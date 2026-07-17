//! ErgoTree deserialization: the lenient consensus reader with Scala's
//! soft-fork wrap semantics (`UnparsedErgoTree`), declared-size handling,
//! version scoping, and the shared depth/position budgets.

use ergo_primitives::reader::{ReadError, VlqReader};

use crate::opcode;
use crate::sigma_value::read_constant;

use super::type_infer::determinable_root_type;
use super::{
    ErgoTree, CONSTANTS_VEC_SOFT_CAP, CONSTANT_SEGREGATION_FLAG, MAX_PROPOSITION_BYTES,
    MAX_SUPPORTED_TREE_VERSION, SIZE_FLAG, VERSION_MASK,
};

/// Deserialize an ErgoTree from bytes.
///
/// For size-delimited trees, exactly `size` bytes are consumed after the size
/// field. For non-size-delimited trees, all remaining bytes in the reader are
/// consumed (the caller must provide exact bounds).
pub fn read_ergo_tree(r: &mut VlqReader) -> Result<ErgoTree, ReadError> {
    let (tree, _was_wrapped) = read_ergo_tree_tracking_wrap(r)?;
    Ok(tree)
}

/// Like [`read_ergo_tree`] but gates V6-EMBEDDABLE TYPE CODES (`SUnsignedBigInt`
/// = code 9, …) under `activated_version` rather than the tree's header version.
///
/// This mirrors Scala `TypeSerializer.getEmbeddableType`, which selects
/// `embeddableV5`/`embeddableV6` by `VersionContext.current.isV6Activated` — the
/// ACTIVATED version (`VersionContext.scala:33`), NOT the tree header. The
/// default [`read_ergo_tree`] gates embeddable codes on the header version
/// (`embeddable_gate_version`), which is correct for the consensus path but wrong
/// for the ergo-compiler post-write self-check: the compile route emits a
/// header-v0 tree (`ErgoTree.defaultHeaderWithVersion(0)`), yet a
/// `tree_version >= 3` (V6-activated) compile legitimately produces a body
/// carrying code 9 that Scala re-parses fine on a V6-activated network
/// (`ErgoTreeSerializer.scala:148-154`, deser runs body/type parse under
/// `withVersions(activatedVersion, treeVersion)`).
///
/// ONLY the compiler self-check uses this — passing its requested `tree_version`
/// as the activated-version floor. Every consensus caller keeps
/// [`read_ergo_tree`] (header-version gating); this function does not exist on
/// their path and is byte-inert for them. The override is restored to its prior
/// value on return so a shared reader is unaffected.
pub fn read_ergo_tree_with_activated_version(
    r: &mut VlqReader,
    activated_version: u8,
) -> Result<ErgoTree, ReadError> {
    let saved = r.embeddable_activated_version();
    r.set_embeddable_activated_version(Some(activated_version));
    let result = read_ergo_tree_tracking_wrap(r);
    r.set_embeddable_activated_version(saved);
    result.map(|(tree, _was_wrapped)| tree)
}

/// Like [`read_ergo_tree`] but also reports whether the returned tree
/// was rebuilt by `unparsed_soft_fork_tree` instead of fully parsed
/// (Scala's `Left(UnparsedErgoTree)` branch). Used by the template-hash
/// path — Scala's `tree.template` throws on the unparsed branch, so we
/// skip recording a template entry rather than emit one bogus hash for
/// every unparsed tree.
/// Advance `r` from the body start to the DECLARED-size end and return the
/// verbatim bytes. Mirrors Scala's wrap path EXACTLY: it computes
/// `numBytes = bodyPos - startPos + declaredSize`, rewinds (`r.position =
/// startPos`), then `propositionBytes = r.getBytes(numBytes)` — leaving the
/// reader at `startPos + numBytes`. Because the declared size is read non-exact
/// (`getUInt().toInt`) it can be NEGATIVE; Scala still accepts as long as
/// `numBytes >= 0` and in range (it does NOT reject merely because the size is
/// negative), and the resulting position can sit BEFORE `body_start`. Errors only
/// when `numBytes` is negative or past the buffer end, as Scala's `getBytes`
/// would. Used only when wrapping; the success path advances by the ACTUAL body
/// length instead. `r` is at `body_start` on entry.
fn take_unparsed_size_region(
    r: &mut VlqReader,
    tree_start: usize,
    body_start: usize,
    declared_size: i32,
) -> Result<Vec<u8>, ReadError> {
    let num_bytes = (body_start - tree_start) as i64 + declared_size as i64;
    let buf_end = (body_start + r.remaining()) as i64; // r is at body_start here
    if num_bytes < 0 || tree_start as i64 + num_bytes > buf_end {
        return Err(ReadError::InvalidData(format!(
            "ErgoTree declared size {declared_size} yields an out-of-range \
             UnparsedErgoTree byte count {num_bytes}"
        )));
    }
    let end = tree_start + num_bytes as usize;
    r.set_position(end); // Scala: position = startPos + numBytes (may rewind)
    Ok(r.data_slice(tree_start, end).to_vec())
}

pub(crate) fn read_ergo_tree_tracking_wrap(
    r: &mut VlqReader,
) -> Result<(ErgoTree, bool), ReadError> {
    let tree_start = r.position();
    let header = r.get_u8()?;
    let version = header & VERSION_MASK;
    let has_size = header & SIZE_FLAG != 0;
    let constant_segregation = header & CONSTANT_SEGREGATION_FLAG != 0;

    if has_size {
        // Scala reads the size with `getUInt().toInt` (NON-exact) and uses it ONLY
        // for the `UnparsedErgoTree` byte count on the wrap path. The body parse is
        // bounded by `MaxPropositionSize`, and on the SUCCESS path the reader
        // advances by the ACTUAL body length (structure-delimited) — the declared
        // size neither bounds the parse nor advances the reader on success. Scala's
        // box parser reads `creationHeight` immediately after this inline tree
        // parse (ErgoBoxCandidate.parseBodyWithIndexedDigests), so matching the
        // advance is consensus-relevant for a box whose declared size ≠ body length.
        let declared_size = r.get_uint_to_i32()?;
        let body_start = r.position();

        // A future-version tree is wrapped LENIENTLY here (the conformance hook
        // feeds size-stripped trees, template-hashing relies on the wrap) and
        // hard-rejected at the box-script layer via `check_tree_version_supported`.
        // Scala HARD-rejects it at deserialize (`VersionContext.withVersions`
        // throws when treeVersion > activated). The reader advances to the
        // declared-size end, as on every wrap path.
        if version > MAX_SUPPORTED_TREE_VERSION {
            let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
            return Ok((
                unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                true,
            ));
        }

        // Parse the body on a view of all remaining bytes WITHOUT advancing `r`,
        // bounded by a POSITION LIMIT of `MaxPropositionSize` (NOT the declared
        // size). `parse_body` is structure-delimited — it reads exactly the root
        // expression — so `inner.position()` is the true body length. A body that
        // would exceed the cap fails the parse and maps to the soft-fork wrap
        // below, exactly as Scala hits its position limit (`ReaderPositionLimit
        // Exceeded` → `CheckPositionLimit` `ValidationException`) and wraps.
        //
        // Scala anchors the limit at `startPos + MaxPropositionSize` (set BEFORE
        // the header + size are read) and checks `position > positionLimit` BEFORE
        // each read, so a final read that BEGINS exactly at the limit still
        // proceeds. The reader's `position_limit` mirrors that begin-check
        // precisely; using it (rather than truncating the view) matches Scala's
        // boundary byte-for-byte. The limit, relative to the inner view that
        // starts at `body_start`, is `MaxPropositionSize - (header + size length)`.
        let body_budget = MAX_PROPOSITION_BYTES.saturating_sub(body_start - tree_start);
        let (parsed, unresolved_checkpoint, body_consumed, inner_ges) = {
            let body_view = r.data_slice(body_start, body_start + r.remaining());
            let mut inner = VlqReader::new(body_view);
            inner.set_position_limit(Some(body_budget));
            // Propagate trust into the body sub-reader so a high-version tree
            // nested in this size-delimited tree's body / segregated constants
            // (an `SBox` constant reached via `skip_ergo_tree`) stays lenient when
            // the outer reader is decoding a trusted stored box. No effect on the
            // (default, untrusted) consensus path.
            inner.set_trusted(r.is_trusted());
            // Gate embeddable type codes (e.g. SUnsignedBigInt, v6-only) against
            // this tree's header version, like Scala's version-scoped
            // `getEmbeddableType`. Covers segregated constants + the body.
            inner.set_ergo_tree_version(Some(version));
            // Also propagate the activated-version override (set by the
            // ergo-compiler self-check) into the size-delimited body reader, so a
            // header-v0 tree gates SUnsignedBigInt (v6-only) by the activated
            // version rather than version 0. Byte-inert on every consensus caller
            // (the override is `None`, falling back to the header version).
            inner.set_embeddable_activated_version(r.embeddable_activated_version());
            let parsed = parse_body(&mut inner, version, has_size, constant_segregation);
            (
                parsed,
                inner.unresolved_method_checkpoint(),
                inner.position(),
                inner.take_group_elements(),
            )
        };
        // A size-delimited tree carrying a method the tree's registry cannot resolve
        // is wrapped by Scala as `UnparsedErgoTree`: `MethodCallSerializer.parse`
        // throws a method-resolution `ValidationException`, caught under has_size.
        // The parser keyed that on the tree-header version (v6-only method in a
        // pre-v3 tree, or a genuinely unknown id at any version) and recorded the
        // group-element sideband length at the exact throw point (after the method's
        // receiver + value args).
        let unresolved_method_wrap = unresolved_checkpoint.is_some();

        // Forward the group elements the inner parse collected onto `r` — EVEN when
        // about to wrap (Scala curve-checks them while deserializing, before
        // producing its UnparsedErgoTree). For the unresolved-method wrap, forward
        // ONLY the prefix Scala reached before it threw at the method; points after
        // it are never deserialized, hence never curve-checked.
        let forward_upto = if unresolved_method_wrap {
            unresolved_checkpoint.unwrap().min(inner_ges.len())
        } else {
            inner_ges.len()
        };
        for ge in &inner_ges[..forward_upto] {
            r.record_group_element(*ge);
        }

        // Once the parser has passed a method the registry cannot resolve, Scala has
        // already thrown the method-resolution `ValidationException` — right after the
        // method's receiver + value args (oracle-confirmed: the obj/args, including any
        // group elements, ARE decoded first; resolution is the next step) — and, under
        // has_size, caught it and wrapped WITHOUT reading the rest of the body. So the
        // outcome is a wrap REGARDLESS of whether the trailing bytes then parsed cleanly
        // OR hit a hard error (depth / overflow / nested HardReject) Scala never reaches.
        // Checked BEFORE the `parsed` match so such a later hard error cannot override it.
        if unresolved_method_wrap {
            let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
            return Ok((
                unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                true,
            ));
        }

        match parsed {
            Ok(tree) => {
                // Scala wraps any non-SigmaProp root
                // (`CheckDeserializedScriptIsSigmaProp`) as `UnparsedErgoTree`.
                // `determinable_root_type` is the rule-1001 typer — it covers inline
                // `Const`/`ConstPlaceholder`, the zero-arg + operator + binding +
                // MethodCall roots — and returns `None` (lenient, no wrap) only for a
                // shape it cannot yet type. The wrap path advances to the
                // declared-size end.
                if determinable_root_type(&tree)
                    .is_some_and(|tpe| tpe != crate::sigma_type::SigmaType::SSigmaProp)
                {
                    let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
                    return Ok((
                        unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                        true,
                    ));
                }
                // Parsed as SigmaProp: advance `r` by the ACTUAL body length so the
                // next box field is read from the structural body end, exactly where
                // Scala leaves the reader on success (the declared size is ignored).
                let _ = r.get_bytes(body_consumed)?;
                Ok((tree, false))
            }
            // Reached only when NO unresolved method preceded the error (that case
            // wrapped above) — so this hard error is the FIRST thing Scala hits too.
            // A tree-depth overflow is Scala's `DeserializeCallDepthExceeded`,
            // a `SerializerException` that `deserializeErgoTree` does NOT catch
            // (it only wraps ReaderPositionLimitExceeded / IllegalArgumentException
            // / ValidationException). So it must HARD-REJECT even under has_size,
            // not become an UnparsedErgoTree — otherwise a size-delimited tree
            // nested past MaxTreeDepth would be accept-invalid vs Scala.
            //
            // `HardReject` carries the same semantics for a NESTED box script
            // (an `SBox` constant whose sizeless pre-v3 inner tree carries a v6
            // method, or violates rule 1012): Scala re-raises those as
            // `SerializerException` too, so they must escape this size-delimited
            // wrap rather than be swallowed into an `UnparsedErgoTree`.
            //
            // `ValueTooLarge` is a VLQ value that overflowed its declared integer
            // width during the body parse. After routing the NON-exact
            // `getUInt().toInt` sites (segregated constants count, `ValUse` id,
            // `FuncValue` arg ids) through `get_uint_to_i32`, every `ValueTooLarge`
            // reachable HERE is from a width Scala hard-rejects: a `getUIntExact`
            // site (ConstantPlaceholder index, ValDef/FunDef id, BlockValue /
            // FuncValue / SigmaAnd-SigmaOr counts, SString length →
            // `ArithmeticException`) or a `getUShort` range overflow — neither a
            // `ValidationException`, so it must escape the wrap.
            Err(
                e @ (ReadError::DepthLimitExceeded { .. }
                | ReadError::HardReject(_)
                | ReadError::ValueTooLarge { .. }),
            ) => Err(e),
            Err(_) => {
                // Other parse failures (unknown opcode, invalid type tag, body
                // truncated at the MaxPropositionSize view) map to Scala's
                // ValidationException, wrapped as UnparsedErgoTree under has_size.
                let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
                Ok((
                    unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                    true,
                ))
            }
        }
    } else {
        // Sizeless body parses directly on `r`; scope the version gate to the body
        // and restore it so subsequent reads (box fields, an enclosing tree) are
        // unaffected. A v6-only embeddable type in a sizeless v<3 tree errors
        // (`InvalidData`); the box-script readers propagate it as a reject, matching
        // Scala re-raising the uncaught `ValidationException` as a hard reject.
        let saved_v = r.ergo_tree_version();
        r.set_ergo_tree_version(Some(version));
        let parsed = parse_body(r, version, has_size, constant_segregation);
        r.set_ergo_tree_version(saved_v);
        parsed.map(|tree| (tree, false))
    }
}

/// Construct a soft-fork-accepted ErgoTree (Scala's
/// `Left(UnparsedErgoTree(bytes, error))`): the outer flags are preserved and
/// the body holds the FULL original tree bytes verbatim
/// ([`crate::opcode::Expr::Unparsed`]), so re-serialization is byte-identical to
/// the wire form (matching Scala's preserved `propositionBytes`) and evaluation
/// hard-errors (Scala throws on an unparsed tree unless its error is an active
/// soft-fork). Used for:
/// - trees whose `version > MAX_SUPPORTED_TREE_VERSION` (version-based soft-fork)
/// - trees with `has_size` whose body fails to parse OR has a non-`SigmaProp`
///   constant root (validation-triggered soft-fork, matches Scala's
///   `UnparsedErgoTree` path)
fn unparsed_soft_fork_tree(
    version: u8,
    has_size: bool,
    constant_segregation: bool,
    full_tree_bytes: Vec<u8>,
) -> ErgoTree {
    ErgoTree {
        version,
        has_size,
        constant_segregation,
        constants: vec![],
        body: crate::opcode::Expr::Unparsed(full_tree_bytes),
    }
}

fn parse_body(
    r: &mut VlqReader,
    version: u8,
    has_size: bool,
    constant_segregation: bool,
) -> Result<ErgoTree, ReadError> {
    let constants = if constant_segregation {
        // Scala `deserializeConstants` reads the count via `getUInt().toInt`
        // (ErgoTreeSerializer.scala:248) — NOT `getUIntExact`. A value past
        // i32::MAX wraps to a negative `Int`, and the `cfor(0)(_ < nConsts)` loop
        // then yields ZERO constants rather than overflowing. Match that: read
        // non-exact and treat a negative count as 0 (an overflowed count is a
        // valid empty-constants tree in Scala, not a hard rejection).
        let count = r.get_uint_to_i32()?.max(0) as usize;
        let mut consts = Vec::with_capacity(count.min(CONSTANTS_VEC_SOFT_CAP));
        for _ in 0..count {
            let (tpe, val) = read_constant(r)?;
            // SHeader value deserialization is gated on isV3OrLaterErgoTreeVersion
            // (Scala DataSerializer.deserialize(SHeader)), per materialized
            // header: a segregated constant carrying a header in a pre-v3 tree
            // is rejected; an empty Coll[Header] is accepted.
            if version < 3 && val.contains_header() {
                return Err(ReadError::InvalidData(format!(
                    "SHeader value requires ErgoTree version >= 3 (got {version})"
                )));
            }
            // SOption data is gated on isV3OrLaterErgoTreeVersion too
            // (CheckSerializableTypeCode rejects SOption pre-v3, Some AND None);
            // a segregated Option constant in a pre-v3 tree is rejected.
            if version < 3 && val.contains_option() {
                return Err(ReadError::InvalidData(format!(
                    "SOption value requires ErgoTree version >= 3 (got {version})"
                )));
            }
            consts.push((tpe, val));
        }
        consts
    } else {
        vec![]
    };

    let body = opcode::parse_body(r, version)?;

    Ok(ErgoTree {
        version,
        has_size,
        constant_segregation,
        constants,
        body,
    })
}
