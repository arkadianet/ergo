//! ErgoTree deserialization: the lenient consensus reader with Scala's
//! soft-fork wrap semantics (`UnparsedErgoTree`), declared-size handling,
//! version scoping, and the shared depth/position budgets.
//! Oracle: test-vectors/scala/const_placeholder_bounds.json

use ergo_primitives::reader::{ReadError, UnresolvedMethodCheckpoint, VlqReader};

use crate::opcode;
use crate::sigma_value::read_constant;

use super::root_type::determinable_root_type;
use super::{
    ErgoTree, CONSTANTS_VEC_SOFT_CAP, CONSTANT_SEGREGATION_FLAG, MAX_PROPOSITION_BYTES,
    MAX_SUPPORTED_TREE_VERSION, RESERVED_HEADER_MASK, SIZE_FLAG, VERSION_MASK,
};

/// Deserialize an ErgoTree from bytes.
///
/// A successfully parsed tree consumes its constants and one opcode expression,
/// leaving following fields available. Size-delimited soft-fork trees retain the
/// declared byte region as an opaque tree; their boundary follows Scala's wrap
/// semantics. Parsing and box/script acceptance are separate gates.
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
    // A tree that starts a fresh top-level reader starts Scala's reader too, so
    // its `valDefTypeStore` is empty and unbound uses are decidable.
    if tree_start == 0 && r.nesting_depth_base() == 0 {
        r.track_val_bindings();
    }
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
        // feeds size-stripped trees, template-hashing relies on the wrap); the
        // box-script layer decides via `check_tree_version_supported`, keyed to
        // the activated version the parse runs under: Scala HARD-rejects it at
        // deserialize from activated 2 on (`VersionContext.withVersions` throws
        // when treeVersion > activated), and below that admits the body to the
        // parse — where a body that fails is kept as `UnparsedErgoTree` exactly
        // like this wrap. The reader advances to the declared-size end, as on
        // every wrap path.
        if version > MAX_SUPPORTED_TREE_VERSION {
            let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
            return Ok((
                unparsed_soft_fork_tree(version, has_size, constant_segregation, full, None),
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
        // The body's reader level starts where `r`'s is; the frames it leaves
        // open at a throw that degrades the tree are counted below.
        let entry_level = r.scala_level();
        let (
            parsed,
            unresolved_checkpoint,
            body_consumed,
            inner_ges,
            header_spans,
            (level_after, leaked_after),
        ) = {
            let body_view = r.data_slice(body_start, body_start + r.remaining());
            let mut inner = VlqReader::new(body_view);
            if r.collects_header_spans() {
                inner.enable_header_spans();
            }
            inner.set_position_limit(Some(body_budget));
            // Propagate trust into the body sub-reader so a high-version tree
            // nested in this size-delimited tree's body / segregated constants
            // (an `SBox` constant reached via `skip_ergo_tree`) stays lenient when
            // the outer reader is decoding a trusted stored box. No effect on the
            // (default, untrusted) consensus path.
            inner.set_trusted(r.is_trusted());
            // Likewise the activated-version scope: Scala's `VersionContext` is
            // ambient to the whole nested parse, so a nested box script inside
            // this body is gated against the same activated version as the
            // outer reader (`check_tree_version_supported`).
            inner.set_activated_script_version(r.activated_script_version());
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
            // Scala parses this body on the SAME reader, so its nesting level
            // (`CoreByteReader.lvl`) keeps climbing across the boundary. This
            // view is a separate reader, so carry the level base over by hand:
            // otherwise a size-delimited tree nested inside an `SBox` constant
            // restarts the MaxTreeDepth budget at 0 and the
            // box -> tree -> constant -> box cycle recurses until the native
            // stack overflows. Inert for a top-level tree, where the base is 0.
            inner.set_nesting_depth_base(r.nesting_depth_base());
            inner.set_scala_level(entry_level);
            inner.set_leaked_levels(r.leaked_levels());
            // The body shares Scala's reader, and with it the binding store,
            // including bindings made before a failure that is then wrapped.
            inner.set_val_bindings(r.val_bindings().cloned());
            let parsed = parse_body(&mut inner, header, has_size, constant_segregation);
            r.set_val_bindings(inner.val_bindings().cloned());
            (
                parsed,
                inner.unresolved_method_checkpoint(),
                inner.position(),
                inner.take_group_elements(),
                inner.header_spans().to_vec(),
                (inner.scala_level(), inner.leaked_levels()),
            )
        };
        for (start, end) in header_spans {
            r.record_header_span(body_start + start, body_start + end);
        }
        // A size-delimited tree carrying a method the tree's registry cannot resolve
        // is wrapped by Scala as `UnparsedErgoTree`: `MethodCallSerializer.parse`
        // throws a method-resolution `ValidationException`, caught under has_size.
        // The parser keyed that on the tree-header version (v6-only method in a
        // pre-v3 tree, or a genuinely unknown id at any version) and recorded the
        // group-element sideband length and the reader level at the exact throw
        // point (after the method's receiver + value args).
        let unresolved_method_wrap = unresolved_checkpoint.is_some();

        // Forward the group elements the inner parse collected onto `r` — EVEN when
        // about to wrap (Scala curve-checks them while deserializing, before
        // producing its UnparsedErgoTree). For the unresolved-method wrap, forward
        // ONLY the prefix Scala reached before it threw at the method; points after
        // it are never deserialized, hence never curve-checked.
        let forward_upto = if unresolved_method_wrap {
            unresolved_checkpoint
                .unwrap()
                .group_elements
                .min(inner_ges.len())
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
        if let Some(checkpoint) = unresolved_checkpoint {
            leave_levels_open(
                r,
                entry_level,
                checkpoint.scala_level,
                checkpoint.leaked_levels,
            );
            let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
            return Ok((
                unparsed_soft_fork_tree(
                    version,
                    has_size,
                    constant_segregation,
                    full,
                    Some(method_validation_rule(
                        checkpoint,
                        version,
                        r.activated_script_version().unwrap_or(1),
                    )),
                ),
                true,
            ));
        }

        match parsed {
            Ok(tree) => {
                // Every frame the body entered returned: only degrades nested
                // in it (a size-delimited box script) left levels open.
                debug_assert_eq!(level_after, entry_level, "unbalanced reader level");
                r.set_scala_level(level_after);
                r.set_leaked_levels(leaked_after);
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
                        unparsed_soft_fork_tree(
                            version,
                            has_size,
                            constant_segregation,
                            full,
                            Some((1001, vec![])),
                        ),
                        true,
                    ));
                }
                // Parsed as SigmaProp: advance `r` by the ACTUAL body length so the
                // next box field is read from the structural body end, exactly where
                // Scala leaves the reader on success (the declared size is ignored).
                let _ = r.get_bytes(body_consumed)?;
                Ok((tree, false))
            }
            // Reached only when NO unresolved method preceded the error (that
            // case wrapped above), so this error is the FIRST thing Scala hits
            // too. Only a `ValidationException` degrades a size-delimited tree:
            // `ErgoTreeSerializer.deserializeErgoTree` (`ErgoTreeSerializer.scala:
            // 141-215`) wraps on `case ve: ValidationException` alone, turns a
            // `ReaderPositionLimitExceeded` into one (rule 1014) and rethrows an
            // `IllegalArgumentException` as a `SerializerException`. Every other
            // throw inside the body is a hard reject: running out of input
            // (`BufferUnderflowException`, or the reader's `require`), a failed
            // `require`, a `ClassCastException` / `MatchError` /
            // `NegativeArraySizeException` / `ArrayIndexOutOfBoundsException`
            // from building a node, `safeNewArray` past 100,000 items, a
            // `DeserializeCallDepthExceeded` or any other `SerializerException`,
            // including one a nested box script re-raises. The body parser
            // reports exactly the `ValidationException` sites as
            // `SigmaValidation` (a validation rule id), so that is the only
            // error the wrap takes.
            Err(error) => {
                let ReadError::SigmaValidation { rule_id, args, .. } = error else {
                    return Err(error);
                };
                let validation_error = Some((
                    validation_rule_version(rule_id, r.activated_script_version().unwrap_or(1)),
                    args,
                ));
                leave_levels_open(r, entry_level, level_after, leaked_after);
                let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
                Ok((
                    unparsed_soft_fork_tree(
                        version,
                        has_size,
                        constant_segregation,
                        full,
                        validation_error,
                    ),
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
        //
        // `deserializeErgoTree` bounds the whole tree, sized or not, to a
        // window of `MaxPropositionSize` from its start
        // (ErgoTreeSerializer.scala:143-144), replacing any enclosing window
        // (a box's) and restoring it afterwards. A sizeless tree cannot
        // degrade, so a read that begins past it rejects the tree.
        let saved_v = r.ergo_tree_version();
        let saved_limit = r.position_limit();
        r.set_ergo_tree_version(Some(version));
        r.set_position_limit(Some(tree_start + MAX_PROPOSITION_BYTES));
        let parsed = parse_body(r, header, has_size, constant_segregation);
        r.set_position_limit(saved_limit);
        r.set_ergo_tree_version(saved_v);
        parsed.map(|tree| (tree, false))
    }
}

/// A size-delimited tree degraded: Scala's `deserializeErgoTree` catches the
/// `ValidationException` and restores only the position limit
/// (ErgoTreeSerializer.scala:209-211), so every frame the throw unwound keeps
/// its reader level for the rest of the reader. Count those frames, the
/// levels between the tree's entry and the throw, as leaked, together with
/// the levels already leaked when it threw.
fn leave_levels_open(
    r: &mut VlqReader,
    entry_level: usize,
    level_at_throw: usize,
    leaked_at_throw: usize,
) {
    let open = level_at_throw.saturating_sub(entry_level);
    r.set_leaked_levels(leaked_at_throw.saturating_add(open));
    r.set_scala_level(entry_level);
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
    validation_error: Option<(u16, Vec<u8>)>,
) -> ErgoTree {
    ErgoTree {
        version,
        has_size,
        constant_segregation,
        reserved_header_bits: full_tree_bytes
            .first()
            .map_or(0, |h| h & RESERVED_HEADER_MASK),
        constants: vec![],
        body: crate::opcode::Expr::Unparsed(crate::opcode::UnparsedErgoTree {
            bytes: full_tree_bytes,
            validation_error,
        }),
    }
}

// Rule identity follows activation, independent of the tree's method registry.
fn validation_rule_version(rule_id: u16, activated_version: u8) -> u16 {
    match (rule_id, activated_version >= 3) {
        (1007, true) => 1017,
        (1008, true) => 1018,
        (1011, true) => 1016,
        _ => rule_id,
    }
}

// MethodsContainer.methodsV5/V6 and CheckAndGetMethodTemplate distinguish
// unknown containers from unknown methods after reading the receiver and args.
fn method_validation_rule(
    UnresolvedMethodCheckpoint {
        type_id, method_id, ..
    }: UnresolvedMethodCheckpoint,
    version: u8,
    activated_version: u8,
) -> (u16, Vec<u8>) {
    if matches!(type_id, 1..=8 | 12 | 36 | 96..=102 | 104..=106) || type_id == 9 && version >= 3 {
        (
            validation_rule_version(1011, activated_version),
            vec![type_id, method_id],
        )
    } else {
        (1010, vec![type_id])
    }
}

fn parse_body(
    r: &mut VlqReader,
    header: u8,
    has_size: bool,
    constant_segregation: bool,
) -> Result<ErgoTree, ReadError> {
    let version = header & VERSION_MASK;
    let constants = if constant_segregation {
        // Scala `deserializeConstants` reads the count via `getUInt().toInt`
        // (ErgoTreeSerializer.scala:248) — NOT `getUIntExact`. A value past
        // i32::MAX wraps to a negative `Int`, and the `cfor(0)(_ < nConsts)` loop
        // then yields ZERO constants rather than overflowing. Match that: read
        // non-exact and treat a negative count as 0 (an overflowed count is a
        // valid empty-constants tree in Scala, not a hard rejection).
        let count = r.get_uint_to_i32()?.max(0) as usize;
        // `safeNewArray[Constant](nConsts)` (ErgoTreeSerializer.scala:254).
        crate::opcode::check_array_length(count, "segregated constants")?;
        let mut consts = Vec::with_capacity(count.min(CONSTANTS_VEC_SOFT_CAP));
        for _ in 0..count {
            let (tpe, val) = read_constant(r)?;
            // The pre-v3 `SHeader` / `SOption` data gates fire inside
            // `read_constant`, at the point Scala throws: the reader carries
            // this tree's version.
            consts.push((tpe, val));
        }
        consts
    } else {
        vec![]
    };

    let saved_pool_len = r.constant_pool_len();
    r.set_constant_pool_len(Some(constants.len()));
    let body = opcode::parse_body_with_constants(r, version, &constants);
    r.set_constant_pool_len(saved_pool_len);
    let body = body?;

    Ok(ErgoTree {
        version,
        has_size,
        constant_segregation,
        reserved_header_bits: header & RESERVED_HEADER_MASK,
        constants,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    // ledger: ORDER-constplaceholder
    #[test]
    fn constant_placeholder_bounds_jvm_verdicts_match() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/const_placeholder_bounds.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["tree_hex"].as_str().unwrap()).unwrap();
            let mut reader = VlqReader::new(&bytes);
            let result = read_ergo_tree(&mut reader);
            match case["jvm"].as_str().unwrap() {
                "Reject" => assert!(
                    matches!(result, Err(ReadError::HardReject(_))),
                    "{}: {result:?}",
                    case["name"]
                ),
                "Accept" => {
                    let tree = result.unwrap();
                    assert!(
                        !matches!(tree.body, opcode::Expr::Unparsed(_)),
                        "{}",
                        case["name"]
                    );
                    assert_eq!(reader.position(), bytes.len(), "{}", case["name"]);
                }
                verdict => panic!("unexpected JVM verdict {verdict}"),
            }
            assert_eq!(reader.constant_pool_len(), None);
        }
    }
}
