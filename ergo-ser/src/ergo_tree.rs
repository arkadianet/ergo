use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::opcode::{self, Body};
use crate::sigma_type::SigmaType;
use crate::sigma_value::{read_constant, write_constant, SigmaValue};

const VERSION_MASK: u8 = 0x07;
const SIZE_FLAG: u8 = 0x08;
const CONSTANT_SEGREGATION_FLAG: u8 = 0x10;

/// Soft `Vec::with_capacity` cap for an ErgoTree's segregated-constant list.
/// `parse_body` reads the count via `get_u32_exact`, which only bounds it to
/// i32::MAX — so a hostile tree header claiming `count = i32::MAX` would
/// otherwise reserve multiple GiB before the first constant is read. The Vec
/// still grows on `push`, so a legitimate tree with more constants than this
/// parses unchanged; the cap only bounds the *initial* reservation. It is a
/// soft cap (not the hard reject `skip_ergo_tree` applies to inner,
/// box-size-bounded trees) because `parse_body` is the top-level consensus
/// parse and must not reject a tree the Scala node would accept.
const CONSTANTS_VEC_SOFT_CAP: usize = 4096;

/// Parsed ErgoTree: header byte + optional constants table + parsed
/// body expression.
///
/// The `version` / `has_size` / `constant_segregation` triple is the
/// decomposition of the on-wire header byte:
/// `header = (version & 0x07) | (has_size ? 0x08 : 0) | (cseg ? 0x10 : 0)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ErgoTree {
    /// ErgoTree layout version (low 3 bits of the header byte).
    pub version: u8,
    /// `true` when the header carries a VLQ-`u32` size field that
    /// length-prefixes the body — required for the soft-fork-friendly
    /// path that lets unknown bodies round-trip verbatim.
    pub has_size: bool,
    /// `true` when constants are pulled out into a separate table
    /// referenced by `ConstPlaceholder` opcodes inside the body.
    pub constant_segregation: bool,
    /// Constants table — only populated when `constant_segregation` is set.
    pub constants: Vec<(SigmaType, SigmaValue)>,
    /// Root body expression.
    pub body: Body,
}

/// Serialize an ErgoTree to bytes.
pub fn write_ergo_tree(w: &mut VlqWriter, tree: &ErgoTree) -> Result<(), WriteError> {
    // A soft-fork-wrapped (unparsed) tree re-emits its preserved original bytes
    // verbatim — header + size + body, byte-identical to the wire form — exactly
    // as Scala re-serializes an `UnparsedErgoTree` from its kept `propositionBytes`.
    if let crate::opcode::Expr::Unparsed(raw) = &tree.body {
        w.put_bytes(raw);
        return Ok(());
    }
    let header = (tree.version & VERSION_MASK)
        | if tree.has_size { SIZE_FLAG } else { 0 }
        | if tree.constant_segregation {
            CONSTANT_SEGREGATION_FLAG
        } else {
            0
        };
    w.put_u8(header);

    if tree.has_size {
        let mut inner = VlqWriter::new();
        write_ergo_tree_body(&mut inner, tree)?;
        let inner_bytes = inner.result();
        w.put_u32(inner_bytes.len() as u32);
        w.put_bytes(&inner_bytes);
    } else {
        write_ergo_tree_body(w, tree)?;
    }
    Ok(())
}

fn write_ergo_tree_body(w: &mut VlqWriter, tree: &ErgoTree) -> Result<(), WriteError> {
    if tree.constant_segregation {
        w.put_u32(tree.constants.len() as u32);
        for (tpe, val) in &tree.constants {
            write_constant(w, tpe, val)?;
        }
    }
    opcode::write_body(w, &tree.body, tree.constant_segregation)?;
    Ok(())
}

/// Deserialize an ErgoTree from bytes.
///
/// For size-delimited trees, exactly `size` bytes are consumed after the size
/// field. For non-size-delimited trees, all remaining bytes in the reader are
/// consumed (the caller must provide exact bounds).
/// Maximum ErgoTree version we can fully parse and evaluate.
/// Trees with higher versions are accepted without body parsing (soft-fork).
/// Matches Scala's VersionContext.MaxSupportedScriptVersion = 3.
const MAX_SUPPORTED_TREE_VERSION: u8 = 3;

/// Scala `CheckHeaderSizeBit` (validation rule 1012, in `deserializeErgoTree`
/// via `deserializeHeaderAndSize`): a non-zero ErgoTree version REQUIRES the
/// size bit, so an old node can skip an unknown-version tree by its declared
/// byte length. A `version != 0` tree with the size bit clear is rejected with a
/// hard `SerializerException`. Version-0 trees legitimately carry no size bit.
///
/// [`read_ergo_tree`] is intentionally LENIENT about this (the SANTA conformance
/// hook feeds it size-stripped trees, and higher-version soft-fork trees parse
/// opaquely), so the consensus box-script readers enforce the rule AFTER parsing
/// — boxes are the consensus-reachable deserialization path for ErgoTrees.
pub fn check_header_size_bit(tree: &ErgoTree) -> Result<(), ReadError> {
    if tree.version != 0 && !tree.has_size {
        return Err(ReadError::InvalidData(format!(
            "ErgoTree version {} requires the size bit (CheckHeaderSizeBit, rule 1012)",
            tree.version
        )));
    }
    Ok(())
}

/// Reject a v6/EIP-50 method ([`crate::opcode::is_v3_only_method`]) carried in a
/// real pre-v3 (tree-header version < 3) ErgoTree at DESERIALIZE — the box-parse
/// twin of the evaluator's spend-path gate (`check_v3_only_methods` /
/// `EvalError::PreV3V6Method`). Scala resolves the method table against the
/// tree-header version (`MethodsContainer._methodsMap`, methods.scala): a
/// v6-only id in a v0/v1/v2 tree is absent from `_v5MethodsMap`, so
/// `MethodCallSerializer.parse` throws a `ValidationException`.
///
/// **Gated on the SIZELESS case only.** When the size bit is set,
/// `ErgoTreeSerializer.deserializeErgoTree` CATCHES that `ValidationException`
/// and wraps the tree as `UnparsedErgoTree` (stored verbatim, rejected later on
/// spend — which the evaluator gate already does); only WITHOUT the size bit is
/// it re-raised as a hard `SerializerException` that rejects the box at parse
/// (`ErgoTreeSerializer.scala:196-209`). Gating a size-flagged tree here would
/// be reject-valid. Since rule 1012 already rejects a sizeless `version != 0`
/// tree, the reachable case is a sizeless v0 tree carrying a v6 method.
///
/// Enforced at the box-script readers (alongside [`check_header_size_bit`]):
/// `read_ergo_tree` stays lenient, so an OUTPUT box storing such a tree —
/// never spent, so the evaluator gate never fires — is still rejected at the
/// creating transaction's parse, matching Scala's eager box-deserialize reject.
pub fn check_v3_only_methods(tree: &ErgoTree) -> Result<(), ReadError> {
    if !tree.has_size && tree.version < 3 {
        if let Some((type_id, method_id)) = crate::opcode::find_v3_only_method(&tree.body) {
            return Err(ReadError::InvalidData(format!(
                "method ({type_id}, {method_id}) requires ErgoTree version >= 3, got tree version {} (CheckAndGetMethod at deserialize)",
                tree.version
            )));
        }
    }
    Ok(())
}

/// The deserialized root's static type WHEN it is trivially determinable from
/// the parsed IR: an inline `Const` carries its own type, and a
/// `ConstPlaceholder` resolves to its segregated constant's type (Scala
/// `ConstantPlaceholderSerializer.parse` gives the placeholder the constant's
/// `tpe`). Scala's `CheckDeserializedScriptIsSigmaProp` rejects (→ soft-fork
/// wrap under `has_size`) any root whose type is not `SSigmaProp`. For every
/// other root shape we have no typechecker and accept — a genuinely non-sigma
/// `Op` root would fail later at evaluation. Returns `None` when the root type
/// is not statically known here (including an out-of-range placeholder index,
/// which we leave to the existing lenient handling).
fn determinable_root_type(tree: &ErgoTree) -> Option<&crate::sigma_type::SigmaType> {
    match &tree.body {
        crate::opcode::Expr::Const { tpe, .. } => Some(tpe),
        crate::opcode::Expr::Op(node) => match &node.payload {
            crate::opcode::Payload::ConstPlaceholder { index } => {
                tree.constants.get(*index as usize).map(|(tpe, _)| tpe)
            }
            _ => None,
        },
        crate::opcode::Expr::Unparsed(_) => None,
    }
}

pub fn read_ergo_tree(r: &mut VlqReader) -> Result<ErgoTree, ReadError> {
    let (tree, _was_wrapped) = read_ergo_tree_tracking_wrap(r)?;
    Ok(tree)
}

/// Like [`read_ergo_tree`] but also reports whether the returned tree
/// was rebuilt by `unparsed_soft_fork_tree` instead of fully parsed
/// (Scala's `Left(UnparsedErgoTree)` branch). Used by the template-hash
/// path — Scala's `tree.template` throws on the unparsed branch, so we
/// skip recording a template entry rather than emit one bogus hash for
/// every unparsed tree.
pub(crate) fn read_ergo_tree_tracking_wrap(
    r: &mut VlqReader,
) -> Result<(ErgoTree, bool), ReadError> {
    let tree_start = r.position();
    let header = r.get_u8()?;
    let version = header & VERSION_MASK;
    let has_size = header & SIZE_FLAG != 0;
    let constant_segregation = header & CONSTANT_SEGREGATION_FLAG != 0;

    if has_size {
        let size = r.get_u32_exact()? as usize;
        let bounded_data = r.get_bytes(size)?;
        // Capture the FULL original tree bytes (header + size + body) so a
        // soft-fork-wrapped tree re-serializes byte-identically (Scala preserves
        // `propositionBytes` verbatim for an `UnparsedErgoTree`). `data_slice`
        // borrows the underlying buffer, not `r`, so this coexists with the
        // later `r.record_group_element` (which mutably borrows `r`).
        let tree_end = r.position();
        let full_tree_bytes = r.data_slice(tree_start, tree_end).to_vec();

        // Soft-fork: trees with version > our max are accepted without parsing.
        // The Scala auto-accepts these in Interpreter.checkSoftForkCondition.
        // We still need to consume the bytes (via get_bytes above) but skip body parsing.
        if version > MAX_SUPPORTED_TREE_VERSION {
            return Ok((
                unparsed_soft_fork_tree(version, has_size, constant_segregation, full_tree_bytes),
                true,
            ));
        }

        // Match Scala's sigma.serialization.ErgoTreeSerializer.deserializeErgoTree
        // (sigmastate-interpreter/.../ErgoTreeSerializer.scala:141-208):
        //
        // 1. The `size` field is a position LIMIT (upper bound) for the
        //    body reader, not an equality constraint. If parse consumes
        //    fewer bytes than declared, Scala silently accepts — the
        //    extra bytes inside the size region are not checked. This
        //    is why we pass `bounded_data` (length = size) to the inner
        //    reader and then NOT assert `inner.is_empty()` after parse.
        //
        // 2. CheckDeserializedScriptIsSigmaProp (ValidationRules.scala:39-52)
        //    raises ValidationException if the root's type is not
        //    SigmaProp. The root type is the authoritative check, not
        //    leftover bytes.
        //
        // 3. When ValidationException fires AND has_size is set
        //    (sizeOpt.isDefined), Scala wraps as UnparsedErgoTree and
        //    preserves the full declared-size bytes. This is the
        //    soft-fork-compatible path that lets size-flagged boxes
        //    containing unknown or malformed content ship without
        //    breaking historical sync. (See Scala line 197-208.)
        //
        // 4. Without has_size, Scala re-raises — so for the non-has_size
        //    branch below we still propagate errors as before.
        //
        // Our parser's untyped IR can only check the root type when it's
        // a `Const { tpe, ... }` (leaf constant). For `Op(..)` roots we
        // accept, because (a) proving SigmaProp would require a typechecker
        // we don't have, and (b) a non-sigma-typed Op tree would fail
        // downstream at script evaluation anyway, at which point
        // CheckedTransaction / block validation surfaces the real error.
        // This is a narrower net than Scala's full typechecker but catches
        // the observed mainnet malformed trees (Const of a non-SigmaProp
        // type inside a size-delimited wrapper — e.g. block 1,702,686).
        let mut inner = VlqReader::new(bounded_data);
        let parsed = parse_body(&mut inner, version, has_size, constant_segregation);
        // Forward the group elements the inner parse collected (constants + body
        // up to any failure point) onto the OUTER reader — EVEN when the body is
        // about to be soft-fork-wrapped below. Scala curve-checks these while
        // deserializing, before producing its UnparsedErgoTree, so the obligation
        // must survive the wrap (this is the case a post-parse AST walk loses).
        //
        // KNOWN DIVERGENCE B (reject-valid, deferred — see
        // `known_divergence_offcurve_ge_after_v6_method_is_collected`): because
        // this version-independent parse runs the WHOLE body, it forwards GEs
        // that sit AFTER a v6-only method in a pre-v3 tree. Scala's parse throws
        // at that method and never reaches them, so it wraps the tree and never
        // curve-checks the trailing GE. The sound fix is parser-side
        // checkpointing of the sideband length at the would-throw point; it
        // needs Scala oracle vectors and is tracked separately.
        for ge in inner.take_group_elements() {
            r.record_group_element(ge);
        }
        match parsed {
            Ok(tree) => {
                // CheckDeserializedScriptIsSigmaProp: a root whose statically
                // known type is not SigmaProp (an inline non-SigmaProp constant,
                // or a ConstPlaceholder resolving to a non-SigmaProp constant) is
                // soft-fork-wrapped under has_size, as Scala does.
                let root_non_sigmaprop = determinable_root_type(&tree)
                    .is_some_and(|tpe| *tpe != crate::sigma_type::SigmaType::SSigmaProp);
                if root_non_sigmaprop {
                    return Ok((
                        unparsed_soft_fork_tree(
                            version,
                            has_size,
                            constant_segregation,
                            full_tree_bytes,
                        ),
                        true,
                    ));
                }
                Ok((tree, false))
            }
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
            Err(e @ (ReadError::DepthLimitExceeded { .. } | ReadError::HardReject(_))) => Err(e),
            Err(_) => {
                // Other parse failures (unknown opcode, invalid type tag) map to
                // Scala's ValidationException, which under has_size is wrapped
                // as UnparsedErgoTree (the soft-fork-compatible path).
                Ok((
                    unparsed_soft_fork_tree(
                        version,
                        has_size,
                        constant_segregation,
                        full_tree_bytes,
                    ),
                    true,
                ))
            }
        }
    } else {
        parse_body(r, version, has_size, constant_segregation).map(|tree| (tree, false))
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
        let count = r.get_u32_exact()? as usize;
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

/// Failure modes for [`tree_hash_from_bytes`]. Separate variants for
/// parse-failure vs reserialize-failure let callers map each onto the
/// right HTTP envelope (Scala returns 400 on either; we keep them
/// distinct in the type for diagnostics).
#[derive(Debug)]
pub enum TreeHashError {
    /// Input bytes could not be parsed into an `ErgoTree`.
    Parse(ReadError),
    /// Tree parsed cleanly but failed to re-serialize.
    Write(WriteError),
}

impl std::fmt::Display for TreeHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "ergo-tree parse: {e:?}"),
            Self::Write(e) => write!(f, "ergo-tree reserialize: {e:?}"),
        }
    }
}

impl std::error::Error for TreeHashError {}

/// Mirror of Scala's `IndexedErgoAddressSerializer.hashErgoTree(tree)`
/// for the API-surface case where the caller submits raw tree bytes.
/// Parse → re-serialize → blake2b256 yields the same key the indexer's
/// address-keyed tables use, so the byErgoTree routes can dispatch into
/// the address methods without a separate trait surface.
///
/// Re-serializing matches Scala's `tree.bytes` accessor (canonical
/// form). Hashing the input bytes verbatim would risk a mismatch on
/// non-canonical inputs that still parse cleanly; the parse-then-write
/// roundtrip pins us to the exact bytes the indexer keys on. The cost
/// is one extra serialization per request — negligible for a route
/// behind the indexer status gate.
pub fn tree_hash_from_bytes(tree_bytes: &[u8]) -> Result<[u8; 32], TreeHashError> {
    let mut reader = VlqReader::new(tree_bytes);
    let tree = read_ergo_tree(&mut reader).map_err(TreeHashError::Parse)?;
    let mut writer = VlqWriter::new();
    write_ergo_tree(&mut writer, &tree).map_err(TreeHashError::Write)?;
    Ok(*blake2b256(&writer.result()).as_bytes())
}

/// Failure modes for the template-hash derivations. Distinct from
/// [`TreeHashError`] because templating has the extra `Unparseable`
/// case: a tree that `read_ergo_tree` accepted as a soft-fork
/// placeholder cannot produce a meaningful template hash (Scala's
/// `tree.template` throws on its `Left(UnparsedErgoTree)` branch).
#[derive(Debug)]
pub enum TemplateHashError {
    /// Input bytes could not be parsed into an `ErgoTree`.
    Parse(ReadError),
    /// Tree parsed cleanly but its template body failed to re-serialize.
    Write(WriteError),
    /// Tree was rebuilt by `unparsed_soft_fork_tree` and does not have
    /// a meaningful template — the indexer must skip template recording
    /// for this output rather than emit a hash that collides across all
    /// unparsed trees.
    Unparseable,
}

impl std::fmt::Display for TemplateHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "ergo-tree parse: {e:?}"),
            Self::Write(e) => write!(f, "ergo-tree template reserialize: {e:?}"),
            Self::Unparseable => write!(f, "ergo-tree was wrapped as unparsed soft-fork"),
        }
    }
}

impl std::error::Error for TemplateHashError {}

/// Serialize the body of an `ErgoTree` to bytes. Mirrors Scala's
/// `ErgoTree.template` (which calls
/// `DefaultSerializer.serializeErgoTreeTemplate(tree)` =
/// `ValueSerializer.serialize(tree.toProposition(replaceConstants = false))`).
///
/// Result excludes the header byte and (when `constant_segregation` is
/// set) the constants table — both live in the parent serialization,
/// not the template. For segregated trees the body contains
/// `ConstPlaceholder` opcodes that reference the (omitted) constants
/// table; those placeholders are the byte sequence Scala diffs against.
pub fn template_bytes(tree: &ErgoTree) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    crate::opcode::write_body(&mut w, &tree.body, tree.constant_segregation)?;
    Ok(w.result())
}

/// `hashTreeTemplate(tree) = blake2b256(tree.template)` from the parsed
/// `ErgoTree`. Mirrors `IndexedContractTemplate.hashTreeTemplate` under
/// `VersionContext.withVersions(MaxSupportedScriptVersion = 3, ...)`.
///
/// Returns `TemplateHashError::Unparseable` on soft-fork-wrapped trees
/// — caller must check `was_wrapped` (use [`template_hash_from_bytes`]
/// for the parse-then-hash path).
pub fn template_hash(tree: &ErgoTree) -> Result<[u8; 32], TemplateHashError> {
    let bytes = template_bytes(tree).map_err(TemplateHashError::Write)?;
    Ok(*blake2b256(&bytes).as_bytes())
}

/// `hashTreeTemplate` from raw tree bytes. Parses, detects the
/// soft-fork wrap branch, and on the parsed branch hashes the template
/// body. The hot path on the indexer apply loop — one parse + one body
/// reserialize + one hash per output box.
pub fn template_hash_from_bytes(tree_bytes: &[u8]) -> Result<[u8; 32], TemplateHashError> {
    let mut reader = VlqReader::new(tree_bytes);
    let (tree, was_wrapped) =
        read_ergo_tree_tracking_wrap(&mut reader).map_err(TemplateHashError::Parse)?;
    if was_wrapped {
        return Err(TemplateHashError::Unparseable);
    }
    template_hash(&tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::Expr;
    use ergo_primitives::group_element::GroupElement;

    // ----- helpers -----

    /// Simplest valid body: a boolean constant `true` (serializes as 0x01 0x01).
    /// NOTE: a non-SigmaProp root is only valid under a NON-size-delimited tree.
    /// Under `has_size`, Scala's `CheckDeserializedScriptIsSigmaProp` soft-fork-
    /// wraps a non-SigmaProp root into `Expr::Unparsed`, so size-delimited
    /// fixtures must use [`sigma_prop_body`] instead.
    fn simple_body() -> Body {
        Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        }
    }

    /// A valid proposition body for size-delimited (`has_size`) fixtures:
    /// `sigmaProp(true)` (root type `SSigmaProp`), which survives re-parse
    /// without being soft-fork-wrapped.
    fn sigma_prop_body() -> Body {
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
        }
    }

    /// A ConstPlaceholder body for cseg tests (serializes as 0x73 + VLQ(0)).
    fn placeholder_body() -> Body {
        Expr::Op(crate::opcode::IrNode {
            opcode: 0x73,
            payload: crate::opcode::Payload::ConstPlaceholder { index: 0 },
        })
    }

    fn roundtrip(tree: &ErgoTree) {
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, tree).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ergo_tree(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after roundtrip");
        assert_eq!(&decoded, tree);
    }

    fn roundtrip_bytes(tree: &ErgoTree) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, tree).unwrap();
        w.result()
    }

    // ----- round-trips -----

    #[test]
    fn header_byte_version_only() {
        let tree = ErgoTree {
            version: 3,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        assert_eq!(bytes[0], 0x03);
        roundtrip(&tree);
    }

    #[test]
    fn header_byte_all_flags() {
        let tree = ErgoTree {
            version: 1,
            has_size: true,
            constant_segregation: true,
            constants: vec![],
            body: sigma_prop_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        // version=1, size=0x08, cseg=0x10 => 0x19
        assert_eq!(bytes[0], 0x19);
        roundtrip(&tree);
    }

    #[test]
    fn header_byte_size_flag_only() {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: sigma_prop_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        assert_eq!(bytes[0], 0x08);
        roundtrip(&tree);
    }

    #[test]
    fn header_byte_cseg_flag_only() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![],
            body: simple_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        assert_eq!(bytes[0], 0x10);
        roundtrip(&tree);
    }

    #[test]
    fn no_constants_no_size() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn cseg_no_constants_no_size() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![],
            body: simple_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn cseg_with_constants_no_size() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![
                (SigmaType::SInt, SigmaValue::Int(42)),
                (SigmaType::SLong, SigmaValue::Long(1_000_000)),
            ],
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn cseg_with_constants_and_size() {
        // The body is `ConstPlaceholder(0)`, so under `has_size` the root's
        // resolved type IS checked (CheckDeserializedScriptIsSigmaProp): the
        // placeholder must resolve to a SigmaProp constant or the tree would be
        // soft-fork-wrapped. constants[0] is therefore `sigmaProp(true)`; the
        // trailing non-SigmaProp constants still exercise multi-constant cseg.
        let tree = ErgoTree {
            version: 1,
            has_size: true,
            constant_segregation: true,
            constants: vec![
                (
                    SigmaType::SSigmaProp,
                    SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
                ),
                (SigmaType::SBoolean, SigmaValue::Boolean(true)),
                (
                    SigmaType::SColl(Box::new(SigmaType::SByte)),
                    SigmaValue::Coll(crate::sigma_value::CollValue::Bytes(vec![0xDE, 0xAD])),
                ),
            ],
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn read_ergo_tree_constant_count_above_soft_cap_still_parses() {
        // CONSTANTS_VEC_SOFT_CAP bounds only the initial Vec reservation; it must
        // NOT reject a tree the Scala node would accept. A cseg tree with more
        // constants than the cap round-trips — the Vec grows past the cap on
        // push and parsing succeeds. Pins the consensus-acceptance claim of the
        // soft cap (contrast `read_ergo_tree_huge_constant_count_does_not_oom`,
        // which checks the hostile short-payload path returns an error).
        let n = CONSTANTS_VEC_SOFT_CAP + 904; // 5000, comfortably above the cap
        assert!(n > CONSTANTS_VEC_SOFT_CAP);
        let constants: Vec<(SigmaType, SigmaValue)> = (0..n)
            .map(|i| (SigmaType::SInt, SigmaValue::Int(i as i32)))
            .collect();
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants,
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn size_delimited_no_cseg() {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: sigma_prop_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn multiple_constants_roundtrip() {
        let ge_bytes = [0x02; 33];
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![
                (SigmaType::SInt, SigmaValue::Int(0)),
                (SigmaType::SLong, SigmaValue::Long(i64::MAX)),
                (SigmaType::SBoolean, SigmaValue::Boolean(false)),
                (
                    SigmaType::SGroupElement,
                    SigmaValue::GroupElement(GroupElement::from_bytes(ge_bytes)),
                ),
            ],
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    /// Assert that `hex` decodes to a valid ErgoTree wire form: header +
    /// optional constants table + body parses cleanly with no leftover
    /// bytes. Used by the per-fixture regression tests below to pin
    /// specific mainnet contracts.
    fn trace_tree(hex: &str) {
        let raw = hex::decode(hex).unwrap();
        let mut r = VlqReader::new(&raw);
        let header = r.get_u8().unwrap();
        let has_size = header & 0x08 != 0;
        let cseg = header & 0x10 != 0;

        if has_size {
            let _ = r.get_u32_exact().unwrap();
        }
        let const_count = if cseg { r.get_u32_exact().unwrap() } else { 0 };
        for _ in 0..const_count {
            crate::sigma_value::read_constant(&mut r).expect("constant parse");
        }
        crate::opcode::parse_body(&mut r, 0).expect("body parse");
        assert!(
            r.is_empty(),
            "leftover bytes: {} remaining at pos {}",
            r.remaining(),
            r.position()
        );
    }

    #[test]
    fn trace_emission_contract() {
        trace_tree("101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f");
    }

    #[test]
    fn mainnet_ergotrees_roundtrip() {
        #[derive(serde::Deserialize)]
        struct TestVector {
            #[allow(dead_code)]
            source: String,
            bytes: String,
        }

        let json_data = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/ergotrees_1_10.json"
        ))
        .expect("test vectors file");
        let vectors: Vec<TestVector> = serde_json::from_str(&json_data).expect("parse JSON");

        for (i, tv) in vectors.iter().enumerate() {
            let original_bytes =
                hex::decode(&tv.bytes).unwrap_or_else(|e| panic!("vector {i}: bad hex: {e}"));

            let mut r = VlqReader::new(&original_bytes);
            let tree = read_ergo_tree(&mut r)
                .unwrap_or_else(|e| panic!("vector {i} ({}): parse failed: {e}", tv.source));
            assert!(
                r.is_empty(),
                "vector {i} ({}): leftover bytes after parse",
                tv.source
            );

            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &tree).unwrap();
            let reserialized = w.result();

            assert_eq!(
                original_bytes,
                reserialized,
                "vector {i} ({}): roundtrip mismatch.\n  original:     {}\n  reserialized: {}",
                tv.source,
                hex::encode(&original_bytes),
                hex::encode(&reserialized),
            );
        }
    }

    #[test]
    fn trace_failing_tree_0x59() {
        // Tree #1645: height_700046, 440 bytes, header=0x19 (cseg, has_size)
        // Fails with "unknown type code: 0x59"
        let hex_bytes = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/failing_tree_1645.hex"
        ))
        .expect("read failing tree hex");
        let hex = hex_bytes.trim();
        trace_tree(hex.trim());
    }

    #[test]
    fn trace_block_1160831_tx14() {
        // TX 14 Out 0 from block 1160831 - complex contract with 24 constants
        trace_tree("19fc031808cd03c3ce4fd9a252ec9e58a766481f7d09dae2c9c2c48f22b47d97c4af12347a2ffc04000580a0be819501040404060402040004000e201b694b15467c62f0cd4525e368dbdea2329c713aa200b73df4a622e950551b400e208b08cdd5449a9592a9e79711d7d79249d7a03c535d17efaee83e216e80a44c4b05a8b22505bc81c4cbf9dbfa06058080d287e2bc2d040404ca0f06010104d00f0580a0be81950104ca0f0e691005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a5730405000500058092f4010100d803d6017300d602b2a4730100d6037302eb027201d195ed92b1a4730393b1db630872027304d804d604db63087202d605b2a5730500d606b2db63087205730600d6077e8c72060206edededededed938cb2720473070001730893c27205d07201938c72060173099272077e730a06927ec172050699997ec1a7069d9c72077e730b067e730c067e720306909c9c7e8cb27204730d0002067e7203067e730e069c9a7207730f9a9c7ec17202067e7310067e9c73117e7312050690b0ada5d90108639593c272087313c1720873147315d90108599a8c7208018c72080273167317");
    }

    #[test]
    fn trace_block_1160831_tx18_spectrum_dex() {
        // TX 18 Out 0 from block 1160831 - Spectrum DEX
        trace_tree("1999030f0400040204020404040405feffffffffffffffff0105feffffffffffffffff01050004d00f040004000406050005000580dac409d819d601b2a5730000d602e4c6a70404d603db63087201d604db6308a7d605b27203730100d606b27204730200d607b27203730300d608b27204730400d6099973058c720602d60a999973068c7205027209d60bc17201d60cc1a7d60d99720b720cd60e91720d7307d60f8c720802d6107e720f06d6117e720d06d612998c720702720fd6137e720c06d6147308d6157e721206d6167e720a06d6177e720906d6189c72117217d6199c72157217d1ededededededed93c27201c2a793e4c672010404720293b27203730900b27204730a00938c7205018c720601938c7207018c72080193b17203730b9593720a730c95720e929c9c721072117e7202069c7ef07212069a9c72137e7214067e9c720d7e72020506929c9c721372157e7202069c7ef0720d069a9c72107e7214067e9c72127e7202050695ed720e917212730d907216a19d721872139d72197210ed9272189c721672139272199c7216721091720b730e");
    }

    #[test]
    fn trace_block_1160831_tx35_options() {
        // TX 35 Out 0 from block 1160831 - options contract
        trace_tree("00d836d601db6308a7d60286028300020500d603b272010400017202d6048c720301d605e4c6a70763d606ed937204c5720593c2a7c27205d6079572067205a7d608e4c67207091ad609ef7206d60ac57207d60bb0dc0c0fa501d9010b63addb6308720bd9010d4d0e95938c720d01720a8c720d0205000500d9010b599a8c720b018c720b02d60cb27208040200d60db27208040400d60eb27208040600d60fb27208040800d610b2a5040000d611c27210d612e4c672070811d613b27212040c00d6149a72130580897ad615e4c67207050ed61695937211c2a7edededed92c17210721493e4c67210040ee4c67207040e93e4c67210050e721593e4c67210060ee4c67207060e93e4c67210076372070100d617b27212040600d618db6903db6503fed619c1a7d61ab27212040a00d61bdb63087210d61cb2721b0400017202d61d8c720302d61eb27212040400d61fb27212040800d62093b272120400000500d6218c721c02d622b2721b0402017202d623b2a5040200d6240e20e540cceffd3b8dd0f401193576cc413467039695969427df94454193dddfb375d6259172187217d626ed720693721d0502d6279593b272120402000500eded722672258f72189a72170580f0b252ed72269072187217d628b272010402017202d6298c722802d62a8c722202d62b8c722201d62cdb63087223d62db2722c0400017202d62e8c722d01d62f8c722d02d630b2a5040400d631db63087230d632b272310400017202d633957206e4c6a7081183020505000500d634b27233040000d635b27233040200d6368c721c01eb02ea02cdeeb27208040000d1ed720993720b0500d1ececec95eded720993b1a4040493b1a50406d804d637b2a4040200d638c17237d6399a999972197213721a7238d63a9572209d721d721e9d9972399c050472149c721f721eedededededededededededededededed927238058092f40193cbb2e4c67237091a040200720c93cbb2e4c67237091a040400720d93cbb2e4c67237091a040600720e93cbb2e4c67237091a040800720f72168f99721772180580909cf1c00593c17210723992c172109c05047214d801d63b723693723bc5a79372219a723a0502ecededed7220d801d63b722b93723b7215937222720393b1721b0404edef722093b1721b040293b2e4c672100811040000723a93b2e4c672100811040200050093cbc27223720c93c17223721a93cbc2b2a50404007224010095eded722793b1a4040493b1a50408d807d637957220997229722a997219c17210d6389572209d7237721e9d72379c721f721ed639b2db6308b2a40402000400017202d63a95938c723901720a8c7239020500d63b7230d63c7231d63d7232ededededededed937238723a7216ecedededededededed7220937203721c93c172107219ec93722b721593722a050093722e721593722f723793b1722c040292c1723b9c9c7238721f721e93b1723c0400edededededef722092c17223723793b1722c0400938c723d017215928c723d029c7238721e93b1723c040293b2e4c672100811040000723493b2e4c6721008110402009a7235723a93cbc2723b720e93cbc2b2a5040600722490c1b2a50406007213010095eded720693b1a4040293b1a50406edededededededededededed93c172109999721972130580897a721693723672049372210502937222722893b2e4c672100811040000723493b2e4c672100811040200050093cbc27223720d93c172230580897a93b1722c0402d801d637722e937237720493722f99721d050293cbc2b2a50404007224010095eced7225ef722795720693723572340100ededededededed93b1a4040293b1a5040493cb7211720f92c1721099721972139372368c722801937221722993720b050093cbc2722372240100");
    }

    #[test]
    fn trace_block_1160831_tx35_out1() {
        trace_tree("00d806d601e4c6a7091ad602b27201040000d603b27201040a00d604937203cbc2b2a5040000d605e4c6a7050ed606e4c6a70711eb02ea02cdee7202d1ef7204d195eded93b1a4040493b1a5040493cbc2b2a40400007203d801d607b2a4040000ededed93c2a7c27207ed93c17207c1a793e4c67207050e7205938cb27206040000017203ec93720672019683020193e4c67207060ee4c6a7060e93e4c67207070e7206d801d607b2a4040000ededededed93c2a7c27207ed93c17207c1a793e4c67207050e720593e4c67207060ee4c6a7060e93e4c67207070e7206d801d608e4c672070811eded93b27208040000720293b27208040200720493c172079c9c997208c17207050472039c72040502");
    }

    // ----- error paths -----

    #[test]
    fn read_ergo_tree_huge_constant_count_does_not_oom() {
        // Non-size-delimited, constant-segregated tree (header 0x10) that
        // claims count = i32::MAX with no constant bytes. Before the soft cap,
        // `Vec::with_capacity(count)` reserved multiple GiB and aborted the
        // process; the cap bounds the reservation, so parsing returns a clean
        // decode error instead.
        let mut bytes = vec![CONSTANT_SEGREGATION_FLAG]; // v0, no size, cseg
        bytes.extend_from_slice(&ergo_primitives::vlq::encode_vlq(i32::MAX as u64));
        let mut r = VlqReader::new(&bytes);
        assert!(read_ergo_tree(&mut r).is_err());
    }

    // ----- oracle parity -----

    // -- Size-flagged malformed tree (Scala UnparsedErgoTree parity) --

    /// Block 1,702,686 tx #3 output[0] on mainnet carries an ErgoTree with
    /// header 0x09 (v=1, has_size=true, no cseg), declared body size 47
    /// bytes. The body's first two bytes parse as `Const(SByte = 4)`, but
    /// since the root type is SByte — not SigmaProp — Scala's
    /// CheckDeserializedScriptIsSigmaProp raises a ValidationException,
    /// and because `has_size` is set the outer catch wraps as
    /// UnparsedErgoTree preserving all declared bytes (Scala
    /// ErgoTreeSerializer.scala:197-208). The remaining 45 bytes inside
    /// the declared-size region are ignored — size is a position LIMIT,
    /// not an equality constraint.
    ///
    /// Our parser must NOT raise on this input. It must accept and return a
    /// soft-fork-wrapped tree whose body is [`Expr::Unparsed`], preserving the
    /// full original tree bytes verbatim (mirroring Scala's
    /// `UnparsedErgoTree(propositionBytes)`). Regression guard for sync
    /// stalling at block 1702686.
    #[test]
    fn size_flagged_non_sigmaprop_root_wraps_as_unparsed() {
        let hex = "092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402";
        let bytes = hex::decode(hex).unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree =
            read_ergo_tree(&mut r).expect("size-flagged non-SigmaProp tree must wrap, not raise");
        assert_eq!(tree.version, 1);
        assert!(tree.has_size);
        assert!(!tree.constant_segregation);
        // The body holds the FULL original tree bytes verbatim (Scala preserves
        // an UnparsedErgoTree's propositionBytes), so re-serialization is
        // byte-identical and evaluation hard-errors rather than silently
        // succeeding as an always-true proposition.
        match &tree.body {
            Expr::Unparsed(raw) => assert_eq!(
                raw, &bytes,
                "unparsed soft-fork body must preserve the full tree bytes"
            ),
            other => panic!("expected Unparsed soft-fork body, got {other:?}"),
        }
        // Byte-identical re-serialization — the property that closes the wire
        // round-trip divergence for soft-fork-wrapped scripts.
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree).unwrap();
        assert_eq!(
            w.result(),
            bytes,
            "soft-fork-wrapped tree must re-serialize verbatim"
        );
    }

    /// A size-delimited tree whose ROOT is a `ConstPlaceholder` resolving to a
    /// non-SigmaProp segregated constant fails Scala's
    /// `CheckDeserializedScriptIsSigmaProp` just like an inline non-SigmaProp
    /// `Const` root — the placeholder carries the constant's type
    /// (`ConstantPlaceholderSerializer.parse`). It must soft-fork-wrap to
    /// `Expr::Unparsed` (byte-preserving), NOT be accepted as a parsed
    /// `Int`-typed proposition. A placeholder resolving to a SigmaProp constant
    /// is a valid root and is NOT wrapped.
    #[test]
    fn size_flagged_const_placeholder_non_sigmaprop_root_wraps_as_unparsed() {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SInt, SigmaValue::Int(7))],
            body: placeholder_body(), // ConstPlaceholder(0) → SInt (non-SigmaProp)
        };
        let bytes = roundtrip_bytes(&tree);
        let decoded = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
        match &decoded.body {
            Expr::Unparsed(raw) => assert_eq!(
                raw, &bytes,
                "non-SigmaProp placeholder root must wrap, preserving bytes"
            ),
            other => panic!("expected Unparsed soft-fork body, got {other:?}"),
        }
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &decoded).unwrap();
        assert_eq!(w.result(), bytes, "wrapped tree must re-serialize verbatim");

        // A placeholder resolving to a SigmaProp constant is a valid root.
        let valid = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(
                SigmaType::SSigmaProp,
                SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
            )],
            body: placeholder_body(),
        };
        roundtrip(&valid);
    }

    /// A size-delimited (`has_size`) tree whose body nests past MaxTreeDepth
    /// (110) must HARD-REJECT, NOT be wrapped as `UnparsedErgoTree`. Scala's
    /// `DeserializeCallDepthExceeded` is a `SerializerException` that
    /// `deserializeErgoTree` does not catch, so a depth overflow is
    /// consensus-rejected even under the soft-fork wrapper. (Regression for the
    /// codex review of the MAX_EXPR_DEPTH=110 fix — the wrapper used to swallow
    /// this into an accepted unparsed tree.)
    #[test]
    fn size_flagged_over_depth_body_hard_rejects_not_wrapped() {
        // header 0x08 = v0, has_size, no cseg; body = 150x SizeOf(0xB1) then a
        // Height (0xA3) leaf — depth far exceeds MaxTreeDepth (110).
        let mut body = vec![0xB1u8; 150];
        body.push(0xA3);
        let mut bytes = vec![0x08u8];
        ergo_primitives::vlq::encode_vlq_into(body.len() as u64, &mut bytes);
        bytes.extend_from_slice(&body);
        let mut r = VlqReader::new(&bytes);
        let err = read_ergo_tree(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { .. }),
            "size-delimited over-depth tree must hard-reject, not soft-fork wrap; got {err:?}"
        );
    }

    /// Same tree, but with `has_size` bit cleared — Scala raises rather
    /// than wraps (ErgoTreeSerializer.scala:205). We match: the non-size
    /// path still parses strictly.
    #[test]
    fn non_size_flagged_non_sigmaprop_root_returns_const_without_wrap() {
        // Header 0x01 = v=1, no has_size, no cseg. Body: SByte=4.
        // Without a size delimiter, parse_body consumes 2 bytes
        // ("02 04") and returns Const(SByte=4) cleanly — no wrap
        // because we don't have the size field to justify it.
        let bytes = hex::decode("010204").unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        match &tree.body {
            Expr::Const { tpe, .. } => assert_eq!(
                *tpe,
                SigmaType::SByte,
                "without has_size, non-SigmaProp Const is returned verbatim"
            ),
            other => panic!("expected Const(SByte), got {other:?}"),
        }
    }

    // -- Template-hash derivations --

    /// `template_bytes` strips the header byte and (when present) the
    /// constants table — only the body opcode stream survives. For a
    /// simple non-segregated tree with body `Const(SBoolean=true)`, the
    /// full tree serializes as `[header, 0x01, 0x01]` and the template
    /// is just `[0x01, 0x01]`.
    #[test]
    fn template_bytes_excludes_header_for_simple_tree() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        let full = roundtrip_bytes(&tree);
        let tmpl = template_bytes(&tree).unwrap();
        assert_eq!(full[0], 0x00, "header byte should be 0x00 (no flags)");
        assert_eq!(
            tmpl,
            full[1..].to_vec(),
            "template = full - header (no cseg, no size)"
        );
    }

    /// For a segregated tree, `template_bytes` excludes both the header
    /// AND the constants table — only the body (which contains
    /// `ConstPlaceholder` opcodes referencing the omitted constants by
    /// index) is hashed. This is what makes templates structurally
    /// equal across different parameter values.
    #[test]
    fn template_bytes_excludes_constants_table_for_segregated_tree() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: placeholder_body(),
        };
        let full = roundtrip_bytes(&tree);
        let tmpl = template_bytes(&tree).unwrap();
        // Full layout (no has_size): [header=0x10][const_count=0x01]
        // [const_type=0x01][const_val=0x01][body opcode 0x73][index 0x00]
        // = 6 bytes. Template = body only = [0x73, 0x00] = 2 bytes.
        assert_eq!(full.len(), 6);
        assert_eq!(tmpl, vec![0x73, 0x00]);
    }

    /// `template_hash` is exactly `blake2b256(template_bytes)`.
    #[test]
    fn template_hash_is_blake2_of_template_bytes() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        let tmpl = template_bytes(&tree).unwrap();
        let expected = *blake2b256(&tmpl).as_bytes();
        assert_eq!(template_hash(&tree).unwrap(), expected);
    }

    /// Emission-contract self-consistency: parsing a known mainnet tree
    /// then taking `template_hash` of the parsed value must equal taking
    /// `template_hash_from_bytes` of the original bytes. This is the
    /// API-surface invariant the indexer apply path relies on (it has
    /// the parsed tree in hand) versus the byErgoTree route (which
    /// receives raw bytes from the client).
    #[test]
    fn template_hash_self_consistent_for_emission_contract() {
        let hex = "101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f";
        let bytes = hex::decode(hex).unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        assert!(r.is_empty());

        let from_parsed = template_hash(&tree).unwrap();
        let from_bytes = template_hash_from_bytes(&bytes).unwrap();
        assert_eq!(from_parsed, from_bytes);
    }

    /// Block 1,702,686 size-flagged non-SigmaProp tree must surface as
    /// `Unparseable` from the bytes path so the indexer can skip
    /// recording an entry rather than emitting a hash that would
    /// collide across every soft-fork-wrapped tree on the chain.
    #[test]
    fn template_hash_from_bytes_unparseable_for_block_1702686() {
        let hex = "092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402";
        let bytes = hex::decode(hex).unwrap();
        match template_hash_from_bytes(&bytes) {
            Err(TemplateHashError::Unparseable) => {}
            other => panic!("expected Unparseable, got {other:?}"),
        }
    }

    /// A v4 tree (version > MAX_SUPPORTED_TREE_VERSION = 3) is wrapped
    /// by the version-soft-fork branch and must also surface as
    /// `Unparseable`.
    #[test]
    fn template_hash_from_bytes_unparseable_for_v4_softfork() {
        // Header: 0x0C = v=4, has_size=true, no cseg. Size VLQ(1)=0x01.
        // Body: one arbitrary byte (0x00) — never parsed because version
        // exceeds MAX_SUPPORTED_TREE_VERSION, so the wrap branch fires.
        let bytes = hex::decode("0C0100").unwrap();
        match template_hash_from_bytes(&bytes) {
            Err(TemplateHashError::Unparseable) => {}
            other => panic!("expected Unparseable for v4 tree, got {other:?}"),
        }
    }

    /// Every mainnet vector that the existing roundtrip test exercises
    /// must also produce a template hash without surfacing
    /// `Unparseable` — the corpus is curated to be parseable. Also
    /// confirms `template_hash(parsed) == template_hash_from_bytes(raw)`
    /// for each, which is the indexer-vs-API-route consistency contract.
    #[test]
    fn template_hash_consistent_across_mainnet_vectors() {
        #[derive(serde::Deserialize)]
        struct TestVector {
            #[allow(dead_code)]
            source: String,
            bytes: String,
        }

        let json_data = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/ergotrees_1_10.json"
        ))
        .expect("test vectors file");
        let vectors: Vec<TestVector> = serde_json::from_str(&json_data).expect("parse JSON");

        for (i, tv) in vectors.iter().enumerate() {
            let raw = hex::decode(&tv.bytes).unwrap_or_else(|e| panic!("vector {i}: bad hex: {e}"));
            let mut r = VlqReader::new(&raw);
            let tree = read_ergo_tree(&mut r)
                .unwrap_or_else(|e| panic!("vector {i} ({}): parse failed: {e}", tv.source));

            let from_parsed = template_hash(&tree)
                .unwrap_or_else(|e| panic!("vector {i} ({}): template_hash: {e}", tv.source));
            let from_bytes = template_hash_from_bytes(&raw).unwrap_or_else(|e| {
                panic!("vector {i} ({}): template_hash_from_bytes: {e}", tv.source)
            });
            assert_eq!(
                from_parsed, from_bytes,
                "vector {i} ({}): parsed/bytes hash mismatch",
                tv.source
            );
        }
    }

    // ----- check_v3_only_methods (box-deserialize v6-in-pre-v3 gate) -----

    fn parse_tree(hex_str: &str) -> ErgoTree {
        let bytes = hex::decode(hex_str).unwrap();
        read_ergo_tree(&mut VlqReader::new(&bytes)).expect("tree parses")
    }

    /// A SIZELESS pre-v3 tree carrying a v6 method (`SGlobal.none[Int]`, 106/10)
    /// is rejected — Scala re-raises the method-resolution `ValidationException`
    /// because there is no size bit to soft-fork-wrap it.
    #[test]
    fn check_v3_only_methods_rejects_sizeless_pre_v3_v6() {
        let tree = parse_tree("1000d1efe6db6a0add04");
        assert_eq!(tree.version, 0);
        assert!(!tree.has_size);
        let err = check_v3_only_methods(&tree).expect_err("sizeless v0 + v6 method must reject");
        assert!(
            matches!(&err, ReadError::InvalidData(m) if m.contains("requires ErgoTree version >= 3")),
            "got {err:?}",
        );
    }

    /// The SAME body with the SIZE bit set must NOT be rejected here: Scala
    /// catches the `ValidationException` and stores the tree as
    /// `UnparsedErgoTree` (rejected later on spend, which the evaluator gate
    /// handles). Gating it at box-parse would be reject-valid.
    #[test]
    fn check_v3_only_methods_accepts_size_flagged_pre_v3_v6() {
        let tree = parse_tree("180900d1efe6db6a0add04");
        assert_eq!(tree.version, 0);
        assert!(tree.has_size);
        assert!(check_v3_only_methods(&tree).is_ok());
    }

    /// KNOWN DIVERGENCE B (reject-valid, adversarial) — pinned, not yet fixed.
    ///
    /// A size-flagged pre-v3 tree whose body places an off-curve GroupElement
    /// constant AFTER a v6-only method (`SBox.getReg[Int]`, 99/19) in
    /// serialization order. Scala's `deserializeErgoTree` throws the v6 method's
    /// `ValidationException` while parsing the body and — because `has_size` —
    /// wraps the tree as `UnparsedErgoTree`, so the trailing off-curve GE is
    /// NEVER decoded/curve-checked and the box is ACCEPTED at creation
    /// (ErgoTreeSerializer.scala:166,196; GroupElementSerializer decodes a point
    /// only once the reader reaches it).
    ///
    /// This node parses version-independently (the v6 method id parses fine and
    /// is gated only at EVAL), so the whole body is read, the off-curve GE is
    /// recorded on the reader's group-element sideband, and the tree is returned
    /// PARSED. The downstream tx chokepoint (`validate_group_elements`) then
    /// curve-rejects that GE → the box is REJECTED at creation. Scala accepts,
    /// we reject: a reject-valid / liveness stall reachable by a Scala miner.
    ///
    /// The SOUND fix is parser-side checkpointing — record the sideband length
    /// at the exact point Scala would throw (after a v6 method's receiver+args,
    /// before its type args) and, only at this version-aware layer, wrap as
    /// `Unparsed` and forward just that GE prefix. A naive "drop every GE after
    /// the first v6 method" is UNSOUND: Scala throws AFTER the method's own
    /// receiver/args, so an off-curve GE inside them must still reject (else
    /// accept-invalid). Deferred pending Scala oracle vectors. This test pins the
    /// CURRENT (divergent) behavior: the post-method GE IS collected (hence
    /// rejected downstream).
    #[test]
    fn known_divergence_offcurve_ge_after_v6_method_is_collected() {
        let mut off_curve = [0xffu8; 33];
        off_curve[0] = 0x02; // off-curve x (cf. trivial_p2pk_offcurve_ge_constant_rejects)

        let v6_method = Expr::Op(crate::opcode::IrNode {
            opcode: 0xDC,
            payload: crate::opcode::Payload::MethodCall {
                type_id: 99,
                method_id: 19, // SBox.getReg[T] — v6-only
                obj: Box::new(Expr::Op(crate::opcode::IrNode {
                    opcode: 0xA7, // Self
                    payload: crate::opcode::Payload::Zero,
                })),
                args: vec![Expr::Op(crate::opcode::IrNode {
                    opcode: 0xA3, // a 0-arg leaf in the reg-id slot
                    payload: crate::opcode::Payload::Zero,
                })],
                type_args: vec![SigmaType::SInt],
            },
        });
        let ge_after = Expr::Const {
            tpe: SigmaType::SGroupElement,
            val: SigmaValue::GroupElement(GroupElement::from_bytes(off_curve)),
        };
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            // Plus(v6_method, ge_after): the GE is parsed AFTER the method.
            body: Expr::Op(crate::opcode::IrNode {
                opcode: 0x9A,
                payload: crate::opcode::Payload::Two(Box::new(v6_method), Box::new(ge_after)),
            }),
        };

        // The v6 method is present (gated at eval) and box-parse does NOT reject
        // a size-flagged tree — Scala wraps, we parse; both accept at creation.
        assert_eq!(
            crate::opcode::find_v3_only_method(&tree.body),
            Some((99, 19))
        );
        assert!(check_v3_only_methods(&tree).is_ok());

        let bytes = roundtrip_bytes(&tree);
        let mut r = VlqReader::new(&bytes);
        let decoded = read_ergo_tree(&mut r).expect("parses version-independently");
        assert!(
            !matches!(decoded.body, Expr::Unparsed(_)),
            "size-flagged v6 tree is parsed, not wrapped (divergence vs Scala's wrap)"
        );
        // THE DIVERGENCE: the off-curve GE sitting AFTER the v6 method was still
        // collected, so the downstream curve-check rejects it — where Scala
        // wrapped before reaching it and accepts.
        let collected = r.take_group_elements();
        assert!(
            collected.iter().any(|ge| ge == &off_curve),
            "post-v6-method off-curve GE is collected (would be rejected downstream)"
        );
    }

    /// A valid sizeless tree with no v6 method passes.
    #[test]
    fn check_v3_only_methods_accepts_valid_sizeless_tree() {
        let tree = parse_tree("0008d3");
        assert!(check_v3_only_methods(&tree).is_ok());
    }

    /// Regression: an `SBox` constant whose sizeless pre-v3 inner tree carries a
    /// v6 method, embedded in the constants table of a SIZE-DELIMITED outer
    /// tree, must REJECT. The nested `HardReject` must NOT be swallowed into an
    /// `UnparsedErgoTree` by the outer tree's soft-fork wrap (Scala re-raises the
    /// nested `SerializerException`, which the enclosing tree's deserialize does
    /// not catch).
    #[test]
    fn nested_box_constant_v6_in_size_delimited_outer_hard_rejects() {
        // Inner box: sizeless v0 tree carrying SGlobal.none[Int].
        let mut bw = ergo_primitives::writer::VlqWriter::new();
        bw.put_u64(1_000_000);
        bw.put_bytes(&hex::decode("1000d1efe6db6a0add04").unwrap());
        bw.put_u32(100);
        bw.put_u8(0);
        bw.put_u8(0);
        bw.put_bytes(&[0u8; 32]);
        bw.put_u16(0);
        let inner_box = bw.result();

        let outer = ErgoTree {
            version: 0,
            has_size: true, // SIZE-DELIMITED outer — the soft-fork-wrap path
            constant_segregation: true,
            constants: vec![(SigmaType::SBox, SigmaValue::OpaqueBoxBytes(inner_box))],
            body: placeholder_body(),
        };
        let mut w = ergo_primitives::writer::VlqWriter::new();
        write_ergo_tree(&mut w, &outer).unwrap();
        let outer_bytes = w.result();

        let err = read_ergo_tree(&mut VlqReader::new(&outer_bytes)).expect_err(
            "a nested v6 box constant under a size-delimited outer tree must hard-reject",
        );
        assert!(matches!(err, ReadError::HardReject(_)), "got {err:?}");
    }

    /// Contrast with the v6 case: a nested `SBox` constant whose inner tree
    /// violates rule 1012 (`version != 0`, sizeless) is a Scala
    /// `ValidationException` (thrown in `deserializeHeaderAndSize`, before the
    /// inner catch), so a SIZE-DELIMITED outer tree WRAPS it as
    /// `UnparsedErgoTree` rather than rejecting — the rule-1012 nested rejection
    /// must therefore be SOFT (`InvalidData`), not `HardReject`. Rejecting here
    /// would be reject-valid.
    #[test]
    fn nested_box_constant_rule1012_in_size_delimited_outer_wraps() {
        // Inner box: sizeless version-1 tree (header 0x01) — rule-1012 violation.
        let mut bw = ergo_primitives::writer::VlqWriter::new();
        bw.put_u64(1_000_000);
        bw.put_bytes(&hex::decode("01d3").unwrap());
        bw.put_u32(100);
        bw.put_u8(0);
        bw.put_u8(0);
        bw.put_bytes(&[0u8; 32]);
        bw.put_u16(0);
        let inner_box = bw.result();

        let outer = ErgoTree {
            version: 0,
            has_size: true, // SIZE-DELIMITED outer — must WRAP a nested ValidationException
            constant_segregation: true,
            constants: vec![(SigmaType::SBox, SigmaValue::OpaqueBoxBytes(inner_box))],
            body: placeholder_body(),
        };
        let mut w = ergo_primitives::writer::VlqWriter::new();
        write_ergo_tree(&mut w, &outer).unwrap();
        let outer_bytes = w.result();

        let (tree, was_wrapped) = read_ergo_tree_tracking_wrap(&mut VlqReader::new(&outer_bytes))
            .expect(
            "a nested rule-1012 box constant under a size-delimited outer must WRAP, not reject",
        );
        assert!(
            was_wrapped,
            "the outer tree must be wrapped as UnparsedErgoTree, not parsed",
        );
        let _ = tree;
    }

    // ----- unparsed (soft-fork-wrapped) tree: verbatim round-trip -----

    /// A size-delimited tree whose body cannot be parsed is wrapped as
    /// `Expr::Unparsed` holding the FULL original bytes, and re-serializes
    /// BYTE-IDENTICAL — matching Scala's preserved `propositionBytes`. (The
    /// prior `Const(true)` substitution lost the bytes, changing the
    /// `propositionBytes` / boxId on re-serialization.)
    #[test]
    fn unparsed_soft_fork_tree_roundtrips_byte_identical() {
        for hex_str in [
            "0b01fd",     // v3 + size, 1-byte unknown-opcode body 0xfd
            "0b03fd0102", // v3 + size, 3-byte unknown-opcode body
            "1c020008",   // v4 (> MAX_SUPPORTED) + size, opaque body — version soft-fork
        ] {
            let bytes = hex::decode(hex_str).unwrap();
            let tree = read_ergo_tree(&mut VlqReader::new(&bytes))
                .unwrap_or_else(|e| panic!("{hex_str} must parse (soft-fork wrap): {e:?}"));
            assert!(
                matches!(tree.body, crate::opcode::Expr::Unparsed(_)),
                "{hex_str} must wrap to Expr::Unparsed, got {:?}",
                tree.body
            );
            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &tree).unwrap();
            assert_eq!(
                w.result(),
                bytes,
                "{hex_str} must re-serialize byte-identical"
            );
        }
    }
}
