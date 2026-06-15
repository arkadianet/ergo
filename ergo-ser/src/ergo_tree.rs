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
    let header = r.get_u8()?;
    let version = header & VERSION_MASK;
    let has_size = header & SIZE_FLAG != 0;
    let constant_segregation = header & CONSTANT_SEGREGATION_FLAG != 0;

    if has_size {
        let size = r.get_u32_exact()? as usize;
        let bounded_data = r.get_bytes(size)?;

        // Soft-fork: trees with version > our max are accepted without parsing.
        // The Scala auto-accepts these in Interpreter.checkSoftForkCondition.
        // We still need to consume the bytes (via get_bytes above) but skip body parsing.
        if version > MAX_SUPPORTED_TREE_VERSION {
            return Ok((
                unparsed_soft_fork_tree(version, has_size, constant_segregation),
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
        match parse_body(&mut inner, version, has_size, constant_segregation) {
            Ok(tree) => {
                if let crate::opcode::Expr::Const { tpe, .. } = &tree.body {
                    if *tpe != crate::sigma_type::SigmaType::SSigmaProp {
                        // root is a non-SigmaProp constant → Scala's
                        // CheckDeserializedScriptIsSigmaProp equivalent.
                        return Ok((
                            unparsed_soft_fork_tree(version, has_size, constant_segregation),
                            true,
                        ));
                    }
                }
                Ok((tree, false))
            }
            // A tree-depth overflow is Scala's `DeserializeCallDepthExceeded`,
            // a `SerializerException` that `deserializeErgoTree` does NOT catch
            // (it only wraps ReaderPositionLimitExceeded / IllegalArgumentException
            // / ValidationException). So it must HARD-REJECT even under has_size,
            // not become an UnparsedErgoTree — otherwise a size-delimited tree
            // nested past MaxTreeDepth would be accept-invalid vs Scala.
            Err(e @ ReadError::DepthLimitExceeded { .. }) => Err(e),
            Err(_) => {
                // Other parse failures (unknown opcode, invalid type tag) map to
                // Scala's ValidationException, which under has_size is wrapped
                // as UnparsedErgoTree (the soft-fork-compatible path).
                Ok((
                    unparsed_soft_fork_tree(version, has_size, constant_segregation),
                    true,
                ))
            }
        }
    } else {
        parse_body(r, version, has_size, constant_segregation).map(|tree| (tree, false))
    }
}

/// Construct a soft-fork-accepted ErgoTree: the outer flags are preserved
/// (so re-serialization can reproduce the correct header) but the body is
/// a trivial `true` constant. Used for:
/// - trees whose `version > MAX_SUPPORTED_TREE_VERSION` (version-based soft-fork)
/// - trees with `has_size` whose body fails to parse OR leaves residual
///   bytes after parsing (validation-triggered soft-fork, matches
///   Scala's UnparsedErgoTree path)
fn unparsed_soft_fork_tree(version: u8, has_size: bool, constant_segregation: bool) -> ErgoTree {
    ErgoTree {
        version,
        has_size,
        constant_segregation,
        constants: vec![],
        body: crate::opcode::Expr::Const {
            tpe: crate::sigma_type::SigmaType::SBoolean,
            val: crate::sigma_value::SigmaValue::Boolean(true),
        },
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
    fn simple_body() -> Body {
        Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
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
            body: simple_body(),
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
            body: simple_body(),
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
        let tree = ErgoTree {
            version: 1,
            has_size: true,
            constant_segregation: true,
            constants: vec![
                (SigmaType::SInt, SigmaValue::Int(-7)),
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
            body: simple_body(),
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
    /// Our parser must NOT raise on this input. It must accept and
    /// return a soft-fork-style tree (body = always-true boolean).
    /// Regression guard for sync stalling at block 1702686.
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
        // Body should be the always-true placeholder from
        // unparsed_soft_fork_tree, matching Scala's soft-fork acceptance.
        match &tree.body {
            Expr::Const { tpe, val } => {
                assert_eq!(*tpe, SigmaType::SBoolean);
                match val {
                    SigmaValue::Boolean(b) => {
                        assert!(*b, "unparsed wrap must evaluate to always-true")
                    }
                    _ => panic!("unexpected soft-fork body value: {val:?}"),
                }
            }
            other => panic!("expected Const(SBoolean=true) soft-fork body, got {other:?}"),
        }
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
}
