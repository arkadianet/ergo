use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::error::WriteError;
use ergo_ser::opcode::{parse_expr, write_expr_segregating, ConstantSink, Expr};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

/// The output of a successful [`crate::compile`]: the assembled tree, its wire
/// bytes, and both script-address encodings.
#[derive(Debug, Clone, PartialEq)]
pub struct CompileResult {
    /// Canonical wire bytes of `ergo_tree` (`write_ergo_tree` output).
    pub tree_bytes: Vec<u8>,
    /// The assembled tree: header version = the requested `tree_version`,
    /// size bit iff `tree_version > 0` (Scala
    /// `defaultHeaderWithVersion(treeVersion)`, `ScriptApiRoute.scala:58`);
    /// constant-segregated unless the root is a bare `SigmaPropConstant` —
    /// the D-C1 flip.
    pub ergo_tree: ErgoTree,
    /// Pay-to-Script address over the FULL `tree_bytes`
    /// (`ergo_ser::address::encode_p2s`). Deliberately NOT routed through
    /// `encode_address`/`encode_address_from_tree_bytes`: the compile surface
    /// always answers P2S (Scala `Pay2SAddress(tree)`), even when the tree is
    /// a bare `SigmaPropConstant(ProveDlog)` that the wallet-side
    /// `fromProposition` routing would render as P2PK.
    pub p2s_address: String,
    /// Pay-to-Script-Hash address over the PROPOSITION bytes (root
    /// expression only, no tree header/constants wrapper) — Scala
    /// `Pay2SHAddress(prop)`, `ErgoAddress.scala:201-218`.
    pub p2sh_address: String,
}

/// `true` when `root` is a bare `SigmaPropConstant` — the ONE class Scala's
/// `fromProposition` routes to `withoutSegregation` (header `0x00`, inline).
/// The check is on the ROOT node only: a `SigmaPropConstant` nested inside a
/// larger proposition is just another constant that segregates like any other.
pub(crate) fn is_bare_sigma_prop_constant(root: &Expr) -> bool {
    matches!(
        root,
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(_),
        }
    )
}

/// Constant segregation — Scala's `ErgoTree.withSegregation`
/// (`ErgoTree.scala:384-398`), a literal write→re-read round trip:
///
/// 1. serialize `root` through [`write_expr_segregating`] with a fresh
///    [`ConstantSink`]: every `Expr::Const` is appended to the sink (slot =
///    first-write order, append-only, NO dedup) and a `ConstPlaceholder(index)`
///    is written in its place — the SAME writer traversal as the plain path, so
///    the slot order IS the serialization pre-order and the Relation2 `0x85`
///    bool-pair compaction is bypassed for free (it never reaches the
///    `Expr::Const` arm);
/// 2. re-read those bytes with [`parse_expr`] to materialize the
///    placeholder-bearing body — we do NOT hand-build the placeholder tree,
///    mirroring Scala's `ValueSerializer.deserialize(r)` step exactly.
///
/// Returns `(placeholder_body, constants_table)`. A re-read failure of bytes we
/// just wrote is an internal invariant violation (the SAME reader accepts every
/// real chain tree), surfaced as [`WriteError::InvalidData`] rather than
/// `.unwrap()`-ing in library code.
fn segregate(root: &Expr) -> Result<(Expr, Vec<(SigmaType, SigmaValue)>), WriteError> {
    let mut sink = ConstantSink::new();
    let mut w = VlqWriter::new();
    write_expr_segregating(&mut w, root, &mut sink)?;
    let bytes = w.result();

    let mut r = VlqReader::new(&bytes);
    // tree_version 0: the segregation re-read is version-independent (opcode-
    // driven); a `0x73` byte parses as ConstPlaceholder regardless.
    let body = parse_expr(&mut r, 0, 0).map_err(|e| {
        WriteError::InvalidData(format!("constant-segregation re-read failed: {e:?}"))
    })?;
    if !r.is_empty() {
        return Err(WriteError::InvalidData(
            "constant-segregation re-read left trailing bytes".into(),
        ));
    }
    Ok((body, sink.into_constants()))
}

/// Assemble the ErgoTree around an emitted root expression.
///
/// Mirrors `ErgoTree.fromProposition(header, prop)` (sigma-state 6.0.2,
/// `core/.../sigma/ast/ErgoTree.scala:344-349`):
///
/// ```text
/// prop match {
///   case SigmaPropConstant(_) => withoutSegregation(header, prop)   // header 0x00
///   case _                    => withSegregation(header, prop)      // header 0x10
/// }
/// ```
///
/// **The D-C1 flip** (header bytes quoted for `tree_version = 0`; at v3 they
/// are `0x0b`/`0x1b`): a bare-constant root (e.g. `PK("...")` →
/// `SigmaPropConstant`) takes `withoutSegregation` — header `0x00`, empty
/// constants table, the constant itself as the body (byte-identical to Scala on
/// both sides). EVERY other root takes `withSegregation` via [`segregate`] —
/// header `0x10`, constants pulled into the table, `ConstPlaceholder` nodes in
/// the body. Both forms are valid, parseable, semantically equal trees.
///
/// Header provenance (route fact): the header is
/// `ErgoTree.defaultHeaderWithVersion(treeVersion)` — the node's
/// `ScriptApiRoute.compileSource` forwards its `treeVersion` request parameter
/// straight into the header (`ScriptApiRoute.scala:58`, ergo 6.0.7/6.0.8;
/// `ScriptApiRouteSpec` asserts header `0x10` at `treeVersion = 0` and `0x19`
/// at `treeVersion = 1`). So `version = tree_version`, and `has_size` is set
/// iff `tree_version > 0` (`ErgoTree.setRequiredBits`). `tree_version = 0`
/// therefore yields the historical `0x00` / `0x10` headers byte-for-byte.
///
/// `tree_version >= 8` does not fit the 3-bit version field; Scala's
/// `setVersionBits` `require(version < 8)` throws, and this returns
/// [`WriteError::InvalidData`].
pub(crate) fn build_tree(root: Expr, tree_version: u8) -> Result<ErgoTree, WriteError> {
    if tree_version >= 8 {
        return Err(WriteError::InvalidData(format!(
            "ErgoTree.version should be < 8: {tree_version}"
        )));
    }
    let has_size = tree_version > 0;
    if is_bare_sigma_prop_constant(&root) {
        Ok(ErgoTree {
            version: tree_version,
            has_size,
            constant_segregation: false,
            reserved_header_bits: 0,
            constants: vec![],
            body: root,
        })
    } else {
        let (body, constants) = segregate(&root)?;
        Ok(ErgoTree {
            version: tree_version,
            has_size,
            constant_segregation: true,
            reserved_header_bits: 0,
            constants,
            body,
        })
    }
}
