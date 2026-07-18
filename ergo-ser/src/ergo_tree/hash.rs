//! Indexer-facing hash utilities: canonical tree hash
//! (`IndexedErgoAddressSerializer.hashErgoTree`) and template bytes /
//! template hash (`ErgoTree.template` / `hashTreeTemplate`).

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

use super::{read_ergo_tree, read_ergo_tree_tracking_wrap, write_ergo_tree, ErgoTree};

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
    // Reject trailing bytes: `valid_tree ++ junk` must not hash to the same
    // key as the canonical tree (a malformed input resolving to the same
    // index key as a real address).
    if !reader.is_empty() {
        return Err(TreeHashError::Parse(ReadError::InvalidData(
            "trailing bytes after ergoTree".into(),
        )));
    }
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
    // A soft-fork-wrapped tree has an `Expr::Unparsed` whole-tree body with no
    // meaningful template. Honor the documented contract by returning
    // `Unparseable` rather than passing `Expr::Unparsed` to `template_bytes`
    // (which surfaces a generic `Write` error).
    if matches!(tree.body, crate::opcode::Expr::Unparsed(_)) {
        return Err(TemplateHashError::Unparseable);
    }
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
    if !reader.is_empty() {
        return Err(TemplateHashError::Parse(ReadError::InvalidData(
            "trailing bytes after ergoTree".into(),
        )));
    }
    if was_wrapped {
        return Err(TemplateHashError::Unparseable);
    }
    template_hash(&tree)
}
