//! Indexer-facing hash utilities: received tree hash
//! (`IndexedErgoAddressSerializer.hashErgoTree`) and template bytes /
//! template hash (`ErgoTree.template` / `hashTreeTemplate`).

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

use super::{read::read_ergo_tree_tracking_template, read_ergo_tree, ErgoTree};

/// Failure modes for [`tree_hash_from_bytes`]. The byte helper validates
/// parsing and consumption without re-serializing the received tree.
#[derive(Debug)]
pub enum TreeHashError {
    /// Input bytes could not be parsed into an `ErgoTree`.
    Parse(ReadError),
    /// Retained for source compatibility; the byte helper no longer serializes.
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

/// Scala's `IndexedErgoAddressSerializer.hashErgoTree(tree)` for received
/// bytes: validate one complete tree, then hash those exact bytes.
///
/// Scala's parsed `ErgoTree.bytes` caches the received encoding. Accepted
/// non-canonical encodings can serialize differently, so normalizing here would
/// choose a different key from the indexer's received-byte address key.
/// This query helper retains its complete-input policy; it does not change the
/// streaming consensus reader or its acceptance gates.
pub fn tree_hash_from_bytes(tree_bytes: &[u8]) -> Result<[u8; 32], TreeHashError> {
    let mut reader = VlqReader::new(tree_bytes);
    read_ergo_tree(&mut reader).map_err(TreeHashError::Parse)?;
    // Keep the query helper's existing complete-input contract.
    if !reader.is_empty() {
        return Err(TreeHashError::Parse(ReadError::InvalidData(
            "trailing bytes after ergoTree".into(),
        )));
    }
    Ok(*blake2b256(tree_bytes).as_bytes())
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

/// Serialize the structured body of an `ErgoTree`, without its header or
/// constants. This is the template for a newly constructed tree.
///
/// An AST does not retain a parsed tree's original expression encoding. Use
/// [`template_hash_from_bytes`] when hashing a received tree's cached template;
/// it preserves accepted non-canonical body encodings and placeholders.
pub fn template_bytes(tree: &ErgoTree) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    crate::opcode::write_body(&mut w, &tree.body, tree.constant_segregation)?;
    Ok(w.result())
}

/// Hash the serialized template of a structured or newly constructed tree.
/// Use [`template_hash_from_bytes`] for a received tree's cached-byte identity.
/// Soft-fork-wrapped trees have no structured template.
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

/// Hash the original expression slice of one completely parsed tree,
/// excluding its received header, size field and segregated constants.
/// This mirrors Scala's cached `ErgoTree.template`; expression normalization
/// cannot change the index key. Soft-fork-wrapped trees keep the existing
/// `Unparseable` result.
pub fn template_hash_from_bytes(tree_bytes: &[u8]) -> Result<[u8; 32], TemplateHashError> {
    let mut reader = VlqReader::new(tree_bytes);
    let (_tree, was_wrapped, template) =
        read_ergo_tree_tracking_template(&mut reader).map_err(TemplateHashError::Parse)?;
    if !reader.is_empty() {
        return Err(TemplateHashError::Parse(ReadError::InvalidData(
            "trailing bytes after ergoTree".into(),
        )));
    }
    if was_wrapped {
        return Err(TemplateHashError::Unparseable);
    }
    let template = template.ok_or(TemplateHashError::Unparseable)?;
    Ok(*blake2b256(&tree_bytes[template]).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- pinned cached-byte identity -----

    #[test]
    fn received_tree_and_template_hashes_preserve_scala_cached_bytes() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/tree-cached-identity/cases.json"
        ))
        .unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            let input = hex::decode(case["tree_hex"].as_str().unwrap()).unwrap();
            let cached = hex::decode(case["cached_tree_hex"].as_str().unwrap()).unwrap();
            let template = hex::decode(case["cached_template_hex"].as_str().unwrap()).unwrap();
            let mut reader = VlqReader::new(&input);
            reader.set_activated_script_version(Some(
                case["activated_version"].as_u64().unwrap() as u8
            ));
            let tree = read_ergo_tree(&mut reader).unwrap();
            assert_eq!(
                reader.position(),
                case["consumed"].as_u64().unwrap() as usize
            );
            assert!(reader.is_empty());
            let mut writer = VlqWriter::new();
            super::super::write_ergo_tree(&mut writer, &tree).unwrap();
            assert_eq!(
                hex::encode(writer.result()),
                case["serialized_tree_hex"].as_str().unwrap()
            );
            assert_eq!(
                tree_hash_from_bytes(&input).unwrap(),
                *blake2b256(&cached).as_bytes()
            );
            assert_eq!(
                template_hash_from_bytes(&input).unwrap(),
                *blake2b256(&template).as_bytes()
            );
            assert_ne!(
                template_hash(&tree).unwrap(),
                template_hash_from_bytes(&input).unwrap()
            );
        }
    }

    #[test]
    fn received_identity_helpers_keep_complete_input_and_wrap_policy() {
        let mut trailing = hex::decode("1000d17f").unwrap();
        trailing.push(0);
        assert!(matches!(
            tree_hash_from_bytes(&trailing),
            Err(TreeHashError::Parse(_))
        ));
        assert!(matches!(
            template_hash_from_bytes(&trailing),
            Err(TemplateHashError::Parse(_))
        ));
        assert!(matches!(
            template_hash_from_bytes(&hex::decode("0b01fd").unwrap()),
            Err(TemplateHashError::Unparseable)
        ));
    }
}
