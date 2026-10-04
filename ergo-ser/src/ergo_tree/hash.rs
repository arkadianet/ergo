//! Indexer-facing hash utilities: received tree hash
//! (`IndexedErgoAddressSerializer.hashErgoTree`) and template bytes /
//! template hash (`ErgoTree.template` / `hashTreeTemplate`).

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

use super::read::{read_ergo_tree_tracking_template, wrapped_tree_template};
use super::{read_ergo_tree, ErgoTree};

/// Failure modes for [`tree_hash_from_bytes`]. The byte helper validates
/// parsing and consumption without re-serializing the received tree.
#[derive(Debug)]
pub enum TreeHashError {
    /// Input bytes could not be parsed into an `ErgoTree`.
    Parse(ReadError),
    /// Never constructed: the byte helper no longer serializes. Retained for
    /// source compatibility with exhaustive matches.
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
/// [`TreeHashError`] because the structured [`template_hash`] has the extra
/// `Unparseable` case. [`template_hash_from_bytes`] returns only `Parse`.
#[derive(Debug)]
pub enum TemplateHashError {
    /// Input bytes could not be parsed into an `ErgoTree`.
    Parse(ReadError),
    /// [`template_hash`] only: the structured body failed to serialize.
    Write(WriteError),
    /// [`template_hash`] only: a soft-fork-wrapped tree has no structured
    /// body to serialize. Its received bytes still have Scala's cached
    /// template; hash them with [`template_hash_from_bytes`].
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
    // structured template. Honor the documented contract by returning
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
/// This mirrors Scala's `IndexedContractTemplateSerializer.hashTreeTemplate`
/// over the cached `ErgoTree.template`; expression normalization cannot change
/// the index key. A soft-fork-wrapped tree keeps its received bytes, and Scala
/// still derives a template from them by re-reading the header, size and
/// constants; when that re-read throws, `hashTreeTemplate` hashes the whole
/// tree bytes. Only a parse failure of the input itself is an error.
pub fn template_hash_from_bytes(tree_bytes: &[u8]) -> Result<[u8; 32], TemplateHashError> {
    let mut reader = VlqReader::new(tree_bytes);
    let (_tree, was_wrapped, template) =
        read_ergo_tree_tracking_template(&mut reader).map_err(TemplateHashError::Parse)?;
    if !reader.is_empty() {
        return Err(TemplateHashError::Parse(ReadError::InvalidData(
            "trailing bytes after ergoTree".into(),
        )));
    }
    let template = if was_wrapped {
        wrapped_tree_template(tree_bytes)
    } else {
        template
    };
    let hashed = template.map_or(tree_bytes, |range| &tree_bytes[range]);
    Ok(*blake2b256(hashed).as_bytes())
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
    fn received_identity_helpers_keep_complete_input_policy() {
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
    }

    /// Expected templates come from sigma-state 6.0.6 (Maven Central jar,
    /// sha1 e7dcc53775ed64daaa2f159eb781340b35dc3f4a) driven from Java: each
    /// tree was read with `deserializeErgoTree(reader, 4096)` under
    /// `VersionContext.withVersions(a, 0)` for activated versions a = 1, 2, 3,
    /// then `withVersions(3, 3) { tree.template }` as in ergo-scala's
    /// `hashTreeTemplate`. Every tree parsed with `root.isRight == false` and
    /// the same template at each accepted version (`0b01fd` is rejected at
    /// activation 2). `None` marks a template that threw, where
    /// `hashTreeTemplate` hashes the whole `tree.bytes` (here, the input).
    #[test]
    fn wrapped_trees_hash_the_scala_cached_template() {
        // Mainnet block 1,702,686 output: v1, sized, non-SigmaProp root.
        let block_1702686 = "092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402";
        let cases = [
            (block_1702686, Some(&block_1702686[4..])),
            ("0b01fd", Some("fd")),
            ("08020101", Some("0101")),
            // Segregated constants are stripped as for a parsed tree.
            ("18050101017300", Some("7300")),
            // A v3-only constant type wraps this v0 tree, but `template`
            // re-reads the constants with the (3, 3) type table.
            ("180601090105d17f", Some("d17f")),
            // Constants after the wrapping one still fail the re-read.
            ("180502090105ff", None),
            ("180402090105", None),
            ("18050209010500", None),
        ];
        for (tree_hex, template_hex) in cases {
            let bytes = hex::decode(tree_hex).unwrap();
            let mut reader = VlqReader::new(&bytes);
            let (tree, wrapped, _) = read_ergo_tree_tracking_template(&mut reader).unwrap();
            assert!(wrapped && reader.is_empty(), "{tree_hex}");
            assert!(matches!(
                template_hash(&tree),
                Err(TemplateHashError::Unparseable)
            ));
            let hashed = template_hex.map_or(bytes.clone(), |t| hex::decode(t).unwrap());
            assert_eq!(
                template_hash_from_bytes(&bytes).unwrap(),
                *blake2b256(&hashed).as_bytes(),
                "{tree_hex}"
            );
        }
        // The key Scala serves under /blockchain/box/byTemplateHash.
        assert_eq!(
            hex::encode(template_hash_from_bytes(&hex::decode(block_1702686).unwrap()).unwrap()),
            "c7f899c5518eddc86a5052a932551fd54706cd8d12641150b160c25cdbd4befd"
        );
    }
}
