//! Block-level validation: root hash checks and section header_id consistency.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ergo_types::modifier_id::{Digest32, ModifierId};
use ergo_types::transaction::ErgoFullBlock;

use crate::merkle::{empty_merkle_root, merkle_root};
use crate::validation_rules::ValidationSettings;

/// Errors arising from block-level validation.
#[derive(Debug, thiserror::Error)]
pub enum BlockValidationError {
    #[error("transactions root mismatch: expected {expected:?}, got {got:?}")]
    TransactionsRootMismatch { expected: Digest32, got: Digest32 },
    #[error("AD proofs root mismatch: expected {expected:?}, got {got:?}")]
    AdProofsRootMismatch { expected: Digest32, got: Digest32 },
    #[error("extension root mismatch: expected {expected:?}, got {got:?}")]
    ExtensionRootMismatch { expected: Digest32, got: Digest32 },
    #[error("missing AD proofs in digest mode")]
    MissingAdProofs,
    #[error(
        "section header_id mismatch: section references {section_header_id}, expected {expected}"
    )]
    SectionHeaderMismatch {
        section_header_id: ModifierId,
        expected: ModifierId,
    },
    #[error("transaction parse error at index {index}: {error}")]
    TransactionParseError { index: usize, error: String },
}

/// Compute Blake2b-256 of raw data (no prefix).
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("correct output size");
    out
}

/// Validate a full block's root hashes against its header.
///
/// Checks:
/// 1. BlockTransactions Merkle root == header.transactions_root
/// 2. ADProofs hash == header.ad_proofs_root (when proofs present, in ALL modes)
///    2b. ADProofs presence required (digest mode only)
/// 3. Extension Merkle root == header.extension_root
/// 4. All sections reference the correct header ID
pub fn validate_full_block(
    block: &ErgoFullBlock,
    header_id: &ModifierId,
    digest_mode: bool,
    _settings: &ValidationSettings,
) -> Result<(), BlockValidationError> {
    // ── 1. Transactions root ──────────────────────────────────────────
    // Scala computes Merkle root over transaction IDs (blake2b256 of unsigned bytes),
    // NOT over raw serialized tx bytes. For v2+ blocks, witness IDs are appended.
    let mut tx_ids: Vec<[u8; 32]> = Vec::with_capacity(block.block_transactions.tx_bytes.len());
    let mut witness_ids: Vec<Vec<u8>> = Vec::new();
    let need_witness = block.block_transactions.block_version > 1;

    for (i, tx_data) in block.block_transactions.tx_bytes.iter().enumerate() {
        let tx = ergo_wire::transaction_ser::parse_transaction(tx_data).map_err(|e| {
            BlockValidationError::TransactionParseError {
                index: i,
                error: format!("{e}"),
            }
        })?;
        tx_ids.push(tx.tx_id.0);
        if need_witness {
            // witnessSerializedId = blake2b256(concat(spending_proofs)).tail (31 bytes)
            let mut concat_proofs = Vec::new();
            for input in &tx.inputs {
                concat_proofs.extend_from_slice(&input.proof_bytes);
            }
            let hash = blake2b256(&concat_proofs);
            witness_ids.push(hash[1..].to_vec()); // drop first byte → 31 bytes
        }
    }

    // Build Merkle leaves: v1 = tx_ids only; v2+ = tx_ids ++ witness_ids
    let mut leaves: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    if need_witness {
        for wid in &witness_ids {
            leaves.push(wid.as_slice());
        }
    }
    let computed_tx_root = if leaves.is_empty() {
        empty_merkle_root()
    } else {
        merkle_root(&leaves).unwrap()
    };
    if computed_tx_root != block.header.transactions_root.0 {
        return Err(BlockValidationError::TransactionsRootMismatch {
            expected: block.header.transactions_root,
            got: Digest32(computed_tx_root),
        });
    }

    // ── 2. AD proofs root ─────────────────────────────────────────────
    // Always validate AD proofs hash when proofs are present (both modes)
    if let Some(proofs) = &block.ad_proofs {
        let computed_ad_root = blake2b256(&proofs.proof_bytes);
        if computed_ad_root != block.header.ad_proofs_root.0 {
            return Err(BlockValidationError::AdProofsRootMismatch {
                expected: block.header.ad_proofs_root,
                got: Digest32(computed_ad_root),
            });
        }
    }
    // Only require AD proofs presence in digest mode
    if digest_mode && block.ad_proofs.is_none() {
        return Err(BlockValidationError::MissingAdProofs);
    }

    // ── 3. Extension root ─────────────────────────────────────────────
    // Scala kvToLeaf: [key_length_byte] ++ key ++ value
    let ext_leaves: Vec<Vec<u8>> = block
        .extension
        .fields
        .iter()
        .map(|(key, value)| {
            let mut leaf = Vec::with_capacity(1 + key.len() + value.len());
            leaf.push(key.len() as u8); // key length prefix
            leaf.extend_from_slice(key);
            leaf.extend_from_slice(value);
            leaf
        })
        .collect();
    let ext_slices: Vec<&[u8]> = ext_leaves.iter().map(|v| v.as_slice()).collect();
    let computed_ext_root = if ext_slices.is_empty() {
        empty_merkle_root()
    } else {
        merkle_root(&ext_slices).unwrap()
    };
    if computed_ext_root != block.header.extension_root.0 {
        return Err(BlockValidationError::ExtensionRootMismatch {
            expected: block.header.extension_root,
            got: Digest32(computed_ext_root),
        });
    }

    // ── 4. Section header_id consistency ──────────────────────────────
    if block.block_transactions.header_id != *header_id {
        return Err(BlockValidationError::SectionHeaderMismatch {
            section_header_id: block.block_transactions.header_id,
            expected: *header_id,
        });
    }
    if block.extension.header_id != *header_id {
        return Err(BlockValidationError::SectionHeaderMismatch {
            section_header_id: block.extension.header_id,
            expected: *header_id,
        });
    }
    if let Some(proofs) = &block.ad_proofs {
        if proofs.header_id != *header_id {
            return Err(BlockValidationError::SectionHeaderMismatch {
                section_header_id: proofs.header_id,
                expected: *header_id,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation_rules::ValidationSettings;
    use ergo_types::ad_proofs::ADProofs;
    use ergo_types::block_transactions::BlockTransactions;
    use ergo_types::extension::Extension;
    use ergo_types::header::Header;
    use ergo_types::transaction::*;
    use ergo_wire::transaction_ser::{compute_tx_id, serialize_transaction};

    fn vs() -> ValidationSettings {
        ValidationSettings::initial()
    }

    /// Empty extension bytes for context extension (count=0).
    fn empty_extension_bytes() -> Vec<u8> {
        vec![0x00]
    }

    /// Build a simple ErgoTransaction with one input and one output.
    fn make_test_tx(box_id_byte: u8, value: u64, height: u32) -> ErgoTransaction {
        let mut tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([box_id_byte; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: empty_extension_bytes(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                creation_height: height,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);
        tx
    }

    /// Compute Extension Merkle root using Scala's kvToLeaf format:
    /// leaf = [key_length_byte] ++ key ++ value
    fn extension_merkle_root(fields: &[([u8; 2], Vec<u8>)]) -> [u8; 32] {
        if fields.is_empty() {
            return blake2b256(&[]);
        }
        let leaves: Vec<Vec<u8>> = fields
            .iter()
            .map(|(k, v)| {
                let mut leaf = Vec::with_capacity(1 + k.len() + v.len());
                leaf.push(k.len() as u8);
                leaf.extend_from_slice(k);
                leaf.extend_from_slice(v);
                leaf
            })
            .collect();
        let slices: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();
        merkle_root(&slices).unwrap()
    }

    /// Compute BlockTransactions Merkle root from tx_ids (v1 format).
    fn tx_merkle_root(tx_ids: &[[u8; 32]]) -> [u8; 32] {
        if tx_ids.is_empty() {
            return blake2b256(&[]);
        }
        let slices: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
        merkle_root(&slices).unwrap()
    }

    /// Build a valid block with empty tx_bytes and empty extension fields.
    fn valid_empty_block(header_id: ModifierId) -> ErgoFullBlock {
        let empty_root = blake2b256(&[]);
        let mut header = Header::default_for_test();
        header.transactions_root = Digest32(empty_root);
        header.extension_root = Digest32(empty_root);

        ErgoFullBlock {
            header,
            block_transactions: BlockTransactions {
                header_id,
                block_version: 1,
                tx_bytes: Vec::new(),
            },
            extension: Extension {
                header_id,
                fields: Vec::new(),
            },
            ad_proofs: None,
        }
    }

    /// Build a valid block with real serialized transactions and extension fields.
    fn valid_populated_block(header_id: ModifierId) -> ErgoFullBlock {
        let tx1 = make_test_tx(0x11, 1_000_000_000, 100_000);
        let tx2 = make_test_tx(0x22, 500_000_000, 200_000);
        let tx1_bytes = serialize_transaction(&tx1);
        let tx2_bytes = serialize_transaction(&tx2);
        let tx_root = tx_merkle_root(&[tx1.tx_id.0, tx2.tx_id.0]);

        let fields = vec![
            ([0x00, 0x01], vec![0x10, 0x20]),
            ([0x01, 0x00], vec![0xff; 8]),
        ];
        let ext_root = extension_merkle_root(&fields);

        let proof_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let ad_root = blake2b256(&proof_bytes);

        let mut header = Header::default_for_test();
        header.transactions_root = Digest32(tx_root);
        header.extension_root = Digest32(ext_root);
        header.ad_proofs_root = Digest32(ad_root);

        ErgoFullBlock {
            header,
            block_transactions: BlockTransactions {
                header_id,
                block_version: 1,
                tx_bytes: vec![tx1_bytes, tx2_bytes],
            },
            extension: Extension { header_id, fields },
            ad_proofs: Some(ADProofs {
                header_id,
                proof_bytes,
            }),
        }
    }

    #[test]
    fn valid_block_with_correct_roots_passes() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_populated_block(header_id);
        assert!(validate_full_block(&block, &header_id, true, &vs()).is_ok());
    }

    #[test]
    fn tampered_transactions_root_returns_mismatch() {
        let header_id = ModifierId([0xaa; 32]);
        let mut block = valid_populated_block(header_id);
        block.header.transactions_root = Digest32([0xff; 32]);
        let err = validate_full_block(&block, &header_id, false, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::TransactionsRootMismatch { .. }),
            "expected TransactionsRootMismatch, got: {err}"
        );
    }

    #[test]
    fn tampered_ad_proofs_root_returns_mismatch_in_digest_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let mut block = valid_populated_block(header_id);
        block.header.ad_proofs_root = Digest32([0xff; 32]);
        let err = validate_full_block(&block, &header_id, true, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::AdProofsRootMismatch { .. }),
            "expected AdProofsRootMismatch, got: {err}"
        );
    }

    #[test]
    fn tampered_extension_root_returns_mismatch() {
        let header_id = ModifierId([0xaa; 32]);
        let mut block = valid_populated_block(header_id);
        block.header.extension_root = Digest32([0xff; 32]);
        let err = validate_full_block(&block, &header_id, false, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::ExtensionRootMismatch { .. }),
            "expected ExtensionRootMismatch, got: {err}"
        );
    }

    #[test]
    fn missing_ad_proofs_in_digest_mode_returns_error() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        let err = validate_full_block(&block, &header_id, true, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::MissingAdProofs),
            "expected MissingAdProofs, got: {err}"
        );
        // Without digest_mode, the same block passes.
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn section_header_id_mismatch_returns_error() {
        let header_id = ModifierId([0xaa; 32]);
        let wrong_id = ModifierId([0xbb; 32]);
        let mut block = valid_empty_block(header_id);
        block.block_transactions.header_id = wrong_id;
        let err = validate_full_block(&block, &header_id, false, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::SectionHeaderMismatch { .. }),
            "expected SectionHeaderMismatch, got: {err}"
        );
    }

    #[test]
    fn empty_transactions_merkle_root_matches_empty_hash() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn empty_extension_fields_merkle_root_matches_empty_hash() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn ad_proofs_root_mismatch_rejected_in_utxo_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let mut block = valid_populated_block(header_id);
        block.header.ad_proofs_root = Digest32([0xff; 32]);
        let err = validate_full_block(&block, &header_id, false, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::AdProofsRootMismatch { .. }),
            "expected AdProofsRootMismatch in UTXO mode, got: {err}"
        );
    }

    #[test]
    fn ad_proofs_correct_passes_in_utxo_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_populated_block(header_id);
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn missing_ad_proofs_ok_in_utxo_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn missing_ad_proofs_rejected_in_digest_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        let err = validate_full_block(&block, &header_id, true, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::MissingAdProofs),
            "expected MissingAdProofs in digest mode, got: {err}"
        );
    }

    #[test]
    fn v2_block_with_witness_ids_in_merkle_root() {
        let header_id = ModifierId([0xaa; 32]);
        let tx = make_test_tx(0x33, 1_000_000_000, 300_000);
        let tx_bytes = serialize_transaction(&tx);

        // For v2: leaves = [tx_id] ++ [witness_id]
        // witness_id = blake2b256(concat(spending_proofs))[1..] (31 bytes)
        let mut concat_proofs = Vec::new();
        for input in &tx.inputs {
            concat_proofs.extend_from_slice(&input.proof_bytes);
        }
        let witness_hash = blake2b256(&concat_proofs);
        let witness_id = &witness_hash[1..]; // 31 bytes

        let leaves: Vec<&[u8]> = vec![tx.tx_id.0.as_slice(), witness_id];
        let tx_root = merkle_root(&leaves).unwrap();

        let empty_root = blake2b256(&[]);
        let mut header = Header::default_for_test();
        header.transactions_root = Digest32(tx_root);
        header.extension_root = Digest32(empty_root);

        let block = ErgoFullBlock {
            header,
            block_transactions: BlockTransactions {
                header_id,
                block_version: 2,
                tx_bytes: vec![tx_bytes],
            },
            extension: Extension {
                header_id,
                fields: Vec::new(),
            },
            ad_proofs: None,
        };

        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }
}
