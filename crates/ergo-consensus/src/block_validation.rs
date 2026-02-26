//! Block-level validation: root hash checks and section header_id consistency.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use ergo_types::modifier_id::{Digest32, ModifierId};
use ergo_types::transaction::ErgoFullBlock;

use crate::merkle::merkle_root;
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
    #[error("section header_id mismatch: section references {section_header_id}, expected {expected}")]
    SectionHeaderMismatch {
        section_header_id: ModifierId,
        expected: ModifierId,
    },
}

/// Compute Blake2b-256 of raw data (no prefix).
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct output size");
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
    let tx_slices: Vec<&[u8]> = block
        .block_transactions
        .tx_bytes
        .iter()
        .map(|v| v.as_slice())
        .collect();
    let computed_tx_root = merkle_root(&tx_slices).unwrap_or([0u8; 32]);
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
    let ext_leaves: Vec<Vec<u8>> = block
        .extension
        .fields
        .iter()
        .map(|(key, value)| {
            let mut leaf = Vec::with_capacity(key.len() + value.len());
            leaf.extend_from_slice(key);
            leaf.extend_from_slice(value);
            leaf
        })
        .collect();
    let ext_slices: Vec<&[u8]> = ext_leaves.iter().map(|v| v.as_slice()).collect();
    let computed_ext_root = merkle_root(&ext_slices).unwrap_or([0u8; 32]);
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

    /// Shorthand for initial validation settings (all rules active).
    fn vs() -> ValidationSettings {
        ValidationSettings::initial()
    }

    /// Helper: build a valid block with empty tx_bytes and empty extension fields.
    /// The default_for_test header has all-zero roots, which matches empty Merkle trees.
    fn valid_empty_block(header_id: ModifierId) -> ErgoFullBlock {
        ErgoFullBlock {
            header: Header::default_for_test(),
            block_transactions: BlockTransactions {
                header_id,
                block_version: 2,
                tx_bytes: Vec::new(),
            },
            extension: Extension {
                header_id,
                fields: Vec::new(),
            },
            ad_proofs: None,
        }
    }

    /// Helper: build a valid block with actual transactions and extension fields,
    /// computing the correct header roots.
    fn valid_populated_block(header_id: ModifierId) -> ErgoFullBlock {
        let tx1 = vec![0x01, 0x02, 0x03];
        let tx2 = vec![0x04, 0x05];
        let tx_slices: Vec<&[u8]> = vec![tx1.as_slice(), tx2.as_slice()];
        let tx_root = merkle_root(&tx_slices).unwrap();

        let fields = vec![
            ([0x00, 0x01], vec![0x10, 0x20]),
            ([0x01, 0x00], vec![0xff; 8]),
        ];
        let ext_leaves: Vec<Vec<u8>> = fields
            .iter()
            .map(|(k, v)| {
                let mut leaf = Vec::new();
                leaf.extend_from_slice(k);
                leaf.extend_from_slice(v);
                leaf
            })
            .collect();
        let ext_slices: Vec<&[u8]> = ext_leaves.iter().map(|v| v.as_slice()).collect();
        let ext_root = merkle_root(&ext_slices).unwrap();

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
                block_version: 2,
                tx_bytes: vec![tx1, tx2],
            },
            extension: Extension {
                header_id,
                fields,
            },
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
        block.header.transactions_root = Digest32([0xff; 32]); // wrong root
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
        block.header.ad_proofs_root = Digest32([0xff; 32]); // wrong root
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
        block.header.extension_root = Digest32([0xff; 32]); // wrong root
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
        // Digest mode requires AD proofs, but we have None.
        let err = validate_full_block(&block, &header_id, true, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::MissingAdProofs),
            "expected MissingAdProofs, got: {err}"
        );

        // Verify that without digest_mode, the same block passes.
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn section_header_id_mismatch_returns_error() {
        let header_id = ModifierId([0xaa; 32]);
        let wrong_id = ModifierId([0xbb; 32]);
        let mut block = valid_empty_block(header_id);
        // Set block_transactions to reference a wrong header_id.
        block.block_transactions.header_id = wrong_id;
        let err = validate_full_block(&block, &header_id, false, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::SectionHeaderMismatch { .. }),
            "expected SectionHeaderMismatch, got: {err}"
        );
    }

    #[test]
    fn empty_transactions_merkle_root_matches_zero_digest() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        // Header has all-zero transactions_root, empty tx_bytes produces [0;32] fallback.
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn empty_extension_fields_merkle_root_matches_zero_digest() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        // Header has all-zero extension_root, empty fields produces [0;32] fallback.
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    // ── AD proofs root validation in all modes ──────────────────────

    #[test]
    fn ad_proofs_root_mismatch_rejected_in_utxo_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let mut block = valid_populated_block(header_id);
        // Tamper the header's ad_proofs_root so it no longer matches the actual proofs
        block.header.ad_proofs_root = Digest32([0xff; 32]);
        // In UTXO mode (digest_mode=false), the mismatch must still be caught
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
        // Correct proofs in UTXO mode (digest_mode=false) should pass
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn missing_ad_proofs_ok_in_utxo_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        // UTXO mode does not require AD proofs to be present
        assert!(validate_full_block(&block, &header_id, false, &vs()).is_ok());
    }

    #[test]
    fn missing_ad_proofs_rejected_in_digest_mode() {
        let header_id = ModifierId([0xaa; 32]);
        let block = valid_empty_block(header_id);
        // Digest mode requires AD proofs; absence must be an error
        let err = validate_full_block(&block, &header_id, true, &vs()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::MissingAdProofs),
            "expected MissingAdProofs in digest mode, got: {err}"
        );
    }
}
