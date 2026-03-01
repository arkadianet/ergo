use std::fmt;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::ad_proofs::ADProofs;
use crate::block_transactions::BlockTransactions;
use crate::extension::Extension;
use crate::header::Header;

// ── Constants ───────────────────────────────────────────────────────

/// Absolute floor for box value in nanoERGs.
///
/// Even the smallest possible box must carry at least this many nanoERGs.
/// The actual minimum for a given box is `max(box_serialized_size * min_value_per_byte, MIN_BOX_VALUE)`.
pub const MIN_BOX_VALUE: u64 = 10_800;

/// Default value of the MinValuePerByte parameter (nanoERG per serialized byte).
///
/// This corresponds to parameter ID 2 in the on-chain voting protocol.
/// Can be changed by miner voting; the default is 360.
pub const DEFAULT_MIN_VALUE_PER_BYTE: u64 = 360;

/// Maximum size in bytes for a single serialized box.
pub const MAX_BOX_SIZE: usize = 4096;

/// Maximum number of distinct tokens a single box may hold.
pub const MAX_TOKENS_PER_BOX: usize = 122;

/// Maximum number of inputs in a transaction.
pub const MAX_INPUTS: usize = 32767;

/// Maximum number of data inputs in a transaction.
pub const MAX_DATA_INPUTS: usize = 32767;

/// Maximum number of outputs in a transaction.
pub const MAX_OUTPUTS: usize = 32767;

/// Number of nanoERGs per whole ERG.
pub const UNITS_PER_ERGO: u64 = 1_000_000_000;

// ── Core identifier types ───────────────────────────────────────────

/// A 32-byte identifier for an unspent transaction output (box).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxId(pub [u8; 32]);

impl fmt::Display for BoxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// A 32-byte transaction identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId(pub [u8; 32]);

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// ── Transaction components ──────────────────────────────────────────

/// A transaction input that spends an existing box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// ID of the box being spent.
    pub box_id: BoxId,
    /// Serialized spending proof (sigma protocol proof).
    pub proof_bytes: Vec<u8>,
    /// Serialized context extension for the script interpreter.
    pub extension_bytes: Vec<u8>,
}

/// A read-only reference to an existing box (no spending).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataInput {
    /// ID of the referenced box.
    pub box_id: BoxId,
}

/// A box candidate that has not yet been assigned a transaction ID or index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoBoxCandidate {
    /// Value in nanoERGs.
    pub value: u64,
    /// Serialized ErgoTree bytes (guarding script).
    pub ergo_tree_bytes: Vec<u8>,
    /// Height at which this box was created.
    pub creation_height: u32,
    /// Tokens carried by this box: (token_id, amount).
    pub tokens: Vec<(BoxId, u64)>,
    /// Additional registers (R4..R9) as (register index, serialized value).
    pub additional_registers: Vec<(u8, Vec<u8>)>,
}

impl ErgoBoxCandidate {
    /// Estimate the serialized size of this box candidate in bytes.
    ///
    /// This provides a conservative estimate of the standalone serialized
    /// representation used for dust limit computation. The estimate accounts
    /// for VLQ-encoded fields but may differ from the exact serialized size
    /// by a few bytes due to VLQ encoding variance.
    ///
    /// Layout: value(VLQ) + tree_len(VLQ) + tree + creation_height(VLQ)
    ///       + token_count(VLQ) + tokens(32+VLQ each) + register_bitmap(1)
    ///       + register_bytes
    pub fn estimated_serialized_size(&self) -> usize {
        // VLQ size helper: compute bytes needed for a VLQ-encoded u64 value
        fn vlq_size(mut val: u64) -> usize {
            let mut size = 1;
            while val >= 0x80 {
                val >>= 7;
                size += 1;
            }
            size
        }

        // ZigZag + VLQ for a signed i64 value
        fn zigzag_vlq_size(val: i64) -> usize {
            let encoded = ((val << 1) ^ (val >> 63)) as u64;
            vlq_size(encoded)
        }

        let mut size = 0;
        // value: zigzag+VLQ i64
        size += zigzag_vlq_size(self.value as i64);
        // ergo_tree_len: VLQ u32
        size += vlq_size(self.ergo_tree_bytes.len() as u64);
        // ergo_tree: raw bytes
        size += self.ergo_tree_bytes.len();
        // creation_height: VLQ u32
        size += vlq_size(self.creation_height as u64);
        // token_count: VLQ u32
        size += vlq_size(self.tokens.len() as u64);
        // each token: 32-byte ID + zigzag+VLQ i64 amount
        for &(_, amount) in &self.tokens {
            size += 32;
            size += zigzag_vlq_size(amount as i64);
        }
        // register bitmap: 1 byte
        size += 1;
        // register data: raw bytes
        for (_, reg_bytes) in &self.additional_registers {
            size += reg_bytes.len();
        }
        size
    }
}

/// A fully identified box with its transaction ID and output index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoBox {
    /// The underlying box candidate fields.
    pub candidate: ErgoBoxCandidate,
    /// ID of the transaction that created this box.
    pub transaction_id: TxId,
    /// Output index within the creating transaction.
    pub index: u16,
    /// Unique box identifier derived from (transaction_id, index).
    pub box_id: BoxId,
}

/// A signed Ergo transaction containing inputs, data inputs, and output candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoTransaction {
    /// Inputs spending existing boxes.
    pub inputs: Vec<Input>,
    /// Read-only data inputs.
    pub data_inputs: Vec<DataInput>,
    /// Output box candidates created by this transaction.
    pub output_candidates: Vec<ErgoBoxCandidate>,
    /// Transaction identifier.
    pub tx_id: TxId,
}

/// A complete Ergo block containing all sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoFullBlock {
    /// Block header.
    pub header: Header,
    /// Block transactions section.
    pub block_transactions: BlockTransactions,
    /// Extension section with key-value parameters.
    pub extension: Extension,
    /// Optional AD proofs (absent in UTXO-mode nodes).
    pub ad_proofs: Option<ADProofs>,
}

/// Compute the box ID for an output at the given index in a transaction.
/// Ergo box ID = blake2b256(tx_id ++ vlq(output_index))
pub fn compute_box_id(tx_id: &TxId, output_index: u16) -> BoxId {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(&tx_id.0);
    // VLQ encode the output index
    let mut idx = output_index as u64;
    let mut vlq_buf = [0u8; 10];
    let mut vlq_len = 0;
    loop {
        let mut byte = (idx & 0x7F) as u8;
        idx >>= 7;
        if idx != 0 {
            byte |= 0x80;
        }
        vlq_buf[vlq_len] = byte;
        vlq_len += 1;
        if idx == 0 {
            break;
        }
    }
    hasher.update(&vlq_buf[..vlq_len]);
    let mut result = [0u8; 32];
    hasher.finalize_variable(&mut result).unwrap();
    BoxId(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modifier_id::ModifierId;
    use std::collections::HashSet;

    #[test]
    fn constants_values() {
        assert_eq!(MIN_BOX_VALUE, 10_800);
        assert_eq!(MAX_BOX_SIZE, 4096);
        assert_eq!(MAX_TOKENS_PER_BOX, 122);
        assert_eq!(MAX_INPUTS, 32767);
        assert_eq!(MAX_DATA_INPUTS, 32767);
        assert_eq!(MAX_OUTPUTS, 32767);
        assert_eq!(UNITS_PER_ERGO, 1_000_000_000);
    }

    #[test]
    fn box_id_construction() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let id = BoxId(bytes);
        assert_eq!(id.0[0], 0xab);
        assert_eq!(id.0[31], 0xcd);
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn tx_id_construction() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xfe;
        bytes[31] = 0x01;
        let id = TxId(bytes);
        assert_eq!(id.0[0], 0xfe);
        assert_eq!(id.0[31], 0x01);
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn box_id_display_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xff;
        bytes[1] = 0x01;
        let id = BoxId(bytes);
        let hex = format!("{id}");
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("ff01"));
    }

    #[test]
    fn tx_id_display_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        let id = TxId(bytes);
        let hex = format!("{id}");
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("dead"));
    }

    #[test]
    fn box_id_hash() {
        let id_a = BoxId([0x01; 32]);
        let id_b = BoxId([0x02; 32]);
        let id_a_dup = BoxId([0x01; 32]);

        let mut set = HashSet::new();
        set.insert(id_a);
        set.insert(id_b);
        set.insert(id_a_dup);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn input_construction() {
        let input = Input {
            box_id: BoxId([0xaa; 32]),
            proof_bytes: Vec::new(),
            extension_bytes: Vec::new(),
        };
        assert_eq!(input.box_id, BoxId([0xaa; 32]));
        assert!(input.proof_bytes.is_empty());
        assert!(input.extension_bytes.is_empty());
    }

    #[test]
    fn data_input_construction() {
        let data_input = DataInput {
            box_id: BoxId([0xbb; 32]),
        };
        assert_eq!(data_input.box_id, BoxId([0xbb; 32]));
    }

    #[test]
    fn ergo_box_candidate_with_tokens() {
        let token_a = (BoxId([0x01; 32]), 1000_u64);
        let token_b = (BoxId([0x02; 32]), 500_u64);
        let register = (4_u8, vec![0x05, 0x00, 0x80]);

        let candidate = ErgoBoxCandidate {
            value: MIN_BOX_VALUE,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: vec![token_a, token_b],
            additional_registers: vec![register],
        };

        assert_eq!(candidate.value, MIN_BOX_VALUE);
        assert_eq!(candidate.tokens.len(), 2);
        assert_eq!(candidate.tokens[0].1, 1000);
        assert_eq!(candidate.tokens[1].1, 500);
        assert_eq!(candidate.additional_registers.len(), 1);
        assert_eq!(candidate.additional_registers[0].0, 4);
    }

    #[test]
    fn ergo_transaction_clone_eq() {
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0x11; 32]),
                proof_bytes: vec![0x01],
                extension_bytes: vec![0x02],
            }],
            data_inputs: vec![DataInput {
                box_id: BoxId([0x22; 32]),
            }],
            output_candidates: vec![ErgoBoxCandidate {
                value: UNITS_PER_ERGO,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                creation_height: 500_000,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0x33; 32]),
        };

        let cloned = tx.clone();
        assert_eq!(tx, cloned);
    }

    #[test]
    fn ergo_full_block_with_proofs() {
        let block = ErgoFullBlock {
            header: Header::default_for_test(),
            block_transactions: BlockTransactions {
                header_id: ModifierId([0xaa; 32]),
                block_version: 2,
                tx_bytes: vec![vec![0x01]],
            },
            extension: Extension {
                header_id: ModifierId([0xaa; 32]),
                fields: Vec::new(),
            },
            ad_proofs: Some(ADProofs {
                header_id: ModifierId([0xaa; 32]),
                proof_bytes: vec![0xde, 0xad],
            }),
        };

        assert!(block.ad_proofs.is_some());
        assert_eq!(block.ad_proofs.as_ref().unwrap().proof_bytes.len(), 2);
        assert_eq!(block.block_transactions.tx_bytes.len(), 1);
    }

    #[test]
    fn ergo_full_block_without_proofs() {
        let block = ErgoFullBlock {
            header: Header::default_for_test(),
            block_transactions: BlockTransactions {
                header_id: ModifierId([0xbb; 32]),
                block_version: 1,
                tx_bytes: Vec::new(),
            },
            extension: Extension {
                header_id: ModifierId([0xbb; 32]),
                fields: Vec::new(),
            },
            ad_proofs: None,
        };

        assert!(block.ad_proofs.is_none());
        assert!(block.block_transactions.tx_bytes.is_empty());
    }

    #[test]
    fn compute_box_id_deterministic() {
        let tx_id = TxId([0xAA; 32]);
        let id1 = compute_box_id(&tx_id, 0);
        let id2 = compute_box_id(&tx_id, 0);
        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_box_id_different_index() {
        let tx_id = TxId([0xBB; 32]);
        let id0 = compute_box_id(&tx_id, 0);
        let id1 = compute_box_id(&tx_id, 1);
        assert_ne!(id0, id1);
    }

    #[test]
    fn compute_box_id_different_tx() {
        let tx1 = TxId([0xCC; 32]);
        let tx2 = TxId([0xDD; 32]);
        let id1 = compute_box_id(&tx1, 0);
        let id2 = compute_box_id(&tx2, 0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn compute_box_id_is_32_bytes() {
        let tx_id = TxId([0xEE; 32]);
        let id = compute_box_id(&tx_id, 42);
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn compute_box_id_large_index_vlq() {
        let tx_id = TxId([0xFF; 32]);
        let id_127 = compute_box_id(&tx_id, 127);
        let id_128 = compute_box_id(&tx_id, 128);
        assert_ne!(id_127, id_128);
    }

    #[test]
    fn default_min_value_per_byte_is_360() {
        assert_eq!(DEFAULT_MIN_VALUE_PER_BYTE, 360);
    }

    #[test]
    fn estimated_serialized_size_minimal_box() {
        let candidate = ErgoBoxCandidate {
            value: 1_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };
        let size = candidate.estimated_serialized_size();
        // Minimal box: value(~2) + tree_len(1) + tree(3) + height(~3) + tokens(1) + bitmap(1) = ~11
        assert!(size >= 8, "minimal box size {size} too small");
        assert!(size <= 20, "minimal box size {size} too large");
    }

    #[test]
    fn estimated_serialized_size_with_tokens() {
        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 500_000,
            tokens: vec![(BoxId([0xAA; 32]), 1_000), (BoxId([0xBB; 32]), 999_999)],
            additional_registers: Vec::new(),
        };
        let size = candidate.estimated_serialized_size();
        // Two tokens add 2 * (32 + VLQ) bytes.
        assert!(size > 70, "box-with-tokens size {size} should be > 70");
    }

    #[test]
    fn estimated_serialized_size_with_registers() {
        let candidate = ErgoBoxCandidate {
            value: 1_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: vec![(4, vec![0x05, 0x00, 0x80])],
        };
        let size = candidate.estimated_serialized_size();
        // Registers add 3 bytes of data.
        assert!(size >= 11, "box-with-register size {size} should be >= 11");
    }

    #[test]
    fn estimated_serialized_size_large_ergo_tree() {
        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00; 500],
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };
        let size = candidate.estimated_serialized_size();
        assert!(
            size > 500,
            "box with 500-byte tree should have size > 500, got {size}"
        );
    }

    #[test]
    fn dynamic_min_value_exceeds_floor_for_large_box() {
        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00; 200],
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };
        let size = candidate.estimated_serialized_size() as u64;
        let dynamic_min = size * DEFAULT_MIN_VALUE_PER_BYTE;
        assert!(
            dynamic_min > MIN_BOX_VALUE,
            "dynamic min ({dynamic_min}) should exceed floor ({MIN_BOX_VALUE}) for 200-byte tree"
        );
    }
}
