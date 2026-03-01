//! Data structure for a wallet-tracked UTXO box.

use serde::{Deserialize, Serialize};

/// A box tracked by the wallet.
///
/// Contains full box data plus wallet-specific metadata such as
/// whether it has been spent and the spending transaction ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackedBox {
    /// Blake2b-256 hash identifying this box.
    pub box_id: [u8; 32],
    /// Raw ErgoTree bytes (proposition guarding the box).
    pub ergo_tree_bytes: Vec<u8>,
    /// NanoERG value locked in the box.
    pub value: u64,
    /// Tokens contained in the box: `(token_id, amount)`.
    pub tokens: Vec<([u8; 32], u64)>,
    /// Height at which the creating transaction was included.
    pub creation_height: u32,
    /// Block height at which this box appeared on-chain.
    pub inclusion_height: u32,
    /// Transaction that created this box.
    pub tx_id: [u8; 32],
    /// Index of this box within the creating transaction's outputs.
    pub output_index: u16,
    /// Full wire-format serialized box bytes.
    pub serialized_box: Vec<u8>,
    /// Non-mandatory registers R4..R9: (register_index, serialized_value_bytes).
    #[serde(default)]
    pub additional_registers: Vec<(u8, Vec<u8>)>,
    /// Whether this box has been spent.
    pub spent: bool,
    /// Transaction that spent this box (if any).
    pub spending_tx_id: Option<[u8; 32]>,
    /// Height at which this box was spent (if any).
    pub spending_height: Option<u32>,
    /// Scan IDs that matched this box (e.g. 10 = PaymentsScanId).
    #[serde(default = "default_scan_ids")]
    pub scan_ids: Vec<u16>,
}

/// Default scan IDs for backward compatibility with existing serialized entries.
/// Returns `vec![10]` (PaymentsScanId).
fn default_scan_ids() -> Vec<u16> {
    vec![10]
}

impl TrackedBox {
    /// Serialize to JSON bytes for DB storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("TrackedBox serialization cannot fail")
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("TrackedBox deserialization error: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_box(box_id_byte: u8, value: u64, height: u32) -> TrackedBox {
        let mut box_id = [0u8; 32];
        box_id[0] = box_id_byte;
        let mut tx_id = [0u8; 32];
        tx_id[0] = box_id_byte;
        tx_id[1] = 0xFF;

        TrackedBox {
            box_id,
            ergo_tree_bytes: vec![0x00, 0x08, 0xCD],
            value,
            tokens: vec![],
            creation_height: height,
            inclusion_height: height,
            tx_id,
            output_index: 0,
            serialized_box: vec![0xDE, 0xAD],
            additional_registers: vec![],
            spent: false,
            spending_tx_id: None,
            spending_height: None,
            scan_ids: vec![10],
        }
    }

    #[test]
    fn roundtrip_serialization() {
        let tb = sample_box(1, 1_000_000_000, 100);
        let bytes = tb.to_bytes();
        let restored = TrackedBox::from_bytes(&bytes).unwrap();
        assert_eq!(tb, restored);
    }

    #[test]
    fn roundtrip_with_tokens_and_spent() {
        let mut tb = sample_box(2, 500_000, 200);
        let mut token_id = [0u8; 32];
        token_id[0] = 0xAA;
        tb.tokens = vec![(token_id, 1000)];
        tb.spent = true;
        let mut spending = [0u8; 32];
        spending[0] = 0xBB;
        tb.spending_tx_id = Some(spending);
        tb.spending_height = Some(210);

        let bytes = tb.to_bytes();
        let restored = TrackedBox::from_bytes(&bytes).unwrap();
        assert_eq!(tb, restored);
    }

    #[test]
    fn from_bytes_invalid_returns_error() {
        let result = TrackedBox::from_bytes(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_with_registers() {
        let mut tb = sample_box(3, 2_000_000, 300);
        // Simulate R4 and R5 register values.
        tb.additional_registers = vec![
            (4, vec![0x05, 0x00, 0x80]),       // R4
            (5, vec![0x0E, 0x02, 0xAB, 0xCD]), // R5
        ];
        let bytes = tb.to_bytes();
        let restored = TrackedBox::from_bytes(&bytes).unwrap();
        assert_eq!(tb, restored);
        assert_eq!(restored.additional_registers.len(), 2);
        assert_eq!(restored.additional_registers[0].0, 4);
        assert_eq!(restored.additional_registers[1].0, 5);
    }

    #[test]
    fn deserialize_without_registers_backward_compat() {
        // Simulate a JSON blob that was serialized before the field existed.
        let tb = sample_box(4, 500_000, 400);
        let mut json_val: serde_json::Value = serde_json::to_value(&tb).unwrap();
        // Remove the field to simulate old data.
        json_val
            .as_object_mut()
            .unwrap()
            .remove("additional_registers");
        let json_bytes = serde_json::to_vec(&json_val).unwrap();
        let restored = TrackedBox::from_bytes(&json_bytes).unwrap();
        assert!(restored.additional_registers.is_empty());
    }
}
