//! JSON deserialization types for the block API response (`POST /blocks/headerIds`)
//! and wire-format conversion functions for feeding blocks into `put_modifier`.
//!
//! These are the *inbound* counterparts of the `*Response` types in `api/mod.rs`
//! (which are `Serialize`-only for outbound). We keep them separate so that
//! wire-conversion code can live alongside these types without touching
//! the API module.

use serde::Deserialize;

use ergo_types::block_transactions::MAX_TRANSACTIONS_IN_BLOCK;
use ergo_types::transaction::{
    BoxId, DataInput, ErgoBoxCandidate, ErgoTransaction, Input, TxId,
};
use ergo_wire::vlq::{put_uint, put_ushort};

// ── Error type ──────────────────────────────────────────────────────

/// Errors that can occur during fast block sync JSON-to-wire conversion.
#[derive(Debug, thiserror::Error)]
pub enum FastBlockSyncError {
    /// Hex decoding failed.
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A required block section is missing from the JSON response.
    #[error("missing section: {0}")]
    MissingSection(String),

    /// HTTP request error.
    #[error("http: {0}")]
    Http(String),

    /// JSON parsing / structure error.
    #[error("json: {0}")]
    Json(String),
}

// ── JSON deserialization types ──────────────────────────────────────

/// Top-level block returned by `POST /blocks/headerIds`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFullBlock {
    pub header: JsonBlockHeader,
    pub block_transactions: Option<JsonBlockTransactions>,
    pub extension: Option<JsonExtension>,
    pub ad_proofs: Option<serde_json::Value>,
    pub size: usize,
}

/// Minimal block header fields needed for wire conversion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonBlockHeader {
    pub id: String,
    pub height: u32,
    pub version: u8,
}

/// Block transactions section.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonBlockTransactions {
    pub header_id: String,
    pub transactions: Vec<JsonTransaction>,
    pub block_version: u8,
}

/// A single transaction.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonTransaction {
    pub id: String,
    pub inputs: Vec<JsonInput>,
    pub data_inputs: Vec<JsonDataInput>,
    pub outputs: Vec<JsonOutput>,
}

/// Transaction input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonInput {
    pub box_id: String,
    pub spending_proof: JsonSpendingProof,
}

/// Spending proof attached to an input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSpendingProof {
    pub proof_bytes: String,
    pub extension: serde_json::Value,
}

/// Data input (read-only box reference).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonDataInput {
    pub box_id: String,
}

/// Transaction output (box).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonOutput {
    pub box_id: Option<String>,
    pub value: u64,
    pub ergo_tree: String,
    pub creation_height: u32,
    pub assets: Vec<JsonAsset>,
    pub additional_registers: serde_json::Value,
    pub transaction_id: Option<String>,
    pub index: Option<u16>,
}

/// Token asset inside an output.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonAsset {
    pub token_id: String,
    pub amount: u64,
}

/// Extension section of a block.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExtension {
    pub header_id: String,
    pub fields: Vec<(String, String)>,
}

// ── Wire-format conversion functions ────────────────────────────────

/// Convert a JSON Extension to the exact wire bytes that `put_modifier` expects.
///
/// Wire layout:
/// ```text
/// [32 bytes: header_id]
/// [VLQ UShort: field_count]
/// per field: [2 bytes key] [1 byte value_len] [value bytes]
/// ```
pub fn extension_json_to_wire(
    header_id_hex: &str,
    ext: &JsonExtension,
) -> Result<Vec<u8>, FastBlockSyncError> {
    let header_id = hex_to_32(header_id_hex)?;

    let mut buf = Vec::with_capacity(64);

    // header_id: 32 bytes
    buf.extend_from_slice(&header_id);

    // field_count: VLQ UShort
    put_ushort(&mut buf, ext.fields.len() as u16);

    // each field: key(2 hex bytes → 1..N raw bytes) + value_length(1) + value
    for (key_hex, value_hex) in &ext.fields {
        let key_bytes = hex::decode(key_hex)?;
        if key_bytes.len() != 2 {
            return Err(FastBlockSyncError::Json(format!(
                "extension field key must be 2 bytes, got {}",
                key_bytes.len()
            )));
        }
        let value_bytes = hex::decode(value_hex)?;
        buf.extend_from_slice(&key_bytes);
        buf.push(value_bytes.len() as u8);
        buf.extend_from_slice(&value_bytes);
    }

    Ok(buf)
}

/// Convert JSON BlockTransactions to the exact wire bytes that `put_modifier` expects.
///
/// Wire layout:
/// ```text
/// [32 bytes: header_id]
/// if block_version > 1: [VLQ UInt: MAX_TRANSACTIONS_IN_BLOCK + block_version]
/// [VLQ UInt: tx_count]
/// for each tx: [inline serialized tx bytes]
/// ```
pub fn block_transactions_json_to_wire(
    header_id_hex: &str,
    bt: &JsonBlockTransactions,
) -> Result<Vec<u8>, FastBlockSyncError> {
    let header_id = hex_to_32(header_id_hex)?;

    let mut buf = Vec::with_capacity(256);

    // header_id: 32 bytes
    buf.extend_from_slice(&header_id);

    // version sentinel: only for block_version > 1
    if bt.block_version > 1 {
        put_uint(&mut buf, MAX_TRANSACTIONS_IN_BLOCK + bt.block_version as u32);
    }

    // tx_count: VLQ UInt
    put_uint(&mut buf, bt.transactions.len() as u32);

    // each transaction: inline serialized bytes (no length prefix)
    for jtx in &bt.transactions {
        let ergo_tx = json_tx_to_ergo_transaction(jtx)?;
        let tx_bytes = ergo_wire::transaction_ser::serialize_transaction(&ergo_tx);
        buf.extend_from_slice(&tx_bytes);
    }

    Ok(buf)
}

/// Convert a JSON transaction to our internal `ErgoTransaction` type.
fn json_tx_to_ergo_transaction(
    jtx: &JsonTransaction,
) -> Result<ErgoTransaction, FastBlockSyncError> {
    // Parse inputs
    let inputs = jtx
        .inputs
        .iter()
        .map(|ji| {
            let box_id = BoxId(hex_to_32(&ji.box_id)?);
            let proof_bytes = hex::decode(&ji.spending_proof.proof_bytes)?;
            let extension_bytes = parse_context_extension(&ji.spending_proof.extension)?;
            Ok(Input {
                box_id,
                proof_bytes,
                extension_bytes,
            })
        })
        .collect::<Result<Vec<_>, FastBlockSyncError>>()?;

    // Parse data inputs
    let data_inputs = jtx
        .data_inputs
        .iter()
        .map(|jdi| {
            let box_id = BoxId(hex_to_32(&jdi.box_id)?);
            Ok(DataInput { box_id })
        })
        .collect::<Result<Vec<_>, FastBlockSyncError>>()?;

    // Parse output candidates
    let output_candidates = jtx
        .outputs
        .iter()
        .map(|jo| {
            let ergo_tree_bytes = hex::decode(&jo.ergo_tree)?;
            let tokens = jo
                .assets
                .iter()
                .map(|a| {
                    let token_id = BoxId(hex_to_32(&a.token_id)?);
                    Ok((token_id, a.amount))
                })
                .collect::<Result<Vec<_>, FastBlockSyncError>>()?;
            let additional_registers = parse_additional_registers(&jo.additional_registers)?;
            Ok(ErgoBoxCandidate {
                value: jo.value,
                ergo_tree_bytes,
                creation_height: jo.creation_height,
                tokens,
                additional_registers,
            })
        })
        .collect::<Result<Vec<_>, FastBlockSyncError>>()?;

    // Build tx with placeholder tx_id; serialize_transaction via sigma-rust
    // recomputes internally.
    let mut tx = ErgoTransaction {
        inputs,
        data_inputs,
        output_candidates,
        tx_id: TxId([0u8; 32]),
    };
    tx.tx_id = ergo_wire::transaction_ser::compute_tx_id(&tx);
    Ok(tx)
}

/// Parse a JSON context extension object into sigma-serialized extension bytes.
///
/// The JSON format is `{"0": "0500...", "2": "05c0..."}` where keys are decimal
/// indices and values are hex-encoded sigma-serialized Constant bytes.
///
/// The wire format is:
/// - VLQ(count)
/// - For each entry (sorted by key): u8(key) + raw_constant_bytes
///
/// Returns `vec![0x00]` (VLQ encoding of 0) for empty extensions.
fn parse_context_extension(
    val: &serde_json::Value,
) -> Result<Vec<u8>, FastBlockSyncError> {
    let obj = match val.as_object() {
        Some(obj) => obj,
        None => {
            // Treat non-object (e.g. null or empty) as empty extension
            return Ok(vec![0x00]);
        }
    };

    if obj.is_empty() {
        return Ok(vec![0x00]);
    }

    // Collect and sort entries by key index
    let mut entries: Vec<(u8, Vec<u8>)> = Vec::with_capacity(obj.len());
    for (key_str, val_json) in obj {
        let key_idx: u8 = key_str.parse::<u8>().map_err(|e| {
            FastBlockSyncError::Json(format!("invalid extension key '{key_str}': {e}"))
        })?;
        let hex_str = val_json.as_str().ok_or_else(|| {
            FastBlockSyncError::Json(format!(
                "extension value for key '{key_str}' is not a string"
            ))
        })?;
        let constant_bytes = hex::decode(hex_str)?;
        entries.push((key_idx, constant_bytes));
    }
    entries.sort_by_key(|(k, _)| *k);

    // Serialize: VLQ(count) + for each: u8(key) + raw bytes
    let mut buf = Vec::new();
    ergo_wire::vlq::put_uint(&mut buf, entries.len() as u32);
    for (key, bytes) in &entries {
        buf.push(*key);
        buf.extend_from_slice(bytes);
    }

    Ok(buf)
}

/// Parse JSON additional registers into our register list format.
///
/// JSON format: `{"R4": "0500...", "R5": "05c0..."}` where values are
/// hex-encoded sigma-serialized values.
///
/// Returns `Vec<(u8, Vec<u8>)>` with register index and raw bytes.
fn parse_additional_registers(
    val: &serde_json::Value,
) -> Result<Vec<(u8, Vec<u8>)>, FastBlockSyncError> {
    let obj = match val.as_object() {
        Some(obj) => obj,
        None => return Ok(Vec::new()),
    };

    if obj.is_empty() {
        return Ok(Vec::new());
    }

    let mut regs: Vec<(u8, Vec<u8>)> = Vec::with_capacity(obj.len());
    for (key_str, val_json) in obj {
        // Parse "R4" → 4, "R5" → 5, etc.
        if !key_str.starts_with('R') {
            return Err(FastBlockSyncError::Json(format!(
                "invalid register key '{key_str}': expected R4..R9"
            )));
        }
        let idx: u8 = key_str[1..].parse::<u8>().map_err(|e| {
            FastBlockSyncError::Json(format!("invalid register key '{key_str}': {e}"))
        })?;
        if !(4..=9).contains(&idx) {
            return Err(FastBlockSyncError::Json(format!(
                "register index {idx} out of range (4..9)"
            )));
        }
        let hex_str = val_json.as_str().ok_or_else(|| {
            FastBlockSyncError::Json(format!(
                "register value for '{key_str}' is not a string"
            ))
        })?;
        let bytes = hex::decode(hex_str)?;
        regs.push((idx, bytes));
    }
    // Sort by register index for deterministic output
    regs.sort_by_key(|(k, _)| *k);

    Ok(regs)
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Decode a hex string into a fixed 32-byte array.
fn hex_to_32(hex_str: &str) -> Result<[u8; 32], FastBlockSyncError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(FastBlockSyncError::Json(format!(
            "expected 32 bytes, got {} from hex '{}'",
            bytes.len(),
            hex_str
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wire::extension_ser::parse_extension;

    #[test]
    fn extension_json_to_wire_roundtrip() {
        let header_id_hex = "aa".repeat(32);
        let ext = JsonExtension {
            header_id: header_id_hex.clone(),
            fields: vec![
                ("0001".to_string(), "1020".to_string()),
                ("0100".to_string(), hex::encode([0xFF; 32])),
                ("0205".to_string(), "42".to_string()),
            ],
        };

        let wire = extension_json_to_wire(&header_id_hex, &ext).unwrap();
        let parsed = parse_extension(&wire).unwrap();

        assert_eq!(parsed.fields.len(), 3);
        assert_eq!(parsed.header_id.0, [0xAA; 32]);
        assert_eq!(parsed.fields[0].0, [0x00, 0x01]);
        assert_eq!(parsed.fields[0].1, vec![0x10, 0x20]);
        assert_eq!(parsed.fields[1].0, [0x01, 0x00]);
        assert_eq!(parsed.fields[1].1, vec![0xFF; 32]);
        assert_eq!(parsed.fields[2].0, [0x02, 0x05]);
        assert_eq!(parsed.fields[2].1, vec![0x42]);
    }

    #[test]
    fn extension_json_to_wire_empty_fields() {
        let header_id_hex = "bb".repeat(32);
        let ext = JsonExtension {
            header_id: header_id_hex.clone(),
            fields: vec![],
        };
        let wire = extension_json_to_wire(&header_id_hex, &ext).unwrap();
        let parsed = parse_extension(&wire).unwrap();
        assert!(parsed.fields.is_empty());
        assert_eq!(parsed.header_id.0, [0xBB; 32]);
    }

    #[test]
    fn parse_context_extension_empty() {
        let val = serde_json::json!({});
        let bytes = parse_context_extension(&val).unwrap();
        assert_eq!(bytes, vec![0x00]);
    }

    #[test]
    fn parse_context_extension_null() {
        let val = serde_json::Value::Null;
        let bytes = parse_context_extension(&val).unwrap();
        assert_eq!(bytes, vec![0x00]);
    }

    #[test]
    fn parse_context_extension_with_entries() {
        let val = serde_json::json!({"0": "0500", "2": "05c0"});
        let bytes = parse_context_extension(&val).unwrap();
        // VLQ(2) = 0x02, then key=0 + [0x05, 0x00], key=2 + [0x05, 0xc0]
        assert_eq!(bytes[0], 0x02); // count = 2
        assert_eq!(bytes[1], 0x00); // key 0
        assert_eq!(&bytes[2..4], &[0x05, 0x00]); // value for key 0
        assert_eq!(bytes[4], 0x02); // key 2
        assert_eq!(&bytes[5..7], &[0x05, 0xc0]); // value for key 2
    }

    #[test]
    fn parse_additional_registers_empty() {
        let val = serde_json::json!({});
        let regs = parse_additional_registers(&val).unwrap();
        assert!(regs.is_empty());
    }

    #[test]
    fn parse_additional_registers_with_values() {
        let val = serde_json::json!({"R4": "0500", "R5": "05c0"});
        let regs = parse_additional_registers(&val).unwrap();
        assert_eq!(regs.len(), 2);
        assert_eq!(regs[0].0, 4);
        assert_eq!(regs[0].1, vec![0x05, 0x00]);
        assert_eq!(regs[1].0, 5);
        assert_eq!(regs[1].1, vec![0x05, 0xc0]);
    }

    #[test]
    fn parse_additional_registers_invalid_key() {
        let val = serde_json::json!({"X4": "0500"});
        let result = parse_additional_registers(&val);
        assert!(result.is_err());
    }

    #[test]
    fn parse_additional_registers_out_of_range() {
        let val = serde_json::json!({"R10": "0500"});
        let result = parse_additional_registers(&val);
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_32_valid() {
        let hex_str = "aa".repeat(32);
        let arr = hex_to_32(&hex_str).unwrap();
        assert_eq!(arr, [0xAA; 32]);
    }

    #[test]
    fn hex_to_32_wrong_length() {
        let hex_str = "aabb";
        let result = hex_to_32(hex_str);
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_32_invalid_hex() {
        let hex_str = "zz".repeat(32);
        let result = hex_to_32(&hex_str);
        assert!(result.is_err());
    }

    #[test]
    fn block_transactions_json_to_wire_v2() {
        // Build a minimal valid transaction via JSON
        let header_id_hex = "cc".repeat(32);
        let input_box_id = "11".repeat(32);

        // Build a P2PK ErgoTree: header=0x08 (size bit), VLQ(35)=0x23,
        // body=0x08 0xCD + 33-byte dummy pubkey
        let mut tree_bytes = vec![0x08u8, 0x23, 0x08, 0xCD];
        tree_bytes.extend_from_slice(&[0x02; 33]);
        let tree_hex = hex::encode(&tree_bytes);

        let bt = JsonBlockTransactions {
            header_id: header_id_hex.clone(),
            transactions: vec![JsonTransaction {
                id: "00".repeat(32), // placeholder, recomputed
                inputs: vec![JsonInput {
                    box_id: input_box_id,
                    spending_proof: JsonSpendingProof {
                        proof_bytes: String::new(),
                        extension: serde_json::json!({}),
                    },
                }],
                data_inputs: vec![],
                outputs: vec![JsonOutput {
                    box_id: None,
                    value: 1_000_000_000,
                    ergo_tree: tree_hex,
                    creation_height: 100_000,
                    assets: vec![],
                    additional_registers: serde_json::json!({}),
                    transaction_id: None,
                    index: None,
                }],
            }],
            block_version: 2,
        };

        let wire = block_transactions_json_to_wire(&header_id_hex, &bt).unwrap();

        // Verify we can round-trip parse it
        let parsed =
            ergo_wire::block_transactions_ser::parse_block_transactions(&wire).unwrap();
        assert_eq!(parsed.header_id.0, [0xCC; 32]);
        assert_eq!(parsed.block_version, 2);
        assert_eq!(parsed.tx_bytes.len(), 1);
    }

    #[test]
    fn block_transactions_json_to_wire_v1() {
        let header_id_hex = "dd".repeat(32);
        let input_box_id = "22".repeat(32);

        let mut tree_bytes = vec![0x08u8, 0x23, 0x08, 0xCD];
        tree_bytes.extend_from_slice(&[0x02; 33]);
        let tree_hex = hex::encode(&tree_bytes);

        let bt = JsonBlockTransactions {
            header_id: header_id_hex.clone(),
            transactions: vec![JsonTransaction {
                id: "00".repeat(32),
                inputs: vec![JsonInput {
                    box_id: input_box_id,
                    spending_proof: JsonSpendingProof {
                        proof_bytes: String::new(),
                        extension: serde_json::json!({}),
                    },
                }],
                data_inputs: vec![],
                outputs: vec![JsonOutput {
                    box_id: None,
                    value: 500_000_000,
                    ergo_tree: tree_hex,
                    creation_height: 200_000,
                    assets: vec![],
                    additional_registers: serde_json::json!({}),
                    transaction_id: None,
                    index: None,
                }],
            }],
            block_version: 1,
        };

        let wire = block_transactions_json_to_wire(&header_id_hex, &bt).unwrap();
        let parsed =
            ergo_wire::block_transactions_ser::parse_block_transactions(&wire).unwrap();
        assert_eq!(parsed.block_version, 1);
        assert_eq!(parsed.tx_bytes.len(), 1);
    }
}
