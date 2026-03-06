# Fast Block Sync Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bulk-download block body sections (BlockTransactions + Extension) via peer REST APIs, bypassing the slow P2P request/response cycle for block downloads.

**Architecture:** After fast header sync completes and headers are stored, walk the height index to collect header IDs, batch them into chunks of 16, and POST to `/blocks/headerIds` on peer REST APIs in parallel. Parse JSON responses, reconstruct wire-format bytes using existing serializers, and bulk-store to DB via a new `BulkBlockSections` processor command. The existing processor `apply_progress` mechanism applies blocks sequentially afterward.

**Tech Stack:** Rust, tokio, reqwest, serde/serde_json, ergo-wire serializers, RocksDB WriteBatch

---

## Context

### Key Files
- `crates/ergo-node/src/fast_header_sync.rs` — existing fast header sync (pattern to follow)
- `crates/ergo-network/src/block_processor.rs` — ProcessorCommand enum, batch processing
- `crates/ergo-network/src/node_view.rs` — process_modifier, apply_progress, has_all_sections
- `crates/ergo-node/src/event_loop.rs` — main loop, shared state, task spawning
- `crates/ergo-node/src/api/mod.rs` — JSON response types (BlockResponse, etc.)
- `crates/ergo-wire/src/block_transactions_ser.rs` — BlockTransactions wire serialization
- `crates/ergo-wire/src/extension_ser.rs` — Extension wire serialization
- `crates/ergo-wire/src/transaction_ser.rs` — Transaction wire serialization
- `crates/ergo-storage/src/history_db.rs` — HistoryBatch, put_modifier

### Wire Formats

**BlockTransactions (type 102):**
```text
[32 bytes: header_id]
if block_version > 1:
  [VLQ UInt: MAX_TRANSACTIONS_IN_BLOCK + block_version]
[VLQ UInt: tx_count]
for each tx: [inline tx bytes]
```

**Extension (type 108):**
```text
[32 bytes: header_id]
[VLQ UShort: field_count]
for each field: [2 bytes key] [1 byte value_len] [value bytes]
```

### Storage Pattern
Body sections are stored via `put_modifier(type_id, &header_id, wire_bytes)` — keyed by **header_id** (extracted from the first 32 bytes of wire data), NOT section_id. The `process_block_section` / `has_all_sections` checks use header_id.

### Section Modifier IDs
`section_id = blake2b256([type_id] ++ header_id ++ root_hash)` — computed via `ergo_types::header::compute_section_id`. These are NOT used as DB keys for body sections; header_id is.

### JSON Response Shape (from POST /blocks/headerIds)
```rust
BlockResponse {
    header: HeaderResponse { id, height, version, ... },
    block_transactions: Option<BlockTransactionsResponse {
        header_id: String,
        transactions: Vec<TransactionResponse { id, inputs, data_inputs, outputs, size }>,
        block_version: u8,
        size: usize,
    }>,
    extension: Option<ExtensionResponse {
        header_id: String,
        digest: String,
        fields: Vec<(String, String)>,  // hex key, hex value
    }>,
    ad_proofs: Option<String>,
    size: usize,
}
```

### Existing Shared Types (from fast_header_sync.rs)
```rust
pub type ApiPeerUrls = Arc<RwLock<HashMap<u64, String>>>;
pub type SharedHeadersHeight = Arc<AtomicU32>;
pub type SharedFastSyncActive = Arc<AtomicBool>;
```

---

## Task 1: JSON Deserialization Types for Block API Response

**Files:**
- Create: `crates/ergo-node/src/fast_block_sync.rs`

**Step 1: Create the module with serde types**

Create `fast_block_sync.rs` with serde `Deserialize` structs that mirror the JSON shape returned by `POST /blocks/headerIds`. These are the *inbound* counterparts of the existing `*Response` types in `api/mod.rs` (those are `Serialize`-only for outbound).

```rust
//! Fast block sync via REST API bulk download.
//!
//! Downloads block body sections (BlockTransactions + Extension) in bulk
//! from peer REST APIs, converts JSON to wire-format bytes, and stores
//! them via BulkBlockSections processor commands.

use serde::Deserialize;

/// A full block from the peer REST API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFullBlock {
    pub header: JsonBlockHeader,
    pub block_transactions: Option<JsonBlockTransactions>,
    pub extension: Option<JsonExtension>,
}

/// Minimal header fields needed for fast block sync.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonBlockHeader {
    pub id: String,
    pub height: u32,
    pub version: u8,
}

/// Block transactions from JSON.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonBlockTransactions {
    pub header_id: String,
    pub transactions: Vec<JsonTransaction>,
    pub block_version: u8,
}

/// A single transaction from JSON.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonTransaction {
    pub id: String,
    pub inputs: Vec<JsonInput>,
    pub data_inputs: Vec<JsonDataInput>,
    pub outputs: Vec<JsonOutput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonInput {
    pub box_id: String,
    pub spending_proof: JsonSpendingProof,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSpendingProof {
    pub proof_bytes: String,
    pub extension: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonDataInput {
    pub box_id: String,
}

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonAsset {
    pub token_id: String,
    pub amount: u64,
}

/// Extension section from JSON.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExtension {
    pub header_id: String,
    pub fields: Vec<(String, String)>,
}
```

**Step 2: Add module declaration**

In `crates/ergo-node/src/main.rs` (or wherever the module tree is), add:
```rust
pub mod fast_block_sync;
```

Find the existing `pub mod fast_header_sync;` line and add `fast_block_sync` next to it.

**Step 3: Run tests**

```bash
cargo test -p ergo-node --lib
cargo clippy -p ergo-node -- -D warnings
```

**Step 4: Commit**

```bash
git add crates/ergo-node/src/fast_block_sync.rs crates/ergo-node/src/main.rs
git commit -m "feat(fast-block-sync): add JSON deserialization types for block API response"
```

---

## Task 2: JSON-to-Wire Conversion Functions

**Files:**
- Modify: `crates/ergo-node/src/fast_block_sync.rs`

This is the core of the feature: converting the JSON API response back into the exact wire-format bytes that `put_modifier` expects.

**Step 1: Write the conversion function for Extension**

Extension is simpler (no transaction parsing), so start here. The wire format is:
- 32 bytes: header_id
- VLQ UShort: field_count
- Per field: 2-byte key + 1-byte value_len + value bytes

JSON fields are `Vec<(String, String)>` where both strings are hex-encoded.

```rust
use ergo_types::modifier_id::ModifierId;

/// Errors that can occur during fast block sync.
#[derive(Debug, thiserror::Error)]
pub enum FastBlockSyncError {
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("missing block section for header {0}")]
    MissingSection(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON parse error: {0}")]
    Json(String),
}

/// Convert a JSON Extension to wire-format bytes.
///
/// Replicates the exact binary layout of `serialize_extension()` in
/// `ergo-wire/src/extension_ser.rs`.
pub fn extension_json_to_wire(
    header_id_hex: &str,
    ext: &JsonExtension,
) -> Result<Vec<u8>, FastBlockSyncError> {
    let header_id_bytes = hex::decode(header_id_hex)?;
    let mut buf = Vec::with_capacity(128);

    // header_id: 32 bytes
    buf.extend_from_slice(&header_id_bytes);

    // field_count: VLQ UShort
    ergo_wire::vlq::put_ushort(&mut buf, ext.fields.len() as u16);

    // each field: key(2) + value_length(1) + value(variable)
    for (key_hex, value_hex) in &ext.fields {
        let key = hex::decode(key_hex)?;
        let value = hex::decode(value_hex)?;
        buf.extend_from_slice(&key);       // 2 bytes
        buf.push(value.len() as u8);       // 1 byte
        buf.extend_from_slice(&value);
    }

    Ok(buf)
}
```

**Step 2: Write the conversion function for BlockTransactions**

This is more complex because we need to reconstruct the full transaction wire bytes from JSON. The approach: rebuild `ErgoTransaction` structs from JSON fields, then use `ergo_wire::transaction_ser::serialize_transaction()` to get the wire bytes for each tx. Then assemble the BlockTransactions wire format.

```rust
use ergo_types::transaction::{
    BoxId, DataInput, ErgoBoxCandidate, ErgoTransaction, Input, SpendingProof, TxId,
};

/// Convert a JSON BlockTransactions to wire-format bytes.
///
/// Replicates the exact binary layout of `serialize_block_transactions()` in
/// `ergo-wire/src/block_transactions_ser.rs`.
pub fn block_transactions_json_to_wire(
    header_id_hex: &str,
    bt: &JsonBlockTransactions,
) -> Result<Vec<u8>, FastBlockSyncError> {
    let header_id_bytes = hex::decode(header_id_hex)?;
    let block_version = bt.block_version;

    // Serialize each transaction to wire bytes
    let mut tx_wire_bytes: Vec<Vec<u8>> = Vec::with_capacity(bt.transactions.len());
    for jtx in &bt.transactions {
        let tx = json_tx_to_ergo_transaction(jtx)?;
        let wire = ergo_wire::transaction_ser::serialize_transaction(&tx);
        tx_wire_bytes.push(wire);
    }

    let mut buf = Vec::with_capacity(256);

    // header_id: 32 bytes
    buf.extend_from_slice(&header_id_bytes);

    // version sentinel: only for block_version > 1
    if block_version > 1 {
        ergo_wire::vlq::put_uint(
            &mut buf,
            ergo_types::block_transactions::MAX_TRANSACTIONS_IN_BLOCK + block_version as u32,
        );
    }

    // tx_count: VLQ UInt
    ergo_wire::vlq::put_uint(&mut buf, tx_wire_bytes.len() as u32);

    // each transaction: inline bytes (no length prefix)
    for tw in &tx_wire_bytes {
        buf.extend_from_slice(tw);
    }

    Ok(buf)
}

/// Convert a JSON transaction to an ErgoTransaction struct.
fn json_tx_to_ergo_transaction(
    jtx: &JsonTransaction,
) -> Result<ErgoTransaction, FastBlockSyncError> {
    let mut inputs = Vec::with_capacity(jtx.inputs.len());
    for ji in &jtx.inputs {
        let box_id_bytes = hex::decode(&ji.box_id)?;
        let proof_bytes = hex::decode(&ji.spending_proof.proof_bytes)?;

        // Parse context extension from JSON Value
        let extension = parse_context_extension(&ji.spending_proof.extension)?;

        inputs.push(Input {
            box_id: BoxId(box_id_bytes.try_into().map_err(|_| {
                FastBlockSyncError::Hex(hex::FromHexError::InvalidStringLength)
            })?),
            spending_proof: SpendingProof {
                proof_bytes,
                extension,
            },
        });
    }

    let mut data_inputs = Vec::with_capacity(jtx.data_inputs.len());
    for jdi in &jtx.data_inputs {
        let box_id_bytes = hex::decode(&jdi.box_id)?;
        data_inputs.push(DataInput {
            box_id: BoxId(box_id_bytes.try_into().map_err(|_| {
                FastBlockSyncError::Hex(hex::FromHexError::InvalidStringLength)
            })?),
        });
    }

    let mut outputs = Vec::with_capacity(jtx.outputs.len());
    for jo in &jtx.outputs {
        let ergo_tree = hex::decode(&jo.ergo_tree)?;
        let mut assets = Vec::with_capacity(jo.assets.len());
        for a in &jo.assets {
            let token_id = hex::decode(&a.token_id)?;
            assets.push((
                token_id.try_into().map_err(|_| {
                    FastBlockSyncError::Hex(hex::FromHexError::InvalidStringLength)
                })?,
                a.amount,
            ));
        }

        let registers = parse_additional_registers(&jo.additional_registers)?;

        outputs.push(ErgoBoxCandidate {
            value: jo.value,
            ergo_tree,
            creation_height: jo.creation_height,
            tokens: assets,
            additional_registers: registers,
        });
    }

    Ok(ErgoTransaction {
        inputs,
        data_inputs,
        outputs,
    })
}

/// Parse context extension from serde_json::Value.
///
/// JSON shape: `{}` (empty) or `{"0": "0500...", "2": "05c0..."}` — keys are
/// decimal register indices, values are hex-encoded SigmaType serialization.
fn parse_context_extension(
    val: &serde_json::Value,
) -> Result<Vec<(u8, Vec<u8>)>, FastBlockSyncError> {
    match val {
        serde_json::Value::Object(map) if map.is_empty() => Ok(Vec::new()),
        serde_json::Value::Object(map) => {
            let mut ext = Vec::with_capacity(map.len());
            for (k, v) in map {
                let idx: u8 = k.parse().map_err(|_| {
                    FastBlockSyncError::Json(format!("invalid context extension key: {k}"))
                })?;
                let bytes = hex::decode(v.as_str().ok_or_else(|| {
                    FastBlockSyncError::Json("context extension value not a string".into())
                })?)?;
                ext.push((idx, bytes));
            }
            // Sort by key to match Scala serialization order
            ext.sort_by_key(|(k, _)| *k);
            Ok(ext)
        }
        _ => Ok(Vec::new()),
    }
}

/// Parse additional registers from serde_json::Value.
///
/// JSON shape: `{}` or `{"R4": "0500...", "R5": "05c0..."}` — keys are
/// register names R4-R9, values are hex-encoded.
fn parse_additional_registers(
    val: &serde_json::Value,
) -> Result<Vec<(u8, Vec<u8>)>, FastBlockSyncError> {
    match val {
        serde_json::Value::Object(map) if map.is_empty() => Ok(Vec::new()),
        serde_json::Value::Object(map) => {
            let mut regs = Vec::with_capacity(map.len());
            for (k, v) in map {
                let idx: u8 = if k.starts_with('R') || k.starts_with('r') {
                    k[1..].parse().map_err(|_| {
                        FastBlockSyncError::Json(format!("invalid register name: {k}"))
                    })?
                } else {
                    k.parse().map_err(|_| {
                        FastBlockSyncError::Json(format!("invalid register key: {k}"))
                    })?
                };
                let bytes = hex::decode(v.as_str().ok_or_else(|| {
                    FastBlockSyncError::Json("register value not a string".into())
                })?)?;
                regs.push((idx, bytes));
            }
            // Sort by register index for deterministic serialization
            regs.sort_by_key(|(k, _)| *k);
            Ok(regs)
        }
        _ => Ok(Vec::new()),
    }
}
```

**Step 3: Verify ergo_wire VLQ functions are public**

Check that `ergo_wire::vlq::put_uint`, `ergo_wire::vlq::put_ushort` are `pub`. If not, make them public.

**Step 4: Verify ErgoTransaction fields match**

Read `crates/ergo-types/src/transaction.rs` to confirm `ErgoTransaction`, `Input`, `SpendingProof`, `ErgoBoxCandidate`, etc. field names. The `SpendingProof.extension` field type must be `Vec<(u8, Vec<u8>)>` and `ErgoBoxCandidate.additional_registers` must also be `Vec<(u8, Vec<u8>)>`. Adjust the conversion code if field names or types differ.

**Step 5: Write a unit test**

Add at the bottom of `fast_block_sync.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_json_to_wire_roundtrip() {
        // Build a JSON extension with known fields
        let ext = JsonExtension {
            header_id: "ab".repeat(32),
            fields: vec![
                ("0001".into(), "deadbeef".into()),
                ("0102".into(), "cafe".into()),
            ],
        };
        let header_id_hex = "ab".repeat(32);
        let wire = extension_json_to_wire(&header_id_hex, &ext).unwrap();

        // Parse it back with the canonical parser
        let parsed = ergo_wire::extension_ser::parse_extension(&wire).unwrap();
        assert_eq!(parsed.fields.len(), 2);
        assert_eq!(parsed.fields[0].0, [0x00, 0x01]);
        assert_eq!(parsed.fields[0].1, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parsed.fields[1].0, [0x01, 0x02]);
        assert_eq!(parsed.fields[1].1, vec![0xCA, 0xFE]);
    }
}
```

**Step 6: Run tests**

```bash
cargo test -p ergo-node fast_block_sync -- --nocapture
cargo clippy -p ergo-node -- -D warnings
```

**Step 7: Commit**

```bash
git add crates/ergo-node/src/fast_block_sync.rs
git commit -m "feat(fast-block-sync): add JSON-to-wire conversion for Extension and BlockTransactions"
```

---

## Task 3: BulkBlockSections Processor Command

**Files:**
- Modify: `crates/ergo-network/src/block_processor.rs`

**Step 1: Add the BulkBlockSections variant to ProcessorCommand**

Add after the existing `BulkHeaders` variant (line ~76):

```rust
    /// A batch of pre-serialized block body sections from fast block sync.
    ///
    /// Each section is stored via put_modifier in a single WriteBatch.
    /// After the batch is written, has_all_sections is checked for each
    /// unique header_id; if all sections are present, apply_progress runs.
    BulkBlockSections {
        /// Tuples of (type_id, header_id, wire_bytes).
        /// header_id is used as the DB key (matching normal section storage).
        sections: Vec<(u8, ModifierId, Vec<u8>)>,
    },
```

**Step 2: Add the command handler dispatch**

In the main `run` loop (around line 272-289), add a match arm for `BulkBlockSections`:

```rust
ProcessorCommand::BulkBlockSections { sections } => {
    process_bulk_block_sections(
        state,
        evt_tx,
        sections,
        &mut BatchAccum {
            new_headers: &mut new_headers,
            blocks_to_download: &mut blocks_to_download,
        },
    );
}
```

**Step 3: Implement the handler function**

Add after `process_bulk_headers`:

```rust
/// Process a `BulkBlockSections` command.
///
/// Stores all sections in a single WriteBatch, then checks has_all_sections
/// for each unique header_id. If a block is complete (header + all body
/// sections present), triggers apply_progress.
fn process_bulk_block_sections(
    state: &mut ProcessorState,
    evt_tx: &tokio::sync::mpsc::Sender<ProcessorEvent>,
    sections: Vec<(u8, ModifierId, Vec<u8>)>,
    _accum: &mut BatchAccum<'_>,
) {
    let count = sections.len();

    // Collect unique header IDs for completeness check after batch write.
    let mut header_ids = Vec::new();

    // Write all sections in a single WriteBatch for fast I/O.
    let mut batch = state.node_view.history.write_batch();
    for (type_id, header_id, wire_bytes) in &sections {
        batch.put_modifier(*type_id, header_id, wire_bytes);
        if !header_ids.contains(header_id) {
            header_ids.push(*header_id);
        }
    }
    if let Err(e) = batch.write() {
        tracing::error!(%e, "bulk_block_sections: batch write failed");
        return;
    }

    tracing::debug!(count, blocks = header_ids.len(), "bulk_block_sections: batch written");

    // For each unique header_id, check if the block is now complete.
    for header_id in &header_ids {
        if state.node_view.history.has_all_sections(header_id).unwrap_or(false) {
            // Block is complete — trigger apply_progress.
            // We call process_block_section with a dummy ProgressInfo just to
            // trigger the apply pipeline. Actually, we should call apply_progress
            // directly if the block's header is at the right height.
            //
            // The simplest approach: let the periodic apply_from_cache / status
            // tick pick these up. Alternatively, explicitly trigger apply.
            // For now, emit a hint that sections are ready.
        }
    }

    // Trigger apply_from_cache which will find complete blocks and apply them.
    apply_from_cache_processor(state, evt_tx);

    // Emit applied blocks if any were applied.
    emit_applied_blocks(state, evt_tx);
}
```

**Important:** The exact implementation of how `apply_progress` gets triggered needs to match how the existing `process_modifier` → `process_block_section` → `apply_progress` flow works. Read `history_db.rs` `process_block_section` to understand what it does and replicate the critical parts (marking sections as present, checking completeness). The WriteBatch `put_modifier` stores the raw bytes; `process_block_section` also updates internal indexes. We may need to call `process_block_section` per header_id after the batch write, or replicate its index updates in the batch.

**Step 4: Verify process_block_section behavior**

Read `crates/ergo-storage/src/history_db.rs` to find `process_block_section` and `has_all_sections`. Understand what index keys they check. If `has_all_sections` only checks that `get_modifier(type_id, header_id)` returns `Some`, then the WriteBatch `put_modifier` is sufficient. If it checks additional index keys, those must also be written.

**Step 5: Run tests**

```bash
cargo test -p ergo-network -- --nocapture
cargo clippy --workspace -- -D warnings
```

**Step 6: Commit**

```bash
git add crates/ergo-network/src/block_processor.rs
git commit -m "feat(fast-block-sync): add BulkBlockSections processor command and handler"
```

---

## Task 4: Fetch-and-Convert Pipeline

**Files:**
- Modify: `crates/ergo-node/src/fast_block_sync.rs`

**Step 1: Add the chunk fetch function**

This fetches a batch of blocks from a peer, converts JSON to wire bytes, and returns sections ready for BulkBlockSections.

```rust
/// Fetch a chunk of blocks from a peer and convert to wire-format sections.
///
/// Returns Vec<(type_id, header_id, wire_bytes)> for BulkBlockSections.
async fn fetch_and_convert_chunk(
    client: &reqwest::Client,
    peer_url: &str,
    header_ids: &[ModifierId],
) -> Result<Vec<(u8, ModifierId, Vec<u8>)>, FastBlockSyncError> {
    // Build the request body: array of header ID hex strings
    let id_strs: Vec<String> = header_ids.iter().map(|id| hex::encode(id.0)).collect();

    let url = format!("{}/blocks/headerIds", peer_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&id_strs)
        .send()
        .await
        .map_err(|e| FastBlockSyncError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(FastBlockSyncError::Http(format!(
            "POST /blocks/headerIds returned {}",
            resp.status()
        )));
    }

    let blocks: Vec<JsonFullBlock> = resp
        .json()
        .await
        .map_err(|e| FastBlockSyncError::Json(e.to_string()))?;

    let mut sections = Vec::with_capacity(blocks.len() * 2);

    for block in &blocks {
        let header_id_hex = &block.header.id;
        let header_id_bytes: [u8; 32] = hex::decode(header_id_hex)?
            .try_into()
            .map_err(|_| FastBlockSyncError::Hex(hex::FromHexError::InvalidStringLength))?;
        let header_id = ModifierId(header_id_bytes);

        // BlockTransactions → wire bytes
        if let Some(bt) = &block.block_transactions {
            let wire = block_transactions_json_to_wire(header_id_hex, bt)?;
            sections.push((102u8, header_id, wire));
        }

        // Extension → wire bytes
        if let Some(ext) = &block.extension {
            let wire = extension_json_to_wire(header_id_hex, ext)?;
            sections.push((108u8, header_id, wire));
        }
    }

    Ok(sections)
}
```

**Step 2: Run tests**

```bash
cargo test -p ergo-node fast_block_sync -- --nocapture
cargo clippy -p ergo-node -- -D warnings
```

**Step 3: Commit**

```bash
git add crates/ergo-node/src/fast_block_sync.rs
git commit -m "feat(fast-block-sync): add fetch-and-convert pipeline for chunk download"
```

---

## Task 5: run_fast_block_sync Pipeline

**Files:**
- Modify: `crates/ergo-node/src/fast_block_sync.rs`

This is the main async pipeline, structured to mirror `run_fast_sync` from `fast_header_sync.rs`.

**Step 1: Add shared type for full height**

```rust
/// Shared atomic that the event loop writes on each BlockApplied event.
/// Fast block sync reads this to throttle (don't get too far ahead of applied height).
pub type SharedFullHeight = std::sync::Arc<std::sync::atomic::AtomicU32>;
```

**Step 2: Implement run_fast_block_sync**

```rust
use crate::fast_header_sync::{ApiPeerUrls, SharedFastSyncActive};

const CHUNK_SIZE: usize = 16;
const HANDOFF_DISTANCE: u32 = 1000;
const PEER_MAX_FAILURES: u32 = 3;
const PEER_FETCH_TIMEOUT_SECS: u64 = 20;
const THROTTLE_LOOKAHEAD: u32 = 50_000;

/// Run the fast block sync pipeline.
///
/// Fetches block body sections via HTTP from peers discovered in `api_urls`.
/// Converts JSON to wire-format bytes and stores via BulkBlockSections.
/// Stops when within HANDOFF_DISTANCE of headers_height or on shutdown.
#[allow(clippy::too_many_arguments)]
pub async fn run_fast_block_sync(
    api_urls: ApiPeerUrls,
    history_path: std::path::PathBuf,
    cmd_tx: std::sync::mpsc::SyncSender<ergo_network::block_processor::ProcessorCommand>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    shared_full_height: SharedFullHeight,
    shared_headers_height: crate::fast_header_sync::SharedHeadersHeight,
) {
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::Ordering;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    // Wait for at least one peer to advertise a REST API URL (up to 60s).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if *shutdown.borrow() {
            return;
        }
        let count = api_urls.read().unwrap().len();
        if count > 0 {
            tracing::info!(peers = count, "fast_block_sync: found API peers");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::info!("fast_block_sync: no API peers after 60s, falling back to P2P");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // Determine the range to sync.
    let full_height = shared_full_height.load(Ordering::Relaxed);
    let headers_height = shared_headers_height.load(Ordering::Relaxed);

    if headers_height < HANDOFF_DISTANCE + full_height {
        tracing::info!(
            full_height,
            headers_height,
            "fast_block_sync: not enough headers ahead, P2P will handle"
        );
        return;
    }

    let start_height = full_height + 1;
    let target_height = headers_height.saturating_sub(HANDOFF_DISTANCE);

    tracing::info!(
        start_height,
        target_height,
        "fast_block_sync: starting bulk download"
    );

    // Open a read-only history DB to walk the height index.
    let history = match ergo_storage::history_db::HistoryDb::open_read_only(&history_path) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(%e, "fast_block_sync: failed to open history DB");
            return;
        }
    };

    // Collect header IDs from the height index and chunk them.
    let mut chunks: VecDeque<Vec<ModifierId>> = VecDeque::new();
    let mut current_chunk = Vec::with_capacity(CHUNK_SIZE);
    for height in start_height..=target_height {
        match history.header_ids_at_height(height) {
            Ok(ids) if !ids.is_empty() => {
                current_chunk.push(ids[0]); // best header at this height
                if current_chunk.len() >= CHUNK_SIZE {
                    chunks.push_back(std::mem::take(&mut current_chunk));
                    current_chunk = Vec::with_capacity(CHUNK_SIZE);
                }
            }
            _ => {
                // Missing header — can happen if fast header sync hasn't caught up yet.
                // Stop chunking here and resume later.
                tracing::debug!(height, "fast_block_sync: missing header, stopping chunk collection");
                break;
            }
        }
    }
    if !current_chunk.is_empty() {
        chunks.push_back(current_chunk);
    }

    let total_chunks = chunks.len();
    tracing::info!(total_chunks, "fast_block_sync: prepared chunk queue");

    // Per-peer failure tracking
    let mut peer_failures: HashMap<u64, u32> = HashMap::new();
    let mut completed = 0usize;

    while let Some(chunk) = chunks.pop_front() {
        if *shutdown.borrow() {
            tracing::info!("fast_block_sync: shutdown signal received");
            break;
        }

        // Throttle: don't get too far ahead of applied height.
        let current_full = shared_full_height.load(Ordering::Relaxed);
        let chunk_min_height = chunk.first().and_then(|id| {
            history.load_header(id).ok().flatten().map(|h| h.height)
        }).unwrap_or(0);
        if chunk_min_height > current_full + THROTTLE_LOOKAHEAD {
            tracing::debug!(
                chunk_min_height,
                current_full,
                "fast_block_sync: throttling (too far ahead)"
            );
            chunks.push_front(chunk);
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        // Pick a healthy peer
        let peer = {
            let urls = api_urls.read().unwrap();
            urls.iter()
                .find(|(id, _)| peer_failures.get(id).copied().unwrap_or(0) < PEER_MAX_FAILURES)
                .map(|(id, url)| (*id, url.clone()))
        };

        let (peer_id, peer_url) = match peer {
            Some(p) => p,
            None => {
                tracing::warn!("fast_block_sync: no healthy peers, waiting 10s");
                chunks.push_front(chunk);
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                // Reset failures after waiting
                peer_failures.clear();
                continue;
            }
        };

        // Fetch with timeout
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(PEER_FETCH_TIMEOUT_SECS),
            fetch_and_convert_chunk(&client, &peer_url, &chunk),
        )
        .await;

        match result {
            Ok(Ok(sections)) if !sections.is_empty() => {
                let section_count = sections.len();
                // Send to processor
                if let Err(e) = cmd_tx.try_send(
                    ergo_network::block_processor::ProcessorCommand::BulkBlockSections {
                        sections,
                    },
                ) {
                    tracing::warn!(%e, "fast_block_sync: processor channel full, retrying chunk");
                    chunks.push_front(chunk);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                completed += 1;
                if completed % 100 == 0 || completed == total_chunks {
                    tracing::info!(
                        completed,
                        total_chunks,
                        section_count,
                        "fast_block_sync: progress"
                    );
                }
            }
            Ok(Ok(_)) => {
                // Empty response — peer doesn't have these blocks
                tracing::debug!(peer_id, "fast_block_sync: empty response, trying next peer");
                *peer_failures.entry(peer_id).or_insert(0) += 1;
                chunks.push_front(chunk);
            }
            Ok(Err(e)) => {
                tracing::warn!(peer_id, %e, "fast_block_sync: fetch error");
                *peer_failures.entry(peer_id).or_insert(0) += 1;
                chunks.push_front(chunk);
            }
            Err(_) => {
                tracing::warn!(peer_id, "fast_block_sync: timeout");
                *peer_failures.entry(peer_id).or_insert(0) += 1;
                chunks.push_front(chunk);
            }
        }
    }

    tracing::info!(completed, "fast_block_sync: finished");
}
```

**Step 3: Run tests**

```bash
cargo test -p ergo-node --lib
cargo clippy -p ergo-node -- -D warnings
```

**Step 4: Commit**

```bash
git add crates/ergo-node/src/fast_block_sync.rs
git commit -m "feat(fast-block-sync): implement run_fast_block_sync parallel pipeline"
```

---

## Task 6: Event Loop Integration

**Files:**
- Modify: `crates/ergo-node/src/event_loop.rs`

**Step 1: Add SharedFullHeight atomic**

Near the existing `shared_headers_height` declaration (line ~319):

```rust
// Shared atomic full-block height — updated by the event loop on each
// BlockApplied event, read by fast block sync to throttle downloads.
let shared_full_height: crate::fast_block_sync::SharedFullHeight =
    std::sync::Arc::new(std::sync::atomic::AtomicU32::new(cached_full_height));
```

**Step 2: Update SharedFullHeight on BlockApplied**

In the `ProcessorEvent::BlockApplied { header_id, height }` handler (find the existing block):

```rust
ProcessorEvent::BlockApplied { header_id, height } => {
    pending_body_sections = pending_body_sections.saturating_sub(2);
    shared_full_height.store(height, std::sync::atomic::Ordering::Relaxed);
    // ... existing logging ...
}
```

**Step 3: Also update on StateUpdate**

In the `ProcessorEvent::StateUpdate` handler, update from `full_height`:

```rust
shared_full_height.store(full_height, std::sync::atomic::Ordering::Relaxed);
```

**Step 4: Spawn fast block sync task**

After the fast header sync spawn block (around line 419), add:

```rust
// Spawn the fast block sync task if enabled.
// Waits for fast header sync to populate headers before starting.
if settings.ergo.node.fast_header_sync {
    let fbs_api_urls = api_peer_urls.clone();
    let fbs_cmd_tx = cmd_tx.clone();
    let fbs_shutdown = shutdown_rx.clone();
    let fbs_full_height = shared_full_height.clone();
    let fbs_headers_height = shared_headers_height.clone();
    let fbs_history_path = settings.ergo.directory.clone().unwrap_or_else(|| ".ergo".into());
    let fbs_history_path = std::path::PathBuf::from(fbs_history_path).join("history");
    tokio::spawn(async move {
        // Wait for fast header sync to make progress first (30s delay).
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        crate::fast_block_sync::run_fast_block_sync(
            fbs_api_urls,
            fbs_history_path,
            fbs_cmd_tx,
            fbs_shutdown,
            fbs_full_height,
            fbs_headers_height,
        )
        .await;
    });
    tracing::info!("fast block sync task spawned (will start after 30s delay)");
}
```

**Step 5: Run tests**

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

**Step 6: Commit**

```bash
git add crates/ergo-node/src/event_loop.rs crates/ergo-node/src/fast_block_sync.rs
git commit -m "feat(fast-block-sync): integrate fast block sync into event loop"
```

---

## Task 7: Wire Format Verification Test

**Files:**
- Modify: `crates/ergo-node/src/fast_block_sync.rs` (test module)

This critical test ensures that JSON→wire→parse roundtrips produce identical results to the canonical serializers.

**Step 1: Add a roundtrip test for BlockTransactions**

```rust
#[test]
fn block_transactions_json_roundtrip() {
    // Build a minimal transaction JSON and convert to wire
    let jtx = JsonTransaction {
        id: "aa".repeat(32),
        inputs: vec![JsonInput {
            box_id: "bb".repeat(32),
            spending_proof: JsonSpendingProof {
                proof_bytes: String::new(),
                extension: serde_json::Value::Object(serde_json::Map::new()),
            },
        }],
        data_inputs: vec![],
        outputs: vec![JsonOutput {
            box_id: None,
            value: 1000000,
            ergo_tree: "0008d3".into(),
            creation_height: 100,
            assets: vec![],
            additional_registers: serde_json::Value::Object(serde_json::Map::new()),
            transaction_id: None,
            index: None,
        }],
    };

    let jbt = JsonBlockTransactions {
        header_id: "cc".repeat(32),
        transactions: vec![jtx],
        block_version: 2,
    };

    let header_id_hex = "cc".repeat(32);
    let wire = block_transactions_json_to_wire(&header_id_hex, &jbt).unwrap();

    // Verify the first 32 bytes are the header_id
    assert_eq!(&wire[..32], &hex::decode(&header_id_hex).unwrap()[..]);

    // Parse back and verify structure
    let parsed = ergo_wire::block_transactions_ser::parse_block_transactions(&wire).unwrap();
    assert_eq!(parsed.header_id.0, hex::decode(&header_id_hex).unwrap().as_slice());
    assert_eq!(parsed.tx_bytes.len(), 1);
    assert_eq!(parsed.block_version, 2);
}
```

**Step 2: Run tests**

```bash
cargo test -p ergo-node fast_block_sync -- --nocapture
cargo clippy -p ergo-node -- -D warnings
```

**Step 3: Commit**

```bash
git add crates/ergo-node/src/fast_block_sync.rs
git commit -m "test(fast-block-sync): add wire format roundtrip verification tests"
```

---

## Task 8: Final Verification

**Step 1: Run full test suite**

```bash
cargo test --workspace
```

**Step 2: Run clippy**

```bash
cargo clippy --workspace -- -D warnings
```

**Step 3: Run fmt**

```bash
cargo fmt --check
```

**Step 4: Build release**

```bash
cargo build --release
```

**Step 5: Fix any issues and commit**

```bash
cargo fmt
git add -A
git commit -m "style: formatting fixes"
```

---

## Summary of Changes

| File | Change |
|------|--------|
| `crates/ergo-node/src/fast_block_sync.rs` | NEW: JSON types, JSON→wire converters, fetch pipeline, run_fast_block_sync |
| `crates/ergo-network/src/block_processor.rs` | ADD: BulkBlockSections command + handler |
| `crates/ergo-node/src/event_loop.rs` | ADD: SharedFullHeight, spawn fast block sync task |
| `crates/ergo-node/src/main.rs` | ADD: `pub mod fast_block_sync` |

## Key Design Decisions

1. **No new config setting** — reuses `fast_header_sync` flag
2. **Wire format via existing serializers** — `serialize_transaction()` ensures consensus-equivalence
3. **WriteBatch for bulk storage** — same pattern as BulkHeaders
4. **Throttle at 50,000 blocks** — bounded disk usage while allowing large batches
5. **30s startup delay** — gives fast header sync time to populate headers first
6. **Read-only history DB** — for walking the height index without blocking the processor
