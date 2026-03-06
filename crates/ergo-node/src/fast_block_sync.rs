//! JSON deserialization types for the block API response (`POST /blocks/headerIds`)
//! and wire-format conversion functions for feeding blocks into `put_modifier`.
//!
//! These are the *inbound* counterparts of the `*Response` types in `api/mod.rs`
//! (which are `Serialize`-only for outbound). We keep them separate so that
//! wire-conversion code can live alongside these types without touching
//! the API module.

use serde::Deserialize;

use ergo_types::block_transactions::MAX_TRANSACTIONS_IN_BLOCK;
use ergo_types::transaction::{BoxId, DataInput, ErgoBoxCandidate, ErgoTransaction, Input, TxId};
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
        put_uint(
            &mut buf,
            MAX_TRANSACTIONS_IN_BLOCK + bt.block_version as u32,
        );
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
fn parse_context_extension(val: &serde_json::Value) -> Result<Vec<u8>, FastBlockSyncError> {
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
            FastBlockSyncError::Json(format!("register value for '{key_str}' is not a string"))
        })?;
        let bytes = hex::decode(hex_str)?;
        regs.push((idx, bytes));
    }
    // Sort by register index for deterministic output
    regs.sort_by_key(|(k, _)| *k);

    Ok(regs)
}

// ── Fetch + convert pipeline ────────────────────────────────────────

/// Fetch a chunk of blocks from a peer and convert to wire-format sections.
///
/// Returns `Vec<(type_id, header_id, wire_bytes)>` for `BulkBlockSections`.
pub(crate) async fn fetch_and_convert_chunk(
    client: &reqwest::Client,
    peer_url: &str,
    header_ids: &[ergo_types::modifier_id::ModifierId],
) -> Result<Vec<(u8, ergo_types::modifier_id::ModifierId, Vec<u8>)>, FastBlockSyncError> {
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
        let header_id = ergo_types::modifier_id::ModifierId(hex_to_32(header_id_hex)?);

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

// ── Shared types ────────────────────────────────────────────────────

/// Shared atomic that the event loop writes on each BlockApplied event.
/// Fast block sync reads this to throttle (don't get too far ahead of applied height).
pub type SharedFullHeight = std::sync::Arc<std::sync::atomic::AtomicU32>;

// ── Pipeline constants ──────────────────────────────────────────────

const CHUNK_SIZE: usize = 16;
const HANDOFF_DISTANCE: u32 = 1000;
const PEER_MAX_FAILURES: u32 = 3;
const PEER_FETCH_TIMEOUT_SECS: u64 = 20;
const THROTTLE_LOOKAHEAD: u32 = 50_000;

// ── Main pipeline ───────────────────────────────────────────────────

/// Run the fast block sync pipeline.
///
/// Fetches block body sections (BlockTransactions + Extension) via the
/// `POST /blocks/headerIds` REST API from peers discovered in `api_urls`.
/// Sends `BulkBlockSections` commands to the processor for storage and
/// application.
///
/// The pipeline:
/// 1. Waits for API peers (up to 60s).
/// 2. Reads current full_height and headers_height from shared atomics.
/// 3. Computes the download range: full_height+1 .. headers_height - HANDOFF_DISTANCE.
/// 4. Walks the height index to collect header IDs, grouping into chunks of CHUNK_SIZE.
/// 5. For each chunk: picks a healthy peer, fetches with timeout, sends to processor.
/// 6. Throttles: won't get more than THROTTLE_LOOKAHEAD blocks ahead of applied height.
/// 7. Handles failures: re-queues failed chunks, tracks per-peer failure counts.
#[allow(clippy::too_many_arguments)]
pub async fn run_fast_block_sync(
    api_urls: crate::fast_header_sync::ApiPeerUrls,
    history: ergo_storage::history_db::HistoryDb,
    cmd_tx: std::sync::mpsc::SyncSender<ergo_network::block_processor::ProcessorCommand>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    shared_full_height: SharedFullHeight,
    shared_headers_height: crate::fast_header_sync::SharedHeadersHeight,
    fast_sync_active: crate::fast_header_sync::SharedFastSyncActive,
) {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    // ── 0. Wait for fast header sync to finish ──────────────────────
    // Block downloads only make sense once the header chain is populated.
    tracing::info!("fast_block_sync: waiting for fast header sync to complete");
    loop {
        if *shutdown.borrow() {
            return;
        }
        // fast_sync_active is set true when header sync starts, false when it ends.
        if !fast_sync_active.load(Ordering::Relaxed) {
            // Check that headers have actually been written (not just "never started").
            let hh = shared_headers_height.load(Ordering::Relaxed);
            if hh > 0 {
                tracing::info!(
                    headers_height = hh,
                    "fast_block_sync: header sync complete, starting block download"
                );
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    // ── 1. Wait for at least one peer (up to 60s) ───────────────────
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if *shutdown.borrow() {
            return;
        }
        let urls: Vec<String> = api_urls.read().unwrap().values().cloned().collect();
        if !urls.is_empty() {
            tracing::info!(peers = urls.len(), "fast_block_sync: found API peers");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::info!("fast_block_sync: no peers with REST API URLs after 60s, giving up");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // ── 2. Get current heights ──────────────────────────────────────
    let full_height = shared_full_height.load(Ordering::Relaxed);
    let headers_height = shared_headers_height.load(Ordering::Relaxed);

    if headers_height <= full_height + HANDOFF_DISTANCE {
        tracing::info!(
            full_height,
            headers_height,
            "fast_block_sync: within handoff distance or already synced"
        );
        return;
    }

    let target = headers_height - HANDOFF_DISTANCE;
    let start = full_height + 1;

    tracing::info!(
        start,
        target,
        "fast_block_sync: walking header chain to build chunk queue"
    );

    // ── 3. Walk best-header chain backwards to build chunk queue ─────
    //
    // The height→ID index may be missing after unclean shutdown, so we
    // walk the header chain via parent_id links instead.  This is O(n)
    // but each RocksDB point-read takes microseconds — ~5-10s for 1.7M
    // headers on SSD.
    let best_id = match history.best_header_id() {
        Ok(Some(id)) => id,
        _ => {
            tracing::info!("fast_block_sync: no best header in DB, exiting");
            return;
        }
    };

    let mut chain: Vec<ergo_types::modifier_id::ModifierId> = Vec::new();
    let mut current_id = best_id;
    let walk_start = std::time::Instant::now();

    loop {
        match history.load_header(&current_id) {
            Ok(Some(h)) => {
                if h.height >= start && h.height <= target {
                    chain.push(current_id);
                }
                if h.height <= start
                    || h.parent_id == ergo_types::modifier_id::ModifierId::GENESIS_PARENT
                {
                    break;
                }
                current_id = h.parent_id;
            }
            Ok(None) => {
                tracing::warn!(
                    id = %hex::encode(current_id.0),
                    "fast_block_sync: header not found during chain walk"
                );
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "fast_block_sync: DB error during chain walk");
                break;
            }
        }
    }

    // Chain was built in descending order; reverse to ascending.
    chain.reverse();

    let walk_elapsed = walk_start.elapsed();
    tracing::info!(
        headers = chain.len(),
        walk_ms = walk_elapsed.as_millis() as u64,
        "fast_block_sync: chain walk complete"
    );

    // Filter out headers that already have body sections.
    let all_ids: Vec<ergo_types::modifier_id::ModifierId> = chain
        .into_iter()
        .filter(|id| !history.has_all_sections(id).unwrap_or(true))
        .collect();

    tracing::info!(
        need_bodies = all_ids.len(),
        "fast_block_sync: filtered to headers missing body sections"
    );

    if all_ids.is_empty() {
        tracing::info!("fast_block_sync: all headers already have body sections, exiting");
        return;
    }

    // Chunk the IDs into batches of CHUNK_SIZE.
    let chunks: Vec<Vec<ergo_types::modifier_id::ModifierId>> =
        all_ids.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();

    tracing::info!(
        chunks = chunks.len(),
        total_ids = all_ids.len(),
        "fast_block_sync: starting parallel fetch"
    );

    // ── 4. Work-stealing queue + peer tracking ──────────────────────
    let pending: Arc<std::sync::Mutex<VecDeque<Vec<ergo_types::modifier_id::ModifierId>>>> =
        Arc::new(std::sync::Mutex::new(chunks.into_iter().collect()));

    let peer_failures: Arc<std::sync::RwLock<HashMap<String, u32>>> =
        Arc::new(std::sync::RwLock::new(HashMap::new()));
    let busy_peers: Arc<std::sync::Mutex<HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));
    let peer_idle = Arc::new(tokio::sync::Notify::new());
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let client = Arc::new(client);
    let cmd_tx = Arc::new(cmd_tx);

    let mut handles = Vec::new();
    let mut total_sections = 0usize;
    let mut chunks_dispatched = 0usize;

    // ── 5. Main dispatch loop ───────────────────────────────────────
    loop {
        if *shutdown.borrow() {
            break;
        }

        // Pop next chunk.
        let chunk = pending.lock().unwrap().pop_front();
        let Some(chunk_ids) = chunk else {
            // Queue appears empty; wait for in-flight tasks.
            if in_flight.load(Ordering::Relaxed) == 0 {
                break;
            }
            tokio::select! {
                _ = peer_idle.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
            }
            continue;
        };

        // ── 6. Throttle ────────────────────────────────────────────
        // Don't get more than THROTTLE_LOOKAHEAD blocks ahead of applied height.
        loop {
            if *shutdown.borrow() {
                break;
            }
            let applied = shared_full_height.load(Ordering::Relaxed);
            let chunk_start = start + (chunks_dispatched as u32) * (CHUNK_SIZE as u32);
            if chunk_start <= applied + THROTTLE_LOOKAHEAD {
                break;
            }
            tracing::debug!(
                chunk_start,
                applied,
                gap = chunk_start - applied,
                "fast_block_sync: throttling (too far ahead)"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // ── 7. Pick a healthy idle peer ─────────────────────────────
        let mut no_peer_polls = 0u32;
        let url = loop {
            if *shutdown.borrow() {
                break None;
            }
            let candidate = {
                let all_urls: Vec<String> = api_urls.read().unwrap().values().cloned().collect();
                let busy = busy_peers.lock().unwrap();
                let failures = peer_failures.read().unwrap();
                all_urls
                    .into_iter()
                    .filter(|u| !busy.contains(u))
                    .find(|u| failures.get(u).copied().unwrap_or(0) < PEER_MAX_FAILURES)
            };
            if let Some(url) = candidate {
                break Some(url);
            }
            no_peer_polls += 1;
            if no_peer_polls > 30 {
                tracing::warn!("fast_block_sync: no healthy peers available after 60s, stopping");
                break None;
            }
            tokio::select! {
                _ = peer_idle.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
        };

        let Some(url) = url else {
            break;
        };

        busy_peers.lock().unwrap().insert(url.clone());
        in_flight.fetch_add(1, Ordering::Relaxed);
        chunks_dispatched += 1;

        // Log progress every 100 chunks.
        if chunks_dispatched.is_multiple_of(100) {
            tracing::info!(
                chunks_dispatched,
                in_flight = in_flight.load(Ordering::Relaxed),
                "fast_block_sync: progress"
            );
        }

        let client = client.clone();
        let cmd_tx = cmd_tx.clone();
        let peer_failures = peer_failures.clone();
        let busy_peers_clone = busy_peers.clone();
        let peer_idle_clone = peer_idle.clone();
        let pending_clone = pending.clone();
        let in_flight_clone = in_flight.clone();

        handles.push(tokio::spawn(async move {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(PEER_FETCH_TIMEOUT_SECS),
                fetch_chunk_and_send(&client, &url, &chunk_ids, &cmd_tx),
            )
            .await;

            let result: Result<usize, FastBlockSyncError> = match result {
                Ok(r) => r,
                Err(_elapsed) => Err(FastBlockSyncError::Http(format!(
                    "peer {url} timed out after {PEER_FETCH_TIMEOUT_SECS}s"
                ))),
            };

            let count = match &result {
                Ok(count) => {
                    tracing::debug!(count, peer = url, "fast_block_sync: chunk done");
                    peer_failures.write().unwrap().remove(&url);
                    *count
                }
                Err(e) => {
                    tracing::debug!(peer = url, error = %e, "fast_block_sync: chunk failed, requeueing");
                    pending_clone.lock().unwrap().push_front(chunk_ids);
                    let mut failures = peer_failures.write().unwrap();
                    let cnt = failures.entry(url.clone()).or_insert(0);
                    *cnt += 1;
                    if *cnt >= PEER_MAX_FAILURES {
                        tracing::warn!(peer = url, "fast_block_sync: peer blacklisted");
                    }
                    0
                }
            };

            busy_peers_clone.lock().unwrap().remove(&url);
            in_flight_clone.fetch_sub(1, Ordering::Relaxed);
            peer_idle_clone.notify_one();

            count
        }));
    }

    // Wait for all in-flight tasks.
    let mut errors = 0usize;
    for handle in handles {
        match handle.await {
            Ok(count) => total_sections += count,
            Err(_) => errors += 1,
        }
    }

    tracing::info!(
        total_sections,
        chunks_dispatched,
        errors,
        "fast_block_sync: parallel fetch complete"
    );
}

/// Fetch one chunk of blocks and send the sections to the processor.
async fn fetch_chunk_and_send(
    client: &reqwest::Client,
    peer_url: &str,
    header_ids: &[ergo_types::modifier_id::ModifierId],
    cmd_tx: &std::sync::mpsc::SyncSender<ergo_network::block_processor::ProcessorCommand>,
) -> Result<usize, FastBlockSyncError> {
    use ergo_network::block_processor::ProcessorCommand;

    let sections = fetch_and_convert_chunk(client, peer_url, header_ids).await?;
    let count = sections.len();

    // Send BulkBlockSections to the processor.
    let mut cmd = ProcessorCommand::BulkBlockSections { sections };
    loop {
        match cmd_tx.try_send(cmd) {
            Ok(()) => break,
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                tokio::task::yield_now().await;
                cmd = returned;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return Ok(count),
        }
    }

    // Trigger apply_from_cache so the processor attempts to assemble complete blocks.
    loop {
        match cmd_tx.try_send(ProcessorCommand::ApplyFromCache) {
            Ok(()) => break,
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                tokio::task::yield_now().await;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
        }
    }

    Ok(count)
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
        let parsed = ergo_wire::block_transactions_ser::parse_block_transactions(&wire).unwrap();
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
        let parsed = ergo_wire::block_transactions_ser::parse_block_transactions(&wire).unwrap();
        assert_eq!(parsed.block_version, 1);
        assert_eq!(parsed.tx_bytes.len(), 1);
    }
}
