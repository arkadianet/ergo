//! Fast header sync via chainSlice REST API.

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;

/// A single header from the chainSlice JSON response.
///
/// The Scala reference node encodes `extensionRoot` as `"extensionHash"` in JSON.
/// We accept both names via `#[serde(alias)]` for compatibility with different API
/// implementations (Scala reference uses `extensionHash`, our Rust node uses `extensionRoot`).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSliceHeader {
    pub id: String,
    pub parent_id: String,
    pub height: u32,
    pub timestamp: u64,
    pub n_bits: u64,
    pub version: u8,
    pub state_root: String,
    pub transactions_root: String,
    #[serde(alias = "extensionRoot")]
    pub extension_hash: String,
    pub ad_proofs_root: String,
    pub pow_solutions: ChainSlicePow,
    pub votes: String,
}

/// PoW solution fields from chainSlice JSON.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSlicePow {
    pub pk: String,
    pub w: String,
    pub n: String,
    pub d: String,
}

/// Convert a chainSlice JSON header into an ergo_types Header.
/// Returns (ModifierId, Header, raw_wire_bytes).
pub fn json_header_to_wire(
    jh: &ChainSliceHeader,
) -> Result<(ModifierId, Header, Vec<u8>), FastSyncError> {
    use blake2::digest::{Update, VariableOutput};
    use ergo_types::header::AutolykosSolution;
    use ergo_types::modifier_id::{ADDigest, Digest32};

    let parent_id_bytes = hex::decode(&jh.parent_id)?;
    let ad_proofs_root_bytes = hex::decode(&jh.ad_proofs_root)?;
    let transactions_root_bytes = hex::decode(&jh.transactions_root)?;
    let state_root_bytes = hex::decode(&jh.state_root)?;
    let extension_root_bytes = hex::decode(&jh.extension_hash)?;
    let votes_bytes = hex::decode(&jh.votes)?;
    let pk_bytes = hex::decode(&jh.pow_solutions.pk)?;
    let w_bytes = hex::decode(&jh.pow_solutions.w)?;
    let n_bytes = hex::decode(&jh.pow_solutions.n)?;

    // d is a decimal BigUint string; convert to unsigned big-endian bytes.
    // Scala uses BigIntegers.asUnsignedByteArray() which does NOT add a leading 0x00.
    let d_bytes = if jh.pow_solutions.d == "0" {
        Vec::new()
    } else {
        use num_bigint::BigUint;
        let d_val: BigUint = jh
            .pow_solutions
            .d
            .parse()
            .map_err(|e| FastSyncError::InvalidField(format!("d: {e}")))?;
        d_val.to_bytes_be()
    };

    let to_32 = |v: &[u8], name: &str| -> Result<[u8; 32], FastSyncError> {
        v.try_into().map_err(|_| {
            FastSyncError::InvalidField(format!("{name}: expected 32 bytes, got {}", v.len()))
        })
    };
    let to_33 = |v: &[u8], name: &str| -> Result<[u8; 33], FastSyncError> {
        v.try_into().map_err(|_| {
            FastSyncError::InvalidField(format!("{name}: expected 33 bytes, got {}", v.len()))
        })
    };

    let header = Header {
        version: jh.version,
        parent_id: ModifierId(to_32(&parent_id_bytes, "parentId")?),
        ad_proofs_root: Digest32(to_32(&ad_proofs_root_bytes, "adProofsRoot")?),
        transactions_root: Digest32(to_32(&transactions_root_bytes, "transactionsRoot")?),
        state_root: ADDigest(to_33(&state_root_bytes, "stateRoot")?),
        timestamp: jh.timestamp,
        extension_root: Digest32(to_32(&extension_root_bytes, "extensionRoot")?),
        n_bits: jh.n_bits,
        height: jh.height,
        votes: votes_bytes
            .as_slice()
            .try_into()
            .map_err(|_| FastSyncError::InvalidField("votes: expected 3 bytes".into()))?,
        unparsed_bytes: Vec::new(),
        pow_solution: AutolykosSolution {
            miner_pk: to_33(&pk_bytes, "pk")?,
            w: to_33(&w_bytes, "w")?,
            nonce: n_bytes
                .as_slice()
                .try_into()
                .map_err(|_| FastSyncError::InvalidField("nonce: expected 8 bytes".into()))?,
            d: d_bytes,
        },
    };

    let raw = ergo_wire::header_ser::serialize_header(&header);

    // Compute header ID = blake2b256(raw).
    let mut hasher = blake2::Blake2bVar::new(32).unwrap();
    hasher.update(&raw);
    let mut id_bytes = [0u8; 32];
    hasher.finalize_variable(&mut id_bytes).unwrap();
    let mid = ModifierId(id_bytes);

    // Verify computed ID matches declared ID.
    let declared_id = hex::decode(&jh.id)?;
    if declared_id.len() == 32 && mid.0.as_slice() != declared_id.as_slice() {
        return Err(FastSyncError::InvalidField(format!(
            "header ID mismatch: computed {} vs declared {}",
            hex::encode(mid.0),
            jh.id
        )));
    }

    Ok((mid, header, raw))
}

/// Divide a height range into chunks of `chunk_size`.
/// Returns Vec<(from_height, to_height)> inclusive on both ends.
pub fn compute_chunks(our_height: u32, best_height: u32, chunk_size: u32) -> Vec<(u32, u32)> {
    if best_height <= our_height {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut from = our_height + 1;
    while from <= best_height {
        let to = (from + chunk_size - 1).min(best_height);
        chunks.push((from, to));
        from = to + 1;
    }
    chunks
}

/// Fetch headers from a peer's chainSlice endpoint.
/// Returns parsed ChainSliceHeader objects.
pub async fn fetch_chain_slice(
    client: &reqwest::Client,
    base_url: &str,
    from_height: u32,
    to_height: u32,
) -> Result<Vec<ChainSliceHeader>, FastSyncError> {
    let url = format!(
        "{}/blocks/chainSlice?fromHeight={}&toHeight={}",
        base_url.trim_end_matches('/'),
        from_height,
        to_height,
    );
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| FastSyncError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(FastSyncError::Http(format!("HTTP {}", resp.status())));
    }

    let headers: Vec<ChainSliceHeader> = resp
        .json()
        .await
        .map_err(|e| FastSyncError::Http(e.to_string()))?;
    Ok(headers)
}

/// Fetch the best header height from a peer's /info endpoint.
pub async fn fetch_peer_height(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<u32, FastSyncError> {
    let url = format!("{}/info", base_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| FastSyncError::Http(e.to_string()))?;

    let info: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FastSyncError::Http(e.to_string()))?;

    info.get("headersHeight")
        .or_else(|| info.get("bestHeaderHeight"))
        .and_then(|v| v.as_u64())
        .map(|h| h as u32)
        .ok_or_else(|| FastSyncError::InvalidField("missing headersHeight in /info".into()))
}

/// Run the fast header sync pipeline.
///
/// Fetches headers via HTTP from `api_urls`, validates PoW, and sends them
/// to the processor via `cmd_tx`. Stops when within `HANDOFF_DISTANCE` of
/// the chain tip or when `shutdown` is signalled.
pub async fn run_fast_sync(
    api_urls: Vec<String>,
    our_height: u32,
    chunk_size: u32,
    max_concurrent: u32,
    cmd_tx: std::sync::mpsc::SyncSender<ergo_network::block_processor::ProcessorCommand>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    if api_urls.is_empty() {
        tracing::info!("fast_header_sync: no peers with REST API URLs, skipping");
        return;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap();

    // Discover best height from first available peer
    let mut best_height = 0u32;
    for url in &api_urls {
        match fetch_peer_height(&client, url).await {
            Ok(h) => {
                best_height = h;
                tracing::info!(height = h, url, "fast_header_sync: discovered chain height");
                break;
            }
            Err(e) => {
                tracing::warn!(url, error = %e, "fast_header_sync: failed to query /info");
            }
        }
    }

    if best_height <= our_height {
        tracing::info!(our_height, best_height, "fast_header_sync: already synced");
        return;
    }

    const HANDOFF_DISTANCE: u32 = 1000;
    let target = best_height.saturating_sub(HANDOFF_DISTANCE);
    if target <= our_height {
        tracing::info!("fast_header_sync: within handoff distance, P2P will handle");
        return;
    }

    let chunks = compute_chunks(our_height, target, chunk_size);
    tracing::info!(
        chunks = chunks.len(),
        from = our_height + 1,
        to = target,
        peers = api_urls.len(),
        "fast_header_sync: starting parallel fetch"
    );

    let semaphore = Arc::new(Semaphore::new(max_concurrent as usize));
    let client = Arc::new(client);
    let api_urls = Arc::new(api_urls);
    let cmd_tx = Arc::new(cmd_tx);

    let mut handles = Vec::new();

    for (i, (from, to)) in chunks.into_iter().enumerate() {
        if *shutdown.borrow() {
            break;
        }

        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = api_urls[i % api_urls.len()].clone();
        let cmd_tx = cmd_tx.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit;
            let result = fetch_and_validate_chunk(&client, &url, from, to, &cmd_tx).await;
            match &result {
                Ok(count) => tracing::debug!(from, to, count, "fast_header_sync: chunk done"),
                Err(e) => tracing::warn!(from, to, error = %e, "fast_header_sync: chunk failed"),
            }
            result
        });
        handles.push(handle);
    }

    let mut total = 0usize;
    let mut errors = 0usize;
    for handle in handles {
        match handle.await {
            Ok(Ok(count)) => total += count,
            Ok(Err(_)) => errors += 1,
            Err(_) => errors += 1,
        }
    }

    tracing::info!(
        total_headers = total,
        errors,
        "fast_header_sync: parallel fetch complete"
    );
}

/// Fetch one chunk of headers, validate PoW, and send to the processor.
async fn fetch_and_validate_chunk(
    client: &reqwest::Client,
    base_url: &str,
    from: u32,
    to: u32,
    cmd_tx: &std::sync::mpsc::SyncSender<ergo_network::block_processor::ProcessorCommand>,
) -> Result<usize, FastSyncError> {
    use ergo_network::block_processor::ProcessorCommand;

    let json_headers = fetch_chain_slice(client, base_url, from, to).await?;

    // Convert JSON to wire headers
    let mut wire_headers = Vec::with_capacity(json_headers.len());
    for jh in &json_headers {
        match json_header_to_wire(jh) {
            Ok(triple) => wire_headers.push(triple),
            Err(e) => {
                tracing::warn!(height = jh.height, error = %e, "fast_header_sync: bad header");
            }
        }
    }

    // Validate PoW for each header
    let validated: Vec<_> = wire_headers
        .into_iter()
        .filter(
            |(_, header, _)| match ergo_consensus::header_validation::validate_pow(header) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        height = header.height,
                        error = %e,
                        "fast_header_sync: PoW invalid"
                    );
                    false
                }
            },
        )
        .collect();

    let count = validated.len();

    // Sort by height and send to processor
    let mut validated = validated;
    validated.sort_by_key(|(_, h, _)| h.height);

    for (mid, header, raw) in validated {
        let _ = cmd_tx.try_send(ProcessorCommand::StorePrevalidatedHeader {
            modifier_id: mid,
            header: Box::new(header),
            raw_data: raw,
            peer_hint: None,
        });
    }
    let _ = cmd_tx.try_send(ProcessorCommand::ApplyFromCache);

    Ok(count)
}

/// Errors from the fast sync subsystem.
#[derive(Debug, thiserror::Error)]
pub enum FastSyncError {
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid header field: {0}")]
    InvalidField(String),
    #[error("HTTP request failed: {0}")]
    Http(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real mainnet block 1 header data from the Ergo reference node API.
    /// Field names match the Scala jsonEncoder output (extensionHash, not extensionRoot).
    fn sample_json() -> &'static str {
        r#"{
            "id": "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
            "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 1,
            "timestamp": 1561978977137,
            "nBits": 100734821,
            "version": 1,
            "stateRoot": "18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303",
            "transactionsRoot": "93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba",
            "extensionHash": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            "adProofsRoot": "766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb",
            "powSolutions": {
                "pk": "03be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb66",
                "w": "02da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0",
                "n": "000000030151dc63",
                "d": "46909460813884299753486408728361968139945651324239558400157099627"
            },
            "votes": "000000"
        }"#
    }

    #[test]
    fn parse_chain_slice_json() {
        let jh: ChainSliceHeader = serde_json::from_str(sample_json()).unwrap();
        assert_eq!(jh.height, 1);
        assert_eq!(jh.version, 1);
        assert_eq!(jh.n_bits, 100734821);
    }

    #[test]
    fn parse_chain_slice_json_extension_root_alias() {
        // Our Rust node uses extensionRoot, not extensionHash.
        // Verify the serde alias works.
        let json = r#"{
            "id": "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
            "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 1,
            "timestamp": 1561978977137,
            "nBits": 100734821,
            "version": 1,
            "stateRoot": "18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303",
            "transactionsRoot": "93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba",
            "extensionRoot": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            "adProofsRoot": "766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb",
            "powSolutions": {
                "pk": "03be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb66",
                "w": "02da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0",
                "n": "000000030151dc63",
                "d": "46909460813884299753486408728361968139945651324239558400157099627"
            },
            "votes": "000000"
        }"#;
        let jh: ChainSliceHeader = serde_json::from_str(json).unwrap();
        assert_eq!(
            jh.extension_hash,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn json_header_to_wire_produces_valid_header() {
        let jh: ChainSliceHeader = serde_json::from_str(sample_json()).unwrap();
        let (mid, header, raw) = json_header_to_wire(&jh).unwrap();

        // ID should match the declared id from JSON
        let expected_id = hex::decode(&jh.id).unwrap();
        assert_eq!(mid.0.as_slice(), expected_id.as_slice());

        // Header fields should match JSON
        assert_eq!(header.height, 1);
        assert_eq!(header.version, 1);
        assert_eq!(header.n_bits, 100734821);
        assert_eq!(header.timestamp, 1561978977137);
        assert_eq!(hex::encode(header.votes), "000000");

        // Raw bytes should be non-empty wire-format serialization
        assert!(!raw.is_empty());

        // blake2b256(raw) should equal the declared ID
        use blake2::digest::{Update, VariableOutput};
        let mut hasher = blake2::Blake2bVar::new(32).unwrap();
        hasher.update(&raw);
        let mut hash = [0u8; 32];
        hasher.finalize_variable(&mut hash).unwrap();
        assert_eq!(&hash, mid.0.as_slice());
    }

    #[test]
    fn compute_chunks_splits_height_range() {
        let chunks = compute_chunks(0, 20000, 8192);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], (1, 8192));
        assert_eq!(chunks[1], (8193, 16384));
        assert_eq!(chunks[2], (16385, 20000));
    }

    #[test]
    fn compute_chunks_single_chunk() {
        let chunks = compute_chunks(0, 100, 8192);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], (1, 100));
    }

    #[test]
    fn compute_chunks_exact_boundary() {
        let chunks = compute_chunks(0, 8192, 8192);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], (1, 8192));
    }

    #[test]
    fn compute_chunks_nonzero_start() {
        let chunks = compute_chunks(5000, 15000, 4096);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], (5001, 9096));
        assert_eq!(chunks[1], (9097, 13192));
        assert_eq!(chunks[2], (13193, 15000));
    }

    #[test]
    fn json_header_to_wire_bad_hex_returns_error() {
        let bad_json = r#"{
            "id": "ZZZZ",
            "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 1, "timestamp": 0, "nBits": 0, "version": 1,
            "stateRoot": "00", "transactionsRoot": "00", "extensionHash": "00",
            "adProofsRoot": "00",
            "powSolutions": { "pk": "00", "w": "00", "n": "00", "d": "0" },
            "votes": "000000"
        }"#;
        let jh: ChainSliceHeader = serde_json::from_str(bad_json).unwrap();
        assert!(json_header_to_wire(&jh).is_err());
    }

    #[test]
    fn json_header_to_wire_v2_header() {
        // A v2 header (height > 417792) — d should be "0" (empty bytes)
        let json = r#"{
            "id": "0000000000000000000000000000000000000000000000000000000000000001",
            "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 500000,
            "timestamp": 1700000000000,
            "nBits": 117440512,
            "version": 2,
            "stateRoot": "a5df145d41ab15a01e0cd3ffbab046f0d029e5412293072ad0f5827428589b9302",
            "transactionsRoot": "93fb06ab9d1352ee48de921543d6e78a78290e1e9f1a0670a956368ce575dc19",
            "extensionRoot": "9e5eab14b67a63fb18c33c7a1b3d5ab0ce7f2b8dfed6c4e0e50234abe17d5dbc",
            "adProofsRoot": "b7e6b85fd1afb5a2cff7e34b2c7e11eb0b0ebec95e49cb1c2fd53fd201b8a94b",
            "powSolutions": {
                "pk": "0350e25cee8562697d55275c96bb01b34228f9bd68fd9933f2a25ff195526864f5",
                "w": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "n": "00000000deadbeef",
                "d": "0"
            },
            "votes": "000000"
        }"#;
        let jh: ChainSliceHeader = serde_json::from_str(json).unwrap();
        let result = json_header_to_wire(&jh);
        // The ID won't match since we used a dummy — that's expected.
        match result {
            Ok((_, header, raw)) => {
                assert_eq!(header.height, 500000);
                assert_eq!(header.version, 2);
                assert!(!raw.is_empty());
            }
            Err(FastSyncError::InvalidField(msg)) if msg.contains("ID mismatch") => {
                // Expected for dummy data — ID won't match declared dummy "01" ID
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
