//! Companion extractor for the Mode 5 executor-replay oracle test.
//!
//! The replay test in `ergo-sync` crosses the voting-epoch boundary
//! 1_796_096. The digest path recomputes the epoch's voted parameters at
//! that block by walking the previous epoch's 1024 headers' `votes`
//! (`compute_epoch_votes`), reading each through `header_at(height)`. The
//! ADProof-replay corpus only carries headers from 1_795_968 onward, so the
//! recompute would fail at the boundary with a missing-header read for the
//! 1_795_072..1_795_967 prefix.
//!
//! This extractor emits canonical header bytes for that prefix, each gated
//! by `blake2b256(bytes) == header id` (the `/blocks/at/{h}` id) exactly as
//! the main corpus extractor gates them, so the replay test seeds genuine
//! mainnet header bytes for the vote tally rather than synthetic ones.
//!
//! It also emits the active protocol parameters that were in effect for the
//! replay window's start, parsed from the previous epoch-start block's
//! extension (block 1_795_072) through the production `parse_active_params`
//! and `parse_validation_settings_update` parsers. Those become the
//! `voted_params` row the replay test seeds at the epoch start so
//! `store.active_params()` / `store.validation_settings()` reflect the exact
//! pre-boundary state mainnet validated against.
//!
//! Run: `cargo run -p ergo-state --example extract_mode5_prior_headers`

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::{serialize_header, Header};
use ergo_validation::active_params::{parse_active_params, ActiveProtocolParameters};
use ergo_validation::voting::validation_settings::parse_validation_settings_update;
use serde_json::Value;

const NODE: &str = "http://localhost:9053";
/// Previous epoch start for the replay window's first applied epoch. The
/// replay applies 1_795_978..=1_796_160 and crosses the boundary at
/// 1_796_096; that boundary's vote recompute walks [1_795_072, 1_796_095].
const PRIOR_LO: u32 = 1_795_072;
/// One below the main corpus's lowest height (1_795_968) — the corpus
/// supplies 1_795_968 and up.
const PRIOR_HI: u32 = 1_795_967;
/// The epoch-start block whose extension carries the active parameters in
/// effect for the replay window's start.
const START_EPOCH: u32 = 1_795_072;

fn main() {
    // Mainnet ErgoTree / register expressions can parse with deep recursion;
    // headers do not, but keep the large-stack worker for parity with the
    // main extractor in case a future field needs it.
    let worker = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("spawn worker thread");
    match worker.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("\nFATAL: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("\nFATAL: worker thread panicked");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let out_dir = corpus_dir();
    fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;

    let n = PRIOR_HI - PRIOR_LO + 1;
    println!(
        "Extracting prior headers {PRIOR_LO}..={PRIOR_HI} ({n} headers) for the vote recompute"
    );

    let mut headers = serde_json::Map::new();
    let mut gated = 0usize;
    for h in PRIOR_LO..=PRIOR_HI {
        let (header_id, header_json) = fetch_header_at(h)?;
        let header = build_header(&header_json)?;
        let (bytes, id) = serialize_header(&header).map_err(|e| format!("h{h}: serialize: {e}"))?;
        let id_hex = hex::encode(id.as_bytes());
        if id_hex != header_id {
            return Err(format!(
                "h{h}: header id GATE FAILED\n  computed: {id_hex}\n  expected: {header_id}"
            ));
        }
        gated += 1;
        headers.insert(h.to_string(), Value::String(hex::encode(&bytes)));
        if h.is_multiple_of(128) || h == PRIOR_HI {
            println!("  h{h} id={}... gated", &header_id[..16]);
        }
    }

    // Active params for the replay window's start, parsed from the previous
    // epoch-start block's extension through the production parsers.
    let start_params = fetch_start_epoch_params()?;

    let record = serde_json::json!({
        "prior_lo": PRIOR_LO,
        "prior_hi": PRIOR_HI,
        "start_epoch_height": START_EPOCH,
        "headers": headers,
        "start_active_params_hex": hex::encode(
            start_params.serialize().map_err(|e| format!("serialize start params: {e}"))?
        ),
    });

    let path = out_dir.join("prior_headers.json");
    let serialized =
        serde_json::to_string_pretty(&record).map_err(|e| format!("serialize record: {e}"))?;
    fs::write(&path, serialized).map_err(|e| format!("write {}: {e}", path.display()))?;

    println!("\n=== DONE ===");
    println!("  prior headers written: {gated} ({PRIOR_LO}..={PRIOR_HI})");
    println!("  header id gate:        100% passed");
    println!(
        "  start active params:   epoch_start={}  max_block_cost={}  max_block_size={}  disabled={:?}",
        start_params.epoch_start_height,
        start_params.max_block_cost,
        start_params.max_block_size,
        start_params.activated_update.rules_to_disable,
    );
    println!("  file:                  {}", path.display());
    Ok(())
}

/// Parse the active parameter set for the replay window's start from the
/// previous epoch-start block's extension. The numeric params come from
/// `parse_active_params`; the cumulative validation settings (Scala's
/// `0x02` prefix entries) are folded into this row's `activated_update` so
/// the replay store's `validation_settings` reflects them exactly — the
/// store derives settings by folding every row's `activated_update`.
fn fetch_start_epoch_params() -> Result<ActiveProtocolParameters, String> {
    let block = fetch_block_at(START_EPOCH)?;
    let extension = build_extension(&block["extension"])?;
    let mut params = parse_active_params(&extension, START_EPOCH)
        .map_err(|e| format!("parse_active_params at {START_EPOCH}: {e}"))?;
    let cumulative = parse_validation_settings_update(&extension)
        .map_err(|e| format!("parse_validation_settings_update at {START_EPOCH}: {e}"))?;
    // Seed the cumulative validation settings as this row's activated_update
    // so `compute_validation_settings_at(start) == empty.updated(cumulative)
    // == cumulative` — the exact pre-boundary cumulative the extension at
    // the next boundary is checked against.
    params.activated_update = cumulative;
    Ok(params)
}

fn build_extension(ext_json: &Value) -> Result<Extension, String> {
    let mut fields: Vec<ExtensionField> = Vec::new();
    for pair in ext_json["fields"]
        .as_array()
        .ok_or_else(|| "extension missing fields".to_string())?
    {
        let arr = pair
            .as_array()
            .ok_or_else(|| "extension field not a pair".to_string())?;
        if arr.len() != 2 {
            return Err(format!("extension field pair has {} elements", arr.len()));
        }
        let key = hex_n::<2>(
            arr[0].as_str().ok_or("extension key not a string")?,
            "extension key",
        )?;
        let value = hex::decode(arr[1].as_str().ok_or("extension value not a string")?)
            .map_err(|e| format!("bad extension value hex: {e}"))?;
        fields.push(ExtensionField { key, value });
    }
    // header_id is irrelevant to param parsing (the parsers read fields).
    Ok(Extension {
        header_id: ModifierId::from_bytes([0u8; 32]),
        fields,
    })
}

/// Build a `Header` from the header JSON (Autolykos V2, header v2+).
/// Mirrors `extract_mode5_corpus::build_header`.
fn build_header(header: &Value) -> Result<Header, String> {
    let version = u8::try_from(json_u64(header, "version")?)
        .map_err(|_| "header version overflows u8".to_string())?;
    let parent_id = hex32(header, "parentId").map(ModifierId::from_bytes)?;
    let ad_proofs_root = hex32(header, "adProofsRoot").map(Digest32::from_bytes)?;
    let transactions_root = hex32(header, "transactionsRoot").map(Digest32::from_bytes)?;
    let state_root = hex_n::<33>(json_str(header, "stateRoot")?.as_str(), "stateRoot")
        .map(ADDigest::from_bytes)?;
    let timestamp = json_u64(header, "timestamp")?;
    let extension_root = hex32(header, "extensionHash").map(Digest32::from_bytes)?;
    let n_bits = json_u32(header, "nBits")?;
    let height = json_u32(header, "height")?;
    let votes = hex_n::<3>(json_str(header, "votes")?.as_str(), "votes")?;

    let pow = header
        .get("powSolutions")
        .ok_or_else(|| "header missing powSolutions".to_string())?;
    let pk = hex_n::<33>(json_str(pow, "pk")?.as_str(), "powSolutions.pk")
        .map(GroupElement::from_bytes)?;
    let nonce = hex_n::<8>(json_str(pow, "n")?.as_str(), "powSolutions.n")?;

    if version < 2 {
        return Err(format!(
            "header version {version} is pre-Autolykos-v2; this extractor targets v2+ headers"
        ));
    }
    let solution = AutolykosSolution::V2 { pk, nonce };

    Ok(Header {
        version,
        parent_id,
        ad_proofs_root,
        transactions_root,
        state_root,
        timestamp,
        extension_root,
        n_bits,
        height,
        votes,
        unparsed_bytes: vec![],
        solution,
    })
}

// ----- node REST helpers -----

fn fetch_header_at(h: u32) -> Result<(String, Value), String> {
    let id = fetch_block_id_at(h)?;
    let header = curl_json(&format!("{NODE}/blocks/{id}/header"))?;
    Ok((id, header))
}

fn fetch_block_at(h: u32) -> Result<Value, String> {
    let id = fetch_block_id_at(h)?;
    curl_json(&format!("{NODE}/blocks/{id}"))
}

fn fetch_block_id_at(h: u32) -> Result<String, String> {
    let arr = curl_json(&format!("{NODE}/blocks/at/{h}"))?;
    arr.as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("no block id at height {h}"))
}

fn curl_json(url: &str) -> Result<Value, String> {
    let out = Command::new("curl")
        .args(["-s", "--fail-with-body", url])
        .output()
        .map_err(|e| format!("curl spawn failed for {url}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} failed (status {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("parse JSON from {url}: {e}"))
}

// ----- small JSON accessors (mirror extract_mode5_corpus) -----

fn json_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing/invalid string field '{key}'"))
}

fn json_u32(v: &Value, key: &str) -> Result<u32, String> {
    let n = v
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing/invalid u64 field '{key}'"))?;
    u32::try_from(n).map_err(|_| format!("field '{key}' overflows u32: {n}"))
}

fn json_u64(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing/invalid u64 field '{key}'"))
}

fn hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    hex::decode(s)
        .map_err(|e| format!("{what}: bad hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("{what}: expected {N} bytes, got {}", v.len()))
}

fn hex32(v: &Value, key: &str) -> Result<[u8; 32], String> {
    hex_n::<32>(json_str(v, key)?.as_str(), key)
}

/// Output directory: the `mode5` parent, NOT the `ad_proofs_replay`
/// subdir. The in-memory replay test scans every `*.json` under
/// `ad_proofs_replay` as a per-height row, so this companion fixture lives
/// one level up to stay out of that scan.
fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors")
        .join("mode5")
}
