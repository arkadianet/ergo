//! Streamed archival replay driver for the fuzz-differential harness.
//!
//! Pulls full blocks from a live Scala node one at a time, applies them
//! in-process via the same pipeline the Rust node uses, and diffs the
//! resulting state root against the Scala-committed `stateRoot` field.
//! Any divergence is emitted as a JSONL record; the final summary line
//! reports totals. Exit non-zero on any divergence or pin mismatch.
//!
//! Usage:
//!   replay [--from <h>] --to <h> [--node <url>] [--pins <path>]
//!
//! The `--from` height must be 1 (contiguous-from-genesis only). The
//! apply pipeline needs the full UTXO history to validate each block's
//! input boxes, so there is no mid-chain entry point.
//!
//! Genesis initialization: the 3 Ergo genesis boxes are embedded at
//! compile time from `test-vectors/mainnet/genesis_boxes.json` (the same
//! file the chain-validate integration tests use). The genesis block
//! (height 1) is applied unchecked via `StateStore::apply_genesis`;
//! subsequent blocks go through `validate_full_block_parallel` then
//! `StateStore::apply_block`.
//!
//! HTTP client: plain HTTP/1.1 over `std::net::TcpStream`. No new
//! runtime or HTTP-client dependencies — the workspace has no blocking
//! HTTP client and the local-node use case doesn't need one.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as IoRead, Write as IoWrite};
use std::net::TcpStream;

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_rest_json::types::ScalaFullBlock;
use ergo_rest_json::{
    decode_block_transactions_with_mode, decode_extension, decode_scala_header, DecodeMode,
};
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{read_block_transactions, BlockTransactions};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::extension::{read_extension, Extension};
use ergo_ser::header::{read_header, Header};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_state::chain::HeaderMeta;
use ergo_state::store::{StateError, StateStore};
use ergo_validation::block::{validate_full_block_parallel, BlockValidationContext};
use ergo_validation::header::CheckedHeader;
use ergo_validation::ProtocolParams;
use serde::Deserialize;

// ── embedded genesis fixtures ──────────────────────────────────────────────

/// The 3 Ergo genesis boxes, embedded at compile time.
/// Same file as `ergo-state/tests/chain_validate_1_*.rs`.
static GENESIS_BOXES_JSON: &str = include_str!("../../../test-vectors/mainnet/genesis_boxes.json");

// ── CLI args ────────────────────────────────────────────────────────────────

struct Args {
    from: u32,
    to: u32,
    node: String,
    pins_path: String,
}

impl Args {
    fn parse(mut argv: impl Iterator<Item = String>) -> Result<Self, String> {
        // skip argv[0]
        argv.next();
        let mut from = 1u32;
        let mut to: Option<u32> = None;
        let mut node = "http://127.0.0.1:9053".to_string();
        let mut pins_path = "ergo-difftest/replay-pins.json".to_string();

        while let Some(arg) = argv.next() {
            match arg.as_str() {
                "--from" => {
                    from = argv
                        .next()
                        .ok_or("--from needs a value")?
                        .parse()
                        .map_err(|e| format!("--from: {e}"))?;
                }
                "--to" => {
                    to = Some(
                        argv.next()
                            .ok_or("--to needs a value")?
                            .parse()
                            .map_err(|e| format!("--to: {e}"))?,
                    );
                }
                "--node" => {
                    node = argv.next().ok_or("--node needs a value")?;
                }
                "--pins" => {
                    pins_path = argv.next().ok_or("--pins needs a value")?;
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Args {
            from,
            to: to.ok_or("--to is required")?,
            node,
            pins_path,
        })
    }
}

// ── pin file ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PinFile {
    heights: HashMap<String, PinEntry>,
}

#[derive(Deserialize)]
struct PinEntry {
    #[serde(rename = "headerId")]
    header_id: String,
    #[serde(rename = "stateRoot")]
    state_root: String,
}

fn load_pins(path: &str) -> Result<HashMap<u32, PinEntry>, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read pins file {path}: {e}"))?;
    let pf: PinFile =
        serde_json::from_str(&data).map_err(|e| format!("pins JSON parse error: {e}"))?;
    let mut out = HashMap::new();
    for (k, v) in pf.heights {
        let h: u32 = k
            .parse()
            .map_err(|e| format!("pin key {k:?} is not a u32: {e}"))?;
        out.insert(h, v);
    }
    Ok(out)
}

// ── plain HTTP/1.1 client ───────────────────────────────────────────────────
//
// The workspace carries no blocking HTTP client library. The replay driver
// only talks to a local node, so raw HTTP/1.1 over TcpStream is sufficient.
// A new connection is opened per request; connection pooling is not needed
// for a CLI tool running at most a few thousand requests.

/// Parse `http://host:port` → `(host_port, "")` or `http://host:port/path`.
fn parse_http_url(url: &str) -> Result<(String, String), String> {
    let without_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// URLs supported, got: {url}"))?;
    let slash_pos = without_scheme.find('/').unwrap_or(without_scheme.len());
    let host_port = without_scheme[..slash_pos].to_string();
    let path = if slash_pos < without_scheme.len() {
        without_scheme[slash_pos..].to_string()
    } else {
        "/".to_string()
    };
    Ok((host_port, path))
}

/// Blocking HTTP GET. Returns the response body as a String on 200 OK.
/// Any non-200 status or network error is returned as Err.
fn http_get(base_url: &str, path: &str) -> Result<String, String> {
    let (host_port, _base_path) = parse_http_url(base_url)?;
    // If the base URL has a path prefix (rare), combine carefully.
    // For :9053 base = "http://127.0.0.1:9053" so base_path = "/" and we use `path` directly.
    let full_path = path;

    let mut stream =
        TcpStream::connect(&host_port).map_err(|e| format!("TCP connect to {host_port}: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .ok();

    // Send HTTP/1.1 GET request
    let request = format!(
        "GET {full_path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("HTTP write: {e}"))?;

    // Read response
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("HTTP read status: {e}"))?;
    let status_line = status_line.trim();

    // Parse status code
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed HTTP status line: {status_line:?}"))?;

    // Read headers to find Content-Length and skip to body
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("HTTP header read: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break; // blank line = end of headers
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            content_length = trimmed[15..].trim().parse().ok();
        }
        if lower.contains("transfer-encoding") && lower.contains("chunked") {
            chunked = true;
        }
    }

    if status != 200 {
        // Drain a bit of body for the error message
        let mut snippet = vec![0u8; 256];
        let n = IoRead::read(&mut reader, &mut snippet).unwrap_or(0);
        let body_hint = String::from_utf8_lossy(&snippet[..n]);
        return Err(format!("HTTP {status} from {full_path}: {body_hint}"));
    }

    // Read body
    let body = if chunked {
        // Read chunked transfer encoding
        let mut body = Vec::new();
        loop {
            let mut size_line = String::new();
            reader
                .read_line(&mut size_line)
                .map_err(|e| format!("chunk size read: {e}"))?;
            let chunk_size = usize::from_str_radix(size_line.trim(), 16)
                .map_err(|e| format!("chunk size parse {size_line:?}: {e}"))?;
            if chunk_size == 0 {
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            read_exact_from_bufreader(&mut reader, &mut chunk)
                .map_err(|e| format!("chunk body read: {e}"))?;
            body.extend_from_slice(&chunk);
            // trailing \r\n after chunk data
            let mut crlf = [0u8; 2];
            read_exact_from_bufreader(&mut reader, &mut crlf)
                .map_err(|e| format!("chunk CRLF: {e}"))?;
        }
        String::from_utf8(body).map_err(|e| format!("response body UTF-8: {e}"))?
    } else if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        read_exact_from_bufreader(&mut reader, &mut body).map_err(|e| format!("body read: {e}"))?;
        String::from_utf8(body).map_err(|e| format!("response body UTF-8: {e}"))?
    } else {
        // No content-length, no chunked — read until EOF
        let mut body = String::new();
        loop {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| format!("body read: {e}"))?;
            if n == 0 {
                break;
            }
            body.push_str(&line);
        }
        body
    };

    Ok(body)
}

fn read_exact_from_bufreader<R: BufRead>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = reader.read(&mut buf[offset..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF reading HTTP body",
            ));
        }
        offset += n;
    }
    Ok(())
}

// ── node API helpers ─────────────────────────────────────────────────────────

/// `GET /blocks/at/{h}` → first headerId in the array.
fn fetch_header_id_at(node: &str, h: u32) -> Result<String, String> {
    let body = http_get(node, &format!("/blocks/at/{h}"))?;
    let ids: Vec<String> =
        serde_json::from_str(&body).map_err(|e| format!("blocks/at/{h} parse: {e}"))?;
    ids.into_iter()
        .next()
        .ok_or_else(|| format!("no block ids at height {h}"))
}

/// `GET /blocks/{id}` → `ScalaFullBlock`.
fn fetch_full_block(node: &str, id: &str) -> Result<ScalaFullBlock, String> {
    let body = http_get(node, &format!("/blocks/{id}"))?;
    // The Scala node serves the `powSolutions.d` field as a bare big integer
    // for v1 headers (Autolykos v1). Without serde_json's `arbitrary_precision`
    // feature, large integers lose precision when parsed as f64. Pre-process
    // the raw JSON to quote unquoted numeric `d` values so they survive
    // round-trip as exact decimal strings — exactly the representation
    // `decode_scala_header` expects.
    let body = quote_pow_d_field(&body);
    serde_json::from_str(&body).map_err(|e| format!("blocks/{id} parse: {e}: body={body:.200}"))
}

/// Quote unquoted numeric `d` fields in `powSolutions` JSON.
///
/// The Scala node emits `"d" : <integer>` (note: space before `:`) for
/// v1 (Autolykos v1) headers. Rust's `decode_scala_header` expects the
/// value to be a decimal string. Without serde_json's `arbitrary_precision`
/// feature, very large integers lose precision when parsed as f64.
///
/// This function scans the raw JSON body and for every `"d"` key followed
/// by `:` and an unquoted number, wraps the number in double-quotes so
/// serde_json preserves the full decimal representation.
fn quote_pow_d_field(json: &str) -> String {
    let key = b"\"d\"";
    let bytes = json.as_bytes();
    let mut out = String::with_capacity(json.len() + 4);
    let mut pos = 0;

    while pos + key.len() <= bytes.len() {
        if &bytes[pos..pos + key.len()] != key {
            // JSON keys are ASCII, so we can safely push one byte at a time.
            out.push(char::from(bytes[pos]));
            pos += 1;
            continue;
        }

        // Found `"d"` — look ahead for optional whitespace then `:`
        let key_end = pos + key.len();
        let mut scan = key_end;
        while scan < bytes.len() && bytes[scan] == b' ' {
            scan += 1;
        }
        if scan >= bytes.len() || bytes[scan] != b':' {
            // Not a key:value pattern — emit as-is and continue
            out.push('"');
            out.push('d');
            out.push('"');
            pos = key_end;
            continue;
        }
        let colon_pos = scan;
        scan = colon_pos + 1; // past ':'

        // Skip whitespace after the colon
        while scan < bytes.len() && bytes[scan] == b' ' {
            scan += 1;
        }

        if scan >= bytes.len() || bytes[scan] == b'"' {
            // Already a quoted string — copy the key+colon verbatim
            out.push_str(&json[pos..scan]);
            pos = scan;
            continue;
        }

        // It looks like an unquoted value. Check if it's a number.
        let num_start = scan;
        if bytes[scan] == b'-' {
            scan += 1;
        }
        let digits_start = scan;
        while scan < bytes.len() && bytes[scan].is_ascii_digit() {
            scan += 1;
        }
        // Handle optional decimal/exponent part (unlikely for `d` but robust)
        if scan < bytes.len() && matches!(bytes[scan], b'.' | b'e' | b'E') {
            while scan < bytes.len()
                && matches!(bytes[scan], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                scan += 1;
            }
        }

        if scan > digits_start {
            // Emit `"d" : "<number>"` (preserving original whitespace around `:`)
            out.push_str(&json[pos..num_start]); // includes `"d"`, whitespace, colon, whitespace
            out.push('"');
            out.push_str(&json[num_start..scan]);
            out.push('"');
            pos = scan;
        } else {
            // Not a number after all — emit key and move on
            out.push_str(&json[pos..colon_pos + 1]);
            pos = colon_pos + 1;
        }
    }

    // Flush any remaining bytes
    if pos < bytes.len() {
        out.push_str(&json[pos..]);
    }

    out
}

// ── genesis box parsing ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GenesisBoxJson {
    #[serde(rename = "boxId")]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: HashMap<String, String>,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
    #[serde(default)]
    assets: Vec<AssetJson>,
}

#[derive(Deserialize)]
struct AssetJson {
    #[serde(rename = "tokenId")]
    token_id: String,
    amount: u64,
}

fn parse_genesis_box(json: &GenesisBoxJson) -> Result<(ModifierId, Vec<u8>), String> {
    let box_id_bytes: [u8; 32] = hex::decode(&json.box_id)
        .map_err(|e| format!("boxId hex: {e}"))?
        .try_into()
        .map_err(|_| "boxId wrong length".to_string())?;
    let box_id = ModifierId::from_bytes(box_id_bytes);

    let tree_bytes = hex::decode(&json.ergo_tree).map_err(|e| format!("ergoTree hex: {e}"))?;
    let mut r = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).map_err(|e| format!("ergoTree parse: {e:?}"))?;

    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    for (key, val_hex) in &json.additional_registers {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => return Err(format!("unknown register {key}")),
        };
        let val_bytes = hex::decode(val_hex).map_err(|e| format!("register {key} hex: {e}"))?;
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) =
            read_constant(&mut vr).map_err(|e| format!("register {key} parse: {e:?}"))?;
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
    }
    reg_vec.sort_by_key(|(idx, _)| *idx);

    let tokens: Vec<Token> = json
        .assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(&a.token_id)
                .map_err(|e| format!("tokenId hex: {e}"))
                .and_then(|b| b.try_into().map_err(|_| "tokenId wrong length".to_string()))?;
            Ok(Token {
                token_id: ergo_primitives::digest::Digest32::from_bytes(id),
                amount: a.amount,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let registers = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };
    let candidate = ErgoBoxCandidate::new(
        json.value,
        ergo_tree,
        json.creation_height,
        tokens,
        registers,
    )
    .map_err(|e| format!("genesis box candidate: {e}"))?;

    let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
        .map_err(|e| format!("transactionId hex: {e}"))?
        .try_into()
        .map_err(|_| "transactionId wrong length".to_string())?;
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: json.index,
    };
    let serialized = serialize_ergo_box(&ergo_box).map_err(|e| format!("serialize box: {e}"))?;
    Ok((box_id, serialized))
}

// ── output-box parsing (for genesis block 1 apply) ──────────────────────────
//
// Block 1 is the coinbase block. Its transaction's outputs are direct JSON
// objects in the `blockTransactions.transactions[*].outputs` array.
// We parse them as `ScalaOutput` (already decoded by serde from the
// ScalaFullBlock). The genesis apply path needs `&[Transaction]` — we decode
// those from the `block_transactions_bytes` that `decode_block_transactions_with_mode`
// produces.

// ── block decode helpers ─────────────────────────────────────────────────────

/// Decode a `ScalaFullBlock` into its wire-byte sections using
/// `DecodeMode::Preserve` (accepts soft-fork ergoTrees already on chain).
struct BlockSections {
    header_bytes: Vec<u8>,
    block_transactions_bytes: Vec<u8>,
    extension_bytes: Vec<u8>,
}

/// Work around a KNOWN, DEFERRED production decode bug so the replay driver can
/// reconstruct byte-exact header bytes (needed because `from_persisted_parts`
/// re-hashes them). `ergo-rest-json` decodes the Autolykos v1 pow `d` field as
/// SIGNED two's-complement, but Scala serializes it UNSIGNED
/// (`asUnsignedByteArray`, minimal magnitude, never a leading 0x00). So a `d`
/// that begins with 0x00 (len >= 2) is unambiguously the spurious sign byte the
/// buggy decode prepended for a magnitude whose top byte is >= 0x80 (mainnet
/// height 3 is the first such block). We strip it with precise byte-surgery on
/// the header's trailing `[d_len][d]` fields, leaving every other byte
/// byte-identical to Scala. Full writeup + fix recipe: gitignored dev-docs
/// Autolykos note; the production fix is a deferred, tightly-scoped PR.
fn correct_v1_pow_d(header_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let hdr = parse_header(header_bytes)?;
    if let AutolykosSolution::V1 { d, .. } = &hdr.solution {
        if d.len() >= 2 && d[0] == 0x00 {
            let l = d.len();
            // tail is the last `l + 1` bytes: [d_len = l][d (l bytes)].
            let cut = header_bytes.len() - l - 1;
            let mut fixed = header_bytes[..cut].to_vec();
            fixed.push((l - 1) as u8);
            fixed.extend_from_slice(&d[1..]);
            return Ok(fixed);
        }
    }
    Ok(header_bytes.to_vec())
}

fn decode_block(block: &ScalaFullBlock) -> Result<BlockSections, String> {
    // The recomputed modifier id is intentionally discarded: the replay driver
    // uses the archival node's authoritative id (see `checked_header_with_oracle_id`).
    let (raw_header_bytes, _hid_modifier) =
        decode_scala_header(&block.header).map_err(|(r, d)| format!("header decode ({r}): {d}"))?;
    let header_bytes = correct_v1_pow_d(&raw_header_bytes)?;

    let block_transactions_bytes =
        decode_block_transactions_with_mode(&block.block_transactions, DecodeMode::Preserve)
            .map_err(|(r, d)| format!("blockTransactions decode ({r}): {d}"))?;

    let extension_bytes = decode_extension(&block.extension)
        .map_err(|(r, d)| format!("extension decode ({r}): {d}"))?;

    Ok(BlockSections {
        header_bytes,
        block_transactions_bytes,
        extension_bytes,
    })
}

fn parse_header(bytes: &[u8]) -> Result<Header, String> {
    let mut r = VlqReader::new(bytes);
    read_header(&mut r).map_err(|e| format!("header parse: {e:?}"))
}

fn parse_block_transactions(bytes: &[u8]) -> Result<BlockTransactions, String> {
    let mut r = VlqReader::new(bytes);
    read_block_transactions(&mut r).map_err(|e| format!("blockTransactions parse: {e:?}"))
}

fn parse_extension(bytes: &[u8]) -> Result<Extension, String> {
    let mut r = VlqReader::new(bytes);
    read_extension(&mut r).map_err(|e| format!("extension parse: {e:?}"))
}

/// Build a `CheckedHeader` from canonical header bytes.
/// Uses `from_persisted_parts` with `pow_validity = 1` — the Scala node
/// is the oracle (it already validated and committed the block), so we
/// trust its PoW rather than re-verifying it in the difftest replay loop.
fn make_checked_header(bytes: &[u8], header_id: [u8; 32]) -> Result<CheckedHeader, String> {
    let hdr = parse_header(bytes)?;
    CheckedHeader::from_persisted_parts(
        bytes,
        header_id,
        /* meta_pow_validity */ 1, // trust the Scala oracle
        hdr.height,
        *hdr.parent_id.as_bytes(),
        hdr.timestamp,
    )
    .map_err(|e| format!("CheckedHeader: {e}"))
}

// ── divergence schema ────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct Divergence {
    surface: String,
    kind: &'static str,
    height: u32,
    rust: DivergenceDetail,
    jvm: DivergenceDetail,
    provenance: String,
    triage: &'static str,
}

#[derive(serde::Serialize)]
struct DivergenceDetail {
    verdict: &'static str,
    detail: String,
}

fn emit_divergence(div: &Divergence) {
    println!("{}", serde_json::to_string(div).unwrap());
}

// ── summary ──────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct Summary {
    from: u32,
    to: u32,
    blocks: u32,
    tx_total: usize,
    divergences: usize,
    pins_verified: usize,
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args = match Args::parse(std::env::args()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("usage: replay [--from <h>] --to <h> [--node <url>] [--pins <path>]");
            std::process::exit(1);
        }
    };

    if args.from != 1 {
        eprintln!(
            "error: --from {} is not supported; contiguous-from-genesis (--from 1) only.\n\
             The in-process apply pipeline needs the full UTXO history from height 1.",
            args.from
        );
        std::process::exit(1);
    }

    // Load pin file
    let pins = match load_pins(&args.pins_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error loading pins: {e}");
            std::process::exit(1);
        }
    };

    // Open a temporary StateStore (replay never persists to disk)
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let db_path = tmpdir.path().join("replay.redb");
    let mut store = StateStore::open(&db_path).expect("StateStore::open");

    // Seed genesis boxes
    if let Err(e) = seed_genesis(&mut store) {
        eprintln!("error seeding genesis: {e}");
        std::process::exit(1);
    }

    let mut divergences = 0usize;
    let mut pins_verified = 0usize;
    let mut blocks_applied = 0u32;
    let mut tx_total = 0usize;
    let mut had_fatal = false;

    // Block 1 (genesis block) — apply unchecked
    match apply_genesis_block(&args.node, &pins, &mut store, &mut pins_verified) {
        Ok(tx_count) => {
            blocks_applied += 1;
            tx_total += tx_count;
        }
        Err(e) => {
            eprintln!("fatal: genesis block (height 1) failed: {e}");
            print_summary(
                args.from,
                args.to,
                blocks_applied,
                tx_total,
                divergences,
                pins_verified,
            );
            std::process::exit(1);
        }
    }

    if args.to < 2 {
        print_summary(
            args.from,
            args.to,
            blocks_applied,
            tx_total,
            divergences,
            pins_verified,
        );
        std::process::exit(0);
    }

    // We need the genesis block's CheckedHeader to seed the parent context for height 2.
    // Fetch it again (cheap — same data we just fetched).
    let genesis_checked_header = match fetch_and_make_genesis_checked_header(&args.node) {
        Ok(ch) => ch,
        Err(e) => {
            eprintln!("fatal: cannot build genesis CheckedHeader for chain context: {e}");
            print_summary(
                args.from,
                args.to,
                blocks_applied,
                tx_total,
                divergences,
                pins_verified,
            );
            std::process::exit(1);
        }
    };

    // We need the genesis block's extension to seed interlink validation.
    // For simplicity we pass `parent_extension: None` (matches Scala's
    // `exIlUnableToValidate` path when no parent extension is available).
    // This is safe because the first 200 blocks predate meaningful interlink
    // enforcement; the extension-root merkle check still runs.
    let params = ProtocolParams::mainnet_default();

    // Sliding window of last ~10 checked headers for CONTEXT.headers in script eval.
    // Fixed-size ring; prepend newest so index 0 = most recent.
    let mut last_headers: Vec<CheckedHeader> = Vec::with_capacity(11);
    last_headers.push(genesis_checked_header.clone());

    let mut parent = genesis_checked_header;

    for h in 2..=args.to {
        match apply_one_block(
            h,
            &args.node,
            &pins,
            &params,
            &parent,
            &last_headers,
            &mut store,
            &mut pins_verified,
            &mut divergences,
        ) {
            Ok(BlockResult {
                checked_header,
                tx_count,
            }) => {
                blocks_applied += 1;
                tx_total += tx_count;
                // Slide the last-headers window (keep at most 10)
                last_headers.insert(0, checked_header.clone());
                if last_headers.len() > 10 {
                    last_headers.pop();
                }
                parent = checked_header;
            }
            Err(e) => {
                eprintln!("fatal at height {h}: {e}");
                had_fatal = true;
                break;
            }
        }
    }

    print_summary(
        args.from,
        args.to,
        blocks_applied,
        tx_total,
        divergences,
        pins_verified,
    );

    if divergences > 0 || had_fatal {
        std::process::exit(1);
    }
}

// ── genesis seeding ──────────────────────────────────────────────────────────

fn seed_genesis(store: &mut StateStore) -> Result<(), String> {
    let genesis_boxes: Vec<GenesisBoxJson> = serde_json::from_str(GENESIS_BOXES_JSON)
        .map_err(|e| format!("genesis_boxes.json parse: {e}"))?;

    let mut boxes: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(genesis_boxes.len());
    for json_box in &genesis_boxes {
        let (modifier_id, serialized) = parse_genesis_box(json_box)?;
        boxes.push((*modifier_id.as_bytes(), serialized));
    }
    store
        .initialize_genesis(&boxes)
        .map_err(|e| format!("initialize_genesis: {e}"))?;
    Ok(())
}

// ── genesis block (height 1) apply ────────────────────────────────────────────

fn apply_genesis_block(
    node: &str,
    pins: &HashMap<u32, PinEntry>,
    store: &mut StateStore,
    pins_verified: &mut usize,
) -> Result<usize, String> {
    let header_id_hex = fetch_header_id_at(node, 1)?;

    // Pin check for height 1
    if let Some(pin) = pins.get(&1) {
        if !header_id_hex.eq_ignore_ascii_case(&pin.header_id) {
            return Err(format!(
                "PIN MISMATCH at height 1: node returned {header_id_hex}, pin expects {}",
                pin.header_id
            ));
        }
        *pins_verified += 1;
    }

    let block = fetch_full_block(node, &header_id_hex)?;
    let sections = decode_block(&block)?;

    // Parse the header to extract the stateRoot
    let header = parse_header(&sections.header_bytes)?;
    let state_root = header.state_root;
    // Use the archival node's authoritative id (see `checked_header_with_oracle_id`
    // for the deferred Autolykos-`d` decode note).
    let header_id = hex32(&header_id_hex)?;

    // Parse block transactions to get the raw transactions
    let bt = parse_block_transactions(&sections.block_transactions_bytes)?;
    let tx_count = bt.transactions.len();

    // Pre-store HEADER_META for height 1 so persist_apply's chain-index
    // walk can find the row. Production sync stores this via header_proc
    // before apply; here the replay driver must do it manually.
    let meta = HeaderMeta {
        parent_id: *header.parent_id.as_bytes(),
        height: 1,
        cumulative_score: vec![0u8], // placeholder; replay doesn't need difficulty
        pow_validity: 1,
        timestamp: header.timestamp,
    };
    store
        .store_header_meta(&header_id, &meta)
        .map_err(|e| format!("store_header_meta h=1: {e}"))?;

    // Apply genesis block unchecked (height 1, no prior state to validate against)
    store
        .apply_genesis(&header_id, &state_root, &bt.transactions)
        .map_err(|e| match e {
            StateError::DigestMismatch { computed, expected } => format!(
                "height 1 state root mismatch: Rust computed {computed}, Scala expected {expected}"
            ),
            other => format!("height 1 apply_genesis: {other}"),
        })?;

    Ok(tx_count)
}

/// Parse a 32-byte hex modifier id (header id) into bytes.
fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| format!("header id hex: {e}"))?
        .try_into()
        .map_err(|_| format!("header id not 32 bytes: {s}"))
}

/// The archival Scala node is the oracle for the header id, so use the id it
/// serves (`/blocks/at/{h}`) rather than the one `decode_scala_header`
/// recomputes from the JSON round-trip. This sidesteps a KNOWN, DEFERRED
/// production decode bug: `ergo-rest-json` decodes the Autolykos v1 pow `d`
/// field as SIGNED two's-complement, but Scala serializes it UNSIGNED
/// (`asUnsignedByteArray`). For early v1 headers whose `d` high byte is >= 0x80
/// (height 3 is the first on mainnet) the signed decode prepends a spurious
/// 0x00, producing a wrong header id — which then fails the BlockTransactions
/// section-id match. `d` is the header's trailing PoW field (unused here: PoW is
/// trusted, meta_pow_validity = 1), so the correct id + the intact stateRoot /
/// height / parentId prefix are all we need for state-root replay. Full
/// writeup + fix recipe live in the (gitignored) dev-docs Autolykos note; the
/// production fix is deferred to a tightly-scoped PR.
fn checked_header_with_oracle_id(
    sections: &BlockSections,
    oracle_id_hex: &str,
) -> Result<CheckedHeader, String> {
    make_checked_header(&sections.header_bytes, hex32(oracle_id_hex)?)
}

fn fetch_and_make_genesis_checked_header(node: &str) -> Result<CheckedHeader, String> {
    let header_id_hex = fetch_header_id_at(node, 1)?;
    let block = fetch_full_block(node, &header_id_hex)?;
    let sections = decode_block(&block)?;
    checked_header_with_oracle_id(&sections, &header_id_hex)
}

// ── per-block apply (height 2+) ───────────────────────────────────────────────

struct BlockResult {
    checked_header: CheckedHeader,
    tx_count: usize,
}

#[allow(clippy::too_many_arguments)]
fn apply_one_block(
    h: u32,
    node: &str,
    pins: &HashMap<u32, PinEntry>,
    params: &ProtocolParams,
    parent: &CheckedHeader,
    last_headers: &[CheckedHeader],
    store: &mut StateStore,
    pins_verified: &mut usize,
    divergences: &mut usize,
) -> Result<BlockResult, String> {
    // 1. Fetch header id at this height
    let header_id_hex = fetch_header_id_at(node, h)?;

    // 2. Pin check
    if let Some(pin) = pins.get(&h) {
        if !header_id_hex.eq_ignore_ascii_case(&pin.header_id) {
            // Hard error: reorg or wrong node. Stop the run.
            return Err(format!(
                "PIN MISMATCH at height {h}: node returned {header_id_hex}, pin expects {}",
                pin.header_id
            ));
        }
        *pins_verified += 1;
    }

    // 3. Fetch and decode full block
    let block = fetch_full_block(node, &header_id_hex)?;
    let sections = decode_block(&block)?;

    // 4. Parse header bytes → CheckedHeader (trust the Scala oracle's PoW + id;
    //    see `checked_header_with_oracle_id` for the deferred Autolykos-`d` note).
    let checked_header = checked_header_with_oracle_id(&sections, &header_id_hex)?;

    // 5. Parse block transactions + extension
    let bt = parse_block_transactions(&sections.block_transactions_bytes)?;
    let ext = parse_extension(&sections.extension_bytes)?;
    let tx_count = bt.transactions.len();

    // 6. Build block validation context.
    //    Mainnet voting length = 1024. Rule 215 (hdrVotesUnknown) was disabled
    //    by the v6.0 soft-fork activation (mainnet parameter softFork 2024).
    //    For heights 1-200 the rule is active but never fires (epoch boundary
    //    is height 1024), so `votes_unknown_rule_disabled: false` is correct.
    //    `soft_fork_state: None` — no soft-fork in progress at these heights.
    //    `parent_extension: None` — skips interlink validation (Scala's
    //    `exIlUnableToValidate` recovery path when no parent extension cached).
    //    `reemission: None` — EIP-27 launched much later than height 200.
    //    `script_validation_checkpoint: None` — forced full script validation.
    let ctx = BlockValidationContext {
        parent,
        utxo: store,
        params,
        voting_length: 1024,
        votes_unknown_rule_disabled: false,
        parent_extension: None,
        soft_fork_state: None,
        last_headers,
        script_validation_checkpoint: None,
        reemission: None,
    };

    // 7. Validate the full block (parallel path, same as production)
    let checked_block = match validate_full_block_parallel(checked_header.clone(), &bt, &ext, &ctx)
    {
        Ok(cb) => cb,
        Err(e) => {
            // A tx in a committed block is valid by definition.
            // A Rust reject is a TxValidity divergence.
            let div = Divergence {
                surface: format!("block:{h}"),
                kind: "TxValidity",
                height: h,
                rust: DivergenceDetail {
                    verdict: "Reject",
                    detail: format!("{e}"),
                },
                jvm: DivergenceDetail {
                    verdict: "Accept",
                    detail: "Scala node committed this block".to_string(),
                },
                provenance: format!("replay:h{h}"),
                triage: "PENDING",
            };
            emit_divergence(&div);
            *divergences += 1;
            // Cannot continue: block was not applied, state is at h-1.
            return Err(format!(
                "block {h} validation failed (divergence recorded): {e}"
            ));
        }
    };

    // 8. Pre-store HEADER_META so persist_apply's chain-index walk can find
    //    the row. Production sync stores this via header_proc before apply;
    //    the replay driver must do it manually (same as for height 1).
    let hdr = checked_header.header();
    let meta = HeaderMeta {
        parent_id: *hdr.parent_id.as_bytes(),
        height: h,
        cumulative_score: vec![0u8], // placeholder; replay doesn't need difficulty
        pow_validity: 1,
        timestamp: hdr.timestamp,
    };
    store
        .store_header_meta(checked_header.header_id(), &meta)
        .map_err(|e| format!("store_header_meta h={h}: {e}"))?;

    // 9. Apply block to state
    match store.apply_block(&checked_block, None, None) {
        Ok(()) => {
            // 9. Diff: Rust root_digest() was just asserted inside apply_block
            //    (it returns StateError::DigestMismatch if wrong). If we got
            //    here, the root matched. Also check the pin's stateRoot if present.
            if let Some(pin) = pins.get(&h) {
                let rust_root = hex::encode(store.root_digest().as_bytes());
                if !rust_root.eq_ignore_ascii_case(&pin.state_root) {
                    let div = Divergence {
                        surface: format!("block:{h}"),
                        kind: "RootMismatch",
                        height: h,
                        rust: DivergenceDetail {
                            verdict: "Accept",
                            detail: format!("root={rust_root}"),
                        },
                        jvm: DivergenceDetail {
                            verdict: "Accept",
                            detail: format!("pinned root={}", pin.state_root),
                        },
                        provenance: format!("replay:h{h}"),
                        triage: "PENDING",
                    };
                    emit_divergence(&div);
                    *divergences += 1;
                    // Root vs pin mismatch: the block was applied (AVL root matched
                    // the Scala header's stateRoot), but the pin disagrees with what
                    // we computed. This is a data integrity issue, not a chain split,
                    // so we continue.
                }
            }
        }
        Err(StateError::DigestMismatch { computed, expected }) => {
            // Rust AVL root != header's stateRoot: real RootMismatch divergence.
            let div = Divergence {
                surface: format!("block:{h}"),
                kind: "RootMismatch",
                height: h,
                rust: DivergenceDetail {
                    verdict: "Reject",
                    detail: format!("computed root={computed}"),
                },
                jvm: DivergenceDetail {
                    verdict: "Accept",
                    detail: format!("stateRoot={expected}"),
                },
                provenance: format!("replay:h{h}"),
                triage: "PENDING",
            };
            emit_divergence(&div);
            *divergences += 1;
            // Cannot continue: block was not applied, state is corrupt from this
            // height onward.
            return Err(format!(
                "height {h} state root mismatch (divergence recorded): computed={computed} expected={expected}"
            ));
        }
        Err(e) => {
            return Err(format!("height {h} apply_block: {e}"));
        }
    }

    Ok(BlockResult {
        checked_header,
        tx_count,
    })
}

// ── summary helpers ───────────────────────────────────────────────────────────

fn print_summary(
    from: u32,
    to: u32,
    blocks: u32,
    tx_total: usize,
    divergences: usize,
    pins_verified: usize,
) {
    let summary = Summary {
        from,
        to,
        blocks,
        tx_total,
        divergences,
        pins_verified,
    };
    println!("{}", serde_json::to_string(&summary).unwrap());
}
