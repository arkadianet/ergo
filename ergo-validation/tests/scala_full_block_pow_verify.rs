//! §12 step (c) — proves the JSON → decode → header-bytes →
//! `verify_pow_solution` pipeline lands on Ok for real mainnet
//! blocks and rejects mutated solutions.
//!
//! This is the integration anchor for the `POST /blocks` admission
//! path: any future regression in
//! `ergo_rest_json::decode_scala_full_block` /
//! `decode_scala_header` that breaks the header-bytes round-trip
//! (e.g. the v1 `d` signed-BigInt invariant we pinned in §12(a))
//! would land here as a PoW rejection, *before* it could reach the
//! bridge's submit path in step (e).
//!
//! Coverage:
//! - v2 PoW: real mainnet full-block `block_836113.json`
//!   (height 836_113, well past the v1→v2 transition at 417_792).
//! - v1 PoW: real mainnet h=1 header, round-tripped through
//!   `decode_scala_header` (inline `header_to_scala` mirrors the
//!   production encoder shape in `ergo-node::api_bridge::compat`).
//! - Negative: mutating the parsed header's PoW nonce flips
//!   `verify_pow_solution` to `Err`.

use ergo_crypto::pow::verify_pow_solution;
use ergo_primitives::reader::VlqReader;
use ergo_rest_json::types::{ScalaFullBlock, ScalaHeader, ScalaPowSolutions};
use ergo_rest_json::{decode_scala_full_block, decode_scala_header};
use ergo_ser::header::read_header;
use serde::Deserialize;
use serde_json::Value as JsonValue;

#[derive(Deserialize)]
struct HeaderVec {
    id: String,
    bytes: String,
}

fn fixture(rel: &str) -> String {
    format!(
        "{}/../test-vectors/mainnet/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    )
}

/// Production-shape encoder for a parsed internal v1 `Header`,
/// mirroring the v1 branch of
/// `ergo-node::api_bridge::compat::header_to_scala_header_dto` (the
/// inverse of `decode_scala_header`). Inlined here so this integration
/// test depends only on `ergo-ser` + `ergo-rest-json` + `ergo-crypto`.
///
/// **v1-only.** v2 path is exercised by the real
/// `block_836113.json` fixture below; there is no v2 branch here
/// because the production v2 encoder substitutes the secp256k1
/// generator constant for `w` (see `SECP256K1_GENERATOR_HEX` in
/// `ergo-node::api_bridge::compat`) and we don't want a drift-prone
/// duplicate of that constant in this test file.
fn v1_header_to_scala(h: &ergo_ser::header::Header, id: &str) -> ScalaHeader {
    let pow_solutions = match &h.solution {
        ergo_ser::autolykos::AutolykosSolution::V1 { pk, w, nonce, d } => ScalaPowSolutions {
            pk: hex::encode(pk.as_bytes()),
            w: hex::encode(w.as_bytes()),
            n: hex::encode(nonce),
            d: JsonValue::String(num_bigint::BigInt::from_signed_bytes_be(d).to_string()),
        },
        ergo_ser::autolykos::AutolykosSolution::V2 { .. } => {
            panic!("v1_header_to_scala called on v2 header — use block_836113.json fixture")
        }
    };
    ScalaHeader {
        extension_id: String::new(),
        difficulty: "0".to_string(),
        votes: hex::encode(h.votes),
        timestamp: h.timestamp,
        size: 0,
        unparsed_bytes: hex::encode(&h.unparsed_bytes),
        state_root: hex::encode(h.state_root.as_bytes()),
        height: h.height,
        n_bits: h.n_bits as u64,
        version: h.version,
        id: id.to_string(),
        ad_proofs_root: hex::encode(h.ad_proofs_root.as_bytes()),
        transactions_root: hex::encode(h.transactions_root.as_bytes()),
        extension_hash: hex::encode(h.extension_root.as_bytes()),
        pow_solutions,
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: hex::encode(h.parent_id.as_bytes()),
    }
}

// ----- happy path -----

#[test]
fn verify_pow_passes_on_decoded_v2_mainnet_full_block_836113() {
    let raw = std::fs::read_to_string(fixture("block_836113.json")).unwrap();
    let scala: ScalaFullBlock = serde_json::from_str(&raw).unwrap();

    let decoded = decode_scala_full_block(&scala).expect("decode_scala_full_block must succeed");
    let mut r = VlqReader::new(&decoded.header_bytes);
    let header = read_header(&mut r).expect("re-parse decoded header bytes");

    // Decoded header id must match the JSON-claimed id (pin the
    // round-trip identity of decode_scala_header at the full-block
    // composition layer).
    assert_eq!(
        hex::encode(decoded.header_id.as_bytes()),
        scala.header.id.to_lowercase(),
        "decoded header_id must equal JSON header.id",
    );

    verify_pow_solution(&header).expect("v2 PoW must verify on a real mainnet block");
}

#[test]
fn verify_pow_passes_on_decoded_v1_mainnet_header_h1() {
    let headers: Vec<HeaderVec> =
        serde_json::from_str(&std::fs::read_to_string(fixture("headers_1_10.json")).unwrap())
            .unwrap();
    let hv = &headers[0];
    let raw = hex::decode(&hv.bytes).unwrap();
    let mut r0 = VlqReader::new(&raw);
    let parsed = read_header(&mut r0).unwrap();
    assert_eq!(parsed.version, 1, "h=1 must be v1");

    // Build the ScalaHeader DTO, serialize to JSON text, then
    // round-trip through serde back to ScalaHeader. This exercises
    // the same serde-from-text hop that the future bridge handler
    // in step (e) will take when reading the request body, so any
    // serde-level regression (rename collision, missing field
    // attribute, type mismatch) lands here.
    let scala_in = v1_header_to_scala(&parsed, &hv.id);
    let json_text = serde_json::to_string(&scala_in).expect("ScalaHeader must serialize");
    let scala: ScalaHeader = serde_json::from_str(&json_text)
        .expect("ScalaHeader must round-trip through serde JSON text");

    let (header_bytes, header_id) =
        decode_scala_header(&scala).expect("decode_scala_header must succeed for v1");
    assert_eq!(header_bytes, raw, "decoded bytes differ from original");
    assert_eq!(hex::encode(header_id.as_bytes()), hv.id);

    let mut r1 = VlqReader::new(&header_bytes);
    let header = read_header(&mut r1).unwrap();
    verify_pow_solution(&header).expect("v1 PoW must verify on h=1 mainnet header");
}

// ----- error paths -----

#[test]
fn verify_pow_rejects_mutated_v2_nonce() {
    let raw = std::fs::read_to_string(fixture("block_836113.json")).unwrap();
    let scala: ScalaFullBlock = serde_json::from_str(&raw).unwrap();
    let decoded = decode_scala_full_block(&scala).unwrap();
    let mut r = VlqReader::new(&decoded.header_bytes);
    let mut header = read_header(&mut r).unwrap();

    // Flip the high bit of nonce[0]. The PoW message hash is over
    // header bytes *without* the nonce — but the Autolykos v2
    // equation feeds the nonce into the per-element seeds. Any
    // single-byte mutation collapses verification.
    match &mut header.solution {
        ergo_ser::autolykos::AutolykosSolution::V2 { nonce, .. } => {
            nonce[0] ^= 0x80;
        }
        ergo_ser::autolykos::AutolykosSolution::V1 { .. } => panic!("expected v2 at 836113"),
    }

    let err = verify_pow_solution(&header).expect_err("mutated nonce must NOT verify");
    let msg = format!("{err}");
    assert!(
        msg.contains("v2 PoW") || msg.contains("invalid"),
        "unexpected PoW error shape: {msg}",
    );
}
