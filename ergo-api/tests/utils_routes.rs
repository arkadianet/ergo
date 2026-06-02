//! `/utils/*` — Scala-compat stateless helper endpoints.
//!
//! These are the routes that gave the openapi.yaml its "utils tag" of
//! 9 path entries; they're parity-shaped to Scala's
//! `ErgoUtilsApiRoute` but have no node-state coupling, so the test
//! suite here exercises the routes against a minimal
//! `Router<NetworkPrefix>` rather than booting a full `ServerCtx`.
//!
//! Coverage:
//! - `seed` (32-byte default + bounded `length` param + edge cases)
//! - `hash/blake2b` (round-trip vs canonical fixture)
//! - `rawToAddress` / `addressToRaw` round-trip (P2PK pubkey↔address)
//! - `address` validity check (GET path + POST body, success and error envelope)
//! - `ergoTreeToAddress` round-trip (P2PK tree bytes → P2PK address)

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use ergo_api::utils;
use ergo_ser::address::NetworkPrefix;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

fn build_utils_router(network: NetworkPrefix) -> Router {
    Router::<NetworkPrefix>::new()
        .route("/utils/seed", get(utils::seed_default_handler))
        .route("/utils/seed/:length", get(utils::seed_length_handler))
        .route("/utils/hash/blake2b", post(utils::hash_blake2b_handler))
        .route(
            "/utils/rawToAddress/:pubkey_hex",
            get(utils::raw_to_address_handler),
        )
        .route(
            "/utils/addressToRaw/:address",
            get(utils::address_to_raw_handler),
        )
        .route(
            "/utils/address/:address",
            get(utils::validate_address_get_handler),
        )
        .route("/utils/address", post(utils::validate_address_post_handler))
        .route(
            "/utils/ergoTreeToAddress/:tree_hex",
            get(utils::ergo_tree_to_address_get_handler),
        )
        .route(
            "/utils/ergoTreeToAddress",
            post(utils::ergo_tree_to_address_post_handler),
        )
        .with_state(network)
}

async fn request_get(app: Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json)
}

async fn request_post(app: Router, path: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json)
}

// ----- /utils/seed -----

#[tokio::test]
async fn seed_default_returns_32_byte_hex() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, "/utils/seed").await;
    assert_eq!(status, StatusCode::OK);
    let hex = body.as_str().expect("seed body is a JSON string");
    assert_eq!(hex.len(), 64, "32-byte seed = 64 hex chars");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn seed_length_returns_specified_byte_count() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, "/utils/seed/16").await;
    assert_eq!(status, StatusCode::OK);
    let hex = body.as_str().unwrap();
    assert_eq!(hex.len(), 32, "16-byte seed = 32 hex chars");
}

#[tokio::test]
async fn seed_zero_length_is_400() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, "/utils/seed/0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
}

#[tokio::test]
async fn seed_oversize_length_is_400() {
    // Scala accepts any positive int; we cap at 8 KiB to bound CSPRNG
    // work and response size per request.
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, "/utils/seed/100000").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"].as_str().unwrap().contains("8192"),
        "error must name the cap, got: {body:?}",
    );
}

#[tokio::test]
async fn seed_two_calls_return_distinct_hex() {
    // The cap is statistical, not absolute — two 32-byte CSPRNG outputs
    // collide with probability 2^-256. If they ever match the test
    // suite has bigger problems than this assertion.
    let app1 = build_utils_router(NetworkPrefix::Mainnet);
    let app2 = build_utils_router(NetworkPrefix::Mainnet);
    let (_, b1) = request_get(app1, "/utils/seed").await;
    let (_, b2) = request_get(app2, "/utils/seed").await;
    assert_ne!(
        b1.as_str().unwrap(),
        b2.as_str().unwrap(),
        "successive seeds must differ",
    );
}

// ----- POST /utils/hash/blake2b -----

#[tokio::test]
async fn hash_blake2b_returns_canonical_digest() {
    // blake2b256("hello world") is a well-known hex digest. Scala's
    // route hashes the UTF-8 bytes of the JSON string body; pinned
    // here so a future input-type change (e.g. accepting hex instead)
    // gets caught.
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) =
        request_post(app, "/utils/hash/blake2b", &Value::from("hello world")).await;
    assert_eq!(status, StatusCode::OK);
    let hex_digest = body.as_str().unwrap();
    // Independently computed: blake2b256(b"hello world")
    let expected = {
        let d = ergo_primitives::digest::blake2b256(b"hello world");
        hex::encode(d.as_bytes())
    };
    assert_eq!(hex_digest, expected);
    assert_eq!(hex_digest.len(), 64);
}

#[tokio::test]
async fn hash_blake2b_empty_string_returns_canonical_digest() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_post(app, "/utils/hash/blake2b", &Value::from("")).await;
    assert_eq!(status, StatusCode::OK);
    let expected = {
        let d = ergo_primitives::digest::blake2b256(b"");
        hex::encode(d.as_bytes())
    };
    assert_eq!(body.as_str().unwrap(), expected);
}

// ----- rawToAddress / addressToRaw round-trip -----

#[tokio::test]
async fn raw_to_address_p2pk_round_trips_via_address_to_raw() {
    // Stable canonical pubkey (33 bytes, all 0x02). The compressed
    // form is what Scala emits on chain; the encoder doesn't validate
    // it as a real secp256k1 point and neither do we — so this is
    // safe as a fixture for the encoding contract.
    let pubkey = [0x02u8; 33];
    let pubkey_hex = hex::encode(pubkey);
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/rawToAddress/{pubkey_hex}")).await;
    assert_eq!(status, StatusCode::OK);
    let address = body["address"].as_str().unwrap().to_string();
    assert!(!address.is_empty(), "address must be a base58 string");

    // Round-trip: addressToRaw on the encoded address yields the same
    // pubkey hex.
    let app2 = build_utils_router(NetworkPrefix::Mainnet);
    let (status2, body2) = request_get(app2, &format!("/utils/addressToRaw/{address}")).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body2["raw"].as_str().unwrap(), pubkey_hex);
}

#[tokio::test]
async fn raw_to_address_rejects_short_pubkey() {
    let pubkey_hex = hex::encode([0x02u8; 32]); // 32 bytes, one short
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/rawToAddress/{pubkey_hex}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
}

#[tokio::test]
async fn raw_to_address_rejects_invalid_hex() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, _) = request_get(app, "/utils/rawToAddress/not_hex_at_all").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn address_to_raw_rejects_bad_checksum() {
    // A P2PK string with a flipped final-character. Decode catches the
    // checksum mismatch (`AddressDecodeError::BadChecksum`) and the
    // handler surfaces 400.
    //
    // We don't manually craft the malformed string — instead we take a
    // valid one, mangle the last char, and feed it back through.
    let pubkey = [0x03u8; 33];
    let valid =
        ergo_ser::address::encode_p2pk_from_pubkey(NetworkPrefix::Mainnet, &pubkey).unwrap();
    let mut mangled = valid.clone();
    let last = mangled.pop().unwrap();
    let replacement = if last == 'A' { 'B' } else { 'A' };
    mangled.push(replacement);

    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/addressToRaw/{mangled}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
}

// ----- /utils/address validity probe -----

#[tokio::test]
async fn validate_address_get_reports_isvalid_true_for_round_tripped_address() {
    let pubkey = [0x02u8; 33];
    let address =
        ergo_ser::address::encode_p2pk_from_pubkey(NetworkPrefix::Mainnet, &pubkey).unwrap();
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/address/{address}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["address"].as_str().unwrap(), address);
    assert_eq!(body["isValid"], true);
    assert!(body.get("error").is_none());
}

#[tokio::test]
async fn validate_address_post_reports_isvalid_false_for_garbage() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_post(
        app,
        "/utils/address",
        &Value::from("totally not an address"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "POST validity is a 200 either way");
    assert_eq!(body["isValid"], false);
    assert!(body["error"].as_str().is_some(), "error must be populated");
}

#[tokio::test]
async fn validate_address_rejects_wrong_network() {
    // Encode a P2PK on testnet, then validate on a mainnet-configured
    // server. The network-mismatch path must surface as isValid=false.
    let pubkey = [0x04u8; 33];
    let testnet_addr =
        ergo_ser::address::encode_p2pk_from_pubkey(NetworkPrefix::Testnet, &pubkey).unwrap();
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/address/{testnet_addr}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["isValid"], false);
    let err = body["error"].as_str().unwrap();
    assert!(
        err.contains("network mismatch"),
        "error must name the network-mismatch path: {err}",
    );
}

// ----- /utils/ergoTreeToAddress -----

#[tokio::test]
async fn ergo_tree_to_address_p2pk_round_trips() {
    // Canonical P2PK tree bytes: `[0x00, 0x08, 0xCD, <pubkey_33B>]`.
    let pubkey = [0x05u8; 33];
    let mut tree_bytes = vec![0x00u8, 0x08, 0xCD];
    tree_bytes.extend_from_slice(&pubkey);
    let tree_hex = hex::encode(&tree_bytes);

    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/ergoTreeToAddress/{tree_hex}")).await;
    assert_eq!(status, StatusCode::OK);
    let address = body["address"].as_str().unwrap().to_string();

    // Round-trip via addressToRaw: for a P2PK address the content
    // bytes are the bare 33-byte pubkey.
    let app2 = build_utils_router(NetworkPrefix::Mainnet);
    let (_, body2) = request_get(app2, &format!("/utils/addressToRaw/{address}")).await;
    assert_eq!(body2["raw"].as_str().unwrap(), hex::encode(pubkey));
}

#[tokio::test]
async fn ergo_tree_to_address_post_accepts_json_string_body() {
    let pubkey = [0x06u8; 33];
    let mut tree_bytes = vec![0x00u8, 0x08, 0xCD];
    tree_bytes.extend_from_slice(&pubkey);
    let tree_hex = hex::encode(&tree_bytes);

    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) =
        request_post(app, "/utils/ergoTreeToAddress", &Value::from(tree_hex)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["address"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn ergo_tree_to_address_rejects_invalid_hex() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, _) = request_get(app, "/utils/ergoTreeToAddress/zz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ergo_tree_to_address_rejects_malformed_tree_bytes() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, "/utils/ergoTreeToAddress/00").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("ergo_tree parse failed"),
        "error must name the parse path: {body:?}",
    );
}

// ----- P2SH address support -----

/// Synthesize a P2SH address from a raw 24-byte script hash. We don't
/// have a public P2SH encoder in `ergo-ser` (the indexer rejects P2SH
/// addresses by design, so the encoder side was never needed) — for
/// this test we build the wire form directly: `header || hash || checksum`.
fn synthesize_p2sh_address(network: NetworkPrefix, script_hash: &[u8; 24]) -> String {
    let header = match network {
        NetworkPrefix::Mainnet => 0x02_u8, // TYPE_P2SH | mainnet nibble (0x00)
        NetworkPrefix::Testnet => 0x12,    // TYPE_P2SH | testnet nibble (0x10)
    };
    let mut buf = Vec::with_capacity(1 + 24 + 4);
    buf.push(header);
    buf.extend_from_slice(script_hash);
    // 4-byte truncated blake2b256 of header+content
    let digest = ergo_primitives::digest::blake2b256(&buf);
    buf.extend_from_slice(&digest.as_bytes()[..4]);
    bs58::encode(&buf).into_string()
}

#[tokio::test]
async fn address_to_raw_supports_p2sh() {
    // `decode_address_content_bytes` must accept P2SH addresses for
    // Scala-route parity on `addressToRaw` and `address` validity
    // checks. A synthetic P2SH address must round-trip via
    // `addressToRaw`, yielding the 24-byte script hash back.
    let script_hash = [0xAA_u8; 24];
    let p2sh_addr = synthesize_p2sh_address(NetworkPrefix::Mainnet, &script_hash);
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/addressToRaw/{p2sh_addr}")).await;
    assert_eq!(status, StatusCode::OK, "P2SH must not 400: {body:?}");
    assert_eq!(body["raw"].as_str().unwrap(), hex::encode(script_hash));
}

#[tokio::test]
async fn validate_address_accepts_p2sh_as_valid() {
    let script_hash = [0xBB_u8; 24];
    let p2sh_addr = synthesize_p2sh_address(NetworkPrefix::Mainnet, &script_hash);
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_get(app, &format!("/utils/address/{p2sh_addr}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["isValid"], true,
        "P2SH address must validate: {body:?}"
    );
}

// ----- POST body error-envelope shape -----
//
// axum's default `Json<String>` extractor returns a plain-text body
// on parse failure, drifting from this API's structured error envelope.
// We use raw `Bytes` + a manual JSON-string parse to emit the standard
// `{error, reason, detail}` shape for malformed POSTs.

#[tokio::test]
async fn hash_blake2b_malformed_body_returns_structured_400() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let req = Request::builder()
        .method("POST")
        .uri("/utils/hash/blake2b")
        .header("content-type", "application/json")
        .body(Body::from("this is not json"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("structured body");
    assert_eq!(json["reason"], "bad-request");
    assert!(json["detail"].as_str().unwrap().contains("invalid JSON"));
}

#[tokio::test]
async fn hash_blake2b_non_string_json_returns_structured_400() {
    // JSON object body — parses as JSON, but isn't a string. The
    // helper rejects with "body must be a JSON string".
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let (status, body) = request_post(app, "/utils/hash/blake2b", &Value::from(42)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert!(body["detail"].as_str().unwrap().contains("JSON string"));
}

#[tokio::test]
async fn validate_address_post_malformed_body_returns_structured_400() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let req = Request::builder()
        .method("POST")
        .uri("/utils/address")
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["reason"], "bad-request");
}

#[tokio::test]
async fn ergo_tree_to_address_post_malformed_body_returns_structured_400() {
    let app = build_utils_router(NetworkPrefix::Mainnet);
    let req = Request::builder()
        .method("POST")
        .uri("/utils/ergoTreeToAddress")
        .header("content-type", "application/json")
        .body(Body::from("not-json-at-all"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["reason"], "bad-request");
}
