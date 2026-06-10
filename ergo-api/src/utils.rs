//! `/utils/*` (Scala `ErgoUtilsApiRoute`) + the two decode-only members of
//! `/script/*` (Scala `ScriptApiRoute`) — Scala-compat stateless helper
//! endpoints.
//!
//! All routes here are pure functions of input — no node state, no DB reads,
//! no chain query trait dependency. `NetworkPrefix` is the only piece of
//! operator config the address routes need.
//!
//! Routes (response shapes match Scala JsonCodecs exactly):
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | `GET`  | `/utils/seed` | `"<hex>"` (32-byte random) |
//! | `GET`  | `/utils/seed/{length}` | `"<hex>"` of `length` bytes |
//! | `POST` | `/utils/hash/blake2b` | `"<hex>"` of `blake2b256(utf8(body))` |
//! | `GET`  | `/utils/rawToAddress/{pubKeyHex}` | `{"address": "..."}` |
//! | `GET`  | `/utils/addressToRaw/{address}` | `{"raw": "<hex>"}` |
//! | `GET`  | `/utils/address/{address}` | `{"address": "...", "isValid": bool, "error"?: "..."}` |
//! | `POST` | `/utils/address` | (same as GET) |
//! | `GET`  | `/utils/ergoTreeToAddress/{hex}` | `{"address": "..."}` |
//! | `POST` | `/utils/ergoTreeToAddress` | (same as GET) |
//! | `GET`  | `/script/addressToTree/{address}` | `{"tree": "<ergoTree hex>"}` |
//! | `GET`  | `/script/addressToBytes/{address}` | `{"bytes": "<Coll[Byte] const hex>"}` |
//!
//! `/script/*`'s compile-requiring members (`p2sAddress`, `p2shAddress`,
//! `executeWithContext`) are not implemented — they compile ErgoScript source,
//! and this node ships no compiler.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ergo_primitives::digest::blake2b256;
use ergo_ser::address::{
    decode_address_content_bytes, decode_address_to_tree_bytes, encode_address_from_tree_bytes,
    encode_p2pk_from_pubkey, AddressDecodeError, NetworkPrefix,
};
use rand::RngCore;
use serde_json::{json, Value as JsonValue};

/// Extract the request body as a JSON string, returning the structured
/// `{"error":400,"reason":"bad-request","detail":"..."}` envelope on
/// any parse failure. axum's default `Json<String>` extractor returns a
/// plain-text rejection which drifts from the rest of this API's error
/// envelope; this helper keeps the shape consistent.
fn parse_json_string_body(body: &Bytes) -> Result<String, Box<Response>> {
    let value: JsonValue = serde_json::from_slice(body)
        .map_err(|e| Box::new(bad_request(format!("invalid JSON body: {e}"))))?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Box::new(bad_request("body must be a JSON string")))
}

/// Default seed size when caller omits a length argument. Matches
/// Scala `ErgoUtilsApiRoute.SeedSize`.
const DEFAULT_SEED_SIZE: usize = 32;

/// Hard cap on `/utils/seed/{length}` to bound response size and
/// CSPRNG work per request. Scala's route accepts any positive int
/// (so a hostile request for `length = i32::MAX` would DoS), so this
/// is a Rust-side hardening that Scala doesn't ship. 8 KiB hex
/// covers every legitimate caller (longest entry under audit: 64-byte
/// XOF seeds).
const SEED_LENGTH_CAP: usize = 8192;

fn bad_request(detail: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": 400,
            "reason": "bad-request",
            "detail": detail.into(),
        })),
    )
        .into_response()
}

fn fresh_seed_hex(length: usize) -> String {
    let mut buf = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(&buf)
}

// ----- /utils/seed (default 32-byte) -----

pub async fn seed_default_handler() -> Response {
    Json(fresh_seed_hex(DEFAULT_SEED_SIZE)).into_response()
}

// ----- /utils/seed/{length} -----

pub async fn seed_length_handler(Path(length): Path<usize>) -> Response {
    if length == 0 {
        return bad_request("seed length must be > 0");
    }
    if length > SEED_LENGTH_CAP {
        return bad_request(format!(
            "seed length {length} exceeds cap {SEED_LENGTH_CAP}; pick something smaller"
        ));
    }
    Json(fresh_seed_hex(length)).into_response()
}

// ----- POST /utils/hash/blake2b -----
//
// Scala body: a JSON string. Returns hex of blake2b256(utf8 bytes).
// Uses raw `Bytes` + `parse_json_string_body` instead of `Json<String>`
// so a malformed body returns our structured 400 envelope instead of
// axum's default plain-text rejection.

pub async fn hash_blake2b_handler(body: Bytes) -> Response {
    let message = match parse_json_string_body(&body) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let digest = blake2b256(message.as_bytes());
    Json(hex::encode(digest.as_bytes())).into_response()
}

// ----- GET /utils/rawToAddress/{pubKeyHex} -----

pub async fn raw_to_address_handler(
    State(network): State<NetworkPrefix>,
    Path(pubkey_hex): Path<String>,
) -> Response {
    let bytes = match hex::decode(&pubkey_hex) {
        Ok(b) => b,
        Err(e) => return bad_request(format!("invalid hex: {e}")),
    };
    match encode_p2pk_from_pubkey(network, &bytes) {
        Ok(address) => Json(json!({ "address": address })).into_response(),
        Err(e) => bad_request(decode_error_message(&e)),
    }
}

// ----- GET /utils/addressToRaw/{address} -----

pub async fn address_to_raw_handler(
    State(network): State<NetworkPrefix>,
    Path(address): Path<String>,
) -> Response {
    match decode_address_content_bytes(&address, network) {
        Ok(bytes) => Json(json!({ "raw": hex::encode(bytes) })).into_response(),
        Err(e) => bad_request(decode_error_message(&e)),
    }
}

// ----- GET /utils/address/{address} -----

pub async fn validate_address_get_handler(
    State(network): State<NetworkPrefix>,
    Path(address): Path<String>,
) -> Response {
    Json(validate_address_response(&address, network)).into_response()
}

// ----- POST /utils/address -----

pub async fn validate_address_post_handler(
    State(network): State<NetworkPrefix>,
    body: Bytes,
) -> Response {
    let address = match parse_json_string_body(&body) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    Json(validate_address_response(&address, network)).into_response()
}

fn validate_address_response(address: &str, network: NetworkPrefix) -> JsonValue {
    match decode_address_content_bytes(address, network) {
        Ok(_) => json!({
            "address": address,
            "isValid": true,
        }),
        Err(e) => json!({
            "address": address,
            "isValid": false,
            "error": decode_error_message(&e),
        }),
    }
}

// ----- GET /utils/ergoTreeToAddress/{hex} -----

pub async fn ergo_tree_to_address_get_handler(
    State(network): State<NetworkPrefix>,
    Path(tree_hex): Path<String>,
) -> Response {
    ergo_tree_to_address_response(network, &tree_hex)
}

// ----- POST /utils/ergoTreeToAddress -----

pub async fn ergo_tree_to_address_post_handler(
    State(network): State<NetworkPrefix>,
    body: Bytes,
) -> Response {
    let tree_hex = match parse_json_string_body(&body) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    ergo_tree_to_address_response(network, &tree_hex)
}

fn ergo_tree_to_address_response(network: NetworkPrefix, tree_hex: &str) -> Response {
    let bytes = match hex::decode(tree_hex) {
        Ok(b) => b,
        Err(e) => return bad_request(format!("invalid hex: {e}")),
    };
    match encode_address_from_tree_bytes(network, &bytes) {
        Ok(addr) => Json(json!({ "address": addr })).into_response(),
        Err(e) => bad_request(format!("ergo_tree parse failed: {e}")),
    }
}

fn decode_error_message(e: &AddressDecodeError) -> String {
    // Scala collapses every parse failure to a single 400; we follow
    // the same envelope but preserve the variant in the detail for
    // operator telemetry. The format string is the Display impl.
    format!("{e}")
}

// ----- /script/* address-conversion endpoints (Scala ScriptApiRoute) -----
//
// The two decode-only members of Scala's `/script` family. The rest of that
// route — `p2sAddress` / `p2shAddress` / `executeWithContext` — compiles
// ErgoScript *source* (the request body carries a `source` + `treeVersion`),
// which needs an ErgoScript compiler this node deliberately does not ship
// (it is an interpreter, not a compiler). Those stay unimplemented; these two
// need only the address decoder, which already backs the `/utils` and
// `/blockchain` address routes.
//
// P2PK and P2S addresses are supported; a P2SH address decodes to
// `UnsupportedType` (a 400) — the same boundary `decode_address_to_tree_bytes`
// already imposes on every other tree-decoding route (`/blockchain/balance`,
// `byAddress`), so this adds no new asymmetry. Scala DOES answer P2SH here,
// returning a *synthetic* P2SH script (the deserialize-and-hash-check wrapper
// with the 24-byte hash embedded); we deliberately do not, because that
// template lives nowhere in the workspace and P2SH is a deprecated address
// class (see `ergo_ser::address`'s module doc). Supporting it is a separate
// feature, not a tweak to these decode routes. A wrong-network address is a
// 400 (`NetworkMismatch`), matching Scala's "Trying to decode testnet address
// in mainnet".

/// Pure core of `/script/addressToTree`: `{"tree": "<ergoTree hex>"}`.
fn address_to_tree_json(
    address: &str,
    network: NetworkPrefix,
) -> Result<JsonValue, AddressDecodeError> {
    let tree = decode_address_to_tree_bytes(address, network)?;
    Ok(json!({ "tree": hex::encode(tree) }))
}

/// Pure core of `/script/addressToBytes`: the ErgoTree serialized AS a
/// `Coll[Byte]` constant — type code `0x0e`, VLQ length, then the tree bytes.
/// Scala emits e.g. `0e24…` for a 36-byte P2PK tree (`0x24` == 36).
fn address_to_bytes_json(
    address: &str,
    network: NetworkPrefix,
) -> Result<JsonValue, AddressDecodeError> {
    let tree = decode_address_to_tree_bytes(address, network)?;
    let mut out = Vec::with_capacity(1 + 5 + tree.len());
    out.push(0x0e); // SColl[SByte] type code
    ergo_primitives::vlq::encode_vlq_into(tree.len() as u64, &mut out);
    out.extend_from_slice(&tree);
    Ok(json!({ "bytes": hex::encode(out) }))
}

/// `GET /script/addressToTree/{address}`
pub async fn script_address_to_tree_handler(
    State(network): State<NetworkPrefix>,
    Path(address): Path<String>,
) -> Response {
    match address_to_tree_json(&address, network) {
        Ok(v) => Json(v).into_response(),
        Err(e) => bad_request(decode_error_message(&e)),
    }
}

/// `GET /script/addressToBytes/{address}`
pub async fn script_address_to_bytes_handler(
    State(network): State<NetworkPrefix>,
    Path(address): Path<String>,
) -> Response {
    match address_to_bytes_json(&address, network) {
        Ok(v) => Json(v).into_response(),
        Err(e) => bad_request(decode_error_message(&e)),
    }
}

#[cfg(test)]
mod script_tests {
    use super::*;

    // Oracle vectors captured from the live Scala mainnet node (`:9053`):
    //   GET /script/addressToTree/<ADDR>  -> {"tree":"0008cd03…068df"}
    //   GET /script/addressToBytes/<ADDR> -> {"bytes":"0e240008cd03…068df"}
    // ADDR is a real mainnet P2PK address read off a live box.
    const ADDR: &str = "9gZyL9m7J9eJv7h6gvxurbD986nWkw44NmHBgMkcxGezesPiETp";
    const TREE: &str = "0008cd030e0048c32f4c804c809edfdff3f3fb70154e5066d0c4e04a767bb5bd149068df";

    #[test]
    fn address_to_tree_matches_scala_oracle() {
        let v = address_to_tree_json(ADDR, NetworkPrefix::Mainnet).expect("decode");
        assert_eq!(v["tree"], TREE);
    }

    #[test]
    fn address_to_bytes_wraps_tree_as_coll_byte_constant() {
        // 0x0e (Coll[Byte] type) + 0x24 (VLQ length 36) + the 36-byte tree.
        let v = address_to_bytes_json(ADDR, NetworkPrefix::Mainnet).expect("decode");
        assert_eq!(v["bytes"], format!("0e24{TREE}"));
    }

    #[test]
    fn wrong_network_is_rejected() {
        // The mainnet vector decoded as Testnet must fail with NetworkMismatch
        // — parity with Scala's "Trying to decode testnet address in mainnet".
        let err = address_to_tree_json(ADDR, NetworkPrefix::Testnet).unwrap_err();
        assert!(
            matches!(err, AddressDecodeError::NetworkMismatch { .. }),
            "expected NetworkMismatch, got {err:?}",
        );
    }
}
