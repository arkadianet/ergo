//! API-key authentication middleware for operator routes.
//!
//! Mirrors the Scala reference's `ApiDirectives.withAuth`
//! (`scorex/core/api/http/ApiDirectives.scala`):
//!
//! * Header name: `api_key` (lowercase, underscore). Not `X-Api-Key`,
//!   not `Authorization` — the existing operator tooling (curl one-liners,
//!   wallet SDKs, Scala node integration tests) all assume `api_key`.
//! * Hash: Blake2b-256 of the raw header bytes → lowercase Base16 (hex).
//! * Compare: constant-time `subtle::ConstantTimeEq` against the
//!   operator-configured `api_key_hash` (also 64-char lowercase hex).
//! * Rejection: HTTP 403 with JSON body
//!   `{ "error": 403, "reason": "invalid.api-key", "detail": null }`,
//!   matching Scala's `ApiError.ApiKeyNotValid`
//!   (`http/api/ApiError.scala:37`).
//!
//! Mounted by [`crate::wallet::router_with_security`] and [`crate::server`] around the
//! `/wallet/*` and `/node/*` subtrees when an [`ApiSecurity`] is
//! configured. Public routes (`/info`, `/blocks/*`, `/peers/*`, …) do not
//! receive the layer.
//!
//! **Mounting discipline**: always attach this gate with
//! `Router::route_layer`, never `Router::layer`. A plain `layer` also
//! wraps the subtree's implicit fallback, and `Router::merge` propagates
//! that wrapped fallback into the assembled router — every unmatched
//! path node-wide then answers `403 invalid.api-key` instead of `404`,
//! masking "route does not exist" as "you need a key". Whole-prefix
//! gating (Scala's `pathPrefix(...) & withAuth`) is preserved via
//! explicit catch-all routes ([`unknown_gated_subpath`]) that
//! `route_layer` does cover. Regression pinned by
//! `tests/openapi_native_runtime_mount.rs`.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use blake2::{digest::consts::U32, Blake2b, Digest};
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// HTTP header name carrying the operator's plaintext API key. Matches
/// Scala `ApiRoute.apiKeyHeaderName = "api_key"`.
pub const API_KEY_HEADER: &str = "api_key";

/// Operator-side state required by [`require_api_key`]. Built once at
/// server boot from the loaded `[api.security].api_key_hash` config
/// field and handed to the middleware via axum state.
#[derive(Debug, Clone)]
pub struct ApiSecurity {
    /// Lowercase Base16 (hex) of the Blake2b-256 hash of the operator's
    /// secret API key. Always 64 chars. Compared in constant time
    /// against the hex digest of incoming `api_key` header bytes.
    api_key_hash_hex: String,
}

/// Validation errors for the operator-supplied `api_key_hash`. Surfaced
/// at config load so a malformed hash exits the node with a clear shell
/// message rather than silently disabling auth.
#[derive(Debug, thiserror::Error)]
pub enum ApiSecurityError {
    /// Hash string isn't 64 chars (32 bytes hex).
    #[error("api_key_hash must be 64 lowercase hex chars, got {got}")]
    InvalidLength {
        /// Length of the supplied string in bytes.
        got: usize,
    },
    /// Hash contains chars outside `[0-9a-f]`.
    #[error("api_key_hash must be lowercase hex (0-9, a-f only)")]
    InvalidChars,
}

impl ApiSecurity {
    /// Build an [`ApiSecurity`] from the operator's configured hash.
    /// Returns [`ApiSecurityError`] on length or charset violations so
    /// the node refuses to start rather than running with an unparseable
    /// hash silently treated as "always reject."
    pub fn new(api_key_hash_hex: String) -> Result<Self, ApiSecurityError> {
        if api_key_hash_hex.len() != 64 {
            return Err(ApiSecurityError::InvalidLength {
                got: api_key_hash_hex.len(),
            });
        }
        if !api_key_hash_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ApiSecurityError::InvalidChars);
        }
        Ok(Self { api_key_hash_hex })
    }

    /// Lowercase Base16 (hex) of the Blake2b-256 of `raw_key`. Matches
    /// Scala `ScorexEncoder.encode(Blake2b256(key))` at
    /// `ApiDirectives.scala:15`. Exposed for the `blake2b256-cli`-style
    /// operator helper and for test oracle pinning.
    pub fn hash_key(raw_key: &[u8]) -> String {
        let mut h = Blake2b::<U32>::new();
        h.update(raw_key);
        hex::encode(h.finalize())
    }
}

type Blake2b256 = Blake2b<U32>;

/// axum middleware that gates a router subtree on the `api_key` header.
///
/// Returns 403 + the Scala-parity JSON envelope on missing header or
/// hash mismatch. Forwards to the inner handler only when the header's
/// Blake2b-256 hex digest matches the configured hash byte-for-byte
/// (constant time).
pub async fn require_api_key(
    State(sec): State<Arc<ApiSecurity>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Some(header_val) = req.headers().get(API_KEY_HEADER) else {
        return reject_invalid();
    };
    let mut h = Blake2b256::new();
    h.update(header_val.as_bytes());
    let computed_hex = hex::encode(h.finalize());

    // Constant-time compare on the hex strings. Lengths are both 64 by
    // construction (`ApiSecurity::new` validates the config side;
    // `hex::encode` of a 32-byte digest is always 64). `ct_eq` returns
    // `Choice` — `.into()` to bool only after both sides have been
    // walked end-to-end.
    if bool::from(
        computed_hex
            .as_bytes()
            .ct_eq(sec.api_key_hash_hex.as_bytes()),
    ) {
        next.run(req).await
    } else {
        reject_invalid()
    }
}

/// Post-auth catch-all for unknown subpaths under a gated prefix
/// (`/wallet/*`, `/node/*`). Scala gates the whole `pathPrefix` before
/// inner route matching (`(pathPrefix("wallet") & withAuth)`,
/// `WalletApiRoute.scala`), so an unknown gated subpath rejects on the
/// key first; once the key passes we return the house plain `404`
/// (Scala renders its global `handleNotFound` 400 `bad.request`
/// envelope here — `ApiRejectionHandler.scala:35` — the 404 is the same
/// deliberate divergence as the unmounted-surface rule).
///
/// Registered as real routes (`/wallet`, `/wallet/*rest`, …) rather
/// than a subtree fallback so the `route_layer`-mounted gate covers
/// them — see the mounting-discipline note in the module docs.
pub(crate) async fn unknown_gated_subpath() -> StatusCode {
    StatusCode::NOT_FOUND
}

fn reject_invalid() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": 403,
            "reason": "invalid.api-key",
            "detail": null,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// External oracle: `Blake2b256("hello") -> "324dcf...72cf"` is
    /// the exact `(secret, hash)` pair pinned in every Scala config
    /// template (`reference/ergo/src/main/resources/{application,
    /// mainnet,testnet,devnet}.conf::apiKeyHash`) AND sent by the
    /// Scala integration test client at
    /// `reference/ergo/src/it/scala/.../api/NodeApi.scala:52`
    /// (`setHeader("api_key", "hello")`). If our implementation
    /// matches this hash, our Blake2b-256 + Base16 lowercase digest
    /// is byte-for-byte parity with the Scala node — any drift would
    /// break operator tools that ship that exact hash.
    ///
    /// The literal is duplicated in three other test fixtures
    /// (`ergo-api/tests/auth.rs`, `ergo-node/src/config.rs::tests`,
    /// `ergo-node/tests/common/mod.rs`). All four MUST stay in sync
    /// with the Scala reference if it ever changes — there is no
    /// shared fixture crate today.
    const HELLO: &[u8] = b"hello";
    const HELLO_BLAKE2B256_HEX: &str =
        "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";

    // ----- happy path -----

    #[test]
    fn hash_key_matches_scala_oracle_for_hello() {
        assert_eq!(ApiSecurity::hash_key(HELLO), HELLO_BLAKE2B256_HEX);
    }

    #[test]
    fn api_security_new_accepts_valid_lowercase_hex() {
        let sec = ApiSecurity::new(HELLO_BLAKE2B256_HEX.to_string()).expect("valid hex");
        assert_eq!(sec.api_key_hash_hex, HELLO_BLAKE2B256_HEX);
    }

    // ----- error paths -----

    #[test]
    fn api_security_new_rejects_wrong_length() {
        let err = ApiSecurity::new("deadbeef".to_string()).expect_err("too short");
        assert!(matches!(err, ApiSecurityError::InvalidLength { got: 8 }));
    }

    #[test]
    fn api_security_new_rejects_uppercase_hex() {
        // Scala parity (`ScorexEncoder.encode` is lowercase Base16) +
        // operator-facing simplicity (one canonical form, no normalize).
        let upper = HELLO_BLAKE2B256_HEX.to_uppercase();
        let err = ApiSecurity::new(upper).expect_err("uppercase rejected");
        assert!(matches!(err, ApiSecurityError::InvalidChars));
    }

    #[test]
    fn api_security_new_rejects_non_hex_chars() {
        let mut bad = HELLO_BLAKE2B256_HEX.to_string();
        bad.pop();
        bad.push('z');
        let err = ApiSecurity::new(bad).expect_err("non-hex char rejected");
        assert!(matches!(err, ApiSecurityError::InvalidChars));
    }
}
