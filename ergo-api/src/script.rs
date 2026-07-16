//! `/script/p2sAddress` + `/script/p2shAddress` — the two compile-requiring
//! members of Scala `ScriptApiRoute` this node previously omitted (see
//! `crate::utils` for the two decode-only siblings, `addressToTree` /
//! `addressToBytes`, which needed no compiler). Wired now that
//! `ergo_compiler::compile` exists.
//!
//! **Public, ungated** — Scala's `ScriptApiRoute` carries no `withAuth`
//! (`ScriptApiRoute.scala:38-46`), unlike the admin/`/node/*` routes, even
//! though it reads wallet pubkeys server-side to build the compile env
//! (`keysToEnv`, `ScriptApiRoute.scala:52-54`). Parity says these two stay
//! public here too — mounted directly (not behind
//! `crate::wallet::router_with_security`'s api-key gate).
//!
//! State: a `(NetworkPrefix, Arc<dyn WalletAdmin>)` tuple, mirroring the
//! `miner_stats_routes` tuple-state precedent (`server.rs`'s
//! `(Arc<dyn NodeChainQuery>, NetworkPrefix)` router) rather than growing
//! `crate::utils`'s stateless `Router<NetworkPrefix>` — that module's own doc
//! frames it as pure/stateless, and these two routes are neither.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_compiler::{compile, EnvValue, NetworkPrefix, ScriptEnv};
use ergo_ser::address::decode_p2pk_address;
use serde::Deserialize;
use serde_json::json;

use crate::utils::bad_request;
use crate::wallet::{WalletAdmin, WalletAdminError};

/// Scala `loadMaxKeys` (`ScriptApiRoute.scala:48,75`): cap the number of
/// wallet addresses folded into the compile env, so an unusually large
/// tracked-address set can't turn every compile request into unbounded work.
const MAX_ENV_KEYS: usize = 100;

/// Wire request DTO — Scala `CompileRequest`
/// (`http/api/requests/CompileRequest.scala:10`: `case class
/// CompileRequest(source: String, treeVersion: Byte)`), decoded via
/// `Decoder.forProduct2("source", "treeVersion")`
/// (`ApiRequestsCodecs.scala:29`): the wire JSON is exactly `{"source":
/// "<script text>", "treeVersion": <byte>}`. `executeWithContext` is the ONE
/// `/script/*` member that also accepts a caller-supplied `namedConstants`
/// env — out of scope here, not one of these two routes.
#[derive(Deserialize)]
pub struct CompileRequestDto {
    source: String,
    #[serde(rename = "treeVersion")]
    tree_version: u8,
}

/// Build the compile-time env from the wallet's tracked addresses, mirroring
/// Scala's `keysToEnv` (`ScriptApiRoute.scala:52-54`): each address becomes
/// `myPubKey_N -> ProveDlog(pk)`, capped at `MAX_ENV_KEYS` (`loadMaxKeys`).
///
/// An address that fails to decode to a valid P2PK pubkey (wrong network,
/// wrong address type, bad checksum, off-curve/identity point) is surfaced as
/// the SAME 400 class this route already returns for a compile failure — no
/// special-casing needed, `decode_p2pk_address`'s `AddressDecodeError`
/// implements `Display` like every other decode error in this crate.
fn build_env(
    addrs: &[String],
    network: NetworkPrefix,
) -> Result<ScriptEnv, ergo_ser::address::AddressDecodeError> {
    let mut env = ScriptEnv::new();
    for (i, addr) in addrs.iter().take(MAX_ENV_KEYS).enumerate() {
        let pk = decode_p2pk_address(addr, network)?;
        env.insert(format!("myPubKey_{i}"), EnvValue::ProveDlog(pk));
    }
    Ok(env)
}

/// Map a `WalletAdminError` from the `addresses()` read to a `Response`.
///
/// `addresses()` never actually errors in the real node backend (it reads
/// whatever address set is currently visible, empty or not, regardless of
/// lock state — see the M6 report's decision-4 note), but the trait's
/// signature is fallible, so a real error IS possible from a future/alternate
/// `WalletAdmin` implementation. Surfaced honestly rather than invented:
/// `Locked`/`Uninitialized` map to 400 (a well-formed request against a wallet
/// that isn't ready yet, not a caller error), everything else to 500.
fn wallet_error_response(e: WalletAdminError) -> Response {
    match e {
        WalletAdminError::Locked | WalletAdminError::Uninitialized => {
            bad_request(format!("wallet not ready: {e}"))
        }
        other => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": 500,
                "reason": "internal",
                "detail": other.to_string(),
            })),
        )
            .into_response(),
    }
}

/// Compile `req.source` against the wallet-address env and answer with one
/// address field, or a `bad_request` envelope on any compile/env failure.
/// `pick` selects which of `CompileResult`'s two pre-computed addresses to
/// serve — `p2s_address` for `p2sAddressR`, `p2sh_address` for `p2shAddressR`
/// (`ScriptApiRoute.scala:60-65`, `addressResponse`, `:50`).
async fn compile_address_response(
    network: NetworkPrefix,
    wallet_admin: &Arc<dyn WalletAdmin>,
    req: CompileRequestDto,
    pick: impl FnOnce(&ergo_compiler::CompileResult) -> &str,
) -> Response {
    let addrs = match wallet_admin.addresses().await {
        Ok(list) => list.0,
        Err(e) => return wallet_error_response(e),
    };
    let env = match build_env(&addrs, network) {
        Ok(env) => env,
        Err(e) => return bad_request(format!("{e}")),
    };
    match compile(&env, &req.source, req.tree_version, network) {
        Ok(result) => Json(json!({ "address": pick(&result) })).into_response(),
        Err(e) => bad_request(e.to_string()),
    }
}

/// `POST /script/p2sAddress` — Scala `p2sAddressR` (`ScriptApiRoute.scala:71-76`).
pub async fn p2s_address_handler(
    State((network, wallet_admin)): State<(NetworkPrefix, Arc<dyn WalletAdmin>)>,
    Json(req): Json<CompileRequestDto>,
) -> Response {
    compile_address_response(network, &wallet_admin, req, |r| r.p2s_address.as_str()).await
}

/// `POST /script/p2shAddress` — Scala `p2shAddressR` (`ScriptApiRoute.scala:78-83`).
pub async fn p2sh_address_handler(
    State((network, wallet_admin)): State<(NetworkPrefix, Arc<dyn WalletAdmin>)>,
    Json(req): Json<CompileRequestDto>,
) -> Response {
    compile_address_response(network, &wallet_admin, req, |r| r.p2sh_address.as_str()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::address::NetworkPrefix;

    // ----- helpers -----

    /// A real mainnet P2PK address (same vector `utils.rs`'s script tests
    /// use) — decodes to a genuine on-curve pubkey via `decode_p2pk_address`.
    const ADDR: &str = "9gZyL9m7J9eJv7h6gvxurbD986nWkw44NmHBgMkcxGezesPiETp";

    // ----- happy path -----

    #[test]
    fn build_env_injects_my_pubkey_n_per_address() {
        let env = build_env(&[ADDR.to_string()], NetworkPrefix::Mainnet).expect("decode");
        assert!(env.contains("myPubKey_0"));
        assert!(!env.contains("myPubKey_1"));
    }

    #[test]
    fn build_env_caps_at_max_env_keys() {
        let addrs = vec![ADDR.to_string(); MAX_ENV_KEYS + 10];
        let env = build_env(&addrs, NetworkPrefix::Mainnet).expect("decode");
        assert!(env.contains(&format!("myPubKey_{}", MAX_ENV_KEYS - 1)));
        assert!(!env.contains(&format!("myPubKey_{MAX_ENV_KEYS}")));
    }

    #[test]
    fn build_env_empty_address_list_yields_empty_env() {
        let env = build_env(&[], NetworkPrefix::Mainnet).expect("decode");
        assert!(!env.contains("myPubKey_0"));
    }

    // ----- error paths -----

    #[test]
    fn build_env_invalid_address_errors() {
        let err = build_env(&["not-a-real-address".to_string()], NetworkPrefix::Mainnet)
            .expect_err("must fail to decode");
        // Same AddressDecodeError family every other decode route in this
        // crate surfaces — exercised end-to-end (not just this pure core) by
        // `ergo-api/tests/script_compile_routes.rs`.
        let _ = err.to_string();
    }

    #[test]
    fn wallet_error_response_not_ready_variants_map_to_400() {
        use crate::wallet::WalletAdminError;
        for e in [WalletAdminError::Locked, WalletAdminError::Uninitialized] {
            let resp = wallet_error_response(e);
            assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn wallet_error_response_other_maps_to_500() {
        use crate::wallet::WalletAdminError;
        let resp = wallet_error_response(WalletAdminError::Internal("boom".into()));
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
