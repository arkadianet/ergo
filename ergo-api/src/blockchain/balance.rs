//! `/blockchain/balance` (POST) and `/blockchain/balanceForAddress/{address}` (GET).
//!
//! Both routes resolve a base58 address to its `tree_hash` (the redb key
//! for `INDEXED_ADDRESS`), pull the confirmed balance from the indexer,
//! and overlay an additive unconfirmed view from the snapshot-backed
//! [`MempoolView`].
//!
//! `unconfirmed` semantics are strictly additive per Scala
//! `BlockchainApiRoute.scala:444-451`: pool outputs paying the address
//! add to `unconfirmed`, but pool inputs spending the user's confirmed
//! boxes do NOT subtract from `confirmed`. Wallets needing a true
//! spendable view should compose
//! `/blockchain/box/unspent/byAddress?excludeMempoolSpent=true&includeUnconfirmed=true`.
//!
//! `address_to_tree_hash` and `invalid_address` are exposed as
//! `pub(super)` so the byAddress / unspent-byAddress route families can
//! reuse them when those modules land.

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::{BalanceDto, TokenId, TreeHash};
use ergo_ser::address::{decode_address_to_tree_hash, AddressDecodeError, NetworkPrefix};
use ergo_ser::ergo_tree::tree_hash_from_bytes;
use serde::Serialize;

use crate::traits::MempoolView;

use super::{BlockchainState, ErrorEnvelope};

/// JSON wire shape for `/blockchain/balance` and the GET twin per
/// `openapi.yaml`. `unconfirmed` is populated from the snapshot-backed
/// [`MempoolView`] overlay. When the router is wired with
/// [`crate::traits::NoopMempoolView`] the overlay yields all-zero —
/// same wire shape, no `warning` field either way.
///
/// `unconfirmed` semantics are strictly additive per Scala
/// `BlockchainApiRoute.scala:444-451`: pool outputs paying the address
/// add to `unconfirmed`, but pool inputs spending the user's confirmed
/// boxes do NOT subtract from `confirmed`. Wallets needing a true
/// spendable view should compose
/// `/blockchain/box/unspent/byAddress?excludeMempoolSpent=true&includeUnconfirmed=true`.
#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub confirmed: BalanceInfoEntry,
    pub unconfirmed: BalanceInfoEntry,
}

#[derive(Debug, Default, Serialize)]
pub struct BalanceInfoEntry {
    #[serde(rename = "nanoErgs")]
    pub nano_ergs: i64,
    pub tokens: Vec<TokenAmountEntry>,
}

#[derive(Debug, Serialize)]
pub struct TokenAmountEntry {
    #[serde(rename = "tokenId")]
    pub token_id: String,
    pub amount: i64,
}

/// `POST /blockchain/balance`. Body is a JSON-encoded base58 address
/// string (Scala wire shape: `requestBody.application/json.schema =
/// type:string`). 400 on parse failure, 200 with all-zero confirmed
/// balance for an unindexed address.
pub async fn balance_post_handler(
    State(state): State<BlockchainState>,
    Json(address): Json<String>,
) -> Response {
    render_balance(&state, &address)
}

/// `GET /blockchain/balanceForAddress/{address}`. Functionally identical
/// to the POST form; differs only in how the address arrives. 400 on
/// parse failure with the pinned error envelope.
pub async fn balance_for_address_handler(
    State(state): State<BlockchainState>,
    Path(address): Path<String>,
) -> Response {
    render_balance(&state, &address)
}

fn render_balance(state: &BlockchainState, address: &str) -> Response {
    let tree_hash = match address_to_tree_hash(address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
    };
    let confirmed = state
        .indexer
        .address_balance(&tree_hash)
        .map(balance_dto_to_entry)
        .unwrap_or_default();
    let unconfirmed = unconfirmed_balance_for_tree(state.mempool.as_ref(), &tree_hash);
    let body = BalanceResponse {
        confirmed,
        unconfirmed,
    };
    Json(body).into_response()
}

/// Walk the mempool overlay's pool outputs, sum value + tokens for any
/// box whose `ergo_tree_bytes` hash to `tree_hash`. Strictly additive —
/// see [`BalanceResponse`] for the spec rationale.
///
/// Token aggregation: outputs in iteration order seed the `tokens` vec,
/// later occurrences of the same `TokenId` accumulate into the existing
/// entry. The `tokens` vec is then sorted by `tokenId` hex so the wire
/// shape is stable across snapshot rebuilds (the underlying
/// `pool_outputs()` is a `HashMap`, so iteration order is not
/// deterministic). This diverges from Scala's first-touch
/// `ArrayBuffer` ordering on the confirmed path, but matches the spec's
/// "stable wire shape under snapshot rebuilds" requirement for the P5
/// overlay.
fn unconfirmed_balance_for_tree(
    mempool: &dyn MempoolView,
    tree_hash: &TreeHash,
) -> BalanceInfoEntry {
    let outputs = mempool.pool_outputs();
    if outputs.is_empty() {
        return BalanceInfoEntry::default();
    }
    let mut nano_ergs: i64 = 0;
    let mut token_index: std::collections::HashMap<TokenId, usize> =
        std::collections::HashMap::new();
    let mut tokens: Vec<TokenAmountEntry> = Vec::new();
    for box_data in outputs.values() {
        let tree_bytes = box_data.candidate.ergo_tree_bytes();
        let computed = match tree_hash_from_bytes(tree_bytes) {
            Ok(h) => TreeHash::from_bytes(h),
            // Pool outputs went through admission's canonicalization, so
            // a parse / write failure here implies a snapshot publisher
            // bug. Skip rather than poisoning the response — the same
            // box would also fail to project into the indexer DTO path.
            Err(err) => {
                tracing::warn!(error = ?err, "unconfirmed balance: skipping pool output with unparseable ergo_tree (snapshot/admission canonicalization drift?)");
                continue;
            }
        };
        if computed != *tree_hash {
            continue;
        }
        nano_ergs = nano_ergs.saturating_add(box_data.candidate.value as i64);
        for token in &box_data.candidate.tokens {
            match token_index.get(&token.token_id) {
                Some(&i) => {
                    tokens[i].amount = tokens[i].amount.saturating_add(token.amount as i64);
                }
                None => {
                    token_index.insert(token.token_id, tokens.len());
                    tokens.push(TokenAmountEntry {
                        token_id: hex::encode(token.token_id.as_bytes()),
                        amount: token.amount as i64,
                    });
                }
            }
        }
    }
    tokens.sort_by(|a, b| a.token_id.cmp(&b.token_id));
    BalanceInfoEntry { nano_ergs, tokens }
}

/// Decode the base58 address into its canonical `tree_hash` (the redb
/// key for `INDEXED_ADDRESS`). Errors are returned as `String` for the
/// `400 invalid-address` envelope's `detail` field.
pub(super) fn address_to_tree_hash(s: &str, network: NetworkPrefix) -> Result<TreeHash, String> {
    let raw =
        decode_address_to_tree_hash(s, network).map_err(|e: AddressDecodeError| e.to_string())?;
    Ok(TreeHash::from_bytes(raw))
}

fn balance_dto_to_entry(dto: BalanceDto) -> BalanceInfoEntry {
    BalanceInfoEntry {
        nano_ergs: dto.nano_ergs,
        tokens: dto
            .tokens
            .into_iter()
            .map(|(id, amount)| TokenAmountEntry {
                token_id: hex::encode(id.as_bytes()),
                amount,
            })
            .collect(),
    }
}

pub(super) fn invalid_address(detail: &str) -> Response {
    let body = ErrorEnvelope {
        error: 400,
        reason: "invalid-address",
        detail: detail.to_string(),
    };
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}
