//! `addresses/*` reads (`v1-api-design.md` §3.7). This group OWNS the
//! `/api/v1/addresses/*` subtree (coherence O9). `balance` and `transactions`
//! are unique here; `boxes` / `unspent` are the SAME resources as
//! `boxes/{by-address,unspent/by-address}` (O10) — one handler
//! ([`super::boxes`]), dual-mounted in the router, never a second copy.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::Page as IdxPage;
use serde::Deserialize;
use utoipa::ToSchema;

use super::dto::{address_tx_summary_from_indexed, Collection, V1Asset, V1Balance, V1BalanceEntry};
use super::extract::V1Query;
use super::{offset_from_cursor, offset_page, parse_sort, V1State};
use crate::blockchain::{
    address_to_tree_hash, build_indexed_tx_response, unconfirmed_balance_for_tree, BalanceInfoEntry,
};
use crate::v1::cursor::clamp_limit;
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::routes::dto::V1AddressTxSummary;

const DEFAULT_LIMIT: u32 = 20;
const MAX_LIMIT: u32 = 500;

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct AddressTxQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    sort: Option<String>,
}

fn invalid_address(detail: &str) -> Response {
    v1_error(
        Reason::InvalidAddress,
        "address is not valid base58 for this network",
        detail.to_string(),
    )
}

/// Map the compat balance entry (`nano_ergs: i64` + `tokens`) into the v1
/// entry: the nanoERG leaf is `value` (glossary C.2), a decimal string.
fn balance_entry_from_info(e: BalanceInfoEntry) -> V1BalanceEntry {
    V1BalanceEntry {
        value: e.nano_ergs.to_string(),
        assets: e
            .tokens
            .into_iter()
            .map(|t| V1Asset {
                token_id: t.token_id,
                amount: t.amount.to_string(),
            })
            .collect(),
    }
}

// ----- addresses/{address}/balance ----------------------------------------

/// `GET /api/v1/addresses/{address}/balance`. `unconfirmed` is strictly
/// additive (Scala parity) — pool outputs add; pool spends do NOT subtract from
/// `confirmed`.
#[utoipa::path(
    get, path = "/api/v1/addresses/{address}/balance", tag = "addresses",
    params(("address" = String, Path, description = "Base58 address")),
    responses(
        (status = 200, description = "Confirmed + unconfirmed balance", body = V1Balance),
        (status = 400, description = "Invalid address", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 503, description = "Extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn balance(State(state): State<V1State>, Path(address): Path<String>) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let tree_hash = match address_to_tree_hash(&address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
    };
    let confirmed = match idx.address_balance(&tree_hash) {
        Some(dto) => V1BalanceEntry {
            value: dto.nano_ergs.to_string(),
            assets: dto
                .tokens
                .into_iter()
                .map(|(id, amount)| V1Asset {
                    token_id: hex::encode(id.as_bytes()),
                    amount: amount.to_string(),
                })
                .collect(),
        },
        None => V1BalanceEntry {
            value: "0".to_string(),
            assets: Vec::new(),
        },
    };
    let unconfirmed = balance_entry_from_info(unconfirmed_balance_for_tree(
        state.mempool.as_ref(),
        &tree_hash,
    ));
    Json(V1Balance {
        address,
        confirmed,
        unconfirmed,
    })
    .into_response()
}

// ----- addresses/{address}/transactions -----------------------------------

/// `GET /api/v1/addresses/{address}/transactions` — a small tx summary
/// projected DOWN from the shared indexed-tx builder (never re-derives the
/// confirmation math).
#[utoipa::path(
    get, path = "/api/v1/addresses/{address}/transactions", tag = "addresses",
    params(
        ("address" = String, Path, description = "Base58 address"),
        ("limit" = Option<u32>, Query, description = "Page size (default 20, cap 500)"),
        ("cursor" = Option<String>, Query, description = "Opaque page cursor from a prior response"),
        ("sort" = Option<String>, Query, description = "`desc` (default) or `asc`"),
    ),
    responses(
        (status = 200, description = "Address transaction history", body = Collection<V1AddressTxSummary>),
        (status = 400, description = "Invalid address/sort/cursor", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 500, description = "Failed to assemble the address transaction summary", body = V1Error),
        (status = 503, description = "Chain reader unavailable, or extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn transactions(
    State(state): State<V1State>,
    Path(address): Path<String>,
    V1Query(q): V1Query<AddressTxQuery>,
) -> Response {
    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let tree_hash = match address_to_tree_hash(&address, state.network) {
        Ok(h) => h,
        Err(e) => return invalid_address(&e),
    };
    let dir = match parse_sort(q.sort.as_deref()) {
        Ok(d) => d,
        Err(e) => return *e,
    };
    let start = match offset_from_cursor(q.cursor.as_deref()) {
        Ok(o) => o,
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let txs = idx.address_txs_paged(
        &tree_hash,
        IdxPage {
            offset: start,
            limit: limit + 1,
        },
        dir,
    );
    // Building tx summaries resolves inputs via the chain reader — but only when
    // there ARE txs; an empty result is authoritative from the index and needs
    // no chain. Guard the non-empty case so a missing reader is an honest
    // `chain_reader_unavailable`, not a 500 from the downstream
    // `build_indexed_tx_response` (CodeRabbit #170).
    if !txs.is_empty() {
        if let Err(e) = state.chain() {
            return *e;
        }
    }
    let bstate = state.blockchain_state(idx);
    let built: Result<Vec<_>, String> = txs
        .iter()
        .map(|tx| build_indexed_tx_response(&bstate, tx))
        .collect();
    let resps = match built {
        Ok(v) => v,
        Err(d) => {
            return v1_error(
                Reason::InternalError,
                "failed to assemble the address transaction summary",
                d,
            )
        }
    };
    let items: Vec<_> = resps.iter().map(address_tx_summary_from_indexed).collect();
    let (items, page) = offset_page(items, start, limit);
    Json(Collection { items, page }).into_response()
}
