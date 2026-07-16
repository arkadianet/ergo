//! Semantic-decode HTTP surface: the protocol-registry discovery endpoints
//! (`GET /protocols`, `GET /protocols/{id}`), the stateless off-chain decoder
//! (`POST /boxes/decode`), and the singleton-state one-shot
//! (`GET /protocols/{id}/state`). The core `?decode=true` augmentation on the
//! box routes is wired in `dto.rs`; this file is the registry's own surface.
//! All T0, all bounded.

use std::collections::BTreeMap;
use utoipa::ToSchema;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::{Page as IdxPage, SortDir, TokenId};
use ergo_ser::address::encode_address_from_tree_bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::dto::{v1box_from_indexed_box, Collection};
use super::extract::{V1Json, V1Query};
use super::{parse_id32, V1State};
use crate::v1::decode::registry::{entry_by_id, MatchKind, ProtocolEntry, REGISTRY};
use crate::v1::error::{v1_error, Reason, V1Error};

// ----- discovery: GET /protocols, GET /protocols/{id} ---------------------

/// A `GET /protocols` list item — the registry capability advertisement.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ProtocolListItem {
    protocol_id: &'static str,
    name: &'static str,
    family: &'static str,
    version: &'static str,
    box_roles: Vec<&'static str>,
    matcher_count: usize,
    /// `true` only when a verified matcher + real decoder exist. `false` marks
    /// a discoverable stub (recognized, full decode TODO) — never a lie.
    decodable: bool,
    reference: &'static str,
    note: &'static str,
}

/// De-duplicated box roles across an entry's matchers (stable order).
fn box_roles(entry: &ProtocolEntry) -> Vec<&'static str> {
    let mut roles: Vec<&'static str> = Vec::new();
    for m in entry.matchers {
        if !roles.contains(&m.box_role) {
            roles.push(m.box_role);
        }
    }
    roles
}

fn list_item(entry: &'static ProtocolEntry) -> ProtocolListItem {
    ProtocolListItem {
        protocol_id: entry.id,
        name: entry.name,
        family: entry.family.wire(),
        version: entry.version,
        box_roles: box_roles(entry),
        matcher_count: entry.matchers.len(),
        decodable: entry.decodable,
        reference: entry.reference,
        note: entry.note,
    }
}

/// `GET /api/v1/protocols` — the registry listing (discoverability: a client
/// learns exactly what this node can decode). Static registry → a trivial
/// single page. No indexer dependency; the cheapest possible T0.
#[utoipa::path(
    get, path = "/api/v1/protocols", tag = "decode",
    responses(
        (status = 200, description = "Registered protocols (single page)", body = Collection<ProtocolListItem>),
    ),
)]
pub async fn list_protocols(State(_state): State<V1State>) -> Response {
    let items: Vec<ProtocolListItem> = REGISTRY.iter().map(list_item).collect();
    Json(Collection::single_page(items)).into_response()
}

/// One matcher, projected for `GET /protocols/{id}` so an integrator can
/// pre-compute keys client-side.
#[derive(Debug, Serialize, ToSchema)]
struct MatcherView {
    kind: &'static str,
    key: &'static str,
    box_role: &'static str,
}

/// `GET /api/v1/protocols/{id}` detail body.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ProtocolDetail {
    protocol_id: &'static str,
    name: &'static str,
    family: &'static str,
    version: &'static str,
    reference: &'static str,
    note: &'static str,
    decodable: bool,
    matchers: Vec<MatcherView>,
}

/// `GET /api/v1/protocols/{protocol_id}` — one registry entry incl. its
/// matchers. Unknown id → `404 protocol_not_found` (a genuinely absent
/// resource, not a disabled subsystem).
#[utoipa::path(
    get, path = "/api/v1/protocols/{protocol_id}", tag = "decode",
    params(("protocol_id" = String, Path, description = "Registry protocol id")),
    responses(
        (status = 200, description = "Protocol detail incl. matchers", body = ProtocolDetail),
        (status = 404, description = "No protocol with that id", body = V1Error),
    ),
)]
pub async fn protocol_by_id(
    State(_state): State<V1State>,
    Path(protocol_id): Path<String>,
) -> Response {
    let Some(entry) = entry_by_id(&protocol_id) else {
        return v1_error(
            Reason::ProtocolNotFound,
            "no protocol with that id in the registry",
            "GET /api/v1/protocols lists every registered protocol id",
        );
    };
    let matchers = entry
        .matchers
        .iter()
        .map(|m| MatcherView {
            kind: m.kind.wire(),
            key: m.key,
            box_role: m.box_role,
        })
        .collect();
    Json(ProtocolDetail {
        protocol_id: entry.id,
        name: entry.name,
        family: entry.family.wire(),
        version: entry.version,
        reference: entry.reference,
        note: entry.note,
        decodable: entry.decodable,
        matchers,
    })
    .into_response()
}

// ----- POST /boxes/decode (stateless, off-chain) --------------------------

/// An asset on an off-chain box (`amount` a string per the glossary).
#[derive(Debug, Deserialize, ToSchema)]
pub struct AssetIn {
    token_id: String,
    amount: String,
}

/// `POST /api/v1/boxes/decode` body — a structured box (the shape `tx/build` and
/// `tx/simulate` emit). `value` and asset `amount`s are strings (§1.1).
///
/// Raw `box_bytes` decoding is intentionally not offered here: the box parser is
/// tree-boundary-dependent for non-size-delimited contract trees (the exact
/// trees these protocols use), so a bytes path would be unreliable — the
/// structured form is complete and honest.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DecodeBoxBody {
    ergo_tree: String,
    value: String,
    #[serde(default)]
    assets: Vec<AssetIn>,
    #[serde(default)]
    registers: BTreeMap<String, String>,
}

/// The `POST /boxes/decode` response: the derived address + the shared `decoded`
/// object (identical shape to `boxes/{id}?decode=true`).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DecodeBoxResponse {
    address: Option<String>,
    decoded: Value,
}

fn invalid_amount(detail: impl Into<String>) -> Response {
    v1_error(
        Reason::BadRequest,
        "value/amount is not a base-10 unsigned integer string",
        detail,
    )
}

/// `POST /api/v1/boxes/decode` — decode an off-chain / not-yet-submitted box.
/// Stateless: works even when the indexer is disabled. Pure CPU, body-capped.
#[utoipa::path(
    post, path = "/api/v1/boxes/decode", tag = "decode",
    request_body = DecodeBoxBody,
    responses(
        (status = 200, description = "Derived address + decoded contract (null if unmatched)", body = DecodeBoxResponse),
        (status = 400, description = "Invalid ergo_tree/value/asset amount", body = V1Error),
    ),
)]
pub async fn decode_off_chain_box(
    State(state): State<V1State>,
    V1Json(body): V1Json<DecodeBoxBody>,
) -> Response {
    let value: u64 = match body.value.trim().parse() {
        Ok(v) => v,
        Err(e) => return invalid_amount(format!("value: {e}")),
    };
    let mut tokens: Vec<(String, u64)> = Vec::with_capacity(body.assets.len());
    for a in &body.assets {
        match a.amount.trim().parse::<u64>() {
            Ok(amt) => tokens.push((a.token_id.clone(), amt)),
            Err(e) => return invalid_amount(format!("asset {}: {e}", a.token_id)),
        }
    }
    // The tree must be hex; a parse-level tree failure is a malformed request.
    // Decoded ONCE — the same bytes derive the address and feed the decode seam.
    let tree_bytes = match hex::decode(body.ergo_tree.trim()) {
        Ok(bytes) => bytes,
        Err(e) => {
            return v1_error(
                Reason::InvalidErgoTree,
                "ergo_tree is not valid hex",
                format!("hex decode: {e}"),
            )
        }
    };
    let address = encode_address_from_tree_bytes(state.network, &tree_bytes).ok();
    let decoded =
        crate::v1::decode::decode_box_bytes(Some(&tree_bytes), value, &tokens, &body.registers);
    Json(DecodeBoxResponse { address, decoded }).into_response()
}

// ----- GET /protocols/{id}/state (singleton one-shot) ---------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct StateQuery {
    #[serde(default)]
    box_role: Option<String>,
}

/// `GET /api/v1/protocols/{id}/state` response — the canonical singleton state.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ProtocolStateResponse {
    protocol_id: &'static str,
    box_role: &'static str,
    box_id: String,
    height: Option<i32>,
    as_of_height: u32,
    confirmed: bool,
    /// The decoded `contract` object (incl. `state`), or `null` if the resolved
    /// box did not decode to this protocol (kept honest).
    contract: Value,
}

/// `GET /api/v1/protocols/{protocol_id}/state` — resolve the current unspent box
/// holding the protocol's identifying NFT and return its decoded state (the
/// "give me SigmaUSD reserves right now" one-shot). Requires an
/// `identifying_token` matcher.
#[utoipa::path(
    get, path = "/api/v1/protocols/{protocol_id}/state", tag = "decode",
    params(
        ("protocol_id" = String, Path, description = "Registry protocol id"),
        ("box_role" = Option<String>, Query, description = "Disambiguate when the protocol has more than one singleton role"),
    ),
    responses(
        (status = 200, description = "Singleton box + decoded contract state", body = ProtocolStateResponse),
        (status = 400, description = "box_role does not match this protocol's identifying-token role", body = V1Error),
        (status = 404, description = "No protocol with that id, or the protocol has no singleton to resolve", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 500, description = "Registry data bug (bad identifying-token key), or box assembly failed", body = V1Error),
        (status = 503, description = "No unspent box currently holds the singleton NFT (mid-reorg/uninitialized), or extra index syncing/halted", body = V1Error),
    ),
)]
pub async fn protocol_state(
    State(state): State<V1State>,
    Path(protocol_id): Path<String>,
    V1Query(q): V1Query<StateQuery>,
) -> Response {
    let Some(entry) = entry_by_id(&protocol_id) else {
        return v1_error(
            Reason::ProtocolNotFound,
            "no protocol with that id in the registry",
            "GET /api/v1/protocols lists every registered protocol id",
        );
    };
    // The identifying-token matcher for the requested (or first) role.
    let matcher = entry.matchers.iter().find(|m| {
        m.kind == MatchKind::IdentifyingToken
            && q.box_role.as_deref().is_none_or(|r| r == m.box_role)
    });
    let Some(matcher) = matcher else {
        // Distinguish a mismatched `box_role` on a singleton protocol from a
        // true many-instance protocol with no identifying token at all.
        let singleton = entry
            .matchers
            .iter()
            .find(|m| m.kind == MatchKind::IdentifyingToken);
        return match (q.box_role.as_deref(), singleton) {
            (Some(role), Some(m)) => v1_error(
                Reason::InvalidParams,
                "no identifying-token matcher for that box_role",
                format!(
                    "requested box_role `{role}`; this protocol's identifying-token role is `{}`",
                    m.box_role
                ),
            ),
            _ => v1_error(
                Reason::NotASingletonProtocol,
                "this protocol has no identifying-token singleton to resolve",
                "use GET /api/v1/protocols/{id}/boxes for many-instance protocols",
            ),
        };
    };

    let idx = match state.indexer() {
        Ok(i) => i,
        Err(e) => return *e,
    };
    let Some(raw) = parse_id32(matcher.key) else {
        return v1_error(
            Reason::InternalError,
            "registry identifying-token key is not a 32-byte hex id",
            "this is a registry data bug, not a client error",
        );
    };
    let tid = TokenId::from_bytes(raw);
    let boxes = idx.token_unspent_paged(
        &tid,
        IdxPage {
            offset: 0,
            limit: 1,
        },
        SortDir::Desc,
    );
    let Some(b) = boxes.into_iter().next() else {
        return v1_error(
            Reason::StateUnavailable,
            "no unspent box currently holds this protocol's singleton NFT",
            "the singleton may be mid-reorg, or the protocol is uninitialized",
        );
    };
    let best = state.read.status().best_full_block_height;
    let v1box = match v1box_from_indexed_box(state.network, &b, best, true) {
        Ok(v) => v,
        Err(d) => {
            return v1_error(
                Reason::InternalError,
                "failed to assemble the singleton box",
                d,
            )
        }
    };
    let contract = v1box
        .decoded
        .and_then(|d| d.get("contract").cloned())
        .unwrap_or(Value::Null);
    Json(ProtocolStateResponse {
        protocol_id: entry.id,
        box_role: matcher.box_role,
        box_id: v1box.box_id,
        height: v1box.inclusion_height,
        as_of_height: best,
        confirmed: v1box.confirmed,
        contract,
    })
    .into_response()
}
