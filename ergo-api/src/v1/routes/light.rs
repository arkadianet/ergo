//! `light/*` — trustless mobile-sync proofs (`v1-api-design.md` §3.13).
//!
//! A phone wallet syncs against *this* node without trusting it: it verifies
//! PoW + interlink structure itself. Three primitives — a NiPoPoW bootstrap
//! proof (`bootstrap-proof`), a forward header/interlink page to extend a
//! verified suffix (`headers-interlinks`), and a Merkle membership proof
//! (`membership-proof`) — plus a `status` capability advertisement.
//!
//! **Zero new proving logic.** Every route re-skins the already-shipping
//! NiPoPoW prover hooks
//! ([`NodeChainQuery::nipopow_proof`](crate::compat::NodeChainQuery::nipopow_proof),
//! [`nipopow_header_at_height`](crate::compat::NodeChainQuery::nipopow_header_at_height),
//! [`proof_for_tx`](crate::compat::NodeChainQuery::proof_for_tx)) through a
//! snake_case serde layer + the v1 envelope + cost governors. The
//! `membership-proof` handler is Overlap O2: it delegates to the SAME core as
//! `chain/proofs/{id}/transactions/{tx_id}` (see [`super::chain`]).

use utoipa::ToSchema;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::dto::unix_ms_to_iso;
use super::extract::V1Query;
use super::{valid_modifier_id, V1State};
use crate::v1::cursor::{clamp_limit, decode_opt_cursor, encode_cursor, Page};
use crate::v1::error::{v1_error, Reason};
use ergo_rest_json::types::{
    ScalaBatchMerkleProof, ScalaHeader, ScalaNipopowProof, ScalaPopowHeader,
};

/// Hard cap on the NiPoPoW `m` (min-superchain prefix) param — mirrors the
/// frozen compat `MAX_NIPOPOW_M` (`compat/handlers.rs`). `m` is the cost
/// amplifier (~50 KB + ~12 ms/unit), so this is the load-bearing T0 lever.
const MAX_NIPOPOW_M: u32 = 100;
/// Hard cap on the NiPoPoW `k` (suffix / unstable-head) param.
const MAX_NIPOPOW_K: u32 = 100;
/// Default `m` / `k` when a caller omits them (real params are ~6–30).
const DEFAULT_NIPOPOW_M: u32 = 6;
const DEFAULT_NIPOPOW_K: u32 = 6;

/// Response-byte ceiling for `bootstrap-proof` — a secondary governor beyond
/// the `m,k ≤ 100` cap. A proof serializing beyond this answers
/// `413 proof_too_large` rather than stream a multi-MB body.
const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// Default / max page size for `headers-interlinks` (§3.13).
const HEADERS_DEFAULT_LIMIT: u32 = 128;
const HEADERS_MAX_LIMIT: u32 = 512;

// ----- wire DTOs (snake_case mirrors of the camelCase compat proof DTOs) ---

/// One header projected into the light-client glossary shape. A snake_case
/// re-skin of [`ScalaHeader`] carrying the fields a light client checks (PoW
/// `n_bits`, `difficulty`, the `parent_id` link). No consensus bytes are
/// re-encoded — this is a field rename over the already-decoded prover output.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightHeader {
    pub header_id: String,
    pub height: u32,
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
    pub timestamp_iso: String,
    pub n_bits: u64,
    pub difficulty: String,
    pub transactions_root: String,
    pub extension_hash: String,
    pub version: u8,
}

impl LightHeader {
    fn from_scala(h: &ScalaHeader) -> Self {
        LightHeader {
            header_id: h.id.clone(),
            height: h.height,
            parent_id: h.parent_id.clone(),
            timestamp_unix_ms: h.timestamp,
            timestamp_iso: unix_ms_to_iso(h.timestamp),
            n_bits: h.n_bits,
            difficulty: h.difficulty.clone(),
            transactions_root: h.transactions_root.clone(),
            extension_hash: h.extension_hash.clone(),
            version: h.version,
        }
    }
}

/// One index entry of a batch-Merkle interlinks proof.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightBatchIndex {
    pub index: u32,
    pub digest: String,
}

/// One sibling of a batch-Merkle interlinks path. `digest: null` is the
/// odd-trailing empty sibling (the compat encoder serializes it as the empty
/// string; we surface it honestly as `null`). `side` is the lowercase enum.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightBatchElement {
    pub digest: Option<String>,
    pub side: LightSide,
}

#[derive(Debug, Serialize, Clone, Copy, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LightSide {
    Left,
    Right,
}

/// Batch-Merkle proof tying a header's interlinks to its extension digest.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightBatchMerkleProof {
    pub indices: Vec<LightBatchIndex>,
    pub proofs: Vec<LightBatchElement>,
}

impl LightBatchMerkleProof {
    fn from_scala(p: &ScalaBatchMerkleProof) -> Self {
        LightBatchMerkleProof {
            indices: p
                .indices
                .iter()
                .map(|i| LightBatchIndex {
                    index: i.index,
                    digest: i.digest.clone(),
                })
                .collect(),
            proofs: p
                .proofs
                .iter()
                .map(|e| LightBatchElement {
                    // Empty string = the odd-trailing empty sibling → null.
                    digest: if e.digest.is_empty() {
                        None
                    } else {
                        Some(e.digest.clone())
                    },
                    side: if e.side == 0 {
                        LightSide::Left
                    } else {
                        LightSide::Right
                    },
                })
                .collect(),
        }
    }
}

/// A header + its interlinks vector + the batch-Merkle proof binding them.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightPopowHeader {
    pub header: LightHeader,
    /// Base16 header ids, genesis first (KMZ17 reverse-level order).
    pub interlinks: Vec<String>,
    pub interlinks_proof: LightBatchMerkleProof,
}

impl LightPopowHeader {
    fn from_scala(h: &ScalaPopowHeader) -> Self {
        LightPopowHeader {
            header: LightHeader::from_scala(&h.header),
            interlinks: h.interlinks.clone(),
            interlinks_proof: LightBatchMerkleProof::from_scala(&h.interlinks_proof),
        }
    }
}

/// Echo of the resolved proof parameters (so the client knows what it got).
#[derive(Debug, Serialize, ToSchema)]
pub struct LightProofParams {
    pub m: u32,
    pub k: u32,
    pub anchor_header_id: Option<String>,
}

/// The `bootstrap-proof` body — a snake_case re-skin of [`ScalaNipopowProof`].
/// `prefix`/`suffix_head`/`suffix` mirror the compat `prefix`/`suffixHead`/
/// `suffixTail`, renamed for the light-client glossary.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightPopowProof {
    pub prefix: Vec<LightPopowHeader>,
    pub suffix_head: LightPopowHeader,
    pub suffix: Vec<LightHeader>,
    pub params: LightProofParams,
}

impl LightPopowProof {
    fn from_scala(p: &ScalaNipopowProof, anchor: Option<String>) -> Self {
        LightPopowProof {
            prefix: p.prefix.iter().map(LightPopowHeader::from_scala).collect(),
            suffix_head: LightPopowHeader::from_scala(&p.suffix_head),
            suffix: p.suffix_tail.iter().map(LightHeader::from_scala).collect(),
            params: LightProofParams {
                m: p.m,
                k: p.k,
                anchor_header_id: anchor,
            },
        }
    }
}

// ----- GET /light/bootstrap-proof -----------------------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct BootstrapQuery {
    #[serde(default)]
    m: Option<u32>,
    #[serde(default)]
    k: Option<u32>,
    /// Anchor the proof at a specific header (default: tip).
    #[serde(default)]
    at: Option<String>,
}

/// `GET /api/v1/light/bootstrap-proof` — the NiPoPoW suffix proof for
/// from-scratch trustless sync. Heaviest T0 read in the group: `m` is capped,
/// and the serialized proof is subject to a response-byte ceiling.
pub async fn bootstrap_proof(
    State(state): State<V1State>,
    V1Query(q): V1Query<BootstrapQuery>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let m = q.m.unwrap_or(DEFAULT_NIPOPOW_M);
    let k = q.k.unwrap_or(DEFAULT_NIPOPOW_K);
    if !(1..=MAX_NIPOPOW_M).contains(&m) {
        return v1_error(
            Reason::InvalidParams,
            "m out of range",
            format!("m must be 1..={MAX_NIPOPOW_M}"),
        );
    }
    if !(1..=MAX_NIPOPOW_K).contains(&k) {
        return v1_error(
            Reason::InvalidParams,
            "k out of range",
            format!("k must be 1..={MAX_NIPOPOW_K}"),
        );
    }
    let anchor = match q.at {
        Some(ref at) => {
            if !valid_modifier_id(at) {
                return v1_error(
                    Reason::InvalidHex,
                    "at is not a 64-character hex header id",
                    "supply an unprefixed hex header id, or omit to anchor at the tip",
                );
            }
            Some(at.clone())
        }
        None => None,
    };
    match chain.nipopow_proof(m, k, anchor.as_deref()) {
        Ok(proof) => {
            let dto = LightPopowProof::from_scala(&proof, anchor);
            // Serialize once to enforce the response-byte ceiling before the
            // body is handed to the client (§3.13 governor #2).
            match serde_json::to_vec(&dto) {
                Ok(bytes) if bytes.len() > MAX_PROOF_BYTES => v1_error(
                    Reason::ProofTooLarge,
                    "the proof exceeds the response-byte ceiling",
                    format!(
                        "serialized {} bytes > {} cap; request a smaller m/k",
                        bytes.len(),
                        MAX_PROOF_BYTES
                    ),
                ),
                Ok(bytes) => (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    bytes,
                )
                    .into_response(),
                Err(_) => v1_error(
                    Reason::InternalError,
                    "failed to serialize the proof",
                    "the prover returned a proof that could not be encoded",
                ),
            }
        }
        // The prover default `Err` path = extension/interlink data not
        // retained (a pruned node cannot build the proof).
        Err(detail) => v1_error(
            Reason::NipopowUnavailable,
            "this node cannot build a NiPoPoW proof",
            detail,
        ),
    }
}

// ----- GET /light/headers-interlinks --------------------------------------

/// Opaque forward cursor for `headers-interlinks`: the next height to serve.
/// Genuinely stable under a growing chain (never an offset).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct NextHeightCursor {
    next_height: u32,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct HeadersQuery {
    #[serde(default)]
    from_height: Option<u32>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    cursor: Option<String>,
}

/// The collection envelope for `headers-interlinks`.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightHeadersPage {
    pub items: Vec<LightPopowHeader>,
    pub page: Page,
}

/// `GET /api/v1/light/headers-interlinks` — cursor-paginated headers each
/// carrying its interlink vector + batch-Merkle proof, so a verified light
/// client extends its suffix forward without re-bootstrapping.
pub async fn headers_interlinks(
    State(state): State<V1State>,
    V1Query(q): V1Query<HeadersQuery>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    // Cursor supersedes from_height; one of them is required.
    let start = match decode_opt_cursor::<NextHeightCursor>(q.cursor.as_deref()) {
        Ok(Some(c)) => c.next_height,
        Ok(None) => match q.from_height {
            Some(h) => h,
            None => {
                return v1_error(
                    Reason::InvalidParams,
                    "from_height is required",
                    "supply ?from_height=<u32> (or a cursor from a prior page)",
                )
            }
        },
        Err(e) => return *e,
    };
    let limit = clamp_limit(q.limit, HEADERS_DEFAULT_LIMIT, HEADERS_MAX_LIMIT);

    // A height past the tip is not an error — it is simply an empty tail.
    let tip = state.read.sync().best_full_block_height;
    if start > tip {
        return Json(LightHeadersPage {
            items: Vec::new(),
            page: Page {
                limit,
                next_cursor: None,
                has_more: false,
            },
        })
        .into_response();
    }

    let end = start.saturating_add(limit).min(tip.saturating_add(1));
    let mut items: Vec<LightPopowHeader> = Vec::new();
    let mut last_height = start;
    for h in start..end {
        match chain.nipopow_header_at_height(h) {
            Some(ph) => {
                items.push(LightPopowHeader::from_scala(&ph));
                last_height = h;
            }
            // A miss at a height <= tip means the extension/interlink data is
            // not retained on this node — honest 409, never a silent gap.
            None => {
                if items.is_empty() {
                    return v1_error(
                        Reason::NipopowUnavailable,
                        "interlink data is not retained on this node",
                        "a pruned node cannot serve popow headers",
                    );
                }
                break;
            }
        }
    }

    let has_more = last_height < tip;
    let next_cursor = has_more.then(|| {
        encode_cursor(&NextHeightCursor {
            next_height: last_height.saturating_add(1),
        })
    });
    Json(LightHeadersPage {
        items,
        page: Page {
            limit,
            next_cursor,
            has_more,
        },
    })
    .into_response()
}

// ----- GET /light/membership-proof (O2 dual mount) ------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct MembershipQuery {
    #[serde(default)]
    header_id: Option<String>,
    #[serde(default)]
    tx_id: Option<String>,
}

/// `GET /api/v1/light/membership-proof?header_id&tx_id` — the trustless
/// "did my payment land" primitive. **Overlap O2:** delegates to the SAME
/// membership-proof core as `chain/proofs/{header_id}/transactions/{tx_id}`
/// ([`super::chain::merkle_membership_proof`]) — identical proof semantics,
/// one implementation; this mount only differs in reading the two ids from
/// the query string instead of the path.
pub async fn membership_proof(
    State(state): State<V1State>,
    V1Query(q): V1Query<MembershipQuery>,
) -> Response {
    let chain = match state.chain() {
        Ok(c) => c,
        Err(e) => return *e,
    };
    let Some(header_id) = q.header_id else {
        return v1_error(
            Reason::InvalidParams,
            "header_id is required",
            "supply ?header_id=<hex>&tx_id=<hex>",
        );
    };
    let Some(tx_id) = q.tx_id else {
        return v1_error(
            Reason::InvalidParams,
            "tx_id is required",
            "supply ?header_id=<hex>&tx_id=<hex>",
        );
    };
    super::chain::merkle_membership_proof(chain.as_ref(), &header_id, &tx_id)
}

// ----- GET /light/status --------------------------------------------------

/// The `light/status` capability advertisement — never a 404. A wallet reads
/// this to pick a node that can serve it trustless-sync proofs.
#[derive(Debug, Serialize, ToSchema)]
pub struct LightStatus {
    pub nipopow_bootstrap: bool,
    pub serves_bootstrap_proof: bool,
    pub serves_membership_proof: bool,
    pub interlinks_available: bool,
    pub max_proof_m: u32,
    pub max_proof_k: u32,
}

/// `GET /api/v1/light/status`. `serves_*` are derived from whether the node
/// wires a chain reader at all (the prover hooks live on it); a node without
/// one honestly advertises `false` rather than 404.
pub async fn status(State(state): State<V1State>) -> Response {
    let identity = state.read.identity();
    let has_chain = state.chain.is_some();
    Json(LightStatus {
        nipopow_bootstrap: identity.nipopow_bootstrap,
        serves_bootstrap_proof: has_chain,
        serves_membership_proof: has_chain,
        interlinks_available: has_chain,
        max_proof_m: MAX_NIPOPOW_M,
        max_proof_k: MAX_NIPOPOW_K,
    })
    .into_response()
}
