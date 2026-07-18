//! v1 box / token / address-balance DTOs and their indexer
//! projections (`v1box_from_indexed_response`, `token_from_dto`,
//! `address_tx_summary_from_indexed`).

use std::collections::BTreeMap;
use utoipa::ToSchema;

use ergo_indexer_types::types::IndexedErgoBox;
use ergo_indexer_types::IndexedTokenDto;
use ergo_ser::address::NetworkPrefix;
use serde::Serialize;

use super::common::{confirmations, unix_ms_to_iso};
use crate::blockchain::{
    build_indexed_box_response, IndexedErgoBoxResponse, IndexedErgoTransactionResponse,
};

// ----- transactions + boxes ----------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct V1Asset {
    pub token_id: String,
    pub amount: String,
}

/// The v1 box object. Every box-returning surface
/// shares this shape. `box_id`/`confirmed` are always present; the remaining
/// fields are `Option` because a box can appear in three provenance contexts
/// with different available metadata:
///
/// * fully-indexed (confirmed tx read) — all fields populated;
/// * block-embedded output (from a block's own bytes) — no `global_index` /
///   `spent_by`;
/// * an unresolved input of an unconfirmed tx — only `box_id` is known, the
///   rest are `null` (honest "unknown", never fabricated).
///
/// The `boxes/*` group owns the final canonical box shape (coherence Part B /
/// coordination flag #2); this is the transactions-group projection it must
/// match when it lands.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1Box {
    pub box_id: String,
    pub value: Option<String>,
    pub ergo_tree: Option<String>,
    pub address: Option<String>,
    pub assets: Option<Vec<V1Asset>>,
    pub registers: Option<BTreeMap<String, String>>,
    pub creation_height: Option<u32>,
    pub tx_id: Option<String>,
    pub output_index: Option<u16>,
    pub spent_by: Option<String>,
    pub confirmed: bool,
    pub inclusion_height: Option<i32>,
    pub confirmations: Option<i64>,
    pub global_index: Option<i64>,
    /// Reserved: populated only on input boxes carrying a proof; `null` here.
    pub spending_proof: Option<serde_json::Value>,
    /// Semantic decode: **omitted** unless `?decode=true`, `null` when
    /// requested but the semantic-decode registry (a later group) matched no
    /// contract. The registry owns the populated object's shape; this group
    /// owns the toggle + presence contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<serde_json::Value>,
}

// ----- boxes / tokens / addresses ----------------------------------

/// The v1 token object. `box_id` is the *minting*
/// box; `emission_amount` is the string-restrung ever-minted figure.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1Token {
    pub token_id: String,
    pub box_id: String,
    pub emission_amount: String,
    pub name: String,
    pub description: String,
    pub decimals: i32,
}

/// One row of `tokens/{token_id}/holders`.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1TokenHolder {
    pub address: String,
    pub amount: String,
}

/// Whole-result scalars for `tokens/{token_id}/holders`, carried under the
/// collection `meta` (Part D). `scan_capped` is set honestly when the token's
/// total unspent-box count exceeds the bounded scan cap — an approximate
/// ranking, never a silently-partial one.
#[derive(Debug, Serialize, ToSchema)]
pub struct HoldersMeta {
    pub as_of_height: u64,
    pub scanned_boxes: u64,
    pub scan_capped: bool,
}

/// `tokens/{token_id}/stats` — bare object (not a collection). `box_count` is
/// exact/cheap; `circulating_supply` / `holder_count` come from the same
/// bounded scan as `/holders` and inherit its `scan_capped` honesty flag.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1TokenStats {
    pub token_id: String,
    pub emission_amount: String,
    pub circulating_supply: String,
    pub holder_count: u64,
    pub box_count: u64,
    pub scan_capped: bool,
}

/// One confirmed/unconfirmed side of an `addresses/{address}/balance`. The
/// nanoERG leaf is `value` (glossary C.2), a decimal string.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1BalanceEntry {
    pub value: String,
    pub assets: Vec<V1Asset>,
}

/// `addresses/{address}/balance`. `unconfirmed` is strictly additive (Scala
/// parity): pool outputs paying the address add here; pool spends do NOT
/// subtract from `confirmed`.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1Balance {
    pub address: String,
    pub confirmed: V1BalanceEntry,
    pub unconfirmed: V1BalanceEntry,
}

/// A deliberately smaller tx projection for `addresses/{address}/transactions`
/// — glossary-named (`header_id`, `inclusion_height`, `size_bytes`,
/// `input_count`/`output_count`, coherence Part B/C), projected DOWN from
/// [`IndexedErgoTransactionResponse`] so the confirmation math never re-derives
/// (a second drift site).
#[derive(Debug, Serialize, ToSchema)]
pub struct V1AddressTxSummary {
    pub tx_id: String,
    pub header_id: String,
    pub inclusion_height: i32,
    pub confirmations: i64,
    pub timestamp_unix_ms: u64,
    pub timestamp_iso: String,
    pub size_bytes: u32,
    pub input_count: u32,
    pub output_count: u32,
    pub global_index: i64,
}

// ----- box / token / tx-summary projections -------------------------------

/// Map an already-built indexer box response into the canonical [`V1Box`].
///
/// Detects the pool-overlay sentinel (`inclusion_height == 0`, unreachable for
/// a confirmed box since chain heights start at 1) and renders it as an
/// unconfirmed box with `confirmed = false` and null on-chain metadata
/// (`inclusion_height` / `confirmations` / `global_index`). `decode`
/// wires the `?decode=true` toggle: `Some(null)` when requested (registry is a
/// later group), field omitted otherwise. `spending_proof` stays `null` here —
/// a reserved field the box-read surface does not yet populate.
pub(crate) fn v1box_from_indexed_response(
    resp: IndexedErgoBoxResponse,
    best_full_block_height: u32,
    decode: bool,
) -> V1Box {
    let confirmed = resp.inclusion_height >= 1;
    // The shared semantic-decode seam. Built from the box body BEFORE the
    // assets are consumed below. `None` (field omitted) unless `?decode=true`;
    // when requested, `decode_box` yields `{registers, contract}` with an honest
    // `contract: null` for an unrecognized box (never fabricated state).
    let decoded = decode.then(|| {
        let tokens: Vec<(String, u64)> = resp
            .assets
            .iter()
            .map(|a| (a.token_id.clone(), a.amount))
            .collect();
        crate::v1::decode::decode_box(
            &resp.ergo_tree,
            resp.value,
            &tokens,
            &resp.additional_registers,
        )
    });
    let assets = resp
        .assets
        .into_iter()
        .map(|a| V1Asset {
            token_id: a.token_id,
            amount: a.amount.to_string(),
        })
        .collect();
    V1Box {
        box_id: resp.box_id,
        value: Some(resp.value.to_string()),
        ergo_tree: Some(resp.ergo_tree),
        address: Some(resp.address),
        assets: Some(assets),
        registers: Some(resp.additional_registers),
        creation_height: Some(resp.creation_height),
        tx_id: Some(resp.transaction_id),
        output_index: Some(resp.index),
        spent_by: resp.spent_transaction_id,
        confirmed,
        inclusion_height: confirmed.then_some(resp.inclusion_height),
        confirmations: confirmed
            .then(|| confirmations(best_full_block_height, resp.inclusion_height)),
        global_index: confirmed.then_some(resp.global_index),
        spending_proof: None,
        decoded,
    }
}

/// Project an indexer box record straight into the canonical [`V1Box`]
/// (builds the intermediate response, then [`v1box_from_indexed_response`]).
pub(crate) fn v1box_from_indexed_box(
    network: NetworkPrefix,
    b: &IndexedErgoBox,
    best_full_block_height: u32,
    decode: bool,
) -> Result<V1Box, String> {
    let resp = build_indexed_box_response(network, b)?;
    Ok(v1box_from_indexed_response(
        resp,
        best_full_block_height,
        decode,
    ))
}

/// Restring an [`IndexedTokenDto`] into the v1 token object.
pub(crate) fn token_from_dto(t: &IndexedTokenDto) -> V1Token {
    V1Token {
        token_id: hex::encode(t.token_id.as_bytes()),
        box_id: hex::encode(t.creating_box_id.as_bytes()),
        emission_amount: t.emission_amount.to_string(),
        name: t.name.clone(),
        description: t.description.clone(),
        decimals: t.decimals,
    }
}

/// Project a fully-built [`IndexedErgoTransactionResponse`] DOWN to the small
/// address-history summary. Reuses the builder's confirmation math verbatim.
pub(crate) fn address_tx_summary_from_indexed(
    resp: &IndexedErgoTransactionResponse,
) -> V1AddressTxSummary {
    V1AddressTxSummary {
        tx_id: resp.id.clone(),
        header_id: resp.block_id.clone(),
        inclusion_height: resp.inclusion_height,
        confirmations: i64::from(resp.num_confirmations),
        timestamp_unix_ms: resp.timestamp,
        timestamp_iso: unix_ms_to_iso(resp.timestamp),
        size_bytes: resp.size.max(0) as u32,
        input_count: resp.inputs.len() as u32,
        output_count: resp.outputs.len() as u32,
        global_index: resp.global_index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::blockchain::{AssetEntry, IndexedErgoBoxResponse};

    // ----- helpers -----

    fn indexed_box_response(inclusion_height: i32) -> IndexedErgoBoxResponse {
        let mut regs = BTreeMap::new();
        regs.insert("R4".to_string(), "0e0454455354".to_string());
        IndexedErgoBoxResponse {
            box_id: "6a2d".to_string(),
            value: 80_000_000_000,
            ergo_tree: "0008cd02".to_string(),
            assets: vec![AssetEntry {
                token_id: "aa".to_string(),
                amount: 1000,
            }],
            creation_height: 431_358,
            additional_registers: regs,
            transaction_id: "16b2".to_string(),
            index: 0,
            address: "9fADDR".to_string(),
            spent_transaction_id: None,
            inclusion_height,
            spending_proof: None,
            global_index: 3_454_590,
        }
    }

    /// The canonical V1Box key set — the ONE box shape every
    /// box-returning v1 surface converges on. Both the transactions group (which
    /// defined `V1Box`) and this boxes group serialize the identical struct;
    /// this pins the glossary field names so neither can drift.
    const V1_BOX_KEYS: &[&str] = &[
        "box_id",
        "value",
        "ergo_tree",
        "address",
        "assets",
        "registers",
        "creation_height",
        "tx_id",
        "output_index",
        "spent_by",
        "confirmed",
        "inclusion_height",
        "confirmations",
        "global_index",
        "spending_proof",
    ];

    // ----- happy path -----

    #[test]
    fn v1box_confirmed_has_canonical_glossary_field_names() {
        let v = v1box_from_indexed_response(indexed_box_response(431_360), 431_772, false);
        let json = serde_json::to_value(&v).unwrap();
        for key in V1_BOX_KEYS {
            assert!(
                json.get(key).is_some(),
                "confirmed box missing {key}: {json}"
            );
        }
        // Value discipline: nanoERG leaf `value` is a string; amounts too.
        assert_eq!(json["value"], serde_json::json!("80000000000"));
        assert_eq!(json["assets"][0]["amount"], serde_json::json!("1000"));
        assert_eq!(json["confirmed"], serde_json::json!(true));
        assert_eq!(json["inclusion_height"].as_i64(), Some(431_360));
        assert_eq!(json["confirmations"].as_i64(), Some(412));
        assert_eq!(json["global_index"].as_i64(), Some(3_454_590));
        // No camelCase / compat leakage.
        assert!(json.get("boxId").is_none());
        assert!(json.get("additionalRegisters").is_none());
        assert!(json.get("transactionId").is_none());
        // decode not requested → `decoded` omitted.
        assert!(json.get("decoded").is_none());
    }

    #[test]
    fn v1box_pool_sentinel_renders_unconfirmed_with_null_metadata() {
        // inclusion_height == 0 is the pool-overlay sentinel: the box is
        // unconfirmed, so its on-chain metadata is honest `null`.
        let v = v1box_from_indexed_response(indexed_box_response(0), 431_772, false);
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["confirmed"], serde_json::json!(false));
        assert!(json["inclusion_height"].is_null());
        assert!(json["confirmations"].is_null());
        assert!(json["global_index"].is_null());
        // The box body is still present.
        assert_eq!(json["value"], serde_json::json!("80000000000"));
    }

    #[test]
    fn v1box_decode_toggle_populates_registers_and_null_contract_when_unmatched() {
        let v = v1box_from_indexed_response(indexed_box_response(1), 1, true);
        let json = serde_json::to_value(&v).unwrap();
        // `?decode=true` → `decoded` present as `{registers, contract}`.
        assert!(json.get("decoded").is_some());
        // The box carries no known protocol NFT and a non-protocol tree, so the
        // contract is honestly `null` — but the typed registers are still there
        // (a raw box is never *less* useful with decode=true).
        assert!(json["decoded"]["contract"].is_null());
        assert_eq!(json["decoded"]["registers"]["R4"]["type"], "coll[byte]");
        assert_eq!(json["decoded"]["registers"]["R4"]["value"], "54455354");
    }

    #[test]
    fn v1token_restrings_emission_amount_and_renames_box_id() {
        let dto = IndexedTokenDto {
            token_id: ergo_indexer_types::TokenId::from_bytes([0xab; 32]),
            creating_box_id: ergo_indexer_types::BoxId::from_bytes([0xcd; 32]),
            emission_amount: 1_000_000,
            name: "SigUSD".to_string(),
            description: "d".to_string(),
            decimals: 2,
        };
        let json = serde_json::to_value(token_from_dto(&dto)).unwrap();
        for key in [
            "token_id",
            "box_id",
            "emission_amount",
            "name",
            "description",
            "decimals",
        ] {
            assert!(json.get(key).is_some(), "token missing {key}");
        }
        assert_eq!(json["emission_amount"], serde_json::json!("1000000"));
        assert!(json.get("boxId").is_none());
        assert!(json.get("emissionAmount").is_none());
    }
}
