//! Shared v1 wire DTOs + projection helpers for the `chain/*` and
//! `transactions/*` route groups (`v1-api-design.md` §3.5–§3.6, §3.7 box).
//!
//! **This is the first v1 route group, so the shapes here are the template
//! every later group copies.** Field names are the §1.1 glossary verbatim
//! (`tx_id`, `header_id`, `value` as string, `size_bytes`, `inclusion_height`,
//! …), timestamps follow §1.2 (`*_unix_ms` int + `*_iso` mirror), amounts that
//! can exceed 2^53 are strings, and enums are lowercase strings (`"left"` /
//! `"right"`), never magic ints.
//!
//! Provenance: these are glossary-renamed projections of the frozen Scala-compat
//! DTOs (`ergo_rest_json::types::*`) returned by [`crate::compat::NodeChainQuery`]
//! and of `IndexedErgoBoxResponse` (`crate::blockchain`). The compat shapes stay
//! camelCase and frozen; v1 wraps, never mutates them.

use std::collections::BTreeMap;

use ergo_rest_json::types::{
    ScalaAdProofs, ScalaBlockSection, ScalaExtension, ScalaFullBlock, ScalaHeader, ScalaInput,
    ScalaOutput, ScalaTransaction,
};
use ergo_ser::address::{encode_address_from_tree_bytes, encode_p2pk_from_pubkey, NetworkPrefix};
use serde::Serialize;

use crate::v1::cursor::Page;

// ----- timestamps (§1.2) --------------------------------------------------

/// Render a unix-milliseconds instant as the `<name>_iso` ISO-8601 mirror
/// required by §1.2 (`YYYY-MM-DDTHH:MM:SS.sssZ`, always UTC/`Z`).
///
/// Self-contained (no `chrono`/`time` dependency): the calendar date is
/// derived with Howard Hinnant's `civil_from_days` algorithm, which is exact
/// for all in-range instants. Pinned by oracle tests against well-known unix
/// epochs (0, 10^9 s, 1.6×10^9 s).
pub(crate) fn unix_ms_to_iso(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

// ----- collections envelope (§1.3) ----------------------------------------

/// A v1 collection: `{items, page}` (`v1-api-design.md` §1.3). Uniform for
/// every list, even single-page ones (a block's tx list, header-ids at a
/// height): those carry `page.has_more = false`, `page.next_cursor = null`.
#[derive(Debug, Serialize)]
pub struct Collection<T> {
    pub items: Vec<T>,
    pub page: Page,
}

impl<T> Collection<T> {
    /// A bounded, single-page collection (`has_more = false`), for lists that
    /// never span pages (block transactions, header-ids at a height).
    pub fn single_page(items: Vec<T>) -> Self {
        let limit = items.len() as u32;
        Collection {
            items,
            page: Page {
                limit,
                next_cursor: None,
                has_more: false,
            },
        }
    }
}

// ----- header / block (§3.5) ----------------------------------------------

/// Glossary-renamed header fields shared by the standalone header object,
/// the full block, and a block summary (`serde(flatten)`ed into each).
#[derive(Debug, Serialize)]
pub struct V1HeaderBase {
    pub header_id: String,
    pub height: u32,
    pub parent_id: String,
    pub timestamp_unix_ms: u64,
    pub timestamp_iso: String,
    pub version: u8,
    /// Decimal string (may exceed 2^53).
    pub difficulty: String,
    pub n_bits: u64,
    /// Fixed-width hex vote triple, e.g. `"000000"`.
    pub votes: String,
    pub state_root: String,
    pub ad_proofs_root: String,
    pub transactions_root: String,
    pub extension_id: String,
    pub extension_hash: String,
    /// Miner public key (frozen `pk` wire name lives only on the mining
    /// `WorkMessage`; here the glossary name is `miner_pk`).
    pub miner_pk: String,
    /// P2PK address derived from `miner_pk`; `null` if the pubkey is malformed.
    pub miner_address: Option<String>,
}

/// Standalone header object (`GET /chain/headers/{header_id}` etc.).
#[derive(Debug, Serialize)]
pub struct V1Header {
    #[serde(flatten)]
    pub base: V1HeaderBase,
    pub size_bytes: u32,
}

/// One item of the `GET /chain/blocks` list — a block summary.
#[derive(Debug, Serialize)]
pub struct V1BlockSummary {
    #[serde(flatten)]
    pub base: V1HeaderBase,
    pub size_bytes: u32,
    pub transaction_count: u32,
    /// First-deliverer peer — only known inside the near-tip live ring;
    /// `null` for any block outside it (documented capability gap, §3.5).
    pub delivered_by: Option<String>,
}

/// Full block (`GET /chain/blocks/{header_id}`).
#[derive(Debug, Serialize)]
pub struct V1Block {
    #[serde(flatten)]
    pub base: V1HeaderBase,
    pub size_bytes: u32,
    pub transactions: Vec<V1BlockTx>,
    pub extension: V1Extension,
    /// `null` in UTXO / pruned mode (block exists, section doesn't).
    pub ad_proofs: Option<V1AdProofs>,
}

#[derive(Debug, Serialize)]
pub struct V1Extension {
    pub digest: String,
    pub fields: Vec<[String; 2]>,
}

#[derive(Debug, Serialize)]
pub struct V1AdProofs {
    pub proof_bytes: String,
    pub digest: String,
}

/// `GET /chain/proofs/{header_id}` — the block's AD-proofs section.
#[derive(Debug, Serialize)]
pub struct V1BlockAdProofs {
    pub header_id: String,
    pub proof_bytes: String,
    pub digest: String,
    pub size_bytes: u32,
}

/// `GET /chain/modifiers/{modifier_id}` — v1 adds the explicit `kind`
/// discriminant the untagged Scala `BlockSection` lacks (§3.5).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum V1Modifier {
    Header(Box<V1Header>),
    BlockTransactions(V1BlockTransactions),
    Extension(V1Extension),
    AdProofs(V1BlockAdProofs),
}

/// The block-transactions section as a modifier `data` payload.
#[derive(Debug, Serialize)]
pub struct V1BlockTransactions {
    pub header_id: String,
    pub transactions: Vec<V1BlockTx>,
    pub size_bytes: u32,
}

/// `GET /chain/proofs/{header_id}/transactions/{tx_id}` — Merkle membership
/// proof. Side byte `0/1` rendered as `"left"/"right"` strings (§3.5).
#[derive(Debug, Serialize)]
pub struct V1MerkleProof {
    pub tx_id: String,
    pub levels: Vec<V1MerkleLevel>,
}

#[derive(Debug, Serialize)]
pub struct V1MerkleLevel {
    pub sibling: String,
    pub side: MerkleSide,
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum MerkleSide {
    Left,
    Right,
}

// ----- transactions + boxes (§3.6, §3.7) ----------------------------------

#[derive(Debug, Serialize)]
pub struct V1Asset {
    pub token_id: String,
    pub amount: String,
}

/// The v1 box object (`v1-api-design.md` §3.7). Every box-returning surface
/// shares this shape. `box_id`/`confirmed` are always present; the remaining
/// fields are `Option` because a box can appear in three provenance contexts
/// with different available metadata:
///
/// * fully-indexed (confirmed tx read) — all fields populated;
/// * block-embedded output (from a block's own bytes) — no `global_index` /
///   `spent_by`;
/// * an unresolved input of an unconfirmed tx — only `box_id` is known, the
///   rest are `null` (honest "unknown", never fabricated — §1.1).
///
/// The `boxes/*` group owns the final canonical box shape (coherence Part B /
/// coordination flag #2); this is the transactions-group projection it must
/// match when it lands.
#[derive(Debug, Serialize)]
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
    /// Semantic decode — owned by the semantic-decode group; `null` until a
    /// `?decode=true` toggle group lands (§3.7).
    pub decoded: Option<serde_json::Value>,
}

/// Spending-proof reference on a block-embedded transaction input.
#[derive(Debug, Serialize)]
pub struct V1SpendingProof {
    pub proof_bytes: String,
    pub extension: BTreeMap<String, String>,
}

/// A block-embedded transaction input — a *reference* to a spent box, not a
/// resolved box (the block does not carry the spent box's body).
#[derive(Debug, Serialize)]
pub struct V1SpendInput {
    pub box_id: String,
    pub spending_proof: V1SpendingProof,
}

/// A transaction as embedded in a block (`GET /chain/blocks/*`): inputs are
/// spend-references, outputs are the block's own output boxes.
#[derive(Debug, Serialize)]
pub struct V1BlockTx {
    pub tx_id: String,
    pub inputs: Vec<V1SpendInput>,
    pub data_inputs: Vec<String>,
    pub outputs: Vec<V1Box>,
    pub size_bytes: u32,
}

/// A single transaction read (`GET /api/v1/transactions/{tx_id}`): inputs and
/// outputs are resolved box objects; on-chain metadata is `null` when the tx
/// is still in the mempool (`confirmed = false`).
#[derive(Debug, Serialize)]
pub struct V1Tx {
    pub tx_id: String,
    pub confirmed: bool,
    pub inclusion_height: Option<i32>,
    pub confirmations: Option<i64>,
    pub header_id: Option<String>,
    pub timestamp_unix_ms: Option<u64>,
    pub timestamp_iso: Option<String>,
    pub index_in_block: Option<i32>,
    pub global_index: Option<i64>,
    pub size_bytes: u32,
    /// Sum of output values paying the fee proposition (output-side, so
    /// computable even with unresolved inputs). Decimal string.
    pub fee: String,
    pub inputs: Vec<V1Box>,
    pub data_inputs: Vec<String>,
    pub outputs: Vec<V1Box>,
}

// ----- projections --------------------------------------------------------

/// Blocks-above confirmation count: `best - inclusion`, floored at 0. Matches
/// the Scala `IndexedErgoTransaction` mirror (`blockchain/transactions.rs`).
pub(crate) fn confirmations(best_full_block_height: u32, inclusion_height: i32) -> i64 {
    (i64::from(best_full_block_height) - i64::from(inclusion_height)).max(0)
}

fn miner_address(network: NetworkPrefix, miner_pk_hex: &str) -> Option<String> {
    hex::decode(miner_pk_hex)
        .ok()
        .and_then(|b| encode_p2pk_from_pubkey(network, &b).ok())
}

/// Project a Scala header into the shared glossary header base.
pub(crate) fn header_base(network: NetworkPrefix, h: &ScalaHeader) -> V1HeaderBase {
    let miner_pk = h.pow_solutions.pk.clone();
    let miner_address = miner_address(network, &miner_pk);
    V1HeaderBase {
        header_id: h.id.clone(),
        height: h.height,
        parent_id: h.parent_id.clone(),
        timestamp_unix_ms: h.timestamp,
        timestamp_iso: unix_ms_to_iso(h.timestamp),
        version: h.version,
        difficulty: h.difficulty.clone(),
        n_bits: h.n_bits,
        votes: h.votes.clone(),
        state_root: h.state_root.clone(),
        ad_proofs_root: h.ad_proofs_root.clone(),
        transactions_root: h.transactions_root.clone(),
        extension_id: h.extension_id.clone(),
        extension_hash: h.extension_hash.clone(),
        miner_pk,
        miner_address,
    }
}

pub(crate) fn header_from_scala(network: NetworkPrefix, h: &ScalaHeader) -> V1Header {
    V1Header {
        base: header_base(network, h),
        size_bytes: h.size,
    }
}

fn extension_from_scala(e: &ScalaExtension) -> V1Extension {
    V1Extension {
        digest: e.digest.clone(),
        fields: e.fields.clone(),
    }
}

fn ad_proofs_from_scala(p: &ScalaAdProofs) -> V1AdProofs {
    V1AdProofs {
        proof_bytes: p.proof_bytes.clone(),
        digest: p.digest.clone(),
    }
}

/// Project a Scala block output box into the shared v1 box shape. Block
/// outputs are confirmed-in-block but carry no indexer metadata
/// (`global_index` / `spent_by` are `null`); `inclusion_height` /
/// `confirmations` are set when the block height is known.
fn block_output_box(
    network: NetworkPrefix,
    out: &ScalaOutput,
    block_height: Option<u32>,
    best_full_block_height: u32,
) -> V1Box {
    let address =
        encode_address_from_tree_bytes(network, &hex::decode(&out.ergo_tree).unwrap_or_default())
            .ok();
    let assets = out
        .assets
        .iter()
        .map(|a| V1Asset {
            token_id: a.token_id.clone(),
            amount: a.amount.to_string(),
        })
        .collect();
    let inclusion_height = block_height.map(|h| h as i32);
    let confirmations = inclusion_height.map(|h| confirmations(best_full_block_height, h));
    V1Box {
        box_id: out.box_id.clone(),
        value: Some(out.value.to_string()),
        ergo_tree: Some(out.ergo_tree.clone()),
        address,
        assets: Some(assets),
        registers: Some(out.additional_registers.clone()),
        creation_height: Some(out.creation_height),
        tx_id: Some(out.transaction_id.clone()),
        output_index: Some(out.index),
        spent_by: None,
        confirmed: true,
        inclusion_height,
        confirmations,
        global_index: None,
        spending_proof: None,
        decoded: None,
    }
}

fn spend_input_from_scala(i: &ScalaInput) -> V1SpendInput {
    V1SpendInput {
        box_id: i.box_id.clone(),
        spending_proof: V1SpendingProof {
            proof_bytes: i.spending_proof.proof_bytes.clone(),
            extension: i
                .spending_proof
                .extension
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        },
    }
}

/// Project a Scala block transaction into the block-embedded tx shape.
pub(crate) fn block_tx_from_scala(
    network: NetworkPrefix,
    tx: &ScalaTransaction,
    block_height: Option<u32>,
    best_full_block_height: u32,
) -> V1BlockTx {
    V1BlockTx {
        tx_id: tx.id.clone(),
        inputs: tx.inputs.iter().map(spend_input_from_scala).collect(),
        data_inputs: tx.data_inputs.iter().map(|d| d.box_id.clone()).collect(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| block_output_box(network, o, block_height, best_full_block_height))
            .collect(),
        size_bytes: tx.size,
    }
}

/// Project a whole Scala full block into the v1 block object.
pub(crate) fn block_from_scala(
    network: NetworkPrefix,
    fb: &ScalaFullBlock,
    best_full_block_height: u32,
) -> V1Block {
    let height = fb.header.height;
    V1Block {
        base: header_base(network, &fb.header),
        size_bytes: fb.size,
        transactions: fb
            .block_transactions
            .transactions
            .iter()
            .map(|tx| block_tx_from_scala(network, tx, Some(height), best_full_block_height))
            .collect(),
        extension: extension_from_scala(&fb.extension),
        ad_proofs: fb.ad_proofs.as_ref().map(ad_proofs_from_scala),
    }
}

/// Project a Scala full block into the `GET /chain/blocks` summary item.
pub(crate) fn block_summary_from_scala(
    network: NetworkPrefix,
    fb: &ScalaFullBlock,
) -> V1BlockSummary {
    V1BlockSummary {
        base: header_base(network, &fb.header),
        size_bytes: fb.size,
        transaction_count: fb.block_transactions.transactions.len() as u32,
        delivered_by: None,
    }
}

/// Wrap a Scala block section in the v1 tagged modifier.
pub(crate) fn modifier_from_scala(
    network: NetworkPrefix,
    section: &ScalaBlockSection,
    best_full_block_height: u32,
) -> V1Modifier {
    match section {
        ScalaBlockSection::Header(h) => V1Modifier::Header(Box::new(header_from_scala(network, h))),
        ScalaBlockSection::BlockTransactions(bt) => {
            V1Modifier::BlockTransactions(V1BlockTransactions {
                header_id: bt.header_id.clone(),
                transactions: bt
                    .transactions
                    .iter()
                    .map(|tx| block_tx_from_scala(network, tx, None, best_full_block_height))
                    .collect(),
                size_bytes: bt.size,
            })
        }
        ScalaBlockSection::Extension(e) => V1Modifier::Extension(extension_from_scala(e)),
        ScalaBlockSection::AdProofs(p) => V1Modifier::AdProofs(V1BlockAdProofs {
            header_id: p.header_id.clone(),
            proof_bytes: p.proof_bytes.clone(),
            digest: p.digest.clone(),
            size_bytes: p.size,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity (well-known unix epochs) -----

    #[test]
    fn unix_ms_to_iso_epoch_zero() {
        assert_eq!(unix_ms_to_iso(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn unix_ms_to_iso_billion_seconds() {
        // 1_000_000_000 s — the famous "unix billennium".
        assert_eq!(
            unix_ms_to_iso(1_000_000_000_000),
            "2001-09-09T01:46:40.000Z"
        );
    }

    #[test]
    fn unix_ms_to_iso_preserves_millis() {
        assert_eq!(
            unix_ms_to_iso(1_600_000_000_123),
            "2020-09-13T12:26:40.123Z"
        );
    }

    // ----- happy path -----

    #[test]
    fn single_page_collection_never_spans() {
        let c = Collection::single_page(vec![1u32, 2, 3]);
        assert_eq!(c.page.limit, 3);
        assert!(!c.page.has_more);
        assert!(c.page.next_cursor.is_none());
    }

    #[test]
    fn merkle_side_serializes_as_lowercase_string() {
        assert_eq!(
            serde_json::to_value(MerkleSide::Left).unwrap(),
            serde_json::json!("left")
        );
        assert_eq!(
            serde_json::to_value(MerkleSide::Right).unwrap(),
            serde_json::json!("right")
        );
    }
}
