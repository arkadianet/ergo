//! v1 header / block / modifier DTOs and their Scala-compat
//! projections (`header_from_scala`, `block_from_scala`,
//! `modifier_from_scala`, ...), plus the block-embedded and resolved
//! transaction shapes (`V1BlockTx`, `V1Tx`) and the Merkle
//! membership-proof DTOs.

use std::collections::BTreeMap;
use utoipa::ToSchema;

use ergo_rest_json::types::{
    ScalaAdProofs, ScalaBlockSection, ScalaExtension, ScalaFullBlock, ScalaHeader, ScalaInput,
    ScalaOutput, ScalaTransaction,
};
use ergo_ser::address::{encode_address_from_tree_bytes, encode_p2pk_from_pubkey, NetworkPrefix};
use serde::Serialize;

use super::boxes::{V1Asset, V1Box};
use super::common::{confirmations, unix_ms_to_iso};

// ----- header / block ----------------------------------------------

/// Glossary-renamed header fields shared by the standalone header object,
/// the full block, and a block summary (`serde(flatten)`ed into each).
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct V1Header {
    #[serde(flatten)]
    pub base: V1HeaderBase,
    pub size_bytes: u32,
}

/// One item of the `GET /chain/blocks` list — a block summary.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1BlockSummary {
    #[serde(flatten)]
    pub base: V1HeaderBase,
    pub size_bytes: u32,
    pub transaction_count: u32,
    /// First-deliverer peer — only known inside the near-tip live ring;
    /// `null` for any block outside it (documented capability gap).
    pub delivered_by: Option<String>,
}

/// Full block (`GET /chain/blocks/{header_id}`).
#[derive(Debug, Serialize, ToSchema)]
pub struct V1Block {
    #[serde(flatten)]
    pub base: V1HeaderBase,
    pub size_bytes: u32,
    pub transactions: Vec<V1BlockTx>,
    pub extension: V1Extension,
    /// `null` in UTXO / pruned mode (block exists, section doesn't).
    pub ad_proofs: Option<V1AdProofs>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct V1Extension {
    pub digest: String,
    pub fields: Vec<[String; 2]>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct V1AdProofs {
    pub proof_bytes: String,
    pub digest: String,
}

/// `GET /chain/proofs/{header_id}` — the block's AD-proofs section.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1BlockAdProofs {
    pub header_id: String,
    pub proof_bytes: String,
    pub digest: String,
    pub size_bytes: u32,
}

/// `GET /chain/modifiers/{modifier_id}` — v1 adds the explicit `kind`
/// discriminant the untagged Scala `BlockSection` lacks.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum V1Modifier {
    Header(Box<V1Header>),
    BlockTransactions(V1BlockTransactions),
    Extension(V1Extension),
    AdProofs(V1BlockAdProofs),
}

/// The block-transactions section as a modifier `data` payload.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1BlockTransactions {
    pub header_id: String,
    pub transactions: Vec<V1BlockTx>,
    pub size_bytes: u32,
}

/// `GET /chain/proofs/{header_id}/transactions/{tx_id}` — Merkle membership
/// proof. Side byte `0/1` rendered as `"left"/"right"` strings.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1MerkleProof {
    pub tx_id: String,
    pub levels: Vec<V1MerkleLevel>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct V1MerkleLevel {
    pub sibling: String,
    pub side: MerkleSide,
}

#[derive(Debug, Serialize, Clone, Copy, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MerkleSide {
    Left,
    Right,
}

/// Spending-proof reference on a block-embedded transaction input.
#[derive(Debug, Serialize, ToSchema)]
pub struct V1SpendingProof {
    pub proof_bytes: String,
    pub extension: BTreeMap<String, String>,
}

/// A block-embedded transaction input — a *reference* to a spent box, not a
/// resolved box (the block does not carry the spent box's body).
#[derive(Debug, Serialize, ToSchema)]
pub struct V1SpendInput {
    pub box_id: String,
    pub spending_proof: V1SpendingProof,
}

/// A transaction as embedded in a block (`GET /chain/blocks/*`): inputs are
/// spend-references, outputs are the block's own output boxes.
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
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
