//! Scala-compat JSON DTOs. Mirrors the wire shapes Scala emits via
//! `Header.jsonEncoder` / `BlockTransactions.jsonEncoder` /
//! `Extension.jsonEncoder` / `ApiCodecs` / `JsonCodecs.scala`. Field
//! order matches Scala's emission order so a captured-fixture diff
//! is readable.
//!
//! These types live in the shared crate so the read-side
//! (ergo-api), the JSON-bodied tx-submit path (ergo-node), and the
//! historical-block byte-fidelity diagnostics (ergo-validation) all
//! share one definition. Drift is pinned by the b4_* byte-parity
//! oracle in `ergo-node/src/api_bridge.rs`.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

/// Wire shape of `/blocks/{id}` and the body of `/blocks/headerIds`.
/// `null` for `adProofs` matches Scala's `Option#asJson` (renders as
/// JSON `null`), not the conditional `optionalFields` pattern used
/// for `restApiUrl` in `/info`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaFullBlock {
    pub header: ScalaHeader,
    #[serde(rename = "blockTransactions")]
    pub block_transactions: ScalaBlockTransactions,
    pub extension: ScalaExtension,
    #[serde(rename = "adProofs")]
    pub ad_proofs: Option<ScalaAdProofs>,
    pub size: u32,
}

/// Header DTO matching Scala's `Header.jsonEncoder`
/// (`Header.scala`, ~lines 280-300). Field order mirrors Scala emission.
///
/// `difficulty` is rendered as a JSON string (Scala
/// `requiredDifficulty.toString`) so values >= 2^53 don't lose
/// precision in JS clients. All hex fields are unprefixed lowercase.
/// `unparsedBytes` is "" (empty hex) for v2-v4 blocks where Scala
/// discards the extension byte content; populated for v5+.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaHeader {
    #[serde(rename = "extensionId")]
    pub extension_id: String,
    pub difficulty: String,
    pub votes: String,
    pub timestamp: u64,
    pub size: u32,
    #[serde(rename = "unparsedBytes")]
    pub unparsed_bytes: String,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    pub height: u32,
    #[serde(rename = "nBits")]
    pub n_bits: u64,
    pub version: u8,
    pub id: String,
    #[serde(rename = "adProofsRoot")]
    pub ad_proofs_root: String,
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: String,
    #[serde(rename = "extensionHash")]
    pub extension_hash: String,
    #[serde(rename = "powSolutions")]
    pub pow_solutions: ScalaPowSolutions,
    #[serde(rename = "adProofsId")]
    pub ad_proofs_id: String,
    #[serde(rename = "transactionsId")]
    pub transactions_id: String,
    #[serde(rename = "parentId")]
    pub parent_id: String,
}

/// Autolykos solution DTO. `d` is `JsonValue` because Scala emits an
/// integer literal for v2 (always 0) and a decimal-string for v1
/// BigInts; keeping the field flexible matches both without
/// splitting the type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaPowSolutions {
    pub pk: String,
    pub w: String,
    pub n: String,
    pub d: JsonValue,
}

/// `BlockTransactions.jsonEncoder` shape:
/// `{ headerId, transactions[], blockVersion, size }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaBlockTransactions {
    #[serde(rename = "headerId")]
    pub header_id: String,
    pub transactions: Vec<ScalaTransaction>,
    #[serde(rename = "blockVersion")]
    pub block_version: u8,
    pub size: u32,
}

/// `ErgoTransaction` shape: the inner `ErgoLikeTransaction.jsonEncoder`
/// fields (`id`, `inputs`, `dataInputs`, `outputs`) plus the `size`
/// field added by `ErgoTransaction.jsonEncoder` via
/// `mapObject(_.add("size", ...))`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaTransaction {
    pub id: String,
    pub inputs: Vec<ScalaInput>,
    #[serde(rename = "dataInputs")]
    pub data_inputs: Vec<ScalaDataInput>,
    pub outputs: Vec<ScalaOutput>,
    pub size: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaInput {
    #[serde(rename = "boxId")]
    pub box_id: String,
    #[serde(rename = "spendingProof")]
    pub spending_proof: ScalaSpendingProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaSpendingProof {
    #[serde(rename = "proofBytes")]
    pub proof_bytes: String,
    /// `ContextExtension` map: keys are decimal stringified `Byte`
    /// (e.g. `"0"`, `"1"`); values are hex of
    /// `ValueSerializer.serialize` applied to each `EvaluatedValue`
    /// (type prefix + data).
    ///
    /// Backed by [`IndexMap`] (not `BTreeMap`) so the JSON object
    /// key order from the wallet survives deserialization. Scala
    /// `Map[Byte, T]` for ≤ 4 entries is `Map1`-`Map4` (insertion-
    /// ordered): a wallet that signs bytes for entries inserted in
    /// `(5, 3, 8)` order emits JSON with those keys in that order
    /// and our re-serialization must reproduce them in that order.
    /// `BTreeMap` would silently re-sort by lex-stringified key,
    /// destroying that property and breaking the signature on the
    /// JSON submit path.
    pub extension: IndexMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaDataInput {
    #[serde(rename = "boxId")]
    pub box_id: String,
}

/// `ErgoBox.jsonEncoder` shape. Order is the Scala emission order so
/// a captured fixture diff is readable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaOutput {
    #[serde(rename = "boxId")]
    pub box_id: String,
    pub value: u64,
    #[serde(rename = "ergoTree")]
    pub ergo_tree: String,
    pub assets: Vec<ScalaAsset>,
    #[serde(rename = "creationHeight")]
    pub creation_height: u32,
    /// Register map keyed `R4`..`R9`, sorted by register number per
    /// `registersEncoder` in `JsonCodecs.scala`. Each value is the
    /// hex of `ValueSerializer.serialize` applied to the typed
    /// register value.
    #[serde(rename = "additionalRegisters")]
    pub additional_registers: BTreeMap<String, String>,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    pub index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaAsset {
    #[serde(rename = "tokenId")]
    pub token_id: String,
    pub amount: u64,
}

/// Input variant of [`ScalaTransaction`] used by the JSON submit
/// handlers (`POST /transactions[/check]`).
///
/// Mirrors Scala's `ergoLikeTransactionDecoder`
/// (`reference/ergo-core/.../JsonCodecs.scala:377-383`) which reads
/// only `inputs`, `dataInputs`, and `outputs`. The `id` and `size`
/// fields are derived from the canonical bytes and are
/// accepted-and-ignored, which matches serde's default lenient handling
/// of unknown fields. Omitting them here means a request that supplies
/// them parses cleanly and the supplied values are discarded.
#[derive(Clone, Debug, Deserialize)]
pub struct ScalaTransactionInput {
    pub inputs: Vec<ScalaInput>,
    #[serde(rename = "dataInputs")]
    pub data_inputs: Vec<ScalaDataInput>,
    pub outputs: Vec<ScalaOutputInput>,
}

/// Input variant of [`ScalaOutput`] used by the JSON submit handlers.
///
/// Mirrors Scala's `ergoBoxCandidateDecoder`
/// (`reference/ergo-core/.../JsonCodecs.scala:352-366`) which reads
/// only `value`, `ergoTree`, `assets`, `creationHeight`,
/// `additionalRegisters`. The derived fields (`boxId`,
/// `transactionId`, `index`) are accepted-and-ignored — same omission
/// rationale as [`ScalaTransactionInput`].
#[derive(Clone, Debug, Deserialize)]
pub struct ScalaOutputInput {
    pub value: u64,
    #[serde(rename = "ergoTree")]
    pub ergo_tree: String,
    pub assets: Vec<ScalaAsset>,
    #[serde(rename = "creationHeight")]
    pub creation_height: u32,
    #[serde(rename = "additionalRegisters")]
    pub additional_registers: BTreeMap<String, String>,
}

/// `Extension.jsonEncoder` shape: `headerId`, `digest`, and `fields`
/// as a JSON array of two-element string arrays `[key_hex, value_hex]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaExtension {
    #[serde(rename = "headerId")]
    pub header_id: String,
    pub digest: String,
    pub fields: Vec<[String; 2]>,
}

/// `ADProofs.jsonEncoder` shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaAdProofs {
    #[serde(rename = "headerId")]
    pub header_id: String,
    #[serde(rename = "proofBytes")]
    pub proof_bytes: String,
    pub digest: String,
    pub size: u32,
}

/// `/blocks/modifier/{id}` response — Scala's `BlockSection` is a
/// sealed trait whose `asJson` produces a bare object per variant
/// with no discriminator field. `untagged` here matches that wire
/// shape: consumers must inspect fields to tell the variant apart,
/// exactly as they do against the Scala node.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScalaBlockSection {
    Header(Box<ScalaHeader>),
    BlockTransactions(ScalaBlockTransactions),
    Extension(ScalaExtension),
    AdProofs(ScalaAdProofs),
}
