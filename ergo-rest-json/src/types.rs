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
use num_bigint::BigUint;
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

/// Autolykos solution DTO. `d` is `JsonValue` rather than a concrete
/// integer type because it is a Scala `BigInt` reaching ~2^190 for v1
/// (0 for v2), and because the wire admits two spellings: Scala emits a
/// bare JSON NUMBER (`ApiCodecs.bigIntEncoder` =
/// `JsonNumber.fromDecimalStringUnsafe`), while circe's
/// `Decoder[BigInt]` — and so this crate — also tolerates a decimal
/// string inbound. Read it with `unsigned_bigint_from_json` rather
/// than matching the value inline; that is the one place both spellings
/// are handled.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaPowSolutions {
    pub pk: String,
    pub w: String,
    pub n: String,
    pub d: JsonValue,
}

/// Read a nonnegative Scala `BigInt` magnitude from a JSON number or numeric
/// string. Exact integral decimal/exponent forms follow pinned Circe 0.14.15;
/// negative nonzero values are refused by this field's unsigned policy.
///
/// Shared by the two such fields on the REST surface: the mining target
/// `b` (`WorkMessage`) and the Autolykos v1 PoW distance `d`
/// (`AutolykosSolution`). These fields use a nonnegative magnitude policy.
/// Header wire serialization of `d` separately applies the signed BigInt
/// leading-zero convention; this helper does not choose that wire encoding.
///
/// `arbitrary_precision` retains the decimal spelling without an f64 round trip.
/// Nonzero results are limited to the reference's 2^18 decimal digits before
/// materializing exponent zeros. Zero needs no exponent expansion.
///
/// `field` names the JSON path in the error, e.g. `"powSolutions.d"`.
pub(crate) fn unsigned_bigint_from_json(field: &str, value: &JsonValue) -> Result<BigUint, String> {
    match value {
        JsonValue::Number(n) => exact_unsigned_decimal(&n.to_string()),
        JsonValue::String(s) => exact_unsigned_decimal(s),
        other => {
            return Err(format!(
                "{field} must be a JSON number or decimal string, got {other}"
            ))
        }
    }
    .map_err(|reason| format!("{field} is not a valid unsigned decimal: {reason}"))
}

// Circe 0.14.15 BiggerDecimal.MaxBigIntegerDigits. Check the resulting length,
// not the exponent alone: significant digits and scale can cancel each other.
const MAX_BIGINT_DECIMAL_DIGITS: usize = 1 << 18;

fn exact_unsigned_decimal(decimal: &str) -> Result<BigUint, &'static str> {
    let (mantissa, exponent) = decimal
        .split_once(['e', 'E'])
        .map_or((decimal, None), |(m, e)| (m, Some(e)));
    let (negative, magnitude) = mantissa
        .strip_prefix('-')
        .map_or((false, mantissa), |m| (true, m));
    let (integer, fractional) = magnitude
        .split_once('.')
        .map_or((magnitude, None), |(i, f)| (i, Some(f)));
    let digits_only = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits_only(integer) || fractional.is_some_and(|f| !digits_only(f)) {
        return Err("invalid decimal syntax");
    }
    if let Some(exponent) = exponent {
        let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if !digits_only(digits) {
            return Err("invalid exponent syntax");
        }
    }
    let fractional = fractional.unwrap_or("");
    let mut digits = String::with_capacity(integer.len() + fractional.len());
    digits.push_str(integer);
    digits.push_str(fractional);
    let nonzero = digits.trim_matches('0');
    if nonzero.is_empty() {
        return Ok(BigUint::default());
    }
    if negative {
        return Err("negative value is outside the unsigned magnitude domain");
    }
    let trailing_zeros = digits.len() - digits.trim_end_matches('0').len();
    let exponent: i64 = match exponent {
        None => 0,
        Some(e) => e
            .parse()
            .map_err(|_| "nonzero exponent is outside the integral digit bound")?,
    };
    let fractional_len =
        i64::try_from(fractional.len()).map_err(|_| "decimal scale is too large")?;
    let trailing_zeros = i64::try_from(trailing_zeros).map_err(|_| "decimal scale is too large")?;
    let zeros = exponent
        .checked_sub(fractional_len)
        .and_then(|v| v.checked_add(trailing_zeros))
        .ok_or("decimal scale is too large")?;
    let zeros = usize::try_from(zeros).map_err(|_| "fractional value is not an integer")?;
    let result_len = nonzero
        .len()
        .checked_add(zeros)
        .ok_or("decimal digit count overflow")?;
    if result_len > MAX_BIGINT_DECIMAL_DIGITS {
        return Err("nonzero integer exceeds the reference's 2^18 decimal digit bound");
    }
    let mut integer = Vec::with_capacity(result_len);
    integer.extend_from_slice(nonzero.as_bytes());
    integer.resize(result_len, b'0');
    BigUint::parse_bytes(&integer, 10).ok_or("invalid unsigned decimal magnitude")
}

fn deserialize_nonnegative_long<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let value = JsonValue::deserialize(deserializer)?;
    let magnitude = unsigned_bigint_from_json("nonnegative Scala Long", &value)
        .map_err(serde::de::Error::custom)?;
    let value = u64::try_from(magnitude).map_err(serde::de::Error::custom)?;
    i64::try_from(value).map_err(serde::de::Error::custom)?;
    Ok(value)
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
    #[serde(deserialize_with = "deserialize_nonnegative_long")]
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
    #[serde(deserialize_with = "deserialize_nonnegative_long")]
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
    #[serde(deserialize_with = "deserialize_nonnegative_long")]
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

/// One proved leaf of a `BatchMerkleProof` — `(leaf index, leaf digest)`.
/// Scala `PoPowHeader.scala:84-88` (`batchMerkleProofEncoder` `indices`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaBatchProofIndex {
    pub index: u32,
    /// Base16 leaf digest (always 32 bytes on the wire, never empty).
    pub digest: String,
}

/// One sibling entry of a `BatchMerkleProof` path.
/// Scala `PoPowHeader.scala:89-93` (`batchMerkleProofEncoder` `proofs`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaBatchProofElement {
    /// Base16 sibling digest. Scala's odd-trailing empty sibling
    /// (`EmptyByteArray`) serializes as the EMPTY STRING here — not as
    /// 32 zero bytes (that form is wire-only). Pinned by the captured
    /// mainnet fixture `popowHeaderByHeight_1000.json`.
    pub digest: String,
    /// 0 = sibling hashes on the left, 1 = right.
    pub side: u8,
}

/// `BatchMerkleProof` JSON shape (`PoPowHeader.scala:81-96`). Note the
/// Scala node's own `openapi.yaml` omits this object from its
/// `PopowHeader` schema — a Scala documentation bug; the live JSON
/// always includes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaBatchMerkleProof {
    pub indices: Vec<ScalaBatchProofIndex>,
    pub proofs: Vec<ScalaBatchProofElement>,
}

/// `PoPowHeader.jsonEncoder` shape (`PoPowHeader.scala:121-128`):
/// a full header DTO + the interlinks vector + the batch Merkle proof
/// tying those interlinks to the header's extension digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaPopowHeader {
    pub header: ScalaHeader,
    /// Base16 header ids, genesis first (KMZ17 reverse-level order).
    pub interlinks: Vec<String>,
    #[serde(rename = "interlinksProof")]
    pub interlinks_proof: ScalaBatchMerkleProof,
}

/// `NipopowProof.nipopowProofEncoder` shape (`NipopowProof.scala:164-173`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalaNipopowProof {
    pub m: u32,
    pub k: u32,
    pub prefix: Vec<ScalaPopowHeader>,
    #[serde(rename = "suffixHead")]
    pub suffix_head: ScalaPopowHeader,
    /// Plain headers (no interlinks) — mirrors the wire asymmetry where
    /// only prefix + suffixHead carry `PoPowHeader` blobs.
    #[serde(rename = "suffixTail")]
    pub suffix_tail: Vec<ScalaHeader>,
    /// Always `true` on the REST surface (`NipopowApiRoute.scala:69-90`
    /// passes `continuous = true` unconditionally).
    pub continuous: bool,
}
