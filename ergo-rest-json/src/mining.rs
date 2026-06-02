//! JSON DTOs for `/mining/candidate` and `/mining/solution`.
//!
//! Lives in `ergo-rest-json` rather than `ergo-mining` so the
//! operator-API crate (`ergo-api`) can mount the `/mining/*` routes
//! without picking up the storage / sync / mempool transitives that
//! `ergo-mining` pulls in. The wire shapes are pure JSON; the
//! consensus-bearing code in `ergo-mining` re-exports these types for
//! its own internal use.
//!
//! Scala parity:
//!
//! - `WorkMessage` from `ergo-core/.../mining/WorkMessage.scala`
//! - `AutolykosSolution` from `ergo-core/.../mining/AutolykosSolution.scala`
//!
//! Both shapes match Scala's circe encoders byte-for-byte for the
//! field names and on-wire types Lithos-Client / Rigel / ErgoStratum
//! consume. `WorkMessage` carries the mining target as a decimal-
//! encoded BigInt string (Scala `bigIntEncoder`); the `proof` field
//! is omitted entirely when None (`collect {... case (n, Some) =>}`
//! in Scala's `WorkMessage.encoder`).
//!
//! `WorkMessageJson` additionally carries two node-specific pool
//! extensions BEYOND Scala's `WorkMessage` — `template_seq` and
//! `clean_jobs` — for the longpoll / Stratum-proxy consumers that roll
//! jobs (the existing `msg` doubles as the template id). They are
//! always present and append after the Scala fields; the Scala-parity
//! fields (`msg` / `b` / `h` / `pk` / `proof`) keep their exact names,
//! types, and encoding, and a client that ignores unknown fields
//! (Lithos / Rigel / ErgoStratum) is unaffected.

use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// JSON payload returned by `GET /mining/candidate` and
/// `POST /mining/candidateWithTxs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkMessageJson {
    /// Hex-encoded 32-byte Blake2b256 of `serialize_header_without_pow(header)`.
    /// The external miner hashes this with their nonce to compute the
    /// Autolykos v2 hit.
    pub msg: String,

    /// Mining target as a decimal-encoded BigInt string. The miner's
    /// hit must satisfy `hit <= target` to be a valid solution.
    #[serde(serialize_with = "serialize_biguint_decimal")]
    #[serde(deserialize_with = "deserialize_biguint_decimal")]
    pub b: BigUint,

    /// Candidate block height. Always populated for v2+ headers;
    /// optional for v1 backwards-compat. v1 produced an empty `h`
    /// before EIP-39 made it mandatory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,

    /// Hex-encoded 33-byte compressed secp256k1 miner pubkey.
    pub pk: String,

    /// Proof-of-upcoming-transactions for mandatory-tx candidates.
    /// Omitted entirely when no mandatory transactions are present
    /// (matches Scala's `collect { case (n, Some) => ... }` pattern).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<serde_json::Value>,

    /// Node-specific pool extension (not part of Scala's WorkMessage):
    /// monotonic per-publish template sequence. A Stratum proxy uses this to
    /// distinguish successive same-parent (mempool-refresh) templates. Always
    /// emitted by this node; `#[serde(default)]` so the DTO still deserializes
    /// a legacy / Scala candidate that omits it (defaults to 0).
    #[serde(default)]
    pub template_seq: u64,

    /// Node-specific pool extension: true when this template starts a new
    /// chain era (parent changed) vs the previously published one — the
    /// getblocktemplate `clean_jobs` signal (discard prior jobs). Always
    /// emitted by this node; `#[serde(default)]` so the DTO still deserializes
    /// a legacy / Scala candidate that omits it (defaults to `false`).
    #[serde(default)]
    pub clean_jobs: bool,
}

/// JSON payload accepted by `POST /mining/solution`. Autolykos v2 form
/// only — v1 carried an additional `d` BigInt (distance), which v2
/// replaces with the hit-comparison directly on `n` (nonce).
///
/// Per Scala `AutolykosSolution.jsonDecoder` (`AutolykosSolution.scala:46-56`):
/// `pk`, `w`, and `d` are all optional with defaults — `pk` defaults
/// to the dlog-group identity (placeholder; the actor injects the
/// miner's real pk), `w` defaults to the generator, `d` defaults to 0.
/// Only `n` is strictly required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutolykosSolutionJson {
    /// Hex-encoded miner pubkey (33-byte compressed point). May be
    /// the dlog-group identity placeholder; mining inserts the real
    /// pk when accepting the solution per `CandidateGenerator.scala:202-207`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pk: Option<String>,

    /// Autolykos v1 one-time key. Defaults to the dlog-group generator
    /// for v2 solutions per Scala `wForV2`. Always present in v1
    /// solutions; in v2 it's a placeholder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub w: Option<String>,

    /// Hex-encoded 8-byte nonce. Required.
    pub n: String,

    /// Distance value. v1-only; v2 defaults to 0 per `dForV2`. Encoded
    /// as decimal-BigInt string when present.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_opt_biguint_decimal")]
    #[serde(deserialize_with = "deserialize_opt_biguint_decimal")]
    pub d: Option<BigUint>,
}

/// JSON payload returned by `GET /mining/rewardAddress`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardAddressResponse {
    /// Base58 P2S address derived from `rewardOutputScript(720, miner_pk)`.
    #[serde(rename = "rewardAddress")]
    pub reward_address: String,
}

/// JSON payload returned by `GET /mining/rewardPublicKey`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardPublicKeyResponse {
    /// Hex-encoded 33-byte compressed miner pubkey.
    #[serde(rename = "rewardPubkey")]
    pub reward_pubkey: String,
}

// ---- BigUint serde helpers ----

fn serialize_biguint_decimal<S: Serializer>(v: &BigUint, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_str_radix(10))
}

fn deserialize_biguint_decimal<'de, D: Deserializer<'de>>(d: D) -> Result<BigUint, D::Error> {
    let s = String::deserialize(d)?;
    s.parse::<BigUint>()
        .map_err(|e| serde::de::Error::custom(format!("biguint parse: {e}")))
}

fn serialize_opt_biguint_decimal<S: Serializer>(
    v: &Option<BigUint>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(b) => s.serialize_str(&b.to_str_radix(10)),
        None => s.serialize_none(),
    }
}

fn deserialize_opt_biguint_decimal<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<BigUint>, D::Error> {
    let opt = Option::<String>::deserialize(d)?;
    match opt {
        Some(s) => s
            .parse::<BigUint>()
            .map(Some)
            .map_err(|e| serde::de::Error::custom(format!("biguint parse: {e}"))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn work_message_serializes_with_proof_omitted_when_none() {
        let m = WorkMessageJson {
            msg: "aa".repeat(32),
            b: BigUint::from(123456789u64),
            h: Some(1_786_188),
            pk: "02".to_string() + &"bb".repeat(32),
            proof: None,
            template_seq: 7,
            clean_jobs: true,
        };
        let j = serde_json::to_value(&m).expect("serialize");
        assert_eq!(j["msg"], serde_json::Value::String("aa".repeat(32)));
        assert_eq!(j["b"], serde_json::Value::String("123456789".into()));
        assert_eq!(j["h"], serde_json::Value::Number(1_786_188.into()));
        assert_eq!(j["pk"].as_str().unwrap().len(), 66);
        assert!(j.get("proof").is_none(), "proof must be omitted when None");
        // Node-specific pool extensions are always present.
        assert_eq!(j["template_seq"], serde_json::Value::Number(7.into()));
        assert_eq!(j["clean_jobs"], serde_json::Value::Bool(true));
    }

    #[test]
    fn legacy_candidate_without_extension_fields_deserializes() {
        // A legacy / Scala `WorkMessage` JSON carries only `msg`/`b`/`h`/`pk`
        // (and an optional `proof`); it has no `template_seq` / `clean_jobs`.
        // The DTO must still parse it (the node serializes the extensions, but
        // any consumer using this shared type to read a plain candidate must
        // not break) — `#[serde(default)]` fills the missing extensions.
        let legacy = r#"{"msg":"aabb","b":"123456789","h":1786188,"pk":"02cc"}"#;
        let parsed: WorkMessageJson = serde_json::from_str(legacy).expect("legacy parses");
        assert_eq!(parsed.msg, "aabb");
        assert_eq!(parsed.b, BigUint::from(123456789u64));
        assert_eq!(parsed.h, Some(1_786_188));
        assert!(parsed.proof.is_none());
        assert_eq!(parsed.template_seq, 0, "missing template_seq defaults to 0");
        assert!(!parsed.clean_jobs, "missing clean_jobs defaults to false");
    }

    #[test]
    fn autolykos_solution_parses_v2_minimal_with_only_n() {
        let s = r#"{"n":"0123456789abcdef"}"#;
        let parsed: AutolykosSolutionJson = serde_json::from_str(s).expect("de");
        assert_eq!(parsed.n, "0123456789abcdef");
        assert!(parsed.pk.is_none());
        assert!(parsed.w.is_none());
        assert!(parsed.d.is_none());
    }

    #[test]
    fn reward_address_response_keys_are_camel_case() {
        let r = RewardAddressResponse {
            reward_address: "9foo".into(),
        };
        let s = serde_json::to_string(&r).expect("ser");
        assert!(s.contains("\"rewardAddress\""), "{s}");
        assert!(!s.contains("reward_address"), "{s}");
    }

    #[test]
    fn reward_pubkey_response_keys_are_camel_case() {
        let r = RewardPublicKeyResponse {
            reward_pubkey: "02aa".into(),
        };
        let s = serde_json::to_string(&r).expect("ser");
        assert!(s.contains("\"rewardPubkey\""), "{s}");
    }

    // ----- error paths -----

    #[test]
    fn work_message_rejects_invalid_b_string() {
        let bad = r#"{"msg":"aa","b":"not_a_number","pk":"02ff"}"#;
        let err =
            serde_json::from_str::<WorkMessageJson>(bad).expect_err("must reject non-numeric b");
        assert!(err.to_string().contains("biguint parse"), "{err}");
    }
}
