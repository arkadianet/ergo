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
//! consume. `WorkMessage` carries the mining target `b` as a bare JSON
//! NUMBER — Scala's `bigIntEncoder` is
//! `JsonNumber.fromDecimalStringUnsafe`, pinned here against a live
//! 6.0.3 testnet capture — and the `proof` field is omitted entirely
//! when None (`collect {... case (n, Some) =>}` in Scala's
//! `WorkMessage.encoder`). Both `b` and the v1 solution `d` still
//! ACCEPT a decimal string inbound, matching circe's `Decoder[BigInt]`,
//! so a client that sends the older string form keeps working.
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

    /// Mining target: the miner's hit must satisfy `hit <= target` to
    /// be a valid solution.
    ///
    /// A bare JSON NUMBER on the wire, as Scala emits it — `WorkMessage`
    /// carries `b: BigInt` and `ApiCodecs.bigIntEncoder` renders a
    /// `JsonNumber`, verified against a live 6.0.3 testnet node (see
    /// `mining_candidate_scala_oracle.rs`). A decimal string is also
    /// accepted inbound, as circe's `Decoder[BigInt]` accepts one.
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

    /// Distance value. v1-only; v2 defaults to 0 per `dForV2`.
    ///
    /// UNSIGNED: Scala carries `d` as the magnitude that
    /// `BigIntegers.asUnsignedByteArray` writes to the wire, so a
    /// `BigUint` is the faithful type — a signed BigInt would admit
    /// values no Scala node can serialize. On the wire it is a bare
    /// JSON NUMBER (`ApiCodecs.bigIntEncoder` =
    /// `JsonNumber.fromDecimalStringUnsafe`), matching the `d` the
    /// header encoder emits; a decimal string is also accepted inbound,
    /// as circe's `Decoder[BigInt]` accepts one.
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

/// Render an unsigned magnitude the way Scala's `ApiCodecs.bigIntEncoder`
/// does: a bare JSON number (`JsonNumber.fromDecimalStringUnsafe`).
/// `serde_json`'s `arbitrary_precision` feature (enabled by this crate)
/// carries the full ~256-bit value losslessly; a plain `f64` number
/// would not.
fn biguint_as_json_number(v: &BigUint) -> Result<serde_json::Number, String> {
    v.to_str_radix(10)
        .parse::<serde_json::Number>()
        .map_err(|e| format!("biguint as JSON number: {e}"))
}

/// Read an unsigned magnitude from what circe's `Decoder[BigInt]`
/// accepts: a JSON number (the form Scala's own encoder emits) or a
/// decimal string. Both `b` and `d` are unsigned magnitudes, so a
/// negative or fractional value is malformed rather than something to
/// reinterpret.
fn biguint_from_json_value<E: serde::de::Error>(
    field: &str,
    value: serde_json::Value,
) -> Result<BigUint, E> {
    let decimal = match value {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s,
        other => {
            return Err(E::custom(format!(
                "{field} must be a JSON number or decimal string, got {other}"
            )))
        }
    };
    decimal
        .parse::<BigUint>()
        .map_err(|e| E::custom(format!("biguint parse: {e}")))
}

fn serialize_biguint_decimal<S: Serializer>(v: &BigUint, s: S) -> Result<S::Ok, S::Error> {
    biguint_as_json_number(v)
        .map_err(serde::ser::Error::custom)?
        .serialize(s)
}

fn deserialize_biguint_decimal<'de, D: Deserializer<'de>>(d: D) -> Result<BigUint, D::Error> {
    biguint_from_json_value("b", serde_json::Value::deserialize(d)?)
}

/// Autolykos v1 `d`, rendered the way Scala renders it — a bare JSON
/// number, per `AutolykosSolution.jsonEncoder` → `bigIntEncoder`.
fn serialize_opt_biguint_decimal<S: Serializer>(
    v: &Option<BigUint>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(d) => serialize_biguint_decimal(d, s),
        None => s.serialize_none(),
    }
}

/// Inbound `d`. Absent and `null` both mean "no distance" (a v2
/// solution); anything present goes through the same number-or-string
/// reading as `b`.
fn deserialize_opt_biguint_decimal<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<BigUint>, D::Error> {
    match Option::<serde_json::Value>::deserialize(d)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => biguint_from_json_value("d", value).map(Some),
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
        assert!(
            j["b"].is_number(),
            "b must be a bare JSON number, as Scala emits it: {}",
            j["b"],
        );
        assert_eq!(j["b"].to_string(), "123456789");
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
        // `b` is given here in the older STRING form this DTO used to emit,
        // pinning that the switch to a number stayed backward-compatible
        // inbound.
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

    /// `d` from mainnet header 3
    /// (`3ff49e2419f779390a9347e8c3ee6391dd3f9e543c12dabcb0f1ebc8168754f4`),
    /// the first block on the chain whose Autolykos v1 distance has its
    /// top bit set: 27 magnitude bytes starting `0x9a`.
    const MAINNET_H3_D: &str = "63676299738664633458272122943823860664316059640250223568297740204";

    #[test]
    fn autolykos_solution_parses_v1_d_from_json_number() {
        // Scala's `AutolykosSolution.jsonEncoder` emits `d` as a bare
        // JSON number, so this is the shape a Scala-compatible v1 miner
        // POSTs. Rejecting it would close the door on the real wire form.
        let s = format!(r#"{{"n":"0000000900cb491a","d":{MAINNET_H3_D}}}"#);
        let parsed: AutolykosSolutionJson = serde_json::from_str(&s).expect("de");
        let d = parsed.d.expect("d present");
        assert_eq!(d.to_str_radix(10), MAINNET_H3_D);
        let magnitude = d.to_bytes_be();
        assert_eq!(magnitude.len(), 27, "unsigned magnitude is minimal-length");
        assert!(
            magnitude[0] >= 0x80,
            "h=3 exercises the high-bit case: {:#04x}",
            magnitude[0],
        );
    }

    #[test]
    fn autolykos_solution_parses_v1_d_from_decimal_string() {
        // circe's `Decoder[BigInt]` also accepts a string, so stay as
        // permissive inbound as the node we mirror.
        let s = format!(r#"{{"n":"0000000900cb491a","d":"{MAINNET_H3_D}"}}"#);
        let parsed: AutolykosSolutionJson = serde_json::from_str(&s).expect("de");
        assert_eq!(parsed.d.expect("d present").to_str_radix(10), MAINNET_H3_D);
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

    // ----- round-trips -----

    #[test]
    fn autolykos_solution_v1_d_roundtrips_as_bare_json_number() {
        let s = format!(r#"{{"n":"0000000900cb491a","d":{MAINNET_H3_D}}}"#);
        let parsed: AutolykosSolutionJson = serde_json::from_str(&s).expect("de");
        let json = serde_json::to_value(&parsed).expect("ser");
        assert!(
            json["d"].is_number(),
            "d must re-emit as a JSON number, not a string: {}",
            json["d"],
        );
        assert_eq!(
            json["d"].to_string(),
            MAINNET_H3_D,
            "arbitrary-precision number must survive the round trip intact",
        );
        let reparsed: AutolykosSolutionJson =
            serde_json::from_value(json).expect("re-emitted form re-parses");
        assert_eq!(reparsed, parsed);
    }

    // ----- error paths -----

    #[test]
    fn autolykos_solution_rejects_negative_d() {
        // `d` is the unsigned magnitude Scala writes with
        // `BigIntegers.asUnsignedByteArray`; a negative value is not a
        // solution any node could have produced.
        let s = r#"{"n":"0000000900cb491a","d":-1}"#;
        let err = serde_json::from_str::<AutolykosSolutionJson>(s).expect_err("must reject");
        assert!(err.to_string().contains("biguint parse"), "{err}");
    }

    #[test]
    fn autolykos_solution_rejects_fractional_d() {
        let s = r#"{"n":"0000000900cb491a","d":1.5}"#;
        let err = serde_json::from_str::<AutolykosSolutionJson>(s).expect_err("must reject");
        assert!(err.to_string().contains("biguint parse"), "{err}");
    }

    #[test]
    fn autolykos_solution_rejects_non_numeric_d() {
        let s = r#"{"n":"0000000900cb491a","d":true}"#;
        let err = serde_json::from_str::<AutolykosSolutionJson>(s).expect_err("must reject");
        assert!(
            err.to_string().contains("JSON number or decimal string"),
            "{err}"
        );
    }

    #[test]
    fn work_message_rejects_invalid_b_string() {
        let bad = r#"{"msg":"aa","b":"not_a_number","pk":"02ff"}"#;
        let err =
            serde_json::from_str::<WorkMessageJson>(bad).expect_err("must reject non-numeric b");
        assert!(err.to_string().contains("biguint parse"), "{err}");
    }

    #[test]
    fn work_message_rejects_non_numeric_b() {
        let bad = r#"{"msg":"aa","b":true,"pk":"02ff"}"#;
        let err = serde_json::from_str::<WorkMessageJson>(bad).expect_err("must reject");
        assert!(
            err.to_string().contains("JSON number or decimal string"),
            "{err}"
        );
    }

    // ----- oracle parity -----

    /// `GET /mining/candidate` captured VERBATIM from a live Scala 6.0.3
    /// testnet node (`http://127.0.0.1:9062`, h=522032, 2026-09-03).
    /// Nothing re-serialized or hand-edited, so the on-wire JSON TYPE of
    /// every field is an external oracle — which is the whole point
    /// here: `b` is a bare number, not a string.
    fn candidate_oracle_raw() -> String {
        let path = format!(
            "{}/../test-vectors/testnet/mining_json/scala_candidate_522032.json",
            env!("CARGO_MANIFEST_DIR"),
        );
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    #[test]
    fn work_message_scala_candidate_b_is_a_bare_json_number() {
        let served: serde_json::Value =
            serde_json::from_str(&candidate_oracle_raw()).expect("fixture parses");
        assert!(
            served["b"].is_number(),
            "the node serves b as a JSON number; if this ever fails the \
             parity target moved, not our encoder: {}",
            served["b"],
        );
        // ~2^222: far past f64's exact-integer range, so the DTO must
        // carry it through arbitrary precision rather than a float.
        let b = served["b"].to_string();
        assert_eq!(b.len(), 67, "unexpected magnitude width: {b}");
    }

    #[test]
    fn work_message_roundtrips_scala_candidate_byte_exactly() {
        let raw = candidate_oracle_raw();
        let parsed: WorkMessageJson = serde_json::from_str(&raw).expect("real candidate parses");
        let served: serde_json::Value = serde_json::from_str(&raw).expect("fixture parses");

        assert_eq!(parsed.msg, served["msg"].as_str().expect("msg"));
        assert_eq!(parsed.pk, served["pk"].as_str().expect("pk"));
        assert_eq!(parsed.h, Some(served["h"].as_u64().expect("h") as u32));
        assert_eq!(parsed.b.to_str_radix(10), served["b"].to_string());
        assert!(parsed.proof.is_none(), "the capture carries no proof");

        // Re-emitting must reproduce the node's own field types and
        // values for every Scala-parity field. `template_seq` /
        // `clean_jobs` are this node's documented additions and are
        // expected to appear; a client that ignores unknown fields
        // (Lithos / Rigel / ErgoStratum) is unaffected.
        let ours = serde_json::to_value(&parsed).expect("ser");
        for field in ["msg", "b", "h", "pk"] {
            assert_eq!(
                ours[field], served[field],
                "{field}: re-emitted value/type differs from the node's",
            );
        }
        assert!(ours.get("proof").is_none(), "proof stays omitted");
    }
}
