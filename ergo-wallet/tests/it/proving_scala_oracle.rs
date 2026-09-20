//! Scala signing-spec oracle — verify-side parity tests.
//!
//! Loads the 8 byte-pinned proof vectors committed under
//! `test-vectors/scala/proving/scala_signing_spec.json` and asserts our
//! `ergo_sigma::verify::verify_sigma_proof` accepts the exact byte-for-byte
//! signatures Scala produced for the same propositions.
//!
//! Source vectors: `reference/sigmastate-interpreter/interpreter/shared/
//! src/test/scala/sigmastate/crypto/SigningSpecification.scala`.
//!
//! Scope: verify-side parity. Prove-side byte parity is not yet
//! covered — see the JSON fixture's adjacent README for the trust chain
//! and the full list of what is NOT covered.

use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{read_value, SigmaBoolean, SigmaValue};
use ergo_sigma::verify::verify_sigma_proof;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use num_bigint::BigUint;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

/// `SigmaBooleanSerializer` tag byte for `ProveDHTuple` — `0xCE`. Prepended
/// to the Scala-pinned 132-byte body so the proposition flows through the
/// production wire reader (`read_value(_, SSigmaProp)`), not an ad-hoc slicer.
const PROVE_DHTUPLE_TAG: u8 = 0xCE;

const VECTORS_PATH: &str = "../test-vectors/scala/proving/scala_signing_spec.json";
const SK_A_PK_HEX_SCALA_PINNED: &str =
    "03cb0d49e4eae7e57059a3da8ac52626d26fc11330af8fb093fa597d8b93deb7b1";

/// SHA-256 of each Scala-produced signature, byte-by-byte. Pinned in test
/// source so the JSON cannot be silently retargeted to non-Scala vectors —
/// any swap of `signature_hex` for a valid-but-different proof would still
/// verify but would break these hashes.
const SIGNATURE_DIGESTS: &[(&str, &str)] = &[
    (
        "simple_schnorr",
        "9bf2f011f5c4598b06a1b66734abe424d27981ddcf88bad78e0fbb856c27d74a",
    ),
    (
        "prove_dht",
        "d7fc36b6edab6ac92c3359e3ba20671a6473a9ade06a92a8341f9b67afbb5fc3",
    ),
    (
        "and_2",
        "fbdfeab24b1ce86f2a96a726a135534788a722a0c05c48b4c9bd99db7fdb263c",
    ),
    (
        "or_2",
        "9ee3922cef8b13179fd54a4849bb09f6d2c9b89e2b00802f8f4d40a76d57a708",
    ),
    (
        "or_dlog_dht",
        "0203a427752f169fb107a0cffe11107b48fd7ab13d45b6af1fb4ef00b9123f38",
    ),
    (
        "and_dlog_or_dlog_dlog",
        "eafdf4925cc712f16bb74eda9a0a3ac0f3726f14d4e7eb9fc1790fc7ed43e25d",
    ),
    (
        "or_dlog_and_dlog_dlog",
        "f3de4a76cde83d42a5dadf541190cda6c6f4e8290071c0c8299fe2fb8ca2c570",
    ),
    (
        "threshold_2_of_3",
        "5719e347fc5093da2ac558d3457afaa1b22fd7e80c25c62377607d35e6a98348",
    ),
    // OR branch-position isolation + threshold(2-of-5) residuals:
    (
        "or_2_real_first_only",
        "40945d12512ea0e310d5d5be0c4065dc59a902ad2dd2e9ec6e9e2ca03a1ddf76",
    ),
    (
        "or_2_real_last_only",
        "0cf968a3216459175547f1361db7b46d567e90ab5c00920c7934bf68b973613d",
    ),
    (
        "threshold_2_of_5",
        "091cf4a0a81660ad894fe2bbcc5310f6eaca4f770a88aff9a6481869ba21eaa7",
    ),
];

// ----- helpers -----

fn load() -> JsonValue {
    let raw = std::fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("read {VECTORS_PATH}: {e}"));
    serde_json::from_str(&raw).expect("parse scala_signing_spec.json")
}

fn scalar_from_dec(dec: &str) -> Scalar {
    let n =
        BigUint::parse_bytes(dec.as_bytes(), 10).unwrap_or_else(|| panic!("parse sk_dec {dec}"));
    let mut be = n.to_bytes_be();
    assert!(
        be.len() <= 32,
        "sk_dec {dec} exceeds 32-byte secp256k1 scalar size"
    );
    while be.len() < 32 {
        be.insert(0, 0u8);
    }
    let arr: [u8; 32] = be.try_into().expect("padded to 32 bytes");
    Scalar::from_repr(FieldBytes::from(arr))
        .into_option()
        .unwrap_or_else(|| panic!("sk_dec {dec} is not a valid secp256k1 scalar"))
}

fn pubkey_compressed(s: &Scalar) -> [u8; 33] {
    ProjectivePoint::mul_by_generator(s)
        .to_affine()
        .to_bytes()
        .into()
}

fn pk_for_idx(secrets: &JsonValue, idx: &str) -> [u8; 33] {
    let key = format!("sk_{idx}_dec");
    let dec = secrets[&key]
        .as_str()
        .unwrap_or_else(|| panic!("secrets.{key} missing/not-string"));
    pubkey_compressed(&scalar_from_dec(dec))
}

fn parse_prove_dht_raw(raw_hex: &str) -> SigmaBoolean {
    let body = hex::decode(raw_hex).unwrap_or_else(|e| panic!("decode dht raw hex: {e}"));
    assert_eq!(
        body.len(),
        4 * 33,
        "ProveDhTuple raw_hex body must be 132 bytes (4 SEC1-compressed points), got {}",
        body.len()
    );
    // Prepend the SigmaBoolean tag and feed the wire into the production
    // reader. This exercises the actual deserialize path a Scala-sent
    // proposition would take, not a slice cast.
    let mut wire = Vec::with_capacity(1 + body.len());
    wire.push(PROVE_DHTUPLE_TAG);
    wire.extend_from_slice(&body);
    let mut r = VlqReader::new(&wire);
    let val = read_value(&mut r, &SigmaType::SSigmaProp)
        .unwrap_or_else(|e| panic!("read_value(SSigmaProp) on DHT raw_hex: {e:?}"));
    // Trailing bytes would silently widen the oracle claim: any future
    // fixture with garbage past the proposition would still pass.
    assert!(
        r.is_empty(),
        "DHT wire had {} trailing bytes after read_value — fixture wider than the ProveDhTuple body",
        r.remaining()
    );
    match val {
        SigmaValue::SigmaProp(sb @ SigmaBoolean::ProveDHTuple { .. }) => sb,
        other => panic!("expected SigmaProp(ProveDHTuple), got {other:?}"),
    }
}

fn build_proposition(secrets: &JsonValue, node: &JsonValue) -> SigmaBoolean {
    let kind = node["kind"].as_str().expect("proposition.kind");
    match kind {
        "ProveDlog" => {
            let idx = node["sk_idx"].as_str().expect("ProveDlog.sk_idx");
            SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_for_idx(secrets, idx)))
        }
        "ProveDhTuple" => {
            let raw = node["raw_hex"].as_str().expect("ProveDhTuple.raw_hex");
            parse_prove_dht_raw(raw)
        }
        "Cand" => {
            let children = node["children"].as_array().expect("Cand.children array");
            SigmaBoolean::Cand(
                children
                    .iter()
                    .map(|c| build_proposition(secrets, c))
                    .collect(),
            )
        }
        "Cor" => {
            let children = node["children"].as_array().expect("Cor.children array");
            SigmaBoolean::Cor(
                children
                    .iter()
                    .map(|c| build_proposition(secrets, c))
                    .collect(),
            )
        }
        "Cthreshold" => {
            let k = node["k"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .expect("Cthreshold.k u16");
            let children = node["children"]
                .as_array()
                .expect("Cthreshold.children array");
            SigmaBoolean::Cthreshold {
                k,
                children: children
                    .iter()
                    .map(|c| build_proposition(secrets, c))
                    .collect(),
            }
        }
        other => panic!("unknown proposition kind: {other}"),
    }
}

struct LoadedVector {
    prop: SigmaBoolean,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

fn vector_by_name(vectors: &JsonValue, name: &str) -> LoadedVector {
    let secrets = &vectors["secrets"];
    let msg_hex = vectors["msg_hex_shared"]
        .as_str()
        .expect("msg_hex_shared string");
    let entry = vectors["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no fixture vector named {name}"));
    let prop = build_proposition(secrets, &entry["proposition"]);
    let msg = hex::decode(msg_hex).expect("msg_hex_shared decode");
    let sig_hex = entry["signature_hex"].as_str().expect("signature_hex");
    let sig = hex::decode(sig_hex).expect("signature_hex decode");
    LoadedVector { prop, msg, sig }
}

fn assert_verifies(name: &str) {
    let vectors = load();
    let v = vector_by_name(&vectors, name);
    let ok = verify_sigma_proof(&v.prop, &v.sig, &v.msg)
        .unwrap_or_else(|e| panic!("{name}: verify errored: {e:?}"));
    assert!(ok, "{name}: Scala-produced signature did not verify");
}

fn assert_sig_tamper_rejects(name: &str) {
    let vectors = load();
    let v = vector_by_name(&vectors, name);
    let mut tampered = v.sig.clone();
    assert!(
        !tampered.is_empty(),
        "{name}: empty signature, cannot tamper"
    );
    tampered[0] ^= 0x01;
    let result = verify_sigma_proof(&v.prop, &tampered, &v.msg);
    let accepted = matches!(result, Ok(true));
    assert!(
        !accepted,
        "{name}: tampered signature (flipped low bit of byte 0) was accepted — verifier is not binding to signature bytes"
    );
}

fn assert_msg_tamper_rejects(name: &str) {
    let vectors = load();
    let v = vector_by_name(&vectors, name);
    let mut tampered_msg = v.msg.clone();
    assert!(
        !tampered_msg.is_empty(),
        "{name}: empty message, cannot tamper"
    );
    tampered_msg[0] ^= 0x01;
    let result = verify_sigma_proof(&v.prop, &v.sig, &tampered_msg);
    let accepted = matches!(result, Ok(true));
    assert!(
        !accepted,
        "{name}: original signature accepted under tampered message (flipped low bit of byte 0) — verifier is not binding to message"
    );
}

// ----- anchor: pubkey derivation matches Scala source -----

#[test]
fn sk_a_derivation_matches_scala_pinned_pubkey() {
    // SigningSpecification.scala:22 explicitly pins:
    //   Base16.encode(sk.publicImage.pkBytes) shouldBe "03cb0d49...debe7b1"
    // for sk_dec = 1097...157746. If our k256-based derivation diverges from
    // this, every other vector's pk derivation in this file is suspect.
    let vectors = load();
    let dec = vectors["secrets"]["sk_a_dec"].as_str().unwrap();
    let derived = pubkey_compressed(&scalar_from_dec(dec));
    let pinned = hex::decode(SK_A_PK_HEX_SCALA_PINNED).unwrap();
    assert_eq!(
        derived.as_slice(),
        pinned.as_slice(),
        "k256 derivation of sk_a does not match Scala-pinned pkBytes — \
         downstream pk_for_idx results cannot be trusted"
    );
    let pinned_in_json = vectors["secrets"]["sk_a_pk_hex_scala_pinned"]
        .as_str()
        .unwrap();
    assert_eq!(
        pinned_in_json, SK_A_PK_HEX_SCALA_PINNED,
        "JSON sk_a_pk_hex_scala_pinned drifted from the constant in this test"
    );
}

// ----- corpus pin -----

#[test]
fn corpus_count_matches_declaration() {
    // Silent shrinkage of the fixture (e.g. accidentally deleted vector)
    // should fail loudly. Both the JSON's _corpus_count header and the
    // hard-coded 8 must match the actual vectors.len().
    let vectors = load();
    let declared = vectors["_corpus_count"]
        .as_u64()
        .expect("_corpus_count u64");
    let actual = vectors["vectors"].as_array().expect("vectors array").len();
    assert_eq!(
        declared as usize, actual,
        "JSON _corpus_count != vectors.len()"
    );
    assert_eq!(
        actual, 11,
        "expected 11 Scala-pinned vectors (8 from sigma-state SigningSpecification + 3 OR/threshold residuals)"
    );
}

// ----- happy path: 8 verify-only positive tests, one per Scala vector -----

#[test]
fn simple_schnorr_verifies() {
    assert_verifies("simple_schnorr");
}

#[test]
fn prove_dht_verifies() {
    assert_verifies("prove_dht");
}

#[test]
fn and_2_verifies() {
    assert_verifies("and_2");
}

#[test]
fn or_2_verifies() {
    assert_verifies("or_2");
}

#[test]
fn or_dlog_dht_verifies() {
    assert_verifies("or_dlog_dht");
}

#[test]
fn and_dlog_or_dlog_dlog_verifies() {
    assert_verifies("and_dlog_or_dlog_dlog");
}

#[test]
fn or_dlog_and_dlog_dlog_verifies() {
    assert_verifies("or_dlog_and_dlog_dlog");
}

#[test]
fn threshold_2_of_3_verifies() {
    assert_verifies("threshold_2_of_3");
}

// ----- error paths: tampered signatures must reject -----

#[test]
fn simple_schnorr_rejects_tamper() {
    assert_sig_tamper_rejects("simple_schnorr");
}

#[test]
fn prove_dht_rejects_tamper() {
    assert_sig_tamper_rejects("prove_dht");
}

#[test]
fn and_2_rejects_tamper() {
    assert_sig_tamper_rejects("and_2");
}

#[test]
fn or_2_rejects_tamper() {
    assert_sig_tamper_rejects("or_2");
}

#[test]
fn or_dlog_dht_rejects_tamper() {
    assert_sig_tamper_rejects("or_dlog_dht");
}

#[test]
fn and_dlog_or_dlog_dlog_rejects_tamper() {
    assert_sig_tamper_rejects("and_dlog_or_dlog_dlog");
}

#[test]
fn or_dlog_and_dlog_dlog_rejects_tamper() {
    assert_sig_tamper_rejects("or_dlog_and_dlog_dlog");
}

#[test]
fn threshold_2_of_3_rejects_tamper() {
    assert_sig_tamper_rejects("threshold_2_of_3");
}

// ----- error paths: tampered messages must reject -----

#[test]
fn simple_schnorr_rejects_msg_tamper() {
    assert_msg_tamper_rejects("simple_schnorr");
}

#[test]
fn prove_dht_rejects_msg_tamper() {
    assert_msg_tamper_rejects("prove_dht");
}

#[test]
fn and_2_rejects_msg_tamper() {
    assert_msg_tamper_rejects("and_2");
}

#[test]
fn or_2_rejects_msg_tamper() {
    assert_msg_tamper_rejects("or_2");
}

#[test]
fn or_dlog_dht_rejects_msg_tamper() {
    assert_msg_tamper_rejects("or_dlog_dht");
}

#[test]
fn and_dlog_or_dlog_dlog_rejects_msg_tamper() {
    assert_msg_tamper_rejects("and_dlog_or_dlog_dlog");
}

#[test]
fn or_dlog_and_dlog_dlog_rejects_msg_tamper() {
    assert_msg_tamper_rejects("or_dlog_and_dlog_dlog");
}

#[test]
fn threshold_2_of_3_rejects_msg_tamper() {
    assert_msg_tamper_rejects("threshold_2_of_3");
}

// ----- residuals: OR branch-position isolation + threshold(2-of-5) -----
// Captured via extract-tools/scala-signing-harness/SigningResidualsSpec.scala
// against reference/sigmastate-interpreter/. These close two verifier-confidence
// gaps: a branch-position-specific verifier bug or an n>3-threshold parsing bug
// would surface in these vectors.

#[test]
fn or_2_real_first_only_verifies() {
    assert_verifies("or_2_real_first_only");
}

#[test]
fn or_2_real_first_only_rejects_tamper() {
    assert_sig_tamper_rejects("or_2_real_first_only");
}

#[test]
fn or_2_real_first_only_rejects_msg_tamper() {
    assert_msg_tamper_rejects("or_2_real_first_only");
}

#[test]
fn or_2_real_last_only_verifies() {
    assert_verifies("or_2_real_last_only");
}

#[test]
fn or_2_real_last_only_rejects_tamper() {
    assert_sig_tamper_rejects("or_2_real_last_only");
}

#[test]
fn or_2_real_last_only_rejects_msg_tamper() {
    assert_msg_tamper_rejects("or_2_real_last_only");
}

#[test]
fn threshold_2_of_5_verifies() {
    assert_verifies("threshold_2_of_5");
}

#[test]
fn threshold_2_of_5_rejects_tamper() {
    assert_sig_tamper_rejects("threshold_2_of_5");
}

#[test]
fn threshold_2_of_5_rejects_msg_tamper() {
    assert_msg_tamper_rejects("threshold_2_of_5");
}

// ----- provenance pin: every fixture signature must match its hardcoded SHA-256 -----

#[test]
fn signature_bytes_match_pinned_sha256_digests() {
    // The JSON `signature_hex` for each vector must SHA-256-equal the
    // value pinned in SIGNATURE_DIGESTS at the top of this file. This is
    // a strong anti-drift gate: swapping in a different-but-valid proof
    // for the same proposition would still verify under our verifier,
    // but would fail this hash check.
    let vectors = load();
    let arr = vectors["vectors"].as_array().expect("vectors array");
    assert_eq!(
        arr.len(),
        SIGNATURE_DIGESTS.len(),
        "vectors count drifted from SIGNATURE_DIGESTS pinned in test source"
    );
    for v in arr {
        let name = v["name"].as_str().expect("vector name");
        let sig_hex = v["signature_hex"].as_str().expect("signature_hex");
        let bytes = hex::decode(sig_hex).unwrap_or_else(|e| panic!("{name}: hex {e}"));
        let actual = hex::encode(Sha256::digest(&bytes));
        let expected = SIGNATURE_DIGESTS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, d)| *d)
            .unwrap_or_else(|| panic!("{name}: no SIGNATURE_DIGESTS entry — drift"));
        assert_eq!(
            actual, expected,
            "{name}: signature SHA-256 mismatch — JSON fixture has drifted from the Scala-pinned bytes"
        );
    }
}
