//! Byte-parity oracle tests for multi-sig proof extraction.
//!
//! Fixtures in test-vectors/scala/multi_sig_*.json were produced by
//! extract-tools/sigma-rust-multisig-oracle (a standalone binary that calls
//! sigma-rust's TestProver + bag_for_multi_sig). sigma-rust is the canonical
//! Rust port of sigmastate; its proof wire format is byte-identical to Scala.
//!
//! Each test:
//!   1. Loads a fixture JSON (proposition + proof bytes + expected hints).
//!   2. Reconstructs our SigmaBoolean from the proposition JSON.
//!   3. Feeds sigma-rust's proof bytes to OUR bag_for_multisig.
//!   4. Asserts that the extracted challenges are byte-identical to sigma-rust's
//!      extracted challenges. Challenges are deterministic from proof bytes
//!      (no randomness), so mismatch = real parity break in our parser.
//!   5. Verifies the proof passes OUR verifier.
//!
//! If a test fails with a challenge mismatch, stop immediately and report the
//! divergence — do NOT adjust the test to paper over it.

use ergo_primitives::group_element::GroupElement;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_wallet::proving::extract::bag_for_multisig;
use ergo_wallet::proving::hints::Hint;
use serde_json::Value;
use std::{fs, path::Path};

// ---------------------------------------------------------------------------
// Fixture loading helpers
// ---------------------------------------------------------------------------

fn load_fixture(name: &str) -> Value {
    // CARGO_MANIFEST_DIR points to ergo-wallet/ at compile time (set by cargo).
    // The fixtures live at workspace-root/test-vectors/scala/ which is ../test-vectors/scala
    // relative to ergo-wallet/.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest_dir)
        .join("../test-vectors/scala")
        .join(format!("multi_sig_{}.json", name));
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("load fixture {:?}: {}", path, e));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse fixture {:?}: {}", path, e))
}

/// Reconstruct our SigmaBoolean from the proposition JSON emitted by the
/// extraction binary.
fn sb_from_json(v: &Value) -> SigmaBoolean {
    let ty = v["type"].as_str().expect("type field missing");
    match ty {
        "ProveDlog" => {
            let pk_hex = v["pk"].as_str().expect("pk field missing");
            let pk_bytes: [u8; 33] = hex::decode(pk_hex)
                .expect("pk hex decode")
                .try_into()
                .expect("pk must be 33 bytes");
            SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_bytes))
        }
        "ProveDhTuple" => {
            let g = point_from_field(v, "g");
            let h = point_from_field(v, "h");
            let u = point_from_field(v, "u");
            let v_pt = point_from_field(v, "v");
            SigmaBoolean::ProveDHTuple { g, h, u, v: v_pt }
        }
        "Cand" => {
            let children: Vec<SigmaBoolean> = v["children"]
                .as_array()
                .expect("Cand children must be array")
                .iter()
                .map(sb_from_json)
                .collect();
            SigmaBoolean::Cand(children)
        }
        "Cor" => {
            let children: Vec<SigmaBoolean> = v["children"]
                .as_array()
                .expect("Cor children must be array")
                .iter()
                .map(sb_from_json)
                .collect();
            SigmaBoolean::Cor(children)
        }
        "Cthreshold" => {
            let k = u16::try_from(v["k"].as_u64().expect("k field missing"))
                .expect("Cthreshold.k out of u16 range");
            let children: Vec<SigmaBoolean> = v["children"]
                .as_array()
                .expect("Cthreshold children must be array")
                .iter()
                .map(sb_from_json)
                .collect();
            SigmaBoolean::Cthreshold { k, children }
        }
        other => panic!("unknown proposition type: {}", other),
    }
}

fn point_from_field(v: &Value, field: &str) -> GroupElement {
    let hex = v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{} field missing", field));
    let bytes: [u8; 33] = hex::decode(hex)
        .expect("point hex decode")
        .try_into()
        .expect("point must be 33 bytes");
    GroupElement::from_bytes(bytes)
}

/// Extract challenge hex strings from sigma-rust's hint JSON list.
/// Only counts RealSecretProof and SimulatedSecretProof entries.
fn oracle_challenges(fixture: &Value) -> Vec<(String, String)> {
    fixture["extracted_hints"]
        .as_array()
        .expect("extracted_hints must be array")
        .iter()
        .filter_map(|h| {
            let kind = h["kind"].as_str()?;
            if kind == "RealSecretProof" || kind == "SimulatedSecretProof" {
                let challenge = h["challenge"].as_str()?.to_string();
                Some((kind.to_string(), challenge))
            } else {
                None
            }
        })
        .collect()
}

/// Extract challenge hex strings from OUR extracted hints bag.
fn our_challenges(bag: &ergo_wallet::proving::hints::HintsBag) -> Vec<(String, String)> {
    bag.hints
        .iter()
        .filter_map(|h| match h {
            Hint::RealSecretProof(rsp) => {
                Some(("RealSecretProof".to_string(), hex::encode(rsp.challenge)))
            }
            Hint::SimulatedSecretProof(ssp) => Some((
                "SimulatedSecretProof".to_string(),
                hex::encode(ssp.challenge),
            )),
            _ => None,
        })
        .collect()
}

/// Verify the proof through our sigma verifier.
fn verify_proof(tree: &SigmaBoolean, proof: &[u8], message: &[u8]) -> bool {
    ergo_sigma::verify::verify_sigma_proof(tree, proof, message).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Test 1: 2-of-2 AND(Dlog, Dlog)
// ---------------------------------------------------------------------------

#[test]
fn oracle_two_of_two_and_byte_parity() {
    let fixture = load_fixture("two_of_two_and");

    let sigma_tree = sb_from_json(&fixture["proposition"]);

    let proof_hex = fixture["proof_hex"].as_str().expect("proof_hex missing");
    let proof_bytes = hex::decode(proof_hex).expect("proof hex decode");

    let message_hex = fixture["message_hex"]
        .as_str()
        .expect("message_hex missing");
    let message = hex::decode(message_hex).expect("message hex decode");

    let real_props: Vec<SigmaBoolean> = fixture["real_propositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(sb_from_json)
        .collect();
    let sim_props: Vec<SigmaBoolean> = fixture["simulated_propositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(sb_from_json)
        .collect();

    // Verify sigma-rust's proof passes our verifier.
    assert!(
        verify_proof(&sigma_tree, &proof_bytes, &message),
        "sigma-rust proof must verify against our verifier (parity break if false)"
    );

    let bag = bag_for_multisig(&sigma_tree, &proof_bytes, &real_props, &sim_props)
        .unwrap_or_else(|e| panic!("bag_for_multisig failed: {:?}", e));

    let oracle = oracle_challenges(&fixture);
    let ours = our_challenges(&bag);

    assert_eq!(
        oracle.len(),
        ours.len(),
        "hint count mismatch:\n  sigma-rust: {}\n  ours: {}",
        oracle.len(),
        ours.len()
    );

    for (i, (oracle_hint, our_hint)) in oracle.iter().zip(ours.iter()).enumerate() {
        assert_eq!(
            oracle_hint, our_hint,
            "hint[{}] parity break:\n  sigma-rust: {:?}\n  ours: {:?}\n\
             Mismatch means our proof parser diverges from sigma-rust's wire format.",
            i, oracle_hint, our_hint
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: 2-of-3 Cthreshold k=2
// ---------------------------------------------------------------------------

#[test]
fn oracle_two_of_three_threshold_byte_parity() {
    let fixture = load_fixture("two_of_three_threshold");

    let sigma_tree = sb_from_json(&fixture["proposition"]);

    let proof_hex = fixture["proof_hex"].as_str().expect("proof_hex missing");
    let proof_bytes = hex::decode(proof_hex).expect("proof hex decode");

    let message_hex = fixture["message_hex"]
        .as_str()
        .expect("message_hex missing");
    let message = hex::decode(message_hex).expect("message hex decode");

    let real_props: Vec<SigmaBoolean> = fixture["real_propositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(sb_from_json)
        .collect();
    let sim_props: Vec<SigmaBoolean> = fixture["simulated_propositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(sb_from_json)
        .collect();

    assert!(
        verify_proof(&sigma_tree, &proof_bytes, &message),
        "sigma-rust threshold proof must verify against our verifier"
    );

    let bag = bag_for_multisig(&sigma_tree, &proof_bytes, &real_props, &sim_props)
        .unwrap_or_else(|e| panic!("bag_for_multisig failed: {:?}", e));

    let oracle = oracle_challenges(&fixture);
    let ours = our_challenges(&bag);

    assert_eq!(
        oracle.len(),
        ours.len(),
        "hint count mismatch:\n  sigma-rust: {}\n  ours: {}",
        oracle.len(),
        ours.len()
    );

    for (i, (oracle_hint, our_hint)) in oracle.iter().zip(ours.iter()).enumerate() {
        assert_eq!(
            oracle_hint, our_hint,
            "hint[{}] parity break:\n  sigma-rust: {:?}\n  ours: {:?}\n\
             Mismatch means our threshold proof parser diverges from sigma-rust.",
            i, oracle_hint, our_hint
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: AND(Dlog, DHTuple) mixed compound
// ---------------------------------------------------------------------------

#[test]
fn oracle_mixed_dlog_dht_compound_byte_parity() {
    let fixture = load_fixture("mixed_dlog_dht");

    let sigma_tree = sb_from_json(&fixture["proposition"]);

    let proof_hex = fixture["proof_hex"].as_str().expect("proof_hex missing");
    let proof_bytes = hex::decode(proof_hex).expect("proof hex decode");

    let message_hex = fixture["message_hex"]
        .as_str()
        .expect("message_hex missing");
    let message = hex::decode(message_hex).expect("message hex decode");

    let real_props: Vec<SigmaBoolean> = fixture["real_propositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(sb_from_json)
        .collect();
    let sim_props: Vec<SigmaBoolean> = fixture["simulated_propositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(sb_from_json)
        .collect();

    assert!(
        verify_proof(&sigma_tree, &proof_bytes, &message),
        "sigma-rust mixed AND(Dlog, DHT) proof must verify against our verifier"
    );

    let bag = bag_for_multisig(&sigma_tree, &proof_bytes, &real_props, &sim_props)
        .unwrap_or_else(|e| panic!("bag_for_multisig failed: {:?}", e));

    let oracle = oracle_challenges(&fixture);
    let ours = our_challenges(&bag);

    assert_eq!(
        oracle.len(),
        ours.len(),
        "hint count mismatch:\n  sigma-rust: {}\n  ours: {}",
        oracle.len(),
        ours.len()
    );

    for (i, (oracle_hint, our_hint)) in oracle.iter().zip(ours.iter()).enumerate() {
        assert_eq!(
            oracle_hint, our_hint,
            "hint[{}] parity break:\n  sigma-rust: {:?}\n  ours: {:?}\n\
             Mismatch means our AND(Dlog,DHT) proof parser diverges from sigma-rust.",
            i, oracle_hint, our_hint
        );
    }
}
