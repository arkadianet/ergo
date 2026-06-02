//! Round-trip tests for the `TxHintsBagDto` wire shape.
//!
//! Exercises every `HintDto` variant + `FirstProverMessageJson` variant through
//! `serde_json::to_string` → `serde_json::from_str` and checks structural
//! equality. Also pins the `hint` / `op` tag names to their canonical
//! Scala/sigma-rust values so a schema regression shows up immediately.

use ergo_api::wallet::sending::{FirstProverMessageJson, HintDto, SigmaBooleanJson, TxHintsBagDto};

// ----- helpers -----

fn fake_point_hex() -> String {
    // 33 bytes: SEC1 compressed prefix (0x02) + 32 zero bytes.
    format!("02{}", "00".repeat(32))
}

fn fake_challenge_hex() -> String {
    // 24 bytes.
    "cc".repeat(24)
}

fn fake_response_hex() -> String {
    // 32 bytes.
    "dd".repeat(32)
}

fn fake_secret_hex() -> String {
    // 32 bytes scalar.
    "ee".repeat(32)
}

fn fake_image() -> SigmaBooleanJson {
    SigmaBooleanJson {
        inner: serde_json::json!({
            "op": "205",
            "h": fake_point_hex()
        }),
    }
}

fn dlog_commitment() -> FirstProverMessageJson {
    FirstProverMessageJson::Dlog {
        a: fake_point_hex(),
    }
}

fn dht_commitment() -> FirstProverMessageJson {
    FirstProverMessageJson::DhTuple {
        a: fake_point_hex(),
        b: fake_point_hex(),
    }
}

fn roundtrip<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
    v: &T,
) -> T {
    let json = serde_json::to_string(v).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}

// ----- happy path -----

#[test]
fn round_trip_real_commitment() {
    let hint = HintDto::RealCommitment {
        image: fake_image(),
        commitment: dlog_commitment(),
        position: "1".to_string(),
    };
    assert_eq!(roundtrip(&hint), hint);
}

#[test]
fn round_trip_simulated_commitment() {
    let hint = HintDto::SimulatedCommitment {
        image: fake_image(),
        commitment: dht_commitment(),
        challenge: fake_challenge_hex(),
        position: "1-0".to_string(),
    };
    assert_eq!(roundtrip(&hint), hint);
}

#[test]
fn round_trip_own_commitment() {
    let hint = HintDto::OwnCommitment {
        image: fake_image(),
        secret: fake_secret_hex(),
        commitment: dlog_commitment(),
        position: "1".to_string(),
    };
    assert_eq!(roundtrip(&hint), hint);
}

#[test]
fn round_trip_real_secret_proof() {
    let hint = HintDto::RealSecretProof {
        image: fake_image(),
        challenge: fake_challenge_hex(),
        response: fake_response_hex(),
        position: "1-1".to_string(),
    };
    assert_eq!(roundtrip(&hint), hint);
}

#[test]
fn round_trip_simulated_secret_proof() {
    let hint = HintDto::SimulatedSecretProof {
        image: fake_image(),
        challenge: fake_challenge_hex(),
        response: fake_response_hex(),
        position: "1-0-2".to_string(),
    };
    assert_eq!(roundtrip(&hint), hint);
}

#[test]
fn round_trip_full_bag_all_variants() {
    let mut bag = TxHintsBagDto::default();

    // input 0: own commitment (secret side)
    bag.secret_hints.insert(
        "0".to_string(),
        vec![HintDto::OwnCommitment {
            image: fake_image(),
            secret: fake_secret_hex(),
            commitment: dlog_commitment(),
            position: "1".to_string(),
        }],
    );

    // input 0: real commitment + simulated commitment (public side)
    bag.public_hints.insert(
        "0".to_string(),
        vec![
            HintDto::RealCommitment {
                image: fake_image(),
                commitment: dlog_commitment(),
                position: "1".to_string(),
            },
            HintDto::SimulatedCommitment {
                image: fake_image(),
                commitment: dht_commitment(),
                challenge: fake_challenge_hex(),
                position: "1-0".to_string(),
            },
            HintDto::RealSecretProof {
                image: fake_image(),
                challenge: fake_challenge_hex(),
                response: fake_response_hex(),
                position: "1".to_string(),
            },
            HintDto::SimulatedSecretProof {
                image: fake_image(),
                challenge: fake_challenge_hex(),
                response: fake_response_hex(),
                position: "1-0".to_string(),
            },
        ],
    );

    let rt = roundtrip(&bag);
    assert_eq!(rt.secret_hints, bag.secret_hints);
    assert_eq!(rt.public_hints, bag.public_hints);
}

// ----- round-trips -----

#[test]
fn first_prover_message_dlog_roundtrip() {
    let fpm = FirstProverMessageJson::Dlog {
        a: fake_point_hex(),
    };
    assert_eq!(roundtrip(&fpm), fpm);
}

#[test]
fn first_prover_message_dht_roundtrip() {
    let fpm = FirstProverMessageJson::DhTuple {
        a: fake_point_hex(),
        b: fake_point_hex(),
    };
    assert_eq!(roundtrip(&fpm), fpm);
}

// ----- oracle parity -----

/// Pin the `hint` tag values to the Scala/sigma-rust canonical names.
#[test]
fn hint_tag_names_pinned() {
    let real_cmt = HintDto::RealCommitment {
        image: fake_image(),
        commitment: dlog_commitment(),
        position: "1".to_string(),
    };
    let json = serde_json::to_value(&real_cmt).unwrap();
    assert_eq!(json["hint"], "cmtReal");

    let sim_cmt = HintDto::SimulatedCommitment {
        image: fake_image(),
        commitment: dht_commitment(),
        challenge: fake_challenge_hex(),
        position: "1".to_string(),
    };
    let json = serde_json::to_value(&sim_cmt).unwrap();
    assert_eq!(json["hint"], "cmtSimulated");

    let own_cmt = HintDto::OwnCommitment {
        image: fake_image(),
        secret: fake_secret_hex(),
        commitment: dlog_commitment(),
        position: "1".to_string(),
    };
    let json = serde_json::to_value(&own_cmt).unwrap();
    assert_eq!(json["hint"], "cmtWithSecret");

    let real_proof = HintDto::RealSecretProof {
        image: fake_image(),
        challenge: fake_challenge_hex(),
        response: fake_response_hex(),
        position: "1".to_string(),
    };
    let json = serde_json::to_value(&real_proof).unwrap();
    assert_eq!(json["hint"], "proofReal");

    let sim_proof = HintDto::SimulatedSecretProof {
        image: fake_image(),
        challenge: fake_challenge_hex(),
        response: fake_response_hex(),
        position: "1".to_string(),
    };
    let json = serde_json::to_value(&sim_proof).unwrap();
    assert_eq!(json["hint"], "proofSimulated");
}

/// Pin the `op` tag values for `FirstProverMessageJson`.
#[test]
fn fpm_op_tag_names_pinned() {
    let dlog = FirstProverMessageJson::Dlog {
        a: fake_point_hex(),
    };
    let json = serde_json::to_value(&dlog).unwrap();
    assert_eq!(json["op"], "dlogA");

    let dht = FirstProverMessageJson::DhTuple {
        a: fake_point_hex(),
        b: fake_point_hex(),
    };
    let json = serde_json::to_value(&dht).unwrap();
    assert_eq!(json["op"], "dhtABab");
}

/// `node_position_to_str` and `node_position_from_str` roundtrip.
#[test]
fn node_position_str_roundtrip() {
    use ergo_api::wallet::sending::{node_position_from_str, node_position_to_str};

    let positions: Vec<u32> = vec![1, 0, 2];
    let s = node_position_to_str(&positions);
    assert_eq!(s, "1-0-2");
    let back = node_position_from_str(&s).unwrap();
    assert_eq!(back, positions);

    // crypto-tree prefix [0] → "0" (matches Scala NodePosition.CryptoTreePrefix)
    let prefix = vec![0u32];
    assert_eq!(node_position_to_str(&prefix), "0");
    assert_eq!(node_position_from_str("0").unwrap(), prefix);
}
