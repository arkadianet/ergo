//! SANTA authds conformance — full grading of the vendored
//! `AvlVerify.ergots_corpus` (blessed by `jvm:scrypto-3.0.0`).
//!
//! This is the same three-chained-dimension grading the SANTA runner
//! (`runners/vixen`, `src/authds.rs`) performs, now expressible end-to-end
//! because `AvlVerifier` reports what the corpus expects for every
//! operation tag:
//!
//! 1. **`proof_accepted`** — a verifier built from `starting_digest_hex` +
//!    `proof_hex` + settings (including the corpus-declared
//!    `max_num_operations` / `max_deletes` operation bounds, honored since
//!    the operation-bounds change) produced an initial digest before any op.
//! 2. **`results`** — one `{ok, value}` per operation, in order. `value` is
//!    the OLD value the proof witnessed (scrypto `performOneOperation`
//!    semantics), hex-encoded or null. Once one operation fails, every later
//!    one is emitted `{ok: false, value: null}` WITHOUT being performed —
//!    the verifier is poisoned.
//! 3. **`new_digest_hex`** — the digest after the last operation, null when
//!    any operation failed.
//!
//! The previously-ungradeable entry classes (Update / InsertOrUpdate /
//! RemoveIfExists / UpdateLongBy / UnknownModification) are covered by the
//! widened `AvlVerifier` surface; the adverse entries (malicious extra
//! nodes, mismatched key length, swapped digest, truncated proof) pin the
//! reject side.

use ergo_sigma::avl::AvlVerifier;

const VECTOR: &str = include_str!("../../test-vectors/santa/AvlVerify.ergots_corpus.json");

fn hexnull(v: Option<&Vec<u8>>) -> serde_json::Value {
    match v {
        Some(b) => serde_json::Value::String(hex::encode(b)),
        None => serde_json::Value::Null,
    }
}

fn okvalue(ok: bool, v: Option<&Vec<u8>>) -> serde_json::Value {
    serde_json::json!({ "ok": ok, "value": hexnull(v) })
}

#[test]
fn grades_full_avl_verify_corpus() {
    let v: serde_json::Value = serde_json::from_str(VECTOR).expect("vector JSON");
    let entries = v["entries"].as_array().expect("entries");
    assert!(entries.len() >= 30, "corpus should be non-trivial");

    let mut graded = 0usize;
    for e in entries {
        let name = e["name"].as_str().unwrap();
        let settings = &e["settings"];
        let payload = &e["payload"];
        let expected = &e["expected"];

        let key_length = settings["key_length"].as_u64().unwrap() as usize;
        let value_length = settings["value_length"].as_u64().map(|x| x as usize);
        let max_num_operations = settings["max_num_operations"].as_u64().map(|x| x as usize);
        let max_deletes = settings["max_deletes"].as_u64().map(|x| x as usize);

        let digest = hex::decode(payload["starting_digest_hex"].as_str().unwrap()).unwrap();
        let proof = hex::decode(payload["proof_hex"].as_str().unwrap()).unwrap();

        // Level 1 — construction + initial digest, before any operation.
        let mut verifier = match AvlVerifier::new(
            &digest,
            &proof,
            key_length,
            value_length,
            max_num_operations,
            max_deletes,
        ) {
            Ok(v) if v.digest().is_some() => v,
            _ => {
                assert_eq!(
                    expected["proof_accepted"], false,
                    "{name}: construction rejected but the corpus expects acceptance"
                );
                assert!(
                    expected["results"].as_array().unwrap().is_empty(),
                    "{name}: rejected construction must expect no results"
                );
                assert!(
                    expected["new_digest_hex"].is_null(),
                    "{name}: rejected construction must expect no digest"
                );
                graded += 1;
                continue;
            }
        };
        assert_eq!(
            expected["proof_accepted"], true,
            "{name}: construction accepted but the corpus expects rejection"
        );

        // Level 2 — one result per operation, unperformed after the first
        // failure (the verifier is poisoned).
        let mut results: Vec<serde_json::Value> = Vec::new();
        let mut poisoned = false;
        for op in payload["operations"].as_array().unwrap() {
            if poisoned {
                results.push(okvalue(false, None));
                continue;
            }
            let tag = op["tag"].as_str().unwrap();
            let key_hex = op["key_hex"].as_str().unwrap_or("");
            let key = hex::decode(key_hex).unwrap();
            let outcome: Result<Option<Vec<u8>>, ()> = match tag {
                "Lookup" => verifier.lookup(&key),
                "Insert" => {
                    let val = hex::decode(op["value_hex"].as_str().unwrap_or("")).unwrap();
                    verifier.insert(&key, &val)
                }
                "Update" => {
                    let val = hex::decode(op["value_hex"].as_str().unwrap_or("")).unwrap();
                    verifier.update(&key, &val)
                }
                "InsertOrUpdate" => {
                    let val = hex::decode(op["value_hex"].as_str().unwrap_or("")).unwrap();
                    verifier.insert_or_update(&key, &val)
                }
                "Remove" => verifier.remove_returning_value(&key),
                "RemoveIfExists" => verifier.remove_if_exists(&key),
                "UpdateLongBy" => verifier.update_long_by(&key, op["delta"].as_i64().unwrap_or(0)),
                "UnknownModification" => verifier.unknown_modification(&key),
                other => panic!("{name}: unsupported op tag {other} — widen the grader"),
            };
            match outcome {
                Ok(old) => results.push(okvalue(true, old.as_ref())),
                Err(()) => {
                    results.push(okvalue(false, None));
                    poisoned = true;
                }
            }
        }
        assert_eq!(
            serde_json::Value::Array(results),
            expected["results"],
            "{name}: operation results diverge from the scrypto blessing"
        );

        // Level 3 — post-ops digest, null when any operation failed.
        let new_digest = if poisoned {
            None
        } else {
            verifier.digest().map(|d| hex::encode(&d))
        };
        assert_eq!(
            new_digest,
            expected["new_digest_hex"].as_str().map(|s| s.to_string()),
            "{name}: post-operation digest diverges from the scrypto blessing"
        );
        graded += 1;
    }
    // The vendored corpus must be graded in full — a silently-skipped entry
    // would be an undetected coverage gap.
    assert_eq!(graded, entries.len(), "every corpus entry must be graded");
}
