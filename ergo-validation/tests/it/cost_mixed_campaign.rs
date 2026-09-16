//! Oracle: test-vectors/ergo-sigma/cost-ledger/results/l6-2026-09-16.json
//! Live Scala 6.0.5 verdicts and JVM BuildBlock.scala transaction costs.

use std::{collections::BTreeMap, io::Read, path::Path};

use sha2::{Digest, Sha256};

use serde_json::Value;

// ----- helpers -----

fn campaign_members(root: &Path, results: &Value) -> BTreeMap<String, Vec<u8>> {
    let archive_path = "test-vectors/ergo-sigma/cost-ledger/results/l6-2026-09-16-artifacts.tar.gz";
    let bytes = std::fs::read(root.join(archive_path)).unwrap();
    assert_eq!(&bytes[3..8], &[0, 0, 0, 0, 0]); // No gzip filename or timestamp.
    let digest = hex::encode(Sha256::digest(&bytes));
    for run in results["runs"].as_array().unwrap() {
        assert_eq!(run["manifest"]["evidence"][archive_path], digest);
    }
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
    let mut members = BTreeMap::new();
    let mut index = String::new();
    let mut previous_name = String::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        assert!(entry.header().entry_type().is_file());
        assert_eq!(entry.header().mtime().unwrap(), 0);
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert_eq!(entry.header().gid().unwrap(), 0);
        let name = entry.path().unwrap().to_str().unwrap().to_owned();
        assert!(previous_name < name);
        previous_name.clone_from(&name);
        let mut payload = Vec::new();
        entry.read_to_end(&mut payload).unwrap();
        index.push_str(&format!(
            "{name}\t{}\t{}\n",
            payload.len(),
            hex::encode(Sha256::digest(&payload))
        ));
        assert!(members
            .insert(format!("{archive_path}#{name}"), payload)
            .is_none());
    }
    assert_eq!(
        index,
        std::fs::read_to_string(root.join(archive_path.replace(".tar.gz", ".index.txt"))).unwrap()
    );
    for run in results["runs"].as_array().unwrap() {
        for (name, expected) in run["manifest"]["evidence"].as_object().unwrap() {
            if name.starts_with(&format!("{archive_path}#")) {
                assert_eq!(
                    hex::encode(Sha256::digest(&members[name])),
                    expected.as_str().unwrap()
                );
            }
        }
    }
    members
}

fn commitment(info: &Value) -> (&Value, &Value, &Value) {
    (
        &info["fullHeight"],
        &info["bestFullHeaderId"],
        &info["stateRoot"],
    )
}

fn paired(infos: &Value) {
    assert!(infos["scala"]["fullHeight"].is_u64());
    assert_eq!(infos["scala"]["stateRoot"].as_str().unwrap().len(), 66);
    assert_eq!(commitment(&infos["scala"]), commitment(&infos["rust"]));
}

fn check_direction(direction: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = root.join("test-vectors/ergo-sigma/cost-ledger/results/l6-2026-09-16.json");
    let results: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let members = campaign_members(root, &results);
    let runs = results["runs"].as_array().unwrap();
    let successes: Vec<_> = runs
        .iter()
        .filter(|run| run["direction"] == direction && run["status"] == "PASS")
        .collect();
    assert_eq!(successes.len(), 1);
    let run = successes[0];
    assert_eq!(run["selected"], 7);
    assert_eq!(run["executed"], 7);
    assert_eq!(run["failed"], 0);
    assert_eq!(run["skipped"], 0);
    assert_eq!(run["stopped"], true);
    assert_eq!(run["manifest"]["scala"]["node_app_version"], "6.0.5");
    assert_eq!(run["manifest"]["context"]["voted_params"]["4"], 37509);
    let workload = run["workload"].as_array().unwrap();
    assert_eq!(workload.len(), 4);
    assert_eq!(workload[0]["selection"]["case"], "f-v6-devnet");
    for item in workload {
        paired(&item["before"]);
        paired(&item["after"]);
        assert_eq!(item["oracle"]["verdict"], "Accept");
        assert_eq!(
            item["after"]["scala"]["fullHeight"].as_u64().unwrap(),
            item["before"]["scala"]["fullHeight"].as_u64().unwrap() + 1
        );
        assert_eq!(
            item["after"]["scala"]["bestFullHeaderId"],
            item["block"]["header"]["id"]
        );
        assert!(item["block"]["blockTransactions"]["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tx| tx["id"] == item["transaction_id"]));
    }
    let injections = run["injections"].as_array().unwrap();
    assert_eq!(injections.len(), 4); // Funding and three cap boundaries.
    for (case, total, costs, verdict) in [
        ("sum-at-cap", 37509, vec![12503, 12503, 12503], "Accept"),
        (
            "sum-over-cap",
            37510,
            vec![12504, 12503, 12503],
            "RejectCost",
        ),
        ("single-at-cap", 37509, vec![37509], "Accept"),
    ] {
        let records: Vec<_> = injections.iter().filter(|r| r["case"] == case).collect();
        assert_eq!(records.len(), 1);
        let record = records[0];
        let oracle_path = record["artifacts"][".oracle.json"]["path"]
            .as_str()
            .unwrap();
        let oracle: Value = serde_json::from_reader(flate2::read::GzDecoder::new(
            members[oracle_path].as_slice(),
        ))
        .unwrap();
        assert_eq!(record["oracle"], oracle);
        paired(&record["before"]);
        paired(&record["after"]);
        assert_eq!(record["oracle"]["independent_tx_cost_sum"], total);
        assert_eq!(
            record["oracle"]["independent_tx_costs"],
            serde_json::json!(costs)
        );
        if verdict == "RejectCost" {
            assert_eq!(oracle["verdict"], "Reject");
            assert!(oracle["rejection_detail"]
                .as_str()
                .unwrap()
                .contains("CostLimitException"));
        } else {
            assert_eq!(oracle["verdict"], "Accept");
        }
        assert_eq!(
            record["oracle"]["state_root_before"],
            record["before"]["scala"]["stateRoot"]
        );
        assert_eq!(
            record["oracle"]["state_root_after"],
            record["after"]["scala"]["stateRoot"]
        );
        for node in ["scala", "rust"] {
            assert_eq!(record["verdicts"][node], verdict);
            if verdict == "RejectCost" {
                assert_eq!(
                    commitment(&record["before"][node]),
                    commitment(&record["after"][node])
                );
                let log = record["validation_logs"][node].as_str().unwrap();
                assert!(if node == "scala" {
                    log.contains("CostLimitException")
                } else {
                    log.contains("BlockCostExceeded")
                        || log.contains("block cost exceeded: total=37510, limit=37509")
                });
            } else {
                assert_eq!(
                    record["after"][node]["bestFullHeaderId"],
                    record["block_id"]
                );
                assert_eq!(
                    record["after"][node]["fullHeight"].as_u64().unwrap(),
                    record["before"][node]["fullHeight"].as_u64().unwrap() + 1
                );
            }
        }
    }
}

// ----- oracle parity -----

#[test]
fn mixed_campaign_scala_direction_matches_jvm_boundaries() {
    check_direction("scala-mines");
}

// ledger: BLOCK-rejection-state-unchanged
#[test]
fn mixed_campaign_both_directions_rejection_preserves_state() {
    for direction in ["scala-mines", "rust-mines"] {
        check_direction(direction);
    }
}

// ledger: BLOCK-L6-mining-safety-gap
#[test]
fn mixed_campaign_rust_low_cap_records_selection_divergence() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = root.join("test-vectors/ergo-sigma/cost-ledger/results/l6-2026-09-16.json");
    let results: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let members = campaign_members(root, &results);
    let archive = results["safety_gap_resolution"]["archived_result"]
        .as_str()
        .unwrap();
    let original: Value =
        serde_json::from_reader(flate2::read::GzDecoder::new(members[archive].as_slice())).unwrap();
    let results = original;
    let run = &results["runs"][1];
    assert_eq!(run["direction"], "rust-mines");
    assert_eq!(run["status"], "DIVERGENT");
    assert_eq!(run["executed"], 1);
    assert_eq!(run["skipped"], 6);
    assert_eq!(run["failed"], 1);
    assert_eq!(run["stopped"], true);
    assert_eq!(
        run["manifest"]["rust"]["binary_sha256"],
        results["runs"][0]["manifest"]["rust"]["binary_sha256"]
    );
    let workload = &run["workload"][0];
    assert_eq!(workload["selection"]["case"], "f-v6-devnet");
    assert_eq!(workload["oracle"]["verdict"], "Accept");
    assert_eq!(workload["oracle"]["independent_tx_cost_sum"], 12204);
    paired(&workload["before"]);
    paired(&workload["after"]);
    let transactions = workload["block"]["blockTransactions"]["transactions"]
        .as_array()
        .unwrap();
    assert_eq!(transactions.len(), 1);
    assert!(transactions
        .iter()
        .all(|tx| tx["id"] != workload["transaction_id"]));
    assert_eq!(run["injections"].as_array().unwrap().len(), 1);
    assert_eq!(run["injections"][0]["case"], "funding");
}
