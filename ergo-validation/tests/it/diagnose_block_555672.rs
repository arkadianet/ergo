#![cfg(feature = "diagnostics")]
//! Per-tx diagnostic for block 555672 transactions-root mismatch.
//!
//! Live IBD wedge at h=555,672 after the 303,967 ergoTree-bytes fix
//! (commit 5fa2b5d) had unblocked an earlier divergence. Same
//! diagnostic procedure: decode each tx → recompute id → diff
//! against Scala's claimed id to isolate the culprit field.

use ergo_primitives::reader::VlqReader;
use ergo_rest_json::{decode_scala_transaction, ScalaTransaction};
use ergo_ser::transaction::{read_transaction, transaction_id};

#[test]
fn diff_per_tx_ids_for_block_555672() {
    let raw = std::fs::read_to_string("/tmp/block_555672_txs.json")
        .expect("capture file at /tmp/block_555672_txs.json");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let txs_json = value["transactions"]
        .as_array()
        .expect("transactions array");
    eprintln!("block 555672: {} txs in JSON", txs_json.len());

    let mut mismatches: Vec<(usize, String, String)> = Vec::new();
    for (i, tx_json) in txs_json.iter().enumerate() {
        let scala_id_hex = tx_json["id"].as_str().unwrap().to_lowercase();

        let scala_tx: ScalaTransaction =
            serde_json::from_value(tx_json.clone()).expect("ScalaTransaction parse");

        let input = ergo_rest_json::ScalaTransactionInput {
            inputs: scala_tx.inputs.clone(),
            data_inputs: scala_tx.data_inputs.clone(),
            outputs: scala_tx
                .outputs
                .iter()
                .map(|o| ergo_rest_json::ScalaOutputInput {
                    value: o.value,
                    ergo_tree: o.ergo_tree.clone(),
                    assets: o.assets.clone(),
                    creation_height: o.creation_height,
                    additional_registers: o.additional_registers.clone(),
                })
                .collect(),
        };

        let wire_bytes = match decode_scala_transaction(&input) {
            Ok(b) => b,
            Err((reason, detail)) => {
                eprintln!("tx[{i}] {scala_id_hex}: decode FAIL ({reason}): {detail}");
                mismatches.push((
                    i,
                    scala_id_hex.clone(),
                    format!("decode_failed: {reason}: {detail}"),
                ));
                continue;
            }
        };

        let mut r = VlqReader::new(&wire_bytes);
        let parsed = match read_transaction(&mut r) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("tx[{i}] {scala_id_hex}: re-parse FAIL: {e:?}");
                mismatches.push((i, scala_id_hex.clone(), format!("re-parse_failed: {e:?}")));
                continue;
            }
        };

        let computed_id = match transaction_id(&parsed) {
            Ok(id) => hex::encode(id.as_bytes()),
            Err(e) => {
                eprintln!("tx[{i}] {scala_id_hex}: id-compute FAIL: {e:?}");
                mismatches.push((i, scala_id_hex.clone(), format!("id_compute_failed: {e:?}")));
                continue;
            }
        };

        if computed_id == scala_id_hex {
            eprintln!("tx[{i}] {scala_id_hex}: ✓ MATCH");
        } else {
            eprintln!("tx[{i}] {scala_id_hex}: ✗ MISMATCH — computed {computed_id}");
            mismatches.push((i, scala_id_hex.clone(), computed_id));
        }
    }

    eprintln!();
    eprintln!("=== summary ===");
    eprintln!("total txs: {}", txs_json.len());
    eprintln!("mismatches: {}", mismatches.len());
    for (i, scala, computed) in &mismatches {
        eprintln!("  tx[{i}] scala={scala} computed={computed}");
    }

    assert!(
        mismatches.is_empty(),
        "expected all tx ids to match Scala; mismatches: {:?}",
        mismatches
    );
}
