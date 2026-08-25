#![cfg(feature = "diagnostics")]
//! Per-tx diagnostic for block 303967 transactions-root mismatch.
//!
//! Loads block 303967's JSON transactions captured from Scala REST
//! (`/tmp/block_303967_txs.json` — `/blocks/{blockId}/transactions`).
//! For each tx:
//! 1. Decode to canonical wire bytes via `decode_scala_transaction`.
//! 2. Parse those bytes as a `Transaction`.
//! 3. Compute `transaction_id()` (= blake2b256(bytes_to_sign)).
//! 4. Compare to Scala's claimed tx id.
//!
//! Per codex 2026-05-02 review: the first mismatch identifies the
//! culprit tx whose `bytes_to_sign` diverges. From there, we diff
//! the divergent regions (inputs/extensions, data inputs, token
//! table, outputs).

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_rest_json::{decode_scala_transaction, ScalaTransaction};
use ergo_ser::transaction::{bytes_to_sign, read_transaction, transaction_id, write_transaction};

#[test]
fn diff_per_tx_ids_for_block_303967() {
    let raw = std::fs::read_to_string("/tmp/block_303967_txs.json").expect("capture file");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let txs_json = value["transactions"]
        .as_array()
        .expect("transactions array");
    eprintln!("block 303967: {} txs in JSON", txs_json.len());

    let mut mismatches: Vec<(usize, String, String)> = Vec::new();
    for (i, tx_json) in txs_json.iter().enumerate() {
        let scala_id_hex = tx_json["id"].as_str().unwrap().to_lowercase();

        // Parse via the read-side DTO (ScalaTransaction has the
        // derived fields like `id`, `boxId`, etc).
        let scala_tx: ScalaTransaction =
            serde_json::from_value(tx_json.clone()).expect("ScalaTransaction parse");

        // Convert ScalaTransaction → ScalaTransactionInput shape
        // (drops the derived ids that Scala would compute itself).
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

    // Post-fix (decode_ergo_tree_canonicalize returning input
    // bytes instead of re-emit): all 10 tx IDs must match Scala's
    // claimed values. Pre-fix tx[1] diverged because output[0]'s
    // ergoTree `1000d1ed8501` was lossily re-emitted as
    // `1000d1ed01010100`.
    assert!(
        mismatches.is_empty(),
        "expected all 10 tx ids to match Scala post-fix; mismatches: {:?}",
        mismatches
    );
}

/// Deep-dive on the culprit tx[1]. Dumps:
/// 1. JSON→wire bytes (our `decode_scala_transaction` output).
/// 2. Re-parse → re-serialize roundtrip — does our serializer
///    produce the SAME bytes back? If no, parser/serializer is
///    non-canonical for some field.
/// 3. `bytes_to_sign` (the actual hash input).
/// 4. Per-output ergoTree bytes from each output, to spot if
///    decode_scala_transaction is altering them.
#[test]
fn dump_culprit_tx1_bytes() {
    let raw = std::fs::read_to_string("/tmp/block_303967_txs.json").unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let tx_json = &value["transactions"][1];
    let scala_id = tx_json["id"].as_str().unwrap();
    eprintln!("=== tx[1] {scala_id} ===");

    let scala_tx: ScalaTransaction = serde_json::from_value(tx_json.clone()).unwrap();
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

    // Step 1: JSON → wire bytes via decode_scala_transaction.
    let wire = decode_scala_transaction(&input).expect("decode");
    eprintln!("decode_scala_transaction → {} bytes", wire.len());
    eprintln!("  first 64: {}", hex::encode(&wire[..64.min(wire.len())]));

    // Step 2: Parse those bytes back, then re-emit.
    let mut r = VlqReader::new(&wire);
    let parsed = read_transaction(&mut r).expect("re-parse");
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &parsed).expect("re-emit");
    let re_emitted = w.result();
    eprintln!("re-emit                  → {} bytes", re_emitted.len());
    if re_emitted == wire {
        eprintln!("  ✓ self-roundtrip stable");
    } else {
        eprintln!("  ✗ self-roundtrip DIFFERS — non-canonical serializer for this tx!");
        // Find first diff
        let len = re_emitted.len().min(wire.len());
        for i in 0..len {
            if wire[i] != re_emitted[i] {
                let lo = i.saturating_sub(8);
                let hi = (i + 16).min(len);
                eprintln!("  first diff at byte {i}");
                eprintln!("    decode [{lo}..{hi}] = {}", hex::encode(&wire[lo..hi]));
                eprintln!(
                    "    re-emit[{lo}..{hi}] = {}",
                    hex::encode(&re_emitted[lo..hi])
                );
                break;
            }
        }
    }

    // Step 3: bytes_to_sign for ID computation.
    let bts = bytes_to_sign(&parsed).expect("bytes_to_sign");
    eprintln!("bytes_to_sign            → {} bytes", bts.len());

    // Step 4: per-output dump (ergoTree + registers as we hold them).
    eprintln!();
    eprintln!("=== outputs ===");
    for (i, out) in parsed.output_candidates.iter().enumerate() {
        let scala_tree = scala_tx.outputs[i].ergo_tree.clone();
        let our_tree = hex::encode(out.ergo_tree_bytes());
        let scala_regs: std::collections::BTreeMap<String, String> = scala_tx.outputs[i]
            .additional_registers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        eprintln!("output[{i}]:");
        eprintln!(
            "  scala ergoTree len={} : {}",
            scala_tree.len() / 2,
            &scala_tree[..40.min(scala_tree.len())]
        );
        eprintln!(
            "  our   ergoTree len={} : {}",
            out.ergo_tree_bytes().len(),
            &our_tree[..40.min(our_tree.len())]
        );
        if our_tree.to_lowercase() != scala_tree.to_lowercase() {
            eprintln!("  ✗ ergoTree DIVERGES at output[{i}]");
        }
        eprintln!("  scala registers: {:?}", scala_regs);
        eprintln!(
            "  our   registers (count): {}",
            out.additional_registers.registers.len()
        );
        for (idx, reg_bytes) in out.additional_registers.registers.iter().enumerate() {
            eprintln!("    R{}: {:?}", 4 + idx, reg_bytes);
        }
    }
}
