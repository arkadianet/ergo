//! Block-level byte-fidelity regression for block 836113.
//!
//! Live IBD wedge at h=836,113 (header_id e34fc969…93268ca1) — the
//! REST decoder was canonicalizing `Constant[STuple]` registers (R9
//! NFT IPFS pair) and `spendingProof.extension` bytes through
//! write_registers / write_context_extension, breaking byte-fidelity
//! for `bytes_to_sign(tx)`. Two test variants:
//!
//! 1. **Per-tx diagnostic** via `decode_scala_transaction_with_mode`
//!    — the original isolation harness mirroring the diagnose_block_*
//!    precedent (303967, 555672). Pinpoints divergent txs by index.
//!
//! 2. **Block-section consensus oracle** via
//!    `decode_block_transactions_with_mode` — asserts the full
//!    Merkle invariant `compute_transactions_root(reconstructed) ==
//!    header.transactions_root`. Variant 1 alone (single-tx decode)
//!    misses drift between the two decoder entry points; this
//!    second variant pins the block-section path against the same
//!    Merkle invariant.

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::merkle::transactions_root;
use ergo_primitives::reader::VlqReader;
use ergo_rest_json::{decode_block_transactions_with_mode, DecodeMode, ScalaFullBlock};
#[cfg(feature = "diagnostics")]
use ergo_rest_json::{decode_scala_transaction_with_mode, ScalaTransaction};
use ergo_ser::block_transactions::read_block_transactions;
#[cfg(feature = "diagnostics")]
use ergo_ser::transaction::read_transaction;
use ergo_ser::transaction::{bytes_to_sign, transaction_id};

#[cfg(feature = "diagnostics")]
#[test]
fn diff_per_tx_ids_for_block_836113() {
    let raw = std::fs::read_to_string("/tmp/block_836113_txs.json")
        .expect("capture file at /tmp/block_836113_txs.json");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let txs_json = value["transactions"]
        .as_array()
        .expect("transactions array");
    eprintln!("block 836113: {} txs in JSON", txs_json.len());

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

        // Use Preserve mode — Submit canonicalizes registers via
        // write_registers which loses byte-fidelity for
        // Constant[STuple] forms (h=836113 R9). Preserve passes the
        // raw register/extension bytes through verbatim so
        // bytes_to_sign(tx) reproduces Scala's emission byte-for-byte.
        let wire_bytes = match decode_scala_transaction_with_mode(&input, DecodeMode::Preserve) {
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

/// Block-section consensus oracle: JSON → canonical wire bytes via
/// `decode_block_transactions_with_mode(_, DecodeMode::Preserve)` →
/// `read_block_transactions` → `transactions_root(tx_ids,
/// witness_ids)`, asserting the computed root matches the header's
/// claimed `transactionsRoot`.
///
/// This is the durable form codex's review recommended in place of
/// the per-tx diagnostic harness above. Per-tx isolation stays
/// available for future regressions; the consensus invariant lives
/// here.
#[test]
fn block_transactions_root_for_836113_via_preserve_decoder() {
    let raw = std::fs::read_to_string("../test-vectors/mainnet/block_836113.json")
        .expect("test-vectors/mainnet/block_836113.json (full Scala block JSON)");
    let scala_full: ScalaFullBlock = serde_json::from_str(&raw).expect("ScalaFullBlock parse");

    // JSON → canonical wire bytes for the BlockTransactions section.
    let bt_bytes =
        decode_block_transactions_with_mode(&scala_full.block_transactions, DecodeMode::Preserve)
            .expect("decode_block_transactions_with_mode Preserve");

    let mut r = VlqReader::new(&bt_bytes);
    let parsed =
        read_block_transactions(&mut r).expect("read_block_transactions over reconstructed bytes");
    assert!(r.is_empty(), "trailing bytes after read_block_transactions");

    let header = &scala_full.header;
    assert_eq!(
        parsed.transactions.len(),
        scala_full.block_transactions.transactions.len(),
        "tx count parity"
    );

    // Per-tx tx_id parity (cheap sanity; the consensus assertion is
    // the Merkle root below).
    for (i, tx) in parsed.transactions.iter().enumerate() {
        let computed = transaction_id(tx).expect("transaction_id");
        let computed_hex = hex::encode(computed.as_bytes());
        let scala_id_hex = scala_full.block_transactions.transactions[i]
            .id
            .to_lowercase();
        assert_eq!(
            computed_hex, scala_id_hex,
            "tx[{i}] id parity (Preserve-mode decode path)"
        );
    }

    // transactionsRoot consensus invariant. v2 = Merkle over
    // tx_ids ++ witness_ids; mirrors the path
    // `ergo-validation/src/block.rs:382-413` walks during
    // `validate_full_block`.
    assert_eq!(
        header.version, 2,
        "block 836113 is v2 — adjust witness logic if this ever changes"
    );

    let tx_ids: Vec<Vec<u8>> = parsed
        .transactions
        .iter()
        .map(|tx| {
            let bts = bytes_to_sign(tx).expect("bytes_to_sign");
            blake2b256(&bts).to_vec()
        })
        .collect();

    let witness_ids: Vec<Vec<u8>> = parsed
        .transactions
        .iter()
        .map(|tx| {
            let mut all_proofs = Vec::new();
            for input in &tx.inputs {
                all_proofs.extend_from_slice(&input.spending_proof.proof);
            }
            let h = blake2b256(&all_proofs);
            h[1..].to_vec()
        })
        .collect();

    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    let witness_refs: Vec<&[u8]> = witness_ids.iter().map(|w| w.as_slice()).collect();

    let computed_root = transactions_root(&tx_id_refs, Some(&witness_refs));
    let expected_root =
        hex::decode(&header.transactions_root).expect("header.transactionsRoot hex");
    assert_eq!(
        hex::encode(computed_root),
        hex::encode(&expected_root),
        "transactionsRoot mismatch — Preserve-mode decoder lost \
         byte-fidelity on the block-section path"
    );
}
