//! Block structural validation tests.
//!
//! Exercises header linkage + tx root + ext root + section-to-header IDs
//! on both available full-block corpora (blocks_1_5 v1 + blocks_700k v2).
//!
//! Full pipeline with state (tx validation + state application) is in
//! ergo-state/tests/ where genesis infrastructure lives.

use std::collections::HashMap;

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::merkle::{extension_root, transactions_root};
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::BlockTransactions;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_ser::transaction::read_transaction;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::block::{
    validate_full_block, validate_full_block_parallel, BlockValidationContext, BlockValidationError,
};
use ergo_validation::context::{ProtocolParams, UtxoView};
use ergo_validation::error::ValidationError;
use ergo_validation::header::{CheckedHeader, HeaderValidationError};

use serde::Deserialize;

struct EmptyUtxo;
impl UtxoView for EmptyUtxo {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

#[derive(Deserialize)]
struct BlockJson {
    #[serde(rename = "headerId")]
    header_id: String,
    height: u32,
    transactions: Vec<TxJson>,
    extension: ExtJson,
}

#[derive(Deserialize)]
struct TxJson {
    #[allow(dead_code)]
    id: String,
    bytes: String,
}

#[derive(Deserialize)]
struct ExtJson {
    #[serde(rename = "headerId")]
    header_id: Option<String>,
    #[allow(dead_code)]
    digest: String,
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    bytes: String,
}

fn load_blocks(path: &str) -> Vec<BlockJson> {
    let data = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn load_headers_map(path: &str) -> HashMap<u32, (Header, [u8; 32])> {
    let data = std::fs::read_to_string(path).unwrap();
    let vecs: Vec<HeaderVec> = serde_json::from_str(&data).unwrap();
    vecs.iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            let h = read_header(&mut r).unwrap();
            let (_, id) = serialize_header(&h).expect("real mainnet header serializes");
            (v.height, (h, *id.as_bytes()))
        })
        .collect()
}

fn build_block_transactions(block: &BlockJson) -> BlockTransactions {
    let header_id =
        ModifierId::from_bytes(hex::decode(&block.header_id).unwrap().try_into().unwrap());
    let txs = block
        .transactions
        .iter()
        .map(|t| {
            let bytes = hex::decode(&t.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            read_transaction(&mut r).unwrap()
        })
        .collect();
    BlockTransactions {
        header_id,
        transactions: txs,
    }
}

fn build_extension(block: &BlockJson) -> Extension {
    let hid_hex = block
        .extension
        .header_id
        .as_deref()
        .unwrap_or(&block.header_id);
    let header_id = ModifierId::from_bytes(hex::decode(hid_hex).unwrap().try_into().unwrap());
    let fields = block
        .extension
        .fields
        .iter()
        .map(|(k, v)| ExtensionField {
            key: hex::decode(k).unwrap().try_into().unwrap(),
            value: hex::decode(v).unwrap(),
        })
        .collect();
    Extension { header_id, fields }
}

/// Verify structural integrity of a block: header linkage, tx root, ext root, section IDs.
fn verify_block_structural(
    block: &BlockJson,
    header: &Header,
    header_id: &[u8; 32],
    parent: &Header,
    parent_id: &[u8; 32],
) {
    let bt = build_block_transactions(block);
    let ext = build_extension(block);

    // Section-to-header linkage
    assert_eq!(
        bt.header_id.as_bytes(),
        header_id,
        "BlockTransactions header_id mismatch at h={}",
        block.height
    );
    assert_eq!(
        ext.header_id.as_bytes(),
        header_id,
        "Extension header_id mismatch at h={}",
        block.height
    );

    // Header linkage (parent ID + timestamp)
    assert_eq!(
        header.parent_id.as_bytes(),
        parent_id,
        "parent_id mismatch at h={}",
        block.height
    );
    assert!(
        header.timestamp > parent.timestamp,
        "timestamp not monotonic at h={}: {} <= {}",
        block.height,
        header.timestamp,
        parent.timestamp
    );

    // PoW (skip difficulty at epoch boundaries)
    ergo_crypto::pow::verify_pow_solution(header)
        .unwrap_or_else(|e| panic!("PoW failed at h={}: {e}", block.height));

    // Transactions root
    let txs = &bt.transactions;
    let tx_ids: Vec<Vec<u8>> = txs
        .iter()
        .map(|tx| {
            let bts = ergo_ser::transaction::bytes_to_sign(tx).unwrap();
            blake2b256(&bts).to_vec()
        })
        .collect();
    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();

    let computed_tx_root = if header.version >= 2 {
        let witness_data: Vec<Vec<u8>> = txs
            .iter()
            .map(|tx| {
                let mut proofs = Vec::new();
                for input in &tx.inputs {
                    proofs.extend_from_slice(&input.spending_proof.proof);
                }
                blake2b256(&proofs)[1..].to_vec()
            })
            .collect();
        let wrefs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
        transactions_root(&tx_id_refs, Some(&wrefs))
    } else {
        transactions_root(&tx_id_refs, None)
    };
    assert_eq!(
        computed_tx_root,
        *header.transactions_root.as_bytes(),
        "tx root mismatch at h={}",
        block.height
    );

    // Extension root
    let ext_fields: Vec<(&[u8], &[u8])> = ext
        .fields
        .iter()
        .map(|f| (f.key.as_slice(), f.value.as_slice()))
        .collect();
    let computed_ext_root = extension_root(&ext_fields);
    assert_eq!(
        computed_ext_root,
        *header.extension_root.as_bytes(),
        "ext root mismatch at h={}",
        block.height
    );
}

#[test]
fn block_structural_blocks_1_5() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_1_5.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_1_2000.json");

    let mut validated = 0;
    for block in blocks.iter().skip(1) {
        let (ref header, ref header_id) = headers[&block.height];
        let (ref parent, ref parent_id) = headers[&(block.height - 1)];
        verify_block_structural(block, header, header_id, parent, parent_id);
        validated += 1;
        let nf = block.extension.fields.len();
        eprintln!(
            "OK: h={} ({} txs, {} ext fields, v{})",
            block.height,
            block.transactions.len(),
            nf,
            header.version
        );
    }
    assert_eq!(validated, 4);
    eprintln!("blocks_1_5: {validated} blocks structurally verified");
}

#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn block_validate_full_block_700k_v2_pipeline() {
    // Exercises validate_full_block() on v2 multi-tx blocks.
    // Uses EmptyUtxo — tx validation will fail with InputBoxNotFound,
    // but header + section linkage + tx root + ext root are all verified
    // through the production code path before the first tx is attempted.
    let blocks = load_blocks("../test-vectors/mainnet/blocks_700000_700010.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_700000_700500.json");
    let params = ProtocolParams::mainnet_default();

    let mut header_root_verified = 0;
    for block in blocks.iter().skip(1) {
        let (ref header, ref header_id) = headers[&block.height];
        let (ref parent, ref parent_id) = headers[&(block.height - 1)];
        let bt = build_block_transactions(block);
        let ext = build_extension(block);

        let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);
        let block_ctx = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let checked_header = CheckedHeader::trust_me(header.clone(), *header_id);
        match validate_full_block(checked_header, &bt, &ext, &block_ctx) {
            Ok(_checked_block) => {
                // Unexpected success with empty UTXO — block has no inputs?
                header_root_verified += 1;
                eprintln!("OK: h={} (no-input block, fully validated)", block.height);
            }
            Err(BlockValidationError::Transaction {
                index: 0,
                error: ValidationError::InputBoxNotFound { .. },
            }) => {
                // Expected: header + roots + linkage passed, first tx failed on missing UTXO
                header_root_verified += 1;
                eprintln!(
                    "OK: h={} header+roots+linkage verified, tx stopped at missing UTXO ({} txs, {} ext, v{})",
                    block.height, block.transactions.len(), block.extension.fields.len(), header.version,
                );
            }
            Err(e) => {
                panic!("unexpected error at h={}: {e}", block.height);
            }
        }
    }
    assert!(header_root_verified >= 10);
    eprintln!("700k: {header_root_verified} v2 blocks verified through validate_full_block()");
}

/// Helper: run validate_full_block on a block range through the production pipeline.
/// Returns count of blocks where header+roots+linkage were verified.
fn run_validate_full_block_range(blocks_path: &str, headers_path: &str, label: &str) -> usize {
    let blocks = load_blocks(blocks_path);
    let headers = load_headers_map(headers_path);
    let params = ProtocolParams::mainnet_default();

    let mut verified = 0;
    for block in blocks.iter().skip(1) {
        let header_entry = match headers.get(&block.height) {
            Some(h) => h,
            None => continue,
        };
        let parent_entry = match headers.get(&(block.height - 1)) {
            Some(h) => h,
            None => continue,
        };
        let (ref header, ref header_id) = *header_entry;
        let (ref parent, ref parent_id) = *parent_entry;
        let bt = build_block_transactions(block);
        let ext = build_extension(block);

        let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);
        let block_ctx = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let checked_header = CheckedHeader::trust_me(header.clone(), *header_id);
        match validate_full_block(checked_header, &bt, &ext, &block_ctx) {
            Ok(_checked_block) => {
                verified += 1;
                eprintln!("  h={} fully validated (no-input block)", block.height);
            }
            Err(BlockValidationError::Transaction {
                index: 0,
                error: ValidationError::InputBoxNotFound { .. },
            }) => {
                verified += 1;
                eprintln!(
                    "  h={} header+roots+linkage OK ({} txs, {} ext, v{})",
                    block.height,
                    bt.transactions.len(),
                    ext.fields.len(),
                    header.version
                );
            }
            Err(e) => {
                panic!("{label}: unexpected error at h={}: {e}", block.height);
            }
        }
    }
    verified
}

#[test]
#[ignore = "needs gitignored headers_417785_417800.json — extract via test-vectors/scripts then run with --ignored"]
fn validate_full_block_v1_to_v2_transition() {
    let verified = run_validate_full_block_range(
        "../test-vectors/mainnet/blocks_417785_417800.json",
        "../test-vectors/mainnet/headers_417785_417800.json",
        "v1→v2",
    );
    assert_eq!(verified, 15, "expected exactly 15 blocks verified");
    eprintln!("v1→v2 transition: {verified} blocks through validate_full_block()");
}

#[test]
#[ignore = "needs gitignored headers_843000_844672.json + headers_844673_846000.json — extract via test-vectors/scripts then run with --ignored"]
fn validate_full_block_eip37_activation() {
    // Need headers covering 844665-844680. Merge from two existing files.
    let mut headers = load_headers_map("../test-vectors/mainnet/headers_843000_844672.json");
    let headers2 = load_headers_map("../test-vectors/mainnet/headers_844673_846000.json");
    headers.extend(headers2);

    let blocks = load_blocks("../test-vectors/mainnet/blocks_844665_844680.json");
    let params = ProtocolParams::mainnet_default();

    let mut verified = 0;
    for block in blocks.iter().skip(1) {
        let header_entry = match headers.get(&block.height) {
            Some(h) => h,
            None => continue,
        };
        let parent_entry = match headers.get(&(block.height - 1)) {
            Some(h) => h,
            None => continue,
        };
        let (ref header, ref header_id) = *header_entry;
        let (ref parent, ref parent_id) = *parent_entry;
        let bt = build_block_transactions(block);
        let ext = build_extension(block);

        // Epoch boundaries lack lookback headers for difficulty recalc —
        // use structural verification instead (avoids panic in difficulty code).
        let cfg = ergo_crypto::difficulty::DifficultyParams::mainnet();
        if ergo_crypto::difficulty::is_recalculation_height(header.height, &cfg) {
            verify_block_structural(block, header, header_id, parent, parent_id);
            verified += 1;
            eprintln!(
                "  h={} epoch boundary, structural fallback ({} txs, {} ext)",
                block.height,
                bt.transactions.len(),
                ext.fields.len()
            );
            continue;
        }

        let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);
        let block_ctx = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let checked_header = CheckedHeader::trust_me(header.clone(), *header_id);
        match validate_full_block(checked_header, &bt, &ext, &block_ctx) {
            Ok(_checked_block) => {
                verified += 1;
            }
            Err(BlockValidationError::Transaction {
                index: 0,
                error: ValidationError::InputBoxNotFound { .. },
            }) => {
                verified += 1;
                eprintln!(
                    "  h={} header+roots+linkage OK ({} txs, {} ext, v{})",
                    block.height,
                    bt.transactions.len(),
                    ext.fields.len(),
                    header.version
                );
            }
            Err(e) => {
                panic!("EIP-37: unexpected error at h={}: {e}", block.height);
            }
        }
    }
    // 15 blocks: 14 through validate_full_block, 1 epoch boundary structural fallback
    assert_eq!(verified, 15, "expected exactly 15 blocks verified");
    eprintln!("EIP-37 activation: {verified} blocks through validate_full_block()");
}

/// Shadow test: for every block in a real mainnet range, run the sequential
/// `validate_full_block` AND `validate_full_block_parallel` on identical
/// input, assert both produce equivalent outcomes. Guards against the
/// parallel path drifting from consensus before it's wired into
/// `process_block`.
///
/// EmptyUtxo forces the per-tx path to fail at tx 0 with InputBoxNotFound,
/// but everything up to that point — section linkage, tx root, extension
/// root, layering — runs on real mainnet bytes. The equivalence check is:
/// either both paths return `Ok`, or both return
/// `Transaction { index, InputBoxNotFound }` at the SAME index.
#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn parallel_equivalent_to_sequential_on_mainnet_700k() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_700000_700010.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_700000_700500.json");
    let params = ProtocolParams::mainnet_default();

    let mut compared = 0;
    for block in blocks.iter().skip(1) {
        let (ref header, ref header_id) = headers[&block.height];
        let (ref parent, ref parent_id) = headers[&(block.height - 1)];
        let bt = build_block_transactions(block);
        let ext = build_extension(block);
        let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);

        let ctx_seq = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let ctx_par = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };

        let h_seq = CheckedHeader::trust_me(header.clone(), *header_id);
        let h_par = CheckedHeader::trust_me(header.clone(), *header_id);

        let seq_result = validate_full_block(h_seq, &bt, &ext, &ctx_seq);
        let par_result = validate_full_block_parallel(h_par, &bt, &ext, &ctx_par);

        match (&seq_result, &par_result) {
            (Ok(a), Ok(b)) => {
                assert_eq!(
                    a.transactions().len(),
                    b.transactions().len(),
                    "tx count diverges at h={}",
                    block.height
                );
                for (i, (ta, tb)) in a
                    .transactions()
                    .iter()
                    .zip(b.transactions().iter())
                    .enumerate()
                {
                    assert_eq!(
                        ta.tx_id(),
                        tb.tx_id(),
                        "tx_id diverges at h={} tx{i}",
                        block.height
                    );
                }
            }
            (
                Err(BlockValidationError::Transaction {
                    index: ia,
                    error: ValidationError::InputBoxNotFound { box_id: ba },
                }),
                Err(BlockValidationError::Transaction {
                    index: ib,
                    error: ValidationError::InputBoxNotFound { box_id: bb },
                }),
            ) => {
                assert_eq!(
                    ia, ib,
                    "error index diverges at h={}: seq={ia} par={ib}",
                    block.height
                );
                assert_eq!(ba, bb, "missing box_id diverges at h={}", block.height);
            }
            (a, b) => {
                panic!(
                    "divergence at h={}: sequential={a:?} parallel={b:?}",
                    block.height,
                );
            }
        }
        compared += 1;
    }
    assert!(
        compared >= 10,
        "should have compared at least 10 blocks, got {compared}"
    );
    eprintln!("parallel parity: {compared} blocks match sequential path byte-for-byte");
}

/// Checkpoint mismatch: when configured, the observed header_id at exactly
/// `checkpoint.height` MUST equal the configured `block_id`. A different
/// chain at that height is an instant hard error — this is the single
/// point of trust that protects every below-checkpoint skip.
#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn checkpoint_mismatch_at_pinned_height_hard_fails() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_700000_700010.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_700000_700500.json");
    let params = ProtocolParams::mainnet_default();

    // Pick the block at height 700001 and configure a checkpoint with
    // an INTENTIONALLY-WRONG block_id pinned to that exact height.
    let target_h: u32 = 700001;
    let block = blocks
        .iter()
        .find(|b| b.height == target_h)
        .expect("h=700001 in fixture");
    let (ref header, ref header_id) = headers[&target_h];
    let (ref parent, ref parent_id) = headers[&(target_h - 1)];

    let bt = build_block_transactions(block);
    let ext = build_extension(block);
    let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);

    let wrong_id = [0xAAu8; 32];
    let bad_ckpt = Some((target_h, wrong_id));

    let ctx = BlockValidationContext {
        parent: &checked_parent,
        utxo: &EmptyUtxo,
        params: &params,
        voting_length: 1024,
        votes_unknown_rule_disabled: false,
        parent_extension: None,
        soft_fork_state: None,
        last_headers: &[],
        script_validation_checkpoint: bad_ckpt,
        reemission: None,
    };

    let h = CheckedHeader::trust_me(header.clone(), *header_id);
    let err = validate_full_block_parallel(h, &bt, &ext, &ctx).unwrap_err();
    match err {
        BlockValidationError::CheckpointMismatch {
            height,
            expected,
            got,
        } => {
            assert_eq!(height, target_h);
            assert_eq!(expected, wrong_id);
            assert_eq!(got, *header_id);
        }
        other => panic!("expected CheckpointMismatch, got {other:?}"),
    }
}

/// Checkpoint hit on the correct chain: when observed header_id matches
/// the configured block_id at the pinned height, validation proceeds
/// normally (and below the checkpoint scripts would be skipped — exercised
/// by the live IBD path, not here, since this fixture uses EmptyUtxo and
/// hits InputBoxNotFound before reaching scripts).
#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn checkpoint_match_at_pinned_height_passes_through() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_700000_700010.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_700000_700500.json");
    let params = ProtocolParams::mainnet_default();

    let target_h: u32 = 700001;
    let block = blocks
        .iter()
        .find(|b| b.height == target_h)
        .expect("h=700001 in fixture");
    let (ref header, ref header_id) = headers[&target_h];
    let (ref parent, ref parent_id) = headers[&(target_h - 1)];

    let bt = build_block_transactions(block);
    let ext = build_extension(block);
    let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);

    // Configure checkpoint with the CORRECT header_id at this height.
    let good_ckpt = Some((target_h, *header_id));

    let ctx = BlockValidationContext {
        parent: &checked_parent,
        utxo: &EmptyUtxo,
        params: &params,
        voting_length: 1024,
        votes_unknown_rule_disabled: false,
        parent_extension: None,
        soft_fork_state: None,
        last_headers: &[],
        script_validation_checkpoint: good_ckpt,
        reemission: None,
    };

    let h = CheckedHeader::trust_me(header.clone(), *header_id);
    // EmptyUtxo means tx 0 input resolution still fails — but the
    // checkpoint assertion runs FIRST and must not raise. Acceptable
    // outcomes: Ok (no inputs needed, unlikely) OR
    // Transaction { InputBoxNotFound } — anything but CheckpointMismatch.
    match validate_full_block_parallel(h, &bt, &ext, &ctx) {
        Ok(_) => {}
        Err(BlockValidationError::Transaction {
            error: ValidationError::InputBoxNotFound { .. },
            ..
        }) => {}
        Err(other) => panic!("checkpoint match must not raise; got {other:?}"),
    }
}

/// Sequential and parallel paths must reject rule 306
/// (`bsBlockTransactionsSize`) identically. Construct a real
/// mainnet block from the v1 corpus, configure `max_block_size =
/// actual_serialized_size - 1`, and assert both validators raise
/// `BlockTransactionsTooLarge` with the same `(size, max)` fields.
///
/// Pins the cross-path symmetry Codex flagged on commit 6754803:
/// without this test, a future drift where one path's wiring is
/// dropped would silently allow consensus divergence between
/// sequential and parallel apply.
#[test]
fn rule_306_rejection_parity_across_sequential_and_parallel_paths() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_1_5.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_1_2000.json");

    let block = blocks
        .iter()
        .find(|b| b.height == 2)
        .expect("block at h=2 in fixture");
    let (header, header_id) = &headers[&block.height];
    let (parent, parent_id) = &headers[&(block.height - 1)];

    let bt = build_block_transactions(block);
    let ext = build_extension(block);

    // Measure actual serialized size via the same helper the
    // validator uses, then lower the cap one byte below it.
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::block_transactions::write_block_transactions_with_version(
        &mut w,
        &bt,
        header.version,
    )
    .unwrap();
    let actual_size = w.result().len();
    let lowered_cap = (actual_size - 1) as u32;

    let mut params = ProtocolParams::mainnet_default();
    params.max_block_size = lowered_cap;

    let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);
    let ctx_seq = BlockValidationContext {
        parent: &checked_parent,
        utxo: &EmptyUtxo,
        params: &params,
        voting_length: 1024,
        votes_unknown_rule_disabled: false,
        parent_extension: None,
        soft_fork_state: None,
        last_headers: &[],
        script_validation_checkpoint: None,
        reemission: None,
    };
    let ctx_par = BlockValidationContext {
        parent: &checked_parent,
        utxo: &EmptyUtxo,
        params: &params,
        voting_length: 1024,
        votes_unknown_rule_disabled: false,
        parent_extension: None,
        soft_fork_state: None,
        last_headers: &[],
        script_validation_checkpoint: None,
        reemission: None,
    };
    let h_seq = CheckedHeader::trust_me(header.clone(), *header_id);
    let h_par = CheckedHeader::trust_me(header.clone(), *header_id);

    let seq_err = validate_full_block(h_seq, &bt, &ext, &ctx_seq).unwrap_err();
    let par_err = validate_full_block_parallel(h_par, &bt, &ext, &ctx_par).unwrap_err();

    match (seq_err, par_err) {
        (
            BlockValidationError::BlockTransactionsTooLarge {
                size: s_seq,
                max: m_seq,
            },
            BlockValidationError::BlockTransactionsTooLarge {
                size: s_par,
                max: m_par,
            },
        ) => {
            assert_eq!(s_seq, actual_size, "seq path reported wrong size");
            assert_eq!(s_par, actual_size, "par path reported wrong size");
            assert_eq!(m_seq, lowered_cap, "seq path reported wrong cap");
            assert_eq!(m_par, lowered_cap, "par path reported wrong cap");
        }
        (s, p) => panic!("rule 306 cross-path symmetry broken: sequential={s:?}, parallel={p:?}",),
    }
}

/// Always-on counterpart to the `#[ignore]`'d
/// `parallel_equivalent_to_sequential_on_mainnet_700k`: drives committed
/// multi-tx mainnet blocks (heights 417785..=417800, spanning the v1->v2
/// activation, up to 7 txs per block) through BOTH `validate_full_block`
/// (sequential) and `validate_full_block_parallel` (production) and
/// asserts identical outcomes.
///
/// The two paths share a block-validation prologue that is duplicated by
/// design — the sequential path exists to cross-check the parallel one,
/// and the parallel path is kept structurally decoupled on purpose.
/// Comments alone don't stop the two from silently diverging; this test
/// is what enforces it in the default suite. The 700k version covers a
/// broader corpus but lives behind an ignore gate (gitignored headers),
/// so without an always-on equivalent an accepting-path drift would ship
/// unnoticed.
///
/// `EmptyUtxo` makes input-spending txs fail with `InputBoxNotFound`, but
/// header linkage, section IDs, tx/extension roots and tx-layering all run
/// on real mainnet bytes first — the same depth the 700k oracle reaches.
/// The assertion is pure agreement: both `Ok` with identical tx ordering,
/// or both the same `Err`.
#[test]
fn parallel_equivalent_to_sequential_on_committed_multitx_blocks() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_417785_417800.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_v1v2_parity_curated.json");
    let params = ProtocolParams::mainnet_default();

    let mut compared = 0;
    let (mut saw_v1, mut saw_v2) = (false, false);
    for block in &blocks {
        // Need both the block's header and its parent's header in the
        // curated slice to build the validation context; skip otherwise.
        let (Some((header, header_id)), Some((parent, parent_id))) =
            (headers.get(&block.height), headers.get(&(block.height - 1)))
        else {
            continue;
        };
        if header.version >= 2 {
            saw_v2 = true;
        } else {
            saw_v1 = true;
        }
        let bt = build_block_transactions(block);
        let ext = build_extension(block);
        let checked_parent = CheckedHeader::trust_me(parent.clone(), *parent_id);

        let ctx_seq = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let ctx_par = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let h_seq = CheckedHeader::trust_me(header.clone(), *header_id);
        let h_par = CheckedHeader::trust_me(header.clone(), *header_id);

        let seq_result = validate_full_block(h_seq, &bt, &ext, &ctx_seq);
        let par_result = validate_full_block_parallel(h_par, &bt, &ext, &ctx_par);

        assert_eq!(
            seq_result.is_ok(),
            par_result.is_ok(),
            "accept/reject diverges at h={}: seq={seq_result:?} par={par_result:?}",
            block.height
        );
        match (seq_result, par_result) {
            (Ok(a), Ok(b)) => {
                let a_ids: Vec<_> = a.transactions().iter().map(|t| t.tx_id()).collect();
                let b_ids: Vec<_> = b.transactions().iter().map(|t| t.tx_id()).collect();
                assert_eq!(a_ids, b_ids, "tx ordering diverges at h={}", block.height);
            }
            (Err(a), Err(b)) => {
                // Debug-string compare captures variant + fields without
                // requiring PartialEq on the whole error tree.
                assert_eq!(
                    format!("{a:?}"),
                    format!("{b:?}"),
                    "rejection reason diverges at h={}",
                    block.height
                );
            }
            _ => unreachable!("is_ok() equality asserted just above"),
        }
        compared += 1;
    }
    // Pin the corpus shape so the oracle can't silently shrink: the
    // committed fixture is heights 417785..=417800 (16 headers); every
    // block except the first (whose parent 417784 is absent) is comparable.
    assert_eq!(
        compared, 15,
        "curated parity corpus changed shape — expected 15 comparable blocks"
    );
    assert!(
        saw_v1 && saw_v2,
        "corpus must straddle the v1->v2 activation (saw_v1={saw_v1}, saw_v2={saw_v2})"
    );
}

/// Provenance guard for the committed parity corpus: every entry's `id`
/// must be the modifier id its `bytes` actually serialize to. This is an
/// external-oracle check — the `id` values were captured from a mainnet
/// node, so a corrupted or mis-sliced fixture (real-looking id paired
/// with the wrong bytes) fails here instead of silently making
/// `parallel_equivalent_to_sequential_on_committed_multitx_blocks` run on
/// garbage.
#[test]
fn parity_corpus_header_ids_match_bytes() {
    #[derive(Deserialize)]
    struct Entry {
        height: u32,
        id: String,
        bytes: String,
    }
    let data = std::fs::read_to_string("../test-vectors/mainnet/headers_v1v2_parity_curated.json")
        .unwrap();
    let mut entries: Vec<Entry> = serde_json::from_str(&data).unwrap();
    entries.sort_by_key(|e| e.height);
    assert_eq!(entries.len(), 16, "curated corpus must hold 16 headers");

    let mut prev: Option<(u32, String)> = None;
    for e in &entries {
        let bytes = hex::decode(&e.bytes).unwrap();
        let mut r = VlqReader::new(&bytes);
        let h = read_header(&mut r).unwrap();
        let (_, id) = serialize_header(&h).expect("real mainnet header serializes");
        // bytes <-> committed id (external-oracle provenance).
        assert_eq!(
            hex::encode(id.as_bytes()),
            e.id,
            "header id does not match its bytes — corrupt parity fixture at h={}",
            e.height
        );
        if let Some((prev_height, prev_id)) = &prev {
            // Contiguous heights and a real parent chain — a mis-sliced
            // fixture (gap, or a header from the wrong fork) fails here.
            assert_eq!(e.height, prev_height + 1, "non-contiguous height");
            assert_eq!(
                hex::encode(h.parent_id.as_bytes()),
                *prev_id,
                "header at h={} does not link to its predecessor",
                e.height
            );
        }
        prev = Some((e.height, e.id.clone()));
    }
    assert_eq!(entries.first().unwrap().height, 417_785);
    assert_eq!(entries.last().unwrap().height, 417_800);
}

/// Call-site gating for rule 215 (`hdrVotesUnknown`) through both full-block
/// validators. Mainnet's v6.0 soft-fork disabled the rule
/// (`rules_to_disable = [215, 409]`), and `block_proc` now sets
/// `BlockValidationContext.votes_unknown_rule_disabled` from
/// `ErgoValidationSettings::is_rule_disabled(215)`. The unit test in
/// `header.rs` covers `check_votes_known_active` in isolation; this drives
/// the real `validate_full_block` / `validate_full_block_parallel` entry
/// points with the flag off vs on, reproducing the epoch-start
/// `MaxBlockCostDecrease` (-4) proposal that froze the node at block
/// 1802240. Flag off → rejected at the rule; flag on → passes the rule and
/// fails later (tx-root over the empty section list), never with
/// `VotesUnknown`.
#[test]
fn rule_215_gated_at_full_block_call_sites() {
    let headers = load_headers_map("../test-vectors/mainnet/headers_1_2000.json");

    // A real header re-stamped to an epoch start (1024 % 1024 == 0) with a
    // `-4` vote in slot 0 — the shape of mainnet block 1802240. Re-serialize
    // so the header_id matches the mutated bytes (sections link to it below).
    let (base, _) = headers[&1024].clone();
    let mut header = base;
    header.height = 1024;
    header.votes = [(-4i8) as u8, 0, 0];
    let (_, id) = serialize_header(&header).expect("mutated header serializes");
    let header_id = *id.as_bytes();

    // Minimal sections that satisfy section-to-header linkage (step 2) so
    // validation reaches the rule-215 step (2.5). Empty transactions
    // intentionally mismatch the tx root, so the rule-disabled path fails
    // *after* the gate with a non-215 error.
    let bt = BlockTransactions {
        header_id: ModifierId::from_bytes(header_id),
        transactions: vec![],
    };
    let ext = Extension {
        header_id: ModifierId::from_bytes(header_id),
        fields: vec![],
    };

    let (parent, parent_id) = headers[&1023].clone();
    let checked_parent = CheckedHeader::trust_me(parent, parent_id);
    let params = ProtocolParams::mainnet_default();

    let is_votes_unknown = |e: &BlockValidationError| {
        matches!(
            e,
            BlockValidationError::Header(HeaderValidationError::VotesUnknown { vote: -4, .. })
        )
    };

    for &disabled in &[false, true] {
        let ctx = BlockValidationContext {
            parent: &checked_parent,
            utxo: &EmptyUtxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: disabled,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
            reemission: None,
        };
        let seq = validate_full_block(
            CheckedHeader::trust_me(header.clone(), header_id),
            &bt,
            &ext,
            &ctx,
        );
        let par = validate_full_block_parallel(
            CheckedHeader::trust_me(header.clone(), header_id),
            &bt,
            &ext,
            &ctx,
        );
        for (label, res) in [("seq", seq), ("par", par)] {
            // The block is structurally incomplete either way, so both
            // paths always error — only *which* error distinguishes the gate.
            let err = res.expect_err("structurally incomplete block must error");
            if disabled {
                assert!(
                    !is_votes_unknown(&err),
                    "{label}: rule disabled must pass the gate, got {err:?}"
                );
            } else {
                assert!(
                    is_votes_unknown(&err),
                    "{label}: rule active must reject the epoch-start -4 vote, got {err:?}"
                );
            }
        }
    }
}
