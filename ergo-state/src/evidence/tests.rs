#![cfg(test)]

use super::*;
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_validation::header::CheckedHeader;

fn header(height: u32, parent: [u8; 32], root: ADDigest, salt: u8) -> (Header, Vec<u8>, [u8; 32]) {
    let h = Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent),
        ad_proofs_root: Digest32::from_bytes([salt; 32]),
        state_root: root,
        transactions_root: Digest32::from_bytes([0; 32]),
        extension_root: Digest32::from_bytes([0; 32]),
        timestamp: 1_700_000_000 + u64::from(height),
        n_bits: 0x1d00ffff,
        height,
        votes: [0; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes(
                hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            nonce: [salt; 8],
        },
    };
    let (bytes, id) = serialize_header(&h).unwrap();
    (h, bytes, *id.as_bytes())
}
fn checked(h: &Header, bytes: &[u8], id: [u8; 32]) -> CheckedBlock {
    CheckedBlock::from_parts(
        CheckedHeader::from_persisted_parts(
            bytes,
            id,
            1,
            h.height,
            *h.parent_id.as_bytes(),
            h.timestamp,
        )
        .unwrap(),
        vec![],
    )
}
fn store() -> (StateStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open_with_cache(&dir.path().join("state.redb"), 1 << 20).unwrap();
    store.initialize_genesis(&[]).unwrap();
    (store, dir)
}
fn start(store: &mut StateStore, pipeline: bool) -> [u8; 32] {
    let root = store.root_digest();
    let (_, bytes, id) = header(1, [0; 32], root, 1);
    store.enable_applied_evidence(id).unwrap();
    if pipeline {
        store.enable_persist_pipeline(8);
    }
    let capture = CapturedBlock::trusted_genesis(
        &bytes,
        &root,
        &[],
        id,
        store.active_params(),
        store.validation_settings(),
    )
    .unwrap();
    store
        .apply_observed_genesis(&id, &root, &[], capture)
        .unwrap();
    store.flush_persist_pipeline().unwrap();
    id
}
fn apply(
    store: &mut StateStore,
    height: u32,
    salt: u8,
    checkpoint: Option<(u32, [u8; 32])>,
) -> [u8; 32] {
    let root = store.root_digest();
    let parent = store.chain_state().best_full_block_id;
    let (h, bytes, id) = header(height, parent, root, salt);
    let block = checked(&h, &bytes, id);
    let capture = CapturedBlock::checked(
        &block,
        &bytes,
        &root,
        store.active_params(),
        store.validation_settings(),
        checkpoint,
    )
    .unwrap();
    store
        .apply_observed_block(&block, None, None, capture)
        .unwrap();
    id
}
fn page(store: &StateStore) -> CommittedPage {
    read_committed(&store.db_arc(), None, 1000).unwrap()
}

#[test]
fn default_store_has_no_evidence_tables() {
    let (mut s, _dir) = store();
    let root = s.root_digest();
    s.apply_genesis(&[1; 32], &root, &[]).unwrap();
    assert!(!recording_exists(&s.db_arc()).unwrap());
    assert!(read_committed(&s.db_arc(), None, 10).is_err());
}
#[test]
fn synchronous_apply_has_explicit_genesis_and_checked_full_provenance() {
    let (mut s, _dir) = store();
    start(&mut s, false);
    let id = apply(&mut s, 2, 2, None);
    let p = page(&s);
    assert_eq!(p.events.len(), 2);
    assert_eq!(p.meta.tip_id, hex::encode(id));
    assert!(!p.meta.reconstruction_required);
    assert_eq!(
        p.events[0].event.capture.as_ref().unwrap()["provenance"]["kind"],
        "trustedGenesisAnchor"
    );
    let capture = p.events[1].event.capture.as_ref().unwrap();
    assert_eq!(capture["provenance"]["kind"], "full");
    assert_eq!(capture["parentStateRoot"].as_str().unwrap().len(), 66);
    assert_eq!(
        capture["effectiveParametersBytesHex"]
            .as_str()
            .unwrap()
            .len(),
        11 * 16
    );
}
#[test]
fn queued_pipeline_jobs_are_invisible_until_atomic_batch_commit() {
    let (mut s, _dir) = store();
    start(&mut s, true);
    let db = s.db_arc();
    // Deterministically block the worker's next write transaction.
    let blocker = db.begin_write().unwrap();
    let id2 = apply(&mut s, 2, 2, None);
    let id3 = apply(&mut s, 3, 3, None);
    let before = read_committed(&db, None, 100).unwrap();
    assert_eq!(before.meta.tip_height, 1);
    assert_eq!(before.events.len(), 1);
    drop(blocker);
    s.flush_persist_pipeline().unwrap();
    let after = page(&s);
    assert_eq!(after.events.len(), 3);
    assert_eq!(after.meta.tip_id, hex::encode(id3));
    assert_eq!(after.events[1].event.block_id, hex::encode(id2));
    assert!(!after.meta.reconstruction_required);
}
#[test]
fn wrong_state_root_leaves_no_journal_or_chain_update_on_both_paths() {
    for pipeline in [false, true] {
        let (mut s, _dir) = store();
        start(&mut s, pipeline);
        let before = page(&s).meta.cursor;
        let parent = s.root_digest();
        let (h, bytes, id) = header(
            2,
            s.chain_state().best_full_block_id,
            ADDigest::from_bytes([7; 33]),
            2,
        );
        let block = checked(&h, &bytes, id);
        let capture = CapturedBlock::checked(
            &block,
            &bytes,
            &parent,
            s.active_params(),
            s.validation_settings(),
            None,
        )
        .unwrap();
        assert!(s.apply_observed_block(&block, None, None, capture).is_err());
        s.flush_persist_pipeline().unwrap();
        assert_eq!(page(&s).meta.cursor, before);
        assert_eq!(s.height(), 1);
    }
}
#[test]
fn rollback_retains_old_branch_and_updates_canonical_pointer_atomically() {
    for pipeline in [false, true] {
        let (mut s, _dir) = store();
        let first = start(&mut s, pipeline);
        let old = apply(&mut s, 2, 2, None);
        apply(&mut s, 3, 3, None);
        s.rollback_to(1, None, None).unwrap();
        let rollback = page(&s);
        assert_eq!(rollback.meta.tip_id, hex::encode(first));
        assert_eq!(rollback.meta.branch_generation, 1);
        assert_eq!(rollback.events.len(), 4);
        assert_eq!(rollback.events[3].event.operation, "rollback");
        let new = apply(&mut s, 2, 99, None);
        s.flush_persist_pipeline().unwrap();
        let p = page(&s);
        assert_eq!(p.events[1].event.block_id, hex::encode(old));
        assert_eq!(p.events[4].event.block_id, hex::encode(new));
        assert_eq!(p.events[4].event.branch_generation, 1);
        let db = s.db_arc();
        let txn = db.begin_read().unwrap();
        let canonical = txn.open_table(CANONICAL).unwrap();
        assert_eq!(canonical.get(2).unwrap().unwrap().value(), 5);
        assert!(canonical.get(3).unwrap().is_none());
    }
}
#[test]
fn checkpoint_skipped_is_never_full_and_requires_reconstruction() {
    let (mut s, _dir) = store();
    start(&mut s, false);
    apply(&mut s, 2, 2, Some((10, [9; 32])));
    apply(&mut s, 3, 3, None);
    let p = page(&s);
    assert!(p.meta.reconstruction_required);
    assert_eq!(
        p.events[1].event.capture.as_ref().unwrap()["provenance"]["kind"],
        "checkpointSkipped"
    );
    assert!(p.events[1].event.gap_reason.is_some());
}
#[test]
fn generic_unchecked_apply_records_a_gap_instead_of_full() {
    let (mut s, _dir) = store();
    start(&mut s, false);
    let root = s.root_digest();
    s.apply_block_unchecked_for_test(2, &[2; 32], &root, &[])
        .unwrap();
    let p = page(&s);
    assert!(p.meta.reconstruction_required);
    assert!(p.events[1].event.capture.is_none());
}
#[test]
fn late_enablement_cannot_promote_historical_blocks() {
    let (mut s, _dir) = store();
    let root = s.root_digest();
    s.apply_genesis(&[1; 32], &root, &[]).unwrap();
    s.enable_applied_evidence([1; 32]).unwrap();
    assert!(page(&s).meta.reconstruction_required);
}
#[test]
fn restart_without_capture_still_journals_unobserved_apply_and_refuses_anchor_change() {
    let (mut s, dir) = store();
    let anchor = start(&mut s, false);
    let cursor = page(&s).meta.cursor;
    s.shutdown_cleanly().unwrap();
    drop(s);
    let mut reopened =
        StateStore::open_with_cache(&dir.path().join("state.redb"), 1 << 20).unwrap();
    assert_eq!(page(&reopened).meta.cursor, cursor);
    assert!(reopened.applied_evidence_anchor().is_none());
    let root = reopened.root_digest();
    reopened
        .apply_block_unchecked_for_test(2, &[2; 32], &root, &[])
        .unwrap();
    assert!(page(&reopened).meta.reconstruction_required);
    assert!(reopened.enable_applied_evidence([9; 32]).is_err());
    reopened.enable_applied_evidence(anchor).unwrap();
    assert!(page(&reopened).meta.reconstruction_required);
}
#[test]
fn cursor_pages_validate_identity_hash_and_rewind() {
    let (mut s, _dir) = store();
    start(&mut s, false);
    apply(&mut s, 2, 2, None);
    apply(&mut s, 3, 3, None);
    let db = s.db_arc();
    let p = read_committed(&db, None, 1).unwrap();
    assert_eq!(p.events.len(), 1);
    let q = read_committed(&db, Some(&p.next_cursor), 1).unwrap();
    assert_eq!(q.events[0].event.sequence, 2);
    let mut wrong = p.next_cursor.clone();
    wrong.event_hash = hex::encode([9; 32]);
    assert!(read_committed(&db, Some(&wrong), 10).is_err());
    wrong = p.next_cursor;
    wrong.archive_id = "wrong".into();
    assert!(read_committed(&db, Some(&wrong), 10).is_err());
    wrong = q.meta.cursor;
    wrong.sequence += 1;
    assert!(read_committed(&db, Some(&wrong), 10).is_err());
    assert!(read_committed(&db, None, 0).is_err());
    assert!(read_committed(&db, None, 1001).is_err());
}
#[test]
fn journal_gap_and_corrupt_record_refuse_committed_read() {
    for corrupt in [false, true] {
        let (mut s, _dir) = store();
        start(&mut s, false);
        apply(&mut s, 2, 2, None);
        let db = s.db_arc();
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(EVENTS).unwrap();
            if corrupt {
                table.insert(2, b"{\"corrupt\":true}".as_slice()).unwrap();
            } else {
                table.remove(2).unwrap();
            }
        }
        txn.commit().unwrap();
        assert!(read_committed(&db, None, 10).is_err());
    }
}
#[test]
fn generation_overflow_refuses_entire_rollback() {
    let (mut s, _dir) = store();
    start(&mut s, false);
    apply(&mut s, 2, 2, None);
    let db = s.db_arc();
    let txn = db.begin_write().unwrap();
    let mut meta = load_meta(&txn).unwrap();
    meta.branch_generation = MAX_GENERATION;
    save_meta(&txn, &meta).unwrap();
    txn.commit().unwrap();
    assert!(s.rollback_to(1, None, None).is_err());
    assert_eq!(s.height(), 2);
    assert_eq!(page(&s).meta.tip_height, 2);
    assert_eq!(page(&s).events.len(), 2);
}
#[test]
fn target_epoch_parameter_and_sigma_rule_fingerprints_use_activated_values() {
    use ergo_validation::voting::validation_settings::RuleStatus;
    let parent = ergo_validation::scala_launch();
    let rules = ErgoValidationSettings::empty();
    let mut target = parent.clone();
    target.epoch_start_height = 1024;
    target.input_cost += 1;
    target
        .activated_update
        .status_updates
        .push((1007, RuleStatus::Changed(vec![0x11])));
    let before = fingerprints(&parent, &rules).unwrap();
    let after = fingerprints(&target, &rules).unwrap();
    assert_ne!(before.0, after.0);
    assert_ne!(before.1, after.1);
    let mut pending = target.clone();
    pending
        .proposed_update
        .status_updates
        .push((1008, RuleStatus::Disabled));
    assert_eq!(fingerprints(&pending, &rules).unwrap().1, after.1);
    let cumulative = rules.updated(&target.activated_update);
    assert_ne!(fingerprints(&target, &cumulative).unwrap().1, after.1);
}
#[test]
fn wrong_capture_parameters_are_refused_before_apply() {
    let (mut s, _dir) = store();
    start(&mut s, false);
    let root = s.root_digest();
    let (h, bytes, id) = header(2, s.chain_state().best_full_block_id, root, 2);
    let block = checked(&h, &bytes, id);
    let mut wrong = s.active_params().clone();
    wrong.input_cost += 1;
    let capture =
        CapturedBlock::checked(&block, &bytes, &root, &wrong, s.validation_settings(), None)
            .unwrap();
    assert!(s.apply_observed_block(&block, None, None, capture).is_err());
    assert_eq!(s.height(), 1);
    assert_eq!(page(&s).events.len(), 1);
}
#[test]
fn arbitrary_genesis_and_trailing_bytes_cannot_become_an_anchor() {
    let (mut s, _dir) = store();
    let root = s.root_digest();
    let (_, mut bytes, id) = header(1, [0; 32], root, 1);
    assert!(CapturedBlock::trusted_genesis(
        &bytes,
        &root,
        &[],
        [9; 32],
        s.active_params(),
        s.validation_settings()
    )
    .is_err());
    bytes.push(0);
    assert!(CapturedBlock::trusted_genesis(
        &bytes,
        &root,
        &[],
        id,
        s.active_params(),
        s.validation_settings()
    )
    .is_err());
}

#[test]
fn production_parallel_validator_overlay_boxes_are_captured_without_reresolution() {
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::transaction::{transaction_id, Transaction};
    use ergo_validation::block::{validate_full_block_parallel, BlockValidationContext};
    use ergo_validation::context::UtxoView;
    use std::collections::HashMap;
    let tree = ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: true,
        constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        },
    };
    let candidate = |height| {
        ErgoBoxCandidate::new(
            1_000_000_000,
            tree.clone(),
            height,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    };
    let a = ErgoBox {
        candidate: candidate(99),
        transaction_id: ModifierId::from_bytes([11; 32]),
        index: 0,
    };
    let b = ErgoBox {
        candidate: candidate(99),
        transaction_id: ModifierId::from_bytes([12; 32]),
        index: 0,
    };
    let input = |id| Input {
        box_id: id,
        spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
    };
    let tx1 = Transaction {
        inputs: vec![input(a.box_id().unwrap())],
        data_inputs: vec![],
        output_candidates: vec![candidate(100)],
    };
    let c = ErgoBox {
        candidate: tx1.output_candidates[0].clone(),
        transaction_id: transaction_id(&tx1).unwrap(),
        index: 0,
    };
    let tx2 = Transaction {
        inputs: vec![input(c.box_id().unwrap())],
        data_inputs: vec![DataInput {
            box_id: a.box_id().unwrap(),
        }],
        output_candidates: vec![candidate(100)],
    };
    let d = ErgoBox {
        candidate: tx2.output_candidates[0].clone(),
        transaction_id: transaction_id(&tx2).unwrap(),
        index: 0,
    };
    let tx3 = Transaction {
        inputs: vec![input(b.box_id().unwrap())],
        data_inputs: vec![
            DataInput {
                box_id: c.box_id().unwrap(),
            },
            DataInput {
                box_id: d.box_id().unwrap(),
            },
        ],
        output_candidates: vec![candidate(100)],
    };
    struct Base(HashMap<Digest32, ErgoBox>);
    impl UtxoView for Base {
        fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
            self.0.get(id).cloned()
        }
    }
    let base = Base(HashMap::from([
        (a.box_id().unwrap(), a.clone()),
        (b.box_id().unwrap(), b),
    ]));
    let root = ADDigest::from_bytes([0; 33]);
    let (parent_h, parent_bytes, parent_id) = header(99, [0; 32], root, 99);
    let parent = CheckedHeader::from_persisted_parts(
        &parent_bytes,
        parent_id,
        1,
        99,
        [0; 32],
        parent_h.timestamp,
    )
    .unwrap();
    let (mut h, _, _) = header(100, parent_id, root, 100);
    let txs = vec![tx1, tx2, tx3];
    let ids: Vec<_> = txs.iter().map(|t| transaction_id(t).unwrap()).collect();
    let refs: Vec<&[u8]> = ids.iter().map(|id| id.as_bytes().as_slice()).collect();
    let empty_proof_hash = blake2b256(&[]);
    let proof_ids: Vec<&[u8]> = vec![&empty_proof_hash.as_bytes()[1..]; 3];
    h.transactions_root = Digest32::from_bytes(ergo_crypto::merkle::transactions_root(
        &refs,
        Some(&proof_ids),
    ));
    h.extension_root = Digest32::from_bytes(ergo_crypto::merkle::extension_root(&[(
        &[3u8, 0][..],
        &[1u8][..],
    )]));
    let (bytes, id) = serialize_header(&h).unwrap();
    let id = *id.as_bytes();
    let active = ergo_validation::scala_launch();
    let params = ergo_validation::context::ProtocolParams::from_active(&active);
    let ctx = BlockValidationContext {
        parent: &parent,
        utxo: &base,
        params: &params,
        voting_length: 1024,
        votes_unknown_rule_disabled: false,
        parent_extension: None,
        soft_fork_state: None,
        last_headers: &[],
        script_validation_checkpoint: None,
        reemission: None,
    };
    let checked = validate_full_block_parallel(
        CheckedHeader::from_persisted_parts(&bytes, id, 1, 100, parent_id, h.timestamp).unwrap(),
        &ergo_ser::block_transactions::BlockTransactions {
            header_id: ModifierId::from_bytes(id),
            transactions: txs,
        },
        &ergo_ser::extension::Extension {
            header_id: ModifierId::from_bytes(id),
            fields: vec![ergo_ser::extension::ExtensionField {
                key: [3, 0],
                value: vec![1],
            }],
        },
        &ctx,
    )
    .unwrap();
    // The base cannot resolve C or D. They come only from production's overlay.
    assert!(base.get_box(&c.box_id().unwrap()).is_none());
    assert!(base.get_box(&d.box_id().unwrap()).is_none());
    let captured = CapturedBlock::checked(
        &checked,
        &bytes,
        &root,
        &active,
        &ErgoValidationSettings::empty(),
        None,
    )
    .unwrap();
    assert_eq!(
        captured.transactions[1].resolved_inputs[0].bytes_hex,
        hex::encode(serialize_ergo_box(&c).unwrap())
    );
    assert_eq!(
        captured.transactions[1].resolved_data_inputs[0].bytes_hex,
        hex::encode(serialize_ergo_box(&a).unwrap())
    );
    assert_eq!(
        captured.transactions[2].resolved_data_inputs[0].bytes_hex,
        hex::encode(serialize_ergo_box(&c).unwrap())
    );
    assert_eq!(
        captured.transactions[2].resolved_data_inputs[1].bytes_hex,
        hex::encode(serialize_ergo_box(&d).unwrap())
    );
    assert_eq!(captured.transactions[1].transaction_index, 1);
    assert_eq!(captured.transactions[1].resolved_inputs[0].input_index, 0);
    assert_eq!(
        captured.transactions[1].resolved_inputs[0].origin,
        BoxOrigin::EarlierOutput
    );
    assert_eq!(
        captured.transactions[1].resolved_data_inputs[0].origin,
        BoxOrigin::PreBlock
    );
    assert_eq!(
        captured.transactions[2].resolved_data_inputs[0].origin,
        BoxOrigin::EarlierOutput
    );
    assert_eq!(
        captured.transactions[2].resolved_data_inputs[1].origin,
        BoxOrigin::EarlierOutput
    );
    assert_eq!(
        captured.transactions[1].context_extensions[0].input_index,
        0
    );
    assert_eq!(
        captured.transactions[1].context_extensions[0].bytes_hex,
        "00"
    );
    assert_eq!(captured.provenance, Provenance::Full);
}

#[test]
fn epoch_effective_row_and_evidence_co_commit_on_both_paths() {
    use ergo_validation::voting::validation_settings::RuleStatus;
    for pipeline in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut voting = ergo_chain_spec::VotingParams::mainnet();
        voting.voting_length = 4;
        let mut s = StateStore::open_with_cache_launch_voting(
            &dir.path().join("state.redb"),
            1 << 20,
            ergo_validation::scala_launch(),
            voting,
        )
        .unwrap();
        s.initialize_genesis(&[]).unwrap();
        start(&mut s, pipeline);
        apply(&mut s, 2, 2, None);
        apply(&mut s, 3, 3, None);
        let predecessor = s.validation_settings().clone();
        let mut target = s.active_params().clone();
        target.epoch_start_height = 4;
        target.input_cost += 77;
        target
            .activated_update
            .status_updates
            .push((1007, RuleStatus::Changed(vec![0x11])));
        let expected = fingerprints(&target, &predecessor).unwrap();
        let root = s.root_digest();
        let (h, bytes, id) = header(4, s.chain_state().best_full_block_id, root, 4);
        let block = checked(&h, &bytes, id);
        let capture =
            CapturedBlock::checked(&block, &bytes, &root, &target, &predecessor, None).unwrap();
        s.apply_observed_block(&block, Some(target.clone()), None, capture)
            .unwrap();
        s.flush_persist_pipeline().unwrap();
        let p = page(&s);
        let evidence = p.events[3].event.capture.as_ref().unwrap();
        assert_eq!(evidence["parametersDigest"], expected.0);
        assert_eq!(evidence["rulesDigest"], expected.1);
        assert_eq!(s.active_params_at(4).unwrap().unwrap(), target);
        assert_eq!(s.active_params(), &target);
        assert_ne!(
            fingerprints(&target, s.validation_settings()).unwrap().1,
            expected.1
        );
        assert!(!p.meta.reconstruction_required);
    }
}

#[test]
fn outbox_write_failure_aborts_chain_and_evidence_on_sync_and_batch_paths() {
    for pipeline in [false, true] {
        let (mut s, _dir) = store();
        start(&mut s, pipeline);
        let before = page(&s).meta;
        let db = s.db_arc();
        let txn = db.begin_write().unwrap();
        let mut blocked = load_meta(&txn).unwrap();
        blocked.cursor.sequence = MAX_GENERATION;
        save_meta(&txn, &blocked).unwrap();
        txn.commit().unwrap();
        let root = s.root_digest();
        let (h, bytes, id) = header(2, s.chain_state().best_full_block_id, root, 2);
        let block = checked(&h, &bytes, id);
        let capture = CapturedBlock::checked(
            &block,
            &bytes,
            &root,
            s.active_params(),
            s.validation_settings(),
            None,
        )
        .unwrap();
        let result = s.apply_observed_block(&block, None, None, capture);
        if pipeline {
            assert!(result.is_ok());
            assert!(s.flush_persist_pipeline().is_err());
        } else {
            assert!(result.is_err());
        }
        let txn = db.begin_read().unwrap();
        let chain = txn.open_table(crate::store::CHAIN_STATE_META).unwrap();
        let value = chain.get("chain_state").unwrap().unwrap();
        assert_eq!(
            crate::chain::ChainStateMeta::deserialize(value.value())
                .unwrap()
                .best_full_block_height,
            1
        );
        let events = txn.open_table(EVENTS).unwrap();
        assert!(events.get(2).unwrap().is_none());
        drop(events);
        drop(value);
        drop(chain);
        drop(txn);
        let txn = db.begin_write().unwrap();
        save_meta(&txn, &before).unwrap();
        txn.commit().unwrap();
        assert_eq!(read_committed(&db, None, 10).unwrap().events.len(), 1);
    }
}

#[test]
fn missing_metadata_is_corrupt_not_a_fresh_archive() {
    let (mut s, dir) = store();
    start(&mut s, false);
    let db = s.db_arc();
    let txn = db.begin_write().unwrap();
    txn.open_table(META).unwrap().remove("meta").unwrap();
    txn.commit().unwrap();
    assert!(recording_exists(&db).is_err());
    assert!(read_committed(&db, None, 10).is_err());
    s.shutdown_cleanly().unwrap();
    drop(s);
    drop(db);
    assert!(StateStore::open_with_cache(&dir.path().join("state.redb"), 1 << 20).is_err());
}
