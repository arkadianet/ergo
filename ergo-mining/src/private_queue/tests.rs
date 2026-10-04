use super::*;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{write_transaction, Transaction};

fn entry(input: u8) -> Entry {
    let mut reader = VlqReader::new(&[0, 8, 0xd3]);
    let tx = Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([input; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            1_000_000,
            read_ergo_tree(&mut reader).unwrap(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    };
    let id = transaction_id(&tx).unwrap();
    let mut writer = VlqWriter::new();
    write_transaction(&mut writer, &tx).unwrap();
    let bytes = writer.result();
    read_transaction(&mut VlqReader::new(&bytes)).expect("synthetic signed transaction round trip");
    Entry::new(
        Digest32::from_bytes(*id.as_bytes()),
        Arc::from(bytes.clone()),
        vec![Digest32::from_bytes([input; 32])],
        vec![],
        vec![],
        0,
        0,
        bytes.len() as u32,
        100,
        TxSource::Wallet,
    )
}

#[test]
fn restart_recovers_private_bytes_and_reservations_without_public_pool() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    let tx = entry(1);
    let item = queue
        .admit(&tx, PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    drop(queue);
    let reopened = PrivateTransactionQueue::open(&path).unwrap();
    assert_eq!(reopened.reserved_inputs(), BTreeSet::from([[1; 32]]));
    assert_eq!(
        reopened.selection_entries()[0].bytes.as_ref(),
        tx.bytes.as_ref()
    );
    assert_eq!(reopened.selection_entries()[0].fee, 0);
    reopened.cancel(&item.tx_id).unwrap();
    let reopened = PrivateTransactionQueue::open(&path).unwrap();
    assert!(reopened.reserved_inputs().is_empty());
    reopened
        .reconcile(
            99,
            "fork".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| true,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        reopened.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Cancelled
    );
    assert!(reopened.selection_entries().is_empty());
}

#[test]
fn mined_and_conflicted_items_recover_after_rollback() {
    let queue = PrivateTransactionQueue::default();
    let item = queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    let candidate = BTreeSet::from([item.tx_id.clone()]);
    queue
        .reconcile(
            100,
            "parent".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| true,
            &candidate,
        )
        .unwrap();
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::InCandidate
    );
    let mined = BTreeMap::from([(item.tx_id.clone(), (101, "block".into()))]);
    queue
        .reconcile(
            101,
            "block".into(),
            &mined,
            |_, _| true,
            |_| false,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Mined
    );
    assert_eq!(queue.reserved_inputs(), BTreeSet::from([[1; 32]]));
    queue
        .reconcile(
            101,
            "fork".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| false,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Conflicted
    );
    queue
        .reconcile(
            100,
            "parent".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| true,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Queued
    );
    assert_eq!(queue.reserved_inputs(), BTreeSet::from([[1; 32]]));
}

#[test]
fn height_and_time_deadlines_filter_builds_and_never_reactivate() {
    let queue = PrivateTransactionQueue::default();
    let options = PrivateTransactionOptions {
        expires_at_ms: Some(20),
        expires_at_height: Some(102),
        ..Default::default()
    };
    let item = queue.admit(&entry(1), options, 10, 100).unwrap();
    assert_eq!(queue.selection_entries_at(19, 101).len(), 1);
    assert!(queue.selection_entries_at(19, 102).is_empty());
    assert!(queue.selection_entries_at(20, 101).is_empty());
    assert_eq!(queue.expire(19, 102).unwrap(), vec![item.tx_id.clone()]);
    queue
        .reconcile(
            99,
            "fork".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| true,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Expired
    );
    assert!(queue.selection_entries().is_empty());
    assert!(queue
        .admit(
            &entry(2),
            PrivateTransactionOptions {
                expires_at_height: Some(100),
                ..Default::default()
            },
            10,
            100
        )
        .is_err());
}

#[test]
fn duplicate_input_reservation_and_failed_commit_do_not_release_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    let tx = entry(1);
    let item = queue
        .admit(&tx, PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    let mut conflicting = entry(2);
    conflicting.inputs = tx.inputs;
    assert!(queue
        .admit(&conflicting, PrivateTransactionOptions::default(), 11, 100)
        .is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(queue.cancel(&item.tx_id).is_err());
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Queued
    );
    assert_eq!(queue.reserved_inputs(), BTreeSet::from([[1; 32]]));
}

#[test]
fn corrupted_reservation_metadata_fails_startup_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    let mut store: Store = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    store
        .records
        .values_mut()
        .next()
        .unwrap()
        .entry
        .input_ids
        .clear();
    std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();
    assert!(PrivateTransactionQueue::open(&path).is_err());
}

#[test]
fn confirmation_overrides_an_expiry_or_cancellation_that_raced_its_block() {
    // The block confirming each transaction was applied before the queue
    // noticed, but the deadline or the operator's cancel landed first.
    let queue = PrivateTransactionQueue::default();
    let expiring = queue
        .admit(
            &entry(1),
            PrivateTransactionOptions {
                expires_at_ms: Some(20),
                ..Default::default()
            },
            10,
            100,
        )
        .unwrap();
    let cancelled = queue
        .admit(&entry(2), PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    assert_eq!(queue.expire(20, 100).unwrap(), vec![expiring.tx_id.clone()]);
    queue.cancel(&cancelled.tx_id).unwrap();
    let applied = BTreeMap::from([
        (expiring.tx_id.clone(), (101, "block".into())),
        (cancelled.tx_id.clone(), (101, "block".into())),
    ]);
    queue
        .reconcile(
            101,
            "block".into(),
            &applied,
            |_, _| true,
            |_| false,
            &BTreeSet::new(),
        )
        .unwrap();
    for id in [&expiring.tx_id, &cancelled.tx_id] {
        let item = queue.entry(id).unwrap();
        assert_eq!(item.state, PrivateTransactionState::Mined);
        assert_eq!(item.mined_height, Some(101));
    }
    assert!(
        queue.cancel(&cancelled.tx_id).is_err(),
        "mined cannot be cancelled"
    );
    assert!(queue.expire(u64::MAX, u32::MAX).unwrap().is_empty());

    // Rolling the block back restores the withdrawal, never the queue.
    queue
        .reopen_rolled_back(&BTreeSet::from([
            expiring.tx_id.clone(),
            cancelled.tx_id.clone(),
        ]))
        .unwrap();
    assert_eq!(
        queue.entry(&expiring.tx_id).unwrap().state,
        PrivateTransactionState::Expired
    );
    assert_eq!(
        queue.entry(&cancelled.tx_id).unwrap().state,
        PrivateTransactionState::Cancelled
    );
    assert!(queue.selection_entries().is_empty());
}

#[test]
fn cancelling_a_conflict_prevents_reactivation_after_rollback() {
    let queue = PrivateTransactionQueue::default();
    let item = queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    queue
        .reconcile(
            101,
            "competing-spend".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| false,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Conflicted
    );
    assert_eq!(
        queue.cancel(&item.tx_id).unwrap().state,
        PrivateTransactionState::Cancelled
    );
    queue
        .reconcile(
            100,
            "fork".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| true,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Cancelled
    );
}

#[test]
fn first_admission_persists_branch_identity_before_lifecycle_tick() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    let tip = hex::encode([9; 32]);
    queue
        .admit_at_tip(
            &entry(1),
            PrivateTransactionOptions::default(),
            10,
            100,
            Some(tip.clone()),
        )
        .unwrap();
    let restarted = PrivateTransactionQueue::open(&path).unwrap();
    assert_eq!(restarted.observation_cursor(), (100, Some(tip)));
}

#[test]
fn mined_and_conflicted_inputs_remain_reserved_before_history_catchup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    let item = queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    let applied = BTreeMap::from([(item.tx_id.clone(), (101, "old-block".into()))]);
    queue
        .reconcile(
            101,
            "old-block".into(),
            &applied,
            |_, _| true,
            |_| false,
            &BTreeSet::new(),
        )
        .unwrap();
    let restarted = PrivateTransactionQueue::open(&path).unwrap();
    // This reservation is already present if chain state restores the input,
    // before any lifecycle tick or deep ancestor scan has run.
    assert_eq!(restarted.reserved_inputs(), BTreeSet::from([[1; 32]]));
    let cursor = restarted.observation_cursor();
    restarted
        .reopen_rolled_back(&BTreeSet::from([item.tx_id.clone()]))
        .unwrap();
    assert_eq!(restarted.observation_cursor(), cursor);
    assert_eq!(
        restarted.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Queued
    );
    restarted
        .reconcile(
            101,
            "competing-block".into(),
            &BTreeMap::new(),
            |_, _| false,
            |_| false,
            &BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(restarted.reserved_inputs(), BTreeSet::from([[1; 32]]));
    restarted.cancel(&item.tx_id).unwrap();
    assert!(restarted.reserved_inputs().is_empty());
}

#[test]
fn opening_sweeps_temporaries_left_by_an_interrupted_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    // Names from every temporary scheme: pid, pid plus counter, random.
    let stale = [
        "queue.4242.tmp",
        "queue.1.0.tmp",
        "queue.00ff00ff00ff00ff.tmp",
    ];
    for name in stale {
        std::fs::write(dir.path().join(name), b"signed bytes").unwrap();
    }
    let unrelated = ["other.tmp", "queue.json.bak", "queue.tmp"];
    for name in unrelated {
        std::fs::write(dir.path().join(name), b"keep").unwrap();
    }
    PrivateTransactionQueue::open(&path).unwrap();
    for name in stale {
        assert!(!dir.path().join(name).exists(), "{name} was not swept");
    }
    for name in unrelated {
        assert!(dir.path().join(name).exists(), "{name} must be kept");
    }
}

#[test]
fn leftover_temporaries_named_from_the_process_id_do_not_block_commits() {
    // A container restarts the node under the same process id, so names built
    // from the pid and a per-start counter repeat the previous run's leftovers.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    let pid = std::process::id();
    for sequence in 0..2048 {
        std::fs::write(dir.path().join(format!("queue.{pid}.{sequence}.tmp")), b"").unwrap();
    }
    queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 10, 100)
        .expect("a random temporary name avoids the leftovers");
}
