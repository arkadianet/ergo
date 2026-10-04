use super::*;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{write_transaction, Transaction};

/// Rollback window used by tests that do not exercise settlement.
const WINDOW: u32 = 200;

fn entry(input: u8) -> Entry {
    entry_spending([input; 32])
}

/// A distinct transaction for every `n`.
fn numbered_entry(n: u32) -> Entry {
    let mut input = [0xA5; 32];
    input[..4].copy_from_slice(&n.to_be_bytes());
    entry_spending(input)
}

fn entry_spending(input: [u8; 32]) -> Entry {
    let mut reader = VlqReader::new(&[0, 8, 0xd3]);
    let tx = Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes(input),
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
        vec![Digest32::from_bytes(input)],
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
        .reconcile(99, "fork".into(), &BTreeMap::new(), true, |_| true, WINDOW)
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
    let observe = |height: u32, tip: &str, applied: &BTreeMap<String, (u32, String)>, inputs| {
        queue
            .reconcile(height, tip.into(), applied, true, |_| inputs, WINDOW)
            .unwrap()
    };
    // Candidate membership is derived when listing, never stored.
    assert!(!observe(100, "parent", &BTreeMap::new(), true).changed);
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Queued
    );
    let mined = BTreeMap::from([(item.tx_id.clone(), (101, "block".into()))]);
    observe(101, "block", &mined, false);
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Mined
    );
    assert_eq!(queue.reserved_inputs(), BTreeSet::from([[1; 32]]));
    // A recorded confirmation is only re-checked after a rollback.
    assert!(!observe(101, "block", &BTreeMap::new(), false).changed);
    queue
        .reopen_rolled_back(&BTreeSet::from([item.tx_id.clone()]))
        .unwrap();
    observe(101, "fork", &BTreeMap::new(), false);
    assert_eq!(
        queue.entry(&item.tx_id).unwrap().state,
        PrivateTransactionState::Conflicted
    );
    observe(100, "parent", &BTreeMap::new(), true);
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
        .reconcile(99, "fork".into(), &BTreeMap::new(), true, |_| true, WINDOW)
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
        .reconcile(101, "block".into(), &applied, true, |_| false, WINDOW)
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
            true,
            |_| false,
            WINDOW,
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
        .reconcile(100, "fork".into(), &BTreeMap::new(), true, |_| true, WINDOW)
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
        .reconcile(101, "old-block".into(), &applied, true, |_| false, WINDOW)
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
            true,
            |_| false,
            WINDOW,
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

// ----- bounded retention -----

#[test]
fn finished_records_never_fill_the_queue_and_can_be_queued_again() {
    let queue = PrivateTransactionQueue::default();
    let ids: Vec<String> = (0..MAX_PRIVATE_TRANSACTIONS as u32)
        .map(|n| {
            queue
                .admit(
                    &numbered_entry(n),
                    PrivateTransactionOptions::default(),
                    10,
                    100,
                )
                .unwrap()
                .tx_id
        })
        .collect();
    let overflow = numbered_entry(MAX_PRIVATE_TRANSACTIONS as u32);
    assert!(queue
        .admit(&overflow, PrivateTransactionOptions::default(), 10, 100)
        .is_err());
    for id in &ids {
        queue.cancel(id).unwrap();
    }
    queue
        .admit(&overflow, PrivateTransactionOptions::default(), 10, 100)
        .expect("cancelled records no longer count against the bound");
    // A cancelled or expired id is a fresh item when queued again.
    let again = queue
        .admit(
            &numbered_entry(0),
            PrivateTransactionOptions::default(),
            11,
            100,
        )
        .unwrap();
    assert_eq!(again.state, PrivateTransactionState::Queued);
    assert_eq!(again.created_at_ms, 11);
    let expiring = PrivateTransactionOptions {
        expires_at_ms: Some(20),
        ..Default::default()
    };
    let expired = queue.admit(&entry(1), expiring, 10, 100).unwrap();
    queue.expire(20, 100).unwrap();
    queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 21, 100)
        .unwrap();
    assert_eq!(
        queue.entry(&expired.tx_id).unwrap().state,
        PrivateTransactionState::Queued
    );
    assert!(queue
        .selection_entries()
        .iter()
        .any(|e| hex::encode(e.tx_id.as_bytes()) == expired.tx_id));
}

#[test]
fn withdrawn_transactions_leave_no_signed_bytes_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    let cancelled = entry(1);
    let expiring = entry(2);
    let first = queue
        .admit(&cancelled, PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    queue
        .admit(
            &expiring,
            PrivateTransactionOptions {
                expires_at_ms: Some(20),
                ..Default::default()
            },
            10,
            100,
        )
        .unwrap();
    queue.cancel(&first.tx_id).unwrap();
    queue.expire(20, 100).unwrap();
    let file = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    for tx in [&cancelled, &expiring] {
        assert!(!file.contains(&hex::encode(&tx.bytes)), "signed bytes kept");
        assert!(!file.contains(&hex::encode(tx.inputs[0].as_bytes())));
    }
    assert!(queue.reserved_inputs().is_empty());
    assert!(queue.guarded_ids().is_empty());
    // Tombstones still answer for the ids after a restart.
    let reopened = PrivateTransactionQueue::open(&path).unwrap();
    assert_eq!(
        reopened.entry(&first.tx_id).unwrap().state,
        PrivateTransactionState::Cancelled
    );
}

#[test]
fn mined_bytes_stay_recoverable_through_the_rollback_window_only() {
    let queue = PrivateTransactionQueue::default();
    let item = queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    let mined = BTreeMap::from([(item.tx_id.clone(), (101, "block".into()))]);
    let observe = |height: u32, applied: &BTreeMap<String, (u32, String)>| {
        queue
            .reconcile(
                height,
                format!("tip-{height}"),
                applied,
                true,
                |_| false,
                10,
            )
            .unwrap()
    };
    observe(101, &mined);
    assert!(observe(110, &BTreeMap::new()).released.is_empty());
    assert_eq!(queue.guarded_ids().len(), 1, "within the window");
    // A rollback inside the window returns the signed bytes to selection.
    queue
        .reopen_rolled_back(&BTreeSet::from([item.tx_id.clone()]))
        .unwrap();
    assert_eq!(queue.selection_entries().len(), 1);
    observe(101, &mined);

    let settled = observe(111, &BTreeMap::new());
    assert_eq!(settled.released, vec![item.tx_id.clone()]);
    assert!(settled.changed);
    assert!(queue.guarded_ids().is_empty());
    assert!(queue.reserved_inputs().is_empty());
    let tombstone = queue.entry(&item.tx_id).unwrap();
    assert_eq!(tombstone.state, PrivateTransactionState::Mined);
    assert_eq!(tombstone.mined_height, Some(101));
    // Resubmitting the same bytes is idempotent.
    assert_eq!(
        queue
            .admit(&entry(1), PrivateTransactionOptions::default(), 30, 120)
            .unwrap()
            .state,
        PrivateTransactionState::Mined
    );
}

#[test]
fn tombstones_are_bounded_and_the_oldest_are_forgotten() {
    let queue = PrivateTransactionQueue::default();
    let extra = 5;
    let ids: Vec<String> = (0..(MAX_FINISHED_RECORDS + extra) as u32)
        .map(|n| {
            let id = queue
                .admit(
                    &numbered_entry(n),
                    PrivateTransactionOptions::default(),
                    10,
                    100,
                )
                .unwrap()
                .tx_id;
            queue.cancel(&id).unwrap();
            id
        })
        .collect();
    assert_eq!(queue.list().len(), MAX_FINISHED_RECORDS);
    for id in &ids[..extra] {
        assert!(queue.entry(id).is_none(), "oldest tombstone forgotten");
    }
    assert!(queue.entry(ids.last().unwrap()).is_some());
}

#[test]
fn cursor_only_progress_is_written_in_bounded_steps() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    queue
        .admit_at_tip(
            &entry(1),
            PrivateTransactionOptions::default(),
            10,
            100,
            Some("tip-100".into()),
        )
        .unwrap();
    let observe = |height: u32| {
        queue
            .reconcile(
                height,
                format!("tip-{height}"),
                &BTreeMap::new(),
                true,
                |_| true,
                WINDOW,
            )
            .unwrap()
    };
    let on_disk = || {
        PrivateTransactionQueue::open(&path)
            .unwrap()
            .observation_cursor()
    };
    for height in 101..100 + CURSOR_PERSIST_INTERVAL {
        assert!(!observe(height).changed);
    }
    assert_eq!(
        on_disk(),
        (100, Some("tip-100".into())),
        "no rewrite per block"
    );
    assert_eq!(
        queue.observation_cursor(),
        (131, Some("tip-131".into())),
        "the live cursor still advances"
    );
    observe(100 + CURSOR_PERSIST_INTERVAL);
    assert_eq!(on_disk(), (132, Some("tip-132".into())));
}

#[test]
fn a_failed_write_is_a_storage_error_and_a_bad_request_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.json");
    let queue = PrivateTransactionQueue::open(&path).unwrap();
    let item = queue
        .admit(&entry(1), PrivateTransactionOptions::default(), 10, 100)
        .unwrap();
    let elapsed = PrivateTransactionOptions {
        expires_at_height: Some(100),
        ..Default::default()
    };
    assert!(matches!(
        queue.admit(&entry(2), elapsed, 10, 100),
        Err(PrivateQueueError::Rejected(_))
    ));
    assert!(matches!(
        queue.cancel(&"ab".repeat(32)),
        Err(PrivateQueueError::Rejected(_))
    ));
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        queue.admit(&entry(3), PrivateTransactionOptions::default(), 10, 100),
        Err(PrivateQueueError::Storage(_))
    ));
    assert!(matches!(
        queue.cancel(&item.tx_id),
        Err(PrivateQueueError::Storage(_))
    ));
}
