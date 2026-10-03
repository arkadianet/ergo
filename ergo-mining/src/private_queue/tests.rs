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
    assert!(queue.reserved_inputs().is_empty());
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
    assert!(queue.expire(19, 102).unwrap());
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
