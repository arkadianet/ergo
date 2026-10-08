use super::*;
use ergo_crypto::autolykos::common::blake2b256;
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_state::evidence::CapturedBlock;
use ergo_state::store::StateStore;
use redb::ReadableTable;

fn fixture() -> (StateStore, tempfile::TempDir, [u8; 32]) {
    let directory = tempfile::tempdir().unwrap();
    let mut store =
        StateStore::open_with_cache(&directory.path().join("reader.redb"), 1 << 20).unwrap();
    store.initialize_genesis(&[]).unwrap();
    let root = store.root_digest();
    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0; 32]),
        ad_proofs_root: Digest32::from_bytes([1; 32]),
        state_root: root,
        transactions_root: Digest32::from_bytes([0; 32]),
        extension_root: Digest32::from_bytes([0; 32]),
        timestamp: 1_700_000_001,
        n_bits: 0x1d00ffff,
        height: 1,
        votes: [0; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes(
                hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            nonce: [1; 8],
        },
    };
    let (bytes, id) = serialize_header(&header).unwrap();
    let anchor = *id.as_bytes();
    store.enable_applied_evidence(anchor).unwrap();
    let capture = CapturedBlock::trusted_genesis(
        &bytes,
        &root,
        &[],
        anchor,
        store.active_params(),
        store.validation_settings(),
    )
    .unwrap();
    store
        .apply_observed_genesis(&anchor, &root, &[], capture)
        .unwrap();
    (store, directory, anchor)
}

#[test]
fn committed_evidence_bridge_preserves_normative_event_bytes_source_tip_and_cursor() {
    let (mut store, _directory, anchor) = fixture();
    let root = store.root_digest();
    store
        .apply_block_unchecked_for_test(2, &[2; 32], &root, &[])
        .unwrap();
    let reader = CommittedEvidenceBridge::new(store.db_arc(), anchor);
    let first = reader.read_committed(None, 1).unwrap();
    let original = ergo_state::evidence::read_committed(&store.db_arc(), None, 1).unwrap();
    assert_eq!(first.source.configured_genesis_anchor, hex::encode(anchor));
    assert_eq!(first.meta.tip_id, hex::encode([2; 32]));
    assert_eq!(first.meta.tip_height, 2);
    assert_eq!(
        first.events[0].event_json,
        serde_json::to_string(&original.events[0].event).unwrap()
    );
    let mut preimage = b"ergo/applied-evidence/event/v1\0".to_vec();
    preimage.extend_from_slice(&(first.events[0].event_json.len() as u64).to_be_bytes());
    preimage.extend_from_slice(first.events[0].event_json.as_bytes());
    assert_eq!(
        hex::encode(blake2b256(&preimage)),
        first.events[0].event_hash
    );
    let event: serde_json::Value = serde_json::from_str(&first.events[0].event_json).unwrap();
    assert_eq!(
        event["capture"]["provenance"]["kind"],
        "trustedGenesisAnchor"
    );
    let second = reader.read_committed(Some(&first.next_cursor), 1).unwrap();
    assert_eq!(second.next_cursor.sequence, 2);
    assert!(second.meta.reconstruction_required);
    let gap: serde_json::Value = serde_json::from_str(&second.events[0].event_json).unwrap();
    assert!(gap["capture"].is_null());
    assert!(gap["gapReason"].is_string());
    let end = reader.read_committed(Some(&second.next_cursor), 1).unwrap();
    assert!(end.events.is_empty());
    assert_eq!(end.next_cursor, second.next_cursor);
    let mut wrong = first.next_cursor;
    wrong.event_hash = hex::encode([9; 32]);
    assert!(matches!(
        reader.read_committed(Some(&wrong), 1),
        Err(EvidenceReadError::ReconstructionRequired(_))
    ));
    assert!(matches!(
        CommittedEvidenceBridge::new(store.db_arc(), [9; 32]).read_committed(None, 1),
        Err(EvidenceReadError::ReconstructionRequired(_))
    ));
}

#[test]
fn committed_evidence_bridge_never_observes_queued_persist_jobs_or_overlay_tip() {
    let (mut store, _directory, anchor) = fixture();
    store.enable_persist_pipeline(8);
    let db = store.db_arc();
    let reader = CommittedEvidenceBridge::new(db.clone(), anchor);
    let blocker = db.begin_write().unwrap();
    let root = store.root_digest();
    store
        .apply_block_unchecked_for_test(2, &[2; 32], &root, &[])
        .unwrap();
    store
        .apply_block_unchecked_for_test(3, &[3; 32], &root, &[])
        .unwrap();
    assert_eq!(store.chain_state().best_full_block_height, 3);
    let before = reader.read_committed(None, 16).unwrap();
    assert_eq!(before.meta.tip_height, 1);
    assert_eq!(before.events.len(), 1);
    drop(blocker);
    store.flush_persist_pipeline().unwrap();
    let after = reader.read_committed(None, 16).unwrap();
    assert_eq!(after.meta.tip_height, 3);
    assert_eq!(after.meta.tip_id, hex::encode([3; 32]));
    assert_eq!(after.events.len(), 3);
}

#[test]
fn committed_evidence_bridge_refuses_missing_corrupt_and_bypassed_journal_rows() {
    for kind in ["gap", "corrupt", "tip"] {
        let (store, _directory, anchor) = fixture();
        let db = store.db_arc();
        let transaction = db.begin_write().unwrap();
        if kind == "tip" {
            let table_name = redb::TableDefinition::<&str, &[u8]>::new("chain_state_meta");
            let mut table = transaction.open_table(table_name).unwrap();
            let mut chain = ergo_state::chain::ChainStateMeta::deserialize(
                table.get("chain_state").unwrap().unwrap().value(),
            )
            .unwrap();
            chain.best_full_block_height = 2;
            table
                .insert("chain_state", chain.serialize().as_slice())
                .unwrap();
        } else {
            let table_name = redb::TableDefinition::<u64, &[u8]>::new("applied_evidence_events_v1");
            let mut table = transaction.open_table(table_name).unwrap();
            if kind == "gap" {
                table.remove(1).unwrap();
            } else {
                table.insert(1, b"{\"corrupt\":true}".as_slice()).unwrap();
            }
        }
        transaction.commit().unwrap();
        let reader = CommittedEvidenceBridge::new(db, anchor);
        assert!(
            matches!(
                reader.read_committed(None, 1),
                Err(EvidenceReadError::ReconstructionRequired(_))
            ),
            "{kind}"
        );
    }
}
