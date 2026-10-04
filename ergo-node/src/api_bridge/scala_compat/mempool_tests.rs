use super::*;
use ergo_api::types::{ApiInfo, ApiMempoolTransaction, ApiTxSource, ApiWeightFunction};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{transaction_id, write_transaction, Transaction};

#[test]
fn unconfirmed_cost_matches_all_views_and_unknown_is_null() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ergo_state::store::StateStore::open(&tmp.path().join("state.redb")).unwrap();
    let tree_bytes = [0, 8, 0xd3];
    let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut ergo_primitives::reader::VlqReader::new(
        &tree_bytes,
    ))
    .unwrap();
    let mut tx = Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([1; 32]),
            spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            1_000_000,
            tree,
            0,
            vec![ergo_ser::token::Token {
                token_id: Digest32::from_bytes([2; 32]),
                amount: 1,
            }],
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    };
    tx.output_candidates.push(
        ErgoBoxCandidate::new(
            1_000_000,
            ergo_ser::ergo_tree::read_ergo_tree(&mut ergo_primitives::reader::VlqReader::new(
                ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES,
            ))
            .unwrap(),
            0,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap(),
    );
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    let bytes = w.result();
    let size = bytes.len() as u32;
    let id = transaction_id(&tx).unwrap();
    let id_hex = hex::encode(id.as_bytes());
    let mut snap = crate::snapshot::NodeSnapshot::empty(
        ApiInfo {
            agent_name: "test".into(),
            node_name: "test".into(),
            network: "mainnet".into(),
            version: "test".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        },
        ApiWeightFunction::Cost,
    );
    snap.pool_full_txs = Arc::new(vec![(
        Digest32::from_bytes(*id.as_bytes()),
        Arc::from(bytes),
    )]);
    snap.mempool_transactions
        .transactions
        .push(ApiMempoolTransaction {
            tx_id: id_hex.clone(),
            fee_nano_erg: 1_000_000,
            fee_per_byte_nano_erg: 1,
            size_bytes: size,
            validation_cost_units: 21_456,
            priority_weight: 1,
            source: ApiTxSource::Api,
            input_count: 1,
            output_count: 1,
            parents_in_pool: 0,
            first_seen_unix_ms: 0,
            first_seen_age_ms: 0,
            last_checked_age_ms: 0,
        });
    let handle = Arc::new(arc_swap::ArcSwap::from_pointee(snap));
    let bridge = ScalaCompatBridge::new(
        handle.clone(),
        ScalaCompatStatic {
            name: "test".into(),
            app_version: "test".into(),
            network: "mainnet".into(),
            state_type: crate::config::StateType::Utxo,
            launch_time_unix_ms: 0,
            voting_length: ergo_chain_spec::ChainSpec::mainnet().voting.voting_length,
            rest_api_url: None,
            min_relay_fee_nano_erg: 2_500_000,
        },
        store.reader_handle(),
        ergo_chain_spec::DifficultyParams::mainnet(),
    );
    let responses = [
        bridge.pool_txs_paged(0, 10).remove(0),
        bridge.pool_tx_by_id(&id_hex).unwrap(),
        bridge.pool_txs_by_ergo_tree(&tree_bytes).remove(0),
        bridge.pool_txs_by_box_id(&[1; 32]).remove(0),
        bridge.pool_txs_by_token_id(&[2; 32]).remove(0),
        bridge.pool_txs_by_registers(&Default::default()).remove(0),
    ];
    for result in responses {
        let json = serde_json::to_value(result).unwrap();
        assert_eq!(json["cost"], 21_456);
        assert_eq!(json["size"], size);
        assert_eq!(json["id"], id_hex);
    }
    // Same bytes but no measured cost: never invent zero or omit the key.
    let empty =
        crate::snapshot::NodeSnapshot::empty(handle.load().info.clone(), ApiWeightFunction::Cost);
    let old = handle.swap(Arc::new(empty));
    let mut snap = Arc::try_unwrap(old).ok().unwrap();
    snap.mempool_transactions.transactions.clear();
    handle.store(Arc::new(snap));
    let unknown = serde_json::to_value(bridge.pool_tx_by_id(&id_hex).unwrap()).unwrap();
    assert!(unknown.get("cost").unwrap().is_null());
    let confirmed =
        serde_json::to_value(crate::api_bridge::compat::encode_transaction(&tx).unwrap()).unwrap();
    assert!(confirmed.get("cost").is_none());
    // A populated pool must also respect the configured fee floor.
    assert_eq!(bridge.pool_recommended_fee(1, 1), 2_500_000);
    // Sparse canonical observations supply the relay floor, not fabricated congestion.
    assert_eq!(bridge.pool_recommended_fee(1, 10_000), 2_500_000);
    assert_eq!(
        bridge.pool_expected_wait_time_ms(2_500_000, 10_000),
        pool_fee_stats::UNKNOWN_WAIT_MS
    );
    assert!(
        !bridge
            .pool_fee_estimate(120_000, 1000, 0)
            .unwrap()
            .available
    );
}

#[test]
fn fee_model_pauses_during_same_height_reorg_commit_lag() {
    let mut snap = crate::snapshot::NodeSnapshot::empty(
        ApiInfo {
            agent_name: "test".into(),
            node_name: "test".into(),
            network: "mainnet".into(),
            version: "test".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        },
        ApiWeightFunction::Cost,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    snap.recent_blocks = Arc::new(
        (0..4)
            .map(|offset| ergo_api::types::ApiRecentBlock {
                height: 100 - offset,
                header_id: format!("{:064x}", 100 - offset),
                ts_unix_ms: now - u64::from(offset) * 120_000,
                txs: 2,
                size_bytes: 1000,
                delivered_by: None,
                miner_pk: None,
                miner_address: None,
                fee_observation: Some(ergo_api::types::ApiBlockFeeObservation {
                    transactions_size_bytes: 900,
                    fee_paying_transactions: 1,
                    fee_paying_size_bytes: 500,
                    median_fee_per_byte_nano_erg: Some(2),
                }),
            })
            .collect(),
    );
    snap.status.best_full_block_height = 100;
    snap.tip.best_full_block.height = 100;
    snap.tip.best_full_block.header_id = snap.recent_blocks[0].header_id.clone();
    assert!(fee_model(&snap).is_some());
    // The applied tip has switched forks; persisted sections still describe
    // the old tip at the same height. Never forecast from those orphan samples.
    snap.tip.best_full_block.header_id = "ab".repeat(32);
    assert!(fee_model(&snap).is_none());
}
