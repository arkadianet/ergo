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
    let first_snapshot = handle.load_full();
    let ranked = bridge.ranked_pool(&first_snapshot);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].cost_units, 21_456);
    assert!(Arc::ptr_eq(&ranked, &bridge.ranked_pool(&first_snapshot)));
    drop(first_snapshot);
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
    let next_snapshot = handle.load_full();
    let next_ranked = bridge.ranked_pool(&next_snapshot);
    assert!(!Arc::ptr_eq(&ranked, &next_ranked));
    assert_eq!(next_ranked[0].cost_units, 0);
    assert!(Arc::ptr_eq(
        &next_ranked,
        &bridge.ranked_pool(&next_snapshot)
    ));
    drop(next_snapshot);
    let unknown = serde_json::to_value(bridge.pool_tx_by_id(&id_hex).unwrap()).unwrap();
    assert!(unknown.get("cost").unwrap().is_null());
    let confirmed =
        serde_json::to_value(crate::api_bridge::compat::encode_transaction(&tx).unwrap()).unwrap();
    assert!(confirmed.get("cost").is_none());
    // A populated pool must also respect the configured fee floor.
    assert_eq!(bridge.pool_recommended_fee(1, 1), 2_500_000);
    // Sparse canonical observations supply the relay floor, not fabricated congestion.
    assert_eq!(bridge.pool_recommended_fee(1, 10_000), 2_500_000);
    assert_eq!(bridge.pool_expected_wait_time_ms(2_500_000, 10_000), 0);
    assert!(
        !bridge
            .pool_fee_estimate(120_000, 1000, 0)
            .unwrap()
            .available
    );
    assert_eq!(bridge.pool_wait_estimate_ms(2_500_000, 10_000), None);
    assert_eq!(bridge.pool_expected_wait_time_ms(2_500_000, 0), 0);
    let mut digest = bridge;
    Arc::make_mut(&mut digest.static_cfg).state_type = crate::config::StateType::Digest;
    let estimate = digest.pool_fee_estimate(120_000, 1000, 0).unwrap();
    assert!(!estimate.available);
    assert_eq!(
        estimate.reason.as_deref(),
        Some("observed fee estimates require UTXO state")
    );
    assert_eq!(digest.pool_expected_wait_time_ms(2_500_000, 1000), 0);
    assert_eq!(digest.pool_recommended_fee(1, 1000), 2_500_000);
    Arc::make_mut(&mut digest.static_cfg).min_relay_fee_nano_erg = u64::MAX;
    assert_eq!(
        digest.pool_recommended_fee(u32::MAX, u32::MAX),
        i64::MAX as u64
    );
}

#[test]
fn fee_model_uses_committed_tip_during_apply_lag_and_rejects_replaced_samples() {
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
    let committed_id = hex::decode(&snap.recent_blocks[0].header_id)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(fee_model(&snap, Some((100, committed_id))).is_some());
    // In-memory apply can lead the durable chain by a tick. Keep using the
    // committed window until the persist pipeline catches up.
    snap.status.best_full_block_height = 101;
    snap.tip.best_full_block.height = 101;
    snap.tip.best_full_block.header_id = "ab".repeat(32);
    assert!(fee_model(&snap, Some((100, committed_id))).is_some());
    // Once the committed chain changes, old cached samples cannot forecast.
    assert!(fee_model(&snap, Some((100, [0xab; 32]))).is_none());
    let mut replacement = (*snap.recent_blocks).clone();
    replacement[0].header_id = "ab".repeat(32);
    replacement[0]
        .fee_observation
        .as_mut()
        .unwrap()
        .median_fee_per_byte_nano_erg = Some(20);
    snap.recent_blocks = Arc::new(replacement);
    assert!(fee_model(&snap, Some((100, [0xab; 32]))).is_some());
    snap.produced_at -= std::time::Duration::from_secs(61);
    assert!(fee_model(&snap, Some((100, [0xab; 32]))).is_none());
}

#[test]
fn compat_histogram_uses_pool_residence_age_and_fee_factor() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ergo_state::store::StateStore::open(&tmp.path().join("state.redb")).unwrap();
    for weight in [
        ApiWeightFunction::Cost,
        ApiWeightFunction::Size,
        ApiWeightFunction::Min,
    ] {
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
            weight,
        );
        snap.mempool_transactions.transactions = [0, 12_000, 60_000]
            .into_iter()
            .enumerate()
            .map(|(index, age)| ApiMempoolTransaction {
                tx_id: format!("{index:064x}"),
                fee_nano_erg: 1_000_000,
                fee_per_byte_nano_erg: 5000,
                size_bytes: 200,
                validation_cost_units: 100,
                priority_weight: 9999,
                source: ApiTxSource::Api,
                input_count: 1,
                output_count: 2,
                parents_in_pool: 0,
                first_seen_unix_ms: 0,
                first_seen_age_ms: age,
                last_checked_age_ms: 0,
            })
            .collect();
        let mut full_txs = Vec::new();
        for (index, row) in snap
            .mempool_transactions
            .transactions
            .iter_mut()
            .enumerate()
        {
            let tx = Transaction {
                inputs: vec![Input {
                    box_id: Digest32::from_bytes([index as u8; 32]),
                    spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty())
                        .unwrap(),
                }],
                data_inputs: vec![],
                output_candidates: vec![ErgoBoxCandidate::new(
                    row.fee_nano_erg,
                    ergo_ser::ergo_tree::read_ergo_tree(
                        &mut ergo_primitives::reader::VlqReader::new(
                            ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES,
                        ),
                    )
                    .unwrap(),
                    0,
                    vec![],
                    AdditionalRegisters::empty(),
                )
                .unwrap()],
            };
            let id = transaction_id(&tx).unwrap();
            let mut writer = VlqWriter::new();
            write_transaction(&mut writer, &tx).unwrap();
            let bytes = writer.result();
            row.tx_id = hex::encode(id.as_bytes());
            row.size_bytes = bytes.len() as u32;
            row.fee_per_byte_nano_erg = row.fee_nano_erg / u64::from(row.size_bytes);
            row.output_count = 1;
            full_txs.push((Digest32::from_bytes(*id.as_bytes()), Arc::from(bytes)));
        }
        snap.pool_full_txs = Arc::new(full_txs);
        let size = u64::from(snap.mempool_transactions.transactions[0].size_bytes);
        let factor = match weight {
            ApiWeightFunction::Cost => 100,
            ApiWeightFunction::Size => size,
            ApiWeightFunction::Min => 100.max(size),
        };
        let bridge = ScalaCompatBridge::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(snap)),
            ScalaCompatStatic {
                name: "test".into(),
                app_version: "test".into(),
                network: "mainnet".into(),
                state_type: crate::config::StateType::Utxo,
                voting_length: 1024,
                launch_time_unix_ms: 0,
                rest_api_url: None,
                min_relay_fee_nano_erg: 1_000_000,
            },
            store.reader_handle(),
            ergo_chain_spec::DifficultyParams::mainnet(),
        );
        let bins = bridge.pool_fee_histogram(10, 60_000);
        assert_eq!(bins.len(), 11);
        for index in [0, 2, 10] {
            assert_eq!(bins[index].n_txns, 1);
            assert_eq!(bins[index].total_fee, 1_000_000 * 1024 / factor);
        }
        assert_eq!(bins.iter().map(|bin| bin.n_txns).sum::<u32>(), 3);
        assert_eq!(bridge.pool_fee_histogram(10, 0)[10].n_txns, 3);
        assert_eq!(
            bridge.pool_fee_histogram(u32::MAX, 60_000).len(),
            pool_fee_stats::MAX_HISTOGRAM_BINS + 1
        );
    }
}
