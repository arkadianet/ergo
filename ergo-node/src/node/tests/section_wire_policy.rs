//! #317: real typed persistence, RequestModifier serving and REST bridge,
//! compared with an unmodified Scala node's production HistoryStorage.
use super::*;
use ergo_api::NodeChainQuery;

#[test]
fn scala_section_storage_fixture_pins_received_wire_policy_and_rest_sizes() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/scala/block_section_storage_6_0_7.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let wire = hex::decode(case["wire_hex"].as_str().unwrap()).unwrap();
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            case["accepted"], true,
            "{label}: this fixture scopes accepted inputs"
        );
        let header_bytes = hex::decode(case["header_hex"].as_str().unwrap()).unwrap();
        let header = ergo_ser::header::read_header(&mut ergo_primitives::reader::VlqReader::new(
            &header_bytes,
        ))
        .unwrap();
        let header_id = *ergo_primitives::digest::blake2b256(&header_bytes).as_bytes();
        assert_eq!(hex::encode(header_id), case["header_id"], "{label}");
        let section_id: [u8; 32] = hex::decode(case["section_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            ergo_ser::modifier_id::compute_section_id(
                102,
                &header_id,
                header.transactions_root.as_bytes()
            ),
            section_id,
            "{label}"
        );
        let bt = ergo_ser::block_transactions::read_block_transactions(
            &mut ergo_primitives::reader::VlqReader::new(&wire),
        )
        .unwrap();
        let ids: Vec<_> = bt
            .transactions
            .iter()
            .map(|tx| ergo_ser::transaction::transaction_id(tx).unwrap())
            .collect();
        assert_eq!(
            ids.iter()
                .map(|id| hex::encode(id.as_bytes()))
                .collect::<Vec<_>>(),
            case["tx_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect::<Vec<_>>(),
            "{label}"
        );
        ergo_sync::coordinator::verify_section_modifier_id(102, &section_id, &wire).unwrap();
        let canonical = hex::decode(case["canonical_hex"].as_str().unwrap()).unwrap();
        let mut writer = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::block_transactions::write_block_transactions_with_version(
            &mut writer,
            &bt,
            header.version,
        )
        .unwrap();
        assert_eq!(
            writer.result(),
            canonical,
            "{label}: canonical writer must match Scala"
        );
        assert_eq!(case["stored_hex"], case["canonical_hex"], "{label}");
        assert_eq!(case["served_hex"], case["canonical_hex"], "{label}");

        for digest in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state.redb");
            let mut state = if digest {
                make_digest_state(&path)
            } else {
                make_state(&path)
            };
            state
                .store
                .store_validated_header(
                    &header_id,
                    &header_bytes,
                    &ergo_state::chain::HeaderMeta {
                        parent_id: *header.parent_id.as_bytes(),
                        height: header.height,
                        cumulative_score: vec![1],
                        pow_validity: 1,
                        timestamp: header.timestamp,
                    },
                    None,
                )
                .unwrap();
            state.executor.execute(
                Action::PersistSection {
                    modifier_id: section_id,
                    section_bytes: wire.clone(),
                    section_type: 102,
                },
                &mut state.store,
                &mut state.coordinator,
                Instant::now(),
                None,
            );
            assert_eq!(
                state.store.get_block_section(&section_id).unwrap().unwrap(),
                wire,
                "{label}"
            );
            let request = message::serialize_inv(&InvData {
                type_id: 102,
                ids: vec![section_id],
            })
            .unwrap();
            let peer = test_peer();
            let _receiver = register_connected_peer(&mut state, peer);
            let actions = handle_message(
                &mut state,
                peer,
                message::CODE_REQUEST_MODIFIER,
                &request,
                Instant::now(),
            );
            assert_eq!(actions.len(), 1, "{label}");
            let Action::SendToPeer { code, payload, .. } = &actions[0] else {
                panic!("{label}: no response")
            };
            assert_eq!(*code, message::CODE_MODIFIER);
            let served = message::deserialize_modifiers(payload).unwrap();
            assert_eq!(
                served.modifiers,
                vec![(section_id, wire.clone())],
                "{label}"
            );

            let publisher = crate::snapshot::SnapshotPublisher::new(
                ergo_api::types::ApiInfo {
                    agent_name: "test".into(),
                    node_name: "test".into(),
                    network: "mainnet".into(),
                    version: "test".into(),
                    started_at_unix_ms: 0,
                    uptime_seconds: 0,
                    target_block_interval_ms: 120_000,
                },
                Instant::now(),
                ergo_api::types::ApiWeightFunction::Cost,
            );
            let bridge = crate::api_bridge::ScalaCompatBridge::new(
                publisher.handle(),
                crate::api_bridge::ScalaCompatStatic {
                    name: "test".into(),
                    app_version: "test".into(),
                    network: "mainnet".into(),
                    voting_length: 1024,
                    launch_time_unix_ms: 0,
                    rest_api_url: None,
                    min_relay_fee_nano_erg: 1_000_000,
                },
                state.store.reader_handle(),
                ergo_chain_spec::DifficultyParams::mainnet(),
            );
            // This is the production NodeChainQuery method called by
            // GET /blocks/{id}/transactions, not a raw-P2P JSON substitute.
            let rest = serde_json::to_value(
                bridge
                    .try_block_transactions_by_id(&hex::encode(header_id))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                rest, case["rest_json_cached"],
                "{label}: REST parsed values and received size"
            );
            let mut canonical_size_rest = rest;
            canonical_size_rest["size"] = serde_json::json!(canonical.len());
            assert_eq!(
                canonical_size_rest, case["rest_json_reopened"],
                "{label}: only section size changes on Scala cache eviction"
            );
            drop(bridge);
            state.store.shutdown_cleanly().unwrap();
            drop(state);
            if digest {
                let store = ergo_state::DigestStateStore::open(
                    &path,
                    ergo_validation::scala_launch(),
                    ergo_chain_spec::VotingParams {
                        voting_length: 2,
                        ..ergo_chain_spec::VotingParams::mainnet()
                    },
                    [0; 33],
                )
                .unwrap();
                assert_eq!(store.get_block_section(&section_id).unwrap().unwrap(), wire);
            } else {
                let store = StateStore::open(&path).unwrap();
                assert_eq!(store.get_block_section(&section_id).unwrap().unwrap(), wire);
            }
        }
    }
}
