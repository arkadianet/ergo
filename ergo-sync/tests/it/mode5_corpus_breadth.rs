//! External Scala captures exercise full digest block processing on two
//! additional mainnet windows and public testnet, including corrupted-proof rejection and
//! rollback/replay. These windows complement the existing voting-boundary
//! corpus rather than replacing it.

use std::collections::BTreeMap;
use std::path::Path;

use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ad_proofs::{write_ad_proofs, ADProofs};
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::chain::{ChainStateMeta, HeaderAvailability, HeaderMeta};
use ergo_state::{
    BlockApply, ChainStateRead, DigestStateStore, HeaderSectionStore, StateBackendKind,
};
use ergo_sync::block_proc::process_block;
use ergo_validation::active_params::{parse_active_params, ActiveProtocolParameters};
use ergo_validation::voting::validation_settings::parse_validation_settings_update;

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}
fn fixed<const N: usize>(value: &serde_json::Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}
fn json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn store_header(store: &mut DigestStateStore, bytes: &[u8], expected_id: [u8; 32]) {
    assert_eq!(
        *blake2b256(bytes).as_bytes(),
        expected_id,
        "captured header must match reference-reported identity"
    );
    let header = read_header(&mut VlqReader::new(bytes)).unwrap();
    let meta = HeaderMeta {
        height: header.height,
        parent_id: *header.parent_id.as_bytes(),
        timestamp: header.timestamp,
        pow_validity: 1,
        cumulative_score: u64::from(header.height).to_be_bytes().to_vec(),
    };
    store
        .store_validated_header(&expected_id, bytes, &meta, None)
        .unwrap();
    store
        .seed_header_chain_index_for_test(header.height, &expected_id)
        .unwrap();
}

fn open(path: &Path, network: ergo_chain_spec::Network) -> DigestStateStore {
    DigestStateStore::open(
        path,
        ergo_validation::scala_launch_for_network(network),
        ergo_chain_spec::ChainSpec::for_network(network).voting,
        ergo_chain_spec::GenesisParams::for_network(network).state_digest,
    )
    .unwrap()
}

fn fixture(
    directory: &str,
    path: &Path,
) -> (
    StateBackendKind,
    BTreeMap<u32, serde_json::Value>,
    ergo_chain_spec::Network,
    ActiveProtocolParameters,
) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors/mode5/breadth")
        .join(directory);
    let context = json(&root.join("context.json"));
    let network = match context["network"].as_str().unwrap() {
        "mainnet" => ergo_chain_spec::Network::Mainnet,
        "testnet" => ergo_chain_spec::Network::Testnet,
        other => panic!("unexpected fixture network: {other}"),
    };
    assert_eq!(context["reference_info"]["network"], context["network"]);
    assert!(
        context["reference_info"]["appVersion"]
            .as_str()
            .unwrap()
            .starts_with("6."),
        "fixture must identify its Scala reference version"
    );
    let from = context["from"].as_u64().unwrap() as u32;
    let to = context["to"].as_u64().unwrap() as u32;
    let epoch_start = context["epoch_start"].as_u64().unwrap() as u32;
    let epoch_bytes = bytes(&context["epoch_header"]["bytes"]);
    let epoch_header = read_header(&mut VlqReader::new(&epoch_bytes)).unwrap();
    assert_eq!(epoch_header.height, epoch_start);
    assert_eq!(
        *blake2b256(&epoch_bytes).as_bytes(),
        fixed::<32>(&context["epoch_header"]["id"])
    );
    let extension_bytes = bytes(&context["epoch_extension_bytes"]);
    let extension =
        ergo_ser::extension::read_extension(&mut VlqReader::new(&extension_bytes)).unwrap();
    let fields: Vec<_> = extension
        .fields
        .iter()
        .map(|field| (field.key.as_slice(), field.value.as_slice()))
        .collect();
    assert_eq!(
        ergo_crypto::merkle::extension_root(&fields),
        *epoch_header.extension_root.as_bytes(),
        "parameter context must match the independently captured epoch header commitment"
    );
    let mut params = parse_active_params(&extension, epoch_start).unwrap();
    params.activated_update = parse_validation_settings_update(&extension).unwrap();
    assert_eq!(
        params,
        ActiveProtocolParameters::deserialize(&bytes(&context["active_params_hex"])).unwrap()
    );
    let mut store = open(path, network);
    store.seed_voted_params_row_for_test(&params).unwrap();
    let context_headers = context["context_headers"].as_object().unwrap();
    for height in from - 10..from {
        let row = &context_headers[&height.to_string()];
        store_header(&mut store, &bytes(&row["bytes"]), fixed(&row["id"]));
    }
    let mut rows = BTreeMap::new();
    let mut parent_id = fixed::<32>(&context_headers[&(from - 1).to_string()]["id"]);
    let parent_bytes = bytes(&context_headers[&(from - 1).to_string()]["bytes"]);
    let mut parent_root = *read_header(&mut VlqReader::new(&parent_bytes))
        .unwrap()
        .state_root
        .as_bytes();
    for height in from..=to {
        let row = json(&root.join(format!("{height}.json")));
        let raw = bytes(&row["header_bytes"]);
        let id = fixed::<32>(&row["header_id"]);
        let header = read_header(&mut VlqReader::new(&raw)).unwrap();
        assert_eq!(header.height, height);
        assert_eq!(*header.parent_id.as_bytes(), parent_id);
        assert_eq!(fixed::<33>(&row["parent_state_root"]), parent_root);
        assert_eq!(
            *header.state_root.as_bytes(),
            fixed::<33>(&row["state_root"])
        );
        store_header(&mut store, &raw, id);
        let expected = ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        store
            .store_block_section_typed(
                &expected.transactions_id,
                &bytes(&row["block_tx_bytes"]),
                102,
            )
            .unwrap();
        store
            .store_block_section_typed(&expected.extension_id, &bytes(&row["extension_bytes"]), 108)
            .unwrap();
        let proof = bytes(&row["proof_bytes"]);
        assert_eq!(blake2b256(&proof), header.ad_proofs_root);
        let mut writer = VlqWriter::new();
        write_ad_proofs(
            &mut writer,
            &ADProofs {
                header_id: ModifierId::from_bytes(id),
                proof_bytes: proof,
            },
        );
        store
            .store_block_section_typed(&expected.ad_proofs_id, &writer.result(), 104)
            .unwrap();
        parent_id = id;
        parent_root = *header.state_root.as_bytes();
        rows.insert(height, row);
    }
    store.seed_tip_for_test(
        fixed(&rows[&from]["parent_state_root"]),
        ChainStateMeta {
            best_header_id: fixed(&rows[&to]["header_id"]),
            best_header_height: to,
            best_header_score: u64::from(to).to_be_bytes().to_vec(),
            best_full_block_id: fixed(&context_headers[&(from - 1).to_string()]["id"]),
            best_full_block_height: from - 1,
            header_availability: HeaderAvailability::Dense,
        },
    );
    (StateBackendKind::Digest(store), rows, network, params)
}

fn apply(backend: &mut StateBackendKind, height: u32, row: &serde_json::Value) {
    let id = fixed::<32>(&row["header_id"]);
    let processed = process_block(
        backend,
        &id,
        &ergo_validation::context::ProtocolParams::mainnet_default(),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("captured block {height} failed: {error}"));
    assert_eq!(processed.height, height);
    let StateBackendKind::Digest(store) = backend else {
        unreachable!()
    };
    assert_eq!(store.root_digest(), fixed::<33>(&row["state_root"]));
    assert_eq!(store.height(), height);
    assert_eq!(store.chain_state_meta().best_full_block_id, id);
}

fn replay(directory: &str) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("digest.redb");
    let (mut backend, rows, _network, params) = fixture(directory, &path);
    let from = *rows.first_key_value().unwrap().0;
    let to = *rows.last_key_value().unwrap().0;
    for (&height, row) in &rows {
        apply(&mut backend, height, row);
    }
    backend.rollback_to(from + 2, None, None).unwrap();
    let StateBackendKind::Digest(ref store) = backend else {
        unreachable!()
    };
    assert_eq!(
        store.root_digest(),
        fixed::<33>(&rows[&(from + 2)]["state_root"])
    );
    for (&height, row) in rows.range(from + 3..) {
        apply(&mut backend, height, row);
    }
    assert_eq!(backend.chain_state_meta().best_full_block_height, to);
    assert_eq!(backend.active_params(), &params);
}

// ----- oracle parity -----

#[test]
fn mode5_scala_mainnet_1761000_replay_and_rollback_match_roots() {
    replay("mainnet-1761000");
}
#[test]
fn mode5_scala_mainnet_1885600_replay_and_rollback_match_roots() {
    replay("mainnet-1885600");
}
#[test]
fn mode5_scala_testnet_442325_replay_and_rollback_match_roots() {
    replay("testnet-442325");
}

// ----- error paths -----

#[test]
fn mode5_scala_breadth_corrupted_proofs_preserve_committed_state() {
    for directory in ["mainnet-1761000", "mainnet-1885600", "testnet-442325"] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("digest.redb");
        let (mut backend, rows, _, params) = fixture(directory, &path);
        let (&height, row) = rows.first_key_value().unwrap();
        let id = fixed::<32>(&row["header_id"]);
        let header = read_header(&mut VlqReader::new(&bytes(&row["header_bytes"]))).unwrap();
        let expected = ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        let original = backend
            .get_block_section(&expected.ad_proofs_id)
            .unwrap()
            .unwrap();
        let mut corrupted = original.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        backend
            .store_block_section_typed(&expected.ad_proofs_id, &corrupted, 104)
            .unwrap();
        let before = backend.chain_state_meta();
        let error = process_block(
            &mut backend,
            &id,
            &ergo_validation::context::ProtocolParams::mainnet_default(),
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("proof that contradicts the captured header commitment must fail");
        assert!(
            matches!(
                error,
                ergo_sync::block_proc::BlockProcessError::DigestApply(
                    ergo_state::DigestApplyError::AdProofsRootMismatch { .. }
                )
            ),
            "{directory}: {error}"
        );
        assert_eq!(backend.chain_state_meta().serialize(), before.serialize());
        let StateBackendKind::Digest(ref store) = backend else {
            unreachable!()
        };
        assert_eq!(store.root_digest(), fixed::<33>(&row["parent_state_root"]));
        assert_eq!(backend.active_params(), &params);
        backend
            .store_block_section_typed(&expected.ad_proofs_id, &original, 104)
            .unwrap();
        apply(&mut backend, height, row);
    }
}
