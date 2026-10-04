//! Finite public-testnet observations bound to pinned Sigma header bytes.
//! These assertions establish launch/first-epoch compatibility for the captured
//! network identity, not continuous chain authentication or full block execution.

use ergo_chain_spec::{ChainSpec, Network};
use ergo_crypto::{merkle::extension_root, pow::verify_pow_solution};
use ergo_primitives::{digest::ModifierId, reader::VlqReader};
use ergo_ser::{
    extension::{Extension, ExtensionField},
    header::{read_header, serialize_header, Header},
};
use ergo_validation::{
    active_params::parse_active_params,
    scala_launch_for_network,
    voting::{
        extension_validation::validate_epoch_extension,
        validation_settings::{parse_validation_settings_update, ErgoValidationSettings},
    },
};
use serde::Deserialize;
use serde_json::Value;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-vectors/testnet/initial-context/"
);

#[derive(Deserialize)]
struct HeaderObservation {
    height: u32,
    bytes: String,
    id: String,
}

fn json(name: &str) -> Value {
    let path = format!("{FIXTURES}{name}");
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")))
        .expect("captured JSON")
}

fn headers() -> Vec<(Header, String)> {
    let observations: Vec<HeaderObservation> =
        serde_json::from_value(json("headers.json")).unwrap();
    assert_eq!(
        observations.iter().map(|v| v.height).collect::<Vec<_>>(),
        [1, 2, 128, 1024]
    );
    observations
        .into_iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut reader = VlqReader::new(&bytes);
            let header = read_header(&mut reader).unwrap();
            assert!(
                reader.is_empty(),
                "header h={} consumed all bytes",
                v.height
            );
            assert_eq!(header.height, v.height);
            let (round_trip, id) = serialize_header(&header).unwrap();
            assert_eq!(round_trip, bytes);
            assert_eq!(hex::encode(id.as_bytes()), v.id, "pinned JVM header ID");
            (header, v.id)
        })
        .collect()
}

fn extension(block: &Value, header_id: &str) -> Extension {
    assert_eq!(block["extension"]["headerId"].as_str().unwrap(), header_id);
    Extension {
        header_id: ModifierId::from_bytes(hex::decode(header_id).unwrap().try_into().unwrap()),
        fields: block["extension"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| ExtensionField {
                key: hex::decode(field[0].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                value: hex::decode(field[1].as_str().unwrap()).unwrap(),
            })
            .collect(),
    }
}

#[test]
fn captured_identity_headers_pow_and_extension_commitments() {
    let spec = ChainSpec::testnet();
    let observations = headers();
    let genesis_id = hex::encode(spec.genesis.header_id.unwrap());
    assert_eq!(observations[0].1, genesis_id);
    assert_eq!(json("node-info.json")["genesisBlockId"], genesis_id);
    assert_eq!(
        json("explorer-genesis.json")["block"]["header"]["id"],
        genesis_id
    );
    assert_eq!(observations[0].0.version, 1, "version-1 genesis exception");
    assert_eq!(observations[0].0.parent_id.as_bytes(), &[0; 32]);
    assert_eq!(observations[1].0.version, 4);
    assert_eq!(
        hex::encode(observations[1].0.parent_id.as_bytes()),
        genesis_id
    );
    assert_eq!(
        json("genesis.json"),
        serde_json::from_str::<Value>(spec.genesis.boxes_json.unwrap()).unwrap()
    );

    for (header, id) in observations {
        verify_pow_solution(&header)
            .unwrap_or_else(|e| panic!("captured h={}: {e}", header.height));
        let block = json(&format!("block-{}.json", header.height));
        assert_eq!(block["header"]["id"], id);
        assert_eq!(block["header"]["height"], header.height);
        let ext = extension(&block, &id);
        let fields: Vec<_> = ext
            .fields
            .iter()
            .map(|f| (f.key.as_slice(), f.value.as_slice()))
            .collect();
        assert_eq!(extension_root(&fields), *header.extension_root.as_bytes());
        assert_eq!(
            hex::encode(header.extension_root.as_bytes()),
            block["extension"]["digest"].as_str().unwrap()
        );
    }
}

#[test]
fn first_epoch_bootstrap_keeps_proposed_rules_inactive() {
    let voting = ChainSpec::testnet().voting;
    assert_eq!(voting.voting_length, 128);
    let (header, id) = headers()
        .into_iter()
        .find(|(h, _)| h.height == 128)
        .unwrap();
    let ext = extension(&json("block-128.json"), &id);
    let launch = scala_launch_for_network(Network::Testnet);
    for epoch_height in [128, 1024] {
        let (epoch_header, epoch_id) = headers()
            .into_iter()
            .find(|(h, _)| h.height == epoch_height)
            .unwrap();
        let epoch_ext = extension(&json(&format!("block-{epoch_height}.json")), &epoch_id);
        let mut parsed = parse_active_params(&epoch_ext, epoch_header.height).unwrap();
        assert_eq!(parsed.subblocks_per_block, Some(30));
        parsed.epoch_start_height = 0;
        parsed.subblocks_per_block = None;
        assert_eq!(parsed, launch, "captured numeric defaults and proposal");
        assert_eq!(
            parse_validation_settings_update(&epoch_ext).unwrap(),
            launch.activated_update,
            "captured cumulative settings remain empty"
        );
    }
    // Pinned ErgoStateContext.processExtension accepts parsed parameters and
    // cumulative settings while currentParameters.height == 0. This deliberately
    // does not assert a prior-vote tally from these four sparse observations.
    let outcome = validate_epoch_extension(
        &ext,
        &header,
        &launch,
        &ErgoValidationSettings::empty(),
        &[],
        &voting,
        false,
    )
    .unwrap();
    assert_eq!(outcome.computed.epoch_start_height, 128);
    assert_eq!(outcome.computed.block_version, 4);
    assert_eq!(outcome.computed.subblocks_per_block, Some(30));
    assert_eq!(outcome.computed.proposed_update, launch.proposed_update);
    assert_eq!(
        outcome.computed.proposed_update.rules_to_disable,
        [215, 409]
    );
    assert_eq!(outcome.next_settings, ErgoValidationSettings::empty());
    assert_eq!(outcome.activated_update, launch.activated_update);
}
