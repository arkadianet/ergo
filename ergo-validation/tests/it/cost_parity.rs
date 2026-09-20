//! Oracle: test-vectors/scripts/scala/ComputeTransactionCosts.scala
//! Oracle: scripts/jvm_checkpoint_oracle/CheckpointOracle.scala
//! Oracle: test-vectors/ergo-sigma/cost-total/l4-v6-reject-valid.json
//! Field-by-field block-unit comparisons against one JVM validateStateful run.

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::{ergo_box, header, transaction};
use ergo_sigma::cost_trace::{self, CostTrace};
use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::{tx::validate_transaction, TxValidationCtx, TxValidationRules, UtxoView};
use serde::Deserialize;
use std::collections::HashMap;

// ----- helpers -----

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct InputCost {
    index: usize,
    eval_block_cost: u64,
    crypto_block_cost: u64,
    rent: u64,
}

#[derive(Debug, Deserialize)]
struct ScalaCostVector {
    tx_id: String,
    height: u32,
    block_cost: u64,
    init_block_cost: u64,
    token_block_cost: u64,
    inputs: Vec<InputCost>,
}

/// Read observations from the accepted production validation run. Crypto deltas
/// are already rounded by the evaluator; input boundary totals include its snap.
fn compare_breakdown(expected: &ScalaCostVector, total: u64, trace: &CostTrace) {
    let mut inputs = Vec::new();
    let mut start = None;
    let mut crypto = 0;
    let mut rent = 0;
    for entry in &trace.entries {
        if let Some(index) = entry.label.strip_prefix("InputStart:") {
            assert!(start.is_none(), "overlapping input observations");
            start = Some((index.parse::<usize>().unwrap(), entry.total));
            crypto = 0;
            rent = 0;
        } else if entry.label.starts_with("Crypto:") {
            crypto += entry.delta;
        } else if entry.label.starts_with("Rent:") {
            rent += entry.delta;
        } else if let Some(index) = entry.label.strip_prefix("InputEnd:") {
            let (expected_index, before) = start.take().expect("input start");
            let index = index.parse::<usize>().unwrap();
            assert_eq!(index, expected_index);
            assert_eq!((entry.total - before) % 10, 0);
            inputs.push(InputCost {
                index,
                eval_block_cost: (entry.total - before - crypto - rent) / 10,
                crypto_block_cost: crypto / 10,
                rent: rent / 10,
            });
        }
    }
    assert!(start.is_none(), "unfinished input observation");
    assert_eq!(trace.count_by_prefix("TxInit"), 1);
    assert_eq!(trace.count_by_prefix("TxToken"), 1);
    let init = trace.sum_by_prefix("TxInit") / 10;
    let token = trace.sum_by_prefix("TxToken") / 10;
    assert_eq!(init, expected.init_block_cost, "{} init", expected.tx_id);
    assert_eq!(token, expected.token_block_cost, "{} token", expected.tx_id);
    assert_eq!(inputs, expected.inputs, "{} inputs", expected.tx_id);
    assert_eq!(total, expected.block_cost, "{} total", expected.tx_id);
    assert_eq!(
        init + token
            + inputs
                .iter()
                .map(|i| i.eval_block_cost + i.crypto_block_cost + i.rent)
                .sum::<u64>(),
        total,
        "{} Rust reconciliation",
        expected.tx_id
    );
    assert_eq!(
        expected.init_block_cost
            + expected.token_block_cost
            + expected
                .inputs
                .iter()
                .map(|i| i.eval_block_cost + i.crypto_block_cost + i.rent)
                .sum::<u64>(),
        expected.block_cost,
        "{} JVM reconciliation",
        expected.tx_id
    );
}

struct MapUtxo(HashMap<Digest32, ergo_box::ErgoBox>);
impl UtxoView for MapUtxo {
    fn get_box(&self, id: &Digest32) -> Option<ergo_box::ErgoBox> {
        self.0.get(id).cloned()
    }
}

#[derive(Deserialize)]
struct FixtureTransaction {
    #[serde(flatten)]
    cost: ScalaCostVector,
    tx_bytes: String,
}

#[derive(Deserialize)]
struct HeaderBytes {
    height: u32,
    bytes: String,
}

#[derive(Deserialize)]
struct BoxBytes {
    box_id: String,
    bytes: String,
}

#[derive(Deserialize)]
struct Parameters {
    storage_fee_factor: i32,
    min_value_per_byte: u64,
    max_block_cost: u64,
    input_cost: u64,
    data_input_cost: u64,
    output_cost: u64,
    token_access_cost: u64,
    block_version: u8,
}

#[derive(Deserialize)]
struct RecordedContext {
    header_heights: Vec<u32>,
    header_ids: Vec<String>,
    previous_state_digest: String,
}

#[derive(Deserialize)]
struct Fixture {
    manifest: serde_json::Value,
    #[serde(default)]
    contexts: HashMap<String, RecordedContext>,
    headers: Vec<HeaderBytes>,
    boxes: Vec<BoxBytes>,
    parameters: HashMap<String, Parameters>,
    transactions: Vec<FixtureTransaction>,
}

/// Require the exact block-validation window, newest first. The script layer
/// derives LastBlockUtxoRootHash from the first ancestor's state root.
fn replay_headers(headers: &HashMap<u32, header::Header>, height: u32) -> Vec<header::Header> {
    let ancestors: Vec<_> = (height - 9..height)
        .rev()
        .map(|h| {
            headers
                .get(&h)
                .unwrap_or_else(|| panic!("missing context header {h}"))
                .clone()
        })
        .collect();
    let mut child = &headers[&height];
    for parent in &ancestors {
        assert_eq!(
            child.parent_id,
            header::serialize_header(parent).unwrap().1,
            "disconnected context at {}",
            child.height
        );
        child = parent;
    }
    ancestors
}

#[derive(Deserialize)]
struct CheckpointObservation {
    tx_id: String,
    height: u32,
    checkpoint_height: Option<u32>,
    block_cost: u64,
    box_reads: usize,
}

fn replay_fixture(
    fixture: Fixture,
    headers_spend: Option<&str>,
    checkpoints: &[CheckpointObservation],
) {
    assert_eq!(fixture.manifest["ergo_core_version"], "6.0.5");
    assert_eq!(fixture.manifest["ergo_wallet_version"], "6.0.5");
    assert_eq!(fixture.manifest["sigma_state_version"], "6.0.6");
    let mut checked_headers_spends = 0;
    let headers: HashMap<_, _> = fixture
        .headers
        .iter()
        .map(|h| {
            let bytes = hex::decode(&h.bytes).unwrap();
            let parsed = header::read_header(&mut VlqReader::new(&bytes)).unwrap();
            assert_eq!(parsed.height, h.height);
            (h.height, parsed)
        })
        .collect();
    let utxo = MapUtxo(
        fixture
            .boxes
            .iter()
            .map(|b| {
                let bytes = hex::decode(&b.bytes).unwrap();
                let parsed = ergo_box::read_ergo_box(&mut VlqReader::new(&bytes)).unwrap();
                let id = parsed.box_id().unwrap();
                assert_eq!(hex::encode(id.as_bytes()), b.box_id);
                (id, parsed)
            })
            .collect(),
    );
    for tx in &fixture.transactions {
        let h = tx.cost.height;
        let hdr = &headers[&h];
        let p = &fixture.parameters[&h.to_string()];
        let params = ProtocolParams {
            storage_fee_factor: p.storage_fee_factor,
            min_value_per_byte: p.min_value_per_byte,
            max_block_cost: p.max_block_cost,
            input_cost: p.input_cost,
            data_input_cost: p.data_input_cost,
            output_cost: p.output_cost,
            token_access_cost: p.token_access_cost,
            ..ProtocolParams::mainnet_default()
        };
        assert_eq!(
            p.block_version, hdr.version,
            "voted version must match block"
        );
        let ctx = TransactionContext {
            height: h,
            miner_pubkey: *hdr.solution.pk().as_bytes(),
            pre_header_timestamp: hdr.timestamp,
            activated_script_version: p.block_version - 1,
            pre_header_version: hdr.version,
            pre_header_parent_id: *hdr.parent_id.as_bytes(),
            pre_header_n_bits: u64::from(hdr.n_bits),
            pre_header_votes: hdr.votes,
        };
        let last_headers = replay_headers(&headers, h);
        if let Some(recorded) = fixture.contexts.get(&h.to_string()) {
            assert_eq!(
                last_headers.iter().map(|h| h.height).collect::<Vec<_>>(),
                recorded.header_heights
            );
            assert_eq!(
                last_headers
                    .iter()
                    .map(|h| hex::encode(header::serialize_header(h).unwrap().1.as_bytes()))
                    .collect::<Vec<_>>(),
                recorded.header_ids
            );
            assert_eq!(
                hex::encode(last_headers[0].state_root.as_bytes()),
                recorded.previous_state_digest
            );
        }
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(p.max_block_cost).unwrap());
        let mut cx = TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &last_headers,
            rules: TxValidationRules::default(),
        };
        let bytes = hex::decode(&tx.tx_bytes).unwrap();
        let parsed = transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        assert_eq!(
            hex::encode(transaction::transaction_id(&parsed).unwrap().as_bytes()),
            tx.cost.tx_id
        );
        cost_trace::enable();
        let result = validate_transaction(&bytes, &utxo, &LocalPolicy::default_policy(), &mut cx);
        let trace = cost_trace::take().unwrap();
        result.unwrap_or_else(|e| panic!("{}: JVM Accept, Rust {e}", tx.cost.tx_id));
        compare_breakdown(&tx.cost, cost.total_block_cost(), &trace);
        for observation in checkpoints.iter().filter(|o| o.tx_id == tx.cost.tx_id) {
            assert_eq!(observation.height, h);
            let skip = observation
                .checkpoint_height
                .is_some_and(|checkpoint| h <= checkpoint);
            let mut checkpoint_cost =
                CostAccumulator::new(JitCost::from_block_cost(p.max_block_cost).unwrap());
            let mut checkpoint_cx = TxValidationCtx {
                ctx: &ctx,
                params: &params,
                cost: &mut checkpoint_cost,
                last_headers: &last_headers,
                rules: TxValidationRules::default(),
            };
            cost_trace::enable();
            let result = ergo_validation::tx::validate_transaction_parsed(
                parsed.clone(),
                &bytes,
                parsed
                    .inputs
                    .iter()
                    .map(|i| utxo.get_box(&i.box_id).unwrap())
                    .collect(),
                parsed
                    .data_inputs
                    .iter()
                    .map(|i| utxo.get_box(&i.box_id).unwrap())
                    .collect(),
                skip,
                &mut checkpoint_cx,
            );
            let trace = cost_trace::take().unwrap();
            result.unwrap();
            assert_eq!(checkpoint_cost.total_block_cost(), observation.block_cost);
            if skip {
                assert_eq!(observation.box_reads, 0);
                assert!(
                    trace.entries.is_empty(),
                    "checkpoint must pair skipped evaluation with skipped init/token costs"
                );
            } else {
                assert_eq!(
                    observation.box_reads,
                    parsed.inputs.len() + parsed.data_inputs.len()
                );
                compare_breakdown(&tx.cost, checkpoint_cost.total_block_cost(), &trace);
            }
        }
        if headers_spend == Some(tx.cost.tx_id.as_str()) {
            // The selected mainnet spend must actually read the header window:
            // its JVM-accepted script fails when the window is absent.
            let mut missing_cost =
                CostAccumulator::new(JitCost::from_block_cost(p.max_block_cost).unwrap());
            let mut missing_cx = TxValidationCtx {
                ctx: &ctx,
                params: &params,
                cost: &mut missing_cost,
                last_headers: &[],
                rules: TxValidationRules::default(),
            };
            let error = validate_transaction(
                &bytes,
                &utxo,
                &LocalPolicy::default_policy(),
                &mut missing_cx,
            )
            .expect_err("selected spend must require CONTEXT.headers");
            assert!(
                error.to_string().contains("index"),
                "unexpected missing-header error: {error}"
            );
            checked_headers_spends += 1;
        }
    }
    assert_eq!(checked_headers_spends, usize::from(headers_spend.is_some()));
}

// ----- oracle parity -----

// ledger: TX-init-formula, TX-token-cost
#[test]
fn transaction_breakdown_mainnet_all_ten_match_jvm() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-total/breakdown_700000_700001.json"
    ))
    .unwrap();
    assert_eq!(fixture.transactions.len(), 10);
    replay_fixture(fixture, None, &[]);
}

// ledger: METHOD-context-headers
#[test]
fn context_headers_mainnet_900058_matches_jvm() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-total/breakdown_900058_900058.json"
    ))
    .unwrap();
    assert_eq!(fixture.transactions.len(), 12);
    assert_eq!(fixture.contexts.len(), 1);
    assert_eq!(fixture.manifest["node_app_version"], "6.0.5");
    replay_fixture(
        fixture,
        Some("897d79ef0ca57b715e0176a22924ba396ff6bb25e23d8e604be136453f581781"),
        &[],
    );
}

// ledger: TX-scripts-skipped-pairing
#[test]
fn transaction_checkpoint_boundaries_match_jvm() {
    #[derive(Deserialize)]
    struct Checkpoints {
        observations: Vec<CheckpointObservation>,
    }
    let oracle: Checkpoints = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-total/checkpoint-pairing.json"
    ))
    .unwrap();
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-total/breakdown_700000_700001.json"
    ))
    .unwrap();
    assert_eq!(oracle.observations.len(), fixture.transactions.len() * 4);
    for tx in &fixture.transactions {
        let cases: Vec<_> = oracle
            .observations
            .iter()
            .filter(|o| o.tx_id == tx.cost.tx_id)
            .map(|o| o.checkpoint_height)
            .collect();
        assert_eq!(
            cases,
            [
                None,
                Some(tx.cost.height - 1),
                Some(tx.cost.height),
                Some(tx.cost.height + 1)
            ]
        );
    }
    replay_fixture(fixture, None, &oracle.observations);
}

// ledger: VERSION-jit-activation, VERSION-pre-v3-upcast
#[test]
fn transaction_activation_boundaries_match_jvm() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-total/activation-boundaries.json"
    ))
    .unwrap();
    let mut heights: Vec<_> = fixture.transactions.iter().map(|t| t.cost.height).collect();
    heights.sort_unstable();
    heights.dedup();
    assert_eq!(
        heights,
        [417_791, 417_792, 417_793, 889_855, 889_856, 889_857, 1_628_159, 1_628_160, 1_628_161]
    );
    replay_fixture(fixture, None, &[]);
}

// ledger: TX-l4-v6-activation-reject-valid
#[test]
fn transaction_v6_activation_spends_match_jvm() {
    let fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-total/l4-v6-reject-valid.json"
    ))
    .unwrap();
    replay_fixture(fixture, None, &[]);
}

#[cfg(feature = "diagnostics")]
mod ranges {
    use std::collections::{BTreeMap, HashMap};
    use std::path::Path;

    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::{
        ergo_box::ErgoBox,
        extension::{Extension, ExtensionField},
    };
    use ergo_validation::active_params::{parse_active_params, ActiveProtocolParameters};
    use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
    use ergo_validation::cost::{CostAccumulator, JitCost};
    use ergo_validation::{tx::validate_transaction, TxValidationCtx, TxValidationRules, UtxoView};
    use serde::{Deserialize, Serialize};

    use super::{compare_breakdown, replay_headers, ScalaCostVector};

    // ----- helpers -----

    const VECTORS_DIR: &str = "../test-vectors/mainnet";
    const REQUIRED_RANGES: &[(u32, u32)] = &[
        (500_000, 501_000),
        (700_000, 701_000),
        (750_000, 751_000),
        (889_000, 890_000),
        (900_000, 901_000),
        (1_000_000, 1_001_000),
        (1_100_000, 1_101_000),
        (1_300_000, 1_301_000),
        (1_500_000, 1_501_000),
        (1_750_000, 1_751_000),
        (417_792 - 1024, 417_792 + 1024),
        (889_856 - 1024, 889_856 + 1024),
        (1_628_160 - 1024, 1_628_160 + 1024),
    ];

    #[derive(Deserialize)]
    struct Epoch {
        height: u32,
        block_id: String,
        fields: Vec<[String; 2]>,
    }

    #[derive(Deserialize)]
    struct Activation {
        height: u32,
        version: u8,
    }

    #[derive(Deserialize)]
    struct EpochManifest {
        node_version: String,
        tip_height: u32,
        epochs: Vec<Epoch>,
        activations: Vec<Activation>,
    }

    fn historical_parameters() -> (u32, BTreeMap<u32, ActiveProtocolParameters>) {
        let manifest: EpochManifest =
            serde_json::from_reader(flate2::read::GzDecoder::new(
                &include_bytes!(
                    "../../../test-vectors/ergo-sigma/cost-total/mainnet-epochs.json.gz"
                )[..],
            ))
            .unwrap();
        assert_eq!(manifest.node_version, "6.0.5");
        assert_eq!(
            manifest
                .activations
                .iter()
                .map(|a| a.version)
                .collect::<Vec<_>>(),
            [2, 3, 4]
        );
        for activation in manifest.activations {
            assert!(
                REQUIRED_RANGES.contains(&(activation.height - 1024, activation.height + 1024)),
                "missing activation boundary in REQUIRED_RANGES"
            );
        }
        let mut parameters = BTreeMap::new();
        for (index, epoch) in manifest.epochs.into_iter().enumerate() {
            assert_eq!(
                epoch.height,
                (index as u32 + 1) * 1024,
                "missing historical epoch"
            );
            let extension = Extension {
                header_id: ModifierId::from_bytes(
                    hex::decode(epoch.block_id).unwrap().try_into().unwrap(),
                ),
                fields: epoch
                    .fields
                    .into_iter()
                    .map(|[key, value]| ExtensionField {
                        key: hex::decode(key).unwrap().try_into().unwrap(),
                        value: hex::decode(value).unwrap(),
                    })
                    .collect(),
            };
            parameters.insert(
                epoch.height,
                parse_active_params(&extension, epoch.height).unwrap(),
            );
        }
        assert_eq!(
            parameters.last_key_value().unwrap().0 / 1024,
            manifest.tip_height / 1024
        );
        (manifest.tip_height, parameters)
    }

    fn required_ranges(parameters: &BTreeMap<u32, ActiveProtocolParameters>) -> Vec<(u32, u32)> {
        let mut ranges = REQUIRED_RANGES.to_vec();
        let mut previous = None;
        for (&height, p) in parameters {
            let costs = (
                p.max_block_cost,
                p.token_access_cost,
                p.input_cost,
                p.data_input_cost,
                p.output_cost,
                // Replay charges storage rent from this factor, so an epoch that
                // changes only it must still select its range.
                p.storage_fee_factor,
            );
            if previous.is_some_and(|prev| prev != costs)
                && !ranges
                    .iter()
                    .any(|&(start, end)| start <= height && height <= end)
            {
                ranges.push((height, height));
            }
            previous = Some(costs);
        }
        ranges.sort_unstable();
        ranges.dedup();
        ranges
    }

    #[derive(Deserialize)]
    struct TxVector {
        id: String,
        bytes: String,
        height: u32,
    }

    #[derive(Deserialize)]
    struct NodeBox {
        #[serde(flatten)]
        output: ergo_rest_json::ScalaOutputInput,
        #[serde(rename = "boxId")]
        box_id: String,
        #[serde(rename = "transactionId")]
        transaction_id: String,
        index: u16,
    }

    #[derive(Serialize)]
    struct Observation {
        tx_id: String,
        height: u32,
        reason: String,
        missing_boxes: Vec<String>,
    }

    #[derive(Serialize)]
    struct RangeResult {
        start: u32,
        end: u32,
        selected: usize,
        executed: usize,
        matched: usize,
        failed: usize,
        skipped: Vec<Observation>,
        failures: Vec<Observation>,
    }

    struct RangeUtxo<'a> {
        local: HashMap<super::Digest32, ErgoBox>,
        captured: &'a super::MapUtxo,
    }

    impl UtxoView for RangeUtxo<'_> {
        fn get_box(&self, id: &super::Digest32) -> Option<ErgoBox> {
            self.local
                .get(id)
                .cloned()
                .or_else(|| self.captured.get_box(id))
        }
    }

    fn run_range(
        start: u32,
        end: u32,
        parameters: &BTreeMap<u32, ActiveProtocolParameters>,
        captured: &super::MapUtxo,
    ) -> RangeResult {
        let dir = Path::new(VECTORS_DIR);
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
        };
        let expected: Vec<ScalaCostVector> =
            serde_json::from_str(&read(&format!("tx_costs_{start}_{end}.json"))).unwrap();
        let mut txs: Vec<TxVector> =
            serde_json::from_str(&read(&format!("transactions_{start}_{end}.json"))).unwrap();
        txs.sort_by_key(|tx| tx.height);
        assert_eq!(
            txs.len(),
            expected.len(),
            "every selected transaction needs a JVM observation"
        );
        assert!(txs.iter().all(|tx| (start..=end).contains(&tx.height)));
        let mut headers = HashMap::new();
        for entry in std::fs::read_dir(dir).unwrap().map(Result::unwrap) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name
                .strip_prefix("headers_")
                .and_then(|s| s.strip_suffix(".json"))
            else {
                continue;
            };
            let Some((a, b)) = stem.split_once('_') else {
                continue;
            };
            let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) else {
                continue;
            };
            if a > end || b < start - 9 {
                continue;
            }
            let data: Vec<super::HeaderBytes> = serde_json::from_str(&read(&name)).unwrap();
            for h in data
                .into_iter()
                .filter(|h| (start - 9..=end).contains(&h.height))
            {
                let bytes = hex::decode(h.bytes).unwrap();
                let header = ergo_ser::header::read_header(&mut VlqReader::new(&bytes)).unwrap();
                assert_eq!(header.height, h.height);
                headers.insert(h.height, header);
            }
        }
        let mut utxo = RangeUtxo {
            local: HashMap::new(),
            captured,
        };
        let box_path = dir.join(format!("input_boxes_{start}_{end}.json"));
        if box_path.exists() {
            let boxes: Vec<NodeBox> =
                serde_json::from_str(&std::fs::read_to_string(box_path).unwrap()).unwrap();
            for b in boxes {
                let candidate = ergo_rest_json::decode_output_with_mode(
                    &b.output,
                    ergo_rest_json::DecodeMode::Preserve,
                )
                .unwrap();
                let ergo_box = ErgoBox {
                    candidate,
                    transaction_id: ModifierId::from_bytes(
                        hex::decode(b.transaction_id).unwrap().try_into().unwrap(),
                    ),
                    index: b.index,
                };
                let id = ergo_box.box_id().unwrap();
                assert_eq!(hex::encode(id.as_bytes()), b.box_id);
                utxo.local.insert(id, ergo_box);
            }
        }
        let expected_count = expected.len();
        let expected: HashMap<_, _> = expected.iter().map(|v| (v.tx_id.as_str(), v)).collect();
        assert_eq!(expected_count, expected.len(), "duplicate JVM observation");
        let mut result = RangeResult {
            start,
            end,
            selected: expected.len(),
            executed: 0,
            matched: 0,
            failed: 0,
            skipped: Vec::new(),
            failures: Vec::new(),
        };
        let mut seen = std::collections::HashSet::new();
        for v in txs {
            let bytes = hex::decode(&v.bytes).unwrap();
            let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
            let tx_id = ergo_ser::transaction::transaction_id(&tx).unwrap();
            assert_eq!(hex::encode(tx_id.as_bytes()), v.id);
            if let Some(expected) = expected.get(v.id.as_str()) {
                assert!(seen.insert(v.id.clone()), "duplicate selected transaction");
                assert_eq!(v.height, expected.height);
                let missing_boxes: Vec<_> = tx
                    .inputs
                    .iter()
                    .map(|i| &i.box_id)
                    .chain(tx.data_inputs.iter().map(|i| &i.box_id))
                    .filter(|id| utxo.get_box(id).is_none())
                    .map(|id| hex::encode(id.as_bytes()))
                    .collect();
                if !missing_boxes.is_empty() {
                    result.skipped.push(Observation {
                        tx_id: v.id.clone(),
                        height: v.height,
                        reason: "missing input boxes".into(),
                        missing_boxes,
                    });
                } else {
                    let active = &parameters[&(v.height / 1024 * 1024)];
                    let params = ProtocolParams::from_active(active);
                    let hdr = &headers[&v.height];
                    let ctx = TransactionContext {
                        height: v.height,
                        miner_pubkey: *hdr.solution.pk().as_bytes(),
                        pre_header_timestamp: hdr.timestamp,
                        activated_script_version: active.block_version - 1,
                        pre_header_version: hdr.version,
                        pre_header_parent_id: *hdr.parent_id.as_bytes(),
                        pre_header_n_bits: u64::from(hdr.n_bits),
                        pre_header_votes: hdr.votes,
                    };
                    let last_headers = replay_headers(&headers, v.height);
                    let mut cost = CostAccumulator::new(
                        JitCost::from_block_cost(params.max_block_cost).unwrap(),
                    );
                    let mut cx = TxValidationCtx {
                        ctx: &ctx,
                        params: &params,
                        cost: &mut cost,
                        last_headers: &last_headers,
                        rules: TxValidationRules::default(),
                    };
                    ergo_sigma::cost_trace::enable();
                    let accepted = validate_transaction(
                        &bytes,
                        &utxo,
                        &LocalPolicy::default_policy(),
                        &mut cx,
                    );
                    let trace = ergo_sigma::cost_trace::take().unwrap();
                    result.executed += 1;
                    let outcome = match accepted {
                        Ok(_) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            compare_breakdown(expected, cost.total_block_cost(), &trace)
                        }))
                        .map_err(|e| {
                            e.downcast_ref::<String>()
                                .cloned()
                                .unwrap_or_else(|| "breakdown mismatch".into())
                        }),
                        Err(e) => Err(format!("JVM Accept, Rust rejected: {e}")),
                    };
                    match outcome {
                        Ok(()) => result.matched += 1,
                        Err(reason) => {
                            result.failed += 1;
                            result.failures.push(Observation {
                                tx_id: v.id.clone(),
                                height: v.height,
                                reason,
                                missing_boxes: Vec::new(),
                            });
                        }
                    }
                }
            }
            // This is per-transaction cost replay. Retain historical boxes for
            // data inputs even when another transaction in the block spends them.
            // Mainnet accepted these outputs, including when local replay failed.
            for (index, candidate) in tx.output_candidates.into_iter().enumerate() {
                let b = ErgoBox {
                    candidate,
                    transaction_id: tx_id,
                    index: index.try_into().unwrap(),
                };
                utxo.local.insert(b.box_id().unwrap(), b);
            }
        }
        for (&id, expected) in &expected {
            if !seen.contains(id) {
                result.skipped.push(Observation {
                    tx_id: id.into(),
                    height: expected.height,
                    reason: "missing transaction bytes".into(),
                    missing_boxes: Vec::new(),
                });
            }
        }
        assert_eq!(result.selected, result.executed + result.skipped.len());
        result
    }

    fn replay_selection() {
        let (tip_height, parameters) = historical_parameters();
        let required = required_ranges(&parameters);
        let requested = std::env::var("L4_RANGE").ok().map(|s| {
            let (start, end) = s.split_once('-').expect("L4_RANGE=start-end");
            (start.parse().unwrap(), end.parse().unwrap())
        });
        let selection = requested.map_or_else(|| required.clone(), |r| vec![r]);
        let captured_path = Path::new(VECTORS_DIR).join("l4_boxes.json");
        let mut captured = super::MapUtxo(HashMap::new());
        if captured_path.exists() {
            let boxes: Vec<super::BoxBytes> =
                serde_json::from_str(&std::fs::read_to_string(captured_path).unwrap()).unwrap();
            for b in boxes {
                let bytes = hex::decode(b.bytes).unwrap();
                let parsed =
                    ergo_ser::ergo_box::read_ergo_box(&mut VlqReader::new(&bytes)).unwrap();
                let id = parsed.box_id().unwrap();
                assert_eq!(hex::encode(id.as_bytes()), b.box_id);
                captured.0.insert(id, parsed);
            }
        }
        let results: Vec<_> = selection
            .iter()
            .map(|&(start, end)| {
                let result = run_range(start, end, &parameters, &captured);
                eprintln!(
                    "L4 {start}-{end}: selected={} executed={} failed={} skipped={}",
                    result.selected,
                    result.executed,
                    result.failed,
                    result.skipped.len()
                );
                result
            })
            .collect();
        let selected: usize = results.iter().map(|r| r.selected).sum();
        let executed: usize = results.iter().map(|r| r.executed).sum();
        let failed: usize = results.iter().map(|r| r.failed).sum();
        let missing: Vec<_> = required
            .iter()
            .filter(|&&(start, end)| {
                !results.iter().any(|r| {
                    r.start == start && r.end == end && r.executed == r.selected && r.selected > 0
                })
            })
            .collect();
        let revision = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(revision.status.success());
        let manifest = serde_json::json!({"rust_revision": String::from_utf8(revision.stdout).unwrap().trim(), "oracle": "test-vectors/scripts/scala/ComputeTransactionCosts.scala", "sigma_state_version": "6.0.6", "epoch_manifest": "test-vectors/ergo-sigma/cost-total/mainnet-epochs.json.gz", "node_version": "6.0.5", "tip_height": tip_height, "required_ranges": required, "selected": selected, "executed": executed, "failed": failed, "ranges": results, "missing_required_ranges": missing});
        if let Ok(path) = std::env::var("L4_DIAGNOSTICS") {
            std::fs::write(path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
        }
        eprintln!("L4 selected={selected} executed={executed} failed={failed}");
        assert_eq!(
            selected, executed,
            "itemized skipped transactions in L4_DIAGNOSTICS"
        );
        if let Ok(path) = std::env::var("L4_RESULTS") {
            write_results(Path::new(&path), &manifest, &missing).unwrap();
        }
        assert_eq!(failed, 0, "JVM/Rust divergences in L4_DIAGNOSTICS");
    }

    fn write_results(
        path: &Path,
        manifest: &serde_json::Value,
        missing: &[&(u32, u32)],
    ) -> Result<(), String> {
        if !missing.is_empty() {
            return Err(format!("required ranges not executed: {missing:?}"));
        }
        use std::io::Write;
        use std::process::{Command, Stdio};

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = std::path::absolute(path).map_err(|e| e.to_string())?;
        let log_path = path.with_extension("log");
        let log: String = manifest["ranges"]
            .as_array()
            .ok_or("missing replay ranges")?
            .iter()
            .map(|range| format!("L4_RANGE {range}\n"))
            .collect();
        // This closed log contains every range observation, including failures.
        // It is independent of the test runner's still-open stdout/stderr log.
        std::fs::write(&log_path, log).map_err(|e| e.to_string())?;
        let command = std::env::var("L4_RUN_COMMAND").map_err(|_| {
            "set L4_RUN_COMMAND to the exact replay invocation when writing L4_RESULTS"
        })?;
        let mut child = Command::new("python3")
            .current_dir(root)
            .arg("scripts/l4-results-manifest.py")
            .arg("--log")
            .arg(&log_path)
            .arg("--run-command")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("start L4 provenance writer: {e}"))?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_string_pretty(manifest).unwrap().as_bytes())
            .map_err(|e| format!("send L4 results to provenance writer: {e}"))?;
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "L4 provenance writer failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        std::fs::write(path, output.stdout).map_err(|e| e.to_string())
    }

    // ----- error paths -----

    #[test]
    fn results_missing_required_range_rejected() {
        // This path cannot be opened: the coverage check must run first.
        let error = write_results(
            Path::new("../test-vectors/mainnet/nonexistent/l4-results.json"),
            &serde_json::json!({}),
            &[&REQUIRED_RANGES[0]],
        )
        .unwrap_err();
        assert!(error.starts_with("required ranges not executed:"));
    }

    // ----- oracle parity -----

    #[test]
    fn cost_parity_required_matrix_records_mainnet_selection() {
        let (tip_height, parameters) = historical_parameters();
        let required = required_ranges(&parameters);
        assert_eq!(
            required.len(),
            388,
            "refresh the epoch snapshot and selection together"
        );
        if let Ok(path) = std::env::var("L4_SELECTION") {
            std::fs::write(
                path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "tip_height": tip_height, "required_ranges": required,
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }

    // ledger: TX-voted-params
    #[test]
    fn cost_parity_stratified_ranges_match_jvm() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let (_, parameters) = historical_parameters();
                let captured = super::MapUtxo(HashMap::new());
                for &(start, end) in &REQUIRED_RANGES[..10] {
                    let result = run_range(start, end, &parameters, &captured);
                    assert_eq!(result.executed, result.selected);
                    assert_eq!(result.failed, 0, "{}-{}", start, end);
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn cost_parity_required_selection_matches_jvm() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(replay_selection)
            .unwrap()
            .join()
            .unwrap();
    }
}
