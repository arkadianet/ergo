//! Oracle: test-vectors/ergo-sigma/cost-ledger/blocks/
//! JVM producer: scripts/jvm_block_oracle/BlockOracle.scala (Ergo 6.0.5).

use std::{collections::BTreeMap, fs::File, path::Path, sync::Mutex};

use ergo_primitives::{digest::Digest32, reader::VlqReader};
use ergo_ser::{
    block_transactions::BlockTransactions,
    ergo_box::{read_ergo_box, ErgoBox},
    extension::{Extension, ExtensionField},
    header::{read_header, serialize_header},
    modifier_id::{compute_section_id, TYPE_AD_PROOFS},
    transaction::read_transaction,
};
use ergo_state::{avl::tree::AvlTree, store::StateStore, DigestProofVerifier, DigestUtxoView};
use ergo_validation::{
    active_params::parse_active_params,
    block::{
        validate_full_block, validate_full_block_parallel_with_costs,
        validate_full_block_with_costs, BlockValidationContext, BlockValidationError,
    },
    header::CheckedHeader,
    ProtocolParams, UtxoView, ValidationError,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

// ----- helpers -----

/// The only `evidence.hash_scope` this checker implements: it hashes the compact
/// JSON with `manifest` removed, and hashes inputs over their exact file bytes.
const SUPPORTED_HASH_SCOPE: &str =
    "UTF-8 compact output JSON excluding manifest; input hash covers exact file bytes";

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    ledger: Vec<String>,
    manifest: Value,
    boundary_basis: Option<Value>,
    parameters: BTreeMap<String, i32>,
    parent_boxes_hex: Vec<String>,
    bootstrap_box_hex: String,
    initial_box_order_hex: Vec<String>,
    genesis_state_root: String,
    parent_headers_hex: Vec<String>,
    parent_blocks: Vec<Section>,
    parent_state_root: String,
    transactions_hex: Vec<String>,
    block: Section,
    expected: Expected,
    digest_expected: Option<Expected>,
    transition: Option<Transition>,
}

#[derive(Deserialize)]
struct Transition {
    previous_parameters: BTreeMap<String, i32>,
    updated_parameters: BTreeMap<String, i32>,
    epoch_votes: Vec<(i8, i32)>,
    stale_verdict: String,
    stale_cost: Option<u64>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Entry {
    index: usize,
    accumulated_cost: u64,
}

#[derive(Deserialize)]
struct Expected {
    #[serde(default)]
    transaction_entries: Vec<Entry>,
    verdict: String,
    sum_block_cost: Option<u64>,
    failure_class: Option<String>,
    rejection_detail: Option<String>,
    state_root_before: String,
    state_root_after: String,
}

#[derive(Deserialize)]
struct Section {
    header_hex: String,
    transactions_hex: Vec<String>,
    extension_fields: Vec<(String, String)>,
    ad_proofs_hex: String,
}

struct Block {
    header: CheckedHeader,
    transactions: BlockTransactions,
    extension: Extension,
    proof: Vec<u8>,
}

fn decode_box(bytes: &[u8]) -> ErgoBox {
    read_ergo_box(&mut VlqReader::new(bytes)).expect("canonical JVM box")
}

impl Section {
    fn decode(&self) -> Block {
        let bytes = hex::decode(&self.header_hex).unwrap();
        let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        let (encoded, id) = serialize_header(&header).unwrap();
        assert_eq!(encoded, bytes);
        ergo_crypto::pow::verify_pow_solution(&header).expect("JVM difficulty-one PoW");
        Block {
            // The oracle supplies a synthetic chain, not a history/retargeting fixture.
            // PoW is checked above; linkage and height are checked during replay.
            header: CheckedHeader::trust_me(header, *id.as_bytes()),
            transactions: BlockTransactions {
                header_id: id,
                transactions: self
                    .transactions_hex
                    .iter()
                    .map(|encoded| {
                        read_transaction(&mut VlqReader::new(&hex::decode(encoded).unwrap()))
                            .unwrap()
                    })
                    .collect(),
            },
            extension: Extension {
                header_id: id,
                fields: self
                    .extension_fields
                    .iter()
                    .map(|(key, value)| ExtensionField {
                        key: hex::decode(key).unwrap().try_into().unwrap(),
                        value: hex::decode(value).unwrap(),
                    })
                    .collect(),
            },
            proof: hex::decode(&self.ad_proofs_hex).unwrap(),
        }
    }
}

struct State(AvlTree);

struct ObservedView<'a> {
    state: &'a dyn UtxoView,
    reads: Mutex<Vec<Digest32>>,
}

impl UtxoView for ObservedView<'_> {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.reads.lock().unwrap().push(*id);
        self.state.get_box(id)
    }
}

impl UtxoView for State {
    fn get_box(&self, id: &Digest32) -> Option<ErgoBox> {
        self.0.lookup(id.as_bytes()).map(|bytes| decode_box(&bytes))
    }
}

impl State {
    fn apply(&mut self, block: &Block) {
        let header = block.header.header();
        let txs: Vec<_> = block.transactions.transactions.iter().collect();
        let (remove, insert) = StateStore::build_utxo_changes_raw(&txs).unwrap();
        let lookups: Vec<_> = txs
            .iter()
            .flat_map(|tx| tx.data_inputs.iter())
            .map(|input| *input.box_id.as_bytes())
            .collect();
        let root = DigestProofVerifier::apply_block_in_memory(
            compute_section_id(
                TYPE_AD_PROOFS,
                block.header.header_id(),
                header.ad_proofs_root.as_bytes(),
            ),
            &block.proof,
            header,
            self.0.root_digest().as_bytes(),
            &lookups,
            &remove,
            &insert,
        )
        .expect("JVM ADProof authenticates this state transition");
        for key in remove.keys() {
            assert!(self.0.remove(key).is_some());
        }
        for (key, bytes) in insert {
            assert!(self.0.insert(key, bytes).is_none());
        }
        assert_eq!(self.0.root_digest().as_bytes(), &root);
    }
}

fn context<'a>(
    state: &'a dyn UtxoView,
    parents: &'a [Block],
    params: &'a ProtocolParams,
    headers: &'a [CheckedHeader],
) -> BlockValidationContext<'a> {
    let parent = parents.last().unwrap();
    BlockValidationContext {
        parent: &parent.header,
        utxo: state,
        params,
        rule_306_max_block_size: params.max_block_size,
        voting_length: 128,
        votes_unknown_rule_disabled:
            ergo_validation::voting::validation_settings::parse_validation_settings_update(
                &parent.extension,
            )
            .unwrap()
            .rules_to_disable
            .contains(&215),
        parent_extension: Some(&parent.extension),
        soft_fork_state: None,
        last_headers: headers,
        script_validation_checkpoint: None,
        reemission: None,
    }
}

fn jvm_verdict(expected: &Expected) -> &'static str {
    if expected.verdict == "Accept" {
        assert_eq!(expected.failure_class, None);
        assert_eq!(expected.rejection_detail, None);
        return "Accept";
    }
    assert_eq!(expected.verdict, "Reject");
    assert_eq!(
        expected.failure_class.as_deref(),
        Some("org.ergoplatform.validation.MalformedModifierError")
    );
    let detail = expected
        .rejection_detail
        .as_deref()
        .expect("JVM rejection detail");
    // Rule 307 and the rule-119 embedded CostLimitException are independently captured.
    if detail
        .starts_with("Accumulated cost of block transactions should not exceed <maxBlockCost>. ")
        || (detail.starts_with("Scripts of all transaction inputs should pass verification. ")
            && detail.contains("=> Failure(sigma.exceptions.CostLimitException: "))
    {
        "RejectCost"
    } else if detail.starts_with("Scripts of all transaction inputs should pass verification. ")
        && detail.contains("=> Success((false,")
    {
        "RejectScript"
    } else if detail.starts_with("Scripts of all transaction inputs should pass verification. ")
        && detail.ends_with("=> Failure(sigma.exceptions.InterpreterException: ErgoTree version 3 is higher than activated 2)")
    {
        "RejectVersion"
    } else {
        panic!("unmapped JVM rejection: {detail}");
    }
}

fn rust_verdict(error: Option<&BlockValidationError>) -> &'static str {
    match error {
        None => "Accept",
        Some(BlockValidationError::BlockCostExceeded { .. })
        | Some(BlockValidationError::Transaction {
            error: ValidationError::CostExceeded { .. },
            ..
        }) => "RejectCost",
        Some(BlockValidationError::Transaction {
            error: ValidationError::ProofFailed { .. },
            ..
        }) => "RejectScript",
        Some(BlockValidationError::Transaction {
            error: ValidationError::ScriptError { index: 0, reason },
            ..
        }) if reason.ends_with("ErgoTree version 3 is higher than activated 2") => "RejectVersion",
        Some(BlockValidationError::Transaction {
            error: ValidationError::ScriptError { reason, .. },
            ..
        }) if reason.starts_with("evaluation error: cost limit exceeded:") => "RejectCost",
        Some(error) => panic!("unmapped Rust rejection: {error:?}"),
    }
}

fn read_fixture(path: &Path) -> Fixture {
    // Preserve Circe's insertion order when reproducing its compact payload hash.
    let mut value: Value =
        serde_json::from_reader(flate2::read::GzDecoder::new(File::open(path).unwrap())).unwrap();
    let manifest = value
        .as_object_mut()
        .unwrap()
        .shift_remove("manifest")
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(serde_json::to_vec(&value).unwrap())),
        manifest["evidence"]["output_payload_sha256"]
            .as_str()
            .unwrap(),
        "payload hash: {}",
        path.display()
    );
    validate_manifest(&manifest, &value);
    value["manifest"] = manifest;
    serde_json::from_value(value).unwrap()
}

fn validate_manifest(manifest: &Value, payload: &Value) {
    for pointer in [
        "/rust/git_sha",
        "/rust/toolchain",
        "/tool/script",
        "/tool/git_sha",
        "/tool/script_sha256",
        "/tool/scala_cli",
        "/tool/jvm",
        "/context/network",
        "/context/chain_id",
        "/run/command",
        "/run/timestamp",
    ] {
        assert!(
            !manifest
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap()
                .is_empty(),
            "missing manifest {pointer}"
        );
    }

    // The integrity check always hashes compact JSON with `manifest` removed, so
    // a fixture must not be able to declare a different scope and still pass.
    assert_eq!(
        manifest
            .pointer("/evidence/hash_scope")
            .and_then(Value::as_str),
        Some(SUPPORTED_HASH_SCOPE),
        "unsupported evidence.hash_scope"
    );
    for (name, sha) in [
        ("ergo_v6.0.5", "5528ef569a41ebccbc8658212e6ee3c97d990b96"),
        (
            "sigmastate_v6.0.6",
            "ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042",
        ),
        ("ergo_v6.0.2", "2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1"),
        (
            "sigmastate_v6.0.2",
            "23dd29f612249c169d09fae9bca76d7cc02e144c",
        ),
    ] {
        assert_eq!(manifest["scala"]["source_shas"][name], sha);
    }
    assert_eq!(manifest["scala"]["ergo_version"], "6.0.5");
    assert_eq!(manifest["scala"]["sigmastate_version"], "6.0.6");
    assert!(manifest["scala"].get("node_app_version").is_some());
    assert!(!manifest["rust"]["features"].as_array().unwrap().is_empty());
    assert!(manifest["run"].get("seeds").is_some());
    assert_eq!(
        manifest["context"]["chain_id"],
        payload["genesis_state_root"]
    );
    assert_eq!(
        manifest["context"]["height_range"],
        serde_json::json!([1, payload["parent_blocks"].as_array().unwrap().len() + 1])
    );
    assert_eq!(
        &manifest["context"]["voted_params"],
        payload
            .pointer("/transition/updated_parameters")
            .unwrap_or(&payload["parameters"])
    );
    let version = payload["parameters"]["123"].as_u64().unwrap();
    assert_eq!(manifest["context"]["block_version"], version);
    assert_eq!(manifest["context"]["activated_script_version"], version - 1);
    for (pointer, bytes) in [
        ("/rust/git_sha", 20),
        ("/tool/git_sha", 20),
        ("/tool/script_sha256", 32),
        ("/evidence/output_payload_sha256", 32),
    ] {
        assert_eq!(
            hex::decode(manifest.pointer(pointer).unwrap().as_str().unwrap())
                .unwrap()
                .len(),
            bytes
        );
    }
    let input = manifest["evidence"].get("input_sha256").unwrap();
    if !input.is_null() {
        assert_eq!(hex::decode(input.as_str().unwrap()).unwrap().len(), 32);
    }
}

fn fixture(name: &str) -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors/ergo-sigma/cost-ledger/blocks")
        .join(format!("{name}.json.gz"));
    read_fixture(&path)
}

fn replay(fixture: Fixture) {
    assert_eq!(fixture.schema_version, 1);
    assert!(fixture.ledger.iter().any(|id| id == "BLOCK-parallel-equiv"));
    let mut initial = fixture.parent_boxes_hex.clone();
    initial.push(fixture.bootstrap_box_hex.clone());
    initial.sort();
    let mut ordered = fixture.initial_box_order_hex.clone();
    ordered.sort();
    assert_eq!(initial, ordered);
    let mut state = State(AvlTree::new());
    for encoded in &fixture.initial_box_order_hex {
        let bytes = hex::decode(encoded).unwrap();
        let id = decode_box(&bytes).box_id().unwrap();
        assert!(state.0.insert(*id.as_bytes(), bytes).is_none());
    }
    assert_eq!(
        hex::encode(state.0.root_digest().as_bytes()),
        fixture.genesis_state_root
    );
    assert!(matches!(fixture.parent_blocks.len(), 128 | 383));
    assert_eq!(
        fixture.parent_headers_hex,
        fixture
            .parent_blocks
            .iter()
            .map(|b| b.header_hex.clone())
            .collect::<Vec<_>>()
    );
    let mut parents: Vec<Block> = Vec::new();
    for section in &fixture.parent_blocks {
        let block = section.decode();
        assert_eq!(block.header.height() as usize, parents.len() + 1);
        // All synthetic extensions carry the same complete parameter table.
        let active = parse_active_params(&block.extension, block.header.height()).unwrap();
        let params = ProtocolParams::from_active(&active);
        let table: BTreeMap<_, _> = block
            .extension
            .fields
            .iter()
            .filter(|field| field.key[0] == 0 && field.key[1] != 124)
            .map(|field| {
                (
                    field.key[1].to_string(),
                    i32::from_be_bytes(field.value.clone().try_into().unwrap()),
                )
            })
            .collect();
        assert_eq!(table, fixture.parameters);
        if let Some(parent) = parents.last() {
            assert_eq!(
                block.header.header().parent_id.as_bytes(),
                parent.header.header_id()
            );
            let headers: Vec<_> = parents
                .iter()
                .rev()
                .take(10)
                .map(|b| b.header.clone())
                .collect();
            validate_full_block(
                block.header.clone(),
                &block.transactions,
                &block.extension,
                &context(&state, &parents, &params, &headers),
            )
            .expect("valid JVM parent block");
        } else {
            assert_eq!(block.header.header().parent_id.as_bytes(), &[0; 32]);
            // Genesis has no BlockValidationContext parent; authenticate its sections and state.
            let ids: Vec<_> = block
                .transactions
                .transactions
                .iter()
                .map(|tx| ergo_ser::transaction::transaction_id(tx).unwrap())
                .collect();
            let id_bytes: Vec<_> = ids.iter().map(|id| id.as_bytes().as_slice()).collect();
            let witnesses: Vec<_> = block
                .transactions
                .transactions
                .iter()
                .map(|tx| {
                    let proofs: Vec<_> = tx
                        .inputs
                        .iter()
                        .flat_map(|input| input.spending_proof.proof.iter().copied())
                        .collect();
                    ergo_crypto::autolykos::common::blake2b256(&proofs)[1..].to_vec()
                })
                .collect();
            let witness_bytes: Vec<_> = witnesses.iter().map(Vec::as_slice).collect();
            assert_eq!(
                ergo_crypto::merkle::transactions_root(&id_bytes, Some(&witness_bytes)),
                *block.header.header().transactions_root.as_bytes()
            );
            assert_eq!(
                ergo_crypto::merkle::extension_root(
                    &block
                        .extension
                        .fields
                        .iter()
                        .map(|f| (f.key.as_slice(), f.value.as_slice()))
                        .collect::<Vec<_>>()
                ),
                *block.header.header().extension_root.as_bytes()
            );
        }
        state.apply(&block);
        parents.push(block);
    }
    assert_eq!(
        hex::encode(state.0.root_digest().as_bytes()),
        fixture.parent_state_root
    );
    assert_eq!(
        fixture.expected.state_root_before,
        fixture.parent_state_root
    );
    for encoded in &fixture.parent_boxes_hex {
        let bytes = hex::decode(encoded).unwrap();
        assert_eq!(
            state
                .0
                .lookup(decode_box(&bytes).box_id().unwrap().as_bytes()),
            Some(bytes)
        );
    }
    let params = ProtocolParams::from_active(
        &parse_active_params(&parents.last().unwrap().extension, 128).unwrap(),
    );
    let headers: Vec<_> = parents
        .iter()
        .rev()
        .take(10)
        .map(|b| b.header.clone())
        .collect();
    let target = fixture.block.decode();
    let updated_params = fixture.transition.as_ref().map(|transition| {
        use ergo_validation::voting::validation_settings::ErgoValidationSettingsUpdate;
        use ergo_validation::voting::{compute_next_params, VotingSettings};
        let previous = parse_active_params(&parents.last().unwrap().extension, 256).unwrap();
        let parsed = parse_active_params(&target.extension, target.header.height()).unwrap();
        assert_eq!(transition.previous_parameters, fixture.parameters);
        let mut votes = BTreeMap::new();
        for block in parents.iter().filter(|b| b.header.height() >= 256) {
            for vote in block.header.header().votes.iter().filter(|&&v| v != 0) {
                *votes.entry(*vote as i8).or_insert(0) += 1;
            }
        }
        assert_eq!(
            votes.into_iter().collect::<Vec<_>>(),
            transition.epoch_votes
        );
        let mut settings = VotingSettings::testnet();
        settings.soft_fork_epochs = 8;
        let (computed, _) = compute_next_params(
            &previous,
            &transition.epoch_votes,
            false,
            &ErgoValidationSettingsUpdate::empty(),
            target.header.height(),
            &settings,
        )
        .unwrap();
        assert_eq!(computed, parsed);
        let table: BTreeMap<_, _> = target
            .extension
            .fields
            .iter()
            .filter(|f| f.key[0] == 0 && f.key[1] != 124)
            .map(|f| {
                (
                    f.key[1].to_string(),
                    i32::from_be_bytes(f.value.clone().try_into().unwrap()),
                )
            })
            .collect();
        assert_eq!(table, transition.updated_parameters);
        let stale = validate_full_block_with_costs(
            target.header.clone(),
            &target.transactions,
            &target.extension,
            &context(&state, &parents, &params, &headers),
        );
        assert_eq!(
            if stale.is_ok() { "Accept" } else { "Reject" },
            transition.stale_verdict
        );
        assert_eq!(
            stale
                .ok()
                .map(|(_, costs)| costs.iter().map(|(_, c)| c).sum::<u64>()),
            transition.stale_cost
        );
        ProtocolParams::for_block(&previous, Some(&computed))
    });
    let observed_view = ObservedView {
        state: &state,
        reads: Mutex::new(Vec::new()),
    };
    let ctx = context(
        &observed_view,
        &parents,
        updated_params.as_ref().unwrap_or(&params),
        &headers,
    );
    assert_eq!(fixture.transactions_hex, fixture.block.transactions_hex);
    assert_eq!(target.header.height() as usize, parents.len() + 1);
    assert_eq!(
        target.header.header().parent_id.as_bytes(),
        ctx.parent.header_id()
    );
    let sequential = validate_full_block(
        target.header.clone(),
        &target.transactions,
        &target.extension,
        &ctx,
    );
    let sequential_reads = std::mem::take(&mut *observed_view.reads.lock().unwrap());
    let observed = validate_full_block_with_costs(
        target.header.clone(),
        &target.transactions,
        &target.extension,
        &ctx,
    );
    let observed_reads = std::mem::take(&mut *observed_view.reads.lock().unwrap());
    let parallel = validate_full_block_parallel_with_costs(
        target.header.clone(),
        &target.transactions,
        &target.extension,
        &ctx,
    );
    let parallel_reads = std::mem::take(&mut *observed_view.reads.lock().unwrap());
    if fixture
        .ledger
        .iter()
        .any(|id| id == "BLOCK-stop-after-invalid-B002")
    {
        let third_input = target.transactions.transactions[2].inputs[0].box_id;
        let executed = fixture
            .expected
            .transaction_entries
            .iter()
            .any(|entry| entry.index == 2);
        for reads in [&sequential_reads, &observed_reads, &parallel_reads] {
            assert_eq!(
                reads.iter().filter(|id| **id == third_input).count(),
                usize::from(executed)
            );
        }
        if !executed {
            for error in [
                sequential.as_ref().err(),
                observed.as_ref().err(),
                parallel.as_ref().err(),
            ] {
                assert!(matches!(
                    error,
                    Some(BlockValidationError::Transaction { index: 1, .. })
                ));
            }
        }
    }
    let expected = jvm_verdict(&fixture.expected);
    if let Some(digest_expected) = &fixture.digest_expected {
        let txs: Vec<_> = target.transactions.transactions.iter().collect();
        let (remove, insert) = StateStore::build_utxo_changes_raw(&txs).unwrap();
        let lookups: Vec<_> = txs
            .iter()
            .flat_map(|tx| tx.data_inputs.iter())
            .map(|input| *input.box_id.as_bytes())
            .collect();
        let (_, resolved) = DigestProofVerifier::apply_block_resolving_boxes(
            compute_section_id(
                TYPE_AD_PROOFS,
                target.header.header_id(),
                target.header.header().ad_proofs_root.as_bytes(),
            ),
            &target.proof,
            target.header.header(),
            state.0.root_digest().as_bytes(),
            &lookups,
            &remove,
            &insert,
        )
        .unwrap();
        let digest_view =
            DigestUtxoView::new(&resolved, &target.transactions.transactions).unwrap();
        let digest_ctx = context(&digest_view, &parents, &params, &headers);
        for result in [
            validate_full_block_with_costs(
                target.header.clone(),
                &target.transactions,
                &target.extension,
                &digest_ctx,
            ),
            validate_full_block_parallel_with_costs(
                target.header.clone(),
                &target.transactions,
                &target.extension,
                &digest_ctx,
            ),
        ] {
            assert_eq!(
                rust_verdict(result.as_ref().err()),
                jvm_verdict(digest_expected)
            );
            assert_eq!(
                result
                    .ok()
                    .map(|(_, costs)| costs.iter().map(|(_, c)| c).sum::<u64>()),
                digest_expected.sum_block_cost
            );
        }
        assert_eq!(digest_expected.verdict, fixture.expected.verdict);
        assert_eq!(
            digest_expected.sum_block_cost,
            fixture.expected.sum_block_cost
        );
        assert_eq!(
            digest_expected.transaction_entries,
            fixture.expected.transaction_entries
        );
    }
    for actual in [
        sequential.as_ref().err(),
        observed.as_ref().err(),
        parallel.as_ref().err(),
    ] {
        assert_eq!(rust_verdict(actual), expected, "{actual:?}");
        if fixture.parameters["4"] == 25005 && fixture.transactions_hex.len() == 3 {
            assert!(
                matches!(
                    actual,
                    Some(BlockValidationError::BlockCostExceeded {
                        total: 37509,
                        limit: 25005
                    })
                ),
                "{actual:?}"
            );
        }
    }
    if expected != "Accept" {
        // Failed JVM execution has no payload; a deferred Rust sum is not substituted.
        assert_eq!(fixture.expected.sum_block_cost, None);
        assert_eq!(
            fixture.expected.state_root_before,
            fixture.expected.state_root_after
        );
        assert_eq!(
            hex::encode(state.0.root_digest().as_bytes()),
            fixture.parent_state_root
        );
        return;
    }
    let sequential = sequential.expect("sequential JVM acceptance");
    let (observed, costs) = observed.expect("observed sequential JVM acceptance");
    let (parallel, mut parallel_costs) = parallel.expect("parallel JVM acceptance");
    parallel_costs.sort_unstable_by_key(|(index, _)| *index);
    assert_eq!(costs, parallel_costs);
    if !fixture.expected.transaction_entries.is_empty() {
        let mut accumulated = 0;
        for ((index, cost), entry) in costs.iter().zip(&fixture.expected.transaction_entries) {
            assert_eq!(*index, entry.index);
            assert_eq!(accumulated, entry.accumulated_cost);
            accumulated += cost;
        }
        assert_eq!(costs.len(), fixture.expected.transaction_entries.len());
    }
    assert_eq!(
        Some(costs.iter().map(|(_, cost)| cost).sum::<u64>()),
        fixture.expected.sum_block_cost
    );
    for block in [&observed, &parallel] {
        assert_eq!(
            sequential
                .transactions()
                .iter()
                .map(|tx| tx.tx_id())
                .collect::<Vec<_>>(),
            block
                .transactions()
                .iter()
                .map(|tx| tx.tx_id())
                .collect::<Vec<_>>()
        );
    }
    state.apply(&target);
    assert_eq!(
        hex::encode(state.0.root_digest().as_bytes()),
        fixture.expected.state_root_after
    );
}

// ----- oracle parity -----

// ledger: BLOCK-parallel-equiv
#[test]
fn block_fixtures_both_validators_match_jvm() {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/ergo-sigma/cost-ledger/blocks");
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.to_string_lossy().ends_with(".json.gz"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "block oracle corpus must not be empty");
    for path in &paths {
        eprintln!("block fixture: {}", path.display());
        let fixture = read_fixture(path);
        replay(fixture);
    }
    eprintln!(
        "selected={} executed={} skipped=0 failed=0",
        paths.len(),
        paths.len()
    );
}

// ledger: BLOCK-accum-equiv, BLOCK-per-tx-cap, BLOCK-sum-op, LIMIT-block-sum
#[test]
fn block_boundaries_running_accumulator_matches_jvm() {
    let exact = fixture("a-exact-sum");
    assert_eq!(
        exact.expected.sum_block_cost,
        Some(exact.parameters["4"] as u64)
    );
    let over = fixture("b-sum-plus-one");
    assert_eq!(exact.transactions_hex, over.transactions_hex);
    assert_eq!(exact.parameters["4"], over.parameters["4"] + 1);
    let single = fixture("c-single-cap");
    assert_eq!(single.transactions_hex.len(), 1);
    assert_eq!(
        single.expected.sum_block_cost,
        Some(single.parameters["4"] as u64)
    );
    let forward = fixture("d-mid-block");
    let reverse = fixture("d-mid-block-reversed");
    assert_eq!(forward.transactions_hex.len(), 3);
    assert_eq!(
        forward.transactions_hex.iter().rev().collect::<Vec<_>>(),
        reverse.transactions_hex.iter().collect::<Vec<_>>()
    );
    assert_eq!(forward.parameters, reverse.parameters);
    assert_eq!(
        forward.parameters["4"] as u64 + 1,
        2 * single.expected.sum_block_cost.unwrap()
    );
    for mid in [&forward, &reverse] {
        let bytes = hex::decode(&mid.transactions_hex[1]).unwrap();
        let tx = read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        let id = ergo_ser::transaction::transaction_id(&tx).unwrap();
        assert!(mid
            .expected
            .rejection_detail
            .as_ref()
            .unwrap()
            .contains(&hex::encode(id.as_bytes())));
    }
    for rejected in [&over, &forward, &reverse] {
        assert_eq!(jvm_verdict(&rejected.expected), "RejectCost");
    }
    for case in [exact, over, single, forward, reverse] {
        replay(case);
    }
}

// ledger: ORDER-init-token
#[test]
fn block_token_remaining_budget_matches_jvm() {
    let case = fixture("e-token-order");
    assert_eq!(case.transactions_hex.len(), 2);
    let prefix = case.boundary_basis.as_ref().unwrap()["single_p2pk"]["sum_block_cost"]
        .as_u64()
        .unwrap();
    let remaining = case.parameters["4"] as u64 - prefix;
    let initial = 10000 + case.parameters["6"] as u64 + case.parameters["8"] as u64;
    assert!(initial <= remaining);
    assert!(initial + 4 * case.parameters["5"] as u64 > remaining);
    assert_eq!(jvm_verdict(&case.expected), "RejectCost");
    assert!(case
        .expected
        .rejection_detail
        .as_ref()
        .unwrap()
        .ends_with(": assets cost"));
    replay(case);
}

#[test]
fn block_v6_devnet_context_matches_jvm() {
    let case = fixture("f-v6-devnet");
    assert_eq!(case.parameters["123"], 4);
    assert_eq!(case.manifest["context"]["activated_script_version"], 3);
    assert_eq!(
        case.manifest["context"]["ergo_tree_versions"],
        serde_json::json!([3])
    );
    assert_eq!(case.expected.verdict, "Accept");
    assert_eq!(case.expected.sum_block_cost, Some(12104));
    let control = fixture("f-v5-control");
    assert_eq!(control.parameters["123"], 3);
    assert_eq!(control.transactions_hex, case.transactions_hex);
    assert_eq!(control.parent_boxes_hex, case.parent_boxes_hex);
    assert_eq!(control.parent_state_root, case.parent_state_root);
    let mut v5_params = case.parameters.clone();
    v5_params.insert("123".into(), 3);
    assert_eq!(control.parameters, v5_params);
    assert_eq!(jvm_verdict(&control.expected), "RejectVersion");
    replay(case);
    replay(control);
}

#[test]
fn block_invalid_signature_is_script_rejection() {
    let case = fixture("rejection-script-control");
    assert_eq!(jvm_verdict(&case.expected), "RejectScript");
    replay(case);
}

// ledger: BLOCK-stop-after-invalid-B002
#[test]
fn block_invalid_second_skips_third_matches_jvm() {
    let rejected = fixture("g-stop-after-invalid");
    let control = fixture("g-stop-control");
    assert_eq!(
        ergo_ser::transaction::bytes_to_sign(&rejected.block.decode().transactions.transactions[2])
            .unwrap(),
        ergo_ser::transaction::bytes_to_sign(&control.block.decode().transactions.transactions[2])
            .unwrap()
    );
    assert_eq!(
        rejected
            .expected
            .transaction_entries
            .iter()
            .map(|e| e.index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(
        control
            .expected
            .transaction_entries
            .iter()
            .map(|e| e.index)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        rejected.expected.transaction_entries,
        control.expected.transaction_entries[..2]
    );
    assert_eq!(control.expected.verdict, "Accept");
    replay(rejected);
    replay(control);
}

// ledger: BLOCK-digest-state-accounting-B005
#[test]
fn block_digest_delegated_accounting_matches_jvm() {
    for name in ["h-digest-accept", "h-digest-reject"] {
        let case = fixture(name);
        assert!(case.digest_expected.is_some());
        replay(case);
    }
}

// ledger: BLOCK-param-voting
#[test]
fn block_epoch_voting_threshold_matches_jvm() {
    for name in [
        "i-vote-16384-down",
        "i-vote-16384-up",
        "i-vote-16385-down",
        "i-vote-16385-up",
        "i-vote-output-one-up",
    ] {
        let case = fixture(name);
        assert!(case.transition.is_some());
        assert_eq!(case.parent_blocks.len(), 383);
        replay(case);
    }
}

// ledger: BLOCK-updated-context-before-validation-B006
#[test]
fn block_epoch_updated_context_matches_jvm() {
    let case = fixture("j-context-updated");
    assert_eq!(case.transition.as_ref().unwrap().stale_verdict, "Accept");
    assert_eq!(case.expected.verdict, "Reject");
    assert_eq!(case.parent_blocks.len(), 383);
    replay(case);
}
