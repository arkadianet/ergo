//! Oracle: test-vectors/ergo-sigma/cost-ledger/blocks/
//! JVM producer: scripts/jvm_block_oracle/BlockOracle.scala (Ergo 6.0.5).

use std::{collections::BTreeMap, fs::File, path::Path};

use ergo_primitives::{digest::Digest32, reader::VlqReader};
use ergo_ser::{
    block_transactions::BlockTransactions,
    ergo_box::{read_ergo_box, ErgoBox},
    extension::{Extension, ExtensionField},
    header::{read_header, serialize_header},
    modifier_id::{compute_section_id, TYPE_AD_PROOFS},
    transaction::read_transaction,
};
use ergo_state::{avl::tree::AvlTree, store::StateStore, DigestProofVerifier};
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

// ----- helpers -----

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    ledger: Vec<String>,
    manifest: Value,
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
}

#[derive(Deserialize)]
struct Expected {
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
    state: &'a State,
    parents: &'a [Block],
    params: &'a ProtocolParams,
    headers: &'a [CheckedHeader],
) -> BlockValidationContext<'a> {
    let parent = parents.last().unwrap();
    BlockValidationContext {
        parent: &parent.header,
        utxo: state,
        params,
        voting_length: 128,
        votes_unknown_rule_disabled: false,
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
        Some(error) => panic!("unmapped Rust rejection: {error:?}"),
    }
}

fn replay(fixture: Fixture) {
    assert_eq!(fixture.schema_version, 1);
    assert!(fixture.ledger.iter().any(|id| id == "BLOCK-parallel-equiv"));
    for field in ["scala", "rust", "tool", "context", "run", "evidence"] {
        assert!(
            fixture.manifest[field].is_object(),
            "missing manifest {field}"
        );
    }
    assert_eq!(fixture.manifest["scala"]["ergo_version"], "6.0.5");
    assert_eq!(fixture.manifest["scala"]["sigmastate_version"], "6.0.6");
    assert_eq!(
        fixture.manifest["evidence"]["output_payload_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    if let Some(hash) = fixture.manifest["evidence"]["input_sha256"].as_str() {
        assert_eq!(hash.len(), 64);
    }
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
    assert_eq!(fixture.parent_blocks.len(), 128);
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
    let ctx = context(&state, &parents, &params, &headers);
    assert_eq!(fixture.transactions_hex, fixture.block.transactions_hex);
    let target = fixture.block.decode();
    assert_eq!(target.header.height(), 129);
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
    let observed = validate_full_block_with_costs(
        target.header.clone(),
        &target.transactions,
        &target.extension,
        &ctx,
    );
    let parallel = validate_full_block_parallel_with_costs(
        target.header.clone(),
        &target.transactions,
        &target.extension,
        &ctx,
    );
    let expected = jvm_verdict(&fixture.expected);
    for actual in [
        sequential.as_ref().err(),
        observed.as_ref().err(),
        parallel.as_ref().err(),
    ] {
        assert_eq!(rust_verdict(actual), expected, "{actual:?}");
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
        let fixture =
            serde_json::from_reader(flate2::read::GzDecoder::new(File::open(path).unwrap()))
                .unwrap();
        replay(fixture);
    }
    eprintln!(
        "selected={} executed={} skipped=0 failed=0",
        paths.len(),
        paths.len()
    );
}
