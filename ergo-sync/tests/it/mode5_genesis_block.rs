//! Mode 5 genesis fast-path: drive the REAL executor digest path
//! (`ergo_sync::block_proc::process_block`) for block 1 against a fresh,
//! genesis-seeded `DigestStateStore` and assert the digest advances from
//! the mainnet genesis root (`a5df...02`) to the height-1 root
//! (`18b7...03`).
//!
//! Block 1's parent is the all-zero genesis sentinel, so the digest arm
//! takes its `height == 1 && parent == [0;32]` branch: it skips
//! `validate_full_block` (no parent header to bind parent-dependent rules
//! against, mirroring the UTXO arm's `apply_genesis`) but still replays
//! the block's ADProofs against the genesis state root and cross-checks
//! the computed post-root against `header.state_root` before commit.
//!
//! Internal producer/consumer interop, NOT external Scala parity: there
//! is no Scala-extracted genesis-era ADProof corpus, so the ADProofs are
//! derived from the Mode-1 prover (via the `test-helpers`
//! `derive_ad_proofs_over_boxes` seam) and the header's `ad_proofs_root`
//! is synthesized from that self-derived witness. The state-root
//! transition itself (`a5df...02` -> `18b7...03`) is the consensus-pinned
//! value that `ergo-state/tests/genesis_digest.rs` independently pins for
//! Mode 1.

use std::collections::HashMap;

use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ad_proofs::{write_ad_proofs, ADProofs};
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::extension::{write_extension, Extension};
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::{read_transaction, Transaction};
use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
use ergo_state::test_helpers::derive_ad_proofs_over_boxes;
use ergo_state::{DigestStateStore, HeaderSectionStore, StateBackendKind};
use ergo_sync::block_proc::process_block;
use ergo_validation::context::ProtocolParams;

const GENESIS_STATE_DIGEST_HEX: &str =
    "a5df145d41ab15a01e0cd3ffbab046f0d029e5412293072ad0f5827428589b9302";
const HEIGHT_1_STATE_DIGEST_HEX: &str =
    "18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303";

const BLOCKS_1_5_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-vectors/mainnet/blocks_1_5.json"
));

#[derive(serde::Deserialize)]
struct GenesisBoxJson {
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: HashMap<String, String>,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
}

#[derive(serde::Deserialize)]
struct BlockJson {
    height: u32,
    transactions: Vec<TxJson>,
}
#[derive(serde::Deserialize)]
struct TxJson {
    bytes: String,
}

fn arr33(h: &str) -> [u8; 33] {
    let v = hex::decode(h).expect("hex33");
    v.try_into().expect("len 33")
}

fn parse_genesis_box(json: &GenesisBoxJson) -> ErgoBox {
    let tree_bytes = hex::decode(&json.ergo_tree).expect("ergo_tree hex");
    let mut r = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).expect("read_ergo_tree");

    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    for (key, val_hex) in &json.additional_registers {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            other => panic!("unknown register {other}"),
        };
        let val_bytes = hex::decode(val_hex).expect("register hex");
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) = read_constant(&mut vr).expect("read_constant");
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
    }
    reg_vec.sort_by_key(|(idx, _)| *idx);
    let registers = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };

    let candidate = ErgoBoxCandidate::new(
        json.value,
        ergo_tree,
        json.creation_height,
        Vec::new(),
        registers,
    )
    .expect("ErgoBoxCandidate::new");

    let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
        .expect("tx id hex")
        .try_into()
        .expect("tx id len");
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: json.index,
    }
}

/// The 3 genesis boxes as `(box_id, serialized_box_bytes)` — the AVL+
/// pre-state at height 0.
fn genesis_pre_state() -> Vec<([u8; 32], Vec<u8>)> {
    let boxes_json = ergo_chain_spec::GenesisParams::mainnet()
        .boxes_json
        .expect("mainnet genesis boxes embedded");
    let boxes: Vec<GenesisBoxJson> = serde_json::from_str(boxes_json).expect("parse genesis boxes");
    assert_eq!(boxes.len(), 3, "mainnet genesis has 3 boxes");
    boxes
        .iter()
        .map(|jb| {
            let eb = parse_genesis_box(jb);
            let box_id = *eb.box_id().expect("box_id").as_bytes();
            let serialized = serialize_ergo_box(&eb).expect("serialize_ergo_box");
            (box_id, serialized)
        })
        .collect()
}

fn block_1_tx() -> Transaction {
    let blocks: Vec<BlockJson> = serde_json::from_str(BLOCKS_1_5_JSON).expect("parse blocks_1_5");
    let block1 = blocks
        .iter()
        .find(|b| b.height == 1)
        .expect("block 1 present");
    assert_eq!(block1.transactions.len(), 1, "block 1 has one tx");
    let tx_bytes = hex::decode(&block1.transactions[0].bytes).expect("tx bytes hex");
    let mut r = VlqReader::new(&tx_bytes);
    read_transaction(&mut r).expect("read block-1 tx")
}

/// `transactions_root` for a single-tx, version-2 block — the same
/// merkle computation `validate_full_block` runs (tx-id leaves followed
/// by 31-byte witness-hash leaves for version >= 2).
fn compute_transactions_root(tx: &Transaction) -> [u8; 32] {
    let bts = ergo_ser::transaction::bytes_to_sign(tx).expect("bytes_to_sign");
    let tx_id = blake2b256(&bts).as_bytes().to_vec();
    let mut all_proofs = Vec::new();
    for input in &tx.inputs {
        all_proofs.extend_from_slice(&input.spending_proof.proof);
    }
    let witness = blake2b256(&all_proofs).as_bytes()[1..].to_vec();
    ergo_crypto::merkle::transactions_root(&[tx_id.as_slice()], Some(&[witness.as_slice()]))
}

/// `extension_root` for an empty extension.
fn compute_extension_root() -> [u8; 32] {
    ergo_crypto::merkle::extension_root(&[])
}

/// Synthesize a parseable block-1 header pinned to the supplied roots.
/// Genesis skips PoW validation, but the merkle roots are real (computed
/// from the actual sections) so the block is internally consistent — the
/// test must not rely on the genesis path accepting mismatched roots.
fn synth_block_1_header(
    state_root: [u8; 33],
    ad_proofs_root: [u8; 32],
    transactions_root: [u8; 32],
    extension_root: [u8; 32],
) -> Header {
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::from_bytes(ad_proofs_root),
        state_root: ADDigest::from_bytes(state_root),
        transactions_root: Digest32::from_bytes(transactions_root),
        timestamp: 1_561_978_800_000,
        n_bits: 0x1d00ffff,
        height: 1,
        extension_root: Digest32::from_bytes(extension_root),
        votes: [0u8; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0xAA; 8],
        },
    }
}

fn block_txs_section_bytes(header_id: [u8; 32], tx: &Transaction) -> Vec<u8> {
    let bt = BlockTransactions {
        header_id: ModifierId::from_bytes(header_id),
        transactions: vec![tx.clone()],
    };
    let mut w = VlqWriter::new();
    write_block_transactions(&mut w, &bt).expect("write_block_transactions");
    w.result()
}

fn extension_section_bytes(header_id: [u8; 32]) -> Vec<u8> {
    let ext = Extension {
        header_id: ModifierId::from_bytes(header_id),
        fields: vec![],
    };
    let mut w = VlqWriter::new();
    write_extension(&mut w, &ext).expect("write_extension");
    w.result()
}

fn ad_proofs_section_bytes(header_id: [u8; 32], proof_bytes: &[u8]) -> Vec<u8> {
    let ap = ADProofs {
        header_id: ModifierId::from_bytes(header_id),
        proof_bytes: proof_bytes.to_vec(),
    };
    let mut w = VlqWriter::new();
    write_ad_proofs(&mut w, &ap);
    w.result()
}

/// All artifacts of the synthesized block 1: the canonical header id /
/// bytes, the section bytes, and the self-derived ADProofs.
struct GenesisBlockFixture {
    header: Header,
    header_id: [u8; 32],
    header_bytes: Vec<u8>,
    tx: Transaction,
    proof_bytes: Vec<u8>,
}

/// Derive the block-1 ADProofs over the genesis state and synthesize a
/// fully consistent (real merkle roots, self-derived ADProofs) block-1
/// header + sections.
fn build_genesis_block_fixture() -> GenesisBlockFixture {
    let height_1_root = arr33(HEIGHT_1_STATE_DIGEST_HEX);
    let tx = block_1_tx();
    let (to_remove, to_insert) =
        StateStore::build_utxo_changes_raw(&[&tx]).expect("build_utxo_changes_raw");

    let pre_state = genesis_pre_state();
    let (derived_root, proof_bytes) =
        derive_ad_proofs_over_boxes(&pre_state, &[], &to_remove, &to_insert)
            .expect("derive genesis-block ADProofs");
    assert_eq!(
        derived_root, height_1_root,
        "producer post-root != consensus-pinned height-1 digest",
    );

    let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
    let header = synth_block_1_header(
        height_1_root,
        ad_proofs_root,
        compute_transactions_root(&tx),
        compute_extension_root(),
    );
    let (header_bytes, header_id_mod) = serialize_header(&header).expect("serialize_header");
    let header_id = *header_id_mod.as_bytes();

    GenesisBlockFixture {
        header,
        header_id,
        header_bytes,
        tx,
        proof_bytes,
    }
}

/// Open a fresh genesis-seeded store and persist the block-1 header
/// (advancing best_header to height 1) + its three sections.
fn open_store_with_block_1(
    db_path: &std::path::Path,
    fx: &GenesisBlockFixture,
) -> DigestStateStore {
    let mut store = DigestStateStore::open(
        db_path,
        ergo_validation::scala_launch(),
        ergo_chain_spec::VotingParams::mainnet(),
        ergo_chain_spec::GenesisParams::mainnet().state_digest,
    )
    .expect("open digest store");

    let tx_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        &fx.header_id,
        fx.header.transactions_root.as_bytes(),
    );
    let ext_id = compute_section_id(
        TYPE_EXTENSION,
        &fx.header_id,
        fx.header.extension_root.as_bytes(),
    );
    let ad_id = compute_section_id(
        TYPE_AD_PROOFS,
        &fx.header_id,
        fx.header.ad_proofs_root.as_bytes(),
    );

    // Validate + accept the block-1 header, advancing best_header to
    // height 1 (the header pipeline runs before the full-block apply, so
    // the `best_header >= best_full_block` invariant holds at commit).
    let meta = HeaderMeta {
        parent_id: [0u8; 32],
        height: 1,
        cumulative_score: 1u64.to_be_bytes().to_vec(),
        pow_validity: 1,
        timestamp: fx.header.timestamp,
    };
    store
        .store_validated_header(
            &fx.header_id,
            &fx.header_bytes,
            &meta,
            Some((1, 1u64.to_be_bytes().to_vec())),
        )
        .expect("store + accept block-1 header");
    store
        .store_block_section_typed(
            &tx_id,
            &block_txs_section_bytes(fx.header_id, &fx.tx),
            TYPE_BLOCK_TRANSACTIONS,
        )
        .expect("store block_tx section");
    store
        .store_block_section_typed(
            &ext_id,
            &extension_section_bytes(fx.header_id),
            TYPE_EXTENSION,
        )
        .expect("store extension section");
    store
        .store_block_section_typed(
            &ad_id,
            &ad_proofs_section_bytes(fx.header_id, &fx.proof_bytes),
            TYPE_AD_PROOFS,
        )
        .expect("store ad_proofs section");
    store
}

#[test]
fn mode5_process_block_genesis_advances_to_height_1() {
    let genesis_root = arr33(GENESIS_STATE_DIGEST_HEX);
    let height_1_root = arr33(HEIGHT_1_STATE_DIGEST_HEX);

    let fx = build_genesis_block_fixture();
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = open_store_with_block_1(&tmp.path().join("digest_state.redb"), &fx);

    // Fresh store boots at the genesis root.
    assert_eq!(
        store.root_digest(),
        genesis_root,
        "fresh store must seed genesis root"
    );
    assert_eq!(store.height(), 0);

    let mut backend = StateBackendKind::Digest(store);
    let params = ProtocolParams::mainnet_default();

    let processed = process_block(
        &mut backend,
        &fx.header_id,
        &params,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("process_block must apply the genesis block");
    assert_eq!(processed.height, 1, "processed height must be 1");

    let StateBackendKind::Digest(ref d) = backend else {
        unreachable!("backend is Digest");
    };
    assert_eq!(
        d.root_digest(),
        height_1_root,
        "post-genesis root must be the consensus-pinned height-1 digest",
    );
    assert_eq!(d.height(), 1, "full-block tip must advance to height 1");
    assert_eq!(
        d.chain_state().best_full_block_id,
        fx.header_id,
        "best_full_block_id must be the block-1 header id",
    );
}

#[test]
fn mode5_process_block_genesis_rejects_tampered_state_root() {
    // The genesis fast-path skips parent-dependent full validation (no
    // parent header exists at height 1, mirroring the UTXO arm's
    // `apply_genesis`), so its binding consensus anchor is the verifier's
    // `computed_root == header.state_root` cross-check. A block-1 header
    // carrying a state_root the real ADProofs do not reach MUST reject —
    // forging the committed state_root from a different tx set would need
    // an AVL+ root preimage collision.
    let height_1_root = arr33(HEIGHT_1_STATE_DIGEST_HEX);
    let tx = block_1_tx();
    let (to_remove, to_insert) =
        StateStore::build_utxo_changes_raw(&[&tx]).expect("build_utxo_changes_raw");
    let pre_state = genesis_pre_state();
    let (derived_root, proof_bytes) =
        derive_ad_proofs_over_boxes(&pre_state, &[], &to_remove, &to_insert)
            .expect("derive genesis-block ADProofs");
    assert_eq!(derived_root, height_1_root);

    // Tamper the header's state_root (flip one byte) while keeping the
    // ad_proofs_root consistent with the REAL proof, so the verifier's
    // ADProofs-root binding passes and the post-root cross-check is the
    // arm that fires.
    let mut tampered_root = height_1_root;
    tampered_root[0] ^= 0xFF;
    let ad_proofs_root = *blake2b256(&proof_bytes).as_bytes();
    let header = synth_block_1_header(
        tampered_root,
        ad_proofs_root,
        compute_transactions_root(&tx),
        compute_extension_root(),
    );
    let (header_bytes, header_id_mod) = serialize_header(&header).expect("serialize_header");
    let header_id = *header_id_mod.as_bytes();
    let fx = GenesisBlockFixture {
        header,
        header_id,
        header_bytes,
        tx,
        proof_bytes,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = open_store_with_block_1(&tmp.path().join("digest_state.redb"), &fx);
    let mut backend = StateBackendKind::Digest(store);
    let params = ProtocolParams::mainnet_default();

    let err = process_block(
        &mut backend,
        &fx.header_id,
        &params,
        None,
        None,
        None,
        None,
        None,
    )
    .expect_err("a tampered genesis state_root must be rejected by the verifier");
    // The post-apply digest cross-check surfaces as a verifier/state error,
    // and the store must NOT have advanced.
    let StateBackendKind::Digest(ref d) = backend else {
        unreachable!("backend is Digest");
    };
    assert_eq!(
        d.height(),
        0,
        "rejected genesis block must not advance the tip"
    );
    let msg = format!("{err:?}");
    assert!(
        msg.to_lowercase().contains("digest") || msg.to_lowercase().contains("mismatch"),
        "rejection should reflect the digest/state-root mismatch: {msg}",
    );
}

#[test]
fn mode5_process_block_genesis_on_non_fresh_tip_is_out_of_order() {
    // The genesis fast-path is gated on `store.height() == 0`. Replaying
    // block 1 against a store already advanced past genesis must NOT take
    // the genesis branch (which would verify against the wrong tip root);
    // it must classify as `DigestOutOfOrder`, the linear-apply fork/replay
    // signal — NOT a verifier rejection.
    let fx = build_genesis_block_fixture();
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = open_store_with_block_1(&tmp.path().join("digest_state.redb"), &fx);

    // Apply block 1 once so the tip is at height 1.
    let mut backend = StateBackendKind::Digest(store);
    let params = ProtocolParams::mainnet_default();
    process_block(
        &mut backend,
        &fx.header_id,
        &params,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("first genesis apply must succeed");

    // Re-process block 1 against the now-height-1 tip.
    let err = process_block(
        &mut backend,
        &fx.header_id,
        &params,
        None,
        None,
        None,
        None,
        None,
    )
    .expect_err("replaying block 1 on a non-fresh tip must be rejected");
    assert!(
        matches!(
            err,
            ergo_sync::block_proc::BlockProcessError::DigestOutOfOrder {
                expected: 2,
                got: 1
            }
        ),
        "expected DigestOutOfOrder, got {err:?}",
    );
}
