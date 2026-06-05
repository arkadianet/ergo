//! Off-loop candidate engine seam test: the engine's contract is *relocation
//! equivalence* — building a candidate off the committed redb snapshot must
//! produce exactly the block the on-loop live-store build would have, and the
//! published cache must serve it with correct CAS / synced gating.
//!
//! Scope: this is a **self-consistency** proof between the two views of the
//! same builder, not an external-oracle consensus-validity check. The
//! candidate's mainnet validity is covered elsewhere — the emission tx against
//! captured mainnet vectors (`reemission`/`coinbase` tests), the difficulty
//! retarget against its own vectors, and the AVL dry-run `(state_root,
//! ADProofs)` against the live tree (`ergo-state` `committed_snapshot_parity`).
//! What is unique to the engine, and pinned here, is that relocating the build
//! off the action loop changes nothing about the produced block.
//!
//! Two properties are pinned, both against a synthetic-but-internally-
//! consistent chain built on a real `StateStore`:
//!
//! 1. **Off-loop == on-loop parity**: `generate_candidate` run against the
//!    live `StateStore` view and against the `CommittedSnapshot` view of the
//!    same committed tip produce byte-identical `(Candidate, WorkMessage)`.
//!    This is the headline guarantee the engine relies on — the off-loop
//!    snapshot build is the same block the on-loop build would have produced.
//!
//! 2. **Published path**: `engine::build_and_publish` against that store
//!    returns `BuildOutcome::Published`, and the work it caches is served back
//!    through `MiningHandle::cached_work_if_synced` matching the on-loop oracle.
//!    A follow-up build whose live tip has moved off the built parent is
//!    dropped (`BuildOutcome::DroppedStale`), proving the publish CAS.
//!
//! The chain is constructed so every read `generate_candidate` performs against
//! the parent tip resolves: a trivially-spendable emission box seeded into the
//! genesis UTXO set, a parent header carrying that box in its
//! BlockTransactions section, a parent Extension section with a valid
//! interlinks vector, and ten chained + indexed headers so the last-10 window
//! and the `synced(tip)` gate both hold. The candidate height is chosen on the
//! difficulty non-recalc path (parent reuses its own `n_bits`) and away from
//! any epoch / hard-fork boundary, so difficulty retarget needs only the
//! parent header.
//!
//! Both EIP-27 regimes are exercised via the `Regime` abstraction:
//! - **pre-EIP-27** (`reemission = None`, candidate height 15): the
//!   non-EIP-27 / public-testnet emission path (`build_pre_eip27_emission_tx`).
//! - **mainnet / post-EIP-27** (`reemission = Some(mainnet)`, candidate height
//!   777_300 — above the 777_217 activation, clear of epoch boundaries): the
//!   deployed mainnet path (`build_post_eip27_emission_tx`), where the seeded
//!   emission box carries the EIP-27 NFT + reemission stash and each block
//!   deducts the per-block reemission share to the miner. The post-activation
//!   chain is seeded directly at height 777_290..=777_299 (no sequential-height
//!   check in `apply_block_unchecked`), so no 777k-block replay is needed.

use ergo_crypto::difficulty::DifficultyParams;
use ergo_mempool::MempoolReadSnapshot;
use ergo_mining::candidate::{generate_candidate, Candidate};
use ergo_mining::emission_rules::MonetarySettings;
use ergo_mining::engine::{build_and_publish, BestTip, BuildIntent, BuildOutcome, BuildReason};
use ergo_mining::error::MiningError;
use ergo_mining::handle::MiningHandle;
use ergo_mining::reemission::ReemissionSettings;
use ergo_mining::work_message::WorkMessage;
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::ergo_box::{write_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::token::Token;
use ergo_ser::transaction::Transaction;
use ergo_state::store::StateStore;
use ergo_validation::popow::algos::pack_interlinks;
use std::sync::Arc;

// ----- helpers -----

const MINER_PK: [u8; 33] = [0x02u8; 33];

/// Parent (tip) height. The candidate is built for `PARENT_HEIGHT + 1`.
/// 14 keeps the candidate at height 15: ≥10 (last-10 window holds), not a
/// multiple of 1024 (non-epoch), parent height 14 not a multiple of the 1024
/// epoch length (difficulty non-recalc → reuse parent `n_bits`), and far below
/// the v2 (417_792) / EIP-37 (844_673) mainnet boundaries.
const PARENT_HEIGHT: u32 = 14;

/// Parent (tip) height for the mainnet / post-EIP-27 regime. The candidate is
/// built for `EIP27_PARENT_HEIGHT + 1 = 777_300`, which is:
/// - above the EIP-27 activation height (777_217), so `generate_candidate`
///   takes the `build_post_eip27_emission_tx` branch;
/// - clear of the surrounding 1024-block epoch boundaries (777_216 and
///   778_240), so `is_epoch_boundary_mainnet` does not reject it;
/// - a non-recalc difficulty height (parent 777_299 is not a 1024-multiple),
///   so `next_n_bits` reuses the parent's `n_bits` from the single parent
///   header alone — same reasoning as `PARENT_HEIGHT`;
/// - below the EIP-37 boundary (844_673), so the 1024-block epoch length holds.
const EIP27_PARENT_HEIGHT: u32 = 777_299;

/// A compact-bits value that round-trips through decode→encode unchanged, so
/// the non-recalc difficulty path reproduces it verbatim as the candidate's
/// `n_bits`. Matches the value the `ergo-state` snapshot parity harness uses.
const N_BITS: u32 = 16_842_752;

/// Parent header timestamp, deliberately far in the future (≈ year 2100). The
/// candidate timestamp is `max(now_ms, parent.timestamp + 1)`; with a parent
/// timestamp this far ahead, the clamped-monotonic branch wins, so both the
/// on-loop and off-loop builds compute the IDENTICAL deterministic timestamp
/// (`parent.timestamp + 1`) instead of two different wall-clock reads. Without
/// this, the two builds run microseconds apart and their headers — hence
/// `work.msg` — would differ on the timestamp field alone.
///
/// This loses no seam coverage: the timestamp is view-INDEPENDENT (pure
/// wall-clock + the parent header timestamp, which both views read identically),
/// so the off-loop and on-loop builds can only ever differ on it by wall-clock
/// skew, never by which view produced it. Pinning it removes a spurious flake,
/// not a real divergence the parity assertion would otherwise catch.
const PARENT_TIMESTAMP: u64 = 4_100_000_000_000;

/// Emission box value: comfortably above both the per-block miner reward at a
/// fixed-rate-window height (67.5 ERG) and the structural min-value floor.
/// Also above the post-EIP-27 miner reward at h=777_300 (63 ERG), so the same
/// value seeds both regimes' emission boxes without underflow.
const EMISSION_BOX_VALUE: u64 = 73_000_000_000_000;

/// Reemission stash seeded into the post-EIP-27 emission box. The mainnet
/// fixture at h=777_217 carries 19_999_988_000_000_000 reemission tokens; any
/// amount comfortably above the 12-ERG per-block charge
/// (`reemission_for_height` at h=777_300) works, so we reuse the fixture's.
const EIP27_REEMISSION_STASH: u64 = 19_999_988_000_000_000;

/// Mining regime: which EIP-27 settings the build runs under, what parent
/// height the synthetic chain tips at, and which tokens the seeded emission
/// box carries. The two constructors mirror the deployed paths:
/// - `pre_eip27`: `reemission = None`, no emission-box tokens — the
///   non-EIP-27 / public-testnet path (`build_pre_eip27_emission_tx`).
/// - `mainnet_post_eip27`: `reemission = Some(mainnet)`, emission box carries
///   the NFT + reemission stash, parent above activation — the deployed
///   mainnet path (`build_post_eip27_emission_tx`).
struct Regime {
    parent_height: u32,
    reemission: Option<ReemissionSettings>,
    /// Tokens on the seeded emission box (`tx[0].output[0]` of the parent
    /// block). Empty for the pre-EIP-27 regime; `[NFT, reemission stash]` for
    /// post-EIP-27 (the 2-entry shape `build_post_eip27_emission_tx` requires).
    emission_tokens: Vec<Token>,
}

impl Regime {
    fn pre_eip27() -> Self {
        Self {
            parent_height: PARENT_HEIGHT,
            reemission: None,
            emission_tokens: Vec::new(),
        }
    }

    fn mainnet_post_eip27() -> Self {
        let reem = ReemissionSettings::mainnet();
        // NFT (amount 1) at index 0, reemission stash at index 1 — the
        // mainnet emission-box token layout (777_217 fixture output[0]).
        let emission_tokens = vec![
            Token {
                token_id: reem.emission_nft_id,
                amount: 1,
            },
            Token {
                token_id: reem.reemission_token_id,
                amount: EIP27_REEMISSION_STASH,
            },
        ];
        Self {
            parent_height: EIP27_PARENT_HEIGHT,
            reemission: Some(reem),
            emission_tokens,
        }
    }

    fn candidate_height(&self) -> u32 {
        self.parent_height + 1
    }
}

/// A trivially-true ErgoTree (`SBoolean true`, inline): `header 0x00`, body
/// `0x01 0x01`. Reduces to `TrivialProp(true)`, so the emission tx's single
/// input verifies with an empty spending proof — the same shape the
/// `ergo-mining::emission_box` discovery test relies on.
fn trivial_true_tree() -> (Vec<u8>, ergo_ser::ergo_tree::ErgoTree) {
    let bytes = vec![0x00u8, 0x01, 0x01];
    let mut r = VlqReader::new(&bytes);
    let tree = read_ergo_tree(&mut r).expect("trivial-true tree decodes");
    (bytes, tree)
}

/// The emission tx that the parent block "applied": one input (an arbitrary
/// prior box id) and `output[0]` = the emission box the candidate will consume.
/// A second output keeps the shape close to a real coinbase but only
/// `output[0]` matters for emission-box discovery. `output[0]` carries the
/// regime's emission tokens (none pre-EIP-27; NFT + reemission stash for
/// post-EIP-27), so the candidate's post-activation emission tx finds the
/// 2-token box `build_post_eip27_emission_tx` requires.
fn parent_emission_tx(regime: &Regime) -> Transaction {
    let (tree_bytes, tree) = trivial_true_tree();
    let input = Input {
        box_id: Digest32::from_bytes([0xAAu8; 32]),
        spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
    };
    let emission_out = ErgoBoxCandidate::from_trusted_raw_parts(
        EMISSION_BOX_VALUE,
        tree.clone(),
        tree_bytes.clone(),
        regime.parent_height,
        regime.emission_tokens.clone(),
        AdditionalRegisters::empty(),
        vec![0x00],
    );
    let miner_out = ErgoBoxCandidate::from_trusted_raw_parts(
        65_000_000_000,
        tree,
        tree_bytes,
        regime.parent_height,
        Vec::new(),
        AdditionalRegisters::empty(),
        vec![0x00],
    );
    Transaction {
        inputs: vec![input],
        data_inputs: Vec::new(),
        output_candidates: vec![emission_out, miner_out],
    }
}

/// Recover the emission box (`tx[0].output[0]`) exactly as
/// `lookup_emission_box_from_parent` reconstructs it: candidate +
/// `transaction_id = blake2b256(bytes_to_sign(tx))` + index 0.
fn emission_box_from(tx: &Transaction) -> ErgoBox {
    let bts = ergo_ser::transaction::bytes_to_sign(tx).expect("bytes_to_sign");
    let tx_id: ModifierId = ergo_primitives::digest::blake2b256(&bts).into();
    ErgoBox {
        candidate: tx.output_candidates[0].clone(),
        transaction_id: tx_id,
        index: 0,
    }
}

/// Header for `height`, chained to `parent_id`, carrying the supplied
/// committed `state_root` and the (caller-chosen) section digests used as
/// section-id key material.
fn header(
    height: u32,
    parent_id: ModifierId,
    state_root: ADDigest,
    transactions_root: Digest32,
    extension_root: Digest32,
) -> Header {
    Header {
        version: 2,
        parent_id,
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        transactions_root,
        state_root,
        timestamp: PARENT_TIMESTAMP + height as u64,
        extension_root,
        n_bits: N_BITS,
        height,
        votes: [0u8; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from(MINER_PK),
            nonce: [0u8; 8],
        },
    }
}

/// Serialize the parent's Extension section in the canonical Scala wire shape
/// `read_parent_extension_bytes` / `unpack_interlinks_from_extension` read —
/// the exact bytes `ergo_ser::extension::write_extension` emits and that
/// `apply_mined_block` / peer ingest persist (`[32-byte header_id][u16
/// n_fields]` then per field `[2-byte key][u8 val_len][val]`). The interlinks
/// keys come from `pack_interlinks`, which are exactly 2 bytes.
fn extension_section_bytes(header_id: &[u8; 32], fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    use ergo_ser::extension::{write_extension, Extension, ExtensionField};
    let ext = Extension {
        header_id: ModifierId::from_bytes(*header_id),
        fields: fields
            .iter()
            .map(|(k, v)| ExtensionField {
                key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                value: v.clone(),
            })
            .collect(),
    };
    let mut w = VlqWriter::new();
    write_extension(&mut w, &ext).expect("write extension");
    w.result()
}

/// A fully-wired store synced to `regime.parent_height`, returning the temp
/// dir guard, the store, and the tip (parent) header id.
///
/// Construction:
/// 1. Seed genesis with the regime's emission box keyed by its real `box_id`
///    so the candidate's input resolves against the committed UTXO set.
/// 2. Apply the ten heights `(parent_height - 9)..=parent_height` with empty
///    change-sets (the emission box stays in the set, committed root
///    unchanged), chaining + indexing the headers so the last-10 window and
///    `synced(tip)` hold. `apply_block_unchecked` sets `self.height = height`
///    directly with no `height == prev + 1` check, so the chain can be seeded
///    at an arbitrary base height (here 777_290) without applying 777k blocks.
/// 3. Store the parent's BlockTransactions section (carrying the emission tx)
///    and Extension section (a one-entry interlinks vector) under the
///    section-ids derived from the parent header's roots.
fn synced_store(regime: &Regime) -> (tempfile::TempDir, StateStore, [u8; 32]) {
    // Default parent extension: a single-entry interlinks vector (the
    // genesis-style `[parent_id]` set), built once the tip id is known.
    synced_store_with_parent_interlinks(regime, |tip| {
        pack_interlinks(&[ModifierId::from_bytes(*tip)])
    })
}

/// `synced_store` parameterized by the parent extension's interlinks fields.
/// `interlinks_fields(tip)` is given the parent (tip) header id and returns the
/// canonical-wire `(key, value)` pairs to seed into the parent Extension
/// section. The default `synced_store` seeds a one-entry interlinks vector; the
/// guard test seeds an empty one (no `0x01`-prefixed fields) to drive the
/// non-genesis-parent-without-interlinks path.
fn synced_store_with_parent_interlinks(
    regime: &Regime,
    interlinks_fields: impl Fn(&[u8; 32]) -> Vec<(Vec<u8>, Vec<u8>)>,
) -> (tempfile::TempDir, StateStore, [u8; 32]) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    let em_tx = parent_emission_tx(regime);
    let em_box = emission_box_from(&em_tx);
    let em_box_id = *em_box.box_id().expect("emission box id").as_bytes();
    let em_box_bytes = write_box_bytes(&em_box);

    store
        .initialize_genesis(&[(em_box_id, em_box_bytes)])
        .unwrap();
    let committed_root = store.root_digest();

    // Parent header's roots are chosen freely (they only key the stored
    // sections); use distinct, non-zero digests so the two section-ids differ.
    let parent_tx_root = Digest32::from_bytes([0x77u8; 32]);
    let parent_ext_root = Digest32::from_bytes([0x55u8; 32]);

    let parent_height = regime.parent_height;
    let base_height = parent_height - 9;
    let mut parent_id: ModifierId = Digest32::from_bytes([0u8; 32]).into();
    let mut tip = [0u8; 32];
    for h in base_height..=parent_height {
        // Only the parent (top) header needs real section roots; the earlier
        // window headers just need to chain + index, so zeroed roots are fine.
        let hdr = if h == parent_height {
            header(
                h,
                parent_id,
                committed_root,
                parent_tx_root,
                parent_ext_root,
            )
        } else {
            header(
                h,
                parent_id,
                committed_root,
                Digest32::from_bytes([0u8; 32]),
                Digest32::from_bytes([0u8; 32]),
            )
        };
        let (bytes, id) = serialize_header(&hdr).expect("serialize header");
        let id_bytes: [u8; 32] = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).expect("store_header");
        if h == base_height {
            // Seed the best-header chain index for the window's base height
            // before applying it. The first `apply_block_unchecked` rewrites
            // HEADER_CHAIN_INDEX from the new tip down via HEADER_META parent
            // links; with the chain seeded at an arbitrary base (777_290) the
            // synthesized HEADER_META below the tip has a zero parent_id, so
            // without this seed the rewrite walk runs off the bottom and trips
            // `rewrite_best_chain_into_index: row missing during walk`. A
            // pre-seeded entry at the base makes the walk terminate on the
            // `already_matches` fork-point at `base_height` instead.
            store
                .test_force_put_header_chain_index(h, &id_bytes)
                .expect("seed header chain index at base height");
        }
        store
            .apply_block_unchecked_for_test(h, &id_bytes, &committed_root, &[])
            .expect("apply empty block");
        parent_id = id;
        tip = id_bytes;
    }

    // Parent BlockTransactions section (emission tx at index 0).
    let bt = BlockTransactions {
        header_id: ModifierId::from_bytes(tip),
        transactions: vec![em_tx],
    };
    let mut w = VlqWriter::new();
    write_block_transactions_with_version(&mut w, &bt, 2).expect("write block txs");
    let bt_section_id =
        compute_section_id(TYPE_BLOCK_TRANSACTIONS, &tip, parent_tx_root.as_bytes());
    store
        .store_block_section_typed(&bt_section_id, &w.result(), TYPE_BLOCK_TRANSACTIONS)
        .expect("store block-transactions section");

    // Parent Extension section, seeded with the caller-supplied interlinks
    // fields. The default `synced_store` seeds a single-entry interlinks vector
    // (non-empty so `update_interlinks` never hits its empty-vector assertion,
    // well-formed so `unpack_interlinks` accepts it); the guard test seeds an
    // empty set to exercise the non-genesis-parent-without-interlinks path.
    let interlinks = interlinks_fields(&tip);
    let ext_bytes = extension_section_bytes(&tip, &interlinks);
    let ext_section_id = compute_section_id(TYPE_EXTENSION, &tip, parent_ext_root.as_bytes());
    store
        .store_block_section_typed(&ext_section_id, &ext_bytes, TYPE_EXTENSION)
        .expect("store extension section");

    (dir, store, tip)
}

fn handle(regime: &Regime) -> MiningHandle {
    MiningHandle::new(
        MINER_PK,
        MonetarySettings::mainnet(),
        regime.reemission.clone(),
        DifficultyParams::mainnet(),
    )
}

/// Fixed publish-time wall-clock stamp for the published template's
/// `built_at_ms`, returned by the `now_ms` closure passed to
/// `build_and_publish`. The parity assertions never inspect it, so a constant
/// keeps the build deterministic.
const BUILT_AT_MS: u64 = 1_700_000_000_000;

fn build_intent(parent: [u8; 32], parent_height: u32) -> BuildIntent {
    BuildIntent {
        expected_parent: parent,
        expected_height: parent_height,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: MINER_PK,
        eligible_rent_boxes: Arc::new(Vec::new()),
        reason: BuildReason::Startup,
    }
}

fn write_box_bytes(b: &ErgoBox) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_ergo_box(&mut w, b).expect("serialize emission box");
    w.result()
}

/// Run the on-loop oracle build directly against the live `StateStore`, under
/// the regime's reemission settings.
fn on_loop_build(store: &StateStore, regime: &Regime) -> (Candidate, WorkMessage) {
    let (c, w, _timings) = generate_candidate(
        store,
        MempoolReadSnapshot::empty(),
        &MINER_PK,
        &MonetarySettings::mainnet(),
        regime.reemission.as_ref(),
        &DifficultyParams::mainnet(),
        &[],
    )
    .expect("on-loop generate_candidate ok")
    .expect("on-loop candidate is Some");
    (c, w)
}

fn serialize_txs(txs: &[Transaction]) -> Vec<Vec<u8>> {
    txs.iter()
        .map(|tx| {
            let mut w = VlqWriter::new();
            ergo_ser::transaction::write_transaction(&mut w, tx).expect("serialize tx");
            w.result()
        })
        .collect()
}

// ----- happy path -----

#[test]
fn build_and_publish_publishes_and_serves_onloop_work() {
    publish_and_serve_under(&Regime::pre_eip27());
}

/// Mainnet / post-EIP-27 twin of `build_and_publish_publishes_and_serves_onloop_work`:
/// `reemission = Some(mainnet)` and a candidate height (777_300) above the
/// EIP-27 activation, so the published candidate carries the post-activation
/// emission tx (NFT + reemission-stash deduction). Guards the deployed publish
/// path, not just the pre-EIP-27 testnet one.
#[test]
fn build_and_publish_publishes_and_serves_onloop_work_post_eip27() {
    publish_and_serve_under(&Regime::mainnet_post_eip27());
}

/// Build-and-publish the candidate for `regime`'s synced tip, then assert the
/// engine published it and the served work matches the on-loop oracle
/// (`msg` + consensus-bearing `target` + height + pk).
fn publish_and_serve_under(regime: &Regime) {
    let (_dir, store, tip) = synced_store(regime);
    let oracle_w = on_loop_build(&store, regime).1;

    let handle = handle(regime);
    let intent = build_intent(tip, regime.parent_height);

    // The action loop maintains the authoritative tip on the handle; the engine
    // CAS-publishes against it. Set it to the synced tip the build will target
    // before invoking the engine.
    handle.set_best_tip(BestTip {
        parent_id: tip,
        chain_seq: 1,
        synced: true,
    });

    let outcome = build_and_publish(&store.reader_handle(), &handle, &intent, || BUILT_AT_MS)
        .expect("build_and_publish ok");
    let timings = match outcome {
        BuildOutcome::Published { timings } => timings,
        other => {
            panic!("engine must publish a candidate for the committed synced tip, got {other:?}",)
        }
    };
    // build_and_publish must PRESERVE the measured payload, not default it.
    // dryrun always executes real work so its Duration is provably non-zero.
    assert!(
        timings.dryrun > std::time::Duration::ZERO,
        "build_and_publish must thread non-zero dryrun timing through Published: {timings:?}",
    );

    // Serving then returns the published work, whose `msg` matches the
    // on-loop oracle.
    let served = handle
        .cached_work_if_synced()
        .expect("synced tip with a published candidate serves work");
    assert_eq!(
        served.msg, oracle_w.msg,
        "served work msg must equal the on-loop oracle's",
    );
    assert_eq!(
        served.target, oracle_w.target,
        "served work target must equal the on-loop oracle's",
    );
    assert_eq!(served.height, regime.candidate_height());
    assert_eq!(served.pk, MINER_PK);
}

#[test]
fn generate_candidate_measures_phase_timings() {
    let regime = Regime::mainnet_post_eip27();
    let (_dir, store, _tip) = synced_store(&regime);
    let snapshot = store
        .reader_handle()
        .committed_snapshot()
        .expect("snapshot read")
        .expect("committed state present");
    let (_c, _w, timings) = generate_candidate(
        &snapshot,
        MempoolReadSnapshot::empty(),
        &MINER_PK,
        &MonetarySettings::mainnet(),
        regime.reemission.as_ref(),
        &DifficultyParams::mainnet(),
        &[],
    )
    .expect("generate_candidate ok")
    .expect("candidate is Some");

    // emission, dryrun, and roots always execute real multi-statement work,
    // so nanosecond-resolution Duration provably exceeds zero even on the
    // fast in-memory test store.
    assert!(
        timings.emission > std::time::Duration::ZERO,
        "emission phase must record non-zero elapsed time: {timings:?}",
    );
    assert!(
        timings.dryrun > std::time::Duration::ZERO,
        "dryrun phase must record non-zero elapsed time: {timings:?}",
    );
    assert!(
        timings.roots > std::time::Duration::ZERO,
        "roots phase must record non-zero elapsed time: {timings:?}",
    );

    // rent and select legitimately measure near-zero on an empty mempool /
    // no rent boxes — assert only a sane upper ceiling (60 s).
    let sixty_s = std::time::Duration::from_secs(60);
    assert!(timings.rent < sixty_s, "rent ceiling: {timings:?}");
    assert!(timings.select < sixty_s, "select ceiling: {timings:?}");
}

// ----- error paths -----

#[test]
fn build_and_publish_drops_when_live_tip_moved_off_built_parent() {
    let regime = Regime::pre_eip27();
    let (_dir, store, tip) = synced_store(&regime);

    let handle = handle(&regime);
    // The live tip the action loop maintains is a DIFFERENT parent than the
    // one the committed snapshot builds against. The build succeeds off the
    // committed tip, but the publish CAS rejects it because the live tip no
    // longer matches the parent the candidate was built for.
    handle.set_best_tip(BestTip {
        parent_id: [0x99u8; 32],
        chain_seq: 2,
        synced: true,
    });

    let intent = build_intent(tip, regime.parent_height);
    let outcome = build_and_publish(&store.reader_handle(), &handle, &intent, || BUILT_AT_MS)
        .expect("build_and_publish ok");
    assert_eq!(
        outcome,
        BuildOutcome::DroppedStale,
        "a build whose live tip moved off the built parent must be dropped",
    );
    // Nothing was published, so serving (even at the live tip) yields nothing.
    assert_eq!(handle.cached_work_if_synced(), None);
}

#[test]
fn generate_candidate_non_genesis_parent_without_interlinks_errors_without_panicking() {
    // Seed a synced store whose non-genesis parent extension is canonical but
    // carries NO interlinks fields (a single non-`0x01`-prefixed system field).
    // `generate_candidate` must return the `parent_interlinks` decode error
    // rather than letting `update_interlinks` panic the engine task on its
    // empty-interlinks assertion. The test reaching this assertion at all (a
    // returned `Err`, not an unwind) is what proves the guard fires before the
    // panic.
    let regime = Regime::pre_eip27();
    let (_dir, store, tip) = synced_store_with_parent_interlinks(&regime, |_tip| {
        // One canonical field with a non-interlinks 2-byte key (`0x00..`), so
        // `unpack_interlinks` returns an empty vector for a non-genesis parent.
        vec![(vec![0x00, 0x01], vec![0xDE, 0xAD])]
    });
    assert_ne!(tip, [0u8; 32], "parent is non-genesis");

    let err = generate_candidate(
        &store,
        MempoolReadSnapshot::empty(),
        &MINER_PK,
        &MonetarySettings::mainnet(),
        regime.reemission.as_ref(),
        &DifficultyParams::mainnet(),
        &[],
    )
    .expect_err("non-genesis parent without interlinks must fail the build");

    match err {
        MiningError::Decode { op, .. } => assert_eq!(
            op, "parent_interlinks",
            "must be the parent-interlinks guard, not some other decode failure",
        ),
        other => panic!("expected parent_interlinks decode error, got {other:?}"),
    }
}

// ----- oracle parity -----
// On-loop is the reference path (itself validated against Scala/mainnet by the
// emission + difficulty + dry-run oracles elsewhere); the engine's contract is
// that its off-loop committed-snapshot build is byte-identical to it. This pins
// that contract — a self-consistency proof between the two views, not an
// external-oracle check.

#[test]
fn generate_candidate_offloop_snapshot_matches_onloop_store_byte_for_byte() {
    offloop_matches_onloop_under(&Regime::pre_eip27());
}

/// Mainnet / post-EIP-27 twin of the off-loop==on-loop parity test:
/// `reemission = Some(mainnet)` and candidate height 777_300, so both views
/// run the `build_post_eip27_emission_tx` branch (one-input emission tx,
/// per-block reemission-token deduction). A regression in post-EIP-27 emission
/// selection / token deduction / validation would diverge the two builds here
/// — the pre-EIP-27 variant cannot catch it.
#[test]
fn generate_candidate_offloop_snapshot_matches_onloop_post_eip27_byte_for_byte() {
    offloop_matches_onloop_under(&Regime::mainnet_post_eip27());
}

/// Build the candidate both on-loop (live `StateStore` view) and off-loop
/// (committed snapshot) under `regime`, and assert byte-for-byte parity across
/// the work message and the full candidate (header, AVL proof, extension,
/// serialized txs).
fn offloop_matches_onloop_under(regime: &Regime) {
    let (_dir, store, tip) = synced_store(regime);
    let monetary = MonetarySettings::mainnet();

    // On-loop oracle: build straight off the live StateStore view.
    let (oracle_c, oracle_w) = on_loop_build(&store, regime);

    // Off-loop: build off the single committed snapshot the engine uses.
    let snap = store
        .committed_snapshot()
        .expect("snapshot read")
        .expect("committed state present");
    let (snap_c, snap_w, _timings) = generate_candidate(
        &snap,
        MempoolReadSnapshot::empty(),
        &MINER_PK,
        &MonetarySettings::mainnet(),
        regime.reemission.as_ref(),
        &DifficultyParams::mainnet(),
        &[],
    )
    .expect("off-loop generate_candidate ok")
    .expect("off-loop candidate is Some");

    // The candidate must be built for our tip at parent_height + 1.
    assert_eq!(oracle_c.parent_id, tip, "oracle built against the tip");
    assert_eq!(oracle_c.header.height, regime.candidate_height());

    // The parity below is only meaningful if the build was non-trivial:
    // the coinbase (emission) tx is present, the AVL dry-run emitted a real
    // proof, and the interlinks-only extension carries a field. Guard against
    // a future change that silently turns these into empty-vector comparisons.
    assert!(
        !oracle_c.transactions.is_empty(),
        "candidate must carry the coinbase emission tx",
    );
    assert!(
        !oracle_c.ad_proof_bytes.is_empty(),
        "candidate dry-run must produce non-empty AVL proof bytes",
    );
    assert!(
        !oracle_c.extension_fields.is_empty(),
        "candidate extension must carry interlinks fields",
    );

    // Discriminating check that the post-EIP-27 branch actually ran (not the
    // pre-EIP-27 fallback): the coinbase tx's emission output keeps the
    // NFT + reduced reemission stash (2 tokens), and the miner output takes
    // the per-block reemission share (1 token of 12 ERG at h=777_300). A
    // regression that silently selected the pre-EIP-27 path would leave the
    // coinbase token-free and fail here before the parity asserts.
    if let Some(reem) = regime.reemission.as_ref() {
        let coinbase = &oracle_c.transactions[0];
        assert_eq!(
            coinbase.inputs.len(),
            1,
            "post-EIP-27 coinbase consumes exactly the emission box",
        );
        assert_eq!(
            coinbase.output_candidates[0].tokens.len(),
            2,
            "post-EIP-27 emission output keeps NFT + reduced reemission stash",
        );
        let reem_share = ergo_mining::reemission::reemission_for_height(
            regime.candidate_height(),
            &monetary,
            reem,
        );
        let miner_tokens = &coinbase.output_candidates[1].tokens;
        assert_eq!(
            miner_tokens.len(),
            1,
            "post-EIP-27 miner output takes one reemission-token entry",
        );
        assert_eq!(
            miner_tokens[0].token_id, reem.reemission_token_id,
            "miner reemission token id must match the chain spec",
        );
        assert_eq!(
            miner_tokens[0].amount, reem_share,
            "miner reemission share must equal reemission_for_height",
        );
    }

    // WorkMessage parity.
    assert_eq!(snap_w.msg, oracle_w.msg, "work msg must match");
    assert_eq!(snap_w.target, oracle_w.target, "work target must match");
    assert_eq!(snap_w.height, oracle_w.height, "work height must match");
    assert_eq!(snap_w.pk, oracle_w.pk, "work pk must match");

    // Candidate parity at the full-block level.
    assert_eq!(snap_c.parent_id, oracle_c.parent_id, "parent_id must match");
    assert_eq!(
        serialize_header(&snap_c.header).unwrap().0,
        serialize_header(&oracle_c.header).unwrap().0,
        "candidate header bytes must match",
    );
    assert_eq!(
        snap_c.ad_proof_bytes, oracle_c.ad_proof_bytes,
        "ad_proof_bytes must match",
    );
    assert_eq!(
        snap_c.extension_fields, oracle_c.extension_fields,
        "extension_fields must match",
    );
    assert_eq!(
        serialize_txs(&snap_c.transactions),
        serialize_txs(&oracle_c.transactions),
        "serialized candidate transactions must match",
    );
}
