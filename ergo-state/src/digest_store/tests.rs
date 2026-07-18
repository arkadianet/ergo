//! Unit tests for the Mode 5 [`super::DigestStateStore`] backend —
//! open/consistency shapes, apply/rollback atomicity, voted-params
//! guards. Moved verbatim from the former inline `mod tests` block of
//! `digest_store.rs`.

#![cfg(test)]

use super::*;
use crate::backend::{ChainStateRead, HeaderSectionStore};
use crate::chain::HeaderAvailability;
use ergo_validation::scala_launch;
use redb::ReadableTable;
use std::path::Path;
use tempfile::tempdir;

// ----- helpers -----

/// Test voting cadence with a short epoch length (2). Heights
/// 2, 4, 6, … are epoch boundaries; 1, 3, 5, … are not — letting
/// the voted-params boundary guard be exercised on both sides
/// without mainnet's 1024-block epoch.
fn test_voting() -> ergo_chain_spec::VotingParams {
    ergo_chain_spec::VotingParams {
        voting_length: 2,
        ..ergo_chain_spec::VotingParams::mainnet()
    }
}

fn open_at(dir: &Path) -> DigestStateStore {
    let path = dir.join("digest_state.redb");
    open_at_path(&path)
}

/// Synthetic genesis digest for the unit tests below. The synth
/// apply/rollback helpers fabricate arbitrary digests and expect
/// rollback-to-0 to restore this fixed height-0 value, so the tests
/// seed the store with it rather than a real network digest. Equal
/// to `EMPTY_AVL_DIGEST` so the historical `== EMPTY_AVL_DIGEST`
/// assertions read naturally as "back at the genesis seed".
const TEST_GENESIS_DIGEST: [u8; 33] = EMPTY_AVL_DIGEST;

fn open_at_path(db_path: &Path) -> DigestStateStore {
    DigestStateStore::open(db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect("DigestStateStore::open")
}

fn synth_digest(seed: u32) -> [u8; 33] {
    let mut out = [0u8; 33];
    let seed_bytes = seed.to_be_bytes();
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed_bytes[i % 4].wrapping_add(i as u8 + 1);
    }
    out
}

fn synth_header_id(seed: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    let seed_bytes = seed.to_be_bytes();
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed_bytes[i % 4] ^ (i as u8);
    }
    out
}

/// Synth ChainStateMeta at height `h` — header_id, score, and
/// full-block-id derived from `h`. best_header and
/// best_full_block both point at the same value (no fork in
/// these tests).
fn synth_chain_state(h: u32) -> ChainStateMeta {
    let id = synth_header_id(h);
    let score = (h as u64).to_be_bytes().to_vec();
    ChainStateMeta {
        best_header_id: id,
        best_header_height: h,
        best_header_score: score,
        best_full_block_id: id,
        best_full_block_height: h,
        header_availability: HeaderAvailability::Dense,
    }
}

/// Serialized v2 header committing `state_root`, keyed (by the caller)
/// under `synth_header_id(h)`. The open/rollback root-anchor reads only
/// `state_root`, so the other fields are plausible filler; the bytes
/// must round-trip through `read_header`, which a v2 header with an
/// empty `unparsed_bytes` and a stored (unvalidated) group element does
/// (see `ergo_ser::header::tests::header_v2_roundtrips`).
fn synth_header_bytes(h: u32, state_root: [u8; 33]) -> Vec<u8> {
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{serialize_header, Header};
    let parent_id = if h <= 1 {
        [0u8; 32]
    } else {
        synth_header_id(h - 1)
    };
    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent_id),
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        state_root: ADDigest::from_bytes(state_root),
        transactions_root: Digest32::from_bytes([0u8; 32]),
        timestamp: 1_700_000_000,
        n_bits: 0x1d00_ffff,
        height: h,
        extension_root: Digest32::from_bytes([0u8; 32]),
        votes: [0u8; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0xAA; 8],
        },
    };
    let (bytes, _) = serialize_header(&header).expect("serialize_header");
    bytes
}

/// Store the tip header the open/rollback root-anchor will check, then
/// apply the digest block through the raw seam. The header's
/// `state_root` is the committed root, keyed by the chain-state's
/// `best_full_block_id`, so a later reopen or rollback to this tip
/// finds a header its stored root reconciles against. `apply_synth` is
/// the common (synth id, no voted-params) case; tests that drive a
/// custom chain-state or a voted-params row call this directly.
fn apply_digest_with_header(
    store: &mut DigestStateStore,
    root: [u8; 33],
    chain_state: ChainStateMeta,
    voted: Option<ActiveProtocolParameters>,
) {
    let height = chain_state.best_full_block_height;
    let header_bytes = synth_header_bytes(height, root);
    HeaderSectionStore::store_header(store, &chain_state.best_full_block_id, &header_bytes)
        .expect("store tip header");
    store
        .apply_block_digest(root, chain_state, voted)
        .unwrap_or_else(|e| panic!("apply at height {height}: {e}"));
}

fn apply_synth(store: &mut DigestStateStore, h: u32) {
    apply_digest_with_header(store, synth_digest(h), synth_chain_state(h), None);
}

// ----- happy path -----

#[test]
fn fresh_open_initializes_to_genesis() {
    let tmp = tempdir().expect("tempdir");
    let store = open_at(tmp.path());
    assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
    assert_eq!(store.height(), 0);
    assert_eq!(store.chain_state().best_header_height, 0);
    assert_eq!(store.chain_state().best_header_id, [0u8; 32]);
}

#[test]
fn fresh_open_seeds_the_supplied_genesis_digest() {
    // The fresh-store root is whatever genesis digest the network
    // supplies, NOT the all-zero sentinel. Seed with mainnet's real
    // genesis root and confirm the store boots with it — this is the
    // value Mode 5 verifies block 1 against.
    let mainnet_genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
    assert_ne!(mainnet_genesis, EMPTY_AVL_DIGEST);
    let tmp = tempdir().expect("tempdir");
    let path = tmp.path().join("digest_state.redb");
    let store = DigestStateStore::open(&path, scala_launch(), test_voting(), mainnet_genesis)
        .expect("open");
    assert_eq!(store.root_digest(), mainnet_genesis);
    assert_eq!(store.height(), 0);
}

#[test]
fn rollback_to_genesis_restores_supplied_genesis_digest() {
    // After applying synth blocks on a store seeded with a real
    // genesis digest, rollback-to-0 must restore exactly that
    // digest — DIGEST_HISTORY[0] holds the genesis root.
    let mainnet_genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
    let tmp = tempdir().expect("tempdir");
    let path = tmp.path().join("digest_state.redb");
    let mut store = DigestStateStore::open(&path, scala_launch(), test_voting(), mainnet_genesis)
        .expect("open");
    for h in 1u32..=3 {
        apply_synth(&mut store, h);
    }
    store.rollback_to(0).expect("rollback to genesis");
    assert_eq!(store.root_digest(), mainnet_genesis);
    assert_eq!(store.height(), 0);
}

#[test]
fn fresh_genesis_matches_crate_canonical_empty_state() {
    // The digest backend's genesis must be byte-identical to the
    // crate-wide `ChainState::empty()` — notably
    // `best_header_score == [0]`, NOT an empty vec. A divergence
    // would make the two backends disagree on the pre-genesis
    // score encoding.
    let tmp = tempdir().expect("tempdir");
    let store = open_at(tmp.path());
    let canonical = crate::chain::ChainState::empty().to_persisted();
    assert_eq!(
        store.chain_state().best_header_score,
        canonical.best_header_score,
    );
    assert_eq!(store.chain_state().best_header_score, vec![0]);
    assert_eq!(store.chain_state().best_header_id, canonical.best_header_id);
    assert_eq!(
        store.chain_state().best_full_block_height,
        canonical.best_full_block_height,
    );
}

#[test]
fn apply_advances_root_chain_state_and_height() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    apply_synth(&mut store, 1);
    assert_eq!(store.root_digest(), synth_digest(1));
    assert_eq!(store.height(), 1);
    assert_eq!(store.chain_state().best_full_block_id, synth_header_id(1));
}

// ----- round-trips -----

#[test]
fn apply_persists_across_reopen() {
    let tmp = tempdir().expect("tempdir");
    {
        let mut store = open_at(tmp.path());
        apply_synth(&mut store, 1);
    }
    let store = open_at(tmp.path());
    assert_eq!(store.root_digest(), synth_digest(1));
    assert_eq!(store.height(), 1);
    assert_eq!(store.chain_state().best_full_block_id, synth_header_id(1));
}

#[test]
fn sequential_applies_advance_through_multiple_heights() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    for h in 1u32..=5 {
        apply_synth(&mut store, h);
        assert_eq!(store.height(), h);
        assert_eq!(store.root_digest(), synth_digest(h));
    }
}

#[test]
fn rollback_restores_root_chain_state_at_target_height() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    for h in 1u32..=5 {
        apply_synth(&mut store, h);
    }
    store.rollback_to(3).expect("rollback");
    assert_eq!(store.height(), 3);
    assert_eq!(store.root_digest(), synth_digest(3));
    assert_eq!(store.chain_state().best_full_block_id, synth_header_id(3));
    assert_eq!(
        store.chain_state().best_header_score,
        (3u64).to_be_bytes().to_vec(),
    );
}

#[test]
fn rollback_to_genesis_restores_empty_state() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    for h in 1u32..=3 {
        apply_synth(&mut store, h);
    }
    store.rollback_to(0).expect("rollback to genesis");
    assert_eq!(store.height(), 0);
    assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
    assert_eq!(store.chain_state().best_header_height, 0);
    // Genesis restores the canonical empty-state score ([0]),
    // matching `ChainState::empty()`.
    assert_eq!(store.chain_state().best_header_score, vec![0]);
}

#[test]
fn rollback_to_genesis_then_reopen_boots_clean() {
    // The genesis-after-rollback on-disk shape: chain_state
    // present at height 0, root_digest present (= the genesis
    // seed), CHAIN_INDEX empty (rollback truncated all
    // applied-height rows). `read_consistent_state` must accept
    // this as a valid genesis state, NOT reject it as a torn write.
    let tmp = tempdir().expect("tempdir");
    {
        let mut store = open_at(tmp.path());
        for h in 1u32..=3 {
            apply_synth(&mut store, h);
        }
        store.rollback_to(0).expect("rollback to genesis");
    }
    let store = open_at(tmp.path());
    assert_eq!(store.height(), 0);
    assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
    assert_eq!(store.chain_state().best_header_score, vec![0]);
}

#[test]
fn rollback_persists_across_reopen() {
    let tmp = tempdir().expect("tempdir");
    {
        let mut store = open_at(tmp.path());
        for h in 1u32..=4 {
            apply_synth(&mut store, h);
        }
        store.rollback_to(2).expect("rollback");
    }
    let store = open_at(tmp.path());
    assert_eq!(store.height(), 2);
    assert_eq!(store.root_digest(), synth_digest(2));
    assert_eq!(store.chain_state().best_full_block_id, synth_header_id(2));
}

#[test]
fn rollback_then_reapply_reaches_same_tip_as_uninterrupted_path() {
    let tmp_straight = tempdir().expect("tempdir");
    let tmp_redo = tempdir().expect("tempdir");

    let mut straight = open_at(tmp_straight.path());
    for h in 1u32..=5 {
        apply_synth(&mut straight, h);
    }
    let straight_tip = (
        straight.root_digest(),
        straight.chain_state().best_full_block_id,
        straight.chain_state().best_full_block_height,
    );

    let mut redo = open_at(tmp_redo.path());
    for h in 1u32..=5 {
        apply_synth(&mut redo, h);
    }
    redo.rollback_to(2).expect("redo rollback");
    for h in 3u32..=5 {
        apply_synth(&mut redo, h);
    }
    let redo_tip = (
        redo.root_digest(),
        redo.chain_state().best_full_block_id,
        redo.chain_state().best_full_block_height,
    );
    assert_eq!(redo_tip, straight_tip);
}

// ----- error paths -----

#[test]
fn apply_out_of_order_rejected() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    let err = store
        .apply_block_digest(synth_digest(2), synth_chain_state(2), None)
        .expect_err("must reject out-of-order apply");
    let msg = format!("{err}");
    assert!(msg.contains("out of order"), "msg={msg}");
    assert!(msg.contains("expected next height 1"), "msg={msg}");
    assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
    assert_eq!(store.height(), 0);
}

#[test]
fn rollback_beyond_tip_rejected() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    apply_synth(&mut store, 1);
    let err = store
        .rollback_to(5)
        .expect_err("must reject rollback beyond tip");
    let msg = format!("{err}");
    assert!(msg.contains("rollback target 5"), "msg={msg}");
    assert!(msg.contains("current tip 1"), "msg={msg}");
}

#[test]
fn rollback_to_current_height_is_noop() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    for h in 1u32..=3 {
        apply_synth(&mut store, h);
    }
    let before = (store.root_digest(), store.height());
    store.rollback_to(3).expect("noop");
    assert_eq!((store.root_digest(), store.height()), before);
}

#[test]
fn open_rejects_half_populated_store() {
    // Torn shape: STATE_META["root_digest"] present but
    // CHAIN_STATE_META["chain_state"] absent (and chain_state is
    // the authoritative anchor). Mirrors an external `redb`
    // mutation or a torn write.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "torn-write").expect("open");
        crate::store::verify_or_init_state_type_inner(&db, DIGEST_VERIFIER_STATE_TYPE)
            .expect("stamp");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut t = txn.open_table(crate::store::STATE_META).expect("open");
            t.insert(ROOT_DIGEST_KEY, &synth_digest(7)[..])
                .expect("insert");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("torn write must reject");
    let msg = format!("{err}");
    assert!(msg.contains("chain_state"), "msg={msg}");
}

#[test]
fn open_rejects_tip_id_split_brain() {
    // chain_state.best_full_block_height matches the CHAIN_INDEX
    // tip height, but the header id stored at that tip differs
    // from chain_state.best_full_block_id. The atomic commit
    // writes them together, so a divergence is corruption — open
    // must reject rather than boot a split-brain tip.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        apply_synth(&mut store, 1);
    }
    // Corrupt CHAIN_INDEX[1] to a different id than
    // chain_state.best_full_block_id (= synth_header_id(1)).
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut idx = txn
                .open_table(crate::store::CHAIN_INDEX)
                .expect("open chain_index");
            idx.insert(1u64, &[0xFFu8; 32][..])
                .expect("overwrite tip id");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("split-brain tip must reject");
    let msg = format!("{err}");
    assert!(msg.contains("split-brain"), "msg={msg}");
}

#[test]
fn open_rejects_applied_store_with_missing_rollback_substrate() {
    // A torn write commits chain_state@h + root + matching tip
    // but loses the history rows (the rollback substrate). The
    // old open path would boot "healthy" and only fail at the
    // first reorg; open must reject so the operator sees it now.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=2 {
            apply_synth(&mut store, h);
        }
    }
    // Drop the parent-height history rows (h-1 = 1) from both
    // ledgers, simulating a torn write / external mutation.
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
            dh.remove(1u64).expect("remove digest_history[1]");
            let mut ch = txn
                .open_table(CHAIN_STATE_HISTORY)
                .expect("open chain_state_history");
            ch.remove(1u64).expect("remove chain_state_history[1]");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("missing rollback substrate must reject");
    let msg = format!("{err}");
    assert!(msg.contains("rollback substrate missing"), "msg={msg}",);
}

#[test]
fn open_rejects_stored_root_diverging_from_tip_header() {
    // The integrity check the genesis seed displaced, restored as a
    // header anchor: an applied tip's stored root must equal the tip
    // header's committed `state_root`. Mutating `STATE_META[root_digest]`
    // to any other value — here the genesis digest, exactly the case a
    // bare "root == genesis ⇒ empty block" heuristic would wave through
    // — is a torn write the anchor now rejects at open.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        apply_synth(&mut store, 1); // header[1].state_root = synth_digest(1)
    }
    // Rewrite ONLY the stored root to the genesis seed; header[1] still
    // commits synth_digest(1), so root and header now disagree.
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "rewrite").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut meta = txn.open_table(crate::store::STATE_META).expect("open");
            meta.insert(ROOT_DIGEST_KEY, &TEST_GENESIS_DIGEST[..])
                .expect("rewrite root to genesis seed");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("root diverging from the tip header's state_root must reject");
    let msg = format!("{err}");
    assert!(msg.contains("disagrees with tip header"), "msg={msg}");
}

#[test]
fn open_accepts_applied_root_matching_tip_header() {
    // The legitimate empty-block shape: a height-1 block that changed
    // no boxes leaves the root at the genesis seed AND its header
    // commits that same genesis digest as `state_root`. Because the
    // stored root agrees with the header anchor, open accepts it — the
    // anchor rejects root/header divergence, never the genesis value
    // itself.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        // Empty block at height 1: header commits the genesis root and
        // the applied root stays at the genesis seed.
        let header_bytes = synth_header_bytes(1, TEST_GENESIS_DIGEST);
        HeaderSectionStore::store_header(&store, &synth_header_id(1), &header_bytes)
            .expect("store empty-block tip header");
        store
            .apply_block_digest(TEST_GENESIS_DIGEST, synth_chain_state(1), None)
            .expect("apply empty block at height 1");
    }
    let store =
        DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
            .expect("applied root matching the tip header must be accepted");
    assert_eq!(store.height(), 1);
    assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
}

#[test]
fn open_rejects_applied_store_with_wrong_genesis_digest() {
    // Cross-network mis-open guard: a committed store carries its
    // network's genesis digest in DIGEST_HISTORY[0]. Reopening it
    // with a DIFFERENT supplied genesis digest must fail loud at
    // open — not boot clean and only diverge at a deep rollback.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        // Seed + apply with the real mainnet genesis digest.
        let genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
        let mut store =
            DigestStateStore::open(&db_path, scala_launch(), test_voting(), genesis).expect("open");
        for h in 1u32..=2 {
            apply_synth(&mut store, h);
        }
    }
    // Reopen with a foreign genesis digest (testnet's).
    let foreign = ergo_chain_spec::GenesisParams::testnet().state_digest;
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), foreign)
        .expect_err("wrong-network genesis digest must reject at open");
    let msg = format!("{err}");
    assert!(msg.contains("wrong-network or corrupted dir"), "msg={msg}");
}

#[test]
fn fresh_open_rejects_cross_network_reopen_before_first_apply() {
    // A NEVER-APPLIED dir persists no genesis digest (the root lives
    // in memory until the first apply writes DIGEST_HISTORY[0]), so
    // the committed-store digest guard cannot fire here. The one row
    // the first fresh open DID persist is the genesis VOTED_PARAMS[0]
    // launch baseline. Reopening the same fresh dir for a different
    // network — distinct launch params — must reject, not silently
    // reuse the first network's protocol baseline against the second
    // network's genesis root.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");

    // Two distinct per-network launch baselines. `scala_launch()` is
    // network A; a single-field tweak stands in for network B's
    // distinct launch parameters (mainnet/testnet differ in real
    // cost tables, so the equality guard is a sound discriminator).
    let launch_a = scala_launch();
    let mut launch_b = scala_launch();
    launch_b.storage_fee_factor += 1;
    assert_ne!(launch_a, launch_b, "the two launches must differ");

    // First fresh open seeds VOTED_PARAMS[0] from launch A. No apply.
    {
        let store = DigestStateStore::open(&db_path, launch_a, test_voting(), TEST_GENESIS_DIGEST)
            .expect("first fresh open seeds launch A");
        assert_eq!(store.height(), 0, "still fresh — never applied");
    }

    // Reopen the same fresh dir with network B's launch — must reject.
    let err = DigestStateStore::open(&db_path, launch_b, test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("cross-network fresh reopen must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("different network"),
        "rejection must name the cross-network cause: {msg}",
    );

    // Reopening with the SAME launch (A) is fine — idempotent.
    DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect("same-network reopen of a fresh dir must succeed");
}

#[test]
fn open_rejects_deep_history_hole_below_tip() {
    // A hole BELOW the immediate parent (h-1) — the case a
    // presence-only check on h-1 would miss. Apply to height 5,
    // punch out history[2], reopen. The density check must catch
    // it (len != last+1) so a deep reorg never hits a missing row
    // at runtime.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=5 {
            apply_synth(&mut store, h);
        }
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
            dh.remove(2u64).expect("remove digest_history[2]");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("deep history hole must reject");
    let msg = format!("{err}");
    assert!(msg.contains("holes"), "msg={msg}");
}

#[test]
fn open_rejects_chain_index_hole_below_tip() {
    // CHAIN_INDEX is a shared load-bearing height→block-id table.
    // A hole below the tip (the tip alone matches chain_state)
    // must be caught at open, not surface in a later point lookup
    // or reorg walk.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=5 {
            apply_synth(&mut store, h);
        }
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut idx = txn
                .open_table(crate::store::CHAIN_INDEX)
                .expect("open chain_index");
            idx.remove(3u64).expect("punch hole at chain_index[3]");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("chain_index hole must reject");
    let msg = format!("{err}");
    assert!(msg.contains("chain_index not dense"), "msg={msg}");
}

#[test]
fn applied_digest_dir_with_lost_sentinel_not_restampable_as_utxo() {
    // Defense-in-depth: if a digest-verifier dir loses its
    // `data_dir_state_type` sentinel to partial corruption, the
    // on-disk markers (history ledger / root_digest key) must
    // still prevent it from being silently re-stamped as the
    // UTXO backend.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        apply_synth(&mut store, 1);
    }
    // Delete only the sentinel key, leaving the digest data intact.
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut meta = txn
                .open_table(crate::store::CHAIN_STATE_META)
                .expect("open chain_state_meta");
            meta.remove(crate::store::DATA_DIR_STATE_TYPE_KEY)
                .expect("remove sentinel");
        }
        txn.commit().expect("commit");
    }
    // Re-stamping as utxo must be refused — the digest markers
    // (history ledger / root_digest key) are still on disk. Test
    // the stamp guard directly rather than through StateStore::open
    // so we exercise the misopen logic, not StateStore's
    // reconstruction of a frankenstein dir.
    let db = crate::redb_util::open_with_repair_logging(&db_path, "reopen").expect("reopen");
    let err = crate::store::verify_or_init_state_type_inner(&db, "utxo")
        .expect_err("utxo re-stamp of a digest-verifier dir must reject");
    let msg = format!("{err}");
    assert!(msg.contains("digest-verifier"), "msg={msg}");
    assert!(msg.contains("utxo"), "msg={msg}");
}

#[test]
fn frankenstore_with_both_schemas_and_no_sentinel_hard_fails() {
    // A dir carrying BOTH a UTXO arena row AND digest-verifier
    // markers, with no sentinel, is corrupt — the stamp guard
    // must refuse to infer either backend rather than silently
    // pick UTXO.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        apply_synth(&mut store, 1); // writes digest markers
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            // Inject an AVL_NODES row (UTXO marker) and delete the
            // sentinel — now both schemas appear present.
            let mut avl = txn.open_table(crate::store::AVL_NODES).expect("open avl");
            avl.insert(0u64, &[0x01u8, 0x02][..])
                .expect("inject avl row");
            let mut meta = txn
                .open_table(crate::store::CHAIN_STATE_META)
                .expect("open chain_state_meta");
            meta.remove(crate::store::DATA_DIR_STATE_TYPE_KEY)
                .expect("remove sentinel");
        }
        txn.commit().expect("commit");
    }
    let db = crate::redb_util::open_with_repair_logging(&db_path, "reopen").expect("reopen");
    let err = crate::store::verify_or_init_state_type_inner(&db, "utxo")
        .expect_err("frankenstore must hard-fail");
    let msg = format!("{err}");
    assert!(msg.contains("incompatible schemas"), "msg={msg}");
}

#[test]
fn rollback_rejects_history_row_with_wrong_height_in_body() {
    // A CHAIN_STATE_HISTORY row that decodes cleanly but encodes
    // the wrong height for its key must be caught at rollback
    // time, before its corrupt payload is written into
    // CHAIN_STATE_META.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=3 {
            apply_synth(&mut store, h);
        }
    }
    // Overwrite CHAIN_STATE_HISTORY[2] with a snapshot that
    // (wrongly) claims height 99.
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let bogus = ChainStateMeta {
                best_header_id: synth_header_id(99),
                best_header_height: 99,
                best_header_score: vec![0x09],
                best_full_block_id: synth_header_id(99),
                best_full_block_height: 99,
                header_availability: HeaderAvailability::Dense,
            };
            let mut ch = txn
                .open_table(CHAIN_STATE_HISTORY)
                .expect("open chain_state_history");
            ch.insert(2u64, bogus.serialize().as_slice())
                .expect("overwrite history[2]");
        }
        txn.commit().expect("commit");
    }
    let mut store = open_at_path(&db_path);
    let err = store
        .rollback_to(2)
        .expect_err("rollback to a corrupt-body snapshot must reject");
    let msg = format!("{err}");
    assert!(msg.contains("body does not match its key"), "msg={msg}");
    // The store's in-memory state must be untouched by the
    // rejected rollback (validation happens before any mutation).
    assert_eq!(store.height(), 3);
}

#[test]
fn rollback_rejects_history_row_with_id_disagreeing_with_chain_index() {
    // A CHAIN_STATE_HISTORY[target] row whose best_full_block_id
    // disagrees with CHAIN_INDEX[target] (the row that becomes
    // the post-rollback tip) must be caught before commit.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=3 {
            apply_synth(&mut store, h);
        }
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            // Right height (2), wrong block id.
            let bogus = ChainStateMeta {
                best_header_id: [0xDDu8; 32],
                best_header_height: 2,
                best_header_score: vec![0x02],
                best_full_block_id: [0xDDu8; 32],
                best_full_block_height: 2,
                header_availability: HeaderAvailability::Dense,
            };
            let mut ch = txn
                .open_table(CHAIN_STATE_HISTORY)
                .expect("open chain_state_history");
            ch.insert(2u64, bogus.serialize().as_slice())
                .expect("overwrite history[2]");
        }
        txn.commit().expect("commit");
    }
    let mut store = open_at_path(&db_path);
    let err = store
        .rollback_to(2)
        .expect_err("id/chain_index disagreement must reject");
    let msg = format!("{err}");
    assert!(msg.contains("disagrees with chain_index"), "msg={msg}");
    assert_eq!(store.height(), 3);
}

#[test]
fn open_rejects_applied_store_missing_genesis_voted_params() {
    // An applied store that lost VOTED_PARAMS[0] must fail loud,
    // NOT silently re-seed — a missing genesis row would let
    // read_latest_at fall back to a later epoch's parameters.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=2 {
            apply_synth(&mut store, h);
        }
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut vp = txn
                .open_table(crate::active_params::VOTED_PARAMS)
                .expect("open voted_params");
            vp.remove(0u64).expect("remove voted_params[0]");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("missing genesis voted_params on applied store must reject");
    let msg = format!("{err}");
    assert!(msg.contains("genesis voted-params row absent"), "msg={msg}",);
}

#[test]
fn divergent_header_and_full_block_pointers_round_trip() {
    // ChainStateMeta carries best_header_* SEPARATE from
    // best_full_block_*, plus a HeaderAvailability tag. The
    // persistence path must round-trip all of them — the synth
    // helper pins both pointers to the same id, so this test
    // exercises the divergent + PoPowSparse shape explicitly.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    let divergent = ChainStateMeta {
        best_header_id: [0xA1u8; 32],
        best_header_height: 9,
        best_header_score: vec![0x07, 0x42],
        best_full_block_id: [0xB2u8; 32],
        best_full_block_height: 1,
        header_availability: HeaderAvailability::PoPowSparse {
            dense_from_height: 4,
            proof_suffix_height: 9,
        },
    };
    {
        let mut store = open_at_path(&db_path);
        apply_digest_with_header(&mut store, synth_digest(1), divergent, None);
    }
    let store = open_at_path(&db_path);
    let cs = store.chain_state();
    assert_eq!(cs.best_header_id, [0xA1u8; 32]);
    assert_eq!(cs.best_header_height, 9);
    assert_eq!(cs.best_header_score, vec![0x07, 0x42]);
    assert_eq!(cs.best_full_block_id, [0xB2u8; 32]);
    assert_eq!(cs.best_full_block_height, 1);
    assert_eq!(
        cs.header_availability,
        HeaderAvailability::PoPowSparse {
            dense_from_height: 4,
            proof_suffix_height: 9,
        },
    );
}

// ----- oracle parity (state-type stamp shared with StateStore) -----

#[test]
fn reopening_a_utxo_stamped_dir_as_digest_verifier_is_rejected() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("state.redb");
    {
        let store = crate::store::StateStore::open(&db_path).expect("StateStore::open");
        store.verify_or_init_state_type("utxo").expect("stamp utxo");
        drop(store);
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("digest-verifier open of utxo dir must reject");
    let msg = format!("{err}");
    assert!(msg.contains("state_type"), "msg={msg}");
    assert!(
        msg.contains("digest-verifier") && msg.contains("utxo"),
        "rejection must name both backends: {msg}",
    );
}

#[test]
fn reopening_a_mode_6_digest_dir_as_digest_verifier_is_rejected() {
    // The collision case: a Mode 6 dir stamps "digest"
    // (StateStore headers-only schema). Mode 5's DigestStateStore
    // stamps "digest-verifier" (a distinct, incompatible schema).
    // Opening a Mode 6 dir as Mode 5 must REJECT — otherwise the
    // digest chain would silently boot against an empty
    // StateStore-shaped dir.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("state.redb");
    {
        let store = crate::store::StateStore::open(&db_path).expect("StateStore::open");
        store
            .verify_or_init_state_type("digest")
            .expect("stamp digest (Mode 6)");
        drop(store);
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("Mode 6 digest dir opened as Mode 5 must reject");
    let msg = format!("{err}");
    assert!(msg.contains("state_type"), "msg={msg}");
    assert!(
        msg.contains("digest-verifier") && msg.contains("\"digest\""),
        "rejection must distinguish digest vs digest-verifier: {msg}",
    );
}

// ----- atomic-commit invariant -----

#[test]
fn apply_co_commits_voted_params_row() {
    // A co-committed row must land at a real epoch boundary
    // (height 2 under the test cadence of 2) and be keyed to that
    // height. Apply height 1 (no row), then the boundary block at
    // height 2 with `epoch_start_height = 2`.
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    apply_synth(&mut store, 1);
    let mut params = scala_launch();
    params.epoch_start_height = 2;
    apply_digest_with_header(
        &mut store,
        synth_digest(2),
        synth_chain_state(2),
        Some(params),
    );
    drop(store);
    let reopened = open_at(tmp.path());
    assert_eq!(reopened.height(), 2);
    assert_eq!(reopened.root_digest(), synth_digest(2));
    let read = reopened.db.begin_read().expect("begin_read");
    let table = read
        .open_table(crate::active_params::VOTED_PARAMS)
        .expect("open voted_params");
    let row = table.get(2u64).expect("get").expect("row present");
    assert!(
        !row.value().is_empty(),
        "voted_params row must be non-empty"
    );
}

#[test]
fn apply_rejects_voted_params_at_non_epoch_boundary() {
    // A voted-params row at a non-epoch-start height (1 is not a
    // multiple of the test cadence 2) is a caller bug — reject it
    // before persisting, matching the Mode 1 guard.
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    let mut params = scala_launch();
    params.epoch_start_height = 1;
    let err = store
        .apply_block_digest(synth_digest(1), synth_chain_state(1), Some(params))
        .expect_err("voted_params at non-boundary height must reject");
    let msg = format!("{err}");
    assert!(msg.contains("non-epoch-start height"), "msg={msg}");
    assert_eq!(store.height(), 0);
}

#[test]
fn apply_rejects_voted_params_row_keyed_to_wrong_height() {
    // At a real boundary (height 2), a row whose
    // epoch_start_height is not that height is a caller bug that
    // would persist consensus drift — reject it.
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    apply_synth(&mut store, 1);
    let mut params = scala_launch();
    params.epoch_start_height = 1024; // applying boundary height 2
    let err = store
        .apply_block_digest(synth_digest(2), synth_chain_state(2), Some(params))
        .expect_err("epoch_start_height != block height must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("epoch_start_height != block height"),
        "msg={msg}",
    );
    // The rejected apply must not have advanced the store past 1.
    assert_eq!(store.height(), 1);
}

#[test]
fn rollback_prunes_voted_params_rows_above_target() {
    // Epoch-boundary reorg invariant: params rows above the
    // rollback target must not survive. Boundary blocks at
    // heights 2 and 4 (test cadence 2) each co-commit a row;
    // odd heights carry none. Rolling back to height 1 must
    // prune the rows at 2 and 4.
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    for h in 1u32..=4 {
        let voted = if h.is_multiple_of(2) {
            let mut params = scala_launch();
            params.epoch_start_height = h;
            Some(params)
        } else {
            None
        };
        apply_digest_with_header(&mut store, synth_digest(h), synth_chain_state(h), voted);
    }
    // Pre-rollback: boundary rows at 2 and 4 are present.
    {
        let read = store.db.begin_read().expect("begin_read");
        let t = read
            .open_table(crate::active_params::VOTED_PARAMS)
            .expect("open");
        assert!(t.get(2u64).expect("get").is_some());
        assert!(t.get(4u64).expect("get").is_some());
    }
    store.rollback_to(1).expect("rollback");
    // After rollback to height 1: rows above 1 must be pruned.
    let read = store.db.begin_read().expect("begin_read");
    let t = read
        .open_table(crate::active_params::VOTED_PARAMS)
        .expect("open");
    assert!(
        t.get(2u64).expect("get").is_none(),
        "row at height 2 must be pruned (2 > target=1)",
    );
    assert!(
        t.get(4u64).expect("get").is_none(),
        "row at height 4 must be pruned",
    );
    // Genesis (0) survives.
    assert!(
        t.get(0u64).expect("get").is_some(),
        "genesis voted_params row must survive rollback",
    );
}

#[test]
fn open_rejects_orphan_history_with_no_chain_state() {
    // A torn write that lost chain_state / root / chain_index but
    // left orphan history rows must NOT be classified fresh —
    // booting as genesis would silently discard an applied chain.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=2 {
            apply_synth(&mut store, h);
        }
    }
    // Wipe the authoritative anchors but leave the history
    // ledgers intact.
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut meta = txn.open_table(crate::store::STATE_META).expect("open");
            meta.remove(ROOT_DIGEST_KEY).expect("remove root_digest");
            let mut cs = txn
                .open_table(crate::store::CHAIN_STATE_META)
                .expect("open chain_state_meta");
            cs.remove(CHAIN_STATE_KEY).expect("remove chain_state");
            let mut idx = txn
                .open_table(crate::store::CHAIN_INDEX)
                .expect("open chain_index");
            let keys: Vec<u64> = idx
                .iter()
                .expect("iter")
                .filter_map(|r| r.ok().map(|(k, _)| k.value()))
                .collect();
            for k in keys {
                idx.remove(k).expect("remove chain_index row");
            }
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("orphan history must reject, not boot fresh");
    let msg = format!("{err}");
    assert!(msg.contains("history_rows=true"), "msg={msg}");
}

#[test]
fn open_rejects_corrupt_genesis_history_root() {
    // digest_history[0] must hold the network's genesis digest. If
    // it is corrupted to any other value, the open-time
    // cross-network guard rejects it before the store is ever
    // handed out — the corrupt genesis substrate can no longer
    // reach a rollback_to(0) at runtime.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=2 {
            apply_synth(&mut store, h);
        }
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
            dh.insert(0u64, &synth_digest(7)[..])
                .expect("corrupt history[0]");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("corrupt genesis history row must reject at open");
    let msg = format!("{err}");
    assert!(msg.contains("wrong-network or corrupted dir"), "msg={msg}");
}

#[test]
fn rollback_to_applied_empty_block_height_with_genesis_root_succeeds() {
    // The empty-block shape: block 1 changed no boxes, so the root at
    // height 1 equals the genesis digest AND header[1] commits that
    // same digest. Rolling back FROM a later tip TO that height must
    // succeed — the restored root agrees with the tip header anchor.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    let mut store = open_at_path(&db_path);
    // Height 1: an empty block whose header commits the genesis root,
    // leaving the applied root at the genesis seed.
    let header_bytes = synth_header_bytes(1, TEST_GENESIS_DIGEST);
    HeaderSectionStore::store_header(&store, &synth_header_id(1), &header_bytes)
        .expect("store empty-block tip header");
    store
        .apply_block_digest(TEST_GENESIS_DIGEST, synth_chain_state(1), None)
        .expect("apply empty block at height 1");
    // Heights 2..=3: normal applies that advance the root.
    for h in 2u32..=3 {
        apply_synth(&mut store, h);
    }
    // Roll back to the empty-block height. digest_history[1] holds the
    // genesis digest and header[1] commits it; this must restore
    // cleanly, not reject.
    store
        .rollback_to(1)
        .expect("rollback to an applied empty-block height must succeed");
    assert_eq!(store.height(), 1);
    assert_eq!(store.root_digest(), TEST_GENESIS_DIGEST);
    assert_eq!(store.chain_state().best_full_block_id, synth_header_id(1));
}

#[test]
fn rollback_to_rejects_restored_root_diverging_from_tip_header() {
    // Symmetric to the open-path anchor: if `DIGEST_HISTORY[target]`
    // is mutated so the restored root no longer matches the target
    // tip header's `state_root`, rollback must refuse to install it
    // live — the same poisoned root open would have rejected.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=3 {
            apply_synth(&mut store, h);
        }
    }
    // Corrupt the height-1 snapshot root to the genesis seed; header[1]
    // still commits synth_digest(1), so a rollback to 1 must reject.
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
            dh.insert(1u64, &TEST_GENESIS_DIGEST[..])
                .expect("corrupt digest_history[1]");
        }
        txn.commit().expect("commit");
    }
    // Reopen succeeds: the TIP (height 3) root + header still agree.
    let mut store =
        DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
            .expect("reopen at an intact tip");
    let err = store
        .rollback_to(1)
        .expect_err("restored root diverging from the tip header must reject");
    let msg = format!("{err}");
    assert!(msg.contains("disagrees with tip header"), "msg={msg}");
}

#[test]
fn open_rejects_applied_tip_with_missing_header() {
    // An applied tip cannot exist without its header — the full block
    // is verified against that header before it commits. A height-1
    // store whose tip header row is absent is therefore corruption,
    // not a benign miss; open must reject it rather than boot a tip it
    // cannot anchor.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        // Apply height 1 through the raw seam WITHOUT storing the tip
        // header, fabricating the absent-header shape.
        store
            .apply_block_digest(synth_digest(1), synth_chain_state(1), None)
            .expect("apply h1 without a tip header");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("applied tip with no stored header must reject at open");
    let msg = format!("{err}");
    assert!(msg.contains("no stored header"), "msg={msg}");
}

#[test]
fn rollback_to_rejects_target_tip_with_missing_header() {
    // The rollback anchor needs the target tip's header to reconcile
    // the restored root. If height 1's header is absent, rolling back
    // to it must reject — the same absent-header corruption the open
    // path catches, surfaced at the reorg seam instead.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    let mut store = open_at_path(&db_path);
    // Height 1 through the raw seam, no header stored.
    store
        .apply_block_digest(synth_digest(1), synth_chain_state(1), None)
        .expect("apply h1 without a tip header");
    // Heights 2..=3 with headers, so the live tip is anchorable and the
    // rollback's other cross-checks pass before it reaches the anchor.
    for h in 2u32..=3 {
        apply_synth(&mut store, h);
    }
    let err = store
        .rollback_to(1)
        .expect_err("rollback to a target whose tip header is absent must reject");
    let msg = format!("{err}");
    assert!(msg.contains("no stored header"), "msg={msg}");
}

#[test]
fn lost_sentinel_with_only_chain_state_history_still_detected_as_digest_verifier() {
    // R8-2: the marker check must treat CHAIN_STATE_HISTORY as a
    // digest-verifier marker too. A torn write that loses the
    // sentinel, DIGEST_HISTORY, and root_digest but keeps
    // CHAIN_STATE_HISTORY must still NOT be re-stampable as utxo.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        apply_synth(&mut store, 1);
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            // Strip sentinel, DIGEST_HISTORY, and root_digest;
            // leave CHAIN_STATE_HISTORY as the sole marker.
            let mut cs = txn
                .open_table(crate::store::CHAIN_STATE_META)
                .expect("open chain_state_meta");
            cs.remove(crate::store::DATA_DIR_STATE_TYPE_KEY)
                .expect("remove sentinel");
            let mut dh = txn.open_table(DIGEST_HISTORY).expect("open digest_history");
            let keys: Vec<u64> = dh
                .iter()
                .expect("iter")
                .filter_map(|r| r.ok().map(|(k, _)| k.value()))
                .collect();
            for k in keys {
                dh.remove(k).expect("remove digest_history row");
            }
            let mut meta = txn.open_table(crate::store::STATE_META).expect("open");
            meta.remove(ROOT_DIGEST_KEY).expect("remove root_digest");
        }
        txn.commit().expect("commit");
    }
    let db = crate::redb_util::open_with_repair_logging(&db_path, "reopen").expect("reopen");
    let err = crate::store::verify_or_init_state_type_inner(&db, "utxo")
        .expect_err("CHAIN_STATE_HISTORY alone must still block utxo re-stamp");
    let msg = format!("{err}");
    assert!(msg.contains("digest-verifier"), "msg={msg}");
    assert!(msg.contains("utxo"), "msg={msg}");
}

#[test]
fn apply_rejects_chain_state_with_header_behind_full_block() {
    // best_header_height must lead or equal best_full_block_height.
    // A chain state with the header tip behind the full-block tip
    // is a nonsense fork-choice view — reject at the seam.
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    let bad = ChainStateMeta {
        best_header_id: synth_header_id(1),
        best_header_height: 0, // behind best_full_block_height = 1
        best_header_score: vec![0x01],
        best_full_block_id: synth_header_id(1),
        best_full_block_height: 1,
        header_availability: HeaderAvailability::Dense,
    };
    let err = store
        .apply_block_digest(synth_digest(1), bad, None)
        .expect_err("header behind full block must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("best_header_height < best_full_block_height"),
        "msg={msg}",
    );
    assert_eq!(store.height(), 0);
}

#[test]
fn open_rejects_orphan_voted_params_row_above_tip() {
    // A voted-params row above the committed tip (here, on a
    // fresh store whose tip is 0) is an orphan from a torn write
    // — reject at open rather than let read_latest_at key off it.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    // First open seeds VOTED_PARAMS[0]; store stays fresh (no apply).
    drop(open_at_path(&db_path));
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut vp = txn
                .open_table(crate::active_params::VOTED_PARAMS)
                .expect("open voted_params");
            // Inject a row at height 5 — no chain has been applied.
            let mut p = scala_launch();
            p.epoch_start_height = 5;
            vp.insert(5u64, p.serialize().expect("serialize").as_slice())
                .expect("inject orphan row");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("orphan voted_params row above tip must reject");
    let msg = format!("{err}");
    assert!(msg.contains("not a valid epoch boundary"), "msg={msg}");
}

#[test]
fn open_rejects_off_boundary_voted_params_row() {
    // A voted-params row at a non-epoch-boundary height (3 is not
    // a multiple of the test cadence 2) is off-boundary garbage.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=4 {
            apply_synth(&mut store, h);
        }
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut vp = txn
                .open_table(crate::active_params::VOTED_PARAMS)
                .expect("open voted_params");
            let mut p = scala_launch();
            p.epoch_start_height = 3; // 3 % 2 != 0
            vp.insert(3u64, p.serialize().expect("serialize").as_slice())
                .expect("inject off-boundary row");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("off-boundary voted_params row must reject");
    let msg = format!("{err}");
    assert!(msg.contains("not a valid epoch boundary"), "msg={msg}");
}

#[test]
fn failed_misopen_does_not_poison_state_type_sentinel() {
    // A sentinel-less dir carrying a StateStore-shaped
    // chain_state (no root_digest, no digest history) opened as
    // Mode 5 must fail at shape validation WITHOUT writing the
    // `data_dir_state_type` sentinel — otherwise the mis-open
    // would re-classify the dir as digest-verifier on disk.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        // Write only a genesis chain_state row — no sentinel, no
        // root_digest, no history ledgers (a torn / foreign shape).
        let db = crate::redb_util::open_with_repair_logging(&db_path, "seed").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut cs = txn
                .open_table(crate::store::CHAIN_STATE_META)
                .expect("open chain_state_meta");
            cs.insert(
                CHAIN_STATE_KEY,
                genesis_chain_state().serialize().as_slice(),
            )
            .expect("write chain_state");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("shape-invalid dir must reject");
    // It fails on shape validation, not state-type mismatch.
    let msg = format!("{err}");
    assert!(msg.contains("root_digest absent"), "msg={msg}");
    // Critical: the sentinel must NOT have been written by the
    // failed open.
    let db = crate::redb_util::open_with_repair_logging(&db_path, "verify").expect("reopen");
    let read = db.begin_read().expect("begin_read");
    let table = read
        .open_table(crate::store::CHAIN_STATE_META)
        .expect("open chain_state_meta");
    let sentinel = table
        .get(crate::store::DATA_DIR_STATE_TYPE_KEY)
        .expect("get sentinel");
    assert!(
        sentinel.is_none(),
        "failed mis-open must not stamp the data_dir_state_type sentinel",
    );
}

#[test]
fn open_rejects_voted_params_row_with_bad_payload_at_valid_key() {
    // A row at a valid boundary key but whose bytes decode to a
    // different embedded epoch_start_height is corruption — open
    // must reject it, not defer to a lazy read_latest_at failure.
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        for h in 1u32..=4 {
            apply_synth(&mut store, h);
        }
    }
    {
        let db = crate::redb_util::open_with_repair_logging(&db_path, "corrupt").expect("open");
        let txn = crate::begin_write_qr(&db).expect("begin_write");
        {
            let mut vp = txn
                .open_table(crate::active_params::VOTED_PARAMS)
                .expect("open voted_params");
            // Valid boundary key 2, but the body claims height 4.
            let mut p = scala_launch();
            p.epoch_start_height = 4;
            vp.insert(2u64, p.serialize().expect("serialize").as_slice())
                .expect("inject mismatched-body row");
        }
        txn.commit().expect("commit");
    }
    let err = DigestStateStore::open(&db_path, scala_launch(), test_voting(), TEST_GENESIS_DIGEST)
        .expect_err("mismatched-body voted_params row must reject");
    let msg = format!("{err}");
    assert!(msg.contains("embedded epoch_start_height"), "msg={msg}",);
}

// ----- StateBackend read-side traits -----

#[test]
fn header_section_store_round_trips_a_header_through_the_trait() {
    let tmp = tempdir().expect("tempdir");
    let store = open_at(tmp.path());
    let id = synth_header_id(42);
    // `store_header` attempts to parse the bytes for the section
    // height index but swallows parse failures, so opaque bytes
    // round-trip cleanly — this test exercises the store/get path,
    // not header parsing.
    let bytes = vec![0xABu8; 64];
    HeaderSectionStore::store_header(&store, &id, &bytes).expect("store_header");
    let got = HeaderSectionStore::get_header(&store, &id).expect("get_header");
    assert_eq!(got, Some(bytes));
    // An unknown id reads back as absent.
    assert_eq!(
        HeaderSectionStore::get_header(&store, &synth_header_id(99)).expect("get_header"),
        None,
    );
}

#[test]
fn chain_state_read_reports_genesis_on_fresh_store() {
    let tmp = tempdir().expect("tempdir");
    let store = open_at(tmp.path());
    assert_eq!(ChainStateRead::height(&store), 0);
    // `ChainStateMeta` has no `PartialEq`; compare the load-bearing
    // pointers field-by-field, matching the snapshot the inherent
    // `chain_state()` accessor exposes.
    let snapshot = ChainStateRead::chain_state_meta(&store);
    let inherent = store.chain_state();
    assert_eq!(snapshot.best_header_id, inherent.best_header_id);
    assert_eq!(snapshot.best_header_height, inherent.best_header_height);
    assert_eq!(snapshot.best_header_score, inherent.best_header_score);
    assert_eq!(snapshot.best_full_block_id, inherent.best_full_block_id);
    assert_eq!(
        snapshot.best_full_block_height,
        inherent.best_full_block_height,
    );
    assert_eq!(snapshot.header_availability, inherent.header_availability);
    assert_eq!(
        ChainStateRead::read_minimal_full_block_height(&store).expect("min full block"),
        1,
    );
    // The genesis launch row keys to height 0.
    assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 0);
}

#[test]
fn session_invalid_round_trips_through_the_trait() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    let id = synth_header_id(7);
    assert!(
        !HeaderSectionStore::is_invalid(&store, &id).expect("is_invalid"),
        "unknown id starts valid",
    );
    HeaderSectionStore::mark_session_invalid(&mut store, id);
    assert!(
        HeaderSectionStore::is_invalid(&store, &id).expect("is_invalid"),
        "marked id reads invalid",
    );
    assert!(
        !HeaderSectionStore::is_invalid(&store, &synth_header_id(8)).expect("is_invalid"),
        "an unmarked id stays valid",
    );
}

#[test]
fn apply_across_epoch_boundary_refreshes_cached_active_params() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    // Genesis: caches reflect the launch row.
    assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 0);
    let launch_input_cost = scala_launch().input_cost;
    assert_eq!(
        ChainStateRead::active_params(&store).input_cost,
        launch_input_cost,
    );

    apply_synth(&mut store, 1); // non-boundary, no row

    // Epoch boundary (voting_length = 2): co-commit a changed-param row.
    let mut row = scala_launch();
    row.epoch_start_height = 2;
    row.input_cost = 9999;
    store
        .apply_block_digest(synth_digest(2), synth_chain_state(2), Some(row))
        .expect("apply h2 with epoch-boundary row");

    // The read-side cache tracks the committed tip, not the open snapshot.
    assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 2);
    assert_eq!(ChainStateRead::active_params(&store).input_cost, 9999);
    // validation_settings stays consistent with a fresh fold at the tip.
    let fresh = crate::active_params::compute_validation_settings_at(
        &store.db.begin_read().expect("begin_read"),
        store.height(),
    )
    .expect("fold");
    assert_eq!(ChainStateRead::validation_settings(&store), &fresh);
}

#[test]
fn rollback_across_epoch_boundary_reverts_cached_active_params() {
    let tmp = tempdir().expect("tempdir");
    let mut store = open_at(tmp.path());
    apply_synth(&mut store, 1);
    let mut row = scala_launch();
    row.epoch_start_height = 2;
    row.input_cost = 9999;
    store
        .apply_block_digest(synth_digest(2), synth_chain_state(2), Some(row))
        .expect("apply h2");
    assert_eq!(ChainStateRead::active_params(&store).input_cost, 9999);

    store.rollback_to(1).expect("rollback to 1");
    // The epoch row above height 1 was pruned, so the cache reverts
    // to the launch set rather than reporting the rolled-back epoch.
    assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 0);
    assert_eq!(
        ChainStateRead::active_params(&store).input_cost,
        scala_launch().input_cost,
    );
}

#[test]
fn reopen_after_epoch_apply_reads_tip_params_not_genesis() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("digest_state.redb");
    {
        let mut store = open_at_path(&db_path);
        apply_synth(&mut store, 1);
        let mut row = scala_launch();
        row.epoch_start_height = 2;
        row.input_cost = 9999;
        apply_digest_with_header(&mut store, synth_digest(2), synth_chain_state(2), Some(row));
    }
    // Reopen at a non-genesis tip: open() must fold params from the
    // persisted voted_params rows, not reset to launch/empty.
    let store = open_at_path(&db_path);
    assert_eq!(store.height(), 2);
    assert_eq!(ChainStateRead::active_params(&store).epoch_start_height, 2);
    assert_eq!(ChainStateRead::active_params(&store).input_cost, 9999);
}

/// The `BlockApply` apply-bridge.
///
/// The successful real-box-change path (a header's `state_root`
/// advancing across genuine inserts/removes, verified against a
/// Scala/mainnet ADProof) is the consensus gate and is covered
/// elsewhere by a real-corpus replay, NOT here — a self-generated
/// proof is not a valid consensus oracle. These tests cover the bridge's
/// guard logic, error classification, session-invalid marking, and
/// the commit plumbing using a no-op transition (which still
/// exercises section fetch → parse → verifier construction at a
/// real AVL root → finalize → `apply_block_digest`, independent of
/// genesis `state_root` semantics).
mod c2_bridge {
    use super::*;
    use crate::backend::BlockApply;
    use crate::chain::{ChainStateMeta, HeaderAvailability};
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
    use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
    use ergo_avltree_rust::operation::{KeyValue, Operation};
    use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::ad_proofs::{write_ad_proofs, ADProofs};
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{serialize_header, Header};
    use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};
    use ergo_validation::block::CheckedBlock;
    use ergo_validation::header::CheckedHeader;
    use std::collections::{BTreeMap, BTreeSet};

    // ----- helpers -----

    fn new_prover() -> BatchAVLProver {
        let tree = AVLTree::new(
            |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
            32,
            None,
        );
        BatchAVLProver::new(tree, true)
    }

    fn prover_digest(p: &mut BatchAVLProver) -> [u8; 33] {
        let raw = p.digest().expect("prover has a digest");
        let mut out = [0u8; 33];
        out.copy_from_slice(&raw);
        out
    }

    /// A committed non-empty prover root R0 plus a proof of ZERO
    /// operations at R0. Driving the verifier with no box changes
    /// against this proof finalizes back to R0 — the minimal valid
    /// transition that still flexes the whole bridge.
    fn committed_root_and_noop_proof() -> ([u8; 33], Vec<u8>) {
        let mut p = new_prover();
        p.perform_one_operation(&Operation::Insert(KeyValue {
            key: bytes::Bytes::from(vec![7u8; 32]),
            value: bytes::Bytes::from(vec![9u8; 16]),
        }))
        .expect("seed insert");
        let _ = p.generate_proof(); // commit the insert; tree now at R0
        let r0 = prover_digest(&mut p);
        let noop_proof = p.generate_proof().to_vec(); // zero ops since commit
        (r0, noop_proof)
    }

    fn synth_block_header(
        height: u32,
        parent_id: [u8; 32],
        state_root: [u8; 33],
        ad_proofs_root: [u8; 32],
    ) -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent_id),
            ad_proofs_root: Digest32::from_bytes(ad_proofs_root),
            state_root: ADDigest::from_bytes(state_root),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            timestamp: 1_700_000_000,
            n_bits: 0x1d00ffff,
            height,
            extension_root: Digest32::from_bytes([0u8; 32]),
            votes: [0u8; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        }
    }

    /// Canonical header id + an empty-transaction `CheckedBlock`.
    fn empty_block(header: Header) -> ([u8; 32], CheckedBlock) {
        let (_, id_modifier) = serialize_header(&header).expect("serialize_header");
        let header_id = *id_modifier.as_bytes();
        let checked = CheckedHeader::trust_me(header, header_id);
        (header_id, CheckedBlock::from_parts(checked, vec![]))
    }

    fn section_bytes(inner_header_id: [u8; 32], proof_bytes: Vec<u8>) -> Vec<u8> {
        let ap = ADProofs {
            header_id: ModifierId::from_bytes(inner_header_id),
            proof_bytes,
        };
        let mut w = VlqWriter::new();
        write_ad_proofs(&mut w, &ap);
        w.result()
    }

    fn section_id(header_id: [u8; 32], ad_proofs_root: [u8; 32]) -> [u8; 32] {
        compute_section_id(TYPE_AD_PROOFS, &header_id, &ad_proofs_root)
    }

    /// Seed an opened store to a committed non-genesis tip: root +
    /// `best_full_block_height = h`, with `best_header` one ahead so
    /// a linear apply at `h + 1` satisfies the chain-state
    /// invariant (header accepted before its full block).
    fn seed_tip(store: &mut DigestStateStore, root: [u8; 33], h: u32) {
        store.root_digest = root;
        let id = synth_header_id(h);
        store.chain_state = ChainStateMeta {
            best_header_id: id,
            best_header_height: h + 1,
            best_header_score: ((h as u64) + 1).to_be_bytes().to_vec(),
            best_full_block_id: id,
            best_full_block_height: h,
            header_availability: HeaderAvailability::Dense,
        };
    }

    struct NoopHook;
    impl crate::wallet::WalletApplyHook for NoopHook {
        fn tracked_p2pk_trees(&self) -> BTreeSet<Vec<u8>> {
            BTreeSet::new()
        }
        fn cached_pubkeys(&self) -> BTreeMap<u64, [u8; 33]> {
            BTreeMap::new()
        }
    }

    struct NoopGuard;
    impl crate::wallet::apply::RescanGuard for NoopGuard {
        fn abort_in_progress(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
            Ok(())
        }
        fn force_invalidate(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
            Ok(())
        }
    }

    // ----- happy path (no-op transition: commit plumbing) -----

    #[test]
    fn apply_full_block_noop_advances_full_block_tip() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        let (r0, noop_proof) = committed_root_and_noop_proof();
        seed_tip(&mut store, r0, 4); // committed tip at height 4, root R0

        let ad_root = *blake2b256(&noop_proof).as_bytes();
        let header = synth_block_header(5, synth_header_id(4), r0, ad_root);
        let (header_id, block) = empty_block(header);
        store
            .headers
            .store_block_section_typed(
                &section_id(header_id, ad_root),
                &section_bytes(header_id, noop_proof),
                TYPE_AD_PROOFS,
            )
            .expect("store ADProofs section");

        BlockApply::apply_full_block(&mut store, &block, None, None).expect("apply_full_block");

        // A no-op transition keeps the root; only the full-block tip
        // advances. A successful return means apply_block_digest
        // committed (it only mutates in-memory state post-commit).
        assert_eq!(store.root_digest(), r0);
        assert_eq!(store.height(), 5);
        assert_eq!(store.chain_state().best_full_block_id, header_id);
    }

    // ----- error paths -----

    #[test]
    fn apply_full_block_rejects_wallet_hook() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        let header = synth_block_header(1, [0u8; 32], [0u8; 33], [0u8; 32]);
        let (_, block) = empty_block(header);
        let hook = NoopHook;
        let err = BlockApply::apply_full_block(&mut store, &block, None, Some(&hook))
            .expect_err("wallet hook must be rejected");
        assert!(
            matches!(err, StateError::InvalidPrecondition { .. }),
            "got {err:?}"
        );
        assert_eq!(store.height(), 0, "no state advance on rejection");
    }

    #[test]
    fn rollback_rejects_wallet_hook_and_rescan_guard() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        let hook = NoopHook;
        let guard = NoopGuard;
        assert!(matches!(
            BlockApply::rollback_to(&mut store, 0, Some(&hook), None).expect_err("hook"),
            StateError::InvalidPrecondition { .. }
        ));
        assert!(matches!(
            BlockApply::rollback_to(&mut store, 0, None, Some(&guard)).expect_err("guard"),
            StateError::InvalidPrecondition { .. }
        ));
    }

    #[test]
    fn apply_full_block_wrong_height_is_out_of_order() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path()); // tip at genesis height 0
                                             // Height 5 against a height-0 tip (parent is the genesis
                                             // sentinel, matching the tip), rejected at the linear height
                                             // preflight before any section/proof work.
        let header = synth_block_header(5, [0u8; 32], [0u8; 33], [0u8; 32]);
        let (_, block) = empty_block(header);
        let err = BlockApply::apply_full_block(&mut store, &block, None, None)
            .expect_err("out-of-order height must be rejected");
        assert!(
            matches!(
                err,
                StateError::ApplyOutOfOrder {
                    expected_next: 1,
                    got: 5
                }
            ),
            "got {err:?}"
        );
        assert_eq!(store.height(), 0);
    }

    #[test]
    fn apply_full_block_non_tip_parent_is_non_linear_not_invalid() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        seed_tip(&mut store, [1u8; 33], 4); // committed tip id = synth_header_id(4)
                                            // Correct height (5 == tip 4 + 1) but a parent that is NOT
                                            // the committed tip → not linearly applicable. Must reject
                                            // before proof work, and must NOT mark the block invalid (it
                                            // may be a valid fork block we simply cannot apply linearly).
        let foreign_parent = synth_header_id(99);
        let header = synth_block_header(5, foreign_parent, [1u8; 33], [0xCDu8; 32]);
        let (header_id, block) = empty_block(header);
        let err = BlockApply::apply_full_block(&mut store, &block, None, None)
            .expect_err("non-tip parent must be rejected");
        assert!(
            matches!(err, StateError::DigestNonLinearParent { height: 5, .. }),
            "got {err:?}"
        );
        assert!(
            !store.session_invalids.contains(&header_id),
            "a non-tip-parent block must not be marked session-invalid"
        );
        assert_eq!(store.height(), 4, "no state advance");
    }

    #[test]
    fn apply_full_block_genesis_parent_passes_linear_gate() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path()); // genesis: height 0
        let genesis_tip = store.chain_state().best_full_block_id;
        // A height-1 block whose parent IS the genesis tip passes
        // BOTH linear preflights (0 + 1 == 1, parent == tip) and
        // proceeds to section fetch — proving the gate ADMITS the
        // genesis transition rather than rejecting it as
        // out-of-order or non-linear. (The successful genesis apply
        // itself, seeding the verifier at the pinned genesis state
        // digest, is covered elsewhere by a real-corpus replay.)
        let header = synth_block_header(1, genesis_tip, [1u8; 33], [0xCDu8; 32]);
        let (_, block) = empty_block(header);
        let err = BlockApply::apply_full_block(&mut store, &block, None, None)
            .expect_err("missing section");
        assert!(
            matches!(err, StateError::DigestAdProofsSectionMissing { .. }),
            "genesis-parent block must clear the linear gate, got {err:?}"
        );
    }

    #[test]
    fn apply_full_block_missing_section_is_unavailable_not_invalid() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        seed_tip(&mut store, [1u8; 33], 4);
        let header = synth_block_header(5, synth_header_id(4), [1u8; 33], [0xCDu8; 32]);
        let (header_id, block) = empty_block(header);
        // No section stored.
        let err = BlockApply::apply_full_block(&mut store, &block, None, None)
            .expect_err("missing section must error");
        assert!(
            matches!(err, StateError::DigestAdProofsSectionMissing { .. }),
            "got {err:?}"
        );
        // Data-availability, NOT block invalidity.
        assert!(
            !store.session_invalids.contains(&header_id),
            "missing section must not mark the header session-invalid"
        );
        assert_eq!(store.height(), 4);
    }

    #[test]
    fn apply_full_block_trailing_bytes_in_section_is_corruption() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        seed_tip(&mut store, [1u8; 33], 4);
        let ad_root = [0xABu8; 32];
        let header = synth_block_header(5, synth_header_id(4), [1u8; 33], ad_root);
        let (header_id, block) = empty_block(header);
        let mut bytes = section_bytes(header_id, vec![0u8; 8]);
        bytes.push(0xFF); // trailing junk after the proof
        store
            .headers
            .store_block_section_typed(&section_id(header_id, ad_root), &bytes, TYPE_AD_PROOFS)
            .expect("store section");
        let err = BlockApply::apply_full_block(&mut store, &block, None, None)
            .expect_err("trailing bytes must error");
        assert!(
            matches!(
                err,
                StateError::DbCorruption {
                    table: "block_sections",
                    ..
                }
            ),
            "got {err:?}"
        );
        assert_eq!(store.height(), 4);
    }

    #[test]
    fn apply_full_block_section_inner_header_id_mismatch_is_corruption() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        seed_tip(&mut store, [1u8; 33], 4);
        let ad_root = [0xABu8; 32];
        let header = synth_block_header(5, synth_header_id(4), [1u8; 33], ad_root);
        let (header_id, block) = empty_block(header);
        // Section parses cleanly but carries a foreign inner header id.
        let bytes = section_bytes([0x55u8; 32], vec![0u8; 8]);
        store
            .headers
            .store_block_section_typed(&section_id(header_id, ad_root), &bytes, TYPE_AD_PROOFS)
            .expect("store section");
        let err = BlockApply::apply_full_block(&mut store, &block, None, None)
            .expect_err("inner header-id mismatch must error");
        assert!(
            matches!(
                err,
                StateError::DbCorruption {
                    table: "block_sections",
                    ..
                }
            ),
            "got {err:?}"
        );
        assert_eq!(store.height(), 4);
    }

    #[test]
    fn apply_full_block_bad_ad_proofs_root_rejects_and_marks_session_invalid() {
        let tmp = tempdir().expect("tempdir");
        let mut store = open_at(tmp.path());
        seed_tip(&mut store, [1u8; 33], 4);
        // ad_proofs_root the proof bytes do NOT hash to → the
        // verifier's root-hash gate rejects (AdProofsRootMismatch).
        let ad_root = [0xABu8; 32];
        let header = synth_block_header(5, synth_header_id(4), [1u8; 33], ad_root);
        let (header_id, block) = empty_block(header);
        let bytes = section_bytes(header_id, vec![0u8; 8]);
        store
            .headers
            .store_block_section_typed(&section_id(header_id, ad_root), &bytes, TYPE_AD_PROOFS)
            .expect("store section");
        let err = BlockApply::apply_full_block(&mut store, &block, None, None)
            .expect_err("bad ad_proofs_root must be rejected");
        assert!(
            matches!(err, StateError::DigestApplyRejected { .. }),
            "got {err:?}"
        );
        // A verifier rejection is session-scoped invalidity.
        assert!(
            store.session_invalids.contains(&header_id),
            "verifier rejection must mark the header session-invalid"
        );
        assert_eq!(store.height(), 4, "no state advance on rejection");
    }
}
