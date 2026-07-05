//! Live mainnet validation of the fast interlinks-walk
//! `StateStore::prove_with_db` (Part 2 sub-phase 14.10).
//!
//! Reads a fully-synced Mode 1 archival data_dir (path passed via
//! `ERGO_MAINNET_DATA_DIR` env var, OR the default location
//! `ergo-data.backup-pre-nipopow-attempt` in the repo root if
//! present), constructs a NiPoPoW proof via the fast variant, and:
//!
//! 1. Asserts proof construction completes.
//! 2. Reports compute time (Scala parity target: seconds, not minutes).
//! 3. Reports proof structure (prefix.len, suffix_tail.len, m, k).
//! 4. Asserts the produced proof passes the consume-side validator
//!    (full round-trip: construct on serve side, verify on consume
//!    side, against the chain it was constructed from).
//!
//! Test passes vacuously when no archival data_dir is available —
//! CI doesn't require a 6 GB mainnet state. Run locally after a
//! mainnet sync to exercise the fast path.

use std::path::PathBuf;

fn locate_data_dir() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("ERGO_MAINNET_DATA_DIR") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    // Repo-root default — set by the live mainnet capture session.
    let p = PathBuf::from("../ergo-data.backup-pre-nipopow-attempt");
    if p.exists() {
        return Some(p);
    }
    None
}

#[test]
fn prove_with_db_against_live_mainnet_archive() {
    let data_dir = match locate_data_dir() {
        Some(p) => p,
        None => {
            eprintln!(
                "[skipped] no mainnet archival data_dir available. \
                 Set ERGO_MAINNET_DATA_DIR or place a synced data_dir at \
                 ergo-data.backup-pre-nipopow-attempt to exercise prove_with_db."
            );
            return;
        }
    };

    // The node convention: data_dir contains `state.redb`. Pass the
    // `.redb` file directly (StateStore::open takes a redb file
    // path, not a directory).
    let db_path = data_dir.join("state.redb");
    let store = ergo_state::store::StateStore::open(&db_path).expect("open state.redb");
    let cs = store.chain_state();
    eprintln!(
        "[mainnet] best_header_height={}, best_full_block_height={}, mode={:?}",
        cs.best_header_height, cs.best_full_block_height, cs.header_availability
    );

    // Sparse-mode archive nodes can't serve — skip.
    if !matches!(
        cs.header_availability,
        ergo_state::chain::HeaderAvailability::Dense
    ) {
        eprintln!("[skipped] data_dir is sparse-mode (NiPoPoW-bootstrapped)");
        return;
    }
    // Too-short chain — skip.
    if cs.best_header_height < 100 {
        eprintln!("[skipped] chain too short (height < 100)");
        return;
    }

    // Probe whether genesis has its extension stored. A Mode 2-
    // bootstrapped node only has extensions from snapshot_height
    // onwards — historical extensions (heights 1 through
    // snapshot_height) are never downloaded. Such a node CAN'T act
    // as a NiPoPoW server even with blocks_to_keep = -1.
    let genesis_popow = store
        .popow_header_at_height(1)
        .expect("HEADER_CHAIN_INDEX read succeeds");
    if genesis_popow.is_none() {
        eprintln!(
            "[skipped] data_dir lacks historical extension data \
             (likely Mode 2-bootstrapped, not a Mode 1 native archive). \
             Re-run on a node synced from genesis to exercise serve side."
        );
        return;
    }

    let t0 = std::time::Instant::now();
    let proof = store
        .prove_with_db(6, 10, None)
        .expect("prove_with_db succeeds on Dense archive");
    let elapsed = t0.elapsed();

    eprintln!(
        "[mainnet] prove_with_db: m={}, k={}, prefix.len={}, suffix_tail.len={}, continuous={}",
        proof.m,
        proof.k,
        proof.prefix.len(),
        proof.suffix_tail.len(),
        proof.continuous,
    );
    eprintln!(
        "[mainnet] elapsed: {:.2}s ({} ms)",
        elapsed.as_secs_f64(),
        elapsed.as_millis()
    );

    assert_eq!(proof.m, 6);
    assert_eq!(proof.k, 10);
    assert_eq!(
        proof.suffix_tail.len(),
        9,
        "suffix_tail should have k-1 = 9 entries"
    );
    assert!(
        !proof.prefix.is_empty(),
        "prefix must be non-empty for a non-trivial chain"
    );

    // Serialize + deserialize round-trip: bytes match.
    let bytes = ergo_ser::popow_proof::serialize_nipopow_proof(&proof).expect("serialize");
    let reparsed =
        ergo_ser::popow_proof::deserialize_nipopow_proof(&bytes).expect("deserialize round-trip");
    let rebytes = ergo_ser::popow_proof::serialize_nipopow_proof(&reparsed).expect("re-serialize");
    assert_eq!(bytes, rebytes, "round-trip must be byte-identical");

    // Consume-side validation: the proof we constructed must pass
    // our own validator. This catches any drift between the prove
    // (serve) and is_valid (consume) algorithms.
    use ergo_validation::popow::NipopowProofExt;
    let chain_config = ergo_crypto::difficulty::DifficultyParams::mainnet();
    assert!(
        proof.has_valid_heights(),
        "constructed proof must have monotone heights"
    );
    // `has_valid_connections` requires Scala parity on the interlinks
    // lookback window; pin it explicitly.
    assert!(
        proof.has_valid_connections(&chain_config),
        "constructed proof must have valid connections"
    );
    assert!(
        proof.has_valid_proofs(),
        "constructed proof must have valid batch merkle proofs"
    );
    // Per-header PoW must verify for all non-genesis headers.
    assert!(
        proof.has_valid_per_header_pow(),
        "constructed proof must have valid per-header PoW"
    );
    // Difficulty headers are required for continuous proofs.
    assert!(
        proof.has_valid_difficulty_headers(&chain_config),
        "constructed proof must include all required difficulty headers"
    );

    eprintln!("[mainnet] PASS: prove_with_db produces a valid Scala-parity proof");
}

/// The REST serve path (`ChainStoreReader::prove_nipopow`) is a second
/// DB-backed implementation of the same interlinks walk as
/// `StateStore::prove_with_db` (it exists because REST handlers hold
/// only the lock-free reader). Two implementations of one algorithm
/// can drift — this pins them byte-identical on a real mainnet chain,
/// the same equivalence discipline as Scala's `PoPowAlgosWithDBSpec`
/// (in-memory prover == DB prover).
#[test]
fn reader_prover_matches_store_prover_byte_exact() {
    let data_dir = match locate_data_dir() {
        Some(p) => p,
        None => {
            eprintln!("[skipped] no mainnet archival data_dir available.");
            return;
        }
    };
    let db_path = data_dir.join("state.redb");
    let store = ergo_state::store::StateStore::open(&db_path).expect("open state.redb");
    let cs = store.chain_state();
    if !matches!(
        cs.header_availability,
        ergo_state::chain::HeaderAvailability::Dense
    ) || cs.best_header_height < 100
        || store
            .popow_header_at_height(1)
            .expect("index read")
            .is_none()
    {
        eprintln!("[skipped] data_dir can't serve proofs (sparse/short/no-genesis-extension)");
        return;
    }

    let params = ergo_chain_spec::DifficultyParams::mainnet();
    let reader = store.reader_handle();

    for (m, k) in [(6u32, 10u32), (3, 5), (10, 20)] {
        let via_store = store
            .prove_with_db(m, k, None)
            .expect("store prover succeeds");
        let via_reader = reader
            .prove_nipopow(m, k, None, cs.best_header_height, true, &params)
            .expect("reader prover succeeds");
        let store_bytes =
            ergo_ser::popow_proof::serialize_nipopow_proof(&via_store).expect("serialize store");
        let reader_bytes =
            ergo_ser::popow_proof::serialize_nipopow_proof(&via_reader).expect("serialize reader");
        assert_eq!(
            store_bytes, reader_bytes,
            "prover divergence at (m={m}, k={k}): store and reader walks must be byte-identical"
        );
        eprintln!(
            "[equivalence] (m={m}, k={k}): {} bytes, prefix.len={}",
            store_bytes.len(),
            via_store.prefix.len()
        );
    }
}
