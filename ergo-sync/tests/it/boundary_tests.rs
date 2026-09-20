//! Mainnet boundary transition tests for the header processing pipeline.
//!
//! Tests process_header at the two critical mainnet transitions:
//! - Autolykos v2 activation at height 417,792
//! - EIP-37 epoch length change at height 844,673
//!
//! These tests seed prerequisite headers directly into the store (bypassing
//! PoW validation for speed) and then run the boundary header through the
//! full process_header pipeline.

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::read_header;
use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
use ergo_sync::header_proc::process_header;

fn load_headers_file(name: &str) -> Vec<serde_json::Value> {
    let path = format!("../test-vectors/mainnet/{name}");
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&data).unwrap()
}

fn get_header_bytes_from(headers: &[serde_json::Value], height: u32) -> Vec<u8> {
    let h = headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == height as u64)
        .unwrap_or_else(|| panic!("header at height {height} not found"));
    hex::decode(h["bytes"].as_str().unwrap()).unwrap()
}

/// Seed a range of headers into the store WITHOUT running full validation.
/// Stores header bytes + header_meta (with cumulative score computed from nBits).
/// This is fast because it skips PoW verification.
fn seed_headers_range(
    store: &mut StateStore,
    headers: &[serde_json::Value],
    from_height: u32,
    to_height: u32,
) {
    let mut prev_score = num_bigint::BigUint::from(0u64);

    for height in from_height..=to_height {
        let h = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64);
        let h = match h {
            Some(h) => h,
            None => continue, // skip if not in file
        };
        let h_bytes = hex::decode(h["bytes"].as_str().unwrap()).unwrap();
        let h_id = *blake2b256(&h_bytes).as_bytes();
        let mut r = VlqReader::new(&h_bytes);
        let header = read_header(&mut r).unwrap();

        if height == from_height {
            let prev_id = *header.parent_id.as_bytes();
            // Store a minimal parent meta if we don't have it
            if store.get_header_meta(&prev_id).unwrap().is_none() {
                store
                    .store_header_meta(
                        &prev_id,
                        &HeaderMeta {
                            parent_id: [0u8; 32],
                            height: height - 1,
                            cumulative_score: vec![1],
                            pow_validity: 1,
                            timestamp: header.timestamp.saturating_sub(120_000),
                        },
                    )
                    .unwrap();
            }
        }

        let difficulty = decode_compact_bits(header.n_bits);
        let cumulative = &prev_score + &difficulty;
        let score_bytes = cumulative.to_bytes_be();

        store.store_header(&h_id, &h_bytes).unwrap();
        store
            .store_header_meta(
                &h_id,
                &HeaderMeta {
                    parent_id: *header.parent_id.as_bytes(),
                    height,
                    cumulative_score: score_bytes.clone(),
                    pow_validity: 1,
                    timestamp: header.timestamp,
                },
            )
            .unwrap();

        // Update best header + HEADER_CHAIN_INDEX entry so a later real
        // persist_apply's rewrite_best_chain_into_index finds a fork-point
        // within the seeded range rather than walking past it.
        store
            .test_force_set_best_header_unsafe(h_id, height, score_bytes.clone())
            .unwrap();
        store
            .test_force_put_header_chain_index(height, &h_id)
            .unwrap();

        prev_score = cumulative;
    }
}

/// Test: process_header at Autolykos v2 activation (height 417,792).
///
/// v2 activation uses a fixed initial difficulty. The difficulty module
/// has a special case for this height. This test proves that
/// process_header handles the v2 transition correctly through ergo-sync.
#[test]
#[ignore = "needs gitignored headers_417785_417800.json — extract via test-vectors/scripts then run with --ignored"]
fn process_header_at_v2_activation_417792() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    // Seed headers 417,785 to 417,791 (parents needed for the boundary)
    let pre_headers = load_headers_file("headers_417785_417800.json");
    seed_headers_range(&mut store, &pre_headers, 417_785, 417_791);

    assert_eq!(store.chain_state().best_header_height, 417_791);

    // Process header 417,792 through the real pipeline
    let h_bytes = get_header_bytes_from(&pre_headers, 417_792);
    match process_header(&mut store, &h_bytes) {
        Ok(processed) => {
            assert_eq!(processed.height, 417_792);
            assert!(processed.is_new_best);
            assert_eq!(store.chain_state().best_header_height, 417_792);
        }
        Err(e) => panic!("process_header failed at v2 activation 417,792: {e}"),
    }

    // Also process 417,793 to verify post-v2 works
    let h_bytes = get_header_bytes_from(&pre_headers, 417_793);
    match process_header(&mut store, &h_bytes) {
        Ok(processed) => {
            assert_eq!(processed.height, 417_793);
        }
        Err(e) => panic!("process_header failed at 417,793 (post-v2): {e}"),
    }
}

/// Test: process_header at EIP-37 activation (height 844,673).
///
/// EIP-37 changes epoch length from 1024 to 128. Height 844,673's parent
/// (844,672) is an epoch boundary under the NEW 128-block epoch length.
/// This means difficulty recalculation needs headers at 128-block intervals.
///
/// This test seeds headers from 843,648 (8 epochs back at 128-block intervals)
/// through 844,672, then processes 844,673 through the real pipeline.
#[test]
#[ignore = "needs gitignored headers_843000_844672.json + headers_844673_846000.json — extract via test-vectors/scripts then run with --ignored"]
fn process_header_at_eip37_activation_844673() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    // Seed headers from 843,000 to 844,672 (covers 8+ epochs of 128 blocks)
    let pre_headers = load_headers_file("headers_843000_844672.json");
    seed_headers_range(&mut store, &pre_headers, 843_000, 844_672);

    assert_eq!(store.chain_state().best_header_height, 844_672);

    // Process header 844,673 through the real pipeline
    let post_headers = load_headers_file("headers_844673_846000.json");
    let h_bytes = get_header_bytes_from(&post_headers, 844_673);
    match process_header(&mut store, &h_bytes) {
        Ok(processed) => {
            assert_eq!(processed.height, 844_673);
            assert!(processed.is_new_best);
            assert_eq!(store.chain_state().best_header_height, 844_673);
        }
        Err(e) => panic!("process_header failed at EIP-37 activation 844,673: {e}"),
    }

    // Process a few more to verify post-EIP-37 works
    for height in 844_674..=844_676 {
        let h_bytes = get_header_bytes_from(&post_headers, height);
        match process_header(&mut store, &h_bytes) {
            Ok(processed) => assert_eq!(processed.height, height),
            Err(e) => panic!("process_header failed at {height} (post-EIP-37): {e}"),
        }
    }
}
