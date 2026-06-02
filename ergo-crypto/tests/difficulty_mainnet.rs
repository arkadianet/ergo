use ergo_crypto::difficulty::{
    epoch_length_for_height, previous_heights_for_recalculation, DifficultyParams,
};
use ergo_crypto::pow::{verify_header_difficulty, verify_pow_solution};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    #[allow(dead_code)]
    id: String,
    bytes: String,
}

fn load_corpus(path: &str) -> BTreeMap<u32, Header> {
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let vectors: Vec<HeaderVector> =
        serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
    let mut map = BTreeMap::new();
    for v in &vectors {
        let bytes = hex::decode(&v.bytes).unwrap();
        let mut reader = VlqReader::new(&bytes);
        let header = read_header(&mut reader).unwrap();
        assert_eq!(header.height, v.height);
        map.insert(v.height, header);
    }
    map
}

/// For a contiguous corpus, verify difficulty at epoch boundaries.
/// Returns `(checked, skipped)` so callers can pin the exact number
/// of transitions actually verified — guards against silent coverage
/// loss when a corpus has sparse heights and most rows skip for
/// missing context.
fn verify_difficulty_in_corpus(corpus: &BTreeMap<u32, Header>) -> (usize, usize) {
    let heights: Vec<u32> = corpus.keys().copied().collect();
    let min_h = *heights.first().unwrap();
    let max_h = *heights.last().unwrap();
    let cfg = DifficultyParams::mainnet();

    let mut checked = 0;
    let mut skipped = 0;

    for &h in &heights {
        if h == min_h {
            continue; // Can't check the first header
        }

        let epoch_len = epoch_length_for_height(h, &cfg);
        let needed = previous_heights_for_recalculation(h, epoch_len);

        // Check if all needed heights are in the corpus
        if needed.iter().all(|nh| corpus.contains_key(nh)) {
            let epoch_headers: Vec<Header> = needed.iter().map(|nh| corpus[nh].clone()).collect();

            let result = verify_header_difficulty(&corpus[&h], &epoch_headers, &cfg);
            match result {
                Ok(()) => checked += 1,
                Err(e) => {
                    panic!("Difficulty mismatch at height {h}: {e}");
                }
            }
        } else {
            skipped += 1;
        }
    }

    eprintln!(
        "Corpus {min_h}-{max_h}: checked {checked} headers, skipped {skipped} (missing context)"
    );
    assert!(
        checked > 0,
        "should verify at least some headers in {min_h}-{max_h}"
    );
    (checked, skipped)
}

/// Default difficulty-continuity witness against the 10 v1 mainnet
/// headers in `headers_1_10.json`. Every height in 1-10 is non-boundary
/// (parent_height < 1024), so this exercises the
/// `verify_header_difficulty` non-boundary path against real-mainnet
/// `nBits` values. Pre-flight pins the exact 10-height set and the
/// helper-returned (checked, skipped) shape so a fixture regeneration
/// that silently shrinks coverage fails loudly.
#[test]
fn difficulty_curated_window_genesis() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_1_10.json");
    let heights: Vec<u32> = corpus.keys().copied().collect();
    assert_eq!(
        heights,
        (1u32..=10).collect::<Vec<u32>>(),
        "headers_1_10.json must contain exactly heights 1..=10",
    );
    let (checked, skipped) = verify_difficulty_in_corpus(&corpus);
    assert_eq!(
        (checked, skipped),
        (9, 0),
        "expected exactly 9 non-boundary transitions checked (h=2..=10)",
    );
}

/// Default difficulty witness exercising the v1→v2 fork transition.
/// `headers_v2_curated.json` carries 5 heights (417791, 417792, 600000,
/// 1200000, 1761000); only the `417791 → 417792` pair has both members
/// in the corpus, so **only that single transition is actually checked**
/// — the other three v2 rows lack their direct parents in the corpus
/// and the helper skips them. The transition that does run carries
/// real signal because 417791 sits on the last-v1 boundary
/// (`417791 % 1024 == 1023`, non-boundary recalc point) and 417792 is
/// the first post-fork header, so the test pins
/// `verify_header_difficulty` across the Autolykos-v2 hardfork.
#[test]
fn difficulty_curated_window_v2_fork() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_v2_curated.json");
    let mut heights: Vec<u32> = corpus.keys().copied().collect();
    heights.sort_unstable();
    assert_eq!(
        heights,
        vec![417_791, 417_792, 600_000, 1_200_000, 1_761_000],
        "headers_v2_curated.json must contain the 5 fork-boundary heights",
    );
    let (checked, skipped) = verify_difficulty_in_corpus(&corpus);
    assert_eq!(
        (checked, skipped),
        (1, 3),
        "expected exactly 1 transition checked (417791→417792); other 3 v2 rows skip for missing parents",
    );
}

#[test]
#[ignore = "broad corpus replay — ~2000-header non-boundary nBits continuity sweep. The only epoch-boundary recalculation in 1-2000 is at child height 1025 (parent=1024, parent_height%1024==0), which the verifier skips because h=0 does not exist on mainnet. Default-suite coverage lives in `difficulty_curated_window_genesis` and `difficulty_curated_window_v2_fork`. Run with --include-ignored."]
fn difficulty_genesis_epoch() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_1_2000.json");
    verify_difficulty_in_corpus(&corpus);
}

#[test]
#[ignore = "needs gitignored headers_415000_417791.json — extract via test-vectors/scripts then run with --ignored"]
fn difficulty_pre_v2_boundary() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_415000_417791.json");
    verify_difficulty_in_corpus(&corpus);
}

#[test]
#[ignore = "needs gitignored headers_417792_419000.json — extract via test-vectors/scripts then run with --ignored"]
fn difficulty_v2_boundary() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_417792_419000.json");
    verify_difficulty_in_corpus(&corpus);
}

#[test]
#[ignore = "needs gitignored headers_600000_601000.json — extract via test-vectors/scripts then run with --ignored"]
fn difficulty_mid_chain() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_600000_601000.json");
    verify_difficulty_in_corpus(&corpus);
}

#[test]
#[ignore = "needs gitignored headers_843000_844672.json — extract via test-vectors/scripts then run with --ignored"]
fn difficulty_pre_eip37() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_843000_844672.json");
    verify_difficulty_in_corpus(&corpus);
}

#[test]
#[ignore = "needs gitignored headers_844673_846000.json — extract via test-vectors/scripts then run with --ignored"]
fn difficulty_post_eip37() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_844673_846000.json");
    verify_difficulty_in_corpus(&corpus);
}

#[test]
#[ignore = "needs gitignored headers_1200000_1201000.json — extract via test-vectors/scripts then run with --ignored"]
fn difficulty_recent_chain() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_1200000_1201000.json");
    verify_difficulty_in_corpus(&corpus);
}

/// Verify both PoW halves (solution + difficulty) on a corpus.
fn verify_full_pow_in_corpus(corpus: &BTreeMap<u32, Header>) {
    let heights: Vec<u32> = corpus.keys().copied().collect();
    let min_h = *heights.first().unwrap();
    let cfg = DifficultyParams::mainnet();

    let mut checked = 0;
    for &h in &heights {
        if h == min_h {
            continue;
        }

        let epoch_len = epoch_length_for_height(h, &cfg);
        let needed = previous_heights_for_recalculation(h, epoch_len);

        if needed.iter().all(|nh| corpus.contains_key(nh)) {
            let epoch_headers: Vec<Header> = needed.iter().map(|nh| corpus[nh].clone()).collect();
            let header = &corpus[&h];

            verify_pow_solution(header)
                .unwrap_or_else(|e| panic!("PoW solution check failed at height {h}: {e}"));
            verify_header_difficulty(header, &epoch_headers, &cfg)
                .unwrap_or_else(|e| panic!("Difficulty check failed at height {h}: {e}"));
            checked += 1;
        }
    }

    eprintln!(
        "Full PoW verified for {checked} headers in {min_h}-{}",
        heights.last().unwrap()
    );
}

#[test]
#[ignore = "needs gitignored headers_844673_846000.json — extract via test-vectors/scripts then run with --ignored"]
fn full_pow_post_eip37() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_844673_846000.json");
    verify_full_pow_in_corpus(&corpus);
}

#[test]
#[ignore = "needs gitignored headers_1200000_1201000.json — extract via test-vectors/scripts then run with --ignored"]
fn full_pow_recent() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_1200000_1201000.json");
    verify_full_pow_in_corpus(&corpus);
}
