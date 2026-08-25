use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::difficulty::{
    epoch_length_for_height, previous_heights_for_recalculation, DifficultyParams,
};
use ergo_crypto::pow::{verify_header_difficulty, verify_pow_solution};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, serialize_header, Header};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    #[allow(dead_code)]
    id: String,
    bytes: String,
    /// Provenance (present on curated fixtures; absent on raw range dumps).
    #[serde(rename = "sourceFile", default)]
    source_file: Option<String>,
    #[serde(rename = "sourceHeight", default)]
    source_height: Option<u32>,
    #[serde(rename = "selectionReason", default)]
    selection_reason: Option<String>,
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

/// The EIP-37 difficulty-retarget oracle window, pinned to EXTERNAL protocol
/// facts (NOT derived from `previous_heights_for_recalculation`, the code
/// under test, so a window-selection regression is caught here rather than
/// baked into both the fixture and the assertion):
///
/// EIP-37 activates at mainnet height 844_673, switching the difficulty
/// epoch length 1024 -> 128. 844_673 is itself the first post-activation
/// epoch boundary (parent 844_672 is a multiple of 128). The Autolykos
/// difficulty rule looks back 8 epochs, so the recalculation at 844_673
/// consumes the 9 headers 844_672, 844_544, ..., 843_648 (step 128). The
/// committed fixture is those 9 lookback headers plus the 844_673 boundary.
const EIP37_BOUNDARY: u32 = 844_673;
const EIP37_CURATED_HEIGHTS: [u32; 10] = [
    843_648, 843_776, 843_904, 844_032, 844_160, 844_288, 844_416, 844_544, 844_672, 844_673,
];

/// Default difficulty witness exercising the **EIP-37 difficulty retarget**
/// at its activation boundary against real mainnet `nBits`. Two independent
/// external anchors:
///
/// 1. Fixture integrity — every row's `id` is `blake2b256` of its full
///    serialized bytes and the parse round-trips byte-for-byte, so the
///    corpus is provably the real mainnet headers (not substituted data).
/// 2. Retarget oracle — `verify_header_difficulty` is called directly with the
///    EXTERNALLY pinned 8-epoch lookback window (the `EIP37_CURATED_HEIGHTS`
///    const, NOT `previous_heights_for_recalculation`, the code under test), so
///    a window-selection regression cannot hide here. It recomputes the
///    required nBits via the EIP-37 path and compares it to the header's real
///    mainnet nBits at 844_673.
///
/// Previously the only EIP-37 boundary coverage lived in `#[ignore]`'d tests
/// behind gitignored multi-thousand-header corpora, so a retarget regression
/// passed the default suite. `difficulty_eip37_boundary_rejects_wrong_nbits`
/// proves this corpus is load-bearing. Regenerate via `regenerate_eip37_curated`.
#[test]
fn difficulty_curated_window_eip37() {
    let path = "../test-vectors/mainnet/headers_eip37_curated.json";
    let corpus = load_corpus(path);

    // (1) Fixture integrity: anchor each row to mainnet truth independently
    // of the difficulty math — id == blake2b256(bytes) and an exact byte
    // round-trip (full, no-trailing-byte consumption on parse + re-emit).
    let raw = std::fs::read_to_string(path).unwrap();
    let vectors: Vec<HeaderVector> = serde_json::from_str(&raw).unwrap();
    for v in &vectors {
        let bytes = hex::decode(&v.bytes).unwrap();
        assert_eq!(
            hex::encode(blake2b256(&bytes)),
            v.id,
            "fixture row at height {} is not a real mainnet header (id != blake2b256(bytes))",
            v.height,
        );
        // `serialize_header` returns the canonical (bytes, header_id) pair.
        let (reserialized, id) = serialize_header(&corpus[&v.height]).expect("re-serialize header");
        assert_eq!(
            reserialized, bytes,
            "fixture header at height {} does not round-trip byte-for-byte",
            v.height,
        );
        assert_eq!(
            hex::encode(id.as_bytes()),
            v.id,
            "serialize_header id disagrees with the fixture id at height {}",
            v.height,
        );
        // Unfabricatable mainnet anchor: each fixture header must carry a valid
        // Autolykos PoW solution. `id == blake2b256(bytes)` alone only proves a
        // self-consistent {id, bytes} pair; valid PoW proves a real mined
        // mainnet header, not synthesized data.
        verify_pow_solution(&corpus[&v.height])
            .unwrap_or_else(|e| panic!("fixture header at height {} fails PoW: {e}", v.height));
        // Provenance, matching the curated v2 fixture's discipline: source
        // file present, sourceHeight self-consistent, and a selection reason.
        assert!(
            v.source_file.is_some(),
            "fixture row at height {} lacks `sourceFile` provenance",
            v.height,
        );
        assert_eq!(
            v.source_height,
            Some(v.height),
            "fixture row at height {} has a mismatched `sourceHeight`",
            v.height,
        );
        assert!(
            v.selection_reason.is_some(),
            "fixture row at height {} lacks `selectionReason` provenance",
            v.height,
        );
    }
    // No duplicate rows: a `BTreeMap` silently collapses them, which would hide
    // drift behind the heights-equality check below.
    assert_eq!(
        vectors.len(),
        EIP37_CURATED_HEIGHTS.len(),
        "headers_eip37_curated.json must have exactly {} rows (no duplicates)",
        EIP37_CURATED_HEIGHTS.len(),
    );

    // Corpus is exactly the spec-pinned EIP-37 boundary + 8-epoch lookback.
    let heights: Vec<u32> = corpus.keys().copied().collect();
    assert_eq!(
        heights,
        EIP37_CURATED_HEIGHTS.to_vec(),
        "headers_eip37_curated.json must hold exactly the EIP-37 boundary + lookback window",
    );

    // (2) Retarget oracle against real mainnet nBits — using the EXTERNALLY
    // pinned 8-epoch lookback window (the const, NOT
    // `previous_heights_for_recalculation`, which is the code under test).
    // `verify_header_difficulty` recomputes the required nBits via the EIP-37
    // path (`eip37_calculate`/`interpolate`/`cap_change`) and compares it to the
    // header's real mainnet nBits at 844_673.
    let cfg = DifficultyParams::mainnet();
    let lookback: Vec<Header> = EIP37_CURATED_HEIGHTS
        .iter()
        .filter(|&&h| h != EIP37_BOUNDARY)
        .map(|h| corpus[h].clone())
        .collect();
    verify_header_difficulty(&corpus[&EIP37_BOUNDARY], &lookback, &cfg)
        .expect("EIP-37 boundary 844673 must verify against its externally-pinned lookback window");
}

/// Negative witness proving the EIP-37 curated corpus is LOAD-BEARING:
/// perturbing the boundary header's nBits must make `verify_header_difficulty`
/// reject (the recomputed required difficulty no longer matches the header's),
/// so the positive test genuinely exercises the comparison rather than merely
/// loading a fixture.
#[test]
fn difficulty_eip37_boundary_rejects_wrong_nbits() {
    let corpus = load_corpus("../test-vectors/mainnet/headers_eip37_curated.json");
    let cfg = DifficultyParams::mainnet();
    let lookback: Vec<Header> = EIP37_CURATED_HEIGHTS
        .iter()
        .filter(|&&h| h != EIP37_BOUNDARY)
        .map(|h| corpus[h].clone())
        .collect();

    // Control: the unmodified mainnet header verifies.
    assert!(
        verify_header_difficulty(&corpus[&EIP37_BOUNDARY], &lookback, &cfg).is_ok(),
        "the unmodified EIP-37 boundary header must verify",
    );

    // A clearly-different compact target must be rejected.
    let mut bad = corpus[&EIP37_BOUNDARY].clone();
    bad.n_bits = 0x1d00_ffff;
    assert!(
        verify_header_difficulty(&bad, &lookback, &cfg).is_err(),
        "a wrong nBits at the EIP-37 boundary must be rejected",
    );

    // The lookback window is load-bearing: perturb the most-recent lookback
    // header (the boundary's direct parent, 844_672), whose nBits AND timestamp
    // both feed the retarget. (The oldest header is only a window endpoint, so
    // its nBits alone is not consumed — perturbing it would be a weak witness.)
    // The recomputed difficulty then changes and the real boundary nBits is
    // rejected, proving the verifier actually consumes the window.
    let mut lookback_mut = lookback.clone();
    let parent = lookback_mut.last_mut().expect("lookback is non-empty");
    parent.n_bits = 0x1d00_ffff;
    parent.timestamp = parent.timestamp.wrapping_add(600_000);
    assert!(
        verify_header_difficulty(&corpus[&EIP37_BOUNDARY], &lookback_mut, &cfg).is_err(),
        "perturbing the parent lookback header must change the retarget and reject the real boundary nBits",
    );
}

/// Regenerate-only helper for `headers_eip37_curated.json`. Run with:
///   cargo test -p ergo-crypto --test difficulty_mainnet \
///     regenerate_eip37_curated -- --ignored --nocapture
/// Reads the gitignored full corpora and writes the `EIP37_CURATED_HEIGHTS`
/// rows verbatim (each `{height,id,bytes,...}` entry copied as-is, so the
/// committed bytes are byte-identical to the extracted mainnet headers). The
/// height set is the spec-pinned constant, NOT a value computed from the code
/// under test.
#[test]
#[ignore = "regenerate-only: rebuilds headers_eip37_curated.json from the gitignored headers_843000_844672.json + headers_844673_846000.json"]
fn regenerate_eip37_curated() {
    use serde_json::Value;
    let mut by_height: BTreeMap<u32, Value> = BTreeMap::new();
    for src in [
        "../test-vectors/mainnet/headers_843000_844672.json",
        "../test-vectors/mainnet/headers_844673_846000.json",
    ] {
        let data = std::fs::read_to_string(src)
            .unwrap_or_else(|e| panic!("regenerate needs the gitignored {src}: {e}"));
        let arr: Vec<Value> = serde_json::from_str(&data).unwrap();
        for v in arr {
            if let Some(h) = v.get("height").and_then(Value::as_u64) {
                by_height.insert(h as u32, v);
            }
        }
    }
    let curated: Vec<Value> = EIP37_CURATED_HEIGHTS
        .iter()
        .map(|h| {
            let mut entry = by_height
                .get(h)
                .unwrap_or_else(|| panic!("source corpora missing height {h}"))
                .clone();
            let source_file = if *h <= 844_672 {
                "headers_843000_844672.json"
            } else {
                "headers_844673_846000.json"
            };
            let reason = if *h == EIP37_BOUNDARY {
                "EIP-37 activation boundary (844673): epoch length 1024->128, first post-activation difficulty recalculation"
            } else {
                "EIP-37 8-epoch difficulty-lookback header (step 128)"
            };
            if let Value::Object(m) = &mut entry {
                m.insert("sourceFile".into(), Value::from(source_file));
                m.insert("sourceHeight".into(), Value::from(*h));
                m.insert("selectionReason".into(), Value::from(reason));
            }
            entry
        })
        .collect();
    let out = "../test-vectors/mainnet/headers_eip37_curated.json";
    std::fs::write(out, serde_json::to_string_pretty(&curated).unwrap()).unwrap();
    eprintln!(
        "wrote {} headers to {out}: {EIP37_CURATED_HEIGHTS:?}",
        curated.len()
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
