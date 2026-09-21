use ergo_crypto::pow::verify_pow_solution;
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{read_header, serialize_header_without_pow, Header};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    id: String,
    bytes: String,
    #[serde(rename = "headerWithoutPow")]
    header_without_pow: Option<String>,
}

fn load_vectors(path: &str) -> Vec<HeaderVector> {
    let data = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {path}: {e}"))
}

fn decode_header(v: &HeaderVector) -> Header {
    let bytes = hex::decode(&v.bytes).unwrap();
    let mut reader = VlqReader::new(&bytes);
    read_header(&mut reader).unwrap()
}

fn verify_headers(path: &str) {
    let vectors = load_vectors(path);
    let mut passed = 0;
    let mut failed = 0;

    for v in &vectors {
        let header = decode_header(v);
        assert_eq!(header.height, v.height, "height mismatch for {}", v.id);

        if let Some(ref hwp_hex) = v.header_without_pow {
            let expected = hex::decode(hwp_hex).unwrap();
            let actual =
                serialize_header_without_pow(&header).expect("real mainnet header must serialize");
            assert_eq!(
                actual, expected,
                "headerWithoutPow mismatch at height {} id {}",
                v.height, v.id
            );
        }

        match verify_pow_solution(&header) {
            Ok(()) => passed += 1,
            Err(e) => {
                eprintln!("FAIL: height={} id={} error={}", v.height, v.id, e);
                failed += 1;
            }
        }
    }

    assert_eq!(
        failed,
        0,
        "{failed}/{} headers failed PoW verification in {path}",
        vectors.len()
    );
    eprintln!("{passed}/{} headers passed in {path}", vectors.len());
}

// Default suite runs two curated PoW-solution acceptance witnesses
// (`pow_v1_curated`, `pow_v2_curated`) plus four v2 negative-mutation
// tests against the same curated fixture. Broad-corpus replay
// (`pow_corpus_1_2000` plus the six gitignored mainnet ranges) is
// `#[ignore]`'d and runs via `cargo test ... -- --include-ignored`.
// `load_vectors` is strict on missing fixtures.

/// V1 PoW-solution acceptance against the 10 v1 mainnet headers in
/// `headers_1_10.json`. `verify_pow_solution` covers the EC-equation
/// half of header validation only; difficulty / `nBits` recalculation
/// lives in `tests/difficulty_mainnet.rs` and inline `src/difficulty.rs`.
///
/// Pre-flight pins the fixture to exactly 10 rows with every row a V1
/// solution — any fixture regeneration that drops a row or introduces
/// a v2 variant fails loudly rather than silently degrading the
/// witness.
#[test]
fn pow_v1_curated() {
    let vectors = load_vectors("../test-vectors/mainnet/headers_1_10.json");
    assert_eq!(
        vectors.len(),
        10,
        "headers_1_10.json must contain exactly 10 rows",
    );
    for v in &vectors {
        assert!(
            matches!(decode_header(v).solution, AutolykosSolution::V1 { .. }),
            "headers_1_10.json row h={} must be V1",
            v.height,
        );
    }
    verify_headers("../test-vectors/mainnet/headers_1_10.json");
}

/// V2 PoW-solution acceptance against 5 curated mainnet headers
/// spanning the Autolykos-v2 fork plus later eras: h=417791 (last v1),
/// h=417792 (first v2), 600000 (mid-chain), 1200000 (recent),
/// 1761000 (post-EIP-37). Source: `headers_v2_curated.json`.
///
/// Pre-flight pins the exact 5-height set and the V1/V2 variant at
/// the fork boundary — any fixture regeneration that drops one of
/// these rows fails loudly rather than silently shrinking the span
/// the witness claims to cover.
#[test]
fn pow_v2_curated() {
    let vectors = load_vectors("../test-vectors/mainnet/headers_v2_curated.json");

    // Pin the exact height set, not just len.
    let mut heights: Vec<u32> = vectors.iter().map(|v| v.height).collect();
    heights.sort_unstable();
    assert_eq!(
        heights,
        vec![417_791, 417_792, 600_000, 1_200_000, 1_761_000],
        "headers_v2_curated.json must contain exactly these 5 heights spanning the v2 fork + later eras",
    );

    let h417791 = vectors.iter().find(|v| v.height == 417_791).unwrap();
    assert!(
        matches!(
            decode_header(h417791).solution,
            AutolykosSolution::V1 { .. }
        ),
        "h=417791 must be a V1 solution (last v1 — pre-Autolykos-v2-fork boundary)",
    );

    let h417792 = vectors.iter().find(|v| v.height == 417_792).unwrap();
    assert!(
        matches!(
            decode_header(h417792).solution,
            AutolykosSolution::V2 { .. }
        ),
        "h=417792 must be a V2 solution (first v2 — post-Autolykos-v2-fork boundary)",
    );

    verify_headers("../test-vectors/mainnet/headers_v2_curated.json");
}

/// Number of V2 rows in `headers_v2_curated.json` (5 rows total:
/// h=417791 is V1, the other 4 at h=417792, 600000, 1200000, 1761000
/// are V2). Each v2 negative test below asserts
/// `mutated == EXPECTED_V2_ROWS` so a fixture regeneration that
/// quietly drops a v2 row fails the test.
const EXPECTED_V2_ROWS: usize = 4;

/// V2 PoW rejection witness — mutated nonce against the curated
/// fixture. Mirrors the `--ignored` `negative_bad_nonce_v2` (which
/// needs the gitignored `headers_700000_700500.json` corpus).
#[test]
fn negative_v2_bad_nonce_curated() {
    let vectors = load_vectors("../test-vectors/mainnet/headers_v2_curated.json");
    let mut mutated = 0;
    for v in &vectors {
        let mut header = decode_header(v);
        if let AutolykosSolution::V2 { ref mut nonce, .. } = header.solution {
            nonce[0] ^= 0xFF;
            assert!(
                verify_pow_solution(&header).is_err(),
                "mutated v2 nonce at h={} must be rejected",
                header.height,
            );
            mutated += 1;
        }
    }
    assert_eq!(
        mutated, EXPECTED_V2_ROWS,
        "expected exactly {EXPECTED_V2_ROWS} V2 rows in headers_v2_curated.json (fixture shape regression)",
    );
}

/// V2 PoW rejection witness — corrupted nBits mantissa against the
/// curated fixture. Mirrors the `--ignored` `negative_bad_nbits`.
#[test]
fn negative_v2_bad_nbits_curated() {
    let vectors = load_vectors("../test-vectors/mainnet/headers_v2_curated.json");
    let mut mutated = 0;
    for v in &vectors {
        let mut header = decode_header(v);
        if matches!(header.solution, AutolykosSolution::V2 { .. }) {
            header.n_bits ^= 0x0000_FF00;
            assert!(
                verify_pow_solution(&header).is_err(),
                "mutated v2 nBits at h={} must be rejected",
                header.height,
            );
            mutated += 1;
        }
    }
    assert_eq!(
        mutated, EXPECTED_V2_ROWS,
        "expected exactly {EXPECTED_V2_ROWS} V2 rows",
    );
}

// No `negative_v2_malformed_pk_*` default test exists by design:
// `verify_pow_solution` destructures v2 as `AutolykosSolution::V2
// { pk: _, nonce }` (see `ergo-crypto/src/pow.rs`), and `pk` is not
// part of `header_bytes_without_pow`. The v2 verify path therefore
// never inspects `pk`, so no test exercising `verify_pow_solution`
// alone can pin malformed-pk rejection. The `--ignored`
// `negative_malformed_pk_v2` rejects because it also mutates `nonce`,
// not because pk is validated. v1 malformed-`w` (which IS part of the
// v1 EC equation) is covered by `negative_malformed_w_v1` below.

/// V2 PoW rejection witness — mutated `height` only against the
/// curated fixture. The v2 hit pipeline pulls `header.height` into
/// `calc_n` and the message hash. Height-only mutation isolates the
/// height path so a version-path regression cannot mask itself —
/// paired with `negative_v2_mutated_version_curated` below.
#[test]
fn negative_v2_mutated_height_curated() {
    let vectors = load_vectors("../test-vectors/mainnet/headers_v2_curated.json");
    let mut mutated = 0;
    for v in &vectors {
        let mut header = decode_header(v);
        if matches!(header.solution, AutolykosSolution::V2 { .. }) {
            // Pick a height that is genuinely different from the
            // fixture's real h, regardless of which row we're at.
            let new_height = if v.height == 100_000 {
                200_000
            } else {
                100_000
            };
            header.height = new_height;
            assert!(
                verify_pow_solution(&header).is_err(),
                "v2 header with mutated height (real h={}) must be rejected",
                v.height,
            );
            mutated += 1;
        }
    }
    assert_eq!(
        mutated, EXPECTED_V2_ROWS,
        "expected exactly {EXPECTED_V2_ROWS} V2 rows",
    );
}

/// V2 PoW rejection witness — mutated `version` only against the
/// curated fixture. `header.version` appears in the serialized message
/// via `serialize_header_without_pow`, so a version-only mutation
/// changes `msg` and breaks the v2 hit. Isolates the version path so
/// a height-path regression cannot mask itself — paired with
/// `negative_v2_mutated_height_curated` above.
#[test]
fn negative_v2_mutated_version_curated() {
    let vectors = load_vectors("../test-vectors/mainnet/headers_v2_curated.json");
    let mut mutated = 0;
    for v in &vectors {
        let mut header = decode_header(v);
        if matches!(header.solution, AutolykosSolution::V2 { .. }) {
            // Pick a version different from the real one. Real v2
            // headers in this fixture have version >= 2; bump by 1 to
            // change `msg` without touching height.
            header.version = header.version.wrapping_add(1);
            assert!(
                verify_pow_solution(&header).is_err(),
                "v2 header with mutated version (real h={}) must be rejected",
                v.height,
            );
            mutated += 1;
        }
    }
    assert_eq!(
        mutated, EXPECTED_V2_ROWS,
        "expected exactly {EXPECTED_V2_ROWS} V2 rows",
    );
}

#[test]
#[ignore = "broad corpus replay — 2000-header v1 sweep. Default PoW-solution acceptance witness is `pow_v1_curated`. Run with --include-ignored to replay."]
fn pow_corpus_1_2000() {
    verify_headers("../test-vectors/mainnet/headers_1_2000.json");
}

#[test]
#[ignore = "needs gitignored headers_415000_417791.json — extract via test-vectors/scripts then run with --ignored"]
fn pow_corpus_415000_417791() {
    verify_headers("../test-vectors/mainnet/headers_415000_417791.json");
}

#[test]
#[ignore = "needs gitignored headers_417792_419000.json — extract via test-vectors/scripts then run with --ignored"]
fn pow_corpus_417792_419000() {
    verify_headers("../test-vectors/mainnet/headers_417792_419000.json");
}

#[test]
#[ignore = "needs gitignored headers_600000_601000.json — extract via test-vectors/scripts then run with --ignored"]
fn pow_corpus_600000_601000() {
    verify_headers("../test-vectors/mainnet/headers_600000_601000.json");
}

#[test]
#[ignore = "needs gitignored headers_843000_844672.json — extract via test-vectors/scripts then run with --ignored"]
fn pow_corpus_843000_844672() {
    verify_headers("../test-vectors/mainnet/headers_843000_844672.json");
}

#[test]
#[ignore = "needs gitignored headers_844673_846000.json — extract via test-vectors/scripts then run with --ignored"]
fn pow_corpus_844673_846000() {
    verify_headers("../test-vectors/mainnet/headers_844673_846000.json");
}

#[test]
#[ignore = "needs gitignored headers_1200000_1201000.json — extract via test-vectors/scripts then run with --ignored"]
fn pow_corpus_1200000_1201000() {
    verify_headers("../test-vectors/mainnet/headers_1200000_1201000.json");
}

// --- Negative corpus: mutation-based rejection tests (100+ cases) ---

fn load_v2_headers(n: usize) -> Vec<Header> {
    load_vectors("../test-vectors/mainnet/headers_700000_700500.json")
        .iter()
        .take(n)
        .map(decode_header)
        .collect()
}

fn load_v1_headers(n: usize) -> Vec<Header> {
    load_vectors("../test-vectors/mainnet/headers_1_2000.json")
        .iter()
        .take(n)
        .map(decode_header)
        .collect()
}

// 20 cases: flip nonce bits in v2 headers
#[test]
#[ignore = "load_v2_headers reads gitignored headers_700000_700500.json — run with --ignored"]
fn negative_bad_nonce_v2() {
    for mut header in load_v2_headers(20) {
        if let AutolykosSolution::V2 { ref mut nonce, .. } = header.solution {
            nonce[0] ^= 0xFF;
        }
        assert!(
            verify_pow_solution(&header).is_err(),
            "bad nonce should be rejected at height {}",
            header.height
        );
    }
}

// 20 cases: flip nonce bits in v1 headers
#[test]
fn negative_bad_nonce_v1() {
    for mut header in load_v1_headers(20) {
        if let AutolykosSolution::V1 { ref mut nonce, .. } = header.solution {
            nonce[0] ^= 0xFF;
        }
        assert!(
            verify_pow_solution(&header).is_err(),
            "bad nonce should be rejected at height {}",
            header.height
        );
    }
}

// 20 cases: corrupt nBits mantissa
#[test]
#[ignore = "load_v2_headers reads gitignored headers_700000_700500.json — run with --ignored"]
fn negative_bad_nbits() {
    for mut header in load_v2_headers(20) {
        header.n_bits ^= 0x0000_FF00;
        assert!(
            verify_pow_solution(&header).is_err(),
            "bad nBits should be rejected at height {}",
            header.height
        );
    }
}

// 10 cases: v1 header with mutated `height` rejected — re-serializing
// header-without-pow under the wrong height shifts `msg`, the EC equation
// stops holding, and we surface `InvalidSolution`. Scala parity: the
// validator does NOT enforce version-by-height, so the rejection has to
// fall out of the math, not a gating check.
#[test]
fn negative_v1_header_with_mutated_height_fails_ec_equation() {
    for mut header in load_v1_headers(10) {
        header.height = 500_000;
        assert!(
            verify_pow_solution(&header).is_err(),
            "v1 header with mutated height must fail PoW"
        );
    }
}

// 10 cases: same idea, but mutating both `height` and `version` on a v2
// header. The v2 hit pipeline pulls `header.height` and `header.version`
// into `calc_n` and the message hash, so any mutation breaks the hit.
#[test]
#[ignore = "load_v2_headers reads gitignored headers_700000_700500.json — run with --ignored"]
fn negative_v2_header_with_mutated_height_and_version_fails_hit() {
    for mut header in load_v2_headers(10) {
        header.height = 100_000;
        header.version = 2;
        assert!(
            verify_pow_solution(&header).is_err(),
            "v2 header with mutated height/version must fail PoW"
        );
    }
}

// 10 cases: malformed solution — garbage pk bytes (not a valid curve point)
#[test]
#[ignore = "load_v2_headers reads gitignored headers_700000_700500.json — run with --ignored"]
fn negative_malformed_pk_v2() {
    for mut header in load_v2_headers(10) {
        header.solution = AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0xFF; 33]), // invalid point
            nonce: [0xAA; 8],
        };
        assert!(
            verify_pow_solution(&header).is_err(),
            "malformed pk should be rejected at height {}",
            header.height
        );
    }
}

// 10 cases: malformed v1 solution — garbage w bytes
#[test]
fn negative_malformed_w_v1() {
    for mut header in load_v1_headers(10) {
        if let AutolykosSolution::V1 { ref mut w, .. } = header.solution {
            *w = GroupElement::from_bytes([0xFF; 33]); // invalid point
        }
        assert!(
            verify_pow_solution(&header).is_err(),
            "malformed w should be rejected at height {}",
            header.height
        );
    }
}

// 10 cases: nBits set to adjacent value (off-by-one in exponent)
#[test]
#[ignore = "load_v2_headers reads gitignored headers_700000_700500.json — run with --ignored"]
fn negative_nbits_adjacent_exponent() {
    for mut header in load_v2_headers(10) {
        // Shift the exponent byte by 1 (changes target by factor of 256)
        let exponent = (header.n_bits >> 24) as u8;
        header.n_bits = ((exponent.wrapping_add(1) as u32) << 24) | (header.n_bits & 0x00FF_FFFF);
        assert!(
            verify_pow_solution(&header).is_err(),
            "adjacent-exponent nBits should be rejected at height {}",
            header.height
        );
    }
}

// Total negative cases: 20+20+20+10+10+10+10+10 = 110
