//! Scala oracle for the input-block PoW target/verdict functions
//! (`ergo-crypto/src/pow.rs`: `input_block_target`,
//! `input_block_hit_valid`, `header_hit_v2`, `verify_input_block_pow`).
//!
//! `pure_cases` in `pow.json` exercise the target arithmetic and both
//! the strict verifier comparison (`hit < target`, Scala
//! `checkInputBlockPoW`) and the miner's classification boundary
//! (`hit <= target`, Scala `checkNonces`) at the exact boundary values
//! (`target - 1`, `target`, `target + 1`) across several `nBits` /
//! multiplier combinations. Where `hit == input_target` exactly, the
//! two disagree (`verifier_accepts == false`,
//! `miner_classifies_input == true`) — that is upstream finding F2
//! (`<` vs `<=`), recorded in the vector data rather than asserted
//! only in a test.
//!
//! `header_cases` are real mined solutions (found by brute-force
//! nonce search against a tiny-difficulty header in the Scala
//! harness) — one classified by Scala as an ordering-block solution,
//! one as an input-block solution — checked end-to-end through
//! `header_hit_v2` / `verify_input_block_pow` / `verify_pow_solution`.

use ergo_crypto::pow::{
    header_hit_v2, input_block_hit_valid, input_block_target, verify_input_block_pow,
    verify_pow_solution,
};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use num_bigint::BigUint;
use serde::Deserialize;

#[derive(Deserialize)]
struct PowVectors {
    pure_cases: Vec<PureCase>,
    header_cases: Vec<HeaderCase>,
}

#[derive(Deserialize)]
struct PureCase {
    n_bits: u32,
    multiplier: i32,
    hit: String,
    input_target: String,
    verifier_accepts: bool,
    miner_classifies_input: bool,
}

#[derive(Deserialize)]
struct HeaderCase {
    name: String,
    header_hex: String,
    hit: String,
    multiplier: i32,
    input_pow_valid: bool,
    ordering_pow_valid: bool,
}

fn load() -> PowVectors {
    let data = std::fs::read_to_string("../test-vectors/weak-blocks/pow.json")
        .expect("need test-vectors/weak-blocks/pow.json");
    serde_json::from_str(&data).expect("pow.json must parse")
}

#[test]
fn pure_cases_match_scala_target_and_verdicts() {
    let vectors = load();
    assert_eq!(vectors.pure_cases.len(), 60, "expected 60 pure_cases");
    for c in &vectors.pure_cases {
        let hit = BigUint::parse_bytes(c.hit.as_bytes(), 10).expect("hit parses");
        let expected_target =
            BigUint::parse_bytes(c.input_target.as_bytes(), 10).expect("input_target parses");

        let target = input_block_target(c.n_bits, c.multiplier);
        assert_eq!(
            target, expected_target,
            "input_block_target mismatch for n_bits={} multiplier={}",
            c.n_bits, c.multiplier
        );

        let verdict = input_block_hit_valid(&hit, c.n_bits, c.multiplier);
        assert_eq!(
            verdict, c.verifier_accepts,
            "input_block_hit_valid mismatch for n_bits={} multiplier={} hit={}",
            c.n_bits, c.multiplier, c.hit
        );

        // Sanity: the miner's `<=` boundary must not be conflated with
        // the verifier's strict `<` boundary — this is finding F2,
        // and it must be visible here, not just asserted away.
        if c.miner_classifies_input && !c.verifier_accepts {
            assert_eq!(
                hit, expected_target,
                "F2 boundary row must have hit == input_target exactly"
            );
        }
    }
}

#[test]
fn header_cases_match_scala_hit_and_verdicts() {
    let vectors = load();
    assert_eq!(
        vectors.header_cases.len(),
        2,
        "expected both a real input-block and a real ordering-block solution"
    );
    assert!(vectors
        .header_cases
        .iter()
        .any(|c| c.name == "real_input_solution"));
    assert!(vectors
        .header_cases
        .iter()
        .any(|c| c.name == "real_ordering_solution"));

    for c in &vectors.header_cases {
        let bytes = hex::decode(&c.header_hex).expect("header_hex decodes");
        let mut r = VlqReader::new(&bytes);
        let header = read_header(&mut r).expect("header parses");

        let hit = header_hit_v2(&header).expect("v2 header must hash");
        assert_eq!(hit.to_string(), c.hit, "{}: hit mismatch", c.name);

        assert_eq!(
            verify_input_block_pow(&header, c.multiplier).is_ok(),
            c.input_pow_valid,
            "{}: verify_input_block_pow verdict mismatch",
            c.name
        );
        assert_eq!(
            verify_pow_solution(&header).is_ok(),
            c.ordering_pow_valid,
            "{}: verify_pow_solution verdict mismatch",
            c.name
        );
    }
}
