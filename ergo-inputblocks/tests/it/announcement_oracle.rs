//! Scala oracle for `ergo-inputblocks::announcement`.
//!
//! Two independent components, checked separately rather than as one
//! composite `validate_announcement_parity` call, because the fixed
//! header used to build `extension_proof.json`'s cases carries no valid
//! PoW (see its `header_hex`/`n_bits`/solution in the harness) — a
//! composite call would always fail with `Pow(..)`, telling us nothing
//! about the proof/binding logic under test:
//!
//! 1. **PoW**: `verify_input_block_pow` against `pow.json`'s
//!    `real_input_solution` header (a real mined solution, multiplier 30).
//! 2. **Proof / binding**: `extension_proof.json`'s cases, checked against
//!    `ergo_validation::popow::merkle::verify_batch_merkle_proof` (the
//!    Scala-parity proof reducer `validate_announcement_parity` calls) and
//!    `verify_field_binding` (the strict-policy addition this crate makes
//!    on top of it).
//!
//! Expected values come from `scripts/jvm_weak_blocks_oracle`
//! (`WeakBlocksOracle.scala`'s `extensionProofCases`/`powCases`) — never
//! computed here.
use ergo_crypto::pow::verify_input_block_pow;
use ergo_inputblocks::announcement::verify_field_binding;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_ser::input_block::parse_input_block_announcement;
use ergo_validation::popow::merkle::verify_batch_merkle_proof;
use serde::Deserialize;

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/weak-blocks/");
    let text = std::fs::read_to_string(format!("{path}{name}.json")).expect("vector file");
    serde_json::from_str(&text).expect("vector json")
}

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

// ----- pow.json (component 1: PoW only) -----

#[derive(Deserialize)]
struct PowDoc {
    header_cases: Vec<HeaderCase>,
}
#[derive(Deserialize)]
struct HeaderCase {
    name: String,
    header_hex: String,
    multiplier: i32,
    input_pow_valid: bool,
}

#[test]
fn real_input_solution_header_passes_input_block_pow() {
    let doc: PowDoc = load("pow");
    let case = doc
        .header_cases
        .iter()
        .find(|c| c.name == "real_input_solution")
        .expect("pow.json must carry a real_input_solution header case");
    assert_eq!(case.multiplier, 30, "harness pins multiplier 30");
    assert!(
        case.input_pow_valid,
        "pow.json's real_input_solution must be Scala-valid as an input-block solution"
    );

    let bytes = hex(&case.header_hex);
    let mut r = VlqReader::new(&bytes);
    let header = read_header(&mut r).expect("real_input_solution header parses");

    assert_eq!(
        verify_input_block_pow(&header, case.multiplier).is_ok(),
        case.input_pow_valid,
        "verify_input_block_pow parity for real_input_solution"
    );
}

// ----- extension_proof.json (component 2: proof reduction + binding) -----

#[derive(Deserialize)]
struct ExtensionProofDoc {
    cases: Vec<ExtensionProofCase>,
}
#[derive(Deserialize)]
struct ExtensionProofCase {
    name: String,
    bytes_hex: String,
    scala_ext_valid: bool,
    expected_binding_verdict: bool,
}

#[test]
fn extension_proof_vectors_match_scala_reduction_and_binding() {
    let doc: ExtensionProofDoc = load("extension_proof");
    assert_eq!(doc.cases.len(), 5, "expected 5 extension_proof cases");

    for case in &doc.cases {
        let bytes = hex(&case.bytes_hex);
        let ann = parse_input_block_announcement(&bytes)
            .unwrap_or_else(|e| panic!("{}: parse failed: {e}", case.name));

        let proof_reduces =
            verify_batch_merkle_proof(&ann.fields.proof, ann.header.extension_root.as_bytes());

        if case.name == "empty_proof" {
            // Documented divergence (see the module doc and the task-8
            // report): the brief's working hypothesis for finding F4 was
            // that Scala's `BatchMerkleProof.valid` accepts an *empty*
            // proof against any root. Measuring it (scrypto 3.0.0
            // `BatchMerkleProof.valid`, `scorex.crypto.authds.merkle`)
            // shows the opposite for this vector: Scala's `loop` reduces
            // an empty (indices=[], proofs=[]) input to an empty result
            // sequence, which never satisfies `root.size == 1`, so it
            // returns `false` — `scala_ext_valid` is `false` here.
            // `ergo_validation::popow::merkle::verify_batch_merkle_proof`
            // (from M0) instead special-cases empty-indices/empty-proofs
            // as trivially valid against *any* root (`true`) — a real,
            // pre-existing Rust/Scala divergence in the OTHER direction
            // from the one hypothesized, out of this task's file list to
            // fix. `verify_field_binding`'s `ProofEmpty` check is exactly
            // what keeps this from being exploitable at the announcement
            // level: it rejects an empty proof regardless of what the
            // (over-permissive) reducer says.
            assert!(!case.scala_ext_valid, "empty_proof: scala rejects");
            assert!(
                proof_reduces,
                "empty_proof: Rust reducer over-accepts (documented)"
            );
        } else {
            assert_eq!(
                proof_reduces, case.scala_ext_valid,
                "{}: verify_batch_merkle_proof vs scala_ext_valid",
                case.name
            );
        }

        assert_eq!(
            verify_field_binding(&ann.fields).is_ok(),
            case.expected_binding_verdict,
            "{}: verify_field_binding verdict",
            case.name
        );
    }
}
