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
//!    `verify_extension_proof` (`validate_announcement_parity`'s proof
//!    component — the empty-proof-guarded, Scala-parity check) and
//!    `verify_field_binding` (the strict-policy addition this crate makes
//!    on top of it).
//!
//! Expected values come from `scripts/jvm_weak_blocks_oracle`
//! (`WeakBlocksOracle.scala`'s `extensionProofCases`/`powCases`) — never
//! computed here.
use ergo_crypto::pow::verify_input_block_pow;
use ergo_inputblocks::announcement::{verify_extension_proof, verify_field_binding};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_ser::input_block::parse_input_block_announcement;
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

        // `verify_extension_proof` is `validate_announcement_parity`'s proof
        // component, tested here in isolation (the fixed header these
        // vectors use has no valid PoW, so a call to the full function
        // would only ever report `Pow(..)`). Asserted uniformly across
        // every case, including `empty_proof`: `verify_extension_proof`
        // rejects an empty proof before ever calling the shared popow
        // reducer (which would otherwise accept it against any root),
        // matching scrypto's real `BatchMerkleProof.valid` — see the
        // crate doc and findings-8-r1.md finding 1.
        assert_eq!(
            verify_extension_proof(&ann.fields, ann.header.extension_root.as_bytes()).is_ok(),
            case.scala_ext_valid,
            "{}: verify_extension_proof vs scala_ext_valid",
            case.name
        );

        assert_eq!(
            verify_field_binding(&ann.fields).is_ok(),
            case.expected_binding_verdict,
            "{}: verify_field_binding verdict",
            case.name
        );
    }
}
