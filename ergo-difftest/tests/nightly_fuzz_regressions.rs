//! Pin the nightly fuzz crashers from run 31147270919.
//!
//! After the Bug #19 harness exemption + Unparsed self-delimitation write
//! guard + 0x83↔0x85 PartialEq fix, these must not report `Outcome::Bug`.

use ergo_difftest::{run_input, Outcome};

fn assert_outcome(surface: &str, hex: &str, expected: Outcome) {
    let bytes = hex::decode(hex).unwrap_or_else(|e| panic!("{surface}: bad hex: {e}"));
    let results = run_input(&bytes, Some(surface));
    assert_eq!(results.len(), 1, "{surface}: expected one surface result");
    let (name, outcome) = &results[0];
    assert_eq!(*name, surface);
    assert_eq!(
        *outcome, expected,
        "{surface}: expected {expected:?} for {hex}, got {outcome:?}"
    );
}

#[test]
fn ergo_tree_empty_unparsed_is_write_rejected() {
    // cargo-fuzz ergo_tree: empty Unparsed propositionBytes
    assert_outcome(
        "ergo_tree",
        "2afaffffff0fd614f20272fad614f20272042a66042a66d684",
        Outcome::WriteRejected,
    );
}

#[test]
fn ergo_tree_mid_vlq_cut_is_write_rejected() {
    // Near-miss of the empty case: declared size -1 → mid-VLQ Unparsed region
    assert_outcome("ergo_tree", "08ffffffff0f0204", Outcome::WriteRejected);
    assert_outcome("ergo_tree", "08feffffff0f0204", Outcome::WriteRejected);
}

#[test]
fn sigma_expr_empty_bool_collection_accepted() {
    // cargo-fuzz sigma_expr: 0x83 empty Coll[Boolean] packs to 0x85
    assert_outcome(
        "sigma_expr",
        "1005040004000e36100204a00bffffffffffffffffffffac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683000193c2b2a573010074730293c2b2a57301007473027303238301087304",
        Outcome::Accepted,
    );
}

#[test]
fn corpus_mutation_structure_changed_sample_accepted() {
    assert_outcome(
        "ergo_tree",
        "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683000193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304",
        Outcome::Accepted,
    );
    assert_outcome(
        "sigma_expr",
        "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683000193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304",
        Outcome::Accepted,
    );
}

#[test]
fn ergo_box_candidate_size_zero_unparsed_not_bug() {
    // cargo-fuzz ergo_box_candidate: size-0 Unparsed + non-canonical height
    // → Bug #19 reshape on re-decode. Consensus writers still emit verbatim;
    // harness classifies as WriteRejected.
    assert_outcome(
        "ergo_box_candidate",
        "00eb00e4da0000001a0000000000000000001a000000000000001ae4e4",
        Outcome::WriteRejected,
    );
}

#[test]
fn ergo_box_candidate_declared_size_one_reshape_not_bug() {
    // Declared size ≥ 1 wrap→structural flip (Kimi audit Finding 1b)
    assert_outcome(
        "ergo_box_candidate",
        "0108018c81000000",
        Outcome::WriteRejected,
    );
}

#[test]
fn transaction_size_zero_unparsed_not_bug() {
    assert_outcome(
        "transaction",
        "01b69575e11c0200feffffff5976ee0d6245a1168396b2e2a4f384691f275d501c000000000280b48128cb00f30000000008040900000000000000169900b5be00000a",
        Outcome::WriteRejected,
    );
}
