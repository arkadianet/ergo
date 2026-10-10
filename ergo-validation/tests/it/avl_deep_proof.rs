//! Deep AVL proofs fail closed through full transaction validation.
//!
//! Fixture `test-vectors/ergo-validation/avl_deep_proof_txs.json` holds two
//! captured transactions spending a box whose script is
//! `sigmaProp(!SELF.R4[AvlTree].get.contains(Coll(1), getVar[Coll[Byte]](0).get))`,
//! with context variable 0 a left-spine proof of 3,000 and 21,800 levels. The
//! tree digest does not match the proof, so `contains` is false and the spend
//! is valid whenever the proof can be verified at all. The 21,800-level entry
//! is rejected by the reference verdict captured with it.
//!
//! Each case runs in a child process on a thread with the node's validation
//! stack, so a stack overflow fails the case instead of aborting the test
//! binary.

use crate::santa_tx::{validate, NodeVerdict};
use ergo_ser::decode_stack::DECODE_THREAD_STACK_BYTES;
use ergo_sigma::avl::MAX_SCRIPT_AVL_PROOF_HEIGHT;
use serde_json::Value as J;

// ----- helpers -----

const CHILD_ENV: &str = "ERGO_VALIDATION_DEEP_AVL_CHILD";

fn fixture_entry(name: &str) -> J {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/ergo-validation/avl_deep_proof_txs.json"
    );
    let doc: J = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("fixture entry {name}"))
        .clone()
}

/// The left-spine proof the fixtures carry: keyLength 1, empty values.
fn spine_proof(depth: usize) -> Vec<u8> {
    let mut proof = vec![2u8, 0, 1];
    for _ in 0..depth {
        proof.extend_from_slice(&[2, 1, 0]);
    }
    proof.extend_from_slice(&[4, 0]);
    proof
}

fn vlq(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// The 3,000-level fixture with its proof replaced by one of `depth` levels.
fn entry_with_depth(depth: usize) -> J {
    let mut entry = fixture_entry("avl-deep-3000");
    let tx = hex::decode(entry["tx_bytes_hex"].as_str().unwrap()).unwrap();
    let old = spine_proof(3_000);
    let mut old_value = vec![0x0E]; // Coll[Byte] constant
    old_value.extend(vlq(old.len()));
    old_value.extend_from_slice(&old);
    let at = tx
        .windows(old_value.len())
        .position(|w| w == old_value.as_slice())
        .expect("fixture carries the 3,000-level proof");
    let new = spine_proof(depth);
    let mut rebuilt = tx[..at].to_vec();
    rebuilt.push(0x0E);
    rebuilt.extend(vlq(new.len()));
    rebuilt.extend_from_slice(&new);
    rebuilt.extend_from_slice(&tx[at + old_value.len()..]);
    entry["tx_bytes_hex"] = J::String(hex::encode(rebuilt));
    entry
}

/// Run `body` on a validation-stack thread inside a child process that
/// re-runs only `test_path`; the parent passes once the child passed.
fn run_isolated(test_path: &str, body: fn()) {
    if std::env::var_os(CHILD_ENV).is_some() {
        std::thread::Builder::new()
            .stack_size(DECODE_THREAD_STACK_BYTES)
            .spawn(body)
            .expect("spawn validation-stack thread")
            .join()
            .expect("deep AVL proof case");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([test_path, "--exact", "--test-threads=1", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("run child test process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child run of {test_path} failed ({}):\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_accepted(entry: &J) {
    match validate(entry).expect("fixture setup") {
        NodeVerdict::Accept(_) => {}
        NodeVerdict::Reject(reason) => panic!("expected accept, got reject: {reason}"),
    }
}

fn assert_rejected_as_too_tall(entry: &J) {
    match validate(entry).expect("fixture setup") {
        NodeVerdict::Reject(reason) => assert!(
            reason.contains("taller than the script-level bound"),
            "expected a script error for the proof height, got: {reason}"
        ),
        NodeVerdict::Accept(cost) => panic!("expected reject, got accept at cost {cost}"),
    }
}

// ----- happy path -----

#[test]
fn deep_avl_proof_at_script_bound_is_verified() {
    assert_eq!(MAX_SCRIPT_AVL_PROOF_HEIGHT, 12_000);
    run_isolated(
        "avl_deep_proof::deep_avl_proof_at_script_bound_is_verified",
        || assert_accepted(&entry_with_depth(MAX_SCRIPT_AVL_PROOF_HEIGHT)),
    );
}

#[test]
fn moderate_depth_avl_proof_fixture_is_verified() {
    run_isolated(
        "avl_deep_proof::moderate_depth_avl_proof_fixture_is_verified",
        || assert_accepted(&fixture_entry("avl-deep-3000")),
    );
}

// ----- error paths -----

#[test]
fn deep_avl_proof_above_script_bound_fails_closed() {
    run_isolated(
        "avl_deep_proof::deep_avl_proof_above_script_bound_fails_closed",
        || assert_rejected_as_too_tall(&entry_with_depth(MAX_SCRIPT_AVL_PROOF_HEIGHT + 1)),
    );
}

#[test]
fn deep_avl_proof_fixture_fails_closed() {
    run_isolated(
        "avl_deep_proof::deep_avl_proof_fixture_fails_closed",
        || assert_rejected_as_too_tall(&fixture_entry("avl-deep-21800")),
    );
}
