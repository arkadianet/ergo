#![allow(clippy::style, clippy::complexity, clippy::perf)]
//! Regression test: a crafted proof encoding a deep left spine must not drive
//! label computation to the packed depth.
//!
//! `Node::label` used to recurse into both children, so the recursion depth was
//! the depth of the tree — and a verifier's tree is materialised from proof
//! bytes. `reconstruct_tree` evaluates `label(&root)` *before* comparing it
//! against the starting digest, so the attacker needs no valid digest at all:
//! any 33 bytes reach the traversal. The result was a stack overflow, which
//! aborts the process rather than raising a catchable panic.
//!
//! The work runs on a worker with an explicit stack size, so the test measures
//! the implementation rather than the platform's default thread stack — an
//! earlier version keyed off the default and passed at 2 MiB while aborting at
//! 512 KiB.
//!
//! Both bounds below are measured, not guessed:
//!
//! * the recursive `label` exhausted this worker at roughly depth 700, so 2,000
//!   fails loudly if the iterative walk regresses (verified by reverting it);
//! * tearing the `Rc` chain down is still recursive and exhausts this worker at
//!   roughly depth 5,000, so 2,000 stays clear of a limit this test is not
//!   about.
//!
//! A regression aborts the process rather than failing the assertion — that is
//! inherent to testing stack exhaustion, and the abort is the signal.

use bytes::Bytes;
use ergo_avltree::batch_avl_verifier::BatchAVLVerifier;
use std::thread;

mod common;
use common::generate_tree;

const LEAF: u8 = 2;
const LABEL: u8 = 3;
const END_OF_TREE: u8 = 4;

/// Explicit worker stack: small enough to be a meaningful bound, large enough
/// that the depth below is not near the teardown limit.
const WORKER_STACK: usize = 1 << 20; // 1 MiB

/// ~68 KB of proof. See the module comment for why this depth.
const SPINE_DEPTH: usize = 2_000;

fn deep_spine_proof() -> Bytes {
    let mut proof: Vec<u8> = Vec::new();
    proof.push(LEAF);
    proof.extend_from_slice(&[0x10, 0x20, 0xaa]); // key, nextLeafKey, value
    for _ in 0..SPINE_DEPTH {
        proof.push(LABEL);
        proof.extend_from_slice(&[0x11u8; 32]);
        proof.push(0x00); // internal node, balance 0
    }
    proof.push(END_OF_TREE);
    proof.push(0x01); // directions
    Bytes::from(proof)
}

#[test]
fn deep_spine_proof_is_rejected_without_exhausting_the_stack() {
    let worker = thread::Builder::new()
        .stack_size(WORKER_STACK)
        .spawn(|| {
            // 33 arbitrary bytes: the digest comparison is never reached, the
            // traversal that computes the label to compare against it is.
            let v = BatchAVLVerifier::new(
                &Bytes::from(vec![7u8; 33]),
                &deep_spine_proof(),
                generate_tree(1, Some(1)),
                None,
                None,
            );
            assert!(v.is_err(), "deep-spine proof must be rejected");
        })
        .expect("spawn worker");

    worker.join().expect("worker panicked");
}
