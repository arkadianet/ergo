//! Phase-1 oracle-free differential for the AVL verifier panic guard.
//!
//! Asserts two safety properties of `ergo_sigma::avl::AvlVerifier` (the guarded
//! wrapper) against the RAW `ergo_avltree_rust::BatchAVLVerifier` it wraps,
//! across a deterministic fuzz of random trees and valid/adversarial proofs:
//!
//!   1. FAITHFUL — on every input where the raw crate does NOT panic, the
//!      wrapper returns the same op success/failure AND the same digest. The
//!      guard changes nothing for honest inputs.
//!   2. FAIL CLOSED — on every input where the raw crate PANICS (the consensus
//!      DoS class: a structurally-valid-but-wrong proof), the wrapper instead
//!      returns a failure AND `digest()` is `None` (poisoned) — never a panic
//!      escaping to the caller, never a half-mutated digest. This mirrors Scala's
//!      `Try` boundary (`topNode = None` after a failed op).
//!
//! This is oracle-FREE: panic-containment and wrapper/raw faithfulness are
//! safety properties of the fix, not a claim about Scala parity. The Scala
//! differential (does the Rust fail-closed set match the Scala verifier's?) is a
//! separate committed-vector test — see `avl_scala_oracle_parity.rs`.
//!
//! The fuzz is self-validating: it asserts it actually drove the raw crate into
//! a panic at least once, so a future change that silently stops reaching the
//! panic class (making the test vacuous) fails loudly.

use bytes::Bytes;
use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
use ergo_avltree_rust::batch_avl_verifier::BatchAVLVerifier;
use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
use ergo_avltree_rust::operation::{KeyValue, Operation};
use ergo_sigma::avl::AvlVerifier;
use std::panic::{catch_unwind, AssertUnwindSafe};

// ----- helpers -----

/// Deterministic SplitMix64 — same generator family `ergo-difftest` uses, so a
/// `(seed)` fully reproduces a run with no external rand dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send>;

/// RAII silencer for the process panic hook. We deliberately drive the raw crate
/// into its known panics thousands of times; without this the run floods stderr.
struct SilenceHook(Option<PanicHook>);

impl SilenceHook {
    fn install() -> Self {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        SilenceHook(Some(prev))
    }
}

impl Drop for SilenceHook {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            std::panic::set_hook(prev);
        }
    }
}

fn new_prover() -> BatchAVLProver {
    let tree = AVLTree::new(
        |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
        32,
        None,
    );
    BatchAVLProver::new(tree, true)
}

/// A random 32-byte key that avoids the all-`0x00` / all-`0xFF` sentinels the
/// prover rejects.
fn rand_key(rng: &mut SplitMix64) -> [u8; 32] {
    let mut k = [0u8; 32];
    for chunk in k.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes()[..chunk.len()]);
    }
    if k == [0u8; 32] || k == [0xFFu8; 32] {
        k[0] ^= 0x55;
    }
    k
}

#[derive(Clone)]
enum Op {
    Lookup([u8; 32]),
    Remove([u8; 32]),
    Insert([u8; 32], Vec<u8>),
}

impl Op {
    fn as_operation(&self) -> Operation {
        match self {
            Op::Lookup(k) => Operation::Lookup(Bytes::from(k.to_vec())),
            Op::Remove(k) => Operation::Remove(Bytes::from(k.to_vec())),
            Op::Insert(k, v) => Operation::Insert(KeyValue {
                key: Bytes::from(k.to_vec()),
                value: Bytes::from(v.clone()),
            }),
        }
    }
    fn pick(rng: &mut SplitMix64, keys: &[[u8; 32]]) -> Op {
        // Bias the key toward an existing tree key half the time so removes /
        // lookups land on the witnessed access path (and drive deleteMax).
        let key = if !keys.is_empty() && rng.coin() {
            keys[rng.below(keys.len() as u64) as usize]
        } else {
            rand_key(rng)
        };
        match rng.below(3) {
            0 => Op::Lookup(key),
            1 => Op::Remove(key),
            _ => Op::Insert(key, vec![0xAB, 0xCD]),
        }
    }
}

/// Run `op` against a fresh RAW `BatchAVLVerifier` built from `(start, proof)`,
/// catching any panic. `None` = the raw crate panicked. `Some((ok, digest))` =
/// it completed with op-success `ok` and resulting `digest`.
fn run_raw(start: &[u8], proof: &[u8], op: &Op) -> Option<(bool, Option<Vec<u8>>)> {
    catch_unwind(AssertUnwindSafe(|| {
        let mut bv = match BatchAVLVerifier::new(
            &Bytes::from(start.to_vec()),
            &Bytes::from(proof.to_vec()),
            AVLTree::new(
                |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
                32,
                None,
            ),
            None,
            None,
        ) {
            Ok(bv) => bv,
            Err(_) => return (false, None),
        };
        let ok = bv.perform_one_operation(&op.as_operation()).is_ok();
        let digest = bv.digest().map(|d| d.to_vec());
        (ok, digest)
    }))
    .ok()
}

/// Run `op` against a fresh guarded `AvlVerifier`. `None` = a panic ESCAPED the
/// wrapper (a fix failure). `Some((ok, digest))` = the wrapper contained it.
fn run_wrapped(start: &[u8], proof: &[u8], op: &Op) -> Option<(bool, Option<Vec<u8>>)> {
    catch_unwind(AssertUnwindSafe(|| {
        let mut w = match AvlVerifier::new(start, proof, 32, None) {
            Ok(w) => w,
            Err(_) => return (false, None),
        };
        let ok = match op {
            Op::Lookup(k) => w.lookup(k).is_ok(),
            Op::Remove(k) => w.remove(k).is_ok(),
            Op::Insert(k, v) => w.insert(k, v).is_ok(),
        };
        (ok, w.digest())
    }))
    .ok()
}

/// Build a tree of `keys`, capture the starting digest, apply `proof_op` to the
/// prover, and return `(start_digest, proof_bytes)`. The proof witnesses
/// `proof_op`; the test then VERIFIES a possibly-different op against it.
fn make_case(keys: &[[u8; 32]], proof_op: &Op) -> (Vec<u8>, Vec<u8>) {
    let mut prover = new_prover();
    for k in keys {
        let _ = prover.perform_one_operation(&Operation::Insert(KeyValue {
            key: Bytes::from(k.to_vec()),
            value: Bytes::from(vec![0xABu8, 0xCD]),
        }));
    }
    let _ = prover.generate_proof();
    let start = prover.digest().expect("prover digest").to_vec();
    // Apply the proof-op (may legitimately fail, e.g. insert-existing); the
    // generated proof then witnesses whatever access path was walked.
    let _ = prover.perform_one_operation(&proof_op.as_operation());
    let proof = prover.generate_proof().to_vec();
    (start, proof)
}

// ----- error paths -----

#[test]
fn guarded_verifier_is_faithful_and_fails_closed_vs_raw_crate() {
    let _silence = SilenceHook::install();
    let mut rng = SplitMix64(0xA5A5_1234_DEAD_BEEF);

    const ITERS: usize = 4000;
    let mut raw_panics = 0usize;
    let mut compared = 0usize;

    for i in 0..ITERS {
        let n = 1 + rng.below(8);
        let keys: Vec<[u8; 32]> = (0..n).map(|_| rand_key(&mut rng)).collect();
        let proof_op = Op::pick(&mut rng, &keys);
        let verify_op = Op::pick(&mut rng, &keys);

        let (start, proof) = make_case(&keys, &proof_op);

        let raw = run_raw(&start, &proof, &verify_op);
        let wrapped = run_wrapped(&start, &proof, &verify_op);

        // (1) A panic must NEVER escape the wrapper.
        let (w_ok, w_digest) = match wrapped {
            Some(v) => v,
            None => panic!(
                "iter {i}: a panic ESCAPED AvlVerifier — the guard has a gap. \
                 seed=0xA5A51234DEADBEEF n={n}"
            ),
        };

        match raw {
            // (2) Raw panicked → wrapper must fail closed: Err + no digest.
            None => {
                raw_panics += 1;
                assert!(
                    !w_ok && w_digest.is_none(),
                    "iter {i}: raw crate panicked but wrapper did not fail closed \
                     (ok={w_ok}, digest={:?}) — poisoning is broken",
                    w_digest.as_ref().map(hex::encode),
                );
            }
            // (3) Raw completed → wrapper must be byte-identical (faithful).
            Some((r_ok, r_digest)) => {
                compared += 1;
                assert_eq!(
                    (w_ok, &w_digest),
                    (r_ok, &r_digest),
                    "iter {i}: wrapper diverged from the raw crate on a non-panicking input",
                );
            }
        }
    }

    // Non-vacuity: the fuzz MUST have exercised the panic→fail-closed path,
    // otherwise it proves nothing about the guard.
    assert!(
        raw_panics > 0,
        "fuzz never triggered a raw-crate panic in {ITERS} iters — it is not \
         exercising the guard; broaden generation",
    );
    // And it must have compared genuine non-panic agreement too.
    assert!(compared > 0, "fuzz never hit a non-panicking comparison");
    eprintln!("differential: {compared} faithful comparisons, {raw_panics} fail-closed (raw-panic) cases over {ITERS} iters");
}
