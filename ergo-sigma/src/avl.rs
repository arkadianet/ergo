//! Thin wrapper around `ergo_avltree_rust` for AVL+ tree proof verification.
//!
//! All `ergo_avltree_rust` imports are confined to this module, providing a
//! single dependency boundary for the evaluator. The crate is a pure-Rust
//! implementation of the Scorex authenticated AVL+ tree and is intentionally
//! accepted as a runtime consensus dependency (not sigma-rust).
//!
//! Operations supported: lookup, update, insert, digest extraction.

use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
use ergo_avltree_rust::batch_avl_verifier::BatchAVLVerifier;
use ergo_avltree_rust::batch_node::{AVLTree, Node, NodeHeader};
use ergo_avltree_rust::operation::{KeyValue, Operation};
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};

thread_local! {
    /// Armed while an AVL verifier operation runs inside its panic guard. The
    /// node's global panic hook reads this (via [`in_expected_avl_panic`]) to
    /// recognise an EXPECTED, already-contained AVL verifier panic — a
    /// malformed attacker-supplied proof — and suppress the alarming
    /// "node panicked" error log, so a flood of crafted transactions cannot
    /// amplify into a log-flood DoS. The rejection itself stays observable on
    /// the validation path.
    static IN_AVL_GUARD: Cell<bool> = const { Cell::new(false) };
}

/// True when the current thread is inside a guarded AVL verifier operation.
/// The node's global panic hook calls this to suppress the log for an expected,
/// contained AVL verifier panic (see [`AvlVerifier::guarded`]).
pub fn in_expected_avl_panic() -> bool {
    IN_AVL_GUARD.with(|f| f.get())
}

/// RAII: arm `IN_AVL_GUARD` for the duration of a guarded op and restore the
/// previous value on drop (drop runs after `catch_unwind` returns, since the
/// guard's own frame does not unwind).
struct AvlGuard {
    prev: bool,
}

impl AvlGuard {
    fn arm() -> Self {
        AvlGuard {
            prev: IN_AVL_GUARD.with(|f| f.replace(true)),
        }
    }
}

impl Drop for AvlGuard {
    fn drop(&mut self) {
        IN_AVL_GUARD.with(|f| f.set(self.prev));
    }
}

/// Opaque handle to a BatchAVLVerifier from `ergo_avltree_rust`.
///
/// Operation methods return `Result<_, ()>` because the underlying crate's
/// error types are opaque — callers map failures to their own error type.
///
/// Wraps the verifier so the evaluator does not need direct imports from
/// the underlying crate. All proof verification operations go through
/// this type's methods.
///
/// The inner verifier is an `Option` so it can be POISONED. `ergo_avltree_rust`
/// `panic!`s (rather than returning `Err`) on a structurally-valid-but-wrong
/// proof — e.g. a lookup proof supplied where a remove proof belongs — at
/// several op-time sites (`authenticated_tree_ops.rs` 413/431/635/...). The
/// Scala reference throws the same error but catches it in an enclosing `Try`,
/// so the operation fails and the transaction is invalid while the node
/// survives. [`AvlVerifier::guarded`] restores that fail-closed parity: a caught
/// panic drops the inner verifier (`None`), and every later op — including
/// [`AvlVerifier::digest`] — then fails, exactly as Scala's `topNode = None`
/// does after a failed op. Reading a digest from a half-mutated verifier would
/// be an accept-invalid divergence (a fork), strictly worse than the crash, so
/// poisoning is load-bearing, not cosmetic.
pub struct AvlVerifier(Option<BatchAVLVerifier>);

// `clippy::result_unit_err`: the underlying `ergo_avltree_rust` crate
// returns opaque errors from `perform_one_operation`; collapsing to
// `Result<_, ()>` at this boundary lets callers map the failure into
// their own error type without leaking the upstream type.
#[allow(clippy::result_unit_err)]
impl AvlVerifier {
    /// Construct from raw AVL tree parameters and proof bytes.
    ///
    /// `digest`: 33-byte tree digest (32 bytes + 1 height byte).
    /// `proof`: serialized batch proof bytes.
    /// `key_length`: fixed key length in bytes.
    /// `value_length_opt`: optional fixed value length.
    pub fn new(
        digest: &[u8],
        proof: &[u8],
        key_length: usize,
        value_length_opt: Option<usize>,
    ) -> Result<Self, String> {
        let digest = bytes::Bytes::from(digest.to_vec());
        let proof = bytes::Bytes::from(proof.to_vec());
        BatchAVLVerifier::new(
            &digest,
            &proof,
            AVLTree::new(
                |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
                key_length,
                value_length_opt,
            ),
            None,
            None,
        )
        .map(|v| AvlVerifier(Some(v)))
        .map_err(|e| format!("{e}"))
    }

    /// Run `f` against the wrapped verifier, isolating any panic from the
    /// upstream `ergo_avltree_rust` crate into the fail-closed `Err(())` path.
    ///
    /// The crate `panic!`s on a structurally-valid-but-wrong proof at op time
    /// (see the type doc). This restores Scala's `Try`-boundary semantics: a
    /// caught panic POISONS the verifier (the inner value was moved into the
    /// unwinding closure and dropped, so `self.0` stays `None`) and surfaces
    /// `Err(())`. A verifier already poisoned by an earlier caught panic stays
    /// failed. A clean (non-panicking) `Err` from the crate is returned
    /// unchanged and does NOT poison — existing, oracle-verified behaviour is
    /// untouched; only the previously-undefined panic case changes.
    ///
    /// Relies on `panic = "unwind"` (enforced by a compile guard in `lib.rs`):
    /// `catch_unwind` cannot catch an aborting panic.
    fn guarded<R>(
        &mut self,
        f: impl FnOnce(&mut BatchAVLVerifier) -> Result<R, ()>,
    ) -> Result<R, ()> {
        // Already poisoned by an earlier caught panic → stay failed.
        let mut bv = match self.0.take() {
            Some(bv) => bv,
            None => return Err(()),
        };
        // `AssertUnwindSafe` is justified: `bv` is owned (not shared, no locks),
        // and on panic it is dropped during unwinding — no broken invariant is
        // ever observed, because the verifier is never reused after a panic.
        let _guard = AvlGuard::arm();
        match catch_unwind(AssertUnwindSafe(move || {
            let r = f(&mut bv);
            (bv, r)
        })) {
            // Op completed (Ok, or a clean crate Err) → keep the verifier.
            Ok((bv, r)) => {
                self.0 = Some(bv);
                r
            }
            // Panicked: `bv` was moved into the closure and dropped while
            // unwinding; `self.0` stays `None` (poisoned) and we fail closed.
            Err(_) => Err(()),
        }
    }

    /// Single-key lookup. Returns the value bytes if found.
    pub fn lookup(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            match bv.perform_one_operation(&Operation::Lookup(bytes::Bytes::from(key.to_vec()))) {
                Ok(Some(v)) => Ok(Some(v.to_vec())),
                Ok(None) => Ok(None),
                Err(_) => Err(()),
            }
        })
    }

    /// Update an existing key with a new value. Returns Ok(true) on success.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::Update(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|_| ())
            .map_err(|_| ())
        })
    }

    /// Insert a new key-value pair. Returns Ok(()) on success.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::Insert(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|_| ())
            .map_err(|_| ())
        })
    }

    /// Insert a new entry OR overwrite an existing one for the same
    /// key. Backs the EIP-50 v6 `SAvlTree.insertOrUpdate` MethodCall
    /// (Scala `SAvlTreeMethods.insertOrUpdateMethod` at
    /// `methods.scala:1671-1686`). Returns Ok(()) on success.
    pub fn insert_or_update(&mut self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::InsertOrUpdate(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|_| ())
            .map_err(|_| ())
        })
    }

    /// Remove a key from the tree. Returns Ok(()) on success.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::Remove(bytes::Bytes::from(key.to_vec())))
                .map(|_| ())
                .map_err(|_| ())
        })
    }

    /// Remove a key AND report whether the key was present in the
    /// tree according to the proof. Distinguishes the two failure
    /// classes the wrapping caller needs to separate:
    ///
    /// - `Ok(true)`: the proof asserted the key was present, the
    ///   Remove succeeded, and the digest advanced.
    /// - `Ok(false)`: the proof asserted the key was NOT in the
    ///   tree; the Remove is a no-op success. Cryptographically
    ///   definitive evidence the input doesn't exist — callers
    ///   classify this as "input absent per proof", not "verifier
    ///   failure".
    /// - `Err(())`: the verifier itself failed (witness missing
    ///   for the access path, malformed envelope partway through,
    ///   etc.). Opaque from this side; treat as session-scoped.
    pub fn remove_with_presence(&mut self, key: &[u8]) -> Result<bool, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::Remove(bytes::Bytes::from(key.to_vec())))
                .map(|opt| opt.is_some())
                .map_err(|_| ())
        })
    }

    /// Remove a key AND return the old value the proof witnessed — the
    /// serialized bytes of the box being spent. `Ok(Some(bytes))` is a
    /// present-key remove (the digest advances); `Ok(None)` is an
    /// explicit non-membership witness; `Err(())` is an opaque verifier
    /// failure. The digest-mode validator needs the old value to
    /// resolve spent input boxes from the ADProofs (Scala's
    /// `proofs.verify` returns these), so this variant keeps the value
    /// that `remove_with_presence` discards.
    pub fn remove_returning_value(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::Remove(bytes::Bytes::from(key.to_vec())))
                .map(|opt| opt.map(|v| v.to_vec()))
                .map_err(|_| ())
        })
    }

    /// Extract the updated tree digest after mutations.
    /// Returns the 33-byte digest (32 hash bytes + 1 height byte).
    ///
    /// Returns `None` if the verifier was poisoned by a caught op-time panic
    /// (Scala parity: a failed op yields `topNode = None`, so no digest leaks).
    pub fn digest(&self) -> Option<Vec<u8>> {
        self.0
            .as_ref()
            .and_then(|bv| bv.digest())
            .map(|d| d.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
    use ergo_avltree_rust::batch_node::{AVLTree as ProverTree, Node, NodeHeader};
    use ergo_avltree_rust::operation::{KeyValue as ProverKv, Operation as ProverOp};

    // ----- helpers -----

    fn new_prover() -> BatchAVLProver {
        let tree = ProverTree::new(
            |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
            32,
            None,
        );
        BatchAVLProver::new(tree, true)
    }

    fn prover_digest(prover: &mut BatchAVLProver) -> Vec<u8> {
        prover.digest().expect("prover digest").to_vec()
    }

    fn pk(key: [u8; 32], value: Vec<u8>) -> ProverKv {
        ProverKv {
            key: bytes::Bytes::from(key.to_vec()),
            value: bytes::Bytes::from(value),
        }
    }

    // ----- happy path -----

    #[test]
    fn remove_with_presence_present_key_returns_true() {
        // Stand up a prover with one box; capture the parent
        // digest; then perform a Remove on that key and grab
        // the witness. Feed the witness into AvlVerifier and
        // confirm `remove_with_presence` returns Ok(true) —
        // proof asserted membership.
        let mut prover = new_prover();
        let key = [0x42u8; 32];
        prover
            .perform_one_operation(&ProverOp::Insert(pk(key, vec![0x01])))
            .expect("seed insert");
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        prover
            .perform_one_operation(&ProverOp::Remove(bytes::Bytes::from(key.to_vec())))
            .expect("prover remove");
        let proof = prover.generate_proof().to_vec();
        let mut verifier =
            AvlVerifier::new(&parent, &proof, 32, None).expect("verifier construction");
        let result = verifier.remove_with_presence(&key);
        assert_eq!(result, Ok(true), "present-key remove must return Ok(true)");
    }

    // ----- error paths -----

    #[test]
    fn remove_with_presence_uncovered_key_returns_err() {
        // The witness covers `covered_key`, but the caller
        // queries a DIFFERENT key. The upstream verifier has
        // no access path for it and returns Err — the wrapper
        // surfaces that as `Err(())`. This is the realistic
        // session-scoped failure class (distinct from the
        // unexercised `Ok(false)` non-membership-witness arm).
        let mut prover = new_prover();
        let covered_key = [0x10u8; 32];
        prover
            .perform_one_operation(&ProverOp::Insert(pk(covered_key, vec![0x01])))
            .expect("seed");
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        prover
            .perform_one_operation(&ProverOp::Remove(bytes::Bytes::from(covered_key.to_vec())))
            .expect("prover remove");
        let proof = prover.generate_proof().to_vec();
        let mut verifier =
            AvlVerifier::new(&parent, &proof, 32, None).expect("verifier construction");
        let uncovered = [0x99u8; 32];
        let result = verifier.remove_with_presence(&uncovered);
        assert_eq!(
            result,
            Err(()),
            "uncovered-key remove must surface session-scoped Err(())",
        );
    }

    // The third arm of remove_with_presence — Ok(false) for an
    // explicit non-membership witness — cannot be cleanly
    // synthesized through `BatchAVLProver`'s public API: the
    // RemoveIfExists+absent-key path emits a witness shape the
    // verifier's Remove does not consume as Ok(None). Closing
    // that gap requires either a real Scala/mainnet ADProof
    // corpus or a synthetic witness builder outside the
    // upstream prover API. The arm is correct by inspection
    // against the upstream return type.

    #[test]
    fn remove_structurally_valid_wrong_proof_fails_closed_not_panic() {
        // CONSENSUS-DoS REGRESSION. A structurally-valid LOOKUP proof supplied
        // where a REMOVE proof belongs (in a permissionless contract the spender
        // controls the proof bytes). The proof CONSTRUCTS fine, then the Remove
        // walks into a LabelOnly node the lookup proof never materialised, and
        // the upstream crate `panic!`s at OPERATION time
        // (`authenticated_tree_ops.rs:635 "Not internal node"` for this shape —
        // a sibling of the 413/431 "this proof is wrong" sites). Scala throws the
        // same error but catches it in an enclosing `Try`, so the op fails and
        // the tx is invalid while the node survives. The `guarded` panic boundary
        // must reproduce that fail-closed outcome:
        //   1. `remove()` returns `Err` — no panic escapes to crash the node; and
        //   2. the verifier is POISONED — `digest()` reads `None`, not a
        //      half-mutated tree (which would be accept-invalid, a fork — strictly
        //      worse than the DoS) — and every later op stays failed.
        let keys: [[u8; 32]; 2] = [[1u8; 32], [12u8; 32]];

        // Parent digest of the {keys[0], keys[1]} tree.
        let mut prover = new_prover();
        for k in &keys {
            prover
                .perform_one_operation(&ProverOp::Insert(pk(*k, vec![0xAB])))
                .expect("seed insert");
        }
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);

        // A genuine LOOKUP proof for keys[0] against that same tree — valid
        // bytes, wrong operation. Rebuild an identical prover so the lookup
        // batch is emitted on its own.
        let mut lp = new_prover();
        for k in &keys {
            lp.perform_one_operation(&ProverOp::Insert(pk(*k, vec![0xAB])))
                .expect("seed insert");
        }
        let _ = lp.generate_proof();
        lp.perform_one_operation(&ProverOp::Lookup(bytes::Bytes::from(keys[0].to_vec())))
            .expect("prover lookup");
        let lookup_proof = lp.generate_proof().to_vec();

        let mut verifier =
            AvlVerifier::new(&parent, &lookup_proof, 32, None).expect("verifier construction");

        // (1) Fail closed, do not panic.
        assert_eq!(
            verifier.remove(&keys[0]),
            Err(()),
            "a structurally-valid wrong-op remove proof must fail closed, not panic",
        );
        // (2) Poisoned: no half-mutated digest may leak (Scala: failed op → None).
        assert_eq!(
            verifier.digest(),
            None,
            "a panic-poisoned verifier must report no digest (accept-invalid guard)",
        );
        // And it stays failed for every subsequent operation.
        assert_eq!(
            verifier.remove(&keys[1]),
            Err(()),
            "a poisoned verifier must stay failed",
        );
    }

    #[test]
    fn corrupted_proof_never_panics_during_operations() {
        // Pins the CONSTRUCTION-time failure boundary for crude proof
        // corruptions: the upstream `BatchAVLVerifier` rebuilds the entire proof
        // graph in `new()`, so byte-level corruptions almost always fail (or
        // panic) AT CONSTRUCTION; a verifier that does construct then returns
        // `Ok`/`Err` from these ops, not an operation-time panic.
        //
        // This is NOT the whole story: a *structurally-valid-but-wrong* proof
        // (e.g. a lookup proof used for a remove) constructs cleanly and DOES
        // panic at operation time — see
        // `remove_structurally_valid_wrong_proof_fails_closed_not_panic`. That
        // op-time panic is now contained by `AvlVerifier::guarded`, so the
        // wrapper — not just `digest_apply`'s construction guard — is the panic
        // boundary. The `op_panicked` check below therefore stays green because
        // the guard converts any op-time panic into `Err`.
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let mut prover = new_prover();
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let key_c = [0x33u8; 32];
        for k in [key_a, key_b, key_c] {
            prover
                .perform_one_operation(&ProverOp::Insert(pk(k, vec![0xAB])))
                .expect("seed insert");
        }
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        prover
            .perform_one_operation(&ProverOp::Remove(bytes::Bytes::from(key_b.to_vec())))
            .expect("prover remove");
        let good_proof = prover.generate_proof().to_vec();

        // Truncations at eighth-steps plus single-byte flips at several offsets.
        let mut corruptions: Vec<Vec<u8>> = Vec::new();
        for div in 1..8usize {
            corruptions.push(good_proof[..good_proof.len() * div / 8].to_vec());
        }
        for off in [
            0usize,
            1,
            good_proof.len() / 3,
            good_proof.len() / 2,
            good_proof.len().saturating_sub(1),
        ] {
            if off < good_proof.len() {
                let mut c = good_proof.clone();
                c[off] ^= 0xFF;
                corruptions.push(c);
            }
        }

        let mut survived_construction = 0usize;
        for (i, bad) in corruptions.iter().enumerate() {
            // Construction may panic (caught upstream by digest_apply) or Err.
            let constructed = catch_unwind(AssertUnwindSafe(|| {
                AvlVerifier::new(&parent, bad, 32, None)
            }));
            if let Ok(Ok(mut verifier)) = constructed {
                survived_construction += 1;
                // A verifier that constructed from a corrupted proof must
                // still never panic at operation time — only Ok/Err.
                let op_panicked = catch_unwind(AssertUnwindSafe(|| {
                    let _ = verifier.remove_returning_value(&key_b);
                    let _ = verifier.lookup(&key_a);
                    let _ = verifier.insert(&[0x44u8; 32], &[0x01]);
                    let _ = verifier.digest();
                }))
                .is_err();
                assert!(
                    !op_panicked,
                    "corruption #{i} produced an operation-time panic — \
                     the digest_apply op path needs its own catch_unwind guard",
                );
            }
        }
        // Crude byte corruptions almost always fail IN `new()` (graph rebuild),
        // so the op-check arm above is frequently empty — which is exactly why
        // the NON-VACUOUS companion test below carries the load-bearing evidence
        // that a constructed verifier's ops are panic-free. (Printed, not
        // asserted: we can't guarantee a crude corruption survives construction.)
        eprintln!("corruptions surviving construction: {survived_construction}");
    }

    #[test]
    fn constructed_verifier_adversarial_ops_return_err_not_panic() {
        // Non-vacuous companion to `corrupted_proof_never_panics_during_operations`.
        // Construction from a VALID proof is guaranteed to succeed, so the op
        // path below is always exercised. Each adversarial op is the FIRST op on
        // a freshly-constructed verifier — representative of `digest_apply`,
        // which returns on the first `Err` and never operates past a failure.
        // Keys the proof does not witness (uncovered, zero/ff, a pseudo-random
        // sweep) across lookup/remove/remove_with_presence/insert must all
        // return `Ok`/`Err`, never panic. This pins the benign case (an op that
        // merely falls off its witnessed access path returns `Err` on its own).
        // It does NOT cover the structurally-valid-but-wrong proof, which panics
        // at op time and is contained by `AvlVerifier::guarded` — see
        // `remove_structurally_valid_wrong_proof_fails_closed_not_panic`.
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let mut prover = new_prover();
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let key_c = [0x33u8; 32];
        for k in [key_a, key_b, key_c] {
            prover
                .perform_one_operation(&ProverOp::Insert(pk(k, vec![0xAB])))
                .expect("seed insert");
        }
        let _ = prover.generate_proof();
        let parent = prover_digest(&mut prover);
        prover
            .perform_one_operation(&ProverOp::Remove(bytes::Bytes::from(key_b.to_vec())))
            .expect("prover remove");
        let good_proof = prover.generate_proof().to_vec();

        let mut adversarial: Vec<[u8; 32]> = vec![
            key_a,
            key_b,
            key_c,
            [0x00u8; 32],
            [0xFFu8; 32],
            [0x99u8; 32],
        ];
        for i in 0u8..32 {
            adversarial.push([i.wrapping_mul(7).wrapping_add(3); 32]);
        }

        for (i, k) in adversarial.iter().enumerate() {
            // Fresh verifier per op: construction is guaranteed (valid proof),
            // and the single op below is the "first op" digest_apply would run.
            let mut v =
                AvlVerifier::new(&parent, &good_proof, 32, None).expect("valid proof constructs");
            let panicked = catch_unwind(AssertUnwindSafe(|| match i % 4 {
                0 => {
                    let _ = v.lookup(k);
                }
                1 => {
                    let _ = v.remove_returning_value(k);
                }
                2 => {
                    let _ = v.remove_with_presence(k);
                }
                _ => {
                    let _ = v.insert(k, &[0x01]);
                }
            }))
            .is_err();
            assert!(
                !panicked,
                "adversarial op {} on key #{i} panicked at operation time — \
                 the digest_apply op path would need a catch_unwind guard",
                i % 4,
            );
        }

        // Phase 2 — after PARTIAL stream consumption (not just first-op): drive
        // the real Mode-5 op order (lookups, then the witnessed remove, then an
        // insert) on one verifier, legitimately consuming proof stream, THEN
        // fall off the witnessed access paths with adversarial ops. None may
        // panic. Guaranteed non-vacuous: the valid proof always constructs.
        let mut v =
            AvlVerifier::new(&parent, &good_proof, 32, None).expect("valid proof constructs");
        let post_consumption_panicked = catch_unwind(AssertUnwindSafe(|| {
            let _ = v.lookup(&key_a); // uncovered lookup → Err
            let _ = v.remove_returning_value(&key_b); // witnessed remove → Ok (consumes stream)
            let _ = v.insert(&[0x44u8; 32], &[0x05]); // unwitnessed insert
            for k in &adversarial {
                let _ = v.lookup(k);
                let _ = v.remove_returning_value(k);
                let _ = v.remove_with_presence(k);
                let _ = v.insert(k, &[0x07]);
            }
            let _ = v.digest();
        }))
        .is_err();
        assert!(
            !post_consumption_panicked,
            "ops after partial proof-stream consumption must return Ok/Err, never panic",
        );
    }
}
