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
use ergo_avltree_rust::operation::{KeyDelta, KeyValue, Operation};
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
/// contained AVL verifier panic (see `AvlVerifier::guarded`).
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

/// Length of an AVL+ digest: a 32-byte root label plus one height byte.
pub const AVL_DIGEST_LENGTH: usize = 33;

// Packed-proof node markers (scrypto `BatchProofConstants`; the same values
// are crate-private in `ergo_avltree_rust::batch_node`). Any other byte is an
// internal node whose value is its balance.
const PROOF_LEAF: u8 = 2;
const PROOF_LABEL: u8 = 3;
const PROOF_END_OF_TREE: u8 = 4;
const PROOF_LABEL_LENGTH: usize = 32;

/// Height of the tree a packed AVL+ batch proof reconstructs, computed
/// without building it: one pass over the bytes with a heap stack of subtree
/// heights. Leaves and label-only nodes have height 0; an internal node has
/// height `max(left, right) + 1`.
///
/// Mirrors the reconstruction in `ergo_avltree_rust`'s `BatchAVLVerifier`
/// (and scrypto's) exactly: a leaf carries its key only when the previous
/// node was not a leaf (a label node resets this, an internal node does
/// not), then the next-leaf key, then a 4-byte big-endian length when values
/// are not fixed-length, then the value. Returns `None` exactly when that
/// reconstruction fails on the proof's structure: a read past the end
/// (including a missing end-of-tree marker), an internal node with fewer
/// than two subtrees below it, or anything but one tree at the end. Failures
/// that need the tree itself (node-count bound, root label versus digest)
/// are left to the crate.
pub fn proof_tree_height(
    proof: &[u8],
    key_length: usize,
    value_length_opt: Option<usize>,
) -> Option<usize> {
    fn advance(proof: &[u8], i: usize, n: usize) -> Option<usize> {
        let end = i.checked_add(n)?;
        (end <= proof.len()).then_some(end)
    }

    let mut heights: Vec<u32> = Vec::new();
    let mut previous_was_leaf = false;
    let mut i = 0usize;
    loop {
        let marker = *proof.get(i)?;
        if marker == PROOF_END_OF_TREE {
            break;
        }
        i += 1;
        match marker {
            PROOF_LABEL => {
                i = advance(proof, i, PROOF_LABEL_LENGTH)?;
                heights.push(0);
                previous_was_leaf = false;
            }
            PROOF_LEAF => {
                if !previous_was_leaf {
                    i = advance(proof, i, key_length)?;
                }
                i = advance(proof, i, key_length)?;
                let value_length = match value_length_opt {
                    Some(len) => len,
                    None => {
                        let end = advance(proof, i, 4)?;
                        let len_bytes: [u8; 4] = proof[i..end].try_into().ok()?;
                        i = end;
                        u32::from_be_bytes(len_bytes) as usize
                    }
                };
                i = advance(proof, i, value_length)?;
                heights.push(0);
                previous_was_leaf = true;
            }
            _ => {
                let right = heights.pop()?;
                let left = heights.pop()?;
                heights.push(left.max(right).checked_add(1)?);
            }
        }
    }
    match heights.as_slice() {
        [root] => Some(*root as usize),
        _ => None,
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
/// survives. `AvlVerifier::guarded` restores that fail-closed parity: a caught
/// panic drops the inner verifier (`None`), and every later op — including
/// [`AvlVerifier::digest`] — then fails, exactly as Scala's `topNode = None`
/// does after a failed op. Reading a digest from a half-mutated verifier would
/// be an accept-invalid divergence (a fork), strictly worse than the crash, so
/// poisoning is load-bearing, not cosmetic.
///
/// Construction ([`AvlVerifier::new`]) is guarded the same way — the crate can
/// also panic while parsing a malformed proof — so `new` catches it and returns
/// `Err` instead of panicking. `AvlVerifier` is thus a single fail-closed
/// boundary at BOTH construction and operation time.
///
/// The root height is tracked here rather than in the crate. It starts at the
/// starting digest's height byte, which the proof does not authenticate, so
/// operations can move it below 0 or above 255. The crate keeps it in a
/// `usize` and asserts it is below 256 when producing a digest; keeping the
/// authoritative value here lets [`AvlVerifier::digest_checked`] report an
/// out-of-range height as an error instead of a panic or a wrapped value.
pub struct AvlVerifier {
    inner: Option<BatchAVLVerifier>,
    root_height: i64,
}

/// The root height reached a value a digest's height byte cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvlHeightOutOfRange {
    /// The root height after the operations.
    pub height: i64,
}

/// Offset added to the crate's `usize` root height while an operation runs,
/// so a decrement below the real height 0 cannot underflow. Each operation
/// moves the height by at most one.
const CRATE_HEIGHT_BIAS: i64 = 1 << 32;

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
    /// `max_num_operations` / `max_deletes`: optional operation-count
    /// bounds (scrypto `BatchAVLVerifier` semantics: a proof is capped
    /// at a node count derived from the bound, so an over-large proof
    /// is rejected AT CONSTRUCTION; `max_deletes` defaults to
    /// `max_num_operations` when `None`). The crate implements the
    /// bound but it is opt-in: callers that do not pass one get NO
    /// node-count cap. Parity map:
    /// - block-level ADProofs verification → `Some(op_count)`, matching
    ///   Scala `ADProofs.verify` (`maxNumOperations = Some(
    ///   changes.operations.size)`, changes netted per
    ///   `ErgoState.stateChanges`);
    /// - script-level evaluation → `None`, matching Scala
    ///   `CAvlTreeVerifier.apply` (no bounds);
    /// - SANTA authds adverse vectors rely on the bound to reject
    ///   self-consistent proofs padded with extra nodes.
    ///
    /// The proof bytes are pre-scanned (see [`proof_tree_height`]) before
    /// the crate sees them: a proof the crate's reconstruction would reject
    /// for its structure is rejected here without building any tree.
    /// No height bound is applied; see [`Self::new_with_height_bound`].
    pub fn new(
        digest: &[u8],
        proof: &[u8],
        key_length: usize,
        value_length_opt: Option<usize>,
        max_num_operations: Option<usize>,
        max_deletes: Option<usize>,
    ) -> Result<Self, String> {
        Self::construct(
            digest,
            proof,
            key_length,
            value_length_opt,
            max_num_operations,
            max_deletes,
            None,
        )
    }

    /// As [`Self::new`], and additionally rejects a proof whose
    /// reconstructed tree is taller than `max_tree_height` before any tree
    /// is built.
    ///
    /// The upstream crate walks the reconstructed tree recursively (node
    /// labels, tree operations, and the drop of the tree itself), one stack
    /// frame per level, so the tree height must be bounded before
    /// construction for the walk to fit on a validation thread's stack.
    pub fn new_with_height_bound(
        digest: &[u8],
        proof: &[u8],
        key_length: usize,
        value_length_opt: Option<usize>,
        max_num_operations: Option<usize>,
        max_deletes: Option<usize>,
        max_tree_height: usize,
    ) -> Result<Self, String> {
        Self::construct(
            digest,
            proof,
            key_length,
            value_length_opt,
            max_num_operations,
            max_deletes,
            Some(max_tree_height),
        )
    }

    fn construct(
        digest: &[u8],
        proof: &[u8],
        key_length: usize,
        value_length_opt: Option<usize>,
        max_num_operations: Option<usize>,
        max_deletes: Option<usize>,
        max_tree_height: Option<usize>,
    ) -> Result<Self, String> {
        // scrypto 3.0.0 AuthenticatedTreeOps.scala:33 fatally allocates an
        // Int.MaxValue-sized infinity key. Reject this wire-reachable class
        // before constructing the upstream tree; allocation failure cannot
        // be contained by catch_unwind.
        if key_length >= i32::MAX as usize {
            return Err("AVL key length exceeds the JVM array limit".to_string());
        }
        // The crate checks these two before reading the proof; checking them
        // first keeps the failure order of the reconstruction.
        if key_length == 0 {
            return Err("AVL key length must be positive".to_string());
        }
        if digest.len() != AVL_DIGEST_LENGTH {
            return Err(format!(
                "AVL digest must be {AVL_DIGEST_LENGTH} bytes, got {}",
                digest.len()
            ));
        }
        // Structural pre-scan. A proof that fails here also fails the
        // crate's reconstruction (same grammar, same failure points), so the
        // verdict is unchanged; the crate is simply never handed a proof it
        // would reject mid-parse, which would otherwise drop a partially
        // built (and possibly very deep) tree.
        let height = proof_tree_height(proof, key_length, value_length_opt)
            .ok_or_else(|| "malformed AVL proof: tree reconstruction fails".to_string())?;
        if let Some(bound) = max_tree_height {
            if height > bound {
                return Err(format!(
                    "AVL proof tree height {height} exceeds the bound {bound}"
                ));
            }
        }
        let digest = bytes::Bytes::from(digest.to_vec());
        let proof = bytes::Bytes::from(proof.to_vec());
        // The upstream crate can `panic!` while parsing a malformed proof into
        // its in-memory tree (e.g. a truncated proof → a slice-index panic in
        // `batch_avl_verifier.rs`). Contain it HERE so construction — like the
        // ops below — is a self-guarded fail-closed boundary: a caught panic
        // becomes a normal `Err`, mirroring Scala's `reconstructedTree` `Try`
        // (which yields `topNode = None`). Every consumer is then protected at
        // both construction and op time without having to wrap `new()` itself
        // (callers that still do are harmless belt-and-suspenders). Arming
        // `AvlGuard` lets the node's panic hook recognise this as an expected,
        // contained AVL panic and suppress the log-flood. Sound for the same
        // reason as the op guard: the panic is deterministic on the proof bytes,
        // mutates no shared state, and the half-built verifier (owned,
        // stack-local) is dropped on unwind.
        let _guard = AvlGuard::arm();
        match catch_unwind(AssertUnwindSafe(|| {
            BatchAVLVerifier::new(
                &digest,
                &proof,
                AVLTree::new(
                    |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
                    key_length,
                    value_length_opt,
                ),
                max_num_operations,
                max_deletes,
            )
        })) {
            Ok(Ok(v)) => Ok(AvlVerifier {
                root_height: i64::from(digest[AVL_DIGEST_LENGTH - 1]),
                inner: Some(v),
            }),
            Ok(Err(e)) => Err(format!("{e}")),
            Err(_) => Err("AVL verifier construction panicked on a malformed proof".to_string()),
        }
    }

    /// Run `f` against the wrapped verifier, isolating any panic from the
    /// upstream `ergo_avltree_rust` crate into the fail-closed `Err(())` path.
    ///
    /// The crate `panic!`s on a structurally-valid-but-wrong proof at op time
    /// (see the type doc). This restores Scala's `Try`-boundary semantics: a
    /// caught panic POISONS the verifier (the inner value was moved into the
    /// unwinding closure and dropped, so `self.inner` stays `None`) and surfaces
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
        let mut bv = match self.inner.take() {
            Some(bv) => bv,
            None => return Err(()),
        };
        bv.state().tree.height = (self.root_height + CRATE_HEIGHT_BIAS) as usize;
        // `AssertUnwindSafe` is justified: `bv` is owned (not shared, no locks),
        // and on panic it is dropped during unwinding — no broken invariant is
        // ever observed, because the verifier is never reused after a panic.
        let _guard = AvlGuard::arm();
        match catch_unwind(AssertUnwindSafe(move || {
            let r = f(&mut bv);
            (bv, r)
        })) {
            // Op completed (Ok, or a clean crate Err) → keep the verifier.
            Ok((mut bv, r)) => {
                // A failed operation clears the root (and the height with
                // it); the digest is then absent whatever the height.
                if bv.get_state().tree.root.is_some() {
                    self.root_height = bv.get_state().tree.height as i64 - CRATE_HEIGHT_BIAS;
                }
                // Keep the crate's own copy in the range its digest accepts;
                // `digest_checked` decides on `root_height`.
                bv.state().tree.height = self.root_height.clamp(0, 255) as usize;
                self.inner = Some(bv);
                r
            }
            // Panicked: `bv` was moved into the closure and dropped while
            // unwinding; `self.inner` stays `None` (poisoned) and we fail closed.
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

    /// Update an existing key with a new value. Returns the OLD value the
    /// proof witnessed for the key (scrypto `performOneOperation` semantics:
    /// the value associated with the key BEFORE the operation). `Ok(None)`
    /// is unreachable on success — an Update of an absent key is an op
    /// failure (`Err(())`), mirroring scrypto's `update_fn` "Key does not
    /// exists" error.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::Update(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|old| old.map(|v| v.to_vec()))
            .map_err(|_| ())
        })
    }

    /// Insert a new key-value pair. Returns the OLD value (`Ok(None)` on
    /// success — an Insert of an existing key is an op failure, mirroring
    /// scrypto's `update_fn` "Key already exists" error).
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::Insert(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|old| old.map(|v| v.to_vec()))
            .map_err(|_| ())
        })
    }

    /// Insert a new entry OR overwrite an existing one for the same
    /// key. Backs the EIP-50 v6 `SAvlTree.insertOrUpdate` MethodCall
    /// (Scala `SAvlTreeMethods.insertOrUpdateMethod` at
    /// `methods.scala:1671-1686`). Returns the OLD value the proof
    /// witnessed: `Some(old)` when an existing entry was overwritten,
    /// `None` when the key was absent (fresh insert).
    pub fn insert_or_update(&mut self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::InsertOrUpdate(KeyValue {
                key: bytes::Bytes::from(key.to_vec()),
                value: bytes::Bytes::from(value.to_vec()),
            }))
            .map(|old| old.map(|v| v.to_vec()))
            .map_err(|_| ())
        })
    }

    /// Remove a key if present; a no-op success on an absent key (scrypto
    /// `Operation::RemoveIfExists`: the absent case does NOT fail, unlike
    /// [`Self::remove`]). Returns the OLD value the proof witnessed —
    /// `Some(old)` when the key existed, `None` when it did not.
    pub fn remove_if_exists(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::RemoveIfExists(bytes::Bytes::from(key.to_vec())))
                .map(|old| old.map(|v| v.to_vec()))
                .map_err(|_| ())
        })
    }

    /// scrypto `Operation::UpdateLongBy`: interpret the key's value as a
    /// big-endian i64 and add `delta` — failing if the result is negative,
    /// removing the key when the result is exactly zero, and treating an
    /// absent key as 0 (insert with `delta` if positive, fail if negative,
    /// no-op if zero). Returns the OLD value the proof witnessed.
    pub fn update_long_by(&mut self, key: &[u8], delta: i64) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::UpdateLongBy(KeyDelta {
                key: bytes::Bytes::from(key.to_vec()),
                delta,
            }))
            .map(|old| old.map(|v| v.to_vec()))
            .map_err(|_| ())
        })
    }

    /// scrypto `Operation::UnknownModification`: an identity op — the tree
    /// is unchanged and the CURRENT value for the key is returned (the
    /// operation's `update_fn` passes `old_value` through). Serves the
    /// SANTA authds corpus entry class of the same name; there is no
    /// ErgoTree surface for it.
    pub fn unknown_modification(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ()> {
        self.guarded(|bv| {
            bv.perform_one_operation(&Operation::UnknownModification(bytes::Bytes::from(
                key.to_vec(),
            )))
            .map(|old| old.map(|v| v.to_vec()))
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
    /// (Scala parity: a failed op yields `topNode = None`, so no digest leaks),
    /// and also when the root height is out of range (see
    /// [`Self::digest_checked`], which tells the two apart).
    pub fn digest(&self) -> Option<Vec<u8>> {
        self.digest_checked().ok().flatten()
    }

    /// As [`Self::digest`], but a tree whose root height left `0..=255`
    /// (possible because the starting height byte is not authenticated by
    /// the proof) is an `Err` rather than `None`. `Ok(None)` still means the
    /// verifier failed (construction or an operation).
    pub fn digest_checked(&self) -> Result<Option<Vec<u8>>, AvlHeightOutOfRange> {
        let Some(bv) = self.inner.as_ref() else {
            return Ok(None);
        };
        if bv.get_state().tree.root.is_none() {
            return Ok(None);
        }
        if !(0..=255).contains(&self.root_height) {
            return Err(AvlHeightOutOfRange {
                height: self.root_height,
            });
        }
        Ok(bv.digest().map(|d| d.to_vec()))
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

    // ----- SANTA authds regression: adverse-malicious-extra-nodes -----

    /// SANTA authds vector `AvlVerify.ergots_corpus/adverse-malicious-extra-nodes`
    /// (oracle: scrypto 3.0.0, blessed `proof_accepted = false`). The proof
    /// carries a self-consistent tree padded with extra nodes; with the
    /// operation bound declared in the vector's settings
    /// (`max_num_operations = 0` → scrypto caps the proof at 1 node) the
    /// crate must reject AT CONSTRUCTION. Without a bound the crate accepts
    /// (and the lookup would return attacker-chosen bytes) — that is the
    /// JVM-parity behaviour for script-level evaluation, where Scala's
    /// `CAvlTreeVerifier.apply` passes no bound; block-level verification
    /// always passes `Some(op_count)` (see `digest_apply.rs`).
    #[test]
    fn santa_adverse_extra_nodes_rejected_under_operation_bound() {
        let digest =
            hex::decode("215197cff0244d874639dab08e97913fa0b1979192b264a64f4f24f9ac132e7a02")
                .unwrap();
        let proof = hex::decode(
            "03fbf12f7c13a9bd41c97bcb4073995069741012a975a254df1d2fc3519d9b7503020202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030300000008020202020202020203752a2fcab8542e5360a9df7074ed5ff3f0f89938218370923775e6cbc35add0a00000402",
        )
        .unwrap();

        // scrypto parity: settings declare max_num_operations = 0 → the
        // verifier must refuse to construct (proof_accepted = false).
        let verdict = AvlVerifier::new(&digest, &proof, 32, None, Some(0), None);
        assert!(
            verdict.is_err(),
            "malicious extra-nodes proof must be rejected under the declared operation bound"
        );

        // Without a bound construction succeeds (documented JVM-eval
        // parity) — pinned so a future strictness change is deliberate.
        assert!(
            AvlVerifier::new(&digest, &proof, 32, None, None, None).is_ok(),
            "unbounded construction is the JVM script-eval parity behaviour"
        );
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
            AvlVerifier::new(&parent, &proof, 32, None, None, None).expect("verifier construction");
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
            AvlVerifier::new(&parent, &proof, 32, None, None, None).expect("verifier construction");
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

        let mut verifier = AvlVerifier::new(&parent, &lookup_proof, 32, None, None, None)
            .expect("verifier construction");

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
                AvlVerifier::new(&parent, bad, 32, None, None, None)
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
            let mut v = AvlVerifier::new(&parent, &good_proof, 32, None, None, None)
                .expect("valid proof constructs");
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
        let mut v = AvlVerifier::new(&parent, &good_proof, 32, None, None, None)
            .expect("valid proof constructs");
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

#[cfg(test)]
mod deep_proof_tests {
    use super::*;
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_avltree_rust::batch_avl_prover::BatchAVLProver;
    use ergo_avltree_rust::batch_node::{AVLTree as ProverTree, Node, NodeHeader};
    use ergo_avltree_rust::operation::{KeyValue as ProverKv, Operation as ProverOp};

    // ----- helpers -----

    /// Stack size of the node's validation threads.
    const VALIDATION_STACK: usize = 8 * 1024 * 1024;

    /// A depth whose tree the upstream crate can neither label nor drop on
    /// an 8 MB stack (labelling overflows near 14,000 levels, dropping a
    /// one between 50,000 and 200,000).
    const FAR_TOO_DEEP: usize = 200_000;

    /// Set in the child process that runs a deep-proof test body.
    const CHILD_ENV: &str = "ERGO_SIGMA_DEEP_AVL_CHILD";

    /// Run `body` on a thread with the validation stack size, inside a child
    /// process that re-runs only test `test_path` of this test binary. A stack
    /// overflow aborts the process it happens in; running the body in a child
    /// turns such a regression into an ordinary failure of this one test.
    fn run_isolated(test_path: &str, body: fn()) {
        if std::env::var_os(CHILD_ENV).is_some() {
            std::thread::Builder::new()
                .stack_size(VALIDATION_STACK)
                .spawn(body)
                .expect("spawn validation-stack thread")
                .join()
                .expect("deep-proof test body");
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let output = std::process::Command::new(exe)
            .args([test_path, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("run child test process");
        assert!(
            output.status.success(),
            "child run of {test_path} failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "child run of {test_path} did not run the test",
        );
    }

    /// Packed proof of a left spine with `depth` internal nodes (key length
    /// 1, values fixed at 0 bytes), followed by direction bits that always
    /// go left. Returns the proof and the matching 33-byte digest.
    fn spine_proof(depth: usize) -> (Vec<u8>, Vec<u8>) {
        let leaf_label = |key: u8, next: u8| crate::blake2b256(&[0u8, key, next]);
        let mut proof = vec![PROOF_LEAF, 0x10, 0x30];
        let mut label = leaf_label(0x10, 0x30);
        for level in 0..depth {
            // A leaf after a leaf or an internal node reuses the previous
            // next-leaf key as its key, so only the next-leaf key is written.
            let right = if level == 0 {
                leaf_label(0x30, 0x20)
            } else {
                leaf_label(0x20, 0x20)
            };
            proof.extend_from_slice(&[PROOF_LEAF, 0x20, 0x00]);
            let mut internal = vec![1u8, 0x00];
            internal.extend_from_slice(&label);
            internal.extend_from_slice(&right);
            label = crate::blake2b256(&internal);
        }
        proof.push(PROOF_END_OF_TREE);
        proof.extend(std::iter::repeat_n(0xFFu8, spine_directions_len(depth)));
        let mut digest = label.to_vec();
        digest.push(depth.min(200) as u8);
        (proof, digest)
    }

    fn spine_directions_len(depth: usize) -> usize {
        depth / 8 + 8
    }

    fn prover_key(i: u32) -> [u8; 32] {
        // Byte 4 keeps every key above the all-zero negative-infinity key.
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&i.wrapping_mul(2_654_435_761).to_be_bytes());
        key[4] = 1;
        key
    }

    // ----- happy path -----

    #[test]
    fn proof_tree_height_of_spine_equals_its_depth() {
        for depth in [0usize, 1, 2, 7, 300] {
            let (proof, _) = spine_proof(depth);
            assert_eq!(proof_tree_height(&proof, 1, Some(0)), Some(depth));
        }
    }

    #[test]
    fn proof_tree_height_of_prover_proof_is_within_digest_height() {
        let tree = ProverTree::new(
            |d| Node::LabelOnly(NodeHeader::new(Some(*d), None)),
            32,
            None,
        );
        let mut prover = BatchAVLProver::new(tree, true);
        for i in 0u32..2_000 {
            prover
                .perform_one_operation(&ProverOp::Insert(ProverKv {
                    key: bytes::Bytes::copy_from_slice(&prover_key(i)),
                    value: bytes::Bytes::from(vec![0xAB; 5]),
                }))
                .expect("insert");
        }
        let _ = prover.generate_proof();
        let parent = prover.digest().expect("digest").to_vec();
        for i in (0u32..2_000).step_by(97) {
            prover
                .perform_one_operation(&ProverOp::Lookup(bytes::Bytes::copy_from_slice(
                    &prover_key(i),
                )))
                .expect("lookup");
        }
        let proof = prover.generate_proof().to_vec();
        let height = proof_tree_height(&proof, 32, None).expect("well-formed proof");
        assert!(
            height <= usize::from(parent[32]),
            "proof height {height} above digest height {}",
            parent[32]
        );
        assert!(
            AvlVerifier::new_with_height_bound(&parent, &proof, 32, None, None, None, height)
                .is_ok()
        );
    }

    #[test]
    fn moderate_depth_avl_proof_verifies_as_before() {
        run_isolated(
            "avl::deep_proof_tests::moderate_depth_avl_proof_verifies_as_before",
            || {
                let (proof, digest) = spine_proof(1_000);
                let mut verifier = AvlVerifier::new(&digest, &proof, 1, Some(0), None, None)
                    .expect("well-formed spine with matching digest");
                assert_eq!(verifier.lookup(&[0x10]), Ok(Some(Vec::new())));
                let mut wrong = digest.clone();
                wrong[0] ^= 1;
                assert!(
                    AvlVerifier::new(&wrong, &proof, 1, Some(0), None, None).is_err(),
                    "a digest mismatch still fails construction"
                );
            },
        );
    }

    // ----- error paths -----

    #[test]
    fn proof_tree_height_rejects_what_reconstruction_rejects() {
        let (spine, _) = spine_proof(3);
        let tree_len = spine.len() - spine_directions_len(3);
        // No end-of-tree marker.
        assert_eq!(proof_tree_height(&spine[..tree_len - 1], 1, Some(0)), None);
        // Empty proof.
        assert_eq!(proof_tree_height(&[], 1, Some(0)), None);
        // Internal node with nothing below it.
        assert_eq!(
            proof_tree_height(&[0x00, PROOF_END_OF_TREE], 1, Some(0)),
            None
        );
        // Two trees left at the end.
        assert_eq!(
            proof_tree_height(
                &[PROOF_LEAF, 1, 2, PROOF_LEAF, 3, PROOF_END_OF_TREE],
                1,
                Some(0)
            ),
            None
        );
        // Truncated label.
        assert_eq!(
            proof_tree_height(&[PROOF_LABEL, 0, 0, PROOF_END_OF_TREE], 1, Some(0)),
            None
        );
        // Variable-length value whose length runs past the end.
        assert_eq!(
            proof_tree_height(
                &[PROOF_LEAF, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF, PROOF_END_OF_TREE],
                1,
                None
            ),
            None
        );
        // A single label-only root is a complete tree of height 0.
        let mut label_root = vec![PROOF_LABEL];
        label_root.extend_from_slice(&[0u8; PROOF_LABEL_LENGTH]);
        label_root.push(PROOF_END_OF_TREE);
        assert_eq!(proof_tree_height(&label_root, 1, Some(0)), Some(0));
    }

    #[test]
    fn avl_proof_at_height_bound_is_accepted_and_one_above_is_rejected() {
        let (proof, digest) = spine_proof(300);
        assert!(
            AvlVerifier::new_with_height_bound(&digest, &proof, 1, Some(0), None, None, 300)
                .is_ok(),
            "a proof exactly at the bound constructs"
        );
        assert!(
            AvlVerifier::new_with_height_bound(&digest, &proof, 1, Some(0), None, None, 299)
                .is_err(),
            "a proof one level above the bound is rejected"
        );
    }

    #[test]
    fn deep_avl_proof_over_height_bound_fails_closed() {
        run_isolated(
            "avl::deep_proof_tests::deep_avl_proof_over_height_bound_fails_closed",
            || {
                let (proof, digest) = spine_proof(FAR_TOO_DEEP);
                assert!(AvlVerifier::new_with_height_bound(
                    &digest,
                    &proof,
                    1,
                    Some(0),
                    None,
                    None,
                    255
                )
                .is_err());
            },
        );
    }

    #[test]
    fn deep_malformed_avl_proof_fails_closed() {
        // A deep spine that never reaches its end-of-tree marker. The crate
        // would build the whole spine before failing on the missing marker,
        // then drop it recursively; the pre-scan rejects the proof first.
        run_isolated(
            "avl::deep_proof_tests::deep_malformed_avl_proof_fails_closed",
            || {
                let (mut proof, digest) = spine_proof(FAR_TOO_DEEP);
                proof.truncate(proof.len() - spine_directions_len(FAR_TOO_DEEP) - 1);
                assert!(AvlVerifier::new(&digest, &proof, 1, Some(0), None, None).is_err());
            },
        );
    }
}
