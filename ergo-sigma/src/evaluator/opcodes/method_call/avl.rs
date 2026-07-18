//! `SAvlTree` (type_id 100) `0xDC MethodCall` arms: contains(9), get(10),
//! getMany(11), insert(12), update(13), remove(14), updateDigest(15),
//! insertOrUpdate(16), updateOperations(8) — a contiguous, self-contained
//! cluster in the original file, lifted whole together with its private
//! helpers (`AvlEntries`, `AvlMutOp`, `extract_avl_entries`, `extract_avl_keys`,
//! `eval_avl_mutate`).

use ergo_primitives::cost::{CostKind, JitCost};
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use crate::evaluator::cost::{avl_cost_height, try_make_avl_verifier};
use crate::evaluator::eval_ctx::EvalCtx;
use crate::evaluator::types::{EvalError, Value};

// SAvlTree(100).contains(9) -> Boolean
// Args: key (Coll[Byte]), proof (Coll[Byte])
// Scala `SAvlTreeMethods.containsMethod` — same prover/verifier
// workflow as `get` (cost-shape matches) but returns the
// presence bit instead of the value. Without this arm any
// script using `tree.contains(key, proof)` stalls block apply
// with "expected supported MethodCall, got type_id=100,
// method_id=9" (testnet h=262,028 tx[2] input 0).
pub(super) fn contains(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }
    let avl = match &obj_val {
        Value::AvlTree(a) => a,
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for contains",
                got: format!("{other:?}"),
            })
        }
    };
    let key = match cx.eval_expr(&args[0])? {
        Value::CollBytes(k) => k,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL key",
                got: format!("{other:?}"),
            })
        }
    };
    let proof = match cx.eval_expr(&args[1])? {
        Value::CollBytes(p) => p,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL proof",
                got: format!("{other:?}"),
            })
        }
    };
    let create_cost = CostKind::PerItem {
        base: JitCost::from_jit(110),
        per_chunk: JitCost::from_jit(20),
        chunk_size: 64,
    };
    cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
    let lookup_cost = CostKind::PerItem {
        base: JitCost::from_jit(40),
        per_chunk: JitCost::from_jit(10),
        chunk_size: 1,
    };
    // Scala contains_eval (CErgoTreeEvaluator.scala:78-93): a bad
    // proof yields reconstructedTree=None and performLookup ->
    // Failure -> `case Failure(_) => false`. It NEVER throws —
    // construction OR lookup failure both return false, as does a
    // witnessed-absent key (Success(None)). The LookupAvlTree cost is
    // charged over bv.treeHeight, which equals the digest's height
    // byte (rootNodeHeight = startingDigest.last, set BEFORE the proof
    // parse) even on a failed construction — so the lookup cost is the
    // same on both paths.
    cx.cost.add(lookup_cost.compute(avl_cost_height(avl))?)?;
    match try_make_avl_verifier(avl, &proof) {
        Some(mut bv) => match bv.lookup(&key) {
            Ok(Some(_)) => Ok(Value::Bool(true)),
            Ok(None) | Err(_) => Ok(Value::Bool(false)),
        },
        None => Ok(Value::Bool(false)),
    }
}

// SAvlTree(100).get(10) -> Option[Coll[Byte]]
// Args: key (Coll[Byte]), proof (Coll[Byte])
pub(super) fn get(obj_val: Value, args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }
    let avl = match &obj_val {
        Value::AvlTree(a) => a,
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for get",
                got: format!("{other:?}"),
            })
        }
    };
    let key = match cx.eval_expr(&args[0])? {
        Value::CollBytes(k) => k,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL key",
                got: format!("{other:?}"),
            })
        }
    };
    let proof = match cx.eval_expr(&args[1])? {
        Value::CollBytes(p) => p,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL proof",
                got: format!("{other:?}"),
            })
        }
    };
    // Cost: CreateAvlVerifier(proof.len) + LookupAvlTree(treeHeight)
    let create_cost = CostKind::PerItem {
        base: JitCost::from_jit(110),
        per_chunk: JitCost::from_jit(20),
        chunk_size: 64,
    };
    cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
    let lookup_cost = CostKind::PerItem {
        base: JitCost::from_jit(40),
        per_chunk: JitCost::from_jit(10),
        chunk_size: 1,
    };
    // Scala get_eval (CErgoTreeEvaluator.scala:95-109): charges
    // LookupAvlTree(treeHeight) then performs the lookup; a Failure
    // (bad-proof construction OR a lookup that throws) calls
    // syntax.error -> errored (NOT version-gated). Only a witnessed-
    // absent key (Success(None)) returns None. The LookupAvlTree cost
    // is charged BEFORE the lookup runs (Scala's addSeqCost adds the
    // cost before the block), so it is charged on the construction-
    // failure path too; height = avl_cost_height (digest height on
    // valid metadata/bad proof, 0 for invalid metadata e.g.
    // keyLength==0). (The cost is consensus-inert here since a get
    // failure errors and the tx is rejected, but matching Scala's
    // charge order keeps the accumulator faithful.)
    cx.cost.add(lookup_cost.compute(avl_cost_height(avl))?)?;
    match try_make_avl_verifier(avl, &proof) {
        Some(mut bv) => match bv.lookup(&key) {
            Ok(Some(v)) => Ok(Value::Opt(Some(Box::new(Value::CollBytes(v))))),
            Ok(None) => Ok(Value::Opt(None)),
            Err(_) => Err(EvalError::TypeError {
                expected: "valid AVL proof for get",
                got: "proof verification failed".into(),
            }),
        },
        None => Err(EvalError::TypeError {
            expected: "valid AVL proof for get",
            got: "verifier construction failed".into(),
        }),
    }
}

// SAvlTree(100).getMany(11) -> Coll[Option[Coll[Byte]]]
// Args: keys (Coll[Coll[Byte]]), proof (Coll[Byte])
pub(super) fn get_many(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }
    let avl = match &obj_val {
        Value::AvlTree(a) => a,
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for getMany",
                got: format!("{other:?}"),
            })
        }
    };
    let keys_val = cx.eval_expr(&args[0])?;
    let keys: Vec<Vec<u8>> = match keys_val {
        // Outer `Coll[Coll[Byte]]` is the boxed-element coll
        // carrier; each inner element is a typed `CollBytes`.
        Value::CollGeneric(items, _) => items
            .into_iter()
            .map(|item| match item {
                Value::CollBytes(k) => Ok(k),
                other => Err(EvalError::TypeError {
                    expected: "Coll[Byte] in keys",
                    got: format!("{other:?}"),
                }),
            })
            .collect::<Result<_, _>>()?,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Coll[Byte]] for AVL keys",
                got: format!("{other:?}"),
            })
        }
    };
    let proof = match cx.eval_expr(&args[1])? {
        Value::CollBytes(p) => p,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL proof",
                got: format!("{other:?}"),
            })
        }
    };
    // Cost: CreateAvlVerifier(proof.len) + N * LookupAvlTree(treeHeight)
    let create_cost = CostKind::PerItem {
        base: JitCost::from_jit(110),
        per_chunk: JitCost::from_jit(20),
        chunk_size: 64,
    };
    cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
    let lookup_cost = CostKind::PerItem {
        base: JitCost::from_jit(40),
        per_chunk: JitCost::from_jit(10),
        chunk_size: 1,
    };
    // Scala getMany_eval (CErgoTreeEvaluator.scala:111-130): the
    // proof failure is only observed INSIDE the per-key lookup
    // (`keys.map { ... case Failure(_) => syntax.error }`), so a
    // construction failure must NOT abort before the loop — with an
    // empty key list NO lookup runs and the method returns an empty
    // Coll, which Scala accepts. Carry the verifier as an Option and
    // treat a construction failure as a per-key lookup Failure; a
    // Failure (construction OR lookup) errors when a key is processed
    // (NOT version-gated). A witnessed-absent key yields a None
    // element.
    let mut bv_opt = try_make_avl_verifier(avl, &proof);
    let tree_height = avl_cost_height(avl);
    let mut results = Vec::with_capacity(keys.len());
    for key in keys {
        cx.cost.add(lookup_cost.compute(tree_height)?)?;
        let looked = match bv_opt.as_mut() {
            Some(bv) => bv.lookup(&key),
            None => Err(()),
        };
        match looked {
            Ok(Some(v)) => results.push(Value::Opt(Some(Box::new(Value::CollBytes(v))))),
            Ok(None) => results.push(Value::Opt(None)),
            Err(_) => {
                return Err(EvalError::TypeError {
                    expected: "valid AVL proof for getMany",
                    got: "proof verification failed".into(),
                })
            }
        }
    }
    // AVL `getMany` returns `Coll[Option[Coll[Byte]]]`; tag
    // the carrier with that exact element type so empty
    // results and serialize-back preserve the right shape.
    Ok(Value::CollGeneric(
        results,
        Box::new(SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(
            SigmaType::SByte,
        ))))),
    ))
}

// SAvlTree(100).update(13) -> Option[AvlTree]
// Args: entries (Coll[(Coll[Byte], Coll[Byte])]), proof (Coll[Byte])
pub(super) fn update(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }
    let avl = match &obj_val {
        Value::AvlTree(a) => a.clone(),
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for update",
                got: format!("{other:?}"),
            })
        }
    };
    // Args evaluated before the body (Scala evaluates a MethodCall's
    // args before the method runs), so the flag-deny path still pays
    // the entries+proof eval cost. Outcome/cost in eval_avl_mutate.
    let entries = extract_avl_entries(cx.eval_expr(&args[0])?)?;
    let proof = match cx.eval_expr(&args[1])? {
        Value::CollBytes(p) => p,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL proof",
                got: format!("{other:?}"),
            })
        }
    };
    eval_avl_mutate(&avl, entries, &proof, AvlMutOp::Update, cx)
}

// SAvlTree(100).insert(12) -> Option[AvlTree]
pub(super) fn insert(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }
    let avl = match &obj_val {
        Value::AvlTree(a) => a.clone(),
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for insert",
                got: format!("{other:?}"),
            })
        }
    };
    // Args evaluated before the body (Scala order) so the flag-deny
    // path still pays the entries+proof eval cost. Outcome (incl. the
    // pre-v3 insert-failure throw) and cost in eval_avl_mutate.
    let entries = extract_avl_entries(cx.eval_expr(&args[0])?)?;
    let proof = match cx.eval_expr(&args[1])? {
        Value::CollBytes(p) => p,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL proof",
                got: format!("{other:?}"),
            })
        }
    };
    eval_avl_mutate(&avl, entries, &proof, AvlMutOp::Insert, cx)
}

// SAvlTree(100).insertOrUpdate(16) -> Option[AvlTree].
// EIP-50 v6 method. Mirrors `SAvlTreeMethods.insertOrUpdateMethod`
// at `methods.scala:1671-1686` — inserts new entries OR
// overwrites existing ones for the same key in a single
// proof-verified batch. Same args/result shape as
// `insert` (100,12): `(entries: Coll[(Coll[Byte], Coll[Byte])],
// proof: Coll[Byte]) -> Option[AvlTree]`.
//
// Gating: BOTH `insert_allowed` AND `update_allowed` must be
// set on the tree, since at evaluation time we don't know
// whether each key is present (update) or absent (insert).
// A tree that disables either op can't safely accept an
// `InsertOrUpdate` batch.
//
// Cost model matches `insert`: per-proof create_cost + per-entry
// insert_cost, computed against the proof bytes and tree height.
pub(super) fn insert_or_update(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }
    let avl = match &obj_val {
        Value::AvlTree(a) => a.clone(),
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for insertOrUpdate",
                got: format!("{other:?}"),
            })
        }
    };
    // Args evaluated before the body (Scala order) so the flag-deny
    // path still pays the entries+proof eval cost. insertOrUpdate
    // charges BOTH flag costs and uses the Update cost kind for both
    // paths — handled in eval_avl_mutate.
    let entries = extract_avl_entries(cx.eval_expr(&args[0])?)?;
    let proof = match cx.eval_expr(&args[1])? {
        Value::CollBytes(p) => p,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL proof",
                got: format!("{other:?}"),
            })
        }
    };
    eval_avl_mutate(&avl, entries, &proof, AvlMutOp::InsertOrUpdate, cx)
}

// SAvlTree(100).remove(14) -> Option[AvlTree]
pub(super) fn remove(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: args.len(),
        });
    }
    let avl = match &obj_val {
        Value::AvlTree(a) => a.clone(),
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for remove",
                got: format!("{other:?}"),
            })
        }
    };
    // Args evaluated before the body (Scala order) so the flag-deny
    // path still pays the keys+proof eval cost.
    let keys = extract_avl_keys(cx.eval_expr(&args[0])?)?;
    let proof = match cx.eval_expr(&args[1])? {
        Value::CollBytes(p) => p,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for AVL proof",
                got: format!("{other:?}"),
            })
        }
    };
    cx.cost.add(JitCost::from_jit(15))?; // isRemoveAllowed
    if !avl.remove_allowed {
        return Ok(Value::Opt(None));
    }
    let create_cost = CostKind::PerItem {
        base: JitCost::from_jit(110),
        per_chunk: JitCost::from_jit(20),
        chunk_size: 64,
    };
    cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
    let remove_cost = CostKind::PerItem {
        base: JitCost::from_jit(100),
        per_chunk: JitCost::from_jit(15),
        chunk_size: 1,
    };
    let mut bv_opt = try_make_avl_verifier(&avl, &proof);
    // treeHeight == digest height byte even on a failed construction.
    let nitems = avl_cost_height(&avl).max(1);
    // Scala remove_eval uses cfor (NOT forall): every key is charged
    // and attempted; per-op results are IGNORED — the outcome is
    // decided solely by the final bv.digest. Never throws.
    for key in &keys {
        cx.cost.add(remove_cost.compute(nitems)?)?;
        if let Some(bv) = bv_opt.as_mut() {
            let _ = bv.remove(key);
        }
    }
    // remove uniquely charges digest_Info(15) UNCONDITIONALLY after
    // the loop (insert/update/insertOrUpdate do not).
    cx.cost.add(JitCost::from_jit(15))?;
    match bv_opt.as_ref().and_then(|bv| bv.digest()) {
        Some(d) if d.len() == 33 => {
            cx.cost.add(JitCost::from_jit(40))?; // updateDigest_Info
            let mut updated = avl.clone();
            updated.digest = d;
            Ok(Value::Opt(Some(Box::new(Value::AvlTree(updated)))))
        }
        _ => Ok(Value::Opt(None)),
    }
}

// SAvlTree(100).updateDigest(15): SFunc(SAvlTree, SByteArray) -> SAvlTree.
// Scala CAvlTree.updateDigest = treeData.copy(digest = newDigest) — stores
// the new Coll[Byte] VERBATIM with NO length validation (3-byte, empty
// and over-length digests are all accepted). Body cost
// FixedCost(JitCost(40)); the 0xDC MethodCall(4) + obj/arg framing is
// charged at the eval entry. Returns a plain AvlTree (NOT Option).
pub(super) fn update_digest(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 1 {
        return Err(EvalError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }
    let mut updated = match &obj_val {
        Value::AvlTree(a) => a.clone(),
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for updateDigest",
                got: format!("{other:?}"),
            })
        }
    };
    let new_digest = match cx.eval_expr(&args[0])? {
        Value::CollBytes(b) => b,
        other => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for updateDigest",
                got: format!("{other:?}"),
            })
        }
    };
    cx.cost.add(JitCost::from_jit(40))?; // updateDigest FixedCost
    updated.digest = new_digest;
    Ok(Value::AvlTree(updated))
}

// SAvlTree(100).updateOperations(8): SFunc(SAvlTree, SByte) -> SAvlTree.
// Scala CAvlTree.updateOperations = treeData.copy(treeFlags =
// AvlTreeFlags(newOps)) — decodes the Byte bit-by-bit (insert = & 0x01,
// update = & 0x02, remove = & 0x04; higher bits ignored). Body cost
// FixedCost(JitCost(45)). Touches only the flags. Returns a plain AvlTree.
pub(super) fn update_operations(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if args.len() != 1 {
        return Err(EvalError::ArityMismatch {
            expected: 1,
            got: args.len(),
        });
    }
    let mut updated = match &obj_val {
        Value::AvlTree(a) => a.clone(),
        other => {
            return Err(EvalError::TypeError {
                expected: "AvlTree for updateOperations",
                got: format!("{other:?}"),
            })
        }
    };
    let flags = match cx.eval_expr(&args[0])? {
        Value::Byte(b) => b as u8,
        other => {
            return Err(EvalError::TypeError {
                expected: "Byte for updateOperations",
                got: format!("{other:?}"),
            })
        }
    };
    cx.cost.add(JitCost::from_jit(45))?; // updateOperations FixedCost
    updated.insert_allowed = flags & 0x01 != 0;
    updated.update_allowed = flags & 0x02 != 0;
    updated.remove_allowed = flags & 0x04 != 0;
    Ok(Value::AvlTree(updated))
}

/// Decoded `Coll[(Coll[Byte], Coll[Byte])]` AVL insert/update entries.
type AvlEntries = Vec<(Vec<u8>, Vec<u8>)>;

/// The three batch-mutating SAvlTree operations that take a
/// `Coll[(Coll[Byte], Coll[Byte])]` of key/value entries.
#[derive(Clone, Copy)]
enum AvlMutOp {
    Insert,
    Update,
    InsertOrUpdate,
}

/// Extract `Coll[(Coll[Byte], Coll[Byte])]` entries from an evaluated value
/// (the outer collection is the boxed-element `CollGeneric` carrier; each
/// inner element is a real 2-tuple `Value::Tuple`).
fn extract_avl_entries(v: Value) -> Result<AvlEntries, EvalError> {
    match v {
        Value::CollGeneric(items, _) => items
            .into_iter()
            .map(|item| match item {
                Value::Tuple(pair) if pair.len() == 2 => {
                    let mut it = pair.into_iter();
                    let k = match it.next().unwrap() {
                        Value::CollBytes(k) => k,
                        other => {
                            return Err(EvalError::TypeError {
                                expected: "Coll[Byte] for AVL entry key",
                                got: format!("{other:?}"),
                            })
                        }
                    };
                    let v = match it.next().unwrap() {
                        Value::CollBytes(v) => v,
                        other => {
                            return Err(EvalError::TypeError {
                                expected: "Coll[Byte] for AVL entry value",
                                got: format!("{other:?}"),
                            })
                        }
                    };
                    Ok((k, v))
                }
                other => Err(EvalError::TypeError {
                    expected: "(Coll[Byte], Coll[Byte]) AVL entry",
                    got: format!("{other:?}"),
                }),
            })
            .collect(),
        other => Err(EvalError::TypeError {
            expected: "Coll[(Coll[Byte], Coll[Byte])] AVL entries",
            got: format!("{other:?}"),
        }),
    }
}

/// Extract `Coll[Coll[Byte]]` keys from an evaluated value.
fn extract_avl_keys(v: Value) -> Result<Vec<Vec<u8>>, EvalError> {
    match v {
        Value::CollGeneric(items, _) => items
            .into_iter()
            .map(|item| match item {
                Value::CollBytes(k) => Ok(k),
                other => Err(EvalError::TypeError {
                    expected: "Coll[Byte] in AVL keys",
                    got: format!("{other:?}"),
                }),
            })
            .collect(),
        other => Err(EvalError::TypeError {
            expected: "Coll[Coll[Byte]] AVL keys",
            got: format!("{other:?}"),
        }),
    }
}

/// Shared insert/update/insertOrUpdate evaluation, mirroring Scala
/// `CErgoTreeEvaluator.{insert,update,insertOrUpdate}_eval`. The caller must
/// have already evaluated (and thereby charged) the `entries`/`proof` args
/// — Scala evaluates a MethodCall's args before the body, so the flag-deny
/// path still pays the arg-eval cost.
///
/// Cost (all JitCost): flag check(s) FixedCost(15) each (insertOrUpdate
/// charges BOTH isUpdate + isInsert = 30) BEFORE the boolean guard;
/// CreateAvlVerifier PerItemCost(110,20,64) over `proof.len`; per-entry op
/// cost (InsertIntoAvlTree(40,10,1) for insert, UpdateAvlTree(120,20,1) for
/// update AND insertOrUpdate) over `max(treeHeight,1)`, charged BEFORE the
/// per-entry validity check (so a failed entry is charged); updateDigest_Info
/// FixedCost(40) only on success.
///
/// Outcome: a flag-disabled tree returns None. Construction failure (bad
/// proof) and any op failure (bad key, wrong value-length) make the verifier
/// degrade — insert is the ONLY version-gated op (pre-v3 failure → errored;
/// v3+ → None); update/insertOrUpdate always return None on failure. Success
/// returns Some(tree.updateDigest(...)). Entries are processed with a
/// forall-style short-circuit after the first failing entry.
fn eval_avl_mutate(
    avl: &ergo_ser::sigma_value::AvlTreeData,
    entries: AvlEntries,
    proof: &[u8],
    op: AvlMutOp,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    // Flag *_Info cost(s) charged before the guard (insertOrUpdate needs both).
    match op {
        AvlMutOp::Insert => {
            cx.cost.add(JitCost::from_jit(15))?;
            if !avl.insert_allowed {
                return Ok(Value::Opt(None));
            }
        }
        AvlMutOp::Update => {
            cx.cost.add(JitCost::from_jit(15))?;
            if !avl.update_allowed {
                return Ok(Value::Opt(None));
            }
        }
        AvlMutOp::InsertOrUpdate => {
            cx.cost.add(JitCost::from_jit(15))?; // isUpdateAllowed
            cx.cost.add(JitCost::from_jit(15))?; // isInsertAllowed
            if !avl.update_allowed || !avl.insert_allowed {
                return Ok(Value::Opt(None));
            }
        }
    }
    let create_cost = CostKind::PerItem {
        base: JitCost::from_jit(110),
        per_chunk: JitCost::from_jit(20),
        chunk_size: 64,
    };
    cx.cost.add(create_cost.compute(proof.len() as u32)?)?;
    let op_cost = match op {
        AvlMutOp::Insert => CostKind::PerItem {
            base: JitCost::from_jit(40),
            per_chunk: JitCost::from_jit(10),
            chunk_size: 1,
        },
        AvlMutOp::Update | AvlMutOp::InsertOrUpdate => CostKind::PerItem {
            base: JitCost::from_jit(120),
            per_chunk: JitCost::from_jit(20),
            chunk_size: 1,
        },
    };
    let mut bv_opt = try_make_avl_verifier(avl, proof);
    // nItems = max(treeHeight,1); treeHeight == the digest's height byte even
    // on a failed construction (rootNodeHeight is set before the proof parse).
    let nitems = avl_cost_height(avl).max(1);
    let mut all_ok = true;
    for (key, value) in entries {
        // Per-entry op cost charged before the validity check.
        cx.cost.add(op_cost.compute(nitems)?)?;
        let ok = match bv_opt.as_mut() {
            Some(bv) => {
                // Pre-validate the value length to avoid the crate's op-time
                // assert! panic; a mismatch is the same op failure scrypto's
                // require() raises.
                if avl
                    .value_length_opt
                    .is_some_and(|vl| value.len() != vl as usize)
                {
                    false
                } else {
                    match op {
                        AvlMutOp::Insert => bv.insert(&key, &value).is_ok(),
                        AvlMutOp::Update => bv.update(&key, &value).is_ok(),
                        AvlMutOp::InsertOrUpdate => bv.insert_or_update(&key, &value).is_ok(),
                    }
                }
            }
            None => false, // construction failed
        };
        if !ok {
            all_ok = false;
            break; // forall short-circuit
        }
    }
    // Any op OR construction failure makes scrypto's topNode None -> digest
    // None -> the method returns None. Do NOT consult bv.digest() on failure:
    // a value-length failure is caught by the pre-check WITHOUT running the
    // op, so the verifier's topNode/digest is still the pre-failure value —
    // but Scala's failed performInsert/Update would have nulled it. And
    // updateDigest_Info(40) is charged only on success, so it's skipped here.
    if !all_ok {
        // insert is the ONLY version-gated op: a failed insert on a pre-v3
        // ErgoTree throws (syntax.error). `activated_script_version < 3`
        // implies the ErgoTree version is < 3 (a v3 tree cannot be spent
        // before v3 activation), so the throw is correct for that case.
        // PRE-EXISTING GAP (tracked): a legacy ErgoTree-v<3 box spent in a
        // post-activation (activated>=3) block — Scala throws but we return
        // None — needs the ErgoTree header version threaded into the eval
        // context (the same version-threading gap as getReg / SOption-pre-v3
        // / SHeader); the old no-gate code had this gap too.
        if matches!(op, AvlMutOp::Insert) && cx.ctx.activated_script_version < 3 {
            return Err(EvalError::RuntimeException(
                "AvlTree.insert failed on a pre-v3 ErgoTree",
            ));
        }
        return Ok(Value::Opt(None));
    }
    match bv_opt.as_ref().and_then(|bv| bv.digest()) {
        Some(d) if d.len() == 33 => {
            cx.cost.add(JitCost::from_jit(40))?; // updateDigest_Info (success only)
            let mut updated = avl.clone();
            updated.digest = d;
            Ok(Value::Opt(Some(Box::new(Value::AvlTree(updated)))))
        }
        _ => Ok(Value::Opt(None)),
    }
}
