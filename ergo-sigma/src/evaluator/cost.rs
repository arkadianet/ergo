use ergo_primitives::cost::{CostAccumulator, CostKind, JitCost};

use super::types::{BoxSource, EvalError, ReductionContext, Value};
use crate::cost_table;

pub(crate) fn add_cost(cost: &mut CostAccumulator, opcode: u8) -> Result<(), EvalError> {
    let delta = cost_table::opcode_cost(opcode)?.compute(0)?;
    cost.add(delta)?;
    #[cfg(feature = "cost-trace")]
    crate::cost_trace::record(
        format!("OP:0x{:02X}", opcode),
        delta.value(),
        cost.total().value(),
    );
    Ok(())
}

/// Add per-item cost for a collection opcode.
pub(crate) fn add_cost_per_item(
    cost: &mut CostAccumulator,
    opcode: u8,
    n: u32,
) -> Result<(), EvalError> {
    let delta = cost_table::opcode_cost(opcode)?.compute(n)?;
    cost.add(delta)?;
    #[cfg(feature = "cost-trace")]
    crate::cost_trace::record(
        format!("OP:0x{:02X}:n={}", opcode, n),
        delta.value(),
        cost.total().value(),
    );
    Ok(())
}

/// Add method-specific cost for MethodCall/PropertyCall dispatch.
pub(crate) fn add_method_cost(cost: &mut CostAccumulator, jit: u64) -> Result<(), EvalError> {
    cost.add(JitCost::from_jit(jit))?;
    #[cfg(feature = "cost-trace")]
    crate::cost_trace::record(format!("Method:{}", jit), jit, cost.total().value());
    Ok(())
}

/// Add arithmetic cost, accounting for BigInt operands.
pub(crate) fn add_arith_cost(
    cost: &mut CostAccumulator,
    opcode: u8,
    is_bigint: bool,
) -> Result<(), EvalError> {
    let delta = cost_table::arith_cost(opcode, is_bigint)?;
    cost.add(delta)?;
    #[cfg(feature = "cost-trace")]
    crate::cost_trace::record(
        format!("Arith:0x{:02X}", opcode),
        delta.value(),
        cost.total().value(),
    );
    Ok(())
}

/// Charge EQ_COA_Box = PerItemCost(base=15, perChunk=5, chunk=1) for Coll[Box] equality.
/// Scala short-circuits when collection lengths differ — only MatchType(1) is charged.
/// Called only from [`eq_with_cost_inner`]; the `eq_with_cost` wrapper emits the
/// single cumulative `cost-trace` entry, so no per-charge tracing is done here.
fn add_coll_box_eq_cost(
    cost: &mut CostAccumulator,
    n: u32,
    colls_match_len: bool,
) -> Result<(), EvalError> {
    // MatchType for collection dispatch in equalDataValues (1 only, no inner dispatch)
    cost.add(JitCost::from_jit(1))?;
    if colls_match_len {
        let delta = CostKind::PerItem {
            base: JitCost::from_jit(15),
            per_chunk: JitCost::from_jit(5),
            chunk_size: 1,
        }
        .compute(n)?;
        cost.add(delta)?;
    }
    Ok(())
}

/// Runtime length of a collection-carrier `Value` (resolving `BoxCollection`
/// through the context). Returns 0 for non-collection values (callers only
/// ask about collections).
fn coll_len(v: &Value, ctx: &ReductionContext<'_>) -> usize {
    match v {
        Value::CollBytes(c) => c.len(),
        Value::CollBool(c) => c.len(),
        Value::CollInt(c) => c.len(),
        Value::CollLong(c) => c.len(),
        Value::CollShort(c) => c.len(),
        Value::Str(s) => s.len(),
        Value::CollSigmaProp(c) => c.len(),
        Value::CollBox(c) => c.len(),
        Value::CollHeader(c) => c.len(),
        Value::Tokens(c) => c.len(),
        Value::CollGeneric(c, _) => c.len(),
        Value::BoxCollection(src) => match src {
            BoxSource::Outputs => ctx.outputs.len(),
            BoxSource::Inputs => ctx.inputs.len(),
            BoxSource::DataInputs => ctx.data_inputs.len(),
        },
        _ => 0,
    }
}

/// `EQ_COA_*` per-item cost descriptor for a `Coll[elem]` whose element type
/// has a dedicated Scala `DataValueComparer` descriptor (the
/// `equalColls_Dispatch` primitive/descriptor branches). Returns `None` for
/// element types with NO descriptor (`Coll`/`Tuple`/`Option`/`Any`/…), which
/// Scala routes to the `equalColls` FALLBACK (per-element recursion + EQ_Coll).
///
/// Chunk sizes mirror `sigma.data.DataValueComparer`: Boolean/Byte 128,
/// Short 96, Int 64, Long 48, BigInt (15,7,5), GroupElement/Box/Header (15,5,1),
/// AvlTree (15,5,2), PreHeader (15,3,1).
fn descriptor_cost_kind(elem: &ergo_ser::sigma_type::SigmaType) -> Option<CostKind> {
    use ergo_ser::sigma_type::SigmaType as T;
    let pic = |per_chunk: u64, chunk_size: u32| CostKind::PerItem {
        base: JitCost::from_jit(15),
        per_chunk: JitCost::from_jit(per_chunk),
        chunk_size,
    };
    Some(match elem {
        T::SBoolean | T::SByte => pic(2, 128),
        T::SShort => pic(2, 96),
        T::SInt => pic(2, 64),
        T::SLong => pic(2, 48),
        T::SBigInt | T::SUnsignedBigInt => pic(7, 5),
        T::SGroupElement => pic(5, 1),
        T::SAvlTree => pic(5, 2),
        T::SBox => pic(5, 1),
        T::SPreHeader => pic(3, 1),
        T::SHeader => pic(5, 1),
        // No Scala descriptor for SigmaProp; our typed `CollSigmaProp`
        // carrier has historically costed (15,5,1) and no vector exercises
        // a `Coll[SigmaProp]` equality, so keep parity here pending a vector.
        T::SSigmaProp => pic(5, 1),
        // SColl/SOption/STuple/SAny/SString/SContext/SGlobal/SFunc/STypeVar/
        // SUnit/SReserved* → equalColls fallback (no descriptor).
        _ => return None,
    })
}

/// Cost-aware structural equality for the `EQ`/`NEQ` opcodes and `indexOf`,
/// faithfully mirroring Scala `DataValueComparer.equalDataValues`: it dispatches
/// on the LEFT value, charges the same per-case cost in the same order, and
/// returns the SAME boolean as [`super::helpers::values_equal`] (which stays the
/// uncosted equality authority for callers like `startsWith`/`endsWith` that
/// charge no per-element cost in Scala).
///
/// Charge model (all values are `JitCost`):
/// * primitives `EQ_Prim(3)`, BigInt `EQ_BigInt(5)`, GroupElement(172),
///   Box(6), AvlTree(6), Header(6), PreHeader(4) — fixed, via `add_eq_cost`.
/// * Tuple: `EQ_Tuple(4)` then pairwise recursion with `&&` short-circuit.
/// * Option: `EQ_Option(4)` then inner recursion on `(Some, Some)`.
/// * Collection: `MatchType(1)` UNCONDITIONALLY; on length mismatch returns
///   `false` having charged only the MatchType (Scala's `return false`); else
///   either the descriptor `EQ_COA_*` PerItem over the full length (boolean
///   from `values_equal`), or the `equalColls` fallback (per-element recursion
///   + `EQ_Coll(10,2,1)` over the number of elements actually compared).
///
/// This thin wrapper records a single cumulative `cost-trace` entry covering
/// the whole comparison (all recursion goes through the untraced
/// [`eq_with_cost_inner`]), so the trace's per-entry cumulative invariant
/// holds and the trace total still equals the accumulator total.
pub(crate) fn eq_with_cost(
    left: &Value,
    right: &Value,
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<bool, EvalError> {
    #[cfg(feature = "cost-trace")]
    let before = cost.total().value();
    let result = eq_with_cost_inner(left, right, ctx, cost);
    #[cfg(feature = "cost-trace")]
    {
        let total = cost.total().value();
        if total != before {
            crate::cost_trace::record("EQ", total - before, total);
        }
    }
    result
}

/// Untraced recursive core of [`eq_with_cost`]; see that function's docs. All
/// internal recursion calls THIS (not the wrapper) so the wrapper records
/// exactly one trace entry per top-level comparison.
fn eq_with_cost_inner(
    left: &Value,
    right: &Value,
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<bool, EvalError> {
    match left {
        // Tuple: EQ_Tuple, then pairwise `&&` short-circuit (Scala case 3).
        Value::Tuple(a) => {
            cost.add(JitCost::from_jit(cost_table::EQ_TUPLE))?;
            match right {
                Value::Tuple(b) if a.len() == b.len() => {
                    for (ai, bi) in a.iter().zip(b.iter()) {
                        if !eq_with_cost_inner(ai, bi, ctx, cost)? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
        // Option: EQ_Option, then recurse the inner value on (Some, Some).
        Value::Opt(a) => {
            cost.add(JitCost::from_jit(cost_table::EQ_OPTION))?;
            match (a.as_deref(), right) {
                (None, Value::Opt(None)) => Ok(true),
                (Some(ai), Value::Opt(Some(bi))) => eq_with_cost_inner(ai, bi, ctx, cost),
                _ => Ok(false),
            }
        }
        // Boxed-element collection carrier: dispatch on the element-type tag.
        Value::CollGeneric(a, elem_type) => {
            cost.add(JitCost::from_jit(cost_table::MATCH_TYPE))?;
            let match_len = a.len() == coll_len(right, ctx);
            if !match_len {
                return Ok(false); // Scala `return false` after the lone MatchType.
            }
            if let Some(kind) = descriptor_cost_kind(elem_type) {
                cost.add(kind.compute(a.len() as u32)?)?;
                Ok(super::helpers::values_equal(left, right, ctx)?)
            } else {
                eq_coll_fallback(a, right, ctx, cost)
            }
        }
        // BoxCollection — Coll[Box]; length needs the context.
        Value::BoxCollection(_) => {
            let n = coll_len(left, ctx);
            let match_len = n == coll_len(right, ctx);
            add_coll_box_eq_cost(cost, n as u32, match_len)?;
            Ok(super::helpers::values_equal(left, right, ctx)?)
        }
        // Typed primitive/descriptor coll carriers + Tokens: the existing
        // `add_eq_cost` arms already charge MatchType + length-gated PerItem
        // faithfully (full length, no per-element short-circuit — Scala's
        // primitive/descriptor branches cost the whole array).
        Value::CollBytes(_)
        | Value::CollBool(_)
        | Value::CollInt(_)
        | Value::CollLong(_)
        | Value::CollShort(_)
        | Value::Str(_)
        | Value::CollSigmaProp(_)
        | Value::CollBox(_)
        | Value::CollHeader(_)
        | Value::Tokens(_) => {
            let match_len = coll_len(left, ctx) == coll_len(right, ctx);
            cost_table::add_eq_cost(cost, left, match_len)?;
            Ok(super::helpers::values_equal(left, right, ctx)?)
        }
        // Scalars / Box / AvlTree / Header / PreHeader / GroupElement / BigInt /
        // SigmaProp / Global: fixed cost, no recursion.
        _ => {
            cost_table::add_eq_cost(cost, left, true)?;
            Ok(super::helpers::values_equal(left, right, ctx)?)
        }
    }
}

/// Scala `equalColls` FALLBACK for a `Coll[non-descriptor]` (e.g. `Coll[Coll]`,
/// `Coll[Tuple]`, `Coll[Option]`): recurse per element charging each element's
/// `equalDataValues` cost, stopping at the first unequal element, then charge
/// `EQ_Coll = PerItemCost(10, 2, 1)` over the number of elements ACTUALLY
/// compared (`k_eff`) — matching Scala's `addSeqCost(EQ_Coll, i)` after the loop.
/// The caller has already charged the collection `MatchType` and verified equal
/// lengths.
fn eq_coll_fallback(
    a: &[Value],
    right: &Value,
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<bool, EvalError> {
    let b: &[Value] = match right {
        Value::CollGeneric(b, _) | Value::CollBox(b) => b,
        // Non-descriptor element collections are carried as CollGeneric on
        // both sides; any other right carrier is a type the comparison cannot
        // reach (require_comparable gates this). Fall back to the uncosted
        // authority for the boolean; cost already reflects the MatchType.
        _ => {
            return super::helpers::values_equal(
                &Value::CollGeneric(a.to_vec(), Box::new(ergo_ser::sigma_type::SigmaType::SAny)),
                right,
                ctx,
            )
        }
    };
    let mut k_eff = 0u32;
    let mut all_eq = true;
    for (ai, bi) in a.iter().zip(b.iter()) {
        k_eff += 1;
        if !eq_with_cost_inner(ai, bi, ctx, cost)? {
            all_eq = false;
            break;
        }
    }
    let eq_coll = CostKind::PerItem {
        base: JitCost::from_jit(10),
        per_chunk: JitCost::from_jit(2),
        chunk_size: 1,
    };
    cost.add(eq_coll.compute(k_eff)?)?;
    Ok(all_eq)
}

/// Tree-height byte stored in the trailing position of an `ADDigest`
/// (32-byte digest || 1-byte height). Mirrors Scala
/// `AvlTreeData.treeHeight` and is the input the lookup-cost
/// per-item model multiplies against.
pub(crate) fn avl_tree_height(avl: &ergo_ser::sigma_value::AvlTreeData) -> u32 {
    *avl.digest
        .as_bytes()
        .last()
        .expect("ADDigest is always 33 bytes by construction (32 digest + 1 height)") as u32
}

/// The tree height to use for AVL per-op/lookup cost (`nItems`). scrypto's
/// `BatchAVLVerifier` sets `rootNodeHeight = startingDigest.last` (= the
/// digest's height byte) only AFTER its metadata `require`s pass — chiefly
/// `require(keyLength > 0)`. If the metadata itself is rejected (a tree with
/// `keyLength == 0`, or a wrapped-negative keyLength), reconstruction fails
/// BEFORE `rootNodeHeight` is set, so `treeHeight` stays 0. A bad PROOF on
/// otherwise-valid metadata fails AFTER `rootNodeHeight` is set, so the
/// height is still the digest byte. This distinction is consensus-visible in
/// the per-op cost (`Math.max(treeHeight, 1)` for mutators), so a tree with
/// invalid metadata must cost `nItems = 1`, not the digest height. On a
/// successful construction `keyLength > 0` holds, so this returns the digest
/// height as before.
///
/// The metadata `require`s are evaluated against the SIGNED `Int` view Scala
/// exposes: `require(keyLength > 0)` and `require(valueLengthOpt.forall(_ >=
/// 0))`. `key_length`/`value_length_opt` are now signed `i32` (a serialized
/// length above `i32::MAX` is read wrapped to a NEGATIVE value), so a wrapped
/// length is directly `< 0` here and correctly counts as invalid metadata.
pub(crate) fn avl_cost_height(avl: &ergo_ser::sigma_value::AvlTreeData) -> u32 {
    if avl.key_length > 0 && avl.value_length_opt.is_none_or(|v| v >= 0) {
        avl_tree_height(avl)
    } else {
        0
    }
}

/// Construct an AVL proof verifier from AvlTreeData and proof bytes.
pub(crate) fn make_avl_verifier(
    avl: &ergo_ser::sigma_value::AvlTreeData,
    proof: &[u8],
) -> Result<crate::avl::AvlVerifier, EvalError> {
    // Reject invalid metadata up front (scrypto `require(keyLength > 0)` /
    // `require(valueLengthOpt.forall(_ >= 0))` — these fail BEFORE the tree is
    // reconstructed, yielding reconstructedTree=None). Doing this here mirrors
    // Scala AND avoids passing a wrapped-negative length to the third-party
    // crate as a huge `usize`. `try_make_avl_verifier` maps this Err to None,
    // so the method arms degrade gracefully (contains→false, etc.).
    if avl.key_length <= 0 || avl.value_length_opt.is_some_and(|v| v < 0) {
        return Err(EvalError::TypeError {
            expected: "valid AVL metadata (keyLength > 0, valueLengthOpt >= 0)",
            got: format!(
                "keyLength={}, valueLengthOpt={:?}",
                avl.key_length, avl.value_length_opt
            ),
        });
    }
    crate::avl::AvlVerifier::new(
        avl.digest.as_bytes(),
        proof,
        avl.key_length as usize,
        avl.value_length_opt.map(|v| v as usize),
    )
    .map_err(|e| EvalError::TypeError {
        expected: "valid AVL proof",
        got: format!("verifier construction failed: {e}"),
    })
}

/// Construct an AVL verifier, degrading gracefully on ANY construction
/// failure — both the typed `Err` (digest mismatch) AND a panic from the
/// third-party `ergo_avltree_rust` crate's eager proof-graph reconstruction
/// (a malformed/empty/truncated/0x00 proof panics inside
/// `BatchAVLVerifier::new`). Returns `None` on failure, mirroring scrypto,
/// where a bad proof yields `reconstructedTree = None` (the constructor
/// never throws) — so each SAvlTree method arm maps `None` to its Scala
/// per-method outcome (contains → false, get/getMany → error, insert
/// pre-v3 → error / v3+ → None, update/remove/insertOrUpdate → None)
/// instead of aborting the whole evaluation.
///
/// COST NOTE: a failed construction yields `digest = None`, but its
/// `treeHeight` is STILL the digest's height byte — scrypto sets
/// `rootNodeHeight = startingDigest.last` BEFORE the proof parse that fails
/// (BatchAVLVerifier), so `treeHeight` does not drop to 0 on failure.
/// Therefore the failure-path lookup/op per-item cost uses the digest height
/// (`avl_tree_height`), exactly as the success path — NOT zero. (Verified
/// against the JVM-blessed contains-on-bad-proof vector cost.)
///
/// The `catch_unwind` is confined to this evaluator-only helper; the shared
/// [`crate::avl::AvlVerifier`] is left untouched so the digest-mode
/// validator (which has its own construction guard) is unaffected.
pub(crate) fn try_make_avl_verifier(
    avl: &ergo_ser::sigma_value::AvlTreeData,
    proof: &[u8],
) -> Option<crate::avl::AvlVerifier> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        make_avl_verifier(avl, proof)
    }))
    .ok()
    .and_then(|r| r.ok())
}

/// Get the length of a collection value (for per-item costing).
pub(crate) fn collection_len(coll: &Value, ctx: &ReductionContext) -> usize {
    match coll {
        Value::CollBytes(v) => v.len(),
        Value::CollShort(v) => v.len(),
        Value::CollInt(v) => v.len(),
        Value::CollLong(v) => v.len(),
        Value::CollBool(v) => v.len(),
        Value::CollSigmaProp(v) => v.len(),
        Value::CollBox(v) => v.len(),
        Value::CollHeader(v) => v.len(),
        Value::Tokens(v) => v.len(),
        // `CollGeneric` is the boxed-element coll carrier (Coll[Tuple]
        // etc.); a real `Value::Tuple` is not a collection and falls
        // through to the `_ => 0` non-coll branch below.
        Value::CollGeneric(v, _) => v.len(),
        Value::BoxCollection(src) => match src {
            BoxSource::Outputs => ctx.outputs.len(),
            BoxSource::Inputs => ctx.inputs.len(),
            BoxSource::DataInputs => ctx.data_inputs.len(),
        },
        _ => 0,
    }
}
