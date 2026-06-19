use ergo_primitives::cost::{CostAccumulator, CostKind, JitCost};
use ergo_ser::sigma_value::SigmaBoolean;

use super::types::{BoxSource, EvalError, ReductionContext, Value};
use crate::cost_table;

/// Faithful port of Scala `DataValueComparer.equalSigmaBoolean` (cost AND
/// value/error). `cost` is `Some` on the consensus EQ/NEQ path (charges the
/// Scala costs) and `None` for the uncosted `values_equal` authority — both
/// must agree on the boolean AND on when to error.
///
/// Per Scala (DataValueComparer.scala:252-282):
/// * one `MatchType` (JitCost 1) per node, charged at the top before dispatch;
/// * `EQ_GroupElement` (JitCost 172) per EcPoint comparison, with the
///   ProveDHTuple `&&` short-circuit (no cost past the first unequal point);
/// * LEAF arms (ProveDlog/ProveDHTuple/TrivialProp) have NO guard and return
///   `false` on a constructor mismatch;
/// * CONJECTURE arms (Cand/Cor/Cthreshold) are guarded, and a mismatched-right
///   falls through to `sys.error` — i.e. THROWS (errored). Order-sensitive:
///   `CAND` left vs `ProveDlog` right errors, but `ProveDlog` left vs `CAND`
///   right is `false`.
pub(crate) fn equal_sigma_boolean(
    l: &SigmaBoolean,
    r: &SigmaBoolean,
    mut cost: Option<&mut CostAccumulator>,
) -> Result<bool, EvalError> {
    // One MatchType per node, before dispatch (charged even on throwing arms).
    if let Some(c) = cost.as_deref_mut() {
        c.add(JitCost::from_jit(cost_table::MATCH_TYPE))?;
    }
    let mismatch =
        || EvalError::RuntimeException("Cannot compare SigmaBoolean values: unknown type");
    match l {
        SigmaBoolean::ProveDlog(x) => match r {
            SigmaBoolean::ProveDlog(y) => {
                if let Some(c) = cost.as_deref_mut() {
                    c.add(JitCost::from_jit(cost_table::EQ_GROUP_ELEMENT))?;
                }
                Ok(x == y)
            }
            _ => Ok(false),
        },
        SigmaBoolean::ProveDHTuple {
            g: xg,
            h: xh,
            u: xu,
            v: xv,
        } => match r {
            SigmaBoolean::ProveDHTuple {
                g: yg,
                h: yh,
                u: yu,
                v: yv,
            } => {
                // `&&` short-circuit: equalECPoint charges 172 then compares;
                // a mismatch stops the chain (later points not charged).
                for (a, b) in [(xg, yg), (xh, yh), (xu, yu)] {
                    if let Some(c) = cost.as_deref_mut() {
                        c.add(JitCost::from_jit(cost_table::EQ_GROUP_ELEMENT))?;
                    }
                    if a != b {
                        return Ok(false);
                    }
                }
                if let Some(c) = cost.as_deref_mut() {
                    c.add(JitCost::from_jit(cost_table::EQ_GROUP_ELEMENT))?;
                }
                Ok(xv == yv)
            }
            _ => Ok(false),
        },
        SigmaBoolean::TrivialProp(a) => match r {
            // No extra cost beyond the per-node MatchType already charged.
            SigmaBoolean::TrivialProp(b) => Ok(a == b),
            _ => Ok(false),
        },
        SigmaBoolean::Cand(ch) => match r {
            SigmaBoolean::Cand(rch) => equal_sigma_booleans(ch, rch, cost),
            _ => Err(mismatch()),
        },
        SigmaBoolean::Cor(ch) => match r {
            SigmaBoolean::Cor(rch) => equal_sigma_booleans(ch, rch, cost),
            _ => Err(mismatch()),
        },
        SigmaBoolean::Cthreshold { k, children } => match r {
            SigmaBoolean::Cthreshold {
                k: k2,
                children: c2,
            } => {
                // `k == k2 && equalSigmaBooleans(...)`: k mismatch short-circuits
                // to false (NOT an error — same constructor).
                if k != k2 {
                    return Ok(false);
                }
                equal_sigma_booleans(children, c2, cost)
            }
            _ => Err(mismatch()),
        },
    }
}

/// Scala `equalSigmaBooleans`: length mismatch -> `false` (no recursion/cost);
/// otherwise compare element-wise with a first-false short-circuit (errors
/// propagate).
pub(crate) fn equal_sigma_booleans(
    xs: &[SigmaBoolean],
    ys: &[SigmaBoolean],
    mut cost: Option<&mut CostAccumulator>,
) -> Result<bool, EvalError> {
    if xs.len() != ys.len() {
        return Ok(false);
    }
    for (x, y) in xs.iter().zip(ys.iter()) {
        if !equal_sigma_boolean(x, y, cost.as_deref_mut())? {
            return Ok(false);
        }
    }
    Ok(true)
}

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
        // SigmaProp: Scala equalDataValues charges ONE MatchType then dispatches
        // to equalSigmaBoolean (which has its own per-node cost AND the
        // conjecture-mismatch throw). Must be its own arm — the add_eq_cost +
        // values_equal split cannot express the short-circuit nor the error.
        Value::SigmaProp(lsb) => {
            cost.add(JitCost::from_jit(cost_table::MATCH_TYPE))?;
            match right {
                Value::SigmaProp(rsb) => equal_sigma_boolean(lsb, rsb, Some(cost)),
                _ => Ok(false),
            }
        }
        // Coll[SigmaProp]: Scala has NO primitive descriptor for SigmaProp, so
        // it uses the equalColls fallback — collection MatchType, then per
        // element `equalDataValues` (one MatchType + equalSigmaBoolean), then
        // EQ_Coll = PerItemCost(10,2,1) over the elements actually compared.
        // Routing through equalSigmaBoolean is what lets a Coll[CAND] vs
        // Coll[ProveDlog] element throw (errored), matching the reference.
        Value::CollSigmaProp(a) => {
            cost.add(JitCost::from_jit(cost_table::MATCH_TYPE))?;
            match right {
                Value::CollSigmaProp(b) => {
                    if a.len() != b.len() {
                        return Ok(false);
                    }
                    let mut k_eff = 0u32;
                    let mut all_eq = true;
                    for (li, ri) in a.iter().zip(b.iter()) {
                        k_eff += 1;
                        // per-element equalDataValues SigmaProp-case MatchType
                        cost.add(JitCost::from_jit(cost_table::MATCH_TYPE))?;
                        if !equal_sigma_boolean(li, ri, Some(cost))? {
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
                _ => Ok(false),
            }
        }
        // Primitive coll carriers: Scala's `equalCOA_Prim` short-circuits BOTH
        // value and cost at the first unequal element — `PerItemCost` is billed
        // over the COMPARED PREFIX, not the full length. Mirror that. (All-equal
        // and length-mismatch costs are unchanged; only early-mismatch is
        // cheaper, matching the reference.) Per-type chunk sizes from
        // `cost_table::add_eq_cost`: Byte/Bool=128, Short=96, Int=64, Long=48.
        Value::CollBytes(a) => match right {
            Value::CollBytes(b) => prim_coll_eq(cost, a, b, 128),
            _ => prim_coll_eq_fallback(cost, left, right, ctx),
        },
        Value::CollBool(a) => match right {
            Value::CollBool(b) => prim_coll_eq(cost, a, b, 128),
            _ => prim_coll_eq_fallback(cost, left, right, ctx),
        },
        Value::CollShort(a) => match right {
            Value::CollShort(b) => prim_coll_eq(cost, a, b, 96),
            _ => prim_coll_eq_fallback(cost, left, right, ctx),
        },
        Value::CollInt(a) => match right {
            Value::CollInt(b) => prim_coll_eq(cost, a, b, 64),
            _ => prim_coll_eq_fallback(cost, left, right, ctx),
        },
        Value::CollLong(a) => match right {
            Value::CollLong(b) => prim_coll_eq(cost, a, b, 48),
            _ => prim_coll_eq_fallback(cost, left, right, ctx),
        },
        // SString equality is NOT equalCOA_Prim: Scala's string case bills
        // `addSeqCost(EQ_COA_Short, s.length)` — the FULL length even on an early
        // mismatch — so it must NOT short-circuit (doing so would undercharge a
        // long early-mismatch string and diverge on cost-limit decisions). Keep
        // the full-length `add_eq_cost` charge. Box / Header / Tokens colls use
        // Scala's `equalColls` (per-element) path, also charged via `add_eq_cost`.
        Value::Str(_) | Value::CollBox(_) | Value::CollHeader(_) => {
            let match_len = coll_len(left, ctx) == coll_len(right, ctx);
            cost_table::add_eq_cost(cost, left, match_len)?;
            Ok(super::helpers::values_equal(left, right, ctx)?)
        }
        // Tokens = Coll[(Coll[Byte], Long)]. Scala compares this via case 2
        // (Coll) → the `equalColls` fallback (the pair element type is not a
        // `descriptors` entry): outer `MatchType`, then per-token
        // `equalDataValues` short-circuiting at the FIRST unequal token, then
        // `EQ_Coll(10,2,1)` over the number of tokens actually compared.
        // Materialize each token as a `Tuple(Coll[Byte], Long)` and reuse the
        // Tuple / CollBytes / Long arms, which already reproduce — with full
        // short-circuit at every level — the per-token cost: `EQ_Tuple(4)` +
        // token-id (`MatchType(1)` + `EQ_COA_Byte` over the compared byte
        // prefix) + amount (`EQ_Prim(3)`, skipped by the tuple's `&&` when the
        // id already differs). A token collection can arrive on the right as
        // either `Tokens` or the `CollGeneric` tuple carrier (the two are
        // bridged by `PartialEq`), so normalize both carriers.
        Value::Tokens(a) => {
            cost.add(JitCost::from_jit(cost_table::MATCH_TYPE))?;
            let b_view = match right {
                Value::Tokens(b) => token_tuple_values(b),
                Value::CollGeneric(b, _) => b.clone(),
                // `require_comparable` gates the operand types; any other right
                // carrier is unreachable. The case-2 MatchType is charged;
                // defer the boolean to the uncosted authority.
                _ => return super::helpers::values_equal(left, right, ctx),
            };
            if a.len() != b_view.len() {
                return Ok(false); // Scala returns false after the lone MatchType
            }
            eq_coll_elems(&token_tuple_values(a), &b_view, ctx, cost)
        }
        // Scalars / Box / AvlTree / Header / PreHeader / GroupElement / BigInt /
        // Global: fixed cost, no recursion.
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
    // A token collection on the right is carried as `Value::Tokens`, not
    // `CollGeneric` — materialize it into the same tuple view so the
    // per-element costs are charged (skipping this is an UNDERCHARGE vs the
    // Scala `equalColls` fallback).
    let b_owned;
    let b: &[Value] = match right {
        Value::CollGeneric(b, _) | Value::CollBox(b) => b,
        Value::Tokens(t) => {
            b_owned = token_tuple_values(t);
            &b_owned
        }
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
    eq_coll_elems(a, b, ctx, cost)
}

/// Materialize a `Value::Tokens` payload as the `Coll[(Coll[Byte], Long)]`
/// tuple view Scala's `equalColls` walks — one `Tuple(Coll[Byte], Long)` per
/// token. Lets the token-equality cost reuse the Tuple / CollBytes / Long
/// short-circuit arms instead of a bespoke (and previously divergent) charge.
fn token_tuple_values(tokens: &[([u8; 32], u64)]) -> Vec<Value> {
    tokens
        .iter()
        .map(|(id, amount)| {
            Value::Tuple(vec![
                Value::CollBytes(id.to_vec()),
                Value::Long(*amount as i64),
            ])
        })
        .collect()
}

/// Scala `equalColls` per-element loop: recurse each element through
/// `equalDataValues` (`eq_with_cost_inner`), stopping at the first unequal
/// element, then charge `EQ_Coll = PerItemCost(10, 2, 1)` over the number of
/// elements ACTUALLY compared (`k_eff`) — matching `addSeqCost(EQ_Coll, i)`.
/// Callers must have charged the collection `MatchType` and verified equal
/// lengths.
fn eq_coll_elems(
    a: &[Value],
    b: &[Value],
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<bool, EvalError> {
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

/// Scala `DataValueComparer.equalCOA_Prim`: primitive-array equality that
/// short-circuits BOTH value and cost at the first unequal element. Charges
/// `MatchType`, then `PerItemCost(15, 2, chunk_size)` over the COMPARED PREFIX
/// — the first-mismatch index + 1, or the full length when all elements are
/// equal — mirroring `addSeqCost(EQ_COA_<T>, i)` where `i` is the loop's
/// returned compared count. A length mismatch returns `false` after only the
/// `MatchType` charge (Scala returns before the per-item loop). For all-equal
/// (and empty) collections the compared count equals the length, so the cost is
/// identical to the prior full-length charge. The caller guarantees `a`/`b` are
/// the same primitive carrier.
fn prim_coll_eq<T: PartialEq>(
    cost: &mut CostAccumulator,
    a: &[T],
    b: &[T],
    chunk_size: u32,
) -> Result<bool, EvalError> {
    cost.add(JitCost::from_jit(cost_table::MATCH_TYPE))?;
    if a.len() != b.len() {
        return Ok(false);
    }
    let mut k_eff = 0u32;
    let mut all_eq = true;
    for (ai, bi) in a.iter().zip(b.iter()) {
        k_eff += 1;
        if ai != bi {
            all_eq = false;
            break;
        }
    }
    let eq_coa = CostKind::PerItem {
        base: JitCost::from_jit(15),
        per_chunk: JitCost::from_jit(2),
        chunk_size,
    };
    cost.add(eq_coa.compute(k_eff)?)?;
    Ok(all_eq)
}

/// Defensive fallback for the unreachable case where two operands reaching
/// equality are not the same primitive carrier (`require_comparable` gates this
/// out). Charges the prior full-length cost and defers the boolean to the
/// uncosted authority.
fn prim_coll_eq_fallback(
    cost: &mut CostAccumulator,
    left: &Value,
    right: &Value,
    ctx: &ReductionContext<'_>,
) -> Result<bool, EvalError> {
    let match_len = coll_len(left, ctx) == coll_len(right, ctx);
    cost_table::add_eq_cost(cost, left, match_len)?;
    super::helpers::values_equal(left, right, ctx)
}

/// Tree-height byte stored in the trailing position of an `ADDigest`
/// (32-byte digest || 1-byte height). Mirrors Scala
/// `AvlTreeData.treeHeight` and is the input the lookup-cost
/// per-item model multiplies against.
pub(crate) fn avl_tree_height(avl: &ergo_ser::sigma_value::AvlTreeData) -> u32 {
    // The trailing byte of a 33-byte digest is the tree height. After
    // `SAvlTree.updateDigest` the digest may be any length (incl. empty), so
    // this must NOT panic: an empty digest has no height byte -> 0 (matching
    // scrypto's `rootNodeHeight` initializer).
    avl.digest.last().copied().map(u32::from).unwrap_or(0)
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
    // scrypto's `BatchAVLVerifier` `require(startingDigest.length == labelLength
    // + 1)` (= 33) throws BEFORE `rootNodeHeight = startingDigest.last` is set,
    // so a non-33-byte digest (e.g. from `updateDigest`) yields a failed
    // reconstruction with treeHeight 0 — NOT the trailing byte. Without this
    // guard a 3-byte digest would mis-cost the lookup at height = its last byte.
    if avl.key_length > 0 && avl.value_length_opt.is_none_or(|v| v >= 0) && avl.digest.len() == 33 {
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
        &avl.digest,
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

#[cfg(test)]
mod prim_coll_eq_tests {
    use super::*;

    // ----- helpers -----

    fn eq_cost(a: &[u8], b: &[u8]) -> (u64, bool) {
        let mut c = CostAccumulator::recording_only();
        let eq = prim_coll_eq(&mut c, a, b, 128).expect("prim_coll_eq");
        (c.total().value(), eq)
    }

    // ----- happy path -----

    /// `equalCOA_Prim`: the per-item cost scales with the COMPARED prefix
    /// (first-mismatch index + 1), so an early mismatch costs strictly less than
    /// a late one — the Scala short-circuit the prior full-length charge missed.
    #[test]
    fn collbytes_eq_cost_short_circuits_at_first_mismatch() {
        let base = vec![0u8; 512];
        let mut early = base.clone();
        early[0] = 1; // mismatch at index 0 -> compared 1
        let mut late = base.clone();
        late[500] = 1; // mismatch at index 500 -> compared 501

        let (c_early, e_early) = eq_cost(&base, &early);
        let (c_late, e_late) = eq_cost(&base, &late);
        assert!(!e_early && !e_late, "both differ -> not equal");
        assert!(
            c_early < c_late,
            "early mismatch must cost less than late: {c_early} vs {c_late}"
        );
    }

    /// All-equal bills over the full length (compared count == length), so the
    /// cost is unchanged from the prior full-length charge.
    #[test]
    fn collbytes_eq_cost_all_equal_bills_full_length() {
        let base = vec![7u8; 512];
        let (c_eq, eq) = eq_cost(&base, &base);
        let mut last = base.clone();
        last[511] = 9; // mismatch at the last index -> compared 512 == length
        let (c_full, _) = eq_cost(&base, &last);
        assert!(eq, "identical colls are equal");
        assert_eq!(
            c_eq, c_full,
            "all-equal must bill the same as a last-element mismatch (both compare all)"
        );
    }

    // ----- error paths -----

    /// A length mismatch returns `false` after only the `MatchType` charge —
    /// Scala returns before the per-item loop, so no per-item cost is billed.
    #[test]
    fn collbytes_eq_cost_length_mismatch_charges_only_match_type() {
        let (c, eq) = eq_cost(&vec![0u8; 512], &[0u8; 10]);
        assert!(!eq, "different lengths -> not equal");
        assert_eq!(
            c,
            cost_table::MATCH_TYPE,
            "length mismatch bills only MatchType, no per-item"
        );
    }

    /// Two empty colls are equal; the compared count is 0, so the cost is
    /// `MatchType` + `PerItemCost.compute(0)` (the base, no chunks).
    #[test]
    fn collbytes_eq_cost_empty_collections() {
        let (c, eq) = eq_cost(&[], &[]);
        assert!(eq, "empty colls are equal");
        let base = CostKind::PerItem {
            base: JitCost::from_jit(15),
            per_chunk: JitCost::from_jit(2),
            chunk_size: 128,
        }
        .compute(0)
        .unwrap()
        .value();
        assert_eq!(
            c,
            cost_table::MATCH_TYPE + base,
            "empty: MatchType + base cost over 0 items"
        );
    }

    /// The short-circuit holds across the non-byte chunk sizes (Short=96,
    /// Int=64, Long=48) — `prim_coll_eq` is generic over the carrier, so an
    /// early mismatch must cost less than a late one at every chunk size.
    #[test]
    fn prim_coll_eq_short_circuits_across_chunk_sizes() {
        fn cost_i32(a: &[i32], b: &[i32], chunk: u32) -> u64 {
            let mut c = CostAccumulator::recording_only();
            prim_coll_eq(&mut c, a, b, chunk).expect("prim_coll_eq");
            c.total().value()
        }
        for chunk in [96u32, 64, 48] {
            let base = vec![0i32; 200];
            let mut early = base.clone();
            early[0] = 1;
            let mut late = base.clone();
            late[199] = 1;
            let c_early = cost_i32(&base, &early, chunk);
            let c_late = cost_i32(&base, &late, chunk);
            assert!(
                c_early < c_late,
                "chunk {chunk}: early {c_early} must cost less than late {c_late}"
            );
        }
    }
}

#[cfg(test)]
mod token_eq_tests {
    use super::*;
    use ergo_ser::sigma_type::SigmaType;

    // ----- helpers -----

    fn tok(id_fill: u8, amount: u64) -> ([u8; 32], u64) {
        ([id_fill; 32], amount)
    }

    /// Top-level EQ cost (and boolean) for two values, via the real
    /// `eq_with_cost` entry the EQ/NEQ opcode uses.
    fn cost_eq(left: &Value, right: &Value) -> (u64, bool) {
        let c = ReductionContext::minimal(500_000, 0);
        let mut acc = CostAccumulator::recording_only();
        let eq = eq_with_cost(left, right, &c, &mut acc).expect("eq_with_cost");
        (acc.total().value(), eq)
    }

    // Oracle (Scala `DataValueComparer`, case 2 Coll -> `equalColls` fallback,
    // token id 32 bytes): outer MatchType(1) + per compared token
    //   [EQ_Tuple(4) + id(MatchType(1) + EQ_COA_Byte over compared bytes = 17)
    //    + amount EQ_Prim(3), the amount skipped by the tuple `&&` if the id
    //    already differs] + EQ_Coll(10,2,1) over the compared token count.
    // 1 equal 32-byte token => 1 + (4+18+3) + 12 = 38.

    // ----- happy path -----

    #[test]
    fn token_eq_single_equal_bills_38() {
        let t = Value::Tokens(vec![tok(0xAA, 100)]);
        let (c, eq) = cost_eq(&t, &t.clone());
        assert!(eq, "identical single-token colls are equal");
        assert_eq!(c, 38);
    }

    #[test]
    fn token_eq_empty_bills_11() {
        let t = Value::Tokens(vec![]);
        let (c, eq) = cost_eq(&t, &t.clone());
        assert!(eq, "empty token colls are equal");
        assert_eq!(c, 11); // 1 + EQ_Coll.compute(0)=10
    }

    // ----- error paths -----

    #[test]
    fn token_eq_length_mismatch_bills_only_match_type() {
        let l = Value::Tokens(vec![tok(0xAA, 100)]);
        let r = Value::Tokens(vec![]);
        let (c, eq) = cost_eq(&l, &r);
        assert!(!eq, "different lengths -> not equal");
        assert_eq!(c, cost_table::MATCH_TYPE);
    }

    // ----- short-circuit (Scala `equalColls` stops at first unequal token) -----

    /// A mismatch in the FIRST token compares only one token; a mismatch in the
    /// SECOND compares both. The prior full-length charge billed both regardless
    /// (65 for either) — this is the short-circuit overcharge the fix removes.
    #[test]
    fn token_eq_short_circuits_at_first_unequal_token() {
        let base = Value::Tokens(vec![tok(0xAA, 1), tok(0xBB, 2)]);
        // first token's amount differs -> id equal, amount compared, stop:
        // 1 + 25 + EQ_Coll(1)=12 = 38
        let first_diff = Value::Tokens(vec![tok(0xAA, 9), tok(0xBB, 2)]);
        // second token differs -> both compared: 1 + 25 + 25 + EQ_Coll(2)=14 = 65
        let second_diff = Value::Tokens(vec![tok(0xAA, 1), tok(0xBB, 9)]);
        let (c_first, e1) = cost_eq(&base, &first_diff);
        let (c_second, e2) = cost_eq(&base, &second_diff);
        assert!(!e1 && !e2);
        assert_eq!(c_first, 38, "first-token mismatch compares only 1 token");
        assert_eq!(c_second, 65, "second-token mismatch compares both tokens");
    }

    /// When a token id differs, Scala's tuple `&&` skips the amount comparison,
    /// so no `EQ_Prim` is billed for the amount: 1 + (EQ_Tuple 4 + id 18) + 12 = 35.
    #[test]
    fn token_eq_id_mismatch_skips_amount_cost() {
        let base = Value::Tokens(vec![tok(0xAA, 1)]);
        let id_diff = Value::Tokens(vec![tok(0xBB, 1)]);
        let (c, eq) = cost_eq(&base, &id_diff);
        assert!(!eq);
        assert_eq!(c, 35);
    }

    // ----- cross-carrier (CollGeneric tuple carrier vs Tokens) -----

    /// A token collection can reach equality as the `CollGeneric` tuple carrier
    /// on one side and `Tokens` on the other. Previously `eq_coll_fallback` did
    /// not materialize a right-hand `Tokens`, returning after only the outer
    /// MatchType (cost 1) — an UNDERCHARGE. It must now bill the full
    /// per-element cost, identical to the `Tokens == Tokens` path (38).
    #[test]
    fn token_eq_cross_carrier_charges_full_elements() {
        let tokens = Value::Tokens(vec![tok(0xAA, 100)]);
        let token_elem = SigmaType::STuple(vec![
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaType::SLong,
        ]);
        let as_generic = Value::CollGeneric(
            vec![Value::Tuple(vec![
                Value::CollBytes([0xAA; 32].to_vec()),
                Value::Long(100),
            ])],
            Box::new(token_elem),
        );
        // left = CollGeneric (-> eq_coll_fallback), right = Tokens.
        let (c, eq) = cost_eq(&as_generic, &tokens);
        assert!(eq, "same tokens via different carriers are equal");
        assert_eq!(c, 38);
    }
}
