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

/// Add EQ/NEQ dynamic cost based on value structure.
///
/// For BoxCollection values, resolves the collection length from context
/// and charges EQ_COA_Box = PerItemCost(15, 5, 1) matching Scala's
/// DataValueComparer collection dispatch. For derived Coll[Box] stored as
/// Tuple of BoxRefs, charges the same per-item cost instead of tuple cost.
pub(crate) fn add_eq_neq_cost(
    cost: &mut CostAccumulator,
    left: &Value,
    right: &Value,
    ctx: &ReductionContext<'_>,
) -> Result<(), EvalError> {
    // Scala short-circuits collection EQ when lengths differ: only charges
    // MatchType(1) without equalColls_Dispatch. We replicate this by
    // checking if both sides are collections of matching length.
    let colls_match_len = match (left, right) {
        (Value::CollBytes(a), Value::CollBytes(b)) => a.len() == b.len(),
        (Value::CollBytes(a), Value::CollInt(b)) | (Value::CollInt(b), Value::CollBytes(a)) => {
            a.len() == b.len()
        }
        (Value::CollInt(a), Value::CollInt(b)) => a.len() == b.len(),
        (Value::CollLong(a), Value::CollLong(b)) => a.len() == b.len(),
        (Value::CollBool(a), Value::CollBool(b)) => a.len() == b.len(),
        (Value::CollSigmaProp(a), Value::CollSigmaProp(b)) => a.len() == b.len(),
        (Value::CollBox(a), Value::CollBox(b)) => a.len() == b.len(),
        (Value::CollHeader(a), Value::CollHeader(b)) => a.len() == b.len(),
        (Value::Tokens(a), Value::Tokens(b)) => a.len() == b.len(),
        // Tokens ↔ CollGeneric bridge: Tokens carries (id, amt) pairs;
        // an evaluator path that decomposed via collection_to_values
        // expresses them as a `CollGeneric` of `Tuple(CollBytes, Long)`.
        (Value::Tokens(a), Value::CollGeneric(b, _))
        | (Value::CollGeneric(b, _), Value::Tokens(a)) => a.len() == b.len(),
        // CollGeneric ↔ CollGeneric — boxed-element coll length
        // short-circuit. Scala charges only `MatchType` and skips the
        // per-item recursion when lengths differ; without this arm
        // the per-item cost is still charged here, drifting from the
        // Scala-anchored cost boundary.
        (Value::CollGeneric(a, _), Value::CollGeneric(b, _)) => a.len() == b.len(),
        // Cross-carrier Coll[Box] length short-circuits. After the
        // carrier split, `Coll[Box]` can arrive as `CollBox`,
        // `BoxCollection`, or `CollGeneric` (when filter / flatMap
        // demoted it). Skipping these here meant the per-item
        // `EQ_COA_Box` charge fired even on length-mismatched
        // operands — Scala-anchored cost drift.
        (Value::CollBox(a), Value::CollGeneric(b, _))
        | (Value::CollGeneric(b, _), Value::CollBox(a)) => a.len() == b.len(),
        (Value::BoxCollection(src), Value::CollGeneric(b, _))
        | (Value::CollGeneric(b, _), Value::BoxCollection(src)) => {
            let len = match src {
                BoxSource::Outputs => ctx.outputs.len(),
                BoxSource::Inputs => ctx.inputs.len(),
                BoxSource::DataInputs => ctx.data_inputs.len(),
            };
            len == b.len()
        }
        (Value::BoxCollection(a), Value::BoxCollection(b)) => {
            let len = |s: &BoxSource| match s {
                BoxSource::Outputs => ctx.outputs.len(),
                BoxSource::Inputs => ctx.inputs.len(),
                BoxSource::DataInputs => ctx.data_inputs.len(),
            };
            len(a) == len(b)
        }
        _ => true, // non-collection types: no short-circuit
    };
    match left {
        Value::BoxCollection(source) => {
            let n = match source {
                BoxSource::Outputs => ctx.outputs.len(),
                BoxSource::Inputs => ctx.inputs.len(),
                BoxSource::DataInputs => ctx.data_inputs.len(),
            };
            add_coll_box_eq_cost(cost, n as u32, colls_match_len)
        }
        Value::CollBox(elems) => add_coll_box_eq_cost(cost, elems.len() as u32, colls_match_len),
        // A `CollGeneric` whose elements are all box-shaped is a
        // Coll[Box] arriving via the boxed-element fallback carrier;
        // cost it as `Coll[Box] EQ`, not as a tuple compare. A real
        // `Value::Tuple` is fixed-arity STuple and falls through to
        // the per-type branch below.
        Value::CollGeneric(elems, _)
            if !elems.is_empty()
                && elems
                    .iter()
                    .all(|e| matches!(e, Value::SelfBox | Value::BoxRef { .. })) =>
        {
            add_coll_box_eq_cost(cost, elems.len() as u32, colls_match_len)
        }
        _ => {
            #[cfg(feature = "cost-trace")]
            let before = cost.total().value();
            cost_table::add_eq_cost(cost, left, colls_match_len)?;
            #[cfg(feature = "cost-trace")]
            {
                let label = match left {
                    Value::CollBytes(_) => "EQ:CollBytes",
                    Value::CollInt(_) => "EQ:CollInt",
                    Value::CollLong(_) => "EQ:CollLong",
                    Value::CollBool(_) => "EQ:CollBool",
                    Value::CollSigmaProp(_) => "EQ:CollSigmaProp",
                    Value::Tokens(_) => "EQ:Tokens",
                    Value::Tuple(_) => "EQ:Tuple",
                    Value::CollGeneric(_, _) => "EQ:CollGeneric",
                    Value::SigmaProp(_) => "EQ:SigmaProp",
                    _ => "EQ:Prim",
                };
                crate::cost_trace::record(
                    label,
                    cost.total().value() - before,
                    cost.total().value(),
                );
            }
            Ok(())
        }
    }
}

/// Charge EQ_COA_Box = PerItemCost(base=15, perChunk=5, chunk=1) for Coll[Box] equality.
/// Scala short-circuits when collection lengths differ — only MatchType(1) is charged.
pub(crate) fn add_coll_box_eq_cost(
    cost: &mut CostAccumulator,
    n: u32,
    colls_match_len: bool,
) -> Result<(), EvalError> {
    // MatchType for collection dispatch in equalDataValues (1 only, no inner dispatch)
    cost.add(JitCost::from_jit(1))?;
    #[cfg(feature = "cost-trace")]
    crate::cost_trace::record("EQ:CollBox:MatchType", 1, cost.total().value());
    if colls_match_len {
        let delta = CostKind::PerItem {
            base: JitCost::from_jit(15),
            per_chunk: JitCost::from_jit(5),
            chunk_size: 1,
        }
        .compute(n)?;
        cost.add(delta)?;
        #[cfg(feature = "cost-trace")]
        crate::cost_trace::record(
            format!("EQ:CollBox:PerItem(n={})", n),
            delta.value(),
            cost.total().value(),
        );
    }
    Ok(())
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

/// Construct an AVL proof verifier from AvlTreeData and proof bytes.
pub(crate) fn make_avl_verifier(
    avl: &ergo_ser::sigma_value::AvlTreeData,
    proof: &[u8],
) -> Result<crate::avl::AvlVerifier, EvalError> {
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
