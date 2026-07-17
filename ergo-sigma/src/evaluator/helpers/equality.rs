//! Value comparison: the comparability gate (`require_comparable`/
//! `check_comparable`), deep structural equality (`values_equal`/`seq_equal`),
//! and `resolve_box` (needed by `values_equal`).

use super::*;
use crate::evaluator::types::*;

/// Verify a value contains only concrete comparable types, recursively.
/// Carrier types (SelfBox, BoxRef, BoxCollection, Opt) do not have
/// meaningful Ergo equality — comparing them via Rust PartialEq would
/// produce results based on evaluator representation, not semantic identity.
pub(crate) fn require_comparable(l: &Value, r: &Value) -> Result<(), EvalError> {
    check_comparable(l)?;
    check_comparable(r)
}

pub(crate) fn check_comparable(v: &Value) -> Result<(), EvalError> {
    match v {
        Value::Unit
        | Value::Byte(_)
        | Value::Short(_)
        | Value::Int(_)
        | Value::Long(_)
        | Value::BigInt(_)
        | Value::UnsignedBigInt(_)
        | Value::Bool(_)
        | Value::Str(_)
        | Value::CollBytes(_)
        | Value::CollShort(_)
        | Value::CollInt(_)
        | Value::CollLong(_)
        | Value::CollBool(_)
        | Value::GroupElement(_)
        | Value::SigmaProp(_) => Ok(()),
        Value::Tokens(items) => {
            // Token pairs are ([u8;32], u64) — always concrete
            let _ = items;
            Ok(())
        }
        Value::Tuple(items) | Value::CollGeneric(items, _) => {
            for item in items {
                check_comparable(item)?;
            }
            Ok(())
        }
        Value::CollSigmaProp(_) => Ok(()),
        Value::CollBox(_) => Ok(()),
        Value::Opt(Some(inner)) => check_comparable(inner),
        Value::Opt(None) => Ok(()),
        // Box, PreHeader, and BoxCollection are comparable in Scala consensus
        // (DataValueComparer cases 7, 8, 9, 10 and Coll[Box]).
        Value::SelfBox
        | Value::BoxRef { .. }
        | Value::InlineBox(_)
        | Value::BoxCollection(_)
        | Value::PreHeader
        | Value::AvlTree(_)
        | Value::Header(_)
        | Value::CollHeader(_) => Ok(()),
        // Global is a singleton — structural identity is fine
        Value::Global => Ok(()),
        // Functions are never comparable in Ergo
        Value::Func { .. } => Err(EvalError::TypeError {
            expected: "comparable value (not function)",
            got: format!("{v:?}"),
        }),
    }
}

/// Compare two Values for equality, recursively resolving box references
/// through the context at every level.
///
/// Matches Scala's DataValueComparer.equalDataValues which recurses through
/// tuples, options, and collections, comparing Box values (not carrier
/// representations) at every depth.
pub(crate) fn values_equal(
    l: &Value,
    r: &Value,
    ctx: &ReductionContext<'_>,
) -> Result<bool, EvalError> {
    match (l, r) {
        // Box values — resolve and compare by box ID
        (
            Value::SelfBox | Value::BoxRef { .. } | Value::InlineBox(_),
            Value::SelfBox | Value::BoxRef { .. } | Value::InlineBox(_),
        ) => {
            let lb = resolve_box(l, ctx)?;
            let rb = resolve_box(r, ctx)?;
            Ok(lb.id == rb.id)
        }
        // PreHeader is a singleton per block
        (Value::PreHeader, Value::PreHeader) => Ok(true),
        // BoxCollection vs BoxCollection — expand and compare element-wise
        (Value::BoxCollection(a), Value::BoxCollection(b)) => {
            if a == b {
                return Ok(true); // same source, definitely equal
            }
            // Different sources — expand both and compare element-wise
            let la = expand_box_collection(*a, ctx);
            let lb = expand_box_collection(*b, ctx);
            seq_equal(&la, &lb, ctx)
        }
        // CollBox vs CollBox — element-wise
        (Value::CollBox(a), Value::CollBox(b)) => seq_equal(a, b, ctx),
        // Cross-representation Coll[Box]: BoxCollection ↔ CollBox ↔
        // CollGeneric. CollGeneric is the boxed-element collection
        // carrier (post Coll[Tuple] disambiguation); a real
        // `Value::Tuple` here would be a type error, not a Coll[Box]
        // alias.
        (Value::BoxCollection(src), Value::CollBox(items)) => {
            let expanded = expand_box_collection(*src, ctx);
            seq_equal(&expanded, items, ctx)
        }
        (Value::CollBox(items), Value::BoxCollection(src)) => {
            let expanded = expand_box_collection(*src, ctx);
            seq_equal(items, &expanded, ctx)
        }
        (Value::BoxCollection(src), Value::CollGeneric(items, _)) => {
            let expanded = expand_box_collection(*src, ctx);
            seq_equal(&expanded, items, ctx)
        }
        (Value::CollGeneric(items, _), Value::BoxCollection(src)) => {
            let expanded = expand_box_collection(*src, ctx);
            seq_equal(items, &expanded, ctx)
        }
        (Value::CollBox(a), Value::CollGeneric(b, _)) => seq_equal(a, b, ctx),
        (Value::CollGeneric(a, _), Value::CollBox(b)) => seq_equal(a, b, ctx),
        // CollGeneric — boxed-element coll, recurse element-wise.
        // Element-type tag is intentionally not compared (semantic
        // equality is element-wise).
        (Value::CollGeneric(a, _), Value::CollGeneric(b, _)) => seq_equal(a, b, ctx),
        // Tuple — recurse element-wise (may contain box refs at any depth)
        (Value::Tuple(a), Value::Tuple(b)) => seq_equal(a, b, ctx),
        // Option — recurse into inner value
        (Value::Opt(a), Value::Opt(b)) => match (a.as_deref(), b.as_deref()) {
            (None, None) => Ok(true),
            (Some(ai), Some(bi)) => values_equal(ai, bi, ctx),
            _ => Ok(false),
        },
        // NOTE: SigmaProp / Coll[SigmaProp] are handled by the catch-all
        // `l == r` (structural PartialEq) — NOT the throwing equalSigmaBoolean.
        // `values_equal` is the plain-equality authority used by
        // `SColl.startsWith`/`endsWith`, whose Scala impls (`xs.startsWith(ys)`)
        // use normal element `==` and return `false` on a constructor mismatch.
        // Only the DataValueComparer paths (`==`/`!=`/`indexOf`, via
        // `eq_with_cost`) get the throwing conjecture-mismatch semantics.
        // Cross-type CollBytes ↔ CollInt is intentionally not bridged here —
        // see the PartialEq impl above for the type-strictness rationale.
        // Primitive types and collections of primitives — Value::PartialEq is correct
        // (no box references can hide inside CollBytes, CollInt, CollLong, CollBool,
        // CollSigmaProp, Tokens, Int, Long, BigInt, Bool, GroupElement, SigmaProp)
        _ => Ok(l == r),
    }
}

/// Compare two sequences element-wise using values_equal.
pub(crate) fn seq_equal(
    a: &[Value],
    b: &[Value],
    ctx: &ReductionContext<'_>,
) -> Result<bool, EvalError> {
    if a.len() != b.len() {
        return Ok(false);
    }
    for (ai, bi) in a.iter().zip(b.iter()) {
        if !values_equal(ai, bi, ctx)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Resolve a Value to a reference to an EvalBox.
pub(crate) fn resolve_box<'a>(
    val: &'a Value,
    ctx: &'a ReductionContext<'_>,
) -> Result<&'a EvalBox, EvalError> {
    match val {
        Value::SelfBox => ctx.self_box.ok_or(EvalError::TypeError {
            expected: "SELF box in context",
            got: "no self_box".into(),
        }),
        Value::BoxRef { source, index } => {
            let collection = match source {
                BoxSource::Outputs => ctx.outputs,
                BoxSource::Inputs => ctx.inputs,
                BoxSource::DataInputs => ctx.data_inputs,
            };
            collection.get(*index).ok_or(EvalError::TypeError {
                expected: "valid box index",
                got: format!("{source:?}[{index}]"),
            })
        }
        Value::InlineBox(b) => Ok(b.as_ref()),
        _ => Err(EvalError::TypeError {
            expected: "Box",
            got: format!("{val:?}"),
        }),
    }
}
