//! Collection helpers: the `CollKind` element-kind tag and the
//! runtime-collection <-> `Vec<Value>` conversions/inference used across the
//! evaluator. Also hosts `strict_value_sigma_type`/`contains_sany`, which are
//! consumed only by `infer_collection`.

use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use super::*;
use crate::evaluator::types::*;

pub(crate) enum CollKind {
    Byte,
    Short,
    Int,
    Long,
    Bool,
    SigmaProp,
    Box,
    Header,
    Tuple,
    Token,
}

/// Decompose a collection Value into (element_kind, items).
pub(crate) fn collection_to_values(
    coll: Value,
    ctx: &ReductionContext,
) -> Result<(CollKind, Vec<Value>), EvalError> {
    match coll {
        // Coll[Byte] stays as Vec<u8> in storage; elements surface
        // as Value::Byte at the element boundary (typed carrier).
        Value::CollBytes(bytes) => Ok((
            CollKind::Byte,
            bytes.into_iter().map(|b| Value::Byte(b as i8)).collect(),
        )),
        Value::CollShort(shorts) => Ok((
            CollKind::Short,
            shorts.into_iter().map(Value::Short).collect(),
        )),
        Value::CollInt(ints) => Ok((CollKind::Int, ints.into_iter().map(Value::Int).collect())),
        Value::CollLong(longs) => {
            Ok((CollKind::Long, longs.into_iter().map(Value::Long).collect()))
        }
        Value::CollBool(bools) => {
            Ok((CollKind::Bool, bools.into_iter().map(Value::Bool).collect()))
        }
        Value::CollSigmaProp(props) => Ok((
            CollKind::SigmaProp,
            props.into_iter().map(Value::SigmaProp).collect(),
        )),
        Value::Tokens(tokens) => Ok((
            CollKind::Token,
            tokens
                .into_iter()
                .map(|(id, amt)| {
                    Value::Tuple(vec![Value::CollBytes(id.to_vec()), Value::Long(amt as i64)])
                })
                .collect(),
        )),
        // CollGeneric is the boxed-element collection carrier. A
        // real `Value::Tuple` (STuple) is NOT a collection and is
        // intentionally not accepted here — accepting it would let
        // `Coll.updated` etc. mutate tuples. The tagged `elem_type`
        // is discarded here; downstream callers that need it should
        // capture via `coll_elem_type` on the input value.
        Value::CollGeneric(items, _) => Ok((CollKind::Tuple, items)),
        Value::CollBox(items) => Ok((CollKind::Box, items)),
        Value::CollHeader(headers) => Ok((
            CollKind::Header,
            headers
                .into_iter()
                .map(|h| Value::Header(Box::new(h)))
                .collect(),
        )),
        Value::BoxCollection(src) => {
            let len = match src {
                BoxSource::Outputs => ctx.outputs.len(),
                BoxSource::Inputs => ctx.inputs.len(),
                BoxSource::DataInputs => ctx.data_inputs.len(),
            };
            Ok((
                CollKind::Box,
                (0..len)
                    .map(|i| Value::BoxRef {
                        source: src,
                        index: i,
                    })
                    .collect(),
            ))
        }
        _ => Err(EvalError::TypeError {
            expected: "collection for lambda operation",
            got: format!("{coll:?}"),
        }),
    }
}

/// Recover the static element `SigmaType` of a collection-shaped
/// `Value`. Used by callers of `values_to_collection` and
/// `Value::CollGeneric` constructors that need to preserve or derive
/// the element type from an input collection (Filter / Slice /
/// Append / Reverse / flatMap / zip element-shape).
/// Returns `None` for non-collection values.
pub(crate) fn coll_elem_type(v: &Value) -> Option<SigmaType> {
    match v {
        Value::CollBytes(_) => Some(SigmaType::SByte),
        Value::CollShort(_) => Some(SigmaType::SShort),
        Value::CollInt(_) => Some(SigmaType::SInt),
        Value::CollLong(_) => Some(SigmaType::SLong),
        Value::CollBool(_) => Some(SigmaType::SBoolean),
        Value::CollSigmaProp(_) => Some(SigmaType::SSigmaProp),
        Value::CollBox(_) | Value::BoxCollection(_) => Some(SigmaType::SBox),
        Value::CollHeader(_) => Some(SigmaType::SHeader),
        // Tokens are `Coll[(Coll[Byte], Long)]` in Scala.
        Value::Tokens(_) => Some(SigmaType::STuple(vec![
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaType::SLong,
        ])),
        Value::CollGeneric(_, elem_type) => Some((**elem_type).clone()),
        _ => None,
    }
}

/// Reassemble filtered items into the same collection type as the source.
/// Used by Filter (output elements are same type as input).
/// Fails if any element doesn't match the expected kind.
///
/// `elem_type` is required to construct the `CollGeneric` fallback —
/// callers usually derive it from the input collection via
/// `coll_elem_type`. Typed primitive kinds ignore the parameter.
pub(crate) fn values_to_collection(
    kind: CollKind,
    items: Vec<Value>,
    elem_type: SigmaType,
) -> Result<Value, EvalError> {
    match kind {
        CollKind::Int => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Int(n) => v.push(n),
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "Int in collection",
                            got: format!("{item:?}"),
                        })
                    }
                }
            }
            Ok(Value::CollInt(v))
        }
        CollKind::Long => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Long(n) => v.push(n),
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "Long in collection",
                            got: format!("{item:?}"),
                        })
                    }
                }
            }
            Ok(Value::CollLong(v))
        }
        CollKind::Bool => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Bool(b) => v.push(b),
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "Bool in collection",
                            got: format!("{item:?}"),
                        })
                    }
                }
            }
            Ok(Value::CollBool(v))
        }
        CollKind::SigmaProp => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::SigmaProp(sb) => v.push(sb),
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "SigmaProp in collection",
                            got: format!("{item:?}"),
                        })
                    }
                }
            }
            Ok(Value::CollSigmaProp(v))
        }
        CollKind::Byte => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Byte(n) => v.push(n as u8),
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "Byte in collection",
                            got: format!("{item:?}"),
                        })
                    }
                }
            }
            Ok(Value::CollBytes(v))
        }
        CollKind::Short => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Short(n) => v.push(n),
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "Short in collection",
                            got: format!("{item:?}"),
                        })
                    }
                }
            }
            Ok(Value::CollShort(v))
        }
        // Box: typed CollBox (preserves element type even when empty)
        CollKind::Box => Ok(Value::CollBox(items)),
        // Header: typed CollHeader
        CollKind::Header => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Header(h) => v.push(*h),
                    _ => {
                        return Err(EvalError::TypeError {
                            expected: "Header in collection",
                            got: format!("{item:?}"),
                        })
                    }
                }
            }
            Ok(Value::CollHeader(v))
        }
        // Token: reconstruct Value::Tokens from Tuple(CollBytes, Long) pairs.
        // Slice/Filter on Tokens decomposes into Tuple pairs via
        // collection_to_values; reconstruct back to preserve type
        // parity with SBox.tokens (Value::Tokens). Non-canonical
        // shapes fall back to `Value::CollGeneric` (the boxed-
        // element collection carrier) tagged with the Token element
        // type `(Coll[Byte], Long)`.
        CollKind::Token => {
            let token_elem_type = SigmaType::STuple(vec![
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaType::SLong,
            ]);
            let mut tokens = Vec::with_capacity(items.len());
            for item in &items {
                match item {
                    Value::Tuple(inner) if inner.len() == 2 => {
                        if let (Value::CollBytes(id), Value::Long(amt)) = (&inner[0], &inner[1]) {
                            if id.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(id);
                                tokens.push((arr, *amt as u64));
                                continue;
                            }
                        }
                        return Ok(Value::CollGeneric(items, Box::new(token_elem_type)));
                    }
                    _ => return Ok(Value::CollGeneric(items, Box::new(token_elem_type))),
                }
            }
            Ok(Value::Tokens(tokens))
        }
        // Fallback: boxed-element collection. The `elem_type` carried
        // here flows from the caller's static type knowledge (input
        // collection's elem type, IR-inferred type, etc.) so an
        // empty result preserves the original `Coll[T]` shape.
        _ => Ok(Value::CollGeneric(items, Box::new(elem_type))),
    }
}

/// Infer collection type from mapper output elements (used by MapCollection).
/// Unlike values_to_collection, this doesn't have a predetermined kind —
/// it infers from the first element. When empty, derives the output type from
/// the mapper body using structural type inference on the IR.
pub(crate) fn infer_collection(
    items: Vec<Value>,
    mapper_body: &Expr,
    param_bindings: &std::collections::HashMap<u32, SigmaType>,
    constants: &[(SigmaType, SigmaValue)],
) -> Result<Value, EvalError> {
    if items.is_empty() {
        let inferred = infer_expr_type(mapper_body, param_bindings, constants);
        let kind = inferred.as_ref().and_then(sigma_type_to_coll_kind);
        return match kind {
            Some(CollKind::Byte) => Ok(Value::CollBytes(vec![])),
            Some(CollKind::Short) => Ok(Value::CollShort(vec![])),
            Some(CollKind::Int) => Ok(Value::CollInt(vec![])),
            Some(CollKind::Long) => Ok(Value::CollLong(vec![])),
            Some(CollKind::Bool) => Ok(Value::CollBool(vec![])),
            Some(CollKind::SigmaProp) => Ok(Value::CollSigmaProp(vec![])),
            Some(CollKind::Box) => Ok(Value::CollBox(vec![])),
            Some(CollKind::Header) => Ok(Value::CollHeader(vec![])),
            // Empty boxed-element coll — tag with the inferred elem
            // type when available; fall back to `SAny` so serialize-
            // back paths still reject loudly rather than emit wrong
            // bytes.
            _ => Ok(Value::CollGeneric(
                vec![],
                Box::new(inferred.unwrap_or(SigmaType::SAny)),
            )),
        };
    }
    // Prefer the mapper-body's IR-inferred element type when it's
    // available. Falling back only to `value_to_sigma_type(&items[0])`
    // degrades for `[None, Some(x)]` (first item recovers as
    // `SOption(SAny)`) — IR inference recovers `SOption(T)` from the
    // mapper body and threads `T` through. If IR inference fails,
    // scan items for the first concrete recovery before defaulting
    // to `SAny`.
    let ir_elem_type = infer_expr_type(mapper_body, param_bindings, constants);
    let kind = match &items[0] {
        Value::Byte(_) => CollKind::Byte,
        Value::Short(_) => CollKind::Short,
        Value::Int(_) => CollKind::Int,
        Value::Long(_) => CollKind::Long,
        Value::Bool(_) => CollKind::Bool,
        Value::SigmaProp(_) => CollKind::SigmaProp,
        Value::SelfBox | Value::BoxRef { .. } => return Ok(Value::CollBox(items)),
        _ => {
            let elem_type = ir_elem_type
                .clone()
                .or_else(|| items.iter().find_map(strict_value_sigma_type))
                .unwrap_or(SigmaType::SAny);
            return Ok(Value::CollGeneric(items, Box::new(elem_type)));
        }
    };
    let elem_type = ir_elem_type
        .or_else(|| items.iter().find_map(strict_value_sigma_type))
        .unwrap_or(SigmaType::SAny);
    values_to_collection(kind, items, elem_type)
}

pub(crate) fn sigma_type_to_coll_kind(tpe: &SigmaType) -> Option<CollKind> {
    match tpe {
        SigmaType::SInt => Some(CollKind::Int),
        SigmaType::SLong => Some(CollKind::Long),
        SigmaType::SShort => Some(CollKind::Short),
        SigmaType::SBoolean => Some(CollKind::Bool),
        SigmaType::SByte => Some(CollKind::Byte),
        SigmaType::SSigmaProp => Some(CollKind::SigmaProp),
        SigmaType::SBox => Some(CollKind::Box),
        SigmaType::SHeader => Some(CollKind::Header),
        _ => None,
    }
}

/// Expand a BoxCollection carrier into a Vec of BoxRef values.
pub(crate) fn expand_box_collection(source: BoxSource, ctx: &ReductionContext<'_>) -> Vec<Value> {
    let collection = match source {
        BoxSource::Outputs => ctx.outputs,
        BoxSource::Inputs => ctx.inputs,
        BoxSource::DataInputs => ctx.data_inputs,
    };
    (0..collection.len())
        .map(|i| Value::BoxRef { source, index: i })
        .collect()
}

/// Unpack a collection Value into its individual elements (SubstConstants path).
/// Byte/Short/CollShort surface as typed carriers (no erasure to Int).
pub(crate) fn unpack_collection(val: Value) -> Result<Vec<Value>, EvalError> {
    match val {
        Value::CollSigmaProp(v) => Ok(v.into_iter().map(Value::SigmaProp).collect()),
        Value::CollBytes(v) => Ok(v.into_iter().map(|b| Value::Byte(b as i8)).collect()),
        Value::CollShort(v) => Ok(v.into_iter().map(Value::Short).collect()),
        Value::CollInt(v) => Ok(v.into_iter().map(Value::Int).collect()),
        Value::CollLong(v) => Ok(v.into_iter().map(Value::Long).collect()),
        Value::CollBool(v) => Ok(v.into_iter().map(Value::Bool).collect()),
        // SubstConstants takes a Coll[T] of replacement values; a
        // real STuple is not a collection, so accept only the
        // boxed-element coll carrier here.
        Value::CollGeneric(items, _) => Ok(items),
        // Native Coll[Header] carrier (e.g. CONTEXT.headers used as
        // substitution values). Yields Header elements so the
        // subst_constants header v3 gate + value_to_typed_sigma run.
        Value::CollHeader(v) => Ok(v.into_iter().map(|h| Value::Header(Box::new(h))).collect()),
        other => Err(EvalError::TypeError {
            expected: "collection for SubstConstants values",
            got: format!("{other:?}"),
        }),
    }
}
