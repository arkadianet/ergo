use ergo_primitives::group_element::GroupElement;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use super::types::*;

/// Truncated `Debug` projection used by trace entries. Keeps the first
/// 150 bytes of the formatted value so trace lines stay grep-friendly.
pub(crate) fn trace_val(v: &Value) -> String {
    let s = format!("{v:?}");
    if s.len() > 150 {
        format!("{}...", &s[..150])
    } else {
        s
    }
}

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

/// One-directional subtype check on `SigmaType` for the
/// serialize-back / `Coll.updated` type gate.
///
/// `SAny` is accepted ONLY on the `observed` side — it is the marker
/// the recovery path (`value_to_sigma_type`) emits when the runtime
/// value can't surface its precise inner type (the canonical case is
/// `Value::Opt(None)` → `SOption(SAny)`). Carriers must never declare
/// `SAny` in their `elem_type` tag; tightening the gate this way
/// rejects malformed carriers that lost type information at
/// construction time.
///
/// Recurses through `SOption`, `SColl`, and `STuple` so a nested
/// `None` inside a tuple inside a Coll still threads the wildcard
/// through.
pub(crate) fn sigma_type_compatible(declared: &SigmaType, observed: &SigmaType) -> bool {
    match (declared, observed) {
        (_, SigmaType::SAny) => true,
        (SigmaType::SOption(a), SigmaType::SOption(b)) => sigma_type_compatible(a, b),
        (SigmaType::SColl(a), SigmaType::SColl(b)) => sigma_type_compatible(a, b),
        (SigmaType::STuple(a), SigmaType::STuple(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| sigma_type_compatible(x, y))
        }
        (x, y) => x == y,
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

/// `value_to_sigma_type` variant that never returns `SAny`-degraded
/// types — used when scanning a collection for a concrete elem-type
/// witness. Returns `None` for `Value::Opt(None)` so callers skip
/// past it to the next item rather than tagging the carrier with
/// `SOption(SAny)`.
fn strict_value_sigma_type(v: &Value) -> Option<SigmaType> {
    let t = value_to_sigma_type(v)?;
    if contains_sany(&t) {
        None
    } else {
        Some(t)
    }
}

fn contains_sany(t: &SigmaType) -> bool {
    match t {
        SigmaType::SAny => true,
        SigmaType::SOption(inner) | SigmaType::SColl(inner) => contains_sany(inner),
        SigmaType::STuple(elems) => elems.iter().any(contains_sany),
        _ => false,
    }
}

/// Derive the result SigmaType of an expression given a type environment.
///
/// This is lightweight structural type inference — not a full type checker,
/// but sound for the expressions it handles. Walks the IR recursively using
/// actual type rules (not opcode heuristics). Returns None when it can't
/// determine the type, which causes empty map results to fall back to
/// untyped Tuple.
pub(crate) fn infer_expr_type(
    expr: &Expr,
    bindings: &std::collections::HashMap<u32, SigmaType>,
    constants: &[(SigmaType, SigmaValue)],
) -> Option<SigmaType> {
    match expr {
        Expr::Const { tpe, .. } => Some(tpe.clone()),
        Expr::Op(node) => infer_op_type(node, bindings, constants),
    }
}

pub(crate) fn infer_op_type(
    node: &IrNode,
    bindings: &std::collections::HashMap<u32, SigmaType>,
    constants: &[(SigmaType, SigmaValue)],
) -> Option<SigmaType> {
    match (node.opcode, &node.payload) {
        // Variable lookup — type from bindings
        (0x72, Payload::ValUse { id }) => bindings.get(id).cloned(),
        // Constant placeholder — type from constants array
        (0x73, Payload::ConstPlaceholder { index }) => {
            constants.get(*index as usize).map(|(t, _)| t.clone())
        }
        // BlockValue — type of result expression (with ValDef bindings)
        (0xD8, Payload::BlockValue { items, result }) => {
            let mut inner_bindings = bindings.clone();
            for item in items {
                if let Expr::Op(def) = item {
                    if let (0xD6, Payload::ValDef { id, rhs, .. }) = (def.opcode, &def.payload) {
                        if let Some(t) = infer_expr_type(rhs, &inner_bindings, constants) {
                            inner_bindings.insert(*id, t);
                        }
                    }
                }
            }
            infer_expr_type(result, &inner_bindings, constants)
        }
        // If — type of then branch (both branches must have same type)
        (0x95, Payload::Three(_, then_br, _)) => infer_expr_type(then_br, bindings, constants),
        // Comparisons → Bool
        (0x8F..=0x94, _) => Some(SigmaType::SBoolean),
        // Boolean ops → Bool
        (0x96 | 0x97 | 0xEC | 0xED, _) => Some(SigmaType::SBoolean),
        (0xE6, _) => Some(SigmaType::SBoolean), // OptionIsDefined
        // Box extractors
        (0xC1, _) => Some(SigmaType::SLong), // ExtractAmount
        (0xC2, _) => Some(SigmaType::SColl(Box::new(SigmaType::SByte))), // ExtractScriptBytes
        (0xC3, _) => Some(SigmaType::SColl(Box::new(SigmaType::SByte))), // ExtractBytes
        (0xC4, _) => Some(SigmaType::SColl(Box::new(SigmaType::SByte))), // ExtractBytesNoRef
        (0xC5, _) => Some(SigmaType::SColl(Box::new(SigmaType::SByte))), // ExtractId
        (0xC6, Payload::ExtractRegisterAs { tpe, .. }) => {
            Some(SigmaType::SOption(Box::new(tpe.clone())))
        }
        (0xC7, _) => Some(SigmaType::STuple(vec![
            SigmaType::SInt,
            SigmaType::SColl(Box::new(SigmaType::SByte)),
        ])), // CreationInfo
        // SizeOf → Int
        (0xB1, _) => Some(SigmaType::SInt),
        // Context/box
        (0xA3, _) => Some(SigmaType::SInt), // Height
        (0xA7, _) => Some(SigmaType::SBox), // Self
        (0xA4 | 0xA5, _) => Some(SigmaType::SColl(Box::new(SigmaType::SBox))), // Inputs, Outputs
        // Arithmetic — type of operand (recurse on first arg)
        (0x9A | 0x99 | 0x9C | 0x9D | 0x9E | 0xA1 | 0xA2, Payload::Two(left, _)) => {
            infer_expr_type(left, bindings, constants)
        }
        // Negation — type of operand
        (0xF0, Payload::One(inner)) => infer_expr_type(inner, bindings, constants),
        // Sigma constructors
        (0xD1 | 0xCD | 0xCE, _) => Some(SigmaType::SSigmaProp),
        (0xEA | 0xEB, _) => Some(SigmaType::SSigmaProp), // SigmaAnd, SigmaOr
        // SelectField — can't determine without tuple type info
        // OptionGet — unwrap the option type
        (0xE4, Payload::One(inner)) => match infer_expr_type(inner, bindings, constants) {
            Some(SigmaType::SOption(t)) => Some(*t),
            _ => None,
        },
        // Downcast / Upcast — target type is on the node payload directly.
        (0x7D, Payload::NumericCast { tpe, .. }) => Some(tpe.clone()),
        (0x7E, Payload::NumericCast { tpe, .. }) => Some(tpe.clone()),
        // PropertyCall / MethodCall — limited table for return types that affect
        // empty-collection inference (e.g. headers.map(_.version) on empty coll).
        // This is NOT a complete method registry; only the entries that feed
        // back-to-back map-over-empty-coll sites with Byte/Short outputs.
        // Broader static-method-type inference is tracked as follow-up.
        (
            0xDB | 0xDC,
            Payload::MethodCall {
                type_id, method_id, ..
            },
        ) => {
            match (*type_id, *method_id) {
                // SHeader.version (type_id=104, method 2) → Byte
                (104, 2) => Some(SigmaType::SByte),
                // SPreHeader.version (type_id=105, method 1) → Byte.
                // Fixed from (105, 2) which is parentId (Coll[Byte]) — the
                // evaluator dispatch at lines 1396-1399 and Scala
                // methods.scala:1841 both agree version is method 1.
                (105, 1) => Some(SigmaType::SByte),
                // SAvlTree.enabledOperations (type_id=100, method 2) → Byte
                (100, 2) => Some(SigmaType::SByte),
                // SAvlTree.isInsertAllowed/isUpdateAllowed/isRemoveAllowed
                // (type_id=100, methods 5/6/7) → Boolean. Needed so an empty
                // `map` whose body is a flag accessor infers Coll[Boolean]
                // rather than degrading to CollGeneric(SAny). Cross-check:
                // eval_no_arg_method returns Value::Bool for the same ids.
                (100, 5) | (100, 6) | (100, 7) => Some(SigmaType::SBoolean),
                // SHeader.height (104, 9) → Int
                (104, 9) => Some(SigmaType::SInt),
                // SHeader.timestamp (104, 7) → Long
                (104, 7) => Some(SigmaType::SLong),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Derive a SigmaType from a runtime Value (for type environment construction).
pub(crate) fn value_to_sigma_type(val: &Value) -> Option<SigmaType> {
    match val {
        Value::Unit => Some(SigmaType::SUnit),
        Value::Byte(_) => Some(SigmaType::SByte),
        Value::Short(_) => Some(SigmaType::SShort),
        Value::Int(_) => Some(SigmaType::SInt),
        Value::Long(_) => Some(SigmaType::SLong),
        Value::BigInt(_) => Some(SigmaType::SBigInt),
        Value::UnsignedBigInt(_) => Some(SigmaType::SUnsignedBigInt),
        Value::Bool(_) => Some(SigmaType::SBoolean),
        Value::Str(_) => Some(SigmaType::SString),
        Value::GroupElement(_) => Some(SigmaType::SGroupElement),
        Value::SigmaProp(_) => Some(SigmaType::SSigmaProp),
        Value::CollBytes(_) => Some(SigmaType::SColl(Box::new(SigmaType::SByte))),
        Value::CollInt(_) => Some(SigmaType::SColl(Box::new(SigmaType::SInt))),
        Value::CollLong(_) => Some(SigmaType::SColl(Box::new(SigmaType::SLong))),
        Value::CollShort(_) => Some(SigmaType::SColl(Box::new(SigmaType::SShort))),
        Value::CollBool(_) => Some(SigmaType::SColl(Box::new(SigmaType::SBoolean))),
        Value::CollSigmaProp(_) => Some(SigmaType::SColl(Box::new(SigmaType::SSigmaProp))),
        Value::CollBox(_) => Some(SigmaType::SColl(Box::new(SigmaType::SBox))),
        Value::SelfBox | Value::BoxRef { .. } | Value::InlineBox(_) => Some(SigmaType::SBox),
        Value::BoxCollection(_) => Some(SigmaType::SColl(Box::new(SigmaType::SBox))),
        Value::PreHeader => Some(SigmaType::SPreHeader),
        Value::Header(_) => Some(SigmaType::SHeader),
        Value::CollHeader(_) => Some(SigmaType::SColl(Box::new(SigmaType::SHeader))),
        Value::AvlTree(_) => Some(SigmaType::SAvlTree),
        Value::Global | Value::Func { .. } => None,
        // Tokens are `Coll[(Coll[Byte], Long)]`.
        Value::Tokens(_) => Some(SigmaType::SColl(Box::new(SigmaType::STuple(vec![
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaType::SLong,
        ])))),
        // Option: recurse on inner when present; `None` has no
        // recoverable inner type, so surface `SOption(SAny)` as the
        // best available approximation.
        Value::Opt(Some(inner)) => Some(SigmaType::SOption(Box::new(
            value_to_sigma_type(inner).unwrap_or(SigmaType::SAny),
        ))),
        Value::Opt(None) => Some(SigmaType::SOption(Box::new(SigmaType::SAny))),
        // Real STuple: heterogeneous element types — recurse each.
        Value::Tuple(items) => Some(SigmaType::STuple(
            items
                .iter()
                .map(|v| value_to_sigma_type(v).unwrap_or(SigmaType::SAny))
                .collect(),
        )),
        // Boxed-element coll carrier already carries its T.
        Value::CollGeneric(_, elem_type) => Some(SigmaType::SColl(Box::new((**elem_type).clone()))),
    }
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

/// Convert a runtime Value to (SigmaType, SigmaValue) for serialization.
pub(crate) fn value_to_typed_sigma(val: &Value) -> Result<(SigmaType, SigmaValue), EvalError> {
    use ergo_ser::sigma_value::CollValue;
    match val {
        Value::Bool(b) => Ok((SigmaType::SBoolean, SigmaValue::Boolean(*b))),
        Value::Int(n) => Ok((SigmaType::SInt, SigmaValue::Int(*n))),
        Value::Long(n) => Ok((SigmaType::SLong, SigmaValue::Long(*n))),
        Value::BigInt(n) => Ok((SigmaType::SBigInt, SigmaValue::BigInt(n.clone()))),
        // SigmaValue carries unsigned bigints in the same BigInt
        // variant as signed; the SigmaType is what distinguishes them
        // on the wire. ergo-ser's write_unsigned_bigint_value
        // (sigma_value.rs) refuses negative input, so the SigmaType
        // tag here is load-bearing — it routes to the unsigned
        // writer that emits canonical magnitude bytes without a sign
        // byte. Without this arm, any v6 method that produces an
        // UnsignedBigInt (e.g. `SBigInt.toUnsigned`, `SUnsignedBigInt.
        // plusMod`) would fall through to the catch-all and break
        // `SGlobal.serialize` for scripts that compose v6 methods.
        Value::UnsignedBigInt(n) => Ok((SigmaType::SUnsignedBigInt, SigmaValue::BigInt(n.clone()))),
        Value::GroupElement(ge) => Ok((
            SigmaType::SGroupElement,
            SigmaValue::GroupElement(GroupElement::from_bytes(*ge)),
        )),
        Value::SigmaProp(sb) => Ok((SigmaType::SSigmaProp, SigmaValue::SigmaProp(sb.clone()))),
        Value::Str(s) => Ok((SigmaType::SString, SigmaValue::Str(s.clone()))),
        // Unit, Byte, Short surface as their own typed carriers
        // (no erasure to Int) on the wire boundary.
        Value::Unit => Ok((SigmaType::SUnit, SigmaValue::Unit)),
        Value::Byte(n) => Ok((SigmaType::SByte, SigmaValue::Byte(*n))),
        Value::Short(n) => Ok((SigmaType::SShort, SigmaValue::Short(*n))),
        Value::CollBytes(b) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes(b.clone())),
        )),
        // Coll[Short] — generic CollValue::Values: ergo-ser only
        // special-cases Coll[Boolean] and Coll[Byte], so there is no
        // packed byte encoding for Short.
        Value::CollShort(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SShort)),
            SigmaValue::Coll(CollValue::Values(
                v.iter().map(|n| SigmaValue::Short(*n)).collect(),
            )),
        )),
        Value::CollBool(b) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            SigmaValue::Coll(CollValue::BoolBits(b.clone())),
        )),
        Value::CollInt(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SInt)),
            SigmaValue::Coll(CollValue::Values(
                v.iter().map(|n| SigmaValue::Int(*n)).collect(),
            )),
        )),
        Value::CollLong(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SLong)),
            SigmaValue::Coll(CollValue::Values(
                v.iter().map(|n| SigmaValue::Long(*n)).collect(),
            )),
        )),
        Value::CollSigmaProp(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
            SigmaValue::Coll(CollValue::Values(
                v.iter()
                    .map(|sb| SigmaValue::SigmaProp(sb.clone()))
                    .collect(),
            )),
        )),
        // `Option[T]` — inverse of the `SOption(_)` arm of
        // `sigma_to_value`. Some(inner) recurses on `inner`;
        // None surfaces with `SOption(SAny)` and the caller's
        // type-compatibility check (`sigma_type_compatible`) bridges
        // the wildcard back to the concrete `T` when needed.
        Value::Opt(Some(inner)) => {
            let (inner_ty, inner_val) = value_to_typed_sigma(inner)?;
            Ok((
                SigmaType::SOption(Box::new(inner_ty)),
                SigmaValue::Opt(Some(Box::new(inner_val))),
            ))
        }
        Value::Opt(None) => Ok((
            SigmaType::SOption(Box::new(SigmaType::SAny)),
            SigmaValue::Opt(None),
        )),
        // Real `STuple` — fixed-arity heterogeneous tuple. Inverse
        // of the `(SigmaType::STuple, SigmaValue::Tuple)` arm of
        // `sigma_to_value`. Each element is serialized via the same
        // recursion, so byte-parity to Scala follows from the parse
        // path being Scala-anchored.
        Value::Tuple(items) => {
            let mut types: Vec<SigmaType> = Vec::with_capacity(items.len());
            let mut vals: Vec<SigmaValue> = Vec::with_capacity(items.len());
            for item in items {
                let (t, v) = value_to_typed_sigma(item)?;
                types.push(t);
                vals.push(v);
            }
            Ok((SigmaType::STuple(types), SigmaValue::Tuple(vals)))
        }
        // Boxed-element `Coll[X]` — inverse of `sigma_to_value`'s
        // `SColl(non-primitive)` fallback that emits `CollGeneric`.
        // The carrier's `elem_type` is the static `SigmaType` the IR
        // pinned at script-load (or that the producer operation
        // guarantees), so empty `Coll[T]` survives serialize-back
        // for any T — no element-probe needed.
        //
        // For non-empty collections we still cross-check each
        // element's recovered `SigmaType` against `elem_type`; a
        // mismatch surfaces `TypeError` rather than emitting bytes
        // a Scala decoder would reject.
        Value::CollGeneric(items, elem_type) => {
            let mut sigma_vals: Vec<SigmaValue> = Vec::with_capacity(items.len());
            for item in items {
                let (t, v) = value_to_typed_sigma(item)?;
                // `sigma_type_compatible` bridges the `SAny`
                // wildcard `Value::Opt(None)` surfaces back to the
                // carrier's concrete `T`, so a mixed
                // `[Some(_), None]` collection still serializes
                // under the right `SOption(T)` tag.
                if !sigma_type_compatible(elem_type, &t) {
                    return Err(EvalError::TypeError {
                        expected: "element matches CollGeneric elem_type",
                        got: format!("declared {elem_type:?}, found {t:?}"),
                    });
                }
                sigma_vals.push(v);
            }
            Ok((
                SigmaType::SColl(Box::new((**elem_type).clone())),
                SigmaValue::Coll(CollValue::Values(sigma_vals)),
            ))
        }
        // AvlTree: inverse of sigma_to_value's SAvlTree arm. The carrier
        // already holds the wire-shaped `AvlTreeData`, so serialize-back is a
        // direct hand-off to `write_avl_tree` (DataSerializer SAvlTree case).
        // Scala writes keyLength / valueLengthOpt with `putUInt`, which throws
        // on a negative value. `read_avl_tree` deliberately preserves a length
        // above i32::MAX as a wrapped-negative i32 ("succeeds with invalid
        // AvlTreeData"); serializing such a tree must error rather than cast to
        // u32 and emit bytes the reference would reject.
        Value::AvlTree(avl) => {
            if avl.key_length < 0 || avl.value_length_opt.is_some_and(|v| v < 0) {
                return Err(EvalError::TypeError {
                    expected: "non-negative AvlTree keyLength/valueLengthOpt for serialize",
                    got: format!(
                        "keyLength={}, valueLengthOpt={:?}",
                        avl.key_length, avl.value_length_opt
                    ),
                });
            }
            Ok((SigmaType::SAvlTree, SigmaValue::AvlTree(avl.clone())))
        }
        // Header: DataSerializer routes SHeader to ErgoHeader.sigmaSerializer
        // (gated on isV3OrLaterErgoTreeVersion — already enforced upstream by
        // the v6 method gate on SGlobal.serialize). `to_header` rebuilds the
        // wire `Header` from the eval carrier; `write_header` emits the bytes
        // and `serialize_put_cost(SHeader)` charges the matching put costs.
        Value::Header(h) => Ok((
            SigmaType::SHeader,
            SigmaValue::Header(Box::new(h.to_header())),
        )),
        // Native `Coll[Header]` carrier (e.g. CONTEXT.headers) — the standard
        // runtime source of header collections. Convert each element to the
        // wire `Header` so `serialize` / `SubstConstants` can consume it (a
        // bare `CollGeneric` only covers hand-built header colls). The v3 gate
        // is value-based via `contains_header`, so a non-empty Coll[Header] is
        // rejected on a pre-v3 tree while an empty one is accepted.
        Value::CollHeader(headers) => {
            let vals = headers
                .iter()
                .map(|h| SigmaValue::Header(Box::new(h.to_header())))
                .collect();
            Ok((
                SigmaType::SColl(Box::new(SigmaType::SHeader)),
                SigmaValue::Coll(CollValue::Values(vals)),
            ))
        }
        // SBox: the InlineBox carrier holds the verbatim serialized box bytes
        // (`raw_bytes` == Scala serialize(box), byte-identical — the parser
        // preserves the tree and register bytes verbatim). DataSerializer
        // routes SBox to `ErgoBox.sigmaSerializer`; hand the cached bytes to
        // `write_value(SBox, OpaqueBoxBytes)` (-> put_bytes), and
        // `serialize_put_cost(SBox)` re-parses them for the put-cost sum.
        // SelfBox / BoxRef would need context resolution to a concrete box; no
        // SANTA vector exercises a top-level serialize(SELF)/serialize(INPUTS),
        // so they stay in the catch-all below.
        Value::InlineBox(eb) => Ok((
            SigmaType::SBox,
            SigmaValue::OpaqueBoxBytes(eb.raw_bytes.clone()),
        )),
        // Catch-all rejects the remaining non-serializable runtime carriers
        // (BoxCollection / SelfBox / BoxRef / Func / Global / Opt / Tokens /
        // PreHeader / CollBox). These either lack a public SigmaValue
        // counterpart or have no Scala-anchored bytes for the
        // SubstConstants/SGlobal.serialize boundary.
        other => Err(EvalError::TypeError {
            expected: "serializable value for SubstConstants",
            got: format!("{other:?}"),
        }),
    }
}

/// Count total nodes in a SigmaBoolean tree (for SigmaPropBytes PerItem cost).
pub(crate) fn count_sigma_nodes(sb: &SigmaBoolean) -> usize {
    match sb {
        SigmaBoolean::TrivialProp(_) | SigmaBoolean::ProveDlog(_) => 1,
        // Scala `ProveDHTuple.size = 4` ("one node for each EcPoint",
        // SigmaBoolean.scala). SigmaPropBytes' PerItemCost(35,6,1) is charged
        // over `SigmaBoolean.size`, so a DHTuple counts 3 nodes more than a
        // Dlog (compounding through CAND/COR/CTHRESHOLD children).
        SigmaBoolean::ProveDHTuple { .. } => 4,
        SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
            1 + children.iter().map(count_sigma_nodes).sum::<usize>()
        }
        SigmaBoolean::Cthreshold { children, .. } => {
            1 + children.iter().map(count_sigma_nodes).sum::<usize>()
        }
    }
}

/// Replace constants in a serialized ErgoTree at given positions, mirroring
/// Scala `ErgoTreeSerializer.substituteConstants` (JIT path). Returns
/// `(result_bytes, n_constants)` where `n_constants` is the number of constants
/// in the input tree — the count Scala feeds to `SubstConstants`'s
/// `PerItemCost(100, 100, 1)`.
///
/// Faithful to the reference in three consensus-critical ways:
/// - The tree BODY is kept as opaque raw bytes (`deserializeHeaderWithTreeBytes`
///   → `treeBytes` → `putBytes(treeBytes)`); it is never re-parsed or
///   re-serialized. Only the constants section is rewritten. Parsing and
///   re-serializing the body would risk a non-identity round trip — a chain
///   split — and reject trees whose body our parser cannot fully decode.
/// - Out-of-range positions are SKIPPED, not rejected: Scala
///   `getPositionsBackref` ignores `pos < 0 || pos >= nConstants` and the first
///   reference to a given index wins. A non-segregated tree thus returns
///   unchanged with `n_constants = 0`.
/// - A parse failure, a positions/newValues length mismatch, or a type mismatch
///   (`require(c.tpe == newConst.tpe)`) raises `RuntimeException` (Scala
///   throws), surfacing as `errored` — not the `not-implemented` an
///   `UnsupportedOpcode` would produce.
pub(crate) fn subst_constants(
    script_bytes: &[u8],
    positions: &[i32],
    new_values: &[Value],
    is_v3_ergo_tree: bool,
) -> Result<(Vec<u8>, usize), EvalError> {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::sigma_value::{read_constant, write_constant};

    // Scala `require(positions.length == newVals.length)`.
    if positions.len() != new_values.len() {
        return Err(EvalError::RuntimeException(
            "substConstants: positions and newValues length mismatch",
        ));
    }

    let parse_err = |_| EvalError::RuntimeException("substConstants: malformed ErgoTree bytes");
    let reser_err =
        |_| EvalError::RuntimeException("substConstants: constant re-serialization failed");

    // deserializeHeaderWithTreeBytes: header [+ size] + segregated constants,
    // leaving the body as opaque raw bytes.
    let mut r = VlqReader::new(script_bytes);
    let header = r.get_u8().map_err(parse_err)?;
    let has_size = header & 0x08 != 0;
    let constant_segregation = header & 0x10 != 0;
    if has_size {
        // Original declared size; recomputed on output for v3+ trees and
        // dropped pre-v3 (bug-for-bug with Scala's pre-v6 substituteConstants).
        r.get_u32_exact().map_err(parse_err)?;
    }
    let mut constants: Vec<(SigmaType, SigmaValue)> = Vec::new();
    if constant_segregation {
        let n = r.get_u32_exact().map_err(parse_err)? as usize;
        for _ in 0..n {
            let (tpe, val) = read_constant(&mut r).map_err(parse_err)?;
            // Scala deserializes the constants under the executing
            // VersionContext: `DataSerializer.deserialize(SHeader)` is gated on
            // `isV3OrLaterErgoTreeVersion` (pre-v3 falls through to the base
            // deserializer and throws). Our `read_constant` is version-agnostic,
            // so a pre-v3 tree carrying an SHeader constant — reachable via
            // crafted `scriptBytes` — must be rejected here even when that
            // constant is not the one being substituted (else we accept where
            // the reference errors). The check is VALUE-based (per materialized
            // header): an empty `Coll[Header]` constant materializes no header
            // and is accepted on any version, matching Scala.
            if !is_v3_ergo_tree && val.contains_header() {
                return Err(EvalError::RuntimeException(
                    "substConstants: SHeader constant requires ErgoTree version >= 3",
                ));
            }
            // SOption is gated identically to SHeader (CoreDataSerializer matches
            // SOption only at isV3OrLaterErgoTreeVersion); a pre-v3 tree carrying
            // a materialized Option constant in crafted scriptBytes is rejected.
            // Value-based: an empty Coll[Option] materializes none and is accepted.
            if !is_v3_ergo_tree && val.contains_option() {
                return Err(EvalError::RuntimeException(
                    "substConstants: SOption constant requires ErgoTree version >= 3",
                ));
            }
            constants.push((tpe, val));
        }
    }
    let tree_bytes = script_bytes[r.position()..].to_vec();
    let n_constants = constants.len();

    // getPositionsBackref: backref[i] = index into `positions` that targets
    // constant i, or -1. Out-of-range positions are ignored; first reference
    // wins.
    let mut backref = vec![-1i64; n_constants];
    for (i_pos, &pos) in positions.iter().enumerate() {
        if pos >= 0 && (pos as usize) < n_constants && backref[pos as usize] == -1 {
            backref[pos as usize] = i_pos as i64;
        }
    }

    // Re-serialize the constants section: the segregation count (only when
    // segregated) followed by each constant — substituted where a position
    // references it, original otherwise.
    let mut const_w = VlqWriter::new();
    if constant_segregation {
        const_w.put_u32(n_constants as u32);
    }
    for (i, (template_type, original_value)) in constants.iter().enumerate() {
        if backref[i] >= 0 {
            let new_value = &new_values[backref[i] as usize];
            let (new_type, sv) = value_to_typed_sigma(new_value)?;
            // Scala `require(c.tpe == newConst.tpe)`: a substitution cannot
            // change the constant's type. `sigma_type_compatible` bridges the
            // SAny wildcard our type recovery surfaces for `Opt(None)` / empty
            // collections back to the template's concrete type.
            if !sigma_type_compatible(template_type, &new_type) {
                return Err(EvalError::RuntimeException(
                    "substConstants: new value type does not match the constant type",
                ));
            }
            // Re-serializing a Header constant runs the same version-gated
            // DataSerializer.serialize(SHeader) (which throws pre-v3); a pre-v3
            // executing ErgoTree must reject it. Same `errored` class as the
            // template-constant gate above — both mirror a Scala throw.
            if sv.contains_header() && !is_v3_ergo_tree {
                return Err(EvalError::RuntimeException(
                    "substConstants: SHeader substitution requires ErgoTree version >= 3",
                ));
            }
            // Same v3 gate for a substituted Option value
            // (DataSerializer.serialize(SOption) throws pre-v3) — covers e.g. a
            // non-empty Coll[Option] replacement of an empty (accepted) template.
            if sv.contains_option() && !is_v3_ergo_tree {
                return Err(EvalError::RuntimeException(
                    "substConstants: SOption substitution requires ErgoTree version >= 3",
                ));
            }
            // Serialize with the TEMPLATE type (== the new value's type by the
            // check above), matching Scala and preserving the template's
            // concrete descriptor where our recovery would degrade to
            // `SOption(SAny)`.
            write_constant(&mut const_w, template_type, &sv).map_err(reser_err)?;
        } else {
            write_constant(&mut const_w, template_type, original_value).map_err(reser_err)?;
        }
    }
    let const_bytes = const_w.result();

    // Compose the result: header [+ recomputed size for v3+] + constants + body.
    let mut w = VlqWriter::new();
    w.put_u8(header);
    if is_v3_ergo_tree && has_size {
        w.put_u32((const_bytes.len() + tree_bytes.len()) as u32);
    }
    w.put_bytes(&const_bytes);
    w.put_bytes(&tree_bytes);

    Ok((w.result(), n_constants))
}

/// Convert a typed SigmaValue to a runtime Value.
///
/// Shared lowering path for constants (ConstPlaceholder), register values
/// (ExtractRegisterAs), context-var extensions (GetVar) and `deserializeTo`
/// — every boundary that turns a typed `SigmaValue` into a runtime `Value`.
/// [`sigma_to_value`] plus the v6-type gates. Scala materializes an `SHeader`
/// or `SOption` value only when `VersionContext.isV3OrLaterErgoTreeVersion`
/// (`CoreDataSerializer` matches each only at ergoTreeVersion>=3, else falls
/// through and throws) — so a pre-v3 ErgoTree carrying either is rejected.
/// Mirror that here so we never accept input the reference node rejects
/// (accept-invalid fork hazard). This is the VALUE-materialization companion
/// to the parse-time constant gates in `ergo-ser` (`contains_header` /
/// `contains_option`), and it is what gates register / context-var / plain-
/// constant payloads that bypass `parse_expr`.
///
/// The gates key on whether the VALUE actually materializes a header / option
/// (Scala gates per materialized value, not per static type): an empty
/// `Coll[Header]` / `Coll[Option[T]]` materializes none and is accepted on any
/// version, matching the reference.
///
/// NOTE: registers and context vars are additionally subject to the reference's
/// `CheckV6Type`, which rejects Option/Header/UnsignedBigInt-typed values
/// UNCONDITIONALLY (at every activated version, not just pre-v3). The
/// version-conditional gate below matches the reference pre-v3 (and for
/// constants/`deserializeTo` at all versions); the unconditional v3+
/// register/context rejection is a separate, pre-existing gap shared with the
/// SHeader gate, tracked with the Box-register-access work.
pub(crate) fn sigma_to_value_versioned(
    tpe: &SigmaType,
    val: &SigmaValue,
    ctx: &ReductionContext<'_>,
) -> Result<Value, EvalError> {
    if !ctx.is_v3_ergo_tree() && val.contains_header() {
        return Err(EvalError::TypeError {
            expected: "ErgoTree version >= 3 for an SHeader value (isV3OrLaterErgoTreeVersion)",
            got: format!("ergoTreeVersion={}", ctx.ergo_tree_version),
        });
    }
    if !ctx.is_v3_ergo_tree() && val.contains_option() {
        return Err(EvalError::TypeError {
            expected: "ErgoTree version >= 3 for an SOption value (isV3OrLaterErgoTreeVersion)",
            got: format!("ergoTreeVersion={}", ctx.ergo_tree_version),
        });
    }
    sigma_to_value(tpe, val)
}

pub fn sigma_to_value(tpe: &SigmaType, val: &SigmaValue) -> Result<Value, EvalError> {
    use ergo_ser::sigma_value::CollValue;
    match (tpe, val) {
        // Unit, Byte, Short no longer erase to Int — typed-carrier
        // invariant on the sigma-value → evaluator boundary.
        (SigmaType::SUnit, SigmaValue::Unit) => Ok(Value::Unit),
        (SigmaType::SByte, SigmaValue::Byte(n)) => Ok(Value::Byte(*n)),
        (SigmaType::SShort, SigmaValue::Short(n)) => Ok(Value::Short(*n)),
        (SigmaType::SInt, SigmaValue::Int(n)) => Ok(Value::Int(*n)),
        (SigmaType::SLong, SigmaValue::Long(n)) => Ok(Value::Long(*n)),
        (SigmaType::SBigInt, SigmaValue::BigInt(n)) => Ok(Value::BigInt(n.clone())),
        (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(n)) => {
            // Wire-layer (sigma_value.rs::read_unsigned_bigint_value)
            // already enforces the 32-byte unsigned magnitude bound, so
            // by the time we reach this case the value satisfies
            // `0 <= n < 2^256`. A negative `n` here is a deserializer
            // bug, not a script-author bug — surface it loudly as the
            // dedicated `UnsupportedConstant` rather than papering over
            // it by silently lifting the sign.
            if n.sign() == num_bigint::Sign::Minus {
                return Err(EvalError::UnsupportedConstant(SigmaType::SUnsignedBigInt));
            }
            Ok(Value::UnsignedBigInt(n.clone()))
        }
        (SigmaType::SBoolean, SigmaValue::Boolean(b)) => Ok(Value::Bool(*b)),
        (SigmaType::SSigmaProp, SigmaValue::SigmaProp(sb)) => Ok(Value::SigmaProp(sb.clone())),
        (SigmaType::SGroupElement, SigmaValue::GroupElement(ge)) => {
            // Scala validates + canonicalizes a GroupElement when it is
            // deserialized (GroupElementSerializer.parse): 0x00-lead encodings
            // become the canonical identity (33 zeros) and non-0x00 encodings
            // are decoded on-curve (off-curve rejected). Apply the same here so
            // a register / constant / context-var GE value is canonical and
            // validated, matching `decodePoint`.
            Ok(Value::GroupElement(
                super::opcodes::sigma::canonicalize_group_element(*ge.as_bytes())?,
            ))
        }
        (SigmaType::SColl(inner), SigmaValue::Coll(coll)) => {
            match (inner.as_ref(), coll) {
                (SigmaType::SByte, CollValue::Bytes(b)) => Ok(Value::CollBytes(b.clone())),
                (SigmaType::SBoolean, CollValue::BoolBits(bits)) => {
                    Ok(Value::CollBool(bits.clone()))
                }
                (elem_type, CollValue::Values(vs)) => {
                    let items: Result<Vec<Value>, EvalError> =
                        vs.iter().map(|v| sigma_to_value(elem_type, v)).collect();
                    let items = items?;
                    match elem_type {
                        SigmaType::SByte => {
                            // Rare: Coll[Byte] arriving as generic Values — canonicalize to CollBytes.
                            let v: Vec<u8> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Byte(n) = v {
                                        Some(*n as u8)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollBytes(v))
                        }
                        SigmaType::SShort => {
                            let v: Vec<i16> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Short(n) = v {
                                        Some(*n)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollShort(v))
                        }
                        SigmaType::SInt => {
                            let v: Vec<i32> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Int(n) = v {
                                        Some(*n)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollInt(v))
                        }
                        SigmaType::SLong => {
                            let v: Vec<i64> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Long(n) = v {
                                        Some(*n)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollLong(v))
                        }
                        SigmaType::SBoolean => {
                            let v: Vec<bool> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Bool(b) = v {
                                        Some(*b)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollBool(v))
                        }
                        SigmaType::SSigmaProp => {
                            let v: Vec<SigmaBoolean> = items
                                .into_iter()
                                .filter_map(|v| {
                                    if let Value::SigmaProp(sb) = v {
                                        Some(sb)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollSigmaProp(v))
                        }
                        // SColl(non-primitive) → boxed-element coll
                        // carrier (Coll[Tuple], Coll[Header], etc.).
                        // `elem_type` is the inner T from the wire
                        // type tag; carry it on the value so empty
                        // round-trips work and downstream
                        // `Coll.updated` knows the element shape.
                        _ => Ok(Value::CollGeneric(items, Box::new(elem_type.clone()))),
                    }
                }
                (_, CollValue::Bytes(b)) => Ok(Value::CollBytes(b.clone())),
                _ => Err(EvalError::UnsupportedConstant(tpe.clone())),
            }
        }
        (SigmaType::STuple(elem_types), SigmaValue::Tuple(vals)) => {
            let items: Result<Vec<Value>, EvalError> = elem_types
                .iter()
                .zip(vals.iter())
                .map(|(t, v)| sigma_to_value(t, v))
                .collect();
            Ok(Value::Tuple(items?))
        }
        (SigmaType::SOption(inner), SigmaValue::Opt(opt_val)) => match opt_val {
            Some(v) => Ok(Value::Opt(Some(Box::new(sigma_to_value(inner, v)?)))),
            None => Ok(Value::Opt(None)),
        },
        // SBox constant — parse full ErgoBox (candidate + txId + index) with real identity
        (SigmaType::SBox, SigmaValue::OpaqueBoxBytes(bytes)) => {
            use ergo_ser::register::RegisterId;
            let mut r = ergo_primitives::reader::VlqReader::new(bytes);
            let ergo_box =
                ergo_ser::ergo_box::read_ergo_box(&mut r).map_err(|e| EvalError::TypeError {
                    expected: "valid SBox constant",
                    got: format!("box deser error: {e}"),
                })?;
            let box_id = ergo_box.box_id().map_err(|e| EvalError::TypeError {
                expected: "box_id computation",
                got: format!("{e}"),
            })?;
            let registers = [
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R4)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R5)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R6)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R7)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R8)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R9)
                    .cloned(),
            ];
            let tokens: Vec<([u8; 32], u64)> = ergo_box
                .candidate
                .tokens
                .iter()
                .map(|t| (*t.token_id.as_bytes(), t.amount))
                .collect();
            let raw_bytes = {
                let mut w = ergo_primitives::writer::VlqWriter::new();
                ergo_ser::ergo_box::write_ergo_box(&mut w, &ergo_box).unwrap_or_default();
                w.result()
            };
            Ok(Value::InlineBox(Box::new(EvalBox {
                creation_height: ergo_box.candidate.creation_height,
                script_bytes: ergo_box.candidate.ergo_tree_bytes().to_vec(),
                value: ergo_box.candidate.value as i64,
                id: *box_id.as_bytes(),
                // read_ergo_box parses the real transaction id and output
                // index from the box tail; carry them through so
                // ExtractCreationInfo (R3 ref = txId ++ 2-byte big-endian
                // index) and ExtractBytesWithNoRef (strips 32 + VLQ(index))
                // reflect the real identity rather than zeros.
                transaction_id: *ergo_box.transaction_id.as_bytes(),
                output_index: ergo_box.index,
                registers,
                tokens,
                raw_bytes,
            })))
        }
        (SigmaType::SAvlTree, SigmaValue::AvlTree(data)) => Ok(Value::AvlTree(data.clone())),
        (SigmaType::SString, SigmaValue::Str(s)) => Ok(Value::Str(s.clone())),
        // SHeader value -> Value::Header. The header id is Blake2b256 over the
        // serialized header (the block-header path computes it the same way).
        // Version-agnostic: the v3+ (isV3OrLaterErgoTreeVersion) gate is
        // enforced by the evaluator callers that materialize an SHeader value
        // (getVar / constant eval / deserializeTo), which carry the ErgoTree
        // version; this converter does not.
        (SigmaType::SHeader, SigmaValue::Header(h)) => {
            let (_bytes, hid) =
                ergo_ser::header::serialize_header(h).map_err(|e| EvalError::TypeError {
                    expected: "re-serializable SHeader value",
                    got: format!("{e:?}"),
                })?;
            Ok(Value::Header(Box::new(
                crate::evaluator::types::EvalHeader::from_header(h, *hid.as_bytes()),
            )))
        }
        _ => Err(EvalError::UnsupportedConstant(tpe.clone())),
    }
}
