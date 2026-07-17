//! Static type inference over the IR (`infer_expr_type`/`infer_op_type`)
//! plus the runtime-value <-> `SigmaType` derivation and compatibility checks.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use crate::evaluator::types::*;

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

/// `value_to_sigma_type` variant that never returns `SAny`-degraded
/// types — used when scanning a collection for a concrete elem-type
/// witness. Returns `None` for `Value::Opt(None)` so callers skip
/// past it to the next item rather than tagging the carrier with
/// `SOption(SAny)`.
pub(crate) fn strict_value_sigma_type(v: &Value) -> Option<SigmaType> {
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
        // No static type for an unparsed (soft-fork-wrapped) body.
        Expr::Unparsed(_) => None,
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
