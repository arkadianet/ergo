//! Exhaustive structural walks over every `Payload` variant:
//! `expr_has_deserialize` (does the tree contain a DeserializeContext/Register
//! node?) and `inline_placeholders` (rebuild the tree with segregated
//! constants inlined). Both are wildcard-free so a new `Payload` variant with
//! children cannot silently escape the walk.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

#[inline(never)]
/// Deep walk: does the expression contain a `DeserializeContext` (0xD4)
/// or `DeserializeRegister` (0xD5) node anywhere? Mirrors Scala
/// `Value.hasDeserialize` (counts exactly those two node classes).
/// Exhaustive over `Payload` — no wildcard arm, so a future variant
/// with children cannot silently escape the walk.
pub(crate) fn expr_has_deserialize(expr: &Expr) -> bool {
    let node = match expr {
        // An unparsed (soft-fork-wrapped) body has no AST to inspect; it errors
        // at evaluation regardless, so the deserialize-substitution path is moot.
        Expr::Const { .. } | Expr::Unparsed(_) => return false,
        Expr::Op(node) => node,
    };
    match &node.payload {
        Payload::DeserializeContext { .. } | Payload::DeserializeRegister { .. } => true,
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::NoneValue { .. } => false,
        Payload::One(a) => expr_has_deserialize(a),
        Payload::Two(a, b) => expr_has_deserialize(a) || expr_has_deserialize(b),
        Payload::Three(a, b, c) => {
            expr_has_deserialize(a) || expr_has_deserialize(b) || expr_has_deserialize(c)
        }
        Payload::Four(a, b, c, d) => {
            expr_has_deserialize(a)
                || expr_has_deserialize(b)
                || expr_has_deserialize(c)
                || expr_has_deserialize(d)
        }
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => expr_has_deserialize(rhs),
        Payload::BlockValue { items, result } => {
            items.iter().any(expr_has_deserialize) || expr_has_deserialize(result)
        }
        Payload::FuncValue { body, .. } => expr_has_deserialize(body),
        Payload::MethodCall { obj, args, .. } => {
            expr_has_deserialize(obj) || args.iter().any(expr_has_deserialize)
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter().any(expr_has_deserialize),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => expr_has_deserialize(input),
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            expr_has_deserialize(input)
                || expr_has_deserialize(index)
                || default.as_deref().is_some_and(expr_has_deserialize)
        }
        Payload::FuncApply { func, args } => {
            expr_has_deserialize(func) || args.iter().any(expr_has_deserialize)
        }
    }
}

/// Structural rebuild replacing every `ConstPlaceholder { index }` with
/// the corresponding inline `Expr::Const` from the segregated constant
/// table. Out-of-range indexes are left as placeholders — they error at
/// evaluation exactly like the placeholder path. Exhaustive over
/// `Payload` (no wildcard) for the same reason as
/// [`expr_has_deserialize`].
pub(super) fn inline_placeholders(expr: &Expr, constants: &[(SigmaType, SigmaValue)]) -> Expr {
    let node = match expr {
        // Nothing to inline in a constant or an unparsed (verbatim) body.
        Expr::Const { .. } | Expr::Unparsed(_) => return expr.clone(),
        Expr::Op(node) => node,
    };
    let sub = |e: &Expr| inline_placeholders(e, constants);
    let sub_box = |e: &Expr| Box::new(inline_placeholders(e, constants));
    let payload = match &node.payload {
        Payload::ConstPlaceholder { index } => match constants.get(*index as usize) {
            Some((tpe, val)) => {
                return Expr::Const {
                    tpe: tpe.clone(),
                    val: val.clone(),
                }
            }
            None => Payload::ConstPlaceholder { index: *index },
        },
        p @ (Payload::Zero
        | Payload::ValUse { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::NoneValue { .. }
        | Payload::DeserializeContext { .. }) => p.clone(),
        Payload::One(a) => Payload::One(sub_box(a)),
        Payload::Two(a, b) => Payload::Two(sub_box(a), sub_box(b)),
        Payload::Three(a, b, c) => Payload::Three(sub_box(a), sub_box(b), sub_box(c)),
        Payload::Four(a, b, c, d) => Payload::Four(sub_box(a), sub_box(b), sub_box(c), sub_box(d)),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id: *id,
            tpe: tpe.clone(),
            rhs: sub_box(rhs),
        },
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => Payload::FunDef {
            id: *id,
            tpe: tpe.clone(),
            tpe_args: tpe_args.clone(),
            rhs: sub_box(rhs),
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: items.iter().map(sub).collect(),
            result: sub_box(result),
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args: args.clone(),
            body: sub_box(body),
        },
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => Payload::MethodCall {
            type_id: *type_id,
            method_id: *method_id,
            obj: sub_box(obj),
            args: args.iter().map(sub).collect(),
            type_args: type_args.clone(),
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type: elem_type.clone(),
            items: items.iter().map(sub).collect(),
        },
        Payload::Tuple { items } => Payload::Tuple {
            items: items.iter().map(sub).collect(),
        },
        Payload::SigmaCollection { items } => Payload::SigmaCollection {
            items: items.iter().map(sub).collect(),
        },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: sub_box(input),
            field_idx: *field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: sub_box(input),
            reg_id: *reg_id,
            tpe: tpe.clone(),
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id: *reg_id,
            tpe: tpe.clone(),
            default: default.as_deref().map(sub_box),
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: sub_box(input),
            index: sub_box(index),
            default: default.as_deref().map(sub_box),
        },
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: sub_box(input),
            tpe: tpe.clone(),
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: sub_box(func),
            args: args.iter().map(sub).collect(),
        },
    };
    Expr::Op(IrNode {
        opcode: node.opcode,
        payload,
    })
}

/// Substitute bottom-up, visiting dead branches and defaults before their parent.
/// Inserted scripts are not revisited, matching Scala `everywherebu`.
pub(super) fn substitute_deserialize(
    expr: &mut Expr,
    ctx: &super::ReductionContext<'_>,
    cost: &mut ergo_primitives::cost::CostAccumulator,
) -> Result<ergo_ser::opcode::ConstructorType, super::EvalError> {
    let mut types = ergo_ser::opcode::ConstructorTypes::default();
    let mut extension_bytes = std::collections::HashMap::new();
    substitute_node(expr, ctx, cost, &mut types, &mut extension_bytes).map(|(_, tpe)| tpe)
}

fn substitute_node(
    expr: &mut Expr,
    ctx: &super::ReductionContext<'_>,
    cost: &mut ergo_primitives::cost::CostAccumulator,
    types: &mut ergo_ser::opcode::ConstructorTypes,
    extension_bytes: &mut std::collections::HashMap<u8, std::sync::OnceLock<Option<Vec<u8>>>>,
) -> Result<(bool, ergo_ser::opcode::ConstructorType), super::EvalError> {
    use super::EvalError;
    use ergo_ser::opcode::{check_rebuilt_constructor, ConstructorError};
    let Expr::Op(node) = expr else {
        return Ok((false, types.node_type(expr, &[])));
    };
    if let Payload::FuncValue { args, .. } = &node.payload {
        types.bind_args(args);
    }
    let children: Vec<&mut Expr> = match &mut node.payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => vec![],
        Payload::One(a) => vec![a],
        Payload::Two(a, b) => vec![a, b],
        Payload::Three(a, b, c) => vec![a, b, c],
        Payload::Four(a, b, c, d) => vec![a, b, c, d],
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => vec![rhs],
        Payload::BlockValue { items, result } => {
            let mut v: Vec<&mut Expr> = items.iter_mut().collect();
            v.push(result);
            v
        }
        Payload::FuncValue { body, .. } => vec![body],
        Payload::MethodCall { obj, args, .. } => {
            let mut v = vec![obj.as_mut()];
            v.extend(args.iter_mut());
            v
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter_mut().collect(),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => vec![input],
        Payload::DeserializeRegister { default, .. } => {
            default.as_deref_mut().into_iter().collect()
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            let mut v = vec![input.as_mut(), index.as_mut()];
            v.extend(default.as_deref_mut());
            v
        }
        Payload::FuncApply { func, args } => {
            let mut v = vec![func.as_mut()];
            v.extend(args.iter_mut());
            v
        }
    };
    let mut changed = false;
    let mut child_types = Vec::with_capacity(children.len());
    for child in children {
        let (child_changed, tpe) = substitute_node(child, ctx, cost, types, extension_bytes)?;
        changed |= child_changed;
        child_types.push(tpe);
    }
    // Deliberately match the JVM quirk: only the rule's direct ClassCastException
    // is swallowed. Reflective ancestor construction is OUTSIDE that catch and
    // its InvocationTargetException must reject even on a dead branch.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/kiama/rewriting/Rewriter.scala#L180-L191
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/kiama/rewriting/Rewriter.scala#L448-L473
    if changed {
        check_rebuilt_constructor(expr, &child_types)
            .map_err(|_| EvalError::RuntimeException("deserialize ancestor constructor failed"))?;
    }
    let original_type = types.node_type(expr, &child_types);
    let Expr::Op(node) = expr else { unreachable!() };
    let (source, tpe, default) = match &node.payload {
        Payload::DeserializeContext { id, tpe } => {
            let source = match ctx.extension.get(id) {
                // Interpreter checks the source's declared type BEFORE .value.
                Some((t @ SigmaType::SColl(elem), v)) if **elem == SigmaType::SByte => {
                    let cache = extension_bytes.entry(*id).or_default();
                    Some(deserialize_value_bytes(t, v, cache)?)
                }
                _ => None,
            };
            (source, tpe, None)
        }
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => {
            let source = match ctx.self_box {
                Some(b) => match reg_id {
                    // ErgoBoxCandidate.get synthesizes every mandatory register.
                    // Only R1 has the byte-array carrier needed by this macro;
                    // R0/R2/R3 are PRESENT and fail its unchecked collection cast.
                    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/org/ergoplatform/ErgoBoxCandidate.scala#L69-L83
                    1 => Some(Some(b.script_bytes.as_slice())),
                    0 | 2 | 3 => Some(None),
                    _ => match reg_id.checked_sub(4).map(usize::from) {
                        Some(i) if i < b.registers.len() => match &b.registers[i] {
                            Some(r) => Some(deserialize_value_bytes(
                                &r.tpe,
                                &r.value,
                                &b.lazy_vals
                                    .deserialize_register_bytes
                                    .get_or_init(Default::default)
                                    [usize::from(ctx.ergo_tree_version >= 3)][i],
                            )?),
                            None => None,
                        },
                        _ => None,
                    },
                },
                None => None,
            };
            (source, tpe, default.as_deref())
        }
        _ => return Ok((changed, original_type)),
    };
    if let Some(Some(bytes)) = source {
        let decoded = deserialize_measured(bytes, ctx, cost)?;
        if let Some((script, actual)) = decoded {
            // Decode succeeded and charged the WHOLE buffer before .tpe was read.
            // A deferred Filter type cast is swallowed with the charge retained.
            // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala#L97-L126
            match actual {
                Err(ConstructorError::ClassCast) => return Ok((changed, original_type)),
                Ok(actual) if actual.as_ref() == Some(tpe) => {
                    *expr = script;
                    return Ok((true, Ok(actual)));
                }
                _ => {
                    if matches!(node.payload, Payload::DeserializeRegister { .. }) {
                        return Err(EvalError::RuntimeException(
                            "DeserializeRegister script type mismatch",
                        ));
                    }
                    return Err(EvalError::SigmaValidation {
                        rule_id: 1000,
                        args: vec![],
                    });
                }
            }
        }
        return Ok((changed, original_type));
    }
    // A failed unchecked source cast leaves the macro unresolved, including its
    // default. Only an absent register selects the already rewritten default.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/org/ergoplatform/ErgoLikeInterpreter.scala#L17-L39
    if source.is_none() {
        if let Some(default) = default {
            *expr = default.clone();
            return Ok((true, child_types.pop().unwrap_or(Ok(None))));
        }
    }
    Ok((changed, original_type))
}

/// Borrow ordinary byte constants, caching only lazy stored-node materialization.
/// A failure of `.value` (for example CollectionUtil.cast's AssertionError) is
/// not the byte-array ClassCastException and must escape the rewrite strategy.
/// <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/util/CollectionUtil.scala#L184-L193>
fn deserialize_value_bytes<'a>(
    tpe: &SigmaType,
    value: &'a SigmaValue,
    cache: &'a std::sync::OnceLock<Option<Vec<u8>>>,
) -> Result<Option<&'a [u8]>, super::EvalError> {
    if let (
        SigmaType::SColl(elem),
        SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(bytes)),
    ) = (tpe, value)
    {
        if **elem == SigmaType::SByte {
            return Ok(Some(bytes));
        }
    }
    // Plain non-byte Constants have no lazy children to materialize. Their
    // carrier fails the unchecked cast immediately, without evaluator type gates.
    let lazy_node = matches!(value, SigmaValue::ConcreteCollection { .. })
        || matches!((tpe, value), (SigmaType::STuple(_), SigmaValue::Coll(_)));
    if !lazy_node && !matches!(tpe, SigmaType::SColl(elem) if **elem == SigmaType::SByte) {
        return Ok(None);
    }
    if cache.get().is_none() {
        // This is stored `.value`, not expression evaluation/DataSerializer:
        // do not apply evaluator Header/Option version gates to a failed cast.
        let materialized = crate::evaluator::helpers::sigma_to_value(tpe, value)?;
        let bytes = match materialized {
            crate::evaluator::Value::CollBytes(bytes) => Some(bytes),
            _ => None,
        };
        // A concurrent evaluation may have won initialization; both compute
        // the same source carrier/bytes in the same version class.
        let _ = cache.set(bytes);
    }
    Ok(cache.get().and_then(Option::as_deref))
}

/// Scala parses before `addCostChecked`, then charges the entire supplied buffer.
fn deserialize_measured(
    bytes: &[u8],
    ctx: &super::ReductionContext<'_>,
    cost: &mut ergo_primitives::cost::CostAccumulator,
) -> Result<Option<(Expr, ergo_ser::opcode::ConstructorType)>, super::EvalError> {
    use ergo_primitives::cost::{CostError, JitCost};
    let mut reader = ergo_primitives::reader::VlqReader::new(bytes);
    // The executing VersionContext also scopes nested SBox tree parsing.
    // Its version require raises SerializerException, escaping both soft-fork
    // handling and Kiama's ClassCastException swallowing below.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ErgoTreeSerializer.scala#L151-L196
    reader.set_activated_script_version(Some(ctx.activated_script_version));
    reader.set_strict_method_resolution();
    reader.set_embeddable_activated_version(Some(ctx.activated_script_version));
    let parsed = ergo_ser::opcode::parse_body_for_substitution(&mut reader, ctx.ergo_tree_version);
    // Deliberately match Kiama.strategy's swallowed direct ClassCastException:
    // leave the live macro unresolved; do not charge a failed payload decode.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/kiama/rewriting/Rewriter.scala#L180-L191
    if matches!(
        parsed,
        Err(ergo_primitives::reader::ReadError::ClassCast(_))
    ) {
        return Ok(None);
    }
    let script = parsed.map_err(|e| {
        if let ergo_primitives::reader::ReadError::SigmaValidation { rule_id, args, .. } = e {
            // ValidationRules: A6 uses new rule identities even for legacy trees.
            let rule_id = match (rule_id, (ctx.activated_script_version as i8) >= 3) {
                (1011, true) => 1016,
                (1007, true) => 1017,
                (1008, true) => 1018,
                _ => rule_id,
            };
            super::EvalError::SigmaValidation { rule_id, args }
        } else {
            super::EvalError::TypeError {
                expected: "valid serialized expression",
                got: format!("deserialization error: {e}"),
            }
        }
    })?;
    let charge = JitCost::from_block_cost(bytes.len() as u64 * 2).map_err(CostError::from)?;
    cost.add(charge)?;
    Ok(Some(script))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::ergo_tree::substitution_type_of;

    // ----- helpers -----

    fn op(opcode: u8, payload: Payload) -> Expr {
        Expr::Op(IrNode { opcode, payload })
    }

    // ----- happy path -----

    #[test]
    fn substitution_type_collection_exact_type() {
        let script = op(
            0x83,
            Payload::ConcreteCollection {
                elem_type: SigmaType::SInt,
                items: vec![],
            },
        );
        assert_eq!(
            substitution_type_of(&script),
            Some(SigmaType::SColl(Box::new(SigmaType::SInt)))
        );
    }

    #[test]
    fn swallowed_cast_cost_depends_on_decode_or_type_read_phase() {
        use ergo_primitives::cost::{CostAccumulator, JitCost};
        use ergo_ser::opcode::ConstructorError;
        let ctx = super::super::ReductionContext::minimal(0, 0);
        let mut cost = CostAccumulator::recording_only();
        let decode_cast = hex::decode("e4b2860204000400040000").unwrap();
        assert!(deserialize_measured(&decode_cast, &ctx, &mut cost)
            .unwrap()
            .is_none());
        assert_eq!(cost.total_block_cost(), 0);
        let type_cast = hex::decode("b5b2860204000400040000d90101040101").unwrap();
        assert!(matches!(
            deserialize_measured(&type_cast, &ctx, &mut cost).unwrap(),
            Some((_, Err(ConstructorError::ClassCast)))
        ));
        assert_eq!(cost.total_block_cost(), 34);
        // The cost-limit exception happens before the deferred cast and must
        // escape. Catching every decode/type error would wrongly accept this.
        let mut limited = CostAccumulator::new(JitCost::from_block_cost(33).unwrap());
        assert!(matches!(
            deserialize_measured(&type_cast, &ctx, &mut limited),
            Err(super::super::EvalError::CostExceeded(_))
        ));
        // A successfully decoded expression charges ignored trailing bytes too.
        let mut trailing = CostAccumulator::recording_only();
        assert!(deserialize_measured(&[4, 2, 0xff], &ctx, &mut trailing)
            .unwrap()
            .is_some());
        assert_eq!(trailing.total_block_cost(), 6);
    }

    #[test]
    fn stored_source_assertion_is_not_swallowed_as_a_byte_array_cast() {
        let tpe = SigmaType::SColl(Box::new(SigmaType::SByte));
        let value = SigmaValue::ConcreteCollection {
            elem_type: Box::new(SigmaType::SByte),
            items: vec![SigmaValue::Unevaluated(Box::new(op(0xA3, Payload::Zero)))],
        };
        let cache = std::sync::OnceLock::new();
        assert!(deserialize_value_bytes(&tpe, &value, &cache).is_err());
    }

    // ----- error paths -----

    #[test]
    fn substitution_type_unknown_or_imprecise_rejected() {
        let unknown = op(0x72, Payload::ValUse { id: 1 });
        assert_eq!(substitution_type_of(&unknown), None);
        let imprecise = op(
            0x86,
            Payload::Tuple {
                items: vec![unknown],
            },
        );
        assert_eq!(substitution_type_of(&imprecise), None);
        assert_eq!(substitution_type_of(&Expr::Unparsed(vec![].into())), None);
    }
}
