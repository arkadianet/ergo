use ergo_primitives::cost::CostAccumulator;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use super::cost::*;
use super::eval_ctx::EvalCtx;
use super::helpers::*;
use super::opcodes;
use super::types::*;

pub fn reduce_expr(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
) -> Result<SigmaBoolean, EvalError> {
    let mut cost = CostAccumulator::recording_only();
    reduce_expr_with_cost(expr, ctx, constants, &mut cost)
}

/// Evaluate an ErgoTree expression to a SigmaBoolean, accumulating cost.
pub fn reduce_expr_with_cost(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    cost: &mut CostAccumulator,
) -> Result<SigmaBoolean, EvalError> {
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    let val = eval_expr(expr, ctx, constants, &mut env, &mut depth, cost, &mut trace)?;
    match val {
        Value::SigmaProp(sb) => Ok(sb),
        Value::Bool(true) => Ok(SigmaBoolean::TrivialProp(true)),
        Value::Bool(false) => Ok(SigmaBoolean::TrivialProp(false)),
        other => Err(EvalError::TypeError {
            expected: "SigmaProp or Bool",
            got: format!("{other:?}"),
        }),
    }
}

/// Trace entry recording an intermediate evaluation result.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub label: String,
    pub value: String,
}

/// Evaluate an expression to a raw Value (test-only).
#[cfg(test)]
pub(crate) fn eval_to_value(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
) -> Result<Value, EvalError> {
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut cost = CostAccumulator::recording_only();
    let mut trace = None;
    eval_expr(
        expr, ctx, constants, &mut env, &mut depth, &mut cost, &mut trace,
    )
}

/// Evaluate with tracing — records each ValDef binding, If condition,
/// and SigmaOr/SigmaAnd child result. For debugging wrong-branch reductions.
pub fn reduce_expr_traced(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
) -> (Result<SigmaBoolean, EvalError>, Vec<TraceEntry>) {
    let mut cost = CostAccumulator::recording_only();
    reduce_expr_traced_with_cost(expr, ctx, constants, &mut cost)
}

/// Evaluate with tracing, accumulating cost.
pub fn reduce_expr_traced_with_cost(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    cost: &mut CostAccumulator,
) -> (Result<SigmaBoolean, EvalError>, Vec<TraceEntry>) {
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = Some(Vec::new());
    let result = eval_expr(expr, ctx, constants, &mut env, &mut depth, cost, &mut trace);
    let entries = trace.unwrap_or_default();
    let sb_result = result.and_then(|val| match val {
        Value::SigmaProp(sb) => Ok(sb),
        Value::Bool(true) => Ok(SigmaBoolean::TrivialProp(true)),
        Value::Bool(false) => Ok(SigmaBoolean::TrivialProp(false)),
        other => Err(EvalError::TypeError {
            expected: "SigmaProp or Bool",
            got: format!("{other:?}"),
        }),
    });
    (sb_result, entries)
}

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
        Payload::Five(a, b, c, d, e) => {
            expr_has_deserialize(a)
                || expr_has_deserialize(b)
                || expr_has_deserialize(c)
                || expr_has_deserialize(d)
                || expr_has_deserialize(e)
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

/// Validate every `GroupElement` constant in the segregated constant table the
/// way Scala's `GroupElementSerializer.parse` does at deserialize time: a
/// non-zero lead byte must encode a point on SecP256K1, so an off-curve
/// constant errors EVEN WHEN the live evaluation path never reads it (it sits
/// in a dead `if`-branch). A lead-`0x00` (identity) encoding is accepted with
/// its trailing bytes discarded — only non-zero leads curve-validate. GE values
/// nested inside `Coll`/`Tuple`/`Option` constants are walked too.
fn validate_group_element_constants(
    constants: &[(SigmaType, SigmaValue)],
) -> Result<(), EvalError> {
    fn walk(v: &SigmaValue) -> Result<(), EvalError> {
        match v {
            SigmaValue::GroupElement(ge) => {
                opcodes::sigma::canonicalize_group_element(*ge.as_bytes())?;
                Ok(())
            }
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vs))
            | SigmaValue::Tuple(vs) => vs.iter().try_for_each(walk),
            SigmaValue::Opt(Some(inner)) => walk(inner),
            _ => Ok(()),
        }
    }
    constants.iter().try_for_each(|(_, val)| walk(val))
}

/// Reject a ContextExtension whose variable-id key has the high bit set
/// (>= 0x80). Scala stores extension keys as signed `Byte` and `toSigmaContext`
/// materializes a dense `Array(maxKey + 1)` indexed by that key — a key >= 0x80
/// is negative as a `Byte`, so the array build throws BEFORE any bytecode runs
/// and the spend fails regardless of whether the script reads the extension.
/// (Our map stores keys as unsigned `u8`; `k as i8 < 0` is the same domain.)
fn check_extension_key_domain(ctx: &ReductionContext<'_>) -> Result<(), EvalError> {
    if ctx.extension.keys().any(|&k| (k as i8) < 0) {
        return Err(EvalError::RuntimeException(
            "ContextExtension variable id with the high bit set (>= 0x80) is invalid",
        ));
    }
    Ok(())
}

/// Whole-tree checks Scala performs at context-build / deserialize time, BEFORE
/// any reduction runs (trivial or full): the ContextExtension key domain
/// (`toSigmaContext`) and every GroupElement constant on-curve
/// (`GroupElementSerializer.parse`). Exposed for the verifier so the
/// trivial-reduction fast path (`reduce::trivial_reduce`, which never enters
/// [`eval_expr`]) enforces them too — otherwise a bare P2PK spend with a
/// malformed context/constant would be accepted where Scala rejects.
pub(crate) fn pre_reduction_checks(
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    body: &Expr,
) -> Result<(), EvalError> {
    validate_group_element_constants(constants)?;
    check_extension_key_domain(ctx)?;
    check_v3_only_methods(ctx, body)?;
    Ok(())
}

/// Reject a v6/EIP-50 method ([`ergo_ser::opcode::is_v3_only_method`]) used in a
/// real pre-v3 (tree-header version < 3) ErgoTree. Scala's `deserializeErgoTree`
/// resolves the method table against the TREE-HEADER version and throws a
/// `ValidationException` for a v3-only method id in a v0/v1/v2 tree — eagerly,
/// over the whole AST, so even a dead `If`-branch method rejects (vector
/// `Global.none_pre_v3_dead_branch`). The wire parser stays version-independent
/// (headerless register / context payloads parse with a v0 sentinel and gate v6
/// methods at evaluation time via [`EvalError::SoftForkNotActivated`]); this
/// gate runs once at the shared depth-0 reduction entry — covering the spend
/// path — and keys on the tree-header version ([`ReductionContext::is_v3_ergo_tree`]),
/// NOT the activated soft-fork version.
fn check_v3_only_methods(ctx: &ReductionContext<'_>, body: &Expr) -> Result<(), EvalError> {
    if !ctx.is_v3_ergo_tree() {
        if let Some((type_id, method_id)) = ergo_ser::opcode::find_v3_only_method(body) {
            return Err(EvalError::PreV3V6Method {
                type_id,
                method_id,
                tree_version: ctx.ergo_tree_version,
            });
        }
    }
    Ok(())
}

/// Validate one group-element encoding exactly as Scala's
/// `GroupElementSerializer.parse` does at deserialize time: a `0x00`-lead
/// encoding is the identity (accepted, trailing bytes ignored); any other lead
/// must decode to an on-curve SecP256K1 point. Off-curve points and invalid
/// SEC1 prefixes error.
///
/// Exposed for the consensus group-element check: the node stores group elements
/// as raw bytes and defers the curve check to spend-eval, so a transaction
/// carrying an off-curve point would be accepted at creation where the JVM
/// rejects it at deserialize. `ergo-ser` collects every point seen during a
/// parse on the reader's sideband; `ergo-validation` drains that set and passes
/// each point here.
pub fn validate_group_element(bytes: [u8; 33]) -> Result<(), EvalError> {
    opcodes::sigma::canonicalize_group_element(bytes).map(|_| ())
}

/// Structural rebuild replacing every `ConstPlaceholder { index }` with
/// the corresponding inline `Expr::Const` from the segregated constant
/// table. Out-of-range indexes are left as placeholders — they error at
/// evaluation exactly like the placeholder path. Exhaustive over
/// `Payload` (no wildcard) for the same reason as
/// [`expr_has_deserialize`].
fn inline_placeholders(expr: &Expr, constants: &[(SigmaType, SigmaValue)]) -> Expr {
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
        Payload::Five(a, b, c, d, e) => {
            Payload::Five(sub_box(a), sub_box(b), sub_box(c), sub_box(d), sub_box(e))
        }
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

pub(in crate::evaluator) fn eval_expr(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    env: &mut Env,
    depth: &mut usize,
    cost: &mut CostAccumulator,
    trace: &mut Option<Vec<TraceEntry>>,
) -> Result<Value, EvalError> {
    // Scala `Interpreter.fullReduction` forks on `ErgoTree.hasDeserialize`:
    // a tree containing DeserializeContext/DeserializeRegister goes
    // through `propositionFromErgoTree` →
    // `toProposition(isConstantSegregation)` — segregated constants are
    // INLINED into the proposition — and `reduceToCryptoJITC` then
    // evaluates with `EmptyConstants`. An inline `Constant` charges
    // `Constant.costKind` (5 jit) where a `ConstantPlaceholder` charges
    // 1, so the reduction cost of a deserialize-carrying segregated
    // tree differs from the placeholder path even when no deserialize
    // node is ever evaluated (vector:
    // DeserializeContext_over_absent_wrong_typed_var dead-branch
    // entries, +4 per segregated constant).
    //
    // Root-gated at depth 0, which holds at every public entry
    // (`reduce_expr_with_cost`, test-only `eval_to_value`, the
    // conformance hook) and never mid-evaluation (the counter is
    // incremented before any child dispatch). The recursive call passes
    // empty constants — mirroring Scala's `EmptyConstants` and making
    // the gate non-reentrant.
    if *depth == 0 {
        // Whole-tree checks Scala performs at context/deserialize time, BEFORE
        // any bytecode runs — so they fire even when the live path never reaches
        // the offending value (off-curve GE constant on a dead branch; a
        // high-bit ContextExtension key with the script never reading it). Run
        // once at the shared depth-0 entry (real reduce path, test-only
        // `eval_to_value`, and the conformance hook all funnel here at depth 0).
        // The verifier ALSO runs these before its trivial-reduction fast path
        // (which bypasses this function); re-running here is cheap and keeps the
        // non-verifier entries covered.
        pre_reduction_checks(ctx, constants, expr)?;
    }
    if *depth == 0 && !constants.is_empty() && expr_has_deserialize(expr) {
        let inlined = inline_placeholders(expr, constants);
        return eval_expr(&inlined, ctx, &[], env, depth, cost, trace);
    }
    *depth += 1;
    if *depth > MAX_EVAL_DEPTH {
        return Err(EvalError::DepthLimitExceeded(*depth));
    }
    let result = match expr {
        Expr::Const { tpe, val } => {
            cost.add(ergo_primitives::cost::JitCost::from_jit(5))?;
            sigma_to_value_versioned(tpe, val, ctx)
        }
        Expr::Op(node) => eval_op(node, ctx, constants, env, depth, cost, trace),
        // A soft-fork-wrapped tree body cannot be evaluated — Scala throws on an
        // `UnparsedErgoTree` (unless its error is an active soft-fork), so the
        // box is UNSPENDABLE rather than trivially `true`.
        Expr::Unparsed(_) => Err(EvalError::UnparsedErgoTree),
    };
    *depth -= 1;
    result
}

#[inline(never)]
fn eval_op(
    node: &IrNode,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    env: &mut Env,
    depth: &mut usize,
    cost: &mut CostAccumulator,
    trace: &mut Option<Vec<TraceEntry>>,
) -> Result<Value, EvalError> {
    // Bundle the six shared borrows once. Converted opcode helpers take
    // `&mut cx`; helpers that genuinely need only a subset of the bundle
    // (`eval_const_placeholder`, `eval_val_use`, `eval_func_value`,
    // `eval_get_var`, simple constant emitters) keep their narrow
    // signatures and read fields directly off `cx`.
    let mut cx = EvalCtx {
        ctx,
        constants,
        env,
        depth,
        cost,
        trace,
    };
    match (node.opcode, &node.payload) {
        // ConstPlaceholder(index)
        (0x73, Payload::ConstPlaceholder { index }) => {
            opcodes::binding::eval_const_placeholder(*index, cx.constants, cx.cost)
        }

        // ValUse — reference a bound variable
        (0x72, Payload::ValUse { id }) => opcodes::binding::eval_val_use(*id, cx.env, cx.cost),

        // BlockValue — evaluate ValDefs then return result
        (0xD8, Payload::BlockValue { items, result }) => {
            opcodes::binding::eval_block_value(items, result, &mut cx)
        }

        // ValDef — standalone reject. Binding happens ONLY inside the
        // BlockValue item loop (Scala BlockValue.eval binds items
        // inline; the ValDef node itself has no eval and a bare
        // occurrence hits notSupportedError).
        (0xD6, _) => opcodes::errors::eval_val_def_standalone(),

        // True constant
        (0x7F, Payload::Zero) => opcodes::constants::eval_true(cost),

        // False constant
        (0x80, Payload::Zero) => opcodes::constants::eval_false(cost),

        // 0x81 UnitConstant: no dispatch arm. Scala does not register a
        // serializer for 0x81 at the dispatch position; SUnit values
        // flow through the constant-encoding path (type-prefixed, byte
        // ≤ LastConstantCode). The parser at ergo-ser/src/opcode.rs
        // rejects 0x81, so this byte is unreachable from real wire
        // bytes. `Value::Unit` still exists and reaches the evaluator
        // via `sigma_to_value(SUnit)` for legitimate Unit constants.

        // GroupGenerator — secp256k1 generator. values.scala:709-723, Fixed(10).
        (0x82, Payload::Zero) => opcodes::constants::eval_group_generator(cost),

        // If(condition, then_branch, else_branch)
        (0x95, Payload::Three(cond, then_br, else_br)) => {
            opcodes::binding::eval_if(cond, then_br, else_br, &mut cx)
        }

        // Lt (<)
        (0x8F, Payload::Two(left, right)) => opcodes::comparison::eval_lt(left, right, &mut cx),

        // Le (<=)
        (0x90, Payload::Two(left, right)) => opcodes::comparison::eval_le(left, right, &mut cx),

        // Gt (>)
        (0x91, Payload::Two(left, right)) => opcodes::comparison::eval_gt(left, right, &mut cx),

        // Neq (!=)
        (0x94, Payload::Two(left, right)) => opcodes::comparison::eval_neq(left, right, &mut cx),

        // Minus (-)
        (0x99, Payload::Two(left, right)) => opcodes::arithmetic::eval_minus(left, right, &mut cx),

        // Multiply (*)
        (0x9C, Payload::Two(left, right)) => {
            opcodes::arithmetic::eval_multiply(left, right, &mut cx)
        }

        // Division (/)
        (0x9D, Payload::Two(left, right)) => {
            opcodes::arithmetic::eval_division(left, right, &mut cx)
        }

        // Modulo (%)
        (0x9E, Payload::Two(left, right)) => opcodes::arithmetic::eval_modulo(left, right, &mut cx),

        // Upcast — numeric type widening.
        (0x7E, Payload::NumericCast { input, tpe }) => {
            opcodes::cast::eval_upcast(input, tpe, &mut cx)
        }

        // Downcast — numeric type narrowing (Math.toIntExact-style; overflow throws).
        (0x7D, Payload::NumericCast { input, tpe }) => {
            opcodes::cast::eval_downcast(input, tpe, &mut cx)
        }

        // OR (||) — boolean reducer over Coll[Boolean] (not sigma)
        (0x97, Payload::One(inner)) => opcodes::boolean::eval_or_collection(inner, &mut cx),

        // HEIGHT
        (0xA3, Payload::Zero) => opcodes::constants::eval_height(ctx, cost),

        // GetVar(var_id, type) -> Option[T] — extension lookup with exact-type match.
        (0xE3, Payload::GetVar { var_id, tpe }) => {
            opcodes::box_context::eval_get_var(*var_id, tpe, cx.ctx, cx.cost)
        }

        // DeserializeContext(id, type) -> T
        (0xD4, Payload::DeserializeContext { id, tpe: _ }) => {
            opcodes::sigma::eval_deserialize_context(*id, &mut cx)
        }

        // DeserializeRegister(reg_id, type, default) -> T
        (
            0xD5,
            Payload::DeserializeRegister {
                reg_id,
                tpe: _,
                default,
            },
        ) => opcodes::sigma::eval_deserialize_register(*reg_id, default.as_deref(), &mut cx),

        // SELF
        (0xA7, Payload::Zero) => opcodes::constants::eval_self(cost),

        // ExtractCreationInfo(box) -> Tuple(Int, Coll[Byte])
        // Scala: (creationHeight, transactionId ++ Shorts.toByteArray(outputIndex))
        // The Coll[Byte] is 34 bytes: 32-byte txId + 2-byte big-endian index.
        // ExtractCreationInfo — (creationHeight, txId++index).
        (0xC7, Payload::One(input)) => {
            opcodes::box_context::eval_extract_creation_info(input, &mut cx)
        }

        // ExtractAmount(box) -> Long.
        (0xC1, Payload::One(input)) => opcodes::box_context::eval_extract_amount(input, &mut cx),

        // ExtractId(box) -> Coll[Byte].
        (0xC5, Payload::One(input)) => opcodes::box_context::eval_extract_id(input, &mut cx),

        // ExtractRegisterAs(box, reg_id, tpe) -> Option[T] for R0..R9.
        (0xC6, Payload::ExtractRegisterAs { input, reg_id, tpe }) => {
            opcodes::box_context::eval_extract_register_as(input, *reg_id, tpe, &mut cx)
        }

        // INPUTS
        (0xA4, Payload::Zero) => opcodes::constants::eval_inputs(cost),

        // CONTEXT (0xFE) — placeholder; context ops handled via MethodCall.
        (0xFE, Payload::Zero) => opcodes::constants::eval_context(cost),

        // OptionGet — unwrap Option, error if None or non-Option.
        (0xE4, Payload::One(inner)) => opcodes::option::eval_option_get(inner, &mut cx),

        // BinOr (lazy ||) — short-circuit
        (0xEC, Payload::Two(left, right)) => opcodes::boolean::eval_bin_or(left, right, &mut cx),

        // BinAnd (lazy &&) — short-circuit
        (0xED, Payload::Two(left, right)) => opcodes::boolean::eval_bin_and(left, right, &mut cx),

        // LogicalNot — boolean negation
        (0xEF, Payload::One(inner)) => opcodes::boolean::eval_logical_not(inner, &mut cx),

        // Global object — SGlobal singleton for method dispatch
        (0xDD, Payload::Zero) => opcodes::constants::eval_global(cost),

        // MethodCall — dispatch on type_id and method_id
        // MethodCall — dispatch on type_id and method_id.
        // `type_args` is parsed at the wire layer (v6 explicit-type
        // args) and threaded through so methods like
        // `SContext.getVar[T]` / `SGlobal.deserializeTo[T]` can
        // consult the explicit `[T]` binding.
        (
            0xDC,
            Payload::MethodCall {
                type_id,
                method_id,
                obj,
                args,
                type_args,
            },
        ) => opcodes::method_call::eval_method_call(
            *type_id, *method_id, obj, args, type_args, &mut cx,
        ),

        // PropertyCall — no-arg method invocation. Shared dispatch table
        // with MethodCall lives in opcodes::property_call::eval_no_arg_method.
        (
            0xDB,
            Payload::MethodCall {
                type_id,
                method_id,
                obj,
                ..
            },
        ) => opcodes::property_call::eval_property_call(*type_id, *method_id, obj, &mut cx),

        // SelectField(input, field_idx) — 1-indexed tuple field access.
        (0x8C, Payload::SelectField { input, field_idx }) => {
            opcodes::binding::eval_select_field(input, *field_idx, &mut cx)
        }

        // GE (>=)
        (0x92, Payload::Two(left, right)) => opcodes::comparison::eval_ge(left, right, &mut cx),

        // Plus (+)
        (0x9A, Payload::Two(left, right)) => opcodes::arithmetic::eval_plus(left, right, &mut cx),

        // BoolToSigmaProp — lenient pass-through for double-wrapped SigmaProp.
        (0xD1, Payload::One(inner)) => opcodes::boolean::eval_bool_to_sigma_prop(inner, &mut cx),

        // AtLeast(bound, children) -> SigmaProp
        // k-of-n threshold: returns CTHRESHOLD(k, sigma_1, ..., sigma_n)
        // AtLeast(bound, children) -> SigmaProp k-of-n threshold.
        (0x98, Payload::Two(bound_expr, children_expr)) => {
            opcodes::sigma::eval_at_least(bound_expr, children_expr, &mut cx)
        }

        // SigmaAnd (collection form) — short-circuit on TrivialFalse.
        (0xEA, Payload::SigmaCollection { items }) => {
            opcodes::sigma::eval_sigma_and_collection(items, &mut cx)
        }

        // SigmaOr (collection form) — short-circuit on TrivialTrue.
        (0xEB, Payload::SigmaCollection { items }) => {
            opcodes::sigma::eval_sigma_or_collection(items, &mut cx)
        }

        // EQ (==)
        (0x93, Payload::Two(left, right)) => opcodes::comparison::eval_eq(left, right, &mut cx),

        // AND (&&) — boolean reducer over Coll[Boolean] (not sigma)
        (0x96, Payload::One(inner)) => opcodes::boolean::eval_and_collection(inner, &mut cx),

        // OUTPUTS
        (0xA5, Payload::Zero) => opcodes::constants::eval_outputs(cost),

        // LastBlockUtxoRootHash — values.scala:1490-1502, Fixed(15).
        (0xA6, Payload::Zero) => opcodes::constants::eval_last_block_utxo_root_hash(ctx, cost),

        // MinerPubkey
        (0xAC, Payload::Zero) => opcodes::constants::eval_miner_pubkey(ctx, cost),

        // SizeOf(collection)
        (0xB1, Payload::One(inner)) => opcodes::collection::eval_size_of(inner, &mut cx),

        // ByIndex(collection, index, default?)
        (
            0xB2,
            Payload::ByIndex {
                input,
                index,
                default,
            },
        ) => opcodes::collection::eval_by_index(input, index, default.as_deref(), &mut cx),

        // ExtractScriptBytes(box).
        (0xC2, Payload::One(input)) => {
            opcodes::box_context::eval_extract_script_bytes(input, &mut cx)
        }

        // ExtractBytes(box) — full serialized box bytes.
        (0xC3, Payload::One(input)) => opcodes::box_context::eval_extract_bytes(input, &mut cx),

        // ExtractBytesWithNoRef(box) — candidate bytes (raw_bytes minus
        // 32-byte txId + VLQ-encoded output_index suffix).
        (0xC4, Payload::One(input)) => {
            opcodes::box_context::eval_extract_bytes_with_no_ref(input, &mut cx)
        }

        // SubstConstants(script_bytes, positions, new_values)
        // Generic: new_values can be Coll[SigmaProp], Coll[Coll[Byte]], Coll[GroupElement], etc.
        // SubstConstants(script_bytes, positions, new_values).
        (0x74, Payload::Three(script_expr, positions_expr, values_expr)) => {
            opcodes::sigma::eval_subst_constants(script_expr, positions_expr, values_expr, &mut cx)
        }

        // ConcreteCollection evaluation
        (_, Payload::ConcreteCollection { elem_type, items }) if node.opcode == 0x83 => {
            add_cost(cost, 0x83)?;
            match elem_type {
                SigmaType::SBoolean => {
                    let mut bools = Vec::with_capacity(items.len());
                    for item in items {
                        match eval_expr(item, ctx, constants, env, depth, cost, trace)? {
                            Value::Bool(b) => bools.push(b),
                            other => {
                                return Err(EvalError::TypeError {
                                    expected: "Bool",
                                    got: format!("{other:?}"),
                                })
                            }
                        }
                    }
                    Ok(Value::CollBool(bools))
                }
                SigmaType::SSigmaProp => {
                    let mut props = Vec::with_capacity(items.len());
                    for item in items {
                        match eval_expr(item, ctx, constants, env, depth, cost, trace)? {
                            Value::SigmaProp(sp) => props.push(sp),
                            other => {
                                return Err(EvalError::TypeError {
                                    expected: "SigmaProp",
                                    got: format!("{other:?}"),
                                })
                            }
                        }
                    }
                    Ok(Value::CollSigmaProp(props))
                }
                SigmaType::SByte => {
                    let mut bytes = Vec::with_capacity(items.len());
                    for item in items {
                        match eval_expr(item, ctx, constants, env, depth, cost, trace)? {
                            Value::Byte(v) => bytes.push(v as u8),
                            other => {
                                return Err(EvalError::TypeError {
                                    expected: "Byte in ConcreteCollection",
                                    got: format!("{other:?}"),
                                })
                            }
                        }
                    }
                    Ok(Value::CollBytes(bytes))
                }
                SigmaType::SShort => {
                    let mut shorts = Vec::with_capacity(items.len());
                    for item in items {
                        match eval_expr(item, ctx, constants, env, depth, cost, trace)? {
                            Value::Short(v) => shorts.push(v),
                            other => {
                                return Err(EvalError::TypeError {
                                    expected: "Short in ConcreteCollection",
                                    got: format!("{other:?}"),
                                })
                            }
                        }
                    }
                    Ok(Value::CollShort(shorts))
                }
                SigmaType::SInt => {
                    let mut ints = Vec::with_capacity(items.len());
                    for item in items {
                        match eval_expr(item, ctx, constants, env, depth, cost, trace)? {
                            Value::Int(v) => ints.push(v),
                            other => {
                                return Err(EvalError::TypeError {
                                    expected: "Int",
                                    got: format!("{other:?}"),
                                })
                            }
                        }
                    }
                    Ok(Value::CollInt(ints))
                }
                SigmaType::SLong => {
                    let mut longs = Vec::with_capacity(items.len());
                    for item in items {
                        match eval_expr(item, ctx, constants, env, depth, cost, trace)? {
                            Value::Long(v) => longs.push(v),
                            other => {
                                return Err(EvalError::TypeError {
                                    expected: "Long",
                                    got: format!("{other:?}"),
                                })
                            }
                        }
                    }
                    Ok(Value::CollLong(longs))
                }
                SigmaType::SBox => {
                    let mut boxes = Vec::with_capacity(items.len());
                    for item in items {
                        let v = eval_expr(item, ctx, constants, env, depth, cost, trace)?;
                        boxes.push(v);
                    }
                    Ok(Value::CollBox(boxes))
                }
                SigmaType::SGroupElement => {
                    // Boxed-element coll carrier (no typed Vec<GE>).
                    let mut vals = Vec::with_capacity(items.len());
                    for item in items {
                        vals.push(eval_expr(item, ctx, constants, env, depth, cost, trace)?);
                    }
                    Ok(Value::CollGeneric(vals, Box::new(SigmaType::SGroupElement)))
                }
                _ => {
                    // Boxed-element coll fallback (Coll[Tuple],
                    // Coll[Header], etc.). The `CollGeneric` carrier
                    // distinguishes Coll[X] from real `Value::Tuple`
                    // (STuple), so mutating methods like
                    // `Coll.updated` can accept the former and reject
                    // the latter. The IR-declared `elem_type` is
                    // tagged onto the carrier so empty results and
                    // serialize-back preserve the right `Coll[T]` T.
                    let mut vals = Vec::with_capacity(items.len());
                    for item in items {
                        vals.push(eval_expr(item, ctx, constants, env, depth, cost, trace)?);
                    }
                    Ok(Value::CollGeneric(vals, Box::new(elem_type.clone())))
                }
            }
        }

        // ProveDlog(group_element) — create sigma proposition from point.
        (0xCD, Payload::One(inner)) => opcodes::sigma::eval_prove_dlog(inner, &mut cx),

        // ProveDHTuple(g, h, u, v) — create DHT sigma proposition.
        (0xCE, Payload::Four(g_expr, h_expr, u_expr, v_expr)) => {
            opcodes::sigma::eval_prove_dh_tuple(g_expr, h_expr, u_expr, v_expr, &mut cx)
        }

        // VerifyStark(proofChunks, publicInputs, imageId, vmType, costParams)
        // — EIP-0045 native STARK verify. DEVNET-ONLY (byte 0xB9); a stock
        // node never reaches this arm. See opcodes::sigma::eval_verify_stark.
        (0xB9, Payload::Five(proof_chunks, public_inputs, image_id, vm_type, cost_params)) => {
            opcodes::sigma::eval_verify_stark(
                proof_chunks,
                public_inputs,
                image_id,
                vm_type,
                cost_params,
                &mut cx,
            )
        }

        // DecodePoint(bytes) — parse compressed point from first 33 bytes.
        (0xEE, Payload::One(inner)) => opcodes::sigma::eval_decode_point(inner, &mut cx),

        // Min
        (0xA1, Payload::Two(left, right)) => opcodes::arithmetic::eval_min(left, right, &mut cx),

        // Max
        (0xA2, Payload::Two(left, right)) => opcodes::arithmetic::eval_max(left, right, &mut cx),

        // Negation (unary minus)
        (0xF0, Payload::One(inner)) => opcodes::arithmetic::eval_negation(inner, &mut cx),

        // SigmaPropBytes — SigmaProp → ErgoTree-wrapped Coll[Byte].
        (0xD0, Payload::One(inner)) => opcodes::sigma::eval_sigma_prop_bytes(inner, &mut cx),

        // Tuple creation
        (0x86, Payload::Tuple { items }) => opcodes::binding::eval_tuple(items, &mut cx),

        // 0x87/0x88/0x89/0x8A/0x8B Select1-Select5: no dispatch arms.
        // Scala registers only SelectField (0x8C) at
        // ValueSerializer.scala:47; Select1-5 have no serializer
        // registration and the compiler always emits SelectField.
        // Tuple field access goes exclusively through the 0x8C
        // SelectField arm; the parser at ergo-ser/src/opcode.rs
        // rejects 0x87..=0x8B.

        // XorOf — XOR-reduce of a Coll[Boolean] -> Boolean. Scala
        // wires this opcode through `LogicalTransformerSerializer`
        // (one Coll[SBoolean] input), same shape as 0x96 And / 0x97 Or.
        (0xFF, Payload::One(input)) => opcodes::arithmetic::eval_xor_of(input, &mut cx),

        // OptionIsDefined — check if Option is Some.
        (0xE6, Payload::One(inner)) => opcodes::option::eval_option_is_defined(inner, &mut cx),

        // OptionGetOrElse — unwrap Option with default.
        (0xE5, Payload::Two(opt_expr, default_expr)) => {
            opcodes::option::eval_option_get_or_else(opt_expr, default_expr, &mut cx)
        }

        // 0xDF NoneValue: no dispatch arm. Scala does not register a
        // serializer for 0xDF at the dispatch position. `None: Option[T]`
        // values flow through the constant-encoding path (type-prefixed
        // SOption encoding at sigma_value.rs:149,513), reaching
        // sigma_to_value which lowers to Value::Opt(None).

        // CalcBlake2b256 — accepts Coll[Byte] and Coll[Int] (bytes widened by Map).
        (0xCB, Payload::One(inner)) => opcodes::sigma::eval_calc_blake2b256(inner, &mut cx),

        // CalcSha256 — accepts Coll[Byte] and Coll[Int].
        (0xCC, Payload::One(inner)) => opcodes::sigma::eval_calc_sha256(inner, &mut cx),

        // FuncValue — closure capturing the current environment.
        (0xD9, Payload::FuncValue { args, body }) => {
            opcodes::binding::eval_func_value(args, body, cx.env, cx.cost)
        }

        // FuncApply — closure invocation (charges AddToEnv per call).
        (
            0xDA,
            Payload::FuncApply {
                func,
                args: arg_exprs,
            },
        ) => opcodes::binding::eval_func_apply(func, arg_exprs, &mut cx),

        // ForAll(collection, predicate)
        (0xAF, Payload::Two(coll_expr, pred_expr)) => {
            opcodes::collection::eval_forall(coll_expr, pred_expr, &mut cx)
        }

        // Filter(collection, predicate)
        (0xB5, Payload::Two(coll_expr, pred_expr)) => {
            opcodes::collection::eval_filter(coll_expr, pred_expr, &mut cx)
        }

        // Fold(collection, zero, op) — left fold
        (0xB0, Payload::Three(coll_expr, zero_expr, op_expr)) => {
            opcodes::collection::eval_fold(coll_expr, zero_expr, op_expr, &mut cx)
        }

        // MapCollection(collection, mapper) — output type inferred from mapper.
        (0xAD, Payload::Two(coll_expr, mapper_expr)) => {
            opcodes::collection::eval_map_collection(coll_expr, mapper_expr, &mut cx)
        }

        // Exists(collection, predicate)
        (0xAE, Payload::Two(coll_expr, pred_expr)) => {
            opcodes::collection::eval_exists(coll_expr, pred_expr, &mut cx)
        }

        // Append(left, right) — concatenate two collections
        (0xB3, Payload::Two(left_expr, right_expr)) => {
            opcodes::collection::eval_append(left_expr, right_expr, &mut cx)
        }

        // Slice(collection, from, until)
        (0xB4, Payload::Three(coll_expr, from_expr, until_expr)) => {
            opcodes::collection::eval_slice(coll_expr, from_expr, until_expr, &mut cx)
        }

        // LongToByteArray
        (0x7A, Payload::One(inner)) => opcodes::arithmetic::eval_long_to_byte_array(inner, &mut cx),

        // ByteArrayToBigInt
        (0x7B, Payload::One(inner)) => {
            opcodes::arithmetic::eval_byte_array_to_big_int(inner, &mut cx)
        }

        // ByteArrayToLong
        (0x7C, Payload::One(inner)) => opcodes::arithmetic::eval_byte_array_to_long(inner, &mut cx),

        // Exponentiate: GroupElement ** BigInt — EC scalar multiplication.
        (0x9F, Payload::Two(left, right)) => {
            opcodes::sigma::eval_exponentiate(left, right, &mut cx)
        }

        // MultiplyGroup: GroupElement * GroupElement — EC point addition.
        (0xA0, Payload::Two(left, right)) => {
            opcodes::sigma::eval_multiply_group(left, right, &mut cx)
        }

        // BinXor — Boolean XOR (Fixed(20) cost, strict eager).
        (0xF4, Payload::Two(left, right)) => {
            opcodes::sigma::eval_bin_xor_bool(left, right, &mut cx)
        }

        // Xor (byte-array) — element-wise XOR over Coll[Byte], truncates to shorter.
        (0x9B, Payload::Two(left, right)) => opcodes::sigma::eval_xor(left, right, &mut cx),

        // Standalone ConcreteCollectionBooleanConstant. Scala `values.scala:844`
        // switches the companion from `ConcreteCollection` to this variant
        // when all items are boolean constants, affecting only the emitted
        // opcode byte (0x85 vs 0x83); `eval` is the same
        // `ConcreteCollection.eval` at values.scala:858, cost Fixed(20).
        // Our parser pre-decodes the packed bits into `Payload::BoolCollection`,
        // so the arm only has to wire the Vec<bool> to Value::CollBool.
        (0x85, Payload::BoolCollection { bits }) => {
            opcodes::constants::eval_bool_collection(bits, cost)
        }

        // Reject-only arms. Two cost disciplines preserved here:
        // charge-then-reject for the BitOp family (0xF2/F3/F5/F6/F7/F8),
        // zero-cost reject for the rest. See opcodes/errors.rs for
        // per-arm provenance docblocks.
        (0xB6, _) => opcodes::errors::eval_create_avl_tree(),
        (0xB7, _) => opcodes::errors::eval_tree_lookup(),
        (0xF2, _) => opcodes::errors::eval_bit_or(cost),
        (0xF3, _) => opcodes::errors::eval_bit_and(cost),
        (0xF5, _) => opcodes::errors::eval_bit_xor(cost),
        (0xF6, _) => opcodes::errors::eval_bit_shift_right(cost),
        (0xF7, _) => opcodes::errors::eval_bit_shift_left(cost),
        (0xF8, _) => opcodes::errors::eval_bit_shift_right_zeroed(cost),
        (0xCF, _) => opcodes::errors::eval_sigma_prop_is_proven(),

        // FunDef — standalone reject, same rule as ValDef above:
        // binding happens only inside the BlockValue item loop.
        (0xD7, _) => opcodes::errors::eval_fun_def_standalone(),
        (0xE7, _) => opcodes::errors::eval_mod_q_e7(),
        (0xE8, _) => opcodes::errors::eval_mod_q_e8(),
        (0xE9, _) => opcodes::errors::eval_mod_q_e9(),
        (0xF1, _) => opcodes::errors::eval_bit_inversion(),

        _ => Err(EvalError::UnsupportedOpcode(node.opcode)),
    }
}
