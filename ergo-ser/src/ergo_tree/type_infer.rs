//! The rule-1001 (`CheckDeserializedScriptIsSigmaProp`) static
//! type-inference subsystem: a faithful replica of Scala's parse-order
//! `valDefTypeStore` plus the root-type judgement mirrored from Scala's
//! deserialize-time `Value.tpe` derivation.
//! Oracle: scripts/jvm_serde_oracle/MethodTypes.scala
//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/deserialize-types.json.gz

use super::ErgoTree;

mod method_registry;

/// Root type for rule 1001 (`CheckDeserializedScriptIsSigmaProp`). The gate
/// treats unknown types leniently; embedded substitution requires an exact type.
pub(super) fn determinable_root_type(tree: &ErgoTree) -> Option<crate::sigma_type::SigmaType> {
    determinable_root_type_of(&tree.body, &tree.constants)
}

/// [`determinable_root_type`] over a raw `(body, constants)` pair — so the nested
/// `SBox`-constant inner-script path (which parses a body + constants without
/// building an [`ErgoTree`]) can run the same rule-1001 root-type judgement.
/// Entry point: the root is typed with an EMPTY [`ValDefTypeStore`].
/// `Some(SSigmaProp)` accepts, `Some(other)` is the wrap/reject verdict, and
/// `None` is lenient (the root type is not statically determinable). Public so
/// the `difftest --methodcall` harness can diff this exact verdict against the
/// JVM reference.
///
/// Segregated constants are parsed BEFORE the body on the same Scala reader, so
/// a constant that materializes a box value (whose nested `ErgoTree` is parsed
/// on that shared reader) can pre-populate Scala's `valDefTypeStore` with ids
/// we never see. Starting from an empty store is still exact-or-lenient: an id
/// the BODY binds overwrites any constant-table pollution before the body can
/// read it (the body's `ValDef` write is the last write, both here and in
/// Scala), and an id the body never binds misses our store and resolves `None`
/// (lenient — Scala reads the polluted type, or throws for a genuinely unbound
/// id; see [`infer_type`] on both residuals).
pub fn determinable_root_type_of(
    body: &crate::opcode::Expr,
    constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
) -> Option<crate::sigma_type::SigmaType> {
    let mut store = ValDefTypeStore::new();
    infer_type(body, &mut store, constants)
}

/// Exact static type for embedded-script substitution. Unlike the rule-1001
/// gate, substitution must not accept an unknown type or an imprecision sentinel.
pub fn substitution_type_of(body: &crate::opcode::Expr) -> Option<crate::sigma_type::SigmaType> {
    determinable_root_type_of(body, &[]).filter(type_is_precise)
}

/// The node-side replica of Scala's `ValDefTypeStore`
/// (`sigma/serialization/ValDefTypeStore.scala`): a single FLAT, never-scoped,
/// last-write-wins map from binding id to type, shared across the whole reader
/// and evolving in PARSE (serialization) order:
///
///  - `ValDefSerializer.parse` (ValDef 0xD6 / FunDef 0xD7) parses the `rhs`
///    FIRST (nested `ValUse`s read the store as it stands), THEN writes
///    `store(id) = rhs.tpe` — so a later `ValDef` of the same id overwrites.
///  - `FuncValueSerializer.parse` writes each argument's DECLARED type into the
///    store BEFORE parsing the body — and never pops it (the flat store has no
///    scoping), so lambda args survive past the lambda.
///  - `ValUseSerializer.parse` reads `store(id)` at its parse position:
///    whatever the most recent write before that point in the byte stream was.
///
/// [`infer_type`] therefore walks EVERY node in exact serialization order (not
/// just the type-determining spine): a rebind buried in an off-spine subtree
/// mutates the store a later spine `ValUse` reads. The stored value is
/// `Option<SigmaType>`: `Some(t)` when the writer's rhs/declared type is
/// statically determinable (then it is EXACT — every `Some` this typer
/// produces is oracle-verified to equal Scala's `Value.tpe`), `None` when it
/// is not (a `ValUse` of such an id stays lenient).
///
/// Worked examples (parse order = serialization order):
///  - `{ val x = 0L; val x = 0L; x }` → store\[x\]=SLong, store\[x\]=SLong,
///    `ValUse(x)`=SLong → root non-SigmaProp → REJECT (Scala rejects).
///  - `{ val x = sigmaProp; val y = x; val x = 0L; y }` → store\[x\]=SigmaProp;
///    `ValDef(y, ValUse(x))`: the rhs `ValUse(x)` reads SigmaProp so
///    store\[y\]=SigmaProp; then store\[x\]=SLong (rebind); the result
///    `ValUse(y)` reads SigmaProp → ACCEPT (Scala accepts — `y` was fixed
///    BEFORE the rebind; rejecting this shape would be a reject-valid = stall).
type ValDefTypeStore = std::collections::HashMap<u32, Option<crate::sigma_type::SigmaType>>;

/// `true` if `val` MATERIALIZES at least one box value (possibly nested in a
/// collection / option / tuple). A box value is the only constant whose bytes embed
/// a nested ErgoTree, which Scala parses on the shared reader — so only an actual
/// box can pollute `valDefTypeStore`. We key on the VALUE, not the type: an empty
/// `Coll[SBox]` has a box-bearing type but materializes no box and changes nothing,
/// so it must NOT trigger `ValUse` leniency (which would be an accept-invalid).
pub(super) fn value_contains_box(val: &crate::sigma_value::SigmaValue) -> bool {
    use crate::sigma_value::{CollValue, SigmaValue};
    match val {
        SigmaValue::OpaqueBoxBytes(_) => true,
        // `BoolBits` / `Bytes` collections never hold boxes; only `Values` can.
        SigmaValue::Coll(CollValue::Values(items)) | SigmaValue::Tuple(items) => {
            items.iter().any(value_contains_box)
        }
        SigmaValue::Opt(Some(inner)) => value_contains_box(inner),
        _ => false,
    }
}

/// Single-pass static-type inference over the ErgoTree IR — the rule-1001
/// (`CheckDeserializedScriptIsSigmaProp`) root typechecker, computing the same
/// `Value.tpe` Scala derives bottom-up at deserialize while threading the
/// [`ValDefTypeStore`] through EVERY node in exact serialization order (each
/// arm walks all of its children, in the order the wire serializer emits them,
/// before computing its own type — so the store at any `ValUse` matches
/// Scala's at that byte position). Returns the type when it is STATICALLY
/// DETERMINABLE, or `None` (treated as lenient/accept by the gate) — so an
/// as-yet-unhandled shape can never reject a tree Scala accepts. Each node is
/// visited exactly once, so the whole judgement is linear in the tree size (no
/// re-walking of MethodCall receiver chains — a parse-time CPU-DoS guard).
///
/// Two shapes are left lenient (`None`) as DOCUMENTED, oracle-probed residuals
/// outside this typer:
///
///  - A `ValUse` of an id with NO prior write. Scala's `store(id)` throws
///    `NoSuchElementException` at PARSE — not a `ValidationException`, so
///    `deserializeErgoTree` does not wrap it: a hard reject even under
///    `has_size`. That is a PARSE-layer verdict this rule-1001 typer cannot
///    express (`Some(non-sigma)` would wrap-accept a has_size tree Scala hard
///    rejects); the node's parser accepts an unbound `ValUse` (pre-existing),
///    so the typer stays lenient rather than mis-classify. (When a box
///    constant precedes the `ValUse`, lenient is also the CORRECT direction:
///    the box's nested script may have bound the id to any type.)
///  - A constant that MATERIALIZES a box value ([`value_contains_box`]).
///    Scala parses the box's nested ErgoTree on the SAME reader
///    (`ErgoTreeSerializer.deserializeErgoTree` saves `constantStore` /
///    `wasDeserialize` but NOT `valDefTypeStore`), so the nested script's
///    `ValDef`s — invisible to this walk — can rebind ANY id at the box's
///    parse position. Positionally exact handling: at the box constant, every
///    existing store entry becomes untrusted (`None`); a binding the outer
///    body re-establishes AFTER the box is trusted again (it overwrites the
///    pollution, last-write-wins — in Scala too).
fn infer_type(
    body: &crate::opcode::Expr,
    store: &mut ValDefTypeStore,
    constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
) -> Option<crate::sigma_type::SigmaType> {
    use crate::opcode::Payload;
    use crate::sigma_type::SigmaType;
    match body {
        crate::opcode::Expr::Const { tpe, val } => {
            if value_contains_box(val) {
                // Box pollution point: the nested script may have rebound any
                // id — every entry written so far is now untrusted. (An id it
                // may have FRESHLY bound stays absent here and resolves
                // lenient, which is the same safe direction.)
                for t in store.values_mut() {
                    *t = None;
                }
            }
            Some(tpe.clone())
        }
        crate::opcode::Expr::Op(node) => match &node.payload {
            Payload::ConstPlaceholder { index } => {
                constants.get(*index as usize).map(|(tpe, _)| tpe.clone())
            }
            // Payloads carrying their result type EXPLICITLY in the IR.
            // `Deserialize{Context,Register}[T]` return `T` DIRECTLY, so they CAN
            // be SigmaProp (accept iff T == SSigmaProp); `NumericCast`'s target is
            // always a numeric type (never SigmaProp). Returning the declared type
            // lets the gate accept/reject exactly as Scala does (oracle-verified:
            // `DeserializeRegister[SigmaProp]` accepts, `[SLong]` rejects).
            Payload::DeserializeContext { tpe, .. } => Some(tpe.clone()),
            Payload::DeserializeRegister { tpe, default, .. } => {
                // The inline default expression is parsed on the same reader
                // (after the register id + type), so its bindings evolve the
                // store even though the result type is the declared `T`.
                if let Some(d) = default.as_deref() {
                    infer_type(d, store, constants);
                }
                Some(tpe.clone())
            }
            Payload::NumericCast { input, tpe } => {
                infer_type(input, store, constants);
                Some(tpe.clone())
            }
            // `getVar[T]` / `box.RX[T]` statically return `Option[T]` — never
            // SigmaProp, even for T = SigmaProp (oracle-verified).
            Payload::GetVar { tpe, .. } => Some(SigmaType::SOption(Box::new(tpe.clone()))),
            Payload::ExtractRegisterAs { input, tpe, .. } => {
                infer_type(input, store, constants);
                Some(SigmaType::SOption(Box::new(tpe.clone())))
            }
            // Collection / tuple literals — `Coll[..]` / a tuple — are never
            // SigmaProp even when every element is SigmaProp (oracle-verified:
            // `Coll[SigmaProp]` and `(SigmaProp, SigmaProp)` both reject).
            Payload::ConcreteCollection { elem_type, items } => {
                for i in items {
                    infer_type(i, store, constants);
                }
                Some(SigmaType::SColl(Box::new(elem_type.clone())))
            }
            Payload::BoolCollection { .. } => Some(SigmaType::SColl(Box::new(SigmaType::SBoolean))),
            Payload::Tuple { items } => {
                let types: Vec<_> = items
                    .iter()
                    .map(|i| infer_type(i, store, constants))
                    .collect();
                types
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .map(SigmaType::STuple)
            }
            // ARG-DEPENDENT roots whose type is a PROJECTION of a child's type
            // (Scala computes these bottom-up at deserialize). Every child is
            // still walked (store evolution); only the projected child's type
            // is kept — a non-determinable child maps to `None` (lenient) and
            // this can NEVER reject a tree Scala accepts.
            //
            // ArithOp (Minus/Plus/Multiply/Division/Modulo/Min/Max): `tpe =
            // left.tpe` and Scala does NOT type-check the operands at deserialize,
            // so a SigmaProp LEFT operand makes the op SigmaProp (oracle-verified:
            // `Plus(sigma, x)` accepts, `Plus(Long, Long)` rejects).
            Payload::Two(left, right)
                if matches!(node.opcode, 0x99 | 0x9A | 0x9C | 0x9D | 0x9E | 0xA1 | 0xA2) =>
            {
                let t = infer_type(left, store, constants);
                infer_type(right, store, constants);
                t
            }
            // If: `If.tpe = trueBranch.tpe` (the then-branch, child 1; Scala does
            // NOT unify the branches at deserialize).
            Payload::Three(cond, then_branch, else_branch) if node.opcode == 0x95 => {
                infer_type(cond, store, constants);
                let t = infer_type(then_branch, store, constants);
                infer_type(else_branch, store, constants);
                t
            }
            // Fold: result = the accumulator type = the `zero` arg (child 1;
            // wire order input, zero, foldOp — FoldSerializer.scala).
            Payload::Three(coll, zero, fold_op) if node.opcode == 0xB0 => {
                infer_type(coll, store, constants);
                let t = infer_type(zero, store, constants);
                infer_type(fold_op, store, constants);
                t
            }
            // BlockValue `{ vals...; result }`: type = the result expression's
            // type. The items are walked first (in order) — each `ValDef` /
            // `FunDef` item writes the store from its own arm below.
            Payload::BlockValue { items, result } => {
                for item in items {
                    infer_type(item, store, constants);
                }
                infer_type(result, store, constants)
            }
            // ValDef 0xD6 / FunDef 0xD7 (`ValDefSerializer.parse`): the rhs is
            // parsed FIRST under the current store, then `store(id) = rhs.tpe`
            // (last-write-wins; a non-determinable rhs writes `None` so a
            // `ValUse` of it stays lenient — never a stale earlier type). The
            // node's own type is `rhs.tpe` (`ValDef.tpe`, values.scala:924) —
            // a `FunDef` rhs is NOT always a function (e.g. `fun x =
            // sigmaProp`), so deriving it from the rhs keeps a `ValUse` of a
            // SigmaProp-RHS binding accepting (oracle-verified).
            Payload::ValDef { id, rhs, .. } | Payload::FunDef { id, rhs, .. } => {
                let t = infer_type(rhs, store, constants);
                store.insert(*id, t.clone());
                t
            }
            // ValUse: `store(id)` at this parse position (see
            // [`ValDefTypeStore`]). An untrusted (`None`) entry or an id with
            // no prior write resolves lenient (see [`infer_type`] residuals).
            Payload::ValUse { id } => store.get(id).cloned().flatten(),
            // FuncValue writes declared arguments before its body, without popping
            // them. Its result is the full function type, including tuple ranges.
            Payload::FuncValue { args, body } => {
                for (id, tpe) in args {
                    store.insert(*id, tpe.clone());
                }
                let body_t = infer_type(body, store, constants);
                let dom: Option<Vec<SigmaType>> = args.iter().map(|(_, t)| t.clone()).collect();
                match (dom, body_t) {
                    (Some(t_dom), Some(t_range)) => Some(SigmaType::SFunc {
                        t_dom,
                        t_range: Box::new(t_range),
                        tpe_params: vec![],
                    }),
                    _ => None,
                }
            }
            // SelectField `tuple._i`: the i-th component type of the input tuple
            // (1-based). Only resolvable when the input's type is a determinable
            // `STuple` (e.g. a tuple constant); otherwise lenient.
            Payload::SelectField { input, field_idx } => {
                match infer_type(input, store, constants) {
                    Some(SigmaType::STuple(items)) => (*field_idx as usize)
                        .checked_sub(1)
                        .and_then(|i| items.get(i))
                        .cloned(),
                    _ => None,
                }
            }
            // ByIndex `coll(i)`: the element type of the input collection.
            Payload::ByIndex {
                input,
                index,
                default,
            } => {
                let t = infer_type(input, store, constants);
                infer_type(index, store, constants);
                if let Some(d) = default.as_deref() {
                    infer_type(d, store, constants);
                }
                match t {
                    Some(SigmaType::SColl(elem)) => Some(*elem),
                    _ => None,
                }
            }
            // OptionGet `opt.get` / OptionGetOrElse `opt.getOrElse(d)`: the option's
            // element type (the option is child 0 in both).
            Payload::One(opt) if node.opcode == 0xE4 => match infer_type(opt, store, constants) {
                Some(SigmaType::SOption(elem)) => Some(*elem),
                _ => None,
            },
            Payload::Two(opt, default) if node.opcode == 0xE5 => {
                let t = infer_type(opt, store, constants);
                infer_type(default, store, constants);
                match t {
                    Some(SigmaType::SOption(elem)) => Some(*elem),
                    _ => None,
                }
            }
            // MethodCall / PropertyCall: the receiver and value args are walked
            // first (wire order: obj, then args; the explicit type args carry
            // no expressions), then the method's result static type is
            // classified by the (type_id, method_id) registry the `difftest
            // --methodcall` harness verified end-to-end against the JVM
            // reference. See [`method_call_result_type`].
            Payload::MethodCall {
                type_id,
                method_id,
                obj,
                args,
                type_args,
            } => {
                let obj_type = infer_type(obj, store, constants);
                let arg_types: Vec<Option<SigmaType>> = args
                    .iter()
                    .map(|a| infer_type(a, store, constants))
                    .collect();
                method_call_result_type(*type_id, *method_id, obj_type, &arg_types, type_args)
            }
            // Apply projects a function range or collection element type (values.scala).
            Payload::FuncApply { func, args } => {
                let t = infer_type(func, store, constants);
                for a in args {
                    infer_type(a, store, constants);
                }
                match t {
                    Some(SigmaType::SFunc { t_range, .. }) => Some(*t_range),
                    Some(SigmaType::SColl(elem)) => Some(*elem),
                    _ => None,
                }
            }
            // Sigma conjunctions retain SigmaProp after visiting every child.
            Payload::SigmaCollection { items } => {
                for i in items {
                    infer_type(i, store, constants);
                }
                op_root_non_sigma_type(node.opcode)
            }
            // A zero-argument (leaf) opcode root has a statically-known type and
            // NONE of them is `SSigmaProp` (see [`zero_arg_root_type`]), so a
            // script rooted at one fails CheckDeserializedScriptIsSigmaProp just
            // like an inline non-SigmaProp `Const`.
            Payload::Zero => Some(zero_arg_root_type(node.opcode)),
            // Collection transforms preserve the input or project the mapper range.
            Payload::Two(input, mapper) if node.opcode == 0xAD => {
                infer_type(input, store, constants);
                match infer_type(mapper, store, constants) {
                    Some(SigmaType::SFunc { t_range, .. }) => Some(SigmaType::SColl(t_range)),
                    _ => None,
                }
            }
            Payload::Two(input, other)
                if matches!(node.opcode, 0xB3 | 0xB5 | 0xF2 | 0xF3 | 0xF5..=0xF8) =>
            {
                let t = infer_type(input, store, constants);
                infer_type(other, store, constants);
                t
            }
            Payload::Three(input, from, until) if node.opcode == 0xB4 => {
                let t = infer_type(input, store, constants);
                infer_type(from, store, constants);
                infer_type(until, store, constants);
                t
            }
            Payload::One(input) if matches!(node.opcode, 0xF0 | 0xF1) => {
                infer_type(input, store, constants)
            }
            // Fixed-result operators still visit all children in wire order.
            Payload::One(a) => {
                infer_type(a, store, constants);
                op_root_non_sigma_type(node.opcode)
            }
            Payload::Two(a, b) => {
                infer_type(a, store, constants);
                infer_type(b, store, constants);
                op_root_non_sigma_type(node.opcode)
            }
            Payload::Three(a, b, c) => {
                infer_type(a, store, constants);
                infer_type(b, store, constants);
                infer_type(c, store, constants);
                op_root_non_sigma_type(node.opcode)
            }
            Payload::Four(a, b, c, d) => {
                infer_type(a, store, constants);
                infer_type(b, store, constants);
                infer_type(c, store, constants);
                infer_type(d, store, constants);
                op_root_non_sigma_type(node.opcode)
            }
            // TaggedVar has no type in the serialized payload; NoneValue has
            // no registered Scala serializer. Neither supplies a substitution type.
            Payload::TaggedVar { .. } | Payload::NoneValue { .. } => {
                op_root_non_sigma_type(node.opcode)
            }
        },
        crate::opcode::Expr::Unparsed(_) => None,
    }
}

/// Substitution requires a concrete type without unknown/Any components.
fn type_is_precise(t: &crate::sigma_type::SigmaType) -> bool {
    use crate::sigma_type::SigmaType;
    match t {
        SigmaType::SAny => false,
        SigmaType::SColl(e) | SigmaType::SOption(e) => type_is_precise(e),
        SigmaType::STuple(items) => items.iter().all(type_is_precise),
        SigmaType::SFunc {
            t_dom,
            t_range,
            tpe_params,
        } => {
            t_dom.iter().all(type_is_precise)
                && type_is_precise(t_range)
                && tpe_params.iter().all(type_is_precise)
        }
        _ => true,
    }
}

/// Specialize the JVM-extracted signature using Scala's directional unification.
/// A failed unification leaves the template unchanged (SMethod.specializeFor).
fn method_call_result_type(
    type_id: u8,
    method_id: u8,
    obj_type: Option<crate::sigma_type::SigmaType>,
    arg_types: &[Option<crate::sigma_type::SigmaType>],
    type_args: &[crate::sigma_type::SigmaType],
) -> Option<crate::sigma_type::SigmaType> {
    use crate::sigma_type::SigmaType;
    let (signature, explicit) = method_registry::signature(type_id, method_id)?;
    let mut subst = std::collections::HashMap::new();
    for (param, arg) in explicit.iter().zip(type_args) {
        if let SigmaType::STypeVar(name) = param {
            subst.insert(name.clone(), arg.clone());
        }
    }
    let signature = apply_type_subst(&signature, &subst);
    let SigmaType::SFunc { t_dom, t_range, .. } = signature else {
        return None;
    };
    let actual: Option<Vec<_>> = std::iter::once(obj_type)
        .chain(arg_types.iter().cloned())
        .collect();
    let actual = actual?;
    subst.clear();
    if unify_type_lists(&t_dom, &actual, &mut subst) {
        Some(apply_type_subst(&t_range, &subst))
    } else {
        Some(*t_range)
    }
}

type TypeSubst = std::collections::HashMap<String, crate::sigma_type::SigmaType>;

fn apply_type_subst(
    t: &crate::sigma_type::SigmaType,
    subst: &TypeSubst,
) -> crate::sigma_type::SigmaType {
    use crate::sigma_type::SigmaType::*;
    match t {
        STypeVar(name) => subst.get(name).cloned().unwrap_or_else(|| t.clone()),
        SColl(e) => SColl(Box::new(apply_type_subst(e, subst))),
        SOption(e) => SOption(Box::new(apply_type_subst(e, subst))),
        STuple(items) => STuple(items.iter().map(|t| apply_type_subst(t, subst)).collect()),
        SFunc {
            t_dom,
            t_range,
            tpe_params,
        } => SFunc {
            t_dom: t_dom.iter().map(|t| apply_type_subst(t, subst)).collect(),
            t_range: Box::new(apply_type_subst(t_range, subst)),
            tpe_params: tpe_params
                .iter()
                .filter(|t| !matches!(t, STypeVar(n) if subst.contains_key(n)))
                .cloned()
                .collect(),
        },
        _ => t.clone(),
    }
}

/// Scala zips domains without an arity check; nested tuples/functions check lengths.
fn unify_type_lists(
    a: &[crate::sigma_type::SigmaType],
    b: &[crate::sigma_type::SigmaType],
    subst: &mut TypeSubst,
) -> bool {
    a.iter().zip(b).all(|(a, b)| unify_types(a, b, subst))
}

fn unify_types(
    a: &crate::sigma_type::SigmaType,
    b: &crate::sigma_type::SigmaType,
    subst: &mut TypeSubst,
) -> bool {
    use crate::sigma_type::SigmaType::*;
    match (a, b) {
        (STypeVar(a), STypeVar(b)) => a == b,
        (STypeVar(name), t) => match subst.get(name) {
            Some(previous) => previous == t,
            None => {
                subst.insert(name.clone(), t.clone());
                true
            }
        },
        (SColl(a), SColl(b)) | (SOption(a), SOption(b)) => unify_types(a, b, subst),
        (SColl(a), STuple(_)) => unify_types(a, &SAny, subst),
        (STuple(a), STuple(b)) => a.len() == b.len() && unify_type_lists(a, b, subst),
        (
            SFunc {
                t_dom: a,
                t_range: ar,
                ..
            },
            SFunc {
                t_dom: b,
                t_range: br,
                ..
            },
        ) => a.len() == b.len() && unify_type_lists(a, b, subst) && unify_types(ar, br, subst),
        (SBoolean, SSigmaProp) | (SAny, _) => true,
        _ => a == b,
    }
}

/// Fixed-result opcode types from the pinned Scala AST declarations.
fn op_root_non_sigma_type(opcode: u8) -> Option<crate::sigma_type::SigmaType> {
    if matches!(opcode, 0x98 | 0xCD | 0xCE | 0xD1 | 0xEA | 0xEB) {
        return Some(crate::sigma_type::SigmaType::SSigmaProp);
    }
    use crate::sigma_type::SigmaType::*;
    match opcode {
        0x8F..=0x94
        | 0x96
        | 0x97
        | 0xAE
        | 0xAF
        | 0xCF
        | 0xE6
        | 0xEC
        | 0xED
        | 0xEF
        | 0xF4
        | 0xFF => Some(SBoolean),
        0xB1 => Some(SInt),
        0x7C | 0xC1 => Some(SLong),
        0x7B | 0xE7..=0xE9 => Some(SBigInt),
        0x9F | 0xA0 | 0xEE => Some(SGroupElement),
        0x74 | 0x7A | 0x9B | 0xC2..=0xC5 | 0xCB | 0xCC | 0xD0 => Some(SColl(Box::new(SByte))),
        0xC7 => Some(STuple(vec![SInt, SColl(Box::new(SByte))])),
        0xB7 => Some(SOption(Box::new(SColl(Box::new(SByte))))),
        _ => None,
    }
}

/// Statically-known result type of a zero-argument (leaf) ErgoTree opcode. EVERY
/// leaf in the parser's table is non-`SSigmaProp`: `True`/`False` → `SBoolean`,
/// `GroupGenerator` → `SGroupElement`, `Height` → `SInt`, `Inputs`/`Outputs` →
/// `Coll[SBox]`, `LastBlockUtxoRootHash` → `SAvlTree`, `Self` → `SBox`,
/// `MinerPubkey` → `Coll[SByte]`, `Global` → `SGlobal`, `Context` → `SContext`.
/// (A `SigmaProp`-producing op — `ProveDlog`, `BoolToSigmaProp`, `SigmaAnd`, … —
/// always takes arguments, so it is never a `Zero` leaf.) An unrecognized leaf
/// falls back to `SAny`, still `!= SSigmaProp`, so the rule-1001 gate rejects it.
fn zero_arg_root_type(opcode: u8) -> crate::sigma_type::SigmaType {
    use crate::sigma_type::SigmaType::*;
    match opcode {
        0x7F | 0x80 => SBoolean,              // True / False
        0x82 => SGroupElement,                // GroupGenerator
        0xA3 => SInt,                         // Height
        0xA4 | 0xA5 => SColl(Box::new(SBox)), // Inputs / Outputs
        0xA6 | 0xB6 => SAvlTree,              // LastBlockUtxoRootHash
        0xA7 => SBox,                         // Self
        0xAC => SColl(Box::new(SByte)),       // MinerPubkey
        0xDD => SGlobal,                      // Global
        0xFE => SContext,                     // Context
        _ => SAny,                            // deprecated/unknown leaf — still non-SigmaProp
    }
}

#[cfg(test)]
mod tests {
    //! Focused unit tests for the parse-order `valDefTypeStore` replica: the
    //! duplicate-binding-id accept/reject boundary (Finding E). Every verdict
    //! below is pinned by the live-oracle probe set in
    //! `ergo-difftest/src/oracle.rs`
    //! (`valdef_type_store_shapes_match_jvm_oracle`).

    use super::determinable_root_type_of;
    use crate::opcode::{Expr, IrNode, Payload};
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{SigmaBoolean, SigmaValue};

    // ----- helpers -----

    fn op(opcode: u8, payload: Payload) -> Expr {
        Expr::Op(IrNode { opcode, payload })
    }
    fn long0() -> Expr {
        Expr::Const {
            tpe: SigmaType::SLong,
            val: SigmaValue::Long(0),
        }
    }
    fn sigma_const() -> Expr {
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        }
    }
    fn box_const() -> Expr {
        Expr::Const {
            tpe: SigmaType::SBox,
            val: SigmaValue::OpaqueBoxBytes(vec![]),
        }
    }
    fn val_def(id: u32, rhs: Expr) -> Expr {
        op(
            0xD6,
            Payload::ValDef {
                id,
                tpe: None,
                rhs: Box::new(rhs),
            },
        )
    }
    fn fun_def(id: u32, rhs: Expr) -> Expr {
        op(
            0xD7,
            Payload::FunDef {
                id,
                tpe: None,
                tpe_args: vec![SigmaType::STypeVar("T".into())],
                rhs: Box::new(rhs),
            },
        )
    }
    fn val_use(id: u32) -> Expr {
        op(0x72, Payload::ValUse { id })
    }
    fn block(items: Vec<Expr>, result: Expr) -> Expr {
        op(
            0xD8,
            Payload::BlockValue {
                items,
                result: Box::new(result),
            },
        )
    }
    fn func_value(args: Vec<(u32, Option<SigmaType>)>, body: Expr) -> Expr {
        op(
            0xD9,
            Payload::FuncValue {
                args,
                body: Box::new(body),
            },
        )
    }
    fn root(body: &Expr) -> Option<SigmaType> {
        determinable_root_type_of(body, &[])
    }

    // ----- oracle parity -----

    /// `{ val x = 0L; val x = 0L; x }`
    /// resolves the root `ValUse` from the last store write (SLong) → the gate
    /// rejects, as Scala does. And last-write-wins in the ACCEPT direction:
    /// `{ val x = 0L; val x = sigma; x }` is SigmaProp (a first-write-wins bug
    /// would reject-valid it).
    #[test]
    fn duplicate_id_valuse_resolves_to_last_parse_order_write() {
        let dup = block(vec![val_def(1, long0()), val_def(1, long0())], val_use(1));
        assert_eq!(root(&dup), Some(SigmaType::SLong));

        let last_sigma = block(
            vec![val_def(1, long0()), val_def(1, sigma_const())],
            val_use(1),
        );
        assert_eq!(root(&last_sigma), Some(SigmaType::SSigmaProp));
    }

    /// THE GUARDRAIL (a reject here = reject-valid = chain stall):
    /// `{ val x = sigma; val y = x; val x = 0L; y }` MUST classify SigmaProp —
    /// `y`'s rhs `ValUse(x)` reads the store BEFORE the rebind, exactly as
    /// Scala's `ValDefSerializer.parse` does (oracle ACCEPT).
    #[test]
    fn guardrail_forward_reference_fixed_before_rebind_stays_sigma() {
        let guardrail = block(
            vec![
                val_def(1, sigma_const()),
                val_def(2, val_use(1)),
                val_def(1, long0()),
            ],
            val_use(2),
        );
        assert_eq!(root(&guardrail), Some(SigmaType::SSigmaProp));
    }

    /// Off-spine and scope-boundary rebinds all reach the flat store in parse
    /// order (oracle REJECT for each — the node was lenient-ACCEPT pre-fix):
    /// a rebind nested in a later item's rhs; a `FuncValue` ARG declaration; a
    /// rebind inside a `FuncValue` BODY (no scoping/popping); a `FunDef` write.
    #[test]
    fn off_spine_and_boundary_rebinds_reach_the_store() {
        // { val x = sigma; val d = { val x = 0L; 0L }; x } -> SLong.
        let offspine = block(
            vec![
                val_def(1, sigma_const()),
                val_def(2, block(vec![val_def(1, long0())], long0())),
            ],
            val_use(1),
        );
        assert_eq!(root(&offspine), Some(SigmaType::SLong));

        // { val x = sigma; val f = (id1: Long) => 0L; x } -> the lambda ARG
        // rebinds x to its declared SLong.
        let arg_rebind = block(
            vec![
                val_def(1, sigma_const()),
                val_def(2, func_value(vec![(1, Some(SigmaType::SLong))], long0())),
            ],
            val_use(1),
        );
        assert_eq!(root(&arg_rebind), Some(SigmaType::SLong));

        // { val x = sigma; val f = (id3: Long) => { val x = 0L; 0L }; x } ->
        // the ValDef inside the lambda body rebinds x (flat store, never popped).
        let body_rebind = block(
            vec![
                val_def(1, sigma_const()),
                val_def(
                    2,
                    func_value(
                        vec![(3, Some(SigmaType::SLong))],
                        block(vec![val_def(1, long0())], long0()),
                    ),
                ),
            ],
            val_use(1),
        );
        assert_eq!(root(&body_rebind), Some(SigmaType::SLong));

        // { fun f[T] = sigma; val f = 0L; f } -> FunDef writes like ValDef;
        // the later ValDef wins.
        let fundef_rebind = block(
            vec![fun_def(1, sigma_const()), val_def(1, long0())],
            val_use(1),
        );
        assert_eq!(root(&fundef_rebind), Some(SigmaType::SLong));

        // Lambda args SURVIVE the lambda (never popped): a root ValUse of a
        // lambda arg id reads its declared type.
        let arg_survives = block(
            vec![val_def(
                2,
                func_value(vec![(5, Some(SigmaType::SLong))], long0()),
            )],
            val_use(5),
        );
        assert_eq!(root(&arg_survives), Some(SigmaType::SLong));
    }

    /// Leniency boundaries that MUST stay lenient (`None` = accept):
    /// a `ValUse` with no prior write (Scala throws at parse — a parse-layer
    /// verdict this typer cannot express, documented residual), and a dup-id
    /// tree whose root does not resolve through the store at all is still
    /// classified.
    #[test]
    fn unbound_valuse_is_lenient_and_independent_root_still_classified() {
        assert_eq!(root(&block(vec![], val_use(1))), None);
        // Use-before-def inside the same block: the write happens AFTER the
        // use in parse order, so the use sees nothing (Scala throws).
        let use_before_def = block(
            vec![val_def(2, val_use(1)), val_def(1, long0())],
            val_use(2),
        );
        assert_eq!(root(&use_before_def), None);
        // Root independent of the reused id -> still classified.
        let independent = block(
            vec![val_def(1, long0()), val_def(1, long0())],
            sigma_const(),
        );
        assert_eq!(root(&independent), Some(SigmaType::SSigmaProp));
    }

    /// Box-constant pollution is POSITIONAL: a box value's nested script parses
    /// on Scala's shared reader at the constant's position, so entries written
    /// BEFORE it become untrusted (lenient), while a binding (re)established
    /// AFTER it is trusted again (it overwrites any pollution, last-write-wins
    /// — in Scala too). A segregated box constant parses before the whole body,
    /// so a body-bound id stays trusted.
    #[test]
    fn box_constant_pollution_is_positional() {
        // { val x = sigma; val b = box; x } -> x's entry predates the box -> lenient.
        let poisoned = block(
            vec![val_def(1, sigma_const()), val_def(2, box_const())],
            val_use(1),
        );
        assert_eq!(root(&poisoned), None);

        // { val b = box; val x = sigma; x } -> x bound after the box -> trusted.
        let rebound = block(
            vec![val_def(2, box_const()), val_def(1, sigma_const())],
            val_use(1),
        );
        assert_eq!(root(&rebound), Some(SigmaType::SSigmaProp));

        // Segregated box constant + `{ val x = 0L; x }`: the constant table is
        // parsed BEFORE the body, so the body's ValDef overwrites any pollution
        // -> the SLong root is trusted (REJECT, as Scala: its last write to x
        // is also the body's).
        let body = block(vec![val_def(1, long0())], val_use(1));
        let constants = vec![(SigmaType::SBox, SigmaValue::OpaqueBoxBytes(vec![]))];
        assert_eq!(
            determinable_root_type_of(&body, &constants),
            Some(SigmaType::SLong)
        );
    }

    /// A bare `ValDef`/`FunDef` node types as its rhs (`ValDef.tpe = rhs.tpe`,
    /// values.scala:924) — a Long rhs is non-SigmaProp (reject), a sigma rhs is
    /// SigmaProp (accept).
    #[test]
    fn bare_valdef_root_types_as_its_rhs() {
        assert_eq!(root(&val_def(1, long0())), Some(SigmaType::SLong));
        assert_eq!(
            root(&val_def(1, sigma_const())),
            Some(SigmaType::SSigmaProp)
        );
        assert_eq!(root(&fun_def(1, long0())), Some(SigmaType::SLong));
    }

    /// A `FuncValue` types as `SFunc(declared args, body.tpe)` when the body is
    /// determinable, returning `None` otherwise — never SigmaProp
    /// either way (a FuncValue root always rejects).
    #[test]
    fn func_value_types_as_sfunc_when_precise() {
        let lambda = func_value(vec![(1, Some(SigmaType::SLong))], long0());
        assert_eq!(
            root(&lambda),
            Some(SigmaType::SFunc {
                t_dom: vec![SigmaType::SLong],
                t_range: Box::new(SigmaType::SLong),
                tpe_params: vec![],
            })
        );
        // Tuple component types remain precise inside a function range.
        let tuple_range = func_value(
            vec![(1, Some(SigmaType::SLong))],
            op(
                0x86,
                Payload::Tuple {
                    items: vec![long0(), long0()],
                },
            ),
        );
        assert_eq!(
            root(&tuple_range),
            Some(SigmaType::SFunc {
                t_dom: vec![SigmaType::SLong],
                t_range: Box::new(SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong])),
                tpe_params: vec![],
            })
        );
    }
}
