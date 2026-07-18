//! The rule-1001 (`CheckDeserializedScriptIsSigmaProp`) static
//! type-inference subsystem: a faithful replica of Scala's parse-order
//! `valDefTypeStore` plus the root-type judgement mirrored from Scala's
//! deserialize-time `Value.tpe` derivation.

use super::ErgoTree;

/// The deserialized root's static type WHEN it is trivially determinable from
/// the parsed IR: an inline `Const` carries its own type, a `ConstPlaceholder`
/// resolves to its segregated constant's type (Scala
/// `ConstantPlaceholderSerializer.parse` gives the placeholder the constant's
/// `tpe`), and the boolean-literal leaves `TrueLeaf`/`FalseLeaf` are
/// unconditionally `SBoolean`. Scala's `CheckDeserializedScriptIsSigmaProp`
/// rejects (→ soft-fork wrap under `has_size`, hard reject when sizeless) any
/// root whose type is not `SSigmaProp`. For every other `Op` root shape we have
/// no typechecker and accept — a genuinely non-sigma operator root would fail
/// later at evaluation. Returns `None` when the root type is not statically
/// known here (including an out-of-range placeholder index, which we leave to
/// the existing lenient handling).
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
                for i in items {
                    infer_type(i, store, constants);
                }
                Some(SigmaType::SAny)
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
            // FuncValue (`FuncValueSerializer.parse`): each arg's DECLARED
            // type is written to the store BEFORE the body is parsed — and
            // never popped. Scala `FuncValue.tpe = SFunc(args.map(_.tpe),
            // body.tpe)` — never SigmaProp, so a FuncValue root always fails
            // rule 1001 (oracle-verified). The `SFunc` is built only when the
            // body type is PRECISE ([`type_is_precise`]): `SAny` inside a
            // computed type is this typer's imprecision sentinel, and
            // embedding it would later compare as a real type in [`agree`] (a
            // false `specializeFor` mismatch = a reject-valid). An imprecise
            // body degrades the whole function to the top-level `SAny`
            // sentinel (still non-SigmaProp; `Unknown` to [`agree`]). The
            // declared arg types are wire-exact and kept as-is.
            Payload::FuncValue { args, body } => {
                for (id, tpe) in args {
                    store.insert(*id, tpe.clone());
                }
                let body_t = infer_type(body, store, constants);
                let dom: Option<Vec<SigmaType>> = args.iter().map(|(_, t)| t.clone()).collect();
                match (dom, body_t) {
                    (Some(t_dom), Some(t_range)) if type_is_precise(&t_range) => {
                        Some(SigmaType::SFunc {
                            t_dom,
                            t_range: Box::new(t_range),
                            tpe_params: vec![],
                        })
                    }
                    _ => Some(SigmaType::SAny),
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
                method_call_result_type(*type_id, *method_id, obj_type, &arg_types, args, type_args)
            }
            // Apply's result is the callee's range; kept lenient (as before the
            // store rework) — the children are still walked for their bindings.
            Payload::FuncApply { func, args } => {
                infer_type(func, store, constants);
                for a in args {
                    infer_type(a, store, constants);
                }
                None
            }
            // SigmaAnd / SigmaOr (0xEA / 0xEB) ARE SigmaProp — lenient `None`
            // is the same accept verdict at the root, and a `None` store entry
            // for a sigma-collection rhs can only turn "accept" into "accept"
            // (only a determinable non-SigmaProp type rejects).
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
            // Generic operator payloads: walk every child (store evolution),
            // then classify by opcode — relations, arithmetic, etc. whose
            // result is unconditionally non-SigmaProp get `Some(SAny)`;
            // SigmaProp-capable opcodes stay lenient (`None`).
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
            // Childless payloads with no statically-tracked type here:
            // `TaggedVar` (0x71, type-tag dependent) and `NoneValue` (0xDF,
            // not parser-reachable) — both resolve through the opcode
            // classifier to `None` (lenient).
            Payload::TaggedVar { .. } | Payload::NoneValue { .. } => {
                op_root_non_sigma_type(node.opcode)
            }
        },
        crate::opcode::Expr::Unparsed(_) => None,
    }
}

/// `true` when a computed type is PRECISE — i.e. contains no `SAny`, which this
/// typer also uses as its "non-`SigmaProp`, but exact type not tracked"
/// sentinel (a non-landmine `MethodCall`, a `Tuple` literal, a non-SigmaProp
/// operator, an unknown leaf, …). A sentinel is only safe at the TOP level of a
/// type (where [`agree`] maps it to `Unknown`); embedding one inside a
/// constructed type (the `FuncValue` → `SFunc` range) would let it structurally
/// compare against a real type and manufacture a false mismatch (a
/// reject-valid). A REAL wire `SAny` degraded by this check only widens
/// leniency — the safe direction.
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

/// The result static type of a `MethodCall` / `PropertyCall`, for the rule-1001
/// root judgement, from the ALREADY-INFERRED receiver/arg types (the caller's
/// single-pass walk computes each exactly once, in wire order). Scala computes
/// `MethodCall.tpe` as the SMethod's result type specialized for the
/// receiver/arg types; the only methods whose specialized result can be
/// `SigmaProp` are the 7 the `difftest --methodcall` harness verified
/// END-TO-END against the JVM reference (every other of the 199 registered methods
/// returns a concrete type or an `Option`/`Coll`/tuple wrapper — structurally never
/// `SigmaProp`). Each of the 7 is a projection of the receiver / args / explicit
/// type, exactly mirroring the `ByIndex` / `OptionGet` / `Fold` / `Deserialize`
/// arms of [`infer_type`]. A result type VARIABLE that occurs more than once
/// (`getOrElse`'s receiver + default, `fold`'s zero + op range) is reconciled with
/// [`agree`] — Scala `unifyTypeLists` makes the result `SigmaProp` only
/// when ALL occurrences are, so checking just one would accept a tree Scala rejects.
///
/// (A determinable occurrence MISMATCH actually makes Scala THROW at deserialize —
/// `specializeFor`'s `IllegalArgumentException` — which our structural parser does
/// not replicate at parse time. The rule-1001 verdict still matches where it is
/// enforced: this returns `SAny` (non-`SigmaProp`), so a SIZELESS conflict root is
/// rejected as Scala rejects it. A has_size conflict tree is soft-fork-wrapped here
/// vs hard-rejected by Scala — a pre-existing parse-layer accept-invalid, the safe
/// direction, outside this rule-1001 root typer.)
///
/// Reject-valid-safe by construction:
///  - a non-determinable projection returns `None` (lenient), so a SigmaProp-capable
///    method whose receiver type we cannot pin never gets rejected;
///  - every OTHER `(type_id, method_id)` returns `SAny` (non-`SigmaProp`). For the
///    192 known non-landmine methods this is the harness's verified result; an
///    UNKNOWN method is rejected by Scala at method resolution (so a non-`SigmaProp`
///    root verdict matches). The landmine set MUST stay complete — adding a method
///    here that can return `SigmaProp` without listing it would be a reject-valid.
fn method_call_result_type(
    type_id: u8,
    method_id: u8,
    obj_type: Option<crate::sigma_type::SigmaType>,
    arg_types: &[Option<crate::sigma_type::SigmaType>],
    args: &[crate::opcode::Expr],
    type_args: &[crate::sigma_type::SigmaType],
) -> Option<crate::sigma_type::SigmaType> {
    use crate::sigma_type::SigmaType;
    let arg_ty = |i: usize| arg_types.get(i).cloned().flatten();
    // The receiver's Coll / Option element type (the result type variable `IV`/`T`).
    let coll_elem = || match &obj_type {
        Some(SigmaType::SColl(elem)) => Some((**elem).clone()),
        _ => None,
    };
    let opt_elem = || match &obj_type {
        Some(SigmaType::SOption(elem)) => Some((**elem).clone()),
        _ => None,
    };
    // Each landmine's result is the receiver/explicit projection, GATED on every
    // signature constraint Scala's `specializeFor` (`unifyTypeLists`) enforces: a
    // FIXED-type arg must equal its signature type, and every additional occurrence
    // of the result type variable must agree with the receiver/zero. A determinable
    // violation leaves the variable unbound -> non-`SigmaProp` (`SAny`, reject); an
    // undeterminable one -> `None` (lenient). See [`gated`] / [`agree`].
    let int = Some(SigmaType::SInt);
    match (type_id, method_id) {
        // Coll.apply(index: SInt): IV. `IV` is only in the receiver, but the index
        // must be SInt (else specializeFor fails and IV stays unbound).
        (12, 10) => gated(coll_elem(), &[agree(arg_ty(0), int)]),
        // Coll.getOrElse(index: SInt, default: IV): IV. index = SInt; default = IV.
        (12, 2) => {
            let elem = coll_elem();
            gated(
                elem.clone(),
                &[agree(arg_ty(0), int), agree(elem, arg_ty(1))],
            )
        }
        // Coll.fold(zero: OV, op: (OV, IV) => OV): OV. OV = zero = op arg0 = op range;
        // IV (receiver elem) = op arg1. The op's declared arg types come from the
        // syntactic `FuncValue` payload (wire-exact); its RANGE from the op's
        // inferred `SFunc` type (precise by construction, and also available
        // when the op is a `ValUse` of a stored lambda).
        (12, 5) => {
            let zero = arg_ty(0);
            let (op_a0, op_a1) = args.get(1).map_or((None, None), func_value_arg_types);
            let op_range = match arg_ty(1) {
                Some(SigmaType::SFunc { t_range, .. }) => Some(*t_range),
                _ => None,
            };
            gated(
                zero.clone(),
                &[
                    agree(zero.clone(), op_range),
                    agree(zero, op_a0),
                    agree(coll_elem(), op_a1),
                ],
            )
        }
        // Option.get: the receiver Option's element type (`T` only in the receiver).
        (36, 3) => opt_elem(),
        // Option.getOrElse(default: T): T. T = receiver elem = default.
        (36, 4) => {
            let elem = opt_elem();
            gated(elem.clone(), &[agree(elem, arg_ty(0))])
        }
        // Global.deserializeTo[T] / fromBigEndianBytes[T]: the explicit type arg `T`.
        // Scala applies the EXPLICIT type subst (T -> ...) to the method BEFORE
        // `specializeFor`, and `specializeFor` returns that already-substituted method
        // even when `unifyTypeLists` fails — so the result is `T` REGARDLESS of the
        // receiver or the `Coll[Byte]` value arg. Oracle-verified: a has_size
        // `deserializeTo[SigmaProp]` on a `Global`, a `Box`(SELF), or with an `Int`
        // value arg ALL classify SIGMA. Hence no receiver/arg gating here.
        (106, 4) | (106, 5) => type_args.first().cloned(),
        // Every other method (and any unknown one) is non-SigmaProp.
        _ => Some(SigmaType::SAny),
    }
}

/// Three-state result of comparing two inferred types for `specializeFor`
/// unification: `Some(Match)` they are equal, `Some(Mismatch)` a determinable
/// conflict (Scala fails to unify), `None`-side -> `Unknown` (non-determinable).
#[derive(PartialEq)]
enum Unify {
    Match,
    Mismatch,
    Unknown,
}

/// Compare two occurrences of a unified type (or an arg against its fixed signature
/// type, passed as `b`): equal -> `Match`, both PRECISELY determinable but different
/// -> `Mismatch`, otherwise `Unknown`. `SAny` is the typer's "non-`SigmaProp`, but
/// precise type not tracked" sentinel (returned for a non-landmine `MethodCall`, a
/// `Tuple`, a non-`SigmaProp` operator, …), NOT a literal `SAny` — so it is treated
/// as `Unknown`, never a `Mismatch`. Reporting `Mismatch` for it would reject a tree
/// Scala accepts, e.g. `Coll[SigmaProp].apply(coll.size)` whose `SInt` index the
/// sentinel hides (a reject-valid).
fn agree(
    a: Option<crate::sigma_type::SigmaType>,
    b: Option<crate::sigma_type::SigmaType>,
) -> Unify {
    use crate::sigma_type::SigmaType::SAny;
    match (a, b) {
        (Some(SAny), _) | (_, Some(SAny)) | (None, _) | (_, None) => Unify::Unknown,
        (Some(x), Some(y)) if x == y => Unify::Match,
        (Some(_), Some(_)) => Unify::Mismatch,
    }
}

/// Fold a landmine's projected `result` with its signature `checks`: any determinable
/// `Mismatch` makes `specializeFor` fail -> non-`SigmaProp` (`SAny`, reject); else any
/// `Unknown` -> lenient (`None`); else the projected result.
fn gated(
    result: Option<crate::sigma_type::SigmaType>,
    checks: &[Unify],
) -> Option<crate::sigma_type::SigmaType> {
    if checks.contains(&Unify::Mismatch) {
        Some(crate::sigma_type::SigmaType::SAny)
    } else if checks.contains(&Unify::Unknown) {
        None
    } else {
        result
    }
}

/// The first two declared argument types of a `FuncValue` operand (e.g.
/// `Coll.fold`'s `(OV, IV) => OV` reducer). `(None, None)` for a non-`FuncValue`.
fn func_value_arg_types(
    op: &crate::opcode::Expr,
) -> (
    Option<crate::sigma_type::SigmaType>,
    Option<crate::sigma_type::SigmaType>,
) {
    if let crate::opcode::Expr::Op(node) = op {
        if let crate::opcode::Payload::FuncValue { args, .. } = &node.payload {
            let a0 = args.first().and_then(|(_, t)| t.clone());
            let a1 = args.get(1).and_then(|(_, t)| t.clone());
            return (a0, a1);
        }
    }
    (None, None)
}

/// A non-`SSigmaProp` result type for operator (generic `One`/`Two`/`Three`
/// payload) opcodes whose result is UNCONDITIONALLY non-SigmaProp regardless of
/// argument types. Returns `Some(SAny)` for those (the gate only needs
/// `!= SSigmaProp`); `None` otherwise. Every listed opcode is oracle-verified to
/// reject a well-formed sizeless root (Scala 6.0.2, rule 1001).
///
/// NOT listed — and therefore left lenient (`None`) — are opcodes that CAN be
/// `SigmaProp` (`ProveDlog`/`ProveDHTuple` 0xCD/0xCE, `BoolToSigmaProp` 0xD1,
/// `AtLeast` 0x98, `SigmaAnd`/`SigmaOr` 0xEA/0xEB — all oracle-verified to ACCEPT)
/// and those whose result type DEPENDS on their arguments (`If` 0x95,
/// `BlockValue`/`FuncValue`/`FuncApply`, `SelectField`/`ByIndex`/`ValUse`/
/// `OptionGet`, `TaggedVar` 0x71). Adding any of those would reject a
/// Scala-accepted (SigmaProp-rooted) tree — a reject-valid. Payloads carrying an
/// explicit static type (`ConcreteCollection`, `Tuple`, `GetVar`,
/// `ExtractRegisterAs`, `NumericCast`, `Deserialize{Context,Register}`) and
/// `MethodCall`/`PropertyCall` (see [`method_call_result_type`]) are classified by
/// [`infer_type`]'s dedicated arms BEFORE this fallback.
fn op_root_non_sigma_type(opcode: u8) -> Option<crate::sigma_type::SigmaType> {
    let never_sigma = matches!(
        opcode,
        0x8F..=0x94                    // Lt Le Gt Ge Eq Neq -> SBoolean
        // NB: ArithOp (Minus 0x99, Plus 0x9A, Multiply 0x9C, Division 0x9D,
        // Modulo 0x9E, Min 0xA1, Max 0xA2) is NOT here: Scala types it as
        // `left.tpe` with NO operand type-check, so a SigmaProp left operand makes
        // the whole op SigmaProp (oracle-verified ACCEPT). It is handled by the
        // arg-dependent left-operand arm in `infer_type`.
        | 0x9F | 0xA0                  // Exponentiate / MultiplyGroup (operand-typed -> reject sigma)
        | 0x7A | 0x7B | 0x7C           // LongToByteArray ByteArrayToBigInt ByteArrayToLong
        | 0xB1                         // SizeOf -> SInt
        | 0xCB | 0xCC                  // CalcBlake2b256 CalcSha256 -> Coll[SByte]
        | 0xC1 | 0xC2 | 0xC3 | 0xC4 | 0xC5 | 0xC7  // Extract{Amount,ScriptBytes,Bytes,BytesNoRef,Id,CreationInfo}
        | 0xCF | 0xD0                  // SigmaPropIsProven -> SBoolean, SigmaPropBytes -> Coll[SByte]
        // Boolean-result operators (predicates / Bool logic) -> SBoolean.
        | 0x96 | 0x97                  // And Or (Bool BinAnd/BinOr over Coll[Boolean]; NOT SigmaAnd/Or 0xEA/0xEB)
        | 0xAE | 0xAF                  // Exists ForAll
        | 0xE6                         // OptionIsDefined
        | 0xEC | 0xED | 0xEF | 0xF4 | 0xFF  // BinOr BinAnd LogicalNot BinXor XorOf
        // Numeric / byte-collection-result operators -> never SigmaProp.
        | 0x9B                         // Xor (byte-array)
        | 0xE7 | 0xE8 | 0xE9           // ModQ PlusModQ MinusModQ
        | 0xF0 | 0xF1 | 0xF2 | 0xF3 | 0xF5 | 0xF6 | 0xF7 | 0xF8  // Negation BitInversion BitOr BitAnd BitXor BitShift{Right,Left,RightZeroed}
        // Fixed-result structural ops.
        | 0x74                         // SubstConstants -> Coll[SByte]
        | 0xB7                         // TreeLookup -> Option[Coll[SByte]]
        | 0xEE                         // DecodePoint -> SGroupElement
        | 0xB3 | 0xB5                  // Append Filter -> Coll
        | 0xAD | 0xB4 // MapCollection Slice -> Coll
                      // NB: Fold (0xB0) / ByIndex (0xB2) / OptionGet (0xE4) / OptionGetOrElse
                      // (0xE5) are arg-dependent (result = accumulator / element type) and are
                      // handled by dedicated arms — they CAN be SigmaProp.
    );
    never_sigma.then_some(crate::sigma_type::SigmaType::SAny)
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
        0xA6 => SAvlTree,                     // LastBlockUtxoRootHash
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

    /// The Finding-E accept-invalid, fixed: `{ val x = 0L; val x = 0L; x }`
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
    /// precise, degrading to the `SAny` sentinel otherwise — never SigmaProp
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
        // Imprecise body (a Tuple literal types as the SAny sentinel) -> the
        // function degrades to top-level SAny (still non-SigmaProp) rather
        // than embedding the sentinel where `agree` could mis-compare it.
        let imprecise = func_value(
            vec![(1, Some(SigmaType::SLong))],
            op(
                0x86,
                Payload::Tuple {
                    items: vec![long0(), long0()],
                },
            ),
        );
        assert_eq!(root(&imprecise), Some(SigmaType::SAny));
    }
}
