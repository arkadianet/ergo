//! The rule-1001 (`CheckDeserializedScriptIsSigmaProp`) static
//! type-inference subsystem: binding scan, lexical type environment, and
//! the root-type judgement mirrored from Scala's deserialize-time
//! `Value.tpe` derivation.

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
/// Entry point: the root is typed in an empty binding environment. `Some(SSigmaProp)`
/// accepts, `Some(other)` is the wrap/reject verdict, and `None` is lenient (the
/// root type is not statically determinable). Public so the `difftest --methodcall`
/// harness can diff this exact verdict against the JVM reference.
pub fn determinable_root_type_of(
    body: &crate::opcode::Expr,
    constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
) -> Option<crate::sigma_type::SigmaType> {
    let scan = scan_tree(body, constants);
    infer_type(
        body,
        &[],
        &InferCtx {
            constants,
            scan: &scan,
        },
    )
}

/// The set of binding ids (`ValDef` / `FunDef` / `FuncValue` arg) that occur more
/// than once anywhere in the tree. Walks EVERY child (not just the type-
/// determining spine) so a rebinding buried in an off-spine subtree is recorded.
///
/// Scala's `ValUse.tpe` is read from a FLAT, never-popped, last-write-wins
/// `valDefTypeStore` keyed by id, SHARED across the whole reader. Two things make
/// our post-parse lexical [`infer_type`] env disagree with it, and [`scan_tree`]
/// detects both so a `ValUse` can fall back to `None` (lenient) rather than trust a
/// stale type and REJECT a tree Scala accepts (a reject-valid):
///
///  - REUSED binding ids ([`BindingScan::dup_ids`]). A `ValUse` of a reused id is
///    resolved to `None` (lenient). Matching Scala here would require its exact
///    POSITION-AWARE store evolution: the value of a reused id depends on how many
///    of its rebinds have been parsed at the point of the `ValUse`, and a rebind can
///    sit in an off-spine subtree our type recursion never visits. Every cheaper
///    approximation we tried (trust the lexical env / the whole-tree last write)
///    reject-valid'd a real Scala-accepted shape — e.g.
///    `{ val x = sigmaProp; val y = x; val x = 0L; y }`, where Scala fixes `y` to
///    SigmaProp BEFORE the rebind. Since a reused binding id NEVER occurs in a
///    legitimately compiled tree, we take the safe direction (lenient) and accept a
///    residual ACCEPT-invalid on adversarial duplicate-id trees whose root type is
///    statically determinable (e.g. `{ val x = 0L; val x = 0L; x }`, which Scala
///    rejects). The leniency is scoped to a `ValUse` of the reused id, so a
///    duplicate-id tree whose ROOT is independent of it (e.g. a Boolean block
///    result) is still classified and rule-1001-rejected.
///  - A constant that MATERIALIZES a box value ([`BindingScan::has_box_const`], by
///    [`value_contains_box`] — value, not type, so an empty `Coll[SBox]` does not
///    count). Scala parses a box's NESTED ErgoTree on the SAME reader, whose
///    `valDefTypeStore` is shared and NOT restored
///    (`ErgoTreeSerializer.deserializeErgoTree` saves `constantStore`/
///    `wasDeserialize` but not `valDefTypeStore`); so the inner script's `ValDef`s
///    — invisible to our body walk — can rebind an id the outer body uses. With a
///    box value present we therefore trust no `ValUse`.
///
/// Legitimate Scala-produced trees reuse no id and rarely embed box constants, so
/// for them `dup_ids` is empty and `has_box_const` is false.
struct BindingScan {
    dup_ids: std::collections::HashSet<u32>,
    has_box_const: bool,
}

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

/// Whole-tree scan (every child, not just the type spine) collecting reused binding
/// ids and whether any constant — inline in `body` or in the segregated `constants`
/// table — materializes a box value. See [`BindingScan`] for why both matter.
fn scan_tree(
    body: &crate::opcode::Expr,
    constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
) -> BindingScan {
    use crate::opcode::Payload;
    fn walk(
        e: &crate::opcode::Expr,
        seen: &mut std::collections::HashSet<u32>,
        dups: &mut std::collections::HashSet<u32>,
        has_box: &mut bool,
    ) {
        let node = match e {
            crate::opcode::Expr::Unparsed(_) => return,
            crate::opcode::Expr::Const { val, .. } => {
                *has_box |= value_contains_box(val);
                return;
            }
            crate::opcode::Expr::Op(node) => node,
        };
        let mut record = |id: u32| {
            if !seen.insert(id) {
                dups.insert(id);
            }
        };
        match &node.payload {
            Payload::ValDef { id, rhs, .. } | Payload::FunDef { id, rhs, .. } => {
                record(*id);
                walk(rhs, seen, dups, has_box);
            }
            Payload::FuncValue { args, body } => {
                for (id, _) in args {
                    record(*id);
                }
                walk(body, seen, dups, has_box);
            }
            Payload::BlockValue { items, result } => {
                for item in items {
                    walk(item, seen, dups, has_box);
                }
                walk(result, seen, dups, has_box);
            }
            Payload::MethodCall { obj, args, .. } => {
                walk(obj, seen, dups, has_box);
                for a in args {
                    walk(a, seen, dups, has_box);
                }
            }
            Payload::One(a) => walk(a, seen, dups, has_box),
            Payload::Two(a, b) => {
                walk(a, seen, dups, has_box);
                walk(b, seen, dups, has_box);
            }
            Payload::Three(a, b, c) => {
                walk(a, seen, dups, has_box);
                walk(b, seen, dups, has_box);
                walk(c, seen, dups, has_box);
            }
            Payload::Four(a, b, c, d) => {
                walk(a, seen, dups, has_box);
                walk(b, seen, dups, has_box);
                walk(c, seen, dups, has_box);
                walk(d, seen, dups, has_box);
            }
            Payload::ConcreteCollection { items, .. }
            | Payload::Tuple { items }
            | Payload::SigmaCollection { items } => {
                for i in items {
                    walk(i, seen, dups, has_box);
                }
            }
            Payload::SelectField { input, .. }
            | Payload::ExtractRegisterAs { input, .. }
            | Payload::NumericCast { input, .. } => walk(input, seen, dups, has_box),
            Payload::ByIndex {
                input,
                index,
                default,
            } => {
                walk(input, seen, dups, has_box);
                walk(index, seen, dups, has_box);
                if let Some(d) = default.as_deref() {
                    walk(d, seen, dups, has_box);
                }
            }
            Payload::FuncApply { func, args } => {
                walk(func, seen, dups, has_box);
                for a in args {
                    walk(a, seen, dups, has_box);
                }
            }
            Payload::DeserializeRegister { default, .. } => {
                if let Some(d) = default.as_deref() {
                    walk(d, seen, dups, has_box);
                }
            }
            // Leaves and id-free payloads: no binding ids, nothing to recurse.
            Payload::Zero
            | Payload::ValUse { .. }
            | Payload::ConstPlaceholder { .. }
            | Payload::TaggedVar { .. }
            | Payload::BoolCollection { .. }
            | Payload::GetVar { .. }
            | Payload::DeserializeContext { .. }
            | Payload::NoneValue { .. } => {}
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut dups = std::collections::HashSet::new();
    // A segregated constant pollutes the shared store the same way an inline one
    // does, even when no `ConstPlaceholder` references it (the whole table is
    // parsed), so seed the box flag from the constants table too.
    let mut has_box = constants.iter().any(|(_, val)| value_contains_box(val));
    walk(body, &mut seen, &mut dups, &mut has_box);
    BindingScan {
        dup_ids: dups,
        has_box_const: has_box,
    }
}

/// Immutable context threaded through [`infer_type`] for the whole judgement: the
/// segregated `constants` table (for `ConstPlaceholder`) plus the [`BindingScan`]
/// flags that make a `ValUse` fall back to `None`.
struct InferCtx<'a> {
    constants: &'a [(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
    scan: &'a BindingScan,
}

/// A binding environment frame: `(binding id, its static type)` pairs, threaded
/// through [`infer_type`] so a `ValUse` can recover the type of the `ValDef` /
/// `FunDef` it references (Scala's `ValUse.tpe` reads a type the wire does NOT
/// carry for us). A `ValUse` flagged ambiguous by the [`BindingScan`] is resolved
/// to `None` instead, so the at-most-one-relevant-entry-per-id assumption the
/// newest-first scan relies on holds for every id it actually returns.
type TypeEnv<'a> = &'a [(u32, crate::sigma_type::SigmaType)];

/// Recursive static-type inference over the ErgoTree IR — the rule-1001
/// (`CheckDeserializedScriptIsSigmaProp`) root typechecker, computing the same
/// `Value.tpe` Scala derives bottom-up at deserialize. Returns the type when it
/// is STATICALLY DETERMINABLE, or `None` (treated as lenient/accept by the gate)
/// — so an as-yet-unhandled shape can never reject a tree Scala accepts.
fn infer_type(
    body: &crate::opcode::Expr,
    env: TypeEnv,
    ctx: &InferCtx,
) -> Option<crate::sigma_type::SigmaType> {
    use crate::opcode::Payload;
    use crate::sigma_type::SigmaType;
    match body {
        crate::opcode::Expr::Const { tpe, .. } => Some(tpe.clone()),
        crate::opcode::Expr::Op(node) => match &node.payload {
            Payload::ConstPlaceholder { index } => ctx
                .constants
                .get(*index as usize)
                .map(|(tpe, _)| tpe.clone()),
            // Payloads carrying their result type EXPLICITLY in the IR.
            // `Deserialize{Context,Register}[T]` return `T` DIRECTLY, so they CAN
            // be SigmaProp (accept iff T == SSigmaProp); `NumericCast`'s target is
            // always a numeric type (never SigmaProp). Returning the declared type
            // lets the gate accept/reject exactly as Scala does (oracle-verified:
            // `DeserializeRegister[SigmaProp]` accepts, `[SLong]` rejects).
            Payload::DeserializeContext { tpe, .. }
            | Payload::DeserializeRegister { tpe, .. }
            | Payload::NumericCast { tpe, .. } => Some(tpe.clone()),
            // `getVar[T]` / `box.RX[T]` statically return `Option[T]` — never
            // SigmaProp, even for T = SigmaProp (oracle-verified).
            Payload::GetVar { tpe, .. } | Payload::ExtractRegisterAs { tpe, .. } => {
                Some(SigmaType::SOption(Box::new(tpe.clone())))
            }
            // Collection / tuple literals — `Coll[..]` / a tuple — are never
            // SigmaProp even when every element is SigmaProp (oracle-verified:
            // `Coll[SigmaProp]` and `(SigmaProp, SigmaProp)` both reject).
            Payload::ConcreteCollection { elem_type, .. } => {
                Some(SigmaType::SColl(Box::new(elem_type.clone())))
            }
            Payload::BoolCollection { .. } => Some(SigmaType::SColl(Box::new(SigmaType::SBoolean))),
            Payload::Tuple { .. } => Some(SigmaType::SAny),
            // ARG-DEPENDENT roots whose type is a PROJECTION of a child's type
            // (Scala computes these bottom-up at deserialize). RECURSE into the
            // type-determining child — `determinable_root_type_of` only ever yields
            // an oracle-verified concrete type or `None`, so a non-determinable
            // child maps to `None` (lenient) and this can NEVER reject a tree Scala
            // accepts. `MethodCall`/`PropertyCall` are typed by
            // [`method_call_result_type`] (the harness-verified registry);
            // `FuncApply` still needs a binding environment and stays lenient via the
            // fallback below.
            //
            // ArithOp (Minus/Plus/Multiply/Division/Modulo/Min/Max): `tpe =
            // left.tpe` and Scala does NOT type-check the operands at deserialize,
            // so a SigmaProp LEFT operand makes the op SigmaProp (oracle-verified:
            // `Plus(sigma, x)` accepts, `Plus(Long, Long)` rejects). Recurse into
            // the left operand (child 0 of the `Two` payload).
            Payload::Two(left, _right)
                if matches!(node.opcode, 0x99 | 0x9A | 0x9C | 0x9D | 0x9E | 0xA1 | 0xA2) =>
            {
                infer_type(left, env, ctx)
            }
            // If: `If.tpe = trueBranch.tpe` (the then-branch, child 1; Scala does
            // NOT unify the branches at deserialize).
            Payload::Three(_cond, then_branch, _else) if node.opcode == 0x95 => {
                infer_type(then_branch, env, ctx)
            }
            // Fold: result = the accumulator type = the `zero` arg (child 1).
            Payload::Three(_coll, zero, _op) if node.opcode == 0xB0 => infer_type(zero, env, ctx),
            // BlockValue `{ vals...; result }`: type = the result expression's type,
            // typed under an environment extended with each `ValDef` / `FunDef`
            // binding (in order; a later item may reference an earlier one). Both
            // bind their id to their RHS type — Scala's `ValUse.tpe` reads the
            // referenced definition's value type, and a `FunDef` RHS is NOT always a
            // function (e.g. `fun x = sigmaProp`), so deriving it from the RHS keeps
            // a `ValUse` of a SigmaProp-RHS binding accepting (oracle-verified).
            // A non-determinable RHS is skipped, so a `ValUse` of it stays lenient.
            Payload::BlockValue { items, result } => {
                let mut scope = env.to_vec();
                for item in items {
                    if let crate::opcode::Expr::Op(item_node) = item {
                        if let Payload::ValDef { id, rhs, .. } | Payload::FunDef { id, rhs, .. } =
                            &item_node.payload
                        {
                            if let Some(t) = infer_type(rhs, &scope, ctx) {
                                scope.push((*id, t));
                            }
                        }
                    }
                }
                infer_type(result, &scope, ctx)
            }
            // ValUse: the type of the `ValDef`/`FunDef` it binds. We cannot match
            // Scala's flat, shared, last-write-wins store for an ambiguous id, so go
            // lenient (`None`) for: a REUSED id (its value is position-dependent and
            // may be rebound off-spine), or ANY `ValUse` once an `SBox` constant is
            // present (its nested script can rebind ids on the shared reader with
            // bindings we cannot see). A unique id in a box-free tree resolves from
            // the lexical env. See [`BindingScan`].
            Payload::ValUse { id } => {
                if ctx.scan.has_box_const || ctx.scan.dup_ids.contains(id) {
                    return None;
                }
                env.iter()
                    .rev()
                    .find(|(i, _)| i == id)
                    .map(|(_, t)| t.clone())
            }
            // A function literal is never SigmaProp (its type is `SFunc`), so a
            // `FuncValue` root fails rule 1001 (oracle-verified: a FuncValue-rooted
            // tree rejects).
            Payload::FuncValue { .. } => Some(SigmaType::SAny),
            // SelectField `tuple._i`: the i-th component type of the input tuple
            // (1-based). Only resolvable when the input's type is a determinable
            // `STuple` (e.g. a tuple constant); otherwise lenient.
            Payload::SelectField { input, field_idx } => match infer_type(input, env, ctx) {
                Some(SigmaType::STuple(items)) => (*field_idx as usize)
                    .checked_sub(1)
                    .and_then(|i| items.get(i))
                    .cloned(),
                _ => None,
            },
            // ByIndex `coll(i)`: the element type of the input collection.
            Payload::ByIndex { input, .. } => match infer_type(input, env, ctx) {
                Some(SigmaType::SColl(elem)) => Some(*elem),
                _ => None,
            },
            // OptionGet `opt.get` / OptionGetOrElse `opt.getOrElse(d)`: the option's
            // element type (the option is child 0 in both).
            Payload::One(opt) if node.opcode == 0xE4 => match infer_type(opt, env, ctx) {
                Some(SigmaType::SOption(elem)) => Some(*elem),
                _ => None,
            },
            Payload::Two(opt, _default) if node.opcode == 0xE5 => match infer_type(opt, env, ctx) {
                Some(SigmaType::SOption(elem)) => Some(*elem),
                _ => None,
            },
            // MethodCall / PropertyCall: the method's result static type, classified
            // by the (type_id, method_id) registry the `difftest --methodcall`
            // harness verified end-to-end against the JVM reference. See
            // [`method_call_result_type`].
            Payload::MethodCall {
                type_id,
                method_id,
                obj,
                args,
                type_args,
            } => method_call_result_type(*type_id, *method_id, obj, args, type_args, env, ctx),
            // A zero-argument (leaf) opcode root has a statically-known type and
            // NONE of them is `SSigmaProp` (see [`zero_arg_root_type`]), so a
            // script rooted at one fails CheckDeserializedScriptIsSigmaProp just
            // like an inline non-SigmaProp `Const`.
            Payload::Zero => Some(zero_arg_root_type(node.opcode)),
            // An operator root whose result type is unconditionally non-SigmaProp
            // (regardless of its argument types) — relations, arithmetic, etc.
            _ => op_root_non_sigma_type(node.opcode),
        },
        crate::opcode::Expr::Unparsed(_) => None,
    }
}

/// The result static type of a `MethodCall` / `PropertyCall`, for the rule-1001
/// root judgement. Scala computes `MethodCall.tpe` as the SMethod's result type
/// specialized for the receiver/arg types; the only methods whose specialized
/// result can be `SigmaProp` are the 7 the `difftest --methodcall` harness verified
/// END-TO-END against the JVM reference (every other of the 199 registered methods
/// returns a concrete type or an `Option`/`Coll`/tuple wrapper — structurally never
/// `SigmaProp`). Each of the 7 is a projection of the receiver / args / explicit
/// type, exactly mirroring the `ByIndex` / `OptionGet` / `Fold` / `Deserialize`
/// arms above. A result type VARIABLE that occurs more than once (`getOrElse`'s
/// receiver + default, `fold`'s zero + op range) is reconciled with
/// [`unify_occurrences`] — Scala `unifyTypeLists` makes the result `SigmaProp` only
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
    obj: &crate::opcode::Expr,
    args: &[crate::opcode::Expr],
    type_args: &[crate::sigma_type::SigmaType],
    env: TypeEnv,
    ctx: &InferCtx,
) -> Option<crate::sigma_type::SigmaType> {
    use crate::sigma_type::SigmaType;
    let arg_ty = |i: usize| args.get(i).and_then(|a| infer_type(a, env, ctx));
    // The receiver's Coll / Option element type (the result type variable `IV`/`T`).
    // Computed LAZILY and AT MOST ONCE per call — inferring the receiver eagerly for
    // every MethodCall (including the non-landmine fallback) re-walks a nested
    // MethodCall receiver chain on each level, which is exponential (a parse-time
    // CPU DoS). The non-landmine / Global arms never touch the receiver.
    let coll_elem = || match infer_type(obj, env, ctx) {
        Some(SigmaType::SColl(elem)) => Some(*elem),
        _ => None,
    };
    let opt_elem = || match infer_type(obj, env, ctx) {
        Some(SigmaType::SOption(elem)) => Some(*elem),
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
        // IV (receiver elem) = op arg1.
        (12, 5) => {
            let zero = arg_ty(0);
            let (op_a0, op_a1) = args.get(1).map_or((None, None), func_value_arg_types);
            let op_range = args.get(1).and_then(|op| func_value_range(op, env, ctx));
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

/// The RANGE type of a `FuncValue` operand (e.g. `Coll.fold`'s `(OV, IV) => OV`
/// reducer): its body typed under the function's declared arg types. `None` for a
/// non-`FuncValue` arg or a non-determinable body — leaving the caller lenient.
fn func_value_range(
    op: &crate::opcode::Expr,
    env: TypeEnv,
    ctx: &InferCtx,
) -> Option<crate::sigma_type::SigmaType> {
    let crate::opcode::Expr::Op(node) = op else {
        return None;
    };
    let crate::opcode::Payload::FuncValue { args, body } = &node.payload else {
        return None;
    };
    let mut scope = env.to_vec();
    for (id, tpe) in args {
        if let Some(t) = tpe {
            scope.push((*id, t.clone()));
        }
    }
    infer_type(body, &scope, ctx)
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
/// [`determinable_root_type_of`] BEFORE this fallback.
fn op_root_non_sigma_type(opcode: u8) -> Option<crate::sigma_type::SigmaType> {
    let never_sigma = matches!(
        opcode,
        0x8F..=0x94                    // Lt Le Gt Ge Eq Neq -> SBoolean
        // NB: ArithOp (Minus 0x99, Plus 0x9A, Multiply 0x9C, Division 0x9D,
        // Modulo 0x9E, Min 0xA1, Max 0xA2) is NOT here: Scala types it as
        // `left.tpe` with NO operand type-check, so a SigmaProp left operand makes
        // the whole op SigmaProp (oracle-verified ACCEPT). It is handled by the
        // arg-dependent left-operand recursion in `determinable_root_type_of`.
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
                      // (0xE5) are arg-dependent (result = accumulator / element type) and stay
                      // lenient — they CAN be SigmaProp.
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
