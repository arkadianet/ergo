use crate::stype::SType;
use crate::typed::{node_tpe, product_prefix, ConstPayload, TypedExpr};
use crate::typer::methods::{container_exists, get_method, global_method};
use crate::typer::predef_ir::predef_ir_builder;
use crate::typer::unify::{
    apply_subst, apply_subst_func, const_downcast, const_upcast, is_numeric, msg_type_of,
    unify_type_lists, upcast_to, BuildError, TypeSubst,
};
use crate::typer::{TypeEnv, TyperCtx};

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// §1.7-1.10 Apply arms + §1.12 ApplyTypes (SigmaTyper.scala:137-300, 423-438)
// ─────────────────────────────────────────────────────────────────────────────

/// Route an `Apply(func, args)` to the correct arm (source order is load-bearing):
/// §1.7 `Apply(ApplyTypes(Select…, [T]), …)`, §1.8 `Apply(Select…, …)`,
/// §1.9 `Apply(Ident, …)` when the ident names a SGlobal method, else §1.10.
pub(crate) fn assign_apply(
    env: &TypeEnv,
    func: TypedExpr,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // §1.7 — Apply(ApplyTypes(Select(obj, n, _), Seq(rangeTpe)), args).
    if let TypedExpr::ApplyTypes {
        input, type_args, ..
    } = &func
    {
        if type_args.len() == 1 {
            if let TypedExpr::Select { obj, field, .. } = input.as_ref() {
                return assign_apply_explicit_method(
                    env,
                    obj.as_ref().clone(),
                    field.clone(),
                    type_args[0].clone(),
                    args,
                    ctx,
                );
            }
        }
    }
    // §1.8 — Apply(Select(obj, nOriginal, resType), args).
    if let TypedExpr::Select {
        obj,
        field,
        res_type,
        ..
    } = &func
    {
        return assign_apply_select(
            env,
            obj.as_ref().clone(),
            field.clone(),
            res_type.clone(),
            args,
            ctx,
        );
    }
    // §1.9 — Apply(Ident, args) if SGlobalMethods.hasMethod(ident.name).
    if let TypedExpr::Ident { name, .. } = &func {
        if let Some(method) = global_method(name, ctx.tree_version) {
            let new_args = type_all(env, args, ctx)?;
            return process_global_method(&method, new_args);
        }
    }
    // §1.10 — generic application.
    assign_apply_generic(env, func, args, ctx)
}

/// §1.7 `Apply(ApplyTypes(Select(obj, n, _), Seq(rangeTpe)), args)` —
/// SigmaTyper.scala:137-179 (`obj.m[T](args)` explicit type args on a method).
pub(crate) fn assign_apply_explicit_method(
    env: &TypeEnv,
    obj: TypedExpr,
    field: String,
    range_tpe: SType,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // getVarFromInput arg-narrow (SigmaTyper.scala:139-147): both args are
    // numeric constants -> (Short, Byte).  Range-checked via const_downcast
    // (Scala toShortExact/toByteExact throw ArithmeticException on overflow;
    // we propagate as TyperError — verdict parity, class-tag differs).
    let n_args = if field == "getVarFromInput"
        && args.len() == 2
        && numeric_const_value(&args[0]).is_some()
        && numeric_const_value(&args[1]).is_some()
    {
        vec![
            narrow_numeric_const_to(&args[0], &SType::SShort, ctx.tree_version)?,
            narrow_numeric_const_to(&args[1], &SType::SByte, ctx.tree_version)?,
        ]
    } else {
        args
    };

    let new_obj = assign_type(env, obj, ctx)?;
    let t_obj = node_tpe(&new_obj).clone();
    let new_args = type_all(env, n_args, ctx)?;
    if !container_exists(&t_obj) {
        return Err(TyperError::typer(format!(
            "Cannot get field '{field}' in the object of non-product type {t_obj:?}"
        )));
    }
    let method = get_method(&t_obj, &field, ctx.tree_version).ok_or_else(|| {
        TyperError::method_not_found(format!(
            "Cannot find method '{field}' in the object of Product type {t_obj:?}"
        ))
    })?;
    // subst = Map(genFunTpe.tpeParams.head.ident -> rangeTpe) (SigmaTyper.scala:156).
    let tparam = method.stype.tpe_params.first().ok_or_else(|| {
        TyperError::typer(format!("Method '{field}' has no type parameter for [T]"))
    })?;
    let subst: TypeSubst = std::iter::once((tparam.clone(), range_tpe.clone())).collect();
    let concr = apply_subst_func(&method.stype, &subst);
    let expected_args = concr.dom_tail();
    let actual_types: Vec<SType> = new_args.iter().map(|a| node_tpe(a).clone()).collect();
    if expected_args.len() != actual_types.len()
        || !expected_args
            .iter()
            .zip(&actual_types)
            .all(|(ea, na)| *ea == SType::SAny || ea == na)
    {
        return Err(TyperError::typer(format!(
            "For method {field} expected args: {expected_args:?}; actual: {actual_types:?}"
        )));
    }
    if method.has_ir_builder {
        // Scala routes through the method's OWN irBuilder —
        // `irBuilder.lift(builder, newObj, method, newArgs, subst)
        //  .getOrElse(mkMethodCall(newObj, method, newArgs, subst))`
        // (SigmaTyper.scala:167-171): a custom-irBuilder method
        // (slice/filter/map/getOrElse/fold/…) lowers to its dedicated node
        // exactly as on the no-type-arg §1.8 path, while a MethodCallIrBuilder
        // method (getReg/some/none/deserializeTo/fromBigEndianBytes/
        // getVarFromInput) survives as a MethodCall carrying the {T->rangeTpe}
        // substitution (seed §4). Before Task-11 wave 2 this branch built the
        // MethodCall UNCONDITIONALLY, leaving e.g. `arr1.slice[Byte](0, 1)` a
        // residual `MethodCall (12,7)` no evaluator accepts while Scala emits
        // `Slice` (adversarial-findings-methodcalls.md F5; oracle 2026-07-07
        // ×3: the annotated and un-annotated forms reply byte-identically,
        // `…d193b1b47300…`). `lower_method` is the same catalog Scala's
        // irBuilders implement, so routing through it IS the §1.7 rule.
        let lowered = lower_method(
            &t_obj,
            &field,
            new_obj,
            new_args,
            concr.range.clone(),
            ctx.tree_version,
        );
        Ok(thread_method_subst(lowered, &subst))
    } else {
        // mkApply(mkSelect(newObj, n, Some(concrFunTpe)), newArgs).
        let concr_ty = spec_to_stype(&concr);
        let sel = TypedExpr::Select {
            obj: Box::new(new_obj),
            field,
            res_type: Some(concr_ty.clone()),
            tpe: concr_ty,
        };
        Ok(TypedExpr::Apply {
            func: Box::new(sel),
            args: new_args,
            tpe: concr.range,
        })
    }
}

/// §1.8 `Apply(Select(obj, nOriginal, resType), args)` — SigmaTyper.scala:181-223
/// (`obj.m(args)`).
pub(crate) fn assign_apply_select(
    env: &TypeEnv,
    obj: TypedExpr,
    n_original: String,
    res_type: Option<SType>,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_args = type_all(env, args, ctx)?;
    // exp -> expUnsigned hack (SigmaTyper.scala:188-193).
    let n = if n_original == "exp"
        && new_args
            .first()
            .is_some_and(|a| matches!(node_tpe(a), SType::SUnsignedBigInt))
    {
        "expUnsigned".to_string()
    } else {
        n_original
    };
    // newSel = assignType(Select(obj, n, resType)) — re-runs §1.5.
    let sel = TypedExpr::Select {
        obj: Box::new(obj.clone()),
        field: n.clone(),
        res_type,
        tpe: SType::NoType,
    };
    let new_sel = assign_type(env, sel, ctx)?;
    match node_tpe(&new_sel).clone() {
        SType::SFunc { dom: arg_types, .. } => {
            let new_obj = assign_type(env, obj, ctx)?;
            let new_arg_types: Vec<SType> = new_args.iter().map(|a| node_tpe(a).clone()).collect();
            match unify_type_lists(&arg_types, &new_arg_types) {
                Some(subst) => {
                    let concr = apply_subst(node_tpe(&new_sel), &subst);
                    let (concr_dom, concr_range) = func_parts(&concr);
                    let t_obj = node_tpe(&new_obj).clone();
                    match get_method(&t_obj, &n, ctx.tree_version) {
                        Some(method) if method.has_ir_builder => {
                            // A1 (accept-invalid fix): a type-parametric SMethod that
                            // requires an on-wire explicit type argument (getReg /
                            // getVarFromInput / some / none / deserializeTo /
                            // fromBigEndianBytes — the six `explicit_type_args` methods),
                            // or one whose specialized result still carries an unresolved
                            // type var, MUST be applied through an explicit `[T]`
                            // ApplyTypes (§1.7).  Reached here via the no-type-arg
                            // Apply(Select) path, the reference typer throws
                            // IllegalArgumentException at MethodCall construction (the
                            // method still carries unresolved tpeParams).  We reject for
                            // verdict parity — the JVM `IllegalArgumentException` class is
                            // non-reproducible, so we map to `TyperException` (E5-advisory,
                            // like the D-T1 family).  Boundary (oracle-pinned): the
                            // predef-IR `getVar(1)` → `Option[T]` still ACCEPTS on both
                            // sides — that path does not reach here.
                            if method.explicit_type_args || stype_has_free_type_var(&concr_range) {
                                return Err(TyperError::typer(format!(
                                    "Method '{n}' is type-parametric and requires an explicit type argument [T]"
                                )));
                            }
                            // expectedArgs = concrFunTpe.tDom (receiver already dropped).
                            if concr_dom.len() != new_arg_types.len()
                                || !concr_dom
                                    .iter()
                                    .zip(&new_arg_types)
                                    .all(|(ea, na)| *ea == SType::SAny || ea == na)
                            {
                                return Err(TyperError::typer(format!(
                                    "For method {n} expected args: {concr_dom:?}; actual: {new_arg_types:?}"
                                )));
                            }
                            Ok(lower_method(
                                &t_obj,
                                &n,
                                new_obj,
                                new_args,
                                concr_range.clone(),
                                ctx.tree_version,
                            ))
                        }
                        _ => {
                            // mkApply(mkSelect(newObj, n, Some(concrFunTpe)), newArgs).
                            let sel2 = TypedExpr::Select {
                                obj: Box::new(new_obj),
                                field: n,
                                res_type: Some(concr.clone()),
                                tpe: concr,
                            };
                            Ok(TypedExpr::Apply {
                                func: Box::new(sel2),
                                args: new_args,
                                tpe: concr_range.clone(),
                            })
                        }
                    }
                }
                None => Err(TyperError::typer(format!(
                    "Invalid argument type of application: expected {arg_types:?}; actual: {new_arg_types:?}"
                ))),
            }
        }
        // else -> mkApply(newSel, newArgs) (newSel is not a function type).
        other => {
            let tpe = apply_result_tpe(&other);
            Ok(TypedExpr::Apply {
                func: Box::new(new_sel),
                args: new_args,
                tpe,
            })
        }
    }
}

/// §1.10 `Apply(f, args)` — SigmaTyper.scala:231-300 (generic application:
/// predefined funcs, collection indexing, tuple indexing).
pub(crate) fn assign_apply_generic(
    env: &TypeEnv,
    f: TypedExpr,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_f = assign_type(env, f, ctx)?;
    match node_tpe(&new_f).clone() {
        // Predefined function application (SigmaTyper.scala:233-259).
        SType::SFunc { dom, range, .. } => {
            if args.len() != dom.len() {
                return Err(TyperError::typer(
                    "Invalid argument type of application: invalid number of arguments".to_string(),
                ));
            }
            let typed_args = type_all(env, args, ctx)?;
            let adapted = adapt_apply_args(&new_f, typed_args, ctx)?;
            let actual: Vec<SType> = adapted.iter().map(|a| node_tpe(a).clone()).collect();
            if unify_type_lists(&dom, &actual).is_none() {
                return Err(TyperError::typer(format!(
                    "Invalid argument type of application: expected {dom:?}; actual after typing: {actual:?}"
                )));
            }
            // PredefinedFuncApply post-wrapper (SigmaTyper.scala:297-299).
            if let TypedExpr::Ident { name, .. } = &new_f {
                if let Some(res) = predef_ir_builder(name, &new_f, &adapted, ctx.tree_version) {
                    return res;
                }
            }
            Ok(TypedExpr::Apply {
                func: Box::new(new_f),
                args: adapted,
                tpe: *range,
            })
        }
        // Collection indexing `coll(i)` (SigmaTyper.scala:261-277).
        SType::SColl(elem) => assign_collection_index(env, new_f, args, *elem, ctx),
        // Tuple indexing `tup(i)` (SigmaTyper.scala:278-294).
        SType::STuple(items) => assign_tuple_index(env, new_f, args, items, ctx),
        other => Err(TyperError::typer(format!(
            "Invalid array application: array type is expected but was {other:?}"
        ))),
    }
}

/// Collection application `coll(i)` (SigmaTyper.scala:261-277).
pub(crate) fn assign_collection_index(
    env: &TypeEnv,
    new_f: TypedExpr,
    mut args: Vec<TypedExpr>,
    elem: SType,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    if args.len() != 1 {
        return Err(TyperError::typer(
            "Invalid argument of array application: expected integer value".to_string(),
        ));
    }
    let index = args.pop().unwrap();
    // Seq(c @ Constant(index, _: SNumericType)) -> IntConstant(SInt.upcast(index)).
    if let Some((payload, ctype)) = numeric_constant_parts(&index) {
        let folded = const_upcast(&payload, &ctype, &SType::SInt, ctx.tree_version)
            .map_err(build_to_typer)?;
        return Ok(TypedExpr::ByIndex {
            input: Box::new(new_f),
            index: Box::new(TypedExpr::Constant {
                value: folded,
                tpe: SType::SInt,
            }),
            default: None,
            tpe: elem,
        });
    }
    // Seq(index) -> typedIndex.upcastTo(SInt) if numeric, else error.
    let typed_index = assign_type(env, index, ctx)?;
    if !is_numeric(node_tpe(&typed_index)) {
        return Err(TyperError::typer(format!(
            "Invalid argument type of array application: expected numeric type; actual: {:?}",
            node_tpe(&typed_index)
        )));
    }
    let idx = upcast_to(typed_index, &SType::SInt).map_err(build_to_typer)?;
    Ok(TypedExpr::ByIndex {
        input: Box::new(new_f),
        index: Box::new(idx),
        default: None,
        tpe: elem,
    })
}

/// Tuple application `tup(i)` (SigmaTyper.scala:278-294).
pub(crate) fn assign_tuple_index(
    env: &TypeEnv,
    new_f: TypedExpr,
    mut args: Vec<TypedExpr>,
    items: Vec<SType>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    if args.len() != 1 {
        return Err(TyperError::typer(
            "Invalid argument of tuple application: expected integer value".to_string(),
        ));
    }
    let index = args.pop().unwrap();
    // Seq(Constant(index, _: SNumericType)) -> SelectField(tup, SByte.downcast(index)+1).
    if let Some((payload, ctype)) = numeric_constant_parts(&index) {
        let narrowed = const_downcast(&payload, &ctype, &SType::SByte, ctx.tree_version)
            .map_err(build_to_typer)?;
        let byte_idx = match narrowed {
            ConstPayload::Byte(v) => v,
            _ => unreachable!("const_downcast to SByte yields a Byte payload"),
        };
        let field_index = byte_idx as i16 + 1; // 1-based
        if field_index < 1 || field_index as usize > items.len() {
            return Err(TyperError::typer(format!(
                "Invalid tuple field index {field_index} for tuple of arity {}",
                items.len()
            )));
        }
        let tpe = items[(field_index as usize) - 1].clone();
        return Ok(TypedExpr::SelectField {
            input: Box::new(new_f),
            field_index: field_index as i8,
            tpe,
        });
    }
    // Seq(index) non-const -> mkByIndex(new_f.asCollection[SAny], upcastTo(SInt), None).
    let typed_index = assign_type(env, index, ctx)?;
    if !is_numeric(node_tpe(&typed_index)) {
        return Err(TyperError::typer(format!(
            "Invalid argument type of tuple application: expected numeric type; actual: {:?}",
            node_tpe(&typed_index)
        )));
    }
    let idx = upcast_to(typed_index, &SType::SInt).map_err(build_to_typer)?;
    Ok(TypedExpr::ByIndex {
        input: Box::new(new_f),
        index: Box::new(idx),
        default: None,
        tpe: SType::SAny,
    })
}

/// §1.12 `ApplyTypes(input, targs)` — SigmaTyper.scala:423-438 (standalone `f[T]`).
pub(crate) fn assign_apply_types(
    env: &TypeEnv,
    input: TypedExpr,
    type_args: Vec<SType>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_input = assign_type(env, input, ctx)?;
    match node_tpe(&new_input).clone() {
        SType::SFunc { dom, range, .. } => {
            // tpeParams recovered as the free type vars of the SFunc, in
            // first-appearance order (robust for parser-built empty-param SFuncs too).
            let tpe_params = free_type_vars(&dom, &range);
            if tpe_params.len() != type_args.len() {
                return Err(TyperError::typer(format!(
                    "Wrong number of type arguments: expected {tpe_params:?} but provided {type_args:?}. \
                     Note that partial application of type parameters is not supported."
                )));
            }
            let subst: TypeSubst = tpe_params.into_iter().zip(type_args).collect();
            let concr = apply_subst(node_tpe(&new_input), &subst);
            match new_input {
                TypedExpr::Select { obj, field, .. } => {
                    // mkSelect(obj, n, Some(concrFunTpe.tRange)).
                    let (_, concr_range) = func_parts(&concr);
                    let r = concr_range.clone();
                    Ok(TypedExpr::Select {
                        obj,
                        field,
                        res_type: Some(r.clone()),
                        tpe: r,
                    })
                }
                TypedExpr::Ident { name, .. } => {
                    // mkIdent(name, concrFunTpe).
                    Ok(TypedExpr::Ident { name, tpe: concr })
                }
                other => Err(TyperError::typer(format!(
                    "Invalid application of type arguments: unexpected input {}",
                    product_prefix(&other)
                ))),
            }
        }
        _ => Err(TyperError::typer(
            "Invalid application of type arguments: function doesn't have type parameters"
                .to_string(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// arg adaptation (§8.3 adaptSigmaPropToBoolean + getVar-family narrowing)
// ─────────────────────────────────────────────────────────────────────────────

/// §1.10 arg adaptation (SigmaTyper.scala:241-252): allOf/anyOf coerce SigmaProp
/// elements to Boolean; getVar/executeFromVar/getVarFromInput narrow constant ids.
pub(crate) fn adapt_apply_args(
    new_f: &TypedExpr,
    typed_args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<Vec<TypedExpr>, TyperError> {
    let name = match new_f {
        TypedExpr::Ident { name, .. } => name.as_str(),
        _ => return Ok(typed_args),
    };
    match name {
        "allOf" | "anyOf" => {
            // adaptSigmaPropToBoolean(typedArgs, argTypes) with argTypes = [Coll[Bool]].
            adapt_sigma_prop_to_boolean(typed_args, &[SType::SColl(Box::new(SType::SBoolean))])
        }
        // Range-checked via const_downcast (Scala toByteExact throws ArithmeticException
        // on overflow; we propagate as TyperError — verdict parity, class-tag differs).
        "getVar" | "executeFromVar"
            if typed_args.len() == 1 && numeric_const_value(&typed_args[0]).is_some() =>
        {
            Ok(vec![narrow_numeric_const_to(
                &typed_args[0],
                &SType::SByte,
                ctx.tree_version,
            )?])
        }
        "getVarFromInput"
            if typed_args.len() == 2
                && numeric_const_value(&typed_args[0]).is_some()
                && numeric_const_value(&typed_args[1]).is_some() =>
        {
            Ok(vec![
                narrow_numeric_const_to(&typed_args[0], &SType::SShort, ctx.tree_version)?,
                narrow_numeric_const_to(&typed_args[1], &SType::SByte, ctx.tree_version)?,
            ])
        }
        _ => Ok(typed_args),
    }
}

/// `adaptSigmaPropToBoolean(items, expectedTypes)` — SigmaTyper.scala:558-567.
pub(crate) fn adapt_sigma_prop_to_boolean(
    items: Vec<TypedExpr>,
    expected: &[SType],
) -> Result<Vec<TypedExpr>, TyperError> {
    let bool_array = SType::SColl(Box::new(SType::SBoolean));
    let mut out = Vec::with_capacity(items.len());
    for (i, it) in items.into_iter().enumerate() {
        let exp = expected.get(i);
        match (it, exp) {
            // (cc: ConcreteCollection, SBooleanArray) -> recurse + finalize.
            (
                TypedExpr::ConcreteCollection {
                    items: inner_items,
                    elem_type: inner_elem,
                    ..
                },
                Some(e),
            ) if *e == bool_array => {
                let filled = vec![SType::SBoolean; inner_items.len()];
                let adapted = adapt_sigma_prop_to_boolean(inner_items, &filled)?;
                if adapted.is_empty() {
                    // `allOf(Coll[Boolean]())` / `anyOf(Coll[Boolean]())`: an
                    // empty typed collection has no element to infer a type from,
                    // so `finalize_collection` (msgTypeOf over the items) would
                    // reject with "Undefined type of empty collection". Scala's
                    // typer instead PRESERVES the declared element type
                    // (`SigmaTyper.assignConcreteCollection` keeps `cc.elementType`
                    // for an empty `cc`), and the vacuous `AND`/`OR` folds
                    // downstream (`allOf(empty) → true`, `anyOf(empty) → false`,
                    // `crate::fold`). Mirror that: rebuild the empty collection
                    // with its declared `elem_type` (here `SBoolean`) rather than
                    // re-deriving it.
                    out.push(TypedExpr::ConcreteCollection {
                        tpe: SType::SColl(Box::new(inner_elem.clone())),
                        items: adapted,
                        elem_type: inner_elem,
                    });
                } else {
                    out.push(finalize_collection(adapted)?);
                }
            }
            // (it, SBoolean) where it.tpe == SSigmaProp -> SigmaPropIsProven(it).
            (it, Some(e)) if *e == SType::SBoolean && *node_tpe(&it) == SType::SSigmaProp => {
                out.push(TypedExpr::SigmaPropIsProven {
                    input: Box::new(it),
                    tpe: SType::SBoolean,
                });
            }
            (it, _) => out.push(it),
        }
    }
    Ok(out)
}

/// `assignConcreteCollection(cc, items)` over ALREADY-TYPED items (no re-typing) —
/// SigmaTyper.scala:545-556.  Computes the element type via msgTypeOf.
pub(crate) fn finalize_collection(items: Vec<TypedExpr>) -> Result<TypedExpr, TyperError> {
    let mut types: Vec<SType> = Vec::new();
    for it in &items {
        let t = node_tpe(it).clone();
        if !types.contains(&t) {
            types.push(t);
        }
    }
    let t_item = if items.is_empty() {
        return Err(TyperError::typer(
            "Undefined type of empty collection".to_string(),
        ));
    } else {
        msg_type_of(&types).ok_or_else(|| {
            TyperError::typer(format!(
                "All element of array should have the same type but found {types:?}"
            ))
        })?
    };
    Ok(TypedExpr::ConcreteCollection {
        tpe: SType::SColl(Box::new(t_item.clone())),
        items,
        elem_type: t_item,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// small helpers for the Apply arms
// ─────────────────────────────────────────────────────────────────────────────

/// Numeric value of a numeric `Constant` (Byte/Short/Int/Long), else `None`.
pub(crate) fn numeric_const_value(e: &TypedExpr) -> Option<i64> {
    numeric_constant_parts(e).map(|(payload, _)| match payload {
        ConstPayload::Byte(v) => v as i64,
        ConstPayload::Short(v) => v as i64,
        ConstPayload::Int(v) => v as i64,
        ConstPayload::Long(v) => v,
        _ => unreachable!("numeric_constant_parts only yields numeric payloads"),
    })
}

/// `(payload, type)` of a numeric `Constant` (Byte/Short/Int/Long/BigInt), else
/// `None`.  Mirrors the `Constant(index, _: SNumericType)` match arms.
pub(crate) fn numeric_constant_parts(e: &TypedExpr) -> Option<(ConstPayload, SType)> {
    match e {
        TypedExpr::Constant { value, tpe } => match value {
            ConstPayload::Byte(_)
            | ConstPayload::Short(_)
            | ConstPayload::Int(_)
            | ConstPayload::Long(_)
            | ConstPayload::BigInt(_) => Some((value.clone(), tpe.clone())),
            _ => None,
        },
        _ => None,
    }
}

/// Range-check and narrow a numeric constant to `target` via Scala's
/// `SByte.downcast` / `SShort.downcast` (= `toByteExact` / `toShortExact`).
///
/// Scala throws `ArithmeticException` on overflow; we return `Err(TyperError)`.
/// Verdict parity is exact (both sides REJECT on out-of-range input).
/// Class-tag deviation: ArithmeticException vs TyperError — recorded in
/// lib.rs § "Known M2 deviations".
pub(crate) fn narrow_numeric_const_to(
    e: &TypedExpr,
    target: &SType,
    tree_version: u8,
) -> Result<TypedExpr, TyperError> {
    let (payload, ctype) = numeric_constant_parts(e).ok_or_else(|| {
        TyperError::typer("narrow_numeric_const_to: not a numeric constant".to_string())
    })?;
    let narrowed =
        const_downcast(&payload, &ctype, target, tree_version).map_err(build_to_typer)?;
    Ok(TypedExpr::Constant {
        value: narrowed,
        tpe: target.clone(),
    })
}

/// Destructure an `SType::SFunc` into `(dom, range)`; empty/NoType for non-funcs.
pub(crate) fn func_parts(t: &SType) -> (Vec<SType>, SType) {
    match t {
        SType::SFunc { dom, range, .. } => (dom.clone(), (**range).clone()),
        _ => (vec![], SType::NoType),
    }
}

/// Convert an `SFuncSpec` to the `SType::SFunc` shape, carrying the (remaining)
/// tpe_params onto the printed type.  On the explicit-`[T]` path the single tparam is
/// already substituted (so this yields empty params — a monomorphic printed type).
pub(crate) fn spec_to_stype(spec: &crate::typer::unify::SFuncSpec) -> SType {
    SType::SFunc {
        dom: spec.dom.clone(),
        range: Box::new(spec.range.clone()),
        tpe_params: spec.tpe_params.clone(),
    }
}

/// `mkApply` result type — mirrors `Apply.tpe` (values.scala:1218-1222).
///
/// - `SFunc { range, .. }` → range (the standard call-result type).
/// - `SColl(elem)` → elem: `SCollectionType.elemType` (SType.scala:750).
///   This handles the §1.8 `other` branch for a select that resolves to a
///   collection type; `Apply:(elem)` is the result shape the oracle produces.
/// - All other types → `NoType`; the global post-condition rejects.
pub(crate) fn apply_result_tpe(func_tpe: &SType) -> SType {
    match func_tpe {
        SType::SFunc { range, .. } => (**range).clone(),
        SType::SColl(elem) => (**elem).clone(),
        _ => SType::NoType,
    }
}

/// Free type variables of an `SFunc(dom, range)` in first-appearance order.
/// Recovers the `tpeParams` that `SType::SFunc` cannot carry, for §1.12.
pub(crate) fn free_type_vars(dom: &[SType], range: &SType) -> Vec<String> {
    let mut acc = Vec::new();
    for d in dom {
        collect_type_vars(d, &mut acc);
    }
    collect_type_vars(range, &mut acc);
    acc
}

/// Map a builder-layer error to a typer exception (the `mkByIndex`/`upcastTo`
/// paths are outside `bimap`, so their throws surface as generic rejections).
pub(crate) fn build_to_typer(be: BuildError) -> TyperError {
    TyperError::typer(format!("{be:?}"))
}
