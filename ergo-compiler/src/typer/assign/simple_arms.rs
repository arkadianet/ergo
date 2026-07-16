use crate::stype::SType;
use crate::typed::{node_tpe, product_prefix, TypedExpr};
use crate::typer::methods::{container_exists, get_method, global_method};
use crate::typer::unify::{apply_subst_func, msg_type_of, unify_types};
use crate::typer::{coll_elem, TypeEnv, TyperCtx};

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// §1.1 Block (E1-lenient)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn assign_block(
    env: &TypeEnv,
    bindings: Vec<TypedExpr>,
    result: TypedExpr,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let mut cur_env = env.clone();
    let mut new_binds = Vec::with_capacity(bindings.len());
    for b in bindings {
        let (name, body) = match b {
            TypedExpr::ValNode { name, body, .. } => (name, *body),
            other => {
                return Err(TyperError::typer(format!(
                    "Block binding is not a Val: {}",
                    product_prefix(&other)
                )))
            }
        };
        // Duplicate-name check (SigmaTyper.scala:58-59).
        if let Some(prev) = cur_env.get(&name) {
            return Err(TyperError::typer(format!(
                "Variable {name} already defined ({name} = {prev:?}"
            )));
        }
        let b1 = assign_type(&cur_env, body, ctx)?;
        let b1_tpe = node_tpe(&b1).clone();
        // E1: the Val's explicit annotation is DISCARDED — bind n -> b1.tpe,
        // mkVal(n, b1.tpe, b1) (SigmaTyper.scala:60,62; NOT the HEAD-only
        // isAssignableTo check).
        cur_env.insert(name.clone(), b1_tpe.clone());
        new_binds.push(TypedExpr::ValNode {
            name,
            given_type: b1_tpe.clone(),
            body: Box::new(b1),
            tpe: b1_tpe,
        });
    }
    let result1 = assign_type(&cur_env, result, ctx)?;
    let tpe = node_tpe(&result1).clone();
    Ok(TypedExpr::Block {
        bindings: new_binds,
        result: Box::new(result1),
        tpe,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.3 ConcreteCollection (msgTypeOf — NO numeric widening across elements)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn assign_concrete_collection(
    env: &TypeEnv,
    items: Vec<TypedExpr>,
    elem_type: SType,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let is_empty = items.is_empty();
    let new_items = type_all(env, items, ctx)?;
    // types = newItems.map(_.tpe).distinct (SigmaTyper.scala:546)
    let mut types: Vec<SType> = Vec::new();
    for it in &new_items {
        let t = node_tpe(it).clone();
        if !types.contains(&t) {
            types.push(t);
        }
    }
    let t_item = if is_empty {
        if elem_type == SType::NoType {
            return Err(TyperError::typer(
                "Undefined type of empty collection".to_string(),
            ));
        }
        elem_type
    } else {
        // msgTypeOf(types) (SigmaTyper.scala:552): folds msgType — collections do
        // NOT numeric-widen across elements ([1, 2L] -> None -> error).
        msg_type_of(&types).ok_or_else(|| {
            TyperError::typer(format!(
                "All element of array should have the same type but found {types:?}"
            ))
        })?
    };
    let tpe = SType::SColl(Box::new(t_item.clone()));
    Ok(TypedExpr::ConcreteCollection {
        items: new_items,
        elem_type: t_item,
        tpe,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.4 Ident
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn assign_ident(
    name: &str,
    env: &TypeEnv,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // env.get(n) -> mkIdent(n, t) (SigmaTyper.scala:76-77)
    if let Some(t) = env.get(name) {
        return Ok(TypedExpr::Ident {
            name: name.to_string(),
            tpe: t.clone(),
        });
    }
    // None -> SGlobalMethods.method(n): a no-arg global property (tDom.length==1,
    // e.g. `groupGenerator` without parens) -> processGlobalMethod
    // (SigmaTyper.scala:79-82).  groupGenerator lowers to the dedicated
    // GroupGenerator node via processGlobalMethod (§8.1); other no-arg SGlobal
    // properties fall back to a MethodCall(Global, …).
    if let Some(method) = global_method(name, ctx.tree_version) {
        if method.stype.dom.len() == 1 {
            return process_global_method(&method, vec![]);
        }
    }
    // else -> error (SigmaTyper.scala:84)
    Err(TyperError::typer(format!(
        "Cannot assign type for variable '{name}' because it is not found in env"
    )))
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.5 Select(obj, n, None) — the method/property resolver
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn assign_select(
    env: &TypeEnv,
    obj: TypedExpr,
    field: String,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_obj = assign_type(env, obj, ctx)?;
    let t_obj = node_tpe(&new_obj).clone();
    // newObj.tpe must be SProduct (SigmaTyper.scala:90-91); container_exists is
    // true for every SProduct (incl. the empty SBoolean/SString/SAny/SUnit
    // containers), false for non-product types (SFunc/NoType/STypeVar/...).
    if !container_exists(&t_obj) {
        return Err(TyperError::typer(format!(
            "Cannot get field '{field}' in the object of non-product type {t_obj:?}"
        )));
    }
    // getMethod(tNewObj, n) — None -> MethodNotFound (incl. empty containers, E4).
    let method = get_method(&t_obj, &field, ctx.tree_version).ok_or_else(|| {
        TyperError::method_not_found(format!(
            "Cannot find method '{field}' in the object of Product type {t_obj:?}"
        ))
    })?;

    // Compute tRes (SigmaTyper.scala:97-107).  Every descriptor has an SFunc
    // stype (SFuncSpec), so the SFunc branch always applies.
    let t_meth = &method.stype;
    let t_this = t_meth.dom.first().cloned().unwrap_or(SType::SAny); // dom[0] is always the receiver in practice
    let spec = match unify_types(&t_this, &t_obj) {
        Some(subst) if !subst.is_empty() => apply_subst_func(t_meth, &subst),
        _ => t_meth.clone(),
    };
    let t_res = if spec.dom.len() == 1 && spec.tpe_params.is_empty() {
        // property / nullary method -> tRange
        spec.range.clone()
    } else {
        // function type: drop the receiver, keep remaining args (consumed by Apply).
        // Carry the method's remaining type parameters onto the printed function type
        // so an *unapplied* polymorphic method value renders its `[T]`/`[OV]` binder
        // (oracle: `Coll(1,2,3).map` → `[OV]((Int) => OV) => Coll[OV]`; `SELF.R4` →
        // `[T]() => Option[T]`).  When the method is applied, the enclosing Apply
        // consumes this Select and substitutes the params away.
        SType::SFunc {
            dom: spec.dom_tail().to_vec(),
            range: Box::new(spec.range.clone()),
            tpe_params: spec.tpe_params.clone(),
        }
    };
    let t_res_is_func = matches!(t_res, SType::SFunc { .. });

    // Node choice (SigmaTyper.scala:108-119).
    if method.has_ir_builder && !t_res_is_func {
        // Parameter-less property with a lowering builder.  Custom irBuilders
        // lower to dedicated nodes (SOption.get -> OptionGet, isDefined ->
        // OptionIsDefined); every other property survives as MethodCall (the golden
        // seed shows box/context/avltree/header properties as `%Owner.name [] {}`).
        // Cast methods (toByte..) and SCollection.size have has_ir_builder=false
        // and take the Select branch below (they stay Select until GraphBuilding).
        Ok(lower_method(
            &t_obj,
            &field,
            new_obj,
            vec![],
            t_res,
            ctx.tree_version,
        ))
    } else {
        // Select survives: numeric cast methods (no irBuilder) and method-with-args
        // carriers (tRes.isFunc), consumed by an enclosing Apply (Task 6).
        Ok(TypedExpr::Select {
            obj: Box::new(new_obj),
            field,
            res_type: Some(t_res.clone()),
            tpe: t_res,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.6 Lambda
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn assign_lambda(
    env: &TypeEnv,
    tpe_params: Vec<crate::typed::STypeParam>,
    args: Vec<(String, SType)>,
    given_res_type: SType,
    body: Option<Box<TypedExpr>>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // Args must be fully annotated (SigmaTyper.scala:125-127).
    for (name, arg_t) in &args {
        if *arg_t == SType::NoType {
            return Err(TyperError::typer(format!(
                "Invalid function: undefined type of argument {name}"
            )));
        }
    }
    // lambdaEnv = env ++ args (SigmaTyper.scala:128)
    let mut lambda_env = env.clone();
    for (name, arg_t) in &args {
        lambda_env.insert(name.clone(), arg_t.clone());
    }
    let new_body = match body {
        Some(b) => Some(Box::new(assign_type(&lambda_env, *b, ctx)?)),
        None => None,
    };
    // Declared-result check (SigmaTyper.scala:130-133).
    if given_res_type != SType::NoType {
        if let Some(b) = &new_body {
            if given_res_type != *node_tpe(b) {
                return Err(TyperError::typer(format!(
                    "Invalid function: resulting expression type {:?} doesn't equal declared type {given_res_type:?}",
                    node_tpe(b)
                )));
            }
        }
    }
    // mkGenLambda: resultType = newBody.fold(t)(_.tpe) (SigmaTyper.scala:134).
    let result_type = match &new_body {
        Some(b) => node_tpe(b).clone(),
        None => given_res_type,
    };
    let tpe = SType::SFunc {
        dom: args.iter().map(|(_, t)| t.clone()).collect(),
        range: Box::new(result_type.clone()),
        tpe_params: vec![],
    };
    Ok(TypedExpr::Lambda {
        tpe_params,
        args,
        given_res_type: result_type,
        body: new_body,
        tpe,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.13 If, §1.14 AND/OR, §1.19 Exponentiate, §1.20 ByIndex
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn assign_if(
    env: &TypeEnv,
    c: TypedExpr,
    t: TypedExpr,
    e: TypedExpr,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let c1 = assign_type(env, c, ctx)?;
    let t1 = assign_type(env, t, ctx)?;
    let e1 = assign_type(env, e, ctx)?;
    let tpe = node_tpe(&t1).clone(); // If.tpe = trueBranch.tpe
                                     // Condition check first, then branch-equality (SigmaTyper.scala:445-448).
    if !matches!(node_tpe(&c1), SType::SBoolean) {
        return Err(TyperError::typer(format!(
            "Invalid type of condition in If: expected Boolean; actual: {:?}",
            node_tpe(&c1)
        )));
    }
    if node_tpe(&t1) != node_tpe(&e1) {
        return Err(TyperError::typer(format!(
            "Invalid type of condition If: both branches should have the same type but was {:?} and {:?}",
            node_tpe(&t1),
            node_tpe(&e1)
        )));
    }
    Ok(TypedExpr::If {
        condition: Box::new(c1),
        true_branch: Box::new(t1),
        false_branch: Box::new(e1),
        tpe,
    })
}

pub(crate) fn assign_and_or(
    env: &TypeEnv,
    input: TypedExpr,
    is_and: bool,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let input1 = assign_type(env, input, ctx)?;
    // require input1.tpe.isCollection && elemType == SBoolean (SigmaTyper.scala:453/459)
    let ok = matches!(node_tpe(&input1), SType::SColl(e) if **e == SType::SBoolean);
    if !ok {
        let opn = if is_and { "AND" } else { "OR" };
        return Err(TyperError::typer(format!(
            "Invalid operation {opn}: {:?}",
            node_tpe(&input1)
        )));
    }
    Ok(if is_and {
        TypedExpr::AND {
            input: Box::new(input1),
            tpe: SType::SBoolean,
        }
    } else {
        TypedExpr::OR {
            input: Box::new(input1),
            tpe: SType::SBoolean,
        }
    })
}

pub(crate) fn assign_exponentiate(
    env: &TypeEnv,
    ctx: &TyperCtx,
    left: TypedExpr,
    right: TypedExpr,
) -> Result<TypedExpr, TyperError> {
    let l1 = assign_type(env, left, ctx)?;
    let r1 = assign_type(env, right, ctx)?;
    // require exactly (SGroupElement, SBigInt) (SigmaTyper.scala:488-489)
    if !matches!(node_tpe(&l1), SType::SGroupElement) || !matches!(node_tpe(&r1), SType::SBigInt) {
        return Err(TyperError::typer(format!(
            "Invalid binary operation Exponentiate: expected argument types (GroupElement, BigInt); actual: ({:?}, {:?})",
            node_tpe(&l1),
            node_tpe(&r1)
        )));
    }
    Ok(TypedExpr::Exponentiate {
        left: Box::new(l1),
        right: Box::new(r1),
        tpe: SType::SGroupElement,
    })
}

pub(crate) fn assign_byindex(
    env: &TypeEnv,
    ctx: &TyperCtx,
    input: TypedExpr,
    index: Box<TypedExpr>,
    default: Option<Box<TypedExpr>>,
) -> Result<TypedExpr, TyperError> {
    let c1 = assign_type(env, input, ctx)?;
    // require isCollectionLike (SigmaTyper.scala:494)
    let elem = match coll_elem(node_tpe(&c1)) {
        Some(e) => e.clone(),
        None => {
            return Err(TyperError::typer(format!(
                "Invalid operation ByIndex: expected Collection argument type; actual: {:?}",
                node_tpe(&c1)
            )))
        }
    };
    // default value type must match the element type (SigmaTyper.scala:497-498).
    // deviation (D-T11): Scala compares typeCode (which ignores type args); we compare
    // structural equality.  ByIndex is not produced by the binder or any in-scope
    // arm — the index/default carry pre-typed children and are passed through
    // un-retyped, exactly as Scala does (SigmaTyper.scala:499).
    // Ledger: lib.rs § "Known M2 deviations" D-T11.
    if let Some(v) = &default {
        if *node_tpe(v) != elem {
            return Err(TyperError::typer(format!(
                "Invalid operation ByIndex: expected default value type ({elem:?}); actual: ({:?})",
                node_tpe(v)
            )));
        }
    }
    Ok(TypedExpr::ByIndex {
        input: Box::new(c1),
        index,
        default,
        tpe: elem,
    })
}
