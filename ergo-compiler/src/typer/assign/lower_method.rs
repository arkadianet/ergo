use crate::stype::SType;
use crate::typed::{MethodRef, TypedExpr};
use crate::typer::methods::owner_name_for_method;

/// The shared method/property irBuilder lowering catalog.
///
/// Maps custom-irBuilder methods to their dedicated typed nodes; everything else
/// (MethodCallIrBuilder) falls back to `MethodCall(obj, %Owner.name, args, {})`.
/// Keyed on `(receiver type, method name)` — receiver-specific because e.g.
/// `SCollection.map` lowers to `MapCollection` while `SOption.map` survives as a
/// MethodCall (seed line 21 vs 107).  `ret` is the method's specialized return
/// type.  Used by §1.5 (properties, `args = []`) and §1.8 (methods with args).
pub(crate) fn lower_method(
    recv: &SType,
    name: &str,
    obj: TypedExpr,
    args: Vec<TypedExpr>,
    ret: SType,
    tree_version: u8,
) -> TypedExpr {
    let b = Box::new;
    let mut it = args.clone().into_iter();
    match (recv, name) {
        // ── SGlobal custom irBuilders (method-on-Global receiver form) ────────
        // `Global.groupGenerator` → GroupGenerator, `Global.xor(a,b)` → Xor — the two
        // SGlobal methods with dedicated-node irBuilders (methods.scala:595).  The
        // predef-FUNCTION forms `groupGenerator`/`xor(a,b)` lower via
        // `process_global_method`; this arm matches the receiver-method dispatch.  All
        // other SGlobal methods (serialize/some/none/...) are MethodCallIrBuilder and
        // fall through to the generic MethodCall below.
        (SType::SGlobal, "groupGenerator") => TypedExpr::GroupGenerator { tpe: ret },
        (SType::SGlobal, "xor") => {
            let left = it.next().expect("Global.xor left arg");
            let right = it.next().expect("Global.xor right arg");
            TypedExpr::Xor {
                left: b(left),
                right: b(right),
                tpe: ret,
            }
        }
        // ── SOption custom irBuilders ─────────────────────────────────────────
        (SType::SOption(_), "get") => TypedExpr::OptionGet {
            input: b(obj),
            tpe: ret,
        },
        (SType::SOption(_), "isDefined") => TypedExpr::OptionIsDefined {
            input: b(obj),
            tpe: ret,
        },
        (SType::SOption(_), "getOrElse") => TypedExpr::OptionGetOrElse {
            input: b(obj),
            default: b(it.next().expect("getOrElse arg")),
            tpe: ret,
        },
        // ── SCollection custom irBuilders ─────────────────────────────────────
        (SType::SColl(_), "map") => TypedExpr::MapCollection {
            input: b(obj),
            mapper: b(it.next().expect("map arg")),
            tpe: ret,
        },
        (SType::SColl(_), "filter") => TypedExpr::Filter {
            input: b(obj),
            condition: b(it.next().expect("filter arg")),
            tpe: ret,
        },
        (SType::SColl(_), "exists") => TypedExpr::Exists {
            input: b(obj),
            condition: b(it.next().expect("exists arg")),
            tpe: ret,
        },
        (SType::SColl(_), "forall") => TypedExpr::ForAll {
            input: b(obj),
            condition: b(it.next().expect("forall arg")),
            tpe: ret,
        },
        (SType::SColl(_), "fold") => {
            let zero = it.next().expect("fold zero");
            let fold_op = it.next().expect("fold op");
            TypedExpr::Fold {
                input: b(obj),
                zero: b(zero),
                fold_op: b(fold_op),
                tpe: ret,
            }
        }
        (SType::SColl(_), "slice") => {
            let from = it.next().expect("slice from");
            let until = it.next().expect("slice until");
            TypedExpr::Slice {
                input: b(obj),
                from: b(from),
                until: b(until),
                tpe: ret,
            }
        }
        (SType::SColl(_), "append") => TypedExpr::Append {
            input: b(obj),
            col2: b(it.next().expect("append arg")),
            tpe: ret,
        },
        (SType::SColl(_), "getOrElse") => {
            let index = it.next().expect("getOrElse index");
            let default = it.next().expect("getOrElse default");
            TypedExpr::ByIndex {
                input: b(obj),
                index: b(index),
                default: Some(b(default)),
                tpe: ret,
            }
        }
        // ── SGroupElement custom irBuilders ──────────────────────────────────
        (SType::SGroupElement, "exp") => TypedExpr::Exponentiate {
            left: b(obj),
            right: b(it.next().expect("exp arg")),
            tpe: ret,
        },
        (SType::SGroupElement, "multiply") => TypedExpr::MultiplyGroup {
            left: b(obj),
            right: b(it.next().expect("multiply arg")),
            tpe: ret,
        },
        // ── everything else: MethodCall(obj, %Owner.name, args, {}) ──────────
        _ => {
            // B4: numeric toBytes/toBits print `%SNumericType.<m>` at tree_version < 3
            // (shared SNumericTypeMethods container), concrete `%Int.<m>` at V6.
            let owner = owner_name_for_method(recv, name, tree_version);
            TypedExpr::MethodCall {
                obj: b(obj),
                method: MethodRef {
                    owner: owner.to_string(),
                    name: name.to_string(),
                },
                args,
                type_subst: vec![],
                tpe: ret,
            }
        }
    }
}
