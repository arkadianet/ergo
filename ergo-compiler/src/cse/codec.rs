use ergo_primitives::writer::VlqWriter;
use ergo_ser::opcode::{Expr, Payload};
use ergo_ser::sigma_type::{write_type, SigmaType};

pub(crate) fn boxn(it: &mut dyn Iterator<Item = Expr>) -> Box<Expr> {
    Box::new(
        it.next()
            .expect("recompose: fewer rebuilt children than the template"),
    )
}

pub(crate) fn takev(it: &mut dyn Iterator<Item = Expr>, n: usize) -> Vec<Expr> {
    (0..n)
        .map(|_| {
            it.next()
                .expect("recompose: fewer rebuilt children than the template")
        })
        .collect()
}

/// EXHAUSTIVE inverse of [`decompose`]: rebuild a `Payload` from its template
/// (scalar fields) and the rebuilt children `it` yields in `decompose` child
/// order. A `_ =>` arm is FORBIDDEN — a new child-carrying `Payload` variant must
/// fail to compile here, mirroring [`decompose`]'s own exhaustiveness discipline
/// (a mismatch would silently drop or misplace a child). The child COUNT and
/// ORDER for each variant match [`decompose`] exactly.
pub(crate) fn recompose(template: &Payload, it: &mut dyn Iterator<Item = Expr>) -> Payload {
    match template {
        Payload::Zero => Payload::Zero,
        Payload::One(_) => Payload::One(boxn(it)),
        Payload::Two(_, _) => Payload::Two(boxn(it), boxn(it)),
        Payload::Three(_, _, _) => Payload::Three(boxn(it), boxn(it), boxn(it)),
        Payload::Four(_, _, _, _) => Payload::Four(boxn(it), boxn(it), boxn(it), boxn(it)),
        Payload::ValUse { id } => Payload::ValUse { id: *id },
        Payload::ConstPlaceholder { index } => Payload::ConstPlaceholder { index: *index },
        Payload::TaggedVar { id, tpe } => Payload::TaggedVar {
            id: *id,
            tpe: tpe.clone(),
        },
        Payload::ValDef { id, tpe, .. } => Payload::ValDef {
            id: *id,
            tpe: tpe.clone(),
            rhs: boxn(it),
        },
        Payload::FunDef {
            id, tpe, tpe_args, ..
        } => Payload::FunDef {
            id: *id,
            tpe: tpe.clone(),
            tpe_args: tpe_args.clone(),
            rhs: boxn(it),
        },
        Payload::BlockValue { items, .. } => {
            let n = items.len();
            let items = takev(it, n);
            Payload::BlockValue {
                items,
                result: boxn(it),
            }
        }
        Payload::FuncValue { args, .. } => Payload::FuncValue {
            args: args.clone(),
            body: boxn(it),
        },
        Payload::MethodCall {
            type_id,
            method_id,
            args,
            type_args,
            ..
        } => {
            let obj = boxn(it);
            let n = args.len();
            let args = takev(it, n);
            Payload::MethodCall {
                type_id: *type_id,
                method_id: *method_id,
                obj,
                args,
                type_args: type_args.clone(),
            }
        }
        Payload::ConcreteCollection { elem_type, items } => {
            let n = items.len();
            Payload::ConcreteCollection {
                elem_type: elem_type.clone(),
                items: takev(it, n),
            }
        }
        Payload::BoolCollection { bits } => Payload::BoolCollection { bits: bits.clone() },
        Payload::Tuple { items } => {
            let n = items.len();
            Payload::Tuple {
                items: takev(it, n),
            }
        }
        Payload::SelectField { field_idx, .. } => Payload::SelectField {
            input: boxn(it),
            field_idx: *field_idx,
        },
        Payload::ExtractRegisterAs { reg_id, tpe, .. } => Payload::ExtractRegisterAs {
            input: boxn(it),
            reg_id: *reg_id,
            tpe: tpe.clone(),
        },
        Payload::GetVar { var_id, tpe } => Payload::GetVar {
            var_id: *var_id,
            tpe: tpe.clone(),
        },
        Payload::DeserializeContext { id, tpe } => Payload::DeserializeContext {
            id: *id,
            tpe: tpe.clone(),
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id: *reg_id,
            tpe: tpe.clone(),
            default: default.as_ref().map(|_| boxn(it)),
        },
        Payload::SigmaCollection { items } => {
            let n = items.len();
            Payload::SigmaCollection {
                items: takev(it, n),
            }
        }
        Payload::NoneValue { tpe } => Payload::NoneValue { tpe: tpe.clone() },
        Payload::ByIndex { default, .. } => {
            let input = boxn(it);
            let index = boxn(it);
            Payload::ByIndex {
                input,
                index,
                default: default.as_ref().map(|_| boxn(it)),
            }
        }
        Payload::NumericCast { tpe, .. } => Payload::NumericCast {
            input: boxn(it),
            tpe: tpe.clone(),
        },
        Payload::FuncApply { args, .. } => {
            let func = boxn(it);
            let n = args.len();
            Payload::FuncApply {
                func,
                args: takev(it, n),
            }
        }
    }
}

/// EXHAUSTIVE decomposition of a payload into `(ordered child expressions,
/// canonical scalar-literal bytes)`. This is the single child-and-literal
/// walker; a `_ =>` arm is FORBIDDEN (cannonQ A.6) — a missed variant would
/// silently drop a node from interning, so a new `Payload` variant must fail to
/// compile here. All scalar encodings are self-delimiting (VLQ ints, framed
/// types), so their fixed-order concatenation is unambiguous within a class.
pub(crate) fn decompose(payload: &Payload) -> (Vec<&Expr>, Vec<u8>) {
    let mut lw = VlqWriter::new();
    let children: Vec<&Expr> = match payload {
        Payload::Zero => Vec::new(),
        Payload::One(a) => vec![a],
        Payload::Two(a, b) => vec![a, b],
        Payload::Three(a, b, c) => vec![a, b, c],
        Payload::Four(a, b, c, d) => vec![a, b, c, d],
        Payload::ValUse { id } => {
            lw.put_u32(*id);
            Vec::new()
        }
        Payload::ConstPlaceholder { index } => {
            lw.put_u32(*index);
            Vec::new()
        }
        Payload::TaggedVar { id, tpe } => {
            lw.put_u32(*id);
            put_opt_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::ValDef { id, tpe, rhs } => {
            lw.put_u32(*id);
            put_opt_type(&mut lw, tpe);
            vec![rhs]
        }
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => {
            lw.put_u32(*id);
            put_opt_type(&mut lw, tpe);
            put_types(&mut lw, tpe_args);
            vec![rhs]
        }
        Payload::BlockValue { items, result } => {
            let mut v: Vec<&Expr> = items.iter().collect();
            v.push(result);
            v
        }
        Payload::FuncValue { args, body } => {
            put_args(&mut lw, args);
            vec![body]
        }
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => {
            lw.put_u8(*type_id);
            lw.put_u8(*method_id);
            put_types(&mut lw, type_args);
            let mut v: Vec<&Expr> = vec![obj];
            v.extend(args.iter());
            v
        }
        Payload::ConcreteCollection { elem_type, items } => {
            let _ = write_type(&mut lw, elem_type);
            items.iter().collect()
        }
        Payload::BoolCollection { bits } => {
            lw.put_u32(bits.len() as u32);
            for b in bits {
                lw.put_u8(u8::from(*b));
            }
            Vec::new()
        }
        Payload::Tuple { items } => items.iter().collect(),
        Payload::SelectField { input, field_idx } => {
            lw.put_u8(*field_idx);
            vec![input]
        }
        Payload::ExtractRegisterAs { input, reg_id, tpe } => {
            lw.put_u8(*reg_id);
            let _ = write_type(&mut lw, tpe);
            vec![input]
        }
        Payload::GetVar { var_id, tpe } => {
            lw.put_u8(*var_id);
            let _ = write_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::DeserializeContext { id, tpe } => {
            lw.put_u8(*id);
            let _ = write_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => {
            lw.put_u8(*reg_id);
            let _ = write_type(&mut lw, tpe);
            default.as_deref().into_iter().collect()
        }
        Payload::SigmaCollection { items } => items.iter().collect(),
        Payload::NoneValue { tpe } => {
            let _ = write_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            let mut v: Vec<&Expr> = vec![input, index];
            if let Some(d) = default.as_deref() {
                v.push(d);
            }
            v
        }
        Payload::NumericCast { input, tpe } => {
            let _ = write_type(&mut lw, tpe);
            vec![input]
        }
        Payload::FuncApply { func, args } => {
            let mut v: Vec<&Expr> = vec![func];
            v.extend(args.iter());
            v
        }
    };
    (children, lw.result())
}

pub(crate) fn put_opt_type(w: &mut VlqWriter, tpe: &Option<SigmaType>) {
    match tpe {
        Some(t) => {
            w.put_u8(1);
            let _ = write_type(w, t);
        }
        None => w.put_u8(0),
    }
}

pub(crate) fn put_types(w: &mut VlqWriter, types: &[SigmaType]) {
    w.put_u32(types.len() as u32);
    for t in types {
        let _ = write_type(w, t);
    }
}

pub(crate) fn put_args(w: &mut VlqWriter, args: &[(u32, Option<SigmaType>)]) {
    w.put_u32(args.len() as u32);
    for (id, tpe) in args {
        w.put_u32(*id);
        put_opt_type(w, tpe);
    }
}
