use ergo_ser::opcode::{Expr, Payload};

/// Push every child expression of `payload` onto `stack` — the exhaustive
/// child map of [`Payload`] (a new child-carrying variant fails to compile
/// here until it is mapped).
pub(crate) fn push_children<'a>(payload: &'a Payload, stack: &mut Vec<&'a Expr>) {
    match payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => {}
        Payload::One(a) | Payload::NumericCast { input: a, .. } => stack.push(a),
        Payload::Two(a, b) => stack.extend([a.as_ref(), b.as_ref()]),
        Payload::Three(a, b, c) => stack.extend([a.as_ref(), b.as_ref(), c.as_ref()]),
        Payload::Four(a, b, c, d) => stack.extend([a.as_ref(), b.as_ref(), c.as_ref(), d.as_ref()]),
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => stack.push(rhs),
        Payload::BlockValue { items, result } => {
            stack.extend(items.iter());
            stack.push(result);
        }
        Payload::FuncValue { body, .. } => stack.push(body),
        Payload::MethodCall { obj, args, .. } => {
            stack.push(obj);
            stack.extend(args.iter());
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => stack.extend(items.iter()),
        Payload::SelectField { input, .. } | Payload::ExtractRegisterAs { input, .. } => {
            stack.push(input)
        }
        Payload::DeserializeRegister { default, .. } => {
            if let Some(d) = default {
                stack.push(d);
            }
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            stack.extend([input.as_ref(), index.as_ref()]);
            if let Some(d) = default {
                stack.push(d);
            }
        }
        Payload::FuncApply { func, args } => {
            stack.push(func);
            stack.extend(args.iter());
        }
    }
}
