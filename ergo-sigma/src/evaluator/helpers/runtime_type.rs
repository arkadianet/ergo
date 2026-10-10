//! Runtime value-class checks mirroring the reference interpreter's
//! `SType.isValueOfType` and the receiver casts of reflective method calls.
//! <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/ast/SType.scala#L187-L212>

use ergo_ser::sigma_type::SigmaType;

use crate::evaluator::types::{EvalError, Value};

/// `true` for every carrier the reference represents as a `Coll`. A non-pair
/// tuple is materialized as `Coll[Any]` there.
pub(crate) fn is_coll_value(v: &Value) -> bool {
    matches!(
        v,
        Value::CollGeneric(..)
            | Value::CollLegacyPair(..)
            | Value::CollBool(_)
            | Value::CollBytes(_)
            | Value::Tokens(_)
            | Value::CollInt(_)
            | Value::CollLong(_)
            | Value::CollShort(_)
            | Value::CollSigmaProp(_)
            | Value::CollBox(_)
            | Value::CollHeader(_)
            | Value::BoxCollection(_)
    ) || matches!(v, Value::Tuple(items) if items.len() != 2)
}

fn is_box_value(v: &Value) -> bool {
    matches!(
        v,
        Value::SelfBox | Value::BoxRef { .. } | Value::InlineBox(_)
    )
}

/// Scala `Value.checkType(tpe, value)`: a shallow class test of `value`
/// against `tpe`. Types without a case there (`SAny`, type variables,
/// `SString`, non-pair tuples, multi-argument functions, `SUnsignedBigInt`
/// in a pre-v3 tree) throw whatever the value.
pub(crate) fn check_value_type(tpe: &SigmaType, v: &Value, v3_tree: bool) -> Result<(), EvalError> {
    let ok = match tpe {
        SigmaType::SBoolean => matches!(v, Value::Bool(_)),
        SigmaType::SByte => matches!(v, Value::Byte(_)),
        SigmaType::SShort => matches!(v, Value::Short(_)),
        SigmaType::SInt => matches!(v, Value::Int(_)),
        SigmaType::SLong => matches!(v, Value::Long(_)),
        SigmaType::SBigInt => matches!(v, Value::BigInt(_)),
        SigmaType::SUnsignedBigInt if v3_tree => matches!(v, Value::UnsignedBigInt(_)),
        SigmaType::SGroupElement => matches!(v, Value::GroupElement(_)),
        SigmaType::SSigmaProp => matches!(v, Value::SigmaProp(_)),
        SigmaType::SBox => is_box_value(v),
        SigmaType::SColl(_) => is_coll_value(v),
        SigmaType::SOption(_) => matches!(v, Value::Opt(_)),
        SigmaType::STuple(items) if items.len() == 2 => {
            matches!(v, Value::Tuple(items) if items.len() == 2)
        }
        SigmaType::SFunc { t_dom, .. } if t_dom.len() == 1 => matches!(v, Value::Func { .. }),
        SigmaType::SContext => matches!(v, Value::Context),
        SigmaType::SAvlTree => matches!(v, Value::AvlTree(_)),
        SigmaType::SGlobal => matches!(v, Value::Global),
        SigmaType::SHeader => matches!(v, Value::Header(_)),
        SigmaType::SPreHeader => matches!(v, Value::PreHeader),
        SigmaType::SUnit => matches!(v, Value::Unit),
        SigmaType::SString => return Err(EvalError::RuntimeException("Unknown type SString")),
        _ => {
            return Err(EvalError::RuntimeException(
                "Value.checkType: type without a runtime class",
            ))
        }
    };
    if ok {
        Ok(())
    } else {
        Err(EvalError::TypeError {
            expected: "value of the static type (Value.checkType)",
            got: format!("{tpe:?} vs {}", value_class(v)),
        })
    }
}

fn value_class(v: &Value) -> &'static str {
    match v {
        Value::Unit => "Unit",
        Value::Byte(_) => "Byte",
        Value::Short(_) => "Short",
        Value::Int(_) => "Int",
        Value::Long(_) => "Long",
        Value::BigInt(_) => "BigInt",
        Value::UnsignedBigInt(_) => "UnsignedBigInt",
        Value::Bool(_) => "Boolean",
        Value::Str(_) => "String",
        Value::SigmaProp(_) => "SigmaProp",
        Value::Tuple(_) => "Tuple",
        Value::GroupElement(_) => "GroupElement",
        Value::Opt(_) => "Option",
        Value::Global => "Global",
        Value::Context => "Context",
        Value::PreHeader => "PreHeader",
        Value::AvlTree(_) => "AvlTree",
        Value::Header(_) => "Header",
        Value::Func { .. } => "Function",
        v if is_box_value(v) => "Box",
        _ => "Coll",
    }
}

/// Whether `v` is an instance of the class declaring the methods of
/// `type_id`. Reflective invocation (`RMethod.invoke`) and the numeric
/// methods' `obj.asInstanceOf[T]` both throw on any other receiver.
/// Unknown type ids are not checked here.
pub(crate) fn receiver_matches(type_id: u8, v: &Value) -> bool {
    match type_id {
        2 => matches!(v, Value::Byte(_)),
        3 => matches!(v, Value::Short(_)),
        4 => matches!(v, Value::Int(_)),
        5 => matches!(v, Value::Long(_)),
        6 => matches!(v, Value::BigInt(_)),
        7 => matches!(v, Value::GroupElement(_)),
        8 => matches!(v, Value::SigmaProp(_)),
        9 => matches!(v, Value::UnsignedBigInt(_)),
        12 => is_coll_value(v),
        36 => matches!(v, Value::Opt(_)),
        99 => is_box_value(v),
        100 => matches!(v, Value::AvlTree(_)),
        101 => matches!(v, Value::Context),
        104 => matches!(v, Value::Header(_)),
        105 => matches!(v, Value::PreHeader),
        106 => matches!(v, Value::Global),
        _ => true,
    }
}

/// Reject a method receiver whose class does not declare the method.
pub(crate) fn check_receiver(type_id: u8, method_id: u8, v: &Value) -> Result<(), EvalError> {
    if receiver_matches(type_id, v) {
        Ok(())
    } else {
        Err(EvalError::TypeError {
            expected: "method receiver of the declaring type",
            got: format!("({type_id}, {method_id}) on {}", value_class(v)),
        })
    }
}
