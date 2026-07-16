//! The typed value renderer — [`decode_value`] maps a parsed [`SigmaValue`]
//! (+ its [`SigmaType`]) into a self-describing `{ "type", "value" }` JSON node.
//! It is the generic layer under both "decode any register" and every family
//! decoder, so it lives here and is re-exported for the script-playground /
//! tx-intelligence groups to reuse.
//!
//! The JSON-safe-integer discipline is obeyed: `Long`/`BigInt` render as
//! strings (they can exceed `2^53`, the largest integer a JSON number
//! round-trips exactly through a JS/JSON parser), `Byte`/`Short`/`Int` as
//! JSON numbers, `Coll[Byte]` as hex. No consensus evaluation happens here —
//! this is pure deserialization + projection.

use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{AvlTreeData, CollValue, SigmaBoolean, SigmaValue};
use serde_json::{json, Value};

/// A stable, lowercase sigma type grammar, e.g. `coll[byte]`,
/// `option[long]`, `(long,coll[byte])`. Chosen once so clients can match on it.
pub fn sigma_type_name(t: &SigmaType) -> String {
    match t {
        SigmaType::SBoolean => "boolean".into(),
        SigmaType::SByte => "byte".into(),
        SigmaType::SShort => "short".into(),
        SigmaType::SInt => "int".into(),
        SigmaType::SLong => "long".into(),
        SigmaType::SBigInt => "bigint".into(),
        SigmaType::SUnsignedBigInt => "unsigned_bigint".into(),
        SigmaType::SGroupElement => "group_element".into(),
        SigmaType::SSigmaProp => "sigma_prop".into(),
        SigmaType::SReserved10 => "reserved_10".into(),
        SigmaType::SReserved11 => "reserved_11".into(),
        SigmaType::SAny => "any".into(),
        SigmaType::SUnit => "unit".into(),
        SigmaType::SBox => "box".into(),
        SigmaType::SAvlTree => "avl_tree".into(),
        SigmaType::SContext => "context".into(),
        SigmaType::SString => "string".into(),
        SigmaType::STypeVar(name) => name.clone(),
        SigmaType::SHeader => "header".into(),
        SigmaType::SPreHeader => "pre_header".into(),
        SigmaType::SGlobal => "global".into(),
        SigmaType::SColl(inner) => format!("coll[{}]", sigma_type_name(inner)),
        SigmaType::SOption(inner) => format!("option[{}]", sigma_type_name(inner)),
        SigmaType::STuple(items) => {
            let parts: Vec<String> = items.iter().map(sigma_type_name).collect();
            format!("({})", parts.join(","))
        }
        SigmaType::SFunc { t_dom, t_range, .. } => {
            let dom: Vec<String> = t_dom.iter().map(sigma_type_name).collect();
            format!("({})=>{}", dom.join(","), sigma_type_name(t_range))
        }
    }
}

/// Render a [`SigmaBoolean`] to a compact structural JSON node (used for
/// `SigmaProp` values). Curve points are surfaced as SEC1-compressed hex.
fn sigma_boolean_json(sb: &SigmaBoolean) -> Value {
    match sb {
        SigmaBoolean::TrivialProp(b) => json!({ "trivial": b }),
        SigmaBoolean::ProveDlog(ge) => {
            json!({ "prove_dlog": hex::encode(ge.as_bytes()) })
        }
        SigmaBoolean::ProveDHTuple { g, h, u, v } => json!({
            "prove_dh_tuple": {
                "g": hex::encode(g.as_bytes()),
                "h": hex::encode(h.as_bytes()),
                "u": hex::encode(u.as_bytes()),
                "v": hex::encode(v.as_bytes()),
            }
        }),
        SigmaBoolean::Cand(children) => {
            json!({ "and": children.iter().map(sigma_boolean_json).collect::<Vec<_>>() })
        }
        SigmaBoolean::Cor(children) => {
            json!({ "or": children.iter().map(sigma_boolean_json).collect::<Vec<_>>() })
        }
        SigmaBoolean::Cthreshold { k, children } => json!({
            "at_least": {
                "k": k,
                "children": children.iter().map(sigma_boolean_json).collect::<Vec<_>>(),
            }
        }),
    }
}

/// Render an [`AvlTreeData`] handle as a structural JSON node.
fn avl_tree_json(t: &AvlTreeData) -> Value {
    json!({
        "digest": hex::encode(&t.digest),
        "insert_allowed": t.insert_allowed,
        "update_allowed": t.update_allowed,
        "remove_allowed": t.remove_allowed,
        "key_length": t.key_length,
        "value_length": t.value_length_opt,
    })
}

/// Map a [`SigmaValue`] to its JSON body (the `value` half of a `DecodedValue`).
fn sigma_value_json(v: &SigmaValue) -> Value {
    match v {
        SigmaValue::Unit => Value::Null,
        SigmaValue::Boolean(b) => Value::Bool(*b),
        // Small ints fit a JSON number safely (< 2^53).
        SigmaValue::Byte(n) => json!(*n),
        SigmaValue::Short(n) => json!(*n),
        SigmaValue::Int(n) => json!(*n),
        // 64-bit + arbitrary precision must be strings.
        SigmaValue::Long(n) => Value::String(n.to_string()),
        SigmaValue::BigInt(n) => Value::String(n.to_string()),
        SigmaValue::Str(s) => Value::String(s.clone()),
        SigmaValue::GroupElement(ge) => Value::String(hex::encode(ge.as_bytes())),
        SigmaValue::SigmaProp(sb) => sigma_boolean_json(sb),
        SigmaValue::AvlTree(t) => avl_tree_json(t),
        SigmaValue::OpaqueBoxBytes(bytes) => Value::String(hex::encode(bytes)),
        // Canonical serialized header bytes — Debug output is not a stable
        // wire shape. (Defensive: consensus rejects Header-typed register /
        // context constants at every version, so real boxes never reach this.)
        SigmaValue::Header(h) => {
            let mut w = ergo_primitives::writer::VlqWriter::new();
            match ergo_ser::header::write_header(&mut w, h) {
                Ok(()) => Value::String(hex::encode(w.result())),
                Err(_) => Value::Null,
            }
        }
        SigmaValue::Coll(c) => match c {
            CollValue::Bytes(bytes) => Value::String(hex::encode(bytes)),
            CollValue::BoolBits(bits) => Value::Array(bits.iter().map(|b| json!(*b)).collect()),
            CollValue::Values(vs) => Value::Array(vs.iter().map(sigma_value_json).collect()),
        },
        SigmaValue::Opt(inner) => match inner {
            Some(v) => sigma_value_json(v),
            None => Value::Null,
        },
        SigmaValue::Tuple(items) => Value::Array(items.iter().map(sigma_value_json).collect()),
    }
}

/// Render a typed constant `(SigmaType, SigmaValue)` into the shared
/// `DecodedValue` node: `{ "type": "<grammar>", "value": <json> }`.
pub fn decode_value(tpe: &SigmaType, val: &SigmaValue) -> Value {
    json!({
        "type": sigma_type_name(tpe),
        "value": sigma_value_json(val),
    })
}
