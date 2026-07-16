use ergo_primitives::group_element::GroupElement;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

use crate::stype::SType;
use crate::typed::ConstPayload;

use super::EmitError;

/// Map a compiler-domain [`SType`] to the wire-domain [`SigmaType`].
///
/// Mechanical 1:1 for every serializable variant; `SFunc` renames
/// `dom`/`range` → `t_dom`/`t_range` and lifts each `tpe_params` ident into
/// a `SigmaType::STypeVar` (the ergo-ser writer requires exactly that shape,
/// `sigma_type.rs:235-244`). `NoType`/`STypeApply` are compiler-internal and
/// error as [`EmitError::UnresolvedType`].
pub(crate) fn map_type(t: &SType) -> Result<SigmaType, EmitError> {
    Ok(match t {
        // Compiler-internal shapes the typer must eliminate (OQ2 defense).
        SType::NoType => return Err(EmitError::UnresolvedType("NoType".to_string())),
        SType::STypeApply { name, .. } => {
            return Err(EmitError::UnresolvedType(format!("STypeApply({name})")))
        }

        // 1:1 renames (stype.rs:14-56 ↔ sigma_type.rs:70-135).
        SType::SBoolean => SigmaType::SBoolean,
        SType::SByte => SigmaType::SByte,
        SType::SShort => SigmaType::SShort,
        SType::SInt => SigmaType::SInt,
        SType::SLong => SigmaType::SLong,
        SType::SBigInt => SigmaType::SBigInt,
        SType::SUnsignedBigInt => SigmaType::SUnsignedBigInt,
        SType::SGroupElement => SigmaType::SGroupElement,
        SType::SSigmaProp => SigmaType::SSigmaProp,
        SType::SAvlTree => SigmaType::SAvlTree,
        SType::SContext => SigmaType::SContext,
        SType::SGlobal => SigmaType::SGlobal,
        SType::SHeader => SigmaType::SHeader,
        SType::SPreHeader => SigmaType::SPreHeader,
        SType::SString => SigmaType::SString,
        SType::SBox => SigmaType::SBox,
        SType::SUnit => SigmaType::SUnit,
        SType::SAny => SigmaType::SAny,
        SType::STypeVar(name) => SigmaType::STypeVar(name.clone()),

        // Compound shapes recurse.
        SType::SColl(elem) => SigmaType::SColl(Box::new(map_type(elem)?)),
        SType::SOption(elem) => SigmaType::SOption(Box::new(map_type(elem)?)),
        SType::STuple(elems) => {
            SigmaType::STuple(elems.iter().map(map_type).collect::<Result<Vec<_>, _>>()?)
        }

        // SFunc: dom→t_dom, range→t_range, String idents → STypeVar
        // (the ergo-ser writer requires STypeVar tpe_params,
        // sigma_type.rs:235-244).
        SType::SFunc {
            dom,
            range,
            tpe_params,
        } => SigmaType::SFunc {
            t_dom: dom.iter().map(map_type).collect::<Result<Vec<_>, _>>()?,
            t_range: Box::new(map_type(range)?),
            tpe_params: tpe_params
                .iter()
                .map(|ident| SigmaType::STypeVar(ident.clone()))
                .collect(),
        },
    })
}

/// Map a constant payload (+ its node type) to the wire `(type, value)` pair.
///
/// The pair is derived from the payload (the byte-of-record); the node type
/// is cross-checked against it — a mismatch is a typer bug surfaced as
/// [`EmitError::InvalidShape`]. `SUnsignedBigInt` values reuse
/// `SigmaValue::BigInt` on the wire (`write_unsigned_bigint_value` takes the
/// BigInt payload, `sigma_value.rs:225-227`).
pub(crate) fn map_const(p: &ConstPayload, t: &SType) -> Result<(SigmaType, SigmaValue), EmitError> {
    // The typer stores BigInt/UnsignedBigInt canonically via
    // `num_bigint::{BigInt,BigUint}::to_string` (D-T3), so a parse failure
    // here means a hand-built payload bypassed the frontend.
    fn parse_bigint(s: &str) -> Result<num_bigint::BigInt, EmitError> {
        s.parse::<num_bigint::BigInt>().map_err(|_| {
            EmitError::InvalidShape("BigInt constant payload is not a decimal integer")
        })
    }

    let (tpe, val) = match p {
        ConstPayload::Bool(b) => (SigmaType::SBoolean, SigmaValue::Boolean(*b)),
        ConstPayload::Byte(v) => (SigmaType::SByte, SigmaValue::Byte(*v)),
        ConstPayload::Short(v) => (SigmaType::SShort, SigmaValue::Short(*v)),
        ConstPayload::Int(v) => (SigmaType::SInt, SigmaValue::Int(*v)),
        ConstPayload::Long(v) => (SigmaType::SLong, SigmaValue::Long(*v)),
        ConstPayload::BigInt(s) => (SigmaType::SBigInt, SigmaValue::BigInt(parse_bigint(s)?)),
        // SUnsignedBigInt reuses the BigInt value on the wire
        // (write_unsigned_bigint_value, sigma_value.rs:225-227).
        ConstPayload::UnsignedBigInt(s) => (
            SigmaType::SUnsignedBigInt,
            SigmaValue::BigInt(parse_bigint(s)?),
        ),
        ConstPayload::String(s) => (SigmaType::SString, SigmaValue::Str(s.clone())),
        ConstPayload::Unit => (SigmaType::SUnit, SigmaValue::Unit),
        // Signed i8 elements reinterpreted as raw wire bytes.
        ConstPayload::ByteColl(bytes) => (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes(bytes.iter().map(|b| *b as u8).collect())),
        ),
        ConstPayload::LongColl(longs) => (
            SigmaType::SColl(Box::new(SigmaType::SLong)),
            SigmaValue::Coll(CollValue::Values(
                longs.iter().map(|v| SigmaValue::Long(*v)).collect(),
            )),
        ),
        // 33-byte SEC1-compressed point, on-curve-checked upstream (D-T5).
        ConstPayload::GroupElement(bytes) => (
            SigmaType::SGroupElement,
            SigmaValue::GroupElement(GroupElement::from_bytes(*bytes)),
        ),
        // Binder PK-rule output — same shape as ergo-ser's own P2PK
        // construction (address.rs:365-368).
        ConstPayload::ProveDlog(pubkey) => (
            SigmaType::SSigmaProp,
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(*pubkey))),
        ),
        // Opaque env-injected sigma proposition: no curve bytes to
        // serialize (module docs + lib.rs ledger entry).
        ConstPayload::SigmaProp(_) => {
            return Err(EmitError::UnsupportedNode(
                "opaque SigmaProp constant payload".to_string(),
            ))
        }
    };

    // Cross-check the payload-derived wire type against the node's assigned
    // type: a mismatch is a typer bug, caught here rather than at write time.
    if map_type(t)? != tpe {
        return Err(EmitError::InvalidShape(
            "constant payload does not match the node's assigned type",
        ));
    }
    Ok((tpe, val))
}
