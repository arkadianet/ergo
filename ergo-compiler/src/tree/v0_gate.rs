use ergo_ser::opcode::{Expr, IrNode};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use super::*;

/// Scala-faithful predicate for constant DATA the v0 wire header cannot
/// carry: `CoreDataSerializer.serialize` (v6.0.2) gates `SUnsignedBigInt`
/// (`:39`) and `SOption` (`:78`) data on `isV3OrLaterErgoTreeVersion` — under
/// the compile route's pinned `treeVersion = 0` both fall through to the
/// `:86` `SerializerException` catch-all. Collections/tuples recurse per
/// ELEMENT: an EMPTY `Coll[UnsignedBigInt]` constant WRITES fine on both
/// sides — only element DATA hits the gated arm; the TYPE-code write is
/// ungated (`TypeSerializer.serialize`, `case p: SEmbeddable =>
/// w.put(p.typeCode)`) — but the version-gated READ side refuses such bytes,
/// which is what the post-write self-check in [`compile`] catches (lib.rs
/// D-C6 item 5; the `.size` fold usually keeps the type code off the wire
/// entirely, D-C6 item 4). `SHeader` data is likewise v3-gated
/// (`DataSerializer.scala`), included for completeness though unreachable
/// from ErgoScript source.
fn v0_unserializable_data(tpe: &SigmaType, val: &SigmaValue) -> Option<&'static str> {
    match (tpe, val) {
        (SigmaType::SUnsignedBigInt, _) => Some("UnsignedBigInt constant data"),
        (SigmaType::SOption(_), _) | (_, SigmaValue::Opt(_)) => Some("Option constant data"),
        (SigmaType::SHeader, _) => Some("Header constant data"),
        (SigmaType::SColl(el), SigmaValue::Coll(CollValue::Values(items))) => {
            items.iter().find_map(|v| v0_unserializable_data(el, v))
        }
        (SigmaType::STuple(ts), SigmaValue::Tuple(vs)) => ts
            .iter()
            .zip(vs)
            .find_map(|(t, v)| v0_unserializable_data(t, v)),
        _ => None,
    }
}

/// Walk an emitted body for constants whose DATA cannot serialize under the
/// v0 header (see the gate comment in [`compile`]). Returns a description
/// of the first offender, or `None` when the tree is v0-clean.
pub(crate) fn find_v0_unserializable(expr: &Expr) -> Option<String> {
    let mut stack = vec![expr];
    while let Some(e) = stack.pop() {
        match e {
            Expr::Const { tpe, val } => {
                if let Some(what) = v0_unserializable_data(tpe, val) {
                    return Some(what.to_string());
                }
            }
            // Never produced by emit (soft-fork wrapper for UNPARSED wire
            // trees only) — nothing to scan.
            Expr::Unparsed(_) => {}
            Expr::Op(IrNode { payload, .. }) => push_children(payload, &mut stack),
        }
    }
    None
}
