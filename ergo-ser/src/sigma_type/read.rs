//! Deserialization direction of the sigma type-descriptor codec:
//! [`read_type`] / [`decode_type`] and the depth-tracked recursive
//! decoders enforcing `MAX_TYPE_DEPTH`.

use ergo_primitives::reader::{ReadError, VlqReader};

use super::{
    embeddable_gate_version, prim_from_code, SigmaType, FUNC_CODE, MAX_TYPE_DEPTH, PRIM_RANGE,
    SANY_CODE, SAVL_TREE_CODE, SBOX_CODE, SCONTEXT_CODE, SGLOBAL_CODE, SHEADER_CODE,
    SPREHEADER_CODE, SSTRING_CODE, STYPEVAR_CODE, SUNIT_CODE, TUPLE_CODE,
};

/// Deserialize a Sigma type descriptor.
///
/// Iterative: nesting is tracked on a heap stack of `Frame`s rather than the
/// native stack, so a descriptor as deep as `MAX_TYPE_DEPTH` allows cannot
/// overflow the reader. Items are read in exactly the order Scala's recursive
/// `TypeSerializer.deserialize` reads them, and every error is raised at the
/// same point of that order.
pub fn read_type(r: &mut VlqReader) -> Result<SigmaType, ReadError> {
    let byte = r.get_u8()?;
    decode_type(r, byte)
}

/// Decode a type descriptor given the first byte already consumed.
/// Public so the opcode parser can decode inline constant types.
pub fn decode_type(r: &mut VlqReader, first: u8) -> Result<SigmaType, ReadError> {
    let gate_v = embeddable_gate_version(r);
    let mut stack: Vec<Frame> = Vec::new();
    let mut byte = first;
    let mut depth = 0usize;
    loop {
        let mut done = match decode_one(r, byte, depth, gate_v)? {
            Step::Done(t) => t,
            Step::Open(frame) => {
                depth = frame.child_depth;
                stack.push(frame);
                byte = read_type_byte(r, depth)?;
                continue;
            }
        };
        // Hand the finished type to its parent; close every parent it completes.
        loop {
            let Some(mut frame) = stack.pop() else {
                return Ok(done);
            };
            match frame.accept(r, done, gate_v)? {
                Some(t) => done = t,
                None => {
                    depth = frame.child_depth;
                    stack.push(frame);
                    byte = read_type_byte(r, depth)?;
                    break;
                }
            }
        }
    }
}

/// Read the byte that starts a nested type at `depth`, after checking the
/// depth guard.
fn read_type_byte(r: &mut VlqReader, depth: usize) -> Result<u8, ReadError> {
    if depth > MAX_TYPE_DEPTH {
        // DeserializeCallDepthExceeded is a SerializerException, not a
        // ValidationException: hard at every boundary, including sized trees.
        // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/serialization/TypeSerializer.scala#L134-L137
        return Err(ReadError::DepthLimitExceeded {
            max: MAX_TYPE_DEPTH,
        });
    }
    r.get_u8()
}

/// The outcome of decoding one type byte: a complete type, or a compound
/// type still waiting for its children.
enum Step {
    Done(SigmaType),
    Open(Frame),
}

/// A compound type whose children are still being read.
struct Frame {
    /// Depth at which this frame's children are read.
    child_depth: usize,
    kind: FrameKind,
}

enum FrameKind {
    /// `Coll[T]` (0x0C), `Coll[Coll[T]]` (0x18), `Option[T]` (0x24) or
    /// `Option[Coll[T]]` (0x30) with a non-embeddable `T`: wrap the one child.
    Wrap(fn(SigmaType) -> SigmaType),
    /// A tuple collecting `remaining` more items. `then_prim` is the compact
    /// pair `(T, prim)` (0x48 + prim): its embeddable second item is decoded
    /// only after the first item has been read.
    Tuple {
        items: Vec<SigmaType>,
        remaining: usize,
        then_prim: Option<u8>,
    },
    /// `SFunc`: domain items, then the range, then the type parameters.
    Func {
        t_dom: Vec<SigmaType>,
        remaining_dom: usize,
        t_range: Option<Box<SigmaType>>,
        tpe_params: Vec<SigmaType>,
        remaining_params: usize,
    },
}

impl Frame {
    /// Take one finished child. Returns the completed type when this was the
    /// frame's last child, or `None` when another child must be read.
    fn accept(
        &mut self,
        r: &mut VlqReader,
        child: SigmaType,
        gate_v: u8,
    ) -> Result<Option<SigmaType>, ReadError> {
        match &mut self.kind {
            FrameKind::Wrap(wrap) => Ok(Some(wrap(child))),
            FrameKind::Tuple {
                items,
                remaining,
                then_prim,
            } => {
                items.push(child);
                *remaining -= 1;
                if *remaining > 0 {
                    return Ok(None);
                }
                if let Some(prim_id) = then_prim.take() {
                    items.push(prim_from_code(prim_id, gate_v)?);
                }
                Ok(Some(SigmaType::STuple(std::mem::take(items))))
            }
            FrameKind::Func {
                t_dom,
                remaining_dom,
                t_range,
                tpe_params,
                remaining_params,
            } => {
                if *remaining_dom > 0 {
                    t_dom.push(child);
                    *remaining_dom -= 1;
                    return Ok(None);
                }
                if t_range.is_none() {
                    *t_range = Some(Box::new(child));
                    *remaining_params = r.get_u8()? as usize;
                } else {
                    if !matches!(child, SigmaType::STypeVar(_)) {
                        return Err(ReadError::InvalidData(
                            "SFunc tpeParam must be an STypeVar".into(),
                        ));
                    }
                    tpe_params.push(child);
                    *remaining_params -= 1;
                }
                if *remaining_params > 0 {
                    return Ok(None);
                }
                Ok(Some(SigmaType::SFunc {
                    t_dom: std::mem::take(t_dom),
                    t_range: t_range
                        .take()
                        .expect("the range is read before the parameters"),
                    tpe_params: std::mem::take(tpe_params),
                }))
            }
        }
    }
}

/// A tuple frame expecting `count` items, or the empty tuple at once.
fn open_tuple(child_depth: usize, count: usize) -> Step {
    if count == 0 {
        return Step::Done(SigmaType::STuple(Vec::new()));
    }
    // The items grow as they are read, so an untrusted count reserves
    // nothing up front: a chain of frames each declaring 255 items and
    // opening the next as its first costs the bytes it reads, not
    // 255 slots per level.
    Step::Open(Frame {
        child_depth,
        kind: FrameKind::Tuple {
            items: Vec::new(),
            remaining: count,
            then_prim: None,
        },
    })
}

/// Decode one type byte at `depth`.
fn decode_one(r: &mut VlqReader, byte: u8, depth: usize, gate_v: u8) -> Result<Step, ReadError> {
    let next = depth + 1;
    let done = |t| Ok(Step::Done(t));
    match byte {
        // Scala `TypeSerializer.deserialize` guards `if (c <= 0) throw new
        // InvalidTypePrefix(...)` on EVERY type byte it reads (`getUByte`, so
        // `c <= 0` is exactly `c == 0`). `InvalidTypePrefix` extends
        // `SerializerException`, NOT `ValidationException`, so
        // `deserializeErgoTree`'s catch does not cover it: a size-delimited tree
        // whose body carries a zero type byte is REJECTED outright, never wrapped
        // as `UnparsedErgoTree`. Returning a soft `InvalidData` here funneled it
        // into the generic body-error wrap and accepted a tree the reference
        // rejects (cargo-fuzz #305). Every OTHER unknown type code is a rule-1016
        // `ValidationException` in the reference and stays soft (`InvalidData`)
        // below, so a size-delimited tree still wraps for those.
        0 => Err(ReadError::HardReject(
            "type prefix 0 is not a valid type code (Scala InvalidTypePrefix)".to_string(),
        )),

        // Primitive embeddable types (1..=11), version-gated exactly like Scala's
        // `getEmbeddableType` (embeddableV5 = codes 1..=8 pre-v3; embeddableV6 adds
        // SUnsignedBigInt = code 9 at v3+).
        1..=11 => done(prim_from_code(byte, gate_v)?),

        // Special non-embeddable
        SANY_CODE => done(SigmaType::SAny),
        SUNIT_CODE => done(SigmaType::SUnit),
        SBOX_CODE => done(SigmaType::SBox),
        SAVL_TREE_CODE => done(SigmaType::SAvlTree),
        SCONTEXT_CODE => done(SigmaType::SContext),
        SSTRING_CODE => done(SigmaType::SString),
        STYPEVAR_CODE => {
            // Scala TypeSerializer.scala:203-204 reads the name length as an
            // unsigned byte (anything 0..=255) and decodes the bytes with
            // `new String(bytes, UTF_8)` — the JVM's LOSSY decoder. A strict
            // `from_utf8` here rejected ill-formed names the Scala node
            // accepts (reject-valid on sizeless trees; a too-broad soft-fork
            // placeholder on size-delimited ones), so we mirror the JVM byte
            // for byte. See [`crate::jvm_utf8`].
            let name_len = r.get_u8()? as usize;
            let name_bytes = r.get_bytes(name_len)?;
            done(SigmaType::STypeVar(crate::jvm_utf8::decode(name_bytes)))
        }
        SHEADER_CODE => done(SigmaType::SHeader),
        SPREHEADER_CODE => done(SigmaType::SPreHeader),
        SGLOBAL_CODE => done(SigmaType::SGlobal),

        // ConstrId-based ranges (12..=95)
        b @ 12..=95 => decode_constructor(b, depth, gate_v),

        // General tuple. Scala TypeSerializer.scala:189-192 reads count as a
        // single unsigned byte (max 255) and then reads exactly that many
        // item types — with NO arity check on the way in. Two bugs traced to
        // the same missing-item-read-order root cause here (cargo-fuzz #305
        // follow-up):
        //
        //   - reject-valid: an earlier version of this arm rejected
        //     `count < 2` with a soft `InvalidData` BEFORE reading any item
        //     type. Scala's reader has no such floor — a size-1 (or size-0)
        //     `STuple` type is a normal accept (e.g. `sigmaProp((0,) == (0,))`
        //     embeds `STuple[SInt]`, count=1). Rejecting it diverged from a
        //     tree the reference accepts (a chain-stall class of bug: a block
        //     containing such a tree would be wrongly rejected).
        //   - accept-invalid: because that same check fired before the item
        //     loop ran, a zero type-prefix inside a 1-element (or 0-element)
        //     tuple never reached the per-item read that hard-rejects byte 0
        //     (see the `0 =>` arm above), so it fell through as a soft
        //     `InvalidData` — accepted-and-wrapped on a size-delimited tree the
        //     reference hard-rejects (`InvalidTypePrefix`, a
        //     `SerializerException` outside `deserializeErgoTree`'s catch).
        //
        // Reading every item unconditionally, with no arity floor, fixes
        // both at once: `count` in 0..=255 is always accepted structurally,
        // and a zero prefix at ANY item position (including the only item of
        // a 1-tuple) hits the hard reject before this tuple completes.
        //
        // The writer (`write_tuple`) keeps its own `count >= 2` floor — Scala
        // is asymmetric here: `TypeSerializer.serialize` itself throws
        // writing back a 0- or 1-element `STuple`, so parity requires the
        // node to accept such a type on READ (it can appear inside an
        // existing tree) while still refusing to ORIGINATE one on WRITE.
        TUPLE_CODE => {
            let count = r.get_u8()? as usize;
            Ok(open_tuple(next, count))
        }

        // SFunc: 0x70 + 1-byte domain count + domain types + range type
        // + 1-byte tpeParams count + STypeVar idents. Scala
        // TypeSerializer.scala:212-224 reads counts as unsigned bytes
        // and requires each tpeParam ident to be an STypeVar
        // (`require(ident.isInstanceOf[STypeVar])`).
        // A headerless extension uses the enclosing VersionContext too.
        // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/serialization/TypeSerializer.scala#L214-L228
        FUNC_CODE
            if r.ergo_tree_version()
                .or(r.activated_script_version())
                .is_some_and(|version| (version as i8) < 3) =>
        {
            Err(ReadError::SigmaValidation {
                rule_id: 1008,
                args: vec![FUNC_CODE],
                message: "SFunc type requires ErgoTree version >= 3".into(),
            })
        }
        FUNC_CODE => {
            let dom_count = r.get_u8()? as usize;
            Ok(Step::Open(Frame {
                child_depth: next,
                kind: FrameKind::Func {
                    // Grows as read, like a tuple's items (`open_tuple`).
                    t_dom: Vec::new(),
                    remaining_dom: dom_count,
                    t_range: None,
                    tpe_params: Vec::new(),
                    remaining_params: 0,
                },
            }))
        }

        _ => Err(ReadError::SigmaValidation {
            rule_id: 1008,
            args: vec![byte],
            message: format!("unknown type code: 0x{byte:02X}"),
        }),
    }
}

fn decode_constructor(byte: u8, depth: usize, gate_v: u8) -> Result<Step, ReadError> {
    let constr_id = byte / PRIM_RANGE;
    let prim_id = byte % PRIM_RANGE;
    let next = depth + 1;
    let wrap = |child_depth, wrap| {
        Ok(Step::Open(Frame {
            child_depth,
            kind: FrameKind::Wrap(wrap),
        }))
    };
    let prim = || prim_from_code(prim_id, gate_v);
    let coll = |t| SigmaType::SColl(Box::new(t));
    let option = |t| SigmaType::SOption(Box::new(t));

    match (constr_id, prim_id) {
        // constrId 1: Coll[T]
        (1, 0) => wrap(next, |t| SigmaType::SColl(Box::new(t))),
        (1, _) => Ok(Step::Done(coll(prim()?))),

        // getArgType makes only ONE recursive call, even when the compact
        // constructor creates two collection layers. Embedded primitives make
        // no recursive call at all. Deliberately retain this wire-shape limit.
        // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/serialization/TypeSerializer.scala#L150-L163
        (2, 0) => wrap(next, |t| {
            SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(t))))
        }),
        (2, _) => Ok(Step::Done(coll(coll(prim()?)))),

        // constrId 3: Option[T]
        (3, 0) => wrap(next, |t| SigmaType::SOption(Box::new(t))),
        (3, _) => Ok(Step::Done(option(prim()?))),

        // Option[Coll[T]] also makes just one getArgType recursive call.
        (4, 0) => wrap(next, |t| {
            SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(t))))
        }),
        (4, _) => Ok(Step::Done(option(coll(prim()?)))),

        // constrId 5: general pair (primId 0), or `(prim, T)`: the embeddable
        // first item is decoded before the second is read.
        (5, 0) => Ok(open_tuple(next, 2)),
        (5, _) => {
            let first = prim()?;
            Ok(Step::Open(Frame {
                child_depth: next,
                kind: FrameKind::Tuple {
                    items: vec![first],
                    remaining: 1,
                    then_prim: None,
                },
            }))
        }

        // constrId 6: triple (primId 0), or `(T, prim)`: Scala validates the
        // embedded second type BEFORE recursively reading the first type.
        (6, 0) => Ok(open_tuple(next, 3)),
        (6, _) => {
            prim()?;
            Ok(Step::Open(Frame {
                child_depth: next,
                kind: FrameKind::Tuple {
                    items: Vec::with_capacity(2),
                    remaining: 1,
                    then_prim: Some(prim_id),
                },
            }))
        }

        // constrId 7: quad (primId 0), or the symmetric pair `(prim, prim)`.
        (7, 0) => Ok(open_tuple(next, 4)),
        (7, _) => {
            let t = prim()?;
            Ok(Step::Done(SigmaType::STuple(vec![t.clone(), t])))
        }

        _ => Err(ReadError::InvalidData(format!(
            "unknown type constructor: constrId={constr_id} (byte=0x{byte:02X})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::write_type;
    use ergo_primitives::writer::VlqWriter;

    // ----- helpers -----

    fn encode(t: &SigmaType) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_type(&mut w, t).unwrap();
        w.result()
    }

    fn roundtrip(t: &SigmaType) {
        let bytes = encode(t);
        let mut r = VlqReader::new(&bytes);
        let decoded = read_type(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after decoding {t:?}");
        assert_eq!(&decoded, t);
    }

    // ----- round-trips -----

    #[test]
    fn roundtrip_primitives() {
        for t in [
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SShort,
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SBigInt,
            SigmaType::SGroupElement,
            SigmaType::SSigmaProp,
            SigmaType::SBox,
            SigmaType::SAvlTree,
            SigmaType::SContext,
            SigmaType::SHeader,
            SigmaType::SPreHeader,
        ] {
            roundtrip(&t);
        }
    }

    #[test]
    fn roundtrip_coll_embeddable() {
        for inner in [
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SBigInt,
            SigmaType::SGroupElement,
            SigmaType::SSigmaProp,
        ] {
            roundtrip(&SigmaType::SColl(Box::new(inner)));
        }
    }

    #[test]
    fn roundtrip_coll_nested() {
        // Coll[Coll[Byte]] — constrId 2
        roundtrip(&SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(
            SigmaType::SByte,
        )))));
        // Coll[SBox] — constrId 1, primId 0
        roundtrip(&SigmaType::SColl(Box::new(SigmaType::SBox)));
        roundtrip(&SigmaType::SColl(Box::new(SigmaType::SAvlTree)));
    }

    #[test]
    fn roundtrip_option_embeddable() {
        for inner in [
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SInt,
            SigmaType::SLong,
        ] {
            roundtrip(&SigmaType::SOption(Box::new(inner)));
        }
    }

    #[test]
    fn roundtrip_option_nested() {
        // Option[Coll[Int]] — constrId 4
        roundtrip(&SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(
            SigmaType::SInt,
        )))));
        // Option[SBox] — constrId 3, primId 0
        roundtrip(&SigmaType::SOption(Box::new(SigmaType::SBox)));
    }

    #[test]
    fn roundtrip_pair() {
        roundtrip(&SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]));
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaType::SInt,
        ]));
    }

    #[test]
    fn roundtrip_pair_symmetric() {
        roundtrip(&SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt]));
        roundtrip(&SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong]));
    }

    #[test]
    fn roundtrip_pair_second_embed() {
        roundtrip(&SigmaType::STuple(vec![SigmaType::SBox, SigmaType::SInt]));
    }

    #[test]
    fn roundtrip_nested_pair() {
        // (Int, (Long, Byte))
        let inner = SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SByte]);
        roundtrip(&SigmaType::STuple(vec![SigmaType::SInt, inner]));
    }

    #[test]
    fn roundtrip_triple() {
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SByte,
        ]));
        // Non-embeddable first element
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SBox,
            SigmaType::SInt,
            SigmaType::SLong,
        ]));
    }

    #[test]
    fn roundtrip_quad() {
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SInt,
            SigmaType::SLong,
        ]));
        // Non-embeddable first element
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SAvlTree,
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SByte,
        ]));
    }

    #[test]
    fn roundtrip_general_tuple_5() {
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SShort,
            SigmaType::SInt,
            SigmaType::SLong,
        ]));
    }

    #[test]
    fn roundtrip_func() {
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::SInt],
            t_range: Box::new(SigmaType::SLong),
            tpe_params: vec![],
        });
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::SInt, SigmaType::SLong],
            t_range: Box::new(SigmaType::SBoolean),
            tpe_params: vec![],
        });
        // Non-embeddable domain
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::SBox],
            t_range: Box::new(SigmaType::SInt),
            tpe_params: vec![],
        });
        // Generic function type: tpeParams carried after the range.
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::STypeVar("T".into())],
            t_range: Box::new(SigmaType::STypeVar("T".into())),
            tpe_params: vec![SigmaType::STypeVar("T".into())],
        });
    }

    #[test]
    fn roundtrip_sstring() {
        let t = SigmaType::SString;
        let data = encode(&t);
        let mut r = VlqReader::new(&data);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    #[test]
    fn roundtrip_sglobal() {
        let t = SigmaType::SGlobal;
        let data = encode(&t);
        let mut r = VlqReader::new(&data);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    #[test]
    fn roundtrip_stypevar() {
        let t = SigmaType::STypeVar("T".into());
        let data = encode(&t);
        let mut r = VlqReader::new(&data);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    #[test]
    fn stypevar_name_at_255_byte_max_round_trips_per_scala() {
        // Scala accepts 0..=255 byte names for STypeVar. The previous
        // Rust-only 64-byte cap rejected legitimate Scala-valid
        // descriptors. Pin the round-trip at the actual Scala max so
        // any reintroduction of a tighter cap fails loudly.
        let name = "x".repeat(255);
        let t = SigmaType::STypeVar(name.clone());
        let bytes = encode(&t);
        let mut r = VlqReader::new(&bytes);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    // ----- error paths -----

    #[test]
    fn error_unknown_type_code() {
        let data = [0xFE];
        let mut r = VlqReader::new(&data);
        let err = read_type(&mut r).unwrap_err();
        assert!(
            matches!(&err, ReadError::SigmaValidation { rule_id: 1008, args, .. } if args == &[0xfe]),
            "expected type validation rule 1008, got: {err:?}"
        );
    }

    #[test]
    fn error_unexpected_eof() {
        let data = [];
        let mut r = VlqReader::new(&data);
        let err = read_type(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::UnexpectedEnd { .. }),
            "expected UnexpectedEnd, got: {err:?}"
        );
    }

    #[test]
    fn error_truncated_nested_coll() {
        // Coll with non-embeddable element but no element type follows
        let data = [0x0C]; // COLL_CODE with primId 0
        let mut r = VlqReader::new(&data);
        let err = read_type(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::UnexpectedEnd { .. }),
            "expected UnexpectedEnd for truncated Coll, got: {err:?}"
        );
    }

    // NB: type code 0 is covered by `read_type_prefix_zero_hard_rejects` in the
    // oracle-parity section — it is a HARD reject, not a soft `InvalidData`.

    /// `Coll[Coll[T]]` (24) and `Option[Coll[T]]` (48) with a non-embeddable
    /// `T` hold two levels in one byte. Neither writer emits them: both expand
    /// to one `Coll` byte per level. The depth guard must give the compact
    /// form the verdict of that canonical form, or a re-encode flips it.
    #[test]
    fn compact_two_level_codes_count_both_levels() {
        for (compact, expanded) in [(0x18u8, [0x0Cu8, 0x0C]), (0x30, [0x24, 0x0C])] {
            for pairs in [50, 51] {
                let mut short = vec![compact; pairs];
                short.push(0x01);
                let mut long: Vec<u8> = std::iter::repeat_n(expanded, pairs).flatten().collect();
                long.push(0x01);
                assert_eq!(
                    read_type(&mut VlqReader::new(&short)).is_ok(),
                    read_type(&mut VlqReader::new(&long)).is_ok(),
                    "code {compact:#x} x{pairs}"
                );
            }
        }
    }

    /// Run `f` on a thread with a stack large enough for the recursive walks
    /// (writer, equality, drop) over a type `MAX_TYPE_DEPTH` levels deep in an
    /// unoptimized test build.
    fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    /// `Coll^n[Byte]`: `n - 1` generic `Coll` bytes (0x0C), then `Coll[Byte]`.
    fn nested_coll_bytes(n: usize) -> Vec<u8> {
        let mut bytes = vec![0x0Cu8; n - 1];
        bytes.push(0x0E);
        bytes
    }

    #[test]
    fn read_type_nested_to_max_depth_round_trips() {
        // Eight recursive calls plus an embedded terminal are accepted.
        on_big_stack(|| {
            let bytes = nested_coll_bytes(MAX_TYPE_DEPTH + 1);
            let mut r = VlqReader::new(&bytes);
            let t = read_type(&mut r).expect("a chain at the guard parses");
            assert!(r.is_empty());
            // The writer, like Scala's, folds the innermost `Coll[Coll[Byte]]`
            // into its compact code 0x1A.
            let mut canonical = vec![0x0Cu8; MAX_TYPE_DEPTH - 1];
            canonical.push(0x1A);
            assert_eq!(encode(&t), canonical);
            let mut r = VlqReader::new(&canonical);
            assert_eq!(read_type(&mut r).unwrap(), t);
        });
    }

    #[test]
    fn read_type_past_max_depth_hard_rejects() {
        // One recursive call beyond 8 throws DeserializeCallDepthExceeded;
        // it cannot degrade even inside a size-delimited tree.
        let bytes = nested_coll_bytes(MAX_TYPE_DEPTH + 2);
        let mut r = VlqReader::new(&bytes);
        match read_type(&mut r) {
            Err(ReadError::DepthLimitExceeded { max }) => assert_eq!(max, 8),
            other => panic!("expected a hard depth reject, got: {other:?}"),
        }
    }

    #[test]
    fn read_type_wide_tuple_chain_past_max_depth_hard_rejects() {
        // Each `STuple` of 255 items (`60 ff`) opens the next as its first
        // item: two bytes per level, so this runs past the guard in 32 KiB.
        // The reader must not reserve 255 item slots per open frame before
        // the items arrive, or the chain costs hundreds of MiB before the
        // reject.
        let bytes = [0x60u8, 0xFF].repeat(MAX_TYPE_DEPTH + 2);
        let mut r = VlqReader::new(&bytes);
        match read_type(&mut r) {
            Err(ReadError::DepthLimitExceeded { max }) => assert_eq!(max, 8),
            other => panic!("expected a hard depth reject, got: {other:?}"),
        }
    }

    #[test]
    fn read_type_compact_nested_coll_counts_recursive_calls() {
        // Eight compact constructors make eight recursive calls while
        // constructing 16 collection layers. The embedded terminal adds none.
        let mut bytes = vec![0x18u8; MAX_TYPE_DEPTH];
        bytes.push(0x0E);
        let mut r = VlqReader::new(&bytes);
        assert!(read_type(&mut r).is_ok(), "the last item sits at the guard");
        bytes.insert(0, 0x18);
        let mut r = VlqReader::new(&bytes);
        assert!(matches!(
            read_type(&mut r),
            Err(ReadError::DepthLimitExceeded { max: 8 })
        ));
    }

    // ----- oracle parity -----

    /// Type prefix `0` is Scala's `InvalidTypePrefix` — a `SerializerException`,
    /// NOT a `ValidationException` — so `deserializeErgoTree`'s catch does not
    /// cover it and a size-delimited tree carrying one is REJECTED, never
    /// wrapped as `UnparsedErgoTree`. Oracle (`ErgoSerdeOracle.scala`,
    /// sigma-state 6.0.2, surface `ergo_tree`):
    ///
    /// ```text
    /// ergo_tree 080100   -> REJECT InvalidTypePrefix
    /// ergo_tree 08016b   -> ACCEPT 08016b
    /// ```
    ///
    /// `08016b` is the discriminator twin: an unknown but NON-zero type code is
    /// rule-1016 `ValidationException` territory, which the reference DOES
    /// catch and wrap — so it must stay a soft [`ReadError::InvalidData`].
    #[test]
    fn read_type_prefix_zero_hard_rejects() {
        let mut r = VlqReader::new(&[0x00]);
        let err = read_type(&mut r).expect_err("type prefix 0 must reject");
        assert!(
            matches!(&err, ReadError::HardReject(m) if m.contains("type prefix 0")),
            "type prefix 0 must be a HardReject so it escapes the size-delimited \
             soft-fork wrap (Scala InvalidTypePrefix), got: {err:?}"
        );
    }

    #[test]
    fn read_type_unknown_nonzero_code_stays_soft() {
        let mut r = VlqReader::new(&[0x6b]);
        let err = read_type(&mut r).expect_err("type code 0x6b must reject");
        assert!(
            matches!(&err, ReadError::SigmaValidation { rule_id: 1008, args, .. } if args == &[0x6b]),
            "an unknown non-zero type code is a wrappable ValidationException in \
             the reference, so it must stay soft, got: {err:?}"
        );
    }

    /// General-tuple (`TUPLE_CODE` = 0x60) read parity, cargo-fuzz #305
    /// follow-up. Scala `TypeSerializer.deserialize` (TypeSerializer.scala:
    /// 188-192) reads `count` item types with NO arity floor — a 0- or
    /// 1-element `STuple` is a normal accept — and every item read hits the
    /// same `c <= 0` hard reject as any other type-byte position, wherever it
    /// falls in the tuple.
    ///
    /// Oracle (`ErgoSerdeOracle.scala`, sigma-state 6.0.2, surface
    /// `sigma_type`):
    ///
    /// ```text
    /// sigma_type 6000     -> ACCEPT      (0-element tuple)
    /// sigma_type 600104   -> ACCEPT      (1-element tuple: STuple[SInt])
    /// sigma_type 600100   -> REJECT InvalidTypePrefix  (1-element, item byte 0)
    /// sigma_type 60020004 -> REJECT InvalidTypePrefix  (2-element, first item byte 0)
    /// ```
    ///
    /// (`ACCEPT` here has no canonical-bytes suffix: Scala's own
    /// `TypeSerializer.serialize` throws re-emitting a 0- or 1-element
    /// `STuple` — `write_tuple` keeps its `count >= 2` floor for exactly
    /// that reason, an intentional read/write asymmetry, see its doc.)
    #[test]
    fn read_type_general_tuple_arity_zero_and_one_accept() {
        for (bytes, want) in [
            (&[0x60u8, 0x00][..], SigmaType::STuple(vec![])),
            (
                &[0x60u8, 0x01, 0x04][..],
                SigmaType::STuple(vec![SigmaType::SInt]),
            ),
        ] {
            let mut r = VlqReader::new(bytes);
            let got = read_type(&mut r)
                .unwrap_or_else(|e| panic!("tuple bytes {bytes:02x?} must accept: {e:?}"));
            assert_eq!(got, want, "bytes {bytes:02x?}");
        }
    }

    #[test]
    fn read_type_general_tuple_zero_item_hard_rejects_at_any_position() {
        // count=1, sole item byte 0.
        let mut r = VlqReader::new(&[0x60, 0x01, 0x00]);
        let err = read_type(&mut r).expect_err("zero item type in a 1-tuple must hard-reject");
        assert!(
            matches!(&err, ReadError::HardReject(_)),
            "expected HardReject (Scala InvalidTypePrefix), got: {err:?}"
        );

        // count=2, FIRST item byte 0 (the second item, 0x04 = SInt, is never
        // reached — matches Scala reading item types left to right and
        // throwing on the first zero byte it hits).
        let mut r = VlqReader::new(&[0x60, 0x02, 0x00, 0x04]);
        let err = read_type(&mut r).expect_err("zero item type in a 2-tuple must hard-reject");
        assert!(
            matches!(&err, ReadError::HardReject(_)),
            "expected HardReject (Scala InvalidTypePrefix), got: {err:?}"
        );
    }
}
