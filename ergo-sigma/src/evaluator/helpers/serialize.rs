//! The wire <-> runtime value boundary, both directions kept together for
//! side-by-side review: `value_to_typed_sigma` (runtime -> typed sigma) and
//! `sigma_to_value*` (sigma -> runtime), with `count_sigma_nodes`/`trace_val`.
//! `sigma_to_value` is the crate's one `pub` helper (re-exported at
//! `evaluator::sigma_to_value`).

use ergo_primitives::group_element::GroupElement;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use super::*;
use crate::evaluator::types::*;

/// Truncated `Debug` projection used by trace entries. Keeps the first
/// 150 bytes of the formatted value so trace lines stay grep-friendly.
pub(crate) fn trace_val(v: &Value) -> String {
    let s = format!("{v:?}");
    if s.len() > 150 {
        format!("{}...", &s[..150])
    } else {
        s
    }
}

/// Convert a runtime Value to (SigmaType, SigmaValue) for serialization.
pub(crate) fn value_to_typed_sigma(val: &Value) -> Result<(SigmaType, SigmaValue), EvalError> {
    use ergo_ser::sigma_value::CollValue;
    match val {
        Value::Bool(b) => Ok((SigmaType::SBoolean, SigmaValue::Boolean(*b))),
        Value::Int(n) => Ok((SigmaType::SInt, SigmaValue::Int(*n))),
        Value::Long(n) => Ok((SigmaType::SLong, SigmaValue::Long(*n))),
        Value::BigInt(n) => Ok((SigmaType::SBigInt, SigmaValue::BigInt(n.clone()))),
        // SigmaValue carries unsigned bigints in the same BigInt
        // variant as signed; the SigmaType is what distinguishes them
        // on the wire. ergo-ser's write_unsigned_bigint_value
        // (sigma_value.rs) refuses negative input, so the SigmaType
        // tag here is load-bearing — it routes to the unsigned
        // writer that emits canonical magnitude bytes without a sign
        // byte. Without this arm, any v6 method that produces an
        // UnsignedBigInt (e.g. `SBigInt.toUnsigned`, `SUnsignedBigInt.
        // plusMod`) would fall through to the catch-all and break
        // `SGlobal.serialize` for scripts that compose v6 methods.
        Value::UnsignedBigInt(n) => Ok((SigmaType::SUnsignedBigInt, SigmaValue::BigInt(n.clone()))),
        Value::GroupElement(ge) => Ok((
            SigmaType::SGroupElement,
            SigmaValue::GroupElement(GroupElement::from_bytes(*ge)),
        )),
        Value::SigmaProp(sb) => Ok((SigmaType::SSigmaProp, SigmaValue::SigmaProp(sb.clone()))),
        Value::Str(s) => Ok((SigmaType::SString, SigmaValue::Str(s.clone()))),
        // Unit, Byte, Short surface as their own typed carriers
        // (no erasure to Int) on the wire boundary.
        Value::Unit => Ok((SigmaType::SUnit, SigmaValue::Unit)),
        Value::Byte(n) => Ok((SigmaType::SByte, SigmaValue::Byte(*n))),
        Value::Short(n) => Ok((SigmaType::SShort, SigmaValue::Short(*n))),
        Value::CollBytes(b) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes(b.clone())),
        )),
        // Coll[Short] — generic CollValue::Values: ergo-ser only
        // special-cases Coll[Boolean] and Coll[Byte], so there is no
        // packed byte encoding for Short.
        Value::CollShort(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SShort)),
            SigmaValue::Coll(CollValue::Values(
                v.iter().map(|n| SigmaValue::Short(*n)).collect(),
            )),
        )),
        Value::CollBool(b) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            SigmaValue::Coll(CollValue::BoolBits(b.clone())),
        )),
        Value::CollInt(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SInt)),
            SigmaValue::Coll(CollValue::Values(
                v.iter().map(|n| SigmaValue::Int(*n)).collect(),
            )),
        )),
        Value::CollLong(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SLong)),
            SigmaValue::Coll(CollValue::Values(
                v.iter().map(|n| SigmaValue::Long(*n)).collect(),
            )),
        )),
        Value::CollSigmaProp(v) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
            SigmaValue::Coll(CollValue::Values(
                v.iter()
                    .map(|sb| SigmaValue::SigmaProp(sb.clone()))
                    .collect(),
            )),
        )),
        // `Option[T]` — inverse of the `SOption(_)` arm of
        // `sigma_to_value`. Some(inner) recurses on `inner`;
        // None surfaces with `SOption(SAny)` and the caller's
        // type-compatibility check (`sigma_type_compatible`) bridges
        // the wildcard back to the concrete `T` when needed.
        Value::Opt(Some(inner)) => {
            let (inner_ty, inner_val) = value_to_typed_sigma(inner)?;
            Ok((
                SigmaType::SOption(Box::new(inner_ty)),
                SigmaValue::Opt(Some(Box::new(inner_val))),
            ))
        }
        Value::Opt(None) => Ok((
            SigmaType::SOption(Box::new(SigmaType::SAny)),
            SigmaValue::Opt(None),
        )),
        // Real `STuple` — fixed-arity heterogeneous tuple. Inverse
        // of the `(SigmaType::STuple, SigmaValue::Tuple)` arm of
        // `sigma_to_value`. Each element is serialized via the same
        // recursion, so byte-parity to Scala follows from the parse
        // path being Scala-anchored.
        Value::Tuple(items) => {
            let mut types: Vec<SigmaType> = Vec::with_capacity(items.len());
            let mut vals: Vec<SigmaValue> = Vec::with_capacity(items.len());
            for item in items {
                let (t, v) = value_to_typed_sigma(item)?;
                types.push(t);
                vals.push(v);
            }
            Ok((SigmaType::STuple(types), SigmaValue::Tuple(vals)))
        }
        // Boxed-element `Coll[X]` — inverse of `sigma_to_value`'s
        // `SColl(non-primitive)` fallback that emits `CollGeneric`.
        // The carrier's `elem_type` is the static `SigmaType` the IR
        // pinned at script-load (or that the producer operation
        // guarantees), so empty `Coll[T]` survives serialize-back
        // for any T — no element-probe needed.
        //
        // For non-empty collections we still cross-check each
        // element's recovered `SigmaType` against `elem_type`; a
        // mismatch surfaces `TypeError` rather than emitting bytes
        // a Scala decoder would reject.
        Value::CollGeneric(items, elem_type) => {
            let mut sigma_vals: Vec<SigmaValue> = Vec::with_capacity(items.len());
            for item in items {
                let (t, v) = value_to_typed_sigma(item)?;
                // `sigma_type_compatible` bridges the `SAny`
                // wildcard `Value::Opt(None)` surfaces back to the
                // carrier's concrete `T`, so a mixed
                // `[Some(_), None]` collection still serializes
                // under the right `SOption(T)` tag.
                if !sigma_type_compatible(elem_type, &t) {
                    return Err(EvalError::TypeError {
                        expected: "element matches CollGeneric elem_type",
                        got: format!("declared {elem_type:?}, found {t:?}"),
                    });
                }
                sigma_vals.push(v);
            }
            Ok((
                SigmaType::SColl(Box::new((**elem_type).clone())),
                SigmaValue::Coll(CollValue::Values(sigma_vals)),
            ))
        }
        // AvlTree: inverse of sigma_to_value's SAvlTree arm. The carrier
        // already holds the wire-shaped `AvlTreeData`, so serialize-back is a
        // direct hand-off to `write_avl_tree` (DataSerializer SAvlTree case).
        // Scala writes keyLength / valueLengthOpt with `putUInt`, which throws
        // on a negative value. `read_avl_tree` deliberately preserves a length
        // above i32::MAX as a wrapped-negative i32 ("succeeds with invalid
        // AvlTreeData"); serializing such a tree must error rather than cast to
        // u32 and emit bytes the reference would reject.
        Value::AvlTree(avl) => {
            if avl.key_length < 0 || avl.value_length_opt.is_some_and(|v| v < 0) {
                return Err(EvalError::TypeError {
                    expected: "non-negative AvlTree keyLength/valueLengthOpt for serialize",
                    got: format!(
                        "keyLength={}, valueLengthOpt={:?}",
                        avl.key_length, avl.value_length_opt
                    ),
                });
            }
            Ok((SigmaType::SAvlTree, SigmaValue::AvlTree(avl.clone())))
        }
        // Header: DataSerializer routes SHeader to ErgoHeader.sigmaSerializer
        // (gated on isV3OrLaterErgoTreeVersion — already enforced upstream by
        // the v6 method gate on SGlobal.serialize). `to_header` rebuilds the
        // wire `Header` from the eval carrier; `write_header` emits the bytes
        // and `serialize_put_cost(SHeader)` charges the matching put costs.
        Value::Header(h) => Ok((
            SigmaType::SHeader,
            SigmaValue::Header(Box::new(h.to_header())),
        )),
        // Native `Coll[Header]` carrier (e.g. CONTEXT.headers) — the standard
        // runtime source of header collections. Convert each element to the
        // wire `Header` so `serialize` / `SubstConstants` can consume it (a
        // bare `CollGeneric` only covers hand-built header colls). The v3 gate
        // is value-based via `contains_header`, so a non-empty Coll[Header] is
        // rejected on a pre-v3 tree while an empty one is accepted.
        Value::CollHeader(headers) => {
            let vals = headers
                .iter()
                .map(|h| SigmaValue::Header(Box::new(h.to_header())))
                .collect();
            Ok((
                SigmaType::SColl(Box::new(SigmaType::SHeader)),
                SigmaValue::Coll(CollValue::Values(vals)),
            ))
        }
        // SBox: the InlineBox carrier holds the verbatim serialized box bytes
        // (`raw_bytes` == Scala serialize(box), byte-identical — the parser
        // preserves the tree and register bytes verbatim). DataSerializer
        // routes SBox to `ErgoBox.sigmaSerializer`; hand the cached bytes to
        // `write_value(SBox, OpaqueBoxBytes)` (-> put_bytes), and
        // `serialize_put_cost(SBox)` re-parses them for the put-cost sum.
        // SelfBox / BoxRef would need context resolution to a concrete box; no
        // SANTA vector exercises a top-level serialize(SELF)/serialize(INPUTS),
        // so they stay in the catch-all below.
        Value::InlineBox(eb) => Ok((
            SigmaType::SBox,
            SigmaValue::OpaqueBoxBytes(eb.raw_bytes.clone()),
        )),
        // Catch-all rejects the remaining non-serializable runtime carriers
        // (BoxCollection / SelfBox / BoxRef / Func / Global / Opt / Tokens /
        // PreHeader / CollBox). These either lack a public SigmaValue
        // counterpart or have no Scala-anchored bytes for the
        // SubstConstants/SGlobal.serialize boundary.
        other => Err(EvalError::TypeError {
            expected: "serializable value for SubstConstants",
            got: format!("{other:?}"),
        }),
    }
}

/// Count total nodes in a SigmaBoolean tree (for SigmaPropBytes PerItem cost).
pub(crate) fn count_sigma_nodes(sb: &SigmaBoolean) -> usize {
    match sb {
        SigmaBoolean::TrivialProp(_) | SigmaBoolean::ProveDlog(_) => 1,
        // Scala `ProveDHTuple.size = 4` ("one node for each EcPoint",
        // SigmaBoolean.scala). SigmaPropBytes' PerItemCost(35,6,1) is charged
        // over `SigmaBoolean.size`, so a DHTuple counts 3 nodes more than a
        // Dlog (compounding through CAND/COR/CTHRESHOLD children).
        SigmaBoolean::ProveDHTuple { .. } => 4,
        SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
            1 + children.iter().map(count_sigma_nodes).sum::<usize>()
        }
        SigmaBoolean::Cthreshold { children, .. } => {
            1 + children.iter().map(count_sigma_nodes).sum::<usize>()
        }
    }
}

/// Convert a typed SigmaValue to a runtime Value.
///
/// Shared lowering path for constants (ConstPlaceholder), register values
/// (ExtractRegisterAs), context-var extensions (GetVar) and `deserializeTo`
/// — every boundary that turns a typed `SigmaValue` into a runtime `Value`.
/// [`sigma_to_value`] plus the v6-type gates. Scala materializes an `SHeader`
/// or `SOption` value only when `VersionContext.isV3OrLaterErgoTreeVersion`
/// (`CoreDataSerializer` matches each only at ergoTreeVersion>=3, else falls
/// through and throws) — so a pre-v3 ErgoTree carrying either is rejected.
/// Mirror that here so we never accept input the reference node rejects
/// (accept-invalid fork hazard). This is the VALUE-materialization companion
/// to the parse-time constant gates in `ergo-ser` (`contains_header` /
/// `contains_option`), and it is what gates register / context-var / plain-
/// constant payloads that bypass `parse_expr`.
///
/// The gates key on whether the VALUE actually materializes a header / option
/// (Scala gates per materialized value, not per static type): an empty
/// `Coll[Header]` / `Coll[Option[T]]` materializes none and is accepted on any
/// version, matching the reference.
///
/// NOTE: registers and context vars are additionally subject to the reference's
/// `CheckV6Type`, which rejects Option/Header/UnsignedBigInt-typed values
/// UNCONDITIONALLY (at every activated version, not just pre-v3). The
/// version-conditional gate below matches the reference pre-v3 (and for
/// constants/`deserializeTo` at all versions); the unconditional v3+
/// register/context rejection is a separate, pre-existing gap shared with the
/// SHeader gate, tracked with the Box-register-access work.
pub(crate) fn sigma_to_value_versioned(
    tpe: &SigmaType,
    val: &SigmaValue,
    ctx: &ReductionContext<'_>,
) -> Result<Value, EvalError> {
    if !ctx.is_v3_ergo_tree() && val.contains_header() {
        return Err(EvalError::TypeError {
            expected: "ErgoTree version >= 3 for an SHeader value (isV3OrLaterErgoTreeVersion)",
            got: format!("ergoTreeVersion={}", ctx.ergo_tree_version),
        });
    }
    if !ctx.is_v3_ergo_tree() && val.contains_option() {
        return Err(EvalError::TypeError {
            expected: "ErgoTree version >= 3 for an SOption value (isV3OrLaterErgoTreeVersion)",
            got: format!("ergoTreeVersion={}", ctx.ergo_tree_version),
        });
    }
    sigma_to_value(tpe, val)
}

pub fn sigma_to_value(tpe: &SigmaType, val: &SigmaValue) -> Result<Value, EvalError> {
    use ergo_ser::sigma_value::CollValue;
    match (tpe, val) {
        // Unit, Byte, Short no longer erase to Int — typed-carrier
        // invariant on the sigma-value → evaluator boundary.
        (SigmaType::SUnit, SigmaValue::Unit) => Ok(Value::Unit),
        (SigmaType::SByte, SigmaValue::Byte(n)) => Ok(Value::Byte(*n)),
        (SigmaType::SShort, SigmaValue::Short(n)) => Ok(Value::Short(*n)),
        (SigmaType::SInt, SigmaValue::Int(n)) => Ok(Value::Int(*n)),
        (SigmaType::SLong, SigmaValue::Long(n)) => Ok(Value::Long(*n)),
        (SigmaType::SBigInt, SigmaValue::BigInt(n)) => Ok(Value::BigInt(n.clone())),
        (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(n)) => {
            // Wire-layer (sigma_value.rs::read_unsigned_bigint_value)
            // already enforces the 32-byte unsigned magnitude bound, so
            // by the time we reach this case the value satisfies
            // `0 <= n < 2^256`. A negative `n` here is a deserializer
            // bug, not a script-author bug — surface it loudly as the
            // dedicated `UnsupportedConstant` rather than papering over
            // it by silently lifting the sign.
            if n.sign() == num_bigint::Sign::Minus {
                return Err(EvalError::UnsupportedConstant(SigmaType::SUnsignedBigInt));
            }
            Ok(Value::UnsignedBigInt(n.clone()))
        }
        (SigmaType::SBoolean, SigmaValue::Boolean(b)) => Ok(Value::Bool(*b)),
        (SigmaType::SSigmaProp, SigmaValue::SigmaProp(sb)) => Ok(Value::SigmaProp(sb.clone())),
        (SigmaType::SGroupElement, SigmaValue::GroupElement(ge)) => {
            // Scala validates + canonicalizes a GroupElement when it is
            // deserialized (GroupElementSerializer.parse): 0x00-lead encodings
            // become the canonical identity (33 zeros) and non-0x00 encodings
            // are decoded on-curve (off-curve rejected). Apply the same here so
            // a register / constant / context-var GE value is canonical and
            // validated, matching `decodePoint`.
            Ok(Value::GroupElement(
                crate::evaluator::opcodes::sigma::canonicalize_group_element(*ge.as_bytes())?,
            ))
        }
        (SigmaType::SColl(inner), SigmaValue::Coll(coll)) => {
            match (inner.as_ref(), coll) {
                (SigmaType::SByte, CollValue::Bytes(b)) => Ok(Value::CollBytes(b.clone())),
                (SigmaType::SBoolean, CollValue::BoolBits(bits)) => {
                    Ok(Value::CollBool(bits.clone()))
                }
                (elem_type, CollValue::Values(vs)) => {
                    let items: Result<Vec<Value>, EvalError> =
                        vs.iter().map(|v| sigma_to_value(elem_type, v)).collect();
                    let items = items?;
                    match elem_type {
                        SigmaType::SByte => {
                            // Rare: Coll[Byte] arriving as generic Values — canonicalize to CollBytes.
                            let v: Vec<u8> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Byte(n) = v {
                                        Some(*n as u8)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollBytes(v))
                        }
                        SigmaType::SShort => {
                            let v: Vec<i16> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Short(n) = v {
                                        Some(*n)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollShort(v))
                        }
                        SigmaType::SInt => {
                            let v: Vec<i32> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Int(n) = v {
                                        Some(*n)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollInt(v))
                        }
                        SigmaType::SLong => {
                            let v: Vec<i64> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Long(n) = v {
                                        Some(*n)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollLong(v))
                        }
                        SigmaType::SBoolean => {
                            let v: Vec<bool> = items
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Bool(b) = v {
                                        Some(*b)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollBool(v))
                        }
                        SigmaType::SSigmaProp => {
                            let v: Vec<SigmaBoolean> = items
                                .into_iter()
                                .filter_map(|v| {
                                    if let Value::SigmaProp(sb) = v {
                                        Some(sb)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            Ok(Value::CollSigmaProp(v))
                        }
                        // SColl(non-primitive) → boxed-element coll
                        // carrier (Coll[Tuple], Coll[Header], etc.).
                        // `elem_type` is the inner T from the wire
                        // type tag; carry it on the value so empty
                        // round-trips work and downstream
                        // `Coll.updated` knows the element shape.
                        _ => Ok(Value::CollGeneric(items, Box::new(elem_type.clone()))),
                    }
                }
                (_, CollValue::Bytes(b)) => Ok(Value::CollBytes(b.clone())),
                _ => Err(EvalError::UnsupportedConstant(tpe.clone())),
            }
        }
        (SigmaType::STuple(elem_types), SigmaValue::Tuple(vals)) => {
            let items: Result<Vec<Value>, EvalError> = elem_types
                .iter()
                .zip(vals.iter())
                .map(|(t, v)| sigma_to_value(t, v))
                .collect();
            Ok(Value::Tuple(items?))
        }
        (SigmaType::SOption(inner), SigmaValue::Opt(opt_val)) => match opt_val {
            Some(v) => Ok(Value::Opt(Some(Box::new(sigma_to_value(inner, v)?)))),
            None => Ok(Value::Opt(None)),
        },
        // SBox constant — parse full ErgoBox (candidate + txId + index) with real identity
        (SigmaType::SBox, SigmaValue::OpaqueBoxBytes(bytes)) => {
            use ergo_ser::register::RegisterId;
            let mut r = ergo_primitives::reader::VlqReader::new(bytes);
            let ergo_box =
                ergo_ser::ergo_box::read_ergo_box(&mut r).map_err(|e| EvalError::TypeError {
                    expected: "valid SBox constant",
                    got: format!("box deser error: {e}"),
                })?;
            let box_id = ergo_box.box_id().map_err(|e| EvalError::TypeError {
                expected: "box_id computation",
                got: format!("{e}"),
            })?;
            let registers = [
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R4)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R5)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R6)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R7)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R8)
                    .cloned(),
                ergo_box
                    .candidate
                    .additional_registers
                    .get(RegisterId::R9)
                    .cloned(),
            ];
            let tokens: Vec<([u8; 32], u64)> = ergo_box
                .candidate
                .tokens
                .iter()
                .map(|t| (*t.token_id.as_bytes(), t.amount))
                .collect();
            let raw_bytes = {
                let mut w = ergo_primitives::writer::VlqWriter::new();
                ergo_ser::ergo_box::write_ergo_box(&mut w, &ergo_box).unwrap_or_default();
                w.result()
            };
            Ok(Value::InlineBox(Box::new(EvalBox {
                creation_height: ergo_box.candidate.creation_height,
                script_bytes: ergo_box.candidate.ergo_tree_bytes().to_vec(),
                value: ergo_box.candidate.value as i64,
                id: *box_id.as_bytes(),
                // read_ergo_box parses the real transaction id and output
                // index from the box tail; carry them through so
                // ExtractCreationInfo (R3 ref = txId ++ 2-byte big-endian
                // index) and ExtractBytesWithNoRef (strips 32 + VLQ(index))
                // reflect the real identity rather than zeros.
                transaction_id: *ergo_box.transaction_id.as_bytes(),
                output_index: ergo_box.index,
                registers,
                tokens,
                raw_bytes,
                register_bytes: ergo_box.candidate.register_bytes().to_vec(),
            })))
        }
        (SigmaType::SAvlTree, SigmaValue::AvlTree(data)) => Ok(Value::AvlTree(data.clone())),
        (SigmaType::SString, SigmaValue::Str(s)) => Ok(Value::Str(s.clone())),
        // SHeader value -> Value::Header. The header id is Blake2b256 over the
        // serialized header (the block-header path computes it the same way).
        // Version-agnostic: the v3+ (isV3OrLaterErgoTreeVersion) gate is
        // enforced by the evaluator callers that materialize an SHeader value
        // (getVar / constant eval / deserializeTo), which carry the ErgoTree
        // version; this converter does not.
        (SigmaType::SHeader, SigmaValue::Header(h)) => {
            let (_bytes, hid) =
                ergo_ser::header::serialize_header(h).map_err(|e| EvalError::TypeError {
                    expected: "re-serializable SHeader value",
                    got: format!("{e:?}"),
                })?;
            Ok(Value::Header(Box::new(
                crate::evaluator::types::EvalHeader::from_header(h, *hid.as_bytes()),
            )))
        }
        _ => Err(EvalError::UnsupportedConstant(tpe.clone())),
    }
}
