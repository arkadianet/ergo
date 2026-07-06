//! ErgoTree assembly + the public end-to-end [`compile`] API (M3 Task 9).
//!
//! Wires the full pipeline source → bytes → address: parse → bind →
//! typecheck ([`crate::typecheck_with_network`]) → root coercion → emit
//! ([`crate::emit`]) → [`build_tree`] → wire write → P2S/P2SH address
//! construction. Mirrors the node's compile surface,
//! `ScriptApiRoute.compileSource`
//! (`ergo/src/main/scala/org/ergoplatform/http/api/ScriptApiRoute.scala:56-67`).

use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_p2s, encode_p2sh, NetworkPrefix};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::{write_expr, Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};

use crate::emit::{emit, EmitError};
use crate::env::ScriptEnv;
use crate::stype::SType;
use crate::typecheck::{typecheck_with_network, CompileError};
use crate::typed::node_tpe;
use crate::typed_print::to_term_string;

/// The output of a successful [`compile`]: the assembled tree, its wire
/// bytes, and both script-address encodings.
#[derive(Debug, Clone, PartialEq)]
pub struct CompileResult {
    /// Canonical wire bytes of `ergo_tree` (`write_ergo_tree` output).
    pub tree_bytes: Vec<u8>,
    /// The assembled tree (M3: always version 0, non-segregated, no size).
    pub ergo_tree: ErgoTree,
    /// Pay-to-Script address over the FULL `tree_bytes`
    /// (`ergo_ser::address::encode_p2s`). Deliberately NOT routed through
    /// `encode_address`/`encode_address_from_tree_bytes`: the compile surface
    /// always answers P2S (Scala `Pay2SAddress(tree)`), even when the tree is
    /// a bare `SigmaPropConstant(ProveDlog)` that the wallet-side
    /// `fromProposition` routing would render as P2PK.
    pub p2s_address: String,
    /// Pay-to-Script-Hash address over the PROPOSITION bytes (root
    /// expression only, no tree header/constants wrapper) — Scala
    /// `Pay2SHAddress(prop)`, `ErgoAddress.scala:201-218`.
    pub p2sh_address: String,
}

/// Assemble the M3 ErgoTree around an emitted root expression.
///
/// Mirrors `ErgoTree.fromProposition(header, prop)` (sigma-state 6.0.2,
/// `core/.../sigma/ast/ErgoTree.scala:344-349`):
///
/// ```text
/// prop match {
///   case SigmaPropConstant(_) => withoutSegregation(header, prop)   // header 0x00
///   case _                    => withSegregation(header, prop)      // header 0x10
/// }
/// ```
///
/// At M3 we implement ONLY the `withoutSegregation` branch for EVERY root —
/// header `0x00`, empty constants table, inline constants in the body. For a
/// bare-constant root (e.g. `PK("...")` → `SigmaPropConstant`) this is
/// byte-identical to Scala; for any other root Scala segregates (header
/// `0x10`, constants pulled into the table, `ConstPlaceholder` in the body) —
/// THAT is the M4 flip point (the constant-segregation transform), tracked in
/// the module ledger. Both forms are valid, parseable, semantically equal
/// trees; only the bytes (and hence the P2S address) differ.
///
/// Header provenance (route fact): the wire header always comes from
/// `ErgoTree.defaultHeaderWithVersion(0)` — `ScriptApiRoute.compileSource`
/// never forwards its `treeVersion` request parameter into the header; that
/// parameter only gates frontend method visibility via
/// `VersionContext.withVersions`. So `version` is fixed 0 and `has_size`
/// false (the size bit is only required for version > 0).
pub(crate) fn build_tree(root: Expr) -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: root,
    }
}

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
/// M3 v0 header (see the gate comment in [`compile`]). Returns a description
/// of the first offender, or `None` when the tree is v0-clean.
fn find_v0_unserializable(expr: &Expr) -> Option<String> {
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

/// Push every child expression of `payload` onto `stack` — the exhaustive
/// child map of [`Payload`] (a new child-carrying variant fails to compile
/// here until it is mapped).
fn push_children<'a>(payload: &'a Payload, stack: &mut Vec<&'a Expr>) {
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

/// Rewrite pass: `SizeOf(<ConcreteCollection literal>)` → `IntConstant(n)`
/// (Task-11 wave 2, adversarial-findings-constants.md F-3; lib.rs D-C6).
///
/// Scala's GraphBuilding folds `.size` of a collection LITERAL to the element
/// count regardless of element constancy (oracle 2026-07-07 ×3:
/// `cc sigmaProp(Coll(HEIGHT).size == 1)` and `cc sigmaProp(Coll(1, 2).size
/// == 2)` both fold — replies are the fully-folded `10010101d17300`; `cc
/// sigmaProp(Coll[UnsignedBigInt]().size.toLong == SELF.value)` folds the
/// `.size` to `Int 0` even though the surrounding expression cannot fold —
/// reply `10010400d1937e730005c1a7`). The fold is what keeps Scala's WIRE
/// clean for `Coll[UnsignedBigInt]()`: without it our emitted bytes carry
/// v3-only TYPE code 9 (the ConcreteCollection elem type) under the v0
/// header — bytes our own `read_ergo_tree` refuses (a stranded-funds P2S).
///
/// Runs AFTER the GraphBuilding gates so the discarded elements are still
/// verdict-checked (`Coll(2147483647 + 1).size` must keep rejecting with
/// Scala's ArithmeticException), and BEFORE serialization/addresses. The walk
/// is bottom-up, so nested literals fold inside-out. Residual (lib.rs D-C6):
/// a VAL-BOUND collection literal (`{ val u = Coll[UnsignedBigInt](); …
/// u.size … }`) is `SizeOf(ValUse)` here — Scala inlines the val and still
/// folds (same oracle reply as the inline form); we don't, and the v3-type
/// residue is then caught by the post-write self-check in [`compile`].
fn fold_literal_coll_sizes(e: Expr) -> Expr {
    /// Map every child expression of `payload` through the fold — the
    /// exhaustive by-value twin of [`push_children`] (a new child-carrying
    /// variant fails to compile here until it is mapped).
    fn fold_payload(p: Payload) -> Payload {
        let f = |b: Box<Expr>| Box::new(fold_literal_coll_sizes(*b));
        let fv = |items: Vec<Expr>| -> Vec<Expr> {
            items.into_iter().map(fold_literal_coll_sizes).collect()
        };
        match p {
            Payload::Zero
            | Payload::ValUse { .. }
            | Payload::ConstPlaceholder { .. }
            | Payload::TaggedVar { .. }
            | Payload::BoolCollection { .. }
            | Payload::GetVar { .. }
            | Payload::DeserializeContext { .. }
            | Payload::NoneValue { .. } => p,
            Payload::One(a) => Payload::One(f(a)),
            Payload::NumericCast { input, tpe } => Payload::NumericCast {
                input: f(input),
                tpe,
            },
            Payload::Two(a, b) => Payload::Two(f(a), f(b)),
            Payload::Three(a, b, c) => Payload::Three(f(a), f(b), f(c)),
            Payload::Four(a, b, c, d) => Payload::Four(f(a), f(b), f(c), f(d)),
            Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
                id,
                tpe,
                rhs: f(rhs),
            },
            Payload::FunDef {
                id,
                tpe,
                tpe_args,
                rhs,
            } => Payload::FunDef {
                id,
                tpe,
                tpe_args,
                rhs: f(rhs),
            },
            Payload::BlockValue { items, result } => Payload::BlockValue {
                items: fv(items),
                result: f(result),
            },
            Payload::FuncValue { args, body } => Payload::FuncValue {
                args,
                body: f(body),
            },
            Payload::MethodCall {
                type_id,
                method_id,
                obj,
                args,
                type_args,
            } => Payload::MethodCall {
                type_id,
                method_id,
                obj: f(obj),
                args: fv(args),
                type_args,
            },
            Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
                elem_type,
                items: fv(items),
            },
            Payload::Tuple { items } => Payload::Tuple { items: fv(items) },
            Payload::SigmaCollection { items } => Payload::SigmaCollection { items: fv(items) },
            Payload::SelectField { input, field_idx } => Payload::SelectField {
                input: f(input),
                field_idx,
            },
            Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
                input: f(input),
                reg_id,
                tpe,
            },
            Payload::DeserializeRegister {
                reg_id,
                tpe,
                default,
            } => Payload::DeserializeRegister {
                reg_id,
                tpe,
                default: default.map(f),
            },
            Payload::ByIndex {
                input,
                index,
                default,
            } => Payload::ByIndex {
                input: f(input),
                index: f(index),
                default: default.map(f),
            },
            Payload::FuncApply { func, args } => Payload::FuncApply {
                func: f(func),
                args: fv(args),
            },
        }
    }

    match e {
        Expr::Op(IrNode { opcode, payload }) => {
            let payload = fold_payload(payload);
            // SizeOf (0xB1) over a ConcreteCollection (0x83) literal.
            if opcode == 0xB1 {
                if let Payload::One(inner) = &payload {
                    if let Expr::Op(IrNode {
                        opcode: 0x83,
                        payload: Payload::ConcreteCollection { items, .. },
                    }) = inner.as_ref()
                    {
                        return Expr::Const {
                            tpe: SigmaType::SInt,
                            // A source literal's arity is far below i32::MAX.
                            val: SigmaValue::Int(items.len() as i32),
                        };
                    }
                }
            }
            Expr::Op(IrNode { opcode, payload })
        }
        other => other,
    }
}

/// GraphBuilding verdict-parity gate over the emitted body — lambda and
/// application shapes the FULL Scala compiler rejects (lib.rs D-C5, wave 1;
/// adversarial-findings-bindings.md F1/F2 + fresh boundary captures
/// 2026-07-07, every probe 3 identical oracle runs).
///
/// Oracle-pinned rules:
/// - **Zero-arg `FuncValue` rejects ANYWHERE** — even as the rhs of an
///   unused val (`cc { val unused = {() => 1}; sigmaProp(true) }` → `REJECT
///   1:17 GraphBuildingException`): the definition itself crashes Scala's
///   graph construction, before any dead-code elimination.
/// - **`FuncApply` with arg count != 1 rejects** (`f(1, 2)` → `REJECT 1:50`,
///   `f()`, aliased `g(1, 2)`, inline `{(x, y) => x + y}(1, 2)` — all
///   `GraphBuildingException`): Scala lowers only 1-arg applications. The
///   multi-arg lambda DEFINITION is fine (the IR tuples it), so an unused
///   val-bound multi-arg lambda (`{ val unused = {(x: Int, y: Int) => x +
///   y}; sigmaProp(true) }` → OK), an un-applied alias (`val g = f` with no
///   call → OK) and every HOF-callback use — direct `fold(0L, {(a, b) =>
///   ...})` AND val-bound `fold(0L, f)` (fresh capture: `cc { val f = {(a:
///   Long, b: Long) => a + b}; sigmaProp(Coll(1L, 2L).fold(0L, f) == 3L) }`
///   → OK, the D-C4 both-accept class, e.g. corpus
///   `crystalpool/swap-tokens.es`) — stay ACCEPTED: the gate keys on the
///   APPLICATION node, not on the `FuncValue`.
/// - **A lambda with a FUNCTION-typed parameter rejects** (`{(f: Int => Int)
///   => f(10)}` and the param-unused body variant → `REJECT 0:0
///   MatchError`) UNLESS the lambda is the rhs of a ValDef whose id has zero
///   `ValUse` occurrences (fresh capture: `cc { val unused = {(f: Int =>
///   Int) => 1}; sigmaProp(true) }` → OK — the unused val is dead-code
///   eliminated before the lowering that dies). Residual asymmetry vs the
///   zero-arg rule is oracle-pinned, not a modeling choice. A `FuncValue`
///   with an `SFunc` param NESTED inside an unused val's rhs (not directly
///   the rhs) is still rejected — un-probed exotic corner, reject-side
///   bounded (D-C5).
fn graph_building_lambda_reject(root: &Expr) -> Option<EmitError> {
    use std::collections::HashSet;

    // Pass 1: every ValUse id occurring anywhere in the body.
    let mut used: HashSet<u32> = HashSet::new();
    let mut stack = vec![root];
    while let Some(e) = stack.pop() {
        if let Expr::Op(IrNode { payload, .. }) = e {
            if let Payload::ValUse { id } = payload {
                used.insert(*id);
            }
            push_children(payload, &mut stack);
        }
    }

    // Pass 2: walk with a one-hop exemption flag for a FuncValue that is the
    // rhs of an UNUSED ValDef (Scala prunes it before the SFunc-param
    // lowering; the zero-arg rule is NOT exempted — see the fn docs).
    let mut stack: Vec<(&Expr, bool)> = vec![(root, false)];
    while let Some((e, pruned_rhs)) = stack.pop() {
        let Expr::Op(IrNode { payload, .. }) = e else {
            continue;
        };
        match payload {
            Payload::FuncValue { args, body } => {
                if args.is_empty() {
                    return Some(EmitError::GraphBuildingReject {
                        class: "GraphBuildingException",
                        what: "zero-arg lambda: Scala's graph construction rejects a \
                               FuncValue definition with no arguments (even unused)"
                            .into(),
                    });
                }
                if !pruned_rhs
                    && args
                        .iter()
                        .any(|(_, t)| matches!(t, Some(SigmaType::SFunc { .. })))
                {
                    return Some(EmitError::GraphBuildingReject {
                        class: "MatchError",
                        what: "lambda with a function-typed parameter: Scala's \
                               GraphBuilding cannot lower a higher-order user lambda"
                            .into(),
                    });
                }
                stack.push((body, false));
            }
            Payload::FuncApply { func, args } => {
                if args.len() != 1 {
                    return Some(EmitError::GraphBuildingReject {
                        class: "GraphBuildingException",
                        what: format!(
                            "{}-arg lambda application: Scala's GraphBuilding lowers \
                             only 1-arg applications",
                            args.len(),
                        ),
                    });
                }
                stack.push((func.as_ref(), false));
                stack.push((&args[0], false));
            }
            Payload::ValDef { id, rhs, .. } => {
                let exempt = !used.contains(id)
                    && matches!(
                        rhs.as_ref(),
                        Expr::Op(IrNode {
                            payload: Payload::FuncValue { .. },
                            ..
                        })
                    );
                stack.push((rhs.as_ref(), exempt));
            }
            other => {
                let mut children = Vec::new();
                push_children(other, &mut children);
                stack.extend(children.into_iter().map(|c| (c, false)));
            }
        }
    }
    None
}

/// Numeric widths participating in the compile-time constant fold (the
/// signed ladder only — BigInt arithmetic is NOT compile-folded by Scala,
/// oracle control `cc sigmaProp(bigInt(2^254) + bigInt(2^254) > 0)` → OK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FoldWidth {
    Byte,
    Short,
    Int,
    Long,
}

fn fold_width(t: &SigmaType) -> Option<FoldWidth> {
    match t {
        SigmaType::SByte => Some(FoldWidth::Byte),
        SigmaType::SShort => Some(FoldWidth::Short),
        SigmaType::SInt => Some(FoldWidth::Int),
        SigmaType::SLong => Some(FoldWidth::Long),
        _ => None,
    }
}

fn in_fold_range(w: FoldWidth, v: i64) -> bool {
    match w {
        FoldWidth::Byte => i8::try_from(v).is_ok(),
        FoldWidth::Short => i16::try_from(v).is_ok(),
        FoldWidth::Int => i32::try_from(v).is_ok(),
        FoldWidth::Long => true,
    }
}

/// Compile-time constant-fold overflow CHECK (lib.rs D-C5; the emitted tree
/// stays UNFOLDED — this walk never rewrites, it only mirrors the verdict).
///
/// Scala's GraphBuilding evaluates constant-operand `Byte`/`Short`/`Int`/
/// `Long` arithmetic with EXACT semantics at compile time; the
/// `ArithmeticException` aborts compilation (oracle: `cc sigmaProp(
/// (2147483647 + 1) < 0)` → `REJECT 0:0 ArithmeticException` — the whole
/// N-2/F-2 family, adversarial-findings-{numerics,constants}.md). Probed
/// fold boundary, honored exactly:
/// - folded: `+`/`-`/`*` over same-width constant operands (operands may
///   themselves be folded arith or folded casts-of-literals — `cc
///   sigmaProp((127.toByte + 1.toByte) < 0.toByte)` REJECTs); `Downcast`/
///   `Upcast` of a DIRECT constant (`300.toByte` REJECTs; mixed-width `cc
///   sigmaProp((9223372036854775807L + 1) < 0L)` REJECTs via the folded
///   `Upcast(1)`); the fold runs EVERYWHERE — unused-val rhs (`cc { val
///   unused = 2147483647 + 1; sigmaProp(true) }` REJECTs) and lambda bodies
///   (`cc sigmaProp(Coll(1).map({(t: Int) => 2147483647 + 1})(0) < 0)`
///   REJECTs) included (all fresh captures 2026-07-07, 3 identical runs);
/// - NOT folded: division/modulo (`cc sigmaProp(1 / 0 == 0)` → OK), BigInt
///   arithmetic, `min`/`max`, `Negation` (Scala negates WRAPPING, never
///   throws — probe 65), and casts of NON-direct-constant subexpressions
///   (`ccs sigmaProp((x * 100).toByte > 0.toByte)` → OK: Scala folds
///   `x * 100` to 1000 but leaves the Downcast unfolded; a cast-of-cast
///   chain is likewise treated as unfolded — un-probed, accept-side
///   bounded).
///
/// Returns the folded `(width, value)` for constant subtrees (`Ok(None)` for
/// non-constant ones) so parent arith arms can chain; an overflow anywhere
/// is `Err` (class `ArithmeticException`, matching the oracle).
fn fold_overflow_check(e: &Expr) -> Result<Option<(FoldWidth, i64)>, EmitError> {
    let overflow = |what: String| EmitError::GraphBuildingReject {
        class: "ArithmeticException",
        what,
    };
    match e {
        Expr::Const { val, .. } => Ok(match val {
            SigmaValue::Byte(v) => Some((FoldWidth::Byte, i64::from(*v))),
            SigmaValue::Short(v) => Some((FoldWidth::Short, i64::from(*v))),
            SigmaValue::Int(v) => Some((FoldWidth::Int, i64::from(*v))),
            SigmaValue::Long(v) => Some((FoldWidth::Long, *v)),
            _ => None,
        }),
        Expr::Unparsed(_) => Ok(None),
        Expr::Op(IrNode { opcode, payload }) => match (opcode, payload) {
            // ArithOp +/-/* (wire bytes: Plus 0x9A, Minus 0x99, Multiply
            // 0x9C). Division 0x9D / modulo 0x9E / min 0xA1 / max 0xA2 fall
            // to the recurse-only arm below (not compile-folded).
            (0x9A | 0x99 | 0x9C, Payload::Two(l, r)) => {
                let lf = fold_overflow_check(l)?;
                let rf = fold_overflow_check(r)?;
                let (Some((wl, a)), Some((wr, b))) = (lf, rf) else {
                    return Ok(None);
                };
                if wl != wr {
                    // Post-typer operands share a width; a mismatch means a
                    // hand-built tree — stay conservative, no fold.
                    return Ok(None);
                }
                // i64 math is exact for Byte/Short/Int operands (|v| <= 2^31,
                // so even products fit i64); Long uses checked ops.
                let (sym, v) = match opcode {
                    0x9A => ("+", a.checked_add(b)),
                    0x99 => ("-", a.checked_sub(b)),
                    _ => ("*", a.checked_mul(b)),
                };
                match v.filter(|v| in_fold_range(wl, *v)) {
                    Some(v) => Ok(Some((wl, v))),
                    None => Err(overflow(format!(
                        "compile-time constant fold overflows {wl:?}: {a} {sym} {b}"
                    ))),
                }
            }
            // Downcast (0x7D) / Upcast (0x7E) of a DIRECT constant fold to
            // the target width; the downcast is range-checked exactly
            // (`300.toByte` rejects). Casts of non-direct-constant inputs
            // stay unfolded (the `(x * 100).toByte` control), but their
            // subtree is still checked.
            (0x7D | 0x7E, Payload::NumericCast { input, tpe }) => {
                let f = fold_overflow_check(input)?;
                let direct_const = matches!(input.as_ref(), Expr::Const { .. });
                match (direct_const, f, fold_width(tpe)) {
                    (true, Some((_, v)), Some(w)) => {
                        if *opcode == 0x7D && !in_fold_range(w, v) {
                            Err(overflow(format!(
                                "compile-time constant downcast out of {w:?} range: {v}"
                            )))
                        } else {
                            Ok(Some((w, v)))
                        }
                    }
                    _ => Ok(None),
                }
            }
            // Everything else: not foldable itself, but every child subtree
            // is still checked (folds run everywhere in Scala's graph
            // construction — see the fn docs).
            (_, payload) => {
                let mut children = Vec::new();
                push_children(payload, &mut children);
                for c in children {
                    fold_overflow_check(c)?;
                }
                Ok(None)
            }
        },
    }
}

/// Compile ErgoScript `source` end-to-end: typecheck, lower to opcode IR,
/// assemble the ErgoTree, serialize, and derive the P2S/P2SH addresses.
///
/// Pipeline: parse → bind → typecheck → root-coerce → emit → [`build_tree`] →
/// `write_ergo_tree` → addresses. Mirrors `ScriptApiRoute.compileSource`
/// (`ScriptApiRoute.scala:56-67`).
///
/// # The three version axes
///
/// 1. **`tree_version` (axis 1, frontend gate ONLY):** threads the v5/v6
///    method-table + predef visibility gate through parse/bind/typecheck
///    (`tree_version >= 3` ⇔ `VersionContext.isV3OrLaterErgoTreeVersion`).
///    Scala's route forwards its `treeVersion` param ONLY into
///    `VersionContext.withVersions` — never into the tree header.
/// 2. **Wire header version (axis 2):** fixed at 0 in M3 (and in the route:
///    `ErgoTree.defaultHeaderWithVersion(0.toByte)` unconditionally). See
///    [`build_tree`].
/// 3. **Activated script version (axis 3):** the EVALUATOR's
///    block-consensus version; a compile-time no-op here — it decides how a
///    node executes the tree, not what bytes we produce.
///
/// # Root coercion
///
/// Mirrors the route's dispatch (`ScriptApiRoute.scala:60-65`): a
/// `SigmaProp`-typed root passes through; a `Boolean`-typed root is wrapped
/// in `BoolToSigmaProp` (opcode `0xD1`, Scala `script.toSigmaProp`); any
/// other root type is [`CompileError::Root`] (the route's bare
/// `new Exception(...)`; oracle: `cc HEIGHT` → `REJECT 0:0 Exception`).
///
/// # P2SH contract
///
/// The P2SH content hash covers the PROPOSITION bytes — the serialized root
/// expression WITHOUT the ErgoTree header/constants wrapper
/// (`Pay2SHAddress.apply(prop)`, `ErgoAddress.scala:210-218`). At M3 trees
/// are non-segregated, so the body already has every constant inline and no
/// substitution step is needed. M4 NOTE: once [`build_tree`] grows the
/// segregation branch, the proposition must be constant-INLINED first
/// (`toProposition(replaceConstants = isConstantSegregation)`,
/// `Pay2SHAddress.apply(script: ErgoTree)`, `ErgoAddress.scala:201-204`) —
/// hashing a body with `ConstPlaceholder` nodes yields a wrong address.
///
/// # Task-10 verdict adjudication (the semantic-parity gate)
///
/// The Task-10 corpus run (`tests/compile_semantic_parity.rs`,
/// `test-vectors/ergoscript/compile/compile_seed.json`) adjudicated every
/// verdict divergence against the full Scala compiler:
/// - Postfix method-call residuals (e.g. `arr1 size`): the UNWRAPPED corpus
///   forms have non-`Boolean`/`SigmaProp` roots, so the route's root
///   dispatch rejects them (class advisory); the WRAPPED forms
///   (`sigmaProp((arr1 size) > 0)`) are rejected by the Task-11 wave-1
///   `%SCollection.size` gate in `emit_method_call` (lib.rs D-C5, exact
///   `GraphBuildingException` class).
/// - `xorOf` over `Coll[SigmaProp]`: rejected in `emit` (Scala
///   GraphBuilding `AssertionError`; see the `XorOf` arm).
/// - v6-only constant data under the v0 header (`unsignedBigInt(..)`
///   comparisons): rejected by the v0-header data gate below
///   ([`CompileError::Serializer`], mirroring Scala's
///   `SerializerException`).
/// - Residual `SigmaPropIsProven` in mixed `Bool`/`SigmaProp` logical
///   contexts: STILL OPEN — lib.rs D-C3 (compile output carries wire
///   opcode `0xCF`, which no evaluator accepts; the Scala IR folds or
///   sigma-reconstructs it away).
/// - Task-11 wave 1 added the GraphBuilding reject-gate family (lib.rs
///   D-C5): bit ops, zero-arg/non-1-arg lambda applications, SFunc-typed
///   lambda params, postfix `size`, out-of-range `getReg` literals,
///   pre-v3 SNumericType methods, and the constant-fold overflow check
///   ([`graph_building_lambda_reject`] / [`fold_overflow_check`] below +
///   the emit-arm gates).
///
/// # Examples
///
/// ```
/// use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
///
/// let r = compile(&ScriptEnv::new(), "sigmaProp(HEIGHT > 100)", 0, NetworkPrefix::Mainnet)
///     .unwrap();
/// // M3 trees are non-segregated: header byte 0x00.
/// assert_eq!(r.tree_bytes[0], 0x00);
/// ```
pub fn compile(
    env: &ScriptEnv,
    source: &str,
    tree_version: u8,
    network: NetworkPrefix,
) -> Result<CompileResult, CompileError> {
    let typed = typecheck_with_network(env, source, tree_version, network)?;

    // Root dispatch — ScriptApiRoute.scala:60-65.
    let root = match node_tpe(&typed) {
        SType::SSigmaProp => emit(&typed)?,
        SType::SBoolean => Expr::Op(IrNode {
            // BoolToSigmaProp — Scala `script.toSigmaProp` (values.scala:58).
            opcode: 0xD1,
            payload: Payload::One(Box::new(emit(&typed)?)),
        }),
        other => {
            return Err(CompileError::Root {
                tpe: to_term_string(other),
            })
        }
    };

    // GraphBuilding verdict-parity gates (lib.rs D-C5): reject the emitted
    // shapes Scala's full compiler rejects — lambda/application rules first,
    // then the constant-fold overflow check; both precede the serializer
    // gate below because GraphBuilding runs before serialization in Scala
    // (the relative order of the two walks is deterministic but advisory —
    // the oracle grades the verdict, classes are exact per family).
    if let Some(e) = graph_building_lambda_reject(&root) {
        return Err(CompileError::Emit(e));
    }
    fold_overflow_check(&root).map_err(CompileError::Emit)?;

    // Wave-2 lowering rewrite (lib.rs D-C6): fold `SizeOf(<coll literal>)` to
    // the element count, as Scala's GraphBuilding does. AFTER the gates above
    // — the discarded literal elements must still be verdict-checked — and
    // BEFORE the v0 data gate/serialization, so a `Coll[UnsignedBigInt]()`
    // under `.size` never puts its v3-only elem-type code on the wire.
    let root = fold_literal_coll_sizes(root);

    // v0-header data gate — Scala's compile route cannot serialize v6-only
    // constant DATA: `ErgoTreeSerializer.serializeErgoTree` re-pins
    // `VersionContext.withVersions(_, treeVersion = ergoTree.version)`
    // (v6.0.2 `data/.../ErgoTreeSerializer.scala:105-112`), and the route's
    // header is ALWAYS `defaultHeaderWithVersion(0)` — so even an
    // ORACLE_TREE_VERSION=3 compile serializes under `treeVersion = 0`, where
    // `CoreDataSerializer.serialize`'s v3-gated arms (`SUnsignedBigInt` at
    // :39, `SOption` at :78) fall through to the :86 catch-all
    // `SerializerException`. Mirror the reject (oracle:
    // `cc unsignedBigInt("5") > unsignedBigInt("3")` → `REJECT 0:0
    // SerializerException`, compile_seed.json). Our wire layer is
    // deliberately version-independent (ergo-ser stays consensus-lenient), so
    // the gate lives here in the compile surface. M4 NOTE: when `build_tree`
    // grows versioned headers, gate on the emitted header version < 3.
    if let Some(what) = find_v0_unserializable(&root) {
        return Err(CompileError::Serializer { what });
    }

    let ergo_tree = build_tree(root);

    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &ergo_tree)?;
    let tree_bytes = w.result();

    // Post-write self-check (Task-11 wave 2; lib.rs D-C6): the bytes we are
    // about to derive ADDRESSES from must round-trip through our own
    // version-gated reader. A failure means compile() would hand out a P2S
    // address whose script no deserializer accepts — funds sent there are
    // stranded (the F-3 class, adversarial-findings-constants.md). This is a
    // DELIBERATE reject-side divergence for two oracle-probed families the
    // ledger documents: (1) `getVar[UnsignedBigInt](1)`-style v3-only TYPE
    // codes under the v0 header, which Scala also emits and ALSO cannot
    // re-read (Note A — the oracle's ACCEPT verdict is itself poisoned:
    // both products are unusable); (2) missing-fold residuals like a
    // val-bound `Coll[UnsignedBigInt]()` under `.size`, where Scala's
    // inline+fold keeps its wire clean and ours would not be. Reject-side
    // safe per the crate bar: a wrong-reject surfaces a user error, a
    // wrong-accept strands funds.
    {
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::ergo_tree::read_ergo_tree;
        let mut r = VlqReader::new(&tree_bytes);
        let reread = read_ergo_tree(&mut r);
        if let Err(e) = reread {
            return Err(CompileError::Serializer {
                what: format!(
                    "emitted tree is not self-readable ({e:?}): refusing to derive an \
                     address for a script no deserializer accepts"
                ),
            });
        }
        if !r.is_empty() {
            return Err(CompileError::Serializer {
                what: "emitted tree has trailing bytes after re-read".to_string(),
            });
        }
    }

    // Proposition bytes for P2SH: root expression only, no header/constants.
    // Non-segregated at M3, so no constant-inlining step (see the fn docs).
    let mut pw = VlqWriter::new();
    write_expr(&mut pw, &ergo_tree.body, false)?;
    let proposition_bytes = pw.result();

    let p2s_address = encode_p2s(network, &tree_bytes);
    let p2sh_address = encode_p2sh(network, &proposition_bytes);

    Ok(CompileResult {
        tree_bytes,
        ergo_tree,
        p2s_address,
        p2sh_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::EnvValue;
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

    // ----- helpers -----

    /// secp256k1 generator, SEC1-compressed. The Task-1 PK test address
    /// `3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN` decodes to
    /// ProveDlog of exactly this point (the well-known "secret = 1" testnet
    /// address), and the oracle env's `g1` is bound to it too.
    const GENERATOR_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Oracle capture, VERBATIM (TyperOracle.scala `cc` verb, sigma-state
    /// 6.0.2 SigmaCompiler + ErgoTreeSerializer + Pay2S/Pay2SHAddress,
    /// ORACLE_NETWORK=testnet, captured 2026-07-04,
    /// `.superpowers/sdd/task-1-report.md` Step-4 smoke, line 2):
    ///
    ///   cc PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")
    ///   → OK <ORACLE_PK_TREE_HEX> <ORACLE_PK_P2S> <ORACLE_PK_P2SH>
    const ORACLE_PK_TREE_HEX: &str =
        "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ORACLE_PK_P2S: &str = "5AgXz2KadZrAXE86MMjVQ7UAWeRFbhBZcQms4j2RgBuHNrVRwY7xvp2S";
    const ORACLE_PK_P2SH: &str = "qETVgcEctaXurNbFRgGUcZEGg4EKa8R4a5UNHY7";

    /// Same capture, line 1:
    ///
    ///   cc sigmaProp(HEIGHT > 100)
    ///   → OK 100104c801d191a37300 Xw4DF8oEhUcUi3f7LAHt
    ///        qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S
    ///
    /// The oracle tree is SEGREGATED (header 0x10, constants table
    /// `01 04c801`, body `d191a37300` with placeholder `7300`); its
    /// constant-INLINED proposition — what Pay2SHAddress hashes — is
    /// `d191a304c801`.
    const ORACLE_HGT_P2S: &str = "Xw4DF8oEhUcUi3f7LAHt";
    const ORACLE_HGT_P2SH: &str = "qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S";

    fn compile_testnet(env: &ScriptEnv, source: &str) -> Result<CompileResult, CompileError> {
        // tree_version 0 = the route default; axis-1 only gates v6 method
        // visibility, which none of these sources touch.
        compile(env, source, 0, NetworkPrefix::Testnet)
    }

    fn ct(source: &str) -> Result<CompileResult, CompileError> {
        compile_testnet(&ScriptEnv::new(), source)
    }

    fn generator_env() -> ScriptEnv {
        let bytes: [u8; 33] = hex::decode(GENERATOR_HEX).unwrap().try_into().unwrap();
        let mut env = ScriptEnv::new();
        env.insert(
            "g1",
            EnvValue::GroupElement(GroupElement::from_bytes(bytes)),
        );
        env
    }

    fn reparse(bytes: &[u8]) -> ErgoTree {
        let mut r = VlqReader::new(bytes);
        read_ergo_tree(&mut r).expect("compiled tree must reparse")
    }

    // ----- happy path -----

    #[test]
    fn compile_bool_root_wraps_in_bool_to_sigma_prop() {
        // `HEIGHT > 100` types SBoolean → route coercion wraps in 0xD1
        // (ScriptApiRoute.scala:62-63 `script.toSigmaProp`), producing the
        // SAME tree as the explicit `sigmaProp(...)` form.
        let bare = ct("HEIGHT > 100").expect("compile");
        let explicit = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert!(
            matches!(&bare.ergo_tree.body, Expr::Op(IrNode { opcode: 0xD1, .. })),
            "bool root must be wrapped in BoolToSigmaProp"
        );
        assert_eq!(bare.tree_bytes, explicit.tree_bytes);
        assert_eq!(bare.p2s_address, explicit.p2s_address);
        assert_eq!(bare.p2sh_address, explicit.p2sh_address);
    }

    #[test]
    fn compile_pk_bare_const_header_zero_and_shape() {
        // PK(...) compiles straight to a bare SigmaPropConstant — the
        // fromProposition `SigmaPropConstant(_)` branch (withoutSegregation):
        // header 0x00, empty constants, body = the constant itself (the
        // exact `detect_p2pk` shape in ergo-ser).
        let r = compile_testnet(
            &ScriptEnv::new(),
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
        )
        .expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00, "non-segregated v0 header");
        assert!(r.ergo_tree.constants.is_empty());
        assert!(matches!(
            &r.ergo_tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_)),
            }
        ));
    }

    #[test]
    fn compile_sigmaprop_height_header_zero_nonsegregated() {
        // Decision 3 (M3): EVERY tree is emitted non-segregated (header
        // 0x00). Scala segregates non-bare-constant roots (header 0x10, see
        // the oracle capture in the parity section) — the M4 flip point is
        // build_tree's missing withSegregation branch.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00);
        assert!(!r.ergo_tree.constant_segregation);
        assert!(r.ergo_tree.constants.is_empty());
        // Oracle-derived expected bytes: 0x00 header + the constant-inlined
        // proposition of the oracle capture (`100104c801d191a37300` with
        // placeholder 7300 → constant 04c801) = 00 d1 91 a3 04c801.
        assert_eq!(hex::encode(&r.tree_bytes), "00d191a304c801");
    }

    // ----- round-trips -----

    #[test]
    fn compile_output_reparses_to_same_tree() {
        for src in [
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
            "sigmaProp(HEIGHT > 100)",
            "HEIGHT > 100",
        ] {
            let r = compile_testnet(&ScriptEnv::new(), src).expect("compile");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "src = {src}");
        }
        let r = compile_testnet(&generator_env(), "proveDlog(g1)").expect("compile");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
    }

    // ----- error paths -----

    #[test]
    fn compile_int_root_rejects_with_exception_class() {
        // Route :64-65: neither Bool nor SigmaProp root → bare Exception.
        let err = ct("1 + 1").expect_err("Int root must reject");
        assert!(matches!(&err, CompileError::Root { tpe } if tpe == "Int"));
        assert_eq!(err.class(), "Exception");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_height_root_rejects_matching_oracle_probe() {
        // Oracle (task-1-report.md extra probes): `cc HEIGHT` →
        // `REJECT 0:0 Exception`.
        let err = ct("HEIGHT").expect_err("Int root must reject");
        assert_eq!(err.class(), "Exception");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_parse_error_propagates_as_parse_phase() {
        let err = ct(")(").expect_err("parse must fail");
        assert!(matches!(err, CompileError::Parse(_)));
    }

    #[test]
    fn compile_unsigned_bigint_constant_rejects_serializer_class() {
        // Oracle (compile_seed.json, ORACLE_TREE_VERSION=3, captured
        // 2026-07-07): both UnsignedBigInt comparison sources reply
        // `REJECT 0:0 SerializerException` — the route's fixed v0 header
        // cannot carry UnsignedBigInt constant DATA (the v0-header data gate
        // in `compile`; mechanism citations there). tree_version = 3: the
        // FRONTEND accepts the v6 predef; the reject is the WIRE header's —
        // the two version axes are independent.
        for src in [
            r#"unsignedBigInt("5") == unsignedBigInt("3")"#,
            r#"unsignedBigInt("5") > unsignedBigInt("3")"#,
        ] {
            let err = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)
                .expect_err("UBI constant under a v0 header must reject");
            assert!(
                matches!(&err, CompileError::Serializer { .. }),
                "{src}: {err:?}"
            );
            assert_eq!(err.class(), "SerializerException", "{src}");
            assert_eq!(err.pos(), 0, "{src}");
        }
    }

    // ----- error paths: GraphBuilding parity gates (lib.rs D-C5, wave 1) -----
    // Every oracle fact below: captured 2026-07-07, 3 identical runs,
    // committed as compile_seed.json vectors (except the ACCEPT boundaries
    // whose trees are unevaluable on our side — the D-C4 class — which are
    // pinned here verdict-only).

    #[test]
    fn compile_bit_op_wrapped_in_sigmaprop_rejects_graph_building_class() {
        // Oracle: `cc sigmaProp((1 | 2) == 3)` → `REJECT 1:12
        // GraphBuildingException` (all of |,&,^,<<,>>,>>>,~ — the emit
        // BitOp/BitInversion arms; width matrix pinned in emit.rs tests).
        for src in ["sigmaProp((1 | 2) == 3)", "sigmaProp((~1) == -2)"] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "GraphBuildingException", "{src}");
        }
        // Boolean ^ is BinXor, not a BitOp — still compiles.
        ct("sigmaProp((HEIGHT > 1) ^ (HEIGHT < 5))").expect("BinXor untouched");
    }

    #[test]
    fn compile_zero_arg_lambda_rejects_even_unused() {
        // Oracle: `cc { val f = {() => 1}; sigmaProp(f() == 1) }` → `REJECT
        // 1:12 GraphBuildingException`; the UNUSED variant rejects too
        // (`REJECT 1:17`) — the definition itself crashes Scala's graph
        // construction, before dead-code elimination.
        for src in [
            "{ val f = {() => 1}; sigmaProp(f() == 1) }",
            "{ val unused = {() => 1}; sigmaProp(true) }",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "GraphBuildingException", "{src}");
        }
    }

    #[test]
    fn compile_multi_arg_application_rejects_definitions_and_hof_slots_accept() {
        // Rejects: every non-1-arg APPLICATION (direct, aliased, inline) —
        // oracle `REJECT GraphBuildingException` on all four.
        for src in [
            "{ val f = {(x: Int, y: Int) => x + y}; sigmaProp(f(1, 2) == 3) }",
            "{ val f = {(x: Int, y: Int, z: Int) => x + y + z}; sigmaProp(f(1, 2, 3) == 6) }",
            "{ val f = {(x: Int, y: Int) => x + y}; val g = f; sigmaProp(g(1, 2) == 3) }",
            "sigmaProp({(x: Int, y: Int) => x + y}(1, 2) == 3)",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "GraphBuildingException", "{src}");
        }
        // Accepts (oracle OK): the multi-arg DEFINITION is fine — unused
        // val, un-applied alias, and both fold-callback forms (direct and
        // val-bound = the D-C4 both-accept class; our trees for these stay
        // unevaluable multi-arg FuncValues, ledger D-C4/D-C5).
        for src in [
            "{ val unused = {(x: Int, y: Int) => x + y}; sigmaProp(true) }",
            "{ val f = {(x: Int, y: Int) => x + y}; val g = f; sigmaProp(true) }",
            "{ val f = {(a: Long, b: Long) => a + b}; sigmaProp(Coll(1L, 2L).fold(0L, f) == 3L) }",
            "sigmaProp(Coll(1L, 2L).fold(0L, {(a: Long, b: Long) => a + b}) == 3L)",
        ] {
            ct(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        }
    }

    #[test]
    fn compile_function_typed_lambda_param_rejects_match_error_class() {
        // Oracle: `REJECT 0:0 MatchError` — even when the parameter is never
        // applied in the body; the exemption is an UNUSED val binding
        // (pruned before the lowering that dies — fresh boundary capture).
        for src in [
            "{ val h = {(f: Int => Int) => f(10)}; sigmaProp(h({(x: Int) => x + 1}) == 11) }",
            "{ val h = {(f: Int => Int) => 1}; sigmaProp(h({(x: Int) => x}) == 1) }",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "MatchError", "{src}");
        }
        // Oracle OK: unused val-bound SFunc-param lambda (pruned)...
        ct("{ val unused = {(f: Int => Int) => 1}; sigmaProp(true) }")
            .expect("unused SFunc-param lambda is pruned by Scala — must accept");
        // ...and a lambda RETURNING a lambda (curried) is not a
        // function-typed PARAMETER — accepted on both sides.
        ct("{ val f = {(x: Int) => {(y: Int) => x + y}}; sigmaProp(f(1)(2) == 3) }")
            .expect("curried lambda accepts");
    }

    #[test]
    fn compile_postfix_size_and_get_reg_range_reject_with_oracle_classes() {
        // Postfix residual `size` (emit gate; oracle `cc sigmaProp((OUTPUTS
        // size) >= 0)` → `REJECT 1:12 GraphBuildingException`).
        let err = ct("sigmaProp((OUTPUTS size) >= 0)").expect_err("postfix size");
        assert_eq!(err.class(), "GraphBuildingException");
        // getReg out-of-range literal (emit gate; oracle `REJECT 0:0
        // ArrayIndexOutOfBoundsException`); v6 method → tree_version 3.
        let err = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.getReg[Int](100).isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect_err("out-of-range getReg");
        assert_eq!(err.class(), "ArrayIndexOutOfBoundsException");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_constant_fold_overflow_rejects_arithmetic_exception_class() {
        // Oracle: `REJECT 0:0 ArithmeticException` on the whole family
        // (compile-time exact fold of constant +,-,* and casts-of-literals;
        // the fold runs in unused-val rhs and lambda bodies too).
        for src in [
            "sigmaProp(300.toByte < 0.toByte)",
            "sigmaProp(2147483647.toShort > 0.toShort)",
            "sigmaProp((2147483647 + 1) < 0)",
            "sigmaProp((9223372036854775807L + 1L) < 0L)",
            "sigmaProp((9223372036854775807L + 1) < 0L)", // folded Upcast(1) feeds the +
            "sigmaProp(9223372036854775807L * 2L > 0L)",
            "sigmaProp((127.toByte + 1.toByte) < 0.toByte)",
            "sigmaProp(-2147483647 - 2 < 0)",
            "{ val unused = 2147483647 + 1; sigmaProp(true) }",
            "sigmaProp(Coll(1).map({(t: Int) => 2147483647 + 1})(0) < 0)",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "ArithmeticException", "{src}");
            assert_eq!(err.pos(), 0, "{src}");
        }
    }

    #[test]
    fn compile_fold_boundary_controls_still_accept() {
        // Oracle ACCEPT controls pinning what Scala does NOT compile-fold:
        // division (`1 / 0` compiles!), in-range folds, non-constant
        // operands, exactly-representable boundaries.
        for src in [
            "sigmaProp(1 / 0 == 0)",
            "sigmaProp((2147483647 + 0) < 0)",
            "sigmaProp((2147483646 + 1) < 0)",
            "sigmaProp((-9223372036854775807L - 1L) < 0L)", // exactly Long.MIN
            "sigmaProp((HEIGHT + 2147483647) > 0)",
        ] {
            ct(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        }
        // A cast of a NON-direct-constant subexpression is not folded even
        // when the subtree folds (oracle: `ccs sigmaProp((x * 100).toByte >
        // 0.toByte)` → OK, residual Downcast; x is the env constant 10).
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Int(10));
        compile(
            &env,
            "sigmaProp((x * 100).toByte > 0.toByte)",
            0,
            NetworkPrefix::Testnet,
        )
        .expect("cast of folded-but-not-direct constant stays unfolded — must accept");
    }

    #[test]
    fn compile_xorof_sigmaprop_coll_rejects_matching_oracle_verdict() {
        // Oracle: `cc xorOf(Coll(sigmaProp(true)))` → `REJECT 0:0
        // AssertionError` (GraphBuilding.scala:855-862 force-casts the input
        // to Coll[Boolean] and dies; see the emit XorOf arm). The class is
        // advisory — Java's AssertionError has no Rust analog — the REJECT
        // verdict is the parity fact.
        let err = ct("xorOf(Coll(sigmaProp(true)))").expect_err("must reject");
        assert!(matches!(&err, CompileError::Emit(_)), "{err:?}");
        // Boolean-element xorOf is untouched by the gate.
        ct("xorOf(Coll(true, false))").expect("boolean xorOf still compiles");
    }

    // ----- oracle parity -----

    #[test]
    fn compile_pk_bytes_and_addresses_match_oracle() {
        // The ONE byte-gated class at M3: a bare-constant root takes the
        // withoutSegregation branch on BOTH sides, so bytes AND both
        // addresses must match the oracle verbatim (capture provenance on
        // the ORACLE_PK_* consts above; testnet capture → testnet compile).
        let r = compile_testnet(
            &ScriptEnv::new(),
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
        )
        .expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), ORACLE_PK_TREE_HEX);
        assert_eq!(r.p2s_address, ORACLE_PK_P2S);
        assert_eq!(r.p2sh_address, ORACLE_PK_P2SH);
        // The oracle P2S reply doubles as the forced-P2S pin: Scala's
        // Pay2SAddress answers P2S even for a bare ProveDlog constant, and
        // matching it proves we did not route through encode_address (which
        // would detect_p2pk this exact body and emit a P2PK address).
        // Belt-and-braces: the raw prefix byte is testnet|P2S = 0x13.
        let raw = bs58::decode(&r.p2s_address).into_vec().unwrap();
        assert_eq!(raw[0], 0x13, "testnet P2S prefix, not P2PK (0x11)");
    }

    #[test]
    fn compile_sigmaprop_height_p2s_differs_p2sh_matches_oracle() {
        // Honest M3 state for the segregated class: the oracle tree is
        // `100104c801d191a37300` (header 0x10); ours is non-segregated
        // (header 0x00, asserted in the happy-path section), so the tree
        // bytes and the P2S address MUST differ until the M4 segregation
        // transform lands. The semantic-equality gate is Task 10.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_ne!(r.p2s_address, ORACLE_HGT_P2S);
        // The P2SH address, however, hashes the constant-INLINED proposition
        // (`d191a304c801`) — exactly our non-segregated body bytes — so it
        // must MATCH the oracle capture byte-for-byte. This is a genuine
        // cross-representation parity gate on our proposition bytes.
        assert_eq!(r.p2sh_address, ORACLE_HGT_P2SH);
    }

    // ----- oracle parity: Task-11 wave-2 lowerings/folds (lib.rs D-C6) -----
    // Every oracle fact below: TyperOracle cc/ccs verbs, sigma-state 6.0.2,
    // ORACLE_TREE_VERSION=3, ORACLE_NETWORK=testnet, captured 2026-07-07,
    // 3 identical runs (committed as compile_seed.json wave-2 vectors).
    // Our trees stay non-segregated (D-C1), so the ORACLE-comparable byte
    // surface is the P2SH address — it hashes the constant-inlined
    // PROPOSITION, which must be node-for-node identical after the fixes.

    #[test]
    fn compile_get_reg_literal_lowers_to_r5_bytes_and_oracle_p2sh() {
        // Oracle: `cc sigmaProp(SELF.getReg[Int](5).isDefined)` and
        // `cc sigmaProp(SELF.R5[Int].isDefined)` reply IDENTICALLY:
        // `1000d1e6c6a70504 2b6DJR5QoSgM31MUQ6 qzYN3szTjLnSbqXUA55vyCopdNpu88qJuPzmoks`.
        let get_reg = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.getReg[Int](5).isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        let r5 = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.R5[Int].isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(get_reg.tree_bytes, r5.tree_bytes);
        assert_eq!(hex::encode(&get_reg.tree_bytes), "00d1e6c6a70504");
        assert_eq!(
            get_reg.p2sh_address,
            "qzYN3szTjLnSbqXUA55vyCopdNpu88qJuPzmoks"
        );
        // Dynamic index keeps the MethodCall on BOTH sides (oracle:
        // `1000d1e6dc6313a701a304 … q1RuFk3PeKdvEbAb6dUZqVxYDZ5i8QdWg4DkK4Z`).
        let dynamic = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.getReg[Int](HEIGHT).isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&dynamic.tree_bytes), "00d1e6dc6313a701a304");
        assert_eq!(
            dynamic.p2sh_address,
            "q1RuFk3PeKdvEbAb6dUZqVxYDZ5i8QdWg4DkK4Z"
        );
    }

    #[test]
    fn compile_val_bound_get_reg_index_stays_residual_method_call() {
        // D-C6 residual, pinned verdict-only (NOT a committed vector): Scala
        // const-propagates the val and still lowers (oracle: `cc { val i =
        // 4; sigmaProp(SELF.getReg[Int](i).isDefined) }` → `1000d1e6c6a70404`,
        // the val eliminated entirely); our typed AST keeps the ValUse, so
        // the MethodCall survives — BOTH sides accept, but our tree is
        // unevaluable under the v0 header (the oracle's evaluates), which is
        // why the semantic gate cannot carry this vector.
        let r = compile(
            &ScriptEnv::new(),
            "{ val i = 4; sigmaProp(SELF.getReg[Int](i).isDefined) }",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("both-accept residual must still compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "00d801d6010408d1e6dc6313a701720104"
        );
    }

    #[test]
    fn compile_slice_explicit_type_arg_matches_unannotated_and_oracle_p2sh() {
        // Oracle: the annotated and un-annotated forms reply IDENTICALLY
        // (`ccs sigmaProp(arr1.slice[Byte](0, 1).size == 1)` =
        //  `ccs sigmaProp(arr1.slice(0, 1).size == 1)` →
        // `10040e020102040004020402d193b1b47300730173027303 …
        //  rgwBvuzJFRePZZ1FJp4qddZq8KXpjkdA5a8hfbJ`).
        let mut env = ScriptEnv::new();
        env.insert("arr1", EnvValue::ByteArray(vec![1, 2]));
        let annotated = compile(
            &env,
            "sigmaProp(arr1.slice[Byte](0, 1).size == 1)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        let plain = compile(
            &env,
            "sigmaProp(arr1.slice(0, 1).size == 1)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(annotated.tree_bytes, plain.tree_bytes);
        assert_eq!(
            hex::encode(&annotated.tree_bytes),
            "00d193b1b40e020102040004020402"
        );
        assert_eq!(
            annotated.p2sh_address,
            "rgwBvuzJFRePZZ1FJp4qddZq8KXpjkdA5a8hfbJ"
        );
    }

    #[test]
    fn compile_numeric_const_fold_matches_oracle_p2sh() {
        // Oracle: `ccs sigmaProp(x.toBytes.size == 4)` →
        // `10020e040000000a0408d193b173007301 … qApjfu2kT7Lr8bYG7c4UMKgYJSPD32SkbBDAQMD`
        // (x = 10; the folded big-endian Coll[Byte] constant), and
        // `ccs sigmaProp(x.toBits.size == 32)` →
        // `10020d20000000500440d193b173007301 … qse65TyiDnutjxRzCP1mnCttRKWZqPrhnsvG7cg`.
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Int(10));
        let bytes = compile(
            &env,
            "sigmaProp(x.toBytes.size == 4)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&bytes.tree_bytes), "00d193b10e040000000a0408");
        assert_eq!(
            bytes.p2sh_address,
            "qApjfu2kT7Lr8bYG7c4UMKgYJSPD32SkbBDAQMD"
        );
        let bits = compile(
            &env,
            "sigmaProp(x.toBits.size == 32)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&bits.tree_bytes), "00d193b10d20000000500440");
        assert_eq!(bits.p2sh_address, "qse65TyiDnutjxRzCP1mnCttRKWZqPrhnsvG7cg");
    }

    #[test]
    fn compile_sizeof_coll_literal_folds_to_clean_v0_bytes() {
        // F-3 (adversarial-findings-constants.md): before wave 2 the empty
        // `Coll[UnsignedBigInt]()` literal put v3-only TYPE code 9 on the v0
        // wire — bytes our own read_ergo_tree refuses (a stranded-funds
        // P2S). The SizeOf fold keeps it off the wire, matching Scala's
        // GraphBuilding fold (oracle: `.size == 0` → the fully-folded
        // `10010101d17300`; `.size.toLong == SELF.value` →
        // `10010400d1937e730005c1a7 … pvyEFnLjY1hb7ebaccofdS88Z9v1WwKxUzUB4y9`
        // — the `.size` folds to Int 0 even when the surrounding expression
        // cannot fold).
        let r = compile(
            &ScriptEnv::new(),
            "sigmaProp(Coll[UnsignedBigInt]().size == 0)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "00d19304000400");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
        let r = compile(
            &ScriptEnv::new(),
            "sigmaProp(Coll[UnsignedBigInt]().size.toLong == SELF.value)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "00d1937e040005c1a7");
        assert_eq!(r.p2sh_address, "pvyEFnLjY1hb7ebaccofdS88Z9v1WwKxUzUB4y9");
        // The fold covers NON-constant elements too (oracle: `cc sigmaProp(
        // Coll(HEIGHT).size == 1)` folds — reply `10010101d17300`).
        let r = ct("sigmaProp(Coll(HEIGHT).size == 1)").expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "00d19304020402");
        // Discarded elements are still verdict-checked: the constant-fold
        // overflow gate runs BEFORE the rewrite (oracle rejects this too).
        let err = ct("sigmaProp(Coll(2147483647 + 1).size == 1)").expect_err("overflow");
        assert_eq!(err.class(), "ArithmeticException");
    }

    #[test]
    fn compile_self_unreadable_emission_rejects_serializer_class() {
        // Post-write self-check (D-C6): compile() re-reads its own bytes and
        // REFUSES to hand out an address for a script no deserializer
        // accepts. Two oracle-probed families flip verdict DELIBERATELY
        // (documented reject-side divergences, NOT committed vectors):
        //
        // (1) Note A: `cc sigmaProp(getVar[UnsignedBigInt](1).isDefined)` —
        //     oracle ACCEPTs `1000d1e6e30109`, bytes NEITHER side's
        //     version-gated reader re-parses (type code 9 under the v0
        //     header). The oracle's ACCEPT is itself poisoned: funds sent to
        //     its address are stranded on BOTH implementations.
        let err = compile(
            &ScriptEnv::new(),
            "sigmaProp(getVar[UnsignedBigInt](1).isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect_err("self-unreadable emission must reject");
        assert!(matches!(&err, CompileError::Serializer { .. }), "{err:?}");
        assert_eq!(err.class(), "SerializerException");
        //
        // (2) Missing-fold residual: a VAL-BOUND `Coll[UnsignedBigInt]()`
        //     under `.size` — Scala inlines the val and folds (oracle reply
        //     identical to the inline form, `10010400d1937e730005c1a7`); our
        //     `SizeOf(ValUse)` keeps the poisoned literal on the wire, so
        //     the self-check rejects rather than strand funds.
        let err = compile(
            &ScriptEnv::new(),
            "{ val u = Coll[UnsignedBigInt](); sigmaProp(u.size.toLong == SELF.value) }",
            3,
            NetworkPrefix::Testnet,
        )
        .expect_err("val-bound poisoned literal must reject");
        assert!(matches!(&err, CompileError::Serializer { .. }), "{err:?}");
    }

    #[test]
    fn compile_prove_dlog_generator_unfolded_header_and_shape_only() {
        // Oracle capture, line 3: `cce proveDlog(g1)` → the SAME reply as
        // the PK line (tree `0008cd0279be...`, both addresses identical):
        // Scala's IR pipeline constant-folds CreateProveDlog(const) →
        // SigmaPropConstant at the GraphBuilding stage (task-1-report.md
        // Concern 1; g1 = the generator = the PK test key). WE emit the
        // unfolded `CreateProveDlog(Const)` — still non-segregated 0x00 but
        // DIFFERENT body bytes, so this asserts header/shape only. The
        // constant fold is an M4/M5 lowering rule (ledger note).
        let r = compile_testnet(&generator_env(), "proveDlog(g1)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00);
        assert!(r.ergo_tree.constants.is_empty());
        // Body = CreateProveDlog (0xCD) over a GroupElement constant.
        match &r.ergo_tree.body {
            Expr::Op(IrNode {
                opcode: 0xCD,
                payload: Payload::One(inner),
            }) => assert!(matches!(
                inner.as_ref(),
                Expr::Const {
                    tpe: SigmaType::SGroupElement,
                    ..
                }
            )),
            other => panic!("expected CreateProveDlog node, got {other:?}"),
        }
        // NOT byte-equal to the oracle's folded bare-constant tree.
        assert_ne!(hex::encode(&r.tree_bytes), ORACLE_PK_TREE_HEX);
        assert_ne!(r.p2s_address, ORACLE_PK_P2S);
        assert_ne!(r.p2sh_address, ORACLE_PK_P2SH);
    }
}
