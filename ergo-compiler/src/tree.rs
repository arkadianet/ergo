//! ErgoTree assembly + the public end-to-end [`compile`] API (M3 Task 9).
//!
//! Wires the full pipeline source → bytes → address: parse → bind →
//! typecheck ([`crate::typecheck_with_network`]) → root coercion → emit
//! ([`crate::emit`]) → [`build_tree`] → wire write → P2S/P2SH address
//! construction. Mirrors the node's compile surface,
//! `ScriptApiRoute.compileSource`
//! (`ergo/src/main/scala/org/ergoplatform/http/api/ScriptApiRoute.scala:56-67`).

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_p2s, encode_p2sh, NetworkPrefix};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::error::WriteError;
use ergo_ser::opcode::{
    parse_expr, write_expr, write_expr_segregating, ConstantSink, Expr, IrNode, Payload,
};
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
    /// The assembled tree (always version 0, no size; constant-segregated
    /// unless the root is a bare `SigmaPropConstant` — the D-C1 flip).
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

/// `true` when `root` is a bare `SigmaPropConstant` — the ONE class Scala's
/// `fromProposition` routes to `withoutSegregation` (header `0x00`, inline).
/// The check is on the ROOT node only: a `SigmaPropConstant` nested inside a
/// larger proposition is just another constant that segregates like any other
/// (recon-segregation.md §3, last paragraph).
pub(crate) fn is_bare_sigma_prop_constant(root: &Expr) -> bool {
    matches!(
        root,
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(_),
        }
    )
}

/// Constant segregation — Scala's `ErgoTree.withSegregation`
/// (`ErgoTree.scala:384-398`), a literal write→re-read round trip:
///
/// 1. serialize `root` through [`write_expr_segregating`] with a fresh
///    [`ConstantSink`]: every `Expr::Const` is appended to the sink (slot =
///    first-write order, append-only, NO dedup) and a `ConstPlaceholder(index)`
///    is written in its place — the SAME writer traversal as the plain path, so
///    the slot order IS the serialization pre-order and the Relation2 `0x85`
///    bool-pair compaction is bypassed for free (it never reaches the
///    `Expr::Const` arm);
/// 2. re-read those bytes with [`parse_expr`] to materialize the
///    placeholder-bearing body — we do NOT hand-build the placeholder tree,
///    mirroring Scala's `ValueSerializer.deserialize(r)` step exactly.
///
/// Returns `(placeholder_body, constants_table)`. A re-read failure of bytes we
/// just wrote is an internal invariant violation (the SAME reader accepts every
/// real chain tree), surfaced as [`WriteError::InvalidData`] rather than
/// `.unwrap()`-ing in library code.
fn segregate(root: &Expr) -> Result<(Expr, Vec<(SigmaType, SigmaValue)>), WriteError> {
    let mut sink = ConstantSink::new();
    let mut w = VlqWriter::new();
    write_expr_segregating(&mut w, root, &mut sink)?;
    let bytes = w.result();

    let mut r = VlqReader::new(&bytes);
    // tree_version 0: the segregation re-read is version-independent (opcode-
    // driven); a `0x73` byte parses as ConstPlaceholder regardless.
    let body = parse_expr(&mut r, 0, 0).map_err(|e| {
        WriteError::InvalidData(format!("constant-segregation re-read failed: {e:?}"))
    })?;
    if !r.is_empty() {
        return Err(WriteError::InvalidData(
            "constant-segregation re-read left trailing bytes".into(),
        ));
    }
    Ok((body, sink.into_constants()))
}

/// Assemble the ErgoTree around an emitted root expression.
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
/// **The D-C1 flip (M4 Task 2):** a bare-constant root (e.g. `PK("...")` →
/// `SigmaPropConstant`) takes `withoutSegregation` — header `0x00`, empty
/// constants table, the constant itself as the body (byte-identical to Scala on
/// both sides). EVERY other root takes `withSegregation` via [`segregate`] —
/// header `0x10`, constants pulled into the table, `ConstPlaceholder` nodes in
/// the body. Both forms are valid, parseable, semantically equal trees.
///
/// Header provenance (route fact): the wire header always comes from
/// `ErgoTree.defaultHeaderWithVersion(0)` — `ScriptApiRoute.compileSource`
/// never forwards its `treeVersion` request parameter into the header; that
/// parameter only gates frontend method visibility via
/// `VersionContext.withVersions`. So `version` is fixed 0 and `has_size`
/// false (the size bit is only required for version > 0).
pub(crate) fn build_tree(root: Expr) -> Result<ErgoTree, WriteError> {
    if is_bare_sigma_prop_constant(&root) {
        Ok(ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: root,
        })
    } else {
        let (body, constants) = segregate(&root)?;
        Ok(ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants,
            body,
        })
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
///   APPLICATION node, not on the `FuncValue`. Those accepted multi-arg
///   DEFINITIONS are lowered to the tupled 1-arg form downstream by
///   [`crate::tuple`] (M4 Task 7, D-C4 CLOSED), which is why they are
///   evaluable and byte-matchable — this gate itself is unchanged.
/// - **A lambda with a FUNCTION-typed parameter rejects** (`{(f: Int => Int)
///   => f(10)}` and the param-unused body variant → `REJECT 0:0
///   MatchError`) UNLESS the lambda is the rhs of a ValDef whose id has zero
///   `ValUse` occurrences (fresh capture: `cc { val unused = {(f: Int =>
///   Int) => 1}; sigmaProp(true) }` → OK — the unused val is dead-code
///   eliminated before the lowering that dies). Residual asymmetry vs the
///   zero-arg rule is oracle-pinned, not a modeling choice. A `FuncValue`
///   with an `SFunc` param NESTED inside an unused val's rhs (not directly
///   the rhs) is still rejected — PROBE-CONFIRMED reject-valid divergence
///   (the regression re-verify's NF-2: the oracle prunes the unused val and
///   ACCEPTs; we reject). Reject-side bounded, ledgered at D-C5 class 3;
///   closes when the M4/M5 pruning transform lands.
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
pub(crate) enum FoldWidth {
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

pub(crate) fn in_fold_range(w: FoldWidth, v: i64) -> bool {
    match w {
        FoldWidth::Byte => i8::try_from(v).is_ok(),
        FoldWidth::Short => i16::try_from(v).is_ok(),
        FoldWidth::Int => i32::try_from(v).is_ok(),
        FoldWidth::Long => true,
    }
}

/// Explicit-cast folds, BOTH directions (M4 Task 4; recon-transforms.md §7).
///
/// Scala's `buildNode`/`eval` intercepts `Upcast(Constant(v,_), toTpe)` /
/// `Downcast(Constant(v,_), toTpe)` (`GraphBuilding.scala:514-518`) as a
/// STRUCTURAL, non-recursive pattern match against the untouched AST: it
/// fires only when the cast's immediate argument, as it was ORIGINALLY
/// built (before any lowering — ours or Scala's), is itself a bare
/// `Constant` node. This walk mirrors that exactly:
///
/// - **fold** (direction (a), the D-C5 checker's retired cast arm): a
///   `Downcast`/`Upcast` whose immediate child IS `Expr::Const` folds to the
///   cast target's `Const` — range-checked exactly like Scala's
///   `toByteExact`/`toShortExact`/`toIntExact` (`300.toByte` REJECTs,
///   `ArithmeticException`, matching the retired checker's message
///   verbatim); Upcast never overflows (widening only). Flips
///   recon-targets.md vectors 60/61/62 outright (`0.toByte`/`9.toByte`
///   argument casts) and is an ingredient of 73/84/85 and the chaincash
///   corpus's `Upcast` residuals (still MULTI — those also need Task 5's
///   generic const-fold for the surrounding `Eq`/bitwise).
/// - **do NOT fold** (direction (b) — the cascade a naive bottom-up
///   implementation of this SAME pass would introduce; no such over-fold
///   ever shipped in either the typer or emit — pinned by the
///   `mod tests` regression pair
///   `compile_cast_chain_keeps_only_innermost_fold_matching_oracle_probe_34`
///   / `compile_cast_chain_depth_three_nested_under_gt_keeps_all_outer_casts`):
///   when the child is anything else — critically, ANOTHER
///   `Downcast`/`Upcast` node. A literal cast CHAIN (`1.toByte.toLong
///   .toBigInt`) builds `Upcast(Upcast(Downcast(Const(1),Byte),Long),BigInt)`
///   at emit time (verified: `ergo-compiler/src/emit.rs`'s Select-cast arm
///   just wraps whatever `self.emit(obj)` returns, one opcode per source
///   `.castMethod`, with NO fold). Recursing into that non-constant child
///   (to give the innermost `Downcast` its OWN, independent fold decision)
///   and then REBUILDING the same outer node — never re-checking whether
///   the now-lowered child happens to have become a `Const` — is what keeps
///   this non-cascading: only the cast immediately adjacent to the literal
///   folds, matching numerics N-3 probe 34's oracle capture
///   (`d1917e7e730005067301`: TWO real `Upcast` nodes over the folded Byte
///   constant, not one folded `BigInt` constant). A naive bottom-up
///   "recurse first, then check if the (now-lowered) child is `Const`"
///   traversal would cascade-fold the whole chain — this is the exact bug
///   class this function must NOT reintroduce.
///
/// **Pass position:** runs immediately BEFORE [`crate::fold::fold`] (the
/// generic constant fold, whose overflow-reject arm this pass's retired D-C5
/// twin folded into) and BEFORE that pass's `SizeOf`-literal fold / the
/// v0-data gate / [`crate::lower::lower`]. Both orderings are load-bearing,
/// not incidental:
/// - **before the arithmetic fold:** a direct-constant `Upcast` (e.g. the
///   typer's mixed-width widening in `9223372036854775807L + 1` — the Int
///   `1` upcasts to `Long`) must already be a plain `Const` by the time the
///   arithmetic fold inspects it, or its `Expr::Const` fast path never sees a
///   value to propagate into the enclosing `+`/`-`/`*`/`min`/`max`, silently
///   losing the overflow detection. Symmetrically, [`crate::fold::fold`] never
///   folds a `NumericCast` node itself — so a cast whose child only BECOMES a
///   `Const` via a later arith fold (`ccs (x*100).toByte`) stays unfolded,
///   exactly like the oracle.
/// - **before the `SizeOf` fold:** `sigmaProp(Coll[UnsignedBigInt]()
///   .size.toLong == SELF.value)` is an oracle-pinned regression
///   (`compile_sizeof_coll_literal_folds_to_clean_v0_bytes`, tree_hex
///   `10010400d1937e730005c1a7`) whose `.toLong` wraps a `SizeOf` that is
///   STILL an unevaluated `Op` node at THIS pass's position — so this walk
///   correctly leaves the `Upcast` unfolded, exactly like the oracle (Scala's
///   `.size` fold is a separate, later rewrite that never retroactively
///   un-wraps an already-built enclosing `Upcast`). Running this cast fold any
///   later — after [`crate::fold::fold`] has already turned that `SizeOf` into
///   `Const(0)` — would see an apparently-direct constant and WRONGLY fold the
///   `Upcast`, regressing that pin.
fn fold_direct_const_casts(e: Expr) -> Result<Expr, EmitError> {
    match e {
        Expr::Op(IrNode {
            opcode: opcode @ (0x7D | 0x7E),
            payload: Payload::NumericCast { input, tpe },
        }) => {
            if let Expr::Const { tpe: src_tpe, val } = input.as_ref() {
                if let Some(folded) = fold_numeric_cast(opcode, src_tpe, val, &tpe)? {
                    return Ok(folded);
                }
            }
            // Not a direct constant: give the child its OWN independent
            // fold decision, then rebuild THIS node around the (possibly
            // rewritten) result — never re-examining whether that result
            // is now `Const` (the anti-cascade discipline the fn docs
            // describe).
            let input = fold_direct_const_casts(*input)?;
            Ok(Expr::Op(IrNode {
                opcode,
                payload: Payload::NumericCast {
                    input: Box::new(input),
                    tpe,
                },
            }))
        }
        Expr::Op(IrNode { opcode, payload }) => Ok(Expr::Op(IrNode {
            opcode,
            payload: fold_direct_const_casts_children(payload)?,
        })),
        other => Ok(other),
    }
}

/// By-value, fallible child map for [`fold_direct_const_casts`] — the
/// exhaustive twin of [`push_children`]/[`crate::fold`]'s private
/// `fold_children` (a new child-carrying `Payload` variant fails to compile
/// here until it is mapped). Kept separate from `crate::lower`'s own
/// (infallible) child map: this pass runs at a different, earlier pipeline
/// position (see the fn docs) and must reject on downcast overflow, so it
/// cannot share that traversal.
fn fold_direct_const_casts_children(payload: Payload) -> Result<Payload, EmitError> {
    let f = |b: Box<Expr>| -> Result<Box<Expr>, EmitError> {
        Ok(Box::new(fold_direct_const_casts(*b)?))
    };
    let fv = |items: Vec<Expr>| -> Result<Vec<Expr>, EmitError> {
        items.into_iter().map(fold_direct_const_casts).collect()
    };
    Ok(match payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => payload,
        Payload::One(a) => Payload::One(f(a)?),
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: f(input)?,
            tpe,
        },
        Payload::Two(a, b) => Payload::Two(f(a)?, f(b)?),
        Payload::Three(a, b, c) => Payload::Three(f(a)?, f(b)?, f(c)?),
        Payload::Four(a, b, c, d) => Payload::Four(f(a)?, f(b)?, f(c)?, f(d)?),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id,
            tpe,
            rhs: f(rhs)?,
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
            rhs: f(rhs)?,
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: fv(items)?,
            result: f(result)?,
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args,
            body: f(body)?,
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
            obj: f(obj)?,
            args: fv(args)?,
            type_args,
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type,
            items: fv(items)?,
        },
        Payload::Tuple { items } => Payload::Tuple { items: fv(items)? },
        Payload::SigmaCollection { items } => Payload::SigmaCollection { items: fv(items)? },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: f(input)?,
            field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: f(input)?,
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
            default: default.map(f).transpose()?,
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: f(input)?,
            index: f(index)?,
            default: default.map(f).transpose()?,
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: f(func)?,
            args: fv(args)?,
        },
    })
}

/// Fold a DIRECT-constant `Downcast` (`opcode == 0x7D`, range-checked, exact
/// Scala `toByteExact`/`toShortExact`/`toIntExact`/`BigInt.toXExact`
/// semantics) or `Upcast` (`opcode == 0x7E`, never overflows — widening
/// only) to a plain `Expr::Const`. `Ok(None)` when `(src_tpe, target)` is not
/// one of the five numeric types' (Byte/Short/Int/Long/BigInt) valid
/// cast pairs — defensive: emit only ever builds `NumericCast` nodes over
/// this ladder (`ergo-compiler/src/emit.rs` `emit_select`'s cast arm), so
/// every REAL invocation matches; an unrecognized pair just stays unfolded
/// rather than mis-handling an unexpected shape.
fn fold_numeric_cast(
    opcode: u8,
    src_tpe: &SigmaType,
    val: &SigmaValue,
    target: &SigmaType,
) -> Result<Option<Expr>, EmitError> {
    let overflow = |what: String| EmitError::GraphBuildingReject {
        class: "ArithmeticException",
        what,
    };
    match (src_tpe, val) {
        (SigmaType::SByte | SigmaType::SShort | SigmaType::SInt | SigmaType::SLong, _) => {
            let v: i64 = match val {
                SigmaValue::Byte(n) => i64::from(*n),
                SigmaValue::Short(n) => i64::from(*n),
                SigmaValue::Int(n) => i64::from(*n),
                SigmaValue::Long(n) => *n,
                _ => return Ok(None),
            };
            fold_i64_cast(opcode, v, target, overflow)
        }
        (SigmaType::SBigInt, SigmaValue::BigInt(n)) => {
            fold_bigint_cast(opcode, n, target, overflow)
        }
        _ => Ok(None),
    }
}

/// The Byte/Short/Int/Long half of [`fold_numeric_cast`] — `v` is exact for
/// every source width (i64 losslessly carries all four). Upcast targets
/// among these four are always in range by construction (the source is
/// strictly narrower — that is what made `opcode == 0x7E` in the first
/// place); Downcast is range-checked via [`in_fold_range`]/[`fold_width`],
/// the SAME width ladder [`crate::fold`]'s arithmetic fold uses.
fn fold_i64_cast(
    opcode: u8,
    v: i64,
    target: &SigmaType,
    overflow: impl Fn(String) -> EmitError,
) -> Result<Option<Expr>, EmitError> {
    let width = match fold_width(target) {
        Some(w) => w,
        // Long -> BigInt upcast: BigInt has no `FoldWidth` member (it is
        // unbounded), handled directly here rather than through the shared
        // width table.
        None if matches!(target, SigmaType::SBigInt) => {
            return Ok(Some(Expr::Const {
                tpe: SigmaType::SBigInt,
                val: SigmaValue::BigInt(num_bigint::BigInt::from(v)),
            }));
        }
        None => return Ok(None),
    };
    if opcode == 0x7D && !in_fold_range(width, v) {
        return Err(overflow(format!(
            "compile-time constant downcast out of {width:?} range: {v}"
        )));
    }
    Ok(Some(match width {
        FoldWidth::Byte => Expr::Const {
            tpe: SigmaType::SByte,
            // In range by the check above (Downcast) or by construction
            // (Upcast never targets a narrower width).
            val: SigmaValue::Byte(v as i8),
        },
        FoldWidth::Short => Expr::Const {
            tpe: SigmaType::SShort,
            val: SigmaValue::Short(v as i16),
        },
        FoldWidth::Int => Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(v as i32),
        },
        FoldWidth::Long => Expr::Const {
            tpe: SigmaType::SLong,
            val: SigmaValue::Long(v),
        },
    }))
}

/// The `SBigInt`-source half of [`fold_numeric_cast`] — only reachable as a
/// `Downcast` (BigInt is the top of this 5-type ladder, so an `Upcast` FROM
/// BigInt would only ever be a same-type identity, which `emit.rs`'s
/// same-type arm already unwraps to the bare input before a `NumericCast`
/// node is ever built — defensive `Ok(None)` if ever reached). Range-checked
/// via `num_bigint`'s own `TryFrom<&BigInt>` impls, mirroring
/// `ergo-sigma/src/evaluator/opcodes/cast.rs::eval_downcast`'s BigInt arm
/// exactly (same overflow semantics, compile-time instead of eval-time).
fn fold_bigint_cast(
    opcode: u8,
    n: &num_bigint::BigInt,
    target: &SigmaType,
    overflow: impl Fn(String) -> EmitError,
) -> Result<Option<Expr>, EmitError> {
    if opcode != 0x7D {
        return Ok(None);
    }
    Ok(Some(match target {
        SigmaType::SByte => Expr::Const {
            tpe: SigmaType::SByte,
            val: SigmaValue::Byte(i8::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Byte range: {n}"
                ))
            })?),
        },
        SigmaType::SShort => Expr::Const {
            tpe: SigmaType::SShort,
            val: SigmaValue::Short(i16::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Short range: {n}"
                ))
            })?),
        },
        SigmaType::SInt => Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(i32::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Int range: {n}"
                ))
            })?),
        },
        SigmaType::SLong => Expr::Const {
            tpe: SigmaType::SLong,
            val: SigmaValue::Long(i64::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Long range: {n}"
                ))
            })?),
        },
        _ => return Ok(None),
    }))
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
/// (`Pay2SHAddress.apply(prop)`, `ErgoAddress.scala:210-218`). Scala hashes
/// `toProposition(replaceConstants = isConstantSegregation)`
/// (`ErgoAddress.scala:201-204`) — i.e. it re-INLINES placeholders before
/// hashing. We hash the PRE-segregation `root` (still fully inline) directly,
/// which is byte-equal to that re-inlined proposition and cheaper. This is why
/// P2SH is SEGREGATION-invariant (the D-C1 flip never moves it; D-C7 covers the
/// residual IR-shape divergences that DO move it).
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
///   contexts: coercion-cancellation CLOSED (M4 Task 6, lib.rs D-C3) —
///   [`crate::isproven`] cancels the `BoolToSigmaProp`/`SigmaPropIsProven`
///   round trips before the fold and after the lowering block. The
///   surviving-sigma `HasSigmas` `SigmaAnd`/`SigmaOr` reconstruction (a
///   residual `0xCF` in five corpus outputs) stays open, co-blocked on
///   val-inline/CSE (Tasks 8/9).
/// - Task-11 wave 1 added the GraphBuilding reject-gate family (lib.rs
///   D-C5): bit ops, zero-arg/non-1-arg lambda applications, SFunc-typed
///   lambda params, postfix `size`, out-of-range `getReg` literals,
///   pre-v3 SNumericType methods, and the constant-fold overflow check
///   ([`graph_building_lambda_reject`] below + [`crate::fold`]'s
///   arithmetic-overflow reject arm + the emit-arm gates).
///
/// # Examples
///
/// ```
/// use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
///
/// let r = compile(&ScriptEnv::new(), "sigmaProp(HEIGHT > 100)", 0, NetworkPrefix::Mainnet)
///     .unwrap();
/// // A non-bare root segregates: header byte 0x10 (constant-segregation bit).
/// assert_eq!(r.tree_bytes[0], 0x10);
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
    // shapes Scala's full compiler rejects — lambda/application rules first.
    if let Some(e) = graph_building_lambda_reject(&root) {
        return Err(CompileError::Emit(e));
    }

    // Explicit-cast folds, BOTH directions (M4 Task 4, lib.rs D-C7 cast
    // bullet; recon-transforms.md §7): fold `Downcast`/`Upcast` of a DIRECT
    // constant (range-checked — the reject side of the retired D-C5 checker
    // cast arm now lives in this pass, one code path) while leaving a
    // cast-of-cast CHAIN's outer casts unfolded, exactly like Scala. MUST run
    // BEFORE `crate::fold::fold` below: a direct-constant `Upcast` (e.g. the
    // typer's mixed-width widening in `9223372036854775807L + 1`) needs to
    // already BE a plain `Const` by the time the arithmetic fold looks at it,
    // or that pass's `Expr::Const` fast path never sees a value to propagate
    // into the parent `+`/`-`/`*`/`min`/`max` (the overflow would silently go
    // undetected). It also runs before the generic fold's `SizeOf`-literal
    // rule — see `fold_direct_const_casts`'s docs for the oracle-pinned
    // `.size.toLong` regression that position protects.
    let root = fold_direct_const_casts(root).map_err(CompileError::Emit)?;

    // isProven→isValid fusion (M4 Task 6, D-C3; recon-transforms.md §3;
    // `crate::isproven`): `SigmaPropIsProven(BoolToSigmaProp(x)) → x` and its
    // dual `BoolToSigmaProp(SigmaPropIsProven(p)) → p`. This first placement is
    // the fixpoint fusion (`GraphBuilding.scala:188-189`) — it must run BEFORE
    // the generic fold so a fusion-exposed Boolean feeds the fold (e.g.
    // `sigmaProp(true) ^ (1 == 1)` → `BinXor(true, true)` → `false`). The
    // second placement is AFTER the lowering block (the top-level
    // `removeIsProven`, over the coercion adjacency the unwrap/D-C2 fold
    // expose) — see below.
    let root = crate::isproven::eliminate_isproven(root);

    // Generic constant fold (M4 Task 5, recon-transforms.md §1b/§2a-2d;
    // `crate::fold`) — the GraphBuilding-exact `rewriteDef` cascade as one
    // bottom-up fixpoint pass. It ABSORBS the two retired D-C5/D-C6 twins into
    // one traversal (F5 discipline): the overflow CHECK is now the fold's
    // reject arm (a both-`Const` `+`/`-`/`*` that overflows its width is
    // Scala's `ArithmeticException` → compile reject, now byte-correct because
    // the node is actually replaced), and the `SizeOf(<coll literal>)` element-
    // count fold is one rule among many. Runs AFTER `fold_direct_const_casts`
    // (casts fold their immediate-`Const` children BEFORE arith sees them, and
    // this pass never re-folds a cast — mirroring Scala's build-time cast
    // interception vs the `rewriteDef` fixpoint) and BEFORE the v0 data gate
    // below — so a fold that erases v3-only constant DATA (a
    // `Coll[UnsignedBigInt]().size` collapsing to `Int`, or the NF-1
    // `unsignedBigInt == unsignedBigInt` closure) never puts that data on the
    // wire (locked decision 1).
    let root = crate::fold::fold(root).map_err(CompileError::Emit)?;

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

    // Lowering block (M4 Task 3, locked decision 1): AFTER every gate/fold
    // above, BEFORE constant segregation. D-C2 (`CreateProveDlog(Const)` /
    // `CreateProveDHTuple(Const×4)` → bare `SigmaPropConstant`) + the
    // single-element `anyOf`/`allOf`/`allZK`/`anyZK` unwrap
    // (recon-transforms.md §4/§5; `crate::lower`). Must run before the P2SH
    // proposition bytes below are computed, so the folded/unwrapped shape is
    // what both the proposition hash and `build_tree`'s bare-root check see.
    let root = crate::lower::lower(root);

    // Top-level `removeIsProven` (M4 Task 6, D-C3; recon-transforms.md §3;
    // `GraphBuilding.scala:245-252`, applied at `:418` AFTER buildGraph). The
    // lowering block above (D-C2 `proveDlog(const)` fold + single-element
    // `AllOf`/`AnyOf` unwrap) is what makes the `BoolToSigmaProp`/
    // `SigmaPropIsProven` adjacency appear: `allOf(Coll(proveDlog(g1)))` lowers
    // to `BoolToSigmaProp(SigmaPropIsProven(Const{SigmaProp}))`, which this
    // strips to the bare `SigmaPropConstant` root (header `0x00`, matching PK).
    // The `false`-XOR / `BinAnd` forms were already fused+folded pre-fold above,
    // so this second pass is a no-op for them.
    let root = crate::isproven::eliminate_isproven(root);

    // Multi-arg lambda TUPLING (M4 Task 7, D-C4; recon-transforms.md §6;
    // `crate::tuple`): a fold-slot lambda `{(a, b) => ...}` emits as a 2-arg
    // `FuncValue`, which is wire-legal but unevaluable — the reference JIT
    // hard-errors on any non-1-arg function (`values.scala:1042-1056`). Scala's
    // IR pipeline lowers it to the tupled 1-arg form
    // `FuncValue([(id, STuple(t_a, t_b))], body[a := SelectField(ValUse(id),1),
    // b := SelectField(ValUse(id),2)])` (`GraphBuilding.scala:917-924` +
    // `TreeBuilding.scala:185-190/454-457`) — the only shape real `Fold` trees
    // carry on-chain. Runs AFTER `graph_building_lambda_reject` above (which has
    // already rejected the non-1-arg *applications* Scala refuses; every
    // multi-arg *definition* surviving to here is the D-C4 both-accept class —
    // fold-slot and un-applied lambdas both compilers accept) and is a no-op for
    // every 1-arg lambda. The tuple param reuses the first arg's id, matching
    // Scala's `varId = defId + 1` for the non-CSE case (byte-verified against the
    // oracle).
    let root = crate::tuple::tuple_lambdas(root);

    // P2SH proposition bytes — Scala's `Pay2SHAddress.apply(script: ErgoTree)`
    // hashes `toProposition(replaceConstants = isConstantSegregation)`
    // (`ErgoAddress.scala:201-204`), i.e. the constant-INLINED proposition. The
    // pre-segregation `root` already IS that inlined body (every constant is
    // still inline here, no placeholders yet), so hashing it is byte-equal to
    // Scala's re-inlining step AND cheaper than segregating then substituting
    // back. For a bare-constant root this is the body itself — equivalent. This
    // is why the D-C1 segregation flip leaves the P2SH address INVARIANT
    // (recon-segregation.md §4; lib.rs D-C1/D-C7).
    let mut pw = VlqWriter::new();
    write_expr(&mut pw, &root, false)?;
    let proposition_bytes = pw.result();

    let ergo_tree = build_tree(root)?;

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

    /// The [`fold_direct_const_casts`] output BEFORE `build_tree`/
    /// segregation — needed to inspect a cast-fold's shape directly, since
    /// `CompileResult::ergo_tree.body` replaces every folded constant with
    /// a `ConstPlaceholder` once segregation runs.
    fn folded_root(source: &str) -> Expr {
        let typed = typecheck_with_network(&ScriptEnv::new(), source, 0, NetworkPrefix::Testnet)
            .expect("typecheck");
        let root = emit(&typed).expect("emit");
        fold_direct_const_casts(root).expect("fold_direct_const_casts")
    }

    /// Depth-first search for the first `FuncValue` payload in `expr`
    /// (test-only tree introspection — reuses [`push_children`]).
    fn find_func_value(expr: &Expr) -> Option<&Payload> {
        let mut stack = vec![expr];
        while let Some(e) = stack.pop() {
            if let Expr::Op(IrNode { payload, .. }) = e {
                if matches!(payload, Payload::FuncValue { .. }) {
                    return Some(payload);
                }
                push_children(payload, &mut stack);
            }
        }
        None
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
    fn compile_sigmaprop_height_segregated_matches_oracle_bytes() {
        // The D-C1 flip (M4 Task 2): a non-bare root segregates. Scala's
        // `withSegregation` header 0x10, constants table `01 04c801` (one SInt
        // constant, value 100), body `d191a37300` = BoolToSigmaProp(GT(HEIGHT,
        // ConstPlaceholder(0))). Oracle capture (sigma-state 6.0.2, testnet):
        // `cc sigmaProp(HEIGHT > 100)` → `100104c801d191a37300`.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x10, "constant-segregation header");
        assert!(r.ergo_tree.constant_segregation);
        assert_eq!(
            r.ergo_tree.constants,
            vec![(SigmaType::SInt, SigmaValue::Int(100))],
            "one segregated constant, first-write slot"
        );
        assert_eq!(hex::encode(&r.tree_bytes), "100104c801d191a37300");
    }

    #[test]
    fn compile_bool_pair_compaction_survives_segregation_zero_constants() {
        // The Relation2 `0x85` bool-pair compaction is bypassed by the
        // constant sink (it never reaches the Expr::Const arm), so a script
        // whose only literal constants are a compacted bool pair segregates to
        // a header-0x10 tree with a ZERO-entry constants table. Oracle:
        // `cc c1 && c2` (env booleans → literals → compacted) → `1000d1ed8501`.
        let mut env = ScriptEnv::new();
        env.insert("c1", EnvValue::Bool(true));
        env.insert("c2", EnvValue::Bool(false));
        let r = compile_testnet(&env, "c1 && c2").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x10, "segregated header");
        assert!(
            r.ergo_tree.constants.is_empty(),
            "the compacted bool pair must NOT segregate"
        );
        assert_eq!(hex::encode(&r.tree_bytes), "1000d1ed8501");
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

    #[test]
    fn compile_v0_data_gate_runs_before_segregation() {
        // D-C6 pipeline-order invariant (locked decision 1): the
        // v0-unserializable-data gate runs on the PRE-segregation root (every
        // constant still inline), so the D-C1 flip does not change what it
        // catches — a UnsignedBigInt-data source (a NON-bare root that WOULD
        // otherwise segregate its UBI constant into the table) still rejects
        // identically, BEFORE `build_tree`/`segregate` ever runs. This pins
        // that the gate never needs to walk the post-segregation constants
        // table instead.
        let err = compile(
            &ScriptEnv::new(),
            r#"unsignedBigInt("5") == unsignedBigInt("3")"#,
            3,
            NetworkPrefix::Testnet,
        )
        .expect_err("UBI data must reject at the pre-segregation v0 gate");
        assert!(matches!(&err, CompileError::Serializer { .. }), "{err:?}");
        assert_eq!(err.class(), "SerializerException");
    }

    // ----- error paths: GraphBuilding parity gates (lib.rs D-C5, wave 1) -----
    // Every oracle fact below: captured 2026-07-07, 3 identical runs,
    // committed as compile_seed.json vectors (except the ACCEPT boundaries
    // that byte-mismatch pending val-inline/pruning — the unused/aliased
    // multi-arg-definition boundaries — which are pinned here verdict-only;
    // the D-C4 fold-slot class is now tupled+committed, see the smoke vector).

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
        // val-bound = the D-C4 both-accept class; our trees for these now
        // TUPLE to the evaluable 1-arg form, ledger D-C4 CLOSED / D-C5).
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
    fn compile_fold_slot_multi_arg_lambda_tuples_to_one_arg_funcvalue() {
        // D-C4 (M4 Task 7): the fold's 2-arg lambda must reach `build_tree` as
        // a TUPLED 1-arg `FuncValue(STuple)` — the only on-chain-valid shape.
        // (The context-free smoke also byte-matches the oracle in
        // compile_semantic_parity via compile_seed.json; this pins the shape
        // through the full pipeline.)
        let r = ct("sigmaProp(Coll(1, 2).fold(0, {(a: Int, b: Int) => a + b}) == 3)")
            .expect("fold with a 2-arg lambda compiles");
        let fv = find_func_value(&r.ergo_tree.body).expect("a FuncValue in the fold op slot");
        let Payload::FuncValue { args, .. } = fv else {
            unreachable!()
        };
        assert_eq!(args.len(), 1, "multi-arg lambda tupled to a single arg");
        assert!(
            matches!(&args[0].1, Some(SigmaType::STuple(ts)) if ts.len() == 2),
            "the single arg is a 2-tuple, got {:?}",
            args[0].1
        );
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
    fn compile_allzk_anyzk_reject_staging_exception_full_pipeline() {
        // D-C8 (M4 Task 8 review): `allZK`/`anyZK` typecheck fine (the
        // typer's `predefined_env` has both names) but Scala's
        // `SigmaPredef.AllZKFunc`/`AnyZKFunc` register `PredefFuncInfo(
        // undefined)` as their irBuilder — genuinely unimplemented upstream
        // (sigmastate-interpreter#543), not a porting gap. The typed tree
        // keeps the raw `Apply(Ident, args)` shape (byte-identical to the
        // oracle's `tce` residual), and `compiler.compile`'s GraphBuilding
        // stage throws `StagingException` reaching that unbound `Ident` —
        // live-probed 2026-07-07, ×3 identical runs: literal single-element,
        // literal multi-element, AND a val-bound `Coll` ALL reject
        // identically for both names. There is NO accepting form — the
        // "literal Coll unwraps to SigmaAnd/SigmaOr" shape this port used to
        // assume never fires for the direct function-call route (that
        // unwrap only applies to typed `SigmaAnd`/`SigmaOr` nodes built by
        // the `&&`/`||` OPERATORS, a disjoint code path).
        for src in [
            "allZK(Coll(proveDlog(g1)))",
            "anyZK(Coll(proveDlog(g1)))",
            "{ val c = Coll(proveDlog(g1)); allZK(c) }",
        ] {
            let err = compile_testnet(&generator_env(), src).expect_err(src);
            assert_eq!(err.class(), "StagingException", "{src}");
        }
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
            "sigmaProp((-(2147483647) - 2) < 0)", // parser folds -(<lit>) → the `-` fold fires
            "{ val unused = 2147483647 + 1; sigmaProp(true) }",
            "sigmaProp(Coll(1).map({(t: Int) => 2147483647 + 1})(0) < 0)",
            // folded arith chains INTO a parent fold (review follow-up probe)
            "sigmaProp(((2147483646 + 1) + 1) < 0)",
            // min/max propagate their folded constant into the parent check
            "sigmaProp((min(2147483647, 1) + 2147483647) < 0)",
            "sigmaProp((max(2147483647, 1) + 2147483647) < 0)",
            // mixed-width min: the typer's Upcast(1, SLong) folds first
            "sigmaProp((min(1, 9223372036854775807L) + 9223372036854775807L) < 0L)",
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
            // min/max fold-through NON-overflow controls (oracle OK)
            "sigmaProp((min(1, 2) + 1) == 2)",
            "sigmaProp((max(1, 2) + 1) == 3)",
            // a non-constant min operand breaks the chain — no fold, no reject
            "sigmaProp((min(HEIGHT, 1) + 2147483647) > 0)",
            // Negation over a NON-literal folded constant stays unfolded on
            // both sides (probe-confirmed: oracle tree keeps the 0xF0 node)
            "sigmaProp((-(0 + 2147483647) - 2) < 0)",
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

    /// A second bare-const pin beyond the PK class — and the oracle
    /// authority for the SigmaTyperTest env's `g2 = 2·G` value (final
    /// whole-M3 review finding 1). The oracle constant-folds
    /// `proveDlog(g2)` into a bare `SigmaPropConstant` carrying the
    /// NORMALIZED compressed point, so its tree hex is a byte-level pin
    /// of the 2·G bytes the twin envs must bind.
    ///
    /// Oracle: `ccs proveDlog(g2)` →
    /// `OK 0008cd02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    ///  5AgXz2LADsxyCxEWvvHHpM9vKJsKbCwMjhXmVVrjH1dFtMgEupoAtSQd
    ///  rnwHaWHeaqaP7sCPFCF8VdN2Mxe72y4oLt8XKAt`
    /// (sigma-state 6.0.2, ORACLE_NETWORK=testnet, captured 2026-07-07).
    /// **M4 Task 3 flip:** the D-C2 fold now runs (`crate::lower`), so our
    /// `CreateProveDlog(Const)` collapses into the SAME bare
    /// `SigmaPropConstant` the oracle emits — full tree bytes AND both
    /// addresses now match, not just the 33-byte point inside the constant.
    #[test]
    fn compile_provedlog_two_g_point_bytes_match_oracle_fold() {
        let mut env = ScriptEnv::new();
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        env.insert(
            "g2",
            EnvValue::GroupElement(GroupElement::from_bytes(bytes)),
        );
        let r = compile_testnet(&env, "proveDlog(g2)").expect("compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "0008cd02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
        assert_eq!(
            r.p2s_address,
            "5AgXz2LADsxyCxEWvvHHpM9vKJsKbCwMjhXmVVrjH1dFtMgEupoAtSQd"
        );
        assert_eq!(r.p2sh_address, "rnwHaWHeaqaP7sCPFCF8VdN2Mxe72y4oLt8XKAt");
    }

    #[test]
    fn compile_sigmaprop_height_p2s_and_p2sh_match_oracle_after_segregation() {
        // Post-D-C1 (M4 Task 2): the oracle tree `100104c801d191a37300`
        // (header 0x10) and ours are now byte-identical, so the P2S address
        // MATCHES the oracle capture — the segregation-only gap is closed for
        // this shape-identical vector.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_eq!(r.p2s_address, ORACLE_HGT_P2S);
        // The P2SH address hashes the constant-INLINED proposition
        // (`d191a304c801`) — segregation-invariant, so it matched before AND
        // after the flip. Wherever Scala's IR reshapes the proposition itself,
        // the P2SH diverges (lib.rs D-C7; wave-3 address gate).
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
        // Segregated header 0x10, zero-entry table (no literal constant in
        // this register-accessor body) — byte-identical to the oracle capture.
        assert_eq!(hex::encode(&get_reg.tree_bytes), "1000d1e6c6a70504");
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
        assert_eq!(hex::encode(&dynamic.tree_bytes), "1000d1e6dc6313a701a304");
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
        // Self-pin (NOT an oracle vector): our tree keeps the ValUse/MethodCall
        // where Scala eliminates the val, so our SEGREGATED bytes (header 0x10,
        // one SInt(4) constant slot, ValDef rhs → ConstPlaceholder(0)) differ
        // from the oracle's `1000d1e6c6a70404`. A regression guard on our own
        // deterministic output, not a parity claim.
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "10010408d801d6017300d1e6dc6313a701720104"
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
        // Segregated, byte-identical to the oracle capture above.
        assert_eq!(
            hex::encode(&annotated.tree_bytes),
            "10040e020102040004020402d193b1b47300730173027303"
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
        assert_eq!(
            hex::encode(&bytes.tree_bytes),
            "10020e040000000a0408d193b173007301"
        );
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
        assert_eq!(
            hex::encode(&bits.tree_bytes),
            "10020d20000000500440d193b173007301"
        );
        assert_eq!(bits.p2sh_address, "qse65TyiDnutjxRzCP1mnCttRKWZqPrhnsvG7cg");
    }

    #[test]
    fn compile_bitwise_or_xor_fold_values_pinned() {
        // Value-distinguishing forms of the bitwise folds: the whole equality
        // folds to `sigmaProp(true)` ONLY if the folded byte VALUE is right
        // (`5 | 3 = 7`, `5 ^ 3 = 6`) — a wrong value would leave a residual
        // `Eq(<byte>, <byte>)` (or fold to `false`), so this pins the value.
        //
        // **M4 Task 5:** with the cast fold (Task 4: `5.toByte`, `3.toByte`,
        // `7.toByte`/`6.toByte` all fold to bare Byte constants) AND the
        // pre-existing bitwiseOr/Xor-of-constants fold feeding two equal Byte
        // constants into the `Eq`, the generic engine's `Const == Const →
        // true` closes it: byte-identical to the oracle (`10010101d17300`).
        // recon-targets vectors 84/85 graduate out of `DC7_P2SH_MISMATCH_SET`.
        let env = ScriptEnv::new();
        let cv3 = |src| compile(&env, src, 3, NetworkPrefix::Testnet);
        let or = cv3("sigmaProp((5.toByte.bitwiseOr(3.toByte)) == 7.toByte)").expect("compile");
        assert_eq!(hex::encode(&or.tree_bytes), "10010101d17300");
        let xor = cv3("sigmaProp((5.toByte.bitwiseXor(3.toByte)) == 6.toByte)").expect("compile");
        assert_eq!(hex::encode(&xor.tree_bytes), "10010101d17300");
    }

    #[test]
    fn compile_cast_chain_keeps_only_innermost_fold_matching_oracle_probe_34() {
        // The crux regression this task's fold-one-level/keep-chain
        // invariant exists to pin (M3 numerics N-3 probe 34,
        // adversarial-findings-numerics.md:137; now committed as an M4
        // Task 4 `cc` vector in `compile_probes.txt`/`compile_seed.json`,
        // re-verified via `compile_seed_live_recapture`): a literal cast
        // CHAIN folds ONLY the cast immediately adjacent to the literal —
        // `1.toByte` folds to a bare `Const(Byte, 1)`, but the two outer
        // `.toLong`/`.toBigInt` casts stay real `Upcast` nodes wrapping it,
        // exactly like Scala's `GraphBuilding.scala:514-518` (a
        // non-recursive structural match against the untouched AST child).
        // Byte-exact vs. the oracle capture — NOT a self-oracle: this is
        // the live-recaptured, committed `p2sh_address`
        // (`rnuja5Bnkuz4BzMETLRwybfPAo6VBt4eC4dP3CL`) too.
        let r = ct("sigmaProp(1.toByte.toLong.toBigInt > 0.toBigInt)").expect("compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "10020201060100d1917e7e730005067301"
        );
        assert_eq!(r.p2sh_address, "rnuja5Bnkuz4BzMETLRwybfPAo6VBt4eC4dP3CL");
        // Structural pin, same invariant from the AST side: exactly TWO
        // real `Upcast` (0x7E) nodes remain over a folded `Const(Byte, 1)`
        // — a cascade-fold bug would collapse both into a single
        // `Const(BigInt, 1)` and this match would fail to find any cast
        // node at all. Inspected on the PRE-segregation tree (`emit` +
        // `fold_direct_const_casts` directly): `r.ergo_tree.body` has
        // already been segregated into a `ConstPlaceholder`, which would
        // hide the very shape this test pins.
        let folded = folded_root("sigmaProp(1.toByte.toLong.toBigInt > 0.toBigInt)");
        let Expr::Op(IrNode {
            opcode: 0xD1,
            payload: Payload::One(gt),
        }) = &folded
        else {
            panic!("root must be BoolToSigmaProp: {folded:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x91,
            payload: Payload::Two(lhs, _rhs),
        }) = gt.as_ref()
        else {
            panic!("expected GT: {gt:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x7E,
            payload: Payload::NumericCast { input: inner1, .. },
        }) = lhs.as_ref()
        else {
            panic!("expected outer Upcast (toBigInt): {lhs:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x7E,
            payload: Payload::NumericCast { input: inner2, .. },
        }) = inner1.as_ref()
        else {
            panic!("expected middle Upcast (toLong): {inner1:?}");
        };
        assert!(
            matches!(
                inner2.as_ref(),
                Expr::Const {
                    tpe: SigmaType::SByte,
                    val: SigmaValue::Byte(1),
                }
            ),
            "innermost cast must have folded to a bare Const(Byte, 1): {inner2:?}"
        );
    }

    #[test]
    fn compile_cast_chain_depth_three_nested_under_gt_keeps_all_outer_casts() {
        // Generalizes the probe-34 invariant one nesting level deeper
        // (`1.toByte.toShort.toLong.toBigInt`, 4 casts total): the
        // anti-cascade rule Scala's structural match implements
        // (GraphBuilding.scala:514-518, depth-independent by construction —
        // it only ever inspects ONE node's immediate, untouched child) must
        // leave THREE real `Upcast` nodes over the folded innermost
        // constant, not just the two probe-34 pins. This is a
        // self-consistency shape check on OUR OWN non-cascading discipline
        // (not an independent oracle round-trip — the underlying rule is
        // already oracle-verified at depth 2 above; this extends it
        // structurally to depth 3, which the fold's node-local recursion
        // makes mechanically identical).
        let r = ct("sigmaProp(1.toByte.toShort.toLong.toBigInt > 0.toBigInt)").expect("compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "10020201060100d1917e7e7e73000305067301"
        );
        fn cast_depth_over_byte_const(e: &Expr) -> usize {
            match e {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { input, .. },
                }) => 1 + cast_depth_over_byte_const(input),
                Expr::Const {
                    tpe: SigmaType::SByte,
                    val: SigmaValue::Byte(1),
                } => 0,
                other => panic!("expected an Upcast chain over Const(Byte, 1): {other:?}"),
            }
        }
        // Inspected on the PRE-segregation tree — see `folded_root`'s docs.
        let folded = folded_root("sigmaProp(1.toByte.toShort.toLong.toBigInt > 0.toBigInt)");
        let Expr::Op(IrNode {
            opcode: 0xD1,
            payload: Payload::One(gt),
        }) = &folded
        else {
            panic!("root must be BoolToSigmaProp: {folded:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x91,
            payload: Payload::Two(lhs, _rhs),
        }) = gt.as_ref()
        else {
            panic!("expected GT: {gt:?}");
        };
        assert_eq!(
            cast_depth_over_byte_const(lhs),
            3,
            "depth-3 chain must keep exactly 3 real Upcast nodes, not cascade-fold"
        );
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
        // M4 Task 5: the generic const fold now folds `.size` → Int 0 AND the
        // enclosing `0 == 0` → `sigmaProp(true)`, byte-identical to the oracle
        // (`10010101d17300`) — recon-targets vector 77 graduates (NF-1 closure:
        // the SizeOf fold erases the empty `Coll[UnsignedBigInt]()` BEFORE the
        // v0-data gate, so the F-3 stranded-funds invariant holds too).
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
        let r = compile(
            &ScriptEnv::new(),
            "sigmaProp(Coll[UnsignedBigInt]().size.toLong == SELF.value)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        // Shape-identical to the oracle here (the `.size` fold matches Scala,
        // the surrounding expression is un-foldable on BOTH sides) — so our
        // segregated bytes are byte-identical to the oracle capture.
        assert_eq!(hex::encode(&r.tree_bytes), "10010400d1937e730005c1a7");
        assert_eq!(r.p2sh_address, "pvyEFnLjY1hb7ebaccofdS88Z9v1WwKxUzUB4y9");
        // The `.size` fold covers NON-constant elements too (a `Coll(HEIGHT)`
        // literal folds to Int 1 regardless of item constancy); M4 Task 5's
        // `Const == Const → true` then closes the equality, byte-identical to
        // the oracle (`10010101d17300`) — recon-targets vector 79 graduates.
        let r = ct("sigmaProp(Coll(HEIGHT).size == 1)").expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
        // Discarded elements are still verdict-checked: children fold BEFORE a
        // parent's SizeOf, so the overflow in the dropped item still rejects
        // (oracle rejects this too).
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
    fn compile_prove_dlog_generator_folds_to_bare_const_matching_pk_oracle() {
        // Oracle capture, line 3: `cce proveDlog(g1)` → the SAME reply as
        // the PK line (tree `0008cd0279be...`, both addresses identical):
        // Scala's IR pipeline constant-folds CreateProveDlog(const) →
        // SigmaPropConstant at the GraphBuilding stage (task-1-report.md
        // Concern 1; g1 = the generator = the PK test key).
        //
        // **M4 Task 3 flip:** `crate::lower`'s D-C2 fold now runs BEFORE
        // `build_tree`, so our `CreateProveDlog(Const)` folds to the SAME
        // bare `SigmaPropConstant` the oracle emits — the root is bare, so
        // it takes `withoutSegregation` (header `0x00`, empty constants
        // table) exactly like the PK vector, and every byte/address matches
        // the oracle verbatim (D-C2 CLOSED).
        let r = compile_testnet(&generator_env(), "proveDlog(g1)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00, "folded bare root, no segregation");
        assert!(r.ergo_tree.constants.is_empty());
        assert!(matches!(
            &r.ergo_tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_)),
            }
        ));
        assert_eq!(hex::encode(&r.tree_bytes), ORACLE_PK_TREE_HEX);
        assert_eq!(r.p2s_address, ORACLE_PK_P2S);
        assert_eq!(r.p2sh_address, ORACLE_PK_P2SH);
    }

    #[test]
    fn compile_isproven_bool_and_reconstructs_binand_matching_oracle() {
        // M4 Task 6 (D-C3): `sigmaProp(true) && (1 == 1)` — the SigmaProp
        // operand's `.isProven` fuses (`SigmaPropIsProven(BoolToSigmaProp(true))
        // → true`) BEFORE the fold, exposing `BinAnd(true, EQ(1,1))`. The fold
        // reduces `EQ(1,1) → true` but keeps `BinAnd` (lazy, never const-folded),
        // and the Boolean root re-wraps in `BoolToSigmaProp` — byte-identical to
        // the oracle `BoolToSigmaProp(BinAnd(true, true))` (`1000d1ed8503`; the
        // `85` bool-pair compaction extracts ZERO constants, header `0x10`/`00`).
        for src in ["sigmaProp(true) && (1 == 1)", "(1 == 1) && sigmaProp(true)"] {
            let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).expect(src);
            assert_eq!(hex::encode(&r.tree_bytes), "1000d1ed8503", "{src}");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "{src}");
        }
    }

    #[test]
    fn compile_isproven_bool_xor_folds_to_false_matching_oracle() {
        // M4 Task 6 (D-C3): `sigmaProp(true) ^ (1 == 1)` — same isProven fusion
        // exposes `BinXor(true, EQ(1,1))`; unlike BinAnd, BinXor IS eagerly
        // const-folded (`true ^ true → false`), so the whole XOR collapses to a
        // `false` constant. Segregation extracts it into the constants table
        // (`0100` = SBoolean/false) with a placeholder body — byte-identical to
        // the oracle `BoolToSigmaProp(placeholder0=false)` (`10010100d17300`).
        for src in ["sigmaProp(true) ^ (1 == 1)", "(1 == 1) ^ sigmaProp(true)"] {
            let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).expect(src);
            assert_eq!(hex::encode(&r.tree_bytes), "10010100d17300", "{src}");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "{src}");
        }
    }

    #[test]
    fn compile_allof_singleton_provedlog_strips_isproven_to_bare_const() {
        // M4 Task 6 (D-C3): `allOf(Coll(proveDlog(g1)))` — the lowering block
        // (D-C2 `CreateProveDlog(const)` fold + single-element `AllOf` unwrap)
        // exposes `BoolToSigmaProp(SigmaPropIsProven(Const{SigmaProp}))`, which
        // the post-lower top-level `removeIsProven` strips to the bare
        // `SigmaPropConstant` root. Bare root → `withoutSegregation` (header
        // `0x00`), byte-identical to the oracle `0008cd0279be…` — the SAME tree
        // as `proveDlog(g1)`/PK.
        let r = compile(
            &generator_env(),
            "allOf(Coll(proveDlog(g1)))",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00, "bare root, no segregation");
        assert!(matches!(
            &r.ergo_tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_)),
            }
        ));
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
    }

    #[test]
    fn compile_bare_singleton_lowering_matches_oracle_property_call() {
        // M4 Task 8 (recon-transforms.md §9, D-C7 singleton bullet, vector
        // 30): bare `LastBlockUtxoRootHash` and bare `groupGenerator` are NOT
        // `IsContextProperty` primitives on the Scala side — both re-emit as
        // `PropertyCall`s. Oracle-confirmed 2026-07-07, `ORACLE_TREE_VERSION=3`:
        for (src, oracle_hex) in [
            (
                "sigmaProp(LastBlockUtxoRootHash.digest.size > 0)",
                "10010400d191b1db6401db6509fe7300",
            ),
            (
                "sigmaProp(groupGenerator.getEncoded.size > 0)",
                "10010400d191b1db0702db6a01dd7300",
            ),
        ] {
            let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).expect(src);
            assert_eq!(hex::encode(&r.tree_bytes), oracle_hex, "{src}");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "{src}");
        }
    }

    #[test]
    fn compile_deserialize_constant_matches_oracle() {
        // M4 Task 8 (gap F6, D-T2 CLOSED): `deserialize[Int]("Jq")` decodes
        // (Base58) to bytes `04 0a` — `IntConstant(5)` — and folds through the
        // generic constant fold (`5 == 5` → `true`) exactly like the oracle.
        // Oracle-confirmed 2026-07-07: `sigmaProp(deserialize[Int]("Jq") == 5)`
        // → `10010101d17300`.
        let r = compile(
            &ScriptEnv::new(),
            "sigmaProp(deserialize[Int](\"Jq\") == 5)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
    }
}
