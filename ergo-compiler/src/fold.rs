//! Generic constant-folding engine over the emitted opcode IR
//! (`ergo_ser::opcode::Expr`), a GraphBuilding-exact port of Scala's
//! `rewriteDef` fold cascade.
//!
//! # What this ports (each rule pins its Scala `file:line`)
//!
//! Scala runs `rewriteDef` in the `toExp` fixpoint (`Base.scala:837-849`):
//! every graph node, once built (children already fixpoint-rewritten), is
//! rewritten to fixpoint before its parent uses it. We mirror that with a
//! **bottom-up traversal** (fold children first) followed by a **per-node
//! fixpoint loop** ([`fold`]) — a rewrite that produces a new top node (e.g.
//! `0 - x → -x`, `true ^ y → !y`) is re-examined until stable, but its
//! already-folded children are not re-walked.
//!
//! - **§2a algebraic identities** (`DefRewriting.scala:137-164`, `:63-67`,
//!   NOT gated on const-prop): `x+0→x`, `0+x→x`, `x-0→x`, `0-x→-x`,
//!   `_*0→0`, `0*_→0`, `x*1→x`, `1*x→x`, `-(-x)→x`.
//! - **§2b whole-expression propagation** (`DefRewriting.scala:98-203`, gated
//!   on `constantPropagation=true`, `Transforming.scala:51`): both-`Const`
//!   `+`/`-`/`*` fold with the ExactNumeric overflow guard (`propagateBinOp` →
//!   `applySeq` throws `ArithmeticException` on overflow → compile reject,
//!   absorbing the retired D-C5 `fold_overflow_check`); `min`/`max` fold (never
//!   overflow); `/`/`%` fold **only when the divisor is a non-zero constant**
//!   (`DivOp.shouldPropagate = rhs != n.zero`, `NumericOps.scala:73`,
//!   `compile_probes.txt`); ordering comparisons `<`/`<=`/`>`/`>=` fold both-`Const`;
//!   `!Const(b)→Const(!b)` (`:89`).
//! - **§2b Equals/NotEquals** (`DefRewriting.scala:100-129`): `x==y→true` /
//!   `x!=y→false` fire on Scala **graph-ref equality** (hash-consing), which we
//!   mirror with structural `Expr` equality **restricted to `Const` operands**
//!   (the non-`Const` `a==a` case is CSE substrate, handled by `crate::cse`);
//!   the boolean-`Const` arms (`x==true→x`, `x==false→!x`, and NotEquals'
//!   mirror) are ported. A **non-equal, non-boolean** `Const==Const` (e.g.
//!   `1==2`) does NOT fold — Scala's `Equals` case is terminal (never falls to
//!   `propagateBinOp`), oracle-pinned (`cc sigmaProp((1 == 2) || (HEIGHT >
//!   0))` keeps the `Eq` node).
//! - **§2a boolean XOR** (`LogicalOps.rewriteBoolConsts`, `LogicalOps.scala:
//!   46-73`, via `DefRewriting.scala:134`): `BinXor` with a boolean-`Const`
//!   operand — `true^y→!y`, `false^y→y` (and mirror). `&&`/`||` (`BinAnd`/
//!   `BinOr`) are **lazy** (`lazy_&&`/`lazy_||`, not `ApplyBinOp`) so they never
//!   reach `rewriteBinOp` and do NOT fold — oracle-pinned (`cc true && (1 ==
//!   1)` keeps `BinAnd(true, true)`, `1000d1ed8503`).
//! - **§2d collection-length fold** (`IRContext.scala:116-118`, the
//!   `fromItems(items).length → items.length` rule, absorbing the retired D-C6
//!   `fold_literal_coll_sizes`): `SizeOf(<ConcreteCollection literal>)` folds to
//!   the element count. This is the NF-1 closure — it eliminates a
//!   `Coll[UnsignedBigInt]()` (v3-only elem type) BEFORE the v0-data gate: this
//!   fold pass always runs before that gate. A `SizeOf` over a `Coll` CONSTANT
//!   is NOT folded (see [`coll_len`] for the oracle pin).
//! - **§4 all-`Const` `anyOf`/`allOf`** (`GraphBuilding.scala:214-219`, gated on
//!   const-prop): `Or`/`And` over a `ConcreteCollection` whose items are all
//!   `Const[Boolean]` fold to `exists`/`forall`. The single-element unwrap and
//!   sigma-split (`:205-208`) remain in `crate::lower`, which runs
//!   AFTER this pass.
//! - **De Morgan on `!`** (`DefRewriting.scala:73-85`, NOT gated on const-prop):
//!   `!(x<y)→x>=y`, `!(x<=y)→x>y`, `!(x>y)→x<=y`, `!(x>=y)→x<y`; `!(!x)→x`.
//!
//! # What this deliberately does NOT fold (kept-shape, oracle-pinned)
//!
//! - **`Negation` of a constant** (`DefRewriting.scala:63-67` — `NumericNegate`
//!   only matches `-(-x)`, never `propagateUnOp`): a `Negation` node over a
//!   graph-folded constant stays unfolded on BOTH sides (vector 83,
//!   `sigmaProp((-(0 + 2147483647) - 2) < 0)` — we fold the inner `0+2147483647`
//!   but keep the `Negation`).
//! - **`NumericCast` (`Upcast`/`Downcast`) nodes** — folded (structurally, over
//!   an immediate `Const`) by [`crate::tree::fold_direct_const_casts`], which
//!   runs BEFORE this pass with a non-cascade discipline this general fixpoint
//!   must not break. This engine recurses THROUGH a cast (folds its children)
//!   but never folds the cast itself and never treats it as `Const` for a
//!   parent fold — so `ccs (x*100).toByte > 0.toByte` folds `x*100→1000` yet
//!   keeps the `Downcast` AND the `Gt` (oracle-pinned).
//! - **`BigInt` arithmetic/comparison** — outside the `i64` width ladder; not
//!   compile-folded (oracle-confirmed, respecting the existing cast-fold boundary). A
//!   BigInt `Const` is opaque to [`as_num`], so no BigInt fold ever fires.
//! - **Division/modulo by a zero constant** — divisor-`0` skips the fold (Scala
//!   `shouldPropagate=false`), leaving `1/0`/`1%0` unfolded (oracle-pinned).

use crate::emit::EmitError;
use crate::tree::{in_fold_range, FoldWidth};
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

// Opcode bytes this pass matches (ergo-ser/src/opcode/types.rs).
const LT: u8 = 0x8F;
const LE: u8 = 0x90;
const GT: u8 = 0x91;
const GE: u8 = 0x92;
const EQ: u8 = 0x93;
const NEQ: u8 = 0x94;
const AND: u8 = 0x96; // allOf (logical, single ConcreteCollection arg)
const OR: u8 = 0x97; // anyOf
const MINUS: u8 = 0x99;
const PLUS: u8 = 0x9A;
const MULTIPLY: u8 = 0x9C;
const DIVISION: u8 = 0x9D;
const MODULO: u8 = 0x9E;
const MIN: u8 = 0xA1;
const MAX: u8 = 0xA2;
const SIZE_OF: u8 = 0xB1;
const CONCRETE_COLLECTION: u8 = 0x83;
const LOGICAL_NOT: u8 = 0xEF;
const NEGATION: u8 = 0xF0;
const BIN_XOR: u8 = 0xF4;

/// Run the generic constant fold over `expr` — bottom-up, each node then
/// fixpoint-rewritten (see the module docs for the mirror of Scala's `toExp`
/// fixpoint). Returns `Err` when a both-`Const` `+`/`-`/`*` fold overflows its
/// width (Scala `ArithmeticException` → compile reject; the absorbed D-C5
/// behavior, now byte-correct because the node is actually replaced).
pub(crate) fn fold(expr: Expr) -> Result<Expr, EmitError> {
    // 1. Fold children first (post-order).
    let expr = match expr {
        Expr::Op(IrNode { opcode, payload }) => Expr::Op(IrNode {
            opcode,
            payload: fold_children(payload)?,
        }),
        other => return Ok(other),
    };
    // 2. Fixpoint the node itself; a rewrite that produces a new top node is
    //    re-examined, but its (already-folded) children are not re-walked.
    let mut cur = expr;
    loop {
        match rewrite_node(cur)? {
            Rewrite::Changed(next) => cur = next,
            Rewrite::Same(same) => return Ok(same),
        }
    }
}

/// One fixpoint step: either the node was rewritten ([`Rewrite::Changed`], loop
/// again) or no rule fired ([`Rewrite::Same`], done). Both carry an owned
/// `Expr` so a rule can move an operand out as the whole result.
enum Rewrite {
    Changed(Expr),
    Same(Expr),
}

/// A numeric `Const`'s (width, value) — `None` for any non-`Const` or a
/// `Const` outside the `i64` width ladder (`Boolean`/`BigInt`/`GroupElement`/…
/// are opaque here). The `i64` carrier is exact for every ladder width
/// (`|Byte/Short/Int| <= 2^31`, `Long` native).
fn as_num(e: &Expr) -> Option<(FoldWidth, i64)> {
    match e {
        Expr::Const { val, .. } => match val {
            SigmaValue::Byte(v) => Some((FoldWidth::Byte, i64::from(*v))),
            SigmaValue::Short(v) => Some((FoldWidth::Short, i64::from(*v))),
            SigmaValue::Int(v) => Some((FoldWidth::Int, i64::from(*v))),
            SigmaValue::Long(v) => Some((FoldWidth::Long, *v)),
            _ => None,
        },
        _ => None,
    }
}

/// A boolean `Const`'s value, else `None`.
fn as_bool(e: &Expr) -> Option<bool> {
    match e {
        Expr::Const {
            val: SigmaValue::Boolean(b),
            ..
        } => Some(*b),
        _ => None,
    }
}

fn is_const(e: &Expr) -> bool {
    matches!(e, Expr::Const { .. })
}

/// A numeric `Const` equal to zero (matches Scala `isZero`, `NumericOps.scala:
/// 124`) — the `x+0`/`x*0`/… identity guard.
fn is_zero(e: &Expr) -> bool {
    matches!(as_num(e), Some((_, 0)))
}

/// A numeric `Const` equal to one (matches Scala `isOne`, `NumericOps.scala:
/// 127`) — the `x*1` identity guard.
fn is_one(e: &Expr) -> bool {
    matches!(as_num(e), Some((_, 1)))
}

/// Build a numeric `Const` of `width` carrying `v` (`v` is assumed in range —
/// every caller range-checks before constructing).
fn num_const(width: FoldWidth, v: i64) -> Expr {
    let (tpe, val) = match width {
        FoldWidth::Byte => (SigmaType::SByte, SigmaValue::Byte(v as i8)),
        FoldWidth::Short => (SigmaType::SShort, SigmaValue::Short(v as i16)),
        FoldWidth::Int => (SigmaType::SInt, SigmaValue::Int(v as i32)),
        FoldWidth::Long => (SigmaType::SLong, SigmaValue::Long(v)),
    };
    Expr::Const { tpe, val }
}

fn bool_const(b: bool) -> Expr {
    Expr::Const {
        tpe: SigmaType::SBoolean,
        val: SigmaValue::Boolean(b),
    }
}

fn not_node(inner: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode: LOGICAL_NOT,
        payload: Payload::One(Box::new(inner)),
    })
}

fn negation_node(inner: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode: NEGATION,
        payload: Payload::One(Box::new(inner)),
    })
}

fn overflow(what: String) -> EmitError {
    EmitError::GraphBuildingReject {
        class: "ArithmeticException",
        what,
    }
}

/// Apply the rewrite rules to a single node whose children are already folded.
/// See the module docs for the per-rule Scala pins.
fn rewrite_node(e: Expr) -> Result<Rewrite, EmitError> {
    let Expr::Op(IrNode { opcode, payload }) = e else {
        return Ok(Rewrite::Same(e));
    };
    // Binary (two-operand) arithmetic / comparison / xor.
    if let Payload::Two(l, r) = payload {
        return rewrite_binary(opcode, l, r);
    }
    // Unary logical-not / negation, and the single-arg any/all collection folds
    // and SizeOf all take a `One` payload.
    if let Payload::One(inner) = payload {
        return rewrite_unary(opcode, inner);
    }
    Ok(Rewrite::Same(Expr::Op(IrNode { opcode, payload })))
}

/// Rebuild a two-operand node unchanged (no rule fired).
fn keep2(opcode: u8, l: Box<Expr>, r: Box<Expr>) -> Rewrite {
    Rewrite::Same(Expr::Op(IrNode {
        opcode,
        payload: Payload::Two(l, r),
    }))
}

/// Rebuild a one-operand node unchanged.
fn keep1(opcode: u8, inner: Box<Expr>) -> Rewrite {
    Rewrite::Same(Expr::Op(IrNode {
        opcode,
        payload: Payload::One(inner),
    }))
}

fn rewrite_binary(opcode: u8, l: Box<Expr>, r: Box<Expr>) -> Result<Rewrite, EmitError> {
    match opcode {
        // Ordering comparisons: both-Const numeric → Const(bool). Widths agree
        // post-typer/post-cast-fold; a mismatch stays conservative (no fold).
        LT | LE | GT | GE => {
            if let (Some((wl, a)), Some((wr, b))) = (as_num(&l), as_num(&r)) {
                if wl == wr {
                    let res = match opcode {
                        LT => a < b,
                        LE => a <= b,
                        GT => a > b,
                        _ => a >= b,
                    };
                    return Ok(Rewrite::Changed(bool_const(res)));
                }
            }
            Ok(keep2(opcode, l, r))
        }
        // Equals: graph-ref equality (Const-restricted) → true; boolean-Const
        // arms; a non-equal non-boolean Const pair does NOT fold (terminal).
        EQ => {
            if is_const(&l) && is_const(&r) && l == r {
                return Ok(Rewrite::Changed(bool_const(true)));
            }
            if let Some(b) = as_bool(&r) {
                return Ok(Rewrite::Changed(if b { *l } else { not_node(*l) }));
            }
            if let Some(b) = as_bool(&l) {
                return Ok(Rewrite::Changed(if b { *r } else { not_node(*r) }));
            }
            Ok(keep2(opcode, l, r))
        }
        NEQ => {
            if is_const(&l) && is_const(&r) && l == r {
                return Ok(Rewrite::Changed(bool_const(false)));
            }
            if let Some(b) = as_bool(&r) {
                return Ok(Rewrite::Changed(if b { not_node(*l) } else { *l }));
            }
            if let Some(b) = as_bool(&l) {
                return Ok(Rewrite::Changed(if b { not_node(*r) } else { *r }));
            }
            Ok(keep2(opcode, l, r))
        }
        // x + 0 → x, 0 + x → x, else both-Const fold (overflow → reject).
        PLUS => {
            if is_zero(&r) {
                return Ok(Rewrite::Changed(*l));
            }
            if is_zero(&l) {
                return Ok(Rewrite::Changed(*r));
            }
            fold_checked_arith(opcode, l, r, i64::checked_add, "+")
        }
        // x - 0 → x, 0 - x → -x, else both-Const fold.
        MINUS => {
            if is_zero(&r) {
                return Ok(Rewrite::Changed(*l));
            }
            if is_zero(&l) {
                return Ok(Rewrite::Changed(negation_node(*r)));
            }
            fold_checked_arith(opcode, l, r, i64::checked_sub, "-")
        }
        // _ * 0 → 0, 0 * _ → 0, x * 1 → x, 1 * x → x, else both-Const fold.
        MULTIPLY => {
            if is_zero(&r) {
                return Ok(Rewrite::Changed(*r));
            }
            if is_zero(&l) {
                return Ok(Rewrite::Changed(*l));
            }
            if is_one(&r) {
                return Ok(Rewrite::Changed(*l));
            }
            if is_one(&l) {
                return Ok(Rewrite::Changed(*r));
            }
            fold_checked_arith(opcode, l, r, i64::checked_mul, "*")
        }
        // Divisor-nonzero constant division/modulo fold (Scala DivOp
        // shouldPropagate = rhs != 0). checked_* guards the Long MIN / -1
        // wrap corner (unpinned, no vector) — keep unfolded there.
        DIVISION => fold_div_like(opcode, l, r, i64::checked_div),
        MODULO => fold_div_like(opcode, l, r, i64::checked_rem),
        // min/max never overflow (select an operand); the propagated Const
        // feeds parent folds.
        MIN | MAX => {
            if let (Some((wl, a)), Some((wr, b))) = (as_num(&l), as_num(&r)) {
                if wl == wr {
                    let v = if opcode == MIN { a.min(b) } else { a.max(b) };
                    return Ok(Rewrite::Changed(num_const(wl, v)));
                }
            }
            Ok(keep2(opcode, l, r))
        }
        // Boolean XOR with a boolean-Const operand (rewriteBoolConsts): a
        // both-Const pair folds in two fixpoint steps via the produced `!`.
        BIN_XOR => {
            if let Some(b) = as_bool(&l) {
                return Ok(Rewrite::Changed(if b { not_node(*r) } else { *r }));
            }
            if let Some(b) = as_bool(&r) {
                return Ok(Rewrite::Changed(if b { not_node(*l) } else { *l }));
            }
            Ok(keep2(opcode, l, r))
        }
        _ => Ok(keep2(opcode, l, r)),
    }
}

/// Both-`Const` `+`/`-`/`*` fold with the ExactNumeric overflow guard: an
/// out-of-width result is Scala's `ArithmeticException` (compile reject), a
/// same-width in-range result folds. Operands of differing width stay
/// conservative (a hand-built tree; post-typer they always agree).
fn fold_checked_arith(
    opcode: u8,
    l: Box<Expr>,
    r: Box<Expr>,
    op: fn(i64, i64) -> Option<i64>,
    sym: &str,
) -> Result<Rewrite, EmitError> {
    if let (Some((wl, a)), Some((wr, b))) = (as_num(&l), as_num(&r)) {
        if wl == wr {
            return match op(a, b).filter(|v| in_fold_range(wl, *v)) {
                Some(v) => Ok(Rewrite::Changed(num_const(wl, v))),
                None => Err(overflow(format!(
                    "compile-time constant fold overflows {wl:?}: {a} {sym} {b}"
                ))),
            };
        }
    }
    Ok(keep2(opcode, l, r))
}

/// Division/modulo fold, gated on a non-zero constant divisor. `checked`
/// returns `None` for divisor-0 (already excluded) or the Long MIN / -1
/// overflow — both leave the node unfolded (the former matches
/// `shouldPropagate=false`; the latter is an unpinned corner, kept conservative
/// rather than mis-folded).
fn fold_div_like(
    opcode: u8,
    l: Box<Expr>,
    r: Box<Expr>,
    checked: fn(i64, i64) -> Option<i64>,
) -> Result<Rewrite, EmitError> {
    if let (Some((wl, a)), Some((wr, b))) = (as_num(&l), as_num(&r)) {
        if wl == wr && b != 0 {
            if let Some(v) = checked(a, b).filter(|v| in_fold_range(wl, *v)) {
                return Ok(Rewrite::Changed(num_const(wl, v)));
            }
        }
    }
    Ok(keep2(opcode, l, r))
}

fn rewrite_unary(opcode: u8, inner: Box<Expr>) -> Result<Rewrite, EmitError> {
    match opcode {
        // LogicalNot: De Morgan comparison flips, double-not, and !Const(b).
        LOGICAL_NOT => {
            if let Expr::Op(IrNode {
                opcode: cmp @ (LT | LE | GT | GE),
                payload: Payload::Two(a, b),
            }) = *inner
            {
                let flipped = match cmp {
                    LT => GE,
                    LE => GT,
                    GT => LE,
                    _ => LT,
                };
                return Ok(Rewrite::Changed(Expr::Op(IrNode {
                    opcode: flipped,
                    payload: Payload::Two(a, b),
                })));
            }
            match *inner {
                // !(!x) → x
                Expr::Op(IrNode {
                    opcode: LOGICAL_NOT,
                    payload: Payload::One(x),
                }) => Ok(Rewrite::Changed(*x)),
                // !Const(b) → Const(!b)
                Expr::Const {
                    val: SigmaValue::Boolean(b),
                    ..
                } => Ok(Rewrite::Changed(bool_const(!b))),
                other => Ok(keep1(opcode, Box::new(other))),
            }
        }
        // Negation: only -(-x) → x; a Negation of a Const is NOT folded.
        NEGATION => match *inner {
            Expr::Op(IrNode {
                opcode: NEGATION,
                payload: Payload::One(x),
            }) => Ok(Rewrite::Changed(*x)),
            other => Ok(keep1(opcode, Box::new(other))),
        },
        // anyOf/allOf over an all-Const[Boolean] ConcreteCollection literal.
        AND | OR => {
            if let Expr::Op(IrNode {
                opcode: CONCRETE_COLLECTION,
                payload: Payload::ConcreteCollection { items, .. },
            }) = inner.as_ref()
            {
                if let Some(bools) = all_bool_consts(items) {
                    let res = if opcode == AND {
                        bools.iter().all(|&b| b)
                    } else {
                        bools.iter().any(|&b| b)
                    };
                    return Ok(Rewrite::Changed(bool_const(res)));
                }
            }
            Ok(keep1(opcode, inner))
        }
        // SizeOf of a collection literal / Coll Const → element count.
        SIZE_OF => match coll_len(&inner) {
            Some(n) => Ok(Rewrite::Changed(Expr::Const {
                tpe: SigmaType::SInt,
                // Source-literal arity is far below i32::MAX.
                val: SigmaValue::Int(n as i32),
            })),
            None => Ok(keep1(opcode, inner)),
        },
        _ => Ok(keep1(opcode, inner)),
    }
}

/// The boolean values if every item is a `Const[Boolean]`, else `None`.
fn all_bool_consts(items: &[Expr]) -> Option<Vec<bool>> {
    items.iter().map(as_bool).collect()
}

/// Element count of a `SizeOf` operand that is a collection LITERAL
/// (`ConcreteCollection`, Scala's `fromItems(items).length → items.length`,
/// `IRContext.scala:116-118`), else `None`.
///
/// A `Coll` CONSTANT (`SizeOf(<Const Coll>)`) is deliberately NOT folded: the
/// Scala `CollConst(coll).length → coll.length` rule (`IRContext.scala:113-115`)
/// matches the graph `Coll.length` node, which a lifted `x.toBytes`/`x.toBits`
/// constant's `.size` does NOT lower to — oracle-pinned (`ccs sigmaProp(
/// x.toBytes.size == 4)` KEEPS `SizeOf(<Coll[Byte] const>)` unfolded,
/// `10020e040000000a0408d193b173007301`, `compile_numeric_const_fold_matches_
/// oracle_p2sh`). Folding it here would diverge (accept-side over-fold).
fn coll_len(inner: &Expr) -> Option<usize> {
    match inner {
        Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection { items, .. },
        }) => Some(items.len()),
        _ => None,
    }
}

/// Fold every child of `payload` (post-order), the fallible by-value twin of
/// `crate::tree::push_children` (a new child-carrying `Payload` variant fails
/// to compile here until it is mapped).
fn fold_children(payload: Payload) -> Result<Payload, EmitError> {
    let f = |b: Box<Expr>| -> Result<Box<Expr>, EmitError> { Ok(Box::new(fold(*b)?)) };
    let fv = |items: Vec<Expr>| -> Result<Vec<Expr>, EmitError> {
        items.into_iter().map(fold).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn int(v: i32) -> Expr {
        Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(v),
        }
    }

    fn long(v: i64) -> Expr {
        Expr::Const {
            tpe: SigmaType::SLong,
            val: SigmaValue::Long(v),
        }
    }

    fn byte(v: i8) -> Expr {
        Expr::Const {
            tpe: SigmaType::SByte,
            val: SigmaValue::Byte(v),
        }
    }

    fn boolean(b: bool) -> Expr {
        bool_const(b)
    }

    /// A non-const leaf (Height, opcode 0xA3) for shape tests.
    fn height() -> Expr {
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        })
    }

    fn op2(opcode: u8, l: Expr, r: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::Two(Box::new(l), Box::new(r)),
        })
    }

    fn op1(opcode: u8, inner: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::One(Box::new(inner)),
        })
    }

    fn coll(items: Vec<Expr>) -> Expr {
        Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection {
                elem_type: SigmaType::SBoolean,
                items,
            },
        })
    }

    fn f(e: Expr) -> Expr {
        fold(e).expect("fold ok")
    }

    // ----- happy path -----

    #[test]
    fn fold_lt_two_int_consts_folds_to_bool() {
        assert_eq!(f(op2(LT, int(1), int(2))), boolean(true));
        assert_eq!(f(op2(LT, int(2), int(1))), boolean(false));
    }

    #[test]
    fn fold_ge_min_plus_one_chain_folds() {
        // (min(1, 2) + 1) == 2  → true  (vector 81 core).
        let min = op2(MIN, int(1), int(2));
        let plus = op2(PLUS, min, int(1));
        let eq = op2(EQ, plus, int(2));
        assert_eq!(f(eq), boolean(true));
    }

    #[test]
    fn fold_max_plus_one_chain_folds() {
        let mx = op2(MAX, int(1), int(2));
        let eq = op2(EQ, op2(PLUS, mx, int(1)), int(3));
        assert_eq!(f(eq), boolean(true));
    }

    #[test]
    fn fold_eq_equal_int_consts_folds_true() {
        assert_eq!(f(op2(EQ, int(1), int(1))), boolean(true));
    }

    #[test]
    fn fold_eq_unequal_nonbool_consts_stays_unfolded() {
        // Scala's Equals case is terminal — `1 == 2` does NOT fold to false
        // (oracle-pinned; the Eq node survives).
        assert_eq!(f(op2(EQ, int(1), int(2))), op2(EQ, int(1), int(2)));
    }

    #[test]
    fn fold_neq_equal_consts_folds_false() {
        assert_eq!(f(op2(NEQ, int(5), int(5))), boolean(false));
    }

    #[test]
    fn fold_neq_unequal_nonbool_consts_stays_unfolded() {
        assert_eq!(f(op2(NEQ, int(1), int(2))), op2(NEQ, int(1), int(2)));
    }

    #[test]
    fn fold_eq_bool_const_true_returns_other_operand() {
        // x == true → x  (x a non-const so the identity is visible).
        assert_eq!(f(op2(EQ, height(), boolean(true))), height());
        // x == false → !x
        assert_eq!(f(op2(EQ, height(), boolean(false))), not_node(height()));
    }

    #[test]
    fn fold_plus_zero_identity_removes_add() {
        assert_eq!(f(op2(PLUS, height(), int(0))), height());
        assert_eq!(f(op2(PLUS, int(0), height())), height());
    }

    #[test]
    fn fold_plus_zero_over_const_max_folds_to_that_const() {
        // (2147483647 + 0) < 0 → false (vector 49 core).
        let plus = op2(PLUS, int(2147483647), int(0));
        assert_eq!(f(op2(LT, plus, int(0))), boolean(false));
    }

    #[test]
    fn fold_minus_zero_left_becomes_negation() {
        // 0 - x → -x (a Negation NODE, never a folded constant for non-const x).
        assert_eq!(f(op2(MINUS, int(0), height())), negation_node(height()));
    }

    #[test]
    fn fold_times_zero_folds_to_zero_and_one_is_identity() {
        assert_eq!(f(op2(MULTIPLY, height(), int(0))), int(0));
        assert_eq!(f(op2(MULTIPLY, int(0), height())), int(0));
        assert_eq!(f(op2(MULTIPLY, height(), int(1))), height());
        assert_eq!(f(op2(MULTIPLY, int(1), height())), height());
    }

    #[test]
    fn fold_long_minus_folds_within_range() {
        // (-9223372036854775807L - 1L) == Long::MIN, no overflow (vector 51).
        let m = op2(MINUS, long(-9223372036854775807), long(1));
        assert_eq!(f(op2(LT, m, long(0))), boolean(true));
    }

    #[test]
    fn fold_division_nonzero_divisor_folds() {
        // 4/2 == 2 and 5/2 == 2 (integer division) — oracle-pinned fold.
        assert_eq!(
            f(op2(EQ, op2(DIVISION, int(4), int(2)), int(2))),
            boolean(true)
        );
        assert_eq!(
            f(op2(EQ, op2(DIVISION, int(5), int(2)), int(2))),
            boolean(true)
        );
    }

    #[test]
    fn fold_modulo_nonzero_divisor_folds() {
        assert_eq!(
            f(op2(EQ, op2(MODULO, int(5), int(3)), int(2))),
            boolean(true)
        );
    }

    #[test]
    fn fold_not_true_folds_to_false() {
        assert_eq!(f(op1(LOGICAL_NOT, boolean(true))), boolean(false));
    }

    #[test]
    fn fold_bin_xor_true_false_folds_to_true() {
        // true ^ false → !false → true (two fixpoint steps, vector 25).
        assert_eq!(
            f(op2(BIN_XOR, boolean(true), boolean(false))),
            boolean(true)
        );
    }

    #[test]
    fn fold_bin_xor_false_left_removes_xor() {
        // false ^ y → y
        assert_eq!(f(op2(BIN_XOR, boolean(false), height())), height());
        // x ^ false → x
        assert_eq!(f(op2(BIN_XOR, height(), boolean(false))), height());
    }

    #[test]
    fn fold_sizeof_concrete_collection_literal_folds_to_len() {
        // Coll(HEIGHT, HEIGHT).size == 2 (vectors 79/80 core).
        let c = Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection {
                elem_type: SigmaType::SLong,
                items: vec![height(), height()],
            },
        });
        assert_eq!(f(op1(SIZE_OF, c)), int(2));
    }

    #[test]
    fn fold_sizeof_empty_ubi_collection_folds_and_erases_ubi() {
        // Coll[UnsignedBigInt]().size == 0 → true; the folded tree carries no
        // UBI (v3-only) data (NF-1 closure).
        let empty = Expr::Op(IrNode {
            opcode: CONCRETE_COLLECTION,
            payload: Payload::ConcreteCollection {
                elem_type: SigmaType::SUnsignedBigInt,
                items: vec![],
            },
        });
        assert_eq!(f(op2(EQ, op1(SIZE_OF, empty), int(0))), boolean(true));
    }

    #[test]
    fn fold_anyof_allof_all_const_bool_fold() {
        // anyOf(Coll(true, false)) → true ; allOf(Coll(true, false)) → false.
        assert_eq!(
            f(op1(OR, coll(vec![boolean(true), boolean(false)]))),
            boolean(true)
        );
        assert_eq!(
            f(op1(AND, coll(vec![boolean(true), boolean(false)]))),
            boolean(false)
        );
        assert_eq!(
            f(op1(AND, coll(vec![boolean(true), boolean(true)]))),
            boolean(true)
        );
    }

    #[test]
    fn fold_double_negation_removes_both() {
        // -(-(HEIGHT)) → HEIGHT.
        assert_eq!(f(negation_node(negation_node(height()))), height());
    }

    #[test]
    fn fold_not_of_comparison_flips_de_morgan() {
        // !(HEIGHT < 5) → HEIGHT >= 5.
        assert_eq!(
            f(op1(LOGICAL_NOT, op2(LT, height(), int(5)))),
            op2(GE, height(), int(5))
        );
        // !(HEIGHT >= 5) → HEIGHT < 5.
        assert_eq!(
            f(op1(LOGICAL_NOT, op2(GE, height(), int(5)))),
            op2(LT, height(), int(5))
        );
    }

    #[test]
    fn fold_byte_bitwise_result_equality_folds_true() {
        // The receiver is already a folded Byte Const (emit's bitwise fold);
        // this pass then folds the surrounding equality: 7.toByte == 7.toByte → true.
        assert_eq!(f(op2(EQ, byte(7), byte(7))), boolean(true));
    }

    // ----- round-trips -----

    #[test]
    fn fold_is_idempotent_on_already_folded() {
        let folded = boolean(true);
        assert_eq!(f(folded.clone()), folded);
        // A non-const leaf is untouched.
        assert_eq!(f(height()), height());
    }

    #[test]
    fn fold_recurses_through_numeric_cast_but_never_folds_the_cast() {
        // Downcast(x*100) : the child Times folds to Const(1000) but the
        // Downcast node itself is NEVER folded here (that is the pre-pass's
        // structural job) and is not treated as Const for a parent — mirrors
        // the oracle keeping `Downcast` + `Gt` over `(x*100).toByte`.
        let cast = Expr::Op(IrNode {
            opcode: 0x7D, // Downcast
            payload: Payload::NumericCast {
                input: Box::new(op2(MULTIPLY, int(5), int(100))),
                tpe: SigmaType::SByte,
            },
        });
        let gt = op2(GT, cast, byte(0));
        let folded = f(gt.clone());
        // The Times inside folded to Const(500); the Downcast + Gt survive.
        let expected_cast = Expr::Op(IrNode {
            opcode: 0x7D,
            payload: Payload::NumericCast {
                input: Box::new(int(500)),
                tpe: SigmaType::SByte,
            },
        });
        assert_eq!(folded, op2(GT, expected_cast, byte(0)));
    }

    // ----- error paths -----

    #[test]
    fn fold_int_add_overflow_rejects_arithmetic_exception() {
        let plus = op2(PLUS, int(2147483647), int(1));
        let err = fold(plus).expect_err("overflow rejects");
        assert!(matches!(
            err,
            EmitError::GraphBuildingReject {
                class: "ArithmeticException",
                ..
            }
        ));
    }

    #[test]
    fn fold_chained_arith_overflow_after_fold_rejects() {
        // ((2147483646 + 1) + 1) overflows on the SECOND add (the first folds
        // to 2147483647, chaining into the parent).
        let inner = op2(PLUS, int(2147483646), int(1));
        let outer = op2(PLUS, inner, int(1));
        assert!(fold(outer).is_err());
    }

    #[test]
    fn fold_division_by_zero_constant_stays_unfolded() {
        // 1 / 0 : shouldPropagate=false → the Division node survives, so the
        // enclosing Eq keeps its non-const operand and also stays.
        let div = op2(DIVISION, int(1), int(0));
        assert_eq!(f(div.clone()), div);
        assert_eq!(f(op2(EQ, div.clone(), int(0))), op2(EQ, div, int(0)));
    }

    #[test]
    fn fold_modulo_by_zero_constant_stays_unfolded() {
        let m = op2(MODULO, int(1), int(0));
        assert_eq!(f(m.clone()), m);
    }
}
