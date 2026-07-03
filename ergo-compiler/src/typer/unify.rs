//! Type unification, substitution, and numeric upcast machinery.
//!
//! Port of the Scala reference (sigma-state 6.0.2, pinned worktree
//! `/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2`):
//!
//! - `core/shared/src/main/scala/sigma/ast/package.scala:15-108`
//!   (unifyTypes 12 ordered rules, unifyTypeLists TRUNCATING zip, applySubst,
//!   msgType/msgTypeOf)
//! - `core/shared/src/main/scala/sigma/ast/SType.scala:363-591`
//!   (numeric ladder, upcast/downcast with v3 BigInt gate)
//! - `data/shared/src/main/scala/sigma/ast/syntax.scala:168-177` (upcastTo)
//! - `data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala:659-706`
//!   (applyUpcast + arithOp / comparisonOp / equalityOp in TransformingSigmaBuilder)
//!
//! # tpe_params decision
//!
//! `SType::SFunc` (stype.rs) has no `tpe_params` field — it was kept lean for M1
//! parser compat (blast radius: 12+ call sites in parse.rs/ast.rs).  Instead, the
//! typer uses the `SFuncSpec` wrapper here for method signatures that carry type
//! parameters.  `apply_subst` on a bare `SType::SFunc` recurses into dom/range and
//! drops nothing (there are no tpe_params to drop); `apply_subst_func` on an
//! `SFuncSpec` drops substituted tpe_params per PKG:74.  Task 3 uses `SFuncSpec`
//! for method entries; M1 parser code is untouched.

use std::collections::BTreeMap;

use crate::stype::SType;
use crate::typed::{node_tpe, ConstPayload, TypedExpr};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministic type substitution map.
///
/// Uses `BTreeMap` (sorted by key) for stable iteration order across runs —
/// important for deterministic code generation and test assertions.
///
/// Mirrors `STypeSubst = Map[STypeVar, SType]`
/// (package.scala:10, v6.0.2 worktree).
pub type TypeSubst = BTreeMap<String, SType>;

/// Method signature with type parameters, for use in the typer (Tasks 3+).
///
/// Mirrors `SFunc(tDom: Seq[SType], tRange: SType, tpeParams: Seq[STypeParam])`
/// (SType.scala:649-660, v6.0.2 worktree).  `SType::SFunc` omits tpe_params for
/// M1 parser compat; this wrapper carries them where needed.
///
/// `tpe_params` contains ident strings only; Task 3 fills them from the method
/// table transcription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SFuncSpec {
    pub dom: Vec<SType>,
    pub range: SType,
    /// Unsubstituted type parameter idents (e.g. "IV", "OV").
    /// Mirrors `STypeParam.ident: STypeVar` (SType.scala:78-89).
    pub tpe_params: Vec<String>,
}

/// Errors from the builder-side op layers and numeric conversions.
///
/// These mirror the exception hierarchy from sigma.exceptions
/// (ConstraintFailed, InvalidBinaryOperationParameters).  Task 5 wires these
/// into the full typer error surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// `comparisonOp` pre-upcast: at least one operand is not numeric.
    /// Mirrors `OnlyNumericConstrain` check in SigmaBuilder.scala:692.
    OnlyNumericRequired(String),
    /// `comparisonOp`/`equalityOp` post-upcast: operand types differ.
    /// Mirrors `SameTypeConstrain` check in SigmaBuilder.scala:684,695.
    SameTypeRequired(String),
    /// `upcast_to`: source not numeric, or target < source in the ladder.
    /// Mirrors `assert` in syntax.scala:169-173.
    InvalidUpcast(String),
    /// `const_downcast`: value is out of range for the target type.
    /// Mirrors `toByteExact`/`toShortExact`/`toIntExact` throws (SType.scala).
    OutOfRange(String),
    /// `const_upcast`/`const_downcast`: BigInt/UnsignedBigInt path requires
    /// `tree_version >= 3` (`VersionContext.isV3OrLaterErgoTreeVersion`).
    /// Source: SType.scala:412-413, 428-429, 451-452, 476-477, 487-488,
    ///         503-504, 512, 524, 528, 540 (v6.0.2 worktree).
    BigIntGated(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// §2 Unification  (package.scala:15-108, v6.0.2 worktree)
// ─────────────────────────────────────────────────────────────────────────────

/// Find a substitution `subst` such that `apply_subst(t1, subst) == t2`.
///
/// 12 ordered match rules, exact port of `unifyTypes` in package.scala:39-64.
/// `t1` is the "pattern" (generic) side; type variables in `t1` are bound.
///
/// Rules:
///  1. `(STypeVar n1, STypeVar n2)` → `n1==n2 ? Some({}) : None`
///  2. `(STypeVar id, _)` → `Some({id → t2})`
///  3. `(SColl e1, SColl e2)` → `unify(e1, e2)`
///  4. `(SColl e1, STuple _)` → `unify(e1, SAny)`
///  5. `(SOption e1, SOption e2)` → `unify(e1, e2)`
///  6. `(STuple e1, STuple e2)` same-len → `unify_type_lists(items)`
///  7. `(SFunc e1, SFunc e2)` same-dom-len → `unify_type_lists(dom ++ [range])`
///  8. `(STypeApply n1 a1, STypeApply n2 a2)` same-name/arity → `unify_type_lists(args)`
///  9. `(SBoolean, SSigmaProp)` → `Some({})` (asymmetric implicit widening)
/// 10. `(SPrimType e1, SPrimType e2)` same value → `Some({})`
/// 11. `(SAny, _)` → `Some({})`
/// 12. else → `None`
pub fn unify_types(t1: &SType, t2: &SType) -> Option<TypeSubst> {
    match (t1, t2) {
        // Rule 1: both type vars — equal names → empty subst, else None.
        // package.scala:40-41
        (SType::STypeVar(n1), SType::STypeVar(n2)) => {
            if n1 == n2 {
                Some(TypeSubst::new())
            } else {
                None
            }
        }
        // Rule 2: type var on left → bind to t2.
        // package.scala:42-43
        (SType::STypeVar(id), _) => {
            let mut s = TypeSubst::new();
            s.insert(id.clone(), t2.clone());
            Some(s)
        }
        // Rule 3: Coll vs Coll → unify elem types.
        // package.scala:44-45
        (SType::SColl(e1), SType::SColl(e2)) => unify_types(e1, e2),
        // Rule 4: Coll vs Tuple → unify elem with SAny.
        // package.scala:46-47
        (SType::SColl(e1), SType::STuple(_)) => unify_types(e1, &SType::SAny),
        // Rule 5: Option vs Option → unify elem types.
        // package.scala:48-49
        (SType::SOption(e1), SType::SOption(e2)) => unify_types(e1, e2),
        // Rule 6: Tuple vs Tuple, same length → pairwise.
        // package.scala:50-51
        (SType::STuple(e1), SType::STuple(e2)) if e1.len() == e2.len() => unify_type_lists(e1, e2),
        // Rule 7: SFunc vs SFunc, same dom length → unify dom++range.
        // package.scala:52-53
        (SType::SFunc { dom: d1, range: r1 }, SType::SFunc { dom: d2, range: r2 })
            if d1.len() == d2.len() =>
        {
            let mut list1: Vec<SType> = d1.clone();
            list1.push(*r1.clone());
            let mut list2: Vec<SType> = d2.clone();
            list2.push(*r2.clone());
            unify_type_lists(&list1, &list2)
        }
        // Rule 8: STypeApply — same name and arity → unify args.
        // package.scala:54-56
        (SType::STypeApply { name: n1, args: a1 }, SType::STypeApply { name: n2, args: a2 })
            if n1 == n2 && a1.len() == a2.len() =>
        {
            unify_type_lists(a1, a2)
        }
        // Rule 9: SBoolean → SSigmaProp (asymmetric; reverse is None).
        // package.scala:57-58
        (SType::SBoolean, SType::SSigmaProp) => Some(TypeSubst::new()),
        // Rule 10: both SPrimType with equal value.
        // package.scala:59-60. SPrimType.unapply = allPredefTypes.find(_ == t).
        (t1, t2) if is_prim_type(t1) && is_prim_type(t2) && t1 == t2 => Some(TypeSubst::new()),
        // Rule 11: SAny on the left unifies with anything.
        // package.scala:61-62
        (SType::SAny, _) => Some(TypeSubst::new()),
        // Rule 12: no match.
        // package.scala:63
        _ => None,
    }
}

/// Pairwise unification of two type lists, **truncating to the shorter list**.
///
/// All pairs must unify; if the same variable maps to two different types the
/// fold returns `None` (consistency check).  Length guards live in callers.
///
/// Mirrors `unifyTypeLists` in package.scala:17-33 (v6.0.2 worktree).
/// The `zipped` truncation is load-bearing — callers that need length parity
/// must check it before calling this function.
pub fn unify_type_lists(ts1: &[SType], ts2: &[SType]) -> Option<TypeSubst> {
    let mut merged = TypeSubst::new();
    for (t1, t2) in ts1.iter().zip(ts2.iter()) {
        let subst = unify_types(t1, t2)?;
        for (id, ty) in subst {
            match merged.get(&id) {
                Some(existing) if existing != &ty => return None,
                _ => {
                    merged.insert(id, ty);
                }
            }
        }
    }
    Some(merged)
}

/// Apply a type substitution bottom-up to a type.
///
/// For `SType::SFunc`: recurse into dom/range; no tpe_params to drop (use
/// `apply_subst_func` for `SFuncSpec` when tpe_param dropping is needed).
/// For `STypeVar`: replace if present in `subst`; identity otherwise.
/// All other compound shapes recurse bottom-up; primitives are identity.
///
/// Mirrors `applySubst` in package.scala:72-81 (v6.0.2 worktree).
/// The Scala uses kiama `everywherebu` (bottom-up rewriting); we recurse
/// explicitly, which is equivalent for acyclic types.
pub fn apply_subst(t: &SType, subst: &TypeSubst) -> SType {
    if subst.is_empty() {
        return t.clone();
    }
    match t {
        SType::STypeVar(name) => subst.get(name).cloned().unwrap_or_else(|| t.clone()),
        SType::SColl(e) => SType::SColl(Box::new(apply_subst(e, subst))),
        SType::SOption(e) => SType::SOption(Box::new(apply_subst(e, subst))),
        SType::STuple(items) => {
            SType::STuple(items.iter().map(|i| apply_subst(i, subst)).collect())
        }
        // SType::SFunc has no tpe_params (M1 compat); recurse into dom/range only.
        SType::SFunc { dom, range } => SType::SFunc {
            dom: dom.iter().map(|d| apply_subst(d, subst)).collect(),
            range: Box::new(apply_subst(range, subst)),
        },
        SType::STypeApply { name, args } => SType::STypeApply {
            name: name.clone(),
            args: args.iter().map(|a| apply_subst(a, subst)).collect(),
        },
        // All primitive/leaf types: identity (no type variables inside).
        other => other.clone(),
    }
}

/// Apply substitution to an `SFuncSpec`, dropping substituted tpe_params.
///
/// Mirrors the `SFunc` case of `applySubst` in package.scala:73-75:
/// ```scala
/// case SFunc(args, res, tparams) =>
///   val remainingVars = tparams.filterNot { p => subst.contains(p.ident) }
///   SFunc(args.map(applySubst(_, subst)), applySubst(res, subst), remainingVars)
/// ```
pub fn apply_subst_func(spec: &SFuncSpec, subst: &TypeSubst) -> SFuncSpec {
    SFuncSpec {
        dom: spec.dom.iter().map(|d| apply_subst(d, subst)).collect(),
        range: apply_subst(&spec.range, subst),
        tpe_params: spec
            .tpe_params
            .iter()
            .filter(|p| !subst.contains_key(*p))
            .cloned()
            .collect(),
    }
}

/// Most general type of two types.
///
/// `msgType(a, b)`: try `unify(a, b)` → `Some(a)`; else try `unify(b, a)` →
/// `Some(b)`; else `None`.
///
/// Mirrors `msgType` in package.scala:89-92 (v6.0.2 worktree).
pub fn msg_type(t1: &SType, t2: &SType) -> Option<SType> {
    if unify_types(t1, t2).is_some() {
        Some(t1.clone())
    } else if unify_types(t2, t1).is_some() {
        Some(t2.clone())
    } else {
        None
    }
}

/// Most specific generalized type of a non-empty list.
///
/// Fold `msgType` over the list starting from the head.  Returns `None` if
/// the list is empty or any pair is incompatible.
///
/// Mirrors `msgTypeOf` in package.scala:96-108 (v6.0.2 worktree).
pub fn msg_type_of(types: &[SType]) -> Option<SType> {
    if types.is_empty() {
        return None;
    }
    let mut res = types[0].clone();
    for t in &types[1..] {
        res = msg_type(t, &res)?;
    }
    Some(res)
}

// ─────────────────────────────────────────────────────────────────────────────
// §3 Numeric ladder and upcast  (SType.scala + syntax.scala + SigmaBuilder.scala)
// ─────────────────────────────────────────────────────────────────────────────

/// True iff `t` is a predefined primitive type (matches `SPrimType.unapply`).
///
/// `SPrimType.unapply(t)` returns `SType.allPredefTypes.find(_ == t)`,
/// where `allPredefTypes` includes all 18 predef types (v5 core + SUnsignedBigInt
/// under v3+; we always include SUnsignedBigInt here since version gating lives
/// at method-table level, not at unification).
/// Source: SType.scala:321-322 (v6.0.2 worktree).
pub fn is_prim_type(t: &SType) -> bool {
    matches!(
        t,
        SType::SBoolean
            | SType::SByte
            | SType::SShort
            | SType::SInt
            | SType::SLong
            | SType::SBigInt
            | SType::SUnsignedBigInt
            | SType::SGroupElement
            | SType::SSigmaProp
            | SType::SAvlTree
            | SType::SContext
            | SType::SGlobal
            | SType::SHeader
            | SType::SPreHeader
            | SType::SString
            | SType::SBox
            | SType::SUnit
            | SType::SAny
    )
}

/// Position of a numeric type in the implicit upcast ladder.
///
/// Ladder: `SByte(0) < SShort(1) < SInt(2) < SLong(3) < SBigInt(4)`.
/// `SUnsignedBigInt(5)` is on the ladder by index but is NOT implicitly
/// reachable from the signed side — use explicit `.toUnsigned` (no implicit
/// cross-sign upcast; SBigInt.upcast and SUnsignedBigInt.upcast are disjoint).
///
/// Source: SType.scala `numericTypeIndex`:
///   SByte:402, SShort:425, SInt:447, SLong:472, SBigInt:503, SUnsignedBigInt:540.
pub fn numeric_index(t: &SType) -> Option<u8> {
    match t {
        SType::SByte => Some(0),
        SType::SShort => Some(1),
        SType::SInt => Some(2),
        SType::SLong => Some(3),
        SType::SBigInt => Some(4),
        SType::SUnsignedBigInt => Some(5),
        _ => None,
    }
}

/// True iff `t` is a numeric type (has a ladder index).
pub fn is_numeric(t: &SType) -> bool {
    numeric_index(t).is_some()
}

/// The larger of two numeric types by ladder index.
///
/// Mirrors `SNumericType.max` in SType.scala:363-364 (v6.0.2 worktree):
/// `if (this.numericTypeIndex > that.numericTypeIndex) this else that`
///
/// # Panics
/// Panics if either argument is not a numeric type.
pub fn numeric_max(t1: &SType, t2: &SType) -> SType {
    let i1 = numeric_index(t1).expect("numeric_max: t1 not numeric");
    let i2 = numeric_index(t2).expect("numeric_max: t2 not numeric");
    if i1 >= i2 {
        t1.clone()
    } else {
        t2.clone()
    }
}

/// Wrap `expr` in an `Upcast` node targeting `target`, or return unchanged if
/// source and target are already the same type.
///
/// Asserts (returning `Err`) that:
/// 1. `expr.tpe` is a numeric type.
/// 2. `target` is numeric and its index ≥ the source index.
///
/// Mirrors `upcastTo[T]` in syntax.scala:168-177 (v6.0.2 worktree):
/// ```scala
/// assert(v.tpe.isInstanceOf[SNumericType], ...)
/// assert(targetType.max(tV.tpe) == targetType, ...)
/// if (targetType == tV.tpe) v.asValue[T] else mkUpcast(tV, targetType)
/// ```
pub fn upcast_to(expr: TypedExpr, target: &SType) -> Result<TypedExpr, BuildError> {
    let src = node_tpe(&expr).clone();
    let src_idx = numeric_index(&src).ok_or_else(|| {
        BuildError::InvalidUpcast(format!(
            "Cannot upcast value of type {src:?} to {target:?}: only numeric types can be upcasted."
        ))
    })?;
    let tgt_idx = numeric_index(target).ok_or_else(|| {
        BuildError::InvalidUpcast(format!(
            "Invalid upcast target {target:?}: not a numeric type."
        ))
    })?;
    if tgt_idx < src_idx {
        return Err(BuildError::InvalidUpcast(format!(
            "Invalid upcast from {src:?} to {target:?}: target type should be larger than source type."
        )));
    }
    if &src == target {
        return Ok(expr);
    }
    Ok(TypedExpr::Upcast {
        input: Box::new(expr),
        tpe: target.clone(),
    })
}

/// Upcast both operands of a binary op to their numeric max, if they differ.
///
/// Mirrors `applyUpcast` in SigmaBuilder.scala:667-676 (v6.0.2 worktree):
/// ```scala
/// (left.tpe, right.tpe) match {
///   case (t1: SNumericType, t2: SNumericType) if t1 != t2 =>
///     val tmax = t1 max t2
///     (left.upcastTo(tmax), right.upcastTo(tmax))
///   case _ => (left, right)
/// }
/// ```
pub fn apply_upcast(
    left: TypedExpr,
    right: TypedExpr,
) -> Result<(TypedExpr, TypedExpr), BuildError> {
    let lt = node_tpe(&left).clone();
    let rt = node_tpe(&right).clone();
    if is_numeric(&lt) && is_numeric(&rt) && lt != rt {
        let tmax = numeric_max(&lt, &rt);
        let l = upcast_to(left, &tmax)?;
        let r = upcast_to(right, &tmax)?;
        Ok((l, r))
    } else {
        Ok((left, right))
    }
}

/// Builder `arithOp` layer: apply upcast only, no constraint check.
///
/// Used by `mkPlus/Minus/Multiply/Divide/Modulo/Min/Max`.
/// Mirrors `arithOp` in SigmaBuilder.scala:700-705 (v6.0.2 worktree):
/// ```scala
/// val t = applyUpcast(left, right); cons(t._1, t._2)
/// ```
/// Returns the (possibly upcasted) operand pair; the caller constructs the node.
pub fn arith_op(left: TypedExpr, right: TypedExpr) -> Result<(TypedExpr, TypedExpr), BuildError> {
    apply_upcast(left, right)
}

/// Builder `comparisonOp` layer: `OnlyNumeric` → upcast → `SameType`.
///
/// Used by `mkGT/GE/LT/LE`.
/// Mirrors `comparisonOp` in SigmaBuilder.scala:688-697 (v6.0.2 worktree):
/// ```scala
/// check2(left, right, OnlyNumericConstrain)  // pre-upcast
/// val t = applyUpcast(left, right)
/// check2(t._1, t._2, SameTypeConstrain)       // post-upcast
/// cons(t._1, t._2)
/// ```
/// The `SameType` post-upcast check is logically redundant when both operands
/// are numeric (apply_upcast always produces equal types), but we keep it for
/// exact parity with the Scala implementation.
pub fn comparison_op(
    left: TypedExpr,
    right: TypedExpr,
) -> Result<(TypedExpr, TypedExpr), BuildError> {
    // Pre-upcast: both must be numeric.
    let lt = node_tpe(&left).clone();
    let rt = node_tpe(&right).clone();
    if !is_numeric(&lt) || !is_numeric(&rt) {
        return Err(BuildError::OnlyNumericRequired(format!(
            "comparison requires numeric operands; got ({lt:?}, {rt:?})"
        )));
    }
    let (l, r) = apply_upcast(left, right)?;
    // Post-upcast: types must be identical.
    let lt2 = node_tpe(&l).clone();
    let rt2 = node_tpe(&r).clone();
    if lt2 != rt2 {
        return Err(BuildError::SameTypeRequired(format!(
            "comparison operands must have the same type after upcast; got ({lt2:?}, {rt2:?})"
        )));
    }
    Ok((l, r))
}

/// Builder `equalityOp` layer: upcast → `SameType`.
///
/// Used by `mkEQ/mkNEQ`.
/// Mirrors `equalityOp` in SigmaBuilder.scala:679-686 (v6.0.2 worktree):
/// ```scala
/// val t = applyUpcast(left, right)
/// check2(t._1, t._2, SameTypeConstrain)
/// cons(t._1, t._2)
/// ```
/// For non-numeric operands, apply_upcast is a no-op; the `SameType` check then
/// enforces that both sides have the same type (e.g. `true == false` passes,
/// `true == 1` fails).
pub fn equality_op(
    left: TypedExpr,
    right: TypedExpr,
) -> Result<(TypedExpr, TypedExpr), BuildError> {
    let (l, r) = apply_upcast(left, right)?;
    let lt = node_tpe(&l).clone();
    let rt = node_tpe(&r).clone();
    if lt != rt {
        return Err(BuildError::SameTypeRequired(format!(
            "equality operands must have the same type after upcast; got ({lt:?}, {rt:?})"
        )));
    }
    Ok((l, r))
}

// ─────────────────────────────────────────────────────────────────────────────
// §3 Constant up/downcast folding  (SType.scala:395-591, v6.0.2 worktree)
// ─────────────────────────────────────────────────────────────────────────────

/// Fold a constant upcast (source ≤ target in the numeric ladder).
///
/// BigInt/UnsignedBigInt paths (source OR target) require `tree_version >= 3`
/// (`VersionContext.isV3OrLaterErgoTreeVersion`; E8 binding decision).
///
/// Source: SType.scala `upcast` methods:
///   SByte:403-406, SShort:426-430, SInt:449-454, SLong:475-481,
///   SBigInt:506-514, SUnsignedBigInt:543-557.
///
/// Limitation: BigInt payloads (stored as decimal strings) are parsed via
/// `i128` for value extraction.  Payloads that exceed `i128::MAX` are
/// rejected with `BigIntGated`.  This covers all realistic script constants.
pub fn const_upcast(
    payload: &ConstPayload,
    from: &SType,
    to: &SType,
    tree_version: u8,
) -> Result<ConstPayload, BuildError> {
    let from_idx = numeric_index(from)
        .ok_or_else(|| BuildError::InvalidUpcast(format!("{from:?} is not a numeric type")))?;
    let to_idx = numeric_index(to)
        .ok_or_else(|| BuildError::InvalidUpcast(format!("{to:?} is not a numeric type")))?;
    if to_idx < from_idx {
        return Err(BuildError::InvalidUpcast(format!(
            "const_upcast from {from:?} to {to:?}: target must be >= source in the ladder"
        )));
    }
    // BigInt/UnsignedBigInt source or target: v3 gate.
    // Source: SType.scala:512, 528 (SBigInt.upcast), 543-557 (SUnsignedBigInt.upcast).
    if (matches!(from, SType::SBigInt | SType::SUnsignedBigInt)
        || matches!(to, SType::SBigInt | SType::SUnsignedBigInt))
        && tree_version < 3
    {
        return Err(BuildError::BigIntGated(format!(
            "BigInt/UnsignedBigInt upcast requires tree_version >= 3 \
             (VersionContext.isV3OrLaterErgoTreeVersion); got {tree_version}"
        )));
    }
    // Extract i64 from signed numeric payloads.
    let val: i64 = match payload {
        ConstPayload::Byte(v) => *v as i64,
        ConstPayload::Short(v) => *v as i64,
        ConstPayload::Int(v) => *v as i64,
        ConstPayload::Long(v) => *v,
        ConstPayload::BigInt(_) => {
            // BigInt → BigInt is identity (same type).
            if from == to {
                return Ok(payload.clone());
            }
            // BigInt → UnsignedBigInt: no implicit upcast (separate sub-ladder).
            return Err(BuildError::InvalidUpcast(format!(
                "No implicit upcast from SBigInt to {to:?}; use .toUnsigned explicitly"
            )));
        }
        _ => {
            return Err(BuildError::InvalidUpcast(format!(
                "non-numeric payload for const_upcast from {from:?}"
            )))
        }
    };
    match to {
        SType::SByte => Ok(ConstPayload::Byte(val as i8)),
        SType::SShort => Ok(ConstPayload::Short(val as i16)),
        SType::SInt => Ok(ConstPayload::Int(val as i32)),
        SType::SLong => Ok(ConstPayload::Long(val)),
        // Byte/Short/Int/Long → BigInt: CBigInt(BigInteger.valueOf(x.toLong))
        // Source: SType.scala:508-511 (SBigInt.upcast).
        SType::SBigInt => Ok(ConstPayload::BigInt(val.to_string())),
        // Byte/Short/Int/Long → UnsignedBigInt: non-negative only.
        // Source: SType.scala:544-556 (SUnsignedBigInt.upcast).
        SType::SUnsignedBigInt => {
            if val < 0 {
                return Err(BuildError::OutOfRange(format!(
                    "Cannot upcast negative value {val} to SUnsignedBigInt"
                )));
            }
            // Stored as BigInt(String) payload (no dedicated UBI payload in M2 scope).
            Ok(ConstPayload::BigInt(val.to_string()))
        }
        _ => Err(BuildError::InvalidUpcast(format!(
            "{to:?} is not a valid numeric upcast target"
        ))),
    }
}

/// Fold a constant downcast (source ≥ target in the numeric ladder).
///
/// BigInt/UnsignedBigInt source requires `tree_version >= 3` (E8; same gate
/// as upcast — see `const_upcast` docs).  Out-of-range values produce
/// `BuildError::OutOfRange` (mirrors `toByteExact`/`toShortExact` throws in
/// `scala.math.BigInt`/Java long arithmetic).
///
/// Source: SType.scala `downcast` methods:
///   SByte:407-415, SShort:431-438, SInt:455-463, SLong:482-490,
///   SBigInt:518-527, SUnsignedBigInt:560-573.
///
/// BigInt payload limitation: same as `const_upcast` — parsed via `i128`.
pub fn const_downcast(
    payload: &ConstPayload,
    from: &SType,
    to: &SType,
    tree_version: u8,
) -> Result<ConstPayload, BuildError> {
    let from_idx = numeric_index(from)
        .ok_or_else(|| BuildError::InvalidUpcast(format!("{from:?} is not a numeric type")))?;
    let to_idx = numeric_index(to)
        .ok_or_else(|| BuildError::InvalidUpcast(format!("{to:?} is not a numeric type")))?;
    if to_idx > from_idx {
        return Err(BuildError::InvalidUpcast(format!(
            "const_downcast from {from:?} to {to:?}: target must be <= source in the ladder"
        )));
    }
    // BigInt/UnsignedBigInt source: v3 gate.
    // Source: SType.scala:412-413, 435-436, 460-461, 487-488, 524, 528 (downcast cases).
    if matches!(from, SType::SBigInt | SType::SUnsignedBigInt) && tree_version < 3 {
        return Err(BuildError::BigIntGated(format!(
            "BigInt/UnsignedBigInt downcast to {to:?} requires tree_version >= 3 \
             (VersionContext.isV3OrLaterErgoTreeVersion); got {tree_version}"
        )));
    }
    // Extract i128 for range checking.  All non-BigInt payloads fit in i64 (i128).
    let val: i128 = match payload {
        ConstPayload::Byte(v) => *v as i128,
        ConstPayload::Short(v) => *v as i128,
        ConstPayload::Int(v) => *v as i128,
        ConstPayload::Long(v) => *v as i128,
        ConstPayload::BigInt(s) => s.parse::<i128>().map_err(|_| {
            BuildError::OutOfRange(format!(
                "BigInt value '{s}' exceeds i128 range; cannot range-check for {to:?}"
            ))
        })?,
        _ => {
            return Err(BuildError::InvalidUpcast(format!(
                "non-numeric payload for const_downcast from {from:?}"
            )))
        }
    };
    match to {
        SType::SByte => {
            if val < i8::MIN as i128 || val > i8::MAX as i128 {
                return Err(BuildError::OutOfRange(format!(
                    "value {val} is out of Byte range [{}, {}] (toByteExact)",
                    i8::MIN,
                    i8::MAX
                )));
            }
            Ok(ConstPayload::Byte(val as i8))
        }
        SType::SShort => {
            if val < i16::MIN as i128 || val > i16::MAX as i128 {
                return Err(BuildError::OutOfRange(format!(
                    "value {val} is out of Short range [{}, {}] (toShortExact)",
                    i16::MIN,
                    i16::MAX
                )));
            }
            Ok(ConstPayload::Short(val as i16))
        }
        SType::SInt => {
            if val < i32::MIN as i128 || val > i32::MAX as i128 {
                return Err(BuildError::OutOfRange(format!(
                    "value {val} is out of Int range [{}, {}] (toIntExact)",
                    i32::MIN,
                    i32::MAX
                )));
            }
            Ok(ConstPayload::Int(val as i32))
        }
        SType::SLong => {
            // Long → Long is identity; BigInt→Long is the interesting case.
            if val < i64::MIN as i128 || val > i64::MAX as i128 {
                return Err(BuildError::OutOfRange(format!(
                    "value {val} is out of Long range (toLongExact)"
                )));
            }
            Ok(ConstPayload::Long(val as i64))
        }
        // BigInt → BigInt: identity (from must also be SBigInt).
        SType::SBigInt => Ok(payload.clone()),
        // UnsignedBigInt → UnsignedBigInt: identity.
        SType::SUnsignedBigInt => {
            if val < 0 {
                return Err(BuildError::OutOfRange(format!(
                    "Cannot downcast negative value {val} to SUnsignedBigInt"
                )));
            }
            Ok(payload.clone())
        }
        _ => Err(BuildError::InvalidUpcast(format!(
            "{to:?} is not a valid numeric downcast target"
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed::{ConstPayload, TypedExpr, ARITH_PLUS};

    // ----- helpers -----

    fn empty() -> TypeSubst {
        TypeSubst::new()
    }

    fn bind(var: &str, t: SType) -> TypeSubst {
        let mut m = TypeSubst::new();
        m.insert(var.to_string(), t);
        m
    }

    fn int_const(v: i32) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Int(v),
            tpe: SType::SInt,
        }
    }

    fn long_const(v: i64) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Long(v),
            tpe: SType::SLong,
        }
    }

    fn byte_const(v: i8) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Byte(v),
            tpe: SType::SByte,
        }
    }

    fn bool_const(v: bool) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Bool(v),
            tpe: SType::SBoolean,
        }
    }

    fn coll(elem: SType) -> SType {
        SType::SColl(Box::new(elem))
    }

    fn opt(elem: SType) -> SType {
        SType::SOption(Box::new(elem))
    }

    fn func(dom: Vec<SType>, range: SType) -> SType {
        SType::SFunc {
            dom,
            range: Box::new(range),
        }
    }

    fn tvar(name: &str) -> SType {
        SType::STypeVar(name.to_string())
    }

    fn tapp(name: &str, args: Vec<SType>) -> SType {
        SType::STypeApply {
            name: name.to_string(),
            args,
        }
    }

    // ----- happy path — unify rules -----

    #[test]
    fn unify_rule1_typevar_vs_typevar_equal_succeeds() {
        // Rule 1: (STypeVar "T", STypeVar "T") → Some({}).
        // package.scala:40-41
        assert_eq!(unify_types(&tvar("T"), &tvar("T")), Some(empty()));
    }

    #[test]
    fn unify_rule1_typevar_vs_typevar_different_fails() {
        // Rule 1: (STypeVar "T", STypeVar "U") → None.
        assert_eq!(unify_types(&tvar("T"), &tvar("U")), None);
    }

    #[test]
    fn unify_rule2_typevar_left_binds_to_any_type() {
        // Rule 2: STypeVar on left → Some({T → t2}).
        // package.scala:42-43
        assert_eq!(
            unify_types(&tvar("T"), &SType::SInt),
            Some(bind("T", SType::SInt))
        );
        assert_eq!(
            unify_types(&tvar("IV"), &coll(SType::SByte)),
            Some(bind("IV", coll(SType::SByte)))
        );
    }

    #[test]
    fn unify_rule3_coll_vs_coll_recurses_into_elem() {
        // Rule 3: SColl(e1) vs SColl(e2) → unify(e1, e2).
        // package.scala:44-45
        assert_eq!(
            unify_types(&coll(tvar("T")), &coll(SType::SLong)),
            Some(bind("T", SType::SLong))
        );
        assert_eq!(
            unify_types(&coll(SType::SInt), &coll(SType::SInt)),
            Some(empty())
        );
        assert_eq!(unify_types(&coll(SType::SInt), &coll(SType::SLong)), None);
    }

    #[test]
    fn unify_rule4_coll_vs_tuple_unifies_elem_with_sany() {
        // Rule 4: SColl(e1) vs STuple(_) → unify(e1, SAny).
        // package.scala:46-47. SAny on left → rule 11 → Some({}).
        let tuple2 = SType::STuple(vec![SType::SInt, SType::SLong]);
        assert_eq!(unify_types(&coll(SType::SAny), &tuple2), Some(empty()));
        // Any elem type: unify(elem, SAny) fires rule 10 (if elem==SAny) or rule 11 on SAny side.
        // unify(SInt, SAny): rule 9 fails (not Bool/Prop), rule 10: is_prim(SInt)&&is_prim(SAny)
        //   but SInt != SAny → fails, rule 11: SAny is on LEFT in recursive call, but here
        //   t1=SInt, t2=SAny so rule 11 doesn't fire. Actually this returns None.
        // Rule 4: unify(SInt, SAny) → is this Some or None?
        // SAny on LEFT would be rule 11. But SAny is on the RIGHT here (t2=SAny).
        // unify(SInt, SAny): rule 1 fails, rule 2 fails (SInt not typevar), rule 3-8 fail,
        //   rule 9 fails (SInt not SBoolean), rule 10: is_prim(SInt)&&is_prim(SAny)&&SInt==SAny? No.
        //   rule 11: SAny is on LEFT (t1=SInt is not SAny), rule 12: None.
        // So unify(SInt, SAny) = None! This means coll(SInt) vs tuple → None.
        assert_eq!(unify_types(&coll(SType::SInt), &tuple2), None);
        // But coll(tvar("T")) vs tuple: unify(tvar("T"), SAny) = rule 2 → Some({T → SAny}).
        assert_eq!(
            unify_types(&coll(tvar("T")), &tuple2),
            Some(bind("T", SType::SAny))
        );
    }

    #[test]
    fn unify_rule5_option_vs_option_recurses_into_elem() {
        // Rule 5: SOption(e1) vs SOption(e2) → unify(e1, e2).
        // package.scala:48-49
        assert_eq!(
            unify_types(&opt(tvar("T")), &opt(SType::SBoolean)),
            Some(bind("T", SType::SBoolean))
        );
        assert_eq!(unify_types(&opt(SType::SInt), &opt(SType::SLong)), None);
    }

    #[test]
    fn unify_rule6_tuple_vs_tuple_same_length_pairwise() {
        // Rule 6: same-length tuples → pairwise.
        // package.scala:50-51
        let t1 = SType::STuple(vec![tvar("A"), tvar("B")]);
        let t2 = SType::STuple(vec![SType::SInt, SType::SLong]);
        let mut expected = TypeSubst::new();
        expected.insert("A".into(), SType::SInt);
        expected.insert("B".into(), SType::SLong);
        assert_eq!(unify_types(&t1, &t2), Some(expected));
    }

    #[test]
    fn unify_rule6_tuple_different_lengths_fails() {
        // Rule 6 guard: lengths must match.
        let t1 = SType::STuple(vec![SType::SInt, SType::SLong]);
        let t2 = SType::STuple(vec![SType::SInt]);
        assert_eq!(unify_types(&t1, &t2), None);
    }

    #[test]
    fn unify_rule7_sfunc_vs_sfunc_same_dom_length() {
        // Rule 7: SFunc(dom, range) vs SFunc(dom, range) → unify(dom++range).
        // package.scala:52-53
        let f1 = func(vec![tvar("T")], tvar("T"));
        let f2 = func(vec![SType::SLong], SType::SLong);
        assert_eq!(unify_types(&f1, &f2), Some(bind("T", SType::SLong)));
    }

    #[test]
    fn unify_rule7_sfunc_different_dom_lengths_fails() {
        let f1 = func(vec![SType::SInt, SType::SInt], SType::SInt);
        let f2 = func(vec![SType::SInt], SType::SInt);
        assert_eq!(unify_types(&f1, &f2), None);
    }

    #[test]
    fn unify_rule8_typeapply_same_name_and_arity() {
        // Rule 8: STypeApply — same name+arity → unify args.
        // package.scala:54-56
        let ta1 = tapp("Foo", vec![tvar("T")]);
        let ta2 = tapp("Foo", vec![SType::SInt]);
        assert_eq!(unify_types(&ta1, &ta2), Some(bind("T", SType::SInt)));
    }

    #[test]
    fn unify_rule8_typeapply_different_name_fails() {
        let ta1 = tapp("Foo", vec![SType::SInt]);
        let ta2 = tapp("Bar", vec![SType::SInt]);
        assert_eq!(unify_types(&ta1, &ta2), None);
    }

    #[test]
    fn unify_rule9_boolean_to_sigmaprop_succeeds_asymmetric() {
        // Rule 9: (SBoolean, SSigmaProp) → Some({}).
        // package.scala:57-58. Reverse (SSigmaProp, SBoolean) must be None.
        assert_eq!(
            unify_types(&SType::SBoolean, &SType::SSigmaProp),
            Some(empty())
        );
        // Reverse: SSigmaProp → SBoolean must be None (rule 9 is asymmetric).
        // (SSigmaProp, SBoolean): rule 9 → no (wrong order). rule 10: both prim,
        // equal? No. rule 11: SAny on left? No. → None.
        assert_eq!(unify_types(&SType::SSigmaProp, &SType::SBoolean), None);
    }

    #[test]
    fn unify_rule10_prim_equality_succeeds() {
        // Rule 10: both prim with equal value → Some({}).
        // package.scala:59-60
        for t in [
            SType::SBoolean,
            SType::SByte,
            SType::SInt,
            SType::SLong,
            SType::SBigInt,
            SType::SGroupElement,
            SType::SSigmaProp,
            SType::SUnit,
            SType::SAny,
        ] {
            assert_eq!(unify_types(&t, &t), Some(empty()), "rule10 identity {t:?}");
        }
    }

    #[test]
    fn unify_rule10_prim_different_types_fails() {
        // Rule 10: same rule but different prims → falls through to rule 12.
        assert_eq!(unify_types(&SType::SInt, &SType::SLong), None);
        assert_eq!(unify_types(&SType::SBoolean, &SType::SUnit), None);
    }

    #[test]
    fn unify_rule11_sany_left_matches_anything() {
        // Rule 11: (SAny, _) → Some({}).
        // package.scala:61-62
        assert_eq!(unify_types(&SType::SAny, &SType::SInt), Some(empty()));
        assert_eq!(
            unify_types(&SType::SAny, &coll(SType::SByte)),
            Some(empty())
        );
        assert_eq!(unify_types(&SType::SAny, &SType::SAny), Some(empty()));
        // But SAny on the RIGHT does NOT match (rule 11 is also asymmetric).
        assert_eq!(unify_types(&SType::SInt, &SType::SAny), None);
    }

    #[test]
    fn unify_rule12_default_none() {
        // Rule 12: anything that doesn't match → None.
        assert_eq!(unify_types(&SType::SInt, &SType::SBoolean), None);
        assert_eq!(unify_types(&coll(SType::SInt), &opt(SType::SInt)), None);
    }

    // ----- happy path — ordered precedence -----

    #[test]
    fn unify_rule9_fires_before_rule10_for_bool_sigmaprop() {
        // Rule 9 before Rule 10: (SBoolean, SSigmaProp) must hit rule 9 → Some({}).
        // If rule 10 fired, both are prim but SBoolean != SSigmaProp → None (wrong).
        assert_eq!(
            unify_types(&SType::SBoolean, &SType::SSigmaProp),
            Some(empty())
        );
    }

    #[test]
    fn unify_rule11_fires_after_rule10_for_sany_sany() {
        // (SAny, SAny): rule 10 fires first (both prim, equal) → Some({}).
        // Rule 11 would also return Some({}) — same result in this case.
        assert_eq!(unify_types(&SType::SAny, &SType::SAny), Some(empty()));
    }

    #[test]
    fn unify_rule2_fires_before_rule10_for_typevar_vs_prim() {
        // (STypeVar "T", SInt): rule 2 fires → Some({T → SInt}).
        // Rule 10 would fail (STypeVar is not a prim type).
        assert_eq!(
            unify_types(&tvar("T"), &SType::SInt),
            Some(bind("T", SType::SInt))
        );
    }

    // ----- happy path — unify_type_lists -----

    #[test]
    fn unify_type_lists_pairwise_all_succeed() {
        // All pairs must unify; merged subst is the union.
        let ts1 = [tvar("A"), tvar("B"), SType::SInt];
        let ts2 = [SType::SLong, SType::SBoolean, SType::SInt];
        let result = unify_type_lists(&ts1, &ts2);
        let mut expected = TypeSubst::new();
        expected.insert("A".into(), SType::SLong);
        expected.insert("B".into(), SType::SBoolean);
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn unify_type_lists_truncates_to_shorter() {
        // package.scala:19: `.zipped` → truncation; NOT a length-mismatch error.
        // Longer list elements beyond the shorter are ignored.
        let ts1 = [SType::SInt, SType::SLong, SType::SBoolean];
        let ts2 = [SType::SInt];
        assert_eq!(unify_type_lists(&ts1, &ts2), Some(empty()));
        // Reverse: shorter on left.
        assert_eq!(unify_type_lists(&ts2, &ts1), Some(empty()));
    }

    #[test]
    fn unify_type_lists_merge_conflict_returns_none() {
        // Same var maps to two different types → None.
        // package.scala:25: `if (res.contains(id) && res(id) != t) return None`.
        let ts1 = [tvar("T"), tvar("T")];
        let ts2 = [SType::SInt, SType::SLong];
        assert_eq!(unify_type_lists(&ts1, &ts2), None);
    }

    #[test]
    fn unify_type_lists_empty_inputs_succeed() {
        assert_eq!(unify_type_lists(&[], &[]), Some(empty()));
    }

    // ----- round-trips — apply_subst -----

    #[test]
    fn apply_subst_typevar_replaced() {
        let subst = bind("T", SType::SInt);
        assert_eq!(apply_subst(&tvar("T"), &subst), SType::SInt);
    }

    #[test]
    fn apply_subst_typevar_absent_unchanged() {
        let subst = bind("T", SType::SInt);
        assert_eq!(apply_subst(&tvar("U"), &subst), tvar("U"));
    }

    #[test]
    fn apply_subst_empty_subst_is_identity() {
        let subst = empty();
        let complex = coll(func(vec![tvar("T")], opt(SType::SLong)));
        assert_eq!(apply_subst(&complex, &subst), complex);
    }

    #[test]
    fn apply_subst_coll_recurses_into_elem() {
        let subst = bind("T", SType::SBigInt);
        assert_eq!(apply_subst(&coll(tvar("T")), &subst), coll(SType::SBigInt));
    }

    #[test]
    fn apply_subst_sfunc_recurses_dom_and_range() {
        let subst = bind("A", SType::SInt);
        let f = func(vec![tvar("A"), SType::SBoolean], tvar("A"));
        let expected = func(vec![SType::SInt, SType::SBoolean], SType::SInt);
        assert_eq!(apply_subst(&f, &subst), expected);
    }

    #[test]
    fn apply_subst_nested_compound_rewrites_all_vars() {
        let mut subst = TypeSubst::new();
        subst.insert("IV".into(), SType::SInt);
        subst.insert("OV".into(), SType::SLong);
        let t = func(vec![tvar("IV")], coll(tvar("OV")));
        let expected = func(vec![SType::SInt], coll(SType::SLong));
        assert_eq!(apply_subst(&t, &subst), expected);
    }

    // ----- round-trips — apply_subst_func -----

    #[test]
    fn apply_subst_func_drops_substituted_tpe_params() {
        // Mirrors package.scala:74: remainingVars = tparams.filterNot(subst.contains(_.ident)).
        let spec = SFuncSpec {
            dom: vec![tvar("IV"), SType::SBoolean],
            range: tvar("OV"),
            tpe_params: vec!["IV".into(), "OV".into(), "UNUSED".into()],
        };
        let mut subst = TypeSubst::new();
        subst.insert("IV".into(), SType::SInt);
        subst.insert("OV".into(), SType::SLong);
        let result = apply_subst_func(&spec, &subst);
        assert_eq!(result.dom, vec![SType::SInt, SType::SBoolean]);
        assert_eq!(result.range, SType::SLong);
        // Only "UNUSED" survives (IV and OV were substituted).
        assert_eq!(result.tpe_params, vec!["UNUSED".to_string()]);
    }

    #[test]
    fn apply_subst_func_empty_subst_leaves_all_tpe_params() {
        let spec = SFuncSpec {
            dom: vec![tvar("T")],
            range: tvar("T"),
            tpe_params: vec!["T".into()],
        };
        let result = apply_subst_func(&spec, &empty());
        assert_eq!(result.tpe_params, vec!["T".to_string()]);
    }

    // ----- happy path — msgType / msgTypeOf -----

    #[test]
    fn msg_type_unifies_first_direction_returns_t1() {
        // msgType(a, b): if unify(a, b) → Some(a).
        // package.scala:89-91
        assert_eq!(msg_type(&SType::SInt, &SType::SInt), Some(SType::SInt));
        // SBoolean vs SSigmaProp: unify(SBoolean, SSigmaProp) = Some → returns SBoolean.
        assert_eq!(
            msg_type(&SType::SBoolean, &SType::SSigmaProp),
            Some(SType::SBoolean)
        );
    }

    #[test]
    fn msg_type_fallback_second_direction_returns_t2() {
        // msgType(a, b): unify(a,b) fails, try unify(b,a) → returns t2.
        // Example: msgType(SSigmaProp, SBoolean): unify(Sigma,Bool)=None, unify(Bool,Sigma)=Some → Some(SBoolean).
        assert_eq!(
            msg_type(&SType::SSigmaProp, &SType::SBoolean),
            Some(SType::SBoolean)
        );
    }

    #[test]
    fn msg_type_incompatible_types_returns_none() {
        // SInt and SLong: neither direction unifies → None.
        assert_eq!(msg_type(&SType::SInt, &SType::SLong), None);
        assert_eq!(msg_type(&SType::SBoolean, &SType::SInt), None);
    }

    #[test]
    fn msg_type_of_empty_returns_none() {
        assert_eq!(msg_type_of(&[]), None);
    }

    #[test]
    fn msg_type_of_singleton_returns_head() {
        assert_eq!(msg_type_of(&[SType::SInt]), Some(SType::SInt));
    }

    #[test]
    fn msg_type_of_homogeneous_returns_type() {
        // All same type → Some(that type).
        assert_eq!(
            msg_type_of(&[SType::SLong, SType::SLong, SType::SLong]),
            Some(SType::SLong)
        );
    }

    #[test]
    fn msg_type_of_bool_and_sigmaprop_returns_bool() {
        // unify_types(SBoolean, SBoolean) → Some → fold yields SBoolean.
        // Then msgType(SSigmaProp, SBoolean): unify(Sigma,Bool)=None, unify(Bool,Sigma)=Some → Bool.
        // Result: msgTypeOf([SBoolean, SSigmaProp, SBoolean]) = Some(SBoolean).
        // This is the `Coll(bool, prop, bool)` implicit coercion path.
        let result = msg_type_of(&[SType::SBoolean, SType::SSigmaProp, SType::SBoolean]);
        assert_eq!(result, Some(SType::SBoolean));
    }

    #[test]
    fn msg_type_of_mixed_numeric_fails() {
        // SInt and SLong are not unifiable either direction → None.
        // This is the "no numeric widening in ConcreteCollection" gotcha.
        assert_eq!(msg_type_of(&[SType::SInt, SType::SLong]), None);
    }

    // ----- happy path — numeric ladder -----

    #[test]
    fn numeric_index_returns_ladder_positions() {
        // SType.scala: SByte=0, SShort=1, SInt=2, SLong=3, SBigInt=4, SUnsignedBigInt=5.
        assert_eq!(numeric_index(&SType::SByte), Some(0));
        assert_eq!(numeric_index(&SType::SShort), Some(1));
        assert_eq!(numeric_index(&SType::SInt), Some(2));
        assert_eq!(numeric_index(&SType::SLong), Some(3));
        assert_eq!(numeric_index(&SType::SBigInt), Some(4));
        assert_eq!(numeric_index(&SType::SUnsignedBigInt), Some(5));
    }

    #[test]
    fn numeric_index_non_numeric_types_return_none() {
        assert_eq!(numeric_index(&SType::SBoolean), None);
        assert_eq!(numeric_index(&SType::SGlobal), None);
        assert_eq!(numeric_index(&coll(SType::SInt)), None);
    }

    #[test]
    fn numeric_max_returns_higher_index_type() {
        // SType.scala:363-364: max = higher numericTypeIndex.
        assert_eq!(numeric_max(&SType::SInt, &SType::SLong), SType::SLong);
        assert_eq!(numeric_max(&SType::SLong, &SType::SInt), SType::SLong);
        assert_eq!(numeric_max(&SType::SByte, &SType::SBigInt), SType::SBigInt);
        assert_eq!(numeric_max(&SType::SLong, &SType::SLong), SType::SLong);
    }

    // ----- happy path — upcast_to -----

    #[test]
    fn upcast_to_identity_returns_unchanged() {
        // syntax.scala:174: if (targetType == tV.tpe) v.asValue[T]
        let e = int_const(5);
        let result = upcast_to(e.clone(), &SType::SInt).unwrap();
        assert_eq!(result, e);
    }

    #[test]
    fn upcast_to_int_to_long_wraps_upcast_node() {
        // syntax.scala:176: mkUpcast(tV, targetType) = Upcast(input, tpe).
        // This is the shape in the golden seed: `1L + 1` produces
        // `(ArithOp:Long (ConstantNode:Long @1) (Upcast:Long (ConstantNode:Int @1)) @-102)`.
        // Ref: test-vectors/ergoscript/typer/golden_seed.txt line 23+.
        let e = int_const(1);
        let result = upcast_to(e.clone(), &SType::SLong).unwrap();
        assert_eq!(
            result,
            TypedExpr::Upcast {
                input: Box::new(e),
                tpe: SType::SLong,
            }
        );
    }

    #[test]
    fn upcast_to_byte_to_bigint_wraps_upcast_node() {
        let e = byte_const(42);
        let result = upcast_to(e.clone(), &SType::SBigInt).unwrap();
        assert!(matches!(
            result,
            TypedExpr::Upcast {
                tpe: SType::SBigInt,
                ..
            }
        ));
    }

    // ----- error paths — upcast_to -----

    #[test]
    fn upcast_to_non_numeric_source_errors() {
        let e = bool_const(true);
        assert!(matches!(
            upcast_to(e, &SType::SInt),
            Err(BuildError::InvalidUpcast(_))
        ));
    }

    #[test]
    fn upcast_to_target_smaller_than_source_errors() {
        let e = long_const(1);
        assert!(matches!(
            upcast_to(e, &SType::SInt),
            Err(BuildError::InvalidUpcast(_))
        ));
    }

    // ----- happy path — apply_upcast -----

    #[test]
    fn apply_upcast_both_numeric_different_widens_both_to_max() {
        // SigmaBuilder.scala:667-676: both upcasted to max.
        // Shape verified by golden seed: `1L + 1` → (Upcast:Long (Int @1)).
        let l = long_const(1);
        let r = int_const(1);
        let (l2, r2) = apply_upcast(l.clone(), r.clone()).unwrap();
        // l is already Long (max) → unchanged.
        assert_eq!(l2, l);
        // r (Int) is wrapped in Upcast to Long.
        assert!(matches!(
            r2,
            TypedExpr::Upcast {
                tpe: SType::SLong,
                ..
            }
        ));
    }

    #[test]
    fn apply_upcast_same_numeric_type_unchanged() {
        let l = long_const(1);
        let r = long_const(2);
        let (l2, r2) = apply_upcast(l.clone(), r.clone()).unwrap();
        assert_eq!(l2, l);
        assert_eq!(r2, r);
    }

    #[test]
    fn apply_upcast_non_numeric_unchanged() {
        let l = bool_const(true);
        let r = bool_const(false);
        let (l2, r2) = apply_upcast(l.clone(), r.clone()).unwrap();
        assert_eq!(l2, l);
        assert_eq!(r2, r);
    }

    // ----- happy path — op layers -----

    #[test]
    fn arith_op_numeric_different_types_returns_upcasted_pair() {
        // arithOp: no constraint check, just upcast.
        // SigmaBuilder.scala:700-705
        let l = int_const(5);
        let r = long_const(10);
        let (l2, r2) = arith_op(l, r).unwrap();
        // Int (index 2) < Long (index 3) → l gets upcasted to Long.
        assert!(matches!(
            l2,
            TypedExpr::Upcast {
                tpe: SType::SLong,
                ..
            }
        ));
        assert_eq!(node_tpe(&r2), &SType::SLong);
    }

    #[test]
    fn arith_op_non_numeric_no_constraint_still_passes() {
        // arithOp has no constraint → non-numeric pair passes through.
        let l = bool_const(true);
        let r = bool_const(false);
        let result = arith_op(l.clone(), r.clone()).unwrap();
        assert_eq!(result, (l, r));
    }

    #[test]
    fn comparison_op_numeric_pair_succeeds() {
        // comparisonOp: OnlyNumeric (pre-upcast) → upcast → SameType (post-upcast).
        // SigmaBuilder.scala:688-697
        let l = int_const(1);
        let r = long_const(2);
        let (l2, r2) = comparison_op(l, r).unwrap();
        assert_eq!(node_tpe(&l2), &SType::SLong);
        assert_eq!(node_tpe(&r2), &SType::SLong);
    }

    #[test]
    fn comparison_op_boolean_pair_fails_only_numeric_before_sametype() {
        // (SBoolean, SBoolean): OnlyNumeric check fires FIRST → Err(OnlyNumericRequired).
        // This proves the constraint ORDER: OnlyNumeric → upcast → SameType.
        // If SameType fired first, (SBoolean, SBoolean) would pass (same type).
        let l = bool_const(true);
        let r = bool_const(false);
        assert!(matches!(
            comparison_op(l, r),
            Err(BuildError::OnlyNumericRequired(_))
        ));
    }

    #[test]
    fn equality_op_numeric_different_types_upcasts_then_succeeds() {
        // equalityOp: upcast → SameType.
        // SigmaBuilder.scala:679-686
        let l = int_const(1);
        let r = long_const(2);
        let (l2, r2) = equality_op(l, r).unwrap();
        assert_eq!(node_tpe(&l2), &SType::SLong);
        assert_eq!(node_tpe(&r2), &SType::SLong);
    }

    #[test]
    fn equality_op_same_non_numeric_type_succeeds() {
        // Both SBoolean: apply_upcast is no-op, SameType passes.
        let l = bool_const(true);
        let r = bool_const(false);
        let (l2, r2) = equality_op(l.clone(), r.clone()).unwrap();
        assert_eq!(l2, l);
        assert_eq!(r2, r);
    }

    #[test]
    fn equality_op_different_non_numeric_types_fails_same_type() {
        // SBoolean + SInt: not numeric → apply_upcast no-op → SameType fails.
        let l = bool_const(true);
        let r = int_const(1);
        assert!(matches!(
            equality_op(l, r),
            Err(BuildError::SameTypeRequired(_))
        ));
    }

    // ----- happy path — const_upcast -----

    #[test]
    fn const_upcast_byte_to_int_succeeds() {
        let result = const_upcast(&ConstPayload::Byte(5), &SType::SByte, &SType::SInt, 0);
        assert_eq!(result, Ok(ConstPayload::Int(5)));
    }

    #[test]
    fn const_upcast_int_to_long_succeeds() {
        let result = const_upcast(&ConstPayload::Int(42), &SType::SInt, &SType::SLong, 0);
        assert_eq!(result, Ok(ConstPayload::Long(42)));
    }

    #[test]
    fn const_upcast_byte_to_bigint_requires_v3() {
        // Byte → BigInt: BigInt target → v3 gate.
        // SType.scala: BigInt upcast/downcast paths gated on isV3OrLaterErgoTreeVersion.
        assert!(matches!(
            const_upcast(&ConstPayload::Byte(1), &SType::SByte, &SType::SBigInt, 2),
            Err(BuildError::BigIntGated(_))
        ));
        assert_eq!(
            const_upcast(&ConstPayload::Byte(1), &SType::SByte, &SType::SBigInt, 3),
            Ok(ConstPayload::BigInt("1".into()))
        );
    }

    #[test]
    fn const_upcast_long_to_bigint_v3_succeeds() {
        let result = const_upcast(&ConstPayload::Long(9999), &SType::SLong, &SType::SBigInt, 3);
        assert_eq!(result, Ok(ConstPayload::BigInt("9999".into())));
    }

    // ----- error paths — const_upcast -----

    #[test]
    fn const_upcast_direction_error_when_target_smaller() {
        // Int → Byte is a downcast, not an upcast.
        let result = const_upcast(&ConstPayload::Int(5), &SType::SInt, &SType::SByte, 0);
        assert!(matches!(result, Err(BuildError::InvalidUpcast(_))));
    }

    #[test]
    fn const_upcast_negative_to_unsigned_bigint_fails() {
        let result = const_upcast(
            &ConstPayload::Long(-1),
            &SType::SLong,
            &SType::SUnsignedBigInt,
            3,
        );
        assert!(matches!(result, Err(BuildError::OutOfRange(_))));
    }

    // ----- happy path — const_downcast -----

    #[test]
    fn const_downcast_long_to_int_in_range_succeeds() {
        let result = const_downcast(&ConstPayload::Long(42), &SType::SLong, &SType::SInt, 0);
        assert_eq!(result, Ok(ConstPayload::Int(42)));
    }

    #[test]
    fn const_downcast_long_to_byte_in_range_succeeds() {
        let result = const_downcast(&ConstPayload::Long(100), &SType::SLong, &SType::SByte, 0);
        assert_eq!(result, Ok(ConstPayload::Byte(100)));
    }

    #[test]
    fn const_downcast_bigint_to_int_requires_v3() {
        // SType.scala:460-461: BigInt → Int requires isV3OrLaterErgoTreeVersion.
        // v2 → BigIntGated; v3 → succeeds.
        let payload = ConstPayload::BigInt("100".into());
        assert!(matches!(
            const_downcast(&payload, &SType::SBigInt, &SType::SInt, 2),
            Err(BuildError::BigIntGated(_))
        ));
        assert_eq!(
            const_downcast(&payload, &SType::SBigInt, &SType::SInt, 3),
            Ok(ConstPayload::Int(100))
        );
    }

    #[test]
    fn const_downcast_bigint_to_long_v3_succeeds() {
        let payload = ConstPayload::BigInt("9999999".into());
        let result = const_downcast(&payload, &SType::SBigInt, &SType::SLong, 3);
        assert_eq!(result, Ok(ConstPayload::Long(9999999)));
    }

    // ----- error paths — const_downcast -----

    #[test]
    fn const_downcast_long_to_byte_out_of_range_fails() {
        // 1000 > i8::MAX (127) → OutOfRange (toByteExact).
        let result = const_downcast(&ConstPayload::Long(1000), &SType::SLong, &SType::SByte, 0);
        assert!(matches!(result, Err(BuildError::OutOfRange(_))));
    }

    #[test]
    fn const_downcast_long_to_short_out_of_range_fails() {
        // 100000 > i16::MAX (32767) → OutOfRange (toShortExact).
        let result = const_downcast(
            &ConstPayload::Long(100_000),
            &SType::SLong,
            &SType::SShort,
            0,
        );
        assert!(matches!(result, Err(BuildError::OutOfRange(_))));
    }

    #[test]
    fn const_downcast_direction_error_when_target_larger() {
        // Byte → Long is an upcast, not a downcast.
        let result = const_downcast(&ConstPayload::Byte(5), &SType::SByte, &SType::SLong, 0);
        assert!(matches!(result, Err(BuildError::InvalidUpcast(_))));
    }

    // ----- oracle parity -----

    #[test]
    fn oracle_parity_1l_plus_1_upcast_shape() {
        // `1L + 1` → (ArithOp:Long (ConstantNode:Long @1) (Upcast:Long (ConstantNode:Int @1)) @-102)
        // Golden seed: test-vectors/ergoscript/typer/golden_seed.txt (committed oracle output).
        // The Int operand is wrapped in Upcast:Long by apply_upcast (both operands → max = Long).
        let l = long_const(1);
        let r = int_const(1);
        let (l2, r2) = apply_upcast(l.clone(), r.clone()).unwrap();
        // Left: Long (already max) → unchanged.
        assert_eq!(l2, l);
        // Right: Int → wrapped in Upcast:Long.
        let expected_r2 = TypedExpr::Upcast {
            input: Box::new(int_const(1)),
            tpe: SType::SLong,
        };
        assert_eq!(r2, expected_r2);
        // The ArithOp node itself (Plus opcode = -102):
        let arith = TypedExpr::ArithOp {
            left: Box::new(l2),
            right: Box::new(r2),
            opcode: ARITH_PLUS,
            tpe: SType::SLong,
        };
        assert_eq!(node_tpe(&arith), &SType::SLong);
    }

    #[test]
    fn oracle_parity_bool_sigmaprop_coll_msgtype() {
        // `Coll(true, proveDlog(g))`: elem types = [SBoolean, SSigmaProp].
        // msgTypeOf([SBoolean, SSigmaProp]):
        //   head = SBoolean; then msgType(SSigmaProp, SBoolean):
        //     unify(Sigma, Bool) = None; unify(Bool, Sigma) = Some → returns Bool.
        //   → Some(SBoolean).
        // Mirrors ConcreteCollection `msgTypeOf` path (SigmaTyper.scala:554-555).
        let types = vec![SType::SBoolean, SType::SSigmaProp];
        assert_eq!(msg_type_of(&types), Some(SType::SBoolean));
    }
}
