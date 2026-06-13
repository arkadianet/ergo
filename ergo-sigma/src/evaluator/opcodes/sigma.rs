//! Sigma-protocol and crypto opcodes:
//!
//! - 0xCD ProveDlog          — `GroupElement → SigmaProp(ProveDlog)`
//! - 0xCE ProveDhTuple       — four GroupElements → DHT sigma proposition
//! - 0xEE DecodePoint        — first 33 bytes of a Coll[Byte] → GroupElement
//! - 0xCB CalcBlake2b256     — Coll[Byte] / Coll[Int] → Coll[Byte] hash
//! - 0xCC CalcSha256         — Coll[Byte] / Coll[Int] → Coll[Byte] hash
//! - 0x9F Exponentiate       — `GroupElement ** BigInt` (EC scalar mul)
//! - 0xA0 MultiplyGroup      — `GroupElement * GroupElement` (EC point add)
//! - 0xF4 BinXor             — strict eager Boolean XOR (Fixed(20) cost)
//! - 0x9B Xor                — element-wise Coll[Byte] XOR (PerItem on shorter)
//! - 0xD0 SigmaPropBytes     — `SigmaProp` → ErgoTree-wrapped Coll[Byte]
//!
//! Plus `decode_group_element` — the EC-decode helper used by both
//! Exponentiate (0x9F) and MultiplyGroup (0xA0). The helper stays
//! cost-free (cost is charged in the calling arms) and preserves both
//! the `bytes[0] == 0x00 → IDENTITY` shortcut and the exact
//! `EvalError::TypeError` messages from the original arm bodies.

use ergo_primitives::group_element::GroupElement;
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use super::super::cost::{add_cost, add_cost_per_item};
use super::super::dispatch::TraceEntry;
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{count_sigma_nodes, trace_val, unpack_collection};
use super::super::types::{EvalError, Value};

// EC point decode used by both Exponentiate (0x9F) and MultiplyGroup
// (0xA0). Cost-free; cost stays in the calling arms. Preserves the
// `bytes[0] == 0x00 → IDENTITY` shortcut and exact `TypeError` messages
// from the original closure.
pub(super) fn decode_group_element(bytes: &[u8; 33]) -> Result<k256::ProjectivePoint, EvalError> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{AffinePoint, EncodedPoint, ProjectivePoint};
    if bytes[0] == 0x00 {
        return Ok(ProjectivePoint::IDENTITY);
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| EvalError::TypeError {
        expected: "valid SEC1 point",
        got: "invalid encoding".into(),
    })?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    if affine.is_some().into() {
        Ok(ProjectivePoint::from(affine.unwrap()))
    } else {
        Err(EvalError::TypeError {
            expected: "valid curve point",
            got: "not on curve".into(),
        })
    }
}

// 0xCD ProveDlog(group_element)
pub(in crate::evaluator) fn eval_prove_dlog(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xCD)?;
    let val = cx.eval_expr(inner)?;
    match val {
        Value::GroupElement(pk) => Ok(Value::SigmaProp(SigmaBoolean::ProveDlog(
            GroupElement::from_bytes(pk),
        ))),
        _ => Err(EvalError::TypeError {
            expected: "GroupElement",
            got: format!("{val:?}"),
        }),
    }
}

// 0xCE ProveDhTuple(g, h, u, v)
pub(in crate::evaluator) fn eval_prove_dh_tuple(
    g_expr: &Expr,
    h_expr: &Expr,
    u_expr: &Expr,
    v_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xCE)?;
    let g_val = cx.eval_expr(g_expr)?;
    let h_val = cx.eval_expr(h_expr)?;
    let u_val = cx.eval_expr(u_expr)?;
    let v_val = cx.eval_expr(v_expr)?;
    match (g_val, h_val, u_val, v_val) {
        (
            Value::GroupElement(g),
            Value::GroupElement(h),
            Value::GroupElement(u),
            Value::GroupElement(v),
        ) => Ok(Value::SigmaProp(SigmaBoolean::ProveDHTuple {
            g: GroupElement::from_bytes(g),
            h: GroupElement::from_bytes(h),
            u: GroupElement::from_bytes(u),
            v: GroupElement::from_bytes(v),
        })),
        (g, h, u, v) => Err(EvalError::TypeError {
            expected: "4 GroupElements for ProveDHTuple",
            got: format!("{g:?}, {h:?}, {u:?}, {v:?}"),
        }),
    }
}

// 0xEE DecodePoint — first 33 bytes of a Coll[Byte] → GroupElement.
// Scala `GroupElementSerializer.parse` reads exactly 33 bytes from the front
// (trailing data ignored) and then VALIDATES on the curve:
//   - `encoded(0) == 0` → `CryptoContext.default.infinity` (the canonical
//     identity), whose encoding is 33 zero bytes — any trailing X bytes are
//     discarded.
//   - otherwise → `decodePoint(encoded)` (BouncyCastle on the JVM oracle),
//     which REJECTS off-curve points, wrong prefixes, and non-square X.
// Our prior code copied the raw 33 bytes with no validation (accept-invalid
// for off-curve inputs, and raw bytes — not 33 zeros — for zero-lead inputs).
pub(in crate::evaluator) fn eval_decode_point(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xEE)?;
    let val = cx.eval_expr(inner)?;
    match val {
        Value::CollBytes(b) if b.len() >= 33 => {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&b[..33]);
            if arr[0] == 0x00 {
                // Identity canonicalizes to 33 zeros (discards trailing bytes).
                Ok(Value::GroupElement([0u8; 33]))
            } else {
                // Reject off-curve / malformed encodings (k256, same SEC1
                // validation the JVM's BouncyCastle applies). A valid 0x02/0x03
                // compressed point is already its own canonical encoding.
                decode_group_element(&arr)?;
                Ok(Value::GroupElement(arr))
            }
        }
        _ => Err(EvalError::TypeError {
            expected: "Coll[Byte] of length >= 33",
            got: format!("{val:?}"),
        }),
    }
}

// 0xCB CalcBlake2b256 — accepts Coll[Byte] and Coll[Int] (bytes widened by Map).
pub(in crate::evaluator) fn eval_calc_blake2b256(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let val = cx.eval_expr(inner)?;
    let bytes = match val {
        Value::CollBytes(b) => b,
        Value::CollInt(ints) => ints.iter().map(|&i| i as u8).collect(),
        _ => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for CalcBlake2b256",
                got: format!("{val:?}"),
            })
        }
    };
    add_cost_per_item(cx.cost, 0xCB, bytes.len() as u32)?;
    let hash = ergo_primitives::digest::blake2b256(&bytes);
    Ok(Value::CollBytes(hash.as_bytes().to_vec()))
}

// 0xCC CalcSha256 — accepts Coll[Byte] and Coll[Int].
pub(in crate::evaluator) fn eval_calc_sha256(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let val = cx.eval_expr(inner)?;
    let bytes = match val {
        Value::CollBytes(b) => b,
        Value::CollInt(ints) => ints.iter().map(|&i| i as u8).collect(),
        _ => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for CalcSha256",
                got: format!("{val:?}"),
            })
        }
    };
    add_cost_per_item(cx.cost, 0xCC, bytes.len() as u32)?;
    use sha2::Digest;
    let hash = sha2::Sha256::digest(&bytes);
    Ok(Value::CollBytes(hash.to_vec()))
}

// 0x9F Exponentiate — `GroupElement ** BigInt` (EC scalar multiplication).
// Scalar reduction follows Scala/BouncyCastle: exp.mod(group_order)
// using Euclidean (always non-negative) remainder.
pub(in crate::evaluator) fn eval_exponentiate(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x9F)?;
    let lv = cx.eval_expr(left)?;
    let rv = cx.eval_expr(right)?;
    match (lv, rv) {
        (Value::GroupElement(ge_bytes), Value::BigInt(exp)) => {
            use k256::elliptic_curve::group::GroupEncoding;
            use k256::elliptic_curve::ops::Reduce;
            use k256::Scalar;

            let point = decode_group_element(&ge_bytes)?;

            // Convert BigInt to scalar (mod group order).
            // Scala/BouncyCastle: bigInteger.mod(groupOrder) then use as scalar.
            // Must handle: negative values, values > group order, values > 256 bits.
            let group_order = num_bigint::BigInt::parse_bytes(
                b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                16,
            )
            .unwrap();

            // Euclidean mod: always non-negative
            let exp_mod = ((exp % &group_order) + &group_order) % &group_order;
            let (_, mod_bytes) = exp_mod.to_bytes_be();

            let mut scalar_bytes = [0u8; 32];
            let len = mod_bytes.len().min(32);
            scalar_bytes[32 - len..]
                .copy_from_slice(&mod_bytes[mod_bytes.len().saturating_sub(32)..]);

            let wide = k256::U256::from_be_slice(&scalar_bytes);
            let scalar = Scalar::reduce(wide);

            let result = point * scalar;
            let result_bytes = result.to_bytes();
            let mut out = [0u8; 33];
            out.copy_from_slice(&result_bytes);
            Ok(Value::GroupElement(out))
        }
        (l, r) => Err(EvalError::TypeError {
            expected: "(GroupElement, BigInt) for Exponentiate",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0xA0 MultiplyGroup — `GroupElement * GroupElement` (EC point addition).
pub(in crate::evaluator) fn eval_multiply_group(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xA0)?;
    let lv = cx.eval_expr(left)?;
    let rv = cx.eval_expr(right)?;
    match (lv, rv) {
        (Value::GroupElement(a_bytes), Value::GroupElement(b_bytes)) => {
            use k256::elliptic_curve::group::GroupEncoding;
            let a = decode_group_element(&a_bytes)?;
            let b = decode_group_element(&b_bytes)?;
            let result = a + b;
            let result_bytes = result.to_bytes();
            let mut out = [0u8; 33];
            out.copy_from_slice(&result_bytes);
            Ok(Value::GroupElement(out))
        }
        (l, r) => Err(EvalError::TypeError {
            expected: "(GroupElement, GroupElement) for MultiplyGroup",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0xF4 BinXor — Boolean XOR. trees.scala:1284-1302. Fixed(20) cost,
// strict eager evaluation of both operands (matches Scala `^`).
pub(in crate::evaluator) fn eval_bin_xor_bool(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_cost(cx.cost, 0xF4)?;
    match (l, r) {
        (Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a ^ b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "(Boolean, Boolean) for BinXor",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x9B Xor (byte-array) — trees.scala:1001-1026. Element-wise XOR over
// Coll[Byte]. Scala impl `left.zip(right).map(l ^ r)` truncates to the
// shorter length; mismatched lengths are allowed. Cost is per-item on
// `min(ls.length, rs.length)` via PerItemCost(10, 2, 128).
pub(in crate::evaluator) fn eval_xor(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    match (l, r) {
        (Value::CollBytes(a), Value::CollBytes(b)) => {
            let n = a.len().min(b.len());
            add_cost_per_item(cx.cost, 0x9B, n as u32)?;
            let out: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
            Ok(Value::CollBytes(out))
        }
        (l, r) => Err(EvalError::TypeError {
            expected: "(Coll[Byte], Coll[Byte]) for Xor",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

/// `sigma.data.COR.normalized`: a TrueProp child makes the whole OR true;
/// FalseProp children drop; empty → FalseProp; a lone survivor collapses to
/// itself. Shared by the SigmaOr collapse and the AtLeast reducer so trivial
/// folding is identical everywhere a disjunction is normalized.
fn cor_normalized(children: Vec<SigmaBoolean>) -> SigmaBoolean {
    if children
        .iter()
        .any(|sb| matches!(sb, SigmaBoolean::TrivialProp(true)))
    {
        return SigmaBoolean::TrivialProp(true);
    }
    let real: Vec<SigmaBoolean> = children
        .into_iter()
        .filter(|sb| !matches!(sb, SigmaBoolean::TrivialProp(false)))
        .collect();
    match real.len() {
        0 => SigmaBoolean::TrivialProp(false),
        1 => real.into_iter().next().unwrap(),
        _ => SigmaBoolean::Cor(real),
    }
}

/// `sigma.data.CAND.normalized`: a FalseProp child makes the whole AND false;
/// TrueProp children drop; empty → TrueProp; a lone survivor collapses to
/// itself. Mirror of [`cor_normalized`] for conjunctions.
fn cand_normalized(children: Vec<SigmaBoolean>) -> SigmaBoolean {
    if children
        .iter()
        .any(|sb| matches!(sb, SigmaBoolean::TrivialProp(false)))
    {
        return SigmaBoolean::TrivialProp(false);
    }
    let real: Vec<SigmaBoolean> = children
        .into_iter()
        .filter(|sb| !matches!(sb, SigmaBoolean::TrivialProp(true)))
        .collect();
    match real.len() {
        0 => SigmaBoolean::TrivialProp(true),
        1 => real.into_iter().next().unwrap(),
        _ => SigmaBoolean::Cand(real),
    }
}

/// Scala `SigmaConstants.MaxChildrenCountForAtLeastOp` (255): the maximum
/// number of children an `AtLeast` (k-of-n threshold) may carry. The
/// Cthreshold polynomial arithmetic uses single-byte inputs, so more than
/// 255 children cannot be represented.
const AT_LEAST_MAX_CHILDREN: usize = 255;

/// Port of Scala `sigma.ast.AtLeast.reduce` (trees.scala). Folds trivial
/// children out and adjusts the bound so the result NEVER carries a nested
/// TrivialProp — the proof verifier (`verify::parse_and_compute_challenges`)
/// relies on that invariant and rejects any tree that violates it. A TrueProp
/// child satisfies one slot for free (drop it, bound −= 1); a FalseProp child
/// is dead weight (drop it); survivors collapse to COR / CAND / CTHRESHOLD via
/// the same normalization as SigmaOr / SigmaAnd.
///
/// Kept structurally identical to the Scala loop ("HOTSPOT: don't beautify
/// this code") so it stays auditable line-for-line against the reference. The
/// per-item AtLeast cost is charged on the full pre-fold child count by the
/// caller, before this runs.
fn at_least_reduce(bound: i32, children: Vec<SigmaBoolean>) -> SigmaBoolean {
    let n_children = children.len();
    if bound <= 0 {
        return SigmaBoolean::TrivialProp(true);
    }
    if bound as usize > n_children {
        return SigmaBoolean::TrivialProp(false);
    }
    let mut cur_bound = bound as usize;
    let mut children_left = n_children;
    let mut sigmas: Vec<SigmaBoolean> = Vec::with_capacity(n_children);
    let mut iter = children.into_iter();
    loop {
        if cur_bound == 1 {
            sigmas.extend(iter);
            return cor_normalized(sigmas);
        }
        if cur_bound == children_left {
            sigmas.extend(iter);
            return cand_normalized(sigmas);
        }
        match iter.next() {
            Some(SigmaBoolean::TrivialProp(true)) => {
                children_left -= 1;
                cur_bound -= 1;
            }
            Some(SigmaBoolean::TrivialProp(false)) => {
                children_left -= 1;
            }
            Some(other) => sigmas.push(other),
            None => break,
        }
    }
    if cur_bound == 1 {
        return cor_normalized(sigmas);
    }
    if cur_bound == children_left {
        return cand_normalized(sigmas);
    }
    SigmaBoolean::Cthreshold {
        k: cur_bound as u8,
        children: sigmas,
    }
}

// 0x98 AtLeast(bound, children) -> SigmaProp. k-of-n threshold; folds trivial
// children and collapses to COR / CAND / CTHRESHOLD per Scala AtLeast.reduce
// (see at_least_reduce). Cost is per-item on the pre-fold child count.
pub(in crate::evaluator) fn eval_at_least(
    bound_expr: &Expr,
    children_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let bound_val = cx.eval_expr(bound_expr)?;
    let k = match bound_val {
        Value::Int(n) => n,
        _ => {
            return Err(EvalError::TypeError {
                expected: "Int for AtLeast bound",
                got: format!("{bound_val:?}"),
            })
        }
    };
    let children_val = cx.eval_expr(children_expr)?;
    let sigma_props = match children_val {
        Value::CollSigmaProp(items) => items,
        _ => {
            return Err(EvalError::TypeError {
                expected: "Coll[SigmaProp] for AtLeast",
                got: format!("{children_val:?}"),
            })
        }
    };
    add_cost_per_item(cx.cost, 0x98, sigma_props.len() as u32)?;
    // Scala's eval path runs `CSigmaDslBuilder.atLeast` (CSigmaDslBuilder.scala:103),
    // which throws when `props.length > MaxChildrenCount` (255) BEFORE
    // `AtLeast.reduce`. So the cap fires even for a degenerate bound that
    // reduce would otherwise short-circuit (bound<=0 -> TrueProp,
    // bound>nChildren -> FalseProp). Cthreshold polynomial arithmetic uses
    // single-byte inputs, hence the 255 limit.
    if sigma_props.len() > AT_LEAST_MAX_CHILDREN {
        return Err(EvalError::RuntimeException(
            "AtLeast children count exceeds MaxChildrenCount (255)",
        ));
    }
    Ok(Value::SigmaProp(at_least_reduce(k, sigma_props)))
}

// 0xEA SigmaAnd (collection form) — short-circuit on TrivialFalse.
pub(in crate::evaluator) fn eval_sigma_and_collection(
    items: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost_per_item(cx.cost, 0xEA, items.len() as u32)?;
    // Scala SigmaAnd.eval evaluates EVERY operand (charging each) BEFORE
    // collapsing — a sigma conjunction is not a boolean short-circuit. The
    // collapse (FalseProp is absorbing, TrueProp is the identity) is cost-free
    // and happens only after all children are evaluated. Returning early on a
    // trivial operand (as before) skipped a later operand's eval cost.
    let mut children = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let val = cx.eval_expr(item)?;
        if let Some(t) = cx.trace.as_mut() {
            t.push(TraceEntry {
                label: format!("SigmaAnd child {i}"),
                value: trace_val(&val),
            });
        }
        match val {
            Value::SigmaProp(sb) => children.push(sb),
            _ => {
                return Err(EvalError::TypeError {
                    expected: "SigmaProp",
                    got: format!("{val:?}"),
                })
            }
        }
    }
    // Cost-free collapse via the shared CAND normalization (FalseProp absorbs,
    // TrueProp drops) — the identical fold AtLeast applies to its children.
    Ok(Value::SigmaProp(cand_normalized(children)))
}

// 0xEB SigmaOr (collection form) — short-circuit on TrivialTrue.
pub(in crate::evaluator) fn eval_sigma_or_collection(
    items: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost_per_item(cx.cost, 0xEB, items.len() as u32)?;
    // Scala SigmaOr.eval evaluates EVERY operand (charging each) BEFORE
    // collapsing (TrueProp is absorbing, FalseProp is the identity); the
    // collapse is cost-free. Returning early on a trivial operand skipped a
    // later operand's eval cost.
    let mut children = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let val = cx.eval_expr(item)?;
        if let Some(t) = cx.trace.as_mut() {
            t.push(TraceEntry {
                label: format!("SigmaOr child {i}"),
                value: trace_val(&val),
            });
        }
        match val {
            Value::SigmaProp(sb) => children.push(sb),
            _ => {
                return Err(EvalError::TypeError {
                    expected: "SigmaProp",
                    got: format!("{val:?}"),
                })
            }
        }
    }
    // Cost-free collapse via the shared COR normalization (TrueProp absorbs,
    // FalseProp drops).
    Ok(Value::SigmaProp(cor_normalized(children)))
}

// 0x74 SubstConstants(script_bytes, positions, new_values).
// Generic: new_values can be Coll[SigmaProp], Coll[Coll[Byte]],
// Coll[GroupElement], etc. Cost is per-item on the number of constants
// in the template ErgoTree (returned by `subst_constants`).
pub(in crate::evaluator) fn eval_subst_constants(
    script_expr: &Expr,
    positions_expr: &Expr,
    values_expr: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let script = cx.eval_expr(script_expr)?;
    let positions = cx.eval_expr(positions_expr)?;
    let new_values = cx.eval_expr(values_expr)?;

    let script_bytes = match script {
        Value::CollBytes(b) => b,
        _ => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte]",
                got: format!("{script:?}"),
            })
        }
    };
    let pos_vec = match positions {
        Value::CollInt(v) => v,
        _ => {
            return Err(EvalError::TypeError {
                expected: "Coll[Int]",
                got: format!("{positions:?}"),
            })
        }
    };
    // Unpack the collection of new values into individual elements
    let value_items = unpack_collection(new_values)?;

    let (result, n_template_constants) = super::super::helpers::subst_constants(
        &script_bytes,
        &pos_vec,
        &value_items,
        cx.ctx.is_v3_ergo_tree(),
    )?;
    // Scala's ErgoTreeSerializer.substituteConstants returns nItems =
    // number of constants in the template ErgoTree. The evaluator
    // charges PerItem cost based on this count.
    add_cost_per_item(cx.cost, 0x74, n_template_constants as u32)?;
    Ok(Value::CollBytes(result))
}

// 0xD4 DeserializeContext(id, type) -> T.
// Reads a Coll[Byte] from context extension, deserializes as expression,
// evaluates. Scala validates the deserialized expression's static type
// matches `tpe` at the AST level. We don't track static types, so type
// errors surface naturally when the value is consumed in a
// type-incompatible context.
pub(in crate::evaluator) fn eval_deserialize_context(
    id: u8,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let (ext_tpe, ext_val) = cx
        .ctx
        .extension
        .get(&id)
        .ok_or_else(|| EvalError::TypeError {
            expected: "context extension variable",
            got: format!("extension var {id} not found"),
        })?;
    let bytes = match (ext_tpe, ext_val) {
        (SigmaType::SColl(inner), SigmaValue::Coll(coll_val))
            if matches!(inner.as_ref(), SigmaType::SByte) =>
        {
            match coll_val {
                ergo_ser::sigma_value::CollValue::Bytes(b) => b.clone(),
                _ => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for DeserializeContext",
                        got: "non-byte collection".into(),
                    })
                }
            }
        }
        _ => {
            return Err(EvalError::TypeError {
                expected: "Coll[Byte] for DeserializeContext",
                got: format!("{ext_tpe:?}"),
            })
        }
    };
    add_cost_per_item(cx.cost, 0xD4, bytes.len() as u32)?;
    // Deserialize as expression subtree (no constant segregation)
    let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
    // tree_version=0: the deserialized expression has no header of its
    // own. The version does not affect method-call parsing — explicit
    // type-args reads are keyed on `(type_id, method_id)` alone — so a
    // v6 MethodCall in the payload parses correctly; not-yet-activated
    // v6 methods are then rejected at evaluation time
    // (`require_method_version`).
    let expr = ergo_ser::opcode::parse_body(&mut r, 0).map_err(|e| EvalError::TypeError {
        expected: "valid serialized expression",
        got: format!("deserialization error: {e}"),
    })?;
    // Reject trailing bytes — full buffer must be consumed
    if !r.is_empty() {
        return Err(EvalError::TypeError {
            expected: "fully consumed DeserializeContext bytes",
            got: format!("{} trailing bytes", r.remaining()),
        });
    }
    cx.eval_expr(&expr)
}

// 0xD5 DeserializeRegister(reg_id, type, default) -> T.
// Reads Coll[Byte] from SELF box register, deserializes as expression,
// evaluates. If register is absent and a default expression is provided,
// evaluates the default.
pub(in crate::evaluator) fn eval_deserialize_register(
    reg_id: u8,
    default: Option<&Expr>,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let self_box = cx.ctx.self_box.ok_or(EvalError::TypeError {
        expected: "SELF box for DeserializeRegister",
        got: "no self box in context".into(),
    })?;
    if !(4..=9).contains(&reg_id) {
        return Err(EvalError::TypeError {
            expected: "register R4-R9 for DeserializeRegister",
            got: format!("register R{reg_id}"),
        });
    }
    let reg_idx = (reg_id - 4) as usize;
    match &self_box.registers[reg_idx] {
        Some(rv) => {
            let bytes = match (&rv.tpe, &rv.value) {
                (SigmaType::SColl(inner), SigmaValue::Coll(coll_val))
                    if matches!(inner.as_ref(), SigmaType::SByte) =>
                {
                    match coll_val {
                        ergo_ser::sigma_value::CollValue::Bytes(b) => b.clone(),
                        _ => {
                            return Err(EvalError::TypeError {
                                expected: "Coll[Byte] for DeserializeRegister",
                                got: "non-byte collection".into(),
                            })
                        }
                    }
                }
                _ => {
                    return Err(EvalError::TypeError {
                        expected: "Coll[Byte] for DeserializeRegister",
                        got: format!("{:?}", rv.tpe),
                    })
                }
            };
            add_cost_per_item(cx.cost, 0xD5, bytes.len() as u32)?;
            let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
            // tree_version=0: the deserialized expression has no header of its
            // own. The version does not affect method-call parsing — explicit
            // type-args reads are keyed on `(type_id, method_id)` alone — so a
            // v6 MethodCall in the payload parses correctly; not-yet-activated
            // v6 methods are then rejected at evaluation time
            // (`require_method_version`).
            let expr =
                ergo_ser::opcode::parse_body(&mut r, 0).map_err(|e| EvalError::TypeError {
                    expected: "valid serialized expression in register",
                    got: format!("deserialization error: {e}"),
                })?;
            if !r.is_empty() {
                return Err(EvalError::TypeError {
                    expected: "fully consumed DeserializeRegister bytes",
                    got: format!("{} trailing bytes", r.remaining()),
                });
            }
            cx.eval_expr(&expr)
        }
        None => {
            if let Some(default_expr) = default {
                cx.eval_expr(default_expr)
            } else {
                Err(EvalError::TypeError {
                    expected: "register present or default for DeserializeRegister",
                    got: format!("R{} absent with no default", reg_id),
                })
            }
        }
    }
}

// 0xD0 SigmaPropBytes — serialize SigmaProp as ErgoTree proposition bytes.
// In Ergo, `SigmaProp.propBytes` produces a full ErgoTree wrapping
// (header + inline constant), not just the raw SigmaBoolean. Scala
// charges PerItem based on the number of sigma tree nodes.
pub(in crate::evaluator) fn eval_sigma_prop_bytes(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let val = cx.eval_expr(inner)?;
    // Scala charges PerItem based on number of sigma tree nodes
    let n_nodes = match &val {
        Value::SigmaProp(sb) => count_sigma_nodes(sb) as u32,
        _ => 0,
    };
    add_cost_per_item(cx.cost, 0xD0, n_nodes)?;
    match val {
        Value::SigmaProp(sb) => {
            let mut w = ergo_primitives::writer::VlqWriter::new();
            // ErgoTree header: version 0, no size flag, no constant segregation
            w.put_u8(0x00);
            // Body: inline Const(SSigmaProp, SigmaProp(sb))
            ergo_ser::sigma_value::write_constant(
                &mut w,
                &SigmaType::SSigmaProp,
                &SigmaValue::SigmaProp(sb),
            )
            .map_err(|_| EvalError::UnsupportedOpcode(0xD0))?;
            Ok(Value::CollBytes(w.result()))
        }
        _ => Err(EvalError::TypeError {
            expected: "SigmaProp for SigmaPropBytes",
            got: format!("{val:?}"),
        }),
    }
}
