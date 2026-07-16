use crate::stype::SType;
use crate::typed::{
    node_tpe, TypedExpr, ARITH_DIVISION, ARITH_MAX, ARITH_MIN, ARITH_MINUS, ARITH_MODULO,
    ARITH_MULTIPLY, ARITH_PLUS, BIT_AND, BIT_OR, BIT_XOR,
};
use crate::typer::unify::{arith_op, comparison_op, equality_op, BuildError};
use crate::typer::{TypeEnv, TyperCtx};

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// §1.16 ArithOp / §1.17 BitOp arms
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn assign_arith(
    env: &TypeEnv,
    ctx: &TyperCtx,
    left: TypedExpr,
    right: TypedExpr,
    opcode: i8,
) -> Result<TypedExpr, TyperError> {
    // Map opcode -> op symbol (SigmaTyper.scala:470-476).  Unknown opcodes fall to
    // the §1.25 fallthrough in Scala (no matching ArithOp arm).
    let op = match opcode {
        ARITH_MINUS => "-",
        ARITH_PLUS => "+",
        ARITH_MULTIPLY => "*",
        ARITH_MODULO => "%",
        ARITH_DIVISION => "/",
        ARITH_MIN => "min",
        ARITH_MAX => "max",
        _ => {
            return Err(TyperError::typer(format!(
                "Don't know how to assignType(ArithOp opcode {opcode})"
            )))
        }
    };
    // mk*: arith_op (upcast, no constraint) then ArithOp; tpe = left.tpe post-upcast.
    bimap(
        env,
        ctx,
        op,
        left,
        right,
        move |l, r| {
            let (l, r) = arith_op(l, r)?;
            let tpe = node_tpe(&l).clone();
            Ok(TypedExpr::ArithOp {
                left: Box::new(l),
                right: Box::new(r),
                opcode,
                tpe,
            })
        },
        tt(),
        tt(),
    )
}

pub(crate) fn assign_bitop(
    env: &TypeEnv,
    ctx: &TyperCtx,
    left: TypedExpr,
    right: TypedExpr,
    opcode: i8,
) -> Result<TypedExpr, TyperError> {
    let op = match opcode {
        BIT_OR => "|",
        BIT_AND => "&",
        BIT_XOR => "^",
        _ => {
            return Err(TyperError::typer(format!(
                "Don't know how to assignType(BitOp opcode {opcode})"
            )))
        }
    };
    // mkBitOr/And/Xor build BitOp DIRECTLY — NO upcast (SigmaBuilder.scala:630-637;
    // oracle: `1 | 2L` -> BitOp:Int with a Long operand).  tpe = left.tpe.
    bimap(
        env,
        ctx,
        op,
        left,
        right,
        move |l, r| {
            let tpe = node_tpe(&l).clone();
            Ok(TypedExpr::BitOp {
                left: Box::new(l),
                right: Box::new(r),
                opcode,
                tpe,
            })
        },
        tt(),
        tt(),
    )
}

// ----- relation / equality node builders (the builder-op layer, §3) -----

pub(crate) enum RelOp {
    Ge,
    Le,
    Gt,
    Lt,
}

/// `comparisonOp` (OnlyNumeric -> upcast -> SameType) then the relation node.
pub(crate) fn build_relation(
    l: TypedExpr,
    r: TypedExpr,
    op: RelOp,
) -> Result<TypedExpr, BuildError> {
    let (l, r) = comparison_op(l, r)?;
    let (left, right) = (Box::new(l), Box::new(r));
    let tpe = SType::SBoolean;
    Ok(match op {
        RelOp::Ge => TypedExpr::GE { left, right, tpe },
        RelOp::Le => TypedExpr::LE { left, right, tpe },
        RelOp::Gt => TypedExpr::GT { left, right, tpe },
        RelOp::Lt => TypedExpr::LT { left, right, tpe },
    })
}

/// `equalityOp` (upcast -> SameType) then EQ/NEQ.
pub(crate) fn build_equality(
    l: TypedExpr,
    r: TypedExpr,
    is_eq: bool,
) -> Result<TypedExpr, BuildError> {
    let (l, r) = equality_op(l, r)?;
    let (left, right) = (Box::new(l), Box::new(r));
    let tpe = SType::SBoolean;
    Ok(if is_eq {
        TypedExpr::EQ { left, right, tpe }
    } else {
        TypedExpr::NEQ { left, right, tpe }
    })
}
