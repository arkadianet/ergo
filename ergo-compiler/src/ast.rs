//! Untyped AST produced by the parser. One variant per node the Scala parser
//! can emit (sigma.ast values.scala, frontend nodes with opCode=Undefined plus
//! the surviving constant/op nodes). Distinct from the ergo-ser opcode IR by
//! design (design doc §6): this is a semantic tree with names and spans.

use crate::span::Pos;
use crate::stype::SType;

/// `val name (: T)? = body` binding (values.scala:1146 ValNode).
#[derive(Debug, Clone, PartialEq)]
pub struct ValDef {
    pub name: String,
    pub given_type: SType, // NoType when unascribed (SigmaParser.scala:26-30)
    pub body: Expr,
    pub pos: Pos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithKind {
    Minus,
    Divide,
    Modulo,
} // trees.scala:704 ArithOp opcodes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitKind {
    Or,
    And,
} // trees.scala:911 BitOp

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelKind {
    Eq,
    Neq,
    Ge,
    Gt,
    Le,
    Lt,
} // trees.scala:1090-1221

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    // ----- constants (values already validated by the lexer/parser) -----
    IntConst {
        value: i32,
        pos: Pos,
    }, // Literals.scala:106-116, default Int
    LongConst {
        value: i64,
        pos: Pos,
    }, // suffix L/l
    BoolConst {
        value: bool,
        pos: Pos,
    }, // Literals.scala:72-77
    /// Raw captured string with only delimiting `"` stripped — escapes are NOT
    /// decoded (Literals.scala:119-124). Also carries the `null`, `'c'`, `'sym`
    /// and id-prefixed-string quirk forms (recon-lexical.md §4-5).
    StringConst {
        value: String,
        pos: Pos,
    },
    UnitConst {
        pos: Pos,
    }, // SigmaBuilder.scala:652

    // ----- frontend nodes (eliminated by binder/typer in M2+) -----
    Ident {
        name: String,
        tpe: SType,
        pos: Pos,
    }, // values.scala:1192; tpe=NoType
    // except the ZKProof callee
    Select {
        obj: Box<Expr>,
        field: String,
        pos: Pos,
    }, // values.scala:1165
    Apply {
        func: Box<Expr>,
        args: Vec<Expr>,
        pos: Pos,
    }, // values.scala:1213
    ApplyTypes {
        input: Box<Expr>,
        type_args: Vec<SType>,
        pos: Pos,
    }, // values.scala:1257
    MethodCallLike {
        obj: Box<Expr>,
        name: String,
        args: Vec<Expr>,
        pos: Pos,
    }, // values.scala:1282
    Lambda {
        args: Vec<(String, SType)>, // NoType when unascribed
        given_res_type: SType,      // NoType except `def f(...): R`
        body: Box<Expr>,
        pos: Pos,
    }, // values.scala:1395; tpeParams always empty
    Val(Box<ValDef>), // a `val`/`def` in statement position
    Block {
        bindings: Vec<ValDef>,
        result: Box<Expr>,
        pos: Pos,
    }, // values.scala:1079
    Tuple {
        items: Vec<Expr>,
        pos: Pos,
    }, // values.scala:778
    If {
        condition: Box<Expr>,
        true_branch: Box<Expr>,
        false_branch: Box<Expr>,
        pos: Pos,
    },

    // ----- operation nodes built by mk_unary_op / mk_binary_op -----
    LogicalNot {
        input: Box<Expr>,
        pos: Pos,
    }, // trees.scala:1378
    Negation {
        input: Box<Expr>,
        pos: Pos,
    }, // trees.scala:881
    BitInversion {
        input: Box<Expr>,
        pos: Pos,
    }, // trees.scala:899
    Relation {
        kind: RelKind,
        left: Box<Expr>,
        right: Box<Expr>,
        pos: Pos,
    },
    ArithOp {
        kind: ArithKind,
        left: Box<Expr>,
        right: Box<Expr>,
        pos: Pos,
    },
    BitOp {
        kind: BitKind,
        left: Box<Expr>,
        right: Box<Expr>,
        pos: Pos,
    },
}

/// `SNumericType` membership (SType.scala:412-547): Byte, Short, Int, Long,
/// BigInt, UnsignedBigInt. Mirrors `isNumType` (package.scala:133).
fn is_numeric(t: &SType) -> bool {
    matches!(
        t,
        SType::SByte
            | SType::SShort
            | SType::SInt
            | SType::SLong
            | SType::SBigInt
            | SType::SUnsignedBigInt
    )
}

/// Scala's `SType.?:` (values.scala:1152/1406): `given` unless it is `NoType`,
/// otherwise the lazily-computed fallback.
fn or_no_type(given: &SType, fallback: impl FnOnce() -> SType) -> SType {
    if *given == SType::NoType {
        fallback()
    } else {
        given.clone()
    }
}

impl Expr {
    /// The node's source position (every node has one —
    /// SigmaParserTest `assertSrcCtxForAllNodes`, LangTests.scala).
    pub fn pos(&self) -> Pos {
        match self {
            Expr::IntConst { pos, .. } => *pos,
            Expr::LongConst { pos, .. } => *pos,
            Expr::BoolConst { pos, .. } => *pos,
            Expr::StringConst { pos, .. } => *pos,
            Expr::UnitConst { pos } => *pos,
            Expr::Ident { pos, .. } => *pos,
            Expr::Select { pos, .. } => *pos,
            Expr::Apply { pos, .. } => *pos,
            Expr::ApplyTypes { pos, .. } => *pos,
            Expr::MethodCallLike { pos, .. } => *pos,
            Expr::Lambda { pos, .. } => *pos,
            Expr::Val(val_def) => val_def.pos,
            Expr::Block { pos, .. } => *pos,
            Expr::Tuple { pos, .. } => *pos,
            Expr::If { pos, .. } => *pos,
            Expr::LogicalNot { pos, .. } => *pos,
            Expr::Negation { pos, .. } => *pos,
            Expr::BitInversion { pos, .. } => *pos,
            Expr::Relation { pos, .. } => *pos,
            Expr::ArithOp { pos, .. } => *pos,
            Expr::BitOp { pos, .. } => *pos,
        }
    }

    /// The parse-time node type, mirroring the Scala frontend AST `tpe`
    /// definitions EXACTLY (paths under `sigmastate-interpreter/.../sigma/ast/`).
    /// The `mkUnaryOp`/`mkBinaryOp` numeric guards (SigmaParser.scala:44/55/61/
    /// 85/91) read `arg.tpe`, and the reference nodes carry a DERIVED type — not
    /// a blanket `NoType` — so an approximation that treats every non-constant as
    /// `NoType` wrongly accepts e.g. `-(1 == 2)` (a Relation is `SBoolean`, not
    /// `NoType`). Each arm cites the mirrored Scala `tpe`:
    ///
    /// - `IntConst`/`LongConst`/`BoolConst`/`StringConst`/`UnitConst` — the
    ///   constant's own type (Literals.scala:72-124, SigmaBuilder.scala:652).
    /// - `Ident` — its `tpe` field (values.scala:1192; `NoType` except the
    ///   ZKProof callee, which carries `SFunc`).
    /// - `Select` — `resType.getOrElse(obj.tpe match { SProduct => method-lookup;
    ///   _ => NoType })` (values.scala:1171-1178). At parse time `resType` is
    ///   `None` and `obj.tpe` is `NoType` for every identifier-rooted object
    ///   (the only realistic parse-time object), so the fallback yields `NoType`;
    ///   the `SProduct` method-lookup branch is deferred to the typer and left as
    ///   `NoType` here (never a false-reject — `NoType` always passes the guard).
    /// - `Apply` — `func.tpe match { SFunc => range; SColl => elem; _ => NoType }`
    ///   (values.scala:1218-1222).
    /// - `ApplyTypes` — `input.tpe` (values.scala:1262-1267; `applySubst` on an
    ///   `SFunc` stays an `SFunc`, so the numeric/NoType classification of
    ///   `input` is preserved).
    /// - `MethodCallLike` — `NoType` default (values.scala:1282).
    /// - `Lambda` — `SFunc(args, givenResType ?: body.tpe)` (values.scala:1404-1407).
    /// - `Val`/`ValNode` — `givenType ?: body.tpe` (values.scala:1152).
    /// - `Block` — `result.tpe` (values.scala:1082).
    /// - `Tuple` — `STuple(items.map(_.tpe))` (values.scala:783).
    /// - `If` — `trueBranch.tpe` (trees.scala:1348-1351).
    /// - `LogicalNot` — `SBoolean` (trees.scala:1378).
    /// - `Negation`/`BitInversion` — `input.tpe` (trees.scala:881-884/899-902).
    /// - `Relation` — `SBoolean` (trees.scala:1072-1073, `NotReadyValueBoolean`).
    /// - `ArithOp` — `left.tpe` (trees.scala:704-707).
    /// - `BitOp` — `left.tpe` (trees.scala:911-915).
    pub fn parse_tpe(&self) -> SType {
        match self {
            Expr::IntConst { .. } => SType::SInt,
            Expr::LongConst { .. } => SType::SLong,
            Expr::BoolConst { .. } => SType::SBoolean,
            Expr::StringConst { .. } => SType::SString,
            Expr::UnitConst { .. } => SType::SUnit,
            Expr::Ident { tpe, .. } => tpe.clone(),
            Expr::Select { .. } => SType::NoType,
            Expr::Apply { func, .. } => match func.parse_tpe() {
                SType::SFunc { range, .. } => *range,
                SType::SColl(elem) => *elem,
                _ => SType::NoType,
            },
            Expr::ApplyTypes { input, .. } => input.parse_tpe(),
            Expr::MethodCallLike { .. } => SType::NoType,
            Expr::Lambda {
                args,
                given_res_type,
                body,
                ..
            } => SType::SFunc {
                dom: args.iter().map(|(_, t)| t.clone()).collect(),
                range: Box::new(or_no_type(given_res_type, || body.parse_tpe())),
            },
            Expr::Val(val_def) => or_no_type(&val_def.given_type, || val_def.body.parse_tpe()),
            Expr::Block { result, .. } => result.parse_tpe(),
            Expr::Tuple { items, .. } => SType::STuple(items.iter().map(Expr::parse_tpe).collect()),
            Expr::If { true_branch, .. } => true_branch.parse_tpe(),
            Expr::LogicalNot { .. } => SType::SBoolean,
            Expr::Negation { input, .. } => input.parse_tpe(),
            Expr::BitInversion { input, .. } => input.parse_tpe(),
            Expr::Relation { .. } => SType::SBoolean,
            Expr::ArithOp { left, .. } => left.parse_tpe(),
            Expr::BitOp { left, .. } => left.parse_tpe(),
        }
    }

    /// The `isNumTypeOrNoType` guard (package.scala:139): the node's parse-time
    /// type is numeric (`SNumericType`: Byte/Short/Int/Long/BigInt/UnsignedBigInt,
    /// SType.scala:412-547) or `NoType`. Used by `mk_unary_op`/`mk_binary_op` for
    /// `-`/`~`/`|`/`&`.
    pub fn is_num_type_or_no_type(&self) -> bool {
        let t = self.parse_tpe();
        is_numeric(&t) || t == SType::NoType
    }

    /// True only for IntConst/LongConst — the mkUnaryOp "-" constant-fold guard
    /// (`isInstanceOf[Constant] && tpe.isNumType`, SigmaParser.scala:43).
    pub fn is_numeric_constant(&self) -> bool {
        matches!(self, Expr::IntConst { .. } | Expr::LongConst { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----
    fn make_pos(offset: u32) -> Pos {
        offset
    }

    // ----- happy path -----
    #[test]
    fn int_const_construction_and_pos() {
        let expr = Expr::IntConst {
            value: 42,
            pos: make_pos(10),
        };
        assert_eq!(expr.pos(), 10);
    }

    #[test]
    fn long_const_construction_and_pos() {
        let expr = Expr::LongConst {
            value: 9223372036854775807i64,
            pos: make_pos(20),
        };
        assert_eq!(expr.pos(), 20);
    }

    #[test]
    fn bool_const_construction_and_pos() {
        let expr = Expr::BoolConst {
            value: true,
            pos: make_pos(5),
        };
        assert_eq!(expr.pos(), 5);
    }

    #[test]
    fn string_const_construction_and_pos() {
        let expr = Expr::StringConst {
            value: "hello".to_string(),
            pos: make_pos(15),
        };
        assert_eq!(expr.pos(), 15);
    }

    #[test]
    fn unit_const_construction_and_pos() {
        let expr = Expr::UnitConst { pos: make_pos(8) };
        assert_eq!(expr.pos(), 8);
    }

    #[test]
    fn ident_construction_and_pos() {
        let expr = Expr::Ident {
            name: "x".to_string(),
            tpe: SType::NoType,
            pos: make_pos(25),
        };
        assert_eq!(expr.pos(), 25);
    }

    #[test]
    fn lambda_construction_and_pos() {
        let expr = Expr::Lambda {
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::NoType,
            body: Box::new(Expr::Ident {
                name: "x".to_string(),
                tpe: SType::NoType,
                pos: make_pos(30),
            }),
            pos: make_pos(28),
        };
        assert_eq!(expr.pos(), 28);
    }

    #[test]
    fn block_construction_and_pos() {
        let val_def = ValDef {
            name: "x".to_string(),
            given_type: SType::SInt,
            body: Expr::IntConst {
                value: 5,
                pos: make_pos(35),
            },
            pos: make_pos(32),
        };
        let expr = Expr::Block {
            bindings: vec![val_def],
            result: Box::new(Expr::Ident {
                name: "x".to_string(),
                tpe: SType::NoType,
                pos: make_pos(40),
            }),
            pos: make_pos(31),
        };
        assert_eq!(expr.pos(), 31);
    }

    #[test]
    fn val_expr_construction_and_pos() {
        let val_def = ValDef {
            name: "y".to_string(),
            given_type: SType::SLong,
            body: Expr::LongConst {
                value: 100i64,
                pos: make_pos(50),
            },
            pos: make_pos(45),
        };
        let expr = Expr::Val(Box::new(val_def));
        assert_eq!(expr.pos(), 45);
    }

    #[test]
    fn if_expr_construction_and_pos() {
        let expr = Expr::If {
            condition: Box::new(Expr::BoolConst {
                value: true,
                pos: make_pos(60),
            }),
            true_branch: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(65),
            }),
            false_branch: Box::new(Expr::IntConst {
                value: 0,
                pos: make_pos(70),
            }),
            pos: make_pos(55),
        };
        assert_eq!(expr.pos(), 55);
    }

    #[test]
    fn select_construction_and_pos() {
        let expr = Expr::Select {
            obj: Box::new(Expr::Ident {
                name: "obj".to_string(),
                tpe: SType::NoType,
                pos: make_pos(75),
            }),
            field: "field".to_string(),
            pos: make_pos(72),
        };
        assert_eq!(expr.pos(), 72);
    }

    #[test]
    fn apply_construction_and_pos() {
        let expr = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".to_string(),
                tpe: SType::NoType,
                pos: make_pos(82),
            }),
            args: vec![Expr::IntConst {
                value: 1,
                pos: make_pos(85),
            }],
            pos: make_pos(80),
        };
        assert_eq!(expr.pos(), 80);
    }

    #[test]
    fn is_num_type_or_no_type_int_const() {
        let expr = Expr::IntConst {
            value: 42,
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type());
    }

    #[test]
    fn is_num_type_or_no_type_long_const() {
        let expr = Expr::LongConst {
            value: 42i64,
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type());
    }

    #[test]
    fn is_num_type_or_no_type_bool_const_false() {
        let expr = Expr::BoolConst {
            value: false,
            pos: make_pos(0),
        };
        assert!(!expr.is_num_type_or_no_type());
    }

    #[test]
    fn is_num_type_or_no_type_string_const_false() {
        let expr = Expr::StringConst {
            value: "test".to_string(),
            pos: make_pos(0),
        };
        assert!(!expr.is_num_type_or_no_type());
    }

    #[test]
    fn is_num_type_or_no_type_unit_const_false() {
        let expr = Expr::UnitConst { pos: make_pos(0) };
        assert!(!expr.is_num_type_or_no_type());
    }

    #[test]
    fn is_num_type_or_no_type_ident_true() {
        let expr = Expr::Ident {
            name: "x".to_string(),
            tpe: SType::NoType,
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type());
    }

    #[test]
    fn is_num_type_or_no_type_apply_true() {
        let expr = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".to_string(),
                tpe: SType::NoType,
                pos: make_pos(1),
            }),
            args: vec![],
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type());
    }

    // ----- parse-time type derivation (parse_tpe) -----

    #[test]
    fn parse_tpe_constants_are_their_own_type() {
        assert_eq!(Expr::IntConst { value: 1, pos: 0 }.parse_tpe(), SType::SInt);
        assert_eq!(
            Expr::LongConst { value: 1, pos: 0 }.parse_tpe(),
            SType::SLong
        );
        assert_eq!(
            Expr::BoolConst {
                value: true,
                pos: 0
            }
            .parse_tpe(),
            SType::SBoolean
        );
        assert_eq!(
            Expr::StringConst {
                value: "s".into(),
                pos: 0
            }
            .parse_tpe(),
            SType::SString
        );
        assert_eq!(Expr::UnitConst { pos: 0 }.parse_tpe(), SType::SUnit);
    }

    #[test]
    fn parse_tpe_relation_and_logical_not_are_sboolean() {
        // trees.scala:1072-1073 (NotReadyValueBoolean), :1378.
        let rel = Expr::Relation {
            kind: RelKind::Eq,
            left: Box::new(Expr::IntConst { value: 1, pos: 0 }),
            right: Box::new(Expr::IntConst { value: 2, pos: 0 }),
            pos: 0,
        };
        assert_eq!(rel.parse_tpe(), SType::SBoolean);
        assert!(!rel.is_num_type_or_no_type()); // SBoolean fails the numeric guard
        let not = Expr::LogicalNot {
            input: Box::new(Expr::Ident {
                name: "x".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(not.parse_tpe(), SType::SBoolean);
        assert!(!not.is_num_type_or_no_type());
    }

    #[test]
    fn parse_tpe_tuple_is_stuple_of_item_tpes() {
        // values.scala:783.
        let t = Expr::Tuple {
            items: vec![
                Expr::IntConst { value: 1, pos: 0 },
                Expr::BoolConst {
                    value: true,
                    pos: 0,
                },
            ],
            pos: 0,
        };
        assert_eq!(
            t.parse_tpe(),
            SType::STuple(vec![SType::SInt, SType::SBoolean])
        );
        assert!(!t.is_num_type_or_no_type()); // STuple fails the numeric guard
    }

    #[test]
    fn parse_tpe_block_is_result_tpe() {
        // values.scala:1082 — a Block of a NoType result passes the guard, a Block
        // of a numeric/bool result takes that result's type.
        let numeric_result = Expr::Block {
            bindings: vec![],
            result: Box::new(Expr::Ident {
                name: "x".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(numeric_result.parse_tpe(), SType::NoType);
        assert!(numeric_result.is_num_type_or_no_type());
        let bool_result = Expr::Block {
            bindings: vec![],
            result: Box::new(Expr::BoolConst {
                value: true,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(bool_result.parse_tpe(), SType::SBoolean);
        assert!(!bool_result.is_num_type_or_no_type());
    }

    #[test]
    fn parse_tpe_arith_and_if_recurse_into_children() {
        // trees.scala:704-707 (ArithOp -> left.tpe), :1348-1351 (If -> trueBranch.tpe).
        let arith = Expr::ArithOp {
            kind: ArithKind::Minus,
            left: Box::new(Expr::IntConst { value: 1, pos: 0 }),
            right: Box::new(Expr::IntConst { value: 2, pos: 0 }),
            pos: 0,
        };
        assert_eq!(arith.parse_tpe(), SType::SInt);
        assert!(arith.is_num_type_or_no_type());
        let if_bool = Expr::If {
            condition: Box::new(Expr::Ident {
                name: "c".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            true_branch: Box::new(Expr::BoolConst {
                value: true,
                pos: 0,
            }),
            false_branch: Box::new(Expr::BoolConst {
                value: false,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(if_bool.parse_tpe(), SType::SBoolean);
        assert!(!if_bool.is_num_type_or_no_type());
    }

    #[test]
    fn parse_tpe_apply_derives_from_func_range() {
        // values.scala:1218-1222 — Apply of an SFunc callee (the ZKProof Ident)
        // yields the SFunc's range (SBoolean here); an Apply of a NoType callee is
        // NoType.
        let zk = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "ZKProof".into(),
                tpe: SType::SFunc {
                    dom: vec![SType::SSigmaProp],
                    range: Box::new(SType::SBoolean),
                },
                pos: 0,
            }),
            args: vec![Expr::Ident {
                name: "p".into(),
                tpe: SType::NoType,
                pos: 0,
            }],
            pos: 0,
        };
        assert_eq!(zk.parse_tpe(), SType::SBoolean);
        let plain = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            args: vec![],
            pos: 0,
        };
        assert_eq!(plain.parse_tpe(), SType::NoType);
    }

    #[test]
    fn parse_tpe_lambda_is_sfunc() {
        // values.scala:1404-1407.
        let lam = Expr::Lambda {
            args: vec![("x".into(), SType::SInt)],
            given_res_type: SType::NoType,
            body: Box::new(Expr::Ident {
                name: "x".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            pos: 0,
        };
        assert!(matches!(lam.parse_tpe(), SType::SFunc { .. }));
        assert!(!lam.is_num_type_or_no_type());
    }

    #[test]
    fn is_numeric_constant_int_const() {
        let expr = Expr::IntConst {
            value: 42,
            pos: make_pos(0),
        };
        assert!(expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_long_const() {
        let expr = Expr::LongConst {
            value: 100i64,
            pos: make_pos(0),
        };
        assert!(expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_bool_const_false() {
        let expr = Expr::BoolConst {
            value: true,
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_string_const_false() {
        let expr = Expr::StringConst {
            value: "test".to_string(),
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_unit_const_false() {
        let expr = Expr::UnitConst { pos: make_pos(0) };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_ident_false() {
        let expr = Expr::Ident {
            name: "x".to_string(),
            tpe: SType::NoType,
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_apply_false() {
        let expr = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".to_string(),
                tpe: SType::NoType,
                pos: make_pos(1),
            }),
            args: vec![],
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn tuple_construction_and_pos() {
        let expr = Expr::Tuple {
            items: vec![
                Expr::IntConst {
                    value: 1,
                    pos: make_pos(92),
                },
                Expr::IntConst {
                    value: 2,
                    pos: make_pos(95),
                },
            ],
            pos: make_pos(90),
        };
        assert_eq!(expr.pos(), 90);
    }

    #[test]
    fn negation_construction_and_pos() {
        let expr = Expr::Negation {
            input: Box::new(Expr::IntConst {
                value: 5,
                pos: make_pos(102),
            }),
            pos: make_pos(100),
        };
        assert_eq!(expr.pos(), 100);
    }

    #[test]
    fn relation_eq_construction_and_pos() {
        let expr = Expr::Relation {
            kind: RelKind::Eq,
            left: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(110),
            }),
            right: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(115),
            }),
            pos: make_pos(107),
        };
        assert_eq!(expr.pos(), 107);
    }

    #[test]
    fn arith_op_construction_and_pos() {
        let expr = Expr::ArithOp {
            kind: ArithKind::Minus,
            left: Box::new(Expr::IntConst {
                value: 5,
                pos: make_pos(125),
            }),
            right: Box::new(Expr::IntConst {
                value: 3,
                pos: make_pos(130),
            }),
            pos: make_pos(122),
        };
        assert_eq!(expr.pos(), 122);
    }

    #[test]
    fn bit_op_construction_and_pos() {
        let expr = Expr::BitOp {
            kind: BitKind::Or,
            left: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(140),
            }),
            right: Box::new(Expr::IntConst {
                value: 2,
                pos: make_pos(145),
            }),
            pos: make_pos(137),
        };
        assert_eq!(expr.pos(), 137);
    }
}
