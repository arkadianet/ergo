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

    /// Parse-time type approximation used ONLY by the mk_unary_op/mk_binary_op
    /// numeric guards (`isNumTypeOrNoType`, SigmaParser.scala:55/61/85/91).
    /// Constants know their type; Ident/Select/Apply/etc. are NoType at parse
    /// time, which PASSES the guard — mirror exactly:
    /// IntConst/LongConst -> num; BoolConst -> SBoolean (fails num guard);
    /// StringConst -> SString (fails); UnitConst -> SUnit (fails);
    /// everything else -> NoType (passes).
    pub fn is_num_type_or_no_type(&self) -> bool {
        match self {
            Expr::IntConst { .. } | Expr::LongConst { .. } => true,
            Expr::BoolConst { .. } => false,
            Expr::StringConst { .. } => false,
            Expr::UnitConst { .. } => false,
            // Everything else has NoType at parse time, passes guard
            _ => true,
        }
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
