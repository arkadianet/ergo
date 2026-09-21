//! Ported `SigmaParserTest` integration suite — the M1 acceptance gate.
//!
//! A production-for-production port of every `property(...)` block of the Scala
//! reference test
//! `REF/parsers/shared/src/test/scala/sigmastate/lang/SigmaParserTest.scala`
//! (sigma-state 6.0.2), driven ONLY through the crate's public API
//! (`ergo_compiler::{parse, parse_type, Expr, SType, ValDef, ...}`). The Scala
//! file is the oracle: expected values are NEVER adjusted to make a test pass.
//!
//! Translation key (SigmaParserTest.scala:69-71, LangTests.scala:18-27):
//! - `and`/`or`/`xor`/`plus`/`++`/`*`/`>>`/`<<`/`>>>` parse to `MethodCallLike`;
//!   `-`/`/`/`%` -> `ArithOp`, `==`/`>`/`>=` -> `Relation`, `&`/`|` -> `BitOp`.
//! - typed idents (`IntIdent`/`BoolIdent`/`GEIdent`/`BigIntIdent`) are the SAME
//!   runtime object as `Ident(name, NoType)` — the type witness comes from the
//!   typer, not the parser — so they all map to `ident(name)` here.
//! - `.asValue[T]`/`.asIntValue` are Scala compile-time casts (identity at
//!   runtime) and are ignored.
//! - predefined-function symbols (`Func.symNoType`) are `Ident(name, NoType)`;
//!   the binder resolves them in M2, so at parse time they are plain idents.
//! - `SByteArray = SColl(SByte)`, `SLongArray = SColl(SLong)`.
//! - tree_version = 3 everywhere.

use ergo_compiler::{parse, parse_type, Expr, SType, ValDef};
use SType::{NoType, SBoolean, SBox, SByte, SGroupElement, SInt, SLong, SShort, SSigmaProp};

// ============================================================================
// Helper prelude (mirrors SigmaParserTest.scala:25-71 + LangTests.scala:18-27).
// ============================================================================

/// `check(src, expected)` — parse succeeds, every node's position is within
/// bounds (our `assertSrcCtxForAllNodes` equivalent), and the position-stripped
/// tree equals `expected`.
fn check(src: &str, expected: Expr) {
    let parsed = parse(src, 3).unwrap_or_else(|e| panic!("parse failed for {src:?}: {e:?}"));
    walk_positions(&parsed, src);
    assert_eq!(strip_pos(&parsed), expected, "source: {src:?}");
}

/// `check_type(src, expected)` — the type grammar (`SigmaParser.parseType`).
fn check_type(src: &str, expected: SType) {
    assert_eq!(
        parse_type(src, 3).unwrap_or_else(|e| panic!("parseType failed for {src:?}: {e:?}")),
        expected,
        "type source: {src:?}"
    );
}

/// `fail_at(src, line, col)` — parse errs AND `error.line_col(src)` equals the
/// Scala-reported `(line, col)` (SigmaParserTest.scala:61-67).
fn fail_at(src: &str, line: u32, col: u32) {
    let e = parse(src, 3).expect_err(&format!("expected parse error for {src:?}"));
    assert_eq!(e.line_col(src), (line, col), "source: {src:?}");
}

/// `reject(src)` — parse errs (no positioned expectation; the Scala
/// `an[ParserException] should be thrownBy parse(...)` form).
fn reject(src: &str) {
    assert!(parse(src, 3).is_err(), "expected parse error for {src:?}");
}

/// `reject_type(src)` — `SigmaParser.parseType` errs (accept/reject parity only).
fn reject_type(src: &str) {
    assert!(
        parse_type(src, 3).is_err(),
        "expected parseType error for {src:?}"
    );
}

/// `accept_type(src)` — `SigmaParser.parseType` succeeds (accept-parity only; used
/// where the exact `SType` shape is not the point).
fn accept_type(src: &str) {
    assert!(
        parse_type(src, 3).is_ok(),
        "expected parseType accept for {src:?}"
    );
}

/// `accept(src)` — parse succeeds (accept-parity only; used where the exact AST
/// is not the point) and every node position is within bounds.
fn accept(src: &str) {
    let parsed = parse(src, 3).unwrap_or_else(|e| panic!("expected accept for {src:?}: {e:?}"));
    walk_positions(&parsed, src);
}

// ----- node constructors (position-free; pos filled with 0) -----

fn int(v: i32) -> Expr {
    Expr::IntConst { value: v, pos: 0 }
}
fn long(v: i64) -> Expr {
    Expr::LongConst { value: v, pos: 0 }
}
fn boolean(v: bool) -> Expr {
    Expr::BoolConst { value: v, pos: 0 }
}
fn string(s: &str) -> Expr {
    Expr::StringConst {
        value: s.into(),
        pos: 0,
    }
}
fn unit() -> Expr {
    Expr::UnitConst { pos: 0 }
}
fn ident(n: &str) -> Expr {
    Expr::Ident {
        name: n.into(),
        tpe: NoType,
        pos: 0,
    }
}
fn tuple(items: Vec<Expr>) -> Expr {
    Expr::Tuple { items, pos: 0 }
}
fn select(obj: Expr, f: &str) -> Expr {
    Expr::Select {
        obj: Box::new(obj),
        field: f.into(),
        pos: 0,
    }
}
fn apply(f: Expr, args: Vec<Expr>) -> Expr {
    Expr::Apply {
        func: Box::new(f),
        args,
        pos: 0,
    }
}
fn apply_types(input: Expr, type_args: Vec<SType>) -> Expr {
    Expr::ApplyTypes {
        input: Box::new(input),
        type_args,
        pos: 0,
    }
}
/// single-arg `MethodCallLike` (the only shape the suite exercises).
fn mcl(obj: Expr, name: &str, arg: Expr) -> Expr {
    Expr::MethodCallLike {
        obj: Box::new(obj),
        name: name.into(),
        args: vec![arg],
        pos: 0,
    }
}
/// zero-arg `MethodCallLike` (trailing PostFix lone id).
fn mcl0(obj: Expr, name: &str) -> Expr {
    Expr::MethodCallLike {
        obj: Box::new(obj),
        name: name.into(),
        args: vec![],
        pos: 0,
    }
}
fn and(l: Expr, r: Expr) -> Expr {
    mcl(l, "&&", r)
}
fn or(l: Expr, r: Expr) -> Expr {
    mcl(l, "||", r)
}
fn xor(l: Expr, r: Expr) -> Expr {
    mcl(l, "^", r)
}
fn plus(l: Expr, r: Expr) -> Expr {
    mcl(l, "+", r)
}
fn minus(l: Expr, r: Expr) -> Expr {
    Expr::ArithOp {
        kind: ergo_compiler::ArithKind::Minus,
        left: Box::new(l),
        right: Box::new(r),
        pos: 0,
    }
}
fn divide(l: Expr, r: Expr) -> Expr {
    Expr::ArithOp {
        kind: ergo_compiler::ArithKind::Divide,
        left: Box::new(l),
        right: Box::new(r),
        pos: 0,
    }
}
fn modulo(l: Expr, r: Expr) -> Expr {
    Expr::ArithOp {
        kind: ergo_compiler::ArithKind::Modulo,
        left: Box::new(l),
        right: Box::new(r),
        pos: 0,
    }
}
fn eq_(l: Expr, r: Expr) -> Expr {
    rel(ergo_compiler::RelKind::Eq, l, r)
}
fn gt(l: Expr, r: Expr) -> Expr {
    rel(ergo_compiler::RelKind::Gt, l, r)
}
fn ge(l: Expr, r: Expr) -> Expr {
    rel(ergo_compiler::RelKind::Ge, l, r)
}
fn lt(l: Expr, r: Expr) -> Expr {
    rel(ergo_compiler::RelKind::Lt, l, r)
}
fn rel(kind: ergo_compiler::RelKind, l: Expr, r: Expr) -> Expr {
    Expr::Relation {
        kind,
        left: Box::new(l),
        right: Box::new(r),
        pos: 0,
    }
}
fn bit_and(l: Expr, r: Expr) -> Expr {
    Expr::BitOp {
        kind: ergo_compiler::BitKind::And,
        left: Box::new(l),
        right: Box::new(r),
        pos: 0,
    }
}
fn bit_or(l: Expr, r: Expr) -> Expr {
    Expr::BitOp {
        kind: ergo_compiler::BitKind::Or,
        left: Box::new(l),
        right: Box::new(r),
        pos: 0,
    }
}
fn negation(input: Expr) -> Expr {
    Expr::Negation {
        input: Box::new(input),
        pos: 0,
    }
}
fn bit_inversion(input: Expr) -> Expr {
    Expr::BitInversion {
        input: Box::new(input),
        pos: 0,
    }
}
fn logical_not(input: Expr) -> Expr {
    Expr::LogicalNot {
        input: Box::new(input),
        pos: 0,
    }
}
fn if_(c: Expr, t: Expr, f: Expr) -> Expr {
    Expr::If {
        condition: Box::new(c),
        true_branch: Box::new(t),
        false_branch: Box::new(f),
        pos: 0,
    }
}
fn lambda(args: Vec<(&str, SType)>, body: Expr) -> Expr {
    lambda_r(args, NoType, body)
}
fn lambda_r(args: Vec<(&str, SType)>, given_res_type: SType, body: Expr) -> Expr {
    Expr::Lambda {
        args: args.into_iter().map(|(n, t)| (n.to_string(), t)).collect(),
        given_res_type,
        body: Box::new(body),
        pos: 0,
    }
}
fn val_def(name: &str, given_type: SType, body: Expr) -> ValDef {
    ValDef {
        name: name.into(),
        given_type,
        body,
        pos: 0,
    }
}
/// a `val`/`def` in statement (block-result) position.
fn val_expr(name: &str, given_type: SType, body: Expr) -> Expr {
    Expr::Val(Box::new(val_def(name, given_type, body)))
}
fn block(bindings: Vec<ValDef>, result: Expr) -> Expr {
    Expr::Block {
        bindings,
        result: Box::new(result),
        pos: 0,
    }
}

// ----- type constructors -----

fn coll(t: SType) -> SType {
    SType::SColl(Box::new(t))
}
fn stuple(ts: Vec<SType>) -> SType {
    SType::STuple(ts)
}
fn tvar(n: &str) -> SType {
    SType::STypeVar(n.into())
}

// ----- position machinery -----

/// `assertSrcCtxForAllNodes` (LangTests.scala:74-81) equivalent: every node
/// carries a source context, so every recorded position is within `[0, len]`.
fn walk_positions(e: &Expr, src: &str) {
    let n = src.len() as u32;
    assert!(
        e.pos() <= n,
        "node pos {} exceeds src len {n} for {src:?}",
        e.pos()
    );
    match e {
        Expr::IntConst { .. }
        | Expr::LongConst { .. }
        | Expr::BoolConst { .. }
        | Expr::StringConst { .. }
        | Expr::UnitConst { .. }
        | Expr::Ident { .. } => {}
        Expr::Select { obj, .. } => walk_positions(obj, src),
        Expr::Apply { func, args, .. } => {
            walk_positions(func, src);
            args.iter().for_each(|a| walk_positions(a, src));
        }
        Expr::ApplyTypes { input, .. } => walk_positions(input, src),
        Expr::MethodCallLike { obj, args, .. } => {
            walk_positions(obj, src);
            args.iter().for_each(|a| walk_positions(a, src));
        }
        Expr::Lambda { body, .. } => walk_positions(body, src),
        Expr::Val(v) => walk_val(v, src),
        Expr::Block {
            bindings, result, ..
        } => {
            bindings.iter().for_each(|b| walk_val(b, src));
            walk_positions(result, src);
        }
        Expr::Tuple { items, .. } => items.iter().for_each(|i| walk_positions(i, src)),
        Expr::If {
            condition,
            true_branch,
            false_branch,
            ..
        } => {
            walk_positions(condition, src);
            walk_positions(true_branch, src);
            walk_positions(false_branch, src);
        }
        Expr::LogicalNot { input, .. }
        | Expr::Negation { input, .. }
        | Expr::BitInversion { input, .. } => walk_positions(input, src),
        Expr::Relation { left, right, .. }
        | Expr::ArithOp { left, right, .. }
        | Expr::BitOp { left, right, .. } => {
            walk_positions(left, src);
            walk_positions(right, src);
        }
    }
}
fn walk_val(v: &ValDef, src: &str) {
    assert!(
        v.pos <= src.len() as u32,
        "val pos {} exceeds src len for {src:?}",
        v.pos
    );
    walk_positions(&v.body, src);
}

/// Reset every position to 0 for shape-only comparison against the helper
/// constructors above (Scala `shouldBe` compares structurally, ignoring pos).
fn strip_pos(e: &Expr) -> Expr {
    match e {
        Expr::IntConst { value, .. } => Expr::IntConst {
            value: *value,
            pos: 0,
        },
        Expr::LongConst { value, .. } => Expr::LongConst {
            value: *value,
            pos: 0,
        },
        Expr::BoolConst { value, .. } => Expr::BoolConst {
            value: *value,
            pos: 0,
        },
        Expr::StringConst { value, .. } => Expr::StringConst {
            value: value.clone(),
            pos: 0,
        },
        Expr::UnitConst { .. } => Expr::UnitConst { pos: 0 },
        Expr::Ident { name, tpe, .. } => Expr::Ident {
            name: name.clone(),
            tpe: tpe.clone(),
            pos: 0,
        },
        Expr::Select { obj, field, .. } => Expr::Select {
            obj: Box::new(strip_pos(obj)),
            field: field.clone(),
            pos: 0,
        },
        Expr::Apply { func, args, .. } => Expr::Apply {
            func: Box::new(strip_pos(func)),
            args: args.iter().map(strip_pos).collect(),
            pos: 0,
        },
        Expr::ApplyTypes {
            input, type_args, ..
        } => Expr::ApplyTypes {
            input: Box::new(strip_pos(input)),
            type_args: type_args.clone(),
            pos: 0,
        },
        Expr::MethodCallLike {
            obj, name, args, ..
        } => Expr::MethodCallLike {
            obj: Box::new(strip_pos(obj)),
            name: name.clone(),
            args: args.iter().map(strip_pos).collect(),
            pos: 0,
        },
        Expr::Lambda {
            args,
            given_res_type,
            body,
            ..
        } => Expr::Lambda {
            args: args.clone(),
            given_res_type: given_res_type.clone(),
            body: Box::new(strip_pos(body)),
            pos: 0,
        },
        Expr::Val(v) => Expr::Val(Box::new(strip_val(v))),
        Expr::Block {
            bindings, result, ..
        } => Expr::Block {
            bindings: bindings.iter().map(strip_val).collect(),
            result: Box::new(strip_pos(result)),
            pos: 0,
        },
        Expr::Tuple { items, .. } => Expr::Tuple {
            items: items.iter().map(strip_pos).collect(),
            pos: 0,
        },
        Expr::If {
            condition,
            true_branch,
            false_branch,
            ..
        } => Expr::If {
            condition: Box::new(strip_pos(condition)),
            true_branch: Box::new(strip_pos(true_branch)),
            false_branch: Box::new(strip_pos(false_branch)),
            pos: 0,
        },
        Expr::LogicalNot { input, .. } => Expr::LogicalNot {
            input: Box::new(strip_pos(input)),
            pos: 0,
        },
        Expr::Negation { input, .. } => Expr::Negation {
            input: Box::new(strip_pos(input)),
            pos: 0,
        },
        Expr::BitInversion { input, .. } => Expr::BitInversion {
            input: Box::new(strip_pos(input)),
            pos: 0,
        },
        Expr::Relation {
            kind, left, right, ..
        } => Expr::Relation {
            kind: *kind,
            left: Box::new(strip_pos(left)),
            right: Box::new(strip_pos(right)),
            pos: 0,
        },
        Expr::ArithOp {
            kind, left, right, ..
        } => Expr::ArithOp {
            kind: *kind,
            left: Box::new(strip_pos(left)),
            right: Box::new(strip_pos(right)),
            pos: 0,
        },
        Expr::BitOp {
            kind, left, right, ..
        } => Expr::BitOp {
            kind: *kind,
            left: Box::new(strip_pos(left)),
            right: Box::new(strip_pos(right)),
            pos: 0,
        },
    }
}
fn strip_val(v: &ValDef) -> ValDef {
    ValDef {
        name: v.name.clone(),
        given_type: v.given_type.clone(),
        body: strip_pos(&v.body),
        pos: 0,
    }
}

// ============================================================================
// Ported properties (SigmaParserTest.scala, top to bottom).
// ============================================================================

#[test]
fn simple_expressions() {
    check("10", int(10)); // :74
    check("-10", int(-10)); // :75
    check("10L", long(10)); // :76
    check("10l", long(10)); // :77
    check("-10L", long(-10)); // :78
    check("0x10", int(0x10)); // :79
    check("0x10L", long(0x10)); // :80
    check("0x10l", long(0x10)); // :81
    check("10L-11L", minus(long(10), long(11))); // :82
    check("(10-11)", minus(int(10), int(11))); // :83
    check("(-10-11)", minus(int(-10), int(11))); // :84
    check("(10+11)", plus(int(10), int(11))); // :85
    check("(10-11) - 12", minus(minus(int(10), int(11)), int(12))); // :86
    check("10   - 11 - 12", minus(minus(int(10), int(11)), int(12))); // :87
    check("10   + 11 + 12", plus(plus(int(10), int(11)), int(12))); // :88
    check(
        "1-2-3-4-5",
        minus(minus(minus(minus(int(1), int(2)), int(3)), int(4)), int(5)),
    ); // :89
    check("10 - 11", minus(int(10), int(11))); // :90
    check("1 / 2", divide(int(1), int(2))); // :91
    check("5 % 2", modulo(int(5), int(2))); // :92
    check("1==1", eq_(int(1), int(1))); // :93
    check("true && true", and(boolean(true), boolean(true))); // :94
    check("true || false", or(boolean(true), boolean(false))); // :95
    check("true ^ false", xor(boolean(true), boolean(false))); // :96
    check(
        "true || (true && false)",
        or(boolean(true), and(boolean(true), boolean(false))),
    ); // :97
    check(
        "true || (true ^ false)",
        or(boolean(true), xor(boolean(true), boolean(false))),
    ); // :98
    check(
        "false || false || false",
        or(or(boolean(false), boolean(false)), boolean(false)),
    ); // :99
    check(
        "false ^ false ^ false",
        xor(xor(boolean(false), boolean(false)), boolean(false)),
    ); // :100
    check(
        "(1>= 0)||(3L >2L)",
        or(ge(int(1), int(0)), gt(long(3), long(2))),
    ); // :101
    check("arr1 ++ arr2", mcl(ident("arr1"), "++", ident("arr2"))); // :102
    check("col1 ++ col2", mcl(ident("col1"), "++", ident("col2"))); // :103
    check(
        "ge.exp(n)",
        apply(select(ident("ge"), "exp"), vec![ident("n")]),
    ); // :104
    check("g1 * g2", mcl(ident("g1"), "*", ident("g2"))); // :105
    check("g1 + g2", plus(ident("g1"), ident("g2"))); // :106
}

#[test]
fn precedence_of_binary_operations() {
    check("1 - 2 - 3", minus(minus(int(1), int(2)), int(3))); // :110
    check("1 + 2 + 3", plus(plus(int(1), int(2)), int(3))); // :111
    check(
        "1 - 2 - 3 - 4",
        minus(minus(minus(int(1), int(2)), int(3)), int(4)),
    ); // :112
    check(
        "1 + 2 + 3 + 4",
        plus(plus(plus(int(1), int(2)), int(3)), int(4)),
    ); // :113
    check(
        "1 == 0 || 3 == 2",
        or(eq_(int(1), int(0)), eq_(int(3), int(2))),
    ); // :114
    check(
        "3 - 2 > 2 - 1",
        gt(minus(int(3), int(2)), minus(int(2), int(1))),
    ); // :115
    check(
        "3 + 2 > 2 + 1",
        gt(plus(int(3), int(2)), plus(int(2), int(1))),
    ); // :116
    check(
        "1 - 2 - 3 > 4 - 5 - 6",
        gt(
            minus(minus(int(1), int(2)), int(3)),
            minus(minus(int(4), int(5)), int(6)),
        ),
    ); // :117
    check(
        "1 + 2 + 3 > 4 + 5 + 6",
        gt(
            plus(plus(int(1), int(2)), int(3)),
            plus(plus(int(4), int(5)), int(6)),
        ),
    ); // :118
    check(
        "1 >= 0 || 3 > 2",
        or(ge(int(1), int(0)), gt(int(3), int(2))),
    ); // :119
    check(
        "2 >= 0 - 1 || 3 - 1 >= 2",
        or(
            ge(int(2), minus(int(0), int(1))),
            ge(minus(int(3), int(1)), int(2)),
        ),
    ); // :120
    check(
        "2 >= 0 + 1 || 3 + 1 >= 2",
        or(
            ge(int(2), plus(int(0), int(1))),
            ge(plus(int(3), int(1)), int(2)),
        ),
    ); // :121
    check(
        "x1 || x2 > x3 - x4 - x5 || x6",
        or(
            or(
                ident("x1"),
                gt(
                    ident("x2"),
                    minus(minus(ident("x3"), ident("x4")), ident("x5")),
                ),
            ),
            ident("x6"),
        ),
    ); // :122
    check(
        "x1 || x2 > x3 - x4",
        or(
            ident("x1"),
            gt(ident("x2"), minus(ident("x3"), ident("x4"))),
        ),
    ); // :128
    check(
        "x1 || x2 > x3 + x4 + x5 || x6",
        or(
            or(
                ident("x1"),
                gt(
                    ident("x2"),
                    plus(plus(ident("x3"), ident("x4")), ident("x5")),
                ),
            ),
            ident("x6"),
        ),
    ); // :132
    check(
        "x1 || x2 > x3 + x4",
        or(ident("x1"), gt(ident("x2"), plus(ident("x3"), ident("x4")))),
    ); // :138
}

#[test]
fn tuple_operations() {
    check("()", unit()); // :145
    check("(1)", int(1)); // :146
    check("(1, 2)", tuple(vec![int(1), int(2)])); // :147
    check("(1, X - 1)", tuple(vec![int(1), minus(ident("X"), int(1))])); // :148
    check("(1, X + 1)", tuple(vec![int(1), plus(ident("X"), int(1))])); // :149
    check("(1, 2, 3)", tuple(vec![int(1), int(2), int(3)])); // :150
    check(
        "(1, 2 - 3, 4)",
        tuple(vec![int(1), minus(int(2), int(3)), int(4)]),
    ); // :151
    check(
        "(1, 2 + 3, 4)",
        tuple(vec![int(1), plus(int(2), int(3)), int(4)]),
    ); // :152
    check("(1, 2L)._1", select(tuple(vec![int(1), long(2)]), "_1")); // :154
    check("(1, 2L)._2", select(tuple(vec![int(1), long(2)]), "_2")); // :155
    check(
        "(1, 2L, 3)._3",
        select(tuple(vec![int(1), long(2), int(3)]), "_3"),
    ); // :156
    check("(1, 2L).size", select(tuple(vec![int(1), long(2)]), "size")); // :159
    check(
        "(1, 2L)(0)",
        apply(tuple(vec![int(1), long(2)]), vec![int(0)]),
    ); // :160
    check(
        "(1, 2L).getOrElse(2, 3)",
        apply(
            select(tuple(vec![int(1), long(2)]), "getOrElse"),
            vec![int(2), int(3)],
        ),
    ); // :161
    check(
        "{ (a: Int) => (1, 2L)(a) }",
        lambda(
            vec![("a", SInt)],
            apply(tuple(vec![int(1), long(2)]), vec![ident("a")]),
        ),
    ); // :162
}

#[test]
fn val_constructs() {
    check(
        "{val X = 10\n3 > 2}\n      ",
        block(vec![val_def("X", NoType, int(10))], gt(int(3), int(2))),
    ); // :166
    check(
        "{val X = 10; 3 > 2}",
        block(vec![val_def("X", NoType, int(10))], gt(int(3), int(2))),
    ); // :171
    check(
        "{val X = 3 - 2; 3 > 2}",
        block(
            vec![val_def("X", NoType, minus(int(3), int(2)))],
            gt(int(3), int(2)),
        ),
    ); // :172
    check(
        "{val X = 3 + 2; 3 > 2}",
        block(
            vec![val_def("X", NoType, plus(int(3), int(2)))],
            gt(int(3), int(2)),
        ),
    ); // :173
    check(
        "{val X = if (true) true else false; false}",
        block(
            vec![val_def(
                "X",
                NoType,
                if_(boolean(true), boolean(true), boolean(false)),
            )],
            boolean(false),
        ),
    ); // :174
    check(
        "{val X = 10\nval Y = 11\nX > Y}\n      ",
        block(
            vec![val_def("X", NoType, int(10)), val_def("Y", NoType, int(11))],
            gt(ident("X"), ident("Y")),
        ),
    ); // :176-182
}

#[test]
fn types() {
    check(
        "{val X: Byte = 10; 3 > 2}",
        block(vec![val_def("X", SByte, int(10))], gt(int(3), int(2))),
    ); // :186
    check(
        "{val X: Int = 10; 3 > 2}",
        block(vec![val_def("X", SInt, int(10))], gt(int(3), int(2))),
    ); // :187
    check(
        "{val X: (Int, Boolean) = (10, true); 3 > 2}",
        block(
            vec![val_def(
                "X",
                stuple(vec![SInt, SBoolean]),
                tuple(vec![int(10), boolean(true)]),
            )],
            gt(int(3), int(2)),
        ),
    ); // :188
    check(
        "{val X: Coll[Int] = Coll(1,2,3); X.size}",
        block(
            vec![val_def(
                "X",
                coll(SInt),
                apply(ident("Coll"), vec![int(1), int(2), int(3)]),
            )],
            select(ident("X"), "size"),
        ),
    ); // :190
    check(
        "{val X: (Coll[Int], Box) = (Coll(1,2,3), INPUT); X._1}",
        block(
            vec![val_def(
                "X",
                stuple(vec![coll(SInt), SBox]),
                tuple(vec![
                    apply(ident("Coll"), vec![int(1), int(2), int(3)]),
                    ident("INPUT"),
                ]),
            )],
            select(ident("X"), "_1"),
        ),
    ); // :193
}

#[test]
fn multiline() {
    check("\n\nfalse\n\n\n      ", boolean(false)); // :199-205
    check(
        "{val X = 10;\n\ntrue}\n      ",
        block(vec![val_def("X", NoType, int(10))], boolean(true)),
    ); // :207-211
    check(
        "{val X = 11\ntrue}\n      ",
        block(vec![val_def("X", NoType, int(11))], boolean(true)),
    ); // :212-215
}

#[test]
fn comments() {
    let src = "{\n// line comment\nval X = 12\n/* comment // nested line comment\n*/\n3 - // end line comment\n  2\n}\n      ";
    check(
        src,
        block(vec![val_def("X", NoType, int(12))], minus(int(3), int(2))),
    ); // :219-228
}

#[test]
fn if_property() {
    check("if(true) 1 else 2", if_(boolean(true), int(1), int(2))); // :232
    check(
        "if(true) 1 else if(X==Y) 2 else 3",
        if_(
            boolean(true),
            int(1),
            if_(eq_(ident("X"), ident("Y")), int(2), int(3)),
        ),
    ); // :233
    check(
        "if ( true )\n1\nelse if(X== Y)\n     2\n     else 3",
        if_(
            boolean(true),
            int(1),
            if_(eq_(ident("X"), ident("Y")), int(2), int(3)),
        ),
    ); // :234-239
    check(
        "if (true) false else false==false",
        if_(
            boolean(true),
            boolean(false),
            eq_(boolean(false), boolean(false)),
        ),
    ); // :241
    check(
        "if\n\n             (true)\n{ val A = 10;\n  1 }\nelse if ( X == Y) 2 else 3",
        if_(
            boolean(true),
            block(vec![val_def("A", NoType, int(10))], int(1)),
            if_(eq_(ident("X"), ident("Y")), int(2), int(3)),
        ),
    ); // :243-253
}

#[test]
fn array_literals() {
    let empty_coll = || apply(ident("Coll"), vec![]);
    let empty_coll2 = || apply(ident("Coll"), vec![empty_coll()]);
    check("Coll()", empty_coll()); // :259
    check("Coll(Coll())", empty_coll2()); // :261
    check(
        "Coll(Coll(Coll()))",
        apply(ident("Coll"), vec![empty_coll2()]),
    ); // :262
    check("Coll(1)", apply(ident("Coll"), vec![int(1)])); // :264
    check("Coll(1, X)", apply(ident("Coll"), vec![int(1), ident("X")])); // :265
    check(
        "Coll(1, X - 1, Coll())",
        apply(
            ident("Coll"),
            vec![int(1), minus(ident("X"), int(1)), empty_coll()],
        ),
    ); // :266
    check(
        "Coll(1, X + 1, Coll())",
        apply(
            ident("Coll"),
            vec![int(1), plus(ident("X"), int(1)), empty_coll()],
        ),
    ); // :272
    check(
        "Coll(Coll(X - 1))",
        apply(
            ident("Coll"),
            vec![apply(ident("Coll"), vec![minus(ident("X"), int(1))])],
        ),
    ); // :278
    check(
        "Coll(Coll(X + 1))",
        apply(
            ident("Coll"),
            vec![apply(ident("Coll"), vec![plus(ident("X"), int(1))])],
        ),
    ); // :281
}

#[test]
fn option_constructors() {
    check("None", ident("None")); // :287
    check("Some(None)", apply(ident("Some"), vec![ident("None")])); // :288
    check("Some(10)", apply(ident("Some"), vec![int(10)])); // :289
    check("Some(X)", apply(ident("Some"), vec![ident("X")])); // :290
    check(
        "Some(Some(X - 1))",
        apply(
            ident("Some"),
            vec![apply(ident("Some"), vec![minus(ident("X"), int(1))])],
        ),
    ); // :291
    check(
        "Some(Some(X + 1))",
        apply(
            ident("Some"),
            vec![apply(ident("Some"), vec![plus(ident("X"), int(1))])],
        ),
    ); // :294
}

#[test]
fn array_indexed_access() {
    check("Coll()", apply(ident("Coll"), vec![])); // :300
    check(
        "Array()(0)",
        apply(apply(ident("Array"), vec![]), vec![int(0)]),
    ); // :301
    check(
        "Array()(0)(0)",
        apply(
            apply(apply(ident("Array"), vec![]), vec![int(0)]),
            vec![int(0)],
        ),
    ); // :302
}

#[test]
fn array_indexed_access_with_default_values() {
    check(
        "Array()(0, 1)",
        apply(apply(ident("Array"), vec![]), vec![int(0), int(1)]),
    ); // :306
    check(
        "Array()(0, 1)(0)",
        apply(
            apply(apply(ident("Array"), vec![]), vec![int(0), int(1)]),
            vec![int(0)],
        ),
    ); // :308
}

#[test]
fn generic_methods_of_arrays() {
    check(
        "OUTPUTS.map({ (out: Box) => out.value })",
        apply(
            select(ident("OUTPUTS"), "map"),
            vec![lambda(vec![("out", SBox)], select(ident("out"), "value"))],
        ),
    ); // :315
    check(
        "OUTPUTS.exists({ (out: Box) => out.value > 0 })",
        apply(
            select(ident("OUTPUTS"), "exists"),
            vec![lambda(
                vec![("out", SBox)],
                gt(select(ident("out"), "value"), int(0)),
            )],
        ),
    ); // :318
    check(
        "OUTPUTS.forall({ (out: Box) => out.value > 0 })",
        apply(
            select(ident("OUTPUTS"), "forall"),
            vec![lambda(
                vec![("out", SBox)],
                gt(select(ident("out"), "value"), int(0)),
            )],
        ),
    ); // :321
    check(
        "Array(1,2).fold(0, { (n1: Int, n2: Int) => n1 - n2 })",
        apply(
            select(apply(ident("Array"), vec![int(1), int(2)]), "fold"),
            vec![
                int(0),
                lambda(
                    vec![("n1", SInt), ("n2", SInt)],
                    minus(ident("n1"), ident("n2")),
                ),
            ],
        ),
    ); // :324
    check(
        "Array(1,2).fold(0, { (n1: Int, n2: Int) => n1 + n2 })",
        apply(
            select(apply(ident("Array"), vec![int(1), int(2)]), "fold"),
            vec![
                int(0),
                lambda(
                    vec![("n1", SInt), ("n2", SInt)],
                    plus(ident("n1"), ident("n2")),
                ),
            ],
        ),
    ); // :329
    check(
        "OUTPUTS.slice(0, 10)",
        apply(select(ident("OUTPUTS"), "slice"), vec![int(0), int(10)]),
    ); // :334
    check(
        "OUTPUTS.filter({ (out: Box) => out.value > 0 })",
        apply(
            select(ident("OUTPUTS"), "filter"),
            vec![lambda(
                vec![("out", SBox)],
                gt(select(ident("out"), "value"), int(0)),
            )],
        ),
    ); // :336
}

#[test]
fn global_functions() {
    check("f(x)", apply(ident("f"), vec![ident("x")])); // :342
    check(
        "f((x, y))",
        apply(ident("f"), vec![tuple(vec![ident("x"), ident("y")])]),
    ); // :343
    check("f(x, y)", apply(ident("f"), vec![ident("x"), ident("y")])); // :344
    check(
        "f(x, y).size",
        select(apply(ident("f"), vec![ident("x"), ident("y")]), "size"),
    ); // :345
    check(
        "f(x, y).get(1)",
        apply(
            select(apply(ident("f"), vec![ident("x"), ident("y")]), "get"),
            vec![int(1)],
        ),
    ); // :346
    check(
        "{val y = f(x); y}",
        block(
            vec![val_def("y", NoType, apply(ident("f"), vec![ident("x")]))],
            ident("y"),
        ),
    ); // :347
    check(
        "getVar[Coll[Byte]](10).get",
        select(
            apply(
                apply_types(ident("getVar"), vec![coll(SByte)]),
                vec![int(10)],
            ),
            "get",
        ),
    ); // :348
    check(
        "min(x, y)",
        apply(ident("min"), vec![ident("x"), ident("y")]),
    ); // :349
    check("min(1, 2)", apply(ident("min"), vec![int(1), int(2)])); // :350
    check(
        "max(x, y)",
        apply(ident("max"), vec![ident("x"), ident("y")]),
    ); // :351
    check("max(1, 2)", apply(ident("max"), vec![int(1), int(2)])); // :352
}

#[test]
fn lambdas() {
    check(
        "{ (x) => x - 1 }",
        lambda(vec![("x", NoType)], minus(ident("x"), int(1))),
    ); // :356
    check(
        "{ (x: Int) => x - 1 }",
        lambda(vec![("x", SInt)], minus(ident("x"), int(1))),
    ); // :358
    check(
        "{ (x: Int) => x + 1 }",
        lambda(vec![("x", SInt)], plus(ident("x"), int(1))),
    ); // :360
    check(
        "{ (x: Int, box: Box) => x - box.value }",
        lambda_r(
            vec![("x", SInt), ("box", SBox)],
            NoType,
            minus(ident("x"), select(ident("box"), "value")),
        ),
    ); // :366
    check(
        "{ (p: (Int, GroupElement), box: Box) => p._1 > box.value && p._2.isIdentity }",
        lambda_r(
            vec![("p", stuple(vec![SInt, SGroupElement])), ("box", SBox)],
            NoType,
            and(
                gt(select(ident("p"), "_1"), select(ident("box"), "value")),
                select(select(ident("p"), "_2"), "isIdentity"),
            ),
        ),
    ); // :369
    check(
        "{ (p: (Int, SigmaProp), box: Box) => p._1 > box.value && p._2.isProven }",
        lambda_r(
            vec![("p", stuple(vec![SInt, SSigmaProp])), ("box", SBox)],
            NoType,
            and(
                gt(select(ident("p"), "_1"), select(ident("box"), "value")),
                select(select(ident("p"), "_2"), "isProven"),
            ),
        ),
    ); // :376
    check(
        "{ (x: Int) => { x - 1 } }",
        lambda(vec![("x", SInt)], block(vec![], minus(ident("x"), int(1)))),
    ); // :386
    check(
        "{ (x: Int) =>  val y = x - 1; y }",
        lambda(
            vec![("x", SInt)],
            block(
                vec![val_def("y", NoType, minus(ident("x"), int(1)))],
                ident("y"),
            ),
        ),
    ); // :388
    check(
        "{ (x: Int) => { val y = x - 1; y } }",
        lambda(
            vec![("x", SInt)],
            block(
                vec![val_def("y", NoType, minus(ident("x"), int(1)))],
                ident("y"),
            ),
        ),
    ); // :391
    check(
        "{ (x: Int) =>\nval y = x - 1\ny\n}",
        lambda(
            vec![("x", SInt)],
            block(
                vec![val_def("y", NoType, minus(ident("x"), int(1)))],
                ident("y"),
            ),
        ),
    ); // :394-400
}

#[test]
fn passing_a_lambda_argument() {
    let tree = || {
        apply(
            select(ident("arr"), "exists"),
            vec![lambda(vec![("a", SInt)], ge(ident("a"), int(1)))],
        )
    };
    check("arr.exists ({ (a: Int) => a >= 1 })", tree()); // :407
    check("arr.exists { (a: Int) => a >= 1 }", tree()); // :409
    check("arr.exists { (a: Int) =>\na >= 1 }", tree()); // :411-413

    let tree1 = || {
        apply(
            ident("f"),
            vec![lambda(
                vec![("a", SInt)],
                block(
                    vec![val_def("b", NoType, minus(ident("a"), int(1)))],
                    minus(ident("a"), ident("b")),
                ),
            )],
        )
    };
    check("f { (a: Int) => val b = a - 1; a - b }", tree1()); // :420
    check("f { (a: Int) =>\nval b = a - 1\na - b\n}", tree1()); // :422-426

    check(
        "f { (a: Int) =>\ndef g(c: Int) = c - 1\na - g(a)\n}",
        apply(
            ident("f"),
            vec![lambda(
                vec![("a", SInt)],
                block(
                    vec![val_def(
                        "g",
                        NoType,
                        lambda(vec![("c", SInt)], minus(ident("c"), int(1))),
                    )],
                    minus(ident("a"), apply(ident("g"), vec![ident("a")])),
                ),
            )],
        ),
    ); // :429-439
}

#[test]
fn function_definitions_via_val() {
    check(
        "{val f = { (x: Int) => x - 1 }; f}",
        block(
            vec![val_def(
                "f",
                NoType,
                lambda(vec![("x", SInt)], minus(ident("x"), int(1))),
            )],
            ident("f"),
        ),
    ); // :443
    check(
        "{val f = { (x: Int) => x - 1 }\nf}\n      ",
        block(
            vec![val_def(
                "f",
                NoType,
                lambda(vec![("x", SInt)], minus(ident("x"), int(1))),
            )],
            ident("f"),
        ),
    ); // :445-449
}

#[test]
fn function_one_arg_definition_expr_body() {
    check(
        "{ def f(x: Int): Int = x - 1 }",
        block(
            vec![],
            val_expr(
                "f",
                SInt,
                lambda_r(vec![("x", SInt)], SInt, minus(ident("x"), int(1))),
            ),
        ),
    ); // :453
}

#[test]
fn function_one_arg_definition_with_no_res_type_expr_body() {
    check(
        "{ def f(x: Int) = x - 1 }",
        block(
            vec![],
            val_expr(
                "f",
                NoType,
                lambda_r(vec![("x", SInt)], NoType, minus(ident("x"), int(1))),
            ),
        ),
    ); // :458
}

#[test]
fn function_one_arg_definition_brackets_body() {
    let expected = || {
        block(
            vec![],
            val_expr(
                "f",
                SInt,
                lambda_r(
                    vec![("x", SInt)],
                    SInt,
                    block(vec![], minus(ident("x"), int(1))),
                ),
            ),
        )
    };
    check("{ def f(x: Int): Int = { x - 1 } }", expected()); // :465
    check(
        "{\n         def f(x: Int): Int = {\n           x - 1\n         }\n        }\n      ",
        expected(),
    ); // :466-472
}

#[test]
fn function_two_arg_definition_expr_body() {
    check(
        "{ def f(x: Int, y: Int): Int = x - y }",
        block(
            vec![],
            val_expr(
                "f",
                SInt,
                lambda_r(
                    vec![("x", SInt), ("y", SInt)],
                    SInt,
                    minus(ident("x"), ident("y")),
                ),
            ),
        ),
    ); // :476
}

#[test]
fn function_definition_and_application() {
    check(
        "{\n         def f(x: Int): Int = {\n           x - 1\n         }\n         f(5)\n        }\n      ",
        block(
            vec![val_def(
                "f",
                SInt,
                lambda_r(
                    vec![("x", SInt)],
                    SInt,
                    block(vec![], minus(ident("x"), int(1))),
                ),
            )],
            apply(ident("f"), vec![int(5)]),
        ),
    ); // :482-493
}

#[test]
fn function_with_type_args() {
    check(
        "{ def f[A, B](x: A, y: B): (A, B) = (x, y) }",
        block(
            vec![],
            val_expr(
                "f",
                stuple(vec![tvar("A"), tvar("B")]),
                lambda_r(
                    vec![("x", tvar("A")), ("y", tvar("B"))],
                    stuple(vec![tvar("A"), tvar("B")]),
                    tuple(vec![ident("x"), ident("y")]),
                ),
            ),
        ),
    ); // :499-507
}

#[test]
fn function_no_args_definition_expr_body() {
    check(
        "{ def f: Int = 1 }",
        block(vec![], val_expr("f", SInt, lambda_r(vec![], SInt, int(1)))),
    ); // :511
}

#[test]
fn method_extension_dotty_no_args_with_type_args() {
    check(
        "{ def (pairs: Coll[(A,B)]) f[A, B]: Coll[(B, A)] = pairs.magicSwap }",
        block(
            vec![],
            val_expr(
                "f",
                coll(stuple(vec![tvar("B"), tvar("A")])),
                lambda_r(
                    vec![("pairs", coll(stuple(vec![tvar("A"), tvar("B")])))],
                    coll(stuple(vec![tvar("B"), tvar("A")])),
                    select(ident("pairs"), "magicSwap"),
                ),
            ),
        ),
    ); // :518-526
}

#[test]
fn method_extension_dotty_one_arg_with_type_args() {
    check(
        "{ def (pairs: Coll[(A,B)]) take[A, B](i: Int): Coll[(A, B)] = pairs.drop(i) }",
        block(
            vec![],
            val_expr(
                "take",
                coll(stuple(vec![tvar("A"), tvar("B")])),
                lambda_r(
                    vec![
                        ("pairs", coll(stuple(vec![tvar("A"), tvar("B")]))),
                        ("i", SInt),
                    ],
                    coll(stuple(vec![tvar("A"), tvar("B")])),
                    apply(select(ident("pairs"), "drop"), vec![ident("i")]),
                ),
            ),
        ),
    ); // :532-540
}

#[test]
fn get_field_of_ref() {
    check("XXX.YYY", select(ident("XXX"), "YYY")); // :544
    check("\n\n X.Y\n\n      ", select(ident("X"), "Y")); // :545-549
}

#[test]
fn box_properties() {
    check(
        "{ (box: Box) => box.value }",
        lambda_r(vec![("box", SBox)], NoType, select(ident("box"), "value")),
    ); // :553
    check(
        "{ (box: Box) => box.propositionBytes }",
        lambda_r(
            vec![("box", SBox)],
            NoType,
            select(ident("box"), "propositionBytes"),
        ),
    ); // :554
    check(
        "{ (box: Box) => box.bytes }",
        lambda_r(vec![("box", SBox)], NoType, select(ident("box"), "bytes")),
    ); // :555
    check(
        "{ (box: Box) => box.id }",
        lambda_r(vec![("box", SBox)], NoType, select(ident("box"), "id")),
    ); // :556
}

#[test]
fn type_parameters() {
    check("X[Byte]", apply_types(ident("X"), vec![SByte])); // :560
    check("X[Int]", apply_types(ident("X"), vec![SInt])); // :561
    check(
        "X[Int].isDefined",
        select(apply_types(ident("X"), vec![SInt]), "isDefined"),
    ); // :562
    check(
        "X[Int].isEmpty",
        select(apply_types(ident("X"), vec![SInt]), "isEmpty"),
    ); // :563
    check(
        "X[(Int, Boolean)]",
        apply_types(ident("X"), vec![stuple(vec![SInt, SBoolean])]),
    ); // :564
    check(
        "X[Int, Boolean]",
        apply_types(ident("X"), vec![SInt, SBoolean]),
    ); // :565
    check(
        "SELF.R1[Int]",
        apply_types(select(ident("SELF"), "R1"), vec![SInt]),
    ); // :566
    check(
        "SELF.getReg[Int](1)",
        apply(
            apply_types(select(ident("SELF"), "getReg"), vec![SInt]),
            vec![int(1)],
        ),
    ); // :567
    check(
        "SELF.R1[Int].isDefined",
        select(
            apply_types(select(ident("SELF"), "R1"), vec![SInt]),
            "isDefined",
        ),
    ); // :568
    check(
        "SELF.R1[Int].isEmpty",
        select(
            apply_types(select(ident("SELF"), "R1"), vec![SInt]),
            "isEmpty",
        ),
    ); // :569
    check(
        "f[Int](10)",
        apply(apply_types(ident("f"), vec![SInt]), vec![int(10)]),
    ); // :570
    check(
        "INPUTS.map[Int]",
        apply_types(select(ident("INPUTS"), "map"), vec![SInt]),
    ); // :571
    check(
        "INPUTS.map[Int](10)",
        apply(
            apply_types(select(ident("INPUTS"), "map"), vec![SInt]),
            vec![int(10)],
        ),
    ); // :572
    check(
        "Coll[Int]()",
        apply(apply_types(ident("Coll"), vec![SInt]), vec![]),
    ); // :573
}

#[test]
fn type_tests() {
    check_type("Int", SInt); // :577
    check_type("(Int, Long)", stuple(vec![SInt, SLong])); // :578
    check_type("Coll[(Int, Long)]", coll(stuple(vec![SInt, SLong]))); // :579
                                                                      // ErgoBox.STokensRegType = SColl(STuple(SColl(SByte), SLong)).
    check_type(
        "Coll[(Coll[Byte], Long)]",
        coll(stuple(vec![coll(SByte), SLong])),
    ); // :580
    check_type(
        "Coll[(Coll[Byte], Coll[Long])]",
        coll(stuple(vec![coll(SByte), coll(SLong)])),
    ); // :581
    check_type(
        "Coll[(Coll[Byte], (Coll[Long], Long))]",
        coll(stuple(vec![coll(SByte), stuple(vec![coll(SLong), SLong])])),
    ); // :582
}

#[test]
fn negative_tests() {
    fail_at("(10", 1, 4); // :586
    fail_at("10)", 1, 3); // :587
    fail_at("X)", 1, 2); // :588
    fail_at("(X", 1, 3); // :589
    fail_at("{ X", 1, 4); // :590
    fail_at("{ val X", 1, 8); // :591
    fail_at("\"str", 1, 5); // :592
}

#[test]
fn not_yet_supported_lambda_syntax() {
    fail_at("arr.exists ( (a: Int) => a >= 1 )", 1, 16); // :597
    reject("arr.exists ( a => a >= 1 )"); // :599
    reject("arr.exists { a => a >= 1 }"); // :600
}

#[test]
fn numeric_casts() {
    check("1.toByte", select(int(1), "toByte")); // :604
    check("1.toShort", select(int(1), "toShort")); // :605
    check("1L.toInt", select(long(1), "toInt")); // :606
    check("1.toLong", select(int(1), "toLong")); // :607
    check("1.toBigInt", select(int(1), "toBigInt")); // :608
}

#[test]
fn string_literals() {
    check("\"hello\"", string("hello")); // :612
    check("\"\"\"hello\"\"\"", string("hello")); // :614
    check("\"\"\"hel\nlo\"\"\"", string("hel\nlo")); // :616
                                                     // :617-620 — a backslash escape inside a triple-quoted string is rejected;
                                                     // Scala's "Parse Error, Position 1:5" maps to line_col == (1, 5).
    fail_at("\"\"\"h\\el\nlo\"\"\"", 1, 5); // :617
    check(
        " \"hello\" == \"hello\" ",
        eq_(string("hello"), string("hello")),
    ); // :622
}

#[test]
fn string_concat() {
    check(
        " \"hello\" + \"hello\" ",
        mcl(string("hello"), "+", string("hello")),
    ); // :626
}

#[test]
fn bigint_string_decoding() {
    check(
        "bigInt(\"32667486267383620946248345338628674027033885928301927616853987602485119134400\")",
        apply(
            ident("bigInt"),
            vec![string(
                "32667486267383620946248345338628674027033885928301927616853987602485119134400",
            )],
        ),
    ); // :631
}

#[test]
fn from_base_x_string_decoding() {
    check(
        "fromBase16(\"1111\")",
        apply(ident("fromBase16"), vec![string("1111")]),
    ); // :636
    check(
        "fromBase58(\"111\")",
        apply(ident("fromBase58"), vec![string("111")]),
    ); // :637
    check(
        "fromBase64(\"111\")",
        apply(ident("fromBase64"), vec![string("111")]),
    ); // :638
}

#[test]
fn pk() {
    check("PK(\"111\")", apply(ident("PK"), vec![string("111")])); // :642
}

#[test]
fn deserialize() {
    check(
        "deserialize[GroupElement](\"12345\")",
        apply(
            apply_types(ident("deserialize"), vec![SGroupElement]),
            vec![string("12345")],
        ),
    ); // :646
    check(
        "deserialize[(GroupElement, Coll[(Int, Byte)])](\"12345\")",
        apply(
            apply_types(
                ident("deserialize"),
                vec![stuple(vec![SGroupElement, coll(stuple(vec![SInt, SByte]))])],
            ),
            vec![string("12345")],
        ),
    ); // :648
}

#[test]
fn zkproof() {
    // ZKProof discards the block's bindings and applies its result; the callee
    // Ident carries ZKProofFunc's function type (parse.rs:1691-1706).
    let zk_callee = || Expr::Ident {
        name: "ZKProof".into(),
        tpe: SType::SFunc {
            dom: vec![SSigmaProp],
            range: Box::new(SBoolean),
            tpe_params: vec![],
        },
        pos: 0,
    };
    check(
        "ZKProof { condition }",
        apply(zk_callee(), vec![ident("condition")]),
    ); // :653
    check(
        "ZKProof { sigmaProp(HEIGHT > 1000) }",
        apply(
            zk_callee(),
            vec![apply(
                ident("sigmaProp"),
                vec![gt(ident("HEIGHT"), int(1000))],
            )],
        ),
    ); // :654
}

#[test]
fn invalid_zkproof_non_block_parameter() {
    fail_at("ZKProof 1 > 1", 1, 9); // :660
}

#[test]
fn sigma_prop() {
    check(
        "sigmaProp(HEIGHT > 1000)",
        apply(ident("sigmaProp"), vec![gt(ident("HEIGHT"), int(1000))]),
    ); // :664
}

#[test]
fn sbigint_to_bytes() {
    check(
        "10.toBigInt.toBytes",
        select(select(int(10), "toBigInt"), "toBytes"),
    ); // :669
}

#[test]
fn sbigint_mod_q() {
    check(
        "10.toBigInt.modQ",
        select(select(int(10), "toBigInt"), "modQ"),
    ); // :673
}

#[test]
fn sbigint_plus_mod_q() {
    check(
        "10.toBigInt.plusModQ(1.toBigInt)",
        apply(
            select(select(int(10), "toBigInt"), "plusModQ"),
            vec![select(int(1), "toBigInt")],
        ),
    ); // :677
}

#[test]
fn sbigint_minus_mod_q() {
    check(
        "10.toBigInt.minusModQ(1.toBigInt)",
        apply(
            select(select(int(10), "toBigInt"), "minusModQ"),
            vec![select(int(1), "toBigInt")],
        ),
    ); // :682
}

#[test]
fn sbigint_mult_mod_q() {
    check(
        "10.toBigInt.multModQ(1.toBigInt)",
        apply(
            select(select(int(10), "toBigInt"), "multModQ"),
            vec![select(int(1), "toBigInt")],
        ),
    ); // :687
}

#[test]
fn byte_array_to_long() {
    check(
        "byteArrayToLong(Coll[Byte](1.toByte))",
        apply(
            ident("byteArrayToLong"),
            vec![apply(
                apply_types(ident("Coll"), vec![SByte]),
                vec![select(int(1), "toByte")],
            )],
        ),
    ); // :692
}

#[test]
fn decode_point() {
    check(
        "decodePoint(Coll[Byte](1.toByte))",
        apply(
            ident("decodePoint"),
            vec![apply(
                apply_types(ident("Coll"), vec![SByte]),
                vec![select(int(1), "toByte")],
            )],
        ),
    ); // :701
}

#[test]
fn xor_of() {
    check(
        "xorOf(Coll[Boolean](true, false))",
        apply(
            ident("xorOf"),
            vec![apply(
                apply_types(ident("Coll"), vec![SBoolean]),
                vec![boolean(true), boolean(false)],
            )],
        ),
    ); // :710
}

#[test]
fn sboolean_to_byte() {
    check("true.toByte", select(boolean(true), "toByte")); // :719
}

#[test]
fn soption_map() {
    check(
        "Some(1).map { (b: Int) => b}",
        apply(
            select(apply(ident("Some"), vec![int(1)]), "map"),
            vec![lambda(vec![("b", SInt)], ident("b"))],
        ),
    ); // :723
}

#[test]
fn scollection_zip() {
    check(
        "OUTPUTS.zip(Coll(1, 2))",
        apply(
            select(ident("OUTPUTS"), "zip"),
            vec![apply(ident("Coll"), vec![int(1), int(2)])],
        ),
    ); // :729
}

#[test]
fn scollection_zip_with() {
    check(
        "OUTPUTS.zipWith(Coll(1, 2), { (box: Box, i: Int) => i })",
        apply(
            select(ident("OUTPUTS"), "zipWith"),
            vec![
                apply(ident("Coll"), vec![int(1), int(2)]),
                lambda(vec![("box", SBox), ("i", SInt)], ident("i")),
            ],
        ),
    ); // :735
}

#[test]
fn scollection_flat_map() {
    check(
        "OUTPUTS.flatMap({ (box: Box) => Coll(box) })",
        apply(
            select(ident("OUTPUTS"), "flatMap"),
            vec![lambda(
                vec![("box", SBox)],
                apply(ident("Coll"), vec![ident("box")]),
            )],
        ),
    ); // :742
}

#[test]
fn sgroup_element_exp() {
    check(
        "{ (g: GroupElement) => g.exp(1.toBigInt) }",
        lambda_r(
            vec![("g", SGroupElement)],
            NoType,
            apply(select(ident("g"), "exp"), vec![select(int(1), "toBigInt")]),
        ),
    ); // :749
}

#[test]
fn snumeric_to_bytes() {
    check("1.toBytes", select(int(1), "toBytes")); // :756
    check("1L.toBytes", select(long(1), "toBytes")); // :757
}

#[test]
fn snumeric_to_bits() {
    check("1.toBits", select(int(1), "toBits")); // :761
    check("1L.toBits", select(long(1), "toBits")); // :762
}

#[test]
fn snumeric_compare() {
    check(
        "1.compare(2)",
        apply(select(int(1), "compare"), vec![int(2)]),
    ); // :766
}

#[test]
fn numeric_constant_negation() {
    check("-3", int(-3)); // :770
    check("-3.toByte", select(int(-3), "toByte")); // :771
}

#[test]
fn numeric_negation_unary_op() {
    check("-OUTPUTS.size", negation(select(ident("OUTPUTS"), "size"))); // :775
    check("- (3 - 2)", negation(minus(int(3), int(2)))); // :776
}

#[test]
fn bitwise_inversion_unary_op() {
    check(
        "~OUTPUTS.size",
        bit_inversion(select(ident("OUTPUTS"), "size")),
    ); // :780
}

#[test]
fn headers_and_sheader_methods() {
    check("HEADERS", ident("HEADERS")); // :784
    check(
        "HEADERS(0).version",
        select(apply(ident("HEADERS"), vec![int(0)]), "version"),
    ); // :785
    check(
        "HEADERS(0).parentId",
        select(apply(ident("HEADERS"), vec![int(0)]), "parentId"),
    ); // :786
}

#[test]
fn logical_not_unary_op() {
    check("!true", logical_not(boolean(true))); // :790
    check("! (1 == 0)", logical_not(eq_(int(1), int(0)))); // :791
}

#[test]
fn logical_xor() {
    check("true ^ false", mcl(boolean(true), "^", boolean(false))); // :795
}

#[test]
fn bit_and_bitwise_and_for_numeric_types() {
    check("1 & 2", bit_and(int(1), int(2))); // :799
}

#[test]
fn bit_or_bitwise_or_for_numeric_types() {
    check("1 | 2", bit_or(int(1), int(2))); // :803
}

#[test]
fn bit_xor_bitwise_xor_for_numeric_types() {
    check("1 ^ 2", mcl(int(1), "^", int(2))); // :807
}

#[test]
fn bit_shift_right_for_numeric_types() {
    check("128 >> 2", mcl(int(128), ">>", int(2))); // :811
}

#[test]
fn bit_shift_left_for_numeric_types() {
    check("128 << 2", mcl(int(128), "<<", int(2))); // :815
}

#[test]
fn bit_shift_right_zeroed_for_numeric_types() {
    check("128 >>> 2", mcl(int(128), ">>>", int(2))); // :819
}

#[test]
fn coll_shift_right() {
    check(
        "Coll(true, false) >> 2",
        mcl(
            apply(ident("Coll"), vec![boolean(true), boolean(false)]),
            ">>",
            int(2),
        ),
    ); // :823
}

#[test]
fn coll_shift_left() {
    check(
        "Coll(true, false) << 2",
        mcl(
            apply(ident("Coll"), vec![boolean(true), boolean(false)]),
            "<<",
            int(2),
        ),
    ); // :828
}

#[test]
fn coll_shift_right_zeroed() {
    check(
        "Coll(true, false) >>> 2",
        mcl(
            apply(ident("Coll"), vec![boolean(true), boolean(false)]),
            ">>>",
            int(2),
        ),
    ); // :833
}

#[test]
fn coll_rotate_left() {
    check(
        "Coll(true, false).rotateLeft(2)",
        apply(
            select(
                apply(ident("Coll"), vec![boolean(true), boolean(false)]),
                "rotateLeft",
            ),
            vec![int(2)],
        ),
    ); // :838
}

#[test]
fn coll_rotate_right() {
    check(
        "Coll(true, false).rotateRight(2)",
        apply(
            select(
                apply(ident("Coll"), vec![boolean(true), boolean(false)]),
                "rotateRight",
            ),
            vec![int(2)],
        ),
    ); // :843
}

#[test]
fn outer_join() {
    let src = "outerJoin[Byte, Short, Int, Long](\n Coll[(Byte, Short)]((1.toByte, 2.toShort)),\n Coll[(Byte, Int)]((1.toByte, 3.toInt)),\n { (b, s) => (b + s).toLong },\n { (b, i) => (b + i).toLong },\n { (b, s, i) => (b + s + i).toLong }\n )";
    check(
        src,
        apply(
            apply_types(ident("outerJoin"), vec![SByte, SShort, SInt, SLong]),
            vec![
                apply(
                    apply_types(ident("Coll"), vec![stuple(vec![SByte, SShort])]),
                    vec![tuple(vec![
                        select(int(1), "toByte"),
                        select(int(2), "toShort"),
                    ])],
                ),
                apply(
                    apply_types(ident("Coll"), vec![stuple(vec![SByte, SInt])]),
                    vec![tuple(vec![
                        select(int(1), "toByte"),
                        select(int(3), "toInt"),
                    ])],
                ),
                lambda(
                    vec![("b", NoType), ("s", NoType)],
                    select(plus(ident("b"), ident("s")), "toLong"),
                ),
                lambda(
                    vec![("b", NoType), ("i", NoType)],
                    select(plus(ident("b"), ident("i")), "toLong"),
                ),
                lambda(
                    vec![("b", NoType), ("s", NoType), ("i", NoType)],
                    select(plus(plus(ident("b"), ident("s")), ident("i")), "toLong"),
                ),
            ],
        ),
    ); // :848-889
}

#[test]
fn subst_constants() {
    check(
        "substConstants[Long](Coll[Byte](1.toByte), Coll[Int](1), Coll[Long](1L))",
        apply(
            apply_types(ident("substConstants"), vec![SLong]),
            vec![
                apply(
                    apply_types(ident("Coll"), vec![SByte]),
                    vec![select(int(1), "toByte")],
                ),
                apply(apply_types(ident("Coll"), vec![SInt]), vec![int(1)]),
                apply(apply_types(ident("Coll"), vec![SLong]), vec![long(1)]),
            ],
        ),
    ); // :893-900
}

#[test]
fn execute_from_var() {
    check(
        "executeFromVar[Boolean](1)",
        apply(
            apply_types(ident("executeFromVar"), vec![SBoolean]),
            vec![int(1)],
        ),
    ); // :904
}

#[test]
fn serialize() {
    check("serialize(1)", apply(ident("serialize"), vec![int(1)])); // :910
    check(
        "serialize((1, 2L))",
        apply(ident("serialize"), vec![tuple(vec![int(1), long(2)])]),
    ); // :911
    check(
        "serialize(Coll(1, 2, 3))",
        apply(
            ident("serialize"),
            vec![apply(ident("Coll"), vec![int(1), int(2), int(3)])],
        ),
    ); // :913
}

#[test]
fn single_name_pattern_fail() {
    fail_at("{val (a,b) = (1,2)}", 1, 6); // :921
}

#[test]
fn unknown_prefix_in_unary_op() {
    fail_at("+1", 1, 2); // :925
}

#[test]
fn empty_lines_before_invalid_op() {
    fail_at("\n\n\n+1", 4, 2); // :929-933
}

#[test]
fn unknown_binary_op() {
    fail_at("1**1", 1, 1); // :937
}

#[test]
fn compound_types_not_supported() {
    fail_at("Coll[Int with Sortable](1)", 1, 6); // :941
}

#[test]
fn path_types_not_supported() {
    fail_at("Coll[Int.A](1)", 1, 10); // :945
}

#[test]
fn block_contains_non_val_binding_before_expression() {
    fail_at("{1 ; 1 == 1}", 1, 2); // :949
}

// ============================================================================
// Spec-derived quirk set (task brief Step 3; zero SigmaParserTest coverage —
// recon-gap.md item 15). Each carries a spec-derived citation.
// ============================================================================

#[test]
fn quirk_trailing_postfix_lone_id() {
    // spec-derived: Exprs.scala:99-116 — a trailing lone id is a zero-arg
    // PostFix MethodCallLike.
    check("x id", mcl0(ident("x"), "id"));
    // PostFix's `~ Newline.?` (Exprs.scala:100) is left UNCONSUMED (see the round-5
    // fix): a trailing newline after a lone postfix is transparent to the top-level
    // `~ End` (skipped by `peek`), so `x id\n` still yields the bare MethodCallLike.
    check("x id\n", mcl0(ident("x"), "id"));
}

#[test]
fn quirk_backtick_identifier_atom_and_infix_rejection() {
    // spec-derived: Identifiers.scala:36-37 — a backtick id is an atom whose name
    // includes the backticks (span-verbatim, parse.rs:1497-1502).
    check("`foo`", ident("`foo`"));
    // spec-derived: Exprs.scala:92 `Id.!` gives a backtick op precedence 0, which
    // mkBinaryOp rejects as an unknown binary operation (SigmaParser.scala:99).
    reject("a `foo` b");
}

#[test]
fn quirk_null_char_symbol_string_constants() {
    // spec-derived: Literals.scala:88 — `null` is a StringConstant("null").
    check("null", string("null"));
    // spec-derived: Literals.scala:94-101,119 — `'c'` / `'sym` keep the leading
    // quote and become raw StringConstants.
    check("'a'", string("'a'"));
    check("'sym", string("'sym"));
}

#[test]
fn quirk_string_interpolation_acceptance() {
    // spec-derived: Literals.scala:127-130 — in an id-prefixed string `$$` and
    // `$`+plain-id are accepted; the whole raw text (prefix + quotes) is kept.
    check("s\"100%$$\"", string("s\"100%$$\""));
    check("s\"a $x b\"", string("s\"a $x b\""));
    // D6 deviation: the `${ … }` interpolation-block form is rejected in M1.
    reject("s\"a ${x} b\""); // D6 deviation
                             // spec-derived: plain (unprefixed) strings use NoInterp — `${x}` is content.
    check("\"${x}\"", string("${x}"));
}

#[test]
fn quirk_tuple_lambda_arrow_and_eq_forms() {
    // spec-derived: PostfixLambda (Exprs.scala:65-70) — `(a,b) => e` wraps the
    // body in a Block via LambdaRhs semi-inference.
    check(
        "(a, b) => a",
        lambda(
            vec![("a", NoType), ("b", NoType)],
            block(vec![], ident("a")),
        ),
    );
    // spec-derived: SuperPostfixSuffix `= Expr` (Exprs.scala:77) uses a raw Expr
    // body (no block wrapper).
    check(
        "(a, b) = a",
        lambda(vec![("a", NoType), ("b", NoType)], ident("a")),
    );
}

#[test]
fn quirk_lt_gt_precedence() {
    // spec-derived: Exprs.scala:150-151 duplicate `>` — the later toMap entry
    // wins, so `>` (6) binds tighter than `<` (5): `a < b > c` == `a < (b > c)`.
    check("a < b > c", lt(ident("a"), gt(ident("b"), ident("c"))));
}

#[test]
fn quirk_min_value_literal_rejections() {
    // spec-derived: Literals.scala:106-116 — the positive magnitude is parsed
    // BEFORE the sign folds, so Int/Long MinValue magnitudes overflow and reject.
    reject("-2147483648");
    reject("-9223372036854775808L");
    reject("0x80000000");
}

#[test]
fn quirk_keyword_boundary_identifiers() {
    // spec-derived: Basic.scala:74-75 — the keyword boundary is
    // `!LetterDigitDollarUnderscore`, so `truex` / `if1` are ordinary idents.
    check("truex", ident("truex"));
    check("if1", ident("if1"));
    // spec-derived: Identifiers.scala:51 — `then` IS reserved, so it is not a
    // valid standalone expression.
    reject("then");
}

#[test]
fn quirk_trailing_comma_only_before_newline() {
    // spec-derived: Literals.scala:63 — a trailing comma is legal only when a
    // newline follows.
    check("f(1,\n)", apply(ident("f"), vec![int(1)]));
    reject("f(1,)");
}

#[test]
fn quirk_fundef_extra_arg_list_dropped() {
    // spec-derived: FunDef (Exprs.scala:220 args.headOption) — with no dotty
    // subject the extra `(b: Int)` arg list is silently dropped.
    check(
        "def f(a: Int)(b: Int) = a",
        val_expr("f", NoType, lambda_r(vec![("a", SInt)], NoType, ident("a"))),
    );
}

#[test]
fn quirk_negative_hex_folds_into_literal() {
    // spec-derived: SigmaParser.scala:43 — `-0x10` folds the sign into the
    // numeric constant -> IntConstant(-16).
    check("-0x10", int(-16));
}

#[test]
fn quirk_if_without_else_is_hard_error() {
    // spec-derived: Exprs.scala:47-52 — the `if` keyword commits; a missing
    // `else` is a hard error (parse.rs:769-773).
    reject("if (true) 1");
}

#[test]
fn quirk_empty_block_rejects_without_semi() {
    // extractBlockStats' empty arm (Exprs.scala:271-272) is reachable only via an
    // explicit ';' — bare {} fails in fastparse before reaching it (oracle-verified).
    // Reject position = one past the empty block's closing `}`.
    fail_at("{}", 1, 3); // oracle: ParserOracle sigma-state 6.0.2
    fail_at("{ }", 1, 4); // oracle: ParserOracle sigma-state 6.0.2
    fail_at("{\n}", 2, 2); // oracle: ParserOracle sigma-state 6.0.2
    fail_at("{//c\n}", 2, 2); // oracle: ParserOracle sigma-state 6.0.2
    fail_at("{/*c*/}", 1, 8); // oracle: ParserOracle sigma-state 6.0.2
    fail_at("f({})", 1, 5); // oracle: ParserOracle sigma-state 6.0.2
    fail_at("({})", 1, 4); // oracle: ParserOracle sigma-state 6.0.2
    fail_at("ZKProof {}", 1, 11); // oracle: ParserOracle sigma-state 6.0.2
                                  // oracle REJECT 1:5; ours rejects at the inner block (1,4) — furthest-failure
                                  // vs recursive-descent position difference, reject-parity holds.
    reject("{{}}"); // oracle: ParserOracle sigma-state 6.0.2
}

#[test]
fn quirk_empty_block_with_semi_accepts() {
    // A literal ';' rescues the empty block into Block([], ()) — the only path that
    // reaches extractBlockStats' empty arm (Exprs.scala:271-272).
    check("{;}", block(vec![], unit())); // oracle: ParserOracle sigma-state 6.0.2
    check("{;;}", block(vec![], unit())); // oracle: ParserOracle sigma-state 6.0.2
}

#[test]
fn quirk_def_alone_is_ident() {
    // Exprs.scala:55 — `def` has no cut, so `def` alone (FunDef fails at the missing
    // name before any cut) backtracks to an ordinary identifier.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT as Ident.
    check("def", ident("def"));
}

#[test]
fn quirk_empty_type_args_apply() {
    // spec-derived: Types.scala:117 rep(0) — `X[]` is a legal empty type-app.
    check("X[]", apply_types(ident("X"), vec![]));
}

#[test]
fn quirk_entry_trailing_newline_ok_but_semicolon_errors() {
    // spec-derived: SigmaParser.scala:114-117 `StatCtx.Expr ~ End` — a trailing
    // newline is skipped but a trailing `;` is a hard error.
    check("1\n", int(1));
    reject("1;");
}

// -----------------------------------------------------------------------------
// Codex round-2 parity fixes (separator-first arg lists, faithful parse-time
// types, raw prefix guard). Every case oracle-pinned against ParserOracle.
// -----------------------------------------------------------------------------

#[test]
fn separator_first_multiline_arg_lists_accept() {
    // Finding 1: `Arg.rep(1, ",") ~ TrailingComma` / `TypeArg.rep(1, ",")` are
    // separator-first — a `,\n item` is a separator, not a trailing comma. A
    // multi-line block-lambda head, FunArgs list, extractor pattern, and FunTypeArgs
    // all bind every element.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each
    accept("{ (x: Int,\n y: Int) => x }");
    accept("{ (x: Int,\n y: Int,\n z: Int) => x }");
    accept("{ def f(\n x: Int,\n y: Int\n) = x; 1 }");
    accept("{ def f(a: Int,\n b: Int)(c: Int) = a; 1 }");
    accept("{ def f[T,\n U](x: Int) = x; 1 }");
    accept("{ def f[A,\n B,\n C](x: Int) = x; 1 }");
    accept("{ val Some(a,\n b) = t; a }");
}

#[test]
fn separator_first_trailing_comma_newline_accepts() {
    // Finding 1: a trailing comma directly before a Newline IS legal
    // (`TrailingComma = ("," WS Newline)?`, Literals.scala:63).
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each
    accept("{ (x: Int,\n) => x }");
    accept("{ def f[T,\n](x: Int) = x; 1 }");
    accept("{ val Some(a,\n) = t; a }");
}

#[test]
fn separator_first_no_newline_trailing_comma_rejects() {
    // Finding 1 regression: a trailing comma NOT followed by a Newline is rejected
    // wherever Scala rejects. Reject-parity holds; the exact position is a
    // pre-existing furthest-failure vs recursive-descent difference (the block-lambda
    // head backtracks and re-parses `(x: Int,)` as a parenthesized expr) unaffected
    // by this fix, so only the verdict is asserted.
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT each
    reject("{ (x: Int,) => x }");
    reject("{ def f[T,](x: Int) = x; 1 }");
    reject("{ val Some(a,) = t; a }");
}

#[test]
fn parse_time_numeric_guard_rejects_non_numeric_operands() {
    // Finding 2: mkUnaryOp/mkBinaryOp read `arg.tpe` (SigmaParser.scala:44/55/61/
    // 85/91). A Relation/LogicalNot is SBoolean, a Tuple is STuple, a Lambda is
    // SFunc, an If is trueBranch.tpe — none are numeric-or-NoType, so `-`/`~`/`&`/`|`
    // on them is a parse-time error (not a blanket accept).
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT at the pinned position
    fail_at("-(1 == 2)", 1, 3); // Relation -> SBoolean, pinned to the left operand
    fail_at("~(1 < 2)", 1, 3);
    fail_at("!x & 3", 1, 2); // `!x` is LogicalNot -> SBoolean
    fail_at("{true} & 1", 1, 2); // Block result SBoolean
    fail_at("{true} & {false}", 1, 2);
    fail_at("~(1, 2)", 1, 2); // Tuple -> STuple
    fail_at("(1==2) & (3==4)", 1, 2);
    fail_at("-{ (x: Int) => x }", 1, 4); // Lambda -> SFunc
    fail_at("-true", 1, 2);
    fail_at("-\"hi\"", 1, 2);
    fail_at("true | false", 1, 1);
    fail_at("true | x", 1, 1);
    fail_at("-(if (x) (1==1) else (2==2))", 1, 3); // If -> trueBranch.tpe = SBoolean
}

#[test]
fn parse_time_numeric_guard_accepts_numeric_or_notype_operands() {
    // Finding 2 regression: NoType operands (Ident/Select/Apply) and numeric-typed
    // operands (Block of an Ident, ArithOp, If with numeric branch) still pass.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each
    accept("-OUTPUTS.size"); // Select on a NoType object -> NoType
    accept("x | y"); // Idents -> NoType
    accept("-{ val x = 1; x }"); // Block result is an Ident -> NoType
    accept("-(1 - 2)"); // ArithOp -> left.tpe = SInt
    accept("-(if (x) 1 else 2)"); // If trueBranch numeric -> SInt
    accept("ZKProof { proveDlog(g) }"); // standalone; the SFunc Ident is the callee
}

#[test]
fn prefix_op_honours_raw_next_char_comment_is_op_char() {
    // Finding 3: ExprPrefix's `~~ !OpChar` runs on the RAW source before comment/WS
    // skipping. A `-`/`+`/`!`/`~` immediately followed by `/` (a comment start, which
    // is an op-char) is NOT a prefix — the op falls through to SimpleExpr as an
    // operator ident, leaving the operand as trailing input.
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT at the pinned position
    fail_at("-/*c*/1", 1, 7);
    fail_at("+/*c*/1", 1, 7);
    fail_at("~/*c*/1", 1, 7);
    fail_at("!//c\nx", 2, 1);
}

#[test]
fn prefix_op_still_folds_across_whitespace_and_adjacency() {
    // Finding 3 regression: a `-` folds a numeric constant whether adjacent (`-5`)
    // or separated by whitespace (`- 5`); a block-comment before a NON-op operand
    // (`-/*c*/x`) still prefixes; a line comment that ends the input is harmless.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each
    check("-5", int(-5));
    check("- 5", int(-5));
    accept("-/*c*/x"); // Negation(Ident) — the operand is not an op-char
    accept("!//c");
}

// ----- oracle parity: round-3 comment/newline machinery -----

#[test]
fn r3_symbolic_keyword_before_comment_is_identifier() {
    // A symbolic-keyword op-run DIRECTLY before a `//`/`/*` comment lexes as an
    // operator identifier (the reserved-check's `!OpChar` sees the comment's `/`),
    // so after a `.` it is a valid `Select` FIELD — while the bare reserved form is
    // refused. oracle: ParserOracle sigma-state 6.0.2 — ACCEPT / REJECT as pinned.
    accept("a.=>/*c*/");
    accept("a.:/*c*/");
    accept("a.@/*c*/");
    accept("a.#/*c*/");
    accept("a.=/*c*/");
    fail_at("a.=>", 1, 3); // bare reserved `=>` after `.` is not a PlainId
    fail_at("a.:", 1, 3);
    fail_at("a.@", 1, 3);
    // In identifier/infix position the op-id flows through `mkInfixOp`, which has no
    // case for these — an "unknown binary operation" pinned to the left operand.
    fail_at("a =//c\n b", 1, 1);
    fail_at("x #/*c*/ y", 1, 1);
    fail_at("x :/*c*/ Int", 1, 1);
}

#[test]
fn r3_symbolic_keyword_before_comment_still_works_in_keyword_positions() {
    // The GRAMMAR keyword matchers `Key.O(...)` carry a comment exception, so the
    // same comment-adjacent op-id still binds as the keyword at `=`/`:`/`=>`/`@`
    // sites (reproduced by `Cursor::at_sym_kw`). oracle: ACCEPT each.
    accept("{ val x =//c\n 1; x }"); // `=` before a line comment
    accept("{ val x =/*c*/ 1; x }"); // `=` before a block comment
    accept("{ (x: Int) =>/*c*/ x }"); // lambda `=>`
    accept("{ (x: Int) =>//c\n x }");
    accept("{ (x:/*c*/ Int) => x }"); // lambda-arg `:`
    accept("{ val x:/*c*/ Int = 1; x }"); // val-ascription `:`
    accept("{ def f(x: Int):/*c*/ Int = x; 1 }"); // def result `:`
    accept("{ def f(x: Int) =/*c*/ x; 1 }"); // def `=`
    accept("{ (f: Int =>/*c*/ Long) => f }"); // function-type `=>`
    accept("{ @/*c*/foo val x = 1; x }"); // annotation `@`
    accept("{ def f[T:/*c*/ Int](x: Int) = x; 1 }"); // context-bound `:`
}

#[test]
fn r3_one_nl_max_rejects_post_newline_dangling_block_comment() {
    // `OneNLMax`'s `ConsumeComments` matches a block comment via `MultilineComment
    // = "/*" ~/ …`; the `~/` cut turns a block comment NOT followed by the required
    // `Newline` into a hard failure, so the infix continuation is refused and the
    // operator becomes a postfix — the rhs is then trailing input. oracle: REJECT
    // at the pinned position (the rhs on the continuation line).
    fail_at("a +\n/*c*/b", 2, 6);
    fail_at("a +\n/*c*//*d*/b", 2, 11);
    fail_at("a +\n /*c*/ b", 2, 8);
    // shares the fix with the TYPE-grammar infix (`InfixType`'s `OneNLMax`).
    fail_at("{ val x: Int +\n/*c*/Long = y; x }", 1, 14);
}

#[test]
fn r3_one_nl_max_still_accepts_clean_comment_continuations() {
    // Regression: a line comment (no `~/` cut), a block comment that IS
    // newline-terminated (a clean `ConsumeComments` line), a comment BEFORE the
    // sole newline (leading `WS`, NoCut), and no-comment continuations all pass.
    // oracle: ACCEPT each.
    accept("a +\n//c\nb");
    accept("a +\n/*c*/\nb");
    accept("a + /*c*/\nb");
    accept("a +/*c*/\nb");
    accept("a +\nb");
    accept("a + /*c*/b");
    accept("{ val x: Int +\n Long = y; x }");
}

#[test]
fn r3_no_newline_limit_before_def_arg_lists() {
    // `FunDef = … Id.! ~ FunSig` and `FunArgs.rep`'s inter-iteration whitespace are
    // implicit-`ScalaWhitespace` positions, so an arg list may follow any number of
    // blank lines. oracle: ACCEPT each.
    accept("{ def f\n\n(x: Int) = x; 1 }");
    accept("{ def f(x: Int)\n\n(y: Int) = x; 1 }");
    accept("{ def f\n\n(x: Int)\n\n(y: Int) = x; 1 }");
    accept("{ def f\n\n[T](x: Int) = x; 1 }");
    // The ONE live `OneNLMax`: the first arg list after a present `FunTypeArgs`
    // (`FunTypeArgs.? ~~ FunArgs` joins them with RAW `~~`) — one newline ok, two not.
    accept("{ def f[T]\n(x: Int) = x; 1 }");
    reject("{ def f[T]\n\n(x: Int) = x; 1 }");
}

#[test]
fn r3_block_lambda_and_raw_block_arg_newline_sites_unchanged() {
    // The block-lambda head is reached through an implicit-whitespace position
    // (`{` ~/ Block, and BaseBlock's leading `Semis.?`), so blank lines before it
    // are fine — while the ExprSuffix block-arg `OneNLMax` sits in a raw `repX`
    // position, so a `{ … }` on a new line does NOT continue a call in Stat context.
    // oracle: ACCEPT the lambdas, REJECT the block-args.
    accept("{\n\n(x: Int) => x }");
    accept("{ (x: Int)\n\n=> x }");
    reject("f\n\n{ 1 }");
    reject("f\n{ 1 }");
}

// -----------------------------------------------------------------------------
// Codex round-4 parity fixes: committed-`def` no-fallback, block-lambda `BlockEnd`
// semis, full `Pattern` grammar in extractor `TupleEx`. Every case oracle-pinned
// against ParserOracle (sigma-state 6.0.2).
// -----------------------------------------------------------------------------

// ----- oracle parity: F1 committed-`def` fallback boundary -----

#[test]
fn r4_def_committed_cut_failure_rejects() {
    // `Fun = `def` ~ FunDef` (Exprs.scala:55) has NO cut after `def`: a FunDef that
    // fails before crossing a cut backtracks to parse `def` as an identifier, but
    // once a FunDef cut fires — an opened FunArgs `(`, a FunTypeArgs `[`, a
    // DottyExtMethodSubj `(`, a result `:`, or the Body `=` — fastparse's `|` cannot
    // backtrack past it and the failure is hard (Types.scala:142-143,150; Exprs.scala:216).
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT at the cited position.
    fail_at("def +(x)", 1, 9); // opened FunArgs `(`, then Body `=` missing
    fail_at("def ||()", 1, 9);
    fail_at("def +(x): Int", 1, 14); // result `:` present, Body `=` missing
    fail_at("def + : Int", 1, 12); // bare op-id name, result-`:` cut
    fail_at("def f[T]", 1, 9); // FunTypeArgs `[` cut
    fail_at("def f[T](x)", 1, 12);
    fail_at("def f()", 1, 8); // empty FunArgs `(` cut, Body `=` missing
    fail_at("def f: Int", 1, 11); // result-`:` cut, Body `=` missing
    fail_at("def(1)", 1, 5); // DottyExtMethodSubj `(` cut, name expected
    fail_at("def (x) = 1", 1, 7); // dotty `(` cut, inner `:` expected
    fail_at("def f[123]", 1, 7); // FunTypeArgs cut, bad type arg
    fail_at("def f[]", 1, 7);
}

#[test]
fn r4_def_precut_failure_falls_back_to_ident() {
    // No cut fired → `def` is an ordinary identifier and the rest parses via
    // PostfixLambda. oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each.
    check("def", ident("def"));
    accept("def f"); // name only, no cut, no `=`
    accept("def + 1"); // op-id name as infix, no cut
    accept("def +");
    accept("def ||");
    accept("def * 2");
    accept("x + def");
    accept("def.toString");
    accept("def + def");
    accept("{ def x = 1; x }"); // a real def inside a block still parses
}

#[test]
fn r4_def_committed_and_complete_accepts() {
    // The committed forms that reach the Body `=` are ordinary defs.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each.
    accept("def +(x) = x");
    accept("def +(x): Int = x");
    accept("def f = 1");
    accept("def f() = 1");
    accept("def (x: Int) foo = x"); // DottyExtMethodSubj succeeds, then name `foo`
}

// ----- oracle parity: F2 block-lambda `BlockEnd` trailing semis -----

#[test]
fn r4_block_lambda_empty_body_trailing_semis_accept() {
    // `BlockEnd = Semis.? ~ &("}")` (Exprs.scala:281) absorbs a trailing `;` run
    // before the closer even when the block-lambda body is empty; the body is then
    // `block(Seq())` = `Block([], ())` (Exprs.scala:286-292, 271-272).
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT; body shape pinned via check().
    check(
        "{ (x,y)=>; }",
        lambda(vec![("x", NoType), ("y", NoType)], block(vec![], unit())),
    );
    check(
        "{ (x,y)=> }",
        lambda(vec![("x", NoType), ("y", NoType)], block(vec![], unit())),
    );
    check("{ ()=>; }", lambda(vec![], block(vec![], unit())));
    accept("{ (x,y)=>;; }");
    accept("{ (x,y)=>;}");
    accept("{ (x,y)=> ; ; }");
}

// ----- oracle parity: F3 extractor `TupleEx` full `Pattern` grammar -----

#[test]
fn r4_extractor_pattern_full_grammar_accepts() {
    // `TupleEx` elements are full `Pattern`s (Exprs.scala:304-306): a `TypePattern`
    // `v : CompoundType` (head is `_`/backtick/`VarId`) and `|`-alternation, all
    // parsed-and-DISCARDED (the extractor keeps only the `StableId` name, :236).
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each.
    accept("{ val Some(x: Int) = 1; 1 }");
    accept("{ val Some(_: Int) = 1; 1 }");
    accept("{ val Some(_x: Int) = 1; 1 }");
    accept("{ val Some($x: Int) = 1; 1 }");
    accept("{ val Some(`A`: Int) = 1; 1 }"); // backtick head escapes the uppercase rule
    accept("{ val Some(x: Coll[Int]) = 1; 1 }"); // TypePat = CompoundType
    accept("{ val Some(x | y) = 1; 1 }");
    accept("{ val Some(Foo | x) = 1; 1 }");
    accept("{ val Some(x: Int | y) = 1; 1 }"); // CompoundType stops at `|`
    accept("{ val Some(x, y: Int) = 1; 1 }");
    accept("{ val Some(x: Int, y) = 1; 1 }");
}

#[test]
fn r4_extractor_pattern_malformed_rejects() {
    // The `|` separator carries a cut (`"|"./`) and the `(` carries a cut; an
    // UppercaseId head is a constructor `StableId` (not a `VarId`), so a typed
    // uppercase element strands the `:` before `)`. oracle: sigma-state 6.0.2 —
    // REJECT at the cited position.
    fail_at("{ val Some(x |) = 1; 1 }", 1, 15); // `|` cut, no following alternative
    fail_at("{ val Some(x: ) = 1; 1 }", 1, 13); // empty TypePat → bind `x`, `:` stranded
    fail_at("{ val Some(Foo: Int) = 1; 1 }", 1, 15); // uppercase head → StableId
    fail_at("{ val Some(A.b: Int) = 1; 1 }", 1, 15); // dotted StableId, then `:`
    fail_at("{ val Some((a,b): Int) = 1; 1 }", 1, 17); // nested tuple, then `:`
    fail_at("{ val Some(Foo(y): Int) = 1; 1 }", 1, 18); // extractor, then `:`
    fail_at("{ val Some((x |)) = 1; 1 }", 1, 16); // nested `TupleEx` applies the `|` cut
}

#[test]
fn r4_val_tuple_pattern_uses_real_tupleex() {
    // The `val (…)` binder's `TupleEx` is now the real `Pattern` grammar (not a
    // balanced-paren scan): a well-formed tuple reduces to the non-name `Other` and
    // is rejected at the pattern start, while a malformed inner pattern hard-rejects
    // at its own position. oracle: ParserOracle sigma-state 6.0.2.
    fail_at("{ val (a, b) = t; a }", 1, 7); // well-formed tuple → non-name reject
    fail_at("{ val (x: ) = 1; 1 }", 1, 9); // empty TypePat, inner reject
    fail_at("{ val (a, b = t; a }", 1, 13); // unterminated inner group
}

// -----------------------------------------------------------------------------
// Codex round-5 parity fixes: the block-lambda / LambdaRhs / PostFix chunking
// machinery. `LambdaRhs = Index ~ BlockChunk` is a LONE chunk (only `;` continues,
// a newline ends it) while the block `Body = BlockChunk.repX(sep = Semis)` spans
// many chunks; a BlockLambda head at any chunk start is a `MatchError`; and a lone
// PostFix must leave its trailing newline as the block separator. Every case is
// oracle-pinned against ParserOracle (sigma-state 6.0.2).
// -----------------------------------------------------------------------------

// ----- oracle parity: Finding 1 — tuple-lambda RHS is a single BlockChunk -----

#[test]
fn r5_lambda_rhs_single_chunk_stops_at_newline() {
    // `LambdaRhs = Index ~ BlockChunk` (Exprs.scala:59) — a LONE chunk. Its
    // `BlockStat.rep(sep = Semis)` continues only across a `;`; a newline-separated
    // statement opens a NEW chunk that belongs to the ENCLOSING block. So the lambda
    // body is just `x`, and `f` is the outer block's result.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT; body shape pinned.
    check(
        "{ val f = (x,y)=>x\nf }",
        block(
            vec![val_def(
                "f",
                NoType,
                lambda(
                    vec![("x", NoType), ("y", NoType)],
                    block(vec![], ident("x")),
                ),
            )],
            ident("f"),
        ),
    );
    // Newline-separated trailing statements (a following `val` or bare exprs) all go
    // to the enclosing block, never the lambda body.
    accept("{ val f = (x,y)=>x\nval g = 1\ng }"); // val after the lambda
    accept("{ val f = (x,y)=>val y=1; y\nf }"); // `;`-chunk body, then `\nf`
    accept("{ val f = (x,y)=>val y=1\nf }"); // val-only body, then `\nf`
}

#[test]
fn r5_lambda_rhs_semicolon_absorbs_next_stat_into_body() {
    // A `;` DOES continue the single chunk, so `; f` is pulled into the lambda body
    // → `block([x, f])`, where `x` is a non-Val in non-tail position: a block-shape
    // error pinned to `x` (1:18). Contrast `\nf` above (ACCEPT).
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT at 1:18.
    fail_at("{ val f = (x,y)=>x; f }", 1, 18);
    fail_at("{ val f = (x,y)=>x; y\nf }", 1, 18); // `; y` absorbed, then `\nf` splits
    fail_at("{ val f = (x,y)=>x;; f }", 1, 18); // `;;` still one separator
    fail_at("{ val f = (x,y)=>x\n;y }", 1, 18); // a `;` anywhere in the run continues
}

#[test]
fn r5_lambda_rhs_second_newline_statement_is_end_error() {
    // With the single-chunk body stopping at the first newline, a SECOND newline-
    // separated statement in the enclosing context is trailing input. At top level
    // (`StatCtx.Expr ~ End`) the leftover fails the `End` at the stranded token.
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT at the leftover token.
    fail_at("(x,y)=>x\nf", 2, 1); // top level: `f` after the single-chunk body
    fail_at("{ val f = (x,y)=>x\ng\nh }", 2, 1); // `g` is a non-Val non-tail in the block
}

// ----- oracle parity: Finding 2 — leading block-lambda + `;` + statement -----

#[test]
fn r5_leading_lambda_semicolon_then_body_statement() {
    // `{ (x)=>; x }`: the leading `;` opens an empty first `Body` chunk; the `;` is a
    // `repX` separator, and `x` is the next chunk's stat — the lambda body. Two
    // chunks → BaseBlock's second map arm wraps it: `block([x])` (Exprs.scala:286-292).
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT; body shape pinned.
    check(
        "{ (x)=>; x }",
        lambda(vec![("x", NoType)], block(vec![], ident("x"))),
    );
    check(
        "{ (x)=>;; x }",
        lambda(vec![("x", NoType)], block(vec![], ident("x"))),
    );
    check(
        "{ (x)=>; val y=1; y }",
        lambda(
            vec![("x", NoType)],
            block(vec![val_def("y", NoType, int(1))], ident("y")),
        ),
    );
    // A newline (not a `;`) after the head needs no special handling — `peek` skips
    // it — and, being a single one-stat chunk, yields the RAW body `x` (first arm).
    check("{ (x)=> x }", lambda(vec![("x", NoType)], ident("x")));
    check("{ (x)=>\n x }", lambda(vec![("x", NoType)], ident("x")));
}

// ----- oracle parity: Finding 3 — block-lambda head in any later chunk -----

#[test]
fn r5_block_lambda_head_in_later_chunk_rejects() {
    // A `BlockLambda` head at any `Body` chunk start makes that chunk's
    // `BlockLambda.rep` non-empty → the flatMap `case (Seq(), exprs)` is a
    // `scala.MatchError` (Exprs.scala:288-296): position-less REJECT `0:0` in the
    // reference; we reject it (Semantic, pinned to the head — D5 error-class +
    // position deviation, both sides REJECT).
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT each.
    reject("{ val x = 1\n(x,y)=>x }"); // later chunk after a newline gap
    reject("{ val x = 1\n(a)=>a }"); // single-param head is also a BlockLambda head
    reject("{ (a)=>a\n(b)=>b }"); // leading lambda, stat, newline, head
    reject("{ (a)=>(b)=>c }"); // consecutive leading heads (D5)
    reject("{ (x)=>; (a,b)=>c }"); // empty chunk, `;` separator, then a head
    reject("{ val x=1\n(a,b)=>a\n(c,d)=>c }"); // head starting a later chunk
}

#[test]
fn r5_semicolon_continued_lambda_is_an_expression_lambda() {
    // After a `;` that CONTINUES a non-empty chunk, a `(a,b)=>e` is a `StatCtx.Expr`
    // expression lambda (NOT a BlockLambda head) — so it is accepted as a block
    // binding's neighbour, while a single-ident `(a)=>b` there is the ordinary
    // "Invalid declaration of lambda" error.
    // oracle: ParserOracle sigma-state 6.0.2.
    check(
        "{ val x = 1; (x,y)=>x }",
        block(
            vec![val_def("x", NoType, int(1))],
            lambda(
                vec![("x", NoType), ("y", NoType)],
                block(vec![], ident("x")),
            ),
        ),
    );
    fail_at("{ (a)=>a; (b)=>b }", 1, 11); // 2nd `(b)=>b` = invalid-lambda at its `(`
    fail_at("{ (a)=>a; (b,c)=>d }", 1, 8); // valid expr lambda, but `a` non-Val non-tail
}

#[test]
fn r5_expression_level_tuple_lambdas_still_accepted() {
    // Tuple-lambdas OUTSIDE a chunk boundary keep working: a nested argument, an IIFE
    // application, and a bare tuple (no `=>`) at a chunk boundary are NOT heads.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each.
    accept("{ f((x,y)=>x) }"); // lambda in argument position
    accept("((x,y)=>x)(1,2)"); // immediately-applied lambda
    accept("{ val x=1\n(a,b) }"); // later chunk is a bare Tuple, not a head
}

// ----- oracle parity: Finding 4 — PostFix leaves the block-separator newline -----

#[test]
fn r5_postfix_leaves_newline_for_block_separator() {
    // A lone `*` PostFix ends the val, and the `\n` separates the next statement:
    // `val x = "s".*` (binding) then the `if` (result) → a valid block.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT; shape pinned.
    check(
        "{ val x = \"s\" *\nif (true) z else () }",
        block(
            vec![val_def("x", NoType, mcl0(string("s"), "*"))],
            if_(boolean(true), ident("z"), unit()),
        ),
    );
    accept("{ val a = z *; if (true) x else y }"); // a `;` separates just the same
                                                   // A lone PostFix as the sole/last statement is a plain zero-arg MethodCallLike.
    check("{ z * }", block(vec![], mcl0(ident("z"), "*")));
}

#[test]
fn r5_bare_postfix_statement_then_next_is_block_shape_error() {
    // When the postfix statement is a BARE expression (not a `val`), the `\n` still
    // separates the next statement — so `z.*` lands as a non-Val in non-tail position
    // and the block-shape error pins to `z` (1:3). NOT a "missing separator" reject.
    // oracle: ParserOracle sigma-state 6.0.2 — REJECT at 1:3.
    fail_at("{ z *\nif (true) a else b }", 1, 3);
    fail_at("{ z *\nval a = 1\na }", 1, 3);
    fail_at("{ z *\n\nif (true) a else b }", 1, 3); // two newlines, same result
    fail_at("{ z tl\ny }", 1, 3); // a non-operator lone postfix, same shape
                                  // Inside parens (`ExprCtx`) a following expression makes the lone id an INFIX op
                                  // whose unknown operator rejects at the left operand.
    fail_at("(x id\ny)", 1, 2);
    fail_at("{ x id\ny }", 1, 3);
}

// ----- oracle parity: round 6 (F1) — Select.tpe product-method lookup -----

#[test]
fn r6_product_select_type_fails_the_numeric_guard() {
    // Scala `Select.tpe` (values.scala:1171-1178) looks up the field method on a
    // parse-time-typed product object; a FOUND method makes the Select an `SFunc`
    // (its `m.stype`), which is non-numeric and fails the mkUnaryOp/mkBinaryOp guard.
    // A tuple literal `(a,b)._i` (i in range) and a numeric-constant cast/bitwise
    // method are the reachable cases. oracle: ParserOracle sigma-state 6.0.2 — REJECT.
    fail_at("-((1,2)._1)", 1, 3); // Negation guard, tuple `_1` → SFunc
    fail_at("~((1,2)._1)", 1, 3); // BitInversion guard, same
    fail_at("-((1,2)._2)", 1, 3); // in-range on a 2-tuple
    fail_at("-((1,2,3)._3)", 1, 3); // in-range on a 3-tuple
    fail_at("-((1,2).size)", 1, 3); // inherited Coll `size`
    fail_at("~((1,2).apply)", 1, 3); // inherited Coll `apply`
    fail_at("((1,true)._2) | 1", 1, 2); // `|` guard, tuple `_2` → SFunc
    fail_at("((1,2)._1) & 1", 1, 2); // `&` guard, tuple `_1` → SFunc
    fail_at("-(5.toByte)", 1, 3); // SInt cast method → SFunc
    fail_at("-(5L.toByte)", 1, 3); // SLong cast method → SFunc
    fail_at("-(5.toBytes(0))", 1, 3); // Apply of `.toBytes` → SColl[SByte], non-numeric
    fail_at("-(5.bitwiseOr)", 1, 3); // v6-only numeric method (tree_version=3) → SFunc
                                     // `-(1,2)._1`: the prefix `-` binds the `(1,2)` atom FIRST (a tuple, non-numeric),
                                     // so the guard rejects at the tuple `1:2` before `._1` is ever reached.
    fail_at("-(1,2)._1", 1, 2);
}

#[test]
fn r6_non_product_select_still_passes_the_numeric_guard() {
    // A NoType object (identifier-rooted), an out-of-range / non-canonical tuple
    // component, a missing tuple/String/Boolean method, and a Unit receiver (not
    // SProduct) all keep the Select `NoType`, which passes the guard.
    // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT.
    accept("-OUTPUTS.size"); // Ident object → NoType (StableId consumed the dot chain)
    accept("-((1,2)._3)"); // `_3` out of range on a 2-tuple → None → NoType
    accept("-((1,2)._0)"); // `_0` is not a component name
    accept("-((1,2)._01)"); // non-canonical index form
    accept("-((1,2).nope)"); // no such tuple method
    accept("-(\"ab\".size)"); // SString defines no methods
    accept("-(true.toByte)"); // SBoolean defines no methods
    accept("-(().foo)"); // SUnit is not an SProduct
    accept("-(5.toByte(0))"); // Apply of `.toByte` → SByte (numeric) passes
    accept("-((1,2)._1(0))"); // Apply of tuple `_1` → SInt (numeric) passes
}

// ----- oracle parity: round 6 (F2) — raw leading `=>` at the Type entry -----

#[test]
fn r6_leading_type_arrow_is_raw_only_at_the_top_level_entry() {
    // `Type = `=>`.? ~~ PostfixType` (Types.scala:63): the leading arrow is
    // raw-adjacent to the production start. At the top-level parse_type entry a
    // leading gap breaks the raw match (the arrow then falls to PostfixType, which
    // can't parse `=>` as a compound type). oracle: sigma-state 6.0.2.
    reject_type(" => Int"); // leading space
    reject_type("\n=>Int"); // leading newline
    reject_type("/*c*/=>Int"); // leading comment
    reject_type("  =>Int"); // leading spaces
    check_type("=> Int", SInt); // arrow at offset 0 → discarded → `Int`
    check_type("=>Int", SInt);
    check_type("=>/*c*/Int", SInt); // comment AFTER the arrow is fine
    check_type("=>  Int", SInt); // gap AFTER the arrow is fine
                                 // A NON-arrow leading gap is always fine (PostfixType consumes leading WS).
    check_type(" Int", SInt);
    // NESTED Type positions accept a gap before `=>` — the caller `~`/`~/` already
    // consumed it, so from Type's local view the arrow is adjacent.
    check_type("Coll[ => Int]", SType::SColl(Box::new(SInt)));
    check_type("Coll[=> Int]", SType::SColl(Box::new(SInt)));
    accept_type("( => Int) => Int"); // arrow-gap inside a tuple element
    accept_type("Int => => Int"); // arrow-gap on the `=>` RHS Type
}

// ----- oracle parity: round 6 (F3) — stray-brace deviation (deliberate) -----

#[test]
fn r6_stray_brace_block_absurdity_is_deliberately_rejected() {
    // SigmaParser ACCEPTS these malformed inputs as blocks (result `a` / `/`) — a
    // genuine reference-parser misbehavior on garbage input. M1 rejects at the first
    // `}` (bare-empty-block reject). Reproducing the accept would mean emitting a
    // valid tree for garbage, so we deliberately keep the reject-side divergence.
    // See the "Known M1 deviations" ledger in lib.rs.
    reject("{ } a }"); // oracle: ACCEPT (sic) — deliberate M1 deviation, see lib.rs ledger
    reject("{}/}"); // oracle: ACCEPT (sic) — deliberate M1 deviation, see lib.rs ledger
}

// ----- oracle parity: round 7 (F1) — Unicode arrow `⇒` is an op-id, not a keyword -----

#[test]
fn r7_unicode_arrow_is_an_operator_identifier_not_a_keyword() {
    // `⇒` (U+21D2) is not in SymbolicKeywords (Identifiers.scala:55-57), so it lexes
    // as an ordinary op-id; only the `=>` KEYWORD matcher (Core.scala:23) also accepts
    // it. Wherever an `Id` can match first — the expression infix layer — `⇒` is grabbed
    // as an unknown binary operator. oracle: sigma-state 6.0.2.
    //
    // Top-level `(tuple) ⇒ body`: the infix layer grabs `⇒` before the `Fun` arrow →
    // `mkBinaryOp("⇒", (x,y), 1)` → "Unknown binary operation", pinned to the lhs.
    fail_at("(x,y) ⇒ 1", 1, 1); // vs ASCII `(x,y) => 1` which is a lambda (accepts)
    accept("(x,y) => 1");
    // A bare-identifier lhs is "Invalid declaration of lambda" for BOTH forms.
    fail_at("x ⇒ 1", 1, 1);
    fail_at("x => 1", 1, 1);
    // Inside a val body the same infix grab fires, pinned to the tuple `(x,y)` (col 11).
    fail_at("{ val f = (x,y) ⇒ x; 1 }", 1, 11);
    // A `def` body expecting `=` sees the op-id `⇒` (not `=>`), so the error is at the
    // arrow start (col 15), one column left of the ASCII `=>` form (col 16).
    fail_at("def f(x: Int) ⇒ 1", 1, 15);
    fail_at("def f(x: Int) => 1", 1, 16);
    // In KEYWORD position (a block-lambda head) `⇒` IS accepted as the arrow, exactly
    // like `=>` — via `Cursor::at_sym_kw`.
    accept("{ (x) ⇒ x }");
    accept("{ (x) => x }");
}

#[test]
fn r7_unicode_arrow_in_type_is_an_infix_type_id_not_sfunc() {
    // In the type grammar `InfixType`'s `Id.!` (Types.scala:70-95) grabs `⇒` as an
    // infix type operator BEFORE `PostfixType`'s `=>` matcher, yielding a junk
    // `STypeApply("⇒", [Int, Int])` — whereas the ASCII `Int => Int` is an `SFunc`.
    check_type(
        "Int ⇒ Int",
        SType::STypeApply {
            name: "\u{21D2}".to_string(),
            args: vec![SInt, SInt],
        },
    );
    check_type(
        "Int => Int",
        SType::SFunc {
            dom: vec![SInt],
            range: Box::new(SInt),
            tpe_params: vec![],
        },
    );
}

// ----- oracle parity: round 7 (F2) — signed numeric literal as a prefix-op operand -----

#[test]
fn r7_signed_literal_is_a_prefix_op_operand() {
    // Literal `"-".? ~ Index ~ Int` under NoWhitespace (Literals.scala:106-112): a `-`
    // byte-adjacent to the digits is part of the LITERAL. `PrefixExpr` allows only ONE
    // `ExprPrefix` (Exprs.scala:85-88), so a second sign is absorbed by the Literal.
    // oracle: sigma-state 6.0.2.
    accept("! -1"); // `!` prefix, operand literal `-1`
    accept("- -1"); // `-` prefix, operand `-1` → folds to +1
    accept("~ /*c*/ -0x1"); // `~` prefix, comment gap, adjacent `-0x1`
    accept("~ -1");
    accept("! -0x1L"); // long-literal operand
    accept("- -0x1L");
    // Adjacency is required: a gap between the sign and the digits is NOT a literal
    // sign (only ONE prefix is allowed), so `- 1` cannot be a SimpleExpr operand.
    fail_at("! - 1", 1, 5);
    fail_at("!-1", 1, 3); // `!-` munches into one op-id → not a prefix
    fail_at("--1", 1, 3); // `--` is one op-id
                          // `+` is not a literal sign and not a valid prefix op → "Unknown prefix operation".
    fail_at("+ -1", 1, 4);
    fail_at("! +1", 1, 4);
    // Regressions: plain sign folds and infix-rhs signs are unaffected.
    accept("-(-1)");
    accept("1 - -1");
    check("- -1", int(1)); // double negation constant-folds to +1
    check("~ -1", bit_inversion(int(-1))); // `~` prefix over the folded `-1`
}
