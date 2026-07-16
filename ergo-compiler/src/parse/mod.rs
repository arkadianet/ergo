//! Parser entry points: `parse` and `parse_type` (Scala `SigmaParser.apply` /
//! `SigmaParser.parseType`, SigmaParser.scala:103-117).
//!
//! The grammar itself is split across submodules:
//! - [`cursor`] — the token-stream `Cursor` (backtracking, lookahead,
//!   newline-sensitivity primitives) and the shared depth guard.
//! - [`types`] — the TYPE grammar, a production-for-production port of Scala
//!   `Types.scala` (169 lines); resolves straight to `SType` (there is no
//!   separate type-AST in the reference).
//! - [`expr_atoms`] — expression atoms (`SimpleExpr`) and the postfix-suffix
//!   machinery.
//! - [`block`] — block/val/def/lambda machinery, further split into
//!   [`block::definitions`] (val/pattern/fun defs) and [`block::lambda`]
//!   (postfix lambdas, `StableId`, apply-suffix folding).
//! - [`operators`] — the prefix/infix/postfix operator-precedence layer.
//!
//! ## Backtracking and cuts
//! The reference is a fastparse grammar. Two mechanisms are ported:
//! - **Backtracking** is a cursor index `save`/`restore` (fastparse rewinds the
//!   input position the same way).
//! - **Cuts** (`~/`) turn a later failure into a hard error that must not fall
//!   back to an alternative. Every `~/` site in the type grammar follows an
//!   unambiguous opening token (`(`, `[`, `@`, `with`, `>:`, `<:`, `=>`), so we
//!   realise cuts by *leading-token dispatch*: once the opener is seen the
//!   production is committed and inner failures propagate via `?`. Ordered
//!   choices likewise dispatch on the leading token, so no alternative is ever
//!   tried after a cut.

use crate::ast::Expr;
use crate::error::ParseError;
use crate::stype::SType;
use crate::token::{tokenize, TokenKind};

mod block;
mod cursor;
mod expr_atoms;
mod operators;
mod types;
pub(crate) use block::*;
pub(crate) use cursor::*;
pub(crate) use expr_atoms::*;
pub(crate) use operators::*;
pub(crate) use types::*;

/// Maximum combined `expr()`/`type_()` recursion depth this crate's own
/// recursive-descent parser accepts before rejecting with
/// [`ParseError::TooDeep`].
///
/// Source-text nesting depth upper-bounds every downstream structure (typed
/// AST, emitted IR, wire body -- the M4/M5 transform passes rewrite the tree,
/// they don't deepen it beyond source depth times a small constant), so this
/// ONE cap -- shared by both of `parse.rs`'s structural-nesting recursion
/// families (`expr()`'s statement/block/paren/lambda nesting AND `type_()`'s
/// `Coll[Coll[...]]`-style type nesting, via a single [`Cursor::depth`]
/// counter both entry points share) -- bounds the whole compile pipeline in
/// one place, rather than adding separate counters to `emit.rs` and every
/// M4/M5 pass individually (M6 recon §5 audit: `fold.rs`/`lower.rs`/
/// `inline.rs`/`cse.rs`/`isproven.rs`/`tuple.rs` are all call-stack-recursive
/// 1:1 tree walks over the already-depth-bounded typed AST -- none amplifies
/// depth beyond what the parser already accepted, so none needs its own
/// guard).
///
/// NOT oracle-pinned: the compiler's own limits are explicitly not
/// consensus-critical (`lib.rs` D-note), unlike `ergo_ser::opcode::types::
/// MAX_EXPR_DEPTH` (110, the CONSENSUS wire-tree depth bound the assembled
/// tree is re-parsed against at `build_tree` time, `tree.rs`). Set
/// conservatively ABOVE that consensus bound -- source text can legitimately
/// nest a little deeper than the assembled/segregated tree before the
/// transform passes fold/fuse it down -- while staying far below any real
/// stack-overflow threshold. No vendored corpus contract (`test-vectors/
/// ergoscript/corpus`, ~79 real deployed scripts) comes anywhere close: the
/// deepest, `rosen-bridge/RwtRepo.es`, bottoms out around a dozen levels of
/// structural nesting (see `corpus_deepest_contract_still_parses` below).
const MAX_PARSE_DEPTH: usize = 128;

/// Parse an ErgoScript expression (Scala `SigmaParser.apply`,
/// SigmaParser.scala:114-117: `StatCtx.Expr ~ End`).
///
/// The accepted grammar is `Exprs.scala:46-74`: `If | Fun | PostfixLambda` in
/// statement context (`StatCtx`), then `~ End` (SigmaParser.scala:114-117).
/// This covers the full expression grammar — infix, prefix/postfix, lambdas,
/// blocks, `if`/`else`, `val`/`def`, and all atom forms.
pub fn parse(source: &str, tree_version: u8) -> Result<Expr, ParseError> {
    let toks = tokenize(source)?;
    let mut c = Cursor::new(source, toks, tree_version);
    let e = match expr(&mut c, Ctx::Stat) {
        Ok(e) => e,
        Err(err) => return Err(clamp_zero_progress(err, &c)),
    };
    // `~ End`: trailing whitespace/newlines/comments are skipped by `peek`.
    let tail = c.peek();
    if tail.kind != TokenKind::Eof {
        return Err(ParseError::Syntax {
            pos: tail.start,
            expected: "end of input".to_string(),
        });
    }
    Ok(e)
}

/// fastparse `Parsed.Failure.index` quirk for the top-level `Expr ~ End`
/// (SigmaParser.scala:114-117). When `Expr` matches NOTHING — the offending token
/// is the first meaningful token, preceded only by whitespace/comments — the
/// failure index is the start of input (`0` → `1:1`), NOT the token's own offset.
/// Once `Expr` consumes >=1 token the real furthest position is kept. Detected by
/// the cursor never having advanced (`save() == 0`). Empirically: `@x` / `  @x` /
/// `/* c */ @x` → `1:1`; `1 @x` → `1:3` (reported by the tail `End` check above,
/// not here, so it is unaffected). Realises the fastparse behavior that a leading
/// block/line comment before an unparsable first token still points at `1:1`
/// (the `@contract`/`@test` LSP template files).
fn clamp_zero_progress(err: ParseError, c: &Cursor) -> ParseError {
    if c.save() != 0 {
        return err; // >=1 token consumed: keep the real furthest position
    }
    match err {
        ParseError::Syntax { expected, .. } => ParseError::Syntax { pos: 0, expected },
        ParseError::Lexical { msg, .. } => ParseError::Lexical { pos: 0, msg },
        ParseError::Semantic { msg, .. } => ParseError::Semantic { pos: 0, msg },
        // Unreachable in practice: `TooDeep` requires >=1 consumed token per
        // nesting level to even reach `MAX_PARSE_DEPTH`, so `c.save() == 0`
        // (this function's only call path) never coincides with it. Passed
        // through unchanged rather than clamped -- the position is real, not
        // a fastparse zero-progress artifact.
        other @ ParseError::TooDeep { .. } => other,
    }
}

/// Parse an ErgoScript type (Scala `SigmaParser.parseType`,
/// SigmaParser.scala:103-111: `Type ~ End`).
pub fn parse_type(source: &str, tree_version: u8) -> Result<SType, ParseError> {
    let toks = tokenize(source)?;
    let mut c = Cursor::new(source, toks, tree_version);
    // Top-level entry: the leading `=>` must be raw-adjacent to offset 0.
    let t = type_(&mut c, true)?;
    // `~ End`: trailing whitespace/newlines/comments are skipped by `peek`.
    let tail = c.peek();
    if tail.kind != TokenKind::Eof {
        return Err(ParseError::Syntax {
            pos: tail.start,
            expected: "end of input".to_string(),
        });
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stype::SType;

    // ----- helpers -----

    fn cur(src: &str) -> Cursor<'_> {
        Cursor::new(src, tokenize(src).unwrap(), 3)
    }

    // ----- happy path -----

    // tests ported from SigmaParserTest.scala:577-582 ("parseType") + Types.scala spec
    #[test]
    fn parse_type_primitives_and_nesting() {
        assert_eq!(parse_type("Int", 3).unwrap(), SType::SInt);
        assert_eq!(
            parse_type("(Int, Long)", 3).unwrap(),
            SType::STuple(vec![SType::SInt, SType::SLong])
        );
        assert_eq!(
            parse_type("Coll[(Int, Long)]", 3).unwrap(),
            SType::SColl(Box::new(SType::STuple(vec![SType::SInt, SType::SLong])))
        );
        assert_eq!(
            parse_type("Coll[(Coll[Byte], (Coll[Long], Long))]", 3).unwrap(),
            SType::SColl(Box::new(SType::STuple(vec![
                SType::SColl(Box::new(SType::SByte)),
                SType::STuple(vec![SType::SColl(Box::new(SType::SLong)), SType::SLong]),
            ])))
        );
    }

    #[test]
    fn parse_type_option_function_and_unknowns() {
        // Types.scala:126-127 structural Coll/Option; :129 unknown bare name -> STypeVar
        assert_eq!(
            parse_type("Option[Int]", 3).unwrap(),
            SType::SOption(Box::new(SType::SInt))
        );
        assert_eq!(parse_type("Foo", 3).unwrap(), SType::STypeVar("Foo".into()));
        // Types.scala:54-62: tuple lhs FLATTENS into multi-arg SFunc
        assert_eq!(
            parse_type("(Int, Boolean) => Int", 3).unwrap(),
            SType::SFunc {
                dom: vec![SType::SInt, SType::SBoolean],
                range: Box::new(SType::SInt),
                tpe_params: vec![],
            }
        );
        assert_eq!(
            parse_type("Int => Int", 3).unwrap(),
            SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SInt),
                tpe_params: vec![],
            }
        );
        // spec-derived: Types.scala:122 rep(0) — "()" is an empty tuple type
        assert_eq!(parse_type("()", 3).unwrap(), SType::STuple(vec![]));
        // spec-derived: Types.scala:63 — leading `=>` and trailing `*` are parsed and IGNORED
        assert_eq!(parse_type("=> Int", 3).unwrap(), SType::SInt);
        assert_eq!(parse_type("Int*", 3).unwrap(), SType::SInt);
    }

    #[test]
    fn parse_type_version_gates_unsignedbigint() {
        // D3: predef lookup succeeds (Types.scala:37) but SPrimType availability
        // (Types.scala:128 + SType.scala:105-122) rejects below v3.
        assert_eq!(
            parse_type("UnsignedBigInt", 3).unwrap(),
            SType::SUnsignedBigInt
        );
        assert!(parse_type("UnsignedBigInt", 2).is_err());
    }

    // ----- error paths -----

    #[test]
    fn parse_type_compound_and_path_types_rejected() {
        // fail("Coll[Int with Sortable](1)",1,6) / fail("Coll[Int.A](1)",1,10) are
        // expression-level; here assert the type-level classification:
        assert!(parse_type("Int with Sortable", 3).is_err()); // Types.scala:97-103
        assert!(parse_type("Int.A", 3).is_err()); // Types.scala:108-115
    }

    #[test]
    fn parse_type_infix_mixed_associativity_rejected() {
        // spec-derived: Types.scala:70-95 — ops must be all-right (trailing ':') or all-left
        assert!(parse_type("Int +: Long + Byte", 3).is_err());
        // all-left builds STypeApply junk (never resolvable, but parse succeeds):
        assert_eq!(
            parse_type("Int + Long", 3).unwrap(),
            SType::STypeApply {
                name: "+".into(),
                args: vec![SType::SInt, SType::SLong]
            }
        );
    }

    // ----- Scala-cited edge cases (spec-derived) -----

    #[test]
    fn parse_type_any_and_unit_resolve() {
        // Types.scala:47-48 predef table; Types.scala:128 SPrimType path.
        assert_eq!(parse_type("Any", 3).unwrap(), SType::SAny);
        assert_eq!(parse_type("Unit", 3).unwrap(), SType::SUnit);
    }

    #[test]
    fn parse_type_bare_coll_is_type_var() {
        // Types.scala:129: STypeApply("Coll", ∅) with no type args -> STypeVar.
        assert_eq!(
            parse_type("Coll", 3).unwrap(),
            SType::STypeVar("Coll".into())
        );
    }

    #[test]
    fn parse_type_empty_type_args_reach_unsupported() {
        // Types.scala:117 rep(0): `[]` parses as an empty arg list; the resolution
        // ladder then has no matching case (Types.scala:130-131) -> error.
        assert!(parse_type("Coll[]", 3).is_err());
    }

    #[test]
    fn parse_type_tuple_trailing_comma_needs_newline() {
        // Literals.scala:63: a trailing comma is legal only when a newline follows.
        assert_eq!(
            parse_type("(Int,\n)", 3).unwrap(),
            SType::STuple(vec![SType::SInt])
        );
        // Without the newline it is a parse error (the closer expects a type).
        assert!(parse_type("(Int,)", 3).is_err());
    }

    #[test]
    fn type_list_multiline_separator_commas_are_not_trailing() {
        // Regression (shares the root cause of SigmaParserTest.scala:848): a comma
        // is a separator when another type follows across a newline, so a multi-line
        // tuple/type-arg list keeps every element instead of reducing at the first
        // `,\n`.
        assert_eq!(
            parse_type("(Int,\nLong)", 3).unwrap(),
            SType::STuple(vec![SType::SInt, SType::SLong])
        );
        assert_eq!(
            parse_type("Coll[(Int,\nLong)]", 3).unwrap(),
            SType::SColl(Box::new(SType::STuple(vec![SType::SInt, SType::SLong])))
        );
    }

    #[test]
    fn parse_type_all_right_assoc_folds_right() {
        // Types.scala:85-87: all ops end ':' -> `tail.foldRight(head)` with
        // `f((op,t),acc) = STypeApply(op, [t, acc])`. For head=Int and
        // tail=[("+:",Long),("+:",Byte)] this is
        //   f(("+:",Long), f(("+:",Byte), Int))
        //   = STypeApply("+:", [Long, STypeApply("+:", [Byte, Int])]).
        // (The shape is Scala's exact fold, not textbook right-association — these
        // STypeApplys are junk for real scripts, per recon-astNodes.md §1.2.)
        assert_eq!(
            parse_type("Int +: Long +: Byte", 3).unwrap(),
            SType::STypeApply {
                name: "+:".into(),
                args: vec![
                    SType::SLong,
                    SType::STypeApply {
                        name: "+:".into(),
                        args: vec![SType::SByte, SType::SInt],
                    },
                ],
            }
        );
    }

    #[test]
    fn parse_type_backtick_infix_op_keeps_backticks() {
        // Types.scala:92 `Id.!` captures raw text; backticks are part of it, so the
        // op does not end ':' -> left-assoc STypeApply.
        assert_eq!(
            parse_type("Int `foo` Long", 3).unwrap(),
            SType::STypeApply {
                name: "`foo`".into(),
                args: vec![SType::SInt, SType::SLong],
            }
        );
    }

    #[test]
    fn parse_type_trailing_junk_is_end_error() {
        // `Type ~ End` (SigmaParser.scala:103): leftover tokens fail.
        assert!(parse_type("Int Long", 3).is_err());
    }

    // ----- Cursor primitives -----

    #[test]
    fn cursor_peek_and_bump_skip_newlines() {
        let mut c = cur("Int\n+");
        assert_eq!(c.peek().kind, TokenKind::Ident);
        assert_eq!(c.peek2().kind, TokenKind::OpId); // skips the Newline between
        let t = c.bump();
        assert_eq!(t.text("Int\n+"), "Int");
        assert_eq!(c.peek().kind, TokenKind::OpId); // Newline skipped by peek
    }

    #[test]
    fn cursor_save_restore_rewinds() {
        let mut c = cur("Int Long");
        let m = c.save();
        c.bump();
        assert_eq!(c.peek().text("Int Long"), "Long");
        c.restore(m);
        assert_eq!(c.peek().text("Int Long"), "Int");
    }

    #[test]
    fn cursor_no_newline_before_next_detects_newline() {
        let mut c = cur("a\nb");
        assert!(c.no_newline_before_next()); // at `a`, no leading newline
        c.bump(); // consume `a`; cursor now at the Newline token
        assert!(!c.no_newline_before_next()); // a Newline is next
    }

    #[test]
    fn cursor_one_nl_max_accepts_one_rejects_two() {
        // one newline then a token: OK, newline consumed.
        let mut c1 = cur("\nInt");
        assert!(c1.one_nl_max());
        assert_eq!(c1.peek().text("\nInt"), "Int");
        // two blank-line newlines: rejected, cursor restored.
        let mut c2 = cur("\n\nInt");
        let before = c2.save();
        assert!(!c2.one_nl_max());
        assert_eq!(c2.save(), before);
    }
}

#[cfg(test)]
mod expr_tests {
    use super::*;
    use crate::ast::{ArithKind, BitKind, RelKind, ValDef};

    // ----- helpers -----

    // Expected ASTs are taken from SigmaParserTest.scala (cited per test); the
    // Scala suite is the oracle, so these values are NOT self-derived.
    fn p(src: &str) -> Expr {
        crate::parse(src, 3).unwrap()
    }
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
    fn ident0(n: &str) -> Expr {
        Expr::Ident {
            name: n.into(),
            tpe: SType::NoType,
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
    fn minus(l: Expr, r: Expr) -> Expr {
        Expr::ArithOp {
            kind: ArithKind::Minus,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn divide(l: Expr, r: Expr) -> Expr {
        Expr::ArithOp {
            kind: ArithKind::Divide,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn modulo(l: Expr, r: Expr) -> Expr {
        Expr::ArithOp {
            kind: ArithKind::Modulo,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn eq_(l: Expr, r: Expr) -> Expr {
        Expr::Relation {
            kind: RelKind::Eq,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn gt(l: Expr, r: Expr) -> Expr {
        Expr::Relation {
            kind: RelKind::Gt,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn lt(l: Expr, r: Expr) -> Expr {
        Expr::Relation {
            kind: RelKind::Lt,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn bit_and(l: Expr, r: Expr) -> Expr {
        Expr::BitOp {
            kind: BitKind::And,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn bit_or(l: Expr, r: Expr) -> Expr {
        Expr::BitOp {
            kind: BitKind::Or,
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
    fn mcl(obj: Expr, name: &str, arg: Expr) -> Expr {
        Expr::MethodCallLike {
            obj: Box::new(obj),
            name: name.into(),
            args: vec![arg],
            pos: 0,
        }
    }
    fn mcl0args(obj: Expr, name: &str) -> Expr {
        Expr::MethodCallLike {
            obj: Box::new(obj),
            name: name.into(),
            args: vec![],
            pos: 0,
        }
    }
    fn ge(l: Expr, r: Expr) -> Expr {
        Expr::Relation {
            kind: RelKind::Ge,
            left: Box::new(l),
            right: Box::new(r),
            pos: 0,
        }
    }
    fn val(name: &str, given_type: SType, body: Expr) -> ValDef {
        ValDef {
            name: name.into(),
            given_type,
            body,
            pos: 0,
        }
    }
    fn val_expr(name: &str, given_type: SType, body: Expr) -> Expr {
        Expr::Val(Box::new(val(name, given_type, body)))
    }
    fn block(bindings: Vec<ValDef>, result: Expr) -> Expr {
        Expr::Block {
            bindings,
            result: Box::new(result),
            pos: 0,
        }
    }
    fn if_(condition: Expr, true_branch: Expr, false_branch: Expr) -> Expr {
        Expr::If {
            condition: Box::new(condition),
            true_branch: Box::new(true_branch),
            false_branch: Box::new(false_branch),
            pos: 0,
        }
    }
    fn lambda(args: Vec<(&str, SType)>, body: Expr) -> Expr {
        lambda_r(args, SType::NoType, body)
    }
    fn lambda_r(args: Vec<(&str, SType)>, given_res_type: SType, body: Expr) -> Expr {
        Expr::Lambda {
            args: args.into_iter().map(|(n, t)| (n.to_string(), t)).collect(),
            given_res_type,
            body: Box::new(body),
            pos: 0,
        }
    }

    /// Recursively set every `pos` (and `ValDef` pos) to 0 for shape-only
    /// comparison against the position-free helper constructors above.
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

    // ----- happy path -----

    #[test]
    fn atom_literals_map_to_constants() {
        // SigmaParserTest.scala:74-106, :612
        assert_eq!(strip_pos(&p("10")), int(10));
        assert_eq!(strip_pos(&p("10L")), long(10));
        assert_eq!(strip_pos(&p("true")), boolean(true));
        assert_eq!(strip_pos(&p("\"hello\"")), string("hello"));
        assert_eq!(strip_pos(&p("null")), string("null")); // Literals.scala:88
        assert_eq!(strip_pos(&p("()")), unit()); // grouping :145
        assert_eq!(strip_pos(&p("(1)")), int(1)); // :146 grouping, not tuple
    }

    #[test]
    fn tuple_and_tuple_access() {
        // SigmaParserTest.scala:148-162
        assert_eq!(strip_pos(&p("(1, 2)")), tuple(vec![int(1), int(2)]));
        assert_eq!(
            strip_pos(&p("(1, 2L)._1")),
            select(tuple(vec![int(1), long(2)]), "_1")
        );
        assert_eq!(
            strip_pos(&p("(1, 2L)(0)")),
            apply(tuple(vec![int(1), long(2)]), vec![int(0)])
        );
    }

    #[test]
    fn stableid_dotted_chain_folds_selects() {
        // Core.scala:62-69: `a.b.c` is one StableId -> nested Select.
        assert_eq!(
            strip_pos(&p("a.b.c")),
            select(select(ident0("a"), "b"), "c")
        );
    }

    #[test]
    fn call_select_typeapply_chains() {
        // SigmaParserTest.scala:348,560-573,604,324
        assert_eq!(
            strip_pos(&p("X[Int]")),
            apply_types(ident0("X"), vec![SType::SInt])
        );
        assert_eq!(
            strip_pos(&p("SELF.R1[Int]")),
            apply_types(select(ident0("SELF"), "R1"), vec![SType::SInt])
        );
        assert_eq!(
            strip_pos(&p("SELF.getReg[Int](1)")),
            apply(
                apply_types(select(ident0("SELF"), "getReg"), vec![SType::SInt]),
                vec![int(1)]
            )
        );
        assert_eq!(
            strip_pos(&p("Coll[Int]()")),
            apply(apply_types(ident0("Coll"), vec![SType::SInt]), vec![])
        );
        assert_eq!(
            strip_pos(&p("getVar[Coll[Byte]](10).get")),
            select(
                apply(
                    apply_types(ident0("getVar"), vec![SType::SColl(Box::new(SType::SByte))]),
                    vec![int(10)]
                ),
                "get"
            )
        );
        assert_eq!(strip_pos(&p("1.toByte")), select(int(1), "toByte")); // :604
        assert_eq!(
            strip_pos(&p("Coll(1, 2)")),
            apply(ident0("Coll"), vec![int(1), int(2)]) // :324 — no collection literal
        );
    }

    // ----- infix / prefix / postfix layers -----

    #[test]
    fn infix_left_assoc_chain() {
        // SigmaParserTest.scala:74-121, 775-820
        assert_eq!(
            strip_pos(&p("1-2-3-4-5")),
            minus(minus(minus(minus(int(1), int(2)), int(3)), int(4)), int(5))
        ); // :86
        assert_eq!(strip_pos(&p("10L-11L")), minus(long(10), long(11))); // :83
        assert_eq!(strip_pos(&p("(-10-11)")), minus(int(-10), int(11))); // :84 unary fold
        assert_eq!(strip_pos(&p("1 / 2")), divide(int(1), int(2))); // :88
        assert_eq!(strip_pos(&p("5 % 2")), modulo(int(5), int(2))); // :89
    }

    #[test]
    fn infix_precedence_and_methodcalllike() {
        assert_eq!(strip_pos(&p("1==1")), eq_(int(1), int(1))); // :92
        assert_eq!(
            strip_pos(&p("true && true")),
            mcl(boolean(true), "&&", boolean(true))
        ); // :95
        assert_eq!(
            strip_pos(&p("false || false || false")),
            mcl(
                mcl(boolean(false), "||", boolean(false)),
                "||",
                boolean(false)
            )
        );
        assert_eq!(
            strip_pos(&p("1 == 0 || 3 == 2")),
            mcl(eq_(int(1), int(0)), "||", eq_(int(3), int(2)))
        ); // :110
        assert_eq!(
            strip_pos(&p("3 - 2 > 2 - 1")),
            gt(minus(int(3), int(2)), minus(int(2), int(1)))
        ); // :112
        assert_eq!(
            strip_pos(&p("arr1 ++ arr2")),
            mcl(ident0("arr1"), "++", ident0("arr2"))
        ); // :102
        assert_eq!(strip_pos(&p("1 ^ 2")), mcl(int(1), "^", int(2))); // :810
        assert_eq!(strip_pos(&p("128 >> 2")), mcl(int(128), ">>", int(2))); // :816
    }

    #[test]
    fn gt_gets_precedence_six_not_five() {
        // spec-derived: Exprs.scala:150-151 duplicate '>' — later toMap entry wins,
        // so `>` (6) binds TIGHTER than `<` (5): a < b > c == a < (b > c)
        assert_eq!(
            strip_pos(&p("a < b > c")),
            lt(ident0("a"), gt(ident0("b"), ident0("c")))
        );
    }

    #[test]
    fn unary_ops_bind_atom_then_suffixes_wrap() {
        // :775-786 + recon-gap item 2
        assert_eq!(
            strip_pos(&p("-OUTPUTS.size")),
            negation(select(ident0("OUTPUTS"), "size"))
        );
        assert_eq!(
            strip_pos(&p("~OUTPUTS.size")),
            bit_inversion(select(ident0("OUTPUTS"), "size"))
        );
        assert_eq!(strip_pos(&p("!true")), logical_not(boolean(true)));
        assert_eq!(
            strip_pos(&p("-f(x)")),
            apply(negation(ident0("f")), vec![ident0("x")])
        ); // spec-derived
        assert_eq!(strip_pos(&p("-1.toByte")), select(int(-1), "toByte")); // spec-derived
        assert_eq!(strip_pos(&p("1 & 2")), bit_and(int(1), int(2))); // :806
        assert_eq!(strip_pos(&p("1 | 2")), bit_or(int(1), int(2))); // :808
    }

    #[test]
    fn postfix_lone_id_is_methodcalllike() {
        // spec-derived: Exprs.scala:99-116 (zero SigmaParserTest coverage — gap item 15)
        assert_eq!(strip_pos(&p("x id")), mcl0args(ident0("x"), "id"));
    }

    // ----- error paths -----

    #[test]
    fn unknown_ops_error_at_scala_positions() {
        let e = crate::parse("+1", 3).unwrap_err();
        assert_eq!(e.line_col("+1"), (1, 2)); // fail(:921)
        let e = crate::parse("1**1", 3).unwrap_err();
        assert_eq!(e.line_col("1**1"), (1, 1)); // fail(:923)
        assert!(crate::parse("true | false", 3).is_err()); // bit-op numeric guard (SP:84-88)
    }

    #[test]
    fn paren_errors_match_scala_positions() {
        // SigmaParserTest fail() table: the ")"/end-of-input positions.
        let e = crate::parse("(10", 3).unwrap_err();
        assert_eq!(e.line_col("(10"), (1, 4));
        let e = crate::parse("10)", 3).unwrap_err();
        assert_eq!(e.line_col("10)"), (1, 3));
    }

    // ----- Scala-cited edge cases (spec-derived) -----

    #[test]
    fn precedence_of_matches_scala_table() {
        // Exprs.scala:144-162 priorityList/priorityMap/precedenceOf. First char
        // only; letters/backtick/unmapped -> 0; the `>`-quirk lands `>` at 6.
        assert_eq!(precedence_of("|"), 1);
        assert_eq!(precedence_of("||"), 1);
        assert_eq!(precedence_of("^"), 2);
        assert_eq!(precedence_of("&"), 3);
        assert_eq!(precedence_of("&&"), 3);
        assert_eq!(precedence_of("=="), 4);
        assert_eq!(precedence_of("!="), 4);
        assert_eq!(precedence_of("<"), 5);
        assert_eq!(precedence_of("<="), 5);
        assert_eq!(precedence_of("<<"), 5);
        assert_eq!(precedence_of(">"), 6); // quirk: '>' is 6, not grouped with '<'
        assert_eq!(precedence_of(">="), 6);
        assert_eq!(precedence_of(">>>"), 6);
        assert_eq!(precedence_of(":"), 6);
        assert_eq!(precedence_of("+"), 7);
        assert_eq!(precedence_of("-"), 7);
        assert_eq!(precedence_of("++"), 7);
        assert_eq!(precedence_of("*"), 8);
        assert_eq!(precedence_of("/"), 8);
        assert_eq!(precedence_of("%"), 8);
        assert_eq!(precedence_of("`foo`"), 0); // backtick first char -> 0
        assert_eq!(precedence_of("foo"), 0); // letters -> 0
    }

    #[test]
    fn backtick_infix_op_is_rejected() {
        // Exprs.scala:92 `Id.!` captures a backtick op's raw text (precedence 0);
        // mkBinaryOp then rejects it as an "Unknown binary operation" (SP:99).
        assert!(crate::parse("a `foo` b", 3).is_err());
    }

    #[test]
    fn equal_precedence_is_left_associative() {
        // Exprs.scala:170 reduces when precedenceOf(op1) >= precedenceOf(op2): `+`
        // and `-` are both precedence 7, so `a - b + c` == `(a - b) + c`. `+` is a
        // parseAsMethod (SP:96) -> MethodCallLike; `-` -> ArithOp(Minus) (SP:82).
        assert_eq!(
            strip_pos(&p("a - b + c")),
            mcl(minus(ident0("a"), ident0("b")), "+", ident0("c"))
        );
    }

    #[test]
    fn postfix_lone_id_consumes_trailing_newline() {
        // PostFix `~ Newline.?` (Exprs.scala:100): a single trailing newline after
        // the postfix ident is consumed; the result is MethodCallLike(x, id, []).
        assert_eq!(strip_pos(&p("x id\n")), mcl0args(ident0("x"), "id"));
    }

    #[test]
    fn infix_op_newline_gated_by_context() {
        // NoSemis (Exprs.scala:93,100): in StatCtx an infix op may not begin on a
        // new line, so `a\n- b` parses only `a` and leaves `- b` -> End error.
        assert!(crate::parse("a\n- b", 3).is_err());
        // In ExprCtx (inside parens) NoSemis = Pass, so `a\n- b` IS `a - b`.
        assert_eq!(strip_pos(&p("(a\n- b)")), minus(ident0("a"), ident0("b")));
    }

    #[test]
    fn suffix_select_accepts_postdot_banned_words() {
        // ExprSuffix `.` accepts ANY Id incl. `type`/`_` — PostDotCheck (which bans
        // them in StableId) does NOT apply once the StableId has ended
        // (Exprs.scala:80; Core.scala:61). So `a.type` and `a._` are field selects.
        assert_eq!(strip_pos(&p("a.type")), select(ident0("a"), "type"));
        assert_eq!(strip_pos(&p("a._")), select(ident0("a"), "_"));
    }

    #[test]
    fn stableid_keyword_as_field_selects() {
        // `val`/`def` are Idents lexically (recon-lexical.md §2.3), so `a.val`
        // selects a field named "val" via StableId (Core.scala:62-69).
        assert_eq!(strip_pos(&p("a.val")), select(ident0("a"), "val"));
    }

    #[test]
    fn empty_type_args_apply() {
        // TypeArgs `rep(0)` (Types.scala:117): `X[]` is a legal empty type-app.
        assert_eq!(strip_pos(&p("X[]")), apply_types(ident0("X"), vec![]));
    }

    #[test]
    fn arglist_trailing_comma_before_newline() {
        // TrailingComma (Literals.scala:63): a trailing comma is legal only before a
        // Newline. `f(1,\n)` -> Apply(f, [1]).
        assert_eq!(strip_pos(&p("f(1,\n)")), apply(ident0("f"), vec![int(1)]));
        // Without the newline it is a parse error (the closer expects a `)`).
        assert!(crate::parse("f(1,)", 3).is_err());
    }

    #[test]
    fn arglist_multiline_separator_commas_are_not_trailing() {
        // Regression (SigmaParserTest.scala:848 "outerJoin"): `Exprs = Expr.rep(1,
        // ",")` treats a comma as a SEPARATOR whenever another Expr follows across a
        // newline (ExprCtx whitespace absorbs newlines), so `f(a,\nb)` is [a, b] —
        // NOT the trailing-comma reduction [a]. The bug was checking
        // comma_then_newline() before trying `, ~ Expr`.
        assert_eq!(
            strip_pos(&p("f(1,\n2)")),
            apply(ident0("f"), vec![int(1), int(2)])
        );
        assert_eq!(
            strip_pos(&p("f(\n1,\n2,\n3\n)")),
            apply(ident0("f"), vec![int(1), int(2), int(3)])
        );
        // A genuine trailing comma before the closer still reduces (unchanged).
        assert_eq!(strip_pos(&p("f(1,\n)")), apply(ident0("f"), vec![int(1)]));
    }

    #[test]
    fn arglist_newline_gated_by_context() {
        // NoSemis (Exprs.scala:82): in StatCtx an arg-list may not start on a new
        // line, so `f\n(x)` leaves `(x)` dangling -> End error.
        assert!(crate::parse("f\n(x)", 3).is_err());
        // In ExprCtx (inside parens) NoSemis = Pass, so `f\n(x)` IS an application.
        assert_eq!(
            strip_pos(&p("(f\n(x))")),
            apply(ident0("f"), vec![ident0("x")])
        );
    }

    #[test]
    fn char_and_symbol_literals_are_strings() {
        // Literals.scala:94-101,119: `'c'`/`'sym` retain the leading `'` and become
        // StringConst (CharSym raw form; strip only removes leading `"`).
        assert_eq!(strip_pos(&p("'a'")), string("'a'"));
        assert_eq!(strip_pos(&p("'sym")), string("'sym"));
    }

    #[test]
    fn annotation_arguments_parse_and_discard() {
        // Step 5 (Types.scala:159,168): an annotation's `(Exprs)` argument group is
        // parsed via the expression parser and DISCARDED; the annotated type is
        // unchanged.
        assert_eq!(parse_type("Int @foo(1, 2)", 3).unwrap(), SType::SInt);
        // Zero-arg and empty-arg-group forms also discard cleanly.
        assert_eq!(parse_type("Int @foo", 3).unwrap(), SType::SInt);
        assert_eq!(parse_type("Int @foo()", 3).unwrap(), SType::SInt);
    }

    // ----- blocks, val/def, lambdas, if -----

    #[test]
    fn block_val_and_newline_separators() {
        // SigmaParserTest.scala:169-189
        assert_eq!(
            strip_pos(&p("{val X = 10; 3 > 2}")),
            block(vec![val("X", SType::NoType, int(10))], gt(int(3), int(2)))
        );
        assert_eq!(
            strip_pos(&p("{val X = 10\n3 > 2}")),
            block(vec![val("X", SType::NoType, int(10))], gt(int(3), int(2)))
        );
        assert_eq!(
            strip_pos(&p("{val X: Byte = 10; 3 > 2}")),
            block(vec![val("X", SType::SByte, int(10))], gt(int(3), int(2)))
        );
        assert_eq!(
            strip_pos(&p("{val X: (Int, Boolean) = (10, true); 3 > 2}")),
            block(
                vec![val(
                    "X",
                    SType::STuple(vec![SType::SInt, SType::SBoolean]),
                    tuple(vec![int(10), boolean(true)])
                )],
                gt(int(3), int(2))
            )
        );
    }

    #[test]
    fn block_comments_do_not_separate() {
        // SigmaParserTest.scala:219-228
        let src = "{\n// line comment\nval X = 12\n/* comment // nested line comment\n*/\n3 - // end line comment\n  2\n}";
        assert_eq!(
            strip_pos(&p(src)),
            block(
                vec![val("X", SType::NoType, int(12))],
                minus(int(3), int(2))
            )
        );
    }

    #[test]
    fn if_else_and_chain() {
        // SigmaParserTest.scala:232-233
        assert_eq!(
            strip_pos(&p("if(true) 1 else 2")),
            if_(boolean(true), int(1), int(2))
        );
        assert_eq!(
            strip_pos(&p("if(true) 1 else if(X==Y) 2 else 3")),
            if_(
                boolean(true),
                int(1),
                if_(eq_(ident0("X"), ident0("Y")), int(2), int(3))
            )
        );
    }

    #[test]
    fn lambdas_block_forms() {
        // SigmaParserTest.scala:356-393
        assert_eq!(
            strip_pos(&p("{ (x) => x - 1 }")),
            lambda(vec![("x", SType::NoType)], minus(ident0("x"), int(1)))
        );
        assert_eq!(
            strip_pos(&p("{ (x: Int) => x - 1 }")),
            lambda(vec![("x", SType::SInt)], minus(ident0("x"), int(1)))
        );
        assert_eq!(
            strip_pos(&p("{ (x: Int) => { x - 1 } }")),
            lambda(
                vec![("x", SType::SInt)],
                block(vec![], minus(ident0("x"), int(1)))
            )
        );
        assert_eq!(
            strip_pos(&p("{ (x: Int) =>  val y = x - 1; y }")),
            lambda(
                vec![("x", SType::SInt)],
                block(
                    vec![val("y", SType::NoType, minus(ident0("x"), int(1)))],
                    ident0("y")
                )
            )
        );
    }

    #[test]
    fn lambda_argument_sugar_three_forms_equal() {
        // SigmaParserTest.scala:403-413
        let expected = apply(
            select(ident0("arr"), "exists"),
            vec![lambda(vec![("a", SType::SInt)], ge(ident0("a"), int(1)))],
        );
        assert_eq!(
            strip_pos(&p("arr.exists ({ (a: Int) => a >= 1 })")),
            expected
        );
        assert_eq!(strip_pos(&p("arr.exists { (a: Int) => a >= 1 }")), expected);
    }

    #[test]
    fn def_is_val_holding_lambda() {
        // SigmaParserTest.scala:453-459, 511-512
        assert_eq!(
            strip_pos(&p("{ def f(x: Int): Int = x - 1 }")),
            block(
                vec![],
                val_expr(
                    "f",
                    SType::SInt,
                    lambda_r(
                        vec![("x", SType::SInt)],
                        SType::SInt,
                        minus(ident0("x"), int(1))
                    )
                )
            )
        );
        assert_eq!(
            strip_pos(&p("{ def f(x: Int) = x - 1 }")),
            block(
                vec![],
                val_expr(
                    "f",
                    SType::NoType,
                    lambda_r(
                        vec![("x", SType::SInt)],
                        SType::NoType,
                        minus(ident0("x"), int(1))
                    )
                )
            )
        );
        assert_eq!(
            strip_pos(&p("{ def f: Int = 1 }")),
            block(
                vec![],
                val_expr("f", SType::SInt, lambda_r(vec![], SType::SInt, int(1)))
            )
        );
    }

    #[test]
    fn zkproof_requires_block() {
        // SigmaParserTest.scala:652, fail :660
        assert_eq!(
            strip_pos(&p("ZKProof { proveDlog(g) }")),
            apply(
                Expr::Ident {
                    name: "ZKProof".into(),
                    tpe: SType::SFunc {
                        dom: vec![SType::SSigmaProp],
                        range: Box::new(SType::SBoolean),
                        tpe_params: vec![],
                    },
                    pos: 0
                },
                vec![apply(ident0("proveDlog"), vec![ident0("g")])]
            )
        );
        let e = crate::parse("ZKProof 1 > 1", 3).unwrap_err();
        assert_eq!(e.line_col("ZKProof 1 > 1"), (1, 9));
    }

    #[test]
    fn empty_block_rejects_without_semi() {
        // extractBlockStats' empty arm (Exprs.scala:271-272) is reachable only via
        // an explicit ';' — bare {} fails in fastparse before reaching it
        // (oracle-verified). Reject position = one past the closing `}`.
        let e = crate::parse("{}", 3).unwrap_err();
        assert_eq!(e.line_col("{}"), (1, 3)); // oracle: ParserOracle sigma-state 6.0.2
        let e = crate::parse("{ }", 3).unwrap_err();
        assert_eq!(e.line_col("{ }"), (1, 4)); // oracle: ParserOracle sigma-state 6.0.2
        let e = crate::parse("{\n}", 3).unwrap_err();
        assert_eq!(e.line_col("{\n}"), (2, 2)); // oracle: ParserOracle sigma-state 6.0.2
        let e = crate::parse("{/*c*/}", 3).unwrap_err();
        assert_eq!(e.line_col("{/*c*/}"), (1, 8)); // oracle: ParserOracle sigma-state 6.0.2
    }

    #[test]
    fn empty_block_with_semi_is_unit() {
        // A literal ';' rescues the empty block into Block([], ()) — the only path
        // that reaches extractBlockStats' empty arm (Exprs.scala:271-272).
        assert_eq!(strip_pos(&p("{;}")), block(vec![], unit())); // oracle: ParserOracle sigma-state 6.0.2
        assert_eq!(strip_pos(&p("{ ; }")), block(vec![], unit())); // oracle: ParserOracle sigma-state 6.0.2
    }

    // ----- blocks and lambdas — error paths -----

    #[test]
    fn block_and_lambda_rejections_at_scala_positions() {
        let e = crate::parse("{ val X", 3).unwrap_err();
        assert_eq!(e.line_col("{ val X"), (1, 8)); // fail :588
        let e = crate::parse("{val (a,b) = (1,2)}", 3).unwrap_err();
        assert_eq!(e.line_col("{val (a,b) = (1,2)}"), (1, 6)); // fail :921
        let e = crate::parse("{1 ; 1 == 1}", 3).unwrap_err();
        assert_eq!(e.line_col("{1 ; 1 == 1}"), (1, 2)); // fail :949
        assert!(crate::parse("arr.exists { a => a >= 1 }", 3).is_err()); // :600
        let e = crate::parse("arr.exists ( (a: Int) => a >= 1 )", 3).unwrap_err();
        assert_eq!(e.line_col("arr.exists ( (a: Int) => a >= 1 )"), (1, 16)); // :597
                                                                              // D5: block-lambda in non-first chunk is a reject (Scala: MatchError crash).
        assert!(crate::parse("{ val a = 1; (x: Int) => x }", 3).is_err());
    }

    #[test]
    fn one_nl_max_bc_before_only_poisons_when_newline_consumed() {
        // Round-12 fix: bc_before poisons one_nl_max ONLY when it consumed a Newline.
        //
        // (a) later-chunk block-lambda head via newline+comment gap → REJECT
        //     oracle: ParserOracle sigma-state 6.0.2 → REJECT 0:0
        //     The block body's Semis already consumed the `\n`, so one_nl_max at `(`
        //     sees zero newlines — bc_before is ignored — the head IS detected and
        //     reject_chunk_lambda_head fires.
        assert!(crate::parse("{ val x = 1\n/*c*/(x,y)=>x }", 3).is_err());
        // (b) semicolon-separated (same chunk) lambda with trailing comment → ACCEPT
        //     oracle: ParserOracle sigma-state 6.0.2 → ACCEPT
        //     `;` is in the same chunk; no newline crosses one_nl_max; bc_before is
        //     false on `(` (comment precedes no newline in that gap).
        assert!(crate::parse("{ val x = 1; /*c*/(x,y)=>x }", 3).is_ok());
        // (c) infix op across newline+comment without trailing newline → REJECT
        //     oracle: ParserOracle sigma-state 6.0.2 → REJECT 2:6
        //     one_nl_max consumes the `\n`, then sees bc_before on `b` → poison.
        assert!(crate::parse("a +\n/*c*/b", 3).is_err());
        // (d) infix op across comment+newline (comment terminates with newline) → ACCEPT
        //     oracle: ParserOracle sigma-state 6.0.2 → ACCEPT
        //     bc_before is not set (the block comment IS followed by a newline).
        assert!(crate::parse("a + /*c*/\nb", 3).is_ok());
        // (e) type-level infix across newline+comment → REJECT (shared one_nl_max)
        //     oracle: ParserOracle sigma-state 6.0.2 → REJECT 2:6
        //     Goes through `types::infix_type`, not the expression grammar: `Int`/
        //     `Long` here are types, and `+` is the type-level infix operator.
        assert!(crate::parse_type("Int +\n/*c*/Long", 3).is_err());
    }

    // ----- blocks and lambdas — Scala-cited edge cases -----

    #[test]
    fn block_result_may_be_a_val() {
        // extractBlockStats (Exprs.scala:262-273): the LAST stat may itself be a Val.
        assert_eq!(
            strip_pos(&p("{ val x = 1 }")),
            block(vec![], val_expr("x", SType::NoType, int(1)))
        );
    }

    #[test]
    fn block_mixed_separators_and_multi_val() {
        // Semis = (';' | Newline+)+ (Literals.scala:50-51): `;` and newline mix.
        assert_eq!(
            strip_pos(&p("{ val a = 1\n val b = 2; a }")),
            block(
                vec![
                    val("a", SType::NoType, int(1)),
                    val("b", SType::NoType, int(2))
                ],
                ident0("a")
            )
        );
    }

    #[test]
    fn block_lazy_and_annotation_prelude_ignored() {
        // Prelude = Annot.rep ~ `lazy`.? (Exprs.scala:257) — parsed and ignored.
        assert_eq!(
            strip_pos(&p("{ lazy val x = 1; x }")),
            block(vec![val("x", SType::NoType, int(1))], ident0("x"))
        );
        assert_eq!(
            strip_pos(&p("{ @foo val x = 1; x }")),
            block(vec![val("x", SType::NoType, int(1))], ident0("x"))
        );
    }

    #[test]
    fn nested_block_as_statement() {
        // BlockExpr nests: a `{ … }` is an ordinary statement/result.
        assert_eq!(
            strip_pos(&p("{ val x = 1; { x } }")),
            block(
                vec![val("x", SType::NoType, int(1))],
                block(vec![], ident0("x"))
            )
        );
    }

    #[test]
    fn def_backtracks_to_ident_when_not_a_fundef() {
        // Fun = `def` ~ FunDef with NO cut (Exprs.scala:55): `def` alone backtracks
        // to an ordinary identifier via PostfixLambda.
        assert_eq!(strip_pos(&p("def")), ident0("def"));
    }

    #[test]
    fn def_extra_arg_lists_are_dropped() {
        // FunDef quirk (Exprs.scala:220 args.headOption): with no dotty subject the
        // extra `(b: Int)` list is silently dropped, keeping only `a`.
        assert_eq!(
            strip_pos(&p("def f(a: Int)(b: Int) = a")),
            val_expr(
                "f",
                SType::NoType,
                lambda_r(vec![("a", SType::SInt)], SType::NoType, ident0("a"))
            )
        );
    }

    #[test]
    fn expr_tuple_lambda_arrow_and_eq_forms() {
        // PostfixLambda (Exprs.scala:65-70): `(a,b) => e` wraps the body via a
        // semi-inference LambdaRhs → block([e]) = Block([], e) (mkBlock never
        // unwraps, SigmaBuilder.scala:522-523).
        assert_eq!(
            strip_pos(&p("(a, b) => a")),
            lambda(
                vec![("a", SType::NoType), ("b", SType::NoType)],
                block(vec![], ident0("a"))
            )
        );
        // SuperPostfixSuffix `= Expr` (Exprs.scala:77) uses a raw `Expr` body.
        assert_eq!(
            strip_pos(&p("(a, b) = a")),
            lambda(
                vec![("a", SType::NoType), ("b", SType::NoType)],
                ident0("a")
            )
        );
    }

    #[test]
    fn postfix_lambda_sym_kw_forms_accept() {
        // postfix_lambda must use at_sym_kw (not at_kw) so that comment-adjacent and
        // Unicode-arrow forms are matched. Oracle-pinned via ParserOracle.scala:
        //
        // oracle: `(a,b)\n⇒b`           → ACCEPT (U+21D2 lexes OpId, not Kw::FatArrow)
        // oracle: `(a,b)\n=>/*c*/b`      → ACCEPT (comment-adjacent => lexes OpId)
        // oracle: `(a,b)\n=/*c*/b`       → ACCEPT (comment-adjacent = lexes OpId)
        let body_a = lambda(
            vec![("a", SType::NoType), ("b", SType::NoType)],
            block(vec![], ident0("b")),
        );
        let body_eq = lambda(
            vec![("a", SType::NoType), ("b", SType::NoType)],
            ident0("b"),
        );
        // Unicode ⇒
        assert_eq!(strip_pos(&p("(a,b)\n\u{21D2}b")), body_a);
        // comment-adjacent =>
        assert_eq!(strip_pos(&p("(a,b)\n=>/*c*/b")), body_a);
        // comment-adjacent = (SuperPostfixSuffix — raw Expr body, not LambdaRhs block)
        assert_eq!(strip_pos(&p("(a,b)\n=/*c*/b")), body_eq);
    }

    #[test]
    fn non_tuple_lhs_lambda_is_rejected() {
        // lhs not a Tuple + a body present → "Invalid declaration of lambda" (:69).
        assert!(crate::parse("x => e", 3).is_err());
    }

    #[test]
    fn entry_trailing_newline_ok_but_semicolon_errors() {
        // spec-derived (SigmaParser.scala:114-117): `StatCtx.Expr ~ End` skips
        // trailing Newlines but not a trailing `;`.
        assert_eq!(strip_pos(&p("1\n")), int(1));
        assert!(crate::parse("1;", 3).is_err());
    }

    // ----- FunTypeArgs grammar (Finding A, Types.scala:143,153-165) -----

    #[test]
    fn def_typeargs_empty_brackets_errors() {
        // FunTypeArgs = "[" ~/ (Annot.rep ~ TypeArg).rep(1, ",") … (Types.scala:143):
        // the `.rep(1)` requires one TypeArg, so `[]` is rejected after the `[` cut.
        // (The `def` non-cut backtrack then re-parses `def` as an Ident, but the
        // block's trailing `f[](x: Int) = x` still fails — reject overall.)
        assert!(crate::parse("{ def f[](x: Int) = x; 1 }", 3).is_err());
    }

    #[test]
    fn def_typeargs_numeric_errors() {
        // TypeArg head = (Id | `_`) (Types.scala:155): a numeric literal is not an
        // Id, so `[123]` is rejected after the `[` cut.
        assert!(crate::parse("def f[123](x: Int) = x", 3).is_err());
    }

    #[test]
    fn def_typeargs_wellformed_discarded() {
        // `[T, U <: Int]` parses via the real TypeArg grammar (TypeBounds `<: Int`)
        // and is DISCARDED — only the value args survive on the Lambda.
        assert_eq!(
            strip_pos(&p("{ def f[T, U <: Int](x: Int): Int = x; 1 }")),
            block(
                vec![val(
                    "f",
                    SType::SInt,
                    lambda_r(vec![("x", SType::SInt)], SType::SInt, ident0("x"))
                )],
                int(1)
            )
        );
    }

    // ----- Extractor-arg silent drop (Finding B, Exprs.scala:236) -----

    #[test]
    fn val_extractor_args_binds_name_silently_dropping() {
        // Extractor = StableId ~ TupleEx.? (Exprs.scala:236): the TupleEx is dropped,
        // so a single-segment id binds a val of that NAME (`Some`) — a token-dropping
        // quirk, but the reference behavior.
        assert_eq!(
            strip_pos(&p("{ val Some(x) = 1; 2 }")),
            block(vec![val("Some", SType::NoType, int(1))], int(2))
        );
    }

    #[test]
    fn val_dotted_extractor_still_errors() {
        // A DOTTED StableId (`a.b`) folds to a Select — a non-Ident pattern → "Only
        // single name patterns supported" (SigmaParser.scala:31-32). Unchanged.
        assert!(crate::parse("{ val a.b(x) = 1; 2 }", 3).is_err());
    }

    #[test]
    fn val_extractor_bad_inner_pattern_errors() {
        // TupleEx = "(" ~/ Pattern.rep(0, ",") ~ … (Exprs.scala:235): the args are
        // parsed with the real pattern grammar, not a balanced scan. `123` starts no
        // Pattern, so rep(0) matches nothing and the `)` closer fails at `123` after
        // the `(` cut — a hard reject (matching Scala). NB the dispatch suggested
        // `%%%`, but `%%%` is a valid symbolic StableId (Operator, Identifiers.scala:22)
        // that Scala's Extractor accepts, so rejecting it would DIVERGE; `123` is a
        // genuinely un-parseable inner pattern in both.
        assert!(crate::parse("{ val Some(123) = 1; 2 }", 3).is_err());
    }

    // ----- LambdaRhs leading BlockLambda drop (Finding C, Exprs.scala:59-60) -----

    #[test]
    fn lambda_rhs_leading_blocklambda_head_silently_dropped() {
        // LambdaRhs BlockChunk = BlockLambda.rep ~ BlockStat.rep; the `case (_, b)`
        // map (Exprs.scala:59-60) DISCARDS the leading `(a) =>` head, so the body is
        // just `c` — wrapped via block() like every semi-inference LambdaRhs
        // (→ Block([], c), matching `(a,b) => e`).
        assert_eq!(
            strip_pos(&p("(x, y) => (a) => c")),
            lambda(
                vec![("x", SType::NoType), ("y", SType::NoType)],
                block(vec![], ident0("c"))
            )
        );
    }

    // ----- corpus-parity regressions -----

    #[test]
    fn if_expr_is_a_valid_paren_and_arg_item() {
        // Exprs.scala:46 `Expr = If | Fun | PostfixLambda`: `if` is a full-Expr head,
        // so it is a legal Parened item / call argument. The narrower `starts_expr`
        // guard (SimpleExpr only) wrongly rejected these — Dexy `lp/pool/swap.es`
        // (`&& ( if … )`) and Rosen `Collateral.es`/`RwtRepo.es` (`Coll( …, if … )`).
        assert!(crate::parse("Coll(if (x > 1) 1 else 2)", 3).is_ok());
        assert!(crate::parse("Coll(if (x > 1) {c} else {d})", 3).is_ok());
        assert!(crate::parse("a == 0 && ( if (x > 0) 1 else 2 )", 3).is_ok());
        assert!(crate::parse("allOf(Coll(a == b, if (x > 1) {c} else {d}))", 3).is_ok());
    }

    #[test]
    fn top_level_zero_progress_failure_reports_one_one() {
        // fastparse `Expr ~ End`: an unparsable FIRST token preceded only by
        // whitespace/comments fails at index 0 (`1:1`), not the token's offset — the
        // `@contract`/`@test` LSP template files. Once a token is consumed the real
        // furthest position stands.
        for src in ["@x", "   @x", "/* c */ @x", "/*\n c\n*/\n@x"] {
            let e = crate::parse(src, 3).expect_err("must reject");
            assert_eq!(e.line_col(src), (1, 1), "src={src:?}");
        }
        // A consumed token keeps the real position (reported by the tail `End` check).
        let e = crate::parse("1 @x", 3).expect_err("must reject");
        assert_eq!(e.line_col("1 @x"), (1, 3));
    }

    #[test]
    fn val_binding_double_eq_rejects_after_the_first_eq() {
        // `` `=` `` = O("=") = `"=" ~ !OpChar` (Core.scala:25): on `==` the `=`
        // matches and the `!OpChar` lookahead fails one char later — ChainCash
        // `layer2-old/reserve.es` (`val redemptionInputOk == …`) rejects at the 2nd `=`.
        let src = "{ val x == y }";
        let e = crate::parse(src, 3).expect_err("must reject");
        assert_eq!(e.line_col(src), (1, 10));
    }

    #[test]
    fn val_def_fatarrow_reports_scala_position() {
        // expect_assign: O("=") = `"=" ~ !OpChar` (Core.scala:25). ASCII `=>`
        // FatArrow: `=` matches at t.start, `!OpChar` fails at t.start+1 (the `>`).
        // `{ val x => 1; 2 }`: `=>` is at byte 8 (0-indexed), so error is at byte 9
        // → line 1, col 10 (1-based).
        let src = "{ val x => 1; 2 }";
        let e = crate::parse(src, 3).expect_err("must reject");
        assert_eq!(e.line_col(src), (1, 10));
    }

    // ----- structural-nesting depth guard (M6, ParseError::TooDeep) -----

    /// `n` levels of parenthesized nesting around a leaf integer, e.g.
    /// `nested_parens(3)` = `"(((1)))"`. Each level costs exactly one extra
    /// `expr()` call (`simple_expr` -> `parened` -> `expr_list` -> `expr`), so
    /// this is an exact (not approximate) proxy for `Cursor::depth`: `n`
    /// parens reach max depth `n + 1` (the outermost `parse()` call is
    /// already depth 1 before any paren is seen).
    fn nested_parens(n: usize) -> String {
        let mut s = String::with_capacity(2 * n + 1);
        s.push_str(&"(".repeat(n));
        s.push('1');
        s.push_str(&")".repeat(n));
        s
    }

    #[test]
    fn depth_guard_accepts_nesting_up_to_the_limit() {
        // MAX_PARSE_DEPTH - 1 parens reach max depth EXACTLY MAX_PARSE_DEPTH
        // (the outer `parse()` call is depth 1) -- must still parse; the
        // guard only rejects depth that EXCEEDS the cap, never depth AT it.
        let src = nested_parens(MAX_PARSE_DEPTH - 1);
        assert!(
            crate::parse(&src, 3).is_ok(),
            "nesting exactly at the cap must still parse"
        );
    }

    #[test]
    fn depth_guard_rejects_one_past_the_limit() {
        // MAX_PARSE_DEPTH parens reach max depth MAX_PARSE_DEPTH + 1 -- one
        // past the cap, must reject with the exact depth that tripped it.
        let src = nested_parens(MAX_PARSE_DEPTH);
        let e = crate::parse(&src, 3).expect_err("nesting one past the cap must reject");
        match e {
            ParseError::TooDeep { depth, .. } => assert_eq!(depth, MAX_PARSE_DEPTH + 1),
            other => panic!("expected TooDeep, got {other:?}"),
        }
    }

    #[test]
    fn depth_guard_also_bounds_nested_type_annotations() {
        // `type_()` shares the SAME `Cursor::depth` counter as `expr()` (both
        // are structural-nesting recursion families in this file, per
        // `MAX_PARSE_DEPTH`'s doc) -- a pathological `Coll[Coll[...]]` type
        // ascription is an INDEPENDENT recursion path from `expr()` (reached
        // via `val_def`'s `(`:` ~/ Type)` ascription, not through any nested
        // `expr()` call), so this regression proves the shared cap still
        // catches it rather than only guarding paren/block/lambda nesting.
        let mut ty = "Int".to_string();
        for _ in 0..(MAX_PARSE_DEPTH + 10) {
            ty = format!("Coll[{ty}]");
        }
        let src = format!("{{ val x: {ty} = 1; x }}");
        let e = crate::parse(&src, 3).expect_err("deeply nested type ascription must reject");
        assert!(
            matches!(e, ParseError::TooDeep { .. }),
            "expected TooDeep, got {e:?}"
        );
    }

    #[test]
    fn corpus_deepest_contract_still_parses() {
        // A crude bracket/brace-nesting proxy scan (string/comment aware)
        // over the vendored ~79-contract corpus (`test-vectors/ergoscript/
        // corpus`, see `../../ergo-compiler/tests/corpus_smoke.rs`) puts
        // `rosen-bridge/RwtRepo.es` at the deepest structural nesting --
        // around a dozen levels, nowhere near `MAX_PARSE_DEPTH` (128).
        // Regression-pins that specific real deployed contract; the FULL
        // corpus's accept/reject verdicts (all ~79 files) are re-checked
        // post-guard by `corpus_smoke.rs`'s `corpus_verdict_parity`, which
        // this test complements rather than duplicates.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("test-vectors/ergoscript/corpus/rosen-bridge/RwtRepo.es");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        assert!(
            crate::parse(&src, 3).is_ok(),
            "the corpus's deepest-nested real contract must still parse after the depth guard"
        );
    }
}
