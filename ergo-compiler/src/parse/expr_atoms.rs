use crate::ast::Expr;
use crate::error::ParseError;
use crate::stype::SType;
use crate::token::{Kw, Token, TokenKind};

use super::*;

// =============================================================================
// Expression grammar: atoms (SimpleExpr) and the postfix suffix machinery
// (ExprSuffix / applySuffix). Exprs.scala:46-132, 191-211, 315-320; Core.scala:62-69.
// =============================================================================

/// Expression parsing context (Exprs.scala:27-31). Semicolon inference is on in
/// statement positions and off inside nested expressions; it gates the
/// `NoSemis`/`OneSemiMax` combinators (Exprs.scala:42-43).
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Ctx {
    /// `StatCtx` — top level / inside a `{}` block (semiInference = true).
    Stat,
    /// `ExprCtx` — nested in another expression: parens, arg-lists, annotation
    /// arguments, the `if` condition (semiInference = false).
    Expr,
    /// `FreeCtx` — the RHS of `val x = …` / `def f = …` (semiInference = true,
    /// Exprs.scala:31). Behaves like `Stat` for semicolon inference but is a
    /// distinct context, mirroring the reference.
    Free,
}

impl Ctx {
    /// `semiInference` (Exprs.scala:40): true for `StatCtx` and `FreeCtx`.
    pub(crate) fn semi_inference(self) -> bool {
        matches!(self, Ctx::Stat | Ctx::Free)
    }
}

/// One postfix `ExprSuffix` marker (Exprs.scala:79-83), folded by `apply_suffix`.
///
/// The markers carry no positions: every node `apply_suffix` builds takes
/// `pos = f.pos()` (Scala pins `builder.currentSrcCtx = f.sourceContext` for the
/// whole fold, Exprs.scala:192), so a marker's own captured index is discarded.
pub(crate) enum Suffix {
    /// `.id` → `mkSelect(acc, name)` (Exprs.scala:80).
    Select { name: String },
    /// `[T,…]` → `mkApplyTypes(acc, args)` (Exprs.scala:81).
    TypeApply { args: Vec<SType> },
    /// `(…)` → `mkApply` (Exprs.scala:315-319). `None` = `()` (unit carrier);
    /// `Some(xs)` = the tuple carrier `apply_suffix` unwraps into the arg list.
    Args { tuple: Option<Vec<Expr>> },
    /// `{ … }` → a block argument, e.g. `f { … }` (Exprs.scala:320); handled with
    /// the ZKProof special case in `apply_suffix`.
    BlockArg { block: Expr },
}

/// A token that can begin a `SimpleExpr` (Exprs.scala:120-132): a `BlockExpr` `{`,
/// an `ExprLiteral`, a `StableId` head (`Id`), the `_` atom, or a `Parened` `(`.
pub(crate) fn starts_expr(t: &Token) -> bool {
    matches!(
        t.kind,
        TokenKind::LParen
            | TokenKind::LBrace
            | TokenKind::IntLit(_)
            | TokenKind::LongLit(_)
            | TokenKind::Str(_)
            | TokenKind::CharSym(_)
            | TokenKind::Kw(Kw::True)
            | TokenKind::Kw(Kw::False)
    ) || is_id(t)
}

/// A token that can begin a full `Expr` (Exprs.scala:46: `If | Fun | PostfixLambda`),
/// as opposed to `starts_expr` which covers only the `SimpleExpr` atom head. The one
/// extra head is the reserved `if` — `Fun`'s `def` is an `Ident`/word and
/// `PostfixLambda`'s prefix operators (`-`/`!`/`~`) are `OpId`s, both already
/// `is_id`. Used at the guards that parse a full `Expr` item (Parened / `Exprs`
/// arg-lists, annotation arguments, the `=>`-rhs `Expr.?`), where `if` is legal
/// (`Coll(if (c) a else b)`, `f && (if (c) a else b)` — Dexy `swap`, Rosen
/// `Collateral`/`RwtRepo`).
pub(crate) fn starts_full_expr(t: &Token) -> bool {
    starts_expr(t) || t.kind == TokenKind::Kw(Kw::If)
}

/// `ExprLiteral` → constant node (Literals.scala:70-124). Returns `None` when the
/// token is not a literal, so the caller falls through to `StableId`.
///
/// `null` maps to `StringConst("null")` (Literals.scala:88) — but ONLY here, in
/// literal-atom position; `ExprLiteral` precedes `StableId` in `SimpleExpr`, so a
/// bare `null` is a literal, while a `null` used as a binder name in a block stays an
/// ordinary Ident. `Str` carries the already-stripped value; `CharSym` carries the
/// raw `'…'` form (strip only removes leading `"`, Literals.scala:119-124) — both
/// become `StringConst`. Positions are the token start.
pub(crate) fn try_literal(t: &Token, src: &str) -> Option<Expr> {
    let pos = t.start;
    match &t.kind {
        TokenKind::IntLit(v) => Some(Expr::IntConst { value: *v, pos }),
        TokenKind::LongLit(v) => Some(Expr::LongConst { value: *v, pos }),
        TokenKind::Kw(Kw::True) => Some(Expr::BoolConst { value: true, pos }),
        TokenKind::Kw(Kw::False) => Some(Expr::BoolConst { value: false, pos }),
        TokenKind::Str(s) => Some(Expr::StringConst {
            value: s.clone(),
            pos,
        }),
        TokenKind::CharSym(s) => Some(Expr::StringConst {
            value: s.clone(),
            pos,
        }),
        TokenKind::Ident if t.text(src) == "null" => Some(Expr::StringConst {
            value: "null".to_string(),
            pos,
        }),
        _ => None,
    }
}

/// Depth-guarded entry point for [`expr_impl`] -- every recursive call in
/// this module goes through here (not `expr_impl` directly), so the shared
/// `Cursor::depth` counter (`MAX_PARSE_DEPTH`) bounds every nesting path:
/// parens, blocks, `if`/`else` branches, lambda bodies, `val`/`def` right-hand
/// sides. See `MAX_PARSE_DEPTH`'s doc for why one counter at this single
/// choke point covers the whole pipeline.
pub(crate) fn expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
    with_depth_guard(c, |c| expr_impl(c, ctx))
}

/// `Expr` (Exprs.scala:46-75): `If | Fun | PostfixLambda`. Ordered choice by
/// leading token: a reserved `if`, the word `def`, else the postfix/lambda layer.
/// `parse`, `Parened` and `ArgList` all route their sub-expressions through here.
pub(crate) fn expr_impl(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
    // If — `if` is a reserved keyword; once seen we commit (Exprs.scala:47-52).
    if c.at_kw(Kw::If) {
        return if_expr(c, ctx);
    }
    // Fun — `def` FunDef with NO cut after `def` (Exprs.scala:55): the ``def``
    // keyword itself carries no cut, so a FunDef that fails *before* consuming any
    // cut backtracks and lets `def` parse as an ordinary identifier via
    // PostfixLambda. But once FunDef crosses one of its cuts — an opened arg-list
    // `(`, a FunTypeArgs `[`, a DottyExtMethodSubj `(`, a result-type `:`, or the
    // Body `=` — fastparse's `|` cannot backtrack past it, so the failure is hard
    // and propagates instead of falling back (Exprs.scala:74 `If | Fun | …`).
    // `fun_def` reports which case via `committed`.
    // oracle: `def`/`def f`/`def +`/`def * 2` ACCEPT (pre-cut fallback);
    // `def +(x)`/`def ||()`/`def(1)`/`def f[T]`/`def (x) = 1` REJECT (post-cut).
    if c.at_word("def") {
        let mark = c.save();
        c.bump(); // `def`
        let mut committed = false;
        match fun_def(c, &mut committed) {
            Ok(v) => return Ok(v),
            Err(e) if committed => return Err(e),
            Err(_) => c.restore(mark),
        }
    }
    postfix_lambda(c, ctx)
}

/// `If` (Exprs.scala:47-52): `Index ~ `if` ~/ "(" ~ ExprCtx.Expr ~ ")" ~ Expr ~
/// Else` where `Else = Semi.? ~ `else` ~/ Expr`. The `if` keyword commits (a
/// missing `else` is a hard error); the condition parses in `ExprCtx`, both
/// branches in the enclosing `ctx`. Node pos = the `if` token.
pub(crate) fn if_expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
    let pos = c.peek().start; // Index (at `if`)
    c.bump(); // `if` ~/ — committed
    c.expect(&TokenKind::LParen, "(")?;
    let condition = expr(c, Ctx::Expr)?; // ExprCtx.Expr
    c.expect(&TokenKind::RParen, ")")?;
    let true_branch = expr(c, ctx)?;
    c.take_one_semi(); // Semi.? before `else`
    if !c.at_kw(Kw::Else) {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "`else`".to_string(),
        });
    }
    c.bump(); // `else` ~/ — committed
    let false_branch = expr(c, ctx)?;
    Ok(Expr::If {
        condition: Box::new(condition),
        true_branch: Box::new(true_branch),
        false_branch: Box::new(false_branch),
        pos,
    })
}

/// `SimpleExpr` (Exprs.scala:120-132), ordered `BlockExpr | ExprLiteral | StableId
/// | `_` | Parened`. The `_` atom is subsumed by `StableId` (which yields
/// `Ident("_")`), exactly as in the reference where `StableId` precedes it.
///
/// `ctx` does not influence the atom head (`Parened` hardcodes `ExprCtx`), but is
/// carried for signature parity with the Task-8 layer.
pub(crate) fn simple_expr(c: &mut Cursor, _ctx: Ctx) -> Result<Expr, ParseError> {
    let t = c.peek();
    if t.kind == TokenKind::LBrace {
        return block_expr(c); // BlockExpr
    }
    if let Some(e) = try_literal(t, c.src) {
        c.bump(); // ExprLiteral wins over StableId (`null`/`true` are literals)
        return Ok(e);
    }
    // ExprLiteral's signed numeric literal (Literals.scala:106-112): `"-".? ~ Index ~
    // Int` under `NoWhitespace`, so a `-` byte-adjacent to the digits is part of the
    // LITERAL, not a prefix operator. `PrefixExpr = ExprPrefix.? ~ SimpleExpr`
    // (Exprs.scala:85-88) allows only ONE prefix, so a sign reaching `SimpleExpr` sits
    // AFTER an already-consumed prefix (`! -1`, `- -1`, `~ /*c*/ -0x1`). The magnitude
    // was range-checked positive at lex, so negation never overflows (D4); the folded
    // constant's pos is the digits' `Index` (after the sign). oracle: `! -1` / `- -1`
    // (folds to `+1`) / `~ /*c*/ -0x1` ACCEPT; `! - 1` (gap) REJECT 1:5.
    if t.kind == TokenKind::OpId && t.text(c.src) == "-" {
        let sign_end = t.end;
        let n = c.peek2();
        let folded = if sign_end == n.start {
            match n.kind {
                TokenKind::IntLit(v) => Some(Expr::IntConst {
                    value: -v,
                    pos: n.start,
                }),
                TokenKind::LongLit(v) => Some(Expr::LongConst {
                    value: -v,
                    pos: n.start,
                }),
                _ => None,
            }
        } else {
            None
        };
        if let Some(e) = folded {
            c.bump(); // "-"
            c.bump(); // the byte-adjacent Int/Long literal
            return Ok(e);
        }
    }
    if is_id(t) {
        return stable_id(c); // StableId (also the lone `_` atom)
    }
    if t.kind == TokenKind::LParen {
        return parened(c);
    }
    Err(ParseError::Syntax {
        pos: t.start,
        expected: "expression".to_string(),
    })
}

/// `BlockExpr` (Exprs.scala:242): `"{" ~/ ( Block ~ "}" )` where `Block =
/// BaseBlock("}")` (Exprs.scala:302). The `{`/`}` semicolon absorption of
/// Core.scala:49-50 is realised by `BaseBlock`'s own leading `Semis.?` and
/// `BlockEnd`'s trailing `Semis.?`.
pub(crate) fn block_expr(c: &mut Cursor) -> Result<Expr, ParseError> {
    c.expect(&TokenKind::LBrace, "{")?; // "{" ~/ — committed
    let e = base_block(c)?;
    c.expect(&TokenKind::RBrace, "}")?;
    Ok(e)
}
