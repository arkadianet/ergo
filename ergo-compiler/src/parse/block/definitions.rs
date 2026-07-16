use crate::ast::Expr;
use crate::error::ParseError;
use crate::stype::SType;
use crate::token::{Kw, Token, TokenKind};

use super::super::*;
use super::ArgList;

/// `Dcl = `val` ~/ ValVarDef` (Types.scala:25-27) with `ValVarDef = Index ~
/// BindPattern ~ (`:` ~/ Type).? ~ (`=` ~/ FreeCtx.Expr)` (SP:26-33). The pattern
/// must reduce to a single `Ident` → `Val(name, T|NoType, body)` at the pattern's
/// start; any other pattern → Semantic "Only single name patterns supported" at
/// that same position. The `val` keyword is a cut, so a malformed `ValVarDef` is a
/// hard error.
pub(crate) fn val_def(c: &mut Cursor) -> Result<Expr, ParseError> {
    c.bump(); // `val` ~/ — committed
    let pos = c.peek().start; // Index (at the BindPattern)
    let pat = bind_pattern(c)?;
    let given_type = if c.at_sym_kw(Kw::Colon) {
        c.bump(); // `:` ~/ — committed
        type_(c, false)?
    } else {
        SType::NoType
    };
    expect_assign(c)?; // `=` ~/ — committed
    let body = expr(c, Ctx::Free)?; // FreeCtx.Expr
    match pat {
        BindPat::Name(name) => Ok(Expr::Val(Box::new(crate::ast::ValDef {
            name,
            given_type,
            body,
            pos,
        }))),
        BindPat::Other => Err(ParseError::Semantic {
            pos,
            msg: "Only single name patterns supported".to_string(),
        }),
    }
}

/// A parsed `BindPattern`: either a single-name binding or any other (tuple /
/// extractor / dotted) pattern, which the `val` binder rejects.
pub(crate) enum BindPat {
    Name(String),
    Other,
}

/// `BindPattern = SimplePattern` (Exprs.scala:309-312): `TupleEx | Extractor |
/// VarId` (Exprs.scala:234-240). The pattern reduces to the bare `StableId` result:
/// a single-segment id (with or without extractor args) yields `Name`; a dotted path
/// (→ `Select`, non-`Ident`) or a leading tuple pattern yields `Other`. Consumed in
/// full so the following `(`:` Type).? ~ `=` Expr` still parses (matching the
/// reference's parse-then-map order).
pub(crate) fn bind_pattern(c: &mut Cursor) -> Result<BindPat, ParseError> {
    if c.peek().kind == TokenKind::LParen {
        tuple_ex(c)?; // TupleEx `( Pattern,* )` — parsed with the real Pattern grammar
        return Ok(BindPat::Other);
    }
    if !is_id(c.peek()) {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "pattern".to_string(),
        });
    }
    let head = c.bump();
    let name = head.text(c.src).to_string();
    let mut other = false;
    // StableId tail: `('.' Id)*` — a dotted path is not a single name.
    while c.peek().kind == TokenKind::Dot {
        c.bump();
        if !is_id(c.peek()) {
            return Err(ParseError::Syntax {
                pos: c.peek().start,
                expected: "identifier after `.`".to_string(),
            });
        }
        c.bump();
        other = true;
    }
    // Extractor args: `Extractor = StableId ~ TupleEx.?` (Exprs.scala:236). Scala
    // DROPS the TupleEx — the pattern reduces to the bare StableId — so a
    // single-segment id binds a val of that NAME (`val Some(x) = 1` → Val("Some", 1),
    // a token-dropping quirk, but the reference behavior). The arg list is still
    // parsed and discarded (with the real pattern grammar, so a malformed inner
    // pattern hard-rejects at the `(` cut); it does NOT make this a non-name pattern.
    if c.peek().kind == TokenKind::LParen {
        tuple_ex(c)?;
    }
    Ok(if other {
        BindPat::Other
    } else {
        BindPat::Name(name)
    })
}

/// `TupleEx = "(" ~/ Pattern.rep(0, ",") ~ TrailingComma ~ ")"` (Exprs.scala:235).
/// Parsed and DISCARDED (the Extractor drops it, :236). The `(` is a cut, so a
/// malformed inner pattern is a hard reject — each element is parsed with the real
/// `Pattern` grammar (`pattern`: `TypeOrBindPattern` alternatives), not merely a
/// `SimplePattern` and not a balanced-paren scan.
pub(crate) fn tuple_ex(c: &mut Cursor) -> Result<(), ParseError> {
    c.expect(&TokenKind::LParen, "(")?; // "(" ~/ — committed
    if starts_pattern(c.peek()) {
        loop {
            pattern(c)?; // one full Pattern — discarded
            if c.peek().kind != TokenKind::Comma {
                break;
            }
            // Separator-first: `Pattern.rep(_, ",")` takes `, ~ Pattern` greedily
            // (newlines transparent) before the `TrailingComma` fallback.
            let mark = c.save();
            c.bump(); // try the separator comma — another Pattern must follow
            if starts_pattern(c.peek()) {
                continue;
            }
            c.restore(mark); // `sep ~ Pattern` failed → rewind the comma
            if c.comma_then_newline() {
                c.bump(); // TrailingComma; the Newline stays for the closer
            }
            break;
        }
    } else if c.peek().kind == TokenKind::Comma && c.comma_then_newline() {
        c.bump(); // rep(0) matched nothing; TrailingComma still absorbs `,\n`
    }
    c.expect(&TokenKind::RParen, ")")?;
    Ok(())
}

/// A token that can begin a `SimplePattern` (Exprs.scala:234-240): a `(` (TupleEx)
/// or an `Id` (Extractor `StableId` / `VarId`). Also the start set of a full
/// `Pattern`, whose `TypePattern` head (`_`/backtick/`VarId`) is itself an `Id`.
pub(crate) fn starts_pattern(t: &Token) -> bool {
    t.kind == TokenKind::LParen || is_id(t)
}

/// `Pattern = (WL ~ TypeOrBindPattern).rep(1, sep = "|"./)` (Exprs.scala:304).
/// Parsed and DISCARDED (a `TupleEx` element the `Extractor` drops, :235-236). The
/// `|` alternation separator carries a cut (`"|"./`), so a `|` with no following
/// alternative is a HARD reject. oracle: `Some(x | y)` / `Some(Foo | x)` ACCEPT,
/// `Some(x |)` REJECT 1:15.
pub(crate) fn pattern(c: &mut Cursor) -> Result<(), ParseError> {
    type_or_bind_pattern(c)?;
    while c.at_op("|") {
        c.bump(); // "|" ./ — cut: another alternative MUST follow
        type_or_bind_pattern(c)?;
    }
    Ok(())
}

/// `TypeOrBindPattern = (TypePattern | BindPattern).ignore` (Exprs.scala:305): a
/// typed pattern `v : T`, else the `SimplePattern` machinery. Both are DISCARDED.
pub(crate) fn type_or_bind_pattern(c: &mut Cursor) -> Result<(), ParseError> {
    if try_type_pattern(c)? {
        return Ok(());
    }
    bind_pattern(c).map(|_| ()) // BindPattern = SimplePattern (Exprs.scala:309-312)
}

/// `TypePattern = (`_` | BacktickId | VarId) ~ `:` ~ TypePat` with `TypePat =
/// CompoundType` (Exprs.scala:306, 314). There is NO cut, so any non-match — a
/// non-`VarId` head, a missing `:`, or a `CompoundType` that fails — restores the
/// cursor and returns `false` to hand the element to `BindPattern`. oracle:
/// `Some(x: Int)` / `Some(_: Int)` / `` Some(`A`: Int) `` / `Some(x: Coll[Int])`
/// ACCEPT; `Some(Foo: Int)` REJECT (uppercase head is a constructor `StableId`, so
/// the `:` is stranded before `)`); `Some(x: )` REJECT (empty `TypePat` → the `x`
/// re-parses as a bind, `:` then stranded).
pub(crate) fn try_type_pattern(c: &mut Cursor) -> Result<bool, ParseError> {
    if !is_var_id_head(c.peek(), c.src) {
        return Ok(false);
    }
    let mark = c.save();
    c.bump(); // (`_` | BacktickId | VarId)
    if !c.at_sym_kw(Kw::Colon) {
        c.restore(mark);
        return Ok(false);
    }
    c.bump(); // `:`
    if compound_type(c).is_err() {
        c.restore(mark); // TypePat failed → let BindPattern re-parse the head
        return Ok(false);
    }
    Ok(true)
}

/// A `TypePattern` head (Exprs.scala:306): the `_` word, a backtick id, or a `VarId`
/// — an id whose first char is `Lower` (a lowercase letter, `_`, or `$`;
/// Basic.scala:52, Identifiers.scala:28). An `UppercaseId` head (`Foo`) is a
/// constructor `StableId`, NOT a `VarId`, and an operator id is never a `VarId`, so
/// both are excluded.
pub(crate) fn is_var_id_head(t: &Token, src: &str) -> bool {
    match t.kind {
        TokenKind::BacktickId => true,
        TokenKind::Ident => matches!(
            t.text(src).chars().next(),
            Some(ch) if ch.is_lowercase() || ch == '_' || ch == '$'
        ),
        _ => false,
    }
}

/// `Fun = `def` ~ FunDef` body (Exprs.scala:214-232). The caller has consumed
/// `def`. Produces `Val(name, resType|NoType, Lambda(args, resType|NoType, body))`
/// at the production start. No dotty subject: `args` = the FIRST arg list only —
/// extra lists are silently dropped (`args.headOption`, :220). With a dotty subject
/// and ≤1 lists: `args = [subj] ++ first`; with >1 lists: Semantic error (:229-231).
pub(crate) fn fun_def(c: &mut Cursor, committed: &mut bool) -> Result<Expr, ParseError> {
    let pos = c.peek().start; // Index (at DottyExtMethodSubj? / Id)
    let dotty = try_dotty_subj(c, committed)?;
    if !is_id(c.peek()) {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "function name".to_string(),
        });
    }
    let name = c.bump();
    let name = name.text(c.src).to_string();
    let arg_lists = fun_sig(c, committed)?;
    let res_type = if c.at_sym_kw(Kw::Colon) {
        c.bump(); // `:` ~/ — committed
        *committed = true; // the result-type `:` cut fired
        Some(type_(c, false)?)
    } else {
        None
    };
    expect_assign(c)?; // `=` ~/ — committed
    *committed = true; // the Body `=` cut fired
    let body = expr(c, Ctx::Free)?; // FreeCtx.Expr
    let res = res_type.unwrap_or(SType::NoType);

    let args = match dotty {
        None => arg_lists.into_iter().next().unwrap_or_default(),
        Some(subj) => {
            if arg_lists.len() > 1 {
                return Err(ParseError::Semantic {
                    pos,
                    msg: "Function can only have single argument list".to_string(),
                });
            }
            let mut combined = vec![subj];
            combined.extend(arg_lists.into_iter().next().unwrap_or_default());
            combined
        }
    };
    let lambda = Expr::Lambda {
        args,
        given_res_type: res.clone(),
        body: Box::new(body),
        pos,
    };
    Ok(Expr::Val(Box::new(crate::ast::ValDef {
        name,
        given_type: res,
        body: lambda,
        pos,
    })))
}

/// `FunSig = FunTypeArgs.? ~~ FunArgs.rep` (Types.scala:136-145). The optional
/// `FunTypeArgs` (`[ … ]`) is parsed and DISCARDED via the real `TypeArg` grammar;
/// the returned value is the list of `FunArgs` argument lists (each `OneNLMax ~ "("
/// ~/ Args.? ~ ")"`).
///
/// FunArgs' leading `OneNLMax` is VACUOUS at almost every position: `FunDef = …
/// Id.! ~ FunSig` (the `~` eats newlines before the first arg list) and
/// `FunArgs.rep`'s inter-iteration whitespace (which also eats newlines) both sit
/// in implicit-`ScalaWhitespace` positions, so the newlines are gone before
/// `OneNLMax` runs. `peek`'s transparent newline-skip reproduces that with no
/// gate. The ONE exception is the first arg list DIRECTLY after a present
/// `FunTypeArgs`: `FunTypeArgs.? ~~ FunArgs.rep` (Types.scala:136) joins them with
/// RAW `~~`, so there `OneNLMax` is live — at most one newline may follow `]`.
/// oracle: `def f\n\n(x)=x` / `def f(x)\n\n(y)=x` / `def f[T]\n(x)=x` ACCEPT, but
/// `def f[T]\n\n(x)=x` REJECT.
pub(crate) fn fun_sig(c: &mut Cursor, committed: &mut bool) -> Result<Vec<ArgList>, ParseError> {
    let had_type_args = c.peek().kind == TokenKind::LBracket;
    if had_type_args {
        *committed = true; // FunTypeArgs `[` ~/ cut is about to fire
        fun_type_args(c)?; // FunTypeArgs — parsed and discarded
    }
    let mut lists = Vec::new();
    let mut first = true;
    loop {
        // Live `OneNLMax` only for the first arg list after a present FunTypeArgs
        // (the `~~` raw junction); everywhere else newlines are already eaten.
        if had_type_args && first {
            let mark = c.save();
            if !c.one_nl_max() || c.peek().kind != TokenKind::LParen {
                c.restore(mark);
                break;
            }
        } else if c.peek().kind != TokenKind::LParen {
            break; // FunArgs.rep ends
        }
        first = false;
        c.bump(); // "(" ~/ — committed
        *committed = true; // the FunArgs `(` cut fired
        let args = if starts_fun_arg(c.peek()) {
            arg_list(c)?
        } else {
            Vec::new()
        };
        c.expect(&TokenKind::RParen, ")")?;
        lists.push(args);
    }
    Ok(lists)
}

/// `FunTypeArgs = "[" ~/ (Annot.rep ~ TypeArg).rep(1, ",") ~ TrailingComma ~ "]"`
/// (Types.scala:143). The `[` is a cut and the bracketed content is parsed with the
/// real `TypeArg` grammar, then DISCARDED. Because `.rep(1, ",")` requires at least
/// one item, malformed content the reference rejects — `[]`, `[123]`, or a trailing
/// comma not directly followed by a newline (`[T,]`) — is a hard reject here too.
pub(crate) fn fun_type_args(c: &mut Cursor) -> Result<(), ParseError> {
    c.expect(&TokenKind::LBracket, "[")?; // "[" ~/ — committed
    loop {
        while c.at_sym_kw(Kw::At) {
            annot(c)?; // Annot.rep — discarded
        }
        type_arg(c)?; // one TypeArg — discarded
        if c.peek().kind != TokenKind::Comma {
            break;
        }
        // Separator-first: `(Annot.rep ~ TypeArg).rep(1, ",")` takes `, ~ item`
        // greedily (newlines transparent) before the `TrailingComma` fallback, so a
        // multi-line `[T,\n U]` binds both type args.
        let mark = c.save();
        c.bump(); // try the separator comma — another `(Annot.rep ~ TypeArg)` must follow
        if c.at_kw(Kw::At) || is_id(c.peek()) {
            continue;
        }
        // `sep ~ item` failed → rewind the comma; a legal trailing comma is one
        // directly followed by a `Newline`, else `]` reports the failure at the comma.
        c.restore(mark);
        if c.comma_then_newline() {
            c.bump(); // TrailingComma; the Newline stays for the closer
        }
        break;
    }
    c.expect(&TokenKind::RBracket, "]")?;
    Ok(())
}

/// `TypeArg = (Id | `_`) ~ TypeArgList.? ~ TypeBounds ~ CtxBounds` where `CtxBounds =
/// (`:` ~/ Type).rep` (Types.scala:153-156). Parsed and DISCARDED. `_` lexes as an
/// `Ident`, so it is covered by `is_id`; a non-id head (e.g. `123`) is a reject.
pub(crate) fn type_arg(c: &mut Cursor) -> Result<(), ParseError> {
    if !is_id(c.peek()) {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "type parameter".to_string(),
        });
    }
    c.bump(); // (Id | `_`)
    if c.peek().kind == TokenKind::LBracket {
        type_arg_list(c)?; // TypeArgList.?
    }
    type_bounds(c)?; // TypeBounds
    while c.at_sym_kw(Kw::Colon) {
        c.bump(); // CtxBounds: `:` ~/ — committed
        type_(c, false)?;
    }
    Ok(())
}

/// `TypeArgList = "[" ~/ TypeArgVariant.rep(1, ",") ~ TrailingComma ~ "]"`
/// (Types.scala:163-165); `TypeArgVariant = Annot.rep ~ (`+` | `-`).? ~ TypeArg`
/// (:161). Parsed and DISCARDED — the variance markers `+`/`-` are `OpId` tokens.
pub(crate) fn type_arg_list(c: &mut Cursor) -> Result<(), ParseError> {
    c.expect(&TokenKind::LBracket, "[")?; // "[" ~/ — committed
    loop {
        type_arg_variant(c)?;
        if c.peek().kind != TokenKind::Comma {
            break;
        }
        // Separator-first: `TypeArgVariant.rep(1, ",")` takes `, ~ item` greedily
        // (newlines transparent) before the `TrailingComma` fallback.
        let mark = c.save();
        c.bump(); // try the separator comma — another TypeArgVariant must follow
        if c.at_kw(Kw::At) || c.at_op("+") || c.at_op("-") || is_id(c.peek()) {
            continue;
        }
        c.restore(mark); // `sep ~ item` failed → rewind the comma
        if c.comma_then_newline() {
            c.bump(); // TrailingComma
        }
        break;
    }
    c.expect(&TokenKind::RBracket, "]")?;
    Ok(())
}

/// `TypeArgVariant = Annot.rep ~ (`+` | `-`).? ~ TypeArg` (Types.scala:161). Parsed
/// and DISCARDED.
pub(crate) fn type_arg_variant(c: &mut Cursor) -> Result<(), ParseError> {
    while c.at_sym_kw(Kw::At) {
        annot(c)?; // Annot.rep — discarded
    }
    if c.at_op("+") || c.at_op("-") {
        c.bump(); // variance marker
    }
    type_arg(c)
}
