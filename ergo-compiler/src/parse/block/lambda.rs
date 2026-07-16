use crate::ast::Expr;
use crate::error::ParseError;
use crate::span::Pos;
use crate::stype::SType;
use crate::token::{Kw, Token, TokenKind};

use super::super::*;

/// `DottyExtMethodSubj = "(" ~/ Id.! ~ `:` ~/ Type ~ ")"` (Types.scala:150), the
/// (rarely used) extension-method subject. Returns `None` (cursor unmoved) only when
/// there is no leading `(`. Once the `(` matches, the `~/` cut fires — `*committed`
/// is set and every subsequent mismatch is a HARD error, not a `None` backtrack (a
/// leading `(` after `def` can only be a DottyExtMethodSubj, since `Id.!` cannot
/// match `(`). oracle: `def(1)` REJECT 1:5, `def (x) = 1` REJECT 1:7,
/// `def (x: Int) foo = x` ACCEPT.
pub(crate) fn try_dotty_subj(
    c: &mut Cursor,
    committed: &mut bool,
) -> Result<Option<(String, SType)>, ParseError> {
    if c.peek().kind != TokenKind::LParen {
        return Ok(None);
    }
    c.bump(); // "(" ~/ — committed to a DottyExtMethodSubj
    *committed = true;
    if !is_id(c.peek()) {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "identifier".to_string(),
        });
    }
    let id = c.bump();
    let id = id.text(c.src).to_string();
    if !c.at_sym_kw(Kw::Colon) {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "`:`".to_string(),
        });
    }
    c.bump(); // `:` ~/
    let ty = type_(c, false)?;
    if c.peek().kind != TokenKind::RParen {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "`)`".to_string(),
        });
    }
    c.bump(); // ")"
    Ok(Some((id, ty)))
}

/// `PostfixLambda` (Exprs.scala:65-70) + `SuperPostfixSuffix` (:77):
/// `PostfixExpr ~ (`=>` ~ LambdaRhs.? | (`=` ~/ Expr).?).?`. The optional suffix
/// always succeeds (the `=`-variant is itself optional), so it yields
/// `Option<body>`: `None` = no body (the `PostfixExpr` is returned unchanged, both
/// the `Some(None)` and no-suffix cases of :66-67); `Some(body)` = a lambda body,
/// which requires a `Tuple`-of-`Ident` lhs (`lambda()`, :136-139) — any other lhs
/// is the "Invalid declaration of lambda" error (:69), pinned to the `PostfixExpr`
/// start.
pub(crate) fn postfix_lambda(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
    let pos = c.peek().start; // Index
    let e = postfix_expr(c, ctx)?;
    let body: Option<Expr> = if c.at_sym_kw(Kw::FatArrow) {
        c.bump(); // `=>`
        lambda_rhs(c, ctx)?
    } else if c.at_sym_kw(Kw::Assign) {
        c.bump(); // `=` ~/ — SuperPostfixSuffix
        Some(expr(c, ctx)?)
    } else {
        None
    };
    match body {
        None => Ok(e),
        Some(body) => match e {
            Expr::Tuple { items, .. } => lambda_from_tuple(items, body, pos),
            // Exprs.scala:65,69: the error pins to the `PostfixLambda` production
            // start (`Index ~ PostfixExpr`) — i.e. `pos`, captured before any prefix
            // ops — not the parsed expression's own position.
            _ => Err(ParseError::Semantic {
                pos,
                msg: "Invalid declaration of lambda".to_string(),
            }),
        },
    }
}

/// `LambdaRhs` (Exprs.scala:57-63): in a semi-inference context a SINGLE
/// `BlockChunk` wrapped via `block()` (which always succeeds — an empty chunk yields
/// `Block([], Unit)`); otherwise an optional `Expr`. Returns the lambda body, or
/// `None` when (only possible in the `Expr` branch) no expression follows the `=>`.
///
/// Crucially the semi-inference branch is `Index ~ BlockChunk` — a LONE chunk, NOT
/// the block `Body`'s `BlockChunk.repX`. So `block_chunk_stats` continues its
/// `BlockStat.rep` across a literal `;` only: a newline-separated following
/// statement opens a new chunk that belongs to the ENCLOSING block, not this lambda
/// body. oracle: `{ val f = (x,y)=>x\nf }` ACCEPT (body `x`, `f` the block result)
/// vs `{ val f = (x,y)=>x; f }` REJECT 1:18 (body `block([x,f])`, `x` a non-Val).
pub(crate) fn lambda_rhs(c: &mut Cursor, ctx: Ctx) -> Result<Option<Expr>, ParseError> {
    if ctx.semi_inference() {
        let pos = c.peek().start; // LambdaRhs `Index`, before the BlockChunk
                                  // `BlockChunk = BlockLambda.rep ~ BlockStat.rep`; the `case (_, b)` map at
                                  // Exprs.scala:59-60 SILENTLY DISCARDS the leading `BlockLambda.rep`, so the
                                  // body is only the BlockStat list — e.g. `(x,y) => (a) => c` has body `c`.
        while try_block_lambda(c)?.is_some() {} // drop leading BlockLambda heads
        let stats = block_chunk_stats(c)?; // a SINGLE BlockChunk (not the block Body)
        Ok(Some(block_from_stats(stats, pos)?))
    } else if starts_full_expr(c.peek()) {
        Ok(Some(expr(c, ctx)?))
    } else {
        Ok(None)
    }
}

/// `lambda(args, body)` (Exprs.scala:136-139): the tuple's items become the lambda
/// parameters, each `Ident(n, t) → (n, t)`. A non-`Ident` item is Scala's
/// `MatchError` in the `.map`; here it is a Semantic error. Result type is
/// `NoType`.
pub(crate) fn lambda_from_tuple(
    items: Vec<Expr>,
    body: Expr,
    pos: Pos,
) -> Result<Expr, ParseError> {
    let mut args = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Expr::Ident { name, tpe, .. } => args.push((name, tpe)),
            other => {
                return Err(ParseError::Semantic {
                    pos: other.pos(),
                    msg: "lambda parameters must be identifiers".to_string(),
                })
            }
        }
    }
    Ok(Expr::Lambda {
        args,
        given_res_type: SType::NoType,
        body: Box::new(body),
        pos,
    })
}

/// `StableId` (Core.scala:62-69): `Id ("." PostDotCheck ~/ (`this` | Id))*`, folded
/// `Ident(first)` then `Select(acc, seg)` with each `Select`'s pos = the segment's
/// index (Core.scala:65).
///
/// `PostDotCheck` (Core.scala:61) inspects the token after the `.` *without*
/// committing to the dot: a banned token (`super`/`this`/`type`, `_`, or `{`)
/// backtracks the dot and ends the `StableId`. The cut sits AFTER `PostDotCheck`
/// (`"." ~ PostDotCheck ~/ …`), so once it passes a missing Id is a hard error.
pub(crate) fn stable_id(c: &mut Cursor) -> Result<Expr, ParseError> {
    let head = c.bump(); // caller guaranteed `is_id`
    let mut acc = Expr::Ident {
        name: head.text(c.src).to_string(),
        tpe: SType::NoType,
        pos: head.start,
    };
    loop {
        if c.peek().kind != TokenKind::Dot {
            break;
        }
        // PostDotCheck (lookahead): a banned token after the dot ends the StableId
        // with the dot left unconsumed.
        if post_dot_banned(c.peek2(), c.src) {
            break;
        }
        c.bump(); // "." ~ PostDotCheck ~/ — committed
        if !is_id(c.peek()) {
            return Err(ParseError::Syntax {
                pos: c.peek().start,
                expected: "identifier after `.`".to_string(),
            });
        }
        let seg = c.bump();
        acc = Expr::Select {
            obj: Box::new(acc),
            field: seg.text(c.src).to_string(),
            pos: seg.start,
        };
    }
    Ok(acc)
}

/// `PostDotCheck` ban set (Core.scala:61): `!(`super` | `this` | "{" | `_` |
/// `type`)`. `super`/`this`/`type`/`_` are `Key.W` words (Ident tokens), `{` is a
/// brace.
pub(crate) fn post_dot_banned(t: &Token, src: &str) -> bool {
    if t.kind == TokenKind::LBrace {
        return true;
    }
    t.kind == TokenKind::Ident && matches!(t.text(src), "super" | "this" | "type" | "_")
}

/// `Parened` (Exprs.scala:119,126-130): `Index ~ "(" ~/ TypeExpr.rep(0,",") ~
/// TrailingComma ~ ")"`. Items parse in `ExprCtx` (Exprs.scala:33). 0 → `UnitConst`;
/// 1 → the item itself (pure grouping, no node); ≥2 → `Tuple`. The `Index` (before
/// `"("`) is the position of `UnitConst`/`Tuple`.
pub(crate) fn parened(c: &mut Cursor) -> Result<Expr, ParseError> {
    let open = c.expect(&TokenKind::LParen, "(")?; // "(" ~/ — committed
    let pos = open.start;
    let mut items = expr_list(c)?;
    c.expect(&TokenKind::RParen, ")")?;
    Ok(match items.len() {
        0 => Expr::UnitConst { pos },
        1 => items.pop().unwrap(),
        _ => Expr::Tuple { items, pos },
    })
}

/// `TypeExpr.rep(0, ",") ~ TrailingComma` — the comma-separated expression list
/// shared by `Parened` and `ParenArgList`, stopping before the closer. Items parse
/// in `ExprCtx` (Exprs.scala:33). A separator comma must be followed by another
/// item; a trailing comma is legal only when directly followed by a `Newline`
/// (Literals.scala:63).
pub(crate) fn expr_list(c: &mut Cursor) -> Result<Vec<Expr>, ParseError> {
    let mut items = Vec::new();
    if starts_full_expr(c.peek()) {
        loop {
            items.push(expr(c, Ctx::Expr)?);
            if c.peek().kind != TokenKind::Comma {
                break;
            }
            // `Exprs = Expr.rep(1, ",")`: a comma is a SEPARATOR whenever another
            // Expr follows (newlines are transparent in ExprCtx), so try `, ~ Expr`
            // before considering a trailing comma. This is what makes a multi-line
            // arg list like `f(\n a,\n b\n)` parse as `[a, b]` (SigmaParserTest
            // "outerJoin", :848), not `[a]`.
            let mark = c.save();
            c.bump(); // try the separator comma
            if starts_full_expr(c.peek()) {
                continue;
            }
            // `sep ~ Expr` failed → fastparse rewinds the comma; then
            // `TrailingComma = ("," WS Newline)?` absorbs a legal `,\n` before the
            // closer, otherwise the comma is left for the closer's `expect`
            // (Literals.scala:63).
            c.restore(mark);
            if c.comma_then_newline() {
                c.bump(); // trailing comma; the Newline stays for the closer's skip
            }
            break;
        }
    } else if c.peek().kind == TokenKind::Comma && c.comma_then_newline() {
        // rep(0) matched nothing, but TrailingComma still absorbs a lone `,\n`.
        c.bump();
    }
    Ok(items)
}

/// `ExprSuffix` (Exprs.scala:79-83): `(WL "." Id | WL TypeArgs | NoSemis ArgList)*`,
/// collected as `Suffix` markers for `apply_suffix`.
///
/// - `.` has a CUT: a non-Id after a consumed `.` is a hard error. Any Id follows,
///   INCLUDING `_`/`this`/`type` — `PostDotCheck` does NOT apply here (the
///   `StableId` already ended).
/// - `[T,…]` reuses `TypeArgs`; `X[]` is legal (empty).
/// - `NoSemis ~ ArgList`: in semi-inference contexts an arg-list may not start on a
///   new line; `ArgList = ParenArgList | OneNLMax ~ BlockExpr`.
pub(crate) fn expr_suffix(c: &mut Cursor, ctx: Ctx) -> Result<Vec<Suffix>, ParseError> {
    let mut out = Vec::new();
    loop {
        // Alt 1: WL ~ "." ~/ Id
        if c.peek().kind == TokenKind::Dot {
            c.bump(); // "." ~/ — committed
            if !is_id(c.peek()) {
                return Err(ParseError::Syntax {
                    pos: c.peek().start,
                    expected: "identifier after `.`".to_string(),
                });
            }
            let seg = c.bump();
            out.push(Suffix::Select {
                name: seg.text(c.src).to_string(),
            });
            continue;
        }
        // Alt 2: WL ~ TypeArgs
        if c.peek().kind == TokenKind::LBracket {
            out.push(Suffix::TypeApply {
                args: type_args(c)?,
            });
            continue;
        }
        // Alt 3: NoSemis ~ ArgList. NoSemis (semi-inference): the arg-list may not
        // start on a new line.
        if ctx.semi_inference() && !c.no_newline_before_next() {
            break;
        }
        // ArgList = ParenArgList | OneNLMax ~ BlockExpr.
        if c.peek().kind == TokenKind::LParen {
            out.push(paren_arg_list(c)?);
            continue;
        }
        let mark = c.save();
        if c.one_nl_max() && c.peek().kind == TokenKind::LBrace {
            let block = block_expr(c)?;
            out.push(Suffix::BlockArg { block });
            continue;
        }
        c.restore(mark);
        break;
    }
    Ok(out)
}

/// `ParenArgList` (Exprs.scala:315-319): `"(" ~/ Index ~ Exprs.? ~ TrailingComma ~
/// ")"`. `()` → `Suffix::Args { tuple: None }` (unit carrier); a non-empty list →
/// `Suffix::Args { tuple: Some(xs) }` (tuple carrier, unwrapped by `apply_suffix`).
pub(crate) fn paren_arg_list(c: &mut Cursor) -> Result<Suffix, ParseError> {
    c.expect(&TokenKind::LParen, "(")?; // "(" ~/ — committed
    let items = expr_list(c)?;
    c.expect(&TokenKind::RParen, ")")?;
    Ok(Suffix::Args {
        tuple: if items.is_empty() { None } else { Some(items) },
    })
}

/// `applySuffix` (Exprs.scala:191-211): `foldLeft` the markers onto `f`. Every node
/// built here takes `pos = f.pos()` (Scala pins `builder.currentSrcCtx =
/// f.sourceContext` for the whole fold, :192).
pub(crate) fn apply_suffix(f: Expr, suffixes: Vec<Suffix>) -> Result<Expr, ParseError> {
    let f_pos = f.pos();
    let mut acc = f;
    for suf in suffixes {
        acc = match suf {
            Suffix::Select { name } => Expr::Select {
                obj: Box::new(acc),
                field: name,
                pos: f_pos,
            },
            Suffix::Args { tuple: None } => Expr::Apply {
                func: Box::new(acc),
                args: Vec::new(),
                pos: f_pos,
            },
            Suffix::Args { tuple: Some(xs) } => Expr::Apply {
                func: Box::new(acc),
                args: xs,
                pos: f_pos,
            },
            Suffix::TypeApply { args } => Expr::ApplyTypes {
                input: Box::new(acc),
                type_args: args,
                pos: f_pos,
            },
            Suffix::BlockArg { block } => {
                // ZKProof special case (Exprs.scala:199-204): the block's bindings
                // are DISCARDED — only its result is applied — and the callee Ident
                // carries `ZKProofFunc.declaration.tpe`. Verified against
                // SigmaPredef.scala:125-126: `Lambda(Array("block" -> SSigmaProp),
                // SBoolean, None).tpe = SFunc(dom = [SSigmaProp], range = SBoolean)`.
                if matches!(&acc, Expr::Ident { name, .. } if name == "ZKProof") {
                    match block {
                        Expr::Block { result, .. } => {
                            let callee = Expr::Ident {
                                name: "ZKProof".to_string(),
                                tpe: SType::SFunc {
                                    dom: vec![SType::SSigmaProp],
                                    range: Box::new(SType::SBoolean),
                                    tpe_params: vec![],
                                },
                                pos: f_pos,
                            };
                            Expr::Apply {
                                func: Box::new(callee),
                                args: vec![*result],
                                pos: f_pos,
                            }
                        }
                        // A block-arg whose `{ … }` is a leading-lambda block
                        // yields a `Lambda`, not a `Block` — the reference's
                        // non-block ZKProof error path (Exprs.scala:202-203).
                        nonblock => {
                            return Err(ParseError::Semantic {
                                pos: nonblock.pos(),
                                msg: "expected block parameter for ZKProof".to_string(),
                            })
                        }
                    }
                } else {
                    Expr::Apply {
                        func: Box::new(acc),
                        args: vec![block],
                        pos: f_pos,
                    }
                }
            }
        };
    }
    Ok(acc)
}
