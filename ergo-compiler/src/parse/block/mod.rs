use crate::ast::Expr;
use crate::error::ParseError;
use crate::span::Pos;
use crate::stype::SType;
use crate::token::{Kw, Token, TokenKind};

mod definitions;
mod lambda;
pub(crate) use definitions::*;
pub(crate) use lambda::*;

use super::*;

// =============================================================================
// Block machinery, val/def definitions, and the PostfixLambda suffix.
// Exprs.scala:57-77, 214-320; SigmaParser.scala:26-35; Types.scala:25-27, 136-150.
// =============================================================================

/// One argument list: `(name, type)` pairs with `NoType` for unascribed params.
/// Shared by `BlockLambdaHead`, `FunArgs`, and the lambda constructor.
pub(crate) type ArgList = Vec<(String, SType)>;

/// `BaseBlock("}")` (Exprs.scala:280-302): `Index ~ Semis.? ~ BlockLambda.? ~ Body
/// ~/ BlockEnd`. The caller (`block_expr`) has consumed `{` and will consume `}`.
///
/// Shape-for-shape port of the result map (Exprs.scala:283-299):
/// - leading `BlockLambda` + a lone one-statement chunk → `Lambda(args, NoType,
///   stat)` (first arm `Seq((Seq(), Seq(b)))`, :284-285) — the body is that stat RAW.
/// - leading `BlockLambda` + any other body → `Lambda(args, NoType, block(stats))`
///   (second arm, :286-292). "Any other" = a leading/trailing `;`, a newline gap, or
///   more than one statement — exactly the cases where a `Semis` separator was
///   consumed, tracked by `block_body`'s `multi_chunk` return.
/// - no leading `BlockLambda` → `block(stats)`.
///
/// A plain empty block (no leading lambda, zero stats) is REJECTED unless a
/// literal `;` was consumed between the braces. `extractBlockStats`' empty arm
/// (Exprs.scala:271-272) is reachable only via an explicit `;` — bare `{}` fails
/// in fastparse before reaching it, because the implicit whitespace consumes any
/// newlines/comments before `BaseBlock`'s leading `Semis.?` can match
/// (oracle-verified). The failure is reported one past the closing `}`.
///
/// A `BlockLambda` head at ANY `Body` chunk start (the consecutive-head D5 case, or
/// a head in a later chunk after a newline gap / `;`-separated empty chunk) is a
/// `scala.MatchError` in the reference — `block_body` enforces this via
/// `reject_chunk_lambda_head`.
pub(crate) fn base_block(c: &mut Cursor) -> Result<Expr, ParseError> {
    let pos = c.peek().start; // Index (before Semis.?)
    let saw_semi = c.skip_semis_lit(); // Semis.? — was a literal `;` among the run?
    let lead = try_block_lambda(c)?.map(|(_, args)| args); // BlockLambda.?
                                                           // Body = BlockChunk.repX(sep = Semis). `block_body` parses every chunk, rejects
                                                           // a BlockLambda head at any chunk start, absorbs the trailing `BlockEnd` Semis,
                                                           // and reports whether more than a single one-statement chunk was consumed.
    let (stats, multi_chunk) = block_body(c)?;
    match lead {
        Some(args) => {
            // A lone one-statement chunk yields that stat RAW (first map arm,
            // :284-285); every other body wraps the stats in `block(...)` (:286-292).
            // A single one-stat chunk is exactly one that consumed no `Semis`.
            let body = if stats.len() == 1 && !multi_chunk {
                stats.into_iter().next().unwrap()
            } else {
                block_from_stats(stats, pos)?
            };
            Ok(Expr::Lambda {
                args,
                given_res_type: SType::NoType,
                body: Box::new(body),
                pos,
            })
        }
        None => {
            // A plain empty block is rejected unless a literal `;` rescued it: the
            // reference's `Semis.?` matches only a bare `;`, never the implicit
            // whitespace it has already consumed. Report one past the `}` (peekable
            // here — `block_body` stopped before the closer), which reproduces the
            // oracle positions for `{}` / `{ }` / `{\n}` / `{/*c*/}` and the nested
            // forms (`f({})`, `({})`, `ZKProof {}`).
            if stats.is_empty() && !saw_semi {
                return Err(ParseError::Syntax {
                    pos: c.peek().end,
                    expected: "block statement".to_string(),
                });
            }
            block_from_stats(stats, pos)
        }
    }
}

/// `Body = BlockChunk.repX(sep = Semis)` flattened to a statement list, plus a flag
/// that is `true` once ANY `Semis` separator was consumed (i.e. the Body is more
/// than a single one-statement chunk — `base_block` uses it to pick the leading-
/// lambda map arm, Exprs.scala:283-292). Also absorbs the trailing `BlockEnd` Semis.
///
/// `BlockChunk = BlockLambda.rep ~ BlockStat.rep(sep = Semis)` (Exprs.scala:259).
/// Both flatMaps (BaseBlock :288-296, LambdaRhs :59-60) keep only chunks whose
/// `BlockLambda.rep` is EMPTY (`case (Seq(), exprs)`); a BlockLambda head at a chunk
/// start makes that list non-empty → `scala.MatchError` (REJECT). So a head is
/// rejected at every chunk start: the first chunk (right after the leading
/// `BlockLambda.?` — the consecutive-head D5 case) and every later chunk.
///
/// Chunk mechanics (the `.rep`-vs-`repX` / ScalaWhitespace asymmetry): WITHIN a
/// chunk `BlockStat.rep(sep = Semis)` continues only across a literal `;` (the
/// implicit whitespace eats trailing newlines, killing `Semis`' `Newline+`
/// alternative, `Cursor::skip_semis_if_lit`); BETWEEN chunks the outer `repX`'s
/// `Semis` (no whitespace pre-eaten) also matches a bare newline, so a newline-only
/// gap — or a `;` after an empty chunk — opens a NEW chunk. oracle:
/// `{ val x=1\n(x,y)=>x }` REJECT (later-chunk head); `{ val x=1; (x,y)=>x }` ACCEPT
/// (`;`-continued expression lambda, same chunk); `{ (x)=>; (a,b)=>c }` REJECT
/// (empty chunk, `;` separator, then a head).
pub(crate) fn block_body(c: &mut Cursor) -> Result<(Vec<Expr>, bool), ParseError> {
    let mut stats = Vec::new();
    let mut multi_chunk = false;
    loop {
        // Chunk start: `BlockLambda.rep` must be empty (a head → MatchError).
        reject_chunk_lambda_head(c)?;
        // `BlockStat.rep(sep = Semis)`: first stat, then `;`-continued stats only.
        if starts_block_stat(c.peek()) {
            stats.push(block_stat(c)?);
            while c.skip_semis_if_lit() {
                multi_chunk = true;
                if !starts_block_stat(c.peek()) {
                    break;
                }
                stats.push(block_stat(c)?);
            }
        }
        // `repX` separator: a `Semis` run (newlines and/or a leftover `;`) opens the
        // next chunk. A `(...)=>` head there begins a `BlockStat` (`(`), so the loop
        // re-enters and `reject_chunk_lambda_head` fires.
        if !c.skip_semis() {
            break; // no separator → Body ends (BlockEnd = Semis.? ~ &("}"))
        }
        multi_chunk = true;
        if !starts_block_stat(c.peek()) {
            break; // trailing Semis before `}` / end (an empty final chunk)
        }
    }
    Ok((stats, multi_chunk))
}

/// A `BlockChunk` starts with `BlockLambda.rep` (Exprs.scala:259). The BaseBlock and
/// LambdaRhs flatMaps keep only chunks with an EMPTY lambda list (`case (Seq(),
/// exprs)`, :289/296), so a `BlockLambda` head at a chunk start makes the list
/// non-empty and is a `scala.MatchError` — a position-less REJECT (`0:0`) in the
/// reference. We keep it a Semantic reject pinned to the head (D5 deviation: error
/// class + position only; both sides REJECT). No cut is left behind — the head
/// lookahead is fully restored. oracle: `{ (a)=>(b)=>c }`, `{ val x=1\n(x,y)=>x }`,
/// `{ (x)=>; (a,b)=>c }` all REJECT.
pub(crate) fn reject_chunk_lambda_head(c: &mut Cursor) -> Result<(), ParseError> {
    let mark = c.save();
    if let Some((lam_pos, _)) = try_block_lambda(c)? {
        c.restore(mark); // undo the head consumption — we reject anyway
        return Err(ParseError::Semantic {
            pos: lam_pos,
            msg: "block lambda is only allowed at the start of a block".to_string(),
        });
    }
    Ok(()) // None → `try_block_lambda` already restored the cursor
}

/// A single `BlockChunk`'s `BlockStat.rep(sep = Semis)` (Exprs.scala:259) as used by
/// `lambda_rhs`: statements continued ONLY across a literal `;`
/// (`Cursor::skip_semis_if_lit`). Unlike the block `Body`, a newline-separated
/// following statement is NOT part of this chunk — it stays in the input for the
/// enclosing block's next `BlockChunk`. oracle: `{ val f = (x,y)=>x\nf }` — the
/// lambda body is `x`, `f` is the enclosing block's result.
pub(crate) fn block_chunk_stats(c: &mut Cursor) -> Result<Vec<Expr>, ParseError> {
    let mut stats = Vec::new();
    if starts_block_stat(c.peek()) {
        stats.push(block_stat(c)?);
        while c.skip_semis_if_lit() {
            if !starts_block_stat(c.peek()) {
                break;
            }
            stats.push(block_stat(c)?);
        }
    }
    Ok(stats)
}

/// `BlockStat = Prelude ~ BlockDef | StatCtx.Expr` (Exprs.scala:258). `Prelude =
/// Annot.rep ~ `lazy`.?` (:257) is parsed and IGNORED; `BlockDef = Dcl` (SP:35) is
/// the `val` form. A non-`val` after the prelude backtracks (the prelude is
/// discarded) and the statement parses as a `StatCtx.Expr` (which also covers the
/// `def` form via `Fun`).
pub(crate) fn block_stat(c: &mut Cursor) -> Result<Expr, ParseError> {
    let mark = c.save();
    prelude(c)?; // Annot.rep ~ `lazy`.?
    if c.at_word("val") {
        return val_def(c); // Dcl = `val` ~/ ValVarDef
    }
    c.restore(mark); // BlockDef failed → discard the prelude
    expr(c, Ctx::Stat) // StatCtx.Expr
}

/// `Prelude = Annot.rep ~ `lazy`.?` (Exprs.scala:257). Parsed and discarded.
pub(crate) fn prelude(c: &mut Cursor) -> Result<(), ParseError> {
    while c.at_sym_kw(Kw::At) {
        annot(c)?;
    }
    if c.at_word("lazy") {
        c.bump();
    }
    Ok(())
}

/// A token that can begin a `BlockStat`: a `StatCtx.Expr` head, an `if`, or a
/// leading `@` (an annotated `val`). `val`/`def`/`lazy` are ordinary `Ident`s and
/// are already covered by `starts_expr`.
pub(crate) fn starts_block_stat(t: &Token) -> bool {
    starts_expr(t) || matches!(t.kind, TokenKind::Kw(Kw::If) | TokenKind::Kw(Kw::At))
}

/// `block(stats)` / `extractBlockStats` (Exprs.scala:262-278): empty → `Block([],
/// UnitConstant)`; otherwise every stat but the last must be a `Val` (unwrapped
/// into a binding), the last is the result (which MAY itself be a `Val`). A
/// non-`Val` in non-tail position is a Semantic error at that stat's own position.
/// The block/unit node carries the block's `pos`.
pub(crate) fn block_from_stats(stats: Vec<Expr>, pos: Pos) -> Result<Expr, ParseError> {
    if stats.is_empty() {
        return Ok(Expr::Block {
            bindings: Vec::new(),
            result: Box::new(Expr::UnitConst { pos }),
            pos,
        });
    }
    let n = stats.len();
    let mut bindings = Vec::with_capacity(n - 1);
    let mut result = None;
    for (i, s) in stats.into_iter().enumerate() {
        if i == n - 1 {
            result = Some(s); // last stat = result (may itself be a Val)
        } else {
            match s {
                Expr::Val(vd) => bindings.push(*vd),
                other => {
                    return Err(ParseError::Semantic {
                        pos: other.pos(),
                        msg: "Block should contain a list of Val bindings and one expression"
                            .to_string(),
                    })
                }
            }
        }
    }
    Ok(Expr::Block {
        bindings,
        result: Box::new(result.unwrap()),
        pos,
    })
}

/// `BlockLambda = BlockLambdaHead ~ `=>`` (Exprs.scala:244-254). Returns the arg
/// list (and its start position) when a full `( Arg,* ) =>` head is present, else
/// `None` with the cursor restored — the head is NOT cut, so it fully backtracks
/// (this is what lets `(x + 1)` fall through to `Parened`). A `:`-ascription
/// failure inside an `Arg` IS cut (`(`:` ~/ Type).?`, :245) and propagates.
pub(crate) fn try_block_lambda(c: &mut Cursor) -> Result<Option<(Pos, ArgList)>, ParseError> {
    let mark = c.save();
    let pos = c.peek().start;
    if !c.one_nl_max() || c.peek().kind != TokenKind::LParen {
        c.restore(mark);
        return Ok(None);
    }
    c.bump(); // "("
    let args = if starts_fun_arg(c.peek()) {
        arg_list(c)? // Arg.rep(1, ",") ~ TrailingComma
    } else {
        Vec::new() // `()` — no args
    };
    if c.peek().kind != TokenKind::RParen {
        c.restore(mark);
        return Ok(None);
    }
    c.bump(); // ")"
    if !c.at_sym_kw(Kw::FatArrow) {
        c.restore(mark); // a paren group with no `=>` is not a lambda head
        return Ok(None);
    }
    c.bump(); // `=>`
    Ok(Some((pos, args)))
}

/// A token that can begin a `FunArg`/`Arg`: an `Id` or a leading annotation `@`
/// (Exprs.scala:245, Types.scala:137).
pub(crate) fn starts_fun_arg(t: &Token) -> bool {
    is_id(t) || t.kind == TokenKind::Kw(Kw::At)
}

/// `Arg.rep(1, ",") ~ TrailingComma` (Exprs.scala:249, Types.scala:141) — the
/// comma-separated argument list shared by `BlockLambdaHead` and `FunArgs`. Each
/// `Arg = Annot.rep ~ Id.! ~ (`:` ~/ Type).?`, untyped args default to `NoType`.
pub(crate) fn arg_list(c: &mut Cursor) -> Result<ArgList, ParseError> {
    let mut args = vec![fun_arg(c)?];
    loop {
        if c.peek().kind != TokenKind::Comma {
            break;
        }
        // `Arg.rep(1, ",")` is separator-first: a comma is a SEPARATOR whenever
        // another `Arg` follows (newlines are transparent), so try `, ~ Arg` before
        // the `TrailingComma` fallback — mirroring `type_list`/`expr_list`. This is
        // what lets a multi-line head like `(x: Int,\n y: Int)` bind both args
        // instead of stopping at the newline.
        let mark = c.save();
        c.bump(); // try the separator comma
        if starts_fun_arg(c.peek()) {
            args.push(fun_arg(c)?);
            continue;
        }
        // `sep ~ Arg` failed → rewind the comma; a legal trailing comma is one
        // directly followed by a `Newline` before the closer (Literals.scala:63).
        c.restore(mark);
        if c.comma_then_newline() {
            c.bump(); // trailing comma; the Newline stays for the closer
        }
        break;
    }
    Ok(args)
}

/// One `Arg`/`FunArg` = `Annot.rep ~ Id.! ~ (`:` ~/ Type).?` (Exprs.scala:245-248,
/// Types.scala:137-140). Annotations are discarded; an absent type is `NoType`.
pub(crate) fn fun_arg(c: &mut Cursor) -> Result<(String, SType), ParseError> {
    while c.at_sym_kw(Kw::At) {
        annot(c)?;
    }
    if !is_id(c.peek()) {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "argument name".to_string(),
        });
    }
    let name = c.bump();
    let name = name.text(c.src).to_string();
    let tpe = if c.at_sym_kw(Kw::Colon) {
        c.bump(); // `:` ~/ — committed
        type_(c, false)?
    } else {
        SType::NoType
    };
    Ok((name, tpe))
}

/// `` `=` `` (Core.scala:25 = `O("=")` = `"=" ~ !OpChar`): the `val`/`def` binding
/// assignment. A lone `=` is `Kw::Assign`. When the next token is an op-identifier
/// that STARTS with `=` (e.g. `==`), fastparse matches the single `=` char, then
/// the `!OpChar` negative lookahead fails at the FOLLOWING op-char — so the error
/// index is one byte past the `=`, not at it (ChainCash `reserve.es`:
/// `val redemptionInputOk == …` rejects at the second `=`). The token lexer folds
/// `==` into one `OpId`, so this granularity is restored here.
pub(crate) fn expect_assign(c: &mut Cursor) -> Result<(), ParseError> {
    // The reserved `Kw::Assign` OR the comment-adjacent `OpId "="` (`val x =//c 1`,
    // `def f() =/*c*/ x`): `Key.O("=")` carries a comment exception (Basic.scala:76-77),
    // so a lone `=` before a `//`/`/*` — lexed as an operator id — still binds here.
    // oracle: both ACCEPT. (`==`/`=>` below still error one byte past the `=`.)
    if c.at_sym_kw(Kw::Assign) {
        c.bump(); // `=` ~/ — committed
        return Ok(());
    }
    let t = c.peek();
    if t.kind == TokenKind::OpId && t.text(c.src).starts_with('=') {
        // `"="` matched the leading `=`; `!OpChar` fails one byte later.
        return Err(ParseError::Syntax {
            pos: t.start + 1,
            expected: "`=`".to_string(),
        });
    }
    // ASCII `=>` FatArrow (Core.scala:25): O("=") matches the leading `=`, then
    // `!OpChar` fails at the following `>` — one byte past t.start, same as the OpId
    // `==` arm. Only the ASCII `=>` reaches here as `Kw::FatArrow`; the Unicode alias
    // `⇒` (U+21D2) is an `OpId` that does NOT start with `=`, so it falls through to
    // the generic `t.start` arm below (oracle: `def f(x: Int) ⇒ 1` REJECT 1:15, one
    // column left of the ASCII `def f(x: Int) => 1` REJECT 1:16).
    if t.kind == TokenKind::Kw(Kw::FatArrow) {
        return Err(ParseError::Syntax {
            pos: t.start + 1,
            expected: "`=`".to_string(),
        });
    }
    Err(ParseError::Syntax {
        pos: t.start,
        expected: "`=`".to_string(),
    })
}
