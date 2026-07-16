use crate::ast::{ArithKind, BitKind, Expr, RelKind};
use crate::error::ParseError;
use crate::token::TokenKind;

use super::*;

// =============================================================================
// Prefix / infix / postfix layers: operator precedence.
// Exprs.scala:78,85-117,141-189; SigmaParser.scala:40-101.
// =============================================================================

/// `PrefixExpr` (Exprs.scala:85-88): `ExprPrefix? ~ SimpleExpr`. The optional
/// prefix wraps the ATOM via `mk_unary_op` — the suffixes of `PostfixExpr` then
/// wrap around THAT result (so `-f(x)` is `Apply(Negation(f), [x])`, while
/// `-OUTPUTS.size` is `Negation(Select(..))` because `StableId` already consumed
/// the dotted chain inside `SimpleExpr`).
pub(crate) fn prefix_expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
    let op = prefix_op(c);
    let e = simple_expr(c, ctx)?;
    match op {
        Some(op) => mk_unary_op(&op, e, c.tree_version),
        None => Ok(e),
    }
}

/// The ASCII members of `Basic.isOpChar` (Basic.scala:41-45). A raw-byte twin of
/// `is_op_char` used where a lookahead must run on the ORIGINAL source before any
/// whitespace/comment skipping — see `prefix_op`'s `!OpChar` guard.
pub(crate) fn is_op_char_byte(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'%'
            | b'&'
            | b'*'
            | b'+'
            | b'-'
            | b'/'
            | b':'
            | b'<'
            | b'='
            | b'>'
            | b'?'
            | b'@'
            | b'\\'
            | b'^'
            | b'|'
            | b'~'
    )
}

/// `ExprPrefix` (Exprs.scala:78): `WL ~ CharPred("-+!~") ~~ !OpChar ~ WS`. Consume
/// and return a one-char prefix operator. Maximal munch already groups every
/// op-char run into a single `OpId`, so the `!OpChar` guard is satisfied exactly
/// when the `OpId`'s text is a single one of `- + ! ~` (a longer run like `--` or
/// `!=` is one multi-char `OpId` and is NOT a prefix).
///
/// The `~~ !OpChar` runs on the RAW source BEFORE whitespace/comment skipping, so
/// the byte immediately after the op token also disqualifies the prefix. The op-run
/// munch stops before a `//`/`/*` comment (Identifiers.scala:22-24), so a lone
/// prefix-op token can only be followed by a non-op-char OR by `/` (a comment
/// start); the latter is an op-char, so `-/*c*/1` / `!//c\nx` are NOT prefixes —
/// the op falls through to `SimpleExpr` as an operator ident (oracle-verified).
pub(crate) fn prefix_op(c: &mut Cursor) -> Option<String> {
    let t = c.peek();
    if t.kind == TokenKind::OpId {
        let s = t.text(c.src);
        if matches!(s, "-" | "+" | "!" | "~") {
            if c.src
                .as_bytes()
                .get(t.end as usize)
                .copied()
                .is_some_and(is_op_char_byte)
            {
                return None; // raw next char is an op-char → `!OpChar` fails
            }
            let s = s.to_string();
            c.bump();
            return Some(s);
        }
    }
    None
}

/// `PostfixExpr` (Exprs.scala:106-117): `PrefixExpr ~~ ExprSuffix ~~ PostfixSuffix`
/// where `PostfixSuffix = InfixSuffix.repX ~~ PostFix.?` (Exprs.scala:92-104).
///
/// `lhs = applySuffix(prefix, suffix)`, then `obj = mkInfixTree(lhs, infixOps)`
/// resolves precedence, then an optional trailing `PostFix` lone `Id` becomes
/// `MethodCallLike(obj, name, [])` with `pos = obj.pos()`.
pub(crate) fn postfix_expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
    let prefix = prefix_expr(c, ctx)?;
    let suffixes = expr_suffix(c, ctx)?;
    let lhs = apply_suffix(prefix, suffixes)?;

    // PostfixSuffix = InfixSuffix.repX ~~ PostFix.?
    let mut infix_ops: Vec<(String, Expr)> = Vec::new();
    let mut postfix_name: Option<String> = None;
    loop {
        let mark = c.save();
        // Head shared by InfixSuffix and PostFix: `NoSemis ~~ WL ~~ Id.!`. NoSemis
        // (semi-inference) forbids the op from starting on a new line; either way a
        // newline before the op ends the postfix chain in a Stat/Free context.
        if ctx.semi_inference() && !c.no_newline_before_next() {
            break;
        }
        if !is_id(c.peek()) {
            break;
        }
        let op_tok = c.bump();
        let op = op_tok.text(c.src).to_string();

        // InfixSuffix continuation: `OneSemiMax ~ PrefixExpr ~~ ExprSuffix`.
        // OneSemiMax = OneNLMax in semi-inference contexts (else Pass): at most one
        // newline may follow the op. The rhs must actually start a `PrefixExpr`
        // (leading-token dispatch) for the InfixSuffix to commit; otherwise this Id
        // is a trailing `PostFix` — the "WL is non-cutting" backtrack of
        // Exprs.scala:90-91.
        let semi_ok = !ctx.semi_inference() || c.one_nl_max();
        if semi_ok && starts_expr(c.peek()) {
            let rprefix = prefix_expr(c, ctx)?;
            let rsuffixes = expr_suffix(c, ctx)?;
            let rhs = apply_suffix(rprefix, rsuffixes)?;
            infix_ops.push((op, rhs));
            continue;
        }

        // PostFix: `NoSemis ~~ WL ~~ Id.! ~ Newline.?`. Rewind the InfixSuffix
        // attempt (the op and any OneNLMax newline) and re-consume the Id here.
        //
        // The trailing `Newline.?` is NOT consumed: a lone-postfix statement must
        // leave the following newline for the enclosing block's `Semis` separator,
        // otherwise the next statement is stranded. In fastparse the enclosing
        // failure backtracks `PostFix`'s greedy `Newline.?`; in our token model a
        // trailing `Newline` is transparent to `peek`/`End` and absorbed by the
        // block separator (`skip_semis`), so leaving it reproduces the reference.
        // oracle: `{ val x = "s" *\nif (true) z else () }` ACCEPT (the `*` postfix
        // ends the val, the `\n` separates the `if`); `{ z *\nif (…) a else b }`
        // REJECT 1:3 (the `\n` still separates, but `z.*` is a non-Val non-tail).
        c.restore(mark);
        let id_tok = c.bump();
        postfix_name = Some(id_tok.text(c.src).to_string());
        break; // PostFix.? — at most one, and it is terminal
    }

    let obj = mk_infix_tree(lhs, infix_ops, c.tree_version)?;
    match postfix_name {
        // mkMethodCallLike pinned to `obj.sourceContext` (Exprs.scala:113).
        Some(name) => {
            let pos = obj.pos();
            Ok(Expr::MethodCallLike {
                obj: Box::new(obj),
                name,
                args: Vec::new(),
                pos,
            })
        }
        None => Ok(obj),
    }
}

/// `precedenceOf` (Exprs.scala:144-162): precedence by the operator's FIRST char;
/// letters, backtick ids and unmapped symbols are 0 (lowest).
///
/// The `>`-quirk is deliberate: `priorityList` lists `'>'` twice — with `<` at 5
/// (Exprs.scala:150) and with `:` at 6 (:151) — and `.toMap` keeps the later
/// entry, so `>` has precedence **6**, one higher than `<`. Hence `a < b > c`
/// parses as `a < (b > c)`.
pub(crate) fn precedence_of(op: &str) -> u8 {
    match op.chars().next() {
        Some('|') => 1,
        Some('^') => 2,
        Some('&') => 3,
        Some('=') | Some('!') => 4,
        Some('<') => 5,
        Some(':') | Some('>') => 6,
        Some('+') | Some('-') => 7,
        Some('*') | Some('/') | Some('%') => 8,
        _ => 0,
    }
}

/// `mkInfixTree` (Exprs.scala:167-189): the shunting-yard fold that resolves
/// precedence. Reduces while the stacked op's precedence `>=` the incoming op's,
/// i.e. left-associative at equal precedence. There is NO right-associativity for
/// trailing-`:` operators in expressions (that rule is type-grammar only).
pub(crate) fn mk_infix_tree(
    lhs: Expr,
    rest: Vec<(String, Expr)>,
    tree_version: u8,
) -> Result<Expr, ParseError> {
    let mut wait: Vec<(Expr, String)> = Vec::new();
    let mut x = lhs;
    let mut rest = rest.into_iter().peekable();
    loop {
        match (wait.last().is_some(), rest.peek().is_some()) {
            (true, true) => {
                let p_stacked = precedence_of(&wait.last().unwrap().1);
                let p_incoming = precedence_of(&rest.peek().unwrap().0);
                if p_stacked >= p_incoming {
                    let (l, op1) = wait.pop().unwrap();
                    x = mk_binary_op(l, &op1, x, tree_version)?; // reduce; rest unchanged
                } else {
                    let (op2, r) = rest.next().unwrap();
                    wait.push((x, op2)); // shift
                    x = r;
                }
            }
            (false, false) => return Ok(x),
            (false, true) => {
                let (op, r) = rest.next().unwrap();
                wait.push((x, op));
                x = r;
            }
            (true, false) => {
                let (l, op) = wait.pop().unwrap();
                x = mk_binary_op(l, &op, x, tree_version)?;
            }
        }
    }
}

/// `mkUnaryOp` (SigmaParser.scala:40-69). Every node and error is pinned to the
/// ARG's position (`currentSrcCtx.withValue(arg.sourceContext)`, :41).
pub(crate) fn mk_unary_op(op: &str, arg: Expr, tree_version: u8) -> Result<Expr, ParseError> {
    let pos = arg.pos();
    // "-" on a numeric constant: parser-level constant fold (:43-48). Magnitudes
    // are validated positive at lex (no `-2147483648`), so negation never
    // overflows (D4).
    if op == "-" && arg.is_numeric_constant() {
        return match arg {
            Expr::IntConst { value, .. } => Ok(Expr::IntConst { value: -value, pos }),
            Expr::LongConst { value, .. } => Ok(Expr::LongConst { value: -value, pos }),
            // Unreachable: `is_numeric_constant` ⟺ Int/Long. Mirrors the ":49"
            // "cannot prefix" guard for a hypothetical other numeric constant.
            other => Err(ParseError::Semantic {
                pos,
                msg: format!("cannot prefix {other:?} with op {op}"),
            }),
        };
    }
    match op {
        "!" => Ok(Expr::LogicalNot {
            input: Box::new(arg),
            pos,
        }), // :52 — no guard
        "-" => {
            if arg.is_num_type_or_no_type(tree_version) {
                Ok(Expr::Negation {
                    input: Box::new(arg),
                    pos,
                }) // :54-56
            } else {
                Err(ParseError::Semantic {
                    pos,
                    msg: format!("Numeric argument expected for '{op}' operation"),
                }) // :58
            }
        }
        "~" => {
            if arg.is_num_type_or_no_type(tree_version) {
                Ok(Expr::BitInversion {
                    input: Box::new(arg),
                    pos,
                }) // :60-62
            } else {
                Err(ParseError::Semantic {
                    pos,
                    msg: format!("Numeric argument expected for '{op}' operation"),
                }) // :64
            }
        }
        // "+" and anything else (grammatically accepted but not a real prefix).
        _ => Err(ParseError::Semantic {
            pos,
            msg: format!("Unknown prefix operation {op}"),
        }), // :66-67
    }
}

/// The `parseAsMethods` set (SigmaParser.scala:71): infix ops deferred to the
/// typer as `MethodCallLike`.
pub(crate) fn is_parse_as_method(op: &str) -> bool {
    matches!(
        op,
        "*" | "++" | "||" | "&&" | "+" | "^" | "<<" | ">>" | ">>>"
    )
}

/// `mkBinaryOp` (SigmaParser.scala:71-101). Every node and error is pinned to the
/// LEFT operand's position (`currentSrcCtx.withValue(l.sourceContext)`, :74). The
/// match order is exactly the Scala `opName match`: `|`/`&` (with a both-operands
/// numeric-or-NoType guard) are checked BEFORE `parseAsMethods`, so `true | false`
/// errors at parse time while `x | y` passes via `NoType`.
pub(crate) fn mk_binary_op(
    l: Expr,
    op: &str,
    r: Expr,
    tree_version: u8,
) -> Result<Expr, ParseError> {
    let pos = l.pos();
    let rel = |kind: RelKind, l: Expr, r: Expr| Expr::Relation {
        kind,
        left: Box::new(l),
        right: Box::new(r),
        pos,
    };
    let arith = |kind: ArithKind, l: Expr, r: Expr| Expr::ArithOp {
        kind,
        left: Box::new(l),
        right: Box::new(r),
        pos,
    };
    Ok(match op {
        "==" => rel(RelKind::Eq, l, r),       // :76
        "!=" => rel(RelKind::Neq, l, r),      // :77
        ">=" => rel(RelKind::Ge, l, r),       // :78
        ">" => rel(RelKind::Gt, l, r),        // :79
        "<=" => rel(RelKind::Le, l, r),       // :80
        "<" => rel(RelKind::Lt, l, r),        // :81
        "-" => arith(ArithKind::Minus, l, r), // :82
        "|" => {
            // :84-88 — guard both operands BEFORE the parseAsMethods fall-through.
            if l.is_num_type_or_no_type(tree_version) && r.is_num_type_or_no_type(tree_version) {
                Expr::BitOp {
                    kind: BitKind::Or,
                    left: Box::new(l),
                    right: Box::new(r),
                    pos,
                }
            } else {
                return Err(ParseError::Semantic {
                    pos,
                    msg: format!("Numeric arguments expected for '{op}' operation"),
                });
            }
        }
        "&" => {
            // :90-94
            if l.is_num_type_or_no_type(tree_version) && r.is_num_type_or_no_type(tree_version) {
                Expr::BitOp {
                    kind: BitKind::And,
                    left: Box::new(l),
                    right: Box::new(r),
                    pos,
                }
            } else {
                return Err(ParseError::Semantic {
                    pos,
                    msg: format!("Numeric arguments expected for '{op}' operation"),
                });
            }
        }
        _ if is_parse_as_method(op) => Expr::MethodCallLike {
            obj: Box::new(l),
            name: op.to_string(),
            args: vec![r],
            pos,
        }, // :96
        "/" => arith(ArithKind::Divide, l, r), // :97
        "%" => arith(ArithKind::Modulo, l, r), // :98
        // alphanumeric ids, `::`, `**`, backtick ids … (:99)
        _ => {
            return Err(ParseError::Semantic {
                pos,
                msg: format!("Unknown binary operation {op}"),
            })
        }
    })
}
