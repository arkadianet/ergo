use crate::error::ParseError;
use crate::span::Pos;
use crate::stype::{is_predef_available, predef_type, SType};
use crate::token::{Kw, Token, TokenKind};

use super::*;

// =============================================================================
// Leading-token predicates (realise ordered choice / cut boundaries).
// =============================================================================

/// A token that can begin a `SimpleType`/`CompoundType`: `BasicType = TupleType |
/// TypeId` (Types.scala:123), i.e. `(` or an `Id`.
pub(crate) fn starts_compound(t: &Token) -> bool {
    is_id(t) || t.kind == TokenKind::LParen
}

/// A token that can begin a `Type`: `CompoundType` head, or a leading `=>`
/// (Types.scala:63).
pub(crate) fn starts_type(t: &Token) -> bool {
    starts_compound(t) || t.kind == TokenKind::Kw(Kw::FatArrow)
}

// =============================================================================
// Type grammar (Types.scala port).
// =============================================================================

/// `Type` (Types.scala:63): `` `=>`.? ~~ PostfixType ~ TypeBounds ~ `*`.? ``.
/// The leading `=>`, the `TypeBounds`, and the trailing `*` are parsed and
/// discarded.
///
/// The leading `` `=>`.? `` is RAW-adjacent to the production start (the `~~`,
/// Types.scala:63): it matches an arrow ONLY when no input is skipped between the
/// production entry and the arrow. This bites at exactly ONE place — the top-level
/// `parse_type` entry (`raw_entry = true`), the only Type invoked with no preceding
/// `~`/`~/` to consume leading whitespace. Every NESTED Type (a tuple/type-arg
/// element, the `` `=>` ~/ Type `` RHS, a `TypeBounds` RHS) is entered after a
/// caller sequence op that already consumed the gap, so from Type's local view the
/// arrow is adjacent regardless of source spacing (`raw_entry = false`). oracle:
/// top-level ` => Int` / `\n=>Int` / `/*c*/=>Int` REJECT, but `=> Int` / `=>Int`
/// ACCEPT; nested `Coll[ => Int]` / `( => Int) => Int` ACCEPT.
///
/// At the raw entry the top-level production begins at byte 0, so a leading arrow
/// is recognised only when the `=>` token starts at offset 0 (any leading
/// space/newline/comment pushes its start past 0 and breaks the raw match).
pub(crate) fn type_(c: &mut Cursor, raw_entry: bool) -> Result<SType, ParseError> {
    with_depth_guard(c, |c| type_impl(c, raw_entry))
}

/// The guarded body of [`type_`] (renamed so every recursive call in this
/// module goes through the depth-guarded wrapper above, not this directly).
pub(crate) fn type_impl(c: &mut Cursor, raw_entry: bool) -> Result<SType, ParseError> {
    if c.at_sym_kw(Kw::FatArrow) && (!raw_entry || c.peek().start == 0) {
        c.bump();
    }
    let t = postfix_type(c)?;
    type_bounds(c)?;
    if c.at_op("*") {
        c.bump();
    }
    Ok(t)
}

/// `PostfixType` (Types.scala:54-62): `InfixType ~ (`=>` ~/ Type).?`. When an
/// arrow follows, an `STuple` left-hand side FLATTENS into a multi-arg `SFunc`;
/// any other lhs becomes a one-arg `SFunc`.
pub(crate) fn postfix_type(c: &mut Cursor) -> Result<SType, ParseError> {
    let d = infix_type(c)?;
    if c.at_sym_kw(Kw::FatArrow) {
        c.bump(); // `=>` ~/  — committed
        let r = type_(c, false)?;
        let dom = match d {
            SType::STuple(items) => items,
            other => vec![other],
        };
        Ok(SType::SFunc {
            dom,
            range: Box::new(r),
            tpe_params: vec![],
        })
    } else {
        Ok(d)
    }
}

/// `InfixType` (Types.scala:70-95): `CompoundType ~~ (NotNewline ~ Id.! ~~
/// OneNLMax ~ CompoundType).repX`, folded by associativity. `Index` is captured at
/// the production start for the mixed-associativity error position.
pub(crate) fn infix_type(c: &mut Cursor) -> Result<SType, ParseError> {
    let start = c.peek().start;
    let head = compound_type(c)?;
    let mut tail: Vec<(String, SType)> = Vec::new();
    loop {
        let mark = c.save();
        // NotNewline ~ Id.!
        if !c.no_newline_before_next() || !is_id(c.peek()) {
            break;
        }
        // Backtick infix ids capture their raw text INCLUDING the backticks.
        let op_tok = c.bump();
        let op = op_tok.text(c.src).to_string();
        // ~~ OneNLMax ~ CompoundType
        if !c.one_nl_max() || !starts_compound(c.peek()) {
            c.restore(mark);
            break;
        }
        let rhs = compound_type(c)?; // committed: the rhs starts a compound
        tail.push((op, rhs));
    }
    build_infix(head, tail, start)
}

/// `checkAssoc` + `buildInfix` (Types.scala:73-91). All operators must share
/// associativity — all end `:` (right, `foldRight`) or none do (left, `foldLeft`);
/// a mix is a semantic error at the production start. Both folds build
/// `STypeApply{name: op, args: [l, r]}`.
pub(crate) fn build_infix(
    head: SType,
    tail: Vec<(String, SType)>,
    start: Pos,
) -> Result<SType, ParseError> {
    if tail.is_empty() {
        return Ok(head);
    }
    let all_right = tail.iter().all(|(op, _)| op.ends_with(':'));
    if all_right {
        // tail.foldRight(head){ (op,t), acc => STypeApply(op, [t, acc]) }
        let mut acc = head;
        for (op, t) in tail.into_iter().rev() {
            acc = SType::STypeApply {
                name: op,
                args: vec![t, acc],
            };
        }
        return Ok(acc);
    }
    let all_left = tail.iter().all(|(op, _)| !op.ends_with(':'));
    if all_left {
        // tail.foldLeft(head){ acc, (op,t) => STypeApply(op, [acc, t]) }
        let mut acc = head;
        for (op, t) in tail {
            acc = SType::STypeApply {
                name: op,
                args: vec![acc, t],
            };
        }
        return Ok(acc);
    }
    Err(ParseError::Semantic {
        pos: start,
        msg: "All operators must have the same associativity".to_string(),
    })
}

/// `CompoundType` (Types.scala:97-103): `AnnotType.rep(1, `with`./)`. More than one
/// member is a semantic error ("Compound types are not supported") at the
/// production start. The `with`./ separator is a cut: an `annot_type` must follow.
pub(crate) fn compound_type(c: &mut Cursor) -> Result<SType, ParseError> {
    let start = c.peek().start;
    let mut types = vec![annot_type(c)?];
    while c.at_word("with") {
        c.bump(); // `with`./ — committed
        types.push(annot_type(c)?);
    }
    if types.len() == 1 {
        Ok(types.pop().unwrap())
    } else {
        Err(ParseError::Semantic {
            pos: start,
            msg: "Compound types are not supported".to_string(),
        })
    }
}

/// `AnnotType` (Types.scala:105-106): `SimpleType ~~ (NotNewline ~ Annot).repX`.
/// Annotations are parsed and DISCARDED.
pub(crate) fn annot_type(c: &mut Cursor) -> Result<SType, ParseError> {
    let t = simple_type(c)?;
    while c.no_newline_before_next() && c.at_sym_kw(Kw::At) {
        annot(c)?;
    }
    Ok(t)
}

/// `Annot` (Types.scala:159): `` `@` ~/ SimpleType ~ ("(" ~/ (Exprs ~ (`:` ~/
/// `_*`).?).? ~ TrailingComma ~ ")").rep ``. The annotation type and every argument
/// group are parsed and DISCARDED; argument expressions parse in `ExprCtx`
/// (`Exprs`, Types.scala:168).
pub(crate) fn annot(c: &mut Cursor) -> Result<(), ParseError> {
    c.bump(); // `@` ~/ — committed
    simple_type(c)?; // discarded
    while c.peek().kind == TokenKind::LParen {
        annot_arg_group(c)?;
    }
    Ok(())
}

/// One `"(" ~/ (Exprs ~ (`:` ~/ `_*`).?).? ~ TrailingComma ~ ")"` argument group of
/// an annotation (Types.scala:159). Everything parsed here is discarded.
pub(crate) fn annot_arg_group(c: &mut Cursor) -> Result<(), ParseError> {
    c.expect(&TokenKind::LParen, "(")?; // "(" ~/ — committed
    if starts_full_expr(c.peek()) {
        // Exprs = TypeExpr.rep(1, ",") (Types.scala:168); no trailing comma here —
        // the trailing comma belongs to the `TrailingComma` below.
        loop {
            expr(c, Ctx::Expr)?; // discarded
            if c.peek().kind != TokenKind::Comma {
                break;
            }
            // Separator comma when another Expr follows; otherwise rewind and leave
            // the comma for the `TrailingComma` check below (Types.scala:168,
            // Literals.scala:63).
            let mark = c.save();
            c.bump(); // try the separator comma
            if starts_full_expr(c.peek()) {
                continue;
            }
            c.restore(mark);
            break;
        }
        // (`:` ~/ `_*`).? — varargs ascription (Core.scala:47: `` `_*` = `_` ~ `*` ``).
        if c.at_sym_kw(Kw::Colon) {
            c.bump(); // `:` ~/ — committed
            if !(c.peek().kind == TokenKind::Ident && c.peek().text(c.src) == "_") {
                return Err(ParseError::Syntax {
                    pos: c.peek().start,
                    expected: "`_*`".to_string(),
                });
            }
            c.bump(); // `_`
            if !c.at_op("*") {
                return Err(ParseError::Syntax {
                    pos: c.peek().start,
                    expected: "`*`".to_string(),
                });
            }
            c.bump(); // `*`
        }
    }
    // TrailingComma = ("," WS Newline)? (Literals.scala:63).
    if c.peek().kind == TokenKind::Comma && c.comma_then_newline() {
        c.bump();
    }
    c.expect(&TokenKind::RParen, ")")?;
    Ok(())
}

/// `SimpleType` (Types.scala:119-133): `(TupleType | TypeId) ~ TypeArgs.rep`, then
/// resolved to a concrete `SType`. `Index` is captured at the production start for
/// the "Unsupported type" error position.
pub(crate) fn simple_type(c: &mut Cursor) -> Result<SType, ParseError> {
    let start = c.peek().start;
    let base = if c.peek().kind == TokenKind::LParen {
        tuple_type(c)?
    } else {
        type_id(c)?
    };
    let mut arg_groups: Vec<Vec<SType>> = Vec::new();
    while c.peek().kind == TokenKind::LBracket {
        arg_groups.push(type_args(c)?);
    }
    resolve_simple_type(base, arg_groups, start, c.tree_version)
}

/// The `SimpleType` resolution ladder (Types.scala:124-132), case order preserved.
pub(crate) fn resolve_simple_type(
    base: SType,
    mut groups: Vec<Vec<SType>>,
    start: Pos,
    tree_version: u8,
) -> Result<SType, ParseError> {
    // (t: STuple, Seq()) => t                                   (Types.scala:125)
    if matches!(base, SType::STuple(_)) && groups.is_empty() {
        return Ok(base);
    }
    // (STypeApply("Coll"|"Option", ∅), Seq(Seq(t)))            (Types.scala:126-127)
    if let SType::STypeApply { name, args } = &base {
        if args.is_empty() && groups.len() == 1 && groups[0].len() == 1 {
            if name == "Coll" {
                let inner = groups.pop().unwrap().pop().unwrap();
                return Ok(SType::SColl(Box::new(inner)));
            }
            if name == "Option" {
                let inner = groups.pop().unwrap().pop().unwrap();
                return Ok(SType::SOption(Box::new(inner)));
            }
        }
    }
    // (SPrimType(t), Seq()) => t   — predef-available + no type args (Types.scala:128)
    if groups.is_empty() && is_predef_available(&base, tree_version) {
        return Ok(base);
    }
    // (STypeApply(tn, ∅), args) if args.isEmpty => STypeVar(tn) (Types.scala:129)
    if groups.is_empty() {
        if let SType::STypeApply { name, args } = &base {
            if args.is_empty() {
                return Ok(SType::STypeVar(name.clone()));
            }
        }
    }
    // else => error(s"Unsupported type …")                     (Types.scala:130-131)
    Err(ParseError::Semantic {
        pos: start,
        msg: "Unsupported type".to_string(),
    })
}

/// `TupleType` (Types.scala:122): `"(" ~/ Type.rep(0, ",") ~ TrailingComma ~ ")"`.
/// `()` yields the empty tuple type. The paren is a cut, but the FIRST type is not
/// (Types.scala:120-121) — this is naturally satisfied by leading-token dispatch.
pub(crate) fn tuple_type(c: &mut Cursor) -> Result<SType, ParseError> {
    c.expect(&TokenKind::LParen, "(")?;
    let items = type_list(c)?;
    c.expect(&TokenKind::RParen, ")")?;
    Ok(SType::STuple(items))
}

/// `TypeArgs` (Types.scala:117): `"[" ~/ Type.rep(0, ",") ~ TrailingComma ~ "]"`.
/// `[]` is legal and yields an empty argument list. The bracket is a cut.
pub(crate) fn type_args(c: &mut Cursor) -> Result<Vec<SType>, ParseError> {
    c.expect(&TokenKind::LBracket, "[")?;
    let items = type_list(c)?;
    c.expect(&TokenKind::RBracket, "]")?;
    Ok(items)
}

/// `Type.rep(0, ",") ~ TrailingComma` — the comma-separated type list shared by
/// `TupleType` and `TypeArgs`, stopping before the closer. A separator comma must
/// be followed by another type; a trailing comma is legal only when directly
/// followed by a `Newline` (Literals.scala:63).
pub(crate) fn type_list(c: &mut Cursor) -> Result<Vec<SType>, ParseError> {
    let mut items = Vec::new();
    if starts_type(c.peek()) {
        loop {
            items.push(type_(c, false)?);
            if c.peek().kind != TokenKind::Comma {
                break;
            }
            // A comma is a SEPARATOR whenever another type follows (newlines are
            // transparent); only a comma with no following type is a trailing comma.
            // Matches fastparse `Type.rep(_, ",") ~ TrailingComma` — try `, ~ Type`
            // first so a multi-line tuple/type-arg list parses every element.
            let mark = c.save();
            c.bump(); // try the separator comma
            if starts_type(c.peek()) {
                continue;
            }
            // `sep ~ Type` failed → rewind the comma; a legal trailing comma is one
            // directly followed by a `Newline` before the closer (Literals.scala:63).
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

/// `TypeId` (Types.scala:108-115): a `StableId`. A bare identifier resolves via the
/// predef table (hit → the `SType`; miss → `STypeApply{name, args: []}`). A dotted
/// path is a semantic error ("Path types are not supported") at the segment after
/// the (last) dot — mirroring the `mkSelect` fold's source context (Core.scala:63-66).
pub(crate) fn type_id(c: &mut Cursor) -> Result<SType, ParseError> {
    let head = c.peek().clone();
    if !is_id(&head) {
        return Err(ParseError::Syntax {
            pos: head.start,
            expected: "type identifier".to_string(),
        });
    }
    c.bump();
    let name = head.text(c.src).to_string();

    let mut last_segment: Option<Pos> = None;
    while c.peek().kind == TokenKind::Dot {
        c.bump(); // "." ~ PostDotCheck ~/
        let seg = c.peek().clone();
        if !is_id(&seg) {
            return Err(ParseError::Syntax {
                pos: seg.start,
                expected: "identifier after `.`".to_string(),
            });
        }
        last_segment = Some(seg.start);
        c.bump();
    }
    if let Some(pos) = last_segment {
        return Err(ParseError::Semantic {
            pos,
            msg: "Path types are not supported".to_string(),
        });
    }
    Ok(match predef_type(&name) {
        Some(t) => t,
        None => SType::STypeApply {
            name,
            args: Vec::new(),
        },
    })
}

/// `TypeBounds` (Types.scala:152): `(`>:` ~/ Type).? ~ (`<:` ~/ Type).?`. Parsed and
/// discarded; each bound is a cut.
pub(crate) fn type_bounds(c: &mut Cursor) -> Result<(), ParseError> {
    if c.at_op(">:") {
        c.bump();
        type_(c, false)?;
    }
    if c.at_op("<:") {
        c.bump();
        type_(c, false)?;
    }
    Ok(())
}
