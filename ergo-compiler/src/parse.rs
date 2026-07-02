//! Parser entry points and the ErgoScript TYPE grammar.
//!
//! This module lands the crate's final public API — `parse` and `parse_type`
//! (Scala `SigmaParser.apply` / `SigmaParser.parseType`, SigmaParser.scala:103-117)
//! — plus the `Cursor` the expression/statement grammar of Tasks 7-9 drives.
//!
//! The TYPE grammar is a production-for-production port of Scala `Types.scala`
//! (169 lines). Each function cites the mirrored Scala production. Types resolve
//! straight to `SType` (there is no separate type-AST in the reference).
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
use crate::span::Pos;
use crate::stype::{is_predef_available, predef_type, SType};
use crate::token::{tokenize, Kw, Token, TokenKind};

/// Parse an ErgoScript expression (Scala `SigmaParser.apply`,
/// SigmaParser.scala:114-117: `StatCtx.Expr ~ End`).
///
/// The expression grammar lands in Task 7; this task ships only the type grammar
/// and the shared public entry points. We still tokenize so that lexical errors
/// (unterminated comment, numeric overflow) surface at the correct offset instead
/// of being masked by the stub.
pub fn parse(source: &str, tree_version: u8) -> Result<Expr, ParseError> {
    let _ = tree_version;
    let toks = tokenize(source)?;
    let pos = toks.first().map(|t| t.start).unwrap_or(0);
    Err(ParseError::Syntax {
        pos,
        expected: "expression grammar lands in Task 7".to_string(),
    })
}

/// Parse an ErgoScript type (Scala `SigmaParser.parseType`,
/// SigmaParser.scala:103-111: `Type ~ End`).
pub fn parse_type(source: &str, tree_version: u8) -> Result<SType, ParseError> {
    let toks = tokenize(source)?;
    let mut c = Cursor::new(source, toks, tree_version);
    let t = type_(&mut c)?;
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

// =============================================================================
// Cursor: token stream with newline-sensitivity primitives.
// =============================================================================

/// Token cursor consumed by the type grammar (this task) and by the
/// expression/statement grammar (Tasks 7-9).
///
/// Default access (`peek`/`peek2`/`bump`) transparently skips `Newline` tokens,
/// mirroring fastparse's implicit `ScalaWhitespace` (which includes newlines).
/// The newline-sensitivity primitives (`no_newline_before_next`, `take_one_semi`,
/// `skip_semis`, `one_nl_max`) inspect `Newline` tokens explicitly — this is how
/// semicolon inference and the `OneNLMax`/`NotNewline` combinators are realised
/// (Literals.scala:39-63).
struct Cursor<'a> {
    src: &'a str,
    toks: Vec<Token>,
    i: usize,
    tree_version: u8,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a str, toks: Vec<Token>, tree_version: u8) -> Self {
        Cursor {
            src,
            toks,
            i: 0,
            tree_version,
        }
    }

    fn is_nl(t: &Token) -> bool {
        matches!(t.kind, TokenKind::Newline { .. })
    }

    /// First index `>= from` whose token is not a `Newline`. The stream is
    /// `Eof`-terminated and `Eof` is not a `Newline`, so this always terminates.
    fn skip_nl(&self, mut j: usize) -> usize {
        while j < self.toks.len() && Self::is_nl(&self.toks[j]) {
            j += 1;
        }
        j
    }

    /// Next non-`Newline` token.
    fn peek(&self) -> &Token {
        &self.toks[self.skip_nl(self.i)]
    }

    /// Second non-`Newline` token (one token of lookahead past `peek`).
    #[allow(dead_code)] // consumed by Tasks 7-9 (expression lookahead); pinned by tests below.
    fn peek2(&self) -> &Token {
        let j1 = self.skip_nl(self.i);
        let j2 = self.skip_nl(j1 + 1);
        &self.toks[j2]
    }

    /// Advance past any leading `Newline`s and one token; return that token.
    fn bump(&mut self) -> Token {
        let j = self.skip_nl(self.i);
        self.i = j + 1;
        self.toks[j].clone()
    }

    /// Backtracking mark. fastparse rewinds the input position the same way.
    fn save(&self) -> usize {
        self.i
    }

    fn restore(&mut self, mark: usize) {
        self.i = mark;
    }

    fn at_kw(&self, k: Kw) -> bool {
        self.peek().kind == TokenKind::Kw(k)
    }

    /// `Ident` whose text is exactly `w` (grammar words `val`/`def`/`with`/… that
    /// are *not* reserved keywords, recon-lexical.md §2.3).
    fn at_word(&self, w: &str) -> bool {
        let t = self.peek();
        t.kind == TokenKind::Ident && t.text(self.src) == w
    }

    /// `OpId` whose text is exactly `s` (`>:`, `<:`, `*` — Core.scala:42-47).
    fn at_op(&self, s: &str) -> bool {
        let t = self.peek();
        t.kind == TokenKind::OpId && t.text(self.src) == s
    }

    fn expect(&mut self, kind: &TokenKind, what: &str) -> Result<Token, ParseError> {
        if &self.peek().kind == kind {
            Ok(self.bump())
        } else {
            Err(ParseError::Syntax {
                pos: self.peek().start,
                expected: what.to_string(),
            })
        }
    }

    // ----- newline-sensitivity primitives (Literals.scala:39-63) -----

    /// `NotNewline` (Literals.scala:55): true iff no `Newline` separates the
    /// cursor from the next token. A newline manifests as a `Newline` token at
    /// the current raw index, so the check is purely local.
    fn no_newline_before_next(&self) -> bool {
        self.i >= self.toks.len() || !Self::is_nl(&self.toks[self.i])
    }

    /// `Semi` (Literals.scala:50, Basic.scala:35): one `;` *or* a run of one or
    /// more `Newline`s. Returns true if a separator was consumed.
    #[allow(dead_code)] // consumed by Tasks 7-9 (block/statement grammar); pinned by tests below.
    fn take_one_semi(&mut self) -> bool {
        if self.i < self.toks.len() {
            match self.toks[self.i].kind {
                TokenKind::Semi => {
                    self.i += 1;
                    return true;
                }
                TokenKind::Newline { .. } => {
                    while self.i < self.toks.len()
                        && matches!(self.toks[self.i].kind, TokenKind::Newline { .. })
                    {
                        self.i += 1;
                    }
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// `Semis` (Literals.scala:51): `Semi+`. Returns true if any consumed.
    #[allow(dead_code)] // consumed by Tasks 7-9 (block/statement grammar); pinned by tests below.
    fn skip_semis(&mut self) -> bool {
        let mut any = false;
        while self.take_one_semi() {
            any = true;
        }
        any
    }

    /// `OneNLMax` (Literals.scala:57-60), over `Newline` tokens: optionally
    /// consume ONE `Newline` (either flavor), then consume a run of
    /// comment-preceded newlines (`Newline { after_comment: true }`), and succeed
    /// iff the next token is not a `Newline`. Pure lookahead: the cursor is
    /// restored on failure.
    fn one_nl_max(&mut self) -> bool {
        let save = self.i;
        // Basic.Newline.?
        if self.i < self.toks.len() && Self::is_nl(&self.toks[self.i]) {
            self.i += 1;
        }
        // ConsumeComments: (WSChars.? ~ Comment ~ WSChars.? ~ Newline).rep
        while self.i < self.toks.len()
            && matches!(
                self.toks[self.i].kind,
                TokenKind::Newline {
                    after_comment: true
                }
            )
        {
            self.i += 1;
        }
        // ~ NotNewline
        if self.i < self.toks.len() && Self::is_nl(&self.toks[self.i]) {
            self.i = save;
            return false;
        }
        true
    }

    /// True iff the raw token immediately after the comma that `peek` returns is a
    /// `Newline` — the `TrailingComma = "," ~ WS ~ Basic.Newline` predicate
    /// (Literals.scala:63). `WS` is newline-free, so a legal trailing comma is
    /// always directly followed by a `Newline` token.
    fn comma_then_newline(&self) -> bool {
        let j = self.skip_nl(self.i);
        matches!(
            self.toks.get(j + 1).map(|t| &t.kind),
            Some(TokenKind::Newline { .. })
        )
    }
}

// =============================================================================
// Leading-token predicates (realise ordered choice / cut boundaries).
// =============================================================================

/// A `StableId` / infix-operator head: `Id = BacktickId | PlainId` where
/// `PlainId` includes operator identifiers (Identifiers.scala:32,37).
fn is_id(t: &Token) -> bool {
    matches!(
        t.kind,
        TokenKind::Ident | TokenKind::OpId | TokenKind::BacktickId
    )
}

/// A token that can begin a `SimpleType`/`CompoundType`: `BasicType = TupleType |
/// TypeId` (Types.scala:123), i.e. `(` or an `Id`.
fn starts_compound(t: &Token) -> bool {
    is_id(t) || t.kind == TokenKind::LParen
}

/// A token that can begin a `Type`: `CompoundType` head, or a leading `=>`
/// (Types.scala:63).
fn starts_type(t: &Token) -> bool {
    starts_compound(t) || t.kind == TokenKind::Kw(Kw::FatArrow)
}

// =============================================================================
// Type grammar (Types.scala port).
// =============================================================================

/// `Type` (Types.scala:63): `` `=>`.? ~~ PostfixType ~ TypeBounds ~ `*`.? ``.
/// The leading `=>`, the `TypeBounds`, and the trailing `*` are parsed and
/// discarded. The `=>`-prefix uses raw adjacency (`~~`) in Scala, but since it is
/// discarded, consume-if-present is faithful.
fn type_(c: &mut Cursor) -> Result<SType, ParseError> {
    if c.at_kw(Kw::FatArrow) {
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
fn postfix_type(c: &mut Cursor) -> Result<SType, ParseError> {
    let d = infix_type(c)?;
    if c.at_kw(Kw::FatArrow) {
        c.bump(); // `=>` ~/  — committed
        let r = type_(c)?;
        let dom = match d {
            SType::STuple(items) => items,
            other => vec![other],
        };
        Ok(SType::SFunc {
            dom,
            range: Box::new(r),
        })
    } else {
        Ok(d)
    }
}

/// `InfixType` (Types.scala:70-95): `CompoundType ~~ (NotNewline ~ Id.! ~~
/// OneNLMax ~ CompoundType).repX`, folded by associativity. `Index` is captured at
/// the production start for the mixed-associativity error position.
fn infix_type(c: &mut Cursor) -> Result<SType, ParseError> {
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
fn build_infix(head: SType, tail: Vec<(String, SType)>, start: Pos) -> Result<SType, ParseError> {
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
fn compound_type(c: &mut Cursor) -> Result<SType, ParseError> {
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
fn annot_type(c: &mut Cursor) -> Result<SType, ParseError> {
    let t = simple_type(c)?;
    while c.no_newline_before_next() && c.at_kw(Kw::At) {
        annot(c)?;
    }
    Ok(t)
}

/// `Annot` (Types.scala:159): `` `@` ~/ SimpleType ~ ("(" … ")").rep ``.
/// The annotation body is discarded. Annotation arguments are an expression list
/// (`Exprs`) that lands with the expression grammar; until then a `(` after the
/// annotation type is a syntax error. Task 7 replaces this with the real `Exprs`
/// call. No ported test exercises annotation arguments before Task 7.
fn annot(c: &mut Cursor) -> Result<(), ParseError> {
    c.bump(); // `@` ~/ — committed
    simple_type(c)?; // discarded
    if c.peek().kind == TokenKind::LParen {
        return Err(ParseError::Syntax {
            pos: c.peek().start,
            expected: "annotation arguments land in Task 7".to_string(),
        });
    }
    Ok(())
}

/// `SimpleType` (Types.scala:119-133): `(TupleType | TypeId) ~ TypeArgs.rep`, then
/// resolved to a concrete `SType`. `Index` is captured at the production start for
/// the "Unsupported type" error position.
fn simple_type(c: &mut Cursor) -> Result<SType, ParseError> {
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
fn resolve_simple_type(
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
fn tuple_type(c: &mut Cursor) -> Result<SType, ParseError> {
    c.expect(&TokenKind::LParen, "(")?;
    let items = type_list(c)?;
    c.expect(&TokenKind::RParen, ")")?;
    Ok(SType::STuple(items))
}

/// `TypeArgs` (Types.scala:117): `"[" ~/ Type.rep(0, ",") ~ TrailingComma ~ "]"`.
/// `[]` is legal and yields an empty argument list. The bracket is a cut.
fn type_args(c: &mut Cursor) -> Result<Vec<SType>, ParseError> {
    c.expect(&TokenKind::LBracket, "[")?;
    let items = type_list(c)?;
    c.expect(&TokenKind::RBracket, "]")?;
    Ok(items)
}

/// `Type.rep(0, ",") ~ TrailingComma` — the comma-separated type list shared by
/// `TupleType` and `TypeArgs`, stopping before the closer. A separator comma must
/// be followed by another type; a trailing comma is legal only when directly
/// followed by a `Newline` (Literals.scala:63).
fn type_list(c: &mut Cursor) -> Result<Vec<SType>, ParseError> {
    let mut items = Vec::new();
    if starts_type(c.peek()) {
        loop {
            items.push(type_(c)?);
            if c.peek().kind != TokenKind::Comma {
                break;
            }
            if c.comma_then_newline() {
                c.bump(); // trailing comma; the Newline stays for the closer's skip
                break;
            }
            let mark = c.save();
            c.bump(); // separator comma
            if starts_type(c.peek()) {
                continue;
            }
            // No type follows and it was not a valid trailing comma: rewind so the
            // closer's `expect` reports the failure at the comma (fastparse rewinds
            // the whole `sep ~ item` when the item fails without a cut).
            c.restore(mark);
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
fn type_id(c: &mut Cursor) -> Result<SType, ParseError> {
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
fn type_bounds(c: &mut Cursor) -> Result<(), ParseError> {
    if c.at_op(">:") {
        c.bump();
        type_(c)?;
    }
    if c.at_op("<:") {
        c.bump();
        type_(c)?;
    }
    Ok(())
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
                range: Box::new(SType::SInt)
            }
        );
        assert_eq!(
            parse_type("Int => Int", 3).unwrap(),
            SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SInt)
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
        // expression-level (Task 10); here assert the type-level classification:
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

    #[test]
    fn cursor_semi_run_and_semis() {
        // ";" is one Semi.
        let mut c1 = cur("a ; b");
        c1.bump(); // `a`
        assert!(c1.take_one_semi()); // the `;`
        assert_eq!(c1.peek().text("a ; b"), "b");
        // A run of newlines is a single Semi; `;\n;` is three Semis absorbed by skip_semis.
        let mut c2 = cur("a\n\n;b");
        c2.bump(); // `a`
        assert!(c2.skip_semis());
        assert_eq!(c2.peek().text("a\n\n;b"), "b");
        // No separator present.
        let mut c3 = cur("a b");
        c3.bump();
        assert!(!c3.take_one_semi());
    }
}
