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

use crate::ast::{ArithKind, BitKind, Expr, RelKind};
use crate::error::ParseError;
use crate::span::Pos;
use crate::stype::{is_predef_available, predef_type, SType};
use crate::token::{tokenize, Kw, Token, TokenKind};

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

    /// Second non-`Newline` token (one token of lookahead past `peek`). Used by
    /// `stable_id` to realise `PostDotCheck` — inspecting the token after a `.`
    /// without committing to consuming the dot.
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

    /// True iff the next token is the symbolic keyword `k`, accepting BOTH its
    /// reserved `Kw` token AND the comment-adjacent `OpId` form. A symbolic-keyword
    /// op-run lexed DIRECTLY before a `//`/`/*` comment is a `PlainId` operator
    /// identifier (token.rs `lex_op_run`: the reserved-check's `!OpChar` sees the
    /// comment's `/` and fails), yet the grammar keyword matcher `Key.O(...)`
    /// (Basic.scala:76-77) carries a comment exception and still matches it here.
    /// Used at every `=`/`:`/`=>`/`@` keyword site so `val x =//c 1`,
    /// `(x:/*c*/ Int)`, `Int =>/*c*/ Long`, `@/*c*/foo val` all parse — while the
    /// same op-id in an identifier position (`a.=>/*c*/`, an infix `x #/*c*/ y`)
    /// flows through the ordinary `is_id` path. oracle-mapped.
    fn at_sym_kw(&self, k: Kw) -> bool {
        let t = self.peek();
        if t.kind == TokenKind::Kw(k) {
            return true;
        }
        if t.kind != TokenKind::OpId {
            return false;
        }
        match k {
            Kw::Colon => t.text(self.src) == ":",
            Kw::Assign => t.text(self.src) == "=",
            Kw::Hash => t.text(self.src) == "#",
            Kw::At => t.text(self.src) == "@",
            Kw::FatArrow => matches!(t.text(self.src), "=>" | "\u{21D2}"),
            _ => false,
        }
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

    /// `Semis.?` (Literals.scala:50-51): consume a maximal run of `Semi` and
    /// `Newline` tokens (`Semis = ( ';' | Newline+ )+`). Returns whether any were
    /// consumed. Used for the block-body separator, the leading/trailing `Semis`
    /// of `BaseBlock`, and the `{`/`}` semicolon absorption (Core.scala:49-50).
    fn skip_semis(&mut self) -> bool {
        let start = self.i;
        while self.i < self.toks.len() {
            if Self::is_nl(&self.toks[self.i]) || self.toks[self.i].kind == TokenKind::Semi {
                self.i += 1;
            } else {
                break;
            }
        }
        self.i != start
    }

    /// `Semis.?` (as `skip_semis`), additionally reporting whether a LITERAL `;`
    /// (`Semi`) — not merely a `Newline` — was among the consumed run.
    ///
    /// `BaseBlock`'s leading `Semis.?` uses this to decide whether an otherwise
    /// empty block was rescued by an explicit `;`. In SigmaParser the implicit
    /// `ScalaWhitespace` swallows newlines and comments *before* that `Semis.?`
    /// ever runs, so an empty block matches the `Semis` only when a bare `;` is
    /// present: `{;}` parses as `Block([], ())` while `{}` / `{\n}` / `{/*c*/}`
    /// are rejected (oracle-verified against SigmaParser 6.0.2).
    fn skip_semis_lit(&mut self) -> bool {
        let start = self.i;
        self.skip_semis();
        self.toks[start..self.i]
            .iter()
            .any(|t| t.kind == TokenKind::Semi)
    }

    /// `BlockStat.rep(sep = Semis)` continuation for a SINGLE `BlockChunk`
    /// (Exprs.scala:259): consume the upcoming `Newline`/`Semi` run and return
    /// `true` ONLY when it contains a literal `;`; otherwise consume NOTHING and
    /// return `false`.
    ///
    /// Within a `.rep(sep = Semis)` the implicit `ScalaWhitespace` eats the trailing
    /// newlines BEFORE the `Semis` separator runs, so `Semis`' `Newline+` alternative
    /// is dead and only a `;` continues the statement list. A bare-newline run thus
    /// ends the chunk — its statements belong to the enclosing block's NEXT
    /// `BlockChunk`. Used by `lambda_rhs` (a lone `BlockChunk`) and `block_body`'s
    /// intra-chunk loop. oracle: `{ val f = (x,y)=>x\nf }` ACCEPT (body `x`, `f` is
    /// the block result) vs `{ val f = (x,y)=>x; f }` REJECT 1:18 (body `block([x,f])`,
    /// `x` a non-Val non-tail).
    fn skip_semis_if_lit(&mut self) -> bool {
        let mut j = self.i;
        let mut has_semi = false;
        while j < self.toks.len()
            && (Self::is_nl(&self.toks[j]) || self.toks[j].kind == TokenKind::Semi)
        {
            has_semi |= self.toks[j].kind == TokenKind::Semi;
            j += 1;
        }
        if has_semi {
            self.i = j;
        }
        has_semi
    }

    /// `Semi.?` (Literals.scala:50): consume AT MOST one leading `;`. Newlines are
    /// transparently skipped by `peek`, so the only observable effect of the
    /// single-`Semi` option is a lone `;` (a second `;` is left for the caller —
    /// this is what makes `if(c) t;;else e` a hard error, Exprs.scala:48).
    ///
    /// Deviation: `if (c) t\n;else e` — Scala's `Semi.?` (Basic.scala:35) consumes
    /// the newline-run as the single Semi, and the residual `;` blocks `else`
    /// (reject). Our transparent-newline skip consumes the `;` directly (accept).
    /// Accept-divergence on this pathological separator mix only.
    fn take_one_semi(&mut self) {
        let j = self.skip_nl(self.i);
        if j < self.toks.len() && self.toks[j].kind == TokenKind::Semi {
            self.i = j + 1;
        }
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
        // ConsumeComments' `~/`-cut: a block comment in the post-newline region
        // that is not newline-terminated (a `MultilineComment` matched but the
        // required trailing `Basic.Newline` is absent, Literals.scala:58,83) makes
        // the `.rep` fail hard. `OneNLMax` is `NoCut` so the caller backtracks, but
        // the continuation is refused. The lexer stamps this as `bc_before` on the
        // token `OneNLMax` lands on. oracle: `a +\n/*c*/b` REJECT.
        if self.i < self.toks.len() && self.toks[self.i].bc_before {
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
fn type_(c: &mut Cursor, raw_entry: bool) -> Result<SType, ParseError> {
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
fn postfix_type(c: &mut Cursor) -> Result<SType, ParseError> {
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
    while c.no_newline_before_next() && c.at_sym_kw(Kw::At) {
        annot(c)?;
    }
    Ok(t)
}

/// `Annot` (Types.scala:159): `` `@` ~/ SimpleType ~ ("(" ~/ (Exprs ~ (`:` ~/
/// `_*`).?).? ~ TrailingComma ~ ")").rep ``. The annotation type and every argument
/// group are parsed and DISCARDED; argument expressions parse in `ExprCtx`
/// (`Exprs`, Types.scala:168).
fn annot(c: &mut Cursor) -> Result<(), ParseError> {
    c.bump(); // `@` ~/ — committed
    simple_type(c)?; // discarded
    while c.peek().kind == TokenKind::LParen {
        annot_arg_group(c)?;
    }
    Ok(())
}

/// One `"(" ~/ (Exprs ~ (`:` ~/ `_*`).?).? ~ TrailingComma ~ ")"` argument group of
/// an annotation (Types.scala:159). Everything parsed here is discarded.
fn annot_arg_group(c: &mut Cursor) -> Result<(), ParseError> {
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
        type_(c, false)?;
    }
    if c.at_op("<:") {
        c.bump();
        type_(c, false)?;
    }
    Ok(())
}

// =============================================================================
// Expression grammar: atoms (SimpleExpr) and the postfix suffix machinery
// (ExprSuffix / applySuffix). Exprs.scala:46-132, 191-211, 315-320; Core.scala:62-69.
// =============================================================================

/// Expression parsing context (Exprs.scala:27-31). Semicolon inference is on in
/// statement positions and off inside nested expressions; it gates the
/// `NoSemis`/`OneSemiMax` combinators (Exprs.scala:42-43).
#[derive(Clone, Copy, PartialEq)]
enum Ctx {
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
    fn semi_inference(self) -> bool {
        matches!(self, Ctx::Stat | Ctx::Free)
    }
}

/// One postfix `ExprSuffix` marker (Exprs.scala:79-83), folded by `apply_suffix`.
///
/// The markers carry no positions: every node `apply_suffix` builds takes
/// `pos = f.pos()` (Scala pins `builder.currentSrcCtx = f.sourceContext` for the
/// whole fold, Exprs.scala:192), so a marker's own captured index is discarded.
enum Suffix {
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
fn starts_expr(t: &Token) -> bool {
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
fn starts_full_expr(t: &Token) -> bool {
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
fn try_literal(t: &Token, src: &str) -> Option<Expr> {
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

/// `Expr` (Exprs.scala:46-75): `If | Fun | PostfixLambda`. Ordered choice by
/// leading token: a reserved `if`, the word `def`, else the postfix/lambda layer.
/// `parse`, `Parened` and `ArgList` all route their sub-expressions through here.
fn expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
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
fn if_expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
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
fn simple_expr(c: &mut Cursor, _ctx: Ctx) -> Result<Expr, ParseError> {
    let t = c.peek();
    if t.kind == TokenKind::LBrace {
        return block_expr(c); // BlockExpr
    }
    if let Some(e) = try_literal(t, c.src) {
        c.bump(); // ExprLiteral wins over StableId (`null`/`true` are literals)
        return Ok(e);
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
fn block_expr(c: &mut Cursor) -> Result<Expr, ParseError> {
    c.expect(&TokenKind::LBrace, "{")?; // "{" ~/ — committed
    let e = base_block(c)?;
    c.expect(&TokenKind::RBrace, "}")?;
    Ok(e)
}

// =============================================================================
// Block machinery, val/def definitions, and the PostfixLambda suffix.
// Exprs.scala:57-77, 214-320; SigmaParser.scala:26-35; Types.scala:25-27, 136-150.
// =============================================================================

/// One argument list: `(name, type)` pairs with `NoType` for unascribed params.
/// Shared by `BlockLambdaHead`, `FunArgs`, and the lambda constructor.
type ArgList = Vec<(String, SType)>;

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
fn base_block(c: &mut Cursor) -> Result<Expr, ParseError> {
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
fn block_body(c: &mut Cursor) -> Result<(Vec<Expr>, bool), ParseError> {
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
fn reject_chunk_lambda_head(c: &mut Cursor) -> Result<(), ParseError> {
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
fn block_chunk_stats(c: &mut Cursor) -> Result<Vec<Expr>, ParseError> {
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
fn block_stat(c: &mut Cursor) -> Result<Expr, ParseError> {
    let mark = c.save();
    prelude(c)?; // Annot.rep ~ `lazy`.?
    if c.at_word("val") {
        return val_def(c); // Dcl = `val` ~/ ValVarDef
    }
    c.restore(mark); // BlockDef failed → discard the prelude
    expr(c, Ctx::Stat) // StatCtx.Expr
}

/// `Prelude = Annot.rep ~ `lazy`.?` (Exprs.scala:257). Parsed and discarded.
fn prelude(c: &mut Cursor) -> Result<(), ParseError> {
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
fn starts_block_stat(t: &Token) -> bool {
    starts_expr(t) || matches!(t.kind, TokenKind::Kw(Kw::If) | TokenKind::Kw(Kw::At))
}

/// `block(stats)` / `extractBlockStats` (Exprs.scala:262-278): empty → `Block([],
/// UnitConstant)`; otherwise every stat but the last must be a `Val` (unwrapped
/// into a binding), the last is the result (which MAY itself be a `Val`). A
/// non-`Val` in non-tail position is a Semantic error at that stat's own position.
/// The block/unit node carries the block's `pos`.
fn block_from_stats(stats: Vec<Expr>, pos: Pos) -> Result<Expr, ParseError> {
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
fn try_block_lambda(c: &mut Cursor) -> Result<Option<(Pos, ArgList)>, ParseError> {
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
fn starts_fun_arg(t: &Token) -> bool {
    is_id(t) || t.kind == TokenKind::Kw(Kw::At)
}

/// `Arg.rep(1, ",") ~ TrailingComma` (Exprs.scala:249, Types.scala:141) — the
/// comma-separated argument list shared by `BlockLambdaHead` and `FunArgs`. Each
/// `Arg = Annot.rep ~ Id.! ~ (`:` ~/ Type).?`, untyped args default to `NoType`.
fn arg_list(c: &mut Cursor) -> Result<ArgList, ParseError> {
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
fn fun_arg(c: &mut Cursor) -> Result<(String, SType), ParseError> {
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
fn expect_assign(c: &mut Cursor) -> Result<(), ParseError> {
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
    // `!OpChar` fails at the following `>` — one byte past t.start, same as the
    // OpId `==` arm. The Unicode alias `⇒` (U+21D2, three UTF-8 bytes starting
    // 0xE2) does NOT start with `=`, so keep t.start for that form.
    if t.kind == TokenKind::Kw(Kw::FatArrow) {
        let src_byte = c.src.as_bytes().get(t.start as usize).copied();
        let pos_offset = if src_byte == Some(b'=') { 1 } else { 0 };
        return Err(ParseError::Syntax {
            pos: t.start + pos_offset,
            expected: "`=`".to_string(),
        });
    }
    Err(ParseError::Syntax {
        pos: t.start,
        expected: "`=`".to_string(),
    })
}

/// `Dcl = `val` ~/ ValVarDef` (Types.scala:25-27) with `ValVarDef = Index ~
/// BindPattern ~ (`:` ~/ Type).? ~ (`=` ~/ FreeCtx.Expr)` (SP:26-33). The pattern
/// must reduce to a single `Ident` → `Val(name, T|NoType, body)` at the pattern's
/// start; any other pattern → Semantic "Only single name patterns supported" at
/// that same position. The `val` keyword is a cut, so a malformed `ValVarDef` is a
/// hard error.
fn val_def(c: &mut Cursor) -> Result<Expr, ParseError> {
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
enum BindPat {
    Name(String),
    Other,
}

/// `BindPattern = SimplePattern` (Exprs.scala:309-312): `TupleEx | Extractor |
/// VarId` (Exprs.scala:234-240). The pattern reduces to the bare `StableId` result:
/// a single-segment id (with or without extractor args) yields `Name`; a dotted path
/// (→ `Select`, non-`Ident`) or a leading tuple pattern yields `Other`. Consumed in
/// full so the following `(`:` Type).? ~ `=` Expr` still parses (matching the
/// reference's parse-then-map order).
fn bind_pattern(c: &mut Cursor) -> Result<BindPat, ParseError> {
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
fn tuple_ex(c: &mut Cursor) -> Result<(), ParseError> {
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
fn starts_pattern(t: &Token) -> bool {
    t.kind == TokenKind::LParen || is_id(t)
}

/// `Pattern = (WL ~ TypeOrBindPattern).rep(1, sep = "|"./)` (Exprs.scala:304).
/// Parsed and DISCARDED (a `TupleEx` element the `Extractor` drops, :235-236). The
/// `|` alternation separator carries a cut (`"|"./`), so a `|` with no following
/// alternative is a HARD reject. oracle: `Some(x | y)` / `Some(Foo | x)` ACCEPT,
/// `Some(x |)` REJECT 1:15.
fn pattern(c: &mut Cursor) -> Result<(), ParseError> {
    type_or_bind_pattern(c)?;
    while c.at_op("|") {
        c.bump(); // "|" ./ — cut: another alternative MUST follow
        type_or_bind_pattern(c)?;
    }
    Ok(())
}

/// `TypeOrBindPattern = (TypePattern | BindPattern).ignore` (Exprs.scala:305): a
/// typed pattern `v : T`, else the `SimplePattern` machinery. Both are DISCARDED.
fn type_or_bind_pattern(c: &mut Cursor) -> Result<(), ParseError> {
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
fn try_type_pattern(c: &mut Cursor) -> Result<bool, ParseError> {
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
fn is_var_id_head(t: &Token, src: &str) -> bool {
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
fn fun_def(c: &mut Cursor, committed: &mut bool) -> Result<Expr, ParseError> {
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
fn fun_sig(c: &mut Cursor, committed: &mut bool) -> Result<Vec<ArgList>, ParseError> {
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
fn fun_type_args(c: &mut Cursor) -> Result<(), ParseError> {
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
fn type_arg(c: &mut Cursor) -> Result<(), ParseError> {
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
fn type_arg_list(c: &mut Cursor) -> Result<(), ParseError> {
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
fn type_arg_variant(c: &mut Cursor) -> Result<(), ParseError> {
    while c.at_sym_kw(Kw::At) {
        annot(c)?; // Annot.rep — discarded
    }
    if c.at_op("+") || c.at_op("-") {
        c.bump(); // variance marker
    }
    type_arg(c)
}

/// `DottyExtMethodSubj = "(" ~/ Id.! ~ `:` ~/ Type ~ ")"` (Types.scala:150), the
/// (rarely used) extension-method subject. Returns `None` (cursor unmoved) only when
/// there is no leading `(`. Once the `(` matches, the `~/` cut fires — `*committed`
/// is set and every subsequent mismatch is a HARD error, not a `None` backtrack (a
/// leading `(` after `def` can only be a DottyExtMethodSubj, since `Id.!` cannot
/// match `(`). oracle: `def(1)` REJECT 1:5, `def (x) = 1` REJECT 1:7,
/// `def (x: Int) foo = x` ACCEPT.
fn try_dotty_subj(
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
fn postfix_lambda(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
    let pos = c.peek().start; // Index
    let e = postfix_expr(c, ctx)?;
    let body: Option<Expr> = if c.at_kw(Kw::FatArrow) {
        c.bump(); // `=>`
        lambda_rhs(c, ctx)?
    } else if c.at_kw(Kw::Assign) {
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
fn lambda_rhs(c: &mut Cursor, ctx: Ctx) -> Result<Option<Expr>, ParseError> {
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
fn lambda_from_tuple(items: Vec<Expr>, body: Expr, pos: Pos) -> Result<Expr, ParseError> {
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
fn stable_id(c: &mut Cursor) -> Result<Expr, ParseError> {
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
fn post_dot_banned(t: &Token, src: &str) -> bool {
    if t.kind == TokenKind::LBrace {
        return true;
    }
    t.kind == TokenKind::Ident && matches!(t.text(src), "super" | "this" | "type" | "_")
}

/// `Parened` (Exprs.scala:119,126-130): `Index ~ "(" ~/ TypeExpr.rep(0,",") ~
/// TrailingComma ~ ")"`. Items parse in `ExprCtx` (Exprs.scala:33). 0 → `UnitConst`;
/// 1 → the item itself (pure grouping, no node); ≥2 → `Tuple`. The `Index` (before
/// `"("`) is the position of `UnitConst`/`Tuple`.
fn parened(c: &mut Cursor) -> Result<Expr, ParseError> {
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
fn expr_list(c: &mut Cursor) -> Result<Vec<Expr>, ParseError> {
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
fn expr_suffix(c: &mut Cursor, ctx: Ctx) -> Result<Vec<Suffix>, ParseError> {
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
fn paren_arg_list(c: &mut Cursor) -> Result<Suffix, ParseError> {
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
fn apply_suffix(f: Expr, suffixes: Vec<Suffix>) -> Result<Expr, ParseError> {
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

// =============================================================================
// Prefix / infix / postfix layers: operator precedence.
// Exprs.scala:78,85-117,141-189; SigmaParser.scala:40-101.
// =============================================================================

/// `PrefixExpr` (Exprs.scala:85-88): `ExprPrefix? ~ SimpleExpr`. The optional
/// prefix wraps the ATOM via `mk_unary_op` — the suffixes of `PostfixExpr` then
/// wrap around THAT result (so `-f(x)` is `Apply(Negation(f), [x])`, while
/// `-OUTPUTS.size` is `Negation(Select(..))` because `StableId` already consumed
/// the dotted chain inside `SimpleExpr`).
fn prefix_expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
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
fn is_op_char_byte(b: u8) -> bool {
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
fn prefix_op(c: &mut Cursor) -> Option<String> {
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
fn postfix_expr(c: &mut Cursor, ctx: Ctx) -> Result<Expr, ParseError> {
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
fn precedence_of(op: &str) -> u8 {
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
fn mk_infix_tree(
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
fn mk_unary_op(op: &str, arg: Expr, tree_version: u8) -> Result<Expr, ParseError> {
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
fn is_parse_as_method(op: &str) -> bool {
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
fn mk_binary_op(l: Expr, op: &str, r: Expr, tree_version: u8) -> Result<Expr, ParseError> {
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
                        range: Box::new(SType::SBoolean)
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
}
