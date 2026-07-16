use crate::error::ParseError;
use crate::token::{Kw, Token, TokenKind};

use super::MAX_PARSE_DEPTH;

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
pub(crate) struct Cursor<'a> {
    pub(crate) src: &'a str,
    toks: Vec<Token>,
    i: usize,
    pub(crate) tree_version: u8,
    /// Shared `expr()`/`type_()` structural-nesting recursion counter (see
    /// `MAX_PARSE_DEPTH`). Incremented/decremented ONLY by the depth-guard
    /// wrappers around those two entry points, never touched elsewhere.
    depth: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(src: &'a str, toks: Vec<Token>, tree_version: u8) -> Self {
        Cursor {
            src,
            toks,
            i: 0,
            tree_version,
            depth: 0,
        }
    }

    pub(crate) fn is_nl(t: &Token) -> bool {
        matches!(t.kind, TokenKind::Newline { .. })
    }

    /// First index `>= from` whose token is not a `Newline`. The stream is
    /// `Eof`-terminated and `Eof` is not a `Newline`, so this always terminates.
    pub(crate) fn skip_nl(&self, mut j: usize) -> usize {
        while j < self.toks.len() && Self::is_nl(&self.toks[j]) {
            j += 1;
        }
        j
    }

    /// Next non-`Newline` token.
    pub(crate) fn peek(&self) -> &Token {
        &self.toks[self.skip_nl(self.i)]
    }

    /// Second non-`Newline` token (one token of lookahead past `peek`). Used by
    /// `stable_id` to realise `PostDotCheck` — inspecting the token after a `.`
    /// without committing to consuming the dot.
    pub(crate) fn peek2(&self) -> &Token {
        let j1 = self.skip_nl(self.i);
        let j2 = self.skip_nl(j1 + 1);
        &self.toks[j2]
    }

    /// Advance past any leading `Newline`s and one token; return that token.
    pub(crate) fn bump(&mut self) -> Token {
        let j = self.skip_nl(self.i);
        self.i = j + 1;
        self.toks[j].clone()
    }

    /// Backtracking mark. fastparse rewinds the input position the same way.
    pub(crate) fn save(&self) -> usize {
        self.i
    }

    pub(crate) fn restore(&mut self, mark: usize) {
        self.i = mark;
    }

    pub(crate) fn at_kw(&self, k: Kw) -> bool {
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
    ///
    /// For `FatArrow` this OpId arm is ALSO the sole entry for the Unicode arrow `⇒`
    /// (U+21D2): it is not a reserved symbolic keyword, so it always lexes as an
    /// `OpId`, and only the keyword matcher `` `=>` = O("=>") | O("⇒") ``
    /// (Core.scala:23) — i.e. `at_sym_kw` — treats it as the arrow. In an identifier
    /// position the ordinary `is_id` path grabs it first (oracle: `(x,y) ⇒ 1` REJECT,
    /// `{ (x) ⇒ x }` ACCEPT).
    pub(crate) fn at_sym_kw(&self, k: Kw) -> bool {
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
    pub(crate) fn at_word(&self, w: &str) -> bool {
        let t = self.peek();
        t.kind == TokenKind::Ident && t.text(self.src) == w
    }

    /// `OpId` whose text is exactly `s` (`>:`, `<:`, `*` — Core.scala:42-47).
    pub(crate) fn at_op(&self, s: &str) -> bool {
        let t = self.peek();
        t.kind == TokenKind::OpId && t.text(self.src) == s
    }

    pub(crate) fn expect(&mut self, kind: &TokenKind, what: &str) -> Result<Token, ParseError> {
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
    pub(crate) fn no_newline_before_next(&self) -> bool {
        self.i >= self.toks.len() || !Self::is_nl(&self.toks[self.i])
    }

    /// `Semis.?` (Literals.scala:50-51): consume a maximal run of `Semi` and
    /// `Newline` tokens (`Semis = ( ';' | Newline+ )+`). Returns whether any were
    /// consumed. Used for the block-body separator, the leading/trailing `Semis`
    /// of `BaseBlock`, and the `{`/`}` semicolon absorption (Core.scala:49-50).
    pub(crate) fn skip_semis(&mut self) -> bool {
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
    pub(crate) fn skip_semis_lit(&mut self) -> bool {
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
    pub(crate) fn skip_semis_if_lit(&mut self) -> bool {
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
    pub(crate) fn take_one_semi(&mut self) {
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
    ///
    /// `bc_before` on the landing token poisons the call ONLY when a `Newline` was
    /// consumed. Mechanism: `ConsumeComments = (WSChars.? ~ Comment ~ WSChars.? ~
    /// Newline).rep` (Literals.scala:58) cuts on a block comment that is not
    /// followed by a `Newline`; the cut is only reachable AFTER `Newline.?` consumed
    /// a newline. When zero newlines are consumed, the same block comment is plain
    /// implicit whitespace in the gap (not inside `ConsumeComments`) and is harmless
    /// — `OneNLMax` succeeds with zero newlines. oracle: `a +\n/*c*/b` REJECT (nl
    /// consumed → bc_before poisons); `a + /*c*/\nb` ACCEPT (nl consumed, bc_before
    /// not set); `{ val x = 1\n/*c*/(x,y)=>x }` REJECT (block body's `Semis` already
    /// consumed the `\n`, so zero newlines consumed by `one_nl_max` at the `(` — but
    /// `(` must still be detected as a later-chunk block-lambda head and rejected).
    pub(crate) fn one_nl_max(&mut self) -> bool {
        let save = self.i;
        // Basic.Newline.?
        let consumed_nl = self.i < self.toks.len() && Self::is_nl(&self.toks[self.i]);
        if consumed_nl {
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
        // ConsumeComments' `~/`-cut: poisons only when a newline was consumed (the
        // cut is inside ConsumeComments, which is only reached after Newline.? fires).
        // oracle: `a +\n/*c*/b` REJECT; `{ val x=1\n/*c*/(x,y)=>x }` REJECT (zero
        // newlines here — bc_before ignored, head detected, later-chunk reject fires).
        if consumed_nl && self.i < self.toks.len() && self.toks[self.i].bc_before {
            self.i = save;
            return false;
        }
        true
    }

    /// True iff the raw token immediately after the comma that `peek` returns is a
    /// `Newline` — the `TrailingComma = "," ~ WS ~ Basic.Newline` predicate
    /// (Literals.scala:63). `WS` is newline-free, so a legal trailing comma is
    /// always directly followed by a `Newline` token.
    pub(crate) fn comma_then_newline(&self) -> bool {
        let j = self.skip_nl(self.i);
        matches!(
            self.toks.get(j + 1).map(|t| &t.kind),
            Some(TokenKind::Newline { .. })
        )
    }
}

// =============================================================================
// Leading-token predicate shared by the type and expression grammars.
// =============================================================================

/// A `StableId` / infix-operator head: `Id = BacktickId | PlainId` where
/// `PlainId` includes operator identifiers (Identifiers.scala:32,37).
pub(crate) fn is_id(t: &Token) -> bool {
    matches!(
        t.kind,
        TokenKind::Ident | TokenKind::OpId | TokenKind::BacktickId
    )
}

/// The shared depth-guard wrapper used by [`type_`] and [`expr`]: increment
/// the cursor's depth, reject past [`MAX_PARSE_DEPTH`] (position = the token
/// about to be parsed), run the guarded body, and decrement on every path.
/// One implementation so the two guards cannot drift.
pub(crate) fn with_depth_guard<T>(
    c: &mut Cursor,
    f: impl FnOnce(&mut Cursor) -> Result<T, ParseError>,
) -> Result<T, ParseError> {
    c.depth += 1;
    if c.depth > MAX_PARSE_DEPTH {
        let pos = c.peek().start;
        let depth = c.depth;
        c.depth -= 1;
        return Err(ParseError::TooDeep { pos, depth });
    }
    let result = f(c);
    c.depth -= 1;
    result
}
