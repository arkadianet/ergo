//! Lexer core for ErgoScript.
//!
//! There is no separate lexer in the Scala reference — it is a scannerless
//! fastparse grammar (recon-lexical.md §0). This module reconstructs the token
//! stream that grammar observes, so the parser can drive semicolon
//! inference off explicit `Newline` tokens. Every rule cites the mirrored Scala
//! source under `sigmastate-interpreter/parsers/shared/.../parsers`.
//!
//! The complete lexer covers: whitespace/comment/newline machinery, identifiers,
//! keywords, numbers, punctuation, string (`"`) and char/symbol (`'`) literals.
//! String literals support the four forms of Literals.scala:149-156 with
//! raw-capture `strip` semantics, escape validation (never decoding),
//! triple-quote quirks, and id-prefix/interpolation forms.

use crate::error::ParseError;
use crate::span::Pos;

/// Reserved words and symbolic keywords.
///
/// Alphabet keywords (Identifiers.scala:50-53) each require a
/// `!LetterDigitDollarUnderscore` boundary (Basic.scala:74-75) — enforced here
/// by maximal-munch: a run equal to the word only classifies as a keyword when
/// no id-continuation char follows. Symbolic keywords (Identifiers.scala:55-57):
/// an op-char run equal to one of these is the keyword, not an `OpId`. `⇒`
/// (U+21D2) aliases `FatArrow` (Core.scala:23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kw {
    Case,
    Else,
    False,
    Function,
    If,
    Match,
    Return,
    Then,
    True,
    Colon,
    FatArrow,
    Assign,
    Hash,
    At,
}

/// One lexical token kind.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// Plain identifier (incl. `_`, `$x`, `x_+`, uppercase, `val`/`def`/`null`/…).
    Ident,
    /// Symbolic identifier: a run of op-chars (Basic.scala:38-45).
    OpId,
    /// `` `raw` `` — span includes the backticks (Identifiers.scala:36).
    BacktickId,
    /// Value validated at lex time (Literals.scala:106-116).
    IntLit(i32),
    LongLit(i64),
    /// String literal: raw-captured value with quotes stripped per Literals.scala:119-124.
    Str(String),
    /// Char or symbol literal (`'c'` / `'sym` forms): raw text including the leading quote.
    CharSym(String),
    Kw(Kw),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Semi,
    Dot,
    /// One token per newline outside comments (Basic.scala:34). `after_comment`
    /// is true iff only spaces/tabs separate it from the end of the previous
    /// comment — this drives `OneNLMax`'s comment-line absorption
    /// (Literals.scala:57-60).
    Newline {
        after_comment: bool,
    },
    Eof,
}

/// A token with its source byte span `[start, end)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub start: Pos,
    pub end: Pos,
}

impl Token {
    /// The exact source text this token spans.
    pub fn text<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start as usize..self.end as usize]
    }
}

/// Tokenize `src` into the token stream the Scala grammar observes, terminated
/// by an `Eof` token. Errors mirror the reference's two hard-failure surfaces
/// that occur at lex time: unterminated block comments (Literals.scala:83 cut)
/// and numeric-magnitude overflow (Literals.scala:106-116 `parseInt`/`parseLong`
/// throwing `NumberFormatException`).
pub fn tokenize(src: &str) -> Result<Vec<Token>, ParseError> {
    let mut lx = Lexer::new(src);
    let mut tokens = Vec::new();
    loop {
        lx.skip_gap(&mut tokens)?;
        if lx.at_end() {
            let p = lx.pos as u32;
            tokens.push(Token {
                kind: TokenKind::Eof,
                start: p,
                end: p,
            });
            return Ok(tokens);
        }
        let tok = lx.lex_token()?;
        tokens.push(tok);
    }
}

// ----- character classes -----

/// Op-char set (Basic.scala:38-45): the ASCII operators plus Unicode Sm/So.
//
// deviation: full Sm/So op-char classes are deferred (Rust std has no Unicode
// general-category predicate); the single `⇒` (U+21D2, Core.scala:23) is
// special-cased and the ASCII set is exact. No real contract uses another
// Unicode operator, and the corpus oracle catches any counterexample.
fn is_op_char(c: char) -> bool {
    matches!(
        c,
        '!' | '#'
            | '%'
            | '&'
            | '*'
            | '+'
            | '-'
            | '/'
            | ':'
            | '<'
            | '='
            | '>'
            | '?'
            | '@'
            | '\\'
            | '^'
            | '|'
            | '~'
    ) || c == '\u{21D2}'
}

/// A character that may START a plain identifier: `Lower | Upper`
/// (Basic.scala:52-54) = `isLower || '$' || '_'` or `isUpper`. Rust's
/// `is_lowercase`/`is_uppercase` mirror Java's `isLowerCase`/`isUpperCase`
/// (both exclude titlecase Lt and case-less Lo), so a case-less letter cannot
/// start a plain id — matching the reference.
fn is_id_start(c: char) -> bool {
    c.is_lowercase() || c.is_uppercase() || c == '$' || c == '_'
}

/// A character allowed inside an identifier chunk: `'$' | isLetter | isDigit`
/// (Identifiers.scala:41-43). Underscore is deliberately NOT an id-char — it is
/// handled by the underscore chunks of `IdRest`.
//
// deviation: id-rest letters use `char::is_alphabetic` (≈ Lu/Ll/Lt/Lm/Lo) and
// digits use `char::is_numeric` (wider than Nd) rather than exact JVM
// `Character.getType` masks. Number *literals* use ASCII-only `is_ascii_digit`
// (Basic.scala:12, exact). Corpus-checked.
fn is_id_char(c: char) -> bool {
    c == '$' || c.is_alphabetic() || c.is_numeric()
}

// ----- lexer -----

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            src,
            bytes: src.as_bytes(),
            pos: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_byte_at(&self, n: usize) -> Option<u8> {
        self.bytes.get(self.pos + n).copied()
    }

    /// The char at the cursor. `pos` is always kept on a UTF-8 boundary, so the
    /// slice is safe.
    fn peek_char(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn tok(&self, kind: TokenKind, start: usize) -> Token {
        Token {
            kind,
            start: start as u32,
            end: self.pos as u32,
        }
    }

    /// Consume inter-token whitespace, comments and newlines, pushing one
    /// `Newline` token per `\n`/`\r\n` outside comments (Basic.scala:33-34).
    ///
    /// `after_comment` is true iff only spaces/tabs separate the newline from
    /// the end of the previous comment — `last_was_comment` stays set across
    /// spaces/tabs and is cleared by a newline (Literals.scala:57-60). A lone
    /// `\r` not followed by `\n` is skipped silently like the implicit
    /// `ScalaWhitespace` (FP/Whitespace.scala:199) — never a newline token.
    fn skip_gap(&mut self, tokens: &mut Vec<Token>) -> Result<(), ParseError> {
        let mut last_was_comment = false;
        loop {
            match self.peek_byte() {
                Some(b' ') | Some(b'\t') => self.pos += 1,
                Some(b'\n') => {
                    let start = self.pos;
                    self.pos += 1;
                    tokens.push(self.tok(
                        TokenKind::Newline {
                            after_comment: last_was_comment,
                        },
                        start,
                    ));
                    last_was_comment = false;
                }
                Some(b'\r') if self.peek_byte_at(1) == Some(b'\n') => {
                    let start = self.pos;
                    self.pos += 2;
                    tokens.push(self.tok(
                        TokenKind::Newline {
                            after_comment: last_was_comment,
                        },
                        start,
                    ));
                    last_was_comment = false;
                }
                Some(b'\r') => {
                    self.pos += 1; // lone \r: skipped, no token
                    last_was_comment = false; // not a comment; breaks comment-adjacency (Literals.scala:57-60)
                }
                Some(b'/') if self.peek_byte_at(1) == Some(b'/') => {
                    self.consume_line_comment();
                    last_was_comment = true;
                }
                Some(b'/') if self.peek_byte_at(1) == Some(b'*') => {
                    self.consume_block_comment()?;
                    last_was_comment = true;
                }
                _ => return Ok(()), // token start or EOF
            }
        }
    }

    /// Line comment (Literals.scala:84-85): `//` up to (not including) a
    /// `\n`/`\r\n` or EOF. A lone `\r` (not before `\n`) is comment content.
    fn consume_line_comment(&mut self) {
        self.pos += 2; // //
        loop {
            match self.peek_byte() {
                None | Some(b'\n') => return,
                Some(b'\r') if self.peek_byte_at(1) == Some(b'\n') => return,
                Some(_) => {
                    let c = self.peek_char().expect("boundary");
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// Nested block comment (Literals.scala:82-83). The `~/` cut makes an
    /// unterminated comment a hard failure; we report it at the opening `/*`.
    fn consume_block_comment(&mut self) -> Result<(), ParseError> {
        let open = self.pos;
        self.pos += 2; // /*
        let mut depth = 1usize;
        while depth > 0 {
            match self.peek_byte() {
                None => {
                    return Err(ParseError::Lexical {
                        pos: open as u32,
                        msg: "unterminated block comment".into(),
                    });
                }
                Some(b'/') if self.peek_byte_at(1) == Some(b'*') => {
                    self.pos += 2;
                    depth += 1;
                }
                Some(b'*') if self.peek_byte_at(1) == Some(b'/') => {
                    self.pos += 2;
                    depth -= 1;
                }
                Some(_) => {
                    let c = self.peek_char().expect("boundary");
                    self.pos += c.len_utf8();
                }
            }
        }
        Ok(())
    }

    /// Lex exactly one non-newline token at the cursor (caller guarantees not
    /// at EOF).
    fn lex_token(&mut self) -> Result<Token, ParseError> {
        let start = self.pos;
        let c = self.peek_char().expect("not at EOF");
        let kind = match c {
            '(' => {
                self.pos += 1;
                TokenKind::LParen
            }
            ')' => {
                self.pos += 1;
                TokenKind::RParen
            }
            '[' => {
                self.pos += 1;
                TokenKind::LBracket
            }
            ']' => {
                self.pos += 1;
                TokenKind::RBracket
            }
            '{' => {
                self.pos += 1;
                TokenKind::LBrace
            }
            '}' => {
                self.pos += 1;
                TokenKind::RBrace
            }
            ',' => {
                self.pos += 1;
                TokenKind::Comma
            }
            // `;` is not an op-char (Basic.scala:41-45) — punctuation.
            ';' => {
                self.pos += 1;
                TokenKind::Semi
            }
            // `.` is not an op-char — selection punctuation.
            '.' => {
                self.pos += 1;
                TokenKind::Dot
            }
            '`' => return self.lex_backtick(start),
            // Plain string forms 3-4 (Literals.scala:153-154): no id prefix, so
            // interpolation is disabled (`NoInterp`) and the plain single form
            // requires valid escapes (`SingleChars(false)`, allowSlash=false).
            '"' => return self.lex_string(start, false),
            // Char/Symbol quote forms (Literals.scala:96-101,119).
            '\'' => return self.lex_char_sym(start),
            _ if c.is_ascii_digit() => return self.lex_number(start),
            _ if is_id_start(c) => return self.lex_ident(start),
            _ if is_op_char(c) => return Ok(self.lex_op_run(start)),
            _ => {
                return Err(ParseError::Lexical {
                    pos: start as u32,
                    msg: format!("unexpected character {c:?}"),
                });
            }
        };
        Ok(self.tok(kind, start))
    }

    /// Plain identifier: a start char (already at cursor) followed by `IdRest`,
    /// then reserved-word classification. Maximal munch enforces the keyword
    /// boundary rule: a text equal to a reserved word only reaches the keyword
    /// arm when no id-continuation char followed (Basic.scala:74-75).
    fn lex_ident(&mut self, start: usize) -> Result<Token, ParseError> {
        let c = self.peek_char().expect("id start");
        self.pos += c.len_utf8();
        self.consume_id_rest();
        let text = &self.src[start..self.pos];
        let kind = match text {
            // AlphabetKeywords (Identifiers.scala:51). `then` is reserved
            // (recon-gap.md item 11) though no production uses it.
            "case" => TokenKind::Kw(Kw::Case),
            "else" => TokenKind::Kw(Kw::Else),
            "false" => TokenKind::Kw(Kw::False),
            "function" => TokenKind::Kw(Kw::Function),
            "if" => TokenKind::Kw(Kw::If),
            "match" => TokenKind::Kw(Kw::Match),
            "return" => TokenKind::Kw(Kw::Return),
            "then" => TokenKind::Kw(Kw::Then),
            "true" => TokenKind::Kw(Kw::True),
            // val/def/type/this/super/with/extends/implicit/new/lazy/null/_ are
            // NOT reserved (recon-lexical.md §2.3) — they lex as Ident.
            _ => TokenKind::Ident,
        };
        // Id-prefixed string forms 1-2 (Literals.scala:151-152): `Id ~ TQ/"\""`
        // merges an identifier DIRECTLY adjacent to an opening quote with the
        // string into one raw-captured `Str` token, enabling interpolation.
        // Only a `PlainId` can prefix (`Id = BacktickId | PlainId`, and PlainId
        // carries `!Keywords`, Identifiers.scala:32,37) — a reserved word cannot,
        // so a keyword before `"` stays a separate keyword token.
        //
        // deviation: operator-identifier string prefixes are NOT merged. For `-`/`+`/`!`/`~`
        // Scala's ExprPrefix (Exprs.scala:78) consumes the char before the String production
        // sees it, and at infix position InfixSuffix's Id (Exprs.scala:93) takes it — both
        // equivalent to our [OpId, Str] tokens. But for other op-ids at ATOM position
        // (e.g. `*"foo"`), Scala's String production (Literals.scala:152, Id ~ '"') matches
        // the operator as a PlainId prefix and yields one SString("*\"foo\"") where we lex
        // [OpId, Str] and the parser will reject — a real accept/reject divergence on
        // pathological input no real contract contains. Tracked as a known M1 deviation.
        if kind == TokenKind::Ident && self.peek_byte() == Some(b'"') {
            return self.lex_string(start, true);
        }
        Ok(self.tok(kind, start))
    }

    /// `IdRest(allowDollar=true)` (Identifiers.scala:39-47):
    /// `IdUnderscoreChunk.rep ~ (CharsWhileIn("_") ~ CharsWhile(isOpChar, 0)).?`
    /// — alternating `_`*/id-char+ chunks, optionally ending in `_`+ then 0+
    /// op-chars. The trailing op-char run is a raw `CharsWhile(isOpChar, 0)`
    /// with NO comment-stop (unlike the `Operator` production), so e.g. `x_//`
    /// is a single identifier.
    fn consume_id_rest(&mut self) {
        loop {
            let save = self.pos;
            while self.peek_byte() == Some(b'_') {
                self.pos += 1;
            }
            match self.peek_char() {
                Some(c) if is_id_char(c) => {
                    while let Some(c2) = self.peek_char() {
                        if is_id_char(c2) {
                            self.pos += c2.len_utf8();
                        } else {
                            break;
                        }
                    }
                }
                // The underscores we consumed belong to the optional trailing
                // group, not a chunk — backtrack and try that.
                _ => {
                    self.pos = save;
                    break;
                }
            }
        }
        if self.peek_byte() == Some(b'_') {
            while self.peek_byte() == Some(b'_') {
                self.pos += 1;
            }
            while let Some(c) = self.peek_char() {
                if is_op_char(c) {
                    self.pos += c.len_utf8();
                } else {
                    break;
                }
            }
        }
    }

    /// Op-char run with maximal munch that stops before a `//`/`/*` comment
    /// start (Identifiers.scala:22-24). A run exactly equal to a symbolic
    /// keyword (`: => ⇒ = # @`, Identifiers.scala:55-57 + Core.scala:23) is that
    /// keyword; every other run (`:: == <= ++ -` …) is an `OpId`.
    fn lex_op_run(&mut self, start: usize) -> Token {
        self.consume_op_run();
        let run = &self.src[start..self.pos];
        let kind = match run {
            ":" => TokenKind::Kw(Kw::Colon),
            "=>" | "\u{21D2}" => TokenKind::Kw(Kw::FatArrow),
            "=" => TokenKind::Kw(Kw::Assign),
            "#" => TokenKind::Kw(Kw::Hash),
            "@" => TokenKind::Kw(Kw::At),
            _ => TokenKind::OpId,
        };
        self.tok(kind, start)
    }

    /// Consume a maximal op-char run (`Operator`, Identifiers.scala:22-24),
    /// stopping before a `//`/`/*` comment start. Advances the cursor without
    /// classifying — shared by `lex_op_run` and the `'`-symbol form.
    fn consume_op_run(&mut self) {
        loop {
            match self.peek_char() {
                Some('/') => match self.peek_byte_at(1) {
                    Some(b'/') | Some(b'*') => break, // stop before comment
                    _ => self.pos += 1,               // single '/' is an op-char
                },
                Some(c) if is_op_char(c) => self.pos += c.len_utf8(),
                _ => break,
            }
        }
    }

    /// `` `raw` `` (Identifiers.scala:36): backtick, 1+ non-backtick chars
    /// (`CharsWhile(NotBackTick)` min 1, newlines allowed, no escapes), backtick.
    /// The span includes both backticks. An empty or unterminated form is a
    /// lexical error.
    fn lex_backtick(&mut self, start: usize) -> Result<Token, ParseError> {
        self.pos += 1; // opening `
        let content_start = self.pos;
        loop {
            match self.peek_char() {
                None => {
                    return Err(ParseError::Lexical {
                        pos: start as u32,
                        msg: "unterminated backtick identifier".into(),
                    });
                }
                Some('`') => {
                    if self.pos == content_start {
                        return Err(ParseError::Lexical {
                            pos: start as u32,
                            msg: "empty backtick identifier".into(),
                        });
                    }
                    self.pos += 1; // closing `
                                   // A backtick id is also an `Id` (Identifiers.scala:37), so a
                                   // directly-adjacent quote makes it a string prefix (form 1-2).
                    if self.peek_byte() == Some(b'"') {
                        return self.lex_string(start, true);
                    }
                    return Ok(self.tok(TokenKind::BacktickId, start));
                }
                Some(c) => self.pos += c.len_utf8(),
            }
        }
    }

    /// Numeric literal (Basic.scala:12-26, Literals.scala:70,106-116): hex
    /// (`0x` + hex digits, tried first, backtracking to decimal `0` if no hex
    /// digit follows) or a decimal run, then an optional `L`/`l` suffix. No
    /// sign (the parser folds a prefix `-`), no floats, no octal. The magnitude
    /// is parsed with a checked radix conversion; an overflow of `i32`/`i64`
    /// mirrors Java `parseInt`/`parseLong` throwing, reported at the literal
    /// start.
    fn lex_number(&mut self, start: usize) -> Result<Token, ParseError> {
        let radix = if self.src[self.pos..].starts_with("0x")
            && self.peek_byte_at(2).is_some_and(|b| b.is_ascii_hexdigit())
        {
            self.pos += 2; // 0x
            while self.peek_byte().is_some_and(|b| b.is_ascii_hexdigit()) {
                self.pos += 1;
            }
            16
        } else {
            // Decimal run (also the "0x"-with-no-hex-digit backtrack: consumes
            // just the leading `0`, leaving `x…` to the next token).
            while self.peek_byte().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            10
        };
        let digits_start = if radix == 16 { start + 2 } else { start };
        let digits_end = self.pos;
        let is_long = matches!(self.peek_byte(), Some(b'L') | Some(b'l'));
        if is_long {
            self.pos += 1;
        }
        let digit_str = &self.src[digits_start..digits_end];
        let overflow = || ParseError::Lexical {
            pos: start as u32,
            msg: "integer literal out of range".into(),
        };
        let kind = if is_long {
            TokenKind::LongLit(i64::from_str_radix(digit_str, radix).map_err(|_| overflow())?)
        } else {
            TokenKind::IntLit(i32::from_str_radix(digit_str, radix).map_err(|_| overflow())?)
        };
        Ok(self.tok(kind, start))
    }

    /// String literal (Literals.scala:149-156). `start` is the token start
    /// (the id prefix's start when `prefixed`, else the opening quote); the
    /// cursor sits on the opening `"`. The reference tries a triple-quoted form
    /// first (`TQ ~/ ...`, TQ = `"""`), falling back to single-quoted — so three
    /// leading quotes select the triple form and the `~/` cut then commits.
    ///
    /// The token's value is the RAW captured text (prefix, quotes, escapes, all
    /// verbatim) with only the `strip` loop of Literals.scala:119-124 applied:
    /// escapes are validated but NEVER decoded, and an id prefix (which does not
    /// start with `"`) strips nothing — `s"foo"` keeps its 7 chars.
    fn lex_string(&mut self, start: usize, prefixed: bool) -> Result<Token, ParseError> {
        let triple = self.peek_byte() == Some(b'"')
            && self.peek_byte_at(1) == Some(b'"')
            && self.peek_byte_at(2) == Some(b'"');
        if triple {
            self.lex_triple_string(start, prefixed)
        } else {
            self.lex_single_string(start, prefixed)
        }
    }

    /// Finish a string once the closing delimiter has been consumed: build the
    /// `Str` token from the raw span with `strip` (Literals.scala:119-124).
    fn finish_string(&self, start: usize) -> Token {
        let raw = &self.src[start..self.pos];
        self.tok(TokenKind::Str(strip_quotes(raw)), start)
    }

    /// Single-quoted form (Literals.scala:144-154). Content =
    /// `(StringChars | Interp | LiteralSlash | Escape | NonStringEnd).rep`, then
    /// a closing `"`. A raw `\n` cannot be matched by any content class, so it
    /// (and EOF) is where the closing-quote match fails — the reference's
    /// failure index, which we mirror. `prefixed` = interpolation active and
    /// `allowSlash=true` (a backslash is then a LITERAL char, `LiteralSlash`
    /// winning over `Escape`); plain strings use `SingleChars(false)`, so every
    /// `\` must begin a valid `Escape`.
    fn lex_single_string(&mut self, start: usize, prefixed: bool) -> Result<Token, ParseError> {
        self.pos += 1; // opening "
        loop {
            match self.peek_byte() {
                // `~ "\""` fails at EOF: unterminated (index at EOF, matching
                // fail("\"str", 1, 5)).
                None => {
                    return Err(ParseError::Lexical {
                        pos: self.pos as u32,
                        msg: "unterminated string literal".into(),
                    });
                }
                Some(b'"') => {
                    self.pos += 1; // closing "
                    return Ok(self.finish_string(start));
                }
                // Raw newline: no content class admits it (StringChars/NonStringEnd
                // both exclude `\n`), so the closing-quote match fails here.
                Some(b'\n') => {
                    return Err(ParseError::Lexical {
                        pos: self.pos as u32,
                        msg: "newline in single-quoted string".into(),
                    });
                }
                Some(b'\\') => {
                    if prefixed {
                        self.pos += 1; // LiteralSlash: a bare backslash is content
                    } else {
                        self.consume_escape()?; // must be a valid Escape (cut)
                    }
                }
                Some(b'$') if prefixed => self.consume_interp_dollar()?,
                // StringChars / NonStringEnd: any other char (incl. `$` in plain
                // strings, a lone `\r`, and non-ASCII) is verbatim content.
                Some(_) => {
                    let c = self.peek_char().expect("boundary");
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// Triple-quoted form (Literals.scala:142,151,153). After the opening `"""`,
    /// content = `(StringChars | Interp | NonTripleQuoteChar).rep` then
    /// `TripleTail = "\"\"\"" ~ "\"".rep`. `NonTripleQuoteChar` admits raw
    /// newlines and 1-2 quotes not followed by a third, but NOT a backslash
    /// (`CharIn("\\$\n")` = {`$`,`\n`} under fastparse class semantics), so a
    /// `\` is an unconsumable parse failure AT the backslash. The closing `"""`
    /// greedily eats every trailing quote (`TripleTail`).
    fn lex_triple_string(&mut self, start: usize, prefixed: bool) -> Result<Token, ParseError> {
        self.pos += 3; // opening """
        loop {
            match self.peek_byte() {
                None => {
                    return Err(ParseError::Lexical {
                        pos: self.pos as u32,
                        msg: "unterminated triple-quoted string".into(),
                    });
                }
                Some(b'"') => {
                    let two_more = self.peek_byte_at(1) == Some(b'"');
                    let three = two_more && self.peek_byte_at(2) == Some(b'"');
                    if three {
                        // TripleTail: closing """ plus every extra trailing quote.
                        while self.peek_byte() == Some(b'"') {
                            self.pos += 1;
                        }
                        return Ok(self.finish_string(start));
                    } else if two_more {
                        self.pos += 2; // `""` content (next char is not a quote)
                    } else {
                        self.pos += 1; // `"` content
                    }
                }
                // A backslash matches no content class: hard failure AT the `\`.
                Some(b'\\') => {
                    return Err(ParseError::Lexical {
                        pos: self.pos as u32,
                        msg: "backslash in triple-quoted string".into(),
                    });
                }
                Some(b'$') if prefixed => self.consume_interp_dollar()?,
                // NonTripleQuoteChar / StringChars: raw `\n`, `$` (plain), `\r`,
                // and any other char are verbatim content.
                Some(_) => {
                    let c = self.peek_char().expect("boundary");
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// Handle a `$` inside an id-prefixed string where interpolation is active
    /// (Literals.scala:127-130). `$$` and `$`+plain-id are consumed; a bare `$`
    /// that starts no interpolation is still swallowed as content by
    /// `NonStringEnd`/`NonTripleQuoteChar`, so — the raw capture being identical
    /// either way — we consume just the `$` and let the rest fall through as
    /// content. Only `${` is special.
    fn consume_interp_dollar(&mut self) -> Result<(), ParseError> {
        // deviation (D6): the reference's `${ Block }` interpolation is not
        // supported in M1 — reject it rather than parse an embedded expression.
        if self.peek_byte_at(1) == Some(b'{') {
            return Err(ParseError::Lexical {
                pos: self.pos as u32,
                msg: "string interpolation block not supported".into(),
            });
        }
        self.pos += 1; // `$`
        Ok(())
    }

    /// Consume one `Escape` (Literals.scala:90-91) at the cursor (`\`), without
    /// decoding it. The `~/` cut makes an invalid escape a hard failure. Under
    /// fastparse `CharIn` class semantics the single-char set is exactly
    /// `{b t n f r ' " ]}` — note `\]` is (accidentally) legal and `\\` is NOT.
    /// `OctalEscape` is 1-3 DECIMAL digits; `UnicodeEscape` is `u` + exactly 4
    /// hex digits (Basic.scala:20).
    fn consume_escape(&mut self) -> Result<(), ParseError> {
        self.pos += 1; // `\`
        match self.peek_char() {
            None => Err(ParseError::Lexical {
                pos: self.pos as u32,
                msg: "unterminated escape sequence".into(),
            }),
            // Single-char escapes {b t n f r ' " ]} (Literals.scala:91): note `\]`
            // is legal and `\\` is NOT — a backslash is not in the set.
            Some('b' | 't' | 'n' | 'f' | 'r' | '\'' | '"' | ']') => {
                self.pos += 1;
                Ok(())
            }
            Some(c) if c.is_ascii_digit() => {
                self.pos += 1; // first octal digit
                for _ in 0..2 {
                    if self.peek_byte().is_some_and(|b| b.is_ascii_digit()) {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            Some('u') => {
                self.pos += 1; // `u`
                for _ in 0..4 {
                    if self.peek_byte().is_some_and(|b| b.is_ascii_hexdigit()) {
                        self.pos += 1;
                    } else {
                        return Err(ParseError::Lexical {
                            pos: self.pos as u32,
                            msg: "invalid unicode escape".into(),
                        });
                    }
                }
                Ok(())
            }
            Some(_) => Err(ParseError::Lexical {
                pos: self.pos as u32,
                msg: "invalid escape sequence".into(),
            }),
        }
    }

    /// Char/Symbol quote forms (Literals.scala:94-101,119): `'` cut, then either
    /// `Char = (Escape | PrintableChar) ~ "'"` (raw text keeps BOTH quotes,
    /// `'a'`) or `Symbol = PlainId | Keywords` (leading quote only, `'foo`).
    /// `Char` is tried first; a printable/escape not followed by `'` backtracks
    /// to `Symbol`. Both are captured raw and become `SString` — `strip` removes
    /// no `'`. A `'` matched by neither is the `~/` cut's hard failure.
    fn lex_char_sym(&mut self, start: usize) -> Result<Token, ParseError> {
        self.pos += 1; // opening '
        let after_quote = self.pos;

        // Char form: one escape/printable char then a closing `'`.
        match self.peek_char() {
            Some('\\') => {
                self.consume_escape()?; // invalid escape is a hard failure (cut)
                if self.peek_byte() == Some(b'\'') {
                    self.pos += 1;
                    return Ok(
                        self.tok(TokenKind::CharSym(self.src[start..self.pos].into()), start)
                    );
                }
                // Literals.scala:91 — cut after '\\': a valid escape without closing
                // quote is a hard failure; no fallback to Symbol.
                return Err(ParseError::Lexical {
                    pos: self.pos as u32,
                    msg: "expected closing ' after character escape".into(),
                });
            }
            Some(c) if is_printable_char(c) => {
                self.pos += c.len_utf8();
                if self.peek_byte() == Some(b'\'') {
                    self.pos += 1;
                    return Ok(
                        self.tok(TokenKind::CharSym(self.src[start..self.pos].into()), start)
                    );
                }
                self.pos = after_quote; // printable but no closing quote → Symbol
            }
            _ => {}
        }

        // Symbol form: `PlainId | Keywords` (Literals.scala:94, Identifiers.scala:32-59).
        // An id-start begins an identifier / alphabetic-keyword run (`UppercaseId |
        // VarId | AlphabetKeywords`); an op-char begins an `Operator` / symbolic-
        // keyword run (`: = => # @`); and `;` — the one symbolic keyword that is not
        // itself an op-char (Identifiers.scala:55-56) — is accepted on its own.
        match self.peek_char() {
            Some(c) if is_id_start(c) => {
                self.pos += c.len_utf8();
                self.consume_id_rest();
            }
            Some(';') => {
                // SymbolicKeywords `";" ~ !OpChar` (Identifiers.scala:55-56): valid
                // only when not followed by an op-char, else the `~/` cut hard-fails.
                if self
                    .peek_byte_at(1)
                    .map(|b| b as char)
                    .is_some_and(is_op_char)
                {
                    return Err(ParseError::Lexical {
                        pos: after_quote as u32,
                        msg: "expected char or symbol after `'`".into(),
                    });
                }
                self.pos += 1;
            }
            Some(c) if is_op_char(c) => {
                let op_start = self.pos;
                self.consume_op_run();
                if self.pos == op_start {
                    // `Operator = … .rep(1)` requires >=1 op char (Identifiers.scala:22-24);
                    // the munch stopped before a `//`/`/*` comment, so `'` is directly
                    // followed by a comment and no Symbol matches — a hard failure.
                    return Err(ParseError::Lexical {
                        pos: after_quote as u32,
                        msg: "expected char or symbol after `'`".into(),
                    });
                }
            }
            _ => {
                // `'` followed by neither a closing-`'` char form nor a symbol:
                // the reference's cut turns this into a hard failure.
                return Err(ParseError::Lexical {
                    pos: after_quote as u32,
                    msg: "expected char or symbol after `'`".into(),
                });
            }
        }
        Ok(self.tok(TokenKind::CharSym(self.src[start..self.pos].into()), start))
    }
}

/// `strip` (Literals.scala:119-124): while the text starts with `"`, drop one
/// leading `"` and (if present) one trailing `"`, recursively. An id-prefixed
/// capture does not start with `"` and is returned unchanged; a plain `"x"`
/// yields `x`, a triple `"""x"""` also `x`. Ported verbatim, including the
/// `stripSuffix`-is-conditional detail (the recursion guards only on the
/// prefix).
fn strip_quotes(s: &str) -> String {
    let mut cur = s;
    while let Some(rest) = cur.strip_prefix('"') {
        cur = rest.strip_suffix('"').unwrap_or(rest);
    }
    cur.to_string()
}

/// fastparse `isPrintableChar` (CharPredicates, referenced Literals.scala:98).
//
// deviation: the exact predicate also excludes the SPECIALS block and code
// points whose Unicode block is null; we approximate it with "not an ISO
// control character" (Rust `char` can never be an unpaired surrogate). This is
// only used to split the `'`-char form from the `'`-symbol form for a single
// char; the printable chars any contract uses (`'a'` etc.) classify identically.
fn is_printable_char(c: char) -> bool {
    !c.is_control()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----
    fn kinds(src: &str) -> Vec<TokenKind> {
        tokenize(src).unwrap().into_iter().map(|t| t.kind).collect()
    }
    fn lex_err(src: &str) -> ParseError {
        tokenize(src).unwrap_err()
    }

    // ----- happy path -----
    #[test]
    fn ident_underscore_opchar_tail_is_one_token() {
        // Identifiers.scala:39-48: x_+ is a single identifier
        let t = tokenize("x_+").unwrap();
        assert_eq!(t[0].kind, TokenKind::Ident);
        assert_eq!(t[0].text("x_+"), "x_+");
    }
    #[test]
    fn keywords_boundary_rule_truex_is_ident() {
        assert_eq!(kinds("true"), vec![TokenKind::Kw(Kw::True), TokenKind::Eof]);
        assert_eq!(kinds("truex")[0], TokenKind::Ident); // Basic.scala:74-75
        assert_eq!(kinds("if1")[0], TokenKind::Ident);
        assert_eq!(kinds("val")[0], TokenKind::Ident); // val is NOT reserved
    }
    #[test]
    fn opchar_run_munches_maximally_and_reserves_symbolic() {
        assert_eq!(kinds("=")[0], TokenKind::Kw(Kw::Assign));
        assert_eq!(kinds("==")[0], TokenKind::OpId); // == is an OpId, not Assign
        assert_eq!(kinds("=>")[0], TokenKind::Kw(Kw::FatArrow));
        assert_eq!(kinds("⇒")[0], TokenKind::Kw(Kw::FatArrow)); // Core.scala:23
        assert_eq!(kinds("::")[0], TokenKind::OpId);
    }
    #[test]
    fn opid_stops_before_comment_start() {
        // Identifiers.scala:22-24 + Basic.scala:76-77
        assert_eq!(
            kinds("=//c"),
            vec![TokenKind::Kw(Kw::Assign), TokenKind::Eof]
        );
        assert_eq!(
            kinds("+/*c*/+"),
            vec![TokenKind::OpId, TokenKind::OpId, TokenKind::Eof]
        );
    }
    #[test]
    fn numbers_hex_suffix_and_split() {
        assert_eq!(kinds("10")[0], TokenKind::IntLit(10));
        assert_eq!(kinds("10L")[0], TokenKind::LongLit(10));
        assert_eq!(kinds("10l")[0], TokenKind::LongLit(10));
        assert_eq!(kinds("0x10")[0], TokenKind::IntLit(0x10));
        assert_eq!(kinds("0x10L")[0], TokenKind::LongLit(0x10));
        assert_eq!(kinds("007")[0], TokenKind::IntLit(7));
        // "0x" with no hex digit: backtrack to decimal 0 + ident x (Literals.scala:70)
        assert_eq!(kinds("0x")[..2], [TokenKind::IntLit(0), TokenKind::Ident]);
        // no boundary guard: 123abc = 123, abc
        assert_eq!(
            kinds("123abc")[..2],
            [TokenKind::IntLit(123), TokenKind::Ident]
        );
    }
    #[test]
    fn newline_tokens_and_comment_absorption() {
        // one Newline token per \n / \r\n outside comments
        assert_eq!(
            kinds("a\nb"),
            vec![
                TokenKind::Ident,
                TokenKind::Newline {
                    after_comment: false
                },
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
        // newline inside a block comment is swallowed (WS eats multiline comments whole)
        assert_eq!(
            kinds("a /* \n */ b"),
            vec![TokenKind::Ident, TokenKind::Ident, TokenKind::Eof]
        );
        // newline right after a line comment carries after_comment=true
        assert_eq!(
            kinds("a // c\nb")[1],
            TokenKind::Newline {
                after_comment: true
            }
        );
        // nested block comments (Literals.scala:82-83)
        assert_eq!(
            kinds("a /* x /* y */ z */ b"),
            vec![TokenKind::Ident, TokenKind::Ident, TokenKind::Eof]
        );
    }
    #[test]
    fn backtick_id_any_content() {
        let t = tokenize("`if while`").unwrap();
        assert_eq!(t[0].kind, TokenKind::BacktickId);
        assert_eq!(t[0].text("`if while`"), "`if while`");
    }

    // ----- happy path (additional edge cases found while implementing) -----
    #[test]
    fn punctuation_each_is_one_token() {
        // recon-lexical.md §6-7: single-char delimiters; `.` and `;` are not
        // op-chars (Basic.scala:41-45).
        assert_eq!(
            kinds("()[]{},;."),
            vec![
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::LBracket,
                TokenKind::RBracket,
                TokenKind::LBrace,
                TokenKind::RBrace,
                TokenKind::Comma,
                TokenKind::Semi,
                TokenKind::Dot,
                TokenKind::Eof,
            ]
        );
    }
    #[test]
    fn symbolic_keywords_colon_and_others() {
        // Identifiers.scala:55-57: `:` `#` `@` are symbolic keywords; `::` is not.
        assert_eq!(kinds(":")[0], TokenKind::Kw(Kw::Colon));
        assert_eq!(kinds("#")[0], TokenKind::Kw(Kw::Hash));
        assert_eq!(kinds("@")[0], TokenKind::Kw(Kw::At));
        // Maximal munch: a longer run is a plain OpId (the `!OpChar` boundary
        // of SymbolicKeywords fails when another op-char follows).
        assert_eq!(kinds("@@")[0], TokenKind::OpId);
        assert_eq!(kinds(":=")[0], TokenKind::OpId);
        // `>:` `<:` `*` are NOT reserved symbolic keywords → OpId.
        assert_eq!(kinds(">:")[0], TokenKind::OpId);
        assert_eq!(kinds("*")[0], TokenKind::OpId);
    }
    #[test]
    fn then_is_reserved_but_null_and_def_are_ident() {
        // recon-gap.md item 11: `then` IS reserved (Identifiers.scala:51).
        assert_eq!(kinds("then")[0], TokenKind::Kw(Kw::Then));
        // recon-lexical.md §2.3: these grammar-words are NOT reserved.
        assert_eq!(kinds("null")[0], TokenKind::Ident);
        assert_eq!(kinds("def")[0], TokenKind::Ident);
        assert_eq!(kinds("_")[0], TokenKind::Ident); // `_` lexes as an Ident
    }
    #[test]
    fn id_rest_trailing_opchars_have_no_comment_stop() {
        // Identifiers.scala:47: the trailing `_`+opchar* run is a raw
        // CharsWhile(isOpChar,0) — unlike the Operator production it does NOT
        // stop before `//`, so `x_//` is a single identifier.
        let t = tokenize("x_//").unwrap();
        assert_eq!(t[0].kind, TokenKind::Ident);
        assert_eq!(t[0].text("x_//"), "x_//");
        assert_eq!(t[1].kind, TokenKind::Eof);
    }
    #[test]
    fn uppercase_hex_prefix_is_not_hex() {
        // Basic.scala:24: HexNum is literally "0x" (lowercase). `0X10` is decimal
        // 0 then identifier `X10`.
        assert_eq!(kinds("0X10")[..2], [TokenKind::IntLit(0), TokenKind::Ident]);
    }
    #[test]
    fn long_max_value_ok_and_unicode_fatarrow_run() {
        // i64::MAX magnitude is in range (Literals.scala:113 parseLong).
        assert_eq!(
            kinds("9223372036854775807L")[0],
            TokenKind::LongLit(9223372036854775807)
        );
        // `⇒=` is two op-chars → OpId, not the FatArrow keyword.
        assert_eq!(kinds("⇒=")[0], TokenKind::OpId);
    }
    #[test]
    fn lone_cr_between_tokens_is_skipped_no_newline() {
        // recon-lexical.md §1.1: a lone `\r` is skipped like ScalaWhitespace and
        // never emits a Newline token.
        assert_eq!(
            kinds("a\rb"),
            vec![TokenKind::Ident, TokenKind::Ident, TokenKind::Eof]
        );
        // `\r\n` is one Newline (Basic.scala:34).
        assert_eq!(
            kinds("a\r\nb"),
            vec![
                TokenKind::Ident,
                TokenKind::Newline {
                    after_comment: false
                },
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }
    #[test]
    fn newline_after_comment_and_bare_cr_not_after_comment() {
        // Literals.scala:57-60 OneNLMax comment-absorption: a Newline has
        // after_comment=true only when it is immediately preceded (in whitespace)
        // by a comment. A lone \r between the comment and the \n is NOT a comment
        // and must break comment-adjacency → after_comment=false.
        //
        // "a /*c*/ \r \nb": skip_gap sees space, then /*c*/ (last_was_comment=true),
        // then space, then lone \r (resets last_was_comment=false), then space,
        // then \n → Newline { after_comment: false }.
        let toks = tokenize("a /*c*/ \r \nb").unwrap();
        let nl = toks
            .iter()
            .find(|t| matches!(t.kind, TokenKind::Newline { .. }))
            .unwrap();
        assert_eq!(
            nl.kind,
            TokenKind::Newline {
                after_comment: false
            }
        );
    }

    // ----- happy path (strings and char/symbol literals) -----
    #[test]
    fn string_plain_and_triple_strip_quotes() {
        assert_eq!(kinds(r#""hello""#)[0], TokenKind::Str("hello".into()));
        assert_eq!(kinds(r#""""hello""""#)[0], TokenKind::Str("hello".into())); // """hello"""
        assert_eq!(
            kinds("\"\"\"hel\nlo\"\"\"")[0],
            TokenKind::Str("hel\nlo".into())
        ); // raw \n ok
    }
    #[test]
    fn string_escapes_validated_not_decoded() {
        // Literals.scala:119-124 raw capture: value keeps backslash-n as two chars
        assert_eq!(kinds(r#""a\nb""#)[0], TokenKind::Str(r"a\nb".into()));
        assert_eq!(kinds(r#""q\]w""#)[0], TokenKind::Str(r"q\]w".into())); // \] legal (quirk)
        assert_eq!(kinds(r#""uA""#)[0], TokenKind::Str(r"uA".into()));
        assert_eq!(kinds(r#""o\7w""#)[0], TokenKind::Str(r"o\7w".into())); // octal, decimal digits
    }
    #[test]
    fn string_id_prefixed_keeps_prefix_and_quotes() {
        // strip() strips nothing when the raw text starts with the id prefix
        assert_eq!(kinds(r#"s"foo""#)[0], TokenKind::Str(r#"s"foo""#.into()));
        assert_eq!(
            kinds(r#"s"a $x b""#)[0],
            TokenKind::Str(r#"s"a $x b""#.into())
        );
        assert_eq!(
            kinds(r#"s"100%$$""#)[0],
            TokenKind::Str(r#"s"100%$$""#.into())
        );
    }
    #[test]
    fn charsym_quirk_forms_keep_quote() {
        assert_eq!(kinds("'a'")[0], TokenKind::CharSym("'a'".into()));
        assert_eq!(kinds("'foo")[0], TokenKind::CharSym("'foo".into()));
        assert_eq!(kinds("'if")[0], TokenKind::CharSym("'if".into())); // Symbol = PlainId | Keywords
    }
    #[test]
    fn charsym_symbolic_keyword_forms_keep_quote() {
        // Symbol = PlainId | Keywords, and Keywords includes the symbolic keywords
        // `: ; => = # @` (Identifiers.scala:55-57). `;` is the one that is not an
        // op-char, so it needs its own acceptance path.
        // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT each
        assert_eq!(kinds("';")[0], TokenKind::CharSym("';".into()));
        assert_eq!(kinds("'=>")[0], TokenKind::CharSym("'=>".into()));
        assert_eq!(kinds("':")[0], TokenKind::CharSym("':".into()));
        assert_eq!(kinds("'=")[0], TokenKind::CharSym("'=".into()));
        assert_eq!(kinds("'#")[0], TokenKind::CharSym("'#".into()));
        assert_eq!(kinds("'@")[0], TokenKind::CharSym("'@".into()));
    }
    #[test]
    fn charsym_semicolon_before_opchar_errors() {
        // `;` is a symbolic keyword only with `!OpChar` after (Identifiers.scala:56);
        // `';:` has `:` (an op-char) after the `;`, so no Symbol matches and the
        // `~/` cut hard-fails at the `;`.
        // oracle: ParserOracle sigma-state 6.0.2 — REJECT 1:2
        let e = lex_err("';:");
        assert!(matches!(e, ParseError::Lexical { .. }));
        assert_eq!(e.pos(), 1); // the `;`, one past the opening quote
    }
    #[test]
    fn charsym_quote_before_comment_errors() {
        // `Operator = … .rep(1)` needs >=1 op char (Identifiers.scala:22-24); the
        // op-run munch stops before a `//`/`/*` comment, so `'` directly followed by
        // a comment consumes zero chars and no Symbol matches — a hard failure (never
        // an empty `CharSym("'")`).
        // oracle: ParserOracle sigma-state 6.0.2 — REJECT 1:2
        for src in ["'/**/x", "'/**/'", "'//c\nx"] {
            let e = lex_err(src);
            assert!(matches!(e, ParseError::Lexical { .. }), "{src}");
            assert_eq!(e.pos(), 1, "{src}");
        }
    }
    #[test]
    fn charsym_slash_operator_symbol_keeps_quote() {
        // A lone `/` that is NOT a comment start is a valid one-char Operator symbol.
        // oracle: ParserOracle sigma-state 6.0.2 — ACCEPT (`'/x` = `'/`.x postfix)
        assert_eq!(kinds("'/x")[0], TokenKind::CharSym("'/".into()));
    }
    #[test]
    fn charsym_escape_form_keeps_quotes() {
        // Char = (Escape | PrintableChar) ~ "'" (Literals.scala:96-101): a valid
        // escape then a closing `'` — captured raw incl. both quotes, undecoded.
        assert_eq!(kinds("'\\n'")[0], TokenKind::CharSym("'\\n'".into())); // 'BACKSLASH n'
    }
    #[test]
    fn string_empty_and_empty_triple_are_empty() {
        // "" is single form with empty content → strip → ""; """""" (6 quotes) is
        // an empty triple: TQ, no content, TripleTail = TQ then greedy quotes.
        assert_eq!(kinds("\"\"")[0], TokenKind::Str("".into()));
        assert_eq!(kinds("\"\"\"\"\"\"")[0], TokenKind::Str("".into())); // 6 quotes
    }
    #[test]
    fn string_triple_tail_greedy_strip_leaves_quote() {
        // Literals.scala:143 TripleTail eats all trailing quotes, then strip
        // (119-124) is symmetric on the raw capture: 3 leading vs 4 trailing
        // quotes → 3 pairs removed, one trailing quote survives in the value.
        assert_eq!(kinds("\"\"\"a\"\"\"\"")[0], TokenKind::Str("a\"".into())); // """a""""
    }
    #[test]
    fn triple_string_embedded_quotes_are_content() {
        // NonTripleQuoteChar (Literals.scala:141) admits 1-2 quotes not followed
        // by a third.
        assert_eq!(kinds("\"\"\"a\"b\"\"\"")[0], TokenKind::Str("a\"b".into())); // """a"b"""
        assert_eq!(
            kinds("\"\"\"a\"\"b\"\"\"")[0],
            TokenKind::Str("a\"\"b".into())
        ); // """a""b"""
    }
    #[test]
    fn string_unicode_and_octal_escapes_validate_not_decode() {
        // Basic.scala:20 UnicodeEscape = u + 4 hex; Literals.scala:90 OctalEscape
        // = 1-3 decimal digits (greedy, max 3). Value keeps the raw bytes.
        assert_eq!(kinds(r#""ÿ""#)[0], TokenKind::Str(r"ÿ".into()));
        assert_eq!(kinds(r#""\1234""#)[0], TokenKind::Str(r"\1234".into())); // octal \123 then '4'
    }
    #[test]
    fn plain_string_dollar_brace_is_content() {
        // Plain strings use NoInterp (Interp = Fail, Literals.scala:128,153-154),
        // so `$` and `{` are ordinary content — no D6 rejection.
        assert_eq!(kinds(r#""${x}""#)[0], TokenKind::Str("${x}".into()));
    }
    #[test]
    fn prefixed_single_backslash_is_literal_content() {
        // Id-prefixed single = SingleChars(true): LiteralSlash wins over Escape
        // (Literals.scala:145,147), so a backslash is a literal content char and
        // is NOT escape-validated. Prefix means strip removes nothing.
        assert_eq!(kinds(r#"s"a\nb""#)[0], TokenKind::Str(r#"s"a\nb""#.into()));
    }
    #[test]
    fn prefixed_triple_and_bare_dollar_strip_nothing() {
        // Id-prefixed triple (form 1); bare `$` before the closing quote is
        // content (no interp match), raw-captured with the prefix intact.
        assert_eq!(
            kinds("s\"\"\"a\"\"\"")[0],
            TokenKind::Str("s\"\"\"a\"\"\"".into())
        ); // s"""a"""
        assert_eq!(kinds(r#"s"a$""#)[0], TokenKind::Str(r#"s"a$""#.into()));
    }
    #[test]
    fn keyword_prefix_does_not_merge_with_string() {
        // Id = BacktickId | PlainId, PlainId has !Keywords (Identifiers.scala:32),
        // so a reserved word does NOT prefix a string.
        assert_eq!(
            kinds(r#"if"x""#),
            vec![
                TokenKind::Kw(Kw::If),
                TokenKind::Str("x".into()),
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn opid_string_prefix_not_merged_known_deviation() {
        // Known M1 deviation (see comment at the id-prefix merge site): for
        // op-ids at ATOM position Scala's String production (Literals.scala:152,
        // Id ~ '"') matches the operator as a PlainId prefix and yields one
        // op-prefixed SString, whereas we lex [OpId, Str] and the parser will
        // reject. No real contract does this — documented, not fixed.
        assert_eq!(
            kinds(r#"*"foo""#),
            vec![
                TokenKind::OpId,
                TokenKind::Str("foo".into()),
                TokenKind::Eof
            ]
        );
    }

    // ----- error paths -----
    #[test]
    fn string_four_quotes_unterminated_errors() {
        // """" selects the triple form (TQ cut), consumes the 4th quote as
        // content, then TripleTail cannot find its closing """ → hard failure.
        assert!(matches!(lex_err("\"\"\"\""), ParseError::Lexical { .. })); // 4 quotes
    }
    #[test]
    fn string_invalid_unicode_escape_errors() {
        // UnicodeEscape needs exactly 4 hex digits; the Escape cut makes a short
        // one a hard failure.
        assert!(matches!(lex_err(r#""\uAB""#), ParseError::Lexical { .. }));
    }
    #[test]
    fn charsym_invalid_escape_errors() {
        // The Escape cut fires inside Char too: '\x' is a hard failure.
        assert!(matches!(lex_err("'\\x'"), ParseError::Lexical { .. }));
    }
    #[test]
    fn charsym_escape_without_closing_quote_errors() {
        // Literals.scala:91 — cut after '\\': a valid escape (\n) not followed by
        // a closing quote must be a hard Lexical failure, never a Symbol fallback.
        assert!(matches!(lex_err("'\\n x"), ParseError::Lexical { .. }));
    }
    #[test]
    fn triple_string_backslash_position_is_the_backslash() {
        // Independent of the pinned SigmaParserTest vector: the failure index is
        // exactly the backslash byte.
        let e = lex_err("\"\"\"ab\\c\"\"\"");
        assert_eq!(e.pos(), 5); // """ab\c""" — backslash at byte 5
    }
    #[test]
    fn string_unterminated_errors_at_eof() {
        let e = lex_err("\"str");
        assert_eq!(e.pos(), 4); // fail("\"str", 1, 5) — SigmaParserTest
    }
    #[test]
    fn string_backslash_backslash_is_invalid_escape() {
        // recon-lexical.md §4: \\ is NOT in the escape set (fastparse CharIn quirk)
        assert!(matches!(lex_err(r#""a\\b""#), ParseError::Lexical { .. }));
    }
    #[test]
    fn triple_string_backslash_errors_at_backslash() {
        // SigmaParserTest.scala:612-622: """h\el\nlo""" -> Parse Error Position 1:5
        let e = lex_err("\"\"\"h\\el\nlo\"\"\"");
        assert_eq!(e.pos(), 4);
    }
    #[test]
    fn interp_block_rejected_m1() {
        assert!(matches!(
            lex_err(r#"s"a ${x} b""#),
            ParseError::Lexical { .. }
        )); // D6
    }
    #[test]
    fn int_overflow_min_value_magnitude_errors() {
        // D4 / recon-gap.md item 8: Scala rejects -2147483648 because the positive
        // magnitude overflows before the sign applies (Literals.scala:106-116).
        assert!(matches!(lex_err("2147483648"), ParseError::Lexical { .. }));
        assert!(matches!(
            lex_err("9223372036854775808L"),
            ParseError::Lexical { .. }
        ));
        assert!(matches!(lex_err("0x80000000"), ParseError::Lexical { .. })); // > i32::MAX, no L
    }
    #[test]
    fn unterminated_block_comment_errors() {
        // Literals.scala:83 cut after "/*"
        assert!(matches!(lex_err("a /* b"), ParseError::Lexical { .. }));
    }
}
