//! Lexer core for ErgoScript.
//!
//! There is no separate lexer in the Scala reference — it is a scannerless
//! fastparse grammar (recon-lexical.md §0). This module reconstructs the token
//! stream that grammar observes, so the Task 6+ parser can drive semicolon
//! inference off explicit `Newline` tokens. Every rule cites the mirrored Scala
//! source under `sigmastate-interpreter/parsers/shared/.../parsers`.
//!
//! Task 4 scope: whitespace/comment/newline machinery, identifiers, keywords,
//! numbers, and punctuation. String (`"`) and char/symbol (`'`) literals are
//! Task 5 — their `TokenKind` variants exist but a `"`/`'` in the input returns
//! a placeholder `ParseError::Lexical` here (clearly marked "Task 5").

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
    /// Task 5.
    Str(String),
    /// Task 5 (`'c'` / `'sym` raw forms).
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
// Unicode operator, and the Task 11 corpus oracle catches any counterexample.
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
// (Basic.scala:12, exact). Corpus-checked in Task 11.
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
                Some(b'\r') => self.pos += 1, // lone \r: skipped, no token
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
            '"' => {
                // Task 5 scope: string literals are lexed in Task 5.
                return Err(ParseError::Lexical {
                    pos: start as u32,
                    msg: "strings lexed in Task 5".into(),
                });
            }
            '\'' => {
                // Task 5 scope: char/symbol quote forms are lexed in Task 5.
                return Err(ParseError::Lexical {
                    pos: start as u32,
                    msg: "char/symbol literals lexed in Task 5".into(),
                });
            }
            _ if c.is_ascii_digit() => return self.lex_number(start),
            _ if is_id_start(c) => return Ok(self.lex_ident(start)),
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
    fn lex_ident(&mut self, start: usize) -> Token {
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
        self.tok(kind, start)
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

    // ----- error paths -----
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
