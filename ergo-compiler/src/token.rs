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
/// an op-char run equal to one of these ASCII forms (`: ; => = # @`) is the
/// keyword, not an `OpId`. The Unicode arrow `⇒` (U+21D2) is NOT in that reserved
/// set, so it lexes as an ordinary symbolic-identifier `OpId`; only the `FatArrow`
/// KEYWORD matcher (Core.scala:23 `` `=>` = O("=>") | O("⇒") ``) also accepts it,
/// reproduced parser-side by `Cursor::at_sym_kw`.
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
    /// True iff this token's immediate leading gap contains, AFTER the gap's
    /// first newline, a block comment that is NOT terminated by a newline before
    /// this token (only spaces/tabs, or another comment, follow it). This is the
    /// one bit of comment structure `OneNLMax` needs: the reference's
    /// `ConsumeComments = (WSChars.? ~ Comment ~ WSChars.? ~ Newline).rep`
    /// (Literals.scala:58) matches a block comment via `MultilineComment = "/*"
    /// ~/ …` — the `~/` cut means a matched block comment NOT followed by the
    /// required `Newline` turns that `.rep` iteration into a HARD failure (a line
    /// comment has no cut). `OneNLMax` is `NoCut`, so the caller backtracks — but
    /// the continuation is refused. See `Cursor::one_nl_max`. oracle-mapped
    /// (`a +\n/*c*/b` REJECT vs `a +\n/*c*/\nb` / `a + /*c*/b` ACCEPT).
    pub bc_before: bool,
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
        // `skip_gap` reports whether the gap it just consumed poisons a
        // following `OneNLMax` continuation (a post-newline block comment with no
        // terminating newline); the next real token — the one `OneNLMax` would
        // land on — carries that as `bc_before`.
        let bc_before = lx.skip_gap(&mut tokens)?;
        if lx.at_end() {
            let p = lx.pos as u32;
            tokens.push(Token {
                kind: TokenKind::Eof,
                start: p,
                end: p,
                bc_before,
            });
            return Ok(tokens);
        }
        let mut tok = lx.lex_token()?;
        tok.bc_before = bc_before;
        tokens.push(tok);
    }
}

// ----- character classes -----

/// Op-char set (Basic.scala:38-45): the ASCII operators plus Unicode Sm/So.
//
// deviation: full Sm/So op-char classes are deferred (Rust std has no Unicode
// general-category predicate); the single `⇒` (U+21D2, category Sm) is
// special-cased and the ASCII set is exact. `⇒` is an op-char (so `⇒=` munches
// into one `OpId`), but it is NOT a reserved symbolic keyword — a lone `⇒` lexes
// as an `OpId`, matched as the arrow only in keyword position (Core.scala:23). No
// real contract uses another Unicode operator, and the corpus oracle catches any
// counterexample.
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
/// (both include `Other_Uppercase`/`Other_Lowercase` chars), so a case-less
/// letter cannot start a plain id — matching the reference.
///
/// Exception: U+24B6–24E9 (circled Latin capital/small letters, So) carry
/// `Other_Uppercase`/`Other_Lowercase` so both Rust and JVM return `true` for
/// their case predicates. However, Scala's grammar treats So chars as op-chars
/// (not id-starts); our ASCII-only op-char set cannot form a token for them
/// either, so excluding them from id-start produces a lex error — reject-side
/// divergence from Scala (which ACCEPTs `xⒶ` as a postfix call) but verdict
/// parity on mixed forms like `xⒶ+1` (both REJECT). Documented in the Sm/So
/// ledger entry in lib.rs.
///
/// fastparse scans the JVM `String` as UTF-16 `Char`s, so a supplementary
/// code point (> U+FFFF) reaches the id-start check as two surrogate halves,
/// each of category `Cs`, which are never `isLowerCase` or `isUpperCase` and
/// can never start an identifier. Hence the BMP gate (mirrors `is_id_char`).
/// oracle: `𝐀` (U+1D400, `Lu`) REJECT 1:1; `{ val x = 𝐀 }` REJECT 1:11.
fn is_id_start(c: char) -> bool {
    let cp = c as u32;
    if cp > 0xFFFF {
        return false;
    }
    // Circled Latin letters: Other_Uppercase/Other_Lowercase so case predicates fire,
    // but Scala treats them as So op-chars. Exclude to match grammar-level behavior.
    if matches!(cp, 0x24B6..=0x24E9) {
        return false;
    }
    c.is_lowercase() || c.is_uppercase() || c == '$' || c == '_'
}

/// A character allowed inside an identifier chunk: `'$' | isLetter | isDigit`
/// (Identifiers.scala:41-43), where `isLetter`/`isDigit` are fastparse's JVM
/// `Character.isLetter` (categories `Lu|Ll|Lt|Lm|Lo`) and `Character.isDigit`
/// (`Nd`). Underscore is deliberately NOT an id-char — it is handled by the
/// underscore chunks of `IdRest`.
///
/// fastparse scans the JVM `String` as UTF-16 `Char`s, so a supplementary code
/// point (> U+FFFF) reaches `IdCharacter` as two surrogate halves — each of
/// category `Cs`, so neither `isLetter` nor `isDigit` — and can never be an
/// id-tail char. Hence the BMP gate. oracle: `x𝟎` (U+1D7CE `Nd`) / `x𝐀` (U+1D400
/// `Lu`) REJECT; `x²` (U+00B2 `No`) / `x①` (U+2460 `No`) / `xְ` (U+05B0 `Mn`)
/// REJECT; `x५` (U+096B `Nd`) / `xＡ` (U+FF21 `Lu`) ACCEPT.
fn is_id_char(c: char) -> bool {
    if c == '$' {
        return true;
    }
    if (c as u32) > 0xFFFF {
        return false;
    }
    is_jvm_letter(c) || is_jvm_digit(c)
}

/// JVM `Character.isDigit` — general category `Nd`. Rust `char::is_numeric` is the
/// wider `Nd|Nl|No`, so it is narrowed to `Nd` by the `ND` range table (ASCII is the
/// hot path). oracle: `x²`/`x①` (`No`) REJECT, `x५` (`Nd`) ACCEPT.
fn is_jvm_digit(c: char) -> bool {
    c.is_ascii_digit() || (c.is_numeric() && in_ranges(c, ND))
}

/// JVM `Character.isLetter` — general category `Lu|Ll|Lt|Lm|Lo`. Rust
/// `char::is_alphabetic` is the wider Unicode `Alphabetic` property (it also
/// admits `Nl`, `So`, and `Other_Alphabetic` combining marks), narrowed here by
/// subtracting the `ALPHA_NOT_LETTER` table. oracle: `xְ` (U+05B0 `Mn`) REJECT,
/// `xＡ` (U+FF21 `Lu`) ACCEPT, `xⒶ` (U+24B6 `So`) id STOPS at `x` → lex error
/// (Scala: So op-char forms separate token; our ASCII-only op-chars → REJECT).
fn is_jvm_letter(c: char) -> bool {
    c.is_alphabetic() && !in_ranges(c, ALPHA_NOT_LETTER)
}

/// Membership test over a sorted, non-overlapping `[lo, hi]` table. The caller
/// guarantees `c <= U+FFFF` (the BMP gate in `is_id_char`), so the code point fits
/// in `u16`.
fn in_ranges(c: char, table: &[(u16, u16)]) -> bool {
    let cp = c as u16;
    table
        .binary_search_by(|&(lo, hi)| {
            use core::cmp::Ordering;
            if cp < lo {
                Ordering::Greater
            } else if cp > hi {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

// JVM identifier-class range tables (Unicode 16.0.0). Both are generated from the
// intersection of Rust's own `char::is_numeric`/`char::is_alphabetic` sets with the
// UCD general category (`unicodedata`), then collapsed to sorted `[lo, hi]` ranges;
// see `scripts/` provenance in the round-7 report. They are the *difference* sets
// that narrow Rust's wider predicates to the exact JVM `Character.isDigit`/`isLetter`
// masks, so a change in either Rust's or the UCD's Unicode version can only shift a
// handful of exotic code points (none in any real contract).
/// Decimal-digit (`Nd`) code point ranges within the BMP.
/// 370 code points in 37 ranges (Unicode 16.0.0, via UCD `unicodedata`).
const ND: &[(u16, u16)] = &[
    (0x0030, 0x0039),
    (0x0660, 0x0669),
    (0x06F0, 0x06F9),
    (0x07C0, 0x07C9),
    (0x0966, 0x096F),
    (0x09E6, 0x09EF),
    (0x0A66, 0x0A6F),
    (0x0AE6, 0x0AEF),
    (0x0B66, 0x0B6F),
    (0x0BE6, 0x0BEF),
    (0x0C66, 0x0C6F),
    (0x0CE6, 0x0CEF),
    (0x0D66, 0x0D6F),
    (0x0DE6, 0x0DEF),
    (0x0E50, 0x0E59),
    (0x0ED0, 0x0ED9),
    (0x0F20, 0x0F29),
    (0x1040, 0x1049),
    (0x1090, 0x1099),
    (0x17E0, 0x17E9),
    (0x1810, 0x1819),
    (0x1946, 0x194F),
    (0x19D0, 0x19D9),
    (0x1A80, 0x1A89),
    (0x1A90, 0x1A99),
    (0x1B50, 0x1B59),
    (0x1BB0, 0x1BB9),
    (0x1C40, 0x1C49),
    (0x1C50, 0x1C59),
    (0xA620, 0xA629),
    (0xA8D0, 0xA8D9),
    (0xA900, 0xA909),
    (0xA9D0, 0xA9D9),
    (0xA9F0, 0xA9F9),
    (0xAA50, 0xAA59),
    (0xABF0, 0xABF9),
    (0xFF10, 0xFF19),
];

/// BMP code points that Rust `char::is_alphabetic` accepts but JVM `Character.isLetter` rejects (categories `Mn`/`Mc`/`Nl`/`So`).
/// 949 code points in 163 ranges (Unicode 16.0.0, via UCD `unicodedata`).
/// The `So` entry covers the 52 circled Latin letters U+24B6–24E9 (CIRCLED LATIN CAPITAL/SMALL
/// LETTER A–Z) — they carry `Other_Alphabetic` so Rust `is_alphabetic` returns `true`, but
/// `Character.isLetter` returns `false` (category `So`, not `L*`). Scala's lexer therefore ends
/// the identifier before them and parses them as So operator characters; our ASCII-only op-char
/// set cannot produce an operator token for them, so the whole input REJECTS (reject-side
/// divergence from Scala; documented in lib.rs Sm/So ledger entry).
const ALPHA_NOT_LETTER: &[(u16, u16)] = &[
    (0x0345, 0x0345),
    (0x0363, 0x036F),
    (0x05B0, 0x05BD),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C5),
    (0x05C7, 0x05C7),
    (0x0610, 0x061A),
    (0x064B, 0x0657),
    (0x0659, 0x065F),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06E1, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06ED, 0x06ED),
    (0x0711, 0x0711),
    (0x0730, 0x073F),
    (0x07A6, 0x07B0),
    (0x0816, 0x0817),
    (0x081B, 0x0823),
    (0x0825, 0x0827),
    (0x0829, 0x082C),
    (0x0897, 0x0897),
    (0x08D4, 0x08DF),
    (0x08E3, 0x08E9),
    (0x08F0, 0x0903),
    (0x093A, 0x093B),
    (0x093E, 0x094C),
    (0x094E, 0x094F),
    (0x0955, 0x0957),
    (0x0962, 0x0963),
    (0x0981, 0x0983),
    (0x09BE, 0x09C4),
    (0x09C7, 0x09C8),
    (0x09CB, 0x09CC),
    (0x09D7, 0x09D7),
    (0x09E2, 0x09E3),
    (0x0A01, 0x0A03),
    (0x0A3E, 0x0A42),
    (0x0A47, 0x0A48),
    (0x0A4B, 0x0A4C),
    (0x0A51, 0x0A51),
    (0x0A70, 0x0A71),
    (0x0A75, 0x0A75),
    (0x0A81, 0x0A83),
    (0x0ABE, 0x0AC5),
    (0x0AC7, 0x0AC9),
    (0x0ACB, 0x0ACC),
    (0x0AE2, 0x0AE3),
    (0x0AFA, 0x0AFC),
    (0x0B01, 0x0B03),
    (0x0B3E, 0x0B44),
    (0x0B47, 0x0B48),
    (0x0B4B, 0x0B4C),
    (0x0B56, 0x0B57),
    (0x0B62, 0x0B63),
    (0x0B82, 0x0B82),
    (0x0BBE, 0x0BC2),
    (0x0BC6, 0x0BC8),
    (0x0BCA, 0x0BCC),
    (0x0BD7, 0x0BD7),
    (0x0C00, 0x0C04),
    (0x0C3E, 0x0C44),
    (0x0C46, 0x0C48),
    (0x0C4A, 0x0C4C),
    (0x0C55, 0x0C56),
    (0x0C62, 0x0C63),
    (0x0C81, 0x0C83),
    (0x0CBE, 0x0CC4),
    (0x0CC6, 0x0CC8),
    (0x0CCA, 0x0CCC),
    (0x0CD5, 0x0CD6),
    (0x0CE2, 0x0CE3),
    (0x0CF3, 0x0CF3),
    (0x0D00, 0x0D03),
    (0x0D3E, 0x0D44),
    (0x0D46, 0x0D48),
    (0x0D4A, 0x0D4C),
    (0x0D57, 0x0D57),
    (0x0D62, 0x0D63),
    (0x0D81, 0x0D83),
    (0x0DCF, 0x0DD4),
    (0x0DD6, 0x0DD6),
    (0x0DD8, 0x0DDF),
    (0x0DF2, 0x0DF3),
    (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A),
    (0x0E4D, 0x0E4D),
    (0x0EB1, 0x0EB1),
    (0x0EB4, 0x0EB9),
    (0x0EBB, 0x0EBC),
    (0x0ECD, 0x0ECD),
    (0x0F71, 0x0F83),
    (0x0F8D, 0x0F97),
    (0x0F99, 0x0FBC),
    (0x102B, 0x1036),
    (0x1038, 0x1038),
    (0x103B, 0x103E),
    (0x1056, 0x1059),
    (0x105E, 0x1060),
    (0x1062, 0x1064),
    (0x1067, 0x106D),
    (0x1071, 0x1074),
    (0x1082, 0x108D),
    (0x108F, 0x108F),
    (0x109A, 0x109D),
    (0x16EE, 0x16F0),
    (0x1712, 0x1713),
    (0x1732, 0x1733),
    (0x1752, 0x1753),
    (0x1772, 0x1773),
    (0x17B6, 0x17C8),
    (0x1885, 0x1886),
    (0x18A9, 0x18A9),
    (0x1920, 0x192B),
    (0x1930, 0x1938),
    (0x1A17, 0x1A1B),
    (0x1A55, 0x1A5E),
    (0x1A61, 0x1A74),
    (0x1ABF, 0x1AC0),
    (0x1ACC, 0x1ACE),
    (0x1B00, 0x1B04),
    (0x1B35, 0x1B43),
    (0x1B80, 0x1B82),
    (0x1BA1, 0x1BA9),
    (0x1BAC, 0x1BAD),
    (0x1BE7, 0x1BF1),
    (0x1C24, 0x1C36),
    (0x1DD3, 0x1DF4),
    (0x2160, 0x2182),
    (0x2185, 0x2188),
    // U+24B6–24E9: CIRCLED LATIN CAPITAL/SMALL LETTER A–Z (So, Other_Alphabetic).
    // Rust is_alphabetic=true; JVM Character.isLetter=false (So ≠ L*).
    (0x24B6, 0x24E9),
    (0x2DE0, 0x2DFF),
    (0x3007, 0x3007),
    (0x3021, 0x3029),
    (0x3038, 0x303A),
    (0xA674, 0xA67B),
    (0xA69E, 0xA69F),
    (0xA6E6, 0xA6EF),
    (0xA802, 0xA802),
    (0xA80B, 0xA80B),
    (0xA823, 0xA827),
    (0xA880, 0xA881),
    (0xA8B4, 0xA8C3),
    (0xA8C5, 0xA8C5),
    (0xA8FF, 0xA8FF),
    (0xA926, 0xA92A),
    (0xA947, 0xA952),
    (0xA980, 0xA983),
    (0xA9B4, 0xA9BF),
    (0xA9E5, 0xA9E5),
    (0xAA29, 0xAA36),
    (0xAA43, 0xAA43),
    (0xAA4C, 0xAA4D),
    (0xAA7B, 0xAA7D),
    (0xAAB0, 0xAAB0),
    (0xAAB2, 0xAAB4),
    (0xAAB7, 0xAAB8),
    (0xAABE, 0xAABE),
    (0xAAEB, 0xAAEF),
    (0xAAF5, 0xAAF5),
    (0xABE3, 0xABEA),
    (0xFB1E, 0xFB1E),
];

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
            bc_before: false,
        }
    }

    /// Consume inter-token whitespace, comments and newlines, pushing one
    /// `Newline` token per `\n`/`\r\n` outside comments (Basic.scala:33-34).
    ///
    /// `after_comment` is true iff only spaces/tabs separate the newline from
    /// the end of the previous comment — `last_was_comment` stays set across
    /// spaces/tabs and is cleared by a newline (Literals.scala:57-60).
    ///
    /// A lone `\r` (one not followed by `\n`) in the inter-token gap is a hard
    /// `Lexical` error — see the Round-10 CR matrix below. In fastparse it is
    /// neither `Basic.WSChars` (space/tab only) nor `Basic.Newline` (`\r\n`|`\n`
    /// only); it is swallowed by the implicit `ScalaWhitespace` at `~` junctions
    /// yet invisible to every explicit `WS`/`WL`/`Newline`/`Semi`/`OneNLMax`
    /// combinator and a wall at raw `~~` junctions. That makes it behave like a
    /// SPACE at some junctions and like a NEWLINE at others, e.g. (`⇒` = U+21D2):
    ///   oracle: `\r1` ACCEPT · `1\r` ACCEPT · `(x,y)\r=>x` ACCEPT ·
    ///           `{ val x = 1\r x }` ACCEPT · `f(\r)` ACCEPT · `a\rb` ACCEPT ·
    ///           `1\r+2` REJECT 1:1 · `1\r2` REJECT 2:1 · `1 \r 2` REJECT 2:2 ·
    ///           `(x,y)\r⇒x` REJECT 1:1 · `{ val x = 1\r val y = 2; y }` REJECT 1:11
    /// (contrast the LF twins: `a\nb` REJECT, `(x,y)\n⇒x` ACCEPT — i.e. `\r` is
    /// NOT a newline). Reproducing every cell would need an infix-blocking-but-
    /// not-newline gap token threaded through the whole expr parser plus
    /// fastparse furthest-failure positions that even contradict `span::line_col`
    /// (which counts a lone `\r` as no line boundary, Scala `getLines`). Bare-CR
    /// sources are illegitimate and no corpus contract holds one, so we take the
    /// reject-side-safe route: refuse the gap `\r` outright. This matches Scala on
    /// every REJECT cell and cannot cause a wrong-bytes accept; the residual is a
    /// reject-side divergence on the ACCEPT cells above. See lib.rs ledger.
    /// UNTOUCHED: `\r\n` (one Newline), and `\r` inside line-comment content
    /// (`// c\r more` ACCEPT) or string literals (`"a\rb"` ACCEPT) — those are
    /// consumed by the comment/string lexers, never reaching this gap.
    fn skip_gap(&mut self, tokens: &mut Vec<Token>) -> Result<bool, ParseError> {
        let mut last_was_comment = false;
        // `OneNLMax`'s `ConsumeComments` `~/`-cut reconstruction: once a newline has
        // been crossed (`seen_newline`), a block comment that is not immediately
        // (modulo spaces/tabs) followed by another newline poisons the continuation
        // — sticky for the whole gap. Comments BEFORE the first newline are the
        // reference's leading `WS` (NoCut) and never poison. See `Token::bc_before`.
        let mut seen_newline = false;
        let mut bc_cut = false;
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
                    seen_newline = true;
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
                    seen_newline = true;
                }
                Some(b'\r') => {
                    // lone \r (not before \n): reject-side-safe hard failure.
                    // It is neither WSChars nor Basic.Newline in fastparse; its
                    // true behavior is junction-dependent and cannot cause a
                    // wrong-bytes accept, so we refuse it. See the CR matrix and
                    // the ledger. oracle: `1\r+2`/`1\r2`/`(x,y)\r⇒x` REJECT (we
                    // match); `\r1`/`1\r`/`a\rb` ACCEPT (documented reject-side
                    // divergence).
                    return Err(ParseError::Lexical {
                        pos: self.pos as u32,
                        msg: "lone carriage return (\\r) outside string/comment".into(),
                    });
                }
                Some(b'/') if self.peek_byte_at(1) == Some(b'/') => {
                    self.consume_line_comment();
                    last_was_comment = true;
                    // A line comment carries no `~/` cut (Literals.scala:85) — it
                    // never poisons `ConsumeComments`.
                }
                Some(b'/') if self.peek_byte_at(1) == Some(b'*') => {
                    self.consume_block_comment()?;
                    last_was_comment = true;
                    if seen_newline && !self.block_comment_newline_terminated() {
                        bc_cut = true;
                    }
                }
                _ => return Ok(bc_cut), // token start or EOF
            }
        }
    }

    /// After a block comment in a post-newline gap: does a newline (`\n`/`\r\n`)
    /// follow it, modulo spaces/tabs? If so it is a well-formed `ConsumeComments`
    /// comment-line (Literals.scala:58); if not, the `MultilineComment` `~/` cut
    /// makes it a hard `OneNLMax` failure. Pure lookahead — does not advance.
    fn block_comment_newline_terminated(&self) -> bool {
        let mut i = self.pos;
        while matches!(self.bytes.get(i), Some(b' ') | Some(b'\t')) {
            i += 1;
        }
        matches!(self.bytes.get(i), Some(b'\n'))
            || (self.bytes.get(i) == Some(&b'\r') && self.bytes.get(i + 1) == Some(&b'\n'))
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
    /// start (Identifiers.scala:22-24). A run exactly equal to an ASCII symbolic
    /// keyword (`: => = # @`, Identifiers.scala:55-57) is that keyword; every other
    /// run (`:: == <= ++ -`, and the Unicode arrow `⇒` which is NOT reserved) is an
    /// `OpId`. `⇒` reaches the `FatArrow` keyword only in keyword position, via
    /// `Cursor::at_sym_kw` (Core.scala:23).
    fn lex_op_run(&mut self, start: usize) -> Token {
        self.consume_op_run();
        let run = &self.src[start..self.pos];
        // A symbolic-keyword op-run stopped DIRECTLY before a `//`/`/*` comment is an
        // operator IDENTIFIER, not the keyword. Scala's reserved-check
        // `SymbolicKeywords = (":"|";"|"=>"|"="|"#"|"@") ~ !OpChar`
        // (Identifiers.scala:55-57) has no comment exception: for e.g. `=//c` the
        // char after `=` is `/` (an op-char), so `!OpChar` FAILS and the run lexes as
        // a `PlainId`. (The GRAMMAR keyword matchers `Key.O(...)`, Basic.scala:76-77,
        // DO carry a comment exception, so the same text still works in keyword
        // positions — reproduced parser-side by `Cursor::at_sym_kw`.) A run that is
        // not a symbolic keyword is already an `OpId`, so this only reclassifies the
        // six keyword runs. oracle: `a.=>/*c*/` ACCEPT vs `a.=>` REJECT; `x #/*c*/ y`
        // rejects as an unknown infix, not at the keyword.
        let before_comment = self.peek_byte() == Some(b'/')
            && matches!(self.peek_byte_at(1), Some(b'/') | Some(b'*'));
        let kind = if before_comment {
            TokenKind::OpId
        } else {
            match run {
                ":" => TokenKind::Kw(Kw::Colon),
                // Only the ASCII `=>` is reserved; `⇒` (U+21D2) is not in
                // SymbolicKeywords (Identifiers.scala:55-57), so it stays an `OpId`.
                // oracle: `(x,y) ⇒ 1` REJECT 1:1 (infix `⇒` → unknown binary op) vs
                // `(x,y) => 1` ACCEPT.
                "=>" => TokenKind::Kw(Kw::FatArrow),
                "=" => TokenKind::Kw(Kw::Assign),
                "#" => TokenKind::Kw(Kw::Hash),
                "@" => TokenKind::Kw(Kw::At),
                _ => TokenKind::OpId,
            }
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
                // Decode the following CHAR, not the byte: `is_op_char` includes the
                // multi-byte `⇒` (U+21D2), so a byte-level peek would miss it.
                // oracle: `';⇒` REJECT 1:2; `';` / `';x` / `'; x` ACCEPT (`;`
                // followed by EOF / an id-start / a space is a valid symbol keyword).
                if self.src[self.pos + 1..]
                    .chars()
                    .next()
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

/// fastparse `isPrintableChar` (CharPredicates, referenced Literals.scala:98):
/// `!isISOControl && !isSurrogate && block != null && block != SPECIALS`.
///
/// Rust `char` can never be an unpaired surrogate. However, Rust `char` CAN
/// represent supplementary scalars (> U+FFFF); the JVM's `Char`-based parser
/// sees them as two surrogate halves, each of category `Cs`, which fail
/// `!isSurrogate` — so they are not printable. The BMP gate `(c as u32) <=
/// 0xFFFF` reproduces this. `char::is_control` is exactly JVM `isISOControl`
/// (both = category `Cc`). The `SPECIALS` block is U+FFF0..=U+FFFF, excluded
/// explicitly. oracle: `'a'` ACCEPT; `'😀'` (U+1F600) / `'𝐀'` (U+1D400) REJECT
/// 1:2 (supplementary, BMP-gated); `'￰'` (U+FFF0) / `'￿'` (U+FFFF) REJECT
/// 1:2 (SPECIALS).
//
// deviation: the `block == null` clause (code points in NO assigned Unicode block)
// is not reproduced — it only affects char literals over unassigned no-block code
// points that no real contract uses (a probed unassigned-but-in-block point such as
// U+0378 is printable in both). A SPECIALS code point that is ALSO a JVM op-char
// (So/Sm, e.g. U+FFFC) still REJECTS, but one column early, since our op-char set is
// ASCII-only (see the Sm/So op-char deviation) — reject-parity holds either way.
fn is_printable_char(c: char) -> bool {
    (c as u32) <= 0xFFFF && !c.is_control() && !matches!(c as u32, 0xFFF0..=0xFFFF)
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
        // `⇒` (U+21D2) is NOT a reserved symbolic keyword (Identifiers.scala:55-57);
        // it lexes as an `OpId` and is the arrow only in keyword position (Core.scala:23).
        assert_eq!(kinds("⇒")[0], TokenKind::OpId);
        assert_eq!(kinds("::")[0], TokenKind::OpId);
    }
    #[test]
    fn opid_stops_before_comment_start() {
        // Identifiers.scala:22-24 + Basic.scala:76-77: the op-run munch stops before
        // a `//`/`/*` comment start.
        assert_eq!(
            kinds("+/*c*/+"),
            vec![TokenKind::OpId, TokenKind::OpId, TokenKind::Eof]
        );
    }
    #[test]
    fn id_tail_unicode_classes_match_jvm_masks() {
        // `IdCharacter = '$' | isLetter(Lu|Ll|Lt|Lm|Lo) | isDigit(Nd)`
        // (Identifiers.scala:41-43), scanned over UTF-16 chars.
        // Continues an identifier (single Ident token):
        for src in ["x5", "x५", "xＡ", "xé", "x_$y"] {
            let t = tokenize(src).unwrap();
            assert_eq!(t[0].kind, TokenKind::Ident, "{src}");
            assert_eq!(t[0].text(src), src, "{src}"); // whole run is ONE ident
        }
        // NOT an id-tail char, and not otherwise startable → hard lex error at the
        // char. oracle: `x²`(U+00B2 No) / `x①`(U+2460 No) / `xְ`(U+05B0 Mn) REJECT 1:2;
        // the supplementary digit `x𝟎`(U+1D7CE Nd) reaches fastparse as surrogate
        // halves → REJECT.
        for src in ["x²", "x①", "x\u{05B0}", "x\u{1D7CE}"] {
            assert!(
                matches!(tokenize(src), Err(ParseError::Lexical { .. })),
                "{src}"
            );
        }
        // The id-tail always STOPS at the exotic char (the BMP gate / class narrowing
        // did its job). U+2160 (Nl, BMP) then starts a fresh token via `is_id_start`
        // (which is also BMP-gated), so the first token is the bare `x`.
        let t = tokenize("x\u{2160}").unwrap();
        assert_eq!(t[0].kind, TokenKind::Ident);
        assert_eq!(t[0].text("x\u{2160}"), "x");
        // U+1D400 (supplementary Lu): fails both is_id_char (BMP gate) AND is_id_start
        // (BMP gate added by F1 fix) → lex error at the supplementary char.
        // oracle: `x𝐀` REJECT 1:2.
        assert!(
            matches!(tokenize("x\u{1D400}"), Err(ParseError::Lexical { .. })),
            "x𝐀 (supplementary) should lex-error after BMP-gate on is_id_start"
        );
    }
    #[test]
    fn id_tail_circled_letter_so_excluded_from_letter_class() {
        // Round-11 fix: U+24B6–24E9 (CIRCLED LATIN CAPITAL/SMALL LETTER A–Z, category
        // So) are Rust `is_alphabetic` but NOT JVM `Character.isLetter`. They must not
        // extend an identifier; the ALPHA_NOT_LETTER table now covers them.
        //
        // `xⒶ+1`: Scala REJECT 1:4 (id ends at x; Ⓐ is a So op-char; `Ⓐ+` is an
        // operator; `1` is the operand — parses but no well-typed result → REJECT at
        // semantic level). Our lexer: id ends at `x`; Ⓐ is not an ASCII op-char →
        // lex error. Verdict parity: both REJECT.
        // oracle: `xⒶ+1` REJECT 1:4 (Scala), lex error (ours).
        assert!(
            matches!(tokenize("x\u{24B6}+1"), Err(ParseError::Lexical { .. })),
            "xⒶ+1 must lex-error (circled letter ends id, not an ASCII op-char)"
        );
        // Regressions: normal id-tail chars still accepted.
        for src in ["x2", "x_y", "truex"] {
            assert!(tokenize(src).is_ok(), "{src} regression: must still parse");
        }
        // `xⒶ` and `xⒶy`: oracle ACCEPT (sic) — Scala parses Ⓐ/Ⓐy as So op-char
        // identifiers (postfix / infix on `x`). Our ASCII-only op-char set cannot
        // form an operator token for So chars → lex error → REJECT. Reject-side
        // divergence; no real contract uses circled letters as operators.
        // oracle: `xⒶ` ACCEPT (sic), `xⒶy` ACCEPT (sic) — So op-char deviation.
        assert!(
            matches!(tokenize("x\u{24B6}"), Err(ParseError::Lexical { .. })),
            "xⒶ: oracle ACCEPT (sic) — So op-char deviation; our lex-error is expected"
        );
        assert!(
            matches!(tokenize("x\u{24B6}y"), Err(ParseError::Lexical { .. })),
            "xⒶy: oracle ACCEPT (sic) — So op-char deviation; our lex-error is expected"
        );
        // Spot-check both ends of the range: Ⓩ (U+24CF) and ⓩ (U+24E9).
        assert!(
            matches!(tokenize("x\u{24CF}"), Err(ParseError::Lexical { .. })),
            "xⒹ (U+24CF) must lex-error"
        );
        assert!(
            matches!(tokenize("x\u{24E9}"), Err(ParseError::Lexical { .. })),
            "xⓩ (U+24E9) must lex-error"
        );
        // Ⓐx (So as id-start): not a JVM letter → is_id_start returns false → lex error.
        // oracle: Scala Ⓐ is an op-char id-start, so `Ⓐx` is an infix application of
        // the Ⓐ operator on implicit lhs and `x` rhs — rejects without lhs context.
        // Both sides REJECT; same deviation class.
        assert!(
            matches!(tokenize("\u{24B6}x"), Err(ParseError::Lexical { .. })),
            "Ⓐx (So as id-start) must lex-error"
        );
    }
    #[test]
    fn char_literal_printable_excludes_specials() {
        // fastparse `isPrintableChar` excludes the SPECIALS block U+FFF0..=U+FFFF.
        // oracle: `'a'` ACCEPT; `'￯'`(U+FFEF, just below SPECIALS) ACCEPT;
        // `'￰'`(U+FFF0) / `'￿'`(U+FFFF) REJECT as char literals.
        assert_eq!(kinds("'a'")[0], TokenKind::CharSym("'a'".into()));
        assert!(matches!(
            tokenize("'\u{FFEF}'").unwrap()[0].kind,
            TokenKind::CharSym(_)
        ));
        assert!(matches!(lex_err("'\u{FFF0}'"), ParseError::Lexical { .. }));
        assert!(matches!(lex_err("'\u{FFFF}'"), ParseError::Lexical { .. }));
    }
    #[test]
    fn id_start_supplementary_scalar_rejected() {
        // F1 (P2): is_id_start BMP gate — supplementary code points (> U+FFFF)
        // appear as surrogate halves in JVM's UTF-16 scanner, which are never
        // isUpperCase/isLowerCase, so they can never start an identifier.
        // oracle: `𝐀` (U+1D400, Lu supplementary) REJECT 1:1;
        //         `{ val x = 𝐀 }` REJECT 1:11.
        assert!(
            matches!(tokenize("\u{1D400}"), Err(ParseError::Lexical { .. })),
            "𝐀 (U+1D400, supplementary Lu) must not start an identifier"
        );
        // Regression: BMP code point that is id-start stays accepted.
        // oracle: `Ⅰ` (U+2160, BMP Nl, isUpperCase=true in both JVM and Rust) ACCEPT.
        let t = tokenize("\u{2160}").unwrap();
        assert_eq!(
            t[0].kind,
            TokenKind::Ident,
            "Ⅰ (U+2160, BMP) must lex as Ident"
        );
    }
    #[test]
    fn char_literal_supplementary_scalar_rejected() {
        // F3 (P2): is_printable_char BMP gate — supplementary scalars (> U+FFFF)
        // are not printable because the JVM sees them as surrogate halves, which
        // fail `isPrintableChar`'s `!isSurrogate` check.
        // oracle: `'😀'` (U+1F600) REJECT 1:2; `'𝐀'` (U+1D400) REJECT 1:2.
        assert!(
            matches!(lex_err("'\u{1F600}'"), ParseError::Lexical { .. }),
            "'😀' (U+1F600, supplementary) must reject as char literal"
        );
        assert!(
            matches!(lex_err("'\u{1D400}'"), ParseError::Lexical { .. }),
            "'𝐀' (U+1D400, supplementary) must reject as char literal"
        );
        // Regression: plain ASCII char still accepted.
        // oracle: `'a'` ACCEPT.
        assert_eq!(kinds("'a'")[0], TokenKind::CharSym("'a'".into()));
    }
    #[test]
    fn symbolic_keyword_directly_before_comment_is_opid() {
        // A symbolic-keyword op-run stopped DIRECTLY before a comment is an operator
        // IDENTIFIER, not the keyword: `SymbolicKeywords ~ !OpChar`
        // (Identifiers.scala:55-57) sees the comment's leading `/` (an op-char) and
        // fails, so the run is a `PlainId`. Was pinned `Kw(Assign)`; the oracle
        // proves it wrong (`a.=>/*c*/` — a `Select` on the field `=>` — is ACCEPT,
        // only possible if `=>` before a comment is an identifier).
        // oracle: ParserOracle sigma-state 6.0.2
        for (src, run) in [
            ("=//c", "="),
            ("=>/*c*/", "=>"),
            (":/*c*/x", ":"),
            ("#//c", "#"),
        ] {
            let t = tokenize(src).unwrap();
            assert_eq!(t[0].kind, TokenKind::OpId, "{src}");
            assert_eq!(t[0].text(src), run, "{src}");
        }
        // A comment NOT directly adjacent leaves the keyword intact (the run ends at
        // whitespace, and the reserved-check's `!OpChar` sees the space).
        assert_eq!(kinds("= //c")[0], TokenKind::Kw(Kw::Assign));
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
    fn lone_cr_in_gap_is_lexical_error_at_the_cr() {
        // Round-10 CR matrix (oracle: ParserOracle sigma-state 6.0.2). A lone \r
        // in the inter-token gap is neither WSChars nor Basic.Newline; its true
        // behavior is junction-dependent (space at some, newline at others) and
        // cannot cause a wrong-bytes accept, so we take the reject-side-safe route
        // and refuse it at the \r. This matches Scala on every REJECT cell and is
        // a documented reject-side divergence on the ACCEPT cells (see ledger).
        //   Scala-REJECT cells we now match: `1\r+2` `1\r2` `1 \r 2` `(x,y)\r⇒x`
        //     `{ val x = 1\r val y = 2; y }`.
        //   Scala-ACCEPT cells we now reject-side-diverge on: `\r1` `1\r` `a\rb`
        //     `(x,y)\r=>x` `{ val x = 1\r x }` `f(\r)` `if (true) 1\relse 2`.
        for (src, cr_pos) in [
            ("a\rb", 1),
            ("1\r+2", 1),
            ("1\r2", 1),
            ("\r1", 0),
            ("1\r", 1),
            ("(x,y)\r=>x", 5),
        ] {
            let e = lex_err(src);
            assert!(matches!(e, ParseError::Lexical { .. }), "{src:?}");
            assert_eq!(e.pos(), cr_pos, "{src:?}");
        }
    }
    #[test]
    fn crlf_is_still_one_newline_and_cr_in_comment_or_string_is_content() {
        // \r\n is ONE Newline (Basic.scala:34) — the \r\n arm precedes the lone-\r
        // arm, so it is unaffected by the reject-side-safe lone-\r rule.
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
        // UNTOUCHED: a lone \r inside a line comment (Literals.scala:84-85) or a
        // string literal (Literals.scala:144-154, line 1024) is verbatim content,
        // never reaching the gap. oracle: `// c\r more\n1` ACCEPT; `"a\rb"` ACCEPT.
        assert_eq!(
            kinds("// c\r more\n1"),
            vec![
                TokenKind::Newline {
                    after_comment: true
                },
                TokenKind::IntLit(1),
                TokenKind::Eof
            ]
        );
        assert_eq!(kinds("\"a\rb\"")[0], TokenKind::Str("a\rb".into()));
    }

    #[test]
    fn bc_before_marks_post_newline_dangling_block_comment() {
        // `bc_before` = a block comment after the gap's first newline, NOT
        // newline-terminated before the token. Drives `OneNLMax`'s ConsumeComments
        // `~/` cut. oracle (via the infix `a + <gap> b`): the `true` rows REJECT,
        // the `false` rows ACCEPT (ParserOracle sigma-state 6.0.2).
        let last_real_bc = |src: &str| {
            let t = tokenize(src).unwrap();
            t[t.len() - 2].bc_before // the token before EOF
        };
        // block comment right after the sole newline, then `b` on the same line
        assert!(last_real_bc("+\n/*c*/b")); // -> REJECT continuation
        assert!(last_real_bc("+\n/*c*//*d*/b")); // two blocks, second dangles
        assert!(last_real_bc("+\n /*c*/ b")); // spaces around the block
                                              // block comment that IS newline-terminated (a clean comment-line)
        assert!(!last_real_bc("+\n/*c*/\nb"));
        // block comment BEFORE the sole newline: leading `WS` (NoCut) — never poisons
        assert!(!last_real_bc("+/*c*/\nb"));
        assert!(!last_real_bc("+ /*c*/b")); // no newline at all
                                            // a line comment never poisons (no `~/` cut)
        assert!(!last_real_bc("+\n//c\nb"));
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
