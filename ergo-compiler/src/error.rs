//! Parse errors. Mirrors the two Scala failure surfaces with one Rust type:
//! fastparse `Parsed.Failure` (grammar) and `ParserException` (semantic build
//! errors thrown by mkUnaryOp/mkBinaryOp/etc., Basic.scala:56-66). Error
//! MESSAGES are not parity-relevant (design doc §10); positions and
//! accept/reject classification are.

use crate::span::{line_col, Pos};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Grammar-level failure: unexpected token / unexpected end of input.
    #[error("syntax error at offset {pos}: expected {expected}")]
    Syntax { pos: Pos, expected: String },
    /// Lexical failure (bad escape, unterminated string/comment, numeric overflow).
    #[error("lexical error at offset {pos}: {msg}")]
    Lexical { pos: Pos, msg: String },
    /// Semantic build failure (Scala ParserException class): unknown operator,
    /// invalid lambda, unsupported pattern/type, block-shape violations.
    #[error("{msg} (offset {pos})")]
    Semantic { pos: Pos, msg: String },
    /// Structural-nesting depth guard tripped (`parse.rs`'s shared `expr()`/
    /// `type_()` recursion counter, `MAX_PARSE_DEPTH`). NOT a Scala-modeled
    /// failure class like the three above -- the reference's own
    /// recursive-descent parser has the analogous JVM stack-overflow
    /// exposure, it is just never REST-adjacent the way this node's
    /// compile-on-request surface is (M6,
    /// dev-docs/ergoscript-compiler-m6-recon.md §5). The threshold is a
    /// conservative, non-oracle-pinned constant -- the compiler's own limits
    /// are explicitly not consensus-critical (`lib.rs` D-note) -- so this
    /// exists purely to bound stack use once REST exposes untrusted source
    /// text to this parser.
    #[error("expression/type nested too deeply (depth {depth} exceeds the parser's limit) at offset {pos}")]
    TooDeep { pos: Pos, depth: usize },
}

impl ParseError {
    pub fn pos(&self) -> Pos {
        match self {
            ParseError::Syntax { pos, .. }
            | ParseError::Lexical { pos, .. }
            | ParseError::Semantic { pos, .. }
            | ParseError::TooDeep { pos, .. } => *pos,
        }
    }

    /// 1-based (line, column) as the Scala reference reports them.
    pub fn line_col(&self, src: &str) -> (u32, u32) {
        line_col(src, self.pos())
    }
}
