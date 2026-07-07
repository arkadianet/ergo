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
}

impl ParseError {
    pub fn pos(&self) -> Pos {
        match self {
            ParseError::Syntax { pos, .. }
            | ParseError::Lexical { pos, .. }
            | ParseError::Semantic { pos, .. } => *pos,
        }
    }

    /// 1-based (line, column) as the Scala reference reports them.
    pub fn line_col(&self, src: &str) -> (u32, u32) {
        line_col(src, self.pos())
    }
}
