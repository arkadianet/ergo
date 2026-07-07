//! Contract-template parser (`@contract` layer) — a thin wrapper ABOVE the
//! expression grammar, mirroring Scala's `sigmastate.lang.ContractParser` being
//! a *sibling* of `SigmaParser` rather than an extension of it
//! (ContractParser.scala:118-197, sigma-state 6.0.2).
//!
//! The top rule (ContractParser.scala:138) is
//! `Docs.parse ~ Basic.Newline ~ Signature.parse ~ WL.? ~ "=" ~ WL.? ~ AnyChar.rep(1).!`
//! under `import fastparse.NoWhitespace._`: the doc block and signature are
//! hand-parsed here, then EVERYTHING after the top-level `=` is captured raw and
//! handed to the EXISTING [`crate::parse`] entry point — this module never
//! duplicates the expression grammar (§1 of the M7 recon).
//!
//! Reuse points (verbatim, no re-implementation):
//! - `Type` in a parameter → [`crate::parse::parse_type`] (`parse.rs:77`,
//!   Types.scala:63).
//! - the contract body → [`crate::parse::parse`] (`parse.rs:36`,
//!   `SigmaParser(body).get.value`, ContractParser.scala:138).
//! - identifier char classes → [`crate::token::is_id_start`]/[`is_id_char`]
//!   (the same predicates the core lexer uses, `Identifiers.Id`).
//!
//! ## Deviations (M7, reject-side-safe / accept-parity doctrine)
//! - A malformed contract BODY surfaces here as a proper [`ParseError`] with a
//!   position, NOT the uncategorised `NoSuchElementException` Scala's `.get`
//!   throws (ContractParser.scala:138 unwraps the body parse via `.get`). This
//!   is the M1 "prefer information over faithful reproduction of a reference
//!   rough edge" doctrine (lib.rs D6/stray-brace), applied per M7 recon §6 Q3.
//! - Parameter/contract names accept the core `Id` PLAIN-identifier form only;
//!   backtick/operator identifiers in NAME position are rejected (no real
//!   `@contract` source uses them). Types and literal defaults are parsed by the
//!   reused entry points and carry the full grammar.

use crate::ast::Expr;
use crate::error::ParseError;
use crate::parse::{parse, parse_type};
use crate::span::Pos;
use crate::stype::SType;
use crate::token::{is_id_char, is_id_start};

// ── AST ──────────────────────────────────────────────────────────────────────

/// A `@param name text` entry, post-processed from the docstring
/// (`ParameterDoc`, ContractParser.scala:62-74).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterDoc {
    pub name: String,
    pub description: String,
}

/// Contract-template documentation extracted from the preceding `/* ... */`
/// block (`ContractDoc`, ContractParser.scala:76-99).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDoc {
    pub description: String,
    pub params: Vec<ParameterDoc>,
}

/// A single `Id : Type (= Literal)?` parameter (`ContractParam`,
/// ContractParser.scala:107-113). `default` holds the parsed literal expression
/// (Scala keeps the wrapped value; we keep the literal AST and derive the wire
/// value at assembly time via `emit::map_const`).
#[derive(Debug, Clone, PartialEq)]
pub struct ContractParam {
    pub name: String,
    pub tpe: SType,
    pub default: Option<Expr>,
}

/// `@contract def <name>(<params>)` (`ContractSignature`,
/// ContractParser.scala:115-124).
#[derive(Debug, Clone, PartialEq)]
pub struct ContractSignature {
    pub name: String,
    pub params: Vec<ContractParam>,
}

/// The full result of parsing a contract template
/// (`ParsedContractTemplate`, ContractParser.scala:126-136).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedContractTemplate {
    pub docs: ContractDoc,
    pub signature: ContractSignature,
    pub body: Expr,
}

// ── docstring token model (ContractParser.scala:11-56) ───────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum DocToken {
    Description(String),
    EmptyLine,
    Param { name: String, body: String },
    Return,
    UnsupportedTag,
}

// ── whitespace / literal scan helpers ────────────────────────────────────────

/// Skip `WL` — `(WSChars | Comment | Newline).rep` (Literals.scala:45-48):
/// spaces, tabs, newlines, `/* ... */` (nesting-capable) and `// ...` line
/// comments. Returns the new byte offset.
fn skip_wl(s: &[u8], mut i: usize) -> usize {
    loop {
        let start = i;
        while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        // block comment `/* ... */` (MultilineComment, Literals.scala:83 — the
        // reference nests via `~/ CommentChunk.rep`; we track depth).
        if i + 1 < s.len() && s[i] == b'/' && s[i + 1] == b'*' {
            let mut depth = 1usize;
            i += 2;
            while i < s.len() && depth > 0 {
                if i + 1 < s.len() && s[i] == b'/' && s[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if i + 1 < s.len() && s[i] == b'*' && s[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if i + 1 < s.len() && s[i] == b'/' && s[i + 1] == b'/' {
            // line comment (Literals.scala:85) — to end of line.
            i += 2;
            while i < s.len() && s[i] != b'\n' {
                i += 1;
            }
        }
        if i == start {
            return i;
        }
    }
}

/// Scan a PLAIN identifier (`Identifiers.Id` plain form) starting at `i`,
/// reusing the core lexer's char classes. Returns `(name, next_index)`.
fn scan_id(src: &str, i: usize) -> Option<(String, usize)> {
    let bytes = src.as_bytes();
    let first = src[i..].chars().next()?;
    if !is_id_start(first) {
        return None;
    }
    let mut end = i + first.len_utf8();
    while let Some(c) = src[end..].chars().next() {
        if is_id_char(c) {
            end += c.len_utf8();
        } else {
            break;
        }
    }
    let _ = bytes;
    Some((src[i..end].to_string(), end))
}

fn syntax(pos: usize, expected: &str) -> ParseError {
    ParseError::Syntax {
        pos: pos as Pos,
        expected: expected.to_string(),
    }
}

// ── docstring parsing (ContractParser.Docs, ContractParser.scala:145-173) ─────

/// Parse the inner text of the `/* ... */` block into `ContractDoc`.
///
/// Mirrors the docLine model: each line, after its `linePrefix` (`WL.? ~ "*" ~
/// " ".rep.? ~ !"/"`), is an `emptyLine | description | tag ~ Basic.Newline`;
/// `ContractDoc.apply` (ContractParser.scala:78-99) then drops leading empty
/// lines, takes the leading run of descriptions as the top-level description,
/// and folds `@param` tags (plus their continuation lines) into `ParameterDoc`s.
///
/// Returns `Err(offset)` when a line cannot form a valid `docLine` — the two
/// grammar-level reject surfaces the reference has here:
/// (1) a NON-blank line with no `*` prefix (`linePrefix` fails and it is not the
///     `*/` terminator, so `docLine.rep` stops mid-block and `Docs.parse` fails);
/// (2) a `@returns` tag with ANY trailing text — `returnTag = P("@returns")`
///     consumes only the bare literal, so the following `~ Basic.Newline` fails
///     (oracle: a `@returns a sigma proposition` line → `REJECT ParserException`).
fn parse_doc_inner(inner: &str, base: usize) -> Result<ContractDoc, usize> {
    let mut tokens: Vec<DocToken> = Vec::new();
    let mut line_off = base;
    for raw_line in inner.split('\n') {
        let this_off = line_off;
        line_off += raw_line.len() + 1; // + '\n'
                                        // linePrefix: optional leading whitespace, then `*`.
        let trimmed = raw_line.trim_start_matches([' ', '\t', '\r']);
        let Some(after_star) = trimmed.strip_prefix('*') else {
            // No `*` prefix: a blank/whitespace-only line is absorbed by the next
            // linePrefix's `WL.?`; a non-blank one has no valid docLine (reject).
            if trimmed.is_empty() {
                continue;
            }
            return Err(this_off);
        };
        // `" ".rep.? ~ !"/"`: consume spaces after the star; a `/` here is the
        // `!"/"` reject (never a content line — the terminator was excised).
        let content = after_star.trim_start_matches(' ');
        if content.starts_with('/') {
            return Err(this_off);
        }
        let content = content.trim_end_matches('\r');
        if content.is_empty() {
            tokens.push(DocToken::EmptyLine);
        } else if let Some(rest) = content.strip_prefix('@') {
            tokens.push(classify_tag(rest, this_off)?);
        } else {
            // description = `!"@" ~ charUntilNewLine.!`
            tokens.push(DocToken::Description(content.to_string()));
        }
    }
    Ok(assemble_doc(&tokens))
}

/// Classify an `@...` line body (`content` is the text AFTER the `@`, trailing
/// `\r` already stripped). Order mirrors `tag = returnTag | paramTag |
/// unsupportedTag` (ContractParser.scala:167).
fn classify_tag(rest: &str, off: usize) -> Result<DocToken, usize> {
    // returnTag = P("@returns") — a raw-string prefix match. The reference then
    // requires `~ Basic.Newline`, so the ONLY valid `@returns` line is the bare
    // literal; any trailing text (even a space) makes the docLine reject.
    if rest.starts_with("returns") {
        if rest == "returns" {
            return Ok(DocToken::Return);
        }
        return Err(off);
    }
    // paramTag = `"@param" ~ WL ~ word.! ~ WL ~ charUntilNewLine.!` where
    // word = CharsWhile(_ != ' '): whitespace, a non-empty name, whitespace,
    // then a non-empty body. A malformed `@param` falls through to
    // unsupportedTag (which absorbs the whole line — not a reject).
    if let Some(after) = rest.strip_prefix("param") {
        let stripped = after.trim_start_matches([' ', '\t']);
        if stripped.len() < after.len() {
            let mut it = stripped.splitn(2, ' ');
            if let Some(name) = it.next().filter(|n| !n.is_empty()) {
                let body = it.next().unwrap_or("").trim_start_matches(' ');
                if !body.is_empty() {
                    return Ok(DocToken::Param {
                        name: name.to_string(),
                        body: body.to_string(),
                    });
                }
            }
        }
    }
    // Anything else starting with `@` → UnsupportedTag (`"@" ~ charUntilNewLine.?`
    // consumes the whole line; silently absorbed).
    Ok(DocToken::UnsupportedTag)
}

/// `ContractDoc.apply` (ContractParser.scala:78-99).
fn assemble_doc(tokens: &[DocToken]) -> ContractDoc {
    // dropWhile(_ == EmptyLine)
    let start = tokens
        .iter()
        .position(|t| !matches!(t, DocToken::EmptyLine))
        .unwrap_or(tokens.len());
    let rest = &tokens[start..];
    // span(_ == Description) → leading description run.
    let split = rest
        .iter()
        .position(|t| !matches!(t, DocToken::Description(_)))
        .unwrap_or(rest.len());
    let (desc_tokens, param_tokens) = rest.split_at(split);
    let description = desc_tokens
        .iter()
        .filter_map(|t| match t {
            DocToken::Description(b) => Some(b.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ");
    ContractDoc {
        description,
        params: extract_param_docs(param_tokens),
    }
}

/// `extractParamDocs` (ContractParser.scala:85-94): fold each `@param` plus any
/// following `Description` continuation lines into one `ParameterDoc`.
fn extract_param_docs(mut tokens: &[DocToken]) -> Vec<ParameterDoc> {
    let mut out = Vec::new();
    while let Some((head, tail)) = tokens.split_first() {
        match head {
            DocToken::Param { name, body } => {
                let cont = tail
                    .iter()
                    .position(|t| !matches!(t, DocToken::Description(_)))
                    .unwrap_or(tail.len());
                let (desc_tokens, remaining) = tail.split_at(cont);
                let mut parts = vec![body.clone()];
                for t in desc_tokens {
                    if let DocToken::Description(b) = t {
                        parts.push(b.clone());
                    }
                }
                out.push(ParameterDoc {
                    name: name.clone(),
                    description: parts.join(" "),
                });
                tokens = remaining;
            }
            _ => {
                tokens = tail;
            }
        }
    }
    out
}

// ── signature parsing (ContractParser.Signature, ContractParser.scala:180-195)

/// Split a parameter list body (text INSIDE the outer parens) on the top-level
/// commas — commas nested inside `[]`/`()`/`{}` (tuple/type-arg/collection
/// syntax), OR inside a `"..."` string-literal default, do not separate
/// parameters. Scala's `param.rep(1, ",")` reads each `ExprLiteral` with the
/// real string grammar (`Literals.String`, Literals.scala:149-156, `\"`-escape
/// aware), so a `,` inside a string literal is consumed as content, not a
/// separator (verified: oracle ACCEPTs `@contract def f(s: String = "a,b")`).
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut str_scan = StrScan::new();
    let mut parts = Vec::new();
    let mut last = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if str_scan.step(b) {
            continue; // inside a string literal (or the char that opened/closed it)
        }
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&s[last..i]);
                last = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[last..]);
    parts
}

/// Minimal `"..."` string-literal tracker for the parameter-list scanners
/// (splitter + closing-`)` matcher). Mirrors the reject-side of Scala's
/// `Literals.String` (Literals.scala:140-156): a `"` opens a literal, `\`
/// escapes the next byte (so `\"` does NOT close), and an unescaped `"` closes
/// it. This makes `,`/`)` inside a string-literal default non-structural, exactly
/// as fastparse's `param.rep(1, ",")` and `"(" ~ ... ~ ")"` treat them.
///
/// Byte-level scanning is safe: every delimiter it cares about (`"`, `\`, and
/// the paren/comma bytes at the call sites) is ASCII, and UTF-8 continuation
/// bytes are all >= 0x80, so they never alias one.
struct StrScan {
    in_str: bool,
    escaped: bool,
}

impl StrScan {
    fn new() -> Self {
        StrScan {
            in_str: false,
            escaped: false,
        }
    }

    /// Feed one byte; returns `true` iff this byte is part of a string literal
    /// (including its opening/closing quote) and must NOT be read as structural.
    fn step(&mut self, b: u8) -> bool {
        if self.in_str {
            if self.escaped {
                self.escaped = false;
            } else if b == b'\\' {
                self.escaped = true;
            } else if b == b'"' {
                self.in_str = false;
            }
            true
        } else if b == b'"' {
            self.in_str = true;
            true
        } else {
            false
        }
    }
}

/// Find the top-level `=` that separates a parameter's `Type` from its literal
/// default (`paramDefault = WL.? ~ "=" ~ WL.? ~ ExprLiteral`). A `=` that is part
/// of `=>` (function-type arrow) is NOT the separator. Returns the byte index of
/// the separating `=`, or `None` when the parameter has no default.
fn find_default_eq(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 => {
                // Part of `=>`? then skip (function type), else it separates.
                if bytes.get(i + 1) == Some(&b'>') {
                    i += 2;
                    continue;
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse one `Id : Type (= Literal)?` parameter. `base` is the byte offset of
/// `part` within the whole source, for error positions.
fn parse_param(part: &str, base: usize, tree_version: u8) -> Result<ContractParam, ParseError> {
    let after_ws = skip_wl(part.as_bytes(), 0);
    let (name, after_name) =
        scan_id(part, after_ws).ok_or_else(|| syntax(base + after_ws, "parameter identifier"))?;
    // `Id.! ~ ":"` (NoWhitespace): the colon follows the identifier directly.
    let colon = after_name;
    if part.as_bytes().get(colon) != Some(&b':') {
        return Err(syntax(base + colon, "':' after parameter name"));
    }
    let type_and_default = &part[colon + 1..];
    let (type_str, default) = match find_default_eq(type_and_default) {
        Some(eq) => {
            let default_str = &type_and_default[eq + 1..];
            let default_expr = parse_literal_default(default_str, tree_version)
                .map_err(|_| syntax(base + colon + 1 + eq + 1, "literal default value"))?;
            (&type_and_default[..eq], Some(default_expr))
        }
        None => (type_and_default, None),
    };
    // Shift `parse_type` positions (relative to the sliced type string) back
    // into whole-source coordinates, matching the body path's `shift_err`. The
    // type string starts at `base + colon + 1` in the source.
    let tpe = parse_type(type_str, tree_version).map_err(|e| shift_err(e, base + colon + 1))?;
    Ok(ContractParam { name, tpe, default })
}

/// `ExprLiteral` (Core.scala:55, `WL ~ Literals.Expr.Literal`) — a literal-only
/// default. We reuse the full [`crate::parse`] entry (no separate literal
/// grammar exists) and REQUIRE the result to be a literal node, mirroring
/// Scala's restriction to `Literals.Expr.Literal` (a `p: Int = 1 + 1` default is
/// rejected on both sides — recon §1b).
fn parse_literal_default(src: &str, tree_version: u8) -> Result<Expr, ParseError> {
    let e = parse(src, tree_version)?;
    if is_literal(&e) {
        Ok(e)
    } else {
        Err(syntax(
            0,
            "literal default value (non-literal defaults are not allowed)",
        ))
    }
}

fn is_literal(e: &Expr) -> bool {
    matches!(
        e,
        Expr::IntConst { .. }
            | Expr::LongConst { .. }
            | Expr::BoolConst { .. }
            | Expr::StringConst { .. }
            | Expr::UnitConst { .. }
    )
}

// ── top-level entry (ContractParser.parse, ContractParser.scala:138) ──────────

/// Parse an ErgoScript CONTRACT TEMPLATE source into a [`ParsedContractTemplate`].
///
/// Mirrors `ContractParser.parse` (ContractParser.scala:138): the mandatory
/// `/* ... */` doc block, one `Basic.Newline`, the `@contract def name(params)`
/// signature, `WL.? = WL.?`, then the raw body handed to [`crate::parse`].
pub fn parse_contract(
    source: &str,
    tree_version: u8,
) -> Result<ParsedContractTemplate, ParseError> {
    let bytes = source.as_bytes();
    // Docs.parse = `" ".rep.? ~ "/*" ~ ... ~ "*/"` — leading SPACES only.
    let mut i = 0usize;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if !(bytes.get(i) == Some(&b'/') && bytes.get(i + 1) == Some(&b'*')) {
        return Err(syntax(
            i,
            "'/*' doc block (a contract template must be documented)",
        ));
    }
    let open = i + 2;
    // First `*/` closes the block (block comments do not nest at this layer;
    // linePrefix's `!"/"` keeps content `*/` out of doc lines in practice).
    let close = source[open..]
        .find("*/")
        .map(|off| open + off)
        .ok_or_else(|| syntax(i, "closing '*/' of the doc block"))?;
    let docs = parse_doc_inner(&source[open..close], open)
        .map_err(|pos| syntax(pos, "valid docstring line (or bare '@returns')"))?;
    let mut j = close + 2;

    // `~ Basic.Newline ~` — exactly one `\n` or `\r\n` (Basic.scala:34). Trailing
    // spaces/tabs on the `*/` line precede it in real sources; the reference's
    // NoWhitespace `~` does not skip them, but accepting them is reject-side-safe
    // and matches every hand-authored template.
    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
        j += 1;
    }
    if bytes.get(j) == Some(&b'\r') {
        j += 1;
    }
    if bytes.get(j) != Some(&b'\n') {
        return Err(syntax(j, "newline after the doc block"));
    }
    j += 1;

    // Signature.parse = `annotation ~ WL.? ~ def ~ WL.? ~ Id.! ~ params`.
    j = skip_wl(bytes, j);
    let Some(rest) = source[j..].strip_prefix("@contract") else {
        return Err(syntax(j, "'@contract' annotation"));
    };
    j += "@contract".len();
    let _ = rest;
    j = skip_wl(bytes, j);
    // `def` = W("def"): "def" ~ !LetterDigitDollarUnderscore.
    if !source[j..].starts_with("def") || source[j + 3..].chars().next().is_some_and(is_id_char) {
        return Err(syntax(j, "'def'"));
    }
    j += 3;
    j = skip_wl(bytes, j);
    let (name, after_name) = scan_id(source, j).ok_or_else(|| syntax(j, "contract name"))?;
    j = after_name;
    // params = `"(" ~ param.rep(1, ",").? ~ ")"`.
    j = skip_wl(bytes, j);
    if bytes.get(j) != Some(&b'(') {
        return Err(syntax(j, "'(' of the parameter list"));
    }
    // Balanced-paren match to the closing `)` — string-literal aware, so a `)`
    // inside a `"..."` default (e.g. `s: String = ")"`) does not close the list
    // early (verified: oracle ACCEPTs it). Mirrors fastparse reading the closing
    // `)` of `params` only AFTER each param's `ExprLiteral` string is consumed.
    let params_open = j + 1;
    let mut depth = 1i32;
    let mut k = params_open;
    let mut str_scan = StrScan::new();
    while k < bytes.len() && depth > 0 {
        let b = bytes[k];
        if str_scan.step(b) {
            k += 1;
            continue;
        }
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            break;
        }
        k += 1;
    }
    if depth != 0 {
        return Err(syntax(j, "')' closing the parameter list"));
    }
    let params_close = k;
    let params_body = &source[params_open..params_close];
    let params = if params_body.trim().is_empty() {
        Vec::new()
    } else {
        let mut ps = Vec::new();
        for part in split_top_level_commas(params_body) {
            let base = params_open + (part.as_ptr() as usize - params_body.as_ptr() as usize);
            ps.push(parse_param(part, base, tree_version)?);
        }
        ps
    };

    // `WL.? ~ "=" ~ WL.? ~ AnyChar.rep(1).!`
    let mut m = skip_wl(bytes, params_close + 1);
    if bytes.get(m) != Some(&b'=') {
        return Err(syntax(m, "'=' before the contract body"));
    }
    m += 1;
    m = skip_wl(bytes, m);
    if m >= bytes.len() {
        return Err(syntax(m, "contract body"));
    }
    // Hand the remainder to the EXISTING expression parser (no duplication).
    let body = parse(&source[m..], tree_version).map_err(|e| shift_err(e, m))?;

    Ok(ParsedContractTemplate {
        docs,
        signature: ContractSignature { name, params },
        body,
    })
}

/// Shift a body-parse error's position back into whole-source coordinates.
fn shift_err(e: ParseError, base: usize) -> ParseError {
    let base = base as Pos;
    match e {
        ParseError::Syntax { pos, expected } => ParseError::Syntax {
            pos: pos + base,
            expected,
        },
        ParseError::Lexical { pos, msg } => ParseError::Lexical {
            pos: pos + base,
            msg,
        },
        ParseError::Semantic { pos, msg } => ParseError::Semantic {
            pos: pos + base,
            msg,
        },
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn pc(src: &str) -> ParsedContractTemplate {
        parse_contract(src, 3).expect("contract parses")
    }

    // ----- happy path: docstring -----

    #[test]
    fn docs_description_and_param_extracted() {
        let t = pc(
            "/**\n * A height lock.\n * @param threshold the minimum height\n */\n\
             @contract def lock(threshold: Int) = sigmaProp(HEIGHT > threshold)",
        );
        assert_eq!(t.docs.description, "A height lock.");
        assert_eq!(
            t.docs.params,
            vec![ParameterDoc {
                name: "threshold".to_string(),
                description: "the minimum height".to_string(),
            }]
        );
    }

    #[test]
    fn docs_multiline_description_joined_with_spaces() {
        // Leading run of Description tokens joins with " " (ContractDoc.apply).
        let t = pc("/**\n * first line\n * second line\n */\n\
             @contract def c() = sigmaProp(true)");
        assert_eq!(t.docs.description, "first line second line");
    }

    #[test]
    fn docs_param_continuation_line_appended() {
        // A Description token FOLLOWING a @param continues its description.
        let t = pc("/**\n * @param x the x\n * continued\n */\n\
             @contract def c(x: Int) = sigmaProp(x > 0)");
        assert_eq!(t.docs.params[0].description, "the x continued");
    }

    #[test]
    fn docs_empty_block_gives_empty_description() {
        let t = pc("/* */\n@contract def c(x: Int) = sigmaProp(x > 0)");
        assert_eq!(t.docs.description, "");
        assert!(t.docs.params.is_empty());
    }

    #[test]
    fn docs_unsupported_tag_absorbed() {
        let t = pc("/**\n * @author someone\n * @param x the x\n */\n\
             @contract def c(x: Int) = sigmaProp(x > 0)");
        assert_eq!(t.docs.description, "");
        assert_eq!(t.docs.params.len(), 1);
    }

    #[test]
    fn docs_bare_returns_is_absorbed() {
        let t = pc("/**\n * desc\n * @returns\n */\n\
             @contract def c() = sigmaProp(true)");
        assert_eq!(t.docs.description, "desc");
    }

    // ----- happy path: signature -----

    #[test]
    fn signature_name_and_params_no_defaults() {
        let t = pc("/* */\n@contract def rangeCheck(lo: Int, hi: Int) = sigmaProp(HEIGHT > lo && HEIGHT < hi)");
        assert_eq!(t.signature.name, "rangeCheck");
        let names: Vec<&str> = t.signature.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["lo", "hi"]);
        assert_eq!(t.signature.params[0].tpe, SType::SInt);
        assert!(t.signature.params.iter().all(|p| p.default.is_none()));
    }

    #[test]
    fn signature_no_params() {
        let t = pc("/* */\n@contract def bare() = sigmaProp(HEIGHT > 1)");
        assert!(t.signature.params.is_empty());
    }

    #[test]
    fn signature_literal_default_parsed() {
        let t = pc("/* */\n@contract def c(x: Int = 1000) = sigmaProp(HEIGHT > x)");
        assert!(matches!(
            t.signature.params[0].default,
            Some(Expr::IntConst { value: 1000, .. })
        ));
    }

    #[test]
    fn signature_collection_type_param() {
        // Type-arg commas must not split the parameter list.
        let t = pc("/* */\n@contract def c(xs: Coll[Int]) = sigmaProp(xs.size > 0)");
        assert_eq!(t.signature.params.len(), 1);
        assert_eq!(
            t.signature.params[0].tpe,
            SType::SColl(Box::new(SType::SInt))
        );
    }

    // ----- error paths -----

    #[test]
    fn missing_doc_block_rejects() {
        let err = parse_contract("@contract def c() = sigmaProp(true)", 3).unwrap_err();
        assert!(matches!(err, ParseError::Syntax { .. }));
    }

    #[test]
    fn missing_annotation_rejects() {
        let err = parse_contract("/* */\ndef c() = sigmaProp(true)", 3).unwrap_err();
        assert!(matches!(err, ParseError::Syntax { .. }));
    }

    #[test]
    fn returns_with_trailing_text_rejects() {
        // returnTag = P("@returns") consumes only the literal; trailing text
        // fails the docLine `~ Basic.Newline` (oracle REJECT ParserException).
        let err = parse_contract(
            "/**\n * @returns a proposition\n */\n@contract def c() = sigmaProp(true)",
            3,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::Syntax { .. }));
    }

    #[test]
    fn non_literal_default_rejects() {
        let err = parse_contract(
            "/* */\n@contract def c(x: Int = 1 + 1) = sigmaProp(HEIGHT > x)",
            3,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::Syntax { .. }));
    }

    #[test]
    fn body_syntax_error_propagates_with_shifted_position() {
        // A malformed body surfaces as a ParseError (not an uncategorised
        // throw), with a position inside the body region.
        let err = parse_contract("/* */\n@contract def c() = )(", 3).unwrap_err();
        assert!(matches!(err, ParseError::Syntax { .. }));
        assert!(err.pos() as usize >= "/* */\n@contract def c() = ".len());
    }

    // ----- string-literal default delimiters (M7 finding 1) -----

    #[test]
    fn signature_string_default_with_comma_parses() {
        // A `,` inside a string-literal default is NOT a parameter separator —
        // Scala reads each `ExprLiteral` with the real string grammar
        // (Literals.String), so the comma is string content (oracle ACCEPTs).
        let t = pc("/* */\n@contract def c(s: String = \"a,b\") = sigmaProp(true)");
        assert_eq!(t.signature.params.len(), 1);
        assert_eq!(t.signature.params[0].tpe, SType::SString);
        assert!(matches!(
            &t.signature.params[0].default,
            Some(Expr::StringConst { value, .. }) if value == "a,b"
        ));
    }

    #[test]
    fn signature_string_default_with_close_paren_parses() {
        // A `)` inside a string default must not close the parameter list early.
        let t = pc("/* */\n@contract def c(s: String = \")\") = sigmaProp(true)");
        assert_eq!(t.signature.params.len(), 1);
        assert!(matches!(
            &t.signature.params[0].default,
            Some(Expr::StringConst { value, .. }) if value == ")"
        ));
    }

    #[test]
    fn signature_string_default_with_escaped_quote_parses() {
        // `\"` inside the string does not terminate it. Scala's `strip` removes
        // only the outer quotes, leaving the raw two-char `\"` content (verified
        // byte-exact against the ct oracle: constValue bytes 02 5c 22).
        let t = pc("/* */\n@contract def c(s: String = \"\\\"\") = sigmaProp(true)");
        assert_eq!(t.signature.params.len(), 1);
        assert!(matches!(
            &t.signature.params[0].default,
            Some(Expr::StringConst { value, .. }) if value == "\\\""
        ));
    }

    #[test]
    fn signature_multi_param_string_delimiters_dont_split() {
        // A middle string default carrying both `,` and `)` must not corrupt the
        // top-level comma split nor the closing-paren match.
        let t = pc(
            "/* */\n@contract def c(a: Int = 1, s: String = \"x,y)\", b: Int = 2) \
             = sigmaProp(HEIGHT > a && HEIGHT > b)",
        );
        let names: Vec<&str> = t.signature.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a", "s", "b"]);
        assert!(matches!(
            &t.signature.params[1].default,
            Some(Expr::StringConst { value, .. }) if value == "x,y)"
        ));
    }

    #[test]
    fn param_type_error_position_is_source_relative() {
        // Param-type parse errors shift into whole-source coordinates (like the
        // body path), not the sliced type-string offset. The type is
        // bracket-balanced (so the paren-matcher is not what fails) but not a
        // valid type, so `parse_type` rejects INSIDE the type region.
        let source = "/* */\n@contract def c(x: Int Int) = sigmaProp(true)";
        let err = parse_contract(source, 3).unwrap_err();
        assert!(matches!(err, ParseError::Syntax { .. }));
        // The error lands on the trailing `Int` INSIDE the type region — an
        // unshifted (slice-relative) offset would be ~5, well before it.
        let type_at = source.find("Int").expect("type present");
        assert!(
            err.pos() as usize >= type_at,
            "param-type error pos {} should be >= type position {type_at}",
            err.pos()
        );
    }
}
