//! ErgoScript → ErgoTree compiler.
//!
//! M1 scope: source text → untyped AST, faithful to the Scala reference parser
//! (`sigmastate.lang.SigmaParser`, sigma-state 6.0.2): same accept/reject
//! decisions, same AST shapes, same error positions. Design:
//! `dev-docs/ergoscript-compiler-design.md`. Every grammar decision in this
//! crate cites the mirrored Scala source as `file:line` under
//! `sigmastate-interpreter`.
//!
//! NOT a consensus surface: a compiler bug yields a wrong tree/address, never
//! a fork — but a wrong address strands funds, so correctness is held to the
//! oracle-parity bar anyway.
//!
//! # Usage
//!
//! ```
//! use ergo_compiler::{parse, parse_type, Expr, SType};
//!
//! // Parse a simple ErgoScript expression (tree_version=0 → v5 semantics).
//! // `+` is a method call in the reference grammar (SigmaParser.scala:96).
//! let ast = parse("1 + 2", 0).unwrap();
//! assert!(matches!(ast, Expr::MethodCallLike { .. }));
//!
//! // Parse a type annotation.
//! let ty = parse_type("Coll[Int]", 0).unwrap();
//! assert_eq!(ty, SType::SColl(Box::new(SType::SInt)));
//! ```
//!
//! ## Known M1 deviations from the Scala reference
//!
//! All deviations are bounded to either pathological/malformed input that no
//! real contract contains or to deliberate M1 scoping decisions. The corpus
//! (67 accepted / 12 rejected real contracts) serves as the regression oracle
//! for each.
//!
//! - **D6 — `${…}` interpolation block rejected** (`token.rs`): the reference's
//!   `${ Block }` string-interpolation form is rejected with a lexical error rather
//!   than parsing the embedded expression. Scope decision: no real contract uses it
//!   and M1 does not need an expression evaluator inside string literals.
//!
//! - **Sm/So Unicode op-chars deferred** (`token.rs`): the full Unicode Sm/So
//!   general-category op-char set is not checked (Rust std lacks a category
//!   predicate). The ASCII operator set is exact and the single non-ASCII op-char
//!   used in real contracts — `⇒` (U+21D2, `Core.scala:23`) — is included. `⇒` is
//!   an op-char but NOT a reserved symbolic keyword: it lexes as an `OpId` and is
//!   the arrow only in keyword position (`Cursor::at_sym_kw`). Any OTHER Unicode
//!   op-char is mis-tokenized; a knock-on is that a So/Sm code point used as an
//!   identifier tail (e.g. `xⒶ`, U+24B6) — which the JVM lexes as a separate
//!   op-token, still ACCEPT — is folded into one identifier here (same ACCEPT), and
//!   a So/Sm code point in a `'c'` char literal REJECTS one column early. The corpus
//!   oracle catches any accept/reject counterexample.
//!
//! - **id-start/tail Unicode classes** (`token.rs`): both `is_id_start` and
//!   identifier-interior chars (`is_id_char`) are BMP-gated — supplementary code
//!   points (> U+FFFF) reach fastparse as surrogate halves of category `Cs`, which
//!   are never `isUpperCase`/`isLowerCase`/`isLetter`/`isDigit`, so they are
//!   rejected at both id-start and id-tail positions. Id-tail uses the exact JVM
//!   `Character.isLetter` (`Lu|Ll|Lt|Lm|Lo`) and `Character.isDigit` (`Nd`) masks
//!   (`Identifiers.scala:41-43`), reconstructed by narrowing Rust's wider
//!   `char::is_alphabetic`/`is_numeric` with the `ALPHA_NOT_LETTER`/`ND` UCD range
//!   tables. Exact except that 60 BMP code points Rust marks `is_alphabetic` but
//!   the JVM does not treat as letters — 52 `So` (e.g. circled letters U+24B6) plus
//!   8 `Cn` version-skew points — are still accepted as id-tail chars; the `So`
//!   cases are JVM op-chars that form a separate token, so the whole-input
//!   ACCEPT/REJECT verdict is unchanged. Numeric literals use ASCII-only
//!   `is_ascii_digit` (exact).
//!
//! - **`is_printable_char` — supplementary scalars BMP-gated, SPECIALS excluded,
//!   null-block deferred** (`token.rs`): the `'c'`-form char literal vs `'sym`
//!   symbol disambiguation matches fastparse `isPrintableChar`:
//!   `!isISOControl` (= `char::is_control`), `!isSurrogate` (reproduced via BMP
//!   gate `(c as u32) <= 0xFFFF` — Rust `char` can't be a surrogate but CAN be a
//!   supplementary scalar that the JVM sees as surrogate halves), and the SPECIALS
//!   block (U+FFF0..=U+FFFF, excluded). The `block == null` clause (unassigned
//!   no-block code points) is not reproduced — it affects only char literals over
//!   such points, which no real contract uses.
//!
//! - **op-id string prefixes not merged** (`token.rs`): for an operator-id
//!   immediately before a string literal (e.g. `*"foo"`), the reference merges
//!   them into one interpolated `SString` token. M1 emits `[OpId, Str]` and the
//!   parser will reject. An accept/reject divergence only on pathological input
//!   (`-`/`+`/`!`/`~` prefixes are handled correctly via the expression grammar).
//!
//! - **D4 — integer overflow parity** (`token.rs`): positive magnitudes above
//!   `i32::MAX` / `i64::MAX` are rejected at lex time (`ParseError::Lexical`),
//!   matching the Scala reference which rejects them via
//!   `NumberFormatException`/`MatchError`. Both sides REJECT; the error class
//!   differs. The practical consequence is that `-2147483648` is rejected (as in
//!   Scala: the positive magnitude overflows before the sign is applied).
//!
//! - **D5 — block-lambda head at a non-first chunk** (`parse.rs`): a `BlockLambda`
//!   head at any `Body` chunk start — a consecutive head (`{ (a,b)=>(c,d)=>e }`) or
//!   a head in a later chunk after a newline gap / `;`-separated empty chunk
//!   (`{ val x=1\n(x,y)=>x }`, `{ (x)=>; (a,b)=>c }`) — is a `scala.MatchError` crash
//!   in the reference (a position-less `REJECT 0:0`); M1 returns `ParseError::Semantic`
//!   pinned to the head. Both sides REJECT; the error class AND the reject position
//!   (head vs `0:0`) differ. Bounded to block-lambda heads mid-block that no real
//!   contract produces (corpus-verified). A head after a `;` that CONTINUES a
//!   non-empty chunk is an expression lambda, not a head, and is unaffected.
//!
//! - **`|`-separated pattern with a `|`-prefixed op-id** (`parse.rs`): in an
//!   extractor `TupleEx` element, a `Pattern` alternative separator is the literal
//!   char `|`, but the lexer folds a `|`-led operator run (`|:`) into one `OpId`.
//!   So `Some(x |: T)` reports the reject one column early (at the `|:` token, not
//!   inside it). Reject-parity holds; position-only, and only on mid-pattern junk no
//!   real contract contains.
//!
//! - **`line_col` past-end and empty-last-line quirks** (`span.rs`): two
//!   minor deviations from `SourceContext.scala` arithmetic: byte positions
//!   past the string end are added 1-for-1 (unreachable for non-ASCII inputs),
//!   and the empty-last-line fallback col is clamped to `0` instead of `-1`
//!   (matches the `u32` return type). Neither affects error positions for any
//!   real contract.
//!
//! - **`take_one_semi` else-separator edge** (`parse.rs`): the input
//!   `if (c) t\n;else e` — Scala's `Semi.?` (Basic.scala:35, Literals.scala:50)
//!   consumes the newline-run as the single Semi and the residual `;` blocks
//!   `else` (reject). Our transparent-newline `take_one_semi` skips the newlines
//!   and consumes the `;` directly (accept). Accept-divergence on a pathological
//!   newline+semicolon separator mix that no real contract produces.
//!
//! - **Nested empty-block reject position** (`parse.rs`): both sides REJECT a bare
//!   empty block, but on the doubly-nested `{{}}` the reference's furthest-failure
//!   reports `1:5` (past the outer `}`) while our recursive descent fails at the
//!   inner empty block (`1:4`, one past the inner `}`). Position-only, reject-parity
//!   holds; bounded to nested bare empty blocks no real contract produces.
//!
//! - **Stray-brace block absurdity rejected** (`parse.rs`): SigmaParser ACCEPTS the
//!   malformed inputs `{ } a }` (block with result `a`) and `{}/}` (block with
//!   result `/`) — a genuine reference-parser misbehavior where a stray closing `}`
//!   after an empty-looking `{}` still yields a valid block. M1 rejects both at the
//!   first `}` (the bare-empty-block reject). This is a DELIBERATE non-reproduction:
//!   for a compiler frontend the safe direction is rejecting malformed input — a
//!   wrong-accept would emit a bogus tree/address downstream (funds risk), whereas a
//!   wrong-reject only surfaces a user error. Reject-side divergence only, bounded to
//!   garbage no real contract contains. oracle: `parse("{ } a }")` / `parse("{}/}")`
//!   ACCEPT (sic), sigma-state 6.0.2; pinned by
//!   `r6_stray_brace_block_absurdity_is_deliberately_rejected`.

pub mod ast;
pub mod error;
mod parse;
pub mod span;
pub mod stype;
pub mod token;

pub use ast::{ArithKind, BitKind, Expr, RelKind, ValDef};
pub use error::ParseError;
pub use parse::{parse, parse_type};
pub use stype::SType;
