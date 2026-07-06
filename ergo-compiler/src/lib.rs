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
//!   op-char is mis-tokenized; a knock-on is that a So/Sm code point in a `'c'`
//!   char literal REJECTS one column early. **So chars that are also
//!   `Other_Alphabetic` (the 52 circled Latin letters U+24B6–24E9)** are now
//!   correctly excluded from `ALPHA_NOT_LETTER` so the identifier ENDS before
//!   them. Since our op-char set is ASCII-only, the circled letter is then an
//!   unrecognised character → lex error → REJECT. Scala ends the identifier the
//!   same way but can form an So operator token, so `xⒶ` and `xⒶy` are ACCEPT in
//!   Scala and REJECT here (reject-side divergence; no legitimate contract uses
//!   circled letters as operators). `xⒶ+1` REJECTs on both sides (verdict parity).
//!   The corpus oracle catches any remaining accept/reject counterexample.
//!
//! - **id-start/tail Unicode classes** (`token.rs`): both `is_id_start` and
//!   identifier-interior chars (`is_id_char`) are BMP-gated — supplementary code
//!   points (> U+FFFF) reach fastparse as surrogate halves of category `Cs`, which
//!   are never `isUpperCase`/`isLowerCase`/`isLetter`/`isDigit`, so they are
//!   rejected at both id-start and id-tail positions. Id-tail uses the exact JVM
//!   `Character.isLetter` (`Lu|Ll|Lt|Lm|Lo`) and `Character.isDigit` (`Nd`) masks
//!   (`Identifiers.scala:41-43`), reconstructed by narrowing Rust's wider
//!   `char::is_alphabetic`/`is_numeric` with the `ALPHA_NOT_LETTER`/`ND` UCD range
//!   tables. Exact except that 8 `Cn` version-skew BMP code points Rust marks
//!   `is_alphabetic` but the JVM does not treat as letters — these are still
//!   accepted as id-tail chars (unassigned, no real contract uses them). The 52
//!   `So` circled letters (U+24B6–24E9) that were previously in this residual are
//!   now correctly excluded by `ALPHA_NOT_LETTER` (round 11 fix). Numeric literals
//!   use ASCII-only `is_ascii_digit` (exact).
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
//!
//! - **Lone `\r` in the inter-token gap rejected** (`token.rs`): a bare carriage
//!   return not followed by `\n` (outside strings/comments) is refused with a
//!   `ParseError::Lexical` at the `\r`. In fastparse it is neither `Basic.WSChars`
//!   (space/tab only) nor `Basic.Newline` (`\r\n`|`\n` only): the implicit
//!   `ScalaWhitespace` swallows it at `~` junctions, yet it is invisible to every
//!   explicit `WS`/`WL`/`Newline`/`Semi`/`OneNLMax` combinator and a wall at raw
//!   `~~` junctions. So it behaves like a SPACE at some junctions and like a
//!   NEWLINE at others, with no token-stream signal that reproduces both. Full
//!   Round-10 oracle matrix (ParserOracle sigma-state 6.0.2, `⇒` = U+21D2) —
//!   ACCEPT cells: `\r1` · `1\r` · `a\rb` · `(x,y)\r=>x` · `{ val x = 1\r x }` ·
//!   `{ val x = 1\rx }` · `f(\r)` · `f(1,\r2)` · `if (true) 1\relse 2` · `x.\ry` ·
//!   `{1\r}`; REJECT cells: `1\r+2` (1:1) · `1\r2` (2:1) · `1 \r 2` (2:2) ·
//!   `1\r\r2` (3:1) · `(x,y)\r⇒x` (1:1) · `{ val x = 1\r val y = 2; y }` (1:11).
//!   (Contrast the LF twins — `a\nb` REJECT, `(x,y)\n⇒x` ACCEPT — confirming `\r`
//!   is NOT a newline; and `1 +2` ACCEPT vs `1\r+2` REJECT — confirming it is NOT
//!   a space either.) Reproducing every cell would need an infix-blocking-but-not-
//!   newline gap token threaded through the whole expression parser plus
//!   fastparse furthest-failure positions that even contradict `span::line_col`
//!   (Scala `getLines`, where a lone `\r` is no line boundary). Bare-CR sources are
//!   illegitimate and NO corpus contract holds a single `\r` byte, so we take the
//!   reject-side-safe route: refuse the gap `\r`. This matches Scala on every
//!   REJECT cell (verdict; the position is reported at the `\r`) and cannot cause a
//!   wrong-bytes accept — a wrong-accept would emit a bogus tree/address downstream
//!   (funds risk), whereas the residual is only a reject-side divergence on the
//!   ACCEPT cells. UNTOUCHED: `\r\n` (one Newline) and a `\r` inside line-comment
//!   content (`// c\r more` ACCEPT) or a string literal (`"a\rb"` ACCEPT), which the
//!   comment/string lexers consume as content. Pinned by
//!   `lone_cr_in_gap_is_lexical_error_at_the_cr` and
//!   `crlf_is_still_one_newline_and_cr_in_comment_or_string_is_content`.

//! # M2: Binder + Typer
//!
//! The M2 pipeline:
//! - **parse** (`parse.rs`, `token.rs`) → untyped `Expr` AST (same oracle bar as M1)
//! - **bind** (`binder.rs`) → converts `Expr` → `TypedExpr` with `NoType` placeholders,
//!   substitutes env constants, desugars predefined functions (Rules 1–11 from
//!   `SigmaBinder.scala`), runs a single bottom-up pass (fixpoint-equivalent for
//!   these rules — documented in `binder.rs`)
//! - **typecheck** (`typer/`) → assigns concrete `SType` to every node via
//!   `assign_type` dispatch (port of `SigmaTyper.assignType`, 6.0.2)
//!
//! Entry point: [`typecheck`] / [`typecheck_with_network`] (public API, E9).
//!
//! ## Oracle stack
//!
//! The typer is graded by a live JVM oracle pinned to sigma-state 6.0.2:
//! - **Parser oracle** (`scripts/jvm_parser_oracle/`) — M1 accept/reject parity
//! - **Typer oracle** (`scripts/jvm_typer_oracle/TyperOracle.scala`) — typed s-expression
//!   from `SigmaCompiler.typecheck` with `lowerMethodCalls=true`,
//!   `TransformingSigmaBuilder`
//! - **tc1.sh** — fresh-JVM mode for position grading (avoids singleton contamination;
//!   see R1 in `dev-docs/m2-recon/m2-oracle.md`)
//! - **Golden seed** (`test-vectors/ergoscript/typer/golden_seed.txt`) — every committed
//!   record is swept in full by `typer_oracle_parity` (the seed file is the record count
//!   of record; a hardcoded number here rots as sections are added)
//! - **Corpus verdicts** (`test-vectors/ergoscript/typer/corpus_verdicts.json`) — 79-contract
//!   JVM verdicts; swept by `typer_oracle_parity::corpus_typed_verdict_parity`
//!
//! ## Binding decisions (E-digest)
//!
//! - **E1 (lenient Block rule):** The `Val`'s explicit type annotation is DISCARDED in
//!   v6.0.2 (`SigmaTyper.scala:53-66` at the v6.0.2 tag). `{ val x: Long = 1; x }`
//!   accepts with `x: SInt`. The `isAssignableTo`/`getResultType` strict-check is a
//!   post-6.0.2 commit and is NOT implemented here; oracle-confirmed (golden seed §11).
//! - **E5 (oracle grading):** `ACCEPT` records grade s-expression byte equality; `REJECT`
//!   records grade verdict + exception CLASS (advisory). Reject `line:col` is graded only
//!   in fresh-JVM mode (`tc1.sh`) — batch mode contaminates singleton positions (R1).
//! - **E12 (positions):** `TypedExpr` carries no source positions. Every [`TyperError`]
//!   has `pos ≡ 0`. `Parse`/`Bind` errors DO carry positions — the typer is the sole
//!   documented phase-level position gap (see D-T7 below). The 50 `typefail(env, x,
//!   line, col)` assertions from `SigmaTyperTest.scala` port as class+verdict-only; each
//!   original `(line, col)` is preserved in a comment in
//!   `tests/sigma_typer_spec.rs` for a future position pass.
//!
//! ## M3 handoff notes
//!
//! - **SWEEP_SKIP rendering worklist — DONE (M3).** The D-T4/D-T6 fix emptied
//!   `SWEEP_SKIP` in `tests/typer_oracle_parity.rs`; it remains as the mechanism
//!   for any future rendering-only deviation (reject-side divergences live in
//!   the separate `VERDICT_DEVIATION_SOURCES` list).
//! - **fromBase58/fromBase64 canonical decode — DONE (M3 Task-5, D-T2).** Valid
//!   literals now fold to `ByteArrayConstant`; see the consolidated ledger entry
//!   below for the engine-config rationale.
//! - **`deserialize` deferred, re-scoped (D-T2):** `predef_ir_builder` returns
//!   `None` for `deserialize` unconditionally. Scala constant-folds
//!   `deserialize(lit)` at typecheck time; closing this requires an
//!   opcode-IR→`TypedExpr` reverse mapping, deferred past emit (M3 plan Task 12
//!   decision).
//! - **unsignedBigInt canonical constant + bigInt canonicalization — DONE
//!   (M3 Task-6, D-T3).** `ConstPayload::UnsignedBigInt(String)` added;
//!   `bigInt`/`unsignedBigInt` canonicalize leading zeros and enforce the
//!   Scala range caps (255 bits, `tree_version >= 3`-gated, for `BigInt`;
//!   256 bits, unconditional, for `UnsignedBigInt`). See the consolidated
//!   ledger entry below.
//! - **Network-per-contract (M3 byte vectors):** The JVM oracle defaults to
//!   `ORACLE_NETWORK=testnet`. When adding golden-seed records for `PK(...)`, run the
//!   oracle with the matching network env var and record the network in the seed comment.
//!   M3 byte-vector work must account for the network prefix embedded in P2PK addresses.
//!
//! # Known M2 deviations (typer layer)
//!
//! These are bounded gaps between the M2 ErgoScript typer/binder and the Scala reference
//! (`SigmaTyper.scala` / `SigmaBinder.scala`, sigma-state 6.0.2) captured from oracle
//! probes and code review. M3 closes them unless noted as inert. All entries here are
//! oracle-grounded or explicitly bounded.
//!
//! ## Consolidated ledger
//!
//! ### D-T1 — id-narrowing class-tag (ArithmeticException vs TyperError)
//!
//! Scala's `SByte.downcast` / `SShort.downcast` (= `toByteExact` / `toShortExact`,
//! `SType.scala:409,433`) throw `java.lang.ArithmeticException` when a `getVar`,
//! `executeFromVar`, or `getVarFromInput` id constant overflows `Byte`/`Short`.
//! Oracle: `getVar[Int](200)` → `REJECT 0:0 ArithmeticException`; same for
//! `executeFromVar[Int](300)` and `getVarFromInput[Int](70000, 1)`.
//! We route through `const_downcast` and return a `TyperError` — REJECT verdict
//! matches, error class differs. Bounded to out-of-range literal ids which no
//! real contract uses.
//!
//! ### D-T2 — fromBase58/fromBase64 canonical decode — CLOSED (M3 Task-5); deserialize re-scoped
//!
//! **`fromBase58` / `fromBase64` — CLOSED.** Both character-class AND structural
//! padding validation are implemented in `predef_ir_builder` and match Scala's
//! verdicts. Invalid characters cause a `TyperError`; for Base64, padded strings
//! whose total length is not a multiple of 4 are also rejected (oracle-confirmed
//! 2026-07-04: `fromBase64("a=")` and `fromBase64("abcde=")` REJECT). A VALID
//! literal now decodes canonically to `TypedExpr::Constant { value:
//! ConstPayload::ByteColl(..), tpe: SColl(SByte) }` (`decode_base58` /
//! `decode_base64`, `predef_ir.rs`): `fromBase58` via `bs58::decode` (Bitcoin
//! alphabet, byte-identical to Scorex); `fromBase64` via a dedicated
//! `JAVA_BASE64` engine (`base64` crate, standard alphabet,
//! `DecodePaddingMode::Indifferent` + `decode_allow_trailing_bits(true)`) —
//! chosen because the crate's default `STANDARD` engine requires canonical
//! padding and would wrongly reject unpadded input (`fromBase64("ab")` →
//! `OK (ConstantNode:Coll[Byte] <@105>)`, dropping the last quantum's dangling
//! low bits exactly as `java.util.Base64.getDecoder()` does). Scala throws
//! `AssertionError` (Base58) or `IllegalArgumentException` (Base64) on invalid
//! input — both non-reproducible oracle classes, so class parity is not
//! asserted; verdict parity holds. Golden-seed §17 (`golden_seed.txt`) commits
//! byte-exact ACCEPT records for `fromBase58("")`, `fromBase64("")`,
//! `fromBase64("YWJj")`, `fromBase64("ab")`.
//!
//! **`deserialize` — remains deferred, re-scoped.** `predef_ir_builder` returns
//! `None` unconditionally. Scala constant-folds `deserialize(lit)` at type-check
//! time and throws on undeserializable bytes; we accept the `Apply` unlowered
//! (accept-invalid deviation, bounded to malformed literals no real contract
//! uses). Unlike `fromBase58`/`fromBase64`, closing this requires an
//! opcode-IR→`TypedExpr` reverse mapping (`ValueSerializer` decodes to
//! sigma-state's own AST representation, not ours) — deferred past emit (see
//! M3 plan Task 12 decision).
//!
//! ### D-T3 — unsignedBigInt canonical constant + bigInt literal canonicalization — CLOSED (M3 Task-6)
//!
//! `unsignedBigInt(s)` for a valid non-negative decimal now builds the dedicated
//! `ConstPayload::UnsignedBigInt(String)` constant (`predef_ir.rs`
//! `parse_unsigned_big_int`). Negative literals are still rejected (class
//! deviation retained: oracle `InvalidArguments`, ours `TyperException` — see
//! `CLASS_DEVIATION_SOURCES` in `tests/typer_oracle_parity.rs`). Oracle:
//! `unsignedBigInt("5")` → `OK (ConstantNode:UnsignedBigInt (CUnsignedBigInt
//! @5))` (golden_seed.txt §13/§24).
//!
//! **Canonicalization** (oracle-verified, golden_seed.txt §24(a)): both
//! `bigInt` and `unsignedBigInt` strip leading zeros — `bigInt("0005")` /
//! `unsignedBigInt("0005")` both print `@5`, not `@0005`. Parsed with
//! `num_bigint::BigInt`/`BigUint` and stored via `.to_string()`.
//!
//! **Range caps** (§24(c)): `UnsignedBigInt` caps at 256 bits
//! UNCONDITIONALLY (`CUnsignedBigInt.scala:20-22`, no `VersionContext` check);
//! `BigInt` caps at 255 bits ONLY at `tree_version >= 3`
//! (`CBigInt.scala:18-20`, `isV3OrLaterErgoTreeVersion`) — pre-v3 `bigInt(...)`
//! has NO size limit at all (oracle: `bigInt(2^1000)` is `OK` at v2, `REJECT
//! ArithmeticException` at v3). `predef_ir_builder` now threads `tree_version`
//! (previously unused by the function) to implement this gate.
//!
//! **Version-gate investigation** (§24(e), informed the decision NOT to
//! version-gate `unify::is_prim_type` for `SUnsignedBigInt` — see that
//! function's doc comment for the full oracle-backed argument): the
//! `unsignedBigInt`/`bigInt` PREDEF FUNCTIONS themselves are NOT version-gated
//! (oracle: `unsignedBigInt("5")`, and full arithmetic/comparison on two such
//! values, typecheck identically at v2 and v3). Only `bigInt`'s cap (above) and
//! pre-existing UBI METHOD calls (`min_version = 3` on every
//! `unsigned_bigint_methods()` entry, unaffected by this task) are
//! version-sensitive.
//!
//! **`const_upcast`/`const_downcast` fix** (`unify.rs`): these previously used
//! `ConstPayload::BigInt` as a placeholder for upcast results targeting
//! `SUnsignedBigInt` (M2, "no dedicated UBI payload in M2 scope") — now
//! produce/consume the real `ConstPayload::UnsignedBigInt`. The extraction
//! matches in both functions gained an `UnsignedBigInt(_)` arm (previously
//! absent, since no payload variant existed to trigger it — would have hit the
//! `non-numeric payload` catch-all once the dedicated variant appeared).
//!
//! ### D-T4 — ProveDlog placeholder rendering — CLOSED (M3)
//!
//! `typed_print.rs` now decompresses the stored 33-byte key and renders the
//! oracle's `(CSigmaProp (ProveDlog (Ecp @(x,y,1))))` form (no `CGroupElement`
//! wrapper — golden_seed §10/§23). All former `SWEEP_SKIP` records byte-match
//! and are swept normally.
//!
//! **Correction (adversarial-review finding, fixed 2026-07-05):** `x`/`y` in
//! that rendered form are the coordinate's UNPADDED `BigInteger.toString(16)`
//! (same root as D-T12's `showPoint`, per the `TyperOracle.scala` `renderField`
//! trace at golden_seed.txt §23(f)), NOT the fixed-width 64-char hex
//! `decompress_to_affine_hex` returns. `typed_print.rs`'s GroupElement/
//! ProveDlog arms now run `ergo_crypto::group_element::strip_leading_zero_hex`
//! on each coordinate first — oracle-pinned on a leading-zero y-coordinate,
//! golden_seed.txt §23(f).
//!
//! ### D-T5 — GroupElement on-curve validation — CLOSED (M3, with a named residual)
//!
//! `env::lift` and `bind_pk` on-curve-check every GroupElement/pubkey via
//! `ergo_crypto::group_element::decompress_to_affine_hex`, mirroring Scala's
//! `GroupElementSerializer.parse` decode-time validation. Residual (bounded,
//! reject-side-safe): identity (`0x00`-prefix) points are REJECTED alongside
//! off-curve ones, though a JVM env could in principle bind an infinity `Ecp`
//! — no oracle path constructs one at typecheck time (`decodePoint` is never
//! constant-folded, golden_seed §23(e)), so there is no observable Scala
//! verdict to mirror.
//!
//! ### D-T6 — GroupElement hex lift shape — CLOSED (M3)
//!
//! `ConstPayload::GroupElement` now stores the 33-byte SEC1-compressed key
//! (bytes-of-record, matching `ProveDlog`); the printer decompresses on
//! demand. Emit (M3 Task 7+) consumes the bytes directly.
//!
//! ### D-T7 — Typer error positions always 0 (E12)
//!
//! `TypedExpr` carries no source positions: every [`TyperError`] has `pos ≡ 0`.
//! `Parse`/`Bind` errors DO carry real positions (from `span::line_col`).  The
//! typer is therefore the sole documented phase-level position gap — the typer
//! cannot cite a source location because no location was threaded through
//! `TypedExpr` nodes.  Oracle reject positions for typer failures are advisory
//! only (E5); the 50 `typefail(env, x, line, col)` assertions from
//! `SigmaTyperTest.scala` are ported as class+verdict-only in
//! `tests/sigma_typer_spec.rs`, with the original `(line, col)` preserved in
//! comments for a future M3 position pass.
//! Source: `typer/assign.rs` module doc; `typecheck.rs` `CompileError` doc.
//!
//! ### D-T8 — BindError class-tag for irBuilder arg-shape mismatch
//!
//! The `PK` and `serialize` irBuilders are applied via Scala's unconditional
//! `PartialFunction` (`SigmaBinder.scala:105-109`); a non-matching arg shape
//! (wrong arity, or a non-`String`-constant `PK` argument after children-first
//! binding) causes a `scala.MatchError` crash, caught at the caller as a general
//! `BinderException`.  We return a typed `BindError::InvalidArguments`.  The
//! REJECT verdict matches; the error class is more specific (`InvalidArguments`
//! vs the oracle's `TyperException` or bare `Exception`).
//! The `PK(1)` golden-seed §10 reject has class deviation `TyperException` (oracle)
//! vs `InvalidArguments` (Rust); listed in `CLASS_DEVIATION_SOURCES` in
//! `tests/typer_oracle_parity.rs`.
//! Source: `binder.rs:571-616`; golden seed §10.
//!
//! ### D-T9 — `specialize_for` returns `None` on unification failure
//!
//! Scala's `SMethod.specializeFor` (`methods.scala:193-199`) returns `this` (the
//! unspecialized descriptor) when unification fails, silently accepting a
//! type mismatch.  Our `specialize_for` returns `None`, letting the caller surface
//! a `TypeMismatch` error.  The stricter behaviour is correct for a type-checker
//! frontend; the Scala leniency exists to preserve IR round-trips through the
//! evaluator.  No oracle vector or corpus contract exercises this path (the
//! binder ensures well-typed method-call shapes before the typer runs).
//! Source: `typer/methods.rs:773-778`.
//!
//! ### D-T10 — `container_exists` version-independence
//!
//! Scala's `MethodsContainer.contains` (`methods.scala:171-181`) is version-gated
//! (types that gain method containers in V6 are absent at lower versions).  Our
//! `container_exists` is version-independent — it returns `true` for all
//! container types regardless of `tree_version`.  For *container existence* the
//! deviation is inert: the types that gain containers in V6 (`SUnsignedBigInt`,
//! `SHeader` V6 additions) are unconstructable in pre-V6 trees, so the typer never
//! reaches a method-lookup for them at `tree_version < 3`.
//!
//! A RELATED version-dependence is NOT inert and is handled explicitly (M2 wave B):
//! the numeric `toBytes`/`toBits` methods live on the shared `SNumericTypeMethods`
//! container (`objType.typeName = "SNumericType"`) at V5 and gain a per-type container
//! (`Int`/`Long`/…) only at V6.  Since numeric types ARE constructable pre-V6, the
//! printed `MethodCall` owner differs by version (`%SNumericType.toBytes` at
//! `tree_version < 3` vs `%Int.toBytes` at V6).  `owner_name_for_method`
//! (`typer/methods.rs`) selects the owner version-aware; the M2 typed-shape output is
//! oracle-pinned at both v2 and v3 (golden seed §21 / §15).  M3 note: `objType` also
//! feeds `MethodCall` wire serialization (method typeId), so the same container choice
//! must hold at byte level.
//! Source: `typer/methods.rs` (`container_exists`, `owner_name_for_method`).
//!
//! ### D-T11 — ByIndex default-value comparison: typeCode vs structural equality
//!
//! Scala's `SigmaTyper.scala:497-498` checks that the ByIndex default value type
//! matches the collection element type using `typeCode` equality (which ignores
//! type parameters — `Coll[Int]` and `Coll[Boolean]` share the same `typeCode`).
//! We compare structural `SType` equality, which is stricter.  The deviation is
//! unreachable in practice: `ByIndex` is not produced by the M2 binder or any
//! `assign_type` arm — it appears only as a pre-typed passthrough node, and
//! neither the binder nor the oracle exercises a default value whose type differs
//! by type-argument but shares a typeCode.
//! Source: `typer/assign.rs:855-858`.
//!
//! ### D-T12 — String-constant `+` GroupElement/ProveDlog-constant fold (CLOSED for those two payloads; residual below)
//!
//! `mcl_string` (`typer/assign.rs`) folds `StringConstant + <any Constant>` via the
//! JVM `.toString`, matching Scala's `mkStringConcat` (the `@unchecked` `Constant`
//! type args are erased at runtime).  Reproducible payloads fold byte-exactly
//! (`Int`→decimal, `Bool`→`true`/`false`, `Unit`→`()`, `BigInt`→`CBigInt(n)`, …).
//!
//! **CLOSED at M3 Task 4** for `GroupElement` and `ProveDlog`: Scala's `.toString`
//! on an `ECPoint` (via `CryptoFacade.showPoint`, `Platform.scala:81-85`) truncates
//! each affine coordinate's UNPADDED `BigInteger.toString(16)` hex to its first 6
//! chars — `GroupElement(ECPoint(79be66,483ada,...))` for a bare `GroupElement`
//! constant, `SigmaProp(ProveDlog(ECPoint(79be66,483ada,...)))` for a `ProveDlog`
//! constant (e.g. from `PK("<addr>")`). Both ARE byte-derivable from our stored
//! `[u8; 33]` via `ergo_crypto::group_element::decompress_to_affine_hex` (Task 3)
//! composed with `ergo_crypto::group_element::strip_leading_zero_hex` (the payload
//! is on-curve-checked before reaching a `Constant` node — `env::lift` /
//! `binder::bind_pk`, D-T5).
//!
//! **Correction (adversarial-review finding, fixed 2026-07-05):** the generator
//! and non-generator (g3) probes originally cited here confirm only the
//! truncate-to-6-chars SHAPE generalizes across distinct points — NEITHER has a
//! leading-zero-nibble coordinate, so neither actually distinguishes padded
//! 64-char hex (our prior, WRONG assumption — a straight `&decompress_to_affine_hex(..)[..6]`
//! slice) from Java's unpadded `BigInteger.toString(16)` (the real semantics).
//! A fourth probe — a `PK(...)` pubkey chosen specifically for a leading-zero
//! y-coordinate (`0ab0902e...`) — pins this: the oracle folds `ab0902`
//! (unpadded), NOT `0ab090` (padded-slice). Live-captured at golden_seed.txt
//! §23(d) (fold) and independently re-confirmed at the plain, untruncated
//! `Ecp @(x,y,1)` printer surface (§23(f)), which shares the same unpadded
//! `BigInteger`-hex root (see §23(f)'s `TyperOracle.scala` `renderField`
//! source citation) and required the identical fix in `typed_print.rs`
//! (D-T4/D-T6, below).
//!
//! **Residual (still an unreproduced verdict divergence, REJECT kept):** an opaque
//! env-lifted `ConstPayload::SigmaProp(String)` (no real curve bytes in our
//! representation — just a label, e.g. `tcs` env's `p1`/`p2`) and a `ByteColl` /
//! `LongColl` RHS (Scala prints `Coll(<v1>,<v2>,...)`, oracle-probed but not pinned
//! or wired) still fold in Scala via a JVM-runtime `.toString` we cannot reproduce —
//! rather than fold WRONG bytes we keep the REJECT (reject-valid; no golden-seed OK
//! record exercises these, so they carry no `VERDICT_DEVIATION_SOURCES` entry).
//! This resolves the adversarial reject-valid finding (`"ab" + 1` etc.) while pinning
//! the remaining residual to payloads with no reproducible byte source.
//! Source: `typer/assign.rs` `const_java_to_string` / `mcl_string`.
//!
//! # Known M3 deviations (emit layer)
//!
//! ### D-E1 — `CreateAvlTree` not emittable (ergo-ser 0xB6 parity divergence)
//!
//! Scala 6.0.2 registers `CreateAvlTreeSerializer` (four value args) at opcode
//! `0xB6` (`ValueSerializer.scala:54`; `trees.scala:88` `opCode =
//! OpCodes.AvlTreeCode`), but ergo-ser's `opcode_pattern` parses `0xB6` as
//! `Zero` ("AvlTreeCode (deprecated)") — an emitted node would not re-parse.
//! Per the M3 ground rule (resolve toward ergo-ser), `emit` returns
//! `EmitError::UnsupportedNode("CreateAvlTree")`; `avlTree(...)` scripts
//! typecheck but do not compile to bytes. NOTE for the ergo-ser owners: this
//! looks like a genuine ergo-ser↔Scala accept-set divergence (a Scala tree
//! containing `CreateAvlTree` would mis-parse), flagged in the Task-7 report.
//!
//! ### D-E2 — `ZKProofBlock` not emittable (matches Scala)
//!
//! `ZKProof { .. }` has no serializer registration in Scala's
//! `ValueSerializer` and no byte in ergo-ser's `opcode_pattern`; the Scala
//! compiler cannot serialize it either (it is erased by the prover-side
//! `ZKProving` transform). `emit` returns `UnsupportedNode("ZKProofBlock")`.
//!
//! ### D-E3 — opaque env `SigmaProp` constant not emittable
//!
//! `ConstPayload::SigmaProp(String)` is an env-injected opaque label (e.g. the
//! SigmaTyperTest env's `p1`/`p2`) with no curve bytes to serialize; only
//! reachable from a hand-built env, no oracle vector exists. `emit` returns
//! `UnsupportedNode`; real keys flow through `ConstPayload::ProveDlog([u8;33])`.
//!
//! # Known M3 deviations (tree/compile layer)
//!
//! ### D-C1 — no constant segregation (`build_tree` = withoutSegregation only)
//!
//! Scala's `ErgoTree.fromProposition` segregates every root that is not a bare
//! `SigmaPropConstant` (header `0x10`, constants pulled into the table,
//! `ConstPlaceholder` in the body); `tree::build_tree` emits header `0x00`
//! with inline constants for EVERY root. Consequence: for the segregated class
//! the tree bytes and the P2S address DIFFER from Scala (oracle:
//! `cc sigmaProp(HEIGHT > 100)` → `100104c801d191a37300` vs our
//! `00d191a304c801`) while remaining valid, parseable, semantically equal
//! trees. The P2SH address is UNAFFECTED — it hashes the constant-inlined
//! proposition, which is byte-identical to our body (oracle-pinned in
//! `tree.rs` and `ergo-ser/src/address.rs` tests). The bare-constant class
//! (e.g. `PK(...)`) takes the same withoutSegregation branch on both sides and
//! is byte- and address-exact. The segregation transform is the M4 flip point.
//!
//! ### D-C2 — no `CreateProveDlog(Const)` → `SigmaPropConstant` fold
//!
//! Scala's IR pipeline constant-folds `proveDlog(<GroupElement const>)` into a
//! bare `SigmaPropConstant` at the GraphBuilding stage (oracle:
//! `cce proveDlog(g1)` replies with the SAME tree/addresses as the equivalent
//! `PK(...)`, task-1-report Concern 1); we emit the unfolded
//! `CreateProveDlog(Const)` node (`0xCD`) — same header `0x00`, different body
//! bytes, different addresses. The constant fold is an M4/M5 lowering rule.

pub mod ast;
pub mod binder;
pub mod emit;
pub mod env;
pub mod error;
mod parse;
pub mod span;
pub mod stype;
pub mod token;
pub mod tree;
pub mod typecheck;
pub mod typed;
pub mod typed_print;
pub mod typer;

pub use ast::{ArithKind, BitKind, Expr, RelKind, ValDef};
pub use binder::{bind, BindError};
pub use emit::{emit, EmitError};
pub use env::{lift, EnvValue, ScriptEnv};
pub use error::ParseError;
pub use parse::{parse, parse_type};
pub use stype::SType;
pub use tree::{compile, CompileResult};
pub use typecheck::{typecheck, typecheck_with_network, CompileError};
pub use typed::{node_tpe, ConstPayload, TypedExpr};
pub use typed_print::print_typed;
pub use typer::TyperError;

// Re-exported so `PK("addr")` compiles can select the address network without a
// direct `ergo-ser` dependency in downstream crates.
pub use ergo_ser::address::NetworkPrefix;
// Re-exported so callers can build `EnvValue::GroupElement` without a direct
// `ergo-primitives` dependency (the type is part of the `ScriptEnv` surface).
pub use ergo_primitives::group_element::GroupElement;
