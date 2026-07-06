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
//!   opcode-IR→`TypedExpr` reverse mapping — scheduled at M4 alongside the
//!   lowering catalog, which needs the same mapping (M3 close-out decision;
//!   the adversarial pass surfaced no real-contract need).
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
//! # M3: Emit + semantic parity — COMPLETE
//!
//! The full pipeline is live: **parse → bind → typecheck → emit** (`emit.rs`,
//! typed AST → `ergo_ser` opcode IR) → **assemble** (`tree.rs`, v0 `0x00`
//! header, no segregation — D-C1) → **bytes → P2S/P2SH address**. Entry
//! point: [`compile`] → [`CompileResult`].
//!
//! - **Compile oracle:** `scripts/jvm_typer_oracle` gained the `cc`/`cce`/
//!   `ccs` compile verbs (source → ErgoTree hex + P2S/P2SH, 6.0.2); 271
//!   committed vectors in
//!   `test-vectors/ergoscript/compile/compile_seed.json` — the ACCEPT
//!   vectors (85) carry the ORACLE's tree hex + addresses (ready byte
//!   targets for M4/M5); REJECT vectors carry the verdict + class.
//! - **Gate** (`tests/compile_semantic_parity.rs`): every swept ACCEPT pair
//!   reduces to the SAME SigmaBoolean under the dummy context (5
//!   `SEMANTIC_SKIP`, all D-C3); rejects grade the oracle's exception class
//!   exactly; the address gate pins P2SH per-vector against a committed
//!   failing-vector SET (`DC7_P2SH_MISMATCH_SET`, M4 Task 1 —
//!   recon-gap.md Finding 5 upgraded this from a count assert; shrinks as
//!   M4/M5 lowerings land, graduating vectors out explicitly) and
//!   hard-asserts byte-equal-prop ⇒ P2SH-equal. The `PK(...)` bare-constant
//!   class is byte- and address-EXACT.
//! - **Deviation families:** `D-E1..D-E3` (emit layer) and `D-C1..D-C7`
//!   (tree/compile layer), ledgered below. D-C7 (no IR optimization pass)
//!   IS the M4/M5 byte-parity worklist — see the roadmap's "M4 worklist"
//!   section.
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
//! sigma-state's own AST representation, not ours) — scheduled at M4
//! alongside the lowering catalog, which needs the same mapping (M3
//! close-out decision; the adversarial pass surfaced no real-contract need).
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
//! ### D-E3 — opaque env `SigmaProp` constant not emittable (reject-side)
//!
//! `ConstPayload::SigmaProp(String)` is an env-injected opaque label (e.g. the
//! SigmaTyperTest env's `p1`/`p2`) with no curve bytes to serialize; only
//! reachable from a hand-built env. `emit` returns `UnsupportedNode`; real
//! keys flow through `ConstPayload::ProveDlog([u8;33])`. Correction (Task-11
//! wave 3; this entry previously claimed "no oracle vector exists"): the
//! `ccs` verb mirrors the SigmaTyperTest env, whose JVM-side `p1`/`p2` are
//! REAL `ProveDlog`s — `ccs sigmaProp(p1.propBytes.size > 0)` compile-ACCEPTs
//! on the oracle while we reject (methodcalls report, excluded section). A
//! reject-side divergence bounded to the opaque-label env representation;
//! not committable as an ACCEPT vector because our representation carries no
//! curve bytes whose output could be compared.
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
//! trees. The P2SH address is SEGREGATION-invariant — it hashes the
//! constant-inlined proposition, so the D-C1 axis alone never moves it
//! (oracle-pinned in `tree.rs` and `ergo-ser/src/address.rs` tests) — but it
//! is NOT IR-transform-invariant: wherever Scala's GraphBuilding reshapes
//! the proposition itself, the P2SH diverges too. That family is D-C7 below
//! (Task-11 finding H-1 falsified this entry's earlier "P2SH is UNAFFECTED"
//! wording, which held only for shape-identical trees). The bare-constant
//! class (e.g. `PK(...)`) takes the same withoutSegregation branch on both
//! sides and is byte- and address-exact. The segregation transform is the
//! M4 flip point.
//!
//! ### D-C2 — no `CreateProveDlog(Const)` → `SigmaPropConstant` fold
//!
//! Scala's IR pipeline constant-folds `proveDlog(<GroupElement const>)` into a
//! bare `SigmaPropConstant` at the GraphBuilding stage (oracle:
//! `cce proveDlog(g1)` replies with the SAME tree/addresses as the equivalent
//! `PK(...)`, task-1-report Concern 1); we emit the unfolded
//! `CreateProveDlog(Const)` node (`0xCD`) — same header `0x00`, different body
//! bytes, different addresses. The constant fold is an M4/M5 lowering rule —
//! one instance of the general D-C7 no-IR-pass family below.
//!
//! ### D-C3 — residual `SigmaPropIsProven` (0xCF): compile output unevaluable
//!
//! Sources mixing `SigmaProp` and `Boolean` in a logical context — e.g.
//! `sigmaProp(true) && (1 == 1)`, `(1 == 1) ^ sigmaProp(true)`,
//! `allOf(Coll(proveDlog(g1)))` — typecheck (byte-parity with the reference,
//! golden_seed §14/§18) into trees carrying `SigmaPropIsProven` /
//! `Select 'isProven'` coercions. Scala's IR pipeline ELIMINATES them:
//! GraphBuilding lowers `isProven` → `p.isValid` (GraphBuilding.scala:528-529,
//! 765-767) and then constant-folds / sigma-reconstructs — oracle compile
//! replies: `sigmaProp(true) && (1 == 1)` → `BoolToSigmaProp(BinAnd(true,
//! true))` (`1000d1ed8503`), the `^` forms → a folded segregated `false`
//! constant (`10010100d17300`), `allOf(Coll(proveDlog(g1)))` → the bare
//! folded `SigmaPropConstant` (`0008cd0279be…`). Our `emit` maps the node
//! 1:1 to wire opcode `0xCF` — parseable, but NO evaluator accepts it: ours
//! rejects it as internal (`InternalOpcode`), and the reference JIT cannot
//! evaluate it either (`SigmaPropIsProven` has `costKind =
//! Value.notSupportedError` and no `eval`, transformers.scala:321-329). So
//! for these sources `compile()` ACCEPTS but produces a tree that cannot
//! reduce, while Scala produces a folded, evaluable tree. Closing this needs
//! the IR-level partial evaluation / sigma-reconstruction lowering (same
//! M4/M5 machinery as D-C2's fold); a local pre-reject would flip the
//! divergence direction (we-reject/oracle-accepts) and is worse. The five
//! affected corpus vectors are excluded from the Task-10 semantic gate via
//! `SEMANTIC_SKIP` (tests/compile_semantic_parity.rs), each tagged D-C3.
//!
//! ### D-C4 — multi-arg lambda emits a multi-arg `FuncValue`: unevaluable
//!
//! A two-parameter lambda (`.fold(0L, {(a: Long, b: Box) => ...})`) emits as
//! a FuncValue with TWO args — wire-legal (`FuncValueSerializer` carries
//! `numArgs`) but unevaluable: the reference JIT hard-errors on any
//! non-1-arg function (`values.scala:1042-1056`, `"Function must have 1
//! argument"`), and our evaluator equally rejects it. Scala's compile output
//! never carries one — the IR pipeline lowers multi-arg lambdas to the
//! 1-arg TUPLED form (`FuncValue(Array((id, STuple(..))), body)` with
//! `SelectField` projections), which is what real `Fold` trees look like
//! on-chain. Same missing-lowering family as D-C3, discovered by the Task-10
//! Err/Err telemetry (4 of the 18 kept corpus compile vectors — the
//! crystalpool contracts — carry such lambdas; they PASS the semantic gate
//! only because the dummy reduction context makes BOTH sides err before the
//! FuncValue applies on the oracle side). M4/M5 lowering scope; no
//! `SEMANTIC_SKIP` entry is needed while the Err/Err rule covers them, but
//! any richer gate context will surface this first. Wave 1 NARROWED the
//! class: a direct/aliased/inline `FuncApply` with != 1 args now rejects in
//! oracle parity (D-C5 class 2), so D-C4 covers only the un-applied
//! definitions and fold-callback uses that both compilers accept.
//!
//! ### D-C5 — GraphBuilding reject-gate parity (Task-11 adversarial wave 1)
//!
//! Our pipeline has no analogue of Scala's GraphBuilding/IR stage, so before
//! this gate EVERY typed tree emit could serialize was accepted — including
//! whole families the full Scala compiler REJECTS (accept-invalid; several
//! emitted unspendable addresses). Wave 1 closes the reject direction with
//! `EmitError::GraphBuildingReject { class, what }` (class = the oracle's
//! exception class, graded exactly, not advisory): every rule below is
//! oracle-pinned (captures 2026-07-07, 3 identical runs each; committed as
//! `compile_probes.txt` → `compile_seed.json` vectors; findings reports
//! `dev-docs/ergoscript-compiler-m3-recon/adversarial-findings-*.md`).
//!
//! Six gated classes:
//! 1. **Bit ops** (`emit.rs` BitOp/BitInversion arms;
//!    `GraphBuildingException`): Scala 6.0.2 has NO lowering for
//!    `|`,`&`,`^`(numeric),`<<`,`>>`,`>>>`,`~` at any width — opcodes
//!    0xF1-0xF8 are unreachable from both compilers. The TYPER accepts on
//!    both sides (golden-seed bit-op records stay valid); boolean `^`
//!    (BinXor) is untouched.
//! 2. **Zero-arg lambdas + non-1-arg applications** (`tree.rs`
//!    `graph_building_lambda_reject`; `GraphBuildingException`): a zero-arg
//!    `FuncValue` rejects ANYWHERE (even the rhs of an unused val); a
//!    `FuncApply` with != 1 args rejects (direct/aliased/inline). The
//!    multi-arg DEFINITION stays accepted — unused vals, un-applied aliases
//!    and fold-callback uses (direct AND val-bound, e.g.
//!    `crystalpool/swap-tokens.es`) are the D-C4 both-accept class.
//! 3. **Function-typed lambda parameters** (same walk; `MatchError`): any
//!    lambda with an `SFunc`-typed param rejects unless it is the rhs of an
//!    UNUSED val (oracle: pruned → ACCEPT). Residual (reject-side bounded,
//!    probe-CONFIRMED reject-valid — re-verify finding NF-2, 2026-07-07):
//!    an SFunc-param lambda NESTED inside an unused val's rhs BODY IS
//!    pruned by Scala (oracle ACCEPTs `{ val unused = {(x: Int) =>
//!    {(f: Int => Int) => f(x)}}; sigmaProp(true) }` — dead-code
//!    elimination drops the whole unused val) while our ONE-HOP exemption
//!    rejects with `MatchError`. Same unused-val-pruning transform family
//!    as D-C7; bounded to deliberately-unused higher-order lambdas no real
//!    contract contains; closes when the M4/M5 val-pruning lowering lands.
//!    The zero-arg-lambda rule (class 2) must stay UN-exempted even in an
//!    unused rhs — oracle-pinned REJECT.
//! 4. **Postfix residual `size`** (`emit.rs` `emit_method_call`;
//!    `GraphBuildingException`): `MethodCall %SCollection.size` (wire pair
//!    (12,1), the space-form `arr1 size`) has no GraphBuilding arm and no
//!    evaluator accepts it. Bounded to `size` — the sole nullary
//!    custom-irBuilder Coll method; other postfix families reject upstream
//!    in parity.
//! 5. **`Box.getReg[T](<literal>)` out of 0..=9** (`emit_method_call`;
//!    `ArrayIndexOutOfBoundsException`): Scala bounds-checks the const index
//!    while lowering to `ExtractRegisterAs`. Dynamic indices untouched
//!    (MethodCall on both sides, Err/Err parity). The IN-RANGE literal
//!    lowering to `ExtractRegisterAs` landed in Wave 2 (D-C6 item 1).
//! 6. **Shared-SNumericType-container methods at `tree_version < 3`**
//!    (`emit_method_call`; `GraphBuildingException`): `toBytes`/`toBits`
//!    resolve to the `"SNumericType"` owner only pre-v3 (D-T10), where Scala
//!    rejects the v6 method under v5 activation. At v3 the per-type residual
//!    MethodCall is unchanged.
//!
//! Plus the **constant-fold overflow CHECK** (`tree.rs`
//! `fold_overflow_check`; `ArithmeticException`): a bounded exact re-fold of
//! Scala's compile-time constant evaluation — `+`,`-`,`*` over same-width
//! `Byte`/`Short`/`Int`/`Long` constant operands, `min`/`max` over the same
//! (wave-4 review follow-up: they cannot overflow themselves but propagate
//! the constant into the parent checks — `(min(2147483647, 1) +
//! 2147483647)` REJECTs, previously accept-invalid), and `Downcast`/`Upcast`
//! of DIRECT constants; overflow rejects. The emitted tree stays UNFOLDED
//! (semantics unchanged). Probed fold boundary honored: division/modulo NOT
//! folded (`1/0` compiles), BigInt arith NOT folded, `Negation` NOT folded
//! (probe-confirmed PARITY, wave 4: `-(0 + 2147483647) - 2` ACCEPTs with
//! the Negation node unfolded in the oracle tree even over a folded
//! constant, so our recurse-only arm matches; `-(<literal>)` folds at PARSE
//! time on both sides and rejects via the `-` arm — the min/max-chain and
//! Negation residuals flagged at wave 1 are BOTH closed), casts of
//! non-direct-constant subexpressions NOT folded (`(x*100).toByte` compiles;
//! cast-of-cast chains treated the same, un-probed). The fold check runs
//! everywhere — unused-val rhs and lambda bodies included (both
//! oracle-pinned REJECT).
//!
//! Wave-2 items (getReg in-range literal lowering F4, `slice[T]`
//! explicit-type-arg residual F5, v6 numeric constant-receiver folds F6,
//! `Coll[UnsignedBigInt]().size` fold / self-readability, constants F-3)
//! landed as D-C6 below. The remaining Task-11 finding — the whole
//! P2SH-address divergence family (fold/CSE/upcast/ident lowerings —
//! numerics N-3, bindings F3, methodcalls class 4, harness H-1) — is
//! ledgered as D-C7 below, counted and gated by the wave-3 address gate in
//! `tests/compile_semantic_parity.rs`.
//!
//! ### D-C6 — evaluability lowerings + folds (Task-11 adversarial wave 2)
//!
//! Wave 2 closes the oracle-confirmed "both accept, OUR tree cannot evaluate
//! (or re-read) where the oracle's can" families — unlike wave 1 these CHANGE
//! the emitted bytes toward Scala's. Every rule is oracle-pinned (captures
//! 2026-07-07, 3 identical runs each; committed as `compile_probes.txt` →
//! `compile_seed.json` wave-2 vectors; byte/P2SH pins in `emit.rs`/`tree.rs`
//! tests). Since our trees stay non-segregated (D-C1), the oracle-comparable
//! byte surface is the P2SH address (hashes the constant-inlined
//! proposition) — asserted for every lowering below.
//!
//! 1. **`Box.getReg[T](in-range literal)` → `ExtractRegisterAs` (0xC6)**
//!    (`emit_method_call`; methodcalls F4): `SELF.getReg[Int](5)` emits the
//!    SAME bytes as `SELF.R5[Int]` (oracle: both reply `1000d1e6c6a70504`);
//!    the wire carries the INNER elem type T. Dynamic index stays MethodCall
//!    on both sides. RESIDUAL: Scala const-PROPAGATES a val-bound index
//!    (`{ val i = 4; …getReg[Int](i) }` lowers to reg 4, the val
//!    eliminated); our typed AST keeps the ValUse → the MethodCall survives,
//!    both-accept but unevaluable on our side under the v0 header — the
//!    vector is therefore NOT committable (the semantic gate would grade it
//!    mixed Ok/Err); pinned verdict-only in `tree.rs`
//!    (`compile_val_bound_get_reg_index_stays_residual_method_call`).
//!    Const-propagation is M5-family scope.
//! 2. **Explicit-type-arg custom irBuilders lower** (`typer/assign.rs` §1.7;
//!    methodcalls F5): the §1.7 `has_ir_builder` branch previously built a
//!    MethodCall UNCONDITIONALLY; Scala routes through the method's OWN
//!    irBuilder (`irBuilder.lift(...).getOrElse(mkMethodCall(subst))`,
//!    SigmaTyper.scala:167-171). Now routed through the same `lower_method`
//!    catalog: `arr1.slice[Byte](0, 1)` → `Slice` (byte-identical to the
//!    un-annotated form, oracle-matched), same for `filter[T]`/`exists[T]`/
//!    `getOrElse[T]`; MethodCallIrBuilder methods (getReg/some/none/…) still
//!    survive as MethodCalls with the {T→rangeTpe} subst. (`map[T]` with a
//!    concrete-range lambda REJECTS on BOTH sides — the §1.7 expected-args
//!    check fires before the irBuilder, `STypeVar("OV") != SByte`; oracle
//!    `REJECT 1:16 TyperException` — the F5 report's "map[T] OKPAR" control
//!    note was inaccurate.)
//! 3. **v6 numeric methods on CONSTANT receivers fold at v3**
//!    (`emit_method_call` gate (d); methodcalls F6): the oracle-probed fold
//!    set ONLY — `toBytes` (big-endian `Coll[Byte]`), `toBits`
//!    (`Coll[Boolean]`, index 0 = MSB) on Byte/Short/Int/Long constants, and
//!    `bitwiseAnd`/`bitwiseOr`/`bitwiseXor` over two constants (all three
//!    probed to fold). A single explicit cast of a literal (`7.toByte`)
//!    counts as constant (range-checked; out-of-range falls through to the
//!    `fold_overflow_check` ArithmeticException, matching the oracle's
//!    `300.toByte.toBytes` reject). NOT folded (oracle-probed Err/Err
//!    parity): non-constant receivers (`HEIGHT.toBytes`), BigInt receivers
//!    (`n1.toBytes`), `shiftLeft`/`shiftRight`. RESIDUAL: deeper constant
//!    receivers Scala's full partial evaluation folds (arith results,
//!    multi-cast chains) stay residual MethodCalls. The Err/Err pair
//!    (PreV3V6Method, PreV3V6Method) these controls produce is audited in
//!    `compile_semantic_parity.rs` — both compilers keep byte-matching
//!    MethodCalls that neither evaluator accepts under v0.
//! 4. **`SizeOf(<collection literal>)` folds to the element count**
//!    (`tree.rs::fold_literal_coll_sizes`; constants F-3): Scala folds
//!    `.size` of a `ConcreteCollection` literal regardless of element
//!    constancy (`Coll(HEIGHT).size` folds; probed). Runs AFTER the D-C5
//!    gates (discarded elements stay verdict-checked — `Coll(2147483647 +
//!    1).size` still rejects) and BEFORE serialization, so
//!    `Coll[UnsignedBigInt]().size == 0` emits clean v0 bytes (the v3-only
//!    elem-type code 9 never hits the wire — previously a stranded-funds
//!    P2S our own `read_ergo_tree` refused).
//! 5. **Post-write self-check** (`compile`): the tree bytes are re-read via
//!    `read_ergo_tree` before any address is derived; a failure is a
//!    `CompileError::Serializer` reject. This is a DELIBERATE reject-side
//!    divergence (M1 stray-brace precedent: wrong-accept strands funds,
//!    wrong-reject surfaces a user error) for two oracle-probed families:
//!    (a) **Note-A getVar-style v3-type-codes-under-v0** —
//!    `getVar[UnsignedBigInt](1)`: the oracle ACCEPTs `1000d1e6e30109`,
//!    bytes NEITHER side's version-gated reader re-parses (its tree_hex
//!    would not even parse for the semantic gate), so the ACCEPT verdict is
//!    itself poisoned — both products strand funds; (b) **the UBI-fold
//!    family (extended by re-verify finding NF-1, 2026-07-07)** —
//!    reject-side divergent not only on the val-bound
//!    `Coll[UnsignedBigInt]()`-under-`.size` self-check shape but on EVERY
//!    UBI-constant expression whose fold Scala performs and we don't:
//!    equality (`unsignedBigInt("1") == unsignedBigInt("1")`), tuple-select
//!    (`(unsignedBigInt("5"), 1)._2 == 1`), and val-bound forms all fold to
//!    `10010101d17300` on the oracle (usable — the UBI data never reaches
//!    its wire), while our v0 UBI-data gate (`CompileError::Serializer`,
//!    "UnsignedBigInt constant data") fires on the unfolded AST. Bounded to
//!    UBI-under-v0 sources no real contract uses; the NON-foldable shapes
//!    (`unsignedBigInt("5") > unsignedBigInt("3")`) still REJECT in parity,
//!    so the data gate must NOT be weakened — the family closes when M4/M5
//!    constant folding lands. Neither (a) nor (b) is committable as a
//!    vector; the self-check flavor is pinned in `tree.rs`
//!    (`compile_self_unreadable_emission_rejects_serializer_class`).
//!
//! ### D-C7 — no IR optimization pass: proposition-shape (and P2SH) parity only for transform-free trees (Task-11 adversarial wave 3)
//!
//! Our emit is 1:1 with the typed AST; Scala's compiler runs the
//! GraphBuilding/IR stage between typing and serialization, which
//! restructures the proposition wherever any of its rules fires
//! (adversarial reports: harness H-1, numerics N-3, bindings F3,
//! methodcalls class 4 — five consolidated root causes plus folds):
//!
//! - **constant folding** — including env constants (`ccs` binds `x`/`b1`/
//!   `n1`/… as constants, so closed-over comparisons fold to
//!   `sigmaProp(true)`), whole-expression folds (`arr1.size > 0` →
//!   `sigmaProp(true)`), non-overflowing arithmetic
//!   (`sigmaProp((2147483647 + 0) < 0)` folds — the OVERFLOW check is the
//!   D-C5 gate), and `== false` → `LogicalNot`;
//! - **explicit constant-cast shape differences** — Scala folds `0.toByte`
//!   argument casts we keep as `Downcast` nodes (methodcalls (a)), while
//!   our typer folds some literal upcast chains Scala keeps
//!   (`1.toByte.toLong.toBigInt`, numerics N-3 probe 34); either direction
//!   moves the bytes;
//! - **`val` inlining and unused-`val` pruning** (`{ val x = HEIGHT; x > 5 }`
//!   → bare `GT(HEIGHT, 5)`);
//! - **CSE/ValDef sharing** of repeated subterms (`proveDHTuple(g1, g2, g1,
//!   g2)` with one distinct point → a shared constant `ValDef` + four
//!   `ValUse`s; the M5 ValDef-sharing roadmap item);
//! - **single-element `anyOf`/`atLeast` unwrapping** (`anyOf(Coll(HEIGHT >
//!   5))` → the bare comparison);
//! - **`proveDlog(const)` → `SigmaPropConstant`** (= D-C2, one instance of
//!   this family);
//! - **bare-ident context/global singletons lowered to `PropertyCall`s**
//!   (bare `LastBlockUtxoRootHash` → `PropertyCall` over `Context`; bare
//!   `Global.groupGenerator` → `PropertyCall` over `Global`; the dot-forms
//!   match).
//!
//! **CORRECTION (M4 Task 1, recon-gap.md Finding 2):** an earlier pass of
//! this ledger listed "env collections lifted per-element" (env `Coll[Long]`
//! → a per-element `ConcreteCollection` on the Scala side) as a sixth
//! instance of this family. It is **not a compiler transform** — it was an
//! artifact of the M3 test harness's `ccs` (SigmaTyperTest) oracle env,
//! which binds `col1`/`col2` as a per-element `ConcreteCollection` SValue
//! (`TyperOracle.scala:176`), while the `cce` (demo) env and the real
//! `/script` compile API's `liftToConstant` path both always lift
//! `Array[Long]` to a single `LongArrayConstant` (matching us exactly).
//! `EnvValue` has no `ConcreteCollection` variant and never will — the
//! production API cannot produce the shape that "transform" would need to
//! undo. Vector `sigmaProp(col1.slice[Long](0, 1).size == 1)` was
//! re-captured under `cce` instead of `ccs` (`compile_probes.txt`,
//! `compile_seed.json`) and now byte-matches; it never belonged in the D-C7
//! family.
//!
//! Consequence: PROPOSITION bytes — and therefore the P2SH address, which
//! hashes them — diverge from Scala wherever ANY such rule fires, not just
//! on the D-C1 segregation axis (whose "P2SH is UNAFFECTED" sentence wave 3
//! corrected). Semantic parity is unaffected: the Task-10/11 gate reduces
//! every ACCEPT pair to the same SigmaBoolean under the dummy context, and
//! the Task-11 probe batteries verified sem=EQ on every mismatching probe
//! (the untransformed control group P2SH-matches exactly, pinning
//! `encode_p2sh` itself as correct). The class is a SET, not open-ended (M4
//! Task 1, recon-gap.md Finding 5 — a failing-vector-label SET catches a
//! compensating regression a count assert would miss): the address gate
//! (`tests/compile_semantic_parity.rs`) pins the corpus at
//! `DC7_P2SH_MISMATCH_SET` (43 of the 80 swept ACCEPT vectors as of M4
//! Task 1; the other 37 P2SH-match and are hard-asserted equal wherever the
//! proposition bytes agree). The M4 segregation transform plus the M5
//! lowering/ValDef-sharing work close the family; each landed lowering
//! removes the vectors it graduates from the set, deliberately and
//! explicitly.

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
