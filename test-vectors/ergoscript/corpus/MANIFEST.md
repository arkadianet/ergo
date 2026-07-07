# ErgoScript real-contract corpus — MANIFEST

79 real, deployed ErgoScript sources (`.es`), vendored verbatim from the
developer's `~/coding/reference` checkouts. This is the M1 parser's long-tail
acceptance corpus: `ergo-compiler/tests/corpus_smoke.rs` parses every file with
`ergo_compiler::parse(src, tree_version = 3)` and asserts the accept/reject
verdict (and, on reject, the exact 1-based `line:col`) equals the committed
`verdicts.json`.

## Oracle

`verdicts.json` is produced by the **JVM reference parser**, `sigmastate.lang.SigmaParser`
(sigma-state 6.0.2 — the version the consensus node runs), via
`scripts/jvm_parser_oracle/ParserOracle.scala`. It is an external ORACLE: the
Rust parser is graded against it; it is never adjusted to make the Rust parser
pass (the repo's oracle-parity rule). The parser runs under
`VersionContext.withVersions(3, 3)` so the v6 predef type set (incl.
`UnsignedBigInt`) matches Rust's `parse(src, 3)`.

## Origin map

Each corpus file's origin is its path below the group root; the corpus preserves
the source subtree per group (renamed roots only, no content edits).

| Corpus subtree | Origin (under `~/coding/reference/`) | Count |
|---|---|---|
| `dexy/**` | `ergo-apps/protocols/Dexy/dexy-stable/contracts/**` | 23 |
| `hodlcoin/phoenix-hodlcoin-contracts/*` | `ergo-apps/protocols/HodlCoin/phoenix-hodlcoin-contracts/{hodlERG,hodlToken}/contracts/**/ergoscript/*.es` | 6 |
| `hodlcoin/phoenix/*` | `ergo-apps/protocols/HodlCoin/phoenix/src/main/resources/contracts/Phoenix/{BoxGuardScripts,ProxyContracts}/*.es` | 10 |
| `chaincash-basis/chaincash/**` | `ergo-ecosystem/bettermoneylabs/chaincash/contracts/{onchain,offchain,layer2-old}/*.es` | 9 |
| `chaincash-basis/basis-tracker-basis.es` | `ergo-ecosystem/bettermoneylabs/basis-tracker/contract/basis.es` | 1 |
| `rosen-bridge/*` | `ergo-ecosystem/rosen-bridge/contract/src/main/scala/rosen/bridge/scripts/*.es` | 10 |
| `crystalpool/*` | `ergo-apps/dex/CrystalPool/src/lib/contracts/*.es` | 5 |
| `curve-trees/CurveTreeVerifier-v6.es` | `ergo-core/ergo-curve-trees/contracts/CurveTreeVerifier-v6.es` | 1 |
| `lsp/{examples,src,tests}/*`, `lsp/{test_contract,test_simple}.es` | `ergo-tooling/ergoscript-compiler-lsp/{examples,src,tests}/*`, `.../test_contract.es`, `.../test_simple.es` | 13 |
| `lsp/zed-extension-test.es` | `ergo-tooling/ergoscript-zed-extension/test.es` | 1 |

Notes on the renamed/flattened roots (chosen only to avoid filename collisions):
- **HodlCoin**: two independent origin sets are kept apart —
  `phoenix-hodlcoin-contracts/` (the `hodlERG`/`hodlToken` ergoscript trees, the
  `.../ergoscript/` leaf dir dropped) and `phoenix/` (the `phoenix` resources
  `BoxGuardScripts`/`ProxyContracts` flattened) — because both define
  `phoenix_v1_hodltoken_{bank,fee,proxy}.es`.
- **ChainCash/Basis**: `chaincash/{layer2-old,offchain,onchain}/` subtree
  preserved (`note.es`/`reserve.es` recur across `layer2-old` and `onchain`);
  the single `basis-tracker` file is renamed `basis-tracker-basis.es`.
- **LSP**: `examples/`/`src/`/`tests/` subtree preserved; the zed-extension
  `test.es` is renamed `zed-extension-test.es`.

## Skipped forms (M1 scope)

Only `.es` files are vendored. Deliberately skipped:
- **`dexy-stable-use/`** — a near-identical duplicate of `dexy-stable/` (22
  files); only the primary `dexy-stable/contracts/` set is vendored.
- **`.sc` Spectrum/ErgoDex** (`ergo-apps/dex/ErgoDex-Spectrum/…`) — a distinct
  file extension / dialect, out of M1 scope.
- **`.ergo` SigmaFi** (`ergo-apps/protocols/SigmaFi/…`) — different extension.
- **Markdown-embedded Duckpools** (`ergo-apps/protocols/Duckpools/**/*.md`) —
  contracts live inside prose, not standalone sources.
- **SigmaUSD/AgeUSD, oracle-core** — no ErgoScript source (compiled WASM /
  serialized ErgoTrees only).

These are noted for a later milestone; none are consensus surfaces.

## Verdict stats

79 files: **67 accept, 12 reject**. Every reject is explained:
- 8× LSP template/test files (`@contract` / `@test` / `#import` headers) — the
  contract-template DSL is a later milestone (`ContractParser`), not the core
  expression grammar. Both the JVM oracle and Rust reject them; the position is
  `1:1` (fastparse's zero-progress top-level failure index).
- `chaincash-basis/chaincash/layer2-old/reserve.es` — a genuine `val x == …`
  typo in the deprecated layer2 source; both reject at the second `=`.
- `hodlcoin/…/phoenix_v1_hodltoken_proxy.es`, `lsp/examples/{completion_demo,hover_demo}.es`
  — reject at real in-file positions; both sides agree.

## Regeneration

Refresh `verdicts.json` from the live JVM oracle (needs `scala-cli` on PATH and,
first run, network to resolve `sigma-state:6.0.2` from Maven Central):

```bash
cargo test -p ergo-compiler --test corpus_smoke -- --ignored --nocapture
```

`corpus_live_oracle_parity` spawns the oracle, re-derives every verdict, and
asserts it equals the committed `verdicts.json`. To rewrite the file wholesale,
pipe `parse <hex-of-utf8-source>` lines (one per file, sorted by corpus-relative
path) into `scala-cli run scripts/jvm_parser_oracle/ParserOracle.scala` and map
each `ACCEPT` / `REJECT <line>:<col>` reply back to its file.
