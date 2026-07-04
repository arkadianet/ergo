# NiPoPoW Completion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.
> Recon dossiers (read the relevant one before your task):
> `/tmp/claude-1000/-home-rkadias-coding-development-arkadianet-ergo/f02bd743-db6e-4509-9d8c-b56c9bb357f2/scratchpad/nipopow-recon/recon-{node,scala,oracle,gap}.md`

**Goal:** close the last gaps to FULL Scala-parity NiPoPoW (serve + P2P + bootstrap) and
adversarially validate the entire pre-existing popow subsystem, which shipped without its
own oracle-differential pass.

**Context:** recon (4 readers, 2026-07-05) found 28/32 parity items already DONE in main
(prover `prove_with_db`, verifier, interlinks + rules 401/402, BatchMerkleProof
codec/verify/construct, wire serializers, P2P codes 90/91, consume-side bootstrap).
Missing: the 4 REST endpoints + JSON encoders; 2 hardcode gaps; a vacuous oracle test.

**Oracle discipline:** live Scala node :9053 serves all 4 /nipopow/* routes (vectors
captured under `test-vectors/mainnet/nipopow/`). Pinned source reference:
`/home/rkadias/coding/reference/ergo-core` (NipopowAlgos/NipopowProof/PoPowHeader/
NipopowApiRoute/NipopowProverWithDbAlgs). Rust control :9063 (404s today).

## Global Constraints

- Worktree `/home/rkadias/coding/development/arkadianet/ergo/.claude/worktrees/nipopow`,
  branch `feat/nipopow` — always `git -C`, verify branch before/after commits, NEVER push.
- Full workspace gate per task: `cargo fmt --all -- --check && cargo clippy --workspace
  --all-targets --all-features -- -D warnings && cargo test --workspace`. No `#[allow]`.
- JSON parity = the ACTUAL :9053 responses, not Scala's openapi.yaml (which omits
  `interlinksProof` from PopowHeader — a Scala doc bug; the live JSON includes it).
- All expected values from the oracle or pinned Scala source. Never self-derived.

## Tasks

### T1 — REST serve surface (the build) ✅ DONE (a075fb0)
4 GET routes matching `NipopowApiRoute.scala:55-90`: `/nipopow/popowHeaderById/{id}`,
`/nipopow/popowHeaderByHeight/{h}`, `/nipopow/proof/{m}/{k}`,
`/nipopow/proof/{m}/{k}/{headerId}`. JSON encoders for NipopowProof
(`NipopowProof.scala:164-173`), PoPowHeader (`PoPowHeader.scala:121-128`),
BatchMerkleProof (`PoPowHeader.scala:81-96`: `{indices:[{index,digest}],
proofs:[{digest,side}]}`, side 0=left/1=right, base16 digests, camelCase keys,
`suffixHead`/`suffixTail`). Store methods exist (`popow_cache.rs`:
`popow_header_by_id`, `popow_header_at_height`, `prove_with_db`). Wire like the other
scala-compat store-backed routes (server.rs + api_bridge patterns). Behavior parity:
param validation, error shapes/status codes as :9053 does them (probe!), Dense-mode
guard, on-demand prove for non-default m/k (Scala REST computes on demand,
`continuous=true` always). openapi golden regen. Tests: field-exact serde round-trips
against the 4 committed vectors + route tests.

### T2 — Config/hardcode gap closes ✅ DONE (8f3a367)
(a) `use_last_epochs` into `DifficultyParams` (ergo-chain-spec), thread to
`has_valid_connections` (proof.rs:401 hardcoded 8) + any other consumer; mainnet=8,
testnet=8 per ChainSettings.scala. (b) `DifficultyParams::mainnet()` hardcode in
`prove_with_db` (popow_cache.rs:433) → take from the store's chain spec (testnet
correctness). (c) Risk-5 fix: P2P serve handler (messaging.rs:718) serves the cached
default proof for ANY requested m/k — Scala warns + drops on mismatch; match Scala.

### T3 — Fixtures + oracle tests un-vacuoused ✅ DONE (98549bf + 9e45c39; found+fixed 2 live /blocks JSON bugs: negative v1 d, d str-vs-number; size = documented Scala stale-metadata deviation)
Commit a real Scala-produced proof binary (capture via the existing
ERGO_CAPTURE_NIPOPOW_PROOF hook against :9053, or serialize from the REST vector —
implementer picks, oracle-pins either way) so `ergo-ser/tests/nipopow_scala_oracle.rs`
actually runs: byte round-trip + full `is_valid` verification of a genuine Scala proof.
Commit the 4 REST JSON vectors (done — wire tests to them). Add an opt-in live
differential test (env-gated) hitting :9053 + local.

### T4 — Live end-to-end differential ✅ DONE (prod stop+reflink-copy, 55s downtime; dev node on 9073; FULLY GREEN after 3 findings fixed: e39fa40 boundary-block subtree, 1eb4c33 genesis wire form + unconditional EIP-37 epoch)
Build + run the node with mainnet data; diff all 4 endpoints vs :9053: popowHeader
ById/ByHeight across sampled heights (genesis-adjacent, interlink-transition heights,
recent), `proof/{m}/{k}/{headerId}` PINNED to a fixed tip id for determinism (byte-exact
JSON after key-order normalization), several (m,k) combos. Document any divergence;
divergence = bug until adjudicated against Scala source.

### T5 — Adversarial parity review of the WHOLE popow subsystem ✅ DONE (inline: scrypto 20-shape byte parity, max_level_of 132/132, pack_interlinks Scala-exact adversarial semantics oracle-pinned, is_better_than this.m fix, Risk-6 sentinel adjudicated inert)
The pre-existing code never had its own adversarial oracle pass. In-house finder wave
(the M2-proven pattern) over: BatchMerkleProof reduction vs scrypto (Risk 1: odd trees,
all-leaf proofs, single-leaf, duplicate indices — scala-cli scrypto oracle),
`max_level_of` f64 parity vs Scala Double (Risk 6 + precision traps), pack_interlinks
consecutive-vs-all counting (Risk 4, adversarial inputs), verifier
lookback/isBetterThan/genesis handling, prover walk vs NipopowProverWithDbAlgs,
bootstrap state machine vs ErgoNodeViewSynchronizer. Findings → oracle-mapped fix
waves → regression-confirm re-verify.

### T6 — Final whole-branch review + docs ✅ DONE (docs sweep: served openapi.yaml de-staled + interlinksProof/BatchMerkleProof/continuous schemas, compatibility.md, CHANGELOG; review findings fixed: k+m checked-add on the attacker-controlled REST path, arbitrary_precision pinned locally in ergo-node)
Most-capable-model review of the full branch; update deviation notes, CHANGELOG,
memory, this plan's checkboxes.

## Risks (from recon-gap §6)
R1 BatchMerkleProof reduction parity (HIGH, unmitigated until T3/T5) · R2 use_last_epochs
hardcode (T2) · R3 REST absent (T1) · R4 pack_interlinks adversarial divergence (T5
adjudicate: fix vs ledger) · R5 wrong-proof serve (T2) · R6 genesis sentinel u32::MAX vs
Int.MaxValue (T5 adjudicate, likely ledger-only).
