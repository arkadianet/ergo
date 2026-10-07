# ergo-difftest

**Purpose:** A development-only diagnostic harness (`publish = false`), outside
the production node dependency graph. Its stable campaigns check Rust decoder
unwinds and read/write fixed points. Optional pinned Scala processes compare
acceptance, serialization, reduction/cost and selected verification contracts.
A result needs its context and authority record; agreement in one dummy context
is not a general consensus verdict.

**Workspace dependencies:** ergo-primitives, ergo-ser, ergo-sigma, ergo-state,
ergo-validation, ergo-rest-json and ergo-p2p. The detached native fuzz workspace
is excluded from root stable builds.

## Start here

- `src/bin/difftest.rs` dispatches CLI campaigns, repro, canonical checks,
  minimization, MethodCall probes and coverage gates.
- `src/lib.rs` defines `Outcome`, `Finding`, `Stats`, `run_campaign`,
  `run_structured_campaign`, `run_input` and the subprocess selftest.
- `src/surfaces.rs` defines the 28-entry hermetic registry and shared fixed-point
  checks. It separates rejected input, intentional write refusal and invariant
  Bug outcomes. Some readers initially consume only a prefix.
- `src/oracle.rs` defines `Oracle`, `SurfaceSpec`, verdict comparison and the nine
  differential surfaces: `ergo_tree`, `ergo_box_candidate`, `transaction`,
  `header`, `reduce`, `reduce_ctx`, `verify`, `validate`, `verify_avl`.
- `src/bin/replay.rs` implements contiguous early-mainnet heights 1–200 with a
  fixed diagnostic context. Requested/decoded/pinned identities are bound;
  pins count only after successful application and a matching state root.
  Historical later pins do not implement deep replay.

## Modules and evidence flow

| Module | Responsibility |
|---|---|
| `generate.rs`, `rng.rs` | Deterministic byte mutation and SplitMix64 input generation |
| `gen/mod.rs` | Structured generation, 35-feature vocabulary (34 adversarial plus baseline), intended-valid metadata and coverage accounting |
| `gen/asm.rs` | Shared wire assembly constants/helpers |
| `gen/{ergo_tree,sigma_expr,box_candidate,transaction,header,constant}.rs` | Surface-specific construction; structured verify/AVL frames remain unsupported |
| `oracle.rs`, `oracle/transport.rs` | Private Scala source snapshots, bounded startup/query I/O and diagnostics, actual JVM/JAR provenance, terminal cleanup |
| `avl_frame.rs` | Shared AVL operation frame codec |
| `methodcall.rs` | MethodCall registry probes using the independent TSV enumeration |
| `minimize.rs` | Predicate-preserving shrinking and final re-verification |
| `regressions.rs` | Original/minimized record construction; unexplained differences remain Pending |
| `regressions/storage.rs` | Full-record SHA256 identity, immutable publication, filing lock and derived queue |
| `execution_metadata.rs`, `build.rs`, `source_inventory.rs` | Build-time source/compiler observation (baseline keys bind compiled inputs only), running executable hash, exact reference source archive and immutable execution journal |
| `fuzz.rs` | Stable codec `fuzz_one` wrapper; Bug becomes an outer panic |
| `network_fuzz.rs` | Production P2P codecs and a bounded delivery-tracker model |
| `execution_fuzz.rs` | Bounded compiler-source and evaluator checks |

`DivergenceRecord` preserves surface, kind, input, verdicts, generating
seed/iteration/mode, minimization status/error, execution journal and pending
triage. Processing failures preserve the original record and report incomplete
harness work. `auto_file` uses the **full canonical JSON record SHA256**, not a
short input hash. Concurrent filing derives `QUEUE.md` from verified pending
records under a lock. Existing conflicting/corrupt records are not overwritten;
this is not power-loss durability certification.

The CLI archives exact primary/verify Scala sources and journals under
`<output>/runs/`. The guard validates records, source archives, actual reference
identity and a stable comparison-authority baseline key. Legacy short input
baselines cannot mute new authority-bound records. Repro selects archived
sources. Build metadata observes source before compilation; it is not a signed
attestation against arbitrary concurrent changes.

## Contracts and limits

- **Stable hermetic checks:** `catch_unwind` converts decoder unwinds to Bug
  without changing the caller's global panic hook. Aborts, stack overflow and
  allocation failure remain outside that mechanism.
- **Fixed points:** structural and byte convergence checks include explicit
  reference-backed exceptions. Rust fixed-point success does not establish
  transaction validity, chain membership or external parity.
- **Reduction:** `reduce` uses a fixed dummy context; `reduce_ctx` supplies a
  context extension and SELF candidate frame. Neither supplies a matched nonempty
  reference header window. Framed proof verification is a separate surface.
- **Oracle transport:** startup and per-query deadlines cover writes/reads;
  lines and stderr are bounded. Cleanup owns a Unix process group. Windows
  descendants and escaped Unix groups are not certified.
- **Known bugs:** `known_bugs/manifest.toml` currently has 39 catalog records.
  Entry presence does not prove its trigger or generator rediscovery. The
  reinjection source runner requires finding exit1 with the declared channel,
  refuses unsupported `--generated`, and reports an all-skipped run incomplete.
  Saved-log classifier tests are not independent detector execution.
- **Replay:** genesis application is unchecked; node PoW is trusted, parent
  extensions are omitted and AD proofs are not fed to state apply. Failure stops
  replay because later heights require the applied state. Its root comparisons
  are diagnostics, not full reference-node/bootstrap certification.

## CI and detached fuzz targets

Root PR CI runs stable checks and a structured hermetic coverage gate. A
separate pinned-nightly job checks the detached lock with `cargo metadata
--locked`; it does not build/run native targets. Scheduled/manual `fuzz.yml`
runs structured/mutation campaigns, optional JVM comparisons, conditional
archival replay and a 12-leg cargo-fuzz/ASan matrix:

- Six codec targets: `ergo_tree`, `constant`, `ergo_box_candidate`, `transaction`,
  `header`, `sigma_expr` (the last checks tree parsing, not JVM reduction).
- Four P2P targets: `p2p_frame`, `p2p_handshake`, `p2p_message`, `p2p_delivery`.
- Two execution targets: `compiler_source`, `bounded_evaluator`.

Each native leg records source/lock/tool/binary/environment/seed identities and
command logs through `scripts/fuzz-evidence.py` and `fuzz-step.sh`, and always
uploads a bundle with explicit incomplete/failed states. These helpers have
ordinary filesystem unit coverage. Workflow wiring does not prove native
Bug-to-failing-process-to-matching-artifact, replay or actual upload execution.

Unset `REPLAY_NODE_URL` is explicitly **not tested**; deep epoch reconstruction
is unimplemented. Use [fuzz setup](../../ergo-difftest/fuzz/README.md),
[interface contracts](../../ergo-difftest/docs/interface-contracts.md) and the
[current workflow](../../.github/workflows/fuzz.yml) for commands and scope.
Historical campaign reports retain their original revision/evidence limits.
