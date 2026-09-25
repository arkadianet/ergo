# `devnet-matrix` — mixed-node input-block (Matrix) smoke

A private two-node devnet where a **Scala `weak-blocks` node mines** both
ordering blocks and input blocks, and the **Rust node follows**: it
validates the input blocks, keeps an input chain, and reconstructs
ordering blocks from it instead of downloading `BlockTransactions`.

This is the M2 merge gate. It is the sibling of `scripts/devnet-mixed/`
(which pits the Rust node against a *stock* 6.0.5 node over the ordinary
block path) and shares its process-ownership and port-guard shape, but
nothing else: different Scala build, different ports, different miner.

## Ports and data

| | P2P | REST |
|---|---|---|
| Scala | 19560 | 19580 |
| Rust | 19561 | 19581 |

Everything the run writes lives under `scripts/devnet-matrix/.work/`
(gitignored): both node data directories, both logs, the PID files the
lifecycle script owns, the Scala wallet mnemonic, and
`smoke-evidence.json`.

These ports are private to this recipe. They do not overlap
`devnet-mixed` (19530/19531/19553/19554) or any long-running node.

## Running it

```bash
cargo build -p ergo-node
export MATRIX_CLASSPATH=/path/to/scripts/jvm_weak_blocks_oracle/.work/classpath
scripts/devnet-matrix/start.sh
python3 scripts/devnet-matrix/smoke.py --timeout 900
scripts/devnet-matrix/stop.sh     # always, including after a failure
```

`MATRIX_CLASSPATH` points at the classpath file of the Scala
`weak-blocks` build (defaults to this checkout's own
`scripts/jvm_weak_blocks_oracle/.work/classpath`). `start.sh` refuses a
node whose `/info` lacks the `bestInputBlock` key or reports a stock
release version — that node has no input blocks at all and the smoke
would be measuring nothing.

Other knobs: `RUST_NODE` (a prebuilt binary), `SCALA_CONFIG` /
`RUST_CONFIG` (alternate configs, still recognised by `stop.sh`), and
`RUST_LOG` (`info,ergo_node::node::input_blocks=debug` is what the
recorded runs used).

`stop.sh` only ever signals a PID this recipe recorded in
`.work/*.pid`, and only while that PID still runs from this checkout
against the config it was launched with. Nothing is ever matched by
process name.

## Why the Scala node is configured the way it is

- **The `weak-blocks` branch has no switch for input blocks.** They are
  produced unconditionally by the internal miner (`ErgoMiningThread` →
  `InputBlockFound` → `CandidateGenerator.LocallyGeneratedInputBlock`)
  and gated towards peers only on protocol version ≥ 6.5.0. So
  `mining = true`, `offlineGeneration = true`, and — unlike
  `devnet-mixed` — `useExternalMiner = false`: there is no external
  solver here.
- **The Scala wallet must be initialized and unlocked** before the
  internal miner will build a candidate (`Miner can't load secret key
  from wallet: Wallet is locked`). `lifecycle.py` does that between
  starting the Scala node and starting the Rust node, and keeps the
  mnemonic under `.work/` so a restart restores the same wallet.
- **`initialDifficultyHex` is NOT 1.** `AutolykosPowScheme.checkNonces`
  classifies a solution as an ordering block when `d <= b` and as an
  input block when `b < d <= b * subblocksPerBlock`. At difficulty 1,
  `b = q` and *every* solution is an ordering block — the recipe would
  never see a single input block. `004e20` (20 000) is hand-tuned to
  this host: **measured ~22 ordering blocks and 1172 input blocks over a
  20-minute run** — an ordering block every ~55 s and, with
  `subblocksPerBlock = 64`, an input block roughly every second. A
  slower or faster machine wants a different value, and **the Scala
  `initialDifficultyHex` and the Rust `devnet_initial_difficulty_hex`
  must be changed together**. Raising `blockInterval` does not help:
  nothing throttles the miner to it on a chain whose epoch never ends,
  so the target is the only lever on the rate.

  Two traps when retuning:

  * **Keep the leading byte below `0x80`.** Scala decodes
    `initialDifficultyHex` to BYTES and reads them as a *signed* BigInt,
    so `"9c40"` is NEGATIVE, `b = q / difficulty` goes negative, and no
    solution ever qualifies — the miner spins on millions of nonces
    finding nothing, with no error anywhere. Write `"009c40"`.
  * **Do not raise it much past 20 000 on this host.** The Scala miner
    stops at the first solution per candidate and regenerates the
    candidate every `internalMinerPollingInterval`; since input blocks
    are 64x likelier, ordering solutions are found but usually arrive
    when `cachedCandidate` has already been cleared. At 40 000 a
    7-minute run produced 1055 input solutions, 21 ordering solutions
    and **zero** accepted ordering blocks. The chain stalls without
    erroring.

- **`[input_blocks] strict_field_binding = false`.** The pinned miner
  announces a `prevTransactionsDigest` its own extension does not commit
  to (`CandidateGenerator.scala:752` vs `:758`), so the strict binding
  check rejects every input block that carries a transaction. The recipe
  runs in Scala-parity mode; the port default stays strict. See
  `test-vectors/weak-blocks/findings/2026-09-22-2.json`.
- **`[input_blocks.bounds] waitlist_entries = 8192`.** The stock 256
  overflowed 280 times in a 20-minute run at this input-block rate.

The Rust side needs three devnet-only overrides to match the Scala
config: `[chain] devnet_initial_difficulty_hex`,
`[chain] devnet_miner_reward_delay`, and `[input_blocks] enabled = true`. The latter also seeds launch
parameter id 9 (`subblocksPerBlock = 64`), which the `weak-blocks`
branch carries in `Parameters.DefaultParameters` from genesis; without
it the Rust node has no multiplier and drops every announcement with
`MultiplierUnavailable` (spec §12, finding F10).

## The six assertions

All six are REQUIRED. There is no "not exercised" outcome: an assertion
that cannot be observed fails the run.

1. **Peering.** Both nodes have a connected peer, and Rust's
   `/api/v1/peers` shows the Scala node at protocol `6.5.0`.
2. **Tip consistency under lag.** Every `bestInputBlock` Rust reports
   must be a block Scala had on its best chain for the **same ordering
   block**, and the lag — how many input blocks Rust's tip trails
   Scala's by — must have **p95 ≤ 8 and max ≤ 16**. Exact instantaneous
   equality is *recorded* (`exact_tip_matches`) but not required: the
   miner publishes ~64 input blocks per ordering block, so equality at a
   sampled instant measures the sampling clock, and lag is not
   divergence. A tip Scala never had on its best chain IS.
3. **Chain consistency.** At every same-ordering-block sample Rust's
   `bestInputChain` must be a **prefix of Scala's read oldest-first**
   (i.e. Scala's list with the newest *k* entries removed). Zero
   violations. A different history at any depth fails the run.
4. **Reconstruction, both outcomes.** The first ordering block after a
   cold mid-run restart must be an `ordering_reconstruct_fallback` (any
   reason — it is recorded, and `root_mismatch` is what a cold node
   produces: with no input chain the planner names no body, so
   `missing_input_body` cannot fire), and a later one must be an
   `ordering_reconstructed`
   carrying **more than one transaction** — a coinbase-only block proves
   nothing, because the ordering announcement carries its coinbase
   itself. The restart happens under load (see below).
5. **Following.** Rust's `fullHeight` stays within 2 of Scala's for the
   whole run, only the first 60 s after each process start excluded (the
   post-restart catch-up is deliberately included); no `DigestMismatch`,
   `TxDigestMismatch` or `Penalize` counter ever moves; the Scala peer is
   never penalised, dropped, or seen with a negative score.
6. **Mempool.** 20 payments submitted through the Scala wallet must each
   return HTTP 200; each must be observed inside a Rust input block via
   `/blocks/{id}/inputBlockTransactionIds`; each must then be gone from
   Rust's `/transactions/unconfirmed`; and after the next ordering block
   the two pools must agree, with explicit D1/F6 accounting — residue is
   permitted in Scala's pool only, never in Rust's.

Every reconstruction also reports `reconstructedOrder` (`scala` |
`candidate` — divergence D4, upstream finding F12) and
`reconstructionKey` (`self` | `parent` — divergence D5, upstream finding
F5), and the run tallies both. Those two fields are how an operator sees
which upstream disagreement each block had to work around.

### What assertions 2 and 3 actually compare

Not id-for-id equality of the two tips at one instant. The miner
publishes an input block roughly every `blockInterval / subblocksPerBlock`
— about a second here — while one takes a few seconds to reach the
follower and validate, so the two tips are essentially never the same id
at the same moment. Demanding that would test the sampling clock, and
lag is not divergence.

What the gate requires instead is **consistency**: Rust is never on a
block Scala did not have on its best chain, Rust's chain is always a
truncation of Scala's rather than a different history, and the lag stays
inside hard bounds (p95 ≤ 8, max ≤ 16 input blocks). `exact_tip_matches`
is still counted and reported as an aspirational metric.

The two evaluators are pure functions over the sampled series and are
unit-tested on synthetic series:

```bash
python3 scripts/devnet-matrix/smoke.py --self-test
```

The run keeps the raw series in `smoke-evidence.json`
(`agreement_series_sample`), so a verdict can be recomputed from the
evidence rather than trusted because the harness printed it.

### The funded workload

Assertions 4 and 6 need real transactions, which need spendable coin.
`monetary.minerRewardDelay = 10` (Scala) and `[chain]
devnet_miner_reward_delay = 10` (Rust) shorten reward maturity from 720
blocks to 10, so the miner's wallet is spendable around height 11.

The delay is compiled into the emission box's proposition, so it changes
the genesis boxes and the height-0 state root. That is why the Rust side
needs a captured box set per delay
(`GenesisParams::devnet_for_reward_delay`, from `GET /utxo/genesis` on
the pinned Scala node) and why `lifecycle.py` refuses to start a node
whose height-0 `stateRoot` is not the shared one. Get this wrong and the
nodes fork at genesis while every later assertion still appears to run.

A background thread keeps submitting payments during assertion 4, so the
miner is sealing transactions into input blocks across the restart. The
wallet spends its single change box, so most submissions in that thread
fail with "no boxes" — that is expected and is not an observation about
either node; only the accepted ones matter.

### Harness rules

* **A failed REST call is never an observation.** It is retried within
  budget and then fails the assertion that needed it. An empty list from
  a dead endpoint must not compare equal to an empty list from a live one.
* **Failures accumulate.** One failed assertion does not abort the rest;
  the run reports all of them, and the counters in assertion 5 are
  accumulated across both node processes (a restart resets the node's own
  counters, so the harness carries the pre-restart totals forward).
* **Every mismatch writes an artifact** under `.work/findings/<date>-<n>.json`
  with both nodes' REST bodies, the Rust ordering-event tail, the
  debug-log window around the observation's own timestamp, and the RAW
  announcement bytes for every block id the failure names. Artifacts are
  uncapped and land in `.work/` (gitignored); a human promotes the ones
  worth keeping into `test-vectors/weak-blocks/findings/`.
* **Announcement bytes come from one dedicated node line**, not from
  scraping hex off any line that mentions the id — a parent id on such a
  line used to be filed as the block's own payload. The recipe's
  `RUST_LOG` enables `ergo_node::node::input_blocks::announcements=trace`
  for it, and `ergo-node`'s
  `the_announcement_payload_line_has_the_shape_the_harness_parses` pins
  the format the extractor matches.
* **The pool observation belongs to one sweep.** Assertion 6 reads the
  ordering tip, the input-block chain and Rust's unconfirmed pool from
  the SAME sampler sweep, and that sweep re-reads the tip after the pool
  — if an ordering block landed across the pair, the sample is recorded
  and skipped rather than used to credit an eviction.
* **The heartbeat only advances on a sweep that produced a reading**, so
  a final interval in which every REST call failed cannot satisfy the
  sampler-freshness check; and the restart JOINS the in-flight sweep
  (rather than sleeping) before snapshotting BOTH nodes.

## Evidence

`smoke.py` writes `.work/smoke-evidence.json` on every exit path,
successful or not, carrying: the Rust git sha, toolchain, binary path and
working-tree status; the Scala classpath, pinned and observed
`appVersion`; the shared genesis state root; a sha256 of every file in
this directory; per assertion the raw REST bodies behind the verdict; and
the full failure list.

Build the node in **release** before running: the follower's throughput
is what assertions 2, 3 and 5 measure, and a debug build is not a
measurement of the shipped node. `lifecycle.py` prefers
`target/release/ergo-node` and falls back to debug.

## M4: builds, roles and the ablation switch

M4 proves one upstream patch at a time, so the harness had to learn two
things the M2/M3 shape did not need: which BUILD a node is running, and
what JOB it is doing.

### Builds

`builds.toml` lists the provisioned Scala builds by the names
`campaign.py --build` / `--base-build` accept — `stock`, `F16`, `F12F05`,
`F14`, `F13`, `F04`, `F11`, `all`; the #2563 re-measure's `base`,
`base+2506`, `2563f` and `2563f+2506`; the #2562 two-miner build `2562f`;
and the integration build `soak` — and `builds.py` loads them. They live
in the shared archive `../matrix-evidence/scala-builds` beside the
checkouts. The M4 entries
were moved there from a deleted worktree and their classpath files still
name it, so they are refused until re-provisioned (see the file's
header). A build's identity is
its COMPILED OUTPUT as well as its source commit. Each entry's
`ergo_ref` is a full commit id (a branch name is refused), and a build
whose manifest records another `ergo_commit` is refused until it is
re-provisioned. `class_dir_sha256` is the
SHA-256 over the sorted `<project>/<path>` plus content of every class
file on the exported runtime classpath, and a node refuses to start on a
build that no longer reproduces its manifest's hash. Two work
directories at the same commit can still differ (a half-finished
`sbt compile`, a stale incremental cache, an edited file), and a devnet
number attributed to the wrong build is worse than no number.

```bash
python3 scripts/devnet-matrix/builds.py            # list
python3 scripts/devnet-matrix/builds.py --verify   # re-hash each one
```

Every scenario's evidence file records `builds: {role: manifest}`, so a
number in it is attributable or it is not evidence.

### Roles

| role | node | p2p | REST | job |
|---|---|---|---|---|
| `scala_miner` | scala | 19570 | 19590 | the stock reference miner |
| `scala_miner_patched` | scala | 19570 | 19590 | the same slot on `--build` |
| `scala_miner2` | scala2 | 19571 | 19591 | the second miner (fork, rollback) |
| `scala_follower` | scala2 | 19571 | 19591 | the STOCK reference follower |
| `scala_follower_patched` | scala3 | 19573 | 19593 | the patched reference follower |
| `rust_follower` | rust | 19572 | 19592 | the port under test |

(Campaign ports; the smoke's own band is 19560-19563 / 19580-19583.)
A node is a process slot; a role is what it is doing in an experiment.
Roles that share a slot are alternatives, and `campaign.py --self-test`
refuses a scenario whose roles do not map one-to-one onto its nodes.
Whether a Scala node mines is derived from its ROLE, so a follower role
added later cannot silently become a second miner.

The role table lives in `roles.py` rather than `lifecycle.py` on
purpose: `lifecycle` reads its ports from the environment AT IMPORT, and
the campaign resolves roles before it sets them.

### `--build` and `--reference-follower`

`--build <name>` (default `stock`) selects the build for every
`*_patched` role; every other Scala role runs `--base-build` (`stock` by default). That is what
makes a run an ablation — base + one patch against base — rather than a
comparison of two integration builds (spec §7a). An unknown build stops
the run; a declared but unprovisioned one stops it with the
`provision.py` command that would create it.

`--base-build <name>` (default `stock`) is the build of every OTHER
Scala role: the miner(s) and the stock reference follower. It moves the
base under an ablation — the #2563 re-measure runs its miner and stock
follower on `base` (weak-blocks @ a1bd938ef), and a sender-side change
such as #2506 needs the MINER on it — and it applies to every scenario,
including `fork` (both miners) and `reconstruct_rate` (miner and stock
follower).

`--reference-follower stock|patched|both` is accepted by `steady`,
`restart`, `fork` and `reconstruct_rate`. `fork` and `rollback` spend the
`scala2` slot on their second miner, so `stock` and `both` are REFUSED
there with the reason rather than silently downgraded.

### The #2563 re-measure (REVIEW-2563 §3.3)

* `restart --restart-victim scala-followers` (needs
  `--reference-follower`) SIGKILLs every Scala reference follower at the
  same instant, respawns them, and leaves the miner and the Rust
  follower running; the sampler records the victims as down instead of
  losing the sweep. Per victim it reports convergence, the post-kill
  reconstruction accounting and waitlist, and `restart_recovery`: seconds
  from respawn to the miner's tip and the pending store's replay burst in
  the 30 s after the first post-restart apply. `rust` (the default) is
  the M3 scenario. `--ordering-blocks` sets the funded pre-kill window
  and `--post-ordering-blocks` the post-kill one (default 5).
* Every agreement-series sample carries each Scala node's
  `/info.pendingInputAnnouncements` (`pending`), and every evidence file
  summarises it per node (`pending_store`: peak entries and bytes, and
  how much each counter — admitted, replayed, replayNotForwarded,
  evictions, drops by reason — grew, restarts folded in). A build without
  the store reads `absent`. `telemetry` names the shape: `fixed
  telemetry` is the reviewed store (#2563 13fc25df2: `size`, `bytes`,
  `admitted`, `replayed`, `replayNotForwarded`, `evictions`, and `drops`
  by `duplicate`, `hostLimit`, `variantLimit`, `oversize`, `expired`,
  `staleParent`, `disconnected`); `old telemetry` is the pre-review
  store's single `drops` number; anything else is `unrecognised
  telemetry` with its `missing_fixed_keys` listed. A held flood against a
  patched follower requires fixed telemetry.
* Every Scala role's reconstruction accounting carries `waitlist`
  (`Put input block to disconnected queue` per ordering block — each is
  also a parent download) and `root_announcements` (+2 roots seen and
  later valid).
* `flood` uses the shipped caps (`perPeer = 128`) and takes
  `--flood-mode hit-and-run|held` against a Scala follower: fresh hosts
  per wave closed at once (the default), or one connection per host held
  past the TTL with 160 announcements per host per wave
  (`p2p_adversary ... input_block_root_flood ... --hold-ms`).
  `P2P_ADVERSARY` names a prebuilt adversary, as `RUST_NODE` names the
  node.

### Reconstruction accounting

Every scenario's evidence now carries the same five numbers per role, so
a patched follower can be read against a stock one:

| field | Rust (event feed) | Scala (`ErgoNodeViewHolder`, 62c10315) |
|---|---|---|
| `eligible_announcements` | every outcome event | `Processing ordering block announcement for` |
| `reconstructed` | `ordering_reconstructed` | `Applying block transactions from input-blocks for` |
| `download_missing_tx` | fallback `missing_broadcasted_tx` / `missing_input_body` | `… as not all the transactions available` |
| `download_root_mismatch` | fallback `root_mismatch` | `… as Merkle root does not match` |
| `skipped_no_chain` | `ordering_reconstruct_skipped` | `Parent header not found for ordering block` |

An outcome that is none of the five (a `storage_error` fallback) is
counted in the DENOMINATOR and reported separately, never folded into a
bucket it does not belong to. A Scala build that logs none of the five
reads as UNKNOWN, not as a clean run of zeroes.

### `miner_self_reject`

A MEASUREMENT scenario with no pass criterion, for F11: it runs one
Scala miner on `--build` for 40 ordering blocks under a funded workload
and counts submissions, successful replies, error replies, submissions
that got NO reply, PoW failures, applied input blocks, and how many of
those reached the best input chain. A stock run is the baseline the
patched run is read against; `never_sealed = 0` alone proves nothing,
which is why all six denominators are reported together.

PoW failures are counted from the generator's own WARN in either
wording — stock `Removing candidate due to invalid input block`, F11
`No retained candidate matches input solution PoW` — anchored on the
`WARN org.ergoplatform.mining.CandidateGenerator - ` prefix so F11's
`StatusReply$ErrorMessage` echo of the same words is not counted
twice. The ordering arm, F11's stale-parent rejection and F11's other
reply arms (already known, pending, already solved, invalid solution,
timeout, deferral limit) are counted separately, never as PoW
failures. `rejections_exceed_error_replies` flags a window with more
rejections than `ErgoMiningThread` error replies.
