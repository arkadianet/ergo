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
  never see a single input block. The value here is tuned so the JVM CPU
  miner finds an ordering block every ~30 s and, with
  `subblocksPerBlock = 64`, an input block roughly every half second.
  Raise it if the Rust node cannot keep inside assertion 5's ±2 window;
  raising `blockInterval` does not help, because nothing throttles the
  miner to it on a chain whose epoch never ends.

The Rust side needs two devnet-only overrides to match:
`[chain] devnet_initial_difficulty_hex` (same value as the Scala config)
and `[input_blocks] enabled = true`. The latter also seeds launch
parameter id 9 (`subblocksPerBlock = 64`), which the `weak-blocks`
branch carries in `Parameters.DefaultParameters` from genesis; without
it the Rust node has no multiplier and drops every announcement with
`MultiplierUnavailable` (spec §12, finding F10).

## The six assertions

1. **Peering.** Both nodes have a connected peer, and Rust's
   `/api/v1/peers` shows the Scala node at protocol `6.5.0`.
2. **`bestInputBlock` agreement**, at a moment when both nodes report
   the same `bestFullHeaderId`.
3. **`bestInputChain` agreement**, at such a moment.
4. **Reconstruction.** Over ≥ 10 ordering blocks Rust records
   `ordering_reconstructed` events, including at least one *after* a
   mid-run restart (its processor is in-memory, so it must rebuild an
   input chain from scratch first).
5. **Following.** Rust's `fullHeight` stays within 2 of Scala's, no
   `DigestMismatch` / `TxDigestMismatch` drop fires, and the Scala peer
   is never penalised or dropped.
6. **Mempool consistency.** The two `/transactions/unconfirmed` sets
   agree.

### What assertions 2 and 3 actually compare

Not id-for-id equality of the two tips. The miner publishes an input
block roughly every `blockInterval / subblocksPerBlock` — sub-second
here — while one takes a few seconds to reach the follower and validate,
so the two tips are essentially never the same id at the same instant.
Demanding that would test the sampling clock, not the protocol.

What the smoke requires instead is that the follower is on the **same
chain**: Rust's `bestInputBlock` is an entry of Scala's
`bestInputChain`, and Rust's whole chain is exactly Scala's list with
the newest *k* entries removed (`/blocks/bestInputChain` lists newest
first). Any other shape — a shared tip with a different history — is a
real divergence and fails the run with both raw bodies recorded. The
evidence file carries `rust_blocks_behind`, `exact_tip_matches` and
every observed propagation lag, so the lag is measured rather than
assumed.

### Two things this recipe cannot exercise

Both come from one root cause: **there is no spendable coin on this
devnet**, so no transaction can ever be submitted and every ordering
block contains nothing but its coinbase.

Miner rewards mature after `monetary.minerRewardDelay = 720` ordering
blocks — hours at this block rate. Shortening it is not an option: the
delay is compiled into the emission box's script, so it changes the
genesis boxes and therefore the `genesisStateDigestHex` both nodes must
share, and the Rust node's devnet genesis boxes are a pinned fixture.
The genesis founders box is behind the founders' keys, and the
no-premine box is `FalseTree`.

Consequently:

- **Assertion 6's transactions** are never submitted. The smoke still
  compares the two unconfirmed sets (they must agree, and do — both
  empty) and reports `not_exercised` with the wallet balance.
- **Assertion 4's fallback half** is unreachable. `plan_reconstruction`
  only needs input-block bodies for transactions that *came from* input
  blocks; a coinbase-only ordering block is carried by the ordering
  announcement itself, so reconstruction always succeeds and none of
  `missing_input_body` / `missing_broadcasted_tx` / `root_mismatch` can
  fire — with or without the restart. The restart is still performed,
  and the smoke does require the restarted node to reconstruct again.

Neither is silently dropped: both are listed under `not_exercised` in
`smoke-evidence.json` and printed on the result line. Closing them needs
a funded devnet (a genesis with a spendable box, which is a
consensus-visible fixture of its own) — not a change to this harness.

## Evidence

`smoke.py` writes `.work/smoke-evidence.json` on every exit path,
successful or not, carrying: the Rust git sha, toolchain and working-tree
status; the Scala classpath and `appVersion`; a sha256 of every file in
this directory; and, per assertion, the raw REST bodies behind the
verdict. On a failure it also records both nodes' `/info` at the moment
of the failure. A Rust-vs-Scala disagreement additionally belongs in
`test-vectors/weak-blocks/findings/<date>-<n>.json` with the raw bodies.
