# Mixed Scala/Rust devnet

This recipe runs Scala Ergo **6.0.5 / sigma-state 6.0.6** and the Rust node
built from this worktree on one isolated chain. Both nodes validate every
block. The external worker submits a solution to the selected node's mining
API, then waits for the other node to receive and validate the block over
P2P. It never relays blocks through HTTP during the smoke.

## Run

From the repository root, with the Task 6.2 JVM classpath already provisioned:

```sh
test -z "$(git status --porcelain)"
git rev-parse HEAD
cargo build -p ergo-node
scripts/devnet-mixed/start.sh
python3 scripts/devnet-mixed/smoke.py --first rust --blocks 100
scripts/devnet-mixed/stop.sh
```

Always run `stop.sh`, including after a failed smoke. It stops only processes
whose command line and working directory identify this recipe. Data is
preserved; the smoke requires fresh height-zero state. To rerun, stop both
nodes and move `.work/rust` and `.work/scala` aside within `.work/` first.
`start.sh` refuses occupied ports and cleans up its nodes on startup failure.
Use `RUST_NODE=/absolute/path/to/ergo-node` to override the default configured
Cargo-target binary at `/home/rkadias/.cache/cargo-target/debug/ergo-node`.

The classpath comes from `scripts/jvm_block_oracle/.work/classpath`.
Its provisioning script extracts Ergo commit
`5528ef569a41ebccbc8658212e6ee3c97d990b96` and adds the documented
identity-return cost observer to `UtxoState`. This recipe does not alter that
classpath or source tree. It launches `org.ergoplatform.ErgoApp` directly.
Java 17 and scala-cli 1.12 are used. `Solve.scala` pins Scala 2.12,
ergo-core 6.0.5, sigma-state 6.0.6 and circe-parser 0.14.15.

## Chain identity

| Setting | Shared value |
| --- | --- |
| P2P magic | `[7, 7, 7, 7]` |
| Address prefix | `16` |
| Genesis state root | `cb63aa99a3060f341781d8662b58bf18b9ad258db4fe88d09f8f71cb668cad4502` |
| Genesis boxes | `test-vectors/testnet/genesis_boxes.json` (three JVM boxes) |
| Pinned height-one header | None; generated for each fresh campaign |
| Initial difficulty | `1` (`initialDifficultyHex = "01"`) |
| Difficulty / voting epoch | `33554432` (`1 << 25`) |
| Block interval | `20s` |
| Soft-fork / activation epochs | `32` / `32` |
| Monetary rules | Standard emission, reward delay `720` |
| Re-emission | Disabled |
| Launch block version | `4`, empty validation-rule update |
| Public seeds / checkpoints | None |

`genesis.conf` defines the Scala overrides; `ChainSpec::devnet()` mirrors
them in Rust. Scala's `networkType = "devnet60"` selects the version-4
launch parameters. Plain Scala `"devnet"` selects version 3 instead.
Rust selects its private spec with `network = "devnet"`. No public-network
seed is appended. Epoch boundaries are beyond this campaign, rather than
removed mathematically: do not run this recipe to height 33,554,432.

The Rust miner supports the seeded height-zero state and short header windows.
It keeps an empty `CONTEXT.headers` at genesis and the actual available
headers before height ten. Its height-zero carrier is never persisted or
included in interlinks. Only devnet announces locally accepted mined headers
immediately; this also lets an empty Scala peer request a Rust genesis block.
Mainnet/Testnet retain their existing mining gates and consensus parameters.

Scala's candidate generator emits a **version-1 first header**, even with
version-4 launch parameters. `--first scala` therefore uses the pinned JVM
Autolykos-v1 solver for that first solution. Rust's first header is version 4;
subsequent candidates use version 4. Difficulty-one v2 work accepts the
recorded zero nonce; both nodes perform their normal PoW checks.

## Ports, files, and keys

| Item | Value / path relative to `scripts/devnet-mixed/` |
| --- | --- |
| Scala REST / P2P | `127.0.0.1:19553` / `127.0.0.1:19530` |
| Rust REST / P2P | `127.0.0.1:19554` / `127.0.0.1:19531` |
| Chain overrides | `genesis.conf` |
| Node configs | `scala-node.conf`, `rust-node.toml` |
| Lifecycle | `start.sh`, `stop.sh`, `lifecycle.py` |
| External worker / driver | `Solve.scala`, `smoke.py` |
| Console logging config | `logback.xml` |
| Node databases | `.work/scala/`, `.work/rust/` |
| Logs / PIDs | `.work/{scala,rust}.log`, `.work/{scala,rust}.pid` |
| Runtime evidence | `.work/smoke.json`, `.work/smoke.log` |

All listening sockets are loopback. No use is made of ports 9053, 9063, 9052,
9073, 9072, or 19099, or of installations under `~/apps`.

Both miners pay the public test key with secret scalar **1**, compressed
public key `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`.
The API key is the standard local test key **hello**. These values are
intentionally reproducible and carry no real funds.

**Funding limitation:** this uses the independently verified standard genesis
box set. It does not initialize wallets with spendable genesis allocations.
Mining rewards mature after 720 blocks. **Task 7.3 owns the wallet-funding
prerequisite**, including mining through the 720-block maturity delay before
funded-wallet workloads. This recipe proves the mixed-node mining/validation
prerequisite; the full cost-heavy L6 campaign remains separate.

## Smoke evidence

The driver selects 100 blocks, strictly alternating 50 Rust / 50 Scala. For
each block it records both nodes' height, block ID and state root, plus miner,
header version, candidate and solution, and waits for matching commitments on both nodes.
The manifest also records node versions, source and executable hashes, config
and tool hashes, and selected/executed/skipped/failed counts.

The committed receipts below are regenerated from a clean committed source tree.
`smoke.py` rejects a dirty tree and records `git rev-parse HEAD`, empty
`git status --porcelain` before and after the campaign, and the running binary's
SHA-256. Both nodes' commitments are persisted at every height and checked by
reading the receipt back from disk.

Verify the committed receipt and its source inputs:

```sh
python3 scripts/devnet-mixed/verify-receipt.py
```

To reproduce the build, use the receipt's `rust.git_sha` in this worktree with a
clean status, then run `cargo build -p ergo-node` with the recorded toolchain
and default features. Compare `sha256sum /home/rkadias/.cache/cargo-target/debug/ergo-node`
with `rust.binary_sha256` (build paths and toolchain must match).

No cost-ledger rows are closed by this recipe.

Recorded fix-round run: **PASS — 100 selected, 100 executed, 0 skipped, 0 failed**;
50 Rust-mined and 50 Scala-mined blocks, strictly alternating. All 100 paired
observations match and all headers are version 4. Both nodes reached height **100**:

- Block ID: `dc71492d5dd58b583dca84e4642e17dc91f904535ced226a49a2e92071225953`
- State root: `3e87598aebaf1ff398cedc3b56394fa963132b3f33cb4ad038be84445c074ec608`
- Clean source revision: `3cdc04e7db47f140cb05dc05c04a70526a935902`
- Binary SHA-256: `6e57a5719907f5e8bfe29a12dd73cfdd2692f7277c7b62b163bf0783c98902b3`
- Started (UTC): `2026-09-16T00:01:07.529177+00:00`
- Elapsed: **3060.232 seconds**

See [per-block evidence](smoke-evidence.json) and the
[environment, source, gate and shutdown receipt](smoke-environment.json).
Formatting and warning-denying clippy passed. Nextest was unavailable;
`cargo test --workspace` passed with **6,997 passed, 0 failed,
97 ignored** including doctests. Both nodes were stopped and all four
recipe ports were verified closed.

## Direct full-block submission (Task 7.2)

Rust `POST /blocks` requires **both** `Network::Devnet` and
`[api] allow_direct_block_submit = true` (enabled in `rust-node.toml`).
The default is false. Mainnet and testnet return HTTP 403 even with the flag;
the gate runs before JSON decoding. The bridge also enforces the gate before
PoW checking or sending any event. The existing header/section validation and
`LocalFullBlock` → `inject_local_full_block` → `Action::AssembleBlock` path
performs the same block application as sync. HTTP 200 acknowledges admission;
check the full tip and state root to confirm application.

Scala already provides this route: source pin v6.0.2
`src/main/scala/org/ergoplatform/http/api/BlocksApiRoute.scala:126` checks PoW,
then sends `LocallyGeneratedModifier` for the header and each section.
`ErgoNodeViewHolder.scala:664` passes these to `pmodModify`; its state update
at line 233 calls `state.applyModifier`. This path does not submit transactions
to the mempool. The live verification uses Scala 6.0.5 / sigma-state 6.0.6.

To build a full REST block on the current Scala devnet tip:

```sh
scripts/devnet-mixed/stop.sh
cargo build -p ergo-node
scripts/devnet-mixed/start.sh
python3 scripts/devnet-mixed/build-block.py --live scripts/devnet-mixed/.work/block.json
# Or supply an exact, ordered array of signed Scala transaction JSON objects:
python3 scripts/devnet-mixed/build-block.py --live transactions.json scripts/devnet-mixed/.work/block.json
# Verify a new direct submission to each node and matching tips/state roots:
python3 scripts/devnet-mixed/direct-submit.py
scripts/devnet-mixed/stop.sh
```

Always stop the recipe after a failure, using `stop.sh`. The builder only reads
REST port 19553. `BuildBlock.scala` reconstructs the configured genesis and
replays the parent blocks into a temporary database under `.work/`, generates
JVM AVL proofs, mines at difficulty 1, and validates the result with
`UtxoState.applyModifier`. It never opens a live node database. With no supplied
transactions it builds an emission transaction; a supplied nonempty array is
used exactly as given. The result is ready for either node's `POST /blocks`.
No mining-solution or mempool submission is involved. The existing positional
`build-block.py REQUEST OUTPUT` synthetic-fixture mode remains available.

This builder is for short, unforked private chains before the first voting
boundary (33,554,432); it replays from genesis on each invocation and refuses
ambiguous height lookups or a tip that changes during construction. It validates
supplied transactions, so intentional invalid-block construction remains a
separate campaign concern.

Verified on 2026-09-16 UTC, continuing the preserved 100-block recipe chain:

| POST recipient | Height reached by both | Block ID |
| --- | --- | --- |
| Rust, 19554 | 101 | `9d6b7e362764bb1b357d1e693fe34a288420acfaa2b5dc8eedc70bcf11788355` |
| Scala, 19553 | 102 | `71c44eba17b6a435221894316260c4b8dd057ecd61ed08bb5189a42bede09707` |

Both requests returned HTTP 200; both nodes reported the submitted block ID
and identical state roots after each request. The other node received each
block through P2P. `direct-submit-evidence.json` records versions, source and
binary hashes, input/output hashes, parameters, and observations (2 selected,
2 executed, 0 skipped, 0 failed). This is a pre-commit working-tree verification;
the receipt records its base revision and working diff hash. Both recipe-owned
processes were stopped using their PID files after verification. No cost-ledger
row is closed by this transport test.

## Cost campaign (Task 7.3 — blocked)

```sh
cargo build -p ergo-node
scripts/devnet-mixed/campaign.sh --direction scala-mines
scripts/devnet-mixed/campaign.sh --direction rust-mines
```

The driver owns startup and PID-file shutdown, including failures. It uses
separate `.work/campaign-{scala,rust}` databases and the same four private
ports. It mines 720 difficulty-one reward blocks to scalar one before funding
its campaign wallet from a mature reward. `CampaignParameters.scala` supplies
a private `Devnet60LaunchParameters` class with parameter 4 = **37509**;
Rust's `[chain] devnet_max_block_cost` supplies the matching genesis cap.
Public networks reject this setting; an existing UTXO database with another
cap is rejected. All other Scala launch parameters, validation, and accounting
come from the pinned classpath. This override is explicitly recorded in the
manifest. Ordinary `start.sh` still uses the original configurations.

`build-block.py` follows the accepted full-tip ancestry, so a rejected sibling
header does not make later construction ambiguous. It supports a batch of
emission blocks and campaign stages. Each generated campaign block has a
production JVM oracle sidecar and its signed transactions. The intentional
rejection mode requires a JVM `CostLimitException` and unchanged state.
Per-transaction JVM validation separately measures the over-cap total.

The selected workload uses the exact family-(f) v6 `Coll.reverse` tree plus
spendable L2 `coll-flatMap`, `coll-zip`, and `global-xor` fixture trees. Mining
uses the requested node's candidate/solution API; Scala's prioritized
candidate API avoids reusing a cached candidate without the workload. Boundary
injections submit full blocks to both nodes and compare `/info` commitments.
HTTP admission alone never counts as block acceptance. Compressed artifacts
and manifests live under `test-vectors/ergo-sigma/cost-ledger/results/`.

**Recorded outcome: BLOCKED on `BLOCK-L6-mining-safety-gap`.** The resumed
campaign used the executable rebuilt from `9fd384a6` in both directions.
Lifecycle startup waits for initialized Scala before launching Rust, then
requires a connected peer on both nodes. Campaign waits and JVM construction
abort if either node loses its peer.

The fresh chain completed all 720 maturity blocks with matching commitments.
Scala mined all four selected workloads, including v6 `Coll.reverse`. Both
nodes accepted the three-transaction **37509** block, rejected **37510** with
unchanged height/full-tip ID/state root, and accepted one transaction at
**37509**. This direction passed **7/7** cases.

The Rust direction admitted the v6 workload but its completed full candidate
omitted it. Rust reserves a fixed **150000** cost gap even under the **37509**
cap; Scala reserves **0** below **1000000**. Both nodes accepted Rust's
emission-only height-729 block with matching commitments. This is a mining
selection disagreement, not a block-validation disagreement. The mandatory
stop rule leaves six Rust-direction cases skipped and full L6 closure pending.
The emission-discovery fix passed the fresh funding/mining transition.

Both processes are stopped and all four private ports are closed. The result
file preserves both directions and links the compressed prior stopped result;
all earlier artifacts remain. Source snapshots distinguish harness changes
between directions. The driver refuses to resume a recorded divergence until
its ledger obligation is resolved and the result is explicitly archived.
