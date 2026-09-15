# Mixed Scala/Rust devnet

This recipe runs Scala Ergo **6.0.5 / sigma-state 6.0.6** and the Rust node
built from this worktree on one isolated chain. Both nodes validate every
block. The external worker submits a solution to the selected node's mining
API, then waits for the other node to receive and validate the block over
P2P. It never relays blocks through HTTP during the smoke.

## Run

From the repository root, with the Task 6.2 JVM classpath already provisioned:

```sh
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
Mining rewards mature after 720 blocks. Thus the separate Task 7.1 requirement
for wallets funded from genesis remains outstanding; this recipe proves the
mixed-node mining/validation prerequisite, not funded-wallet workloads or the
full cost-heavy L6 campaign.

## Smoke evidence

The driver selects 100 blocks, strictly alternating 50 Rust / 50 Scala. For
each block it records miner, height, header version, block ID, state root,
candidate and solution, and waits for matching commitments on both nodes.
The manifest also records node versions, source and executable hashes, config
and tool hashes, and selected/executed/skipped/failed counts.

Recorded run: **PASS — 100 selected, 100 executed, 0 skipped, 0 failed**;
50 blocks mined by Rust and 50 by Scala, strictly alternating. Both nodes
reached height **100** with:

- Block ID: `acbfbdacf69e3ea08c2d7a635bdf45851d6b6e4decdd76404afe66ab7d32498b`
- State root: `3e87598aebaf1ff398cedc3b56394fa963132b3f33cb4ad038be84445c074ec608`
- Rust implementation revision: `a33b9f0baebc0cbb475c914f4a79df32340b1e20`
- Rust executable SHA-256: `49c10ac8a589857551c55136a39fe3369cffc364058c653f14c7fc53f5630701`
- Started (UTC): `2026-09-15T22:53:26.845468+00:00`

Every height matched, including Rust's first block propagating to the empty
Scala peer. All 100 headers were version 4. See [per-block evidence](smoke-evidence.json)
and the [environment, inputs, gate and shutdown receipt](smoke-environment.json).
The receipt records concurrent test-helper/dev-dependency edits separately;
the shared worktree was not claimed to be clean.

`cargo fmt --all -- --check` and warning-denying workspace clippy passed.
`cargo nextest` was unavailable; `cargo test --workspace` passed with
**6,997 passed, 0 failed, 97 ignored** (including doctests). Both nodes were
stopped afterward and all four recipe ports were verified closed.
No cost-ledger rows are closed by this recipe.
