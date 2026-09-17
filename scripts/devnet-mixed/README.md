# Mixed Scala/Rust devnet — blocked prerequisite

Task 7.1 is **BLOCKED** on candidate
`b3d508c8eff7db2f333a1051fb00b8343b415da6`. This directory does not yet
provide an executable mixed-node recipe. `build-block.py` is the existing
Task 6.2 synthetic-block builder, not a node launcher or a mixed-node smoke.

## Reproduce the blocker

From the worktree root, with the configured shared Cargo target directory:

```sh
cargo build -p ergo-node
~/.cache/cargo-target/debug/ergo-node --network devnet \
  --data-dir scripts/devnet-mixed/.work/rust
```

Observed on 2026-09-15 UTC: build succeeds; node exits with status 1:

```text
config load failed: unknown network: devnet
```

Configuration loading fails before node startup. No node was started, no
blocks were mined, and no state root or wallet funding was established.
The required smoke, **50 blocks mined by each side in turn**, is unexecuted
(0 Scala-mined, 0 Rust-mined; heights and state roots unavailable).

## Why configuration alone cannot unblock this

- `ergo-chain-spec/src/lib.rs`: `Network` contains only `Mainnet` and
  `Testnet`; `network_from_str_unknown_errors` explicitly rejects `devnet`.
- `ergo-node/src/config/load.rs`: the parsed network selects a compiled
  `ChainSpec`. Public-network seed peers are appended to configured peers.
  Substituting `testnet` would not provide the isolated devnet identity.
- `ergo-node/src/config/toml_sections.rs`: `TomlChain` exposes checkpoints
  and a genesis **header ID**, but no genesis-box, state-digest, difficulty,
  epoch-length, magic-byte, or launch-parameter overrides. Unknown TOML
  fields must not be mistaken for implemented chain settings.
- The compiled testnet difficulty epoch is 128 blocks. The required shared
  difficulty-1 chain without epoch boundaries cannot be configured here.
- `~/apps/ergo-devnet-stark/README.md` identifies its binary as built from
  `feat/eip-0045-stark`, with `Network::Devnet`, magic `[7,7,7,7]`, and empty
  seeds. Its TOML is not executable by this candidate. Reusing that binary
  would not test Rust built at the candidate revision.
- Wallets funded from genesis require common, independently verified genesis
  boxes and their state digest, plus known test signing keys. The current
  Rust configuration cannot load such a genesis. Mining rewards alone would
  not satisfy the genesis-funding requirement.

The task permits changes only under `scripts/devnet-mixed/`. Adding the
missing Rust chain support exceeds that scope. No alternative public-network
configuration, borrowed Rust binary, or synthetic block result is presented
as a successful mixed-devnet campaign.

## Reserved recipe layout

These are proposed locations and ports, not running services or verified
configuration. All runtime paths are relative to this directory.

| Item | Path or loopback port | Status |
| --- | --- | --- |
| Shared chain/genesis configuration | `genesis.conf` | Pending Rust chain support and funded genesis |
| Scala configuration | `scala-node.conf` | Pending shared chain |
| Rust configuration | `rust-node.toml` | Pending devnet support |
| Lifecycle scripts | `start.sh`, `stop.sh` | Pending valid configurations |
| Scala REST / P2P | `19553` / `19530` | Proposed; unbound by this task |
| Rust REST / P2P | `19554` / `19531` | Proposed; unbound by this task |
| Scala data / logs / PID | `.work/scala/`, `.work/scala.log`, `.work/scala.pid` | Not created |
| Rust data / logs / PID | `.work/rust/`, `.work/rust.log`, `.work/rust.pid` | Not created |
| Smoke evidence | `.work/smoke.json` | Not created |

The proposed ports avoid 9053, 9063, 9052, 9073, 9072, and 19099.
This task did not query or alter the extraction oracle on port 9053.
There are no task-owned node processes to stop; a `stop.sh` is not supplied
for services that cannot yet be launched.

## Prerequisites and completion procedure

1. Provide candidate Rust support for an isolated devnet: unique magic and
   empty public seeds, difficulty 1, matching launch parameters, no difficulty
   or voting epoch boundaries during the campaign, and configurable funded
   genesis boxes with their independently computed state root.
2. Define one shared chain specification and verify both adapters consume
   identical genesis, monetary, difficulty, voting, and launch parameters.
   Scala's `devnet`, `devnet60`, and `testnet` select different launch settings;
   matching the genesis digest alone is insufficient.
3. Base the Rust config and lifecycle on `~/apps/ergo-devnet-stark/`, and the
   Scala config shape on `~/apps/ergo-node-scala/testnet/`. A Scala 6.0.5 JAR
   is available at `~/apps/ergo-node-scala/mainnet/ergo-6.0.5.jar`; verify its
   reported version before use. Task 6.2 also provisions a pinned classpath
   at `../jvm_block_oracle/.work/classpath` using Ergo source
   `5528ef569a41ebccbc8658212e6ee3c97d990b96` and sigmastate 6.0.6.
   That classpath includes the documented cost-observation wrapper.
4. Keep all node data, logs, and PID files in this worktree. Bind loopback,
   peer the two nodes, verify genesis-funded wallet balances, and mine
   strictly alternately: 50 blocks per node, 100 blocks total. After each
   block wait for the other node to validate it through P2P; compare final
   height, best block ID, and UTXO state root.
5. Record commands, timestamps, candidate SHA/toolchain/features, Scala/JVM
   pins, chain settings, per-node mining counts, final commitments, and
   input/output SHA-256 hashes. Stop both task-owned nodes, then record the
   actual smoke result here. Task 7.1 cannot be called complete before this.

No ledger rows are closed by this blocker reproduction.
