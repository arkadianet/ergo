# ergo-chain-spec

**Purpose:** Single source of truth for "what does network X look like" — magic bytes, address prefix, difficulty/voting/monetary/reemission schedules, genesis identity, block timing, and bootstrap peers/checkpoint. Types, constants, and constructors only: no validation logic, no I/O, no runtime services.

**Depends on (workspace):** ergo-primitives, ergo-ser
**Depended on by:** (see codemap index)
**Approx LOC:** 1 093 (single file, `src/lib.rs`; ~362 of which is the `#[cfg(test)]` oracle-parity block)

## Start here
- `ChainSpec` (`src/lib.rs:526`) — the aggregate that bundles every per-network parameter group; read its fields to see the whole surface.
- `ChainSpec::for_network` (`src/lib.rs:589`) — the crate-boundary constructor; the documented single dispatch point on `Network` (downstream borrows narrow `&DifficultyParams`/`&VotingParams` views).
- `Network` (`src/lib.rs:51`) — the `Mainnet`/`Testnet` selector with `as_str`/`Display`/`FromStr`.
- The crate-level doc comment (`src/lib.rs:1-24`) — charter plus the Scala provenance pins (mainnet `2cdbb8c` / v6.0.2; testnet v6.0.3 after PR #2252).

## Modules
- `src/lib.rs` — the entire crate. Flat module: every parameter type, its `mainnet()`/`testnet()`/`for_network()` constructors, three private hex-decode helpers (`parse_id_hex`, `parse_bytes32_hex`, `parse_digest33_hex` at `src/lib.rs:31-45`), and the inline oracle-parity test suite. No submodules.

## Key types, traits & functions
- `Network` (enum) — network selector, `as_str`/`Display`/`FromStr` round-trip — `src/lib.rs:51`
- `NetworkParams` (struct) — P2P handshake `magic: [u8;4]` + base58 `address_prefix: NetworkPrefix`; `MAINNET`/`TESTNET` consts — `src/lib.rs:90`
- `DifficultyParams` (struct) — epoch length, EIP-37 switch boundary, Autolykos v2 activation, initial-difficulty seed, `desired_interval_ms`; consumed by `ergo-crypto::difficulty`/`pow` — `src/lib.rs:130`
- `V2Activation` (struct) — optional v1→v2 hard-fork descriptor (`height` + `initial_difficulty`); `None` when genesis already carries a v2+ block version — `src/lib.rs:158`
- `VotingParams` (struct) — voting-epoch length + soft-fork/change thresholds + optional `version2_activation`; `soft_fork_approved`/`change_approved` predicates — `src/lib.rs:220`
- `MonetaryParams` (struct) — emission curve (fixed-rate window, per-epoch reduction, founder split, `miner_reward_delay`); identical mainnet/testnet values — `src/lib.rs:293`
- `ReemissionParams` (struct) — EIP-27 activation/stop heights + emission/reemission NFT and token `Digest32` ids — `src/lib.rs:346`
- `GenesisParams` (struct) — 33-byte `state_digest`, optional height-1 `header_id`, optional compile-time-embedded `boxes_json` (`include_str!` of `test-vectors/<net>/genesis_boxes.json`) — `src/lib.rs:389`
- `BlockTimingParams` (struct) — `desired_interval_ms` + `header_chain_diff`; `header_freshness_threshold_ms()` = product of the two, the sync-tip gate — `src/lib.rs:459`
- `BootstrapParams` (struct) — seed `SocketAddr` peers + optional `(height, block_id)` script-validation checkpoint — `src/lib.rs:507`
- `ChainSpec` (struct) — aggregate; note `reemission: Option<ReemissionParams>` is `None` on the post-PR-#2252 testnet — `src/lib.rs:526`
- `ChainSpec::for_network` (fn) — the documented sole `Network` branch point at the crate boundary — `src/lib.rs:589`
- `ChainSpec::emission_script_trees` (fn) — returns `Option<EmissionScriptTrees>` with the three emission-related `ErgoTree` byte vectors; `None` on testnet (no verified oracle yet) and on any spec failing the defensive identity gate (reemission NFT id + genesis digest + `MAINNET` network params must all match canonical values) — `src/lib.rs:613`
- `EmissionScriptTrees` (struct) — serialized `ErgoTree` bytes for the three emission contracts: `emission` (genesis emission box proposition), `reemission` (EIP-27 re-emission box), and `pay_to_reemission` (EIP-27 pay-to-reemission); sourced from live-Scala `/emission/scripts` oracle capture and cross-checked by test — `src/lib.rs:646`

## Invariants & contracts
- **Network-parameter authority.** This crate owns the canonical per-network constants (magic, address prefix, difficulty/voting/monetary/reemission schedules, genesis digest + header id, seed peers, checkpoint). Every value carries a Scala-conf source citation in its doc comment; the inline `oracle parity` tests assert byte/value equality against those references. When upstream Scala moves (mainnet `2cdbb8c`, testnet v6.0.3), re-extract `test-vectors/` and re-run these tests.
- **No discrimination leak.** `Network::Mainnet`/`Testnet` is meant to be branched on only inside the `for_network` constructors; consumers borrow narrow `&DifficultyParams`/`&VotingParams`/etc. views and never see the discriminant (`ChainSpec.network` exists for telemetry/`/info`, not chain rules).
- **Charter boundary.** Types, constants, constructors only — no validation, no I/O, no runtime services, no broad node state. Genesis-box JSON is embedded but *parsed* elsewhere (`ergo-node::genesis::parse_genesis_boxes`).
- **Absence encoded explicitly, not via sentinels.** Networks lacking a feature carry `None` rather than a magic height: testnet has no EIP-37 boundary (`eip37_epoch_length`/`eip37_activation_height` = `None`), no v1→v2 transition (`V2Activation`/`version2_activation` = `None`, since `TestnetLaunchParameters` launches at `BlockVersion = Interpreter60Version = 4`), and no EIP-27 reemission (`ChainSpec.reemission = None`).
- **Genesis digest width.** `GenesisParams.state_digest` is 33 bytes (32-byte AVL digest + 1-byte tree-height marker), not 32; `header_id` is the height-1 header id the NiPoPoW verifier anchors on.
- **Hardcoded-hex soundness.** The private `parse_*_hex` helpers `.expect()` on decode failure — a malformed literal is a compile-baked panic, acceptable because the inputs are constant source strings, not runtime data.

## Notes on doc accuracy
README.md:153-156 and docs/architecture.md:23 describe this crate accurately as of the current source: the field list (difficulty/voting/monetary/reemission/block-timing/bootstrap/genesis), the L2 layer placement, the dependency posture, and the "only site that branches on `Network`; downstream takes narrow views" charter all match `src/lib.rs`. No stale or wrong claims found.
