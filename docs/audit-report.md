# Ergo Rust Node — Drop-In Parity Audit Report

**Date**: 2026-03-01
**Auditor**: 12-agent swarm (consensus, P2P, storage, mempool, API, math, serialization, pipeline, naming, config, red-team)
**Rust codebase**: `/home/rkadias/coding/git/erg-rust-node-full-opus/`
**Scala reference**: `/home/rkadias/coding/reference_materials/ergo-master/`

---

## 1. EXECUTIVE SUMMARY

1. **The Rust node syncs mainnet, validates PoW/blocks/txs, applies state, and serves 50+ REST endpoints.** It is a functional, well-tested node (856+ tests, 0 clippy warnings), not a skeleton.
2. **All consensus math is verified identical** — difficulty adjustment (classic + EIP-37), Autolykos v2 hit computation, compact bits encoding, chain scoring all match Scala byte-for-byte.
3. **All wire serialization is byte-compatible** — VLQ, headers, transactions, extensions, Inv, SyncInfo V2, handshake, message framing, checksums all verified.
4. **CRITICAL: Testnet magic bytes differ** — Rust `[2,0,0,1]` vs Scala `[2,0,2,3]`. Rust testnet nodes cannot connect to Scala testnet. Mainnet magic matches.
5. **Penalty ban threshold is 100 in Rust vs 500 in Scala.** Rust bans peers ~5x more aggressively — risks self-isolation from the network.
6. **maxDeliveryChecks is 2 in Rust vs 100 in Scala.** Rust gives up on slow peers far too quickly, risking sync stalls on congested networks.
7. **UTXO snapshot sync not wired into P2P** — infrastructure exists but message handlers (76-81) are stubs. Full sync from genesis only.
8. **Voting state is in-memory only** — not persisted in undo log. Deep reorgs crossing epoch boundaries may corrupt voting parameters.
9. **MaxTimeDrift is hardcoded at 1,200,000ms (mainnet 20min)** — Scala derives it dynamically as `10 * blockInterval`. On a network with different blockInterval, Rust would be wrong.
10. **856+ tests, clean build, production-grade architecture.** The gaps are at config edges and missing features, not in core consensus logic.

### Red-Team Corrections Applied

The red-team agent (Agent 12) verified 10 claims and made these corrections:
- **MaxBoxSize**: Previously reported as 4,096 vs 4,194,303. **DISPROVED** — both Scala and Rust use 4,096 bytes. The original claim of 4.2MB was incorrect (SigmaConstants.MaxBoxSize = 4096).
- **Peer eviction**: Previously reported as missing. **DISPROVED** — Rust has anti-eclipse eviction in `event_loop.rs:1021-1032` (every 3600s, disconnect random peer if 5+ connected).
- **ErgoStateContext**: Claimed 100% complete. **PARTIALLY CORRECT** — sufficient for script verification but missing `lastExtensionOpt`, `validationSettings`, `votingData`, `genesisStateDigest`.

---

## 2. DROP-IN COMPATIBILITY MATRIX

| # | Subsystem | Scala Capability | Rust Status | Evidence | Risk |
|---|-----------|-----------------|-------------|----------|------|
| **CONSENSUS / VALIDATION** |
| 2.1 | Header validation (10 rules) | Rules 200-216 | **Equivalent** | `header_validation.rs` all rules implemented | Low |
| 2.2 | PoW validation (Autolykos v1+v2) | Full EC + hash | **Equivalent** | `autolykos.rs`: K=32, N growth, q constant all verified byte-identical (Agent 7) | Low |
| 2.3 | Difficulty (classic + EIP-37) | Linear interp + avg | **Equivalent** | `difficulty_adjustment.rs`: PRECISION=1e9, formulas verified identical (Agent 7) | Low |
| 2.4 | Tx validation (stateless, 10 rules) | Rules 100-109 | **Equivalent** | `tx_validation.rs:54` all 10 rules | Low |
| 2.5 | Tx validation (stateful, 7 rules) | Rules 111-124 | **Equivalent** | `tx_stateful_validation.rs:70` ERG/token preservation, dust, monotonic height | Low |
| 2.6 | ErgoScript verification | sigma-rust | **Equivalent** | `sigma_verify.rs` uses ergo-lib 0.28, SigmaStateContext, checkpoint skip | Low |
| 2.7 | Block Merkle roots | Tx + AD + Extension | **Equivalent** | `block_validation.rs:48` incl. witness IDs for v2+ | Low |
| 2.8 | MaxBoxSize enforcement | 4,096 bytes | **Equivalent** | Red-team verified: both 4,096 (Agent 12) | Low |
| 2.9 | EIP-27 re-emission | Spending rules | **Equivalent** | `node_view.rs:1128` `verify_reemission_spending()` | Low |
| 2.10 | Voting / soft-fork | Full state machine | **Equivalent** | `voting.rs`: VotingData, 90% threshold, parameter bounds | Low |
| 2.11 | Block cost accumulation | Per-input fail-fast | **Partial** | Rust checks cost at block end, not per-input (optimization gap, not consensus) | Low |
| **CHAIN SYNC** |
| 2.12 | Headers-first sync | Full state machine | **Equivalent** | `sync_manager.rs`: Idle→HeaderSync→BlockDownload→Synced | Low |
| 2.13 | SyncInfo V1+V2 | Both directions | **Equivalent** | `sync_info.rs`: V1 parse, V2 generate, 0x00+0xFF discriminator (Agent 8) | Low |
| 2.14 | Block section download | 102+104+108 | **Equivalent** | UTXO skips ADProofs(104); digest downloads all 3 | Low |
| 2.15 | Out-of-order cache | LRU two-tier | **Equivalent** | `modifiers_cache.rs`: 8192 headers + 384 body, iterative drain | Low |
| 2.16 | Delivery tracking | Timeout + reassign | **Partial** | `delivery_tracker.rs`: max_checks=2 vs Scala 100 | **Med** |
| 2.17 | Fork detection | Peer chain status | **Equivalent** | `sync_tracker.rs`: Older/Younger/Equal/Fork/Unknown | Low |
| 2.18 | Chain reorg / rollback | Versioned state | **Equivalent** | DigestState + UtxoState undo logs, max 1000 versions (Agent 9) | Low |
| 2.19 | UTXO snapshot bootstrap | P2P messages 76-81 | **Missing** | `snapshots.rs` infra exists; no P2P handlers wired | **Med** |
| 2.20 | Voting state in reorgs | Rolled back with state | **Partial** | VotingEpochInfo is in-memory only; not in undo log (Agent 9 Scenario D) | **Med** |
| **P2P PROTOCOL** |
| 2.21 | Message framing | magic+code+len+chk+body | **Equivalent** | `codec.rs`: exact frame format, blake2b first-4 checksum (Agent 8) | Low |
| 2.22 | Handshake (raw bytes) | PeerSpec+time+features | **Equivalent** | `handshake.rs`: PeerSpec, ModeFeature(16), SessionFeature(3) (Agent 8) | Low |
| 2.23 | Mainnet magic bytes | [1,0,2,4] | **Equivalent** | `network_type.rs` | Low |
| 2.24 | Testnet magic bytes | [2,0,2,3] | **MISMATCH** | Rust [2,0,0,1] vs Scala [2,0,2,3] (Agent 12 verified) | **HIGH** |
| 2.25 | All 15 message codes | 1,2,22,33,55,65,75-81,90-91 | **Equivalent** | `message.rs`: all defined; 9 handled, 6 gracefully ignored | Low |
| 2.26 | Peer scoring/penalties | 500 threshold, 60m ban | **MISMATCH** | Rust: 100 threshold (Agent 12 verified) | **Med** |
| 2.27 | Peer eviction (anti-eclipse) | 1h random eviction | **Equivalent** | `event_loop.rs:1021-1032` every 3600s (Agent 12 corrected) | Low |
| 2.28 | Invalid modifier cache | Bloom filter, 4h expiry | **Missing** | No bloom filter cache in Rust | Low |
| **MEMPOOL** |
| 2.29 | Admission (fee + size + blacklist) | Full | **Equivalent** | `mempool.rs`: min fee, capacity, double-spend, RBF | Low |
| 2.30 | Replace-by-fee | Weight comparison | **Equivalent** | `put_with_size()`: new weight > avg old → replace | Low |
| 2.31 | Sorting options | random/bySize/byCost | **Partial** | Rust: FeePerByte only; `mempool_sorting` config unused (Agent 12) | Low |
| 2.32 | Tx relay (Inv broadcast) | Exclude sender | **Equivalent** | `BroadcastInvExcept` with sender exclusion | Low |
| 2.33 | Cost rate limiting | Per-peer + global | **Equivalent** | 12M global, 10M per-peer cost budgets | Low |
| **MINING** |
| 2.34 | Candidate generation | Header + mempool | **Equivalent** | `mining.rs`: CandidateGenerator, fee collection, reward script | Low |
| 2.35 | Solution submission | POST /mining/solution | **Equivalent** | Nonce format check + channel dispatch | Low |
| 2.36 | Internal CPU miner | Optional threads | **Partial** | Config exists; default 0 threads (Scala default 1) | Low |
| **REST API** |
| 2.37 | Core endpoints | ~60 routes | **Equivalent** | `api.rs`: 50+ endpoints, camelCase JSON, auth on protected | Low |
| 2.38 | Blockchain/indexer | 26 routes | **Equivalent** | `ergo-indexer`: 25 /blockchain/* endpoints | Low |
| 2.39 | Wallet endpoints | 29 routes | **Equivalent** | 23 endpoints behind `wallet` feature flag | Low |
| 2.40 | Scan endpoints | 8 routes | **Equivalent** | All 8 match Scala exactly (Agent 10 verified) | Low |
| 2.41 | NiPoPoW endpoints | 4 routes | **Equivalent** | All 4 match Scala exactly | Low |
| 2.42 | Mining endpoints | 5 routes | **Equivalent** | All 5 present | Low |
| **STORAGE** |
| 2.43 | Modifier persistence | RocksDB (dual CF) | **Equivalent** | `history_db.rs`: objects + indexes CFs, WriteBatch atomicity | Low |
| 2.44 | State hash consistency | AVL+ tree digest | **Equivalent** | `ergo-avldb` + `ergo-state`: verified state_root | Low |
| 2.45 | Block pruning | Sliding window | **Equivalent** | Epoch boundary preservation, minimal_full_block_height | Low |
| 2.46 | Crash recovery | state_version key | **Equivalent** | `[0xFE;32]` key, replay forward on mismatch | Low |
| **CONFIG** |
| 2.47 | Config loading chain | CLI > file > defaults | **Equivalent** | --config > --network > CWD > ~/.ergo > built-in | Low |
| 2.48 | Default equivalence | Various | **Partial** | delivery checks, penalties, sync interval differ (Agent 11) | **Med** |
| 2.49 | EIP-27 config fields | 7 reemission fields | **Missing** | No reemission config in Rust settings | **Med** |
| 2.50 | Unknown key handling | Silently ignored (HOCON) | **Differs** | Rust serde rejects unknown TOML keys | Low |
| **OBSERVABILITY** |
| 2.51 | Structured logging | tracing | **Equivalent** | tracing + tracing-subscriber with env-filter | Low |

---

## 3. CONFIRMED MISMATCHES (Ranked by Severity)

### MISMATCH-1: Testnet Magic Bytes (CRITICAL — Network Partition)

- **Scala**: `[2, 0, 2, 3]` — `testnet.conf:96`
- **Rust**: `[2, 0, 0, 1]` — `network_type.rs:39`
- **Consequence**: Complete testnet isolation. Rust rejects all Scala testnet peer messages at magic check.
- **Red-team**: VERIFIED (Agent 12)
- **Fix**: Change Rust testnet magic to `[2, 0, 2, 3]`.

### MISMATCH-2: Penalty Ban Threshold (MEDIUM — Aggressive Isolation)

- **Scala**: `penaltyScoreThreshold = 500` — `application.conf:586`
- **Rust**: `ban_threshold = 100` — `penalty_manager.rs:59`
- **Consequence**: Rust bans after 1 invalid header (100 pts) or 2 invalid txs (50 each). Scala needs 5x more. Legitimate peers with transient issues get banned.
- **Red-team**: VERIFIED (Agent 12)
- **Fix**: Raise to 500. Implement 2-minute penalty safe interval.

### MISMATCH-3: maxDeliveryChecks (MEDIUM — Sync Reliability)

- **Scala**: `100` — `application.conf:535`
- **Rust**: `2` — `settings.rs:220`
- **Consequence**: Rust abandons modifier requests after 2 retries. Congested networks or slow peers cause permanent sync stalls.
- **Note**: MEMORY.md incorrectly states "Scala default = 2". The actual Scala default is 100.
- **Fix**: Change default to 100 (or at minimum 10-20).

### MISMATCH-4: MaxTimeDrift Hardcoded (LOW — Future Risk)

- **Scala**: `10 * chainSettings.blockInterval.toMillis` (dynamic per network)
- **Rust**: `1_200_000` hardcoded — `header_validation.rs:22`
- **Consequence**: Currently matches mainnet (10 * 120,000ms). But if blockInterval ever changes via governance, Rust would have wrong drift tolerance.
- **Fix**: Derive from config `block_interval_secs * 10 * 1000`.

### MISMATCH-5: Voting State Not Persisted in Undo Log (MEDIUM — Deep Reorg Risk)

- **Scala**: VotingData is part of state snapshots, rolled back with state.
- **Rust**: VotingEpochInfo is in-memory only in NodeViewHolder.
- **Consequence**: A deep reorg crossing an epoch boundary may leave voting parameters incorrect. Reapplied blocks would accumulate votes from the wrong base.
- **Evidence**: Agent 9 Scenario D analysis; `node_view.rs` VotingEpochInfo not in undo log.
- **Fix**: Either persist VotingEpochInfo per-version or rebuild from chain on reorg.

### MISMATCH-6: Sync Interval (LOW — Behavioral)

- **Scala**: `syncInterval = 5s` (unstable mode) — `application.conf:506`
- **Rust**: `sync_interval_secs = 2` — `settings.rs:224`
- **Consequence**: Rust sends SyncInfo 2.5x more often. More aggressive but generates more traffic.

---

## 4. MISSING FEATURES CHECKLIST

### P2P / Network

| Feature | Effort | Notes |
|---------|--------|-------|
| UTXO snapshot P2P sync (messages 76-81) | Medium | Infrastructure in `snapshots.rs`; need handlers + state machine wiring |
| Invalid modifier bloom filter cache | Small | Port ExpiringApproximateCache — FIFO bloom filters with 4h TTL |
| Penalty safe interval (2min window) | Small | Track last penalty timestamp, skip accumulation within window |

### Mempool

| Feature | Effort | Notes |
|---------|--------|-------|
| Cost-based sorting (`byExecutionCost`) | Small | Track `lastCost` per tx, add FeePerCycle weight variant |
| Wire `mempool_sorting` config to actual sort | Trivial | Config field exists but is never read (Agent 12) |

### Config / Consensus

| Fix | Effort | Notes |
|-----|--------|-------|
| Testnet magic → [2,0,2,3] | Trivial | One constant in `network_type.rs` |
| Penalty threshold → 500 | Trivial | One constant in `penalty_manager.rs` |
| maxDeliveryChecks → 100 | Trivial | One default in `settings.rs` |
| MaxTimeDrift → derived from config | Small | Replace hardcoded constant with `block_interval_secs * 10 * 1000` |
| EIP-27 reemission config fields | Medium | 7 new config fields needed for full EIP-27 support |
| Voting state persistence in undo log | Medium | Serialize VotingEpochInfo per-version |

### ErgoStateContext Completeness

| Missing Field | Impact | Notes |
|---------------|--------|-------|
| `lastExtensionOpt` | Low | Not needed for current sigma-rust verification |
| `validationSettings` | Low | Only relevant for soft-fork rule checks during script eval |
| `votingData` | Low | Not accessed by scripts |
| `genesisStateDigest` | Low | Only used in genesis block construction |

---

## 5. UNKNOWNS (Resolved and Remaining)

### Resolved by Agents 7-12

| # | Question | Resolution | Agent |
|---|----------|-----------|-------|
| U1 | Difficulty precision constant | MATCH: both 1,000,000,000 | 7 |
| U2 | VLQ encoding byte-identical | VERIFIED: all edge cases match | 8 |
| U3 | Header serialization field order | VERIFIED: exact same order, nBits as 4-byte BE | 8 |
| U4 | Block processing order | VERIFIED: structural before difficulty in both | 9 |
| U5 | Config key coverage | 48 keys compared; 7 missing (EIP-27), rest match | 11 |
| U6 | Unknown TOML key handling | CONFIRMED: Rust rejects; Scala ignores | 11 |
| U7 | Compact bits edge cases | VERIFIED: MSB padding, sign bit both correct | 7 |
| U8 | genIndexes produces 32 identical indexes | VERIFIED: same algorithm, same output | 7+12 |
| U9 | Extension key length (32 bytes) | VERIFIED: both enforce exactly 2-byte keys | 8 |
| U10 | MaxBoxSize actual values | CORRECTED: both 4,096 (not 4.2MB) | 12 |

### Remaining Unknowns

| # | Unknown | Evidence Needed |
|---|---------|----------------|
| U11 | Sigma-rust version parity | Verify ergo-lib 0.28 matches Scala's sigma-rust version for script semantics |
| U12 | EIP-27 spending rules completeness | Run EIP-27 test vectors (not yet available; activation not yet reached) |
| U13 | Internal CPU miner correctness | Run mining on testnet, verify blocks accepted by Scala peers |
| U14 | Wallet transaction signing | Run wallet feature-flag build, sign tx, verify Scala node accepts |
| U15 | Serde `deny_unknown_fields` behavior | Test TOML config with extra keys; confirm startup behavior |

---

## 6. PARITY TEST PLAN

### Dual-Run Harness

1. **Setup**: Run Scala 6.0.x and Rust node side-by-side, same network, same seed peers
2. **Phase 1 — Sync**: Both start from genesis (or same checkpoint). Record tip progression.
3. **Phase 2 — Steady state**: Both fully synced. Submit transactions to each. Verify relay and acceptance.
4. **Phase 3 — Stress**: Disconnect/reconnect peers, inject invalid blocks, force reorgs.

### Artifacts to Capture

| Artifact | Capture Method | Comparison |
|----------|---------------|------------|
| Best header progression | `/info` every 10s: height + headerID | Must match exactly |
| Best full block progression | `/info` every 10s: fullHeight + fullBlockID | Must match exactly |
| State root at each height | `/info` stateRoot | Must match exactly |
| Block acceptance verdicts | Log grep "Valid"/"Invalid" | Must match exactly |
| Cumulative chain score | `/info` headersScore | Must match (big-endian bytes) |
| P2P messages | TCP proxy or pcap | Structural comparison |
| API response diffs | Script hitting both `/info`, `/blocks/{id}` | JSON diff (field names + values) |

### Acceptance Criteria

1. Both reach same tip within 60s of each other (steady state)
2. State roots match at every 100th block
3. Zero blocks accepted by one and rejected by the other
4. No peer banned by Rust that Scala keeps connected (after threshold fix)
5. API JSON responses equivalent for `/info`, `/blocks/{id}`, `/transactions/{id}`
6. Both survive a forced 5-block reorg identically

### Minimum Pre-Test Fixes

Before running the dual harness, apply these fixes:
1. Testnet magic bytes → `[2, 0, 2, 3]`
2. Penalty threshold → 500
3. maxDeliveryChecks → 100
4. Correct MEMORY.md entry about "Scala default max_delivery_checks = 2"

---

## 7. MATH PARITY TABLE (Agent 7 — All Verified)

| Formula/Constant | Scala Location | Rust Location | Match |
|-----------------|----------------|---------------|-------|
| PRECISION (linear regression) | DifficultyAdjustment.scala:156 | difficulty_adjustment.rs:16 | YES |
| Linear regression (a, b) | DifficultyAdjustment.scala:145-146 | difficulty_adjustment.rs:210-211 | YES |
| EIP-37 ±50% clamp | DifficultyAdjustment.scala:86-95 | difficulty_adjustment.rs:105-114 | YES |
| Bitcoin-style calc | DifficultyAdjustment.scala:71 | difficulty_adjustment.rs:171 | YES |
| secp256k1 order (q) | AutolykosPowScheme.scala:19 | autolykos.rs:51-57 | YES |
| decode/encode compact bits | DifficultySerializer.scala:36-68 | chain_scoring.rs:12-90 | YES |
| target = q / difficulty | AutolykosPowScheme.scala:245 | autolykos.rs:353-359 | YES |
| K=32, N=2^26 | AutolykosPowScheme.scala:33,52 | autolykos.rs:33,39 | YES |
| calcN (5% per 51200 blocks) | AutolykosPowScheme.scala:87 | autolykos.rs:171 | YES |
| genIndexes (hash+slide) | AutolykosPowScheme.scala:252-258 | autolykos.rs:179-200 | YES |
| hitForVersion2 (8-step) | AutolykosPowScheme.scala:196-213 | autolykos.rs:383-430 | YES |
| Chain score (cumulative BigUint) | BigInt arithmetic | chain_scoring.rs:18-102 | YES |

---

## 8. SERIALIZATION PARITY TABLE (Agent 8 — All Verified)

| Type | Scala Serializer | Rust Module | Status |
|------|-----------------|-------------|--------|
| VLQ unsigned | Scorex VLQByteBufferWriter | ergo-wire/vlq.rs | MATCH |
| VLQ signed (ZigZag) | Scorex signed methods | ergo-wire/vlq.rs:82-118 | MATCH |
| Header | HeaderSerializer.scala | ergo-wire/header_ser.rs | MATCH |
| nBits encoding | DifficultySerializer (4-byte BE) | header_ser.rs:41 (`to_be_bytes()`) | MATCH |
| Transaction | ErgoTransactionSerializer | ergo-wire/transaction_ser.rs | MATCH |
| Box (standalone) | ErgoBoxSerializer | ergo-wire/box_ser.rs | MATCH |
| Extension | ExtensionSerializer.scala | ergo-wire/extension_ser.rs | MATCH |
| Inv/RequestModifier | InvSpec.scala | ergo-wire/inv.rs | MATCH |
| Modifiers message | ModifiersSpec.scala | ergo-wire/inv.rs (ModifiersData) | MATCH |
| SyncInfo V2 | ErgoSyncInfoV2Serializer | ergo-wire/sync_info.rs | MATCH |
| Handshake | HandshakeSerializer.scala | ergo-wire/handshake.rs | MATCH |
| PeerSpec | PeerSpecSerializer.scala | ergo-wire/peer_spec.rs | MATCH |
| Message frame | MessageSerializer.scala | ergo-wire/codec.rs | MATCH |
| Checksum | blake2b256 first 4 bytes | codec.rs:109-113 | MATCH |

---

## 9. BLOCK PIPELINE COMPARISON (Agent 9)

| Stage | Scala | Rust | Same Order |
|-------|-------|------|-----------|
| Idempotence check | Implicit (contains check) | Stage 0: explicit | YES |
| Assemble sections | processFullBlock() | Stage 1: load all sections | YES |
| Merkle roots | During block loading | Stage 2: validate_full_block() | YES |
| Difficulty | Header validation phase | Stage 3: verify_difficulty() | YES |
| Parse transactions | Implicit in apply() | Stage 4: explicit parse | YES |
| Stateless validation | In state.applyModifier() | Stage 5: validate_tx_stateless() | YES |
| Stateful validation | UtxoState only | Stage 5b: UTXO only | YES |
| Sigma proofs | Via sigma-rust | Stage 5c: UTXO + above checkpoint | YES |
| State application | ergo_consensus_apply() | Stage 6: apply state | YES |
| Mark valid | Implicit in history | Stage 7: explicit | YES |
| Process votes | In state context | Stage 7b: voting_epoch_info | YES |

### Reorg Scenarios (Agent 9)

| Scenario | Scala | Rust | Match |
|----------|-------|------|-------|
| A: 1-block competing | Fork at parent, unapply/apply | Same via find_common_ancestor | YES |
| B: 5-block deep | Remove old, apply new chain | Same via chain_from_ancestor | YES |
| C: Epoch boundary | New params from Extension | Same; difficulty recalculated | YES |
| D: Different votes | Votes rolled back with state | **GAP**: Voting in-memory only | PARTIAL |
| E: Deeper than keepVersions | Fails (blocks unavailable) | Fails (state version missing) | YES |

---

## 10. CONFIG PARITY SUMMARY (Agent 11)

### Critical Mismatches

| Config Key | Scala Default | Rust Default | Impact |
|-----------|--------------|-------------|--------|
| Testnet magic bytes | [2,0,2,3] | [2,0,0,1] | Network partition |
| max_delivery_checks | 100 | 2 | Sync stalls |
| penalty threshold | 500 | 100 (hardcoded) | Aggressive bans |
| sync_interval (unstable) | 5s | 2s | More traffic |
| internal_miners_count | 1 | 0 | Minor (dev only) |

### Missing Config Categories

| Category | # Missing Fields | Consensus? |
|----------|-----------------|-----------|
| EIP-27 reemission | 7 fields | Yes (future) |
| Voting parameters | 3 fields | Yes (hardcoded to correct values) |
| Penalty tuning | 3 fields | No (hardcoded to correct values) |
| Cache sizes | 6 fields | No |
| NiPoPoW bootstrap | 2 fields | No |

---

## 11. RED-TEAM VERIFICATION RESULTS (Agent 12)

| # | Claim | Verdict |
|---|-------|---------|
| 1 | Genesis height = 1 in both | **VERIFIED** |
| 2 | MaxTimeDrift = 1,200,000ms in both | **VERIFIED** (mainnet; Scala is dynamic per-network) |
| 3 | Autolykos k=32 in both | **VERIFIED** |
| 4 | Extension field max = 64 bytes in both | **VERIFIED** |
| 5 | ErgoStateContext 100% complete | **PARTIALLY CORRECT** (sufficient for scripts, missing some fields) |
| 6 | MaxBoxSize 4096 vs 4,194,303 | **DISPROVED** — both are 4,096 |
| 7 | Testnet magic bytes differ | **VERIFIED** |
| 8 | Penalty threshold 100 vs 500 | **VERIFIED** |
| 9 | Rust lacks peer eviction | **DISPROVED** — exists in event_loop.rs:1021-1032 |
| 10 | Rust only weight-based sort | **VERIFIED** — config exists but unused |
