# ergo-chain-spec audit

Readiness: **NOT_READY for reference-quality certification**. Owned review coverage is complete. Current canonical constructors pass their package gates, and the reviewed mainnet identity/genesis/contracts agree with pinned primary sources and independent checked-in captures. Two narrow public API defects remain; the production testnet launch-row authority is unresolved and blocks a complete testnet compatibility claim. This review does **not** demonstrate a public-network consensus split, remote denial of service or loss of funds.

Confirmed findings: **P0 0, P1 0, P2 3, P3 1**. The P2 count includes an important authority/validation gap, explicitly distinguished below from a demonstrated consensus defect. One possible testnet consensus consequence remains in the separate unresolved-risk list.

These are local, ignored audit artifacts. Implementation, tests, fixtures, existing docs and dependency versions were not changed.

## Scope and baseline

Audit date: 2026-10-03. Revision `5d62fd5851e74fcb965b4aba50e1b423127f46f1`, branch `main`; baseline [baseline.json](baseline.json). Preexisting state: modified `README.md`, untracked `docs/audit-2026-10-03.md`, `docs/audit-prompts/`, `docs/audit-remediation-todo.md`. Findings concern the checked-out authored crate and listed consumer seams, not an inferred clean checkout.

Host: Linux 7.1.5 x86_64, glibc 2.39; rustc `1.95.0 (59807616e 2026-04-14)`, cargo `1.95.0 (f2d3ce0bd 2026-03-21)`, edition 2021, package 0.10.0, MIT OR Apache-2.0, `publish=false`. Test profile has opt-level 1; ordinary test/debug overflow checks remain enabled. Shared builds used `CARGO_BUILD_JOBS=6`. No workspace gate was duplicated; root owns shared fmt/clippy/tests/Rustdoc/advisory/deny/machete results.

Owned authored inventory: `ergo-chain-spec/Cargo.toml` and **all 1,386 lines** of `ergo-chain-spec/src/lib.rs`, including 29 tests, private helpers, literals and comments. The crate has no feature declarations, standalone tests, doctest examples, binary, example, benchmark or build script. `--all-features` and `--no-default-features` introduce no target feature variants. No applicable `AGENTS.md` was found. Full inventory and exact support/seam coverage are in [coverage ledger](ergo-chain-spec-coverage.md), [inventory](ergo-chain-spec-evidence/inventory.json) and [source hashes](ergo-chain-spec-evidence/coverage-progress.json).

Reviewed support includes the common/selected audit prompts, CONTRIBUTING/SECURITY/architecture/compatibility/codemap docs, manifests/toolchain/license/CI policies, embedded genesis/script captures, all authored `scripts/devnet-mixed` files, cited extraction tools, pinned upstream configuration/source, and the listed constructor consumers. Coverage has 82 full-read rows (including both owned files), 10 exact seam reads, 22 generated-data validations, one external config diff validation, four discovery-only consumer files, and four unavailable external-evidence rows. Discovery or partial seam inspection never counts as a full-file read. Larger node/state/validation/mining/sync internals are separate audits, as coordinated by root.

Read-only primary authorities were resolved from `/home/arkadias/Coding/remote/ergo-scala`; its clean HEAD is Ergo v6.0.5 `5528ef569a41ebccbc8658212e6ee3c97d990b96`. Historical tags were read with `git show`, without checking out or changing that neighbor. Full pinned paths, SHA256 and links are in [upstream-authorities.json](ergo-chain-spec-evidence/upstream-authorities.json). Existing neighboring compiled caches are later 6.0.6 snapshot revisions and were **not** treated as v6.0.3/v6.0.5 authority. The pinned node oracle's `.work/classpath` is absent. Available local JVM tools were used only to compile the exact dependency-free voting source into this report's evidence directory: Corretto 17.0.17 and Scala compiler 2.12.21; jar hashes are recorded in [JVM provenance](ergo-chain-spec-evidence/jvm-voting-provenance.json).

Excluded execution: live nodes/peers, production databases/wallets/secrets, native macOS/Windows/32-bit runs, full-chain campaigns, publication and external messages. Source availability was checked before declaring missing evidence; having a JVM does not supply the absent historical testnet first-header/epoch captures.

## Contract map and invariant ownership

`Network::{as_str,Display,FromStr}` selects a preset. Parsing is case-insensitive, does not trim whitespace and rejects every other spelling with a string error; CLI/TOML resolution calls this parser. Rust `devnet` selects a private recipe whose Scala `networkType` is `devnet60`, not the same literal name. This distinction should be reflected in the overly broad `as_str` Rustdoc.

`NetworkParams`, `DifficultyParams`, `V2Activation`, `VotingParams`, `MonetaryParams`, `ReemissionParams`, `GenesisParams`, `BlockTimingParams` and `BootstrapParams` are public mutable data. `ChainSpec::{mainnet,testnet,devnet,for_network}` supplies coherent canonical combinations; `NetworkParams`, `DifficultyParams` and `GenesisParams` additionally have narrow dispatchers. No serialization/validation capability prevents a library caller from building inconsistent or out-of-domain combinations. `NodeConfig::load` establishes normal production presets and validates supported genesis evidence, private magic/cost overrides, checkpoint byte widths and NiPoPoW pin requirements. The whole `ChainSpec` is shared through `Arc`; the crate owns no worker, lock, persistent mutation, cancellation or publication state machine.

Input/output paths reviewed:

| Input/parameter | Consumer boundary and ownership |
|---|---|
| Network string | `ergo-node/src/config/load.rs:47`; CLI/TOML to `Network` to `ChainSpec::for_network` |
| Magic/address prefix | Boot handshake and outgoing/incoming wire configuration at `node/boot/mod.rs:724,906`; address/API/mining bridges consume `network_params.address_prefix` |
| Genesis boxes/root/header ID | `ergo-node::genesis::genesis_boxes_for` chooses immutable embedded data by Network; boot seeds the state, forwards configured genesis ID to executor, and dense restart check verifies stored height-one ID/hash/shape |
| Difficulty schedule/lookback | `ergo-crypto::difficulty` and PoW; `ergo-validation::popow::proof` consumes `use_last_epochs`; store prover and bootstrap receive network difficulty parameters |
| Voting schedule | Boot forwards `ChainSpec.voting` into UTXO/digest stores; updateFork, block fork-window checks and mining use the same re-exported type |
| Monetary/re-emission | `ergo-mining` type re-exports remove constructor duplication; boot mining, candidate building, per-tx EIP-27 validation and emission API receive narrow views |
| Script constants | `ChainSpec::emission_script_trees` gates fixed mainnet bytes; API bridge parses/renders them with the configured address prefix; boot mounts the route only for `Some` |
| Freshness | `BlockTimingParams::header_freshness_threshold_ms` feeds sync readiness; it changes download timing, not header/block consensus acceptance |
| Seeds/checkpoint | Config adds operational seed fallbacks; separate checkpoint resolution supplies the script-validation shortcut; header-only checkpoint is a different opt-in setting |

A custom `genesis.boxes_json` is not a dynamic runtime box source: genesis loading dispatches on `Network`, while `validate_supported` only tests presence. Canonical construction keeps these views aligned. No arbitrary custom-chain support is certified here. Likewise, custom zero epoch lengths, large counts or invalid monetary settings can reach division/overflow or large work in downstream raw helpers. Public construction owns those preconditions; standard external configuration does not expose these schedule fields. Rejecting all impossible plain-data states is not a requirement placed on this crate.

Devnet uses distinct magic, the testnet address prefix and boxes/root, no public height-one ID, no seeds/checkpoint/re-emission, and explicit private recipe directories. Config rejects private magic overrides on public networks and rejects either public magic as a private override. Nine current devnet configuration/integration tests pass. NiPoPoW bootstrap refuses an absent genesis pin, so the unpinned devnet default cannot enable it. Existing-store genesis checking returns early for `None` or sparse PoPoW storage; private epoch/magic persistent fingerprints and full resume isolation remain full-node audit obligations. The campaign explicitly excludes reaching its huge epoch boundary.

### Checkpoint trust assumption

Mainnet's `(1,231,454, ca5aa96a…)` shortcut is present by default and comes from the pinned mainnet config. `ergo-validation/src/block/validate.rs:114,418` pins the ID at the exact checkpoint height and skips per-input script evaluation for heights **at or below** it. Per-tx initialization cost is skipped with evaluation. Rust retains canonical/structural/group-element/height/monetary/EIP-27 checks, section/transaction/extension commitments, and applied AVL state-root verification (`tx/mod.rs:276-345` and block/state consumer seams). Those checks do not establish spending authorization without script execution; the historical prefix is trusted until the known checkpoint is reached.

Pinned Scala `ErgoState.execTransactions` returns `Valid(0L)` below its checkpoint and bypasses a broader stateful-validation loop. Rust's retained checks are therefore a narrower shortcut, not a claim that every skipped reference step matches. No concrete historical reject-valid case was established. A custom checkpoint ID/height is an operator trust decision; disabling the script checkpoint with height zero requests full evaluation. It is distinct from the optional header checkpoint, which skips no validation. Updating seeds does not alter either checkpoint or genesis fields, and historical seed observations do not prove present liveness.

## Field-by-field authority table

Authority keys, all pinned primary sources:

- **A1**: [v6.0.2 mainnet.conf](https://github.com/ergoplatform/ergo/blob/2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1/src/main/resources/mainnet.conf), revision `2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1`.
- **A2**: [v6.0.2 application.conf](https://github.com/ergoplatform/ergo/blob/2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1/src/main/resources/application.conf), same revision; v6.0.3 defaults were diff-validated and the relevant consensus blocks are unchanged.
- **A3**: [v6.0.3 testnet.conf](https://github.com/ergoplatform/ergo/blob/28ebb184b0c90ee9adebe1111eb6aa3244798ba9/src/main/resources/testnet.conf), revision `28ebb184b0c90ee9adebe1111eb6aa3244798ba9`.
- **A4**: [v6.0.3 LaunchParameters.scala](https://github.com/ergoplatform/ergo/blob/28ebb184b0c90ee9adebe1111eb6aa3244798ba9/ergo-core/src/main/scala/org/ergoplatform/settings/LaunchParameters.scala); identical file at v6.0.5. Source/config launch authority, not a captured first-epoch verdict.
- **A5**: pinned v6.0.2 `Parameters.scala`, `VotingSettings.scala`, `DifficultyAdjustment.scala` and `ChainSettings.scala` extracts; exact dependency-free VotingSettings was additionally executed on the JVM.
- **A6**: pinned v6.0.2 `ReemissionContracts.scala` and v6.0.3 `ReemissionSettings.scala` extracts.
- **D**: current `scripts/devnet-mixed/genesis.conf` and `scala-node.conf`; historical paired receipts identify v6.0.5/sigma6.0.6 and earlier Rust revisions explicitly.
- **Gm/Gt**: embedded mainnet/testnet genesis JSON; current-node parser/box IDs/full consumption/AVL reconstruction checked against independently pinned config roots. Testnet height-one capture remains absent.
- **E**: independently captured mainnet `test-vectors/api/emission/scripts.json` and 17 `at_*.json` rows; capture claim lacks a per-file timestamp/source-SHA receipt, so exact bytes/outcomes are stronger evidence than its claimed live version/date.

All rows name the canonical aggregate constructor **C** = `ChainSpec::<network>()`/`for_network`; **N/Df/G** additionally mean `NetworkParams::for_network`, `DifficultyParams::for_network`, `GenesisParams::for_network`. Narrow and aggregate values agree. `None` means absent protocol group/transition/pin, not height zero.

| Field; unit | Mainnet | Testnet | Devnet | Authority / constructor / consumer / limit |
|---|---|---|---|---|
| Network; selector/display | `mainnet` | `testnet` | Rust `devnet`; Scala `devnet60` | A1/A3/D; C; config/telemetry. Case accepted; surrounding whitespace rejected. |
| `network_params.magic`; 4 wire bytes | `[1,0,2,4]` | `[2,3,2,3]` | `[7,7,7,7]` | A1/A3/D; C,N; wire framing. Old `[2,0,2,3]` absent from reset constructors. |
| `address_prefix`; high nibble | `0x00` | `0x10` | `0x10` | A1/A3/D; C,N; address encoder/API/mining. |
| `difficulty.epoch_length`; blocks | 1024 | 128 | 33,554,432 | A2/A3/D; C,Df; retarget/NiPoPoW/mining. |
| `eip37_epoch_length`; blocks | `Some(128)` | `None` | `None` | A1/A3/D; C,Df; child-height epoch regime. |
| `eip37_activation_height`; child block height | `Some(844673)` | `None` | `None` | A5; C,Df; crypto and proof consumers. Before/at/after current helper checked. |
| `v2_activation.height`; block height | `Some(417792)` | `None` | `None` | A1/A4/D; C,Df; reset applies when parent or child is activation height. A4→actual testnet launch unresolved. |
| `v2_activation.initial_difficulty`; BE bytes | `6f98d5000000` | no descriptor | no descriptor | A1; C,Df; BE BigUint reset, `nBits=0x066f98d5`. |
| `initial_difficulty`; BE bytes | `011765000000` | `01` | `01` | A1/A3/D; C,Df; genesis PoW/bootstrap. All pinned values are positive under Scala BigInt and Rust BigUint. |
| `desired_interval_ms`; milliseconds | 120000 | 45000 | 20000 | A2/A3/D; C,Df; retarget. |
| `use_last_epochs`; epochs | 8 | 8 | 8 | A2/A3 inheritance/D; C,Df; crypto duplicate constant and NiPoPoW connections. Agreement test passes; custom differing lookback is not whole-stack support. |
| `voting.voting_length`; blocks/epoch | 1024 | 128 | 33,554,432 | A2/A3/D; C; store/updateFork/mining. |
| `soft_fork_epochs`; voting epochs | 32 | 32 | 32 | A2/A3/D; C; fork tally. |
| `activation_epochs`; voting epochs | 32 | 32 | 32 | A2/A3/D; C; post-approval activation. |
| `version2_activation`; block height | `Some(417792)` | `None` | `None` | A1/A4/D; C; forced-v2 branch; paired with difficulty height. Testnet production launch view differs: ECSP-003. |
| Soft-fork approval; strict tally | `votes > 29491` | `votes > 3686` | JVM/optimized threshold 107374182; debug panic | A5; C; public helper/updateFork/block fork-window. ECSP-002. Mathematical wide product would yield 966367641 and would change pinned JVM behavior. |
| Parameter-change approval; strict tally | `count > 512` | `count > 64` | `count > 16777216` | A5; C; voting; canonical positive signed ranges. |
| `monetary.fixed_rate`; nanoERG/block | 75,000,000,000 | same | same | A2/A3 inheritance/D; C; mining/emission API. |
| `fixed_rate_period`; blocks | 525600 | same | same | A2; C; emission curve. First reduced block is at this height. |
| `monetary.epoch_length`; blocks | 64800 | same | same | A2; C; reduction periods; distinct from voting/difficulty epochs. |
| `one_epoch_reduction`; nanoERG/block | 3,000,000,000 | same | same | A2; C; emission curve. |
| `founders_initial_reward`; nanoERG/block | 7,500,000,000 | same | same | A2; C; founder/miner split. |
| `miner_reward_delay`; blocks | 720 | same | same | A2/A3/D; C; mining output scripts and A6 contracts. Omitted from script identity gate: ECSP-001. |
| Optional `reemission` group | `Some` | `None` | `None` | A1/A3/D; C; EIP-27 validation/mining/API. Testnet config has unreachable activation100000001 and commented/empty IDs; Rust models absence. |
| `activation_height`; block height | 777217 | absent | absent | A1; C; injection/validation and miner deduction. |
| `reemission_start_height`; block height | 2080800 | absent | absent | A1/A6; C; distribution/miner re-emission transition. The name marks post-original-emission payout start; pre-transition accumulation ceases there. Omitted from script gate. |
| `emission_nft_id`; 32 bytes | `20fa2bf23962cdf51b07722d6237c0c7b8a44f78856c0f7ec308dc1ef1a92a51` | absent | absent | A1; C; EIP-27 emission box identity. |
| `reemission_nft_id`; 32 bytes | `d3feeffa87f2df63a7a15b4905e618ae3ce4c69a7975f171bd314d0b877927b8` | absent | absent | A1/A6/E; C; injection/re-emission contract identity. |
| `reemission_token_id`; 32 bytes | `d9a2cc8a09abfaed87afacfbb7daee79a6b26f10c6613fc13d3f3953e5521d1a` | absent | absent | A1; C; EIP-27 token accounting. |
| `genesis.state_digest`; 33 AVL bytes | `a5df145d41ab15a01e0cd3ffbab046f0d029e5412293072ad0f5827428589b9302` | `cb63aa99a3060f341781d8662b58bf18b9ad258db4fe88d09f8f71cb668cad4502` | same as testnet | A1/A3/D/Gm/Gt; C,G; parser→AVL root verified for every preset. |
| `genesis.header_id`; 32-byte height-one ID | `Some(b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b)` | `Some(5b1827ca092b599eafbaf339d2acf2445bc5216ec2e022d9c001a6fff660cad9)` | `None` | A1 proves mainnet; testnet REST capture claimed by source but absent; C,G; header ingest/restart/NiPoPoW. |
| `genesis.boxes_json`; raw embedded JSON | mainnet3 boxes | testnet3 boxes | same testnet3 boxes | Gm/Gt/D; C,G; node genesis dispatch. Emission/founder boxes identical; no-premine registers/box ID differ. |
| `block_timing.desired_interval_ms`; milliseconds | 120000 | 45000 | 20000 | A2/A3/D; C; sync readiness; equals Df interval. |
| `header_chain_diff`; heuristic block count | 100 | 800 | 800 | A2/A3/D inheritance; C; readiness only. |
| Derived freshness threshold; ms | 12,000,000 | 36,000,000 | 16,000,000 | Product checked for presets; C; coordinator. Arbitrary public u64×u32 inputs can overflow; callers own their range. |
| `bootstrap.seed_peers`; SocketAddr list | 13 addresses listed below | `178.104.182.94:9040`, `128.253.41.110:9020`, `176.9.15.237:9021` | empty | A1; testnet intentionally differs from A3 on a claimed2026-08 observation without receipt; C; operational dialing. No current liveness assertion. |
| `bootstrap.checkpoint`; height+32-byte ID | `Some((1231454,ca5aa96a2d560f49cd5652eae4b9e16bbf410ee32365313dc16544ee5fda1e6d))` | `None` | `None` | A1/A3/D; C; exact-height full-block script shortcut, retained state checks as above. No retired h91320 pin inherited. |
| `EmissionScriptTrees.emission`; serialized tree | 228 bytes | `None` | `None` | Gm/E; API bridge; parsed at activated script version0, no trailing bytes. |
| `EmissionScriptTrees.reemission`; serialized tree | 266 bytes | `None` | `None` | A6/E; API bridge; parsed at activated script version1, no trailing bytes. |
| `EmissionScriptTrees.pay_to_reemission`; serialized tree | 62 bytes | `None` | `None` | A6/E; API bridge; distinct pay-to contract, parsed version1, no trailing bytes. Testnet absence is an intentional unverified-route divergence, not proof its contracts do not exist. |

Mainnet seed values, each normalized equivalent to A1: `213.239.193.208:9030`, `159.65.11.55:9030`, `165.227.26.175:9030`, `159.89.116.15:9030`, `136.244.110.145:9030`, `94.130.108.35:9030`, `51.75.147.1:9020`, `221.165.214.185:9030`, `217.182.197.196:9030`, `173.212.220.9:9030`, `176.9.65.58:9130`, `213.152.106.56:9030`, `[2001:41d0:700:6662::]:29031`. All constructor literals parse; `filter_map` currently drops none.

## Confirmed findings

### ECSP-001 — Contract identity gate omits contract-driving monetary/schedule fields

**Category:** API/contract provenance. **Severity:** P2. **Evidence:** REPRODUCED, with pinned-source causal proof. **Owner:** ergo-chain-spec; integration consumer: emission API.

Expected contract: fixed trees returned as verified per-network constants must match the monetary and re-emission settings from which their contracts are derived. `lib.rs:665-680` documents those dependencies and the defensive canonical-identity check. Pinned A6 uses `ms.minerRewardDelay` at ReemissionContracts line82 and `reemissionStartHeight` at line93.

Actual: `ergo-chain-spec/src/lib.rs:693-699` checks Network, magic/prefix, re-emission NFT and genesis state root, but does not check `monetary` or re-emission start height. Starting from `ChainSpec::mainnet()`, set either `monetary.miner_reward_delay=1` or `reemission.reemission_start_height=1`; `emission_script_trees()` still returns exactly the canonical720-delay/2080800-start byte vectors. [Temporary repro](ergo-chain-spec-evidence/public-api-repro.rs), [result](ergo-chain-spec-evidence/public-api-repro.log). The node's public `render_emission_scripts` then renders those bytes, while schedule/mining consumers receive the mutated settings.

Trigger: a library/embedder mutates a public spec and invokes this method or the public bridge. Normal `NodeConfig::load` does not expose these overrides, so no ordinary external production configuration or remote exploit was demonstrated. Returning a canonical address for a changed contract-driving configuration is the demonstrated consequence; wrong on-chain acceptance/funds loss is not demonstrated.

Smallest fix: gate all inputs embedded by these constants, using `MonetaryParams::mainnet()` equality and at least re-emission NFT/start-height agreement (whole `ReemissionParams` equality is a simple conservative canonical-spec policy). Document which custom changes are supported; no dynamic tree generator is needed. Preserve canonical bytes and all three API addresses. Add regressions mutating each contract-driving input; altered settings must yield `None` unless an independently generated matching tree is supplied. Existing tamper test only changes prefix/NFT/None and misses these fields. No storage migration is needed.

### ECSP-002 — Canonical private voting helper panics with overflow checks and custom values can differ from Scala

**Category:** arithmetic/API reliability. **Severity:** P2, narrow private/custom trigger. **Evidence:** REPRODUCED in current debug-checked Rust, optimized Rust, and exact pinned Scala source on the JVM. **Owner:** ergo-chain-spec; validation/block/mining consume its type.

Location: `ergo-chain-spec/src/lib.rs:308`, `ChainSpec::devnet` at629. Canonical devnet has `voting_length=33554432`, `soft_fork_epochs=32`. The intermediate `33554432*32*9` overflows u32. Calling `ChainSpec::devnet().voting.soft_fork_approved(0)` in the existing checked library panics at line308, caught by the temporary repro. Compiling the same authored library with `-C opt-level=3 -C overflow-checks=no` evaluates threshold107374182. Exact A5 `VotingSettings.scala`, compiled offline with Corretto17/Scala2.12.21, also evaluates107374182 and is stable across JVM modes. [Rust checked repro](ergo-chain-spec-evidence/public-api-repro.log), [optimized run](ergo-chain-spec-evidence/voting-optimized-run.log), [JVM run](ergo-chain-spec-evidence/jvm-voting-run.log), [JVM provenance](ergo-chain-spec-evidence/jvm-voting-provenance.json).

A caller-built positive length100000000 with32 epochs proves the signedness issue separately: optimized Rust reports `soft_fork_approved(0)=false`, pinned Scala reports `true` because signed Int wrapping produces threshold−126477107. That custom combination is not a declared supported network. Mainnet29491 and testnet3686 before/at/after comparisons agree with the JVM.

Reachability/impact: direct public helper invocation is sufficient. Block processors invoke it only with active fork state; the recorded private campaign never reaches its huge voting boundary and explicitly excludes that regime. This finding therefore establishes a profile-dependent panic on a canonical public API value and a custom-data arithmetic limit, not a present public-network availability attack. Wider i64 arithmetic alone would yield devnet966367641 and silently change JVM behavior.

Smallest fix: explicitly mirror signed Scala Int multiplication with wrapping operations for the supported signed domain, then signed division and strict comparison; alternatively reject/document unsupported configurations at a validated boundary. Keep canonical mainnet/testnet verdicts unchanged and decide the documented private API behavior. Regression: run exact pinned voting source and Rust for canonical networks, overflow-producing positive lengths, negative/zero votes and threshold−1/at/+1 under checked and optimized builds. Existing tests cover only non-overflowing public presets; the devnet constructor test never calls the helper.

### ECSP-003 — Testnet launch provenance and production parameter row disagree without closing evidence

**Category:** compatibility authority/important validation gap. **Severity:** P2. **Evidence:** SOURCE_CONFIRMED discrepancy and missing external validation; **not** a confirmed consensus split. **Owner:** ergo-validation's launch row, coordinated with ergo-chain-spec and node boot.

Expected contract: the chain spec's launch-based absence semantics and the production launch row must be tied to the same documented authority, or an observed-chain exception must have independent evidence. `ergo-chain-spec/src/lib.rs:213-219,287-294` justifies no testnet forced-v2 transition using `TestnetLaunchParameters` version4. Pinned A4 actually sets version4 and proposed disabled rules215/409, at both v6.0.3 and v6.0.5. v6.0.5 ErgoSettings selects this object for TestNet; `ErgoState.generateGenesisUtxoState` consumes `settings.launchParameters` by default.

Actual: `ergo-validation/src/active_params/launch.rs:30-44` claims that same Scala object is byte-identical to mainnet and returns version1/empty update. Its comment additionally mistakes interpreter50/60 object names for numeric header versions50/60 (actual3/4). The same consumer's `voting/recompute/update_fork.rs:133-136` meanwhile justifies `version2_activation=None` with new public testnet already using Interpreter60Version, reinforcing the internal authority contradiction. `ergo-node/src/node/boot/mod.rs:308-338,372` persists the returned row in ordinary UTXO and digest boot paths. [Current executable output](ergo-chain-spec-evidence/genesis-contract-run.log) prints testnet version1 with both updates empty; [pinned source extracts](ergo-chain-spec-evidence/upstream-authorities.json) prove the contradictory authority. The existing equality tests assert the claim internally, and the cost-default fixture checks mainnet costs only.

The launch file's test comment records a prior real-block h1024 mismatch after changing the row. That historical claim cannot be dismissed in favor of a current config/source literal. This checkout has no independent first-header/first-epoch fixture or full early-chain acceptance receipt to resolve which bootstrap adaptation is correct for the actual reset chain. The supplied higher-height v4 JSON oracles and the private devnet receipt do not answer that question.

Impact: public testnet's configured row/version/proposed-update provenance is unverified and misleading, undermining reference-quality compatibility claims. A block rejection/accept-invalid outcome is a separate hypothesis, below. Do **not** blindly replace the row with version4 on source evidence alone.

Fix order: capture/recover independently pinned reset-testnet height1 bytes, genesis/current settings, first epoch extension/parameter/validation-setting rows and a replay through the disputed h1024 boundary; identify node commit/config/state origin. Then reconcile the launch seed and absence rationale, documenting any historical-chain exception, and rewrite the equality tests around external evidence. Acceptance: fresh Rust UTXO and digest nodes using default testnet settings reproduce the independently observed epoch rows and accepted chain, including boundary−1/at/+1. No parameter migration should be designed before that evidence establishes the intended persisted row.

### ECSP-004 — Published testnet regeneration instructions fail before extraction and describe an obsolete gate

**Category:** documentation/reproducibility. **Severity:** P3. **Evidence:** REPRODUCED argument failures and SOURCE_CONFIRMED schema/status mismatch. **Owner:** testnet provisioning documentation/extraction tooling.

At `test-vectors/testnet/PROVISIONING.md:75,78`, the documented digest and genesis commands supply two arguments. `extract_utxo_digests.sh` requires `(start,end,out)`; `extract_boxes.sh` requires `(ids|block,arg,out)`. Running those exact commands from the documented directory exits1 at usage validation before curl or writes. [Digest log](ergo-chain-spec-evidence/provisioning-digests-usage.log), [genesis log](ergo-chain-spec-evidence/provisioning-genesis-usage.log). Furthermore the latter script extracts output-box IDs/serialized bytes/tree summaries from mined blocks; block0 is not the `/utxo/genesis` array with value, registers, transactionId, creationHeight and index consumed by `GenesisParams`/node genesis parsing.

The same doc's lines81-86 says both testnet fields are `None`, but both are already `Some`; it claims height-one header/digest captures live here, while both are absent. Its build command uses `target/scala-2.13`, whereas the pinned node/build harness targets Scala2.12. The cited local CLAUDE.md is absent and public CONTRIBUTING/compatibility documents now own the oracle policy.

Trigger/impact: an operator following the shipped reproduction steps cannot regenerate the promised baseline evidence. Existing frozen tests pass without running these instructions. Fix: provide the proper digest arity (`1 1 output`), a pinned `/utxo/genesis` capture procedure and receipt/schema/ID/root checks; correct build version/path and describe current startup status and missing first-epoch evidence. Validate argument-only steps offline; validate successful extraction only in an explicitly authorized disposable reference session. Existing fixture bytes must stay unchanged unless independently recaptured evidence justifies a change.

## Unresolved risks and external evidence gaps

- **R01 — HYPOTHESIS_REQUIRING_VALIDATION:** the testnet version1/empty launch seed may disagree with the reset chain's required initial/epoch state or may be a necessary historical bootstrap adaptation. ECSP-003 proves the source/provenance discrepancy, not a consensus verdict. Missing first-header/early-epoch/h1024 independent chain evidence is the prerequisite. Full node/state/validation audits should close the resulting persistent-row behavior.
- Testnet height-one ID `5b1827ca…` is a claimed REST observation without its checked-in header/capture receipt. The configured genesis root **is** independently anchored to A3 and reconstructed successfully; that does not authenticate the height-one pin. `test-vectors/testnet/header_height_1.json` and `state_digest_height_1.json` are absent even including ignored inventory.
- Testnet emission/re-emission/pay-to trees have no independent capture here; `None`/404 is deliberately conservative and documented in compatibility. Source prose saying usable NFT IDs still reside in testnet.conf is stale: they are commented out and inherited defaults are empty. This review makes no claim that the reference API has no contracts.
- Testnet seeds intentionally depart from pinned config, justified by a claimed2026-08 live observation with no durable receipt. Their syntax/count are verified; source-network membership and current liveness are not. No peer was probed.
- Mainnet script/genesis fixtures have pinned bytes and working independent config/capture cross-checks, but per-file origin receipts are incomplete. Full historical EIP-27 transition/block acceptance and continuous NiPoPoW campaigns are not run here. Difficulty boundary probes validate current wiring against source contracts; they are not a fresh JVM retarget differential over captured histories.
- Current 100-block devnet receipt verification passes for historical Rust `3cdc04e7db47f140cb05dc05c04a70526a935902`; the 101-102 submit receipt identifies Rust `608e49fcc3faf0e6bd139a4d4498339246a3af32`. Those records describe v6.0.5/sigma6.0.6 and paired block IDs/roots. They are not current-revision end-to-end passes, cover no voting/retarget boundary and do not establish public-network equivalence.
- Native Windows/macOS/32-bit execution and consumer lifecycle/storage/unsafe dependency proof beyond the listed seams are outside this execution scope. No authored `unsafe`, FFI, secret/entropy handling or concurrency exists in this crate. Miri/sanitizers/model checking are not needed for a concrete target-owned unsafe or lifecycle hypothesis; no transitive safety certification follows from that.

Low-impact comment corrections, beyond ECSP-004: remove claims that consumers never match Network (genesis, launch and candidate consumers do); document Rust `devnet` versus Scala `devnet60`; distinguish the re-emission payout-start meaning from generic distribution stop; remove “comparable” wall-clock voting windows (mainnet1024×120s versus testnet128×45s differs by21⅓). These improve operator/maintainer understanding without changing bytes.

## Coverage and verification evidence

All commands ran at the baseline revision; [commands.json](ergo-chain-spec-evidence/commands.json) records argv/cwd/environment/toolchain/exit/result and full log paths. No implementation edits preceded repros. Full owned-source review and generated validation details are in the [coverage ledger](ergo-chain-spec-coverage.md).

| Command/check | Result and scope | Full evidence |
|---|---|---|
| `cargo test --locked -p ergo-chain-spec` | PASS exit0; 29 unit passed, 0 failed/ignored; 0 doctests | [baseline-test.log](ergo-chain-spec-evidence/baseline-test.log) |
| Scoped all-target/all-feature clippy `-D warnings` | PASS exit0 | [scoped-clippy.log](ergo-chain-spec-evidence/scoped-clippy.log) |
| Locked package doctests | PASS exit0; 0 examples | [doctests.log](ergo-chain-spec-evidence/doctests.log) |
| Strict package Rustdoc `RUSTDOCFLAGS=-D warnings`, no-deps/all-features | PASS exit0 | [strict-docs.log](ergo-chain-spec-evidence/strict-docs.log) |
| Locked package no-default check | PASS exit0; featureless package | [minimal-check.log](ergo-chain-spec-evidence/minimal-check.log) |
| Production normal/build/features tree + metadata | PASS exit0; no JVM/sigma-rust/RNG runtime helper; ergo-ser/primitives plus hex, hashing/number/serde error/proc-macro dependencies | [tree](ergo-chain-spec-evidence/production-tree.log), [metadata](ergo-chain-spec-evidence/metadata.log) |
| Selected mainnet state genesis tests | PASS exit0; 3 passed/0ignored, box IDs + independent config root + block1 captured root | [downstream-genesis.log](ergo-chain-spec-evidence/downstream-genesis.log) |
| Mainnet script-address consumer test | PASS exit0; 1 passed/0ignored, all3 captured addresses | [downstream-contract-addresses.log](ergo-chain-spec-evidence/downstream-contract-addresses.log) |
| Difficulty unit seam | PASS exit0; 13 unit/0ignored; 0 selected integration tests, 44 filtered | [downstream-difficulty.log](ergo-chain-spec-evidence/downstream-difficulty.log) |
| Devnet configuration/selected integrations | PASS exit0; 9 passed/0ignored | [downstream-devnet-config.log](ergo-chain-spec-evidence/downstream-devnet-config.log) |
| Emission oracle test | PASS exit0; 1 test checks all17 independent height records including fixed-rate/founder/EIP-27/start/end boundaries | [downstream-emission-oracle.log](ergo-chain-spec-evidence/downstream-emission-oracle.log) |
| Voting updateFork seam | PASS exit0; 11 passed/0ignored, threshold, forced activation and round-state checks | [downstream-voting.log](ergo-chain-spec-evidence/downstream-voting.log) |
| Runtime genesis/script temporary repro | PASS compile/run exit0; all9 boxes across3 presets, every script/register fully consumed, all3 AVL roots, all3 script trees/context versions, actual launch rows printed | [source](ergo-chain-spec-evidence/genesis-contract-repro.rs), [run](ergo-chain-spec-evidence/genesis-contract-run.log) |
| Activation/paired-parameter probe | PASS compile/run exit0; child heights417791/417792/417793 and844672/844673/844674, interval/v2/lookback agreement and freshness products | [source](ergo-chain-spec-evidence/boundary-probe.rs), [run](ergo-chain-spec-evidence/boundary-run.log) |
| Mutated-spec / checked-overflow repro | Expected inconsistent output + caught panic; mainnet/testnet threshold−1/at/+1 are false/false/true | [source](ergo-chain-spec-evidence/public-api-repro.rs), [run](ergo-chain-spec-evidence/public-api-repro.log) |
| Same authored library with optimized overflow-disabled arithmetic | PASS compile/run exit0; devnet threshold107374182; custom positive domain signedness comparison | [optimized run](ergo-chain-spec-evidence/voting-optimized-run.log) |
| Exact pinned Scala VotingSettings offline | PASS strict compile/run exit0; mainnet/testnet/devnet/custom thresholds independently observed | [compile](ergo-chain-spec-evidence/jvm-voting-compile.log), [run](ergo-chain-spec-evidence/jvm-voting-run.log) |
| Historical devnet receipt verifier | PASS exit0; all100 paired observations, committed source/binary receipt identity; historical revision only | [offline-devnet-receipt.log](ergo-chain-spec-evidence/offline-devnet-receipt.log) |
| Published extraction argument repros | Expected usage FAIL exit1 each, before network/write; ECSP-004 | [digest](ergo-chain-spec-evidence/provisioning-digests-usage.log), [genesis](ergo-chain-spec-evidence/provisioning-genesis-usage.log) |
| Full pinned-node/testnet/historical-chain/native-platform campaign | NOT_RUN / unavailable required dataset/classpath; no parity pass implied | [environment](ergo-chain-spec-evidence/external-environment.json), [inventory](ergo-chain-spec-evidence/inventory.json) |

Production tree includes no target-owned `unsafe` or surprising feature-only execution; transitive primitives/serializer behavior has independent audits. Existing workspace advisory exceptions were reviewed in deny/CI policy and left unchanged: the bincode1.x unmaintained exception applies to local wallet persistence and is not a dependency of this package's normal/build graph. Root supplies current advisory-database/tool provenance and shared gate results.

An initial temporary standalone rustc invocation failed with E0463 because the dependency search path used the visible target directory while the shared build cache stores dependencies elsewhere. [Initial compile log](ergo-chain-spec-evidence/repro-compile.log) is retained. Using the emitted dependency-artifact parent fixed compilation ([corrected log](ergo-chain-spec-evidence/repro-compile-corrected.log)); this was an audit harness error, not a crate failure. Compiler artifacts and temporary binaries remain only under this evidence directory.

Test quality: most inline “matches Scala” assertions mirror literals and preserve snapshots; by themselves they are not independent parity. The actual independent evidence added here is the pinned source/config comparison, externally captured addresses/emission rows, mainnet block1 root, reconstructed genesis roots anchored to external config, and executed pinned JVM voting formula. Cross-crate type-alias equality tests establish wiring consistency rather than a second implementation oracle. Gaps missing from current tests are precisely the omitted contract-gate fields, overflow-producing private voting values, and independently anchored testnet initial/epoch parameters. Fixed-literal panic sites parse only authored immutable strings; every shipped ID/root width and every tree literal was exercised successfully. They are not runtime hex parsers for hostile network data.

## Dependency-ordered remediation and acceptance

1. **Resolve ECSP-003/R01 before changing production testnet parameters.** Recover a pinned reset-testnet capture from an independently provisioned disposable reference (node/config/revision/state origin; first header and epoch-extension rows through h1024). Full-node owner should replay it on both UTXO and digest boot paths. Use that evidence to select/document the initial row and any migration; verify boundary−1/at/+1 and fresh/reopen behavior. No live capture was authorized in this audit.
2. **Fix ECSP-001 gate and preserve existing canonical byte/API outputs.** Mutated monetary/start/NFT settings return None; canonical mainnet still matches all3 captured addresses and genesis emission bytes; public testnet/devnet remain absent until independent contract evidence exists.
3. **Fix ECSP-002 arithmetic with explicit authority.** Use signed JVM semantics or explicit validated supported-domain rejection, never silently widen to a different threshold. Run checked/optimized Rust and the exact pinned JVM formula on canonical/private/overflow inputs; rerun relevant voting/block/mining tests. This needs no stored-byte format change.
4. **Repair ECSP-004 and related accurate-scope Rustdoc.** Correct arities/genesis endpoint, source/build paths, current startup status and origin receipt expectations. Validate successful generation in a separately authorized disposable reference environment, retaining existing expected outputs unless independent evidence establishes replacement.
5. Rerun the changed package's locked tests/scoped clippy/strict docs and only affected downstream gates; reuse unchanged shared workspace results. Native platform/full-chain acceptance remains separate evidence, not a promise inferred from these host checks.

Owned coverage truly completes this audit assignment; external acceptance prerequisites and broader consumer audits remain clearly listed. The readiness judgment is NOT_READY because the confirmed narrow API defects and material public-testnet authority gap are unresolved, not because every downstream crate or native platform was silently assumed reviewed.
