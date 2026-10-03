# `ergo-mining` reference-node audit prompt

Audit `ergo-mining` as the candidate-generation and external-miner solution boundary of a reference-quality Ergo Rust node.
First read `docs/audit-prompts/COMMON.md` and apply its entire audit contract and report format.
Then read `CONTRIBUTING.md`, `docs/compatibility.md`, and `docs/codemap/ergo-mining.md`.
This is a review-only audit unless the invoking user explicitly authorizes remediation.
Verify the implementation and current fixture provenance rather than inheriting historical audit claims.
Independently inventory every crate file, test/include/fixture and shared mining/oracle/extraction script.
Apply COMMON to all implementation, tests, comments, rustdoc, manifests, examples, benchmarks and feature configurations.

## Mission and trust boundaries

Determine whether every served candidate is valid for the current applied chain and every acknowledged solution follows the normal validated, persistent block path.
Treat external solutions, miner keys, custom extension sources, mempool snapshots, optional rent indexes and chain snapshots as separate boundaries.
Distinguish candidate policy from consensus validity; a local selection shortcut cannot bypass the validator's rules.
External-miner support is the implemented scope; do not manufacture a defect from the deliberately absent internal CPU miner.
Inspect node/API/crypto/validation/state seams to establish real cache, scheduling, cancellation and durable success behavior.

## Current source landmarks

- `src/lib.rs`, `src/config.rs`, `src/error.rs`: facade, configuration validation, custom extension fields and failure taxonomy.
- `src/candidate.rs`, `candidate_selection.rs`, `tx_selection.rs`: candidate phases, overlay, selection and budget trimming.
- `src/state_view.rs`: `CandidateStateView`, live store and single-transaction committed-snapshot implementations.
- `src/engine.rs`: `BestTip`, `BuildIntent`, `BuildOutcome`, identity and off-loop build/publish guards.
- `src/handle.rs`: template/cache lock, current-tip publication, reward-key source, voting targets, suspects, longpoll notifications and solution lookup.
- `src/{emission_box,emission_rules,coinbase,reemission,reward_script,genesis}.rs`: applied-parent emission identity, rewards, EIP-27 and genesis paths.
- `src/storage_rent_claim.rs`, `src/extension_builder.rs`: rent interpreter parity, voted epochs, settings chunks and interlinks.
- `src/solution.rs`, `submit.rs`, `work_message.rs`: external work, PoW checks, stale-parent gate and section persistence.
- `tests/it/{main,chain_spec_parity,engine_published_parity,storage_rent_reemission_oracle}.rs` and all inline test modules.
- `ergo-node/src/node/{mining_engine,mining_dispatch}.rs`, `ergo-node/src/mining_bridge.rs`, boot mining wiring and `ergo-node/tests/it/mining_e2e.rs`.
- Shared `test-vectors/mining/`, `test-vectors/testnet/mining_json/`, cost ledgers, mainnet reward/emission/rent captures and referenced extraction tools.

Resolve the complete current module graph and include additional support files beyond these landmarks.

## Parent context, mining readiness and snapshots

- Candidate parent must be the applied full-block tip; a higher best-header tip cannot supply consensus inputs from an unapplied branch.
- Verify height, last applied header window, timestamp, difficulty, version, miner key, votes, parameters/settings and UTXO root all refer to one parent context.
- `CandidateStateView` must preserve a single committed view for every read, including box resolution, emission identity and dry-run prover base.
- Committed snapshot lag must be distinguished from stale-parent/different-branch state; retry outcomes cannot spin or serve a guessed parent.
- Candidate generation must not mutate live AVL state, indexes, emission metadata or wallet state on success or any error/panic path.
- Check `BestTip::synced` one-way mining-started latch: fresh applied-block trigger, nearly-synced height tolerance and restart of a stale persisted tip.
- `offline_generation` may waive only the documented freshness trigger; validate height gating and network/devnet safety at actual node wiring.
- Inspect latch behavior on large header gaps after mining has started, reorgs, no peers and future timestamps against pinned Scala authority.
- Mode 2 first-epoch trust sentinel must prevent boundary candidates that serialize unproven cumulative validation settings.
- Unsupported digest/headers-only mining must fail at configuration and runtime construction, not reach UTXO-only assumptions.

## Candidate transactions, overlays and budgets

- Verify transaction order `[emission, optional rent, selected user transactions, fee]` and parent-before-child ordering within selected users.
- Validate every selected transaction under the candidate context; stale mempool validation facts are not a valid candidate proof.
- Overlay must resolve intra-block creations, consumed inputs, committed data inputs and outputs without double spends or shadowing ambiguity.
- Selection must remain deterministic where promised, skip/record genuinely suspect transactions and retain valid independent candidates after a failed member.
- CPFP/priorities and dependency selection must not seat a child without its required parent or exceed bounded work on broad/deep packages.
- Use current voted `max_block_cost`/`max_block_size`, exact accounting units, reward/rent/fee overhead and cost-safety-gap arithmetic.
- Coinbase/rent prefixes are pinned but still cost/size bounded; an empty mempool cannot justify an oversized mandatory candidate.
- Aggregate transaction cost must match validator semantics and distinguish interpreter overflow/wrapping from policy saturation.
- Serialize final `BlockTransactions` under the selected block version before deciding it fits; estimate-only size checks are insufficient.
- Tail trimming must repair fee transaction, overlay, checked transactions, root/proof, suspects and final section IDs coherently.
- Check one transaction at the limit, many tiny transactions, maximal proof/register bytes, dependency tails and cost-versus-size tradeoffs.
- Dry-run output digest/proof must match exactly the emitted final ordered transactions, not an earlier untrimmed selection.
- A candidate should pass the actual downstream full-block validator before reference readiness is claimed; locally recomputed roots alone are insufficient.

## Emission, rewards, reemission and storage rent

- Resolve emission box through persisted applied-parent identity; distinguish exhausted identity from missing history/corrupt metadata.
- Legacy recovery must be bounded and followed by a verified identity; arbitrary script/box scanning cannot guess the emission input.
- Verify emission amounts, terminal height, reward maturity delay, fee sums and reward tree bytes/public-key placement with independent captures.
- Mainnet/testnet/devnet monetary rules must be explicit; mainnet constants cannot leak into an alternate-network builder.
- Review before/at/after EIP-27 activation, activation transaction shape, reemission box identity/registers and fee/reward redistribution.
- Check exhausted/absent emission boxes and block construction after emission termination.
- Storage-rent self-claim must match interpreter age, empty proof, context-extension variable 127, recreate-versus-seize and output index semantics.
- Verify preservation of script bytes, tokens/registers and creation height as required by rent rules.
- Wrapping/negative fee cases must follow consensus and be safely skipped where uncollectable; policy cannot change what the validator accepts.
- Pinned rent consumes boxes before user selection so fee-bearing competing claims cannot double spend them.
- Budget-bounded rent selection must count actual validation work and final block overhead without unbounded retries.
- Optional indexer rows are eventually consistent; materialize/recheck boxes from the committed candidate view, cap pagination and tolerate stale/missing rows.
- A rent-policy lookup failure can omit optional rent, but a consensus state read failure cannot become a valid empty/base candidate.
- Reward-key resolution, wallet-derived public keys and locked/uninitialized wallet outcomes must never route rewards to an unintended default key.

## Extension, voting and custom inputs

- Verify extension key ordering, uniqueness, per-field/total size, required fields, interlinks and serialized root against the exact final header.
- At epoch boundaries tally the correct finished epoch, compute next parameters/settings with validation's shared rule and serialize canonical map/chunks.
- Cover early/genesis epochs, vote thresholds, activation/deactivation and cumulative validation-setting history.
- Custom fields must not overwrite protocol-reserved keys or inject duplicate/colliding consensus fields.
- File-backed values must validate path/size/parse failures and resolve coherently within a build; inspect re-read policy and content changes during construction.
- Voting targets and custom field changes must participate in template refresh/cache identity where their semantic effect requires it.
- Document intentional first-boundary refusal and unsupported configuration with evidence, rather than treating every difference as a new consensus bug.

## Template publication, solutions and persistence

- Map cache/template identity, parent, chain sequence, pool revision, reward key, voting settings and final work bytes.
- Publish must compare the current tip under the same lock protecting cache state; a stale build must be discarded before serving.
- Serve/search must prefer the intended newest template for the current parent while respecting bounded history and same-parent refresh behavior.
- Longpoll/watch notifications must reflect visible serve changes and avoid missed wakeups, unconditional spin and leaked waits after withdrawal/shutdown.
- Parallel old/current solution lookup and preferred template selection must bind submitted message/nonce/key/proof to the exact cached candidate.
- Autolykos v2 hit/target, nonce size/encoding, invalid bits and equality-at-target must match crypto authority and negative vectors.
- Off-loop parent precheck is only early rejection; `prepare_mined_block` must recheck under action-loop ownership immediately before acceptance.
- Header persistence must precede durable section storage, announce and validated apply in the caller path.
- Retried solutions after partial section write must recover missing sections safely; duplicate header detection is not proof of full-block success.
- Section storage/serialization/commit failure and persist pipeline poisoning must reach `MiningSubmitError` and API responses without success acknowledgement.
- A timeout/dropped reply after processing begins must not hide actual block state; document acknowledgement versus applied/committed/durable guarantees.
- Node owns off-loop builder threads and held DB snapshots; aborting an async waiter must not detach real work or release capacity before work exits.

## Required evidence and meaningful verification

Start with `cargo test --locked -p ergo-mining --lib` and `cargo test --locked -p ergo-mining --test it`; inspect default/runtime dependency features.
Require external reward/emission/EIP-27/storage-rent, candidate/work-message and extension vectors with pinned network/height/context.
Compare live and committed-snapshot candidates byte-for-byte for the same parent and controlled timestamp, with independently validated final blocks.
Exercise parent changes during build/publish/serve/submit, same-height reorg, committed lag, cache eviction and dropped longpoll/submit callers.
Test budgets at limit minus one/at/plus one, final serialized-size trimming, intra-block dependencies and rent/user conflicts.
Include node mining end-to-end tests for PoW reject, accepted durable apply, duplicate retry, section persistence failure and no premature announce.
Inspect generation scripts and corpus registration; missing mainnet/testnet captures and oracle-only cases remain explicit evidence gaps.
Measure build latency and retained DB snapshots under sustained tip/pool changes, including a stale expensive build followed by minimal work.

## Crate-specific completion criteria

Report parent/context provenance, emitted-candidate validation evidence, template race/cancellation coverage and solution acknowledgement semantics under COMMON.
Separate consensus correctness, selection policy, optional rent behavior and external-miner API compatibility.
Do not certify reference readiness if a served candidate mixes snapshots, uses provisional settings, miscalculates rewards/budgets or acknowledges a persist/apply failure as success.
