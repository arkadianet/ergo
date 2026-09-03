//! Mining bridge dispatch: drives one `MiningRequest` (GetCandidate or
//! SubmitSolution) through the action-loop's owned state.
//!
//! # The mining gate (Scala parity)
//!
//! Candidates are built **on the applied full-block tip**, gated by a one-way
//! *mining-started latch* — not by an instantaneous "headers == bodies" test.
//! This mirrors the reference node exactly:
//!
//! - The latch can only be reached from a freshly applied block:
//!   `case FullBlockApplied(header) if shouldStartMine(header)`
//!   (`ErgoMiner.scala:172-174`), where
//!   `shouldStartMine = b.isNew(blockInterval * 2)` (`ErgoMiner.scala:116-117`)
//!   requires the applied block's own timestamp to be recent. Outside
//!   `offlineGeneration` (`ErgoApp.scala:212-216`) that is the ONLY sender of
//!   `StartMining`, so a node that boots on a stale persisted tip does not mine
//!   until the network gives it a fresh block.
//! - `ErgoMiner.isBlockchainNearlySynced`
//!   (`ergo-scala/.../mining/ErgoMiner.scala:119-121`) is
//!   `headersHeight < fullBlockHeight + 6`, checked once on the way from
//!   `starting` to `started` (`ErgoMiner.scala:128-155`); entering `started`
//!   unsubscribes from `FullBlockApplied` and the condition is never re-tested.
//! - `CandidateGenerator.createCandidate` takes its parent from
//!   `history.bestFullBlockOpt` (`CandidateGenerator.scala:530`) — the applied
//!   tip. The header tip plays no part.
//! - The only per-candidate freshness condition is
//!   `CandidateGenerator.generateCandidate`'s `chainSynced`
//!   (`CandidateGenerator.scala:415-416`):
//!   `h.bestFullBlockOpt.id == stateContext.lastHeaderOpt.id`, i.e. the UTXO
//!   state has finished applying the best full block. Our equivalent is the
//!   engine's commit-visibility check (`ergo_mining::engine::build_and_publish`),
//!   which waits for the committed snapshot to reflect the intent's parent.
//!
//! Requiring `best_header == best_full` instead would amplify liveness capture:
//! any party (or hiccup) that pushes headers ahead of bodies silently halts our
//! block production, and once honest production stops it never restarts. Scala
//! keeps producing on its applied tip and its blocks compete. Every input the
//! candidate reads — `last_applied_chain_window_10`, the parent header, the AVL
//! root — is sourced from the APPLIED chain (`CHAIN_INDEX` walked back from
//! `best_full_block_height`, `ergo-state/src/store/mod.rs`), so a leading header
//! tip cannot make a candidate script-divergent.
//!
//! On `SubmitSolution`, walks the same persistence + header pipeline
//! peer-received blocks go through (BT/Extension/ADProofs persist →
//! `process_header_cfg` → executor `AssembleBlock`), then confirms the
//! new tip matches the submitted header before replying `Ok`.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ergo_mining::engine::{BestTip, BuildIntent, BuildReason, MINING_SYNC_TOLERANCE};
use ergo_mining::handle::MiningHandle;
use ergo_state::wallet::RewardKeyResolution;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;
use tokio::sync::watch;
use tracing::{info, warn};

use super::peer_actions::flush_actions;
use super::NodeState;

/// The action loop's half of the off-loop mining wiring: a `MiningHandle`
/// clone (sharing the candidate cache with the engine task) plus the producer
/// end of the intent channel. Bundled into one value so the "mining enabled ⇒
/// both present" invariant is structural — there is no way to have a handle
/// without an intent channel or vice versa. `Some` exactly when mining is
/// configured on; `None` otherwise.
pub(super) struct MiningWiring {
    pub(super) handle: MiningHandle,
    pub(super) intent_tx: watch::Sender<Option<BuildIntent>>,
    /// Debounce window for the same-parent mempool-refresh trigger
    /// (`[mining].block_candidate_generation_interval_ms`). A burst of pool
    /// mutations between tip changes collapses into at most one rebuild per
    /// window; see [`mempool_refresh_due`].
    pub(super) refresh_debounce: Duration,
    /// The network's target block interval
    /// (`chain_spec.difficulty.desired_interval_ms` — mainnet 120_000, testnet
    /// 45_000). Twice this is the freshness window the mining-started latch
    /// requires of the applied tip; see [`mining_started_latch`].
    pub(super) block_interval_ms: u64,
    /// `[mining].offline_generation` — start mining without waiting for a
    /// freshly applied block (Scala `ErgoApp.scala:212-216`). Default `false`.
    pub(super) offline_generation: bool,
}

/// True if a mempool-refresh signal is due: never fired before, or the
/// debounce window has elapsed since the last one. Pure (instant arithmetic
/// only) so the action-loop branch stays trivially testable.
pub(super) fn mempool_refresh_due(
    last_signal: Option<Instant>,
    now: Instant,
    debounce: Duration,
) -> bool {
    last_signal.is_none_or(|t| now.duration_since(t) >= debounce)
}

/// The action-loop producer's tracked state between iterations, as the
/// signal decision consumes it: the tip the last signal reflected, the pool
/// revision it built against, and the timestamps that throttle the recovery
/// retry and the same-parent mempool refresh.
#[derive(Debug, Clone, Copy)]
pub(super) struct MiningProducerState {
    pub(super) last_tip: MiningTipSnapshot,
    pub(super) last_revision: u64,
    pub(super) last_recovery: Option<Instant>,
    pub(super) last_mempool_signal: Option<Instant>,
}

/// The two tuning windows [`decide_mining_signal`] throttles with: how often a
/// synced-but-uncovered node retries the recovery build, and the same-parent
/// mempool-refresh debounce (`[mining].block_candidate_generation_interval_ms`).
#[derive(Debug, Clone, Copy)]
pub(super) struct MiningSignalIntervals {
    pub(super) recovery: Duration,
    pub(super) refresh_debounce: Duration,
}

/// What the action-loop producer should signal this iteration, given the
/// current observations. Pure decision (no I/O) so the tip/recovery/refresh
/// precedence is unit-testable. `None` = signal nothing this iteration.
///
/// `mining_started` is the loop's latched gate (see [`mining_started_latch`]);
/// it is passed in rather than recomputed from `tip_now` because the latch is
/// one-way — a header run-ahead after the node started mining must not silence
/// the recovery/refresh signals.
pub(super) fn decide_mining_signal(
    prev: &MiningProducerState,
    tip_now: MiningTipSnapshot,
    mining_started: bool,
    has_cached_candidate: bool,
    revision_now: u64,
    now: Instant,
    intervals: MiningSignalIntervals,
) -> Option<BuildReason> {
    // 1. Tip moved (full OR header-only) → always re-signal; preempts the rest.
    if tip_now != prev.last_tip {
        return Some(BuildReason::Tip);
    }
    // 2. Started but nothing served yet (wallet just-ready / post-race) →
    //    throttled recovery retry.
    if mining_started
        && !has_cached_candidate
        && prev
            .last_recovery
            .is_none_or(|t| now.duration_since(t) >= intervals.recovery)
    {
        return Some(BuildReason::WalletReady);
    }
    // 3. Same tip, mempool advanced, debounce elapsed → same-parent refresh.
    if mining_started
        && revision_now != prev.last_revision
        && mempool_refresh_due(prev.last_mempool_signal, now, intervals.refresh_debounce)
    {
        return Some(BuildReason::MempoolRefresh);
    }
    None
}

/// A point-in-time view of the committed chain tip + header tip, used by the
/// action loop to detect when the off-loop candidate engine must be
/// re-signalled. `Default` is the zeroed sentinel the loop starts from so the
/// first signal (startup priming) always registers as a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct MiningTipSnapshot {
    best_full_id: [u8; 32],
    best_full_height: u32,
    best_header_id: [u8; 32],
    best_header_height: u32,
}

impl MiningTipSnapshot {
    /// Capture the current committed tip identity from the action-loop state.
    pub(super) fn capture(state: &NodeState) -> Self {
        let cs = state.store.chain_state_meta();
        Self {
            best_full_id: cs.best_full_block_id,
            best_full_height: cs.best_full_block_height,
            best_header_id: cs.best_header_id,
            best_header_height: cs.best_header_height,
        }
    }

    /// Scala's `ErgoMiner.isBlockchainNearlySynced`
    /// (`ErgoMiner.scala:119-121`): a full block exists and the header chain
    /// leads the applied chain by fewer than [`MINING_SYNC_TOLERANCE`] blocks.
    /// Never true at the zeroed genesis state.
    ///
    /// This is the *start* condition only. Once the loop has latched it into
    /// [`BestTip::synced`] the latch never re-closes, so a later header
    /// run-ahead cannot stop block production — see the module docs.
    pub(super) fn nearly_synced(&self) -> bool {
        self.best_full_height > 0
            && self.best_header_height < self.best_full_height + MINING_SYNC_TOLERANCE
    }

    /// The current best-full tip id (the candidate's parent).
    pub(super) fn best_full_id(&self) -> [u8; 32] {
        self.best_full_id
    }

    /// Test-only constructor: the fields are module-private, so unit tests for
    /// [`decide_mining_signal`] build snapshots through this rather than
    /// standing up a full `NodeState`.
    #[cfg(test)]
    pub(super) fn for_test(
        best_full_id: [u8; 32],
        best_full_height: u32,
        best_header_id: [u8; 32],
        best_header_height: u32,
    ) -> Self {
        Self {
            best_full_id,
            best_full_height,
            best_header_id,
            best_header_height,
        }
    }
}

/// Wall-clock milliseconds since the Unix epoch, for the latch's tip-freshness
/// comparison. A clock before the epoch yields 0, which makes every tip look
/// fresh — the same direction Scala's `System.currentTimeMillis` would fail in,
/// and harmless because the latch still requires a block to have been applied
/// while we were running.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// How many block intervals old the applied tip may be and still let the latch
/// open. Scala `ErgoMiner.shouldStartMine` is
/// `b.isNew(ergoSettings.chainSettings.blockInterval * 2)`
/// (`ErgoMiner.scala:116-117`).
const TIP_FRESHNESS_INTERVALS: u64 = 2;

/// The mining-started latch, as a pure function so both its preconditions and
/// its one-wayness are unit-testable. Once set it can never clear.
///
/// Three conditions, all required to OPEN it — the same three Scala applies:
///
/// 1. `full_block_applied` — Scala only ever reaches the sync check through
///    `case FullBlockApplied(header) if shouldStartMine(header)`
///    (`ErgoMiner.scala:172-174`), i.e. a block was just applied. It is never
///    evaluated against whatever state happened to be on disk at start-up.
/// 2. `tip.nearly_synced()` — `isBlockchainNearlySynced`
///    (`ErgoMiner.scala:119-121`).
/// 3. `tip_is_fresh` — `shouldStartMine`'s `isNew(blockInterval * 2)`
///    (`ErgoMiner.scala:116-117`): the applied block's own timestamp must be
///    recent in wall-clock terms.
///
/// (1) and (3) are what stop a node that has been offline for hours from
/// latching on its stale persisted tip the moment it boots — at that point
/// `best_header` and `best_full` are equal (nothing has been received yet) so
/// the height condition alone is trivially satisfied, and the node would mine
/// a dead parent for the whole catch-up with no way to re-close the latch.
///
/// `offline_generation` waives (1) and (3) only — the height condition (2) is
/// never waived, matching Scala, whose `offlineGeneration` path still routes
/// `StartMining` through `isBlockchainNearlySynced`. It exists for peerless
/// devnet chains, where no block will ever arrive to trigger the start.
///
/// Once open it stays open: Scala's `started` state unsubscribes from
/// `FullBlockApplied` (`ErgoMiner.scala:128-155`) and never re-checks. That
/// one-wayness is the liveness property — a party that pushes the header chain
/// ahead of the bodies cannot switch honest block production back off.
pub(super) fn mining_started_latch(
    already_started: bool,
    tip: MiningTipSnapshot,
    full_block_applied: bool,
    tip_is_fresh: bool,
    offline_generation: bool,
) -> bool {
    let start_trigger = offline_generation || (full_block_applied && tip_is_fresh);
    already_started || (start_trigger && tip.nearly_synced())
}

/// Whether the applied tip's own block timestamp is recent enough for the
/// latch — Scala `Header.isNew(blockInterval * 2)`. `None` (the tip's
/// `HEADER_META` row could not be read) is never fresh: refusing to start
/// mining is the safe direction, and the next applied block retries.
pub(super) fn tip_is_fresh(
    best_full_timestamp_ms: Option<u64>,
    now_ms: u64,
    block_interval_ms: u64,
) -> bool {
    let Some(ts) = best_full_timestamp_ms else {
        return false;
    };
    // Scala's `isNew` is a lower bound only — a header from the future is
    // still "new" there, and the block validator is what rejects excessive
    // drift, so we deliberately do not add an upper bound here.
    ts >= now_ms.saturating_sub(block_interval_ms.saturating_mul(TIP_FRESHNESS_INTERVALS))
}

/// Read the applied tip's block timestamp from its `HEADER_META` row.
///
/// Deliberately NOT a field on [`MiningTipSnapshot`]: `capture` runs on every
/// action-loop wake purely for tip-change detection, and this is a redb read
/// txn plus a row decode. Only the latch needs the value, and only while the
/// latch is still closed, so `signal_mining_engine` resolves it there and stops
/// paying for it the moment mining starts.
fn best_full_timestamp_ms(state: &NodeState, tip: &MiningTipSnapshot) -> Option<u64> {
    match state.store.get_header_meta(&tip.best_full_id) {
        Ok(Some(meta)) => Some(meta.timestamp),
        Ok(None) => None,
        Err(e) => {
            warn!(
                error = ?e,
                tip = %hex::encode(tip.best_full_id),
                "mining: could not read applied-tip timestamp; treating the tip as stale",
            );
            None
        }
    }
}

/// Update the mining engine's authoritative tip and, when synced, publish a
/// fresh [`BuildIntent`] over the watch channel. Called by the action loop
/// after every state-mutating arm (and once at startup) so the off-loop engine
/// always tracks the current best-full tip.
///
/// All consensus-bearing build inputs come from the engine's committed
/// snapshot; only the *policy* inputs that need action-loop state — the
/// resolved reward key and the frozen mempool snapshot — are resolved here
/// on the loop and frozen into the intent. Storage-rent-eligible boxes are
/// resolved by the engine task against the same committed snapshot the
/// candidate builds from.
///
/// `chain_seq` bumps on every best-full **id** change (including equal-height
/// reorgs); a header-only advance keeps the same seq. Returns the captured tip
/// so the caller can track it for change detection.
///
/// This is the sole writer of the mining-started latch (`BestTip::synced`).
/// It sets the bit the first time a freshly applied block leaves the node
/// nearly synced, and never clears it thereafter — Scala's one-way
/// `starting → started` transition. See [`mining_started_latch`] for why the
/// start-up prime deliberately cannot open it.
pub(super) fn signal_mining_engine(
    state: &NodeState,
    wiring: &MiningWiring,
    chain_seq: &mut u64,
    prev_best_full_id: &[u8; 32],
    reason: BuildReason,
) -> MiningTipSnapshot {
    let handle = &wiring.handle;
    let intent_tx = &wiring.intent_tx;
    let now = MiningTipSnapshot::capture(state);
    let best_full_advanced = &now.best_full_id != prev_best_full_id;
    if best_full_advanced {
        *chain_seq += 1;
    }
    let already_started = handle.best_tip().synced;
    // Scala's `FullBlockApplied` precondition. At the start-up prime
    // `prev_best_full_id` is the zero sentinel, so a bare id-difference test
    // would read the PERSISTED tip as a fresh application — exactly the case
    // that must not latch. Excluding `Startup` makes the precondition mean
    // "a block was applied while we were running", as it does in Scala.
    let full_block_applied = best_full_advanced && reason != BuildReason::Startup;
    // Only resolve the tip timestamp while the latch is still closed and a
    // block actually landed — see `best_full_timestamp_ms` for why this read is
    // kept off the hot path.
    let fresh = full_block_applied
        && !already_started
        && tip_is_fresh(
            best_full_timestamp_ms(state, &now),
            now_unix_ms(),
            wiring.block_interval_ms,
        );
    let synced = mining_started_latch(
        already_started,
        now,
        full_block_applied,
        fresh,
        wiring.offline_generation,
    );
    handle.set_best_tip(BestTip {
        parent_id: now.best_full_id,
        chain_seq: *chain_seq,
        synced,
    });
    // Never build before the latch closes (IBD); the tip is still published so
    // the serve path refuses correctly.
    if !synced {
        return now;
    }
    let Some(store) = state.store.as_utxo() else {
        return now; // mining is UTXO-only; defensive (the handle wouldn't exist)
    };
    // Resolve the reward key on the loop. Pending (wallet not initialized) or
    // Corrupt → publish no intent; the serve path resolves the key again to
    // return a distinct 503 (Pending) / 500 (Corrupt), and the throttled
    // synced-but-uncovered recovery retries once the wallet becomes ready.
    let miner_pk = match handle.resolve_reward_key(store) {
        RewardKeyResolution::Ready(pk) => pk,
        RewardKeyResolution::Pending | RewardKeyResolution::Corrupt => return now,
    };
    let mempool = ergo_mempool::MempoolReadSnapshot::from_pool(&state.mempool);
    let intent = BuildIntent {
        expected_parent: now.best_full_id,
        expected_height: now.best_full_height,
        mempool: Arc::new(mempool),
        miner_pk,
        reason,
    };
    // `watch::send` replaces the prior value (latest-wins); Err only if the
    // engine task receiver is gone (benign during shutdown).
    let _ = intent_tx.send(Some(intent));
    now
}

/// Skips everything (and replies `Unavailable`) when `mining_handle`
/// is `None` — defensive guard for the case where the channel sender
/// leaks past the configured-disabled gate (the bridge isn't built
/// when disabled, so no sender exists in practice).
pub(super) fn handle_mining_request(
    state: &mut NodeState,
    mining_handle: Option<&ergo_mining::handle::MiningHandle>,
    req: crate::mining_bridge::MiningRequest,
) {
    let handle = match mining_handle {
        Some(h) => h,
        None => {
            // No-op handle: reply Unavailable on whichever oneshot
            // the request carries. We avoid `panic!` even though
            // this branch is unreachable in steady state.
            match req {
                crate::mining_bridge::MiningRequest::GetCandidate { reply } => {
                    let _ = reply.send(Err(ergo_api::MiningApiError::Unavailable(
                        "mining disabled".into(),
                    )));
                }
                crate::mining_bridge::MiningRequest::SubmitSolution { reply, .. } => {
                    let _ = reply.send(Err(ergo_api::MiningApiError::Unavailable(
                        "mining disabled".into(),
                    )));
                }
                crate::mining_bridge::MiningRequest::GetRewardKey { reply } => {
                    let _ = reply.send(Err(ergo_api::MiningApiError::Unavailable(
                        "mining disabled".into(),
                    )));
                }
            }
            return;
        }
    };

    // Reward-key resolution is independent of sync state — answer it before
    // the mining-started gate. The candidate path freezes the reward key; this
    // read does not generate a candidate.
    if let crate::mining_bridge::MiningRequest::GetRewardKey { reply } = req {
        use ergo_state::wallet::RewardKeyResolution;
        // Degrade to a transport error rather than panic if UTXO state is
        // unavailable. In practice mining is config-gated to UTXO mode (so the
        // handle wouldn't exist in digest mode and we'd have returned above),
        // but the reward endpoints must never abort the process — they answer
        // 503/500. A `Pinned` key doesn't consult state at all; only the
        // `Wallet` path reads it.
        let payload = match state.store.as_utxo() {
            Some(store) => match handle.resolve_reward_key(store) {
                RewardKeyResolution::Ready(pk) => Ok(pk),
                RewardKeyResolution::Pending => Err(ergo_api::MiningApiError::Unavailable(
                    "reward key pending: wallet not initialized — unlock the wallet \
                     or set [mining].miner_public_key_hex"
                        .into(),
                )),
                RewardKeyResolution::Corrupt => Err(ergo_api::MiningApiError::Internal(
                    "reward key corrupt: wallet tracking has no/duplicate EIP-3 \
                     first-address key"
                        .into(),
                )),
            },
            None => Err(ergo_api::MiningApiError::Internal(
                "reward key unavailable: node is not running a UTXO state backend".into(),
            )),
        };
        let _ = reply.send(payload);
        return;
    }

    // Mining-started gate — the SAME latch the producer maintains, read from
    // the shared `BestTip` rather than recomputed here, so the serve path and
    // the build path can never disagree. See the module docs for why this is a
    // one-way latch on "nearly synced" and not a live `headers == bodies`
    // test.
    if !handle.best_tip().synced {
        let cs = state.store.chain_state_meta();
        let msg = format!(
            "node still catching up (best_header={}@{} best_full={}@{}); \
             mining starts once the header chain is within {} blocks of the applied chain",
            hex::encode(cs.best_header_id),
            cs.best_header_height,
            hex::encode(cs.best_full_block_id),
            cs.best_full_block_height,
            MINING_SYNC_TOLERANCE,
        );
        match req {
            crate::mining_bridge::MiningRequest::GetCandidate { reply } => {
                let _ = reply.send(Err(ergo_api::MiningApiError::Unavailable(msg)));
            }
            crate::mining_bridge::MiningRequest::SubmitSolution { reply, .. } => {
                let _ = reply.send(Err(ergo_api::MiningApiError::Unavailable(msg)));
            }
            // GetRewardKey is answered before this mining-started gate (above).
            crate::mining_bridge::MiningRequest::GetRewardKey { .. } => {
                unreachable!("GetRewardKey is handled before the mining-started gate")
            }
        }
        return;
    }

    match req {
        crate::mining_bridge::MiningRequest::GetCandidate { reply } => {
            // Cache-only serve. The off-loop engine is the sole candidate
            // producer (it CAS-publishes one candidate per tip into the shared
            // cache); the request path NEVER builds. `cached_work_if_synced`
            // re-checks the synced bit and the candidate's parent under the
            // cache lock, so it returns `None` (→ 503) when the engine has not
            // yet published for the current tip — the miner re-polls and the
            // engine publishes within a tick of the tip change. The
            // mining-started gate above already rejected the IBD case.
            let payload =
                match handle.cached_template_if_synced() {
                    Some((work, identity)) => Ok(crate::mining_bridge::work_message_to_json(
                        work,
                        identity.template_seq,
                        identity.clean_jobs,
                    )),
                    None => {
                        // Nothing published for the current tip yet. Distinguish a
                        // hard reward-key fault (operator misconfiguration) from
                        // transient unavailability, so the API doesn't mask a
                        // permanent error as a retryable race — matching the prior
                        // on-loop path, which surfaced Corrupt as a 500 and a
                        // Pending wallet key as a distinct 503.
                        let store = state.store.as_utxo().expect(
                            "utxo-only: mining candidate serving is gated off in digest mode",
                        );
                        match handle.resolve_reward_key(store) {
                        RewardKeyResolution::Ready(_) => Err(ergo_api::MiningApiError::Unavailable(
                            "no candidate published for the current tip yet; retry shortly".into(),
                        )),
                        RewardKeyResolution::Pending => Err(ergo_api::MiningApiError::Unavailable(
                            "reward key pending: wallet not initialized — unlock the wallet \
                             or set [mining].miner_public_key_hex"
                                .into(),
                        )),
                        RewardKeyResolution::Corrupt => Err(ergo_api::MiningApiError::Internal(
                            "reward key corrupt: wallet tracking has no/duplicate EIP-3 \
                             first-address key"
                                .into(),
                        )),
                    }
                    }
                };
            let _ = reply.send(payload);
        }
        crate::mining_bridge::MiningRequest::SubmitSolution { solution, reply } => {
            // 0. Decode the posted hex fields to typed form. ergo-mining is
            //    JSON-free; the decode + field/length errors live there via
            //    `MinerSolution::from_hex`.
            let typed = match ergo_mining::work_message::MinerSolution::from_hex(
                &solution.n,
                solution.pk.as_deref(),
            ) {
                Ok(t) => t,
                Err(e) => {
                    let _ = reply.send(Err(ergo_api::MiningApiError::Internal(format!(
                        "solution decode: {e:?}"
                    ))));
                    return;
                }
            };
            // 1. Verify against cached candidate (current then previous).
            let outcome = match handle.verify_solution(
                &typed,
                state
                    .store
                    .as_utxo()
                    .expect("utxo-only: mining solution verify is gated off in digest mode"),
            ) {
                Ok(o) => o,
                Err(e) => {
                    let _ = reply.send(Err(ergo_api::MiningApiError::Internal(format!(
                        "verify: {e:?}"
                    ))));
                    return;
                }
            };
            // Verdict line for the operator timeline (logging contract:
            // one INFO per meaningful transition, outcome as a field).
            info!(
                verdict = match &outcome {
                    ergo_mining::solution::SolutionOutcome::Accepted(_) => "accepted",
                    ergo_mining::solution::SolutionOutcome::InvalidPow => "invalid_pow",
                    ergo_mining::solution::SolutionOutcome::StaleParent { .. } => "stale_parent",
                },
                "mining solution verified"
            );
            let block = match outcome {
                ergo_mining::solution::SolutionOutcome::Accepted(b) => {
                    crate::metrics_counters::incr_accepted();
                    b
                }
                ergo_mining::solution::SolutionOutcome::InvalidPow => {
                    crate::metrics_counters::incr_invalid_pow();
                    let _ = reply.send(Err(ergo_api::MiningApiError::InvalidPow));
                    return;
                }
                ergo_mining::solution::SolutionOutcome::StaleParent { .. } => {
                    crate::metrics_counters::incr_stale_parent();
                    let _ = reply.send(Err(ergo_api::MiningApiError::StaleParent));
                    return;
                }
            };
            // 2. Persist BT/Extension/ADProofs + recheck parent_id
            //    under the action-loop lock (the consensus-bearing
            //    TOCTOU close). Returns header bytes + id we feed
            //    to process_header next.
            let (header_id, header_bytes) = match ergo_mining::submit::apply_mined_block(
                state
                    .store
                    .as_utxo_mut()
                    .expect("utxo-only: mined-block persist is gated off in digest mode"),
                block,
            ) {
                Ok(pair) => pair,
                Err(ergo_mining::submit::MiningSubmitError::StaleParent { .. }) => {
                    // Fresh-at-verify but tip moved before persist: still a
                    // stale-parent submission — count it once here so the
                    // two arms never double-count one solution.
                    crate::metrics_counters::incr_stale_parent();
                    let _ = reply.send(Err(ergo_api::MiningApiError::StaleParent));
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "mining: section persist failed");
                    let _ = reply.send(Err(ergo_api::MiningApiError::Internal(format!(
                        "persist: {e}"
                    ))));
                    return;
                }
            };
            // 3. Run the same header pipeline peer-received headers
            //    go through: PoW verify, chain linkage, difficulty
            //    check, persist into HEADERS + HEADER_META + (if
            //    best) HEADER_CHAIN_INDEX. Mining's PoW already
            //    passed the pre-check above, but process_header
            //    re-verifies — same consensus path as inbound
            //    blocks.
            //
            //    Uses `process_header_cfg` with the MiningHandle's
            //    chain_config so testnet mining is validated under
            //    testnet's difficulty schedule, not mainnet's. The
            //    convenience wrapper `process_header` hardcodes
            //    `DifficultyParams::mainnet()` and would misvalidate testnet.
            if let Err(e) = ergo_sync::header_proc::process_header_cfg(
                state
                    .store
                    .as_utxo_mut()
                    .expect("utxo-only: mined-header processing is gated off in digest mode"),
                &header_bytes,
                handle.chain_config(),
            ) {
                warn!(error = %e, "mining: header proc failed");
                let _ = reply.send(Err(ergo_api::MiningApiError::Internal(format!(
                    "process_header: {e}"
                ))));
                return;
            }
            // 4. Drive validation + apply through the executor's
            //    AssembleBlock path. Returns follow-up actions
            //    (Send / Penalize); mining doesn't trigger network
            //    I/O so any follow-ups are discarded.
            let rescan_guard = crate::wallet_boot::ProdRescanGuard;
            let wallet_wiring =
                state
                    .wallet_hook
                    .as_deref()
                    .map(|h| ergo_state::wallet::WalletWiring {
                        hook: h as &dyn ergo_state::wallet::WalletApplyHook,
                        rescan_guard: &rescan_guard,
                    });
            let follow_ups = state.executor.execute(
                Action::AssembleBlock { header_id },
                &mut state.store,
                &mut state.coordinator,
                Instant::now(),
                wallet_wiring,
            );
            // Best-effort routing: peer messages emitted as side-
            // effects (e.g. Inv broadcasts from a downstream chain
            // hook) ride the same dispatch the event-batch path
            // uses.
            flush_actions(state, follow_ups);

            // 5. Confirm the new tip is what we just applied. If
            //    the executor's apply path failed or the block was
            //    rejected, best_full_block_height won't have
            //    advanced and we surface a generic Internal error.
            let new_tip = state.store.chain_state_meta().best_full_block_id;
            if new_tip == header_id {
                let _ = reply.send(Ok(()));
            } else {
                warn!(
                    expected = %hex::encode(header_id),
                    observed = %hex::encode(new_tip),
                    "mining: block submission did not advance tip — likely validation rejection downstream",
                );
                let _ = reply.send(Err(ergo_api::MiningApiError::Internal(
                    "block apply failed (see node logs for the validation failure)".into(),
                )));
            }
        }
        // GetRewardKey is answered before the mining-started gate (above).
        crate::mining_bridge::MiningRequest::GetRewardKey { .. } => {
            unreachable!("GetRewardKey is handled before the mining-started gate")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn mempool_refresh_due_when_never_fired() {
        let now = Instant::now();
        assert!(mempool_refresh_due(None, now, Duration::from_millis(1000)));
    }

    #[test]
    fn mempool_refresh_not_due_within_window() {
        let base = Instant::now();
        let debounce = Duration::from_millis(1000);
        // 999ms after the last signal: one tick short of the window.
        let now = base + Duration::from_millis(999);
        assert!(!mempool_refresh_due(Some(base), now, debounce));
    }

    #[test]
    fn mempool_refresh_due_at_window_boundary() {
        let base = Instant::now();
        let debounce = Duration::from_millis(1000);
        let now = base + debounce;
        assert!(mempool_refresh_due(Some(base), now, debounce));
    }

    #[test]
    fn mempool_refresh_due_after_window() {
        let base = Instant::now();
        let debounce = Duration::from_millis(1000);
        let now = base + debounce + Duration::from_millis(1);
        assert!(mempool_refresh_due(Some(base), now, debounce));
    }

    // ----- tip_is_fresh (Scala shouldStartMine / isNew parity) -----

    /// Mainnet target block interval.
    const INTERVAL_MS: u64 = 120_000;
    /// An arbitrary "now" well clear of the epoch so subtraction is meaningful.
    const NOW_MS: u64 = 1_800_000_000_000;

    #[test]
    fn tip_is_fresh_tip_at_the_two_interval_boundary_is_fresh() {
        // Scala `isNew(d)` is `timestamp >= now - d`; the boundary is inclusive.
        assert!(tip_is_fresh(
            Some(NOW_MS - 2 * INTERVAL_MS),
            NOW_MS,
            INTERVAL_MS
        ));
    }

    #[test]
    fn tip_is_fresh_tip_one_ms_past_the_boundary_is_stale() {
        assert!(!tip_is_fresh(
            Some(NOW_MS - 2 * INTERVAL_MS - 1),
            NOW_MS,
            INTERVAL_MS
        ));
    }

    #[test]
    fn tip_is_fresh_tip_hours_old_is_stale() {
        assert!(!tip_is_fresh(
            Some(NOW_MS - 6 * 60 * 60 * 1000),
            NOW_MS,
            INTERVAL_MS
        ));
    }

    #[test]
    fn tip_is_fresh_unreadable_timestamp_is_stale() {
        assert!(!tip_is_fresh(None, NOW_MS, INTERVAL_MS));
    }

    #[test]
    fn tip_is_fresh_future_tip_is_fresh() {
        // `isNew` is a lower bound only; drift is the block validator's job.
        assert!(tip_is_fresh(
            Some(NOW_MS + INTERVAL_MS),
            NOW_MS,
            INTERVAL_MS
        ));
    }

    // ----- mining_started_latch (one-way, with Scala's preconditions) -----

    #[test]
    fn mining_started_latch_opens_on_a_fresh_applied_block_when_nearly_synced() {
        assert!(mining_started_latch(
            false,
            synced_tip(1, 100),
            true,
            true,
            /* offline_generation */ false,
        ));
    }

    #[test]
    fn mining_started_latch_stays_closed_during_ibd() {
        // Bodies are being applied and they are fresh, but the header chain is
        // still thousands ahead: this is IBD, and Scala does not mine.
        assert!(!mining_started_latch(
            false,
            header_ahead_tip(1, 100, 5_000),
            true,
            true,
            /* offline_generation */ false,
        ));
    }

    #[test]
    fn mining_started_latch_stale_persisted_tip_does_not_start() {
        // The restart case. A node that was fully synced hours ago boots with
        // best_header == best_full on a stale tip, so the height condition is
        // trivially satisfied and nothing has been received yet. Neither the
        // start-up prime (no block applied while running) nor the stale
        // timestamp may open the latch — otherwise the node serves candidates
        // on a dead parent for the whole catch-up, with no way to re-close it.
        let persisted = synced_tip(1, 100);
        assert!(
            !mining_started_latch(
                false, persisted, /* full_block_applied */ false,
                /* tip_is_fresh */ false, /* offline_generation */ false,
            ),
            "a stale persisted tip must not start mining at boot",
        );
        // Even once catch-up starts applying blocks, a tip still hours behind
        // wall clock keeps the latch closed.
        assert!(
            !mining_started_latch(
                false, persisted, /* full_block_applied */ true,
                /* tip_is_fresh */ false, /* offline_generation */ false,
            ),
            "applying historical blocks during catch-up must not start mining",
        );
        // Caught up: a freshly applied block at a nearly-synced tip starts it.
        assert!(
            mining_started_latch(
                false,
                synced_tip(2, 4_000),
                /* full_block_applied */ true,
                /* tip_is_fresh */ true,
                /* offline_generation */ false,
            ),
            "a fresh applied block at a caught-up tip must start mining",
        );
    }

    #[test]
    fn mining_started_latch_startup_prime_alone_never_starts() {
        // Belt and braces: even a genuinely fresh persisted tip does not latch
        // at the prime, because Scala only ever latches from FullBlockApplied.
        assert!(!mining_started_latch(
            false,
            synced_tip(1, 100),
            /* full_block_applied */ false,
            /* tip_is_fresh */ true,
            /* offline_generation */ false,
        ));
    }

    #[test]
    fn mining_started_latch_genesis_from_scratch_stays_closed() {
        // best_full == 0: nothing applied, so `nearly_synced` is false however
        // the other two preconditions land.
        assert!(!mining_started_latch(
            false,
            MiningTipSnapshot::default(),
            true,
            true,
            /* offline_generation */ false,
        ));
    }

    #[test]
    fn mining_started_latch_never_recloses_on_header_run_ahead() {
        // The whole point of the fix: an adversary (or a network hiccup) that
        // drives the header chain far ahead of the applied chain must not be
        // able to switch our block production back off. None of the three
        // opening preconditions is consulted once the latch is set.
        assert!(mining_started_latch(
            true,
            header_ahead_tip(1, 100, 5_000),
            /* full_block_applied */ false,
            /* tip_is_fresh */ false,
            /* offline_generation */ false,
        ));
    }

    #[test]
    fn mining_started_latch_never_recloses_on_a_rolled_back_tip() {
        assert!(mining_started_latch(
            true,
            MiningTipSnapshot::default(),
            false,
            false,
            /* offline_generation */ false,
        ));
    }

    #[test]
    fn mining_started_latch_offline_generation_waives_the_block_trigger() {
        // Devnet / peerless: no block will ever arrive to trigger the start, so
        // the operator opts out of the freshness precondition.
        assert!(mining_started_latch(
            false,
            synced_tip(1, 100),
            /* full_block_applied */ false,
            /* tip_is_fresh */ false,
            /* offline_generation */ true,
        ));
    }

    #[test]
    fn mining_started_latch_offline_generation_still_requires_nearly_synced() {
        // Scala's offlineGeneration path still routes StartMining through
        // `isBlockchainNearlySynced`, so the height condition is never waived.
        assert!(!mining_started_latch(
            false,
            header_ahead_tip(1, 100, 5_000),
            /* full_block_applied */ false,
            /* tip_is_fresh */ false,
            /* offline_generation */ true,
        ));
    }

    // ----- decide_mining_signal -----

    const RECOVERY: Duration = Duration::from_secs(1);
    const DEBOUNCE: Duration = Duration::from_millis(1000);
    const INTERVALS: MiningSignalIntervals = MiningSignalIntervals {
        recovery: RECOVERY,
        refresh_debounce: DEBOUNCE,
    };

    /// A caught-up snapshot at the given height: full == header (same id + height).
    fn synced_tip(id_byte: u8, height: u32) -> MiningTipSnapshot {
        MiningTipSnapshot::for_test([id_byte; 32], height, [id_byte; 32], height)
    }

    /// A snapshot whose header chain leads the applied chain by `lead` blocks.
    fn header_ahead_tip(id_byte: u8, full_height: u32, lead: u32) -> MiningTipSnapshot {
        MiningTipSnapshot::for_test(
            [id_byte; 32],
            full_height,
            [id_byte ^ 0xff; 32],
            full_height + lead,
        )
    }

    // ----- nearly_synced (Scala isBlockchainNearlySynced parity) -----

    #[test]
    fn nearly_synced_header_equal_to_full_is_true() {
        assert!(synced_tip(1, 100).nearly_synced());
    }

    #[test]
    fn nearly_synced_header_five_ahead_is_true() {
        // Scala: headersHeight < fullBlockHeight + 6 → 105 < 106 holds.
        assert!(header_ahead_tip(1, 100, 5).nearly_synced());
    }

    #[test]
    fn nearly_synced_header_six_ahead_is_false() {
        // 106 < 106 is false — the IBD boundary, matching ErgoMiner.scala:119-121.
        assert!(!header_ahead_tip(1, 100, 6).nearly_synced());
    }

    #[test]
    fn nearly_synced_deep_ibd_is_false() {
        assert!(!header_ahead_tip(1, 100, 900_000).nearly_synced());
    }

    #[test]
    fn nearly_synced_at_zero_height_is_false() {
        // Zeroed genesis state: no full block applied yet.
        assert!(!MiningTipSnapshot::default().nearly_synced());
    }

    #[test]
    fn nearly_synced_equal_height_sibling_header_is_true() {
        // best-header on a same-height sibling of the applied tip. Scala builds
        // on `bestFullBlockOpt` regardless (CandidateGenerator.scala:530); every
        // input we read comes from the applied chain, so this is not a reason to
        // stop producing.
        let tip = MiningTipSnapshot::for_test([1; 32], 100, [2; 32], 100);
        assert!(tip.nearly_synced());
    }

    #[test]
    fn decide_tip_change_returns_tip_even_when_revision_advanced() {
        // Tip moved AND the pool advanced: tip preempts the refresh branch.
        let now = Instant::now();
        let prev = MiningProducerState {
            last_tip: synced_tip(1, 10),
            last_revision: 5,
            last_recovery: Some(now), // recovery already fired (would gate WalletReady)
            last_mempool_signal: Some(now), // refresh just fired (would gate MempoolRefresh)
        };
        let tip_now = synced_tip(2, 11);
        let got = decide_mining_signal(
            &prev, tip_now, /* mining_started */ true, /* has_cached */ true,
            /* revision_now */ 9, now, INTERVALS,
        );
        assert_eq!(got, Some(BuildReason::Tip));
    }

    #[test]
    fn decide_synced_uncovered_recovery_due_returns_wallet_ready() {
        let base = Instant::now();
        let tip = synced_tip(1, 10);
        let prev = MiningProducerState {
            last_tip: tip,
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: None,
        };
        let got = decide_mining_signal(
            &prev,
            tip,
            /* mining_started */ true,
            /* has_cached */ false,
            5,
            base + RECOVERY, // interval elapsed
            INTERVALS,
        );
        assert_eq!(got, Some(BuildReason::WalletReady));
    }

    #[test]
    fn decide_synced_uncovered_recovery_within_interval_returns_none() {
        let base = Instant::now();
        let tip = synced_tip(1, 10);
        let prev = MiningProducerState {
            last_tip: tip,
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: None,
        };
        let got = decide_mining_signal(
            &prev,
            tip,
            /* mining_started */ true,
            /* has_cached */ false,
            5,
            base + Duration::from_millis(999), // one tick short of the interval
            INTERVALS,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn decide_same_tip_revision_advanced_debounce_elapsed_returns_refresh() {
        let base = Instant::now();
        let tip = synced_tip(1, 10);
        let prev = MiningProducerState {
            last_tip: tip,
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: Some(base),
        };
        let got = decide_mining_signal(
            &prev,
            tip,
            /* mining_started */ true,
            /* has_cached */ true,            // covered → recovery branch skipped
            6,               // revision advanced
            base + DEBOUNCE, // debounce elapsed
            INTERVALS,
        );
        assert_eq!(got, Some(BuildReason::MempoolRefresh));
    }

    #[test]
    fn decide_same_tip_revision_advanced_within_debounce_returns_none() {
        let base = Instant::now();
        let tip = synced_tip(1, 10);
        let prev = MiningProducerState {
            last_tip: tip,
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: Some(base),
        };
        let got = decide_mining_signal(
            &prev,
            tip,
            /* mining_started */ true,
            /* has_cached */ true,
            6,                                 // revision advanced
            base + Duration::from_millis(999), // within the debounce window
            INTERVALS,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn decide_same_tip_revision_unchanged_returns_none() {
        let base = Instant::now();
        let tip = synced_tip(1, 10);
        let prev = MiningProducerState {
            last_tip: tip,
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: Some(base),
        };
        let got = decide_mining_signal(
            &prev,
            tip,
            /* mining_started */ true,
            /* has_cached */ true,
            5,               // revision unchanged
            base + DEBOUNCE, // debounce elapsed, but nothing to refresh
            INTERVALS,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn decide_not_started_no_tip_change_returns_none() {
        // Still doing IBD and the tip didn't change: neither recovery nor
        // refresh fires before the mining-started latch closes.
        let base = Instant::now();
        let ibd = header_ahead_tip(1, 9, 5_000);
        let prev = MiningProducerState {
            last_tip: ibd,
            last_revision: 5,
            last_recovery: None,
            last_mempool_signal: None,
        };
        let got = decide_mining_signal(
            &prev,
            ibd,
            /* mining_started */ false,
            /* has_cached */ false, // would trigger recovery if started
            6,     // revision advanced — would trigger refresh if started
            base + DEBOUNCE,
            INTERVALS,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn decide_header_ahead_of_full_still_refreshes_once_started() {
        // The liveness property: headers racing ahead of bodies after the node
        // started mining must NOT silence the same-parent refresh. Under the old
        // `headers == full` gate this returned None and production halted.
        let base = Instant::now();
        let tip = header_ahead_tip(1, 100, 40);
        let prev = MiningProducerState {
            last_tip: tip,
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: Some(base),
        };
        let got = decide_mining_signal(
            &prev,
            tip,
            /* mining_started */ true, // latched earlier, never re-closed
            /* has_cached */ true,
            6,
            base + DEBOUNCE,
            INTERVALS,
        );
        assert_eq!(got, Some(BuildReason::MempoolRefresh));
    }

    #[test]
    fn decide_applied_tip_advance_under_header_lead_returns_tip() {
        // Bodies catching up one block while the header chain stays ahead is a
        // tip change: the candidate must be rebuilt on the new applied parent.
        let base = Instant::now();
        let prev = MiningProducerState {
            last_tip: header_ahead_tip(1, 100, 40),
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: Some(base),
        };
        let got = decide_mining_signal(
            &prev,
            header_ahead_tip(2, 101, 39),
            /* mining_started */ true,
            /* has_cached */ true,
            5,
            base,
            INTERVALS,
        );
        assert_eq!(got, Some(BuildReason::Tip));
    }

    #[test]
    fn decide_recovery_preempts_refresh_when_both_could_fire() {
        // Uncovered AND revision advanced AND both windows elapsed: recovery
        // wins (publish *any* candidate before refreshing a missing one).
        let base = Instant::now();
        let tip = synced_tip(1, 10);
        let prev = MiningProducerState {
            last_tip: tip,
            last_revision: 5,
            last_recovery: Some(base),
            last_mempool_signal: Some(base),
        };
        let got = decide_mining_signal(
            &prev,
            tip,
            /* mining_started */ true,
            /* has_cached */ false,
            6,
            base + DEBOUNCE, // both RECOVERY and DEBOUNCE elapsed (equal here)
            INTERVALS,
        );
        assert_eq!(got, Some(BuildReason::WalletReady));
    }
}
