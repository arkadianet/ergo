//! Mining bridge dispatch: drives one `MiningRequest` (GetCandidate or
//! SubmitSolution) through the action-loop's owned state. Gated by the
//! "applied tip == best-header tip" invariant so we never mine on a
//! sibling fork the network is about to reorg off.
//!
//! On `SubmitSolution`, walks the same persistence + header pipeline
//! peer-received blocks go through (BT/Extension/ADProofs persist →
//! `process_header_cfg` → executor `AssembleBlock`), then confirms the
//! new tip matches the submitted header before replying `Ok`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ergo_mining::engine::{BestTip, BuildIntent, BuildReason};
use ergo_mining::handle::MiningHandle;
use ergo_state::wallet::RewardKeyResolution;
use ergo_state::ChainStateRead;
use ergo_sync::coordinator::Action;
use tokio::sync::watch;
use tracing::warn;

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

/// What the action-loop producer should signal this iteration, given the
/// current observations. Pure decision (no I/O) so the tip/recovery/refresh
/// precedence is unit-testable. `None` = signal nothing this iteration.
pub(super) fn decide_mining_signal(
    prev: &MiningProducerState,
    tip_now: MiningTipSnapshot,
    has_cached_candidate: bool,
    revision_now: u64,
    now: Instant,
    recovery_interval: Duration,
    refresh_debounce: Duration,
) -> Option<BuildReason> {
    // 1. Tip moved (full OR header-only) → always re-signal; preempts the rest.
    if tip_now != prev.last_tip {
        return Some(BuildReason::Tip);
    }
    // 2. Synced but nothing served yet (wallet just-ready / post-race) →
    //    throttled recovery retry.
    if tip_now.synced()
        && !has_cached_candidate
        && prev
            .last_recovery
            .is_none_or(|t| now.duration_since(t) >= recovery_interval)
    {
        return Some(BuildReason::WalletReady);
    }
    // 3. Same synced tip, mempool advanced, debounce elapsed → same-parent refresh.
    if tip_now.synced()
        && revision_now != prev.last_revision
        && mempool_refresh_due(prev.last_mempool_signal, now, refresh_debounce)
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

    /// The full live mining-gate predicate (identical to the serve-time gate
    /// and `CommittedSnapshot::synced`): a full block exists and the header
    /// tip equals it. Never true at the zeroed genesis state.
    pub(super) fn synced(&self) -> bool {
        self.best_header_height == self.best_full_height
            && self.best_full_height > 0
            && self.best_header_id == self.best_full_id
    }

    /// The current best-full tip id (the candidate's parent).
    pub(super) fn best_full_id(&self) -> [u8; 32] {
        self.best_full_id
    }

    /// Test-only constructor: the fields are module-private, so unit tests for
    /// [`decide_mining_signal`] build snapshots through this rather than
    /// standing up a full `NodeState`. A synced snapshot needs full==header
    /// (same id + height) with height > 0.
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
    if &now.best_full_id != prev_best_full_id {
        *chain_seq += 1;
    }
    let synced = now.synced();
    handle.set_best_tip(BestTip {
        parent_id: now.best_full_id,
        chain_seq: *chain_seq,
        synced,
    });
    // Never build while unsynced; the tip is still published so the serve path
    // refuses correctly (header-only advance stops serving immediately).
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
    // the synced-tip gate. The candidate path freezes the reward key; this
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

    // Synced-tip gate. ergo-mining's design forbids mining at an
    // unsynced tip: the candidate's script-visible context
    // (last_applied_chain_window_10, last_block_utxo_root) would
    // diverge from the canonical chain the rest of the network is
    // building on, producing script-divergent candidates per
    // `ergo-mining/src/config.rs:17`.
    //
    // Two-part check, both required:
    //
    //   a) Heights match: best_header_height == best_full_block_height.
    //      Closes the obvious "header is ahead of body" gap.
    //
    //   b) Ids match: best_header_id == best_full_block_id. Closes
    //      the equal-height-different-id case where best-header is
    //      on a sibling fork at the same height we've applied — the
    //      chain may be about to reorg onto the heavier tip and
    //      mining on the applied (about-to-be-orphaned) tip would
    //      burn the solution. State permits this divergence after
    //      header processing flips the best-header pointer without
    //      applying the new block; full-block apply only realigns
    //      when it strictly increases the height (see
    //      `ergo-state/src/store/mod.rs` chain-state writes).
    //
    // Both `(a) && (b)` give the "applied tip == best-header tip"
    // invariant `last_applied_chain_window_10` relies on.
    let cs = state.store.chain_state_meta();
    let synced = cs.best_header_height == cs.best_full_block_height
        && cs.best_full_block_height > 0
        && cs.best_header_id == cs.best_full_block_id;
    if !synced {
        let msg = format!(
            "node not synced to tip (best_header={}@{} best_full={}@{}); refusing to mine",
            hex::encode(cs.best_header_id),
            cs.best_header_height,
            hex::encode(cs.best_full_block_id),
            cs.best_full_block_height,
        );
        match req {
            crate::mining_bridge::MiningRequest::GetCandidate { reply } => {
                let _ = reply.send(Err(ergo_api::MiningApiError::Unavailable(msg)));
            }
            crate::mining_bridge::MiningRequest::SubmitSolution { reply, .. } => {
                let _ = reply.send(Err(ergo_api::MiningApiError::Unavailable(msg)));
            }
            // GetRewardKey is answered before this synced-tip gate (above).
            crate::mining_bridge::MiningRequest::GetRewardKey { .. } => {
                unreachable!("GetRewardKey is handled before the synced-tip gate")
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
            // engine publishes within a tick of the tip change. The synced-tip
            // gate above already rejected the unsynced case.
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
            let block = match outcome {
                ergo_mining::solution::SolutionOutcome::Accepted(b) => b,
                ergo_mining::solution::SolutionOutcome::InvalidPow => {
                    let _ = reply.send(Err(ergo_api::MiningApiError::InvalidPow));
                    return;
                }
                ergo_mining::solution::SolutionOutcome::StaleParent { .. } => {
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
        // GetRewardKey is answered before the synced-tip gate (above).
        crate::mining_bridge::MiningRequest::GetRewardKey { .. } => {
            unreachable!("GetRewardKey is handled before the synced-tip gate")
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

    // ----- decide_mining_signal -----

    const RECOVERY: Duration = Duration::from_secs(1);
    const DEBOUNCE: Duration = Duration::from_millis(1000);

    /// A synced snapshot at the given height: full == header (same id + height).
    fn synced_tip(id_byte: u8, height: u32) -> MiningTipSnapshot {
        MiningTipSnapshot::for_test([id_byte; 32], height, [id_byte; 32], height)
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
            &prev, tip_now, /* has_cached */ true, /* revision_now */ 9, now, RECOVERY,
            DEBOUNCE,
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
            /* has_cached */ false,
            5,
            base + RECOVERY, // interval elapsed
            RECOVERY,
            DEBOUNCE,
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
            /* has_cached */ false,
            5,
            base + Duration::from_millis(999), // one tick short of the interval
            RECOVERY,
            DEBOUNCE,
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
            /* has_cached */ true,            // covered → recovery branch skipped
            6,               // revision advanced
            base + DEBOUNCE, // debounce elapsed
            RECOVERY,
            DEBOUNCE,
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
            /* has_cached */ true,
            6,                                 // revision advanced
            base + Duration::from_millis(999), // within the debounce window
            RECOVERY,
            DEBOUNCE,
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
            /* has_cached */ true,
            5,               // revision unchanged
            base + DEBOUNCE, // debounce elapsed, but nothing to refresh
            RECOVERY,
            DEBOUNCE,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn decide_unsynced_no_tip_change_returns_none() {
        // Header ahead of full (unsynced) and the tip didn't change: neither
        // recovery nor refresh fires while unsynced.
        let base = Instant::now();
        let unsynced = MiningTipSnapshot::for_test([1; 32], 9, [2; 32], 10);
        let prev = MiningProducerState {
            last_tip: unsynced,
            last_revision: 5,
            last_recovery: None,
            last_mempool_signal: None,
        };
        let got = decide_mining_signal(
            &prev,
            unsynced,
            /* has_cached */ false, // would trigger recovery if synced
            6,     // revision advanced — would trigger refresh if synced
            base + DEBOUNCE,
            RECOVERY,
            DEBOUNCE,
        );
        assert_eq!(got, None);
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
            /* has_cached */ false,
            6,
            base + DEBOUNCE, // both RECOVERY and DEBOUNCE elapsed (equal here)
            RECOVERY,
            DEBOUNCE,
        );
        assert_eq!(got, Some(BuildReason::WalletReady));
    }
}
