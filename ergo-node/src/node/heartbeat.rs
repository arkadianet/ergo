//! Per-tick operator heartbeat for the action loop.
//!
//! Pure diagnostics: read sync / mempool / network / anchor / perf
//! counters out of `NodeState`, format them onto stderr, and advance
//! `last_beat_*` so the next tick reports a fresh delta.

use ergo_p2p::handshake::PeerFeature;
use ergo_p2p::peer::PeerId;
use ergo_state::ChainStateRead;
use std::time::{Duration, Instant};
use tracing::{debug, info};

use super::NodeState;

/// Idle cadence for the operator `heartbeat tick` line. With no header
/// or block progress the line emits at most once per this interval —
/// enough to confirm liveness and surface a stall, without the
/// per-second flood that drowned the signal on a synced node. `boot`
/// seeds `last_beat_emit` one interval in the past so a node that boots
/// already stalled still emits on its first tick.
pub(super) const HEARTBEAT_IDLE_INTERVAL: Duration = Duration::from_secs(60);

/// Whether the operator `heartbeat tick` line should emit this tick:
/// on any sync progress, or once `HEARTBEAT_IDLE_INTERVAL` has elapsed
/// since the last emission. Progress always wins, so active sync keeps
/// its per-tick progress lines; idle/stalled state pulses once per
/// interval. Pure so the cadence is unit-testable without a NodeState.
fn should_emit_beat(progressed: bool, since_last_emit: Duration) -> bool {
    progressed || since_last_emit >= HEARTBEAT_IDLE_INTERVAL
}

pub(super) fn emit_heartbeat(state: &mut NodeState, now: Instant) {
    let elapsed = now.duration_since(state.last_beat);
    let secs = elapsed.as_secs_f64().max(0.001);
    let cs = state.store.chain_state_meta();
    let h = cs.best_full_block_height;
    let bh = cs.best_header_height;
    // Hand the current best_header_height to the anchor builder so
    // its next pass scans frontier-first (anchors above tip, useful
    // to the scheduler) instead of lowest-first (anchors below
    // tip, useless). Every tick — independent of whether the operator
    // line below emits this tick.
    state
        .anchor_tip_cursor
        .store(bh, std::sync::atomic::Ordering::Relaxed);
    let dh = h.saturating_sub(state.last_beat_height);
    let dbh = bh.saturating_sub(state.last_beat_headers);

    // Operator `heartbeat tick` line. Emit on sync progress; otherwise
    // fall back to one line per HEARTBEAT_IDLE_INTERVAL so a synced node
    // is a once-a-minute liveness pulse, not a per-second flood — while a
    // stall (gap > 0 with no progress) still surfaces on the idle cadence.
    // Per-tick deltas stay exact on every emitted line: a progress tick
    // always emits, and idle ticks carry dh = dbh = 0. The AVL root_digest
    // (tip_state) and the connected-peer scans run only when we emit, not
    // every tick.
    let progressed = dh > 0 || dbh > 0;
    if should_emit_beat(progressed, now.duration_since(state.last_beat_emit)) {
        let d_req_msgs = state
            .req_messages_total
            .saturating_sub(state.last_beat_req_messages);
        let d_req_ids = state.req_ids_total.saturating_sub(state.last_beat_req_ids);
        let drecv = state
            .sections_received_total
            .saturating_sub(state.last_beat_sections_received);
        // Tip state-root digest at the current best_full_block. Backend-
        // agnostic: the UTXO arena root or the digest verifier's ADProof-
        // derived root — both equal the tip header's `state_root`, so a
        // digest-backend (Mode 5) node reports a real value here instead of
        // panicking. Prefixed with `tip_state=` so a fresh-sync run can grep
        // this against the Scala node's `/info` stateRoot for parity.
        let tip_state = hex::encode(state.store.state_root_digest());
        let peer_count = state.peer_manager.connected_peers().count();
        let reg_count = state.registry.peers.len();
        let mgr_count = state.peer_manager.peer_count();
        // rest_peers: connected peers whose handshake advertised a
        // RestApiUrl feature. The header-anchor-map bootstrap needs to know
        // how many peers in the swarm we could query for `/blocks/at/{h}`
        // to build the anchor map. Pure observation.
        let rest_peers = state
            .peer_manager
            .connected_peers()
            .filter(|p| {
                p.peer_spec
                    .as_ref()
                    .map(|s| {
                        s.features
                            .iter()
                            .any(|f| matches!(f, PeerFeature::RestApiUrl { .. }))
                    })
                    .unwrap_or(false)
            })
            .count();
        info!(
            best_full_block_height = h,
            full_block_delta = dh,
            best_header_height = bh,
            header_delta = dbh,
            peers = peer_count,
            peer_manager_count = mgr_count,
            registry_count = reg_count,
            rest_peers,
            rate_blocks_per_sec = format!("{:.1}", dh as f64 / secs),
            gap = bh.saturating_sub(h),
            req_msgs = d_req_msgs,
            req_ids = d_req_ids,
            recv = drecv,
            tip_state = %tip_state,
            "heartbeat tick",
        );
        state.last_beat_emit = now;
    }

    // [net] Pipeline-shape diagnostics (instrumented 2026-05-05) —
    // breaks Inv → RequestModifier filtering down by rejection cause
    // so we can distinguish "peers shipping few IDs" from "peers
    // shipping lots but most get dedup'd". Drained per heartbeat.
    let mut net = state.coordinator.take_net_stats();
    if net.is_active() {
        debug!(
            inv_msgs = net.inv_msgs_received,
            inv_ids = net.inv_ids_total,
            admitted = net.inv_ids_admitted,
            have = net.inv_ids_already_have,
            inflight = net.inv_ids_already_inflight,
            received = net.inv_ids_already_received,
            capped = net.inv_ids_capped_per_peer,
            peers_responded = net.peers_with_response.len(),
            peers_dispatched = net.peers_dispatched_to.len(),
            "net pipeline shape",
        );

        // Per-peer Inv breakdown — only print when there's
        // measurable disparity (some peers high admit %, others
        // low) so steady-state ticks don't flood the log. Sample
        // every 10 ticks so we get a periodic snapshot regardless.
        if net.per_peer_inv.len() >= 5 {
            let mut peer_ratios: Vec<(PeerId, u64, u64, f64)> = net
                .per_peer_inv
                .iter()
                .map(|(p, (total, admitted))| {
                    let ratio = if *total > 0 {
                        100.0 * (*admitted as f64) / (*total as f64)
                    } else {
                        0.0
                    };
                    (*p, *total, *admitted, ratio)
                })
                .collect();
            peer_ratios.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));
            // Show peer-Inv ratio distribution: lowest 3, highest 3,
            // count of peers with admit ratio < 10% vs >= 50%.
            let low_count = peer_ratios.iter().filter(|t| t.3 < 10.0).count();
            let high_count = peer_ratios.iter().filter(|t| t.3 >= 50.0).count();
            let lo: Vec<String> = peer_ratios
                .iter()
                .take(3)
                .map(|(p, t, a, r)| format!("{p}:{a}/{t}({r:.0}%)"))
                .collect();
            let hi: Vec<String> = peer_ratios
                .iter()
                .rev()
                .take(3)
                .map(|(p, t, a, r)| format!("{p}:{a}/{t}({r:.0}%)"))
                .collect();
            debug!(
                n = peer_ratios.len(),
                low_admit_pct = low_count,
                high_admit_pct = high_count,
                worst = %lo.join(","),
                best = %hi.join(","),
                "net per-peer Inv ratio distribution",
            );
        }
    }

    // [peer-mod] unconditional block-sync peer-distribution diagnostic.
    // Separate from [net] (which gates on inv_msgs/inv_ids — both ~0
    // at tip), so block-section ship-out skew stays visible at tip
    // when [net] is silent. `top` is sorted by modifier count desc;
    // `p80` is the smallest peer set covering 80% of modifiers — high
    // concentration (small p80 vs large active count) means a few peers
    // are dominating delivery and dispatch policy may be inefficient.
    if !net.per_peer_modifier.is_empty() {
        let total_mods: u64 = net.per_peer_modifier.values().sum();
        let n_peers = net.per_peer_modifier.len();
        let mut top: Vec<(PeerId, u64)> = net.per_peer_modifier.drain().collect();
        top.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        let connected = state.peer_manager.peer_count();
        let silent = connected.saturating_sub(n_peers);
        let top5: Vec<String> = top
            .iter()
            .take(5)
            .map(|(p, c)| {
                let pct = 100.0 * (*c as f64) / (total_mods.max(1) as f64);
                format!("{p}:{c}({pct:.0}%)")
            })
            .collect();
        let mut acc: u64 = 0;
        let target = (total_mods * 80) / 100;
        let mut p80 = 0;
        for (_, c) in &top {
            acc += c;
            p80 += 1;
            if acc >= target {
                break;
            }
        }
        debug!(
            mods = total_mods,
            active = n_peers,
            connected,
            silent,
            p80,
            top = %top5.join(","),
            "block-sync peer modifier distribution",
        );
    }

    // Step B anchor-map heartbeat. Read counters non-blockingly via
    // `try_*` to avoid stalling the action loop if the background
    // builder is mid-write. We accept stale numbers — they catch up
    // on the next tick. Emission gated on `is_active()` so a quiet
    // tick (no new queries / admissions / disagreements since last
    // read) produces no output, even after the verified set has
    // grown. The verified_total field in the line is for context
    // when something IS happening.
    if let (Some(verified), Some(pending), Some(counters)) = (
        state.anchor_map.try_verified_count(),
        state.anchor_map.try_pending_count(),
        state.anchor_map.try_take_counters(),
    ) {
        // Step C scheduler counters folded into the same line — drained
        // unconditionally so they don't accumulate between active ticks
        // (the heartbeat is the only consumer). `assigned_count` is a
        // gauge (cheap, doesn't need draining).
        let sched_counters = state.anchor_scheduler.take_counters();
        let assigned_now = state.anchor_scheduler.assigned_count();
        if counters.is_active() || sched_counters.is_active() {
            debug!(
                verified_total = verified,
                pending_total = pending,
                queries_attempted = counters.queries_attempted,
                queries_succeeded = counters.queries_succeeded,
                queries_errored = counters.queries_errored,
                anchors_admitted = counters.anchors_admitted,
                anchor_disagreements = counters.anchor_disagreements,
                anchor_assignments = sched_counters.anchor_assignments,
                anchor_reassignments = sched_counters.anchor_reassignments,
                anchors_assigned_now = assigned_now,
                "anchor map heartbeat",
            );
        }
    }

    // Header-pipeline phase timings since last heartbeat. Logged only
    // when there's been work (otherwise the line is noise during a
    // fully-synced steady state). All times in ms; *_wall is the
    // observed wall-clock the action loop spent in that phase, *_cpu
    // is the summed per-header CPU so we can compute parallel speedup.
    let perf = state.executor.header_perf.take();
    if perf.is_active() {
        let ns_to_ms = |ns: u64| ns as f64 / 1_000_000.0;
        let hps = perf.headers as f64 / secs;
        debug!(
            n = perf.headers,
            hps = format!("{hps:.0}"),
            pow_wall_ms = format!("{:.1}", ns_to_ms(perf.pow_wall_ns)),
            pow_cpu_ms = format!("{:.1}", ns_to_ms(perf.pow_cpu_ns)),
            finalize_ms = format!("{:.1}", ns_to_ms(perf.finalize_ns)),
            flush_ms = format!("{:.1}", ns_to_ms(perf.flush_ns)),
            orphan_n = perf.orphan_headers,
            orphan_pow_wall_ms = format!("{:.1}", ns_to_ms(perf.orphan_pow_wall_ns)),
            orphan_pow_cpu_ms = format!("{:.1}", ns_to_ms(perf.orphan_pow_cpu_ns)),
            orphan_finalize_ms = format!("{:.1}", ns_to_ms(perf.orphan_finalize_ns)),
            "header pipeline timings",
        );
    }

    // Block-pipeline phase timings since last heartbeat. `bps` is the
    // observed throughput (blocks/sec). The phase sums (hdr/sec/pctx/
    // validate/apply) tell us where CPU+IO time goes inside
    // process_block. The drain stats tell us about the scheduler:
    // - `drain_calls` = how many times we tried to apply sequential
    //   blocks this window
    // - `drain_wall` = total wall in those drains (bps_drain = blocks
    //   applied / drain_wall — pure validation throughput)
    // - `wait` = drains that stalled on SectionNotFound (the next
    //   block's transactions/extension hadn't arrived yet — upstream
    //   network bottleneck signal)
    // If `total_ns` (sum of per-block phases) is much less than the
    // heartbeat window, the bottleneck is scheduling/section-arrival,
    // not CPU.
    let bperf = state.executor.block_perf.take();
    if bperf.is_active() {
        let ns_to_ms = |ns: u64| ns as f64 / 1_000_000.0;
        let bps = bperf.blocks as f64 / secs;
        let txps = bperf.txs as f64 / secs;
        let avg = if bperf.blocks > 0 {
            ns_to_ms(bperf.total_ns) / bperf.blocks as f64
        } else {
            0.0
        };
        debug!(
            n = bperf.blocks,
            bps = format!("{bps:.1}"),
            txps = format!("{txps:.0}"),
            avg_ms = format!("{avg:.2}"),
            header_load_ms = format!("{:.1}", ns_to_ms(bperf.header_load_ns)),
            sections_load_ms = format!("{:.1}", ns_to_ms(bperf.sections_load_ns)),
            parent_ctx_ms = format!("{:.1}", ns_to_ms(bperf.parent_ctx_ns)),
            validate_ms = format!("{:.1}", ns_to_ms(bperf.validate_ns)),
            apply_ms = format!("{:.1}", ns_to_ms(bperf.apply_ns)),
            total_ms = format!("{:.1}", ns_to_ms(bperf.total_ns)),
            drain_calls = bperf.drain_calls,
            drain_wall_ms = format!("{:.1}", ns_to_ms(bperf.drain_wall_ns)),
            drain_blocks = bperf.drain_blocks,
            section_wait_calls = bperf.section_wait_calls,
            "block pipeline timings",
        );
    }

    state.last_beat = now;
    state.last_beat_height = h;
    state.last_beat_headers = bh;
    state.last_beat_req_messages = state.req_messages_total;
    state.last_beat_req_ids = state.req_ids_total;
    state.last_beat_sections_received = state.sections_received_total;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn should_emit_beat_on_progress_ignores_cadence() {
        // Sync progress always emits, even a moment after the last line —
        // active sync keeps its per-tick progress visibility.
        assert!(should_emit_beat(true, Duration::ZERO));
        assert!(should_emit_beat(true, HEARTBEAT_IDLE_INTERVAL / 2));
    }

    #[test]
    fn should_emit_beat_idle_below_interval_suppresses() {
        assert!(!should_emit_beat(false, Duration::ZERO));
        assert!(!should_emit_beat(
            false,
            HEARTBEAT_IDLE_INTERVAL - Duration::from_millis(1)
        ));
    }

    #[test]
    fn should_emit_beat_idle_at_or_past_interval_emits() {
        // At the boundary and beyond, a synced/stalled node pulses. This
        // is also the freshly-booted-stalled case: `boot` seeds
        // `last_beat_emit` one interval in the past, so the first idle
        // tick lands here and the stall stays visible from tick one.
        assert!(should_emit_beat(false, HEARTBEAT_IDLE_INTERVAL));
        assert!(should_emit_beat(
            false,
            HEARTBEAT_IDLE_INTERVAL + Duration::from_secs(1)
        ));
    }
}
