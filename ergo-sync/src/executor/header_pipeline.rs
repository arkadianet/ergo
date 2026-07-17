//! Header validation pipeline for [`SyncExecutor`].
//!
//! Single-header and batched (rayon Phase 1 + sequential Phase 2)
//! validation paths, the orphan-header buffer (headers whose parent
//! has not arrived yet) with its drain/cap/parent-walk machinery, and
//! the recent-header window maintenance.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use ergo_p2p::peer::{PeerId, Penalty};
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use rayon::prelude::*;
use tracing::{info, warn};

use crate::coordinator::{Action, SyncCoordinator};
use crate::header_proc::{self, HeaderProcessError, ProcessedHeader};

use super::{utxo_header_store_mut, SyncExecutor, LAST_HEADERS_WINDOW};

/// Cap on total buffered orphan headers. Sized for Step D's
/// anchor-spacing scheduler: with `ANCHOR_SPACING = 4_000` and
/// `MAX_ANCHOR_AHEAD = 60_000`, up to ~14 peers can hold
/// concurrent disjoint anchor claims — each shipping a 400-ID
/// response. Actual buffered-header span is bounded by the
/// lookahead window (60_000 headers) so 100_000 leaves
/// comfortable headroom for slow-peer arrivals plus
/// request_orphan_root_parents fetches. Memory: 100_000 ×
/// ~1.5 KB (bytes + cached PreValidated) ≈ 150 MB. Acceptable
/// against the spec §4 "~448 MB total" budget — the orphan
/// buffer is the temporary IBD overflow, not steady-state state.
pub(crate) const ORPHAN_HEADER_LIMIT: usize = 100_000;
/// During IBD, ignore orphan headers too far ahead of `best_header`.
///
/// Bumped from 30_000 → 60_000 with Step D's anchor-spacing
/// scheduler. Spacing concurrent peer assignments by
/// `ANCHOR_SPACING = 4_000` means a 60_000-deep window holds
/// 60_000 / 4_000 = 15 concurrent disjoint slices — the maximum
/// pipeline width before slow-peer responses get dropped. Slow
/// anchored responses (5s+ RTT variance) need this depth so their
/// 400-ID slice still lands inside the buffer even after faster
/// peers have advanced tip several thousand headers. Live-tip
/// far-ahead announces (hundreds of thousands ahead) still drop.
pub(crate) const ORPHAN_HEADER_IBD_LOOKAHEAD: u32 = 60_000;

impl SyncExecutor {
    /// Run the full single-header validation pipeline for an
    /// out-of-band local header (e.g. the §12 `POST /blocks`
    /// sendMinedBlock path) without going through
    /// `Action::ValidateHeader` / `coordinator::on_header_validated`
    /// — those emit per-peer `delivery.request` / `SendToPeer` for
    /// the submitting peer, but a locally-injected header has no peer.
    ///
    /// Equivalent to the success path of `handle_validate_header`:
    /// PoW verify + chain linkage + persist + push into the
    /// recent-header cache + `recently_installed` registration +
    /// orphan-drain pass. The last two matter because orphan headers
    /// previously buffered against this header as parent will only
    /// drain if `recently_installed` knows we just installed it
    /// (`drain_orphans:1589`).
    ///
    /// Returns `(ProcessedHeader, drain_actions)`. The caller MUST
    /// flush `drain_actions` — they are NOT cosmetic; `drain_orphans`
    /// calls `coordinator::on_header_validated` for any orphan that
    /// just unblocked, which registers section downloads
    /// (`delivery.request`) AND emits
    /// `Action::SendToPeer(RequestModifier, …)` for real peers.
    /// Discarding those leaves entries in the delivery tracker for
    /// requests that were never actually sent, leading to false
    /// non-delivery penalties on the affected peers.
    ///
    /// Errors mirror `process_header_cfg` exactly — caller maps to
    /// its own transport-layer error vocabulary.
    pub fn process_local_header(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        header_bytes: &[u8],
        now: Instant,
    ) -> Result<(ProcessedHeader, Vec<Action>), HeaderProcessError> {
        // Header-pipeline telemetry — mirror the single-header path
        // at `handle_validate_header:769-804` so `/metrics`
        // `ergo_node_header_pow_*` / `_headers_total` /
        // `_header_finalize_*` reflect locally-submitted headers too.
        let t_pow = Instant::now();
        let pre_result = header_proc::pre_validate_header(header_bytes);
        let pow_ns = t_pow.elapsed().as_nanos() as u64;
        self.header_perf.add_pow_wall(pow_ns);
        self.header_perf.add_pow_cpu(pow_ns);
        self.header_perf.add_headers(1);
        let pre = pre_result?;

        let t_fin = Instant::now();
        let finalize_result = header_proc::finalize_header(
            utxo_header_store_mut(store),
            pre,
            header_bytes,
            &self.chain_config,
        );
        self.header_perf
            .add_finalize(t_fin.elapsed().as_nanos() as u64);
        let processed = finalize_result?;

        self.push_validated_header(&processed, header_bytes);
        let drain_actions = self.drain_orphans(store, coordinator, now);
        Ok((processed, drain_actions))
    }

    pub(super) fn handle_validate_header(
        &mut self,
        peer: PeerId,
        header_bytes: &[u8],
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        // Single-header path: PoW wall == CPU (one thread). Persist is
        // included in finalize_ns here because store_validated_header
        // happens inside finalize_header on the non-batched path.
        let t_pow = Instant::now();
        let pre = match header_proc::pre_validate_header(header_bytes) {
            Ok(pre) => pre,
            Err(e) => {
                let pow_ns = t_pow.elapsed().as_nanos() as u64;
                self.header_perf.add_pow_wall(pow_ns);
                self.header_perf.add_pow_cpu(pow_ns);
                self.header_perf.add_headers(1);
                warn!(peer = %peer, error = %e, "header validation failed");
                return vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }];
            }
        };
        let pow_ns = t_pow.elapsed().as_nanos() as u64;
        self.header_perf.add_pow_wall(pow_ns);
        self.header_perf.add_pow_cpu(pow_ns);
        self.header_perf.add_headers(1);

        let header_id = *pre.header_id();
        let header_height = pre.height;
        // Clone before finalize consumes pre — if finalize returns
        // ParentNotFound we use the clone to seed the orphan buffer
        // with a cached PoW proof, so retries skip Phase 1 entirely.
        // Cheap clone (PreValidatedHeader is ~hundreds of bytes).
        let pre_for_buffer = pre.clone();

        let t_fin = Instant::now();
        let finalize_result = header_proc::finalize_header(
            utxo_header_store_mut(store),
            pre,
            header_bytes,
            &self.chain_config,
        );
        self.header_perf
            .add_finalize(t_fin.elapsed().as_nanos() as u64);
        match finalize_result {
            Ok(processed) => {
                let expected = ExpectedSections::from_header(
                    &processed.header_id,
                    &processed.transactions_root,
                    &processed.extension_root,
                    &processed.ad_proofs_root,
                );
                let mut followup = coordinator.on_header_validated(
                    peer,
                    processed.header_id,
                    processed.height,
                    processed.header.timestamp,
                    expected,
                    now,
                );
                self.push_validated_header(&processed, header_bytes);

                // Drain orphan buffer — each success may unlock more orphans.
                followup.extend(self.drain_orphans(store, coordinator, now));

                followup
            }
            Err(HeaderProcessError::AlreadyKnown { .. }) => Vec::new(),
            Err(HeaderProcessError::ParentNotFound { .. }) => {
                if !self.buffer_or_defer_orphan_header(
                    peer,
                    pre_for_buffer,
                    header_bytes.to_vec(),
                    header_id,
                    header_height,
                    store,
                    coordinator,
                ) {
                    return Vec::new();
                }
                // Single-header path on ParentNotFound: nothing was
                // installed, so the orphan buffer can't have any new
                // unlocks. Skip the full drain — calling it would
                // re-finalize the entire 50k-cap buffer for nothing
                // (the dominant CPU cost observed at Step C+D
                // fanout — `orphan_n=800k+` per perf-hdr line). Just
                // emit the parent-walk requests so peers ship us
                // the missing parent for the fork-stitch case.
                self.request_orphan_root_parents(store, coordinator, now)
            }
            Err(HeaderProcessError::EpochContextIncomplete { height, .. }) => {
                // Local context gap (older epoch ancestors missing for
                // EIP-37 difficulty recalculation). Not peer
                // misbehavior — buffer + retry once more ancestors
                // arrive. Empirically unreachable on mainnet/testnet
                // preset; matters for custom configs and partial-window
                // recovery.
                warn!(
                    height,
                    peer = %peer,
                    "epoch context incomplete; buffering header for retry (no peer penalty)",
                );
                let _kept = self.buffer_or_defer_orphan_header(
                    peer,
                    pre_for_buffer,
                    header_bytes.to_vec(),
                    header_id,
                    header_height,
                    store,
                    coordinator,
                );
                Vec::new()
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "header validation failed");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        }
    }

    /// Batch-validate a set of headers using two-phase processing:
    /// Phase 1 (rayon parallel): parse + PoW verify
    /// Phase 2 (sequential): chain linkage + atomic persist
    /// Single orphan drain at the end covers all newly stored headers.
    pub(super) fn batch_validate_headers(
        &mut self,
        headers: Vec<(PeerId, Vec<u8>)>,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        // Single header: skip rayon overhead, use direct path
        if headers.len() == 1 {
            let (peer, bytes) = headers.into_iter().next().unwrap();
            return self.handle_validate_header(peer, &bytes, store, coordinator, now);
        }

        // Phase 1: parallel pre-validation (parse + PoW)
        let config = self.chain_config.clone();
        let batch_len = headers.len() as u64;
        // Per-header CPU time accumulator. Captured by reference inside the
        // rayon closure so each worker thread can fetch_add its own work
        // without contending on `self.header_perf` (which would also fail
        // the Send check on `&mut self`).
        let pow_cpu_acc = std::sync::atomic::AtomicU64::new(0);
        let t_pow_wall = Instant::now();
        let mut pre_validated: Vec<_> = headers
            .into_par_iter()
            .map(|(peer, bytes)| {
                let t = Instant::now();
                let result = header_proc::pre_validate_header(&bytes);
                pow_cpu_acc.fetch_add(
                    t.elapsed().as_nanos() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                (peer, bytes, result)
            })
            .collect();
        self.header_perf
            .add_pow_wall(t_pow_wall.elapsed().as_nanos() as u64);
        self.header_perf
            .add_pow_cpu(pow_cpu_acc.load(std::sync::atomic::Ordering::Relaxed));
        self.header_perf.add_headers(batch_len);

        // Topological order: sort by height ascending so parents precede
        // children during sequential finalize. Scala's `continuationIdsV2`
        // is documented as oldest-first, but `sendExtension`'s `groupBy`
        // does not preserve wire order, and we have seen real peers ship
        // Inv batches newest-first. Without this sort, every ParentNotFound
        // ends up in the orphan buffer whose own drain can't resolve
        // self-contained chains — progress stalls hard. Parse/PoW errors
        // bubble to the end (u32::MAX) so they don't contaminate ordering.
        pre_validated.sort_by_key(|(_, _, result)| {
            result
                .as_ref()
                .map(|pre| pre.header().height)
                .unwrap_or(u32::MAX)
        });

        // Phase 2: sequential finalization (chain linkage + deferred persist)
        // Batch mode: store writes go to in-memory buffer, flushed to one
        // redb transaction at the end. Parent lookups hit the buffer first.
        store.begin_header_batch();
        let t_fin = Instant::now();
        let mut actions = Vec::new();
        for (peer, bytes, result) in pre_validated {
            match result {
                Ok(pre) => {
                    let header_id = *pre.header_id();
                    let header_height = pre.height;
                    let pre_for_buffer = pre.clone();
                    match header_proc::finalize_header(
                        utxo_header_store_mut(store),
                        pre,
                        &bytes,
                        &config,
                    ) {
                        Ok(processed) => {
                            let expected = ExpectedSections::from_header(
                                &processed.header_id,
                                &processed.transactions_root,
                                &processed.extension_root,
                                &processed.ad_proofs_root,
                            );
                            let followup = coordinator.on_header_validated(
                                peer,
                                processed.header_id,
                                processed.height,
                                processed.header.timestamp,
                                expected,
                                now,
                            );
                            actions.extend(followup);
                            self.push_validated_header(&processed, &bytes);
                        }
                        Err(HeaderProcessError::AlreadyKnown { .. }) => {}
                        Err(HeaderProcessError::ParentNotFound { .. }) => {
                            self.buffer_or_defer_orphan_header(
                                peer,
                                pre_for_buffer,
                                bytes,
                                header_id,
                                header_height,
                                store,
                                coordinator,
                            );
                        }
                        Err(HeaderProcessError::EpochContextIncomplete { height, .. }) => {
                            // Local context gap, not peer misbehavior —
                            // see single-header path for rationale.
                            warn!(
                                height,
                                peer = %peer,
                                "epoch context incomplete; buffering header for retry (no peer penalty)",
                            );
                            self.buffer_or_defer_orphan_header(
                                peer,
                                pre_for_buffer,
                                bytes,
                                header_id,
                                header_height,
                                store,
                                coordinator,
                            );
                        }
                        Err(e) => {
                            warn!(peer = %peer, error = %e, "header validation failed");
                            actions.push(Action::Penalize {
                                peer,
                                penalty: Penalty::Misbehavior,
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "header pre-validation failed");
                    actions.push(Action::Penalize {
                        peer,
                        penalty: Penalty::Misbehavior,
                    });
                }
            }
        }
        self.header_perf
            .add_finalize(t_fin.elapsed().as_nanos() as u64);
        // Flush all validated headers to redb in one transaction.
        // Panic on failure: chain_state was already updated in-memory during
        // the batch. Continuing with a desynced in-memory/DB state is worse
        // than crashing. On restart, redb is consistent and we re-sync.
        let t_flush = Instant::now();
        store
            .flush_header_batch()
            .expect("header batch flush failed — redb write error is fatal");
        self.header_perf
            .add_flush(t_flush.elapsed().as_nanos() as u64);

        // Single orphan drain covers all newly stored headers
        actions.extend(self.drain_orphans(store, coordinator, now));
        actions
    }

    /// Try to process buffered orphan headers — single pass, no PoW.
    ///
    /// PoW is paid once at insertion (the cached `PreValidatedHeader`
    /// rides along in the buffer), so this drain only does the
    /// height-sorted finalize: try `finalize_header` for each in
    /// order, re-buffer the still-orphaned ones with their cached
    /// `PreValidatedHeader` intact. Cascade ("installing parent X
    /// unlocks child Y") happens naturally inside the loop because
    /// `finalize_header` consults the live `store`.
    ///
    /// Cost: `O(N × finalize_cost)`, no PoW. Re-PoW'ing the residual
    /// buffer (10k entries × 1k+ flushes/min) would dominate CPU and
    /// starve mainline throughput.
    fn drain_orphans(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        let mut all_actions = Vec::new();

        // Take headers installed since last drain — these are the
        // ONLY parents that could unblock orphans. Skipping the
        // orphan if parent_id ∉ this set is correct because orphans
        // entered the buffer with a missing parent; if it was in
        // store BEFORE last drain it would already be installable;
        // if it was installed SINCE it's in this set. Cleared on take.
        let newly_installed = std::mem::take(&mut self.recently_installed);

        if self.orphan_headers.is_empty() {
            self.cap_orphan_buffer();
            all_actions.extend(self.request_orphan_root_parents(store, coordinator, now));
            return all_actions;
        }

        // Pull only the orphans whose parent is in the just-installed
        // set. The buffer is keyed by parent_id, so this is O(|newly_installed|)
        // hashmap lookups instead of O(|buffer|) scans. Cascade
        // within the drain extends `newly_installed` so children
        // become eligible as their parents land.
        let mut work_queue: Vec<(PeerId, header_proc::PreValidatedHeader, Vec<u8>)> = Vec::new();
        for parent_id in &newly_installed {
            if let Some(children) = self.orphan_headers.remove(parent_id) {
                self.orphan_headers_len = self.orphan_headers_len.saturating_sub(children.len());
                work_queue.extend(children);
            }
        }
        if work_queue.is_empty() {
            self.cap_orphan_buffer();
            all_actions.extend(self.request_orphan_root_parents(store, coordinator, now));
            return all_actions;
        }

        // Topological order by height inside the work queue — same
        // reasoning as batch_validate_headers.
        work_queue.sort_by_key(|(_, pre, _)| pre.height);

        let orphan_count = work_queue.len() as u64;
        self.header_perf.add_orphan_headers(orphan_count);

        // Cascade: as we install, more children may become eligible
        // (their parent is in the new install set). Process via a
        // worklist that grows during the loop.
        //
        // Per spec §4 (Crash Safety) and §3 (Concurrency Model
        // "fixed-point drain"): the cascade is logically one chain
        // segment and MUST commit atomically. Wrap the loop in
        // `begin_header_batch()` / `flush_header_batch()` so all
        // cascaded `finalize_header` calls write to the in-memory
        // overlay, then flush as a single redb transaction at the
        // end. Without this, every cascaded header was its own redb
        // commit (~400μs each) — at 24k cascade length that's ~10s
        // of write churn blocking the action loop.
        store.begin_header_batch();
        let mut newly_installed_local = newly_installed;
        let config = self.chain_config.clone();
        let t_fin = Instant::now();
        while let Some((peer, pre, bytes)) = work_queue.pop() {
            let header_id = *pre.header_id();
            let header_height = pre.height;
            let pre_for_buffer = pre.clone();
            match header_proc::finalize_header(utxo_header_store_mut(store), pre, &bytes, &config) {
                Ok(processed) => {
                    // Children waiting on THIS header are now eligible
                    // — pull them out of the buffer and onto the queue.
                    newly_installed_local.insert(processed.header_id);
                    if let Some(children) = self.orphan_headers.remove(&processed.header_id) {
                        self.orphan_headers_len =
                            self.orphan_headers_len.saturating_sub(children.len());
                        work_queue.extend(children);
                        // Re-sort: pop() is LIFO, so later additions
                        // shouldn't reorder mid-stream — but the
                        // height-sort invariant is cheap to maintain.
                        work_queue.sort_by_key(|(_, pre, _)| pre.height);
                    }
                    let expected = ExpectedSections::from_header(
                        &processed.header_id,
                        &processed.transactions_root,
                        &processed.extension_root,
                        &processed.ad_proofs_root,
                    );
                    let followup = coordinator.on_header_validated(
                        peer,
                        processed.header_id,
                        processed.height,
                        processed.header.timestamp,
                        expected,
                        now,
                    );
                    all_actions.extend(followup);
                    self.push_validated_header(&processed, &bytes);
                }
                Err(HeaderProcessError::ParentNotFound { .. }) => {
                    // Defensive — the pre-filter said parent was
                    // installed, but finalize disagreed (e.g. a
                    // fork-choice race). Re-buffer with cached pre.
                    self.buffer_or_defer_orphan_header(
                        peer,
                        pre_for_buffer,
                        bytes,
                        header_id,
                        header_height,
                        store,
                        coordinator,
                    );
                }
                Err(HeaderProcessError::EpochContextIncomplete { .. }) => {
                    // Drain-path equivalent of the single-header /
                    // batch handlers: epoch context still missing on
                    // retry, re-buffer rather than silently drop. Must
                    // come BEFORE the `Err(_) => drop invalid` arm
                    // below — without this match, an EIP-37 boundary
                    // header that re-fails on drain would be
                    // permanently lost. Empirically unreachable on
                    // mainnet/testnet preset; matters for custom
                    // configs and partial-window recovery.
                    self.buffer_or_defer_orphan_header(
                        peer,
                        pre_for_buffer,
                        bytes,
                        header_id,
                        header_height,
                        store,
                        coordinator,
                    );
                }
                Err(HeaderProcessError::AlreadyKnown { .. }) => {}
                Err(_) => {} // drop invalid
            }
        }
        self.header_perf
            .add_orphan_finalize(t_fin.elapsed().as_nanos() as u64);
        // Flush the cascade as a single redb transaction. Per spec
        // §4, a flush failure here means the in-memory state is
        // ahead of disk — same fatal class as the batch path's
        // flush at line ~1247. Match that behaviour: panic so a
        // fresh restart re-syncs from a consistent on-disk state.
        store
            .flush_header_batch()
            .expect("orphan drain flush_header_batch failed — redb write error is fatal");
        // Suppress dead_code: keep the local set live until end of
        // function so cascade tracking is observable in trace.
        let _ = newly_installed_local;

        self.cap_orphan_buffer();

        // Parent-walk: if the buffer is still non-empty after drain, the
        // chain bottoms out at a header we don't have yet. Ask peers for
        // those missing parents so the chain can stitch backward until it
        // meets our store. Once the common ancestor is reached, cumulative-
        // score fork-choice in `finalize_header` + `store.store_validated_header`
        // handles the reorg atomically (best_header_id switch + HEADER_CHAIN_INDEX
        // rewrite). No manual rollback needed because best_full_block_height
        // is gated separately from best_header_height.
        all_actions.extend(self.request_orphan_root_parents(store, coordinator, now));
        all_actions
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn buffer_or_defer_orphan_header(
        &mut self,
        peer: PeerId,
        pre: header_proc::PreValidatedHeader,
        bytes: Vec<u8>,
        header_id: [u8; 32],
        height: u32,
        store: &ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
    ) -> bool {
        if self.should_buffer_orphan_header(height, store, coordinator) {
            let parent_id = pre.parent_id;
            self.orphan_headers
                .entry(parent_id)
                .or_default()
                .push((peer, pre, bytes));
            self.orphan_headers_len = self.orphan_headers_len.saturating_add(1);
            return true;
        }

        coordinator.forget_received_modifier(&header_id);
        let best = store.chain_state_meta().best_header_height;
        warn!(
            height,
            best_header_height = best,
            peer = %peer,
            "deferring far-ahead orphan header; not parent-walking during IBD",
        );
        false
    }

    fn should_buffer_orphan_header(
        &self,
        height: u32,
        store: &ergo_state::StateBackendKind,
        coordinator: &SyncCoordinator,
    ) -> bool {
        if coordinator.sync_state().headers_chain_synced() {
            return true;
        }
        let best = store.chain_state_meta().best_header_height;
        height <= best.saturating_add(ORPHAN_HEADER_IBD_LOOKAHEAD)
    }

    pub(super) fn cap_orphan_buffer(&mut self) {
        if self.orphan_headers_len <= ORPHAN_HEADER_LIMIT {
            return;
        }
        // Buffer is HashMap<parent_id, Vec<orphan>>. Cap by dropping
        // the highest-height ENTRIES — keep the root side of orphan
        // chains so once their parents reconnect, higher tips can
        // be re-fetched through normal SyncInfo/Inv flow.
        //
        // Collect all (height, parent_id, orphan_index) tuples, sort
        // descending by height, drop until under cap. O(N log N) on
        // overflow; only fires when buffer overflows.
        let overflow = self.orphan_headers_len - ORPHAN_HEADER_LIMIT;
        let mut by_height: Vec<(u32, [u8; 32], usize)> =
            Vec::with_capacity(self.orphan_headers_len);
        for (parent_id, children) in &self.orphan_headers {
            for (idx, (_, pre, _)) in children.iter().enumerate() {
                by_height.push((pre.height, *parent_id, idx));
            }
        }
        // Highest first.
        by_height.sort_by_key(|(h, _, _)| std::cmp::Reverse(*h));
        // Drop indices in REVERSE order per parent_id so swap_remove
        // doesn't shift earlier indices.
        let to_drop: Vec<([u8; 32], usize)> = by_height
            .into_iter()
            .take(overflow)
            .map(|(_, p, i)| (p, i))
            .collect();
        // Group by parent_id, sort indices desc per group, swap_remove.
        let mut by_parent: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        for (p, i) in to_drop {
            by_parent.entry(p).or_default().push(i);
        }
        for (parent_id, mut indices) in by_parent {
            indices.sort_unstable_by(|a, b| b.cmp(a));
            if let Some(children) = self.orphan_headers.get_mut(&parent_id) {
                for i in indices {
                    if i < children.len() {
                        children.swap_remove(i);
                        self.orphan_headers_len = self.orphan_headers_len.saturating_sub(1);
                    }
                }
                if children.is_empty() {
                    self.orphan_headers.remove(&parent_id);
                }
            }
        }
    }

    /// Emit `RequestModifier(Header, [parent_id])` per peer for orphan-buffer
    /// headers whose parent is neither in our store nor the id of another
    /// buffered orphan. "Root" parents — the points where the orphan chain
    /// dangles into nothing. Groups by the peer that originally delivered
    /// each orphan so we ask the peer that has the chain; deduplicates
    /// per-peer parent sets.
    fn request_orphan_root_parents(
        &self,
        store: &ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        if self.orphan_headers.is_empty() {
            return Vec::new();
        }

        // Build set of header IDs of every orphan we hold — so we
        // can identify which `parent_id`s are "internal" (parent is
        // another orphan we're already holding) vs "root" (parent
        // is genuinely missing from our world).
        let mut orphan_ids: HashSet<[u8; 32]> = HashSet::with_capacity(self.orphan_headers_len);
        for children in self.orphan_headers.values() {
            for (_, pre, _) in children {
                orphan_ids.insert(*pre.header_id());
            }
        }

        let mut needed_per_peer: HashMap<PeerId, HashSet<[u8; 32]>> = HashMap::new();
        for (parent_id_key, children) in &self.orphan_headers {
            let parent_id = *parent_id_key;
            if orphan_ids.contains(&parent_id) {
                continue; // parent is another orphan we already have buffered
            }
            match store.get_header(&parent_id) {
                Ok(Some(_)) => continue, // parent already in store; drain will retry
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        parent_id = %hex::encode(parent_id),
                        error = %e,
                        "get_header failed during parent-walk",
                    );
                    continue;
                }
            }
            // Ask the FIRST peer that delivered an orphan for this
            // parent — they had the chain when they shipped the
            // child, so they likely have the parent too. Other peers
            // for the same parent_id needn't be re-asked: per-peer
            // sets dedupe and one parent fetch is enough.
            if let Some((peer, _, _)) = children.first() {
                needed_per_peer.entry(*peer).or_default().insert(parent_id);
            }
        }

        if needed_per_peer.is_empty() {
            return Vec::new();
        }

        let mut actions = Vec::new();
        let mut total_req = 0usize;
        for (peer, parents) in needed_per_peer {
            let parent_vec: Vec<[u8; 32]> = parents.into_iter().collect();
            total_req += parent_vec.len();
            actions.extend(coordinator.request_missing_header_parents(peer, &parent_vec, now));
        }
        if total_req > 0 {
            // A reorg signal: logging once per parent-walk request helps
            // operators see when the node traverses a fork boundary.
            info!(
                missing_parents = total_req,
                orphan_buffer = self.orphan_headers_len,
                "parent-walk: requesting missing parents",
            );
        }
        actions
    }

    /// Add a newly validated header + raw bytes to the recent-header window.
    fn push_validated_header(&mut self, processed: &ProcessedHeader, header_bytes: &[u8]) {
        self.last_headers
            .push_front((processed.checked.clone(), header_bytes.to_vec()));
        if self.last_headers.len() > LAST_HEADERS_WINDOW {
            self.last_headers.pop_back();
        }
        if processed.is_new_best {
            self.header_index
                .insert(processed.height, processed.header_id);
        }
        // Track for the orphan drain's parent-existence pre-filter.
        // Cleared at the start of each drain — this set means
        // "headers added since the last drain ran", i.e. potential
        // newly-unlocked parents.
        self.recently_installed.insert(processed.header_id);
    }
}
