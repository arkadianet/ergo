//! Coalesced follower status refreshes after applied chain progress.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ergo_p2p::{
    message,
    peer::{PeerId, SyncVersion},
};
use ergo_state::ChainStateRead;
use ergo_sync::coordinator::ChainView;

use super::{send_to_peer, NodeState};

const REFRESH_SPACING: Duration = Duration::from_millis(250);
const MESH_REFRESH_DELAY: Duration = Duration::from_secs(1);

pub(super) struct SyncRefresh {
    pending: HashMap<PeerId, (Instant, u64)>,
    generation: u64,
    tips: HashMap<PeerId, [u8; 32]>,
    score: Vec<u8>,
}

impl SyncRefresh {
    pub(super) fn new(score: Vec<u8>) -> Self {
        Self {
            pending: HashMap::new(),
            generation: 0,
            tips: HashMap::new(),
            score,
        }
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.pending.values().map(|(at, _)| *at).min()
    }

    pub(super) fn forget(&mut self, peer: &PeerId) {
        self.pending.remove(peer);
        self.tips.remove(peer);
    }

    fn advance(&mut self, score: Vec<u8>) -> bool {
        let value = |bytes: &[u8]| bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let old = &self.score[value(&self.score)..];
        let new = &score[value(&score)..];
        if (new.len(), new) <= (old.len(), old) {
            return false;
        }
        self.score = score;
        true
    }
}

fn eligible(state: &NodeState, peer: PeerId) -> bool {
    state
        .registry
        .peers
        .get(&peer)
        .is_some_and(|rt| rt.sync_version == SyncVersion::V2)
}

fn remaining_spacing(state: &NodeState, peer: PeerId, now: Instant) -> Duration {
    state
        .coordinator
        .sync_state()
        .last_sync_sent(peer)
        .map(|last| REFRESH_SPACING.saturating_sub(now.saturating_duration_since(last)))
        .unwrap_or_default()
}

pub(super) fn schedule(state: &mut NodeState, peer: PeerId, extra: Duration, now: Instant) {
    if !eligible(state, peer) || state.sync_refresh.pending.contains_key(&peer) {
        return;
    }
    let delay = remaining_spacing(state, peer, now).max(extra);
    state.sync_refresh.generation += 1;
    state
        .sync_refresh
        .pending
        .insert(peer, (now + delay, state.sync_refresh.generation));
}

pub(super) fn collect_progress(state: &mut NodeState, now: Instant) {
    for (peer, id, synced) in state.coordinator.take_applied_headers() {
        if let Some(score) = state.store.header_score_for(&id) {
            // The watermark advances during IBD as well as steady-state operation.
            if state.sync_refresh.advance(score) && synced {
                schedule(state, peer, Duration::ZERO, now);
            }
        }
    }
    // Locally installed headers and bootstrap checkpoints also advance the watermark.
    state
        .sync_refresh
        .advance(state.store.chain_state_meta().best_header_score);
    if state.executor.take_full_block_applied() {
        for peer in super::input_blocks::effects::relay_peers(state) {
            schedule(state, peer, MESH_REFRESH_DELAY, now);
        }
    }
}

pub(super) fn fire_due(state: &mut NodeState, now: Instant) {
    let due: Vec<_> = state
        .sync_refresh
        .pending
        .iter()
        .filter(|(_, (at, _))| *at <= now)
        .map(|(peer, (_, generation))| (*peer, *generation))
        .collect();
    for (peer, generation) in due {
        fire(state, peer, generation, now);
    }
}

pub(super) fn fire(state: &mut NodeState, peer: PeerId, generation: u64, now: Instant) {
    if state
        .sync_refresh
        .pending
        .get(&peer)
        .is_none_or(|(_, g)| *g != generation)
    {
        return;
    }
    state.sync_refresh.pending.remove(&peer);
    if !eligible(state, peer) {
        return;
    }
    if !remaining_spacing(state, peer, now).is_zero() {
        schedule(state, peer, Duration::ZERO, now);
        return;
    }
    let tip = state.store.chain_state_meta().best_header_id;
    if state.sync_refresh.tips.get(&peer) == Some(&tip) {
        return;
    }
    let headers = state.store.recent_header_bytes(50);
    if headers.is_empty() {
        return;
    }
    match message::serialize_sync_info(&message::SyncInfo::V2 { headers }) {
        Ok(payload) => {
            if send_to_peer(state, &peer, message::CODE_SYNC_INFO, payload) {
                state.coordinator.sync_state_mut().mark_sync_sent(peer, now);
                state.sync_refresh.tips.insert(peer, tip);
            }
        }
        Err(error) => tracing::warn!(%peer, %error, "failed to serialize SyncInfo refresh"),
    }
}
