//! Header-first block inventory, restricted to sections we can serve now.

use super::{
    peer_actions::flush_actions,
    section_serving::{servable_section, serving_sentinel},
    NodeState,
};
use ergo_p2p::{
    message,
    types::{InvData, ModifierTypeId},
};
use ergo_primitives::reader::VlqReader;
use ergo_ser::{header::read_header, modifier_id::ExpectedSections};
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const RECENT_BLOCK_MS: u64 = 2 * 60 * 60 * 1000;
const RELAY_TIP_WINDOW: u32 = 16;

#[derive(Clone, Copy)]
pub(super) enum Announcement {
    Mined,
    Remote {
        now_ms: u64,
        best_header_height: u32,
    },
}

/// Consume each successful application once, even with no peers or a bad clock.
pub(super) fn applied_block_announcements(
    state: &mut NodeState,
    locally_mined: Option<[u8; 32]>,
) -> Vec<Action> {
    applied_block_announcements_at(state, locally_mined, SystemTime::now())
}

pub(super) fn applied_block_announcements_at(
    state: &mut NodeState,
    locally_mined: Option<[u8; 32]>,
    wall_time: SystemTime,
) -> Vec<Action> {
    let ids = state.executor.take_applied_blocks();
    if state.registry.peers.is_empty() {
        return Vec::new();
    }
    let now_ms = match wall_time.duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_millis() as u64,
        Err(error) => {
            warn!(%error, "cannot determine applied block freshness");
            return Vec::new();
        }
    };
    remote_announcements(
        state,
        ids.into_iter().filter(|id| Some(*id) != locally_mined),
        now_ms,
    )
}

pub(super) fn remote_announcements(
    state: &NodeState,
    ids: impl IntoIterator<Item = [u8; 32]>,
    now_ms: u64,
) -> Vec<Action> {
    let best_header_height = state.store.chain_state_meta().best_header_height;
    ids.into_iter()
        .flat_map(|id| {
            block_announcements(
                state,
                id,
                Announcement::Remote {
                    now_ms,
                    best_header_height,
                },
            )
        })
        .collect()
}

/// The mining handler's complete post-execute relay sequence. Remove the local
/// feedback before generic flush, and announce only a successful new tip.
pub(super) fn relay_local_apply(
    state: &mut NodeState,
    header_id: [u8; 32],
    mut follow_ups: Vec<Action>,
) -> bool {
    follow_ups.extend(applied_block_announcements(state, Some(header_id)));
    flush_actions(state, follow_ups);
    if state.store.chain_state_meta().best_full_block_id != header_id {
        return false;
    }
    let actions = block_announcements(state, header_id, Announcement::Mined);
    info!(id = %hex::encode(header_id), peers = state.registry.peers.len(), "announcing applied mined block");
    flush_actions(state, actions);
    true
}

/// Scala v6.0.6 23aabead8 ErgoNodeViewSynchronizer.scala:286-289,1435-1463:
/// one Inv per id, header then ADProofs, transactions, extension. Advertise
/// only servable sections. Local mining announces after successful apply.
pub(super) fn block_announcements(
    state: &NodeState,
    id: [u8; 32],
    policy: Announcement,
) -> Vec<Action> {
    if state.registry.peers.is_empty() {
        return Vec::new();
    }
    let bytes = match state.store.get_header(&id) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Vec::new(),
        Err(error) => {
            warn!(%error, id = %hex::encode(id), operation = "get_header", "cannot read applied block for inventory");
            return Vec::new();
        }
    };
    let header = match read_header(&mut VlqReader::new(&bytes)) {
        Ok(header) => header,
        Err(error) => {
            warn!(%error, id = %hex::encode(id), "cannot parse applied block header for inventory");
            return Vec::new();
        }
    };
    if let Announcement::Remote {
        now_ms,
        best_header_height,
    } = policy
    {
        // Deliberate deviation: Scala has no height cap. During catch-up this
        // limits both the burst and sustained relay of already-known blocks:
        // our 2,048-frame per-peer queue disconnects on full, and receivers
        // rate-limit frames. At most 17 heights (tip through tip-16) qualify.
        // Future timestamps satisfy Scala's signed age < two hours; a zero
        // clock is not usable evidence of freshness.
        if now_ms == 0
            || now_ms.saturating_sub(header.timestamp) >= RECENT_BLOCK_MS
            || best_header_height.saturating_sub(header.height) > RELAY_TIP_WINDOW
        {
            return Vec::new();
        }
    }
    let sections = ExpectedSections::from_header(
        &id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    let sentinel = serving_sentinel(&state.store);
    let ids = std::iter::once((ModifierTypeId::Header, id)).chain(
        [
            (ModifierTypeId::ADProofs, sections.ad_proofs_id),
            (ModifierTypeId::BlockTransactions, sections.transactions_id),
            (ModifierTypeId::Extension, sections.extension_id),
        ]
        .into_iter()
        .filter(|(_, id)| {
            sentinel
                .and_then(|s| servable_section(&state.store, id, s))
                .is_some_and(|bytes| message::single_modifier_fits(bytes.len()))
        }),
    );
    let mut actions = Vec::new();
    let mut section_count = 0;
    for (kind, modifier_id) in ids {
        match message::serialize_inv(&InvData {
            type_id: kind.as_byte(),
            ids: vec![modifier_id],
        }) {
            Ok(payload) => {
                if kind != ModifierTypeId::Header {
                    section_count += 1;
                }
                actions.extend(state.registry.peers.keys().map(|peer| Action::SendToPeer {
                    peer: *peer,
                    code: message::CODE_INV,
                    payload: payload.clone(),
                }));
            }
            Err(error) => {
                warn!(%error, id = %hex::encode(modifier_id), "cannot serialize block inventory")
            }
        }
    }
    debug!(id = %hex::encode(id), height = header.height, peers = state.registry.peers.len(), sections = section_count, "announcing applied block");
    actions
}
