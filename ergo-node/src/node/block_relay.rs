//! Header-first block inventory, restricted to sections we can serve now.

use super::{
    peer_actions::flush_actions,
    section_serving::{servable_section, serving_sentinel},
    NodeState,
};
use ergo_crypto::merkle::transactions_root;
use ergo_p2p::{
    message,
    types::{InvData, ModifierTypeId},
};
use ergo_primitives::reader::VlqReader;
use ergo_ser::{
    block_transactions::read_block_transactions,
    header::{read_header, Header},
    modifier_id::{compute_section_id, ExpectedSections, TYPE_BLOCK_TRANSACTIONS},
    transaction::transaction_id,
};
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

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

impl Announcement {
    fn label(self) -> &'static str {
        match self {
            Self::Mined => "mined",
            Self::Remote { .. } => "remote",
        }
    }
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
    if !ids.is_empty() {
        // A block applied, so the full tip moved off any parent whose mined
        // child failed; mining on the new tip announces before apply again.
        state.mined_apply_failed_parent = None;
    }
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

/// Queue the inventory of a self-mined block before it is applied, as Scala's
/// `NewBlockMined` does. The caller has passed the header through the full
/// header pipeline and stored every section, so each advertised id is
/// servable. Returns whether an inventory was queued.
///
/// Deliberate deviation: nothing is queued while `parent_id` is the parent of
/// a mined block that became the best header and then failed to apply.
/// Scala's `onSolvedBlockFailed` (CandidateGenerator.scala:94-104 at v6.0.6
/// 23aabead8) drops the cached candidates, so its next solution on that
/// parent comes from a fresh candidate and is announced before apply. Here
/// the failed block's template stays cached, and every further solution on
/// it would advertise another block this node rejects, so blocks on that
/// parent are announced only after they apply (`finish_local_apply`) until a
/// block applies.
pub(super) fn announce_mined_block_before_apply(
    state: &mut NodeState,
    header_id: [u8; 32],
    parent_id: [u8; 32],
) -> bool {
    if state.mined_apply_failed_parent == Some(parent_id) {
        info!(
            id = %hex::encode(header_id),
            parent = %hex::encode(parent_id),
            "a mined block on this parent failed to apply; announcing this one only after it applies"
        );
        return false;
    }
    queue_mined_block_inventory(state, header_id, "before_apply")
}

/// The mining handler's post-execute sequence. The mined block is removed from
/// this flush's applied-block drain, so the remote relay does not announce it
/// here, and a block that applied without a pre-apply announcement is
/// announced instead: the mining path announces each applied mined block
/// once. A later re-apply of the same block (after a restart, a reorg, or a
/// retry following a non-verdict failure, such as a `POST /blocks`
/// resubmission) goes through the remote relay and may announce it again,
/// which is harmless because peers do not request ids they know. When a block
/// that became the best header does not apply, pre-apply announcement stops
/// for its parent until a block applies. Returns whether it became the full
/// tip.
pub(super) fn finish_local_apply(
    state: &mut NodeState,
    header_id: [u8; 32],
    parent_id: [u8; 32],
    submitted: MinedSubmission,
    mut follow_ups: Vec<Action>,
) -> bool {
    follow_ups.extend(applied_block_announcements(state, Some(header_id)));
    flush_actions(state, follow_ups);
    let applied = state.store.chain_state_meta().best_full_block_id == header_id;
    let announced = matches!(submitted, MinedSubmission::NewBest { announced: true });
    if applied && !announced {
        queue_mined_block_inventory(state, header_id, "after_apply");
    }
    if !applied && matches!(submitted, MinedSubmission::NewBest { .. }) {
        state.mined_apply_failed_parent = Some(parent_id);
    }
    applied
}

/// How the header pipeline placed a mined block, and whether its inventory
/// was queued before apply.
#[derive(Clone, Copy)]
pub(super) enum MinedSubmission {
    /// It became the best header, so `AssembleBlock` applies it.
    NewBest { announced: bool },
    /// It was stored as a fork; `AssembleBlock` does not apply it.
    Fork,
}

/// Queue a self-mined block's inventory once every section it would serve
/// passes the check a receiving peer runs on it. Returns whether an inventory
/// was queued.
fn queue_mined_block_inventory(
    state: &mut NodeState,
    header_id: [u8; 32],
    stage: &'static str,
) -> bool {
    if state.registry.peers.is_empty() {
        return false;
    }
    let Some(header) = inventory_header(state, header_id, Announcement::Mined) else {
        error!(
            id = %hex::encode(header_id),
            stage,
            "cannot read the mined block header to check its sections; not announcing it"
        );
        return false;
    };
    // The check and the inventory share one read of each section.
    let sections = servable_sections(state, header_id, &header);
    if let Err(reason) = mined_sections_match_header(header.version, &sections) {
        error!(
            id = %hex::encode(header_id),
            stage,
            %reason,
            "a mined block section fails the receiving peer's section check; not announcing the block"
        );
        return false;
    }
    let actions = inventory_actions(state, header_id, &header, &sections, Announcement::Mined);
    if actions.is_empty() {
        return false;
    }
    info!(id = %hex::encode(header_id), peers = state.registry.peers.len(), stage, "queued mined block inventory");
    flush_actions(state, actions);
    true
}

/// A receiving peer recomputes each section's id from its bytes and rejects
/// (and penalizes) a mismatch: Scala `ErgoNodeViewSynchronizer.parseModifiers`,
/// mirrored by `verify_section_modifier_id`, which this node runs on every
/// section a peer delivers and on every `POST /blocks` submission. Run it on
/// the bytes this node would serve for a mined block: the candidate builder
/// computes the header roots from in-memory transactions, extension fields
/// and proof bytes, and nothing else re-hashes the serialized sections before
/// apply. A section this node cannot serve is neither announced nor served,
/// so there is nothing to check for it.
fn mined_sections_match_header(
    header_version: u8,
    sections: &[ServableSection],
) -> Result<(), String> {
    for section in sections {
        let kind = section.kind.as_byte();
        ergo_sync::coordinator::verify_section_modifier_id(kind, &section.id, &section.bytes)
            .map_err(|error| format!("section type {kind}: {error}"))?;
        if section.kind == ModifierTypeId::BlockTransactions {
            transactions_root_matches_version(header_version, section)?;
        }
    }
    Ok(())
}

/// `verify_section_modifier_id` accepts a BlockTransactions section whose id
/// matches either transactions-root formula. Scala takes the formula from the
/// block version the bytes carry (`BlockTransactionsSerializer.parse`, then
/// `BlockTransactions.transactionsRoot`): transaction ids alone at version
/// one, transaction ids and witness ids above it. Mined sections carry their
/// header's version marker (`ergo_mining::submit`), so a section that matched
/// one formula must have matched the one for its header's version.
fn transactions_root_matches_version(
    header_version: u8,
    section: &ServableSection,
) -> Result<(), String> {
    let block_transactions = read_block_transactions(&mut VlqReader::new(&section.bytes))
        .map_err(|error| format!("BlockTransactions parse: {error:?}"))?;
    let tx_ids = block_transactions
        .transactions
        .iter()
        .map(|tx| transaction_id(tx).map(|id| *id.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("transaction_id: {error:?}"))?;
    let tx_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    let ids_only_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        block_transactions.header_id.as_bytes(),
        &transactions_root(&tx_refs, None),
    );
    // The writer marks, and Scala roots over witness ids as well, only a
    // version above one read as a signed byte.
    let witnessed = (header_version as i8) > 1;
    if (ids_only_id == section.id) == witnessed {
        return Err(format!(
            "BlockTransactions root does not use the block version {header_version} formula"
        ));
    }
    Ok(())
}

/// Scala v6.0.6 23aabead8 ErgoNodeViewSynchronizer.scala:286-289,1435-1463:
/// one Inv per id, header then ADProofs, transactions, extension. `Mined`
/// skips the remote freshness and tip gates; its callers decide when a mined
/// block is announced.
///
/// Deliberate deviation: Scala advertises all three section ids of the header
/// (`Header.sectionIds`); this node advertises only the sections it can serve
/// now, so it never announces something it will not deliver.
pub(super) fn block_announcements(
    state: &NodeState,
    id: [u8; 32],
    policy: Announcement,
) -> Vec<Action> {
    if state.registry.peers.is_empty() {
        return Vec::new();
    }
    let Some(header) = inventory_header(state, id, policy) else {
        return Vec::new();
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
    let sections = servable_sections(state, id, &header);
    inventory_actions(state, id, &header, &sections, policy)
}

/// A stored block section this node serves on request, with the bytes it
/// would send.
struct ServableSection {
    kind: ModifierTypeId,
    id: [u8; 32],
    bytes: Vec<u8>,
}

/// The stored header an inventory for `id` is built from.
fn inventory_header(state: &NodeState, id: [u8; 32], policy: Announcement) -> Option<Header> {
    let bytes = match state.store.get_header(&id) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(error) => {
            warn!(%error, id = %hex::encode(id), policy = policy.label(), operation = "get_header", "cannot read block header for inventory");
            return None;
        }
    };
    match read_header(&mut VlqReader::new(&bytes)) {
        Ok(header) => Some(header),
        Err(error) => {
            warn!(%error, id = %hex::encode(id), policy = policy.label(), "cannot parse block header for inventory");
            None
        }
    }
}

/// The sections of `header` that the `RequestModifier` handler would serve
/// now, each read once. It serves none while the pruning sentinel cannot be
/// read.
fn servable_sections(state: &NodeState, id: [u8; 32], header: &Header) -> Vec<ServableSection> {
    let Some(sentinel) = serving_sentinel(&state.store) else {
        return Vec::new();
    };
    let expected = ExpectedSections::from_header(
        &id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    [
        (ModifierTypeId::ADProofs, expected.ad_proofs_id),
        (ModifierTypeId::BlockTransactions, expected.transactions_id),
        (ModifierTypeId::Extension, expected.extension_id),
    ]
    .into_iter()
    .filter_map(|(kind, id)| {
        servable_section(&state.store, &id, sentinel).map(|bytes| ServableSection {
            kind,
            id,
            bytes,
        })
    })
    .collect()
}

/// One Inv per id to every handshaked peer: the header, then each section
/// small enough to deliver in one Modifier frame.
fn inventory_actions(
    state: &NodeState,
    id: [u8; 32],
    header: &Header,
    sections: &[ServableSection],
    policy: Announcement,
) -> Vec<Action> {
    let ids = std::iter::once((ModifierTypeId::Header, id)).chain(
        sections
            .iter()
            .filter(|section| message::single_modifier_fits(section.bytes.len()))
            .map(|section| (section.kind, section.id)),
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
    debug!(id = %hex::encode(id), height = header.height, peers = state.registry.peers.len(), sections = section_count, policy = policy.label(), "queued block inventory");
    actions
}
