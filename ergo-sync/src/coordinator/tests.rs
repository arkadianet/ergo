use super::*;
use ergo_p2p::delivery::ModifierStatus;
use ergo_p2p::message::{self, SyncInfo};
use ergo_p2p::peer::SyncVersion;
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_primitives::digest::blake2b256;
use ergo_ser::modifier_id::ExpectedSections;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

// ----- helpers -----

fn peer(port: u16) -> PeerId {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

fn mk(v: u8) -> [u8; 32] {
    [v; 32]
}

/// Mock chain view for testing.
struct MockChain {
    best_header_id: [u8; 32],
    best_header_height: u32,
    best_full_block_height: u32,
    known_headers: std::collections::HashSet<[u8; 32]>,
    best_chain_ids: std::collections::HashSet<[u8; 32]>,
    height_to_id: std::collections::HashMap<u32, [u8; 32]>,
    id_to_height: std::collections::HashMap<[u8; 32], u32>,
}

impl MockChain {
    fn new(header_height: u32, full_block_height: u32) -> Self {
        Self {
            best_header_id: [0u8; 32],
            best_header_height: header_height,
            best_full_block_height: full_block_height,
            known_headers: std::collections::HashSet::new(),
            best_chain_ids: std::collections::HashSet::new(),
            height_to_id: std::collections::HashMap::new(),
            id_to_height: std::collections::HashMap::new(),
        }
    }

    /// Helper for tests building a chain: registers `id` at `height`
    /// in both height→id and id→height indexes plus marks it on the
    /// best chain.
    fn add_best_chain_header(&mut self, height: u32, id: [u8; 32]) {
        self.height_to_id.insert(height, id);
        self.id_to_height.insert(id, height);
        self.best_chain_ids.insert(id);
        self.known_headers.insert(id);
    }
}

impl ChainView for MockChain {
    fn best_header_id(&self) -> [u8; 32] {
        self.best_header_id
    }
    fn best_header_height(&self) -> u32 {
        self.best_header_height
    }
    fn best_full_block_height(&self) -> u32 {
        self.best_full_block_height
    }
    fn is_on_best_chain(&self, id: &[u8; 32]) -> bool {
        self.best_chain_ids.contains(id)
    }
    fn has_header(&self, id: &[u8; 32]) -> bool {
        self.known_headers.contains(id)
    }
    fn has_block_section(&self, _id: &[u8; 32]) -> bool {
        false
    }
    fn is_invalid(&self, _id: &[u8; 32]) -> bool {
        false
    }
    fn recent_header_ids(&self, _count: usize) -> Vec<[u8; 32]> {
        Vec::new()
    }
    fn recent_header_bytes(&self, _count: usize) -> Vec<Vec<u8>> {
        Vec::new()
    }
    fn header_id_at_height(&self, h: u32) -> ergo_state::chain::HeightLookup {
        match self.height_to_id.get(&h).copied() {
            Some(id) => ergo_state::chain::HeightLookup::Dense(id),
            None => ergo_state::chain::HeightLookup::AboveTip,
        }
    }
    fn header_height_for(&self, id: &[u8; 32]) -> Option<u32> {
        self.id_to_height.get(id).copied()
    }
}

// ----- happy path / scenario tests -----

#[test]
fn on_inv_requests_unknown_modifiers() {
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p = peer(9030);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1), mk(2), mk(3)],
    };

    let actions = coord.on_inv(p, &inv, &chain, now);
    // Should produce a SendToPeer with RequestModifier
    assert!(actions.iter().any(
        |a| matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER)
    ));
}

#[test]
fn on_inv_skips_known_headers() {
    let mut coord = SyncCoordinator::new(0);
    let mut chain = MockChain::new(10, 10);
    chain.known_headers.insert(mk(1));
    chain.known_headers.insert(mk(2));
    let now = Instant::now();
    let p = peer(9030);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1), mk(2)],
    };

    let actions = coord.on_inv(p, &inv, &chain, now);
    assert!(!actions
        .iter()
        .any(|a| matches!(a, Action::SendToPeer { .. })));
}

#[test]
fn on_inv_section_uses_has_block_section_not_has_header() {
    // Section Inv should use has_block_section, not has_header.
    // mk(1) is known as a header but NOT as a block section — it should
    // still be requested when advertised as a section type.
    let mut coord = SyncCoordinator::new(0);
    let mut chain = MockChain::new(10, 10);
    chain.known_headers.insert(mk(1)); // known as header
                                       // has_block_section returns false for everything in MockChain
    let now = Instant::now();
    let p = peer(9030);

    let inv = InvData {
        type_id: ModifierTypeId::BlockTransactions.as_byte(),
        ids: vec![mk(1)], // known as header but NOT as section
    };

    let actions = coord.on_inv(p, &inv, &chain, now);
    // Section filtering uses has_block_section (returns false) not has_header,
    // so mk(1) should be requested despite being a known header.
    assert!(actions.iter().any(|a| matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER)),
            "section Inv should request mk(1) because has_block_section is false");
}

#[test]
fn on_modifier_received_rejects_spam() {
    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);

    // Receive an unrequested modifier
    let actions =
        coord.on_modifier_received(p, ModifierTypeId::Header.as_byte(), mk(99), vec![1, 2, 3]);
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::Penalize {
            penalty: Penalty::Spam,
            ..
        }
    )));
}

#[test]
fn on_modifier_received_accepts_requested() {
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p = peer(9030);

    // First request via Inv
    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1)],
    };
    coord.on_inv(p, &inv, &chain, now);

    // Now deliver it
    let actions =
        coord.on_modifier_received(p, ModifierTypeId::Header.as_byte(), mk(1), vec![10, 20, 30]);
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::ValidateHeader { .. })));
    assert!(!actions.iter().any(|a| matches!(a, Action::Penalize { .. })));
}

#[test]
fn on_modifier_received_rejects_wire_type_mismatch() {
    // Request a modifier AS a BlockTransactions section, then have the peer
    // deliver that id claiming it's a Header. The wire type must be validated
    // against the requested type: penalize misbehavior, do NOT route, and keep
    // the request outstanding (no mark_received) so a retry can still land.
    let mut coord = SyncCoordinator::new(100);
    let chain = MockChain::new(101, 100);
    let now = Instant::now();
    let p = peer(9030);

    let inv = InvData {
        type_id: ModifierTypeId::BlockTransactions.as_byte(),
        ids: vec![mk(7)],
    };
    coord.on_inv(p, &inv, &chain, now);

    // Deliver the same id but claim it's a Header (mismatched type).
    let actions =
        coord.on_modifier_received(p, ModifierTypeId::Header.as_byte(), mk(7), vec![1, 2, 3]);
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                penalty: Penalty::Misbehavior,
                ..
            }
        )),
        "wire/requested type mismatch must penalize misbehavior",
    );
    assert!(
        !actions.iter().any(|a| matches!(
            a,
            Action::ValidateHeader { .. } | Action::PersistSection { .. }
        )),
        "a mismatched delivery must not be routed",
    );

    // Request preserved (not mark_received): a correctly-typed delivery of the
    // same id from the same peer is still accepted, not treated as spam.
    let ok = coord.on_modifier_received(
        p,
        ModifierTypeId::BlockTransactions.as_byte(),
        mk(7),
        vec![1, 2, 3],
    );
    assert!(
        !ok.iter().any(|a| matches!(
            a,
            Action::Penalize {
                penalty: Penalty::Spam,
                ..
            }
        )),
        "outstanding request survived the mismatch, so the correct-type delivery is accepted",
    );
}

#[test]
fn block_section_accept_records_delivery_success_outcome() {
    // An accepted block-BODY section emits a success outcome for the
    // delivering peer so the peer manager can clear its download streak.
    let mut coord = SyncCoordinator::new(100);
    let chain = MockChain::new(101, 100);
    let now = Instant::now();
    let p = peer(9030);

    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let tx_id = expected.transactions_id;
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    coord.on_header_validated(p, mk(1), 101, recent_ts, expected, now);

    let inv = InvData {
        type_id: ModifierTypeId::BlockTransactions.as_byte(),
        ids: vec![tx_id],
    };
    coord.on_inv(p, &inv, &chain, now);
    let actions = coord.on_modifier_received(
        p,
        ModifierTypeId::BlockTransactions.as_byte(),
        tx_id,
        vec![1],
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::NoteDeliveryOutcome { peer, succeeded: true } if *peer == p
        )),
        "accepted block section must emit a success outcome for the delivering peer"
    );
}

#[test]
fn header_accept_does_not_record_delivery_outcome() {
    // Body-only scoping: an accepted HEADER must NOT reset the streak, or a
    // body-stalling peer could dodge degradation by riding the header flow.
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p = peer(9030);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1)],
    };
    coord.on_inv(p, &inv, &chain, now);
    let actions =
        coord.on_modifier_received(p, ModifierTypeId::Header.as_byte(), mk(1), vec![10, 20, 30]);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::NoteDeliveryOutcome { .. })),
        "header delivery must not emit a delivery outcome (body-only streak)"
    );
}

#[test]
fn mislabeled_header_delivery_does_not_reset_streak() {
    // A peer can't dodge body-download deprioritization by delivering a
    // HEADER while claiming a body-section wire type: the reset is classified
    // by the REQUESTED type (Header), so no success outcome is emitted.
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p = peer(9030);

    // We requested mk(1) as a Header.
    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1)],
    };
    coord.on_inv(p, &inv, &chain, now);

    // Peer delivers it but lies about the type (claims BlockTransactions).
    let actions = coord.on_modifier_received(
        p,
        ModifierTypeId::BlockTransactions.as_byte(),
        mk(1),
        vec![10, 20, 30],
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::NoteDeliveryOutcome { .. })),
        "a header delivery mislabeled as a section must not reset the body streak"
    );
}

#[test]
fn on_header_validated_requests_sections_with_correct_types() {
    let mut coord = SyncCoordinator::new(100);
    let now = Instant::now();
    let p = peer(9030);

    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));

    // Use a recent timestamp so headers_chain_synced triggers
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let actions = coord.on_header_validated(p, mk(1), 101, recent_ts, expected, now);
    // Should produce TWO separate RequestModifier messages: one for
    // BlockTransactions (102) and one for Extension (108).
    let requests: Vec<_> = actions.iter()
            .filter(|a| matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER))
            .collect();
    assert_eq!(
        requests.len(),
        2,
        "expected separate requests for tx and extension sections"
    );
}

#[test]
fn mode_6_headers_only_emits_no_section_requests() {
    // Mode 6 sync path: on_header_validated must update sync_state
    // (best-known-header advances, headers-chain-synced is
    // checked) but emit NO RequestModifier actions and register
    // NO pending blocks. Mirrors Scala `ToDownloadProcessor`
    // returning Nil when `!nodeSettings.verifyTransactions`.
    let mut coord = SyncCoordinator::new_with_window_and_mode(
        100,
        ergo_p2p::sync::DOWNLOAD_WINDOW,
        true, // headers_only = Mode 6
    );
    assert!(coord.is_headers_only());
    let now = Instant::now();
    let p = peer(9030);
    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));

    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let actions = coord.on_header_validated(p, mk(1), 101, recent_ts, expected, now);

    // No RequestModifier actions emitted.
    let requests: Vec<_> = actions
            .iter()
            .filter(|a| {
                matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER)
            })
            .collect();
    assert_eq!(
        requests.len(),
        0,
        "Mode 6 must not request block sections; got: {:?}",
        actions,
    );

    // No pending blocks registered.
    assert_eq!(
        coord.sync_state().pending_count(),
        0,
        "Mode 6 must not register pending blocks",
    );
}

#[test]
fn mode_6_on_inv_drops_section_invs_accepts_header_invs() {
    // Mode 6 perimeter: section Invs (BlockTransactions, ADProofs,
    // Extension) must be silently dropped. Header Invs must still
    // pass through and produce a RequestModifier so the header
    // chain keeps advancing.
    let mut coord =
        SyncCoordinator::new_with_window_and_mode(100, ergo_p2p::sync::DOWNLOAD_WINDOW, true);
    let chain = MockChain::new(100, 100);
    let now = Instant::now();
    let p = peer(9030);

    // BlockTransactions Inv — dropped.
    let section_inv = InvData {
        type_id: ModifierTypeId::BlockTransactions.as_byte(),
        ids: vec![mk(1), mk(2)],
    };
    let actions = coord.on_inv(p, &section_inv, &chain, now);
    assert!(
        actions.is_empty(),
        "Mode 6 must drop BlockTransactions Invs, got {actions:?}",
    );

    // Extension Inv — dropped.
    let ext_inv = InvData {
        type_id: ModifierTypeId::Extension.as_byte(),
        ids: vec![mk(3)],
    };
    let actions = coord.on_inv(p, &ext_inv, &chain, now);
    assert!(
        actions.is_empty(),
        "Mode 6 must drop Extension Invs, got {actions:?}",
    );

    // Header Inv — still requests unknown ids.
    let header_inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(4), mk(5)],
    };
    let actions = coord.on_inv(p, &header_inv, &chain, now);
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::SendToPeer { code, .. }
                if *code == message::CODE_REQUEST_MODIFIER
        )),
        "Mode 6 must keep requesting unknown headers, got {actions:?}",
    );
}

#[test]
fn mode_6_on_modifier_received_drops_section_payloads() {
    // Defense-in-depth at the modifier handoff: even if a section
    // payload reaches `on_modifier_received` (peer push, race with
    // an in-flight request from before the mode flipped), no
    // `PersistSection` or `AssembleBlock` action is emitted. The
    // section never enters the store; the executor never sees it.
    let mut coord =
        SyncCoordinator::new_with_window_and_mode(100, ergo_p2p::sync::DOWNLOAD_WINDOW, true);
    let p = peer(9030);

    // The delivery tracker rejects unrequested IDs as spam — but
    // even if it didn't, the headers_only short-circuit in the
    // section branch must run BEFORE persistence. To make the test
    // robust against the delivery reject path, register the
    // request first so delivery.on_received returns Accept.
    let section_inv = InvData {
        type_id: ModifierTypeId::BlockTransactions.as_byte(),
        ids: vec![mk(1)],
    };
    // Force the delivery state into "Requested" by going through
    // `delivery.request` directly; bypasses on_inv's short-circuit
    // to set up the pre-condition we want to test.
    coord
        .delivery
        .request(p, section_inv.type_id, &[mk(1)], Instant::now());

    let actions = coord.on_modifier_received(
        p,
        ModifierTypeId::BlockTransactions.as_byte(),
        mk(1),
        vec![0xAA; 32],
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::PersistSection { .. })),
        "Mode 6 must not emit PersistSection, got {actions:?}",
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::AssembleBlock { .. })),
        "Mode 6 must not emit AssembleBlock, got {actions:?}",
    );
}

#[test]
fn section_arrival_triggers_assembly() {
    let mut coord = SyncCoordinator::new(100);
    let chain = MockChain::new(101, 100);
    let now = Instant::now();
    let p = peer(9030);

    // Validate header first
    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let tx_id = expected.transactions_id;
    let ext_id = expected.extension_id;
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    coord.on_header_validated(p, mk(1), 101, recent_ts, expected, now);

    // Deliver transactions section (need to request it first via on_inv)
    let inv_tx = InvData {
        type_id: ModifierTypeId::BlockTransactions.as_byte(),
        ids: vec![tx_id],
    };
    coord.on_inv(p, &inv_tx, &chain, now);
    let actions = coord.on_modifier_received(
        p,
        ModifierTypeId::BlockTransactions.as_byte(),
        tx_id,
        vec![1],
    );
    assert!(!actions
        .iter()
        .any(|a| matches!(a, Action::AssembleBlock { .. })));

    // Deliver extension section
    let inv_ext = InvData {
        type_id: ModifierTypeId::Extension.as_byte(),
        ids: vec![ext_id],
    };
    coord.on_inv(p, &inv_ext, &chain, now);
    let actions =
        coord.on_modifier_received(p, ModifierTypeId::Extension.as_byte(), ext_id, vec![2]);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::AssembleBlock { header_id } if *header_id == mk(1))),
        "expected AssembleBlock after both sections arrived"
    );
}

#[test]
fn on_block_applied_updates_state() {
    let mut coord = SyncCoordinator::new(100);
    coord.on_block_applied(mk(1), 101);
    assert_eq!(coord.sync_state().best_full_block_height(), 101);
}

#[test]
fn timeout_produces_penalty() {
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p = peer(9030);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1)],
    };
    coord.on_inv(p, &inv, &chain, now);

    // Advance past timeout — no alternative peer available
    let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[]);
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::Penalize {
            penalty: Penalty::NonDelivery,
            ..
        }
    )));
}

#[test]
fn block_section_timeout_records_delivery_failure_outcome() {
    // Alongside the NonDelivery penalty, a block-BODY section timeout emits a
    // failure outcome for the failed peer so the peer manager can grow its
    // download-failure streak (the signal the decaying score can't provide).
    let mut coord = SyncCoordinator::new(100);
    let now = Instant::now();
    let p = peer(9030);

    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // Registers the header and requests its body sections from p.
    coord.on_header_validated(p, mk(1), 101, recent_ts, expected, now);

    let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[]);
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::NoteDeliveryOutcome { peer, succeeded: false } if *peer == p
        )),
        "a block-section timeout must emit a failure outcome for the failed peer"
    );
}

#[test]
fn header_timeout_records_no_delivery_outcome() {
    // Body-only scoping: a HEADER request timeout still penalizes (NonDelivery)
    // but must NOT emit a delivery-streak outcome — only body sections count.
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p = peer(9030);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1)],
    };
    coord.on_inv(p, &inv, &chain, now);

    let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[]);
    assert!(
        actions.iter().any(|a| matches!(a, Action::Penalize { .. })),
        "header timeout should still penalize"
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::NoteDeliveryOutcome { .. })),
        "header timeout must not emit a delivery-streak outcome (body-only)"
    );
}

#[test]
fn timeout_reassigns_to_different_peer() {
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1)],
    };
    coord.on_inv(p1, &inv, &chain, now);

    let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[p2]);
    // Should have penalty + re-request to p2
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::Penalize { peer, .. } if *peer == p1)));
    assert!(
        actions.iter().any(|a| matches!(a,
            Action::SendToPeer { peer, code: 22, .. } if *peer == p2)),
        "timed-out request should be reassigned to p2"
    );
}

#[test]
fn timed_out_transaction_is_forgotten_without_penalty() {
    // Scala parity (checkDelivery): a timed-out MEMPOOL TRANSACTION is just
    // forgotten — a tx may legitimately have left the peer's mempool, so the
    // peer is NOT penalized and the tx is NOT re-requested. The tracker must
    // also stop tracking the forgotten id entirely.
    let mut coord = SyncCoordinator::new(0);
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);
    let tx_id = mk(7);

    // Register an in-flight Transaction request to p1.
    let (req, requested) = coord.request_transactions(p1, &[tx_id], now);
    assert_eq!(requested, 1, "one id should be registered for p1");
    assert!(
        req.iter()
            .any(|a| matches!(a, Action::SendToPeer { peer, code: 22, .. } if *peer == p1)),
        "tx request should be sent to p1"
    );

    // Advance past the timeout with p2 available as a re-request candidate.
    let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[p2]);

    assert!(
        !actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                penalty: Penalty::NonDelivery,
                ..
            }
        )),
        "a timed-out tx must NOT penalize the peer"
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::SendToPeer { code: 22, .. })),
        "a timed-out tx must NOT be re-requested"
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::NoteDeliveryOutcome { .. })),
        "a timed-out tx must NOT emit a delivery-streak outcome"
    );

    // The tracker no longer tracks the forgotten tx.
    assert_eq!(
        coord.delivery.status(&tx_id),
        ergo_p2p::delivery::ModifierStatus::Unknown,
        "forgotten tx should return to Unknown status"
    );
    assert_eq!(
        coord.delivery.modifier_type(&tx_id),
        None,
        "forgotten tx should leave no residual type record in the tracker"
    );
}

#[test]
fn timed_out_block_modifier_still_penalizes_and_rerequests() {
    // Regression guard: a timed-out HEADER (or any block modifier) keeps the
    // aggressive penalize + re-request behavior — only mempool txs are forgotten.
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1)],
    };
    coord.on_inv(p1, &inv, &chain, now);

    let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[p2]);

    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize { peer, penalty: Penalty::NonDelivery } if *peer == p1
        )),
        "a timed-out header must still penalize the failed peer"
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::SendToPeer { peer, code: 22, .. } if *peer == p2
        )),
        "a timed-out header must still be re-requested from another peer"
    );
}

#[test]
fn orphan_parent_request_revives_exhausted_header_id() {
    // Scala-parity (2Q): after MAX_RETRIES the modifier returns
    // to Unknown status (not the old permanent-Failed state).
    // Parent-walk re-request works either way; this test just
    // pins the new status.
    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);
    let header_id = mk(42);
    let mut now = Instant::now();

    for _ in 0..ergo_p2p::delivery::MAX_RETRIES {
        let actions = coord.request_missing_header_parents(p, &[header_id], now);
        assert!(actions.iter().any(|a| matches!(a,
                Action::SendToPeer { peer, code: 22, .. } if *peer == p)));

        let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
        let _ = coord.check_timeouts(later, &[]);
        now = later + std::time::Duration::from_secs(1);
    }

    // After exhaustion: Unknown (not Failed) per Scala parity.
    assert_eq!(
        coord.delivery().status(&header_id),
        ergo_p2p::delivery::ModifierStatus::Unknown,
    );

    let actions = coord.request_missing_header_parents(p, &[header_id], now);
    assert!(
        actions.iter().any(|a| matches!(a,
            Action::SendToPeer { peer, code: 22, .. } if *peer == p)),
        "parent-walk must be able to request an exhausted root header again"
    );
    assert_eq!(
        coord.delivery().status(&header_id),
        ergo_p2p::delivery::ModifierStatus::Requested,
    );
}

#[test]
fn peer_disconnect_reassigns_requests() {
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p1 = peer(9030);
    let p2 = peer(9031);

    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mk(1), mk(2)],
    };
    coord.on_inv(p1, &inv, &chain, now);

    let actions = coord.on_peer_disconnected(&p1, now, &[p2]);
    // Should re-request both IDs from p2
    let request_actions: Vec<_> = actions
        .iter()
        .filter(|a| matches!(a, Action::SendToPeer { peer, code: 22, .. } if *peer == p2))
        .collect();
    assert_eq!(
        request_actions.len(),
        2,
        "both cancelled requests should be reassigned to p2"
    );
}

// Helper: build a fake serialized header with given parent_id.
// Format: version(1) + parent_id(32) + padding(100)
fn make_header(parent: &[u8; 32]) -> Vec<u8> {
    let mut h = vec![1u8];
    h.extend_from_slice(parent);
    h.extend_from_slice(&[0u8; 100]);
    h
}

#[test]
fn continuation_header_accepted_when_parent_is_best_header() {
    // Scala's continuationHeaderV2 only inspects the FIRST header
    // and requires parent == best_header_id.
    let best_id = mk(99);
    let header = make_header(&best_id);

    let mut chain = MockChain::new(100, 100);
    chain.best_header_id = best_id;

    let result = find_continuation_header(std::slice::from_ref(&header), &chain);
    assert_eq!(result, Some(header));
}

#[test]
fn continuation_header_rejected_when_parent_not_best() {
    // Parent is known but NOT the best header — should be rejected.
    let some_old_id = mk(50);
    let best_id = mk(99);
    let header = make_header(&some_old_id);

    let mut chain = MockChain::new(100, 100);
    chain.best_header_id = best_id;
    chain.known_headers.insert(some_old_id); // known but not best

    let result = find_continuation_header(&[header], &chain);
    assert!(
        result.is_none(),
        "parent must be best_header_id, not just any known header"
    );
}

#[test]
fn continuation_header_rejected_when_already_known() {
    let best_id = mk(99);
    let header = make_header(&best_id);
    let header_id = ergo_primitives::digest::blake2b256(&header);

    let mut chain = MockChain::new(100, 100);
    chain.best_header_id = best_id;
    chain.known_headers.insert(*header_id.as_bytes()); // already have it

    let result = find_continuation_header(&[header], &chain);
    assert!(result.is_none(), "should reject header we already have");
}

#[test]
fn continuation_header_only_checks_first() {
    // Even if the second header's parent is our best, only the first
    // header is considered (matching Scala).
    let best_id = mk(99);
    let wrong_parent = mk(50);
    let header_wrong = make_header(&wrong_parent); // first in list, wrong parent
    let header_good = make_header(&best_id); // second, right parent

    let mut chain = MockChain::new(100, 100);
    chain.best_header_id = best_id;

    let result = find_continuation_header(&[header_wrong, header_good], &chain);
    assert!(
        result.is_none(),
        "only the first header should be inspected"
    );
}

// ---- Effect-ordering characterization tests (Refactor A.1) ----
//
// These tests lock in the exact sequence of Actions emitted by each
// coordinator entry point. They exist specifically so Refactor A.4
// (collapse Action/ExecResult into direct inline effects) can be
// validated against the same ordering — e.g. "tx section requested
// before extension", "Penalize before re-request", "persist both
// sections before AssembleBlock". Existing tests only assert
// presence via .any() / .filter(); these add index-based assertions.

/// Extract just the RequestModifier SendToPeers, preserving the order
/// they were emitted by the coordinator.
fn request_modifier_codes_in_order(actions: &[Action]) -> Vec<u8> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { code, payload, .. } if *code == message::CODE_REQUEST_MODIFIER => {
                // Payload format: type_id byte first, then vlq-count, then ids.
                Some(payload.first().copied().unwrap_or(0))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn on_inv_ordering_single_request_ids_preserve_input_order() {
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let now = Instant::now();
    let p = peer(9030);

    let ids_in = vec![mk(1), mk(2), mk(3), mk(4)];
    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: ids_in.clone(),
    };
    let actions = coord.on_inv(p, &inv, &chain, now);

    // Exactly one RequestModifier for this peer in this turn.
    let req_count = actions
        .iter()
        .filter(|a| {
            matches!(a,
                Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER
            )
        })
        .count();
    assert_eq!(req_count, 1, "exactly one RequestModifier for the batch");
}

#[test]
fn on_header_validated_ordering_tx_request_before_extension() {
    let mut coord = SyncCoordinator::new(100);
    let now = Instant::now();
    let p = peer(9030);

    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let actions = coord.on_header_validated(p, mk(1), 101, recent_ts, expected, now);

    // Walk Action order; first two RequestModifier payloads must be
    // tx-section (102) then extension (108). Not just "both present"
    // — their relative order is load-bearing (Scala parity).
    let seen = request_modifier_codes_in_order(&actions);
    let tx_type = ModifierTypeId::BlockTransactions.as_byte();
    let ext_type = ModifierTypeId::Extension.as_byte();
    assert!(
        seen.len() >= 2,
        "expected ≥2 RequestModifier actions, got {seen:?}"
    );
    assert_eq!(seen[0], tx_type, "first request must be tx section");
    assert_eq!(seen[1], ext_type, "second request must be extension");
}

#[test]
fn section_delivery_ordering_persist_both_before_assemble() {
    let mut coord = SyncCoordinator::new(100);
    let chain = MockChain::new(101, 100);
    let now = Instant::now();
    let p = peer(9030);

    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let tx_id = expected.transactions_id;
    let ext_id = expected.extension_id;
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    coord.on_header_validated(p, mk(1), 101, recent_ts, expected, now);

    // Arrival 1: tx section. Must see PersistSection for tx, but NO
    // AssembleBlock yet.
    let inv_tx = InvData {
        type_id: ModifierTypeId::BlockTransactions.as_byte(),
        ids: vec![tx_id],
    };
    coord.on_inv(p, &inv_tx, &chain, now);
    let after_tx = coord.on_modifier_received(
        p,
        ModifierTypeId::BlockTransactions.as_byte(),
        tx_id,
        vec![1],
    );
    let tx_persist_idx = after_tx.iter().position(|a| {
        matches!(a,
            Action::PersistSection { modifier_id, .. } if *modifier_id == tx_id
        )
    });
    assert!(
        tx_persist_idx.is_some(),
        "tx arrival must produce PersistSection"
    );
    assert!(
        !after_tx
            .iter()
            .any(|a| matches!(a, Action::AssembleBlock { .. })),
        "no AssembleBlock until both sections persisted"
    );

    // Arrival 2: extension section. Must see PersistSection for ext
    // and AssembleBlock, with the persist BEFORE the assemble.
    let inv_ext = InvData {
        type_id: ModifierTypeId::Extension.as_byte(),
        ids: vec![ext_id],
    };
    coord.on_inv(p, &inv_ext, &chain, now);
    let after_ext =
        coord.on_modifier_received(p, ModifierTypeId::Extension.as_byte(), ext_id, vec![2]);
    let ext_persist_idx = after_ext.iter().position(|a| {
        matches!(a,
            Action::PersistSection { modifier_id, .. } if *modifier_id == ext_id
        )
    });
    let assemble_idx = after_ext.iter().position(|a| {
        matches!(a,
            Action::AssembleBlock { header_id } if *header_id == mk(1)
        )
    });
    assert!(
        ext_persist_idx.is_some(),
        "ext arrival must produce PersistSection"
    );
    assert!(
        assemble_idx.is_some(),
        "ext arrival must produce AssembleBlock"
    );
    assert!(
        ext_persist_idx.unwrap() < assemble_idx.unwrap(),
        "PersistSection must precede AssembleBlock in emitted order",
    );
}

#[test]
fn wrong_peer_modifier_ordering_penalty_before_any_send() {
    // Unrequested/wrong-peer modifier delivery must emit Penalize
    // with NO SendToPeer in the same action batch.
    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);
    let mod_id = mk(42);

    let actions =
        coord.on_modifier_received(p, ModifierTypeId::Header.as_byte(), mod_id, vec![0; 10]);

    let penalize_idx = actions
        .iter()
        .position(|a| matches!(a, Action::Penalize { .. }));
    let send_idx = actions
        .iter()
        .position(|a| matches!(a, Action::SendToPeer { .. }));
    assert!(penalize_idx.is_some(), "unrequested delivery must Penalize");
    assert!(
        send_idx.is_none() || penalize_idx.unwrap() < send_idx.unwrap(),
        "if any SendToPeer is emitted, Penalize must come first",
    );
}

#[test]
fn timeout_ordering_penalty_before_rerequest() {
    // Simulate a requested-then-timed-out modifier. check_timeouts must
    // emit the Penalize action BEFORE any re-request SendToPeer for
    // that same modifier.
    let mut coord = SyncCoordinator::new(0);
    let chain = MockChain::new(0, 0);
    let p1 = peer(9030);
    let p2 = peer(9031);
    let t0 = Instant::now();
    let mod_id = mk(7);

    // p1 requests mod_id
    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mod_id],
    };
    coord.on_inv(p1, &inv, &chain, t0);

    // Advance past timeout with another known peer available for reassign
    // Register p2 as known for reassignment availability.
    coord.on_inv(p2, &inv, &chain, t0);

    let later = t0 + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[p2]);

    // If Penalize fires for p1 and we re-request from p2, Penalize must
    // precede the SendToPeer.
    let penalize_idx = actions.iter().position(|a| {
        matches!(a,
            Action::Penalize { peer, .. } if *peer == p1
        )
    });
    let rerequest_idx = actions.iter().position(|a| {
        matches!(a,
            Action::SendToPeer { peer, code, .. }
                if *peer == p2 && *code == message::CODE_REQUEST_MODIFIER
        )
    });
    if let (Some(pi), Some(ri)) = (penalize_idx, rerequest_idx) {
        assert!(
            pi < ri,
            "Penalize must precede re-request (got pi={pi}, ri={ri})"
        );
    }
}

// ---- Characterization of the single-peer request_missing_sections ----
//
// These tests lock in the emission transcript of the original single-peer
// implementation, which `request_missing_sections_bucketed` below replaces
// with bucketed multi-peer requests. Each assertion is a regression guard
// that future refactors must preserve (or consciously break with a test
// update + diff review).

/// Arrange a coordinator + 2-peer situation with 2 pending blocks whose
/// sections are UNKNOWN to the delivery tracker (i.e. not yet requested).
/// Populates sync_state.pending_blocks + assembly.expected_section_ids
/// directly to bypass on_header_validated (which pre-requests sections
/// on behalf of the caller peer and would leave request_missing_sections
/// with nothing to do).
fn setup_pending_blocks_for_request_tests() -> (
    SyncCoordinator,
    MockChain,
    PeerId,
    PeerId,
    [u8; 32],
    [u8; 32],
) {
    let mut coord = SyncCoordinator::new(100);
    let chain = MockChain::new(102, 100);
    let p1 = peer(9030);
    let p2 = peer(9031);

    // Force headers_chain_synced = true without triggering the
    // auto-request path that on_header_validated fires.
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    coord.sync_state_mut().check_headers_synced(recent_ts);

    let exp1 = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let tx1 = exp1.transactions_id;
    let ext1 = exp1.extension_id;
    coord.sync_state_mut().set_best_known_header(101);
    coord.sync_state_mut().add_pending_block(101, mk(1));
    coord.assembly_mut().register_header(exp1);

    let exp2 = ExpectedSections::from_header(&mk(2), &mk(20), &mk(21), &mk(22));
    coord.sync_state_mut().set_best_known_header(102);
    coord.sync_state_mut().add_pending_block(102, mk(2));
    coord.assembly_mut().register_header(exp2);

    (coord, chain, p1, p2, tx1, ext1)
}

#[test]
fn s0_request_missing_sections_empty_when_no_pending() {
    let mut coord = SyncCoordinator::new(100);
    let chain = MockChain::new(100, 100);
    let now = Instant::now();
    let actions = coord.request_missing_sections(&chain, now, |_t| Some(peer(9030)));
    assert!(
        actions.is_empty(),
        "no pending blocks → no RequestModifier, got {:?}",
        actions.len()
    );
}

#[test]
fn s0_request_missing_sections_current_single_peer_per_type() {
    // Current behavior: select_peer is invoked per type_id (tx / ext),
    // and whichever peer it returns receives the WHOLE batch for that
    // type. One SendToPeer per non-empty type, max 2 SendToPeers total.
    // S1 will change this — locking behavior first.
    let (mut coord, chain, p1, _p2, _tx1, _ext1) = setup_pending_blocks_for_request_tests();
    let now = Instant::now();

    let actions = coord.request_missing_sections(&chain, now, |_type_id| Some(p1));

    let sends: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { peer, code, .. } if *code == message::CODE_REQUEST_MODIFIER => {
                Some(*peer)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        sends.len(),
        2,
        "current behavior emits exactly one message per type_id (tx + ext), got {}",
        sends.len()
    );
    assert!(
        sends.iter().all(|p| *p == p1),
        "all current sends go to the select_peer result (p1), got {:?}",
        sends
    );
}

#[test]
fn s0_request_missing_sections_tx_batch_precedes_extension_batch() {
    // Characterize the emission order: BlockTransactions (type 102)
    // before Extension (type 108). Peers that serve both types rely on
    // this ordering to pipeline tx validation before extension parsing.
    let (mut coord, chain, p1, _p2, _tx1, _ext1) = setup_pending_blocks_for_request_tests();
    let now = Instant::now();

    let actions = coord.request_missing_sections(&chain, now, |_type_id| Some(p1));

    let seen_types = request_modifier_codes_in_order(&actions);
    let tx_t = ModifierTypeId::BlockTransactions.as_byte();
    let ext_t = ModifierTypeId::Extension.as_byte();
    assert!(
        seen_types.len() >= 2,
        "expected ≥2 requests, got {seen_types:?}"
    );
    assert_eq!(seen_types[0], tx_t, "tx type must precede extension type");
    assert_eq!(seen_types[1], ext_t, "extension type must follow tx type");
}

#[test]
fn s0_request_missing_sections_idempotent_across_calls() {
    // Calling twice in a row (without any section arrivals between) must
    // not re-emit requests for modifiers already marked Requested by the
    // first call. DeliveryTracker::status gates this.
    let (mut coord, chain, p1, _p2, _tx1, _ext1) = setup_pending_blocks_for_request_tests();
    let now = Instant::now();

    let first = coord.request_missing_sections(&chain, now, |_t| Some(p1));
    let second = coord.request_missing_sections(&chain, now, |_t| Some(p1));

    let first_count = first.iter().filter(|a|
            matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER)
        ).count();
    let second_count = second.iter().filter(|a|
            matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER)
        ).count();

    assert!(first_count > 0, "first call must request something");
    assert_eq!(
        second_count, 0,
        "second call must not re-request already-Requested modifiers, got {second_count} sends"
    );
}

#[test]
fn s0_on_peer_disconnected_preserves_section_type() {
    // Regression guard: when a peer with both tx + ext in-flight
    // disconnects, each re-request to the fallback peer must carry
    // the ORIGINAL type_id (not the Header fallback from
    // rerequest_modifiers' assembly.identify_section() unwrap_or).
    let mut coord = SyncCoordinator::new(100);
    let p1 = peer(9030);
    let p2 = peer(9031);
    let now = Instant::now();

    let exp = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // on_header_validated pre-requests BOTH tx and ext from p1.
    coord.on_header_validated(p1, mk(1), 101, recent_ts, exp, now);

    // p1 disconnects; redistribute to p2.
    let actions = coord.on_peer_disconnected(&p1, now, &[p2]);

    // Both rerequests must be present to p2, each preserving its
    // original type_id. No Header fallback.
    let rerequest_types: Vec<u8> = actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer {
                peer: dst,
                code,
                payload,
            } if *dst == p2 && *code == message::CODE_REQUEST_MODIFIER => Some(payload[0]),
            _ => None,
        })
        .collect();

    let tx_t = ModifierTypeId::BlockTransactions.as_byte();
    let ext_t = ModifierTypeId::Extension.as_byte();
    assert!(
        rerequest_types.contains(&tx_t),
        "expected BlockTransactions rerequest after disconnect, got {rerequest_types:?}"
    );
    assert!(
        rerequest_types.contains(&ext_t),
        "expected Extension rerequest after disconnect, got {rerequest_types:?}"
    );
    assert!(
        !rerequest_types.contains(&ModifierTypeId::Header.as_byte()),
        "Header type leaked through disconnect re-request path, got {rerequest_types:?}"
    );
}

#[test]
fn s0_check_timeouts_preserves_section_type_on_rerequest() {
    // Regression guard: when both a BlockTransactions AND an Extension
    // section time out on the same peer, each re-request to the fallback
    // peer must carry its ORIGINAL type_id — not the Header fallback in
    // rerequest_modifiers' `.unwrap_or(ModifierTypeId::Header)`.
    let mut coord = SyncCoordinator::new(100);
    let p1 = peer(9030);
    let p2 = peer(9031);
    let t0 = Instant::now();

    let exp = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // on_header_validated pre-requests both section types from p1, so
    // both become in-flight and both will time out.
    coord.on_header_validated(p1, mk(1), 101, recent_ts, exp, t0);

    let later = t0 + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = coord.check_timeouts(later, &[p2]);

    // Both rerequests must be present, each with its original type.
    let rerequest_types: Vec<u8> = actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer {
                peer: dst,
                code,
                payload,
            } if *dst == p2 && *code == message::CODE_REQUEST_MODIFIER => Some(payload[0]),
            _ => None,
        })
        .collect();

    let tx_t = ModifierTypeId::BlockTransactions.as_byte();
    let ext_t = ModifierTypeId::Extension.as_byte();
    assert!(
        rerequest_types.contains(&tx_t),
        "expected a BlockTransactions rerequest, got types {rerequest_types:?}"
    );
    assert!(
        rerequest_types.contains(&ext_t),
        "expected an Extension rerequest, got types {rerequest_types:?}"
    );
    // No Header fallback leaked through assembly.identify_section.
    assert!(!rerequest_types.contains(&ModifierTypeId::Header.as_byte()),
            "Header type leaked through the rerequest path (identify_section fallback), got {rerequest_types:?}");
}

// ---- request_missing_sections_bucketed characterization ----

/// Distinct [u8;32] ID per `seed` for test bookkeeping. Unlike `mk()`
/// which repeats a single byte, this scales to n up to u32::MAX.
fn mk32(seed: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&seed.to_be_bytes());
    id
}

fn setup_n_pending_blocks(n: u32) -> (SyncCoordinator, MockChain) {
    setup_n_pending_blocks_with_window(n, ergo_p2p::sync::DOWNLOAD_WINDOW)
}

fn setup_n_pending_blocks_with_window(n: u32, window: usize) -> (SyncCoordinator, MockChain) {
    let mut coord = SyncCoordinator::new_with_window(100, window);
    let chain = MockChain::new(100 + n, 100);
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    coord.sync_state_mut().check_headers_synced(recent_ts);
    for i in 0..n {
        let height = 101 + i;
        let header_id = mk32(1 + i);
        let exp = ExpectedSections::from_header(
            &header_id,
            &mk32(10_000 + i),
            &mk32(20_000 + i),
            &mk32(30_000 + i),
        );
        coord.sync_state_mut().set_best_known_header(height);
        coord.sync_state_mut().add_pending_block(height, header_id);
        coord.assembly_mut().register_header(exp);
    }
    (coord, chain)
}

/// Like `setup_n_pending_blocks_with_window` but lets the caller pick the
/// suppression mode and registers pending blocks DIRECTLY (bypassing
/// `on_header_validated`'s own guard) so the defense-in-depth guards on the
/// request path are exercised even when a block "somehow" got registered.
fn setup_pending_with_mode(
    n: u32,
    headers_only: bool,
    bootstrap: bool,
) -> (SyncCoordinator, MockChain) {
    let mut coord = SyncCoordinator::new_with_window_and_mode(100, 384, headers_only);
    coord.set_bootstrap_in_progress(bootstrap);
    let chain = MockChain::new(100 + n, 100);
    let recent_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    coord.sync_state_mut().check_headers_synced(recent_ts);
    for i in 0..n {
        let height = 101 + i;
        let header_id = mk32(1 + i);
        let exp = ExpectedSections::from_header(
            &header_id,
            &mk32(10_000 + i),
            &mk32(20_000 + i),
            &mk32(30_000 + i),
        );
        coord.sync_state_mut().set_best_known_header(height);
        coord.sync_state_mut().add_pending_block(height, header_id);
        coord.assembly_mut().register_header(exp);
    }
    (coord, chain)
}

#[test]
fn request_missing_sections_bucketed_suppressed_in_headers_only() {
    // Mode 6 (headers-only) must request no block sections, even if pending
    // blocks were registered and the headers-synced latch is set.
    let (mut coord, chain) = setup_pending_with_mode(3, true, false);
    let peers = [peer(9030), peer(9031)];
    let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
    assert!(
        actions.is_empty(),
        "headers-only must not request block sections, got {actions:?}"
    );
}

#[test]
fn request_missing_sections_bucketed_suppressed_during_bootstrap() {
    // Mode 2 (mid-bootstrap) suppresses section download until install completes.
    let (mut coord, chain) = setup_pending_with_mode(3, false, true);
    let peers = [peer(9030), peer(9031)];
    let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
    assert!(
        actions.is_empty(),
        "mid-bootstrap must not request block sections, got {actions:?}"
    );
}

#[test]
fn request_missing_sections_closure_suppressed_in_headers_only() {
    let (mut coord, chain) = setup_pending_with_mode(3, true, false);
    let actions = coord.request_missing_sections(&chain, Instant::now(), |_t| Some(peer(9030)));
    assert!(
        actions.is_empty(),
        "headers-only must not request block sections (closure variant), got {actions:?}"
    );
}

#[test]
fn request_missing_sections_bucketed_emits_when_not_suppressed() {
    // Contrast: the identical pending blocks DO produce requests in normal
    // mode, proving the empties above come from the suppression guard.
    let (mut coord, chain) = setup_pending_with_mode(3, false, false);
    let peers = [peer(9030), peer(9031)];
    let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
    assert!(
        !actions.is_empty(),
        "normal mode must request sections for pending blocks"
    );
}

#[test]
fn s1_bucketed_empty_peers_emits_no_actions() {
    let (mut coord, chain) = setup_n_pending_blocks(5);
    let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &[]);
    assert!(
        actions.is_empty(),
        "empty peers → no sends, got {}",
        actions.len()
    );
}

#[test]
fn s1_bucketed_empty_pending_emits_no_actions() {
    let mut coord = SyncCoordinator::new(100);
    let chain = MockChain::new(100, 100);
    let peers = [peer(9030), peer(9031)];
    let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
    assert!(
        actions.is_empty(),
        "no pending → no sends, got {}",
        actions.len()
    );
}

#[test]
fn s1_bucketed_three_peers_exact_shape() {
    // 30 pending blocks → 30 tx + 30 ext = 60 section IDs.
    // 3 peers × max 12 per type-bucket = 36/type capacity. Per
    // Scala partition: one bucket per peer until pending drains.
    // 30 tx → buckets 12/12/6 = 3 tx sends.
    // 30 ext → buckets 12/12/6 = 3 ext sends.
    // Total 6 RequestModifier actions.
    let (mut coord, chain) = setup_n_pending_blocks(30);
    let peers = vec![peer(9030), peer(9031), peer(9032)];

    let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);

    let decoded: Vec<(PeerId, u8, usize)> = actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer {
                peer,
                code,
                payload,
            } if *code == message::CODE_REQUEST_MODIFIER => {
                let inv = message::deserialize_inv(payload).ok()?;
                Some((*peer, inv.type_id, inv.ids.len()))
            }
            _ => None,
        })
        .collect();

    assert_eq!(
        decoded.len(),
        6,
        "expected 6 (peer,type) sends, got {decoded:?}"
    );

    // tx globally before ext.
    let tx_t = ModifierTypeId::BlockTransactions.as_byte();
    let ext_t = ModifierTypeId::Extension.as_byte();
    let first_ext = decoded.iter().position(|(_, t, _)| *t == ext_t).unwrap();
    assert!(
        decoded[..first_ext].iter().all(|(_, t, _)| *t == tx_t),
        "tx buckets must precede ext buckets, got {decoded:?}"
    );

    // Sizes 12/12/6 per type.
    let tx_sizes: Vec<usize> = decoded
        .iter()
        .filter(|(_, t, _)| *t == tx_t)
        .map(|(_, _, n)| *n)
        .collect();
    assert_eq!(tx_sizes, vec![12, 12, 6]);

    // Ownership: every modifier appears in exactly one bucket.
    let mut seen = std::collections::HashSet::new();
    for a in &actions {
        if let Action::SendToPeer { code, payload, .. } = a {
            if *code == message::CODE_REQUEST_MODIFIER {
                let inv = message::deserialize_inv(payload).unwrap();
                for id in inv.ids {
                    assert!(seen.insert(id), "duplicate modifier_id across peer buckets");
                }
            }
        }
    }
}

#[test]
fn s1_bucketed_rotation_cursor_advances() {
    // Same coord, same peer list, clear delivery between calls.
    // First peer in the emitted actions should cycle.
    let peers = vec![peer(9030), peer(9031), peer(9032)];
    let expected_first_peers = [peers[0], peers[1], peers[2]];
    let (mut coord, chain) = setup_n_pending_blocks(1);

    let mut observed = Vec::new();
    for _ in 0..3 {
        // Reset delivery for each pending-block's sections between
        // calls — bypasses the Requested-status gate so the same
        // demand can be re-partitioned and we observe rotation.
        let pending: Vec<[u8; 32]> = coord
            .sync_state()
            .blocks_to_download()
            .iter()
            .map(|pb| pb.header_id)
            .collect();
        let ids: Vec<_> = pending
            .iter()
            .flat_map(|hid| {
                coord
                    .assembly
                    .expected_section_ids(hid)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(_, id)| id)
            })
            .collect();
        for id in &ids {
            coord.delivery.test_reset_status(id);
        }

        let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
        let first = actions
            .iter()
            .find_map(|a| match a {
                Action::SendToPeer { peer, code, .. }
                    if *code == message::CODE_REQUEST_MODIFIER =>
                {
                    Some(*peer)
                }
                _ => None,
            })
            .expect("expected at least one request per call");
        observed.push(first);
    }

    assert_eq!(observed, expected_first_peers.to_vec(),
            "rotation cursor must cycle through peer list: expected {expected_first_peers:?}, got {observed:?}");
}

#[test]
fn s1_bucketed_idempotent_second_call_empty() {
    let (mut coord, chain) = setup_n_pending_blocks(10);
    let peers = vec![peer(9030), peer(9031)];
    let first = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
    let second = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
    let fc = first.iter().filter(|a|
            matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER)
        ).count();
    let sc = second.iter().filter(|a|
            matches!(a, Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER)
        ).count();
    assert!(fc > 0);
    assert_eq!(sc, 0, "second call must not re-request, got {sc} sends");
}

#[test]
fn s1_bucketed_capacity_truncation_only_registered_ids_on_wire() {
    // Invariant: when delivery.request rejects some bucket IDs
    // (peer at capacity), the emitted payload contains only the
    // registered IDs — not the full intended bucket.
    let (mut coord, chain) = setup_n_pending_blocks(5);
    let peers = vec![peer(9030)];
    let p = peers[0];
    let now = Instant::now();
    let cap = ergo_p2p::delivery::MAX_IN_FLIGHT_PER_PEER;

    // Pre-fill the peer's in-flight to cap-2; leaves 2 slots.
    let filler: Vec<[u8; 32]> = (0..(cap - 2) as u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    let filled = coord
        .delivery
        .request(p, ModifierTypeId::Header.as_byte(), &filler, now);
    assert_eq!(filled.len(), cap - 2);

    let actions = coord.request_missing_sections_bucketed(&chain, now, &peers);
    let total_ids_sent: usize = actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { code, payload, .. } if *code == message::CODE_REQUEST_MODIFIER => {
                message::deserialize_inv(payload)
                    .ok()
                    .map(|inv| inv.ids.len())
            }
            _ => None,
        })
        .sum();

    assert!(
        total_ids_sent <= 2,
        "capacity truncation must cap wire IDs at remaining slots (2), got {total_ids_sent}"
    );
}

#[test]
fn s1_bucketed_single_peer_uses_adaptive_large_bucket() {
    // Regression guard: a hard-cap of 12 per bucket starves 1-peer
    // sync. Adaptive config should give a single peer up to
    // ~400 IDs per call.
    //
    // Use a 192-block window here to exercise the "full window fits
    // in one call" case: 192 × 2 = 384 ≤ 400 (MAX_IN_FLIGHT_PER_PEER).
    let (mut coord, chain) = setup_n_pending_blocks_with_window(192, 192);
    let peers = vec![peer(9030)];
    let actions = coord.request_missing_sections_bucketed(&chain, Instant::now(), &peers);
    let total_ids_sent: usize = actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { code, payload, .. } if *code == message::CODE_REQUEST_MODIFIER => {
                message::deserialize_inv(payload)
                    .ok()
                    .map(|inv| inv.ids.len())
            }
            _ => None,
        })
        .sum();
    assert!(total_ids_sent >= 384,
            "single-peer IBD must enqueue full 192-block window in one call (adaptive cap): got {total_ids_sent} / 384 expected");
}

#[test]
fn s3_bucketed_window_demand_exceeding_cap_balances_50_50() {
    // Pin step 2.5's per-type balancing: when demand exceeds the
    // peer's free in-flight slots, the free budget is split
    // div_ceil(slots/types) per type instead of letting tx claim
    // everything and starving ext. With the default 384-block
    // window, demand per type is 384 (so total demand 768). To
    // force balancing we pre-fill the peer until free slots drop
    // below 768 — leaving 600 free here forces a 300/300 split via
    // div_ceil(600/2). Without balancing tx would take all 600.
    let cap = ergo_p2p::delivery::MAX_IN_FLIGHT_PER_PEER;
    let target_free = 600usize;
    assert!(cap >= target_free, "cap must accommodate target_free");

    let (mut coord, chain) =
        setup_n_pending_blocks_with_window(384, ergo_p2p::sync::DOWNLOAD_WINDOW);
    let peers = vec![peer(9030)];
    let now = Instant::now();
    fill_inflight(&mut coord, peers[0], (cap - target_free) as u16, now);
    assert_eq!(coord.delivery.available_slots(&peers[0]), target_free);

    let actions = coord.request_missing_sections_bucketed(&chain, now, &peers);
    let (tx_sent, ext_sent) = count_by_type(&actions);

    let expected_per_type = target_free.div_ceil(2);
    assert_eq!(
        tx_sent, expected_per_type,
        "tx coverage should be div_ceil(slots/2): tx={tx_sent} ext={ext_sent}"
    );
    assert_eq!(
        ext_sent, expected_per_type,
        "ext coverage should be div_ceil(slots/2): tx={tx_sent} ext={ext_sent}"
    );
    assert!(
        tx_sent + ext_sent <= target_free,
        "one round must not exceed peer's free slots: got {}",
        tx_sent + ext_sent
    );
}

/// Helper: pre-fill `peer`'s in-flight delivery to `n` synthetic
/// header-type IDs so its `available_slots` becomes `400 - n`.
fn fill_inflight(coord: &mut SyncCoordinator, peer: PeerId, n: u16, now: Instant) {
    let filler: Vec<[u8; 32]> = (0..n)
        .map(|i| {
            let mut id = [0xEEu8; 32];
            id[..2].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    let filled = coord
        .delivery
        .request(peer, ModifierTypeId::Header.as_byte(), &filler, now);
    assert_eq!(filled.len() as u16, n);
}

fn count_by_type(actions: &[Action]) -> (usize, usize) {
    let tx_code = ModifierTypeId::BlockTransactions.as_byte();
    let ext_code = ModifierTypeId::Extension.as_byte();
    let mut tx = 0usize;
    let mut ext = 0usize;
    for a in actions {
        if let Action::SendToPeer { code, payload, .. } = a {
            if *code == message::CODE_REQUEST_MODIFIER {
                if let Ok(inv) = message::deserialize_inv(payload) {
                    if inv.type_id == tx_code {
                        tx += inv.ids.len();
                    } else if inv.type_id == ext_code {
                        ext += inv.ids.len();
                    }
                }
            }
        }
    }
    (tx, ext)
}

#[test]
fn hol_hedge_preserves_section_type_when_same_peer_gets_both_sections() {
    let (mut coord, _chain) = setup_n_pending_blocks_with_window(1, 1);
    let p_old = peer(9030);
    let p_new = peer(9031);
    let t0 = Instant::now();
    let header_id = mk32(1);
    let sections = coord
        .assembly
        .expected_section_ids(&header_id)
        .expect("registered sections");

    for (type_id, section_id) in sections {
        let registered = coord.delivery.request(p_old, type_id, &[section_id], t0);
        assert_eq!(registered, vec![section_id]);
    }

    let actions = coord.check_hol_hedges(
        100,
        Duration::from_secs(8),
        t0 + Duration::from_secs(9),
        &[p_new],
    );
    let (tx_sent, ext_sent) = count_by_type(&actions);

    assert_eq!(
        tx_sent, 1,
        "HOL tx section must be sent under BlockTransactions type"
    );
    assert_eq!(
        ext_sent, 1,
        "HOL extension section must be sent under Extension type"
    );
}

#[test]
fn hol_repair_revives_failed_head_section() {
    let (mut coord, _chain) = setup_n_pending_blocks_with_window(1, 1);
    let p_old = peer(9030);
    let p_new = peer(9031);
    let t0 = Instant::now();
    let header_id = mk32(1);
    let tx_type = ModifierTypeId::BlockTransactions.as_byte();
    let tx_section = coord
        .assembly
        .expected_section_ids(&header_id)
        .expect("registered sections")
        .into_iter()
        .find_map(|(type_id, id)| (type_id == tx_type).then_some(id))
        .expect("tx section");

    for attempt in 0..ergo_p2p::delivery::MAX_RETRIES {
        let requested_at = t0 + Duration::from_secs(u64::from(attempt) * 100);
        assert_eq!(
            coord
                .delivery
                .request(p_old, tx_type, &[tx_section], requested_at),
            vec![tx_section]
        );
        let result = coord.delivery.check_timeouts(
            requested_at + ergo_p2p::delivery::DELIVERY_TIMEOUT + Duration::from_secs(1),
        );
        if attempt + 1 < ergo_p2p::delivery::MAX_RETRIES {
            assert!(!result.retryable.is_empty());
        } else {
            assert_eq!(result.exhausted, vec![tx_section]);
        }
    }
    // 2Q Scala-parity: post-exhaustion status is Unknown, not Failed.
    // Sections that fully time out are eligible for fresh re-request
    // via the normal `request_missing_sections_bucketed` path on the
    // next sync_tick. HOL hedge is for IN-FLIGHT sections only — it
    // doesn't apply to fully-exhausted Unknown sections (those are
    // handled by the main request loop). This is identical to Scala:
    // ErgoNodeViewSynchronizer.scala:1287 sets setUnknown for
    // exhausted sections and leaves re-request to CheckModifiersToDownload.
    assert_eq!(coord.delivery.status(&tx_section), ModifierStatus::Unknown);

    // Verify re-request goes through cleanly (delivery accepts it
    // without needing the request_allow_failed escape hatch).
    let registered =
        coord
            .delivery
            .request(p_new, tx_type, &[tx_section], t0 + Duration::from_secs(300));
    assert_eq!(
        registered,
        vec![tx_section],
        "exhausted section must be re-requestable in normal delivery path (Scala parity)",
    );
    assert_eq!(
        coord.delivery.status(&tx_section),
        ModifierStatus::Requested,
    );
}

#[test]
fn hol_hedge_covers_non_head_of_line_in_window_block() {
    // A stuck section several blocks deep (not best+1) must still be hedged —
    // it gates assembly once the tip catches up. Previously only the
    // head-of-line block was repaired.
    let (mut coord, _chain) = setup_n_pending_blocks_with_window(3, 3);
    let p_old = peer(9030);
    let p_new = peer(9031);
    let t0 = Instant::now();

    // Request only the THIRD pending block's sections (height 103; the
    // head-of-line is 101) from p_old, then let them go stuck.
    let deep_header = mk32(3);
    let sections = coord
        .assembly
        .expected_section_ids(&deep_header)
        .expect("registered sections");
    for (type_id, section_id) in &sections {
        coord.delivery.request(p_old, *type_id, &[*section_id], t0);
    }

    let actions = coord.check_hol_hedges(
        100,
        Duration::from_secs(2),
        t0 + Duration::from_secs(3),
        &[p_new],
    );
    let (tx_sent, ext_sent) = count_by_type(&actions);
    assert!(
        tx_sent >= 1 && ext_sent >= 1,
        "a non-head-of-line in-window block's stuck sections must be hedged, got tx={tx_sent} ext={ext_sent}"
    );
}

#[test]
fn hol_hedge_spreads_reassigns_across_capable_peers() {
    // When one peer holds multiple stuck sections, reassigns spread across
    // capable peers (least-in-flight) instead of piling onto the first.
    let (mut coord, _chain) = setup_n_pending_blocks_with_window(1, 1);
    let p_old = peer(9030);
    let p_a = peer(9031);
    let p_b = peer(9032);
    let t0 = Instant::now();

    let sections = coord
        .assembly
        .expected_section_ids(&mk32(1))
        .expect("registered sections");
    for (type_id, section_id) in &sections {
        coord.delivery.request(p_old, *type_id, &[*section_id], t0);
    }

    let actions = coord.check_hol_hedges(
        100,
        Duration::from_secs(2),
        t0 + Duration::from_secs(3),
        &[p_a, p_b],
    );
    let targets: std::collections::HashSet<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { peer, .. } => Some(*peer),
            _ => None,
        })
        .collect();
    assert_eq!(
        targets.len(),
        2,
        "the two hedged sections must land on two distinct capable peers, got {targets:?}"
    );
}

#[test]
fn hol_hedge_win_does_not_failure_mark_the_slow_peer() {
    // Key interaction with #133/#134: when a hedge peer wins the race, the
    // slow original owner must NOT be penalized or body-streak-incremented.
    // `reassign` removes the old peer's inflight entry (keeping it merely
    // late-acceptable), so it never times out and never produces a failure
    // outcome.
    let (mut coord, _chain) = setup_n_pending_blocks_with_window(1, 1);
    let p_slow = peer(9030);
    let p_fast = peer(9031);
    let t0 = Instant::now();

    let tx_type = ModifierTypeId::BlockTransactions.as_byte();
    let tx_section = coord
        .assembly
        .expected_section_ids(&mk32(1))
        .expect("registered sections")
        .into_iter()
        .find_map(|(t, id)| (t == tx_type).then_some(id))
        .expect("tx section");
    coord.delivery.request(p_slow, tx_type, &[tx_section], t0);

    // HOL hedge reassigns the stuck section to p_fast (p_slow stays
    // late-acceptable, not timed out).
    let _ = coord.check_hol_hedges(
        100,
        Duration::from_secs(2),
        t0 + Duration::from_secs(3),
        &[p_fast],
    );

    // p_fast wins the race: credited with a success outcome.
    let win = coord.on_modifier_received(p_fast, tx_type, tx_section, vec![1]);
    assert!(
        win.iter().any(|a| matches!(
            a,
            Action::NoteDeliveryOutcome { peer, succeeded: true } if *peer == p_fast
        )),
        "the winning hedge peer must be credited with a success outcome"
    );

    // A later timeout sweep must neither penalize nor failure-mark the slow
    // peer — it only lost the race.
    let sweep = coord.check_timeouts(t0 + Duration::from_secs(20), &[p_fast]);
    assert!(
        !sweep.iter().any(|a| matches!(
            a,
            Action::Penalize {
                peer,
                penalty: Penalty::NonDelivery,
            } if *peer == p_slow
        )),
        "no NonDelivery penalty after a hedge win — the slow peer only lost the race"
    );
    assert!(
        !sweep.iter().any(|a| matches!(
            a,
            Action::NoteDeliveryOutcome {
                succeeded: false,
                ..
            }
        )),
        "no failure outcome after a hedge win — the slow peer must not be penalized"
    );
}

#[test]
fn s3_bucketed_partial_capacity_two_free_slots() {
    // 2 free slots across two types → 1 tx + 1 ext via div_ceil(2/2).
    let cap = ergo_p2p::delivery::MAX_IN_FLIGHT_PER_PEER;
    let (mut coord, chain) =
        setup_n_pending_blocks_with_window(384, ergo_p2p::sync::DOWNLOAD_WINDOW);
    let peers = vec![peer(9030)];
    let now = Instant::now();
    fill_inflight(&mut coord, peers[0], (cap - 2) as u16, now);
    assert_eq!(coord.delivery.available_slots(&peers[0]), 2);

    let actions = coord.request_missing_sections_bucketed(&chain, now, &peers);
    let (tx_sent, ext_sent) = count_by_type(&actions);
    assert_eq!(
        tx_sent, 1,
        "2 free slots should yield tx=1 (div_ceil): tx={tx_sent} ext={ext_sent}"
    );
    assert_eq!(
        ext_sent, 1,
        "2 free slots should yield ext=1: tx={tx_sent} ext={ext_sent}"
    );
}

#[test]
fn s3_bucketed_single_free_slot_still_emits_request() {
    // Regression guard: 1 free slot with old `floor` division gave
    // 0 requests. `div_ceil` ensures a single-slot budget still
    // drives at least one registered request (tx wins by BTreeMap
    // order).
    let cap = ergo_p2p::delivery::MAX_IN_FLIGHT_PER_PEER;
    let (mut coord, chain) =
        setup_n_pending_blocks_with_window(384, ergo_p2p::sync::DOWNLOAD_WINDOW);
    let peers = vec![peer(9030)];
    let now = Instant::now();
    fill_inflight(&mut coord, peers[0], (cap - 1) as u16, now);
    assert_eq!(coord.delivery.available_slots(&peers[0]), 1);

    let actions = coord.request_missing_sections_bucketed(&chain, now, &peers);
    let (tx_sent, ext_sent) = count_by_type(&actions);
    assert_eq!(
        tx_sent + ext_sent,
        1,
        "1 free slot must register exactly one request: tx={tx_sent} ext={ext_sent}"
    );
}

#[test]
fn s3_bucketed_one_sided_demand_uses_full_budget() {
    // When only one section type has demand, balancing must not
    // halve the peer's capacity — give the full budget to the
    // present type so round 1 doesn't leave half the slots idle.
    let (mut coord, chain) =
        setup_n_pending_blocks_with_window(384, ergo_p2p::sync::DOWNLOAD_WINDOW);
    let peers = vec![peer(9030)];
    let now = Instant::now();

    // Mark all BlockTransactions IDs as "have" in the mock chain
    // (so only Extension section demand remains) by computing
    // them and pre-populating the chain. Simpler path: pre-register
    // all tx IDs as received via DeliveryTracker.
    let tx_code = ModifierTypeId::BlockTransactions.as_byte();
    let blocks: Vec<_> = coord
        .sync_state()
        .blocks_to_download()
        .iter()
        .map(|p| p.header_id)
        .collect();
    for hid in &blocks {
        if let Some(sections) = coord.assembly.expected_section_ids(hid) {
            for (tid, sid) in sections {
                if tid == tx_code {
                    // Mark as received so the coordinator skips it
                    // during tx_ids collection.
                    let reg = coord.delivery.request(peers[0], tid, &[sid], now);
                    if !reg.is_empty() {
                        coord.delivery.mark_received(&sid);
                    }
                }
            }
        }
    }
    // Reset peer inflight so capacity is full again.
    for hid in &blocks {
        if let Some(sections) = coord.assembly.expected_section_ids(hid) {
            for (tid, sid) in sections {
                if tid == tx_code {
                    coord.delivery.mark_received(&sid);
                }
            }
        }
    }

    let actions = coord.request_missing_sections_bucketed(&chain, now, &peers);
    let (tx_sent, ext_sent) = count_by_type(&actions);
    // No tx demand → all budget to ext (up to DeliveryTracker cap).
    assert_eq!(
        tx_sent, 0,
        "no tx demand remains: tx={tx_sent} ext={ext_sent}"
    );
    assert!(
        ext_sent >= 380,
        "one-sided demand must use full available budget: ext={ext_sent}"
    );
}

#[test]
fn s1_bucketed_saturated_peer_skipped_not_stranded() {
    // Invariant: a peer with zero in-flight capacity must not
    // receive a bucket. The earliest IDs should go to the next
    // peer with capacity, not get stranded behind a full peer
    // for multiple rounds.
    let (mut coord, chain) = setup_n_pending_blocks(10);
    let peers = vec![peer(9030), peer(9031)];
    let p_full = peers[0];
    let p_free = peers[1];
    let now = Instant::now();
    let cap = ergo_p2p::delivery::MAX_IN_FLIGHT_PER_PEER;

    // Saturate p_full to its in-flight cap.
    let filler: Vec<[u8; 32]> = (0..cap as u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    let filled = coord
        .delivery
        .request(p_full, ModifierTypeId::Header.as_byte(), &filler, now);
    assert_eq!(filled.len(), cap, "pre-fill p_full to capacity");

    let actions = coord.request_missing_sections_bucketed(&chain, now, &peers);

    // Every bucket should go to p_free. p_full gets zero.
    let sends_to_full = actions
        .iter()
        .filter(|a| {
            matches!(a,
            Action::SendToPeer { peer, code, .. }
                if *peer == p_full && *code == message::CODE_REQUEST_MODIFIER)
        })
        .count();
    let sends_to_free = actions
        .iter()
        .filter(|a| {
            matches!(a,
            Action::SendToPeer { peer, code, .. }
                if *peer == p_free && *code == message::CODE_REQUEST_MODIFIER)
        })
        .count();
    assert_eq!(
        sends_to_full, 0,
        "saturated peer must get zero buckets, got {sends_to_full}"
    );
    assert!(
        sends_to_free > 0,
        "free peer must absorb the demand, got {sends_to_free}"
    );
}

#[test]
fn s1_bucketed_vs_old_emit_different_shapes() {
    // Coexistence: old method emits 1 send per type_id to single
    // peer (total ≤2). New bucketed method emits one send per
    // (peer, type) bucket (total > 2 when peers ≥ 2 and demand
    // saturates ≥ 2 peers).
    let peers = vec![peer(9030), peer(9031), peer(9032)];
    let p = peers[0];

    let (mut coord_old, chain_old) = setup_n_pending_blocks(30);
    let old_actions = coord_old.request_missing_sections(&chain_old, Instant::now(), |_t| Some(p));
    let old_sends: Vec<PeerId> = old_actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { peer, code, .. } if *code == message::CODE_REQUEST_MODIFIER => {
                Some(*peer)
            }
            _ => None,
        })
        .collect();

    let (mut coord_new, chain_new) = setup_n_pending_blocks(30);
    let new_actions =
        coord_new.request_missing_sections_bucketed(&chain_new, Instant::now(), &peers);
    let new_sends: Vec<PeerId> = new_actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { peer, code, .. } if *code == message::CODE_REQUEST_MODIFIER => {
                Some(*peer)
            }
            _ => None,
        })
        .collect();

    assert_eq!(
        old_sends.len(),
        2,
        "old method: 1 send per type to single peer, got {}",
        old_sends.len()
    );
    assert!(old_sends.iter().all(|pp| *pp == p));

    assert!(
        new_sends.len() > 2,
        "new method: multiple sends across peers, got {}",
        new_sends.len()
    );
    let unique: std::collections::HashSet<_> = new_sends.iter().collect();
    assert!(
        unique.len() >= 2,
        "new method must spread across peers, got {unique:?}"
    );
}

/// Build a fake header byte stream that hashes to the given id.
/// We don't need a valid Ergo header here — `on_sync_info` only
/// computes blake2b256 of the bytes as the modifier ID for the
/// commonPoint check. Returning the id concatenated with itself
/// gives a stable byte string per id; we store the inverse mapping
/// (`bytes_to_id`) so test assertions can recover.
fn fake_header_bytes(id: [u8; 32]) -> Vec<u8> {
    // Find a 33+ byte input whose blake2b256 equals `id` is hard;
    // instead, we treat the test's "peer header bytes" as opaque
    // and pre-register the (computed_id → height) mapping below.
    // The bytes themselves are anything — we'll compute blake2b256
    // and use that as the synthetic peer-header ID, then teach the
    // MockChain that id lives at the chosen height.
    id.to_vec()
}

fn id_for_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake2b256(bytes).as_bytes()
}

#[test]
fn on_sync_info_v2_younger_emits_inv_with_continuation_ids() {
    // Setup: peer's tip is on our best chain at height 100, our tip
    // is at height 105. We expect Inv(Header) with ids for heights
    // 101..=105 (5 entries) sent to the peer.
    let mut chain = MockChain::new(105, 100);
    let our_tip_id = [42u8; 32];
    chain.best_header_id = our_tip_id;
    // Set up our chain at heights 100..=105
    let mut our_ids = Vec::new();
    for h in 100u32..=105 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&h.to_be_bytes());
        id[4] = b'O'; // mark as ours
        chain.add_best_chain_header(h, id);
        our_ids.push(id);
    }
    chain.best_header_id = our_ids[5]; // h=105 is our tip
                                       // Mark h=105 as on best chain (already done by add_best_chain_header)

    // Peer sends V2 SyncInfo with their last header at h=100 on our
    // best chain. Since blake is one-way, register a synthetic bytes
    // blob's real id at that height and send those bytes.
    let peer_bytes = fake_header_bytes([0xABu8; 32]);
    let synthetic_top_id = id_for_bytes(&peer_bytes);
    // Re-add the synthetic id at h=100 and remove the one we put there
    chain.height_to_id.insert(100, synthetic_top_id);
    chain.id_to_height.insert(synthetic_top_id, 100);
    chain.best_chain_ids.insert(synthetic_top_id);
    chain.known_headers.insert(synthetic_top_id);
    // Now is_on_best_chain(synthetic_top_id) is true and lives at h=100.

    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);
    let actions = coord.on_sync_info(
        p,
        SyncVersion::V2,
        &SyncInfo::V2 {
            headers: vec![peer_bytes],
        },
        &chain,
        Instant::now(),
    );

    // Expect at least one SendToPeer with code=CODE_INV containing
    // header IDs for heights 101..=105.
    let inv_action = actions
        .iter()
        .find(|a| {
            matches!(a,
                Action::SendToPeer { code, .. } if *code == message::CODE_INV
            )
        })
        .expect("expected CODE_INV action for Younger peer");
    let payload = match inv_action {
        Action::SendToPeer { payload, .. } => payload,
        _ => unreachable!(),
    };
    let inv = ergo_p2p::message::deserialize_inv(payload).unwrap();
    assert_eq!(
        inv.type_id,
        ergo_p2p::types::ModifierTypeId::Header.as_byte()
    );
    // 5 IDs: heights 101, 102, 103, 104, 105
    assert_eq!(
        inv.ids.len(),
        5,
        "expected 5 continuation IDs (h=101..=105), got {}",
        inv.ids.len()
    );
    for (i, id) in inv.ids.iter().enumerate() {
        let expected_h = 101 + i as u32;
        assert_eq!(
            *id,
            our_ids[(expected_h - 100) as usize],
            "id at index {i} (h={expected_h}) doesn't match our chain"
        );
    }
}

#[test]
fn on_sync_info_v2_equal_no_inv() {
    // Peer's tip == our tip → Equal, no Inv emitted.
    let mut chain = MockChain::new(100, 100);
    let peer_bytes = fake_header_bytes([0x77u8; 32]);
    let our_tip_id = id_for_bytes(&peer_bytes);
    chain.best_header_id = our_tip_id;
    chain.add_best_chain_header(100, our_tip_id);

    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);
    let actions = coord.on_sync_info(
        p,
        SyncVersion::V2,
        &SyncInfo::V2 {
            headers: vec![peer_bytes],
        },
        &chain,
        Instant::now(),
    );

    let inv_count = actions
        .iter()
        .filter(|a| {
            matches!(a,
                Action::SendToPeer { code, .. } if *code == message::CODE_INV
            )
        })
        .count();
    assert_eq!(inv_count, 0, "Equal peer must not get an Inv extension");
}

// ----- caught-up-to-peers headers-synced fallback -----

/// A MockChain whose tip == the returned peer bytes' id, so a peer echoing
/// those bytes classifies as `Equal` (header-id match).
fn equal_tip_chain() -> (MockChain, Vec<u8>) {
    let mut chain = MockChain::new(100, 100);
    let peer_bytes = fake_header_bytes([0x77u8; 32]);
    let our_tip_id = id_for_bytes(&peer_bytes);
    chain.best_header_id = our_tip_id;
    chain.add_best_chain_header(100, our_tip_id);
    (chain, peer_bytes)
}

fn note_equal_peer(
    coord: &mut SyncCoordinator,
    chain: &MockChain,
    bytes: &[u8],
    port: u16,
    now: Instant,
) {
    coord.on_sync_info(
        peer(port),
        SyncVersion::V2,
        &SyncInfo::V2 {
            headers: vec![bytes.to_vec()],
        },
        chain,
        now,
    );
}

#[test]
fn caught_up_fallback_flips_latch_with_multiple_equal_and_no_older() {
    let (chain, peer_bytes) = equal_tip_chain();
    let mut coord = SyncCoordinator::new(0);
    let t0 = Instant::now();
    assert!(!coord.sync_state().headers_chain_synced());

    note_equal_peer(&mut coord, &chain, &peer_bytes, 9030, t0);
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9031, t0);
    assert!(
        !coord.sync_state().headers_chain_synced(),
        "on_sync_info must not flip the latch on its own"
    );

    assert!(
        coord.try_mark_caught_up_to_peers(t0, chain.best_header_id),
        "two fresh Equal peers and no Older must flip the latch"
    );
    assert!(coord.sync_state().headers_chain_synced());
    assert!(
        !coord.try_mark_caught_up_to_peers(t0, chain.best_header_id),
        "already-synced must be a no-op (returns false)"
    );
}

#[test]
fn caught_up_fallback_discounts_equal_against_a_superseded_tip() {
    // Equal is relative to the tip it was observed against. If our tip
    // advances/reorgs, those (still time-fresh) Equal snapshots must not be
    // counted as confirming the NEW tip.
    let (chain, peer_bytes) = equal_tip_chain();
    let mut coord = SyncCoordinator::new(0);
    let t0 = Instant::now();
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9030, t0);
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9031, t0);

    // Our tip is now a different header than the one those peers confirmed.
    let new_tip = [0xEEu8; 32];
    assert_ne!(new_tip, chain.best_header_id);
    assert!(
        !coord.try_mark_caught_up_to_peers(t0, new_tip),
        "Equal observed against the old tip must not confirm a superseded tip"
    );
    // Against the tip they actually observed, they still count.
    assert!(coord.try_mark_caught_up_to_peers(t0, chain.best_header_id));
}

#[test]
fn caught_up_fallback_requires_multiple_equal_peers() {
    let (chain, peer_bytes) = equal_tip_chain();
    let mut coord = SyncCoordinator::new(0);
    let t0 = Instant::now();
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9030, t0);
    assert!(
        !coord.try_mark_caught_up_to_peers(t0, chain.best_header_id),
        "a single Equal peer must not flip the latch (one stale/lying peer guard)"
    );
}

#[test]
fn caught_up_fallback_tolerates_a_single_noisy_older_peer() {
    // The DoS guard: a single peer sending non-overlapping/garbage V2 SyncInfo
    // is classified Older, but two honest Equal peers outnumber it, so the
    // fallback still flips (the stall isn't held hostage by one noisy peer).
    let (chain, peer_bytes) = equal_tip_chain();
    let mut coord = SyncCoordinator::new(0);
    let t0 = Instant::now();
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9030, t0);
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9031, t0);
    // No-overlap header → on_sync_info's Older default.
    let older_bytes = fake_header_bytes([0x99u8; 32]);
    note_equal_peer(&mut coord, &chain, &older_bytes, 9032, t0);
    assert!(
        coord.try_mark_caught_up_to_peers(t0, chain.best_header_id),
        "two Equal peers must outvote one noisy Older peer and flip the latch"
    );
}

#[test]
fn caught_up_fallback_blocked_when_older_peers_outnumber_equal() {
    // A genuine majority ahead of us (real mid-IBD) must still defer the flip.
    let (chain, peer_bytes) = equal_tip_chain();
    let mut coord = SyncCoordinator::new(0);
    let t0 = Instant::now();
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9030, t0);
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9031, t0);
    // Three peers ahead of us (Older) > two Equal.
    for (i, port) in [9032u16, 9033, 9034].iter().enumerate() {
        let older_bytes = fake_header_bytes([0x90u8 + i as u8; 32]);
        note_equal_peer(&mut coord, &chain, &older_bytes, *port, t0);
    }
    assert!(
        !coord.try_mark_caught_up_to_peers(t0, chain.best_header_id),
        "an Older majority (we're genuinely behind) must defer the flip"
    );
}

/// A chain with our tip at height 105 plus a lower header at 100 on our best
/// chain. A peer echoing the height-105 bytes reads `Equal`; one echoing the
/// height-100 bytes reads `Younger` (overlaps our chain, newest != our tip).
fn tip_chain_with_lower_overlap() -> (MockChain, Vec<u8>, Vec<u8>) {
    let mut chain = MockChain::new(105, 105);
    let equal_bytes = fake_header_bytes([0x55u8; 32]);
    let tip_id = id_for_bytes(&equal_bytes);
    chain.best_header_id = tip_id;
    chain.add_best_chain_header(105, tip_id);
    let younger_bytes = fake_header_bytes([0x44u8; 32]);
    let younger_id = id_for_bytes(&younger_bytes);
    chain.add_best_chain_header(100, younger_id);
    (chain, equal_bytes, younger_bytes)
}

#[test]
fn caught_up_fallback_blocked_when_younger_peers_are_a_majority() {
    // A peer slightly ahead with an overlapping `[H+1, H, ...]` SyncInfo
    // classifies as Younger, NOT Older. The majority test must count every
    // non-Equal fresh peer, so two Equal peers must not outvote three
    // Younger ones.
    let (chain, equal_bytes, younger_bytes) = tip_chain_with_lower_overlap();
    let mut coord = SyncCoordinator::new(0);
    let t0 = Instant::now();
    note_equal_peer(&mut coord, &chain, &equal_bytes, 9030, t0);
    note_equal_peer(&mut coord, &chain, &equal_bytes, 9031, t0);
    for port in [9032u16, 9033, 9034] {
        note_equal_peer(&mut coord, &chain, &younger_bytes, port, t0);
    }
    assert!(
        !coord.try_mark_caught_up_to_peers(t0, chain.best_header_id),
        "Equal must be a strict majority of ALL fresh peers (Younger peers count)"
    );
}

#[test]
fn caught_up_fallback_suppressed_in_headers_only_mode() {
    // Mode 6 (headers-only) must never start block-section download, even
    // when fully caught up — the fallback must not open the latch there.
    let (chain, peer_bytes) = equal_tip_chain();
    let mut coord = SyncCoordinator::new_with_window_and_mode(0, 100, true);
    let t0 = Instant::now();
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9030, t0);
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9031, t0);
    assert!(
        !coord.try_mark_caught_up_to_peers(t0, chain.best_header_id),
        "headers-only mode must not flip the latch via the caught-up fallback"
    );
    assert!(!coord.sync_state().headers_chain_synced());
}

#[test]
fn caught_up_fallback_ignores_stale_observations() {
    let (chain, peer_bytes) = equal_tip_chain();
    let mut coord = SyncCoordinator::new(0);
    let t0 = Instant::now();
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9030, t0);
    note_equal_peer(&mut coord, &chain, &peer_bytes, 9031, t0);
    // Past the freshness window, those Equal observations no longer count.
    let later = t0 + Duration::from_secs(31);
    assert!(
        !coord.try_mark_caught_up_to_peers(later, chain.best_header_id),
        "stale Equal observations must not flip the latch"
    );
}

#[test]
fn on_sync_info_v2_unknown_peer_falls_through_to_older_path() {
    // Peer's headers are NOT on our chain (Fork or Unknown). We
    // shouldn't emit Inv extension; the existing reciprocal-SyncInfo
    // dance handles catchup.
    let mut chain = MockChain::new(100, 100);
    chain.best_header_id = [42u8; 32];
    chain.add_best_chain_header(100, [42u8; 32]);

    let unknown_bytes = fake_header_bytes([0xFFu8; 32]);
    // Note: id_for_bytes(&unknown_bytes) is NOT on our chain.

    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);
    let actions = coord.on_sync_info(
        p,
        SyncVersion::V2,
        &SyncInfo::V2 {
            headers: vec![unknown_bytes],
        },
        &chain,
        Instant::now(),
    );

    let inv_count = actions
        .iter()
        .filter(|a| {
            matches!(a,
                Action::SendToPeer { code, .. } if *code == message::CODE_INV
            )
        })
        .count();
    assert_eq!(
        inv_count, 0,
        "peer with no overlap should fall through to Older path, no Inv extension"
    );
}

#[test]
fn on_sync_info_v2_offchain_tip_with_older_common_classifies_older() {
    // Peer's TIP (newest header) is off our chain, but an OLDER header of
    // theirs IS on our chain (they forked/advanced above a shared ancestor).
    // Classification keys on the TIP: this is Older (fetch their continuation),
    // NOT Younger. The old `.any()` logic misread the shared older header as
    // "peer is behind us" and would have emitted a catch-up Inv.
    let mut chain = MockChain::new(105, 105);
    for h in 100u32..=105 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&h.to_be_bytes());
        id[4] = b'O';
        chain.add_best_chain_header(h, id);
    }

    // A shared older peer header that maps onto our best chain at h=102.
    let common_bytes = fake_header_bytes([0xC0u8; 32]);
    let common_id = id_for_bytes(&common_bytes);
    chain.height_to_id.insert(102, common_id);
    chain.id_to_height.insert(common_id, 102);
    chain.best_chain_ids.insert(common_id);
    chain.known_headers.insert(common_id);

    // Peer's tip: off our chain (never inserted into any chain set).
    let tip_bytes = fake_header_bytes([0xEEu8; 32]);

    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);
    coord.on_sync_info(
        p,
        SyncVersion::V2,
        &SyncInfo::V2 {
            headers: vec![tip_bytes, common_bytes], // newest-first
        },
        &chain,
        Instant::now(),
    );

    let status = coord
        .peer_sync_snapshots()
        .get(&p)
        .expect("peer snapshot recorded")
        .status;
    assert_eq!(
        status,
        ergo_p2p::sync::PeerChainStatus::Older,
        "off-chain tip above a shared ancestor must classify Older, not Younger",
    );
}

#[test]
fn on_sync_info_v2_younger_caps_at_400_ids() {
    // If our chain is way ahead of the common point, the extension
    // must be capped at MAX_INV_OBJECTS = 400.
    let mut chain = MockChain::new(1000, 1000);
    // Build chain at heights 100..=1000
    for h in 100u32..=1000 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&h.to_be_bytes());
        id[4] = b'C';
        chain.add_best_chain_header(h, id);
    }

    let peer_bytes = fake_header_bytes([0x11u8; 32]);
    let synthetic_top_id = id_for_bytes(&peer_bytes);
    chain.height_to_id.insert(100, synthetic_top_id);
    chain.id_to_height.insert(synthetic_top_id, 100);
    chain.best_chain_ids.insert(synthetic_top_id);
    chain.known_headers.insert(synthetic_top_id);

    let mut coord = SyncCoordinator::new(0);
    let p = peer(9030);
    let actions = coord.on_sync_info(
        p,
        SyncVersion::V2,
        &SyncInfo::V2 {
            headers: vec![peer_bytes],
        },
        &chain,
        Instant::now(),
    );

    let payload = actions
        .iter()
        .find_map(|a| match a {
            Action::SendToPeer { code, payload, .. } if *code == message::CODE_INV => {
                Some(payload.clone())
            }
            _ => None,
        })
        .expect("expected Inv extension");
    let inv = ergo_p2p::message::deserialize_inv(&payload).unwrap();
    assert_eq!(
        inv.ids.len(),
        400,
        "extension capped at 400 IDs, got {}",
        inv.ids.len()
    );
}

// ---- Transaction flow ----

#[test]
fn request_transactions_sends_serialized_request_modifier() {
    let mut coord = SyncCoordinator::new(0);
    let now = Instant::now();
    let (actions, requested) = coord.request_transactions(peer(1), &[mk(10), mk(11)], now);
    assert_eq!(actions.len(), 1);
    assert_eq!(requested, 2, "both fresh ids should be reported requested");
    match &actions[0] {
        Action::SendToPeer {
            peer: p,
            code,
            payload,
        } => {
            assert_eq!(*p, peer(1));
            assert_eq!(*code, message::CODE_REQUEST_MODIFIER);
            let parsed = message::deserialize_inv(payload).unwrap();
            assert_eq!(parsed.type_id, ModifierTypeId::Transaction.as_byte());
            assert_eq!(parsed.ids.len(), 2);
        }
        other => panic!("expected SendToPeer, got {other:?}"),
    }
}

#[test]
fn request_transactions_dedupes_against_in_flight() {
    let mut coord = SyncCoordinator::new(0);
    let now = Instant::now();
    let (_, first) = coord.request_transactions(peer(1), &[mk(20), mk(21)], now);
    assert_eq!(first, 2, "both ids registered on the first request");
    // Same ids from a different peer: DeliveryTracker should
    // filter them as already in-flight, leaving nothing to
    // register and thus no SendToPeer action and a zero count.
    let (actions, requested) = coord.request_transactions(peer(2), &[mk(20), mk(21)], now);
    assert!(actions.is_empty());
    assert_eq!(
        requested, 0,
        "in-flight ids must not be re-counted as requested",
    );
}

#[test]
fn on_transaction_received_accepts_from_requesting_peer() {
    let mut coord = SyncCoordinator::new(0);
    let now = Instant::now();
    let _ = coord.request_transactions(peer(1), &[mk(30)], now);
    let verdict = coord.on_transaction_received(peer(1), &mk(30));
    assert!(matches!(
        verdict,
        ergo_p2p::delivery::DeliveryAction::Accept
    ));
}

#[test]
fn on_transaction_received_rejects_unsolicited() {
    let mut coord = SyncCoordinator::new(0);
    // Peer sends a tx we never requested.
    let verdict = coord.on_transaction_received(peer(9), &mk(99));
    assert!(matches!(
        verdict,
        ergo_p2p::delivery::DeliveryAction::RejectSpam
    ));
}

#[test]
fn on_transaction_received_ignores_duplicate_after_accept() {
    let mut coord = SyncCoordinator::new(0);
    let now = Instant::now();
    let _ = coord.request_transactions(peer(1), &[mk(40)], now);
    let _ = coord.on_transaction_received(peer(1), &mk(40));
    let verdict = coord.on_transaction_received(peer(1), &mk(40));
    assert!(matches!(
        verdict,
        ergo_p2p::delivery::DeliveryAction::Ignore
    ));
}

#[test]
fn request_transactions_empty_ids_emits_nothing() {
    let mut coord = SyncCoordinator::new(0);
    let (actions, requested) = coord.request_transactions(peer(1), &[], Instant::now());
    assert!(actions.is_empty());
    assert_eq!(requested, 0, "no ids → nothing requested");
}

// ----- verify_section_modifier_id (Scala-parity receive-time check) -----

#[test]
fn verify_section_modifier_id_accepts_canonical_ad_proofs() {
    // Round-trip an ADProofs section: serialize, compute expected
    // section_id, hand both to the verifier. ADProofs is the simplest
    // test surface since its content digest is just
    // blake2b256(proof_bytes).
    use ergo_primitives::digest::{blake2b256, ModifierId};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};

    let header_id = [0x42u8; 32];
    let proof_bytes = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let content_digest = *blake2b256(&proof_bytes).as_bytes();
    let expected_id = compute_section_id(TYPE_AD_PROOFS, &header_id, &content_digest);

    let mut w = VlqWriter::new();
    ergo_ser::ad_proofs::write_ad_proofs(
        &mut w,
        &ergo_ser::ad_proofs::ADProofs {
            header_id: ModifierId::from_bytes(header_id),
            proof_bytes,
        },
    );
    let wire = w.result();

    assert!(
        verify_section_modifier_id(TYPE_AD_PROOFS, &expected_id, &wire).is_ok(),
        "canonical ADProofs bytes must match recomputed section_id",
    );
}

#[test]
fn verify_section_modifier_id_rejects_wrong_modifier_id() {
    // Build canonical ADProofs but claim a different modifier_id —
    // Scala parity: this is the "peer sent bytes that don't hash to
    // the ID they claimed" case that triggers a Misbehavior penalty.
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::modifier_id::TYPE_AD_PROOFS;

    let mut w = VlqWriter::new();
    ergo_ser::ad_proofs::write_ad_proofs(
        &mut w,
        &ergo_ser::ad_proofs::ADProofs {
            header_id: ModifierId::from_bytes([0x42u8; 32]),
            proof_bytes: vec![0xAA, 0xBB],
        },
    );
    let wire = w.result();

    let wrong_id = [0xFFu8; 32];
    let result = verify_section_modifier_id(TYPE_AD_PROOFS, &wrong_id, &wire);
    assert!(result.is_err(), "wrong modifier_id must fail");
    assert!(
        result.as_ref().unwrap_err().contains("recomputed"),
        "error must explain the mismatch: {result:?}",
    );
}

#[test]
fn verify_section_modifier_id_rejects_garbage_bytes() {
    // Bytes that don't even parse as a valid section — Scala's
    // `parseBytesTry` catches this same case and penalizes.
    use ergo_ser::modifier_id::TYPE_BLOCK_TRANSACTIONS;
    let result = verify_section_modifier_id(TYPE_BLOCK_TRANSACTIONS, &[0u8; 32], &[1, 2, 3]);
    assert!(result.is_err(), "garbage bytes must fail to parse");
}

#[test]
fn verify_section_modifier_id_rejects_unknown_section_type() {
    // Type-spoof defense: `is_block_section(type_id_byte)` returns
    // `true` for any `type_id >= 50`, but only 102/104/108 have a
    // canonical receive-time check here. A peer claiming `type_id =
    // 255` must not bypass the gate — verify rejects unknown types
    // so the caller penalizes instead of letting bytes through.
    let result = verify_section_modifier_id(255, &[0u8; 32], &[1, 2, 3]);
    assert!(result.is_err(), "unknown section type must be rejected");
    assert!(
        result
            .as_ref()
            .unwrap_err()
            .contains("unknown section type"),
        "error must name the unknown type: {result:?}",
    );
}

#[test]
fn verify_section_modifier_id_rejects_trailing_bytes() {
    // Scala's `parseBytesTry` also rejects canonical-prefix-plus-junk
    // payloads. Serialize a valid ADProofs, then append garbage; the
    // parse succeeds but `r.remaining() != 0` must trigger an Err so
    // the peer doesn't get to smuggle bytes past the gate.
    use ergo_primitives::digest::{blake2b256, ModifierId};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};

    let header_id = [0x42u8; 32];
    let proof_bytes = vec![0xAA, 0xBB];
    let content_digest = *blake2b256(&proof_bytes).as_bytes();
    let expected_id = compute_section_id(TYPE_AD_PROOFS, &header_id, &content_digest);

    let mut w = VlqWriter::new();
    ergo_ser::ad_proofs::write_ad_proofs(
        &mut w,
        &ergo_ser::ad_proofs::ADProofs {
            header_id: ModifierId::from_bytes(header_id),
            proof_bytes,
        },
    );
    let mut wire_plus_junk = w.result();
    wire_plus_junk.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let result = verify_section_modifier_id(TYPE_AD_PROOFS, &expected_id, &wire_plus_junk);
    assert!(result.is_err(), "trailing bytes must be rejected");
    assert!(
        result.as_ref().unwrap_err().contains("trailing bytes"),
        "error must name the trailing-bytes case: {result:?}",
    );
}

// ----- first-deliverer accumulation -----

/// `on_header_validated` records the delivering peer for the accepted
/// header into the drain buffer that the node folds into its first-
/// deliverer ring. The observation is recorded for EVERY accepted header
/// (here on a pre-synced coordinator that takes the early return before
/// any section request), and `take_first_deliverers` drains it once.
#[test]
fn on_header_validated_accumulates_first_deliverer_and_drains_once() {
    // best_full_block_height 0, stale-by-default timestamp keeps the
    // coordinator below headers_chain_synced — exercises the early-return
    // path, proving the observation is recorded BEFORE the section gates.
    let mut coord = SyncCoordinator::new(0);
    let now = Instant::now();
    let p = peer(9030);
    let expected = ExpectedSections::from_header(&mk(1), &mk(10), &mk(11), &mk(12));

    // Stale timestamp (epoch) so headers_chain_synced stays false.
    let _ = coord.on_header_validated(p, mk(1), 1, 0, expected, now);

    let drained = coord.take_first_deliverers();
    assert_eq!(
        drained,
        vec![(mk(1), p)],
        "the accepted header's delivering peer must be recorded",
    );
    // Draining is destructive — a second drain is empty.
    assert!(
        coord.take_first_deliverers().is_empty(),
        "take_first_deliverers must drain (mem::take) the buffer",
    );
}
