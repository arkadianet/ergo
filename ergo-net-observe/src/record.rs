//! JSONL record model for Phase 0 observation.
//!
//! One [`Envelope`] is one line. Common timing fields are written on every
//! record so a reader never has to join streams:
//!
//! * `mono_ns` — monotonic nanoseconds since the observer process started.
//!   **Authoritative for durations.**
//! * `wall_ms` — Unix wall-clock milliseconds at emission.
//! * `clock_offset_ms` / `clock_source` — the measured wall-clock offset
//!   supplied by the operator (normally from `chronyc tracking`). The offset
//!   is informational; `mono_ns` is unaffected by NTP steps.
//!
//! Peer addresses are pseudonymised by default with a keyed Blake2b-256
//! digest (`pseudonym.rs`). Transactions and header ids are public chain
//! identifiers and are emitted in full.

use serde::Serialize;

/// Stable schema id. Bump only on a breaking field change.
pub const SCHEMA: &str = "ergo-observer/1";

/// Pseudonymised (or raw, when pseudonymisation is disabled) peer identity.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeerRef {
    /// Keyed digest of `addr`; equal across records for the same peer.
    pub id: String,
    /// Raw `addr`, present only when pseudonymisation is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
}

/// Block identity attached to announce/receive/validation records.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BlockRef {
    pub header_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

/// One gossiped `PeerSpec`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GossipPeer {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

/// Event bodies. Serialized with an internal `event` tag.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Emitted once at startup with the effective configuration.
    ObserverStart {
        network: String,
        agent: String,
        node_name: String,
        version: String,
        peer_count: usize,
        request_headers: bool,
        request_bodies: bool,
        request_txs: bool,
        /// Chosen outbound ceiling, bytes/second, for operator audit.
        outbound_bytes_per_sec: u64,
    },
    /// TCP connect succeeded (before the handshake).
    ConnOpen { direction: String },
    /// Raw handshake parsed. `sync_version` is filled in once the first
    /// `SyncInfo` reveals whether the peer speaks V1 or V2.
    HandshakeOk {
        agent: String,
        version: String,
        node_name: String,
        features: Vec<String>,
        /// Peer clock field from the handshake, Unix ms.
        peer_time_ms: u64,
    },
    /// Handshake send/parse/connect failure.
    HandshakeFail { reason: String },
    /// Session ended.
    Disconnect { reason: String, lifetime_ms: u64 },
    /// A peer announced ids via `Inv` or `SyncInfo`.
    Announce {
        /// `inv`, `syncinfo_v1`, or `syncinfo_v2`.
        via: String,
        /// Modifier type id (2 tx, 101 header, 102 txs, 104 ADProofs,
        /// 108 extension). For SyncInfo the type is 101.
        type_id: u8,
        count: usize,
        ids: Vec<String>,
        /// Heights, positionally aligned with `ids`, when the announce
        /// carried full headers (SyncInfo V2). Empty otherwise.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        heights: Vec<u32>,
        /// How many ids in this announcement were globally new.
        first_global: usize,
        /// How many ids were new for this peer.
        first_for_peer: usize,
    },
    /// We sent `RequestModifier`.
    RequestSent {
        seq: u64,
        type_id: u8,
        ids: Vec<String>,
    },
    /// A `Modifiers` entry arrived.
    SectionReceived {
        type_id: u8,
        id: String,
        bytes: usize,
        /// Request sequence this satisfies, when we can attribute it.
        #[serde(skip_serializing_if = "Option::is_none")]
        seq: Option<u64>,
        solicited: bool,
        /// Parsed height for a header, when the bytes parse.
        #[serde(skip_serializing_if = "Option::is_none")]
        height: Option<u32>,
        /// `Blake2b256(bytes)` for a header, to compare with the claimed id.
        #[serde(skip_serializing_if = "Option::is_none")]
        computed_id: Option<String>,
        /// Whether the claimed id equals `computed_id` (headers only).
        #[serde(skip_serializing_if = "Option::is_none")]
        id_matches: Option<bool>,
    },
    /// Parse-level request/response latency, one sample per matched request.
    Rtt { seq: u64, type_id: u8, rtt_us: u64 },
    /// Node-only: mempool admission outcome for a peer-sourced transaction.
    TxOutcome {
        tx_id: String,
        /// `admitted` or `rejected`.
        result: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fee: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u32>,
        /// `peer` when validated against the tip, `unavailable` for a
        /// non-validating observer.
        source: String,
        /// Spending-input box ids, when the transaction parsed. Enables
        /// joining an `UnresolvedInput` rejection to the parent that
        /// arrived later (child-before-parent measurement).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        input_ids: Vec<String>,
        /// Read-only data-input box ids, same purpose.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        data_input_ids: Vec<String>,
    },
    /// Node-only: header validation completed.
    HeaderValidated {
        header_id: String,
        /// `valid` or `invalid`.
        result: String,
        /// From header receipt to validation completion.
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_us: Option<u64>,
    },
    /// Node-only: full block applied at the tip.
    BlockApplied {
        header_id: String,
        height: u32,
        /// From the first observed announce of this id to apply completion.
        #[serde(skip_serializing_if = "Option::is_none")]
        since_first_announce_us: Option<u64>,
    },
    /// Peer gossip (`Peers` reply).
    PeerGossip {
        count: usize,
        peers: Vec<GossipPeer>,
    },
    /// Crawler: one completed dial attempt at a seed or learned address.
    /// The `peer` envelope is the *target* address.
    DialAttempt {
        /// `handshaken`, `handshake_fail`, `connect_refused`, or
        /// `connect_timeout`.
        outcome: String,
        /// TCP connect duration in milliseconds, when the attempt reached
        /// a connect decision.
        #[serde(skip_serializing_if = "Option::is_none")]
        connect_ms: Option<u64>,
        /// Consecutive failures of this address before the attempt (0 for a
        /// first try).
        retries: u32,
        /// Pseudonym id of the peer that gossiped this address, or `seed`.
        via: String,
    },
    /// Crawler: an address newly learned from a `Peers` gossip and queued
    /// for dialing. The `peer` envelope is the *learned* address.
    PeerLearned {
        /// Pseudonym id of the peer that gossiped this address.
        via: String,
    },
    /// A peer asked us for peers.
    GetPeersReceived { count: usize },
    /// A peer asked us for modifiers we cannot serve (observer is not a
    /// full node).
    RequestReceived { type_id: u8, count: usize },
    /// Penalty/ban observed in the local node.
    Penalty { kind: String, banned: bool },
    /// Records were dropped because the bounded sink was full.
    Gap { dropped: u64 },
    /// Free-form note (startup, unsupported message, parse warning).
    Note { message: String },
}

/// A complete JSONL line.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    pub schema: &'static str,
    pub vantage: String,
    pub wall_ms: i64,
    pub mono_ns: u64,
    pub clock_offset_ms: f64,
    pub clock_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<BlockRef>,
    #[serde(flatten)]
    pub event: Event,
}

impl Event {
    /// Short event name, useful for tests and tracing.
    pub fn name(&self) -> &'static str {
        match self {
            Event::ObserverStart { .. } => "observer_start",
            Event::ConnOpen { .. } => "conn_open",
            Event::HandshakeOk { .. } => "handshake_ok",
            Event::HandshakeFail { .. } => "handshake_fail",
            Event::Disconnect { .. } => "disconnect",
            Event::Announce { .. } => "announce",
            Event::RequestSent { .. } => "request_sent",
            Event::SectionReceived { .. } => "section_received",
            Event::Rtt { .. } => "rtt",
            Event::TxOutcome { .. } => "tx_outcome",
            Event::HeaderValidated { .. } => "header_validated",
            Event::BlockApplied { .. } => "block_applied",
            Event::PeerGossip { .. } => "peer_gossip",
            Event::DialAttempt { .. } => "dial_attempt",
            Event::PeerLearned { .. } => "peer_learned",
            Event::GetPeersReceived { .. } => "get_peers_received",
            Event::RequestReceived { .. } => "request_received",
            Event::Penalty { .. } => "penalty",
            Event::Gap { .. } => "gap",
            Event::Note { .. } => "note",
        }
    }
}
