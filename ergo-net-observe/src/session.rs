//! One honest, read-mostly observer session with a legacy peer.
//!
//! The session performs the same raw handshake as the node
//! (`ergo-node/src/peer_loop.rs::do_handshake`), then speaks only ordinary
//! legacy messages: `GetPeers`, `SyncInfo`, `Inv`, `RequestModifier`, and
//! `Modifiers`. It never advertises a declared address, never claims a state
//! mode, and never sends unsolicited modifiers.
//!
//! Requests are rate-limited per peer and capped in flight; every send
//! passes through the session's byte bucket, which enforces the documented
//! per-session outbound ceiling. In practice the request pacing (interval,
//! in-flight cap, ids-per-request) bounds a normal session to a few KiB/s.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ergo_p2p::connection::Connection;
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, DeclaredAddress, Handshake,
    PeerFeature, PeerSpec, Version,
};
use ergo_p2p::message::{
    self, SyncInfo, CODE_GET_PEERS, CODE_HANDSHAKE, CODE_INV, CODE_MODIFIER, CODE_PEERS,
    CODE_REQUEST_MODIFIER, CODE_SYNC_INFO,
};
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{header_id_from_bytes, read_header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use crate::record::{BlockRef, Event, GossipPeer, PeerRef};
use crate::sink::{unix_ms, ObserverSink};

/// Chosen outbound ceiling for one peer session. Actual use is far lower:
/// the per-peer request interval and in-flight cap bound a normal session
/// to a few KiB/s, so the process-level egress of a multi-session observer
/// or crawler stays modest in practice.
pub const OUTBOUND_BYTES_PER_SEC: u64 = 64 * 1024;

const MAX_SEEN: usize = 100_000;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub magic: [u8; 4],
    pub network: String,
    pub agent_name: String,
    pub node_name: String,
    pub protocol_version: Version,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub request_headers: bool,
    pub request_bodies: bool,
    pub request_txs: bool,
    /// Minimum spacing between RequestModifier frames to one peer.
    pub request_interval: Duration,
    /// Maximum unanswered requests in flight to one peer.
    pub max_outstanding: usize,
    pub max_ids_per_request: usize,
    pub request_handshake_timeout: Duration,
    pub respond_to_sync_info: bool,
    /// When set, `Peers` replies are also forwarded to the discovery
    /// crawler (bounded channel; a full channel drops the report).
    pub crawl: Option<Arc<crate::crawler::CrawlChannel>>,
    /// When set, raw handshake bytes are captured as hex on the
    /// `handshake_ok` / `handshake_fail` records (offline replay
    /// analysis only; off in the standing dataset streams).
    pub capture_handshake_hex: bool,
    /// When set, incremented once per captured handshake byte sequence
    /// (a completed handshake, or a failure that received at least one
    /// byte). The crawler's `--capture-max` stop condition polls it.
    pub capture_counter: Option<Arc<AtomicU64>>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            magic: ergo_p2p::framing::MAINNET_MAGIC,
            network: "mainnet".to_string(),
            agent_name: "ergo-rust-observer".to_string(),
            node_name: "ergo-rust-observer-phase0".to_string(),
            protocol_version: Version::CURRENT,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(600),
            request_headers: true,
            request_bodies: false,
            request_txs: false,
            request_interval: Duration::from_secs(2),
            max_outstanding: 4,
            max_ids_per_request: 64,
            request_handshake_timeout: Duration::from_secs(30),
            respond_to_sync_info: true,
            crawl: None,
            capture_handshake_hex: false,
            capture_counter: None,
        }
    }
}

/// Bounded insertion-order set. Oldest entries are evicted FIFO so a
/// multi-day session cannot grow without bound.
#[derive(Debug, Default)]
pub struct BoundedSet {
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl BoundedSet {
    /// Insert; returns `true` when the id was not already present.
    pub fn insert(&mut self, id: [u8; 32]) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > MAX_SEEN {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    pub fn contains(&self, id: &[u8; 32]) -> bool {
        self.set.contains(id)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// The newest header this observer has seen in full (V2 announce or
/// type-101 receipt): the highest height for which it holds the bytes.
/// Shared across sessions so a newly connected session can present the
/// tip it observed before that session itself saw anything.
#[derive(Debug, Clone)]
pub struct ObservedTip {
    pub height: u32,
    pub id: [u8; 32],
    pub bytes: Vec<u8>,
}

/// State shared by all peer sessions.
#[derive(Debug, Default)]
pub struct SharedSeen {
    /// Header/tx ids we already received.
    pub received: BoundedSet,
    /// Ids requested from some peer and not yet received.
    pub requested: BoundedSet,
    /// First time this observer saw an id announced.
    pub announced: BoundedSet,
    /// Highest fully-seen header (see [`ObservedTip`]).
    pub tip: Option<ObservedTip>,
}

impl SharedSeen {
    /// Record a fully-seen header as the observed tip when it is ahead of
    /// the current one, or a same-height different id (a reorg). A lower
    /// height from a lagging peer never moves the tip backwards.
    pub fn observe_header(&mut self, height: u32, id: [u8; 32], bytes: &[u8]) {
        let replace = match &self.tip {
            None => true,
            Some(t) => height > t.height || (height == t.height && t.id != id),
        };
        if replace {
            self.tip = Some(ObservedTip {
                height,
                id,
                bytes: bytes.to_vec(),
            });
        }
    }
}

pub type Shared = Arc<Mutex<SharedSeen>>;

fn lock_shared(shared: &Shared) -> std::sync::MutexGuard<'_, SharedSeen> {
    match shared.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The SyncInfo this observer presents to a peer: its observed tip header
/// (newest-first, one entry), or the honest empty V2 before any header has
/// been seen in full.
///
/// Why the tip instead of empty: an empty V2 compares as `Younger` for a
/// seeded peer, and `ErgoNodeViewSynchronizer.processSyncV2` answers every
/// `Younger` with a full continuation extension
/// (`ErgoHistoryReader.continuationIdsV2`, `size = 400` → ids of heights
/// 1..=400 for an empty peer, sent as `Inv` by `sendExtension`),
/// re-triggered on every one of our replies. Presenting the tip compares
/// as `Equal` (the peer does nothing) or, when the tip moved on, `Younger`
/// with an extension of only the ids after our common point.
/// `ergo-p2p::message` caps a V2 header at 1000 bytes, so a larger
/// (unparseable-scale) header falls back to the empty V2.
fn sync_reply_for(tip: Option<&ObservedTip>) -> SyncInfo {
    match tip {
        Some(t) if t.bytes.len() < 1000 => SyncInfo::V2 {
            headers: vec![t.bytes.clone()],
        },
        _ => SyncInfo::V2 {
            headers: Vec::new(),
        },
    }
}

/// Human-readable summary of a SyncInfo reply for debug logs: the header
/// ids and heights it presents, so a reply's wire content can be audited
/// without capturing the connection.
fn sync_reply_log(info: &SyncInfo) -> String {
    match info {
        SyncInfo::V1 { header_ids } => format!("V1 ids={}", header_ids.len()),
        SyncInfo::V2 { headers } if headers.is_empty() => "V2 empty".to_string(),
        SyncInfo::V2 { headers } => headers
            .iter()
            .map(|b| {
                let (id, height) = header_meta(b);
                format!("{id}@{:?}", height)
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

struct Pending {
    sent_at: Instant,
    type_id: u8,
    ids: HashSet<[u8; 32]>,
}

struct ByteBucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    capacity: f64,
}

impl ByteBucket {
    fn new(rate_bytes_per_sec: u64) -> Self {
        let rate = rate_bytes_per_sec as f64;
        Self {
            tokens: rate,
            last: Instant::now(),
            rate,
            capacity: rate,
        }
    }

    fn allow(&mut self, bytes: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        let need = bytes as f64;
        if self.tokens >= need {
            self.tokens -= need;
            true
        } else {
            false
        }
    }
}

enum SessionEnd {
    Closed(String),
    Idle,
}

/// Run one TCP session to completion. The caller owns reconnect/backoff.
/// Returns `true` when the handshake completed (the peer was a live,
/// versioned peer) and `false` when it failed — the crawler uses this to
/// distinguish handshake failures from dial failures.
///
/// `handshake_result`, when given, receives the handshake outcome as soon
/// as it is known (success or failure), before the session itself ends —
/// so a crawler can record the dial outcome without waiting for the whole
/// session lifetime.
pub async fn run_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    cfg: Arc<SessionConfig>,
    sink: ObserverSink,
    shared: Shared,
    handshake_result: Option<tokio::sync::oneshot::Sender<bool>>,
) -> bool {
    let started = Instant::now();
    let addr = peer_addr.to_string();
    let mut session = Session {
        conn: None,
        stream: Some(stream),
        sink,
        cfg,
        addr,
        agent: None,
        version: None,
        node_name: None,
        pending: HashMap::new(),
        peer_seen: BoundedSet::default(),
        next_request_at: Instant::now(),
        next_sync_reply_at: Instant::now(),
        seq: 0,
        bucket: ByteBucket::new(OUTBOUND_BYTES_PER_SEC),
        shared,
        unavailable_txs: HashSet::new(),
        handshaken: false,
        handshake_result,
    };

    let end = session.run().await;
    let lifetime_ms = started.elapsed().as_millis() as u64;
    let reason = match end {
        SessionEnd::Closed(reason) => reason,
        SessionEnd::Idle => format!("idle timeout after {}s", session.cfg.idle_timeout.as_secs()),
    };
    session.emit(Event::Disconnect {
        reason: reason.clone(),
        lifetime_ms,
    });
    debug!(peer = %session.addr, %reason, lifetime_ms, "observer session ended");
    session.handshaken
}

struct Session {
    conn: Option<Connection>,
    stream: Option<TcpStream>,
    sink: ObserverSink,
    cfg: Arc<SessionConfig>,
    addr: String,
    agent: Option<String>,
    version: Option<String>,
    node_name: Option<String>,
    pending: HashMap<u64, Pending>,
    /// Ids already announced to us by THIS peer.
    peer_seen: BoundedSet,
    next_request_at: Instant,
    next_sync_reply_at: Instant,
    seq: u64,
    bucket: ByteBucket,
    shared: Shared,
    unavailable_txs: HashSet<[u8; 32]>,
    /// Set once the handshake completed.
    handshaken: bool,
    /// Resolved with the handshake outcome as soon as it is known.
    handshake_result: Option<tokio::sync::oneshot::Sender<bool>>,
}

impl Session {
    async fn run(&mut self) -> SessionEnd {
        self.emit(Event::ConnOpen {
            direction: "out".to_string(),
        });

        let stream = match self.stream.take() {
            Some(s) => s,
            None => return SessionEnd::Closed("no stream".to_string()),
        };
        let our = Handshake {
            time: unix_ms().max(0) as u64,
            peer_spec: PeerSpec {
                agent_name: self.cfg.agent_name.clone(),
                version: self.cfg.protocol_version,
                node_name: self.cfg.node_name.clone(),
                declared_address: None,
                // No Mode feature: this observer has no chain state to
                // claim. Omitting features is legal and honest.
                features: Vec::new(),
            },
        };
        let (peer_hs, conn, peer_raw) = match do_handshake(
            stream,
            self.cfg.magic,
            &our,
            self.cfg.request_handshake_timeout,
        )
        .await
        {
            Ok(v) => v,
            Err((reason, received)) => {
                let received_hex = if self.cfg.capture_handshake_hex && !received.is_empty() {
                    Some(hex::encode(&received))
                } else {
                    None
                };
                self.emit(Event::HandshakeFail {
                    reason,
                    received_hex: received_hex.clone(),
                });
                if received_hex.is_some() {
                    if let Some(counter) = &self.cfg.capture_counter {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if let Some(tx) = self.handshake_result.take() {
                    let _ = tx.send(false);
                }
                return SessionEnd::Closed("handshake failed".to_string());
            }
        };
        self.agent = Some(peer_hs.peer_spec.agent_name.clone());
        self.version = Some(peer_hs.peer_spec.version.to_string());
        self.node_name = Some(peer_hs.peer_spec.node_name.clone());
        self.conn = Some(conn);
        let peer_handshake_hex = if self.cfg.capture_handshake_hex {
            Some(hex::encode(&peer_raw))
        } else {
            None
        };
        if peer_handshake_hex.is_some() {
            if let Some(counter) = &self.cfg.capture_counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.emit(Event::HandshakeOk {
            agent: peer_hs.peer_spec.agent_name.clone(),
            version: peer_hs.peer_spec.version.to_string(),
            node_name: peer_hs.peer_spec.node_name.clone(),
            features: peer_hs
                .peer_spec
                .features
                .iter()
                .map(feature_label)
                .collect(),
            peer_time_ms: peer_hs.time,
            peer_handshake_hex,
        });
        self.handshaken = true;
        if let Some(tx) = self.handshake_result.take() {
            let _ = tx.send(true);
        }

        if self.send(CODE_GET_PEERS, Vec::new()).await.is_err() {
            return SessionEnd::Closed("send GetPeers failed".to_string());
        }
        // Present the tip observed by this process (or the honest empty V2
        // before any header has been seen), so the peer does not treat us
        // as a genesis-height peer and re-send its catch-up extension on
        // every exchange — see `sync_reply_for`.
        if self.cfg.respond_to_sync_info {
            let reply = self.sync_reply();
            debug!(
                peer = %self.addr,
                reply = %sync_reply_log(&reply),
                "observer sent SyncInfo reply"
            );
            let payload = match message::serialize_sync_info(&reply) {
                Ok(p) => p,
                Err(e) => return SessionEnd::Closed(format!("serialize SyncInfo: {e}")),
            };
            if self.send(CODE_SYNC_INFO, payload).await.is_err() {
                return SessionEnd::Closed("send SyncInfo failed".to_string());
            }
        }

        loop {
            let conn = match self.conn.as_mut() {
                Some(c) => c,
                None => return SessionEnd::Closed("no connection".to_string()),
            };
            let read = tokio::time::timeout(self.cfg.idle_timeout, conn.read_message()).await;
            let frame = match read {
                Err(_) => return SessionEnd::Idle,
                Ok(Err(e)) => return SessionEnd::Closed(format!("read: {e}")),
                Ok(Ok(f)) => f,
            };
            if let Err(reason) = self.handle_frame(frame.code, &frame.payload).await {
                return SessionEnd::Closed(reason);
            }
        }
    }

    fn emit(&self, event: Event) {
        self.sink.try_emit_peer(self.peer_ref(), event);
    }

    fn emit_block(&self, block: BlockRef, event: Event) {
        self.sink.try_emit_peer_block(self.peer_ref(), block, event);
    }

    fn peer_ref(&self) -> PeerRef {
        self.sink.peer_ref(
            &self.addr,
            self.agent.as_deref(),
            self.version.as_deref(),
            self.node_name.as_deref(),
            Some("out"),
        )
    }

    async fn send(&mut self, code: u8, payload: Vec<u8>) -> Result<(), ()> {
        let wire = ergo_p2p::framing::wire_len(payload.len());
        if !self.bucket.allow(wire) {
            debug!(peer = %self.addr, wire, "observer outbound byte cap reached; dropping send");
            return Err(());
        }
        let conn = self.conn.as_mut().ok_or(())?;
        conn.send(code, payload).await.map_err(|_| ())
    }

    async fn handle_frame(&mut self, code: u8, payload: &[u8]) -> Result<(), String> {
        match code {
            CODE_SYNC_INFO => self.on_sync_info(payload).await,
            CODE_INV => self.on_inv(payload).await,
            CODE_MODIFIER => self.on_modifiers(payload).await,
            CODE_PEERS => {
                self.on_peers(payload);
                Ok(())
            }
            CODE_GET_PEERS => {
                let count = 0usize;
                self.emit(Event::GetPeersReceived { count });
                // Honest reply: we know no peers to share.
                let payload = message::serialize_peers(&[]);
                let _ = self.send(CODE_PEERS, payload).await;
                Ok(())
            }
            CODE_REQUEST_MODIFIER => {
                match message::deserialize_inv(payload) {
                    Ok(inv) => self.emit(Event::RequestReceived {
                        type_id: inv.type_id,
                        count: inv.ids.len(),
                    }),
                    Err(e) => self.emit(Event::Note {
                        message: format!("bad RequestModifier: {e}"),
                    }),
                }
                Ok(())
            }
            CODE_HANDSHAKE => {
                self.emit(Event::Note {
                    message: "framed Handshake after admission".to_string(),
                });
                Ok(())
            }
            other => {
                self.emit(Event::Note {
                    message: format!("unsupported message code {other}"),
                });
                Ok(())
            }
        }
    }

    async fn on_sync_info(&mut self, payload: &[u8]) -> Result<(), String> {
        let info = match message::deserialize_sync_info(payload) {
            Ok(i) => i,
            Err(e) => {
                self.emit(Event::Note {
                    message: format!("bad SyncInfo: {e}"),
                });
                return Ok(());
            }
        };
        match info {
            SyncInfo::V1 { header_ids } => {
                let ids: Vec<String> = header_ids.iter().map(hex::encode).collect();
                let (first_global, first_for_peer) =
                    self.record_announce("syncinfo_v1", 101, &header_ids);
                self.emit(Event::Announce {
                    via: "syncinfo_v1".to_string(),
                    type_id: 101,
                    count: header_ids.len(),
                    ids,
                    heights: Vec::new(),
                    first_global,
                    first_for_peer,
                });
                if self.cfg.request_headers {
                    self.request_missing(101, header_ids).await;
                }
            }
            SyncInfo::V2 { headers } => {
                let mut ids = Vec::with_capacity(headers.len());
                let mut heights = Vec::with_capacity(headers.len());
                for bytes in &headers {
                    let (id, height) = header_meta(bytes);
                    ids.push(id);
                    if let Some(h) = height {
                        heights.push(h);
                    }
                }
                let raws: Vec<[u8; 32]> = headers
                    .iter()
                    .map(|b| {
                        header_id_from_bytes(b)
                            .map(|d| {
                                let mut a = [0u8; 32];
                                a.copy_from_slice(d.as_bytes());
                                a
                            })
                            .unwrap_or_else(|_| digest_bytes(b))
                    })
                    .collect();
                let (first_global, first_for_peer) =
                    self.record_announce("syncinfo_v2", 101, &raws);
                self.emit(Event::Announce {
                    via: "syncinfo_v2".to_string(),
                    type_id: 101,
                    count: headers.len(),
                    ids,
                    heights,
                    first_global,
                    first_for_peer,
                });
                // V2 carries the header bytes themselves; mark them received
                // and track the observed tip from them.
                let mut shared = lock_shared(&self.shared);
                for (id, bytes) in raws.iter().zip(headers.iter()) {
                    shared.received.insert(*id);
                    if let Some(h) = header_meta(bytes).1 {
                        shared.observe_header(h, *id, bytes);
                    }
                }
            }
        }
        self.maybe_reply_sync_info().await;
        Ok(())
    }

    async fn maybe_reply_sync_info(&mut self) {
        if !self.cfg.respond_to_sync_info || Instant::now() < self.next_sync_reply_at {
            return;
        }
        self.next_sync_reply_at = Instant::now() + Duration::from_secs(30);
        let reply = self.sync_reply();
        debug!(
            peer = %self.addr,
            reply = %sync_reply_log(&reply),
            "observer sent SyncInfo reply"
        );
        if let Ok(payload) = message::serialize_sync_info(&reply) {
            let _ = self.send(CODE_SYNC_INFO, payload).await;
        }
    }

    /// Build the SyncInfo to present to the current peer from the
    /// process-wide observed tip (see [`sync_reply_for`]).
    fn sync_reply(&self) -> SyncInfo {
        let shared = lock_shared(&self.shared);
        sync_reply_for(shared.tip.as_ref())
    }

    async fn on_inv(&mut self, payload: &[u8]) -> Result<(), String> {
        let inv = match message::deserialize_inv(payload) {
            Ok(i) => i,
            Err(e) => {
                self.emit(Event::Note {
                    message: format!("bad Inv: {e}"),
                });
                return Ok(());
            }
        };
        let (first_global, first_for_peer) = self.record_announce("inv", inv.type_id, &inv.ids);
        self.emit(Event::Announce {
            via: "inv".to_string(),
            type_id: inv.type_id,
            count: inv.ids.len(),
            ids: inv.ids.iter().map(hex::encode).collect(),
            heights: Vec::new(),
            first_global,
            first_for_peer,
        });

        let want = match inv.type_id {
            101 => self.cfg.request_headers,
            102 | 104 | 108 => self.cfg.request_bodies,
            2 => self.cfg.request_txs,
            _ => false,
        };
        if want {
            self.request_missing(inv.type_id, inv.ids).await;
        }
        Ok(())
    }

    fn record_announce(&mut self, _via: &str, _type_id: u8, ids: &[[u8; 32]]) -> (usize, usize) {
        let mut shared = lock_shared(&self.shared);
        let mut first_global = 0usize;
        let mut first_for_peer = 0usize;
        for id in ids {
            if shared.announced.insert(*id) {
                first_global += 1;
            }
            if self.peer_seen.insert(*id) {
                first_for_peer += 1;
            }
        }
        (first_global, first_for_peer)
    }

    async fn request_missing(&mut self, type_id: u8, ids: Vec<[u8; 32]>) {
        if self.pending.len() >= self.cfg.max_outstanding || Instant::now() < self.next_request_at {
            return;
        }
        let mut candidates = Vec::new();
        {
            let shared = lock_shared(&self.shared);
            for id in ids {
                if !shared.received.contains(&id) && !shared.requested.contains(&id) {
                    candidates.push(id);
                    if candidates.len() >= self.cfg.max_ids_per_request {
                        break;
                    }
                }
            }
        }
        if candidates.is_empty() {
            return;
        }
        let seq = self.seq;
        let inv = InvData {
            type_id,
            ids: candidates.clone(),
        };
        let payload = match message::serialize_inv(&inv) {
            Ok(p) => p,
            Err(e) => {
                self.emit(Event::Note {
                    message: format!("serialize RequestModifier: {e}"),
                });
                return;
            }
        };
        if self.send(CODE_REQUEST_MODIFIER, payload).await.is_err() {
            return;
        }
        self.seq = self.seq.wrapping_add(1);
        self.next_request_at = Instant::now() + self.cfg.request_interval;
        {
            let mut shared = lock_shared(&self.shared);
            for id in &candidates {
                shared.requested.insert(*id);
            }
        }
        self.pending.insert(
            seq,
            Pending {
                sent_at: Instant::now(),
                type_id,
                ids: candidates.iter().copied().collect(),
            },
        );
        self.emit(Event::RequestSent {
            seq,
            type_id,
            ids: candidates.iter().map(hex::encode).collect(),
        });
    }

    async fn on_modifiers(&mut self, payload: &[u8]) -> Result<(), String> {
        let data = match message::deserialize_modifiers(payload) {
            Ok(d) => d,
            Err(e) => {
                self.emit(Event::Note {
                    message: format!("bad Modifiers: {e}"),
                });
                return Ok(());
            }
        };
        for (id, bytes) in data.modifiers {
            let attribution = self.take_pending(data.type_id, &id);
            let solicited = attribution.is_some();
            let seq = attribution.map(|(seq, type_id, sent_at)| {
                self.emit(Event::Rtt {
                    seq,
                    type_id,
                    rtt_us: sent_at.elapsed().as_micros() as u64,
                });
                seq
            });
            {
                let mut shared = lock_shared(&self.shared);
                shared.received.insert(id);
                // A type-101 receipt is a fully-seen header too.
                if data.type_id == 101 {
                    if let Some(h) = header_meta(&bytes).1 {
                        shared.observe_header(h, id, &bytes);
                    }
                }
            }
            let (claimed, height, computed, matches) = if data.type_id == 101 {
                let (computed, height) = header_meta(&bytes);
                let matches = computed == hex::encode(id);
                (hex::encode(id), height, Some(computed), Some(matches))
            } else {
                (hex::encode(id), None, None, None)
            };
            let block = BlockRef {
                header_id: claimed.clone(),
                height,
            };
            self.emit_block(
                block,
                Event::SectionReceived {
                    type_id: data.type_id,
                    id: claimed.clone(),
                    bytes: bytes.len(),
                    seq,
                    solicited,
                    height,
                    computed_id: computed,
                    id_matches: matches,
                },
            );
            if data.type_id == 2 && self.unavailable_txs.insert(id) {
                // The standalone observer does not validate transactions.
                // Emit the explicit `unavailable` outcome so the schema is
                // uniform with the node hook.
                self.emit(Event::TxOutcome {
                    tx_id: claimed,
                    result: "unavailable".to_string(),
                    reason: Some("observer does not validate".to_string()),
                    fee: None,
                    size: Some(bytes.len() as u32),
                    source: "unavailable".to_string(),
                    input_ids: Vec::new(),
                    data_input_ids: Vec::new(),
                });
            }
        }
        Ok(())
    }

    /// Remove `id` from its in-flight request. Returns
    /// `(seq, type_id, sent_at)` for the request it belonged to, so the
    /// caller can emit an RTT even when this was the request's last id.
    fn take_pending(&mut self, type_id: u8, id: &[u8; 32]) -> Option<(u64, u8, Instant)> {
        let seq = self
            .pending
            .iter()
            .find(|(_, p)| p.type_id == type_id && p.ids.contains(id))
            .map(|(seq, _)| *seq)?;
        let (pending_type, sent_at, now_empty) = {
            let pending = self.pending.get_mut(&seq)?;
            pending.ids.remove(id);
            (pending.type_id, pending.sent_at, pending.ids.is_empty())
        };
        if now_empty {
            self.pending.remove(&seq);
        }
        Some((seq, pending_type, sent_at))
    }

    fn on_peers(&mut self, payload: &[u8]) {
        let peers = match message::deserialize_peers(payload, 64) {
            Ok(p) => p,
            Err(e) => {
                self.emit(Event::Note {
                    message: format!("bad Peers: {e}"),
                });
                return;
            }
        };
        let gossip: Vec<GossipPeer> = peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let addr = p
                    .declared_address
                    .as_ref()
                    .map(|a| socket_string(&a.addr, a.port))
                    .unwrap_or_else(|| format!("unknown-{i}"));
                GossipPeer {
                    id: self.sink.peer_id(&addr),
                    agent: Some(p.agent_name.clone()),
                    version: Some(p.version.to_string()),
                    node_name: Some(p.node_name.clone()),
                }
            })
            .collect();
        self.emit(Event::PeerGossip {
            count: gossip.len(),
            peers: gossip,
        });

        // Discovery: forward dialable declared addresses to the crawler.
        // The channel is bounded and non-blocking — a full channel drops
        // this report, it never backpressures the session.
        if let Some(channel) = &self.cfg.crawl {
            use crate::crawler::{GossipReport, GossipSpec};
            let specs: Vec<GossipSpec> = peers
                .iter()
                .filter_map(|p| {
                    p.declared_address
                        .as_ref()
                        .and_then(declared_socket)
                        .map(|addr| GossipSpec {
                            addr,
                            agent: p.agent_name.clone(),
                            version: p.version.to_string(),
                            node_name: p.node_name.clone(),
                        })
                })
                .collect();
            if !specs.is_empty() {
                channel.send(GossipReport {
                    via_id: self.sink.peer_id(&self.addr),
                    specs,
                });
            }
        }
    }
}

/// Parse a declared address (4-byte IPv4 or 16-byte IPv6, big-endian) into
/// a dialable `SocketAddr`. Ports outside the 1..=65535 range are not
/// dialable and yield `None`.
fn declared_socket(d: &DeclaredAddress) -> Option<SocketAddr> {
    if d.port == 0 || d.port > u16::MAX as u32 {
        return None;
    }
    let ip = match d.addr.len() {
        4 => IpAddr::V4(Ipv4Addr::new(d.addr[0], d.addr[1], d.addr[2], d.addr[3])),
        16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&d.addr);
            IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(bytes)))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, d.port as u16))
}

fn feature_label(f: &PeerFeature) -> String {
    match f {
        PeerFeature::LocalAddress { .. } => "local_address".to_string(),
        PeerFeature::SessionId { .. } => "session_id".to_string(),
        PeerFeature::RestApiUrl { .. } => "rest_api_url".to_string(),
        PeerFeature::Mode { .. } => "mode".to_string(),
        PeerFeature::Unknown { feature_id, .. } => format!("unknown:{feature_id}"),
    }
}

fn socket_string(addr: &[u8], port: u32) -> String {
    match addr.len() {
        4 => format!("{}.{}.{}.{}:{port}", addr[0], addr[1], addr[2], addr[3]),
        16 => {
            let mut parts = Vec::with_capacity(8);
            for chunk in addr.chunks(2) {
                parts.push(format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])));
            }
            format!("[{}]:{port}", parts.join(":"))
        }
        _ => format!("unknown:{port}"),
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(blake2b256(bytes).as_bytes());
    out
}

fn header_meta(bytes: &[u8]) -> (String, Option<u32>) {
    let id = header_id_from_bytes(bytes)
        .map(|d| hex::encode(d.as_bytes()))
        .unwrap_or_else(|_| hex::encode(blake2b256(bytes).as_bytes()));
    let height = read_header(&mut VlqReader::new(bytes))
        .ok()
        .map(|h| h.height);
    (id, height)
}

/// Performs the unframed handshake. On success returns the parsed
/// handshake, the connection (with any bytes already received past the
/// handshake prefix), and the peer's raw handshake bytes (for capture).
/// On failure returns the reason plus whatever bytes the peer sent, so
/// a capture run can replay rejected handshakes offline.
async fn do_handshake(
    mut stream: TcpStream,
    magic: [u8; 4],
    our: &Handshake,
    deadline: Duration,
) -> Result<(Handshake, Connection, Vec<u8>), (String, Vec<u8>)> {
    let inner = async {
        let bytes = serialize_handshake(our);
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| (format!("send handshake: {e}"), Vec::new()))?;

        let mut buf = vec![0u8; 16_384];
        let mut total = 0usize;
        loop {
            if total == buf.len() {
                return Err(("handshake exceeded read buffer".to_string(), buf.to_vec()));
            }
            let n = stream
                .read(&mut buf[total..])
                .await
                .map_err(|e| (format!("read handshake: {e}"), buf[..total].to_vec()))?;
            if n == 0 {
                return Err((
                    "connection closed during handshake".to_string(),
                    buf[..total].to_vec(),
                ));
            }
            total += n;
            match deserialize_handshake_with_consumed(&buf[..total]) {
                Ok((hs, consumed)) => {
                    let leftover = buf[consumed..total].to_vec();
                    let peer_raw = buf[..consumed].to_vec();
                    return Ok((
                        hs,
                        Connection::new_with_buffer(stream, magic, leftover),
                        peer_raw,
                    ));
                }
                Err(_) if total < 8096 => continue,
                Err(e) => return Err((format!("parse handshake: {e}"), buf[..total].to_vec())),
            }
        }
    };
    match tokio::time::timeout(deadline, inner).await {
        Ok(r) => r,
        Err(_) => Err(("handshake deadline exceeded".to_string(), Vec::new())),
    }
}

/// Helper used by the node hook and tests: type id 101/2/etc.
pub fn is_header(type_id: u8) -> bool {
    type_id == ModifierTypeId::Header.as_byte()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_set_evicts_oldest() {
        let mut set = BoundedSet::default();
        assert!(set.insert([1u8; 32]));
        assert!(!set.insert([1u8; 32]));
        assert!(set.contains(&[1u8; 32]));
    }

    #[test]
    fn byte_bucket_enforces_rate() {
        let mut b = ByteBucket::new(1000);
        assert!(b.allow(900));
        assert!(!b.allow(900));
    }

    #[test]
    fn socket_string_renders_v4_and_v6() {
        assert_eq!(socket_string(&[1, 2, 3, 4], 9030), "1.2.3.4:9030");
        assert_eq!(
            socket_string(
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                9030
            ),
            "[2001:db8:0:0:0:0:0:1]:9030"
        );
    }

    #[test]
    fn header_meta_hashes_unparseable_bytes() {
        let (id, height) = header_meta(b"not a header");
        assert_eq!(id.len(), 64);
        assert!(height.is_none());
    }

    #[test]
    fn observed_tip_tracks_highest_and_reorgs() {
        let mut seen = SharedSeen::default();
        assert!(seen.tip.is_none());
        seen.observe_header(10, [1u8; 32], b"hdr10");
        assert_eq!(seen.tip.as_ref().unwrap().height, 10);
        // A lagging peer never moves the tip backwards.
        seen.observe_header(9, [2u8; 32], b"hdr9");
        assert_eq!(seen.tip.as_ref().unwrap().id, [1u8; 32]);
        seen.observe_header(11, [3u8; 32], b"hdr11");
        assert_eq!(seen.tip.as_ref().unwrap().height, 11);
        // A same-height different id is a reorg: replace.
        seen.observe_header(11, [4u8; 32], b"hdr11b");
        let tip = seen.tip.as_ref().unwrap();
        assert_eq!(tip.id, [4u8; 32]);
        assert_eq!(tip.bytes, b"hdr11b");
    }

    #[test]
    fn sync_reply_presents_observed_tip_or_empty() {
        let empty = sync_reply_for(None);
        assert!(matches!(
            empty,
            SyncInfo::V2 { ref headers } if headers.is_empty()
        ));
        let tip = ObservedTip {
            height: 5,
            id: [7u8; 32],
            bytes: vec![9u8; 220],
        };
        match sync_reply_for(Some(&tip)) {
            SyncInfo::V2 { headers } => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0], vec![9u8; 220]);
            }
            other => panic!("expected V2, got {other:?}"),
        }
        // At/above the codec's V2 header size cap: fall back to empty.
        let big = ObservedTip {
            height: 5,
            id: [7u8; 32],
            bytes: vec![0u8; 1000],
        };
        assert!(matches!(
            sync_reply_for(Some(&big)),
            SyncInfo::V2 { ref headers } if headers.is_empty()
        ));
    }

    #[test]
    fn sync_reply_frame_round_trips() {
        let tip = ObservedTip {
            height: 5,
            id: [7u8; 32],
            bytes: vec![9u8; 220],
        };
        let payload = message::serialize_sync_info(&sync_reply_for(Some(&tip))).unwrap();
        match message::deserialize_sync_info(&payload).unwrap() {
            SyncInfo::V2 { headers } => assert_eq!(headers, vec![vec![9u8; 220]]),
            other => panic!("expected V2, got {other:?}"),
        }
    }
}
