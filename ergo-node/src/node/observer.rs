//! Phase 0 node-side observer hook.
//!
//! Disabled unless `[observer] enabled = true`. When enabled it feeds the
//! same bounded, non-blocking `ergo-net-observe` sink the standalone
//! observer uses, adding data only a validating node has:
//!
//! * transaction announce/request/receive, with the mempool admission
//!   outcome and reason (including `UnresolvedInput`, which is how a
//!   child-before-parent arrival shows up);
//! * transaction input ids, so rejections can be joined to later-arriving
//!   parents;
//! * header receipt → validation timing;
//! * full-block apply latency from the first observed announce.
//!
//! Nothing here changes admission, sync, relay, or consensus behaviour.
//! Every emit is `try_send`: a full queue drops the record and increments
//! a counter the writer turns into a `gap` line.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ergo_net_observe::{Event, ObserverSink, PeerRef, Pseudonymizer, SinkConfig};
use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{header_id_from_bytes, read_header};
use ergo_ser::transaction::read_transaction;
use ergo_sync::executor::ValidationObserver;

use crate::config::ObserverConfig;

/// Bound on remembered announce/receipt times. At mainnet rates this is
/// many hours of headers and transactions; older entries only lose the
/// ability to report `since_first_announce`, never correctness.
const TIME_MAP_LIMIT: usize = 32_768;

struct TimedIds {
    times: HashMap<[u8; 32], Instant>,
    order: VecDeque<[u8; 32]>,
}

impl TimedIds {
    fn new() -> Self {
        Self {
            times: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Record `id` only if absent; returns `true` on first sight.
    fn insert_first(&mut self, id: [u8; 32], at: Instant) -> bool {
        if self.times.contains_key(&id) {
            return false;
        }
        self.times.insert(id, at);
        self.order.push_back(id);
        while self.order.len() > TIME_MAP_LIMIT {
            if let Some(old) = self.order.pop_front() {
                self.times.remove(&old);
            }
        }
        true
    }

    fn get(&self, id: &[u8; 32]) -> Option<Instant> {
        self.times.get(id).copied()
    }
}

/// Inputs to [`NodeObserver::tx_outcome`]. Bundled so the call site reads
/// as one record rather than a long positional list.
pub(crate) struct TxOutcome<'a> {
    pub tx_id: [u8; 32],
    pub bytes: &'a [u8],
    /// `admitted` or `rejected`.
    pub result: &'a str,
    pub reason: Option<String>,
    pub fee: Option<u64>,
    pub size: Option<u32>,
}

pub(crate) struct NodeObserver {
    sink: ObserverSink,
    received_headers: Mutex<TimedIds>,
    announced: Mutex<TimedIds>,
    /// Transactions already announced through this hook, so a repeated Inv
    /// does not inflate `first_global`.
    announced_txs: Mutex<TimedIds>,
    request_seq: AtomicU64,
}

impl NodeObserver {
    /// Build the sink when `[observer] enabled = true`. Must run inside a
    /// Tokio runtime (the sink spawns its writer task).
    pub(crate) fn from_config(
        cfg: &ObserverConfig,
        network: &str,
        agent_name: &str,
        node_name: &str,
    ) -> std::io::Result<Option<Arc<Self>>> {
        if !cfg.enabled {
            return Ok(None);
        }
        let pseudonymizer =
            Pseudonymizer::from_key_file(&cfg.pseudonym_key, !cfg.reveal_peer_addresses)?;
        let sink = ObserverSink::spawn(SinkConfig {
            vantage: cfg.vantage.clone(),
            clock_offset_ms: cfg.clock_offset_ms,
            clock_source: cfg.clock_source.clone(),
            path: cfg.path.clone(),
            queue: cfg.queue,
            pseudonymizer,
        })?;
        sink.try_emit(Event::ObserverStart {
            network: network.to_string(),
            agent: agent_name.to_string(),
            node_name: node_name.to_string(),
            version: ergo_p2p::handshake::Version::CURRENT.to_string(),
            peer_count: 0,
            request_headers: true,
            request_bodies: true,
            request_txs: true,
            outbound_bytes_per_sec: 0,
        });
        Ok(Some(Arc::new(Self {
            sink,
            received_headers: Mutex::new(TimedIds::new()),
            announced: Mutex::new(TimedIds::new()),
            announced_txs: Mutex::new(TimedIds::new()),
            request_seq: AtomicU64::new(0),
        })))
    }

    fn peer(&self, peer: SocketAddr) -> PeerRef {
        self.sink
            .peer_ref(&peer.to_string(), None, None, None, Some("peer"))
    }

    fn lock(map: &Mutex<TimedIds>) -> std::sync::MutexGuard<'_, TimedIds> {
        match map.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Record an `Inv` announcement. `first_global` counts ids this node
    /// had not seen before; the event is emitted for every non-empty Inv
    /// so receive order is preserved in the dataset.
    pub(crate) fn inv(&self, peer: SocketAddr, type_id: u8, ids: &[[u8; 32]]) {
        if ids.is_empty() {
            return;
        }
        let now = Instant::now();
        let map = if type_id == 2 {
            &self.announced_txs
        } else {
            &self.announced
        };
        let first_global = {
            let mut announced = Self::lock(map);
            ids.iter()
                .filter(|id| announced.insert_first(**id, now))
                .count()
        };
        self.sink.try_emit_peer(
            self.peer(peer),
            Event::Announce {
                via: "inv".to_string(),
                type_id,
                count: ids.len(),
                ids: ids.iter().map(hex::encode).collect(),
                heights: Vec::new(),
                first_global,
                first_for_peer: 0,
            },
        );
    }

    /// Record and emit a `SyncInfo` header announcement. V2 carries full
    /// headers, so heights and ids come from the bytes; V1 carries only
    /// ids.
    pub(crate) fn sync_info(&self, peer: SocketAddr, info: &ergo_p2p::message::SyncInfo) {
        let now = Instant::now();
        let (via, ids, heights) = match info {
            ergo_p2p::message::SyncInfo::V1 { header_ids } => {
                ("syncinfo_v1", header_ids.clone(), Vec::new())
            }
            ergo_p2p::message::SyncInfo::V2 { headers } => {
                let mut ids = Vec::with_capacity(headers.len());
                let mut heights = Vec::new();
                for bytes in headers {
                    let id = header_id_from_bytes(bytes)
                        .map(|d| *d.as_bytes())
                        .unwrap_or_else(|_| *blake2b256(bytes).as_bytes());
                    ids.push(id);
                    if let Ok(header) = read_header(&mut VlqReader::new(bytes)) {
                        heights.push(header.height);
                    }
                }
                ("syncinfo_v2", ids, heights)
            }
        };
        if ids.is_empty() {
            return;
        }
        let first_global = {
            let mut announced = Self::lock(&self.announced);
            ids.iter()
                .filter(|id| announced.insert_first(**id, now))
                .count()
        };
        self.sink.try_emit_peer(
            self.peer(peer),
            Event::Announce {
                via: via.to_string(),
                type_id: 101,
                count: ids.len(),
                ids: ids.iter().map(hex::encode).collect(),
                heights,
                first_global,
                first_for_peer: 0,
            },
        );
    }

    /// Emit the exact ids a `RequestModifier` frame asked for.
    pub(crate) fn requested(&self, peer: SocketAddr, type_id: u8, ids: &[[u8; 32]]) {
        if ids.is_empty() {
            return;
        }
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed);
        self.sink.try_emit_peer(
            self.peer(peer),
            Event::RequestSent {
                seq,
                type_id,
                ids: ids.iter().map(hex::encode).collect(),
            },
        );
    }

    /// A transaction section arrived. Emitted before admission so arrival
    /// order is recorded even when admission later rejects it.
    pub(crate) fn tx_received(
        &self,
        peer: SocketAddr,
        id: [u8; 32],
        bytes: &[u8],
        solicited: bool,
    ) {
        self.sink.try_emit_peer(
            self.peer(peer),
            Event::SectionReceived {
                type_id: 2,
                id: hex::encode(id),
                bytes: bytes.len(),
                seq: None,
                solicited,
                height: None,
                computed_id: None,
                id_matches: None,
            },
        );
    }

    /// A block header arrived. Records receipt time for validation latency
    /// and emits the parsed height plus the id-hash cross-check.
    pub(crate) fn header_received(&self, peer: SocketAddr, claimed: [u8; 32], bytes: &[u8]) {
        let now = Instant::now();
        Self::lock(&self.received_headers).insert_first(claimed, now);
        let (height, computed_id) = header_meta(bytes);
        self.sink.try_emit_peer(
            self.peer(peer),
            Event::SectionReceived {
                type_id: 101,
                id: hex::encode(claimed),
                bytes: bytes.len(),
                seq: None,
                solicited: true,
                height,
                id_matches: computed_id.as_ref().map(|c| c == &hex::encode(claimed)),
                computed_id,
            },
        );
    }

    /// Mempool outcome for a peer-sourced transaction.
    pub(crate) fn tx_outcome(&self, peer: SocketAddr, outcome: TxOutcome<'_>) {
        let (input_ids, data_input_ids) = tx_inputs(outcome.bytes);
        self.sink.try_emit_peer(
            self.peer(peer),
            Event::TxOutcome {
                tx_id: hex::encode(outcome.tx_id),
                result: outcome.result.to_string(),
                reason: outcome.reason,
                fee: outcome.fee,
                size: outcome.size,
                source: "peer".to_string(),
                input_ids,
                data_input_ids,
            },
        );
    }

    /// A full block applied at the tip. `height` comes from the caller's
    /// header lookup; `since_first_announce_us` is absent when the announce
    /// predates this process or fell out of the bounded map.
    pub(crate) fn block_applied(&self, id: [u8; 32], height: u32) {
        let since = Self::lock(&self.announced)
            .get(&id)
            .map(|t| t.elapsed().as_micros() as u64);
        self.sink.try_emit(Event::BlockApplied {
            header_id: hex::encode(id),
            height,
            since_first_announce_us: since,
        });
    }

    /// Number of records dropped under backpressure since process start.
    pub(crate) fn dropped(&self) -> u64 {
        self.sink.dropped()
    }
}

impl ValidationObserver for NodeObserver {
    fn on_header_validated(&self, header_id: [u8; 32], _height: u32) {
        let received = Self::lock(&self.received_headers).get(&header_id);
        let duration_us = received.map(|t| t.elapsed().as_micros() as u64);
        self.sink.try_emit(Event::HeaderValidated {
            header_id: hex::encode(header_id),
            result: "valid".to_string(),
            duration_us,
        });
    }
}

/// Compute a transaction id from wire bytes. Returns `None` when the
/// parser rejects the bytes (admission would have rejected them too).
pub(crate) fn tx_id_of(bytes: &[u8]) -> Option<[u8; 32]> {
    let tx = read_transaction(&mut VlqReader::new(bytes)).ok()?;
    let id = ergo_ser::transaction::transaction_id(&tx).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(id.as_bytes());
    Some(out)
}

fn header_meta(bytes: &[u8]) -> (Option<u32>, Option<String>) {
    let computed = header_id_from_bytes(bytes)
        .ok()
        .map(|d| hex::encode(d.as_bytes()))
        .or_else(|| Some(hex::encode(blake2b256(bytes).as_bytes())));
    let height = read_header(&mut VlqReader::new(bytes))
        .ok()
        .map(|h| h.height);
    (height, computed)
}

/// Parse input and data-input box ids. Returns empty vectors on parse
/// failure: the outcome record still carries the tx id and rejection
/// reason.
fn tx_inputs(bytes: &[u8]) -> (Vec<String>, Vec<String>) {
    let Ok(tx) = read_transaction(&mut VlqReader::new(bytes)) else {
        return (Vec::new(), Vec::new());
    };
    let inputs = tx
        .inputs
        .iter()
        .map(|i| hex::encode(i.box_id.as_bytes()))
        .collect();
    let data = tx
        .data_inputs
        .iter()
        .map(|i| hex::encode(i.box_id.as_bytes()))
        .collect();
    (inputs, data)
}

impl std::fmt::Debug for NodeObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeObserver")
            .field("dropped", &self.dropped())
            .finish()
    }
}
