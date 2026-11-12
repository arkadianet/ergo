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

    /// A block header arrived in a `Modifiers` message. Records receipt
    /// time for validation latency and emits the parsed height plus the
    /// id-hash cross-check.
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

    /// Record a header receipt WITHOUT emitting a `section_received`
    /// record. For headers that reach the validation pipeline without a
    /// `Modifiers` message — the `SyncInfoV2` continuation path installs
    /// the peer's continuation header straight from the sync payload —
    /// there is no Modifiers entry to report; emitting one would be
    /// schema-false. Stamping still makes `header_validated.duration_us`
    /// measurable (first sight in the sync payload → validated). First
    /// sight wins, so double-stamping from both paths is a no-op.
    pub(crate) fn header_stamped(&self, claimed: [u8; 32]) {
        Self::lock(&self.received_headers).insert_first(claimed, Instant::now());
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

#[cfg(test)]
mod hook_cost_tests {
    //! Micro-benchmark of the hook's INLINE cost on the validation and
    //! admission paths — the work the node pays per header/tx with
    //! `[observer] enabled = true`. The sink writer's I/O runs on its own
    //! task and is not part of these numbers.
    //!
    //! Run (release, so the figures represent the deployed profile):
    //! ```sh
    //! cargo test -p ergo-node --lib --release hook_cost \
    //!   -- --nocapture --test-threads=1
    //! ```

    use super::*;
    use crate::config::ObserverConfig;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::{
        ergo_box::ErgoBoxCandidate,
        ergo_tree::read_ergo_tree,
        input::{ContextExtension, Input, SpendingProof},
        register::AdditionalRegisters,
        sigma_type::SigmaType,
        sigma_value::SigmaValue,
        transaction::{write_transaction, Transaction},
    };
    use ergo_validation::fee::MAINNET_FEE_PROPOSITION_BYTES;

    /// A realistic peer tx: two inputs (one with a context extension,
    /// as most mainnet txs carry at least a small one), two outputs
    /// (one the canonical fee output). ~350 bytes on the wire.
    fn realistic_tx_bytes() -> Vec<u8> {
        let fee_tree = read_ergo_tree(&mut VlqReader::new(MAINNET_FEE_PROPOSITION_BYTES)).unwrap();
        let out_tree = read_ergo_tree(&mut VlqReader::new(MAINNET_FEE_PROPOSITION_BYTES)).unwrap();
        let ext = {
            let mut e = ContextExtension::empty();
            e.values.insert(0, (SigmaType::SInt, SigmaValue::Int(42)));
            e
        };
        let tx = Transaction {
            inputs: vec![
                Input {
                    box_id: [1u8; 32].into(),
                    spending_proof: SpendingProof::new(vec![7, 9], ext).unwrap(),
                },
                Input {
                    box_id: [2u8; 32].into(),
                    spending_proof: SpendingProof::new(vec![7, 9], ContextExtension::empty())
                        .unwrap(),
                },
            ],
            data_inputs: vec![],
            output_candidates: vec![
                ErgoBoxCandidate::from_trusted_raw_parts(
                    1_000_000,
                    fee_tree,
                    MAINNET_FEE_PROPOSITION_BYTES.to_vec(),
                    0,
                    vec![],
                    AdditionalRegisters::empty(),
                    vec![0],
                ),
                ErgoBoxCandidate::from_trusted_raw_parts(
                    40_000_000,
                    out_tree,
                    MAINNET_FEE_PROPOSITION_BYTES.to_vec(),
                    0,
                    vec![],
                    AdditionalRegisters::empty(),
                    vec![0],
                ),
            ],
        };
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        w.result()
    }

    fn cfg(dir: &std::path::Path, queue: usize) -> ObserverConfig {
        ObserverConfig {
            enabled: true,
            path: dir.join("observer.jsonl"),
            vantage: "bench".into(),
            clock_offset_ms: 0.0,
            clock_source: "unset".into(),
            queue,
            pseudonym_key: dir.join("key.hex"),
            reveal_peer_addresses: false,
        }
    }

    fn percentiles(ns: &[u64]) -> (f64, f64, f64) {
        let mut v = ns.to_vec();
        v.sort_unstable();
        let mean = v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64;
        let p50 = v[v.len() / 2] as f64;
        let p99 = v[(v.len() as f64 * 0.99) as usize] as f64;
        (mean, p50, p99)
    }

    #[test]
    fn hook_inline_cost_benchmark() {
        let dir = tempfile::tempdir().unwrap();
        // Current-thread runtime: the sink's writer task cannot run while
        // a synchronous measurement loop occupies the executor, so queue
        // overflow (and the drop path) is deterministic.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let obs = NodeObserver::from_config(&cfg(dir.path(), 100_000), "mainnet", "bench-agent", "bench")
                .unwrap()
                .unwrap();
            let peer: SocketAddr = "10.0.0.1:9030".parse().unwrap();
            let n = 20_000usize;

            // ── header_validated: stamp n unique ids, then time the
            //    callback (mutex map lookup + elapsed + hex + try_emit)
            //    for each of them.
            let ids: Vec<[u8; 32]> = (0..n as u32)
                .map(|i| {
                    let mut b = [0u8; 32];
                    b[..4].copy_from_slice(&i.to_be_bytes());
                    b
                })
                .collect();
            {
                let mut stamped = NodeObserver::lock(&obs.received_headers);
                for id in &ids {
                    stamped.insert_first(*id, Instant::now());
                }
            }
            let mut header_ns = Vec::with_capacity(n);
            for id in &ids {
                let t = Instant::now();
                obs.on_header_validated(*id, 1);
                header_ns.push(t.elapsed().as_nanos() as u64);
            }
            let (hm, hp50, hp99) = percentiles(&header_ns);

            // ── tx_outcome: the heaviest inline path — full tx parse
            //    (`tx_inputs`) + id hex-encodes + try_emit.
            let tx = realistic_tx_bytes();
            let mut tx_ns = Vec::with_capacity(n);
            for i in 0..n {
                let t = Instant::now();
                obs.tx_outcome(
                    peer,
                    TxOutcome {
                        tx_id: [i as u8; 32],
                        bytes: &tx,
                        result: "rejected",
                        reason: Some("UnresolvedInput".to_string()),
                        fee: None,
                        size: Some(tx.len() as u32),
                    },
                );
                tx_ns.push(t.elapsed().as_nanos() as u64);
            }
            let (tm, tp50, tp99) = percentiles(&tx_ns);

            // ── inv: the announce hot path (per Inv message).
            let inv_batch = |i: u32| -> Vec<[u8; 32]> {
                (0..4u8)
                    .map(|k| {
                        let mut b = [k; 32];
                        b[28..32].copy_from_slice(&i.to_be_bytes());
                        b
                    })
                    .collect()
            };
            let mut inv_ns = Vec::with_capacity(n);
            for i in 0..n as u32 {
                let batch = inv_batch(i);
                let t = Instant::now();
                obs.inv(peer, 2, &batch);
                inv_ns.push(t.elapsed().as_nanos() as u64);
            }
            let (im, ip50, ip99) = percentiles(&inv_ns);

            // ── worst case: queue full, emits take the drop path.
            // The writer task drains fast, so flood until drops are
            // guaranteed before measuring the window.
            let dir2 = tempfile::tempdir().unwrap();
            let small = NodeObserver::from_config(&cfg(dir2.path(), 64), "mainnet", "bench-agent", "bench")
                .unwrap()
                .unwrap();
            for _ in 0..10_000_000 {
                let _ = small.sink.try_emit(Event::ObserverStart {
                    network: "mainnet".into(),
                    agent: "a".into(),
                    node_name: "b".into(),
                    version: "6.0.7".into(),
                    peer_count: 0,
                    request_headers: true,
                    request_bodies: true,
                    request_txs: true,
                    outbound_bytes_per_sec: 0,
                });
                if small.dropped() >= 1_000 {
                    break;
                }
            }
            let dropped_before = small.dropped();
            let mut drop_ns = Vec::with_capacity(n);
            for _ in 0..n {
                let t = Instant::now();
                let _ = small.sink.try_emit(Event::ObserverStart {
                    network: "mainnet".into(),
                    agent: "a".into(),
                    node_name: "b".into(),
                    version: "6.0.7".into(),
                    peer_count: 0,
                    request_headers: true,
                    request_bodies: true,
                    request_txs: true,
                    outbound_bytes_per_sec: 0,
                });
                drop_ns.push(t.elapsed().as_nanos() as u64);
            }
            let (dm, dp50, dp99) = percentiles(&drop_ns);
            let dropped = small.dropped();

            println!(
                "hook inline cost (release, n={}):",
                n
            );
            println!(
                "  header_validated (mutex lookup + try_emit): mean {hm:.0} ns, p50 {hp50:.0} ns, p99 {hp99:.0} ns"
            );
            println!(
                "  tx_outcome (full tx parse + try_emit, {} B tx): mean {tm:.0} ns, p50 {tp50:.0} ns, p99 {tp99:.0} ns",
                tx.len()
            );
            println!(
                "  inv (4 ids, announce hot path): mean {im:.0} ns, p50 {ip50:.0} ns, p99 {ip99:.0} ns"
            );
            println!(
                "  try_emit worst case (queue full, drop path): mean {dm:.0} ns, p50 {dp50:.0} ns, p99 {dp99:.0} ns ({} records dropped)",
                dropped
            );
            assert!(
                dropped.saturating_sub(dropped_before) > 0,
                "the measurement window must have exercised the drop path"
            );
            // Sanity upper bounds: the hook must stay far below a single
            // mainnet header validation (~10s of ms) and below the
            // per-tx validation cost.
            assert!(hp99 < 20_000.0, "header_validated p99 ({hp99} ns) unexpectedly high");
            assert!(tp99 < 200_000.0, "tx_outcome p99 ({tp99} ns) unexpectedly high");
            assert!(ip99 < 20_000.0, "inv p99 ({ip99} ns) unexpectedly high");
        });
    }
}

#[cfg(test)]
mod hook_stamp_tests {
    //! Receipt-stamp semantics: which paths make
    //! `header_validated.duration_us` measurable, and what they (do not)
    //! record. Regression coverage for the `SyncInfoV2` continuation
    //! path, where header bytes reach the validation pipeline without a
    //! `Modifiers` message (7 of the first 40 live mainnet
    //! `header_validated` records had no `duration_us` before the
    //! stamp-only call was added to the SyncInfo dispatch arm).

    use super::*;
    use crate::config::ObserverConfig;

    fn cfg(dir: &std::path::Path) -> ObserverConfig {
        ObserverConfig {
            enabled: true,
            path: dir.join("observer.jsonl"),
            vantage: "stamp-test".into(),
            clock_offset_ms: 0.0,
            clock_source: "unset".into(),
            queue: 1024,
            pseudonym_key: dir.join("key.hex"),
            reveal_peer_addresses: false,
        }
    }

    #[test]
    fn stamp_only_makes_duration_measurable_without_section_record() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let obs = NodeObserver::from_config(&cfg(dir.path()), "mainnet", "a", "b")
                .unwrap()
                .unwrap();
            let id = [7u8; 32];

            // Unstamped: the callback still fires, with no duration.
            obs.on_header_validated(id, 1);
            // Stamp-only path (what the SyncInfo dispatch arm now does):
            // records receipt, emits nothing.
            obs.header_stamped(id);
            // Stamped: duration is now measurable.
            obs.on_header_validated(id, 1);
            // The full receipt path emits a `section_received` record.
            obs.header_received("10.0.0.9:9030".parse().unwrap(), id, &[42u8]);

            // Let the writer task drain + idle-flush (250 ms interval).
            tokio::time::sleep(std::time::Duration::from_millis(450)).await;

            let out =
                std::fs::read_to_string(dir.path().join("observer.jsonl")).expect("sink file");
            let events: Vec<String> = out
                .lines()
                .filter_map(|l| {
                    serde_json::from_str(l)
                        .ok()
                        .map(|v: serde_json::Value| v["event"].as_str().unwrap().to_string())
                })
                .collect();
            let hv: Vec<serde_json::Value> = out
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter(|v| {
                    v["event"] == "header_validated"
                        && v["header_id"] == format!("{:02x}", 7u8).repeat(32)
                })
                .collect();
            assert_eq!(hv.len(), 2, "two callback events: {events:?}");
            assert!(
                hv[0].get("duration_us").is_none(),
                "first callback unstamped: {hv:?}"
            );
            assert!(
                hv[1].get("duration_us").is_some(),
                "stamp-only must make it measurable: {hv:?}"
            );
            // The stamp-only call emitted NO section_received record;
            // exactly one exists, from `header_received`.
            let sr = events.iter().filter(|e| **e == "section_received").count();
            assert_eq!(
                sr, 1,
                "one section_received (header_received only): {events:?}"
            );
        });
    }
}
