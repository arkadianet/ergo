//! Bounded, non-blocking JSONL sink.
//!
//! Observation must never backpressure consensus or the peer read loop.
//! [`ObserverSink::try_emit`] uses a bounded `try_send`: when the writer is
//! behind, the record is dropped and counted. The writer emits a `gap`
//! record on its next successful line so the dataset says how much was lost.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use crate::pseudonym::Pseudonymizer;
use crate::record::{BlockRef, Envelope, Event, PeerRef, SCHEMA};

/// Static metadata written on every record.
#[derive(Debug, Clone)]
pub struct SinkConfig {
    pub vantage: String,
    pub clock_offset_ms: f64,
    pub clock_source: String,
    pub path: std::path::PathBuf,
    /// Bounded queue depth. 8192 lines is a few MiB at most.
    pub queue: usize,
    pub pseudonymizer: Pseudonymizer,
}

impl SinkConfig {
    pub fn new(path: impl Into<std::path::PathBuf>, vantage: impl Into<String>) -> Self {
        Self {
            vantage: vantage.into(),
            clock_offset_ms: 0.0,
            clock_source: "unset".to_string(),
            path: path.into(),
            queue: 8192,
            pseudonymizer: Pseudonymizer::from_key([0u8; 32], true),
        }
    }
}

#[derive(Clone)]
struct Common {
    vantage: String,
    clock_offset_ms: f64,
    clock_source: String,
    start: Instant,
    pseudonymizer: Pseudonymizer,
}

/// Cloneable handle used by the peer task and the node hook.
#[derive(Clone)]
pub struct ObserverSink {
    tx: mpsc::Sender<Envelope>,
    dropped: Arc<AtomicU64>,
    common: Arc<Common>,
}

impl ObserverSink {
    /// Open `cfg.path` for append and spawn the writer task.
    ///
    /// Must be called from inside a Tokio runtime.
    pub fn spawn(cfg: SinkConfig) -> std::io::Result<Self> {
        let path = cfg.path.clone();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let (tx, rx) = mpsc::channel(cfg.queue.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let common = Arc::new(Common {
            vantage: cfg.vantage,
            clock_offset_ms: cfg.clock_offset_ms,
            clock_source: cfg.clock_source,
            start: Instant::now(),
            pseudonymizer: cfg.pseudonymizer,
        });
        tokio::spawn(writer_task(
            rx,
            BufWriter::new(file),
            dropped.clone(),
            common.clone(),
        ));
        Ok(Self {
            tx,
            dropped,
            common,
        })
    }

    /// Build a peer reference from the raw address and handshake/session
    /// fields. The address is pseudonymised by the configured key.
    pub fn peer_ref(
        &self,
        addr: &str,
        agent: Option<&str>,
        version: Option<&str>,
        node_name: Option<&str>,
        direction: Option<&str>,
    ) -> PeerRef {
        let enabled = self.common.pseudonymizer.enabled();
        PeerRef {
            id: self.common.pseudonymizer.peer_id(addr),
            addr: if enabled {
                None
            } else {
                Some(addr.to_string())
            },
            agent: agent.map(str::to_string),
            version: version.map(str::to_string),
            node_name: node_name.map(str::to_string),
            direction: direction.map(str::to_string),
        }
    }

    /// Pseudonymise an address without building a `PeerRef` (gossip lists).
    pub fn peer_id(&self, addr: &str) -> String {
        self.common.pseudonymizer.peer_id(addr)
    }

    /// Non-blocking emit. Returns `false` when the record was dropped.
    pub fn try_emit(&self, event: Event) -> bool {
        self.try_emit_with(None, None, event)
    }

    pub fn try_emit_peer(&self, peer: PeerRef, event: Event) -> bool {
        self.try_emit_with(Some(peer), None, event)
    }

    pub fn try_emit_block(&self, block: BlockRef, event: Event) -> bool {
        self.try_emit_with(None, Some(block), event)
    }

    pub fn try_emit_peer_block(&self, peer: PeerRef, block: BlockRef, event: Event) -> bool {
        self.try_emit_with(Some(peer), Some(block), event)
    }

    fn try_emit_with(&self, peer: Option<PeerRef>, block: Option<BlockRef>, event: Event) -> bool {
        let envelope = Envelope {
            schema: SCHEMA,
            vantage: self.common.vantage.clone(),
            wall_ms: unix_ms(),
            mono_ns: self.common.start.elapsed().as_nanos() as u64,
            clock_offset_ms: self.common.clock_offset_ms,
            clock_source: self.common.clock_source.clone(),
            peer,
            block,
            event,
        };
        match self.tx.try_send(envelope) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Number of records dropped so far. Exposed for the operator log.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

async fn writer_task(
    mut rx: mpsc::Receiver<Envelope>,
    mut out: BufWriter<std::fs::File>,
    dropped: Arc<AtomicU64>,
    common: Arc<Common>,
) {
    // Batch flushes for throughput, but also flush when the stream goes
    // quiet so a crashed or idle observer still leaves readable records.
    let mut since_flush = 0usize;
    let mut idle = tokio::time::interval(std::time::Duration::from_millis(250));
    idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(envelope) = maybe else { break };
                let lost = dropped.swap(0, Ordering::Relaxed);
                if lost > 0 {
                    let gap = Envelope {
                        schema: SCHEMA,
                        vantage: common.vantage.clone(),
                        wall_ms: unix_ms(),
                        mono_ns: common.start.elapsed().as_nanos() as u64,
                        clock_offset_ms: common.clock_offset_ms,
                        clock_source: common.clock_source.clone(),
                        peer: None,
                        block: None,
                        event: Event::Gap { dropped: lost },
                    };
                    if write_line(&mut out, &gap).is_err() {
                        break;
                    }
                }
                if write_line(&mut out, &envelope).is_err() {
                    break;
                }
                since_flush += 1;
                if since_flush >= 64 {
                    since_flush = 0;
                    if out.flush().is_err() {
                        break;
                    }
                }
            }
            _ = idle.tick() => {
                if since_flush > 0 {
                    since_flush = 0;
                    if out.flush().is_err() {
                        break;
                    }
                }
            }
        }
    }
    let _ = out.flush();
}

fn write_line(out: &mut BufWriter<std::fs::File>, envelope: &Envelope) -> std::io::Result<()> {
    serde_json::to_writer(&mut *out, envelope)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    out.write_all(b"\n")
}

pub(crate) fn unix_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(_) => 0,
    }
}

/// Path helper used by the CLI and tests.
pub fn default_output(dir: &Path) -> std::path::PathBuf {
    dir.join("observer.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn writes_one_line_per_record_and_survives_saturation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        let sink = ObserverSink::spawn(SinkConfig {
            queue: 1,
            ..SinkConfig::new(&path, "test")
        })
        .unwrap();
        for i in 0..100u64 {
            // Saturation is expected; the call must return, not block.
            let _ = sink.try_emit(Event::Note {
                message: format!("n{i}"),
            });
        }
        // Let the writer drain; no sleep-free way to wait for a detached
        // task, so yield a bounded number of times.
        for _ in 0..1000 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
            if sink.dropped() == 0 {
                break;
            }
        }
        // Force one more record so the gap line is written.
        while !sink.try_emit(Event::Note {
            message: "tail".into(),
        }) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // The writer flushes within one idle tick (250 ms); allow margin.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.lines().count() >= 2, "expected records, got: {text}");
        assert!(text.contains("\"schema\":\"ergo-observer/1\""));
        for line in text.lines() {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[tokio::test]
    async fn peer_refs_are_pseudonymised_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        let sink = ObserverSink::spawn(SinkConfig::new(&path, "test")).unwrap();
        let peer = sink.peer_ref(
            "203.0.113.7:9030",
            Some("ergoref"),
            Some("6.0.7"),
            None,
            Some("out"),
        );
        assert_eq!(peer.id.len(), 32);
        assert!(peer.addr.is_none());
        assert!(sink.try_emit_peer(
            peer,
            Event::ConnOpen {
                direction: "out".into()
            }
        ));
        tokio::time::sleep(Duration::from_millis(400)).await;
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("203.0.113.7"), "{text}");
        assert!(text.contains("\"event\":\"conn_open\""));
    }
}
