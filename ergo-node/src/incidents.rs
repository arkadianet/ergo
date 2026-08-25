//! Incident snapshots — the forensics capstone of the logging overhaul
//! (`dev-docs/logging-overhaul-DESIGN.md` §4).
//!
//! A bounded ring captures structured events at INFO and above (the
//! minute-cadence gauge lines included). The first ERROR carrying a new
//! `code` within the dedupe window triggers a **snapshot**: the ring,
//! latest gauges, RSS, and build metadata written as one self-contained
//! JSON file under `<data_dir>/incidents/`. Operators attach that single
//! file to a bug report instead of shipping rotated logs.
//!
//! v1 scope notes (documented deviations from the design doc): snapshots
//! are plain `.json`, not gzip (avoids a new dependency); the manual
//! operator endpoint is deferred. Retention keeps the newest
//! [`RETAIN`] files.

use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Ring capacity: ~500 structured events is minutes-to-hours of context
/// at INFO volume and costs well under 1 MiB.
const RING_CAP: usize = 500;
/// One automatic snapshot per error `code` per this window; repeated
/// identical failures extend the existing evidence rather than spamming
/// new files.
const ERROR_DEDUPE_WINDOW_MS: u64 = 300_000;
/// Snapshot files retained per directory.
const RETAIN: usize = 10;

static RING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
static LAST_ERROR_MS: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_GAUGES: Mutex<Option<String>> = Mutex::new(None);
static INCIDENT_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Anchor for monotonic-clock → unix-ms conversions used in file names
/// and event timestamps.
/// Monotonic suffix for snapshot file names: two ERROR codes can trigger
/// on separate threads within the same millisecond, and `File::create`
/// would silently truncate the first snapshot. Pairing unix-ms with this
/// sequence makes every file name unique.
static SNAP_SEQ: AtomicU64 = AtomicU64::new(0);

static BASE: OnceLock<Instant> = OnceLock::new();
fn base() -> Instant {
    *BASE.get_or_init(Instant::now)
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn rel_ms_now() -> u64 {
    Instant::now().duration_since(base()).as_millis() as u64
}

/// Point the snapshot writer at `<data_dir>/incidents`. Called once at
/// boot once the data dir is resolved; before that, snapshots land in
/// `./incidents`.
pub fn set_incident_dir(dir: PathBuf) {
    let _ = INCIDENT_DIR.set(dir);
}

fn incident_dir() -> PathBuf {
    INCIDENT_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("./incidents"))
}

/// Record the latest gauge-line values so snapshots carry attribution
/// even when captured between gauge ticks. Called from the sync tick
/// immediately after the `node_gauges` INFO event.
pub fn set_last_gauges(gauges_json: String) {
    if let Ok(mut g) = LAST_GAUGES.lock() {
        *g = Some(gauges_json);
    }
}

fn push_event(line: String) {
    if let Ok(mut ring) = RING.lock() {
        ring.push_back(line);
        while ring.len() > RING_CAP {
            ring.pop_front();
        }
    }
}

fn clone_ring() -> Vec<String> {
    RING.lock()
        .map(|r| r.iter().cloned().collect())
        .unwrap_or_default()
}

// ---- tracing layer ----

struct FieldCollector {
    fields: serde_json::Map<String, serde_json::Value>,
}

impl Visit for FieldCollector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.insert(field.name().to_string(), value.into());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.insert(field.name().to_string(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.insert(field.name().to_string(), value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.insert(field.name().to_string(), value.into());
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.fields.insert(field.name().to_string(), value.into());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            // The interpolated message arrives as a Debug-recorded
            // "message" field; keep it human-readable.
            "message" => {
                self.fields.insert(
                    "message".to_string(),
                    serde_json::Value::String(format!("{value:?}")),
                );
            }
            _ => {
                self.fields.insert(
                    field.name().to_string(),
                    serde_json::Value::String(format!("{value:?}")),
                );
            }
        }
    }
}

/// Layer capturing INFO-and-above events into the bounded ring, and
/// triggering snapshots on first-sight ERRORs. Install once.
pub struct CaptureLayer;

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // INFO-and-above only (design contract): DEBUG/TRACE mechanics
        // stay out of the forensic ring regardless of output-layer filters.
        if matches!(event.metadata().level(), &Level::TRACE | &Level::DEBUG) {
            return;
        }
        let mut collector = FieldCollector {
            fields: serde_json::Map::new(),
        };
        event.record(&mut collector);

        let mut obj = serde_json::Map::new();
        obj.insert("ts_unix_ms".into(), unix_ms_now().into());
        obj.insert("rel_ms".into(), rel_ms_now().into());
        obj.insert(
            "level".into(),
            match *event.metadata().level() {
                Level::ERROR => "ERROR",
                Level::WARN => "WARN",
                Level::INFO => "INFO",
                Level::DEBUG => "DEBUG",
                Level::TRACE => "TRACE",
            }
            .into(),
        );
        obj.insert("target".into(), event.metadata().target().into());
        for (k, v) in collector.fields {
            obj.insert(k, v);
        }

        if *event.metadata().level() == Level::ERROR {
            let meta = event.metadata();
            let message = obj
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let code = obj
                .get("code")
                .and_then(|c| c.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("{}|{}", meta.target(), message));
            // Dedupe decision on the emitting thread (cheap map ops).
            if error_due(&code, unix_ms_now()) {
                // Push FIRST so the ring snapshot includes the triggering
                // event itself (message, target, structured fields).
                let line = serde_json::Value::Object(obj.clone()).to_string();
                push_event(line);
                let events = clone_ring();
                let gauges = LAST_GAUGES
                    .lock()
                    .ok()
                    .and_then(|g| g.clone())
                    .unwrap_or_else(|| "null".into());
                let dir = incident_dir();
                // Synchronous write: the payload is small (<1 MiB) and
                // errors are rare — blocking briefly here guarantees the
                // evidence survives even an immediate process::exit on the
                // fatal path (no detached-writer flush problem).
                write_snapshot(&dir, unix_ms_now(), &code, &events, &gauges);
                return;
            }
        }

        let line = serde_json::Value::Object(obj).to_string();
        push_event(line);
    }
}

fn error_due(code: &str, now_ms: u64) -> bool {
    let mut last = LAST_ERROR_MS.lock().expect("incident dedupe poisoned");
    // A never-seen code is ALWAYS due — the zero default must not read
    // as "seen within the window".
    let due = match last.get(code) {
        None => true,
        Some(&t) => now_ms.saturating_sub(t) >= ERROR_DEDUPE_WINDOW_MS,
    };
    if due {
        last.insert(code.to_string(), now_ms);
    }
    due
}

fn write_snapshot(dir: &PathBuf, ts_unix_ms: u64, code: &str, events: &[String], gauges: &str) {
    use std::fs;
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let rss_kb = {
        #[cfg(target_os = "linux")]
        {
            fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status.lines().find_map(|l| {
                        l.strip_prefix("VmRSS:")
                            .and_then(|rest| rest.split_whitespace().next())
                            .and_then(|v| v.parse::<u64>().ok())
                    })
                })
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0u64
        }
    };
    let doc = json!({
        "incident": {
            "code": code,
            "ts_unix_ms": ts_unix_ms,
            "version": env!("CARGO_PKG_VERSION"),
            "rss_kb": rss_kb,
        },
        "last_gauges": serde_json::from_str::<serde_json::Value>(gauges)
            .unwrap_or(serde_json::Value::Null),
        "events": events,
    });
    // Collision-safe name: unix-ms + monotonic sequence, created
    // atomically (create_new) so two concurrent triggers can never
    // truncate each other's snapshot.
    use std::io::ErrorKind;
    for _attempt in 0..8 {
        let seq = SNAP_SEQ.fetch_add(1, Ordering::Relaxed);
        let file_name = format!("incident-{ts_unix_ms}-{seq:06}.json");
        let path = dir.join(&file_name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                let body = doc.to_string();
                let _ = f.write_all(body.as_bytes());
                break;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => break,
        }
    }
    enforce_retention(dir);
}

/// Keep the newest [`RETAIN`] `incident-*.json` files.
fn enforce_retention(dir: &PathBuf) {
    use std::fs;
    let mut files: Vec<(String, fs::Metadata)> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("incident-") && name.ends_with(".json") {
                    e.metadata().ok().map(|m| (name, m))
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => return,
    };
    // Sequence suffixes are not zero-padded, so lexical name order is no
    // longer chronological — sort by modification time instead.
    while files.len() > RETAIN {
        files.sort_by_key(|(_, m)| m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH));
        let oldest = files.remove(0);
        let _ = fs::remove_file(dir.join(&oldest.0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn error_dedupe_window_latches_then_expires() {
        let code = format!("test-dedupe-{}", std::process::id());
        assert!(error_due(&code, 1_000), "first sight is due");
        assert!(!error_due(&code, 1_000 + 1), "inside window suppressed");
        assert!(
            error_due(&code, 1_000 + ERROR_DEDUPE_WINDOW_MS),
            "window expiry re-triggers"
        );
    }

    #[test]
    fn write_snapshot_produces_selfcontained_file_and_retains_ten() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().to_path_buf();
        for i in 0..12u64 {
            let ts = 1_700_000_000_000u64 + i * 1_000;
            write_snapshot(
                &dir_path,
                ts,
                &format!("code-{i}"),
                &[format!("{{\"rel_ms\":{i},\"level\":\"ERROR\"}}")],
                "{\"peers\":3}",
            );
        }
        let count = std::fs::read_dir(&dir_path)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("incident-")
            })
            .count();
        assert!(count <= RETAIN, "retention must prune, got {count}");
        // Newest file (by modification time — sequence suffixes are not
        // zero-padded) carries its own code + gauges + events arrays.
        let mut snaps: Vec<(std::path::PathBuf, std::fs::Metadata)> = std::fs::read_dir(&dir_path)
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                let name = p.file_name()?.to_string_lossy().to_string();
                if name.starts_with("incident-") && name.ends_with(".json") {
                    Some((p.clone(), p.metadata().unwrap()))
                } else {
                    None
                }
            })
            .collect();
        snaps.sort_by_key(|(_, m)| m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH));
        assert_eq!(snaps.len(), RETAIN, "retention must prune");
        let text = std::fs::read_to_string(&snaps.last().unwrap().0).unwrap();
        assert!(text.contains("\"code\":\"code-11\""));
        assert!(text.contains("\"last_gauges\":{\"peers\":3}"));
        assert!(text.contains("\"events\":["));
    }

    #[test]
    fn layer_captures_info_events_with_fields_into_bounded_ring() {
        let subscriber = tracing_subscriber::Registry::default().with(CaptureLayer);
        let _guard = tracing::subscriber::set_default(subscriber);
        for i in 0..(RING_CAP + 10) {
            tracing::info!(i = i, "probe event");
        }
        let ring = clone_ring();
        assert_eq!(ring.len(), RING_CAP, "ring must be capped");
        assert!(ring.last().unwrap().contains("probe event"));
        assert!(ring.last().unwrap().contains("\"level\":\"INFO\""));
    }

    #[test]
    fn error_event_triggers_snapshot_write_via_layer() {
        let dir = tempfile::tempdir().unwrap();
        set_incident_dir(dir.path().to_path_buf());
        let subscriber = tracing_subscriber::Registry::default().with(CaptureLayer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let before = std::fs::read_dir(dir.path()).unwrap().count();
        tracing::error!(code = "test-snapshot", "injected storage failure");
        // Synchronous enough: writer thread may lag a moment.
        for _ in 0..50 {
            let count = std::fs::read_dir(dir.path()).unwrap().count();
            if count > before {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let after = std::fs::read_dir(dir.path()).unwrap().count();
        assert!(after > before, "snapshot file must be written on ERROR");
    }
}
