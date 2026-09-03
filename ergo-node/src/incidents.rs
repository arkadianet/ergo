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
            // Monotonic clock for the dedupe window: a wall-clock step
            // backwards must not suppress errors until wall time catches up.
            if error_due(&code, rel_ms_now()) {
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
    // A failed write must not leave a partial JSON file for retention to
    // treat as the newest valid snapshot — remove it, and only prune older
    // files when THIS snapshot fully landed.
    let mut wrote_snapshot = false;
    for _attempt in 0..8 {
        let seq = SNAP_SEQ.fetch_add(1, Ordering::Relaxed);
        let file_name = format!("incident-{ts_unix_ms}-{seq:06}.json");
        let path = dir.join(&file_name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => match f
                .write_all(doc.to_string().as_bytes())
                .and_then(|_| f.flush())
            {
                Ok(()) => {
                    wrote_snapshot = true;
                    break;
                }
                Err(_) => {
                    let _ = fs::remove_file(&path);
                    continue;
                }
            },
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => break,
        }
    }
    if wrote_snapshot {
        enforce_retention(dir);
    }
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
    // Sort by the timestamp + sequence parsed FROM THE NAME: mtimes can
    // collide or be touched externally, and sequence suffixes are not
    // zero-padded so lexical order lies about chronology.
    fn name_key(name: &str) -> Option<(u64, u64)> {
        let stem = name.strip_prefix("incident-")?.strip_suffix(".json")?;
        let mut parts = stem.split('-');
        let ms = parts.next()?.parse::<u64>().ok()?;
        let seq = parts.next().unwrap_or("0").parse::<u64>().ok()?;
        Some((ms, seq))
    }
    while files.len() > RETAIN {
        files.sort_by_key(|(name, _)| name_key(name).unwrap_or((u64::MAX, u64::MAX)));
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

    /// The incident directory these tests share, for the life of the
    /// test binary.
    ///
    /// `INCIDENT_DIR` is a `OnceLock` — a once-at-boot call in
    /// production — so exactly ONE directory is ever active per binary.
    /// Backing it with a per-test `TempDir` raced twice over: which test
    /// won the lock, and whether that winner's `TempDir` had already
    /// dropped (deleting the directory) while another test was still
    /// polling it, which surfaced as a `NotFound` panic in whichever
    /// test lost. One directory that outlives every test removes both
    /// races; tests tell their snapshots apart by `code`, not by
    /// directory.
    static SHARED_INCIDENT_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("incident test dir"));

    /// Install the shared directory (a no-op after the first caller) and
    /// return whichever directory is actually active.
    fn shared_incident_dir() -> PathBuf {
        set_incident_dir(SHARED_INCIDENT_DIR.path().to_path_buf());
        incident_dir()
    }

    /// The marker that identifies the snapshot TRIGGERED BY `code`.
    ///
    /// Every snapshot embeds the process-global event ring, so one test's
    /// file also contains other tests' event text — a bare substring
    /// search finds the wrong file. Only the triggering snapshot carries
    /// the code unescaped at top level: ring entries are nested JSON
    /// strings, so their quotes come back escaped.
    fn snapshot_marker(code: &str) -> String {
        format!("\"code\":\"{code}\"")
    }

    /// Wait for the snapshot triggered by `code` to land in `dir`.
    fn await_snapshot(dir: &std::path::Path, code: &str) -> Option<PathBuf> {
        let marker = snapshot_marker(code);
        for _ in 0..50 {
            let found = std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .find(|path| {
                    std::fs::read_to_string(path)
                        .map(|text| text.contains(&marker))
                        .unwrap_or(false)
                });
            if found.is_some() {
                return found;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        None
    }

    #[test]
    fn error_event_triggers_snapshot_write_via_layer() {
        // The directory is shared with every other incident test (see
        // `SHARED_INCIDENT_DIR`), so identify THIS test's snapshot by its
        // own code rather than by a bare file count — a count can be
        // satisfied by a concurrent test's snapshot.
        let active_dir = shared_incident_dir();
        let code = format!("test-snapshot-{}", std::process::id());
        let subscriber = tracing_subscriber::Registry::default().with(CaptureLayer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::error!(code = %code, "injected storage failure");
        // Synchronous enough: writer thread may lag a moment.
        assert!(
            await_snapshot(&active_dir, &code).is_some(),
            "snapshot file must be written on ERROR"
        );
    }

    /// Issue #281 ask 3: a poisoned store's storage-failure ERROR event
    /// (`code = "storage_error:<store>"`, `store`, `error` — threaded onto
    /// `ergo_state::storage_observability::emit_report`'s existing
    /// `storage_io_failure` et al. for state/indexer, and emitted directly
    /// by `PeerManager::record_storage_error` for peers) reaches this
    /// generic ERROR trigger the same as any other ERROR event, so a
    /// poisoned store produces an incident snapshot with no
    /// shadow-validation dependency. The snapshot content proves the
    /// `store` / `error` fields survive into the forensic file.
    #[test]
    fn storage_error_event_triggers_incident_snapshot() {
        // Shared with the other incident tests, and outliving all of
        // them — see `SHARED_INCIDENT_DIR`. This test already identifies
        // its own snapshot by `code`, so sharing costs it nothing.
        let active_dir = shared_incident_dir();
        let subscriber = tracing_subscriber::Registry::default().with(CaptureLayer);
        let _guard = tracing::subscriber::set_default(subscriber);
        // Real shape production emits (`ergo_state::storage_observability::
        // emit_report`): the pre-existing `storage_io_failure` /
        // `storage_health_transition` / `storage_operation_failed` event
        // names are unchanged (tests elsewhere pin the exact event count
        // per failure), with `code` + `store` now threaded onto them.
        let code = format!("storage_error:state-probe-{}", std::process::id());
        tracing::error!(
            event = "storage_io_failure",
            code = %code,
            store = "state",
            error = "Previous I/O error occurred. Please close and re-open the database.",
            "storage operation failed",
        );
        let path = await_snapshot(&active_dir, &code)
            .expect("storage_error must trigger an incident snapshot");
        let text = std::fs::read_to_string(path).unwrap();
        // Top-level `incident.code` is written directly from the dedupe
        // key, so it's unescaped JSON; the triggering event itself lives
        // inside the `events` array as a nested JSON-*string*, so its
        // fields (`store`, `error`) come back with their quotes escaped.
        assert!(text.contains(&format!("\"code\":\"{code}\"")));
        assert!(text.contains(r#"\"store\":\"state\""#));
        assert!(text.contains("Previous I/O error occurred"));
    }
}
