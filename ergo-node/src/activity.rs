//! Recent structured logs for the operator UI. Independent of browser lifetime.
//! Strict count/byte bounds; no disk I/O, tracing, or waiting on the emitting
//! thread. Rotated file logs remain the durable, full-fidelity archive.
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use ergo_api::types::{ApiActivityPage, ApiActivityRecord};
use serde_json::{Map, Value};

const CAP: usize = 2048;
const BYTE_CAP: usize = 4 * 1024 * 1024;
static DROPPED: AtomicU64 = AtomicU64::new(0);
static HISTORY: LazyLock<Mutex<History>> = LazyLock::new(|| Mutex::new(History::new()));

struct History {
    session: String,
    seq: u64,
    bytes: usize,
    records: VecDeque<(u64, usize, ApiActivityRecord)>,
}

impl History {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self {
            session: format!("{nanos:x}-{:x}", std::process::id()),
            seq: 0,
            bytes: 0,
            records: VecDeque::new(),
        }
    }

    fn push(&mut self, mut record: ApiActivityRecord) {
        self.seq += 1;
        record.seq = self.seq.to_string();
        let bytes = serde_json::to_vec(&record).map(|v| v.len()).unwrap_or(0);
        self.bytes += bytes;
        self.records.push_back((self.seq, bytes, record));
        while self.records.len() > CAP || self.bytes > BYTE_CAP {
            if let Some((_, bytes, _)) = self.records.pop_front() {
                self.bytes -= bytes;
            }
        }
    }

    fn page(&self, session: Option<&str>, since: u64, limit: usize) -> ApiActivityPage {
        let reset = session.is_some_and(|s| s != self.session) || since > self.seq;
        let since = if reset { 0 } else { since };
        let oldest = self.records.front().map(|r| r.0).unwrap_or(0);
        let records: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.0 > since)
            .take(limit.clamp(1, 500))
            .map(|r| r.2.clone())
            .collect();
        let next = records
            .last()
            .and_then(|r| r.seq.parse::<u64>().ok())
            .unwrap_or(since);
        ApiActivityPage {
            session_id: self.session.clone(),
            oldest_seq: oldest.to_string(),
            latest_seq: self.seq.to_string(),
            next_seq: next.to_string(),
            has_more: next < self.seq,
            gap: since > 0 && since < oldest.saturating_sub(1),
            reset,
            capacity: CAP,
            byte_capacity: BYTE_CAP,
            retained: self.records.len(),
            dropped_total: DROPPED.load(Ordering::Relaxed).to_string(),
            records,
        }
    }
}

fn clip(s: &str, cap: usize, truncated: &mut bool) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    *truncated = true;
    let mut end = cap;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase().replace(['-', '_'], "");
    name.contains("password")
        || name.contains("passphrase")
        || name.contains("secret")
        || name.contains("mnemonic")
        || name.contains("privatekey")
        || matches!(
            name.as_str(),
            "pass"
                | "seed"
                | "seedbytes"
                | "apikey"
                | "apikeyhash"
                | "authorization"
                | "cookie"
                | "xprv"
        )
}

fn bounded_record(obj: &Map<String, Value>) -> ApiActivityRecord {
    let mut truncated = false;
    let mut fields = BTreeMap::new();
    for (name, value) in obj {
        if matches!(
            name.as_str(),
            "ts_unix_ms" | "rel_ms" | "level" | "target" | "message"
        ) {
            continue;
        }
        if fields.len() == 32 {
            truncated = true;
            break;
        }
        let value = if sensitive(name) {
            Value::String("[redacted]".into())
        } else {
            match value {
                Value::String(s) => Value::String(clip(s, 1024, &mut truncated)),
                Value::Number(_) | Value::Bool(_) | Value::Null => value.clone(),
                // Capture fields are scalars. Never expose arbitrary nested structures
                // (which could bypass field redaction or the size bound).
                _ => {
                    truncated = true;
                    Value::String("[omitted]".into())
                }
            }
        };
        fields.insert(clip(name, 128, &mut truncated), value);
    }
    let mut text = |key: &str, cap| {
        clip(
            obj.get(key).and_then(Value::as_str).unwrap_or(""),
            cap,
            &mut truncated,
        )
    };
    let level = text("level", 8);
    let target = text("target", 256);
    let message = text("message", 2048);
    ApiActivityRecord {
        seq: String::new(),
        unix_ms: obj.get("ts_unix_ms").and_then(Value::as_u64).unwrap_or(0),
        level,
        target,
        message,
        fields,
        truncated,
    }
}

/// Called by the existing INFO+ capture layer; full file/incident records stay
/// untouched. Protected by the operator API key at the only HTTP mount.
pub(crate) fn record(obj: &Map<String, Value>, context_truncated: bool) {
    let mut record = bounded_record(obj);
    record.truncated |= context_truncated;
    match HISTORY.try_lock() {
        Ok(mut history) => history.push(record),
        Err(_) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(crate) fn span_fields(obj: &Map<String, Value>) -> (Map<String, Value>, bool) {
    let record = bounded_record(obj);
    (record.fields.into_iter().collect(), record.truncated)
}

pub(crate) fn page(session: Option<&str>, since: u64, limit: usize) -> Option<ApiActivityPage> {
    HISTORY
        .try_lock()
        .ok()
        .map(|h| h.page(session, since, limit))
}

/// Explicit recoveries, derived from successful status publications, also enter
/// the durable tracing log. A quieter log or elapsed time cannot clear an issue.
pub(crate) fn status_transitions(
    previous: Option<&ergo_api::types::ApiStatus>,
    next: &ergo_api::types::ApiStatus,
) {
    for (condition, state, message, evidence) in transitions(previous, next) {
        if state == "active" {
            tracing::warn!(target: "ergo_node::activity", code = "node_condition", condition, state, evidence, "{message}");
        } else {
            tracing::info!(target: "ergo_node::activity", code = "node_condition", condition, state, evidence, "{message}");
        }
    }
}

fn rejection_active(s: &ergo_api::types::ApiStatus) -> bool {
    s.last_block_apply_error
        .as_ref()
        .is_some_and(|e| e.height == 0 || s.best_full_block_height <= e.height)
}

fn transitions(
    previous: Option<&ergo_api::types::ApiStatus>,
    next: &ergo_api::types::ApiStatus,
) -> Vec<(&'static str, &'static str, &'static str, String)> {
    use ergo_api::types::SyncStateLabel;
    let mut result = Vec::new();
    let conditions = |s: &ergo_api::types::ApiStatus| {
        [
            s.peer_count == 0,
            matches!(s.sync_state, SyncStateLabel::Stalled),
            rejection_active(s),
        ]
    };
    let now = conditions(next);
    let old = previous.map(conditions);
    let labels = [
        (
            "network",
            "No peer connections",
            "Peer connectivity restored",
        ),
        ("sync", "Chain sync stalled", "Chain sync stall cleared"),
        (
            "block_rejection",
            "Block rejection needs review",
            "Chain advanced beyond rejected block",
        ),
    ];
    for (i, (condition, active, recovered)) in labels.into_iter().enumerate() {
        if old.is_some_and(|p| p[i] == now[i]) || (old.is_none() && !now[i]) {
            continue;
        }
        // Losing peers changes the collapsed sync label too; that is not
        // evidence of a recovered stall. Rejection evidence must persist and
        // refer to the SAME rejected block, not a replaced/cleared error slot.
        if !now[i]
            && ((i == 1
                && (next.peer_count == 0
                    || !matches!(
                        next.sync_state,
                        SyncStateLabel::Syncing | SyncStateLabel::AtTip
                    )))
                || (i == 2
                    && !previous
                        .and_then(|p| p.last_block_apply_error.as_ref())
                        .zip(next.last_block_apply_error.as_ref())
                        .is_some_and(|(a, b)| {
                            a.block_id == b.block_id
                                && b.height > 0
                                && next.best_full_block_height > b.height
                        })))
        {
            continue;
        }
        let evidence = if i == 2 {
            next.last_block_apply_error
                .as_ref()
                .map(|e| {
                    format!(
                        "block={} rejected_height={} applied_height={} reason={}",
                        e.block_id, e.height, next.best_full_block_height, e.reason
                    )
                })
                .unwrap_or_default()
        } else {
            format!(
                "peers={} applied_height={}",
                next.peer_count, next.best_full_block_height
            )
        };
        result.push((
            condition,
            if now[i] { "active" } else { "recovered" },
            if now[i] { active } else { recovered },
            evidence,
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record_with(message: &str) -> ApiActivityRecord {
        bounded_record(json!({"ts_unix_ms": 123, "level": "WARN", "target": "ergo_p2p", "message": message, "peer": "127.0.0.1:9030"}).as_object().unwrap())
    }

    #[test]
    fn resume_is_exact_and_restart_never_silently_loses_history() {
        let mut h = History::new();
        for _ in 0..5 {
            h.push(record_with("retry"));
        }
        let first = h.page(None, 0, 2);
        assert_eq!(first.next_seq, "2");
        assert_eq!(first.latest_seq, "5");
        assert!(first.has_more);
        let next = h.page(Some(&first.session_id), 2, 500);
        assert_eq!(
            next.records
                .iter()
                .map(|r| r.seq.as_str())
                .collect::<Vec<_>>(),
            ["3", "4", "5"]
        );
        assert!(!next.has_more);
        assert!(h.page(Some("previous-process"), 2, 500).reset);
        assert_eq!(h.page(Some("previous-process"), 2, 500).records.len(), 5);
        assert!(h.page(None, 99, 500).reset);
    }

    #[test]
    fn retention_has_count_and_byte_bounds_and_reports_gaps() {
        let mut h = History::new();
        for _ in 0..CAP + 20 {
            h.push(record_with("retry"));
        }
        assert_eq!(h.records.len(), CAP);
        assert!(h.page(None, 1, 500).gap);
        assert!(!h.page(None, 20, 500).gap);
        let mut big = record_with(&"x".repeat(2048));
        for i in 0..32 {
            big.fields
                .insert(i.to_string(), Value::String("x".repeat(1024)));
        }
        for _ in 0..CAP {
            h.push(big.clone());
        }
        assert!(h.bytes <= BYTE_CAP);
        assert!(h.records.len() < CAP);
        assert_eq!(h.page(None, 0, usize::MAX).records.len(), h.records.len());
    }

    #[test]
    fn bounded_unicode_and_secret_fields_do_not_leak_into_operator_records() {
        let raw = json!({"message": "🦀".repeat(2000), "api_key": "secret", "password": "secret", "seed_bytes": "secret", "private_key": "secret", "token_id": "public-id", "nested": {"password": "secret"}});
        let r = bounded_record(raw.as_object().unwrap());
        assert!(r.truncated);
        assert!(r.message.len() < 2060);
        assert_eq!(r.fields["token_id"], "public-id");
        assert!(!serde_json::to_string(&r).unwrap().contains("secret"));
        assert_eq!(
            raw["api_key"], "secret",
            "original forensic record remains intact"
        );
    }

    #[test]
    fn recovery_requires_positive_matching_evidence() {
        use ergo_api::types::{ApiBlockApplyError, ApiStatus, SyncStateLabel};
        let mut a = ApiStatus {
            peer_count: 4,
            best_full_block_height: 99,
            sync_state: SyncStateLabel::Syncing,
            last_block_apply_error: Some(ApiBlockApplyError {
                height: 100,
                block_id: "bad".into(),
                reason: "validation".into(),
                age_ms: 0,
            }),
            ..Default::default()
        };
        let mut b = a.clone();
        b.best_header_height = 200;
        b.last_block_apply_error.as_mut().unwrap().age_ms = 999999;
        assert!(transitions(Some(&a), &b).is_empty());
        b.best_full_block_height = 101;
        assert_eq!(transitions(Some(&a), &b)[0].1, "recovered");
        assert_eq!(
            transitions(Some(&b), &a)[0].1,
            "active",
            "rollback reopens the condition"
        );
        b.last_block_apply_error = None;
        assert!(
            transitions(Some(&a), &b).is_empty(),
            "missing evidence is not recovery"
        );
        a.sync_state = SyncStateLabel::Stalled;
        b = a.clone();
        b.peer_count = 0;
        b.sync_state = SyncStateLabel::Disconnected;
        assert!(transitions(Some(&a), &b).iter().all(|t| t.1 != "recovered"));
    }

    #[test]
    fn captured_logs_keep_updated_span_identity_and_redact_span_secrets() {
        use tracing_subscriber::prelude::*;
        let subscriber =
            tracing_subscriber::Registry::default().with(crate::incidents::CaptureLayer);
        tracing::subscriber::with_default(subscriber, || {
            let outer = tracing::info_span!(
                "block",
                block = "outer-block",
                peer = tracing::field::Empty,
                api_key = "hidden-credential"
            );
            outer.record("peer", "192.0.2.1:9030");
            let _entered = outer.enter();
            let inner = tracing::info_span!("validate", block = "inner-block");
            let _inner = inner.enter();
            tracing::warn!(
                code = "activity_span_fixture",
                height = 123,
                "test evidence"
            );
        });
        let h = HISTORY.lock().unwrap();
        let record = h
            .records
            .iter()
            .rev()
            .find(|r| {
                r.2.fields.get("code").and_then(Value::as_str) == Some("activity_span_fixture")
            })
            .unwrap();
        assert_eq!(record.2.fields["block"], "inner-block");
        assert_eq!(record.2.fields["peer"], "192.0.2.1:9030");
        assert_eq!(record.2.fields["api_key"], "[redacted]");
    }
}
