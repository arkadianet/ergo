//! Header-anchor map builder (Step B v2 — observation only).
//!
//! Builds an in-memory `HashMap<u32, [u8; 32]>` of canonical
//! `(height, header_id)` pairs by querying `GET /blocks/at/{h}` against
//! peers that advertised a `RestApiUrl` feature in the handshake. A
//! height is admitted to `verified` only after `MIN_ANCHOR_AGREEMENT`
//! **distinct source URLs** report the same ID — minimizes Sybil risk.
//!
//! Step B does NOT use the map for anything. It only fills it and
//! exposes counters via the `[anchor]` heartbeat line so we can
//! validate the design in production traffic before turning on Step
//! C (per-peer SyncInfo crafting).
//!
//! All resources are bounded: per-height pending IDs cap, per-ID
//! source cap, HTTP body cap, request timeout, semaphore-bounded
//! parallelism. URL parsing rejects CRLF/control chars/userinfo/IPv6.
//! HTTP-only — `https://` URLs return an error and the caller logs +
//! skips. Per the design doc most Ergo REST endpoints are HTTP.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, RwLock};
use tokio::time::timeout;

/// Step interval used to walk the chain looking for anchors. Matches
/// Scala `MaxInvObjects = 400` so each anchor's continuation
/// response would later cover one full Inv batch (Step C usage).
pub const ANCHOR_INTERVAL: u32 = 400;

/// Number of distinct REST endpoints that must return the same ID
/// for a height before that height's anchor is admitted as
/// `verified`. Distinctness is tracked by source URL — repeated
/// observations from the same URL count as one.
pub const MIN_ANCHOR_AGREEMENT: usize = 2;

/// Cap on parallel REST queries to avoid hammering individual REST
/// endpoints. Live observation showed 64 was too aggressive — first
/// burst of queries succeeded but subsequent batches were rejected
/// (likely per-IP connection rate-limiting on the receiving Scala
/// nodes' akka-http server). 16 keeps each endpoint at ≤4 concurrent
/// connections (16 / 4 healthy URLs) which empirically sustains.
/// Anchor map fill rate at 16 already runs well ahead of the install
/// tip — bumping further has no observable throughput benefit.
pub const REST_MAX_PARALLEL: usize = 16;

/// Per-query timeout for `GET /blocks/at/{h}`.
pub const REST_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on response body size. A `/blocks/at/{h}` response is at most
/// a JSON array of N hex IDs; even N=10 the body is well under 1 KB.
/// 16 KB is a generous safety ceiling — beyond it we treat the
/// response as malicious and drop.
pub const MAX_HTTP_BODY_BYTES: u64 = 16 * 1024;

/// Cap on HTTP response head (status line + headers). Anything more
/// than 8 KB of head bytes is malformed/malicious; abort.
pub const MAX_HTTP_HEAD_BYTES: u64 = 8 * 1024;

/// Cap on distinct IDs we'll track per height in the pending map. If
/// a malicious peer rotates IDs at one height beyond this, additional
/// IDs are silently dropped — we already have enough signal to detect
/// disagreement.
pub const MAX_DISTINCT_IDS_PER_HEIGHT: usize = 8;

/// Cap on distinct source URLs we'll track per (height, id) pair.
/// More than this is redundant for promotion semantics
/// (`MIN_ANCHOR_AGREEMENT` is small).
pub const MAX_SOURCES_PER_ID: usize = 8;

/// Internal book-keeping per height. Each candidate ID tracks the
/// set of distinct **source URLs** (not raw observations) that
/// reported it. Promoted to `verified` once any candidate's set
/// reaches `MIN_ANCHOR_AGREEMENT`.
#[derive(Default)]
struct PendingAnchor {
    /// header_id -> set of distinct source URLs that reported it.
    /// Cap on outer map: `MAX_DISTINCT_IDS_PER_HEIGHT`.
    /// Cap on inner set: `MAX_SOURCES_PER_ID`.
    by_id: HashMap<[u8; 32], HashSet<String>>,
}

/// Snapshot of counters returned by `take_counters` — drained on
/// every read so each heartbeat shows the delta since last tick.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AnchorCounters {
    pub queries_attempted: u64,
    pub queries_succeeded: u64,
    pub queries_errored: u64,
    pub anchors_admitted: u64,
    pub anchor_disagreements: u64,
}

impl AnchorCounters {
    /// True if any counter saw activity since last read. Heartbeat
    /// uses this to gate emission — silent ticks produce no output.
    pub fn is_active(&self) -> bool {
        self.queries_attempted > 0
            || self.queries_succeeded > 0
            || self.queries_errored > 0
            || self.anchors_admitted > 0
            || self.anchor_disagreements > 0
    }
}

struct AnchorMapInner {
    verified: HashMap<u32, [u8; 32]>,
    pending: HashMap<u32, PendingAnchor>,
    counters: AnchorCounters,
}

#[derive(Clone)]
pub struct AnchorMap {
    inner: Arc<RwLock<AnchorMapInner>>,
}

impl Default for AnchorMap {
    fn default() -> Self {
        Self::new()
    }
}

impl AnchorMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AnchorMapInner {
                verified: HashMap::new(),
                pending: HashMap::new(),
                counters: AnchorCounters::default(),
            })),
        }
    }

    /// Record a single (`source`, `height`, `header_id`) report.
    /// Promotes a height to `verified` once `MIN_ANCHOR_AGREEMENT`
    /// distinct **source URLs** report the same ID. Quorum is
    /// per-distinct-source, NOT per-observation, so a single source
    /// can never satisfy quorum no matter how many times it reports.
    ///
    /// Disagreement semantics: a new (source, id) pair counts as a
    /// disagreement only when the source is reporting an ID at a
    /// height that other sources have reported a different ID at.
    /// Same source repeating the same ID is a no-op.
    pub async fn record(&self, source: &str, height: u32, header_id: [u8; 32]) {
        let mut g = self.inner.write().await;

        // Already verified at this height.
        if let Some(existing) = g.verified.get(&height).copied() {
            if existing != header_id {
                g.counters.anchor_disagreements = g.counters.anchor_disagreements.saturating_add(1);
            }
            return;
        }

        // Compute admission outcome inside a tight scope so the
        // mutable borrow of `g.pending` ends before we touch
        // `g.verified` / `g.counters`. Borrow-checker requirement.
        let (newly_inserted, any_other_id, promoted) = {
            let entry = g.pending.entry(height).or_default();

            // Cap distinct IDs per height. If this is a new ID and
            // we're already at cap, drop silently — we've got enough
            // signal already.
            let id_already_known = entry.by_id.contains_key(&header_id);
            if !id_already_known && entry.by_id.len() >= MAX_DISTINCT_IDS_PER_HEIGHT {
                return;
            }

            // Compute disagreement-flag before mutating so semantics
            // are clear: a new ID at a height that already has at
            // least one other ID counts as one new disagreement
            // signal (per distinct new id, not per repeated obs).
            let any_other_id = !entry.by_id.is_empty() && !id_already_known;

            let sources = entry.by_id.entry(header_id).or_default();
            let newly_inserted = if sources.len() >= MAX_SOURCES_PER_ID {
                // At source cap — don't grow further. Treat as
                // not-newly-inserted so we don't double-count.
                false
            } else {
                sources.insert(source.to_string())
            };
            let promoted = newly_inserted && sources.len() >= MIN_ANCHOR_AGREEMENT;
            (newly_inserted, any_other_id, promoted)
        };

        if newly_inserted && any_other_id {
            g.counters.anchor_disagreements = g.counters.anchor_disagreements.saturating_add(1);
        }
        if promoted {
            g.verified.insert(height, header_id);
            g.pending.remove(&height);
            g.counters.anchors_admitted = g.counters.anchors_admitted.saturating_add(1);
        }
    }

    pub async fn note_query_attempt(&self) {
        let mut g = self.inner.write().await;
        g.counters.queries_attempted = g.counters.queries_attempted.saturating_add(1);
    }

    pub async fn note_query_success(&self) {
        let mut g = self.inner.write().await;
        g.counters.queries_succeeded = g.counters.queries_succeeded.saturating_add(1);
    }

    pub async fn note_query_error(&self) {
        let mut g = self.inner.write().await;
        g.counters.queries_errored = g.counters.queries_errored.saturating_add(1);
    }

    pub async fn verified_count(&self) -> usize {
        self.inner.read().await.verified.len()
    }

    pub async fn pending_count(&self) -> usize {
        self.inner.read().await.pending.len()
    }

    /// Non-blocking variant of `verified_count` for the heartbeat.
    pub fn try_verified_count(&self) -> Option<usize> {
        self.inner.try_read().ok().map(|g| g.verified.len())
    }

    /// Non-blocking pending-set diagnostic — number of heights with
    /// at least one (source, id) report but not yet promoted to
    /// verified. Used to distinguish "record() never runs" (pending=0)
    /// from "record() runs but quorum doesn't form" (pending>0).
    pub fn try_pending_count(&self) -> Option<usize> {
        self.inner.try_read().ok().map(|g| g.pending.len())
    }

    /// Non-blocking snapshot of the verified anchor map for the
    /// scheduler's per-tick lookup. Returns `None` if the lock is
    /// contended (builder mid-write); the scheduler treats that as
    /// "no change since last tick" and retries next dispatch.
    pub fn try_verified_snapshot(&self) -> Option<HashMap<u32, [u8; 32]>> {
        self.inner.try_read().ok().map(|g| g.verified.clone())
    }

    pub async fn take_counters(&self) -> AnchorCounters {
        let mut g = self.inner.write().await;
        std::mem::take(&mut g.counters)
    }

    /// Non-blocking variant of `take_counters` for the heartbeat.
    pub fn try_take_counters(&self) -> Option<AnchorCounters> {
        self.inner
            .try_write()
            .ok()
            .map(|mut g| std::mem::take(&mut g.counters))
    }
}

// ---- URL parsing + HTTP ----

/// Parsed URL components used by `http_get`. Defensive parsing
/// rejects malformed input that could enable request-smuggling
/// against the REST endpoint or stall the connection on a bad host.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Strict URL parser for advertised REST endpoints.
///
/// Accepts: `http://host[:port]/path[?query]`. The host is restricted
/// to ASCII letters/digits/`-.` (no IPv6, no userinfo, no IDN). The
/// path is restricted to ASCII printable characters excluding CR, LF,
/// NUL, and the request-terminating sequence space. Port must be a
/// valid u16 (1..=65535).
pub fn parse_rest_url(url: &str) -> Result<ParsedUrl, String> {
    let url = url.trim();
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("malformed url (no scheme): {url}"))?;
    if scheme != "http" {
        return Err(format!(
            "unsupported scheme {scheme} (https not yet supported)"
        ));
    }
    if rest.contains('@') {
        // userinfo would let an attacker inject credentials into the
        // request; reject out of caution.
        return Err("userinfo in url not supported".into());
    }
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host_port.starts_with('[') {
        // IPv6 literals require bracketing; we don't support them
        // because parse + connect against bracketed forms is fiddly
        // and most operator REST is on IPv4.
        return Err("IPv6 url not supported".into());
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{path}")
    };
    // Validate path bytes — no CR, LF, NUL, or non-ASCII. Anything
    // here would be smuggled into the raw HTTP request and could
    // confuse the receiving server.
    for b in path.bytes() {
        if b == b'\r' || b == b'\n' || b == 0 || !(0x20..=0x7e).contains(&b) {
            return Err(format!("invalid path byte 0x{b:02x} in url"));
        }
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|e| format!("invalid port in url: {e}"))?,
        ),
        None => (host_port.to_string(), 80),
    };
    if host.is_empty() {
        return Err("empty host in url".into());
    }
    if port == 0 {
        return Err("port 0 in url".into());
    }
    // Validate host bytes — letters, digits, '.', '-' only. Rejects
    // CRLF/control chars and any other characters that would be
    // smuggled into the request line / Host header.
    for b in host.bytes() {
        let ok = b.is_ascii_alphanumeric() || b == b'.' || b == b'-';
        if !ok {
            return Err(format!("invalid host byte 0x{b:02x} in url"));
        }
    }
    Ok(ParsedUrl { host, port, path })
}

/// One-shot HTTP/1.1 GET. Returns the response body bytes on 200.
/// Strict input parsing + bounded reads to prevent malicious peer
/// REST endpoints from DoS'ing the builder.
pub async fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let parsed = parse_rest_url(url)?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: opus-ferruginis/0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.host, parsed.port
    );

    let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    // Bounded read: head + body capped together. Any peer that sends
    // more than this is treated as malicious and the response is
    // dropped.
    let read_cap = MAX_HTTP_HEAD_BYTES + MAX_HTTP_BODY_BYTES;
    let mut buf = Vec::with_capacity(4096);
    let mut bounded = (&mut stream).take(read_cap);
    bounded
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;

    // Locate end-of-head sequence.
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            format!(
                "malformed response (no header terminator), got {} bytes",
                buf.len()
            )
        })?;
    if split as u64 > MAX_HTTP_HEAD_BYTES {
        return Err(format!("response head exceeds {MAX_HTTP_HEAD_BYTES} bytes"));
    }
    let head = &buf[..split];
    let body = buf[split + 4..].to_vec();
    if (body.len() as u64) > MAX_HTTP_BODY_BYTES {
        return Err(format!(
            "response body exceeds {MAX_HTTP_BODY_BYTES} bytes (got {})",
            body.len()
        ));
    }

    // Parse status line.
    let head_str = std::str::from_utf8(head).map_err(|e| format!("non-utf8 header: {e}"))?;
    let status_line = head_str
        .lines()
        .next()
        .ok_or_else(|| "empty response head".to_string())?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts
        .next()
        .ok_or_else(|| format!("malformed status line: {status_line}"))?;
    if status != "200" {
        return Err(format!("non-200 status: {status_line}"));
    }
    Ok(body)
}

/// Query a peer's REST endpoint for the header IDs at `height`.
/// `Ok(Some(id))` on success; `Ok(None)` if the response was empty;
/// `Err` on transport/parse failure.
pub async fn query_blocks_at(rest_url: &str, height: u32) -> Result<Option<[u8; 32]>, String> {
    let url = format!("{}/blocks/at/{}", rest_url.trim_end_matches('/'), height);
    let body = timeout(REST_QUERY_TIMEOUT, http_get(&url))
        .await
        .map_err(|_| format!("timeout after {REST_QUERY_TIMEOUT:?}"))?
        .map_err(|e| format!("{url}: {e}"))?;
    let ids: Vec<String> =
        serde_json::from_slice(&body).map_err(|e| format!("{url}: json parse: {e}"))?;
    let first = match ids.into_iter().next() {
        Some(s) => s,
        None => return Ok(None),
    };
    let bytes = hex::decode(&first).map_err(|e| format!("{url}: hex decode {first}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{url}: expected 32-byte id, got {}", bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(Some(id))
}

/// Snapshot of REST URLs keyed by `PeerId`. Owned by the action
/// loop; cloned by the builder via `Arc<RwLock<...>>`. Bounded by
/// the peer-manager's `max_connections` cap (default 100) — same
/// natural bound as the connected peer set.
pub type RestPeers = HashMap<std::net::SocketAddr, String>;

/// Long-running background task that polls connected peers' REST
/// URLs and queries `/blocks/at/{h}` to build the anchor map.
/// Step B observation only.
///
/// Cancellation is **latched**: caller flips
/// `cancel_rx.borrow() == true` and triggers `cancel_rx.changed()`.
/// The builder checks the latched value at every loop iteration AND
/// selects on `changed()` between awaits, so cancellation is never
/// missed (no edge-triggered race).
///
/// Per-pass query subtasks are tracked in a local `JoinSet` whose
/// `Drop` impl aborts every child. So whether the builder exits
/// cooperatively (cancel observed) or via `abort()` (parent
/// dropped, future cancelled), the JoinSet drops and every spawned
/// query subtask is aborted — no detached subtasks outlive
/// shutdown.
/// `tip_cursor`: live read of `best_header_height`. The builder
/// uses this to scan anchors STARTING from the current tip rather
/// than h=0 — if we filled lowest-first, the base sync advances
/// past anchors faster than they get verified, leaving the
/// scheduler with nothing eligible above tip. Frontier-first means
/// each admitted anchor is immediately useful for
/// `AnchorScheduler::assign_for_peer`. Updated by the action loop
/// on each heartbeat tick.
pub async fn run_anchor_map_builder(
    map: AnchorMap,
    rest_peers: Arc<std::sync::RwLock<RestPeers>>,
    tip_cursor: Arc<AtomicU32>,
    mut cancel_rx: watch::Receiver<bool>,
) {
    /// Production step matching Scala `MaxInvObjects = 400` so each
    /// anchor's `continuationIdsV1` response covers exactly one full
    /// Inv batch (Step C scheduler usage). Across the full mainnet
    /// height range this yields ~4,500 candidate anchors. Per-pass
    /// query volume is bounded by `REST_MAX_PARALLEL` + `BUILDER_TICK`
    /// — first cold-fill takes several minutes; the scheduler uses
    /// anchors as they are admitted, lowest-height-first, so the
    /// frontier fills first.
    const OBSERVATION_HEIGHT_STEP: u32 = ANCHOR_INTERVAL;
    /// Conservative ceiling so we don't spam dozens of 404s per pass
    /// past the actual mainnet tip.
    const OBSERVATION_HEIGHT_MAX: u32 = 1_800_000;
    /// Min peers to query per height per pass. With
    /// `MIN_ANCHOR_AGREEMENT = 2`, query enough to absorb several
    /// failures. We query ALL available URLs (capped by this number)
    /// because the empirical failure rate per URL is high (~25-50%
    /// of advertised endpoints unreachable) and a deterministic
    /// per-height URL selection that picks an unhealthy subset can
    /// permanently starve that height — no amount of repeated passes
    /// will recover. Querying all URLs per height costs ~`urls.len() /
    /// previous` more network traffic but eliminates the starvation
    /// failure mode. With ~5-10 effective URLs the absolute cost is
    /// negligible (a few hundred bytes per query).
    const QUERIES_PER_HEIGHT: usize = 16;
    /// Pause between full passes.
    const BUILDER_TICK: Duration = Duration::from_secs(15);
    /// Initial delay before first attempt so handshakes can populate
    /// the REST peer map.
    const STARTUP_DELAY: Duration = Duration::from_secs(5);

    /// Helper: cancellable sleep that also returns immediately if
    /// the latched cancel flag is already true.
    async fn cancellable_sleep(d: Duration, rx: &mut watch::Receiver<bool>) -> bool {
        if *rx.borrow() {
            return true;
        }
        tokio::select! {
            _ = tokio::time::sleep(d) => false,
            _ = rx.changed() => true,
        }
    }

    if cancellable_sleep(STARTUP_DELAY, &mut cancel_rx).await {
        return;
    }

    loop {
        // Latched check before each pass — if cancel landed during
        // the previous sleep we exit immediately.
        if *cancel_rx.borrow() {
            return;
        }

        // Snapshot the URL set under the synchronous read lock —
        // clone strings, drop the guard. Sort the snapshot so the
        // per-height URL selection is deterministic across passes —
        // HashMap iteration order is randomized per RandomState seed,
        // which previously meant a single starting layout could
        // permanently starve a height (the same broken URL would be
        // picked every pass for a given height).
        let urls: Vec<String> = match rest_peers.read() {
            Ok(g) => {
                let mut v: Vec<String> = g.values().cloned().collect();
                v.sort();
                v
            }
            Err(_) => Vec::new(),
        };
        if urls.is_empty() {
            if cancellable_sleep(BUILDER_TICK, &mut cancel_rx).await {
                return;
            }
            continue;
        }

        // Frontier-first scan: round our_tip down to the nearest
        // anchor-interval boundary and start from there. This keeps
        // newly-admitted anchors above tip — exactly the range the
        // scheduler picks from. Without this, lowest-first scan
        // fills h=400, 800, ... while base sync advances past
        // them, leaving the scheduler permanently empty.
        //
        // Per-pass scope is capped so each pass completes before
        // tip moves past the verified window. Without the cap, a
        // single pass over 4500 heights × 5 URLs = 22500 queries
        // serialized through a 16-slot semaphore takes ~10 min —
        // tip moves 600k+ in that time, leaving the just-verified
        // anchors useless. With cap=400, each pass attempts ~2000
        // queries → ~60s wall, verifies up to 400 anchors covering
        // 160k headers above tip. P2P tip moves ~60k in 60s, so
        // each pass nets a 100k-height lead. Successive passes
        // accumulate a wider band of verified anchors above tip,
        // letting the scheduler find eligible work continuously.
        const MAX_ANCHORS_PER_PASS: usize = 400;
        let our_tip = tip_cursor.load(Ordering::Relaxed);
        let scan_start = (our_tip / OBSERVATION_HEIGHT_STEP) * OBSERVATION_HEIGHT_STEP;
        let needed: Vec<u32> = {
            let g = map.inner.read().await;
            (scan_start..=OBSERVATION_HEIGHT_MAX)
                .step_by(OBSERVATION_HEIGHT_STEP as usize)
                .filter(|h| !g.verified.contains_key(h))
                .take(MAX_ANCHORS_PER_PASS)
                .collect()
        };
        if needed.is_empty() {
            if cancellable_sleep(BUILDER_TICK, &mut cancel_rx).await {
                return;
            }
            continue;
        }

        let semaphore = Arc::new(tokio::sync::Semaphore::new(REST_MAX_PARALLEL));
        // `JoinSet` rather than `Vec<JoinHandle>` so that if the
        // builder itself gets aborted (e.g. via `RunHandle::Drop`'s
        // `abort()` while the builder is mid-pass), the JoinSet's
        // `Drop` impl aborts every spawned child. With a plain
        // `Vec<JoinHandle>`, dropping it without explicit abort
        // detaches the children — they'd outlive the builder. The
        // JoinSet contract (per tokio docs) makes this race-safe.
        let mut handles: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        for height in &needed {
            // Round-robin URLs starting at a different offset per
            // height. Use `height / OBSERVATION_HEIGHT_STEP` (the
            // ordinal index of this height in the candidate list)
            // rather than `height` directly — when STEP is a
            // multiple of `urls.len()` (e.g. STEP=400, urls.len()=5
            // both share factor 5), `height % urls.len()` collapses
            // to the same offset for every height, defeating the
            // round-robin. The ordinal-based offset rotates one URL
            // per height regardless of STEP.
            let height_ordinal = (*height as usize) / OBSERVATION_HEIGHT_STEP as usize;
            let offset = height_ordinal % urls.len().max(1);
            for i in 0..QUERIES_PER_HEIGHT.min(urls.len()) {
                let url = urls[(offset + i) % urls.len()].clone();
                let sem = semaphore.clone();
                let map = map.clone();
                let h = *height;
                handles.spawn(async move {
                    let _permit = match sem.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    map.note_query_attempt().await;
                    match query_blocks_at(&url, h).await {
                        Ok(Some(id)) => {
                            map.note_query_success().await;
                            map.record(&url, h, id).await;
                        }
                        Ok(None) | Err(_) => {
                            map.note_query_error().await;
                        }
                    }
                });
            }
        }

        // Drain the JoinSet to completion OR observe cancel. On
        // cooperative cancel we explicitly call `abort_all` and
        // drain so abort is observed before the function returns.
        // On the abort-the-builder path, the JoinSet's Drop is what
        // catches detached children — see the comment at its
        // construction above.
        let cancelled = tokio::select! {
            _ = async {
                while handles.join_next().await.is_some() {}
            } => false,
            _ = cancel_rx.changed() => true,
        };
        if cancelled {
            handles.abort_all();
            while handles.join_next().await.is_some() {}
            return;
        }

        if cancellable_sleep(BUILDER_TICK, &mut cancel_rx).await {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ---- AnchorMap quorum + disagreement ----

    #[tokio::test]
    async fn same_source_twice_does_not_promote() {
        // Regression: one source repeating the same ID across
        // passes must NOT satisfy quorum.
        let map = AnchorMap::new();
        map.record("http://a/", 400, id(1)).await;
        map.record("http://a/", 400, id(1)).await;
        assert_eq!(map.verified_count().await, 0);
        let c = map.take_counters().await;
        assert_eq!(c.anchors_admitted, 0);
    }

    #[tokio::test]
    async fn two_distinct_sources_promote() {
        let map = AnchorMap::new();
        map.record("http://a/", 400, id(1)).await;
        map.record("http://b/", 400, id(1)).await;
        assert_eq!(map.verified_count().await, 1);
        let c = map.take_counters().await;
        assert_eq!(c.anchors_admitted, 1);
        assert_eq!(c.anchor_disagreements, 0);
    }

    #[tokio::test]
    async fn disagreement_counts_per_distinct_new_id() {
        let map = AnchorMap::new();
        map.record("http://a/", 400, id(1)).await;
        // Same source repeating same id — no disagreement.
        map.record("http://a/", 400, id(1)).await;
        let c = map.take_counters().await;
        assert_eq!(c.anchor_disagreements, 0);

        // Different source, different id — first disagreement.
        map.record("http://b/", 400, id(2)).await;
        let c = map.take_counters().await;
        assert_eq!(c.anchor_disagreements, 1);

        // Same source repeating its disagreeing id — no new
        // disagreement.
        map.record("http://b/", 400, id(2)).await;
        let c = map.take_counters().await;
        assert_eq!(c.anchor_disagreements, 0);
    }

    #[tokio::test]
    async fn already_verified_rejects_disagreeing_id_with_count() {
        let map = AnchorMap::new();
        map.record("http://a/", 400, id(1)).await;
        map.record("http://b/", 400, id(1)).await; // verified
        map.record("http://c/", 400, id(2)).await; // disagrees with verified
        let c = map.take_counters().await;
        assert_eq!(c.anchors_admitted, 1);
        assert_eq!(c.anchor_disagreements, 1);
    }

    #[tokio::test]
    async fn pending_ids_capped_per_height() {
        let map = AnchorMap::new();
        // Spam (cap + 1) distinct IDs at the same height. Outer map
        // should never exceed MAX_DISTINCT_IDS_PER_HEIGHT.
        for i in 0..(MAX_DISTINCT_IDS_PER_HEIGHT as u8 + 4) {
            map.record(&format!("http://s{i}/"), 400, id(i + 1)).await;
        }
        let g = map.inner.read().await;
        let entry = g.pending.get(&400).expect("pending entry");
        assert!(
            entry.by_id.len() <= MAX_DISTINCT_IDS_PER_HEIGHT,
            "outer cap not enforced: {}",
            entry.by_id.len()
        );
    }

    #[tokio::test]
    async fn sources_capped_per_id() {
        let map = AnchorMap::new();
        for i in 0..(MAX_SOURCES_PER_ID + 4) {
            map.record(&format!("http://s{i}/"), 400, id(1)).await;
        }
        let g = map.inner.read().await;
        // Either verified (if cap >= MIN_ANCHOR_AGREEMENT) or pending
        // — either way, source set must not exceed cap.
        if let Some(entry) = g.pending.get(&400) {
            for sources in entry.by_id.values() {
                assert!(sources.len() <= MAX_SOURCES_PER_ID);
            }
        }
    }

    #[tokio::test]
    async fn take_counters_drains_to_zero() {
        let map = AnchorMap::new();
        map.note_query_attempt().await;
        map.note_query_success().await;
        let c = map.take_counters().await;
        assert_eq!(c.queries_attempted, 1);
        assert_eq!(c.queries_succeeded, 1);
        assert!(c.is_active());
        let c2 = map.take_counters().await;
        assert_eq!(c2, AnchorCounters::default());
        assert!(!c2.is_active());
    }

    // ---- URL parsing ----

    #[test]
    fn parse_rest_url_accepts_http_with_port() {
        let p = parse_rest_url("http://10.0.0.1:9053/blocks/at/0").unwrap();
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 9053);
        assert_eq!(p.path, "/blocks/at/0");
    }

    #[test]
    fn parse_rest_url_default_port_80() {
        let p = parse_rest_url("http://example.com/path").unwrap();
        assert_eq!(p.port, 80);
    }

    #[test]
    fn parse_rest_url_rejects_https() {
        assert!(parse_rest_url("https://example.com/").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_userinfo() {
        assert!(parse_rest_url("http://user:pass@example.com/").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_ipv6() {
        assert!(parse_rest_url("http://[::1]:9053/").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_crlf_in_path() {
        // CRLF would smuggle into the request line.
        assert!(parse_rest_url("http://example.com/path\r\nX:y").is_err());
        assert!(parse_rest_url("http://example.com/path\nbad").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_crlf_in_host() {
        assert!(parse_rest_url("http://exa\r\nmple.com/").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_nul_byte() {
        assert!(parse_rest_url("http://example.com/p\0a").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_invalid_port() {
        assert!(parse_rest_url("http://example.com:99999/").is_err());
        assert!(parse_rest_url("http://example.com:abc/").is_err());
        assert!(parse_rest_url("http://example.com:0/").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_empty_host() {
        assert!(parse_rest_url("http:///path").is_err());
    }

    #[test]
    fn parse_rest_url_rejects_no_scheme() {
        assert!(parse_rest_url("example.com/path").is_err());
    }

    #[test]
    fn parse_rest_url_accepts_no_path_defaults_to_root() {
        let p = parse_rest_url("http://example.com").unwrap();
        assert_eq!(p.path, "/");
    }
}
