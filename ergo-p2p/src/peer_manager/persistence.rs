//! Persistence write-through helpers for [`PeerManager`].
//!
//! Each helper short-circuits when no book is attached. Errors are
//! logged (ERROR — see [`PeerManager::record_storage_error`], issue #281)
//! and swallowed: in-memory state is the source of truth for the running
//! session, the book is best-effort restore-on-restart.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use crate::address_book::{AddressBookError, BanRecord, LastDirection};
use crate::handshake::PeerSpec;
use crate::peer::Direction;

use super::{PeerManager, PeerOrigin, STORAGE_ERROR_LOG_INTERVAL_MS};

impl PeerManager {
    /// Record one `peers.redb` write-through failure: bumps
    /// `storage_error_count`, remembers it for `last_storage_error`
    /// (both unconditionally — every occurrence counts), and emits the
    /// structured `storage_error` ERROR event (issue #281) at most once
    /// per [`STORAGE_ERROR_LOG_INTERVAL_MS`] per `op` — a stable `code`
    /// so the incident-snapshot trigger (#263) dedupes correctly, and a
    /// throttle so a poisoned/full `peers.redb` doesn't flood one ERROR
    /// line per failed write-through (review fix P2-1: unthrottled, that
    /// amplifies the very I/O fault causing it). Occurrences suppressed
    /// during the interval are counted and surfaced as `suppressed_count`
    /// on the next emission for that `op`.
    pub(super) fn record_storage_error(
        &self,
        op: &'static str,
        addr_or_ip: &dyn std::fmt::Display,
        e: &AddressBookError,
    ) {
        let now_ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.storage_error_count
            .set(self.storage_error_count.get() + 1);
        *self.last_storage_error.borrow_mut() = Some((now_ms, format!("peers: {e}")));

        let mut log_state = self.storage_error_log_state.borrow_mut();
        let entry = log_state.entry(op).or_insert((0, 0));
        let (last_emit_ms, suppressed_count) = *entry;
        let due = last_emit_ms == 0
            || now_ms.saturating_sub(last_emit_ms) >= STORAGE_ERROR_LOG_INTERVAL_MS;
        if !due {
            entry.1 = suppressed_count.saturating_add(1);
            return;
        }
        *entry = (now_ms, 0);
        drop(log_state);
        tracing::error!(
            event = "storage_error",
            code = "storage_error:peers",
            store = "peers",
            op,
            peer = %addr_or_ip,
            error = %e,
            suppressed_count = suppressed_count,
            "address_book write failed",
        );
    }

    pub(super) fn persist_handshake(
        &self,
        addr: SocketAddr,
        spec: &PeerSpec,
        direction: Direction,
    ) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        let last_dir = match direction {
            Direction::Outbound => LastDirection::Outbound,
            Direction::Inbound => LastDirection::Inbound,
        };
        let v = [spec.version.major, spec.version.minor, spec.version.patch];
        if let Err(e) = book.upsert_handshaked(
            addr,
            &spec.agent_name,
            v,
            &spec.node_name,
            last_dir,
            SystemTime::now(),
        ) {
            self.record_storage_error("upsert_handshaked", &addr, &e);
        }
    }

    pub(super) fn persist_touch(&self, addr: SocketAddr) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.touch_seen(addr, SystemTime::now()) {
            self.record_storage_error("touch_seen", &addr, &e);
        }
    }

    pub(super) fn persist_failure(&self, addr: SocketAddr) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.mark_failure(addr, SystemTime::now()) {
            self.record_storage_error("mark_failure", &addr, &e);
        }
    }

    pub(super) fn persist_success(&self, addr: SocketAddr) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.mark_success(addr, SystemTime::now()) {
            self.record_storage_error("mark_success", &addr, &e);
        }
    }

    pub(super) fn persist_known(&self, addr: SocketAddr, origin: PeerOrigin) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.add_known(addr, origin) {
            self.record_storage_error("add_known", &addr, &e);
        }
    }

    /// Best-effort delete of a ban's persisted row (cap eviction + expiry
    /// sweep). Errors are logged, not surfaced — same contract as every
    /// other write-through hook.
    pub(super) fn unban_persisted(&self, ip: IpAddr) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.unban(ip) {
            self.record_storage_error("unban", &ip, &e);
        }
    }

    pub(super) fn persist_ban(&self, ip: IpAddr, duration: Duration, count: u32, permanent: bool) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        let until = SystemTime::now() + duration;
        let record = BanRecord {
            ip,
            until,
            count,
            permanent,
        };
        if let Err(e) = book.record_ban(&record) {
            self.record_storage_error("record_ban", &ip, &e);
        }
    }
}
