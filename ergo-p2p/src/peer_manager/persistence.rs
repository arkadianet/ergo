//! Persistence write-through helpers for [`PeerManager`].
//!
//! Each helper short-circuits when no book is attached. Errors are
//! logged and swallowed: in-memory state is the source of truth for
//! the running session, the book is best-effort restore-on-restart.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use tracing::warn;

use crate::address_book::{BanRecord, LastDirection};
use crate::handshake::PeerSpec;
use crate::peer::Direction;

use super::{PeerManager, PeerOrigin};

impl PeerManager {
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
            warn!(peer = %addr, op = "upsert_handshaked", error = %e, "address_book write failed");
        }
    }

    pub(super) fn persist_touch(&self, addr: SocketAddr) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.touch_seen(addr, SystemTime::now()) {
            warn!(peer = %addr, op = "touch_seen", error = %e, "address_book write failed");
        }
    }

    pub(super) fn persist_failure(&self, addr: SocketAddr) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.mark_failure(addr, SystemTime::now()) {
            warn!(peer = %addr, op = "mark_failure", error = %e, "address_book write failed");
        }
    }

    pub(super) fn persist_success(&self, addr: SocketAddr) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.mark_success(addr, SystemTime::now()) {
            warn!(peer = %addr, op = "mark_success", error = %e, "address_book write failed");
        }
    }

    pub(super) fn persist_known(&self, addr: SocketAddr, origin: PeerOrigin) {
        let Some(book) = self.book.as_ref() else {
            return;
        };
        if let Err(e) = book.add_known(addr, origin) {
            warn!(peer = %addr, op = "add_known", error = %e, "address_book write failed");
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
            warn!(ip = %ip, op = "record_ban", error = %e, "address_book write failed");
        }
    }
}
