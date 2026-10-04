//! Acknowledged operator actions: durable writes precede in-memory changes.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

use crate::address_book::{AddressBookError, BanRecord};
use crate::peer::canonical_ip;

use super::{BanEntry, PeerManager, MAX_BANS};

impl PeerManager {
    /// Apply an IP-wide timed ban only when its row has been persisted. The
    /// caller closes sockets and reassigns modifier requests after this succeeds.
    pub fn operator_ban(
        &mut self,
        ip: IpAddr,
        duration: Duration,
        now: Instant,
    ) -> Result<(), AddressBookError> {
        if duration.is_zero() || duration > Duration::from_secs(365 * 24 * 3600) {
            return Err(AddressBookError::Db(
                "ban duration must be 1..31536000 seconds".into(),
            ));
        }
        let ip = canonical_ip(ip);
        if !self.bans.contains_key(&ip) && self.bans.len() >= MAX_BANS {
            return Err(AddressBookError::Db(
                "ban list is full; remove an entry before adding a manual ban".into(),
            ));
        }
        let book = self
            .book
            .as_ref()
            .ok_or_else(|| AddressBookError::Db("persistent address book is unavailable".into()))?;
        let count = self
            .bans
            .get(&ip)
            .map(|entry| entry.count)
            .unwrap_or(0)
            .saturating_add(1);
        book.record_ban(&BanRecord {
            ip,
            until: SystemTime::now() + duration,
            count,
            permanent: false,
        })?;
        self.bans.insert(
            ip,
            BanEntry {
                until: now + duration,
                count,
            },
        );
        self.peers.retain(|addr, _| canonical_ip(addr.ip()) != ip);
        Ok(())
    }

    pub fn operator_unban(&mut self, ip: IpAddr) -> Result<(), AddressBookError> {
        let ip = canonical_ip(ip);
        let book = self
            .book
            .as_ref()
            .ok_or_else(|| AddressBookError::Db("persistent address book is unavailable".into()))?;
        book.unban(ip)?;
        self.bans.remove(&ip);
        Ok(())
    }

    /// Forget an address's durable dial metadata. The caller first closes the
    /// session after this succeeds. Configured seeds may reappear at restart.
    pub fn operator_remove(&mut self, addr: SocketAddr) -> Result<(), AddressBookError> {
        let book = self
            .book
            .as_ref()
            .ok_or_else(|| AddressBookError::Db("persistent address book is unavailable".into()))?;
        book.remove_peer(addr)?;
        self.known_addresses.retain(|known| known.addr != addr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn manual_bans_are_ip_wide_durable_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.redb");
        let book = Arc::new(crate::address_book::AddressBook::open_at(&path).unwrap());
        let mut manager = PeerManager::new(1);
        manager.set_address_book(book.clone());
        let now = Instant::now();
        let addr: SocketAddr = "203.0.113.8:9030".parse().unwrap();
        manager.register_outbound(addr, now).unwrap();
        manager
            .operator_ban(addr.ip(), Duration::from_secs(60), now)
            .unwrap();
        assert!(manager.is_banned(&addr, now));
        assert!(manager.is_banned(&"[::ffff:203.0.113.8]:9031".parse().unwrap(), now));
        assert_eq!(manager.peer_count(), 0);
        assert!(!manager.is_banned(&addr, now + Duration::from_secs(61)));
        assert_eq!(book.load_all(false).unwrap().bans.len(), 1);
        manager.operator_unban(addr.ip()).unwrap();
        assert!(!manager.is_banned(&addr, now));
        assert!(book.load_all(false).unwrap().bans.is_empty());
    }

    #[test]
    fn ban_without_persistence_is_rejected_without_changing_state() {
        let mut manager = PeerManager::new(1);
        let now = Instant::now();
        let addr = "203.0.113.8:9030".parse().unwrap();
        manager.register_outbound(addr, now).unwrap();
        assert!(manager
            .operator_ban(addr.ip(), Duration::from_secs(60), now)
            .is_err());
        assert!(!manager.is_banned(&addr, now));
        assert_eq!(manager.peer_count(), 1);
    }
}
