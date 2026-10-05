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
        if !self.bans.get(&ip).is_some_and(|entry| entry.operator)
            && self.bans.values().filter(|entry| entry.operator).count() >= MAX_BANS
        {
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
            operator: true,
        })?;
        if self.bans.len() >= MAX_BANS && !self.bans.contains_key(&ip) {
            if let Some(victim) = self
                .bans
                .iter()
                .filter(|(_, entry)| !entry.operator)
                .min_by_key(|(_, entry)| entry.until)
                .map(|(ip, _)| *ip)
            {
                self.bans.remove(&victim);
            }
        }
        self.bans.insert(
            ip,
            BanEntry {
                until: now + duration,
                count,
                operator: true,
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
        self.recovery_dials.remove(&addr);
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
    fn automatic_pressure_cannot_evict_or_persist_over_operator_bans() {
        let dir = tempfile::tempdir().unwrap();
        let book = Arc::new(
            crate::address_book::AddressBook::open_at(&dir.path().join("peers.redb")).unwrap(),
        );
        let mut manager = PeerManager::new(1);
        manager.set_address_book(book.clone());
        let now = Instant::now();
        let owner: IpAddr = "203.0.113.8".parse().unwrap();
        manager
            .operator_ban(owner, Duration::from_secs(60), now)
            .unwrap();
        for i in 0..MAX_BANS + 1 {
            manager.record_ban(
                IpAddr::V6(std::net::Ipv6Addr::from(i as u128 + 1)),
                now,
                true,
            );
        }
        assert!(manager.is_banned(&SocketAddr::new(owner, 9030), now));
        assert!(manager.bans.len() <= MAX_BANS - super::super::OPERATOR_BAN_RESERVE + 1);
        let rows = book.load_all(false).unwrap().bans;
        assert_eq!(rows.len(), 1, "automatic bans must not be persisted");
        assert!(rows[0].operator);
        // A later automatic penalty cannot extend or replace an operator ban.
        manager.record_ban(owner, now, true);
        assert!(!manager.is_banned(&SocketAddr::new(owner, 9030), now + Duration::from_secs(61)));
        manager
            .operator_ban("203.0.113.9".parse().unwrap(), Duration::from_secs(60), now)
            .unwrap();
    }

    #[test]
    fn expired_unswept_operator_bans_allow_automatic_bans() {
        let dir = tempfile::tempdir().unwrap();
        let book = Arc::new(
            crate::address_book::AddressBook::open_at(&dir.path().join("peers.redb")).unwrap(),
        );
        let now = Instant::now();
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        let addr = SocketAddr::new(ip, 9030);
        for delay in [60, 61] {
            let mut manager = PeerManager::new(1);
            manager.set_address_book(book.clone());
            manager
                .operator_ban(ip, Duration::from_secs(60), now)
                .unwrap();
            manager.record_ban(ip, now + Duration::from_secs(59), true);
            assert!(manager.bans[&ip].operator);
            let expired = now + Duration::from_secs(delay);
            assert!(!manager.is_banned(&addr, expired));
            manager.record_ban(ip, expired, false);
            assert!(manager.is_banned(&addr, expired));
            assert!(!manager.bans[&ip].operator);
            assert_eq!(
                manager.bans[&ip].until,
                expired + Duration::from_secs(2 * 60 * 60)
            );
            // Automatic penalties remain ephemeral, even after an operator TTL.
            let rows = book.load_all(false).unwrap().bans;
            assert_eq!(rows.len(), 1);
            assert!(rows[0].operator);
            assert_eq!(rows[0].count, 1);
        }
    }

    #[test]
    fn automatic_bans_are_not_written_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let book = Arc::new(
            crate::address_book::AddressBook::open_at(&dir.path().join("peers.redb")).unwrap(),
        );
        let mut manager = PeerManager::new(1);
        manager.set_address_book(book.clone());
        manager.record_ban("203.0.113.8".parse().unwrap(), Instant::now(), true);
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
