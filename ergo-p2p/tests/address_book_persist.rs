//! Integration tests for `AddressBook` persistence semantics.
//!
//! These exercise the on-disk file end-to-end: open → write → drop →
//! reopen → load. Unit tests in `address_book.rs` cover the codec and
//! eviction logic; this file covers what survives a process restart.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use ergo_p2p::address_book::{AddressBook, BanRecord, LastDirection, STALE_AFTER_DAYS};
use ergo_p2p::peer_manager::PeerOrigin;

fn sock(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

fn open(path: &std::path::Path) -> AddressBook {
    AddressBook::open_at(path).expect("open address book")
}

#[test]
fn handshaked_peer_round_trips_through_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");

    let addr = sock(1, 2, 3, 4, 9030);
    let now = SystemTime::now();
    {
        let book = open(&path);
        book.upsert_handshaked(
            addr,
            "ergoref",
            [4, 0, 100],
            "node-1",
            LastDirection::Outbound,
            now,
        )
        .unwrap();
    }

    let book = open(&path);
    let state = book.load_all().unwrap();
    assert_eq!(state.peers.len(), 1);
    let p = &state.peers[0];
    assert_eq!(p.addr, addr);
    assert!(p.handshaked);
    assert_eq!(p.agent_name, "ergoref");
    assert_eq!(p.agent_version, [4, 0, 100]);
    assert_eq!(p.node_name, "node-1");
    assert_eq!(p.last_direction, Some(LastDirection::Outbound));
}

#[test]
fn gossip_then_handshake_upgrades_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");

    let addr = sock(5, 6, 7, 8, 9030);
    let now = SystemTime::now();
    {
        let book = open(&path);
        book.add_known(addr, PeerOrigin::Gossip).unwrap();
        book.upsert_handshaked(addr, "ergoref", [5, 0, 0], "n", LastDirection::Inbound, now)
            .unwrap();
    }

    let book = open(&path);
    let state = book.load_all().unwrap();
    assert_eq!(state.peers.len(), 1);
    assert!(state.peers[0].handshaked);
}

#[test]
fn stale_peer_skipped_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");

    let addr = sock(9, 9, 9, 9, 9030);
    let stale = SystemTime::now() - Duration::from_secs((STALE_AFTER_DAYS + 1) * 24 * 60 * 60);
    {
        let book = open(&path);
        book.upsert_handshaked(
            addr,
            "old",
            [4, 0, 100],
            "n",
            LastDirection::Outbound,
            stale,
        )
        .unwrap();
    }

    let book = open(&path);
    let state = book.load_all().unwrap();
    assert_eq!(state.peers.len(), 0);
    assert_eq!(state.stale_skipped, 1);
}

#[test]
fn expired_ban_purged_on_load_permanent_survives() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");

    let expired_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let perm_ip = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    {
        let book = open(&path);
        book.record_ban(&BanRecord {
            ip: expired_ip,
            until: SystemTime::now() - Duration::from_secs(60),
            count: 1,
            permanent: false,
        })
        .unwrap();
        book.record_ban(&BanRecord {
            ip: perm_ip,
            until: SystemTime::now() - Duration::from_secs(60),
            count: 99,
            permanent: true,
        })
        .unwrap();
    }

    let book = open(&path);
    let state = book.load_all().unwrap();
    assert_eq!(state.bans.len(), 1, "permanent ban must survive expiry");
    assert_eq!(state.bans[0].ip, perm_ip);
    assert_eq!(state.expired_bans_purged, 1);

    // Re-load to confirm the purge is durable, not just in-memory.
    let state2 = book.load_all().unwrap();
    assert_eq!(state2.bans.len(), 1);
    assert_eq!(state2.expired_bans_purged, 0);
}

#[test]
fn failure_then_success_clears_backoff_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");

    let addr = sock(7, 7, 7, 7, 9030);
    {
        let book = open(&path);
        book.mark_failure(addr, SystemTime::now()).unwrap();
        book.mark_failure(addr, SystemTime::now()).unwrap();
        book.mark_success(addr, SystemTime::now()).unwrap();
    }

    let book = open(&path);
    let state = book.load_all().unwrap();
    assert_eq!(state.peers.len(), 1);
    let p = &state.peers[0];
    assert_eq!(p.consecutive_failures, 0);
    assert!(p.last_failure.is_none());
    assert!(p.last_seen.is_some());
}

#[test]
fn unban_removes_entry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    {
        let book = open(&path);
        book.record_ban(&BanRecord {
            ip,
            until: SystemTime::now() + Duration::from_secs(3600),
            count: 1,
            permanent: false,
        })
        .unwrap();
        book.unban(ip).unwrap();
    }

    let book = open(&path);
    let state = book.load_all().unwrap();
    assert_eq!(state.bans.len(), 0);
}

#[test]
fn corruption_renames_and_starts_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");

    // Write garbage that redb cannot parse as a valid file.
    std::fs::write(&path, b"not a redb file at all, just bytes").unwrap();

    // Open should succeed by renaming the corrupt file and creating fresh.
    let book = AddressBook::open_at(&path).expect("recover from corruption");
    let state = book.load_all().unwrap();
    assert_eq!(state.peers.len(), 0);
    assert_eq!(state.bans.len(), 0);

    // Verify a `.corrupt-*` rename sibling exists.
    let parent = path.parent().unwrap();
    let mut found_rename = false;
    for entry in std::fs::read_dir(parent).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("peers.redb.corrupt-") {
            found_rename = true;
            break;
        }
    }
    assert!(found_rename, "corrupt rename sibling not found");
}

#[test]
fn add_known_does_not_overwrite_handshaked_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");
    let addr = sock(3, 3, 3, 3, 9030);
    let now = SystemTime::now();
    {
        let book = open(&path);
        book.upsert_handshaked(
            addr,
            "ergoref",
            [4, 0, 100],
            "n",
            LastDirection::Outbound,
            now,
        )
        .unwrap();
        // Gossip ingest of the same address must not blank the agent fields.
        book.add_known(addr, PeerOrigin::Gossip).unwrap();
    }

    let book = open(&path);
    let state = book.load_all().unwrap();
    assert_eq!(state.peers.len(), 1);
    let p = &state.peers[0];
    assert!(p.handshaked, "handshake bit must survive gossip add_known");
    assert_eq!(p.agent_name, "ergoref");
}

#[test]
fn peer_manager_restores_known_peers_and_bans_from_persisted_address_book() {
    // End-to-end restore-on-restart: persist a handful of peers + a
    // ban via AddressBook, drop the book, reopen from the same path,
    // call load_all, hydrate a PeerManager via restore_known_peer +
    // restore_ban, and verify the PeerManager's observable state
    // (known_addresses_len, is_banned) matches what was persisted.
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ergo_p2p::peer_manager::{KnownPeer, PeerManager};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");
    let now_wall = SystemTime::now();
    let banned_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));

    // --- session 1: write state + close ---
    {
        let book = open(&path);
        // A handshaked peer (origin defaults to Gossip since add_known
        // wasn't called).
        book.upsert_handshaked(
            sock(5, 5, 5, 5, 9030),
            "ergoref",
            [4, 0, 100],
            "n1",
            LastDirection::Outbound,
            now_wall,
        )
        .unwrap();
        // A gossip-learned peer that picked up failures.
        book.add_known(sock(6, 6, 6, 6, 9030), PeerOrigin::Gossip)
            .unwrap();
        book.mark_failure(sock(6, 6, 6, 6, 9030), now_wall).unwrap();
        book.mark_failure(sock(6, 6, 6, 6, 9030), now_wall).unwrap();
        // A seed-trusted peer.
        book.add_known(sock(7, 7, 7, 7, 9030), PeerOrigin::Seed)
            .unwrap();
        // A ban that's still in the future.
        book.record_ban(&BanRecord {
            ip: banned_ip,
            until: now_wall + Duration::from_secs(3600),
            count: 2,
            permanent: false,
        })
        .unwrap();
    }

    // --- session 2: reopen, load, hydrate PeerManager ---
    let book = Arc::new(open(&path));
    let state = book.load_all().expect("load_all");
    assert_eq!(state.peers.len(), 3, "all three peers must survive");
    assert_eq!(state.bans.len(), 1, "the ban must survive");

    let mut mgr = PeerManager::new(42);
    let mono_now = Instant::now();
    for p in &state.peers {
        mgr.restore_known_peer(KnownPeer {
            addr: p.addr,
            last_seen: p.last_seen.map(|_| mono_now),
            origin: p.origin,
            last_failure: p.last_failure.map(|_| mono_now),
            consecutive_failures: p.consecutive_failures,
        });
    }
    for b in &state.bans {
        // The ban's persisted `until` is wall-clock; in the restored
        // PeerManager it becomes a monotonic Instant. For this test
        // we set it 1 hour into the monotonic future to mirror the
        // wall-clock offset.
        mgr.restore_ban(b.ip, mono_now + Duration::from_secs(3600), b.count);
    }

    // PeerManager now mirrors the persisted set.
    assert_eq!(
        mgr.known_addresses_len(),
        3,
        "three known addresses must be restored"
    );
    assert!(
        mgr.is_banned(&std::net::SocketAddr::new(banned_ip, 9030), mono_now),
        "the persisted ban must surface through PeerManager::is_banned"
    );

    // The seed-trusted peer must keep that flag through restore.
    let seeds: Vec<_> = state.peers.iter().filter(|p| p.origin.is_seed()).collect();
    assert_eq!(seeds.len(), 1, "exactly one seed survived");
    assert_eq!(seeds[0].addr, sock(7, 7, 7, 7, 9030));

    // The gossip peer with two failures kept its counter.
    let gossip = state
        .peers
        .iter()
        .find(|p| p.addr == sock(6, 6, 6, 6, 9030))
        .expect("gossip peer present");
    assert_eq!(
        gossip.consecutive_failures, 2,
        "two mark_failure calls must persist as count=2"
    );
}

#[test]
fn mark_failure_atomic_under_concurrent_calls() {
    // Regression for the split-transaction lost-update hazard. Before
    // `mutate_peer`, `mark_failure` did read_peer + write_peer across
    // separate redb transactions; concurrent callers on the same
    // address could lose increments. After the fix the read and write
    // happen inside a single WriteTransaction, so a fan-out of N
    // threads × M increments must yield exactly N×M as the final
    // `consecutive_failures`.
    use std::sync::Arc;
    use std::thread;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peers.redb");
    let book = Arc::new(open(&path));
    let addr = sock(4, 4, 4, 4, 9030);

    const N_THREADS: u32 = 8;
    const N_PER_THREAD: u32 = 25;
    let mut handles = Vec::with_capacity(N_THREADS as usize);
    for _ in 0..N_THREADS {
        let book = book.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..N_PER_THREAD {
                book.mark_failure(addr, SystemTime::now())
                    .expect("mark_failure ok");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let state = book.load_all().unwrap();
    let p = state
        .peers
        .iter()
        .find(|p| p.addr == addr)
        .expect("address present");
    assert_eq!(
        p.consecutive_failures,
        N_THREADS * N_PER_THREAD,
        "every increment must land — no lost updates from split-txn race"
    );
}
