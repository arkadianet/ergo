//! Persistent peer address book.
//!
//! Survives across restarts so cold-start does not pay the seed-and-gossip
//! re-discovery tax.
//!
//! Storage: `{data_dir}/peers.redb` — independent of the consensus state DB
//! so the address book can be wiped or rebuilt without touching the chain.
//!
//! Persisted state:
//! - **Peers**: addresses we've handshaked OR routable addresses learnt
//!   via gossip. Handshaked records carry `agent_name` / `version`.
//! - **Bans**: per-IP TTL'd bans. Expired entries are deleted on load.
//!
//! Diverges from Scala: Scala persists peers in LevelDB at `data_dir/peers/`
//! but holds bans in-memory. We persist both.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{
    Database, DatabaseError, ReadableTable, TableDefinition, TransactionError, WriteTransaction,
};
use tracing::{info, warn};

/// Open a write transaction with redb quick-repair enabled.
///
/// Every production `begin_write` in this module MUST go through this
/// helper; a single commit that omits the flag leaves `peers.redb`
/// needing full repair on the next dirty open. Tests follow the same
/// rule for uniformity.
#[allow(clippy::result_large_err)] // redb's TransactionError shape is fixed upstream
fn begin_write_qr(db: &Database) -> Result<WriteTransaction, TransactionError> {
    let mut txn = db.begin_write()?;
    txn.set_quick_repair(true);
    Ok(txn)
}

/// Open (or create) the `peers.redb` database with a structured-event
/// repair-progress callback wired in.
///
/// Local copy of `ergo_state::open_with_repair_logging` because
/// `ergo-p2p` has no dependency on `ergo-state`. Emits the same
/// `redb_repair_started` / `_progress` / `_complete` events as the
/// shared helper, with `db = "address_book"`. See that helper's docs
/// for the contract.
#[allow(clippy::result_large_err)] // redb's DatabaseError shape is fixed upstream
fn open_address_book_db(path: &Path) -> Result<Database, DatabaseError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    let repair_started = Arc::new(AtomicBool::new(false));
    let cb_started = repair_started.clone();
    let cb_path = path.display().to_string();

    let t0 = Instant::now();
    let db = Database::builder()
        .set_repair_callback(move |session| {
            let was_started = cb_started.swap(true, Ordering::SeqCst);
            let pct = session.progress() * 100.0;
            if !was_started {
                info!(
                    event = "redb_repair_started",
                    db = "address_book",
                    path = %cb_path,
                    progress_pct = pct,
                    "redb repair started",
                );
            } else {
                info!(
                    event = "redb_repair_progress",
                    db = "address_book",
                    path = %cb_path,
                    progress_pct = pct,
                    "redb repair progress",
                );
            }
        })
        .create(path)?;

    if repair_started.load(Ordering::SeqCst) {
        info!(
            event = "redb_repair_complete",
            db = "address_book",
            path = %path.display(),
            elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
            "redb repair complete",
        );
    }

    Ok(db)
}

// ---- Tables ----

const PEERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("peers");
const BANS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bans");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

const META_SCHEMA_VERSION_KEY: &str = "schema_version";
const SCHEMA_VERSION: u64 = 1;

// ---- Tunables ----

/// Cap on persisted peer rows. Above this, trim by `evict_priority`.
pub const MAX_PEERS: usize = 5000;

/// Records older than this are dropped on load — gossip will replenish.
pub const STALE_AFTER_DAYS: u64 = 30;

/// Trim cadence: check the cap every Nth peer-write.
const EVICT_INTERVAL_WRITES: u64 = 64;

mod codec;
use codec::{
    clamp_name, decode_addr_key, decode_ban, decode_ip_key, decode_persisted_peer, encode_addr_key,
    encode_ban, encode_ip_key, encode_persisted_peer,
};

use crate::peer_manager::PeerOrigin;

// ---- Public types ----

/// Direction of the most recent successful handshake. Persisted so
/// `/info`-style introspection can show whether a peer was tried by us
/// or came to us, even after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone)]
pub struct PersistedPeer {
    pub addr: SocketAddr,
    pub last_handshake: Option<SystemTime>,
    pub last_seen: Option<SystemTime>,
    pub last_failure: Option<SystemTime>,
    pub consecutive_failures: u32,
    pub origin: PeerOrigin,
    pub handshaked: bool,
    pub last_direction: Option<LastDirection>,
    pub agent_name: String,
    pub agent_version: [u8; 3],
    pub node_name: String,
}

#[derive(Debug, Clone)]
pub struct BanRecord {
    pub ip: IpAddr,
    pub until: SystemTime,
    pub count: u32,
    pub permanent: bool,
}

/// What `load_all` returns. The caller wires this into `PeerManager`.
#[derive(Debug, Default)]
pub struct LoadedState {
    pub peers: Vec<PersistedPeer>,
    pub bans: Vec<BanRecord>,
    pub stale_skipped: usize,
    pub corrupt_skipped: usize,
    pub expired_bans_purged: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum AddressBookError {
    #[error("redb error: {0}")]
    Db(String),
    #[error("schema mismatch: stored={stored}, current={current}")]
    SchemaMismatch { stored: u64, current: u64 },
    #[error("io error: {0}")]
    Io(String),
}

impl<E: std::fmt::Display> From<E> for AddressBookError
where
    E: RedbErrorMarker,
{
    fn from(e: E) -> Self {
        Self::Db(e.to_string())
    }
}

/// Marker for redb error families we want to flatten into `AddressBookError::Db`.
/// Avoids one `From` impl per redb error type.
pub trait RedbErrorMarker {}
impl RedbErrorMarker for redb::Error {}
impl RedbErrorMarker for redb::DatabaseError {}
impl RedbErrorMarker for redb::TransactionError {}
impl RedbErrorMarker for redb::TableError {}
impl RedbErrorMarker for redb::StorageError {}
impl RedbErrorMarker for redb::CommitError {}

// ---- AddressBook ----

pub struct AddressBook {
    db: Database,
    writes: AtomicU64,
}

impl AddressBook {
    /// Open or create `{data_dir}/peers.redb`. On corruption, rename the
    /// damaged file to `peers.redb.corrupt-{unix_secs}` and create a fresh
    /// one. Operator can inspect or delete the rename.
    pub fn open(data_dir: &Path) -> Result<Self, AddressBookError> {
        let path = data_dir.join("peers.redb");
        Self::open_at(&path)
    }

    /// Direct path open — used by tests.
    pub fn open_at(path: &Path) -> Result<Self, AddressBookError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| AddressBookError::Io(e.to_string()))?;
        }
        let db = match open_address_book_db(path) {
            Ok(db) => db,
            Err(e) => {
                // Corruption: rename the damaged file out of the way and
                // start fresh. Don't lose data silently — operator sees
                // the rename and can investigate.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let corrupt_path: PathBuf = path.with_extension(format!("redb.corrupt-{now}"));
                warn!(
                    path = %path.display(),
                    corrupt_path = %corrupt_path.display(),
                    error = %e,
                    "address_book open failed; renaming corrupt db and starting fresh",
                );
                if let Err(rename_err) = fs::rename(path, &corrupt_path) {
                    return Err(AddressBookError::Io(format!(
                        "rename corrupt db {} -> {}: {rename_err}",
                        path.display(),
                        corrupt_path.display(),
                    )));
                }
                open_address_book_db(path)?
            }
        };

        // Schema-version handshake. New file → write current. Existing file
        // with mismatched version → operator decides (wipe or migrate).
        {
            let read_txn = db.begin_read()?;
            match read_txn.open_table(META) {
                Ok(t) => {
                    if let Some(stored) = t.get(META_SCHEMA_VERSION_KEY)? {
                        let stored = stored.value();
                        if stored != SCHEMA_VERSION {
                            return Err(AddressBookError::SchemaMismatch {
                                stored,
                                current: SCHEMA_VERSION,
                            });
                        }
                    }
                }
                // META table missing → first open. Will be written below.
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        {
            let write_txn = begin_write_qr(&db)?;
            {
                let mut meta = write_txn.open_table(META)?;
                meta.insert(META_SCHEMA_VERSION_KEY, SCHEMA_VERSION)?;
            }
            write_txn.commit()?;
        }

        Ok(Self {
            db,
            writes: AtomicU64::new(0),
        })
    }

    /// Read every row, filtering stale + corrupt; purge expired bans in
    /// the same write txn that returns to the caller.
    pub fn load_all(&self) -> Result<LoadedState, AddressBookError> {
        let now_wall = SystemTime::now();
        let stale_cutoff = now_wall - Duration::from_secs(STALE_AFTER_DAYS * 24 * 60 * 60);

        let mut state = LoadedState::default();

        // Peers — read-only iteration, decode + filter. A fresh DB has
        // no PEERS table yet (redb doesn't auto-create on read); treat
        // that as an empty result, not an error.
        {
            let read_txn = self.db.begin_read()?;
            match read_txn.open_table(PEERS) {
                Ok(table) => {
                    for row in table.iter()? {
                        let (k, v) = row?;
                        let addr = match decode_addr_key(k.value()) {
                            Some(a) => a,
                            None => {
                                state.corrupt_skipped += 1;
                                continue;
                            }
                        };
                        let body = match decode_persisted_peer(addr, v.value()) {
                            Ok(p) => p,
                            Err(_) => {
                                state.corrupt_skipped += 1;
                                continue;
                            }
                        };
                        if let Some(seen) = body.last_seen {
                            if seen < stale_cutoff {
                                state.stale_skipped += 1;
                                continue;
                            }
                        }
                        state.peers.push(body);
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Bans — collect active, separately collect keys to purge. Same
        // fresh-DB tolerance as PEERS above.
        let mut to_purge: Vec<Vec<u8>> = Vec::new();
        {
            let read_txn = self.db.begin_read()?;
            match read_txn.open_table(BANS) {
                Ok(table) => {
                    for row in table.iter()? {
                        let (k, v) = row?;
                        let ip = match decode_ip_key(k.value()) {
                            Some(ip) => ip,
                            None => {
                                state.corrupt_skipped += 1;
                                continue;
                            }
                        };
                        match decode_ban(ip, v.value()) {
                            Ok(b) if b.until > now_wall || b.permanent => state.bans.push(b),
                            Ok(_) => to_purge.push(k.value().to_vec()),
                            Err(_) => state.corrupt_skipped += 1,
                        }
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        if !to_purge.is_empty() {
            let write_txn = begin_write_qr(&self.db)?;
            {
                let mut table = write_txn.open_table(BANS)?;
                for k in &to_purge {
                    table.remove(k.as_slice())?;
                }
            }
            write_txn.commit()?;
            state.expired_bans_purged = to_purge.len();
        }

        Ok(state)
    }

    /// Write a fresh handshaked record. Preserves `FROM_SEED` from any prior
    /// row at this address. Atomic via `mutate_peer`.
    pub fn upsert_handshaked(
        &self,
        addr: SocketAddr,
        agent_name: &str,
        agent_version: [u8; 3],
        node_name: &str,
        direction: LastDirection,
        now: SystemTime,
    ) -> Result<(), AddressBookError> {
        let agent_name = clamp_name(agent_name);
        let node_name = clamp_name(node_name);
        self.mutate_peer(addr, |prior| {
            let origin = prior
                .as_ref()
                .map(|p| p.origin)
                .unwrap_or(PeerOrigin::Gossip);
            Some(PersistedPeer {
                addr,
                last_handshake: Some(now),
                last_seen: Some(now),
                last_failure: None,
                consecutive_failures: 0,
                origin,
                handshaked: true,
                last_direction: Some(direction),
                agent_name,
                agent_version,
                node_name,
            })
        })?;
        self.maybe_evict()?;
        Ok(())
    }

    /// Update `last_seen` on the existing record (does not change handshake
    /// state). No-op if the address is absent. Atomic via `mutate_peer`.
    pub fn touch_seen(&self, addr: SocketAddr, now: SystemTime) -> Result<(), AddressBookError> {
        self.mutate_peer(addr, |prior| {
            prior.map(|mut p| {
                p.last_seen = Some(now);
                p
            })
        })
    }

    /// Increment `consecutive_failures` and stamp `last_failure`. Creates
    /// a stub (HANDSHAKED clear) if the address is unknown. Atomic via
    /// `mutate_peer` so concurrent dial-failure hooks no longer lose
    /// counter increments.
    pub fn mark_failure(&self, addr: SocketAddr, now: SystemTime) -> Result<(), AddressBookError> {
        self.mutate_peer(addr, |prior| {
            let record = match prior {
                Some(mut p) => {
                    p.last_failure = Some(now);
                    p.consecutive_failures = p.consecutive_failures.saturating_add(1);
                    p
                }
                None => PersistedPeer {
                    addr,
                    last_handshake: None,
                    last_seen: None,
                    last_failure: Some(now),
                    consecutive_failures: 1,
                    origin: PeerOrigin::Gossip,
                    handshaked: false,
                    last_direction: None,
                    agent_name: String::new(),
                    agent_version: [0; 3],
                    node_name: String::new(),
                },
            };
            Some(record)
        })?;
        self.maybe_evict()?;
        Ok(())
    }

    /// Clear failure state on success (next dial starts fresh). Atomic via
    /// `mutate_peer`.
    pub fn mark_success(&self, addr: SocketAddr, now: SystemTime) -> Result<(), AddressBookError> {
        self.mutate_peer(addr, |prior| {
            prior.map(|mut p| {
                p.last_failure = None;
                p.consecutive_failures = 0;
                p.last_seen = Some(now);
                p
            })
        })
    }

    /// Add a known address (gossip ingest or config seed). Don't overwrite
    /// an existing handshaked record from a gossip ingest (mirrors Scala's
    /// `AddPeerIfEmpty` semantic). Upgrades the origin to `Seed` if the
    /// caller asserts so even when the row already exists. Atomic via
    /// `mutate_peer`.
    pub fn add_known(&self, addr: SocketAddr, origin: PeerOrigin) -> Result<(), AddressBookError> {
        self.mutate_peer(addr, |prior| match prior {
            Some(mut p) => {
                if origin.is_seed() && !p.origin.is_seed() {
                    p.origin = PeerOrigin::Seed;
                    Some(p)
                } else {
                    None // existing row, no upgrade needed
                }
            }
            None => Some(PersistedPeer {
                addr,
                last_handshake: None,
                last_seen: None,
                last_failure: None,
                consecutive_failures: 0,
                origin,
                handshaked: false,
                last_direction: None,
                agent_name: String::new(),
                agent_version: [0; 3],
                node_name: String::new(),
            }),
        })?;
        self.maybe_evict()?;
        Ok(())
    }

    /// Forget an address entirely (e.g. operator-side surgery).
    pub fn remove_peer(&self, addr: SocketAddr) -> Result<(), AddressBookError> {
        let key = encode_addr_key(addr);
        let write_txn = begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(PEERS)?;
            t.remove(key.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn record_ban(&self, ban: &BanRecord) -> Result<(), AddressBookError> {
        let key = encode_ip_key(ban.ip);
        let val = encode_ban(ban);
        let write_txn = begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(BANS)?;
            t.insert(key.as_slice(), val.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn unban(&self, ip: IpAddr) -> Result<(), AddressBookError> {
        let key = encode_ip_key(ip);
        let write_txn = begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(BANS)?;
            t.remove(key.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ---- Internal ----

    /// Atomic read-modify-write over the PEERS table for one address.
    ///
    /// The mutator receives the prior `PersistedPeer` (if any) and
    /// returns `Some(record)` to persist or `None` to skip the write.
    /// Both the read and the write happen inside the same redb
    /// `WriteTransaction`, so concurrent calls on the same address
    /// can no longer lose updates the way `read_peer` + `write_peer`
    /// across separate transactions could.
    fn mutate_peer<F>(&self, addr: SocketAddr, mutator: F) -> Result<(), AddressBookError>
    where
        F: FnOnce(Option<PersistedPeer>) -> Option<PersistedPeer>,
    {
        let key = encode_addr_key(addr);
        let write_txn = begin_write_qr(&self.db)?;
        let mut wrote = false;
        {
            let mut table = write_txn.open_table(PEERS)?;
            let prior_bytes: Option<Vec<u8>> =
                table.get(key.as_slice())?.map(|row| row.value().to_vec());
            let prior = match prior_bytes.as_deref() {
                Some(bytes) => match decode_persisted_peer(addr, bytes) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        // A corrupt persisted record used to be dropped
                        // silently (.ok()); behaviour is unchanged (still
                        // None -> mutator sees no prior), but storage
                        // corruption is now visible.
                        tracing::warn!(addr = %addr, error = ?e, "address book: corrupt persisted peer record; ignoring prior state");
                        None
                    }
                },
                None => None,
            };
            if let Some(record) = mutator(prior) {
                let val = encode_persisted_peer(&record);
                table.insert(key.as_slice(), val.as_slice())?;
                wrote = true;
            }
        }
        write_txn.commit()?;
        if wrote {
            self.writes.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn maybe_evict(&self) -> Result<(), AddressBookError> {
        let count = self.writes.load(Ordering::Relaxed);
        if count == 0 || !count.is_multiple_of(EVICT_INTERVAL_WRITES) {
            return Ok(());
        }
        self.trim_to_cap()
    }

    /// Read every peer row, sort by eviction priority, delete the oldest
    /// rows above the cap. O(N log N) on N rows; bounded by `MAX_PEERS`
    /// in steady state.
    fn trim_to_cap(&self) -> Result<(), AddressBookError> {
        let mut all: Vec<(Vec<u8>, PersistedPeer)> = Vec::new();
        {
            let read_txn = self.db.begin_read()?;
            let table = match read_txn.open_table(PEERS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            for row in table.iter()? {
                let (k, v) = row?;
                let key_bytes = k.value().to_vec();
                let addr = match decode_addr_key(&key_bytes) {
                    Some(a) => a,
                    None => continue,
                };
                if let Ok(p) = decode_persisted_peer(addr, v.value()) {
                    all.push((key_bytes, p));
                }
            }
        }

        if all.len() <= MAX_PEERS {
            return Ok(());
        }

        all.sort_by_key(|(_, p)| evict_priority(p));
        let to_delete = all.len() - MAX_PEERS;
        let write_txn = begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(PEERS)?;
            for (k, _) in all.iter().take(to_delete) {
                t.remove(k.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}

/// Sort key for eviction: lower priority is evicted first.
///
/// Tier 0: failed gossip-only — ascending `last_failure` (oldest first).
/// Tier 1: unhandshaked, no failures yet — arbitrary (last_seen=0).
/// Tier 2: handshaked — ascending `last_seen` (oldest first).
fn evict_priority(p: &PersistedPeer) -> (u8, u64) {
    let last_seen_secs = p
        .last_seen
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last_failure_secs = p
        .last_failure
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !p.handshaked && last_failure_secs > 0 {
        (0, last_failure_secs)
    } else if !p.handshaked {
        (1, last_seen_secs)
    } else {
        (2, last_seen_secs)
    }
}

#[allow(dead_code)]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AddressBook>();
};

#[cfg(test)]
mod tests {
    use super::codec::{KIND_IPV4, MAX_NAME_LEN, SCHEMA_TAG_PEER};
    use super::*;
    use std::net::Ipv6Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from([a, b, c, d]), port)
    }

    fn v6_addr(s: &str, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()), port)
    }

    fn now_secs() -> SystemTime {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    // ---- begin_write_qr helper ----
    //
    // redb 2.6.3 does not expose a getter for the quick-repair flag on
    // `WriteTransaction`, and `Database::drop` ensures allocator state
    // on graceful close — so these tests can only catch a broken helper
    // signature or open path, not the actual crash-recovery win. The
    // load-bearing artifact is enforcing this helper at every call site
    // in production code.

    #[test]
    fn begin_write_qr_round_trips_through_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qr_p2p_smoke.redb");
        let table: TableDefinition<&str, &[u8]> = TableDefinition::new("t");

        {
            let db = Database::create(&path).unwrap();
            let txn = begin_write_qr(&db).unwrap();
            {
                let mut t = txn.open_table(table).unwrap();
                t.insert("k", b"v".as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        let cb_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cb = cb_fired.clone();
        let db = redb::Builder::new()
            .set_repair_callback(move |_| {
                cb.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .create(&path)
            .unwrap();
        assert!(
            !cb_fired.load(std::sync::atomic::Ordering::SeqCst),
            "repair callback fired on graceful reopen — open path broken"
        );

        let read_txn = db.begin_read().unwrap();
        let t = read_txn.open_table(table).unwrap();
        let got = t.get("k").unwrap().unwrap();
        assert_eq!(got.value(), b"v");
    }

    // ---- Address-key codec ----

    #[test]
    fn addr_key_roundtrip_ipv4() {
        let addr = v4(213, 239, 193, 208, 9030);
        let k = encode_addr_key(addr);
        assert_eq!(k.len(), 7);
        assert_eq!(decode_addr_key(&k), Some(addr));
    }

    #[test]
    fn addr_key_roundtrip_ipv6() {
        let addr = v6_addr("2001:41d0:700:6662::", 29031);
        let k = encode_addr_key(addr);
        assert_eq!(k.len(), 19);
        assert_eq!(decode_addr_key(&k), Some(addr));
    }

    #[test]
    fn addr_key_rejects_malformed() {
        assert_eq!(decode_addr_key(&[]), None);
        assert_eq!(decode_addr_key(&[0xff, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(decode_addr_key(&[KIND_IPV4, 1, 2, 3]), None); // truncated
    }

    // ---- IP-key codec ----

    #[test]
    fn ip_key_roundtrip() {
        let ip4 = IpAddr::from([10, 0, 0, 1]);
        let ip6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(decode_ip_key(&encode_ip_key(ip4)), Some(ip4));
        assert_eq!(decode_ip_key(&encode_ip_key(ip6)), Some(ip6));
    }

    // ---- PersistedPeer codec ----

    #[test]
    fn persisted_peer_roundtrip_handshaked() {
        let addr = v4(1, 2, 3, 4, 9030);
        let now = now_secs();
        let p = PersistedPeer {
            addr,
            last_handshake: Some(now),
            last_seen: Some(now),
            last_failure: None,
            consecutive_failures: 0,
            origin: PeerOrigin::Seed,
            handshaked: true,
            last_direction: Some(LastDirection::Outbound),
            agent_name: "ergoref".into(),
            agent_version: [4, 0, 200],
            node_name: "node-α".into(),
        };
        let bytes = encode_persisted_peer(&p);
        let decoded = decode_persisted_peer(addr, &bytes).expect("decode");
        assert_eq!(decoded.addr, p.addr);
        assert_eq!(decoded.last_handshake, p.last_handshake);
        assert_eq!(decoded.last_seen, p.last_seen);
        assert_eq!(decoded.last_failure, None);
        assert_eq!(decoded.consecutive_failures, 0);
        assert_eq!(decoded.origin, PeerOrigin::Seed);
        assert!(decoded.handshaked);
        assert_eq!(decoded.last_direction, Some(LastDirection::Outbound));
        assert_eq!(decoded.agent_name, "ergoref");
        assert_eq!(decoded.agent_version, [4, 0, 200]);
        assert_eq!(decoded.node_name, "node-α");
    }

    #[test]
    fn persisted_peer_roundtrip_gossip_stub() {
        let addr = v4(5, 6, 7, 8, 9030);
        let p = PersistedPeer {
            addr,
            last_handshake: None,
            last_seen: None,
            last_failure: Some(now_secs()),
            consecutive_failures: 3,
            origin: PeerOrigin::Gossip,
            handshaked: false,
            last_direction: None,
            agent_name: String::new(),
            agent_version: [0; 3],
            node_name: String::new(),
        };
        let decoded = decode_persisted_peer(addr, &encode_persisted_peer(&p)).expect("decode");
        assert!(!decoded.handshaked);
        assert_eq!(decoded.origin, PeerOrigin::Gossip);
        assert_eq!(decoded.last_direction, None);
        assert_eq!(decoded.consecutive_failures, 3);
        assert!(decoded.last_failure.is_some());
    }

    #[test]
    fn persisted_peer_inbound_direction() {
        let addr = v4(9, 9, 9, 9, 9030);
        let p = PersistedPeer {
            addr,
            last_handshake: Some(now_secs()),
            last_seen: Some(now_secs()),
            last_failure: None,
            consecutive_failures: 0,
            origin: PeerOrigin::Gossip,
            handshaked: true,
            last_direction: Some(LastDirection::Inbound),
            agent_name: "x".into(),
            agent_version: [0; 3],
            node_name: "y".into(),
        };
        let decoded = decode_persisted_peer(addr, &encode_persisted_peer(&p)).expect("decode");
        assert_eq!(decoded.last_direction, Some(LastDirection::Inbound));
    }

    #[test]
    fn persisted_peer_unknown_schema_tag_rejected() {
        let bytes = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(decode_persisted_peer(v4(1, 1, 1, 1, 1), &bytes).is_err());
    }

    #[test]
    fn persisted_peer_truncated_rejected() {
        let p = PersistedPeer {
            addr: v4(1, 2, 3, 4, 9030),
            last_handshake: None,
            last_seen: None,
            last_failure: None,
            consecutive_failures: 0,
            origin: PeerOrigin::Gossip,
            handshaked: false,
            last_direction: None,
            agent_name: String::new(),
            agent_version: [0; 3],
            node_name: String::new(),
        };
        let mut bytes = encode_persisted_peer(&p);
        bytes.truncate(bytes.len() / 2);
        assert!(decode_persisted_peer(p.addr, &bytes).is_err());
    }

    #[test]
    fn persisted_peer_oversize_name_rejected_on_decode() {
        // Construct a payload claiming agent_name_len = MAX_NAME_LEN + 1.
        let mut bytes = Vec::new();
        bytes.push(SCHEMA_TAG_PEER);
        bytes.extend_from_slice(&0u64.to_be_bytes()); // last_handshake
        bytes.extend_from_slice(&0u64.to_be_bytes()); // last_seen
        bytes.extend_from_slice(&0u64.to_be_bytes()); // last_failure
        bytes.extend_from_slice(&0u32.to_be_bytes()); // consecutive_failures
        bytes.push(0); // flags
        bytes.extend_from_slice(&[0; 3]); // agent_version
        bytes.extend_from_slice(&((MAX_NAME_LEN + 1) as u16).to_be_bytes());
        bytes.extend(std::iter::repeat_n(b'a', MAX_NAME_LEN + 1));
        bytes.extend_from_slice(&0u16.to_be_bytes()); // node_name_len
        assert!(decode_persisted_peer(v4(1, 1, 1, 1, 1), &bytes).is_err());
    }

    #[test]
    fn clamp_name_truncates_at_char_boundary() {
        let s = "α".repeat(200); // 400 bytes — > MAX_NAME_LEN=256
        let clamped = clamp_name(&s);
        assert!(clamped.len() <= MAX_NAME_LEN);
        // Must still parse as valid UTF-8 (clamp truncates at char boundary).
        let _ = std::str::from_utf8(clamped.as_bytes()).expect("clamp must keep utf8 valid");
    }

    // ---- BanRecord codec ----

    #[test]
    fn ban_record_roundtrip() {
        let ip = IpAddr::from([10, 0, 0, 1]);
        let until = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let b = BanRecord {
            ip,
            until,
            count: 3,
            permanent: false,
        };
        let bytes = encode_ban(&b);
        let decoded = decode_ban(ip, &bytes).expect("decode");
        assert_eq!(decoded.ip, ip);
        assert_eq!(decoded.until, until);
        assert_eq!(decoded.count, 3);
        assert!(!decoded.permanent);
    }

    #[test]
    fn ban_record_permanent_flag_persists() {
        let ip = IpAddr::from([10, 0, 0, 1]);
        let b = BanRecord {
            ip,
            until: UNIX_EPOCH + Duration::from_secs(99_999_999_999),
            count: 1,
            permanent: true,
        };
        let decoded = decode_ban(ip, &encode_ban(&b)).expect("decode");
        assert!(decoded.permanent);
    }

    #[test]
    fn ban_record_unknown_tag_rejected() {
        let bytes = vec![0xEE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(decode_ban(IpAddr::from([0, 0, 0, 0]), &bytes).is_err());
    }

    // ---- evict_priority ordering ----

    #[test]
    fn evict_priority_orders_failed_gossip_first() {
        let now = now_secs();
        let a = PersistedPeer {
            addr: v4(1, 1, 1, 1, 9030),
            last_handshake: None,
            last_seen: None,
            last_failure: Some(now),
            consecutive_failures: 1,
            origin: PeerOrigin::Gossip,
            handshaked: false,
            last_direction: None,
            agent_name: String::new(),
            agent_version: [0; 3],
            node_name: String::new(),
        };
        let b = PersistedPeer {
            handshaked: false,
            last_failure: None,
            last_seen: None,
            ..a.clone()
        };
        let c = PersistedPeer {
            handshaked: true,
            last_seen: Some(now),
            ..a.clone()
        };
        let pa = evict_priority(&a);
        let pb = evict_priority(&b);
        let pc = evict_priority(&c);
        assert!(pa < pb, "failed-gossip < unhandshaked: {pa:?} vs {pb:?}");
        assert!(pb < pc, "unhandshaked < handshaked: {pb:?} vs {pc:?}");
    }
}
