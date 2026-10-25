//! Encrypted redb storage backend for `wallet.redb`.
//!
//! redb reads and writes a flat byte space through [`StorageBackend`]. This
//! backend presents that logical space to redb and stores it on disk as
//! 4 KiB sectors, each sealed with AES-256-GCM under a fresh random nonce.
//! The sector's index and the file's random identifier are the associated
//! data, so a sector cannot be moved, swapped between files or altered
//! without its read failing. Every wallet table, index and redb metadata page
//! is therefore unreadable without the data key, while the store code above
//! is unchanged.
//!
//! The data key never touches the disk in the clear: the daemon keeps it in
//! the password-encrypted keystore (or in a passphrase-wrapped key file for
//! watch-only wallets) and holds it in memory only while unsealed.
//!
//! Layout: a plaintext header region of [`HEADER_BYTES`], then sector `i` at
//! `HEADER_BYTES + i * PHYSICAL_SECTOR`. The header holds two slots written
//! alternately with a sequence number and an HMAC, so a torn header write
//! leaves the other slot valid. Space added by growth is written as sealed
//! zeros, so an all-zero sector on disk is corruption, never an implicit hole.
//!
//! Each sector is stored as two copies, `sequence ‖ nonce ‖ ciphertext ‖ tag`,
//! with the sequence number in the associated data; a read uses the newest
//! copy that authenticates. A write never touches the last copy made durable
//! by `sync_data`: it goes to the other copy, or rewrites a copy written since
//! the last sync. Plain redb relies on a torn write damaging only the bytes
//! written, and it rewrites its commit header in place; here every write
//! re-seals a whole sector, so without the second copy a crash during a
//! header update would leave neither commit slot readable. With it, an
//! interrupted write leaves the sector's last durable contents intact.
//!
//! Residual exposure: the file length reveals the database size, sectors
//! rewritten with identical contents are not linkable (fresh nonces) but write
//! timing is observable, and an attacker who can modify the file can roll a
//! sector back to an older sealed version of itself, for example by damaging
//! its newest copy.
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Bound;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key};
use hmac::{Hmac, Mac};
use parking_lot::{Mutex, RwLock};
use redb::backends::FileBackend;
use redb::{BackendError, StorageBackend};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Logical bytes per sector.
pub const SECTOR: usize = 4096;
const NONCE: usize = 12;
const TAG: usize = 16;
/// On-disk bytes of one sealed copy of a sector.
const COPY: usize = 8 + NONCE + SECTOR + TAG;
/// On-disk bytes per sector: two copies.
pub const PHYSICAL_SECTOR: usize = 2 * COPY;
/// Plaintext header region at the start of the file.
pub const HEADER_BYTES: u64 = 4096;
const SLOT_BYTES: usize = 2048;
const MAGIC: &[u8; 8] = b"ERGWDBE\x01";
const FORMAT_VERSION: u32 = 2;
const REDB_MAGIC: &[u8] = b"redb";

/// A 256-bit data key. Wiped on drop.
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    /// Wrap existing key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Parse 64 hex characters, as `ergo-walletd export-unseal-key` prints
    /// them; surrounding whitespace is ignored.
    pub fn from_hex(text: &str) -> Option<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text.trim(), bytes.as_mut()).ok()?;
        Some(Self(bytes))
    }

    /// A fresh random key from the operating system.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, bytes.as_mut());
        Self(bytes)
    }

    /// The raw key, for wrapping into a keystore.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    fn derive(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.0.as_slice())
            .expect("HMAC accepts any key length");
        mac.update(label);
        Zeroizing::new(mac.finalize().into_bytes().into())
    }
}

impl Clone for DataKey {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataKey([REDACTED])")
    }
}

/// Why an encrypted database could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum EncryptedDbError {
    #[error("wallet database is not encrypted")]
    Cleartext,
    #[error("wallet database key does not match")]
    WrongKey,
    #[error("wallet database is corrupt or was modified: {0}")]
    Corrupt(String),
    #[error("wallet database I/O failure: {0}")]
    Io(#[from] io::Error),
    #[error("wallet database lock failure: {0}")]
    Lock(String),
}

#[derive(Clone, Copy)]
struct Header {
    sequence: u64,
    logical_len: u64,
}

struct State {
    header: Header,
    /// Slot written last; the next header write goes to the other one.
    current_slot: usize,
}

/// The copy of a sector that holds its newest contents.
#[derive(Clone, Copy)]
struct Current {
    copy: usize,
    sequence: u64,
}

/// Which copy of each sector is current, learned as sectors are touched, and
/// which sectors were written since the last `sync_data`.
#[derive(Default)]
struct Copies {
    current: HashMap<u64, Current>,
    dirty: HashSet<u64>,
}

/// redb [`StorageBackend`] that seals every sector with AES-256-GCM.
pub struct EncryptedBackend {
    inner: FileBackend,
    cipher: Aes256Gcm,
    mac_key: Zeroizing<[u8; 32]>,
    key_check: [u8; 32],
    file_id: [u8; 16],
    state: RwLock<State>,
    copies: Mutex<Copies>,
}

impl fmt::Debug for EncryptedBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedBackend")
            .field("logical_len", &self.state.read().header.logical_len)
            .finish_non_exhaustive()
    }
}

fn corrupt(message: impl Into<String>) -> EncryptedDbError {
    EncryptedDbError::Corrupt(message.into())
}

impl EncryptedBackend {
    /// Create a new, empty encrypted database file. The path must not exist.
    ///
    /// The file is initialized under a temporary name and renamed into place
    /// only after its header is durable, so a crash never leaves a
    /// half-initialized file at `path`.
    pub fn create(path: &Path, key: &DataKey) -> Result<Self, EncryptedDbError> {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists).into());
        }
        let file_name = path
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut pending_name = file_name.to_os_string();
        pending_name.push(".creating");
        let pending = path.with_file_name(pending_name);
        // A leftover from an interrupted create was never published.
        match std::fs::remove_file(&pending) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&pending)?;
        let backend = match Self::initialize(file, key) {
            Ok(backend) => backend,
            Err(error) => {
                let _ = std::fs::remove_file(&pending);
                return Err(error);
            }
        };
        if let Err(error) = publish(&pending, path) {
            let _ = backend.inner.close();
            drop(backend);
            let _ = std::fs::remove_file(&pending);
            return Err(error.into());
        }
        Ok(backend)
    }

    fn initialize(file: File, key: &DataKey) -> Result<Self, EncryptedDbError> {
        let mut file_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut file_id);
        let backend = Self::assemble(
            file,
            key,
            file_id,
            Header {
                sequence: 0,
                logical_len: 0,
            },
            1,
        )?;
        backend.inner.set_len(HEADER_BYTES)?;
        // Write both slots so either can be read back.
        backend.write_slot(
            0,
            Header {
                sequence: 0,
                logical_len: 0,
            },
        )?;
        backend.write_slot(
            1,
            Header {
                sequence: 1,
                logical_len: 0,
            },
        )?;
        backend.state.write().header.sequence = 1;
        backend.inner.sync_data()?;
        Ok(backend)
    }

    /// Open an existing encrypted database file with `key`.
    pub fn open(path: &Path, key: &DataKey) -> Result<Self, EncryptedDbError> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let length = file.metadata()?.len();
        let mut region = vec![0u8; HEADER_BYTES as usize];
        if length < HEADER_BYTES {
            let mut prefix = vec![0u8; length as usize];
            read_exact_at(&file, &mut prefix, 0)?;
            return Err(if prefix.starts_with(REDB_MAGIC) {
                EncryptedDbError::Cleartext
            } else {
                corrupt("file is shorter than its header")
            });
        }
        read_exact_at(&file, &mut region, 0)?;
        if region.starts_with(REDB_MAGIC) {
            return Err(EncryptedDbError::Cleartext);
        }
        let mac_key = key.derive(b"ergo-walletd wallet.redb header mac v1");
        let key_check = *key.derive(b"ergo-walletd wallet.redb key check v1");
        let mut best: Option<(Header, usize, [u8; 16])> = None;
        let mut wrong_key = false;
        for slot in 0..2 {
            match parse_slot(
                &region[slot * SLOT_BYTES..(slot + 1) * SLOT_BYTES],
                &mac_key,
                &key_check,
            ) {
                SlotRead::Valid(header, file_id) => {
                    if best.is_none_or(|(current, _, _)| header.sequence > current.sequence) {
                        best = Some((header, slot, file_id));
                    }
                }
                SlotRead::WrongKey => wrong_key = true,
                SlotRead::Invalid => {}
            }
        }
        let Some((header, slot, file_id)) = best else {
            return Err(if wrong_key {
                EncryptedDbError::WrongKey
            } else {
                corrupt("no valid header")
            });
        };
        let expected = HEADER_BYTES + sectors_for(header.logical_len) * PHYSICAL_SECTOR as u64;
        if length < expected {
            return Err(corrupt("file is shorter than its recorded length"));
        }
        if length > expected {
            // A shrink that crashed after publishing the new length leaves
            // sealed copies of the dropped sectors behind. Discard them now:
            // they still authenticate and must never come back.
            file.set_len(expected)?;
            file.sync_data()?;
        }
        Self::assemble(file, key, file_id, header, slot)
    }

    fn assemble(
        file: File,
        key: &DataKey,
        file_id: [u8; 16],
        header: Header,
        current_slot: usize,
    ) -> Result<Self, EncryptedDbError> {
        let sector_key = key.derive(b"ergo-walletd wallet.redb sectors v1");
        let cipher = {
            let key: &Key<Aes256Gcm> = (&*sector_key).into();
            Aes256Gcm::new(key)
        };
        let inner =
            FileBackend::new(file).map_err(|error| EncryptedDbError::Lock(error.to_string()))?;
        Ok(Self {
            inner,
            cipher,
            mac_key: key.derive(b"ergo-walletd wallet.redb header mac v1"),
            key_check: *key.derive(b"ergo-walletd wallet.redb key check v1"),
            file_id,
            state: RwLock::new(State {
                header,
                current_slot,
            }),
            copies: Mutex::new(Copies::default()),
        })
    }

    fn write_slot(&self, slot: usize, header: Header) -> io::Result<()> {
        let mut bytes = vec![0u8; SLOT_BYTES];
        let mut cursor = 0;
        let mut put = |field: &[u8]| {
            bytes[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        };
        put(MAGIC);
        put(&FORMAT_VERSION.to_be_bytes());
        put(&(SECTOR as u32).to_be_bytes());
        put(&self.file_id);
        put(&self.key_check);
        put(&header.sequence.to_be_bytes());
        put(&header.logical_len.to_be_bytes());
        let body_len = cursor;
        let mac = slot_mac(&self.mac_key, &bytes[..body_len]);
        bytes[body_len..body_len + 32].copy_from_slice(&mac);
        self.inner.write((slot * SLOT_BYTES) as u64, &bytes)
    }

    /// Persist a new logical length in the slot not written last.
    fn publish_len(&self, state: &mut State, logical_len: u64) -> io::Result<()> {
        let header = Header {
            sequence: state.header.sequence + 1,
            logical_len,
        };
        let slot = 1 - state.current_slot;
        self.write_slot(slot, header)?;
        state.header = header;
        state.current_slot = slot;
        Ok(())
    }

    fn sector_offset(index: u64) -> u64 {
        HEADER_BYTES + index * PHYSICAL_SECTOR as u64
    }

    fn copy_offset(index: u64, copy: usize) -> u64 {
        Self::sector_offset(index) + (copy * COPY) as u64
    }

    fn aad(&self, index: u64, sequence: u64) -> [u8; 32] {
        let mut aad = [0u8; 32];
        aad[..16].copy_from_slice(&self.file_id);
        aad[16..24].copy_from_slice(&index.to_be_bytes());
        aad[24..].copy_from_slice(&sequence.to_be_bytes());
        aad
    }

    /// Authenticate one sealed copy, returning its sequence and contents.
    fn unseal_copy(&self, index: u64, sealed: &[u8]) -> Option<(u64, Zeroizing<Vec<u8>>)> {
        let sequence = u64::from_be_bytes(sealed[..8].try_into().expect("8-byte sequence"));
        let nonce: [u8; NONCE] = sealed[8..8 + NONCE].try_into().expect("nonce length");
        self.cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &sealed[8 + NONCE..],
                    aad: &self.aad(index, sequence),
                },
            )
            .ok()
            .map(|plain| (sequence, Zeroizing::new(plain)))
    }

    /// Read both copies and return the newest that authenticates.
    fn load(&self, index: u64) -> io::Result<Option<(Current, Zeroizing<Vec<u8>>)>> {
        let mut sealed = vec![0u8; PHYSICAL_SECTOR];
        self.inner.read(Self::sector_offset(index), &mut sealed)?;
        let sequence = |copy: usize| {
            u64::from_be_bytes(sealed[copy * COPY..copy * COPY + 8].try_into().unwrap())
        };
        let order = if sequence(1) > sequence(0) {
            [1, 0]
        } else {
            [0, 1]
        };
        Ok(order.into_iter().find_map(|copy| {
            self.unseal_copy(index, &sealed[copy * COPY..(copy + 1) * COPY])
                .map(|(sequence, plain)| (Current { copy, sequence }, plain))
        }))
    }

    fn unreadable(index: u64) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("wallet database sector {index} failed authentication"),
        )
    }

    fn read_sector(&self, index: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        let known = self.copies.lock().current.get(&index).copied();
        if let Some(current) = known {
            let mut sealed = vec![0u8; COPY];
            self.inner
                .read(Self::copy_offset(index, current.copy), &mut sealed)?;
            return match self.unseal_copy(index, &sealed) {
                Some((sequence, plain)) if sequence == current.sequence => Ok(plain),
                _ => Err(Self::unreadable(index)),
            };
        }
        let (current, plain) = self.load(index)?.ok_or_else(|| Self::unreadable(index))?;
        self.copies.lock().current.entry(index).or_insert(current);
        Ok(plain)
    }

    /// Seal `plain` into one copy of sector `index`.
    fn store_copy(&self, index: u64, copy: usize, sequence: u64, plain: &[u8]) -> io::Result<()> {
        debug_assert_eq!(plain.len(), SECTOR);
        let mut nonce = [0u8; NONCE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let sealed = self
            .cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plain,
                    aad: &self.aad(index, sequence),
                },
            )
            .map_err(|_| io::Error::other("wallet database sector encryption failed"))?;
        let mut physical = Vec::with_capacity(COPY);
        physical.extend_from_slice(&sequence.to_be_bytes());
        physical.extend_from_slice(&nonce);
        physical.extend_from_slice(&sealed);
        self.inner.write(Self::copy_offset(index, copy), &physical)
    }

    /// Write a sector without touching its last durable copy.
    fn write_sector(&self, index: u64, plain: &[u8]) -> io::Result<()> {
        let mut copies = self.copies.lock();
        let current = match copies.current.get(&index) {
            Some(current) => Some(*current),
            None => self.load(index)?.map(|(current, _)| current),
        };
        let (copy, sequence) = match current {
            None => (0, 1),
            // Written since the last sync: the other copy is the durable one.
            Some(current) if copies.dirty.contains(&index) => (current.copy, current.sequence + 1),
            Some(current) => (1 - current.copy, current.sequence + 1),
        };
        self.store_copy(index, copy, sequence, plain)?;
        copies.current.insert(index, Current { copy, sequence });
        copies.dirty.insert(index);
        Ok(())
    }

    /// Flush to disk, then treat every sector written before the flush as
    /// durable.
    fn sync_inner(&self) -> io::Result<()> {
        let flushed = std::mem::take(&mut self.copies.lock().dirty);
        if let Err(error) = self.inner.sync_data() {
            self.copies.lock().dirty.extend(flushed);
            return Err(error);
        }
        Ok(())
    }

    /// Resize under the exclusive state lock.
    fn resize(&self, state: &mut State, len: u64) -> io::Result<()> {
        let old_len = state.header.logical_len;
        let old_sectors = sectors_for(old_len);
        let new_sectors = sectors_for(len);
        if len > old_len {
            // Zero the tail of a partial last sector, then seal new sectors
            // as zeros: grown space must read back as zero.
            if !old_len.is_multiple_of(SECTOR as u64) {
                let index = old_len / SECTOR as u64;
                let mut plain = self.read_sector(index)?;
                plain[(old_len % SECTOR as u64) as usize..].fill(0);
                self.write_sector(index, &plain)?;
            }
            // An interrupted shrink can leave sealed copies above the logical
            // length. Drop them before growing so a new sector never sits
            // beside an older copy with a higher sequence number.
            self.inner.set_len(Self::sector_offset(old_sectors))?;
            self.inner.set_len(Self::sector_offset(new_sectors))?;
            let zeros = vec![0u8; SECTOR];
            {
                let mut copies = self.copies.lock();
                for index in old_sectors..new_sectors {
                    // A new sector has no durable copy yet: seal copy 0.
                    self.store_copy(index, 0, 1, &zeros)?;
                    copies.current.insert(
                        index,
                        Current {
                            copy: 0,
                            sequence: 1,
                        },
                    );
                    copies.dirty.insert(index);
                }
            }
            self.sync_inner()?;
            self.publish_len(state, len)?;
        } else if len < old_len {
            self.publish_len(state, len)?;
            self.sync_inner()?;
            {
                let mut copies = self.copies.lock();
                copies.current.retain(|index, _| *index < new_sectors);
                copies.dirty.retain(|index| *index < new_sectors);
            }
            if !len.is_multiple_of(SECTOR as u64) {
                let index = len / SECTOR as u64;
                let mut plain = self.read_sector(index)?;
                plain[(len % SECTOR as u64) as usize..].fill(0);
                self.write_sector(index, &plain)?;
            }
            self.inner.set_len(Self::sector_offset(new_sectors))?;
        }
        Ok(())
    }
}

fn sectors_for(len: u64) -> u64 {
    len.div_ceil(SECTOR as u64)
}

/// Rename a fully written file into place without replacing anything, and
/// make the rename durable.
fn publish(pending: &Path, path: &Path) -> io::Result<()> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    std::fs::rename(pending, path)?;
    #[cfg(unix)]
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn slot_mac(mac_key: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(mac_key)
        .expect("HMAC accepts any key length");
    mac.update(b"ergo-walletd wallet.redb header slot\0");
    mac.update(body);
    mac.finalize().into_bytes().into()
}

enum SlotRead {
    Valid(Header, [u8; 16]),
    WrongKey,
    Invalid,
}

fn parse_slot(bytes: &[u8], mac_key: &[u8; 32], key_check: &[u8; 32]) -> SlotRead {
    const BODY: usize = 8 + 4 + 4 + 16 + 32 + 8 + 8;
    if &bytes[..8] != MAGIC
        || bytes[8..12] != FORMAT_VERSION.to_be_bytes()
        || bytes[12..16] != (SECTOR as u32).to_be_bytes()
    {
        return SlotRead::Invalid;
    }
    if !bool::from(bytes[32..64].ct_eq(key_check)) {
        return SlotRead::WrongKey;
    }
    if !bool::from(slot_mac(mac_key, &bytes[..BODY]).ct_eq(&bytes[BODY..BODY + 32])) {
        return SlotRead::Invalid;
    }
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&bytes[16..32]);
    let number =
        |range: std::ops::Range<usize>| u64::from_be_bytes(bytes[range].try_into().unwrap());
    SlotRead::Valid(
        Header {
            sequence: number(64..72),
            logical_len: number(72..80),
        },
        file_id,
    )
}

#[cfg(unix)]
fn read_exact_at(file: &File, out: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(out, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut out: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !out.is_empty() {
        match file.seek_read(out, offset)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            read => {
                out = &mut out[read..];
                offset += read as u64;
            }
        }
    }
    Ok(())
}

impl StorageBackend for EncryptedBackend {
    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.state.read().header.logical_len)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        let state = self.state.read();
        let end = offset
            .checked_add(out.len() as u64)
            .filter(|end| *end <= state.header.logical_len)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let mut position = offset;
        while position < end {
            let index = position / SECTOR as u64;
            let within = (position % SECTOR as u64) as usize;
            let take = (SECTOR - within).min((end - position) as usize);
            let plain = self.read_sector(index)?;
            let at = (position - offset) as usize;
            out[at..at + take].copy_from_slice(&plain[within..within + take]);
            position += take as u64;
        }
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        let mut state = self.state.write();
        self.resize(&mut state, len)
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        self.sync_inner()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let mut state = self.state.write();
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        if end > state.header.logical_len {
            self.resize(&mut state, end)?;
        }
        let mut position = offset;
        while position < end {
            let index = position / SECTOR as u64;
            let within = (position % SECTOR as u64) as usize;
            let take = (SECTOR - within).min((end - position) as usize);
            let at = (position - offset) as usize;
            if take == SECTOR {
                self.write_sector(index, &data[at..at + SECTOR])?;
            } else {
                let mut plain = self.read_sector(index)?;
                plain[within..within + take].copy_from_slice(&data[at..at + take]);
                self.write_sector(index, &plain)?;
            }
            position += take as u64;
        }
        Ok(())
    }

    fn close(&self) -> Result<(), io::Error> {
        self.inner.close()
    }

    fn try_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> {
        self.inner.try_lock_range(start, end)
    }

    fn try_lock_shared_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> Result<bool, BackendError> {
        self.inner.try_lock_shared_range(start, end)
    }

    fn lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        self.inner.lock_range(start, end)
    }

    fn lock_shared_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        self.inner.lock_shared_range(start, end)
    }

    fn unlock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        self.inner.unlock_range(start, end)
    }

    fn query_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> {
        self.inner.query_lock_range(start, end)
    }
}

/// Open or create the encrypted database at `path` as a redb [`redb::Database`].
pub fn open_database(path: &Path, key: &DataKey) -> Result<redb::Database, EncryptedDbError> {
    let backend = if path.exists() {
        EncryptedBackend::open(path, key)?
    } else {
        EncryptedBackend::create(path, key)?
    };
    redb::Builder::new()
        .create_with_backend(backend)
        .map_err(|error| corrupt(error.to_string()))
}

/// Encrypt the cleartext redb file at `source` into a new encrypted file at
/// `destination` (which must not exist), verifying the copy byte for byte.
/// The source is not modified.
pub fn encrypt_file(
    source: &Path,
    destination: &Path,
    key: &DataKey,
) -> Result<(), EncryptedDbError> {
    use sha2::Digest;
    let source_file = File::open(source)?;
    let length = source_file.metadata()?.len();
    let backend = EncryptedBackend::create(destination, key)?;
    let result = (|| {
        backend.set_len(length)?;
        let mut buffer = Zeroizing::new(vec![0u8; 1024 * 1024]);
        let mut source_hash = Sha256::new();
        let mut offset = 0;
        while offset < length {
            let count = (length - offset).min(buffer.len() as u64) as usize;
            read_exact_at(&source_file, &mut buffer[..count], offset)?;
            source_hash.update(&buffer[..count]);
            backend.write(offset, &buffer[..count])?;
            offset += count as u64;
        }
        backend.sync_data()?;
        let mut copy_hash = Sha256::new();
        offset = 0;
        while offset < length {
            let count = (length - offset).min(buffer.len() as u64) as usize;
            backend.read(offset, &mut buffer[..count])?;
            copy_hash.update(&buffer[..count]);
            offset += count as u64;
        }
        if source_hash.finalize() != copy_hash.finalize() {
            return Err(corrupt("encrypted copy does not match its source"));
        }
        Ok(())
    })();
    let _ = backend.close();
    drop(backend);
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::{ReadableDatabase, ReadableTableMetadata, TableDefinition};

    const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("t");

    /// The copy of sector `index` with the higher sequence number on disk.
    fn newest_copy(raw: &[u8], index: u64) -> usize {
        let at = EncryptedBackend::sector_offset(index) as usize;
        let sequence =
            |copy: usize| u64::from_be_bytes(raw[at + copy * COPY..][..8].try_into().unwrap());
        usize::from(sequence(1) > sequence(0))
    }

    /// Garble the middle of one copy, as a write interrupted after its
    /// sequence number landed would.
    fn tear(path: &Path, index: u64, copy: usize) {
        let mut raw = std::fs::read(path).unwrap();
        let at = EncryptedBackend::copy_offset(index, copy) as usize;
        for byte in &mut raw[at + 2048..at + 2100] {
            *byte ^= 0x5a;
        }
        std::fs::write(path, &raw).unwrap();
    }

    fn model_check(backend: &EncryptedBackend, model: &[u8]) {
        assert_eq!(backend.len().unwrap(), model.len() as u64);
        let mut out = vec![0u8; model.len()];
        backend.read(0, &mut out).unwrap();
        assert_eq!(out, model);
    }

    #[test]
    fn random_reads_writes_and_resizes_match_a_plain_model() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let key = DataKey::generate();
        let backend = EncryptedBackend::create(&path, &key).unwrap();
        let mut model = Vec::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for _ in 0..400 {
            match next(4) {
                0 => {
                    let len = next(40_000);
                    backend.set_len(len).unwrap();
                    model.resize(len as usize, 0);
                }
                _ if model.is_empty() => {}
                _ => {
                    let offset = next(model.len() as u64) as usize;
                    let len = next((model.len() - offset) as u64 + 1) as usize;
                    let data: Vec<u8> = (0..len).map(|_| next(256) as u8).collect();
                    backend.write(offset as u64, &data).unwrap();
                    model[offset..offset + len].copy_from_slice(&data);
                }
            }
            model_check(&backend, &model);
        }
        // Writing past the end grows with zeros.
        let end = model.len() as u64 + 5000;
        backend.write(end, b"tail").unwrap();
        model.resize(end as usize, 0);
        model.extend_from_slice(b"tail");
        model_check(&backend, &model);
        backend.sync_data().unwrap();
        drop(backend);
        let reopened = EncryptedBackend::open(&path, &key).unwrap();
        model_check(&reopened, &model);
    }

    #[test]
    fn redb_round_trips_and_no_plaintext_reaches_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let key = DataKey::generate();
        let marker = b"9hQTG5EspKUxjhmnFRdzhethHaFmnW4PvjobckSrTSNRYhQLhCZ-marker";
        {
            let db = open_database(&path, &key).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(TABLE).unwrap();
                for index in 0..2000u64 {
                    table.insert(index, marker.as_slice()).unwrap();
                }
            }
            txn.commit().unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.windows(marker.len()).all(|window| window != marker));
        assert!(raw.windows(4).all(|window| window != b"redb"));
        let db = open_database(&path, &key).unwrap();
        let read = db.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        assert_eq!(table.len().unwrap(), 2000);
        assert_eq!(table.get(1999).unwrap().unwrap().value(), marker);
    }

    #[test]
    fn wrong_key_cleartext_and_tampering_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let key = DataKey::generate();
        {
            let db = open_database(&path, &key).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(TABLE)
                .unwrap()
                .insert(1, b"x".as_slice())
                .unwrap();
            txn.commit().unwrap();
        }
        assert!(matches!(
            EncryptedBackend::open(&path, &DataKey::generate()),
            Err(EncryptedDbError::WrongKey)
        ));
        // Flip one byte inside both copies of a sealed sector.
        let mut raw = std::fs::read(&path).unwrap();
        raw[HEADER_BYTES as usize + 100] ^= 1;
        raw[HEADER_BYTES as usize + COPY + 100] ^= 1;
        let tampered = dir.path().join("tampered.redb");
        std::fs::write(&tampered, &raw).unwrap();
        let backend = EncryptedBackend::open(&tampered, &key).unwrap();
        let mut out = vec![0u8; 16];
        assert!(backend.read(0, &mut out).is_err());
        // Swapping two sectors is detected by the index in the AAD.
        let mut raw = std::fs::read(&path).unwrap();
        let (a, b) = (
            HEADER_BYTES as usize,
            HEADER_BYTES as usize + PHYSICAL_SECTOR,
        );
        let first = raw[a..a + PHYSICAL_SECTOR].to_vec();
        raw.copy_within(b..b + PHYSICAL_SECTOR, a);
        raw[b..b + PHYSICAL_SECTOR].copy_from_slice(&first);
        std::fs::write(&tampered, &raw).unwrap();
        let backend = EncryptedBackend::open(&tampered, &key).unwrap();
        assert!(backend.read(0, &mut out).is_err());
        // A cleartext redb file is recognised, not misread.
        let clear = dir.path().join("clear.redb");
        drop(redb::Database::create(&clear).unwrap());
        assert!(matches!(
            EncryptedBackend::open(&clear, &key),
            Err(EncryptedDbError::Cleartext)
        ));
    }

    #[test]
    fn a_torn_header_slot_falls_back_to_the_other() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let key = DataKey::generate();
        let backend = EncryptedBackend::create(&path, &key).unwrap();
        backend.set_len(10_000).unwrap();
        backend.write(0, b"hello").unwrap();
        backend.sync_data().unwrap();
        let slot = backend.state.read().current_slot;
        drop(backend);
        let mut raw = std::fs::read(&path).unwrap();
        raw[slot * SLOT_BYTES + 70] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        // The older slot is valid but records the previous length.
        let reopened = EncryptedBackend::open(&path, &key).unwrap();
        assert!(reopened.len().unwrap() <= 10_000);
    }

    #[test]
    fn cleartext_database_encrypts_to_an_identical_redb() {
        let dir = tempfile::tempdir().unwrap();
        let clear = dir.path().join("clear.redb");
        {
            let db = redb::Database::create(&clear).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(TABLE).unwrap();
                for index in 0..500u64 {
                    table.insert(index, index.to_be_bytes().as_slice()).unwrap();
                }
            }
            txn.commit().unwrap();
        }
        let before = std::fs::read(&clear).unwrap();
        let encrypted = dir.path().join("wallet.redb");
        let key = DataKey::generate();
        encrypt_file(&clear, &encrypted, &key).unwrap();
        assert_eq!(
            std::fs::read(&clear).unwrap(),
            before,
            "the source is untouched"
        );
        let db = open_database(&encrypted, &key).unwrap();
        let read = db.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        assert_eq!(table.len().unwrap(), 500);
        assert_eq!(
            table.get(499).unwrap().unwrap().value(),
            499u64.to_be_bytes()
        );
        assert!(
            encrypt_file(&clear, &encrypted, &key).is_err(),
            "never overwrites"
        );
    }

    #[test]
    fn a_torn_write_leaves_the_last_durable_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let key = DataKey::generate();
        let backend = EncryptedBackend::create(&path, &key).unwrap();
        backend.set_len(SECTOR as u64).unwrap();
        backend.write(0, b"durable").unwrap();
        backend.sync_data().unwrap();
        backend.write(0, b"pending").unwrap();
        backend.sync_data().unwrap();
        drop(backend);
        let pending = newest_copy(&std::fs::read(&path).unwrap(), 0);
        tear(&path, 0, pending);
        let reopened = EncryptedBackend::open(&path, &key).unwrap();
        let mut out = [0u8; 7];
        reopened.read(0, &mut out).unwrap();
        assert_eq!(&out, b"durable");
    }

    #[test]
    fn writes_since_the_last_sync_never_touch_the_durable_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let key = DataKey::generate();
        let backend = EncryptedBackend::create(&path, &key).unwrap();
        backend.set_len(SECTOR as u64).unwrap();
        backend.write(0, b"durable").unwrap();
        backend.sync_data().unwrap();
        let durable = newest_copy(&std::fs::read(&path).unwrap(), 0);
        let at = EncryptedBackend::copy_offset(0, durable) as usize;
        let before = std::fs::read(&path).unwrap()[at..at + COPY].to_vec();
        for value in [b"second!", b"third!!", b"fourth!"] {
            backend.write(0, value).unwrap();
            assert_eq!(
                std::fs::read(&path).unwrap()[at..at + COPY],
                before[..],
                "an unsynced rewrite must not overwrite the durable copy"
            );
        }
        // Lose everything written since the sync: the durable copy remains.
        drop(backend);
        tear(&path, 0, 1 - durable);
        let reopened = EncryptedBackend::open(&path, &key).unwrap();
        let mut out = [0u8; 7];
        reopened.read(0, &mut out).unwrap();
        assert_eq!(&out, b"durable");
    }

    #[test]
    fn a_torn_redb_header_write_reopens_at_the_previous_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let key = DataKey::generate();
        let commit = |value: &[u8]| {
            let db = open_database(&path, &key).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(TABLE).unwrap().insert(1, value).unwrap();
            txn.commit().unwrap();
        };
        commit(b"first");
        commit(b"second");
        // The commit that wrote "second" last rewrote redb's header in sector
        // 0; tear that write.
        let newest = newest_copy(&std::fs::read(&path).unwrap(), 0);
        tear(&path, 0, newest);
        let db = open_database(&path, &key).unwrap();
        let read = db.begin_read().unwrap();
        let value = read.open_table(TABLE).unwrap().get(1).unwrap().unwrap();
        assert!(
            [b"first".as_slice(), b"second".as_slice()].contains(&value.value()),
            "the database opens at a committed state"
        );
    }

    #[test]
    fn create_publishes_only_a_complete_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let pending = dir.path().join("wallet.redb.creating");
        // An interrupted earlier create left a partial file behind.
        std::fs::write(&pending, b"partial").unwrap();
        let key = DataKey::generate();
        drop(EncryptedBackend::create(&path, &key).unwrap());
        assert!(!pending.exists());
        EncryptedBackend::open(&path, &key).unwrap();
        assert!(matches!(
            EncryptedBackend::create(&path, &key),
            Err(EncryptedDbError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
        ));
    }
}
