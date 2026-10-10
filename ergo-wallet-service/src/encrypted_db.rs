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
//! `HEADER_BYTES + i * PHYSICAL_SECTOR`, each `nonce ‖ ciphertext ‖ tag`. The
//! header holds two slots written alternately with a sequence number and an
//! HMAC, so a torn header write leaves the other slot valid. Space added by
//! growth is written as sealed zeros, so an all-zero sector on disk is
//! corruption, never an implicit hole.
//!
//! Residual exposure: the file length reveals the database size, sectors
//! rewritten with identical contents are not linkable (fresh nonces) but write
//! timing is observable, and an attacker who can replace the file can roll a
//! sector back to an older sealed version of itself.
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Bound;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use redb::backends::FileBackend;
use redb::{BackendError, StorageBackend};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Logical bytes per sector.
pub const SECTOR: usize = 4096;
const NONCE: usize = 12;
const TAG: usize = 16;
/// On-disk bytes per sector.
pub const PHYSICAL_SECTOR: usize = NONCE + SECTOR + TAG;
/// Plaintext header region at the start of the file.
pub const HEADER_BYTES: u64 = 4096;
const SLOT_BYTES: usize = 2048;
const MAGIC: &[u8; 8] = b"ERGWDBE\x01";
const FORMAT_VERSION: u32 = 1;
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
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_slice())
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

/// redb [`StorageBackend`] that seals every sector with AES-256-GCM.
pub struct EncryptedBackend {
    inner: FileBackend,
    cipher: Aes256Gcm,
    mac_key: Zeroizing<[u8; 32]>,
    key_check: [u8; 32],
    file_id: [u8; 16],
    state: RwLock<State>,
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
    pub fn create(path: &Path, key: &DataKey) -> Result<Self, EncryptedDbError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
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
        let backend = Self::assemble(file, key, file_id, header, slot)?;
        let expected = HEADER_BYTES + sectors_for(header.logical_len) * PHYSICAL_SECTOR as u64;
        if length < expected {
            return Err(corrupt("file is shorter than its recorded length"));
        }
        Ok(backend)
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

    fn aad(&self, index: u64) -> [u8; 24] {
        let mut aad = [0u8; 24];
        aad[..16].copy_from_slice(&self.file_id);
        aad[16..].copy_from_slice(&index.to_be_bytes());
        aad
    }

    fn read_sector(&self, index: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut sealed = vec![0u8; PHYSICAL_SECTOR];
        self.inner.read(Self::sector_offset(index), &mut sealed)?;
        let (nonce, body) = sealed.split_at(NONCE);
        let nonce: [u8; NONCE] = nonce.try_into().expect("split at the nonce length");
        self.cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: body,
                    aad: &self.aad(index),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("wallet database sector {index} failed authentication"),
                )
            })
    }

    fn write_sector(&self, index: u64, plain: &[u8]) -> io::Result<()> {
        debug_assert_eq!(plain.len(), SECTOR);
        let mut nonce = [0u8; NONCE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let sealed = self
            .cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plain,
                    aad: &self.aad(index),
                },
            )
            .map_err(|_| io::Error::other("wallet database sector encryption failed"))?;
        let mut physical = Vec::with_capacity(PHYSICAL_SECTOR);
        physical.extend_from_slice(&nonce);
        physical.extend_from_slice(&sealed);
        self.inner.write(Self::sector_offset(index), &physical)
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
            self.inner.set_len(Self::sector_offset(new_sectors))?;
            let zeros = vec![0u8; SECTOR];
            for index in old_sectors..new_sectors {
                self.write_sector(index, &zeros)?;
            }
            self.inner.sync_data()?;
            self.publish_len(state, len)?;
        } else if len < old_len {
            self.publish_len(state, len)?;
            self.inner.sync_data()?;
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

fn slot_mac(mac_key: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
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
        self.inner.sync_data()
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
        // Flip one byte inside a sealed sector.
        let mut raw = std::fs::read(&path).unwrap();
        raw[HEADER_BYTES as usize + NONCE + 100] ^= 1;
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
}
