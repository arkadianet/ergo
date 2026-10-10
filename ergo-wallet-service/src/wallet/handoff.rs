//! Publication of a standalone seed-wallet directory from an embedded wallet.
//!
//! Shared by the daemon's offline `ergo-walletd migrate` (from a private copy
//! of a stopped node's database) and the node's own handoff export (from a
//! read transaction on its open database). The published directory is what
//! `ergo-walletd adopt` and a seed-mode daemon accept:
//!
//! ```text
//! wallet.redb        supported wallet tables, cleartext until the first unseal
//! wallet/<file>      the encrypted secret, byte for byte; never decrypted here
//! migration.json     content hashes and row counts
//! wallet-network     the network the wallet belongs to
//! wallet-mode        `seed`, written last: an interrupted publication fails closed
//! ```
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use ergo_wallet::storage::SecretStorage;
use redb::Database;
use sha2::{Digest, Sha256};

use super::migration::{export_embedded_wallet_with, source_network, MigrationReport};
use super::WalletStoreError;

/// Largest encrypted secret file accepted.
const MAX_SECRET_BYTES: u64 = 4 * 1024 * 1024;

/// The `migration.json` record of a published seed directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CutoverReport {
    pub version: u32,
    pub network: String,
    /// SHA-256 of the whole source database, when it was read from a stopped
    /// copy; absent for a handoff from a live database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_database_sha256: Option<String>,
    pub encrypted_secret_sha256: String,
    pub wallet_jobs_quarantined: u64,
    pub wallet: MigrationReport,
}

/// How the export treats the source.
pub struct PublishOptions {
    pub network: ergo_chain_spec::Network,
    pub source_database_sha256: Option<String>,
    pub wallet_jobs_quarantined: u64,
    /// Carry job records the embedded scheduler still owns. Only correct when
    /// that scheduler no longer runs (a node that has stopped hosting the
    /// wallet); otherwise two owners would follow the same transactions.
    pub carry_scheduler_jobs: bool,
}

fn fail(message: impl Into<String>) -> WalletStoreError {
    WalletStoreError::decode(message.into())
}

fn io(error: std::io::Error) -> WalletStoreError {
    fail(error.to_string())
}

/// Read the one unambiguous encrypted secret file of `secret_dir`.
pub fn read_single_secret(secret_dir: &Path) -> Result<(OsString, Vec<u8>), WalletStoreError> {
    if fs::symlink_metadata(secret_dir)
        .map_err(io)?
        .file_type()
        .is_symlink()
    {
        return Err(fail("the secret directory must not be a symlink"));
    }
    let path =
        SecretStorage::find_secret_file(secret_dir).map_err(|error| fail(error.to_string()))?;
    let eligible = fs::read_dir(secret_dir)
        .map_err(io)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file()
                && !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ergo-wallet-pending-")
        })
        .count();
    if eligible != 1 {
        return Err(fail(
            "the wallet needs one unambiguous encrypted secret file",
        ));
    }
    if !fs::symlink_metadata(&path).map_err(io)?.is_file() {
        return Err(fail("the encrypted secret is not a regular file"));
    }
    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(io)?
        .take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        return Err(fail("the encrypted secret exceeds the size limit"));
    }
    let name = path
        .file_name()
        .ok_or_else(|| fail("the encrypted secret has no file name"))?
        .to_os_string();
    Ok((name, bytes))
}

pub fn sync_directory(path: &Path) -> Result<(), WalletStoreError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn create_private_directory(path: &Path) -> Result<(), WalletStoreError> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(io)
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), WalletStoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)
}

/// Export `source`'s wallet into a new seed directory at `destination`.
///
/// Everything is assembled in a private temporary directory beside
/// `destination`; `before_publish` runs after the export and before anything
/// appears at `destination`, so a caller can verify its source did not
/// change. Publication hard-links the files in and writes `wallet-mode` last.
pub fn publish_seed_directory(
    source: &Database,
    secret: (&OsStr, &[u8]),
    destination: &Path,
    options: PublishOptions,
    before_publish: impl FnOnce() -> Result<(), WalletStoreError>,
) -> Result<CutoverReport, WalletStoreError> {
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(fail("the destination already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io(error)),
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let network = match options.network {
        ergo_chain_spec::Network::Mainnet => "mainnet",
        ergo_chain_spec::Network::Testnet => "testnet",
        other => return Err(fail(format!("the daemon does not host {other:?} wallets"))),
    };
    let read = redb::ReadableDatabase::begin_read(source)?;
    if source_network(&read)? != options.network {
        return Err(fail(
            "the wallet's network differs from the committed chain",
        ));
    }
    drop(read);
    let temporary = tempfile::Builder::new()
        .prefix(".ergo-wallet-cutover-")
        .tempdir_in(parent)
        .map_err(io)?;
    let candidate = temporary.path().join("candidate");
    create_private_directory(&candidate)?;
    create_private_directory(&candidate.join("wallet"))?;
    let (secret_name, encrypted) = secret;
    write_private(&candidate.join("wallet").join(secret_name), encrypted)?;
    // Parse only public metadata. A seed is never requested or decrypted.
    SecretStorage::open(candidate.join("wallet"))
        .load_metadata()
        .map_err(|error| fail(error.to_string()))?;
    let wallet = export_embedded_wallet_with(
        source,
        &candidate.join("wallet.redb"),
        options.carry_scheduler_jobs,
    )?;
    before_publish()?;
    let report = CutoverReport {
        version: 1,
        network: network.into(),
        source_database_sha256: options.source_database_sha256,
        encrypted_secret_sha256: hex::encode(Sha256::digest(encrypted)),
        wallet_jobs_quarantined: options.wallet_jobs_quarantined,
        wallet,
    };
    write_private(
        &candidate.join("migration.json"),
        &serde_json::to_vec_pretty(&report).map_err(|error| fail(error.to_string()))?,
    )?;
    write_private(
        &candidate.join("wallet-network"),
        format!("{network}\n").as_bytes(),
    )?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(candidate.join("wallet.redb"))
        .and_then(|file| file.sync_all())
        .map_err(io)?;
    // Reserve the destination without replacing anything, then publish the
    // ownership marker last so an interruption leaves an unadoptable copy.
    create_private_directory(destination)?;
    sync_directory(parent)?;
    create_private_directory(&destination.join("wallet"))?;
    for name in ["wallet.redb", "migration.json", "wallet-network"] {
        fs::hard_link(candidate.join(name), destination.join(name)).map_err(io)?;
    }
    fs::hard_link(
        candidate.join("wallet").join(secret_name),
        destination.join("wallet").join(secret_name),
    )
    .map_err(io)?;
    sync_directory(&destination.join("wallet"))?;
    sync_directory(destination)?;
    write_private(&destination.join("wallet-mode"), b"seed\n")?;
    sync_directory(destination)?;
    sync_directory(parent)?;
    Ok(report)
}
