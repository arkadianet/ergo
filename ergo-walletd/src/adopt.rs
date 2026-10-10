//! `ergo-walletd adopt`: take ownership of a node's wallet handoff.
//!
//! A node that no longer hosts its embedded wallet publishes a verified copy
//! at `<node data_dir>/wallet-handoff/`. Adoption checks that copy, moves it to
//! the daemon's new data directory (a rename on one file system, a verified
//! copy otherwise) and records `wallet-handoff.adopted` beside it, after which
//! the node may purge its legacy wallet rows. The daemon's first unseal
//! upgrades the keystore and encrypts the database.
use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;
use ergo_wallet::storage::SecretStorage;
use ergo_wallet_service::wallet::handoff::{
    create_private_directory, read_single_secret, sync_directory, write_private, CutoverReport,
};
use sha2::{Digest, Sha256};

use crate::config::ConfigError;

/// Marker the node reads before purging its legacy wallet rows.
pub const ADOPTED_MARKER: &str = "wallet-handoff.adopted";

#[derive(Debug, Clone, Args)]
pub struct AdoptArgs {
    /// The node's handoff directory, `<node data_dir>/wallet-handoff`.
    #[arg(long)]
    pub handoff: PathBuf,
    /// New daemon data directory; it must not exist.
    #[arg(long)]
    pub data_dir: PathBuf,
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// Check a handoff directory and return its report.
fn verify(handoff: &Path) -> Result<CutoverReport, ConfigError> {
    let read = |name: &str| {
        fs::read(handoff.join(name)).map_err(|error| invalid(format!("handoff {name}: {error}")))
    };
    if read("wallet-mode")? != b"seed\n" {
        return Err(invalid("the handoff is incomplete or not a seed wallet"));
    }
    let report: CutoverReport = serde_json::from_slice(&read("migration.json")?)
        .map_err(|error| invalid(format!("handoff migration.json: {error}")))?;
    if read("wallet-network")? != format!("{}\n", report.network).as_bytes() {
        return Err(invalid(
            "the handoff network marker differs from its report",
        ));
    }
    if !handoff.join("wallet.redb").is_file() {
        return Err(invalid("the handoff has no wallet.redb"));
    }
    let (_, secret) =
        read_single_secret(&handoff.join("wallet")).map_err(|error| invalid(error.to_string()))?;
    if hex::encode(Sha256::digest(&secret)) != report.encrypted_secret_sha256 {
        return Err(invalid("the handoff secret differs from its report"));
    }
    SecretStorage::open(handoff.join("wallet"))
        .load_metadata()
        .map_err(|error| invalid(error.to_string()))?;
    Ok(report)
}

fn copy_verified(from: &Path, to: &Path) -> Result<(), ConfigError> {
    let bytes = fs::read(from)?;
    write_private(to, &bytes).map_err(|error| invalid(error.to_string()))?;
    if fs::read(to)? != bytes {
        return Err(invalid(format!("copy of {} differs", from.display())));
    }
    Ok(())
}

/// Copy a handoff to `destination` when a rename cannot cross file systems.
fn copy_handoff(handoff: &Path, destination: &Path) -> Result<(), ConfigError> {
    let fail = |error: ergo_wallet_service::WalletStoreError| invalid(error.to_string());
    create_private_directory(destination).map_err(fail)?;
    create_private_directory(&destination.join("wallet")).map_err(fail)?;
    for name in ["wallet.redb", "migration.json", "wallet-network"] {
        copy_verified(&handoff.join(name), &destination.join(name))?;
    }
    let (secret_name, _) =
        read_single_secret(&handoff.join("wallet")).map_err(|error| invalid(error.to_string()))?;
    copy_verified(
        &handoff.join("wallet").join(&secret_name),
        &destination.join("wallet").join(&secret_name),
    )?;
    sync_directory(&destination.join("wallet")).map_err(fail)?;
    // The ownership marker last, as at publication.
    write_private(&destination.join("wallet-mode"), b"seed\n").map_err(fail)?;
    sync_directory(destination).map_err(fail)?;
    fs::remove_dir_all(handoff)?;
    Ok(())
}

/// Move a verified handoff into a new daemon data directory.
pub fn adopt(args: &AdoptArgs) -> Result<CutoverReport, ConfigError> {
    let report = verify(&args.handoff)?;
    match fs::symlink_metadata(&args.data_dir) {
        Ok(_) => return Err(invalid("the daemon data directory already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = args
        .data_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if fs::rename(&args.handoff, &args.data_dir).is_err() {
        copy_handoff(&args.handoff, &args.data_dir)?;
    }
    sync_directory(parent).map_err(|error| invalid(error.to_string()))?;
    verify(&args.data_dir)?;
    let node_dir = args
        .handoff
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let report_hash = hex::encode(Sha256::digest(fs::read(
        args.data_dir.join("migration.json"),
    )?));
    if let Err(error) = write_private(
        &node_dir.join(ADOPTED_MARKER),
        format!("{report_hash}\n").as_bytes(),
    ) {
        eprintln!(
            "ergo-walletd: adopted, but could not record {} in {}: {error}; create it there before purging the node's legacy wallet",
            ADOPTED_MARKER,
            node_dir.display()
        );
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// A minimal published handoff, laid out as the node writes it.
    fn handoff(node_dir: &Path) -> PathBuf {
        ergo_wallet::storage::use_fast_keystore_kdf_for_tests();
        let handoff = node_dir.join("wallet-handoff");
        create_private_directory(&handoff).unwrap();
        let mut secrets = SecretStorage::open(handoff.join("wallet"));
        secrets.restore(PHRASE, "", "pw", false).unwrap();
        let (_, secret) = read_single_secret(&handoff.join("wallet")).unwrap();
        drop(redb::Database::create(handoff.join("wallet.redb")).unwrap());
        let report = serde_json::json!({
            "version": 1,
            "network": "testnet",
            "encrypted_secret_sha256": hex::encode(Sha256::digest(&secret)),
            "wallet_jobs_quarantined": 0,
            "wallet": {"tables": {}, "applied_headers": 0, "wallet_height": 0, "history_complete": true}
        });
        write_private(
            &handoff.join("migration.json"),
            report.to_string().as_bytes(),
        )
        .unwrap();
        write_private(&handoff.join("wallet-network"), b"testnet\n").unwrap();
        write_private(&handoff.join("wallet-mode"), b"seed\n").unwrap();
        handoff
    }

    #[test]
    fn adopt_moves_a_verified_handoff_and_marks_the_node() {
        let node = tempfile::tempdir().unwrap();
        let source = handoff(node.path());
        let daemon = tempfile::tempdir().unwrap();
        let data_dir = daemon.path().join("wallet-data");
        adopt(&AdoptArgs {
            handoff: source.clone(),
            data_dir: data_dir.clone(),
        })
        .unwrap();
        assert!(!source.exists());
        assert!(data_dir.join("wallet-mode").is_file());
        assert!(node.path().join(ADOPTED_MARKER).is_file());
        // A second adoption has nothing to take.
        assert!(adopt(&AdoptArgs {
            handoff: source,
            data_dir: daemon.path().join("again"),
        })
        .is_err());
    }

    #[test]
    fn adopt_refuses_incomplete_or_altered_handoffs() {
        let node = tempfile::tempdir().unwrap();
        let source = handoff(node.path());
        let target = |name: &str| node.path().join(name);
        fs::remove_file(source.join("wallet-mode")).unwrap();
        assert!(adopt(&AdoptArgs {
            handoff: source.clone(),
            data_dir: target("a"),
        })
        .is_err());
        write_private(&source.join("wallet-mode"), b"seed\n").unwrap();
        let secret = SecretStorage::find_secret_file(&source.join("wallet")).unwrap();
        let mut bytes = fs::read(&secret).unwrap();
        bytes.push(b' ');
        fs::write(&secret, bytes).unwrap();
        assert!(adopt(&AdoptArgs {
            handoff: source.clone(),
            data_dir: target("b"),
        })
        .is_err());
        assert!(source.exists(), "a refused adoption leaves the handoff");
        assert!(!target("b").exists());
    }

    /// Node handoff → adopt → sealed daemon → first unseal: the wallet's
    /// rows arrive intact, the database is encrypted and the keystore is
    /// version 2 with its database key.
    #[test]
    fn a_published_handoff_is_adopted_and_encrypted_by_the_first_unseal() {
        use ergo_wallet_service::wallet::handoff::{publish_seed_directory, PublishOptions};
        use ergo_wallet_service::WalletStore;
        ergo_wallet::storage::use_fast_keystore_kdf_for_tests();
        let node = tempfile::tempdir().unwrap();
        let db = crate::migration::tests::embedded_source(node.path());
        let (name, secret) = read_single_secret(&node.path().join("wallet")).unwrap();
        let handoff = node.path().join("wallet-handoff");
        publish_seed_directory(
            &db,
            (&name, &secret),
            &handoff,
            PublishOptions {
                network: ergo_chain_spec::Network::Testnet,
                source_database_sha256: None,
                wallet_jobs_quarantined: 0,
                carry_scheduler_jobs: true,
            },
            || Ok(()),
        )
        .unwrap();
        let daemon_root = tempfile::tempdir().unwrap();
        let data_dir = daemon_root.path().join("wallet-data");
        adopt(&AdoptArgs {
            handoff,
            data_dir: data_dir.clone(),
        })
        .unwrap();
        let config = crate::config::Config {
            mode: crate::config::WalletMode::Seed,
            network: crate::config::Network::Testnet,
            data_dir: data_dir.clone(),
            node_url: "http://127.0.0.1:9/".parse().unwrap(),
            api_key_file: daemon_root.path().join("node-key"),
            descriptor_file: None,
            local_api_key_file: daemon_root.path().join("local-key"),
            node_ca_file: None,
            sync_interval: std::time::Duration::from_secs(60),
            shutdown_timeout: std::time::Duration::from_secs(1),
            sync_batch: 1,
            blocks_page: 1,
            unix_socket: None,
            tcp_fallback: Some("127.0.0.1:0".parse().unwrap()),
            allowed_hosts: Vec::new(),
            lock_policy: crate::config::LockPolicy::default(),
            lock_memory: false,
            unseal_key_file: None,
            multisig_nonces: crate::config::NonceHolder::Daemon,
        };
        let daemon = crate::prepare(crate::config::LoadedConfig {
            config,
            api_key: crate::config::ApiKey::from_test(b"node".to_vec()),
            local_api_key: crate::config::ApiKey::from_test(b"local".to_vec()),
        })
        .unwrap();
        assert!(daemon.is_sealed(), "an adopted wallet starts sealed");
        let raw = fs::read(data_dir.join("wallet.redb")).unwrap();
        assert!(raw.starts_with(b"redb"), "cleartext until the first unseal");
        let (unsealed_tx, _unsealed_rx) = tokio::sync::mpsc::unbounded_channel();
        let (seal_tx, _seal_rx) = tokio::sync::watch::channel(false);
        let gate = crate::seal::Gate::new(daemon.context, None, unsealed_tx, seal_tx);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let opened = runtime
            .block_on(gate.unseal(zeroize::Zeroizing::new(
                "migration-test-password".to_string(),
            )))
            .unwrap();
        let raw = fs::read(data_dir.join("wallet.redb")).unwrap();
        assert!(
            !raw.starts_with(b"redb"),
            "the first unseal encrypts the database"
        );
        let read = opened.service.store().read().unwrap();
        assert_eq!(read.tracked_pubkeys_with_paths().unwrap().len(), 1);
        drop(read);
        let keystore = ergo_wallet::storage::KeystoreFile::parse(
            &fs::read(SecretStorage::find_secret_file(&data_dir.join("wallet")).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(keystore.version(), 2);
        assert!(keystore.has_data_key());
        drop(opened);
        drop(gate);
        runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    }

    #[test]
    fn adopt_copies_when_it_cannot_rename() {
        let node = tempfile::tempdir().unwrap();
        let source = handoff(node.path());
        let daemon = tempfile::tempdir().unwrap();
        let data_dir = daemon.path().join("copied");
        copy_handoff(&source, &data_dir).unwrap();
        assert!(!source.exists());
        verify(&data_dir).unwrap();
    }
}
