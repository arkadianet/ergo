//! First-run helpers: `ergo-walletd init` and `ergo-walletd reward-key`.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Args;
use zeroize::Zeroizing;

use crate::config::{ConfigError, Network};

#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    /// Daemon config file to create; it must not exist. The two credential
    /// files are created beside it.
    #[arg(long)]
    pub config: PathBuf,
    /// Data directory for the new seed wallet.
    #[arg(long)]
    pub data_dir: PathBuf,
    /// The node's API base URL.
    #[arg(long, default_value = "http://127.0.0.1:9053")]
    pub node_url: String,
    #[arg(long, default_value = "mainnet")]
    pub network: Network,
    /// Loopback TCP address for the local API (browser access); the default
    /// is a Unix socket beside the config on Unix.
    #[arg(long)]
    pub tcp: Option<std::net::SocketAddr>,
    /// Also grant the node credential the `operator` scope, for private
    /// mining jobs.
    #[arg(long)]
    pub mining_jobs: bool,
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// 32 random bytes as 64 hex characters, the node's credential format.
fn new_secret() -> Zeroizing<String> {
    let mut random = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, random.as_mut());
    Zeroizing::new(hex::encode(random.as_ref()))
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn toml_string(path: &Path) -> Result<String, ConfigError> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid(format!("{} is not UTF-8", path.display())))?;
    Ok(toml::Value::String(text.to_owned()).to_string())
}

/// What `init` created and what the node needs.
pub struct InitOutcome {
    pub node_key_hash: String,
    pub scopes: Vec<&'static str>,
    pub config: PathBuf,
}

/// Write a seed-mode config and two fresh owner-only credentials.
pub fn init(args: &InitArgs) -> Result<InitOutcome, ConfigError> {
    let directory = args
        .config
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let node_key = directory.join("node-api-key");
    let wallet_key = directory.join("wallet-api-key");
    for path in [&args.config, &node_key, &wallet_key] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(invalid(format!("{} already exists", path.display())));
        }
    }
    let listener = match args.tcp {
        Some(address) => {
            if !address.ip().is_loopback() {
                return Err(invalid("the local API must bind a loopback address"));
            }
            format!("tcp_fallback = \"{address}\"\n")
        }
        None if cfg!(unix) => format!(
            "unix_socket = {}\n",
            toml_string(&directory.join("ergo-walletd.sock"))?
        ),
        None => "tcp_fallback = \"127.0.0.1:3033\"\n".to_string(),
    };
    let config = format!(
        "# Created by `ergo-walletd init`. See docs/configuration.md.\n\
         mode = \"seed\"\n\
         network = \"{network}\"\n\
         data_dir = {data_dir}\n\
         node_url = {node_url}\n\
         api_key_file = {node_key}\n\
         local_api_key_file = {wallet_key}\n\
         \n\
         [api]\n\
         {listener}",
        network = args.network.as_str(),
        data_dir = toml_string(&args.data_dir)?,
        node_url = toml::Value::String(args.node_url.clone()),
        node_key = toml_string(&node_key)?,
        wallet_key = toml_string(&wallet_key)?,
    );
    // Validate before writing anything.
    let file: crate::config::FileConfig =
        toml::from_str(&config).map_err(|error| invalid(error.to_string()))?;
    crate::config::Config::from_file(crate::config::merge_api_section(file)?)?;
    let node_secret = new_secret();
    let wallet_secret = new_secret();
    write_new_private(&node_key, node_secret.as_bytes())?;
    write_new_private(&wallet_key, wallet_secret.as_bytes())?;
    write_new_private(&args.config, config.as_bytes())?;
    let mut scopes = vec!["wallet"];
    if args.mining_jobs {
        scopes.push("operator");
    }
    Ok(InitOutcome {
        node_key_hash: hex::encode(ergo_crypto::autolykos::common::blake2b256(
            node_secret.as_bytes(),
        )),
        scopes,
        config: args.config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_a_loadable_config_and_distinct_private_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let args = InitArgs {
            config: dir.path().join("walletd.toml"),
            data_dir: dir.path().join("data"),
            node_url: "http://127.0.0.1:9053".into(),
            network: Network::Mainnet,
            tcp: Some("127.0.0.1:3033".parse().unwrap()),
            mining_jobs: true,
        };
        let outcome = init(&args).unwrap();
        assert_eq!(outcome.scopes, vec!["wallet", "operator"]);
        let node = fs::read(dir.path().join("node-api-key")).unwrap();
        assert_eq!(
            outcome.node_key_hash,
            hex::encode(ergo_crypto::autolykos::common::blake2b256(&node))
        );
        let loaded =
            crate::config::Config::load(<crate::config::Cli as clap::Parser>::parse_from([
                "ergo-walletd",
                "--config",
                args.config.to_str().unwrap(),
            ]))
            .unwrap();
        assert_eq!(loaded.config.mode, crate::config::WalletMode::Seed);
        assert!(!bool::from(loaded.api_key.ct_eq(&loaded.local_api_key)));
        assert!(init(&args).is_err(), "never overwrites");
    }

    #[test]
    fn reward_key_of_a_fresh_wallet_is_derived_from_its_seed() {
        ergo_wallet::storage::use_fast_keystore_kdf_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let args = InitArgs {
            config: dir.path().join("walletd.toml"),
            data_dir: dir.path().join("data"),
            node_url: "http://127.0.0.1:9053".into(),
            network: Network::Mainnet,
            tcp: Some("127.0.0.1:3033".parse().unwrap()),
            mining_jobs: false,
        };
        init(&args).unwrap();
        let loaded =
            crate::config::Config::load(<crate::config::Cli as clap::Parser>::parse_from([
                "ergo-walletd",
                "--config",
                args.config.to_str().unwrap(),
            ]))
            .unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut storage = ergo_wallet::storage::SecretStorage::open(args.data_dir.join("wallet"));
        storage.restore(phrase, "", "reward-pass", false).unwrap();
        storage.unlock("reward-pass").unwrap();
        let expected = storage
            .unlocked()
            .unwrap()
            .master
            .derive_pubkey_at_path(&ergo_wallet::DerivationPath::eip3_first_address())
            .unwrap();
        assert_eq!(
            crate::seal::reward_key(&loaded.config, "reward-pass").unwrap(),
            expected
        );
        assert!(crate::seal::reward_key(&loaded.config, "wrong").is_err());
    }
}
