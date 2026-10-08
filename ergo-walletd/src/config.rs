use std::fmt;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use ergo_ser::address::NetworkPrefix;
use reqwest::Url;
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_API_KEY_BYTES: usize = 4096;
const MAX_DESCRIPTOR_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Whether this daemon tracks public descriptors or owns an encrypted seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum WalletMode {
    #[default]
    WatchOnly,
    Seed,
}

impl WalletMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WatchOnly => "watch_only",
            Self::Seed => "seed",
        }
    }
}

/// Which Ergo network the daemon reports. The value is required to be one of
/// the two public networks (it defaults to mainnet when the key is absent, and
/// any other value is a hard load error) and it is the single source of truth
/// for descriptor validation and for every base58 address the local API
/// renders. It must match the network the configured `node_url` serves — the
/// daemon cannot infer it from the node, and a mismatch renders addresses that
/// the node's network will not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
}

impl Network {
    /// Address network prefix (base58 high nibble) for this network.
    pub const fn prefix(self) -> NetworkPrefix {
        match self {
            Self::Mainnet => NetworkPrefix::Mainnet,
            Self::Testnet => NetworkPrefix::Testnet,
        }
    }

    /// Config-file spelling of the network.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            other => Err(format!(
                "network must be \"mainnet\" or \"testnet\", not \"{other}\""
            )),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration file error: {0}")]
    File(String),
    #[error("configuration value is invalid: {0}")]
    Invalid(String),
    #[error("API key file is not protected: {0}")]
    ApiKeyPermissions(String),
    #[error("API key file is invalid: {0}")]
    ApiKey(String),
    #[error("descriptor file is invalid: {0}")]
    Descriptor(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ApiSection {
    pub unix_socket: Option<PathBuf>,
    #[serde(alias = "tcp_addr")]
    pub tcp_fallback: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub mode: WalletMode,
    /// Required network identity. Absent means `mainnet`; any value other
    /// than `mainnet`/`testnet` is rejected at load.
    #[serde(default)]
    pub network: Network,
    pub data_dir: PathBuf,
    pub node_url: String,
    pub api_key_file: PathBuf,
    pub descriptor_file: Option<PathBuf>,
    pub local_api_key_file: Option<PathBuf>,
    #[serde(
        default = "default_sync_interval",
        alias = "sync_interval_secs",
        deserialize_with = "deserialize_seconds"
    )]
    pub sync_interval: u64,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
    #[serde(default = "default_sync_batch", alias = "batch_size")]
    pub sync_batch: u32,
    #[serde(default = "default_blocks_page", alias = "page_size")]
    pub blocks_page: u32,
    pub unix_socket: Option<PathBuf>,
    #[serde(alias = "tcp_addr")]
    pub tcp_fallback: Option<SocketAddr>,
    pub api: Option<ApiSection>,
}

fn default_shutdown_timeout() -> u64 {
    5
}

fn deserialize_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("sync_interval must be unsigned")),
        serde_json::Value::String(text) => parse_duration_seconds(&text)
            .ok_or_else(|| serde::de::Error::custom("invalid sync_interval duration")),
        _ => Err(serde::de::Error::custom(
            "sync_interval must be seconds or a duration string",
        )),
    }
}

fn parse_duration_seconds(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds);
    }
    for (suffix, multiplier) in [("ms", 0), ("s", 1), ("m", 60), ("h", 3600)] {
        if let Some(number) = value.strip_suffix(suffix) {
            let number = number.trim().parse::<u64>().ok()?;
            return if suffix == "ms" {
                number.checked_add(999)?.checked_div(1000)
            } else {
                number.checked_mul(multiplier)
            };
        }
    }
    None
}

fn default_sync_interval() -> u64 {
    15
}

fn default_sync_batch() -> u32 {
    256
}

/// Defaults to [`crate::sync::DEFAULT_BLOCKS_PER_PAGE`]. Kept as a literal
/// because the serde default runs before any sync type is in scope here, and
/// `config::bundled_sample_config_matches_the_schema` plus the sync unit test
/// keep the two from drifting.
fn default_blocks_page() -> u32 {
    1
}

#[derive(Debug, Clone, Parser)]
#[command(name = "ergo-walletd", about = "Standalone Ergo wallet daemon")]
pub struct Cli {
    #[arg(long, short = 'c', default_value = "ergo-walletd.toml")]
    pub config: PathBuf,
    #[arg(long, value_enum)]
    pub mode: Option<WalletMode>,
    #[arg(long)]
    pub network: Option<Network>,
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    #[arg(long)]
    pub node_url: Option<String>,
    #[arg(long)]
    pub api_key_file: Option<PathBuf>,
    #[arg(long)]
    pub descriptor_file: Option<PathBuf>,
    #[arg(long)]
    pub local_api_key_file: Option<PathBuf>,
    #[arg(long)]
    pub sync_interval: Option<u64>,
    #[arg(long)]
    pub sync_batch: Option<u32>,
    #[arg(long)]
    pub blocks_page: Option<u32>,
    #[arg(long)]
    pub unix_socket: Option<PathBuf>,
    #[arg(long)]
    pub tcp_fallback: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct ApiKey(Zeroizing<Vec<u8>>);

impl ApiKey {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    #[doc(hidden)]
    pub fn from_test(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApiKey([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: WalletMode,
    pub network: Network,
    pub data_dir: PathBuf,
    pub node_url: Url,
    pub api_key_file: PathBuf,
    pub descriptor_file: Option<PathBuf>,
    pub local_api_key_file: Option<PathBuf>,
    pub sync_interval: Duration,
    pub shutdown_timeout: Duration,
    pub sync_batch: u32,
    pub blocks_page: u32,
    pub unix_socket: Option<PathBuf>,
    pub tcp_fallback: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub api_key: ApiKey,
    pub local_api_key: Option<ApiKey>,
}

impl Config {
    pub fn load(cli: Cli) -> Result<LoadedConfig, ConfigError> {
        let contents = fs::read_to_string(&cli.config)
            .map_err(|error| ConfigError::File(format!("{}: {error}", cli.config.display())))?;
        let mut file: FileConfig = toml::from_str(&contents)
            .map_err(|error| ConfigError::File(format!("{}: {error}", cli.config.display())))?;
        file = merge_api_section(file)?;
        if let Some(value) = cli.mode {
            file.mode = value;
        }
        if let Some(value) = cli.network {
            file.network = value;
        }
        if let Some(value) = cli.data_dir {
            file.data_dir = value;
        }
        if let Some(value) = cli.node_url {
            file.node_url = value;
        }
        if let Some(value) = cli.api_key_file {
            file.api_key_file = value;
        }
        if let Some(value) = cli.descriptor_file {
            file.descriptor_file = Some(value);
        }
        if let Some(value) = cli.local_api_key_file {
            file.local_api_key_file = Some(value);
        }
        if let Some(value) = cli.sync_interval {
            file.sync_interval = value;
        }
        if let Some(value) = cli.sync_batch {
            file.sync_batch = value;
        }
        if let Some(value) = cli.blocks_page {
            file.blocks_page = value;
        }
        if let Some(value) = cli.unix_socket {
            file.unix_socket = Some(value);
        }
        if let Some(value) = cli.tcp_fallback {
            file.tcp_fallback = Some(value);
        }
        let config = Self::from_file(file)?;
        let api_key = read_api_key(&config.api_key_file)?;
        if let Some(path) = &config.descriptor_file {
            validate_file_size(path)?;
        }
        let local_api_key = config
            .local_api_key_file
            .as_deref()
            .map(read_api_key)
            .transpose()?;
        if local_api_key
            .as_ref()
            .is_some_and(|key| key.expose() == api_key.expose())
        {
            return Err(ConfigError::Invalid(
                "local_api_key_file must contain a different credential from api_key_file"
                    .to_string(),
            ));
        }
        Ok(LoadedConfig {
            config,
            api_key,
            local_api_key,
        })
    }

    pub fn from_file(file: FileConfig) -> Result<Self, ConfigError> {
        if file.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "data_dir must not be empty".to_string(),
            ));
        }
        match file.mode {
            WalletMode::WatchOnly => {
                if file
                    .descriptor_file
                    .as_ref()
                    .is_none_or(|path| path.as_os_str().is_empty())
                {
                    return Err(ConfigError::Invalid(
                        "watch_only mode requires descriptor_file".to_string(),
                    ));
                }
                if file.local_api_key_file.is_some() {
                    return Err(ConfigError::Invalid(
                        "local_api_key_file requires seed mode".to_string(),
                    ));
                }
            }
            WalletMode::Seed => {
                if file.descriptor_file.is_some() {
                    return Err(ConfigError::Invalid(
                        "seed mode does not accept descriptor_file".to_string(),
                    ));
                }
                if file
                    .local_api_key_file
                    .as_ref()
                    .is_none_or(|path| path.as_os_str().is_empty())
                {
                    return Err(ConfigError::Invalid(
                        "seed mode requires local_api_key_file".to_string(),
                    ));
                }
            }
        }
        if file.api_key_file.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "api_key_file must not be empty".to_string(),
            ));
        }
        if file.shutdown_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "shutdown_timeout_secs must be greater than zero".to_string(),
            ));
        }
        if file.sync_interval == 0 {
            return Err(ConfigError::Invalid(
                "sync_interval must be greater than zero".to_string(),
            ));
        }
        if !(1..=1024).contains(&file.sync_batch) {
            return Err(ConfigError::Invalid(
                "sync_batch must be between 1 and 1024".to_string(),
            ));
        }
        if !(1..=1024).contains(&file.blocks_page) {
            return Err(ConfigError::Invalid(
                "blocks_page must be between 1 and 1024".to_string(),
            ));
        }
        let node_url = Url::parse(&file.node_url)
            .map_err(|_| ConfigError::Invalid("node_url is not a valid URL".to_string()))?;
        if !matches!(node_url.scheme(), "http" | "https")
            || node_url.host_str().is_none()
            || !node_url.username().is_empty()
            || node_url.password().is_some()
            || node_url.query().is_some()
            || node_url.fragment().is_some()
        {
            return Err(ConfigError::Invalid(
                "node_url must be an http(s) URL without credentials, query, or fragment"
                    .to_string(),
            ));
        }
        if let Some(address) = file.tcp_fallback {
            if !address.ip().is_loopback() {
                return Err(ConfigError::Invalid(
                    "tcp_fallback must bind to a loopback address".to_string(),
                ));
            }
        }
        if file.unix_socket.is_none() && file.tcp_fallback.is_none() {
            return Err(ConfigError::Invalid(
                "at least one of unix_socket or tcp_fallback is required".to_string(),
            ));
        }
        #[cfg(not(unix))]
        if file.unix_socket.is_some() {
            return Err(ConfigError::Invalid(
                "unix_socket is not supported on this platform".to_string(),
            ));
        }
        Ok(Self {
            mode: file.mode,
            network: file.network,
            data_dir: file.data_dir,
            node_url,
            api_key_file: file.api_key_file,
            descriptor_file: file.descriptor_file,
            local_api_key_file: file.local_api_key_file,
            sync_interval: Duration::from_secs(file.sync_interval),
            shutdown_timeout: Duration::from_secs(file.shutdown_timeout_secs),
            sync_batch: file.sync_batch,
            blocks_page: file.blocks_page,
            unix_socket: file.unix_socket,
            tcp_fallback: file.tcp_fallback,
        })
    }
}

/// Fold the optional `[api]` table into the top-level listener fields. The two
/// spellings are aliases, not a merge: specifying both is a load error so a
/// typo cannot silently leave the daemon without the listener the operator
/// intended.
fn merge_api_section(mut file: FileConfig) -> Result<FileConfig, ConfigError> {
    if let Some(api) = file.api.take() {
        if file.unix_socket.is_some() || file.tcp_fallback.is_some() {
            return Err(ConfigError::Invalid(
                "listener fields must be specified either at the top level or in [api], not both"
                    .to_string(),
            ));
        }
        file.unix_socket = api.unix_socket;
        file.tcp_fallback = api.tcp_fallback;
    }
    Ok(file)
}

pub fn read_api_key(path: &Path) -> Result<ApiKey, ConfigError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ConfigError::ApiKeyPermissions(format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(ConfigError::ApiKeyPermissions(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options
        .open(path)
        .map_err(|error| ConfigError::ApiKeyPermissions(format!("{}: {error}", path.display())))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ConfigError::ApiKeyPermissions(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::ApiKeyPermissions(format!(
                "{} must not be accessible by group or other users",
                path.display()
            )));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_API_KEY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| ConfigError::ApiKey(format!("{}: {error}", path.display())))?;
    if bytes.len() > MAX_API_KEY_BYTES {
        return Err(ConfigError::ApiKey("file is too large".to_string()));
    }
    let value = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let value = value.strip_suffix(b"\r").unwrap_or(value);
    if value.is_empty() || value.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
        return Err(ConfigError::ApiKey(
            "file must contain one non-empty header-safe value".to_string(),
        ));
    }
    Ok(ApiKey(Zeroizing::new(value.to_vec())))
}

fn validate_file_size(path: &Path) -> Result<(), ConfigError> {
    let metadata = fs::metadata(path)
        .map_err(|error| ConfigError::Descriptor(format!("{}: {error}", path.display())))?;
    if !metadata.is_file() {
        return Err(ConfigError::Descriptor(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_DESCRIPTOR_FILE_BYTES {
        return Err(ConfigError::Descriptor("file is too large".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn base_file() -> FileConfig {
        FileConfig {
            mode: WalletMode::WatchOnly,
            local_api_key_file: None,
            network: Network::Mainnet,
            data_dir: PathBuf::from("/tmp/ergo-walletd-test"),
            node_url: "http://127.0.0.1:9053".to_string(),
            api_key_file: PathBuf::from("/tmp/api-key"),
            descriptor_file: Some(PathBuf::from("/tmp/descriptors.toml")),
            sync_interval: 1,
            shutdown_timeout_secs: 5,
            sync_batch: 10,
            blocks_page: 2,
            unix_socket: None,
            tcp_fallback: Some("127.0.0.1:3033".parse().unwrap()),
            api: None,
        }
    }

    #[test]
    fn modes_require_their_own_inputs() {
        let mut file = base_file();
        assert_eq!(
            Config::from_file(file.clone()).unwrap().mode,
            WalletMode::WatchOnly
        );
        file.descriptor_file = None;
        assert!(Config::from_file(file.clone()).is_err());
        file.mode = WalletMode::Seed;
        assert!(Config::from_file(file.clone()).is_err());
        file.local_api_key_file = Some(PathBuf::from("local-key"));
        assert_eq!(
            Config::from_file(file.clone()).unwrap().mode,
            WalletMode::Seed
        );
        file.descriptor_file = Some(PathBuf::from("descriptor"));
        assert!(Config::from_file(file.clone()).is_err());
        file.mode = WalletMode::WatchOnly;
        assert!(Config::from_file(file).is_err());
    }

    #[test]
    fn seed_configuration_loads_separate_redacted_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let node_key = dir.path().join("node-key");
        let local_key = dir.path().join("local-key");
        for path in [&node_key, &local_key] {
            fs::write(path, b"same-secret\n").unwrap();
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config_path = dir.path().join("seed.toml");
        fs::write(&config_path, format!(
            "mode = \"seed\"\ndata_dir = {}\nnode_url = \"http://127.0.0.1:9053\"\napi_key_file = {}\nlocal_api_key_file = {}\ntcp_fallback = \"127.0.0.1:3033\"\n",
            toml::Value::String(dir.path().join("data").to_str().unwrap().into()),
            toml::Value::String(node_key.to_str().unwrap().into()),
            toml::Value::String(local_key.to_str().unwrap().into()),
        )).unwrap();
        let cli = Cli::parse_from([
            std::ffi::OsStr::new("ergo-walletd"),
            std::ffi::OsStr::new("--config"),
            config_path.as_os_str(),
        ]);
        let error = Config::load(cli.clone()).unwrap_err();
        assert!(error.to_string().contains("different credential"));
        assert!(!error.to_string().contains("same-secret"));
        fs::write(&local_key, b"local-only-secret\n").unwrap();
        let loaded = Config::load(cli).unwrap();
        assert_eq!(loaded.api_key.expose(), b"same-secret");
        assert_eq!(
            loaded.local_api_key.as_ref().unwrap().expose(),
            b"local-only-secret"
        );
        let debug = format!("{loaded:?}");
        assert!(!debug.contains("same-secret"));
        assert!(!debug.contains("local-only-secret"));
        assert!(loaded.config.descriptor_file.is_none());
    }

    #[test]
    fn api_key_file_read_is_bounded_and_header_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, b"value\r\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_api_key(&path).unwrap().expose(), b"value");
        for bytes in [
            vec![b'x'; MAX_API_KEY_BYTES + 1],
            b"value\nextra".to_vec(),
            vec![],
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(read_api_key(&path).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn api_key_reader_refuses_symlinks_and_public_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, b"value").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_api_key(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(path, &link).unwrap();
        assert!(read_api_key(&link).is_err());
    }

    #[test]
    fn network_is_required_validated_and_defaults_to_mainnet() {
        // Omitted => mainnet.
        let file: FileConfig = toml::from_str(
            r#"
            data_dir = "/tmp/wallet"
            node_url = "http://127.0.0.1:9053"
            api_key_file = "/tmp/key"
            descriptor_file = "/tmp/desc"
            tcp_fallback = "127.0.0.1:3033"
        "#,
        )
        .unwrap();
        let config = Config::from_file(file).unwrap();
        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.network.prefix(), NetworkPrefix::Mainnet);

        // Explicit non-mainnet is honoured and selects the testnet prefix.
        let file: FileConfig = toml::from_str(
            r#"
            network = "testnet"
            data_dir = "/tmp/wallet"
            node_url = "http://127.0.0.1:9053"
            api_key_file = "/tmp/key"
            descriptor_file = "/tmp/desc"
            tcp_fallback = "127.0.0.1:3033"
        "#,
        )
        .unwrap();
        let config = Config::from_file(file).unwrap();
        assert_eq!(config.network, Network::Testnet);
        assert_eq!(config.network.prefix(), NetworkPrefix::Testnet);

        // Anything else is a load error, not a silent fallback to mainnet.
        for value in ["devnet", "MainNet ", "1", "regtest"] {
            let text = format!(
                r#"
                network = "{value}"
                data_dir = "/tmp/wallet"
                node_url = "http://127.0.0.1:9053"
                api_key_file = "/tmp/key"
                descriptor_file = "/tmp/desc"
                tcp_fallback = "127.0.0.1:3033"
            "#
            );
            assert!(
                toml::from_str::<FileConfig>(&text).is_err(),
                "{value} must not load"
            );
        }
    }

    #[test]
    fn network_parsing_accepts_only_the_two_public_networks() {
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!(" MainNet ".parse::<Network>().unwrap(), Network::Mainnet);
        assert!("devnet".parse::<Network>().is_err());
        assert_eq!(Network::Testnet.to_string(), "testnet");
    }

    #[test]
    fn bundled_sample_config_matches_the_schema() {
        // The shipped reference config is documentation: if a key is renamed,
        // added, or given a different type, this fails.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ergo-walletd.toml");
        let text =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let file: FileConfig =
            toml::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let file =
            merge_api_section(file).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        // The sample names a `unix_socket` and no `tcp_fallback`, so it is only
        // a *loadable* config where std has Unix domain sockets. Rather than
        // ship a second non-Unix sample that nothing documents, non-Unix
        // targets assert the one rejection the shipped sample must produce.
        #[cfg(not(unix))]
        let error =
            Config::from_file(file).expect_err("the sample's unix_socket is not available here");
        #[cfg(not(unix))]
        assert!(
            matches!(&error, ConfigError::Invalid(message)
                if message == "unix_socket is not supported on this platform"),
            "unexpected error: {error}"
        );
        #[cfg(unix)]
        {
            let config = Config::from_file(file)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(config.network, Network::Mainnet);
            assert_eq!(config.sync_interval, Duration::from_secs(15));
            assert_eq!(config.sync_batch, 256);
            assert_eq!(config.blocks_page, 1);
            assert!(config.unix_socket.is_some());
            assert!(config.tcp_fallback.is_none());
        }
    }

    #[test]
    fn bundled_seed_config_matches_the_schema() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ergo-walletd-seed.toml");
        let file: FileConfig = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let file = merge_api_section(file).unwrap();
        #[cfg(not(unix))]
        assert!(
            matches!(Config::from_file(file), Err(ConfigError::Invalid(message))
            if message == "unix_socket is not supported on this platform")
        );
        #[cfg(unix)]
        {
            let config = Config::from_file(file).unwrap();
            assert_eq!(config.mode, WalletMode::Seed);
            assert!(config.descriptor_file.is_none());
            assert!(config.local_api_key_file.is_some());
            assert!(config.unix_socket.is_some());
        }
    }

    #[test]
    fn cli_network_overrides_the_file_value() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("api-key");
        fs::write(&key, b"secret\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let descriptors = dir.path().join("descriptors.toml");
        fs::write(
            &descriptors,
            "keys=[{path=\"m/0\",public_key=\"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2\"}]\n",
        )
        .unwrap();
        let config_path = dir.path().join("ergo-walletd.toml");
        fs::write(
            &config_path,
            format!(
                "data_dir = {}\nnode_url = \"http://127.0.0.1:9053\"\napi_key_file = {}\ndescriptor_file = {}\ntcp_fallback = \"127.0.0.1:3033\"\n",
                toml::Value::String(dir.path().to_str().unwrap().to_string()),
                toml::Value::String(key.to_str().unwrap().to_string()),
                toml::Value::String(descriptors.to_str().unwrap().to_string())
            ),
        )
        .unwrap();
        let loaded = Config::load(Cli {
            config: config_path,
            mode: None,
            local_api_key_file: None,
            network: Some(Network::Testnet),
            data_dir: None,
            node_url: None,
            api_key_file: None,
            descriptor_file: None,
            sync_interval: None,
            sync_batch: None,
            blocks_page: None,
            unix_socket: None,
            tcp_fallback: None,
        })
        .unwrap();
        assert_eq!(loaded.config.network, Network::Testnet);
    }

    #[test]
    fn strict_toml_and_url_validation() {
        let text = r#"
            data_dir = "/tmp/wallet"
            node_url = "http://127.0.0.1:9053"
            api_key_file = "/tmp/key"
            descriptor_file = "/tmp/desc"
            sync_batch = 10
            tcp_fallback = "127.0.0.1:3033"
            surprise = true
        "#;
        assert!(toml::from_str::<FileConfig>(text).is_err());
        let mut file = base_file();
        file.node_url = "file:///tmp/node".to_string();
        assert!(Config::from_file(file.clone()).is_err());
        file.node_url = "http://".to_string();
        assert!(Config::from_file(file).is_err());
    }

    #[test]
    fn tcp_fallback_must_be_loopback() {
        let mut file = base_file();
        file.tcp_fallback = Some("0.0.0.0:3033".parse().unwrap());
        assert!(Config::from_file(file).is_err());
    }

    /// `sync_batch` is the apply budget and `blocks_page` is the HTTP page
    /// size: two independent knobs, both bounded, and a bad page is a load
    /// error rather than a startup loop against the node.
    #[test]
    fn blocks_page_is_a_separate_bounded_knob_from_sync_batch() {
        // Absent => the conservative default, and independent of sync_batch.
        let file: FileConfig = toml::from_str(
            r#"
            data_dir = "/tmp/wallet"
            node_url = "http://127.0.0.1:9053"
            api_key_file = "/tmp/key"
            descriptor_file = "/tmp/desc"
            sync_batch = 512
            tcp_fallback = "127.0.0.1:3033"
        "#,
        )
        .unwrap();
        let config = Config::from_file(file).unwrap();
        assert_eq!(config.sync_batch, 512);
        assert_eq!(config.blocks_page, 1);

        // Explicitly overridable, and validated on its own: 0 would ask for an
        // empty page, 1025 would exceed the node's own blocks-since limit.
        let file: FileConfig = toml::from_str(
            r#"
            data_dir = "/tmp/wallet"
            node_url = "http://127.0.0.1:9053"
            api_key_file = "/tmp/key"
            descriptor_file = "/tmp/desc"
            blocks_page = 4
            tcp_fallback = "127.0.0.1:3033"
        "#,
        )
        .unwrap();
        assert_eq!(Config::from_file(file).unwrap().blocks_page, 4);

        for value in ["0", "1025"] {
            let text = format!(
                r#"
                data_dir = "/tmp/wallet"
                node_url = "http://127.0.0.1:9053"
                api_key_file = "/tmp/key"
                descriptor_file = "/tmp/desc"
                blocks_page = {value}
                tcp_fallback = "127.0.0.1:3033"
            "#
            );
            let file: FileConfig = toml::from_str(&text).unwrap();
            let error = Config::from_file(file).expect_err("an unbounded page must be rejected");
            assert!(
                matches!(&error, ConfigError::Invalid(message)
                    if message == "blocks_page must be between 1 and 1024"),
                "unexpected error: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn api_key_file_is_protected_and_debug_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, b"secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let key = read_api_key(&path).unwrap();
        assert_eq!(key.expose(), b"secret");
        assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_api_key(&path),
            Err(ConfigError::ApiKeyPermissions(_))
        ));
    }
}
