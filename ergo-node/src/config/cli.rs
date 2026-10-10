//! `Cli` — clap-derived argument parser.
//!
//! Precedence with the TOML config (handled by `NodeConfig::load`):
//! CLI values override TOML values override built-in defaults.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Offline operator commands. These never start the node or load its config.
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Create a new validated configuration and protected API credential.
    Init(crate::init::InitArgs),
    /// Generate or hash an API credential without starting the node.
    ApiKey {
        #[command(subcommand)]
        command: ApiKeyCommand,
    },
    /// Copy and upgrade a stopped legacy redb database; never replace either path.
    MigrateRedb {
        /// Existing database belonging to a stopped node.
        source: PathBuf,
        /// New database path in an existing directory; must not exist.
        destination: PathBuf,
    },
    /// Upgrade all legacy databases in a stopped node's data directory in place.
    UpgradeData {
        data_dir: PathBuf,
        /// Exactly `[indexer] db_filename`, including any configured path.
        #[arg(long, default_value = "indexer.redb")]
        indexer_db: PathBuf,
        /// Remove legacy rollback copies after verification; requires an external backup to roll back.
        #[arg(long)]
        discard_backups: bool,
        /// Retain a stale legacy indexer instead of deleting derived data before the state upgrade.
        #[arg(long, conflicts_with = "discard_backups")]
        keep_stale_indexer: bool,
    },
    /// Verify and copy a stopped node's complete data directory.
    Backup {
        data_dir: PathBuf,
        destination: PathBuf,
    },
    /// Verify checksums, committed metadata and UTXO root in a backup.
    VerifyBackup { directory: PathBuf },
    /// Restore a verified backup into a new data directory.
    Restore {
        directory: PathBuf,
        destination: PathBuf,
        /// Confirm that private transactions and wallet jobs from this backup may run again.
        #[arg(long)]
        keep_pending_work: bool,
    },
    /// Inspect a stopped node without repairing or changing its databases.
    Doctor { data_dir: PathBuf },
    /// Verify and report logical current-UTXO storage usage.
    UtxoStats { data_dir: PathBuf },
    /// Discover tracked wallet holdings from current UTXOs; no historical blocks required.
    WalletScanUtxo {
        data_dir: PathBuf,
        /// Standalone wallet directory; stop the daemon before discovery.
        /// Omit to retain the embedded wallet target.
        #[arg(long)]
        wallet_data_dir: Option<PathBuf>,
        /// Discard a previous checkpoint and start at the current committed tip.
        #[arg(long)]
        restart: bool,
    },
    /// Remove a legacy embedded wallet's rows from a stopped node once the
    /// wallet daemon has adopted it (`ergo-walletd adopt`).
    WalletLegacyPurge {
        data_dir: PathBuf,
        /// Also delete the legacy encrypted keystore in `data_dir/wallet/`.
        /// The daemon holds its own copy; keep a backup of the mnemonic.
        #[arg(long)]
        remove_keystore: bool,
    },
}

/// Secrets are supplied through files or stdin, never through CLI arguments.
#[derive(Subcommand, Debug, Clone)]
pub enum ApiKeyCommand {
    /// Save a new random secret and print its configuration hash.
    Generate {
        /// New secret file in an existing directory; stdout (-) is forbidden.
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print the configuration hash of an existing secret.
    Hash {
        #[arg(long, required_unless_present = "stdin", conflicts_with = "stdin")]
        secret_file: Option<PathBuf>,
        /// Read from stdin without a prompt.
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Parser, Debug)]
#[command(
    name = "ergo-node",
    version,
    about = "Ergo Rust full node",
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    /// Offline operator command instead of starting a node.
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Path to config file (default: ergo-node.toml in data dir)
    #[arg(long, short = 'c')]
    pub config: Option<PathBuf>,

    /// Network: mainnet, testnet, or devnet
    #[arg(long)]
    pub network: Option<String>,

    /// Peer addresses (comma-separated, overrides config file)
    #[arg(long, value_delimiter = ',')]
    pub peers: Vec<SocketAddr>,

    /// Data directory
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// IBD durability flush interval (blocks). During initial sync,
    /// block commits use `Durability::None` except every N blocks which
    /// use `Durability::Immediate` (a synchronous flush on every supported OS).
    /// Default 500 — empirically reduces durable-flush spikes >500ms by
    /// ~75% vs the old 100, with no measurable loss in apply throughput.
    /// On hard crash, up to N blocks of work replays from peers.
    /// Automatically disabled when near chain tip. 0 = always durable.
    #[arg(long, default_value = "500")]
    pub ibd_flush_interval: u32,

    /// AVL arena cache, in bytes (redb's internal cache is separate).
    /// Larger cache → fewer disk
    /// reads for AVL nodes during IBD on a multi-GB database. Default
    /// matches `StateStore::DEFAULT_CACHE_BYTES`. Set lower on
    /// memory-constrained hosts; higher won't hurt until the working
    /// set fits.
    #[arg(long)]
    pub cache_bytes: Option<usize>,

    /// Script-validation checkpoint height. Blocks at or below this
    /// height skip per-input ErgoScript evaluation but still apply UTXO
    /// mutations and verify the per-block AVL state root. Default is
    /// the network's hardcoded checkpoint (Scala-parity for mainnet).
    /// Use 0 to disable (full validation everywhere). Pair with
    /// `--checkpoint-block-id` so the configured block at this exact
    /// height is asserted on apply — a mismatch is a hard error.
    #[arg(long)]
    pub checkpoint_height: Option<u32>,

    /// Hex-encoded block_id matching `--checkpoint-height`. Required if
    /// `--checkpoint-height` is set (and non-zero) and you want the
    /// safety assertion to fire. Defaults to the network's hardcoded
    /// checkpoint block_id when only the height is overridden.
    #[arg(long)]
    pub checkpoint_block_id: Option<String>,

    /// Disable mempool entirely (useful for sync-test or archival runs).
    /// Equivalent to `[mempool] disabled = true` in the config file.
    #[arg(long)]
    pub mempool_disabled: bool,

    /// Mempool priority sort policy: cost (default), size, or min.
    /// Equivalent to `[mempool] sort_policy = "..."` in the config file.
    #[arg(long)]
    pub mempool_sort: Option<String>,

    /// Enable the external-miner subsystem and its `/mining/*` REST
    /// routes. Equivalent to `[mining] enabled = true` in the config
    /// file. The reward key is taken from `--mining-public-key` /
    /// `[mining] miner_public_key_hex` when set; otherwise it is
    /// resolved from the wallet's EIP-3 first-address key, so the node
    /// must have a wallet. CLI presence forces ON; absence defers to TOML.
    #[arg(long)]
    pub mining_enabled: bool,

    /// Hex-encoded 33-byte compressed secp256k1 miner pubkey (66 hex
    /// chars). The reward output script is constructed as
    /// `SigmaAnd(GE(Height, SELF.creationHeight + 720),
    /// proveDlog(pk))`. Equivalent to `[mining] miner_public_key_hex =
    /// "..."` in the config file.
    #[arg(long)]
    pub mining_public_key: Option<String>,
}
