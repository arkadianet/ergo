//! `Cli` — clap-derived argument parser.
//!
//! Precedence with the TOML config (handled by `NodeConfig::load`):
//! CLI values override TOML values override built-in defaults.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ergo-node", about = "Ergo Rust full node")]
pub struct Cli {
    /// Path to config file (default: ergo-node.toml in data dir)
    #[arg(long, short = 'c')]
    pub config: Option<PathBuf>,

    /// Network: mainnet or testnet
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
    /// use `Durability::Eventual` (queued to OS pagecache, fsync deferred).
    /// Default 500 — empirically reduces durable-flush spikes >500ms by
    /// ~75% vs the old 100, with no measurable loss in apply throughput.
    /// On hard crash, up to N blocks of work replays from peers.
    /// Automatically disabled when near chain tip. 0 = always durable.
    #[arg(long, default_value = "500")]
    pub ibd_flush_interval: u32,

    /// redb + AVL arena page cache, in bytes. Larger cache → fewer disk
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
