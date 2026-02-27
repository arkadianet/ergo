use serde::Deserialize;
use crate::network_type::NetworkType;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WalletSettings {
    #[serde(default)]
    pub test_mnemonic: String,
    #[serde(default)]
    pub test_mnemonic_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ErgoSettings {
    pub ergo: ErgoNodeSettings,
    pub network: NetworkSettings,
    pub api: ApiSettings,
    #[serde(default)]
    pub wallet: Option<WalletSettings>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ErgoNodeSettings {
    pub directory: String,
    pub network_type: NetworkType,
    pub node: NodeSettings,
    pub chain: ChainSettings,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeSettings {
    pub state_type: String,
    pub verify_transactions: bool,
    pub blocks_to_keep: i32,
    pub mining: bool,
    #[serde(default)]
    pub mining_pub_key_hex: String,
    #[serde(default = "default_use_external_miner")]
    pub use_external_miner: bool,
    #[serde(default)]
    pub internal_miners_count: u32,
    #[serde(default = "default_internal_miner_polling_ms")]
    pub internal_miner_polling_ms: u64,
    #[serde(default = "default_candidate_generation_interval_s")]
    pub candidate_generation_interval_s: u64,
    pub max_transaction_cost: u32,
    pub max_transaction_size: u32,
    #[serde(default = "default_keep_versions")]
    pub keep_versions: u32,
    #[serde(default = "default_mempool_capacity")]
    pub mempool_capacity: u32,
    #[serde(
        default = "default_cleanup_secs",
        alias = "mempool_cleanup_duration_mins"
    )]
    pub mempool_cleanup_duration_secs: u64,
    #[serde(default = "default_sorting")]
    pub mempool_sorting: String,
    #[serde(default = "default_rebroadcast")]
    pub rebroadcast_count: u32,
    #[serde(default = "default_min_fee")]
    pub minimal_fee_amount: u64,
    #[serde(default = "default_header_chain_diff")]
    pub header_chain_diff: u32,
    #[serde(default = "default_ad_proofs_suffix")]
    pub ad_proofs_suffix_length: u32,
    #[serde(default)]
    pub extra_index: bool,
    #[serde(default)]
    pub blacklisted_transactions: Vec<String>,
    #[serde(default)]
    pub checkpoint_height: u32,
    #[serde(default = "default_voting_targets")]
    pub voting_targets: Vec<u8>,
    #[serde(default)]
    pub utxo_bootstrap: bool,
    #[serde(default)]
    pub storing_utxo_snapshots: u32,
    #[serde(default = "default_p2p_utxo_snapshots")]
    pub p2p_utxo_snapshots: u32,
    #[serde(default = "default_make_snapshot_every")]
    pub make_snapshot_every: u32,
}

fn default_keep_versions() -> u32 { 200 }
fn default_mempool_capacity() -> u32 { 1000 }
fn default_cleanup_secs() -> u64 { 30 }
fn default_sorting() -> String { "random".into() }
fn default_rebroadcast() -> u32 { 3 }
fn default_min_fee() -> u64 { 1_000_000 }
fn default_header_chain_diff() -> u32 { 100 }
fn default_ad_proofs_suffix() -> u32 { 114688 }
fn default_use_external_miner() -> bool { true }
fn default_internal_miner_polling_ms() -> u64 { 500 }
fn default_candidate_generation_interval_s() -> u64 { 60 }
fn default_p2p_utxo_snapshots() -> u32 { 2 }
fn default_make_snapshot_every() -> u32 { 52224 }
fn default_voting_targets() -> Vec<u8> { vec![0, 0, 0] }

impl NodeSettings {
    /// Parse the configured mining public key (33-byte compressed EC point).
    /// Returns None if mining_pub_key_hex is empty or invalid.
    pub fn mining_pub_key(&self) -> Option<[u8; 33]> {
        if self.mining_pub_key_hex.is_empty() {
            return None;
        }
        let bytes = hex::decode(&self.mining_pub_key_hex).ok()?;
        if bytes.len() != 33 {
            return None;
        }
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&bytes);
        Some(pk)
    }

    /// Get the voting targets as a 3-byte array.
    /// Pads with zeros if fewer than 3 elements are provided.
    pub fn votes(&self) -> [u8; 3] {
        let mut v = [0u8; 3];
        for (i, &b) in self.voting_targets.iter().take(3).enumerate() {
            v[i] = b;
        }
        v
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainSettings {
    pub protocol_version: u8,
    pub address_prefix: u8,
    pub block_interval_secs: u64,
    pub epoch_length: u32,
    pub use_last_epochs: u32,
    pub initial_difficulty_hex: String,
    #[serde(default = "default_genesis_state_digest")]
    pub genesis_state_digest_hex: String,
    #[serde(default)]
    pub genesis_id: String,
    #[serde(default = "default_v2_height")]
    pub version2_activation_height: u32,
    #[serde(default = "default_v2_difficulty")]
    pub version2_activation_difficulty_hex: String,
    pub pow: PowSettings,
    pub monetary: MonetarySettings,
}

fn default_genesis_state_digest() -> String {
    "a5df145d41ab15a01e0cd3ffbab046f0d029e5412293072ad0f5827428589b9302".to_string()
}
fn default_v2_height() -> u32 { 417_792 }
fn default_v2_difficulty() -> String { "6f98d5000000".to_string() }

impl ChainSettings {
    /// Decode the genesis state digest hex string into bytes.
    pub fn genesis_state_digest(&self) -> Vec<u8> {
        hex::decode(&self.genesis_state_digest_hex)
            .unwrap_or_else(|_| vec![0u8; 33])
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PowSettings {
    pub pow_type: String,
    pub k: u32,
    pub n: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MonetarySettings {
    pub fixed_rate_period: u64,
    pub fixed_rate: u64,
    pub founders_initial_reward: u64,
    pub epoch_length: u64,
    pub one_epoch_reduction: u64,
    pub miner_reward_delay: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkSettings {
    pub node_name: String,
    pub app_version: String,
    pub agent_name: String,
    pub bind_address: String,
    pub magic_bytes: Vec<u8>,
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default)]
    pub known_peers: Vec<String>,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
    #[serde(default = "default_delivery_timeout")]
    pub delivery_timeout_secs: u64,
    #[serde(default = "default_max_delivery_checks")]
    pub max_delivery_checks: u32,
    #[serde(default = "default_desired_inv")]
    pub desired_inv_objects: u32,
    #[serde(default = "default_max_modifiers_cache")]
    pub max_modifiers_cache_size: u32,
    #[serde(default = "default_max_peer_spec")]
    pub max_peer_spec_objects: u32,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
    #[serde(default = "default_sync_interval_stable")]
    pub sync_interval_stable_secs: u64,
    #[serde(default = "default_peer_discovery")]
    pub peer_discovery: bool,
    #[serde(default = "default_inactive_deadline")]
    pub inactive_connection_deadline_secs: u64,
}

fn default_handshake_timeout() -> u64 { 30 }
fn default_max_connections() -> u32 { 30 }
fn default_connection_timeout() -> u64 { 1 }
fn default_delivery_timeout() -> u64 { 10 }
fn default_max_delivery_checks() -> u32 { 2 }
fn default_desired_inv() -> u32 { 400 }
fn default_max_modifiers_cache() -> u32 { 1024 }
fn default_max_peer_spec() -> u32 { 64 }
fn default_sync_interval() -> u64 { 5 }
fn default_sync_interval_stable() -> u64 { 30 }
fn default_peer_discovery() -> bool { true }
fn default_inactive_deadline() -> u64 { 600 }

#[derive(Debug, Clone, Deserialize)]
pub struct ApiSettings {
    pub bind_address: String,
    #[serde(default)]
    pub api_key_hash: Option<String>,
    #[serde(default)]
    pub cors_allowed_origin: Option<String>,
    #[serde(default = "default_api_timeout")]
    pub timeout_secs: u64,
}

fn default_api_timeout() -> u64 { 5 }

impl ErgoSettings {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CONFIG: &str = r#"
[ergo]
directory = "/tmp/.ergo"
network_type = "testnet"

[ergo.node]
state_type = "utxo"
verify_transactions = true
blocks_to_keep = -1
mining = false
mining_pub_key_hex = ""
use_external_miner = true
internal_miners_count = 0
internal_miner_polling_ms = 500
candidate_generation_interval_s = 60
max_transaction_cost = 1000000
max_transaction_size = 98304
keep_versions = 200
mempool_capacity = 1000
mempool_cleanup_duration_secs = 30
mempool_sorting = "random"
rebroadcast_count = 3
minimal_fee_amount = 1000000
header_chain_diff = 100
ad_proofs_suffix_length = 114688
extra_index = false

[ergo.chain]
protocol_version = 4
address_prefix = 16
block_interval_secs = 120
epoch_length = 1024
use_last_epochs = 8
initial_difficulty_hex = "01"

[ergo.chain.pow]
pow_type = "autolykos"
k = 32
n = 26

[ergo.chain.monetary]
fixed_rate_period = 525600
fixed_rate = 75000000000
founders_initial_reward = 7500000000
epoch_length = 64800
one_epoch_reduction = 3000000000
miner_reward_delay = 720

[network]
node_name = "ergo-rust-test"
app_version = "6.0.1"
agent_name = "ergoref"
bind_address = "0.0.0.0:9020"
magic_bytes = [2, 0, 0, 1]
handshake_timeout_secs = 30
max_connections = 30
connection_timeout_secs = 1
delivery_timeout_secs = 10
max_delivery_checks = 100
desired_inv_objects = 400
max_modifiers_cache_size = 1024
max_peer_spec_objects = 64
sync_interval_secs = 5
sync_interval_stable_secs = 30
peer_discovery = true

[api]
bind_address = "127.0.0.1:9052"
api_key_hash = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf"
timeout_secs = 5
"#;

    #[test]
    fn parse_minimal_config() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        assert_eq!(settings.ergo.network_type, crate::network_type::NetworkType::TestNet);
        assert_eq!(settings.ergo.node.mempool_capacity, 1000);
        assert_eq!(settings.ergo.chain.pow.k, 32);
        assert_eq!(settings.network.magic_bytes, vec![2, 0, 0, 1]);
        assert_eq!(settings.api.timeout_secs, 5);
    }

    #[test]
    fn node_settings_defaults_match_scala() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        assert_eq!(settings.ergo.node.max_transaction_cost, 1_000_000);
        assert_eq!(settings.ergo.node.max_transaction_size, 98304);
        assert_eq!(settings.ergo.node.keep_versions, 200);
        assert!(!settings.ergo.node.mining);
        assert!(!settings.ergo.node.extra_index);
    }

    #[test]
    fn chain_settings_monetary() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        let m = &settings.ergo.chain.monetary;
        assert_eq!(m.fixed_rate_period, 525_600);
        assert_eq!(m.fixed_rate, 75_000_000_000);
        assert_eq!(m.miner_reward_delay, 720);
    }

    /// Config without mining fields — all mining settings should get defaults.
    #[test]
    fn mining_settings_defaults() {
        // Strip the mining-specific lines from MINIMAL_CONFIG to test defaults
        let config_no_mining = MINIMAL_CONFIG
            .lines()
            .filter(|l| {
                !l.starts_with("mining_pub_key_hex")
                    && !l.starts_with("use_external_miner")
                    && !l.starts_with("internal_miners_count")
                    && !l.starts_with("internal_miner_polling_ms")
                    && !l.starts_with("candidate_generation_interval_s")
            })
            .collect::<Vec<_>>()
            .join("\n");

        let settings: ErgoSettings = toml::from_str(&config_no_mining).unwrap();
        let n = &settings.ergo.node;
        assert!(n.mining_pub_key_hex.is_empty());
        assert!(n.use_external_miner);
        assert_eq!(n.internal_miners_count, 0);
        assert_eq!(n.internal_miner_polling_ms, 500);
        assert_eq!(n.candidate_generation_interval_s, 60);
        assert!(n.mining_pub_key().is_none());
    }

    /// Valid 33-byte compressed public key hex.
    #[test]
    fn mining_pub_key_valid() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        let mut node = settings.ergo.node.clone();
        // 33 bytes = 66 hex chars; use a plausible compressed EC point (02 prefix)
        node.mining_pub_key_hex =
            "0350e25cee8562697d55275c96bb01b34228f9bd68fd9933f2a25ff195526864f5".to_string();
        let pk = node.mining_pub_key();
        assert!(pk.is_some());
        let arr = pk.unwrap();
        assert_eq!(arr.len(), 33);
        assert_eq!(arr[0], 0x03);
    }

    /// Empty hex string returns None.
    #[test]
    fn mining_pub_key_empty() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        assert!(settings.ergo.node.mining_pub_key().is_none());
    }

    /// Invalid hex string returns None.
    #[test]
    fn mining_pub_key_invalid_hex() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        let mut node = settings.ergo.node.clone();

        // Not valid hex
        node.mining_pub_key_hex = "ZZZZ".to_string();
        assert!(node.mining_pub_key().is_none());

        // Valid hex but wrong length (32 bytes instead of 33)
        node.mining_pub_key_hex =
            "0350e25cee8562697d55275c96bb01b34228f9bd68fd9933f2a25ff195526864".to_string();
        assert!(node.mining_pub_key().is_none());
    }

    /// UTXO snapshot settings get correct defaults when not specified in config.
    #[test]
    fn utxo_snapshot_settings_defaults() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        let n = &settings.ergo.node;
        assert!(!n.utxo_bootstrap);
        assert_eq!(n.storing_utxo_snapshots, 0);
        assert_eq!(n.p2p_utxo_snapshots, 2);
        assert_eq!(n.make_snapshot_every, 52224);
    }

    /// UTXO snapshot settings can be explicitly set in config.
    #[test]
    fn utxo_snapshot_settings_explicit() {
        let config_with_utxo = MINIMAL_CONFIG.replace(
            "extra_index = false",
            "extra_index = false\nutxo_bootstrap = true\nstoring_utxo_snapshots = 3\np2p_utxo_snapshots = 5\nmake_snapshot_every = 10000",
        );
        let settings: ErgoSettings = toml::from_str(&config_with_utxo).unwrap();
        let n = &settings.ergo.node;
        assert!(n.utxo_bootstrap);
        assert_eq!(n.storing_utxo_snapshots, 3);
        assert_eq!(n.p2p_utxo_snapshots, 5);
        assert_eq!(n.make_snapshot_every, 10000);
    }

    #[test]
    fn voting_targets_default() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        assert_eq!(settings.ergo.node.votes(), [0, 0, 0]);
    }

    #[test]
    fn voting_targets_explicit() {
        let config_with_votes = MINIMAL_CONFIG.replace(
            "extra_index = false",
            "extra_index = false\nvoting_targets = [1, 5, 0]",
        );
        let settings: ErgoSettings = toml::from_str(&config_with_votes).unwrap();
        assert_eq!(settings.ergo.node.votes(), [1, 5, 0]);
    }

    #[test]
    fn inactive_deadline_default() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        assert_eq!(settings.network.inactive_connection_deadline_secs, 600);
    }

    #[test]
    fn voting_targets_short() {
        let config_with_votes = MINIMAL_CONFIG.replace(
            "extra_index = false",
            "extra_index = false\nvoting_targets = [1]",
        );
        let settings: ErgoSettings = toml::from_str(&config_with_votes).unwrap();
        assert_eq!(settings.ergo.node.votes(), [1, 0, 0]);
    }

    #[test]
    fn genesis_state_digest_parses() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        let digest = settings.ergo.chain.genesis_state_digest();
        // Default mainnet digest is 33 bytes starting with 0xa5
        assert_eq!(digest.len(), 33);
        assert_eq!(digest[0], 0xa5);
    }

    #[test]
    fn genesis_state_digest_invalid_hex_returns_zeros() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        let mut chain = settings.ergo.chain.clone();
        chain.genesis_state_digest_hex = "ZZZZ_not_valid_hex".to_string();
        let digest = chain.genesis_state_digest();
        assert_eq!(digest, vec![0u8; 33]);
    }

    #[test]
    fn v2_settings_defaults() {
        let settings: ErgoSettings = toml::from_str(MINIMAL_CONFIG).unwrap();
        let chain = &settings.ergo.chain;
        assert_eq!(chain.version2_activation_height, 417_792);
        assert_eq!(chain.version2_activation_difficulty_hex, "6f98d5000000");
        assert_eq!(
            chain.genesis_state_digest_hex,
            "a5df145d41ab15a01e0cd3ffbab046f0d029e5412293072ad0f5827428589b9302"
        );
        assert!(chain.genesis_id.is_empty());
    }
}
