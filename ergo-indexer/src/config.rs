use serde::{Deserialize, Serialize};

/// Indexer configuration loaded from the `[indexer]` TOML section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IndexerConfig {
    /// Whether the indexer is enabled. When `false`, `IndexerHandle`
    /// is not constructed and the polling task never spawns.
    pub enabled: bool,
    /// Sleep interval (in ms) when the chain tip has not advanced.
    pub poll_idle_ms: u64,
    /// File name (relative to the node data directory) for the
    /// indexer's redb database.
    pub db_filename: String,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_idle_ms: 1000,
            db_filename: "indexer.redb".to_string(),
        }
    }
}
