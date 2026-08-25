//! `MiningConfig`: the parsed `[mining]` section of `ergo-node.toml`.

use serde::{Deserialize, Serialize};

use crate::error::MiningError;

/// Resolved custom extension fields — `(2-byte key, value bytes)` pairs,
/// as consumed by [`crate::handle::MiningHandle::with_extension_fields`].
pub type ResolvedExtensionFields = Vec<([u8; 2], Vec<u8>)>;

/// Configuration for the mining subsystem.
///
/// Fields map directly to the TOML `[mining]` section. CLI flags
/// (`--mining-enabled`, `--mining-public-key`) override the parsed
/// TOML at startup.
///
/// `offline_generation` is not present in v1 — the bypass would
/// allow mining against an unsynced tip, which can publish candidates
/// whose script context (`CONTEXT.headers`, `LastBlockUtxoRootHash`)
/// diverges from the chain mainnet validators see. Mining is
/// unconditionally gated on `synced(tip)`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MiningConfig {
    /// `false` (default): mining subsystem is disabled and `/mining/*`
    /// endpoints return 503. `true`: subsystem is started; a reward key is
    /// then required, taken from `miner_public_key_hex` if set or resolved
    /// from the wallet's EIP-3 first-address key otherwise.
    #[serde(default)]
    pub enabled: bool,

    /// Miner's reward public key, hex-encoded compressed secp256k1
    /// point (33 bytes → 66 hex chars). Optional: when set it is the pinned
    /// reward key; when omitted the wallet's EIP-3 first-address key is
    /// resolved at candidate time (the node must have a wallet). The reward
    /// output is constructed as
    /// `SigmaAnd(GE(Height, SELF.creationHeight + delta), proveDlog(pk))`
    /// where `delta = chain_config.miner_reward_delay`
    /// (`720` on mainnet).
    #[serde(default)]
    pub miner_public_key_hex: Option<String>,

    /// Debounce window for same-parent mempool-refresh rebuilds, in
    /// milliseconds. When the mempool changes but the tip has not, the action
    /// loop coalesces the burst and re-signals the engine at most once per
    /// window with a fresh mempool snapshot. Lower = fresher candidates but
    /// faster churn of the bounded template ring (8 retained); higher = staler
    /// candidates but longer same-parent history for in-flight solves.
    /// Default: 1000.
    #[serde(default = "default_candidate_interval_ms")]
    pub block_candidate_generation_interval_ms: u64,

    /// v1 must be `true`. The internal CPU-miner thread is deferred
    /// to a follow-up plan; this config exists so a future feature
    /// gate doesn't require a TOML schema change.
    #[serde(default = "default_use_external_miner")]
    pub use_external_miner: bool,

    /// `true`: when an indexer is running, the node sweeps
    /// storage-rent-eligible boxes into a single zero-fee self-claim paid
    /// to the miner's reward key, pinned ahead of mempool selection so any
    /// conflicting fee-bearing claim on the same box is excluded. Default
    /// `false` (opt-in — it changes block contents and seizes rent to the
    /// miner).
    #[serde(default)]
    pub claim_storage_rent: bool,

    /// Upper ceiling on storage-rent boxes swept into one block's
    /// self-claim. This is a safety cap, NOT the real limit: candidate
    /// assembly bounds the claim by the block cost/size budget (after the
    /// coinbase), sweeping the oldest eligible boxes that actually fit. The
    /// default (4096) sits above what a block can hold (~3,700 by cost), so
    /// the budget binds and the claim "fills the block." Lower it to leave
    /// more room for fee-paying user transactions.
    #[serde(default = "default_max_storage_rent_claims")]
    pub max_storage_rent_claims: u32,

    /// `true`: the candidate engine keeps the hydrated AVL working set resident
    /// between candidate builds, keyed on the committed tip. The first build per
    /// block pays the full hydration; same-tip rebuilds (the enriched refresh
    /// and every mempool-driven rebuild) then reuse it and are near-instant.
    /// Default `false` — it holds the full UTXO AVL node graph resident
    /// (multi-GB on a mainnet archival node, scaling with the UTXO-set size), so
    /// it is opt-in for mining nodes with RAM headroom.
    #[serde(default)]
    pub candidate_base_cache: bool,

    /// Operator-configured custom extension fields, injected into every block
    /// candidate's Extension section (the general merge-mining / commitment
    /// hook — e.g. an Aegis `0xAE00` block commitment). Empty by default
    /// (opt-in — it adds bytes to every block). Each entry is a hex `key`
    /// (2 bytes / 4 hex chars) and hex `value` (≤ 64 bytes); the key's first
    /// byte must not be a protocol-reserved namespace (`0x00`/`0x01`/`0x02`).
    /// Validated at startup via [`MiningConfig::validate`].
    #[serde(default)]
    pub extension_fields: Vec<CustomExtensionField>,

    /// `[mining.rent_collector]` — the storage-rent auto-collection
    /// subsystem. Distinct from `claim_storage_rent` (which sweeps rent into
    /// the node's OWN mined block): the collector broadcasts fee-paying
    /// storage-rent claims to the mempool after applying EVERY block (every
    /// synced tip change), not only blocks the node didn't mine. Rent on
    /// blocks the node doesn't win is collected by self-clean: a broadcast
    /// after a self-mined block double-spends the free in-block self-claim, so
    /// if the node mines the next block too the broadcast is evicted unmined
    /// (no fee); when another miner mines next, the broadcast collects. Off by
    /// default. See [`RentCollectorConfig`].
    #[serde(default)]
    pub rent_collector: RentCollectorConfig,
}

/// Fee-bound strategy for the rent-collector's CPFP child fee.
///
/// Serde renames to lower snake_case so the TOML reads
/// `fee_bound = "unbeatable"` / `fee_bound = "observed_competitor"`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FeeBound {
    /// Pay the deterministic *unbeatable* child fee: the family is sized so no
    /// competing claim on the same boxes can out-weigh it under the mempool's
    /// fee-per-cost / fee-per-size ordering (the formula in Phase 1b). The
    /// default — and the only IMPLEMENTED bound.
    #[default]
    Unbeatable,
    /// Pay just enough to beat the cheapest OBSERVED competing claim. A future
    /// stub: NOT yet implemented, so config-load validation rejects it (a
    /// config must not be able to silently select an unimplemented bound).
    ObservedCompetitor,
}

/// `[mining.rent_collector]` configuration: the storage-rent
/// auto-collection subsystem (broadcast fee-paying claims after applying
/// EVERY block; self-clean handles the node's own blocks).
///
/// Mirrors the `claim_storage_rent` / `max_storage_rent_claims` conventions
/// on [`MiningConfig`]: per-field `#[serde(default …)]` so a present-but-
/// partial `[mining.rent_collector]` table fills omitted fields, plus a
/// hand-written [`Default`] impl kept in sync so a programmatically- or
/// CLI-built config (which starts from `Default`, not a deserialized table)
/// gets the same values.
///
/// The cross-section validation (enabling it requires the indexer AND a
/// resolvable proceeds key — the same `RewardKeySource` the miner reward uses)
/// lives at the NODE config-load level, alongside the existing indexer gates;
/// the self-contained parts (the `fee_bound` rejection, and the configured
/// `miner_public_key_hex` well-formedness) are reused from
/// [`MiningConfig::validate`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RentCollectorConfig {
    /// `false` (default): the collector is disabled. `true`: after the node
    /// applies EVERY block (every synced tip change, fully synced + UTXO
    /// mode) — not gated on whether the node mined it — it enumerates eligible
    /// storage-rent boxes, builds fee-paying claims, and admits them to the
    /// local mempool (a broadcast after a self-mined block self-cleans). Enabling
    /// it requires the indexer AND a resolvable proceeds key (checked at node
    /// config-load).
    #[serde(default)]
    pub enabled: bool,

    /// Fee-bound strategy for the CPFP child fee. Default (and only
    /// implemented value) [`FeeBound::Unbeatable`].
    #[serde(default)]
    pub fee_bound: FeeBound,

    /// Upper ceiling on rent boxes swept into one broadcast family. A safety
    /// cap, NOT the real limit: the builder bounds each family by the mempool
    /// per-tx cost/size budget, claiming the oldest eligible boxes that fit.
    /// Mirrors `max_storage_rent_claims`' style; same default (4096).
    #[serde(default = "default_max_storage_rent_claims")]
    pub max_claims: u32,

    /// Minimum net ERG profit (nanoErg) a claim family must clear after fees
    /// and every output's dust before it is broadcast. Default `0` = "claim
    /// any *affordable* box" (still subject to the hard affordability gate —
    /// gross rent must cover the fees + dust). Raise it to skip marginal
    /// boxes whose rent barely exceeds the cost of claiming them.
    #[serde(default)]
    pub min_profit_nanoerg: u64,

    /// Flat fee the recreate-bearing PARENT transaction pays, per input box
    /// claimed (nanoErg). Raised above the relay floor so the parent is
    /// mineable STANDALONE by any fee-sorting pool: Ergo gossips transactions
    /// individually (no package relay), so a CPFP child can never lift a
    /// min-fee parent across the network — only miners that already hold BOTH
    /// family txs and do family-weight ordering would include it. The parent
    /// fee is `max(min_relay_fee, this * num_input_boxes)`; when the family is
    /// batched, the unbeatable child fee auto-adjusts down as the parent
    /// carries more of the weight. Default 0.01 ERG/input. Raise it to win
    /// more contested claims, lower it to keep more of the collected rent.
    #[serde(default = "default_parent_fee_per_input_nanoerg")]
    pub parent_fee_per_input_nanoerg: u64,

    /// Cap on input-disjoint claim families built per tip change. `1`
    /// reproduces the historical single-family path; default `8` chunks
    /// overflow eligible boxes into additional families (still bounded by
    /// `max_claims` total and [`Self::collect_time_budget_ms`]). Binary-swap
    /// without a TOML key activates this.
    #[serde(default = "default_max_families_per_tip")]
    pub max_families_per_tip: u32,

    /// Wall-clock budget (ms) for overflow families after family 1 on a tip
    /// (and for speculative header builds). Family 1 is uncapped; families
    /// 2..N stop when this elapses. Default `40`. `0` ⇒ only family 1.
    /// Ceiling-checked at validate (`≤ 200`).
    #[serde(default = "default_collect_time_budget_ms")]
    pub collect_time_budget_ms: u64,

    /// Re-emit Inv for still-pooled `RentCollector` families every N ms
    /// between tip changes. `0` disables. Default 25000.
    #[serde(default = "default_reannounce_interval_ms")]
    pub reannounce_interval_ms: u64,

    /// ± basis points applied to `parent_fee_per_input_nanoerg` when
    /// `jitter_seed` is also set (e.g. `300` = ±3%). `0` (default) disables
    /// jitter. Ceiling-checked at validate (`≤ 5000`).
    #[serde(default)]
    pub jitter_bps: u32,

    /// Per-node seed for deterministic fee jitter. Jitter is active iff
    /// `jitter_bps > 0` AND this is `Some`. Operator must set a DISTINCT
    /// value per fleet node. Absent seed with `jitter_bps > 0` leaves
    /// jitter inactive (not an error).
    #[serde(default)]
    pub jitter_seed: Option<u64>,

    /// Miner / builder peers that get preferential treatment for
    /// first-occupancy: sticky reserved outbound dials, and RentCollector
    /// Inv fanout ordered so these IPs receive `SendToPeer(Inv)` first
    /// (after [`Self::decisive_peers`]). Empty (default) = historical
    /// HashMap / insertion-order behaviour. Typically curated pool
    /// listening addrs already in `[peers].known`.
    #[serde(default)]
    pub priority_peers: Vec<std::net::SocketAddr>,

    /// Assembler-tier / sticky decider peers (e.g. 2miners
    /// `51.89.64.232:{29030,29031,39030,39031}`). Subset of (or overlap
    /// with) [`Self::priority_peers`]. Used for:
    /// (1) Inv fanout before other priority IPs,
    /// (2) `decisive_ack` metrics — `builder_reach_miss` only when these
    /// ACK count is 0 (public priority ACKs alone must not clear the miss).
    /// Empty = no decisive set (every priority ACK counts as public-only;
    /// `builder_reach_miss` stays true whenever parents are still pooled).
    #[serde(default)]
    pub decisive_peers: Vec<std::net::SocketAddr>,

    /// Optional REST base URLs for assembler-tier delivery of admitted
    /// RentCollector family txs (`POST {url}/transactions/bytes` with a
    /// JSON string of hex — Scala/pool-inject parity). Empty (default) =
    /// P2P Inv only. Unsolicited P2P `Modifiers` are protocol-spam
    /// (`RejectSpam`); REST is the ban-safe push path.
    #[serde(default)]
    pub submit_urls: Vec<String>,
}

impl Default for RentCollectorConfig {
    /// Mirrors the per-field serde defaults so a `Default`-built config (the
    /// missing-section / programmatic path) matches a fully-defaulted
    /// `[mining.rent_collector]` table: off, the `Unbeatable` bound, the 4096
    /// safety cap, a zero profit floor, fleet chunking/re-announce defaults
    /// (`max_families_per_tip=8`, `collect_time_budget_ms=40`), and jitter
    /// off. Kept in sync with the `#[serde(default …)]` attributes above.
    fn default() -> Self {
        Self {
            enabled: false,
            fee_bound: FeeBound::Unbeatable,
            max_claims: default_max_storage_rent_claims(),
            min_profit_nanoerg: 0,
            parent_fee_per_input_nanoerg: default_parent_fee_per_input_nanoerg(),
            max_families_per_tip: default_max_families_per_tip(),
            collect_time_budget_ms: default_collect_time_budget_ms(),
            reannounce_interval_ms: default_reannounce_interval_ms(),
            jitter_bps: 0,
            jitter_seed: None,
            priority_peers: Vec::new(),
            decisive_peers: Vec::new(),
            submit_urls: Vec::new(),
        }
    }
}

/// One operator-configured custom extension field, as hex strings in the
/// `[mining]` TOML (`{ key = "ae00", value = "01…" }`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CustomExtensionField {
    /// 2-byte extension key as hex (4 hex chars), e.g. `"ae00"`.
    pub key: String,
    /// Field value as hex (≤ 64 bytes → ≤ 128 hex chars).
    pub value: String,
}

fn default_candidate_interval_ms() -> u64 {
    1000
}

fn default_use_external_miner() -> bool {
    true
}

fn default_max_storage_rent_claims() -> u32 {
    4096
}

fn default_parent_fee_per_input_nanoerg() -> u64 {
    10_000_000 // 0.01 ERG per input box
}

fn default_max_families_per_tip() -> u32 {
    8
}

fn default_collect_time_budget_ms() -> u64 {
    40
}

fn default_reannounce_interval_ms() -> u64 {
    25_000
}

/// Soft ceiling on `jitter_bps` (±50%). Rejected at validate rather than
/// silently distorting fees.
pub const MAX_JITTER_BPS: u32 = 5000;

/// Soft ceiling on `collect_time_budget_ms` (200ms). Higher values risk
/// stalling the tip-path action loop behind overflow packing.
pub const MAX_COLLECT_TIME_BUDGET_MS: u64 = 200;

impl Default for MiningConfig {
    /// Mirrors the per-field serde defaults so a programmatically- or
    /// CLI-built config (which starts from `Default`, not a deserialized TOML
    /// table) gets the same values a fully-defaulted `[mining]` table would —
    /// notably `use_external_miner = true` and the 1000 ms refresh debounce.
    /// serde's per-field `default = "…"` only applies to a present-but-partial
    /// table; a *missing* `[mining]` section deserializes via `Default`, and
    /// the CLI enable path (`--mining-enabled` with no `[mining]` TOML) builds
    /// from `Default` too — so a derived all-zero `Default` would set
    /// `use_external_miner = false` and fail validation.
    fn default() -> Self {
        Self {
            enabled: false,
            miner_public_key_hex: None,
            block_candidate_generation_interval_ms: default_candidate_interval_ms(),
            use_external_miner: default_use_external_miner(),
            claim_storage_rent: false,
            max_storage_rent_claims: default_max_storage_rent_claims(),
            candidate_base_cache: false,
            extension_fields: Vec::new(),
            rent_collector: RentCollectorConfig::default(),
        }
    }
}

/// Floor for `block_candidate_generation_interval_ms`. Below this, the
/// debounce window churns the bounded template ring faster than miners
/// repoll, so we reject it. This was the prior default — a known-reasonable
/// minimum.
const MIN_CANDIDATE_INTERVAL_MS: u64 = 50;

impl MiningConfig {
    /// Validate the parsed config. Run at startup before the mining
    /// subsystem is spawned so a misconfigured node refuses to start
    /// rather than silently failing later.
    pub fn validate(&self) -> Result<(), MiningError> {
        // Jitter / budget ceilings are independent of enablement — a
        // nonsensical value in the TOML must reject at load rather than
        // wait for enable.
        if self.rent_collector.jitter_bps > MAX_JITTER_BPS {
            return Err(MiningError::InvalidConfig(format!(
                "[mining.rent_collector].jitter_bps must be ≤ {MAX_JITTER_BPS} (got {}); \
                 values above ±50% are rejected rather than silently distorting fees",
                self.rent_collector.jitter_bps,
            )));
        }
        if self.rent_collector.collect_time_budget_ms > MAX_COLLECT_TIME_BUDGET_MS {
            return Err(MiningError::InvalidConfig(format!(
                "[mining.rent_collector].collect_time_budget_ms must be ≤ {MAX_COLLECT_TIME_BUDGET_MS} \
                 (got {}); higher values risk stalling the tip-path action loop",
                self.rent_collector.collect_time_budget_ms,
            )));
        }
        // Nothing to validate when neither the miner nor the rent collector is
        // on — both subsystems are off, so the rest is moot. The collector is
        // DECOUPLED from `[mining].enabled` (it can run with mining off), so a
        // bare `!self.enabled` early-return would skip its checks.
        if !self.enabled && !self.rent_collector.enabled {
            return Ok(());
        }
        // `miner_public_key_hex` is OPTIONAL: when absent, the reward key is
        // resolved from the wallet's EIP-3 first-address key at candidate time
        // (Scala parity — see ergo-mining handle `RewardKeySource::Wallet`).
        // But a value that IS present must be well-formed (66 hex chars → 33
        // bytes), validated early at startup rather than failing later. The
        // rent collector reuses this SAME reward key as its proceeds key, so
        // the check runs whenever either subsystem is enabled.
        if let Some(pk_hex) = self.miner_public_key_hex.as_ref() {
            match hex::decode(pk_hex) {
                Ok(bytes) if bytes.len() == 33 => {}
                Ok(bytes) => {
                    return Err(MiningError::InvalidConfig(format!(
                        "[mining].miner_public_key_hex must be 33 bytes (66 hex chars), got {}",
                        bytes.len()
                    )));
                }
                Err(e) => {
                    return Err(MiningError::InvalidConfig(format!(
                        "[mining].miner_public_key_hex is not valid hex: {e}"
                    )));
                }
            }
        }
        // Rent-collector self-contained checks (the cross-section indexer +
        // resolvable-proceeds-key gate lives at the node config-load level).
        // Reject the unimplemented `observed_competitor` bound so a config
        // can't silently select a fee bound the builder does not implement.
        if self.rent_collector.enabled
            && self.rent_collector.fee_bound == FeeBound::ObservedCompetitor
        {
            return Err(MiningError::InvalidConfig(
                "[mining.rent_collector].fee_bound = \"observed_competitor\" is not yet \
                 implemented; only \"unbeatable\" is supported."
                    .into(),
            ));
        }
        // The remaining checks gate the MINER itself; skip them when only the
        // rent collector is enabled (mining can be off).
        if !self.enabled {
            return Ok(());
        }
        if !self.use_external_miner {
            return Err(MiningError::InvalidConfig(
                "[mining].use_external_miner must be true in v1 (internal CPU miner not yet supported)"
                    .into(),
            ));
        }
        if self.block_candidate_generation_interval_ms < MIN_CANDIDATE_INTERVAL_MS {
            return Err(MiningError::InvalidConfig(format!(
                "[mining].block_candidate_generation_interval_ms must be at least \
                 {MIN_CANDIDATE_INTERVAL_MS} ms (got {}): lower values churn the bounded \
                 template ring faster than miners repoll; default is 1000",
                self.block_candidate_generation_interval_ms,
            )));
        }
        // Custom extension fields: hex-decodable (below) and consensus-legal
        // (rule 404 size, reserved-namespace guard, rule 405 no-duplicates).
        crate::extension_builder::validate_custom_extension_fields(
            &self.resolve_extension_fields()?,
        )?;
        Ok(())
    }

    /// Decode the configured custom extension fields from their hex form into
    /// `(key, value)` byte pairs for [`crate::handle::MiningHandle::with_extension_fields`].
    /// Fails on malformed hex or a key that is not exactly 2 bytes. Deeper
    /// consensus checks (size / namespace / duplicates) are applied by
    /// [`crate::extension_builder::validate_custom_extension_fields`].
    pub fn resolve_extension_fields(&self) -> Result<ResolvedExtensionFields, MiningError> {
        self.extension_fields
            .iter()
            .map(|field| {
                let key_bytes = hex::decode(&field.key).map_err(|e| {
                    MiningError::InvalidConfig(format!(
                        "[mining] extension field key {:?} is not valid hex: {e}",
                        field.key
                    ))
                })?;
                let key: [u8; 2] = key_bytes.as_slice().try_into().map_err(|_| {
                    MiningError::InvalidConfig(format!(
                        "[mining] extension field key {:?} must be exactly 2 bytes (4 hex chars)",
                        field.key
                    ))
                })?;
                let value = hex::decode(&field.value).map_err(|e| {
                    MiningError::InvalidConfig(format!(
                        "[mining] extension field {:?} value is not valid hex: {e}",
                        field.key
                    ))
                })?;
                Ok((key, value))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn validate_passes_when_disabled() {
        let cfg = MiningConfig::default();
        assert!(!cfg.enabled);
        cfg.validate()
            .expect("disabled config validates without pubkey");
    }

    // ----- custom extension fields -----

    #[test]
    fn resolve_extension_fields_decodes_hex_pairs() {
        let cfg = MiningConfig {
            extension_fields: vec![CustomExtensionField {
                key: "ae00".into(),
                value: "01aabb".into(),
            }],
            ..Default::default()
        };
        let resolved = cfg.resolve_extension_fields().expect("valid hex");
        assert_eq!(resolved, vec![([0xAE, 0x00], vec![0x01, 0xaa, 0xbb])]);
    }

    #[test]
    fn validate_rejects_reserved_namespace_and_bad_key_len() {
        // Reserved namespace (0x00 = params).
        let reserved = MiningConfig {
            enabled: true,
            miner_public_key_hex: None,
            extension_fields: vec![CustomExtensionField {
                key: "0001".into(),
                value: "aa".into(),
            }],
            ..Default::default()
        };
        assert!(reserved.validate().is_err());
        // Key not exactly 2 bytes.
        let short_key = MiningConfig {
            extension_fields: vec![CustomExtensionField {
                key: "ae".into(),
                value: "aa".into(),
            }],
            ..Default::default()
        };
        assert!(short_key.resolve_extension_fields().is_err());
    }

    #[test]
    fn validate_passes_when_enabled_with_pubkey() {
        let cfg = MiningConfig {
            enabled: true,
            miner_public_key_hex: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            ),
            block_candidate_generation_interval_ms: 1000,
            use_external_miner: true,
            ..MiningConfig::default()
        };
        cfg.validate().expect("enabled+pubkey validates");
    }

    // ----- error paths -----

    #[test]
    fn validate_passes_when_enabled_without_pubkey() {
        // Pubkey is now optional: absent → wallet-resolved reward key
        // (Scala parity). Enabled-without-pubkey must validate.
        let cfg = MiningConfig {
            enabled: true,
            use_external_miner: true,
            ..MiningConfig::default()
        };
        cfg.validate()
            .expect("enabled without pubkey validates (wallet-resolved)");
        assert!(cfg.miner_public_key_hex.is_none());
    }

    #[test]
    fn validate_rejects_malformed_pubkey_hex() {
        // A configured value must still be well-formed, validated early.
        let bad_hex = MiningConfig {
            enabled: true,
            use_external_miner: true,
            miner_public_key_hex: Some("nothex!!".into()),
            ..MiningConfig::default()
        };
        let err = bad_hex.validate().expect_err("must reject non-hex");
        assert!(
            matches!(err, MiningError::InvalidConfig(ref m) if m.contains("valid hex")),
            "got {err:?}"
        );

        let wrong_len = MiningConfig {
            enabled: true,
            use_external_miner: true,
            miner_public_key_hex: Some("0203".into()), // 2 bytes, not 33
            ..MiningConfig::default()
        };
        let err = wrong_len.validate().expect_err("must reject wrong length");
        assert!(
            matches!(err, MiningError::InvalidConfig(ref m) if m.contains("33 bytes")),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_internal_miner() {
        let cfg = MiningConfig {
            enabled: true,
            // Valid 33-byte pubkey so the hex check passes and the test
            // isolates the use_external_miner rejection.
            miner_public_key_hex: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            ),
            use_external_miner: false,
            block_candidate_generation_interval_ms: 1000,
            ..MiningConfig::default()
        };
        let err = cfg.validate().expect_err("must reject");
        match err {
            MiningError::InvalidConfig(msg) => {
                assert!(msg.contains("use_external_miner"), "{msg}")
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_sub_floor_candidate_interval() {
        // 0 means "rebuild on every candidate-visible mempool mutation",
        // which churns the bounded 8-template ring far faster than miners
        // repoll. The floor rejects it at startup.
        let cfg = MiningConfig {
            enabled: true,
            use_external_miner: true,
            block_candidate_generation_interval_ms: 0,
            ..MiningConfig::default()
        };
        let err = cfg.validate().expect_err("sub-floor interval must reject");
        assert!(
            matches!(
                err,
                MiningError::InvalidConfig(ref m)
                    if m.contains("block_candidate_generation_interval_ms")
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_accepts_candidate_interval_at_floor() {
        // Exactly at the floor is the lowest accepted value.
        let cfg = MiningConfig {
            enabled: true,
            use_external_miner: true,
            block_candidate_generation_interval_ms: MIN_CANDIDATE_INTERVAL_MS,
            ..MiningConfig::default()
        };
        cfg.validate().expect("interval at the floor validates");
    }

    // ----- defaults -----

    #[test]
    fn default_matches_serde_field_defaults() {
        // `Default` must equal a fully-defaulted deserialized table, so the
        // CLI enable path (which starts from `Default`, not a parsed TOML
        // table) gets `use_external_miner = true` and the 1000 ms debounce —
        // not the derived all-zero values that would fail validation.
        let cfg = MiningConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.miner_public_key_hex.is_none());
        assert_eq!(
            cfg.block_candidate_generation_interval_ms,
            default_candidate_interval_ms(),
        );
        assert_eq!(cfg.block_candidate_generation_interval_ms, 1000);
        assert!(cfg.use_external_miner);
        assert_eq!(
            cfg.max_storage_rent_claims,
            default_max_storage_rent_claims()
        );
        // The dry-run base cache is opt-in (multi-GB resident graph).
        assert!(!cfg.candidate_base_cache);
    }

    #[test]
    fn cli_style_enable_on_default_validates() {
        // Mirrors `--mining-enabled` with no `[mining]` TOML section: the load
        // path flips `enabled` on a `Default` config. With `Default` matching
        // the serde field defaults, `use_external_miner` is already `true`, so
        // validation passes (a derived all-zero `Default` would reject it).
        let cfg = MiningConfig {
            enabled: true,
            ..MiningConfig::default()
        };
        assert!(cfg.use_external_miner);
        assert_eq!(cfg.block_candidate_generation_interval_ms, 1000);
        cfg.validate()
            .expect("CLI-enabled default config validates (external miner default true)");
    }

    #[test]
    fn toml_round_trips_with_serde_defaults() {
        let toml_src = r#"
            enabled = true
            miner_public_key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "#;
        let parsed: MiningConfig = toml::from_str(toml_src).expect("parse");
        assert!(parsed.enabled);
        assert_eq!(
            parsed.miner_public_key_hex.as_deref(),
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        );
        assert_eq!(parsed.block_candidate_generation_interval_ms, 1000);
        assert!(parsed.use_external_miner);
        // Storage-rent self-claim is opt-in (off); the cap is a high
        // safety ceiling (the block budget is the real limit).
        assert!(!parsed.claim_storage_rent);
        assert_eq!(parsed.max_storage_rent_claims, 4096);
        // The dry-run base cache is opt-in (off) — a present-but-partial table
        // gets the serde `#[serde(default)]` (false).
        assert!(!parsed.candidate_base_cache);
    }

    #[test]
    fn toml_parses_candidate_base_cache_when_set() {
        // The opt-in path: an explicit `candidate_base_cache = true` parses
        // through, so a mining operator can enable the resident AVL cache.
        let toml_src = r#"
            enabled = true
            candidate_base_cache = true
        "#;
        let parsed: MiningConfig = toml::from_str(toml_src).expect("parse");
        assert!(parsed.candidate_base_cache);
    }

    // ----- rent_collector -----

    #[test]
    fn rent_collector_defaults_are_off_and_unbeatable() {
        // A fully-defaulted MiningConfig (the CLI / missing-section path)
        // gets the rent collector OFF, the only-implemented `Unbeatable`
        // bound, the safety-cap default, a zero profit floor, the
        // 0.01 ERG/input self-sufficient parent fee, fleet chunking +
        // collect budget + re-announce ON, and jitter OFF (needs an
        // explicit per-node seed).
        let cfg = MiningConfig::default();
        let rc = &cfg.rent_collector;
        assert!(!rc.enabled, "rent collector is opt-in (off by default)");
        assert_eq!(rc.fee_bound, FeeBound::Unbeatable);
        assert_eq!(rc.max_claims, default_max_storage_rent_claims());
        assert_eq!(rc.min_profit_nanoerg, 0);
        assert_eq!(rc.parent_fee_per_input_nanoerg, 10_000_000);
        assert_eq!(rc.max_families_per_tip, default_max_families_per_tip());
        assert_eq!(rc.collect_time_budget_ms, default_collect_time_budget_ms());
        assert_eq!(rc.reannounce_interval_ms, default_reannounce_interval_ms());
        assert_eq!(rc.jitter_bps, 0);
        assert_eq!(rc.jitter_seed, None);
        assert!(rc.priority_peers.is_empty());
        assert!(rc.decisive_peers.is_empty());
        assert!(rc.submit_urls.is_empty());
    }

    #[test]
    fn rent_collector_parses_explicit_parent_fee_per_input() {
        // An explicit `parent_fee_per_input_nanoerg` in the table round-trips
        // (not just the serde default), so the operator can tune the
        // self-sufficient parent fee from config.
        let rc: RentCollectorConfig =
            toml::from_str("enabled = true\nparent_fee_per_input_nanoerg = 25000000\n")
                .expect("table with explicit parent fee parses");
        assert!(rc.enabled);
        assert_eq!(rc.parent_fee_per_input_nanoerg, 25_000_000);
        // The other fields still fall back to their defaults.
        assert_eq!(rc.fee_bound, FeeBound::Unbeatable);
        assert_eq!(rc.max_claims, default_max_storage_rent_claims());
    }

    #[test]
    fn rent_collector_default_matches_serde_field_defaults() {
        // A present-but-empty `[mining.rent_collector]` table must
        // deserialize to exactly the same values as `RentCollectorConfig`'s
        // `Default` — the per-field serde defaults and the hand-written
        // `Default` impl must not drift (mirrors `MiningConfig`).
        let from_default = RentCollectorConfig::default();
        let from_empty_table: RentCollectorConfig =
            toml::from_str("").expect("empty table parses via field defaults");
        assert_eq!(from_default, from_empty_table);
    }

    #[test]
    fn rent_collector_self_validation_rejects_observed_competitor_bound() {
        // `ObservedCompetitor` is a documented future stub — the only
        // implemented bound is `Unbeatable`. Selecting the unimplemented
        // bound must be rejected at config-load so it can't silently win.
        let cfg = MiningConfig {
            rent_collector: RentCollectorConfig {
                enabled: true,
                fee_bound: FeeBound::ObservedCompetitor,
                ..RentCollectorConfig::default()
            },
            ..MiningConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("observed_competitor bound must reject");
        assert!(
            matches!(err, MiningError::InvalidConfig(ref m) if m.contains("observed_competitor")),
            "got {err:?}"
        );
    }

    #[test]
    fn rent_collector_self_validation_reuses_pubkey_wellformedness() {
        // The self-contained part of the proceeds-key check: a configured
        // `miner_public_key_hex` that is malformed must still be rejected by
        // `MiningConfig::validate` even when mining itself is disabled but the
        // rent collector is enabled (the collector reuses the reward key).
        let cfg = MiningConfig {
            enabled: false,
            miner_public_key_hex: Some("nothex!!".into()),
            rent_collector: RentCollectorConfig {
                enabled: true,
                ..RentCollectorConfig::default()
            },
            ..MiningConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("malformed pubkey must reject even with mining off");
        assert!(
            matches!(err, MiningError::InvalidConfig(ref m) if m.contains("valid hex")),
            "got {err:?}"
        );
    }

    #[test]
    fn rent_collector_self_validation_passes_with_unbeatable_bound() {
        // Enabling the collector with the implemented bound passes the
        // crate-local self-validation (the cross-section indexer + proceeds-key
        // gate lives at the node level, tested there).
        let cfg = MiningConfig {
            rent_collector: RentCollectorConfig {
                enabled: true,
                fee_bound: FeeBound::Unbeatable,
                ..RentCollectorConfig::default()
            },
            ..MiningConfig::default()
        };
        cfg.validate()
            .expect("enabled collector with unbeatable bound self-validates");
    }

    #[test]
    fn toml_round_trips_rent_collector_including_min_profit() {
        // The full TOML surface: `[mining.rent_collector]` parses end to end,
        // including `min_profit_nanoerg`, and the snake_case `fee_bound`
        // renames round-trip.
        let toml_src = r#"
            enabled = true

            [rent_collector]
            enabled = true
            fee_bound = "unbeatable"
            max_claims = 1024
            min_profit_nanoerg = 5000000
        "#;
        let parsed: MiningConfig = toml::from_str(toml_src).expect("parse");
        let rc = &parsed.rent_collector;
        assert!(rc.enabled);
        assert_eq!(rc.fee_bound, FeeBound::Unbeatable);
        assert_eq!(rc.max_claims, 1024);
        assert_eq!(rc.min_profit_nanoerg, 5_000_000);

        // Re-serialize and re-parse to confirm the round-trip is stable
        // (the snake_case `fee_bound` rename survives a serialize pass).
        let reser = toml::to_string(&parsed).expect("serialize");
        let reparsed: MiningConfig = toml::from_str(&reser).expect("re-parse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn toml_rent_collector_defaults_when_section_absent() {
        // A `[mining]` table with no `[mining.rent_collector]` subsection
        // gets the field-level `#[serde(default)]` — the whole struct's
        // `Default` (off, Unbeatable, cap default, profit 0).
        let toml_src = r#"
            enabled = true
        "#;
        let parsed: MiningConfig = toml::from_str(toml_src).expect("parse");
        assert_eq!(parsed.rent_collector, RentCollectorConfig::default());
    }

    #[test]
    fn fee_bound_serde_renames_to_snake_case() {
        // `observed_competitor` parses to the stub variant (it is then
        // rejected by validation, tested above); the rename is lower
        // snake_case, not the PascalCase Rust identifier.
        #[derive(Deserialize)]
        struct Wrap {
            fee_bound: FeeBound,
        }
        let parsed: Wrap = toml::from_str(r#"fee_bound = "observed_competitor""#).expect("parse");
        assert_eq!(parsed.fee_bound, FeeBound::ObservedCompetitor);
        // PascalCase must NOT parse (rename is in force).
        assert!(toml::from_str::<Wrap>(r#"fee_bound = "Unbeatable""#).is_err());
    }

    #[test]
    fn rent_collector_parses_fleet_knobs() {
        let rc: RentCollectorConfig = toml::from_str(
            "max_families_per_tip = 2\n\
             collect_time_budget_ms = 50\n\
             reannounce_interval_ms = 10000\n\
             jitter_bps = 300\n\
             jitter_seed = 42\n\
             priority_peers = [\"51.89.64.232:29030\", \"94.232.212.33:9030\"]\n\
             decisive_peers = [\"51.89.64.232:29030\", \"51.89.64.232:29031\"]\n\
             submit_urls = [\"http://127.0.0.1:9053\"]\n",
        )
        .expect("fleet knobs parse");
        assert_eq!(rc.max_families_per_tip, 2);
        assert_eq!(rc.collect_time_budget_ms, 50);
        assert_eq!(rc.reannounce_interval_ms, 10_000);
        assert_eq!(rc.jitter_bps, 300);
        assert_eq!(rc.jitter_seed, Some(42));
        assert_eq!(
            rc.priority_peers,
            vec![
                "51.89.64.232:29030".parse().unwrap(),
                "94.232.212.33:9030".parse().unwrap(),
            ]
        );
        assert_eq!(
            rc.decisive_peers,
            vec![
                "51.89.64.232:29030".parse().unwrap(),
                "51.89.64.232:29031".parse().unwrap(),
            ]
        );
        assert_eq!(rc.submit_urls, vec!["http://127.0.0.1:9053".to_string()]);
    }

    #[test]
    fn rent_collector_self_validation_rejects_jitter_bps_above_ceiling() {
        let cfg = MiningConfig {
            rent_collector: RentCollectorConfig {
                jitter_bps: MAX_JITTER_BPS + 1,
                ..RentCollectorConfig::default()
            },
            ..MiningConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("jitter_bps above ceiling must reject");
        assert!(
            matches!(err, MiningError::InvalidConfig(ref m) if m.contains("jitter_bps")),
            "got {err:?}"
        );
    }

    #[test]
    fn rent_collector_self_validation_rejects_collect_time_budget_above_ceiling() {
        let cfg = MiningConfig {
            rent_collector: RentCollectorConfig {
                collect_time_budget_ms: MAX_COLLECT_TIME_BUDGET_MS + 1,
                ..RentCollectorConfig::default()
            },
            ..MiningConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("collect_time_budget_ms above ceiling must reject");
        assert!(
            matches!(err, MiningError::InvalidConfig(ref m) if m.contains("collect_time_budget_ms")),
            "got {err:?}"
        );
    }

    #[test]
    fn rent_collector_self_validation_accepts_jitter_bps_at_ceiling() {
        let cfg = MiningConfig {
            rent_collector: RentCollectorConfig {
                jitter_bps: MAX_JITTER_BPS,
                jitter_seed: Some(1),
                ..RentCollectorConfig::default()
            },
            ..MiningConfig::default()
        };
        cfg.validate().expect("jitter_bps at ceiling is accepted");
    }
}
