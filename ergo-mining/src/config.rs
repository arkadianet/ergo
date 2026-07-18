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
        if !self.enabled {
            return Ok(());
        }
        // `miner_public_key_hex` is OPTIONAL: when absent, the reward key is
        // resolved from the wallet's EIP-3 first-address key at candidate time
        // (Scala parity — see ergo-mining handle `RewardKeySource::Wallet`).
        // But a value that IS present must be well-formed (66 hex chars → 33
        // bytes), validated early at startup rather than failing later.
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
}
