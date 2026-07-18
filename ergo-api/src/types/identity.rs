//! Node identity DTOs: static boot identity (`ApiInfo`), the mode /
//! protocol-flags view (`ApiIdentity` and its field enums), and the
//! host-process metrics view (`ApiHost`).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Static node identity. Cheap to compute; doesn't change after boot.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiInfo {
    pub agent_name: String,
    pub node_name: String,
    pub network: String,
    pub version: String,
    pub started_at_unix_ms: u64,
    pub uptime_seconds: u64,
    /// Target block interval for this network, in milliseconds.
    /// Mainnet = 120_000 (2 min). Testnet = 45_000 (45 s). Read from
    /// the chain spec's `DifficultyParams::desired_interval_ms` at
    /// boot so the operator dashboard can label "avg block time"
    /// against the *actual* network's target instead of hardcoding
    /// the mainnet value (which was wrong on testnet).
    #[serde(default = "default_block_interval_ms")]
    pub target_block_interval_ms: u64,
}

fn default_block_interval_ms() -> u64 {
    120_000
}

/// What kind of node this is, beyond the boot-time `ApiInfo` shape.
///
/// Captures the protocol-visible mode flags advertised on the P2P
/// handshake plus operator-config toggles (extra-index, API submission,
/// declared / bind addr). Set at boot from `NodeConfig` + the hardcoded
/// `Mode` peer-feature; doesn't change at runtime today.
///
/// `mining` mirrors the node's mining configuration (whether the
/// `/mining/*` work-serving routes are wired).
///
/// Backs `GET /api/v1/identity`; consumed by the operator dashboard's
/// identity strip. Rust-native — Scala's `/info` has no equivalent.
///
/// Field contract:
/// - `state_type`, `verify_transactions`, `history_mode`, `mining`,
///   `extra_index_enabled`, `declared_addr`, `bind_addr` are
///   config-intent: what `NodeConfig` asked for at boot. Scala parity
///   for the wire-visible fields lives here.
/// - `utxo_bootstrap` and `nipopow_bootstrap` are effective-state:
///   true when either the operator's config flag is set OR a
///   matching provenance marker on disk confirms the bootstrap
///   actually ran. An operator who cleared the bootstrap flag in
///   config after a successful install therefore still sees `true`
///   on the surface that survived the install. Refreshed by the
///   action loop on bootstrap transitions; live for the process
///   lifetime via `Arc<ArcSwap<ApiIdentity>>` in `api_bridge.rs`.
/// - `mode` is a compact human-readable label composed from both
///   classes, including the Mode 4 `"mode-4 · …"` variants.
///
/// To observe actual runtime progress (e.g. current chain height,
/// peer count), read `fullHeight` / `bestFullHeaderId` on adjacent
/// endpoints.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ApiIdentity {
    /// Compact human-readable summary (e.g. "archive · utxo"). Derived
    /// from `state_type` + `history_mode` + `utxo_bootstrap` so the
    /// dashboard hero strip can render a single string.
    pub mode: String,
    /// Wire byte = 0 / 1 in the `Mode` peer-feature; mirrored here as
    /// a typed enum so consumers don't have to guess the string set.
    pub state_type: ApiStateType,
    pub verify_transactions: bool,
    /// How the operator configured chain-history retention. Tagged
    /// union — clients switch on `kind`. See [`ApiHistoryMode`].
    pub history_mode: ApiHistoryMode,
    pub utxo_bootstrap: bool,
    pub nipopow_bootstrap: bool,
    pub mining: bool,
    pub extra_index_enabled: bool,
    /// `[peers] declared_addr` from the TOML config — what we advertise
    /// to peers in the handshake. `None` = anonymous, not gossipable.
    pub declared_addr: Option<String>,
    /// `[peers] bind_addr` — local TCP listen address. `None` =
    /// outbound-only.
    pub bind_addr: Option<String>,
}

/// State-store backend kind, mirroring the protocol-visible `Mode`
/// peer-feature byte (`utxo` = 0, `digest` = 1).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiStateType {
    #[default]
    Utxo,
    Digest,
}

/// Chain-history retention policy as configured at boot. Tagged
/// union; clients switch on `kind`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiHistoryMode {
    /// `blocks_to_keep = -1` and `utxo_bootstrap = false` and not the
    /// canonical Mode 6 combo. Full archive — the most common live
    /// runtime mode and the `Default` variant.
    #[default]
    Archive,
    /// `utxo_bootstrap = true`. Operator opted into the Mode 2 UTXO
    /// snapshot bootstrap path. The `kind` wires regardless of whether
    /// the snapshot has been applied — observe `fullHeight > 0` on
    /// `/info` or `/api/v1/tip` for that.
    UtxoBootstrapped,
    /// Canonical Mode 6 combo: `state_type = Digest`,
    /// `verify_transactions = false`, `blocks_to_keep = 0`. Boots
    /// successfully via the `is_canonical_mode_6` short-circuit in
    /// `validate_runtime_mode_support`.
    HeadersOnly,
    /// `blocks_to_keep = N` for `N >= 1`. Forward-compat with the
    /// Mode 3 eviction roadmap; currently rejected by the runtime
    /// gate.
    Pruned { suffix_len: u32 },
}

/// Host-process metrics: memory, on-disk databases, free space on the
/// data-directory volume. `None` on any field means "could not
/// determine" — sysinfo refresh failure, permissions, missing file,
/// or platform gap. `Some(0)` means a legitimately zero measurement.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ApiHost {
    /// Resident set size of the node process.
    pub rss_bytes: Option<u64>,
    /// Size of `state.redb` on disk.
    pub state_db_bytes: Option<u64>,
    /// Size of `indexer.redb`. `None` when the indexer is disabled or
    /// the file is missing.
    pub index_db_bytes: Option<u64>,
    /// Free bytes on the volume containing the data directory.
    pub disk_free_bytes: Option<u64>,
    /// Total bytes on that volume.
    pub disk_total_bytes: Option<u64>,
    /// CPU usage of the node process as a percent of one core.
    pub cpu_pct: Option<f32>,
    /// Receive bytes-per-second across all interfaces.
    pub net_in_bps: Option<u64>,
    /// Transmit bps.
    pub net_out_bps: Option<u64>,
    /// 1-minute load average.
    pub load_1m: Option<f32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- ApiHistoryMode: happy path -----

    /// Unit variants emit bare `{"kind":"..."}` with no payload.
    /// snake_case rename covers `UtxoBootstrapped` and `HeadersOnly`.
    #[test]
    fn api_history_mode_unit_variants_serialize_kind_only() {
        let cases: &[(ApiHistoryMode, &str)] = &[
            (ApiHistoryMode::Archive, "archive"),
            (ApiHistoryMode::UtxoBootstrapped, "utxo_bootstrapped"),
            (ApiHistoryMode::HeadersOnly, "headers_only"),
        ];
        for (variant, kind) in cases {
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(
                json,
                serde_json::json!({ "kind": kind }),
                "{variant:?} wire shape regression: got {json}",
            );
        }
    }

    /// `Pruned { suffix_len }` carries the retention length on the
    /// same JSON object as the `kind` tag.
    #[test]
    fn api_history_mode_pruned_serializes_kind_and_suffix_len() {
        let variant = ApiHistoryMode::Pruned { suffix_len: 1440 };
        let json = serde_json::to_value(&variant).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "pruned", "suffix_len": 1440 }),
        );
    }

    // ----- ApiHistoryMode: round-trips -----

    #[test]
    fn api_history_mode_roundtrips_all_variants() {
        let cases = [
            ApiHistoryMode::Archive,
            ApiHistoryMode::UtxoBootstrapped,
            ApiHistoryMode::HeadersOnly,
            ApiHistoryMode::Pruned { suffix_len: 1440 },
        ];
        for original in cases {
            let json = serde_json::to_string(&original).unwrap();
            let decoded: ApiHistoryMode = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, original, "roundtrip failed for {original:?}");
        }
    }

    // ----- ApiHistoryMode: Default -----

    /// `ApiIdentity::default()` calls `ApiHistoryMode::default()` via
    /// the derive. The default is `Archive` — the most common live
    /// runtime mode — so absent-config stubs render a plausible wire
    /// shape rather than panicking on an uninhabited variant.
    #[test]
    fn api_history_mode_default_is_archive() {
        assert_eq!(ApiHistoryMode::default(), ApiHistoryMode::Archive);
    }

    // ----- ApiHistoryMode: error paths -----

    /// Unknown `kind` rejects rather than silently coercing.
    #[test]
    fn api_history_mode_unknown_kind_rejects() {
        let bad = serde_json::json!({ "kind": "ephemeral" });
        let result: Result<ApiHistoryMode, _> = serde_json::from_value(bad);
        assert!(
            result.is_err(),
            "unknown kind must reject, got Ok({:?})",
            result.ok(),
        );
    }

    // ----- ApiStateType: wire shape -----

    #[test]
    fn api_state_type_serializes_to_canonical_lowercase() {
        for (variant, expected) in [
            (ApiStateType::Utxo, "utxo"),
            (ApiStateType::Digest, "digest"),
        ] {
            let got = serde_json::to_value(variant).unwrap();
            assert_eq!(got, serde_json::Value::String(expected.into()));
        }
    }

    #[test]
    fn api_state_type_default_is_utxo() {
        assert_eq!(ApiStateType::default(), ApiStateType::Utxo);
    }

    #[test]
    fn api_state_type_roundtrips_and_rejects_unknown() {
        for v in [ApiStateType::Utxo, ApiStateType::Digest] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ApiStateType = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
        let err = serde_json::from_value::<ApiStateType>(serde_json::json!("ledger"));
        assert!(err.is_err(), "unknown state_type variant must reject");
    }
}
