//! Scan registry (`/scan/*` subsystem, the registration layer).
//!
//! Mirrors Scala's scan storage (`WalletStorage.addScan/removeScan/allScans`)
//! and model (`org.ergoplatform.nodeView.wallet.scanning.{Scan, ScanRequest}`):
//! a [`ScanRegistry`] holds the registered [`Scan`]s and allocates their ids.
//! This is the pure in-memory semantic core — `ergo-node` loads it from redb at
//! boot and write-throughs each mutation back to redb for durability.
//!
//! ## scanId allocation (Scala parity)
//!
//! Ids 1..=10 are reserved (`MiningScanId = 9`, `PaymentsScanId = 10`); user
//! scans start at **11**. Allocation is `lastUsedScanId + 1`, where
//! `lastUsedScanId` is a persisted counter defaulting to `PaymentsScanId` (10).
//! The counter is **monotonic** — deregistering a scan does NOT decrement it, so
//! ids are never reused (`removeScan` only deletes the scan key).
//!
//! ## Wire shape (Scala `ScanJsonCodecs`)
//!
//! ```json
//! // ScanRequest (register body): scanName + trackingRule required;
//! // walletInteraction defaults to "shared", removeOffchain to true.
//! {"scanName":"…","walletInteraction":"shared","removeOffchain":true,
//!  "trackingRule":{ … }}
//! // Scan (listAll element): the request plus the assigned scanId.
//! {"scanId":11,"scanName":"…","walletInteraction":"shared",
//!  "removeOffchain":true,"trackingRule":{ … }}
//! ```

use std::collections::BTreeMap;

use ergo_ser::ergo_box::ErgoBox;
use serde::{Deserialize, Serialize};

use super::predicate::ScanningPredicate;
use crate::error::WalletError;

/// Reserved scan id for the mining scan (Scala `Constants.MiningScanId`).
pub const MINING_SCAN_ID: u16 = 9;
/// Reserved scan id for the default payments scan
/// (Scala `Constants.PaymentsScanId`). Also the `lastUsedScanId` default, so
/// the first user scan is allocated id `PAYMENTS_SCAN_ID + 1` == 11.
pub const PAYMENTS_SCAN_ID: u16 = 10;

/// Maximum scan name length in UTF-8 bytes (Scala `Scan.MaxScanNameLength`).
/// `ScanRequest.toScan` fails ("Too long scan name") above this, which the
/// register route maps to HTTP 400. Measured in bytes (Rust `String::len`),
/// matching Scala's `getBytes("UTF-8").length`.
pub const MAX_SCAN_NAME_LENGTH: usize = 255;

/// How a scan interacts with wallet-owned boxes (Scala
/// `ScanWalletInteraction`). Serialized lowercase: `off` / `shared` / `forced`.
/// Absent in a [`ScanRequest`] defaults to [`WalletInteraction::Shared`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletInteraction {
    /// The scan ignores wallet-owned boxes entirely.
    Off,
    /// The scan shares boxes with the wallet (the Scala default).
    #[default]
    Shared,
    /// Boxes matched by the scan are forced into the wallet.
    Forced,
}

/// A scan registration request (Scala `ScanRequest`).
///
/// `scan_name` and `tracking_rule` are required; `wallet_interaction` and
/// `remove_offchain` are optional and take their Scala defaults when absent
/// (see [`ScanRequest::into_scan`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Human-readable scan name.
    #[serde(rename = "scanName")]
    pub scan_name: String,
    /// The predicate evaluated against each box.
    #[serde(rename = "trackingRule")]
    pub tracking_rule: ScanningPredicate,
    /// Wallet-interaction mode; `None` -> [`WalletInteraction::Shared`].
    #[serde(rename = "walletInteraction", default)]
    pub wallet_interaction: Option<WalletInteraction>,
    /// Whether off-chain boxes are removed; `None` -> `true`.
    #[serde(rename = "removeOffchain", default)]
    pub remove_offchain: Option<bool>,
}

impl ScanRequest {
    /// Resolve this request into a [`Scan`] with the assigned `scan_id`,
    /// applying Scala's defaults: `walletInteraction.getOrElse(Shared)` and
    /// `removeOffchain.getOrElse(true)`.
    pub fn into_scan(self, scan_id: u16) -> Scan {
        Scan {
            scan_id,
            scan_name: self.scan_name,
            tracking_rule: self.tracking_rule,
            wallet_interaction: self.wallet_interaction.unwrap_or_default(),
            remove_offchain: self.remove_offchain.unwrap_or(true),
        }
    }
}

/// A registered scan (Scala `Scan`): a [`ScanRequest`] plus its assigned id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scan {
    /// Allocated scan id (>= 11 for user scans).
    #[serde(rename = "scanId")]
    pub scan_id: u16,
    /// Human-readable scan name.
    #[serde(rename = "scanName")]
    pub scan_name: String,
    /// The predicate evaluated against each box.
    #[serde(rename = "trackingRule")]
    pub tracking_rule: ScanningPredicate,
    /// Wallet-interaction mode.
    #[serde(rename = "walletInteraction")]
    pub wallet_interaction: WalletInteraction,
    /// Whether off-chain boxes are removed.
    #[serde(rename = "removeOffchain")]
    pub remove_offchain: bool,
}

/// The registered scans plus the monotonic `lastUsedScanId` counter.
///
/// Pure in-memory state; persistence (redb) is layered on top in `ergo-node`,
/// which constructs the registry with [`ScanRegistry::from_persisted`] at boot
/// and mirrors each [`ScanRegistry::register`] / [`ScanRegistry::deregister`]
/// back to disk.
#[derive(Debug, Clone)]
pub struct ScanRegistry {
    scans: BTreeMap<u16, Scan>,
    last_used_scan_id: u16,
}

impl Default for ScanRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanRegistry {
    /// An empty registry with no user scans; the next allocated id is 11.
    pub fn new() -> Self {
        Self {
            scans: BTreeMap::new(),
            last_used_scan_id: PAYMENTS_SCAN_ID,
        }
    }

    /// Reconstruct from persisted state: the stored scans and the persisted
    /// `lastUsedScanId`. The counter is floored at [`PAYMENTS_SCAN_ID`] AND at
    /// the largest existing scan id — mirroring Scala `WalletStorage`, whose
    /// `lastUsedScanId` falls back to the largest scan key when the counter is
    /// absent. This guarantees the next allocation can never collide with a live
    /// scan even if the counter row is lost/under-set.
    pub fn from_persisted(scans: impl IntoIterator<Item = Scan>, last_used_scan_id: u16) -> Self {
        let scans: BTreeMap<u16, Scan> = scans.into_iter().map(|s| (s.scan_id, s)).collect();
        let highest_existing = scans.keys().next_back().copied().unwrap_or(0);
        Self {
            last_used_scan_id: last_used_scan_id
                .max(PAYMENTS_SCAN_ID)
                .max(highest_existing),
            scans,
        }
    }

    /// The persisted monotonic counter — the id of the most recently allocated
    /// scan (or [`PAYMENTS_SCAN_ID`] if none allocated yet). Callers persist
    /// this alongside the scans.
    pub fn last_used_scan_id(&self) -> u16 {
        self.last_used_scan_id
    }

    /// Register a scan, allocating `lastUsedScanId + 1` (Scala `addScan`). The
    /// counter advances monotonically. Returns the stored [`Scan`], or
    /// [`WalletError::ScanRegistryFull`] if the counter has reached `u16::MAX`
    /// (unreachable in practice, but guarded so it can never wrap to a
    /// reserved/zero id and overwrite a live scan).
    pub fn register(&mut self, request: ScanRequest) -> Result<Scan, WalletError> {
        let scan_id = self
            .last_used_scan_id
            .checked_add(1)
            .ok_or(WalletError::ScanRegistryFull)?;
        self.last_used_scan_id = scan_id;
        let scan = request.into_scan(scan_id);
        self.scans.insert(scan_id, scan.clone());
        Ok(scan)
    }

    /// Deregister a scan by id (Scala `removeScan`). NOT idempotent: a missing
    /// id is [`WalletError::ScanNotFound`]. The counter is NOT decremented, so
    /// the id is never reused.
    pub fn deregister(&mut self, scan_id: u16) -> Result<(), WalletError> {
        match self.scans.remove(&scan_id) {
            Some(_) => Ok(()),
            None => Err(WalletError::ScanNotFound(scan_id)),
        }
    }

    /// Look up a registered scan by id.
    pub fn get(&self, scan_id: u16) -> Option<&Scan> {
        self.scans.get(&scan_id)
    }

    /// All registered scans, ascending by id (Scala `allScans`).
    pub fn list(&self) -> Vec<Scan> {
        self.scans.values().cloned().collect()
    }

    /// The ids of all registered scans whose tracking rule matches `b`,
    /// ascending by id. The block-apply matcher calls this on each new output
    /// box to record which scans track it.
    pub fn matching_scan_ids(&self, b: &ErgoBox) -> Vec<u16> {
        self.scans
            .values()
            .filter(|s| s.tracking_rule.matches(b))
            .map(|s| s.scan_id)
            .collect()
    }

    /// Number of registered scans.
    pub fn len(&self) -> usize {
        self.scans.len()
    }

    /// Whether no scans are registered.
    pub fn is_empty(&self) -> bool {
        self.scans.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::token::{Token, TokenId};

    fn req(name: &str) -> ScanRequest {
        ScanRequest {
            scan_name: name.to_string(),
            tracking_rule: ScanningPredicate::ContainsAsset {
                asset_id: [0x11; 32],
            },
            wallet_interaction: None,
            remove_offchain: None,
        }
    }

    /// A `containsAsset` request for the given fill-byte asset id.
    fn req_asset(name: &str, fill: u8) -> ScanRequest {
        ScanRequest {
            scan_name: name.to_string(),
            tracking_rule: ScanningPredicate::ContainsAsset {
                asset_id: [fill; 32],
            },
            wallet_interaction: None,
            remove_offchain: None,
        }
    }

    /// An `ErgoBox` carrying a single token with the given fill-byte id.
    fn box_with_token(fill: u8) -> ErgoBox {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        };
        let tokens = vec![Token {
            token_id: TokenId::from_bytes([fill; 32]),
            amount: 1,
        }];
        let cand = ErgoBoxCandidate::new(1_000_000, tree, 1, tokens, AdditionalRegisters::empty())
            .unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([7u8; 32]),
            index: 0,
        }
    }

    #[test]
    fn matching_scan_ids_returns_matching_scans_ascending() {
        let mut reg = ScanRegistry::new();
        reg.register(req_asset("a", 0x11)).unwrap(); // 11
        reg.register(req_asset("b", 0x22)).unwrap(); // 12
        reg.register(req_asset("c", 0x11)).unwrap(); // 13 (also asset 0x11)

        assert_eq!(
            reg.matching_scan_ids(&box_with_token(0x11)),
            vec![11, 13],
            "ascending ids of every scan whose rule matches"
        );
        assert!(
            reg.matching_scan_ids(&box_with_token(0x99)).is_empty(),
            "a box matching no scan returns nothing"
        );
    }

    // ----- allocation (Scala parity) -----

    #[test]
    fn first_user_scan_is_id_11() {
        let mut reg = ScanRegistry::new();
        let scan = reg.register(req("a")).unwrap();
        assert_eq!(scan.scan_id, 11, "first user scan id is PaymentsScanId + 1");
        assert_eq!(reg.last_used_scan_id(), 11);
    }

    #[test]
    fn ids_are_monotonic_and_never_reused_after_deregister() {
        let mut reg = ScanRegistry::new();
        let a = reg.register(req("a")).unwrap(); // 11
        let b = reg.register(req("b")).unwrap(); // 12
        assert_eq!((a.scan_id, b.scan_id), (11, 12));

        // Deregister 11; the counter does NOT roll back.
        reg.deregister(11).unwrap();
        assert_eq!(reg.last_used_scan_id(), 12, "counter is not decremented");

        let c = reg.register(req("c")).unwrap();
        assert_eq!(c.scan_id, 13, "next id continues past the removed one");
        assert!(reg.get(11).is_none(), "deregistered id stays gone");
    }

    #[test]
    fn deregister_missing_is_not_found_not_idempotent() {
        let mut reg = ScanRegistry::new();
        let err = reg.deregister(11).unwrap_err();
        assert!(matches!(err, WalletError::ScanNotFound(11)));
        // And after registering then removing, a second remove also fails.
        reg.register(req("a")).unwrap();
        reg.deregister(11).unwrap();
        assert!(matches!(
            reg.deregister(11).unwrap_err(),
            WalletError::ScanNotFound(11)
        ));
    }

    #[test]
    fn list_returns_scans_ascending_by_id() {
        let mut reg = ScanRegistry::new();
        reg.register(req("a")).unwrap();
        reg.register(req("b")).unwrap();
        reg.register(req("c")).unwrap();
        let ids: Vec<u16> = reg.list().iter().map(|s| s.scan_id).collect();
        assert_eq!(ids, vec![11, 12, 13]);
    }

    #[test]
    fn from_persisted_restores_scans_and_counter() {
        let mut seed = ScanRegistry::new();
        seed.register(req("a")).unwrap(); // 11
        seed.register(req("b")).unwrap(); // 12
        let persisted = seed.list();
        let last = seed.last_used_scan_id();

        let reg = ScanRegistry::from_persisted(persisted.clone(), last);
        assert_eq!(reg.list(), persisted);
        assert_eq!(reg.last_used_scan_id(), 12);

        // A registry rebuilt from a fresh node (no persisted counter) still
        // allocates from 11.
        let mut empty = ScanRegistry::from_persisted(Vec::new(), 0);
        assert_eq!(empty.register(req("x")).unwrap().scan_id, 11);
    }

    #[test]
    fn from_persisted_floors_counter_at_highest_scan_id() {
        // A lost/under-set counter must never re-allocate a live id: with scans
        // 11 and 12 present but a counter of 0, the floor lifts it to 12, so the
        // next allocation is 13 — not a collision with scan 11.
        let scans = {
            let mut seed = ScanRegistry::new();
            seed.register(req("a")).unwrap();
            seed.register(req("b")).unwrap();
            seed.list()
        };
        let mut reg = ScanRegistry::from_persisted(scans, 0);
        assert_eq!(
            reg.last_used_scan_id(),
            12,
            "counter floored at the highest existing scan id"
        );
        assert_eq!(reg.register(req("c")).unwrap().scan_id, 13);
    }

    #[test]
    fn register_at_u16_max_is_registry_full_not_overflow() {
        // The counter never decrements, so it could in principle reach u16::MAX.
        // Allocation there must error, not panic / wrap to a reserved id.
        let mut reg = ScanRegistry::from_persisted(Vec::new(), u16::MAX);
        assert!(matches!(
            reg.register(req("a")).unwrap_err(),
            WalletError::ScanRegistryFull
        ));
        assert_eq!(
            reg.last_used_scan_id(),
            u16::MAX,
            "counter unchanged on error"
        );
    }

    // ----- request defaults (Scala parity) -----

    #[test]
    fn into_scan_applies_scala_defaults() {
        let scan = req("a").into_scan(11);
        assert_eq!(scan.wallet_interaction, WalletInteraction::Shared);
        assert!(scan.remove_offchain, "removeOffchain defaults to true");
    }

    #[test]
    fn into_scan_keeps_explicit_values() {
        let r = ScanRequest {
            wallet_interaction: Some(WalletInteraction::Forced),
            remove_offchain: Some(false),
            ..req("a")
        };
        let scan = r.into_scan(11);
        assert_eq!(scan.wallet_interaction, WalletInteraction::Forced);
        assert!(!scan.remove_offchain);
    }

    // ----- JSON wire parity -----

    #[test]
    fn scan_request_decodes_with_defaults_absent() {
        let json = r#"{"scanName":"Assets","trackingRule":{"predicate":"containsAsset","assetId":"1111111111111111111111111111111111111111111111111111111111111111"}}"#;
        let r: ScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(r.scan_name, "Assets");
        assert_eq!(r.wallet_interaction, None);
        assert_eq!(r.remove_offchain, None);
        // Defaults resolve at into_scan time.
        let scan = r.into_scan(11);
        assert_eq!(scan.wallet_interaction, WalletInteraction::Shared);
        assert!(scan.remove_offchain);
    }

    #[test]
    fn wallet_interaction_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&WalletInteraction::Shared).unwrap(),
            r#""shared""#
        );
        assert_eq!(
            serde_json::from_str::<WalletInteraction>(r#""forced""#).unwrap(),
            WalletInteraction::Forced
        );
    }

    #[test]
    fn scan_round_trips_with_assigned_id() {
        let scan = req("a").into_scan(11);
        let json = serde_json::to_string(&scan).unwrap();
        assert!(json.contains(r#""scanId":11"#));
        assert!(json.contains(r#""walletInteraction":"shared""#));
        let back: Scan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, scan);
    }
}
