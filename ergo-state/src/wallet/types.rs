//! Value structs for the wallet redb tables.
//!
//! All structs derive `serde::Serialize/Deserialize` for bincode
//! encoding. Field names use Rust snake_case internally; REST
//! response DTOs (in `ergo-api/src/wallet/types.rs`) convert to
//! Scala camelCase at the boundary.

use serde::{Deserialize, Serialize};

/// Lifecycle stage of a wallet box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoxStatus {
    /// Output to a tracked pubkey that's been confirmed (block
    /// applied). NOT immature.
    Confirmed,
    /// Mining-reward box that hasn't yet hit
    /// `creation_height + reward_maturity`. Cannot be spent.
    Immature { matures_at: u32 },
    /// Tracked-pubkey input was referenced by a later tx; box is
    /// spent. We KEEP the row (don't delete) so transaction
    /// history can still surface it. The "spent" status filters
    /// it out of `/wallet/boxes/unspent`.
    Spent {
        spent_in_tx: [u8; 32],
        spent_at: u32,
    },
}

/// Provenance of a wallet box — how it was classified at apply
/// time. Matches Scala `WalletScanLogic` output classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoxProvenance {
    /// Output to a tracked P2PK pubkey (the common case).
    Owned,
    /// Mining-reward box: matched the mining-reward script shape
    /// AND went to a tracked pubkey.
    MinerReward,
    /// Output to a registered custom scan. Custom scans aren't
    /// currently surfaced, but the discriminant is reserved so the
    /// type doesn't break when they are.
    Custom { scan_id: u32 },
}

/// Wallet-tracked box. Stored in `WALLET_BOXES` keyed by box id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBox {
    /// Box id (32 bytes). Duplicated here for ergonomics — the
    /// table key already has it, but having it in the value
    /// avoids reconstruction.
    pub box_id: [u8; 32],
    /// Tx that created this box.
    pub creation_tx_id: [u8; 32],
    /// Output index within the creation tx.
    pub creation_output_index: u16,
    /// Block height the creation tx was included in.
    pub creation_height: u32,
    /// Box value in nanoERG.
    pub value: u64,
    /// Assets (token id → amount). Treated as opaque 32-byte ids;
    /// token metadata is not surfaced here.
    pub assets: Vec<([u8; 32], u64)>,
    /// Lifecycle stage.
    pub status: BoxStatus,
    /// How this box was classified.
    pub provenance: BoxProvenance,
}

/// Wallet-tracked transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    pub tx_id: [u8; 32],
    pub block_height: u32,
    /// Block id this tx was included in.
    pub block_id: [u8; 32],
    /// Wallet-relevant outputs (subset of tx outputs that went to
    /// tracked pubkeys).
    pub wallet_outputs: Vec<[u8; 32]>,
    /// Wallet-relevant inputs (subset of tx inputs that referenced
    /// previously-tracked boxes).
    pub wallet_inputs: Vec<[u8; 32]>,
}

/// Metadata about a tracked HD pubkey. Stored in
/// `WALLET_TRACKED_PUBKEYS` value bucket. Matches Scala
/// `WalletStorage` per-key metadata shape (spec §7.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedPubkeyMeta {
    /// BIP32 derivation path components (with hardened bits set).
    /// For the auto-derived master: empty. For EIP-3 first child:
    /// `[44|H, 429|H, 0|H, 0, 0]` where `H = 0x8000_0000`.
    pub derivation_path: Vec<u32>,
    /// Operator-supplied label. Empty for auto-derived keys; set
    /// via the `deriveKey` endpoint (currently stubbed).
    pub derivation_path_label: String,
    /// Block height at which this pubkey was first added to the
    /// tracking set. Used by rescan-from-genesis to determine the
    /// scan-start window for this key.
    pub added_at_height: u32,
}

/// Aggregate balance returned by `/wallet/balances`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Balance {
    /// Sum of `Confirmed`-status boxes' values in nanoERG.
    pub confirmed_nano_ergs: u64,
    /// Sum of `Immature`-status boxes' values (mining rewards still
    /// in the maturity window).
    pub immature_nano_ergs: u64,
    /// Token id → total confirmed amount.
    pub tokens: std::collections::BTreeMap<[u8; 32], u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- round-trips -----

    #[test]
    fn wallet_box_round_trip_through_bincode() {
        let original = WalletBox {
            box_id: [0xAA; 32],
            creation_tx_id: [0xBB; 32],
            creation_output_index: 3,
            creation_height: 1000,
            value: 1_000_000_000,
            assets: vec![([0xCC; 32], 42)],
            status: BoxStatus::Immature { matures_at: 1720 },
            provenance: BoxProvenance::MinerReward,
        };
        let bytes = bincode::serialize(&original).expect("serialize");
        let parsed: WalletBox = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(parsed.box_id, original.box_id);
        assert_eq!(parsed.creation_height, original.creation_height);
        assert_eq!(parsed.value, original.value);
        assert_eq!(parsed.assets.len(), 1);
        assert!(matches!(
            parsed.status,
            BoxStatus::Immature { matures_at: 1720 }
        ));
        assert!(matches!(parsed.provenance, BoxProvenance::MinerReward));
    }

    #[test]
    fn balance_default_is_zero() {
        let b = Balance::default();
        assert_eq!(b.confirmed_nano_ergs, 0);
        assert_eq!(b.immature_nano_ergs, 0);
        assert!(b.tokens.is_empty());
    }
}
