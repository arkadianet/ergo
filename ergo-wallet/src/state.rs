//! In-memory wallet state.
//!
//! Holds cached pubkeys (survives lock per WalletVars.scala:32-37,63),
//! tracked P2PK ErgoTrees for the apply-hook scan, visible addresses
//! cache (filtered per WalletCache.publicKeyAddresses), persisted
//! change address, the use_pre_1627 flag (from the secret file), and
//! a stateless `unlocked` bool that tracks whether the operator has
//! successfully unlocked (the actual key lives in SecretStorage).
//!
//! Boot rehydration order: read WALLET_TRACKED_PUBKEYS in
//! derivation_path_index ASC order (the table is BTree-ordered), then
//! rebuild tracked_p2pk_trees + visible_addresses; read
//! WALLET_CHANGE_ADDRESS; read use_pre_1627 from the cached secret
//! file. After rehydration, the wallet is in Locked state regardless
//! of how it shut down — operator must Unlock to populate the prover.

pub use ergo_state::wallet::hydration::HydrationSource;

use crate::storage::UnlockedSecret;
use std::collections::{BTreeMap, BTreeSet};

/// Public-key visibility for tracked entries ordered by derivation index.
/// Scala WalletCache hides the first master only when the following key has
/// the EIP-3 account prefix. The number of later keys does not affect that rule.
pub fn visible_pubkeys_with_paths(tracked: &[(u64, [u8; 33], Vec<u32>)]) -> Vec<[u8; 33]> {
    let eip3_prefix = [44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000];
    let hide_master =
        tracked.len() > 1 && tracked[0].2.is_empty() && tracked[1].2.starts_with(&eip3_prefix);
    tracked
        .iter()
        .skip(usize::from(hide_master))
        .map(|(_, pk, _)| *pk)
        .collect()
}

/// `WalletState`. Fields are public-within-crate so the apply hook (in
/// `ergo-state`) can read them through a reader trait; public API for
/// outside-crate access goes through the `WalletReader` abstraction in
/// `ergo-state/src/wallet/reader.rs`.
pub struct WalletState {
    /// Tracked HD pubkeys, ordered by their derivation-path index
    /// (mirrors the persisted `WALLET_TRACKED_PUBKEYS` table).
    /// Survives lock — locking only drops the prover, not the cache.
    pub(crate) cached_pubkeys: BTreeMap<u64, [u8; 33]>,

    /// Canonical P2PK ErgoTree bytes for each tracked pubkey. The
    /// apply hook iterates this set membership-checking each output's
    /// ErgoTree bytes; using `BTreeSet<Vec<u8>>` for O(log n) lookup.
    /// Rebuilt from `cached_pubkeys` on every modification.
    pub(crate) tracked_p2pk_trees: BTreeSet<Vec<u8>>,

    /// Public addresses from the persisted visibility table. Low-level
    /// insert/remove calls lack derivation paths and expose all tracked keys;
    /// production writers persist the path-based WalletCache filter and hydrate
    /// from that complete snapshot.
    pub(crate) visible_addresses: Vec<String>,

    /// Persisted change address (None if never set; defaults to
    /// `""` empty string in the REST `/status` response per Scala
    /// parity).
    pub(crate) persisted_change_address: Option<String>,

    /// Whether this wallet uses pre-1627 derivation (set from the
    /// secret-file metadata at boot).
    pub(crate) use_pre_1627: bool,

    /// Stateless unlock flag. Set to `true` by `WalletBootService::unlock_and_sync`
    /// on success; set to `false` on `lock()` or on failed-unlock rollback.
    /// The actual key bytes live in `SecretStorage::unlocked`; this field
    /// just tracks whether the operator has authenticated.
    pub(crate) unlocked: bool,

    /// The unlocked master key + use_pre_1627 flag. Set on unlock,
    /// cleared on lock. The Zeroizing wrapper inside UnlockedSecret
    /// ensures the secret bytes are zeroed when dropped.
    pub(crate) prover: Option<UnlockedSecret>,
}

impl std::fmt::Debug for WalletState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletState")
            .field("cached_pubkeys.len", &self.cached_pubkeys.len())
            .field("tracked_p2pk_trees.len", &self.tracked_p2pk_trees.len())
            .field("visible_addresses.len", &self.visible_addresses.len())
            .field("persisted_change_address", &self.persisted_change_address)
            .field("use_pre_1627", &self.use_pre_1627)
            .field("unlocked", &self.unlocked)
            .field("prover", &self.prover.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl WalletState {
    /// Empty state. Used for a freshly-booted wallet before
    /// hydration from redb. After hydration, fields are populated
    /// from `WALLET_TRACKED_PUBKEYS` etc.
    pub fn empty(use_pre_1627: bool) -> Self {
        Self {
            cached_pubkeys: BTreeMap::new(),
            tracked_p2pk_trees: BTreeSet::new(),
            visible_addresses: Vec::new(),
            persisted_change_address: None,
            use_pre_1627,
            unlocked: false,
            prover: None,
        }
    }

    /// True iff the operator has successfully unlocked the wallet.
    /// The actual key bytes live in `SecretStorage`; this flag reflects
    /// the result of the last `unlock_and_sync` call.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// Set the unlock flag. Called by `WalletBootService::unlock_and_sync`
    /// on success (`true`) and by the lock dispatch or failed-unlock
    /// rollback (`false`).
    pub fn set_unlocked(&mut self, unlocked: bool) {
        self.unlocked = unlocked;
    }

    /// Read-only access to cached pubkeys in derivation-path-index
    /// order.
    pub fn cached_pubkeys(&self) -> &BTreeMap<u64, [u8; 33]> {
        &self.cached_pubkeys
    }

    /// Read-only access to the filtered visible-address list.
    pub fn visible_addresses(&self) -> &[String] {
        &self.visible_addresses
    }

    /// Read-only access to the persisted change address.
    pub fn change_address(&self) -> Option<&str> {
        self.persisted_change_address.as_deref()
    }

    /// True iff the apply hook should classify a given P2PK ErgoTree
    /// as "owned by this wallet" — the apply hook uses this on every
    /// output box.
    pub fn is_tracked_tree(&self, ergo_tree_bytes: &[u8]) -> bool {
        self.tracked_p2pk_trees.contains(ergo_tree_bytes)
    }

    /// Read-only access to the set of canonical P2PK ErgoTree bytes
    /// for all tracked pubkeys. Used by the rescan dispatch to snapshot
    /// the set before spawning the rebuild task.
    pub fn tracked_p2pk_trees(&self) -> &BTreeSet<Vec<u8>> {
        &self.tracked_p2pk_trees
    }

    /// Set the persisted change address (rendered base58 string).
    /// Called after the WALLET_CHANGE_ADDRESS row has been committed.
    pub fn set_change_address(&mut self, address: String) {
        self.persisted_change_address = Some(address);
    }

    /// Update the use_pre_1627 flag. Called by WalletBootService before
    /// unlock so the in-memory state matches the secret file's metadata.
    pub fn set_use_pre_1627(&mut self, use_pre_1627: bool) {
        self.use_pre_1627 = use_pre_1627;
    }

    /// Replace the in-memory prover. Called by WalletBootService during
    /// rollback of a failed unlock (e.g., change-address validation fail).
    pub fn set_prover(&mut self, prover: Option<UnlockedSecret>) {
        self.prover = prover;
    }

    /// Insert a tracked HD pubkey at the given derivation-path index.
    /// This low-level method has no derivation path metadata and exposes every
    /// tracked key. Production HD writers use persisted path-based visibility.
    /// Rebuilds `tracked_p2pk_trees` and `visible_addresses`
    /// atomically. Returns error if the pubkey's P2PK encoding fails
    /// (which means the pubkey isn't a valid SEC1 compressed point —
    /// should have been caught upstream by `k256::PublicKey::from_sec1_bytes`).
    pub fn insert_tracked_pubkey(
        &mut self,
        derivation_path_index: u64,
        pubkey: [u8; 33],
        network: ergo_ser::address::NetworkPrefix,
    ) -> Result<(), crate::error::WalletError> {
        let mut pubkeys = self.cached_pubkeys.clone();
        pubkeys.insert(derivation_path_index, pubkey);
        self.replace_cached_pubkeys(pubkeys, network)
    }

    /// Remove a tracked pubkey by index, preserving trees referenced by another
    /// index. All derived caches are replaced only after validation succeeds.
    pub fn remove_tracked_pubkey(
        &mut self,
        derivation_path_index: u64,
        network: ergo_ser::address::NetworkPrefix,
    ) -> Result<(), crate::error::WalletError> {
        if !self.cached_pubkeys.contains_key(&derivation_path_index) {
            return Ok(());
        }
        let mut pubkeys = self.cached_pubkeys.clone();
        pubkeys.remove(&derivation_path_index);
        self.replace_cached_pubkeys(pubkeys, network)
    }

    fn replace_cached_pubkeys(
        &mut self,
        pubkeys: BTreeMap<u64, [u8; 33]>,
        network: ergo_ser::address::NetworkPrefix,
    ) -> Result<(), crate::error::WalletError> {
        let mut trees = BTreeSet::new();
        let mut visible = Vec::new();
        for pubkey in pubkeys.values() {
            let tree = ergo_ser::address::build_p2pk_tree_bytes(pubkey).map_err(|e| {
                crate::error::WalletError::InvalidPublicKey(format!("p2pk tree build: {e:?}"))
            })?;
            trees.insert(tree);
            // Validate every key, including keys hidden from the public list.
            let address = crate::address::pubkey_to_p2pk_address(pubkey, network)?;
            visible.push(address);
        }
        self.cached_pubkeys = pubkeys;
        self.tracked_p2pk_trees = trees;
        self.visible_addresses = visible;
        Ok(())
    }

    /// Boot-time rehydration: rebuild in-memory caches from the
    /// persistence layer. This replaces cache fields only; the caller owns
    /// the unlock/prover lifecycle.
    ///
    /// Atomicity: the caller wraps this in a single redb read
    /// transaction so the snapshot is consistent. Read or encoding failures
    /// leave the previous caches and change address unchanged.
    pub fn hydrate_from_reader<R: HydrationSource>(
        &mut self,
        reader: &R,
        network: ergo_ser::address::NetworkPrefix,
    ) -> Result<(), crate::error::WalletError> {
        let mut pubkeys = BTreeMap::new();
        let mut trees = BTreeSet::new();
        let mut visible = Vec::new();
        let read_error =
            |error| crate::error::WalletError::SecretFile(format!("wallet hydration: {error}"));
        for (path_idx, pubkey) in reader.tracked_pubkeys().map_err(read_error)? {
            let tree = ergo_ser::address::build_p2pk_tree_bytes(&pubkey).map_err(|e| {
                crate::error::WalletError::InvalidPublicKey(format!("p2pk hydration: {e:?}"))
            })?;
            // The tree builder accepts compressed bytes; address encoding
            // validates their SEC1 point even when this key is not visible.
            crate::address::pubkey_to_p2pk_address(&pubkey, network)?;
            if pubkeys.insert(path_idx, pubkey).is_some() {
                return Err(crate::error::WalletError::SecretFile(
                    "duplicate tracked key index during hydration".into(),
                ));
            }
            trees.insert(tree);
        }
        for (_, pubkey) in reader.visible_pubkeys().map_err(read_error)? {
            visible.push(crate::address::pubkey_to_p2pk_address(&pubkey, network)?);
        }
        let change = reader
            .change_address_pubkey()
            .map_err(read_error)?
            .map(|pk| crate::address::pubkey_to_p2pk_address(&pk, network))
            .transpose()?;
        self.cached_pubkeys = pubkeys;
        self.tracked_p2pk_trees = trees;
        self.visible_addresses = visible;
        self.persisted_change_address = change;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn empty_state_has_no_cached_pubkeys() {
        let s = WalletState::empty(false);
        assert!(s.cached_pubkeys().is_empty());
        assert!(s.visible_addresses().is_empty());
        assert!(s.change_address().is_none());
        assert!(!s.is_unlocked());
        assert!(!s.use_pre_1627);
    }

    #[test]
    fn empty_state_with_pre_1627_carries_flag() {
        let s = WalletState::empty(true);
        assert!(s.use_pre_1627);
    }

    #[test]
    fn untracked_tree_not_contained() {
        let s = WalletState::empty(false);
        assert!(!s.is_tracked_tree(&[0x10, 0x00, 0x00]));
    }

    #[test]
    fn insert_tracked_pubkey_updates_all_caches() {
        let mut s = WalletState::empty(false);
        // BIP32 Vector 1 master pubkey — known-valid compressed SEC1.
        let pk: [u8; 33] =
            hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                .unwrap()
                .try_into()
                .unwrap();
        s.insert_tracked_pubkey(0, pk, ergo_ser::address::NetworkPrefix::Mainnet)
            .expect("insert must succeed for valid pubkey");

        assert_eq!(s.cached_pubkeys().len(), 1);
        assert_eq!(s.tracked_p2pk_trees.len(), 1);
        assert_eq!(s.visible_addresses().len(), 1);
        assert!(s.visible_addresses()[0].starts_with('9'));
    }

    #[test]
    fn replacement_removal_and_rejected_insert_keep_caches_coherent() {
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        let first: [u8; 33] =
            hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                .unwrap()
                .try_into()
                .unwrap();
        let second: [u8; 33] =
            hex::decode("02387003b02747904c5aec88f2de54872c60fca0880661f3449727314b10267338")
                .unwrap()
                .try_into()
                .unwrap();
        let first_tree = ergo_ser::address::build_p2pk_tree_bytes(&first).unwrap();
        let second_tree = ergo_ser::address::build_p2pk_tree_bytes(&second).unwrap();
        let mut state = WalletState::empty(false);
        state.insert_tracked_pubkey(0, first, network).unwrap();
        let before = format!("{state:?}");
        let addresses = state.visible_addresses().to_vec();
        assert!(state.insert_tracked_pubkey(0, [0; 33], network).is_err());
        assert_eq!(format!("{state:?}"), before);
        assert_eq!(state.cached_pubkeys(), &BTreeMap::from([(0, first)]));
        assert_eq!(state.visible_addresses(), addresses);
        assert!(state.is_tracked_tree(&first_tree));

        state.insert_tracked_pubkey(0, second, network).unwrap();
        assert!(!state.is_tracked_tree(&first_tree));
        assert!(state.is_tracked_tree(&second_tree));
        state.insert_tracked_pubkey(1, second, network).unwrap();
        state.remove_tracked_pubkey(0, network).unwrap();
        assert!(state.is_tracked_tree(&second_tree));
        assert_eq!(state.cached_pubkeys(), &BTreeMap::from([(1, second)]));
    }

    #[test]
    fn hydration_read_and_encoding_failures_preserve_the_previous_snapshot() {
        let pk: [u8; 33] =
            hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                .unwrap()
                .try_into()
                .unwrap();
        struct Failing {
            stage: u8,
            pk: [u8; 33],
        }
        impl HydrationSource for Failing {
            fn tracked_pubkeys(&self) -> Result<Vec<(u64, [u8; 33])>, String> {
                if self.stage == 0 {
                    Err("tracked read failed".into())
                } else {
                    Ok(vec![(1, self.pk)])
                }
            }
            fn visible_pubkeys(&self) -> Result<Vec<(u32, [u8; 33])>, String> {
                if self.stage == 1 {
                    Err("visible read failed".into())
                } else {
                    Ok(vec![(0, if self.stage == 3 { [0; 33] } else { self.pk })])
                }
            }
            fn change_address_pubkey(&self) -> Result<Option<[u8; 33]>, String> {
                if self.stage == 2 {
                    Err("change read failed".into())
                } else {
                    Ok(Some(if self.stage == 4 { [0; 33] } else { self.pk }))
                }
            }
        }
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        let mut state = WalletState::empty(true);
        state.insert_tracked_pubkey(0, pk, network).unwrap();
        state.set_change_address(crate::address::pubkey_to_p2pk_address(&pk, network).unwrap());
        state.set_unlocked(true);
        let before = format!("{state:?}");
        let pubkeys = state.cached_pubkeys().clone();
        let trees = state.tracked_p2pk_trees().clone();
        let addresses = state.visible_addresses().to_vec();
        for stage in 0..5 {
            assert!(state
                .hydrate_from_reader(&Failing { stage, pk }, network)
                .is_err());
            assert_eq!(format!("{state:?}"), before);
            assert_eq!(state.cached_pubkeys(), &pubkeys);
            assert_eq!(state.tracked_p2pk_trees(), &trees);
            assert_eq!(state.visible_addresses(), addresses);
        }
    }

    #[test]
    fn raw_insert_does_not_infer_hd_paths_from_key_count() {
        let mut s = WalletState::empty(false);
        let master_pk: [u8; 33] =
            hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                .unwrap()
                .try_into()
                .unwrap();
        // Use a known-valid second pubkey (BIP32 child vector).
        // The test only cares about the visibility filter; specific
        // bytes don't matter as long as the point is valid.
        let child_pk: [u8; 33] =
            hex::decode("02387003b02747904c5aec88f2de54872c60fca0880661f3449727314b10267338")
                .unwrap()
                .try_into()
                .unwrap();
        s.insert_tracked_pubkey(0, master_pk, ergo_ser::address::NetworkPrefix::Mainnet)
            .unwrap();
        s.insert_tracked_pubkey(1, child_pk, ergo_ser::address::NetworkPrefix::Mainnet)
            .unwrap();

        assert_eq!(s.cached_pubkeys().len(), 2);
        assert_eq!(
            s.visible_addresses().len(),
            2,
            "raw inserts have no path metadata for hiding a master",
        );
    }

    #[test]
    fn path_based_visibility_retains_the_wallet_cache_shape_rule() {
        let master = (10, [1; 33], vec![]);
        let pre_eip3 = (11, [2; 33], vec![1]);
        let eip3 = (
            11,
            [2; 33],
            vec![44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0],
        );
        let later = (12, [3; 33], vec![2]);
        assert_eq!(visible_pubkeys_with_paths(&[master.clone()]), vec![[1; 33]]);
        assert_eq!(
            visible_pubkeys_with_paths(&[master.clone(), pre_eip3.clone()]),
            vec![[1; 33], [2; 33]]
        );
        assert_eq!(
            visible_pubkeys_with_paths(&[master.clone(), eip3.clone(), later]),
            vec![[2; 33], [3; 33]]
        );
        assert_eq!(
            visible_pubkeys_with_paths(&[pre_eip3, eip3.clone()]),
            vec![[2; 33], [2; 33]]
        );
        // SDK DerivationPath.isEip3 accepts the account prefix itself.
        let account = (11, [2; 33], eip3.2[..3].to_vec());
        assert_eq!(
            visible_pubkeys_with_paths(&[master, account]),
            vec![[2; 33]]
        );
    }

    #[test]
    fn hydrate_from_reader_rebuilds_caches_in_order() {
        let pks = [
            (
                0u64,
                hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                    .unwrap(),
            ),
            (
                1u64,
                hex::decode("02387003b02747904c5aec88f2de54872c60fca0880661f3449727314b10267338")
                    .unwrap(),
            ),
        ];

        struct Mock {
            pks: Vec<(u64, [u8; 33])>,
            visible: Vec<(u32, [u8; 33])>,
            change_pk: Option<[u8; 33]>,
        }
        impl HydrationSource for Mock {
            fn tracked_pubkeys(&self) -> Result<Vec<(u64, [u8; 33])>, String> {
                Ok(self.pks.clone())
            }
            fn visible_pubkeys(&self) -> Result<Vec<(u32, [u8; 33])>, String> {
                Ok(self.visible.clone())
            }
            fn change_address_pubkey(&self) -> Result<Option<[u8; 33]>, String> {
                Ok(self.change_pk)
            }
        }
        let pk1: [u8; 33] = pks[1].1.clone().try_into().unwrap();
        let mock = Mock {
            pks: pks
                .iter()
                .map(|(i, pk)| (*i, pk.clone().try_into().unwrap()))
                .collect(),
            visible: vec![(0u32, pk1)],
            change_pk: Some(pk1),
        };

        let mut s = WalletState::empty(false);
        s.hydrate_from_reader(&mock, ergo_ser::address::NetworkPrefix::Mainnet)
            .unwrap();
        assert_eq!(s.cached_pubkeys().len(), 2);
        // visible_addresses now rendered from the persisted pubkey
        // bytes at hydration time (not from the heuristic filter).
        // Mock provides 1 visible pubkey.
        assert_eq!(s.visible_addresses().len(), 1);
        assert!(s.visible_addresses()[0].starts_with('9'));
        assert!(s
            .change_address()
            .map(|a| a.starts_with('9'))
            .unwrap_or(false),);
    }
}
