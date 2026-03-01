//! Top-level wallet coordinator — manages lifecycle, key derivation, block
//! scanning, and balance queries through a 3-state machine:
//!
//! - **Uninitialized**: No keystore file exists. Only `init` and `restore` are available.
//! - **Locked**: Keystore exists but mnemonic is not decrypted. Only `unlock` available.
//! - **Unlocked**: Full wallet functionality available.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::keys::WalletKeys;
use crate::keystore::{Keystore, KeystoreError};
use crate::scan_logic::{self, TxInfo};
use crate::tracked_box::TrackedBox;
use crate::wallet_registry::{RegistryError, WalletDigest, WalletRegistry, WalletTransaction};
use crate::wallet_storage::{WalletStorage, WalletStorageError};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by [`WalletManager`] operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// The wallet has not been initialized (no keystore file).
    #[error("wallet not initialized")]
    NotInitialized,

    /// The wallet is locked — unlock it first.
    #[error("wallet is locked")]
    Locked,

    /// The wallet is already initialized.
    #[error("wallet already initialized")]
    AlreadyInitialized,

    /// The wallet is already unlocked.
    #[error("wallet already unlocked")]
    AlreadyUnlocked,

    /// Keystore error (encryption / decryption / I/O).
    #[error("keystore error: {0}")]
    Keystore(#[from] KeystoreError),

    /// Key derivation error.
    #[error("keys error: {0}")]
    Keys(String),

    /// Wallet metadata storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Wallet registry error.
    #[error("registry error: {0}")]
    Registry(String),

    /// Address encoding / decoding error.
    #[error("address error: {0}")]
    Address(String),

    /// Attempt to deregister a reserved (built-in) scan ID.
    #[error("scan ID {0} is reserved and cannot be deregistered")]
    ReservedScanId(u16),
}

impl From<WalletStorageError> for WalletError {
    fn from(e: WalletStorageError) -> Self {
        WalletError::Storage(e.to_string())
    }
}

impl From<RegistryError> for WalletError {
    fn from(e: RegistryError) -> Self {
        WalletError::Registry(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// WalletStatus
// ---------------------------------------------------------------------------

/// Public snapshot of the wallet's current state.
pub struct WalletStatus {
    /// Whether a keystore file exists.
    pub initialized: bool,
    /// Whether the wallet is currently unlocked (keys in memory).
    pub unlocked: bool,
    /// The change address, if set and the wallet is unlocked.
    pub change_address: Option<String>,
    /// Current wallet height (highest block scanned).
    pub wallet_height: u32,
    /// Human-readable error message, if any.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// WalletState (internal)
// ---------------------------------------------------------------------------

/// Internal three-state lifecycle.
enum WalletState {
    /// No keystore file.
    Uninitialized,
    /// Keystore exists, mnemonic not decrypted.
    Locked,
    /// Full functionality — keys in memory.
    Unlocked {
        keys: WalletKeys,
        /// ErgoTree bytes for all derived addresses — used for block scanning.
        ergo_trees: HashSet<Vec<u8>>,
        /// IDs of all unspent tracked boxes — used for block scanning.
        tracked_box_ids: HashSet<[u8; 32]>,
    },
}

// ---------------------------------------------------------------------------
// WalletManager
// ---------------------------------------------------------------------------

/// Top-level wallet coordinator.
///
/// Wraps [`Keystore`], [`WalletStorage`], and [`WalletRegistry`] behind a
/// state machine that enforces correct lifecycle transitions.
pub struct WalletManager {
    keystore: Keystore,
    storage: WalletStorage,
    registry: WalletRegistry,
    state: WalletState,
    #[allow(dead_code)]
    wallet_dir: PathBuf,
}

impl WalletManager {
    /// Open a wallet from a directory. Detects whether initialized / locked.
    ///
    /// Creates the following subdirectories if they don't exist:
    /// - `{dir}/storage` — wallet metadata (addresses, change address, indices)
    /// - `{dir}/registry` — tracked boxes, transactions, balance digest
    pub fn open(dir: &Path) -> Result<Self, WalletError> {
        std::fs::create_dir_all(dir.join("storage"))
            .map_err(|e| WalletError::Storage(format!("create storage dir: {e}")))?;
        std::fs::create_dir_all(dir.join("registry"))
            .map_err(|e| WalletError::Storage(format!("create registry dir: {e}")))?;

        let keystore = Keystore::new(dir);
        let storage = WalletStorage::open(&dir.join("storage"))?;
        let registry = WalletRegistry::open(&dir.join("registry"))?;

        let state = if keystore.exists() {
            WalletState::Locked
        } else {
            WalletState::Uninitialized
        };

        Ok(Self {
            keystore,
            storage,
            registry,
            state,
            wallet_dir: dir.to_path_buf(),
        })
    }

    /// Get the wallet's current status.
    pub fn status(&self) -> WalletStatus {
        let initialized = !matches!(self.state, WalletState::Uninitialized);
        let unlocked = matches!(self.state, WalletState::Unlocked { .. });

        let change_address = if unlocked {
            self.storage.get_change_address()
        } else {
            None
        };

        let wallet_height = self.registry.wallet_height();

        WalletStatus {
            initialized,
            unlocked,
            change_address,
            wallet_height,
            error: None,
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle transitions
    // -----------------------------------------------------------------------

    /// Create a new wallet with a generated mnemonic. Returns the mnemonic phrase.
    ///
    /// Requires **Uninitialized** state. Transitions to **Locked**.
    pub fn init(&mut self, password: &str) -> Result<String, WalletError> {
        if !matches!(self.state, WalletState::Uninitialized) {
            return Err(WalletError::AlreadyInitialized);
        }

        let mnemonic = self.keystore.init(password)?;
        self.state = WalletState::Locked;
        Ok(mnemonic)
    }

    /// Restore a wallet from an existing mnemonic phrase.
    ///
    /// Requires **Uninitialized** state. Transitions to **Locked**.
    pub fn restore(
        &mut self,
        password: &str,
        mnemonic: &str,
        _mnemonic_pass: &str,
    ) -> Result<(), WalletError> {
        if !matches!(self.state, WalletState::Uninitialized) {
            return Err(WalletError::AlreadyInitialized);
        }

        self.keystore.restore(password, mnemonic)?;
        self.state = WalletState::Locked;
        Ok(())
    }

    /// Unlock the wallet with a password.
    ///
    /// Decrypts the mnemonic, derives the master key, loads stored addresses,
    /// derives initial key (index 0) if none exist, and rebuilds the tracking
    /// sets (ergo_trees, tracked_box_ids).
    ///
    /// Requires **Locked** state. Transitions to **Unlocked**.
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        match &self.state {
            WalletState::Uninitialized => return Err(WalletError::NotInitialized),
            WalletState::Unlocked { .. } => return Err(WalletError::AlreadyUnlocked),
            WalletState::Locked => {}
        }

        // Decrypt the mnemonic.
        let mnemonic = self.keystore.unlock(password)?;

        // Derive the master key.
        let keys = WalletKeys::from_mnemonic(&mnemonic, "")
            .map_err(|e| WalletError::Keys(e.to_string()))?;

        // Load stored addresses. If none exist, derive index 0.
        let mut addresses = self.storage.get_addresses();
        if addresses.is_empty() {
            let dk = keys
                .derive_at(0)
                .map_err(|e| WalletError::Keys(e.to_string()))?;
            self.storage.store_address(0, &dk.address)?;
            self.storage.set_next_index(1)?;

            // Also set as change address if none exists.
            if self.storage.get_change_address().is_none() {
                self.storage.set_change_address(&dk.address)?;
            }

            addresses = vec![(0, dk.address)];
        }

        // Build the ErgoTree set from all stored addresses.
        let mut ergo_trees = HashSet::new();
        for (_idx, addr) in &addresses {
            let tree_bytes = address_to_ergo_tree_bytes(addr).map_err(WalletError::Address)?;
            ergo_trees.insert(tree_bytes);
        }

        // Build the tracked box ID set from current unspent boxes.
        let tracked_box_ids: HashSet<[u8; 32]> = self
            .registry
            .unspent_boxes()
            .into_iter()
            .map(|b| b.box_id)
            .collect();

        self.state = WalletState::Unlocked {
            keys,
            ergo_trees,
            tracked_box_ids,
        };

        Ok(())
    }

    /// Lock the wallet — clear keys and tracking sets from memory.
    ///
    /// Requires **Unlocked** state. Transitions to **Locked**.
    pub fn lock(&mut self) {
        if matches!(self.state, WalletState::Unlocked { .. }) {
            self.state = WalletState::Locked;
        }
    }

    // -----------------------------------------------------------------------
    // Key derivation
    // -----------------------------------------------------------------------

    /// Derive the next key (increments internal index).
    ///
    /// Returns `(derivation_path, address)`.
    pub fn derive_next_key(&mut self) -> Result<(String, String), WalletError> {
        let (keys, ergo_trees) = match &mut self.state {
            WalletState::Unlocked {
                keys, ergo_trees, ..
            } => (keys, ergo_trees),
            WalletState::Locked => return Err(WalletError::Locked),
            WalletState::Uninitialized => return Err(WalletError::NotInitialized),
        };

        let next_idx = self.storage.get_next_index();
        let dk = keys
            .derive_at(next_idx)
            .map_err(|e| WalletError::Keys(e.to_string()))?;

        self.storage.store_address(next_idx, &dk.address)?;
        self.storage.set_next_index(next_idx + 1)?;

        // Add the new address's ErgoTree to the tracking set.
        let tree_bytes = address_to_ergo_tree_bytes(&dk.address).map_err(WalletError::Address)?;
        ergo_trees.insert(tree_bytes);

        Ok((dk.path, dk.address))
    }

    /// Derive a key at a specific BIP-32 path. Returns the address.
    pub fn derive_key(&mut self, path: &str) -> Result<String, WalletError> {
        let (keys, ergo_trees) = match &mut self.state {
            WalletState::Unlocked {
                keys, ergo_trees, ..
            } => (keys, ergo_trees),
            WalletState::Locked => return Err(WalletError::Locked),
            WalletState::Uninitialized => return Err(WalletError::NotInitialized),
        };

        let dk = keys
            .derive_path(path)
            .map_err(|e| WalletError::Keys(e.to_string()))?;

        // Store at the index extracted from the path.
        self.storage.store_address(dk.index, &dk.address)?;

        // Add ErgoTree to tracking set.
        let tree_bytes = address_to_ergo_tree_bytes(&dk.address).map_err(WalletError::Address)?;
        ergo_trees.insert(tree_bytes);

        Ok(dk.address)
    }

    /// Get all derived addresses.
    pub fn addresses(&self) -> Result<Vec<String>, WalletError> {
        self.require_unlocked()?;
        Ok(self
            .storage
            .get_addresses()
            .into_iter()
            .map(|(_, addr)| addr)
            .collect())
    }

    /// Update the change address.
    pub fn update_change_address(&mut self, addr: &str) -> Result<(), WalletError> {
        self.require_unlocked()?;
        self.storage.set_change_address(addr)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Block scanning
    // -----------------------------------------------------------------------

    /// Scan a block for wallet-relevant activity.
    ///
    /// Calls [`scan_logic::scan_block`] with the current tracking sets, then
    /// applies the results to the registry. Updates `tracked_box_ids` (add new,
    /// remove spent).
    pub fn scan_block(
        &mut self,
        block_height: u32,
        block_id: &[u8; 32],
        txs: &[TxInfo],
    ) -> Result<(), WalletError> {
        let (ergo_trees, tracked_box_ids) = match &mut self.state {
            WalletState::Unlocked {
                ergo_trees,
                tracked_box_ids,
                ..
            } => (ergo_trees, tracked_box_ids),
            WalletState::Locked => return Err(WalletError::Locked),
            WalletState::Uninitialized => return Err(WalletError::NotInitialized),
        };

        let scans = self.storage.get_all_scans();
        let result = scan_logic::scan_block(txs, block_height, ergo_trees, tracked_box_ids, &scans);

        // Build WalletTransaction records from the scan result.
        let wallet_txs: Vec<WalletTransaction> = result
            .wallet_txs
            .iter()
            .map(|(tx_id, tx_bytes)| WalletTransaction {
                tx_id: *tx_id,
                inclusion_height: block_height,
                tx_bytes: tx_bytes.clone(),
            })
            .collect();

        // Collect new box IDs and scan associations before moving into registry.
        let new_box_ids: Vec<[u8; 32]> = result.new_boxes.iter().map(|b| b.box_id).collect();
        let scan_box_entries: Vec<([u8; 32], Vec<u16>)> = result
            .new_boxes
            .iter()
            .map(|b| (b.box_id, b.scan_ids.clone()))
            .collect();

        // Apply to registry.
        self.registry.update_on_block(
            block_height,
            block_id,
            result.new_boxes,
            result.spent_box_ids.clone(),
            wallet_txs,
        )?;

        // Update scan-box index for scan-matched boxes.
        for (box_id, scan_ids) in &scan_box_entries {
            for &scan_id in scan_ids {
                if scan_id >= crate::scan_types::FIRST_USER_SCAN_ID {
                    let _ = self.registry.add_scan_box(scan_id, box_id);
                }
            }
        }

        // Update the in-memory tracking set.
        for id in &new_box_ids {
            tracked_box_ids.insert(*id);
        }
        for id in &result.spent_box_ids {
            tracked_box_ids.remove(id);
        }

        Ok(())
    }

    /// Rollback to a given height (for chain reorgs).
    pub fn rollback_to_height(&mut self, target_height: u32) -> Result<(), WalletError> {
        self.require_unlocked()?;

        self.registry.rollback_to_height(target_height)?;

        // Rebuild the tracked box ID set from the registry.
        if let WalletState::Unlocked {
            tracked_box_ids, ..
        } = &mut self.state
        {
            *tracked_box_ids = self
                .registry
                .unspent_boxes()
                .into_iter()
                .map(|b| b.box_id)
                .collect();
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Get on-chain balance.
    pub fn balances(&self) -> Result<WalletDigest, WalletError> {
        self.require_unlocked()?;
        Ok(self.registry.get_balance())
    }

    /// Get unspent wallet boxes.
    pub fn unspent_boxes(&self) -> Result<Vec<TrackedBox>, WalletError> {
        self.require_unlocked()?;
        Ok(self.registry.unspent_boxes())
    }

    /// Get all wallet boxes (spent + unspent).
    pub fn all_boxes(&self) -> Result<Vec<TrackedBox>, WalletError> {
        self.require_unlocked()?;
        Ok(self.registry.all_boxes())
    }

    /// Get wallet transactions within a height range (inclusive).
    pub fn get_transactions(
        &self,
        min_height: u32,
        max_height: u32,
    ) -> Result<Vec<WalletTransaction>, WalletError> {
        self.require_unlocked()?;
        Ok(self.registry.get_transactions(min_height, max_height))
    }

    /// Get a wallet transaction by its ID.
    pub fn get_transaction_by_id(
        &self,
        tx_id: &[u8; 32],
    ) -> Result<Option<WalletTransaction>, WalletError> {
        self.require_unlocked()?;
        Ok(self.registry.get_transaction_by_id(tx_id))
    }

    /// Check if the provided mnemonic matches the wallet's stored seed.
    ///
    /// Attempts to decrypt the keystore with the given password and compares
    /// the resulting mnemonic against the provided one.
    pub fn check_seed(&self, password: &str, mnemonic: &str) -> Result<bool, WalletError> {
        if matches!(self.state, WalletState::Uninitialized) {
            return Err(WalletError::NotInitialized);
        }
        match self.keystore.unlock(password) {
            Ok(stored_mnemonic) => Ok(stored_mnemonic.trim() == mnemonic.trim()),
            Err(_) => Ok(false),
        }
    }

    /// Rescan the wallet from the given height by rolling back the registry.
    ///
    /// This removes all tracked data above `from_height`, allowing the wallet
    /// to re-scan blocks from that point onwards during normal block processing.
    pub fn rescan(&mut self, from_height: u32) -> Result<(), WalletError> {
        if matches!(self.state, WalletState::Uninitialized) {
            return Err(WalletError::NotInitialized);
        }
        self.registry.rollback_to_height(from_height)?;

        // Rebuild the tracked box ID set if unlocked.
        if let WalletState::Unlocked {
            tracked_box_ids, ..
        } = &mut self.state
        {
            *tracked_box_ids = self
                .registry
                .unspent_boxes()
                .into_iter()
                .map(|b| b.box_id)
                .collect();
        }

        Ok(())
    }

    /// Get the keys (for signing). Only available when unlocked.
    pub fn keys(&self) -> Result<&WalletKeys, WalletError> {
        match &self.state {
            WalletState::Unlocked { keys, .. } => Ok(keys),
            WalletState::Locked => Err(WalletError::Locked),
            WalletState::Uninitialized => Err(WalletError::NotInitialized),
        }
    }

    /// Get the hex-encoded secret key for the given wallet address.
    ///
    /// Finds the derivation index corresponding to the address among stored
    /// addresses, derives the EIP-3 secret key at that index, and returns the
    /// raw secret bytes as a hex string.
    ///
    /// Requires **Unlocked** state.
    pub fn get_private_key(&self, address: &str) -> Result<String, WalletError> {
        let keys = self.keys()?;
        let addresses = self.storage.get_addresses();
        let idx = addresses
            .iter()
            .find(|(_, addr)| addr == address)
            .map(|(i, _)| *i)
            .ok_or_else(|| WalletError::Address("address not found in wallet".into()))?;
        let sks = keys
            .secret_keys(&[idx])
            .map_err(|e| WalletError::Keys(e.to_string()))?;
        let sk = sks
            .first()
            .ok_or_else(|| WalletError::Keys("failed to derive secret key".into()))?;
        Ok(hex::encode(sk.to_bytes()))
    }

    /// Get wallet transactions associated with a given scan ID.
    ///
    /// Walks all boxes tracked by the scan, collects their creating `tx_id`s,
    /// deduplicates, and returns the corresponding `WalletTransaction` records.
    pub fn get_txs_by_scan_id(&self, scan_id: u16) -> Result<Vec<WalletTransaction>, WalletError> {
        self.require_unlocked()?;
        let box_ids = self.registry.boxes_for_scan(scan_id);
        let mut seen_tx_ids = HashSet::new();
        let mut txs = Vec::new();
        for box_id in &box_ids {
            if let Some(tb) = self.registry.get_box(box_id) {
                if seen_tx_ids.insert(tb.tx_id) {
                    if let Some(wtx) = self.registry.get_transaction_by_id(&tb.tx_id) {
                        txs.push(wtx);
                    }
                }
            }
        }
        txs.sort_by_key(|t| t.inclusion_height);
        Ok(txs)
    }

    /// Get the change address.
    pub fn change_address(&self) -> Result<String, WalletError> {
        self.require_unlocked()?;
        self.storage
            .get_change_address()
            .ok_or_else(|| WalletError::Keys("no change address set".to_string()))
    }

    // -----------------------------------------------------------------------
    // Scan management
    // -----------------------------------------------------------------------

    /// Register a new user-defined scan.
    ///
    /// Allocates the next available scan ID, persists the scan definition, and
    /// returns the assigned ID.
    pub fn register_scan(
        &mut self,
        scan_name: String,
        tracking_rule: crate::scan_types::ScanningPredicate,
        wallet_interaction: crate::scan_types::ScanWalletInteraction,
        remove_offchain: bool,
    ) -> Result<u16, WalletError> {
        self.require_unlocked()?;
        let scan_id = self.storage.next_scan_id()?;
        let scan = crate::scan_types::Scan {
            scan_id,
            scan_name,
            tracking_rule,
            wallet_interaction,
            remove_offchain,
        };
        self.storage.store_scan(&scan)?;
        Ok(scan_id)
    }

    /// Deregister a user-defined scan.
    ///
    /// Only scans with ID >= [`crate::scan_types::FIRST_USER_SCAN_ID`] (11)
    /// can be deregistered. Reserved scan IDs (mining, payments) return an error.
    pub fn deregister_scan(&mut self, scan_id: u16) -> Result<(), WalletError> {
        self.require_unlocked()?;
        if scan_id < crate::scan_types::FIRST_USER_SCAN_ID {
            return Err(WalletError::ReservedScanId(scan_id));
        }
        self.storage.remove_scan(scan_id)?;
        Ok(())
    }

    /// List all registered scans, sorted by scan ID.
    pub fn list_scans(&self) -> Result<Vec<crate::scan_types::Scan>, WalletError> {
        self.require_unlocked()?;
        Ok(self.storage.get_all_scans())
    }

    /// Get all unspent boxes associated with a given scan.
    pub fn unspent_boxes_for_scan(&self, scan_id: u16) -> Result<Vec<TrackedBox>, WalletError> {
        self.require_unlocked()?;
        Ok(self.registry.unspent_boxes_for_scan(scan_id))
    }

    /// Get all spent boxes associated with a given scan.
    pub fn spent_boxes_for_scan(&self, scan_id: u16) -> Result<Vec<TrackedBox>, WalletError> {
        self.require_unlocked()?;
        Ok(self.registry.spent_boxes_for_scan(scan_id))
    }

    /// Remove a box from a scan's tracking index.
    pub fn stop_tracking(&mut self, scan_id: u16, box_id: &[u8; 32]) -> Result<(), WalletError> {
        self.require_unlocked()?;
        self.registry.remove_scan_box(scan_id, box_id)?;
        Ok(())
    }

    /// Store a box in the registry (if not already present) and add
    /// scan-box associations for each provided scan ID.
    pub fn add_box_to_scans(
        &mut self,
        tracked_box: TrackedBox,
        scan_ids: &[u16],
    ) -> Result<(), WalletError> {
        self.require_unlocked()?;

        // Store the box if it does not already exist in the registry.
        if self.registry.get_box(&tracked_box.box_id).is_none() {
            let block_id = [0u8; 32]; // placeholder — the box is being added externally
            self.registry.update_on_block(
                tracked_box.inclusion_height,
                &block_id,
                vec![tracked_box.clone()],
                vec![],
                vec![],
            )?;
        }

        // Add scan-box associations.
        for &scan_id in scan_ids {
            self.registry.add_scan_box(scan_id, &tracked_box.box_id)?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Returns `Ok(())` if the wallet is unlocked, otherwise the appropriate error.
    fn require_unlocked(&self) -> Result<(), WalletError> {
        match &self.state {
            WalletState::Unlocked { .. } => Ok(()),
            WalletState::Locked => Err(WalletError::Locked),
            WalletState::Uninitialized => Err(WalletError::NotInitialized),
        }
    }
}

// ---------------------------------------------------------------------------
// Address → ErgoTree conversion
// ---------------------------------------------------------------------------

/// Convert a base58 Ergo address to its ErgoTree byte representation.
///
/// Uses `ergo_types::address::decode_address` to parse the address, then
/// reconstructs the ErgoTree:
/// - **P2PK**: `[0x00, 0x08, 0xcd] ++ 33-byte compressed public key`
/// - **P2S**: content bytes are already the raw ErgoTree
/// - **P2SH**: not supported (cannot reconstruct the full ErgoTree)
fn address_to_ergo_tree_bytes(addr: &str) -> Result<Vec<u8>, String> {
    let decoded = ergo_types::address::decode_address(addr)
        .map_err(|e| format!("failed to decode address: {e}"))?;

    match decoded.address_type {
        ergo_types::address::AddressType::P2PK => {
            let mut tree = Vec::with_capacity(3 + decoded.content_bytes.len());
            tree.extend_from_slice(&[0x00, 0x08, 0xcd]);
            tree.extend_from_slice(&decoded.content_bytes);
            Ok(tree)
        }
        ergo_types::address::AddressType::P2S => Ok(decoded.content_bytes),
        ergo_types::address::AddressType::P2SH => {
            Err("P2SH addresses cannot be converted to ErgoTree".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_logic::{OutputInfo, TxInfo};
    use tempfile::TempDir;

    /// Well-known test mnemonic from ergo-lib.
    const TEST_MNEMONIC: &str =
        "slow silly start wash bundle suffer bulb ancient height spin express remind today effort helmet";

    const TEST_PASSWORD: &str = "test-password";

    /// Helper: create a WalletManager in a fresh temp dir.
    fn open_fresh() -> (WalletManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let wm = WalletManager::open(dir.path()).unwrap();
        (wm, dir)
    }

    /// Helper: create a WalletManager that's already initialized and locked.
    fn open_initialized() -> (WalletManager, TempDir) {
        let (mut wm, dir) = open_fresh();
        wm.init(TEST_PASSWORD).unwrap();
        (wm, dir)
    }

    /// Helper: create a WalletManager that's already unlocked.
    fn open_unlocked() -> (WalletManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let mut wm = WalletManager::open(dir.path()).unwrap();
        wm.restore(TEST_PASSWORD, TEST_MNEMONIC, "").unwrap();
        wm.unlock(TEST_PASSWORD).unwrap();
        (wm, dir)
    }

    /// Build a deterministic 32-byte array from a single seed byte.
    fn id32(seed: u8) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        arr
    }

    // -----------------------------------------------------------------------
    // 1. open_detects_uninitialized
    // -----------------------------------------------------------------------

    #[test]
    fn open_detects_uninitialized() {
        let (wm, _dir) = open_fresh();
        let status = wm.status();
        assert!(!status.initialized);
        assert!(!status.unlocked);
        assert!(status.change_address.is_none());
        assert_eq!(status.wallet_height, 0);
    }

    // -----------------------------------------------------------------------
    // 2. init_transitions_to_locked
    // -----------------------------------------------------------------------

    #[test]
    fn init_transitions_to_locked() {
        let (mut wm, _dir) = open_fresh();

        let mnemonic = wm.init(TEST_PASSWORD).unwrap();
        assert!(!mnemonic.is_empty());

        // Should be 24 words.
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 24);

        let status = wm.status();
        assert!(status.initialized);
        assert!(!status.unlocked);
    }

    // -----------------------------------------------------------------------
    // 3. unlock_transitions_to_unlocked
    // -----------------------------------------------------------------------

    #[test]
    fn unlock_transitions_to_unlocked() {
        let dir = TempDir::new().unwrap();
        let mut wm = WalletManager::open(dir.path()).unwrap();

        // Restore a known mnemonic so we can verify addresses.
        wm.restore(TEST_PASSWORD, TEST_MNEMONIC, "").unwrap();

        let status = wm.status();
        assert!(status.initialized);
        assert!(!status.unlocked);

        wm.unlock(TEST_PASSWORD).unwrap();

        let status = wm.status();
        assert!(status.initialized);
        assert!(status.unlocked);
        assert!(status.change_address.is_some());

        // Should have derived index 0 automatically.
        let addrs = wm.addresses().unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].starts_with('9'), "expected mainnet P2PK address");
    }

    // -----------------------------------------------------------------------
    // 4. lock_clears_state
    // -----------------------------------------------------------------------

    #[test]
    fn lock_clears_state() {
        let (mut wm, _dir) = open_unlocked();

        // Should be unlocked.
        assert!(wm.status().unlocked);
        assert!(wm.keys().is_ok());

        wm.lock();

        // Should be locked now.
        assert!(!wm.status().unlocked);
        assert!(wm.status().initialized);

        // Keys should not be accessible.
        assert!(wm.keys().is_err());
    }

    // -----------------------------------------------------------------------
    // 5. operations_fail_in_wrong_state
    // -----------------------------------------------------------------------

    #[test]
    fn operations_fail_in_wrong_state() {
        // --- Uninitialized: most operations fail ---
        let (mut wm_uninit, _dir1) = open_fresh();
        assert!(matches!(
            wm_uninit.unlock(TEST_PASSWORD),
            Err(WalletError::NotInitialized)
        ));
        assert!(matches!(
            wm_uninit.addresses(),
            Err(WalletError::NotInitialized)
        ));
        assert!(matches!(
            wm_uninit.balances(),
            Err(WalletError::NotInitialized)
        ));
        assert!(matches!(wm_uninit.keys(), Err(WalletError::NotInitialized)));

        // --- Locked: query operations fail ---
        let (mut wm_locked, _dir2) = open_initialized();
        assert!(matches!(wm_locked.addresses(), Err(WalletError::Locked)));
        assert!(matches!(wm_locked.balances(), Err(WalletError::Locked)));
        assert!(matches!(wm_locked.keys(), Err(WalletError::Locked)));
        assert!(matches!(
            wm_locked.derive_next_key(),
            Err(WalletError::Locked)
        ));

        // init() should fail when already initialized.
        assert!(matches!(
            wm_locked.init(TEST_PASSWORD),
            Err(WalletError::AlreadyInitialized)
        ));

        // --- Unlocked: init/restore fail, unlock fails ---
        let (mut wm_unlocked, _dir3) = open_unlocked();
        assert!(matches!(
            wm_unlocked.init(TEST_PASSWORD),
            Err(WalletError::AlreadyInitialized)
        ));
        assert!(matches!(
            wm_unlocked.restore(TEST_PASSWORD, TEST_MNEMONIC, ""),
            Err(WalletError::AlreadyInitialized)
        ));
        assert!(matches!(
            wm_unlocked.unlock(TEST_PASSWORD),
            Err(WalletError::AlreadyUnlocked)
        ));
    }

    // -----------------------------------------------------------------------
    // 6. derive_next_key_produces_addresses
    // -----------------------------------------------------------------------

    #[test]
    fn derive_next_key_produces_addresses() {
        let (mut wm, _dir) = open_unlocked();

        // Index 0 was derived during unlock. derive_next_key should give index 1, 2, 3.
        let (path1, addr1) = wm.derive_next_key().unwrap();
        let (path2, addr2) = wm.derive_next_key().unwrap();
        let (path3, addr3) = wm.derive_next_key().unwrap();

        // All should be distinct.
        assert_ne!(addr1, addr2);
        assert_ne!(addr2, addr3);
        assert_ne!(addr1, addr3);

        // All should be valid mainnet addresses.
        assert!(addr1.starts_with('9'));
        assert!(addr2.starts_with('9'));
        assert!(addr3.starts_with('9'));

        // Paths should include the correct indices.
        assert!(path1.contains("/1"), "path1: {path1}");
        assert!(path2.contains("/2"), "path2: {path2}");
        assert!(path3.contains("/3"), "path3: {path3}");

        // Total addresses should be 4 (index 0 from unlock + 3 derived).
        let all = wm.addresses().unwrap();
        assert_eq!(all.len(), 4);
    }

    // -----------------------------------------------------------------------
    // 7. scan_block_updates_balance
    // -----------------------------------------------------------------------

    #[test]
    fn scan_block_updates_balance() {
        let (mut wm, _dir) = open_unlocked();

        // Get the wallet's first address and its ErgoTree.
        let addrs = wm.addresses().unwrap();
        let addr = &addrs[0];
        let tree_bytes = address_to_ergo_tree_bytes(addr).unwrap();

        // Create a fake block with one tx that sends 1_000_000 nanoERG to the wallet.
        let block_id = id32(0xAA);
        let tx = TxInfo {
            tx_id: id32(0x01),
            input_box_ids: vec![],
            outputs: vec![OutputInfo {
                box_id: id32(0x10),
                ergo_tree_bytes: tree_bytes.clone(),
                value: 1_000_000,
                tokens: vec![],
                creation_height: 100,
                output_index: 0,
                serialized_box: vec![0xDE, 0xAD],
                additional_registers: vec![],
            }],
            tx_bytes: vec![0xCA, 0xFE],
        };

        // Scan the block.
        wm.scan_block(100, &block_id, &[tx]).unwrap();

        // Balance should reflect the new box.
        let digest = wm.balances().unwrap();
        assert_eq!(digest.erg_balance, 1_000_000);
        assert_eq!(digest.height, 100);

        // Should have 1 unspent box.
        let unspent = wm.unspent_boxes().unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].value, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // 8. scan_block_tracks_spending
    // -----------------------------------------------------------------------

    #[test]
    fn scan_block_tracks_spending() {
        let (mut wm, _dir) = open_unlocked();

        let addrs = wm.addresses().unwrap();
        let tree_bytes = address_to_ergo_tree_bytes(&addrs[0]).unwrap();

        // Block 1: receive 5_000_000 nanoERG.
        let block1_id = id32(0xAA);
        let box_id = id32(0x10);
        let tx1 = TxInfo {
            tx_id: id32(0x01),
            input_box_ids: vec![],
            outputs: vec![OutputInfo {
                box_id,
                ergo_tree_bytes: tree_bytes.clone(),
                value: 5_000_000,
                tokens: vec![],
                creation_height: 100,
                output_index: 0,
                serialized_box: vec![0xDE, 0xAD],
                additional_registers: vec![],
            }],
            tx_bytes: vec![0xCA, 0xFE],
        };
        wm.scan_block(100, &block1_id, &[tx1]).unwrap();
        assert_eq!(wm.balances().unwrap().erg_balance, 5_000_000);

        // Block 2: spend the box, receive 3_000_000 back (change).
        let block2_id = id32(0xBB);
        let change_box_id = id32(0x20);
        let tx2 = TxInfo {
            tx_id: id32(0x02),
            input_box_ids: vec![box_id], // spends the box from block 1
            outputs: vec![OutputInfo {
                box_id: change_box_id,
                ergo_tree_bytes: tree_bytes.clone(),
                value: 3_000_000,
                tokens: vec![],
                creation_height: 200,
                output_index: 0,
                serialized_box: vec![0xBE, 0xEF],
                additional_registers: vec![],
            }],
            tx_bytes: vec![0xBA, 0xBE],
        };
        wm.scan_block(200, &block2_id, &[tx2]).unwrap();

        // Balance should be 3_000_000 (change only, original is spent).
        assert_eq!(wm.balances().unwrap().erg_balance, 3_000_000);
        assert_eq!(wm.unspent_boxes().unwrap().len(), 1);

        // All boxes (spent + unspent) should be 2.
        assert_eq!(wm.all_boxes().unwrap().len(), 2);
    }

    // -----------------------------------------------------------------------
    // 9. rollback_restores_state
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_restores_state() {
        let (mut wm, _dir) = open_unlocked();

        let addrs = wm.addresses().unwrap();
        let tree_bytes = address_to_ergo_tree_bytes(&addrs[0]).unwrap();

        // Block 1: receive 5_000_000 nanoERG at height 100.
        let block1_id = id32(0xAA);
        let box_id = id32(0x10);
        let tx1 = TxInfo {
            tx_id: id32(0x01),
            input_box_ids: vec![],
            outputs: vec![OutputInfo {
                box_id,
                ergo_tree_bytes: tree_bytes.clone(),
                value: 5_000_000,
                tokens: vec![],
                creation_height: 100,
                output_index: 0,
                serialized_box: vec![0xDE, 0xAD],
                additional_registers: vec![],
            }],
            tx_bytes: vec![0xCA, 0xFE],
        };
        wm.scan_block(100, &block1_id, &[tx1]).unwrap();

        // Block 2: spend the box at height 200.
        let block2_id = id32(0xBB);
        let tx2 = TxInfo {
            tx_id: id32(0x02),
            input_box_ids: vec![box_id],
            outputs: vec![],
            tx_bytes: vec![0xBA, 0xBE],
        };
        wm.scan_block(200, &block2_id, &[tx2]).unwrap();

        assert_eq!(wm.balances().unwrap().erg_balance, 0);

        // Rollback to height 150 — the spend at height 200 should be undone.
        wm.rollback_to_height(150).unwrap();

        assert_eq!(wm.balances().unwrap().erg_balance, 5_000_000);
        assert_eq!(wm.unspent_boxes().unwrap().len(), 1);
    }

    // -----------------------------------------------------------------------
    // 10. derive_key_at_path
    // -----------------------------------------------------------------------

    #[test]
    fn derive_key_at_path() {
        let (mut wm, _dir) = open_unlocked();

        let addr = wm.derive_key("m/44'/429'/0'/0/5").unwrap();
        assert!(addr.starts_with('9'), "expected mainnet address");

        // The address should be stored.
        let all = wm.addresses().unwrap();
        assert!(all.contains(&addr));
    }

    // -----------------------------------------------------------------------
    // 11. change_address_management
    // -----------------------------------------------------------------------

    #[test]
    fn change_address_management() {
        let (mut wm, _dir) = open_unlocked();

        // Default change address should be set to index 0.
        let change = wm.change_address().unwrap();
        assert!(change.starts_with('9'));

        // Derive a second key and set it as change address.
        let (_, new_addr) = wm.derive_next_key().unwrap();
        wm.update_change_address(&new_addr).unwrap();

        let change = wm.change_address().unwrap();
        assert_eq!(change, new_addr);
    }

    // -----------------------------------------------------------------------
    // 12. reopen_detects_locked
    // -----------------------------------------------------------------------

    #[test]
    fn reopen_detects_locked() {
        let dir = TempDir::new().unwrap();

        // Create and initialize.
        {
            let mut wm = WalletManager::open(dir.path()).unwrap();
            wm.init(TEST_PASSWORD).unwrap();
        }

        // Reopen — should detect as Locked (initialized).
        {
            let wm = WalletManager::open(dir.path()).unwrap();
            let status = wm.status();
            assert!(status.initialized);
            assert!(!status.unlocked);
        }
    }

    // -----------------------------------------------------------------------
    // 13. wallet_transactions_after_scan
    // -----------------------------------------------------------------------

    #[test]
    fn wallet_transactions_after_scan() {
        let (mut wm, _dir) = open_unlocked();

        let addrs = wm.addresses().unwrap();
        let tree_bytes = address_to_ergo_tree_bytes(&addrs[0]).unwrap();

        let block_id = id32(0xAA);
        let tx = TxInfo {
            tx_id: id32(0x01),
            input_box_ids: vec![],
            outputs: vec![OutputInfo {
                box_id: id32(0x10),
                ergo_tree_bytes: tree_bytes,
                value: 1_000_000,
                tokens: vec![],
                creation_height: 50,
                output_index: 0,
                serialized_box: vec![0xDE, 0xAD],
                additional_registers: vec![],
            }],
            tx_bytes: vec![0xCA, 0xFE],
        };

        wm.scan_block(50, &block_id, &[tx]).unwrap();

        let txs = wm.get_transactions(0, u32::MAX).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].tx_id, id32(0x01));
        assert_eq!(txs[0].inclusion_height, 50);
        assert_eq!(txs[0].tx_bytes, vec![0xCA, 0xFE]);
    }

    // -----------------------------------------------------------------------
    // 14. register_and_list_scans
    // -----------------------------------------------------------------------

    #[test]
    fn register_and_list_scans() {
        use crate::scan_types::{ScanWalletInteraction, ScanningPredicate};

        let (mut wm, _dir) = open_unlocked();

        let scan_id = wm
            .register_scan(
                "test scan".into(),
                ScanningPredicate::ContainsAsset {
                    asset_id: hex::encode([0xAA; 32]),
                },
                ScanWalletInteraction::Off,
                false,
            )
            .unwrap();

        assert_eq!(scan_id, 11);

        let scans = wm.list_scans().unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].scan_name, "test scan");

        wm.deregister_scan(scan_id).unwrap();
        assert!(wm.list_scans().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // 15. cannot_deregister_reserved_scan
    // -----------------------------------------------------------------------

    #[test]
    fn cannot_deregister_reserved_scan() {
        let (mut wm, _dir) = open_unlocked();
        assert!(wm.deregister_scan(10).is_err());
        assert!(wm.deregister_scan(9).is_err());
        assert!(wm.deregister_scan(0).is_err());
    }
}
