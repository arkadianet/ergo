//! HD-secret lookup for the prover.
//!
//! Given an `UnlockedMaster` (the wallet's in-memory unlocked secret)
//! and the set of tracked pubkeys with their derivation paths (from
//! `WALLET_TRACKED_PUBKEYS`), pre-derive the leaf secret for each path.
//! The prover then looks up `ProveDlog(pk) -> Scalar` in O(log n).
//!
//! For non-tracked or non-Dlog propositions (e.g., the miner-reward
//! wrapper's embedded pubkey), the registry returns None and the
//! prover propagates `MissingSecret`.

use crate::derivation::DerivationPath;
use crate::error::WalletError;
use crate::proving::external::ProverExternalSecret;
use crate::storage::UnlockedMaster;
use k256::Scalar;
use std::collections::BTreeMap;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Identity of a DH-tuple proposition: (g, h, u, v) compressed-SEC1
/// point tuple. `Ord` is derived so it can serve as a `BTreeMap` key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DhTupleId(pub [u8; 33], pub [u8; 33], pub [u8; 33], pub [u8; 33]);

/// Pre-derived secrets for every tracked pubkey (DLog) and any
/// externally-supplied DHT secrets. Lookup is O(log n) — avoids
/// per-input re-derivation at signing time. DHT slot is populated
/// via `merge_external_secrets`.
///
/// Stored scalars are wrapped in [`Zeroizing<Scalar>`] so the raw key
/// bytes are wiped from memory when this registry drops. The pubkey
/// `BTreeMap` keys are NOT secrets — `#[zeroize(skip)]` keeps them in
/// the derive but skips them at Drop. Accessors expose `Option<&Scalar>`
/// so consumer code (proving/sigma.rs leaf lookups, arithmetic in
/// finalize) sees the unchanged `&Scalar` API — the `Zeroizing` wrap
/// is a storage-and-drop concern, not a calling-shape concern.
///
/// Scope of the wipe: only the map-stored copy. Request-local copies
/// the prover materializes into `proving::sigma::LeafState::Real {
/// secret: Scalar }` are bare `Scalar` and live for the duration of a
/// single sign call. The registry's `ZeroizeOnDrop` does not reach
/// them.
#[derive(ZeroizeOnDrop)]
pub struct SecretRegistry {
    /// secp256k1 scalar by compressed-SEC1 pubkey (ProveDlog secrets).
    /// The `BTreeMap` itself doesn't impl `Zeroize`, but its `Drop`
    /// fires per-value `Drop` on each `Zeroizing<Scalar>` which DOES
    /// wipe the bytes. `#[zeroize(skip)]` tells the derive to leave
    /// the map alone; per-value cleanup happens through the BTreeMap's
    /// normal Drop chain.
    #[zeroize(skip)]
    dlog_secrets: BTreeMap<[u8; 33], Zeroizing<Scalar>>,
    /// secp256k1 scalar by DH-tuple identity (g, h, u, v).
    /// Empty unless populated via `merge_external_secrets`.
    #[zeroize(skip)]
    dht_secrets: BTreeMap<DhTupleId, Zeroizing<Scalar>>,
}

impl SecretRegistry {
    /// Empty registry (no secrets). Used for external-secret-only signing.
    pub fn empty() -> Self {
        Self {
            dlog_secrets: BTreeMap::new(),
            dht_secrets: BTreeMap::new(),
        }
    }

    /// Build from the unlocked master key + tracked pubkeys.
    ///
    /// `tracked` maps `derivation_path_index → (pubkey, derivation_path_components)`.
    /// Each entry's leaf secret is derived and cached for O(log n) lookup.
    ///
    /// Returns `Err(WalletError::...)` only if derivation fails for a path
    /// (e.g., an invalid hardened path component).
    pub fn from_master_key(
        master: &UnlockedMaster,
        tracked: &BTreeMap<u64, ([u8; 33], Vec<u32>)>,
    ) -> Result<Self, WalletError> {
        let mut dlog_secrets = BTreeMap::new();
        for (pubkey, derivation_path_components) in tracked.values() {
            let path = DerivationPath::from_components(derivation_path_components.clone());
            let scalar = master.derive_scalar_at_path(&path)?;
            dlog_secrets.insert(*pubkey, Zeroizing::new(scalar));
        }
        Ok(Self {
            dlog_secrets,
            dht_secrets: BTreeMap::new(),
        })
    }

    /// Extend the registry with externally-supplied secrets.
    ///
    /// Enables the lock-matrix path: `/wallet/transaction/sign` works
    /// while the wallet is locked if the caller supplies secrets for every
    /// required proposition. The API handler decodes hex scalars to
    /// `ProverExternalSecret` before calling this.
    pub fn merge_external_secrets(
        mut self,
        externals: &[ProverExternalSecret],
    ) -> Result<Self, WalletError> {
        for ext in externals {
            match ext {
                ProverExternalSecret::Dlog { pk, scalar } => {
                    // `scalar: &Zeroizing<Scalar>` (Zeroizing isn't
                    // Copy). Clone to get a fresh wrapper that owns
                    // its own scalar bytes and will zeroize when the
                    // map entry drops.
                    self.dlog_secrets.insert(*pk, scalar.clone());
                }
                ProverExternalSecret::DhTuple { g, h, u, v, scalar } => {
                    self.dht_secrets
                        .insert(DhTupleId(*g, *h, *u, *v), scalar.clone());
                }
            }
        }
        Ok(self)
    }

    /// Look up the scalar for a ProveDlog leaf. Returns `None` if the
    /// pubkey is not tracked (the prover must return `MissingSecret`).
    ///
    /// Returns `Option<&Scalar>` rather than `Option<&Zeroizing<Scalar>>`
    /// so consumer code (sigma.rs leaf lookups, finalize arithmetic) sees
    /// the unchanged `&Scalar` API. The wrap is a storage-and-drop
    /// concern.
    pub fn dlog_secret(&self, pk: &[u8; 33]) -> Option<&Scalar> {
        self.dlog_secrets.get(pk).map(|z| &**z)
    }

    /// Look up the scalar for a ProveDHTuple leaf.
    pub fn dht_secret(&self, id: &DhTupleId) -> Option<&Scalar> {
        self.dht_secrets.get(id).map(|z| &**z)
    }

    /// Returns true if the wallet holds a secret for `ProveDlog(pk)`.
    pub fn can_prove_dlog(&self, pk: &[u8; 33]) -> bool {
        self.dlog_secrets.contains_key(pk)
    }
}
