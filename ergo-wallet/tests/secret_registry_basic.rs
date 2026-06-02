//! SecretRegistry pre-derivation matches the direct derivation oracle.

use ergo_wallet::derivation::DerivationPath;
use ergo_wallet::extended_key::ExtendedSecretKey;
use ergo_wallet::mnemonic::Mnemonic;
use ergo_wallet::proving::secrets::SecretRegistry;
use ergo_wallet::storage::UnlockedMaster;
use std::collections::BTreeMap;

// ----- happy path -----

#[test]
fn registry_derived_scalar_matches_direct_derivation() {
    // 24-word mnemonic (known valid BIP39 checksum).
    let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon art";
    let m = Mnemonic::import(mnemonic_phrase).unwrap();
    let seed = m.to_seed("");
    let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
    let unlocked = UnlockedMaster::Modern(master);

    // Path m/44'/429'/0'/0/0 — derivation vector.
    let path_components: Vec<u32> = vec![44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0];
    let path = DerivationPath::from_components(path_components.clone());

    // Direct derivation gives us the expected pubkey.
    let direct_pk = unlocked.derive_pubkey_at_path(&path).unwrap();

    // Build registry with just this one tracked pubkey.
    let mut tracked = BTreeMap::new();
    tracked.insert(0u64, (direct_pk, path_components));
    let registry = SecretRegistry::from_master_key(&unlocked, &tracked).unwrap();

    // Registry's stored scalar must reproduce the tracked pubkey via G * scalar.
    let stored_scalar = registry
        .dlog_secret(&direct_pk)
        .expect("registry must contain the tracked pubkey");
    use k256::elliptic_curve::group::GroupEncoding;
    let derived_point = k256::ProjectivePoint::GENERATOR * (*stored_scalar);
    let derived_compressed: [u8; 33] = derived_point.to_affine().to_bytes().into();

    assert_eq!(
        derived_compressed, direct_pk,
        "registry-derived scalar must reproduce the tracked pubkey",
    );
}

#[test]
fn registry_untracked_pubkey_returns_none() {
    let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about";
    let m = Mnemonic::import(mnemonic_phrase).unwrap();
    let seed = m.to_seed("");
    let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
    let unlocked = UnlockedMaster::Modern(master);
    let registry = SecretRegistry::from_master_key(&unlocked, &BTreeMap::new()).unwrap();

    // A pubkey not in the tracked set must return None.
    let untracked = [0x02u8; 33];
    assert!(
        registry.dlog_secret(&untracked).is_none(),
        "untracked pubkey must not be in registry",
    );
}
