//! P2PK address parity vs external wallets. Uses the
//! Scala-canonical vectors from
//! `reference/ergo/ergo-wallet/src/test/scala/org/ergoplatform/wallet/secrets/DerivationPathSpec.scala`
//! which Scala's own developers cross-verified against CoinBarn AND
//! Yoroi (see inline comment "This testing pair is checked against
//! CoinBarn and Yoroi" at line 32 of that file).
//!
//! Pinning both halves — modern (use_pre_1627=false, EIP-3 path) and
//! legacy (use_pre_1627=false, pre-EIP-3 m/1 path) — guards against
//! drift in either dimension.

use ergo_ser::address::NetworkPrefix;
use ergo_wallet::address::pubkey_to_p2pk_address;
use ergo_wallet::derivation::DerivationPath;
use ergo_wallet::extended_key::ExtendedSecretKey;
use ergo_wallet::mnemonic::Mnemonic;

// ----- helpers -----

const CROSS_VERIFIED_MNEMONIC: &str =
    "liar exercise solve delay betray sheriff method empower disease river recall vacuum";

// Post-1627 derivation only. Pre-1627 oracle lives in a separate test file.
fn address_for(path: DerivationPath) -> String {
    let m = Mnemonic::import(CROSS_VERIFIED_MNEMONIC).expect("vector mnemonic must import");
    let seed = m.to_seed("");
    let master = ExtendedSecretKey::derive_master_key(&seed, false)
        .expect("master key derivation must succeed");
    let leaf = master
        .derive_at_path(&path)
        .expect("path derivation must succeed");
    let pk = leaf.public_key().compressed_bytes();
    pubkey_to_p2pk_address(&pk, NetworkPrefix::Mainnet).expect("p2pk render must succeed")
}

// ----- oracle parity -----

/// EIP-3 first address. CoinBarn / Yoroi / Scala all produce this
/// address for the test mnemonic at `m/44'/429'/0'/0/0` with modern
/// (post-1627) derivation. Source: `DerivationPathSpec.scala:33`
/// (assertion at line 41).
#[test]
fn modern_wallet_first_address_matches_coinbarn_yoroi() {
    let addr = address_for(DerivationPath::eip3_first_address());
    assert_eq!(
        addr, "9hAymcGaRfTX7bMADNdfWfk7CKzi2ZpvRBCmtEf6d92n8E26Ax7",
        "modern-wallet first address must match CoinBarn/Yoroi/Scala \
         (DerivationPathSpec.scala:33-41)",
    );
}

/// Pre-EIP-3 first address: same mnemonic, modern (post-1627) key
/// derivation, but legacy `m/1` path. Source:
/// `DerivationPathSpec.scala:65-68`.
#[test]
fn pre_eip3_first_address_matches_scala() {
    let addr = address_for(DerivationPath::pre_eip3_first_address());
    assert_eq!(
        addr, "9h7f11AC9RMHkhFbXg46XfYHq3HNnb1A9UtMmMYo6hAuQzWxVWu",
        "pre-EIP-3 first address must match Scala node-derived vector \
         (DerivationPathSpec.scala:65-68 — derived via nextPath with \
         usePreEip3Derivation=true; equals m/1)",
    );
}

/// Sanity: modern path and legacy path produce different addresses
/// from the same mnemonic. If this fails, one of the two path
/// derivations is silently no-op'ing.
#[test]
fn modern_and_pre_eip3_paths_diverge() {
    let modern = address_for(DerivationPath::eip3_first_address());
    let legacy = address_for(DerivationPath::pre_eip3_first_address());
    assert_ne!(modern, legacy);
}
