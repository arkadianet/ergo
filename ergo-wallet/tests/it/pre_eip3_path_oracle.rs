//! Scala-parity tests for pre-EIP-3 vs post-EIP-3 derivation path
//! selection. Source of truth:
//! `C:/Users/Chace/arkadianet/reference/ergo/ergo-wallet/src/test/scala/
//!  org/ergoplatform/wallet/secrets/DerivationPathSpec.scala:65`

use ergo_wallet::derivation::{DerivationPath, ERGO_COIN_TYPE, HARDENED_OFFSET};

// ----- oracle parity -----

#[test]
fn pre_eip3_first_address_matches_scala() {
    let p = DerivationPath::pre_eip3_first_address();
    assert_eq!(
        p.components(),
        &[1],
        "pre-EIP-3 first-address path must be m/1 (the old non-BIP44 \
         scheme); confirmed against Scala DerivationPathSpec.scala line 90 \
         (preEip3DerivationPath = DerivationPath(Array(0, 1), publicBranch=false), \
         external string form = m/1)",
    );
    assert_eq!(format!("{p}"), "m/1");
}

#[test]
fn eip3_first_address_matches_scala() {
    let p = DerivationPath::eip3_first_address();
    assert_eq!(
        p.components(),
        &[
            HARDENED_OFFSET | 44,
            HARDENED_OFFSET | ERGO_COIN_TYPE,
            HARDENED_OFFSET,
            0,
            0,
        ],
        "EIP-3 first-address path must be m/44'/429'/0'/0/0",
    );
}

#[test]
fn ergo_coin_type_is_429() {
    assert_eq!(ERGO_COIN_TYPE, 429, "Ergo BIP44 coin type per SLIP-0044");
}
