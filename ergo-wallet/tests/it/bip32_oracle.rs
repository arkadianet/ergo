//! BIP32 standard test vectors beyond the inline ones in
//! src/extended_key.rs. Source:
//! https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use ergo_wallet::derivation::DerivationPath;
use ergo_wallet::extended_key::ExtendedSecretKey;

// ----- oracle parity -----

/// BIP32 Vector 1, m/0'/1/2'. Expected secret:
/// cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca
#[test]
fn bip32_vector_1_three_step_path() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
    let path: DerivationPath = "m/0'/1/2'".parse().unwrap();
    let leaf = master
        .derive_at_path(&path)
        .expect("vector 1 m/0'/1/2' must derive");
    assert_eq!(
        hex::encode(leaf.secret_bytes()),
        "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
    );
}

/// BIP32 Vector 2 master. Seed (64 bytes, counting-down by 3):
/// fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
/// 9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
/// Expected master secret: 4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e
#[test]
fn bip32_vector_2_master() {
    let seed = hex::decode(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    ).unwrap();
    let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
    assert_eq!(
        hex::encode(master.secret_bytes()),
        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
    );
}
