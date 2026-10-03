//! Scala-produced files and bidirectional wallet interoperability.
use ergo_wallet::storage::SecretStorage;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../test-vectors/wallet/scala_6_0_6.json"
    ))
    .unwrap()
}

#[test]
fn scala_modern_wallet_unlocks_and_matches_scala_address() {
    let oracle = fixture();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("modern.json"), oracle["modern"].to_string()).unwrap();
    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    storage.unlock("test-password").unwrap();
    let pk = storage
        .unlocked()
        .unwrap()
        .master
        .derive_pubkey_at_path(&ergo_wallet::DerivationPath::eip3_first_address())
        .unwrap();
    let address = ergo_wallet::address::pubkey_to_p2pk_address(
        &pk,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
    .unwrap();
    assert_eq!(address, oracle["modernAddress"].as_str().unwrap());
}

#[test]
fn scala_legacy_null_and_missing_flags_use_legacy_derivation() {
    let oracle = fixture();
    for missing in [false, true] {
        let mut file = oracle["legacy"].clone();
        if missing {
            file.as_object_mut()
                .unwrap()
                .remove("usePre1627KeyDerivation");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("legacy.json"), file.to_string()).unwrap();
        let mut storage = SecretStorage::open(dir.path().to_path_buf());
        storage.unlock("test-password").unwrap();
        assert!(storage.unlocked().unwrap().use_pre_1627);
    }
}

#[test]
fn previous_rust_field_layout_still_unlocks() {
    let mut oracle = fixture()["modern"].clone();
    let mut joined = hex::decode(oracle["authTag"].as_str().unwrap()).unwrap();
    joined.extend(hex::decode(oracle["cipherText"].as_str().unwrap()).unwrap());
    let split = joined.len() - 16;
    oracle["cipherText"] = hex::encode(&joined[..split]).into();
    oracle["authTag"] = hex::encode(&joined[split..]).into();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("previous-rust.json"), oracle.to_string()).unwrap();
    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    storage.unlock("test-password").unwrap();
}

#[test]
fn rust_generated_file_exports_for_scala_verification() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    storage
        .restore(phrase, "", "test-rust-to-scala-pw", false)
        .unwrap();
    let path = SecretStorage::find_secret_file(dir.path()).unwrap();
    let mut reopened = SecretStorage::open(dir.path().to_path_buf());
    reopened.unlock("test-rust-to-scala-pw").unwrap();
    assert!(reopened.check_seed(phrase, ""));
    // The JVM CI leg supplies a persistent path, then independently unlocks
    // this exact Rust-produced file with Scala JsonSecretStorage.
    if let Some(output) = std::env::var_os("ERGO_WALLET_INTEROP_FILE") {
        std::fs::copy(path, output).unwrap();
    }
}
