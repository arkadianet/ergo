//! Scala-generated wallet-file round-trip oracle.
//!
//! Loads actual JSON files produced by a Scala node and verifies our
//! storage layer decrypts them correctly. If this fails, we'd
//! silently break wallet imports for every existing Scala-using
//! operator on the network.
//!
//! Fixtures live in `tests/fixtures/`. Each fixture has a known
//! mnemonic + password + first-address triple, asserted below.

use ergo_wallet::storage::SecretStorage;

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

// ----- oracle parity -----

#[test]
#[ignore = "requires Scala node fixture — engineer extracts scala_modern_v6.json before un-ignoring"]
fn load_scala_modern_wallet_and_match_known_address() {
    // The "modern" fixture was generated with the same mnemonic +
    // password as the embedded `DerivationPathSpec.scala` test
    // vector — so the resulting first address is known.
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        format!("{FIXTURE_DIR}/scala_modern_v6.json"),
        dir.path().join("scala_modern_v6.json"),
    )
    .expect("fixture file must exist");

    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    storage
        .unlock("test-password")
        .expect("Scala modern wallet must unlock with known password");

    let unlocked = storage.unlocked().expect("just unlocked");
    let pk = unlocked
        .master
        .derive_pubkey_at_path(&ergo_wallet::DerivationPath::eip3_first_address())
        .unwrap();
    let addr = ergo_wallet::address::pubkey_to_p2pk_address(
        &pk,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
    .unwrap();
    assert_eq!(
        addr, "9hAymcGaRfTX7bMADNdfWfk7CKzi2ZpvRBCmtEf6d92n8E26Ax7",
        "Scala-generated modern wallet must decrypt to the CoinBarn/Yoroi-verified address",
    );
}

#[test]
#[ignore = "requires Scala node fixture — engineer extracts scala_pre_eip3_no_flag.json before un-ignoring"]
fn load_scala_pre_eip3_defaults_field_to_true() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        format!("{FIXTURE_DIR}/scala_pre_eip3_no_flag.json"),
        dir.path().join("scala_pre_eip3_no_flag.json"),
    )
    .unwrap();

    // Verify the field defaults to `true` when missing from the JSON.
    let path = SecretStorage::find_secret_file(dir.path()).unwrap();
    let json = std::fs::read_to_string(&path).unwrap();
    let parsed: ergo_wallet::storage::EncryptedSecret = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.use_pre_1627_key_derivation,
        "field missing → defaults to true per spec §5.1",
    );
}

#[test]
fn save_then_reload_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    storage
        .restore(phrase, /* mnemonic_pass */ "", "pw", false)
        .unwrap();

    // Now re-open the storage and unlock — should work.
    let mut storage2 = SecretStorage::open(dir.path().to_path_buf());
    storage2
        .unlock("pw")
        .expect("re-opened storage must unlock");
    assert!(storage2.check_seed(phrase, ""));
}

#[test]
#[ignore = "requires Scala node — engineer extracts fixture before un-ignoring"]
fn rust_generated_file_unlocks_under_scala_node() {
    // Bidirectional Scala-compat test: engineer runs this Rust-side
    // flow, copies the resulting <uuid>.json into a Scala node's
    // wallet directory, runs `POST /wallet/unlock`, and verifies the
    // Scala node decrypts + uses the seed correctly.
    let dir = tempfile::tempdir().unwrap();
    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    storage
        .restore(phrase, "", "test-rust-to-scala-pw", false)
        .unwrap();

    // The fixture is now at `dir.path()/<uuid>.json`. The engineer
    // copies this file to a Scala node's wallet dir, edits the node's
    // config to point at that dir, runs POST /wallet/unlock with
    // password = "test-rust-to-scala-pw", and verifies the resulting
    // wallet's first address matches
    // `9hAymcGaRfTX7bMADNdfWfk7CKzi2ZpvRBCmtEf6d92n8E26Ax7`
    // (the canonical CoinBarn/Yoroi/Scala vector).
    println!(
        "Fixture written to: {:?} — copy to Scala node wallet dir for manual verification",
        dir.path(),
    );
}
