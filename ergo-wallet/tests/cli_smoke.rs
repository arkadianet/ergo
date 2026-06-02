//! Smoke tests for the `ergo-wallet` CLI binary. Drives the actual
//! compiled binary via `assert_cmd` — covers the end-to-end argument
//! parsing + dispatch path that unit tests skip.

use assert_cmd::Command;
use predicates::str;

// ----- happy path -----

#[test]
fn generate_24_words_prints_mnemonic_and_pubkey() {
    let output = Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["generate", "--strength", "24"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(output).unwrap();
    let word_count = s
        .lines()
        .find(|l| l.split_whitespace().count() >= 12)
        .expect("mnemonic line present")
        .split_whitespace()
        .count();
    assert_eq!(word_count, 24);
    assert!(
        s.contains("miner_public_key_hex"),
        "output must label the pubkey for paste-into-toml ergonomics",
    );
}

#[test]
fn pubkey_subcommand_outputs_66_chars_then_newline() {
    let output = Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args([
            "pubkey",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(output).unwrap();
    let trimmed = s.trim_end();
    assert_eq!(
        trimmed.len(),
        66,
        "pubkey subcommand prints exactly 66 hex chars (33 bytes compressed)",
    );
}

#[test]
fn derive_at_custom_path_prints_path_and_pubkey() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args([
            "derive",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
            "--path",
            "m/44'/429'/0'/0/3",
        ])
        .assert()
        .success()
        .stdout(str::contains("path: m/44'/429'/0'/0/3"))
        .stdout(str::contains("pubkey: "));
}

#[test]
fn address_mainnet_starts_with_9() {
    // First derive a pubkey, then feed it to address.
    let pk_out = Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args([
            "pubkey",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let pk_hex = String::from_utf8(pk_out).unwrap().trim_end().to_string();

    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["address", "--pubkey", &pk_hex, "--network", "mainnet"])
        .assert()
        .success()
        .stdout(str::starts_with("9"));
}

#[test]
fn pubkey_with_passphrase_differs_from_empty() {
    // Same mnemonic, different passphrases → different pubkeys.
    // Regression guard: the CLI MUST honour --passphrase rather than
    // hard-coding it empty.
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let without = String::from_utf8(
        Command::cargo_bin("ergo-wallet")
            .unwrap()
            .args(["pubkey", "--mnemonic", mnemonic])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim_end()
    .to_string();
    let with_pass = String::from_utf8(
        Command::cargo_bin("ergo-wallet")
            .unwrap()
            .args(["pubkey", "--mnemonic", mnemonic, "--passphrase", "TREZOR"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim_end()
    .to_string();
    assert_ne!(
        without, with_pass,
        "--passphrase must actually change the derivation (regression \
         guard against silently hard-coding passphrase empty)",
    );
    assert_eq!(without.len(), 66);
    assert_eq!(with_pass.len(), 66);
}

// ----- error paths -----

#[test]
fn import_with_bad_checksum_exits_nonzero() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args([
            "import",
            "--mnemonic",
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon",
        ])
        .assert()
        .failure()
        .stderr(str::contains("error:"));
}

#[test]
fn unknown_subcommand_exits_nonzero_with_clap_message() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["wat"])
        .assert()
        .failure();
}
