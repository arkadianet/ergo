//! Smoke tests for the `ergo-wallet` CLI binary. Drives the actual
//! compiled binary via `assert_cmd` — covers the end-to-end argument
//! parsing + dispatch path that unit tests skip.
//!
//! Recovery-phrase sources (audit M-3): the safe paths pipe the phrase
//! via `--mnemonic-file -` (stdin) or an interactive prompt; raw argv is
//! gated behind `--dangerously-pass-mnemonic-via-argv` and covered by its
//! own tests below.

use assert_cmd::Command;
use predicates::str;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about";

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
        .args(["pubkey", "--mnemonic-file", "-"])
        .write_stdin(MNEMONIC)
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
            "--mnemonic-file",
            "-",
            "--path",
            "m/44'/429'/0'/0/3",
        ])
        .write_stdin(MNEMONIC)
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
        .args(["pubkey", "--mnemonic-file", "-"])
        .write_stdin(MNEMONIC)
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
    let without = String::from_utf8(
        Command::cargo_bin("ergo-wallet")
            .unwrap()
            .args(["pubkey", "--mnemonic-file", "-"])
            .write_stdin(MNEMONIC)
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
            .args(["pubkey", "--mnemonic-file", "-", "--passphrase", "TREZOR"])
            .write_stdin(MNEMONIC)
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

/// Interactive prompt is the DEFAULT source: no --mnemonic-file, no
/// --mnemonic — the phrase arrives on stdin either way (the prompt reads
/// a line; piping satisfies it).
#[test]
fn default_source_reads_stdin_prompt() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["pubkey"])
        .write_stdin(MNEMONIC)
        .assert()
        .success()
        .stdout(str::contains(
            "02b7da363cb84d41d10193c97e4fcdc35189e12ff963e39f386aba766fa796ea50",
        ));
}

// ----- gated argv (audit M-3) -----

/// `--mnemonic` WITHOUT the gate must be refused with an actionable
/// message naming the safe alternatives.
#[test]
fn mnemonic_argv_without_gate_is_refused() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["pubkey", "--mnemonic", MNEMONIC])
        .assert()
        .failure()
        .stderr(str::contains("refusing --mnemonic from argv"))
        .stderr(str::contains("--mnemonic-file"));
}

/// The gate is validated BEFORE source selection: `--mnemonic-file` must
/// not launder an ungated argv phrase (the argv exposure exists regardless
/// of which source wins).
#[test]
fn mnemonic_argv_without_gate_refused_even_with_file() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["pubkey", "--mnemonic", MNEMONIC, "--mnemonic-file", "-"])
        .write_stdin(MNEMONIC)
        .assert()
        .failure()
        .stderr(str::contains("refusing --mnemonic from argv"));
}

/// Supplying both sources is a conflict — silently picking one would
/// hide which phrase was actually used.
#[test]
fn conflicting_sources_are_refused() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args([
            "pubkey",
            "--mnemonic",
            MNEMONIC,
            "--dangerously-pass-mnemonic-via-argv",
            "--mnemonic-file",
            "-",
        ])
        .write_stdin(MNEMONIC)
        .assert()
        .failure()
        .stderr(str::contains("conflicting mnemonic sources"));
}

/// The explicit gate keeps scripted argv use possible — same pubkey as
/// the stdin path (semantics unchanged, only the source differs).
#[test]
fn mnemonic_argv_with_gate_matches_stdin_path() {
    let via_argv = String::from_utf8(
        Command::cargo_bin("ergo-wallet")
            .unwrap()
            .args([
                "pubkey",
                "--mnemonic",
                MNEMONIC,
                "--dangerously-pass-mnemonic-via-argv",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    let via_stdin = String::from_utf8(
        Command::cargo_bin("ergo-wallet")
            .unwrap()
            .args(["pubkey", "--mnemonic-file", "-"])
            .write_stdin(MNEMONIC)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert_eq!(via_argv, via_stdin);
}

// ----- error paths -----

#[test]
fn import_with_bad_checksum_exits_nonzero() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["import", "--mnemonic-file", "-"])
        .write_stdin(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon",
        )
        .assert()
        .failure()
        .stderr(str::contains("error:"));
}

#[test]
fn empty_mnemonic_source_is_refused() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["pubkey", "--mnemonic-file", "-"])
        .write_stdin("   \n")
        .assert()
        .failure()
        .stderr(str::contains("mnemonic source is empty"));
}

#[test]
fn unknown_subcommand_exits_nonzero_with_clap_message() {
    Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["wat"])
        .assert()
        .failure();
}
