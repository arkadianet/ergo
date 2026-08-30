//! `ergo-wallet` CLI.
//!
//! Run via: `cargo run -p ergo-wallet --bin ergo-wallet -- <subcommand>`
//! After install: `ergo-wallet <subcommand>`.
//!
//! Subcommands:
//! - `generate [--strength 24]` — create a fresh mnemonic, print mnemonic + miner_public_key_hex
//! - `import [--mnemonic-file <path|-]` — validate + show miner_public_key_hex
//! - `derive [--mnemonic-file <path|-] --path "m/44'/429'/0'/0/N"` — show pubkey at custom path
//! - `pubkey [--mnemonic-file <path|-]` — print just the mining pubkey hex
//! - `address --pubkey <hex> [--network mainnet|testnet]` — pubkey → P2PK address
//!
//! The recovery phrase is read from `--mnemonic-file` (path or `-` for
//! stdin) or an interactive prompt. Passing it as a raw `--mnemonic` argv
//! value is possible for scripted use but is gated behind
//! `--dangerously-pass-mnemonic-via-argv`: argv is world-readable through
//! `/proc/<pid>/cmdline` for the process lifetime and persists in shell
//! history and CI logs (audit M-3).

use clap::{Parser, Subcommand, ValueEnum};
use ergo_ser::address::NetworkPrefix;
use ergo_wallet::address::pubkey_to_p2pk_address;
use ergo_wallet::derivation::DerivationPath;
use ergo_wallet::error::WalletError;
use ergo_wallet::extended_key::ExtendedSecretKey;
use ergo_wallet::mnemonic::{Mnemonic, MnemonicStrength};
use std::io::{Read, Write};
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(name = "ergo-wallet", version, about = "Ergo HD wallet CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh mnemonic + show mining pubkey.
    Generate(GenerateArgs),
    /// Validate an existing mnemonic + show mining pubkey.
    Import(ImportArgs),
    /// Derive a key at a custom path.
    Derive(DeriveArgs),
    /// Print only the mining pubkey hex.
    Pubkey(PubkeyArgs),
    /// Render a pubkey as a P2PK address.
    Address(AddressArgs),
}

#[derive(clap::Args, Debug)]
struct GenerateArgs {
    /// Word count: 12, 15, 18, 21, or 24.
    #[arg(long, default_value_t = 24)]
    strength: u8,
}

/// Recovery-phrase source (audit M-3). argv is world-readable through
/// `/proc/<pid>/cmdline` for the process lifetime, persists in shell
/// history, and is frequently captured by CI logs / crash reporters — the
/// recovery phrase is the highest-value secret in the system. The default
/// source is an interactive stdin prompt; scripts should pipe the phrase
/// via `--mnemonic-file` (`-` reads stdin).
#[derive(clap::Args, Debug)]
struct MnemonicSource {
    /// Read the recovery phrase from a file (`-` = stdin). Trailing
    /// whitespace/newline is trimmed.
    #[arg(long, value_name = "PATH")]
    mnemonic_file: Option<String>,

    /// Recovery phrase via argv. World-readable while the process runs
    /// (/proc/<pid>/cmdline) and persists in shell history / CI logs.
    /// Requires --dangerously-pass-mnemonic-via-argv.
    #[arg(long)]
    mnemonic: Option<String>,

    /// Explicit gate required to accept --mnemonic from argv.
    #[arg(long)]
    dangerously_pass_mnemonic_via_argv: bool,
}

impl MnemonicSource {
    /// Resolve the recovery phrase from the configured source, wrapped in
    /// `Zeroizing` so the buffer is wiped on drop.
    fn read(&self) -> Result<Zeroizing<String>, WalletError> {
        if let Some(path) = &self.mnemonic_file {
            let content = if path == "-" {
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .map_err(|e| WalletError::CliSecretSource(format!("stdin read failed: {e}")))?;
                buf
            } else {
                std::fs::read_to_string(path).map_err(|e| {
                    WalletError::CliSecretSource(format!("mnemonic file {path:?}: {e}"))
                })?
            };
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Err(WalletError::CliSecretSource(
                    "mnemonic source is empty".into(),
                ));
            }
            return Ok(Zeroizing::new(trimmed.to_string()));
        }

        if let Some(argv_phrase) = &self.mnemonic {
            if !self.dangerously_pass_mnemonic_via_argv {
                return Err(WalletError::CliSecretSource(
                    "refusing --mnemonic from argv: it is world-readable via /proc/<pid>/cmdline, \
                     persists in shell history, and is captured by CI logs. Pipe it instead: \
                     `--mnemonic-file -` (stdin) or `--mnemonic-file <path>`. If you truly need \
                     argv, pass --dangerously-pass-mnemonic-via-argv."
                        .into(),
                ));
            }
            let trimmed = argv_phrase.trim();
            if trimmed.is_empty() {
                return Err(WalletError::CliSecretSource(
                    "mnemonic source is empty".into(),
                ));
            }
            return Ok(Zeroizing::new(trimmed.to_string()));
        }

        // Default: interactive stdin prompt.
        eprint!("Enter recovery phrase (12-24 words), then press Enter: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| WalletError::CliSecretSource(format!("stdin read failed: {e}")))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(WalletError::CliSecretSource("no mnemonic entered".into()));
        }
        Ok(Zeroizing::new(trimmed.to_string()))
    }
}

#[derive(clap::Args, Debug)]
struct ImportArgs {
    #[command(flatten)]
    source: MnemonicSource,
    /// Optional BIP39 passphrase. Default is empty (matches mnemonics
    /// created without a passphrase). If your mnemonic was created
    /// with a passphrase, you MUST supply it here or this command
    /// will derive the WRONG wallet silently. NOTE: the passphrase is
    /// not spend-capable without the phrase, but it also transits argv —
    /// prefer piping the phrase and using an empty passphrase.
    #[arg(long, default_value = "")]
    passphrase: String,
}

#[derive(clap::Args, Debug)]
struct DeriveArgs {
    #[command(flatten)]
    source: MnemonicSource,
    /// BIP32 path, e.g. `m/44'/429'/0'/0/0`.
    #[arg(long, default_value = "m/44'/429'/0'/0/0")]
    path: String,
    /// Optional BIP39 passphrase. Default is empty (matches mnemonics
    /// created without a passphrase). If your mnemonic was created
    /// with a passphrase, you MUST supply it here or this command
    /// will derive the WRONG wallet silently. NOTE: the passphrase is
    /// not spend-capable without the phrase, but it also transits argv —
    /// prefer piping the phrase and using an empty passphrase.
    #[arg(long, default_value = "")]
    passphrase: String,
}

#[derive(clap::Args, Debug)]
struct PubkeyArgs {
    #[command(flatten)]
    source: MnemonicSource,
    /// Optional BIP39 passphrase. Default is empty (matches mnemonics
    /// created without a passphrase). If your mnemonic was created
    /// with a passphrase, you MUST supply it here or this command
    /// will derive the WRONG wallet silently. NOTE: the passphrase is
    /// not spend-capable without the phrase, but it also transits argv —
    /// prefer piping the phrase and using an empty passphrase.
    #[arg(long, default_value = "")]
    passphrase: String,
}

#[derive(clap::Args, Debug)]
struct AddressArgs {
    /// 33-byte compressed SEC1 pubkey hex.
    #[arg(long)]
    pubkey: String,
    /// `mainnet` or `testnet`.
    #[arg(long, default_value_t = Network::Mainnet)]
    network: Network,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => f.write_str("mainnet"),
            Self::Testnet => f.write_str("testnet"),
        }
    }
}

impl Network {
    fn prefix(self) -> NetworkPrefix {
        match self {
            Self::Mainnet => NetworkPrefix::Mainnet,
            Self::Testnet => NetworkPrefix::Testnet,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cmd: Cmd) -> Result<(), WalletError> {
    match cmd {
        Cmd::Generate(a) => generate(a),
        Cmd::Import(a) => import(a),
        Cmd::Derive(a) => derive(a),
        Cmd::Pubkey(a) => pubkey(a),
        Cmd::Address(a) => address(a),
    }
}

fn generate(a: GenerateArgs) -> Result<(), WalletError> {
    let strength = match a.strength {
        12 => MnemonicStrength::Words12,
        15 => MnemonicStrength::Words15,
        18 => MnemonicStrength::Words18,
        21 => MnemonicStrength::Words21,
        24 => MnemonicStrength::Words24,
        n => return Err(WalletError::UnsupportedWordCount(n as usize)),
    };
    let m = Mnemonic::generate(strength)?;
    let seed = Zeroizing::new(m.to_seed(""));
    let pk = ergo_wallet::miner_pubkey_for_seed(seed.as_ref())?;
    let pk_hex = hex::encode(pk);

    println!("{}-word mnemonic:", a.strength);
    println!();
    println!("    {}", m.phrase());
    println!();
    println!("miner_public_key_hex (paste into [mining] in ergo-node.toml):");
    println!();
    println!("    {pk_hex}");
    println!();
    println!("SAVE THE MNEMONIC. The node does not retain it; this output is");
    println!("the only copy. Anyone with these words can spend your funds.");
    Ok(())
}

fn import(a: ImportArgs) -> Result<(), WalletError> {
    let phrase = a.source.read()?;
    let m = Mnemonic::import(&phrase)?;
    let seed = Zeroizing::new(m.to_seed(&a.passphrase));
    let pk = ergo_wallet::miner_pubkey_for_seed(seed.as_ref())?;
    println!("Mnemonic validates.");
    println!("miner_public_key_hex: {}", hex::encode(pk));
    println!();
    println!("(post-1627 derivation — modern Ergo wallets. Pre-1627 legacy");
    println!(" `usePre1627KeyDerivation`-aware import is not yet supported.)");
    Ok(())
}

fn derive(a: DeriveArgs) -> Result<(), WalletError> {
    let phrase = a.source.read()?;
    let m = Mnemonic::import(&phrase)?;
    let seed = Zeroizing::new(m.to_seed(&a.passphrase));
    let master = ExtendedSecretKey::derive_master_key(seed.as_ref(), false)?;
    let path: DerivationPath = a.path.parse()?;
    let leaf = master.derive_at_path(&path)?;
    let pk_hex = hex::encode(leaf.public_key().compressed_bytes());
    println!("path: {path}");
    println!("pubkey: {pk_hex}");
    Ok(())
}

fn pubkey(a: PubkeyArgs) -> Result<(), WalletError> {
    let phrase = a.source.read()?;
    let m = Mnemonic::import(&phrase)?;
    let seed = Zeroizing::new(m.to_seed(&a.passphrase));
    let pk = ergo_wallet::miner_pubkey_for_seed(seed.as_ref())?;
    // Single line, 66-char hex. Shell-pipe-friendly. Post-1627 only;
    // pre-1627 legacy wallet support not yet implemented.
    println!("{}", hex::encode(pk));
    Ok(())
}

fn address(a: AddressArgs) -> Result<(), WalletError> {
    let bytes = hex::decode(&a.pubkey)?;
    let arr: [u8; 33] = bytes.try_into().map_err(|v: Vec<u8>| {
        WalletError::InvalidPublicKey(format!("pubkey must be 33 bytes, got {}", v.len(),))
    })?;
    let addr = pubkey_to_p2pk_address(&arr, a.network.prefix())?;
    println!("{addr}");
    Ok(())
}
