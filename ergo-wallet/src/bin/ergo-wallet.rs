//! `ergo-wallet` CLI.
//!
//! Run via: `cargo run -p ergo-wallet --bin ergo-wallet -- <subcommand>`
//! After install: `ergo-wallet <subcommand>`.
//!
//! Subcommands:
//! - `generate [--strength 24]` — create a fresh mnemonic, print mnemonic + miner_public_key_hex
//! - `import --mnemonic "<words>"` — validate + show miner_public_key_hex
//! - `derive --mnemonic "<words>" --path "m/44'/429'/0'/0/N"` — show pubkey at custom path
//! - `pubkey --mnemonic "<words>"` — print just the mining pubkey hex
//! - `address --pubkey <hex> [--network mainnet|testnet]` — pubkey → P2PK address

use clap::{Parser, Subcommand, ValueEnum};
use ergo_ser::address::NetworkPrefix;
use ergo_wallet::address::pubkey_to_p2pk_address;
use ergo_wallet::derivation::DerivationPath;
use ergo_wallet::error::WalletError;
use ergo_wallet::extended_key::ExtendedSecretKey;
use ergo_wallet::mnemonic::{Mnemonic, MnemonicStrength};
use std::process::ExitCode;

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

#[derive(clap::Args, Debug)]
struct ImportArgs {
    #[arg(long)]
    mnemonic: String,
    /// Optional BIP39 passphrase. Default is empty (matches mnemonics
    /// created without a passphrase). If your mnemonic was created
    /// with a passphrase, you MUST supply it here or this command
    /// will derive the WRONG wallet silently.
    #[arg(long, default_value = "")]
    passphrase: String,
}

#[derive(clap::Args, Debug)]
struct DeriveArgs {
    #[arg(long)]
    mnemonic: String,
    /// BIP32 path, e.g. `m/44'/429'/0'/0/0`.
    #[arg(long, default_value = "m/44'/429'/0'/0/0")]
    path: String,
    /// Optional BIP39 passphrase. Default is empty (matches mnemonics
    /// created without a passphrase). If your mnemonic was created
    /// with a passphrase, you MUST supply it here or this command
    /// will derive the WRONG wallet silently.
    #[arg(long, default_value = "")]
    passphrase: String,
}

#[derive(clap::Args, Debug)]
struct PubkeyArgs {
    #[arg(long)]
    mnemonic: String,
    /// Optional BIP39 passphrase. Default is empty (matches mnemonics
    /// created without a passphrase). If your mnemonic was created
    /// with a passphrase, you MUST supply it here or this command
    /// will derive the WRONG wallet silently.
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
    let seed = m.to_seed("");
    let pk = ergo_wallet::miner_pubkey_for_seed(&seed)?;
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
    let m = Mnemonic::import(&a.mnemonic)?;
    let seed = m.to_seed(&a.passphrase);
    let pk = ergo_wallet::miner_pubkey_for_seed(&seed)?;
    println!("Mnemonic validates.");
    println!("miner_public_key_hex: {}", hex::encode(pk));
    println!();
    println!("(post-1627 derivation — modern Ergo wallets. Pre-1627 legacy");
    println!(" `usePre1627KeyDerivation`-aware import is not yet supported.)");
    Ok(())
}

fn derive(a: DeriveArgs) -> Result<(), WalletError> {
    let m = Mnemonic::import(&a.mnemonic)?;
    let seed = m.to_seed(&a.passphrase);
    let master = ExtendedSecretKey::derive_master_key(&seed, false)?;
    let path: DerivationPath = a.path.parse()?;
    let leaf = master.derive_at_path(&path)?;
    let pk_hex = hex::encode(leaf.public_key().compressed_bytes());
    println!("path: {path}");
    println!("pubkey: {pk_hex}");
    Ok(())
}

fn pubkey(a: PubkeyArgs) -> Result<(), WalletError> {
    let m = Mnemonic::import(&a.mnemonic)?;
    let seed = m.to_seed(&a.passphrase);
    let pk = ergo_wallet::miner_pubkey_for_seed(&seed)?;
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
