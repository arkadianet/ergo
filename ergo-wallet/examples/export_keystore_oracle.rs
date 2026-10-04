//! Export the public test mnemonic as a Rust keystore for the Appkit oracle.
//! Usage: cargo run -p ergo-wallet --example export_keystore_oracle -- <empty-directory>

use ergo_wallet::storage::SecretStorage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = std::env::args_os()
        .nth(1)
        .ok_or("missing output directory")?;
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../test-vectors/scala/wallet/keystore_appkit_6_0_1.json"
    ))?;
    let destination = std::path::PathBuf::from(destination);
    let mut storage = SecretStorage::open(destination.clone());
    storage.restore(
        oracle["mnemonic"].as_str().unwrap(),
        "",
        oracle["password"].as_str().unwrap(),
        false,
    )?;
    println!(
        "{}",
        SecretStorage::find_secret_file(&destination)?.display()
    );
    Ok(())
}
