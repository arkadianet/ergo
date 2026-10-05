//! New-install setup, dispatched before the node runtime. Planning is read-only.

use std::fs;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use clap::{Args, ValueEnum};
use serde::Serialize;

use crate::api_key::GeneratedKey;
use crate::config::NodeConfig;

const GIB: u64 = 1024 * 1024 * 1024;
const PLAN_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const FAST_CAVEAT: &str = "Fast sync downloads a UTXO snapshot and NiPoPoW proof, avoiding hours-to-days historical replay; download time depends on peers and bandwidth. Snapshot trust is provisional: cross-check the UTXO root against an independently trusted node before relying on it.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    Wallet,
    MiningFast,
    MiningFull,
    Explorer,
    Archival,
}

impl Preset {
    fn mining(self) -> bool {
        matches!(self, Self::MiningFast | Self::MiningFull)
    }
    fn indexer(self) -> bool {
        matches!(self, Self::Explorer | Self::MiningFull)
    }
    fn supports_fast(self) -> bool {
        matches!(self, Self::Wallet | Self::MiningFast)
    }
    fn budget(self, sync: Sync) -> u64 {
        if self.indexer() {
            250
        } else if sync == Sync::Fast {
            100
        } else {
            150
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sync {
    Fast,
    Genesis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Reward {
    Wallet,
    PublicKey,
}

#[derive(Args, Clone, Debug)]
pub struct InitArgs {
    #[arg(long, value_enum)]
    pub preset: Option<Preset>,
    #[arg(long, value_enum)]
    pub sync: Option<Sync>,
    /// Explicitly accept provisional snapshot trust; cross-check the UTXO root.
    #[arg(long)]
    pub accept_unanchored_bootstrap: bool,
    #[arg(long, value_enum)]
    pub network: Option<Network>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:9099")]
    pub api_bind: SocketAddr,
    #[arg(long)]
    pub p2p_bind: Option<SocketAddr>,
    #[arg(long)]
    pub declared_addr: Option<SocketAddr>,
    #[arg(long, value_enum)]
    pub reward: Option<Reward>,
    #[arg(long)]
    pub miner_public_key: Option<String>,
    #[arg(long)]
    pub allow_low_disk: bool,
    #[arg(long)]
    pub non_interactive: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("init: {message}")]
pub struct InitError {
    message: String,
    code: i32,
}
impl InitError {
    pub fn exit_code(&self) -> i32 {
        self.code
    }
}
type Result<T> = std::result::Result<T, InitError>;
fn invalid(message: impl Into<String>) -> InitError {
    InitError {
        message: message.into(),
        code: 2,
    }
}
fn failure(message: impl Into<String>) -> InitError {
    InitError {
        message: message.into(),
        code: 1,
    }
}
impl From<io::Error> for InitError {
    fn from(error: io::Error) -> Self {
        failure(format!("I/O failure: {error}"))
    }
}

#[derive(Serialize)]
struct Plan {
    schema_version: u32,
    dry_run: bool,
    preset: Preset,
    sync: Sync,
    network: Network,
    config_path: PathBuf,
    data_dir: PathBuf,
    key_file: PathBuf,
    config_contents: String,
    reward_address: Option<String>,
    free_bytes: Option<u64>,
    recommended_free_space_bytes: u64,
    warnings: Vec<String>,
    start_command: String,
    dashboard_url: String,
    next_steps: Vec<String>,
}

pub fn run(
    args: &InitArgs,
    tty: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<()> {
    run_with_space(args, tty, input, output, diagnostics, free_space)
}

fn run_with_space(
    args: &InitArgs,
    tty: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    disk: impl FnOnce(&Path) -> Option<u64>,
) -> Result<()> {
    let mut args = args.clone();
    let interactive = tty && !args.non_interactive;
    if interactive {
        if args.preset.is_none() {
            writeln!(diagnostics, "wallet: wallet and transaction relay, without historical indexing; fast or hours-to-days genesis sync.\nmining-fast: external mining without storage-rent claims or indexing; fast or genesis sync.\nmining-full: external mining including storage-rent claims and indexing; requires hours-to-days genesis sync.\nexplorer: historical transaction indexing; requires genesis sync plus index catch-up.\narchival: full historical blocks and transaction relay without indexing; requires genesis sync.")?;
            args.preset = Some(choice(
                input,
                diagnostics,
                "Preset",
                &[
                    "wallet",
                    "mining-fast",
                    "mining-full",
                    "explorer",
                    "archival",
                ],
            )?);
        }
        if args.network.is_none() {
            writeln!(diagnostics, "mainnet: the live Ergo network, with real ERG. testnet: a separate network for testing, with no mainnet funds.")?;
            args.network = Some(choice(
                input,
                diagnostics,
                "Network",
                &["mainnet", "testnet"],
            )?);
        }
        if args.sync.is_none() {
            writeln!(diagnostics, "{FAST_CAVEAT}\nGenesis sync verifies the chain from the beginning and takes hours to days. Historical indexing requires genesis sync.")?;
            let allowed: &[&str] = if args.preset.is_some_and(Preset::supports_fast) {
                &["fast", "genesis"]
            } else {
                &["genesis"]
            };
            args.sync = Some(choice(input, diagnostics, "Sync", allowed)?);
        }
        if args.preset.is_some_and(Preset::mining) && args.reward.is_none() {
            writeln!(diagnostics, "wallet: rewards use the node wallet; initialize and unlock it before work can be served. public-key: rewards go to your compressed public key; keep its private key in your own wallet.")?;
            args.reward = Some(choice(
                input,
                diagnostics,
                "Mining reward",
                &["wallet", "public-key"],
            )?);
        }
        if args.reward == Some(Reward::PublicKey) && args.miner_public_key.is_none() {
            args.miner_public_key = Some(prompt(
                input,
                diagnostics,
                "Compressed miner public key (66 hex characters)",
            )?);
        }
    }
    let mut missing = Vec::new();
    if args.preset.is_none() {
        missing.push("--preset");
    }
    if args.sync.is_none() {
        missing.push("--sync");
    }
    if args.network.is_none() {
        missing.push("--network");
    }
    if args.preset.is_some_and(Preset::mining) && args.reward.is_none() {
        missing.push("--reward");
    }
    if args.reward == Some(Reward::PublicKey) && args.miner_public_key.is_none() {
        missing.push("--miner-public-key");
    }
    if !missing.is_empty() {
        return Err(invalid(format!(
            "missing required choices: {}",
            missing.join(", ")
        )));
    }
    let preset = args.preset.expect("checked");
    let sync = args.sync.expect("checked");
    let network = args.network.expect("checked");
    if sync == Sync::Fast && !preset.supports_fast() {
        return Err(invalid("this preset requires --sync genesis"));
    }
    if !preset.mining() && (args.reward.is_some() || args.miner_public_key.is_some()) {
        return Err(invalid(
            "--reward and --miner-public-key require a mining preset",
        ));
    }
    if args.reward == Some(Reward::Wallet) && args.miner_public_key.is_some() {
        return Err(invalid("--miner-public-key requires --reward public-key"));
    }
    let cwd = std::env::current_dir()?;
    let data_dir = absolute(
        args.data_dir.as_deref().unwrap_or(Path::new("./ergo-data")),
        &cwd,
    )?;
    let config_path = absolute(
        args.config
            .as_deref()
            .unwrap_or(&data_dir.join("ergo-node.toml")),
        &cwd,
    )?;
    let config_dir = config_path
        .parent()
        .ok_or_else(|| invalid("config path must name a file"))?;
    let secrets_dir = config_dir.join("secrets");
    let key_file = secrets_dir.join("api-key");
    absent(
        &config_path,
        "v1 creates new configs only; config path already exists",
    )?;
    absent(&key_file, "API key file already exists")?;
    check_secrets_dir(&secrets_dir)?;
    if sync == Sync::Fast && data_dir.exists() && fs::read_dir(&data_dir)?.next().is_some() {
        return Err(invalid(
            "fast sync requires a new or empty data directory; existing node data is refused",
        ));
    }
    if sync == Sync::Fast && !args.accept_unanchored_bootstrap {
        if !interactive {
            return Err(invalid(format!(
                "{FAST_CAVEAT} Requires --accept-unanchored-bootstrap."
            )));
        }
        writeln!(diagnostics, "{FAST_CAVEAT}")?;
        if !confirm(input, diagnostics, "Accept provisional snapshot trust")? {
            return Err(invalid("fast bootstrap consent declined"));
        }
    }
    let reward_address = if let Some(key) = &args.miner_public_key {
        let bytes =
            hex::decode(key).map_err(|_| invalid("--miner-public-key must be valid hex"))?;
        if bytes.len() != 33
            || !matches!(bytes.first(), Some(2 | 3))
            || k256::PublicKey::from_sec1_bytes(&bytes).is_err()
        {
            return Err(invalid("--miner-public-key must be a valid compressed secp256k1 point (33 bytes, 02/03 prefix)"));
        }
        let prefix = match network {
            Network::Mainnet => ergo_ser::address::NetworkPrefix::Mainnet,
            Network::Testnet => ergo_ser::address::NetworkPrefix::Testnet,
        };
        let pk: [u8; 33] = bytes.try_into().expect("checked length");
        let address = ergo_ser::address::encode_p2pk_from_pubkey(prefix, &pk)
            .map_err(|e| invalid(format!("reward address: {e}")))?;
        if interactive {
            writeln!(diagnostics, "Reward P2PK address ({network:?}): {address}")?;
            if !confirm(input, diagnostics, "Confirm this reward address")? {
                return Err(invalid("reward address declined"));
            }
        }
        Some(address)
    } else {
        None
    };
    let contents = config_contents(&args, &data_dir, PLAN_HASH)?;
    NodeConfig::from_toml(&contents).map_err(invalid)?;
    let free_bytes = disk(&data_dir);
    let recommended = preset.budget(sync) * GIB;
    let mut warnings = Vec::new();
    match free_bytes {
        Some(free) if free < recommended => {
            let warning = format!(
                "Free space: {:.1} GiB; recommended free space (provisional): {} GiB.",
                free as f64 / GIB as f64,
                preset.budget(sync)
            );
            writeln!(diagnostics, "Warning: {warning}")?;
            warnings.push(warning);
            if !args.allow_low_disk
                && !(interactive && confirm(input, diagnostics, "Continue with low disk space")?)
            {
                return Err(invalid(
                    "low disk space requires --allow-low-disk or interactive confirmation",
                ));
            }
        }
        None => {
            let warning =
                "Free space: unknown; recommended free space (provisional) could not be checked.";
            writeln!(diagnostics, "Warning: {warning}")?;
            warnings.push(warning.into());
        }
        _ => {}
    }
    if sync == Sync::Fast {
        warnings.push(FAST_CAVEAT.into());
    }
    let start_command = start_command(&config_path, &data_dir)?;
    let mut dashboard_bind = args.api_bind;
    if dashboard_bind.ip().is_unspecified() {
        dashboard_bind.set_ip(if dashboard_bind.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        });
    }
    let dashboard_url = format!("http://{dashboard_bind}/");
    if !args.api_bind.ip().is_loopback() {
        let warning = "The requested API bind enables [api] public_bind: privileged routes require the API key, but transaction submission remains publicly callable.";
        writeln!(diagnostics, "Warning: {warning}")?;
        warnings.push(warning.into());
    }
    let mut next_steps = vec![format!("Start: {start_command}"), format!("Dashboard: {dashboard_url}"), format!("API key file: {}. Send its contents in the api_key header or enter them in the dashboard; never send the hash.", key_file.display())];
    if preset == Preset::Wallet || args.reward == Some(Reward::Wallet) {
        next_steps.push("Initialize and unlock the node wallet in the dashboard. Wallet mining serves no work until the wallet is unlocked.".into());
    }
    if preset.mining() {
        next_steps.push("Connect an external miner through ergo-solo: https://github.com/arkadianet/ergo-stratum-rs or follow docs/lithos.md.".into());
    }
    if sync == Sync::Genesis {
        next_steps.push(
            "Genesis sync takes hours to days; wait for synchronization before using the node."
                .into(),
        );
    }
    if preset.indexer() {
        next_steps.push("Historical index catch-up adds time after chain synchronization; wait for the indexer before querying history or claiming storage rent.".into());
    }
    next_steps.push("Inbound P2P connections need a listener and port forwarding; embedded network seeds handle outbound discovery.".into());
    next_steps.push("Stop: press Ctrl-C and wait for graceful shutdown.".into());
    #[cfg(windows)]
    next_steps
        .push("Windows uses inherited ACLs; keep secrets in a directory only you can read.".into());
    let plan = Plan {
        schema_version: 1,
        dry_run: args.dry_run,
        preset,
        sync,
        network,
        config_path: config_path.clone(),
        data_dir,
        key_file: key_file.clone(),
        config_contents: contents.replace(PLAN_HASH, "<API_HASH_ELIDED>"),
        reward_address,
        free_bytes,
        recommended_free_space_bytes: recommended,
        warnings,
        start_command,
        dashboard_url,
        next_steps,
    };
    writeln!(
        diagnostics,
        "Config: {}\nData directory: {}\nAPI key file: {}",
        plan.config_path.display(),
        plan.data_dir.display(),
        plan.key_file.display()
    )?;
    if !args.dry_run {
        let key = GeneratedKey::generate(&key_file).map_err(|e| failure(e.to_string()))?;
        let contents = config_contents(&args, &plan.data_dir, &key.hash)?;
        NodeConfig::from_toml(&contents).map_err(invalid)?;
        fs::create_dir_all(config_dir)?;
        create_secrets_dir(&secrets_dir)?;
        // Prepare the validated config before publication. persist_noclobber
        // atomically refuses a config created by another process in the meantime.
        let mut temporary = tempfile::NamedTempFile::new_in(config_dir)?;
        temporary.write_all(contents.as_bytes())?;
        temporary.as_file().sync_all()?;
        key.publish(&key_file).map_err(|e| failure(e.to_string()))?;
        if let Err(error) = temporary.persist_noclobber(&config_path) {
            // Remove only the secret we just exclusively created, never an old file.
            let _ = fs::remove_file(&key_file);
            return Err(failure(format!(
                "publish config {}: {}",
                config_path.display(),
                error.error
            )));
        }
    }
    if args.json {
        serde_json::to_writer_pretty(&mut *output, &plan).map_err(|e| failure(e.to_string()))?;
        writeln!(output)?;
    } else {
        writeln!(
            output,
            "{}\n\n{}",
            if args.dry_run {
                "Dry-run plan (no files written)"
            } else {
                "Created validated configuration and protected API key"
            },
            plan.config_contents
        )?;
        writeln!(
            output,
            "Free space: {}; recommended free space (provisional): {} GiB.",
            free_bytes
                .map(|n| format!("{:.1} GiB", n as f64 / GIB as f64))
                .unwrap_or_else(|| "unknown".into()),
            preset.budget(sync)
        )?;
        for warning in &plan.warnings {
            writeln!(output, "Warning: {warning}")?;
        }
        if let Some(address) = &plan.reward_address {
            writeln!(output, "Reward P2PK address: {address}")?;
        }
        for step in &plan.next_steps {
            writeln!(output, "{step}")?;
        }
    }
    Ok(())
}

fn config_contents(args: &InitArgs, data_dir: &Path, hash: &str) -> Result<String> {
    let preset = args.preset.expect("resolved preset");
    let fast = args.sync == Some(Sync::Fast);
    let network = match args.network.expect("resolved network") {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    };
    let quote = |value: &str| toml::Value::String(value.into()).to_string();
    let data = data_dir
        .to_str()
        .ok_or_else(|| invalid("data directory must be valid UTF-8"))?;
    let public_bind = if args.api_bind.ip().is_loopback() {
        ""
    } else {
        "public_bind = true\n"
    };
    let mut contents = format!("network = {}\ndata_dir = {}\n\n[node]\nstate_type = \"utxo\"\nverify_transactions = true\nblocks_to_keep = -1\n\n[node.utxo]\nutxo_bootstrap = {fast}\n\n[node.nipopow]\nnipopow_bootstrap = {fast}\np2p_nipopows = 2\n\n[api]\nbind = {}\n{public_bind}\n[api.security]\napi_key_hash = {}\n\n[mempool]\ndisabled = false\n\n[indexer]\nenabled = {}\n\n[mining]\nenabled = {}\nuse_external_miner = true\nclaim_storage_rent = {}\n", quote(network), quote(data), quote(&args.api_bind.to_string()), quote(hash), preset.indexer(), preset.mining(), preset == Preset::MiningFull);
    if let Some(key) = &args.miner_public_key {
        contents.push_str(&format!("miner_public_key_hex = {}\n", quote(key)));
    }
    if args.p2p_bind.is_some() || args.declared_addr.is_some() {
        contents.push_str("\n[peers]\n");
        if let Some(bind) = args.p2p_bind {
            contents.push_str(&format!("bind_addr = {}\n", quote(&bind.to_string())));
        }
        if let Some(addr) = args.declared_addr {
            contents.push_str(&format!("declared_addr = {}\n", quote(&addr.to_string())));
        }
    }
    Ok(contents)
}

fn prompt(input: &mut impl BufRead, output: &mut impl Write, label: &str) -> Result<String> {
    write!(output, "{label}: ")?;
    output.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Err(invalid("input ended before all choices were supplied"));
    }
    Ok(line.trim().to_string())
}
fn choice<T: ValueEnum>(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    allowed: &[&str],
) -> Result<T> {
    loop {
        let value = prompt(input, output, &format!("{label} [{}]", allowed.join("/")))?;
        if allowed.contains(&value.as_str()) {
            return T::from_str(&value, false).map_err(invalid);
        }
        writeln!(output, "Choose one of: {}", allowed.join(", "))?;
    }
}
fn confirm(input: &mut impl BufRead, output: &mut impl Write, label: &str) -> Result<bool> {
    loop {
        match prompt(input, output, &format!("{label} [yes/no]"))?
            .to_ascii_lowercase()
            .as_str()
        {
            "yes" | "y" => return Ok(true),
            "no" | "n" => return Ok(false),
            _ => writeln!(output, "Answer yes or no; consent is never assumed.")?,
        }
    }
}

/// Resolve existing ancestors (including symlinks), then append new components.
fn absolute(path: &Path, cwd: &Path) -> Result<PathBuf> {
    let joined = cwd.join(path);
    let mut resolved = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            other => {
                resolved.push(other.as_os_str());
                match fs::canonicalize(&resolved) {
                    Ok(real) => resolved = real,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(resolved)
}
fn absent(path: &Path, reason: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(invalid(format!("{}: {reason}", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn check_secrets_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(invalid("secrets path must be a real directory"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o777 != 0o700 {
                    return Err(invalid("existing secrets directory must have mode 0700; v1 does not change existing permissions"));
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn create_secrets_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => check_secrets_dir(path),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => check_secrets_dir(path),
        Err(e) => Err(e.into()),
    }
}
fn free_space(path: &Path) -> Option<u64> {
    let mut ancestor = path;
    while !ancestor.exists() {
        ancestor = ancestor.parent()?;
    }
    fs4::available_space(ancestor).ok()
}
fn start_command(config: &Path, data: &Path) -> Result<String> {
    fn quote(path: &Path) -> Result<String> {
        let value = path
            .to_str()
            .ok_or_else(|| invalid("paths must be valid UTF-8"))?;
        #[cfg(unix)]
        {
            Ok(format!("'{}'", value.replace('\'', "'\\''")))
        }
        #[cfg(not(unix))]
        {
            Ok(format!("'{}'", value.replace('\'', "''")))
        }
    }
    let executable = std::env::current_exe()?;
    let invocation = if cfg!(windows) {
        format!("& {}", quote(&executable)?)
    } else {
        quote(&executable)?
    };
    Ok(format!(
        "{invocation} --config {} --data-dir {}",
        quote(config)?,
        quote(data)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Cli, Command};
    use clap::Parser;

    fn args(root: &Path, preset: &str, sync: &str) -> InitArgs {
        let cli = Cli::parse_from([
            "ergo-node",
            "init",
            "--preset",
            preset,
            "--sync",
            sync,
            "--network",
            "mainnet",
            "--data-dir",
            root.join("data").to_str().unwrap(),
            "--dry-run",
            "--json",
        ]);
        let Some(Command::Init(mut args)) = cli.command else {
            panic!("init parser");
        };
        if args.preset.is_some_and(Preset::mining) {
            args.reward = Some(Reward::Wallet);
        }
        if args.sync == Some(Sync::Fast) {
            args.accept_unanchored_bootstrap = true;
        }
        args
    }

    fn execute(
        args: &InitArgs,
        tty: bool,
        input: &str,
        space: Option<u64>,
    ) -> (Result<()>, String, String) {
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let result = run_with_space(
            args,
            tty,
            &mut io::Cursor::new(input),
            &mut output,
            &mut diagnostics,
            |_| space,
        );
        (
            result,
            String::from_utf8(output).unwrap(),
            String::from_utf8(diagnostics).unwrap(),
        )
    }

    #[test]
    fn disk_budgets_warning_override_boundary_and_unknown() {
        for (preset, sync, budget) in [
            ("wallet", "fast", 100),
            ("mining-fast", "fast", 100),
            ("wallet", "genesis", 150),
            ("mining-fast", "genesis", 150),
            ("archival", "genesis", 150),
            ("explorer", "genesis", 250),
            ("mining-full", "genesis", 250),
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut args = args(root.path(), preset, sync);
            let (result, output, diagnostics) = execute(&args, false, "", Some(budget * GIB - 1));
            let error = result.unwrap_err();
            assert_eq!(error.exit_code(), 2);
            assert!(error.to_string().contains("--allow-low-disk"));
            assert!(diagnostics.contains("recommended free space (provisional)"));
            assert!(output.is_empty());
            args.allow_low_disk = true;
            let (result, output, diagnostics) = execute(&args, false, "", Some(budget * GIB - 1));
            result.unwrap();
            assert!(diagnostics.contains("Warning:"));
            let plan: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert_eq!(plan["recommended_free_space_bytes"], budget * GIB);
            args.allow_low_disk = false;
            let (result, _, diagnostics) = execute(&args, false, "", Some(budget * GIB));
            result.unwrap();
            assert!(!diagnostics.contains("Warning:"));
            let (result, output, diagnostics) = execute(&args, false, "", None);
            result.unwrap();
            assert!(diagnostics.contains("unknown"));
            let plan: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert!(plan["free_bytes"].is_null());
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn interactive_disk_confirmation_is_separate_and_required() {
        let root = tempfile::tempdir().unwrap();
        let args = args(root.path(), "wallet", "genesis");
        let (result, _, diagnostics) = execute(&args, true, "no\n", Some(1));
        assert_eq!(result.unwrap_err().exit_code(), 2);
        assert!(diagnostics.contains("Continue with low disk space"));
        execute(&args, true, "yes\n", Some(1)).0.unwrap();
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn interactive_fast_consent_is_never_inferred_from_sync_choice() {
        let root = tempfile::tempdir().unwrap();
        let mut args = args(root.path(), "wallet", "fast");
        args.accept_unanchored_bootstrap = false;
        let (result, _, diagnostics) = execute(&args, true, "no\n", Some(300 * GIB));
        assert!(result.unwrap_err().to_string().contains("consent declined"));
        assert!(diagnostics.contains("cross-check the UTXO root"));
        assert!(diagnostics.contains("Accept provisional snapshot trust [yes/no]"));
        execute(&args, true, "yes\n", Some(300 * GIB)).0.unwrap();
        let (result, _, _) = execute(&args, true, "", Some(300 * GIB));
        assert!(result.unwrap_err().to_string().contains("input ended"));
        args.non_interactive = true;
        let (result, _, diagnostics) = execute(&args, true, "yes\n", Some(300 * GIB));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("--accept-unanchored-bootstrap"));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn interactive_missing_choices_and_public_key_confirmation() {
        let root = tempfile::tempdir().unwrap();
        let mut args = args(root.path(), "mining-fast", "genesis");
        args.preset = None;
        args.network = None;
        args.sync = None;
        args.reward = None;
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let answers = format!("mining-full\ntestnet\ngenesis\npublic-key\n{key}\nyes\n");
        let (result, output, diagnostics) = execute(&args, true, &answers, Some(300 * GIB));
        result.unwrap();
        assert!(diagnostics.contains("hours to days"));
        assert!(diagnostics.contains("storage-rent claims"));
        assert!(diagnostics.contains("Confirm this reward address [yes/no]"));
        let plan: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(plan["network"], "testnet");
        assert_eq!(plan["preset"], "mining-full");
        assert!(plan["reward_address"].is_string());
        let answers = answers.replace("\nyes\n", "\nno\n");
        assert!(execute(&args, true, &answers, Some(300 * GIB))
            .0
            .unwrap_err()
            .to_string()
            .contains("reward address declined"));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn paths_resolve_symlink_ancestors_once_and_preserve_parent_semantics() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("real/sub")).unwrap();
        symlink(root.path().join("real/sub"), root.path().join("link")).unwrap();
        assert_eq!(
            absolute(Path::new("link/../new"), root.path()).unwrap(),
            root.path().join("real/new")
        );
    }
}
