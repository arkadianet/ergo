use clap::Parser;
use ergo_walletd::config::{Cli, CliCommand};
use ergo_walletd::{init_logging, prepare, run};

fn main() {
    init_logging();
    // Before any credential or secret file is read.
    if let Err(error) = ergo_walletd::hardening::disable_core_dumps() {
        eprintln!("ergo-walletd: {error}");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    if let Some(CliCommand::Init(args)) = &cli.command {
        match ergo_walletd::onboard::init(args) {
            Ok(outcome) => {
                print!("{}", outcome.instructions());
                return;
            }
            Err(error) => {
                eprintln!("ergo-walletd: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Some(CliCommand::Adopt(args)) = &cli.command {
        match ergo_walletd::adopt::adopt(args) {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("adoption report is serializable")
                );
                println!(
                    "adopted. Next, create the daemon's config for it:\n\n\
                     ergo-walletd init --config <dir>/walletd.toml --data-dir {} \\\n  \
                     --node-url <the node's API URL> --tcp 127.0.0.1:3033\n\n\
                     (or point an existing seed-mode config's data_dir at it). It prints the \
                     remaining steps; the first unlock, with the wallet password this wallet had \
                     before, encrypts the database.",
                    args.data_dir.display()
                );
                return;
            }
            Err(error) => {
                eprintln!("ergo-walletd: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Some(CliCommand::Migrate(args)) = &cli.command {
        match ergo_walletd::migration::migrate(args) {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("migration report is serializable")
                );
                return;
            }
            Err(error) => {
                eprintln!("ergo-walletd: {error}");
                std::process::exit(1);
            }
        }
    }
    let export = matches!(cli.command, Some(CliCommand::ExportUnsealKey));
    let reward = matches!(cli.command, Some(CliCommand::RewardKey));
    let config = match ergo_walletd::config::Config::load(cli) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ergo-walletd: {error}");
            std::process::exit(2);
        }
    };
    if reward {
        let mut secret = zeroize::Zeroizing::new(String::new());
        if std::io::stdin().read_line(&mut secret).is_err() {
            eprintln!("ergo-walletd: could not read the password from standard input");
            std::process::exit(2);
        }
        let secret = secret.trim_end_matches(['\n', '\r']);
        match ergo_walletd::seal::reward_key(&config.config, secret) {
            Ok(key) => {
                let prefix = config.config.network.prefix();
                match ergo_ser::address::encode_p2pk_from_pubkey(prefix, &key) {
                    Ok(address) => {
                        println!("address: {address}\npublic key: {}", hex::encode(key));
                        println!("\n[mining]\nminer_reward_address = \"{address}\"");
                        return;
                    }
                    Err(error) => {
                        eprintln!("ergo-walletd: {error}");
                        std::process::exit(1);
                    }
                }
            }
            Err(error) => {
                eprintln!("ergo-walletd: {error}");
                std::process::exit(1);
            }
        }
    }
    if export {
        let mut secret = zeroize::Zeroizing::new(String::new());
        if std::io::stdin().read_line(&mut secret).is_err() {
            eprintln!("ergo-walletd: could not read the password from standard input");
            std::process::exit(2);
        }
        let secret = secret.trim_end_matches(['\n', '\r']);
        match ergo_walletd::seal::export_unseal_key(&config.config, secret) {
            Ok(key) => {
                println!(
                    "{}",
                    zeroize::Zeroizing::new(hex::encode(key.expose())).as_str()
                );
                return;
            }
            Err(error) => {
                eprintln!("ergo-walletd: {error}");
                std::process::exit(1);
            }
        }
    }
    if config.config.lock_memory {
        if let Err(error) = ergo_walletd::hardening::lock_all_memory() {
            eprintln!("ergo-walletd: {error}");
            std::process::exit(2);
        }
    }
    // The blocking HTTP client is built HERE, before any Tokio runtime exists on
    // this thread. `reqwest::blocking` creates and drops a private runtime
    // inside `ClientBuilder::build`, and Tokio panics when a runtime is dropped
    // from inside an async context — so building the client from under
    // `#[tokio::main]` (or from any `async fn`) aborts the daemon at startup.
    let daemon = match prepare(config) {
        Ok(daemon) => daemon,
        Err(error) => {
            eprintln!("ergo-walletd: {error}");
            std::process::exit(1);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ergo-walletd: {error}");
            std::process::exit(1);
        }
    };
    let result = runtime.block_on(run(daemon));
    runtime.shutdown_background();
    if let Err(error) = result {
        eprintln!("ergo-walletd: {error}");
        std::process::exit(1);
    }
}
