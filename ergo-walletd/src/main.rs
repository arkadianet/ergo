use clap::Parser;
use ergo_walletd::config::Cli;
use ergo_walletd::{init_logging, run};

#[tokio::main]
async fn main() {
    init_logging();
    let cli = Cli::parse();
    let config = match ergo_walletd::config::Config::load(cli) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ergo-walletd: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(config).await {
        eprintln!("ergo-walletd: {error}");
        std::process::exit(1);
    }
}
