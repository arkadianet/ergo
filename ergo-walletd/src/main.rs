use clap::Parser;
use ergo_walletd::config::Cli;
use ergo_walletd::{init_logging, prepare, run};

fn main() {
    init_logging();
    let cli = Cli::parse();
    let config = match ergo_walletd::config::Config::load(cli) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ergo-walletd: {error}");
            std::process::exit(2);
        }
    };
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
    if let Err(error) = runtime.block_on(run(daemon)) {
        eprintln!("ergo-walletd: {error}");
        std::process::exit(1);
    }
}
