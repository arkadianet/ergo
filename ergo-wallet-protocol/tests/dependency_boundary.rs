use std::process::Command;

const FORBIDDEN: &[&str] = &[
    "redb",
    "tokio",
    "axum",
    "utoipa",
    "ergo-state",
    "ergo-api",
    "ergo-node",
    "ergo-wallet",
    "ergo-ser",
    "ergo-primitives",
    "ergo-validation",
    "ergo-sigma",
    "ergo-indexer",
    "ergo-indexer-types",
    "ergo-chain-spec",
    "ergo-crypto",
    "ergo-compiler",
    "ergo-p2p",
    "ergo-sync",
    "ergo-mempool",
    "ergo-mining",
    "ergo-rest-json",
    "ergo-difftest",
];

#[test]
fn protocol_has_only_wire_safe_dependencies() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "ergo-wallet-protocol",
            "-e",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .expect("invoke cargo tree");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let violations: Vec<&str> = FORBIDDEN
        .iter()
        .copied()
        .filter(|name| {
            stdout
                .lines()
                .any(|line| line.starts_with(&format!("{name} ")))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "protocol dependency boundary violated: {violations:?}\n{stdout}"
    );
}
