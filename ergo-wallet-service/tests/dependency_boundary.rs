use std::process::Command;

const WALLET_FORBIDDEN: &[&str] = &[
    "ergo-state",
    "ergo-api",
    "ergo-node",
    "ergo-mempool",
    "ergo-mining",
    "ergo-sync",
];

const SERVICE_FORBIDDEN: &[&str] = &[
    "ergo-state",
    "ergo-api",
    "ergo-node",
    "ergo-mempool",
    "ergo-mining",
    "ergo-sync",
    "tokio",
    "axum",
];

fn normal_tree(package: &str) -> String {
    let output = Command::new(env!("CARGO"))
        .args(["tree", "-p", package, "-e", "normal", "--prefix", "none"])
        .output()
        .expect("invoke cargo tree");
    assert!(
        output.status.success(),
        "cargo tree failed for {package}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_absent(package: &str, forbidden: &[&str]) {
    let tree = normal_tree(package);
    let violations: Vec<&str> = forbidden
        .iter()
        .copied()
        .filter(|name| {
            tree.lines()
                .any(|line| line.starts_with(&format!("{name} ")))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "{package} normal dependency boundary violated: {violations:?}\n{tree}"
    );
}

#[test]
fn wallet_normal_tree_has_no_node_or_state_crates() {
    assert_absent("ergo-wallet", WALLET_FORBIDDEN);
}

#[test]
fn service_normal_tree_has_only_safe_dependencies() {
    assert_absent("ergo-wallet-service", SERVICE_FORBIDDEN);
}
