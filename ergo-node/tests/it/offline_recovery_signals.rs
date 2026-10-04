#![cfg(unix)]

use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn sigint_and_sigterm_remove_backup_and_restore_staging() {
    let parent = tempfile::tempdir().unwrap();
    let data = parent.path().join("data");
    fs::create_dir(&data).unwrap();
    let mut store = ergo_state::store::StateStore::open(&data.join("state.redb")).unwrap();
    store
        .initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())
        .unwrap();
    drop(store);
    fs::create_dir(data.join("wallet")).unwrap();
    fs::File::create(data.join("wallet/large-secret"))
        .unwrap()
        .set_len(128 * 1024 * 1024)
        .unwrap();
    let backup = parent.path().join("source-backup");
    ergo_node::maintenance::backup(&data, &backup).unwrap();
    for operation in ["backup", "restore"] {
        for signal in ["INT", "TERM"] {
            let name = format!("{operation}-{signal}");
            let destination = parent.path().join(&name);
            let staging = parent
                .path()
                .join(format!(".{name}.ergo-{operation}-staging"));
            let source = if operation == "backup" {
                &data
            } else {
                &backup
            };
            let mut child = Command::new(env!("CARGO_BIN_EXE_ergo-node"))
                .arg(operation)
                .arg(source)
                .arg(&destination)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if staging
                    .join("wallet/large-secret")
                    .metadata()
                    .is_ok_and(|m| m.len() > 0)
                {
                    break;
                }
                if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                    let _ = child.kill();
                    let output = child.wait_with_output().unwrap();
                    panic!(
                        "copy never reached staging: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(Command::new("kill")
                .args(["-s", signal, &child.id().to_string()])
                .status()
                .unwrap()
                .success());
            let output = child.wait_with_output().unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("interrupted"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !staging.exists(),
                "{operation} left staging after SIG{signal}"
            );
            assert!(!destination.exists());
        }
    }
}
