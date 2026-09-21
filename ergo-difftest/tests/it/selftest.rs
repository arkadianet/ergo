//! Out-of-process verification that the harness's panic-catching has teeth.
//!
//! A decode panic during a campaign must be CAUGHT and reported, never abort
//! the process — that is the whole basis of the no-panic invariant. We assert
//! it in a subprocess (real `main`, not the libtest harness, which would
//! otherwise interfere with the swapped panic hook).

use std::process::Command;

#[test]
fn difftest_selftest_passes() {
    let exe = env!("CARGO_BIN_EXE_difftest");
    let out = Command::new(exe)
        .arg("--selftest")
        .output()
        .expect("spawn difftest --selftest");
    assert!(
        out.status.success(),
        "difftest --selftest failed (status {:?})\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("selftest: ok"),
        "unexpected output: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
