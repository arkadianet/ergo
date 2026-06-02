//! Boot-time memory sampler.
//!
//! Spawned at the top of `run_inner` so startup transients —
//! modifier-type-index back-fill, redb cache prewarm, address-book
//! restore, indexer DB open — show up in the CSV instead of being
//! invisible until the action-loop sampler takes over. Writes
//! proc-only rows with `sync_phase="Init"`.
//!
//! Stopped via `JoinHandle::abort()` (non-blocking) right before
//! `action_loop` spawns. Both writers append to the same path;
//! `OpenOptions::append(true)` sets `O_APPEND` on Linux, so per-line
//! writes (well under PIPE_BUF) don't tear even if the writers briefly
//! overlap. Within-process header init is serialised by a mutex inside
//! `mem_csv::open_or_init`, so even if the boot and action-loop
//! samplers race on a fresh path, the header is guaranteed to land
//! before any data row appended via the *winner's* handle. Cross-
//! process races (multiple node instances writing the same path) are
//! out of scope for this observability sink.
//!
//! `run_inner` does NOT add any `.await` between spawning this task
//! and the later `abort()`: observability must not block boot. On the
//! production multi-thread runtime the spawned task runs on a worker
//! thread concurrently with `run_inner`'s sync work, so transients
//! during boot (modifier-index back-fill, cache prewarm, etc.) are
//! captured. On a current-thread runtime with no `.await` between
//! spawn and abort (e.g. tests/embedders with `[api] disabled`), this
//! task may not be polled at all — best-effort observability, not a
//! hard contract. That trade-off is intentional: such paths don't
//! have meaningful boot transients to capture.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::oneshot;
use tracing::warn;

use crate::mem_csv::{append_row, now_ms, open_or_init, MemSample};
use crate::mem_probe::read_proc_status;
use crate::mem_smaps::read_smaps_rollup;

/// Cadence for boot-time samples. Tighter than the action-loop tick
/// (5s) because boot transients (back-fill, cache prewarm) can spike
/// and recover within a few seconds.
const BOOT_TICK: Duration = Duration::from_secs(1);

/// Append proc-only `MemSample` rows with `sync_phase="Init"` until
/// `stop_rx` resolves. No-op when `path` is `None` (env var unset).
///
/// Failures log and exit silently — observability must never block
/// boot. The action-loop sampler picks up where this leaves off.
pub async fn boot_sampler_task(path: Option<PathBuf>, stop_rx: oneshot::Receiver<()>) {
    boot_sampler_with_tick(path, stop_rx, BOOT_TICK).await
}

async fn boot_sampler_with_tick(
    path: Option<PathBuf>,
    mut stop_rx: oneshot::Receiver<()>,
    tick: Duration,
) {
    let Some(path) = path else {
        return;
    };
    let mut file = match open_or_init(&path) {
        Ok(f) => f,
        Err(e) => {
            warn!(
                error = %e,
                path = %path.display(),
                "boot sampler open failed",
            );
            return;
        }
    };
    let mut interval = tokio::time::interval(tick);
    loop {
        tokio::select! {
            biased;
            _ = &mut stop_rx => return,
            _ = interval.tick() => {
                let proc = read_proc_status().unwrap_or_default();
                let smaps = read_smaps_rollup().unwrap_or_default();
                let sample = MemSample {
                    ts_ms: now_ms(),
                    sync_phase: "Init",
                    proc,
                    smaps,
                    indexer_status: "Disabled",
                    ..MemSample::default()
                };
                if let Err(e) = append_row(&mut file, &sample) {
                    warn!(error = %e, "boot sampler append failed");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_op_when_path_unset() {
        // No `mem_csv::open_or_init*` call here, so no `TestStateGuard`
        // needed: the function returns immediately on `None` path.
        let (_stop_tx, stop_rx) = oneshot::channel();
        boot_sampler_task(None, stop_rx).await;
    }

    #[tokio::test]
    async fn writes_init_rows_then_stops_on_signal() {
        // Tests that touch `open_or_init*` MUST acquire
        // `mem_csv::test_hooks::acquire` so they don't perturb the
        // deterministic pause-barrier tests in `mem_csv::tests`
        // running in parallel under the same `cargo test --lib`
        // process. The guard:
        //   - takes the crate-wide TEST_SERIAL mutex
        //   - resets HEADER_WRITTEN to false
        //   - disarms any leftover pause barrier
        let _state = crate::mem_csv::test_hooks::acquire();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.csv");
        let (stop_tx, stop_rx) = oneshot::channel();
        // 10ms tick keeps the test fast while still exercising
        // the interval branch of the select.
        let task = tokio::spawn(boot_sampler_with_tick(
            Some(path.clone()),
            stop_rx,
            Duration::from_millis(10),
        ));
        // Let the task tick a few times.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = stop_tx.send(());
        task.await.unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        // header + at least one data row.
        assert!(lines.len() >= 2, "expected ≥1 row, got {}", lines.len());
        for row in &lines[1..] {
            let cols: Vec<&str> = row.split(',').collect();
            assert_eq!(cols[3], "Init", "sync_phase mismatch in row={row}");
            assert_eq!(cols[34], "Disabled", "indexer_status mismatch in row={row}");
        }
    }

    /// `run_inner` adds no `.await` between spawning the boot
    /// sampler and aborting it (observability must not block boot).
    /// On a current-thread runtime with no other `.await` in that
    /// window, the spawned task may never be polled before abort —
    /// that is best-effort by design, NOT a hard contract. This test
    /// pins the actual behavior so the design choice is unambiguous:
    /// spawn → abort with no scheduling opportunity yields zero
    /// `Init` rows (the sampler never opened the file).
    #[test]
    fn spawn_then_immediate_abort_yields_no_rows_on_current_thread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.csv");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (_stop_tx, stop_rx) = oneshot::channel();
            let handle = tokio::spawn(boot_sampler_with_tick(
                Some(path.clone()),
                stop_rx,
                Duration::from_millis(1),
            ));
            handle.abort();
            let _ = handle.await;
        });

        // The CSV file does not exist because the sampler never ran
        // its synchronous `open_or_init` — it was aborted before the
        // executor polled it.
        assert!(
            !path.exists(),
            "expected sampler to be aborted before opening the file; \
             instead the file exists at {}",
            path.display()
        );
    }
}
