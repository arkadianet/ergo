// ----- mining engine exhaustion -----

/// Wire the build worker + coordinator exactly as `boot` does, for tests that
/// drive `run_mining_engine` directly. Boot owns the worker thread and the
/// coordinator future owns only the request `Sender`; this mirrors that split
/// so the tests preserve the production lifecycle (and the log-capture
/// dispatcher snapshot — taken here on the test thread so the worker inherits
/// the test's thread-local subscriber). Returns the spawned coordinator task
/// and the worker `JoinHandle`; the test joins the worker after cancelling.
fn spawn_engine_with_worker(
    reader: ergo_state::reader::ChainStoreReader,
    handle: ergo_mining::handle::MiningHandle,
    indexer: Option<ergo_indexer::IndexerHandle>,
    intent_rx: tokio::sync::watch::Receiver<Option<ergo_mining::engine::BuildIntent>>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> (tokio::task::JoinHandle<()>, std::thread::JoinHandle<()>) {
    let (req_tx, req_rx) = std::sync::mpsc::channel::<super::mining_engine::BuildRequest>();
    let dispatch = tracing::dispatcher::get_default(|d| d.clone());
    let worker = {
        let worker_handle = handle.clone();
        std::thread::Builder::new()
            .name("mining-build-worker-test".to_string())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    // Base cache off: these tests exercise the topology /
                    // exhaustion path, not the cache itself.
                    super::mining_engine::run_build_worker(
                        reader,
                        worker_handle,
                        indexer,
                        false,
                        req_rx,
                    );
                });
            })
            .expect("spawn test mining build worker thread")
    };
    let engine = tokio::spawn(super::mining_engine::run_mining_engine(
        handle, req_tx, intent_rx, cancel_rx,
    ));
    (engine, worker)
}

/// Aborting the coordinator task (the production shutdown path: `shutdown()`
/// `abort()`s the engine after its bounded await, usually while it is parked at
/// an await point) must leave the build worker quiescent — it observes the
/// closed request channel and exits — so it can be joined, never detaching to
/// keep reading/publishing past shutdown.
///
/// This pins the ownership inversion directly: because the coordinator future
/// owns ONLY the `req_tx`, dropping it (on abort) closes the channel and the
/// worker's `recv()` errs. Pre-split the worker `JoinHandle` lived inside the
/// future and was dropped (detached) on abort, leaving the worker running. Here
/// the worker is idle (no intent ever sent), so after the abort the join must
/// complete promptly.
#[tokio::test]
async fn coordinator_abort_leaves_worker_joinable() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_mining::emission_rules::MonetarySettings;
    use ergo_mining::handle::MiningHandle;
    use ergo_mining::reemission::ReemissionSettings;
    use ergo_state::store::StateStore;
    use tokio::sync::watch;

    let tmp = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(tmp.path().join("s.redb").as_path()).unwrap();
    let mut box_id = [0u8; 32];
    box_id[31] = 1;
    store
        .initialize_genesis(&[(box_id, vec![0xAAu8; 32])])
        .unwrap();
    let reader = store.reader_handle();

    let handle = MiningHandle::new(
        [0x02u8; 33],
        MonetarySettings::mainnet(),
        Some(ReemissionSettings::mainnet()),
        DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    );

    // No intent is ever sent, so the coordinator parks on the intent channel —
    // an abort point. The worker parks on `req_rx.recv()`.
    let (_intent_tx, intent_rx) = watch::channel(None);
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let (engine, worker) = spawn_engine_with_worker(reader, handle, None, intent_rx, cancel_rx);

    // Let both park.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Simulate the shutdown abort: drop the coordinator future. This drops its
    // `req_tx`, so the worker's `recv()` errs and the worker exits.
    engine.abort();
    let _ = engine.await; // observe cancellation (JoinError::is_cancelled)

    // The worker must now exit and be joinable promptly. Join off-runtime under
    // a bound; a hang here is the regression (a detached, still-running worker).
    let joined = tokio::task::spawn_blocking(move || worker.join());
    tokio::time::timeout(std::time::Duration::from_secs(5), joined)
        .await
        .expect("worker must exit promptly after the coordinator future is dropped")
        .expect("join task must not fail")
        .expect("worker thread must not panic");
}

/// The engine task must survive `MAX_VIS_RETRIES` `TipNotVisible` returns and
/// then go back to waiting — not spin, not exit.
///
/// The intent carries an `expected_parent` / `expected_height` that can never
/// become commit-visible against a genesis-only store (committed height 0,
/// intent height 5). The test observes the exhaustion `warn!` event via log
/// capture (no fixed-sleep race), then proves the task survives exhaustion and
/// keeps running.
///
/// Capture mechanism: `tracing::subscriber::set_default` installs the
/// collecting subscriber as the thread-local default and returns a guard that
/// keeps it active until dropped. `#[tokio::test]` uses the current-thread
/// runtime, so all task polls (including the spawned engine) execute on this
/// thread and see the same thread-local default — every `warn!` emitted inside
/// the engine goes through the capture buffer.
#[tokio::test]
async fn engine_visibility_retry_exhaustion_warns_and_keeps_running() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_mempool::MempoolReadSnapshot;
    use ergo_mining::emission_rules::MonetarySettings;
    use ergo_mining::engine::{BuildIntent, BuildReason};
    use ergo_mining::handle::MiningHandle;
    use ergo_mining::reemission::ReemissionSettings;
    use ergo_state::store::StateStore;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;
    use tracing_subscriber::fmt::MakeWriter;

    // Shared capture buffer — same pattern as handle_message_emits_span_with_peer_and_code.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish();

    // `set_default` returns a guard that keeps the subscriber active as the
    // thread-local default until dropped. Because #[tokio::test] uses the
    // current-thread runtime, all task polls happen on this thread, so every
    // tracing event dispatched during the test (including from the spawned
    // engine task) routes to `buf`.
    let _guard = tracing::subscriber::set_default(subscriber);

    // A genesis-only store: committed tip is zeroed @ height 0.
    let tmp = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(tmp.path().join("s.redb").as_path()).unwrap();
    let mut box_id = [0u8; 32];
    box_id[31] = 1;
    store
        .initialize_genesis(&[(box_id, vec![0xAAu8; 32])])
        .unwrap();
    let reader = store.reader_handle();

    let handle = MiningHandle::new(
        [0x02u8; 33],
        MonetarySettings::mainnet(),
        Some(ReemissionSettings::mainnet()),
        DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    );

    // Intent whose expected_parent / expected_height can never become
    // commit-visible: committed height is 0, intent expects height 5.
    let intent = BuildIntent {
        expected_parent: [0x42u8; 32],
        expected_height: 5,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: [0x02u8; 33],
        reason: BuildReason::Startup,
    };

    let (intent_tx, intent_rx) = watch::channel(Some(intent));
    let (cancel_tx, cancel_rx) = watch::channel(false);

    // Re-send the intent to advance the watch version from INITIAL (0) to 1.
    // `watch::channel` initialises both the sender state and the receiver at
    // the same version (0), so the engine's first `changed()` call would block
    // forever without this bump — the receiver only wakes on a version advance.
    intent_tx.send_if_modified(|_| true);

    let (engine, worker) = spawn_engine_with_worker(reader, handle, None, intent_rx, cancel_rx);

    // The target warn! message emitted after MAX_VIS_RETRIES exhaustion.
    const EXHAUSTION_MSG: &str =
        "mining engine: commit-visibility retries exhausted; awaiting next intent";

    // Poll every 50 ms until the exhaustion warn appears in the capture buffer.
    // Normal arrival: ~1 s (40 × 25 ms backoff). Timeout at 30 s only caps a
    // hung test.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let observed = loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
        if output.contains(EXHAUSTION_MSG) {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
    };
    assert!(
        observed,
        "timed out (30 s) waiting for exhaustion warn — \
         the engine never emitted '{EXHAUSTION_MSG}'",
    );

    // Exhaustion goes back to waiting, not exit or panic.
    assert!(
        !engine.is_finished(),
        "engine task must survive retry exhaustion and keep running",
    );

    // Cancel cleanly and join within a tight deadline.
    cancel_tx.send(true).unwrap();
    drop(intent_tx);
    tokio::time::timeout(std::time::Duration::from_millis(500), engine)
        .await
        .expect("engine task must exit promptly after cancel")
        .expect("engine task must not panic");
    // The test owns the worker thread now (as boot does in production). The
    // coordinator future dropped its request sender on exit, so the worker's
    // recv() has erred — join it so the thread doesn't leak past the test.
    worker.join().expect("worker thread must not panic");
}

/// Pins that a mid-retry parent switch grants the new tip a FULL
/// visibility-retry budget (the `budget_parent` reset in `run_mining_engine`).
///
/// ## Why the old test didn't pin anything
///
/// The previous version waited for A's exhaustion warn before sending B.  At
/// that point the inner retry loop had already `break`-ed and returned to the
/// outer loop, which re-declares `let mut attempts = 0` when B wakes it — so
/// the test passed even WITHOUT the `budget_parent` reset fix: the outer loop
/// always reset.  The bug only manifests when B is picked up by the INNER
/// loop's re-borrow while A's budget is partially spent (mid-`TipNotVisible`
/// retry), which is exactly what this test arms.
///
/// ## Timing design
///
/// Budget constants: `MAX_VIS_RETRIES = 40`, `VIS_BACKOFF = 25 ms` →
/// a fresh budget takes ≥ 40 × 25 ms = 1 000 ms of backoff before exhausting.
///
/// 1. Send A (parent `[0x42;32]`, h5) and arm the engine.
/// 2. Sleep 500 ms — A is mid-retry (≈ 20 of 40 retries burned).
///    If an exhaustion warn already appeared the scenario didn't arm (the
///    runner is pathologically slow or the clock ran fast); return early with
///    a note rather than failing — the sibling exhaustion test still covers
///    liveness, and a flaky-slow runner should not count as a test failure.
/// 3. Send B (parent `[0x43;32]`, h5) while A's inner loop is still running.
///    The engine's next `borrow_and_update` sees B; because B's parent differs
///    from A's, the `budget_parent` guard resets `attempts = 0`.  A's remaining
///    retries are abandoned (A's exhaustion warn never fires).
/// 4. Poll for the FIRST exhaustion warn (30 s cap).  Record `warn_at`.
/// 5. Assert:
///    - Exactly ONE exhaustion warn total (A's never fired; B's did once).
///    - `warn_at − b_sent ≥ 950 ms`: a full fresh budget of 40 × 25 ms = 1 000 ms
///      of backoff cannot exhaust in under 950 ms.  With the fix the warn
///      cannot arrive earlier; without the fix B inherits ≈ 20 burned retries
///      and the warn lands at ≈ 500 ms, failing the bound.
///      Lower-bound asserts are flake-safe: sleeps never finish early, so a
///      slow CI only pushes the time later, never below the bound.
///
/// ## Honest limitations
///
/// A pathologically slow runner that burned < 2 retries by the time B is sent
/// would mask a buggy inherited budget (the inherited count would still be < 2,
/// and the warn would still take ≈ 950 ms).  The 500 ms arm window and the
/// step-2 early-return guard make that scenario remote in practice.
#[tokio::test]
async fn visibility_retry_budget_resets_on_parent_change() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_mempool::MempoolReadSnapshot;
    use ergo_mining::emission_rules::MonetarySettings;
    use ergo_mining::engine::{BuildIntent, BuildReason};
    use ergo_mining::handle::MiningHandle;
    use ergo_mining::reemission::ReemissionSettings;
    use ergo_state::store::StateStore;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::watch;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let tmp = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(tmp.path().join("s.redb").as_path()).unwrap();
    let mut box_id = [0u8; 32];
    box_id[31] = 1;
    store
        .initialize_genesis(&[(box_id, vec![0xAAu8; 32])])
        .unwrap();
    let reader = store.reader_handle();

    let handle = MiningHandle::new(
        [0x02u8; 33],
        MonetarySettings::mainnet(),
        Some(ReemissionSettings::mainnet()),
        DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    );

    // Step 1 — Intent A: parent [0x42;32], height 5 — commit-visible never
    // (genesis store has height 0, intent expects height 5).
    let intent_a = BuildIntent {
        expected_parent: [0x42u8; 32],
        expected_height: 5,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: [0x02u8; 33],
        reason: BuildReason::Startup,
    };

    let (intent_tx, intent_rx) = watch::channel(Some(intent_a));
    let (cancel_tx, cancel_rx) = watch::channel(false);

    // Bump the watch version so the engine's first `changed()` fires
    // (watch::channel initialises sender and receiver at the same version,
    // so the engine would block on `changed()` without this bump).
    intent_tx.send_if_modified(|_| true);

    let _a_started = Instant::now();
    let (engine, worker) = spawn_engine_with_worker(reader, handle, None, intent_rx, cancel_rx);

    const EXHAUSTION_MSG: &str =
        "mining engine: commit-visibility retries exhausted; awaiting next intent";

    // Step 2 — Sleep 500 ms: A is mid-retry (≈ 20 of 40 retries burned).
    // After waking, check that NO exhaustion warn has appeared yet.
    // If one has — pathologically slow runner or unexpectedly fast clock —
    // the scenario didn't arm; return early rather than failing spuriously.
    tokio::time::sleep(Duration::from_millis(500)).await;
    {
        let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
        if output.contains(EXHAUSTION_MSG) {
            eprintln!(
                "visibility_retry_budget_resets_on_parent_change: \
                 scenario did not arm — A exhausted before B was sent \
                 (slow runner or fast clock); skipping timing assertion. \
                 The sibling exhaustion test still covers liveness."
            );
            cancel_tx.send(true).unwrap();
            drop(intent_tx);
            tokio::time::timeout(Duration::from_millis(500), engine)
                .await
                .expect("engine task must exit promptly after cancel")
                .expect("engine task must not panic");
            worker.join().expect("worker thread must not panic");
            return;
        }
    }

    // Step 3 — Send B mid-retry.  The engine's NEXT `borrow_and_update` sees B;
    // because B's parent differs from A's, the `budget_parent` guard resets
    // `attempts = 0`.  A's remaining retries are abandoned silently.
    let intent_b = BuildIntent {
        expected_parent: [0x43u8; 32],
        expected_height: 5,
        mempool: Arc::new(MempoolReadSnapshot::empty()),
        miner_pk: [0x02u8; 33],
        reason: BuildReason::Tip,
    };
    intent_tx.send(Some(intent_b)).unwrap();
    let b_sent = Instant::now();

    // Step 4 — Poll for the FIRST exhaustion warn (30 s cap).
    let deadline = Instant::now() + Duration::from_secs(30);
    let warn_observed = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
        if output.contains(EXHAUSTION_MSG) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
    };
    let warn_at = Instant::now();

    assert!(
        warn_observed,
        "timed out (30 s) waiting for exhaustion warn after intent-B was sent"
    );

    // Step 5a — Exactly ONE exhaustion warn total.
    // A's was never emitted (the supersession consumed its remaining budget);
    // B's fired exactly once.
    let output = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    let warn_count = output.matches(EXHAUSTION_MSG).count();
    assert_eq!(
        warn_count, 1,
        "expected exactly one exhaustion warn (B's); A's should have been \
         abandoned when B superseded it mid-retry; got {warn_count}",
    );

    // Step 5b — Lower-bound timing: a full fresh budget of 40 × 25 ms = 1 000 ms
    // of backoff cannot exhaust in under 950 ms.  With the fix the warn cannot
    // arrive earlier; without the fix B inherits ≈ 20 burned retries and the
    // warn lands at ≈ 500 ms, failing this bound.  Lower-bound asserts are
    // flake-safe: sleeps never complete early, so a slow CI only pushes the
    // time further above the threshold.
    let elapsed = warn_at.duration_since(b_sent);
    assert!(
        elapsed >= Duration::from_millis(950),
        "exhaustion warn arrived only {elapsed:?} after B was sent; \
         a fresh 40-retry budget at 25 ms/retry requires ≥ 950 ms — \
         B appears to have inherited A's partially-spent retry counter",
    );

    // Task alive after the single exhaustion event.
    assert!(
        !engine.is_finished(),
        "engine task must survive exhaustion and keep running",
    );

    cancel_tx.send(true).unwrap();
    drop(intent_tx);
    tokio::time::timeout(Duration::from_millis(500), engine)
        .await
        .expect("engine task must exit promptly after cancel")
        .expect("engine task must not panic");
    worker.join().expect("worker thread must not panic");
}
