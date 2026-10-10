//! Cancellation regressions for task ownership while graceful shutdown awaits.

use std::future::{pending, Future};
use std::task::Poll;

use clap::Parser;
use tokio::net::TcpListener;

use super::*;

struct ParkedListener {
    listener: Option<TcpListener>,
    dropped: Option<oneshot::Sender<()>>,
}

impl Drop for ParkedListener {
    fn drop(&mut self) {
        // Release the port before the observer sees completion.
        self.listener.take();
        if let Some(tx) = self.dropped.take() {
            let _ = tx.send(());
        }
    }
}

// A failing negative control must still clean up its deliberately parked task.
struct AbortOnTestEnd(tokio::task::AbortHandle);
impl Drop for AbortOnTestEnd {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn parked_task() -> (
    JoinHandle<()>,
    SocketAddr,
    oneshot::Receiver<()>,
    AbortOnTestEnd,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let owner = ParkedListener {
        listener: Some(listener),
        dropped: Some(dropped_tx),
    };
    let (started_tx, started_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _owner = owner;
        let _ = started_tx.send(());
        pending::<()>().await;
    });
    let cleanup = AbortOnTestEnd(task.abort_handle());
    started_rx.await.unwrap();
    (task, address, dropped_rx, cleanup)
}

async fn test_node(directory: &std::path::Path) -> RunHandle {
    let config_path = directory.join("ergo-node.toml");
    std::fs::write(&config_path, "[api]\ndisabled = true\n").unwrap();
    let cli = crate::config::Cli::parse_from([
        "ergo-node",
        "--network",
        "devnet",
        "--data-dir",
        directory.to_str().unwrap(),
        "--config",
        config_path.to_str().unwrap(),
        "--peers",
        "127.0.0.1:1",
    ]);
    let config = crate::config::NodeConfig::load(cli).unwrap();
    crate::node::run_inner(config).await.unwrap()
}

fn retain_loop_for_test(handle: &mut RunHandle) -> JoinHandle<Result<(), NodeError>> {
    std::mem::replace(
        &mut handle.loop_handle,
        tokio::spawn(async { Ok::<(), NodeError>(()) }),
    )
}

async fn assert_released(address: SocketAddr, dropped: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(2), dropped)
        .await
        .expect("owned task was detached when shutdown was cancelled")
        .expect("task must drop its listener owner");
    let rebound = TcpListener::bind(address)
        .await
        .expect("Drop must release the cancelled shutdown task's bound socket");
    drop(rebound);
}

#[tokio::test]
async fn cancelling_api_drain_preserves_drop_cleanup_and_releases_socket() {
    let directory = tempfile::tempdir().unwrap();
    let mut handle = test_node(directory.path()).await;
    let loop_task = retain_loop_for_test(&mut handle);
    let (api_task, address, dropped, _cleanup) = parked_task().await;
    handle.api_handle = Some(api_task);

    // Poll the real drain until it awaits the parked API task, then cancel it.
    // This is the same helper/await point used by explicit node shutdown.
    let mut drain = Box::pin(handle.drain_api_and_inbound());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    drop(handle);
    assert_released(address, dropped).await;
    tokio::time::timeout(Duration::from_secs(3), loop_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancelling_shutdown_preserves_anchor_and_mining_task_cleanup() {
    for mining in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut handle = test_node(directory.path()).await;
        let loop_task = retain_loop_for_test(&mut handle);
        let (task, address, dropped, _cleanup) = parked_task().await;
        if mining {
            handle.mining_engine_handle = Some(task);
        } else {
            handle.anchor_builder_handle = Some(task);
        }
        let mut shutdown = Box::pin(handle.shutdown());
        std::future::poll_fn(|cx| {
            assert!(shutdown.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Cancelling the owning future invokes RunHandle::Drop. The task must
        // still be owned there, even though it ignored cooperative cancellation.
        drop(shutdown);
        assert_released(address, dropped).await;
        tokio::time::timeout(Duration::from_secs(3), loop_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[derive(Default)]
struct ShutdownReplayStore {
    events: std::sync::Mutex<Vec<ergo_api::v1::realtime::journal::ReplayEvent>>,
    reservations: std::sync::atomic::AtomicUsize,
    finalized: tokio::sync::Notify,
}
impl ergo_api::v1::realtime::journal::RealtimeStore for ShutdownReplayStore {
    fn load_events(&self) -> Result<ergo_api::v1::realtime::journal::JournalRecovery, String> {
        Ok(Default::default())
    }
    fn reserve_cursor(&self, _: u64) -> Result<(), String> {
        if self.reservations.fetch_add(1, Ordering::SeqCst) > 0 {
            self.finalized.notify_one();
        }
        Ok(())
    }
    fn append_events(
        &self,
        events: &[ergo_api::v1::realtime::journal::ReplayEvent],
    ) -> Result<(), String> {
        self.events.lock().unwrap().extend_from_slice(events);
        Ok(())
    }
}

#[tokio::test]
async fn shutdown_persists_final_publisher_event_before_closing_journal() {
    let directory = tempfile::tempdir().unwrap();
    let mut handle = test_node(directory.path()).await;
    let real_loop = retain_loop_for_test(&mut handle);
    let store = Arc::new(ShutdownReplayStore::default());
    let services =
        Arc::new(ergo_api::ApiServices::with_durable_realtime(None, store.clone()).unwrap());
    handle.api_services = Some(services.clone());
    let bus = services.realtime.bus.clone();
    let (finish_tx, finish_rx) = oneshot::channel();
    handle.loop_handle = tokio::spawn(async move {
        finish_rx.await.unwrap();
        bus.publish(ergo_api::v1::realtime::RealtimeEventBody::block_applied(
            1,
            "final".into(),
            1,
            1,
            100,
        ));
        Ok(())
    });
    let shutdown = tokio::spawn(handle.shutdown());
    // The old order closes the journal while this final producer is parked.
    // The correct order waits for the producer; release it after that wait.
    let _ = tokio::time::timeout(Duration::from_millis(200), store.finalized.notified()).await;
    finish_tx.send(()).unwrap();
    shutdown.await.unwrap().unwrap();
    real_loop.await.unwrap().unwrap();
    assert_eq!(store.events.lock().unwrap().len(), 1);
    assert_eq!(
        services
            .realtime
            .bus
            .journal_status()
            .unwrap()
            .committed_seq,
        1
    );
}
