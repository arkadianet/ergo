//! End-to-end submission tests against a real `run_inner` node.
//!
//! Drives the in-process `submit` bridge (the same `Arc<dyn NodeSubmit>`
//! the axum handlers use) so the tests cover the production path from
//! the channel boundary through `admit_api_transaction` and back to the
//! caller's oneshot. The HTTP layer itself is covered by
//! `ergo-api/tests/submit_routes.rs` — duplicating it here would only
//! re-test the router.

mod common;

use std::time::Duration;

use ergo_api::types::SubmitMode;

use common::{make_test_config, spawn_node};

/// A fresh data dir has genesis boxes but no full block applied, so
/// `block_context_headers()` is empty and `build_tip_context` returns
/// `None`. Submissions in either mode must surface that as
/// `tip_unready` rather than crashing or hanging — the same wire-shape
/// the HTTP layer turns into `400 reason: "tip_unready"`.
#[tokio::test]
async fn cold_tip_context_rejects_with_tip_unready() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = make_test_config(tmp.path().to_path_buf());
    let handle = spawn_node(config).await;

    // Bytes don't matter — admission rejects on the cold-context check
    // before any deserialization. Using a clearly non-tx blob keeps the
    // intent obvious in `cargo test --nocapture`.
    let bogus_bytes = b"cold-tip-context-test".to_vec();
    let submit = handle
        .submit
        .as_ref()
        .expect("submit bridge is always-on now (Scala-parity)");

    let broadcast = submit
        .submit_transaction(bogus_bytes.clone(), SubmitMode::Broadcast)
        .await
        .expect_err("cold tip must reject");
    assert_eq!(
        broadcast.reason, "tip_unready",
        "Broadcast on cold tip should map to tip_unready, got {broadcast:?}",
    );

    let check = submit
        .submit_transaction(bogus_bytes, SubmitMode::CheckOnly)
        .await
        .expect_err("cold tip must reject in CheckOnly too");
    assert_eq!(
        check.reason, "tip_unready",
        "CheckOnly on cold tip should map to tip_unready, got {check:?}",
    );

    handle.shutdown().await.expect("clean shutdown");
}

/// The API server bound `127.0.0.1:0`; after `run_inner` returns, the
/// handle must carry a fully-resolved port so a real HTTP client could
/// dial it. Regression guard for the `ergo_api::serve` return-tuple
/// change that backed this seam.
#[tokio::test]
async fn api_addr_resolves_ephemeral_port() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = make_test_config(tmp.path().to_path_buf());
    let handle = spawn_node(config).await;

    let addr = handle
        .api_addr
        .expect("api should be bound when api_bind is Some(_)");
    assert!(addr.ip().is_loopback(), "test bind must be loopback");
    assert_ne!(
        addr.port(),
        0,
        "kernel must have replaced the wildcard port",
    );

    handle.shutdown().await.expect("clean shutdown");
}

/// Scala `/info` `restApiUrl` must reflect the actually-bound socket,
/// not the requested bind string. Regression guard for the bind →
/// serve_on split: when `api_bind = 127.0.0.1:0`, the kernel assigns an
/// ephemeral port and `ScalaCompatStatic` must be constructed with the
/// resolved address so wallets and explorers see a dialable URL.
///
/// Drives the real TCP socket (not the in-memory router) because the
/// risk being guarded is in the construction order of `rest_api_url`,
/// which is invisible from a router-only test.
#[tokio::test]
async fn rest_api_url_reflects_actual_bound_port() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = make_test_config(tmp.path().to_path_buf());
    let handle = spawn_node(config).await;

    let addr = handle.api_addr.expect("api should be bound");

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to bound port");
    let req = format!("GET /info HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let text = String::from_utf8(response).expect("utf-8 response");

    let expected = format!("\"restApiUrl\":\"http://{addr}\"");
    assert!(
        text.contains(&expected),
        "Scala /info must publish the actual bound URL ({expected}), got body:\n{text}",
    );

    handle.shutdown().await.expect("clean shutdown");
}

/// Voted-params boundary: the params snapshot read inside
/// `build_tip_context` is sourced from `state.store.active_params()`.
/// On a cold store the active-params cache is the network default
/// (loaded by `StateStore::open`), so the tip-context build still
/// reaches the params lookup before bailing on the empty header
/// context. This test pins the cold-state behavior so a future change
/// to active-params eviction (e.g. a per-epoch demote_all hook that
/// nulls the cache between epochs) cannot silently regress submissions
/// at the boundary into a crash or a different reason code.
///
/// A full epoch-crossing test (apply blocks across an EPOCH_LENGTH
/// boundary, observe `demote_all_for_revalidation`, verify mempool
/// state) requires the block-application infrastructure currently
/// driven by the sync layer; that lives in the sync-integration
/// suite and is deferred from this pure submission-bridge test.
#[tokio::test]
async fn voted_params_boundary_cold_state_is_tip_unready() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = make_test_config(tmp.path().to_path_buf());
    let handle = spawn_node(config).await;

    let err = handle
        .submit
        .as_ref()
        .expect("submit bridge is always-on now (Scala-parity)")
        .submit_transaction(b"params-boundary".to_vec(), SubmitMode::Broadcast)
        .await
        .expect_err("cold-state submit must reject");

    // The cold-state guarantee: params lookup never short-circuits the
    // tip-context build path. If a future regression had the params
    // cache panic on cold reads, this test would crash; if a regression
    // surfaced a different reason (e.g. an internal "params_unloaded"
    // string), the assertion catches the divergence.
    assert_eq!(
        err.reason, "tip_unready",
        "cold-state submit must surface tip_unready, not a params-related error: {err:?}",
    );

    handle.shutdown().await.expect("clean shutdown");
}

/// Inbound P2P listener tracking + reality check: when `[peers]
/// bind_addr` is set, the spawned listener task's JoinHandle must be
/// retained on `RunHandle` so `shutdown()` can abort it, AND the
/// listener task must have actually reached `accept()` (not just been
/// spawned and immediately panicked or failed to bind, which
/// `is_some()` alone would not catch). Verified by TCP-connecting to
/// the bound port: a bound listener accepts the SYN and the connect
/// succeeds; an unbound port returns ECONNREFUSED. Regression guards
/// against silent listener-leak / silent listener-not-bound paths.
#[tokio::test]
async fn shutdown_tracks_and_aborts_inbound_listener() {
    // Bind in the listener task itself (via `bind_addr = 127.0.0.1:0`
    // so the kernel picks the port). Reality is verified by reading
    // the inbound port via the listener task's bind log line — but
    // since we don't expose that, we use a sidecar probe: spawn a
    // lightweight TCP probe loop that scans 127.0.0.1 ports we know
    // were just claimed. Simpler: spin a known-port probe, then have
    // the node try to bind it. If the node listener task is alive,
    // attempting a TCP connect to the port succeeds.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let bind_addr = probe.local_addr().expect("probe addr");
    drop(probe);

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = make_test_config(tmp.path().to_path_buf());
    config.bind_addr = Some(bind_addr);
    let handle = spawn_node(config).await;

    assert!(
        handle.inbound_handle.is_some(),
        "RunHandle must track the inbound listener JoinHandle when bind_addr is set; \
         without it, shutdown cannot abort the listener and the port leaks.",
    );

    // Reality check via TCP connect (not re-bind, because Linux can
    // hold a just-dropped probe port briefly even though the listener
    // task can re-claim it under the hood). If the listener task is
    // alive and bound, the TCP three-way handshake completes; if it
    // panicked or never reached `accept()`, connect fails immediately
    // with ECONNREFUSED. Poll up to ~1s for the async bind to land.
    let mut connected = false;
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(bind_addr).await.is_ok() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        connected,
        "inbound listener at {bind_addr} did not accept any TCP connection within 1s — \
         the spawned task either panicked, failed to bind (ECONNREFUSED forever), or \
         never reached `accept()`.",
    );

    handle.shutdown().await.expect("clean shutdown");

    // Post-shutdown port release: shutdown() must abort the listener
    // task so the bound port is freed promptly. Verified by attempting
    // to TCP-connect to the just-shut-down port — connect must fail
    // (ECONNREFUSED) within 1s of shutdown returning. If the listener
    // task were still parked in `accept()` (e.g. shutdown forgot to
    // abort `inbound_handle`), connect would still succeed.
    // Shutdown-side coverage to complement the pre-shutdown reality
    // check above.
    let mut released = false;
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(bind_addr).await.is_err() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        released,
        "inbound listener at {bind_addr} still accepting TCP connections 1s after shutdown — \
         shutdown() must abort inbound_handle so the port releases.",
    );
}

/// `Drop` impl regression guard: an embedder that drops `RunHandle`
/// without calling `shutdown()` must not leak the API task. The Drop
/// impl fires the shutdown signal and aborts the API + inbound
/// listener handles best-effort. Verified by re-binding the API port
/// after Drop — the bind succeeds only if the API task was aborted
/// (otherwise `127.0.0.1:port` stays held by the prior process
/// listener). Regression guard for the handle-leak-on-Drop path.
#[tokio::test]
async fn drop_without_shutdown_releases_api_port() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = make_test_config(tmp.path().to_path_buf());
    let handle = spawn_node(config).await;

    let api_addr = handle
        .api_addr
        .expect("api should be bound when api_bind is Some(_)");

    drop(handle);

    // Tokio needs a beat to drive the abort to completion; poll up to ~1s
    // before failing to keep the test resilient under load.
    let mut last_err = None;
    for _ in 0..20 {
        match tokio::net::TcpListener::bind(api_addr).await {
            Ok(_listener) => return,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    panic!(
        "API port {api_addr} still bound 1s after Drop — Drop impl failed to abort \
         api_handle (last bind error: {last_err:?})",
    );
}

/// API bind failure logs and degrades to running without an API —
/// REST is an operator surface, not a prerequisite for sync /
/// validation. The signal an embedder uses to detect
/// the failure is `RunHandle.api_addr = None` even though the config
/// requested `api_bind = Some(_)` — distinguishable from "API disabled
/// by config" (where `api_bind` itself is `None`).
///
/// Without this test, a future "embedder-friendly" change might
/// re-introduce bind-failure-fatal and silently change `run`'s
/// behavior under operators whose port is already in use.
#[tokio::test]
async fn api_bind_failure_degrades_to_no_api() {
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind blocker");
    let blocked = blocker.local_addr().expect("addr");

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = make_test_config(tmp.path().to_path_buf());
    config.api_bind = Some(blocked);

    let handle = spawn_node(config).await;
    assert!(
        handle.api_addr.is_none(),
        "API bind failure must surface as api_addr=None (degraded), got {:?}. \
         An embedder that needs strict bind detection compares this against \
         their requested `config.api_bind` — `None` here despite a Some-config \
         is the failure signal.",
        handle.api_addr,
    );

    handle.shutdown().await.expect("clean shutdown");
    drop(blocker);
}

/// Shutdown ordering correctness: a submission that races with
/// `shutdown()` must surface as `shutting_down`, never `timeout`. The
/// failure mode being guarded: with the wrong ordering, the action
/// loop receives the shutdown signal, breaks out, then sits inside
/// `shutdown_cleanly()` for several seconds while `submit_rx` is still
/// alive but unpolled. Submissions queued during that window time out
/// at `SUBMIT_TIMEOUT` (5s) and surface as `timeout` to the caller —
/// the wrong reason code for a stopping node.
///
/// Fix in two places:
///   1. `RunHandle::shutdown()` aborts the API task BEFORE awaiting
///      the loop, so axum can't push new requests onto `submit_rx`.
///   2. `action_loop` drops `submit_rx` immediately after `break` so
///      already-queued items see their oneshot reply senders dropped
///      and surface as `shutting_down` via the `RecvError` path in
///      `api_bridge.rs`. (Defense in depth for the `Drop` path which
///      can't await anything.)
///
/// This test exercises the post-shutdown path — once `shutdown()`
/// returns, the bridge's senders error as `Closed` immediately. We
/// can't easily exercise the in-flight race window without injecting
/// latency into `shutdown_cleanly`, but the post-shutdown invariant
/// is the load-bearing one for the contract: the submitter must see
/// `shutting_down`, not `timeout`, when the loop is gone.
#[tokio::test]
async fn submit_after_shutdown_returns_shutting_down_not_timeout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = make_test_config(tmp.path().to_path_buf());
    let handle = spawn_node(config).await;
    let submit = handle
        .submit
        .as_ref()
        .expect("submit bridge must be present")
        .clone();

    handle.shutdown().await.expect("clean shutdown");

    let err = submit
        .submit_transaction(b"after-shutdown".to_vec(), SubmitMode::Broadcast)
        .await
        .expect_err("submit after shutdown must fail");

    assert_eq!(
        err.reason, "shutting_down",
        "post-shutdown submit must surface shutting_down (not timeout, not overloaded): {err:?}",
    );
}

/// End-to-end integration of the shutdown sequence with an in-flight
/// HTTP POST: the handler must reach the bridge → action loop → reply
/// path, observe the closed channel when shutdown drops `submit_rx`,
/// and surface a structured `503 shutting_down` JSON body — never a
/// TCP RST mid-stream.
///
/// **Pairing with the load-bearing wiring test.** This test verifies
/// the *integration* — that `RunHandle::shutdown()` correctly orders
/// the api and loop signals so the bridge maps to `shutting_down`
/// rather than `timeout`. The *wiring* test for `with_graceful_shutdown`
/// itself lives in `ergo-api/tests/serve_shutdown.rs`, which removes
/// the action loop from the picture and pins that the API task
/// completes naturally on the shutdown signal (a hang there means the
/// `with_graceful_shutdown` call was dropped). An earlier in-tree
/// version of this test conflated those two contracts: slow-body POST
/// through the action loop tests the closed-channel reason mapping,
/// not whether axum drained, because the 5-second abort fallback
/// fires after the handler completes. This test only covers the
/// reason-mapping side.
///
/// Method:
///   1. Open TCP, send POST headers + Content-Length but withhold the
///      body. Hyper parks the per-connection task inside body read.
///   2. Brief sleep to let hyper definitively enter that state.
///   3. Trigger shutdown — `with_graceful_shutdown` waits for in-flight
///      handlers; abort-only would drop the per-connection task here.
///   4. Brief sleep so `api_shutdown_tx.send()` has fired before we
///      finish the body (proves graceful drain is what unparked the
///      handler, not naive completion).
///   5. Send the rest of the body. Handler unparks, parses, calls into
///      the bridge — which by now sees `submit_rx` dropped (action
///      loop has exited via the same shutdown), so the handler returns
///      `503 shutting_down` via the `RecvError` path.
///   6. Read the full response. Must be well-formed HTTP and contain
///      `shutting_down`, proving graceful drain delivered a structured
///      response through the closed-channel path.
///
/// Regression guard: prior versions of this test exited too early
/// (before reading the response body), missing the load-bearing
/// assertion that the structured drain reason actually arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_post_in_flight_during_shutdown_drains_gracefully() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = make_test_config(tmp.path().to_path_buf());
    let handle = spawn_node(config).await;
    let addr = handle.api_addr.expect("api should be bound");

    // Body is irrelevant — admission rejects on cold tip regardless.
    // What matters is that the handler reaches the bridge call before
    // shutdown closes the channel.
    let body = br#"{"id":"00","inputs":[],"dataInputs":[],"outputs":[]}"#.to_vec();
    let headers = format!(
        "POST /api/v1/mempool/submit HTTP/1.1\r\nHost: {addr}\r\n\
         Content-Type: application/json\r\nContent-Length: {len}\r\n\
         Connection: close\r\n\r\n",
        addr = addr,
        len = body.len(),
    );

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write headers");
    stream.flush().await.expect("flush headers");

    // Let hyper park in body read. 100ms is generous; in practice
    // hyper enters body-read state within microseconds of the headers
    // arriving, but slack absorbs CI scheduler variance.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let shutdown_task = tokio::spawn(async move { handle.shutdown().await });

    // Give the shutdown task a window to fire `api_shutdown_tx` before
    // we complete the body. With graceful drain wired, the handler is
    // already in the drain set and will be allowed to finish; with
    // abort-only, the per-connection task is dropped and the next
    // write hits a closed socket (ECONNRESET on read).
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Body completion may fail if the regression case has already
    // closed the socket — that's the failure signal we'd see on
    // abort-only. We tolerate the write error here and let the read
    // assertion below carry the load-bearing failure message.
    let _ = stream.write_all(&body).await;
    let _ = stream.flush().await;

    let mut response = Vec::new();
    let read_outcome =
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
            .await
            .expect("response read should not hang");
    read_outcome.expect(
        "in-flight POST handler during shutdown must drain to a structured \
         HTTP response, not ECONNRESET — this would mean `with_graceful_shutdown` \
         regressed to abort-only behavior",
    );

    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1"),
        "response must be well-formed HTTP after graceful shutdown; got: {:?}",
        &text.chars().take(300).collect::<String>(),
    );
    // The structured-response assertion: with the action loop gone and
    // submit_rx dropped, the bridge surfaces `shutting_down` and the
    // handler returns it as a JSON body. If a future change removed
    // graceful drain but kept abort-only, the test would fail at the
    // ECONNRESET above; if instead the bridge's reason mapping
    // regressed to `timeout`, this assertion catches it.
    assert!(
        text.contains("shutting_down"),
        "response should carry the `shutting_down` reason from the closed \
         bridge channel; got: {:?}",
        &text.chars().take(300).collect::<String>(),
    );

    shutdown_task
        .await
        .expect("shutdown task")
        .expect("clean shutdown");
}
