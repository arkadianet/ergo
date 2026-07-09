//! `GET /api/v1/ws` — the axum WebSocket adapter over the [`RealtimeBus`] +
//! [`Session`] (`v1-api-design.md` §4.1, fragment §2.1).
//!
//! This layer is deliberately thin: it owns the transport (upgrade, text-frame
//! I/O, WS ping/pong, heartbeat/idle timers, connection caps) and delegates
//! ALL protocol semantics to the transport-free [`Session`]. The per-socket
//! bounded queue + drop policy live in the bus; the socket task only observes
//! the `lagged` flag and closes `slow_consumer`.
//!
//! [`spawn_event_bridge`] is the server-seam feeder (runtime-guarded like the
//! O4 depth sampler): it polls the coarse operator event ring via
//! [`NodeReadState::events`] and republishes `block_applied` / `reorg` into the
//! bus `blocks` channel. This is the honest Phase-1 upstream — the coarse ring
//! is bridged INTO the bus (one push path), not a second event source. The
//! fine-grained address/box/token/tx taps live in node internals and are a
//! follow-up; until they land those classes are `channel_unavailable`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Response};
use ergo_ser::address::NetworkPrefix;

use crate::traits::NodeReadState;
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::routes::V1State;

use super::bus::RealtimeBus;
use super::protocol::{
    parse_client_frame, ClientFrame, FrameParseError, Session, HEARTBEAT_MS, MAX_MESSAGE_BYTES,
};

/// Max events replayed per `resume` (bounds the backfill cost, §2.7).
const RESUME_MAX: usize = 1024;

/// Default coarse-ring poll cadence for the bridge feeder. The coarse ring is
/// itself snapshot-tick (block-ish) derived, so a 1 s poll adds negligible
/// latency over the source cadence while keeping the feed near-live.
pub const DEFAULT_BRIDGE_INTERVAL: Duration = Duration::from_secs(1);

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn session_id() -> String {
    let id: u128 = rand::random();
    format!("{id:032x}")
}

/// `GET /api/v1/ws` handler. Rejects before upgrade with the standard v1 error
/// envelope when the subsystem is off (`realtime_disabled`) or a connection cap
/// is hit (`connection_limit`, HTTP 429).
///
/// **Not a plain REST read.** A successful call performs the WebSocket
/// upgrade handshake (HTTP 101) and hands off to the long-lived [`Session`]
/// protocol (subscribe/unsubscribe/resume/ping, `v1-api-design.md` §4.1) — not
/// representable as an OpenAPI response body. Only the pre-upgrade rejection
/// paths are documented below.
#[utoipa::path(
    get, path = "/api/v1/ws", tag = "realtime",
    responses(
        (status = 101, description = "Switching Protocols — WebSocket session established"),
        (status = 409, description = "Real-time subsystem disabled on this node", body = V1Error),
        (status = 429, description = "Connection cap reached", body = V1Error),
    ),
)]
pub async fn ws_handler(
    State(state): State<V1State>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    let handle = match state.realtime.clone() {
        Some(h) => h,
        None => {
            return v1_error(
                Reason::RealtimeDisabled,
                "real-time subscriptions are not enabled on this node",
                "the RealtimeBus is not wired in this build",
            )
        }
    };
    let ip = peer.ip();
    let guard = match handle.limiter.try_acquire(ip) {
        Some(g) => g,
        None => {
            return v1_error(
                Reason::ConnectionLimit,
                "too many open realtime connections",
                "reduce concurrent sockets or retry later",
            )
        }
    };
    let bus = handle.bus.clone();
    let network = state.network;
    ws.max_message_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            // Hold the connection guard for the socket's whole life.
            let _guard = guard;
            run_socket(socket, bus, network).await;
        })
        .into_response()
}

async fn send_frame(
    socket: &mut WebSocket,
    frame: &super::protocol::ServerFrame,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(frame)
        .unwrap_or_else(|_| r#"{"type":"error","reason":"internal_error","message":""}"#.into());
    socket.send(Message::Text(text)).await
}

async fn send_all(
    socket: &mut WebSocket,
    frames: &[super::protocol::ServerFrame],
) -> Result<(), axum::Error> {
    for f in frames {
        send_frame(socket, f).await?;
    }
    Ok(())
}

/// The per-socket event loop. Runs until the client closes, the socket errors,
/// or the server evicts (`slow_consumer` / `idle_timeout`).
async fn run_socket(mut socket: WebSocket, bus: Arc<RealtimeBus>, network: NetworkPrefix) {
    let mut sub = bus.subscribe();
    let mut session = Session::new(session_id(), sub.filter.clone(), network);

    if send_frame(&mut socket, &session.welcome(bus.latest_seq()))
        .await
        .is_err()
    {
        return;
    }

    let heartbeat = Duration::from_millis(HEARTBEAT_MS);
    let mut hb = tokio::time::interval(heartbeat);
    hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    hb.tick().await; // consume the immediate first tick
    let mut last_activity = Instant::now();

    loop {
        tokio::select! {
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Text(text))) => {
                        last_activity = Instant::now();
                        if handle_text(&mut socket, &mut session, &bus, &text).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Binary(_))) => {
                        let _ = send_frame(&mut socket, &super::protocol::ServerFrame::Close {
                            reason: Reason::BinaryUnsupported,
                            message: "binary frames are not supported; send text JSON".into(),
                            last_seq: bus.latest_seq(),
                        }).await;
                        break;
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                        last_activity = Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                }
            }
            event = sub.rx.recv() => {
                match event {
                    Some(ev) => {
                        if sub.lagged.load(Ordering::Acquire) {
                            let _ = close_slow_consumer(&mut socket, bus.latest_seq()).await;
                            break;
                        }
                        let frames = session.on_event(&ev);
                        if send_all(&mut socket, &frames).await.is_err() {
                            break;
                        }
                    }
                    None => break, // bus dropped (shutdown)
                }
            }
            _ = hb.tick() => {
                if sub.lagged.load(Ordering::Acquire) {
                    let _ = close_slow_consumer(&mut socket, bus.latest_seq()).await;
                    break;
                }
                if last_activity.elapsed() > 2 * heartbeat {
                    let _ = send_frame(&mut socket, &super::protocol::ServerFrame::Close {
                        reason: Reason::IdleTimeout,
                        message: "no activity within the idle window".into(),
                        last_seq: bus.latest_seq(),
                    }).await;
                    break;
                }
                let hbf = super::protocol::ServerFrame::Heartbeat {
                    emitted_at_unix_ms: now_unix_ms(),
                    latest_seq: bus.latest_seq(),
                };
                if send_frame(&mut socket, &hbf).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}

async fn close_slow_consumer(socket: &mut WebSocket, last_seq: u64) -> Result<(), axum::Error> {
    send_frame(
        socket,
        &super::protocol::ServerFrame::Close {
            reason: Reason::SlowConsumer,
            message: "send buffer exceeded; reconnect and resume from last_seq".into(),
            last_seq,
        },
    )
    .await
}

/// Handle one inbound text control frame. Returns `Err` only when the socket
/// should close (a send failed); protocol-level rejections are sent inline and
/// keep the socket open.
async fn handle_text(
    socket: &mut WebSocket,
    session: &mut Session,
    bus: &Arc<RealtimeBus>,
    text: &str,
) -> Result<(), axum::Error> {
    // Control-frame rate limit (§2.6) — every inbound text frame counts,
    // BEFORE parsing, so malformed/unknown frames cannot bypass the limiter
    // (each otherwise still costs a parse + error response).
    if !session.record_control_op(Instant::now()) {
        return send_frame(
            socket,
            &super::protocol::ServerFrame::Error {
                id: None,
                reason: Reason::RateLimited,
                message: "too many control frames; slow down".into(),
            },
        )
        .await;
    }

    let frame = match parse_client_frame(text) {
        Ok(f) => f,
        Err(FrameParseError::UnknownOp) => {
            return send_frame(
                socket,
                &super::protocol::ServerFrame::Error {
                    id: None,
                    reason: Reason::UnknownOp,
                    message: "unrecognized op".into(),
                },
            )
            .await;
        }
        Err(FrameParseError::BadRequest(msg)) => {
            return send_frame(
                socket,
                &super::protocol::ServerFrame::Error {
                    id: None,
                    reason: Reason::BadRequest,
                    message: msg,
                },
            )
            .await;
        }
    };

    match frame {
        ClientFrame::Subscribe { id, channels } => {
            let frames = session.handle_subscribe(id, channels, |c| bus.is_live(c));
            send_all(socket, &frames).await
        }
        ClientFrame::Unsubscribe { id, channels } => {
            let frames = session.handle_unsubscribe(id, channels);
            send_all(socket, &frames).await
        }
        ClientFrame::Resume {
            id,
            since,
            channels,
        } => {
            // Register the channels first (same validation/liveness as subscribe).
            let sub_frames = session.handle_subscribe(id.clone(), channels, |c| bus.is_live(c));
            send_all(socket, &sub_frames).await?;
            // Then replay matching retained events, or signal a gap. A page
            // cut off by RESUME_MAX is NOT a complete catch-up — the client
            // must resync rather than believe it is caught up.
            let filter = session.snapshot_filter();
            let page = bus.backfill(&filter, since, RESUME_MAX);
            if page.gap || page.truncated {
                send_frame(
                    socket,
                    &super::protocol::ServerFrame::Resync {
                        id,
                        gap: true,
                        latest_seq: page.latest_seq,
                    },
                )
                .await?;
            } else {
                for ev in page.events {
                    let frames = session.on_event(&ev);
                    send_all(socket, &frames).await?;
                }
            }
            Ok(())
        }
        ClientFrame::Ping { id } => {
            send_frame(socket, &session.handle_ping(id, bus.latest_seq())).await
        }
        ClientFrame::Auth { id } => send_frame(socket, &session.handle_auth(id)).await,
    }
}

/// Project one coarse-ring feed snapshot into the bus, advancing the bridge's
/// cursor. Pure (no I/O, no clock) so the coarse→bus mapping and the boot-seed
/// suppression are directly unit-testable.
///
/// The first call *seeds* — it adopts the current tail without publishing — so
/// a standing history at boot is not replayed as a burst of "new" events (the
/// coarse ring's own differ already primed it). `seeded` is a separate flag
/// from `last_seq` so an empty boot feed (`latest_seq == 0`) still seeds
/// correctly and the genuine first block on the next tick is published, not
/// swallowed.
fn project_tick(
    feed: &crate::types::ApiNodeEvents,
    bus: &RealtimeBus,
    last_seq: &mut u64,
    seeded: &mut bool,
) {
    if !*seeded {
        *seeded = true;
        *last_seq = feed.latest_seq;
        return;
    }
    for ev in &feed.events {
        if ev.seq <= *last_seq {
            continue;
        }
        match ev.kind.as_str() {
            "blockApplied" => {
                bus.publish(super::model::RealtimeEventBody::block_applied(
                    ev.unix_ms,
                    ev.header_id.clone().unwrap_or_default(),
                    ev.height.unwrap_or(0),
                    ev.txs.unwrap_or(0),
                    ev.size_bytes.unwrap_or(0),
                ));
            }
            "reorg" => {
                // The coarse ring names only the new tip; depth and the dropped
                // branch are not derivable here (best-effort guarantee —
                // fine-grained retractions need the node-internal tap).
                bus.publish(super::model::RealtimeEventBody::reorg(
                    ev.unix_ms,
                    ev.height.unwrap_or(0),
                    ev.header_id.clone().unwrap_or_default(),
                    0,
                    Vec::new(),
                ));
            }
            _ => {}
        }
    }
    *last_seq = (*last_seq).max(feed.latest_seq);
}

/// Spawn the server-seam bridge feeder: poll the coarse operator event ring and
/// republish `block_applied` / `reorg` into the bus `blocks` channel. Spawn
/// ONLY from an async context (a Tokio runtime must be current); the server
/// wiring guards the call exactly like the O4 depth sampler.
pub fn spawn_event_bridge(
    read: Arc<dyn NodeReadState>,
    bus: Arc<RealtimeBus>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_seq: u64 = 0;
        let mut seeded = false;
        loop {
            ticker.tick().await;
            let feed = read.events();
            project_tick(&feed, &bus, &mut last_seq, &mut seeded);
        }
    })
}

/// One bridge feeder per process — repeated router assembly in one runtime
/// must not stack pollers (same idempotence rule as the O4 depth sampler and
/// the webhook worker).
static BRIDGE_STARTED: AtomicBool = AtomicBool::new(false);

/// Spawn the bridge feeder at most ONCE per process (idempotent across
/// repeated router assembly). Subsequent calls are no-ops. Call only from an
/// async context (a Tokio runtime must be current).
pub fn spawn_event_bridge_once(
    read: Arc<dyn NodeReadState>,
    bus: Arc<RealtimeBus>,
    interval: Duration,
) {
    if BRIDGE_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    // The JoinHandle is deliberately dropped: the task runs for the process.
    drop(spawn_event_bridge(read, bus, interval));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApiNodeEvent, ApiNodeEvents};

    // ----- helpers -----

    fn block_ev(seq: u64, height: u32) -> ApiNodeEvent {
        ApiNodeEvent {
            seq,
            unix_ms: 1_000,
            kind: "blockApplied".into(),
            height: Some(height),
            header_id: Some(format!("h{height}")),
            txs: Some(2),
            size_bytes: Some(1234),
            addr: None,
            detail: None,
        }
    }

    fn reorg_ev(seq: u64, height: u32) -> ApiNodeEvent {
        ApiNodeEvent {
            seq,
            unix_ms: 2_000,
            kind: "reorg".into(),
            height: Some(height),
            header_id: Some(format!("r{height}")),
            txs: None,
            size_bytes: None,
            addr: None,
            detail: None,
        }
    }

    fn blocks_sub(bus: &Arc<RealtimeBus>) -> super::super::bus::BusSubscription {
        let sub = bus.subscribe();
        *sub.filter.write().unwrap() = std::iter::once("blocks".to_string()).collect();
        sub
    }

    // ----- boot seed -----

    #[test]
    fn project_tick_first_call_seeds_standing_history_without_publishing() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let mut sub = blocks_sub(&bus);
        let feed = ApiNodeEvents {
            latest_seq: 5,
            events: vec![block_ev(4, 104), block_ev(5, 105)],
        };
        let (mut last, mut seeded) = (0u64, false);
        project_tick(&feed, &bus, &mut last, &mut seeded);
        assert!(seeded);
        assert_eq!(last, 5);
        assert_eq!(bus.latest_seq(), 0, "nothing published on the seed tick");
        assert!(sub.rx.try_recv().is_err());
    }

    // ----- happy path: coarse → bus mapping -----

    #[test]
    fn project_tick_publishes_only_new_block_events_after_seed() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let mut sub = blocks_sub(&bus);
        let (mut last, mut seeded) = (0u64, false);
        // Seed on an empty feed so the first real block is NOT swallowed.
        project_tick(
            &ApiNodeEvents {
                latest_seq: 0,
                events: vec![],
            },
            &bus,
            &mut last,
            &mut seeded,
        );
        // Two new blocks arrive on the next tick.
        project_tick(
            &ApiNodeEvents {
                latest_seq: 2,
                events: vec![block_ev(1, 100), block_ev(2, 101)],
            },
            &bus,
            &mut last,
            &mut seeded,
        );
        assert_eq!(last, 2);
        let a = sub.rx.try_recv().unwrap();
        let b = sub.rx.try_recv().unwrap();
        assert_eq!(a.event, "block_applied");
        assert_eq!(a.data["height"], 100);
        assert_eq!(a.data["tx_count"], 2);
        assert!(a.confirmed);
        assert_eq!(b.data["height"], 101);
        // Re-projecting the same feed publishes nothing (cursor advanced).
        project_tick(
            &ApiNodeEvents {
                latest_seq: 2,
                events: vec![block_ev(1, 100), block_ev(2, 101)],
            },
            &bus,
            &mut last,
            &mut seeded,
        );
        assert!(sub.rx.try_recv().is_err());
    }

    #[test]
    fn project_tick_maps_reorg_events() {
        let bus = Arc::new(RealtimeBus::blocks_only());
        let mut sub = blocks_sub(&bus);
        let (mut last, mut seeded) = (0u64, false);
        project_tick(
            &ApiNodeEvents {
                latest_seq: 0,
                events: vec![],
            },
            &bus,
            &mut last,
            &mut seeded,
        );
        project_tick(
            &ApiNodeEvents {
                latest_seq: 1,
                events: vec![reorg_ev(1, 200)],
            },
            &bus,
            &mut last,
            &mut seeded,
        );
        let ev = sub.rx.try_recv().unwrap();
        assert_eq!(ev.event, "reorg");
        assert_eq!(ev.data["height"], 200);
        assert_eq!(ev.data["header_id"], "r200");
    }

    // ----- end-to-end spawn (drives the async task) -----

    #[tokio::test]
    async fn spawn_event_bridge_seeds_then_publishes_live() {
        // A shared feed cell the stub read returns; we mutate it between ticks.
        use std::sync::Mutex;
        struct Feed(Mutex<ApiNodeEvents>);
        impl NodeReadState for Feed {
            fn info(&self) -> crate::types::ApiInfo {
                unreachable!("bridge only calls events()")
            }
            fn status(&self) -> crate::types::ApiStatus {
                unreachable!()
            }
            fn tip(&self) -> crate::types::ApiTip {
                unreachable!()
            }
            fn sync(&self) -> crate::types::ApiSyncStatus {
                unreachable!()
            }
            fn peers(&self) -> Vec<crate::types::ApiPeer> {
                unreachable!()
            }
            fn mempool_summary(&self) -> crate::types::ApiMempoolSummary {
                unreachable!()
            }
            fn mempool_transactions(&self) -> crate::types::ApiMempoolTransactions {
                unreachable!()
            }
            fn mempool_transaction(
                &self,
                _tx_id_hex: &str,
            ) -> Option<crate::types::ApiMempoolTransaction> {
                unreachable!()
            }
            fn health(&self) -> crate::types::ApiHealth {
                unreachable!()
            }
            fn events(&self) -> ApiNodeEvents {
                self.0.lock().unwrap().clone()
            }
        }

        let feed = Arc::new(Feed(Mutex::new(ApiNodeEvents {
            latest_seq: 0,
            events: vec![],
        })));
        let read: Arc<dyn NodeReadState> = feed.clone();
        let bus = Arc::new(RealtimeBus::blocks_only());
        let mut sub = blocks_sub(&bus);
        let handle = spawn_event_bridge(read, bus.clone(), Duration::from_millis(10));

        // Let the first (seed) tick run against the empty feed.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(bus.latest_seq(), 0, "seed tick publishes nothing");

        // A new block appears; a later tick publishes it.
        *feed.0.lock().unwrap() = ApiNodeEvents {
            latest_seq: 1,
            events: vec![block_ev(1, 100)],
        };
        tokio::time::sleep(Duration::from_millis(40)).await;

        handle.abort();
        let ev = sub.rx.try_recv().expect("live block published");
        assert_eq!(ev.data["height"], 100);
    }

    // ----- WS transport (real upgrade + real client) -----

    /// End-to-end over an actual WebSocket: connect → receive `welcome` →
    /// `subscribe` blocks → receive `ack` → a block is published on the shared
    /// bus → receive the `event` frame. Exercises the axum upgrade glue and the
    /// `run_socket` select loop that the pure unit tests cannot reach.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ws_upgrade_subscribe_and_receive_event() {
        use axum::extract::ws::WebSocketUpgrade;
        use axum::routing::get;
        use axum::Router;
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as TMessage;

        let bus = Arc::new(RealtimeBus::blocks_only());
        let bus_for_route = bus.clone();
        let app = Router::new().route(
            "/ws",
            get(move |ws: WebSocketUpgrade| {
                let bus = bus_for_route.clone();
                async move { ws.on_upgrade(move |s| run_socket(s, bus, NetworkPrefix::Mainnet)) }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let url = format!("ws://{addr}/ws");
        let (mut client, _resp) = tokio_tungstenite::connect_async(url).await.unwrap();

        // welcome
        let welcome = next_text(&mut client).await;
        assert_eq!(welcome["type"], "welcome");
        assert!(welcome["session_id"].is_string());
        assert_eq!(welcome["limits"]["max_channels"], 64);

        // subscribe blocks
        client
            .send(TMessage::Text(
                r#"{"op":"subscribe","id":"c1","channels":["blocks"]}"#.into(),
            ))
            .await
            .unwrap();
        let ack = next_text(&mut client).await;
        assert_eq!(ack["type"], "ack");
        assert_eq!(ack["op"], "subscribe");
        assert_eq!(ack["channels"][0], "blocks");

        // publish a block on the shared bus → the socket must deliver it.
        bus.publish(super::super::model::RealtimeEventBody::block_applied(
            42,
            "abcd".into(),
            1808901,
            7,
            4096,
        ));
        let ev = next_text(&mut client).await;
        assert_eq!(ev["type"], "event");
        assert_eq!(ev["channel"], "blocks");
        assert_eq!(ev["event"], "block_applied");
        assert_eq!(ev["confirmed"], true);
        assert_eq!(ev["data"]["height"], 1808901);
        assert_eq!(ev["data"]["tx_count"], 7);
        assert_eq!(ev["seq"], 1);

        // app-level ping → pong
        client
            .send(TMessage::Text(r#"{"op":"ping","id":"p1"}"#.into()))
            .await
            .unwrap();
        let pong = next_text(&mut client).await;
        assert_eq!(pong["type"], "pong");
        assert_eq!(pong["id"], "p1");

        client.close(None).await.ok();
    }

    /// Read frames until the next text frame, decoding it as JSON (skips any
    /// server-initiated heartbeat/ping that may interleave).
    async fn next_text<S>(client: &mut S) -> serde_json::Value
    where
        S: futures_util::StreamExt<
                Item = Result<
                    tokio_tungstenite::tungstenite::Message,
                    tokio_tungstenite::tungstenite::Error,
                >,
            > + Unpin,
    {
        use tokio_tungstenite::tungstenite::Message as TMessage;
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), client.next())
                .await
                .expect("frame within timeout")
                .expect("stream open")
                .expect("ws message");
            match msg {
                TMessage::Text(t) => {
                    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                    if v["type"] == "heartbeat" {
                        continue;
                    }
                    return v;
                }
                TMessage::Ping(_) | TMessage::Pong(_) => continue,
                other => panic!("unexpected ws frame: {other:?}"),
            }
        }
    }
}
