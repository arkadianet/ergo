//! Per-peer async tasks: dial / accept + read/write loop.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ergo_api::SubmitError;
use ergo_p2p::connection::{Connection, ConnectionError, ReadBudget, MAX_PAYLOAD_SIZE};
use ergo_p2p::framing::{wire_len, MessageFrame};
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, Handshake, PeerSpec,
};
use ergo_p2p::peer::{Penalty, HANDSHAKE_TIMEOUT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

/// Events sent from peer tasks to the action loop.
pub enum PeerEvent {
    /// Outbound TCP connect succeeded; handshake bytes have not started
    /// yet. Lets the action loop flip the peer from `Connecting` (5s
    /// timeout) to `Handshaking` (30s timeout) before slow handshake
    /// round-trips trip `evict_timed_out`. Inbound peers skip this — the
    /// listener already accepted the stream, so `register_inbound`
    /// installs them in `Handshaking` directly.
    TcpConnected {
        addr: SocketAddr,
    },
    HandshakeComplete {
        addr: SocketAddr,
        peer_spec: PeerSpec,
        time: u64,
        conn: Connection,
    },
    ConnectFailed {
        addr: SocketAddr,
    },
    /// A peer dialed our listener. The action loop must call
    /// `register_inbound` to apply per-IP / per-subnet / max-inbound
    /// limits, then either spawn `accept_task` with the moved stream
    /// or drop it.
    InboundConnect {
        peer_addr: SocketAddr,
        stream: TcpStream,
    },
    Disconnected {
        peer: SocketAddr,
        /// Score the peer before dropping it. `Some` when the disconnect
        /// was the peer's own failure — today a frame it started and then
        /// stopped sending — so that a peer which reconnects and repeats
        /// it is eventually banned rather than merely dropped. `None` for
        /// ordinary socket errors and clean closes, which say nothing
        /// about the peer's behavior.
        penalty: Option<Penalty>,
    },
    /// Locally-mined block submitted via `POST /blocks` (Scala-compat
    /// `sendMinedBlock`). The bridge has already decoded the request
    /// body into canonical wire bytes and verified the PoW solution
    /// locally so we don't wake the action loop on invalid headers.
    ///
    /// The handler in `events.rs::handle_event` walks the same apply
    /// pipeline as P2P modifier injection: synthesizes
    /// `Action::ValidateHeader` for the header bytes, then one
    /// `Action::PersistSection` per section body, then lets the
    /// executor drive header validation → assembly tracker →
    /// `process_block`. Result is reported via the oneshot reply.
    ///
    /// The submission comes from a synthetic LOCAL peer id, so any
    /// `Action::Penalize` the validator emits on header rejection
    /// fires harmlessly against a peer that was never registered.
    /// The reply channel is the only path back to the API task.
    LocalFullBlock {
        header_bytes: Vec<u8>,
        bt_bytes: Vec<u8>,
        ext_bytes: Vec<u8>,
        ad_proofs_bytes: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<String, SubmitError>>,
    },
    /// Inbound message from a peer. The payload is byte-budgeted through
    /// [`EventByteBudget`] (audit M-5, issues #243 / #280): the permit is
    /// taken at frame-HEADER time, before the body is allocated or read,
    /// rides on the payload ([`MeteredPayload`]), and is released on drop.
    /// So neither the bytes in flight through this channel nor the bytes
    /// accumulating in per-connection read buffers can exceed the budget —
    /// a reader task parks on acquisition instead of reading on, which
    /// turns into TCP backpressure against the sender.
    Message {
        peer: SocketAddr,
        code: u8,
        payload: MeteredPayload,
    },
}

/// Byte-budget for message payloads in flight through the event channel.
///
/// Audit M-5 (issue #243): the channel is bounded at 4096 EVENTS (sized for
/// ~200 B headers), but `Message` payloads reach `MAX_PAYLOAD_SIZE` = 8 MB.
/// Worst case — 256 inbound peers streaming maximal frames into a busy
/// action loop — was 4096 × 8 MB ≈ 32 GiB of queued payloads on top of
/// per-connection read buffers. Bounding by BYTES closes the composition:
/// 256 MiB admits ~32 maximal frames in flight (ample for honest IBD, where
/// the action loop drains header events in batches), and a reader that
/// cannot acquire blocks BEFORE enqueueing — the socket stops being read,
/// kernel buffers fill, and the TCP window closes on the sender. Memory
/// pressure becomes transport backpressure instead of an OOM vector.
pub type EventByteBudget = ReadBudget;

pub const EVENT_BYTE_BUDGET_MAX: usize = 256 * 1024 * 1024;

pub fn new_event_byte_budget() -> EventByteBudget {
    ReadBudget::new(EVENT_BYTE_BUDGET_MAX)
}

/// A message payload holding its byte-budget permit. The permit is
/// released when the struct is dropped — wherever the event is consumed
/// or discarded — so the accounting cannot leak, and no consumer-side
/// release discipline is required.
pub struct MeteredPayload {
    inner: Vec<u8>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl MeteredPayload {
    /// Settle the permits taken while READING the frame against the
    /// payload the frame turned out to carry, and wrap it.
    ///
    /// The read side is admitted incrementally, one socket read at a
    /// time, so `held` covers the body bytes that were actually accepted
    /// — which is not the same number as `inner.len()`: bytes the header
    /// phase had already buffered were never admitted (a shortfall), and
    /// the last chunk is admitted in full even if the read returns less
    /// (an excess). Topping up or releasing the difference here restores
    /// #279's queue invariant exactly: an enqueued payload holds its own
    /// byte length, no more and no less.
    async fn settle(
        inner: Vec<u8>,
        held: Option<tokio::sync::OwnedSemaphorePermit>,
        budget: &EventByteBudget,
    ) -> Self {
        let need = charge_for(inner.len()) as usize;
        let permit = match held {
            Some(mut permit) => {
                // The read charged every wire byte it held plus a full
                // final chunk, so it always covers the payload. Settling
                // is therefore a RELEASE, never an acquisition: acquiring
                // here would be a wait while holding permits, which is
                // exactly the hold-and-wait the slot pool exists to
                // prevent (and this path holds no slot by then).
                let have = permit.num_permits();
                debug_assert!(have >= need, "read charged {have} B for a {need} B payload");
                if have > need {
                    drop(permit.split(have - need));
                }
                permit
            }
            // The frame was already complete when the body phase began,
            // so nothing was charged for it. This acquisition holds no
            // permits while it waits, so it cannot deadlock.
            None => acquire_budget(inner.len(), budget.bytes().clone()).await,
        };
        Self {
            inner,
            _permit: permit,
        }
    }
}

/// Permits one charge of `len` bytes costs.
///
/// Empty payloads still cost one permit so a flood of empty frames
/// cannot bypass the budget entirely. Every call site charges at most
/// one frame's worth of bytes — a payload bounded by `MAX_PAYLOAD_SIZE`,
/// or a single `READ_BUF_SIZE` read chunk — so this fits `u32` with room
/// to spare; the clamp to the budget's own size is belt-and-braces
/// against a caller asking for more than the semaphore could ever grant,
/// which would park forever rather than fail.
fn charge_for(len: usize) -> u32 {
    debug_assert!(
        len <= MAX_PAYLOAD_SIZE,
        "budget charge of {len} B exceeds one maximal frame"
    );
    u32::try_from(len.max(1))
        .unwrap_or(u32::MAX)
        .min(EVENT_BYTE_BUDGET_MAX as u32)
}

/// Take a budget permit for `len` bytes, awaiting while the budget is
/// exhausted.
///
/// Takes the budget handle BY VALUE: an async closure that holds a
/// borrowed `Arc` across an await cannot be proved `Send` for every
/// lifetime, which would make the peer task unspawnable.
///
/// The permit is owned so it can be taken before the bytes it pays for
/// exist, then merged with others and moved onto the payload, releasing
/// on drop wherever the event ends up.
async fn acquire_budget(
    len: usize,
    budget: Arc<tokio::sync::Semaphore>,
) -> tokio::sync::OwnedSemaphorePermit {
    budget
        .acquire_many_owned(charge_for(len))
        .await
        .expect("event byte budget semaphore is never closed")
}

impl std::ops::Deref for MeteredPayload {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Attempt to connect and handshake with a peer.
/// Sends HandshakeComplete or ConnectFailed to the action loop.
///
/// Emits `TcpConnected` after the TCP connect succeeds and before the
/// handshake bytes are exchanged. Without that, the peer manager sees
/// the peer as `Connecting` (5s timeout) for the entire handshake
/// round-trip, and a slow handshake gets evicted by the next
/// `sync_tick`'s `evict_timed_out` — its `HandshakeComplete` then lands
/// on an absent peer entry as `unknown peer`.
pub async fn dial_task(
    addr: SocketAddr,
    magic: [u8; 4],
    our_handshake: Handshake,
    event_tx: mpsc::Sender<PeerEvent>,
) {
    let stream = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(peer = %addr, error = %e, "dial failed: connect error");
            let _ = event_tx.send(PeerEvent::ConnectFailed { addr }).await;
            return;
        }
        Err(_) => {
            debug!(peer = %addr, "dial failed: connect timeout");
            let _ = event_tx.send(PeerEvent::ConnectFailed { addr }).await;
            return;
        }
    };
    // Channel send may fail only if the action loop has shut down; in
    // that case the handshake below would also fail to deliver, so just
    // bail without ceremony.
    if event_tx
        .send(PeerEvent::TcpConnected { addr })
        .await
        .is_err()
    {
        return;
    }
    let result = do_handshake(stream, magic, &our_handshake, HANDSHAKE_TIMEOUT).await;
    emit_handshake_outcome(addr, result, &event_tx, "dial").await;
}

/// Run the inbound side of the handshake on an already-accepted TCP
/// stream. Mirrors `dial_task` but skips the connect step. The action
/// loop must have called `register_inbound(peer_addr, _)` before
/// spawning this task so that `complete_handshake` finds the entry on
/// the `HandshakeComplete` event.
pub async fn accept_task(
    peer_addr: SocketAddr,
    stream: TcpStream,
    magic: [u8; 4],
    our_handshake: Handshake,
    event_tx: mpsc::Sender<PeerEvent>,
) {
    let result = do_handshake(stream, magic, &our_handshake, HANDSHAKE_TIMEOUT).await;
    emit_handshake_outcome(peer_addr, result, &event_tx, "accept").await;
}

async fn emit_handshake_outcome(
    addr: SocketAddr,
    result: Result<(PeerSpec, u64, Connection), String>,
    event_tx: &mpsc::Sender<PeerEvent>,
    role: &str,
) {
    match result {
        Ok((peer_spec, time, conn)) => {
            let _ = event_tx
                .send(PeerEvent::HandshakeComplete {
                    addr,
                    peer_spec,
                    time,
                    conn,
                })
                .await;
        }
        Err(e) => {
            debug!(peer = %addr, role = role, error = %e, "handshake failed");
            let _ = event_tx.send(PeerEvent::ConnectFailed { addr }).await;
        }
    }
}

/// Bind a TcpListener and forward each accepted stream to the action
/// loop as a `PeerEvent::InboundConnect`. The action loop owns the
/// gating logic (peer_manager limits) and the stream, so this task
/// stays a thin accept-and-forward loop.
///
/// On bind failure (port in use, permission denied, etc.) the task logs
/// and exits. The rest of the node keeps running outbound-only — this
/// matches Scala's behavior of treating bind failure as a startup error
/// for the listener while not tearing down the network layer.
pub async fn inbound_listener_task(bind_addr: SocketAddr, event_tx: mpsc::Sender<PeerEvent>) {
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                addr = %bind_addr,
                error = %e,
                "inbound listener bind failed; node will run outbound-only",
            );
            return;
        }
    };
    info!(addr = %bind_addr, "accepting inbound peers");
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if event_tx
                    .send(PeerEvent::InboundConnect { peer_addr, stream })
                    .await
                    .is_err()
                {
                    // Action loop is gone — node is shutting down.
                    return;
                }
            }
            Err(e) => {
                warn!(addr = %bind_addr, error = %e, "inbound accept error");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Bidirectional handshake on an established stream. Used by both
/// outbound (`do_dial`) and inbound (`accept_task`) paths.
///
/// Wire format: handshake bytes are sent raw (no magic/code/length
/// framing) — this matches `HandshakeSerializer.toBytes()` on the Scala
/// side. Subsequent messages use framing. Send order is symmetric:
/// both sides write their handshake immediately and read the peer's,
/// which TCP buffers cleanly.
async fn do_handshake(
    mut stream: TcpStream,
    magic: [u8; 4],
    our_handshake: &Handshake,
    deadline: Duration,
) -> Result<(PeerSpec, u64, Connection), String> {
    // Single ABSOLUTE deadline for the whole handshake (send + read), matching
    // Scala's `scheduleOnce(handshakeTimeout)` in PeerConnectionHandler. The old
    // per-read 30s timer was reset by every byte, so a slow-loris peer trickling
    // one byte per sub-30s window held the connection (FD) + the detached accept
    // task indefinitely. Production passes `HANDSHAKE_TIMEOUT`; the deadline is a
    // parameter only so tests can drive it with a short real clock.
    tokio::time::timeout(deadline, async move {
        let hs_bytes = serialize_handshake(our_handshake);
        stream
            .write_all(&hs_bytes)
            .await
            .map_err(|e| format!("send handshake: {e}"))?;

        // Read peer's handshake as raw bytes. The TCP read may also contain
        // the start of subsequent framed messages — we must not discard those.
        let mut buf = vec![0u8; 16384];
        let mut total_read = 0;

        loop {
            let n = stream
                .read(&mut buf[total_read..])
                .await
                .map_err(|e| format!("read handshake: {e}"))?;

            if n == 0 {
                return Err("connection closed during handshake".to_string());
            }
            total_read += n;

            match deserialize_handshake_with_consumed(&buf[..total_read]) {
                Ok((hs, consumed)) => {
                    let leftover = buf[consumed..total_read].to_vec();
                    let conn = Connection::new_with_buffer(stream, magic, leftover);
                    return Ok((hs.peer_spec, hs.time, conn));
                }
                Err(_) if total_read < 8096 => continue,
                Err(e) => return Err(format!("parse handshake: {e}")),
            }
        }
    })
    .await
    .map_err(|_| "handshake deadline exceeded".to_string())?
}

/// Read one framed message, charging the shared budget for its bytes as
/// they are read (issue #280).
///
/// The header phase returns as soon as the 9-byte framing header is
/// buffered, so the reader knows the declared size before committing to
/// receive it. The body phase then charges the budget one socket read at
/// a time, each chunk paid for BEFORE it is read, so when the budget is
/// exhausted the reader parks with the body still in the sender's socket
/// — reads stop, kernel buffers fill, and the TCP window closes on the
/// sender. This extends the budget from the queue (#279) to the
/// read-side accumulation the queue budget did not cover, WITHOUT
/// letting a peer reserve 8 MB by sending 13 bytes.
///
/// `settle` then trues the permits up to the payload's own length, which
/// is what the event channel is budgeted by — restoring #279's invariant
/// exactly for the queued event.
///
/// Abandoning this future (the `select!` branch losing the race) is safe:
/// the header stays peeked in the connection's read buffer and dropped
/// permits return their bytes to the budget, so the next call re-reads
/// the same header. A peer that disconnects mid-body releases the same
/// way.
async fn read_metered_frame(
    conn: &mut Connection,
    budget: &EventByteBudget,
) -> Result<(u8, MeteredPayload), ConnectionError> {
    conn.read_frame_header().await?;
    let (frame, held) = conn.read_frame_body_metered(budget).await?;
    let payload = MeteredPayload::settle(frame.payload, held, budget).await;
    Ok((frame.code, payload))
}

/// Per-peer read/write loop. Owns the Connection.
/// Reads frames → sends PeerEvent::Message to action loop.
/// Receives outbound MessageFrame from action loop → writes to peer.
pub async fn peer_task(
    peer_id: SocketAddr,
    mut conn: Connection,
    event_tx: mpsc::Sender<PeerEvent>,
    event_byte_budget: EventByteBudget,
    mut outbound_rx: mpsc::Receiver<MessageFrame>,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            result = read_metered_frame(&mut conn, &event_byte_budget) => {
                match result {
                    Ok((code, payload)) => {
                        // Count the exact on-wire frame size on a successful
                        // read. Post-handshake framed bytes only — the
                        // handshake round-trip preceded this task owning
                        // the conn.
                        bytes_in.fetch_add(wire_len(payload.len()) as u64, Ordering::Relaxed);
                        if event_tx.send(PeerEvent::Message {
                            peer: peer_id,
                            code,
                            payload,
                        }).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        // A stall holds a reader and the budget it has
                        // been charged, so it is scored — but a NAT reset
                        // or a crash mid-frame looks identical to
                        // deliberate withholding, so it gets the penalty
                        // Scala uses for the analogous failure to deliver
                        // (2 points), not the one for provable
                        // misbehavior. Repetition still bans.
                        let penalty = match e {
                            ConnectionError::FrameStalled { got, want } => {
                                warn!(
                                    peer = %peer_id, got, want,
                                    "peer stalled mid-frame; disconnecting with penalty",
                                );
                                Some(Penalty::NonDelivery)
                            }
                            _ => {
                                debug!(peer = %peer_id, error = %e, "peer read error; disconnecting");
                                None
                            }
                        };
                        let _ = event_tx.send(PeerEvent::Disconnected { peer: peer_id, penalty }).await;
                        return;
                    }
                }
            }
            msg = outbound_rx.recv() => {
                match msg {
                    Some(frame) => {
                        match conn.write_message(&frame).await {
                            // Count a frame once it is fully flushed. On a
                            // write error a prefix may have reached the
                            // kernel, but we never count partial frames.
                            Ok(()) => {
                                bytes_out.fetch_add(wire_len(frame.payload.len()) as u64, Ordering::Relaxed);
                            }
                            Err(_) => {
                                let _ = event_tx.send(PeerEvent::Disconnected { peer: peer_id, penalty: None }).await;
                                return;
                            }
                        }
                    }
                    None => {
                        // Outbound channel closed — action loop disconnected us
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_p2p::connection::READ_BUF_SIZE;
    use ergo_p2p::framing::{HEADER_LENGTH, MAINNET_MAGIC};
    use tokio::io::AsyncWriteExt;

    // ----- helpers -----

    /// The production charge in one call: take the permit for
    /// `inner.len()` bytes, then hang the payload off it.
    async fn meter(inner: Vec<u8>, budget: &EventByteBudget) -> MeteredPayload {
        MeteredPayload::settle(inner, None, budget).await
    }

    /// A connected loopback pair, server side wrapped as a `Connection`
    /// with `idle` as its body no-progress deadline.
    async fn server_conn_with_idle(idle: Duration) -> (TcpStream, Connection) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (
            client,
            Connection::new(server, MAINNET_MAGIC).with_body_idle_timeout(idle),
        )
    }

    /// The 9 framing-header bytes for a frame declaring `payload_len`
    /// bytes it may never send.
    fn header_bytes(code: u8, payload_len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LENGTH);
        bytes.extend_from_slice(&MAINNET_MAGIC);
        bytes.push(code);
        bytes.extend_from_slice(&(payload_len as i32).to_be_bytes());
        bytes
    }

    /// The most a connection can have buffered when the body phase makes
    /// its first admission: the header phase reads only while fewer than
    /// `HEADER_LENGTH` bytes are held, and that read is capped at
    /// `READ_BUF_SIZE`.
    const HEADER_PHASE_OVERSHOOT: usize = READ_BUF_SIZE + HEADER_LENGTH - 1;

    // ----- happy path -----

    /// Spawn `peer_task` on one end of a TCP pair and confirm it counts the
    /// exact on-wire size of post-handshake framed messages in both
    /// directions: an empty frame is 9 bytes, a 4-byte payload is 13+4=17,
    /// an outbound 10-byte payload is 13+10=23.
    #[tokio::test]
    async fn peer_task_counts_inbound_and_outbound_framed_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut client_conn = Connection::new(client, MAINNET_MAGIC);
        let server_conn = Connection::new(server, MAINNET_MAGIC);

        let peer_id: SocketAddr = "127.0.0.1:9030".parse().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let (outbound_tx, outbound_rx) = mpsc::channel(16);
        let bytes_in = Arc::new(AtomicU64::new(0));
        let bytes_out = Arc::new(AtomicU64::new(0));

        let task = tokio::spawn(peer_task(
            peer_id,
            server_conn,
            event_tx,
            new_event_byte_budget(),
            outbound_rx,
            Arc::clone(&bytes_in),
            Arc::clone(&bytes_out),
        ));

        // Inbound: empty frame (9 bytes) + 4-byte payload frame (13+4=17).
        client_conn.send(1, Vec::new()).await.unwrap();
        client_conn.send(2, vec![0xAA; 4]).await.unwrap();
        // The inbound fetch_add precedes the event send, so once both
        // events arrive bytes_in is final — no race.
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();
        assert_eq!(bytes_in.load(Ordering::Relaxed), 9 + 17);

        // Outbound: a 10-byte payload frame (13+10=23). The fetch_add runs
        // just after write_message returns Ok, which can lag the client's
        // read slightly — poll briefly.
        outbound_tx
            .send(MessageFrame {
                code: 3,
                payload: vec![0xBB; 10],
            })
            .await
            .unwrap();
        let got = client_conn.read_message().await.unwrap();
        assert_eq!(got.code, 3);
        assert_eq!(got.payload.len(), 10);
        for _ in 0..200 {
            if bytes_out.load(Ordering::Relaxed) == 23 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(bytes_out.load(Ordering::Relaxed), 23);

        task.abort();
    }

    // ----- error paths -----

    /// A slow-loris peer that TRICKLES incomplete handshake bytes — fast enough
    /// that a per-read timer would keep resetting — must still hit the ABSOLUTE
    /// handshake deadline. A silent peer wouldn't distinguish the two designs
    /// (a per-read timer also fires on pure silence); the drip is what exercises
    /// the reset bug. Production uses `HANDSHAKE_TIMEOUT` (Scala
    /// `handshakeTimeout = 30s`); the deadline is injectable so this drives a
    /// short real clock instead of the `test-util` paused clock this crate
    /// deliberately avoids (see `mining_bridge` tests).
    #[tokio::test]
    async fn do_handshake_absolute_deadline_fires_on_slow_loris_trickle() {
        use ergo_p2p::handshake::{PeerSpec, Version};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut slow_client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let our = Handshake {
            time: 1_700_000_000_000,
            peer_spec: PeerSpec {
                agent_name: "ergo-rust/test".into(),
                version: Version {
                    major: 5,
                    minor: 0,
                    patch: 13,
                },
                node_name: "t".into(),
                declared_address: None,
                features: vec![],
            },
        };
        let deadline = Duration::from_millis(150);
        // Drip one byte every 50ms — under the deadline, so a per-read timer
        // would reset on each byte and never fire. The bytes never form a valid
        // handshake, so the read loop keeps spinning until the absolute deadline.
        let drip = tokio::spawn(async move {
            loop {
                if slow_client.write_all(&[0]).await.is_err() {
                    break; // server closed on deadline
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let started = tokio::time::Instant::now();
        // Outer watchdog: if the implementation regresses to a per-read timer,
        // the drip above keeps the read pending forever, so this timeout (not the
        // deadline) is what would fire — `.expect` then fails the test instead of
        // hanging. `Connection` isn't `Debug`, so match instead of `unwrap_err`.
        let result = tokio::time::timeout(
            deadline + Duration::from_secs(1),
            do_handshake(server, MAINNET_MAGIC, &our, deadline),
        )
        .await
        .expect("test watchdog: do_handshake did not return — per-read timer regression?");
        let elapsed = started.elapsed();
        drip.abort();

        match result {
            Err(e) => assert!(e.contains("deadline"), "expected deadline error, got: {e}"),
            Ok(_) => panic!("trickling peer should not complete a handshake"),
        }
        // It must actually wait for the deadline rather than failing instantly.
        assert!(
            elapsed >= deadline,
            "returned before deadline: {elapsed:?} < {deadline:?}",
        );
    }

    /// M-5 accounting: a metered payload holds exactly its byte length
    /// out of the shared budget, and dropping the event releases it —
    /// wherever it is consumed or discarded, with no consumer-side
    /// discipline.
    #[tokio::test]
    async fn metered_payload_takes_and_releases_budget() {
        let budget = new_event_byte_budget();
        let before = budget.bytes().available_permits();

        let payload = meter(vec![0xAB; 1_000], &budget).await;
        assert_eq!(
            budget.bytes().available_permits(),
            before - 1_000,
            "acquisition must charge the payload's byte length"
        );

        drop(payload);
        assert_eq!(
            budget.bytes().available_permits(),
            before,
            "drop must release the charged bytes"
        );
    }

    /// A frame read in many chunks is charged per chunk while it is read,
    /// but the payload that reaches the queue must hold EXACTLY its own
    /// length — #279's invariant — with the excess released and the
    /// unadmitted header-phase bytes topped up. A 1 MiB frame crosses 16
    /// read chunks, so this exercises the settle path in both directions.
    #[tokio::test]
    async fn read_metered_frame_settles_permits_to_the_payload_length() {
        const PAYLOAD_LEN: usize = 1 << 20;

        let (client, mut server_conn) = server_conn_with_idle(Duration::from_secs(30)).await;
        let writer = tokio::spawn(async move {
            let mut client_conn = Connection::new(client, MAINNET_MAGIC);
            client_conn.send(88, vec![0x7E; PAYLOAD_LEN]).await.unwrap();
            client_conn
        });

        let budget = new_event_byte_budget();
        let before = budget.bytes().available_permits();
        let (code, payload) = read_metered_frame(&mut server_conn, &budget)
            .await
            .expect("frame");
        assert_eq!(code, 88);
        assert_eq!(payload.len(), PAYLOAD_LEN);
        assert_eq!(
            budget.bytes().available_permits(),
            before - PAYLOAD_LEN,
            "an enqueued payload holds exactly its own bytes"
        );
        assert_eq!(
            budget.slots_available(),
            new_event_byte_budget().slots_available(),
            "the reader slot is released with the frame"
        );

        drop(payload);
        assert_eq!(budget.bytes().available_permits(), before);
        let _client = writer.await.unwrap();
    }

    // ----- error paths -----

    /// #280 P1: a peer that declares a maximal body and then sends
    /// nothing must NOT be able to reserve that whole declaration. The
    /// budget is charged per socket read, so 9 bytes of header buy one
    /// `READ_BUF_SIZE` chunk and no more — 32 such peers cannot drain the
    /// node's budget and park every honest reader.
    #[tokio::test]
    async fn read_metered_frame_header_only_staller_holds_one_read_chunk() {
        // Long deadline: this test is about how MUCH is held, not for how
        // long. The read runs in its own task because the hold has to be
        // observed WHILE the reader is parked — cancelling it releases.
        let (mut client, mut server_conn) = server_conn_with_idle(Duration::from_secs(30)).await;
        client
            .write_all(&header_bytes(88, MAX_PAYLOAD_SIZE))
            .await
            .unwrap();

        let budget = new_event_byte_budget();
        let before = budget.bytes().available_permits();
        let slots_before = budget.slots_available();
        let reader_budget = budget.clone();
        let reader = tokio::spawn(async move {
            let _ = read_metered_frame(&mut server_conn, &reader_budget).await;
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !reader.is_finished(),
            "a body that never arrives cannot complete"
        );
        assert_eq!(
            budget.bytes().available_permits(),
            before - (HEADER_LENGTH + READ_BUF_SIZE),
            "a bare header must hold the bytes it has plus one read chunk, not its declaration"
        );

        // Dropping the parked reader releases the chunk AND the slot:
        // nothing strands.
        reader.abort();
        let _ = reader.await;
        assert_eq!(budget.bytes().available_permits(), before);
        assert_eq!(budget.slots_available(), slots_before);
        drop(client);
    }

    /// #280: with the budget exhausted the reader parks before reading
    /// the body — only the bounded header-phase overshoot is buffered,
    /// not the megabyte the frame declares — and the socket stops being
    /// drained, which is the TCP backpressure the budget trades for
    /// memory. Cancelling the parked read then re-reading resumes on the
    /// same frame: the header was peeked, not consumed.
    #[tokio::test]
    async fn read_metered_frame_exhausted_budget_parks_before_reading_the_body() {
        const PAYLOAD_LEN: usize = 1 << 20; // 1 MiB — 16x the read chunk

        let (client, mut server_conn) = server_conn_with_idle(Duration::from_secs(30)).await;
        // The write blocks once the socket buffers fill — which is the
        // point — so it has to run on its own task.
        let writer = tokio::spawn(async move {
            let mut client_conn = Connection::new(client, MAINNET_MAGIC);
            client_conn.send(88, vec![0x7E; PAYLOAD_LEN]).await.unwrap();
            client_conn
        });

        // Sized so the frame fits with room for the one chunk that is
        // outstanding mid-read, then held down to under a single chunk.
        const BUDGET: usize = PAYLOAD_LEN + 2 * READ_BUF_SIZE;
        let budget = ReadBudget::new(BUDGET);
        let hold = budget
            .bytes()
            .clone()
            .acquire_many_owned((BUDGET - 16) as u32)
            .await
            .unwrap();

        let parked = tokio::time::timeout(
            Duration::from_millis(300),
            read_metered_frame(&mut server_conn, &budget),
        )
        .await;
        assert!(
            parked.is_err(),
            "reader must park on the budget, not deliver the frame"
        );
        assert!(
            server_conn.buffered_bytes() <= HEADER_PHASE_OVERSHOOT,
            "parked reader buffered {} bytes of a {PAYLOAD_LEN}-byte body",
            server_conn.buffered_bytes()
        );

        drop(hold);
        let (code, payload) = read_metered_frame(&mut server_conn, &budget)
            .await
            .expect("frame after the budget frees");
        assert_eq!(code, 88);
        assert_eq!(payload.len(), PAYLOAD_LEN);
        assert_eq!(
            budget.bytes().available_permits(),
            BUDGET - PAYLOAD_LEN,
            "the delivered payload holds exactly its own bytes"
        );
        drop(payload);
        assert_eq!(budget.bytes().available_permits(), BUDGET);

        let _client = writer.await.unwrap();
    }

    /// M-5 backpressure: when the budget is exhausted, a reader's
    /// acquisition blocks (it does not enqueue) until space frees — this
    /// is what turns memory pressure into TCP backpressure.
    #[tokio::test]
    async fn acquisition_blocks_while_budget_exhausted() {
        let budget = ReadBudget::new(2);
        let _hold = meter(vec![0u8; 2], &budget).await;

        let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let a2 = attempted.clone();
        let task = tokio::spawn(async move {
            let p = meter(vec![0u8; 1], &budget).await;
            a2.store(true, Ordering::Relaxed);
            p
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !attempted.load(Ordering::Relaxed),
            "acquisition must block while the budget is exhausted"
        );

        drop(_hold);
        let _p = task.await.unwrap();
        assert!(attempted.load(Ordering::Relaxed));
    }

    /// #280: the body no-progress deadline is a peer-behaviour judgement,
    /// so `peer_task` must both drop the connection AND score it — a
    /// silent disconnect would leave a staller free to reconnect and
    /// repeat, which is the attack the deadline exists to stop.
    #[tokio::test]
    async fn peer_task_stalled_body_disconnects_with_a_penalty() {
        let (mut client, server_conn) = server_conn_with_idle(Duration::from_millis(150)).await;
        client
            .write_all(&header_bytes(88, MAX_PAYLOAD_SIZE))
            .await
            .unwrap();

        let peer_id: SocketAddr = "127.0.0.1:9031".parse().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let (_outbound_tx, outbound_rx) = mpsc::channel::<MessageFrame>(16);
        let task = tokio::spawn(peer_task(
            peer_id,
            server_conn,
            event_tx,
            new_event_byte_budget(),
            outbound_rx,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ));

        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("deadline must fire")
            .expect("event");
        match event {
            PeerEvent::Disconnected { peer, penalty } => {
                assert_eq!(peer, peer_id);
                assert_eq!(
                    penalty,
                    Some(Penalty::NonDelivery),
                    "a withheld body is scored as non-delivery, not provable misbehavior"
                );
            }
            _ => panic!("expected Disconnected"),
        }
        task.await.unwrap();
        drop(client);
    }

    /// #280 P0 — the hold-and-wait deadlock. Readers charged per read
    /// hold permits for what they have taken in and then wait for more.
    /// Concurrent readers whose COMBINED demand exceeds the budget used
    /// to split it between themselves, park needing one more chunk each,
    /// and never complete — nothing reaches the channel, so no payload is
    /// ever dropped and no permit ever comes back. All P2P reading stops,
    /// permanently.
    ///
    /// Forty concurrent readers of 1 MiB frames against a 25 MB budget is
    /// that shape — 44 MB of concurrent demand for 25 MB of budget, and
    /// under the unslotted code every one of them parks — so the slot
    /// pool must get all forty through. Sizes are scaled down from the
    /// production 256 MiB / 8 MB, which is the same ratio in 320 MB of
    /// loopback traffic.
    ///
    /// Each reader drops its payload as soon as it has it, which is what
    /// the action loop does when it drains the event; holding all forty
    /// would exceed the budget by construction and prove nothing about
    /// the readers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_readers_over_budget_all_complete() {
        const READERS: usize = 40;
        const FRAME: usize = 1 << 20;
        // Enough of each frame to put every reader mid-body at the same
        // moment, holding permits and needing more.
        const PART_ONE: usize = 700_000;
        const BUDGET: usize = 25_000_000;

        // The deadlock this pins needs every reader holding at once, so
        // the senders deliver most of each frame, pause while the readers
        // pile up against the budget, then finish. Checked at compile
        // time so a later tweak to the sizes cannot quietly defuse it.
        const _: () = assert!(READERS * PART_ONE > BUDGET);

        let budget = ReadBudget::new(BUDGET);
        let mut readers = Vec::with_capacity(READERS);
        for i in 0..READERS {
            let (mut client, mut server_conn) =
                server_conn_with_idle(Duration::from_secs(30)).await;
            let bytes = ergo_p2p::framing::serialize_frame(
                &MAINNET_MAGIC,
                &MessageFrame {
                    code: 88,
                    payload: vec![i as u8; FRAME],
                },
            );
            let writer = tokio::spawn(async move {
                client.write_all(&bytes[..PART_ONE]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(400)).await;
                client.write_all(&bytes[PART_ONE..]).await.unwrap();
                client
            });
            let reader_budget = budget.clone();
            readers.push(tokio::spawn(async move {
                let (code, payload) = read_metered_frame(&mut server_conn, &reader_budget)
                    .await
                    .expect("every reader must finish");
                let seen = (code, payload.len(), payload[0]);
                // Drain, as the action loop does.
                drop(payload);
                // Hold the writer open until its frame has been read.
                let _client = writer.await.unwrap();
                seen
            }));
        }

        // Generous, but finite: a deadlock fails here instead of hanging
        // the suite.
        let all = tokio::time::timeout(Duration::from_secs(60), async {
            let mut seen = Vec::with_capacity(READERS);
            for reader in readers {
                seen.push(reader.await.unwrap());
            }
            seen
        })
        .await
        .expect("no reader may deadlock on the byte budget");

        assert_eq!(all.len(), READERS);
        for (i, (code, len, first)) in all.iter().enumerate() {
            assert_eq!(*code, 88);
            assert_eq!(*len, FRAME);
            assert_eq!(
                *first, i as u8,
                "frames must not be crossed between readers"
            );
        }
        assert_eq!(
            budget.bytes().available_permits(),
            BUDGET,
            "every byte permit is returned once the payloads are drained"
        );
        assert_eq!(
            budget.slots_available(),
            ReadBudget::new(BUDGET).slots_available(),
            "every slot is returned once its frame is delivered"
        );
    }

    /// The ordering rule that makes the deadlock argument sound: a frame
    /// that fits inside ONE read is charged once, up front, and never
    /// waits while holding permits — so it needs no slot, and header and
    /// transaction gossip cannot queue behind block bodies.
    #[tokio::test]
    async fn small_frame_reader_takes_no_slot() {
        let (client, mut server_conn) = server_conn_with_idle(Duration::from_secs(30)).await;
        let writer = tokio::spawn(async move {
            let mut client_conn = Connection::new(client, MAINNET_MAGIC);
            // Comfortably inside one READ_BUF_SIZE chunk.
            client_conn.send(7, vec![0x5A; 1_024]).await.unwrap();
            client_conn
        });

        let budget = new_event_byte_budget();
        let slots = budget.slots_available();
        let (code, payload) = read_metered_frame(&mut server_conn, &budget)
            .await
            .expect("frame");
        assert_eq!(code, 7);
        assert_eq!(payload.len(), 1_024);
        assert_eq!(
            budget.slots_available(),
            slots,
            "a single-read frame must never consume a hold-and-wait slot"
        );
        let _client = writer.await.unwrap();
    }

    /// P2-3(b): parking on an exhausted budget is BACKPRESSURE, not peer
    /// inactivity. A reader held off the budget for many times the body
    /// deadline must not blame the peer — no stall error, so no penalty.
    ///
    /// Real clock with an injected short deadline, not `tokio::time::pause`:
    /// this crate deliberately avoids the paused clock around live
    /// sockets (see `do_handshake_absolute_deadline_fires_on_slow_loris_trickle`),
    /// where auto-advance can fire a timer while bytes are still in the
    /// kernel.
    #[tokio::test]
    async fn budget_backpressure_longer_than_the_deadline_is_not_a_stall() {
        const FRAME: usize = 300_000;
        const BUDGET: usize = FRAME + 2 * READ_BUF_SIZE;

        // Deadline far shorter than the time we hold the budget shut,
        // but long enough that ordinary scheduling jitter once the budget
        // frees cannot look like a stalled peer.
        let (client, mut server_conn) = server_conn_with_idle(Duration::from_millis(150)).await;
        let writer = tokio::spawn(async move {
            let mut client_conn = Connection::new(client, MAINNET_MAGIC);
            client_conn.send(21, vec![0xA5; FRAME]).await.unwrap();
            client_conn
        });

        let budget = ReadBudget::new(BUDGET);
        let hold = budget
            .bytes()
            .clone()
            .acquire_many_owned((BUDGET - 8) as u32)
            .await
            .unwrap();

        let reader_budget = budget.clone();
        let reader =
            tokio::spawn(async move { read_metered_frame(&mut server_conn, &reader_budget).await });

        // Ten deadline periods parked on the budget.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!reader.is_finished(), "reader should still be parked");

        drop(hold);
        let (code, payload) = reader
            .await
            .unwrap()
            .expect("backpressure must not be reported as a peer stall");
        assert_eq!(code, 21);
        assert_eq!(payload.len(), FRAME);
        let _client = writer.await.unwrap();
    }

    /// The charge helper is the single place a byte count becomes a
    /// permit count; it must never truncate a legal frame size and must
    /// never charge a payload nothing.
    #[test]
    fn charge_for_covers_every_legal_frame_size() {
        assert_eq!(charge_for(0), 1, "an empty payload still costs a permit");
        assert_eq!(charge_for(1), 1);
        assert_eq!(charge_for(READ_BUF_SIZE), READ_BUF_SIZE as u32);
        assert_eq!(charge_for(MAX_PAYLOAD_SIZE), MAX_PAYLOAD_SIZE as u32);
        // Every legal charge is far below the budget, so no call is ever
        // clamped in practice — the clamp exists so an out-of-range ask
        // degrades to something the semaphore can actually grant rather
        // than parking forever (and trips a debug assertion first).
        const _: () = assert!(MAX_PAYLOAD_SIZE < EVENT_BYTE_BUDGET_MAX);
    }
}
