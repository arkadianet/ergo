//! Per-peer async tasks: dial / accept + read/write loop.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ergo_api::SubmitError;
use ergo_p2p::connection::Connection;
use ergo_p2p::framing::{wire_len, MessageFrame};
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, Handshake, PeerSpec,
};
use ergo_p2p::peer::HANDSHAKE_TIMEOUT;
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
    Message {
        peer: SocketAddr,
        code: u8,
        payload: Vec<u8>,
    },
    Disconnected {
        peer: SocketAddr,
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

/// Per-peer read/write loop. Owns the Connection.
/// Reads frames → sends PeerEvent::Message to action loop.
/// Receives outbound MessageFrame from action loop → writes to peer.
pub async fn peer_task(
    peer_id: SocketAddr,
    mut conn: Connection,
    event_tx: mpsc::Sender<PeerEvent>,
    mut outbound_rx: mpsc::Receiver<MessageFrame>,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            result = conn.read_message() => {
                match result {
                    Ok(frame) => {
                        // Count the exact on-wire frame size on a successful
                        // read, before `payload` is moved into the event.
                        // Post-handshake framed bytes only — the handshake
                        // round-trip preceded this task owning the conn.
                        bytes_in.fetch_add(wire_len(frame.payload.len()) as u64, Ordering::Relaxed);
                        if event_tx.send(PeerEvent::Message {
                            peer: peer_id,
                            code: frame.code,
                            payload: frame.payload,
                        }).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        debug!(peer = %peer_id, error = %e, "peer read error; disconnecting");
                        let _ = event_tx.send(PeerEvent::Disconnected { peer: peer_id }).await;
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
                                let _ = event_tx.send(PeerEvent::Disconnected { peer: peer_id }).await;
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
    use ergo_p2p::framing::MAINNET_MAGIC;

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

    /// A silent / slow-loris peer must hit the ABSOLUTE handshake deadline, not
    /// be held forever by the (former) per-read timer that any byte reset.
    /// Production uses `HANDSHAKE_TIMEOUT` (Scala `handshakeTimeout = 30s`); the
    /// deadline is injectable so this drives a short real clock instead of the
    /// `test-util` paused clock this crate deliberately avoids (see
    /// `mining_bridge` tests).
    #[tokio::test]
    async fn do_handshake_absolute_deadline_fires_on_silent_peer() {
        use ergo_p2p::handshake::{PeerSpec, Version};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Connect but never send a (complete) handshake; keep it alive so the
        // server's read stays pending rather than seeing a clean EOF.
        let _silent_client = TcpStream::connect(addr).await.unwrap();
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
        let started = tokio::time::Instant::now();
        // The per-read timer alone would never fire on a silent peer; only the
        // absolute deadline can. `Connection` isn't `Debug`, so match instead of
        // `unwrap_err()` (which would need the Ok tuple to be `Debug`).
        let result = do_handshake(server, MAINNET_MAGIC, &our, deadline).await;
        let elapsed = started.elapsed();
        match result {
            Err(e) => assert!(e.contains("deadline"), "expected deadline error, got: {e}"),
            Ok(_) => panic!("silent peer should not complete a handshake"),
        }
        // It must actually wait for the deadline rather than failing instantly.
        assert!(
            elapsed >= deadline,
            "returned before deadline: {elapsed:?} < {deadline:?}",
        );
    }
}
