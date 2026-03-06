use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::mpsc;

use ergo_wire::codec::RawMessage;
use ergo_wire::handshake::{ConnectionDirection, Handshake, ProtocolVersion};
use ergo_wire::peer_feature::ModeFeature;

use crate::peer_conn::{PeerConnError, PeerConnection};

/// Unique identifier for a connected peer.
pub type PeerId = u64;

/// A message received from a peer.
#[derive(Debug)]
pub struct IncomingMessage {
    pub peer_id: PeerId,
    pub message: RawMessage,
}

/// Handle to a connected peer's outgoing channel.
struct PeerHandle {
    id: PeerId,
    addr: SocketAddr,
    peer_name: String,
    /// User-configured node name from the handshake PeerSpec.
    node_name: String,
    tx: mpsc::Sender<(u8, Vec<u8>)>,
    /// Epoch milliseconds when the peer connected (used for `lastHandshake`).
    connected_at: u64,
    task: tokio::task::JoinHandle<()>,
    version: ProtocolVersion,
    direction: ConnectionDirection,
    /// The peer's ModeFeature extracted from its handshake, if present.
    mode_feature: Option<ModeFeature>,
    /// Epoch milliseconds of the last received message from this peer.
    /// Updated atomically by the peer task on every inbound message.
    last_activity: Arc<AtomicU64>,
}

/// Summary of a connected peer returned by `ConnectionPool::connected_peers()`.
#[derive(Debug, Clone)]
pub struct ConnectedPeerEntry {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub peer_name: String,
    /// User-configured node name from the handshake PeerSpec.
    pub node_name: String,
    pub connected_at: u64,
    pub direction: ConnectionDirection,
    pub version: ProtocolVersion,
    /// The peer's ModeFeature extracted from its handshake, if present.
    pub mode_feature: Option<ModeFeature>,
    /// Epoch milliseconds of the last received message from this peer.
    pub last_activity: u64,
}

/// Manages a pool of peer connections.
///
/// Each peer connection runs as a separate Tokio task. Messages from all peers
/// arrive on a single mpsc channel (`inbox`). Outgoing messages are sent via
/// per-peer mpsc channels.
pub struct ConnectionPool {
    peers: HashMap<PeerId, PeerHandle>,
    inbox_rx: mpsc::Receiver<IncomingMessage>,
    inbox_tx: mpsc::Sender<IncomingMessage>,
    magic: [u8; 4],
    our_handshake: Handshake,
    next_id: PeerId,
    handshake_timeout_secs: u64,
    /// Random session ID generated at startup, used to detect self-connections.
    session_id: Option<u64>,
}

/// Extract the ModeFeature from a peer's handshake, if present.
fn extract_mode_feature(hs: &Handshake) -> Option<ModeFeature> {
    use ergo_wire::peer_feature::PeerFeature;
    hs.peer_spec.features.iter().find_map(|f| {
        if let PeerFeature::Mode(m) = f {
            Some(m.clone())
        } else {
            None
        }
    })
}

impl ConnectionPool {
    /// Create a new empty connection pool.
    pub fn new(magic: [u8; 4], our_handshake: Handshake) -> Self {
        Self::with_handshake_timeout(magic, our_handshake, 30)
    }

    /// Create a new empty connection pool with a custom handshake timeout.
    pub fn with_handshake_timeout(
        magic: [u8; 4],
        our_handshake: Handshake,
        handshake_timeout_secs: u64,
    ) -> Self {
        let (inbox_tx, inbox_rx) = mpsc::channel(1024);
        Self {
            peers: HashMap::new(),
            inbox_rx,
            inbox_tx,
            magic,
            our_handshake,
            next_id: 1,
            handshake_timeout_secs,
            session_id: None,
        }
    }

    /// Set the session ID for self-connection detection.
    pub fn set_session_id(&mut self, session_id: u64) {
        self.session_id = Some(session_id);
    }

    /// Connect to a peer, perform handshake, spawn its task, return PeerId.
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<PeerId, PeerConnError> {
        let (peer_conn, peer_hs) = PeerConnection::connect(
            addr,
            self.magic,
            &self.our_handshake,
            self.handshake_timeout_secs,
            self.session_id,
        )
        .await?;
        let peer_name = peer_hs.peer_spec.agent_name.clone();
        let node_name = peer_hs.peer_spec.node_name.clone();

        let id = self.next_id;
        self.next_id += 1;

        let (outbox_tx, outbox_rx) = mpsc::channel(256);
        let inbox_tx = self.inbox_tx.clone();

        let connected_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let last_activity = Arc::new(AtomicU64::new(connected_at));
        let task = tokio::spawn(peer_task(
            peer_conn,
            id,
            inbox_tx,
            outbox_rx,
            last_activity.clone(),
        ));

        let version = peer_hs.peer_spec.protocol_version;
        let mode_feature = extract_mode_feature(&peer_hs);
        self.peers.insert(
            id,
            PeerHandle {
                id,
                addr,
                peer_name,
                node_name,
                tx: outbox_tx,
                connected_at,
                task,
                version,
                direction: ConnectionDirection::Outgoing,
                mode_feature,
                last_activity,
            },
        );

        Ok(id)
    }

    /// Register an already-handshaked inbound connection.
    pub fn add_inbound(
        &mut self,
        conn: PeerConnection,
        addr: SocketAddr,
        peer_hs: &Handshake,
    ) -> PeerId {
        self.register_peer(conn, addr, peer_hs, ConnectionDirection::Incoming)
    }

    /// Register an already-handshaked outbound connection (from a background connect task).
    pub fn add_outbound(
        &mut self,
        conn: PeerConnection,
        addr: SocketAddr,
        peer_hs: &Handshake,
    ) -> PeerId {
        self.register_peer(conn, addr, peer_hs, ConnectionDirection::Outgoing)
    }

    /// Common helper: register a peer with the given direction.
    fn register_peer(
        &mut self,
        conn: PeerConnection,
        addr: SocketAddr,
        peer_hs: &Handshake,
        direction: ConnectionDirection,
    ) -> PeerId {
        let peer_name = peer_hs.peer_spec.agent_name.clone();
        let node_name = peer_hs.peer_spec.node_name.clone();
        let version = peer_hs.peer_spec.protocol_version;

        let id = self.next_id;
        self.next_id += 1;

        let (outbox_tx, outbox_rx) = mpsc::channel(256);
        let inbox_tx = self.inbox_tx.clone();

        let connected_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let last_activity = Arc::new(AtomicU64::new(connected_at));
        let task = tokio::spawn(peer_task(
            conn,
            id,
            inbox_tx,
            outbox_rx,
            last_activity.clone(),
        ));

        let mode_feature = extract_mode_feature(peer_hs);
        self.peers.insert(
            id,
            PeerHandle {
                id,
                addr,
                peer_name,
                node_name,
                tx: outbox_tx,
                connected_at,
                task,
                version,
                direction,
                mode_feature,
                last_activity,
            },
        );

        id
    }

    /// Disconnect a peer by ID.
    pub fn disconnect(&mut self, peer_id: PeerId) {
        if let Some(handle) = self.peers.remove(&peer_id) {
            handle.task.abort();
        }
    }

    /// Send a message to a specific peer.
    ///
    /// Uses `try_send` to avoid blocking the event loop when a peer's outbox
    /// is full. Returns an error if the peer is unknown, disconnected, or if
    /// the outbox is at capacity (the message is dropped).
    pub fn send_to(&self, peer_id: PeerId, code: u8, body: Vec<u8>) -> Result<(), PeerConnError> {
        let handle = self.peers.get(&peer_id).ok_or_else(|| {
            PeerConnError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "unknown peer",
            ))
        })?;
        match handle.tx.try_send((code, body)) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!(peer_id, code, "peer outbox full, message dropped");
                Err(PeerConnError::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "peer outbox full",
                )))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(PeerConnError::Io(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "peer task gone"),
            )),
        }
    }

    /// Send a message to all connected peers.
    ///
    /// Non-blocking: drops messages for peers whose outbox is full.
    pub fn broadcast(&self, code: u8, body: &[u8]) {
        for handle in self.peers.values() {
            let _ = handle.tx.try_send((code, body.to_vec()));
        }
    }

    /// Send a message to all connected peers except the specified one.
    ///
    /// Non-blocking: drops messages for peers whose outbox is full.
    pub fn broadcast_except(&self, exclude: PeerId, code: u8, body: &[u8]) {
        for (id, handle) in &self.peers {
            if *id != exclude {
                let _ = handle.tx.try_send((code, body.to_vec()));
            }
        }
    }

    /// Receive the next message from any peer.
    pub async fn recv(&mut self) -> Option<IncomingMessage> {
        self.inbox_rx.recv().await
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// List connected peer info.
    pub fn connected_peers(&self) -> Vec<ConnectedPeerEntry> {
        self.peers
            .values()
            .map(|h| ConnectedPeerEntry {
                id: h.id,
                addr: h.addr,
                peer_name: h.peer_name.clone(),
                node_name: h.node_name.clone(),
                connected_at: h.connected_at,
                direction: h.direction,
                version: h.version,
                mode_feature: h.mode_feature.clone(),
                last_activity: h.last_activity.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Return the epoch-millisecond timestamp of the last received message
    /// from the given peer, or `None` if the peer is not connected.
    pub fn peer_last_activity(&self, peer_id: PeerId) -> Option<u64> {
        self.peers
            .get(&peer_id)
            .map(|h| h.last_activity.load(Ordering::Relaxed))
    }

    /// Clean up peers whose tasks have finished (disconnected).
    pub fn cleanup_disconnected(&mut self) {
        let finished: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, h)| h.task.is_finished())
            .map(|(&id, _)| id)
            .collect();
        for id in finished {
            tracing::debug!(peer_id = id, "cleaning up disconnected peer");
            self.peers.remove(&id);
        }
    }
}

/// Per-peer background task.
///
/// Reads messages from the peer connection and forwards them to the shared
/// inbox. Sends outgoing messages from the per-peer outbox to the connection.
async fn peer_task(
    mut conn: PeerConnection,
    peer_id: PeerId,
    inbox_tx: mpsc::Sender<IncomingMessage>,
    mut outbox_rx: mpsc::Receiver<(u8, Vec<u8>)>,
    last_activity: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            result = conn.recv_message() => {
                match result {
                    Ok(msg) => {
                        let now = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        last_activity.store(now, Ordering::Relaxed);
                        if inbox_tx.send(IncomingMessage { peer_id, message: msg }).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(peer_id, error = %e, "peer read error");
                        break;
                    }
                }
            }
            msg = outbox_rx.recv() => {
                match msg {
                    Some((code, body)) => {
                        tracing::trace!(peer_id, code, body_len = body.len(), "peer_task: sending msg");
                        if let Err(e) = conn.send_message(code, &body).await {
                            tracing::debug!(peer_id, error = %e, "peer write error");
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wire::handshake::{PeerSpec, ProtocolVersion};

    /// Helper: create a test handshake.
    fn test_handshake() -> Handshake {
        Handshake {
            time: 1_000_000,
            peer_spec: PeerSpec {
                agent_name: "test-node".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "test".into(),
                declared_address: None,
                features: vec![],
            },
        }
    }

    #[test]
    fn new_pool_is_empty() {
        let pool = ConnectionPool::new([1, 0, 2, 4], test_handshake());
        assert_eq!(pool.peer_count(), 0);
        assert!(pool.connected_peers().is_empty());
    }

    #[test]
    fn pool_has_correct_magic() {
        let magic = [2, 0, 0, 1];
        let pool = ConnectionPool::new(magic, test_handshake());
        // Verify the pool was created with our magic by checking it's
        // operational (peer_count returns without panic).
        assert_eq!(pool.peer_count(), 0);
        assert_eq!(pool.magic, magic);
    }

    #[test]
    fn disconnect_unknown_peer_is_noop() {
        let mut pool = ConnectionPool::new([1, 0, 2, 4], test_handshake());
        // Should not panic.
        pool.disconnect(999);
        assert_eq!(pool.peer_count(), 0);
    }

    #[tokio::test]
    async fn send_to_unknown_peer_returns_error() {
        let pool = ConnectionPool::new([1, 0, 2, 4], test_handshake());
        let result = pool.send_to(999, 1, vec![0xAB]);
        assert!(result.is_err());
    }

    #[test]
    fn cleanup_on_empty_pool_is_noop() {
        let mut pool = ConnectionPool::new([1, 0, 2, 4], test_handshake());
        // Should not panic.
        pool.cleanup_disconnected();
        assert_eq!(pool.peer_count(), 0);
    }

    #[test]
    fn connected_peers_empty_initially() {
        let pool = ConnectionPool::new([1, 0, 2, 4], test_handshake());
        let peers = pool.connected_peers();
        assert!(peers.is_empty());
    }

    #[test]
    fn connected_peer_entry_fields() {
        let pool = ConnectionPool::new([1, 0, 2, 4], test_handshake());
        let peers = pool.connected_peers();
        assert!(peers.is_empty());
        // Verify the return type is Vec<ConnectedPeerEntry> (compile-time check)
        let _: Vec<ConnectedPeerEntry> = peers;
    }

    #[tokio::test]
    async fn pool_add_inbound_tracks_direction() {
        use crate::peer_conn::PeerConnection;

        let magic = [2, 0, 0, 1];

        let hs_server = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "pool-server".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "s".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let hs_client = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "pool-client".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "c".into(),
                declared_address: None,
                features: vec![],
            },
        };

        // Set up a TCP connection pair via listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let hs_server_clone = hs_server.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            PeerConnection::accept(stream, magic, &hs_server_clone, 5, None)
                .await
                .unwrap()
        });

        // Client connects (outgoing).
        let (_client_conn, _) = PeerConnection::connect(addr, magic, &hs_client, 5, None)
            .await
            .unwrap();

        // Server gets the inbound connection.
        let (server_conn, peer_hs) = server.await.unwrap();

        // Add to pool as inbound.
        let mut pool = ConnectionPool::new(magic, hs_server);
        let id = pool.add_inbound(server_conn, addr, &peer_hs);
        assert_eq!(pool.peer_count(), 1);

        let peers = pool.connected_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].id, id);
        assert_eq!(peers[0].direction, ConnectionDirection::Incoming);
        assert_eq!(peers[0].peer_name, "pool-client");

        pool.disconnect(id);
    }

    #[tokio::test]
    async fn pool_connect_sets_outgoing_direction() {
        let magic = [2, 0, 0, 1];

        let hs_server = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "server".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "s".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let hs_pool = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "pool-node".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "p".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server task: accept and send handshake.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(&hs_server.serialize()).await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            // Keep the connection alive for a bit.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let mut pool = ConnectionPool::new(magic, hs_pool);
        let id = pool.connect(addr).await.unwrap();

        let peers = pool.connected_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].id, id);
        assert_eq!(peers[0].direction, ConnectionDirection::Outgoing);

        pool.disconnect(id);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn activity_timestamp_initialized_on_connect() {
        use crate::peer_conn::PeerConnection;

        let magic = [2, 0, 0, 1];

        let hs_server = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "act-server".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "s".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let hs_client = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "act-client".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "c".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let hs_server_clone = hs_server.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            PeerConnection::accept(stream, magic, &hs_server_clone, 5, None)
                .await
                .unwrap()
        });

        let (_client_conn, _) = PeerConnection::connect(addr, magic, &hs_client, 5, None)
            .await
            .unwrap();

        let (server_conn, peer_hs) = server.await.unwrap();

        let mut pool = ConnectionPool::new(magic, hs_server);
        let id = pool.add_inbound(server_conn, addr, &peer_hs);

        let activity = pool.peer_last_activity(id);
        assert!(
            activity.is_some(),
            "peer_last_activity should return Some for connected peer"
        );
        assert!(
            activity.unwrap() > 0,
            "last_activity should be a positive epoch ms timestamp"
        );

        pool.disconnect(id);
    }

    #[tokio::test]
    async fn connected_peer_entry_has_last_activity() {
        use crate::peer_conn::PeerConnection;

        let magic = [2, 0, 0, 1];

        let hs_server = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "entry-server".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "s".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let hs_client = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "entry-client".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "c".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let hs_server_clone = hs_server.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            PeerConnection::accept(stream, magic, &hs_server_clone, 5, None)
                .await
                .unwrap()
        });

        let (_client_conn, _) = PeerConnection::connect(addr, magic, &hs_client, 5, None)
            .await
            .unwrap();

        let (server_conn, peer_hs) = server.await.unwrap();

        let mut pool = ConnectionPool::new(magic, hs_server);
        let _id = pool.add_inbound(server_conn, addr, &peer_hs);

        let peers = pool.connected_peers();
        assert_eq!(peers.len(), 1);
        assert!(
            peers[0].last_activity > 0,
            "ConnectedPeerEntry.last_activity should be a positive epoch ms timestamp"
        );

        pool.disconnect(peers[0].id);
    }
}
