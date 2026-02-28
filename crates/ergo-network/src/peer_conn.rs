use ergo_settings::constants::{
    CHECKSUM_LENGTH, MAX_HANDSHAKE_SIZE, MESSAGE_HEADER_LENGTH,
};
use ergo_wire::codec::{self, FrameError, RawMessage};
use ergo_wire::handshake::{Handshake, ProtocolVersion};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// FrameBuffer
// ---------------------------------------------------------------------------

/// Accumulates TCP bytes and decodes framed P2P messages.
pub struct FrameBuffer {
    magic: [u8; 4],
    buf: Vec<u8>,
}

impl FrameBuffer {
    /// Create a new frame buffer for the given network magic bytes.
    pub fn new(magic: [u8; 4]) -> Self {
        Self {
            magic,
            buf: Vec::new(),
        }
    }

    /// Append incoming TCP data to the internal buffer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to decode a complete message from the buffer.
    ///
    /// Returns `Ok(None)` if not enough data is available yet.
    /// On success the consumed bytes are drained from the buffer.
    pub fn try_decode(&mut self) -> Result<Option<RawMessage>, FrameError> {
        let msg = codec::decode_message(&self.magic, &self.buf)?;
        if let Some(ref m) = msg {
            let consumed = frame_size(m);
            self.buf.drain(..consumed);
        }
        Ok(msg)
    }
}

/// Compute the total byte length of a framed message on the wire.
fn frame_size(msg: &RawMessage) -> usize {
    if msg.body.is_empty() {
        MESSAGE_HEADER_LENGTH
    } else {
        MESSAGE_HEADER_LENGTH + CHECKSUM_LENGTH + msg.body.len()
    }
}

// ---------------------------------------------------------------------------
// PeerConnection
// ---------------------------------------------------------------------------

/// Error type for peer-connection operations.
#[derive(Debug, thiserror::Error)]
pub enum PeerConnError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame error: {0}")]
    Frame(#[from] FrameError),

    #[error("handshake too large ({0} bytes)")]
    HandshakeTooLarge(usize),

    #[error("handshake timed out after {0}s")]
    HandshakeTimeout(u64),

    #[error("handshake parse error: {0}")]
    HandshakeParse(#[from] ergo_wire::vlq::CodecError),

    #[error("peer version {0} below minimum {1}")]
    VersionTooOld(String, String),

    #[error("self-connection detected (matching session_id)")]
    SelfConnection,
}

/// An async TCP connection to an Ergo peer with message framing.
pub struct PeerConnection {
    stream: TcpStream,
    frame_buf: FrameBuffer,
    peer_handshake: Handshake,
}

impl PeerConnection {
    /// Connect to a peer, perform the handshake exchange, and return the
    /// connection together with the remote peer's handshake.
    ///
    /// `handshake_timeout_secs` enforces a deadline on receiving the remote
    /// handshake. If 0, no timeout is applied (not recommended for production).
    pub async fn connect(
        addr: SocketAddr,
        magic: [u8; 4],
        our_handshake: &Handshake,
        handshake_timeout_secs: u64,
        our_session_id: Option<u64>,
    ) -> Result<(Self, Handshake), PeerConnError> {
        // Cap TCP connect to 5 seconds to prevent blocking the caller for
        // the full OS timeout (~135s on Linux) when a peer is unreachable.
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| PeerConnError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TCP connect timed out (5s)",
        )))??;

        // Send our handshake as raw bytes (no message frame).
        let hs_bytes = our_handshake.serialize();
        stream.write_all(&hs_bytes).await?;

        // Receive the peer's handshake with timeout enforcement.
        // A peer that connects but never sends handshake data must not hang
        // the node indefinitely.
        let (peer_hs, leftover) = if handshake_timeout_secs > 0 {
            tokio::time::timeout(
                Duration::from_secs(handshake_timeout_secs),
                read_handshake(&mut stream),
            )
            .await
            .map_err(|_| PeerConnError::HandshakeTimeout(handshake_timeout_secs))??
        } else {
            read_handshake(&mut stream).await?
        };

        check_peer_version(&peer_hs)?;
        if let Some(sid) = our_session_id {
            check_self_connection(&peer_hs, sid)?;
        }

        let mut frame_buf = FrameBuffer::new(magic);
        if !leftover.is_empty() {
            frame_buf.feed(&leftover);
        }

        let conn = Self {
            stream,
            frame_buf,
            peer_handshake: peer_hs.clone(),
        };
        Ok((conn, peer_hs))
    }

    /// Accept an inbound connection on an already-connected TCP stream.
    /// Performs the symmetric handshake exchange (both sides send immediately)
    /// and validates the peer's protocol version.
    pub async fn accept(
        mut stream: TcpStream,
        magic: [u8; 4],
        our_handshake: &Handshake,
        handshake_timeout_secs: u64,
        our_session_id: Option<u64>,
    ) -> Result<(Self, Handshake), PeerConnError> {
        // Send our handshake as raw bytes.
        let hs_bytes = our_handshake.serialize();
        stream.write_all(&hs_bytes).await?;

        // Read remote handshake with timeout.
        let (peer_hs, leftover) = if handshake_timeout_secs > 0 {
            tokio::time::timeout(
                Duration::from_secs(handshake_timeout_secs),
                read_handshake(&mut stream),
            )
            .await
            .map_err(|_| PeerConnError::HandshakeTimeout(handshake_timeout_secs))??
        } else {
            read_handshake(&mut stream).await?
        };

        check_peer_version(&peer_hs)?;
        if let Some(sid) = our_session_id {
            check_self_connection(&peer_hs, sid)?;
        }

        let mut frame_buf = FrameBuffer::new(magic);
        if !leftover.is_empty() {
            frame_buf.feed(&leftover);
        }

        let conn = Self {
            stream,
            frame_buf,
            peer_handshake: peer_hs.clone(),
        };
        Ok((conn, peer_hs))
    }

    /// Encode and send a framed message.
    pub async fn send_message(&mut self, code: u8, body: &[u8]) -> Result<(), PeerConnError> {
        let frame = codec::encode_message(&self.frame_buf.magic, code, body);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Receive and decode the next framed message.
    pub async fn recv_message(&mut self) -> Result<RawMessage, PeerConnError> {
        loop {
            // First try to decode from whatever is already buffered.
            if let Some(msg) = self.frame_buf.try_decode()? {
                return Ok(msg);
            }
            // Need more data from the network.
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(PeerConnError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed connection",
                )));
            }
            self.frame_buf.feed(&tmp[..n]);
        }
    }

    /// The peer's handshake received during connection setup.
    pub fn peer_handshake(&self) -> &Handshake {
        &self.peer_handshake
    }
}

/// Read a raw handshake from the stream. We read up to `MAX_HANDSHAKE_SIZE`
/// bytes. The handshake is self-delimiting via VLQ-encoded lengths, so we read
/// in chunks and try parsing after each chunk.
///
/// Returns the parsed handshake and any leftover bytes that were read beyond
/// the handshake (these belong to subsequent framed messages).
async fn read_handshake(stream: &mut TcpStream) -> Result<(Handshake, Vec<u8>), PeerConnError> {
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 1024];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(PeerConnError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before handshake completed",
            )));
        }
        buf.extend_from_slice(&tmp[..n]);

        if buf.len() > MAX_HANDSHAKE_SIZE {
            return Err(PeerConnError::HandshakeTooLarge(buf.len()));
        }

        // Try to parse — the handshake format is self-delimiting.
        match Handshake::parse(&buf) {
            Ok(hs) => {
                // Determine how many bytes the handshake consumed by
                // re-serializing (the format is deterministic).
                let consumed = hs.serialize().len();
                let leftover = buf[consumed..].to_vec();
                return Ok((hs, leftover));
            }
            Err(_) => {
                // Not enough data yet; keep reading.
                continue;
            }
        }
    }
}

/// Reject peers whose protocol version is below the EIP-37 fork threshold.
fn check_peer_version(peer_hs: &Handshake) -> Result<(), PeerConnError> {
    let min = ProtocolVersion::EIP37_FORK;
    if peer_hs.peer_spec.protocol_version < min {
        return Err(PeerConnError::VersionTooOld(
            peer_hs.peer_spec.protocol_version.to_string(),
            min.to_string(),
        ));
    }
    Ok(())
}

/// Reject connections where the peer's session ID matches ours (self-connection).
///
/// Walks the peer's handshake features looking for a `SessionFeature`. If found
/// and its `session_id` matches `our_session_id`, the connection is rejected.
/// If no `SessionFeature` is present, the check passes (older peers may not
/// include it).
pub fn check_self_connection(peer_hs: &Handshake, our_session_id: u64) -> Result<(), PeerConnError> {
    for feature in &peer_hs.peer_spec.features {
        if let ergo_wire::peer_feature::PeerFeature::Session(sf) = feature {
            if sf.session_id == our_session_id as i64 {
                return Err(PeerConnError::SelfConnection);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_buffer_accumulates() {
        let magic = [1, 0, 2, 4];
        let mut buf = FrameBuffer::new(magic);
        let frame = ergo_wire::codec::encode_message(&magic, 1, &[]);
        buf.feed(&frame[..5]); // partial
        assert!(buf.try_decode().unwrap().is_none());
        buf.feed(&frame[5..]);
        let msg = buf.try_decode().unwrap().unwrap();
        assert_eq!(msg.code, 1);
        assert!(msg.body.is_empty());
    }

    #[test]
    fn frame_buffer_multiple_messages() {
        let magic = [2, 0, 0, 1];
        let mut buf = FrameBuffer::new(magic);
        let f1 = ergo_wire::codec::encode_message(&magic, 1, &[]);
        let f2 = ergo_wire::codec::encode_message(&magic, 55, &[0xDE, 0xAD]);
        let mut combined = Vec::new();
        combined.extend_from_slice(&f1);
        combined.extend_from_slice(&f2);
        buf.feed(&combined);
        let m1 = buf.try_decode().unwrap().unwrap();
        assert_eq!(m1.code, 1);
        let m2 = buf.try_decode().unwrap().unwrap();
        assert_eq!(m2.code, 55);
        assert_eq!(m2.body, vec![0xDE, 0xAD]);
    }

    #[test]
    fn frame_buffer_empty_after_drain() {
        let magic = [1, 0, 2, 4];
        let mut buf = FrameBuffer::new(magic);
        let frame = ergo_wire::codec::encode_message(&magic, 7, &[0xAB]);
        buf.feed(&frame);
        let msg = buf.try_decode().unwrap().unwrap();
        assert_eq!(msg.code, 7);
        // No more data in buffer
        assert!(buf.try_decode().unwrap().is_none());
    }

    #[test]
    fn frame_size_empty_body() {
        let msg = RawMessage {
            code: 1,
            body: Vec::new(),
        };
        assert_eq!(frame_size(&msg), MESSAGE_HEADER_LENGTH);
    }

    #[test]
    fn frame_size_with_body() {
        let msg = RawMessage {
            code: 55,
            body: vec![0xDE, 0xAD],
        };
        assert_eq!(
            frame_size(&msg),
            MESSAGE_HEADER_LENGTH + CHECKSUM_LENGTH + 2
        );
    }

    #[tokio::test]
    async fn peer_connection_duplex() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};

        let magic = [2, 0, 0, 1];

        let hs_a = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "nodeA".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "a".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let hs_b = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "nodeB".into(),
                protocol_version: ProtocolVersion {
                    major: 6,
                    minor: 0,
                    patch: 0,
                },
                node_name: "b".into(),
                declared_address: None,
                features: vec![],
            },
        };

        // Bind a listener so we can accept a connection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let hs_b_clone = hs_b.clone();

        // A notify to keep the server alive until the client has read.
        let done = std::sync::Arc::new(tokio::sync::Notify::new());
        let done_server = done.clone();

        // Server task: accept, perform handshake, send a message.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Send server handshake raw.
            stream.write_all(&hs_b_clone.serialize()).await.unwrap();

            // Read client handshake raw.
            let mut hs_buf = vec![0u8; MAX_HANDSHAKE_SIZE];
            let n = stream.read(&mut hs_buf).await.unwrap();
            let peer_hs = Handshake::parse(&hs_buf[..n]).unwrap();
            assert_eq!(peer_hs.peer_spec.agent_name, "nodeA");

            // Send a framed message.
            let frame = codec::encode_message(&magic, 42, &[1, 2, 3]);
            stream.write_all(&frame).await.unwrap();

            // Wait until the client signals it has read the message.
            done_server.notified().await;
        });

        // Client side.
        let (conn, peer_hs) = PeerConnection::connect(addr, magic, &hs_a, 5, None).await.unwrap();
        assert_eq!(peer_hs.peer_spec.agent_name, "nodeB");

        let mut conn = conn;
        let msg = conn.recv_message().await.unwrap();
        assert_eq!(msg.code, 42);
        assert_eq!(msg.body, vec![1, 2, 3]);

        // Signal server it can shut down.
        done.notify_one();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn peer_connection_accept_duplex() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};

        let magic = [2, 0, 0, 1];

        let hs_server = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "server".into(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 0 },
                node_name: "s".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let hs_client = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "client".into(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 0 },
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
            let (mut conn, peer_hs) = PeerConnection::accept(stream, magic, &hs_server_clone, 5, None).await.unwrap();
            assert_eq!(peer_hs.peer_spec.agent_name, "client");
            // Send a message to the client.
            conn.send_message(99, &[0xAA]).await.unwrap();
            // Receive a message from the client.
            let msg = conn.recv_message().await.unwrap();
            assert_eq!(msg.code, 88);
            assert_eq!(msg.body, vec![0xBB]);
        });

        let (mut conn, peer_hs) = PeerConnection::connect(addr, magic, &hs_client, 5, None).await.unwrap();
        assert_eq!(peer_hs.peer_spec.agent_name, "server");
        // Receive message from server.
        let msg = conn.recv_message().await.unwrap();
        assert_eq!(msg.code, 99);
        assert_eq!(msg.body, vec![0xAA]);
        // Send message to server.
        conn.send_message(88, &[0xBB]).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn accept_rejects_old_version() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
        use tokio::io::AsyncWriteExt;

        let magic = [2, 0, 0, 1];

        let hs_server = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "server".into(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 0 },
                node_name: "s".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let old_hs = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "old-client".into(),
                protocol_version: ProtocolVersion { major: 3, minor: 0, patch: 0 },
                node_name: "old".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let hs_server_clone = hs_server.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let result = PeerConnection::accept(stream, magic, &hs_server_clone, 5, None).await;
            match result {
                Err(err) => assert!(err.to_string().contains("below minimum"), "got: {err}"),
                Ok(_) => panic!("expected VersionTooOld error"),
            }
        });

        // Client sends old version handshake.
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&old_hs.serialize()).await.unwrap();
        // Read server's handshake (to avoid broken pipe).
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_rejects_old_version() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
        use tokio::io::AsyncWriteExt;

        let magic = [2, 0, 0, 1];

        let hs_client = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "client".into(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 0 },
                node_name: "c".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let old_server_hs = Handshake {
            time: 200,
            peer_spec: PeerSpec {
                agent_name: "old-server".into(),
                protocol_version: ProtocolVersion { major: 3, minor: 0, patch: 0 },
                node_name: "old".into(),
                declared_address: None,
                features: vec![],
            },
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Send old version handshake
            stream.write_all(&old_server_hs.serialize()).await.unwrap();
            // Read client's handshake to avoid broken pipe
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
        });

        let result = PeerConnection::connect(addr, magic, &hs_client, 5, None).await;
        match result {
            Err(err) => assert!(err.to_string().contains("below minimum"), "got: {err}"),
            Ok(_) => panic!("expected VersionTooOld error"),
        }

        server.await.unwrap();
    }

    #[test]
    fn check_peer_version_boundary() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};

        let make_hs = |major: u8, minor: u8, patch: u8| Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "test".into(),
                protocol_version: ProtocolVersion { major, minor, patch },
                node_name: "t".into(),
                declared_address: None,
                features: vec![],
            },
        };

        // 4.0.99 is below EIP37_FORK (4.0.100)
        assert!(super::check_peer_version(&make_hs(4, 0, 99)).is_err());
        // 4.0.100 is exactly EIP37_FORK — should pass
        assert!(super::check_peer_version(&make_hs(4, 0, 100)).is_ok());
        // 5.0.0 is above — should pass
        assert!(super::check_peer_version(&make_hs(5, 0, 0)).is_ok());
        // 3.0.0 is way below
        assert!(super::check_peer_version(&make_hs(3, 0, 0)).is_err());
    }

    #[test]
    fn self_connection_detected() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
        use ergo_wire::peer_feature::{PeerFeature, SessionFeature};

        let our_session_id: u64 = 0xDEADBEEF_CAFEBABE;
        let peer_hs = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "test".into(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 0 },
                node_name: "t".into(),
                declared_address: None,
                features: vec![PeerFeature::Session(SessionFeature {
                    network_magic: [1, 0, 2, 4],
                    session_id: our_session_id as i64,
                })],
            },
        };

        let result = super::check_self_connection(&peer_hs, our_session_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("self-connection"));
    }

    #[test]
    fn different_session_ids_pass() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
        use ergo_wire::peer_feature::{PeerFeature, SessionFeature};

        let peer_hs = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "test".into(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 0 },
                node_name: "t".into(),
                declared_address: None,
                features: vec![PeerFeature::Session(SessionFeature {
                    network_magic: [1, 0, 2, 4],
                    session_id: 12345,
                })],
            },
        };

        assert!(super::check_self_connection(&peer_hs, 99999).is_ok());
    }

    #[test]
    fn no_session_feature_passes() {
        use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};

        let peer_hs = Handshake {
            time: 100,
            peer_spec: PeerSpec {
                agent_name: "test".into(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 0 },
                node_name: "t".into(),
                declared_address: None,
                features: vec![],
            },
        };

        assert!(super::check_self_connection(&peer_hs, 12345).is_ok());
    }
}
