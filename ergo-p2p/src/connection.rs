//! Async TCP connection: framed message reading and writing.
//!
//! Wraps a TcpStream with message framing from `framing.rs`.
//! Provides `read_message()` and `write_message()` that handle
//! frame encoding/decoding, buffering, and checksum verification.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::framing::{self, FrameError, FrameHeader, MessageFrame, HEADER_LENGTH};

/// Maximum payload size we'll accept from a peer (8MB — Modifier with ADProof reserve).
pub const MAX_PAYLOAD_SIZE: usize = 8_194_304;

/// Read buffer size for TCP — also the ceiling on how far a socket read
/// may run past the framing header a reader asked for. See
/// [`Connection::read_frame_header`].
pub const READ_BUF_SIZE: usize = 65_536;

/// A framed P2P connection over TCP.
pub struct Connection {
    stream: TcpStream,
    magic: [u8; 4],
    read_buf: Vec<u8>,
}

/// Failures produced by [`Connection::read_message`] /
/// [`Connection::write_message`].
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// Underlying TCP I/O error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Frame decoding rejected the bytes.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    /// Peer closed the TCP stream cleanly (read returned 0 bytes).
    #[error("connection closed by peer")]
    Closed,
    /// Frame's declared payload length exceeded `MAX_PAYLOAD_SIZE`.
    #[error("payload too large: {0} bytes (max {MAX_PAYLOAD_SIZE})")]
    PayloadTooLarge(usize),
}

impl Connection {
    /// Wrap a TcpStream for P2P communication.
    pub fn new(stream: TcpStream, magic: [u8; 4]) -> Self {
        Self {
            stream,
            magic,
            read_buf: Vec::with_capacity(READ_BUF_SIZE),
        }
    }

    /// Wrap a TcpStream with pre-existing buffered data.
    /// Used after handshake when the initial read may contain both the
    /// handshake response AND subsequent framed messages.
    pub fn new_with_buffer(stream: TcpStream, magic: [u8; 4], initial_data: Vec<u8>) -> Self {
        Self {
            stream,
            magic,
            read_buf: initial_data,
        }
    }

    /// Read one complete message frame from the connection.
    ///
    /// Blocks (async) until a full frame is available. Returns the frame's
    /// code and payload. Handles partial reads and buffering internally.
    ///
    /// Equivalent to [`read_frame_header`](Self::read_frame_header)
    /// followed by [`read_frame_body`](Self::read_frame_body); a caller
    /// that must act on the declared size *before* the body is accepted
    /// (byte-budget acquisition, issue #280) calls the two phases itself.
    pub async fn read_message(&mut self) -> Result<MessageFrame, ConnectionError> {
        self.read_frame_header().await?;
        self.read_frame_body().await
    }

    /// Header phase: read until the next frame's [`HEADER_LENGTH`]-byte
    /// framing header is buffered, then parse and size-check it.
    ///
    /// The header is *peeked*, not consumed: the bytes stay in the read
    /// buffer for [`read_frame_body`](Self::read_frame_body), and calling
    /// this again re-parses the same header. That makes the two phases
    /// safe to abandon between calls (a `select!` branch that loses the
    /// race, a permit acquisition that is cancelled) without losing
    /// framing position.
    ///
    /// Returning here is the point at which a caller can admit or refuse
    /// `payload_len` bytes before the body is allocated and read. A
    /// socket read that lands in this phase is capped at
    /// [`READ_BUF_SIZE`], so at most 64 KiB of a frame's body can be
    /// buffered ahead of that decision — a bounded overshoot that keeps
    /// small pipelined frames at one syscall each, against the megabytes
    /// the body phase would otherwise accept unbudgeted.
    pub async fn read_frame_header(&mut self) -> Result<FrameHeader, ConnectionError> {
        loop {
            match framing::parse_frame_header(&self.magic, &self.read_buf) {
                Ok(Some(header)) => {
                    // Reject an oversized declaration before the body is
                    // budgeted, allocated, or read.
                    if header.payload_len > MAX_PAYLOAD_SIZE {
                        self.read_buf.clear();
                        return Err(ConnectionError::PayloadTooLarge(header.payload_len));
                    }
                    return Ok(header);
                }
                // Fewer than 9 bytes buffered: read whatever the socket
                // has. An unbounded chunk here is fine — the header phase
                // never reads past what the kernel already holds.
                Ok(None) => self.fill(READ_BUF_SIZE).await?,
                Err(e) => {
                    // Protocol error — clear buffer and return error
                    self.read_buf.clear();
                    return Err(ConnectionError::Frame(e));
                }
            }
        }
    }

    /// Body phase: read until the frame whose header is already buffered
    /// is complete, then decode and consume it.
    ///
    /// Reads are limited to the bytes this frame still needs and the
    /// buffer is reserved exactly once for it, so accepting a maximal
    /// frame costs its own size and no more; the buffer is released back
    /// to [`READ_BUF_SIZE`] afterwards rather than retaining an 8 MB
    /// allocation for the life of the connection.
    pub async fn read_frame_body(&mut self) -> Result<MessageFrame, ConnectionError> {
        loop {
            match framing::deserialize_frame(&self.magic, &self.read_buf) {
                Ok(Some((frame, consumed))) => {
                    self.read_buf.drain(..consumed);
                    if self.read_buf.len() <= READ_BUF_SIZE {
                        self.read_buf.shrink_to(READ_BUF_SIZE);
                    }
                    return Ok(frame);
                }
                Ok(None) => {
                    // How much this frame still needs. Before the header
                    // is buffered we only know we want the header itself.
                    let want = match framing::parse_frame_header(&self.magic, &self.read_buf) {
                        Ok(Some(header)) => {
                            if header.payload_len > MAX_PAYLOAD_SIZE {
                                self.read_buf.clear();
                                return Err(ConnectionError::PayloadTooLarge(header.payload_len));
                            }
                            framing::wire_len(header.payload_len)
                        }
                        Ok(None) => HEADER_LENGTH,
                        Err(e) => {
                            self.read_buf.clear();
                            return Err(ConnectionError::Frame(e));
                        }
                    };
                    // The frame is known incomplete here, so `want` exceeds
                    // what is buffered; the clamp only keeps a zero-length
                    // read — which would read as EOF — out of `fill`.
                    let missing = want.saturating_sub(self.read_buf.len()).max(1);
                    // Reserve for this frame once, exactly: the first pass
                    // sizes the buffer to the whole frame and the rest find
                    // the capacity already there.
                    self.read_buf.reserve_exact(missing);
                    self.fill(missing).await?;
                }
                Err(e) => {
                    // Protocol error — clear buffer and return error
                    self.read_buf.clear();
                    return Err(ConnectionError::Frame(e));
                }
            }
        }
    }

    /// Append one socket read of at most `limit` bytes to the read
    /// buffer. A read of 0 bytes is a clean peer close.
    async fn fill(&mut self, limit: usize) -> Result<(), ConnectionError> {
        let mut tmp = [0u8; READ_BUF_SIZE];
        let cap = limit.min(READ_BUF_SIZE);
        let n = self.stream.read(&mut tmp[..cap]).await?;
        if n == 0 {
            return Err(ConnectionError::Closed);
        }
        self.read_buf.extend_from_slice(&tmp[..n]);
        Ok(())
    }

    /// Bytes accepted from the socket but not yet consumed as a frame —
    /// this connection's share of read-side accumulation.
    pub fn buffered_bytes(&self) -> usize {
        self.read_buf.len()
    }

    /// Write a message frame to the connection.
    pub async fn write_message(&mut self, frame: &MessageFrame) -> Result<(), ConnectionError> {
        let bytes = framing::serialize_frame(&self.magic, frame);
        self.stream.write_all(&bytes).await?;
        Ok(())
    }

    /// Write a message with a specific code and payload.
    pub async fn send(&mut self, code: u8, payload: Vec<u8>) -> Result<(), ConnectionError> {
        self.write_message(&MessageFrame { code, payload }).await
    }

    /// Get a reference to the underlying TcpStream (for address info, etc.).
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Consume the connection and return the TcpStream.
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{serialize_frame, MAINNET_MAGIC};
    use tokio::net::TcpListener;

    // ----- helpers -----

    async fn connected_pair() -> (Connection, Connection) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        (
            Connection::new(client_stream, MAINNET_MAGIC),
            Connection::new(server_stream, MAINNET_MAGIC),
        )
    }

    /// The 9-byte framing header a frame with `payload_len` payload bytes
    /// would carry — built by hand so a test can put a header on the wire
    /// without the body it declares.
    fn header_bytes(code: u8, payload_len: i32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LENGTH);
        bytes.extend_from_slice(&MAINNET_MAGIC);
        bytes.push(code);
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes
    }

    // ----- happy path -----

    #[tokio::test]
    async fn roundtrip_empty_payload() {
        let (mut client, mut server) = connected_pair().await;

        client.send(1, Vec::new()).await.unwrap(); // GetPeers
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg.code, 1);
        assert!(msg.payload.is_empty());
    }

    #[tokio::test]
    async fn roundtrip_with_payload() {
        let (mut client, mut server) = connected_pair().await;

        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        client.send(55, payload.clone()).await.unwrap();
        let msg = server.read_message().await.unwrap();
        assert_eq!(msg.code, 55);
        assert_eq!(msg.payload, payload);
    }

    #[tokio::test]
    async fn multiple_messages() {
        let (mut client, mut server) = connected_pair().await;

        for i in 0..5u8 {
            client
                .send(i + 1, vec![i; (i as usize + 1) * 10])
                .await
                .unwrap();
        }

        for i in 0..5u8 {
            let msg = server.read_message().await.unwrap();
            assert_eq!(msg.code, i + 1);
            assert_eq!(msg.payload.len(), (i as usize + 1) * 10);
        }
    }

    // ----- round-trips -----

    /// The header phase completes on the header bytes ALONE — before a
    /// single body byte exists on the wire. That is the ordering issue
    /// #280 depends on: a caller can admit or refuse `payload_len` bytes
    /// there, and nothing of the body has been allocated or read yet.
    #[tokio::test]
    async fn read_frame_header_returns_before_body_bytes_arrive() {
        let (mut client, mut server) = connected_pair().await;

        let payload_len = 1_000_000;
        client
            .stream
            .write_all(&header_bytes(77, payload_len as i32))
            .await
            .unwrap();

        let header = server.read_frame_header().await.unwrap();
        assert_eq!(header.code, 77);
        assert_eq!(header.payload_len, payload_len);
        // Nothing beyond the header was accepted.
        assert_eq!(server.read_buf.len(), HEADER_LENGTH);
    }

    /// The header is peeked, not consumed: re-reading it is idempotent
    /// and the following body phase still sees a complete frame. This is
    /// what makes abandoning the two-phase read between the phases (a
    /// lost `select!` race, a cancelled budget acquisition) safe.
    #[tokio::test]
    async fn read_frame_header_peeked_twice_still_reads_body() {
        let (mut client, mut server) = connected_pair().await;

        let payload = vec![0x5A; 4_096];
        client.send(33, payload.clone()).await.unwrap();

        let first = server.read_frame_header().await.unwrap();
        let second = server.read_frame_header().await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.payload_len, payload.len());

        let frame = server.read_frame_body().await.unwrap();
        assert_eq!(frame.code, 33);
        assert_eq!(frame.payload, payload);
    }

    /// The body phase reserves for exactly the frame it is completing and
    /// hands the space back afterwards, so a maximal frame does not leave
    /// an 8 MB buffer attached to the connection for its lifetime.
    #[tokio::test]
    async fn read_frame_body_large_payload_right_sizes_the_buffer() {
        let (mut client, mut server) = connected_pair().await;

        let payload = vec![0xC3; 1 << 20];
        let write = tokio::spawn(async move {
            client.send(44, payload).await.unwrap();
            client
        });

        let header = server.read_frame_header().await.unwrap();
        assert_eq!(header.payload_len, 1 << 20);
        let frame = server.read_frame_body().await.unwrap();
        assert_eq!(frame.payload.len(), 1 << 20);
        assert!(frame.payload.iter().all(|b| *b == 0xC3));
        assert!(
            server.read_buf.capacity() <= READ_BUF_SIZE,
            "read buffer kept {} bytes of capacity after a 1 MiB frame",
            server.read_buf.capacity()
        );

        let _client = write.await.unwrap();
    }

    /// A sender that trickles the frame out a few bytes at a time — the
    /// header split across reads included — still yields one whole frame.
    #[tokio::test]
    async fn read_message_byte_at_a_time_sender_roundtrips() {
        let (mut client, mut server) = connected_pair().await;

        let payload: Vec<u8> = (0..64u8).collect();
        let bytes = serialize_frame(&MAINNET_MAGIC, &MessageFrame { code: 21, payload });
        let drip = tokio::spawn(async move {
            for byte in bytes {
                client.stream.write_all(&[byte]).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            client
        });

        let frame = server.read_message().await.unwrap();
        assert_eq!(frame.code, 21);
        assert_eq!(frame.payload, (0..64u8).collect::<Vec<u8>>());

        let _client = drip.await.unwrap();
    }

    // ----- error paths -----

    #[tokio::test]
    async fn detects_closed_connection() {
        let (client, mut server) = connected_pair().await;
        drop(client); // close the client side
        let result = server.read_message().await;
        assert!(matches!(result, Err(ConnectionError::Closed)));
    }

    /// An oversized DECLARATION is refused in the header phase — before
    /// any budget is charged, any buffer is reserved, and any body byte
    /// is read. Only the 9 header bytes ever exist here.
    #[tokio::test]
    async fn read_frame_header_declared_length_over_max_errors() {
        let (mut client, mut server) = connected_pair().await;

        let oversized = MAX_PAYLOAD_SIZE + 1;
        client
            .stream
            .write_all(&header_bytes(55, oversized as i32))
            .await
            .unwrap();

        let result = server.read_frame_header().await;
        assert!(
            matches!(result, Err(ConnectionError::PayloadTooLarge(n)) if n == oversized),
            "expected PayloadTooLarge({oversized}), got {result:?}"
        );
    }

    /// A peer that sends a header and then vanishes mid-body reports a
    /// clean close from the body phase — the caller's budget permit is
    /// dropped with the failed read rather than stranded.
    #[tokio::test]
    async fn read_frame_body_peer_closes_mid_body_errors() {
        let (mut client, mut server) = connected_pair().await;

        let mut prefix = header_bytes(55, 4_096);
        prefix.extend_from_slice(&[0u8; 16]); // checksum + a few body bytes
        client.stream.write_all(&prefix).await.unwrap();
        drop(client);

        let header = server.read_frame_header().await.unwrap();
        assert_eq!(header.payload_len, 4_096);
        let result = server.read_frame_body().await;
        assert!(
            matches!(result, Err(ConnectionError::Closed)),
            "expected Closed, got {result:?}"
        );
    }

    /// Wrong magic is rejected in the header phase, with the same error
    /// the single-call path reported before the split.
    #[tokio::test]
    async fn read_frame_header_wrong_magic_errors() {
        let (mut client, mut server) = connected_pair().await;

        let frame = MessageFrame {
            code: 1,
            payload: vec![1, 2, 3],
        };
        let bytes = serialize_frame(&crate::framing::TESTNET_MAGIC, &frame);
        client.stream.write_all(&bytes).await.unwrap();

        let result = server.read_frame_header().await;
        assert!(
            matches!(
                result,
                Err(ConnectionError::Frame(FrameError::WrongMagic { .. }))
            ),
            "expected WrongMagic, got {result:?}"
        );
    }

    /// A corrupt checksum is caught in the body phase — the header phase
    /// cannot see it, and the frame is still rejected.
    #[tokio::test]
    async fn read_frame_body_bad_checksum_errors() {
        let (mut client, mut server) = connected_pair().await;

        let frame = MessageFrame {
            code: 55,
            payload: vec![9, 9, 9, 9],
        };
        let mut bytes = serialize_frame(&MAINNET_MAGIC, &frame);
        bytes[9] ^= 0xFF;
        client.stream.write_all(&bytes).await.unwrap();

        server.read_frame_header().await.unwrap();
        let result = server.read_frame_body().await;
        assert!(
            matches!(
                result,
                Err(ConnectionError::Frame(FrameError::ChecksumMismatch))
            ),
            "expected ChecksumMismatch, got {result:?}"
        );
    }
}
