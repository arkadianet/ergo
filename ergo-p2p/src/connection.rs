//! Async TCP connection: framed message reading and writing.
//!
//! Wraps a TcpStream with message framing from `framing.rs`.
//! Provides `read_message()` and `write_message()` that handle
//! frame encoding/decoding, buffering, and checksum verification.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::framing::{self, FrameError, FrameHeader, MessageFrame, HEADER_LENGTH};

/// Maximum payload size we'll accept from a peer (8MB — Modifier with ADProof reserve).
pub const MAX_PAYLOAD_SIZE: usize = 8_194_304;

/// Read buffer size for TCP — also the ceiling on how far a socket read
/// may run past the framing header a reader asked for. See
/// [`Connection::read_frame_header`].
pub const READ_BUF_SIZE: usize = 65_536;

/// How long a frame body may make NO progress before the peer is judged
/// stalled.
///
/// This is a no-progress deadline, not a total one: it restarts on every
/// byte received, so an honest peer trickling an 8 MB block over minutes
/// stays connected while a peer that declares a body and then goes
/// silent is dropped. Without it, a declared-but-unsent body would hold
/// its reader — and whatever budget it has been admitted — until the
/// 600 s inactivity sweep.
pub const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// A framed P2P connection over TCP.
pub struct Connection {
    stream: TcpStream,
    magic: [u8; 4],
    read_buf: Vec<u8>,
    /// Landing area for one socket read, reused for the life of the
    /// connection. Owned rather than a local so it is neither zeroed per
    /// read nor held inside the read future across an await; a cancelled
    /// read leaves it untouched because nothing is committed to
    /// `read_buf` until the read returns.
    scratch: Box<[u8]>,
    body_idle_timeout: Duration,
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
    /// Peer declared a frame body and then stopped sending: no byte of
    /// it arrived within [`BODY_IDLE_TIMEOUT`].
    #[error("frame body stalled: {got} of {want} bytes, no progress for {}s", BODY_IDLE_TIMEOUT.as_secs())]
    BodyStalled {
        /// Wire bytes of this frame received so far.
        got: usize,
        /// Wire bytes the frame's header declared.
        want: usize,
    },
    /// The read-side byte budget was closed — the node is shutting down.
    #[error("event byte budget closed")]
    BudgetClosed,
}

impl Connection {
    /// Wrap a TcpStream for P2P communication.
    pub fn new(stream: TcpStream, magic: [u8; 4]) -> Self {
        Self::with_buf(stream, magic, Vec::with_capacity(READ_BUF_SIZE))
    }

    /// Wrap a TcpStream with pre-existing buffered data.
    /// Used after handshake when the initial read may contain both the
    /// handshake response AND subsequent framed messages.
    pub fn new_with_buffer(stream: TcpStream, magic: [u8; 4], initial_data: Vec<u8>) -> Self {
        Self::with_buf(stream, magic, initial_data)
    }

    fn with_buf(stream: TcpStream, magic: [u8; 4], read_buf: Vec<u8>) -> Self {
        Self {
            stream,
            magic,
            read_buf,
            scratch: vec![0u8; READ_BUF_SIZE].into_boxed_slice(),
            body_idle_timeout: BODY_IDLE_TIMEOUT,
        }
    }

    /// Override the no-progress deadline for frame bodies. Production
    /// runs the [`BODY_IDLE_TIMEOUT`] default; tests that need to observe
    /// the deadline firing shorten it.
    pub fn with_body_idle_timeout(mut self, timeout: Duration) -> Self {
        self.body_idle_timeout = timeout;
        self
    }

    /// Read one complete message frame from the connection.
    ///
    /// Blocks (async) until a full frame is available. Returns the frame's
    /// code and payload. Handles partial reads and buffering internally.
    ///
    /// Equivalent to [`read_frame_header`](Self::read_frame_header)
    /// followed by [`read_frame_body`](Self::read_frame_body). A caller
    /// that meters read-side bytes (issue #280) uses
    /// [`read_frame_body_metered`](Self::read_frame_body_metered) for the
    /// second phase.
    pub async fn read_message(&mut self) -> Result<MessageFrame, ConnectionError> {
        self.read_frame_header().await?;
        self.read_frame_body().await
    }

    /// Header phase: read until the next frame's [`HEADER_LENGTH`]-byte
    /// framing header is buffered, then parse and size-check it.
    ///
    /// The header is *peeked*, not consumed: the bytes stay in the read
    /// buffer for the body phase, and calling this again re-parses the
    /// same header. That makes the two phases safe to abandon between
    /// calls (a `select!` branch that loses the race, an admission that
    /// is cancelled) without losing framing position.
    ///
    /// Returning here is the point at which a caller learns `payload_len`
    /// before committing to receive it. A socket read that lands in this
    /// phase runs only while fewer than [`HEADER_LENGTH`] bytes are
    /// buffered and is capped at [`READ_BUF_SIZE`], so at most
    /// `READ_BUF_SIZE + HEADER_LENGTH - 1` bytes can be buffered ahead of
    /// that point — a bounded overshoot that keeps small pipelined frames
    /// at one syscall each, against the megabytes the body phase would
    /// otherwise accept in one go.
    pub async fn read_frame_header(&mut self) -> Result<FrameHeader, ConnectionError> {
        loop {
            match framing::parse_frame_header(&self.magic, &self.read_buf) {
                Ok(Some(header)) => {
                    // Reject an oversized declaration before the body is
                    // admitted, allocated, or read.
                    if header.payload_len > MAX_PAYLOAD_SIZE {
                        self.read_buf.clear();
                        return Err(ConnectionError::PayloadTooLarge(header.payload_len));
                    }
                    return Ok(header);
                }
                Ok(None) => self.fill(READ_BUF_SIZE).await?,
                Err(e) => {
                    // Protocol error — clear buffer and return error
                    self.read_buf.clear();
                    return Err(ConnectionError::Frame(e));
                }
            }
        }
    }

    /// Body phase with no admission control — the plain read path used by
    /// `read_message` and by callers that do not meter read-side bytes.
    pub async fn read_frame_body(&mut self) -> Result<MessageFrame, ConnectionError> {
        let (frame, _) = self.read_body(None).await?;
        Ok(frame)
    }

    /// Body phase that charges a shared byte budget for the bytes it
    /// accepts, returning the frame together with the permits taken
    /// (issue #280).
    ///
    /// Permits for each socket read are acquired BEFORE that read
    /// happens, so the budget is only ever held by bytes that exist or
    /// are about to. When it is exhausted the reader parks with the body
    /// still in the sender's socket: reads stop, kernel buffers fill, and
    /// the TCP window closes on the sender.
    ///
    /// Charging per read rather than for the length the header declared
    /// is what keeps this safe under attack. A peer that declares 8 MB
    /// and then goes silent holds ONE read chunk of budget, not 8 MB, so
    /// 13 wire bytes cannot reserve a thirty-second of the whole node's
    /// budget; [`BODY_IDLE_TIMEOUT`] then takes even that chunk back.
    /// Waiting on the budget is backpressure, not peer inactivity, and
    /// does not count against that deadline.
    ///
    /// The returned permit covers the wire bytes read HERE — delivered
    /// bytes plus at most one outstanding read chunk — which is not the
    /// payload's length: bytes the header phase had already buffered were
    /// never charged, and the final chunk is charged in full. A caller
    /// that needs the permit to match the payload settles the difference
    /// itself.
    ///
    /// The buffer grows the same way the budget is charged: never past
    /// what the frame needs, and never more than about twice what has
    /// been admitted, so a bare header cannot make the node reserve 8 MB.
    /// On completion the buffer is released back to [`READ_BUF_SIZE`]
    /// instead of keeping a maximal frame's allocation for the life of
    /// the connection.
    pub async fn read_frame_body_metered(
        &mut self,
        budget: &Arc<Semaphore>,
    ) -> Result<(MessageFrame, Option<OwnedSemaphorePermit>), ConnectionError> {
        self.read_body(Some(budget)).await
    }

    async fn read_body(
        &mut self,
        budget: Option<&Arc<Semaphore>>,
    ) -> Result<(MessageFrame, Option<OwnedSemaphorePermit>), ConnectionError> {
        let mut held: Option<OwnedSemaphorePermit> = None;
        // Bytes the header phase had already buffered. They were never
        // charged (see the overshoot bound on `read_frame_header`), so
        // they are excluded from what this frame owes.
        let baseline = self.read_buf.len();
        loop {
            match framing::deserialize_frame(&self.magic, &self.read_buf) {
                Ok(Some((frame, consumed))) => {
                    self.read_buf.drain(..consumed);
                    if self.read_buf.len() <= READ_BUF_SIZE {
                        self.read_buf.shrink_to(READ_BUF_SIZE);
                    }
                    return Ok((frame, held));
                }
                Ok(None) => {
                    // Wire bytes this frame needs in total. Before the
                    // header is buffered we only know we want the header.
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
                    let got = self.read_buf.len();
                    // The frame is known incomplete here, so `want`
                    // exceeds what is buffered; the clamp only keeps a
                    // zero-length read — which reads as EOF — out of
                    // `fill`.
                    let chunk = want.saturating_sub(got).clamp(1, READ_BUF_SIZE);

                    // Pay for the bytes before accepting them. What this
                    // frame owes is everything it has taken in so far
                    // plus the read about to happen; topping that up —
                    // rather than charging a fresh chunk per iteration —
                    // is what keeps a peer dribbling bytes from
                    // accumulating permits far beyond what it has sent.
                    // The hold is therefore always "delivered bytes plus
                    // at most one READ_BUF_SIZE chunk".
                    if let Some(budget) = budget {
                        let owed = got - baseline + chunk;
                        let paid = held.as_ref().map_or(0, |p| p.num_permits());
                        if owed > paid {
                            // The shortfall never exceeds one chunk, so
                            // the cast cannot truncate and the request is
                            // always small enough to be granted.
                            let permit = Arc::clone(budget)
                                .acquire_many_owned((owed - paid) as u32)
                                .await
                                .map_err(|_| ConnectionError::BudgetClosed)?;
                            match &mut held {
                                Some(existing) => existing.merge(permit),
                                None => held = Some(permit),
                            }
                        }
                    }

                    // Grow toward the frame, never past it and never more
                    // than about twice what has been admitted: 13 wire
                    // bytes must not be able to reserve 8 MB.
                    let target = want.min(got.saturating_add(chunk).saturating_mul(2));
                    if target > self.read_buf.capacity() {
                        self.read_buf.reserve_exact(target - got);
                    }

                    // Per-read, so the deadline restarts on every byte a
                    // slow-but-honest peer delivers.
                    tokio::time::timeout(self.body_idle_timeout, self.fill(chunk))
                        .await
                        .map_err(|_| ConnectionError::BodyStalled { got, want })??;
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
        let cap = limit.clamp(1, READ_BUF_SIZE);
        let n = self.stream.read(&mut self.scratch[..cap]).await?;
        if n == 0 {
            return Err(ConnectionError::Closed);
        }
        self.read_buf.extend_from_slice(&self.scratch[..n]);
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
    use std::sync::atomic::{AtomicBool, Ordering};
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

    /// Like [`connected_pair`] with `idle` as the server side's body
    /// no-progress deadline, so a test can watch it fire in milliseconds
    /// instead of the production 30 s.
    async fn connected_pair_with_idle(idle: Duration) -> (Connection, Connection) {
        let (client, server) = connected_pair().await;
        (client, server.with_body_idle_timeout(idle))
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
        // The point is that the megabyte was RELEASED, not the exact
        // figure `shrink_to` lands on: assert a bound that holds however
        // the allocator honours the request.
        assert!(
            server.read_buf.capacity() <= 2 * READ_BUF_SIZE,
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

    /// A body that arrives in small pieces over a span far longer than
    /// the deadline still completes: the deadline measures NO PROGRESS,
    /// not total time. An 8 MB block from a 100 KB/s peer takes ~80 s and
    /// must not be mistaken for a stall.
    #[tokio::test]
    async fn read_frame_body_slow_trickle_beats_the_idle_deadline() {
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_millis(150)).await;

        let payload = vec![0x3C; 512];
        let bytes = serialize_frame(&MAINNET_MAGIC, &MessageFrame { code: 12, payload });
        let total = bytes.len();
        let drip = tokio::spawn(async move {
            // Eight pieces, 60 ms apart: ~480 ms overall, over three
            // deadlines, but never 150 ms without a byte.
            for piece in bytes.chunks(total.div_ceil(8)) {
                client.stream.write_all(piece).await.unwrap();
                tokio::time::sleep(Duration::from_millis(60)).await;
            }
            client
        });

        let frame = server.read_message().await.expect("trickled frame");
        assert_eq!(frame.code, 12);
        assert_eq!(frame.payload, vec![0x3C; 512]);
        let _client = drip.await.unwrap();
    }

    /// #280: a peer that declares a body and then goes silent — without
    /// closing, so no EOF ever arrives — is cut loose by the no-progress
    /// deadline instead of holding a reader (and its admitted budget)
    /// until the 600 s inactivity sweep.
    #[tokio::test]
    async fn read_frame_body_silent_body_trips_the_idle_deadline() {
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_millis(150)).await;

        client
            .stream
            .write_all(&header_bytes(55, 4_096))
            .await
            .unwrap();
        let header = server.read_frame_header().await.unwrap();
        assert_eq!(header.payload_len, 4_096);

        let result = server.read_frame_body().await;
        match result {
            Err(ConnectionError::BodyStalled { got, want }) => {
                assert_eq!(got, HEADER_LENGTH);
                assert_eq!(want, framing::wire_len(4_096));
            }
            other => panic!("expected BodyStalled, got {other:?}"),
        }
        // The peer never closed — the deadline is what ended this.
        drop(client);
    }

    /// #280 P1, at the transport layer: the budget is charged for bytes
    /// as they are read, so a header declaring a maximal body buys ONE
    /// read chunk. Without this, 13 wire bytes would reserve 8 MB of a
    /// shared budget and a handful of peers could park every reader.
    #[tokio::test]
    async fn read_frame_body_metered_bare_header_holds_one_chunk() {
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_secs(30)).await;
        client
            .stream
            .write_all(&header_bytes(55, MAX_PAYLOAD_SIZE as i32))
            .await
            .unwrap();
        server.read_frame_header().await.unwrap();

        let budget = Arc::new(Semaphore::new(MAX_PAYLOAD_SIZE));
        let observed = Arc::new(AtomicBool::new(false));
        let (probe_budget, probe_seen) = (budget.clone(), observed.clone());
        let probe = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            probe_seen.store(true, Ordering::Relaxed);
            probe_budget.available_permits()
        });

        // The read cannot finish; run it only until the probe has looked.
        let _ = tokio::time::timeout(
            Duration::from_millis(400),
            server.read_frame_body_metered(&budget),
        )
        .await;

        let available = probe.await.unwrap();
        assert!(observed.load(Ordering::Relaxed));
        assert_eq!(
            available,
            MAX_PAYLOAD_SIZE - READ_BUF_SIZE,
            "a bare header must hold one read chunk, not its declaration"
        );
        // Cancelling the read released it.
        assert_eq!(budget.available_permits(), MAX_PAYLOAD_SIZE);
        drop(client);
    }

    /// The metered path returns the same frames as the plain one, with a
    /// permit covering what it read.
    #[tokio::test]
    async fn read_frame_body_metered_roundtrips_and_charges() {
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_secs(30)).await;
        let payload = vec![0x11; 200_000];
        let writer = tokio::spawn(async move {
            client.send(9, vec![0x11; 200_000]).await.unwrap();
            client
        });

        let budget = Arc::new(Semaphore::new(MAX_PAYLOAD_SIZE));
        server.read_frame_header().await.unwrap();
        let (frame, permit) = server.read_frame_body_metered(&budget).await.unwrap();
        assert_eq!(frame.code, 9);
        assert_eq!(frame.payload, payload);
        let permit = permit.expect("a 200 KB body crosses several read chunks");
        // Everything except the header phase's bounded overshoot was
        // charged; the caller settles that remainder against the payload.
        assert!(
            permit.num_permits() + READ_BUF_SIZE + HEADER_LENGTH >= payload.len(),
            "permits {} leave more than the header-phase overshoot of {} payload bytes uncharged",
            permit.num_permits(),
            payload.len()
        );
        drop(permit);
        assert_eq!(budget.available_permits(), MAX_PAYLOAD_SIZE);
        let _client = writer.await.unwrap();
    }
}
