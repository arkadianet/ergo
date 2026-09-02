//! Async TCP connection: framed message reading and writing.
//!
//! Wraps a TcpStream with message framing from `framing.rs`.
//! Provides `read_message()` and `write_message()` that handle
//! frame encoding/decoding, buffering, and checksum verification.

use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

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

/// How long a peer has to produce the FIRST byte of a body after its
/// header is complete.
///
/// Deliberately much shorter than [`BODY_IDLE_TIMEOUT`]. A header costs
/// 9 bytes and, for a frame too large to read in one go, claims a
/// [`ReadBudget`] slot — so the cheapest attack on the slot pool is to
/// send headers and nothing else. Holding a slot for 30 s on the
/// strength of 9 bytes is far too generous; a peer that has just
/// announced a frame is already sending it, so 5 s is ample for an
/// honest one. Once any body byte arrives the per-progress
/// [`BODY_IDLE_TIMEOUT`] takes over and slow senders are safe.
pub const FIRST_BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// Wire bytes ONE reader may hold while it is still waiting for more of
/// its frame: the whole frame plus the read it has in flight.
pub const PER_READER_MAX: usize = framing::wire_len(MAX_PAYLOAD_SIZE) + READ_BUF_SIZE;

/// Read-side admission control: the shared byte budget, plus the slot
/// pool that makes waiting on it deadlock-free.
///
/// # Why a slot pool
///
/// Charging for bytes as they arrive means a reader of a large frame
/// holds permits for what it has taken in and then waits for permits to
/// take in more — hold-and-wait. Left unbounded that deadlocks: enough
/// concurrent readers of maximal frames (33 of them against a 256 MiB
/// budget, an attacker's connections or plain IBD) split the budget
/// between them, every reader parks needing one more chunk, nothing is
/// enqueued, so no payload is ever dropped and no permit ever comes
/// back. All P2P reading stops, permanently.
///
/// The slot pool removes the cycle by bounding the readers that may
/// hold-and-wait to [`Self::slots`] = budget / [`PER_READER_MAX`], so
/// their combined worst case still fits the budget and they can always
/// finish. The rules that make that argument sound:
///
/// 1. **A slot is taken before any byte permit, never after.** A reader
///    waits for a slot holding nothing, then waits for bytes holding a
///    slot — one direction only, so there is no cycle.
/// 2. **Only a frame that cannot fit one read takes a slot.** A frame
///    within a single [`READ_BUF_SIZE`] chunk is charged once, up front,
///    and never tops up, so it never waits while holding. Header and
///    transaction gossip therefore never queues behind block bodies.
/// 3. **Every other holder releases without needing the budget**: an
///    enqueued payload drains through the action loop, and a reader
///    stuck mid-frame is cut loose by [`BODY_IDLE_TIMEOUT`]. So a
///    slot-holder's wait is always finite even when non-slot holders
///    have transiently taken more than the arithmetic reserves for them.
/// 4. **One slot per remote address.** A single address cannot hold two
///    slots at once, so occupying the pool costs an attacker one
///    distinct address per slot — across at least ⌈slots/3⌉ different
///    /16s, given the per-subnet connection limit. An honest peer
///    streams one frame at a time and never meets this cap.
#[derive(Clone)]
pub struct ReadBudget {
    bytes: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    /// Remote addresses currently holding a slot, and the wakeup for
    /// readers queued behind one. A `HashSet` guarded by a plain mutex:
    /// the critical section is an insert or a remove, never an await.
    ip_slots: Arc<Mutex<HashSet<IpAddr>>>,
    ip_notify: Arc<Notify>,
    capacity: usize,
    /// Whether the one-slot-per-address cap applies. Always true in
    /// production; tests that need many concurrent slot-holders turn it
    /// off, since every loopback connection shares one address.
    per_address_cap: bool,
}

impl ReadBudget {
    /// Build a budget of `budget_bytes`, with the slot count that keeps
    /// hold-and-wait readers collectively inside it.
    ///
    /// # Panics
    ///
    /// If `budget_bytes` cannot cover a single maximal frame. A budget
    /// that small has no valid slot count: the final charge for a
    /// maximal frame would exceed the semaphore's total permits and park
    /// forever. Production runs 256 MiB against a 8.26 MB
    /// [`PER_READER_MAX`].
    pub fn new(budget_bytes: usize) -> Self {
        assert!(
            budget_bytes >= PER_READER_MAX,
            "read budget of {budget_bytes} B cannot admit one maximal frame ({PER_READER_MAX} B)"
        );
        Self::with_slots(budget_bytes, budget_bytes / PER_READER_MAX, true)
    }

    /// A budget for exercising the SLOT pool on its own: the
    /// per-address cap is off, because every loopback connection shares
    /// one address and would otherwise serialise the readers and hide
    /// what the pool does. `slots: None` removes the pool as well —
    /// the state this branch's deadlock lived in — so a negative control
    /// can prove the workload still deadlocks without it. Never built by
    /// production code.
    #[cfg(test)]
    pub fn for_slot_contention_test(budget_bytes: usize, slots: Option<usize>) -> Self {
        Self::with_slots(budget_bytes, slots.unwrap_or(Semaphore::MAX_PERMITS), false)
    }

    fn with_slots(budget_bytes: usize, slots: usize, per_address_cap: bool) -> Self {
        Self {
            bytes: Arc::new(Semaphore::new(budget_bytes)),
            slots: Arc::new(Semaphore::new(slots)),
            ip_slots: Arc::new(Mutex::new(HashSet::new())),
            ip_notify: Arc::new(Notify::new()),
            capacity: budget_bytes,
            per_address_cap,
        }
    }

    /// The byte semaphore, for callers that settle their own permits.
    pub fn bytes(&self) -> &Arc<Semaphore> {
        &self.bytes
    }

    /// Total bytes this budget can ever grant.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Hold-and-wait reader slots not currently in use.
    pub fn slots_available(&self) -> usize {
        self.slots.available_permits()
    }

    /// Claim `ip`'s single slot entitlement, waiting — holding nothing —
    /// until any earlier large frame from the same address finishes.
    async fn claim_ip(&self, ip: IpAddr) -> IpClaim {
        loop {
            // Register for the wakeup BEFORE looking, or a release
            // between the check and the wait would be missed.
            let notified = self.ip_notify.notified();
            if self.lock_ips().insert(ip) {
                return IpClaim {
                    ip,
                    ip_slots: Arc::clone(&self.ip_slots),
                    ip_notify: Arc::clone(&self.ip_notify),
                };
            }
            notified.await;
        }
    }

    fn lock_ips(&self) -> std::sync::MutexGuard<'_, HashSet<IpAddr>> {
        // The guarded section cannot panic, so poisoning is unreachable;
        // recovering rather than propagating keeps a poisoned lock from
        // taking the whole P2P stack down if that ever changes.
        self.ip_slots.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One address's claim on the slot pool, released on drop — including
/// when the reader is cancelled mid-frame.
struct IpClaim {
    ip: IpAddr,
    ip_slots: Arc<Mutex<HashSet<IpAddr>>>,
    ip_notify: Arc<Notify>,
}

impl Drop for IpClaim {
    fn drop(&mut self) {
        self.ip_slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.ip);
        self.ip_notify.notify_waiters();
    }
}

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
    first_body_timeout: Duration,
    /// Absolute deadline for the frame being received, kept ACROSS reads.
    ///
    /// A read is a `select!` branch in the peer task, so an outbound
    /// message cancels it mid-frame. Re-arming the deadline on each call
    /// would restart the clock every time that happened, and a node that
    /// talks to a peer regularly would never accumulate enough silence to
    /// notice it had stopped sending — a stalled peer could hold a slot
    /// and its permits indefinitely. Holding the deadline here instead
    /// means a cancelled read RESUMES it. Cleared on progress, and when
    /// the frame completes or fails.
    frame_deadline: Option<tokio::time::Instant>,
    /// Remote address, resolved once at construction: the key for the
    /// per-address slot cap. `None` only if the socket was already gone,
    /// in which case the next read fails anyway.
    peer_ip: Option<IpAddr>,
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
    /// Peer started a frame and then stopped sending: no further byte of
    /// it arrived before the deadline that applied.
    #[error("frame stalled: {got} of {want} bytes, no progress for {after:?}")]
    FrameStalled {
        /// Wire bytes of this frame received so far.
        got: usize,
        /// Wire bytes the frame's header declared.
        want: usize,
        /// The deadline that actually fired — [`FIRST_BODY_TIMEOUT`]
        /// while a body has yet to start, [`BODY_IDLE_TIMEOUT`] once it
        /// has (or whatever a test injected). Reported rather than
        /// assumed, so an operator log names the rule that fired.
        after: Duration,
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
        let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
        Self {
            stream,
            magic,
            read_buf,
            scratch: vec![0u8; READ_BUF_SIZE].into_boxed_slice(),
            body_idle_timeout: BODY_IDLE_TIMEOUT,
            first_body_timeout: FIRST_BODY_TIMEOUT,
            frame_deadline: None,
            peer_ip,
        }
    }

    /// Override the no-progress deadline for frame bodies. Production
    /// runs the [`BODY_IDLE_TIMEOUT`] default; tests that need to observe
    /// the deadline firing shorten it.
    pub fn with_body_idle_timeout(mut self, timeout: Duration) -> Self {
        self.body_idle_timeout = timeout;
        self
    }

    /// Override the deadline for the first byte of a body. Production
    /// runs the [`FIRST_BODY_TIMEOUT`] default; tests that need to watch
    /// a header-only staller lose its slot shorten it.
    pub fn with_first_body_timeout(mut self, timeout: Duration) -> Self {
        self.first_body_timeout = timeout;
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
                Ok(None) => {
                    let got = self.read_buf.len();
                    if got == 0 {
                        // Between frames. A quiet peer is not a stalled
                        // one — Ergo peers legitimately go minutes
                        // without sending — so this wait is untimed and
                        // left to the 600 s inactivity sweep.
                        self.fill(READ_BUF_SIZE).await?;
                    } else {
                        // A frame has started. Silence now is a stall,
                        // on the same per-progress deadline as the body.
                        let total = self.body_idle_timeout;
                        self.fill_before_deadline(READ_BUF_SIZE, total, got, HEADER_LENGTH)
                            .await?;
                    }
                }
                Err(e) => {
                    // Protocol error — clear buffer and return error
                    self.read_buf.clear();
                    self.frame_deadline = None;
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
    /// A frame too large to finish in one read takes a [`ReadBudget`]
    /// slot before its first byte permit — see that type for why the
    /// ordering is what keeps concurrent readers deadlock-free.
    ///
    /// The returned permit covers every wire byte of the frame the
    /// connection holds plus the last read charged in full, so it is
    /// always at least the payload's length and usually a little more. A
    /// caller that needs it to match the payload exactly settles by
    /// RELEASING the difference — never by acquiring more, which would
    /// be a wait while holding permits.
    ///
    /// The buffer grows the same way the budget is charged: never past
    /// what the frame needs, and never more than about twice what has
    /// been admitted, so a bare header cannot make the node reserve 8 MB.
    /// On completion the buffer is released back to [`READ_BUF_SIZE`]
    /// instead of keeping a maximal frame's allocation for the life of
    /// the connection.
    pub async fn read_frame_body_metered(
        &mut self,
        budget: &ReadBudget,
    ) -> Result<(MessageFrame, Option<OwnedSemaphorePermit>), ConnectionError> {
        self.read_body(Some(budget)).await
    }

    async fn read_body(
        &mut self,
        budget: Option<&ReadBudget>,
    ) -> Result<(MessageFrame, Option<OwnedSemaphorePermit>), ConnectionError> {
        // Idempotent: the caller has normally peeked this already. Doing
        // it here means the frame's size is known ONCE, before any
        // admission decision, and the body loop never re-parses.
        let header = self.read_frame_header().await?;
        let want = framing::wire_len(header.payload_len);

        // Rules 1, 2 and 4 of `ReadBudget`: a frame that cannot be
        // finished in a single read will have to top its charge up
        // mid-flight, so it takes admission FIRST — while holding no byte
        // permits. A frame that fits one read charges once below and
        // never waits holding anything, so it needs no admission at all
        // and cannot queue behind block bodies.
        //
        // The waits are strictly ordered — address claim, then slot, then
        // bytes — and nothing ever waits in the other direction, so the
        // three cannot form a cycle.
        let mut _claim = None;
        let _slot = match budget {
            Some(budget) if want.saturating_sub(self.read_buf.len()) > READ_BUF_SIZE => {
                // Admission can block, and on a resumed read the frame's
                // deadline is already ticking; that wait is ours, not the
                // peer's, so it is credited back below.
                let waiting_since = tokio::time::Instant::now();
                if budget.per_address_cap {
                    if let Some(ip) = self.peer_ip {
                        _claim = Some(budget.claim_ip(ip).await);
                    }
                }
                let slot = Arc::clone(&budget.slots)
                    .acquire_owned()
                    .await
                    .map_err(|_| ConnectionError::BudgetClosed)?;
                self.credit_internal_wait(waiting_since.elapsed());
                Some(slot)
            }
            _ => None,
        };

        let mut held: Option<OwnedSemaphorePermit> = None;
        loop {
            match framing::deserialize_frame(&self.magic, &self.read_buf) {
                Ok(Some((frame, consumed))) => {
                    self.read_buf.drain(..consumed);
                    if self.read_buf.len() <= READ_BUF_SIZE {
                        self.read_buf.shrink_to(READ_BUF_SIZE);
                    }
                    // This frame is done; the next one arms its own.
                    self.frame_deadline = None;
                    return Ok((frame, held));
                }
                Ok(None) => {
                    let got = self.read_buf.len();
                    // The frame is known incomplete here, so `want`
                    // exceeds what is buffered; the clamp only keeps a
                    // zero-length read — which reads as EOF — out of
                    // `fill`.
                    let chunk = want.saturating_sub(got).clamp(1, READ_BUF_SIZE);

                    // Pay for every wire byte of this frame we hold, plus
                    // the read about to happen. Charging what is HELD —
                    // rather than a fresh chunk per iteration — stops a
                    // peer making many short reads from accumulating
                    // permits far beyond what it has sent. Including the
                    // bytes the header phase had already buffered is what
                    // lets the caller settle by releasing only, never by
                    // acquiring more while it holds permits.
                    if let Some(budget) = budget {
                        let owed = got + chunk;
                        let paid = held.as_ref().map_or(0, |p| p.num_permits());
                        if owed > paid {
                            // The shortfall never exceeds one chunk plus
                            // the header-phase overshoot, so the cast
                            // cannot truncate.
                            let waiting_since = tokio::time::Instant::now();
                            let permit = Arc::clone(&budget.bytes)
                                .acquire_many_owned((owed - paid) as u32)
                                .await
                                .map_err(|_| ConnectionError::BudgetClosed)?;
                            // Budget backpressure is ours, not the peer's.
                            self.credit_internal_wait(waiting_since.elapsed());
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

                    // Per-progress: the deadline restarts on every byte a
                    // slow-but-honest peer delivers. Until the first body
                    // byte lands the peer is on the short leash, so a bare
                    // header cannot hold a slot for the full no-progress
                    // deadline. Read from the BUFFER rather than a local
                    // flag, so a read cancelled mid-frame resumes on the
                    // right one instead of demoting a peer that has
                    // already delivered body bytes back to the short leash.
                    let total = if got > HEADER_LENGTH {
                        self.body_idle_timeout
                    } else {
                        self.first_body_timeout
                    };
                    self.fill_before_deadline(chunk, total, got, want).await?;
                }
                Err(e) => {
                    // Protocol error — clear buffer and return error
                    self.read_buf.clear();
                    self.frame_deadline = None;
                    return Err(ConnectionError::Frame(e));
                }
            }
        }
    }

    /// Wait for one socket read of at most `limit` bytes, under the
    /// deadline for the frame in progress.
    ///
    /// The deadline is armed once per stall window and RESUMED by later
    /// calls, so cancelling a read cannot buy a silent peer more time.
    /// Progress clears it; the next wait arms a fresh one.
    async fn fill_before_deadline(
        &mut self,
        limit: usize,
        total: Duration,
        got: usize,
        want: usize,
    ) -> Result<(), ConnectionError> {
        let deadline = *self
            .frame_deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + total);
        match tokio::time::timeout_at(deadline, self.fill(limit)).await {
            Err(_) => {
                self.frame_deadline = None;
                Err(ConnectionError::FrameStalled {
                    got,
                    want,
                    after: total,
                })
            }
            Ok(result) => {
                // Progress (or a hard error) ends this stall window.
                self.frame_deadline = None;
                result
            }
        }
    }

    /// Push an armed deadline out by `waited`.
    ///
    /// Time spent waiting on our OWN admission control — the byte budget,
    /// a slot, an address claim — is backpressure, not peer silence, and
    /// must not be charged to the peer. It only needs crediting when a
    /// deadline is already armed, which happens when an earlier read of
    /// this frame was cancelled.
    fn credit_internal_wait(&mut self, waited: Duration) {
        if let Some(deadline) = self.frame_deadline.as_mut() {
            *deadline += waited;
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
    use crate::framing::{serialize_frame, MAGIC_LENGTH, MAINNET_MAGIC};
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
        (
            client,
            server
                .with_body_idle_timeout(idle)
                .with_first_body_timeout(idle),
        )
    }

    /// A loopback pair whose server side distinguishes the two deadlines.
    async fn connected_pair_with_deadlines(
        first_body: Duration,
        idle: Duration,
    ) -> (Connection, Connection) {
        let (client, server) = connected_pair().await;
        (
            client,
            server
                .with_body_idle_timeout(idle)
                .with_first_body_timeout(first_body),
        )
    }

    /// One loopback connection whose server side is metered, with both
    /// deadlines long enough to be irrelevant to the test.
    async fn metered_pair() -> (TcpStream, Connection) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (
            client,
            Connection::new(server, MAINNET_MAGIC)
                .with_body_idle_timeout(Duration::from_secs(30))
                .with_first_body_timeout(Duration::from_secs(30)),
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
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_millis(250)).await;

        let payload = vec![0x3C; 512];
        let bytes = serialize_frame(&MAINNET_MAGIC, &MessageFrame { code: 12, payload });
        let total = bytes.len();
        let drip = tokio::spawn(async move {
            // Eight pieces, 50 ms apart: ~400 ms overall, past the
            // deadline, but never 250 ms without a byte.
            for piece in bytes.chunks(total.div_ceil(8)) {
                client.stream.write_all(piece).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
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
            Err(ConnectionError::FrameStalled { got, want, after }) => {
                assert_eq!(got, HEADER_LENGTH);
                assert_eq!(want, framing::wire_len(4_096));
                assert_eq!(
                    after,
                    Duration::from_millis(150),
                    "the reported deadline must be the one that fired"
                );
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

        let budget = ReadBudget::new(PER_READER_MAX);
        let observed = Arc::new(AtomicBool::new(false));
        let (probe_budget, probe_seen) = (budget.clone(), observed.clone());
        let probe = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            probe_seen.store(true, Ordering::Relaxed);
            probe_budget.bytes().available_permits()
        });

        // The read cannot finish; run it only until the probe has looked.
        // Well clear of the probe, so a loaded box cannot cancel the read
        // (releasing its permits) before the probe has looked.
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            server.read_frame_body_metered(&budget),
        )
        .await;

        let available = probe.await.unwrap();
        assert!(observed.load(Ordering::Relaxed));
        assert_eq!(
            available,
            PER_READER_MAX - (HEADER_LENGTH + READ_BUF_SIZE),
            "a bare header must hold the bytes it has plus one read chunk"
        );
        // Cancelling the read released both the bytes and the slot.
        assert_eq!(budget.bytes().available_permits(), PER_READER_MAX);
        assert_eq!(budget.slots_available(), 1);
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

        let budget = ReadBudget::new(PER_READER_MAX);
        server.read_frame_header().await.unwrap();
        let (frame, permit) = server.read_frame_body_metered(&budget).await.unwrap();
        assert_eq!(frame.code, 9);
        assert_eq!(frame.payload, payload);
        let permit = permit.expect("a 200 KB body crosses several read chunks");
        // Every wire byte of the frame is charged, so the permit always
        // covers the payload — the caller settles by releasing, never by
        // acquiring more while holding permits.
        assert!(
            permit.num_permits() >= payload.len(),
            "permits {} must cover the {} payload bytes",
            permit.num_permits(),
            payload.len()
        );
        drop(permit);
        assert_eq!(budget.bytes().available_permits(), PER_READER_MAX);
        let _client = writer.await.unwrap();
    }

    /// P2-3(a): a peer delivering a large frame at a steady but slow rate
    /// crosses many deadline periods and must survive every one — the
    /// production analogue is an 8 MB block from a 100 KB/s peer, ~80 s
    /// against a 30 s deadline. Same ratio here, in milliseconds.
    ///
    /// Real clock with an injected short deadline rather than
    /// `tokio::time::pause`: this crate deliberately avoids the paused
    /// clock around live sockets, where auto-advance can fire a timer
    /// while bytes are still in the kernel.
    #[tokio::test]
    async fn read_frame_body_steady_slow_sender_survives_many_deadlines() {
        // 200 ms deadline, a piece every 20 ms, 40 pieces: ~800 ms of
        // transfer across four deadline periods, with a 10x margin
        // between the sender's gap and the deadline so a loaded CI box
        // cannot turn scheduling jitter into a false stall.
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_millis(200)).await;

        let payload = vec![0x6B; 240_000];
        let bytes = serialize_frame(&MAINNET_MAGIC, &MessageFrame { code: 44, payload });
        let total = bytes.len();
        let sender = tokio::spawn(async move {
            for piece in bytes.chunks(total.div_ceil(40)) {
                client.stream.write_all(piece).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            client
        });

        let frame = server.read_message().await.expect("steady slow sender");
        assert_eq!(frame.code, 44);
        assert_eq!(frame.payload.len(), 240_000);
        let _client = sender.await.unwrap();
    }

    /// The header phase gets the same per-progress deadline, but only
    /// once a frame has actually started: a peer that has sent PART of a
    /// header and stopped is stalled.
    #[tokio::test]
    async fn read_frame_header_partial_header_then_silence_stalls() {
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_millis(150)).await;

        // Four of the nine header bytes, then silence (no close).
        client.stream.write_all(&MAINNET_MAGIC).await.unwrap();

        match server.read_frame_header().await {
            Err(ConnectionError::FrameStalled { got, want, after }) => {
                assert_eq!(got, MAGIC_LENGTH);
                assert_eq!(want, HEADER_LENGTH);
                assert_eq!(after, Duration::from_millis(150));
            }
            other => panic!("expected FrameStalled, got {other:?}"),
        }
        drop(client);
    }

    /// ...but an IDLE connection between frames is not stalled. Ergo
    /// peers legitimately go minutes without sending, and the 600 s
    /// inactivity sweep — not this deadline — is what ends those.
    #[tokio::test]
    async fn read_frame_header_idle_between_frames_is_not_a_stall() {
        let (mut client, mut server) = connected_pair_with_idle(Duration::from_millis(50)).await;

        let waiting = tokio::spawn(async move { server.read_message().await });
        // Many deadline periods of complete silence.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !waiting.is_finished(),
            "a quiet peer between frames must not be judged stalled"
        );

        client.send(3, vec![1, 2, 3]).await.unwrap();
        let frame = waiting.await.unwrap().expect("frame after a long idle");
        assert_eq!(frame.code, 3);
        assert_eq!(frame.payload, vec![1, 2, 3]);
    }

    // ----- helpers: mixed-reader workload -----

    const LARGE_READERS: usize = 40;
    const SMALL_READERS: usize = 40;
    const LARGE_FRAME: usize = 3 << 20;
    /// Enough of each large frame to put every large reader mid-body,
    /// holding permits and needing more, at the same moment.
    const LARGE_PART_ONE: usize = 2 << 20;
    const SMALL_FRAME: usize = 32 * 1024;

    /// Drive `LARGE_READERS` readers whose senders pause mid-frame plus
    /// `SMALL_READERS` single-chunk readers against `budget`, and return
    /// how many finished within `watchdog` — `None` if they did not all
    /// finish, which for this workload means they deadlocked.
    async fn run_mixed_readers(budget: &ReadBudget, watchdog: Duration) -> Option<usize> {
        // The senders' pause must actually exhaust the budget, or the
        // deadlock this pins cannot form.
        assert!(
            LARGE_READERS * LARGE_PART_ONE > budget.capacity(),
            "the paused senders must over-subscribe the budget"
        );

        let mut tasks = Vec::with_capacity(LARGE_READERS + SMALL_READERS);
        for i in 0..LARGE_READERS {
            let (mut client, mut server) = metered_pair().await;
            let bytes = serialize_frame(
                &MAINNET_MAGIC,
                &MessageFrame {
                    code: 88,
                    payload: vec![i as u8; LARGE_FRAME],
                },
            );
            let writer = tokio::spawn(async move {
                client.write_all(&bytes[..LARGE_PART_ONE]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(400)).await;
                client.write_all(&bytes[LARGE_PART_ONE..]).await.unwrap();
                client
            });
            let budget = budget.clone();
            tasks.push(tokio::spawn(async move {
                server.read_frame_header().await.unwrap();
                let (frame, permit) = server.read_frame_body_metered(&budget).await.unwrap();
                assert_eq!(frame.payload.len(), LARGE_FRAME);
                // Drain, as the action loop does.
                drop(permit);
                let _client = writer.await.unwrap();
            }));
        }
        for _ in 0..SMALL_READERS {
            let (mut client, mut server) = metered_pair().await;
            let bytes = serialize_frame(
                &MAINNET_MAGIC,
                &MessageFrame {
                    code: 7,
                    payload: vec![0x5A; SMALL_FRAME],
                },
            );
            let writer = tokio::spawn(async move {
                client.write_all(&bytes).await.unwrap();
                client
            });
            let budget = budget.clone();
            tasks.push(tokio::spawn(async move {
                server.read_frame_header().await.unwrap();
                let (frame, permit) = server.read_frame_body_metered(&budget).await.unwrap();
                assert_eq!(frame.payload.len(), SMALL_FRAME);
                drop(permit);
                let _client = writer.await.unwrap();
            }));
        }

        let total = tasks.len();
        tokio::time::timeout(watchdog, async {
            for task in tasks {
                task.await.unwrap();
            }
            total
        })
        .await
        .ok()
    }

    // ----- admission control -----

    /// #280 P0 — the hold-and-wait deadlock. Readers charged per read
    /// hold permits for what they have taken in and then wait for more.
    /// Concurrent readers whose COMBINED demand exceeds the budget used
    /// to split it between themselves, park needing one more chunk each,
    /// and never complete — nothing is enqueued, so no payload is ever
    /// dropped and no permit ever comes back. All P2P reading stops,
    /// permanently.
    ///
    /// Forty large readers whose senders pause mid-frame put every one of
    /// them in that state at the same moment (40 x 2 MiB of demand
    /// against an 8-slot budget of 66 MB), and forty single-chunk readers
    /// contend alongside them. Every reader must finish.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_readers_over_budget_all_complete() {
        // Per-address cap off: every loopback reader shares one address,
        // and this test is about the SLOT pool. The cap has its own test.
        let budget = ReadBudget::for_slot_contention_test(8 * PER_READER_MAX, Some(8));
        assert_eq!(budget.slots_available(), 8);
        let done = run_mixed_readers(&budget, Duration::from_secs(60)).await;
        assert_eq!(done, Some(LARGE_READERS + SMALL_READERS));
        assert_eq!(
            budget.bytes().available_permits(),
            budget.capacity(),
            "every byte permit is returned once the payloads are drained"
        );
        assert_eq!(budget.slots_available(), 8, "every slot is returned");
    }

    /// The negative control for the test above: the SAME workload with
    /// the slot pool removed must deadlock. Without this, that test only
    /// proves the workload runs — not that the pool is what carries it.
    /// Bounded by a watchdog so a failure is a timeout, not a hung suite.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_readers_over_budget_deadlock_without_slot_pool() {
        let budget = ReadBudget::for_slot_contention_test(8 * PER_READER_MAX, None);
        let done = run_mixed_readers(&budget, Duration::from_secs(10)).await;
        assert_eq!(
            done, None,
            "without the slot pool these readers must deadlock — if this \
             passes, the pool is no longer what makes the workload finish"
        );
        assert!(
            budget.bytes().available_permits() < PER_READER_MAX,
            "the deadlocked readers should be holding the budget between them"
        );
    }

    /// Rule 4: one slot per remote address. A second large frame from an
    /// address already holding a slot waits for the first to finish, so
    /// occupying the pool costs an attacker one address per slot rather
    /// than one socket. An honest peer streams one frame at a time and
    /// never meets the cap.
    #[tokio::test]
    async fn same_address_cannot_hold_two_slots() {
        // TWO slots, so a blocked second reader can only be the
        // per-address cap — with one slot it would park on the pool
        // whether or not the cap existed, and rule 4 would go unpinned.
        let budget = ReadBudget::new(2 * PER_READER_MAX);
        assert_eq!(budget.slots_available(), 2);

        // Two connections from the same loopback address, each announcing
        // a frame far too large for one read and then going quiet.
        let (mut client_a, mut conn_a) = metered_pair().await;
        let (mut client_b, mut conn_b) = metered_pair().await;
        for client in [&mut client_a, &mut client_b] {
            client
                .write_all(&header_bytes(55, MAX_PAYLOAD_SIZE as i32))
                .await
                .unwrap();
        }

        let budget_a = budget.clone();
        let first = tokio::spawn(async move {
            conn_a.read_frame_header().await.unwrap();
            let _ = conn_a.read_frame_body_metered(&budget_a).await;
        });
        // Let the first reader take the address's claim.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            budget.slots_available(),
            1,
            "the first reader holds one of two slots"
        );

        let budget_b = budget.clone();
        let second = tokio::spawn(async move {
            conn_b.read_frame_header().await.unwrap();
            let _ = conn_b.read_frame_body_metered(&budget_b).await;
            conn_b
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !second.is_finished(),
            "a second large frame from the same address must wait"
        );
        assert_eq!(
            budget.slots_available(),
            1,
            "a slot is FREE — the waiter is held by the address cap, not the pool"
        );
        assert_eq!(
            budget.bytes().available_permits(),
            budget.capacity() - (HEADER_LENGTH + READ_BUF_SIZE),
            "the waiting reader must hold NO bytes — it waits before charging"
        );

        first.abort();
        let _ = first.await;
        // With the address free, the second reader claims it and takes a
        // slot of its own.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            budget.slots_available(),
            1,
            "the claim passes to the waiter, which then takes a slot"
        );
        second.abort();
        let _ = second.await;
        assert_eq!(budget.slots_available(), 2, "and both come back on cancel");
        drop((client_a, client_b));
    }

    /// A header costs 9 bytes but claims a slot, so a header-only staller
    /// is the cheapest attack on the pool. The FIRST body byte is on a
    /// deadline of its own, much shorter than the no-progress one, so
    /// that slot comes back in seconds rather than in
    /// `BODY_IDLE_TIMEOUT`.
    #[tokio::test]
    async fn header_only_staller_loses_its_slot_on_the_first_body_deadline() {
        // First-body deadline an order of magnitude under the idle one,
        // mirroring the production 5 s against 30 s.
        let (mut client, mut server) =
            connected_pair_with_deadlines(Duration::from_millis(150), Duration::from_secs(30))
                .await;
        client
            .stream
            .write_all(&header_bytes(55, MAX_PAYLOAD_SIZE as i32))
            .await
            .unwrap();

        let budget = ReadBudget::new(PER_READER_MAX);
        server.read_frame_header().await.unwrap();

        let started = std::time::Instant::now();
        let result = server.read_frame_body_metered(&budget).await;
        assert!(
            matches!(result, Err(ConnectionError::FrameStalled { .. })),
            "expected FrameStalled, got {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the staller must lose its slot on the FIRST-body deadline, \
             not the 30 s no-progress one (took {:?})",
            started.elapsed()
        );
        assert_eq!(budget.slots_available(), 1, "the slot is returned");
        drop(client);
    }

    /// ...while a body that is slow but alive is untouched by the short
    /// first-byte deadline: it only has to START within it.
    #[tokio::test]
    async fn slow_but_live_body_survives_the_first_body_deadline() {
        // The first byte arrives well inside 200 ms; the rest trickles
        // over far longer than that, on the generous no-progress budget.
        let (mut client, mut server) =
            connected_pair_with_deadlines(Duration::from_millis(200), Duration::from_secs(30))
                .await;

        let payload = vec![0x77; 200_000];
        let bytes = serialize_frame(&MAINNET_MAGIC, &MessageFrame { code: 31, payload });
        let total = bytes.len();
        let sender = tokio::spawn(async move {
            for piece in bytes.chunks(total.div_ceil(20)) {
                client.stream.write_all(piece).await.unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            client
        });

        let budget = ReadBudget::new(PER_READER_MAX);
        server.read_frame_header().await.unwrap();
        let (frame, _permit) = server
            .read_frame_body_metered(&budget)
            .await
            .expect("a live slow body must survive the first-byte deadline");
        assert_eq!(frame.code, 31);
        assert_eq!(frame.payload.len(), 200_000);
        let _client = sender.await.unwrap();
    }
}
