//! Adversarial P2P harness for the pre-body byte budget (#283) and the
//! progress-only inactivity timer (#285).
//!
//! This is a **test tool**, not a general-purpose network utility: every
//! scenario below deliberately misbehaves at the framing/handshake level
//! (stalled headers, half-sent bodies, oversized frames, keepalive-only
//! traffic designed to dodge the progress timer). Point it only at nodes
//! you operate — running it against a node you do not own is indistinguishable
//! from an actual attack and may get the source IP banned or worse.
//!
//! Handshakes exactly the way `p2p_probe` does (raw, unframed handshake
//! bytes — see `peer_loop::do_handshake`), then drives one of a set of
//! misbehaving-peer scenarios against a live node and prints a PASS/FAIL
//! line with measured timings.
//!
//! Each client socket binds a distinct `127.<k>.0.1` source address. This
//! matters because the node enforces per-IP (=1 inbound connection) and
//! per-/16 (=3 inbound connections) admission limits (#283): connecting
//! every scenario slot from the same loopback address would only ever let
//! one (or, per /16, three) of them past the admission gate. Binding each
//! slot to its own `127.<k>.0.1` — a distinct host octet on the loopback
//! `/8` — gives each scenario its own IP (and, since `127.<k>.0.0/16` varies
//! per slot, its own /16 too), so scenarios that must run concurrently
//! (`big_frames`, and `same_ip_two_large`'s two connections that *share* a
//! source on purpose) get exactly the admission behavior they're testing.
//!
//! Usage:
//!   cargo run --release --example p2p_adversary -- \
//!       <host:port> <devnet|testnet|mainnet> <api-host:port> <scenario> [args...]
//!
//! Scenarios (expected outcome under #283 admission/deadlines + #285
//! progress-only inactivity — informational until those land on `main`):
//!   header_stall <n>     n header-only frames declaring MAX_PAYLOAD_SIZE;
//!                         expect each connection cut at ~5 s (the pre-body
//!                         byte-budget deadline), never let a declared body
//!                         sit unconsumed indefinitely
//!   body_stall <n>       n frames declaring 1 MiB, half sent then silence;
//!                         expect a cut once the stalled body misses its
//!                         read-progress deadline, not an indefinite wait
//!   trickle              1 MiB declared, 4 KiB every 10 s for 3 min, then
//!                         finish; expect this to succeed — slow-but-
//!                         progressing reads must NOT be penalized
//!   big_frames <n> <r>   n concurrent full 8 MB frames, r rounds; expect
//!                         all frames delivered without spurious eviction
//!   same_ip_two_large    two 8 MB frames from ONE source address; expects
//!                         the second connection from that source to be
//!                         rejected by the per-IP admission limit
//!   idle_slot             GetPeers every 60 s (no real progress); expect
//!                         eviction at ~600 s (the progress-only inactivity
//!                         timer, since GetPeers keepalive alone is not
//!                         progress)
//!   sync_cadence          non-empty SyncInfo every 60 s; expect NO
//!                         eviction — SyncInfo carrying data counts as
//!                         progress
//!   keepalive_only        unknown-code frame every 60 s; expect ~600 s
//!                         eviction — an unrecognized code is drained but
//!                         never counted as progress
//!   input_block_flood <a> <d>
//!                         the Matrix (input blocks) flood, plan 2 task 9:
//!                         `a` input-block announcements (code 100) at the
//!                         node's height + 1, each naming a RANDOM parent
//!                         input block the node has never seen, followed by
//!                         `d` bogus `InputBlockTransactions` (code 104)
//!                         deliveries for input block ids nobody requested.
//!                         Expect every spec §7.4 bound to hold — staged
//!                         bytes and the disconnected waitlist stay under
//!                         their caps, the honest peer is never penalised,
//!                         and the chain keeps advancing. The campaign
//!                         (`scripts/devnet-matrix/campaign.py --scenario
//!                         flood`) reads those bounds off
//!                         `/api/v1/status.input_blocks`; this side only
//!                         has to deliver the traffic and say it did.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

use ergo_p2p::framing::HEADER_LENGTH;
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, Handshake, HandshakeError, PeerSpec,
    Version,
};
use ergo_p2p::message::input_blocks::{
    serialize_input_block, serialize_input_block_txs, InputBlockTxs, CODE_INPUT_BLOCK,
    CODE_INPUT_BLOCK_TXS,
};
use ergo_p2p::message::{serialize_sync_info, SyncInfo};
use ergo_primitives::digest::blake2b256;
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::batch_merkle_proof::BatchMerkleProof;
use ergo_ser::header::Header;
use ergo_ser::input_block::{InputBlockAnnouncement, InputBlockFields};

/// Mirrors the (currently private) `ergo_p2p::connection::MAX_PAYLOAD_SIZE`
/// this harness was written against for #283/#285; kept local so the
/// example builds on `main`, which does not yet expose it. Value pinned to
/// the node's own constant (8 MiB + 2 KiB) — see `ergo-p2p/src/connection.rs`.
const MAX_PAYLOAD_SIZE: usize = 8_194_304;

/// A frame header peeked out of a byte buffer without requiring the full
/// (possibly not-yet-arrived) payload to be present. Mirrors the shape of
/// `ergo_p2p::framing::parse_frame_header`, which #283/#285 add for the
/// same reason (checking a declared length against the byte budget before
/// the body is fully buffered); reimplemented locally here from the public
/// `framing` constants so the example builds on `main`.
struct FrameHead {
    code: u8,
    payload_len: usize,
}

/// See [`FrameHead`]. Returns `Ok(Some(_))` once at least `HEADER_LENGTH`
/// bytes are buffered and the magic matches; `Ok(None)` if more header
/// bytes are still needed; `Err(())` on wrong magic or a negative declared
/// length (mirrors `ergo_p2p::framing::FrameError`'s cases for a header-only
/// parse, collapsed to a single error since the caller here only cares
/// whether framing is still trustworthy).
fn parse_frame_header(magic: &[u8; 4], buf: &[u8]) -> Result<Option<FrameHead>, ()> {
    if buf.len() < HEADER_LENGTH {
        return Ok(None);
    }
    if buf[..4] != *magic {
        return Err(());
    }
    let length = i32::from_be_bytes(buf[5..9].try_into().unwrap());
    if length < 0 {
        return Err(());
    }
    Ok(Some(FrameHead {
        code: buf[4],
        payload_len: length as usize,
    }))
}

/// Message code the node's dispatcher has no arm for: ignored, never
/// penalized, and (per `dispatch.rs`) deliberately NOT progress.
/// What these scenarios claim to speak. 6.0.2 for everything that tests
/// framing and admission; the Matrix flood overrides it, because a node
/// is entitled to ignore input-block traffic from a peer that never
/// claimed to speak the protocol, and a flood the node ignored would
/// pass the §7.4 bounds by not having happened.
const DEFAULT_PEER_VERSION: Version = Version {
    major: 6,
    minor: 0,
    patch: 2,
};
const SUBBLOCKS_PEER_VERSION: Version = Version {
    major: 6,
    minor: 5,
    patch: 0,
};

const CODE_UNKNOWN: u8 = 200;
const CODE_GET_PEERS: u8 = 1;
const CODE_PEERS: u8 = 2;
const CODE_SYNC_INFO: u8 = 65;
/// Any code is fine for a frame the node will only ever see the header of.
const CODE_MODIFIER: u8 = 33;

// ----- framing helpers -----

/// The 9-byte framing header alone: magic || code || length (BE i32).
fn frame_header(magic: &[u8; 4], code: u8, payload_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LENGTH);
    v.extend_from_slice(magic);
    v.push(code);
    v.extend_from_slice(&(payload_len as i32).to_be_bytes());
    v
}

/// Header + checksum, i.e. everything before the payload bytes.
fn frame_prefix(magic: &[u8; 4], code: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = frame_header(magic, code, payload.len());
    if !payload.is_empty() {
        v.extend_from_slice(&blake2b256(payload).as_bytes()[..4]);
    }
    v
}

fn full_frame(magic: &[u8; 4], code: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = frame_prefix(magic, code, payload);
    v.extend_from_slice(payload);
    v
}

/// Non-empty V1 SyncInfo, built with the node's own serializer.
///
/// Hand-rolling this is a trap: the count field is VLQ, not a raw BE u16,
/// and a raw `[0x00, 0x01]` decodes as the V2 sentinel followed by an
/// invalid mode marker — which the dispatcher answers with a Misbehavior
/// penalty rather than counting as progress.
///
/// V1 rather than V2: `SyncInfo::is_empty()` (the progress predicate in
/// `dispatch.rs`) is false for either shape once it carries an entry, and
/// V1 needs only a header id, which the REST API hands us directly.
fn sync_info_v1(ids: &[[u8; 32]]) -> Vec<u8> {
    serialize_sync_info(&SyncInfo::V1 {
        header_ids: ids.to_vec(),
    })
    .expect("one id is within MAX_SYNC_V1_IDS")
}

// ----- connection -----

struct Conn {
    stream: TcpStream,
    magic: [u8; 4],
    buf: Vec<u8>,
    src: Ipv4Addr,
}

impl Conn {
    /// Connect from `src`, then complete the raw handshake.
    async fn open(src: Ipv4Addr, target: SocketAddr, magic: [u8; 4]) -> std::io::Result<Self> {
        Self::open_as(src, target, magic, DEFAULT_PEER_VERSION).await
    }

    async fn open_as(
        src: Ipv4Addr,
        target: SocketAddr,
        magic: [u8; 4],
        version: Version,
    ) -> std::io::Result<Self> {
        let socket = TcpSocket::new_v4()?;
        // Deliberately NOT SO_REUSEADDR. These scenarios churn hundreds
        // of short-lived connections from a handful of source addresses,
        // and SO_REUSEADDR lets the kernel hand back an ephemeral port
        // whose 4-tuple is still in the node's TIME-WAIT table — the peer
        // then RSTs mid-stream, which reads as a node fault but is ours.
        socket.bind(SocketAddr::new(IpAddr::V4(src), 0))?;
        let mut stream = socket.connect(target).await?;

        let hs = Handshake {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            peer_spec: PeerSpec {
                agent_name: "ergoref".into(),
                version,
                node_name: format!("adv-{src}"),
                // No declared address: we do not want the node adding
                // these throwaway sockets to its address book.
                declared_address: None,
                features: vec![],
            },
        };
        stream.write_all(&serialize_handshake(&hs)).await?;

        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(10);
        // Definitely assigned by the `Err` arm below before any read of
        // it; the `Ok` arm returns.
        let mut last_err: HandshakeError;
        loop {
            match deserialize_handshake_with_consumed(&buf) {
                Ok((_, consumed)) => {
                    buf.drain(..consumed);
                    return Ok(Self {
                        stream,
                        magic,
                        buf,
                        src,
                    });
                }
                // Any parse failure here may just be a short read — the
                // handshake arrives over several TCP segments, and a VLQ
                // field can be split mid-value. Keep reading until the
                // deadline; a genuinely malformed handshake surfaces as
                // the timeout below, carrying the last parse error.
                Err(e) => last_err = e,
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(std::io::Error::other(format!(
                    "handshake timeout (last parse: {last_err:?})"
                )));
            }
            match tokio::time::timeout(left, self_read(&mut stream, &mut tmp)).await {
                Ok(Ok(0)) => return Err(std::io::Error::other("closed during handshake")),
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(std::io::Error::other(format!(
                        "handshake timeout (last parse: {last_err:?})"
                    )))
                }
            }
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes).await
    }

    /// Read and discard until the peer closes or `max` elapses.
    /// Returns (elapsed, closed).
    async fn await_close(&mut self, max: Duration) -> (Duration, bool) {
        let start = Instant::now();
        let mut tmp = [0u8; 65536];
        loop {
            let left = max.saturating_sub(start.elapsed());
            if left.is_zero() {
                return (start.elapsed(), false);
            }
            match tokio::time::timeout(left, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return (start.elapsed(), true),
                Ok(Ok(_)) => {}
                Err(_) => return (start.elapsed(), false),
            }
        }
    }

    /// Wait for a frame with `code`. Returns the elapsed time, or None on
    /// timeout / close.
    async fn wait_for_code(&mut self, code: u8, max: Duration) -> Option<Duration> {
        let start = Instant::now();
        let mut tmp = [0u8; 65536];
        loop {
            // Drain whole frames already buffered.
            loop {
                let Ok(Some(h)) = parse_frame_header(&self.magic, &self.buf) else {
                    // Unparsable head (wrong magic / negative len): give up
                    // on framing rather than spin.
                    if self.buf.len() >= HEADER_LENGTH
                        && parse_frame_header(&self.magic, &self.buf).is_err()
                    {
                        self.buf.clear();
                    }
                    break;
                };
                let total = if h.payload_len == 0 {
                    HEADER_LENGTH
                } else {
                    HEADER_LENGTH + 4 + h.payload_len
                };
                if self.buf.len() < total {
                    break;
                }
                self.buf.drain(..total);
                if h.code == code {
                    return Some(start.elapsed());
                }
            }
            let left = max.saturating_sub(start.elapsed());
            if left.is_zero() {
                return None;
            }
            match tokio::time::timeout(left, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return None,
                Ok(Ok(n)) => self.buf.extend_from_slice(&tmp[..n]),
                Err(_) => return None,
            }
        }
    }
}

async fn self_read(stream: &mut TcpStream, tmp: &mut [u8]) -> std::io::Result<usize> {
    stream.read(tmp).await
}

// ----- node API (raw HTTP/1.1, no extra deps) -----

async fn api_get(api: &str, path: &str) -> std::io::Result<(Duration, String)> {
    let start = Instant::now();
    let mut s = TcpStream::connect(api).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {api}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut body = Vec::new();
    s.read_to_end(&mut body).await?;
    Ok((start.elapsed(), String::from_utf8_lossy(&body).into_owned()))
}

fn json_u64(body: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let i = body.find(&needle)? + needle.len();
    let rest = body[i..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn json_first_hex_id(body: &str) -> Option<[u8; 32]> {
    let needle = "\"id\":";
    let mut from = 0usize;
    while let Some(rel) = body[from..].find(needle) {
        let i = from + rel + needle.len();
        let rest = body[i..].trim_start();
        if let Some(stripped) = rest.strip_prefix('"') {
            if let Some(q) = stripped.find('"') {
                if let Ok(v) = hex::decode(&stripped[..q]) {
                    if v.len() == 32 {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&v);
                        return Some(a);
                    }
                }
            }
        }
        from = i;
    }
    None
}

async fn height(api: &str) -> Option<u64> {
    let (_, body) = api_get(api, "/info").await.ok()?;
    json_u64(&body, "fullHeight")
}

// ----- scenarios -----

struct Ctx {
    target: SocketAddr,
    magic: [u8; 4],
    api: String,
}

fn src(k: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, k, 0, 1)
}

/// A deterministic pseudo-random 32-byte value.
///
/// Deterministic on purpose: a flood that cannot be replayed cannot be
/// used to reproduce whatever it provoked, and `rand` is not a
/// dependency of this crate. One blake2b256 per draw is far cheaper than
/// the framing around it.
fn draw(seed: u64, tag: u8, i: u32) -> [u8; 32] {
    let mut bytes = [0u8; 13];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8] = tag;
    bytes[9..].copy_from_slice(&i.to_be_bytes());
    *blake2b256(&bytes).as_bytes()
}

/// One bogus input-block announcement at `height`, naming a parent input
/// block that does not exist.
///
/// Everything in it is syntactically well-formed — the node must parse
/// it, decide it is unusable, and bound what it keeps. A malformed frame
/// would be rejected by the codec and would test nothing about §7.4.
fn bogus_announcement(seed: u64, i: u32, height: u32, parent_id: [u8; 32]) -> Vec<u8> {
    let mut pk = [0u8; 33];
    // The secp256k1 generator, so the point decodes; the solution is not
    // a valid PoW and is not meant to be.
    pk[0] = 0x02;
    pk[1..].copy_from_slice(&hex_literal_generator_x());
    let announcement = InputBlockAnnouncement {
        version: 4,
        header: Header {
            version: 4,
            parent_id: draw(seed, 1, i).into(),
            ad_proofs_root: draw(seed, 2, i).into(),
            transactions_root: draw(seed, 3, i).into(),
            state_root: {
                let mut root = [0u8; 33];
                root[..32].copy_from_slice(&draw(seed, 4, i));
                root.into()
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            extension_root: draw(seed, 5, i).into(),
            n_bits: 0x004e_2000,
            height,
            votes: [0, 0, 0],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes(pk),
                nonce: draw(seed, 6, i)[..8].try_into().expect("8 bytes"),
            },
        },
        fields: InputBlockFields {
            prev_input_block_id: Some(parent_id),
            transactions_digest: draw(seed, 7, i),
            prev_transactions_digest: draw(seed, 8, i),
            proof: BatchMerkleProof {
                indices: Vec::new(),
                proofs: Vec::new(),
            },
        },
        weak_tx_ids: Some(Vec::new()),
        unparsed_bytes: Vec::new(),
    };
    serialize_input_block(&announcement).expect("a well-formed announcement serializes")
}

/// X coordinate of the secp256k1 generator.
fn hex_literal_generator_x() -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(
        &hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
            .expect("a constant hex literal"),
    );
    out
}

/// The Matrix flood: `announcements` bogus code-100 frames at height + 1
/// with random parents, then `deliveries` bogus code-104 payloads for
/// input blocks nobody asked about.
///
/// The verdict here is deliberately narrow: this side reports that it
/// delivered the traffic and that the connection survived long enough to
/// do so. Whether the node held its §7.4 bounds is read off
/// `/api/v1/status.input_blocks` by the campaign, which is the only
/// place that can compare the counters before and after.
async fn input_block_flood(ctx: &Ctx, announcements: u32, deliveries: u32) -> bool {
    let flood_height = height(&ctx.api).await.unwrap_or(1) as u32 + 1;
    println!(
        "[input_block_flood] {announcements} announcements at height {flood_height}, \
         {deliveries} bogus code-104 deliveries"
    );
    let mut conn =
        match Conn::open_as(src(210), ctx.target, ctx.magic, SUBBLOCKS_PEER_VERSION).await {
            Ok(c) => c,
            Err(e) => {
                println!("FAIL input_block_flood: connect failed: {e}");
                return false;
            }
        };
    let seed = 0x4d61_7472_6978_0001; // "Matrix" + a run counter.
    let started = Instant::now();
    let mut sent = 0u32;
    for i in 0..announcements {
        // A random parent every time: each announcement is disconnected,
        // which is exactly what the waitlist cap exists to bound.
        let payload = bogus_announcement(seed, i, flood_height, draw(seed, 9, i));
        let frame = full_frame(&ctx.magic, CODE_INPUT_BLOCK, &payload);
        if conn.stream.write_all(&frame).await.is_err() {
            println!(
                "[input_block_flood] connection closed after {sent} announcements \
                 ({:?}) — a bounded node MAY drop the flooder",
                started.elapsed()
            );
            break;
        }
        sent += 1;
        if sent.is_multiple_of(500) {
            // Let the node breathe: a write loop that never yields
            // measures the loopback socket buffer, not the node.
            tokio::task::yield_now().await;
        }
    }
    let announced_in = started.elapsed();
    let mut delivered = 0u32;
    for i in 0..deliveries {
        let payload = serialize_input_block_txs(&InputBlockTxs {
            input_block_id: draw(seed, 10, i),
            transactions: Vec::new(),
        })
        .expect("an empty transaction list serializes");
        let frame = full_frame(&ctx.magic, CODE_INPUT_BLOCK_TXS, &payload);
        if conn.stream.write_all(&frame).await.is_err() {
            break;
        }
        delivered += 1;
        if delivered.is_multiple_of(100) {
            tokio::task::yield_now().await;
        }
    }
    println!(
        "[input_block_flood] sent {sent}/{announcements} announcements in {announced_in:?}, \
         {delivered}/{deliveries} deliveries in {:?}",
        started.elapsed() - announced_in
    );
    let after = height(&ctx.api).await;
    println!("[input_block_flood] node fullHeight after: {after:?}");
    // The flood is only a valid experiment if the traffic actually
    // reached the node; the BOUNDS verdict belongs to the campaign.
    let ok = sent > 0 && after.is_some();
    println!(
        "{} input_block_flood: node still answering REST after the flood",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

/// Header-only frames declaring MAX_PAYLOAD_SIZE: each must be cut at
/// FIRST_BODY_TIMEOUT (5 s). While they are parked, measure how long an
/// honest small frame and an honest LARGE frame take to be served.
async fn header_stall(ctx: &Ctx, n: u8) -> bool {
    println!("[header_stall] n={n} declaring {MAX_PAYLOAD_SIZE} B bodies");
    let mut tasks = Vec::new();
    for k in 1..=n {
        let target = ctx.target;
        let magic = ctx.magic;
        tasks.push(tokio::spawn(async move {
            let mut c = match Conn::open(src(k), target, magic).await {
                Ok(c) => c,
                Err(e) => return Err(format!("{}: connect/handshake: {e}", src(k))),
            };
            let hdr = frame_header(&magic, CODE_MODIFIER, MAX_PAYLOAD_SIZE);
            if let Err(e) = c.send(&hdr).await {
                return Err(format!("{}: send header: {e}", c.src));
            }
            let t0 = Instant::now();
            let (_, closed) = c.await_close(Duration::from_secs(20)).await;
            Ok((c.src, t0.elapsed(), closed))
        }));
    }

    // Give the stallers a moment to claim their slots.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Honest small frame: GetPeers takes no slot, so it must be served now.
    let small_rtt = {
        let mut c = Conn::open(src(n + 1), ctx.target, ctx.magic)
            .await
            .map_err(|e| println!("[header_stall] honest-small connect failed: {e}"))
            .ok();
        match c.as_mut() {
            Some(c) => {
                let f = full_frame(&ctx.magic, CODE_GET_PEERS, &[]);
                let _ = c.send(&f).await;
                c.wait_for_code(CODE_PEERS, Duration::from_secs(15)).await
            }
            None => None,
        }
    };

    // Honest LARGE frame: needs a slot, so its ingest is the residual to
    // measure. GetPeers is pipelined behind it; the reply cannot come
    // until the big frame has been fully read.
    let large_rtt = {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE];
        let mut big = full_frame(&ctx.magic, CODE_UNKNOWN, &payload);
        big.extend_from_slice(&full_frame(&ctx.magic, CODE_GET_PEERS, &[]));
        match Conn::open(src(n + 2), ctx.target, ctx.magic).await {
            Ok(mut c) => {
                let t0 = Instant::now();
                let _ = c.send(&big).await;
                let r = c.wait_for_code(CODE_PEERS, Duration::from_secs(60)).await;
                println!("[header_stall] honest-large send+serve {:?}", t0.elapsed());
                r
            }
            Err(e) => {
                println!("[header_stall] honest-large connect failed: {e}");
                None
            }
        }
    };

    let mut ok = true;
    let mut times = Vec::new();
    for t in tasks {
        match t.await.unwrap() {
            Ok((ip, elapsed, closed)) => {
                println!("[header_stall] {ip} closed={closed} after {elapsed:?}");
                if !closed || elapsed < Duration::from_secs(4) || elapsed > Duration::from_secs(9) {
                    ok = false;
                }
                times.push(elapsed);
            }
            Err(e) => {
                println!("[header_stall] ERROR {e}");
                ok = false;
            }
        }
    }
    times.sort();
    println!(
        "[header_stall] close times: min={:?} med={:?} max={:?}",
        times.first(),
        times.get(times.len() / 2),
        times.last()
    );
    println!("[header_stall] honest small-frame RTT: {small_rtt:?}");
    println!("[header_stall] honest large-frame RTT: {large_rtt:?}");
    if small_rtt.is_none() {
        println!("[header_stall] UNEXPECTED: honest small frame was not served");
        ok = false;
    }
    println!(
        "{} header_stall: expected close at ~5 s (FIRST_BODY_TIMEOUT)",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

/// Declare 1 MiB, send half, stop: BODY_IDLE_TIMEOUT (30 s) from the
/// last byte.
async fn body_stall(ctx: &Ctx, n: u8) -> bool {
    const BODY: usize = 1024 * 1024;
    println!("[body_stall] n={n} declaring {BODY} B, sending half");
    let mut tasks = Vec::new();
    for k in 1..=n {
        let target = ctx.target;
        let magic = ctx.magic;
        tasks.push(tokio::spawn(async move {
            let payload = vec![0u8; BODY];
            let mut bytes = frame_prefix(&magic, CODE_UNKNOWN, &payload);
            bytes.extend_from_slice(&payload[..BODY / 2]);
            let mut c = match Conn::open(src(k), target, magic).await {
                Ok(c) => c,
                Err(e) => return Err(format!("{}: connect/handshake: {e}", src(k))),
            };
            if let Err(e) = c.send(&bytes).await {
                return Err(format!("{}: send: {e}", c.src));
            }
            let t0 = Instant::now();
            let (_, closed) = c.await_close(Duration::from_secs(60)).await;
            Ok((c.src, t0.elapsed(), closed))
        }));
    }
    let mut ok = true;
    for t in tasks {
        match t.await.unwrap() {
            Ok((ip, elapsed, closed)) => {
                println!("[body_stall] {ip} closed={closed} after {elapsed:?}");
                if !closed || elapsed < Duration::from_secs(28) || elapsed > Duration::from_secs(36)
                {
                    ok = false;
                }
            }
            Err(e) => {
                println!("[body_stall] ERROR {e}");
                ok = false;
            }
        }
    }
    println!(
        "{} body_stall: expected close at ~30 s (BODY_IDLE_TIMEOUT)",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

/// Slow but honest: 4 KiB every 10 s for 3 minutes must NOT be cut,
/// because the deadline is per-progress. Then finish the body.
async fn trickle(ctx: &Ctx) -> bool {
    const BODY: usize = 1024 * 1024;
    const CHUNK: usize = 4096;
    let payload = vec![7u8; BODY];
    let mut c = match Conn::open(src(1), ctx.target, ctx.magic).await {
        Ok(c) => c,
        Err(e) => {
            println!("FAIL trickle: connect: {e}");
            return false;
        }
    };
    if let Err(e) = c
        .send(&frame_prefix(&ctx.magic, CODE_UNKNOWN, &payload))
        .await
    {
        println!("FAIL trickle: prefix: {e}");
        return false;
    }
    let start = Instant::now();
    let mut sent = 0usize;
    let mut alive = true;
    while start.elapsed() < Duration::from_secs(180) && sent + CHUNK <= BODY {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if c.send(&payload[sent..sent + CHUNK]).await.is_err() {
            alive = false;
            break;
        }
        sent += CHUNK;
        // Non-blocking check for a close.
        let (_, closed) = c.await_close(Duration::from_millis(50)).await;
        if closed {
            alive = false;
            break;
        }
    }
    println!(
        "[trickle] {sent} B trickled over {:?}, alive={alive}",
        start.elapsed()
    );
    if !alive {
        println!("FAIL trickle: disconnected while making per-chunk progress");
        return false;
    }
    // Finish the body, then ask a question we can hear the answer to.
    if c.send(&payload[sent..]).await.is_err() {
        println!("FAIL trickle: could not finish body");
        return false;
    }
    let _ = c.send(&full_frame(&ctx.magic, CODE_GET_PEERS, &[])).await;
    let rtt = c.wait_for_code(CODE_PEERS, Duration::from_secs(30)).await;
    println!("[trickle] post-completion GetPeers RTT: {rtt:?}");
    let ok = rtt.is_some();
    println!(
        "{} trickle: expected NO disconnect, body completes, no ban",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

/// N concurrent maximal frames, R rounds. Watch for a read-side
/// deadlock and for /info latency spikes.
async fn big_frames(ctx: &Ctx, n: u8, rounds: usize) -> bool {
    let h0 = height(&ctx.api).await;
    let api = ctx.api.clone();
    let sampler = tokio::spawn(async move {
        let mut worst = Duration::ZERO;
        let mut fails = 0usize;
        for _ in 0..600 {
            match api_get(&api, "/info").await {
                Ok((d, _)) => worst = worst.max(d),
                Err(_) => fails += 1,
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        (worst, fails)
    });

    // One connection per address, held for every round. Reconnecting per
    // round would churn hundreds of sockets through the node's per-IP
    // admission and the kernel's TIME-WAIT table, and the resets that
    // produces have nothing to do with the read path under test.
    let mut ok = true;
    let mut conns = Vec::new();
    for k in 1..=n {
        match Conn::open(src(k), ctx.target, ctx.magic).await {
            Ok(c) => conns.push(c),
            Err(e) => {
                println!("[big_frames] ERROR {}: connect: {e}", src(k));
                ok = false;
            }
        }
    }

    let mut total_bytes = 0usize;
    let round_start = Instant::now();
    for r in 0..rounds {
        let mut tasks = Vec::new();
        for mut c in conns.drain(..) {
            let magic = ctx.magic;
            tasks.push(tokio::spawn(async move {
                let payload = vec![c.src.octets()[1].wrapping_add(1); MAX_PAYLOAD_SIZE];
                let mut bytes = full_frame(&magic, CODE_UNKNOWN, &payload);
                bytes.extend_from_slice(&full_frame(&magic, CODE_GET_PEERS, &[]));
                let t0 = Instant::now();
                let len = bytes.len();
                if let Err(e) = c.send(&bytes).await {
                    return Err(format!("{}: send: {e}", c.src));
                }
                let rtt = c.wait_for_code(CODE_PEERS, Duration::from_secs(120)).await;
                Ok((c, len, t0.elapsed(), rtt))
            }));
        }
        for t in tasks {
            match t.await.unwrap() {
                Ok((c, len, elapsed, rtt)) => {
                    total_bytes += len;
                    println!(
                        "[big_frames] r{r} {} {len} B in {elapsed:?} serve-rtt={rtt:?}",
                        c.src
                    );
                    if rtt.is_none() {
                        println!("[big_frames] UNEXPECTED: frame never fully ingested (no reply)");
                        ok = false;
                    }
                    conns.push(c);
                }
                Err(e) => {
                    println!("[big_frames] ERROR {e}");
                    ok = false;
                }
            }
        }
        if conns.is_empty() {
            break;
        }
    }
    let dur = round_start.elapsed();
    println!(
        "[big_frames] {} MiB in {:?} = {:.1} MiB/s aggregate",
        total_bytes / (1024 * 1024),
        dur,
        total_bytes as f64 / (1024.0 * 1024.0) / dur.as_secs_f64()
    );
    sampler.abort();
    let h1 = height(&ctx.api).await;
    println!("[big_frames] fullHeight {h0:?} -> {h1:?}");
    println!(
        "{} big_frames: expected all frames ingested, no deadlock",
        if ok { "PASS" } else { "FAIL" }
    );
    ok
}

/// Two maximal frames from ONE source address. Interesting only if the
/// node's per-IP inbound limit lets the second connection in at all.
async fn same_ip_two_large(ctx: &Ctx) -> bool {
    let ip = src(9);
    let a = Conn::open(ip, ctx.target, ctx.magic).await;
    let b = Conn::open(ip, ctx.target, ctx.magic).await;
    let mut a = match a {
        Ok(c) => c,
        Err(e) => {
            println!("FAIL same_ip_two_large: first connection failed: {e}");
            return false;
        }
    };
    let payload = vec![3u8; MAX_PAYLOAD_SIZE];
    let mut bytes = full_frame(&ctx.magic, CODE_UNKNOWN, &payload);
    bytes.extend_from_slice(&full_frame(&ctx.magic, CODE_GET_PEERS, &[]));

    match b {
        Ok(mut b) => {
            let t0 = Instant::now();
            let ba = bytes.clone();
            let ta = tokio::spawn(async move {
                let _ = a.send(&ba).await;
                (
                    a.wait_for_code(CODE_PEERS, Duration::from_secs(120)).await,
                    "A",
                )
            });
            let bb = bytes.clone();
            let tb = tokio::spawn(async move {
                let _ = b.send(&bb).await;
                (
                    b.wait_for_code(CODE_PEERS, Duration::from_secs(120)).await,
                    "B",
                )
            });
            let ra = ta.await.unwrap();
            let rb = tb.await.unwrap();
            println!(
                "[same_ip_two_large] both admitted; A={:?} B={:?} wall={:?}",
                ra.0,
                rb.0,
                t0.elapsed()
            );
            let ok = ra.0.is_some() && rb.0.is_some();
            println!(
                "{} same_ip_two_large: both complete, second serialised behind the first",
                if ok { "PASS" } else { "FAIL" }
            );
            ok
        }
        Err(e) => {
            // Expected under the node's default per-IP inbound limit of 1.
            println!("[same_ip_two_large] second connection from {ip} rejected: {e}");
            let t0 = Instant::now();
            let _ = a.send(&bytes).await;
            let ra = a.wait_for_code(CODE_PEERS, Duration::from_secs(120)).await;
            println!(
                "[same_ip_two_large] single 8 MB frame served in {:?} (rtt {:?})",
                t0.elapsed(),
                ra
            );
            println!(
                "N/A same_ip_two_large: per-IP inbound limit = 1 makes two same-address \
                 connections unreachable; the per-address slot cap is defence in depth only"
            );
            ra.is_some()
        }
    }
}

/// Long-running liveness scenarios. `progress` selects what is sent every
/// 60 s; `expect_evict` is what #285 should do about it.
async fn liveness(
    ctx: &Ctx,
    k: u8,
    label: &'static str,
    frame: Vec<u8>,
    expect_evict: bool,
    run_for: Duration,
) -> bool {
    let mut c = match Conn::open(src(k), ctx.target, ctx.magic).await {
        Ok(c) => c,
        Err(e) => {
            println!("FAIL {label}: connect: {e}");
            return false;
        }
    };
    let start = Instant::now();
    let mut closed_at = None;
    while start.elapsed() < run_for {
        if c.send(&frame).await.is_err() {
            closed_at = Some(start.elapsed());
            break;
        }
        let (_, closed) = c.await_close(Duration::from_secs(60)).await;
        if closed {
            closed_at = Some(start.elapsed());
            break;
        }
    }
    let ok = match (expect_evict, closed_at) {
        (true, Some(t)) => {
            println!("[{label}] evicted at {t:?}");
            t >= Duration::from_secs(560) && t <= Duration::from_secs(700)
        }
        (true, None) => {
            println!("[{label}] NOT evicted within {run_for:?} — expected ~600 s");
            false
        }
        (false, None) => {
            println!("[{label}] still connected after {run_for:?}");
            true
        }
        (false, Some(t)) => {
            println!("[{label}] UNEXPECTED eviction at {t:?}");
            false
        }
    };
    println!(
        "{} {label}: {}",
        if ok { "PASS" } else { "FAIL" },
        if expect_evict {
            "expected eviction at ~600 s (INACTIVE_TIMEOUT, no progress)"
        } else {
            "expected NO eviction (SyncInfo is progress)"
        }
    );
    ok
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        eprintln!(
            "usage: p2p_adversary <host:port> <devnet|testnet|mainnet> <api-host:port> <scenario> [args]"
        );
        std::process::exit(2);
    }
    let target: SocketAddr = args[0].parse().expect("host:port");
    // Authoritative magic from ergo-chain-spec (what the live node frames
    // with) — NOT framing::TESTNET_MAGIC, which is the stale PaiNet value.
    // `devnet` is the Matrix recipe's private chain
    // (`scripts/devnet-matrix/genesis.conf`: magicBytes = [7,7,7,7]);
    // without it the campaign's flood would be framed with testnet magic
    // and dropped before the handshake, which would look like a node
    // that withstood a flood it never received.
    let magic: [u8; 4] = match args[1].as_str() {
        "mainnet" => [1, 0, 2, 4],
        "devnet" => [7, 7, 7, 7],
        _ => [2, 3, 2, 3],
    };
    let ctx = Ctx {
        target,
        magic,
        api: args[2].clone(),
    };
    let scenario = args[3].clone();
    let rest = &args[4..];

    let h_before = height(&ctx.api).await;
    println!("[node] fullHeight before: {h_before:?}");

    let ok = match scenario.as_str() {
        "header_stall" => {
            let n: u8 = rest.first().map_or(32, |s| s.parse().unwrap());
            header_stall(&ctx, n).await
        }
        "body_stall" => {
            let n: u8 = rest.first().map_or(4, |s| s.parse().unwrap());
            body_stall(&ctx, n).await
        }
        "trickle" => trickle(&ctx).await,
        "big_frames" => {
            let n: u8 = rest.first().map_or(8, |s| s.parse().unwrap());
            let r: usize = rest.get(1).map_or(3, |s| s.parse().unwrap());
            big_frames(&ctx, n, r).await
        }
        "same_ip_two_large" => same_ip_two_large(&ctx).await,
        "idle_slot" => {
            liveness(
                &ctx,
                200,
                "idle_slot",
                full_frame(&magic, CODE_GET_PEERS, &[]),
                true,
                Duration::from_secs(720),
            )
            .await
        }
        "keepalive_only" => {
            liveness(
                &ctx,
                201,
                "keepalive_only",
                full_frame(&magic, CODE_UNKNOWN, &[]),
                true,
                Duration::from_secs(720),
            )
            .await
        }
        "sync_cadence" => {
            let (_, body) = api_get(&ctx.api, "/blocks/lastHeaders/1")
                .await
                .expect("lastHeaders");
            let id = json_first_hex_id(&body).expect("a header id from /blocks/lastHeaders/1");
            println!("[sync_cadence] using header id {}", hex::encode(id));
            let payload = sync_info_v1(&[id]);
            liveness(
                &ctx,
                203,
                "sync_cadence",
                full_frame(&magic, CODE_SYNC_INFO, &payload),
                false,
                Duration::from_secs(720),
            )
            .await
        }
        "input_block_flood" => {
            let a: u32 = rest.first().map_or(10_000, |s| s.parse().unwrap());
            let d: u32 = rest.get(1).map_or(1_000, |s| s.parse().unwrap());
            input_block_flood(&ctx, a, d).await
        }
        other => {
            eprintln!("unknown scenario: {other}");
            std::process::exit(2);
        }
    };

    let h_after = height(&ctx.api).await;
    println!("[node] fullHeight after: {h_after:?}");
    println!("[result] {scenario}: {}", if ok { "PASS" } else { "FAIL" });
}
