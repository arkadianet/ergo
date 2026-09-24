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
//!   input_block_wrong_body <secs>
//!                         answers the follower's input-block body
//!                         requests (code 105) with bodies the
//!                         announcement does not commit to, forcing the
//!                         ordering-block rebuild to compute a
//!                         transactions root that cannot match the
//!                         header's. Used by the campaign's `evict`
//!                         scenario, which reads the resulting fallback
//!                         off the event feed.
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
//!   input_block_root_flood <hosts> <per_host> <waves> <interval_ms> <first>
//!                         the Matrix ROOT-announcement flood (plan 3, F13):
//!                         `waves` waves, each from `hosts` fresh source
//!                         addresses `127.<first + n>.0.1`, every host
//!                         sending `per_host` announcements at the node's
//!                         height + 2 under a random, unknown ordering
//!                         parent — the shape a patched Scala follower
//!                         holds in its bounded pending store, unvalidated,
//!                         until the parent is applied. Each wave re-reads
//!                         the height, so the flood stays at + 2 while the
//!                         honest chain advances. Fresh hosts per wave
//!                         because the store admits per HOST and a host the
//!                         node blacklists cannot reconnect. Aimed at a
//!                         Scala follower by the campaign's `flood
//!                         --reference-follower patched`, which reads the
//!                         store's caps off `/info` and the honest root
//!                         announcements off the follower's log.
//!
//!                         `--hold-ms <ms>` (after the positionals) is the
//!                         HELD-connection mode: one connection per host,
//!                         opened once and kept for the whole flood, every
//!                         wave sent over it, then held `ms` past the last
//!                         wave while draining whatever the node sends. A
//!                         store that drops a host's entries on disconnect
//!                         keeps them only while the connection stays up,
//!                         so this is the shape that tests its caps for a
//!                         full TTL. Only `hosts` addresses are used (not
//!                         `hosts x waves`). The report says how many
//!                         connections the node closed before the hold
//!                         ended.

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
    deserialize_input_block_txs_request, serialize_input_block, serialize_input_block_txs,
    InputBlockTxs, CODE_INPUT_BLOCK, CODE_INPUT_BLOCK_TXS, CODE_INPUT_BLOCK_TXS_REQUEST,
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
    /// Read the next whole frame, returning `(code, payload)`.
    ///
    /// `wait_for_code` discards payloads; the wrong-body scenario has to
    /// READ them — it answers a request whose input-block id and weak
    /// ids are in the frame it just received.
    async fn next_frame(&mut self, max: Duration) -> Option<(u8, Vec<u8>)> {
        let start = Instant::now();
        let mut tmp = [0u8; 65536];
        loop {
            if let Ok(Some(h)) = parse_frame_header(&self.magic, &self.buf) {
                let total = if h.payload_len == 0 {
                    HEADER_LENGTH
                } else {
                    HEADER_LENGTH + 4 + h.payload_len
                };
                if self.buf.len() >= total {
                    let frame: Vec<u8> = self.buf.drain(..total).collect();
                    let payload = if h.payload_len == 0 {
                        Vec::new()
                    } else {
                        frame[HEADER_LENGTH + 4..].to_vec()
                    };
                    return Some((h.code, payload));
                }
            } else if self.buf.len() >= HEADER_LENGTH {
                // Unparsable head: drop the buffer rather than spin.
                self.buf.clear();
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

/// A top-level numeric field. Tolerates whitespace before the colon, which
/// the Scala node's pretty-printed JSON puts there (`"fullHeight" : 4`).
fn json_u64(body: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let i = body.find(&needle)? + needle.len();
    let rest = body[i..].trim_start().strip_prefix(':')?.trim_start();
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
    let (_, body) = tokio::time::timeout(Duration::from_secs(10), api_get(api, "/info"))
        .await
        .ok()?
        .ok()?;
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

/// Answer the follower's input-block body requests with the WRONG body.
///
/// The `evict` scenario needs the reconstruction fallback to fire, and
/// no configuration lever produces it: the follower assembles from its
/// mempool as well as its input-block cache, so starving the cache does
/// not starve the rebuild. A peer that answers a body request with
/// transactions the announcement does not commit to does, because the
/// rebuilt transactions root then cannot match the header's.
///
/// The adversary makes itself a source the follower will ask: it relays
/// every input-block announcement the follower sends it straight back,
/// which registers it as an announcer for that id, and then answers the
/// resulting `RequestInputBlockTransactions` (code 105) with an
/// `InputBlockTransactions` (code 104) carrying a body list that does
/// not correspond to the requested weak ids.
///
/// It reports how many requests it answered. Whether the follower then
/// fell back is read off the event feed by the campaign — this side
/// only has to deliver the wrong bodies and say that it did.
async fn input_block_wrong_body(ctx: &Ctx, seconds: u64) -> bool {
    println!("[wrong_body] answering 105 requests with mismatched bodies for {seconds}s");
    let mut conn =
        match Conn::open_as(src(211), ctx.target, ctx.magic, SUBBLOCKS_PEER_VERSION).await {
            Ok(c) => c,
            Err(e) => {
                println!("FAIL input_block_wrong_body: connect failed: {e}");
                return false;
            }
        };
    // Built once, and checked once: a decoy that does not serialize would
    // be skipped for every id and the run would report "pushed 0" with
    // nothing to say why — which is what two campaign attempts did.
    let decoy = decoy_transaction();
    let decoy_frame_for = |id: [u8; 32]| -> Result<Vec<u8>, String> {
        let payload = serialize_input_block_txs(&InputBlockTxs {
            input_block_id: id,
            transactions: vec![decoy.clone()],
        })
        .map_err(|e| format!("decoy body does not serialize: {e:?}"))?;
        Ok(full_frame(&ctx.magic, CODE_INPUT_BLOCK_TXS, &payload))
    };
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut tally = WrongBodyTally::default();
    let mut last_report = Instant::now();
    // Input block ids we have already pushed a wrong body for.
    let mut served: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut last_poll = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        // The follower does not relay input-block announcements to this
        // peer — two runs saw zero — so waiting to be told an id never
        // produces one. Its REST surface publishes the same ids, and a
        // body can be pushed for them unsolicited.
        if last_poll.elapsed() >= Duration::from_secs(1) {
            last_poll = Instant::now();
            tally.polls += 1;
            match api_get(&ctx.api, "/blocks/bestInputChain").await {
                Err(e) => tally.note_problem(format!("{e}")),
                Ok((_, body)) => {
                    tally.last_body_len = body.len();
                    // `bestOrdering` is a 64-hex string too, and it is NOT
                    // an input block: pushing a body for it only ever
                    // produced an `UnknownBlock` drop. It is kept as the
                    // tree the pushed ids sit under, so the campaign can
                    // attribute a fallback to the ordering block that
                    // closes that tree.
                    let ordering = json_hex_field(&body, "bestOrdering");
                    let ids: Vec<[u8; 32]> = json_hex_ids(&body)
                        .into_iter()
                        .filter(|id| Some(*id) != ordering)
                        .collect();
                    tally.ids_seen += ids.len() as u32;
                    if ids.is_empty() {
                        // "No ids" and "the request failed" are different
                        // answers; keep a snippet of the former.
                        let tail: String = body
                            .chars()
                            .rev()
                            .take(160)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect();
                        tally.note_problem(format!("no ids in {} bytes: {tail}", body.len()));
                    }
                    for id in ids {
                        if served.contains(&id) {
                            continue;
                        }
                        let frame = match decoy_frame_for(id) {
                            Ok(f) => f,
                            Err(problem) => {
                                tally.note_problem(problem);
                                continue;
                            }
                        };
                        if conn.stream.write_all(&frame).await.is_err() {
                            tally.note_problem("the follower closed the connection".into());
                            break;
                        }
                        served.insert(id);
                        tally.pushed += 1;
                        // The ids we pushed a wrong body FOR, and the tree
                        // they sit under, so the campaign can prove
                        // delivery against the node's own receipt line and
                        // attribute a mismatch fallback to one of them
                        // rather than to a natural mismatch.
                        println!(
                            "[wrong_body] pushed id={} ordering={}",
                            hex::encode(id),
                            ordering.map(hex::encode).unwrap_or_else(|| "none".into())
                        );
                    }
                }
            }
        }
        let left = std::cmp::min(
            deadline.saturating_duration_since(Instant::now()),
            Duration::from_millis(500),
        );
        let Some((code, payload)) = conn.next_frame(left).await else {
            if Instant::now() >= deadline {
                break;
            }
            continue;
        };
        match code {
            // An announcement the follower relayed to us: echo it back,
            // which is what would make us a peer it asks for the bodies,
            // and push a wrong body for it unsolicited, because the
            // follower asks the block's original announcer and the echo
            // arrives second (`AlreadyKnown`).
            CODE_INPUT_BLOCK => {
                let frame = full_frame(&ctx.magic, CODE_INPUT_BLOCK, &payload);
                if conn.stream.write_all(&frame).await.is_err() {
                    break;
                }
                tally.relayed += 1;
                if let Some(id) = announced_input_block_id(&payload) {
                    if served.insert(id) {
                        match decoy_frame_for(id) {
                            Ok(frame) => {
                                if conn.stream.write_all(&frame).await.is_err() {
                                    break;
                                }
                                tally.pushed += 1;
                                println!(
                                    "[wrong_body] pushed id={} ordering=relayed",
                                    hex::encode(id)
                                );
                            }
                            Err(problem) => tally.note_problem(problem),
                        }
                    }
                }
            }
            // The request we exist to answer badly.
            CODE_INPUT_BLOCK_TXS_REQUEST => {
                tally.requests += 1;
                let Ok(request) = deserialize_input_block_txs_request(&payload) else {
                    continue;
                };
                // A body list that does NOT correspond to the requested
                // weak ids: one transaction whose own weak id is nothing
                // anybody asked for.
                match decoy_frame_for(request.input_block_id) {
                    Ok(frame) => {
                        if conn.stream.write_all(&frame).await.is_err() {
                            break;
                        }
                        tally.answered += 1;
                        println!(
                            "[wrong_body] answered id={}",
                            hex::encode(request.input_block_id)
                        );
                    }
                    Err(problem) => tally.note_problem(problem),
                }
            }
            _ => {}
        }
        // Report as we go and FLUSH: stdout to a pipe is block-buffered,
        // so the closing summary was lost when the scenario terminated
        // the harness and the campaign saw only the banner.
        if last_report.elapsed() >= Duration::from_secs(10) {
            last_report = Instant::now();
            tally.report();
        }
    }
    tally.report();
    let ok = tally.answered > 0 || tally.pushed > 0;
    println!(
        "{} input_block_wrong_body: mismatched bodies were delivered to the follower",
        if ok { "PASS" } else { "FAIL" }
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();
    ok
}

/// What `input_block_wrong_body` did, reported as it goes.
#[derive(Default)]
struct WrongBodyTally {
    relayed: u32,
    pushed: u32,
    requests: u32,
    answered: u32,
    polls: u32,
    ids_seen: u32,
    last_body_len: usize,
    /// The FIRST problem hit, kept so "the request failed", "there were
    /// no ids" and "the body would not serialize" stop looking alike.
    first_problem: Option<String>,
}

impl WrongBodyTally {
    fn note_problem(&mut self, problem: String) {
        if self.first_problem.is_none() {
            self.first_problem = Some(problem);
        }
    }

    fn report(&self) {
        use std::io::Write;
        println!(
            "[wrong_body] relayed {}, pushed {} unsolicited wrong bodies, \
             saw {} body requests, answered {}; \
             rest polls={} ids_seen={} last_body={}B first_problem={}",
            self.relayed,
            self.pushed,
            self.requests,
            self.answered,
            self.polls,
            self.ids_seen,
            self.last_body_len,
            self.first_problem.as_deref().unwrap_or("none")
        );
        let _ = std::io::stdout().flush();
    }
}

/// The 32-byte hex value of one string field, e.g. `"bestOrdering":"…"`.
fn json_hex_field(body: &str, key: &str) -> Option<[u8; 32]> {
    let needle = format!("\"{key}\":");
    let i = body.find(&needle)? + needle.len();
    let rest = body[i..].trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    let v = hex::decode(&rest[..end]).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// Every 64-hex id in a JSON body, in order of appearance.
///
/// `/blocks/bestInputChain` answers with a bare array of ids under
/// `bestInputBlocks`, so there is no `"id":` key to key off — this takes
/// the quoted 32-byte hex strings directly.
fn json_hex_ids(body: &str) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for piece in body.split('"') {
        if piece.len() != 64 {
            continue;
        }
        if let Ok(v) = hex::decode(piece) {
            if v.len() == 32 {
                let mut a = [0u8; 32];
                a.copy_from_slice(&v);
                out.push(a);
            }
        }
    }
    out
}

/// The input block id an announcement frame commits to — its header id.
fn announced_input_block_id(payload: &[u8]) -> Option<[u8; 32]> {
    let ann = ergo_ser::input_block::parse_input_block_announcement(payload).ok()?;
    let id = ann.id().ok()?;
    Some(*id.as_bytes())
}

/// One transaction that commits to nothing the follower asked for: no
/// inputs, no data inputs, no outputs. Constructed rather than parsed —
/// the previous version parsed three bytes where the codec needs four
/// (input, data-input, token-table and output counts), so it returned
/// `None` on every call and the adversary pushed nothing at all.
fn decoy_transaction() -> ergo_ser::transaction::Transaction {
    ergo_ser::transaction::Transaction {
        inputs: Vec::new(),
        data_inputs: Vec::new(),
        output_candidates: Vec::new(),
    }
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

/// `input_block_root_flood`'s arguments: five positionals, each with the
/// default it has always had, and the optional `--hold-ms` flag that
/// selects the held-connection mode.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootFloodArgs {
    hosts: u8,
    per_host: u32,
    waves: u8,
    interval: Duration,
    first: u8,
    /// `Some` = held connections, kept this long past the last wave.
    hold: Option<Duration>,
}

impl RootFloodArgs {
    fn parse(rest: &[String]) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut hold = None;
        let mut it = rest.iter();
        while let Some(arg) = it.next() {
            if arg == "--hold-ms" {
                let value = it.next().ok_or("--hold-ms needs a value")?;
                let ms: u64 = value
                    .parse()
                    .map_err(|e| format!("--hold-ms {value}: {e}"))?;
                if ms == 0 {
                    return Err("--hold-ms must be positive".into());
                }
                hold = Some(Duration::from_millis(ms));
            } else {
                positional.push(arg.as_str());
            }
        }
        if positional.len() > 5 {
            return Err(format!("unexpected arguments: {:?}", &positional[5..]));
        }
        fn field<T: std::str::FromStr>(
            values: &[&str],
            i: usize,
            name: &str,
            default: T,
        ) -> Result<T, String>
        where
            T::Err: std::fmt::Display,
        {
            values.get(i).map_or(Ok(default), |v| {
                v.parse().map_err(|e| format!("{name} {v}: {e}"))
            })
        }
        let args = Self {
            hosts: field(&positional, 0, "hosts", 10)?,
            per_host: field(&positional, 1, "per_host", 40)?,
            waves: field(&positional, 2, "waves", 10)?,
            interval: Duration::from_millis(field(&positional, 3, "interval_ms", 15_000)?),
            first: field(&positional, 4, "first", 100)?,
            hold,
        };
        if args.hold.is_some() && args.per_host.saturating_mul(u32::from(args.waves)) > 0xffff {
            // The held mode numbers a host's announcements across waves in
            // the low 16 bits of the draw index; past that they repeat.
            return Err(format!(
                "--hold-ms: per_host x waves = {} exceeds 65535 distinct announcements per host",
                u64::from(args.per_host) * u64::from(args.waves)
            ));
        }
        if args.hosts == 0 || args.per_host == 0 || args.waves == 0 {
            return Err("hosts, per_host and waves must be positive".into());
        }
        if u32::from(args.first) + args.hosts_needed() > 256 {
            return Err("source address range exceeds 127.255.0.1".into());
        }
        Ok(args)
    }

    /// How many distinct `127.<k>.0.1` sources the flood uses: fresh
    /// hosts every wave, or the same `hosts` held for all of them.
    fn hosts_needed(&self) -> u32 {
        let per_wave = u32::from(self.hosts);
        if self.hold.is_some() {
            per_wave
        } else {
            per_wave * u32::from(self.waves)
        }
    }

    /// The draw index of announcement `i` of `wave` from source octet
    /// `k`: distinct per announcement across the whole flood. A fresh
    /// host sends one wave, so its index is `i`; a held host sends every
    /// wave, so its index runs on across them.
    fn announcement_index(&self, k: u8, wave: u8, i: u32) -> u32 {
        let within = if self.hold.is_some() {
            u32::from(wave) * self.per_host + i
        } else {
            i
        };
        (u32::from(k) << 16) | within
    }
}

/// Closure times are observation times, not an attribution to the remote node.
struct HeldConn {
    conn: Conn,
    closure: Option<serde_json::Value>,
}

impl HeldConn {
    fn close(&mut self, kind: &str, error: Option<String>, started: Instant) {
        if self.closure.is_none() {
            self.closure = Some(serde_json::json!({
                "kind": kind, "error": error, "observed_ms": started.elapsed().as_millis()
            }));
        }
    }
}

/// Bound each socket's work so continuous traffic cannot monopolize a pass.
fn drain_pass(conns: &mut [HeldConn], end: Instant, started: Instant) {
    let mut buf = [0u8; 65536];
    for held in conns.iter_mut().filter(|h| h.closure.is_none()) {
        for _ in 0..8 {
            if Instant::now() >= end {
                return;
            }
            match held.conn.stream.try_read(&mut buf) {
                Ok(0) => {
                    held.close("eof", None, started);
                    break;
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    held.close("io_error", Some(e.to_string()), started);
                    break;
                }
            }
        }
    }
}

async fn drain_held(conns: &mut [HeldConn], end: Instant, started: Instant) {
    while Instant::now() < end {
        drain_pass(conns, end, started);
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            end.min(Instant::now() + Duration::from_millis(5)),
        ))
        .await;
    }
}

/// Nonblocking writes advance every connection while reads keep draining.
/// The deadline bounds a whole wave, including peers that never read.
async fn send_held(
    conns: &mut [HeldConn],
    frames: &[Vec<Vec<u8>>],
    timeout: Duration,
    started: Instant,
) -> (u32, u32, Option<Instant>) {
    let end = Instant::now() + timeout;
    let mut positions = vec![(0usize, 0usize); conns.len()];
    let (mut sent, mut errors, mut last_send) = (0, 0, None);
    loop {
        drain_pass(conns, end, started);
        let mut pending = false;
        for (index, held) in conns.iter_mut().enumerate() {
            let (frame, offset) = &mut positions[index];
            if *frame == frames[index].len() || held.closure.is_some() {
                continue;
            }
            if Instant::now() >= end {
                held.close("io_error", Some("wave write timed out".into()), started);
                errors += 1;
                continue;
            }
            pending = true;
            for _ in 0..8 {
                if *frame == frames[index].len() || Instant::now() >= end {
                    break;
                }
                match held
                    .conn
                    .stream
                    .try_write(&frames[index][*frame][*offset..])
                {
                    Ok(0) => {
                        held.close("io_error", Some("write returned zero".into()), started);
                        errors += 1;
                        break;
                    }
                    Ok(n) => {
                        *offset += n;
                        if *offset == frames[index][*frame].len() {
                            *frame += 1;
                            *offset = 0;
                            sent += 1;
                            last_send = Some(Instant::now());
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        held.close("io_error", Some(e.to_string()), started);
                        errors += 1;
                        break;
                    }
                }
            }
        }
        if !pending {
            return (sent, errors, last_send);
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn input_block_root_flood(ctx: &Ctx, args: &RootFloodArgs) -> bool {
    let seed = 0x4d61_7472_6978_0002;
    let started = Instant::now();
    let started_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let mut sockets_open_ms = None;
    let mut conns = Vec::new();
    let mut connections = Vec::new();
    let mut wave_results = Vec::new();
    let mut last_send = None;
    let mut hold_end = None;
    for wave in 0..args.waves {
        if wave == 0 || args.hold.is_none() {
            for h in 0..args.hosts {
                let k = (u32::from(args.first)
                    + u32::from(h)
                    + if args.hold.is_none() {
                        u32::from(wave) * u32::from(args.hosts)
                    } else {
                        0
                    }) as u8;
                let opening = tokio::time::timeout(
                    Duration::from_secs(10),
                    Conn::open_as(src(k), ctx.target, ctx.magic, SUBBLOCKS_PEER_VERSION),
                );
                tokio::pin!(opening);
                let opened = loop {
                    tokio::select! {
                        result = &mut opening => break result.unwrap_or_else(|_| {
                            Err(std::io::Error::new(std::io::ErrorKind::TimedOut,
                                "connect/handshake timed out"))
                        }),
                        _ = drain_held(&mut conns, Instant::now() + Duration::from_millis(10), started) => (),
                    }
                };
                match opened {
                    Ok(conn) => conns.push(HeldConn {
                        conn,
                        closure: None,
                    }),
                    Err(e) => connections.push(serde_json::json!({
                        "source": src(k).to_string(), "opened": false, "survived": false,
                        "closure": {"kind": "open_error", "error": e.to_string(),
                                    "observed_ms": started.elapsed().as_millis()}
                    })),
                }
            }
        }
        if wave == 0 {
            sockets_open_ms = Some(started.elapsed().as_millis());
        }
        // Height lookups must not stop the readers either.
        let height_read = height(&ctx.api);
        tokio::pin!(height_read);
        let current_height = loop {
            tokio::select! {
                value = &mut height_read => break value,
                _ = drain_held(&mut conns, Instant::now() + Duration::from_millis(10), started) => (),
            }
        };
        let (sent, write_errors, sent_at) = if let Some(height) = current_height {
            let frames: Vec<Vec<Vec<u8>>> = conns
                .iter()
                .map(|held| {
                    (0..args.per_host)
                        .map(|i| {
                            let n = args.announcement_index(held.conn.src.octets()[1], wave, i);
                            let payload =
                                bogus_announcement(seed, n, height as u32 + 2, draw(seed, 9, n));
                            full_frame(&ctx.magic, CODE_INPUT_BLOCK, &payload)
                        })
                        .collect()
                })
                .collect();
            // Send a host's full burst before the next host so the per-host
            // cap is exercised before global fairness redistributes capacity.
            // Reads on ALL sockets still progress during each bounded write.
            let mut sent = 0;
            let mut errors = 0;
            let mut last = None;
            for (index, host_frames) in frames.into_iter().enumerate() {
                let mut batch = vec![Vec::new(); conns.len()];
                batch[index] = host_frames;
                let (n, e, at) =
                    send_held(&mut conns, &batch, Duration::from_secs(5), started).await;
                sent += n;
                errors += e;
                if at.is_some() {
                    last = at;
                }
            }
            (sent, errors, last)
        } else {
            (0, 0, None)
        };
        if sent_at.is_some() {
            last_send = sent_at;
        }
        wave_results.push(serde_json::json!({"wave": wave, "sent": sent,
            "write_errors": write_errors, "height_observed": current_height.is_some()}));
        if args.hold.is_none() {
            drain_held(
                &mut conns,
                Instant::now() + Duration::from_millis(500),
                started,
            )
            .await;
            record_connections(&mut conns, &mut connections);
        }
        if wave + 1 < args.waves {
            drain_held(&mut conns, Instant::now() + args.interval, started).await;
        }
    }
    if let (Some(hold), Some(last)) = (args.hold, last_send) {
        let end = last + hold;
        drain_held(&mut conns, end, started).await;
        hold_end = Some(end.duration_since(started).as_millis());
    }
    record_connections(&mut conns, &mut connections);
    let after = height(&ctx.api).await;
    // No early closures are allowed: rejection is evidence, but cannot prove
    // a store was exercised by the configured sustained held experiment.
    let ok = after.is_some()
        && wave_results
            .iter()
            .all(|w| w["sent"] == u32::from(args.hosts) * args.per_host && w["write_errors"] == 0)
        && connections
            .iter()
            .all(|c| c["opened"] == true && (args.hold.is_none() || c["survived"] == true));
    let counts = serde_json::json!({
        "opened": connections.iter().filter(|c| c["opened"] == true).count(),
        "survived": connections.iter().filter(|c| c["survived"] == true).count(),
        "eof": connections.iter().filter(|c| c["closure"]["kind"] == "eof").count(),
        "io_error": connections.iter().filter(|c| c["closure"]["kind"] == "io_error").count(),
        "open_error": connections.iter().filter(|c| c["closure"]["kind"] == "open_error").count(),
    });
    println!(
        "ROOT_FLOOD_RESULT {}",
        serde_json::json!({
            "ok": ok, "waves": wave_results, "connections": connections, "connection_counts": counts,
            "started_unix_ms": started_unix_ms, "sockets_open_ms": sockets_open_ms,
            "last_send_ms": last_send.map(|t| t.duration_since(started).as_millis()),
            "hold_end_ms": hold_end,
            "finished_ms": started.elapsed().as_millis(),
            "started_monotonic_note": "all milliseconds relative to adversary start"
        })
    );
    ok
}

fn record_connections(conns: &mut Vec<HeldConn>, results: &mut Vec<serde_json::Value>) {
    for held in conns.drain(..) {
        results.push(serde_json::json!({"source": held.conn.src.to_string(),
            "opened": true, "survived": held.closure.is_none(), "closure": held.closure}));
    }
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
        "input_block_wrong_body" => {
            let secs: u64 = rest.first().map_or(600, |s| s.parse().unwrap());
            input_block_wrong_body(&ctx, secs).await
        }
        "input_block_flood" => {
            let a: u32 = rest.first().map_or(10_000, |s| s.parse().unwrap());
            let d: u32 = rest.get(1).map_or(1_000, |s| s.parse().unwrap());
            input_block_flood(&ctx, a, d).await
        }
        "input_block_root_flood" => match RootFloodArgs::parse(rest) {
            Ok(args) => input_block_root_flood(&ctx, &args).await,
            Err(e) => {
                eprintln!("input_block_root_flood: {e}");
                std::process::exit(2);
            }
        },
        other => {
            eprintln!("unknown scenario: {other}");
            std::process::exit(2);
        }
    };

    let h_after = height(&ctx.api).await;
    println!("[node] fullHeight after: {h_after:?}");
    println!("[result] {scenario}: {}", if ok { "PASS" } else { "FAIL" });
    if !ok {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    async fn socket_pair() -> (HeldConn, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        (
            HeldConn {
                conn: Conn {
                    stream: client,
                    magic: [0; 4],
                    buf: Vec::new(),
                    src: Ipv4Addr::LOCALHOST,
                },
                closure: None,
            },
            peer,
        )
    }

    // ----- happy path -----

    #[test]
    fn root_flood_args_positionals_only_keep_the_hit_and_run_defaults() {
        let parsed = RootFloodArgs::parse(&args(&["10", "40", "12", "20000", "100"])).unwrap();
        assert_eq!(
            parsed,
            RootFloodArgs {
                hosts: 10,
                per_host: 40,
                waves: 12,
                interval: Duration::from_millis(20_000),
                first: 100,
                hold: None,
            }
        );
        assert_eq!(parsed.hosts_needed(), 120);
        let defaults = RootFloodArgs::parse(&[]).unwrap();
        assert_eq!(
            (
                defaults.hosts,
                defaults.per_host,
                defaults.waves,
                defaults.first
            ),
            (10, 40, 10, 100)
        );
        assert_eq!(defaults.interval, Duration::from_millis(15_000));
        assert_eq!(defaults.hold, None);
    }

    #[test]
    fn root_flood_args_hold_ms_selects_held_mode_with_one_host_set() {
        let parsed = RootFloodArgs::parse(&args(&[
            "10",
            "160",
            "12",
            "20000",
            "100",
            "--hold-ms",
            "130000",
        ]))
        .unwrap();
        assert_eq!(parsed.hold, Some(Duration::from_millis(130_000)));
        assert_eq!(parsed.per_host, 160);
        // The same ten hosts carry every wave.
        assert_eq!(parsed.hosts_needed(), 10);
        // The flag may also precede the positionals.
        let early = RootFloodArgs::parse(&args(&["--hold-ms", "5", "3"])).unwrap();
        assert_eq!(early.hold, Some(Duration::from_millis(5)));
        assert_eq!(early.hosts, 3);
    }

    #[test]
    fn root_flood_announcement_index_held_host_never_repeats_across_waves() {
        let held =
            RootFloodArgs::parse(&args(&["2", "160", "12", "1", "100", "--hold-ms", "1"])).unwrap();
        let mut seen = std::collections::HashSet::new();
        for wave in 0..12 {
            for i in 0..160 {
                assert!(seen.insert(held.announcement_index(100, wave, i)));
            }
        }
        // Another host's indices are disjoint from this one's.
        assert!(!seen.contains(&held.announcement_index(101, 0, 0)));
        // Hit-and-run keeps the index it always had: `(k << 16) | i`.
        let fresh = RootFloodArgs::parse(&args(&["2", "40", "3"])).unwrap();
        assert_eq!(fresh.announcement_index(105, 2, 7), (105 << 16) | 7);
    }

    #[test]
    fn root_flood_address_last_valid_accepts_and_counts_validate() {
        assert!(RootFloodArgs::parse(&args(&["1", "1", "1", "0", "255"])).is_ok());
        assert!(
            RootFloodArgs::parse(&args(&["1", "1", "1", "0", "255", "--hold-ms", "1"])).is_ok()
        );
        assert!(RootFloodArgs::parse(&args(&["2", "1", "1", "0", "255"])).is_err());
        for invalid in [&["0"][..], &["1", "0"], &["1", "1", "0"]] {
            assert!(RootFloodArgs::parse(&args(invalid)).is_err());
        }
    }

    #[tokio::test]
    async fn held_continuous_input_other_eof_observed_within_deadline() {
        let (busy, mut producer) = socket_pair().await;
        let (quiet, peer) = socket_pair().await;
        let task = tokio::spawn(async move {
            let buf = [1u8; 65536];
            while producer.write_all(&buf).await.is_ok() {}
        });
        drop(peer);
        let mut conns = vec![busy, quiet];
        let start = Instant::now();
        drain_held(&mut conns, start + Duration::from_millis(80), start).await;
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(conns[1].closure.as_ref().unwrap()["kind"], "eof");
        task.abort();
        let _ = task.await;
    }

    // The premise is that a peer which never reads eventually fills the
    // kernel's socket buffers and blocks the writer. Windows loopback
    // accepts the whole 32 MiB write at once, so the timeout path is not
    // reachable there; the devnet harness runs this tool on Linux only.
    #[tokio::test]
    #[cfg_attr(
        windows,
        ignore = "Windows loopback buffers the whole write, so a non-reading peer cannot block it"
    )]
    async fn held_nonreading_peer_write_times_out_other_socket_progresses() {
        let (blocked, _peer) = socket_pair().await;
        let (other, mut reader) = socket_pair().await;
        let read = tokio::spawn(async move {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [42]);
        });
        let mut conns = vec![blocked, other];
        let frames = vec![vec![vec![1; 32 * 1024 * 1024]], vec![vec![42]]];
        let start = Instant::now();
        let (sent, errors, _) =
            send_held(&mut conns, &frames, Duration::from_millis(100), start).await;
        assert_eq!((sent, errors), (1, 1));
        assert_eq!(conns[1].closure.as_ref().unwrap()["kind"], "eof");
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(
            conns[0].closure.as_ref().unwrap()["error"],
            "wave write timed out"
        );
        tokio::time::timeout(Duration::from_secs(1), read)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn held_absolute_deadline_does_not_restart_hold_or_count_late_close() {
        let (held, peer) = socket_pair().await;
        let mut conns = vec![held];
        let last_send = Instant::now();
        let deadline = last_send + Duration::from_millis(150);
        // Work after the last send consumes hold time; it does not extend it.
        tokio::time::sleep(Duration::from_millis(60)).await;
        drain_held(&mut conns, deadline, last_send).await;
        assert!(Instant::now() >= deadline);
        assert!(last_send.elapsed() < Duration::from_millis(200));
        assert!(conns[0].closure.is_none());
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline + Duration::from_millis(30),
        ))
        .await;
        drop(peer);
        // Even when invoked again, an expired deadline never reads a late EOF.
        drain_held(&mut conns, deadline, last_send).await;
        assert!(conns[0].closure.is_none());
        drain_held(
            &mut conns,
            Instant::now() + Duration::from_millis(30),
            last_send,
        )
        .await;
        assert_eq!(conns[0].closure.as_ref().unwrap()["kind"], "eof");
    }

    // ----- error paths -----

    #[test]
    fn root_flood_args_bad_hold_ms_errors() {
        for bad in [
            &["--hold-ms"][..],
            &["--hold-ms", "soon"][..],
            &["--hold-ms", "0"][..],
        ] {
            assert!(RootFloodArgs::parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn root_flood_args_extra_or_malformed_positionals_error() {
        assert!(RootFloodArgs::parse(&args(&["1", "2", "3", "4", "5", "6"])).is_err());
        assert!(RootFloodArgs::parse(&args(&["300"])).is_err());
        // A held host's announcements must stay distinct across waves.
        assert!(
            RootFloodArgs::parse(&args(&["1", "10000", "7", "1", "100", "--hold-ms", "1"]))
                .is_err()
        );
    }
}
