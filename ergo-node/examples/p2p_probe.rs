//! Minimal P2P RequestModifier probe (read-only against a running node).
//!
//! Handshakes with a target Ergo node exactly the way the node itself does
//! (raw, unframed handshake bytes — see `peer_loop::do_handshake`), then
//! sends RequestModifier (code 22) frames for caller-supplied ids and prints
//! every inbound frame (code + byte count), so we can empirically confirm
//! serve behavior.
//!
//! Usage:
//!   cargo run --example p2p_probe -- <host:port> <testnet|mainnet> <mode> [args...] [--secs N]
//!
//! Modes:
//!   req <type_id> <hex_id>...     one RequestModifier(type_id) for the given ids
//!   header_n <hex_id> <n>         one RequestModifier(type=101) repeating <hex_id> n times
//!   burst <type_id> <hex_id> <n>  n separate 1-id RequestModifier frames sent back-to-back
//!
//! Read-only: issues only a handshake + RequestModifier traffic, never mutates.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ergo_p2p::framing::{deserialize_frame, serialize_frame, MessageFrame};
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, DeclaredAddress, Handshake,
    HandshakeError, PeerSpec, Version,
};
use ergo_p2p::message;
use ergo_p2p::types::InvData;
use ergo_primitives::reader::ReadError;

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s.trim()).expect("hex");
    assert_eq!(v.len(), 32, "id must be 32 bytes: {s}");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn code_name(c: u8) -> &'static str {
    match c {
        1 => "GetPeers",
        2 => "Peers",
        22 => "RequestModifier",
        33 => "Modifiers",
        55 => "Inv",
        65 => "SyncInfo",
        75 => "Handshake",
        76 => "GetSnapshotsInfo",
        77 => "SnapshotsInfo",
        78 => "GetManifest",
        79 => "Manifest",
        80 => "GetUtxoChunk",
        81 => "UtxoChunk",
        90 => "GetNipopowProof",
        91 => "NipopowProof",
        _ => "?",
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: p2p_probe <host:port> <testnet|mainnet> <mode> [args...] [--secs N]\n\
         modes:\n\
         \x20 req <type_id> <hex_id>...     one RequestModifier(type_id) for the given ids\n\
         \x20 header_n <hex_id> <n>         one RequestModifier(type=101) repeating <hex_id> n times\n\
         \x20 burst <type_id> <hex_id> <n>  n separate 1-id RequestModifier frames back-to-back"
    );
    std::process::exit(2);
}

fn main() {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();

    // pull optional --secs N
    let mut secs = 15u64;
    if let Some(pos) = raw.iter().position(|a| a == "--secs") {
        secs = raw[pos + 1].parse().expect("secs");
        raw.drain(pos..pos + 2);
    }

    if raw.len() < 3 {
        usage();
    }
    let addr = raw[0].clone();
    let net = raw[1].clone();
    // Authoritative magic from ergo-chain-spec (what the live node frames
    // with). NB: ergo_p2p::framing::TESTNET_MAGIC ([2,0,2,3]) is the STALE
    // old-PaiNet value and will NOT match a running testnet node — the node
    // uses `chain_spec.network_params.magic` = [2,3,2,3].
    // NB2: from loopback the node's per-IP inbound limit (=1) rejects a
    // second 127.0.0.1 connection; bind the source to a distinct loopback IP
    // (e.g. 127.0.0.2) — this std-only example cannot bind the source, so run
    // it from a host whose 127.0.0.1 slot is free, or use a socket2 variant.
    let magic: [u8; 4] = if net == "mainnet" {
        [1, 0, 2, 4]
    } else {
        [2, 3, 2, 3]
    };
    let mode = raw[2].clone();
    let margs = &raw[3..];

    // Build the request frame(s) for this mode.
    // Each entry is a full RequestModifier payload (one frame).
    let frames: Vec<Vec<u8>> = match mode.as_str() {
        "req" => {
            if margs.len() < 2 {
                usage();
            }
            let type_id: u8 = margs[0].parse().expect("type_id");
            let ids: Vec<[u8; 32]> = margs[1..].iter().map(|s| hex32(s)).collect();
            match message::serialize_inv(&InvData { type_id, ids }) {
                Ok(p) => vec![p],
                Err(e) => {
                    eprintln!("[probe] serialize_inv FAILED: {e}");
                    Vec::new()
                }
            }
        }
        "header_n" => {
            if margs.len() < 2 {
                usage();
            }
            let id = hex32(&margs[0]);
            let n: usize = margs[1].parse().unwrap();
            let ids = vec![id; n];
            match message::serialize_inv(&InvData { type_id: 101, ids }) {
                Ok(p) => vec![p],
                Err(e) => {
                    eprintln!("[probe] serialize_inv FAILED for n={n}: {e}");
                    Vec::new()
                }
            }
        }
        "burst" => {
            if margs.len() < 3 {
                usage();
            }
            let type_id: u8 = margs[0].parse().expect("type_id");
            let id = hex32(&margs[1]);
            let n: usize = margs[2].parse().unwrap();
            (0..n)
                .map(|_| {
                    message::serialize_inv(&InvData {
                        type_id,
                        ids: vec![id],
                    })
                    .unwrap()
                })
                .collect()
        }
        _ => usage(),
    };
    eprintln!(
        "[probe] mode={mode} → {} RequestModifier frame(s), first payload {} bytes",
        frames.len(),
        frames.first().map(|f| f.len()).unwrap_or(0)
    );

    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();

    // --- handshake: RAW bytes, no frame wrapper (matches peer_loop::do_handshake) ---
    let hs = Handshake {
        time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        peer_spec: PeerSpec {
            agent_name: "ergoref".into(),
            version: Version {
                major: 6,
                minor: 0,
                patch: 2,
            },
            node_name: "p2p-probe".into(),
            declared_address: Some(DeclaredAddress {
                addr: vec![127, 0, 0, 1],
                port: 65000,
            }),
            features: vec![],
        },
    };
    let hs_bytes = serialize_handshake(&hs);
    stream.write_all(&hs_bytes).unwrap();
    eprintln!("[probe] sent raw handshake ({} bytes)", hs_bytes.len());

    // Read the peer handshake first (raw), keep any trailing framed bytes.
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 65536];
    let hs_deadline = Instant::now() + Duration::from_secs(5);
    let leftover: Vec<u8>;
    loop {
        if Instant::now() > hs_deadline {
            eprintln!("[probe] FAILED: no handshake within 5s");
            return;
        }
        match stream.read(&mut tmp) {
            Ok(0) => {
                eprintln!("[probe] peer closed during handshake");
                return;
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("[probe] read err during handshake: {e}");
                return;
            }
        }
        match deserialize_handshake_with_consumed(&buf) {
            Ok((peer_hs, consumed)) => {
                eprintln!(
                    "[probe] <== HANDSHAKE ok: agent={:?} version={:?} node={:?}",
                    peer_hs.peer_spec.agent_name,
                    peer_hs.peer_spec.version,
                    peer_hs.peer_spec.node_name
                );
                leftover = buf[consumed..].to_vec();
                break;
            }
            // Only a short-buffer read is retryable — more bytes may
            // still be in flight. Any other parse error is a real
            // protocol failure and retrying would just mask it.
            Err(HandshakeError::Read(ReadError::UnexpectedEnd { .. })) => continue,
            Err(e) => {
                eprintln!("[probe] handshake parse err: {e}");
                return;
            }
        }
    }

    // --- send the request frame(s) ---
    if frames.is_empty() {
        eprintln!("[probe] no frames to send — done");
        return;
    }
    let send_start = Instant::now();
    for (i, p) in frames.iter().enumerate() {
        let f = serialize_frame(
            &magic,
            &MessageFrame {
                code: message::CODE_REQUEST_MODIFIER,
                payload: p.clone(),
            },
        );
        if let Err(e) = stream.write_all(&f) {
            eprintln!("[probe] write err on frame {i}: {e}");
            break;
        }
    }
    eprintln!(
        "[probe] sent {} RequestModifier frame(s) in {:?}",
        frames.len(),
        send_start.elapsed()
    );

    // --- read loop ---
    let mut buf = leftover;
    let start = Instant::now();
    let mut modifier_bytes_total = 0usize;
    let mut modifier_frames = 0usize;
    let mut total_entries = 0usize;
    let mut peer_closed = false;
    while start.elapsed() < Duration::from_secs(secs) {
        match stream.read(&mut tmp) {
            Ok(0) => {
                eprintln!("[probe] peer CLOSED connection at {:?}", start.elapsed());
                peer_closed = true;
                break;
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("[probe] read err: {e}");
                break;
            }
        }
        loop {
            match deserialize_frame(&magic, &buf) {
                Ok(Some((frame, consumed))) => {
                    let plen = frame.payload.len();
                    eprintln!(
                        "[probe] <== code {:>3} {:<16} payload {} bytes",
                        frame.code,
                        code_name(frame.code),
                        plen
                    );
                    if frame.code == message::CODE_MODIFIER {
                        modifier_bytes_total += plen;
                        modifier_frames += 1;
                        match message::deserialize_modifiers(&frame.payload) {
                            Ok(m) => {
                                total_entries += m.modifiers.len();
                                let sample: Vec<String> = m
                                    .modifiers
                                    .iter()
                                    .take(6)
                                    .map(|(id, b)| {
                                        format!("{}:{}B", &hex::encode(id)[..8], b.len())
                                    })
                                    .collect();
                                eprintln!(
                                    "        Modifiers type_id={} entries={} sample={:?}",
                                    m.type_id,
                                    m.modifiers.len(),
                                    sample
                                );
                            }
                            Err(e) => {
                                eprintln!("        Modifiers DECODE FAILED ({plen}B payload): {e}");
                            }
                        }
                    }
                    buf.drain(..consumed);
                }
                Ok(None) => break,
                Err(e) => {
                    eprintln!(
                        "[probe] frame parse err: {e} (buf {} bytes) — clearing",
                        buf.len()
                    );
                    buf.clear();
                    break;
                }
            }
        }
    }
    eprintln!(
        "[probe] DONE mode={mode} modifier_frames={modifier_frames} entries={total_entries} \
         modifier_bytes_total={modifier_bytes_total} peer_closed={peer_closed}"
    );
}
