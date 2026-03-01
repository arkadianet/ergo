//! Live integration test: connect to an Ergo peer and handshake.
//! Requires network access. Run with: cargo test -p ergo-testkit --test live_handshake -- --ignored
//!
//! IMPORTANT: The handshake is sent as RAW BYTES without the standard message frame.
//! The message frame (magic + code + length + checksum + body) is only used for
//! regular messages AFTER the handshake completes.
//!
//! Testnet seed peers (port 9022): 213.239.193.208, 168.138.185.215, 192.234.196.165
//! Mainnet seed peers (port 9030): 213.239.193.208, 159.65.11.55, 165.227.26.175

use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
use ergo_wire::peer_feature::{ModeFeature, PeerFeature, SessionFeature, StateTypeCode};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

fn build_handshake(magic: [u8; 4]) -> Handshake {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    Handshake {
        time: now,
        peer_spec: PeerSpec {
            agent_name: "ergoref".to_string(),
            protocol_version: ProtocolVersion {
                major: 5,
                minor: 0,
                patch: 12,
            },
            node_name: "ergo-rust-handshake-test".to_string(),
            declared_address: None,
            features: vec![
                PeerFeature::Mode(ModeFeature {
                    state_type: StateTypeCode::Utxo,
                    verifying_transactions: true,
                    nipopow_bootstrapped: None,
                    blocks_to_keep: -1,
                }),
                PeerFeature::Session(SessionFeature {
                    network_magic: magic,
                    session_id: rand_session_id(),
                }),
            ],
        },
    }
}

fn rand_session_id() -> i64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(42);
    h.finish() as i64
}

async fn try_handshake(peer_addr: &str, magic: [u8; 4]) -> Result<Handshake, String> {
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(peer_addr))
        .await
        .map_err(|_| format!("{peer_addr}: connection timeout"))?
        .map_err(|e| format!("{peer_addr}: {e}"))?;

    // Handshake is sent as RAW BYTES - no message frame wrapping
    let hs = build_handshake(magic);
    let raw_bytes = hs.serialize();

    stream
        .write_all(&raw_bytes)
        .await
        .map_err(|e| format!("{peer_addr}: send failed: {e}"))?;

    // Read response - peer also sends raw handshake bytes (no frame)
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(15), stream.read(&mut buf))
        .await
        .map_err(|_| format!("{peer_addr}: read timeout"))?
        .map_err(|e| format!("{peer_addr}: read failed: {e}"))?;

    if n == 0 {
        return Err(format!("{peer_addr}: peer sent no data"));
    }

    println!("  Received {n} bytes: {:02x?}", &buf[..n.min(64)]);

    // Parse raw handshake bytes directly (no frame decoding)
    Handshake::parse(&buf[..n])
        .map_err(|e| format!("{peer_addr}: handshake parse error: {e} (got {n} bytes)"))
}

#[tokio::test]
#[ignore] // requires network access
async fn handshake_with_ergo_peer() {
    const TESTNET_MAGIC: [u8; 4] = [2, 0, 0, 1];
    const MAINNET_MAGIC: [u8; 4] = [1, 0, 2, 4];

    // Try testnet peers first (port 9022), then mainnet peers (port 9030)
    let peers: Vec<(&str, [u8; 4])> = vec![
        ("213.239.193.208:9022", TESTNET_MAGIC),
        ("168.138.185.215:9022", TESTNET_MAGIC),
        ("192.234.196.165:9022", TESTNET_MAGIC),
        ("213.239.193.208:9030", MAINNET_MAGIC),
        ("159.65.11.55:9030", MAINNET_MAGIC),
        ("165.227.26.175:9030", MAINNET_MAGIC),
    ];

    let mut errors = Vec::new();
    for (addr, magic) in &peers {
        println!("Trying {addr}...");
        match try_handshake(addr, *magic).await {
            Ok(peer_hs) => {
                println!("Handshake successful with {addr}!");
                println!("  Agent: {}", peer_hs.peer_spec.agent_name);
                println!(
                    "  Version: {}.{}.{}",
                    peer_hs.peer_spec.protocol_version.major,
                    peer_hs.peer_spec.protocol_version.minor,
                    peer_hs.peer_spec.protocol_version.patch
                );
                println!("  Node name: {}", peer_hs.peer_spec.node_name);
                println!("  Features: {}", peer_hs.peer_spec.features.len());
                assert!(!peer_hs.peer_spec.agent_name.is_empty());
                return; // success
            }
            Err(e) => {
                println!("  Failed: {e}");
                errors.push(e);
            }
        }
    }

    panic!(
        "Could not handshake with any peer. Errors:\n{}",
        errors.join("\n")
    );
}
