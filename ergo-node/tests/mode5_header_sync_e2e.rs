//! Mode 5 (digest verifier) header sync driven by a real P2P peer.
//!
//! `mode_runtime_gate.rs::mode_5_survives_a_sync_tick` boots a PEERLESS
//! digest node: it proves the sync tick survives, but the node never
//! receives a modifier, so the header pipeline is never entered. This
//! test closes that gap end-to-end — the node dials a listener the test
//! owns, the test handshakes as a peer, advertises the genesis header,
//! serves it when the node asks, and the node's header tip must advance.
//!
//! Everything on the wire here is production code on both sides: the
//! node's real outbound dial, `ergo_p2p::Connection` framing, and the
//! canonical mainnet header bytes from `test-vectors/mainnet`.

#[allow(dead_code)]
mod common;

use std::time::Duration;

use ergo_node::run_inner;
use ergo_p2p::connection::Connection;
use ergo_p2p::framing::MAINNET_MAGIC;
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, Handshake, PeerSpec, Version,
};
use ergo_p2p::message::{
    deserialize_inv, serialize_inv, serialize_modifiers, CODE_MODIFIER, CODE_REQUEST_MODIFIER,
};
use ergo_p2p::types::{InvData, ModifierTypeId, ModifiersData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Bound on every wire wait. Generous relative to the node's 1 s sync
/// cadence so a slow CI box doesn't flake, short enough that a genuine
/// regression fails instead of hanging the suite.
const WIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// Canonical mainnet header 1 (genesis) — bytes + id — from the shared
/// fixture the header-pipeline tests already use.
fn mainnet_genesis_header() -> (Vec<u8>, [u8; 32]) {
    let raw = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json")
        .expect("read headers_1_10.json");
    let headers: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("parse headers");
    let h = headers
        .iter()
        .find(|h| h["height"].as_u64() == Some(1))
        .expect("height 1 in fixture");
    let bytes = hex::decode(h["bytes"].as_str().expect("bytes")).expect("header bytes hex");
    let id: [u8; 32] = hex::decode(h["id"].as_str().expect("id"))
        .expect("id hex")
        .try_into()
        .expect("32-byte header id");
    (bytes, id)
}

/// Exchange handshakes with a freshly-dialed node. Ergo sends the
/// handshake as RAW bytes (no magic / code / length framing), and the
/// same TCP read can already carry the start of the first framed
/// message — so the leftover bytes seed the `Connection` read buffer,
/// exactly as `peer_loop::do_handshake` does on the production side.
async fn exchange_handshake(mut stream: TcpStream) -> Connection {
    stream
        .write_all(&test_peer_handshake())
        .await
        .expect("send peer handshake");

    let mut buf = vec![0u8; 16384];
    let mut total = 0usize;
    loop {
        let n = stream
            .read(&mut buf[total..])
            .await
            .expect("read node handshake");
        assert!(n > 0, "node closed the connection during handshake");
        total += n;
        if let Ok((_hs, consumed)) = deserialize_handshake_with_consumed(&buf[..total]) {
            let leftover = buf[consumed..total].to_vec();
            return Connection::new_with_buffer(stream, MAINNET_MAGIC, leftover);
        }
    }
}

fn test_peer_handshake() -> Vec<u8> {
    serialize_handshake(&Handshake {
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64,
        peer_spec: PeerSpec {
            agent_name: "ergo-mode5-test-peer".into(),
            version: Version::CURRENT,
            node_name: "mode5-test-peer".into(),
            declared_address: None,
            features: Vec::new(),
        },
    })
}

#[tokio::test]
async fn mode_5_syncs_a_header_from_a_real_peer() {
    // Regression for the Mode 5 first-inbound-header abort: the executor's
    // header pipeline unwrapped the backend to a UTXO `StateStore`, so the
    // first header a digest node received aborted the action loop. Nothing
    // caught it because no Mode 5 test ever delivered a header.
    //
    // A digest node must complete header sync exactly as a UTXO node does:
    // Mode 5 derives its state root from ADProofs, but the header chain
    // (PoW, difficulty, fork choice) is backend-independent.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = listener.local_addr().expect("peer addr");

    let data_dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = common::make_test_config(data_dir.path().to_path_buf());
    cfg.state_type = ergo_node::config::StateType::Digest;
    // The digest backend has no box store, so the loader/runtime disable
    // the mempool; a programmatic config must mirror that.
    cfg.mempool_config.enabled = false;
    // The node dials its known peers at boot — point it at this test.
    cfg.known_peers = vec![peer_addr];
    let handle = run_inner(cfg).await.expect("canonical Mode 5 must boot");

    let (sock, _) = timeout(WIRE_TIMEOUT, listener.accept())
        .await
        .expect("node must dial its known peer")
        .expect("accept");
    let mut conn = timeout(WIRE_TIMEOUT, exchange_handshake(sock))
        .await
        .expect("handshake timed out");

    // Advertise the genesis header and serve it when the node asks. The
    // coordinator only routes DELIVERED modifiers it actually requested,
    // so the Inv → RequestModifier → Modifier round trip is mandatory.
    let (header_bytes, header_id) = mainnet_genesis_header();
    let inv = serialize_inv(&InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![header_id],
    })
    .expect("serialize inv");
    conn.send(ergo_p2p::message::CODE_INV, inv)
        .await
        .expect("send inv");

    // Drain frames until the node requests the advertised header. Other
    // traffic (SyncInfo, GetPeers, …) is expected and ignored.
    loop {
        let frame = timeout(WIRE_TIMEOUT, conn.read_message())
            .await
            .expect("node never requested the advertised header")
            .expect("read frame");
        if frame.code == CODE_REQUEST_MODIFIER {
            let req = deserialize_inv(&frame.payload).expect("parse RequestModifier");
            if req.type_id == ModifierTypeId::Header.as_byte() && req.ids.contains(&header_id) {
                break;
            }
        }
    }

    let modifiers = serialize_modifiers(&ModifiersData {
        type_id: ModifierTypeId::Header.as_byte(),
        modifiers: vec![(header_id, header_bytes)],
    })
    .expect("serialize modifiers");
    conn.send(CODE_MODIFIER, modifiers)
        .await
        .expect("send header modifier");

    // The API read snapshot refreshes on the 1 s sync tick; poll it until
    // the header tip reflects the delivered header.
    let deadline = std::time::Instant::now() + WIRE_TIMEOUT;
    let mut tip = handle.read.tip();
    while tip.best_header.height < 1 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        tip = handle.read.tip();
    }
    assert_eq!(
        tip.best_header.height, 1,
        "Mode 5 header tip must advance on a peer-delivered header",
    );
    assert_eq!(
        tip.best_header.header_id,
        hex::encode(header_id),
        "header tip must be the header the peer delivered",
    );

    handle
        .shutdown()
        .await
        .expect("Mode-5 action loop must survive an inbound header");
}
