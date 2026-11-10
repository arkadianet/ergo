//! End-to-end loopback test: a fake legacy peer completes the raw handshake,
//! announces one header via `Inv`, answers our `RequestModifier`, and the
//! observer writes the expected JSONL record sequence.
//!
//! This exercises the real framing, session state machine, request rate
//! limiting, and sink — no network access.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ergo_net_observe::session::{run_session, SessionConfig, SharedSeen};
use ergo_net_observe::sink::{ObserverSink, SinkConfig};
use ergo_p2p::connection::Connection;
use ergo_p2p::framing::MAINNET_MAGIC;
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, Handshake, PeerSpec, Version,
};
use ergo_p2p::message::{
    self, serialize_inv, serialize_modifiers, CODE_GET_PEERS, CODE_INV, CODE_MODIFIER,
    CODE_REQUEST_MODIFIER, CODE_SYNC_INFO,
};
use ergo_p2p::types::{InvData, ModifierTypeId, ModifiersData};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{header_id_from_bytes, read_header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Mainnet genesis header bytes (same fixture the codec tests use).
const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

#[tokio::test]
async fn inv_announce_to_section_receive_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.jsonl");
    let sink = ObserverSink::spawn(SinkConfig::new(&path, "loopback")).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let header_bytes = hex::decode(GENESIS_HEX).unwrap();
    let header_id = header_id_from_bytes(&header_bytes).unwrap();
    let expected_height = read_header(&mut VlqReader::new(&header_bytes))
        .expect("fixture header parses")
        .height;
    let mut announced = [0u8; 32];
    announced.copy_from_slice(header_id.as_bytes());

    let peer = tokio::spawn(fake_peer(listener, header_bytes, announced));

    let cfg = Arc::new(SessionConfig {
        magic: MAINNET_MAGIC,
        network: "mainnet".to_string(),
        agent_name: "ergo-rust-observer-test".to_string(),
        node_name: "observer-loopback".to_string(),
        protocol_version: Version::CURRENT,
        request_headers: true,
        request_bodies: false,
        request_txs: false,
        request_interval: Duration::ZERO,
        max_outstanding: 4,
        max_ids_per_request: 8,
        idle_timeout: Duration::from_secs(5),
        request_handshake_timeout: Duration::from_secs(5),
        ..SessionConfig::default()
    });
    let shared = Arc::new(Mutex::new(SharedSeen::default()));

    let stream = TcpStream::connect(addr).await.unwrap();
    run_session(stream, addr, cfg, sink.clone(), shared, None).await;
    peer.await.unwrap();

    // Let the sink's idle flush land.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let text = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let names: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();

    assert!(names.contains(&"handshake_ok"), "{names:?}");
    assert!(names.contains(&"announce"), "{names:?}");
    assert!(names.contains(&"request_sent"), "{names:?}");
    assert!(names.contains(&"section_received"), "{names:?}");
    assert!(names.contains(&"rtt"), "{names:?}");
    assert!(names.contains(&"disconnect"), "{names:?}");

    let announce = events.iter().find(|e| e["event"] == "announce").unwrap();
    assert_eq!(announce["via"], "inv");
    assert_eq!(announce["type_id"], 101);
    assert_eq!(announce["first_global"], 1);

    let section = events
        .iter()
        .find(|e| e["event"] == "section_received")
        .unwrap();
    assert_eq!(section["type_id"], 101);
    assert_eq!(section["id"], hex::encode(announced));
    assert_eq!(section["height"], expected_height);
    assert_eq!(section["id_matches"], true);
    assert_eq!(section["solicited"], true);

    // Peer addresses are pseudonymised: the record must not contain the
    // loopback socket address.
    assert!(!text.contains(&addr.to_string()), "{text}");

    // Sanity: the ledger we emit is really the schema we claim.
    assert!(events.iter().all(|e| e["schema"] == "ergo-observer/1"));
}

async fn fake_peer(listener: TcpListener, header_bytes: Vec<u8>, header_id: [u8; 32]) {
    let (mut stream, _) = listener.accept().await.unwrap();

    // Raw, unframed handshake from the observer.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let consumed = loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "observer closed before handshake");
        buf.extend_from_slice(&tmp[..n]);
        assert!(buf.len() <= 8096, "handshake exceeded 8096 bytes");
        if let Ok((hs, consumed)) = deserialize_handshake_with_consumed(&buf) {
            assert_eq!(hs.peer_spec.agent_name, "ergo-rust-observer-test");
            assert!(hs.peer_spec.features.is_empty());
            break consumed;
        }
    };
    let leftover = buf[consumed..].to_vec();

    // Reply with an honest reference-style handshake.
    let ours = Handshake {
        time: 1_700_000_000_000,
        peer_spec: PeerSpec {
            agent_name: "ergo-ref-loopback".to_string(),
            version: Version::CURRENT,
            node_name: "fake-peer".to_string(),
            declared_address: None,
            features: Vec::new(),
        },
    };
    stream.write_all(&serialize_handshake(&ours)).await.unwrap();

    let mut conn = Connection::new_with_buffer(stream, MAINNET_MAGIC, leftover);

    let first = conn.read_message().await.unwrap();
    assert_eq!(first.code, CODE_GET_PEERS);
    let second = conn.read_message().await.unwrap();
    assert_eq!(second.code, CODE_SYNC_INFO);

    // Announce one header.
    let inv = serialize_inv(&InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![header_id],
    })
    .unwrap();
    conn.send(CODE_INV, inv).await.unwrap();

    let request = conn.read_message().await.unwrap();
    assert_eq!(request.code, CODE_REQUEST_MODIFIER);
    let requested = message::deserialize_inv(&request.payload).unwrap();
    assert_eq!(requested.type_id, ModifierTypeId::Header.as_byte());
    assert_eq!(requested.ids, vec![header_id]);

    let modifiers = serialize_modifiers(&ModifiersData {
        type_id: ModifierTypeId::Header.as_byte(),
        modifiers: vec![(header_id, header_bytes)],
    })
    .unwrap();
    conn.send(CODE_MODIFIER, modifiers).await.unwrap();

    // Give the observer a moment to process before the socket closes.
    tokio::time::sleep(Duration::from_millis(100)).await;
}
