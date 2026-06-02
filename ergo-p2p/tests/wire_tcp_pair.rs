//! End-to-end TCP-pair tests for the `Connection` / framing /
//! handshake layer.
//!
//! These run a real `TcpListener` on `127.0.0.1:0` plus a connecting
//! `TcpStream`, exercise the same `Connection::send` /
//! `Connection::read_message` path that production uses, and assert
//! both sides observe the same wire bytes / `MessageFrame` /
//! `Handshake` values.
//!
//! Unit tests in `ergo-p2p/src/{framing,connection,handshake}.rs`
//! pin the codec individually; this file pins the integration
//! between them — what production actually runs.

use std::time::Duration;

use ergo_p2p::connection::Connection;
use ergo_p2p::framing::{deserialize_frame, MessageFrame, MAINNET_MAGIC, TESTNET_MAGIC};
use ergo_p2p::handshake::{
    deserialize_handshake, serialize_handshake, Handshake, PeerSpec, Version,
};
use ergo_p2p::message::{deserialize_inv, serialize_inv, CODE_INV};
use ergo_p2p::types::InvData;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Spawn a server-side `TcpListener` on an ephemeral loopback port,
/// connect a client `TcpStream` to it, and return both sides.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server_addr = listener.local_addr().expect("local_addr");
    let connect = tokio::spawn(async move { TcpStream::connect(server_addr).await });
    let (server, _) = listener.accept().await.expect("accept");
    let client = connect.await.expect("join").expect("connect");
    (server, client)
}

#[tokio::test(flavor = "current_thread")]
async fn frame_roundtrip_over_tcp_with_mixed_payload_sizes() {
    let (server, client) = tcp_pair().await;
    let mut server_conn = Connection::new(server, MAINNET_MAGIC);
    let mut client_conn = Connection::new(client, MAINNET_MAGIC);

    // Three frames with deliberately varied payload shapes:
    //   - non-empty Inv carrying two ids (passes serialize_inv's
    //     "no empty" check; tests the with-checksum branch)
    //   - small ad-hoc code with a single byte payload
    //   - a few KB payload to cross the read-buffer's 64K page once
    let inv = InvData {
        type_id: 101,
        ids: vec![[0xAA; 32], [0xBB; 32]],
    };
    let inv_bytes = serialize_inv(&inv).expect("serialize_inv");
    let frames = vec![
        MessageFrame {
            code: CODE_INV,
            payload: inv_bytes.clone(),
        },
        MessageFrame {
            code: 7,
            payload: vec![0x42],
        },
        MessageFrame {
            code: 9,
            payload: vec![0x55; 4_096],
        },
    ];

    let frames_to_send = frames.clone();
    let writer = tokio::spawn(async move {
        for f in &frames_to_send {
            client_conn
                .write_message(f)
                .await
                .expect("client write_message");
        }
    });

    let mut received = Vec::with_capacity(frames.len());
    for _ in 0..frames.len() {
        let f = server_conn
            .read_message()
            .await
            .expect("server read_message");
        received.push(f);
    }
    writer.await.expect("writer task");

    assert_eq!(received.len(), frames.len());
    for (got, want) in received.iter().zip(frames.iter()) {
        assert_eq!(got.code, want.code);
        assert_eq!(got.payload, want.payload);
    }

    // Sanity: the first frame is a real Inv that round-trips through
    // the message layer too, not just the framing layer.
    let first_inv = deserialize_inv(&received[0].payload).expect("deserialize_inv");
    assert_eq!(first_inv.type_id, inv.type_id);
    assert_eq!(first_inv.ids, inv.ids);
}

#[tokio::test(flavor = "current_thread")]
async fn read_message_rejects_wrong_magic_from_peer() {
    // Server is configured for mainnet magic; client writes a frame
    // with testnet magic. The framing layer must surface FrameError
    // and not silently proceed.
    let (server, mut client) = tcp_pair().await;
    let mut server_conn = Connection::new(server, MAINNET_MAGIC);

    // Hand-craft a minimal framed message with the wrong magic.
    let frame = MessageFrame {
        code: 7,
        payload: vec![0x01],
    };
    let bytes = ergo_p2p::framing::serialize_frame(&TESTNET_MAGIC, &frame);
    client.write_all(&bytes).await.expect("client write_all");

    // Bound the wait so a regression that hangs the read is visible
    // as a test timeout rather than a hung CI job.
    let result = tokio::time::timeout(Duration::from_secs(2), server_conn.read_message()).await;
    match result {
        Ok(Err(_)) => { /* expected — wrong-magic surfaces as a Frame error */ }
        Ok(Ok(frame)) => panic!("server accepted wrong-magic frame: {frame:?}"),
        Err(_) => panic!("server hung on wrong-magic frame instead of erroring"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_roundtrip_over_tcp_pair() {
    // Both sides exchange a single Handshake frame (code 75) and
    // verify the parsed `PeerSpec` matches what the peer sent.
    let (server, client) = tcp_pair().await;
    let mut server_conn = Connection::new(server, MAINNET_MAGIC);
    let mut client_conn = Connection::new(client, MAINNET_MAGIC);

    let server_hs = Handshake {
        time: 1_700_000_000_000,
        peer_spec: PeerSpec {
            agent_name: "ergo-rust-server".into(),
            version: Version::CURRENT,
            node_name: "server-node".into(),
            declared_address: None,
            features: Vec::new(),
        },
    };
    let client_hs = Handshake {
        time: 1_700_000_001_000,
        peer_spec: PeerSpec {
            agent_name: "ergo-rust-client".into(),
            version: Version::CURRENT,
            node_name: "client-node".into(),
            declared_address: None,
            features: Vec::new(),
        },
    };

    let server_payload = serialize_handshake(&server_hs);
    let client_payload = serialize_handshake(&client_hs);

    // Exchange handshakes concurrently — production is symmetric.
    let server_payload_to_send = server_payload.clone();
    let client_payload_to_send = client_payload.clone();
    let server_task = tokio::spawn(async move {
        server_conn
            .send(75, server_payload_to_send)
            .await
            .expect("server send");
        server_conn.read_message().await.expect("server read")
    });
    let client_task = tokio::spawn(async move {
        client_conn
            .send(75, client_payload_to_send)
            .await
            .expect("client send");
        client_conn.read_message().await.expect("client read")
    });
    let server_received = server_task.await.expect("server task");
    let client_received = client_task.await.expect("client task");

    assert_eq!(server_received.code, 75);
    assert_eq!(client_received.code, 75);

    // Each side parses the bytes the other actually sent.
    let parsed_at_server =
        deserialize_handshake(&server_received.payload).expect("server parses client handshake");
    let parsed_at_client =
        deserialize_handshake(&client_received.payload).expect("client parses server handshake");

    assert_eq!(
        parsed_at_server.peer_spec.agent_name,
        client_hs.peer_spec.agent_name
    );
    assert_eq!(
        parsed_at_server.peer_spec.node_name,
        client_hs.peer_spec.node_name
    );
    assert_eq!(
        parsed_at_server.peer_spec.version,
        client_hs.peer_spec.version
    );
    assert_eq!(parsed_at_server.time, client_hs.time);

    assert_eq!(
        parsed_at_client.peer_spec.agent_name,
        server_hs.peer_spec.agent_name
    );
    assert_eq!(
        parsed_at_client.peer_spec.node_name,
        server_hs.peer_spec.node_name
    );
    assert_eq!(
        parsed_at_client.peer_spec.version,
        server_hs.peer_spec.version
    );
    assert_eq!(parsed_at_client.time, server_hs.time);
}

#[tokio::test(flavor = "current_thread")]
async fn read_message_drains_multi_frame_chunked_write() {
    // Pin the buffered-read path: a single 4 KB write that contains
    // three back-to-back frames must be parsed as three frames, not
    // one giant payload, even if the kernel delivers all bytes in
    // one read.
    let (server, mut client) = tcp_pair().await;
    let mut server_conn = Connection::new(server, MAINNET_MAGIC);

    let f0 = MessageFrame {
        code: 7,
        payload: vec![0xAA; 100],
    };
    let f1 = MessageFrame {
        code: 8,
        payload: vec![0xBB; 200],
    };
    let f2 = MessageFrame {
        code: 9,
        payload: vec![],
    };

    let mut combined = Vec::new();
    combined.extend(ergo_p2p::framing::serialize_frame(&MAINNET_MAGIC, &f0));
    combined.extend(ergo_p2p::framing::serialize_frame(&MAINNET_MAGIC, &f1));
    combined.extend(ergo_p2p::framing::serialize_frame(&MAINNET_MAGIC, &f2));

    // Sanity: no individual frame trips the connection's MAX_PAYLOAD
    // pre-check; we just want to verify the read_message loop
    // correctly drains buffered bytes across three calls.
    assert!(deserialize_frame(&MAINNET_MAGIC, &combined).is_ok());

    client.write_all(&combined).await.expect("client write");
    drop(client); // signal EOF after the writes land

    let r0 = server_conn.read_message().await.expect("frame 0");
    let r1 = server_conn.read_message().await.expect("frame 1");
    let r2 = server_conn.read_message().await.expect("frame 2");
    assert_eq!((r0.code, r0.payload.len()), (7, 100));
    assert_eq!((r1.code, r1.payload.len()), (8, 200));
    assert_eq!((r2.code, r2.payload.len()), (9, 0));
}
