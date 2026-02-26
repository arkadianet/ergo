//! Live integration test: connect to an Ergo peer and sync headers.
//! Requires network access. Run with: cargo test -p ergo-testkit --test live_header_sync -- --ignored
//!
//! Mainnet seed peers (port 9030): 213.239.193.208, 159.65.11.55, 165.227.26.175

use ergo_network::header_chain::HeaderChain;
use ergo_network::peer_conn::PeerConnection;
use ergo_network::sync::{build_request_modifier, build_sync_info, process_modifiers_response};
use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
use ergo_wire::inv::InvData;
use ergo_wire::message::MessageCode;
use ergo_wire::peer_feature::{ModeFeature, PeerFeature, SessionFeature, StateTypeCode};
use ergo_wire::sync_info::ErgoSyncInfo;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{timeout, Duration};

const MAINNET_MAGIC: [u8; 4] = [1, 0, 2, 4];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn build_handshake(magic: [u8; 4]) -> Handshake {
    Handshake {
        time: now_ms(),
        peer_spec: PeerSpec {
            agent_name: "ergoref".to_string(),
            protocol_version: ProtocolVersion {
                major: 5,
                minor: 0,
                patch: 12,
            },
            node_name: "ergo-rust-sync-test".to_string(),
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

#[tokio::test]
#[ignore] // requires network access
async fn sync_first_headers_from_mainnet() {
    let peers = vec![
        "213.239.193.208:9030",
        "159.65.11.55:9030",
        "165.227.26.175:9030",
    ];

    let mut chain = HeaderChain::new();

    for addr_str in &peers {
        println!("Trying {addr_str}...");
        let addr: SocketAddr = addr_str.parse().unwrap();
        let hs = build_handshake(MAINNET_MAGIC);

        // Try to connect
        let (mut conn, peer_hs) = match timeout(
            Duration::from_secs(10),
            PeerConnection::connect(addr, MAINNET_MAGIC, &hs, 10, None),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                println!("  Connection error: {e}");
                continue;
            }
            Err(_) => {
                println!("  Connection timeout");
                continue;
            }
        };

        println!(
            "Connected to {} ({})",
            addr_str, peer_hs.peer_spec.node_name
        );
        println!("  Agent: {}", peer_hs.peer_spec.agent_name);
        println!(
            "  Version: {}.{}.{}",
            peer_hs.peer_spec.protocol_version.major,
            peer_hs.peer_spec.protocol_version.minor,
            peer_hs.peer_spec.protocol_version.patch
        );

        // Step 1: Send empty SyncInfo V2
        let sync_info = build_sync_info(&chain);
        let sync_body = match sync_info {
            ErgoSyncInfo::V2(ref v2) => v2.serialize(),
            _ => unreachable!(),
        };
        if let Err(e) = conn
            .send_message(MessageCode::SyncInfo as u8, &sync_body)
            .await
        {
            println!("  Send SyncInfo error: {e}");
            continue;
        }
        println!("  Sent empty SyncInfo V2");

        // Step 2: Wait for Inv (code 55) with header IDs
        // The peer may send other messages first (like GetPeers), so loop until we get Inv
        let inv_data = match timeout(Duration::from_secs(30), async {
            loop {
                let msg = conn.recv_message().await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(e)
                })?;
                println!("  Received message code={}", msg.code);
                if msg.code == MessageCode::Inv as u8 {
                    return InvData::parse(&msg.body).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                        Box::new(e)
                    });
                }
                // Ignore other messages (GetPeers, etc.)
            }
        })
        .await
        {
            Ok(Ok(inv)) => inv,
            Ok(Err(e)) => {
                println!("  Inv receive/parse error: {e}");
                continue;
            }
            Err(_) => {
                println!("  Waiting for Inv timed out");
                continue;
            }
        };

        println!(
            "  Got Inv with {} header IDs (type={})",
            inv_data.ids.len(),
            inv_data.type_id
        );

        if inv_data.ids.is_empty() {
            println!("  No header IDs in Inv, peer may be syncing too");
            continue;
        }

        // Step 3: Send RequestModifier for those header IDs
        let req_body = build_request_modifier(inv_data.type_id, inv_data.ids.clone());
        if let Err(e) = conn
            .send_message(MessageCode::RequestModifier as u8, &req_body)
            .await
        {
            println!("  Send RequestModifier error: {e}");
            continue;
        }
        println!("  Sent RequestModifier for {} headers", inv_data.ids.len());

        // Step 4: Wait for Modifier (code 33) with header data
        let modifier_body = match timeout(Duration::from_secs(30), async {
            loop {
                let msg = conn.recv_message().await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(e)
                })?;
                println!("  Received message code={}", msg.code);
                if msg.code == MessageCode::Modifier as u8 {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(msg.body);
                }
            }
        })
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => {
                println!("  Modifier receive error: {e}");
                continue;
            }
            Err(_) => {
                println!("  Waiting for Modifier timed out");
                continue;
            }
        };

        println!(
            "  Got Modifier response ({} bytes)",
            modifier_body.len()
        );

        // Step 5: Process modifiers (parse, validate, insert)
        match process_modifiers_response(&modifier_body, &mut chain, now_ms()) {
            Ok(count) => {
                println!("  Processed {count} new headers!");
                println!("  Best height: {}", chain.best_height());
                if let Some(best) = chain.best_header() {
                    println!(
                        "  Best header: height={}, version={}",
                        best.height, best.version
                    );
                }
                if count > 0 {
                    assert!(chain.best_height() > 0);
                    println!("\nSUCCESS: Synced {} headers from {}", count, addr_str);
                    return; // test passes
                }
            }
            Err(e) => {
                println!("  Process modifiers error: {e}");
                continue;
            }
        }
    }

    panic!("Could not sync headers from any peer");
}
