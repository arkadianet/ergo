#[tokio::test]
async fn sync_tick_drives_shorter_heavier_fork_without_rolling_back_for_headers() {
    use ergo_primitives::{digest::blake2b256, reader::VlqReader, writer::VlqWriter};
    use ergo_ser::header::{read_header, write_header};
    use ergo_state::chain::HeaderMeta;
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    let mut tip = [0; 32];
    for height in 1..=3u32 {
        let raw = hex::decode(
            headers.iter().find(|h| h["height"] == height).unwrap()["bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let header = read_header(&mut VlqReader::new(&raw)).unwrap();
        tip = *blake2b256(&raw).as_bytes();
        store
            .store_validated_header(
                &tip,
                &raw,
                &HeaderMeta {
                    parent_id: *header.parent_id.as_bytes(),
                    height,
                    cumulative_score: vec![height as u8],
                    pow_validity: 1,
                    timestamp: header.timestamp,
                },
                Some((height, vec![height as u8])),
            )
            .unwrap();
        let root = store.root_digest();
        store
            .apply_block_unchecked_for_test(height, &tip, &root, &[])
            .unwrap();
    }
    let raw = hex::decode(headers[1]["bytes"].as_str().unwrap()).unwrap();
    let mut header = read_header(&mut VlqReader::new(&raw)).unwrap();
    match &mut header.solution {
        ergo_ser::autolykos::AutolykosSolution::V1 { nonce, .. }
        | ergo_ser::autolykos::AutolykosSolution::V2 { nonce, .. } => nonce[0] ^= 1,
    }
    let mut writer = VlqWriter::new();
    write_header(&mut writer, &header).unwrap();
    let raw = writer.result();
    let branch = *blake2b256(&raw).as_bytes();
    store
        .store_validated_header(
            &branch,
            &raw,
            &HeaderMeta {
                parent_id: *header.parent_id.as_bytes(),
                height: 2,
                cumulative_score: vec![9],
                pow_validity: 1,
                timestamp: header.timestamp,
            },
            Some((2, vec![9])),
        )
        .unwrap();
    let mut state = make_state_with_store(store);
    state.coordinator = SyncCoordinator::new(3);
    state
        .coordinator
        .sync_state_mut()
        .mark_headers_chain_synced();
    handle_sync_tick(&mut state);
    assert_eq!(state.store.chain_state_meta().best_full_block_id, tip);
    assert!(
        state
            .coordinator
            .sync_state()
            .blocks_to_download()
            .iter()
            .any(|b| b.header_id == branch),
        "the driver must run the executor even when the heavier header tip is lower"
    );
}

/// Capture queue state synchronously when the production loop sends its reply,
/// so task scheduling cannot hide which work was serviced first.
#[tokio::test]
async fn action_loop_services_queued_api_before_ready_peer_flood() {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::task::{Context, Wake, Waker};
    struct ReplyWake {
        peers: mpsc::Sender<PeerEvent>,
        capacity_at_reply: Arc<AtomicUsize>,
        sent: Arc<tokio::sync::Notify>,
    }
    impl Wake for ReplyWake {
        fn wake(self: Arc<Self>) {
            self.capacity_at_reply
                .store(self.peers.capacity(), Ordering::Release);
            self.sent.notify_one();
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let state = make_state(&temp.path().join("state.redb"));
    let (event_tx, event_rx) = mpsc::channel(8192);
    for _ in 0..8192 {
        event_tx
            .try_send(PeerEvent::TcpConnected { addr: test_peer() })
            .unwrap_or_else(|_| panic!("queue capacity"));
    }
    let (submit_tx, submit_rx) = mpsc::channel(1);
    let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
    let sent = Arc::new(tokio::sync::Notify::new());
    let capacity_at_reply = Arc::new(AtomicUsize::new(usize::MAX));
    let waker = Waker::from(Arc::new(ReplyWake {
        peers: event_tx,
        capacity_at_reply: capacity_at_reply.clone(),
        sent: sent.clone(),
    }));
    assert!(Pin::new(&mut reply_rx)
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    submit_tx
        .try_send(crate::api_bridge::SubmitRequest {
            bytes: vec![0],
            mode: ergo_api::types::SubmitMode::CheckOnly,
            reply: reply_tx,
        })
        .unwrap_or_else(|_| panic!("submit queue capacity"));
    let (_mining_tx, mining_rx) = mpsc::channel(1);
    let (_connect_tx, connect_rx) = mpsc::channel(1);
    let (_peer_control_tx, peer_control_rx) = mpsc::channel(1);
    let runtime_config = crate::config::NodeConfig::load(
        <crate::config::Cli as clap::Parser>::parse_from(["ergo-node", "--network", "devnet", "--peers", "127.0.0.1:1"]),
    ).unwrap();
    let runtime_control = crate::runtime_control::RuntimeControl::new(&runtime_config).unwrap();
    let (_votes_tx, votes_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(super::action_loop::action_loop(
        state,
        event_rx,
        submit_rx,
        mining_rx,
        connect_rx,
        peer_control_rx,
        runtime_control,
        votes_rx,
        None,
        shutdown_rx,
        1000,
    ));
    tokio::time::timeout(Duration::from_secs(2), sent.notified())
        .await
        .unwrap();
    let capacity = capacity_at_reply.load(Ordering::Acquire);
    let reply = reply_rx.try_recv().unwrap();
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(reply.is_err()); // cold-tip admission remains honest
    assert_eq!(
        capacity, 0,
        "peer events were consumed before queued API admission"
    );
}
