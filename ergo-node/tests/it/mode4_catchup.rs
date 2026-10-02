//! Snapshot discovery parks above the NiPoPoW tip until real P2P header
//! catch-up indexes its anchor. Snapshot and post-install roots come from
//! mainnet headers; the suppliers and every database belong to this test.

use super::common;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use ergo_p2p::connection::Connection;
use ergo_p2p::handshake::{
    deserialize_handshake_with_consumed, serialize_handshake, Handshake, PeerFeature, PeerSpec,
    Version,
};
use ergo_p2p::message as wire;
use ergo_p2p::types::{InvData, ModifiersData, SnapshotsInfo};
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::extension::{write_extension, Extension, ExtensionField};
use ergo_ser::header::{read_header, Header};
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::avl::snapshot_codec::SnapshotServer;
use ergo_state::store::StateStore;
use ergo_state::ChainStateRead;
use ergo_validation::popow::algos::{pack_interlinks, update_interlinks};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(30);

struct Chain {
    headers: Vec<(Header, [u8; 32], Vec<u8>)>,
    sections: HashMap<[u8; 32], (u8, Vec<u8>)>,
}

fn chain() -> Chain {
    let headers: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    let txs: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/transactions_1_10.json"
    ))
    .unwrap();
    let mut result = Chain {
        headers: Vec::new(),
        sections: HashMap::new(),
    };
    let mut previous = None;
    let mut links = Vec::new();
    for row in headers.iter().take(10) {
        let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
        let id = hex::decode(row["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        if let Some(parent) = &previous {
            links = update_interlinks(parent, &links).unwrap();
        }
        let tx_row = txs
            .iter()
            .find(|t| t["height"].as_u64() == Some(u64::from(header.height)))
            .unwrap();
        let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(
            &hex::decode(tx_row["bytes"].as_str().unwrap()).unwrap(),
        ))
        .unwrap();
        let expected = ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        let mut writer = VlqWriter::new();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id: ModifierId::from_bytes(id),
                transactions: vec![tx],
            },
        )
        .unwrap();
        result
            .sections
            .insert(expected.transactions_id, (102, writer.result()));
        let mut writer = VlqWriter::new();
        write_extension(
            &mut writer,
            &Extension {
                header_id: ModifierId::from_bytes(id),
                fields: pack_interlinks(&links)
                    .into_iter()
                    .map(|(key, value)| ExtensionField {
                        key: key.try_into().unwrap(),
                        value,
                    })
                    .collect(),
            },
        )
        .unwrap();
        result
            .sections
            .insert(expected.extension_id, (108, writer.result()));
        result.headers.push((header.clone(), id, bytes));
        previous = Some(header);
    }
    result
}

fn snapshot(chain: &Chain, directory: &std::path::Path) -> SnapshotServer {
    let mut store = StateStore::open(&directory.join("state.redb")).unwrap();
    store
        .initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())
        .unwrap();
    for (header, id, bytes) in chain.headers.iter().take(9) {
        let meta = ergo_state::chain::HeaderMeta {
            height: header.height,
            parent_id: *header.parent_id.as_bytes(),
            timestamp: header.timestamp,
            cumulative_score: u64::from(header.height).to_be_bytes().to_vec(),
            pow_validity: 1,
        };
        store
            .store_validated_header(
                id,
                bytes,
                &meta,
                Some((header.height, meta.cumulative_score.clone())),
            )
            .unwrap();
        let expected = ExpectedSections::from_header(
            id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        let transactions = ergo_ser::block_transactions::read_block_transactions(
            &mut VlqReader::new(&chain.sections[&expected.transactions_id].1),
        )
        .unwrap();
        store
            .apply_block_unchecked_for_test(
                header.height,
                id,
                &header.state_root,
                &transactions.transactions,
            )
            .unwrap();
    }
    assert_eq!(
        store.root_digest(),
        chain.headers[8].0.state_root,
        "snapshot must reproduce mainnet's independently pinned root"
    );
    store.build_snapshot_at_tip(2).unwrap()
}

async fn handshake(mut stream: TcpStream) -> Connection {
    let bytes = serialize_handshake(&Handshake {
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        peer_spec: PeerSpec {
            agent_name: "mode4-acceptance".into(),
            version: Version::CURRENT,
            node_name: "snapshot-supplier".into(),
            declared_address: None,
            features: vec![PeerFeature::Mode {
                state_type: 0,
                verify_tx: true,
                nipopow: None,
                blocks_to_keep: -1,
            }],
        },
    });
    stream.write_all(&bytes).await.unwrap();
    let mut buffer = vec![0; 16384];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buffer[total..]).await.unwrap();
        assert!(n > 0, "peer closed during handshake");
        total += n;
        if let Ok((_, consumed)) = deserialize_handshake_with_consumed(&buffer[..total]) {
            return Connection::new_with_buffer(
                stream,
                ergo_p2p::framing::MAINNET_MAGIC,
                buffer[consumed..total].to_vec(),
            );
        }
    }
}

// Commands keep the advertised anchor above the proof tip until catch-up is sent.
enum Command {
    AdvertiseHeader(usize),
    ConfirmTip(usize),
}

async fn supplier(
    listener: TcpListener,
    snapshot: Arc<SnapshotServer>,
    chain: Arc<Chain>,
    mut commands: mpsc::Receiver<Command>,
    discovered: mpsc::Sender<usize>,
    number: usize,
    manifest_requests: Arc<AtomicUsize>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut connection = handshake(stream).await;
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(Command::AdvertiseHeader(index)) => connection.send(wire::CODE_INV, wire::serialize_inv(&InvData { type_id: 101, ids: vec![chain.headers[index].1] }).unwrap()).await.unwrap(),
                    Some(Command::ConfirmTip(index)) => connection.send(wire::CODE_SYNC_INFO, wire::serialize_sync_info(&wire::SyncInfo::V2 { headers: vec![chain.headers[index].2.clone()] }).unwrap()).await.unwrap(),
                    None => return,
                }
            }
            frame = connection.read_message() => {
                let Ok(frame) = frame else { return; };
                match frame.code {
                    wire::CODE_GET_SNAPSHOTS_INFO => {
                        connection.send(wire::CODE_SNAPSHOTS_INFO, wire::serialize_snapshots_info(&SnapshotsInfo { available_manifests: vec![(9, *snapshot.manifest_id.as_bytes())] }).unwrap()).await.unwrap();
                        discovered.send(number).await.unwrap();
                    },
                    wire::CODE_GET_MANIFEST => {
                        manifest_requests.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(wire::deserialize_get_manifest(&frame.payload).unwrap(), *snapshot.manifest_id.as_bytes());
                        connection.send(wire::CODE_MANIFEST, wire::serialize_manifest(&snapshot.manifest_bytes).unwrap()).await.unwrap();

                    }
                    wire::CODE_GET_UTXO_CHUNK => {
                        let id = wire::deserialize_get_utxo_chunk(&frame.payload).unwrap();
                        let bytes = snapshot.chunk_by_id(&ergo_primitives::digest::Digest32::from_bytes(id)).expect("asked chunk must be advertised");
                        connection.send(wire::CODE_UTXO_CHUNK, wire::serialize_utxo_chunk(bytes).unwrap()).await.unwrap();
                    }
                    wire::CODE_REQUEST_MODIFIER => {
                        let request = wire::deserialize_inv(&frame.payload).unwrap();
                        let modifiers: Vec<_> = request.ids.iter().filter_map(|id| {
                            if request.type_id == 101 { chain.headers.iter().find(|(_, header_id, _)| header_id == id).map(|(_, _, bytes)| (*id, bytes.clone())) }
                            else { chain.sections.get(id).filter(|(kind, _)| *kind == request.type_id).map(|(_, bytes)| (*id, bytes.clone())) }
                        }).collect();
                        if !modifiers.is_empty() { connection.send(wire::CODE_MODIFIER, wire::serialize_modifiers(&ModifiersData { type_id: request.type_id, modifiers }).unwrap()).await.unwrap(); }
                    }
                    wire::CODE_SYNC_INFO => {
                        // Echo the CURRENT advertised chain, so the stale
                        // historical fixture can establish caught-up status
                        // without inventing fresh timestamps or PoW.
                        let info = wire::deserialize_sync_info(&frame.payload).unwrap();
                        connection.send(wire::CODE_SYNC_INFO, wire::serialize_sync_info(&info).unwrap()).await.unwrap();
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn wait_tip(handle: &ergo_node::RunHandle, headers: u32, blocks: u32) {
    tokio::time::timeout(WAIT, async {
        loop {
            let tip = handle.read.tip();
            if tip.best_header.height == headers && tip.best_full_block.height == blocks {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {headers}/{blocks}; actual {:?}; sync {:?}",
            handle.read.tip(),
            handle.read.sync()
        )
    });
}

#[tokio::test]
async fn mode4_snapshot_waits_for_real_header_catchup_installs_applies_and_restarts() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let chain = Arc::new(chain());
    let snapshot = Arc::new(snapshot(&chain, source.path()));
    assert!(
        !snapshot.chunks.is_empty(),
        "fixture must exercise chunk downloads"
    );
    let manifest_requests = Arc::new(AtomicUsize::new(0));
    {
        let mut store = StateStore::open(&target.path().join("state.redb")).unwrap();
        store
            .initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())
            .unwrap();
        store
            .apply_popow_proof(&ergo_state::test_helpers::nipopow_proof_dense_from_2())
            .unwrap();
        assert!(matches!(
            store.lookup_header_at_height(9).unwrap(),
            ergo_state::chain::HeightLookup::AboveTip
        ));
    }
    let mut config = common::make_test_config(target.path().to_path_buf());
    config.utxo_bootstrap = true;
    config.nipopow_bootstrap = true;
    config.blocks_to_keep = 250;
    config.script_validation_checkpoint = None;
    // Keep all three suppliers on the configured localhost address. Extra
    // 127/8 aliases require host configuration on macOS; distinct ports still
    // identify independent P2P connections in the snapshot quorum.
    config.peer_limits.per_ip_limit = 3;
    let (discovered_tx, mut discovered_rx) = mpsc::channel(3);
    let mut commands = Vec::new();
    let mut tasks = Vec::new();
    config.known_peers.clear();
    for number in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.known_peers.push(listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel(2);
        commands.push(tx);
        tasks.push(tokio::spawn(supplier(
            listener,
            snapshot.clone(),
            chain.clone(),
            rx,
            discovered_tx.clone(),
            number,
            manifest_requests.clone(),
        )));
    }
    let handle = ergo_node::run_inner(config).await.unwrap();
    // Wait for all three production discovery requests/replies. The chosen
    // snapshot is above the proof's tip, so the fetch must remain parked.
    for _ in 0..3 {
        tokio::time::timeout(WAIT, discovered_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(handle.read.tip().best_header.height, 8);
    assert_eq!(handle.read.tip().best_full_block.height, 0);
    assert_eq!(
        manifest_requests.load(Ordering::Relaxed),
        0,
        "manifest fetch must remain parked above the header tip"
    );
    commands[0].send(Command::AdvertiseHeader(8)).await.unwrap();
    wait_tip(&handle, 9, 9).await;
    commands[0].send(Command::AdvertiseHeader(9)).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while handle.read.tip().best_header.height < 10 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("real forward header catch-up must reach block 10");
    // The 2019 fixture has a deliberately stale timestamp. Real peers must
    // confirm the exact current tip to open the normal download latch.
    for command in &commands {
        command.send(Command::ConfirmTip(9)).await.unwrap();
    }
    wait_tip(&handle, 10, 10).await;
    assert_eq!(
        manifest_requests.load(Ordering::Relaxed),
        1,
        "verified snapshot must be fetched once"
    );
    handle.shutdown().await.unwrap();
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    {
        let mut store = StateStore::open(&target.path().join("state.redb")).unwrap();
        assert_eq!(
            store.get_header_id_at_height(9).unwrap(),
            Some(chain.headers[8].1),
            "real forward admission must index the snapshot anchor"
        );
        assert_eq!(
            store.root_digest(),
            chain.headers[9].0.state_root,
            "post-install block must match mainnet root"
        );
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 10);
        assert!(store.was_utxo_bootstrapped().unwrap());
    }
    let mut config = common::make_test_config(target.path().to_path_buf());
    config.utxo_bootstrap = true;
    config.nipopow_bootstrap = true;
    config.blocks_to_keep = 250;
    config.script_validation_checkpoint = None;
    let restarted = ergo_node::run_inner(config).await.unwrap();
    wait_tip(&restarted, 10, 10).await;
    restarted.shutdown().await.unwrap();
    let mut store = StateStore::open(&target.path().join("state.redb")).unwrap();
    assert_eq!(store.root_digest(), chain.headers[9].0.state_root);
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 10);
    assert_eq!(
        store.chain_state_meta().best_full_block_id,
        chain.headers[9].1
    );
}
