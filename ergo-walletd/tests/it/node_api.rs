//! Handoff-required real-node integration test.
//!
//! The rest of `tests/it` drives the daemon's chain adapter against a
//! hand-rolled one-shot TCP responder, which proves the wire parsing but not
//! the node side. This module closes that gap with the **real** stack:
//!
//! * a real `ergo_state::store::StateStore` in a temp dir, seeded with
//!   synthetic-but-real full blocks (headers, `BlockTransactions` sections,
//!   UTXO apply) — deterministic, no fixture files, no network;
//! * the real `ergo_node` in-process chain adapter over that store, wrapped in
//!   the real `WalletChainAdapter` (the exact adapter the node hands to
//!   `ergo-api`);
//! * the real `ergo_api` `/api/v1/chain/*` router, including the real
//!   `ApiSecurity` (Blake2b-256 + constant-time) `api_key` gate and the real
//!   `Governor` rate limiter;
//! * the real `ergo_walletd::chain_http::HttpChainClient` and the real
//!   `StandaloneSyncer`, over real HTTP/1.1 on a loopback port.
//!
//! The tests are plain `#[test]`s, not `#[tokio::test]`: the server runs on its
//! own runtime in a background thread, and the daemon client is
//! `reqwest::blocking`, so each test body sits outside any async context — the
//! same invariant `lib::prepare` + `main` rely on in production.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ergo_api::auth::ApiSecurity;
use ergo_api::traits::WalletChain;
use ergo_api::v1::governor::{Governor, GovernorConfig};
use ergo_api::v1::{wallet_chain_router, V1AuthConfig, WalletChainState};
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::opcode::Expr;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::transaction::Transaction;
use ergo_state::store::StateStore;
use ergo_wallet_service::{
    BlocksSinceRequest, BlocksSinceResponse, ChainClient, ChainClientError, ChainCursor,
    ChainSnapshot, CommittedTip, RedbWalletStore, RescanState, SubmitRequest, SubmitResponse,
    UtxoLookup, WalletService, WalletStore,
};

use ergo_walletd::chain_http::HttpChainClient;
use ergo_walletd::config::ApiKey;
use ergo_walletd::sync::{StandaloneSyncer, SyncConfig, SyncError};
use ergo_walletd::tip::CachedNodeTip;

/// A valid, non-default operator key. Deliberately *not* one of
/// `ergo_api::v1::auth::KNOWN_WEAK_KEYS`, so the node's boot-warn posture check
/// stays clean and only the real gate decides.
pub(crate) const NODE_API_KEY: &[u8] = b"ergo-walletd-real-node-handoff-key";
pub(crate) const TIP_HEIGHT: u32 = 3;
const GENESIS_CURSOR_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ----- real node state store -----

fn header(height: u32, parent: ModifierId, nonce: [u8; 8]) -> Header {
    Header {
        version: 2,
        parent_id: parent,
        ad_proofs_root: Digest32::from_bytes([0; 32]),
        transactions_root: Digest32::from_bytes([0; 32]),
        state_root: ADDigest::from_bytes([0; 33]),
        timestamp: 1_000_000 + height as u64,
        extension_root: Digest32::from_bytes([0; 32]),
        n_bits: 16842752,
        height,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
            nonce,
        },
    }
}

/// Apply one empty-but-real full block: persist the header, persist the
/// `BlockTransactions` section (so `blocks-since` can serve the block's
/// transactions), then apply it to the UTXO state. Returns the block id.
fn apply_block(
    store: &mut StateStore,
    height: u32,
    parent: ModifierId,
    nonce: [u8; 8],
) -> [u8; 32] {
    let value = header(height, parent, nonce);
    let (bytes, id) = serialize_header(&value).unwrap();
    let id_bytes = *id.as_bytes();
    store.store_header(&id_bytes, &bytes).unwrap();
    let mut writer = VlqWriter::new();
    write_block_transactions(
        &mut writer,
        &BlockTransactions {
            header_id: id,
            transactions: Vec::new(),
        },
    )
    .unwrap();
    let section_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        &id_bytes,
        value.transactions_root.as_bytes(),
    );
    store
        .store_block_section(&section_id, &writer.result())
        .unwrap();
    let root = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &id_bytes, &root, &[])
        .unwrap();
    id_bytes
}

/// A small, deterministic committed chain: genesis plus `TIP_HEIGHT` blocks.
/// Returns the store and the committed block id at every height 1..=TIP_HEIGHT.
pub(crate) fn seeded_node(dir: &Path) -> (StateStore, Vec<[u8; 32]>) {
    let mut store = StateStore::open(&dir.join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    let mut parent = ModifierId::from_bytes([0; 32]);
    let mut ids = Vec::new();
    for height in 1..=TIP_HEIGHT {
        let id = apply_block(&mut store, height, parent, [0; 8]);
        parent = ModifierId::from_bytes(id);
        ids.push(id);
    }
    assert_eq!(store.height(), TIP_HEIGHT);
    (store, ids)
}

// ----- realistic block size fixture -----

/// Register payload that puts a single output box at roughly the protocol's
/// `max_box_size`, so a big block is built the way a real one is: many
/// full-size boxes, not one impossible one.
const FULL_BOX_REGISTER_BYTES: usize = 3_900;

/// Output boxes per block. `FULL_BOX_REGISTER_BYTES * OUTPUTS_PER_BLOCK` is
/// ~1.5 MiB of serialized `BlockTransactions` per block, which is the premise
/// the paging test asserts: hex-encoded on the wire, a page of three of those
/// cannot fit the daemon's 8 MiB response cap, while the default one-block page
/// comfortably can.
const OUTPUTS_PER_BLOCK: usize = 400;

/// Allowance the paging test adds to its page-size estimate, per block, for the
/// JSON envelope around the hex payload (ids, indices, braces, commas). The real
/// envelope is a few hundred kilobytes; this is a deliberately *loose* slack, so
/// the test's premise assertions are conservative and the outcome is decided by
/// what the daemon actually does, not by the estimate.
const JSON_ENVELOPE_ALLOWANCE_PER_BLOCK: u64 = 64 * 1024;

/// One real transaction whose single input spends a box that does not exist and
/// whose outputs are real `ErgoBoxCandidate`s carrying a full-size data
/// register. The input exists only so the transaction is structurally a spend
/// rather than a bare mint; nothing validates it here (see
/// [`apply_block_with_transactions`]).
fn fat_transaction(height: u32, seed: u8) -> Transaction {
    let tree = ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: true,
        constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        },
    };
    let outputs = (0..OUTPUTS_PER_BLOCK)
        .map(|index| {
            // A distinct payload per output, so no transaction carries the same
            // box `OUTPUTS_PER_BLOCK` times — a shape the wire would allow but
            // a real chain would never produce, and one that would make the
            // fixture's size an artefact of the encoder's dedup rather than of
            // the page math.
            let head: Vec<char> = (0..4)
                .map(|offset| {
                    (b'a' + (index as u8).wrapping_add(seed).wrapping_add(offset) % 26) as char
                })
                .collect();
            let payload: String =
                std::iter::repeat_n(head.iter(), FULL_BOX_REGISTER_BYTES / head.len())
                    .flatten()
                    .copied()
                    .collect();
            let registers = AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SString,
                    value: SigmaValue::Str(payload),
                }],
            };
            ErgoBoxCandidate::new(
                1_000_000 + index as u64,
                tree.clone(),
                height,
                Vec::new(),
                registers,
            )
            .expect("valid candidate")
        })
        .collect();
    Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([seed; 32]),
            spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty())
                .expect("valid spending proof"),
        }],
        data_inputs: Vec::new(),
        output_candidates: outputs,
    }
}

/// Apply one block that *serves* a large, real transaction section, and return
/// the block id and the section's serialized size.
///
/// The state transition itself is applied with an empty transaction list, on
/// purpose: the header's `transactions_root` is a fixture constant and no
/// consensus check runs here, so pushing a 1.4 MiB transaction set through the
/// UTXO apply would add nothing to what this fixture is for. What the test
/// needs is a node that serves a realistically *sized* `blocks-since` page
/// built from real serialized transactions and real ErgoBoxes — the node reads
/// the section, not the apply.
fn apply_block_with_transactions(
    store: &mut StateStore,
    height: u32,
    parent: ModifierId,
    nonce: [u8; 8],
) -> ([u8; 32], usize) {
    let value = header(height, parent, nonce);
    let (bytes, id) = serialize_header(&value).unwrap();
    let id_bytes = *id.as_bytes();
    store.store_header(&id_bytes, &bytes).unwrap();
    let mut writer = VlqWriter::new();
    write_block_transactions(
        &mut writer,
        &BlockTransactions {
            header_id: id,
            transactions: vec![fat_transaction(height, height as u8)],
        },
    )
    .unwrap();
    let section = writer.result();
    let section_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        &id_bytes,
        value.transactions_root.as_bytes(),
    );
    store.store_block_section(&section_id, &section).unwrap();
    let root = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &id_bytes, &root, &[])
        .unwrap();
    (id_bytes, section.len())
}

/// The same chain as [`seeded_node`], with every block carrying a realistically
/// large transaction section.
fn seeded_fat_node(dir: &Path) -> (StateStore, usize) {
    let mut store = StateStore::open(&dir.join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    let mut parent = ModifierId::from_bytes([0; 32]);
    let mut section_bytes = 0usize;
    for height in 1..=TIP_HEIGHT {
        let (id, size) = apply_block_with_transactions(&mut store, height, parent, [0; 8]);
        parent = ModifierId::from_bytes(id);
        section_bytes = size;
    }
    assert_eq!(store.height(), TIP_HEIGHT);
    (store, section_bytes)
}

fn committed_id(store: &StateStore, height: u32) -> [u8; 32] {
    store
        .reader_handle()
        .committed_block_id_at_height(height)
        .unwrap()
        .unwrap_or_else(|| panic!("no committed block at height {height}"))
}

// ----- real node HTTP surface on loopback -----

/// Handle for the in-process node API. Dropping it stops the server and joins
/// its thread, so a failing assertion cannot leave a listener behind.
pub(crate) struct NodeApi {
    address: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl NodeApi {
    pub(crate) fn url(&self) -> String {
        format!("http://{}/", self.address)
    }
}

impl Drop for NodeApi {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serve the real `ergo-api` chain router on an ephemeral loopback port.
///
/// The listener is a `std::net::TcpListener` bound *before* the runtime starts,
/// so the port is known synchronously (no sleep/retry race) and the blocking
/// client in the test body never runs inside the server's runtime. The chain
/// adapter is built from a *cloneable* `ChainStoreReader`, so the server keeps
/// serving the same store across a rollback/re-apply (the reorg test).
pub(crate) fn serve_node_api(store: &StateStore) -> NodeApi {
    let security = Arc::new(
        ApiSecurity::new(ApiSecurity::hash_key(NODE_API_KEY)).expect("valid api_key hash"),
    );
    let governor = Governor::new(GovernorConfig::default()).expect("valid governor config");
    // The real production adapter: ergo-node's in-process chain client over the
    // real StateStore, behind ergo-api's `WalletChain` trait object.
    let chain_client = Arc::new(
        ergo_node::node::wallet_bridge::InProcessChainClient::from_chain_reader(
            store.reader_handle(),
            None::<Arc<dyn ergo_api::NodeSubmit>>,
            false,
            None,
        ),
    );
    let chain: Arc<dyn WalletChain> =
        ergo_node::node::wallet_bridge::WalletChainAdapter::new(chain_client).into_dyn();
    let router = wallet_chain_router(
        WalletChainState::with_chain(chain),
        governor,
        V1AuthConfig::new(Some(security)).into_shared(),
    );

    let std_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = std_listener.local_addr().unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            // `from_std` needs a reactor, so the handoff happens in here; the
            // port was already resolved above, so the caller never waits on it.
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("the node API server runs without error");
        });
    });
    NodeApi {
        address,
        shutdown: Some(shutdown_tx),
        thread: Some(handle),
    }
}

// ----- the daemon's real client, built the way production builds it -----

/// A `#[test]` body is not inside a runtime, so the blocking `reqwest` client
/// builds here exactly as `lib::prepare` builds it in the daemon.
fn daemon_client(url: &str, key: &[u8]) -> HttpChainClient {
    HttpChainClient::with_timeouts(
        reqwest::Url::parse(url).unwrap(),
        ApiKey::from_test(key.to_vec()),
        Duration::from_secs(5),
        Duration::from_secs(10),
    )
    .expect("the blocking client builds outside an async runtime")
}

/// Records the `(cursor height, limit)` of every `blocks-since` call so the
/// sync path's paging can be asserted. Everything else delegates, so the HTTP
/// work is still done by the real `HttpChainClient`.
struct CountingChain {
    inner: HttpChainClient,
    requests: Mutex<VecDeque<(u32, u32)>>,
}

impl CountingChain {
    fn new(inner: HttpChainClient) -> Arc<Self> {
        Arc::new(Self {
            inner,
            requests: Mutex::new(VecDeque::new()),
        })
    }

    fn requests(&self) -> Vec<(u32, u32)> {
        self.requests
            .lock()
            .expect("requests lock")
            .clone()
            .into_iter()
            .collect()
    }
}

impl ChainClient for CountingChain {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        self.inner.committed_tip()
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        self.inner.snapshot()
    }

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        self.requests
            .lock()
            .expect("requests lock")
            .push_back((request.cursor.height, request.limit));
        self.inner.blocks_since(request)
    }

    fn lookup_utxo(
        &self,
        box_id: [u8; 32],
        expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        self.inner.lookup_utxo(box_id, expected_tip)
    }

    fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        self.inner.submit(request)
    }
}

fn syncer(chain: Arc<dyn ChainClient>, store: Arc<RedbWalletStore>) -> StandaloneSyncer {
    let tip = Arc::new(CachedNodeTip::new(chain.clone()));
    let service = Arc::new(WalletService::new(store, chain));
    StandaloneSyncer::new(
        service,
        SyncConfig {
            batch: 8,
            page: ergo_walletd::sync::DEFAULT_BLOCKS_PER_PAGE,
            retry_delay: Duration::ZERO,
            max_retry_delay: Duration::ZERO,
        },
        tip,
    )
}

fn standalone_wallet(dir: &Path) -> Arc<RedbWalletStore> {
    Arc::new(RedbWalletStore::open_standalone(dir.join("wallet.redb")).unwrap())
}

/// A minimal raw HTTP GET, so the auth assertions read the real status code off
/// the real socket rather than through the client under test.
fn raw_status(url: &str, path: &str, key: Option<&[u8]>) -> u16 {
    let address = url.trim_start_matches("http://").trim_end_matches('/');
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\n");
    if let Some(key) = key {
        request.push_str(&format!("api_key: {}\r\n", String::from_utf8_lossy(key)));
    }
    request.push_str("Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response).to_string();
    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in response: {text}"))
}

fn blocks_since_path(height: u32, id: &str, limit: u32) -> String {
    format!("/api/v1/chain/blocks-since?height={height}&id={id}&limit={limit}")
}

// ----- tests -----

/// The daemon's real HTTP client reads the real node tip and real forward
/// pages, and the real sync loop carries a standalone wallet from genesis to
/// the node tip through that same HTTP path.
#[test]
fn real_node_tip_blocks_since_and_sync_against_a_seeded_state_store() {
    let node_dir = tempfile::tempdir().unwrap();
    let (store, ids) = seeded_node(node_dir.path());
    let node = serve_node_api(&store);
    let client = daemon_client(&node.url(), NODE_API_KEY);

    // Tip: exactly what the store committed.
    let tip = client.committed_tip().unwrap();
    assert_eq!(tip.height, TIP_HEIGHT);
    assert_eq!(tip.header_id, *ids.last().unwrap());

    // Blocks-since: a full forward page from the genesis cursor.
    let BlocksSinceResponse::Forward(forward) = client
        .blocks_since(BlocksSinceRequest {
            cursor: ChainCursor::genesis(),
            limit: 16,
        })
        .unwrap()
    else {
        panic!("expected a forward page from the genesis cursor");
    };
    assert_eq!(forward.tip, tip);
    assert_eq!(forward.blocks.len(), TIP_HEIGHT as usize);
    for (offset, block) in forward.blocks.iter().enumerate() {
        let height = offset as u32 + 1;
        assert_eq!(block.height, height);
        assert_eq!(block.block_id, ids[height as usize - 1]);
        assert!(block.transactions.is_empty());
    }
    // The parent chain is contiguous, so the wallet's parent-mismatch check has
    // something real to agree with.
    assert_eq!(forward.blocks[0].parent_id, [0; 32]);
    for pair in forward.blocks.windows(2) {
        assert_eq!(pair[1].parent_id, pair[0].block_id);
    }
    assert_eq!(forward.blocks.last().unwrap().block_id, tip.header_id);

    // A bounded page is a real prefix, and the node's own tip is echoed with it.
    let BlocksSinceResponse::Forward(bounded) = client
        .blocks_since(BlocksSinceRequest {
            cursor: ChainCursor::genesis(),
            limit: 2,
        })
        .unwrap()
    else {
        panic!("expected a forward page");
    };
    assert_eq!(bounded.tip, tip);
    assert_eq!(bounded.blocks.len(), 2);
    assert_eq!(bounded.blocks[1].block_id, ids[1]);

    // A cursor at the tip returns an empty forward page, not an error.
    let BlocksSinceResponse::Forward(empty) = client
        .blocks_since(BlocksSinceRequest {
            cursor: ChainCursor {
                height: tip.height,
                header_id: tip.header_id,
            },
            limit: 4,
        })
        .unwrap()
    else {
        panic!("expected a forward page at the tip");
    };
    assert!(empty.blocks.is_empty());
    assert_eq!(empty.tip, tip);

    // A cursor at a real height whose header id the node has never seen is not
    // a reorg: there is no ancestor walk to do, so the node reports the history
    // as unavailable and the client surfaces a protocol failure. The genuine
    // reorg case (a header the node *did* commit, later replaced) is driven in
    // `real_node_reorg_returns_the_common_ancestor_and_the_daemon_follows_it`.
    assert!(matches!(
        client.blocks_since(BlocksSinceRequest {
            cursor: ChainCursor {
                height: tip.height,
                header_id: [0xEE; 32],
            },
            limit: 4,
        }),
        Err(ChainClientError::Protocol(_))
    ));

    // A cursor ahead of the tip is the real 409, mapped to the real typed
    // conflict, not a silently-empty page.
    assert!(matches!(
        client.blocks_since(BlocksSinceRequest {
            cursor: ChainCursor {
                height: TIP_HEIGHT + 1,
                header_id: [0x11; 32],
            },
            limit: 4,
        }),
        Err(ChainClientError::Conflict)
    ));

    // The real sync path over the real HTTP client, from genesis to the tip.
    let wallet_dir = tempfile::tempdir().unwrap();
    let store = standalone_wallet(wallet_dir.path());
    let chain = CountingChain::new(client);
    let syncer = syncer(chain.clone(), store.clone());
    let report = syncer.sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.from_height, 0);
    assert_eq!(report.wallet_height, TIP_HEIGHT);
    assert_eq!(report.tip, tip);
    assert_eq!(report.blocks_processed, TIP_HEIGHT);
    // The apply budget (8) and the page budget (the default, 1) are separate:
    // the pass applies all three blocks but never asks for more than one at a
    // time, and the loop then finishes on its tip comparison, so there is no
    // fourth request.
    assert_eq!(chain.requests(), vec![(0, 1), (1, 1), (2, 1)]);
    assert!(
        chain
            .requests()
            .iter()
            .all(|(_, limit)| *limit <= ergo_walletd::sync::DEFAULT_BLOCKS_PER_PAGE),
        "no request may exceed the page budget: {:?}",
        chain.requests()
    );
    let read = store.read().unwrap();
    let cursor = read.scan_cursor().unwrap().unwrap();
    assert_eq!(cursor.height, TIP_HEIGHT);
    assert_eq!(cursor.header_id, Some(tip.header_id));
    assert!(!read.scan_invalidated().unwrap());
}

/// The paging contract, on the real node and over real HTTP, with blocks that
/// are actually big.
///
/// The other tests in this module use empty blocks, where any page size works
/// because the response is a few hundred bytes. A real mainnet page is not like
/// that: every output box crosses the wire hex-encoded, so a page of `N` blocks
/// costs roughly twice their serialized bytes, and the daemon refuses any body
/// over 8 MiB. This fixture therefore builds blocks of ~1.4 MiB each — many
/// full-size boxes, the shape a real full block has — so the difference between
/// "page bounded by `blocks_page`" and "page bounded by `sync_batch`" is the
/// difference between a completed pass and a hard failure.
///
/// Three things are pinned:
/// 1. the premise — a whole-tip page would not fit the cap, so the bound is
///    load-bearing rather than decorative;
/// 2. a full pass completes, applying every block, over pages of at most
///    `blocks_page`;
/// 3. the *same* node with the page bound removed fails closed on the first
///    response with the bounded, named error instead of looping.
#[test]
fn real_node_pages_non_empty_full_size_blocks_without_oversized_requests() {
    let node_dir = tempfile::tempdir().unwrap();
    let (store, section_bytes) = seeded_fat_node(node_dir.path());
    let node = serve_node_api(&store);

    // Premise. The wire form is hex, so the body for a page of `N` blocks is
    // about `2 * N * section_bytes` plus a per-block JSON allowance.
    let page_body = |blocks: u32| -> u64 {
        2 * u64::from(blocks) * section_bytes as u64
            + u64::from(blocks) * JSON_ENVELOPE_ALLOWANCE_PER_BLOCK
    };
    assert!(
        page_body(3) > ergo_walletd::chain_http::MAX_RESPONSE_BODY_BYTES as u64,
        "a whole-tip page ({} bytes) must not fit the cap, or this test proves nothing",
        page_body(3)
    );
    assert!(
        page_body(1) < ergo_walletd::chain_http::MAX_RESPONSE_BODY_BYTES as u64,
        "a one-block page ({} bytes) must fit the cap, or the default page is wrong",
        page_body(1)
    );

    // The node really does serve full-size transaction data, so the daemon's
    // canonical-box and identity checks run on real bytes rather than a stub.
    let client = daemon_client(&node.url(), NODE_API_KEY);
    let BlocksSinceResponse::Forward(page) = client
        .blocks_since(BlocksSinceRequest {
            cursor: ChainCursor::genesis(),
            limit: 1,
        })
        .unwrap()
    else {
        panic!("expected a forward page from the genesis cursor");
    };
    assert_eq!(page.blocks.len(), 1);
    assert_eq!(
        page.blocks[0].transactions.len(),
        1,
        "the block must carry a transaction, or the page proves nothing"
    );
    assert_eq!(
        page.blocks[0].transactions[0].outputs.len(),
        OUTPUTS_PER_BLOCK
    );

    // (2) A full pass over the real HTTP path, applying every block, one bounded
    // page at a time.
    let wallet_dir = tempfile::tempdir().unwrap();
    let store_wallet = standalone_wallet(wallet_dir.path());
    let chain = CountingChain::new(client);
    let syncer = syncer(chain.clone(), store_wallet.clone());
    let report = syncer.sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.blocks_processed, TIP_HEIGHT);
    assert_eq!(report.wallet_height, TIP_HEIGHT);
    let requests = chain.requests();
    assert_eq!(
        requests,
        vec![(0, 1), (1, 1), (2, 1)],
        "three blocks at the default one-block page: three requests, each asking \
         for one block"
    );
    assert!(
        requests
            .iter()
            .all(|(_, limit)| *limit <= ergo_walletd::sync::DEFAULT_BLOCKS_PER_PAGE),
        "no request may exceed the page budget: {requests:?}"
    );
    let read = store_wallet.read().unwrap();
    assert_eq!(read.scan_cursor().unwrap().unwrap().height, TIP_HEIGHT);
    assert!(!read.scan_invalidated().unwrap());

    // (3) Remove the page bound — the pre-fix behaviour, where the apply budget
    // sized the request — and the same node produces a body over the cap. It is
    // reported once, as a terminal error naming the cap, the page, and the fact
    // that no smaller page will be tried. It is not retried and does not loop.
    let unbounded_dir = tempfile::tempdir().unwrap();
    let unbounded = CountingChain::new(daemon_client(&node.url(), NODE_API_KEY));
    let unbounded_wallet = standalone_wallet(unbounded_dir.path());
    let unbounded_syncer = StandaloneSyncer::new(
        Arc::new(WalletService::new(
            unbounded_wallet.clone(),
            unbounded.clone(),
        )),
        SyncConfig {
            batch: TIP_HEIGHT,
            page: TIP_HEIGHT,
            retry_delay: Duration::ZERO,
            max_retry_delay: Duration::ZERO,
        },
        Arc::new(CachedNodeTip::new(unbounded.clone())),
    );
    let error = unbounded_syncer.sync_once().unwrap_err();
    let text = error.to_string();
    assert!(matches!(error, SyncError::Protocol(_)), "{text}");
    assert!(
        text.contains(&format!("{TIP_HEIGHT}-block page")),
        "the error must name the page it asked for: {text}"
    );
    assert!(
        text.contains(&ergo_walletd::chain_http::MAX_RESPONSE_BODY_BYTES.to_string()),
        "the error must name the cap: {text}"
    );
    assert!(
        text.contains("does not retry with a smaller page"),
        "the error must say why retrying is pointless: {text}"
    );
    assert_eq!(unbounded.requests().len(), 1, "one request, then it stops");
    assert!(matches!(
        unbounded_wallet.read().unwrap().rescan_state().unwrap(),
        RescanState::Failed { .. }
    ));
}

/// A fresh daemon over an existing wallet database is already at the tip and
/// applies nothing — the durable cursor is what makes a restart cheap, and this
/// is the path that keeps it honest.
#[test]
fn real_node_survives_a_daemon_restart_against_the_same_store() {
    let node_dir = tempfile::tempdir().unwrap();
    let (store, ids) = seeded_node(node_dir.path());
    let node = serve_node_api(&store);
    let wallet_dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_dir.path().join("wallet.redb");

    {
        let chain = CountingChain::new(daemon_client(&node.url(), NODE_API_KEY));
        let store = Arc::new(RedbWalletStore::open_standalone(&wallet_path).unwrap());
        let syncer = syncer(chain, store);
        assert!(syncer.sync_once().unwrap().completed);
    }

    let chain = CountingChain::new(daemon_client(&node.url(), NODE_API_KEY));
    let store = Arc::new(RedbWalletStore::open_standalone(&wallet_path).unwrap());
    let syncer = syncer(chain.clone(), store.clone());
    let report = syncer.sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.wallet_height, TIP_HEIGHT);
    assert_eq!(report.blocks_processed, 0);
    // Nothing to fetch: the durable cursor already equals the node tip, so the
    // loop finishes on its tip comparison without a single `blocks-since`.
    assert_eq!(chain.requests(), Vec::new());
    let read = store.read().unwrap();
    let cursor = read.scan_cursor().unwrap().unwrap();
    assert_eq!(cursor.height, TIP_HEIGHT);
    assert_eq!(cursor.header_id, Some(*ids.last().unwrap()));
}

/// Auth wiring, on the real router: the daemon's client carries the key as the
/// `api_key` header, a wrong key is the real 401 mapped to the real typed
/// error, and a missing key fails closed.
#[test]
fn real_node_api_key_gate_is_wired_and_enforced() {
    let node_dir = tempfile::tempdir().unwrap();
    let (store, _) = seeded_node(node_dir.path());
    let node = serve_node_api(&store);

    assert_eq!(
        raw_status(&node.url(), "/api/v1/chain/tip", Some(NODE_API_KEY)),
        200
    );
    assert_eq!(raw_status(&node.url(), "/api/v1/chain/tip", None), 401);
    assert_eq!(
        raw_status(&node.url(), "/api/v1/chain/tip", Some(b"wrong-key")),
        401
    );
    // The write path sits behind the same gate.
    assert_eq!(
        raw_status(
            &node.url(),
            "/api/v1/chain/transactions",
            Some(b"wrong-key")
        ),
        401
    );

    // A client holding the wrong key sees `Unauthorized` — not a transport
    // error, and not silently-open data.
    let wrong = daemon_client(&node.url(), b"wrong-key");
    assert!(matches!(
        wrong.committed_tip(),
        Err(ChainClientError::Unauthorized)
    ));
    assert!(matches!(
        wrong.blocks_since(BlocksSinceRequest {
            cursor: ChainCursor::genesis(),
            limit: 4,
        }),
        Err(ChainClientError::Unauthorized)
    ));

    // The daemon cannot be configured with no key at all (`Config::load` reads
    // it from a permission-gated file), so `Unauthorized` is the only way the
    // key can be wrong.
    let good = daemon_client(&node.url(), NODE_API_KEY);
    assert_eq!(good.committed_tip().unwrap().height, TIP_HEIGHT);
    assert_eq!(
        raw_status(
            &node.url(),
            &blocks_since_path(0, GENESIS_CURSOR_ID, 4),
            Some(NODE_API_KEY)
        ),
        200
    );
    assert_eq!(
        raw_status(
            &node.url(),
            &blocks_since_path(0, GENESIS_CURSOR_ID, 4),
            None
        ),
        401
    );
}

/// The genesis sentinel is a wire-level contract the real node enforces: height
/// 0 must carry the all-zero cursor id, and a positive height may not. The
/// daemon always sends the sentinel on its first request, so a drift here
/// would be a silent protocol break.
#[test]
fn real_node_enforces_the_genesis_cursor_identity() {
    let node_dir = tempfile::tempdir().unwrap();
    let (store, _) = seeded_node(node_dir.path());
    let node = serve_node_api(&store);
    let zero = "0".repeat(64);
    assert_eq!(
        raw_status(
            &node.url(),
            &blocks_since_path(1, &zero, 4),
            Some(NODE_API_KEY)
        ),
        400
    );
    assert_eq!(
        raw_status(
            &node.url(),
            &blocks_since_path(0, &"1".repeat(64), 4),
            Some(NODE_API_KEY)
        ),
        400
    );
    assert_eq!(
        raw_status(
            &node.url(),
            &blocks_since_path(0, GENESIS_CURSOR_ID, 4),
            Some(NODE_API_KEY)
        ),
        200
    );
}

/// A real reorg against the real node: the store is rolled back with its own
/// `rollback_to` and re-derived with different nonces, so the daemon's rewind
/// branch is driven by the node's real `blocks-since` answer rather than a
/// scripted response.
#[test]
fn real_node_reorg_returns_the_common_ancestor_and_the_daemon_follows_it() {
    let node_dir = tempfile::tempdir().unwrap();
    let (mut store, ids) = seeded_node(node_dir.path());
    let node = serve_node_api(&store);

    let wallet_dir = tempfile::tempdir().unwrap();
    let store_wallet = standalone_wallet(wallet_dir.path());
    let chain = CountingChain::new(daemon_client(&node.url(), NODE_API_KEY));
    let syncer = syncer(chain.clone(), store_wallet.clone());
    let report = syncer.sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.wallet_height, TIP_HEIGHT);
    let old_tip = report.tip;

    // Roll the node back to height 1 and re-derive 2..=3 with new nonces, so
    // height 1 is the common ancestor and the server's cloneable reader sees
    // the new chain without a restart.
    store.rollback_to(1, None, None).unwrap();
    assert_eq!(store.height(), 1);
    let mut parent = ModifierId::from_bytes(committed_id(&store, 1));
    for height in 2..=TIP_HEIGHT {
        let id = apply_block(&mut store, height, parent, [0xA0 + height as u8; 8]);
        parent = ModifierId::from_bytes(id);
    }
    assert_eq!(store.height(), TIP_HEIGHT);
    let new_tip_id = committed_id(&store, TIP_HEIGHT);
    assert_ne!(new_tip_id, old_tip.header_id);
    assert_ne!(new_tip_id, ids[1]);

    // The next pass asks at the stale cursor, is told "rewind to 1", then asks
    // again from the ancestor and receives the whole replacement fork. No panic,
    // no terminal failure, and the cursor ends on the new tip.
    let before_reorg = chain.requests().len();
    let report = syncer.sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.wallet_height, TIP_HEIGHT);
    assert_eq!(report.tip.height, TIP_HEIGHT);
    assert_eq!(report.tip.header_id, new_tip_id);
    assert_eq!(
        chain.requests()[before_reorg..],
        vec![(TIP_HEIGHT, 1), (1, 1), (2, 1)],
        "one ancestor probe at the stale cursor, then the two replacement blocks one \
         bounded page at a time"
    );
    let read = store_wallet.read().unwrap();
    let cursor = read.scan_cursor().unwrap().unwrap();
    assert_eq!(cursor.height, TIP_HEIGHT);
    assert_eq!(cursor.header_id, Some(new_tip_id));
    assert!(!read.scan_invalidated().unwrap());
}
