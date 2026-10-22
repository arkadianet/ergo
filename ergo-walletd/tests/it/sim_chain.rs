//! A small simulated chain with an address index, for the restore and
//! key-derivation tests.
//!
//! The blocks are real: every output is a serialized box whose id the daemon
//! re-derives in `convert_block`, so the wallet code under test sees exactly
//! the shapes it sees from a node. The address index is computed from those
//! same blocks, so the tests can compare an index-assisted restore against a
//! plain block scan of the same chain.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::AdditionalRegisters;
use ergo_wallet_service::{
    AddressHistory, AddressUsage, BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient,
    ChainClientError, ChainInput, ChainOutput, ChainSnapshot, ChainTransaction, CommittedTip,
    ForwardBlocksSince, IndexedTransaction, SubmitRequest, SubmitResponse, UtxoLookup,
};

/// What a test asks a block to contain.
pub struct TxSpec {
    pub inputs: Vec<[u8; 32]>,
    /// `(ErgoTree bytes, value)` of each output.
    pub outputs: Vec<(Vec<u8>, u64)>,
}

struct SimTx {
    tx_id: [u8; 32],
    inputs: Vec<[u8; 32]>,
    outputs: Vec<ChainOutput>,
}

struct SimBlock {
    block_id: [u8; 32],
    txs: Vec<SimTx>,
}

#[derive(Default)]
struct Inner {
    blocks: Vec<SimBlock>,
    /// Box id to the ErgoTree it is locked by.
    trees: BTreeMap<[u8; 32], Vec<u8>>,
}

pub struct SimChain {
    inner: Mutex<Inner>,
    /// Whether the node runs an address index.
    pub indexed: AtomicBool,
    /// Blocks the index is behind the node.
    pub index_lag: AtomicU32,
    /// The index names a different block than the chain holds.
    pub index_lies: AtomicBool,
    /// `(cursor height, limit)` of every `blocks-since` call.
    pub blocks_since_log: Mutex<Vec<(u32, u32)>>,
    /// Height of every `block_at` call.
    pub block_at_log: Mutex<Vec<u32>>,
    pub history_calls: AtomicUsize,
    pub usage_calls: AtomicUsize,
    /// Calls of any kind, for tests that assert the node was never asked.
    pub calls: AtomicUsize,
    /// The node reports a tip this many blocks below its real one.
    pub behind: AtomicU32,
    /// While set, every `blocks-since` fails with a transport error.
    pub down: AtomicBool,
}

impl SimChain {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            indexed: AtomicBool::new(true),
            index_lag: AtomicU32::new(0),
            index_lies: AtomicBool::new(false),
            blocks_since_log: Mutex::new(Vec::new()),
            block_at_log: Mutex::new(Vec::new()),
            history_calls: AtomicUsize::new(0),
            usage_calls: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            behind: AtomicU32::new(0),
            down: AtomicBool::new(false),
        })
    }

    pub fn height(&self) -> u32 {
        self.inner.lock().unwrap().blocks.len() as u32
    }

    pub fn tip(&self) -> CommittedTip {
        let inner = self.inner.lock().unwrap();
        self.visible_tip(&inner)
    }

    /// The tip the node reports: the real one, less `behind` blocks.
    fn visible_tip(&self, inner: &Inner) -> CommittedTip {
        let height = (inner.blocks.len() as u32).saturating_sub(self.behind.load(Ordering::SeqCst));
        match height {
            0 => CommittedTip::new(0, [0; 32]),
            height => CommittedTip::new(height, inner.blocks[height as usize - 1].block_id),
        }
    }

    pub fn push_empty(&self, count: u32) {
        for _ in 0..count {
            self.push_block(Vec::new());
        }
    }

    /// Append a block holding `txs`; returns each transaction's output box
    /// ids, in order.
    pub fn push_block(&self, txs: Vec<TxSpec>) -> Vec<Vec<[u8; 32]>> {
        let mut inner = self.inner.lock().unwrap();
        let height = inner.blocks.len() as u32 + 1;
        let mut created = Vec::new();
        let mut sim_txs = Vec::new();
        for (position, spec) in txs.into_iter().enumerate() {
            let tx_id = tx_id(height, position as u32);
            let mut outputs = Vec::new();
            for (index, (tree, value)) in spec.outputs.iter().enumerate() {
                let output = output_box(tx_id, index as u16, tree, *value, height);
                inner.trees.insert(output.box_id, tree.clone());
                outputs.push(output);
            }
            created.push(outputs.iter().map(|output| output.box_id).collect());
            sim_txs.push(SimTx {
                tx_id,
                inputs: spec.inputs,
                outputs,
            });
        }
        inner.blocks.push(SimBlock {
            block_id: block_id(height),
            txs: sim_txs,
        });
        created
    }

    /// Every transaction at or below `limit` that pays to or spends from one
    /// of `trees`.
    fn touching(&self, limit: u32, trees: &[Vec<u8>]) -> Vec<IndexedTransaction> {
        let inner = self.inner.lock().unwrap();
        let mut found = Vec::new();
        for (offset, block) in inner.blocks.iter().enumerate() {
            let height = offset as u32 + 1;
            if height > limit {
                break;
            }
            for tx in &block.txs {
                let pays = tx
                    .outputs
                    .iter()
                    .any(|output| trees.contains(&inner.trees[&output.box_id]));
                let spends = tx.inputs.iter().any(|input| {
                    inner
                        .trees
                        .get(input)
                        .is_some_and(|tree| trees.contains(tree))
                });
                if pays || spends {
                    found.push(IndexedTransaction {
                        tx_id: tx.tx_id,
                        height,
                        block_id: if self.index_lies.load(Ordering::SeqCst) {
                            [0xEE; 32]
                        } else {
                            block.block_id
                        },
                    });
                }
            }
        }
        found
    }

    fn indexed_height(&self) -> u32 {
        self.height()
            .saturating_sub(self.index_lag.load(Ordering::SeqCst))
    }
}

fn block_id(height: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0xB1;
    id[28..].copy_from_slice(&height.to_be_bytes());
    id
}

fn tx_id(height: u32, position: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0x7A;
    id[1..5].copy_from_slice(&height.to_be_bytes());
    id[5..9].copy_from_slice(&position.to_be_bytes());
    id
}

fn output_box(tx: [u8; 32], index: u16, tree: &[u8], value: u64, height: u32) -> ChainOutput {
    let parsed = read_ergo_tree(&mut VlqReader::new(tree)).expect("fixture tree parses");
    let candidate = ErgoBoxCandidate::new(
        value,
        parsed,
        height,
        Vec::<ergo_ser::token::Token>::new(),
        AdditionalRegisters::empty(),
    )
    .expect("valid fixture box");
    assert_eq!(
        candidate.ergo_tree_bytes(),
        tree,
        "the fixture tree must survive a round trip"
    );
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx),
        index,
    };
    ChainOutput {
        box_id: *ergo_box.box_id().expect("box id").as_bytes(),
        index,
        bytes: serialize_ergo_box(&ergo_box).expect("serializable box"),
    }
}

fn chain_block(inner: &Inner, height: u32) -> ChainBlock {
    let block = &inner.blocks[height as usize - 1];
    let parent = if height == 1 {
        [0; 32]
    } else {
        inner.blocks[height as usize - 2].block_id
    };
    ChainBlock {
        block_id: block.block_id,
        height,
        parent_id: parent,
        header_bytes: Vec::new(),
        transactions: block
            .txs
            .iter()
            .map(|tx| ChainTransaction {
                tx_id: tx.tx_id,
                inputs: tx
                    .inputs
                    .iter()
                    .map(|box_id| ChainInput {
                        box_id: *box_id,
                        index: 0,
                    })
                    .collect(),
                outputs: tx.outputs.clone(),
                // The wire carries the transaction's bytes beside its boxes.
                bytes: Some(
                    tx.outputs
                        .iter()
                        .flat_map(|output| output.bytes.iter().copied())
                        .collect(),
                ),
            })
            .collect(),
    }
}

impl ChainClient for SimChain {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.tip())
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.blocks_since_log
            .lock()
            .unwrap()
            .push((request.cursor.height, request.limit));
        if self.down.load(Ordering::SeqCst) {
            return Err(ChainClientError::Transport("connection refused".into()));
        }
        let inner = self.inner.lock().unwrap();
        let tip = self.visible_tip(&inner);
        let cursor = &request.cursor;
        let on_chain = if cursor.height == 0 {
            cursor.is_genesis_sentinel()
        } else {
            cursor.height <= tip.height
                && inner.blocks[cursor.height as usize - 1].block_id == cursor.header_id
        };
        if !on_chain {
            return Err(ChainClientError::Failure(
                "the simulated chain does not reorg".into(),
            ));
        }
        let last = tip.height.min(cursor.height.saturating_add(request.limit));
        let blocks = (cursor.height + 1..=last)
            .map(|height| chain_block(&inner, height))
            .collect();
        Ok(BlocksSinceResponse::Forward(ForwardBlocksSince {
            tip,
            blocks,
        }))
    }

    fn block_at(&self, height: u32, tip: CommittedTip) -> Result<ChainBlock, ChainClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.block_at_log.lock().unwrap().push(height);
        let inner = self.inner.lock().unwrap();
        let actual = self.visible_tip(&inner);
        if actual != tip {
            return Err(ChainClientError::stale_tip(tip, actual));
        }
        if height == 0 || height > tip.height {
            return Err(ChainClientError::Protocol(
                "block height is outside the committed range".into(),
            ));
        }
        Ok(chain_block(&inner, height))
    }

    fn address_history(
        &self,
        _network: NetworkPrefix,
        ergo_trees: &[Vec<u8>],
    ) -> Result<Option<AddressHistory>, ChainClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.history_calls.fetch_add(1, Ordering::SeqCst);
        if !self.indexed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let indexed_height = self.indexed_height();
        Ok(Some(AddressHistory {
            indexed_height,
            transactions: self.touching(indexed_height, ergo_trees),
        }))
    }

    fn addresses_used(
        &self,
        _network: NetworkPrefix,
        ergo_trees: &[Vec<u8>],
    ) -> Result<Option<AddressUsage>, ChainClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.usage_calls.fetch_add(1, Ordering::SeqCst);
        if !self.indexed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let indexed_height = self.indexed_height();
        Ok(Some(AddressUsage {
            indexed_height,
            used: ergo_trees
                .iter()
                .map(|tree| {
                    !self
                        .touching(indexed_height, std::slice::from_ref(tree))
                        .is_empty()
                })
                .collect(),
        }))
    }

    fn lookup_utxo(
        &self,
        _box_id: [u8; 32],
        _expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }
}

/// The wallet's own keys, derived from a phrase without a wallet: EIP-3
/// `m/44'/429'/account'/0/index`.
pub struct Keys {
    storage: ergo_wallet::storage::SecretStorage,
    _directory: tempfile::TempDir,
}

impl Keys {
    pub fn from_phrase(phrase: &str) -> Self {
        ergo_wallet::storage::use_fast_keystore_kdf_for_tests();
        let directory = tempfile::tempdir().unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(directory.path().to_path_buf());
        storage.restore(phrase, "", "pw", false).unwrap();
        storage.unlock("pw").unwrap();
        Self {
            storage,
            _directory: directory,
        }
    }

    pub fn external(&self, index: u32) -> [u8; 33] {
        self.account(0, index)
    }

    pub fn account(&self, account: u32, index: u32) -> [u8; 33] {
        use ergo_wallet::derivation::{DerivationPath, HARDENED_OFFSET};
        self.storage
            .unlocked()
            .unwrap()
            .master
            .derive_pubkey_at_path(&DerivationPath::from_components(vec![
                HARDENED_OFFSET | 44,
                HARDENED_OFFSET | 429,
                HARDENED_OFFSET | account,
                0,
                index,
            ]))
            .unwrap()
    }
}

/// The P2PK script the wallet matches for `pubkey`.
pub fn p2pk(pubkey: &[u8; 33]) -> Vec<u8> {
    ergo_ser::address::build_p2pk_tree_bytes(pubkey).unwrap()
}

/// A wallet daemon over a [`SimChain`]: seed host, syncer and store, built
/// the way `ergo-walletd` builds them.
pub struct Rig {
    _dir: tempfile::TempDir,
    pub chain: Arc<SimChain>,
    pub store: Arc<ergo_wallet_service::RedbWalletStore>,
    pub host: ergo_walletd::host::WalletHost,
    pub syncer: Arc<ergo_walletd::sync::StandaloneSyncer>,
}

impl Rig {
    pub fn new(chain: Arc<SimChain>) -> Self {
        use ergo_wallet_service::{RedbWalletStore, WalletService};
        use ergo_walletd::config::Network;
        use ergo_walletd::engine_chain::LifecycleChainAccess;
        use ergo_walletd::host::WalletHost;
        use ergo_walletd::sync::{StandaloneSyncer, SyncConfig};
        use ergo_walletd::tip::CachedNodeTip;
        ergo_wallet::storage::use_fast_keystore_kdf_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            RedbWalletStore::open_standalone(dir.path().join("wallet.redb"))
                .unwrap()
                .rebuild_history_on_key_additions(),
        );
        let chain_for_rig = chain.clone();
        let service = Arc::new(WalletService::new(store.clone(), chain.clone()));
        let host = WalletHost::new(
            store.clone(),
            service.clone(),
            Arc::new(LifecycleChainAccess::new(store.clone(), chain.clone())),
            dir.path(),
            Network::Testnet,
        )
        .unwrap();
        let syncer = Arc::new(
            StandaloneSyncer::new(
                service,
                SyncConfig {
                    retry_delay: std::time::Duration::ZERO,
                    max_retry_delay: std::time::Duration::ZERO,
                    ..SyncConfig::default()
                },
                Arc::new(CachedNodeTip::new(chain.clone())),
            )
            .with_network(Network::Testnet.prefix()),
        );
        Self {
            _dir: dir,
            chain: chain_for_rig,
            store,
            host,
            syncer,
        }
    }

    /// A new host over the same wallet database after the secret files are
    /// gone: what the operator gets by deleting `wallet/` to start over.
    pub fn host_without_secret(&self) -> ergo_walletd::host::WalletHost {
        use ergo_wallet_service::WalletService;
        use ergo_walletd::config::Network;
        use ergo_walletd::engine_chain::LifecycleChainAccess;
        let secrets = self._dir.path().join("wallet");
        std::fs::remove_dir_all(&secrets).unwrap();
        let service = Arc::new(WalletService::new(self.store.clone(), self.chain.clone()));
        ergo_walletd::host::WalletHost::new(
            self.store.clone(),
            service,
            Arc::new(LifecycleChainAccess::new(
                self.store.clone(),
                self.chain.clone(),
            )),
            self._dir.path(),
            Network::Testnet,
        )
        .unwrap()
    }

    pub async fn restore_and_unlock(&self, phrase: &str) {
        self.host
            .restore(phrase.to_string(), String::new(), "test".to_string(), false)
            .await
            .unwrap();
        self.host.unlock("test".to_string()).await.unwrap();
    }

    /// Run sync passes until the wallet has caught up with the node.
    pub fn sync(&self) -> ergo_walletd::sync::SyncReport {
        for _ in 0..64 {
            match self.host.sync_once(&self.syncer).unwrap() {
                Some(report) if report.completed => return report,
                Some(_) => {}
                None => panic!("the sync pass was skipped as idle"),
            }
        }
        panic!("the wallet never caught up");
    }

    pub fn read(&self) -> Box<dyn ergo_wallet_service::WalletRead> {
        use ergo_wallet_service::WalletStore;
        self.store.read().unwrap()
    }

    /// Everything a user can see of the wallet's history, in a form two
    /// wallets can be compared by.
    pub fn summary(&self) -> Summary {
        let read = self.read();
        let mut boxes: Vec<_> = read.all_boxes().unwrap();
        boxes.sort_by_key(|wallet_box| wallet_box.box_id);
        let mut txs: Vec<_> = read.all_transactions().unwrap();
        txs.sort_by_key(|tx| (tx.block_height, tx.tx_id));
        let mut keys: Vec<_> = read
            .tracked_pubkeys_with_paths()
            .unwrap()
            .into_iter()
            .map(|(_, pubkey, path)| (path, pubkey))
            .collect();
        keys.sort();
        let balance = read.balance().unwrap();
        Summary {
            boxes: boxes
                .iter()
                .map(|wallet_box| format!("{wallet_box:?}"))
                .collect(),
            txs: txs.iter().map(|tx| format!("{tx:?}")).collect(),
            keys,
            change: read.change_address_pubkey().unwrap(),
            confirmed: balance.confirmed_nano_ergs,
            immature: balance.immature_nano_ergs,
        }
    }

    pub fn invalidated(&self) -> bool {
        self.read().scan_invalidated().unwrap()
    }

    pub fn cursor(&self) -> Option<(u32, Option<[u8; 32]>)> {
        self.read()
            .scan_cursor()
            .unwrap()
            .map(|cursor| (cursor.height, cursor.header_id))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Summary {
    pub boxes: Vec<String>,
    pub txs: Vec<String>,
    pub keys: Vec<(Vec<u32>, [u8; 33])>,
    pub change: Option<[u8; 33]>,
    pub confirmed: u64,
    pub immature: u64,
}
