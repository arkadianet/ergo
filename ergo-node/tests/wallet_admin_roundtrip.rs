//! Integration test: NodeWalletAdmin init→status round-trip via the
//! channel-backed writer task.

use std::sync::Arc;

use async_trait::async_trait;
use ergo_api::wallet::WalletAdmin;
use ergo_api::wallet::WalletAdminError;
use ergo_node::node::wallet_bridge::{
    run_wallet_writer, ChainStateAccessor, NodeWalletAdmin, TxSubmitter, WriterConfig,
};

struct StubChainAccessor;

impl ChainStateAccessor for StubChainAccessor {
    fn wallet_scan_height(&self) -> u32 {
        0
    }

    fn tip_height(&self) -> u32 {
        0
    }

    fn is_pruned(&self) -> bool {
        false
    }

    fn read_block_at(&self, _height: u32) -> Option<ergo_state::wallet::scan::RescanBlock> {
        None
    }
}

/// Chain accessor with a configurable tip height — drives the EIP-27
/// candidate-height (`tip+1`) trigger in `native_balance`.
struct StubChainAccessorTip(u32);

impl ChainStateAccessor for StubChainAccessorTip {
    fn wallet_scan_height(&self) -> u32 {
        self.0
    }

    fn tip_height(&self) -> u32 {
        self.0
    }

    fn is_pruned(&self) -> bool {
        false
    }

    fn read_block_at(&self, _height: u32) -> Option<ergo_state::wallet::scan::RescanBlock> {
        None
    }
}

struct StubTxSubmitter;

#[async_trait]
impl TxSubmitter for StubTxSubmitter {
    async fn submit_transaction(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> Result<String, ergo_api::types::SubmitError> {
        Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string())
    }
}

// ----- happy path -----

#[tokio::test]
async fn admin_init_status_roundtrip() {
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let dir = tempfile::tempdir().unwrap();

    let storage = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet")),
    ));
    let state = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::state::WalletState::empty(false),
    ));
    let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
    let chain: Arc<dyn ChainStateAccessor> = Arc::new(StubChainAccessor);
    let cfg = WriterConfig {
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        expose_private_keys: false,
        reemission: None,
    };

    let submitter: std::sync::Arc<dyn TxSubmitter> = std::sync::Arc::new(StubTxSubmitter);
    let mempool: std::sync::Arc<dyn ergo_api::MempoolView> =
        std::sync::Arc::new(ergo_api::NoopMempoolView::new());
    tokio::spawn(run_wallet_writer(
        rx, storage, state, db, chain, cfg, submitter, mempool,
    ));

    let admin = NodeWalletAdmin::new(tx);

    // Before init: wallet is uninitialized.
    let status_before = admin.status().await.unwrap();
    assert!(
        !status_before.is_initialized,
        "wallet must report uninitialized before init()"
    );

    // Init: generate a 24-word mnemonic.
    let mnemonic = admin
        .init("test-password".to_string(), String::new(), 24)
        .await
        .unwrap();
    assert_eq!(
        mnemonic.split_whitespace().count(),
        24,
        "init() must return a 24-word mnemonic"
    );

    // After init: wallet is initialized (still locked).
    let status_after = admin.status().await.unwrap();
    assert!(
        status_after.is_initialized,
        "wallet must report initialized after init()"
    );
    assert!(
        !status_after.is_unlocked,
        "wallet must remain locked after init()"
    );
}

// ----- error paths -----

#[tokio::test]
async fn get_private_key_gated_by_expose_flag_false() {
    // With `WriterConfig.expose_private_keys = false`, the route
    // returns `Forbidden` before touching wallet state — so the test
    // doesn't need an initialized wallet to drive the gate.
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet")),
    ));
    let state = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::state::WalletState::empty(false),
    ));
    let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
    let chain: Arc<dyn ChainStateAccessor> = Arc::new(StubChainAccessor);
    let cfg = WriterConfig {
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        expose_private_keys: false,
        reemission: None,
    };
    let submitter: std::sync::Arc<dyn TxSubmitter> = std::sync::Arc::new(StubTxSubmitter);
    let mempool: std::sync::Arc<dyn ergo_api::MempoolView> =
        std::sync::Arc::new(ergo_api::NoopMempoolView::new());
    tokio::spawn(run_wallet_writer(
        rx, storage, state, db, chain, cfg, submitter, mempool,
    ));
    let admin = NodeWalletAdmin::new(tx);

    let request = ergo_api::wallet::admin_advanced::GetPrivateKeyRequest {
        address: "9hkXFKDcMUSXn1jUUH4ynjLNiVcyZxKqXjMtqEnDdJyHfXCPmiQ".to_string(),
    };
    let err = admin
        .get_private_key(request)
        .await
        .expect_err("must reject when expose_private_keys = false");
    match err {
        WalletAdminError::Forbidden(msg) => {
            assert!(
                msg.contains("expose_private_keys"),
                "Forbidden message must name the flag, got: {msg}"
            );
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

// ----- oracle parity -----

/// End-to-end guard for the canonical-P2PK send-path fix, driving the REAL
/// `build_unsigned_tx` via `NodeWalletAdmin::transaction_generate_unsigned`
/// (which builds but does not sign, so it needs no `lookup_utxo`). Seeds a
/// funded wallet box, builds an unsigned payment, decodes it, and asserts the
/// recipient output's ErgoTree re-encodes to the recipient's P2PK address.
///
/// This closes the gap the in-isolation `wallet_send_e2e` test left open: that
/// test asserts the tree builders directly but never exercises the send path,
/// so it could not catch a regression that rewired `build_unsigned_tx` back to
/// the segregated `build_prove_dlog_ergo_tree` (which encodes to P2S, the wrong
/// address). This test fails if that ever happens.
#[tokio::test]
async fn generate_unsigned_emits_canonical_p2pk_recipient_tree() {
    use ergo_state::wallet::tables::WALLET_BOXES;
    use ergo_state::wallet::types::{BoxProvenance, BoxStatus, WalletBox};

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet")),
    ));
    let state = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::state::WalletState::empty(false),
    ));
    let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());

    // Seed a confirmed wallet box with enough ERG to fund payment + fee +
    // change, BEFORE the db Arc moves into the writer task. The auto-selection
    // path reads value/tokens from WALLET_BOXES; it does not re-verify
    // ownership at build time (signing would, but generateUnsigned skips it).
    let funded_box = WalletBox {
        box_id: [0x11; 32],
        creation_tx_id: [0x22; 32],
        creation_output_index: 0,
        creation_height: 1,
        value: 1_000_000_000, // 1 ERG — covers a 0.1 ERG payment + fee + change
        assets: vec![],
        status: BoxStatus::Confirmed,
        provenance: BoxProvenance::Owned,
    };
    {
        let wtxn = db.begin_write().unwrap();
        {
            let mut tbl = wtxn.open_table(WALLET_BOXES).unwrap();
            tbl.insert(funded_box.box_id, bincode::serialize(&funded_box).unwrap())
                .unwrap();
        }
        wtxn.commit().unwrap();
    }

    let chain: Arc<dyn ChainStateAccessor> = Arc::new(StubChainAccessor);
    let cfg = WriterConfig {
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        expose_private_keys: false,
        reemission: None,
    };
    let submitter: std::sync::Arc<dyn TxSubmitter> = std::sync::Arc::new(StubTxSubmitter);
    let mempool: std::sync::Arc<dyn ergo_api::MempoolView> =
        std::sync::Arc::new(ergo_api::NoopMempoolView::new());
    tokio::spawn(run_wallet_writer(
        rx, storage, state, db, chain, cfg, submitter, mempool,
    ));
    let admin = NodeWalletAdmin::new(tx);

    // init + unlock — unlock auto-derives keys AND backfills the change
    // address (the bug-B fix), so the build path has a change target.
    admin
        .init("pw".to_string(), String::new(), 24)
        .await
        .unwrap();
    admin.unlock("pw".to_string()).await.unwrap();

    // Recipient = a tracked wallet address (any valid mainnet P2PK works;
    // using our own keeps the vector self-contained).
    let addrs = admin.addresses().await.unwrap();
    let recipient = addrs
        .0
        .first()
        .expect("at least one visible address")
        .clone();
    assert!(recipient.starts_with('9'), "mainnet P2PK starts with 9");

    // Build an unsigned payment through the real send path.
    let req = ergo_api::wallet::sending::TransactionGenerateUnsignedRequest {
        requests: vec![ergo_api::wallet::sending::PaymentRequestDto {
            address: recipient.clone(),
            value: 100_000_000, // 0.1 ERG
            assets: vec![],
        }],
        inputs: None,
        data_inputs: None,
        fee: None,
    };
    let resp = admin
        .transaction_generate_unsigned(req)
        .await
        .expect("generateUnsigned must succeed with a funded box + change address");

    // Decode the unsigned tx and re-encode the recipient output's tree. The
    // recipient output is the first output candidate (payments precede fee +
    // change in the builder's output order).
    let bytes = hex::decode(&resp.unsigned_tx.bytes).expect("hex");
    let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
    let utx = ergo_ser::transaction::read_unsigned_transaction(&mut r).expect("decode unsigned tx");
    let recipient_out = &utx.output_candidates[0];
    let encoded = ergo_ser::address::encode_address_from_tree_bytes(
        ergo_ser::address::NetworkPrefix::Mainnet,
        recipient_out.ergo_tree_bytes(),
    )
    .expect("encode recipient output tree");
    assert_eq!(
        encoded, recipient,
        "recipient output tree must re-encode to the P2PK address it was built for \
         (canonical, non-segregated) — a P2S/segregated tree would fail this",
    );
}

// ----- native balance (EIP-27) -----

/// End-to-end proof of the symptom fix: on an EIP-27 net past activation, the
/// native balance holds back the re-emission tokens a reward box owes
/// (`reserved`), so `available = confirmed − reserved` instead of the
/// over-reported gross. The reserve is computed by the shared consensus helper
/// at candidate height `tip+1`.
#[tokio::test]
async fn native_balance_reserves_eip27_reward_box_tokens() {
    use ergo_state::wallet::tables::WALLET_BOXES;
    use ergo_state::wallet::types::{BoxProvenance, BoxStatus, WalletBox};

    const REEMISSION_TOKEN: [u8; 32] = [0x11; 32];
    const OTHER_TOKEN: [u8; 32] = [0x22; 32];
    const ACTIVATION: u32 = 100;

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet")),
    ));
    let state = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::state::WalletState::empty(false),
    ));
    let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
    let db_for_seed = db.clone();
    // tip 200 → candidate height 201 > activation 100 → the EIP-27 spend trigger fires.
    let chain: Arc<dyn ChainStateAccessor> = Arc::new(StubChainAccessorTip(200));
    let cfg = WriterConfig {
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        expose_private_keys: false,
        reemission: Some(ergo_validation::ReemissionRuleInputs {
            activation_height: ACTIVATION,
            reemission_token_id: REEMISSION_TOKEN,
            pay_to_reemission_tree: vec![0u8], // unused by the reserve estimate
        }),
    };
    let submitter: std::sync::Arc<dyn TxSubmitter> = std::sync::Arc::new(StubTxSubmitter);
    let mempool: std::sync::Arc<dyn ergo_api::MempoolView> =
        std::sync::Arc::new(ergo_api::NoopMempoolView::new());
    tokio::spawn(run_wallet_writer(
        rx, storage, state, db, chain, cfg, submitter, mempool,
    ));
    let admin = NodeWalletAdmin::new(tx);

    // Initialize so the wallet is not Uninitialized (balance is a read — works locked).
    admin
        .init("pw".to_string(), String::new(), 24)
        .await
        .unwrap();

    // Seed two Confirmed boxes: a reward box below the 100k-ERG floor carrying 7
    // re-emission tokens, and an ordinary box with a different token.
    let reward = WalletBox {
        box_id: [0xAA; 32],
        creation_tx_id: [0xA1; 32],
        creation_output_index: 0,
        creation_height: 150,
        value: 1_000_000_000,
        assets: vec![(REEMISSION_TOKEN, 7)],
        status: BoxStatus::Confirmed,
        provenance: BoxProvenance::MinerReward,
    };
    let ordinary = WalletBox {
        box_id: [0xBB; 32],
        creation_tx_id: [0xB1; 32],
        creation_output_index: 0,
        creation_height: 150,
        value: 5_000_000_000,
        assets: vec![(OTHER_TOKEN, 3)],
        status: BoxStatus::Confirmed,
        provenance: BoxProvenance::Owned,
    };
    {
        let w = db_for_seed.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_BOXES).unwrap();
            t.insert(reward.box_id, bincode::serialize(&reward).unwrap())
                .unwrap();
            t.insert(ordinary.box_id, bincode::serialize(&ordinary).unwrap())
                .unwrap();
        }
        w.commit().unwrap();
    }

    let bal = admin.native_balance(false).await.unwrap();

    // confirmed = 1e9 + 5e9; reserved = 7 (re-emission tokens the reward box owes);
    // available = confirmed − reserved (NOT the over-reported gross).
    assert_eq!(bal.nano_erg.confirmed, "6000000000");
    assert_eq!(bal.nano_erg.reserved, "7");
    assert_eq!(bal.nano_erg.available, "5999999993");
    assert_eq!(bal.nano_erg.immature, "0");

    let r = bal
        .reemission
        .expect("reemission block present on an EIP-27 net past activation");
    assert_eq!(r.reserved_token_amount, "7");
    assert_eq!(r.reserved_box_count, 1);
    assert!(!r.reserved_exceeds_confirmed);
    assert_eq!(r.token_id, hex::encode(REEMISSION_TOKEN));

    // The re-emission token is omitted from assets; the other token is kept.
    assert_eq!(
        bal.assets.len(),
        1,
        "re-emission token must be omitted from assets"
    );
    assert_eq!(bal.assets[0].token_id, hex::encode(OTHER_TOKEN));
    assert_eq!(bal.assets[0].amount, "3");

    // Unconfirmed delta is null unless explicitly requested.
    assert!(bal.unconfirmed.is_none());
}

/// Native read endpoints end-to-end: status, paged boxes (sorted before
/// paging), single-box lookup (present + absent), and empty transactions.
#[tokio::test]
async fn native_reads_status_boxes_and_lookup() {
    use ergo_api::wallet::native::dto::NetworkDto;
    use ergo_state::wallet::tables::WALLET_BOXES;
    use ergo_state::wallet::types::{BoxProvenance, BoxStatus, WalletBox};

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet")),
    ));
    let state = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::state::WalletState::empty(false),
    ));
    let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
    let db_seed = db.clone();
    let chain: Arc<dyn ChainStateAccessor> = Arc::new(StubChainAccessorTip(200));
    let cfg = WriterConfig {
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        expose_private_keys: false,
        reemission: None,
    };
    let submitter: std::sync::Arc<dyn TxSubmitter> = std::sync::Arc::new(StubTxSubmitter);
    let mempool: std::sync::Arc<dyn ergo_api::MempoolView> =
        std::sync::Arc::new(ergo_api::NoopMempoolView::new());
    tokio::spawn(run_wallet_writer(
        rx, storage, state, db, chain, cfg, submitter, mempool,
    ));
    let admin = NodeWalletAdmin::new(tx);

    admin
        .init("pw".to_string(), String::new(), 24)
        .await
        .unwrap();

    // Status: initialized, locked, mainnet, tip 200.
    let st = admin.native_status().await.unwrap();
    assert!(st.initialized && st.locked);
    assert_eq!(st.tip_height, 200);
    assert!(matches!(st.network, NetworkDto::Mainnet));

    // Seed two confirmed boxes at heights 100 and 200.
    let mk = |bid: u8, h: u32, val: u64| WalletBox {
        box_id: [bid; 32],
        creation_tx_id: [bid; 32],
        creation_output_index: 0,
        creation_height: h,
        value: val,
        assets: vec![],
        status: BoxStatus::Confirmed,
        provenance: BoxProvenance::Owned,
    };
    let lo = mk(0xA0, 100, 1_000);
    let hi = mk(0xB0, 200, 2_000);
    {
        let w = db_seed.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_BOXES).unwrap();
            t.insert(lo.box_id, bincode::serialize(&lo).unwrap())
                .unwrap();
            t.insert(hi.box_id, bincode::serialize(&hi).unwrap())
                .unwrap();
        }
        w.commit().unwrap();
    }

    // Boxes: total 2, sorted (creationHeight desc) → the height-200 box first.
    let page = admin.native_boxes(0, 50).await.unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].box_id, hex::encode([0xB0; 32]));
    assert_eq!(page.items[0].value, "2000");
    assert_eq!(page.items[1].box_id, hex::encode([0xA0; 32]));

    // Paging window: limit 1 → one item, total still the full count.
    let p1 = admin.native_boxes(0, 1).await.unwrap();
    assert_eq!(p1.items.len(), 1);
    assert_eq!(p1.total, 2);
    assert_eq!(p1.items[0].box_id, hex::encode([0xB0; 32]));

    // Single-box lookup: present + absent.
    assert!(admin
        .native_box_by_id(hex::encode([0xA0; 32]))
        .await
        .unwrap()
        .is_some());
    assert!(admin
        .native_box_by_id(hex::encode([0xCC; 32]))
        .await
        .unwrap()
        .is_none());

    // No transactions seeded → empty page.
    let txs = admin.native_transactions(0, 50).await.unwrap();
    assert_eq!(txs.total, 0);
    assert!(txs.items.is_empty());
}

/// codex P1-3: `changeAddress` is persisted public metadata — native status must
/// surface it even while the wallet is LOCKED (it is `null` only when unset).
#[tokio::test]
async fn native_status_shows_change_address_while_locked() {
    use ergo_state::wallet::tables::WALLET_CHANGE_ADDRESS;

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet")),
    ));
    let state = Arc::new(parking_lot::RwLock::new(
        ergo_wallet::state::WalletState::empty(false),
    ));
    let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
    let db_seed = db.clone();
    let chain: Arc<dyn ChainStateAccessor> = Arc::new(StubChainAccessor);
    let cfg = WriterConfig {
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        expose_private_keys: false,
        reemission: None,
    };
    let submitter: std::sync::Arc<dyn TxSubmitter> = std::sync::Arc::new(StubTxSubmitter);
    let mempool: std::sync::Arc<dyn ergo_api::MempoolView> =
        std::sync::Arc::new(ergo_api::NoopMempoolView::new());
    tokio::spawn(run_wallet_writer(
        rx, storage, state, db, chain, cfg, submitter, mempool,
    ));
    let admin = NodeWalletAdmin::new(tx);

    admin
        .init("pw".to_string(), String::new(), 24)
        .await
        .unwrap();

    // Persist a change-address pubkey (the secp256k1 generator — a valid point)
    // directly, and DO NOT unlock.
    let pk_bytes =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    let pk: [u8; 33] = pk_bytes.try_into().unwrap();
    {
        let w = db_seed.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_CHANGE_ADDRESS).unwrap();
            t.insert((), pk).unwrap();
        }
        w.commit().unwrap();
    }

    let st = admin.native_status().await.unwrap();
    assert!(st.locked, "wallet must be locked (never unlocked)");
    let expected = ergo_wallet::address::pubkey_to_p2pk_address(
        &pk,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
    .unwrap();
    assert_eq!(
        st.change_address.as_deref(),
        Some(expected.as_str()),
        "changeAddress must be surfaced while locked (codex P1-3)",
    );
}
