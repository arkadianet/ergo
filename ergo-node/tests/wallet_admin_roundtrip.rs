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

struct StubTxSubmitter;

#[async_trait]
impl TxSubmitter for StubTxSubmitter {
    async fn submit_transaction(&self, _tx_bytes: Vec<u8>) -> Result<String, WalletAdminError> {
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
