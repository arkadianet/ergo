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

/// Chain accessor that ALSO exposes EIP-27 rules via `reemission_rules()` — the
/// source the tx-build/select path reads (the self-verify gate + validator read
/// the same), distinct from the balance path's `cfg.reemission`.
struct StubChainReemission {
    tip: u32,
    rules: ergo_validation::ReemissionRuleInputs,
}

impl ChainStateAccessor for StubChainReemission {
    fn wallet_scan_height(&self) -> u32 {
        self.tip
    }

    fn tip_height(&self) -> u32 {
        self.tip
    }

    fn is_pruned(&self) -> bool {
        false
    }

    fn read_block_at(&self, _height: u32) -> Option<ergo_state::wallet::scan::RescanBlock> {
        None
    }

    fn reemission_rules(&self) -> Option<&ergo_validation::ReemissionRuleInputs> {
        Some(&self.rules)
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

/// Submitter that always rejects with a configurable typed reason — used to drive
/// the native `send` idempotency mapping (`duplicate` → accepted; other → error)
/// and to PROVE the known-tx short-circuit never submits.
struct RejectingSubmitter {
    reason: String,
}

#[async_trait]
impl TxSubmitter for RejectingSubmitter {
    async fn submit_transaction(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> Result<String, ergo_api::types::SubmitError> {
        Err(ergo_api::types::SubmitError {
            reason: self.reason.clone(),
            detail: None,
        })
    }
}

/// A minimal VALID serialized signed transaction (1 empty-proof input, 1
/// always-true output) + its computed tx id. Enough to drive the `send.signed`
/// path (txId computation + idempotency); it is never actually validated here.
fn minimal_signed_tx() -> (Vec<u8>, [u8; 32]) {
    // `00 08 d3` = Const(SSigmaProp, TrivialProp::true): a SigmaProp root, the
    // only kind a box script may have (CheckDeserializedScriptIsSigmaProp).
    let tree =
        ergo_ser::ergo_tree::read_ergo_tree(&mut ergo_primitives::reader::VlqReader::new(&[
            0x00, 0x08, 0xd3,
        ]))
        .unwrap();
    let out = ergo_ser::ergo_box::ErgoBoxCandidate::new(
        1_000_000,
        tree,
        1,
        vec![],
        ergo_ser::register::AdditionalRegisters::empty(),
    )
    .unwrap();
    let input = ergo_ser::input::Input {
        box_id: ergo_primitives::digest::Digest32::from_bytes([0x55; 32]),
        spending_proof: ergo_ser::input::SpendingProof::new(
            Vec::new(),
            ergo_ser::input::ContextExtension::empty(),
        )
        .unwrap(),
    };
    let tx = ergo_ser::transaction::Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![out],
    };
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_transaction(&mut w, &tx).unwrap();
    let id = ergo_ser::transaction::transaction_id(&tx).unwrap();
    (w.result(), *id.as_bytes())
}

/// Spawn a writer task with the given submitter; returns the admin handle, a db
/// clone for direct seeding, and the tempdir guard (keep it alive).
fn spawn_writer(
    submitter: Arc<dyn TxSubmitter>,
) -> (NodeWalletAdmin, Arc<redb::Database>, tempfile::TempDir) {
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
        reemission: None,
    };
    let mempool: std::sync::Arc<dyn ergo_api::MempoolView> =
        std::sync::Arc::new(ergo_api::NoopMempoolView::new());
    tokio::spawn(run_wallet_writer(
        rx, storage, state, db, chain, cfg, submitter, mempool,
    ));
    (NodeWalletAdmin::new(tx), db_seed, dir)
}

/// `send.signed` idempotency (codex P0-4): a tx whose id is already a confirmed
/// wallet row short-circuits to `accepted:true` + its summary WITHOUT submitting.
/// The rejecting submitter proves no submit occurs (else the response would error).
#[tokio::test]
async fn native_send_signed_known_tx_short_circuits() {
    use ergo_api::wallet::native::dto::{SendTxRequest, TxRepr};
    use ergo_state::wallet::tables::{wallet_tx_key, WALLET_TXS};
    use ergo_state::wallet::types::WalletTransaction;

    let (signed_bytes, tx_id) = minimal_signed_tx();
    let (admin, db_seed, _dir) = spawn_writer(Arc::new(RejectingSubmitter {
        reason: "should_not_submit".to_string(),
    }));

    // Seed a confirmed wallet tx row with the SAME id.
    let wt = WalletTransaction {
        tx_id,
        block_height: 150,
        block_id: [0xCD; 32],
        wallet_outputs: vec![[0x01; 32]],
        wallet_inputs: vec![[0x02; 32]],
    };
    {
        let w = db_seed.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_TXS).unwrap();
            t.insert(
                wallet_tx_key(wt.block_height, &wt.tx_id),
                bincode::serialize(&wt).unwrap(),
            )
            .unwrap();
        }
        w.commit().unwrap();
    }

    let resp = admin
        .send_transaction(SendTxRequest::Signed {
            signed_transaction: TxRepr::from_bytes(&signed_bytes),
        })
        .await
        .expect("a known tx must short-circuit, not submit");
    assert!(resp.accepted);
    assert_eq!(resp.tx_id, hex::encode(tx_id));
    let summary = resp
        .transaction
        .expect("a known confirmed tx returns its summary");
    assert_eq!(summary.tx_id, hex::encode(tx_id));
    assert_eq!(summary.block_height, 150);
}

/// `send.signed` of an unknown tx the pool already holds: the typed `duplicate`
/// submit reason is an idempotent `accepted:true` (never a 5xx on a re-seen tx).
#[tokio::test]
async fn native_send_signed_duplicate_is_idempotent_accept() {
    use ergo_api::wallet::native::dto::{SendTxRequest, TxRepr};

    let (signed_bytes, tx_id) = minimal_signed_tx();
    let (admin, _db, _dir) = spawn_writer(Arc::new(RejectingSubmitter {
        reason: "duplicate".to_string(),
    }));

    let resp = admin
        .send_transaction(SendTxRequest::Signed {
            signed_transaction: TxRepr::from_bytes(&signed_bytes),
        })
        .await
        .expect("a duplicate is an idempotent accept");
    assert!(resp.accepted);
    assert_eq!(resp.tx_id, hex::encode(tx_id));
    assert!(resp.transaction.is_none(), "no confirmed row yet");
}

/// `send.signed` of an unknown tx the node rejects for a real reason surfaces a
/// client error carrying the typed reason — never an opaque 5xx.
#[tokio::test]
async fn native_send_signed_real_rejection_is_error() {
    use ergo_api::wallet::native::dto::{SendTxRequest, TxRepr};

    let (signed_bytes, _tx_id) = minimal_signed_tx();
    let (admin, _db, _dir) = spawn_writer(Arc::new(RejectingSubmitter {
        reason: "too_big".to_string(),
    }));

    let err = admin
        .send_transaction(SendTxRequest::Signed {
            signed_transaction: TxRepr::from_bytes(&signed_bytes),
        })
        .await
        .expect_err("a real rejection must be an error");
    match err {
        WalletAdminError::BadRequest(m) => assert!(m.contains("too_big")),
        other => panic!("expected BadRequest carrying the reason, got {other:?}"),
    }
}

/// `send.signed` with valid-hex-but-not-a-transaction bytes is a client error
/// (`bad_request` 400), NOT a server fault (500) from the txId helper (workflow P1).
#[tokio::test]
async fn native_send_signed_malformed_bytes_is_bad_request() {
    use ergo_api::wallet::native::dto::{SendTxRequest, TxRepr};

    let (admin, _db, _dir) = spawn_writer(Arc::new(RejectingSubmitter {
        reason: "should_not_reach_submit".to_string(),
    }));
    // `00` is valid hex (one 0x00 byte) but not a serialized Transaction.
    let err = admin
        .send_transaction(SendTxRequest::Signed {
            signed_transaction: TxRepr::from_bytes(&[0x00]),
        })
        .await
        .expect_err("malformed tx bytes must be rejected");
    assert!(
        matches!(err, WalletAdminError::BadRequest(_)),
        "malformed signed tx must be bad_request, not internal: {err:?}"
    );
}

/// `send.intent` requires an unlocked wallet (it builds + signs with the wallet's
/// own secrets): locked → `wallet_locked`.
#[tokio::test]
async fn native_send_intent_locked_rejects() {
    use ergo_api::wallet::native::dto::{InputSource, OutputIntent, SendTxRequest, TxIntent};

    let (admin, _db, _dir) = spawn_writer(Arc::new(StubTxSubmitter));
    // Initialized but locked.
    admin
        .init("pw".to_string(), String::new(), 24)
        .await
        .unwrap();

    let intent = TxIntent {
        outputs: vec![OutputIntent::Payment {
            address: "9hHDQb26AjnJUXxcqriqY1mnhpLuUeC81C4pggtK7tupr92Ma1MG".to_string(),
            value: "1000000000".to_string(),
            assets: vec![],
            registers: None,
        }],
        fee: None,
        inputs: InputSource::default(),
        data_inputs: Default::default(),
        change_address: None,
        allow_reemission_spend: false,
        allow_token_burn: false,
    };
    let err = admin
        .send_transaction(SendTxRequest::Intent { intent })
        .await
        .expect_err("intent send requires unlock");
    assert!(matches!(err, WalletAdminError::Locked), "got {err:?}");
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
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

/// Native `boxes/select` end-to-end through the channel-backed writer: a target
/// that pulls in a reward box triggers the EIP-27 burn (reported, not folded), the
/// re-emission token is stripped from change while an ordinary token surplus is
/// kept, and `allowReemissionSpend=false` is fail-closed.
#[tokio::test]
async fn native_select_boxes_burn_aware_dry_run() {
    use ergo_api::wallet::native::dto::{BoxSelectRequest, InputSource, SelectTarget};
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
    let db_seed = db.clone();
    let rules = ergo_validation::ReemissionRuleInputs {
        activation_height: ACTIVATION,
        reemission_token_id: REEMISSION_TOKEN,
        pay_to_reemission_tree: vec![0u8], // unused by the dry-run (no tree parse)
    };
    // tip 200 → candidate height 201 > activation 100 → the EIP-27 trigger fires.
    let chain: Arc<dyn ChainStateAccessor> = Arc::new(StubChainReemission { tip: 200, rules });
    let cfg = WriterConfig {
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        expose_private_keys: false,
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
        reemission: None, // build/select read chain.reemission_rules(), not cfg
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
    // select requires an unlocked wallet (design §2).
    admin.unlock("pw".to_string()).await.unwrap();

    // A reward box (<= floor, 7 re-emission tokens) and a larger ordinary box
    // (different token). Greedy selection takes the ordinary box first, so a
    // target above its value pulls in the reward box → the burn fires.
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
        let w = db_seed.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_BOXES).unwrap();
            t.insert(reward.box_id, bincode::serialize(&reward).unwrap())
                .unwrap();
            t.insert(ordinary.box_id, bincode::serialize(&ordinary).unwrap())
                .unwrap();
        }
        w.commit().unwrap();
    }

    let req = |allow: bool| BoxSelectRequest {
        target: SelectTarget {
            nano_erg: "5500000000".to_string(), // > ordinary alone → needs the reward box too
            assets: vec![],
        },
        inputs: InputSource::Auto {
            min_confirmations: 0,
            exclude_box_ids: vec![],
        },
        change_address: None,
        allow_reemission_spend: allow,
    };

    // Fail-closed without opt-in.
    let denied = admin.select_boxes(req(false)).await.unwrap_err();
    assert!(
        matches!(denied, WalletAdminError::ReemissionSpendNotAllowed(_)),
        "a reward-box selection must be rejected when allowReemissionSpend=false: {denied:?}"
    );

    // With opt-in: both boxes selected, burn reported, token stripped from change.
    let plan = admin.select_boxes(req(true)).await.unwrap();
    assert_eq!(plan.inputs_selected.len(), 2, "ordinary + reward selected");
    let burn = plan
        .reemission_burn
        .expect("a reward-box selection incurs an EIP-27 burn");
    assert_eq!(burn.tokens_burned, "7");
    assert_eq!(burn.nano_erg_routed, "7");
    assert_eq!(burn.token_id, hex::encode(REEMISSION_TOKEN));
    // change = 6e9 inputs − 5.5e9 target − 7 burn.
    assert_eq!(plan.change.nano_erg, "499999993");
    // The re-emission token is burned (absent from change); the ordinary surplus stays.
    assert_eq!(
        plan.change.assets.len(),
        1,
        "only the ordinary token in change"
    );
    assert_eq!(plan.change.assets[0].token_id, hex::encode(OTHER_TOKEN));
    assert_eq!(plan.change.assets[0].amount, "3");
    assert_eq!(plan.as_of, 200);

    // P0 (codex): the re-emission token can NEVER be a selection target when a
    // reward box is spent — it must be burned, not delivered. Even with the spend
    // opt-in, targeting it is rejected (a payment output carrying it would make the
    // built tx fail `verify_reemission_spending`).
    let target_token = BoxSelectRequest {
        target: SelectTarget {
            nano_erg: "100000000".to_string(),
            assets: vec![ergo_api::wallet::native::dto::WalletAssetDto {
                token_id: hex::encode(REEMISSION_TOKEN),
                amount: "1".to_string(),
            }],
        },
        inputs: InputSource::Auto {
            min_confirmations: 0,
            exclude_box_ids: vec![],
        },
        change_address: None,
        allow_reemission_spend: true,
    };
    let err = admin.select_boxes(target_token).await.unwrap_err();
    assert!(
        matches!(err, WalletAdminError::ReemissionSpendNotAllowed(_)),
        "targeting the re-emission token must be rejected: {err:?}"
    );

    // P1b (codex): `boxIds` is EXACT (uses ALL listed boxes, like build) — so the
    // dry-run cannot under-report the burn vs what build would spend. Selecting the
    // reward box explicitly reports its 7-token burn.
    let exact = BoxSelectRequest {
        target: SelectTarget {
            nano_erg: "100000000".to_string(),
            assets: vec![],
        },
        inputs: InputSource::BoxIds {
            box_ids: vec![hex::encode([0xAA; 32])], // the reward box only
        },
        change_address: None,
        allow_reemission_spend: true,
    };
    let plan = admin.select_boxes(exact).await.unwrap();
    assert_eq!(plan.inputs_selected.len(), 1, "exactly the listed box");
    assert_eq!(
        plan.reemission_burn
            .expect("reward box burns")
            .tokens_burned,
        "7"
    );
    // change = 1e9 input − 0.1e9 target − 7 burn.
    assert_eq!(plan.change.nano_erg, "899999993");
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
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

/// codex P0: `init`/`restore` must refuse to overwrite an existing wallet — the
/// guard returns `WalletExists` rather than persisting a second secret file.
#[tokio::test]
async fn init_twice_returns_wallet_exists() {
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
        min_relay_fee_nano_erg: 1_000_000,
        max_tx_size_bytes: 98_304,
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
    let err = admin
        .init("pw2".to_string(), String::new(), 24)
        .await
        .expect_err("second init must refuse an existing wallet");
    assert!(
        matches!(err, WalletAdminError::WalletExists),
        "expected WalletExists, got {err:?}",
    );
}
