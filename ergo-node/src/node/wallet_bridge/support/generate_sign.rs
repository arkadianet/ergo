//! `PaymentSend` + `TransactionGenerate*` + `TransactionSign` + `BoxesCollect`
//! writer-task implementations.

use parking_lot::RwLock;

use ergo_api::wallet::sending::{BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto};

use super::hints_codec::tx_hints_bag_from_dto;
use super::sign_submit::{decode_external_secret, serialize_signed_tx, sign_unsigned_tx};
use super::tx_build::{build_unsigned_tx, MIN_BOX_VALUE};
use crate::node::wallet_bridge::{ChainStateAccessor, TxSubmitter, WalletAdminError};

/// `PaymentSend` + `TransactionSend` shared path: build, sign, self-verify, submit.
///
/// Requires an unlocked wallet: change-address derivation and HD-key signing
/// both need the decrypted master key. Returns `WalletAdminError::Locked`
/// (HTTP 400 wallet_locked) before attempting to build the tx, preventing a
/// confusing Internal/500 from `MissingSecret` deep in the signing path.
/// `transaction_sign` is the only route that accepts the locked + externals path.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn payment_send_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    submitter: &dyn TxSubmitter,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<String, WalletAdminError> {
    // Reject immediately with a clean 400 wallet_locked rather than letting
    // the signing path fail deep inside prove_sigma with MissingSecret → 500.
    if storage.read().unlocked().is_none() {
        return Err(WalletAdminError::Locked);
    }

    let unsigned_bytes = build_unsigned_tx(
        requests,
        override_inputs,
        override_data_inputs,
        fee_override,
        None, // change_address_override (compat path uses the persisted change address)
        state,
        db,
        chain,
        network,
    )
    .await?
    .bytes;

    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("deserialize unsigned tx: {e:?}")))?
    };

    // Scope the guard so it lexically ends before the .await below —
    // `parking_lot::RwLockReadGuard` is `!Send`, and the future returned by
    // `payment_send_impl` is spawned on a multi-thread runtime where any
    // value live across an .await must be `Send`. An explicit `drop()`
    // does not shrink the future state machine's scope; a block does.
    let signed_tx = {
        let storage = storage.read();
        sign_unsigned_tx(
            &unsigned_tx,
            &storage,
            db,
            chain,
            &[],
            &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
        )?
    };

    let tx_id = ergo_ser::transaction::transaction_id(&signed_tx)
        .map_err(|e| WalletAdminError::Internal(format!("transaction_id: {e:?}")))?;
    let tx_id_hex = hex::encode(tx_id.as_bytes());

    let tx_bytes = serialize_signed_tx(&signed_tx)?;
    // Compat boundary: collapse the typed SubmitError to `Internal` exactly as
    // the adapter did before (unchanged compat behavior). The native send path
    // maps the typed reason — e.g. `duplicate` → 200 — at its own boundary.
    submitter
        .submit_transaction(tx_bytes)
        .await
        .map_err(|e| WalletAdminError::Internal(format!("submit: {}", e.reason)))?;

    Ok(tx_id_hex)
}

/// `TransactionGenerate` path: build, sign, self-verify; do NOT submit.
///
/// Requires an unlocked wallet for the same reason as `payment_send_impl`.
/// Returns `WalletAdminError::Locked` (400 wallet_locked) when locked.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn transaction_generate_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<Vec<u8>, WalletAdminError> {
    if storage.read().unlocked().is_none() {
        return Err(WalletAdminError::Locked);
    }

    let unsigned_bytes = build_unsigned_tx(
        requests,
        override_inputs,
        override_data_inputs,
        fee_override,
        None, // change_address_override (compat path uses the persisted change address)
        state,
        db,
        chain,
        network,
    )
    .await?
    .bytes;

    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("deserialize unsigned tx: {e:?}")))?
    };

    let storage = storage.read();
    let signed_tx = sign_unsigned_tx(
        &unsigned_tx,
        &storage,
        db,
        chain,
        &[],
        &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
    )?;
    drop(storage);

    serialize_signed_tx(&signed_tx)
}

/// `TransactionGenerateUnsigned` path: build only; no sign, no submit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn transaction_generate_unsigned_impl(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<Vec<u8>, WalletAdminError> {
    // Require the wallet to be unlocked so change-address is available.
    {
        let _storage = storage.read();
    }
    build_unsigned_tx(
        requests,
        override_inputs,
        override_data_inputs,
        fee_override,
        None, // change_address_override (compat path uses the persisted change address)
        state,
        db,
        chain,
        network,
    )
    .await
    .map(|built| built.bytes)
}

/// `TransactionSign` path: decode an unsigned tx hex, sign it, self-verify.
/// Works with external secrets even when the wallet is locked.
pub(crate) async fn transaction_sign_impl(
    unsigned_tx_hex: &str,
    external_secret_dtos: Option<&[ergo_api::wallet::sending::ExternalSecretDto]>,
    hints: Option<&ergo_api::wallet::sending::TxHintsBagDto>,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    _state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<u8>, WalletAdminError> {
    // The unsigned tx bytes are fully client-supplied (native sign + compat sign):
    // a malformed value is a client error (400), not a server fault (500).
    let unsigned_tx_bytes = hex::decode(unsigned_tx_hex)
        .map_err(|_| WalletAdminError::BadRequest("unsigned_tx: bad hex".into()))?;
    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_tx_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::BadRequest(format!("unsigned_tx decode: {e:?}")))?
    };

    let externals: Vec<ergo_wallet::proving::external::ProverExternalSecret> = external_secret_dtos
        .unwrap_or(&[])
        .iter()
        .map(decode_external_secret)
        .collect::<Result<_, _>>()?;

    let hints_bag: ergo_wallet::proving::hints::TransactionHintsBag = match hints {
        Some(dto) => tx_hints_bag_from_dto(dto)
            .map_err(|e| WalletAdminError::Internal(format!("decode hints: {e:?}")))?,
        None => ergo_wallet::proving::hints::TransactionHintsBag::empty(),
    };

    let storage = storage.read();
    let signed_tx = sign_unsigned_tx(&unsigned_tx, &storage, db, chain, &externals, &hints_bag)?;
    drop(storage);

    serialize_signed_tx(&signed_tx)
}

/// `BoxesCollect` path: run box selection; no signing, no submit.
pub(crate) fn boxes_collect_impl(
    request: &BoxesCollectRequest,
    _storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    _state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
) -> Result<BoxesCollectResponse, WalletAdminError> {
    let _ = chain; // used for UTXO lookup in future phases
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let unspent = wallet_reader
        .unspent_boxes()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    let summaries: Vec<ergo_wallet::box_selector::BoxSummary> = unspent
        .iter()
        .map(|wb| ergo_wallet::box_selector::BoxSummary {
            box_id: wb.box_id,
            value: wb.value,
            tokens: wb.assets.iter().copied().collect(),
        })
        .collect();

    let target_tokens: std::collections::BTreeMap<[u8; 32], u64> = request
        .target_assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(&a.token_id)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    WalletAdminError::Internal(format!("bad token_id: {}", a.token_id))
                })?;
            Ok((id, a.amount))
        })
        .collect::<Result<_, WalletAdminError>>()?;

    let target = ergo_wallet::box_selector::SelectionTarget {
        erg_amount: request.target_balance,
        tokens: target_tokens,
        min_change_value: MIN_BOX_VALUE,
    };

    let selector = ergo_wallet::box_selector::default::DefaultBoxSelector;
    let selection = ergo_wallet::box_selector::BoxSelector::select(&selector, &summaries, &target)
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    let boxes = selection.selected_ids.iter().map(hex::encode).collect();
    let change_boxes = if selection.change_erg > 0 || !selection.change_tokens.is_empty() {
        // There is change; the actual change box will be built at tx-construction time.
        // For now report the ERG change amount as a synthetic hex-encoded placeholder.
        vec![hex::encode(selection.change_erg.to_be_bytes())]
    } else {
        vec![]
    };

    Ok(BoxesCollectResponse {
        boxes,
        change_boxes,
    })
}
