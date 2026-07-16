//! Send-side handlers for `WalletCommand` — payment + build + sign +
//! submit + boxes_collect. See `super::mod` for the WriterContext
//! design and grouping rationale.

use tokio::sync::oneshot;

use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::WalletAdminError;

use super::WriterContext;

/// Whether the wallet is locked (no in-memory master key). Native build/select
/// require an unlocked wallet and map `Locked` → `409 wallet_locked`.
fn is_locked(ctx: &WriterContext<'_>) -> bool {
    ctx.storage.read().unlocked().is_none()
}

pub(crate) async fn native_select_boxes(
    ctx: &WriterContext<'_>,
    req: ergo_api::wallet::native::dto::BoxSelectRequest,
    reply: oneshot::Sender<
        Result<ergo_api::wallet::native::dto::BoxSelectResponse, WalletAdminError>,
    >,
) {
    if is_locked(ctx) {
        let _ = reply.send(Err(WalletAdminError::Locked));
        return;
    }
    let result =
        super::select_boxes_impl(&req, ctx.state, ctx.db, ctx.chain.as_ref(), ctx.cfg.network);
    let _ = reply.send(result);
}

pub(crate) async fn native_build_transaction(
    ctx: &WriterContext<'_>,
    intent: ergo_api::wallet::native::dto::TxIntent,
    reply: oneshot::Sender<
        Result<ergo_api::wallet::native::dto::BuildTxResponse, WalletAdminError>,
    >,
) {
    if is_locked(ctx) {
        let _ = reply.send(Err(WalletAdminError::Locked));
        return;
    }
    let result = super::build_transaction_impl(
        &intent,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn native_sign_transaction(
    ctx: &WriterContext<'_>,
    req: ergo_api::wallet::native::dto::SignTxRequest,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::SignTxResponse, WalletAdminError>>,
) {
    // No `Locked` precondition: signing succeeds while locked when
    // external secrets cover every input; otherwise the prover's missing-secret
    // surfaces as `missing_secret`, never `wallet_locked`.
    let result = super::sign_transaction_native_impl(
        &req,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
    )
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn native_send_transaction(
    ctx: &WriterContext<'_>,
    req: ergo_api::wallet::native::dto::SendTxRequest,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::SendTxResponse, WalletAdminError>>,
) {
    // `intent` builds + signs with the wallet's own secrets → needs unlock;
    // `signed` submits caller-supplied bytes → no unlock needed.
    if matches!(
        req,
        ergo_api::wallet::native::dto::SendTxRequest::Intent { .. }
    ) && is_locked(ctx)
    {
        let _ = reply.send(Err(WalletAdminError::Locked));
        return;
    }
    let result = super::send_transaction_native_impl(
        &req,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.submit_handle.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn payment_send(
    ctx: &WriterContext<'_>,
    requests: Vec<PaymentRequestDto>,
    reply: oneshot::Sender<Result<String, WalletAdminError>>,
) {
    let result = super::payment_send_impl(
        &requests,
        None,
        None,
        None,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.submit_handle.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn retrieve_rewards(
    ctx: &WriterContext<'_>,
    req: ergo_api::wallet::native::dto::RetrieveRewardsRequest,
    reply: oneshot::Sender<
        Result<ergo_api::wallet::native::dto::RetrieveRewardsResultDto, WalletAdminError>,
    >,
) {
    // Fee arrives as a decimal nanoErg string (native amount convention) — parse
    // it before building so an out-of-range/garbage fee is a clean 400, not a 500.
    let fee = match req.fee.as_deref().map(str::parse::<u64>).transpose() {
        Ok(f) => f,
        Err(_) => {
            let _ = reply.send(Err(WalletAdminError::BadRequest(
                "fee must be a nanoErg decimal string".into(),
            )));
            return;
        }
    };
    let result = super::retrieve_rewards_impl(
        req.destination.as_deref(),
        fee,
        ctx.cfg.min_relay_fee_nano_erg,
        ctx.cfg.max_tx_size_bytes,
        req.box_ids.as_deref(),
        req.dry_run,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.submit_handle.as_ref(),
        ctx.mempool.as_ref(),
        ctx.cfg.network,
    )
    .await
    .map(
        |o| ergo_api::wallet::native::dto::RetrieveRewardsResultDto {
            box_count: o.box_count,
            box_ids: o.box_ids,
            remaining: o.remaining,
            gross_erg: o.gross_erg.to_string(),
            reemission_paid: o.reemission_paid.to_string(),
            fee: o.fee.to_string(),
            net_to_destination: o.net_to_destination.to_string(),
            other_tokens: o
                .other_tokens
                .into_iter()
                .map(|(id, amt)| ergo_api::wallet::native::dto::SweptTokenDto {
                    token_id: hex::encode(id),
                    amount: amt.to_string(),
                })
                .collect(),
            destination: o.destination,
            tx_id: o.tx_id,
        },
    );
    let _ = reply.send(result);
}

pub(crate) async fn transaction_generate(
    ctx: &WriterContext<'_>,
    request: TransactionGenerateRequest,
    reply: oneshot::Sender<Result<TransactionGenerateResponse, WalletAdminError>>,
) {
    let result = super::transaction_generate_impl(
        &request.requests,
        request.inputs.as_deref(),
        request.data_inputs.as_deref(),
        request.fee,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result.map(|signed_tx_bytes| {
        use ergo_api::wallet::sending::{SignedTxDto, TransactionGenerateResponse};
        TransactionGenerateResponse {
            transaction: SignedTxDto {
                bytes: hex::encode(signed_tx_bytes),
            },
        }
    }));
}

pub(crate) async fn transaction_generate_unsigned(
    ctx: &WriterContext<'_>,
    request: TransactionGenerateUnsignedRequest,
    reply: oneshot::Sender<Result<TransactionGenerateUnsignedResponse, WalletAdminError>>,
) {
    let result = super::transaction_generate_unsigned_impl(
        &request.requests,
        request.inputs.as_deref(),
        request.data_inputs.as_deref(),
        request.fee,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result.map(|unsigned_tx_bytes| {
        use ergo_api::wallet::sending::{TransactionGenerateUnsignedResponse, UnsignedTxDto};
        TransactionGenerateUnsignedResponse {
            unsigned_tx: UnsignedTxDto {
                bytes: hex::encode(unsigned_tx_bytes),
            },
        }
    }));
}

pub(crate) async fn transaction_sign(
    ctx: &WriterContext<'_>,
    request: TransactionSignRequest,
    reply: oneshot::Sender<Result<TransactionSignResponse, WalletAdminError>>,
) {
    let result = super::transaction_sign_impl(
        &request.unsigned_tx.bytes,
        request.external_secrets.as_deref(),
        request.hints.as_ref(),
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
    )
    .await;
    let _ = reply.send(result.map(|signed_tx_bytes| {
        use ergo_api::wallet::sending::{SignedTxDto, TransactionSignResponse};
        TransactionSignResponse {
            transaction: SignedTxDto {
                bytes: hex::encode(signed_tx_bytes),
            },
        }
    }));
}

pub(crate) async fn transaction_send(
    ctx: &WriterContext<'_>,
    request: TransactionSendRequest,
    reply: oneshot::Sender<Result<String, WalletAdminError>>,
) {
    let result = super::payment_send_impl(
        &request.requests,
        request.inputs.as_deref(),
        request.data_inputs.as_deref(),
        request.fee,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.submit_handle.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn boxes_collect(
    ctx: &WriterContext<'_>,
    request: BoxesCollectRequest,
    reply: oneshot::Sender<Result<BoxesCollectResponse, WalletAdminError>>,
) {
    let result =
        super::boxes_collect_impl(&request, ctx.storage, ctx.state, ctx.db, ctx.chain.as_ref());
    let _ = reply.send(result);
}
