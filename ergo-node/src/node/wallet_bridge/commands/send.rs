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
    )
    .await;
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
