//! Multisig + key-derivation handlers for `WalletCommand` —
//! generate_commitments, extract_hints, derive_key, derive_next_key,
//! get_private_key. See `super::mod` for the WriterContext design.

use tokio::sync::oneshot;

use ergo_api::wallet::admin_advanced::{
    DeriveKeyRequest, DeriveKeyResponse, DeriveNextKeyResponse, GetPrivateKeyRequest,
    GetPrivateKeyResponse,
};
use ergo_api::wallet::multi_sig::{
    GenerateCommitmentsRequest, GenerateCommitmentsResponse, HintExtractionRequest,
    HintExtractionResponse,
};
use ergo_api::wallet::WalletAdminError;

use super::WriterContext;

pub(crate) async fn generate_commitments(
    ctx: &WriterContext<'_>,
    request: GenerateCommitmentsRequest,
    reply: oneshot::Sender<Result<GenerateCommitmentsResponse, WalletAdminError>>,
) {
    let result =
        super::generate_commitments_impl(&request, ctx.storage, ctx.db, ctx.chain.as_ref()).await;
    let _ = reply.send(result);
}

pub(crate) async fn extract_hints(
    ctx: &WriterContext<'_>,
    request: HintExtractionRequest,
    reply: oneshot::Sender<Result<HintExtractionResponse, WalletAdminError>>,
) {
    let result = super::extract_hints_impl(&request, ctx.storage, ctx.chain.as_ref()).await;
    let _ = reply.send(result);
}

pub(crate) async fn derive_key(
    ctx: &WriterContext<'_>,
    request: DeriveKeyRequest,
    reply: oneshot::Sender<Result<DeriveKeyResponse, WalletAdminError>>,
) {
    let result = super::derive_key_impl(
        &request,
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn derive_next_key(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<DeriveNextKeyResponse, WalletAdminError>>,
) {
    let result = super::derive_next_key_impl(
        ctx.storage,
        ctx.state,
        ctx.db,
        ctx.chain.as_ref(),
        ctx.cfg.network,
    )
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn get_private_key(
    ctx: &WriterContext<'_>,
    request: GetPrivateKeyRequest,
    reply: oneshot::Sender<Result<GetPrivateKeyResponse, WalletAdminError>>,
) {
    let result = super::get_private_key_impl(&request, ctx.storage, ctx.db, ctx.cfg).await;
    let _ = reply.send(result);
}
