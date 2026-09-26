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
    let result = super::generate_commitments_impl(
        &request,
        ctx.storage,
        ctx.store.as_ref(),
        ctx.chain.as_ref(),
    )
    .await;
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
    let result = async {
        // Check recovery is available before committing a key that fences apply.
        super::admin::rescan_tip(ctx)?;
        let key = super::derive_key_impl(
            &request,
            ctx.storage,
            ctx.state,
            ctx.store.as_ref(),
            ctx.chain.as_ref(),
            ctx.cfg.network,
        )
        .await?;
        rescan_after_derivation(ctx).await?;
        Ok(key)
    }
    .await;
    let _ = reply.send(result);
}

pub(crate) async fn derive_next_key(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<DeriveNextKeyResponse, WalletAdminError>>,
) {
    let result = async {
        super::admin::rescan_tip(ctx)?;
        let key = super::derive_next_key_impl(
            ctx.storage,
            ctx.state,
            ctx.store.as_ref(),
            ctx.chain.as_ref(),
            ctx.cfg.network,
        )
        .await?;
        rescan_after_derivation(ctx).await?;
        Ok(key)
    }
    .await;
    let _ = reply.send(result);
}

async fn rescan_after_derivation(ctx: &WriterContext<'_>) -> Result<(), WalletAdminError> {
    // Key persistence invalidates historical ownership and fences live apply.
    // Start the normal supervised rebuild so the fence clears on completion.
    let (reply, result) = oneshot::channel();
    super::admin::rescan(ctx, 0, reply).await;
    result
        .await
        .map_err(|error| WalletAdminError::Internal(error.to_string()))?
}

pub(crate) async fn get_private_key(
    ctx: &WriterContext<'_>,
    request: GetPrivateKeyRequest,
    reply: oneshot::Sender<Result<GetPrivateKeyResponse, WalletAdminError>>,
) {
    let result =
        super::get_private_key_impl(&request, ctx.storage, ctx.store.as_ref(), ctx.cfg).await;
    let _ = reply.send(result);
}
