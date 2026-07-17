//! Native transaction sign + send, and the shared sign/self-verify/serialize
//! building blocks the send/sweep/generate paths all route through.

use parking_lot::RwLock;

use super::generate_sign::transaction_sign_impl;
use super::tx_build::build_transaction_impl;
use crate::node::wallet_bridge::{ChainStateAccessor, TxSubmitter, WalletAdminError};

/// Convert a native [`ExternalSecret`](ergo_api::wallet::native::dto::ExternalSecret)
/// to the compat `ExternalSecretDto` so the single existing prover decoder
/// ([`decode_external_secret`]) is reused. (`secret` maps to the compat `dlog`/`x`.)
pub(crate) fn native_external_to_compat(
    s: &ergo_api::wallet::native::dto::ExternalSecret,
) -> ergo_api::wallet::sending::ExternalSecretDto {
    use ergo_api::wallet::native::dto::ExternalSecret as N;
    use ergo_api::wallet::sending::ExternalSecretDto as C;
    match s {
        N::Dlog { secret } => C::Dlog {
            dlog: secret.clone(),
        },
        N::DhTuple { g, h, u, v, secret } => C::DhTuple {
            g: g.clone(),
            h: h.clone(),
            u: u.clone(),
            v: v.clone(),
            x: secret.clone(),
        },
    }
}

/// `(transaction, tx_id_hex)` from serialized signed-tx bytes.
pub(crate) fn signed_tx_id_hex(signed_bytes: &[u8]) -> Result<String, WalletAdminError> {
    let mut r = ergo_primitives::reader::VlqReader::new(signed_bytes);
    let tx = ergo_ser::transaction::read_transaction(&mut r)
        .map_err(|e| WalletAdminError::Internal(format!("signed tx decode: {e:?}")))?;
    let id = ergo_ser::transaction::transaction_id(&tx)
        .map_err(|e| WalletAdminError::Internal(format!("transaction_id: {e:?}")))?;
    Ok(hex::encode(id.as_bytes()))
}

/// Native `transactions/sign`: sign a caller-supplied unsigned tx. Runs NO `Locked`
/// precondition (works while locked when `externalSecrets` cover all inputs); the
/// prover's missing-secret surfaces as `missing_secret(422)`. The EIP-27
/// self-verify gate runs inside [`sign_unsigned_tx`], so an unsigned tx that
/// violates the burn rule is caught here rather than network-rejected.
pub(crate) async fn sign_transaction_native_impl(
    req: &ergo_api::wallet::native::dto::SignTxRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
) -> Result<ergo_api::wallet::native::dto::SignTxResponse, WalletAdminError> {
    let externals: Vec<ergo_api::wallet::sending::ExternalSecretDto> = req
        .external_secrets
        .iter()
        .map(native_external_to_compat)
        .collect();
    let signed_bytes = transaction_sign_impl(
        req.unsigned_transaction.bytes_hex(),
        Some(&externals),
        None,
        storage,
        state,
        db,
        chain,
    )
    .await?;
    let tx_id = signed_tx_id_hex(&signed_bytes)?;
    Ok(ergo_api::wallet::native::dto::SignTxResponse {
        signed_transaction: ergo_api::wallet::native::dto::TxRepr::from_bytes(&signed_bytes),
        tx_id,
    })
}

/// Map a prover/sign error to a typed native error so the sign path's advertised
/// 422s are reachable. A missing prover secret — the locked-sign-without-covering-
/// external-secrets case the whole "no Locked precheck on sign" design hinges on —
/// becomes `missing_secret` (NOT `internal`/500, NEVER `wallet_locked`); an
/// input whose script the prover's gate rejects becomes `unsupported_script`. The
/// unsupported-script message is the one the prover emits (`prover.rs`).
pub(crate) fn map_sign_error(e: ergo_wallet::error::WalletError) -> WalletAdminError {
    use ergo_wallet::error::WalletError as W;
    match e {
        W::MissingSecret(_) => WalletAdminError::MissingSecret,
        W::TxBuild(m) if m.contains("unsupported script family") => {
            WalletAdminError::UnsupportedScript
        }
        other => WalletAdminError::Internal(format!("sign: {other}")),
    }
}

/// Map a submit error to a native [`WalletAdminError`]. A `duplicate` reason is the
/// caller's concern (handled as idempotent-accepted upstream); other reasons are a
/// client-correctable rejection (`bad_request` carrying the typed reason).
pub(crate) fn map_submit_error(e: ergo_api::types::SubmitError) -> WalletAdminError {
    WalletAdminError::BadRequest(match e.detail {
        Some(d) => format!("submit rejected ({}): {d}", e.reason),
        None => format!("submit rejected: {}", e.reason),
    })
}

/// Native `transactions/send`. **txId-first** idempotency: compute the
/// id, short-circuit a known wallet tx BEFORE any UTXO-dependent self-verify, then
/// submit. `intent` builds (burn-aware) + signs with the wallet's own secrets;
/// `signed` submits caller-supplied bytes. A `duplicate` submit reason maps to an
/// idempotent `accepted` (never a 5xx on a re-seen tx).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_transaction_native_impl(
    req: &ergo_api::wallet::native::dto::SendTxRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    submitter: &dyn TxSubmitter,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_api::wallet::native::dto::SendTxResponse, WalletAdminError> {
    use ergo_api::wallet::native::dto::{SendTxRequest, SendTxResponse};

    // 1. Produce signed bytes (build+sign own secrets for `intent`; decode for `signed`).
    let signed_bytes = match req {
        SendTxRequest::Intent { intent } => {
            let built = build_transaction_impl(intent, state, db, chain, network).await?;
            // The wallet signs with its own secrets; the EIP-27 self-verify gate runs
            // inside `sign_unsigned_tx` on a freshly built tx (inputs still in the UTXO
            // set, so the self-verify lookup succeeds).
            transaction_sign_impl(
                built.unsigned_transaction.bytes_hex(),
                None,
                None,
                storage,
                state,
                db,
                chain,
            )
            .await?
        }
        SendTxRequest::Signed { signed_transaction } => {
            let bytes = hex::decode(signed_transaction.bytes_hex())
                .map_err(|_| WalletAdminError::BadRequest("signedTransaction: bad hex".into()))?;
            // Validate the caller's bytes parse as a transaction NOW, so a
            // valid-hex-but-not-a-tx blob is a 400 (not a 500 from the txId helper,
            // which stays strict for our own internally-signed bytes).
            let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
            ergo_ser::transaction::read_transaction(&mut r).map_err(|e| {
                WalletAdminError::BadRequest(format!(
                    "signedTransaction: not a valid transaction: {e:?}"
                ))
            })?;
            bytes
        }
    };

    // 2. txId FIRST — so an already-known tx never trips the UTXO-dependent
    //    self-verify (a confirmed tx's inputs are spent → `lookup_utxo` None).
    let tx_id_hex = signed_tx_id_hex(&signed_bytes)?;
    let tx_id: [u8; 32] = hex::decode(&tx_id_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| WalletAdminError::Internal("tx id not 32 bytes".into()))?;

    // Known-tx short-circuit: a confirmed wallet row → idempotent accept with its
    // summary, no re-submit. (Without an indexer a confirmed non-wallet tx is not
    // detectable here; it falls through to submit, where `duplicate` is caught.)
    {
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        if let Some(wt) = reader
            .transaction_by_id(&tx_id)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
        {
            return Ok(SendTxResponse {
                tx_id: tx_id_hex,
                accepted: true,
                transaction: Some(crate::node::wallet_bridge::commands::admin::tx_to_summary(
                    wt,
                )),
            });
        }
    }

    // 3. Submit. A `duplicate` reason (already in-pool) is idempotently accepted.
    match submitter.submit_transaction(signed_bytes).await {
        Ok(_) => Ok(SendTxResponse {
            tx_id: tx_id_hex,
            accepted: true,
            transaction: None,
        }),
        Err(e) if e.reason == "duplicate" => Ok(SendTxResponse {
            tx_id: tx_id_hex,
            accepted: true,
            transaction: None,
        }),
        Err(e) => Err(map_submit_error(e)),
    }
}

pub(crate) fn serialize_unsigned_tx(
    utx: &ergo_ser::transaction::UnsignedTransaction,
) -> Result<Vec<u8>, WalletAdminError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_unsigned_transaction(&mut w, utx)
        .map_err(|e| WalletAdminError::Internal(format!("serialize unsigned tx: {e:?}")))?;
    Ok(w.result())
}

pub(crate) fn serialize_signed_tx(
    tx: &ergo_ser::transaction::Transaction,
) -> Result<Vec<u8>, WalletAdminError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_transaction(&mut w, tx)
        .map_err(|e| WalletAdminError::Internal(format!("serialize signed tx: {e:?}")))?;
    Ok(w.result())
}

/// Decode an `ExternalSecretDto` hex payload into `ProverExternalSecret`.
pub(crate) fn decode_external_secret(
    dto: &ergo_api::wallet::sending::ExternalSecretDto,
) -> Result<ergo_wallet::proving::external::ProverExternalSecret, WalletAdminError> {
    use ergo_api::wallet::sending::ExternalSecretDto;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use k256::elliptic_curve::ops::Reduce;
    use k256::{FieldBytes, Scalar, U256};

    fn decode_scalar(hex_str: &str) -> Result<Scalar, WalletAdminError> {
        let bytes: [u8; 32] = hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                // Never interpolate the value — this is a raw private-key
                // scalar. Report only the structural fault.
                WalletAdminError::Internal(format!(
                    "external secret: invalid scalar hex (expected 64 hex chars / 32 bytes, got {} chars)",
                    hex_str.len()
                ))
            })?;
        let s = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes));
        if s == Scalar::ZERO {
            return Err(WalletAdminError::Internal(
                "external secret: scalar is zero".into(),
            ));
        }
        Ok(s)
    }
    fn decode_pk(hex_str: &str, label: &str) -> Result<[u8; 33], WalletAdminError> {
        hex::decode(hex_str)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                WalletAdminError::Internal(format!("external secret: bad point hex for {label}"))
            })
    }

    match dto {
        ExternalSecretDto::Dlog { dlog } => {
            let scalar = decode_scalar(dlog)?;
            // Recover the corresponding pubkey from the scalar. Read the
            // scalar through a borrow so we don't hold a bare copy past
            // the wrap below.
            use k256::elliptic_curve::group::GroupEncoding;
            use k256::elliptic_curve::ops::MulByGenerator;
            use k256::ProjectivePoint;
            let pk_point = ProjectivePoint::mul_by_generator(&scalar);
            let pk_bytes: [u8; 33] = pk_point.to_affine().to_bytes().into();
            Ok(ProverExternalSecret::Dlog {
                pk: pk_bytes,
                // Wrap so the scalar zeroizes when the enum drops.
                scalar: zeroize::Zeroizing::new(scalar),
            })
        }
        ExternalSecretDto::DhTuple { g, h, u, v, x } => Ok(ProverExternalSecret::DhTuple {
            g: decode_pk(g, "g")?,
            h: decode_pk(h, "h")?,
            u: decode_pk(u, "u")?,
            v: decode_pk(v, "v")?,
            scalar: zeroize::Zeroizing::new(decode_scalar(x)?),
        }),
    }
}

/// Build a `Prover` from wallet secrets and/or caller-supplied external secrets.
///
/// If the wallet is unlocked, the HD-derived secrets for all tracked pubkeys
/// are pre-loaded into the registry. If the wallet is locked, the registry
/// starts empty and relies on `externals` to cover all required propositions.
/// A locked wallet with no externals will produce a registry that fails at
/// proof time with `MissingSecret` — that is the correct failure mode.
pub(crate) fn build_prover(
    storage: &ergo_wallet::storage::SecretStorage,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    externals: &[ergo_wallet::proving::external::ProverExternalSecret],
) -> Result<ergo_wallet::proving::prover::Prover, WalletAdminError> {
    let registry = if let Some(unlocked) = storage.unlocked() {
        // Wallet unlocked: pre-derive secrets for all tracked pubkeys.
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let tracked_with_paths: std::collections::BTreeMap<u64, ([u8; 33], Vec<u32>)> =
            wallet_reader
                .tracked_pubkeys_with_paths()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .into_iter()
                .map(|(idx, pk, path)| (idx, (pk, path)))
                .collect();

        ergo_wallet::proving::secrets::SecretRegistry::from_master_key(
            &unlocked.master,
            &tracked_with_paths,
        )
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?
        .merge_external_secrets(externals)
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?
    } else {
        // Wallet locked: start with an empty registry. If externals cover all
        // required propositions, signing succeeds; otherwise prove_sigma returns
        // MissingSecret, which surfaces as a sign error (not a Locked error).
        ergo_wallet::proving::secrets::SecretRegistry::empty()
            .merge_external_secrets(externals)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
    };

    let params = chain.build_signing_params()?;
    Ok(ergo_wallet::proving::prover::Prover::new(registry, params))
}

/// Sign an `UnsignedTransaction` using the wallet prover, performing
/// mandatory self-verify before returning the signed bytes.
///
/// `hints` is threaded through to the prover so multi-sig callers can
/// supply a populated `TransactionHintsBag`; single-sig callers pass
/// `&TransactionHintsBag::empty()`.
pub(crate) fn sign_unsigned_tx(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    storage: &ergo_wallet::storage::SecretStorage,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    externals: &[ergo_wallet::proving::external::ProverExternalSecret],
    hints: &ergo_wallet::proving::hints::TransactionHintsBag,
) -> Result<ergo_ser::transaction::Transaction, WalletAdminError> {
    let state_ctx = chain.build_signing_context()?;
    let params = chain.build_signing_params()?;
    let prover = build_prover(storage, db, chain, externals)?;

    // Look up the full ErgoBox for each input.
    let boxes_to_spend: Vec<ergo_ser::ergo_box::ErgoBox> = unsigned_tx
        .inputs
        .iter()
        .enumerate()
        .map(|(idx, ui)| {
            let box_id = ui.box_id.as_bytes();
            chain.lookup_utxo(box_id).ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "input {} box {} not found in UTXO set",
                    idx,
                    hex::encode(box_id)
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    let data_boxes: Vec<ergo_ser::ergo_box::ErgoBox> = unsigned_tx
        .data_inputs
        .iter()
        .enumerate()
        .map(|(idx, di)| {
            let box_id = di.box_id.as_bytes();
            chain.lookup_utxo(box_id).ok_or_else(|| {
                WalletAdminError::Internal(format!(
                    "data input {} box {} not found in UTXO set",
                    idx,
                    hex::encode(box_id)
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    let signed_tx = prover
        .sign(unsigned_tx, &boxes_to_spend, &data_boxes, &state_ctx, hints)
        .map_err(map_sign_error)?;

    // Pre-submit structural validation against the SAME ruleset the node's
    // consensus validator runs (size-aware min box value =
    // serialized_box_size * min_value_per_byte, box/collection caps). This
    // replaces the wallet's old flat MIN_BOX_VALUE heuristic so the wallet
    // never builds a tx the node would reject as dust. Runs on the final
    // signed tx, before the cost-accounting self-verify and submit.
    let protocol_params = chain.build_protocol_params()?;
    ergo_validation::tx::structural::validate_structural(&signed_tx, &protocol_params)
        .map_err(|e| WalletAdminError::BadRequest(format!("transaction rejected: {e}")))?;

    // Mandatory self-verify: reproduces chain validator cost accounting + the
    // EIP-27 re-emission burn gate before submission.
    self_verify_signed_tx(
        &signed_tx,
        &boxes_to_spend,
        &data_boxes,
        &state_ctx,
        &params,
        chain.reemission_rules(),
    )?;

    Ok(signed_tx)
}

/// Self-verify every input's spending proof against the real block cost limit.
///
/// Reproduces the chain validator's cost accounting exactly:
///
/// 1. Compute the transaction-level init cost (same formula as
///    `ergo_validation::compute_tx_init_cost`) and pre-charge it into the
///    accumulator before the input loop.
/// 2. Reuse ONE `CostAccumulator` across all inputs — this matches
///    `ergo-validation/src/tx/mod.rs` where the accumulator is threaded
///    through `validate_scripts` across the entire input set.  A per-input
///    fresh accumulator would miss cross-input cost overages that the chain
///    validator would catch.
///
/// The per-call `verify_spending_proof_with_context_and_cost` still fires
/// its own cost check, so a single input that alone exceeds the limit is
/// still caught immediately.
pub(crate) fn self_verify_signed_tx(
    tx: &ergo_ser::transaction::Transaction,
    boxes_to_spend: &[ergo_ser::ergo_box::ErgoBox],
    data_boxes: &[ergo_ser::ergo_box::ErgoBox],
    state_ctx: &ergo_wallet::tx_context::BlockchainStateContext,
    params: &ergo_wallet::tx_context::BlockchainParameters,
    reemission: Option<&ergo_validation::ReemissionRuleInputs>,
) -> Result<(), WalletAdminError> {
    use ergo_primitives::cost::{CostAccumulator, JitCost};
    use ergo_sigma::reduce::verify_spending_proof_with_context_and_cost;

    // Fail-closed EIP-27 gate: refuse to EMIT a tx that spends reward boxes
    // without burning the re-emission tokens + paying pay-to-reemission. Uses the
    // SAME shared validator the node runs (`verify_reemission_spending`), at the
    // CANDIDATE height (`tip+1` = `state_ctx.sigma_pre_header.height`) the tx will
    // be validated at — so the wallet never relays/mines a tx the node rejects.
    // No-op off EIP-27 nets (`reemission` is `None`, e.g. testnet).
    if let Some(rules) = reemission {
        ergo_validation::verify_reemission_spending(
            tx,
            boxes_to_spend,
            state_ctx.sigma_pre_header.height,
            rules,
        )
        .map_err(|e| WalletAdminError::ReemissionObligationUnmet(e.to_string()))?;
    }

    let jit_limit = JitCost::from_block_cost(params.max_block_cost)
        .map_err(|e| WalletAdminError::Internal(format!("self-verify cost limit: {e}")))?;

    // ONE accumulator for the entire tx, matching ergo-validation's tx-wide accounting.
    let mut cost_acc = CostAccumulator::new(jit_limit);

    // Pre-charge the tx-level init cost.  Mirrors the validator's Stage 5.5
    // (ergo-validation/src/tx/mod.rs: `compute_tx_init_cost` → `cx.cost.add`).
    // Shared with the consensus validator via ergo-validation, so the
    // self-verify gate can't drift from on-chain cost accounting.
    let init_cost = ergo_validation::compute_tx_init_cost_with_costs(
        tx,
        boxes_to_spend,
        params.interpreter_init_cost,
        params.input_cost,
        params.data_input_cost,
        params.output_cost,
        params.token_access_cost,
    );
    let init_jit = JitCost::from_block_cost(init_cost)
        .map_err(|e| WalletAdminError::Internal(format!("self-verify init cost: {e}")))?;
    cost_acc.add(init_jit).map_err(|_| {
        WalletAdminError::Internal("self-verify: tx init cost exceeds limit".into())
    })?;

    let message = ergo_ser::transaction::bytes_to_sign(tx)
        .map_err(|e| WalletAdminError::Internal(format!("bytes_to_sign: {e:?}")))?;

    let all_input_extensions: Vec<ergo_ser::input::ContextExtension> = tx
        .inputs
        .iter()
        .map(|i| i.spending_proof.extension.clone())
        .collect();

    for (idx, (input, input_box)) in tx.inputs.iter().zip(boxes_to_spend.iter()).enumerate() {
        let owned_rc = state_ctx.build_reduction_owned(
            input_box,
            &input.spending_proof.extension,
            boxes_to_spend,
            data_boxes,
            &tx.output_candidates,
            &all_input_extensions,
        );
        let ctx = owned_rc.as_borrowed();
        let ergo_tree = input_box.candidate.ergo_tree();
        let ok = verify_spending_proof_with_context_and_cost(
            ergo_tree,
            &input.spending_proof.proof,
            &message,
            &ctx,
            &mut cost_acc,
        )
        .map_err(|e| WalletAdminError::Internal(format!("self-verify input {idx}: {e:?}")))?;
        if !ok {
            return Err(WalletAdminError::Internal(format!(
                "self-verify failed for input {idx}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sign-path error mapper makes the advertised 422s reachable: a missing
    /// prover secret → `missing_secret` (NOT internal/500 — the locked-sign-with-
    /// externals contract); an unsupported input script → `unsupported_script`;
    /// anything else stays internal.
    #[test]
    fn map_sign_error_surfaces_typed_422s() {
        use ergo_wallet::error::WalletError as W;
        assert!(matches!(
            map_sign_error(W::MissingSecret("no secret for input 0".into())),
            WalletAdminError::MissingSecret
        ));
        assert!(matches!(
            map_sign_error(W::TxBuild(
                "input 0 has an unsupported script family; only P2PK/DHT".into()
            )),
            WalletAdminError::UnsupportedScript
        ));
        assert!(matches!(
            map_sign_error(W::TxBuild("reduce: boom".into())),
            WalletAdminError::Internal(_)
        ));
    }

    /// A `duplicate` submit reason is handled as idempotent-accept upstream; any
    /// other submit reason maps to a client `bad_request` carrying the typed reason.
    #[test]
    fn map_submit_error_carries_reason() {
        let e = map_submit_error(ergo_api::types::SubmitError {
            reason: "too_big".into(),
            detail: Some("size 1234 > max".into()),
        });
        match e {
            WalletAdminError::BadRequest(m) => {
                assert!(m.contains("too_big") && m.contains("size 1234"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }
}
