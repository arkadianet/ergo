//! Multi-sig dispatch helpers: input/data-input resolution for
//! `generateCommitments`/`extractHints`, and their writer-task implementations.

use parking_lot::RwLock;

use super::hints_codec::tx_hints_bag_to_dto;
use super::sign_submit::decode_external_secret;
use crate::node::wallet_bridge::{ChainStateAccessor, WalletAdminError};

/// Collect all `SigmaBoolean` propositions the registry can prove.
///
/// Builds the `generate_for` list from:
/// - All tracked DLog pubkeys (when the wallet is unlocked).
/// - All externally-supplied DLog and DHT secrets.
///
/// Used by `generate_commitments_impl` to tell `generate_commitments_for_tx`
/// which leaves to generate commitments for.
fn collect_generate_for(
    storage: &ergo_wallet::storage::SecretStorage,
    db: &redb::Database,
    externals: &[ergo_wallet::proving::external::ProverExternalSecret],
) -> Result<Vec<ergo_ser::sigma_value::SigmaBoolean>, WalletAdminError> {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;

    let mut generate_for: Vec<SigmaBoolean> = Vec::new();

    // Wallet-derived DLog keys (available when unlocked).
    if storage.unlocked().is_some() {
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let tracked: Vec<(u64, [u8; 33], Vec<u32>)> = wallet_reader
            .tracked_pubkeys_with_paths()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        for (_, pk, _) in tracked {
            generate_for.push(SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk)));
        }
    }

    // Externally-supplied secrets.
    for ext in externals {
        match ext {
            ProverExternalSecret::Dlog { pk, .. } => {
                generate_for.push(SigmaBoolean::ProveDlog(GroupElement::from_bytes(*pk)));
            }
            ProverExternalSecret::DhTuple { g, h, u, v, .. } => {
                generate_for.push(SigmaBoolean::ProveDHTuple {
                    g: GroupElement::from_bytes(*g),
                    h: GroupElement::from_bytes(*h),
                    u: GroupElement::from_bytes(*u),
                    v: GroupElement::from_bytes(*v),
                });
            }
        }
    }

    Ok(generate_for)
}

/// Parse a proposition string for `POST /wallet/extractHints`.
///
/// Accepts two forms:
/// - **Hex string** (66 hex chars = 33 bytes): `ProveDlog(GroupElement)`.
///   Kept for backwards compatibility with the original DLog-only REST API.
/// - **JSON object**: `{"g":"<hex>","h":"<hex>","u":"<hex>","v":"<hex>"}` →
///   `ProveDHTuple`. Detect by trying `serde_json::from_str` first; fall back
///   to hex-DLog parse on failure.
pub(crate) fn hex_pk_to_sigma_boolean(
    s: &str,
) -> Result<ergo_ser::sigma_value::SigmaBoolean, WalletAdminError> {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;

    // Try structured JSON form first (ProveDHTuple).
    let trimmed = s.trim();
    if trimmed.starts_with('{') {
        #[derive(serde::Deserialize)]
        struct DhtJson {
            g: String,
            h: String,
            u: String,
            v: String,
        }

        fn decode_ge_field(hex_str: &str, field: &str) -> Result<GroupElement, WalletAdminError> {
            let bytes: [u8; 33] = hex::decode(hex_str)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "extractHints: ProveDHTuple bad point hex for '{field}'"
                    ))
                })?;
            Ok(GroupElement::from_bytes(bytes))
        }

        let dto: DhtJson = serde_json::from_str(trimmed).map_err(|e| {
            WalletAdminError::Internal(format!("extractHints: JSON proposition parse failed: {e}"))
        })?;
        return Ok(SigmaBoolean::ProveDHTuple {
            g: decode_ge_field(&dto.g, "g")?,
            h: decode_ge_field(&dto.h, "h")?,
            u: decode_ge_field(&dto.u, "u")?,
            v: decode_ge_field(&dto.v, "v")?,
        });
    }

    // Fall back to hex-encoded 33-byte DLog pubkey.
    let bytes: [u8; 33] = hex::decode(trimmed)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            WalletAdminError::Internal(format!(
                "extractHints: bad proposition (expected 33-byte hex pubkey or DHT JSON object): {s}"
            ))
        })?;
    Ok(SigmaBoolean::ProveDlog(GroupElement::from_bytes(bytes)))
}

/// Resolve input box IDs: use `override_ids` if supplied, else look up every
/// input in the unsigned transaction from the UTXO set via `chain`.
pub(crate) fn resolve_inputs_for_unsigned(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
    label: &str,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("{label} override[{i}]: bad box id hex"))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "{label} override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => unsigned_tx
            .inputs
            .iter()
            .enumerate()
            .map(|(i, ui)| {
                let box_id = ui.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "{label}[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// Resolve data-input box IDs (same logic, from `unsigned_tx.data_inputs`).
pub(crate) fn resolve_data_inputs_for_unsigned(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!(
                            "data_input override[{i}]: bad box id hex"
                        ))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => unsigned_tx
            .data_inputs
            .iter()
            .enumerate()
            .map(|(i, di)| {
                let box_id = di.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// Resolve input box IDs for a signed transaction.
pub(crate) fn resolve_inputs_for_signed(
    tx: &ergo_ser::transaction::Transaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("input override[{i}]: bad box id hex"))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "input override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => tx
            .inputs
            .iter()
            .enumerate()
            .map(|(i, inp)| {
                let box_id = inp.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "input[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// Resolve data-input boxes for a signed transaction.
pub(crate) fn resolve_data_inputs_for_signed(
    tx: &ergo_ser::transaction::Transaction,
    override_ids: Option<&[String]>,
    chain: &dyn ChainStateAccessor,
) -> Result<Vec<ergo_ser::ergo_box::ErgoBox>, WalletAdminError> {
    match override_ids {
        Some(ids) => ids
            .iter()
            .enumerate()
            .map(|(i, hex_id)| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!(
                            "data_input override[{i}]: bad box id hex"
                        ))
                    })?;
                chain.lookup_utxo(&id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input override[{i}] box {} not in UTXO set",
                        hex_id
                    ))
                })
            })
            .collect(),
        None => tx
            .data_inputs
            .iter()
            .enumerate()
            .map(|(i, di)| {
                let box_id = di.box_id.as_bytes();
                chain.lookup_utxo(box_id).ok_or_else(|| {
                    WalletAdminError::Internal(format!(
                        "data_input[{i}] box {} not in UTXO set",
                        hex::encode(box_id)
                    ))
                })
            })
            .collect(),
    }
}

/// `POST /wallet/generateCommitments` writer-task implementation.
///
/// Decodes the unsigned tx, collects all propositions the wallet knows
/// secrets for (HD-derived + external), builds a signing context, and
/// calls `generate_commitments_for_tx`.
pub(crate) async fn generate_commitments_impl(
    request: &ergo_api::wallet::multi_sig::GenerateCommitmentsRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
) -> Result<ergo_api::wallet::multi_sig::GenerateCommitmentsResponse, WalletAdminError> {
    use ergo_api::wallet::multi_sig::GenerateCommitmentsResponse;

    let unsigned_tx_bytes = hex::decode(&request.unsigned_tx).map_err(|_| {
        WalletAdminError::Internal("generateCommitments: unsigned_tx bad hex".into())
    })?;
    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&unsigned_tx_bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r).map_err(|e| {
            WalletAdminError::Internal(format!("generateCommitments: unsigned_tx decode: {e:?}"))
        })?
    };

    let externals: Vec<ergo_wallet::proving::external::ProverExternalSecret> = request
        .external_secrets
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(decode_external_secret)
        .collect::<Result<_, _>>()?;

    let storage_guard = storage.read();
    let generate_for = collect_generate_for(&storage_guard, db, &externals)?;
    drop(storage_guard);

    let boxes_to_spend =
        resolve_inputs_for_unsigned(&unsigned_tx, request.inputs.as_deref(), chain, "input")?;
    let data_boxes =
        resolve_data_inputs_for_unsigned(&unsigned_tx, request.data_inputs.as_deref(), chain)?;

    let state_ctx = chain.build_signing_context()?;

    let mut rng = ergo_wallet::proving::randomness::OsRngBackend;
    let tbag = ergo_wallet::proving::commitments::generate_commitments_for_tx(
        &unsigned_tx,
        &boxes_to_spend,
        &data_boxes,
        &state_ctx,
        &generate_for,
        &mut rng,
    )
    .map_err(|e| WalletAdminError::Internal(format!("generateCommitments: {e}")))?;

    let hints_dto = tx_hints_bag_to_dto(&tbag);
    Ok(GenerateCommitmentsResponse { hints: hints_dto })
}

/// `POST /wallet/extractHints` writer-task implementation.
///
/// Decodes the signed tx, parses the `real` / `simulated` pubkey lists,
/// and calls `bag_for_transaction`.
pub(crate) async fn extract_hints_impl(
    request: &ergo_api::wallet::multi_sig::HintExtractionRequest,
    _storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    chain: &dyn ChainStateAccessor,
) -> Result<ergo_api::wallet::multi_sig::HintExtractionResponse, WalletAdminError> {
    use ergo_api::wallet::multi_sig::HintExtractionResponse;

    let tx_bytes = hex::decode(&request.tx)
        .map_err(|_| WalletAdminError::Internal("extractHints: tx bad hex".into()))?;
    let tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&tx_bytes);
        ergo_ser::transaction::read_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("extractHints: tx decode: {e:?}")))?
    };

    let real: Vec<ergo_ser::sigma_value::SigmaBoolean> = request
        .real
        .iter()
        .map(|s| hex_pk_to_sigma_boolean(s))
        .collect::<Result<_, _>>()?;

    let simulated: Vec<ergo_ser::sigma_value::SigmaBoolean> = request
        .simulated
        .iter()
        .map(|s| hex_pk_to_sigma_boolean(s))
        .collect::<Result<_, _>>()?;

    let boxes_to_spend = resolve_inputs_for_signed(&tx, request.inputs.as_deref(), chain)?;
    let data_boxes = resolve_data_inputs_for_signed(&tx, request.data_inputs.as_deref(), chain)?;

    let state_ctx = chain.build_signing_context()?;

    let tbag = ergo_wallet::proving::extract::bag_for_transaction(
        &tx,
        &boxes_to_spend,
        &data_boxes,
        &state_ctx,
        &real,
        &simulated,
    )
    .map_err(|e| WalletAdminError::Internal(format!("extractHints: {e}")))?;

    let hints_dto = tx_hints_bag_to_dto(&tbag);
    Ok(HintExtractionResponse { hints: hints_dto })
}
