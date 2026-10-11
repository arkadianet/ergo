//! Durable, finite maintenance operations owned by the wallet writer.
//!
//! A signed transaction is journaled BEFORE private admission. Following a
//! crash, the same bytes are resubmitted; a payment is never rebuilt after it
//! might already have been admitted. Public broadcasting is not a job action.

use std::collections::{BTreeMap, BTreeSet};

use crate::wallet::types::{BoxProvenance, BoxStatus, WalletBox};
use ergo_wallet_protocol::native::dto::{
    DataInputSource, InputSource, OutputIntent, TxIntent, WalletAssetDto, WalletJob,
    WalletJobRequest, WalletJobState, WalletJobTask, WalletJobs,
};
use ergo_wallet_protocol::WalletAdminError;
use serde::{Deserialize, Serialize};

use super::{build as tx_build, send as generate_sign, sign as sign_submit, WalletEngine};
use crate::wallet::WalletStore;

const MAX_JOBS: usize = 256;
const MAX_BOXES: usize = 100;
const MAX_RECORD_BYTES: usize = 512 * 1024;
/// Furthest deadline an approval may set, in blocks above the chain tip
/// (about 30 days at the two-minute block target).
pub const MAX_SCHEDULE_BLOCKS: u32 = 21_600;
/// Mined and conflicted jobs follow their admitted transaction through reorgs.
/// Without one there is nothing to follow, and such a job is final.
fn follows_queue(record: &Record) -> bool {
    !record.job.state.terminal()
        || (matches!(
            record.job.state,
            WalletJobState::Mined | WalletJobState::Conflicted
        ) && record.job.tx_id.is_some())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[doc(hidden)]
pub struct Record {
    pub job: WalletJob,
    /// Not included in the API response. Durable recovery uses these exact
    /// bytes, so they are kept only while the job follows the private queue.
    pub signed_hex: Option<String>,
    /// Retry at most once per applied height; wall-clock polling cannot exhaust
    /// the owner's retry allowance while a chain is quiet.
    pub last_attempt_height: Option<u32>,
}

fn internal(error: impl std::fmt::Display) -> WalletAdminError {
    WalletAdminError::Internal(format!("wallet mining jobs: {error}"))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn id(value: &str) -> Result<u64, WalletAdminError> {
    value
        .parse()
        .map_err(|_| WalletAdminError::BadRequest("job id must be a decimal integer".into()))
}

fn validate_box_ids(box_ids: &[String]) -> Result<(), WalletAdminError> {
    if box_ids.is_empty() || box_ids.len() > MAX_BOXES {
        return Err(WalletAdminError::BadRequest(
            "jobs require 1..=100 pinned input boxes".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for box_id in box_ids {
        let bytes = hex::decode(box_id)
            .map_err(|_| WalletAdminError::BadRequest("invalid job input box id".into()))?;
        if bytes.len() != 32 || box_id != &hex::encode(&bytes) || !seen.insert(bytes) {
            return Err(WalletAdminError::BadRequest(
                "job input ids must be distinct lowercase 32-byte hex values".into(),
            ));
        }
    }
    Ok(())
}

fn validate_request(request: &WalletJobRequest) -> Result<(), WalletAdminError> {
    if request.label.is_empty() || request.label.len() > 160 {
        return Err(WalletAdminError::BadRequest(
            "job label must contain 1..=160 bytes".into(),
        ));
    }
    if request.expires_at_height <= request.not_before_height
        || !(1..=100).contains(&request.max_attempts)
    {
        return Err(WalletAdminError::BadRequest(
            "job needs a later expiry height and 1..=100 attempts".into(),
        ));
    }
    match &request.task {
        WalletJobTask::Send { intent } => {
            // Finite maintenance jobs accept payments only. Issuance IDs and
            // intentional token burns belong to an interactive approval flow.
            if intent.outputs.is_empty()
                || intent.outputs.len() > MAX_BOXES
                || intent
                    .outputs
                    .iter()
                    .any(|output| !matches!(output, OutputIntent::Payment { .. }))
                || intent.allow_token_burn
                || intent.fee.as_deref().is_some_and(|fee| fee != "0")
            {
                return Err(WalletAdminError::BadRequest(
                    "maintenance sends require payment outputs, zero miner fee, and no token burn"
                        .into(),
                ));
            }
            match &intent.inputs {
                InputSource::BoxIds { box_ids } => validate_box_ids(box_ids)?,
                _ => {
                    return Err(WalletAdminError::BadRequest(
                        "job inputs must be pinned boxIds from an approved preview".into(),
                    ))
                }
            }
        }
        WalletJobTask::Consolidate { box_ids, .. }
        | WalletJobTask::Renew { box_ids }
        | WalletJobTask::Rewards { box_ids, .. } => validate_box_ids(box_ids)?,
    }
    Ok(())
}

#[doc(hidden)]
pub fn records(store: &dyn WalletStore) -> Result<Vec<(u64, Record)>, WalletAdminError> {
    let rows = store
        .read()
        .map_err(internal)?
        .mining_job_records()
        .map_err(internal)?;
    if rows.len() > MAX_JOBS {
        return Err(internal("job journal bounds exceeded"));
    }
    rows.into_iter()
        .map(|(key, bytes)| {
            if bytes.len() > MAX_RECORD_BYTES {
                return Err(internal("job journal bounds exceeded"));
            }
            Ok((key, serde_json::from_slice(&bytes).map_err(internal)?))
        })
        .collect()
}

fn encode(record: &Record) -> Result<Vec<u8>, WalletAdminError> {
    let bytes = serde_json::to_vec(record).map_err(internal)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(WalletAdminError::BadRequest(
            "job transaction exceeds journal size limit".into(),
        ));
    }
    Ok(bytes)
}

#[doc(hidden)]
pub fn save(store: &dyn WalletStore, job_id: u64, record: &Record) -> Result<(), WalletAdminError> {
    let bytes = encode(record)?;
    let mut write = store.begin_write().map_err(internal)?;
    write
        .put_mining_job_record(job_id, &bytes)
        .map_err(internal)?;
    write.commit().map_err(internal)
}

/// Restore reservations before accepting commands following a crash during
/// unsigned preparation. Signed Prepared records retain their exact bytes.
pub fn recover_preparing(db: &dyn WalletStore) -> Result<(), WalletAdminError> {
    for (job_id, mut record) in records(db)? {
        if record.job.state == WalletJobState::Preparing {
            if record.signed_hex.is_some() {
                return Err(internal("preparing job contains signed bytes"));
            }
            transition(
                &mut record,
                WalletJobState::Waiting,
                Some("recovering interrupted preparation".into()),
            );
            save(db, job_id, &record)?;
        }
    }
    Ok(())
}

pub fn list(db: &dyn WalletStore) -> Result<WalletJobs, WalletAdminError> {
    let mut items: Vec<_> = records(db)?
        .into_iter()
        .map(|(_, record)| record.job)
        .collect();
    items.reverse();
    Ok(WalletJobs {
        items,
        max_jobs: MAX_JOBS as u32,
    })
}

/// Pending jobs reserve their approved input set. The wallet writer marks its
/// current job Preparing before building, so only that job's own reservation
/// is released during its serialized build/sign operation.
pub fn reserved_inputs(db: &dyn WalletStore) -> Result<BTreeSet<[u8; 32]>, WalletAdminError> {
    let mut reserved = BTreeSet::new();
    for (_, record) in records(db)? {
        if record.job.state.terminal() || record.job.state == WalletJobState::Preparing {
            continue;
        }
        for value in task_box_ids(&record.job.request.task) {
            let bytes: [u8; 32] = hex::decode(value)
                .map_err(internal)?
                .try_into()
                .map_err(|_| internal("bad journal input id"))?;
            reserved.insert(bytes);
        }
    }
    Ok(reserved)
}

pub async fn create_owned(
    ctx: &mut WalletEngine,
    request: WalletJobRequest,
) -> Result<WalletJob, WalletAdminError> {
    validate_request(&request)?;
    // Approval authorizes a later signature with the wallet key, so it has the
    // precondition of an intent send: the owner has unlocked the wallet.
    if ctx.storage.read().unlocked().is_none() {
        return Err(WalletAdminError::Locked);
    }
    // Jobs deliver only to this node's private mining queue; without one an
    // approval could never run, yet would reserve its inputs until expiry.
    if !ctx.submitter.private_mining_configured() {
        return Err(WalletAdminError::BadRequest(
            "maintenance jobs need private mining; enable [mining] on this node".into(),
        ));
    }
    super::scan_guard::require_valid_scan(ctx.store.as_ref())?;
    let height = ctx.chain.tip_height().map_err(internal)?;
    if request.expires_at_height <= height {
        return Err(WalletAdminError::BadRequest(
            "job deadline has already passed".into(),
        ));
    }
    if request.expires_at_height - height > MAX_SCHEDULE_BLOCKS {
        return Err(WalletAdminError::BadRequest(format!(
            "job deadline may be at most {MAX_SCHEDULE_BLOCKS} blocks after the current height {height}"
        )));
    }
    let mut reserved = ctx.chain.reserved_wallet_inputs()?;
    reserved.extend(reserved_inputs(ctx.store.as_ref())?);
    let reader = ctx.store.read().map_err(internal)?;
    let mut matures_at = None;
    let mut boxes = Vec::new();
    for value in task_box_ids(&request.task) {
        let bytes: [u8; 32] = hex::decode(value)
            .map_err(internal)?
            .try_into()
            .map_err(|_| internal("bad job input id"))?;
        if reserved.contains(&bytes) {
            return Err(WalletAdminError::BadRequest(
                "input already reserved by another wallet job".into(),
            ));
        }
        let wallet_box = reader
            .box_by_id(&bytes)
            .map_err(internal)?
            .ok_or(WalletAdminError::BoxNotFound)?;
        match wallet_box.status {
            BoxStatus::Spent { .. } => return Err(WalletAdminError::BoxNotFound),
            BoxStatus::Immature { matures_at: height } => matures_at = matures_at.max(Some(height)),
            BoxStatus::Confirmed => {}
        }
        let expected = if matches!(request.task, WalletJobTask::Rewards { .. }) {
            BoxProvenance::MinerReward
        } else {
            BoxProvenance::Owned
        };
        if wallet_box.provenance != expected {
            return Err(WalletAdminError::BadRequest(
                "job input provenance does not match its task".into(),
            ));
        }
        boxes.push(wallet_box);
    }
    drop(reader);
    // A job cannot sign before its rewards mature, so its schedule starts there.
    if let Some(height) = matures_at.filter(|height| request.not_before_height < *height) {
        return Err(WalletAdminError::BadRequest(format!(
            "selected rewards mature at height {height}; start the job at or after it"
        )));
    }
    match &request.task {
        WalletJobTask::Consolidate { destination, .. }
        | WalletJobTask::Rewards { destination, .. } => tracked_destination(ctx, destination)?,
        _ => {}
    }
    dry_run(ctx, &request.task, &boxes).await?;
    create(ctx.store.as_ref(), request)
}

pub fn create(
    db: &dyn WalletStore,
    request: WalletJobRequest,
) -> Result<WalletJob, WalletAdminError> {
    validate_request(&request)?;
    let existing = records(db)?;
    let remove = if existing.len() >= MAX_JOBS {
        Some(
            existing
                .iter()
                .find(|(_, record)| {
                    record.job.state.terminal() && record.job.state != WalletJobState::Conflicted
                })
                .map(|(key, _)| *key)
                .ok_or_else(|| {
                    WalletAdminError::BadRequest("private wallet job limit reached".into())
                })?,
        )
    } else {
        None
    };
    let mut write = db.begin_write().map_err(internal)?;
    let job_id = write.mining_job_next_id().map_err(internal)?;
    write
        .set_mining_job_next_id(
            job_id
                .checked_add(1)
                .ok_or_else(|| internal("job id exhausted"))?,
        )
        .map_err(internal)?;
    let now = now_ms();
    let job = WalletJob {
        id: job_id.to_string(),
        request,
        state: WalletJobState::Waiting,
        created_at_ms: now,
        updated_at_ms: now,
        attempts: 0,
        tx_id: None,
        detail: None,
    };
    let record = Record {
        job: job.clone(),
        signed_hex: None,
        last_attempt_height: None,
    };
    let bytes = serde_json::to_vec(&record).map_err(internal)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(WalletAdminError::BadRequest(
            "job exceeds journal size limit".into(),
        ));
    }
    if let Some(key) = remove {
        write.remove_mining_job_record(key).map_err(internal)?;
    }
    write
        .put_mining_job_record(job_id, &bytes)
        .map_err(internal)?;
    write.commit().map_err(internal)?;
    Ok(job)
}

#[doc(hidden)]
pub fn transition(record: &mut Record, state: WalletJobState, detail: Option<String>) {
    record.job.state = state;
    record.job.detail = detail;
    record.job.updated_at_ms = now_ms();
    // A cancelled, expired or failed job never submits again, so its
    // unpublished signed transaction need not stay at rest in the journal.
    if !follows_queue(record) {
        record.signed_hex = None;
    }
}

pub async fn cancel(ctx: &mut WalletEngine, job_id: &str) -> Result<WalletJob, WalletAdminError> {
    let job_id = id(job_id)?;
    let mut record = records(ctx.store.as_ref())?
        .into_iter()
        .find(|(key, _)| *key == job_id)
        .map(|(_, record)| record)
        .ok_or_else(|| WalletAdminError::BadRequest("wallet job not found".into()))?;
    if record.job.state.terminal() && record.job.state != WalletJobState::Conflicted {
        return Ok(record.job);
    }
    if let Some(tx_id) = &record.job.tx_id {
        // A queue stored on disk keeps admitted work while mining is disabled,
        // and enabling mining would mine it, so it is withdrawn there too.
        // Only a node without any private queue has nothing queued.
        let queued = match ctx
            .submitter
            .job_private_transaction_status(tx_id.clone())
            .await
        {
            Ok(entry) => entry.is_some(),
            Err(error)
                if !ctx.submitter.private_mining_configured()
                    && error.reason == "private_mining_unavailable" =>
            {
                false
            }
            Err(error) => return Err(super::map_submit_error(error)),
        };
        if queued {
            ctx.submitter
                .job_cancel_private_transaction(tx_id.clone())
                .await
                .map_err(super::map_submit_error)?;
        } else if !ctx.submitter.private_mining_configured()
            // Without queue knowledge, only a confirmation the wallet's
            // history already shows refuses the cancellation.
            && mined_in_wallet(ctx, tx_id, 0)? == Some(true)
        {
            transition(
                &mut record,
                WalletJobState::Mined,
                Some(MINED_IN_WALLET.into()),
            );
            save(ctx.store.as_ref(), job_id, &record)?;
            return Err(WalletAdminError::BadRequest(
                "the job transaction is already confirmed and cannot be cancelled".into(),
            ));
        }
    }
    transition(&mut record, WalletJobState::Cancelled, None);
    save(ctx.store.as_ref(), job_id, &record)?;
    Ok(record.job)
}

pub const MINED_IN_WALLET: &str = "confirmed in the wallet's chain history";
pub const PINNED_INPUT_UNAVAILABLE: &str =
    "a pinned input is spent or used by another transaction; this approval will not sign";

/// Without private queue knowledge, the wallet's own history tells a mined job
/// from one that never confirmed. `None` while that history is incomplete, or
/// has not yet scanned through `through_height`.
fn mined_in_wallet(
    ctx: &WalletEngine,
    tx_id: &str,
    through_height: u32,
) -> Result<Option<bool>, WalletAdminError> {
    if ctx.rescan.in_progress()
        || super::scan_guard::require_valid_scan(ctx.store.as_ref()).is_err()
        || !ctx
            .chain
            .wallet_scan_height()
            .is_ok_and(|scanned| scanned >= through_height)
    {
        return Ok(None);
    }
    let tx_id: [u8; 32] = hex::decode(tx_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| internal("bad journal transaction id"))?;
    let read = ctx.store.read().map_err(internal)?;
    let found = read.transaction_by_id(&tx_id).map_err(internal)?;
    Ok(Some(found.is_some()))
}

/// Why an unsigned job must wait without spending its retry allowance: an
/// invalidated wallet scan, or reward inputs that are still maturing.
fn waiting_reason(
    ctx: &WalletEngine,
    task: &WalletJobTask,
) -> Result<Option<String>, WalletAdminError> {
    if let Err(error) = super::scan_guard::require_valid_scan(ctx.store.as_ref()) {
        return Ok(Some(error.to_string()));
    }
    let reader = ctx.store.read().map_err(internal)?;
    let mut matures_at = None;
    for value in task_box_ids(task) {
        let bytes: [u8; 32] = hex::decode(value)
            .map_err(internal)?
            .try_into()
            .map_err(|_| internal("bad journal box id"))?;
        if let Some(BoxStatus::Immature { matures_at: height }) = reader
            .box_by_id(&bytes)
            .map_err(internal)?
            .map(|wallet_box| wallet_box.status)
        {
            matures_at = matures_at.max(Some(height));
        }
    }
    Ok(matures_at
        .map(|height| format!("waiting for the selected rewards to mature at height {height}")))
}

fn task_box_ids(task: &WalletJobTask) -> &[String] {
    match task {
        WalletJobTask::Send { intent } => match &intent.inputs {
            InputSource::BoxIds { box_ids } => box_ids,
            _ => &[],
        },
        WalletJobTask::Consolidate { box_ids, .. }
        | WalletJobTask::Renew { box_ids }
        | WalletJobTask::Rewards { box_ids, .. } => box_ids,
    }
}

fn loaded_boxes(
    ctx: &WalletEngine,
    task: &WalletJobTask,
) -> Result<Vec<WalletBox>, WalletAdminError> {
    let reader = ctx.store.read().map_err(internal)?;
    task_box_ids(task)
        .iter()
        .map(|value| {
            let bytes: [u8; 32] = hex::decode(value)
                .map_err(internal)?
                .try_into()
                .map_err(|_| internal("bad journal box id"))?;
            let wallet_box = reader
                .box_by_id(&bytes)
                .map_err(internal)?
                .ok_or(WalletAdminError::BoxNotFound)?;
            match wallet_box.status {
                BoxStatus::Confirmed => {}
                BoxStatus::Immature { .. } => {
                    return Err(WalletAdminError::BadRequest(
                        "approved reward inputs are not mature yet".into(),
                    ))
                }
                BoxStatus::Spent { .. } => return Err(WalletAdminError::BoxNotFound),
            }
            let expected = if matches!(task, WalletJobTask::Rewards { .. }) {
                BoxProvenance::MinerReward
            } else {
                BoxProvenance::Owned
            };
            if !matches!(task, WalletJobTask::Send { .. }) && wallet_box.provenance != expected {
                return Err(WalletAdminError::BadRequest(
                    "maintenance input provenance does not match its task".into(),
                ));
            }
            Ok(wallet_box)
        })
        .collect()
}

fn tracked_destination(ctx: &WalletEngine, address: &str) -> Result<(), WalletAdminError> {
    let pk = ergo_ser::address::decode_p2pk_address(address, ctx.config.network)
        .map_err(|_| WalletAdminError::BadRequest("invalid maintenance destination".into()))?;
    let read = ctx.store.read().map_err(internal)?;
    if !read
        .tracked_pubkeys_with_paths()
        .map_err(internal)?
        .iter()
        .any(|(_, key, _)| *key == pk)
    {
        return Err(WalletAdminError::BadRequest(
            "maintenance destination must be tracked by this wallet".into(),
        ));
    }
    Ok(())
}

fn aggregated_output(
    ctx: &WalletEngine,
    boxes: &[WalletBox],
    destination: &str,
    rewards: bool,
) -> Result<OutputIntent, WalletAdminError> {
    tracked_destination(ctx, destination)?;
    let mut value = 0u64;
    let mut tokens = BTreeMap::<[u8; 32], u64>::new();
    let owned_rules = ctx.chain.reemission_rules_owned();
    let rules = owned_rules.as_ref();
    let height = ctx.chain.tip_height().map_err(internal)?.saturating_add(1);
    let obligation = rules.map(|rules| {
        ergo_validation::reemission_obligation_core(
            boxes.iter().map(|wallet_box| {
                (
                    wallet_box.value,
                    wallet_box
                        .assets
                        .iter()
                        .find(|(key, _)| key == &rules.reemission_token_id)
                        .map(|(_, amount)| *amount)
                        .unwrap_or(0),
                )
            }),
            height,
            rules.activation_height,
        )
    });
    for wallet_box in boxes {
        value = value
            .checked_add(wallet_box.value)
            .ok_or_else(|| internal("maintenance value overflow"))?;
        for (key, amount) in &wallet_box.assets {
            if rewards
                && obligation.as_ref().is_some_and(|value| value.triggered)
                && rules.is_some_and(|rules| key == &rules.reemission_token_id)
            {
                continue;
            }
            let entry = tokens.entry(*key).or_default();
            *entry = entry
                .checked_add(*amount)
                .ok_or_else(|| internal("maintenance token overflow"))?;
        }
    }
    if rewards {
        value = value
            .checked_sub(obligation.map(|value| value.to_burn).unwrap_or(0))
            .ok_or_else(|| {
                WalletAdminError::BadRequest(
                    "rewards cannot cover their re-emission obligation".into(),
                )
            })?;
    }
    if tokens.len() > 122 {
        return Err(WalletAdminError::BadRequest(
            "selected tokens require multiple maintenance jobs; no tokens were burned".into(),
        ));
    }
    Ok(OutputIntent::Payment {
        address: destination.into(),
        value: value.to_string(),
        assets: tokens
            .into_iter()
            .map(|(key, amount)| WalletAssetDto {
                token_id: hex::encode(key),
                amount: amount.to_string(),
            })
            .collect(),
        registers: None,
    })
}

fn renewal_outputs(
    ctx: &WalletEngine,
    boxes: &[WalletBox],
) -> Result<Vec<OutputIntent>, WalletAdminError> {
    let read = ctx.store.read().map_err(internal)?;
    let keys = read.tracked_pubkeys_with_paths().map_err(internal)?;
    let snapshot = ctx.chain.signing_view().map_err(super::map_chain_error)?;
    let mut outputs = Vec::new();
    for wallet_box in boxes {
        let full = snapshot
            .lookup_utxo(&wallet_box.box_id)
            .map_err(internal)?
            .ok_or(WalletAdminError::BoxNotFound)?;
        let pk = keys
            .iter()
            .find_map(|(_, pk, _)| {
                (ergo_ser::address::build_p2pk_tree_bytes(pk).ok().as_deref()
                    == Some(full.candidate.ergo_tree_bytes()))
                .then_some(pk)
            })
            .ok_or(WalletAdminError::UnsupportedScript)?;
        let address =
            ergo_ser::address::encode_p2pk_from_pubkey(ctx.config.network, pk).map_err(internal)?;
        let raw_regs = ergo_ser::register::split_register_bytes(full.candidate.register_bytes())
            .map_err(internal)?;
        let registers = (!raw_regs.is_empty()).then(|| {
            raw_regs
                .into_iter()
                .enumerate()
                .map(|(index, bytes)| (format!("R{}", index + 4), hex::encode(bytes)))
                .collect()
        });
        outputs.push(OutputIntent::Payment {
            address,
            value: wallet_box.value.to_string(),
            assets: wallet_box
                .assets
                .iter()
                .map(|(key, amount)| WalletAssetDto {
                    token_id: hex::encode(key),
                    amount: amount.to_string(),
                })
                .collect(),
            registers,
        });
    }
    Ok(outputs)
}

/// The zero-fee intent a job's transaction is built from.
fn job_intent(
    ctx: &WalletEngine,
    task: &WalletJobTask,
    boxes: &[WalletBox],
) -> Result<TxIntent, WalletAdminError> {
    let outputs = match task {
        WalletJobTask::Send { intent } => {
            let mut intent = intent.clone();
            intent.fee = Some("0".into());
            return Ok(intent);
        }
        WalletJobTask::Consolidate { destination, .. } => {
            vec![aggregated_output(ctx, boxes, destination, false)?]
        }
        WalletJobTask::Rewards { destination, .. } => {
            vec![aggregated_output(ctx, boxes, destination, true)?]
        }
        WalletJobTask::Renew { .. } => renewal_outputs(ctx, boxes)?,
    };
    Ok(TxIntent {
        outputs,
        fee: Some("0".into()),
        inputs: InputSource::BoxIds {
            box_ids: task_box_ids(task).to_vec(),
        },
        data_inputs: DataInputSource::default(),
        change_address: None,
        allow_reemission_spend: matches!(task, WalletJobTask::Rewards { .. }),
        allow_token_burn: false,
    })
}

/// Build, without signing, the transaction a job will sign, so approval
/// refuses an operation that could never be signed or admitted.
async fn dry_run(
    ctx: &WalletEngine,
    task: &WalletJobTask,
    boxes: &[WalletBox],
) -> Result<(), WalletAdminError> {
    let intent = job_intent(ctx, task, boxes)?;
    let unsigned = match (task, intent.outputs.as_slice()) {
        // Wallet selection does not offer rewards that are still maturing, so
        // build from the exact input IDs with the explicit-input builder that
        // preparation's native builder wraps. The reward output carries no
        // registers, so the transaction is the same.
        (
            WalletJobTask::Rewards { box_ids, .. },
            [OutputIntent::Payment {
                address,
                value,
                assets,
                registers: None,
            }],
        ) => {
            let request = ergo_wallet_protocol::scala::sending::PaymentRequestDto {
                address: address.clone(),
                value: tx_build::parse_u64_dec(value, "output value")?,
                assets: tx_build::parse_native_assets(assets)?
                    .into_iter()
                    .map(
                        |(id, amount)| ergo_wallet_protocol::scala::sending::AssetDto {
                            token_id: hex::encode(id),
                            amount,
                        },
                    )
                    .collect(),
            };
            tx_build::build_unsigned_tx(
                &[request],
                Some(box_ids),
                None,
                Some(0),
                None,
                &ctx.state,
                ctx.store.as_ref(),
                ctx.chain.as_ref(),
                ctx.config.network,
            )?
            .bytes
        }
        (WalletJobTask::Rewards { .. }, _) => {
            return Err(internal("reward retrieval builds one payment output"))
        }
        _ => {
            let (built, _) = tx_build::build_transaction_impl_with_snapshot(
                &intent,
                &ctx.state,
                ctx.store.as_ref(),
                ctx.chain.as_ref(),
                ctx.config.network,
                ctx.mempool.as_ref(),
            )?;
            hex::decode(built.unsigned_transaction.bytes_hex()).map_err(internal)?
        }
    };
    check_unsigned(ctx, &unsigned)
}

/// Consensus structure and admission size of an unsigned job transaction.
/// Each job input is spent by one 56-byte Schnorr proof, so 64-byte
/// placeholder proofs make the serialized size an upper bound.
fn check_unsigned(ctx: &WalletEngine, unsigned: &[u8]) -> Result<(), WalletAdminError> {
    const PROOF_BOUND: usize = 64;
    let unsigned = ergo_ser::transaction::read_unsigned_transaction(
        &mut ergo_primitives::reader::VlqReader::new(unsigned),
    )
    .map_err(|error| internal(format!("unsigned transaction decode: {error}")))?;
    let inputs = unsigned
        .inputs
        .iter()
        .map(|input| {
            ergo_ser::input::SpendingProof::new(vec![0; PROOF_BOUND], input.extension.clone())
                .map(|spending_proof| ergo_ser::input::Input {
                    box_id: input.box_id,
                    spending_proof,
                })
                .map_err(|error| internal(format!("placeholder proof: {error:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let transaction = ergo_ser::transaction::Transaction {
        inputs,
        data_inputs: unsigned.data_inputs,
        output_candidates: unsigned.output_candidates,
    };
    let size = sign_submit::serialize_signed_tx(&transaction)?.len();
    if size > ctx.config.max_tx_size_bytes {
        return Err(WalletAdminError::BadRequest(format!(
            "job transaction (about {size} bytes) exceeds the configured {}-byte limit; \
             approve fewer boxes per job",
            ctx.config.max_tx_size_bytes
        )));
    }
    let params = ctx
        .chain
        .build_protocol_params()
        .map_err(super::map_chain_error)?;
    ergo_validation::tx::structural::validate_structural(&transaction, &params)
        .map_err(|error| WalletAdminError::BadRequest(format!("job transaction rejected: {error}")))
}

async fn prepare(ctx: &WalletEngine, record: &Record) -> Result<Vec<u8>, WalletAdminError> {
    super::scan_guard::require_valid_scan(ctx.store.as_ref())?;
    if ctx.storage.read().unlocked().is_none() {
        return Err(WalletAdminError::Locked);
    }
    let boxes = loaded_boxes(ctx, &record.job.request.task)?;
    let intent = job_intent(ctx, &record.job.request.task, &boxes)?;
    let (built, pool) = tx_build::build_transaction_impl_with_snapshot(
        &intent,
        &ctx.state,
        ctx.store.as_ref(),
        ctx.chain.as_ref(),
        ctx.config.network,
        ctx.mempool.as_ref(),
    )?;
    let snapshot = super::chain::PoolSigningView::new(
        ctx.chain.signing_view().map_err(super::map_chain_error)?,
        pool.outputs,
    );
    let signed = generate_sign::transaction_sign_impl_with_snapshot(
        built.unsigned_transaction.bytes_hex(),
        None,
        None,
        &ctx.storage,
        &ctx.state,
        ctx.store.as_ref(),
        &snapshot,
    )?;
    ctx.chain
        .ensure_view_current(&snapshot)
        .map_err(super::map_chain_error)?;
    // Private admission enforces the same limit; refusing here keeps an
    // oversized transaction out of the journal.
    if signed.len() > ctx.config.max_tx_size_bytes {
        return Err(WalletAdminError::BadRequest(format!(
            "signed job transaction is {} bytes, above the configured {}-byte limit; \
             approve fewer boxes per job",
            signed.len(),
            ctx.config.max_tx_size_bytes
        )));
    }
    Ok(signed)
}

/// Private queue knowledge for one scheduler wake.
enum Queue {
    /// This node has no private mining queue: nothing can be admitted, and no
    /// admitted transaction is waiting here.
    Disabled,
    /// The snapshot failed. Admissions stay uncertain until a later read.
    Unavailable(Option<String>),
    Entries(BTreeMap<String, ergo_wallet_protocol::mining::PrivateTransactionEntry>),
}

/// Perform at most one due preparation/submission per wake. This runs inside
/// the existing wallet writer so lock, cancel and shutdown retain its ordering.
/// A failing job records its error and the wake ends; only a journal that
/// cannot be read or written is returned as an error, which stops the writer.
pub async fn tick(ctx: &mut WalletEngine) -> Result<(), WalletAdminError> {
    if ctx.rescan.shutdown_requested() {
        return Ok(());
    }
    let jobs = records(ctx.store.as_ref())?;
    if jobs.is_empty() {
        return Ok(());
    }
    let height = match ctx.chain.tip_height() {
        Ok(height) => height,
        Err(error) => {
            tracing::warn!(%error, "wallet jobs wait for a readable chain tip");
            return Ok(());
        }
    };
    // One queue RPC per wake, regardless of retained job count. An unavailable
    // snapshot is never evidence that an uncertain admission disappeared, so it
    // holds back only jobs with an admitted transaction, and only until their
    // deadline, which the queue enforces at the same height.
    let queue = if !ctx.submitter.private_mining_configured() {
        Queue::Disabled
    } else if jobs
        .iter()
        .any(|(_, record)| follows_queue(record) && record.job.tx_id.is_some())
    {
        match ctx.submitter.job_private_transactions().await {
            Ok(entries) => Queue::Entries(
                entries
                    .into_iter()
                    .map(|entry| (entry.tx_id.clone(), entry))
                    .collect(),
            ),
            Err(error) => Queue::Unavailable(error.detail.or(Some(error.reason))),
        }
    } else {
        Queue::Entries(BTreeMap::new())
    };
    for (job_id, mut record) in jobs {
        if !follows_queue(&record) {
            continue;
        }
        let mut queue_known = false;
        if let Some(tx_id) = record.job.tx_id.clone() {
            match &queue {
                Queue::Entries(entries) => match entries.get(&tx_id) {
                    Some(entry) => {
                        queue_known = true;
                        let state = match entry.state.as_str() {
                            "mined" => WalletJobState::Mined,
                            "in_candidate" => WalletJobState::InCandidate,
                            "conflicted" => WalletJobState::Conflicted,
                            "cancelled" => WalletJobState::Cancelled,
                            "expired" => WalletJobState::Expired,
                            "queued" => WalletJobState::Queued,
                            _ => {
                                continue;
                            }
                        };
                        if record.job.state != state {
                            transition(&mut record, state, entry.reason.clone());
                            save(ctx.store.as_ref(), job_id, &record)?;
                        }
                        if state.terminal() {
                            continue;
                        }
                    }
                    None if record.job.state == WalletJobState::Mined => {
                        continue;
                    }
                    None if matches!(
                        record.job.state,
                        WalletJobState::Queued | WalletJobState::InCandidate
                    ) =>
                    {
                        transition(
                            &mut record,
                            WalletJobState::Prepared,
                            Some("recovering private admission from durable signed bytes".into()),
                        );
                        save(ctx.store.as_ref(), job_id, &record)?;
                    }
                    None => {}
                },
                // Without queue knowledge a mined or conflicted job keeps its state.
                _ if record.job.state.terminal() => continue,
                Queue::Unavailable(detail) if height < record.job.request.expires_at_height => {
                    if record.job.detail != *detail {
                        record.job.detail = detail.clone();
                        save(ctx.store.as_ref(), job_id, &record)?;
                    }
                    continue;
                }
                _ => {}
            }
        }
        // The queue applies the same height deadline once it has read that
        // block, so a transaction mined in its last eligible block is reported
        // as mined. A queue still listing the transaction as unfinished at the
        // deadline height may not have read the block yet: withdrawing it
        // then would report a confirmed transaction as expired. Wait a block.
        let deadline = record.job.request.expires_at_height;
        if height > deadline || (height == deadline && !queue_known) {
            if let Some(tx_id) = record.job.tx_id.as_ref() {
                if queue_known {
                    match ctx
                        .submitter
                        .job_cancel_private_transaction(tx_id.clone())
                        .await
                    {
                        Ok(()) => {}
                        Err(error) if error.reason == "not_found" => {}
                        Err(error) => {
                            record.job.detail = error.detail.or(Some(error.reason));
                            save(ctx.store.as_ref(), job_id, &record)?;
                            return Ok(());
                        }
                    }
                } else if !matches!(queue, Queue::Entries(_)) {
                    // The transaction may have confirmed at the deadline height
                    // while the queue could not report it. The wallet's history
                    // decides once it has scanned that block.
                    match mined_in_wallet(ctx, tx_id, deadline)? {
                        None => continue,
                        Some(true) => {
                            transition(
                                &mut record,
                                WalletJobState::Mined,
                                Some(MINED_IN_WALLET.into()),
                            );
                            save(ctx.store.as_ref(), job_id, &record)?;
                            continue;
                        }
                        Some(false) => {}
                    }
                }
            }
            transition(
                &mut record,
                WalletJobState::Expired,
                Some("approved height deadline reached".into()),
            );
            save(ctx.store.as_ref(), job_id, &record)?;
            if queue_known {
                return Ok(());
            }
            continue;
        }
        if matches!(queue, Queue::Disabled) {
            // Nothing can be delivered: wait for the deadline or a cancellation
            // without signing or spending the retry allowance.
            let detail = Some("private mining is not enabled on this node".to_owned());
            if record.job.detail != detail {
                record.job.detail = detail;
                save(ctx.store.as_ref(), job_id, &record)?;
            }
            continue;
        }
        if height < record.job.request.not_before_height
            || record.last_attempt_height == Some(height)
            || matches!(
                record.job.state,
                WalletJobState::Queued | WalletJobState::InCandidate
            )
        {
            continue;
        }
        if record.job.attempts >= record.job.request.max_attempts {
            transition(
                &mut record,
                WalletJobState::Failed,
                Some("approved retry limit reached".into()),
            );
            save(ctx.store.as_ref(), job_id, &record)?;
            continue;
        }
        // Locked wallets wait without consuming retry allowance.
        if record.signed_hex.is_none() && ctx.storage.read().unlocked().is_none() {
            if record.job.state != WalletJobState::WaitingForWallet {
                transition(
                    &mut record,
                    WalletJobState::WaitingForWallet,
                    Some("unlock wallet to prepare approved operation".into()),
                );
                save(ctx.store.as_ref(), job_id, &record)?;
            }
            continue;
        }
        // So do an invalidated scan and rewards that are still maturing.
        if record.signed_hex.is_none() {
            if let Some(detail) = waiting_reason(ctx, &record.job.request.task)? {
                if record.job.state != WalletJobState::Waiting
                    || record.job.detail.as_ref() != Some(&detail)
                {
                    transition(&mut record, WalletJobState::Waiting, Some(detail));
                    save(ctx.store.as_ref(), job_id, &record)?;
                }
                continue;
            }
        }
        record.job.attempts += 1;
        record.last_attempt_height = Some(height);
        if record.signed_hex.is_none() {
            transition(&mut record, WalletJobState::Preparing, None);
            save(ctx.store.as_ref(), job_id, &record)?;
            let prepared = match prepare(ctx, &record).await {
                Ok(bytes) => sign_submit::signed_tx_id_hex(&bytes).map(|tx_id| (tx_id, bytes)),
                Err(error) => Err(error),
            };
            match prepared {
                Ok((tx_id, bytes)) => {
                    record.job.tx_id = Some(tx_id);
                    record.signed_hex = Some(hex::encode(bytes));
                    transition(&mut record, WalletJobState::Prepared, None);
                }
                // A pinned input that is spent or held by another transaction
                // ends the approval for good: signing it after that input comes
                // back could repeat an operation the owner has since redone.
                Err(WalletAdminError::BoxNotFound) => {
                    transition(
                        &mut record,
                        WalletJobState::Failed,
                        Some(PINNED_INPUT_UNAVAILABLE.into()),
                    );
                    save(ctx.store.as_ref(), job_id, &record)?;
                    return Ok(());
                }
                Err(error) => {
                    // The tip moving during preparation, or a lock or scan
                    // change racing it, is no verdict on the approved operation.
                    if matches!(
                        error,
                        WalletAdminError::StaleChainTip(_)
                            | WalletAdminError::Locked
                            | WalletAdminError::ScanInvalidated
                    ) {
                        record.job.attempts -= 1;
                    }
                    transition(
                        &mut record,
                        WalletJobState::Waiting,
                        Some(error.to_string()),
                    );
                    save(ctx.store.as_ref(), job_id, &record)?;
                    return Ok(());
                }
            }
        }
        // This commit is the recovery boundary: only after it succeeds may
        // the signed bytes leave the journal for the private mining queue.
        // Bytes the journal cannot hold are never submitted.
        if let Err(error) = encode(&record) {
            record.signed_hex = None;
            record.job.tx_id = None;
            transition(
                &mut record,
                WalletJobState::Waiting,
                Some(error.to_string()),
            );
            save(ctx.store.as_ref(), job_id, &record)?;
            return Ok(());
        }
        save(ctx.store.as_ref(), job_id, &record)?;
        let bytes = hex::decode(
            record
                .signed_hex
                .as_deref()
                .ok_or_else(|| internal("prepared bytes missing"))?,
        )
        .map_err(internal)?;
        let options = ergo_wallet_protocol::mining::PrivateTransactionOptions {
            label: Some(format!("Wallet job {}", record.job.id)),
            expires_at_height: Some(record.job.request.expires_at_height),
            ..Default::default()
        };
        match ctx
            .submitter
            .job_submit_private_transaction(bytes, options)
            .await
        {
            Ok(_) => transition(&mut record, WalletJobState::Queued, None),
            Err(error) if error.reason == "duplicate" => {
                transition(&mut record, WalletJobState::Queued, None)
            }
            Err(error) => {
                // A queue that is unavailable, catching up with the chain or
                // slow to answer has not judged the transaction.
                if matches!(
                    error.reason.as_str(),
                    "private_mining_unavailable" | "timeout"
                ) {
                    record.job.attempts -= 1;
                }
                transition(
                    &mut record,
                    WalletJobState::Prepared,
                    error.detail.or(Some(error.reason)),
                )
            }
        }
        save(ctx.store.as_ref(), job_id, &record)?;
        return Ok(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----
    fn request() -> WalletJobRequest {
        WalletJobRequest {
            label: "renew".into(),
            task: WalletJobTask::Renew {
                box_ids: vec!["11".repeat(32)],
            },
            not_before_height: 10,
            expires_at_height: 100,
            max_attempts: 3,
        }
    }

    // ----- happy path -----
    #[test]
    fn job_journal_assigns_durable_ids_and_bounds_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            assert_eq!(create(&db, request()).unwrap().id, "1");
        }
        let db = redb::Database::open(&path).unwrap();
        assert_eq!(create(&db, request()).unwrap().id, "2");
        for _ in 2..MAX_JOBS {
            create(&db, request()).unwrap();
        }
        assert!(create(&db, request()).is_err());
        let (_, mut record) = records(&db).unwrap().remove(0);
        transition(&mut record, WalletJobState::Cancelled, None);
        save(&db, 1, &record).unwrap();
        assert_eq!(create(&db, request()).unwrap().id, "257");
        assert_eq!(list(&db).unwrap().items.len(), MAX_JOBS);
    }

    #[test]
    fn job_reservations_survive_removed_wallet_rows_and_quarantine_is_inert() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("jobs.redb")).unwrap();
        create(&db, request()).unwrap();
        let before = reserved_inputs(&db).unwrap();
        let txn = crate::wallet::store::begin_write_quick(&db).unwrap();
        txn.open_table(crate::wallet::tables::WALLET_BOXES)
            .unwrap()
            .retain(|_, _| false)
            .unwrap();
        txn.open_table(crate::wallet::tables::WALLET_TXS)
            .unwrap()
            .retain(|_, _| false)
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(reserved_inputs(&db).unwrap(), before);
        assert_eq!(
            crate::wallet::mining_jobs::pending_jobs(
                &redb::ReadableDatabase::begin_read(&db).unwrap()
            )
            .unwrap(),
            vec![1]
        );
        let original = records(&db).unwrap().remove(0).1;
        assert_eq!(crate::wallet::mining_jobs::quarantine(&db).unwrap(), 1);
        assert!(list(&db).unwrap().items.is_empty());
        assert!(reserved_inputs(&db).unwrap().is_empty());
        let read = redb::ReadableDatabase::begin_read(&db).unwrap();
        let raw = read
            .open_table(crate::wallet::mining_jobs::QUARANTINE)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        let saved: Record = serde_json::from_slice(&raw).unwrap();
        assert_eq!(saved.job, original.job);
    }

    // ----- round-trips -----
    #[test]
    fn prepared_job_recovery_keeps_exact_signed_bytes_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            create(&db, request()).unwrap();
            let (_, mut record) = records(&db).unwrap().remove(0);
            record.signed_hex = Some("abcd".into());
            record.job.tx_id = Some("22".repeat(32));
            record.last_attempt_height = Some(50);
            transition(&mut record, WalletJobState::Prepared, None);
            save(&db, 1, &record).unwrap();
        }
        let db = redb::Database::open(&path).unwrap();
        let recovered = records(&db).unwrap().remove(0).1;
        assert_eq!(recovered.signed_hex.as_deref(), Some("abcd"));
        assert_eq!(recovered.last_attempt_height, Some(50));
        let response = serde_json::to_value(list(&db).unwrap()).unwrap();
        assert!(!response.to_string().contains("abcd"));
        assert!(response["items"][0].get("signedHex").is_none());
    }

    #[test]
    fn interrupted_unsigned_preparation_recovers_input_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("jobs.redb")).unwrap();
        create(&db, request()).unwrap();
        assert!(reserved_inputs(&db).unwrap().contains(&[0x11; 32]));
        let (_, mut record) = records(&db).unwrap().remove(0);
        transition(&mut record, WalletJobState::Preparing, None);
        save(&db, 1, &record).unwrap();
        assert!(reserved_inputs(&db).unwrap().is_empty());
        recover_preparing(&db).unwrap();
        assert!(reserved_inputs(&db).unwrap().contains(&[0x11; 32]));
        assert_eq!(list(&db).unwrap().items[0].state, WalletJobState::Waiting);
        transition(&mut record, WalletJobState::Cancelled, None);
        save(&db, 1, &record).unwrap();
        assert!(reserved_inputs(&db).unwrap().is_empty());
    }

    // ----- error paths -----
    #[test]
    fn job_approval_rejects_unbounded_inputs_and_invalid_deadlines() {
        let mut req = request();
        req.expires_at_height = req.not_before_height;
        assert!(validate_request(&req).is_err());
        req = request();
        req.max_attempts = 0;
        assert!(validate_request(&req).is_err());
        req = request();
        req.task = WalletJobTask::Renew {
            box_ids: vec!["11".repeat(32); 2],
        };
        assert!(validate_request(&req).is_err());
    }
}
