//! Bounded wallet-approved direct Spectrum N2T swaps. Only the serialized
//! wallet writer calls these operations. A generation is journaled before
//! admission; retiring its private queue entry precedes every re-sign.

use std::collections::{BTreeMap, BTreeSet};

use ergo_api::wallet::native::dto::{
    MiningSwap, MiningSwapDirection, MiningSwapPreview, MiningSwapRequest, MiningSwaps, TxRepr,
    WalletJobState,
};
use ergo_api::wallet::WalletAdminError;
use ergo_ser::ergo_box::ErgoBox;
use ergo_state::wallet::reader::WalletReader;
use ergo_state::wallet::types::{BoxProvenance, BoxStatus};
use ergo_wallet::spectrum_n2t::{self, Direction, Pool};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::commands::WriterContext;
use super::support::{generate_sign, sign_submit};
use super::ChainSnapshot;

const SWAPS: TableDefinition<u64, &[u8]> = TableDefinition::new("wallet_mining_swaps_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("wallet_mining_swaps_meta_v1");
const MAX_SWAPS: usize = 128;
const MAX_RECORD_BYTES: usize = 512 * 1024;
const SCAN_PER_WAKE: u32 = 128;
const MAX_LIFETIME: u32 = 7200;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    swap: MiningSwap,
    signed_hex: Option<String>,
    last_attempt_height: Option<u32>,
    approval_height: u32,
    search_height: u32,
    search_anchor: Option<[u8; 32]>,
    #[serde(default)]
    retiring_for_rebuild: bool,
    #[serde(default)]
    cancel_requested: bool,
}

fn internal(error: impl std::fmt::Display) -> WalletAdminError {
    WalletAdminError::Internal(format!("wallet mining swaps: {error}"))
}
fn bad(message: impl Into<String>) -> WalletAdminError {
    WalletAdminError::BadRequest(message.into())
}
fn bytes32(value: &str) -> Result<[u8; 32], WalletAdminError> {
    let bytes = hex::decode(value).map_err(|_| bad("expected lowercase 32-byte hex identifier"))?;
    if value != hex::encode(&bytes) {
        return Err(bad("expected lowercase 32-byte hex identifier"));
    }
    bytes
        .try_into()
        .map_err(|_| bad("expected lowercase 32-byte hex identifier"))
}
fn amount(value: &str) -> Result<u64, WalletAdminError> {
    let parsed: u64 = value
        .parse()
        .map_err(|_| bad("swap amounts must be positive decimal Long strings"))?;
    if parsed == 0 || parsed > i64::MAX as u64 || parsed.to_string() != value {
        return Err(bad("swap amounts must be positive decimal Long strings"));
    }
    Ok(parsed)
}
fn direction(value: MiningSwapDirection) -> Direction {
    match value {
        MiningSwapDirection::ErgToToken => Direction::ErgToToken,
        MiningSwapDirection::TokenToErg => Direction::TokenToErg,
    }
}
fn minimum(request: &MiningSwapRequest) -> Result<u64, WalletAdminError> {
    let quoted = amount(&request.approved_quote_output)?;
    let retained = 10_000u128
        .checked_sub(request.max_slippage_basis_points as u128)
        .ok_or_else(|| bad("slippage must be at most10000 basis points"))?;
    let slippage_min = (quoted as u128 * retained / 10_000) as u64;
    Ok(amount(&request.min_output_amount)?.max(slippage_min))
}
fn validate(request: &MiningSwapRequest) -> Result<(), WalletAdminError> {
    bytes32(&request.pool_box_id)?;
    bytes32(&request.pool_nft)?;
    if request.pool_tree_hash != spectrum_n2t::TREE_HASH {
        return Err(bad(
            "only the canonical Spectrum N2T v1 proposition hash is supported",
        ));
    }
    if request.label.is_empty()
        || request.label.len() > 160
        || request.receiving_address.len() > 256
    {
        return Err(bad("swap label/address is empty or exceeds its size bound"));
    }
    if request.funding_box_ids.is_empty() || request.funding_box_ids.len() > 32 {
        return Err(bad("swap approval requires1..=32 pinned funding boxes"));
    }
    let mut seen = BTreeSet::new();
    for id in &request.funding_box_ids {
        if !seen.insert(bytes32(id)?) {
            return Err(bad("funding box IDs must be distinct"));
        }
    }
    if seen.contains(&bytes32(&request.pool_box_id)?)
        || amount(&request.input_amount)? > amount(&request.max_input_amount)?
    {
        return Err(bad(
            "input exceeds max input or pool appears in owned funding",
        ));
    }
    minimum(request)?;
    if request.expires_at_height <= request.not_before_height
        || !(1..=100).contains(&request.max_attempts)
    {
        return Err(bad(
            "swap needs a later height deadline and1..=100 attempts",
        ));
    }
    Ok(())
}
fn records(db: &redb::Database) -> Result<Vec<(u64, Record)>, WalletAdminError> {
    let read = db.begin_read().map_err(internal)?;
    let table = match read.open_table(SWAPS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
        Err(error) => return Err(internal(error)),
    };
    let mut result = vec![];
    for row in table.iter().map_err(internal)? {
        let (key, bytes) = row.map_err(internal)?;
        if result.len() >= MAX_SWAPS || bytes.value().len() > MAX_RECORD_BYTES {
            return Err(internal("swap journal bounds exceeded"));
        }
        let record: Record = serde_json::from_slice(bytes.value()).map_err(internal)?;
        validate(&record.swap.request).map_err(internal)?;
        result.push((key.value(), record));
    }
    Ok(result)
}
fn save(db: &redb::Database, id: u64, record: &Record) -> Result<(), WalletAdminError> {
    let bytes = serde_json::to_vec(record).map_err(internal)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(bad("swap transaction exceeds journal limit"));
    }
    let write = db.begin_write().map_err(internal)?;
    write
        .open_table(SWAPS)
        .map_err(internal)?
        .insert(id, bytes.as_slice())
        .map_err(internal)?;
    write.commit().map_err(internal)
}
fn transition(record: &mut Record, state: WalletJobState, detail: Option<String>) {
    record.swap.state = state;
    record.swap.detail = detail;
    record.swap.updated_at_ms = crate::snapshot::unix_now_ms();
}

pub(super) fn recover_preparing(db: &redb::Database) -> Result<(), WalletAdminError> {
    for (id, mut record) in records(db)? {
        if record.swap.state == WalletJobState::Preparing {
            if record.signed_hex.is_some() {
                return Err(internal("preparing swap contains signed bytes"));
            }
            transition(
                &mut record,
                WalletJobState::Waiting,
                Some("recovering interrupted swap preparation".into()),
            );
            save(db, id, &record)?;
        }
    }
    Ok(())
}
pub(super) fn list(db: &redb::Database) -> Result<MiningSwaps, WalletAdminError> {
    let mut items = records(db)?
        .into_iter()
        .map(|(_, record)| record.swap)
        .collect::<Vec<_>>();
    items.reverse();
    Ok(MiningSwaps {
        items,
        max_swaps: MAX_SWAPS as u32,
    })
}
pub(crate) fn reserved_inputs(db: &redb::Database) -> Result<BTreeSet<[u8; 32]>, WalletAdminError> {
    let mut result = BTreeSet::new();
    for (_, record) in records(db)? {
        if record.swap.state.terminal() || record.swap.state == WalletJobState::Preparing {
            continue;
        }
        for value in &record.swap.request.funding_box_ids {
            result.insert(bytes32(value).map_err(internal)?);
        }
    }
    Ok(result)
}

fn funding_and_destination(
    ctx: &WriterContext<'_>,
    request: &MiningSwapRequest,
    snapshot: &ChainSnapshot,
    check_reservations: bool,
) -> Result<(Vec<ErgoBox>, Vec<u8>), WalletAdminError> {
    super::scan_guard::require_valid_scan(ctx.store.as_ref())?;
    let public_key =
        ergo_ser::address::decode_p2pk_address(&request.receiving_address, ctx.cfg.network)
            .map_err(|_| bad("receiving address must be tracked P2PK"))?;
    let reserved = if check_reservations {
        ctx.chain.reserved_wallet_inputs()?
    } else {
        BTreeSet::new()
    };
    let read = ctx.db.begin_read().map_err(internal)?;
    let reader = WalletReader::new(&read);
    let keys = reader.tracked_pubkeys_with_paths().map_err(internal)?;
    if !keys.iter().any(|(_, pk, _)| *pk == public_key) {
        return Err(bad("receiving address must be tracked by this wallet"));
    }
    let trees = keys
        .iter()
        .map(|(_, pk, _)| ergo_ser::address::build_p2pk_tree_bytes(pk).map_err(internal))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut funding = vec![];
    for value in &request.funding_box_ids {
        let id = bytes32(value)?;
        if reserved.contains(&id) {
            return Err(bad(
                "funding input is already reserved by private work or another wallet job",
            ));
        }
        let owned = reader
            .box_by_id(&id)
            .map_err(internal)?
            .ok_or(WalletAdminError::BoxNotFound)?;
        if owned.status != BoxStatus::Confirmed || owned.provenance != BoxProvenance::Owned {
            return Err(bad(
                "swap funding must be confirmed owned P2PK wallet boxes",
            ));
        }
        let full = snapshot
            .lookup_utxo(&id)
            .map_err(internal)?
            .ok_or(WalletAdminError::BoxNotFound)?;
        if !trees.contains(full.candidate.ergo_tree_bytes()) {
            return Err(WalletAdminError::UnsupportedScript);
        }
        funding.push(full);
    }
    let tree = ergo_ser::address::build_p2pk_tree_bytes(&public_key).map_err(internal)?;
    Ok((funding, tree))
}
fn build_preview(
    ctx: &WriterContext<'_>,
    request: &MiningSwapRequest,
    pool_id: &str,
    check_reservations: bool,
) -> Result<(MiningSwapPreview, ChainSnapshot), WalletAdminError> {
    validate(request)?;
    let snapshot = ctx.chain.chain_snapshot().map_err(super::map_chain_error)?;
    let height = snapshot.tip().height;
    if height >= request.expires_at_height
        || request.expires_at_height > height.saturating_add(MAX_LIFETIME)
    {
        return Err(bad("deadline must be in the next1..=7200 block heights"));
    }
    let full = snapshot
        .lookup_utxo(&bytes32(pool_id)?)
        .map_err(internal)?
        .ok_or(WalletAdminError::BoxNotFound)?;
    let pool =
        Pool::parse(full, &bytes32(&request.pool_nft)?).map_err(|error| bad(error.to_string()))?;
    let (funding, tree) = funding_and_destination(ctx, request, &snapshot, check_reservations)?;
    let effective_minimum = minimum(request)?;
    let (unsigned, output) = spectrum_n2t::build(
        &pool,
        &funding,
        &tree,
        spectrum_n2t::SwapTerms {
            direction: direction(request.direction),
            input: amount(&request.input_amount)?,
            min_output: effective_minimum,
            height: height.saturating_add(1),
        },
        snapshot.protocol_params(),
    )
    .map_err(|error| bad(error.to_string()))?;
    let mut writer = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_unsigned_transaction(&mut writer, &unsigned).map_err(internal)?;
    let preview = MiningSwapPreview {
        pool_box_id: pool_id.into(),
        pool_nft: request.pool_nft.clone(),
        pool_tree_hash: spectrum_n2t::TREE_HASH.into(),
        trade_token_id: hex::encode(pool.box_data.candidate.tokens[2].token_id.as_bytes()),
        direction: request.direction,
        input_amount: request.input_amount.clone(),
        quoted_output_amount: output.to_string(),
        effective_min_output_amount: effective_minimum.to_string(),
        fee_numerator: pool.fee_numerator as u32,
        snapshot_height: height,
        unsigned_transaction: TxRepr::from_bytes(&writer.result()),
    };
    ctx.chain
        .ensure_snapshot_current(&snapshot)
        .map_err(super::map_chain_error)?;
    Ok((preview, snapshot))
}
pub(super) fn preview(
    ctx: &WriterContext<'_>,
    request: &MiningSwapRequest,
) -> Result<MiningSwapPreview, WalletAdminError> {
    Ok(build_preview(ctx, request, &request.pool_box_id, true)?.0)
}
pub(super) fn create_owned(
    ctx: &WriterContext<'_>,
    request: MiningSwapRequest,
) -> Result<MiningSwap, WalletAdminError> {
    let preview = preview(ctx, &request)?;
    let anchor = ctx
        .chain
        .read_block_at(preview.snapshot_height)
        .map_err(internal)?
        .ok_or_else(|| bad("approval block unavailable; enable historical section retention"))?
        .block_id;
    create(ctx.db, request, preview.snapshot_height, anchor)
}
fn create(
    db: &redb::Database,
    request: MiningSwapRequest,
    height: u32,
    anchor: [u8; 32],
) -> Result<MiningSwap, WalletAdminError> {
    validate(&request)?;
    let prior = records(db)?;
    let remove = if prior.len() >= MAX_SWAPS {
        Some(
            prior
                .iter()
                .find(|(_, record)| record.swap.state.terminal())
                .map(|(id, _)| *id)
                .ok_or_else(|| bad("all bounded swap slots are active"))?,
        )
    } else {
        None
    };
    let write = db.begin_write().map_err(internal)?;
    let id = {
        let mut meta = write.open_table(META).map_err(internal)?;
        let last = meta
            .get("last_id")
            .map_err(internal)?
            .map(|guard| guard.value())
            .unwrap_or(0);
        let next = last
            .checked_add(1)
            .ok_or_else(|| internal("swap ID exhausted"))?;
        meta.insert("last_id", next).map_err(internal)?;
        next
    };
    let now = crate::snapshot::unix_now_ms();
    let swap = MiningSwap {
        id: id.to_string(),
        current_pool_box_id: request.pool_box_id.clone(),
        request,
        state: WalletJobState::Waiting,
        created_at_ms: now,
        updated_at_ms: now,
        attempts: 0,
        generation: 0,
        quoted_output_amount: None,
        tx_id: None,
        detail: None,
    };
    let record = Record {
        swap: swap.clone(),
        signed_hex: None,
        last_attempt_height: None,
        approval_height: height,
        search_height: height,
        search_anchor: Some(anchor),
        retiring_for_rebuild: false,
        cancel_requested: false,
    };
    let bytes = serde_json::to_vec(&record).map_err(internal)?;
    {
        let mut table = write.open_table(SWAPS).map_err(internal)?;
        if let Some(id) = remove {
            table.remove(id).map_err(internal)?;
        }
        table.insert(id, bytes.as_slice()).map_err(internal)?;
    }
    write.commit().map_err(internal)?;
    Ok(swap)
}

type QueueMetadata = BTreeMap<String, ergo_api::mining::PrivateTransactionEntry>;

async fn queue_metadata(ctx: &WriterContext<'_>) -> Result<QueueMetadata, WalletAdminError> {
    let entries = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        ctx.submit_handle.private_transactions(),
    )
    .await
    .map_err(|_| bad("private queue metadata timed out; signed generation retained"))?
    .map_err(sign_submit::map_submit_error)?;
    Ok(entries
        .into_iter()
        .map(|entry| (entry.tx_id.clone(), entry))
        .collect())
}

async fn retire(
    ctx: &WriterContext<'_>,
    record: &mut Record,
    metadata: &QueueMetadata,
) -> Result<bool, WalletAdminError> {
    if let Some(tx_id) = record.swap.tx_id.as_ref() {
        if let Some(entry) = metadata.get(tx_id) {
            if entry.state == "mined" {
                transition(record, WalletJobState::Mined, entry.reason.clone());
                return Ok(false);
            }
            // A timeout is uncertain: retain the exact durable generation.
            // Retirement acknowledgement removes eligibility and offered templates.
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                ctx.submit_handle.cancel_private_transaction(tx_id.clone()),
            )
            .await
            .map_err(|_| bad("private cancellation timed out; prior generation retained"))?
            .map_err(sign_submit::map_submit_error)?;
        }
    }
    record.swap.tx_id = None;
    record.signed_hex = None;
    Ok(true)
}
pub(super) async fn cancel(
    ctx: &WriterContext<'_>,
    value: &str,
) -> Result<MiningSwap, WalletAdminError> {
    let id: u64 = value
        .parse()
        .map_err(|_| bad("swap ID must be a decimal integer"))?;
    let mut record = records(ctx.db)?
        .into_iter()
        .find(|(key, _)| *key == id)
        .map(|(_, record)| record)
        .ok_or_else(|| bad("swap intent not found"))?;
    if record.swap.state.terminal() {
        return Ok(record.swap);
    }
    record.cancel_requested = true;
    record.retiring_for_rebuild = false;
    transition(
        &mut record,
        WalletJobState::Waiting,
        Some("cancellation requested; retaining prior bytes until retirement is confirmed".into()),
    );
    save(ctx.db, id, &record)?;
    let metadata = queue_metadata(ctx).await?;
    if !record.swap.state.terminal() && retire(ctx, &mut record, &metadata).await? {
        transition(&mut record, WalletJobState::Cancelled, None);
    }
    save(ctx.db, id, &record)?;
    Ok(record.swap)
}

/// Follow only the pinned NFT and exact canonical proposition. Read no more
/// than128 retained applied blocks per wake. A missing section or changed
/// anchor prevents signing; no latest-box guess or public service is used.
fn follow_pool(ctx: &WriterContext<'_>, record: &mut Record) -> Result<bool, WalletAdminError> {
    let snapshot = ctx.chain.chain_snapshot().map_err(super::map_chain_error)?;
    let tip = snapshot.tip().height;
    if snapshot
        .lookup_utxo(&bytes32(&record.swap.current_pool_box_id)?)
        .map_err(internal)?
        .is_some()
    {
        return Ok(true);
    }
    if let Some(anchor) = record.search_anchor {
        let block = ctx
            .chain
            .read_block_at(record.search_height)
            .map_err(internal)?
            .ok_or_else(|| bad("retained pool-following history is unavailable"))?;
        if block.block_id != anchor {
            record.swap.current_pool_box_id = record.swap.request.pool_box_id.clone();
            record.search_height = record.approval_height.saturating_sub(1);
            record.search_anchor = None;
        }
    }
    if tip < record.search_height || tip.saturating_sub(record.approval_height) > MAX_LIFETIME {
        return Err(bad(
            "pool follower exceeded its approved retained-history window",
        ));
    }
    let nft = bytes32(&record.swap.request.pool_nft)?;
    let end = tip.min(record.search_height.saturating_add(SCAN_PER_WAKE));
    for height in record.search_height.saturating_add(1)..=end {
        let block = ctx
            .chain
            .read_block_at(height)
            .map_err(internal)?
            .ok_or_else(|| bad("retained pool-following history is unavailable"))?;
        for tx in &block.txs {
            for output in &tx.outputs {
                if output
                    .assets
                    .first()
                    .is_some_and(|(id, amount)| id == &nft && *amount == 1)
                    && spectrum_n2t::is_supported_tree(&output.ergo_tree_bytes)
                {
                    record.swap.current_pool_box_id = hex::encode(output.box_id);
                }
            }
        }
        record.search_height = height;
        record.search_anchor = Some(block.block_id);
    }
    ctx.chain
        .ensure_snapshot_current(&snapshot)
        .map_err(super::map_chain_error)?;
    if end < tip {
        return Ok(false);
    }
    Ok(snapshot
        .lookup_utxo(&bytes32(&record.swap.current_pool_box_id)?)
        .map_err(internal)?
        .is_some())
}

pub(super) async fn tick(ctx: &WriterContext<'_>) -> Result<(), WalletAdminError> {
    if ctx.rescan.stopping() {
        return Ok(());
    }
    let height = ctx.chain.tip_height().map_err(internal)?;
    let pending = records(ctx.db)?;
    if pending.is_empty() {
        return Ok(());
    }
    // One bounded authoritative read per wake. Unavailable metadata is never
    // treated as absence and never authorizes re-signing uncertain old work.
    let metadata = match queue_metadata(ctx).await {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    let mut followed_pool = false;
    for (id, mut record) in pending {
        macro_rules! retire_generation {
            () => {
                match retire(ctx, &mut record, &metadata).await {
                    Ok(retired) => retired,
                    Err(error) => {
                        transition(
                            &mut record,
                            WalletJobState::Waiting,
                            Some(error.to_string()),
                        );
                        save(ctx.db, id, &record)?;
                        return Ok(());
                    }
                }
            };
        }
        if record.swap.state.terminal() && record.swap.state != WalletJobState::Mined {
            continue;
        }
        if let Some(tx_id) = &record.swap.tx_id {
            let entry = metadata.get(tx_id);
            if let Some(entry) = entry {
                if entry.state == "mined" {
                    if record.swap.state != WalletJobState::Mined
                        || record.swap.detail != entry.reason
                    {
                        transition(&mut record, WalletJobState::Mined, entry.reason.clone());
                        save(ctx.db, id, &record)?;
                    }
                    continue;
                }
                if record.swap.state == WalletJobState::Mined {
                    transition(
                        &mut record,
                        WalletJobState::Queued,
                        Some("mined swap returned to private queue after reorg".into()),
                    );
                }
                if entry.state == "cancelled" || entry.state == "expired" {
                    let state = if entry.state == "cancelled" {
                        WalletJobState::Cancelled
                    } else {
                        WalletJobState::Expired
                    };
                    if state == WalletJobState::Cancelled
                        && record.retiring_for_rebuild
                        && !record.cancel_requested
                    {
                        record.swap.tx_id = None;
                        record.signed_hex = None;
                        record.retiring_for_rebuild = false;
                        transition(&mut record, WalletJobState::Waiting, Some("previous generation retirement confirmed; bounded pool refresh may resume".into()));
                        save(ctx.db, id, &record)?;
                    } else {
                        transition(&mut record, state, entry.reason.clone());
                        save(ctx.db, id, &record)?;
                        continue;
                    }
                }
            }
        }
        if record.cancel_requested {
            if retire_generation!() {
                transition(&mut record, WalletJobState::Cancelled, None);
            }
            save(ctx.db, id, &record)?;
            return Ok(());
        }
        if height >= record.swap.request.expires_at_height {
            if retire_generation!() {
                transition(
                    &mut record,
                    WalletJobState::Expired,
                    Some("approved containing-block deadline reached".into()),
                );
            }
            save(ctx.db, id, &record)?;
            return Ok(());
        }
        if height < record.swap.request.not_before_height {
            continue;
        }
        let snapshot = ctx.chain.chain_snapshot().map_err(super::map_chain_error)?;
        if record
            .swap
            .request
            .funding_box_ids
            .iter()
            .map(|value| bytes32(value))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|id| snapshot.lookup_utxo(id).is_ok_and(|value| value.is_none()))
        {
            if record.swap.state == WalletJobState::Mined {
                continue;
            }
            if retire_generation!() {
                transition(
                    &mut record,
                    WalletJobState::Conflicted,
                    Some("an approved funding input was spent".into()),
                );
            }
            save(ctx.db, id, &record)?;
            return Ok(());
        }
        let old_pool = record.swap.current_pool_box_id.clone();
        let pool_spent = snapshot
            .lookup_utxo(&bytes32(&old_pool)?)
            .map_err(internal)?
            .is_none();
        if pool_spent && record.signed_hex.is_some() {
            if !record.retiring_for_rebuild {
                record.retiring_for_rebuild = true;
                save(ctx.db, id, &record)?;
            }
            if !retire_generation!() {
                save(ctx.db, id, &record)?;
                continue;
            }
            record.retiring_for_rebuild = false;
            transition(
                &mut record,
                WalletJobState::Waiting,
                Some("previous private generation retired; following spent pool".into()),
            );
            // Cancellation recovery boundary: a crash here cannot re-admit old bytes.
            save(ctx.db, id, &record)?;
        }
        if pool_spent {
            if followed_pool {
                continue;
            }
            followed_pool = true;
            let before_follow = record.clone();
            match follow_pool(ctx, &mut record) {
                Ok(true) => {}
                Ok(false) => {
                    transition(
                        &mut record,
                        WalletJobState::Waiting,
                        Some("following bounded retained pool history".into()),
                    );
                    save(ctx.db, id, &record)?;
                    continue;
                }
                Err(error) => {
                    record = before_follow;
                    transition(
                        &mut record,
                        WalletJobState::Waiting,
                        Some(error.to_string()),
                    );
                    save(ctx.db, id, &record)?;
                    continue;
                }
            }
        }
        if record.signed_hex.is_some() {
            let entry = metadata.get(
                record
                    .swap
                    .tx_id
                    .as_ref()
                    .ok_or_else(|| internal("signed swap missing transaction ID"))?,
            );
            if let Some(entry) =
                entry.filter(|entry| entry.state == "queued" || entry.state == "in_candidate")
            {
                let state = if entry.state == "in_candidate" {
                    WalletJobState::InCandidate
                } else {
                    WalletJobState::Queued
                };
                if record.swap.state != state || record.swap.detail != entry.reason {
                    transition(&mut record, state, entry.reason.clone());
                    save(ctx.db, id, &record)?;
                }
                continue;
            }
        }
        if record.last_attempt_height == Some(height) {
            continue;
        }
        if record.swap.attempts >= record.swap.request.max_attempts {
            if retire_generation!() {
                transition(
                    &mut record,
                    WalletJobState::Failed,
                    Some("approved retry limit reached".into()),
                );
            }
            save(ctx.db, id, &record)?;
            return Ok(());
        }
        if record.signed_hex.is_none() && ctx.storage.read().unlocked().is_none() {
            transition(
                &mut record,
                WalletJobState::WaitingForWallet,
                Some("unlock node wallet to sign approved swap".into()),
            );
            save(ctx.db, id, &record)?;
            continue;
        }
        record.swap.attempts += 1;
        record.last_attempt_height = Some(height);
        if record.signed_hex.is_none() {
            transition(&mut record, WalletJobState::Preparing, None);
            save(ctx.db, id, &record)?;
            let prepared = (|| {
                let (preview, snapshot) = build_preview(
                    ctx,
                    &record.swap.request,
                    &record.swap.current_pool_box_id,
                    true,
                )?;
                let signed = generate_sign::transaction_sign_impl_with_snapshot(
                    preview.unsigned_transaction.bytes_hex(),
                    None,
                    None,
                    ctx.storage,
                    ctx.state,
                    ctx.db,
                    &snapshot,
                )?;
                ctx.chain
                    .ensure_snapshot_current(&snapshot)
                    .map_err(super::map_chain_error)?;
                Ok::<_, WalletAdminError>((signed, preview.quoted_output_amount))
            })();
            match prepared {
                Ok((signed, output)) => {
                    record.swap.tx_id = Some(sign_submit::signed_tx_id_hex(&signed)?);
                    record.signed_hex = Some(hex::encode(signed));
                    record.swap.generation += 1;
                    record.swap.quoted_output_amount = Some(output);
                    // Set follower cursor to the exact signing snapshot height;
                    // only future successor creation needs to be searched.
                    record.search_height = height;
                    record.search_anchor = ctx
                        .chain
                        .read_block_at(height)
                        .map_err(internal)?
                        .map(|block| block.block_id);
                    transition(&mut record, WalletJobState::Prepared, None);
                }
                Err(error) => {
                    transition(
                        &mut record,
                        WalletJobState::Waiting,
                        Some(error.to_string()),
                    );
                    save(ctx.db, id, &record)?;
                    return Ok(());
                }
            }
        }
        // Durable exact-byte boundary precedes all private admission.
        save(ctx.db, id, &record)?;
        let bytes = hex::decode(
            record
                .signed_hex
                .as_deref()
                .ok_or_else(|| internal("prepared swap bytes missing"))?,
        )
        .map_err(internal)?;
        let options = ergo_api::mining::PrivateTransactionOptions {
            label: Some(format!(
                "Swap {} generation {}: {}",
                record.swap.id, record.swap.generation, record.swap.request.label
            )),
            // Hard height expiry is threaded through queue selection/solution dispatch.
            expires_at_height: Some(record.swap.request.expires_at_height),
            ..Default::default()
        };
        match tokio::time::timeout(
            std::time::Duration::from_secs(1),
            ctx.submit_handle.submit_private_transaction(bytes, options),
        )
        .await
        {
            Err(_) => transition(
                &mut record,
                WalletJobState::Prepared,
                Some("private admission timed out; exact signed bytes retained".into()),
            ),
            Ok(result) => match result {
                Ok(_) => transition(&mut record, WalletJobState::Queued, None),
                Err(error) if error.reason == "duplicate" => {
                    transition(&mut record, WalletJobState::Queued, None)
                }
                Err(error) => transition(
                    &mut record,
                    WalletJobState::Prepared,
                    error.detail.or(Some(error.reason)),
                ),
            },
        }
        save(ctx.db, id, &record)?;
        return Ok(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----
    fn request() -> MiningSwapRequest {
        MiningSwapRequest {
            label: "approved swap".into(),
            pool_box_id: "11".repeat(32),
            pool_nft: "22".repeat(32),
            pool_tree_hash: spectrum_n2t::TREE_HASH.into(),
            funding_box_ids: vec!["33".repeat(32)],
            receiving_address: "tracked".into(),
            direction: MiningSwapDirection::ErgToToken,
            input_amount: "100000000".into(),
            max_input_amount: "100000000".into(),
            min_output_amount: "100".into(),
            approved_quote_output: "1000".into(),
            max_slippage_basis_points: 100,
            not_before_height: 10,
            expires_at_height: 100,
            max_attempts: 3,
        }
    }
    fn database() -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("swaps.redb")).unwrap();
        (dir, db)
    }

    struct QueueStub {
        entries: parking_lot::Mutex<Vec<ergo_api::mining::PrivateTransactionEntry>>,
        fail_metadata: bool,
        fail_cancel: bool,
        metadata_reads: std::sync::atomic::AtomicUsize,
        cancellations: std::sync::atomic::AtomicUsize,
        public_submissions: std::sync::atomic::AtomicUsize,
    }
    #[async_trait::async_trait]
    impl super::super::TxSubmitter for QueueStub {
        async fn submit_transaction(
            &self,
            _: Vec<u8>,
        ) -> Result<String, ergo_api::types::SubmitError> {
            self.public_submissions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("swap intents must never use public submission");
        }
        async fn private_transactions(
            &self,
        ) -> Result<Vec<ergo_api::mining::PrivateTransactionEntry>, ergo_api::types::SubmitError>
        {
            self.metadata_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_metadata {
                return Err(ergo_api::types::SubmitError {
                    reason: "metadata_unavailable".into(),
                    detail: None,
                });
            }
            Ok(self.entries.lock().clone())
        }
        async fn cancel_private_transaction(
            &self,
            _: String,
        ) -> Result<(), ergo_api::types::SubmitError> {
            self.cancellations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_cancel {
                return Err(ergo_api::types::SubmitError {
                    reason: "cancellation_unavailable".into(),
                    detail: None,
                });
            }
            Ok(())
        }
    }
    fn queue(state: &str, fail_metadata: bool, fail_cancel: bool) -> Arc<QueueStub> {
        let entry = serde_json::from_value(serde_json::json!({
            "tx_id": "44".repeat(32), "state": state, "reason": null, "created_at_ms": 0,
            "expires_at_ms": null, "expires_at_height": 100, "priority": 0, "label": null,
            "input_ids": [], "fee_nano_erg": "0", "size_bytes": 2, "validation_cost": 0,
            "mined_block_id": null, "mined_height": null
        }))
        .unwrap();
        Arc::new(QueueStub {
            entries: parking_lot::Mutex::new(vec![entry]),
            fail_metadata,
            fail_cancel,
            metadata_reads: Default::default(),
            cancellations: Default::default(),
            public_submissions: Default::default(),
        })
    }
    use std::sync::Arc;
    struct ChainStub(u32);
    impl super::super::ChainStateAccessor for ChainStub {
        fn wallet_scan_height(&self) -> Result<u32, ergo_state::store::StateError> {
            Ok(self.0)
        }
        fn tip_height(&self) -> Result<u32, ergo_state::store::StateError> {
            Ok(self.0)
        }
        fn is_pruned(&self) -> bool {
            false
        }
        fn read_block_at(
            &self,
            _: u32,
        ) -> Result<
            Option<ergo_state::wallet::scan::RescanBlock>,
            ergo_state::wallet::scan::RescanReadError,
        > {
            Ok(None)
        }
    }
    struct Harness {
        _directory: tempfile::TempDir,
        db: Arc<redb::Database>,
        storage: Arc<parking_lot::RwLock<ergo_wallet::SecretStorage>>,
        state: Arc<parking_lot::RwLock<ergo_wallet::WalletState>>,
        rescan: Arc<crate::wallet_boot::RescanControl>,
        chain: Arc<dyn super::super::ChainStateAccessor>,
        submit: Arc<dyn super::super::TxSubmitter>,
        store: Arc<dyn ergo_state::wallet::WalletStore>,
        mempool: Arc<dyn ergo_api::MempoolView>,
        cfg: super::super::WriterConfig,
    }
    impl Harness {
        fn new(submit: Arc<QueueStub>, height: u32) -> Self {
            let (directory, db) = database();
            let db = Arc::new(db);
            Self {
                storage: Arc::new(parking_lot::RwLock::new(ergo_wallet::SecretStorage::open(
                    directory.path().join("wallet"),
                ))),
                state: Arc::new(parking_lot::RwLock::new(ergo_wallet::WalletState::empty(
                    false,
                ))),
                rescan: Arc::new(crate::wallet_boot::RescanControl::default()),
                chain: Arc::new(ChainStub(height)),
                submit,
                store: Arc::new(ergo_state::wallet::RedbWalletStore::new(db.clone())),
                mempool: Arc::new(ergo_api::NoopMempoolView::new()),
                cfg: super::super::WriterConfig {
                    network: ergo_ser::address::NetworkPrefix::Mainnet,
                    expose_private_keys: false,
                    reemission: None,
                    min_relay_fee_nano_erg: 1_000_000,
                    max_tx_size_bytes: 100_000,
                },
                db,
                _directory: directory,
            }
        }
        fn ctx(&self) -> WriterContext<'_> {
            WriterContext {
                rescan: &self.rescan,
                rescan_workers: &self.rescan.workers,
                storage: &self.storage,
                state: &self.state,
                db: &self.db,
                store: &self.store,
                chain: &self.chain,
                cfg: &self.cfg,
                submit_handle: &self.submit,
                mempool: &self.mempool,
            }
        }
        fn signed(&self) {
            create(&self.db, request(), 10, [1; 32]).unwrap();
            let (id, mut record) = records(&self.db).unwrap().remove(0);
            record.swap.tx_id = Some("44".repeat(32));
            record.signed_hex = Some("abcd".into());
            transition(&mut record, WalletJobState::Queued, None);
            save(&self.db, id, &record).unwrap();
        }
    }

    fn committed_inputs(harness: &mut Harness) {
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::ergo_box::{read_ergo_box, serialize_ergo_box};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/wallet/native_mint_burn_scala.json"
        ))
        .unwrap();
        let bytes = hex::decode(fixture["input_hex"].as_str().unwrap()).unwrap();
        let funding = read_ergo_box(&mut VlqReader::new(&bytes)).unwrap();
        let mut pool = funding.clone();
        pool.transaction_id = ModifierId::from_bytes([7; 32]);
        let pool_id = pool.box_id().unwrap();
        let funding_id = funding.box_id().unwrap();
        let mut store =
            ergo_state::store::StateStore::open(&harness._directory.path().join("state.redb"))
                .unwrap();
        store
            .initialize_genesis(&[
                (*funding_id.as_bytes(), bytes),
                (*pool_id.as_bytes(), serialize_ergo_box(&pool).unwrap()),
            ])
            .unwrap();
        let mut parent = ModifierId::from_bytes([0; 32]);
        for height in 1..=10 {
            let header = ergo_ser::header::Header {
                version: 2,
                parent_id: parent,
                ad_proofs_root: Digest32::ZERO,
                transactions_root: Digest32::ZERO,
                state_root: ADDigest::from_bytes([0; 33]),
                timestamp: 1_000_000 + height as u64,
                extension_root: Digest32::ZERO,
                n_bits: 16842752,
                height,
                votes: [0; 3],
                unparsed_bytes: vec![],
                solution: AutolykosSolution::V2 {
                    pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
                    nonce: [0; 8],
                },
            };
            let (bytes, id) = ergo_ser::header::serialize_header(&header).unwrap();
            store.store_header(id.as_bytes(), &bytes).unwrap();
            let root = store.root_digest();
            store
                .apply_block_unchecked_for_test(height, id.as_bytes(), &root, &[])
                .unwrap();
            parent = id;
        }
        harness.chain = Arc::new(super::super::ChainStateAccessorImpl::new(
            store.db_arc(),
            false,
            None,
        ));
        let (id, mut record) = records(&harness.db).unwrap().remove(0);
        record.swap.current_pool_box_id = hex::encode(pool_id.as_bytes());
        record.swap.request.pool_box_id = record.swap.current_pool_box_id.clone();
        record.swap.request.funding_box_ids = vec![hex::encode(funding_id.as_bytes())];
        save(&harness.db, id, &record).unwrap();
    }

    // ----- happy path -----
    #[test]
    fn approved_swap_minimum_combines_absolute_and_slippage_bounds() {
        let mut req = request();
        assert_eq!(minimum(&req).unwrap(), 990);
        req.min_output_amount = "995".into();
        assert_eq!(minimum(&req).unwrap(), 995);
        req.approved_quote_output = i64::MAX.to_string();
        req.max_slippage_basis_points = 0;
        assert_eq!(minimum(&req).unwrap(), i64::MAX as u64);
    }
    #[test]
    fn swap_reservations_release_only_terminal_or_serialized_preparation() {
        let (_dir, db) = database();
        create(&db, request(), 10, [1; 32]).unwrap();
        assert!(reserved_inputs(&db).unwrap().contains(&[0x33; 32]));
        let (id, mut record) = records(&db).unwrap().remove(0);
        transition(&mut record, WalletJobState::Preparing, None);
        save(&db, id, &record).unwrap();
        assert!(reserved_inputs(&db).unwrap().is_empty());
        recover_preparing(&db).unwrap();
        assert!(reserved_inputs(&db).unwrap().contains(&[0x33; 32]));
        transition(&mut record, WalletJobState::Cancelled, None);
        save(&db, id, &record).unwrap();
        assert!(reserved_inputs(&db).unwrap().is_empty());
    }

    // ----- round-trips -----
    #[test]
    fn swap_journal_reopens_exact_signed_generation_without_exposing_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swaps.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            assert_eq!(create(&db, request(), 10, [1; 32]).unwrap().id, "1");
            let (id, mut record) = records(&db).unwrap().remove(0);
            record.swap.generation = 2;
            record.swap.tx_id = Some("44".repeat(32));
            record.signed_hex = Some("abcd".into());
            record.last_attempt_height = Some(11);
            transition(&mut record, WalletJobState::Prepared, None);
            save(&db, id, &record).unwrap();
        }
        let db = redb::Database::open(&path).unwrap();
        let record = records(&db).unwrap().remove(0).1;
        assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
        assert_eq!(record.swap.generation, 2);
        assert_eq!(record.last_attempt_height, Some(11));
        let public = serde_json::to_value(list(&db).unwrap()).unwrap();
        assert!(!public.to_string().contains("abcd"));
        assert!(public["items"][0].get("signedHex").is_none());
        assert_eq!(create(&db, request(), 10, [1; 32]).unwrap().id, "2");
    }

    // ----- error paths -----
    #[tokio::test]
    async fn swap_uncertain_admission_recovers_authoritative_queue_before_exhausted_attempts() {
        let queue = queue("in_candidate", false, false);
        let mut harness = Harness::new(queue.clone(), 10);
        harness.signed();
        committed_inputs(&mut harness);
        let (id, mut record) = records(&harness.db).unwrap().remove(0);
        record.swap.request.max_attempts = 1;
        record.swap.attempts = 1;
        transition(
            &mut record,
            WalletJobState::Prepared,
            Some("private admission timed out".into()),
        );
        save(&harness.db, id, &record).unwrap();
        tick(&harness.ctx()).await.unwrap();
        let record = records(&harness.db).unwrap().remove(0).1;
        assert_eq!(record.swap.state, WalletJobState::InCandidate);
        assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
        assert_eq!(record.swap.attempts, 1);
        assert_eq!(
            queue
                .cancellations
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
    #[tokio::test]
    async fn swap_uncertain_internal_retirement_resumes_approved_refresh_after_confirmed_cancel() {
        let queue = queue("cancelled", false, false);
        let mut harness = Harness::new(queue.clone(), 10);
        harness.signed();
        committed_inputs(&mut harness);
        let (id, mut record) = records(&harness.db).unwrap().remove(0);
        record.retiring_for_rebuild = true;
        transition(
            &mut record,
            WalletJobState::Waiting,
            Some("private cancellation timed out".into()),
        );
        save(&harness.db, id, &record).unwrap();
        tick(&harness.ctx()).await.unwrap();
        let record = records(&harness.db).unwrap().remove(0).1;
        assert_eq!(record.swap.state, WalletJobState::WaitingForWallet);
        assert!(record.signed_hex.is_none());
        assert!(record.swap.tx_id.is_none());
        assert!(!record.retiring_for_rebuild);
        assert_eq!(record.swap.attempts, 0);
        assert_eq!(
            queue
                .cancellations
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn swap_failed_retirement_keeps_exact_prior_generation_and_never_broadcasts() {
        let queue = queue("queued", false, true);
        let harness = Harness::new(queue.clone(), 10);
        harness.signed();
        assert!(cancel(&harness.ctx(), "1").await.is_err());
        let record = records(&harness.db).unwrap().remove(0).1;
        assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
        assert_eq!(record.swap.state, WalletJobState::Waiting);
        assert!(record.cancel_requested);
        assert_eq!(
            queue
                .cancellations
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            queue
                .public_submissions
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
    #[tokio::test]
    async fn swap_unavailable_queue_metadata_keeps_durable_signed_work() {
        let queue = queue("queued", true, false);
        let harness = Harness::new(queue.clone(), 10);
        harness.signed();
        tick(&harness.ctx()).await.unwrap();
        let record = records(&harness.db).unwrap().remove(0).1;
        assert_eq!(record.signed_hex.as_deref(), Some("abcd"));
        assert_eq!(record.swap.attempts, 0);
        assert_eq!(
            queue
                .metadata_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            queue
                .cancellations
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
    #[tokio::test]
    async fn swap_cancellation_reports_already_mined_without_retiring_it() {
        let queue = queue("mined", false, false);
        let harness = Harness::new(queue.clone(), 10);
        harness.signed();
        assert_eq!(
            cancel(&harness.ctx(), "1").await.unwrap().state,
            WalletJobState::Mined
        );
        assert_eq!(
            records(&harness.db)
                .unwrap()
                .remove(0)
                .1
                .signed_hex
                .as_deref(),
            Some("abcd")
        );
        assert_eq!(
            queue
                .cancellations
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
    #[tokio::test]
    async fn swap_deadlines_use_one_bulk_metadata_read_and_one_retirement_per_wake() {
        let queue = queue("queued", false, false);
        let harness = Harness::new(queue.clone(), 100);
        harness.signed();
        for _ in 0..20 {
            create(&harness.db, request(), 10, [1; 32]).unwrap();
        }
        tick(&harness.ctx()).await.unwrap();
        let records = records(&harness.db).unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|(_, record)| record.swap.state == WalletJobState::Expired)
                .count(),
            1
        );
        assert_eq!(
            queue
                .metadata_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            queue
                .cancellations
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn swap_approval_rejects_implicit_inputs_other_contracts_and_unbounded_amounts() {
        let mut req = request();
        req.funding_box_ids.clear();
        assert!(validate(&req).is_err());
        req = request();
        req.funding_box_ids.push(req.funding_box_ids[0].clone());
        assert!(validate(&req).is_err());
        req = request();
        req.input_amount = "100000001".into();
        assert!(validate(&req).is_err());
        req = request();
        req.pool_tree_hash = "55".repeat(32);
        assert!(validate(&req).is_err());
        req = request();
        req.max_slippage_basis_points = 10001;
        assert!(validate(&req).is_err());
        req = request();
        req.expires_at_height = req.not_before_height;
        assert!(validate(&req).is_err());
        req = request();
        req.max_attempts = 101;
        assert!(validate(&req).is_err());
        assert!(amount("010").is_err());
        assert!(amount("9223372036854775808").is_err());
    }
    #[test]
    fn swap_preparation_recovery_rejects_inconsistent_signed_state() {
        let (_dir, db) = database();
        create(&db, request(), 10, [1; 32]).unwrap();
        let (id, mut record) = records(&db).unwrap().remove(0);
        record.signed_hex = Some("abcd".into());
        transition(&mut record, WalletJobState::Preparing, None);
        save(&db, id, &record).unwrap();
        assert!(recover_preparing(&db).is_err());
    }
}
