//! Scan handlers for `WalletCommand` — the full `/scan/*` surface:
//! `register` / `deregister` / `listAll` (registry ops), `unspentBoxes` /
//! `spentBoxes` (tracked-box reads), and `stopTracking` / `addBox` /
//! `p2sRule` (box-level + address-rule writes).
//!
//! The redb tables `WALLET_SCANS` + `WALLET_LAST_USED_SCAN_ID` are the durable
//! registry store; `WALLET_SCAN_BOXES` + `WALLET_SCAN_BOX_INDEX` hold the
//! tracked boxes. Each handler loads the tested [`ScanRegistry`] semantic
//! core, applies the op, and write-throughs the change. The single-writer
//! wallet task serializes these, so the read-then-write in each handler is
//! race-free.
//!
//! `ergo-api` can't depend on `ergo-wallet`, so the API carries the predicate
//! opaquely as JSON ([`ScanRequestDto`] / [`ScanDto`]); the DTO <-> domain
//! conversion (which also validates the `trackingRule` predicate) happens here.

use redb::ReadableTable;
use tokio::sync::oneshot;

use ergo_api::wallet::scan::{ScanBoxEntry, ScanBoxFilter, ScanDto, ScanRequestDto};
use ergo_api::wallet::WalletAdminError;
use ergo_state::wallet::tables::{
    scan_box_key, WALLET_LAST_USED_SCAN_ID, WALLET_SCANS, WALLET_SCAN_BOXES, WALLET_SCAN_BOX_INDEX,
    WALLET_SCAN_TXS,
};
use ergo_state::wallet::types::{ScanBoxStatus, ScanTrackedBox, ScanTxRecord};
use ergo_wallet::scan::{
    Scan, ScanRegister, ScanRegistry, ScanRequest, ScanningPredicate, WalletInteraction,
    MAX_SCAN_NAME_LENGTH, MINING_SCAN_ID, PAYMENTS_SCAN_ID,
};

use super::WriterContext;

fn internal(e: impl std::fmt::Display) -> WalletAdminError {
    WalletAdminError::Internal(e.to_string())
}

/// Refuse a `/scan/*` mutation while a full `/wallet/rescan` scan rebuild is in
/// flight. The rebuild snapshots the scan registry up front and repopulates the
/// scan tables block-by-block in a background task; a registry mutation
/// committed mid-rebuild (a new scan never backfilled, or a deregister/manual
/// row resurrected by later replay) would leave the registry and scan tables
/// out of sync. Reject for the rebuild window — the caller retries once it
/// completes. (`Ordering::SeqCst` matches the rebuild's flag set in
/// `admin.rs`.)
fn reject_during_scan_rebuild() -> Result<(), WalletAdminError> {
    if crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(WalletAdminError::BadRequest(
            "scan rebuild in progress (full /wallet/rescan); retry after it completes".to_string(),
        ));
    }
    Ok(())
}

/// Owns a registry snapshot for a `/wallet/rescan`, implementing ergo-state's
/// `ScanRescanMatcher`: it parses each serialized output box and matches it
/// against the registered scan rules — the rescan analog of
/// `WalletStateHook::match_boxes`, reusing the same
/// `ScanRegistry::matching_scan_ids`, so a rescan reproduces live scan
/// tracking exactly.
pub(crate) struct RescanScanMatcher {
    registry: ScanRegistry,
}

impl ergo_state::wallet::scan::ScanRescanMatcher for RescanScanMatcher {
    fn match_boxes(&self, boxes: &[&[u8]]) -> Vec<Vec<u16>> {
        boxes
            .iter()
            .map(|bytes| {
                let mut r = ergo_primitives::reader::VlqReader::new(bytes);
                match ergo_ser::ergo_box::read_ergo_box(&mut r) {
                    Ok(b) => self.registry.matching_scan_ids(&b),
                    // On-chain boxes were already validated, so a parse failure
                    // here is a serializer fault, not bad input — surface it and
                    // degrade that box to "no match" rather than abort the rescan.
                    Err(e) => {
                        tracing::error!(error = %e, "scan rescan: output box parse failed; no match");
                        Vec::new()
                    }
                }
            })
            .collect()
    }
}

/// Build a rescan scan-matcher snapshot iff ≥1 user scan is registered;
/// otherwise `None` (a node with no scans does no scan rescan). A registry-load
/// error degrades to `None` + log so the wallet rescan still proceeds without
/// touching the scan tables.
pub(crate) fn build_rescan_matcher(db: &redb::Database) -> Option<RescanScanMatcher> {
    match load_registry(db) {
        Ok(registry) if !registry.list().is_empty() => Some(RescanScanMatcher { registry }),
        Ok(_) => None,
        Err(e) => {
            tracing::error!(error = %e, "scan rescan: registry load failed; scans not rebuilt");
            None
        }
    }
}

/// Convert the opaque API request to the domain `ScanRequest`. A malformed
/// predicate / interaction is a client error (HTTP 400). Semantic validation
/// (name length, rule value) happens in [`register_request`], shared with the
/// `/scan/p2sRule` path.
fn request_from_dto(dto: ScanRequestDto) -> Result<ScanRequest, WalletAdminError> {
    let value = serde_json::to_value(&dto).map_err(internal)?;
    serde_json::from_value(value)
        .map_err(|e| WalletAdminError::BadRequest(format!("invalid scan request: {e}")))
}

/// Convert a domain `Scan` back to the opaque API DTO.
fn dto_from_scan(scan: &Scan) -> Result<ScanDto, WalletAdminError> {
    let value = serde_json::to_value(scan).map_err(internal)?;
    serde_json::from_value(value).map_err(internal)
}

/// Load all persisted scans plus the `lastUsedScanId` counter into a registry.
/// Missing tables/rows (a fresh node) yield an empty registry whose counter
/// defaults to [`PAYMENTS_SCAN_ID`], so the first allocated user id is 11.
///
/// `pub(crate)` so the block-apply hook (`WalletStateHook`) can load the
/// registry to match each block's boxes.
pub(crate) fn load_registry(db: &redb::Database) -> Result<ScanRegistry, WalletAdminError> {
    let read = db.begin_read().map_err(internal)?;

    let last_used = match read.open_table(WALLET_LAST_USED_SCAN_ID) {
        Ok(t) => t
            .get(())
            .map_err(internal)?
            .map(|g| g.value())
            .unwrap_or(PAYMENTS_SCAN_ID),
        Err(redb::TableError::TableDoesNotExist(_)) => PAYMENTS_SCAN_ID,
        Err(e) => return Err(internal(e)),
    };

    let scans = match read.open_table(WALLET_SCANS) {
        Ok(t) => {
            let mut scans = Vec::new();
            for entry in t.iter().map_err(internal)? {
                let (_, value) = entry.map_err(internal)?;
                let scan: Scan = serde_json::from_slice(&value.value()).map_err(internal)?;
                scans.push(scan);
            }
            scans
        }
        Err(redb::TableError::TableDoesNotExist(_)) => Vec::new(),
        Err(e) => return Err(internal(e)),
    };

    Ok(ScanRegistry::from_persisted(scans, last_used))
}

pub(crate) async fn register(
    ctx: &WriterContext<'_>,
    request: ScanRequestDto,
    reply: oneshot::Sender<Result<u16, WalletAdminError>>,
) {
    if let Err(e) = reject_during_scan_rebuild() {
        let _ = reply.send(Err(e));
        return;
    }
    let _ = reply.send(register_impl(ctx.db, request));
}

fn register_impl(db: &redb::Database, request: ScanRequestDto) -> Result<u16, WalletAdminError> {
    let request = request_from_dto(request)?;
    register_request(db, request)
}

/// Validate + allocate + persist a domain `ScanRequest`. Shared by
/// `/scan/register` (after DTO conversion) and `/scan/p2sRule` (which builds
/// the request directly from an address).
fn register_request(db: &redb::Database, request: ScanRequest) -> Result<u16, WalletAdminError> {
    // Scala `ScanRequest.toScan` rejects an over-long scan name (> 255 UTF-8
    // bytes) as a bad request before storing.
    if request.scan_name.len() > MAX_SCAN_NAME_LENGTH {
        return Err(WalletAdminError::BadRequest(format!(
            "scan name too long: {} bytes (max {MAX_SCAN_NAME_LENGTH})",
            request.scan_name.len()
        )));
    }
    // Reject a structurally-valid rule whose `contains`/`equals` value is not a
    // serialized constant — Scala rejects these at the registration codec, so a
    // malformed rule never gets stored (and never silently fails to match).
    request
        .tracking_rule
        .validate()
        .map_err(|e| WalletAdminError::BadRequest(format!("invalid tracking rule: {e}")))?;

    let mut registry = load_registry(db)?;
    let scan = registry.register(request).map_err(internal)?;

    // Persist the new scan and the advanced counter atomically (Scala
    // `addScan` writes both the scan key and `lastUsedScanId` in one batch).
    let write = db.begin_write().map_err(internal)?;
    {
        let value = serde_json::to_vec(&scan).map_err(internal)?;
        let mut scans = write.open_table(WALLET_SCANS).map_err(internal)?;
        scans.insert(scan.scan_id, value).map_err(internal)?;
        let mut counter = write
            .open_table(WALLET_LAST_USED_SCAN_ID)
            .map_err(internal)?;
        counter
            .insert((), registry.last_used_scan_id())
            .map_err(internal)?;
    }
    write.commit().map_err(internal)?;
    Ok(scan.scan_id)
}

/// Scala `/scan/p2sRule`: decode the address, register an
/// `equals(R1, ByteArrayConstant(serialized ErgoTree))` scan named after the
/// address itself, with `walletInteraction=off` + `removeOffchain=true`.
///
/// Address classes: P2PK and P2S decode to their canonical tree bytes; P2SH
/// is rejected (Scala registers the synthetic P2SH wrapper script — this
/// build's address path refuses P2SH outright, same posture as the indexer).
fn p2s_rule_impl(
    db: &redb::Database,
    network: ergo_ser::address::NetworkPrefix,
    p2s: &str,
) -> Result<u16, WalletAdminError> {
    let tree_bytes = ergo_ser::address::decode_address_to_tree_bytes(p2s, network)
        .map_err(|e| WalletAdminError::BadRequest(format!("can't parse {p2s}: {e}")))?;
    // The equals value is a serialized `Coll[Byte]` constant: type code 0x0e,
    // VLQ length, then the tree bytes (Scala `ByteArrayConstant`).
    let mut value = vec![0x0e];
    ergo_primitives::vlq::encode_vlq_into(tree_bytes.len() as u64, &mut value);
    value.extend_from_slice(&tree_bytes);
    let request = ScanRequest {
        scan_name: p2s.to_string(),
        tracking_rule: ScanningPredicate::Equals {
            register: ScanRegister::R1,
            value,
        },
        wallet_interaction: Some(WalletInteraction::Off),
        remove_offchain: Some(true),
    };
    register_request(db, request)
}

pub(crate) async fn deregister(
    ctx: &WriterContext<'_>,
    scan_id: u16,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    if let Err(e) = reject_during_scan_rebuild() {
        let _ = reply.send(Err(e));
        return;
    }
    let _ = reply.send(deregister_impl(ctx.db, scan_id));
}

fn deregister_impl(db: &redb::Database, scan_id: u16) -> Result<(), WalletAdminError> {
    let mut registry = load_registry(db)?;
    // Scala `removeScan` is not idempotent: a missing id is a failure. The
    // `/scan/deregister` route maps that to HTTP 400 (BadRequest).
    registry
        .deregister(scan_id)
        .map_err(|_| WalletAdminError::BadRequest(format!("no scan with id {scan_id}")))?;

    // Remove the scan key and persist the counter. The counter is never
    // decremented (deregister leaves `last_used_scan_id` unchanged), so this is
    // a no-op rewrite in the normal case. But when the counter row was
    // lost/under-set, `load_registry` lifts it to the highest scan id; writing
    // it here makes that recovery durable, so deregistering the highest scan
    // can't drop the counter and let the next register reuse the removed id.
    let write = db.begin_write().map_err(internal)?;
    {
        let mut scans = write.open_table(WALLET_SCANS).map_err(internal)?;
        scans.remove(scan_id).map_err(internal)?;
        let mut counter = write
            .open_table(WALLET_LAST_USED_SCAN_ID)
            .map_err(internal)?;
        counter
            .insert((), registry.last_used_scan_id())
            .map_err(internal)?;

        // Purge the scan's tracked-box rows and prune the reverse index, in the
        // same txn. Without this the rows are only hidden-on-read; since scan ids
        // are never reused they would accumulate forever. A box still tracked by
        // a surviving scan keeps its row and a pruned index entry. (Per-tx scan
        // tags in `WALLET_SCAN_TXS` stay hidden-on-read — keyed by height/tx, not
        // scan id, so purging them is a full-table scan left out of scope here.)
        let mut boxes = write.open_table(WALLET_SCAN_BOXES).map_err(internal)?;
        let box_ids: Vec<[u8; 32]> = boxes
            .range(scan_box_key(scan_id, &[0u8; 32])..=scan_box_key(scan_id, &[0xffu8; 32]))
            .map_err(internal)?
            .map(|item| {
                let (k, _) = item.map_err(internal)?;
                let mut id = [0u8; 32];
                id.copy_from_slice(&k.value()[2..]);
                Ok::<[u8; 32], WalletAdminError>(id)
            })
            .collect::<Result<_, _>>()?;
        let mut idx = write.open_table(WALLET_SCAN_BOX_INDEX).map_err(internal)?;
        for box_id in &box_ids {
            boxes
                .remove(scan_box_key(scan_id, box_id))
                .map_err(internal)?;
            let remaining: Vec<u16> = match idx.get(box_id).map_err(internal)? {
                Some(g) => bincode::deserialize::<Vec<u16>>(&g.value())
                    .map_err(internal)?
                    .into_iter()
                    .filter(|&s| s != scan_id)
                    .collect(),
                None => Vec::new(),
            };
            if remaining.is_empty() {
                idx.remove(box_id).map_err(internal)?;
            } else {
                idx.insert(*box_id, bincode::serialize(&remaining).map_err(internal)?)
                    .map_err(internal)?;
            }
        }
    }
    write.commit().map_err(internal)?;
    Ok(())
}

pub(crate) async fn list(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<Vec<ScanDto>, WalletAdminError>>,
) {
    let _ = reply.send(list_impl(ctx.db));
}

fn list_impl(db: &redb::Database) -> Result<Vec<ScanDto>, WalletAdminError> {
    load_registry(db)?
        .list()
        .iter()
        .map(dto_from_scan)
        .collect()
}

/// Parse a 32-byte box id from its hex form (client input → 400 on error).
fn parse_box_id(box_id_hex: &str) -> Result<[u8; 32], WalletAdminError> {
    let bytes = hex::decode(box_id_hex)
        .map_err(|e| WalletAdminError::BadRequest(format!("invalid boxId hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        WalletAdminError::BadRequest(format!("boxId must be 32 bytes, got {}", v.len()))
    })
}

/// Reject operations addressed at a reserved scan id. Our scan tables hold
/// user scans only (Scala's unified TrackedBox store also carries the wallet's
/// Mining/Payments scans, so its `/scan/addBox` can mutate wallet balance —
/// deliberately unsupported here; wallet boxes are managed by block apply).
fn require_user_scan_id(scan_id: u16) -> Result<(), WalletAdminError> {
    if scan_id <= PAYMENTS_SCAN_ID {
        return Err(WalletAdminError::BadRequest(format!(
            "scan id {scan_id} is reserved (1..={PAYMENTS_SCAN_ID}); only user scans can be managed via /scan"
        )));
    }
    Ok(())
}

/// Scala `WalletRegistry.removeScan` semantics: rewrite the box's scan set
/// without `scan_id`. Unknown box is a 400; a box the scan wasn't tracking
/// still succeeds (set-minus no-op); the index row is deleted when the set
/// empties.
///
/// Deliberate divergence: surviving sibling rows are left UNTOUCHED. Scala
/// routes through `updateScans`, which rebuilds every remaining row as a
/// fresh unspent `TrackedBox(box, creationHeight, scans)` — so a spent box
/// "un-spends" for the scans that still track it, an upstream accident we
/// don't replicate. Documented in the openapi header's scan note.
fn stop_tracking_impl(
    db: &redb::Database,
    scan_id: u16,
    box_id_hex: &str,
) -> Result<(), WalletAdminError> {
    require_user_scan_id(scan_id)?;
    let box_id = parse_box_id(box_id_hex)?;

    // The single-writer wallet task serializes this read-then-write; the
    // read happens inside the write txn, so block-apply writes (same redb,
    // global write lock) can't interleave.
    let write = db.begin_write().map_err(internal)?;
    {
        let mut idx = write.open_table(WALLET_SCAN_BOX_INDEX).map_err(internal)?;
        let ids: Vec<u16> = match idx.get(box_id).map_err(internal)? {
            Some(g) => bincode::deserialize(&g.value()).map_err(internal)?,
            None => {
                return Err(WalletAdminError::BadRequest(format!(
                    "no box with id {box_id_hex} found in the scan database"
                )))
            }
        };
        let new_ids: Vec<u16> = ids.iter().copied().filter(|&s| s != scan_id).collect();
        let mut boxes = write.open_table(WALLET_SCAN_BOXES).map_err(internal)?;
        boxes
            .remove(scan_box_key(scan_id, &box_id))
            .map_err(internal)?;
        if new_ids.is_empty() {
            idx.remove(box_id).map_err(internal)?;
        } else {
            idx.insert(box_id, bincode::serialize(&new_ids).map_err(internal)?)
                .map_err(internal)?;
        }
    }
    write.commit().map_err(internal)?;
    Ok(())
}

/// The `box` member of a `/scan/addBox` body: the standard
/// `ErgoTransactionOutput` JSON shape plus `transactionId` + `index`, which
/// Scala's SDK `ErgoBox` decoder requires (they fix the box id). Reuses the
/// canonical output decoder for the candidate fields.
#[derive(serde::Deserialize)]
struct AddBoxJson {
    #[serde(flatten)]
    output: ergo_rest_json::types::ScalaOutputInput,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
}

fn bad_request(e: impl std::fmt::Display) -> WalletAdminError {
    WalletAdminError::BadRequest(e.to_string())
}

/// Scala `/scan/addBox` (`WalletRegistry.updateScans`): REPLACE the box's scan
/// set with `scan_ids`, writing each as a fresh `Unspent` row at the box's
/// `creationHeight` — including scans kept across the update (a re-add resets
/// Spent back to Unspent, exactly as Scala rebuilds the `TrackedBox`). An
/// empty `scan_ids` untracks the box entirely; empty-on-untracked is Scala's
/// "can't remove a box which does not exist" error, surfaced as 400 here
/// (Scala's actor swallows it — an acknowledged `todo` in the reference).
///
/// Divergences (documented): scan ids must be registered user scans — adding
/// to an unregistered id would persist rows invisible to reads (hide-on-read)
/// forever (ids never reused), and reserved ids (<= 10) address the wallet's
/// own tables in this build, not the scan tables.
fn add_box_impl(
    db: &redb::Database,
    scan_ids: &[u16],
    box_json: &serde_json::Value,
) -> Result<String, WalletAdminError> {
    // Set semantics (Scala `Set[ScanId]`): dedupe + order-stabilize.
    let mut new_ids: Vec<u16> = scan_ids.to_vec();
    new_ids.sort_unstable();
    new_ids.dedup();

    let registry = load_registry(db)?;
    for &sid in &new_ids {
        require_user_scan_id(sid)?;
        if registry.get(sid).is_none() {
            return Err(WalletAdminError::BadRequest(format!(
                "no scan with id {sid} is registered"
            )));
        }
    }

    // Parse the box, then fix its identity. Preserve mode: this attaches a box
    // that already exists on chain, so soft-fork trees must be accepted and
    // tree/register wire bytes kept verbatim — Submit-mode re-serialization
    // could shift the computed box id off its on-chain identity, and then
    // block-apply spend-marking (keyed by the real id) would never find it.
    let parsed: AddBoxJson =
        serde_json::from_value(box_json.clone()).map_err(|e| bad_request(format!("box: {e}")))?;
    let candidate = ergo_rest_json::decode::decode_output_with_mode(
        &parsed.output,
        ergo_rest_json::decode::DecodeMode::Preserve,
    )
    .map_err(|(_, d)| bad_request(d))?;
    let tx_id: [u8; 32] = hex::decode(&parsed.transaction_id)
        .map_err(|e| bad_request(format!("transactionId hex: {e}")))?
        .try_into()
        .map_err(|v: Vec<u8>| {
            bad_request(format!("transactionId must be 32 bytes, got {}", v.len()))
        })?;
    let creation_height = candidate.creation_height;
    let ergo_box = ergo_ser::ergo_box::ErgoBox {
        candidate,
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes(tx_id),
        index: parsed.index,
    };
    let box_id = *ergo_box
        .box_id()
        .map_err(|e| bad_request(format!("box id: {e}")))?
        .as_bytes();
    let box_bytes = ergo_ser::ergo_box::serialize_ergo_box(&ergo_box)
        .map_err(|e| bad_request(format!("box serialize: {e}")))?;

    let write = db.begin_write().map_err(internal)?;
    {
        let mut idx = write.open_table(WALLET_SCAN_BOX_INDEX).map_err(internal)?;
        let old_ids: Vec<u16> = match idx.get(box_id).map_err(internal)? {
            Some(g) => bincode::deserialize(&g.value()).map_err(internal)?,
            None => Vec::new(),
        };
        if new_ids.is_empty() && old_ids.is_empty() {
            return Err(WalletAdminError::BadRequest(
                "can't remove a box which does not exist".to_string(),
            ));
        }

        let mut boxes = write.open_table(WALLET_SCAN_BOXES).map_err(internal)?;
        // Replace: drop every old row, then write fresh Unspent rows.
        for sid in old_ids {
            boxes.remove(scan_box_key(sid, &box_id)).map_err(internal)?;
        }
        for &sid in &new_ids {
            let tb = ScanTrackedBox {
                scan_id: sid,
                box_id,
                inclusion_height: creation_height,
                creation_out_index: parsed.index,
                box_bytes: box_bytes.clone(),
                status: ScanBoxStatus::Unspent,
            };
            boxes
                .insert(
                    scan_box_key(sid, &box_id),
                    bincode::serialize(&tb).map_err(internal)?,
                )
                .map_err(internal)?;
        }
        if new_ids.is_empty() {
            idx.remove(box_id).map_err(internal)?;
        } else {
            idx.insert(box_id, bincode::serialize(&new_ids).map_err(internal)?)
                .map_err(internal)?;
        }
    }
    write.commit().map_err(internal)?;
    Ok(hex::encode(box_id))
}

pub(crate) async fn stop_tracking(
    ctx: &WriterContext<'_>,
    scan_id: u16,
    box_id: String,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    if let Err(e) = reject_during_scan_rebuild() {
        let _ = reply.send(Err(e));
        return;
    }
    let _ = reply.send(stop_tracking_impl(ctx.db, scan_id, &box_id));
}

pub(crate) async fn add_box(
    ctx: &WriterContext<'_>,
    scan_ids: Vec<u16>,
    box_json: serde_json::Value,
    reply: oneshot::Sender<Result<String, WalletAdminError>>,
) {
    if let Err(e) = reject_during_scan_rebuild() {
        let _ = reply.send(Err(e));
        return;
    }
    let _ = reply.send(add_box_impl(ctx.db, &scan_ids, &box_json));
}

pub(crate) async fn p2s_rule(
    ctx: &WriterContext<'_>,
    p2s: String,
    reply: oneshot::Sender<Result<u16, WalletAdminError>>,
) {
    if let Err(e) = reject_during_scan_rebuild() {
        let _ = reply.send(Err(e));
        return;
    }
    let _ = reply.send(p2s_rule_impl(ctx.db, ctx.cfg.network, &p2s));
}

/// Transactions associated with a user scan, from `WALLET_SCAN_TXS` —
/// Scala's `getScanTransactions` filters all wallet txs by scan-id membership;
/// here the rows are pre-tagged at block apply and filtered the same way.
/// Unregistered / deregistered user scans read as empty (hide-on-read, parity
/// with the box endpoints).
///
/// Deliberate divergence: reserved ids read as empty here — the matcher tags
/// only registered user scans (≥ 11), while Scala serves mining-scan txs at
/// id 9 from its unified store. (Id 10 is the wallet's own listing at the
/// dispatch layer and never reaches here.)
pub(crate) fn scan_transactions_impl(
    db: &redb::Database,
    scan_id: u16,
    page: ergo_api::wallet::types::Page,
) -> Result<ergo_api::wallet::types::WalletTransactionsPage, WalletAdminError> {
    if scan_id > PAYMENTS_SCAN_ID && load_registry(db)?.get(scan_id).is_none() {
        return Ok(Default::default());
    }

    let read = db.begin_read().map_err(internal)?;
    let table = match read.open_table(WALLET_SCAN_TXS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Default::default()),
        Err(e) => return Err(internal(e)),
    };

    // Table order is (height, tx_id) ascending. Single pass: count every
    // membership match for `total`, but materialize entries only inside the
    // page window — `total` needs the full scan anyway (Scala likewise
    // filters its whole wallet-tx set), but out-of-window rows are dropped
    // without buffering or hex-rendering.
    let offset = page.offset as usize;
    let limit = page.limit as usize;
    let mut match_count: usize = 0;
    let mut items = Vec::new();
    for item in table.iter().map_err(internal)? {
        let (_, value) = item.map_err(internal)?;
        let rec: ScanTxRecord = bincode::deserialize(&value.value()).map_err(internal)?;
        if !rec.scan_ids.contains(&scan_id) {
            continue;
        }
        let in_window = match_count >= offset && items.len() < limit;
        match_count += 1;
        if in_window {
            items.push(ergo_api::wallet::types::WalletTransactionEntry {
                tx_id: hex::encode(rec.tx_id),
                block_height: rec.block_height,
                block_id: hex::encode(rec.block_id),
                wallet_outputs: rec.created.iter().map(hex::encode).collect(),
                wallet_inputs: rec.spent.iter().map(hex::encode).collect(),
                scan_ids: rec.scan_ids,
            });
        }
    }
    Ok(ergo_api::wallet::types::WalletTransactionsPage {
        total: match_count as u32,
        items,
    })
}

pub(crate) async fn unspent_boxes(
    ctx: &WriterContext<'_>,
    scan_id: u16,
    filter: ScanBoxFilter,
    reply: oneshot::Sender<Result<Vec<ScanBoxEntry>, WalletAdminError>>,
) {
    // `None` tip: read_scan_boxes derives the committed tip from the SAME redb
    // snapshot it reads the boxes from (consistent confirmations). The live
    // mempool view feeds the off-chain overlay (minConfirmations=-1).
    let _ = reply.send(read_scan_boxes(
        ctx.db,
        None,
        scan_id,
        false,
        &filter,
        Some(ctx.mempool.as_ref()),
    ));
}

pub(crate) async fn spent_boxes(
    ctx: &WriterContext<'_>,
    scan_id: u16,
    filter: ScanBoxFilter,
    reply: oneshot::Sender<Result<Vec<ScanBoxEntry>, WalletAdminError>>,
) {
    // spentBoxes has no off-chain component (Scala `getScanSpentBoxes`), but the
    // view is threaded through uniformly; the overlay self-gates on want_spent.
    let _ = reply.send(read_scan_boxes(
        ctx.db,
        None,
        scan_id,
        true,
        &filter,
        Some(ctx.mempool.as_ref()),
    ));
}

/// Read a scan's boxes (unspent if `want_spent` is false, spent if true),
/// applying the confirmation/inclusion-height filters and pagination, rendering
/// each to a [`ScanBoxEntry`].
///
/// Confirmations are computed against the live committed chain-tip height
/// (Scala `state.fullHeight`) — NOT the wallet's rescan-frozen scan height.
/// `tip_override` is `None` in production: the tip is then read from the SAME
/// redb snapshot as `WALLET_SCAN_BOXES`, so a block committing mid-read can't
/// give a freshly-tracked box negative confirmations (which the default
/// `minConfirmations=0` would then hide). Tests pass `Some(height)` to drive
/// confirmations deterministically without seeding chain-state meta.
fn read_scan_boxes(
    db: &redb::Database,
    tip_override: Option<u32>,
    scan_id: u16,
    want_spent: bool,
    filter: &ScanBoxFilter,
    mempool: Option<&dyn ergo_api::MempoolView>,
) -> Result<Vec<ScanBoxEntry>, WalletAdminError> {
    // Reserved scan ids 9 (Mining) / 10 (Payments) surface the wallet's OWN
    // boxes, which live in WALLET_BOXES — the scan tables only hold user scans.
    // Bridge them: 9 = `MinerReward` provenance, 10 = `Owned`. Documented
    // divergence — Scala migrates a matured mining box 9→10, whereas our
    // provenance is fixed at creation, so matured mining stays under 9.
    if scan_id == MINING_SCAN_ID || scan_id == PAYMENTS_SCAN_ID {
        return read_reserved_scan_boxes(
            db,
            tip_override,
            scan_id == MINING_SCAN_ID,
            want_spent,
            filter,
            mempool,
        );
    }

    // Hide boxes belonging to a user scan that isn't currently registered.
    // `/scan/deregister` removes the scan from the registry but leaves its
    // tracked rows in WALLET_SCAN_BOXES (we don't purge on deregister), so a
    // read by the old id would otherwise still surface them. Reserved ids
    // (<= PAYMENTS_SCAN_ID) are not user-managed and never have rows here, so
    // they bypass this guard and fall through to the (empty) table read.
    //
    // Deliberate divergence from Scala: `ErgoWalletService.removeScan` neither
    // purges nor hides, so Scala keeps serving boxes tagged with a removed id.
    // Hiding is strictly safer; the orphaned rows are bounded (ids never reuse)
    // and reclaiming them via purge-on-deregister is a tracked follow-up.
    if scan_id > PAYMENTS_SCAN_ID && load_registry(db)?.get(scan_id).is_none() {
        return Ok(Vec::new());
    }

    let read = db.begin_read().map_err(internal)?;
    // Derive the tip from the same snapshot as the boxes (unless overridden).
    // `None` committed tip means no chain is applied yet → no tracked boxes
    // exist, so 0 is a safe base.
    let current_height = match tip_override {
        Some(h) => h,
        None => ergo_state::reader::committed_tip_in(&read)
            .map_err(internal)?
            .map(|(h, _)| h)
            .unwrap_or(0),
    };
    // The scan-boxes table is created lazily on the first tracked-box write, so
    // a scan whose boxes have only ever been seen off-chain (in the mempool) has
    // no table yet. Treat a missing table as "no confirmed boxes" and still fall
    // through to the off-chain overlay below, rather than returning early.
    let table_opt = match read.open_table(WALLET_SCAN_BOXES) {
        Ok(t) => Some(t),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(internal(e)),
    };

    // Range over exactly this scan's keys: [(scan_id, 0..0) ..= (scan_id, ff..ff)].
    let lo = scan_box_key(scan_id, &[0u8; 32]);
    let hi = scan_box_key(scan_id, &[0xffu8; 32]);

    let mut entries: Vec<ScanBoxEntry> = Vec::new();
    if let Some(table) = &table_opt {
        for item in table.range(lo..=hi).map_err(internal)? {
            let (_, value) = item.map_err(internal)?;
            let tb: ScanTrackedBox = bincode::deserialize(&value.value()).map_err(internal)?;

            let spent = matches!(tb.status, ScanBoxStatus::Spent { .. });
            if spent != want_spent {
                continue;
            }

            // Inclusion-height window. A `-1` max means unbounded.
            let h = tb.inclusion_height as i64;
            if h < filter.min_inclusion_height as i64 {
                continue;
            }
            if filter.max_inclusion_height >= 0 && h > filter.max_inclusion_height as i64 {
                continue;
            }

            // Confirmations window. `-1` bounds are unbounded.
            let confirmations = current_height as i64 - tb.inclusion_height as i64;
            if filter.min_confirmations >= 0 && confirmations < filter.min_confirmations as i64 {
                continue;
            }
            if filter.max_confirmations >= 0 && confirmations > filter.max_confirmations as i64 {
                continue;
            }

            // `value` is the leading u64 of the serialized box; read just that
            // rather than parsing the whole box (clients get the full box via `bytes`).
            let value = ergo_primitives::reader::VlqReader::new(&tb.box_bytes)
                .get_u64()
                .map_err(internal)?;

            entries.push(ScanBoxEntry {
                box_id: hex::encode(tb.box_id),
                value,
                inclusion_height: Some(tb.inclusion_height),
                confirmations_num: Some(confirmations),
                spent,
                bytes: hex::encode(&tb.box_bytes),
            });
        }
    }

    // Off-chain (mempool) overlay. Scala `getScanUnspentBoxes` merges the
    // off-chain boxes only when `considerUnconfirmed` (minConfirmations == -1),
    // and only into the UNSPENT list (`getScanSpentBoxes` has no off-chain
    // component). Off-chain boxes carry no inclusion height / confirmations and
    // sort to the front (None < Some) before pagination — `(unspent ++
    // unconfirmed).sortBy(inclusionHeightOpt)`.
    if !want_spent && filter.min_confirmations == -1 {
        if let Some(mp) = mempool {
            let registry = load_registry(db)?;
            let on_chain_ids: std::collections::HashSet<String> =
                entries.iter().map(|e| e.box_id.clone()).collect();
            for (box_id, b) in mp.pool_outputs().iter() {
                let scan_ids = registry.matching_scan_ids(b);
                if !scan_ids.contains(&scan_id) {
                    continue;
                }
                let hex_id = hex::encode(box_id.as_bytes());
                if on_chain_ids.contains(&hex_id) {
                    continue; // already confirmed on-chain in the read gap — dedup
                }
                // removeOffchain retention (Scala `OffChainRegistry.
                // updateOnTransaction`): a pool-created box spent within the pool
                // is dropped from the unspent list UNLESS it belongs to >1 scan,
                // or to a single USER scan (> PaymentsScanId), AND some tracking
                // scan opted out of off-chain removal (remove_offchain == false).
                if mp.is_spent_by_pool(box_id) {
                    let qualifies = scan_ids.len() > 1
                        || (scan_ids.len() == 1 && scan_ids[0] > PAYMENTS_SCAN_ID);
                    let leave = qualifies
                        && scan_ids.iter().any(|sid| {
                            registry
                                .get(*sid)
                                .map(|s| !s.remove_offchain)
                                .unwrap_or(false)
                        });
                    if !leave {
                        continue;
                    }
                }
                let bytes = ergo_ser::ergo_box::serialize_ergo_box(b).map_err(internal)?;
                entries.push(ScanBoxEntry {
                    box_id: hex_id,
                    value: b.candidate.value,
                    inclusion_height: None,
                    confirmations_num: None,
                    spent: false,
                    bytes: hex::encode(&bytes),
                });
            }
        }
    }

    // Order by inclusion height before paginating, matching Scala
    // `getScanUnspentBoxes`/`...SpentBoxes` (`sortBy(inclusionHeightOpt)`); box
    // id breaks ties deterministically (table order is by box id, not height).
    // `Option` orders None first, so off-chain boxes lead, matching Scala.
    entries.sort_by(|a, b| {
        a.inclusion_height
            .cmp(&b.inclusion_height)
            .then_with(|| a.box_id.cmp(&b.box_id))
    });

    let offset = filter.offset.max(0) as usize;
    let limit = filter.limit.max(0) as usize;
    Ok(entries.into_iter().skip(offset).take(limit).collect())
}

/// Reserved-scan-id read bridge: `/scan/{unspent,spent}Boxes/9|10` over the
/// wallet's own boxes (`WALLET_BOXES` + `WALLET_BOX_BYTES`). `mining` selects
/// the Mining scan (9 = `MinerReward`); otherwise Payments (10 = `Owned`).
/// Mirrors [`read_scan_boxes`]'s confirmation/inclusion-height filtering,
/// height-asc ordering, and pagination — the value comes straight from
/// `WalletBox.value` and `bytes` from the companion table (empty for boxes that
/// predate it, until a `/wallet/rescan` backfills them).
fn read_reserved_scan_boxes(
    db: &redb::Database,
    tip_override: Option<u32>,
    mining: bool,
    want_spent: bool,
    filter: &ScanBoxFilter,
    mempool: Option<&dyn ergo_api::MempoolView>,
) -> Result<Vec<ScanBoxEntry>, WalletAdminError> {
    let read = db.begin_read().map_err(internal)?;
    let current_height = match tip_override {
        Some(h) => h,
        None => ergo_state::reader::committed_tip_in(&read)
            .map_err(internal)?
            .map(|(h, _)| h)
            .unwrap_or(0),
    };
    let boxes = ergo_state::wallet::reader::WalletReader::new(&read)
        .reserved_scan_boxes(mining, want_spent)
        .map_err(internal)?;

    let mut entries: Vec<ScanBoxEntry> = Vec::new();
    for rb in boxes {
        let wb = &rb.wallet_box;
        let h = wb.creation_height as i64;
        if h < filter.min_inclusion_height as i64 {
            continue;
        }
        if filter.max_inclusion_height >= 0 && h > filter.max_inclusion_height as i64 {
            continue;
        }
        let confirmations = current_height as i64 - wb.creation_height as i64;
        if filter.min_confirmations >= 0 && confirmations < filter.min_confirmations as i64 {
            continue;
        }
        if filter.max_confirmations >= 0 && confirmations > filter.max_confirmations as i64 {
            continue;
        }
        entries.push(ScanBoxEntry {
            box_id: hex::encode(wb.box_id),
            value: wb.value,
            inclusion_height: Some(wb.creation_height),
            confirmations_num: Some(confirmations),
            spent: want_spent,
            bytes: hex::encode(&rb.box_bytes),
        });
    }

    // Off-chain (mempool) overlay for the wallet's OWN boxes, mirroring the
    // user-scan overlay in [`read_scan_boxes`]. Only the unspent view at
    // minConfirmations == -1 merges off-chain boxes. The reserved ids aren't
    // registry rules, so classify each pool box the same way the apply path
    // does: tree ∈ tracked p2pk trees → Owned (id 10); else an extracted
    // miner-reward pubkey ∈ tracked pubkeys → MinerReward (id 9). A reserved
    // box spent within the pool is always dropped from the unspent list (Scala
    // retains only multi-scan / user-scan boxes).
    if !want_spent && filter.min_confirmations == -1 {
        if let Some(mp) = mempool {
            let tracked_pubkeys: Vec<[u8; 33]> =
                ergo_state::wallet::reader::WalletReader::new(&read)
                    .tracked_pubkeys_with_paths()
                    .map_err(internal)?
                    .into_iter()
                    .map(|(_, pk, _)| pk)
                    .collect();
            let tracked_trees: std::collections::HashSet<Vec<u8>> = tracked_pubkeys
                .iter()
                .filter_map(|pk| ergo_ser::address::build_p2pk_tree_bytes(pk).ok())
                .collect();
            let on_chain_ids: std::collections::HashSet<String> =
                entries.iter().map(|e| e.box_id.clone()).collect();
            for (box_id, b) in mp.pool_outputs().iter() {
                let tree_bytes = b.candidate.ergo_tree_bytes();
                let matches = if mining {
                    ergo_state::wallet::miner_reward::extract_miner_reward_pubkey(tree_bytes)
                        .map(|pk| tracked_pubkeys.contains(&pk))
                        .unwrap_or(false)
                } else {
                    tracked_trees.contains(tree_bytes)
                };
                if !matches || mp.is_spent_by_pool(box_id) {
                    continue;
                }
                let hex_id = hex::encode(box_id.as_bytes());
                if on_chain_ids.contains(&hex_id) {
                    continue; // already confirmed on-chain — dedup
                }
                let bytes = ergo_ser::ergo_box::serialize_ergo_box(b).map_err(internal)?;
                entries.push(ScanBoxEntry {
                    box_id: hex_id,
                    value: b.candidate.value,
                    inclusion_height: None,
                    confirmations_num: None,
                    spent: false,
                    bytes: hex::encode(&bytes),
                });
            }
        }
    }

    entries.sort_by(|a, b| {
        a.inclusion_height
            .cmp(&b.inclusion_height)
            .then_with(|| a.box_id.cmp(&b.box_id))
    });
    let offset = filter.offset.max(0) as usize;
    let limit = filter.limit.max(0) as usize;
    Ok(entries.into_iter().skip(offset).take(limit).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_state::wallet::tables::wallet_tx_key;

    fn temp_db() -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        (dir, db)
    }

    /// A `containsAsset` tracking rule with the given fill byte.
    fn contains_asset_rule(fill: u8) -> serde_json::Value {
        serde_json::json!({
            "predicate": "containsAsset",
            "assetId": hex::encode([fill; 32]),
        })
    }

    fn req(name: &str, fill: u8) -> ScanRequestDto {
        ScanRequestDto {
            scan_name: name.to_string(),
            tracking_rule: contains_asset_rule(fill),
            wallet_interaction: None,
            remove_offchain: None,
        }
    }

    #[test]
    fn register_allocates_id_11_and_persists() {
        let (_dir, db) = temp_db();
        let id = register_impl(&db, req("a", 0x11)).unwrap();
        assert_eq!(id, 11, "first user scan id is PaymentsScanId + 1");

        let scans = list_impl(&db).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].scan_id, 11);
        assert_eq!(scans[0].scan_name, "a");
        // Defaults resolved (Scala): walletInteraction=shared, removeOffchain=true.
        assert_eq!(scans[0].wallet_interaction, "shared");
        assert!(scans[0].remove_offchain);
    }

    #[test]
    fn ids_are_monotonic_across_deregister() {
        let (_dir, db) = temp_db();
        assert_eq!(register_impl(&db, req("a", 0x11)).unwrap(), 11);
        assert_eq!(register_impl(&db, req("b", 0x22)).unwrap(), 12);

        deregister_impl(&db, 11).unwrap();
        // Counter is not rolled back: the next id continues at 13, not 11.
        assert_eq!(register_impl(&db, req("c", 0x33)).unwrap(), 13);

        let ids: Vec<u16> = list_impl(&db).unwrap().iter().map(|s| s.scan_id).collect();
        assert_eq!(ids, vec![12, 13], "11 stays gone; list is ascending by id");
    }

    #[test]
    fn deregister_missing_is_bad_request() {
        let (_dir, db) = temp_db();
        let err = deregister_impl(&db, 99).unwrap_err();
        assert!(matches!(err, WalletAdminError::BadRequest(_)));
        // After register+deregister, a second deregister also 400s (not idempotent).
        register_impl(&db, req("a", 0x11)).unwrap();
        deregister_impl(&db, 11).unwrap();
        assert!(matches!(
            deregister_impl(&db, 11).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
    }

    #[test]
    fn malformed_tracking_rule_is_bad_request() {
        let (_dir, db) = temp_db();
        let bad = ScanRequestDto {
            scan_name: "a".to_string(),
            tracking_rule: serde_json::json!({"predicate": "notARealPredicate"}),
            wallet_interaction: None,
            remove_offchain: None,
        };
        assert!(matches!(
            register_impl(&db, bad).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
    }

    #[test]
    fn invalid_wallet_interaction_is_bad_request() {
        let (_dir, db) = temp_db();
        let bad = ScanRequestDto {
            scan_name: "a".to_string(),
            tracking_rule: contains_asset_rule(0x11),
            wallet_interaction: Some("bogus".to_string()),
            remove_offchain: None,
        };
        assert!(matches!(
            register_impl(&db, bad).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
    }

    #[test]
    fn over_long_scan_name_is_bad_request() {
        let (_dir, db) = temp_db();
        // 256 bytes > MAX_SCAN_NAME_LENGTH (255) — Scala `toScan` rejects this.
        let long_name = "x".repeat(MAX_SCAN_NAME_LENGTH + 1);
        let bad = ScanRequestDto {
            scan_name: long_name,
            tracking_rule: contains_asset_rule(0x11),
            wallet_interaction: None,
            remove_offchain: None,
        };
        assert!(matches!(
            register_impl(&db, bad).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        assert!(list_impl(&db).unwrap().is_empty());
        // A name exactly at the limit is accepted.
        let ok = ScanRequestDto {
            scan_name: "y".repeat(MAX_SCAN_NAME_LENGTH),
            tracking_rule: contains_asset_rule(0x22),
            wallet_interaction: None,
            remove_offchain: None,
        };
        assert_eq!(register_impl(&db, ok).unwrap(), 11);
    }

    #[test]
    fn register_with_malformed_predicate_value_is_rejected_and_not_persisted() {
        let (_dir, db) = temp_db();
        // Structurally valid `contains`, value is valid hex but NOT a serialized
        // constant (0x00 is not a valid type code). Scala rejects this at the
        // registration codec; we reject it too, and persist nothing.
        let bad = ScanRequestDto {
            scan_name: "a".to_string(),
            tracking_rule: serde_json::json!({"predicate": "contains", "value": "00"}),
            wallet_interaction: None,
            remove_offchain: None,
        };
        assert!(matches!(
            register_impl(&db, bad).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        assert!(
            list_impl(&db).unwrap().is_empty(),
            "a rejected registration persists nothing"
        );
    }

    #[test]
    fn scans_survive_reopen_of_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            register_impl(&db, req("a", 0x11)).unwrap();
            register_impl(&db, req("b", 0x22)).unwrap();
        } // db dropped — flush to disk

        // Reopen the same file: scans AND the counter persist.
        let db = redb::Database::create(&path).unwrap();
        let scans = list_impl(&db).unwrap();
        assert_eq!(
            scans.iter().map(|s| s.scan_id).collect::<Vec<_>>(),
            vec![11, 12]
        );
        // Next allocation continues from the persisted counter.
        assert_eq!(register_impl(&db, req("c", 0x33)).unwrap(), 13);
    }

    #[test]
    fn deregister_persists_recovered_counter_so_highest_id_is_not_reused() {
        let (_dir, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 11
        register_impl(&db, req("b", 0x22)).unwrap(); // 12 (counter = 12)

        // Simulate a lost counter row (corruption / pre-counter state): scans
        // 11 and 12 remain, but the `lastUsedScanId` row is gone.
        {
            let w = db.begin_write().unwrap();
            {
                let mut counter = w.open_table(WALLET_LAST_USED_SCAN_ID).unwrap();
                counter.remove(()).unwrap();
            }
            w.commit().unwrap();
        }

        // Deregister the highest scan (12). The lifted counter must be persisted
        // here, or the next register recomputes from the remaining max (11) and
        // reuses 12.
        deregister_impl(&db, 12).unwrap();
        assert_eq!(
            register_impl(&db, req("c", 0x33)).unwrap(),
            13,
            "recovered counter persisted on deregister; id 12 is not reused"
        );
    }

    // ----- box reads -----

    /// Insert a scan-tracked box directly (box_bytes = a VLQ value, so the
    /// reader's value-extraction works without a full box).
    fn put_tracked_box(
        db: &redb::Database,
        scan_id: u16,
        box_fill: u8,
        height: u32,
        value: u64,
        spent: bool,
    ) {
        use ergo_primitives::writer::VlqWriter;
        let mut w = VlqWriter::new();
        w.put_u64(value);
        let tb = ScanTrackedBox {
            scan_id,
            box_id: [box_fill; 32],
            inclusion_height: height,
            creation_out_index: 0,
            box_bytes: w.result(),
            status: if spent {
                ScanBoxStatus::Spent {
                    spent_in_tx: [9u8; 32],
                    spent_at: height + 1,
                }
            } else {
                ScanBoxStatus::Unspent
            },
        };
        let wtxn = db.begin_write().unwrap();
        {
            let mut t = wtxn.open_table(WALLET_SCAN_BOXES).unwrap();
            t.insert(
                scan_box_key(scan_id, &[box_fill; 32]),
                bincode::serialize(&tb).unwrap(),
            )
            .unwrap();
        }
        wtxn.commit().unwrap();
    }

    fn filter() -> ScanBoxFilter {
        ScanBoxFilter {
            min_confirmations: 0,
            max_confirmations: -1,
            min_inclusion_height: 0,
            max_inclusion_height: -1,
            limit: 500,
            offset: 0,
        }
    }

    // ----- mempool (off-chain) overlay -----

    /// A `MempoolView` over a fixed set of pool outputs + spent-input ids,
    /// for the off-chain overlay tests.
    struct FakePool {
        outputs:
            std::sync::Arc<std::collections::HashMap<ergo_primitives::digest::Digest32, ErgoBox>>,
        spent: std::collections::HashSet<ergo_primitives::digest::Digest32>,
    }
    impl ergo_api::MempoolView for FakePool {
        fn is_spent_by_pool(&self, box_id: &ergo_primitives::digest::Digest32) -> bool {
            self.spent.contains(box_id)
        }
        fn pool_spending_tx(
            &self,
            _box_id: &ergo_primitives::digest::Digest32,
        ) -> Option<ergo_primitives::digest::Digest32> {
            None
        }
        fn pool_outputs(
            &self,
        ) -> std::sync::Arc<std::collections::HashMap<ergo_primitives::digest::Digest32, ErgoBox>>
        {
            self.outputs.clone()
        }
    }

    /// An `ErgoBox` carrying a single token with id `[fill; 32]` — matches a
    /// `containsAsset` scan registered via `req(_, fill)`.
    fn pool_box_with_token(fill: u8, value: u64) -> ErgoBox {
        use ergo_ser::ergo_tree::ErgoTree;
        use ergo_ser::opcode::Expr;
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::SigmaValue;
        use ergo_ser::token::{Token, TokenId};
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        };
        let tokens = vec![Token {
            token_id: TokenId::from_bytes([fill; 32]),
            amount: 1,
        }];
        let cand =
            ErgoBoxCandidate::new(value, tree, 1, tokens, AdditionalRegisters::empty()).unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes([7u8; 32]),
            index: 0,
        }
    }

    fn pool_of(boxes: Vec<ErgoBox>) -> (FakePool, Vec<ergo_primitives::digest::Digest32>) {
        let mut outputs = std::collections::HashMap::new();
        let mut ids = Vec::new();
        for b in boxes {
            let id = b.box_id().unwrap();
            ids.push(id);
            outputs.insert(id, b);
        }
        (
            FakePool {
                outputs: std::sync::Arc::new(outputs),
                spent: std::collections::HashSet::new(),
            },
            ids,
        )
    }

    #[test]
    fn mempool_overlay_includes_matching_offchain_box_when_unconfirmed() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // scan 11, containsAsset 0x11
        put_tracked_box(&db, 11, 0xA1, 100, 1_000_000, false); // on-chain unspent
        let (pool, ids) = pool_of(vec![pool_box_with_token(0x11, 5_000_000)]);
        let pid = ids[0];

        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(110), 11, false, &f, Some(&pool)).unwrap();

        assert_eq!(r.len(), 2, "on-chain + off-chain");
        // Off-chain box sorts FIRST (null inclusion height < Some), per Scala.
        let off = &r[0];
        assert_eq!(off.box_id, hex::encode(pid.as_bytes()));
        assert_eq!(off.inclusion_height, None);
        assert_eq!(off.confirmations_num, None);
        assert!(!off.spent);
        assert_eq!(off.value, 5_000_000);
    }

    #[test]
    fn mempool_overlay_gated_off_unless_min_confirmations_neg_one() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        put_tracked_box(&db, 11, 0xA1, 100, 1_000_000, false);
        let (pool, _) = pool_of(vec![pool_box_with_token(0x11, 5_000_000)]);

        // minConfirmations = 0 (default) must NOT pull off-chain boxes.
        let r = read_scan_boxes(&db, Some(110), 11, false, &filter(), Some(&pool)).unwrap();
        assert_eq!(r.len(), 1, "only on-chain at minConfirmations=0");
    }

    #[test]
    fn mempool_overlay_never_applies_to_spent_reads() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        let (pool, _) = pool_of(vec![pool_box_with_token(0x11, 5_000_000)]);

        // spentBoxes has no off-chain component in Scala, even at -1.
        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(110), 11, true, &f, Some(&pool)).unwrap();
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn mempool_overlay_skips_box_not_matching_scan() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // tracks asset 0x11
        let (pool, _) = pool_of(vec![pool_box_with_token(0x99, 5_000_000)]); // asset 0x99

        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(110), 11, false, &f, Some(&pool)).unwrap();
        assert_eq!(r.len(), 0, "pool box matches no scan");
    }

    #[test]
    fn mempool_overlay_dedups_box_already_on_chain() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        let pbox = pool_box_with_token(0x11, 5_000_000);
        let pid = pbox.box_id().unwrap();
        // Same box id already recorded on-chain (confirmed in the gap).
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(pid.as_bytes());
        {
            use ergo_primitives::writer::VlqWriter;
            let mut w = VlqWriter::new();
            w.put_u64(5_000_000);
            let tb = ScanTrackedBox {
                scan_id: 11,
                box_id: id_arr,
                inclusion_height: 100,
                creation_out_index: 0,
                box_bytes: w.result(),
                status: ScanBoxStatus::Unspent,
            };
            let wtxn = db.begin_write().unwrap();
            {
                let mut t = wtxn.open_table(WALLET_SCAN_BOXES).unwrap();
                t.insert(scan_box_key(11, &id_arr), bincode::serialize(&tb).unwrap())
                    .unwrap();
            }
            wtxn.commit().unwrap();
        }
        let (pool, _) = pool_of(vec![pbox]);

        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(110), 11, false, &f, Some(&pool)).unwrap();
        assert_eq!(r.len(), 1, "box already on-chain must not be duplicated");
        assert_eq!(r[0].inclusion_height, Some(100), "on-chain row wins");
    }

    /// A `containsAsset` scan request with `removeOffchain=false`.
    fn req_keep(name: &str, fill: u8) -> ScanRequestDto {
        ScanRequestDto {
            scan_name: name.to_string(),
            tracking_rule: contains_asset_rule(fill),
            wallet_interaction: None,
            remove_offchain: Some(false),
        }
    }

    fn pool_with_spent(b: ErgoBox) -> FakePool {
        let id = b.box_id().unwrap();
        let mut outputs = std::collections::HashMap::new();
        outputs.insert(id, b);
        let mut spent = std::collections::HashSet::new();
        spent.insert(id);
        FakePool {
            outputs: std::sync::Arc::new(outputs),
            spent,
        }
    }

    #[test]
    fn mempool_overlay_default_removeoffchain_drops_pool_spent_box() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // removeOffchain defaults true
        let pool = pool_with_spent(pool_box_with_token(0x11, 5_000_000));

        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(110), 11, false, &f, Some(&pool)).unwrap();
        assert_eq!(
            r.len(),
            0,
            "a pool-created box spent within the pool is dropped under removeOffchain=true"
        );
    }

    #[test]
    fn mempool_overlay_removeoffchain_false_keeps_pool_spent_user_box() {
        let (_d, db) = temp_db();
        register_impl(&db, req_keep("a", 0x11)).unwrap(); // removeOffchain=false
        let pbox = pool_box_with_token(0x11, 5_000_000);
        let pid = pbox.box_id().unwrap();
        let pool = pool_with_spent(pbox);

        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(110), 11, false, &f, Some(&pool)).unwrap();
        assert_eq!(
            r.len(),
            1,
            "removeOffchain=false retains the pool-spent box"
        );
        assert_eq!(r[0].box_id, hex::encode(pid.as_bytes()));
        assert!(!r[0].spent);
    }

    #[test]
    fn read_splits_unspent_and_spent_and_renders_value() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 11
        register_impl(&db, req("b", 0x22)).unwrap(); // 12
        put_tracked_box(&db, 11, 0xA1, 100, 1_000_000, false); // unspent
        put_tracked_box(&db, 11, 0xA2, 101, 2_000_000, true); // spent
        put_tracked_box(&db, 12, 0xB1, 100, 9, false); // other scan

        let unspent = read_scan_boxes(&db, Some(110), 11, false, &filter(), None).unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].box_id, hex::encode([0xA1u8; 32]));
        assert_eq!(unspent[0].value, 1_000_000);
        assert_eq!(unspent[0].inclusion_height, Some(100));
        assert_eq!(unspent[0].confirmations_num, Some(10)); // 110 - 100
        assert!(!unspent[0].spent);

        let spent = read_scan_boxes(&db, Some(110), 11, true, &filter(), None).unwrap();
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0].box_id, hex::encode([0xA2u8; 32]));
        assert!(spent[0].spent);
    }

    #[test]
    fn read_applies_inclusion_height_and_confirmation_filters() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        put_tracked_box(&db, 11, 0x01, 100, 1, false);
        put_tracked_box(&db, 11, 0x02, 200, 1, false);

        // minInclusionHeight = 150 keeps only the height-200 box.
        let mut f = filter();
        f.min_inclusion_height = 150;
        let r = read_scan_boxes(&db, Some(300), 11, false, &f, None).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].inclusion_height, Some(200));

        // maxConfirmations = 150 at tip 300 keeps the height-200 box (conf 100),
        // dropping height-100 (conf 200).
        let mut f = filter();
        f.max_confirmations = 150;
        let r = read_scan_boxes(&db, Some(300), 11, false, &f, None).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].inclusion_height, Some(200));
    }

    #[test]
    fn read_paginates_with_offset_and_limit() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        for i in 0..5u8 {
            put_tracked_box(&db, 11, i, 100 + i as u32, 1, false);
        }
        let mut f = filter();
        f.offset = 1;
        f.limit = 2;
        let r = read_scan_boxes(&db, Some(200), 11, false, &f, None).unwrap();
        assert_eq!(r.len(), 2);
        // Boxes iterate ascending by box id; offset 1 skips box 0x00.
        assert_eq!(r[0].box_id, hex::encode([1u8; 32]));
        assert_eq!(r[1].box_id, hex::encode([2u8; 32]));
    }

    #[test]
    fn read_empty_when_no_scan_box_table() {
        let (_d, db) = temp_db();
        // Register the scan so the read reaches the (absent) box table rather
        // than short-circuiting on the registration guard.
        register_impl(&db, req("a", 0x11)).unwrap();
        assert!(read_scan_boxes(&db, Some(100), 11, false, &filter(), None)
            .unwrap()
            .is_empty());
    }

    // ----- stopTracking -----

    /// The tracked row for `(scan_id, box)` if present.
    fn tracked(db: &redb::Database, scan_id: u16, box_fill: u8) -> Option<ScanTrackedBox> {
        let r = db.begin_read().unwrap();
        let t = match r.open_table(WALLET_SCAN_BOXES) {
            Ok(t) => t,
            Err(_) => return None,
        };
        t.get(scan_box_key(scan_id, &[box_fill; 32]))
            .unwrap()
            .map(|g| bincode::deserialize(&g.value()).unwrap())
    }

    /// Seed the reverse index row for a box (production invariant: every
    /// tracked `(scan, box)` row has its box -> scan-ids index entry).
    fn put_index(db: &redb::Database, box_fill: u8, ids: &[u16]) {
        let w = db.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_SCAN_BOX_INDEX).unwrap();
            t.insert([box_fill; 32], bincode::serialize(&ids.to_vec()).unwrap())
                .unwrap();
        }
        w.commit().unwrap();
    }

    fn index_ids(db: &redb::Database, box_fill: u8) -> Option<Vec<u16>> {
        let r = db.begin_read().unwrap();
        let t = match r.open_table(WALLET_SCAN_BOX_INDEX) {
            Ok(t) => t,
            Err(_) => return None,
        };
        t.get([box_fill; 32])
            .unwrap()
            .map(|g| bincode::deserialize(&g.value()).unwrap())
    }

    fn box_row_exists(db: &redb::Database, scan_id: u16, box_fill: u8) -> bool {
        let r = db.begin_read().unwrap();
        let t = match r.open_table(WALLET_SCAN_BOXES) {
            Ok(t) => t,
            Err(_) => return false,
        };
        t.get(scan_box_key(scan_id, &[box_fill; 32]))
            .unwrap()
            .is_some()
    }

    /// Deregistering a scan must PURGE its tracked-box rows (and prune the
    /// reverse index), not just hide them on read — otherwise orphaned
    /// `WALLET_SCAN_BOXES` rows accumulate forever (scan ids are never reused).
    /// A box still tracked by a surviving scan must keep its row + index entry.
    #[test]
    fn deregister_purges_orphaned_scan_box_rows() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // scan 11
        register_impl(&db, req("b", 0x22)).unwrap(); // scan 12
                                                     // A1/A2: tracked only by 11; B1: only by 12; C1: shared by 11 & 12.
        put_tracked_box(&db, 11, 0xA1, 100, 1, false);
        put_tracked_box(&db, 11, 0xA2, 100, 1, false);
        put_tracked_box(&db, 12, 0xB1, 100, 1, false);
        put_tracked_box(&db, 11, 0xC1, 100, 1, false);
        put_tracked_box(&db, 12, 0xC1, 100, 1, false);
        put_index(&db, 0xA1, &[11]);
        put_index(&db, 0xA2, &[11]);
        put_index(&db, 0xB1, &[12]);
        put_index(&db, 0xC1, &[11, 12]);

        deregister_impl(&db, 11).unwrap();

        // scan-11 rows purged.
        assert!(!box_row_exists(&db, 11, 0xA1), "A1 row should be purged");
        assert!(!box_row_exists(&db, 11, 0xA2), "A2 row should be purged");
        assert!(!box_row_exists(&db, 11, 0xC1), "C1@11 row should be purged");
        // scan-12 rows survive.
        assert!(box_row_exists(&db, 12, 0xB1), "B1 row must survive");
        assert!(box_row_exists(&db, 12, 0xC1), "C1@12 row must survive");
        // reverse index: 11-only boxes removed; shared box keeps 12 only.
        assert_eq!(index_ids(&db, 0xA1), None);
        assert_eq!(index_ids(&db, 0xA2), None);
        assert_eq!(index_ids(&db, 0xB1), Some(vec![12]));
        assert_eq!(index_ids(&db, 0xC1), Some(vec![12]));
    }

    #[test]
    fn stop_tracking_removes_row_and_index_entry() {
        let (_d, db) = temp_db();
        put_tracked_box(&db, 11, 0xA1, 100, 1, false);
        put_tracked_box(&db, 12, 0xA1, 100, 1, false);
        put_index(&db, 0xA1, &[11, 12]);

        stop_tracking_impl(&db, 11, &hex::encode([0xA1u8; 32])).unwrap();

        assert!(tracked(&db, 11, 0xA1).is_none(), "scan 11 row removed");
        assert!(tracked(&db, 12, 0xA1).is_some(), "scan 12 row untouched");
        assert_eq!(index_ids(&db, 0xA1), Some(vec![12]));
    }

    #[test]
    fn stop_tracking_last_scan_deletes_index_row() {
        let (_d, db) = temp_db();
        put_tracked_box(&db, 11, 0xA1, 100, 1, false);
        put_index(&db, 0xA1, &[11]);

        stop_tracking_impl(&db, 11, &hex::encode([0xA1u8; 32])).unwrap();

        assert!(tracked(&db, 11, 0xA1).is_none());
        assert_eq!(index_ids(&db, 0xA1), None, "empty index row deleted");
    }

    #[test]
    fn stop_tracking_unknown_box_is_bad_request() {
        // Scala WalletRegistry.removeScan fails when the box isn't in the
        // database at all.
        let (_d, db) = temp_db();
        let err = stop_tracking_impl(&db, 11, &hex::encode([0xB9u8; 32])).unwrap_err();
        assert!(matches!(err, WalletAdminError::BadRequest(_)));
    }

    #[test]
    fn stop_tracking_succeeds_when_scan_was_not_tracking_the_box() {
        // Scala parity: removeScan computes `scans - scanId` and rewrites —
        // success even if scanId wasn't in the set, as long as the box exists.
        let (_d, db) = temp_db();
        put_tracked_box(&db, 12, 0xA1, 100, 1, false);
        put_index(&db, 0xA1, &[12]);

        stop_tracking_impl(&db, 11, &hex::encode([0xA1u8; 32])).unwrap();
        assert!(tracked(&db, 12, 0xA1).is_some(), "scan 12 untouched");
        assert_eq!(index_ids(&db, 0xA1), Some(vec![12]));
    }

    #[test]
    fn stop_tracking_rejects_reserved_scan_id_and_bad_box_id() {
        let (_d, db) = temp_db();
        // Reserved ids are not managed via /scan in this build.
        assert!(matches!(
            stop_tracking_impl(&db, 10, &hex::encode([0xA1u8; 32])).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        // Malformed box id hex / wrong length.
        assert!(matches!(
            stop_tracking_impl(&db, 11, "zz").unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        assert!(matches!(
            stop_tracking_impl(&db, 11, "abcd").unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
    }

    // ----- addBox -----

    /// A valid `ErgoTransactionOutput` JSON body: canonical P2PK tree over the
    /// secp256k1 generator point, no assets/registers.
    fn box_json(value: u64, creation_height: u32, tx_fill: u8, index: u16) -> serde_json::Value {
        serde_json::json!({
            "value": value,
            "ergoTree": "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "assets": [],
            "creationHeight": creation_height,
            "additionalRegisters": {},
            "transactionId": hex::encode([tx_fill; 32]),
            "index": index,
        })
    }

    /// The tracked row for `(scan_id, box_id)` (explicit 32-byte id).
    fn tracked_id(db: &redb::Database, scan_id: u16, box_id: &[u8; 32]) -> Option<ScanTrackedBox> {
        let r = db.begin_read().unwrap();
        let t = match r.open_table(WALLET_SCAN_BOXES) {
            Ok(t) => t,
            Err(_) => return None,
        };
        t.get(scan_box_key(scan_id, box_id))
            .unwrap()
            .map(|g| bincode::deserialize(&g.value()).unwrap())
    }

    fn index_ids_id(db: &redb::Database, box_id: &[u8; 32]) -> Option<Vec<u16>> {
        let r = db.begin_read().unwrap();
        let t = match r.open_table(WALLET_SCAN_BOX_INDEX) {
            Ok(t) => t,
            Err(_) => return None,
        };
        t.get(*box_id)
            .unwrap()
            .map(|g| bincode::deserialize(&g.value()).unwrap())
    }

    /// Flip an existing tracked row to Spent (simulating a block-apply spend).
    fn mark_spent(db: &redb::Database, scan_id: u16, box_id: &[u8; 32]) {
        let mut tb = tracked_id(db, scan_id, box_id).expect("row exists");
        tb.status = ScanBoxStatus::Spent {
            spent_in_tx: [9u8; 32],
            spent_at: 555,
        };
        let w = db.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_SCAN_BOXES).unwrap();
            t.insert(
                scan_box_key(scan_id, box_id),
                bincode::serialize(&tb).unwrap(),
            )
            .unwrap();
        }
        w.commit().unwrap();
    }

    fn id_from_hex(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn add_box_creates_unspent_rows_and_index() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 11
        register_impl(&db, req("b", 0x22)).unwrap(); // 12

        let id_hex = add_box_impl(&db, &[11, 12], &box_json(1_000_000, 840, 0x77, 3)).unwrap();
        let box_id = id_from_hex(&id_hex);

        for sid in [11u16, 12] {
            let tb = tracked_id(&db, sid, &box_id).expect("row created");
            assert!(matches!(tb.status, ScanBoxStatus::Unspent));
            assert_eq!(tb.inclusion_height, 840, "Scala uses box.creationHeight");
            assert_eq!(tb.creation_out_index, 3);
            // The serialized box's leading VLQ u64 is the value (read path relies on it).
            let v = ergo_primitives::reader::VlqReader::new(&tb.box_bytes)
                .get_u64()
                .unwrap();
            assert_eq!(v, 1_000_000);
        }
        assert_eq!(index_ids_id(&db, &box_id), Some(vec![11, 12]));
    }

    #[test]
    fn add_box_replaces_scan_set() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 11
        register_impl(&db, req("b", 0x22)).unwrap(); // 12
        register_impl(&db, req("c", 0x33)).unwrap(); // 13

        let j = box_json(5, 100, 0x77, 0);
        let id_hex = add_box_impl(&db, &[11, 12], &j).unwrap();
        let box_id = id_from_hex(&id_hex);

        // Scala updateScans REPLACES the set: [11,12] -> [12,13].
        add_box_impl(&db, &[12, 13], &j).unwrap();
        assert!(tracked_id(&db, 11, &box_id).is_none(), "11 dropped");
        assert!(tracked_id(&db, 12, &box_id).is_some(), "12 kept");
        assert!(tracked_id(&db, 13, &box_id).is_some(), "13 added");
        assert_eq!(index_ids_id(&db, &box_id), Some(vec![12, 13]));
    }

    #[test]
    fn add_box_readd_resets_spent_status() {
        // Scala replaces the whole TrackedBox with a fresh unspent row, even
        // for scans kept across the update.
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        let j = box_json(5, 100, 0x77, 0);
        let box_id = id_from_hex(&add_box_impl(&db, &[11], &j).unwrap());
        mark_spent(&db, 11, &box_id);

        add_box_impl(&db, &[11], &j).unwrap();
        assert!(matches!(
            tracked_id(&db, 11, &box_id).unwrap().status,
            ScanBoxStatus::Unspent
        ));
    }

    #[test]
    fn add_box_empty_scan_ids_untracks_box() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        let j = box_json(5, 100, 0x77, 0);
        let box_id = id_from_hex(&add_box_impl(&db, &[11], &j).unwrap());

        // Empty set: Scala updateScans(∅) removes the box entirely.
        add_box_impl(&db, &[], &j).unwrap();
        assert!(tracked_id(&db, 11, &box_id).is_none());
        assert_eq!(index_ids_id(&db, &box_id), None);

        // Empty set on an untracked box: Scala throws ("can't remove a box
        // which does not exist") — surfaced as 400 here, not swallowed.
        assert!(matches!(
            add_box_impl(&db, &[], &j).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
    }

    #[test]
    fn add_box_rejects_unknown_or_reserved_scan_ids() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        let j = box_json(5, 100, 0x77, 0);
        // Unregistered user id: rows would be invisible to reads (hide-on-read)
        // and ids are never reused — reject rather than persist orphans.
        assert!(matches!(
            add_box_impl(&db, &[99], &j).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        // Reserved id (wallet/mining scans live in the wallet tables here).
        assert!(matches!(
            add_box_impl(&db, &[10], &j).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        // Nothing persisted by the rejected calls.
        use redb::ReadableTableMetadata;
        let r = db.begin_read().unwrap();
        let empty = match r.open_table(WALLET_SCAN_BOXES) {
            Ok(t) => t.len().unwrap() == 0,
            Err(_) => true,
        };
        assert!(empty);
    }

    #[test]
    fn add_box_accepts_on_chain_soft_fork_tree() {
        // /scan/addBox attaches a box that already exists on chain, so the
        // decode must be Preserve-mode: live mainnet h=545684 tx[1] out[0]
        // carries a version-5 soft-fork tree (`cd07021a8e6f59fd4a`) that
        // Submit-mode rejects. Preserve also keeps register wire bytes
        // verbatim, so the computed box id matches the chain and block-apply
        // spend-marking can find the row.
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        let mut j = box_json(5, 100, 0x77, 0);
        j["ergoTree"] = serde_json::json!("cd07021a8e6f59fd4a");

        let id_hex = add_box_impl(&db, &[11], &j).expect("on-chain soft-fork box accepted");
        let box_id = id_from_hex(&id_hex);
        assert!(matches!(
            tracked_id(&db, 11, &box_id).unwrap().status,
            ScanBoxStatus::Unspent
        ));
    }

    #[test]
    fn add_box_rejects_malformed_box_json() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();

        // Bad ergoTree hex.
        let mut j = box_json(5, 100, 0x77, 0);
        j["ergoTree"] = serde_json::json!("zz");
        assert!(matches!(
            add_box_impl(&db, &[11], &j).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));

        // Missing transactionId (required to compute the box id).
        let mut j = box_json(5, 100, 0x77, 0);
        j.as_object_mut().unwrap().remove("transactionId");
        assert!(matches!(
            add_box_impl(&db, &[11], &j).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
    }

    // ----- p2sRule -----

    /// The canonical P2PK tree over the secp256k1 generator (same tree
    /// `box_json` pays to), as hex.
    const GEN_P2PK_TREE: &str =
        "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn p2s_rule_registers_equals_scan_that_matches_the_address() {
        use ergo_ser::address::NetworkPrefix;
        let (_d, db) = temp_db();
        let tree = hex::decode(GEN_P2PK_TREE).unwrap();
        let addr = ergo_ser::address::encode_address_from_tree_bytes(NetworkPrefix::Mainnet, &tree)
            .unwrap();

        let id = p2s_rule_impl(&db, NetworkPrefix::Mainnet, &addr).unwrap();
        assert_eq!(id, 11, "first user scan id");

        // Scala builds ScanRequest(p2s, equals(R1, tree), Off, true).
        let scans = list_impl(&db).unwrap();
        assert_eq!(scans[0].scan_name, addr);
        assert_eq!(scans[0].wallet_interaction, "off");
        assert!(scans[0].remove_offchain);
        let rule = &scans[0].tracking_rule;
        assert_eq!(rule["predicate"], "equals");
        let mut expected = vec![0x0e];
        ergo_primitives::vlq::encode_vlq_into(tree.len() as u64, &mut expected);
        expected.extend_from_slice(&tree);
        assert_eq!(rule["value"], hex::encode(&expected));

        // Load-bearing property: a box paying to that address MATCHES the scan.
        let parsed: AddBoxJson = serde_json::from_value(box_json(5, 100, 0x77, 0)).unwrap();
        let candidate = ergo_rest_json::decode::decode_output(&parsed.output).unwrap();
        let b = ergo_ser::ergo_box::ErgoBox {
            candidate,
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes([0x77; 32]),
            index: 0,
        };
        assert_eq!(load_registry(&db).unwrap().matching_scan_ids(&b), vec![11]);
    }

    #[test]
    fn p2s_rule_rejects_bad_or_wrong_network_address() {
        use ergo_ser::address::NetworkPrefix;
        let (_d, db) = temp_db();
        // Garbage.
        assert!(matches!(
            p2s_rule_impl(&db, NetworkPrefix::Mainnet, "not-an-address").unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        // Valid testnet address presented to a mainnet node.
        let tree = hex::decode(GEN_P2PK_TREE).unwrap();
        let testnet =
            ergo_ser::address::encode_address_from_tree_bytes(NetworkPrefix::Testnet, &tree)
                .unwrap();
        assert!(matches!(
            p2s_rule_impl(&db, NetworkPrefix::Mainnet, &testnet).unwrap_err(),
            WalletAdminError::BadRequest(_)
        ));
        // Nothing registered by the rejected calls.
        assert!(list_impl(&db).unwrap().is_empty());
    }

    // ----- RescanScanMatcher (scan participation in /wallet/rescan) -----

    /// `box_json` plus a single `assets` entry, so a `containsAsset` scan rule
    /// over `[token_fill; 32]` matches the box.
    fn box_json_with_asset(token_fill: u8) -> serde_json::Value {
        let mut j = box_json(1_000_000, 100, 0x77, 0);
        j["assets"] = serde_json::json!([
            { "tokenId": hex::encode([token_fill; 32]), "amount": 1u64 }
        ]);
        j
    }

    /// Serialize an `ErgoTransactionOutput` JSON body to its on-chain box
    /// bytes — exactly what the rescan replay hands the matcher.
    fn serialize_box_json(j: &serde_json::Value) -> Vec<u8> {
        let parsed: AddBoxJson = serde_json::from_value(j.clone()).unwrap();
        let candidate = ergo_rest_json::decode::decode_output(&parsed.output).unwrap();
        let b = ergo_ser::ergo_box::ErgoBox {
            candidate,
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes(id_from_hex(
                &parsed.transaction_id,
            )),
            index: parsed.index,
        };
        ergo_ser::ergo_box::serialize_ergo_box(&b).unwrap()
    }

    #[test]
    fn rescan_matcher_routes_serialized_boxes_through_the_registry() {
        use ergo_state::wallet::scan::ScanRescanMatcher;
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // scan 11: containsAsset [0x11;32]

        let matcher = build_rescan_matcher(&db).expect("≥1 scan ⇒ matcher built");

        // A box carrying token 0x11 matches scan 11; a no-asset box matches
        // nothing. The result is one entry per input box, in the same order —
        // the contract `rescan_full_rebuild` relies on.
        let hit = serialize_box_json(&box_json_with_asset(0x11));
        let miss = serialize_box_json(&box_json(5, 100, 0x77, 0));
        let out = matcher.match_boxes(&[hit.as_slice(), miss.as_slice()]);
        assert_eq!(out, vec![vec![11u16], vec![]]);
    }

    #[test]
    fn rescan_matcher_degrades_unparseable_box_to_no_match() {
        use ergo_state::wallet::scan::ScanRescanMatcher;
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap();
        let matcher = build_rescan_matcher(&db).unwrap();

        // Garbage bytes can't be a box: degrade that slot to "no match" rather
        // than abort the whole rescan. Result count still matches input count.
        let good = serialize_box_json(&box_json_with_asset(0x11));
        let bad: &[u8] = &[0xFF, 0xFF, 0xFF];
        let out = matcher.match_boxes(&[bad, good.as_slice()]);
        assert_eq!(out, vec![vec![], vec![11u16]]);
    }

    #[test]
    fn build_rescan_matcher_is_none_without_scans() {
        let (_d, db) = temp_db();
        assert!(
            build_rescan_matcher(&db).is_none(),
            "a node with no registered scans does no scan rescan"
        );
    }

    #[test]
    fn scan_rebuild_in_progress_quiesces_live_scan_apply() {
        // While a full rescan rebuilds the scan tables, the live block-apply
        // scan path must no-op so it doesn't race the rebuild's block-by-block
        // clear+repopulate. The gate lives in the `WalletApplyHook` impl:
        // `registered_scan_count` (the load-bearing gate that skips
        // `apply_block_to_scans`) and `match_boxes` both honor the flag.
        use ergo_state::wallet::WalletApplyHook;
        use std::sync::atomic::Ordering;

        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 1 registered scan, token 0x11

        // A box carrying token 0x11 matches scan 11.
        let parsed: AddBoxJson = serde_json::from_value(box_json_with_asset(0x11)).unwrap();
        let candidate = ergo_rest_json::decode::decode_output(&parsed.output).unwrap();
        let b = ergo_ser::ergo_box::ErgoBox {
            candidate,
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes(id_from_hex(
                &parsed.transaction_id,
            )),
            index: parsed.index,
        };

        let hook = crate::node::wallet_bridge::WalletStateHook {
            wallet: std::sync::Arc::new(parking_lot::RwLock::new(
                ergo_wallet::state::WalletState::empty(false),
            )),
            db: std::sync::Arc::new(db),
        };

        // Baseline (flag clear): the scan is live and the box matches.
        assert_eq!(hook.registered_scan_count(), 1);
        assert_eq!(
            hook.match_boxes(std::slice::from_ref(&b)),
            vec![vec![11u16]]
        );

        // Flag set: both hook methods quiesce. Capture under the flag, then
        // reset BEFORE asserting so a failure can't leak the flag to siblings.
        crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(true, Ordering::SeqCst);
        let gated_count = hook.registered_scan_count();
        let gated_match = hook.match_boxes(std::slice::from_ref(&b));
        crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(false, Ordering::SeqCst);

        assert_eq!(gated_count, 0, "live scan count gated to 0 during rebuild");
        assert_eq!(
            gated_match,
            vec![Vec::<u16>::new()],
            "live match suppressed during rebuild (one empty result per box)"
        );

        // Flag cleared: live apply sees the scan again.
        assert_eq!(hook.registered_scan_count(), 1);
    }

    #[test]
    fn scan_mutation_guard_rejects_during_rebuild() {
        use std::sync::atomic::Ordering;
        // Guard passes when no rebuild is in flight...
        crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(false, Ordering::SeqCst);
        assert!(reject_during_scan_rebuild().is_ok());
        // ...and rejects scan mutations while a rebuild snapshot is live.
        // Capture under the flag, then reset BEFORE asserting so a failure
        // can't leak the flag to sibling tests (same discipline as above).
        crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(true, Ordering::SeqCst);
        let gated = reject_during_scan_rebuild();
        crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(false, Ordering::SeqCst);
        assert!(
            matches!(gated, Err(WalletAdminError::BadRequest(_))),
            "scan mutation must be rejected during rebuild, got {gated:?}"
        );
    }

    // ----- transactionsByScanId (scan-tx reads) -----

    fn put_scan_tx(
        db: &redb::Database,
        height: u32,
        tx_fill: u8,
        scan_ids: Vec<u16>,
        created_fill: Option<u8>,
        spent_fill: Option<u8>,
    ) {
        let rec = ScanTxRecord {
            tx_id: [tx_fill; 32],
            block_height: height,
            block_id: [0xE0; 32],
            scan_ids,
            created: created_fill.map(|f| vec![[f; 32]]).unwrap_or_default(),
            spent: spent_fill.map(|f| vec![[f; 32]]).unwrap_or_default(),
        };
        let w = db.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_SCAN_TXS).unwrap();
            t.insert(
                wallet_tx_key(height, &[tx_fill; 32]),
                bincode::serialize(&rec).unwrap(),
            )
            .unwrap();
        }
        w.commit().unwrap();
    }

    fn page(offset: u32, limit: u32) -> ergo_api::wallet::types::Page {
        ergo_api::wallet::types::Page { offset, limit }
    }

    #[test]
    fn scan_transactions_filters_by_membership_and_renders_entries() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 11
        register_impl(&db, req("b", 0x22)).unwrap(); // 12
        put_scan_tx(&db, 100, 0x01, vec![11], Some(0xA1), None);
        put_scan_tx(&db, 101, 0x02, vec![11, 12], None, Some(0xA1));
        put_scan_tx(&db, 102, 0x03, vec![12], Some(0xB1), None);

        let p = scan_transactions_impl(&db, 11, page(0, 50)).unwrap();
        assert_eq!(p.total, 2, "txs tagged with 11 only");
        assert_eq!(p.items.len(), 2);
        assert_eq!(p.items[0].tx_id, hex::encode([0x01u8; 32]));
        assert_eq!(p.items[0].block_height, 100);
        assert_eq!(p.items[0].block_id, hex::encode([0xE0u8; 32]));
        assert_eq!(p.items[0].wallet_outputs, vec![hex::encode([0xA1u8; 32])]);
        assert!(p.items[0].wallet_inputs.is_empty());
        assert_eq!(p.items[0].scan_ids, vec![11]);
        assert_eq!(p.items[1].tx_id, hex::encode([0x02u8; 32]));
        assert_eq!(p.items[1].scan_ids, vec![11, 12]);
        assert_eq!(p.items[1].wallet_inputs, vec![hex::encode([0xA1u8; 32])]);

        // Pagination applies AFTER the membership filter.
        let p = scan_transactions_impl(&db, 11, page(1, 50)).unwrap();
        assert_eq!(p.total, 2);
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].tx_id, hex::encode([0x02u8; 32]));

        // The discriminating case: scan 12 matches tx2 (table position 2) and
        // tx3 (position 3). offset=1 over the FILTERED set yields exactly
        // [tx3]; a paginate-then-filter bug would yield [tx2, tx3] (offset
        // consumed by non-matching tx1 instead).
        let p = scan_transactions_impl(&db, 12, page(1, 50)).unwrap();
        assert_eq!(p.total, 2);
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].tx_id, hex::encode([0x03u8; 32]));
    }

    #[test]
    fn scan_transactions_hides_unregistered_user_scans() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 11
        put_scan_tx(&db, 100, 0x01, vec![11], Some(0xA1), None);

        // Registered: visible.
        assert_eq!(
            scan_transactions_impl(&db, 11, page(0, 50)).unwrap().total,
            1
        );

        // Deregistered: rows linger but reads hide them (hide-on-read parity
        // with the box endpoints).
        deregister_impl(&db, 11).unwrap();
        let p = scan_transactions_impl(&db, 11, page(0, 50)).unwrap();
        assert_eq!(p.total, 0);
        assert!(p.items.is_empty());

        // Never-registered user id and reserved id (9): empty, not an error.
        assert_eq!(
            scan_transactions_impl(&db, 99, page(0, 50)).unwrap().total,
            0
        );
        assert_eq!(
            scan_transactions_impl(&db, 9, page(0, 50)).unwrap().total,
            0
        );
    }

    #[test]
    fn read_hides_boxes_of_unregistered_or_deregistered_scan() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // scan 11
        put_tracked_box(&db, 11, 0xA1, 100, 1_000_000, false);
        // While registered, the box is visible.
        assert_eq!(
            read_scan_boxes(&db, Some(110), 11, false, &filter(), None)
                .unwrap()
                .len(),
            1
        );

        // Deregister 11. Its tracked rows linger in WALLET_SCAN_BOXES (we don't
        // purge on deregister), but reads must not surface them.
        deregister_impl(&db, 11).unwrap();
        assert!(read_scan_boxes(&db, Some(110), 11, false, &filter(), None)
            .unwrap()
            .is_empty());

        // A user-range id that was never registered also returns nothing, even
        // with rows seeded directly.
        put_tracked_box(&db, 12, 0xB1, 100, 5, false);
        assert!(read_scan_boxes(&db, Some(110), 12, false, &filter(), None)
            .unwrap()
            .is_empty());
    }
}

#[cfg(test)]
mod reserved_scan_read_tests {
    use super::*;
    use ergo_state::wallet::tables::{WALLET_BOXES, WALLET_BOX_BYTES};
    use ergo_state::wallet::types::{BoxProvenance, BoxStatus, WalletBox};

    fn temp_db() -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        (dir, db)
    }

    fn filter() -> ScanBoxFilter {
        ScanBoxFilter {
            min_confirmations: 0,
            max_confirmations: -1,
            min_inclusion_height: 0,
            max_inclusion_height: -1,
            limit: 500,
            offset: 0,
        }
    }

    fn put_wallet_box(
        db: &redb::Database,
        fill: u8,
        value: u64,
        height: u32,
        status: BoxStatus,
        provenance: BoxProvenance,
    ) {
        let wb = WalletBox {
            box_id: [fill; 32],
            creation_tx_id: [0u8; 32],
            creation_output_index: 0,
            creation_height: height,
            value,
            assets: Vec::new(),
            status,
            provenance,
        };
        let w = db.begin_write().unwrap();
        {
            w.open_table(WALLET_BOXES)
                .unwrap()
                .insert([fill; 32], bincode::serialize(&wb).unwrap())
                .unwrap();
            w.open_table(WALLET_BOX_BYTES)
                .unwrap()
                .insert([fill; 32], vec![fill, 0xAA])
                .unwrap();
        }
        w.commit().unwrap();
    }

    /// Reserved ids 9 (mining = MinerReward) and 10 (payments = Owned) bridge to
    /// the wallet's own boxes (WALLET_BOXES + WALLET_BOX_BYTES), not the (empty)
    /// scan tables — splitting by provenance and status.
    #[test]
    fn reserved_id_reads_bridge_wallet_boxes() {
        let (_d, db) = temp_db();
        // Mining: one Immature (unspent), one Spent.
        put_wallet_box(
            &db,
            0x91,
            1000,
            100,
            BoxStatus::Immature { matures_at: 820 },
            BoxProvenance::MinerReward,
        );
        put_wallet_box(
            &db,
            0x92,
            2000,
            101,
            BoxStatus::Spent {
                spent_in_tx: [9u8; 32],
                spent_at: 150,
            },
            BoxProvenance::MinerReward,
        );
        // Payments: one Confirmed (unspent).
        put_wallet_box(
            &db,
            0xA1,
            3000,
            102,
            BoxStatus::Confirmed,
            BoxProvenance::Owned,
        );

        let mining_unspent =
            read_scan_boxes(&db, Some(200), MINING_SCAN_ID, false, &filter(), None).unwrap();
        assert_eq!(mining_unspent.len(), 1);
        assert_eq!(mining_unspent[0].box_id, hex::encode([0x91u8; 32]));
        assert_eq!(mining_unspent[0].value, 1000);
        assert_eq!(mining_unspent[0].inclusion_height, Some(100));
        assert_eq!(mining_unspent[0].confirmations_num, Some(100));
        assert!(!mining_unspent[0].spent);
        assert_eq!(mining_unspent[0].bytes, hex::encode([0x91u8, 0xAA]));

        let mining_spent =
            read_scan_boxes(&db, Some(200), MINING_SCAN_ID, true, &filter(), None).unwrap();
        assert_eq!(mining_spent.len(), 1);
        assert_eq!(mining_spent[0].box_id, hex::encode([0x92u8; 32]));
        assert!(mining_spent[0].spent);

        let pay_unspent =
            read_scan_boxes(&db, Some(200), PAYMENTS_SCAN_ID, false, &filter(), None).unwrap();
        assert_eq!(pay_unspent.len(), 1);
        assert_eq!(pay_unspent[0].box_id, hex::encode([0xA1u8; 32]));
        assert_eq!(pay_unspent[0].value, 3000);
        // Mining boxes must NOT leak into payments (10).
        let pay_spent =
            read_scan_boxes(&db, Some(200), PAYMENTS_SCAN_ID, true, &filter(), None).unwrap();
        assert!(pay_spent.is_empty());
    }

    // ----- reserved-id off-chain (mempool) overlay -----

    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};

    /// A `MempoolView` over a fixed pool-output set (no pool spends).
    struct FakePool {
        outputs:
            std::sync::Arc<std::collections::HashMap<ergo_primitives::digest::Digest32, ErgoBox>>,
    }
    impl ergo_api::MempoolView for FakePool {
        fn is_spent_by_pool(&self, _box_id: &ergo_primitives::digest::Digest32) -> bool {
            false
        }
        fn pool_spending_tx(
            &self,
            _box_id: &ergo_primitives::digest::Digest32,
        ) -> Option<ergo_primitives::digest::Digest32> {
            None
        }
        fn pool_outputs(
            &self,
        ) -> std::sync::Arc<std::collections::HashMap<ergo_primitives::digest::Digest32, ErgoBox>>
        {
            self.outputs.clone()
        }
    }

    fn pool_of(b: ErgoBox) -> FakePool {
        let id = b.box_id().unwrap();
        let mut outputs = std::collections::HashMap::new();
        outputs.insert(id, b);
        FakePool {
            outputs: std::sync::Arc::new(outputs),
        }
    }

    /// Build a pool `ErgoBox` whose ErgoTree is exactly `tree_bytes`
    /// (round-trips through parse → re-serialize in `ErgoBoxCandidate::new`).
    fn pool_box_from_tree(tree_bytes: &[u8], value: u64) -> ErgoBox {
        use ergo_ser::register::AdditionalRegisters;
        let mut r = ergo_primitives::reader::VlqReader::new(tree_bytes);
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut r).unwrap();
        let cand =
            ErgoBoxCandidate::new(value, tree, 1, vec![], AdditionalRegisters::empty()).unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes([7u8; 32]),
            index: 0,
        }
    }

    fn track_pubkey(db: &redb::Database, idx: u64, pk: [u8; 33]) {
        use ergo_state::wallet::tables::{tracked_pubkey_key, WALLET_TRACKED_PUBKEYS};
        use ergo_state::wallet::types::TrackedPubkeyMeta;
        let meta = TrackedPubkeyMeta {
            derivation_path: Vec::new(),
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        let w = db.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_TRACKED_PUBKEYS).unwrap();
            t.insert(
                tracked_pubkey_key(idx, &pk),
                bincode::serialize(&meta).unwrap(),
            )
            .unwrap();
        }
        w.commit().unwrap();
    }

    fn tracked_pk() -> [u8; 33] {
        hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn reserved_payments_overlay_includes_owned_pool_box() {
        let (_d, db) = temp_db();
        let pk = tracked_pk();
        track_pubkey(&db, 0, pk);
        let tree = ergo_ser::address::build_p2pk_tree_bytes(&pk).unwrap();
        let pbox = pool_box_from_tree(&tree, 4_000_000);
        let pid = pbox.box_id().unwrap();
        let pool = pool_of(pbox);

        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(200), PAYMENTS_SCAN_ID, false, &f, Some(&pool)).unwrap();
        assert_eq!(r.len(), 1, "Owned pool box surfaces under payments (10)");
        assert_eq!(r[0].box_id, hex::encode(pid.as_bytes()));
        assert_eq!(r[0].inclusion_height, None);
        assert_eq!(r[0].confirmations_num, None);
        assert_eq!(r[0].value, 4_000_000);

        // An Owned box must NOT appear under mining (9).
        let m = read_scan_boxes(&db, Some(200), MINING_SCAN_ID, false, &f, Some(&pool)).unwrap();
        assert!(m.is_empty(), "Owned box must not surface under mining (9)");
    }

    #[test]
    fn reserved_mining_overlay_includes_reward_pool_box() {
        let (_d, db) = temp_db();
        // Canonical mainnet miner-reward tree (54 bytes) with its embedded pk.
        let reward_tree = hex::decode(
            "100204a00b08cd0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891fea02d192a39a8cc7a70173007301",
        )
        .unwrap();
        let reward_pk: [u8; 33] =
            hex::decode("0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f")
                .unwrap()
                .try_into()
                .unwrap();
        track_pubkey(&db, 0, reward_pk);
        let pbox = pool_box_from_tree(&reward_tree, 67_500_000_000);
        let pid = pbox.box_id().unwrap();
        let pool = pool_of(pbox);

        let mut f = filter();
        f.min_confirmations = -1;
        let r = read_scan_boxes(&db, Some(200), MINING_SCAN_ID, false, &f, Some(&pool)).unwrap();
        assert_eq!(r.len(), 1, "reward pool box surfaces under mining (9)");
        assert_eq!(r[0].box_id, hex::encode(pid.as_bytes()));
        assert_eq!(r[0].inclusion_height, None);

        // A reward box (wrapper tree, not a bare p2pk) must NOT appear under 10.
        let p = read_scan_boxes(&db, Some(200), PAYMENTS_SCAN_ID, false, &f, Some(&pool)).unwrap();
        assert!(
            p.is_empty(),
            "reward box must not surface under payments (10)"
        );
    }

    #[test]
    fn reserved_overlay_gated_off_unless_unconfirmed() {
        let (_d, db) = temp_db();
        let pk = tracked_pk();
        track_pubkey(&db, 0, pk);
        let tree = ergo_ser::address::build_p2pk_tree_bytes(&pk).unwrap();
        let pool = pool_of(pool_box_from_tree(&tree, 4_000_000));

        // minConfirmations = 0 (default) must NOT pull off-chain boxes for 9/10.
        let r = read_scan_boxes(
            &db,
            Some(200),
            PAYMENTS_SCAN_ID,
            false,
            &filter(),
            Some(&pool),
        )
        .unwrap();
        assert!(r.is_empty());
    }
}
