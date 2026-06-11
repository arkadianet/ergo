//! Scan-registry handlers for `WalletCommand` (`/scan/register`,
//! `/scan/deregister`, `/scan/listAll`).
//!
//! The redb tables `WALLET_SCANS` + `WALLET_LAST_USED_SCAN_ID` are the durable
//! store; each handler loads the tested [`ScanRegistry`] semantic core, applies
//! the op, and write-throughs the change. The single-writer wallet task
//! serializes these, so the read-then-write in each handler is race-free.
//!
//! `ergo-api` can't depend on `ergo-wallet`, so the API carries the predicate
//! opaquely as JSON ([`ScanRequestDto`] / [`ScanDto`]); the DTO <-> domain
//! conversion (which also validates the `trackingRule` predicate) happens here.

use redb::ReadableTable;
use tokio::sync::oneshot;

use ergo_api::wallet::scan::{ScanBoxEntry, ScanBoxFilter, ScanDto, ScanRequestDto};
use ergo_api::wallet::WalletAdminError;
use ergo_state::wallet::tables::{
    scan_box_key, WALLET_LAST_USED_SCAN_ID, WALLET_SCANS, WALLET_SCAN_BOXES,
};
use ergo_state::wallet::types::{ScanBoxStatus, ScanTrackedBox};
use ergo_wallet::scan::{Scan, ScanRegistry, ScanRequest, MAX_SCAN_NAME_LENGTH, PAYMENTS_SCAN_ID};

use super::WriterContext;

fn internal(e: impl std::fmt::Display) -> WalletAdminError {
    WalletAdminError::Internal(e.to_string())
}

/// Convert the opaque API request to the domain `ScanRequest`, parsing +
/// validating the `trackingRule` predicate and `walletInteraction` enum. A
/// malformed predicate / interaction is a client error (HTTP 400).
fn request_from_dto(dto: ScanRequestDto) -> Result<ScanRequest, WalletAdminError> {
    let value = serde_json::to_value(&dto).map_err(internal)?;
    let request: ScanRequest = serde_json::from_value(value)
        .map_err(|e| WalletAdminError::BadRequest(format!("invalid scan request: {e}")))?;
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
    Ok(request)
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
    let _ = reply.send(register_impl(ctx.db, request));
}

fn register_impl(db: &redb::Database, request: ScanRequestDto) -> Result<u16, WalletAdminError> {
    let request = request_from_dto(request)?;
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

pub(crate) async fn deregister(
    ctx: &WriterContext<'_>,
    scan_id: u16,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    let _ = reply.send(deregister_impl(ctx.db, scan_id));
}

fn deregister_impl(db: &redb::Database, scan_id: u16) -> Result<(), WalletAdminError> {
    let mut registry = load_registry(db)?;
    // Scala `removeScan` is not idempotent: a missing id is a failure. The
    // `/scan/deregister` route maps that to HTTP 400 (BadRequest), distinct
    // from the 404 `ScanNotFound` used by `transactionsByScanId`.
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

pub(crate) async fn unspent_boxes(
    ctx: &WriterContext<'_>,
    scan_id: u16,
    filter: ScanBoxFilter,
    reply: oneshot::Sender<Result<Vec<ScanBoxEntry>, WalletAdminError>>,
) {
    // `None` tip: read_scan_boxes derives the committed tip from the SAME redb
    // snapshot it reads the boxes from (consistent confirmations).
    let _ = reply.send(read_scan_boxes(ctx.db, None, scan_id, false, &filter));
}

pub(crate) async fn spent_boxes(
    ctx: &WriterContext<'_>,
    scan_id: u16,
    filter: ScanBoxFilter,
    reply: oneshot::Sender<Result<Vec<ScanBoxEntry>, WalletAdminError>>,
) {
    let _ = reply.send(read_scan_boxes(ctx.db, None, scan_id, true, &filter));
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
) -> Result<Vec<ScanBoxEntry>, WalletAdminError> {
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
    let table = match read.open_table(WALLET_SCAN_BOXES) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(internal(e)),
    };

    // Range over exactly this scan's keys: [(scan_id, 0..0) ..= (scan_id, ff..ff)].
    let lo = scan_box_key(scan_id, &[0u8; 32]);
    let hi = scan_box_key(scan_id, &[0xffu8; 32]);

    let mut entries: Vec<ScanBoxEntry> = Vec::new();
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
            inclusion_height: tb.inclusion_height,
            confirmations_num: confirmations,
            spent,
            bytes: hex::encode(&tb.box_bytes),
        });
    }

    // Order by inclusion height before paginating, matching Scala
    // `getScanUnspentBoxes`/`...SpentBoxes` (`sortBy(inclusionHeightOpt)`); box
    // id breaks ties deterministically (table order is by box id, not height).
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

    #[test]
    fn read_splits_unspent_and_spent_and_renders_value() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // 11
        register_impl(&db, req("b", 0x22)).unwrap(); // 12
        put_tracked_box(&db, 11, 0xA1, 100, 1_000_000, false); // unspent
        put_tracked_box(&db, 11, 0xA2, 101, 2_000_000, true); // spent
        put_tracked_box(&db, 12, 0xB1, 100, 9, false); // other scan

        let unspent = read_scan_boxes(&db, Some(110), 11, false, &filter()).unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].box_id, hex::encode([0xA1u8; 32]));
        assert_eq!(unspent[0].value, 1_000_000);
        assert_eq!(unspent[0].inclusion_height, 100);
        assert_eq!(unspent[0].confirmations_num, 10); // 110 - 100
        assert!(!unspent[0].spent);

        let spent = read_scan_boxes(&db, Some(110), 11, true, &filter()).unwrap();
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
        let r = read_scan_boxes(&db, Some(300), 11, false, &f).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].inclusion_height, 200);

        // maxConfirmations = 150 at tip 300 keeps the height-200 box (conf 100),
        // dropping height-100 (conf 200).
        let mut f = filter();
        f.max_confirmations = 150;
        let r = read_scan_boxes(&db, Some(300), 11, false, &f).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].inclusion_height, 200);
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
        let r = read_scan_boxes(&db, Some(200), 11, false, &f).unwrap();
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
        assert!(read_scan_boxes(&db, Some(100), 11, false, &filter())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn read_hides_boxes_of_unregistered_or_deregistered_scan() {
        let (_d, db) = temp_db();
        register_impl(&db, req("a", 0x11)).unwrap(); // scan 11
        put_tracked_box(&db, 11, 0xA1, 100, 1_000_000, false);
        // While registered, the box is visible.
        assert_eq!(
            read_scan_boxes(&db, Some(110), 11, false, &filter())
                .unwrap()
                .len(),
            1
        );

        // Deregister 11. Its tracked rows linger in WALLET_SCAN_BOXES (we don't
        // purge on deregister), but reads must not surface them.
        deregister_impl(&db, 11).unwrap();
        assert!(read_scan_boxes(&db, Some(110), 11, false, &filter())
            .unwrap()
            .is_empty());

        // A user-range id that was never registered also returns nothing, even
        // with rows seeded directly.
        put_tracked_box(&db, 12, 0xB1, 100, 5, false);
        assert!(read_scan_boxes(&db, Some(110), 12, false, &filter())
            .unwrap()
            .is_empty());
    }
}
