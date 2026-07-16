//! Admin + read-side handlers for `WalletCommand`.
//!
//! See `super::mod` for the WriterContext design and grouping rationale.

use std::sync::atomic::Ordering;

use tokio::sync::oneshot;

use ergo_api::wallet::types::{
    Page, TokenBalance, WalletAddressList, WalletBalances, WalletBoxesPage, WalletStatus,
    WalletTransactionEntry, WalletTransactionsPage,
};
use ergo_api::wallet::WalletAdminError;

use super::WriterContext;

pub(crate) async fn status(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletStatus, WalletAdminError>>,
) {
    let storage = ctx.storage.read();
    let state = ctx.state.read();
    let change_address = if state.is_unlocked() {
        state.change_address().unwrap_or("").to_string()
    } else {
        String::new()
    };
    let error = {
        match ctx.db.begin_read() {
            Ok(read_txn) => {
                let invalidated = read_txn
                    .open_table(ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED)
                    .ok()
                    .and_then(|t| t.get(()).ok().flatten().map(|g| g.value()))
                    .unwrap_or(false);
                if invalidated {
                    "scan_invalidated".to_string()
                } else {
                    String::new()
                }
            }
            Err(_) => String::new(),
        }
    };
    let resp = WalletStatus {
        is_initialized: !matches!(
            storage.lock_state(),
            ergo_wallet::storage::LockState::Uninitialized
        ),
        is_unlocked: state.is_unlocked(),
        change_address,
        wallet_height: ctx.chain.wallet_scan_height(),
        error,
    };
    let _ = reply.send(Ok(resp));
}

pub(crate) async fn init(
    ctx: &WriterContext<'_>,
    pass: String,
    mnemonic_pass: String,
    strength: u8,
    reply: oneshot::Sender<Result<String, WalletAdminError>>,
) {
    let mut storage = ctx.storage.write();
    // Refuse to overwrite an existing wallet: `init` on an initialized
    // wallet would persist a second secret file. Return a typed `WalletExists`
    // (native 409 wallet_exists / compat 400) instead of clobbering the seed.
    if !matches!(
        storage.lock_state(),
        ergo_wallet::storage::LockState::Uninitialized
    ) {
        let _ = reply.send(Err(WalletAdminError::WalletExists));
        return;
    }
    let strength_enum = match strength {
        12 => ergo_wallet::mnemonic::MnemonicStrength::Words12,
        15 => ergo_wallet::mnemonic::MnemonicStrength::Words15,
        18 => ergo_wallet::mnemonic::MnemonicStrength::Words18,
        21 => ergo_wallet::mnemonic::MnemonicStrength::Words21,
        24 => ergo_wallet::mnemonic::MnemonicStrength::Words24,
        n => {
            let _ = reply.send(Err(WalletAdminError::Internal(format!(
                "unsupported strength {n}"
            ))));
            return;
        }
    };
    let result = storage
        .init(strength_enum, &pass, &mnemonic_pass)
        .map_err(|e| match e {
            ergo_wallet::error::WalletError::InvalidMnemonic(_) => {
                WalletAdminError::InvalidMnemonic
            }
            _ => WalletAdminError::Internal(e.to_string()),
        });
    let _ = reply.send(result);
}

pub(crate) async fn restore(
    ctx: &WriterContext<'_>,
    mnemonic: String,
    mnemonic_pass: String,
    pass: String,
    use_pre_1627: bool,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    if ctx.chain.is_pruned() {
        let _ = reply.send(Err(WalletAdminError::RestorePruningUnsupported));
        return;
    }
    let mut storage = ctx.storage.write();
    // Refuse to overwrite an existing wallet (same safety guard as `init`).
    if !matches!(
        storage.lock_state(),
        ergo_wallet::storage::LockState::Uninitialized
    ) {
        let _ = reply.send(Err(WalletAdminError::WalletExists));
        return;
    }
    let result = storage
        .restore(&mnemonic, &mnemonic_pass, &pass, use_pre_1627)
        .map_err(|e| match e {
            ergo_wallet::error::WalletError::InvalidMnemonic(_) => {
                WalletAdminError::InvalidMnemonic
            }
            _ => WalletAdminError::Internal(e.to_string()),
        });
    let _ = reply.send(result);
}

// redb::Error is large (~160 B); the background-rescan closures
// can't avoid surfacing it as their `Err` type, so silence the
// `result_large_err` lint at the handler scope.
#[allow(clippy::result_large_err)]
pub(crate) async fn rescan(
    ctx: &WriterContext<'_>,
    from_height: u32,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    // Block replay is not yet wired; refuse before touching any
    // wallet state to prevent the destructive clear-then-skip
    // sequence that would empty the wallet.
    if !ctx.chain.read_block_at_supported() {
        // Backend cannot replay blocks (e.g. digest/pruned). Typed so the native
        // surface maps it to `rescan_unavailable(409)` (and the compat surface to
        // 409 too) rather than an opaque 500.
        let _ = reply.send(Err(WalletAdminError::RescanUnavailable(
            "chain block-read not available on this backend".to_string(),
        )));
        return;
    }
    if ctx.chain.is_pruned() {
        let _ = reply.send(Err(WalletAdminError::RestorePruningUnsupported));
        return;
    }
    let tip_h = ctx.chain.tip_height();
    let start_h = from_height.min(tip_h);
    // Snapshot the registered scans for the rebuild. Scan rebuild is a
    // full-rebuild operation only (start_h == 0); a partial wallet rescan
    // leaves the scan tables untouched. `None` when no scans are registered.
    //
    // Run this fallible preflight BEFORE arming RESCAN_IN_PROGRESS: it can
    // refuse (unreadable registry), and once that flag is set the live apply
    // hook returns empty tracked keys — a block committed in the refuse window
    // would skip wallet classification with no rescan to backfill it.
    let scan_matcher = if start_h == 0 {
        match super::scan::build_rescan_matcher(ctx.db) {
            Ok(m) => m,
            Err(e) => {
                // The scan registry is unreadable, so this rescan can't rebuild
                // scans. Refuse rather than run a rebuild that ends by clearing
                // WALLET_SCAN_INVALIDATED and falsely reporting a healthy wallet
                // while the registry is still corrupt. The flag stays set; the
                // operator must repair / re-register the scans first. (No guard
                // reset needed — RESCAN_IN_PROGRESS isn't armed yet.)
                let _ = reply.send(Err(WalletAdminError::Internal(format!(
                    "scan registry unreadable; cannot rebuild scans \
                     (repair or re-register scans, then rescan): {e}"
                ))));
                return;
            }
        }
    } else {
        None
    };
    // Refuse if a rescan is already in flight; this also arms the live-apply
    // guard (the hook returns empty tracked keys while it is set).
    if crate::wallet_boot::RESCAN_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        // A concurrent rescan is a state precondition (409), not a 500.
        let _ = reply.send(Err(WalletAdminError::RescanUnavailable(
            "rescan already in progress".to_string(),
        )));
        return;
    }
    // Record the start height so native `/wallet/status` can surface
    // `rescan: {type:"running", fromHeight}` while this rebuild is in flight.
    crate::wallet_boot::RESCAN_FROM_HEIGHT.store(start_h, Ordering::SeqCst);
    // Snapshot trees + pubkeys AFTER arming the flag so a concurrent live apply
    // (which returns empty during rescan) can't clobber the rebuild.
    let (trees, pks) = {
        let s = ctx.state.read();
        (
            s.tracked_p2pk_trees()
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            s.cached_pubkeys().clone(),
        )
    };
    // Quiesce live scan apply + reject scan mutations for the whole duration of
    // ANY full rescan (start_h == 0), not only when scans exist at start. A full
    // rescan sets WALLET_SCAN_INVALIDATED, which makes live apply_block_to_scans
    // no-op; if a scan were registered mid-rescan (when start_h == 0 but no scans
    // existed, so the matcher is None and won't rebuild them), its live matches
    // would be dropped and never backfilled. Gating on start_h == 0 makes
    // registered_scan_count return 0 (so apply_block_to_scans isn't called) and
    // makes reject_during_scan_rebuild refuse /scan/register for the rescan's
    // duration. Set BEFORE the spawn so it's active before the first clear;
    // cleared at task end.
    crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(start_h == 0, Ordering::SeqCst);
    let db_bg = ctx.db.clone();
    let chain_bg = ctx.chain.clone();
    tokio::spawn(async move {
        let read_block =
            |h: u32| -> Result<Option<ergo_state::wallet::scan::RescanBlock>, redb::Error> {
                Ok(chain_bg.read_block_at(h))
            };
        let chain_tip = chain_bg.clone();
        let read_tip = move || -> Result<u32, redb::Error> { Ok(chain_tip.tip_height()) };
        let is_cancelled =
            || -> bool { !crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst) };
        let scan_matcher_dyn = scan_matcher
            .as_ref()
            .map(|m| m as &dyn ergo_state::wallet::scan::ScanRescanMatcher);
        if let Err(e) = ergo_state::wallet::scan::WalletScanService::rescan_full_rebuild(
            &db_bg,
            trees,
            pks,
            start_h,
            tip_h,
            read_block,
            read_tip,
            is_cancelled,
            scan_matcher_dyn,
        ) {
            tracing::error!("background rescan failed: {e}");
        }
        crate::wallet_boot::RESCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
        // Resume live scan apply (no-op if it was never set).
        crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(false, Ordering::SeqCst);
    });
    let _ = reply.send(Ok(()));
}

pub(crate) async fn unlock(
    ctx: &WriterContext<'_>,
    pass: String,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    let mut storage = ctx.storage.write();
    let mut state = ctx.state.write();
    let result = crate::wallet_boot::WalletBootService::unlock_and_sync(
        &mut storage,
        &mut state,
        ctx.db,
        ctx.cfg.network,
        &pass,
    )
    .map_err(|e| match e {
        ergo_wallet::error::WalletError::WalletUninitialized => WalletAdminError::Uninitialized,
        ergo_wallet::error::WalletError::Decryption => WalletAdminError::WrongPassword,
        ergo_wallet::error::WalletError::ChangeAddressUntracked => {
            WalletAdminError::ChangeAddressUntracked
        }
        other => WalletAdminError::Internal(other.to_string()),
    });
    let _ = reply.send(result);
}

pub(crate) async fn lock(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    let mut storage = ctx.storage.write();
    let mut state = ctx.state.write();
    storage.lock();
    state.set_unlocked(false);
    let _ = reply.send(Ok(()));
}

pub(crate) async fn check(
    ctx: &WriterContext<'_>,
    mnemonic: String,
    mnemonic_pass: String,
    reply: oneshot::Sender<Result<bool, WalletAdminError>>,
) {
    let storage = ctx.storage.read();
    let matched = storage.check_seed(&mnemonic, &mnemonic_pass);
    let _ = reply.send(Ok(matched));
}

pub(crate) async fn update_change_address(
    ctx: &WriterContext<'_>,
    address: String,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    // Decode address → pubkey; reject if not a valid P2PK address for
    // this node's network (the same keys are tracked on every network,
    // so without the prefix check a testnet address would pass the
    // tracked-pubkey membership test on a mainnet node).
    let pubkey = match ergo_ser::address::decode_p2pk_address(&address, ctx.cfg.network) {
        Ok(pk) => pk,
        Err(_) => {
            let _ = reply.send(Err(WalletAdminError::ChangeAddressUntracked));
            return;
        }
    };
    // Check that the decoded pubkey is in the wallet's tracked set.
    let is_tracked = {
        let s = ctx.state.read();
        s.cached_pubkeys()
            .values()
            .any(|tracked| tracked == &pubkey)
    };
    if !is_tracked {
        let _ = reply.send(Err(WalletAdminError::ChangeAddressUntracked));
        return;
    }
    // Persist to WALLET_CHANGE_ADDRESS.
    let result: Result<(), WalletAdminError> = (|| -> Result<(), WalletAdminError> {
        let txn = ctx
            .db
            .begin_write()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        {
            let mut tbl = txn
                .open_table(ergo_state::wallet::tables::WALLET_CHANGE_ADDRESS)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            tbl.insert((), pubkey)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        Ok(())
    })();
    if result.is_ok() {
        let mut s = ctx.state.write();
        s.set_change_address(address);
    }
    let _ = reply.send(result);
}

pub(crate) async fn balances(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletBalances, WalletAdminError>>,
) {
    let result: Result<WalletBalances, WalletAdminError> =
        (|| -> Result<WalletBalances, WalletAdminError> {
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            let balance = reader
                .balance()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let assets = balance
                .tokens
                .iter()
                .map(|(id, amt)| TokenBalance {
                    token_id: hex::encode(id),
                    amount: *amt,
                })
                .collect();
            Ok(WalletBalances {
                height: ctx.chain.wallet_scan_height(),
                balance: balance.confirmed_nano_ergs,
                assets,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /wallet/balances/withUnconfirmed`: confirmed balance with a
/// single-hop mempool overlay folded in:
///
/// - ADD every pool output paying a tracked wallet tree (incoming pending).
/// - SUBTRACT every CONFIRMED wallet box spent by a pool tx (outgoing
///   pending — e.g. the inputs of a send we just submitted).
///
/// Accumulated in `i128` so a transient pool state where subtractions
/// outweigh the confirmed seed (snapshot rebuilt mid-iteration) can't
/// underflow; the net is clamped at zero before narrowing to `u64`.
///
/// SCOPE / divergence from Scala `OffChainRegistry`: this is a single-hop
/// overlay, NOT a full off-chain registry. It nets pool outputs to the
/// wallet and pool spends of *confirmed* wallet boxes, but does NOT net
/// chains within the pool — a pool output to the wallet that is itself
/// spent by a *later* pool tx still counts as incoming (and an unconfirmed
/// box spent before it ever confirmed is not subtracted, since only
/// confirmed boxes are checked against the pool). For the common case
/// (a pending receipt, or the inputs of one just-submitted send) the figure
/// is exact; under chained mempool activity it can overstate. This matches
/// the additive `/blockchain/balance` overlay's scope. Full chained netting
/// (a real OffChainRegistry tracking pool-created boxes as spendable inputs)
/// is a tracked follow-up.
pub(crate) async fn balances_with_unconfirmed(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletBalances, WalletAdminError>>,
) {
    use ergo_primitives::digest::Digest32;

    let result: Result<WalletBalances, WalletAdminError> =
        (|| -> Result<WalletBalances, WalletAdminError> {
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);

            let confirmed = reader
                .balance()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            // Outgoing pending: confirmed wallet boxes a pool tx already spends.
            let mut subtract: Vec<UnconfirmedDelta> = Vec::new();
            for wb in reader
                .unspent_boxes()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            {
                if ctx
                    .mempool
                    .is_spent_by_pool(&Digest32::from_bytes(wb.box_id))
                {
                    subtract.push(UnconfirmedDelta {
                        nano: wb.value,
                        tokens: wb.assets.clone(),
                    });
                }
            }

            // Incoming pending: pool outputs paying a tracked wallet tree.
            let mut add: Vec<UnconfirmedDelta> = Vec::new();
            {
                let state = ctx.state.read();
                for out in ctx.mempool.pool_outputs().values() {
                    if !state.is_tracked_tree(out.candidate.ergo_tree_bytes()) {
                        continue;
                    }
                    add.push(UnconfirmedDelta {
                        nano: out.candidate.value,
                        tokens: out
                            .candidate
                            .tokens
                            .iter()
                            .map(|t| (*t.token_id.as_bytes(), t.amount))
                            .collect(),
                    });
                }
            }

            let (balance, assets) = overlay_unconfirmed_balance(&confirmed, &add, &subtract);
            Ok(WalletBalances {
                height: ctx.chain.wallet_scan_height(),
                balance,
                assets,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/balance` — the native EIP-27-aware breakdown.
///
/// All figures come from ONE wallet read txn (`height` = its scan height). The
/// re-emission `reserved` holdback is the shared consensus helper
/// [`ergo_validation::reemission_obligation_core`] applied to the wallet's whole
/// confirmed box set at the CANDIDATE height `tip+1` (the height a spend is
/// validated at), so the wallet never over-reports spendable ERG relative to
/// what the validator would force a spend to burn. `reserved` is never clamped:
/// when it exceeds `confirmed`, `available` floors at 0 and
/// `reservedExceedsConfirmed` flags it.
pub(crate) async fn native_balance(
    ctx: &WriterContext<'_>,
    include_unconfirmed: bool,
    reply: oneshot::Sender<
        Result<ergo_api::wallet::native::dto::WalletBalanceDto, WalletAdminError>,
    >,
) {
    use ergo_api::wallet::native::dto::{
        NanoErgBreakdownDto, ReemissionInfoDto, ScopeDto, UnconfirmedDeltaDto, WalletAssetDto,
        WalletBalanceDto,
    };
    use ergo_primitives::digest::Digest32;

    // Uninitialized wallet → 409 (distinct from an empty-but-initialized wallet's
    // zero balance), per the design.
    if matches!(
        ctx.storage.read().lock_state(),
        ergo_wallet::storage::LockState::Uninitialized
    ) {
        let _ = reply.send(Err(WalletAdminError::Uninitialized));
        return;
    }

    let result: Result<WalletBalanceDto, WalletAdminError> =
        (|| -> Result<WalletBalanceDto, WalletAdminError> {
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);

            // asOf from the SAME txn (snapshot consistency — NOT chain.wallet_scan_height()).
            let height = reader
                .scan_height()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .unwrap_or(0);

            let bal = reader
                .balance()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let confirmed = bal.confirmed_nano_ergs;
            let immature = bal.immature_nano_ergs;

            // Confirmed (unspent) boxes — fetched once, reused for the EIP-27
            // reserve and the outgoing leg of the unconfirmed overlay.
            let need_boxes = ctx.cfg.reemission.is_some() || include_unconfirmed;
            let confirmed_boxes = if need_boxes {
                reader
                    .unspent_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                Vec::new()
            };

            // EIP-27 reserve via the shared obligation core at candidate height
            // `tip+1`. The `reemission` block is present whenever EIP-27 is active
            // on this net at the next-spend height (cfg.reemission Some AND
            // tip+1 > activation), even if this wallet holds no reward boxes.
            let reemission_token_id = ctx.cfg.reemission.as_ref().map(|r| r.reemission_token_id);
            let mut reserved: u64 = 0;
            let mut reemission: Option<ReemissionInfoDto> = None;
            if let Some(rules) = ctx.cfg.reemission.as_ref() {
                let candidate_height = ctx.chain.tip_height().saturating_add(1);
                if candidate_height > rules.activation_height {
                    let token_id = rules.reemission_token_id;
                    let obl = ergo_validation::reemission_obligation_core(
                        confirmed_boxes.iter().map(|wb| {
                            let tok = wb
                                .assets
                                .iter()
                                .filter(|(id, _)| *id == token_id)
                                .map(|(_, amt)| *amt)
                                .fold(0u64, u64::saturating_add);
                            (wb.value, tok)
                        }),
                        candidate_height,
                        rules.activation_height,
                    );
                    reserved = obl.to_burn;
                    reemission = Some(ReemissionInfoDto {
                        token_id: hex::encode(token_id),
                        reserved_token_amount: obl.to_burn.to_string(),
                        reserved_box_count: u32::try_from(obl.box_count).unwrap_or(u32::MAX),
                        reserved_exceeds_confirmed: obl.to_burn > confirmed,
                    });
                }
            }
            let available = confirmed.saturating_sub(reserved);

            // Confirmed token balances, omitting the re-emission token (accounted
            // for solely by `reserved`/`reemission`).
            let assets = bal
                .tokens
                .iter()
                .filter(|(id, _)| reemission_token_id.is_none_or(|rt| **id != rt))
                .map(|(id, amt)| WalletAssetDto {
                    token_id: hex::encode(id),
                    amount: amt.to_string(),
                })
                .collect();

            // Labeled single-hop mempool delta (only when requested); NEVER folded
            // into confirmed/available. Incoming = pool outputs to tracked trees;
            // outgoing = confirmed wallet boxes a pool tx already spends.
            let unconfirmed = if include_unconfirmed {
                let mut outgoing: u128 = 0;
                for wb in &confirmed_boxes {
                    if ctx
                        .mempool
                        .is_spent_by_pool(&Digest32::from_bytes(wb.box_id))
                    {
                        outgoing = outgoing.saturating_add(wb.value as u128);
                    }
                }
                let mut incoming: u128 = 0;
                {
                    let state = ctx.state.read();
                    for out in ctx.mempool.pool_outputs().values() {
                        if state.is_tracked_tree(out.candidate.ergo_tree_bytes()) {
                            incoming = incoming.saturating_add(out.candidate.value as u128);
                        }
                    }
                }
                let net = incoming as i128 - outgoing as i128;
                Some(UnconfirmedDeltaDto {
                    scope: ScopeDto::SingleHop,
                    incoming_nano_erg: incoming.to_string(),
                    outgoing_nano_erg: outgoing.to_string(),
                    net_nano_erg: net.to_string(),
                })
            } else {
                None
            };

            Ok(WalletBalanceDto {
                height,
                nano_erg: NanoErgBreakdownDto {
                    confirmed: confirmed.to_string(),
                    available: available.to_string(),
                    reserved: reserved.to_string(),
                    immature: immature.to_string(),
                },
                assets,
                reemission,
                unconfirmed,
            })
        })();
    let _ = reply.send(result);
}

/// One side of the unconfirmed overlay: a box's value + tokens to add or
/// subtract from the confirmed balance.
struct UnconfirmedDelta {
    nano: u64,
    tokens: Vec<([u8; 32], u64)>,
}

/// Pure overlay arithmetic for `balances_with_unconfirmed`, split out so it
/// is unit-testable without redb / mempool / wallet-state wiring.
///
/// Net = confirmed + sum(add) − sum(subtract), accumulated in `i128` so a
/// transient pool state where subtractions outweigh the confirmed seed
/// (snapshot rebuilt mid-iteration) can't underflow; each total is clamped
/// at zero before narrowing to the wire `u64`. Zero-amount tokens are
/// dropped. Returns `(nano_ergs, sorted-by-token-id assets)`.
fn overlay_unconfirmed_balance(
    confirmed: &ergo_state::wallet::types::Balance,
    add: &[UnconfirmedDelta],
    subtract: &[UnconfirmedDelta],
) -> (u64, Vec<TokenBalance>) {
    let mut nano: i128 = confirmed.confirmed_nano_ergs as i128;
    let mut tokens: std::collections::BTreeMap<[u8; 32], i128> = confirmed
        .tokens
        .iter()
        .map(|(id, amt)| (*id, *amt as i128))
        .collect();

    for d in add {
        nano += d.nano as i128;
        for (id, amt) in &d.tokens {
            *tokens.entry(*id).or_insert(0) += *amt as i128;
        }
    }
    for d in subtract {
        nano -= d.nano as i128;
        for (id, amt) in &d.tokens {
            *tokens.entry(*id).or_insert(0) -= *amt as i128;
        }
    }

    let balance = nano.max(0) as u64;
    let assets = tokens
        .into_iter()
        .filter_map(|(id, amt)| {
            let amt = amt.max(0) as u64;
            (amt > 0).then(|| TokenBalance {
                token_id: hex::encode(id),
                amount: amt,
            })
        })
        .collect();
    (balance, assets)
}

pub(crate) async fn addresses(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletAddressList, WalletAdminError>>,
) {
    let state = ctx.state.read();
    let addrs = state.visible_addresses().to_vec();
    let _ = reply.send(Ok(WalletAddressList(addrs)));
}

pub(crate) async fn boxes(
    ctx: &WriterContext<'_>,
    page: Page,
    reply: oneshot::Sender<Result<WalletBoxesPage, WalletAdminError>>,
) {
    let result: Result<WalletBoxesPage, WalletAdminError> =
        (|| -> Result<WalletBoxesPage, WalletAdminError> {
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            let all = reader
                .all_boxes()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            Ok(super::paginate_boxes(all, page))
        })();
    let _ = reply.send(result);
}

pub(crate) async fn boxes_unspent(
    ctx: &WriterContext<'_>,
    page: Page,
    reply: oneshot::Sender<Result<WalletBoxesPage, WalletAdminError>>,
) {
    let result: Result<WalletBoxesPage, WalletAdminError> =
        (|| -> Result<WalletBoxesPage, WalletAdminError> {
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            let unspent = reader
                .unspent_boxes()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            Ok(super::paginate_boxes(unspent, page))
        })();
    let _ = reply.send(result);
}

pub(crate) async fn transactions(
    ctx: &WriterContext<'_>,
    page: Page,
    reply: oneshot::Sender<Result<WalletTransactionsPage, WalletAdminError>>,
) {
    let result: Result<WalletTransactionsPage, WalletAdminError> =
        (|| -> Result<WalletTransactionsPage, WalletAdminError> {
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            let all = reader
                .all_transactions()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            Ok(super::paginate_transactions(all, page))
        })();
    let _ = reply.send(result);
}

pub(crate) async fn transaction_by_id(
    ctx: &WriterContext<'_>,
    tx_id_hex: String,
    reply: oneshot::Sender<Result<Option<WalletTransactionEntry>, WalletAdminError>>,
) {
    let result: Result<Option<WalletTransactionEntry>, WalletAdminError> =
        (|| -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
            let tx_bytes = hex::decode(&tx_id_hex)
                .map_err(|_| WalletAdminError::Internal("tx_id_hex is not valid hex".to_string()))
                .and_then(|v| {
                    v.try_into().map_err(|_| {
                        WalletAdminError::Internal("tx_id must be 32 bytes".to_string())
                    })
                })?;
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            let entry = reader
                .transaction_by_id(&tx_bytes)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(super::wallet_tx_to_entry);
            Ok(entry)
        })();
    let _ = reply.send(result);
}

pub(crate) async fn transactions_by_scan_id(
    ctx: &WriterContext<'_>,
    scan_id: u32,
    page: Page,
    reply: oneshot::Sender<Result<WalletTransactionsPage, WalletAdminError>>,
) {
    // Payments scan (10): the wallet's own transactions, served from
    // WALLET_TXS. (Approximate Scala parity: Scala filters by per-tx scan
    // tags, where pure miner-reward receipts carry MiningScanId (9), not 10 —
    // our wallet rows carry no tags, so the id-10 listing includes them.)
    // Anything else routes to the scan-tx rows written at block apply (user
    // scans; reserved 9 + unknown ids read as empty — Scala serves mining-scan
    // txs at id 9, a documented parity gap).
    let result: Result<WalletTransactionsPage, WalletAdminError> =
        if scan_id == u32::from(ergo_wallet::scan::PAYMENTS_SCAN_ID) {
            (|| -> Result<WalletTransactionsPage, WalletAdminError> {
                let read_txn = ctx
                    .db
                    .begin_read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
                let all = reader
                    .all_transactions()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                Ok(super::paginate_transactions(all, page))
            })()
        } else {
            match u16::try_from(scan_id) {
                Ok(id) => super::scan::scan_transactions_impl(ctx.db, id, page),
                // Scan ids are u16 (Scala Short); anything larger can't match.
                Err(_) => Ok(WalletTransactionsPage::default()),
            }
        };
    let _ = reply.send(result);
}

// ----- native (/api/v1/wallet) reads -----

/// `GET /api/v1/wallet/status`.
pub(crate) async fn native_status(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<
        Result<ergo_api::wallet::native::dto::WalletStatusDto, WalletAdminError>,
    >,
) {
    use ergo_api::wallet::native::dto::{NetworkDto, RescanStateDto, WalletStatusDto};
    let result: Result<WalletStatusDto, WalletAdminError> =
        (|| -> Result<WalletStatusDto, WalletAdminError> {
            let initialized = !matches!(
                ctx.storage.read().lock_state(),
                ergo_wallet::storage::LockState::Uninitialized
            );
            let locked = !ctx.state.read().is_unlocked();
            // Scan height + scan-invalidated + change address from ONE read txn.
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            let scan_height = reader
                .scan_height()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .unwrap_or(0);
            // A never-written table (`TableDoesNotExist`) is the legitimate default
            // (false / unset); any OTHER storage fault is surfaced as `internal`
            // rather than silently reported as a healthy wallet.
            let scan_invalidated = match read_txn
                .open_table(ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED)
            {
                Ok(t) => t
                    .get(())
                    .map_err(|e| WalletAdminError::Internal(format!("scan_invalidated read: {e}")))?
                    .map(|g| g.value())
                    .unwrap_or(false),
                Err(redb::TableError::TableDoesNotExist(_)) => false,
                Err(e) => {
                    return Err(WalletAdminError::Internal(format!(
                        "scan_invalidated table: {e}"
                    )))
                }
            };
            // changeAddress is persisted PUBLIC metadata — surfaced regardless of
            // lock state (it must not disappear when locked); `null` only
            // when unset. Read the stored pubkey + render to the network address.
            let change_address = match read_txn
                .open_table(ergo_state::wallet::tables::WALLET_CHANGE_ADDRESS)
            {
                Ok(t) => t
                    .get(())
                    .map_err(|e| WalletAdminError::Internal(format!("change_address read: {e}")))?
                    .map(|g| g.value())
                    .map(|pk| ergo_wallet::address::pubkey_to_p2pk_address(&pk, ctx.cfg.network))
                    .transpose()
                    .map_err(|e| {
                        WalletAdminError::Internal(format!("change address encode: {e}"))
                    })?,
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => {
                    return Err(WalletAdminError::Internal(format!(
                        "change_address table: {e}"
                    )))
                }
            };
            let tip_height = ctx.chain.tip_height();
            let eip27_active = match &ctx.cfg.reemission {
                Some(rules) => tip_height.saturating_add(1) > rules.activation_height,
                None => false,
            };
            let network = match ctx.cfg.network {
                ergo_ser::address::NetworkPrefix::Mainnet => NetworkDto::Mainnet,
                ergo_ser::address::NetworkPrefix::Testnet => NetworkDto::Testnet,
            };
            // Rescan: `running` while a rebuild is in flight (set by the rescan
            // command); `unavailable` on a non-replay (pruned) backend; else idle.
            let rescan = if crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst) {
                RescanStateDto::Running {
                    from_height: crate::wallet_boot::RESCAN_FROM_HEIGHT.load(Ordering::SeqCst),
                }
            } else if ctx.chain.is_pruned() {
                RescanStateDto::Unavailable {
                    detail: "node is pruned; block replay unavailable".to_string(),
                }
            } else {
                RescanStateDto::Idle
            };
            Ok(WalletStatusDto {
                initialized,
                locked,
                scan_height,
                tip_height,
                change_address,
                network,
                eip27_active,
                rescan,
                scan_invalidated,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/addresses` (paged). Renders each tracked pubkey to its
/// P2PK address; `total` + the page slice come from one read snapshot.
pub(crate) async fn native_addresses(
    ctx: &WriterContext<'_>,
    offset: u32,
    limit: u32,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::AddressPage, WalletAdminError>>,
) {
    use ergo_api::wallet::native::dto::{AddressPage, WalletAddressDto};
    let network = ctx.cfg.network;
    let result: Result<AddressPage, WalletAdminError> =
        (|| -> Result<AddressPage, WalletAdminError> {
            let read_txn = ctx
                .db
                .begin_read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            let as_of = reader
                .scan_height()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .unwrap_or(0);
            // Ordered by path_idx ASC (the reader's contract).
            let metas = reader
                .tracked_addresses_with_meta()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let total = u32::try_from(metas.len()).unwrap_or(u32::MAX);
            let items = metas
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|m| {
                    let address = ergo_wallet::address::pubkey_to_p2pk_address(&m.pubkey, network)
                        .map_err(|e| WalletAdminError::Internal(format!("address encode: {e}")))?;
                    Ok(WalletAddressDto {
                        address,
                        derivation_path: super::super::render_derivation_path(&m.derivation_path),
                        // `index` is `u64` (matches `path_idx`) — no narrowing, so
                        // distinct addresses never alias past `u32::MAX`.
                        index: m.path_idx,
                        label: (!m.label.is_empty()).then_some(m.label),
                        added_at_height: m.added_at_height,
                    })
                })
                .collect::<Result<Vec<_>, WalletAdminError>>()?;
            Ok(AddressPage {
                items,
                total,
                as_of,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/boxes` (paged). All wallet boxes (any status), ordered
/// `(creationHeight desc, boxId asc)` — sorted before paging.
pub(crate) async fn native_boxes(
    ctx: &WriterContext<'_>,
    offset: u32,
    limit: u32,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::BoxPage, WalletAdminError>>,
) {
    use ergo_api::wallet::native::dto::BoxPage;
    let result: Result<BoxPage, WalletAdminError> = (|| -> Result<BoxPage, WalletAdminError> {
        let read_txn = ctx
            .db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let as_of = reader
            .scan_height()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .unwrap_or(0);
        let mut boxes = reader
            .all_boxes()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        boxes.sort_by(|a, b| {
            b.creation_height
                .cmp(&a.creation_height)
                .then_with(|| a.box_id.cmp(&b.box_id))
        });
        let total = u32::try_from(boxes.len()).unwrap_or(u32::MAX);
        let items = boxes
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(box_to_summary)
            .collect::<Result<Vec<_>, WalletAdminError>>()?;
        Ok(BoxPage {
            items,
            total,
            as_of,
        })
    })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/boxes/{boxId}` — O(1) lookup; `None` if not tracked.
pub(crate) async fn native_box_by_id(
    ctx: &WriterContext<'_>,
    box_id_hex: String,
    reply: oneshot::Sender<
        Result<Option<ergo_api::wallet::native::dto::WalletBoxSummary>, WalletAdminError>,
    >,
) {
    let result = (|| {
        let box_id = decode_hex32(&box_id_hex)?;
        let read_txn = ctx
            .db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let wb = reader
            .box_by_id(&box_id)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        wb.map(box_to_summary).transpose()
    })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/transactions` (paged). Ordered `(blockHeight desc, txId
/// asc)` — sorted before paging.
pub(crate) async fn native_transactions(
    ctx: &WriterContext<'_>,
    offset: u32,
    limit: u32,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::TxPage, WalletAdminError>>,
) {
    use ergo_api::wallet::native::dto::TxPage;
    let result: Result<TxPage, WalletAdminError> = (|| -> Result<TxPage, WalletAdminError> {
        let read_txn = ctx
            .db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let as_of = reader
            .scan_height()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .unwrap_or(0);
        let mut txs = reader
            .all_transactions()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        txs.sort_by(|a, b| {
            b.block_height
                .cmp(&a.block_height)
                .then_with(|| a.tx_id.cmp(&b.tx_id))
        });
        let total = u32::try_from(txs.len()).unwrap_or(u32::MAX);
        let items = txs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(tx_to_summary)
            .collect();
        Ok(TxPage {
            items,
            total,
            as_of,
        })
    })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/transactions/{txId}` — `None` if not found.
pub(crate) async fn native_transaction_by_id(
    ctx: &WriterContext<'_>,
    tx_id_hex: String,
    reply: oneshot::Sender<
        Result<Option<ergo_api::wallet::native::dto::WalletTransactionSummary>, WalletAdminError>,
    >,
) {
    let result = (|| {
        let tx_id = decode_hex32(&tx_id_hex)?;
        let read_txn = ctx
            .db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let wt = reader
            .transaction_by_id(&tx_id)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        Ok(wt.map(tx_to_summary))
    })();
    let _ = reply.send(result);
}

// ----- native read helpers -----

/// Decode a 64-char hex id into a 32-byte array (the handler pre-validates the
/// shape; this is the defensive decode at the bridge boundary).
fn decode_hex32(s: &str) -> Result<[u8; 32], WalletAdminError> {
    let v =
        hex::decode(s).map_err(|_| WalletAdminError::BadRequest("invalid hex id".to_string()))?;
    v.try_into()
        .map_err(|_| WalletAdminError::BadRequest("id must be 32 bytes".to_string()))
}

/// Map a stored [`ergo_state::wallet::types::WalletBox`] to the lean native
/// summary. Fallible only on the (invariant-impossible) scan-id overflow — a
/// scan id that does not fit `u16` is corrupt storage, surfaced as `internal`
/// rather than silently truncated to `65535`.
fn box_to_summary(
    wb: ergo_state::wallet::types::WalletBox,
) -> Result<ergo_api::wallet::native::dto::WalletBoxSummary, WalletAdminError> {
    use ergo_api::wallet::native::dto::{
        BoxProvenanceDto, BoxStatusDto, WalletAssetDto, WalletBoxSummary,
    };
    use ergo_state::wallet::types::{BoxProvenance, BoxStatus};
    let status = match wb.status {
        BoxStatus::Confirmed => BoxStatusDto::Confirmed,
        BoxStatus::Immature { matures_at } => BoxStatusDto::Immature {
            matures_at_height: matures_at,
        },
        BoxStatus::Spent {
            spent_in_tx,
            spent_at,
        } => BoxStatusDto::Spent {
            tx_id: hex::encode(spent_in_tx),
            height: spent_at,
        },
    };
    let provenance = match wb.provenance {
        BoxProvenance::Owned => BoxProvenanceDto::Owned,
        BoxProvenance::MinerReward => BoxProvenanceDto::MinerReward,
        // Storage carries a u32 scan id; native ids are u16. The registry only
        // ever allocates u16 ids, so this always fits — but fail loudly rather
        // than truncate if that invariant is ever violated.
        BoxProvenance::Custom { scan_id } => BoxProvenanceDto::Custom {
            scan_id: u16::try_from(scan_id).map_err(|_| {
                WalletAdminError::Internal(format!("custom scan id {scan_id} exceeds u16"))
            })?,
        },
    };
    Ok(WalletBoxSummary {
        box_id: hex::encode(wb.box_id),
        value: wb.value.to_string(),
        assets: wb
            .assets
            .iter()
            .map(|(id, amt)| WalletAssetDto {
                token_id: hex::encode(id),
                amount: amt.to_string(),
            })
            .collect(),
        creation_tx_id: hex::encode(wb.creation_tx_id),
        creation_output_index: wb.creation_output_index,
        creation_height: wb.creation_height,
        status,
        provenance,
    })
}

/// Map a stored [`ergo_state::wallet::types::WalletTransaction`] to the lean summary.
pub(crate) fn tx_to_summary(
    wt: ergo_state::wallet::types::WalletTransaction,
) -> ergo_api::wallet::native::dto::WalletTransactionSummary {
    use ergo_api::wallet::native::dto::WalletTransactionSummary;
    WalletTransactionSummary {
        tx_id: hex::encode(wt.tx_id),
        block_id: hex::encode(wt.block_id),
        block_height: wt.block_height,
        wallet_input_box_ids: wt.wallet_inputs.iter().map(hex::encode).collect(),
        wallet_output_box_ids: wt.wallet_outputs.iter().map(hex::encode).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::{overlay_unconfirmed_balance, UnconfirmedDelta};
    use ergo_state::wallet::types::Balance;

    // ----- helpers -----

    const TOK_A: [u8; 32] = [0xAA; 32];
    const TOK_B: [u8; 32] = [0xBB; 32];

    fn confirmed(nano: u64, tokens: &[([u8; 32], u64)]) -> Balance {
        Balance {
            confirmed_nano_ergs: nano,
            immature_nano_ergs: 0,
            tokens: tokens.iter().copied().collect(),
        }
    }

    fn delta(nano: u64, tokens: &[([u8; 32], u64)]) -> UnconfirmedDelta {
        UnconfirmedDelta {
            nano,
            tokens: tokens.to_vec(),
        }
    }

    // ----- happy path -----

    #[test]
    fn overlay_no_mempool_returns_confirmed_unchanged() {
        let (nano, assets) =
            overlay_unconfirmed_balance(&confirmed(5_000_000, &[(TOK_A, 7)]), &[], &[]);
        assert_eq!(nano, 5_000_000);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].amount, 7);
        assert_eq!(assets[0].token_id, hex::encode(TOK_A));
    }

    #[test]
    fn overlay_incoming_pool_output_adds_to_balance() {
        // A pending receipt of 2 ERG + 3 of TOK_A on top of a 5 ERG / 7 TOK_A
        // confirmed balance.
        let (nano, assets) = overlay_unconfirmed_balance(
            &confirmed(5_000_000, &[(TOK_A, 7)]),
            &[delta(2_000_000, &[(TOK_A, 3)])],
            &[],
        );
        assert_eq!(nano, 7_000_000);
        assert_eq!(assets[0].amount, 10);
    }

    #[test]
    fn overlay_outgoing_pool_spend_subtracts_spent_box() {
        // We just submitted a send spending our only 5 ERG / 7 TOK_A box;
        // the pending change/receipt of 4 ERG + 7 TOK_A comes back to us.
        let (nano, assets) = overlay_unconfirmed_balance(
            &confirmed(5_000_000, &[(TOK_A, 7)]),
            &[delta(4_000_000, &[(TOK_A, 7)])],
            &[delta(5_000_000, &[(TOK_A, 7)])],
        );
        assert_eq!(nano, 4_000_000, "5 - 5 + 4");
        assert_eq!(assets.len(), 1, "tokens fully returned as change");
        assert_eq!(assets[0].amount, 7);
    }

    // ----- error paths -----

    #[test]
    fn overlay_subtraction_below_zero_clamps_to_zero() {
        // Transient snapshot where a spend is visible but its change output
        // is not yet — net must clamp, never underflow/wrap.
        let (nano, assets) = overlay_unconfirmed_balance(
            &confirmed(1_000_000, &[(TOK_A, 1)]),
            &[],
            &[delta(5_000_000, &[(TOK_A, 9)])],
        );
        assert_eq!(nano, 0);
        assert!(
            assets.is_empty(),
            "negative token total dropped, not wrapped"
        );
    }

    #[test]
    fn overlay_zero_net_token_is_dropped_from_assets() {
        // TOK_A nets to zero (spent == confirmed); TOK_B remains.
        let (_, assets) = overlay_unconfirmed_balance(
            &confirmed(10_000_000, &[(TOK_A, 4), (TOK_B, 2)]),
            &[],
            &[delta(0, &[(TOK_A, 4)])],
        );
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].token_id, hex::encode(TOK_B));
        assert_eq!(assets[0].amount, 2);
    }
}
