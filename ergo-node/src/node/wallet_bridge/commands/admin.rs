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
        let _ = reply.send(Err(WalletAdminError::Internal(
            "rescan unavailable: chain block-read not yet implemented".to_string(),
        )));
        return;
    }
    if ctx.chain.is_pruned() {
        let _ = reply.send(Err(WalletAdminError::RestorePruningUnsupported));
        return;
    }
    // Refuse if a rescan is already in flight.
    if crate::wallet_boot::RESCAN_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        let _ = reply.send(Err(WalletAdminError::Internal(
            "rescan already in progress".to_string(),
        )));
        return;
    }
    // Snapshot trees + pubkeys BEFORE setting the flag so the
    // live apply hook (which returns empty during rescan) doesn't
    // clobber the rebuild.
    let tip_h = ctx.chain.tip_height();
    let start_h = from_height.min(tip_h);
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
    // Snapshot the registered scans for the rebuild. Scan rebuild is a
    // full-rebuild operation only (start_h == 0); a partial wallet rescan
    // leaves the scan tables untouched. `None` when no scans are registered.
    let scan_matcher = if start_h == 0 {
        super::scan::build_rescan_matcher(ctx.db)
    } else {
        None
    };
    // Quiesce live scan apply for the rebuild's duration (only when a full
    // rebuild will actually touch the scan tables). Set BEFORE the spawn so
    // it is active before the rebuild's first clear; cleared at task end.
    crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.store(scan_matcher.is_some(), Ordering::SeqCst);
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
