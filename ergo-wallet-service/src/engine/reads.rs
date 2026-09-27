//! Read-side wallet queries: the compat balances / addresses / boxes /
//! transactions reads and the native `/api/v1/wallet` reads.

use ergo_wallet_protocol::scala::types::{
    Page, TokenBalance, WalletAddressList, WalletBalances, WalletBoxesPage, WalletTransactionEntry,
    WalletTransactionsPage,
};
use ergo_wallet_protocol::WalletAdminError;

use super::dto::tx_to_summary;
use super::WalletEngine;

impl WalletEngine {
    pub fn balances(&self) -> Result<WalletBalances, WalletAdminError> {
        (|| -> Result<WalletBalances, WalletAdminError> {
            let balance = if let Some(service) = self.service.as_deref() {
                service
                    .confirmed_balance()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = self
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.balance()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            let assets = balance
                .tokens
                .iter()
                .map(|(id, amt)| TokenBalance {
                    token_id: hex::encode(id),
                    amount: *amt,
                })
                .collect();
            Ok(WalletBalances {
                height: self
                    .chain
                    .wallet_scan_height()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
                balance: balance.confirmed_nano_ergs,
                assets,
            })
        })()
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
    pub fn balances_with_unconfirmed(&self) -> Result<WalletBalances, WalletAdminError> {
        use ergo_primitives::digest::Digest32;

        (|| -> Result<WalletBalances, WalletAdminError> {
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            let confirmed = read
                .balance()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            // Outgoing pending: confirmed wallet boxes a pool tx already spends.
            let mut subtract: Vec<UnconfirmedDelta> = Vec::new();
            for wb in read
                .unspent_boxes()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            {
                if self
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
                let state = self.state.read();
                for out in self.mempool.pool_outputs().values() {
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
                height: self
                    .chain
                    .wallet_scan_height()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
                balance,
                assets,
            })
        })()
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
    pub fn native_balance(
        &self,
        include_unconfirmed: bool,
    ) -> Result<ergo_wallet_protocol::native::dto::WalletBalanceDto, WalletAdminError> {
        use ergo_primitives::digest::Digest32;
        use ergo_wallet_protocol::native::dto::{
            NanoErgBreakdownDto, ReemissionInfoDto, ScopeDto, UnconfirmedDeltaDto, WalletAssetDto,
            WalletBalanceDto,
        };

        // Uninitialized wallet → 409 (distinct from an empty-but-initialized wallet's
        // zero balance), per the design.
        if matches!(
            self.storage.read().lock_state(),
            ergo_wallet::storage::LockState::Uninitialized
        ) {
            return Err(WalletAdminError::Uninitialized);
        }

        (|| -> Result<WalletBalanceDto, WalletAdminError> {
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            let height = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);

            let bal = read
                .balance()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let confirmed = bal.confirmed_nano_ergs;
            let immature = bal.immature_nano_ergs;

            // Confirmed (unspent) boxes — fetched once, reused for the EIP-27
            // reserve and the outgoing leg of the unconfirmed overlay.
            let need_boxes = self.config.reemission.is_some() || include_unconfirmed;
            let confirmed_boxes = if need_boxes {
                read.unspent_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                Vec::new()
            };

            // EIP-27 reserve via the shared obligation core at candidate height
            // `tip+1`. The `reemission` block is present whenever EIP-27 is active
            // on this net at the next-spend height (cfg.reemission Some AND
            // tip+1 > activation), even if this wallet holds no reward boxes.
            let reemission_token_id = self
                .config
                .reemission
                .as_ref()
                .map(|r| r.reemission_token_id);
            let mut reserved: u64 = 0;
            let mut reemission: Option<ReemissionInfoDto> = None;
            if let Some(rules) = self.config.reemission.as_ref() {
                let candidate_height = self
                    .chain
                    .tip_height()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                    .saturating_add(1);
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
                    if self
                        .mempool
                        .is_spent_by_pool(&Digest32::from_bytes(wb.box_id))
                    {
                        outgoing = outgoing.saturating_add(wb.value as u128);
                    }
                }
                let mut incoming: u128 = 0;
                {
                    let state = self.state.read();
                    for out in self.mempool.pool_outputs().values() {
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
        })()
    }

    pub fn addresses(&self) -> Result<WalletAddressList, WalletAdminError> {
        let state = self.state.read();
        let addrs = state.visible_addresses().to_vec();
        Ok(WalletAddressList(addrs))
    }

    pub fn boxes(&self, page: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        (|| -> Result<WalletBoxesPage, WalletAdminError> {
            let all = if let Some(service) = self.service.as_deref() {
                service
                    .boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = self
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.all_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            Ok(super::dto::paginate_boxes(all, page))
        })()
    }

    pub fn boxes_unspent(&self, page: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        (|| -> Result<WalletBoxesPage, WalletAdminError> {
            let unspent = if let Some(service) = self.service.as_deref() {
                service
                    .confirmed_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = self
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.unspent_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            Ok(super::dto::paginate_boxes(unspent, page))
        })()
    }

    pub fn transactions(&self, page: Page) -> Result<WalletTransactionsPage, WalletAdminError> {
        (|| -> Result<WalletTransactionsPage, WalletAdminError> {
            let all = if let Some(service) = self.service.as_deref() {
                service
                    .transactions()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = self
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.all_transactions()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            Ok(super::dto::paginate_transactions(all, page))
        })()
    }

    pub fn transaction_by_id(
        &self,
        tx_id_hex: String,
    ) -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
        (|| -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
            let tx_bytes = hex::decode(&tx_id_hex)
                .map_err(|_| WalletAdminError::Internal("tx_id_hex is not valid hex".to_string()))
                .and_then(|v| {
                    v.try_into().map_err(|_| {
                        WalletAdminError::Internal("tx_id must be 32 bytes".to_string())
                    })
                })?;
            let entry = if let Some(service) = self.service.as_deref() {
                service
                    .transaction_by_id(&tx_bytes)
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                    .map(super::dto::wallet_tx_to_entry)
            } else {
                let read = self
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.transaction_by_id(&tx_bytes)
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                    .map(super::dto::wallet_tx_to_entry)
            };
            Ok(entry)
        })()
    }

    pub fn transactions_by_scan_id(
        &self,
        scan_id: u32,
        page: Page,
    ) -> Result<WalletTransactionsPage, WalletAdminError> {
        // Payments scan (10): the wallet's own transactions, served from
        // WALLET_TXS. (Approximate Scala parity: Scala filters by per-tx scan
        // tags, where pure miner-reward receipts carry MiningScanId (9), not 10 —
        // our wallet rows carry no tags, so the id-10 listing includes them.)
        // Anything else routes to the scan-tx rows written at block apply (user
        // scans; reserved 9 + unknown ids read as empty — Scala serves mining-scan
        // txs at id 9, a documented parity gap).
        if scan_id == u32::from(crate::scan::PAYMENTS_SCAN_ID) {
            (|| -> Result<WalletTransactionsPage, WalletAdminError> {
                let read = self
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                let all = read
                    .all_transactions()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                Ok(super::dto::paginate_transactions(all, page))
            })()
        } else {
            match u16::try_from(scan_id) {
                Ok(id) => super::scan::scan_transactions_impl(self.store.as_ref(), id, page),
                // Scan ids are u16 (Scala Short); anything larger can't match.
                Err(_) => Ok(WalletTransactionsPage::default()),
            }
        }
    }

    /// `GET /api/v1/wallet/status`.
    pub fn native_status(
        &self,
    ) -> Result<ergo_wallet_protocol::native::dto::WalletStatusDto, WalletAdminError> {
        use ergo_wallet_protocol::native::dto::{NetworkDto, RescanStateDto, WalletStatusDto};
        (|| -> Result<WalletStatusDto, WalletAdminError> {
            let initialized = !matches!(
                self.storage.read().lock_state(),
                ergo_wallet::storage::LockState::Uninitialized
            );
            let locked = !self.state.read().is_unlocked();
            // Scan height + scan-invalidated + change address from ONE read txn.
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let scan_height = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);
            let scan_invalidated = read
                .scan_invalidated()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let change_address = read
                .change_address_pubkey()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|pk| ergo_wallet::address::pubkey_to_p2pk_address(&pk, self.config.network))
                .transpose()
                .map_err(|e| WalletAdminError::Internal(format!("change address encode: {e}")))?;
            let tip_height = self
                .chain
                .tip_height()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let eip27_active = match &self.config.reemission {
                Some(rules) => tip_height.saturating_add(1) > rules.activation_height,
                None => false,
            };
            let network = match self.config.network {
                ergo_ser::address::NetworkPrefix::Mainnet => NetworkDto::Mainnet,
                ergo_ser::address::NetworkPrefix::Testnet => NetworkDto::Testnet,
            };
            let rescan_state = read
                .rescan_state()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let rescan = match rescan_state {
                crate::wallet::RescanState::Running { from_height } => {
                    RescanStateDto::Running { from_height }
                }
                crate::wallet::RescanState::Failed { height, reason } => {
                    RescanStateDto::Failed { height, reason }
                }
                crate::wallet::RescanState::Idle if self.chain.is_pruned() => {
                    RescanStateDto::Unavailable {
                        detail: "node is pruned; block replay unavailable".to_string(),
                    }
                }
                crate::wallet::RescanState::Idle => RescanStateDto::Idle,
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
        })()
    }

    /// `GET /api/v1/wallet/addresses` (paged). Renders each tracked pubkey to its
    /// P2PK address; `total` + the page slice come from one read snapshot.
    pub fn native_addresses(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_wallet_protocol::native::dto::AddressPage, WalletAdminError> {
        use ergo_wallet_protocol::native::dto::{AddressPage, WalletAddressDto};
        let network = self.config.network;
        (|| -> Result<AddressPage, WalletAdminError> {
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let as_of = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);
            // Ordered by path_idx ASC (the reader's contract).
            let metas = read
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
                        derivation_path: super::keys::render_derivation_path(&m.derivation_path),
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
        })()
    }

    /// `GET /api/v1/wallet/boxes` (paged). All wallet boxes (any status), ordered
    /// `(creationHeight desc, boxId asc)` — sorted before paging.
    pub fn native_boxes(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_wallet_protocol::native::dto::BoxPage, WalletAdminError> {
        use ergo_wallet_protocol::native::dto::BoxPage;
        (|| -> Result<BoxPage, WalletAdminError> {
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let as_of = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);
            let mut boxes = read
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
        })()
    }

    /// `GET /api/v1/wallet/boxes/{boxId}` — O(1) lookup; `None` if not tracked.
    pub fn native_box_by_id(
        &self,
        box_id_hex: String,
    ) -> Result<Option<ergo_wallet_protocol::native::dto::WalletBoxSummary>, WalletAdminError> {
        (|| {
            let box_id = decode_hex32(&box_id_hex)?;
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let wb = read
                .box_by_id(&box_id)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            wb.map(box_to_summary).transpose()
        })()
    }

    /// `GET /api/v1/wallet/transactions` (paged). Ordered `(blockHeight desc, txId
    /// asc)` — sorted before paging.
    pub fn native_transactions(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<ergo_wallet_protocol::native::dto::TxPage, WalletAdminError> {
        use ergo_wallet_protocol::native::dto::TxPage;
        (|| -> Result<TxPage, WalletAdminError> {
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let as_of = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);
            let mut txs = read
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
        })()
    }

    /// `GET /api/v1/wallet/transactions/{txId}` — `None` if not found.
    pub fn native_transaction_by_id(
        &self,
        tx_id_hex: String,
    ) -> Result<Option<ergo_wallet_protocol::native::dto::WalletTransactionSummary>, WalletAdminError>
    {
        (|| {
            let tx_id = decode_hex32(&tx_id_hex)?;
            let read = self
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let wt = read
                .transaction_by_id(&tx_id)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            Ok(wt.map(tx_to_summary))
        })()
    }
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
    confirmed: &crate::wallet::types::Balance,
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

// ----- native read helpers -----

/// Decode a 64-char hex id into a 32-byte array (the handler pre-validates the
/// shape; this is the defensive decode at the bridge boundary).
fn decode_hex32(s: &str) -> Result<[u8; 32], WalletAdminError> {
    let v =
        hex::decode(s).map_err(|_| WalletAdminError::BadRequest("invalid hex id".to_string()))?;
    v.try_into()
        .map_err(|_| WalletAdminError::BadRequest("id must be 32 bytes".to_string()))
}

/// Map a stored [`crate::wallet::types::WalletBox`] to the lean native
/// summary. Fallible only on the (invariant-impossible) scan-id overflow — a
/// scan id that does not fit `u16` is corrupt storage, surfaced as `internal`
/// rather than silently truncated to `65535`.
fn box_to_summary(
    wb: crate::wallet::types::WalletBox,
) -> Result<ergo_wallet_protocol::native::dto::WalletBoxSummary, WalletAdminError> {
    use crate::wallet::types::{BoxProvenance, BoxStatus};
    use ergo_wallet_protocol::native::dto::{
        BoxProvenanceDto, BoxStatusDto, WalletAssetDto, WalletBoxSummary,
    };
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

#[cfg(test)]
mod tests {
    use super::{overlay_unconfirmed_balance, UnconfirmedDelta};
    use crate::wallet::types::Balance;

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
