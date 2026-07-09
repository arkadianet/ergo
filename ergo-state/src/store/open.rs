//! Store lifecycle: DB open / init paths, the launch-params +
//! voting-params plumbing, and the Mode-2 install trust-flag
//! lifecycle (armed at snapshot install, consumed by the first
//! post-install epoch boundary validator).
//!
//! Sibling of `mod.rs`; pure `impl StateStore { ... }` relocation.
//! `Self::derive_next_id_from_scan` is reached as an associated
//! function on the same struct from `mod.rs`.

use super::*;

impl StateStore {
    /// Open or create a state store at the given path. Seeds the
    /// height-0 launch row with `scala_launch()` (mainnet defaults);
    /// callers running on a non-mainnet network must use
    /// [`Self::open_with_launch_params`] so the genesis row reflects
    /// their network's `LaunchParameters`.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        Self::open_with_cache(path, Self::DEFAULT_CACHE_BYTES)
    }

    /// Open with a custom cache byte budget (for testing with small caches).
    /// Uses mainnet launch defaults (see [`Self::open`]).
    pub fn open_with_cache(path: &Path, cache_bytes: usize) -> Result<Self, StateError> {
        Self::open_with_cache_and_launch(path, cache_bytes, ergo_validation::scala_launch())
    }

    /// Open with explicit launch parameters. Production callers feed
    /// `scala_launch_for_network(chain_spec.network)` so the height-0
    /// voted-params row matches Scala `LaunchParameters` for that
    /// network. In Scala, `MainnetLaunchParameters` and
    /// `TestnetLaunchParameters` carry identical data (`DefaultParameters`
    /// plus empty `proposedUpdate`); the dispatch is preserved here so
    /// the seam is in place if a future network introduces a real launch
    /// override. Only `DevnetLaunchParameters` and
    /// `Devnet60LaunchParameters` do today, by setting `BlockVersion`.
    pub fn open_with_launch_params(
        path: &Path,
        launch_params: ergo_validation::ActiveProtocolParameters,
    ) -> Result<Self, StateError> {
        Self::open_with_cache_and_launch(path, Self::DEFAULT_CACHE_BYTES, launch_params)
    }

    /// Open with custom cache + explicit launch parameters. Legacy
    /// helper retained for callers that haven't been migrated to the
    /// network-aware shape; defaults `voting_settings` to mainnet.
    /// Tests that pass `scala_launch_for_network(Network::Testnet)`
    /// here will silently use mainnet voting cadence — use
    /// [`open_with_cache_launch_voting`] instead.
    pub fn open_with_cache_and_launch(
        path: &Path,
        cache_bytes: usize,
        launch_params: ergo_validation::ActiveProtocolParameters,
    ) -> Result<Self, StateError> {
        Self::open_with_cache_launch_voting(
            path,
            cache_bytes,
            launch_params,
            ergo_chain_spec::VotingParams::mainnet(),
        )
    }

    /// Open with custom cache + explicit launch params + explicit
    /// voting params. Production entrypoint — callers pass
    /// `chain_spec.voting` so the validator's epoch-boundary logic
    /// fires at the right cadence per network.
    pub fn open_with_cache_launch_voting(
        path: &Path,
        cache_bytes: usize,
        launch_params: ergo_validation::ActiveProtocolParameters,
        voting_settings: ergo_chain_spec::VotingParams,
    ) -> Result<Self, StateError> {
        let t0 = std::time::Instant::now();
        let db = Arc::new(
            Database::builder()
                .set_repair_callback(|session| {
                    info!(
                        progress_pct = session.progress() * 100.0,
                        "redb repair progress",
                    );
                })
                .create(path)?,
        );
        info!(
            elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
            "database create",
        );

        // Try to recover from committed state
        let (tree, height) = {
            // Phase 1: read meta + check for allocator under read txn
            let t1 = std::time::Instant::now();
            let (meta_opt, has_allocator, alloc_next_id) = {
                let read_txn = db.begin_read()?;
                match read_txn.open_table(STATE_META) {
                    Ok(table) => {
                        let meta = table
                            .get("root")?
                            .map(|guard| StateMeta::deserialize(guard.value()))
                            .transpose()?;
                        let (has_alloc, alloc_nid) = match table.get("allocator")? {
                            Some(ag) => (true, AllocMeta::deserialize(ag.value())?.next_id),
                            None => (false, 0),
                        };
                        (meta, has_alloc, alloc_nid)
                    }
                    Err(redb::TableError::TableDoesNotExist(_)) => (None, false, 0),
                    Err(e) => return Err(e.into()),
                }
            };

            debug!(
                elapsed_ms = t1.elapsed().as_secs_f64() * 1000.0,
                has_state = meta_opt.is_some(),
                has_alloc = has_allocator,
                "read meta",
            );

            // Phase 2: if we have state but no allocator, do one-time scan + persist
            let next_id = if meta_opt.is_some() && !has_allocator {
                info!("one-time migration: scanning AVL nodes for max ID");
                let read_txn = db.begin_read()?;
                let nid = Self::derive_next_id_from_scan(&read_txn)?;
                drop(read_txn);
                info!(next_id = nid, "migration complete, persisting");
                let write_txn = crate::begin_write_qr(&db)?;
                {
                    let mut meta_table = write_txn.open_table(STATE_META)?;
                    let alloc = AllocMeta { next_id: nid };
                    meta_table.insert("allocator", alloc.serialize().as_slice())?;
                    meta_table.insert(NODE_FORMAT_VERSION_KEY, NODE_FORMAT_V2)?;
                }
                write_txn.commit()?;
                nid
            } else {
                alloc_next_id
            };

            debug!(next_id, "alloc resolved");

            // Phase 3: build the tree
            match meta_opt {
                Some(meta) => {
                    let arena = Box::new(crate::avl::arena::CachedDiskArena::new(
                        Arc::clone(&db),
                        cache_bytes,
                    ));
                    let root_label_bytes: [u8; 32] = meta.root_digest[..32]
                        .try_into()
                        .expect("state_meta.root_digest[..32] must be 32 bytes");
                    let root_label = Digest32::from_bytes(root_label_bytes);
                    let tree = AvlTree::new_with_arena(
                        arena,
                        meta.root_node_id,
                        meta.tree_height,
                        next_id,
                        root_label,
                    );
                    (tree, meta.height)
                }
                None => {
                    let arena = Box::new(crate::avl::arena::CachedDiskArena::new(
                        Arc::clone(&db),
                        cache_bytes,
                    ));
                    (AvlTree::new_disk_backed(arena), 0)
                }
            }
        };
        info!(
            elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
            "total open",
        );

        // Genesis is committed if we recovered from existing state, or
        // if height > 0 (blocks were applied, which requires genesis).
        let genesis_committed = height > 0 || {
            let read_txn = db.begin_read().ok();
            read_txn
                .and_then(|rt| rt.open_table(STATE_META).ok())
                .and_then(|t| t.get("root").ok().flatten())
                .is_some()
        };

        // Recover chain state from chain_state_meta. If absent (pre-Phase-7
        // database or first open), derive from committed UTXO state so that
        // best_full_block pointers match the actual committed height.
        let chain_state = {
            let read_txn = db.begin_read()?;
            let from_table = match read_txn.open_table(CHAIN_STATE_META) {
                Ok(table) => match table.get("chain_state")? {
                    Some(g) => {
                        let meta = ChainStateMeta::deserialize(g.value()).map_err(|e| {
                            StateError::DbCorruption {
                                table: "chain_state_meta",
                                key: hex::encode(b"chain_state"),
                                reason: format!("decode: {e}"),
                            }
                        })?;
                        Some(ChainState::from_persisted(&meta))
                    }
                    None => None,
                },
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(e.into()),
            };
            match from_table {
                Some(cs) => cs,
                None if height > 0 => {
                    // Derive from committed state: best_full_block = current tip.
                    // best_header defaults to same (header-first sync hasn't started).
                    let chain_table = read_txn.open_table(CHAIN_INDEX)?;
                    let tip_id = {
                        let guard = chain_table
                            .get(height as u64)?
                            .ok_or(StateError::NoCommittedState)?;
                        let mut id = [0u8; 32];
                        id.copy_from_slice(guard.value());
                        id
                    };
                    ChainState {
                        best_header_id: tip_id,
                        best_header_height: height,
                        best_header_score: vec![0], // unknown until header sync
                        best_full_block_id: tip_id,
                        best_full_block_height: height,
                        header_availability: crate::chain::HeaderAvailability::Dense,
                        session_invalids: std::collections::HashSet::new(),
                    }
                }
                None => ChainState::empty(),
            }
        };

        let mode2_trust_first_epoch = {
            let read_txn = db.begin_read()?;
            let persisted = match read_txn.open_table(CHAIN_STATE_META) {
                Ok(table) => table
                    .get(MODE2_TRUST_FIRST_EPOCH_KEY)?
                    .map(|g| g.value().first().copied() == Some(0x01))
                    .unwrap_or(false),
                Err(redb::TableError::TableDoesNotExist(_)) => false,
                Err(e) => return Err(e.into()),
            };
            // Self-heal: if a snapshot was installed (best_full_block
            // is set) but CHAIN_INDEX has no entry at
            // best_full_block_height, arm the trust flag even if the
            // persisted byte is missing. Current installs co-commit a
            // CHAIN_INDEX anchor at the snapshot height (see
            // `install_snapshot_state`), so a missing entry marks a
            // data dir installed by an older binary that wrote neither
            // the anchor nor `MODE2_TRUST_FIRST_EPOCH_KEY`.
            // Cheap and idempotent: a normally-synced node has a
            // chain_index entry at best_full_block_height so this
            // branch never fires for them.
            let needs_self_heal = !persisted
                && chain_state.best_full_block_height > 0
                && match read_txn.open_table(CHAIN_INDEX) {
                    Ok(t) => t.get(chain_state.best_full_block_height as u64)?.is_none(),
                    Err(redb::TableError::TableDoesNotExist(_)) => true,
                    Err(e) => return Err(e.into()),
                };
            if needs_self_heal {
                tracing::info!(
                    best_full_block_height = chain_state.best_full_block_height,
                    "Mode 2 install detected without trust flag — self-healing arm",
                );
                let write_txn = crate::begin_write_qr(&db)?;
                write_mode2_trust_sentinel(&write_txn)?;
                write_txn.commit()?;
                true
            } else {
                persisted
            }
        };

        let mut store = Self {
            difficulty_params: ergo_chain_spec::DifficultyParams::mainnet(),
            headers: crate::header_store::HeaderSectionTables::new(db.clone()),
            db,
            tree,
            height,
            genesis_committed,
            chain_state,
            // Provisional value; refreshed below after reconcile guarantees
            // the genesis row exists.
            cached_active_params: launch_params.clone(),
            cached_validation_settings: ergo_validation::ErgoValidationSettings::empty(),
            ibd_mode: false,
            ibd_blocks_since_flush: 0,
            ibd_flush_interval: 0,
            persist_pipeline: None,
            mode2_trust_first_epoch,
            init_launch_params: launch_params,
            voting_settings,
            // Mode 3 default: archive (no pruning). Production boot
            // overrides via `set_blocks_to_keep` from
            // `[node] blocks_to_keep`. Tests opt in by calling the
            // setter explicitly.
            blocks_to_keep: -1,
            rollback_window: ROLLBACK_WINDOW,
        };
        store.backfill_header_chain_index_if_needed()?;
        store.reconcile_voted_params()?;
        store.migrate_voted_params_codec_v2_if_needed()?;
        store.refresh_cached_active_params()?;
        // Open deliberately does NOT seed the prune sentinel.
        // `read_minimal_full_block_height` returns 1 (GenesisHeight)
        // when the key is absent — the legitimate default for
        // archive / Mode 6 / fresh-DB / archive-from-genesis cases.
        // Bootstrap-aware seeding happens at the WRITER side:
        // `install_snapshot_state` co-commits `snapshot_height + 1`
        // and `apply_popow_proof` co-commits `dense_from_height`,
        // both inside their existing atomic write_txns.
        //
        // Open does NOT migrate absent rows for legacy bootstrap DBs
        // (a DB whose `install_snapshot_state` ran before Phase 1b's
        // sentinel co-commit existed). A migration here would have
        // to distinguish "archive with best_full > 1 and absent row"
        // (where the row should stay absent — archive has all
        // blocks) from "bootstrap with best_full > 1 and absent row"
        // (where the row should be stamped at the anchor). Doing
        // that distinction requires config access (`blocks_to_keep`)
        // which open does not have, and Mode 4 has not shipped yet
        // so no production legacy bootstrap DB exists. The Phase 5
        // boot-consistency check (operator-config + persisted-
        // sentinel cross-check, in `ergo-node/src/node/boot.rs`)
        // owns this migration.
        Ok(store)
    }

    /// Peek the Mode 2 install trust claim without consuming it.
    /// Returns the current armed state so the validator can decide
    /// whether to take the trust path. The flag is cleared only via
    /// `consume_mode2_trust_first_epoch` after the boundary block has
    /// applied successfully — leaving consumption tied to apply
    /// success means an in-process retry (apply fails for a non-
    /// validator reason → recovery path → retry the same block) sees
    /// the flag still armed and the trust path fires again.
    pub fn is_mode2_trust_first_epoch_armed(&self) -> bool {
        self.mode2_trust_first_epoch
    }

    /// Consume the Mode 2 install trust claim: clear both the
    /// in-memory latch and the persisted byte. Called after the
    /// first post-install epoch boundary block has fully committed
    /// (validation + apply succeeded). After this point the trusted
    /// cumulative lives durably in `voted_params` (as the synthetic
    /// `activated_update` of the apply'd row) and the trust path no
    /// longer needs to fire.
    ///
    /// The persisted byte is best-effort: a transient write failure
    /// leaves the disk flag set, but the validator's stricter trust
    /// gate (only fires when `prev_settings == empty()`) means a
    /// re-arm on restart is bounded — the cache will already hold
    /// the trusted cumulative from the persisted apply, so the gate
    /// stays closed at the next epoch boundary.
    pub fn consume_mode2_trust_first_epoch(&mut self) {
        self.mode2_trust_first_epoch = false;
        if let Ok(write_txn) = crate::begin_write_qr(&self.db) {
            if let Ok(mut table) = write_txn.open_table(CHAIN_STATE_META) {
                let _ = table.remove(MODE2_TRUST_FIRST_EPOCH_KEY);
            }
            let _ = write_txn.commit();
        }
    }

    /// Arm the Mode-2 sentinel as a standalone write — same key,
    /// same byte that `install_snapshot_state` writes inside its
    /// atomic install txn. Used by the test-only wrapper
    /// `test_helpers::arm_mode2_trust_first_epoch_for_test`;
    /// production code arms via `install_snapshot_state`, which
    /// shares the per-txn primitive `write_mode2_trust_sentinel`
    /// below so any drift in the sentinel encoding is observable
    /// from both code paths.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn arm_mode2_trust_first_epoch_internal(&mut self) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        write_mode2_trust_sentinel(&write_txn)?;
        write_txn.commit()?;
        self.mode2_trust_first_epoch = true;
        Ok(())
    }

    /// Test-only chain_state injection seam. Updates the persisted
    /// `CHAIN_STATE_META["chain_state"]` row's best_full_block_id /
    /// best_full_block_height while preserving header_availability
    /// and best_header_*. Used to exercise apply / bootstrap
    /// precondition guards without setting up a full snapshot
    /// install. Bypasses validation entirely; callers must own
    /// internal consistency.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn set_best_full_block_internal_for_test_helpers(
        &mut self,
        id: [u8; 32],
        height: u32,
    ) -> Result<(), StateError> {
        use super::CHAIN_STATE_META;
        let mut new_cs = self.chain_state.to_persisted();
        new_cs.best_full_block_id = id;
        new_cs.best_full_block_height = height;
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut table = write_txn.open_table(CHAIN_STATE_META)?;
            table.insert("chain_state", new_cs.serialize().as_slice())?;
        }
        write_txn.commit()?;
        self.chain_state = crate::chain::ChainState::from_persisted(&new_cs);
        Ok(())
    }

    /// Test-only HEADERS_BY_HEIGHT seed. Phase 2a eviction reads
    /// this table to walk every header_id at a pruned height.
    /// Production populates it via the header validation
    /// pipeline; eviction tests that bypass block_proc seed it
    /// directly through this helper.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn promote_header_to_height_index_internal_for_test_helpers(
        &self,
        height: u32,
        header_id: &[u8; 32],
    ) -> Result<(), StateError> {
        use super::{promote_to_height_index_slot_0, HEADERS_BY_HEIGHT};
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut table = write_txn.open_table(HEADERS_BY_HEIGHT)?;
            promote_to_height_index_slot_0(&mut table, height, header_id)?;
        }
        write_txn.commit()?;
        Ok(())
    }
}

/// Single sentinel-write primitive shared by `install_snapshot_state`
/// (production install, inside its atomic write_txn) and
/// `arm_mode2_trust_first_epoch_internal` (test-only standalone
/// write). Same key + byte — drift here breaks both paths.
pub(super) fn write_mode2_trust_sentinel(
    write_txn: &redb::WriteTransaction,
) -> Result<(), StateError> {
    let mut table = write_txn.open_table(CHAIN_STATE_META)?;
    table.insert(MODE2_TRUST_FIRST_EPOCH_KEY, [0x01u8].as_slice())?;
    Ok(())
}
