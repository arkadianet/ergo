//! `ScalaCompatBridge` — the read-side half of the Scala-compat API
//! surface. Implements `ergo_api::ChainParamsView` and
//! `ergo_api::NodeChainQuery` against the snapshot handle and a
//! lock-free `ChainStoreReader`.
//!
//! Kept in a sibling submodule of `api_bridge.rs` to keep the parent
//! file navigable. The `use super::*;` wildcard inherits
//! api_bridge.rs's full import environment so this is a pure
//! relocation — no visibility changes needed.

use super::*;
use ergo_ser::difficulty::decode_compact_bits;

/// Boot-time, immutable inputs to the Scala-compat surface. The values
/// here either don't change after the node starts (network, app version,
/// launch time) or are configured once and reflected as-is (rest API URL).
#[derive(Clone, Debug)]
pub struct ScalaCompatStatic {
    pub name: String,
    pub app_version: String,
    pub network: String,
    pub launch_time_unix_ms: u64,
    pub rest_api_url: Option<String>,
}

/// Implements `ergo_api::NodeChainQuery` against the snapshot handle and
/// a lock-free read handle to the chain store. `/info` reads are
/// snapshot-only; id-keyed lookups go through the store reader. The two
/// paths are independent — neither blocks the main loop.
pub struct ScalaCompatBridge {
    handle: SnapshotHandle,
    static_cfg: Arc<ScalaCompatStatic>,
    store_reader: ChainStoreReader,
    /// Network difficulty schedule for the NiPoPoW on-demand prover
    /// (`/nipopow/proof/*`). Wired from `chain_spec.difficulty` at
    /// boot, mirroring `StateStore::set_difficulty_params`.
    difficulty_params: ergo_chain_spec::DifficultyParams,
}

impl ScalaCompatBridge {
    pub fn new(
        handle: SnapshotHandle,
        static_cfg: ScalaCompatStatic,
        store_reader: ChainStoreReader,
        difficulty_params: ergo_chain_spec::DifficultyParams,
    ) -> Self {
        Self {
            handle,
            static_cfg: Arc::new(static_cfg),
            store_reader,
            difficulty_params,
        }
    }

    pub fn into_dyn(self) -> Arc<dyn NodeChainQuery> {
        Arc::new(self)
    }

    /// Hand the bridge to the API as a `ChainParamsView`. Same
    /// instance — the `Arc` holds it once.
    pub fn into_chain_params(self: Arc<Self>) -> Arc<dyn ergo_api::ChainParamsView> {
        self
    }
}

impl ergo_api::ChainParamsView for ScalaCompatBridge {
    fn storage_fee_factor_for_validation_at(&self, h: u32) -> Option<i32> {
        debug_assert!(
            h > 0,
            "ChainParamsView called with h == 0; the storage-rent handler must short-circuit before this point"
        );
        if h == 0 {
            return None;
        }
        let prev = h - 1;
        self.store_reader
            .active_params_at(prev)
            .ok()
            .flatten()
            .map(|p| p.storage_fee_factor)
    }

    fn compute_storage_fee(&self, box_bytes_len: i32, storage_fee_factor: i32) -> i32 {
        ergo_validation::storage_rent::compute_storage_fee(box_bytes_len, storage_fee_factor)
    }
}

impl NodeChainQuery for ScalaCompatBridge {
    fn snapshots_info(&self) -> Vec<(i32, String)> {
        // Mirrored into the published snapshot once per sync_tick from the
        // action loop's Mode-2 serve cache (`SnapshotState`), so this REST
        // read always agrees with the P2P `SnapshotsInfo` reply.
        self.handle.load().snapshot_manifests.clone()
    }

    fn info(&self) -> ScalaInfo {
        let snap = self.handle.load();
        let cfg = &self.static_cfg;

        // Read the active protocol parameter set straight from the
        // snapshot. The snapshot builder reads it once per sync_tick
        // from `voted_params` at the current full-block tip; the table
        // is populated atomically with each epoch-start block's apply
        // and reconciled on every `StateStore::open`. There is no
        // runtime fallback to launch defaults.
        //
        // Known cosmetic gap: `subblocks_per_block` is `u32` in our DTO
        // but `Option[Int]` in Scala. For pre-EIP37 epochs (active
        // `epoch_start_height < 843_776`) Scala emits `null`, we emit
        // `0`. Live mainnet is post-EIP37 and the API is loopback-only,
        // so steady-state operators see byte-exact parity.
        let p = &snap.active_params;
        let parameters = Parameters {
            output_cost: p.output_cost as u64,
            token_access_cost: p.token_access_cost as u64,
            max_block_cost: p.max_block_cost as u64,
            height: p.epoch_start_height,
            max_block_size: p.max_block_size as u32,
            data_input_cost: p.data_input_cost as u64,
            block_version: p.block_version,
            input_cost: p.input_cost as u64,
            storage_fee_factor: p.storage_fee_factor,
            subblocks_per_block: p.subblocks_per_block.unwrap_or(0) as u32,
            min_value_per_byte: p.min_value_per_byte as u64,
        };

        ScalaInfo {
            last_mempool_update_time: snap.last_mempool_update_unix_ms,
            current_time: unix_now_ms(),
            network: cfg.network.clone(),
            name: cfg.name.clone(),
            state_type: "utxo".to_string(),
            // Decoded from the best-header tip's nBits. `u64` is a
            // Scala-surface cap only — native truth is the full-precision
            // String on `ApiTip`; this saturates if difficulty ever
            // exceeds `u64` (well above observed mainnet).
            difficulty: u64::try_from(decode_compact_bits(snap.tip.best_header.n_bits))
                .unwrap_or(u64::MAX),
            best_full_header_id: snap.tip.best_full_block.header_id.clone(),
            best_header_id: snap.tip.best_header.header_id.clone(),
            peers_count: snap.status.peer_count,
            unconfirmed_count: snap.mempool.size,
            app_version: cfg.app_version.clone(),
            // Both EIPs are required to sync mainnet at all, so reporting
            // `true` is accurate any time this node successfully validates
            // post-activation blocks. If we add testnet config later that
            // disables either, gate these on the active config.
            eip37_supported: true,
            state_root: snap.tip.best_full_block.state_root_avl.clone(),
            genesis_block_id: hex::encode(snap.genesis_block_id),
            rest_api_url: cfg.rest_api_url.clone(),
            previous_full_header_id: snap.tip.best_full_block.parent_id.clone(),
            full_height: snap.tip.best_full_block.height,
            headers_height: snap.tip.best_header.height,
            state_version: snap.tip.best_full_block.header_id.clone(),
            full_blocks_score: score_to_u128(&snap.best_full_block_score),
            // SyncState::best_known_header_height() via the snapshot — the network-best-height notion Scala's maxPeerHeight tracks.
            max_peer_height: snap.max_peer_height,
            launch_time: cfg.launch_time_unix_ms,
            is_explorer: false,
            last_seen_message_time: snap.last_seen_message_unix_ms,
            eip27_supported: true,
            headers_score: score_to_u128(&snap.best_header_score),
            parameters,
            is_mining: snap.mining_enabled,
        }
    }

    fn votes_history(&self) -> ergo_api::types::ApiVotesHistory {
        let snap = self.handle.load();
        let current_height = snap.tip.best_full_block.height;
        // Epoch length is network-fixed; surfaced so the UI can explain that
        // changes only land on `voting_length`-block boundaries.
        let epoch_length = match self.static_cfg.network.as_str() {
            "mainnet" => ergo_chain_spec::VotingParams::mainnet().voting_length,
            "testnet" => ergo_chain_spec::VotingParams::testnet().voting_length,
            _ => 0,
        };
        match self.store_reader.voted_params_history() {
            Ok(rows) => build_votes_history(&rows, epoch_length, current_height),
            Err(e) => {
                warn!(handler = "votes_history", error = %e, "scala-compat handler failed");
                ergo_api::types::ApiVotesHistory {
                    epoch_length,
                    current_height,
                    changes: Vec::new(),
                }
            }
        }
    }

    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        // Reads HEADERS_BY_HEIGHT (the multi-id index), which mirrors
        // Scala's `heightIdsKey` row from
        // `HeadersProcessor.scala:264-276`. First entry is always the
        // best-header-chain id at `height`; subsequent entries are
        // orphans (validated headers at this height that aren't on
        // the best chain). DB errors degrade to an empty vec —
        // handlers must never panic.
        match self.store_reader.header_ids_at_height_all(height) {
            Ok(ids) => ids.into_iter().map(hex::encode).collect(),
            Err(e) => {
                warn!(handler = "header_ids_at_height_all", height, error = %e, "scala-compat handler failed");
                Vec::new()
            }
        }
    }

    fn full_block_by_id(&self, header_id_hex: &str) -> Option<ScalaFullBlock> {
        let header_id = parse_header_id(header_id_hex)?;
        match assemble_full_block(&self.store_reader, &header_id) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(handler = "full_block_by_id", header_id = %header_id_hex, error = %e, "scala-compat handler failed");
                None
            }
        }
    }

    fn header_by_id(&self, header_id_hex: &str) -> Option<ScalaHeader> {
        let header_id = parse_header_id(header_id_hex)?;
        match load_and_encode_header(&self.store_reader, &header_id) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(handler = "header_by_id", header_id = %header_id_hex, error = %e, "scala-compat handler failed");
                None
            }
        }
    }

    fn block_transactions_by_id(&self, header_id_hex: &str) -> Option<ScalaBlockTransactions> {
        let header_id = parse_header_id(header_id_hex)?;
        match load_and_encode_block_transactions(&self.store_reader, &header_id) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(handler = "block_transactions_by_id", header_id = %header_id_hex, error = %e, "scala-compat handler failed");
                None
            }
        }
    }

    fn nipopow_header_by_id(
        &self,
        header_id_hex: &str,
    ) -> Option<ergo_rest_json::types::ScalaPopowHeader> {
        let header_id = parse_header_id(header_id_hex)?;
        let ph = match self.store_reader.popow_header_by_id(&header_id) {
            Ok(Some(ph)) => ph,
            Ok(None) => return None,
            Err(e) => {
                warn!(handler = "nipopow_header_by_id", header_id = %header_id_hex, error = %e, "scala-compat handler failed");
                return None;
            }
        };
        match super::nipopow::encode_popow_header(&ph) {
            Ok(dto) => Some(dto),
            Err(e) => {
                warn!(handler = "nipopow_header_by_id", header_id = %header_id_hex, error = %e, "popow header encode failed");
                None
            }
        }
    }

    fn nipopow_header_at_height(
        &self,
        height: u32,
    ) -> Option<ergo_rest_json::types::ScalaPopowHeader> {
        let ph = match self.store_reader.popow_header_at_height(height) {
            Ok(Some(ph)) => ph,
            Ok(None) => return None,
            Err(e) => {
                warn!(handler = "nipopow_header_at_height", height, error = %e, "scala-compat handler failed");
                return None;
            }
        };
        match super::nipopow::encode_popow_header(&ph) {
            Ok(dto) => Some(dto),
            Err(e) => {
                warn!(handler = "nipopow_header_at_height", height, error = %e, "popow header encode failed");
                None
            }
        }
    }

    fn nipopow_proof(
        &self,
        m: u32,
        k: u32,
        header_id_hex: Option<&str>,
    ) -> Result<ergo_rest_json::types::ScalaNipopowProof, String> {
        // Handler pre-validates hex; belt-and-braces here because the
        // trait is also reachable from tests/other bridges.
        let header_id_opt = match header_id_hex {
            Some(hex_str) => Some(
                parse_header_id(hex_str).ok_or_else(|| "Wrong modifierId format".to_string())?,
            ),
            None => None,
        };
        // One consistent meta read supplies BOTH the best-header height
        // and the availability mode — mixing the snapshot's height with
        // the store's mode could tear across a bootstrap transition.
        let meta = self
            .store_reader
            .chain_state_meta()
            .map_err(|e| format!("chain state unavailable: {e}"))?
            .ok_or_else(|| "chain state unavailable: store is empty".to_string())?;
        let is_dense = !matches!(
            meta.header_availability,
            ergo_state::chain::HeaderAvailability::PoPowSparse { .. }
        );
        let proof = self
            .store_reader
            .prove_nipopow(
                m,
                k,
                header_id_opt,
                meta.best_header_height,
                is_dense,
                &self.difficulty_params,
            )
            .map_err(|e| e.to_string())?;
        super::nipopow::encode_nipopow_proof(&proof).map_err(|e| e.to_string())
    }

    fn proof_for_tx(&self, header_id_hex: &str, tx_id_hex: &str) -> Option<ScalaMerkleProof> {
        let header_id = parse_header_id(header_id_hex)?;
        let tx_id = parse_header_id(tx_id_hex)?;
        match build_proof_for_tx(&self.store_reader, &header_id, &tx_id) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(handler = "proof_for_tx", header_id = %header_id_hex, tx_id = %tx_id_hex, error = %e, "scala-compat handler failed");
                None
            }
        }
    }

    fn modifier_by_id(&self, modifier_id_hex: &str) -> Option<ScalaBlockSection> {
        let id = parse_header_id(modifier_id_hex)?;
        match load_and_encode_modifier_by_id(&self.store_reader, &id) {
            Ok(opt) => opt,
            Err(e) => {
                warn!(handler = "modifier_by_id", modifier_id = %modifier_id_hex, error = %e, "scala-compat handler failed");
                None
            }
        }
    }

    fn last_headers(&self, count: u32) -> Vec<ScalaHeader> {
        if count == 0 {
            return Vec::new();
        }
        let tip = self.handle.load().tip.best_header.height;
        // Saturating sub: if `count` exceeds the chain length, start at 1
        // (genesis). Inclusive range, ascending.
        let lo = tip.saturating_sub(count - 1).max(1);
        load_headers_in_range(&self.store_reader, lo, tip)
    }

    fn chain_slice(&self, from_height: u32, to_height: u32) -> Vec<ScalaHeader> {
        let tip = self.handle.load().tip.best_header.height;
        if tip == 0 {
            return Vec::new();
        }
        // Scala: `top = headerIdsAtHeight(toHeight).headOption.flatMap(...).orElse(bestHeaderOpt)`.
        // We approximate "header exists at this height" via the canonical
        // chain index — equivalent for non-fork chains, matches
        // `header_ids_at_height`'s scope for forked ones. The handler
        // passes `u32::MAX` for negative `toHeight` so this branch falls
        // through to tip, identical to Scala's `orElse(bestHeaderOpt)`.
        let top = match self.store_reader.get_header_id_at_height(to_height) {
            Ok(Some(_)) => to_height,
            _ => tip,
        };
        if top == 0 {
            return Vec::new();
        }
        // headerChainBack(MaxHeaders, top, _.height <= from + 1) — start
        // header always included, parents added until predicate triggers
        // (and the triggering header is included). For a canonical chain
        // this collapses to a contiguous height range.
        const MAX_HEADERS: u32 = 16_384;
        let lo = if top <= from_height.saturating_add(1) {
            // Predicate triggers at start; only the start header is returned.
            top
        } else {
            // Lowest height included is from + 1, capped at MAX_HEADERS
            // entries from top walking back, and never below 1.
            let raw_lo = from_height.saturating_add(1);
            let cap_lo = top.saturating_sub(MAX_HEADERS - 1);
            raw_lo.max(cap_lo).max(1)
        };
        load_headers_in_range(&self.store_reader, lo, top)
    }

    fn peers_all(&self) -> Vec<ScalaPeer> {
        self.handle
            .load()
            .peers
            .iter()
            .map(project_scala_peer)
            .collect()
    }

    fn peers_connected(&self) -> Vec<ScalaPeer> {
        self.handle
            .load()
            .peers
            .iter()
            .filter(|p| p.state == ergo_api::types::ApiPeerState::Active)
            .map(project_scala_peer)
            .collect()
    }

    fn peers_blacklisted(&self) -> ScalaBlacklistedPeers {
        // Format each banned IP as Java `InetAddress.toString()`
        // emits — `/literal-ip` for raw IPs (no hostname bound).
        // Matches Scala's `ErgoPeersApiRoute.scala:98-102` wire
        // shape: bare-IP entries get the leading slash, while
        // hostnames (which we don't track) would be
        // `hostname/literal-ip`. Source: `NodeSnapshot.banned_ips`,
        // populated each tick by `PeerManager::currently_banned_ips`
        // (expired entries already filtered out at snapshot time).
        let snap = self.handle.load();
        let addresses = snap.banned_ips.iter().map(|ip| format!("/{ip}")).collect();
        ScalaBlacklistedPeers { addresses }
    }

    fn peers_status(&self) -> ergo_api::compat::types::ScalaPeersStatus {
        // `current_system_time` is the node's clock at response
        // time (Scala parity: `PeersStatusResponse.currentSystemTime`).
        // `last_incoming_message` sources from
        // `NodeSnapshot.last_seen_message_unix_ms` — already
        // computed by `snapshot_emit::build` as the max
        // `last_seen_message_unix_ms` across peers (most recent
        // inbound message arrival).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let snap = self.handle.load();
        ergo_api::compat::types::ScalaPeersStatus {
            last_incoming_message: snap.last_seen_message_unix_ms,
            current_system_time: now,
        }
    }

    // (peers_blacklisted is implemented above — see the override
    // following peers_connected for the snapshot.banned_ips read +
    // /literal-ip formatting.)

    fn peers_sync_info(&self) -> Vec<ergo_api::compat::types::ScalaSyncInfoEntry> {
        // Per-peer projection from the snapshot's
        // `peer_sync: HashMap<SocketAddr, PeerSyncProjection>`.
        // Populated by `SyncCoordinator::on_sync_info` each time a
        // SyncInfo message arrives; evicted by
        // `on_peer_disconnected`.
        //
        // Two honesty filters:
        // (1) Peers without an observation yet (handshaking, no
        //     SyncInfo round-trip completed) are OMITTED — don't
        //     fabricate `status="unknown"`.
        // (2) Peers WITH an observation but no overlap with our
        //     best chain (V1: no height in SyncInfo; V2: no peer-
        //     header on our chain) are ALSO omitted — emitting
        //     `height=0` would fabricate a value we don't have.
        //     This is a coverage gap from the underlying P2P
        //     message format (V1 SyncInfo doesn't carry height,
        //     V2 carries headers from which we can only infer
        //     overlap-height); /peers/syncInfo surfaces only the
        //     peers we have a real height for.
        let snap = self.handle.load();
        snap.peer_sync
            .iter()
            .filter_map(|(addr, proj)| {
                let height = proj.peer_height?;
                Some(ergo_api::compat::types::ScalaSyncInfoEntry {
                    address: addr.to_string(),
                    height,
                    status: proj.status.to_string(),
                })
            })
            .collect()
    }

    fn peers_track_info(&self) -> ergo_api::compat::types::ScalaTrackInfo {
        // Snapshotted `DeliveryCounters` from
        // `state.coordinator.delivery()` — the publish loop
        // refreshes them each `sync_tick`. Saturating-cast already
        // applied at snapshot time so the wire u32 can't overflow.
        let snap = self.handle.load();
        ergo_api::compat::types::ScalaTrackInfo {
            num_requested: snap.delivery_counts.requested,
            num_received: snap.delivery_counts.received,
            num_failed: snap.delivery_counts.failed,
        }
    }

    fn pool_tx_ids(&self) -> Vec<String> {
        self.handle
            .load()
            .mempool_transactions
            .transactions
            .iter()
            .map(|t| t.tx_id.clone())
            .collect()
    }

    fn pool_contains(&self, tx_id_hex: &str) -> bool {
        self.handle
            .load()
            .mempool_transactions
            .transactions
            .iter()
            .any(|t| t.tx_id == tx_id_hex)
    }

    fn pool_size(&self) -> u32 {
        self.handle.load().mempool_transactions.transactions.len() as u32
    }

    fn pool_txs_paged(
        &self,
        offset: u32,
        limit: u32,
    ) -> Vec<ergo_api::compat::types::ScalaTransaction> {
        let snap = self.handle.load();
        snap.pool_full_txs
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .filter_map(|(_, bytes)| pool_bytes_to_scala_tx(bytes))
            .collect()
    }

    fn pool_tx_by_id(&self, tx_id_hex: &str) -> Option<ergo_api::compat::types::ScalaTransaction> {
        let target_bytes: [u8; 32] = hex::decode(tx_id_hex).ok()?.try_into().ok()?;
        let snap = self.handle.load();
        snap.pool_full_txs
            .iter()
            .find(|(id, _)| id.as_bytes() == &target_bytes)
            .and_then(|(_, bytes)| pool_bytes_to_scala_tx(bytes))
    }

    fn pool_txs_by_ids(
        &self,
        tx_ids_hex: &[String],
    ) -> Vec<ergo_api::compat::types::ScalaTransaction> {
        // Single snapshot load for the whole batch so all ids
        // resolve against the same point-in-time pool view. A
        // composed-via-self.pool_tx_by_id variant would reload the
        // snapshot per id — fine for correctness but could mix
        // snapshot versions across entries in one response.
        let snap = self.handle.load();
        tx_ids_hex
            .iter()
            .filter_map(|id_hex| {
                let target_bytes: [u8; 32] = hex::decode(id_hex).ok()?.try_into().ok()?;
                snap.pool_full_txs
                    .iter()
                    .find(|(id, _)| id.as_bytes() == &target_bytes)
                    .and_then(|(_, bytes)| pool_bytes_to_scala_tx(bytes))
            })
            .collect()
    }

    fn pool_txs_by_ergo_tree(
        &self,
        tree_bytes: &[u8],
    ) -> Vec<ergo_api::compat::types::ScalaTransaction> {
        // Single snapshot load — every pool tx scanned against the
        // same point-in-time view. Match is byte-equality between
        // the request's canonical ergoTree wire form and each
        // output's `ergo_tree_bytes()`. Parse-failures are silently
        // skipped (same flatMap(getById) lossy-skip semantics
        // `pool_txs_by_ids` uses for malformed pool entries).
        let snap = self.handle.load();
        snap.pool_full_txs
            .iter()
            .filter_map(|(_, bytes)| {
                let tx = parse_pool_tx(bytes)?;
                let matches = tx
                    .output_candidates
                    .iter()
                    .any(|out| out.ergo_tree_bytes() == tree_bytes);
                if matches {
                    crate::api_bridge::compat::encode_transaction(&tx).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    fn pool_txs_by_box_id(
        &self,
        box_id: &[u8; 32],
    ) -> Vec<ergo_api::compat::types::ScalaTransaction> {
        let snap = self.handle.load();
        snap.pool_full_txs
            .iter()
            .filter_map(|(_, bytes)| {
                let tx = parse_pool_tx(bytes)?;
                let matches = tx.inputs.iter().any(|inp| inp.box_id.as_bytes() == box_id);
                if matches {
                    crate::api_bridge::compat::encode_transaction(&tx).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    fn pool_txs_by_token_id(
        &self,
        token_id: &[u8; 32],
    ) -> Vec<ergo_api::compat::types::ScalaTransaction> {
        let snap = self.handle.load();
        snap.pool_full_txs
            .iter()
            .filter_map(|(_, bytes)| {
                let tx = parse_pool_tx(bytes)?;
                let matches = tx
                    .output_candidates
                    .iter()
                    .any(|out| out.tokens.iter().any(|t| t.token_id.as_bytes() == token_id));
                if matches {
                    crate::api_bridge::compat::encode_transaction(&tx).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    fn pool_fee_histogram(
        &self,
        bins: u32,
        maxtime_ms: u64,
    ) -> Vec<ergo_api::compat::types::ScalaFeeHistogramBin> {
        let snap = self.handle.load();
        let ranked = rank_pool_by_fee_per_byte(&snap.pool_full_txs);
        // Cap `bins` at MAX_HISTOGRAM_BINS so a caller passing
        // `u32::MAX` cannot DoS the response with a multi-gigabyte
        // allocation (4096 entries × 16 bytes = 64 KiB — well
        // beyond any visualization need; OpenAPI sets no maximum
        // but a server-side cap is the responsible behavior).
        // Also avoids the 32-bit target overflow where
        // `bins as usize + 1` could wrap.
        let bin_count = (bins.max(1) as usize).min(MAX_HISTOGRAM_BINS);
        let mut out = vec![
            ergo_api::compat::types::ScalaFeeHistogramBin {
                n_txns: 0,
                total_fee: 0,
            };
            bin_count + 1
        ];
        for (rank, entry) in ranked.iter().enumerate() {
            let wait_ms = estimate_wait_ms_from_rank(rank as u64);
            let bin_index = bin_for_wait_ms(wait_ms, bin_count, maxtime_ms);
            out[bin_index].n_txns = out[bin_index].n_txns.saturating_add(1);
            out[bin_index].total_fee = out[bin_index].total_fee.saturating_add(entry.fee);
        }
        out
    }

    fn pool_recommended_fee(&self, wait_time_minutes: u32, tx_size_bytes: u32) -> u64 {
        if tx_size_bytes == 0 {
            return 0;
        }
        let snap = self.handle.load();
        let min_fee_per_byte = snap.active_params.min_value_per_byte.max(0) as u64;
        let floor = min_fee_per_byte.saturating_mul(tx_size_bytes as u64);
        let ranked = rank_pool_by_fee_per_byte(&snap.pool_full_txs);
        if ranked.is_empty() {
            return floor;
        }
        let target_ms = (wait_time_minutes as u64).saturating_mul(60_000);
        // Find the highest fee-per-byte that would land within
        // `target_ms`. The ranking is descending by fee/byte, so the
        // tx whose estimated wait first exceeds `target_ms` defines
        // the threshold — bid one above its fee/byte to displace it.
        let mut threshold_fee_per_byte: u64 = min_fee_per_byte;
        for (rank, entry) in ranked.iter().enumerate() {
            let wait_ms = estimate_wait_ms_from_rank(rank as u64);
            if wait_ms <= target_ms {
                threshold_fee_per_byte = entry.fee_per_byte;
            } else {
                break;
            }
        }
        let recommended = threshold_fee_per_byte
            .saturating_add(1)
            .saturating_mul(tx_size_bytes as u64);
        recommended.max(floor)
    }

    fn pool_expected_wait_time_ms(&self, fee: u64, tx_size_bytes: u32) -> u64 {
        if tx_size_bytes == 0 {
            return 0;
        }
        let snap = self.handle.load();
        let ranked = rank_pool_by_fee_per_byte(&snap.pool_full_txs);
        let our_fee_per_byte = fee / tx_size_bytes as u64;
        // Position = number of pool txs with fee/byte >= ours.
        // Existing pool entries at equal fee/byte queue AHEAD of a
        // new submission (they're already in the pool; we'd join
        // after them under any stable sort policy), so this counts
        // ">=" not just ">". Counting only strict ">" would
        // underestimate wait time for tx volumes clustered at a
        // single fee/byte tier.
        let rank_count = ranked
            .iter()
            .take_while(|e| e.fee_per_byte >= our_fee_per_byte)
            .count();
        estimate_wait_ms_from_rank(rank_count as u64)
    }

    fn pool_txs_by_registers(
        &self,
        registers: &std::collections::BTreeMap<String, String>,
    ) -> Vec<ergo_api::compat::types::ScalaTransaction> {
        // Parse the request map once: (R-index 0..=5, expected bytes).
        // If any name fails to resolve to R4..R9 or any value fails
        // hex-decode, return an empty result — bridge can't honour an
        // unparseable filter, and the API handler doesn't pre-validate
        // map values (only the JSON shape).
        let mut filter: Vec<(usize, Vec<u8>)> = Vec::with_capacity(registers.len());
        for (name, hex_str) in registers {
            let idx = match name.as_str() {
                "R4" => 0,
                "R5" => 1,
                "R6" => 2,
                "R7" => 3,
                "R8" => 4,
                "R9" => 5,
                _ => return Vec::new(),
            };
            let bytes = match hex::decode(hex_str) {
                Ok(b) => b,
                Err(_) => return Vec::new(),
            };
            filter.push((idx, bytes));
        }

        let snap = self.handle.load();
        snap.pool_full_txs
            .iter()
            .filter_map(|(_, bytes)| {
                let tx = parse_pool_tx(bytes)?;
                let matches = tx.output_candidates.iter().any(|out| {
                    let slices =
                        match ergo_ser::register::split_register_bytes(out.register_bytes()) {
                            Ok(s) => s,
                            Err(_) => return false,
                        };
                    filter.iter().all(|(idx, expected)| {
                        slices.get(*idx).map(|s| s == expected).unwrap_or(false)
                    })
                });
                if matches {
                    crate::api_bridge::compat::encode_transaction(&tx).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    fn header_ids_paged(&self, limit: u32, offset: u32) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        // Scala: `(offset until (offset + limit)).flatMap(bestHeaderIdAtHeight)`.
        // Half-open range, ascending, missing heights silently dropped.
        let lo = offset;
        let hi = offset.saturating_add(limit).saturating_sub(1);
        match self.store_reader.scan_header_chain_range(lo, hi) {
            Ok(entries) => entries.into_iter().map(|(_, id)| hex::encode(id)).collect(),
            Err(e) => {
                warn!(handler = "header_ids_paged", limit, offset, error = %e, "scala-compat handler failed");
                Vec::new()
            }
        }
    }

    fn utxo_box_by_id(&self, box_id_hex: &str) -> Option<ScalaOutput> {
        let id = parse_box_id(box_id_hex)?;
        let raw = match self.store_reader.lookup_box(&id) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return None,
            Err(e) => {
                warn!(handler = "utxo_box_by_id", box_id = %box_id_hex, error = %e, "scala-compat lookup failed");
                return None;
            }
        };
        match encode_scala_output_from_raw(&raw, &id) {
            Ok(out) => Some(out),
            Err(e) => {
                warn!(handler = "utxo_box_by_id", box_id = %box_id_hex, error = %e, "scala-compat decode failed");
                None
            }
        }
    }

    fn utxo_box_bytes_by_id(
        &self,
        box_id_hex: &str,
    ) -> Option<ergo_api::compat::traits::UtxoBoxBytes> {
        let id = parse_box_id(box_id_hex)?;
        match self.store_reader.lookup_box(&id) {
            Ok(Some(bytes)) => Some(ergo_api::compat::traits::UtxoBoxBytes {
                box_id: hex::encode(id),
                bytes: hex::encode(bytes),
            }),
            Ok(None) => None,
            Err(e) => {
                warn!(handler = "utxo_box_bytes_by_id", box_id = %box_id_hex, error = %e, "scala-compat lookup failed");
                None
            }
        }
    }

    fn utxo_genesis_boxes(&self) -> Vec<ScalaOutput> {
        // Scala's `genesisBoxes` returns the three deterministic state
        // boxes derived from chain settings. The rust node embeds the
        // mainnet and testnet box sets under `test-vectors/<net>/` and
        // the bridge encodes them on each call. Volume is fixed at
        // three boxes so per-call work is negligible.
        let raw_boxes = match self.static_cfg.network.as_str() {
            "mainnet" => crate::genesis::mainnet_genesis_boxes(),
            "testnet" => crate::genesis::testnet_genesis_boxes(),
            other => {
                warn!(network = other, "utxo_genesis_boxes: unsupported network");
                return Vec::new();
            }
        };
        raw_boxes
            .into_iter()
            .filter_map(|(id, raw)| match encode_scala_output_from_raw(&raw, &id) {
                Ok(out) => Some(out),
                Err(e) => {
                    warn!(handler = "utxo_genesis_boxes", box_id = %hex::encode(id), error = %e, "scala-compat encode failed");
                    None
                }
            })
            .collect()
    }

    fn utxo_with_pool_box_by_id(&self, box_id_hex: &str) -> Option<ScalaOutput> {
        let id = parse_box_id(box_id_hex)?;
        // Committed UTXO wins (Scala `super.boxById(id).orElse(pool)`).
        if let Some(out) = self.utxo_box_by_id(box_id_hex) {
            return Some(out);
        }
        let snap = self.handle.load();
        let id_digest = Digest32::from_bytes(id);
        let pool_box = snap.pool_outputs.get(&id_digest)?;
        match encode_output(
            &pool_box.candidate,
            hex::encode(id),
            hex::encode(pool_box.transaction_id.as_bytes()),
            pool_box.index,
        ) {
            Ok(out) => Some(out),
            Err(e) => {
                warn!(handler = "utxo_with_pool_box_by_id", box_id = %box_id_hex, error = %e, "scala-compat encode failed");
                None
            }
        }
    }

    fn utxo_with_pool_box_bytes_by_id(
        &self,
        box_id_hex: &str,
    ) -> Option<ergo_api::compat::traits::UtxoBoxBytes> {
        let id = parse_box_id(box_id_hex)?;
        // Committed UTXO wins; reuse the store path (raw store bytes).
        if let Some(env) = self.utxo_box_bytes_by_id(box_id_hex) {
            return Some(env);
        }
        let snap = self.handle.load();
        let id_digest = Digest32::from_bytes(id);
        let pool_box = snap.pool_outputs.get(&id_digest)?;
        // No verbatim wire bytes survive parsing for whole boxes (the
        // parser only preserves register hex on `ErgoBoxCandidate`).
        // Re-serialize via `write_ergo_box` — round-trip through this
        // writer is byte-equal for any box that came in off the wire,
        // since `write_ergo_box_candidate` re-emits the preserved
        // `register_bytes` and `ergo_tree_bytes` verbatim.
        let mut w = VlqWriter::with_capacity(256);
        if let Err(e) = ergo_ser::ergo_box::write_ergo_box(&mut w, pool_box) {
            warn!(handler = "utxo_with_pool_box_bytes_by_id", box_id = %box_id_hex, error = %e, "scala-compat serialize failed");
            return None;
        }
        Some(ergo_api::compat::traits::UtxoBoxBytes {
            box_id: hex::encode(id),
            bytes: hex::encode(w.result()),
        })
    }

    fn utxo_with_pool_boxes_by_ids(&self, box_ids_hex: &[String]) -> Vec<ScalaOutput> {
        // Scala's `flatMap` drops both malformed-hex ids and unknown ids;
        // we mirror by routing each id through the single-id overlay.
        box_ids_hex
            .iter()
            .filter_map(|id| self.utxo_with_pool_box_by_id(id))
            .collect()
    }
}

/// Project an internal `ApiPeer` (operator-surface DTO) into the Scala
/// `Peer` shape. The internal `state` value `"active"` corresponds to
/// Scala's `Connected`; the connection-type capitalization differs
/// between the two surfaces and must be re-mapped here.
///
/// `lastSeen` is approximated as `unix_now_ms() - last_seen_seconds * 1000`.
/// This drifts from the true value by at most the snapshot age (sub-second
/// in practice). Tightening this would require carrying an absolute
/// `last_seen_unix_ms` on `ApiPeer`, which we can do later if a client
/// needs sharper than ~1s precision.
/// Parse pool tx bytes (preserved canonical wire form) into the
/// Scala `ScalaTransaction` DTO. Returns `None` when the bytes
/// fail to round-trip — keeps the live-node surface lossy-skip
/// matching Scala's `flatMap(getById)` semantics rather than
/// surfacing 500 on a single bad entry.
fn pool_bytes_to_scala_tx(bytes: &[u8]) -> Option<ergo_api::compat::types::ScalaTransaction> {
    let mut r = ergo_primitives::reader::VlqReader::new(bytes);
    let tx = ergo_ser::transaction::read_transaction(&mut r).ok()?;
    crate::api_bridge::compat::encode_transaction(&tx).ok()
}

/// Parse a pool tx's wire bytes into the internal `Transaction`
/// without re-encoding to `ScalaTransaction`. Used by the indexed
/// mempool-overlay queries (`pool_txs_by_ergo_tree` /
/// `pool_txs_by_box_id` / `pool_txs_by_token_id` /
/// `pool_txs_by_registers`) where the bridge needs to inspect the
/// parsed shape and only then decide whether to encode the
/// matched tx into the response array.
fn parse_pool_tx(bytes: &[u8]) -> Option<ergo_ser::transaction::Transaction> {
    let mut r = ergo_primitives::reader::VlqReader::new(bytes);
    ergo_ser::transaction::read_transaction(&mut r).ok()
}

#[cfg(test)]
mod bin_for_wait_ms_tests {
    use super::*;

    /// Pin the bin formula for the non-divisible case
    /// (`maxtime % bins != 0`). For `bins=3, maxtime=100`, the
    /// OpenAPI bin definition is
    /// `[0,33.33), [33.33,66.66), [66.66,100)`. Pre-dividing
    /// `maxtime/bins = 33` and then `wait/33` for `wait=66` would
    /// return 2 (wrong); `wait*bins/maxtime` returns 1 (correct).
    #[test]
    fn bin_formula_handles_non_divisible_maxtime() {
        // Edges and interior of each bin under bins=3 / maxtime=100.
        assert_eq!(bin_for_wait_ms(0, 3, 100), 0);
        assert_eq!(bin_for_wait_ms(33, 3, 100), 0); // 33 * 3 / 100 = 0
        assert_eq!(bin_for_wait_ms(34, 3, 100), 1); // 34 * 3 / 100 = 1
        assert_eq!(bin_for_wait_ms(66, 3, 100), 1); // 66 * 3 / 100 = 1 (NOT 2)
        assert_eq!(bin_for_wait_ms(67, 3, 100), 2); // 67 * 3 / 100 = 2
        assert_eq!(bin_for_wait_ms(99, 3, 100), 2);
        // Overflow bin: wait >= maxtime
        assert_eq!(bin_for_wait_ms(100, 3, 100), 3);
        assert_eq!(bin_for_wait_ms(200, 3, 100), 3);
        // maxtime=0 short-circuits to overflow bin
        assert_eq!(bin_for_wait_ms(0, 3, 0), 3);
    }

    /// Pin the OpenAPI defaults (bins=10, maxtime=60000ms = 60s).
    /// Each bin is exactly 6000 ms wide; no rounding wrinkle.
    #[test]
    fn bin_formula_default_window_is_evenly_divisible() {
        assert_eq!(bin_for_wait_ms(0, 10, 60_000), 0);
        assert_eq!(bin_for_wait_ms(5_999, 10, 60_000), 0);
        assert_eq!(bin_for_wait_ms(6_000, 10, 60_000), 1);
        assert_eq!(bin_for_wait_ms(59_999, 10, 60_000), 9);
        assert_eq!(bin_for_wait_ms(60_000, 10, 60_000), 10); // overflow
    }

    /// Adversarial case where `wait_ms * bins` would overflow u64.
    /// A u64 `saturating_mul` would clamp to `u64::MAX` and produce
    /// wrong bin indices for these inputs; the u128 widening
    /// computes the spec-exact result.
    ///
    /// Test case: `wait = u64::MAX - 2`, `maxtime = u64::MAX - 1`,
    /// `bins = 3`. Spec formula `floor(wait * bins / maxtime)` =
    /// `floor(((u64::MAX - 2) * 3) / (u64::MAX - 1))`. With u128
    /// widening: numerator ≈ 3 * (u64::MAX - 2), divided by
    /// (u64::MAX - 1) gives 2 (the correct bin). A u64
    /// `saturating_mul` would give 1.
    #[test]
    fn bin_formula_handles_overflow_via_u128_widening() {
        let big_wait = u64::MAX - 2;
        let big_max = u64::MAX - 1;
        assert_eq!(bin_for_wait_ms(big_wait, 3, big_max), 2);
        // Sanity: smaller variant that does NOT overflow u64.
        // wait = 998, max = 1000, bins = 3 → floor(998*3/1000) = 2.
        assert_eq!(bin_for_wait_ms(998, 3, 1000), 2);
    }
}

// =====================================================================
// Fee-stats helpers
// =====================================================================
//
// `poolHistogram` / `getFee` / `waitTime` all depend on a per-tx
// fee-per-byte ranking of the current pool. The helpers below build
// that ranking from a snapshot's `pool_full_txs` in a single pass.
// `bins` and `maxtime` are caller-supplied (OpenAPI defaults
// `10` / `60000`), so they aren't constants here.

/// `[proposed]` Assumed block time used to convert fee-rank to a
/// wait estimate. Ergo's mainnet target is 120 s; constant because
/// per-block-time observability is not on the snapshot. Operators
/// on testnet/devnet with different timing will see proportionally
/// scaled estimates — acceptable for a hint API.
const BLOCK_TIME_MS: u64 = 120_000;

/// `[proposed]` Assumed transactions-per-block divisor for the
/// fee-rank → wait-time conversion. Mainnet block size ~512 KB; a
/// typical tx is ~1 KB → roughly 500 txs/fully-packed block. Real
/// fill rate varies wildly — stand-in until the snapshot carries
/// recent-block-fill data.
const TX_PER_BLOCK: u64 = 500;

/// Server-side cap on the `bins` query parameter for
/// `/transactions/poolHistogram`. Larger requests are silently
/// clamped (caller still gets a valid histogram, just shorter
/// than asked). OpenAPI sets no maximum, but unbounded allocation
/// on a path that's reachable without auth is a DoS surface.
/// 4096 is well beyond any operator-tooling visualization need
/// (Scala node defaults to 10).
const MAX_HISTOGRAM_BINS: usize = 4096;

#[derive(Clone, Copy)]
struct PoolFeeEntry {
    fee: u64,
    fee_per_byte: u64,
}

/// Build a fee-per-byte descending ranking of every pool tx in the
/// snapshot. Parse-failures and zero-fee txs are dropped (a tx
/// with no fee output cannot land via the normal admission path —
/// Scala mempool rejects them upstream).
///
/// Tie-break: pool entries with equal `fee_per_byte` retain the
/// order `pool_full_txs` gives us, which is `Mempool::iter_transactions`
/// in relay-priority order (`ergo-mempool::pool::iter_transactions`).
/// Under the default `cost`-based weighting that means
/// weight-then-tx-id ordering, NOT insertion order. The exact
/// tie-break only matters for the rank-position assignment when
/// many pool txs sit at the same fee/byte tier — the histogram and
/// fee-suggestion results are insensitive to it because the
/// downstream `(rank / TX_PER_BLOCK) * BLOCK_TIME_MS` bucketing
/// rounds away the individual positions.
fn rank_pool_by_fee_per_byte(
    pool: &[(ergo_primitives::digest::Digest32, std::sync::Arc<[u8]>)],
) -> Vec<PoolFeeEntry> {
    let mut entries: Vec<PoolFeeEntry> = pool
        .iter()
        .filter_map(|(_, bytes)| {
            let tx = parse_pool_tx(bytes)?;
            let fee: u64 = tx
                .output_candidates
                .iter()
                .filter(|c| {
                    c.ergo_tree_bytes() == ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES
                })
                .map(|c| c.value)
                .sum();
            if fee == 0 {
                return None;
            }
            let size = bytes.len() as u64;
            if size == 0 {
                return None;
            }
            Some(PoolFeeEntry {
                fee,
                fee_per_byte: fee / size,
            })
        })
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.fee_per_byte));
    entries
}

fn estimate_wait_ms_from_rank(rank: u64) -> u64 {
    (rank / TX_PER_BLOCK).saturating_mul(BLOCK_TIME_MS)
}

fn bin_for_wait_ms(wait_ms: u64, bins: usize, maxtime_ms: u64) -> usize {
    if maxtime_ms == 0 || wait_ms >= maxtime_ms {
        return bins;
    }
    // Bin formula straight from the OpenAPI spec:
    //   bin_i = [i*maxtime/bins, (i+1)*maxtime/bins)
    // Inverted to find the bin for a given wait:
    //   i = wait * bins / maxtime
    // Compute as `wait * bins` BEFORE dividing by `maxtime` so the
    // formula is exact for non-divisible (`maxtime % bins != 0`)
    // cases. `u64::MAX * u64::MAX` overflows u64; widen to u128 to
    // keep the spec result correct on any 64-bit input.
    let widened = (wait_ms as u128) * (bins as u128) / (maxtime_ms as u128);
    // The pre-check `wait_ms < maxtime_ms` guarantees `widened < bins`
    // when bins fits in usize, but clamp anyway to keep the index
    // safe under hypothetical input combinations the type system
    // can't rule out (e.g. `bins == usize::MAX` on a 32-bit target).
    let idx = widened.min(usize::MAX as u128) as usize;
    idx.min(bins.saturating_sub(1))
}

fn project_scala_peer(p: &ergo_api::types::ApiPeer) -> ScalaPeer {
    let connection_type = match p.direction {
        ergo_api::types::ApiPeerDirection::Inbound => Some("Incoming".to_string()),
        ergo_api::types::ApiPeerDirection::Outbound => Some("Outgoing".to_string()),
    };
    let last_seen = unix_now_ms().saturating_sub(p.last_seen_seconds.saturating_mul(1000));
    ScalaPeer {
        address: p.addr.clone(),
        // Our peer-info table doesn't track restApiUrl for remote peers
        // (Scala learns this via the handshake's `peerSpec.restApiUrl`,
        // which our handshake parser doesn't currently retain). Always
        // null until that field is plumbed.
        rest_api_url: None,
        name: p.node_name.clone(),
        last_seen,
        connection_type,
    }
}

fn parse_header_id(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Diff a `voted_params` history (ascending by epoch-start height) into the
/// parameter-change timeline. Pure — the bridge supplies the rows from the
/// store, keeping the diff independently testable. `rows[0]` is the genesis
/// row, which has no predecessor and is never diffed. Only boundaries where at
/// least one parameter actually changed produce an event.
pub(super) fn build_votes_history(
    rows: &[ergo_validation::ActiveProtocolParameters],
    epoch_length: u32,
    current_height: u32,
) -> ergo_api::types::ApiVotesHistory {
    use ergo_validation::voting::votable_param_descriptors;

    let mut changes = Vec::new();
    let mut prev: Option<&ergo_validation::ActiveProtocolParameters> = None;
    for row in rows {
        if let Some(p) = prev {
            let prev_vals: std::collections::BTreeMap<u8, i32> = votable_param_descriptors(p)
                .into_iter()
                .map(|d| (d.id, d.current))
                .collect();
            let mut params = Vec::new();
            for d in votable_param_descriptors(row) {
                let from = prev_vals.get(&d.id).copied();
                if from != Some(d.current) {
                    params.push(ergo_api::types::ApiParamChange {
                        id: d.id,
                        name: d.name.to_string(),
                        description: d.description.to_string(),
                        from: from.map(|v| v as i64),
                        to: d.current as i64,
                    });
                }
            }
            // blockVersion (123): advanced by soft-fork activation, not a
            // numeric parameter vote, but it IS a governance event worth
            // showing (e.g. the v3 → v4 transition).
            if p.block_version != row.block_version {
                params.push(ergo_api::types::ApiParamChange {
                    id: 123,
                    name: "blockVersion".to_string(),
                    description: "Block format version — advanced by soft-fork \
                                  activation, not a numeric parameter vote."
                        .to_string(),
                    from: Some(p.block_version as i64),
                    to: row.block_version as i64,
                });
            }
            if !params.is_empty() {
                params.sort_by_key(|c| c.id);
                changes.push(ergo_api::types::ApiVoteChangeEvent {
                    height: row.epoch_start_height,
                    params,
                });
            }
        }
        prev = Some(row);
    }

    ergo_api::types::ApiVotesHistory {
        epoch_length,
        current_height,
        changes,
    }
}

/// Same shape as [`parse_header_id`] — both ids are 32-byte blake2b256
/// digests rendered as 64-char unprefixed lowercase hex. Kept as a
/// separate name so call sites at the trait boundary read by intent.
fn parse_box_id(s: &str) -> Option<[u8; 32]> {
    parse_header_id(s)
}

/// Build a `ScalaOutput` from the canonical box bytes the store returned.
///
/// `additionalRegisters` hex is sliced from `candidate.register_bytes()`
/// (verbatim wire bytes preserved by the parser), not re-serialized.
/// The returned `boxId` is the precomputed `id` parameter — the caller
/// already used it as the lookup key, so we don't pay another
/// blake2b256 over the bytes here.
pub(super) fn encode_scala_output_from_raw(
    raw: &[u8],
    id: &[u8; 32],
) -> Result<ScalaOutput, BridgeError> {
    let mut r = VlqReader::new(raw);
    let parsed = read_ergo_box(&mut r).map_err(|source| BridgeError::Parse {
        what: "ergo_box",
        source,
    })?;
    if !r.is_empty() {
        return Err(BridgeError::LeftoverBytes {
            what: "ergo_box",
            remaining: r.remaining(),
        });
    }
    encode_output(
        &parsed.candidate,
        hex::encode(id),
        hex::encode(parsed.transaction_id.as_bytes()),
        parsed.index,
    )
}

#[cfg(test)]
mod votes_history_tests {
    use super::build_votes_history;
    use ergo_validation::scala_launch;

    /// Only boundaries where a parameter actually changed appear, each decoded
    /// (id/name/description) with the correct from→to, ascending by height.
    #[test]
    fn build_votes_history_reports_only_changed_boundaries_with_decoded_deltas() {
        let genesis = scala_launch(); // height 0 (no predecessor → never diffed)
        let mut e1 = scala_launch();
        e1.epoch_start_height = 1024; // identical to genesis → no event

        let mut e2 = scala_launch();
        e2.epoch_start_height = 2048;
        e2.storage_fee_factor = genesis.storage_fee_factor + 25_000; // id 1 changes

        let mut e3 = scala_launch();
        e3.epoch_start_height = 3072; // identical to e2 → no event
        e3.storage_fee_factor = e2.storage_fee_factor;

        let mut e4 = scala_launch();
        e4.epoch_start_height = 4096;
        e4.storage_fee_factor = e2.storage_fee_factor;
        e4.block_version = genesis.block_version + 1; // blockVersion fork event

        let rows = vec![genesis.clone(), e1, e2.clone(), e3, e4];
        let h = build_votes_history(&rows, 1024, 4096);

        assert_eq!(h.epoch_length, 1024);
        assert_eq!(h.current_height, 4096);
        assert_eq!(h.changes.len(), 2, "only 2048 and 4096 changed");

        let at_2048 = &h.changes[0];
        assert_eq!(at_2048.height, 2048);
        assert_eq!(at_2048.params.len(), 1);
        let sff = &at_2048.params[0];
        assert_eq!(sff.id, 1);
        assert_eq!(sff.name, "storageFeeFactor");
        assert_eq!(sff.from, Some(genesis.storage_fee_factor as i64));
        assert_eq!(sff.to, e2.storage_fee_factor as i64);
        assert!(!sff.description.is_empty());

        let at_4096 = &h.changes[1];
        assert_eq!(at_4096.height, 4096);
        assert_eq!(at_4096.params.len(), 1);
        assert_eq!(at_4096.params[0].id, 123);
        assert_eq!(at_4096.params[0].name, "blockVersion");
        assert_eq!(at_4096.params[0].from, Some(genesis.block_version as i64));
        assert_eq!(at_4096.params[0].to, (genesis.block_version + 1) as i64);
    }

    #[test]
    fn build_votes_history_empty_when_only_genesis() {
        let h = build_votes_history(&[scala_launch()], 1024, 0);
        assert!(h.changes.is_empty());
    }
}
