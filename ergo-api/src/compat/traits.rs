//! Live-read trait the node implements for the Scala-compat surface.
//!
//! Distinct from `NodeReadState` — that one is purely snapshot-driven and
//! cannot serve id-keyed lookups (block by id, utxo by id, tx by id). The
//! parity surface needs both: snapshot reads for tip/peer counts, plus
//! live store reads for content. Implementations are expected to be cheap
//! per call; handlers do not coordinate with the node's main loop.

use crate::compat::types::{
    ScalaBlacklistedPeers, ScalaBlockSection, ScalaBlockTransactions, ScalaFullBlock, ScalaHeader,
    ScalaInfo, ScalaMerkleProof, ScalaOutput, ScalaPeer, ScalaPeersStatus, ScalaSyncInfoEntry,
    ScalaTrackInfo, ScalaTransaction,
};

pub trait NodeChainQuery: Send + Sync {
    /// `/info` — node identity, tip pointers, peer/mempool counts,
    /// protocol parameters. Volatile fields may differ slightly from the
    /// instant a client polls; stable fields are config-derived and do
    /// not change after boot.
    fn info(&self) -> ScalaInfo;

    /// `GET /api/v1/votes/history` — the protocol-parameter change timeline,
    /// reconstructed from the node's stored per-epoch parameter rows. Native
    /// (`/api/v1/*`), not a Scala route, but it rides this store-backed trait
    /// because the history comes from `voted_params`, not the snapshot.
    /// Default empty for bridges without a chain store.
    fn votes_history(&self) -> crate::types::ApiVotesHistory {
        crate::types::ApiVotesHistory::default()
    }

    /// `/blocks/at/{height}` — header IDs at a given height.
    ///
    /// Scala's `history.headerIdsAtHeight(h)` returns `Seq[ModifierId]`,
    /// allowing more than one entry per height if forks were observed at
    /// that height. Whether it includes long-discarded orphans is
    /// unverified; in steady state on a synced node the array is
    /// single-element. This implementation returns at most the canonical
    /// chain header — fork tracking is not yet indexed. Returns an empty
    /// vec if the height is past the tip or no chain has been written.
    fn header_ids_at_height(&self, height: u32) -> Vec<String>;

    /// `(height, hex manifest id)` of the locally-served UTXO snapshot
    /// set — Scala `UtxoSetSnapshotPersistence.getSnapshotInfo()`, which
    /// backs BOTH the REST `/utxo/getSnapshotsInfo` route and the P2P
    /// `SnapshotsInfo` reply, so the two views can never disagree. This
    /// build holds at most one entry (the latest 52,224-boundary serve
    /// cache; in-memory only, so empty at boot). Default empty for
    /// bridges without a snapshot view.
    fn snapshots_info(&self) -> Vec<(i32, String)> {
        Vec::new()
    }

    /// `/blocks/{header_id}` — full block reassembly.
    ///
    /// `header_id_hex` is an unprefixed lowercase 64-char hex string; the
    /// implementation is responsible for hex-decoding and treating malformed
    /// or unknown ids as `None`. Returns `None` when any required section
    /// (header, blockTransactions, extension) is missing — partial blocks
    /// must not be served. `adProofs` is `Option`-typed inside the DTO so
    /// pruned/non-archive nodes can still serve the wrapper with
    /// `adProofs: null`.
    fn full_block_by_id(&self, header_id_hex: &str) -> Option<ScalaFullBlock>;

    /// `POST /blocks/headerIds` — bulk full-block fetch.
    ///
    /// Mirrors Scala's `getFullBlockByHeaderIds`
    /// (`BlocksApiRoute.scala:70-73`): `flatMap` filters out missing ids
    /// silently, preserving request order for the ones that do resolve.
    /// Hex parsing happens upstream in the handler (see V4 verification:
    /// any malformed id fails the whole request with 400 at the directive
    /// layer); this trait method only sees pre-validated hex strings.
    /// Default delegates to `full_block_by_id` per id; bridges may override
    /// for batched lookups when redb txn reuse becomes worth it.
    fn full_blocks_by_header_ids(&self, header_id_hexes: &[String]) -> Vec<ScalaFullBlock> {
        header_id_hexes
            .iter()
            .filter_map(|id| self.full_block_by_id(id))
            .collect()
    }

    /// `/blocks/{header_id}/header` — single header DTO. Same id-parse and
    /// not-found semantics as `full_block_by_id`. The Scala emission shape
    /// is identical to the `header` field inside a full block.
    ///
    /// Default impl returns `None` so test stubs that only care about a
    /// subset of the surface need not opt in; production bridges override.
    fn header_by_id(&self, _header_id_hex: &str) -> Option<ScalaHeader> {
        None
    }

    /// `/blocks/{header_id}/transactions` — block-transactions section
    /// DTO. Returns `None` if the header itself is unknown OR the
    /// transactions section has not been downloaded yet (Scala emits 404
    /// in either case).
    fn block_transactions_by_id(&self, _header_id_hex: &str) -> Option<ScalaBlockTransactions> {
        None
    }

    /// `/blocks/{headerId}/proofFor/{txId}` — Merkle membership proof
    /// for a transaction in a block. Mirrors Scala's `getProofForTx`
    /// (`BlocksApiRoute.scala:78-91`):
    /// 1. Load the header. If unknown → `None` (handler 404).
    /// 2. Compute `blockTxsId = NonHeaderBlockSection.computeId(102,
    ///    headerId, header.transactionsRoot)`.
    /// 3. Load block transactions section. If pruned → `None`.
    /// 4. Find tx_id index in `txIds`. If not in block → `None`.
    /// 5. Build proof against the leaf array
    ///    (v1: `txIds`; v2+: `txIds ++ witnessIds`).
    fn proof_for_tx(&self, _header_id_hex: &str, _tx_id_hex: &str) -> Option<ScalaMerkleProof> {
        None
    }

    /// `/blocks/modifier/{modifierId}` — generic-by-id lookup spanning
    /// headers and the three non-header block sections. Mirrors Scala's
    /// `getModifierById` (`BlocksApiRoute.scala:75-76`,
    /// `HistoryStorage.scala:79-90`,
    /// `HistoryModifierSerializer.scala:30-43`). The implementation
    /// dispatches via `MODIFIER_TYPE_INDEX` populated at write time +
    /// boot-time back-fill, then routes to the variant's existing
    /// per-type encoder. Returns `None` for unknown ids — the handler
    /// converts `None` to 404 (V3 verification:
    /// `ApiResponse.scala:30-31`).
    fn modifier_by_id(&self, _modifier_id_hex: &str) -> Option<ScalaBlockSection> {
        None
    }

    /// `/blocks/lastHeaders/{count}` — last `count` headers from the
    /// canonical best-header chain, ascending heights. If the chain has
    /// fewer than `count` headers, the returned vec is shorter.
    fn last_headers(&self, _count: u32) -> Vec<ScalaHeader> {
        Vec::new()
    }

    /// `/blocks/chainSlice?fromHeight=&toHeight=` — replicates Scala's
    /// `getChainSlice` (`BlocksApiRoute.scala:93-109`), which uses
    /// `headerChainBack(MaxHeaders, top, _.height <= fromHeight + 1)`.
    ///
    /// Semantic notes (per `HeadersProcessor.scala:280-307`, doc explicitly
    /// says "it includes one header satisfying until condition"):
    /// - `top` = header at `to_height` if that height is in our chain,
    ///   otherwise the current tip (matches Scala's
    ///   `headerIdsAtHeight(toHeight).headOption.flatMap(typedModifierById).orElse(bestHeaderOpt)`).
    /// - Output is ascending, **always includes the header at `top`**.
    /// - When `top > from_height + 1`, the lowest height returned is
    ///   `from_height + 1` — `from_height` itself is **excluded** (this
    ///   off-by-one is in Scala; preserve it for parity).
    /// - Output is capped at 16384 entries walking back from `top`.
    /// - `to_height` semantics for "use tip": pass `u32::MAX` (handler
    ///   maps Scala's `-1` to that sentinel; the bridge's chain-index
    ///   miss falls back to tip, identical to Scala).
    fn chain_slice(&self, _from_height: u32, _to_height: u32) -> Vec<ScalaHeader> {
        Vec::new()
    }

    /// `/blocks?limit=&offset=` — Scala's `headerIdsAt(offset, limit)`
    /// (`ErgoHistoryReader.scala:423-425`):
    /// `(offset until (limit + offset)).flatMap(bestHeaderIdAtHeight)`.
    ///
    /// `offset` is a **start height**, not "skip from tip". Returns
    /// ascending header IDs over heights `[offset, offset + limit)`,
    /// silently dropping heights with no header (e.g. past the tip,
    /// or the impossible `height = 0`). Validation of `offset >= 0`,
    /// `limit >= 0`, `limit <= 16384` happens in the handler.
    fn header_ids_paged(&self, _limit: u32, _offset: u32) -> Vec<String> {
        Vec::new()
    }

    /// `/peers/all` — every peer the node currently tracks (any state).
    /// Parity gap to flag: Scala's `getAllPeers` includes address-book
    /// entries for peers it has merely *learned about* (gossip, seed
    /// list) without ever connecting; we emit only what's in the live
    /// `PeerManager` table. Closing this gap requires an address-book
    /// projection in the snapshot.
    fn peers_all(&self) -> Vec<ScalaPeer> {
        Vec::new()
    }

    /// `/peers/connected` — peers with a live, handshake-complete
    /// connection. Implementations should mirror Scala's `Connected`
    /// notion (post-handshake), not "TCP socket open".
    fn peers_connected(&self) -> Vec<ScalaPeer> {
        Vec::new()
    }

    /// `/peers/blacklisted` — `{"addresses": [...]}` envelope.
    /// Each entry mirrors Java `InetAddress.toString()` output
    /// (form: `hostname/literal-ip` or `/literal-ip` when no
    /// hostname bound). NOT bare IPs — see `ScalaBlacklistedPeers`
    /// doc for the byte-parity rationale. Default returns an
    /// empty envelope so bridges without blacklist exposure
    /// don't break their handler. Scala source:
    /// `ErgoPeersApiRoute.scala:98-102`.
    fn peers_blacklisted(&self) -> ScalaBlacklistedPeers {
        ScalaBlacklistedPeers {
            addresses: Vec::new(),
        }
    }

    /// `/peers/syncInfo` — per-peer sync state, projected from the
    /// most recent SyncInfo classification (Equal/Younger/Older/
    /// Fork/Unknown/Nonsense) per peer. Production bridges back
    /// this from a `SyncCoordinator::peer_sync_snapshots()`
    /// projection on the `ApiState` snapshot; default empty so
    /// bridges without sync-coord access don't break their handler.
    /// Scala source: `ErgoPeersApiRoute.scala:36-38`.
    fn peers_sync_info(&self) -> Vec<ScalaSyncInfoEntry> {
        Vec::new()
    }

    /// `/peers/trackInfo` — aggregate delivery-tracker counters
    /// `{numRequested, numReceived, numFailed}`. Production
    /// bridges populate from `DeliveryTracker::total_inflight()`
    /// / `received_count()` / `failed_count()` on the
    /// snapshot; default zeros. Scala source:
    /// `ErgoPeersApiRoute.scala:40-42`.
    fn peers_track_info(&self) -> ScalaTrackInfo {
        ScalaTrackInfo {
            num_requested: 0,
            num_received: 0,
            num_failed: 0,
        }
    }

    /// `/peers/status` — P2P-layer freshness probe. Scala returns
    /// `{lastIncomingMessage, currentSystemTime}` both in unix-ms.
    /// `lastIncomingMessage` is the wall-clock timestamp of the
    /// most recent peer message handled; `currentSystemTime` is
    /// the node's clock at response time. Default returns zeros
    /// for bridges without freshness instrumentation. Scala source:
    /// `ErgoPeersApiRoute.scala:76-82`.
    fn peers_status(&self) -> ScalaPeersStatus {
        ScalaPeersStatus {
            last_incoming_message: 0,
            current_system_time: 0,
        }
    }

    /// `/transactions/unconfirmed/transactionIds` — array of pooled tx
    /// id hex strings. Order is implementation-defined; Scala iterates
    /// the pool in priority order.
    fn pool_tx_ids(&self) -> Vec<String> {
        Vec::new()
    }

    /// `HEAD /transactions/unconfirmed/{txId}` — true iff the pool has
    /// `tx_id_hex`. The handler turns the bool into 200 / 404 with no
    /// body, per Scala.
    fn pool_contains(&self, _tx_id_hex: &str) -> bool {
        false
    }

    /// `GET /transactions/unconfirmed?offset=&limit=` — paged list of
    /// full unconfirmed transactions. Scala iterates the pool in
    /// priority order (`MempoolReader.getAll`); the bridge should
    /// honour the same ordering when wiring this trait method.
    /// Default returns empty so legacy bridges (only implementing
    /// `pool_tx_ids`) don't break their handlers.
    fn pool_txs_paged(&self, _offset: u32, _limit: u32) -> Vec<ScalaTransaction> {
        Vec::new()
    }

    /// `GET /transactions/unconfirmed/byTransactionId/{txId}` — full
    /// `ScalaTransaction` envelope for a single pooled tx. `None` →
    /// 404 with the standard `ApiError` envelope.
    fn pool_tx_by_id(&self, _tx_id_hex: &str) -> Option<ScalaTransaction> {
        None
    }

    /// `POST /transactions/unconfirmed/byTransactionIds` — batch
    /// lookup; returns only the txs that resolved (Scala
    /// `flatMap(getById)` semantics). Always 200 with a (possibly
    /// empty) JSON array; ids that don't resolve or fail hex parse
    /// are silently skipped.
    fn pool_txs_by_ids(&self, _tx_ids_hex: &[String]) -> Vec<ScalaTransaction> {
        Vec::new()
    }

    /// `GET /transactions/unconfirmed/size` — current pool size as a
    /// JSON integer. Scala returns it bare (`ApiResponse(mempool.size)`).
    fn pool_size(&self) -> u32 {
        0
    }

    /// `POST /transactions/unconfirmed/byErgoTree` — pool txs whose
    /// outputs include a box paying to the supplied ergoTree.
    ///
    /// `tree_bytes` is the canonical ergoTree wire form (the result of
    /// `Base16.decode` on the request body's hex string — the handler
    /// owns the hex parse and surfaces 400 on bad hex). Matching is
    /// byte-equality between `tree_bytes` and each output's stored
    /// `ergo_tree_bytes`, which is what Scala's `MempoolReader` does
    /// after hashing both sides to a 32-byte `tree_hash` (the hashing
    /// step is an optimization for the indexer-side path; for the
    /// mempool overlay the pool is small enough that direct byte
    /// equality is cheaper than per-tree blake2b256).
    ///
    /// Always 200 with a (possibly empty) JSON array; no pagination
    /// (matches Scala's bare-list response for this endpoint). Order
    /// follows the mempool's priority iteration.
    fn pool_txs_by_ergo_tree(&self, _tree_bytes: &[u8]) -> Vec<ScalaTransaction> {
        Vec::new()
    }

    /// `POST /transactions/unconfirmed/byBoxId` — pool txs that
    /// spend the supplied 32-byte box id (input side). The handler
    /// owns the hex+length validation; this method receives the
    /// already-decoded id.
    ///
    /// Match scope: only `tx.inputs[i].box_id == box_id`. Pool tx
    /// outputs are NOT matched against `box_id` because output box
    /// ids are derived deterministically from `(tx_id, output_index)`
    /// and a caller looking for "this box's existence" would query
    /// `/utxo/byId/{boxId}` for confirmed state. Scala's mempool
    /// reader uses the same input-side scoping.
    fn pool_txs_by_box_id(&self, _box_id: &[u8; 32]) -> Vec<ScalaTransaction> {
        Vec::new()
    }

    /// `POST /transactions/unconfirmed/byTokenId` — pool txs that
    /// reference the supplied 32-byte token id in any output's
    /// `tokens` list. Bridge implementations should NOT chase
    /// input-box token contents (would require UTXO lookup per
    /// input — too expensive for a pool overlay); the output-only
    /// match matches Scala's `MempoolReader.getTransactionsByTokenId`
    /// scope.
    fn pool_txs_by_token_id(&self, _token_id: &[u8; 32]) -> Vec<ScalaTransaction> {
        Vec::new()
    }

    /// `POST /transactions/unconfirmed/byRegisters` — pool txs with
    /// at least one output whose `additionalRegisters` contains
    /// every (name, hex-bytes) pair in `registers`.
    ///
    /// Register names are `R4..R9`; values are the canonical
    /// register-byte hex Scala emits for `additionalRegisters` on
    /// `ScalaOutput`. The handler passes the request map through
    /// verbatim; bridge implementations are responsible for
    /// canonicalizing both sides (parsing the request hex, parsing
    /// each output's `register_bytes` slice).
    fn pool_txs_by_registers(
        &self,
        _registers: &std::collections::BTreeMap<String, String>,
    ) -> Vec<ScalaTransaction> {
        Vec::new()
    }

    /// `GET /transactions/poolHistogram?bins=&maxtime=` — wait-time
    /// histogram of the current mempool. The returned vec has
    /// `bins + 1` entries; bin `i` (`0..bins`) covers wait times
    /// in `[i*maxtime_ms/bins, (i+1)*maxtime_ms/bins)` and the
    /// last entry covers `>= maxtime_ms`. OpenAPI defaults:
    /// `bins = 10`, `maxtime = 60000` ms (1 minute).
    ///
    /// Per-tx wait-time estimate: bridge ranks pool txs by
    /// fee-per-byte descending; tx at rank `r` has estimated
    /// wait `(r / TX_PER_BLOCK) * BLOCK_TIME_MS`. Fee is the sum
    /// of output values paying to the canonical fee proposition
    /// (matches `ergo-mempool::validator`).
    fn pool_fee_histogram(
        &self,
        _bins: u32,
        _maxtime_ms: u64,
    ) -> Vec<crate::compat::types::ScalaFeeHistogramBin> {
        Vec::new()
    }

    /// `GET /transactions/getFee?waitTime=<minutes>&txSize=<bytes>` —
    /// recommended fee in nanoErgs to land within `wait_time_minutes`.
    /// Default impl returns the protocol minimum fee for a tx of
    /// `tx_size_bytes` (matches Scala's `feeFromBuckets` floor when
    /// the pool is empty / smaller than the buckets account for).
    fn pool_recommended_fee(&self, _wait_time_minutes: u32, _tx_size_bytes: u32) -> u64 {
        0
    }

    /// `GET /transactions/waitTime?fee=<nanoErgs>&txSize=<bytes>` —
    /// expected wait in milliseconds for a tx with the given
    /// `fee` and `tx_size_bytes`. Default impl returns 0 (immediate)
    /// when the pool is empty.
    fn pool_expected_wait_time_ms(&self, _fee: u64, _tx_size_bytes: u32) -> u64 {
        0
    }

    /// `/utxo/byId/{boxId}` — single UTXO by id. Returns `None` for
    /// unknown ids and for malformed-hex ids; the handler emits 404 in
    /// either case to match Scala's `ApiResponse(Option)` semantics
    /// (`UtxoApiRoute.scala:65-71`).
    ///
    /// The DTO's register hex is sliced from the raw box bytes preserved
    /// by the parser, so output matches what was originally serialized
    /// into the AVL tree.
    fn utxo_box_by_id(&self, _box_id_hex: &str) -> Option<ScalaOutput> {
        None
    }

    /// `/utxo/byIdBinary/{boxId}` — `{boxId, bytes}` envelope, where
    /// `bytes` is the hex of the canonical box serialization. `None`
    /// rules match `utxo_box_by_id` (`UtxoApiRoute.scala:73-85`). The
    /// returned hex is the raw bytes from the store, not a re-serialized
    /// copy.
    fn utxo_box_bytes_by_id(&self, _box_id_hex: &str) -> Option<UtxoBoxBytes> {
        None
    }

    /// `/utxo/genesis` — the three genesis state boxes (`emission`,
    /// `no-premine`, `founders`). Scala's `genesis` route returns a
    /// non-Optional `Seq[ErgoBox]` (`UtxoApiRoute.scala:87-89`,
    /// `ErgoState.scala:262-264`), so the handler always emits 200.
    fn utxo_genesis_boxes(&self) -> Vec<ScalaOutput> {
        Vec::new()
    }

    /// `/utxo/withPool/byId/{boxId}` — single UTXO with mempool overlay.
    /// Scala's `usr.withMempool(mp).boxById(...)` (`UtxoApiRoute.scala:33-39`,
    /// `UtxoStateReader.scala:164-172`) is purely additive: committed UTXOs
    /// are returned as-is and pool-created outputs supplement them. Pool
    /// inputs do **not** subtract from the committed view, so a UTXO
    /// being spent by a pool tx is still returned. Same `Option` semantics
    /// as `utxo_box_by_id` — `None` → 404 with the standard error envelope.
    fn utxo_with_pool_box_by_id(&self, _box_id_hex: &str) -> Option<ScalaOutput> {
        None
    }

    /// `/utxo/withPool/byIdBinary/{boxId}` — `{boxId, bytes}` envelope
    /// over the same overlay as `utxo_with_pool_box_by_id`. For committed
    /// UTXOs `bytes` is the store-preserved canonical box bytes; for
    /// pool-only outputs the bridge re-serializes via `write_ergo_box`
    /// (no preserved verbatim bytes exist for pool boxes — the parser
    /// only preserves register hex on `ErgoBoxCandidate`, not whole-box
    /// bytes). `None` rules match `utxo_box_bytes_by_id`
    /// (`UtxoApiRoute.scala:50-63`).
    fn utxo_with_pool_box_bytes_by_id(&self, _box_id_hex: &str) -> Option<UtxoBoxBytes> {
        None
    }

    /// `POST /utxo/withPool/byIds` — batch lookup with mempool overlay.
    /// Scala filters out misses (`flatMap` in `UtxoApiRoute.scala:41-48`),
    /// returning only the boxes that resolved. Same overlay rule as
    /// `utxo_with_pool_box_by_id`. Always 200 with a (possibly empty)
    /// JSON array; malformed-hex ids are skipped, matching the upstream
    /// `Base16.decode(id).get` failure mode (drops the id, no 400).
    fn utxo_with_pool_boxes_by_ids(&self, _box_ids_hex: &[String]) -> Vec<ScalaOutput> {
        Vec::new()
    }
}

/// `/utxo/byIdBinary` envelope: `{boxId, bytes}`. The `bytes` field is
/// the hex of the canonical box serialization, identical byte-for-byte
/// to what the store returned (no re-serialization).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UtxoBoxBytes {
    #[serde(rename = "boxId")]
    pub box_id: String,
    pub bytes: String,
}
