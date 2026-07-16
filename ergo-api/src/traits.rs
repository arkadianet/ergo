//! Read-state trait the node implements for the API server.
//!
//! Each call returns an owned, serializable DTO. Implementations are
//! expected to be snapshot reads — handlers may invoke them on every
//! request without coordination with the node's main loop.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ergo_indexer_types::{BoxId, TxId};
use ergo_ser::ergo_box::ErgoBox;

use crate::compat::types::{ScalaFullBlock, ScalaTransactionInput};
use crate::types::{
    ApiHealth, ApiHost, ApiIdentity, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiRecentBlock, ApiStatus, ApiSyncStatus, ApiTip, ApiVotes,
    SubmitError, SubmitMode,
};

/// Snapshot-read surface the node implements for the API server.
///
/// **Production-override contract.** Several methods below ship a default impl
/// that returns an empty / `Default` value. Those defaults exist *solely* so
/// the many test fixtures that implement this trait need not be updated every
/// time a read method is added — they are **not** a valid production shape. Any
/// operator-facing implementation MUST override every defaulted method: a
/// missing override compiles cleanly but then silently serves empty data on a
/// live endpoint (e.g. `GET /api/v1/votes`). The production `SnapshotReadState`
/// in `ergo-node` overrides all of them. When adding a method here, make it
/// required unless test fixtures genuinely never exercise the route.
pub trait NodeReadState: Send + Sync {
    fn info(&self) -> ApiInfo;
    fn status(&self) -> ApiStatus;
    fn tip(&self) -> ApiTip;
    fn sync(&self) -> ApiSyncStatus;
    fn peers(&self) -> Vec<ApiPeer>;
    fn mempool_summary(&self) -> ApiMempoolSummary;
    fn mempool_transactions(&self) -> ApiMempoolTransactions;
    /// Snapshot-read of one pooled tx by hex tx_id. `None` if absent
    /// from the snapshot. Backs `GET /api/v1/mempool/transactions/{tx_id}`.
    fn mempool_transaction(&self, tx_id_hex: &str) -> Option<ApiMempoolTransaction>;
    /// The active mempool priority-weight function (`cost` | `size` | `min`) —
    /// lifted onto `GET /api/v1/mempool/summary` + `fee-histogram`. The default
    /// reads it off the (already-materialized) `mempool_transactions()`
    /// envelope so no implementer must change; the production
    /// `SnapshotReadState` overrides with an O(1) snapshot field read.
    fn mempool_weight_function(&self) -> crate::types::ApiWeightFunction {
        self.mempool_transactions().weight_function
    }
    fn health(&self) -> ApiHealth;
    /// Captured at boot from `NodeConfig` + the hardcoded `Mode` peer-feature.
    /// Default impl returns an empty identity so test fixtures that don't
    /// care about it don't have to be updated; the production
    /// `SnapshotReadState` overrides this with real config-derived values.
    fn identity(&self) -> ApiIdentity {
        ApiIdentity::default()
    }
    /// Operator event feed (`GET /api/v1/events`) — the retained tail of the
    /// node-side bounded ring, projected into the snapshot each tick.
    /// Default impl returns the empty feed so the many test fixtures don't
    /// break; production `SnapshotReadState` overrides.
    fn events(&self) -> crate::types::ApiNodeEvents {
        crate::types::ApiNodeEvents::default()
    }
    /// Postmortem reorg ring (`GET /api/v1/diagnostics/reorgs`). Default
    /// empty for test fixtures; production `SnapshotReadState` overrides.
    fn reorgs(&self) -> crate::types::ApiReorgHistory {
        crate::types::ApiReorgHistory::default()
    }
    /// Host-process metrics — memory, DB sizes, disk space. Default impl
    /// returns all `None`s so test fixtures don't have to be updated; the
    /// production `SnapshotReadState` overrides with sysinfo + filesystem
    /// reads.
    fn host(&self) -> ApiHost {
        ApiHost::default()
    }
    /// Most-recent full blocks, newest-first, for the dashboard's recent
    /// list (`GET /api/v1/blocks/recent`). Snapshot-precomputed as a
    /// bounded tail; `n` is clamped to what the snapshot holds. Default
    /// empty so test fixtures needn't override; the production
    /// `SnapshotReadState` serves the precomputed tail.
    fn recent_blocks(&self, _n: u32) -> Vec<ApiRecentBlock> {
        Vec::new()
    }
    /// Operator-facing voting view: the votable parameters + bounds and the
    /// operator's configured votes (`GET /api/v1/votes`). Default empty so test
    /// fixtures needn't override; the production `SnapshotReadState` serves the
    /// live votable set from the snapshot's active params.
    fn votes(&self) -> ApiVotes {
        ApiVotes::default()
    }
}

/// Submission boundary the node implements for the API server.
///
/// Implementations cross a channel into the node's main loop and await
/// a oneshot reply. The `String` returned on success is the 32-byte
/// modifier id, hex-encoded (no `0x` prefix) — a tx id for the
/// transaction methods, a header id for `submit_full_block`.
#[async_trait]
pub trait NodeSubmit: Send + Sync {
    async fn submit_transaction(
        &self,
        bytes: Vec<u8>,
        mode: SubmitMode,
    ) -> Result<String, SubmitError>;

    /// JSON variant of [`Self::submit_transaction`] for the Scala-compat
    /// `POST /transactions[/check]` routes. The implementation decodes
    /// the parsed Scala-shape DTO into canonical wire bytes via
    /// `ergo-rest-json::decode_scala_transaction`, then runs the same
    /// admission pipeline as the bytes path.
    ///
    /// Decode failures surface through `SubmitError`:
    /// - `reason: "deserialize"` — malformed hex, missing required
    ///   field, structural error.
    /// - `reason: "non_canonical"` — soft-fork ergoTree, non-canonical
    ///   sigma-value re-serialization, or other byte-shape conflict
    ///   the v1 decoder refuses to canonicalize.
    ///
    /// Transport failures (`overloaded`, `shutting_down`, `timeout`)
    /// follow the same shape as the bytes path.
    async fn submit_transaction_json(
        &self,
        input: ScalaTransactionInput,
        mode: SubmitMode,
    ) -> Result<String, SubmitError>;

    /// Locally-mined-block submission, used by Scala-compat
    /// `POST /mining/solution` and `POST /blocks` (sendMinedBlock).
    /// The implementation decodes the parsed Scala-shape DTO into
    /// canonical wire bytes for each section, verifies the PoW
    /// solution locally (so we don't wake the action loop on an
    /// invalid header), and then injects the four section bodies
    /// into the apply pipeline.
    ///
    /// On success, returns the hex-encoded header id (32 bytes,
    /// no `0x` prefix). The action loop confirms admission only —
    /// the block may still be rejected later (orphan, fork on a
    /// stale tip, etc.); operators watch peer events / the chain
    /// tip to learn the outcome.
    ///
    /// Failure reasons:
    /// - `deserialize` — malformed JSON / hex / missing field, or
    ///   per-section header-id mismatch.
    /// - `non_canonical` — soft-fork ergoTree or non-canonical
    ///   sigma re-serialization inside `blockTransactions`.
    /// - `invalid_pow` — PoW solution does not satisfy the
    ///   header's `nBits` target.
    /// - `overloaded` / `shutting_down` / `timeout` — transport
    ///   (same shape as `submit_transaction`).
    /// - `route_disabled` — the bridge is not wired for block
    ///   submission (default impl). Production wiring overrides.
    ///
    /// Default impl returns `route_disabled` so test stubs and
    /// configurations that don't enable block submission don't
    /// have to override the method.
    async fn submit_full_block(&self, _block: ScalaFullBlock) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "route_disabled".to_string(),
            detail: Some(
                "block submission not wired in this NodeSubmit implementation".to_string(),
            ),
        })
    }

    /// Non-mutating dry-run of an assembled transaction, backing
    /// `POST /api/v1/transactions/simulate`.
    ///
    /// Unlike [`SubmitMode::CheckOnly`] — which still mutates the mempool
    /// anti-DoS bookkeeping (mempool invariant #7) — this entrypoint MUST NOT
    /// touch node state: it validates the tx against the current UTXO + pool
    /// view and returns a cost / fee / conflict report only. A cleanly-invalid
    /// tx is a *successful* simulation (`Ok(SimulateOutcome { valid: false, .. })`);
    /// only malformed bytes or a transient node condition surface as a
    /// [`SubmitError`].
    ///
    /// Default impl returns `route_disabled` so test stubs and nodes that have
    /// not wired the read-only validator keep compiling — the endpoint then
    /// answers the honest `route_unavailable` (503). Production wiring overrides
    /// this with a real non-mutating validate pass.
    async fn simulate(
        &self,
        _bytes: Vec<u8>,
        _assume_height: Option<u32>,
    ) -> Result<SimulateOutcome, SubmitError> {
        Err(SubmitError {
            reason: "route_disabled".to_string(),
            detail: Some(
                "non-mutating simulate is not wired in this NodeSubmit implementation".to_string(),
            ),
        })
    }
}

/// Outcome of a non-mutating [`NodeSubmit::simulate`] dry-run — the report
/// `POST /api/v1/transactions/simulate` renders. A cleanly-invalid tx still
/// produces an outcome (`valid = false`); the handler renders it as a 200.
/// nanoErg amounts are raw `u64` here and stringified at the wire boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulateOutcome {
    /// Transaction id computed from the assembled bytes.
    pub tx_id: String,
    /// Whether the tx would be admitted against the current state.
    pub valid: bool,
    /// Sigma-interpreter cost the validation consumed, in block-budget units.
    pub cost_units: u64,
    /// The active epoch's `maxBlockCost` the cost is bounded by.
    pub max_block_cost: u64,
    /// Serialized size of the tx.
    pub size_bytes: u32,
    /// Fee paid (sum of outputs to the fee proposition), nanoErg.
    pub fee_nano_erg: u64,
    /// Minimum fee the node requires for a tx of this size, nanoErg.
    pub min_fee_required_nano_erg: u64,
    /// `fee_nano_erg >= min_fee_required_nano_erg`.
    pub fee_sufficient: bool,
    /// Whether any input references a box unknown to the node.
    pub spends_unknown_inputs: bool,
    /// Pool double-spend conflicts: an input already spent by a pooled tx.
    pub conflicts: Vec<SimulateConflict>,
    /// Non-fatal advisories (e.g. `non_canonical_ergo_tree`).
    pub warnings: Vec<String>,
}

/// A single pool double-spend conflict on a simulated tx: `box_id` is already
/// being spent by `conflicting_tx_id` in the mempool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulateConflict {
    /// The already-spent input box id (hex).
    pub box_id: String,
    /// The pooled tx spending it (hex tx id).
    pub conflicting_tx_id: String,
}

/// Keyless transaction-builder boundary backing
/// `POST /api/v1/transactions/build`.
///
/// "Keyless" = the caller supplies the input universe (addresses to select
/// from, or explicit input box ids) and an explicit change address; no secret
/// material ever crosses this boundary, so the endpoint is T0. This is the ONE
/// builder seam: the production impl delegates to the same selection /
/// change / fee core the keyed wallet build uses — a second builder is never
/// forked. `V1State::tx_builder` is `None` until that core is wired, and the
/// endpoint then answers the honest `route_unavailable` (503) rather than
/// fabricating a coin selection.
#[async_trait]
pub trait NodeTxBuilder: Send + Sync {
    async fn build_unsigned(
        &self,
        request: KeylessBuildRequest,
    ) -> Result<BuiltUnsigned, TxBuildError>;
}

/// A keyless build request — the node-facing projection of the `tx_intent`
/// the handler shapes the wire intent into. Unwired intent shapes (mint,
/// payment registers, raw boxes) are rejected as `unsupported_intent` up front
/// and never reach the builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeylessBuildRequest {
    /// Where inputs are drawn from.
    pub inputs: KeylessInputs,
    /// Requested payment outputs.
    pub outputs: Vec<KeylessOutput>,
    /// Data-input box ids (hex).
    pub data_input_box_ids: Vec<String>,
    /// Fee spec.
    pub fee: KeylessFee,
    /// REQUIRED change address (base58) — the keyless surface never resolves a
    /// persisted change address.
    pub change_address: String,
    /// Optional context height override (defaults to the node tip).
    pub context_height: Option<u32>,
    /// Permit dropping a non-re-emission token surplus (the EIP-27 burn stays
    /// mandatory regardless).
    pub allow_token_burn: bool,
}

/// The input universe for a [`KeylessBuildRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeylessInputs {
    /// Select coins from the UTXOs of these addresses (extra-index scan).
    Select {
        /// Selection universe (base58 addresses).
        from_addresses: Vec<String>,
        /// Minimum confirmations for a candidate box; `-1` includes pool
        /// outputs.
        min_confirmations: i64,
        /// Box ids to exclude from selection (hex).
        exclude_box_ids: Vec<String>,
        /// What the selection must cover.
        target: KeylessTarget,
    },
    /// Spend exactly these input boxes (by hex id).
    BoxIds {
        /// The explicit input box ids (hex).
        box_ids: Vec<String>,
    },
}

/// What a `select` input universe must cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeylessTarget {
    /// Cover the outputs + fee (+ EIP-27 burn) automatically.
    Auto,
    /// Cover exactly this nanoErg amount.
    Value(u64),
}

/// One requested payment output of a [`KeylessBuildRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeylessOutput {
    /// Recipient address (base58).
    pub address: String,
    /// Output value, nanoErg.
    pub value_nano_erg: u64,
    /// Tokens carried by the output.
    pub assets: Vec<KeylessAsset>,
}

/// A `{token_id, amount}` asset on a [`KeylessOutput`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeylessAsset {
    /// 32-byte token id (hex).
    pub token_id: String,
    /// Token amount.
    pub amount: u64,
}

/// Fee spec for a [`KeylessBuildRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeylessFee {
    /// Mempool-derived fee for the given block horizon.
    Auto {
        /// Target confirmation horizon (blocks).
        target_blocks: u32,
    },
    /// Exactly this nanoErg fee.
    Fixed {
        /// Fixed fee, nanoErg.
        value: u64,
    },
}

/// A built keyless unsigned transaction + the selection / change / fee summary
/// the `build` endpoint reports. nanoErg amounts are raw `u64`, stringified at
/// the wire boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltUnsigned {
    /// Canonical serialized bytes of the unsigned transaction.
    pub unsigned_tx_bytes: Vec<u8>,
    /// The transaction id (hex).
    pub tx_id: String,
    /// Box ids selected as inputs (request order, hex).
    pub input_box_ids: Vec<String>,
    /// Total nanoErg the selected inputs carry.
    pub selected_value_nano_erg: u64,
    /// Miner fee, nanoErg.
    pub fee_nano_erg: u64,
    /// `"auto"` when the fee was mempool-derived, `"fixed"` when caller-set.
    pub fee_source: String,
    /// Computed change outputs.
    pub change: Vec<BuiltChange>,
    /// Serialized size of the unsigned tx.
    pub size_bytes: u32,
    /// Estimated interpreter cost, block-budget units.
    pub estimated_cost_units: u64,
}

/// One change output computed by the keyless builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltChange {
    /// Change recipient (the intent's change address, base58).
    pub address: String,
    /// Change value, nanoErg.
    pub value_nano_erg: u64,
    /// Change tokens.
    pub assets: Vec<KeylessAsset>,
}

/// A keyless-build rejection. `reason` reuses the frozen submit-domain /
/// invalid-input verbs (`insufficient_funds`, `no_inputs_found`,
/// `invalid_address`, `invalid_token_id`, `dust_change`, `indexer_disabled`,
/// `unsupported_intent`, `intent_too_large`, `route_disabled`,
/// `internal_error`) so the handler maps them to the canonical v1 error
/// `reason` with no new vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxBuildError {
    /// Frozen reason verb (see the type doc for the accepted set).
    pub reason: String,
    /// Optional actionable detail.
    pub detail: Option<String>,
}

/// Out-of-band node-administration boundary. Currently exposes only
/// the shutdown trigger — fired by `POST /node/shutdown` so operators
/// can ask the action loop to drain cleanly without sending Ctrl+C
/// (useful when the node was launched headless / backgrounded with
/// stdio redirected, where console-signal delivery is unreliable).
///
/// `request_shutdown` is non-blocking and idempotent. The handler
/// returns 202 immediately; the actual drain happens asynchronously
/// in the action loop's existing shutdown path. Callers that want to
/// confirm shutdown completed should poll `GET /api/v1/health` until
/// the connection refuses.
pub trait NodeAdmin: Send + Sync {
    fn request_shutdown(&self);

    /// Fire-and-forget dial request for `POST /peers/connect` (Scala
    /// fires `ConnectTo(PeerInfo.fromAddress(...))` at the network
    /// controller and answers 200 without waiting for the dial's
    /// outcome). Default no-op so admin handles that only expose
    /// shutdown keep compiling; the node wires a real sender into its
    /// action loop.
    fn connect_to_peer(&self, _addr: std::net::SocketAddr) {}

    /// Replace the operator's on-chain voting targets (the auth-gated
    /// `POST /api/v1/votes` write). `targets` is the FULL desired set of
    /// `(parameter_id, target_value)` pairs and REPLACES the current set —
    /// an empty slice clears all votes. The implementation validates that each
    /// `parameter_id` is operator-votable and applies the set to the shared
    /// voting-targets slot the candidate builder reads.
    ///
    /// Default returns [`VotingControlError::MiningDisabled`] so admin handles
    /// without a mining subsystem reject the write — voting only has an effect
    /// while the node is mining.
    fn set_voting_targets(&self, _targets: Vec<(u8, i64)>) -> Result<(), VotingControlError> {
        Err(VotingControlError::MiningDisabled)
    }
}

/// Why an operator `POST /api/v1/votes` write was rejected. The handler maps
/// these to HTTP status + a Scala-parity JSON error envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VotingControlError {
    /// The node is not mining, so there is no candidate builder to apply votes
    /// to. Mapped to `409 Conflict`.
    MiningDisabled,
    /// A target named a parameter id that is not operator-votable (e.g.
    /// `blockVersion` 123, soft-fork 120, or an unknown id). Mapped to
    /// `400 Bad Request`.
    NotVotable {
        /// The offending parameter id.
        parameter_id: u8,
    },
    /// A target fell outside the parameter's allowable `[min, max]` voting
    /// bounds. The consensus recompute only steps a parameter toward a bound and
    /// won't step it past, so a target beyond the bound can never be a settling
    /// value — it would just pin the parameter at the bound forever. The node
    /// rejects it rather than accepting a misleading target. Mapped to
    /// `400 Bad Request`.
    OutOfRange {
        /// The offending parameter id.
        parameter_id: u8,
        /// The rejected target value.
        target: i64,
        /// Inclusive lower bound for this parameter.
        min: i64,
        /// Inclusive upper bound for this parameter.
        max: i64,
    },
}

/// No-op `NodeAdmin` for tests and configurations that don't expose
/// the admin surface. The shutdown route is mounted only when a real
/// admin handle is plumbed in.
#[derive(Debug, Default, Clone)]
pub struct NoopNodeAdmin;

impl NodeAdmin for NoopNodeAdmin {
    fn request_shutdown(&self) {}
}

/// Snapshot-read view over the mempool, consumed by the extra-index
/// pool overlay. Handlers compose `IndexerQuery` (confirmed-only) with
/// this trait to assemble the unconfirmed view that mirrors Scala's
/// blockchain-API mempool overlay shape.
///
/// Implementations are expected to be cheap snapshot reads — the
/// production wiring in `ergo-node` reads from an `ArcSwap<NodeSnapshot>`
/// rebuilt once per `sync_tick`. Handlers may invoke any method on
/// every request without coordination with the node's main loop.
///
/// All methods are sync because the underlying snapshot reads are
/// non-blocking. `Send + Sync` so callers can hold an `Arc<dyn MempoolView>`.
pub trait MempoolView: Send + Sync {
    /// True if any pool tx spends the given committed-box id. Drives
    /// `excludeMempoolSpent` filtering on byErgoTree / byErgoTreeHash
    /// unspent routes.
    fn is_spent_by_pool(&self, box_id: &BoxId) -> bool;

    /// Pool tx that spends `box_id`, or `None` if no pool tx does.
    /// Used to surface a tentative `spending_tx_id` on confirmed UTXOs
    /// that have a pending pool spend (P5 contract — pre-P5 runtime
    /// always returns `None`).
    fn pool_spending_tx(&self, box_id: &BoxId) -> Option<TxId>;

    /// All pool-created output boxes indexed by `box_id`. Handlers
    /// iterate this for `includeUnconfirmed` filtering (by ergo_tree,
    /// template, or token id). Returns the snapshot's shared `Arc`
    /// allocation — cheap to clone, holds the same view for the
    /// duration of the request even if the publisher rebuilds the
    /// snapshot mid-iteration.
    fn pool_outputs(&self) -> Arc<HashMap<BoxId, ErgoBox>>;

    /// Coherent single-snapshot read for the tx-detail endpoint: the
    /// canonical wire bytes of the pooled tx `tx_id` (if present)
    /// together with the SAME snapshot's pool-output overlay, so
    /// pool-parent input resolution cannot race a snapshot rebuild.
    /// `None` when no such pooled tx exists. Defaults to `None` for the
    /// no-overlay / test views; only the snapshot-backed production impl
    /// overrides it.
    fn pool_tx_detail(&self, _tx_id: &TxId) -> Option<PoolTxDetail> {
        None
    }
}

/// Coherent single-snapshot tx-detail pair returned by
/// [`MempoolView::pool_tx_detail`]: the pooled tx's canonical wire bytes
/// and the SAME snapshot's pool-output overlay, so pool-parent input
/// resolution can't race a snapshot rebuild between two reads.
pub type PoolTxDetail = (Arc<[u8]>, Arc<HashMap<BoxId, ErgoBox>>);

/// No-op `MempoolView` for tests and pre-P5 wiring. Reports an empty
/// pool: nothing is spent, no pool outputs exist. Handlers built
/// against this view behave exactly like the confirmed-only path,
/// which is the expected shape of the pre-P5 runtime.
#[derive(Debug, Default, Clone)]
pub struct NoopMempoolView {
    empty_outputs: Arc<HashMap<BoxId, ErgoBox>>,
}

/// Read-side view of the validation-time voted-protocol parameters
/// the storage-rent endpoint needs. Two methods, both pure:
///
/// - `storage_fee_factor_for_validation_at(h)` returns the i32 factor
///   governing block-`h` consensus, i.e. the row at `h - 1` per the
///   voted-parameters spec. The handler MUST short-circuit on `h == 0`
///   before calling — implementations panic in debug, return `None`
///   in release.
/// - `compute_storage_fee` is the consensus-shared arithmetic helper
///   (`storage_fee_factor.wrapping_mul(box_bytes_len)`), exposed
///   through the trait so `ergo-api` can reach it without depending
///   directly on `ergo-validation`.
pub trait ChainParamsView: Send + Sync {
    fn storage_fee_factor_for_validation_at(&self, h: u32) -> Option<i32>;
    fn compute_storage_fee(&self, box_bytes_len: i32, storage_fee_factor: i32) -> i32;
}

impl NoopMempoolView {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MempoolView for NoopMempoolView {
    fn is_spent_by_pool(&self, _box_id: &BoxId) -> bool {
        false
    }

    fn pool_spending_tx(&self, _box_id: &BoxId) -> Option<TxId> {
        None
    }

    fn pool_outputs(&self) -> Arc<HashMap<BoxId, ErgoBox>> {
        self.empty_outputs.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;

    #[test]
    fn noop_view_reports_empty_pool() {
        let v = NoopMempoolView::new();
        let any_id = Digest32::from_bytes([0xAB; 32]);
        assert!(!v.is_spent_by_pool(&any_id));
        assert!(v.pool_spending_tx(&any_id).is_none());
        assert!(v.pool_outputs().is_empty());
    }

    #[test]
    fn noop_view_object_safe_via_arc_dyn() {
        // Compile-time: confirms `MempoolView` is object-safe and
        // handlers can hold `Arc<dyn MempoolView>` (the wiring shape
        // used by `serve()` in production).
        let _v: Arc<dyn MempoolView> = Arc::new(NoopMempoolView::new());
    }

    /// Stub that only implements the required `NodeSubmit` methods;
    /// `submit_full_block` falls through to the trait default.
    struct StubSubmitNoBlockOverride;

    #[async_trait]
    impl NodeSubmit for StubSubmitNoBlockOverride {
        async fn submit_transaction(
            &self,
            _bytes: Vec<u8>,
            _mode: SubmitMode,
        ) -> Result<String, SubmitError> {
            Err(SubmitError {
                reason: "internal_error".to_string(),
                detail: None,
            })
        }
        async fn submit_transaction_json(
            &self,
            _input: ScalaTransactionInput,
            _mode: SubmitMode,
        ) -> Result<String, SubmitError> {
            Err(SubmitError {
                reason: "internal_error".to_string(),
                detail: None,
            })
        }
    }

    /// Pin the trait contract: implementations that don't
    /// wire block submission inherit `route_disabled` on
    /// `submit_full_block`. The Scala-compat `POST /blocks`
    /// handler will map this to 503 so operators see a clear
    /// "not configured" signal rather than a 5xx mystery.
    #[tokio::test]
    async fn submit_full_block_default_impl_returns_route_disabled() {
        let s: Arc<dyn NodeSubmit> = Arc::new(StubSubmitNoBlockOverride);
        // Minimal stub: an empty ScalaFullBlock — the default impl
        // never inspects it (returns Err before touching the body).
        let body = ScalaFullBlock {
            header: crate::compat::types::ScalaHeader {
                extension_id: String::new(),
                difficulty: "0".to_string(),
                votes: String::new(),
                timestamp: 0,
                size: 0,
                unparsed_bytes: String::new(),
                state_root: String::new(),
                height: 0,
                n_bits: 0,
                version: 0,
                id: String::new(),
                ad_proofs_root: String::new(),
                transactions_root: String::new(),
                extension_hash: String::new(),
                pow_solutions: crate::compat::types::ScalaPowSolutions {
                    pk: String::new(),
                    w: String::new(),
                    n: String::new(),
                    d: serde_json::Value::Null,
                },
                ad_proofs_id: String::new(),
                transactions_id: String::new(),
                parent_id: String::new(),
            },
            block_transactions: crate::compat::types::ScalaBlockTransactions {
                header_id: String::new(),
                transactions: vec![],
                block_version: 0,
                size: 0,
            },
            extension: crate::compat::types::ScalaExtension {
                header_id: String::new(),
                digest: String::new(),
                fields: vec![],
            },
            ad_proofs: None,
            size: 0,
        };
        let err = s.submit_full_block(body).await.unwrap_err();
        assert_eq!(err.reason, "route_disabled");
        assert!(err.detail.is_some());
    }
}
