//! Shared types for the mempool crate.
//!
//! Consolidates config, actions, sources, and state-change
//! notification shapes. Pool-internal types live in `pool.rs`.

use std::net::SocketAddr;
use std::sync::Arc;

use ergo_primitives::digest::Digest32;

/// Transaction identifier. Alias of `Digest32` for clarity at call sites.
pub type TxId = Digest32;

/// Peer identifier. Matches `ergo-p2p::peer::PeerId` (socket address)
/// without a dependency on that crate — the orchestrator wires them.
pub type PeerId = SocketAddr;

/// Origin of an incoming transaction. Determines penalty routing and
/// whether per-peer budgets apply at admission time.
#[derive(Debug, Clone)]
pub enum TxSource {
    Peer(PeerId),
    Api,
    Wallet,
    DemotedFromBlock,
}

impl TxSource {
    pub fn is_peer(&self) -> bool {
        matches!(self, TxSource::Peer(_))
    }

    pub fn peer(&self) -> Option<PeerId> {
        match self {
            TxSource::Peer(p) => Some(*p),
            _ => None,
        }
    }
}

/// Actions emitted by mempool entry points. The node event loop consumes
/// `Vec<MempoolAction>` and routes to the P2P / metrics layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolAction {
    /// Advertise this tx to peers. `except` is the source peer (if any),
    /// which already has the tx.
    BroadcastInv { tx_id: TxId, except: Option<PeerId> },
    /// Stop advertising — these txs were replaced, evicted, or confirmed.
    RevokeBroadcast { tx_ids: Vec<TxId> },
    /// Apply a peer penalty.
    Penalize { peer: PeerId, kind: PenaltyKind },
    /// Non-blocking log/metric event.
    Observe { event: ObservedEvent },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyKind {
    Misbehavior,
    NonDelivery,
    Spam,
}

/// Observational events the mempool emits for metrics and logging.
/// Consumers treat these as best-effort, never consensus-relevant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedEvent {
    Admitted {
        tx_id: TxId,
        weight: u64,
        fee: u64,
        size: u32,
    },
    DroppedBelowMinFee {
        tx_id: TxId,
        fee: u64,
    },
    DroppedIbdGated,
    DroppedDuplicate {
        tx_id: TxId,
    },
    DroppedKnownInvalid {
        tx_id: TxId,
    },
    DroppedUnresolvedInput {
        tx_id: TxId,
    },
    DroppedDoubleSpendLoser {
        tx_id: TxId,
    },
    DroppedPoolFull {
        tx_id: TxId,
    },
    DroppedBudgetExhausted {
        tx_id: TxId,
        global: bool,
    },
    Evicted {
        tx_ids: Vec<TxId>,
        reason: EvictionReason,
    },
    /// Emitted once per directly-replaced loser when a heavier candidate
    /// wins a double-spend conflict in `admission::commit`. Carries both
    /// winner and loser weights so consumers can compute the weight
    /// delta without re-reading pool state.
    Replaced {
        loser_id: TxId,
        winner_id: TxId,
        weight_loser: u64,
        weight_winner: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionReason {
    DoubleSpendWinner,
    LowWeight,
    ByteBudget,
    Confirmed,
    InputConflict,
}

/// Pointer to a committed-state tip. Carried by the notifier so
/// `StateStore::tx_diff_since` can compute the diff across reorgs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TipPointer {
    pub height: u32,
    pub header_id: Digest32,
}

/// A tx that entered the committed chain since the previous tip. Carries
/// the spent inputs so the mempool can evict conflicting pool txs even
/// when the applied tx itself is not in the pool.
#[derive(Debug, Clone)]
pub struct AppliedTx {
    pub tx_id: TxId,
    pub spent_inputs: Vec<Digest32>,
}

/// A tx demoted from a rolled-back block. Carries canonical bytes so
/// relay + revalidation can reuse them without re-serializing.
#[derive(Debug, Clone)]
pub struct DemotedTx {
    pub tx_id: TxId,
    pub bytes: Arc<[u8]>,
}

/// Result of `StateStore::tx_diff_since`.
#[derive(Debug, Clone)]
pub struct TxDiff {
    pub new_tip: TipPointer,
    pub applied: Vec<AppliedTx>,
    pub demoted: Vec<DemotedTx>,
    /// Union of `applied[*].spent_inputs` for O(1) conflict checks.
    pub applied_spent_inputs: std::collections::HashSet<Digest32>,
}

// ── Conversions from state-crate types ───────────────────────────
// ergo-state uses [u8; 32] / Vec<u8> to match redb conventions; the
// mempool uses Digest32 / Arc<[u8]>. These cheap bridges let the node
// orchestrator hand a state diff straight to `Mempool::on_tip_change`.
// `TxDiffError` flows through directly from `ergo_state::diff` — see
// the re-export in `lib.rs`; the in-node consumers
// (`ergo-node/src/notifier.rs`, `ergo-node/src/node/mod.rs`) pattern-
// match on the state-crate variants without conversion.

impl From<ergo_state::diff::TipPointer> for TipPointer {
    fn from(t: ergo_state::diff::TipPointer) -> Self {
        Self {
            height: t.height,
            header_id: Digest32::from_bytes(t.header_id),
        }
    }
}

impl From<ergo_state::diff::AppliedTx> for AppliedTx {
    fn from(a: ergo_state::diff::AppliedTx) -> Self {
        Self {
            tx_id: Digest32::from_bytes(a.tx_id),
            spent_inputs: a
                .spent_inputs
                .into_iter()
                .map(Digest32::from_bytes)
                .collect(),
        }
    }
}

impl From<ergo_state::diff::DemotedTx> for DemotedTx {
    fn from(d: ergo_state::diff::DemotedTx) -> Self {
        Self {
            tx_id: Digest32::from_bytes(d.tx_id),
            bytes: d.bytes.into(),
        }
    }
}

impl From<ergo_state::diff::TxDiff> for TxDiff {
    fn from(d: ergo_state::diff::TxDiff) -> Self {
        Self {
            new_tip: d.new_tip.into(),
            applied: d.applied.into_iter().map(Into::into).collect(),
            demoted: d.demoted.into_iter().map(Into::into).collect(),
            applied_spent_inputs: d
                .applied_spent_inputs
                .into_iter()
                .map(Digest32::from_bytes)
                .collect(),
        }
    }
}

/// Mempool configuration. All fields are populated from the `[mempool]`
/// TOML section plus CLI overrides; defaults below are the production
/// values.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub enabled: bool,
    pub max_pool_size: usize,
    pub max_pool_bytes: usize,
    pub min_relay_fee_nano_erg: u64,
    pub max_tx_size_bytes: usize,
    pub max_tx_cost: u64,
    pub invalidation_cache_size: usize,
    pub invalidation_ttl_seconds: u64,
    pub ibd_gate_block_lag: u32,
    pub notifier_poll_ms: u64,
    pub revalidation_per_tick: usize,
    pub revalidation_max_depth: usize,
    pub cpfp_max_family_depth: usize,
    pub cpfp_max_family_ops: usize,
    pub cpfp_max_family_update_ms: u64,
    pub global_cost_budget: u64,
    pub per_peer_cost_budget: u64,
    pub unresolved_cache_size: usize,
    pub unresolved_cache_ttl_seconds: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_pool_size: 1000,
            max_pool_bytes: 64 * 1024 * 1024,
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 98_304,
            max_tx_cost: 4_900_000, // mainnet.conf overrides application.conf default of 1_000_000
            invalidation_cache_size: 10_000,
            invalidation_ttl_seconds: 14_400,
            ibd_gate_block_lag: 10,
            notifier_poll_ms: 250,
            revalidation_per_tick: 100,
            revalidation_max_depth: 10_000,
            cpfp_max_family_depth: 500,
            cpfp_max_family_ops: 10_000,
            cpfp_max_family_update_ms: 500,
            global_cost_budget: 12_000_000,
            per_peer_cost_budget: 10_000_000,
            unresolved_cache_size: 4_096,
            unresolved_cache_ttl_seconds: 60,
        }
    }
}
