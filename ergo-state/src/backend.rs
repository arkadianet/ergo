//! The storage-side abstraction that Mode 1 (`store::StateStore`) and
//! Mode 5 (`digest_store::DigestStateStore`) share, so the action loop
//! can dispatch on `state_type` without baking in the concrete type.
//!
//! Split into three traits because the surfaces differ in nature:
//! - `ChainStateRead` — committed chain pointers + active params.
//! - `HeaderSectionStore` — the header/section table surface (the
//!   table-backed methods are identical between backends and delegate
//!   to a shared `header_store::HeaderSectionTables` component;
//!   session-invalidity, the reader handle, and lifecycle stay on the
//!   concrete backend).
//! - `BlockApply` — the write seam that DIFFERS: the UTXO backend
//!   takes a `CheckedBlock` and derives the root from box mutations;
//!   the digest backend verifies ADProofs to derive the root. Because
//!   the two derive the same `apply_full_block(&CheckedBlock)` answer
//!   by different internal means, this seam is the reason the executor
//!   binds `B: StateBackend` GENERICALLY rather than `dyn` — unifying
//!   the differing internals behind a `dyn` method would force
//!   associated types and break object-safety. The action loop is
//!   single-writer, so monomorphization is free.
//!
//! `NodeState` holds a `StateBackendKind` enum (Utxo/Digest) that
//! forwards to the concrete backend via one internal match, keeping
//! the type parameter out of `NodeState`'s ~40 methods.
//!
//! `#![allow(dead_code)]`: the traits are defined and implemented for
//! `StateStore` here; `DigestStateStore` implements them and the
//! executor binds against them in later phases. No in-crate caller
//! reaches the trait surface yet.
#![allow(dead_code)]

use crate::chain::{ChainStateMeta, HeaderMeta};
use crate::store::StateError;

/// Committed chain-state reads. `chain_state_meta` returns an OWNED
/// snapshot, not a borrow: neither backend keeps a mirrored
/// `ChainStateMeta` in sync with its authoritative state — the UTXO
/// backend projects its in-memory `ChainState` via `to_persisted()`,
/// the digest backend clones its persisted `ChainStateMeta`.
pub trait ChainStateRead {
    /// Best fully-applied block height.
    fn height(&self) -> u32;
    /// Owned snapshot of the committed chain pointers.
    fn chain_state_meta(&self) -> ChainStateMeta;
    /// Active protocol parameters at the current tip. Borrowed — both
    /// backends cache this with a single controlled refresh path (at
    /// epoch boundaries), unlike `chain_state` which has many write
    /// paths, so a borrow is safe here.
    fn active_params(&self) -> &ergo_validation::ActiveProtocolParameters;
    /// Cumulative validation settings at the current tip.
    fn validation_settings(&self) -> &ergo_validation::ErgoValidationSettings;
    /// Lowest height whose full block is retained (Mode-3 pruning
    /// sentinel; inert / returns the floor when not pruning).
    fn read_minimal_full_block_height(&self) -> Result<u32, StateError>;
}

/// Header + block-section persistence. The table-backed methods are
/// identical across backends; `session_invalids`, `reader_handle`, and
/// `shutdown_cleanly` are NOT pure table state and are supplied by the
/// concrete backend (session invalidity is session-scoped in-memory
/// state; the reader handle and lifecycle are backend concerns).
pub trait HeaderSectionStore {
    fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
    fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError>;
    fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError>;
    fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
    fn get_section_height(&self, section_id: &[u8; 32]) -> Result<Option<u32>, StateError>;
    fn scan_header_chain_range(&self, lo: u32, hi: u32)
        -> Result<Vec<(u32, [u8; 32])>, StateError>;
    fn store_header(&self, header_id: &[u8; 32], header_bytes: &[u8]) -> Result<(), StateError>;
    fn store_validated_header(
        &mut self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
        meta: &HeaderMeta,
        new_best: Option<(u32, Vec<u8>)>,
    ) -> Result<(), StateError>;
    fn store_block_section_typed(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
    ) -> Result<(), StateError>;
    fn begin_header_batch(&mut self);
    fn flush_header_batch(&mut self) -> Result<(), StateError>;
    fn mark_session_invalid(&mut self, header_id: [u8; 32]);
    fn is_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError>;
    fn reader_handle(&self) -> crate::reader::ChainStoreReader;
    fn shutdown_cleanly(&mut self) -> Result<(), StateError>;
}

/// The block-apply write seam — the only surface that differs between
/// backends, and the reason the executor is generic, not `dyn`.
pub trait BlockApply {
    /// Apply a fully-validated block, advancing committed state. The
    /// UTXO backend mutates the AVL+ arena and derives the root; the
    /// digest backend verifies the block's ADProofs to derive the root
    /// (see `digest_store`), then persists it. Both present the same
    /// `&CheckedBlock` interface; the differing internals are hidden.
    fn apply_full_block(
        &mut self,
        block: &ergo_validation::block::CheckedBlock,
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
    ) -> Result<(), StateError>;

    /// Roll committed state back to `target_height`. The digest backend
    /// has no wallet hook or rescan guard; it rejects non-`None` values
    /// as a hard error (an assert would no-op in release and silently
    /// drop the arguments).
    fn rollback_to(
        &mut self,
        target_height: u32,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
        rescan_guard: Option<&dyn crate::wallet::apply::RescanGuard>,
    ) -> Result<(), StateError>;
}

/// Umbrella bound the executor binds against.
pub trait StateBackend: ChainStateRead + HeaderSectionStore + BlockApply {}
impl<T: ChainStateRead + HeaderSectionStore + BlockApply> StateBackend for T {}

// ----- StateStore (Mode 1/2/3/6) impls -----
//
// Phase A: delegate to the existing inherent methods, no bodies move.
// (Phase B factors the header/section tables into a shared component;
// these delegations stay valid because the inherent methods keep their
// signatures.)

use crate::store::StateStore;

impl ChainStateRead for StateStore {
    fn height(&self) -> u32 {
        StateStore::height(self)
    }
    fn chain_state_meta(&self) -> ChainStateMeta {
        // Project the in-memory ChainState to its persisted form —
        // owned, computed on read, no stored mirror.
        self.chain_state().to_persisted()
    }
    fn active_params(&self) -> &ergo_validation::ActiveProtocolParameters {
        StateStore::active_params(self)
    }
    fn validation_settings(&self) -> &ergo_validation::ErgoValidationSettings {
        StateStore::validation_settings(self)
    }
    fn read_minimal_full_block_height(&self) -> Result<u32, StateError> {
        StateStore::read_minimal_full_block_height(self)
    }
}

impl HeaderSectionStore for StateStore {
    fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        StateStore::get_header(self, header_id)
    }
    fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError> {
        StateStore::get_header_meta(self, header_id)
    }
    fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        StateStore::get_header_id_at_height(self, height)
    }
    fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        StateStore::get_block_section(self, modifier_id)
    }
    fn get_section_height(&self, section_id: &[u8; 32]) -> Result<Option<u32>, StateError> {
        StateStore::get_section_height(self, section_id)
    }
    fn scan_header_chain_range(
        &self,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
        StateStore::scan_header_chain_range(self, lo, hi)
    }
    fn store_header(&self, header_id: &[u8; 32], header_bytes: &[u8]) -> Result<(), StateError> {
        StateStore::store_header(self, header_id, header_bytes)
    }
    fn store_validated_header(
        &mut self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
        meta: &HeaderMeta,
        new_best: Option<(u32, Vec<u8>)>,
    ) -> Result<(), StateError> {
        StateStore::store_validated_header(self, header_id, header_bytes, meta, new_best)
    }
    fn store_block_section_typed(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
    ) -> Result<(), StateError> {
        StateStore::store_block_section_typed(self, modifier_id, section_bytes, section_type)
    }
    fn begin_header_batch(&mut self) {
        StateStore::begin_header_batch(self)
    }
    fn flush_header_batch(&mut self) -> Result<(), StateError> {
        StateStore::flush_header_batch(self)
    }
    fn mark_session_invalid(&mut self, header_id: [u8; 32]) {
        StateStore::mark_session_invalid(self, header_id)
    }
    fn is_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
        StateStore::is_invalid(self, header_id)
    }
    fn reader_handle(&self) -> crate::reader::ChainStoreReader {
        StateStore::reader_handle(self)
    }
    fn shutdown_cleanly(&mut self) -> Result<(), StateError> {
        StateStore::shutdown_cleanly(self)
    }
}

impl BlockApply for StateStore {
    fn apply_full_block(
        &mut self,
        block: &ergo_validation::block::CheckedBlock,
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
    ) -> Result<(), StateError> {
        StateStore::apply_block(self, block, voted_params_row, wallet_hook)
    }
    fn rollback_to(
        &mut self,
        target_height: u32,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
        rescan_guard: Option<&dyn crate::wallet::apply::RescanGuard>,
    ) -> Result<(), StateError> {
        StateStore::rollback_to(self, target_height, wallet_hook, rescan_guard)
    }
}

/// The state backend `NodeState` holds: the UTXO arena store (Modes
/// 1/2/3/6) or the Mode 5 digest verifier. Implements the
/// `StateBackend` traits by forwarding to the inner backend via one
/// match, so the executor dispatches on the runtime backend without a
/// type parameter or `dyn`.
///
/// `large_enum_variant`: there is exactly one of these per node, held
/// by `NodeState` for the process lifetime — not a collection where a
/// size delta multiplies. Boxing the larger `Utxo` arm would add an
/// indirection to the hottest read/apply path to save a few hundred
/// bytes on a singleton, a net loss.
#[allow(clippy::large_enum_variant)]
pub enum StateBackendKind {
    Utxo(StateStore),
    Digest(crate::digest_store::DigestStateStore),
}

impl StateBackendKind {
    /// Borrow the UTXO backend, or `None` for a digest backend.
    /// UTXO-only subsystems (mempool, wallet, indexer, snapshot,
    /// mining, popow) call this behind their mode gates.
    pub fn as_utxo(&self) -> Option<&StateStore> {
        match self {
            Self::Utxo(s) => Some(s),
            Self::Digest(_) => None,
        }
    }

    /// Mutable counterpart to [`Self::as_utxo`].
    pub fn as_utxo_mut(&mut self) -> Option<&mut StateStore> {
        match self {
            Self::Utxo(s) => Some(s),
            Self::Digest(_) => None,
        }
    }

    /// A cloned `Arc` handle to the underlying redb `Database`, regardless
    /// of backend. The wallet writer task opens its own read txns against
    /// this without a backend-typed branch (both backends share one redb
    /// file per data dir).
    pub fn db_arc(&self) -> std::sync::Arc<redb::Database> {
        match self {
            Self::Utxo(s) => s.db_arc(),
            Self::Digest(d) => d.db_arc(),
        }
    }

    /// The 33-byte authenticated state-root digest at the node's CURRENT tip,
    /// regardless of backend: the UTXO arena's AVL+ root, or the digest
    /// verifier's ADProof-derived root. Both equal the tip header's
    /// `state_root` for their mode, so this is the real value the operator
    /// dashboard reports as the tip state digest — not synthetic data.
    ///
    /// Observability read, NOT a durability claim: on the UTXO pipeline path
    /// the in-memory root can lead the durable commit, so do not consume this
    /// in persistence- or reorg-sensitive code (use the committed
    /// `chain_state_meta` for that). `&mut self` because the UTXO
    /// [`StateStore::root_digest`] accessor takes `&mut self`.
    pub fn state_root_digest(&mut self) -> [u8; 33] {
        match self {
            Self::Utxo(s) => *s.root_digest().as_bytes(),
            Self::Digest(d) => d.root_digest(),
        }
    }
}

impl ChainStateRead for StateBackendKind {
    fn height(&self) -> u32 {
        match self {
            StateBackendKind::Utxo(s) => s.height(),
            StateBackendKind::Digest(d) => d.height(),
        }
    }
    fn chain_state_meta(&self) -> ChainStateMeta {
        match self {
            StateBackendKind::Utxo(s) => s.chain_state_meta(),
            StateBackendKind::Digest(d) => d.chain_state_meta(),
        }
    }
    fn active_params(&self) -> &ergo_validation::ActiveProtocolParameters {
        match self {
            StateBackendKind::Utxo(s) => s.active_params(),
            StateBackendKind::Digest(d) => d.active_params(),
        }
    }
    fn validation_settings(&self) -> &ergo_validation::ErgoValidationSettings {
        match self {
            StateBackendKind::Utxo(s) => s.validation_settings(),
            StateBackendKind::Digest(d) => d.validation_settings(),
        }
    }
    fn read_minimal_full_block_height(&self) -> Result<u32, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.read_minimal_full_block_height(),
            StateBackendKind::Digest(d) => d.read_minimal_full_block_height(),
        }
    }
}

impl HeaderSectionStore for StateBackendKind {
    fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.get_header(header_id),
            StateBackendKind::Digest(d) => d.get_header(header_id),
        }
    }
    fn get_header_meta(&self, header_id: &[u8; 32]) -> Result<Option<HeaderMeta>, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.get_header_meta(header_id),
            StateBackendKind::Digest(d) => d.get_header_meta(header_id),
        }
    }
    fn get_header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.get_header_id_at_height(height),
            StateBackendKind::Digest(d) => d.get_header_id_at_height(height),
        }
    }
    fn get_block_section(&self, modifier_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.get_block_section(modifier_id),
            StateBackendKind::Digest(d) => d.get_block_section(modifier_id),
        }
    }
    fn get_section_height(&self, section_id: &[u8; 32]) -> Result<Option<u32>, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.get_section_height(section_id),
            StateBackendKind::Digest(d) => d.get_section_height(section_id),
        }
    }
    fn scan_header_chain_range(
        &self,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.scan_header_chain_range(lo, hi),
            StateBackendKind::Digest(d) => d.scan_header_chain_range(lo, hi),
        }
    }
    fn store_header(&self, header_id: &[u8; 32], header_bytes: &[u8]) -> Result<(), StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.store_header(header_id, header_bytes),
            StateBackendKind::Digest(d) => d.store_header(header_id, header_bytes),
        }
    }
    fn store_validated_header(
        &mut self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
        meta: &HeaderMeta,
        new_best: Option<(u32, Vec<u8>)>,
    ) -> Result<(), StateError> {
        match self {
            StateBackendKind::Utxo(s) => {
                s.store_validated_header(header_id, header_bytes, meta, new_best)
            }
            StateBackendKind::Digest(d) => {
                d.store_validated_header(header_id, header_bytes, meta, new_best)
            }
        }
    }
    fn store_block_section_typed(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
    ) -> Result<(), StateError> {
        match self {
            StateBackendKind::Utxo(s) => {
                s.store_block_section_typed(modifier_id, section_bytes, section_type)
            }
            StateBackendKind::Digest(d) => {
                d.store_block_section_typed(modifier_id, section_bytes, section_type)
            }
        }
    }
    fn begin_header_batch(&mut self) {
        match self {
            StateBackendKind::Utxo(s) => s.begin_header_batch(),
            StateBackendKind::Digest(d) => d.begin_header_batch(),
        }
    }
    fn flush_header_batch(&mut self) -> Result<(), StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.flush_header_batch(),
            StateBackendKind::Digest(d) => d.flush_header_batch(),
        }
    }
    fn mark_session_invalid(&mut self, header_id: [u8; 32]) {
        match self {
            StateBackendKind::Utxo(s) => s.mark_session_invalid(header_id),
            StateBackendKind::Digest(d) => d.mark_session_invalid(header_id),
        }
    }
    fn is_invalid(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.is_invalid(header_id),
            StateBackendKind::Digest(d) => d.is_invalid(header_id),
        }
    }
    fn reader_handle(&self) -> crate::reader::ChainStoreReader {
        match self {
            StateBackendKind::Utxo(s) => s.reader_handle(),
            StateBackendKind::Digest(d) => d.reader_handle(),
        }
    }
    fn shutdown_cleanly(&mut self) -> Result<(), StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.shutdown_cleanly(),
            StateBackendKind::Digest(d) => d.shutdown_cleanly(),
        }
    }
}

impl BlockApply for StateBackendKind {
    fn apply_full_block(
        &mut self,
        block: &ergo_validation::block::CheckedBlock,
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
    ) -> Result<(), StateError> {
        match self {
            StateBackendKind::Utxo(s) => s.apply_full_block(block, voted_params_row, wallet_hook),
            StateBackendKind::Digest(d) => d.apply_full_block(block, voted_params_row, wallet_hook),
        }
    }
    fn rollback_to(
        &mut self,
        target_height: u32,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
        rescan_guard: Option<&dyn crate::wallet::apply::RescanGuard>,
    ) -> Result<(), StateError> {
        match self {
            // `DigestStateStore` has an inherent `rollback_to(height)`
            // that shadows the trait method on a plain `d.rollback_to`
            // call, so name the trait explicitly here.
            StateBackendKind::Utxo(s) => s.rollback_to(target_height, wallet_hook, rescan_guard),
            StateBackendKind::Digest(d) => {
                BlockApply::rollback_to(d, target_height, wallet_hook, rescan_guard)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_store::DigestStateStore;

    // ----- helpers -----

    fn utxo_backend() -> (StateBackendKind, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.redb");
        let store = StateStore::open(&path).expect("open utxo store");
        (StateBackendKind::Utxo(store), dir)
    }

    fn digest_backend() -> (StateBackendKind, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("digest_state.redb");
        let store = DigestStateStore::open(
            &path,
            ergo_validation::scala_launch(),
            ergo_chain_spec::VotingParams::mainnet(),
            ergo_chain_spec::GenesisParams::mainnet().state_digest,
        )
        .expect("open digest store");
        (StateBackendKind::Digest(store), dir)
    }

    // ----- happy path -----

    #[test]
    fn both_variants_dispatch_chain_state_read_through_enum() {
        let (utxo, _u) = utxo_backend();
        let (digest, _d) = digest_backend();

        // Fresh stores: both backends boot at the genesis tip.
        assert_eq!(ChainStateRead::height(&utxo), 0);
        assert_eq!(ChainStateRead::height(&digest), 0);

        // `chain_state_meta` forwards to each inner backend's owned
        // snapshot; a fresh tip is height 0 with the all-zero header id.
        assert_eq!(utxo.chain_state_meta().best_full_block_height, 0);
        assert_eq!(digest.chain_state_meta().best_full_block_height, 0);
        assert_eq!(utxo.chain_state_meta().best_header_id, [0u8; 32]);
        assert_eq!(digest.chain_state_meta().best_header_id, [0u8; 32]);
    }

    #[test]
    fn as_utxo_is_some_for_utxo_and_none_for_digest() {
        let (utxo, _u) = utxo_backend();
        let (digest, _d) = digest_backend();

        assert!(utxo.as_utxo().is_some());
        assert!(digest.as_utxo().is_none());
    }

    #[test]
    fn as_utxo_mut_is_some_for_utxo_and_none_for_digest() {
        let (mut utxo, _u) = utxo_backend();
        let (mut digest, _d) = digest_backend();

        assert!(utxo.as_utxo_mut().is_some());
        assert!(digest.as_utxo_mut().is_none());
    }

    #[test]
    fn state_root_digest_matches_each_backend_root() {
        let (mut utxo, _u) = utxo_backend();
        let (mut digest, _d) = digest_backend();

        // UTXO: the backend-agnostic accessor returns the same AVL+ root
        // as reading it directly through the concrete store.
        let direct = *utxo.as_utxo_mut().expect("utxo").root_digest().as_bytes();
        assert_eq!(utxo.state_root_digest(), direct);

        // Digest: a fresh store's verified root is the network genesis
        // digest the backend was seeded with (NOT a UTXO assumption / panic).
        let genesis = ergo_chain_spec::GenesisParams::mainnet().state_digest;
        assert_eq!(digest.state_root_digest(), genesis);
    }
}
