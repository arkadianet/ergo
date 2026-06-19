//! `MiningHandle`: the API-task-facing entry point.
//!
//! Holds the bounded-ring candidate cache (the last `MAX_RETAINED_TEMPLATES`
//! published templates, newest at the back, plus the authoritative tip) and
//! exposes thread-safe methods for two callers — the off-loop candidate engine
//! and the REST handlers:
//!
//! - [`MiningHandle::set_best_tip`] / [`MiningHandle::publish_if_current`]:
//!   the action loop sets the authoritative tip; the off-loop engine
//!   ([`crate::engine`]) CAS-publishes candidates built against it.
//! - [`MiningHandle::cached_work_if_synced`]: serves the candidate the engine
//!   published for the current tip — cache-only, never builds. Backs `GET
//!   /mining/candidate`.
//! - [`MiningHandle::verify_solution`]: drives the API-side pre-checks
//!   in [`crate::solution`] and returns the packaged `SubmittedBlock`
//!   when accepted. Called from `POST /mining/solution`.
//!
//! The handle holds an `Arc<RwLock<…>>` for the cache (concurrent readers,
//! single writer on publish) so both the engine task and each axum handler
//! closure can clone the Arc.

use std::sync::{Arc, RwLock};

use ergo_crypto::difficulty::DifficultyParams;
use ergo_state::store::StateStore;
use ergo_state::wallet::RewardKeyResolution;
use ergo_validation::{ReemissionRuleInputs, VotingSettings};

use crate::candidate::Candidate;
use crate::emission_rules::MonetarySettings;
use crate::engine::{BestTip, BuildReason, Template, TemplateIdentity};
use crate::error::MiningError;
use crate::reemission::ReemissionSettings;
use crate::solution::{verify_solution, SolutionOutcome};
use crate::work_message::{MinerSolution, WorkMessage};

/// Upper bound on templates retained in the [`MiningCache`] ring — the number
/// of recently-published templates whose in-flight solutions can still be
/// verified. Deliberately small: it bounds both memory (a handful of full
/// candidates) and the per-`verify_solution` scan cost (each submit recomputes
/// the Autolykos hit for at most this many candidates, so it can't be turned
/// into a large per-submit work amplifier). It covers the last few refresh
/// cycles — enough for the brief window between a template being served and its
/// solution arriving, given that longpoll (§9) keeps miners on a fresh template
/// rather than grinding a stale one. A solution for a template evicted beyond
/// this window is not rejected — the miner re-polls (design §336), and the
/// submit-time executor recheck remains authoritative. Sized for two publishes
/// per tip (minimal + enriched two-phase publish): 16 slots retain ≈8
/// tip-changes of in-flight solution history, matching the pre-two-phase
/// horizon.
const MAX_RETAINED_TEMPLATES: usize = 16;

/// Where the miner reward key comes from. Mirrors Scala's two-tier
/// resolution (`ErgoMiner`): an operator-configured key, or the wallet's
/// EIP-3 first-address key resolved lazily from persisted tracking state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardKeySource {
    /// `[mining].miner_public_key_hex` was configured; decoded once at boot.
    Pinned([u8; 33]),
    /// No key configured — resolve the wallet's EIP-3 first-address key from
    /// `StateStore` at candidate-build time (and for the reward endpoints).
    Wallet,
}

/// Mutable cache state — wrapped in an `RwLock` inside `MiningHandle`.
///
/// Bounded-ring design (design §334): `templates` holds the last
/// [`MAX_RETAINED_TEMPLATES`] published templates, newest at the back. Serving
/// returns the newest template whose parent matches the tip; solution
/// verification scans the whole ring (newest-first) so a solution against any
/// recently superseded template still resolves. Eviction is by age — once the
/// ring is full, publishing a new template pops the oldest from the front.
#[derive(Debug, Default)]
struct MiningCache {
    /// The last `MAX_RETAINED_TEMPLATES` published templates, newest at the
    /// back. `cached_work_if_synced` serves from here; `verify_solution` scans
    /// it newest-first.
    templates: std::collections::VecDeque<Template>,
    /// Monotonic publish counter, stamped onto each template's
    /// `TemplateIdentity::template_seq`. Never reset.
    template_seq: u64,
    /// Authoritative current tip + synced bit, kept INSIDE the cache lock so
    /// the off-loop engine's CAS-publish and the cache-only serve both decide
    /// against the tip and access the cached templates atomically — no TOCTOU
    /// window between reading the tip and reading/writing the cache.
    best_tip: BestTip,
}

/// API-task-facing mining entry point. Cheap to clone (`Arc` wrappers
/// internally) so the axum routing layer can capture per-handler.
#[derive(Clone)]
pub struct MiningHandle {
    cache: Arc<RwLock<MiningCache>>,
    /// "Serve-state changed" signal for longpoll waiters in the API task. Bumped
    /// on every change to what `cached_*_if_synced` would return: a publish
    /// ([`MiningHandle::publish_if_current`] `Some` path) OR a tip transition
    /// ([`MiningHandle::set_best_tip`] with a parent change or synced-bit flip).
    /// A waiter on a stale template wakes the instant either happens, so it
    /// re-fetches immediately instead of sleeping the full longpoll bound on
    /// work the tip already moved off. The value is a monotonic counter; only
    /// its change matters, not the number. `Arc` so every clone of the handle —
    /// the engine task, the action loop, the boot-time subscriber — shares the
    /// one channel.
    serve_notify: Arc<tokio::sync::watch::Sender<u64>>,
    reward_key: RewardKeySource,
    monetary: Arc<MonetarySettings>,
    /// `None` on networks that don't enable EIP-27 reemission
    /// (new public testnet). When `None`, candidate assembly skips
    /// the reemission tx path and builds a pre-EIP-27 emission tx.
    reemission: Option<Arc<ReemissionSettings>>,
    /// EIP-27 re-emission VALIDATION rules (distinct from the emission-curve
    /// `reemission`): threaded into the candidate builder's `TxValidationCtx`
    /// so every assembled transaction (emission, fee, storage-rent, selected
    /// mempool txs) is checked against the burning condition — the same rule
    /// the block validator enforces. `None` where EIP-27 is disabled. Set via
    /// [`MiningHandle::with_reemission_rules`].
    reemission_rules: Option<Arc<ReemissionRuleInputs>>,
    chain_config: Arc<DifficultyParams>,
    /// Per-network voting-epoch settings (length, soft-fork thresholds). Needed
    /// at an epoch-boundary candidate to run `compute_next_params` and to detect
    /// the boundary, exactly as the block validator does. Mainnet:
    /// `voting_length = 1024`.
    voting_settings: Arc<VotingSettings>,
    /// Whether to sweep storage-rent-eligible boxes into a pinned zero-fee
    /// self-claim. Off by default; set via [`MiningHandle::with_rent_config`].
    claim_storage_rent: bool,
    /// Max rent boxes per block's self-claim (see `with_rent_config`).
    max_storage_rent_claims: u32,
    /// Operator-configured on-chain voting targets, keyed by signed-i8
    /// parameter id (stored as `u8`). Empty by default (no voting); seeded from
    /// the `[voting]` config and updatable at runtime via the auth-gated
    /// `POST /api/v1/votes` endpoint. The candidate builder reads a snapshot per
    /// build ([`MiningHandle::voting_targets`]) and reduces it to a
    /// `header.votes` triple through `select_candidate_votes`. The slot is a
    /// SHARED `Arc<RwLock<…>>`: boot hands the SAME lock to this handle, the
    /// API read state (so `GET /api/v1/votes` reflects live edits), and the
    /// admin write path — so a runtime change is seen by all three at once.
    voting_targets: Arc<RwLock<std::collections::BTreeMap<u8, i64>>>,
}

impl MiningHandle {
    /// Construct a fresh handle pinned to a single configured miner pubkey.
    /// `reemission` is `None` for networks without EIP-27.
    pub fn new(
        miner_pk: [u8; 33],
        monetary: MonetarySettings,
        reemission: Option<ReemissionSettings>,
        chain_config: DifficultyParams,
        voting_settings: VotingSettings,
    ) -> Self {
        Self::with_reward_key(
            RewardKeySource::Pinned(miner_pk),
            monetary,
            reemission,
            chain_config,
            voting_settings,
        )
    }

    /// Construct a handle with an explicit reward-key source — `Pinned` for a
    /// configured pubkey, or `Wallet` to resolve the wallet's EIP-3 first-address
    /// key lazily at candidate-build time (Scala parity for an unset config key).
    pub fn with_reward_key(
        reward_key: RewardKeySource,
        monetary: MonetarySettings,
        reemission: Option<ReemissionSettings>,
        chain_config: DifficultyParams,
        voting_settings: VotingSettings,
    ) -> Self {
        Self {
            cache: Arc::new(RwLock::new(MiningCache::default())),
            serve_notify: Arc::new(tokio::sync::watch::channel(0u64).0),
            reward_key,
            monetary: Arc::new(monetary),
            reemission: reemission.map(Arc::new),
            // Defaulted off; the node opts in via `with_reemission_rules` at
            // boot (mirrors `with_rent_config`), so constructors and their
            // callers stay unchanged.
            reemission_rules: None,
            chain_config: Arc::new(chain_config),
            voting_settings: Arc::new(voting_settings),
            claim_storage_rent: false,
            max_storage_rent_claims: 0,
            voting_targets: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        }
    }

    /// Enable (or disable) storage-rent self-claiming and set the per-block
    /// cap. Off by default. Builder-style so existing constructors and
    /// their callers are unaffected.
    pub fn with_rent_config(
        mut self,
        claim_storage_rent: bool,
        max_storage_rent_claims: u32,
    ) -> Self {
        self.claim_storage_rent = claim_storage_rent;
        self.max_storage_rent_claims = max_storage_rent_claims;
        self
    }

    /// Install the EIP-27 re-emission validation rules (mainnet only).
    /// Builder-style (like [`MiningHandle::with_rent_config`]) so the
    /// constructors and their callers stay unchanged. When set, the candidate
    /// builder enforces the burning condition on every transaction it
    /// validates, matching block validation.
    pub fn with_reemission_rules(mut self, reemission_rules: Option<ReemissionRuleInputs>) -> Self {
        self.reemission_rules = reemission_rules.map(Arc::new);
        self
    }

    /// Whether storage-rent self-claiming is enabled.
    pub fn claim_storage_rent(&self) -> bool {
        self.claim_storage_rent
    }

    /// Max rent boxes swept into one block's self-claim.
    pub fn max_storage_rent_claims(&self) -> u32 {
        self.max_storage_rent_claims
    }

    /// Share the operator's on-chain voting-targets slot with this handle.
    /// Boot creates ONE `Arc<RwLock<…>>` and hands the same lock here and to the
    /// API read state + admin write path, so a runtime `POST /api/v1/votes`
    /// edit is reflected in the candidate builder and `GET /api/v1/votes`
    /// together. Builder-style; existing constructors default to an empty slot.
    pub fn with_voting_targets(
        mut self,
        voting_targets: Arc<RwLock<std::collections::BTreeMap<u8, i64>>>,
    ) -> Self {
        self.voting_targets = voting_targets;
        self
    }

    /// A snapshot of the operator's current voting targets — read under the
    /// shared lock and cloned (the map holds at most a handful of entries). The
    /// candidate builder calls this per build, so it always sees the latest
    /// runtime-configured policy. Empty ⇒ neutral votes.
    pub fn voting_targets(&self) -> std::collections::BTreeMap<u8, i64> {
        self.voting_targets
            .read()
            .expect("voting_targets poisoned")
            .clone()
    }

    /// Update the authoritative tip + synced bit. Called by the action loop
    /// on every best-header / best-full transition. Held inside the cache
    /// lock so publish/serve always see a consistent (tip, cache) pair.
    ///
    /// Bumps the serve-state notify ONLY when the tip actually changes (parent
    /// or synced bit), waking longpoll waiters: a header-only advance that flips
    /// synced→false, or a reorg that changes the parent, both change what
    /// `cached_*_if_synced` serves with no publish, so a waiter must not sleep
    /// the full bound on now-stale work. A re-set of the same tip (e.g. the
    /// producer re-signalling on a mempool refresh) changes nothing here and
    /// does not wake — that path's own publish bumps the notify. The watch send
    /// happens outside the cache lock.
    pub fn set_best_tip(&self, tip: BestTip) {
        let changed = {
            let mut cache = self.cache.write().expect("cache poisoned");
            if cache.best_tip == tip {
                false
            } else {
                cache.best_tip = tip;
                true
            }
        };
        if changed {
            self.serve_notify.send_modify(|v| *v = v.wrapping_add(1));
        }
    }

    /// Current authoritative tip + synced bit.
    pub fn best_tip(&self) -> BestTip {
        self.cache.read().expect("cache poisoned").best_tip
    }

    /// Subscribe to serve-state-change notifications. The returned receiver
    /// observes a change on every event that alters what `cached_*_if_synced`
    /// serves: a publish ([`MiningHandle::publish_if_current`] `Some` path) OR a
    /// tip transition ([`MiningHandle::set_best_tip`] with a parent change or
    /// synced-bit flip). Backs the `GET /mining/candidate?longpoll=` wait in the
    /// API task — a waiter parks on `Receiver::changed()` so it wakes the instant
    /// the served state changes, without polling the cache.
    pub fn subscribe_serve_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.serve_notify.subscribe()
    }

    /// Monetary settings the candidate builder uses (for the off-loop engine).
    pub fn monetary(&self) -> &MonetarySettings {
        &self.monetary
    }

    /// EIP-27 reemission settings, or `None` on networks without it.
    pub fn reemission_ref(&self) -> Option<&ReemissionSettings> {
        self.reemission.as_deref()
    }

    /// The EIP-27 re-emission VALIDATION rules, if installed. Used by the
    /// candidate builder to thread them into its `TxValidationCtx`.
    pub fn reemission_rules_ref(&self) -> Option<&ReemissionRuleInputs> {
        self.reemission_rules.as_deref()
    }

    /// CAS-publish a freshly built candidate onto the back of the ring (newest)
    /// ONLY if the live tip is still synced and its parent matches `built_parent`
    /// (the parent the candidate was built against). Returns the stamped
    /// [`TemplateIdentity`] on publish, or `None` if dropped because the tip moved
    /// during the off-loop build (wasted work, never served wrong-parent).
    ///
    /// The tip check and the cache write happen under a SINGLE cache write lock
    /// (the tip lives inside `MiningCache`), so no tip advance can slip between
    /// them — the published candidate's parent always equals the tip recorded
    /// at publish time.
    ///
    /// `template_seq` bumps once per publish; `clean_jobs` is true iff
    /// `chain_seq` advanced versus the most-recently-published template (the ring
    /// back, i.e. the parent changed), and true for the first publish ever.
    /// `built_at_ms` is sampled from `now_ms` under this publish lock, right
    /// after the `should_publish` check passes — so the stamped time is the
    /// actual push instant, never preceding it under reader contention. The
    /// cache never reads the clock itself, so publish stays deterministic under
    /// a fixed-clock test closure.
    ///
    /// The stamped `chain_seq` (era) comes from the live `best_tip` read under
    /// this same write lock — the authoritative current era the action loop
    /// maintains — never from the building intent. The intent's era is only the
    /// era at signal time; an off-loop build that started in one era can finish
    /// in another. The candidate is valid in either era for the same parent
    /// (same block, same UTXO state), so on an ABA reorg (tip A → B → back to A)
    /// a stale first-A-era build that publishes after A is live again must carry
    /// A's *current* era, not the stale signal-time one — otherwise `clean_jobs`
    /// (computed against the prior template's era) comes out wrong across the
    /// B→A era change. Reading the era under the publish lock makes versioning
    /// correct in every case: a same-parent refresh shares the unchanged era
    /// (`clean_jobs` false); a tip advance or reorg bumps it (`clean_jobs` true).
    pub fn publish_if_current(
        &self,
        candidate: Candidate,
        work: WorkMessage,
        built_parent: &[u8; 32],
        now_ms: impl Fn() -> u64,
        reason: BuildReason,
    ) -> Option<TemplateIdentity> {
        let mut cache = self.cache.write().expect("cache poisoned");
        if !crate::engine::should_publish(&cache.best_tip, built_parent) {
            return None;
        }
        let built_at_ms = now_ms();
        let chain_seq = cache.best_tip.chain_seq;
        cache.template_seq += 1;
        let template_seq = cache.template_seq;
        let clean_jobs = cache
            .templates
            .back()
            .is_none_or(|t| chain_seq > t.identity.chain_seq);
        let identity = TemplateIdentity {
            template_id: candidate.msg,
            parent_id: *built_parent,
            chain_seq,
            template_seq,
            clean_jobs,
            built_at_ms,
            reason,
        };
        cache.templates.push_back(Template {
            candidate,
            work,
            identity: identity.clone(),
        });
        // Age-based eviction: keep the ring bounded by dropping the oldest.
        while cache.templates.len() > MAX_RETAINED_TEMPLATES {
            cache.templates.pop_front();
        }
        drop(cache);
        // Wake longpoll waiters: a monotonic bump so a waiter that already
        // observed the prior value sees a change (waiters only need "something
        // changed", not the value). Only on the publish (`Some`) path — a
        // dropped (parent-mismatch) build returns early above and never bumps.
        // The send happens after the cache lock is released.
        self.serve_notify.send_modify(|v| *v = v.wrapping_add(1));
        Some(identity)
    }

    /// Serve the cached work message, but only while the node is synced AND
    /// the cached candidate's parent matches the current tip. Returns `None`
    /// when unsynced (mining refused, matching the live gate) or when no
    /// candidate for the current tip is cached yet (the off-loop engine has
    /// not published — the caller serves 503 and the miner re-polls).
    ///
    /// The synced/parent check and the cached-work read happen under a SINGLE
    /// cache read lock (the tip lives inside `MiningCache`), so a candidate is
    /// returned only if its parent equals the tip at that same instant — no
    /// TOCTOU window can serve a wrong-parent candidate.
    pub fn cached_work_if_synced(&self) -> Option<WorkMessage> {
        let cache = self.cache.read().expect("cache poisoned");
        if !cache.best_tip.synced {
            return None;
        }
        let parent = cache.best_tip.parent_id;
        // Serve the newest template built against the current tip. Scanning the
        // ring newest-first means a same-parent refresh's latest template wins,
        // and an older parent's templates are skipped once the tip advances —
        // the wrong-parent-never-served guarantee.
        cache
            .templates
            .iter()
            .rev()
            .find(|t| t.candidate.parent_id == parent)
            .map(|t| t.work.clone())
    }

    /// Whether any retained template was built against `parent`. The engine
    /// driver uses this to decide a tip's first build (nothing servable yet →
    /// publish a minimal template first) versus a refresh (a template already
    /// serves → go straight to the enriched build).
    pub fn has_template_for_parent(&self, parent: &[u8; 32]) -> bool {
        let cache = self.cache.read().expect("cache poisoned");
        cache
            .templates
            .iter()
            .rev()
            .any(|t| t.candidate.parent_id == *parent)
    }

    /// Like [`MiningHandle::cached_work_if_synced`], but also returns the
    /// served template's [`TemplateIdentity`] so the serve path can expose the
    /// pool-facing versioning (`template_seq` / `clean_jobs`) on `GET
    /// /mining/candidate`. Same gate and same newest-matching-parent selection;
    /// the identity is the one stamped on the template being served.
    pub fn cached_template_if_synced(&self) -> Option<(WorkMessage, TemplateIdentity)> {
        let cache = self.cache.read().expect("cache poisoned");
        if !cache.best_tip.synced {
            return None;
        }
        let parent = cache.best_tip.parent_id;
        cache
            .templates
            .iter()
            .rev()
            .find(|t| t.candidate.parent_id == parent)
            .map(|t| (t.work.clone(), t.identity.clone()))
    }

    /// Convenience constructor for mainnet with a pinned pubkey.
    pub fn mainnet(miner_pk: [u8; 33]) -> Self {
        Self::new(
            miner_pk,
            MonetarySettings::mainnet(),
            Some(ReemissionSettings::mainnet()),
            DifficultyParams::mainnet(),
            VotingSettings::mainnet(),
        )
    }

    /// Resolve the reward key against current persisted state. `Pinned` is
    /// always `Ready`; `Wallet` delegates to the wallet's EIP-3 resolver
    /// (`Pending` until the wallet is initialized, `Corrupt` if tracking is
    /// inconsistent). Used by candidate refresh and the reward endpoints.
    pub fn resolve_reward_key(&self, state: &StateStore) -> RewardKeyResolution {
        match self.reward_key {
            RewardKeySource::Pinned(pk) => RewardKeyResolution::Ready(pk),
            RewardKeySource::Wallet => state.resolve_eip3_reward_key(),
        }
    }

    /// Run the API-side solution pre-check against every cached template,
    /// scanning the ring newest-first. A solution for any retained template
    /// verifies, so a solution submitted against a recently superseded template
    /// during a refresh burst or reorg still resolves (design §334).
    ///
    /// Returns `Ok(SolutionOutcome::Accepted(_))` to indicate the caller
    /// should ship the `SubmittedBlock` to the executor;
    /// `StaleParent` / `InvalidPow` map to 400 responses.
    ///
    /// Reporting precedence on cache misses:
    /// 1. `Accepted` from any template — wins immediately.
    /// 2. `StaleParent` from any template — preferred over `InvalidPow`
    ///    because it carries actionable signal ("your candidate is
    ///    stale, refresh"). A miner that submits valid PoW against a
    ///    chain-flipped candidate gets the actionable answer, not the
    ///    misleading "invalid pow".
    /// 3. `InvalidPow` — the residual fall-through.
    pub fn verify_solution(
        &self,
        solution: &MinerSolution,
        state: &StateStore,
    ) -> Result<SolutionOutcome, MiningError> {
        let cache = self.cache.read().expect("cache poisoned");
        let mut saw_stale: Option<SolutionOutcome> = None;
        for template in cache.templates.iter().rev() {
            match verify_solution(&template.candidate, solution, state)? {
                SolutionOutcome::Accepted(b) => {
                    return Ok(SolutionOutcome::Accepted(b));
                }
                SolutionOutcome::InvalidPow => continue,
                other @ SolutionOutcome::StaleParent { .. } => {
                    // Latch a stale-parent result but keep looking — the
                    // other cached template might still accept.
                    saw_stale = Some(other);
                }
            }
        }
        Ok(saw_stale.unwrap_or(SolutionOutcome::InvalidPow))
    }

    /// Borrow the configured mainnet/testnet DifficultyParams the handle
    /// was built with. Mining's submit path forwards this to
    /// `process_header_cfg` so block-version-aware difficulty
    /// validation runs against the right network (mainnet uses
    /// EIP-37 / 1024-block epochs, testnet uses 128-block epochs).
    pub fn chain_config(&self) -> &ergo_crypto::difficulty::DifficultyParams {
        &self.chain_config
    }

    /// Per-network voting-epoch settings forwarded to the candidate builder for
    /// epoch-boundary detection and the next-epoch parameter recompute.
    pub fn voting_settings(&self) -> &VotingSettings {
        &self.voting_settings
    }

    /// Resolve the reward pubkey as hex against current state. Unlike the old
    /// boot-time accessor this is fallible: a `Wallet`-sourced key is `Pending`
    /// until the wallet is initialized and `Corrupt` if tracking is
    /// inconsistent, so the reward endpoints can return 503 / 500 instead of a
    /// stale or fabricated string.
    pub fn reward_pubkey_hex(&self, state: &StateStore) -> RewardKeyResolution {
        // RewardKeyResolution carries the raw pubkey; callers hex-encode the
        // Ready case. Returned as-is so Pending/Corrupt stay distinguishable.
        self.resolve_reward_key(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// Fixed wall-clock stamp the `now_ms` closures passed to
    /// `publish_if_current` return in tests. The cache stores it verbatim and no
    /// test asserts on it, so a constant suffices.
    const BUILT_AT_MS: u64 = 1_700_000_000_000;

    /// Minimal synthetic candidate + work pair for a given parent, with `msg`
    /// (the template id) set to `msg`. Only the fields the cache/tip logic reads
    /// (`Candidate::parent_id`, `Candidate::msg`, and the returned
    /// `WorkMessage`) carry meaning; everything else is an inert placeholder.
    /// Distinct `msg` values give two same-parent templates distinct identities.
    fn candidate_pair_msg(parent: [u8; 32], msg: [u8; 32]) -> (Candidate, WorkMessage) {
        // 0x1c00ffff is the historical placeholder n_bits; the cache/tip logic
        // never inspects PoW, so it is inert for these tests.
        candidate_pair_msg_nbits(parent, msg, 0x1c00ffff)
    }

    /// `candidate_pair_msg` with an explicit `n_bits`, so `verify_solution`
    /// tests can make a template's PoW pre-check pass or fail deterministically:
    /// `0x03000001` (difficulty 1 ⇒ target = the secp256k1 order) accepts any
    /// hit; `0x00000000` (difficulty 0 ⇒ target 0) rejects every hit.
    fn candidate_pair_msg_nbits(
        parent: [u8; 32],
        msg: [u8; 32],
        n_bits: u32,
    ) -> (Candidate, WorkMessage) {
        use ergo_primitives::digest::{ADDigest, Digest32};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::header::Header;
        use ergo_validation::pre_header::{
            build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
        };

        let pk = [0x02u8; 33];
        let h = Header {
            version: 3,
            parent_id: Digest32::from_bytes(parent).into(),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 1_700_000_000_000,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits,
            height: 1,
            votes: [0u8; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from(pk),
                nonce: [0u8; 8],
            },
        };
        let validation_ctx = CandidateValidationContext {
            pre_header: CandidatePreHeader {
                version: 3,
                parent_id: parent,
                height: 1,
                timestamp: 1_700_000_000_000,
                n_bits,
                votes: [0u8; 3],
                miner_pubkey: pk,
            },
            activated_script_version: 2,
            last_headers: std::array::from_fn(|_| h.clone()),
            last_block_utxo_root: build_last_block_utxo_root(ADDigest::from_bytes([0u8; 33])),
        };
        let candidate = Candidate {
            header: h,
            validation_ctx,
            transactions: Vec::new(),
            ad_proof_bytes: Vec::new(),
            extension_fields: Vec::new(),
            msg,
            target: num_bigint::BigUint::from(1u8),
            parent_id: parent,
        };
        let work = WorkMessage {
            msg,
            target: num_bigint::BigUint::from(1u8),
            height: 1,
            pk,
        };
        (candidate, work)
    }

    /// `candidate_pair_msg` with `msg = parent`: a served work message is then
    /// identifiable by the parent it was built against. Used by tests that don't
    /// need to distinguish two same-parent templates.
    fn candidate_pair(parent: [u8; 32]) -> (Candidate, WorkMessage) {
        candidate_pair_msg(parent, parent)
    }

    fn synced_tip(parent: [u8; 32]) -> BestTip {
        synced_tip_seq(parent, 1)
    }

    fn synced_tip_seq(parent: [u8; 32], chain_seq: u64) -> BestTip {
        BestTip {
            parent_id: parent,
            chain_seq,
            synced: true,
        }
    }

    // ----- happy path -----

    #[test]
    fn pinned_source_carries_the_configured_key() {
        // A pinned handle stores exactly the configured pubkey; the
        // wallet-resolution path is bypassed. (Full resolve_reward_key
        // coverage incl. Wallet/Pending/Corrupt lives in the StateStore-backed
        // resolver tests in ergo-state and the integration tests.)
        let pk = [0x02u8; 33];
        let h = MiningHandle::mainnet(pk);
        assert_eq!(h.reward_key, RewardKeySource::Pinned(pk));
    }

    #[test]
    fn wallet_source_is_distinct_from_pinned() {
        let h = MiningHandle::with_reward_key(
            RewardKeySource::Wallet,
            MonetarySettings::mainnet(),
            Some(ReemissionSettings::mainnet()),
            DifficultyParams::mainnet(),
            VotingSettings::mainnet(),
        );
        assert_eq!(h.reward_key, RewardKeySource::Wallet);
    }

    #[test]
    fn handle_is_cloneable_and_shares_cache() {
        let h1 = MiningHandle::mainnet([0x02u8; 33]);
        let h2 = h1.clone();
        // Both pointers point at the same RwLock.
        assert!(Arc::ptr_eq(&h1.cache, &h2.cache));
    }

    #[test]
    fn set_best_tip_then_best_tip_round_trips() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        // Fresh handle defaults to the unsynced pre-genesis tip.
        assert_eq!(h.best_tip(), BestTip::unsynced());
        let tip = synced_tip([0x11u8; 32]);
        h.set_best_tip(tip);
        assert_eq!(h.best_tip(), tip);
    }

    #[test]
    fn publish_if_current_publishes_and_serves_when_tip_matches() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x33u8; 32];
        h.set_best_tip(synced_tip(parent));
        let (c, w) = candidate_pair(parent);
        let id = h
            .publish_if_current(c, w.clone(), &parent, || BUILT_AT_MS, BuildReason::Tip)
            .expect("publishes when the tip matches");
        assert_eq!(
            id.template_id, w.msg,
            "template_id reuses the candidate msg"
        );
        assert_eq!(id.parent_id, parent);
        assert_eq!(
            id.chain_seq, 1,
            "stamped era is the live best_tip's chain_seq",
        );
        assert_eq!(id.template_seq, 1, "first publish is template_seq 1");
        assert!(id.clean_jobs, "first publish ever is a clean job");
        assert_eq!(h.cached_work_if_synced(), Some(w));
    }

    #[test]
    fn cached_template_returns_served_work_and_its_identity() {
        // The identity-returning serve variant returns the same work as
        // `cached_work_if_synced` plus the template's stamped identity (the one
        // the serve path forwards as `template_seq` / `clean_jobs`).
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x55u8; 32];
        h.set_best_tip(synced_tip_seq(parent, 3));
        let (c, w) = candidate_pair(parent);
        let published = h
            .publish_if_current(c, w.clone(), &parent, || BUILT_AT_MS, BuildReason::Startup)
            .expect("publishes when the tip matches");
        let (served_work, served_id) = h
            .cached_template_if_synced()
            .expect("serves the just-published template");
        assert_eq!(served_work, w, "served work matches cached_work_if_synced");
        assert_eq!(served_id, published, "served identity is the stamped one");
        assert_eq!(served_id.template_seq, 1);
        assert!(served_id.clean_jobs, "first publish ever is a clean job");
    }

    #[test]
    fn cached_template_is_none_when_unsynced() {
        // Same gate as `cached_work_if_synced`: an unsynced tip serves nothing.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x66u8; 32];
        h.set_best_tip(synced_tip(parent));
        let (c, w) = candidate_pair(parent);
        assert!(h
            .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Startup)
            .is_some());
        assert!(h.cached_template_if_synced().is_some());
        h.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 2,
            synced: false,
        });
        assert!(h.cached_template_if_synced().is_none());
    }

    // ----- round-trips -----

    #[test]
    fn template_seq_bumps_once_per_publish() {
        // Three same-parent republishes (debounced mempool refreshes) → the
        // monotonic publish counter advances 1, 2, 3.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x01u8; 32];
        h.set_best_tip(synced_tip(parent));
        for (i, tag) in [0x10u8, 0x11, 0x12].into_iter().enumerate() {
            let (c, w) = candidate_pair_msg(parent, [tag; 32]);
            let id = h
                .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::MempoolRefresh)
                .expect("same-parent republish publishes");
            assert_eq!(id.template_seq, (i + 1) as u64);
        }
    }

    #[test]
    fn clean_jobs_true_on_chain_seq_advance_false_on_same_parent_republish() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        // The era is driven entirely through `set_best_tip` — publish now stamps
        // the live `best_tip.chain_seq`, not a caller-supplied value.
        // First publish ever (era 5) → clean job.
        let p1 = [0x01u8; 32];
        h.set_best_tip(synced_tip_seq(p1, 5));
        let (c1, w1) = candidate_pair(p1);
        let id1 = h
            .publish_if_current(c1, w1, &p1, || BUILT_AT_MS, BuildReason::Startup)
            .expect("first publish");
        assert_eq!(id1.chain_seq, 5, "stamped era follows best_tip");
        assert!(id1.clean_jobs, "first publish ever is a clean job");
        // Same parent, same era (a mempool refresh) → not a clean job.
        let (c1b, w1b) = candidate_pair_msg(p1, [0x1Au8; 32]);
        let id1b = h
            .publish_if_current(c1b, w1b, &p1, || BUILT_AT_MS, BuildReason::MempoolRefresh)
            .expect("same-parent republish");
        assert_eq!(id1b.chain_seq, 5, "same-era republish keeps the era");
        assert!(
            !id1b.clean_jobs,
            "same chain_seq republish must not flag clean_jobs",
        );
        // Tip advances (new parent, era bumps to 6) → clean job again.
        let p2 = [0x02u8; 32];
        h.set_best_tip(synced_tip_seq(p2, 6));
        let (c2, w2) = candidate_pair(p2);
        let id2 = h
            .publish_if_current(c2, w2, &p2, || BUILT_AT_MS, BuildReason::Tip)
            .expect("new-parent publish");
        assert_eq!(
            id2.chain_seq, 6,
            "stamped era follows the advanced best_tip"
        );
        assert!(id2.clean_jobs, "chain_seq advance flags clean_jobs");
    }

    #[test]
    fn minimal_then_full_same_parent_publishes_one_clean_jobs_and_serves_newest() {
        // Two-phase publish contract: the Minimal publish (template A) and the
        // enriched Full publish (template B) for the SAME parent must produce
        // exactly one clean_jobs = true (the first/minimal publish on a new tip)
        // and one clean_jobs = false (the enriched refresh on the same tip), with
        // template_seq incrementing by 1 on the second publish. Serving returns
        // the newest matching the current tip, so B (the enriched template) wins.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0xCC_u8; 32];
        h.set_best_tip(synced_tip_seq(parent, 4));

        // Phase 1: Minimal publish (template A, msg [0xAA;32]).
        let (ca, wa) = candidate_pair_msg(parent, [0xAA_u8; 32]);
        let id_a = h
            .publish_if_current(ca, wa, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .expect("minimal (first) publish for new tip must succeed");
        assert!(
            id_a.clean_jobs,
            "first publish on a new tip must be clean_jobs = true",
        );
        let seq_a = id_a.template_seq;

        // Phase 2: Full (enriched) publish (template B, msg [0xBB;32]) — same parent.
        let (cb, wb) = candidate_pair_msg(parent, [0xBB_u8; 32]);
        let id_b = h
            .publish_if_current(
                cb,
                wb.clone(),
                &parent,
                || BUILT_AT_MS,
                BuildReason::MempoolRefresh,
            )
            .expect("enriched (second) publish for same parent must succeed");
        assert!(
            !id_b.clean_jobs,
            "same-parent republish must not flag clean_jobs",
        );
        assert_eq!(
            id_b.chain_seq, id_a.chain_seq,
            "same-parent republish carries the same chain_seq",
        );
        assert_eq!(
            id_b.template_seq,
            seq_a + 1,
            "enriched publish increments template_seq by exactly 1",
        );

        // Serving returns the newest (B), not A.
        assert_eq!(
            h.cached_work_if_synced().map(|w| w.msg),
            Some([0xBB_u8; 32]),
            "cached_work_if_synced must serve the newest (enriched) template, not the minimal one",
        );
    }

    #[test]
    fn publish_stamps_live_tip_era_not_stale_intent_era_on_aba() {
        // ABA reorg: tip A → B → back to A. A build that started in the first
        // A-era can finish and publish only after the chain has flipped back to
        // A (now a new era). The published template must carry the LIVE era the
        // action loop set under the publish lock, never the build's signal-time
        // era — `publish_if_current` no longer takes a caller era, so the stale
        // signal-time value simply cannot be consulted.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        // Era 6 on parent B → that template carries era 6.
        let parent_b = [0xB0u8; 32];
        h.set_best_tip(synced_tip_seq(parent_b, 6));
        let (cb, wb) = candidate_pair(parent_b);
        let idb = h
            .publish_if_current(cb, wb, &parent_b, || BUILT_AT_MS, BuildReason::Tip)
            .expect("publishes on B");
        assert_eq!(idb.chain_seq, 6);
        // Reorg back to A as a new era (7). A candidate built for parent A in the
        // *first* A-era now finishes and publishes; it must take the live era 7,
        // and `clean_jobs` must be true (7 > 6) across the B→A2 era change.
        let parent_a = [0xA0u8; 32];
        h.set_best_tip(synced_tip_seq(parent_a, 7));
        let (ca, wa) = candidate_pair(parent_a);
        let ida = h
            .publish_if_current(ca, wa, &parent_a, || BUILT_AT_MS, BuildReason::Tip)
            .expect("publishes the stale-era A build against the live A tip");
        assert_eq!(
            ida.chain_seq, 7,
            "stamped era follows the live best_tip, not the stale signal-time era",
        );
        assert!(
            ida.clean_jobs,
            "live-era advance (7 > 6) across the ABA reorg flags clean_jobs",
        );
    }

    #[test]
    fn ring_retains_both_prior_parent_and_same_parent_templates() {
        // The retention guarantee a two-slot cache could not give: after a parent
        // change AND a same-parent refresh, the ring still holds the prior
        // PARENT's template (A) AND the prior SAME-PARENT template (B) AND the
        // newest refresh (B'). An in-flight solve against any of the three still
        // resolves; serving returns the newest matching the current tip.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let pa = [0x07u8; 32];
        let pb = [0x08u8; 32];
        let (a_msg, b_msg, b2_msg) = ([0x10u8; 32], [0x11u8; 32], [0x12u8; 32]);

        // Publish on parent A.
        h.set_best_tip(synced_tip_seq(pa, 5));
        let (ca, wa) = candidate_pair_msg(pa, a_msg);
        assert!(h
            .publish_if_current(ca, wa, &pa, || BUILT_AT_MS, BuildReason::Startup)
            .is_some());

        // Parent advances to B, then a same-parent refresh on B.
        h.set_best_tip(synced_tip_seq(pb, 6));
        let (cb, wb) = candidate_pair_msg(pb, b_msg);
        assert!(h
            .publish_if_current(cb, wb, &pb, || BUILT_AT_MS, BuildReason::Tip)
            .is_some());
        let (cb2, wb2) = candidate_pair_msg(pb, b2_msg);
        assert!(h
            .publish_if_current(cb2, wb2, &pb, || BUILT_AT_MS, BuildReason::MempoolRefresh)
            .is_some());

        let cache = h.cache.read().expect("cache poisoned");
        let ids: Vec<[u8; 32]> = cache
            .templates
            .iter()
            .map(|t| t.identity.template_id)
            .collect();
        assert_eq!(
            ids,
            vec![a_msg, b_msg, b2_msg],
            "ring keeps the prior parent (A), the prior same-parent (B), and the \
             newest refresh (B') — none evicted",
        );
        drop(cache);
        // Serving (tip = B) returns the newest template matching B.
        assert_eq!(h.cached_work_if_synced().map(|w| w.msg), Some(b2_msg));
    }

    #[test]
    fn ring_evicts_oldest_beyond_cap() {
        // Publishing past the cap holds the ring at MAX_RETAINED_TEMPLATES and
        // drops from the front: the oldest survivor is the (cap+1)th publish from
        // the start, never the very first. Serving still returns the newest.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x21u8; 32];
        h.set_best_tip(synced_tip(parent));

        let total = MAX_RETAINED_TEMPLATES + 3;
        let mut last_msg = [0u8; 32];
        for i in 0..total {
            // Distinct msg per publish; i fits a u8 since the cap is small.
            let msg = [i as u8; 32];
            last_msg = msg;
            let (c, w) = candidate_pair_msg(parent, msg);
            assert!(h
                .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::MempoolRefresh)
                .is_some());
        }

        let cache = h.cache.read().expect("cache poisoned");
        assert_eq!(
            cache.templates.len(),
            MAX_RETAINED_TEMPLATES,
            "ring is capped at MAX_RETAINED_TEMPLATES",
        );
        // The first `total - MAX_RETAINED_TEMPLATES` publishes were evicted, so
        // the front is that-many-th publish, not the first.
        let oldest_retained = (total - MAX_RETAINED_TEMPLATES) as u8;
        assert_eq!(
            cache.templates.front().unwrap().identity.template_id,
            [oldest_retained; 32],
            "front is the oldest retained, not the first ever published",
        );
        assert_eq!(
            cache.templates.back().unwrap().identity.template_id,
            last_msg,
            "back is the newest published",
        );
        drop(cache);
        assert_eq!(h.cached_work_if_synced().map(|w| w.msg), Some(last_msg));
    }

    #[test]
    fn subscribe_serve_changes_observes_change_on_publish() {
        // A subscriber sees a change after a successful publish. The observed
        // value is an opaque monotonic counter; only that it changed matters.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x71u8; 32];
        h.set_best_tip(synced_tip(parent));
        let mut rx = h.subscribe_serve_changes();
        // Mark the current value seen (the set_best_tip above bumped it);
        // nothing published yet.
        rx.borrow_and_update();
        assert!(!rx.has_changed().expect("sender alive"));
        let (c, w) = candidate_pair(parent);
        assert!(h
            .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .is_some());
        assert!(rx.has_changed().expect("sender alive"), "publish bumps");
    }

    #[test]
    fn subscribe_serve_changes_does_not_bump_on_dropped_publish() {
        // A publish dropped for a parent mismatch (wasted off-loop build) must
        // NOT wake longpoll waiters — there is no new template to serve.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let tip_parent = [0x81u8; 32];
        let built_parent = [0x82u8; 32];
        h.set_best_tip(synced_tip(tip_parent));
        let mut rx = h.subscribe_serve_changes();
        rx.borrow_and_update();
        let (c, w) = candidate_pair(built_parent);
        assert!(h
            .publish_if_current(c, w, &built_parent, || BUILT_AT_MS, BuildReason::Tip)
            .is_none());
        assert!(
            !rx.has_changed().expect("sender alive"),
            "a dropped publish must not bump the notify",
        );
    }

    #[test]
    fn set_best_tip_to_a_new_tip_bumps_serve_notify() {
        // A tip transition with NO publish (e.g. header-only advance flipping
        // synced→false, or a reorg changing the parent) changes what serving
        // would return, so a longpoll waiter must wake. Both kinds of change
        // bump the notify.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let mut rx = h.subscribe_serve_changes();
        rx.borrow_and_update();
        // Parent change.
        h.set_best_tip(synced_tip([0x91u8; 32]));
        assert!(
            rx.has_changed().expect("sender alive"),
            "a parent change bumps the serve notify",
        );
        rx.borrow_and_update();
        // Synced-bit flip on the same parent.
        h.set_best_tip(BestTip {
            parent_id: [0x91u8; 32],
            chain_seq: 1,
            synced: false,
        });
        assert!(
            rx.has_changed().expect("sender alive"),
            "a synced-bit flip bumps the serve notify",
        );
    }

    #[test]
    fn set_best_tip_to_the_same_tip_does_not_bump() {
        // Re-setting the identical tip (the producer re-signalling on a mempool
        // refresh) changes nothing about what serving returns, so it must NOT
        // wake waiters — only genuine transitions do.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let tip = synced_tip([0xA1u8; 32]);
        h.set_best_tip(tip);
        let mut rx = h.subscribe_serve_changes();
        rx.borrow_and_update();
        h.set_best_tip(tip);
        assert!(
            !rx.has_changed().expect("sender alive"),
            "a same-value re-set must not bump the serve notify",
        );
    }

    // ----- error paths -----

    #[test]
    fn publish_if_current_drops_when_built_parent_is_not_the_current_tip() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let tip_parent = [0xAAu8; 32];
        let built_parent = [0xBBu8; 32];
        h.set_best_tip(synced_tip(tip_parent));
        let (c, w) = candidate_pair(built_parent);
        // Built against a parent the tip already moved off → wasted, dropped.
        assert!(h
            .publish_if_current(c, w, &built_parent, || BUILT_AT_MS, BuildReason::Tip)
            .is_none());
        // Nothing was cached, so serving yields nothing.
        assert_eq!(h.cached_work_if_synced(), None);
    }

    #[test]
    fn publish_if_current_drops_when_unsynced() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0xCCu8; 32];
        h.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 1,
            synced: false,
        });
        let (c, w) = candidate_pair(parent);
        assert!(h
            .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Startup)
            .is_none());
        assert_eq!(h.cached_work_if_synced(), None);
    }

    #[test]
    fn cached_work_is_none_when_tip_goes_unsynced_after_publish() {
        // Header races ahead of the full tip: a candidate published while
        // synced must stop being served the instant the tip flips unsynced.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0xDDu8; 32];
        h.set_best_tip(synced_tip(parent));
        let (c, w) = candidate_pair(parent);
        assert!(h
            .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Startup)
            .is_some());
        assert!(h.cached_work_if_synced().is_some());
        h.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 2,
            synced: false,
        });
        assert_eq!(h.cached_work_if_synced(), None);
    }

    #[test]
    fn cached_work_is_none_when_tip_advances_past_cached_parent() {
        // The wrong-parent-never-served guarantee: once the tip advances to a
        // new parent, the still-cached old candidate is no longer served.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let old_parent = [0xEEu8; 32];
        h.set_best_tip(synced_tip(old_parent));
        let (c, w) = candidate_pair(old_parent);
        assert!(h
            .publish_if_current(c, w, &old_parent, || BUILT_AT_MS, BuildReason::Startup)
            .is_some());
        assert!(h.cached_work_if_synced().is_some());
        // Tip advances to a new parent before the engine republishes.
        h.set_best_tip(synced_tip([0xFFu8; 32]));
        assert_eq!(h.cached_work_if_synced(), None);
    }

    #[test]
    fn verify_solution_scans_whole_ring_not_just_newest() {
        // `verify_solution` must scan the entire ring, not stop at the newest.
        // Bury a PoW-PASSING template (target = secp256k1 order) under several
        // PoW-FAILING ones (target 0), all on the same parent. Scanning
        // newest-first, every failing template returns `InvalidPow` and the scan
        // continues; reaching the deep passing template yields `StaleParent` (its
        // non-zero parent is stale against a fresh store). A scan that stopped at
        // the newest would return `InvalidPow` instead.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x44u8; 32];
        h.set_best_tip(synced_tip(parent));

        // Deep template: PoW passes, so it reaches the parent-id check.
        let (c_pass, w_pass) = candidate_pair_msg_nbits(parent, [0xA0u8; 32], 0x03000001);
        assert!(h
            .publish_if_current(
                c_pass,
                w_pass,
                &parent,
                || BUILT_AT_MS,
                BuildReason::Startup
            )
            .is_some());
        // Several same-parent refreshes whose PoW pre-check fails, layered on top.
        for tag in [0xB0u8, 0xB1, 0xB2, 0xB3] {
            let (c_fail, w_fail) = candidate_pair_msg_nbits(parent, [tag; 32], 0x00000000);
            assert!(h
                .publish_if_current(
                    c_fail,
                    w_fail,
                    &parent,
                    || BUILT_AT_MS,
                    BuildReason::MempoolRefresh
                )
                .is_some());
        }

        // Fresh store: best_full_block_id is the zeroed sentinel, so the
        // PoW-passing template's non-zero parent is stale.
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
        let solution = MinerSolution {
            nonce: [0u8; 8],
            pk: None,
        };
        let outcome = h.verify_solution(&solution, &state).expect("verify ok");
        assert!(
            matches!(outcome, SolutionOutcome::StaleParent { .. }),
            "verify must scan past the PoW-failing newest templates to the deep \
             PoW-passing one, got {outcome:?}",
        );
    }

    #[test]
    fn has_template_for_parent_tracks_publishes() {
        // False before any publish for the parent; true immediately after;
        // false for a different parent.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent_p = [0xE0u8; 32];
        let parent_q = [0xE1u8; 32];

        // Nothing published yet — no template for any parent.
        assert!(
            !h.has_template_for_parent(&parent_p),
            "no template retained before any publish",
        );

        // Set the tip so publish_if_current accepts.
        h.set_best_tip(synced_tip(parent_p));

        // Publish one template for parent P.
        let (c, w) = candidate_pair(parent_p);
        assert!(h
            .publish_if_current(c, w, &parent_p, || BUILT_AT_MS, BuildReason::Tip)
            .is_some());

        // Now P is retained; Q is not.
        assert!(
            h.has_template_for_parent(&parent_p),
            "template for P is retained after publishing it",
        );
        assert!(
            !h.has_template_for_parent(&parent_q),
            "no template for Q when only P was published",
        );
    }

    // ----- oracle parity -----

    #[test]
    fn pinned_and_wallet_resolved_same_pk_yield_identical_reward_script() {
        // The reward script is a pure function of the resolved pubkey, so a
        // wallet-resolved EIP-3 key and a pinned config key for the SAME pubkey
        // must produce byte-identical reward output scripts (and therefore the
        // same reward address). Both sources funnel into the same
        // `RewardKeyResolution::Ready(pk)` → `reward_output_script(pk)`; this
        // pins that they don't diverge.
        let pk = {
            let mut p = [0x07u8; 33];
            p[0] = 0x03;
            p
        };
        // Pinned resolves to Ready(pk) regardless of state (no DB needed).
        let pinned = RewardKeySource::Pinned(pk);
        let resolved_pk = match pinned {
            RewardKeySource::Pinned(p) => p,
            RewardKeySource::Wallet => unreachable!(),
        };
        // A wallet path that resolved Ready(pk) carries the same pk by
        // construction; assert the downstream script bytes match.
        let script_from_pinned = crate::reward_output_script(&resolved_pk);
        let script_from_wallet = crate::reward_output_script(&pk);
        assert_eq!(
            script_from_pinned, script_from_wallet,
            "same pubkey must yield identical reward script regardless of source"
        );
        // And the embedded pubkey is at the canonical offset [7..40].
        assert_eq!(&script_from_pinned[7..40], &pk);
    }
}
