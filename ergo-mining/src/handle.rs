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
//! - [`MiningHandle::withdraw_templates_for_parent`]: the solution handler
//!   withdraws the templates on a parent whose mined child became the best
//!   header and then failed to apply.
//!
//! The handle holds an `Arc<RwLock<…>>` for the cache (concurrent readers,
//! single writer on publish) so both the engine task and each axum handler
//! closure can clone the Arc.

use std::sync::{Arc, Mutex, RwLock};

use ergo_primitives::digest::Digest32;

use ergo_crypto::difficulty::DifficultyParams;
use ergo_state::store::StateStore;
use ergo_state::wallet::RewardKeyResolution;
use ergo_validation::{ReemissionRuleInputs, VotingSettings};

use crate::candidate::Candidate;
use crate::config::ResolvedExtensionFields;
use crate::emission_rules::MonetarySettings;
use crate::engine::{BestTip, BuildReason, Template, TemplateIdentity};
use crate::error::MiningError;
use crate::extension_builder::validate_custom_extension_fields;

/// The subset of a field set whose values are known without reading anything —
/// used for the boot-time validation pass.
fn statically_known(fields: &[crate::config::ExtensionFieldSource]) -> Vec<([u8; 2], Vec<u8>)> {
    fields
        .iter()
        .map(|f| {
            let v = match &f.value {
                crate::config::ExtensionValueSource::Static(v) => v.clone(),
                // Not yet readable; the size check runs per build. An empty
                // stand-in still exercises the key's namespace/duplicate checks.
                crate::config::ExtensionValueSource::File(_) => Vec::new(),
            };
            (f.key, v)
        })
        .collect()
}

/// Upper bound on bytes read from a `value_file`, in hex-text form. The
/// decoded value is capped at
/// [`ergo_validation::block::EXTENSION_FIELD_VALUE_MAX_SIZE`] bytes by rule
/// 404; hex-encoding doubles that, and a small allowance covers an optional
/// `0x`/`0X` prefix plus surrounding whitespace/newline. Kept well short of
/// "reasonable config file" sizes so a large or corrupted file is rejected
/// from a bounded read rather than loaded in full first.
const MAX_VALUE_FILE_BYTES: usize = 2 * ergo_validation::block::EXTENSION_FIELD_VALUE_MAX_SIZE + 16;

/// Why a `value_file` read did not produce a value to decode.
enum ReadValueFileError {
    /// The file does not exist yet — the steady state before a writer has
    /// published anything.
    NotFound,
    /// More than [`MAX_VALUE_FILE_BYTES`] were read without reaching EOF.
    TooLarge,
    /// Any other I/O failure (permissions, not-a-file, …).
    Io(std::io::Error),
}

/// Read `path` as UTF-8 text, bounded at [`MAX_VALUE_FILE_BYTES`].
///
/// Reads at most `MAX_VALUE_FILE_BYTES + 1` bytes via `Read::take` — an
/// oversized or corrupted file is rejected from that bounded read, never
/// loaded in full first (a `File` open + capped read, not
/// `std::fs::read_to_string`, so a huge `value_file` cannot exhaust node
/// memory on every candidate build).
fn read_value_file_bounded(path: &std::path::Path) -> Result<String, ReadValueFileError> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReadValueFileError::NotFound)
        }
        Err(e) => return Err(ReadValueFileError::Io(e)),
    };
    let mut buf = Vec::with_capacity(MAX_VALUE_FILE_BYTES.min(4096));
    file.take(MAX_VALUE_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(ReadValueFileError::Io)?;
    if buf.len() > MAX_VALUE_FILE_BYTES {
        return Err(ReadValueFileError::TooLarge);
    }
    String::from_utf8(buf).map_err(|e| {
        ReadValueFileError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })
}

use crate::reemission::ReemissionSettings;
use crate::solution::{verify_solution, SolutionOutcome, SubmittedBlock};
use crate::work_message::{MinerSolution, WorkMessage};

/// Ordinary template history, independent of requested work.
pub const MAX_RETAINED_TEMPLATES: usize = 16;
/// Requested work shares a bounded budget, with stale/withdrawn jobs evicted first.
/// Charge at least 64 KiB per job to bound scans even for tiny candidates.
pub const MAX_REQUESTED_TEMPLATE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_REQUESTED_TEMPLATES: usize = MAX_REQUESTED_TEMPLATE_BYTES / (64 * 1024);
pub const REQUESTED_GENERATION_INTERVAL_MS: u64 = 60_000;
/// Time for a miner to submit a solution after its last reusable reply.
pub const REQUESTED_SOLUTION_GRACE_MS: u64 = 30_000;
/// Bounded lifecycle event retention; events reset on node restart.
pub const MAX_MINING_OUTCOMES: usize = 128;

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
/// Bounded-ring design: `templates` holds the last
/// ordinary templates plus per-key requested histories, newest at the back. Serving
/// returns the newest offered template whose parent matches the tip; solution
/// verification scans the whole ring (newest-first) so a solution against any
/// recently superseded template still resolves. Eviction is by age — once the
/// ordinary ring is full, its oldest member is evicted; requested work has a
/// separate per-key limit and byte budget. A
/// mined block's failed apply withdraws every template on its parent
/// ([`MiningHandle::withdraw_templates_for_parent`]): a withdrawn template is
/// no longer offered, and ages out of the ring like any other.
#[derive(Debug, Default)]
struct MiningCache {
    /// Retained ordinary and requested histories, newest at the back. `cached_work_if_synced` serves from the offered ones;
    /// `verify_solution` scans them all newest-first.
    templates: std::collections::VecDeque<RetainedTemplate>,
    /// Monotonic publish counter, stamped onto each template's
    /// `TemplateIdentity::template_seq`. Never reset.
    template_seq: u64,
    operator_generation: u64,
    /// Authoritative current tip + synced bit, kept INSIDE the cache lock so
    /// the off-loop engine's CAS-publish and the cache-only serve both decide
    /// against the tip and access the cached templates atomically — no TOCTOU
    /// window between reading the tip and reading/writing the cache.
    best_tip: BestTip,
}

/// A published template in the [`MiningCache`] ring.
#[derive(Debug)]
struct RetainedTemplate {
    template: Arc<Template>,
    /// Set by [`MiningHandle::withdraw_templates_for_parent`] once a block
    /// mined on the template's parent became the best header and failed to
    /// apply. A withdrawn template is never served, never counts as the
    /// parent's template, and a solution to it is answered stale rather than
    /// accepted.
    withdrawn: bool,
    requested_weight: usize,
    last_served_ms: u64,
}

fn template_status(
    retained: &RetainedTemplate,
    parent: [u8; 32],
    current_sequence: Option<u64>,
) -> &'static str {
    if retained.withdrawn {
        "withdrawn"
    } else if retained.template.candidate.parent_id != parent {
        "stale_parent"
    } else if current_sequence == Some(retained.template.identity.template_seq) {
        "current"
    } else {
        "superseded"
    }
}

impl MiningCache {
    /// The templates still offered to miners (not withdrawn), newest first.
    fn offered(&self) -> impl Iterator<Item = &Template> {
        self.templates
            .iter()
            .rev()
            .filter(|t| !t.withdrawn)
            .map(|t| t.template.as_ref())
    }

    /// Plan all evictions before changing history. Recently served live jobs
    /// keep their solution window even when a new package cannot fit.
    fn requested_evictions(&self, weight: usize, pk: [u8; 33], now_ms: u64) -> Option<Vec<usize>> {
        if weight > MAX_REQUESTED_TEMPLATE_BYTES {
            return None;
        }
        let live = |t: &RetainedTemplate| {
            !t.withdrawn && t.template.candidate.parent_id == self.best_tip.parent_id
        };
        let mut eligible: Vec<_> = self
            .templates
            .iter()
            .enumerate()
            .filter(|(_, t)| t.requested_weight != 0)
            .filter(|(_, t)| {
                !live(t)
                    || now_ms.saturating_sub(t.last_served_ms)
                        >= REQUESTED_GENERATION_INTERVAL_MS + REQUESTED_SOLUTION_GRACE_MS
            })
            .collect();
        eligible.sort_by_key(|(_, t)| (live(t), t.last_served_ms));
        let mut bytes = self
            .templates
            .iter()
            .map(|t| t.requested_weight)
            .sum::<usize>();
        let mut count = self
            .templates
            .iter()
            .filter(|t| t.requested_weight != 0 && t.template.work.pk == pk)
            .count();
        let mut removed = Vec::new();
        for (index, t) in &eligible {
            if count < MAX_RETAINED_TEMPLATES {
                break;
            }
            if t.template.work.pk == pk {
                removed.push(*index);
                count -= 1;
                bytes -= t.requested_weight;
            }
        }
        if count >= MAX_RETAINED_TEMPLATES {
            return None;
        }
        for (index, t) in eligible {
            if bytes <= MAX_REQUESTED_TEMPLATE_BYTES - weight {
                break;
            }
            if !removed.contains(&index) {
                removed.push(index);
                bytes -= t.requested_weight;
            }
        }
        (bytes <= MAX_REQUESTED_TEMPLATE_BYTES - weight).then_some(removed)
    }

    /// The newest offered template built on `parent`.
    fn newest_offered_on(&self, parent: &[u8; 32]) -> Option<&Template> {
        self.offered().find(|t| {
            t.candidate.parent_id == *parent && t.identity.reason != BuildReason::Requested
        })
    }
}

/// API-task-facing mining entry point. Cheap to clone (`Arc` wrappers
/// internally) so the axum routing layer can capture per-handler.
#[derive(Clone)]
pub struct MiningHandle {
    cache: Arc<RwLock<MiningCache>>,
    /// "Serve-state changed" signal for longpoll waiters in the API task. Bumped
    /// on changes to the ordinary served work: an ordinary publish
    /// ([`MiningHandle::publish_if_current`] `Some` path), a tip transition
    /// ([`MiningHandle::set_best_tip`] with a parent change or synced-bit flip),
    /// or a withdrawal ([`MiningHandle::withdraw_templates_for_parent`]
    /// withdrawing any). A waiter on a stale template wakes the instant any of
    /// these happens, so it re-fetches immediately instead of sleeping the full
    /// longpoll bound on work that is no longer served. The value is a
    /// monotonic counter; only its change matters, not the number. `Arc` so
    /// every clone of the handle — the engine task, the action loop, the
    /// boot-time subscriber — shares the one channel.
    serve_notify: Arc<tokio::sync::watch::Sender<u64>>,
    private_queue: Arc<crate::private_queue::PrivateTransactionQueue>,
    policy: Arc<RwLock<(u64, crate::policy::BlockPolicy)>>,
    /// Serializes policy edits across their file I/O; see `set_policy`.
    policy_edit: Arc<Mutex<()>>,
    policy_store: Option<Arc<std::path::PathBuf>>,
    outcomes: Arc<Mutex<crate::outcome_journal::OutcomeJournal>>,
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
    network: ergo_chain_spec::Network,
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
    /// Operator-configured custom extension fields injected into every
    /// candidate's extension (the general merge-mining / commitment hook, e.g.
    /// an Aegis `0xAE00` block commitment). Empty by default; set + validated via
    /// [`MiningHandle::with_extension_fields`]. `Arc` so every clone of the handle
    /// shares the one immutable config.
    custom_extension_fields: Arc<Vec<crate::config::ExtensionFieldSource>>,
    /// Ids of pooled txs whose consensus re-validation failed
    /// during the most recent published Full build (suspected tip-invalid). The
    /// off-loop build worker records them here ([`MiningHandle::record_suspects`])
    /// and the action loop drains them ([`MiningHandle::take_suspects`]) to
    /// re-validate against the live tip and evict the still-invalid ones. A
    /// SEPARATE `Mutex` (not the serve `cache` `RwLock`) so this best-effort pool
    /// hint never contends with — or couples to — the consensus serve path.
    /// Latest-wins: each published build replaces the slot.
    suspects: Arc<Mutex<Vec<Digest32>>>,
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
            private_queue: Arc::new(crate::private_queue::PrivateTransactionQueue::default()),
            policy: Arc::new(RwLock::new((0, crate::policy::BlockPolicy::default()))),
            policy_edit: Arc::new(Mutex::new(())),
            policy_store: None,
            outcomes: Arc::new(Mutex::new(crate::outcome_journal::OutcomeJournal::default())),
            reward_key,
            monetary: Arc::new(monetary),
            reemission: reemission.map(Arc::new),
            // Defaulted off; the node opts in via `with_reemission_rules` at
            // boot (mirrors `with_rent_config`), so constructors and their
            // callers stay unchanged.
            reemission_rules: None,
            chain_config: Arc::new(chain_config),
            network: ergo_chain_spec::Network::Mainnet,
            voting_settings: Arc::new(voting_settings),
            claim_storage_rent: false,
            max_storage_rent_claims: 0,
            custom_extension_fields: Arc::new(Vec::new()),
            voting_targets: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            suspects: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Install the node-owned durable operator queue at startup.
    pub fn with_private_queue(
        mut self,
        queue: Arc<crate::private_queue::PrivateTransactionQueue>,
    ) -> Self {
        self.private_queue = queue;
        self
    }

    /// This queue is separate from peer relay, public mempool and explorer APIs.
    pub fn private_queue(&self) -> Arc<crate::private_queue::PrivateTransactionQueue> {
        self.private_queue.clone()
    }

    /// Install a validated initial policy without changing its revision.
    pub fn with_policy(self, policy: crate::policy::BlockPolicy) -> Result<Self, MiningError> {
        policy.validate()?;
        *self.policy.write().expect("policy poisoned") = (0, policy);
        Ok(self)
    }

    /// Snapshot the policy and its revision under one lock.
    pub fn policy_snapshot(&self) -> (u64, crate::policy::BlockPolicy) {
        self.policy.read().expect("policy poisoned").clone()
    }

    /// Reopen saved operator preferences at startup. A saved policy overrides
    /// the boot default; malformed state refuses startup instead of mining
    /// blocks under an unexpected fallback policy.
    pub fn with_policy_store(
        mut self,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<Self, MiningError> {
        let path = path.into();
        if let Some(policy) = crate::policy_store::load(&path)? {
            *self.policy.write().expect("policy poisoned") = (0, policy);
        }
        self.policy_store = Some(Arc::new(path));
        Ok(self)
    }

    pub fn policy(&self) -> crate::policy::BlockPolicy {
        self.policy_snapshot().1
    }

    pub fn policy_revision(&self) -> u64 {
        self.policy.read().expect("policy poisoned").0
    }

    /// Retire old templates atomically with a policy edit. The publish guard
    /// rejects builds carrying the prior revision, including in-flight builds.
    ///
    /// Blocking: saving syncs the policy file to disk, so async callers must
    /// run this off their executor. An invalid policy is
    /// [`MiningError::InvalidConfig`]; any other error is a storage failure
    /// that leaves both the saved and the active policy unchanged.
    /// `Ok(Some(warning))`: the policy is saved and active, but its directory
    /// entry could not be synced.
    pub fn set_policy(
        &self,
        policy: crate::policy::BlockPolicy,
    ) -> Result<Option<String>, MiningError> {
        policy.validate()?;
        // One edit at a time, so the saved file and the active policy change
        // in the same order. The file I/O runs before the policy lock is
        // taken: builds and publishes only ever wait for the swap below.
        let _edit = self.policy_edit.lock().expect("policy edit poisoned");
        if self.policy.read().expect("policy poisoned").1 == policy {
            return Ok(None);
        }
        let warning = match &self.policy_store {
            Some(path) => crate::policy_store::save(path, &policy)?,
            None => None,
        };
        let mut slot = self.policy.write().expect("policy poisoned");
        let mut cache = self.cache.write().expect("cache poisoned");
        slot.0 = slot
            .0
            .checked_add(1)
            .ok_or_else(|| MiningError::InvalidConfig("policy revision exhausted".into()))?;
        slot.1 = policy;
        cache.operator_generation = cache
            .operator_generation
            .checked_add(1)
            .expect("operator generation exhausted");
        for retained in &mut cache.templates {
            retained.withdrawn = true;
        }
        drop(cache);
        drop(slot);
        self.serve_notify.send_modify(|v| *v = v.wrapping_add(1));
        Ok(warning)
    }

    /// Generation frozen by a build before it reads operator queue contents.
    pub fn operator_generation(&self) -> u64 {
        self.cache
            .read()
            .expect("cache poisoned")
            .operator_generation
    }

    /// Freeze a build's operator inputs: the generation, then the queue
    /// contents `read` returns. Reading in this order means a queue change
    /// after the generation read leaves the build on the older generation, so
    /// its snapshot can never publish under the newer one.
    pub fn operator_snapshot<T>(
        &self,
        read: impl FnOnce(&crate::private_queue::PrivateTransactionQueue) -> T,
    ) -> (u64, T) {
        let generation = self.operator_generation();
        (generation, read(&self.private_queue))
    }

    /// Cancel/expire operator work and reject older in-flight builds.
    pub fn invalidate_operator_generation(&self) -> u64 {
        let mut cache = self.cache.write().expect("cache poisoned");
        cache.operator_generation = cache
            .operator_generation
            .checked_add(1)
            .expect("operator generation exhausted");
        for retained in &mut cache.templates {
            retained.withdrawn = true;
        }
        let generation = cache.operator_generation;
        drop(cache);
        self.serve_notify.send_modify(|v| *v = v.wrapping_add(1));
        generation
    }

    /// Withdraw only the retained templates that include one of `tx_ids`, so a
    /// solution found for unrelated work is still accepted. With
    /// `retire_builds`, also advance the operator generation, so a build frozen
    /// before the change can never publish one of them; callers pass it for
    /// transactions that builds may still select. Call it after the queue no
    /// longer offers them (a cancellation), or once selection filters them
    /// (an elapsed deadline): a build that reads the new generation then
    /// cannot see them either. Returns how many templates were withdrawn.
    pub fn withdraw_private_transactions(
        &self,
        tx_ids: &std::collections::HashSet<Digest32>,
        retire_builds: bool,
    ) -> usize {
        let offered: Vec<(u64, Arc<Template>)> = {
            let mut cache = self.cache.write().expect("cache poisoned");
            if retire_builds {
                cache.operator_generation = cache
                    .operator_generation
                    .checked_add(1)
                    .expect("operator generation exhausted");
            }
            cache
                .templates
                .iter()
                .filter(|t| !t.withdrawn)
                .map(|t| (t.template.identity.template_seq, t.template.clone()))
                .collect()
        };
        // Hash outside the lock. Nothing published from here on can include
        // the transactions: older builds fail the generation check, and newer
        // ones no longer select them.
        let affected: std::collections::HashSet<u64> = offered
            .iter()
            .filter(|(_, template)| {
                template
                    .private_transaction_ids()
                    .iter()
                    .any(|id| tx_ids.contains(id))
            })
            .map(|(seq, _)| *seq)
            .collect();
        if affected.is_empty() {
            return 0;
        }
        let withdrawn =
            {
                let mut cache = self.cache.write().expect("cache poisoned");
                let mut withdrawn = 0;
                for t in cache.templates.iter_mut().filter(|t| {
                    !t.withdrawn && affected.contains(&t.template.identity.template_seq)
                }) {
                    t.withdrawn = true;
                    withdrawn += 1;
                }
                withdrawn
            };
        if withdrawn > 0 {
            self.serve_notify.send_modify(|v| *v = v.wrapping_add(1));
        }
        withdrawn
    }

    /// Retained snapshot selected by both work ID and publish sequence. An
    /// absent selector chooses the current offered template; historical lookups
    /// remain available while their bounded cache entry is retained.
    pub fn inspect_template(
        &self,
        msg: Option<[u8; 32]>,
        sequence: Option<u64>,
    ) -> Option<crate::inspection::InspectionSnapshot> {
        let cache = self.cache.read().expect("cache poisoned");
        let current = cache
            .best_tip
            .synced
            .then(|| cache.newest_offered_on(&cache.best_tip.parent_id))
            .flatten();
        let retained = if msg.is_none() && sequence.is_none() {
            let seq = current?.identity.template_seq;
            cache
                .templates
                .iter()
                .find(|t| t.template.identity.template_seq == seq)?
        } else {
            cache.templates.iter().rev().find(|t| {
                msg.is_none_or(|id| t.template.candidate.msg == id)
                    && sequence.is_none_or(|seq| t.template.identity.template_seq == seq)
            })?
        };
        Some(crate::inspection::InspectionSnapshot {
            template: retained.template.clone(),
            status: template_status(
                retained,
                cache.best_tip.parent_id,
                current.map(|t| t.identity.template_seq),
            ),
        })
    }

    /// Bounded history, newest first, with a status determined under one lock.
    pub fn inspect_history(&self) -> Vec<crate::inspection::InspectionSnapshot> {
        let cache = self.cache.read().expect("cache poisoned");
        let current = cache
            .best_tip
            .synced
            .then(|| cache.newest_offered_on(&cache.best_tip.parent_id))
            .flatten()
            .map(|t| t.identity.template_seq);
        cache
            .templates
            .iter()
            .rev()
            .map(|retained| crate::inspection::InspectionSnapshot {
                template: retained.template.clone(),
                status: template_status(retained, cache.best_tip.parent_id, current),
            })
            .collect()
    }

    /// Record local solution handling. The caller must distinguish executor
    /// acceptance from PoW validity and canonical-chain confirmations.
    pub fn record_outcome(
        &self,
        msg: Option<[u8; 32]>,
        block_id: Option<[u8; 32]>,
        outcome: &str,
        detail: Option<String>,
        at_ms: u64,
    ) {
        let template = msg
            .and_then(|id| self.inspect_template(Some(id), None))
            .map(|s| s.template);
        self.append_outcome(msg, template, block_id, outcome, detail, at_ms);
    }

    /// Solved headers identify a retained job by both digest and miner key.
    /// Fee-free work after emission ends can share a digest across keys.
    pub fn record_miner_outcome(
        &self,
        identity: Option<([u8; 32], [u8; 33])>,
        block_id: Option<[u8; 32]>,
        outcome: &str,
        detail: Option<String>,
        at_ms: u64,
    ) {
        let template = identity.and_then(|(msg, pk)| {
            self.cache
                .read()
                .expect("cache poisoned")
                .templates
                .iter()
                .rev()
                .find(|t| t.template.work.msg == msg && t.template.work.pk == pk)
                .map(|t| t.template.clone())
        });
        self.append_outcome(
            identity.map(|(msg, _)| msg),
            template,
            block_id,
            outcome,
            detail,
            at_ms,
        );
    }

    fn append_outcome(
        &self,
        msg: Option<[u8; 32]>,
        template: Option<Arc<Template>>,
        block_id: Option<[u8; 32]>,
        outcome: &str,
        detail: Option<String>,
        at_ms: u64,
    ) {
        let template_seq = template.as_ref().map(|t| t.identity.template_seq);
        let accounting = (outcome == "accepted")
            .then(|| {
                template
                    .as_ref()
                    .filter(|t| {
                        t.identity.reason != BuildReason::Requested
                            || t.candidate.observation.operator_owned
                    })
                    .map(|t| crate::inspection::outcome_accounting(t, self.reemission_ref()))
            })
            .flatten();
        let detail = detail.map(|text| text.chars().take(4096).collect());
        self.outcomes
            .lock()
            .expect("outcomes poisoned")
            .append(crate::inspection::MiningOutcome {
                msg,
                template_seq,
                block_id,
                at_ms,
                outcome: outcome.chars().take(64).collect(),
                detail,
                accounting,
            });
    }

    /// Hydrate durable local submission history at boot. A file that cannot
    /// be read is moved aside rather than refusing startup, and
    /// [`MiningHandle::outcome_journal_status`] reports where it went.
    pub fn with_outcome_journal(self, path: &std::path::Path) -> Self {
        let mut journal = crate::outcome_journal::OutcomeJournal::open(path);
        for accounting in journal
            .events
            .iter_mut()
            .filter_map(|e| e.accounting.as_mut())
        {
            accounting.split_legacy_emission(self.reemission_ref());
        }
        *self.outcomes.lock().expect("outcomes poisoned") = journal;
        self
    }

    pub fn mining_outcomes(&self) -> Vec<crate::inspection::MiningOutcome> {
        self.outcomes
            .lock()
            .expect("outcomes poisoned")
            .events
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    /// Whether history persists, and its latest persistence failure or
    /// startup recovery.
    pub fn outcome_journal_status(&self) -> (bool, Option<String>) {
        let journal = self.outcomes.lock().expect("outcomes poisoned");
        (journal.persistent(), journal.error())
    }

    /// Record the suspect ids from a just-published Full build.
    /// Latest-wins: replaces any undrained set, since the newest build's
    /// suspects supersede an older build's against a now-stale tip. A poisoned
    /// lock is ignored (best-effort hint; never panic the build worker).
    pub fn record_suspects(&self, suspects: Vec<Digest32>) {
        if let Ok(mut slot) = self.suspects.lock() {
            *slot = suspects;
        }
    }

    /// Drain (take + clear) the recorded suspect ids for the action loop to
    /// re-validate against the live tip. Returns empty when nothing is pending.
    pub fn take_suspects(&self) -> Vec<Digest32> {
        match self.suspects.lock() {
            Ok(mut slot) => std::mem::take(&mut *slot),
            Err(_) => Vec::new(),
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

    /// Install operator-configured custom extension fields, injected into every
    /// candidate (the general merge-mining / commitment hook). Validated up
    /// front via [`validate_custom_extension_fields`] (rule 404 size, reserved-
    /// namespace guard, rule 405 no-duplicates) so a misconfiguration fails at
    /// boot rather than producing candidates a peer rejects. Off by default;
    /// builder-style like [`MiningHandle::with_rent_config`].
    pub fn with_extension_fields(
        mut self,
        fields: Vec<crate::config::ExtensionFieldSource>,
    ) -> Result<Self, MiningError> {
        // Everything knowable at boot: keys (namespace, duplicates) and the
        // sizes of STATIC values. A `value_file` entry's bytes are checked per
        // build in `resolve_extension_fields`, because the file is re-read then
        // and is legitimately absent now.
        validate_custom_extension_fields(&statically_known(&fields))?;
        self.custom_extension_fields = Arc::new(fields);
        Ok(self)
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
    /// or synced bit), waking longpoll waiters: a reorg that changes the parent,
    /// or the one-time `false → true` flip of the mining-started latch, both
    /// change what `cached_*_if_synced` serves with no publish, so a waiter must
    /// not sleep the full bound on now-stale work. (`synced` is a one-way latch
    /// — see [`BestTip`] — so it never flips back to `false`.) A re-set of the
    /// same tip (e.g. the producer re-signalling on a mempool refresh) changes
    /// nothing here and does not wake — that path's own publish bumps the
    /// notify. The watch send happens outside the cache lock.
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
    /// serves: a publish ([`MiningHandle::publish_if_current`] `Some` path), a
    /// tip transition ([`MiningHandle::set_best_tip`] with a parent change or
    /// synced-bit flip), or a withdrawal
    /// ([`MiningHandle::withdraw_templates_for_parent`] withdrawing any). Backs
    /// the `GET /mining/candidate?longpoll=` wait in the API task — a waiter
    /// parks on `Receiver::changed()` so it wakes the instant the served state
    /// changes, without polling the cache.
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
    /// [`TemplateIdentity`] on publish, or `None` if requested history is full of protected jobs or the tip moved
    /// during the off-loop build (wasted work, never served wrong-parent).
    ///
    /// The tip check and the cache write happen under a SINGLE cache write lock
    /// (the tip lives inside `MiningCache`), so no tip advance can slip between
    /// them — the published candidate's parent always equals the tip recorded
    /// at publish time.
    ///
    /// `template_seq` bumps once per publish; `clean_jobs` is true iff
    /// `chain_seq` advanced versus the newest offered template (i.e. the parent
    /// changed), and true when none is offered: the first publish ever, and the
    /// rebuild after a withdrawal, whose jobs a Stratum proxy must abandon.
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
        let policy = self.policy.read().expect("policy poisoned");
        let mut cache = self.cache.write().expect("cache poisoned");
        if candidate.observation.policy_revision != policy.0
            || candidate.observation.operator_generation != cache.operator_generation
        {
            return None;
        }
        if !crate::engine::should_publish(&cache.best_tip, built_parent) {
            return None;
        }
        let built_at_ms = now_ms();
        let requested_weight = if reason == BuildReason::Requested {
            let inputs_size: usize = candidate
                .observation
                .transactions
                .iter()
                .flat_map(|tx| &tx.resolved_inputs)
                .map(|box_| {
                    let mut writer = ergo_primitives::writer::VlqWriter::new();
                    if ergo_ser::ergo_box::write_ergo_box(&mut writer, box_).is_err() {
                        return MAX_REQUESTED_TEMPLATE_BYTES;
                    }
                    writer.as_slice().len()
                })
                .sum();
            let proofs_size = work.proof.as_ref().map_or(0, |proof| {
                proof.msg_preimage.len()
                    + proof
                        .tx_proofs
                        .iter()
                        .map(|p| 32 + p.levels.iter().map(Vec::len).sum::<usize>())
                        .sum::<usize>()
            });
            let encoded_size = (work.metrics.transactions_size_bytes as usize)
                .saturating_add(inputs_size)
                .saturating_add(candidate.ad_proof_bytes.len())
                .saturating_add(
                    candidate
                        .extension_fields
                        .iter()
                        .map(|(k, v)| k.len() + v.len())
                        .sum::<usize>(),
                )
                .saturating_add(proofs_size);
            encoded_size.saturating_mul(4).max(64 * 1024)
        } else {
            0
        };
        if reason == BuildReason::Requested {
            let mut evictions =
                cache.requested_evictions(requested_weight, work.pk, built_at_ms)?;
            evictions.sort_unstable_by(|a, b| b.cmp(a));
            for index in evictions {
                cache.templates.remove(index);
            }
        }
        let chain_seq = cache.best_tip.chain_seq;
        cache.template_seq += 1;
        let template_seq = cache.template_seq;
        let clean_jobs = cache
            .offered()
            .find(|t| {
                (t.identity.reason == BuildReason::Requested) == (reason == BuildReason::Requested)
            })
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
        cache.templates.push_back(RetainedTemplate {
            template: Arc::new(Template {
                candidate,
                work,
                identity: identity.clone(),
            }),
            withdrawn: false,
            requested_weight,
            last_served_ms: built_at_ms,
        });
        if reason != BuildReason::Requested {
            while cache
                .templates
                .iter()
                .filter(|t| t.requested_weight == 0)
                .count()
                > MAX_RETAINED_TEMPLATES
            {
                let index = cache
                    .templates
                    .iter()
                    .position(|t| t.requested_weight == 0)
                    .expect("ordinary retention exceeded");
                cache.templates.remove(index);
            }
        }
        drop(cache);
        // Wake longpoll waiters: a monotonic bump so a waiter that already
        // observed the prior value sees a change (waiters only need "something
        // changed", not the value). Only on the publish (`Some`) path — a
        // dropped (parent-mismatch) build returns early above and never bumps.
        // The send happens after the cache lock is released.
        if reason != BuildReason::Requested {
            self.serve_notify.send_modify(|v| *v = v.wrapping_add(1));
        }
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
        // Serve the newest offered template built against the current tip.
        // Scanning the ring newest-first means a same-parent refresh's latest
        // template wins, and an older parent's templates are skipped once the
        // tip advances — the wrong-parent-never-served guarantee.
        cache.newest_offered_on(&parent).map(|t| t.work.clone())
    }

    /// Reuse offered live-parent work for exactly the same ordered package.
    /// Ownership is frozen, so the default-key lookup needs no wallet read.
    pub fn cached_requested_package(
        &self,
        pk: Option<[u8; 33]>,
        ids: &[Digest32],
        now_ms: u64,
    ) -> Option<(WorkMessage, TemplateIdentity)> {
        let mut cache = self.cache.write().expect("cache poisoned");
        if !cache.best_tip.synced {
            return None;
        }
        let parent = cache.best_tip.parent_id;
        let found = cache
            .templates
            .iter_mut()
            .rev()
            .find(|retained| {
                let t = &retained.template;
                !retained.withdrawn
                    && t.identity.reason == BuildReason::Requested
                    && t.candidate.parent_id == parent
                    && pk.map_or(t.candidate.observation.operator_owned, |pk| t.work.pk == pk)
                    && t.candidate.observation.requested_ids == ids
                    && now_ms.saturating_sub(t.identity.built_at_ms)
                        < REQUESTED_GENERATION_INTERVAL_MS
            })
            .map(|t| {
                t.last_served_ms = t.last_served_ms.max(now_ms);
                (t.template.work.clone(), t.template.identity.clone())
            });
        drop(cache);
        found.filter(|(work, _)| {
            !self
                .private_queue
                .deadline_due(now_ms, work.height.saturating_sub(1))
        })
    }

    /// The client-requested job published as `template_seq`, read atomically
    /// with the current tip. The serial worker calls this immediately after
    /// publishing its request; matching the exact publish keeps an older
    /// requested job on the same parent (e.g. after an A→B→A tip change) from
    /// answering a different request. Ordinary GET candidate serving always
    /// uses the operator's own jobs.
    pub fn cached_requested_template_if_synced(
        &self,
        template_seq: u64,
        now_ms: u64,
    ) -> Option<(WorkMessage, TemplateIdentity)> {
        let mut cache = self.cache.write().expect("cache poisoned");
        if !cache.best_tip.synced {
            return None;
        }
        let parent = cache.best_tip.parent_id;
        let found = cache
            .templates
            .iter_mut()
            .rev()
            .find(|retained| {
                let t = &retained.template;
                !retained.withdrawn
                    && t.identity.template_seq == template_seq
                    && t.identity.reason == BuildReason::Requested
                    && t.candidate.parent_id == parent
            })
            .map(|t| {
                t.last_served_ms = t.last_served_ms.max(now_ms);
                (t.template.work.clone(), t.template.identity.clone())
            });
        found
    }

    /// Whether any offered (not withdrawn) template was built against
    /// `parent`. The engine driver uses this to decide a tip's first build
    /// (nothing servable yet → publish a minimal template first) versus a
    /// refresh (a template already serves → go straight to the enriched build).
    pub fn has_template_for_parent(&self, parent: &[u8; 32]) -> bool {
        let cache = self.cache.read().expect("cache poisoned");
        cache.newest_offered_on(parent).is_some()
    }

    /// Withdraw every offered template built on `parent`: none is served
    /// again, and a solution to one of them is answered
    /// [`SolutionOutcome::StaleParent`] instead of accepted. Wakes longpoll
    /// waiters if any was withdrawn, and returns how many were.
    ///
    /// The mining handler calls this when a locally mined block on `parent`
    /// became the best header and then failed to apply. Scala's
    /// `CandidateGenerator.onSolvedBlockFailed` drops its current and previous
    /// cached candidates then (v6.0.6 23aabead8 `CandidateGenerator.scala
    /// :94-104`), normally both on the applied tip, which is `parent` here.
    /// Templates on other parents stay offered: a solution to one of them is
    /// stale unless a reorg returns the tip to its parent.
    ///
    /// A withdrawn template stays in the ring until it ages out, so a solution
    /// the miner already found for it (valid PoW for the work it was given) is
    /// told its candidate is stale rather than that its PoW is invalid. The
    /// action loop then signals a rebuild on the tip
    /// ([`BuildReason::SolvedBlockFailed`]); until it publishes, nothing is
    /// served for the tip, as right after a tip change, and its first publish
    /// carries `clean_jobs`.
    pub fn withdraw_templates_for_parent(&self, parent: &[u8; 32]) -> usize {
        let withdrawn = {
            let mut cache = self.cache.write().expect("cache poisoned");
            let mut withdrawn = 0;
            for t in cache
                .templates
                .iter_mut()
                .filter(|t| !t.withdrawn && t.template.candidate.parent_id == *parent)
            {
                t.withdrawn = true;
                withdrawn += 1;
            }
            withdrawn
        };
        if withdrawn > 0 {
            self.serve_notify.send_modify(|v| *v = v.wrapping_add(1));
        }
        withdrawn
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
            .newest_offered_on(&parent)
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
    /// scanning the ring newest-first. A solution for any offered template
    /// verifies, so a solution submitted against a recently superseded template
    /// during a refresh burst or reorg still resolves.
    ///
    /// Returns `Ok(SolutionOutcome::Accepted(_))` to indicate the caller
    /// should ship the `SubmittedBlock` to the executor;
    /// `StaleParent` / `InvalidPow` map to 400 responses.
    ///
    /// Reporting precedence on cache misses:
    /// 1. `Accepted` from any offered template — wins immediately.
    /// 2. `StaleParent` from any template whose PoW the solution passes: an
    ///    offered one on a parent that is no longer the best full block, or a
    ///    withdrawn one ([`MiningHandle::withdraw_templates_for_parent`]),
    ///    whatever its parent. Preferred over `InvalidPow` because it carries
    ///    actionable signal ("your candidate is stale, refresh"). A miner
    ///    that submits valid PoW against a chain-flipped or withdrawn
    ///    candidate gets the actionable answer, not the misleading "invalid
    ///    pow".
    /// 3. `InvalidPow` — the residual fall-through.
    pub fn verify_solution(
        &self,
        solution: &MinerSolution,
        state: &StateStore,
    ) -> Result<SolutionOutcome, MiningError> {
        self.verify_solution_preferring(solution, state, |_| Ok(true))
    }

    /// Prefer an accepting offered template selected by the caller, falling
    /// back to the newest accepting offered template. The predicate only sees
    /// blocks with valid PoW on the live full parent, never withdrawn templates.
    /// Both preference and fallback ties resolve newest-first.
    ///
    /// The node uses this to recover a stored header with missing sections.
    /// Errors from the predicate propagate; a failed storage read must not
    /// silently select another block. The predicate runs under the cache read
    /// lock and must not mutate the handle.
    pub fn verify_solution_preferring(
        &self,
        solution: &MinerSolution,
        state: &StateStore,
        mut prefer: impl FnMut(&SubmittedBlock) -> Result<bool, MiningError>,
    ) -> Result<SolutionOutcome, MiningError> {
        let cache = self.cache.read().expect("cache poisoned");
        let mut newest = None;
        let mut saw_stale: Option<SolutionOutcome> = None;
        let selected_pk = solution.pk;
        for retained in cache.templates.iter().rev() {
            let candidate = &retained.template.candidate;
            let operator_owned = retained.template.identity.reason != BuildReason::Requested
                || candidate.observation.operator_owned;
            if selected_pk.map_or(!operator_owned, |pk| {
                pk != candidate.validation_ctx.pre_header.miner_pubkey
            }) {
                continue;
            }
            // Once a fallback accepts, only offered templates on the live full
            // parent can improve selection. Before that, PoW distinguishes
            // stale work from invalid work, including withdrawn templates.
            if newest.is_some()
                && (retained.withdrawn
                    || candidate.parent_id != state.chain_state().best_full_block_id)
            {
                continue;
            }
            #[cfg(test)]
            tests::VERIFIED_TIMESTAMPS.with_borrow_mut(|timestamps| {
                if let Some(timestamps) = timestamps {
                    timestamps.push(candidate.header.timestamp);
                }
            });
            match verify_solution(candidate, solution, state)? {
                SolutionOutcome::InvalidPow => continue,
                SolutionOutcome::Accepted(b) if !retained.withdrawn => {
                    if prefer(&b)? {
                        return Ok(SolutionOutcome::Accepted(b));
                    }
                    if newest.is_none() {
                        newest = Some(SolutionOutcome::Accepted(b));
                    }
                }
                // The PoW passes on the live parent, but the template was
                // withdrawn: the block would repeat the one that failed.
                SolutionOutcome::Accepted(_) => {
                    saw_stale = Some(SolutionOutcome::StaleParent {
                        candidate_parent: candidate.parent_id,
                        live_parent: candidate.parent_id,
                    });
                }
                // Latch a stale-parent result but keep looking — another
                // cached template might still accept.
                other @ SolutionOutcome::StaleParent { .. } => {
                    saw_stale = Some(other);
                }
            }
        }
        Ok(newest.or(saw_stale).unwrap_or(SolutionOutcome::InvalidPow))
    }

    /// Select the network whose genesis mining rules apply.
    pub fn with_network(mut self, network: ergo_chain_spec::Network) -> Self {
        self.network = network;
        self
    }

    /// Network gates private-chain genesis mining.
    pub fn network(&self) -> ergo_chain_spec::Network {
        self.network
    }

    /// Borrow the configured mainnet/testnet DifficultyParams the handle
    /// was built with. Mining's submit path forwards this to
    /// `process_header_cfg_with_genesis` so block-version-aware difficulty
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

    /// Resolve the operator-configured custom extension fields for ONE
    /// candidate build (empty unless set via
    /// [`MiningHandle::with_extension_fields`]).
    ///
    /// Static entries are returned as configured. A `value_file` entry is
    /// re-read here, which is what lets a merge-mined commitment track a moving
    /// aux-chain tip without a node restart:
    ///
    /// - missing or blank file ⇒ the field is OMITTED. That is the steady state
    ///   before the writer has published anything, and block production must
    ///   not stall on it.
    /// - malformed content ⇒ the build FAILS. The operator asked for a
    ///   commitment, so mining a block that looks committed and is not would be
    ///   worse than not mining one.
    ///
    /// The fully-resolved set is re-validated, so a file cannot smuggle in an
    /// oversized value that a peer would reject.
    pub fn resolve_extension_fields(&self) -> Result<ResolvedExtensionFields, MiningError> {
        use crate::config::ExtensionValueSource;
        let mut out = Vec::with_capacity(self.custom_extension_fields.len());
        for field in self.custom_extension_fields.iter() {
            let value = match &field.value {
                ExtensionValueSource::Static(v) => v.clone(),
                ExtensionValueSource::File(path) => match read_value_file_bounded(path) {
                    Err(ReadValueFileError::NotFound) => continue,
                    Err(ReadValueFileError::TooLarge) => {
                        return Err(MiningError::InvalidConfig(format!(
                            "[mining] extension field {:02x?} value_file {} exceeds the \
                             {MAX_VALUE_FILE_BYTES}-byte read cap",
                            field.key,
                            path.display()
                        )))
                    }
                    Err(ReadValueFileError::Io(e)) => {
                        return Err(MiningError::InvalidConfig(format!(
                            "[mining] extension field {:02x?} value_file {}: {e}",
                            field.key,
                            path.display()
                        )))
                    }
                    Ok(raw) => {
                        let trimmed = raw.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let body = trimmed
                            .strip_prefix("0x")
                            .or_else(|| trimmed.strip_prefix("0X"))
                            .unwrap_or(trimmed);
                        hex::decode(body).map_err(|e| {
                            MiningError::InvalidConfig(format!(
                                "[mining] extension field {:02x?} value_file {} is not hex: {e}",
                                field.key,
                                path.display()
                            ))
                        })?
                    }
                },
            };
            out.push((field.key, value));
        }
        validate_custom_extension_fields(&out)?;
        Ok(out)
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
    use crate::config::{ExtensionFieldSource, ExtensionValueSource};

    // ----- custom extension fields: per-build resolution -----

    /// A plain handle; only the extension-field slot matters to these tests.
    fn base_handle() -> MiningHandle {
        MiningHandle::new(
            [0x02u8; 33],
            crate::emission_rules::MonetarySettings::mainnet(),
            None,
            ergo_crypto::difficulty::DifficultyParams::mainnet(),
            ergo_validation::VotingSettings::mainnet(),
        )
    }

    /// Build a handle carrying one `value_file`-sourced field under `0xAE00`.
    fn handle_with_file(path: &std::path::Path) -> MiningHandle {
        base_handle()
            .with_extension_fields(vec![ExtensionFieldSource {
                key: [0xAE, 0x00],
                value: ExtensionValueSource::File(path.to_path_buf()),
            }])
            .expect("a file source validates at boot without existing")
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ergo-extfield-{tag}-{}.hex", std::process::id()))
    }

    /// The point of the whole feature: rewriting the file changes what the NEXT
    /// build commits, with no restart. A boot-time constant cannot express a
    /// merge-mined tip, which moves every block.
    #[test]
    fn a_file_sourced_value_is_re_read_on_every_resolve() {
        let p = tmp("moving");
        std::fs::write(&p, "aabb").unwrap();
        let h = handle_with_file(&p);
        assert_eq!(
            h.resolve_extension_fields().unwrap(),
            vec![([0xAE, 0x00], vec![0xaa, 0xbb])]
        );

        std::fs::write(&p, "ccdd").unwrap();
        assert_eq!(
            h.resolve_extension_fields().unwrap(),
            vec![([0xAE, 0x00], vec![0xcc, 0xdd])],
            "the same handle must pick up the new value"
        );
        std::fs::remove_file(&p).ok();
    }

    /// Absent or blank is the steady state before the writer publishes
    /// anything; block production must not stall on it.
    #[test]
    fn a_missing_or_blank_file_commits_nothing() {
        let p = tmp("absent");
        std::fs::remove_file(&p).ok();
        assert!(handle_with_file(&p)
            .resolve_extension_fields()
            .unwrap()
            .is_empty());

        std::fs::write(&p, "  \n").unwrap();
        assert!(handle_with_file(&p)
            .resolve_extension_fields()
            .unwrap()
            .is_empty());
        std::fs::remove_file(&p).ok();
    }

    /// Malformed content fails the build rather than quietly mining a block
    /// that looks committed and is not.
    #[test]
    fn malformed_file_content_fails_the_build() {
        let p = tmp("garbage");
        std::fs::write(&p, "not hex at all").unwrap();
        assert!(handle_with_file(&p).resolve_extension_fields().is_err());
        std::fs::remove_file(&p).ok();
    }

    /// A file value's SIZE is not knowable at boot, so the rule-404 cap has to
    /// be enforced at resolve time — otherwise a file could smuggle in a value
    /// that makes every candidate unacceptable to peers.
    #[test]
    fn an_oversized_file_value_is_rejected_at_resolve() {
        let p = tmp("oversized");
        let too_big = ergo_validation::block::EXTENSION_FIELD_VALUE_MAX_SIZE + 1;
        std::fs::write(&p, "aa".repeat(too_big)).unwrap();
        let err = handle_with_file(&p)
            .resolve_extension_fields()
            .expect_err("must reject");
        assert!(format!("{err:?}").contains("404"), "{err:?}");
        std::fs::remove_file(&p).ok();
    }

    /// A file far past the bounded-read cap must be rejected while reading —
    /// the point of the fix is that `resolve_extension_fields` never
    /// allocates the whole file first. Distinct from
    /// `an_oversized_file_value_is_rejected_at_resolve` above, which covers a
    /// file just over rule 404's decoded-byte cap (well within the bounded
    /// read) to prove the read-time cap and the rule-404 cap don't collide.
    #[test]
    fn a_file_far_over_the_read_cap_fails_at_read_time_not_after_full_load() {
        let p = tmp("way-too-large");
        // Several times MAX_VALUE_FILE_BYTES of valid hex text — if this were
        // loaded in full before any size check, it would still decode (it's
        // well-formed hex), so only a bounded read catches it here.
        let huge_hex = "aa".repeat(MAX_VALUE_FILE_BYTES * 4);
        std::fs::write(&p, &huge_hex).unwrap();
        let err = handle_with_file(&p)
            .resolve_extension_fields()
            .expect_err("must reject before decoding");
        assert!(
            format!("{err:?}").contains("read cap"),
            "expected the bounded-read error, got {err:?}"
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_static_value_still_resolves_unchanged() {
        let h = base_handle()
            .with_extension_fields(vec![ExtensionFieldSource {
                key: [0xAE, 0x00],
                value: ExtensionValueSource::Static(vec![0x01, 0x02]),
            }])
            .expect("valid");
        assert_eq!(
            h.resolve_extension_fields().unwrap(),
            vec![([0xAE, 0x00], vec![0x01, 0x02])]
        );
    }

    #[test]
    fn no_configured_fields_resolves_empty() {
        assert!(base_handle().resolve_extension_fields().unwrap().is_empty());
    }

    // ----- helpers -----

    thread_local! {
        pub(super) static VERIFIED_TIMESTAMPS: std::cell::RefCell<Option<Vec<u64>>> = const {
            std::cell::RefCell::new(None)
        };
    }

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
            last_headers: vec![h.clone(); 10],
            last_block_utxo_root: build_last_block_utxo_root(ADDigest::from_bytes([0u8; 33])),
        };
        let candidate = Candidate {
            header: h,
            validation_ctx,
            observation: Default::default(),
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
            proof: None,
            metrics: Default::default(),
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

    #[test]
    fn withdraw_templates_for_parent_withdraws_only_that_parents_templates() {
        // A mined block on parent B failed to apply: every template on B is
        // withdrawn (the minimal and the enriched one alike, as Scala drops
        // both of its cached candidates) but stays in the ring to answer its
        // in-flight solutions, while the prior parent's template stays offered
        // for a reorg back to A.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let pa = [0x0Au8; 32];
        let pb = [0x0Bu8; 32];
        h.set_best_tip(synced_tip_seq(pa, 1));
        let (ca, wa) = candidate_pair_msg(pa, [0x1Au8; 32]);
        assert!(h
            .publish_if_current(ca, wa, &pa, || BUILT_AT_MS, BuildReason::Startup)
            .is_some());
        h.set_best_tip(synced_tip_seq(pb, 2));
        for tag in [0x1Bu8, 0x2B] {
            let (c, w) = candidate_pair_msg(pb, [tag; 32]);
            assert!(h
                .publish_if_current(c, w, &pb, || BUILT_AT_MS, BuildReason::Tip)
                .is_some());
        }

        assert_eq!(h.withdraw_templates_for_parent(&pb), 2);

        let ring: Vec<([u8; 32], bool)> = h
            .cache
            .read()
            .expect("cache poisoned")
            .templates
            .iter()
            .map(|t| (t.template.identity.template_id, t.withdrawn))
            .collect();
        assert_eq!(
            ring,
            vec![
                ([0x1Au8; 32], false),
                ([0x1Bu8; 32], true),
                ([0x2Bu8; 32], true)
            ],
            "only B's templates are withdrawn, and none leaves the ring"
        );
        assert!(!h.has_template_for_parent(&pb));
        assert!(h.has_template_for_parent(&pa));
        assert_eq!(
            h.cached_template_if_synced(),
            None,
            "nothing is served on the tip until a rebuild publishes"
        );
    }

    #[test]
    fn withdraw_templates_for_parent_bumps_serve_notify_only_when_it_withdraws() {
        // A longpoll waiter parked on a withdrawn template wakes and re-fetches
        // instead of sleeping the full bound on work no solution can use; a
        // withdrawal that withdraws nothing changes nothing served.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x0Cu8; 32];
        h.set_best_tip(synced_tip(parent));
        let (c, w) = candidate_pair(parent);
        assert!(h
            .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .is_some());
        let mut rx = h.subscribe_serve_changes();
        rx.borrow_and_update();

        assert_eq!(h.withdraw_templates_for_parent(&[0x0Du8; 32]), 0);
        assert!(
            !rx.has_changed().expect("sender alive"),
            "withdrawing nothing must not wake waiters"
        );

        assert_eq!(h.withdraw_templates_for_parent(&parent), 1);
        assert!(
            rx.has_changed().expect("sender alive"),
            "withdrawing the served template wakes waiters"
        );
        rx.borrow_and_update();

        assert_eq!(
            h.withdraw_templates_for_parent(&parent),
            0,
            "an already withdrawn template is not withdrawn again"
        );
        assert!(!rx.has_changed().expect("sender alive"));
    }

    #[test]
    fn withdraw_templates_then_same_parent_publish_is_a_clean_job() {
        // After the withdrawal, the rebuild on the same tip carries clean_jobs,
        // so a Stratum proxy abandons the withdrawn jobs instead of treating
        // the fresh template as a same-parent refresh.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0x0Eu8; 32];
        h.set_best_tip(synced_tip_seq(parent, 4));
        let (c1, w1) = candidate_pair_msg(parent, [0x31u8; 32]);
        assert!(
            h.publish_if_current(c1, w1, &parent, || BUILT_AT_MS, BuildReason::Tip)
                .expect("first publish")
                .clean_jobs
        );
        let (c2, w2) = candidate_pair_msg(parent, [0x32u8; 32]);
        assert!(
            !h.publish_if_current(c2, w2, &parent, || BUILT_AT_MS, BuildReason::MempoolRefresh)
                .expect("refresh")
                .clean_jobs
        );

        h.withdraw_templates_for_parent(&parent);
        let (c3, w3) = candidate_pair_msg(parent, [0x33u8; 32]);
        let rebuilt = h
            .publish_if_current(
                c3,
                w3,
                &parent,
                || BUILT_AT_MS,
                BuildReason::SolvedBlockFailed,
            )
            .expect("the rebuild publishes on the same tip");
        assert!(rebuilt.clean_jobs, "the rebuild is a clean job");
        assert_eq!(rebuilt.template_seq, 3, "template_seq never resets");
        let (served, served_id) = h.cached_template_if_synced().expect("serves the rebuild");
        assert_eq!(served.msg, [0x33u8; 32]);
        assert_eq!(served_id, rebuilt);
    }

    #[test]
    fn verify_solution_offered_template_behind_same_parent_rebuild_accepts_its_solution() {
        // A newer template on the same parent does not hide an offered older
        // one: at a real target, a nonce that solves only the older template
        // is accepted for it. A mined header whose section write failed is
        // the best header without a body, so a tip build publishes such a
        // newer template, not a clean job since the full tip did not move,
        // before the miner resubmits the same solution; the resubmission must
        // still reach the template it was found on.
        use ergo_crypto::autolykos::common::calc_n;
        use ergo_crypto::autolykos::v2::hit_for_v2;
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0u8; 32];
        let n_bits = ergo_ser::difficulty::encode_compact_bits(&num_bigint::BigUint::from(16u8));
        let target = ergo_crypto::difficulty::get_target(n_bits);
        let (offered_msg, rebuilt_msg) = ([0x61u8; 32], [0x62u8; 32]);
        h.set_best_tip(synced_tip(parent));
        let (c1, w1) = candidate_pair_msg_nbits(parent, offered_msg, n_bits);
        let offered = h
            .publish_if_current(c1, w1, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .expect("the first template publishes");
        let (mut c2, w2) = candidate_pair_msg_nbits(parent, rebuilt_msg, n_bits);
        // Built later, so a block from it differs from one from the older
        // template.
        c2.header.timestamp += 1;
        let rebuilt = h
            .publish_if_current(c2, w2, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .expect("the same-parent rebuild publishes");
        assert!(
            !rebuilt.clean_jobs,
            "a same-parent rebuild is not a clean job"
        );
        assert_eq!(rebuilt.chain_seq, offered.chain_seq);
        assert_eq!(
            h.cached_template_if_synced().expect("serves the rebuild").1,
            rebuilt,
            "the rebuild is the template served"
        );
        // The helper's templates are version 3 at height 1.
        let n = calc_n(3, 1);
        let solves = |msg: &[u8; 32], nonce: &[u8; 8]| hit_for_v2(msg, nonce, 1, n) <= target;
        let nonce = (0u64..)
            .map(u64::to_be_bytes)
            .find(|nonce| solves(&offered_msg, nonce) && !solves(&rebuilt_msg, nonce))
            .expect("some nonce qualifies");
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
        let block = match h
            .verify_solution(&MinerSolution { nonce, pk: None }, &state)
            .expect("verify ok")
        {
            SolutionOutcome::Accepted(block) => block,
            other => panic!("the older template's solution is accepted, got {other:?}"),
        };
        assert_eq!(
            block.header.timestamp, 1_700_000_000_000,
            "accepted for the older template"
        );
    }

    #[test]
    fn withdrawing_private_work_keeps_unrelated_templates_solvable() {
        for reason in [BuildReason::Tip, BuildReason::Requested] {
            // Cancelling or expiring one private transaction must not discard
            // proof-of-work found for a template that does not include it.
            use ergo_crypto::autolykos::common::calc_n;
            use ergo_crypto::autolykos::v2::hit_for_v2;
            let h = MiningHandle::mainnet([0x02u8; 33]);
            let parent = [0u8; 32];
            let n_bits =
                ergo_ser::difficulty::encode_compact_bits(&num_bigint::BigUint::from(16u8));
            let target = ergo_crypto::difficulty::get_target(n_bits);
            h.set_best_tip(synced_tip(parent));
            let private_tx = ergo_ser::transaction::Transaction {
                inputs: vec![],
                data_inputs: vec![],
                output_candidates: vec![],
            };
            let private_id = Digest32::from_bytes(
                *ergo_ser::transaction::transaction_id(&private_tx)
                    .unwrap()
                    .as_bytes(),
            );
            let (with_msg, without_msg) = ([0x71u8; 32], [0x72u8; 32]);
            let (mut with, w1) = candidate_pair_msg_nbits(parent, with_msg, n_bits);
            with.observation.operator_owned = true;
            with.transactions = vec![private_tx];
            with.observation.transactions = vec![crate::inspection::TransactionObservation {
                category: "private",
                ..Default::default()
            }];
            h.publish_if_current(with, w1, &parent, || BUILT_AT_MS, reason)
                .expect("the template with the private transaction publishes");
            let (mut without, w2) = candidate_pair_msg_nbits(parent, without_msg, n_bits);
            without.observation.operator_owned = true;
            without.header.timestamp += 1;
            h.publish_if_current(without, w2, &parent, || BUILT_AT_MS, reason)
                .expect("the unrelated template publishes");
            let generation = h.operator_generation();

            let ids = std::collections::HashSet::from([private_id]);
            assert_eq!(h.withdraw_private_transactions(&ids, true), 1);
            assert_eq!(
                h.operator_generation(),
                generation + 1,
                "builds frozen before the change cannot publish it"
            );
            assert_eq!(
                h.inspect_template(Some(without_msg), None)
                    .expect("retained work")
                    .template
                    .work
                    .msg,
                without_msg
            );
            let n = calc_n(3, 1);
            let solves = |msg: &[u8; 32], nonce: &[u8; 8]| hit_for_v2(msg, nonce, 1, n) <= target;
            let only = |msg: [u8; 32], other: [u8; 32]| {
                (0u64..)
                    .map(u64::to_be_bytes)
                    .find(|nonce| solves(&msg, nonce) && !solves(&other, nonce))
                    .expect("some nonce qualifies")
            };
            let dir = tempfile::tempdir().unwrap();
            let state = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
            let verify = |nonce| {
                h.verify_solution(&MinerSolution { nonce, pk: None }, &state)
                    .expect("verify ok")
            };
            assert!(
                matches!(
                    verify(only(without_msg, with_msg)),
                    SolutionOutcome::Accepted(_)
                ),
                "work without the withdrawn transaction is accepted"
            );
            assert!(
                matches!(
                    verify(only(with_msg, without_msg)),
                    SolutionOutcome::StaleParent { .. }
                ),
                "work with it is stale"
            );

            // Work that is not selectable (e.g. conflicted) retires no build.
            assert_eq!(h.withdraw_private_transactions(&ids, false), 0);
            assert_eq!(h.operator_generation(), generation + 1);
        }
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
            .map(|t| t.template.identity.template_id)
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
            cache
                .templates
                .front()
                .unwrap()
                .template
                .identity
                .template_id,
            [oldest_retained; 32],
            "front is the oldest retained, not the first ever published",
        );
        assert_eq!(
            cache
                .templates
                .back()
                .unwrap()
                .template
                .identity
                .template_id,
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
        // A tip transition with NO publish (a reorg changing the parent, or the
        // synced bit changing) changes what serving would return, so a longpoll
        // waiter must wake. Both kinds of change bump the notify. The `true →
        // false` direction asserted below cannot arise from the production
        // latch, which is one-way; it is exercised here because `set_best_tip`
        // is a plain setter and must notify on any change of the pair.
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
    fn verify_solution_preferring_fallback_skips_ineligible_pow() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let live_parent = [0; 32];
        // Newest-first: withdrawn, stale, fallback, stale, withdrawn, offered.
        for timestamp in 0..6 {
            let parent = if matches!(timestamp, 2 | 4) {
                [1; 32]
            } else {
                live_parent
            };
            h.set_best_tip(synced_tip(parent));
            let (mut c, w) = candidate_pair_msg_nbits(parent, [timestamp as u8; 32], 0x03000001);
            c.header.timestamp = timestamp;
            assert!(h
                .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Tip)
                .is_some());
        }
        for retained in &mut h.cache.write().unwrap().templates {
            retained.withdrawn = matches!(retained.template.candidate.header.timestamp, 1 | 5);
        }
        // The authoritative live parent comes from state, not the cache tip.
        h.set_best_tip(synced_tip([9; 32]));
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let solution = MinerSolution {
            nonce: [0; 8],
            pk: None,
        };
        VERIFIED_TIMESTAMPS.with_borrow_mut(|timestamps| *timestamps = Some(Vec::new()));
        let mut visited = Vec::new();
        let outcome = h
            .verify_solution_preferring(&solution, &state, |block| {
                visited.push(block.header.timestamp);
                Ok(false)
            })
            .unwrap();
        let verified = VERIFIED_TIMESTAMPS.with_borrow_mut(Option::take).unwrap();
        assert_eq!(verified, [5, 4, 3, 0]);
        assert_eq!(visited, [3, 0]);
        let SolutionOutcome::Accepted(block) = outcome else {
            panic!("offered fallback")
        };
        assert_eq!(block.header.timestamp, 3);
    }

    #[test]
    fn verify_solution_preferring_withdrawn_template_accepts_offered_fallback() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0u8; 32];
        h.set_best_tip(synced_tip(parent));
        for timestamp in [1, 2] {
            let (mut c, w) = candidate_pair_msg_nbits(parent, [timestamp as u8; 32], 0x03000001);
            c.header.timestamp = timestamp;
            assert!(h
                .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Tip)
                .is_some());
            if timestamp == 1 {
                h.withdraw_templates_for_parent(&parent);
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let solution = MinerSolution {
            nonce: [0; 8],
            pk: None,
        };
        let mut visited = Vec::new();
        let outcome = h
            .verify_solution_preferring(&solution, &state, |block| {
                visited.push(block.header.timestamp);
                Ok(block.header.timestamp == 1)
            })
            .unwrap();
        assert_eq!(
            visited,
            [2],
            "only the offered template reaches the predicate"
        );
        let SolutionOutcome::Accepted(block) = outcome else {
            panic!("offered fallback")
        };
        assert_eq!(
            block.header.timestamp, 2,
            "a withdrawn match cannot be preferred"
        );
    }

    #[test]
    fn verify_solution_preferring_storage_error_returns_error() {
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0u8; 32];
        h.set_best_tip(synced_tip(parent));
        let (c, w) = candidate_pair_msg_nbits(parent, [1; 32], 0x03000001);
        assert!(h
            .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .is_some());
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let solution = MinerSolution {
            nonce: [0; 8],
            pk: None,
        };
        let result = h.verify_solution_preferring(&solution, &state, |_| {
            Err(MiningError::StateRead {
                op: "recovery",
                reason: "injected read failure".into(),
            })
        });
        assert!(matches!(
            result,
            Err(MiningError::StateRead { op: "recovery", .. })
        ));
    }

    #[test]
    fn verify_solution_withdrawn_template_solution_returns_stale_parent() {
        // A solution to a withdrawn template is never accepted, and its valid
        // PoW earns the actionable stale answer rather than invalid_pow. The
        // template is on the live parent (a fresh store's zeroed best full
        // block), so before the withdrawal the same solution is accepted.
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0u8; 32];
        h.set_best_tip(synced_tip(parent));
        let (c, w) = candidate_pair_msg_nbits(parent, [0x41u8; 32], 0x03000001);
        assert!(h
            .publish_if_current(c, w, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .is_some());
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
        let solution = MinerSolution {
            nonce: [0u8; 8],
            pk: None,
        };
        assert!(matches!(
            h.verify_solution(&solution, &state).expect("verify ok"),
            SolutionOutcome::Accepted(_)
        ));

        h.withdraw_templates_for_parent(&parent);

        let outcome = h.verify_solution(&solution, &state).expect("verify ok");
        assert!(
            matches!(outcome, SolutionOutcome::StaleParent { .. }),
            "a withdrawn template's solution is stale, got {outcome:?}"
        );
    }

    #[test]
    fn verify_solution_withdrawn_template_real_target_prefers_stale_over_invalid_pow() {
        // At a real target a nonce that solves the withdrawn template almost
        // never solves the rebuilt one on the same parent. Its PoW is valid
        // for the work the miner was given, so the answer is StaleParent (400
        // stale_candidate), not InvalidPow; Scala answers it with its own
        // error, not a PoW failure (CandidateGenerator.scala:246-247 and
        // 280-283 at v6.0.6 23aabead8). A nonce that also solves the rebuilt
        // template is accepted for it, as Scala tries its current candidate
        // first (256-258).
        use ergo_crypto::autolykos::common::calc_n;
        use ergo_crypto::autolykos::v2::hit_for_v2;
        let h = MiningHandle::mainnet([0x02u8; 33]);
        let parent = [0u8; 32];
        let n_bits = ergo_ser::difficulty::encode_compact_bits(&num_bigint::BigUint::from(16u8));
        let target = ergo_crypto::difficulty::get_target(n_bits);
        let (withdrawn_msg, fresh_msg) = ([0x51u8; 32], [0x52u8; 32]);
        h.set_best_tip(synced_tip(parent));
        let (c1, w1) = candidate_pair_msg_nbits(parent, withdrawn_msg, n_bits);
        assert!(h
            .publish_if_current(c1, w1, &parent, || BUILT_AT_MS, BuildReason::Tip)
            .is_some());
        h.withdraw_templates_for_parent(&parent);
        let (c2, w2) = candidate_pair_msg_nbits(parent, fresh_msg, n_bits);
        assert!(h
            .publish_if_current(
                c2,
                w2,
                &parent,
                || BUILT_AT_MS,
                BuildReason::SolvedBlockFailed
            )
            .is_some());
        // The helper's templates are version 3 at height 1.
        let n = calc_n(3, 1);
        let solves = |msg: &[u8; 32], nonce: &[u8; 8]| hit_for_v2(msg, nonce, 1, n) <= target;
        let nonce_where = |pred: &dyn Fn(&[u8; 8]) -> bool| {
            (0u64..)
                .map(u64::to_be_bytes)
                .find(|nonce| pred(nonce))
                .expect("some nonce qualifies")
        };
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
        let verify = |nonce: [u8; 8]| {
            h.verify_solution(&MinerSolution { nonce, pk: None }, &state)
                .expect("verify ok")
        };

        let old_work = nonce_where(&|n| solves(&withdrawn_msg, n) && !solves(&fresh_msg, n));
        let outcome = verify(old_work);
        assert!(
            matches!(outcome, SolutionOutcome::StaleParent { .. }),
            "valid PoW for the withdrawn template is stale, not invalid pow, got {outcome:?}"
        );
        let neither = nonce_where(&|n| !solves(&withdrawn_msg, n) && !solves(&fresh_msg, n));
        assert!(matches!(verify(neither), SolutionOutcome::InvalidPow));
        let both = nonce_where(&|n| solves(&withdrawn_msg, n) && solves(&fresh_msg, n));
        assert!(
            matches!(verify(both), SolutionOutcome::Accepted(_)),
            "a nonce that solves the rebuilt template is accepted for it"
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
    // ----- operator inspection -----

    #[test]
    fn inspection_matches_both_selectors_and_preserves_superseded_templates() {
        let handle = base_handle();
        let parent = [1; 32];
        handle.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 1,
            synced: true,
        });
        let (candidate, work) = candidate_pair_msg(parent, [2; 32]);
        let first = handle
            .publish_if_current(candidate, work, &parent, || 100, BuildReason::Tip)
            .unwrap();
        let frozen = handle
            .inspect_template(Some([2; 32]), Some(first.template_seq))
            .unwrap();
        let (candidate, work) = candidate_pair_msg(parent, [3; 32]);
        handle
            .publish_if_current(
                candidate,
                work,
                &parent,
                || 200,
                BuildReason::MempoolRefresh,
            )
            .unwrap();
        assert_eq!(frozen.template.identity.built_at_ms, 100);
        assert_eq!(
            handle
                .inspect_template(Some([2; 32]), Some(first.template_seq))
                .unwrap()
                .status,
            "superseded"
        );
        assert!(handle
            .inspect_template(Some([2; 32]), Some(first.template_seq + 1))
            .is_none());
        assert_eq!(
            handle
                .inspect_template(None, None)
                .unwrap()
                .template
                .candidate
                .msg,
            [3; 32]
        );
    }

    #[test]
    fn operator_generation_retires_work_and_rejects_older_builds() {
        let handle = base_handle();
        let parent = [1; 32];
        handle.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 1,
            synced: true,
        });
        let (candidate, work) = candidate_pair(parent);
        handle
            .publish_if_current(candidate, work, &parent, || 100, BuildReason::Tip)
            .unwrap();
        let (mut candidate, work) = candidate_pair(parent);
        assert_eq!(handle.invalidate_operator_generation(), 1);
        assert!(handle.inspect_template(None, None).is_none());
        assert!(handle
            .publish_if_current(
                candidate.clone(),
                work.clone(),
                &parent,
                || 200,
                BuildReason::Tip
            )
            .is_none());
        candidate.observation.operator_generation = 1;
        assert!(handle
            .publish_if_current(candidate, work, &parent, || 300, BuildReason::Tip)
            .is_some());
    }

    #[test]
    fn operator_snapshot_freezes_the_generation_before_reading_the_queue() {
        let handle = base_handle();
        let parent = [1; 32];
        handle.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 1,
            synced: true,
        });
        // The queue changes (and invalidates) between the two reads.
        let (generation, entries) = handle.operator_snapshot(|queue| {
            handle.invalidate_operator_generation();
            queue.selection_entries()
        });
        assert_eq!(generation, 0, "the generation is read before the queue");
        assert!(entries.is_empty());
        // So a build carrying that snapshot cannot publish.
        let (mut candidate, work) = candidate_pair(parent);
        candidate.observation.operator_generation = generation;
        assert!(handle
            .publish_if_current(candidate, work, &parent, || 100, BuildReason::Tip)
            .is_none());
    }

    #[test]
    fn policy_save_waits_on_disk_without_holding_the_policy_or_cache_locks() {
        let directory = tempfile::tempdir().unwrap();
        let handle = base_handle()
            .with_policy_store(directory.path().join("mining-policy.json"))
            .unwrap();
        let observer = handle.clone();
        let unlocked = std::rc::Rc::new(std::cell::Cell::new(None));
        let seen = unlocked.clone();
        crate::policy_store::hooks::BEFORE_REPLACE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                seen.set(Some(
                    observer.policy.try_read().is_ok() && observer.cache.try_write().is_ok(),
                ));
            }));
        });
        let mut policy = handle.policy();
        policy.rent_max_cost_basis_points = 0;
        let saved = handle.set_policy(policy.clone());
        crate::policy_store::hooks::BEFORE_REPLACE.with(|hook| hook.borrow_mut().take());
        assert_eq!(saved.unwrap(), None);
        assert_eq!(
            unlocked.get(),
            Some(true),
            "builds and publishes must not wait for the disk sync"
        );
        assert_eq!(handle.policy_snapshot(), (1, policy));
    }

    #[test]
    fn policy_replaced_on_disk_is_active_even_if_its_directory_sync_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mining-policy.json");
        let handle = base_handle().with_policy_store(&path).unwrap();
        let mut policy = handle.policy();
        policy.rent_max_size_basis_points = 0;
        crate::policy_store::hooks::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(true));
        let saved = handle.set_policy(policy.clone());
        crate::policy_store::hooks::FAIL_DIRECTORY_SYNC.with(|fail| fail.set(false));
        assert!(saved.unwrap().is_some(), "the caller is warned");
        assert_eq!(handle.policy_snapshot(), (1, policy.clone()));
        assert_eq!(crate::policy_store::load(&path).unwrap(), Some(policy));
    }

    #[test]
    fn policy_edit_is_shared_retires_work_and_rejects_previous_revision() {
        let handle = base_handle();
        let clone = handle.clone();
        let parent = [1; 32];
        handle.set_best_tip(BestTip {
            parent_id: parent,
            chain_seq: 1,
            synced: true,
        });
        let (candidate, work) = candidate_pair(parent);
        handle
            .publish_if_current(candidate, work, &parent, || 100, BuildReason::Tip)
            .unwrap();
        let mut policy = handle.policy();
        policy.rent_max_cost_basis_points = 0;
        handle.set_policy(policy.clone()).unwrap();
        assert_eq!(clone.policy_snapshot(), (1, policy));
        assert!(clone.cached_template_if_synced().is_none());
        let (mut candidate, work) = candidate_pair(parent);
        assert!(handle
            .publish_if_current(
                candidate.clone(),
                work.clone(),
                &parent,
                || 200,
                BuildReason::Tip
            )
            .is_none());
        candidate.observation.policy_revision = 1;
        candidate.observation.operator_generation = 1;
        assert!(handle
            .publish_if_current(candidate, work, &parent, || 300, BuildReason::Tip)
            .is_some());
    }

    #[test]
    fn local_outcomes_have_bounded_newest_first_retention() {
        let handle = base_handle();
        for at in 0..(MAX_MINING_OUTCOMES as u64 + 3) {
            handle.record_outcome(None, None, "rejected", None, at);
        }
        let events = handle.mining_outcomes();
        assert_eq!(events.len(), MAX_MINING_OUTCOMES);
        assert_eq!(events.last().unwrap().at_ms, 3);
        assert_eq!(events[0].at_ms, MAX_MINING_OUTCOMES as u64 + 2);
    }
    fn candidate_pair_for_key(
        parent: [u8; 32],
        msg: [u8; 32],
        pk: [u8; 33],
        timestamp: u64,
    ) -> (Candidate, WorkMessage) {
        let (mut candidate, mut work) = candidate_pair_msg_nbits(parent, msg, 0x03000001);
        candidate.validation_ctx.pre_header.miner_pubkey = pk;
        candidate.header.timestamp = timestamp;
        candidate.header.solution = ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from(pk),
            nonce: [0; 8],
        };
        work.pk = pk;
        (candidate, work)
    }

    fn requested_test_key() -> [u8; 33] {
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn requested_job_survives_more_than_sixteen_background_refreshes() {
        let operator_pk = [0x02; 33];
        let requested_pk = requested_test_key();
        let handle = MiningHandle::mainnet(operator_pk);
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        let requested_msg = [0xA1; 32];
        let (candidate, work) = candidate_pair_for_key(parent, requested_msg, requested_pk, 10);
        let requested_seq = handle
            .publish_if_current(
                candidate,
                work,
                &parent,
                || BUILT_AT_MS,
                BuildReason::Requested,
            )
            .unwrap()
            .template_seq;
        assert!(
            handle.cached_work_if_synced().is_none(),
            "requested work does not become solo work"
        );
        let mut last_operator_msg = [0; 32];
        for refresh in 0..MAX_RETAINED_TEMPLATES + 4 {
            last_operator_msg = [refresh as u8; 32];
            let (candidate, work) = candidate_pair_for_key(
                parent,
                last_operator_msg,
                operator_pk,
                100 + refresh as u64,
            );
            let identity = handle
                .publish_if_current(
                    candidate,
                    work,
                    &parent,
                    || BUILT_AT_MS,
                    BuildReason::MempoolRefresh,
                )
                .unwrap();
            assert_eq!(identity.clean_jobs, refresh == 0);
        }
        let solo = handle.cached_work_if_synced().unwrap();
        assert_eq!(solo.pk, operator_pk);
        assert_eq!(solo.msg, last_operator_msg);
        assert_eq!(
            handle
                .cached_requested_template_if_synced(requested_seq, BUILT_AT_MS)
                .unwrap()
                .0
                .msg,
            requested_msg
        );
        assert_eq!(
            handle.cache.read().unwrap().templates.len(),
            MAX_RETAINED_TEMPLATES + 1
        );
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let outcome = handle
            .verify_solution(
                &MinerSolution {
                    nonce: [0; 8],
                    pk: Some(requested_pk),
                },
                &state,
            )
            .unwrap();
        let SolutionOutcome::Accepted(block) = outcome else {
            panic!("retained requested job accepts")
        };
        assert_eq!(block.header.timestamp, 10);
    }

    #[test]
    fn requested_lookup_returns_the_published_job_not_an_older_one_after_aba() {
        let operator_pk = [0x02; 33];
        let requested_pk = requested_test_key();
        let handle = MiningHandle::mainnet(operator_pk);
        let (a, b) = ([0xAA; 32], [0xBB; 32]);
        let publish = |parent: [u8; 32], msg: [u8; 32], chain_seq: u64| {
            handle.set_best_tip(synced_tip_seq(parent, chain_seq));
            let (candidate, work) = candidate_pair_for_key(parent, msg, requested_pk, 10);
            handle
                .publish_if_current(
                    candidate,
                    work,
                    &parent,
                    || BUILT_AT_MS,
                    BuildReason::Requested,
                )
                .unwrap()
                .template_seq
        };
        let on_a = publish(a, [0x01; 32], 1);
        let on_b = publish(b, [0x02; 32], 2);
        // The tip returns to A before the worker reads back its B publish.
        handle.set_best_tip(synced_tip_seq(a, 3));
        assert!(
            handle
                .cached_requested_template_if_synced(on_b, BUILT_AT_MS)
                .is_none(),
            "the B job is off-tip and the older A job must not stand in for it"
        );
        assert_eq!(
            handle
                .cached_requested_template_if_synced(on_a, BUILT_AT_MS)
                .unwrap()
                .0
                .msg,
            [0x01; 32]
        );
    }

    #[test]
    fn requested_jobs_with_same_transactions_are_selected_only_by_matching_key() {
        let operator_pk = [0x02; 33];
        let first_pk = requested_test_key();
        let mut second_pk = first_pk;
        second_pk[0] = 3;
        let handle = MiningHandle::mainnet(operator_pk);
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        // The same package and work digest must never make the newest key's
        // candidate stand in for another miner's independently retained job.
        let mut seqs = Vec::new();
        for (pk, timestamp, reason) in [
            (first_pk, 10, BuildReason::Requested),
            (second_pk, 20, BuildReason::Requested),
            (operator_pk, 30, BuildReason::Tip),
        ] {
            let (candidate, work) = candidate_pair_for_key(parent, [0xA2; 32], pk, timestamp);
            let identity = handle
                .publish_if_current(candidate, work, &parent, || BUILT_AT_MS, reason)
                .unwrap();
            seqs.push(identity.template_seq);
        }
        for (seq, pk) in [(seqs[0], first_pk), (seqs[1], second_pk)] {
            assert_eq!(
                handle
                    .cached_requested_template_if_synced(seq, BUILT_AT_MS)
                    .unwrap()
                    .0
                    .pk,
                pk
            );
        }
        assert!(
            handle
                .cached_requested_template_if_synced(seqs[2], BUILT_AT_MS)
                .is_none(),
            "an operator template is never returned as a requested job"
        );
        assert_eq!(handle.cached_work_if_synced().unwrap().pk, operator_pk);
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        for (pk, timestamp) in [(Some(first_pk), 10), (Some(second_pk), 20), (None, 30)] {
            let outcome = handle
                .verify_solution(&MinerSolution { nonce: [0; 8], pk }, &state)
                .unwrap();
            let SolutionOutcome::Accepted(block) = outcome else {
                panic!("matching job accepts")
            };
            assert_eq!(block.header.timestamp, timestamp);
        }
        assert!(matches!(
            handle
                .verify_solution(
                    &MinerSolution {
                        nonce: [0; 8],
                        pk: Some([0x03; 33])
                    },
                    &state
                )
                .unwrap(),
            SolutionOutcome::InvalidPow
        ));
    }

    #[test]
    fn requested_foreign_key_cache_never_accepts_a_solution_without_a_key() {
        let handle = MiningHandle::mainnet([0x02; 33]);
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        let (candidate, work) =
            candidate_pair_for_key(parent, [0xA3; 32], requested_test_key(), 10);
        handle
            .publish_if_current(
                candidate,
                work,
                &parent,
                || BUILT_AT_MS,
                BuildReason::Requested,
            )
            .unwrap();
        assert!(!handle.has_template_for_parent(&parent));
        assert!(handle.cached_template_if_synced().is_none());
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        assert!(matches!(
            handle
                .verify_solution(
                    &MinerSolution {
                        nonce: [0; 8],
                        pk: None
                    },
                    &state
                )
                .unwrap(),
            SolutionOutcome::InvalidPow
        ));
    }

    #[test]
    fn requested_operator_key_job_accepts_a_solution_without_an_explicit_key() {
        let operator_pk = [0x02; 33];
        let handle = MiningHandle::mainnet(operator_pk);
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        let (mut candidate, work) = candidate_pair_for_key(parent, [0xA4; 32], operator_pk, 40);
        candidate.observation.operator_owned = true;
        handle
            .publish_if_current(
                candidate,
                work,
                &parent,
                || BUILT_AT_MS,
                BuildReason::Requested,
            )
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let outcome = handle
            .verify_solution(
                &MinerSolution {
                    nonce: [0; 8],
                    pk: None,
                },
                &state,
            )
            .unwrap();
        let SolutionOutcome::Accepted(block) = outcome else {
            panic!("default-key requested job accepts")
        };
        assert_eq!(block.header.timestamp, 40);
    }
    #[test]
    fn requested_templates_obey_policy_and_generation_publication_guards() {
        for policy_change in [false, true] {
            let handle = MiningHandle::mainnet([2; 33]);
            let parent = [0; 32];
            handle.set_best_tip(synced_tip(parent));
            let (candidate, work) =
                candidate_pair_for_key(parent, [0xA6; 32], requested_test_key(), 10);
            let seq = handle
                .publish_if_current(
                    candidate.clone(),
                    work.clone(),
                    &parent,
                    || BUILT_AT_MS,
                    BuildReason::Requested,
                )
                .unwrap()
                .template_seq;
            if policy_change {
                let mut policy = handle.policy();
                policy.rent_max_cost_basis_points = 0;
                handle.set_policy(policy).unwrap();
            } else {
                handle.invalidate_operator_generation();
            }
            assert!(handle
                .cached_requested_template_if_synced(seq, BUILT_AT_MS)
                .is_none());
            assert_eq!(
                handle.inspect_template(None, Some(seq)).unwrap().status,
                "withdrawn"
            );
            assert!(handle
                .publish_if_current(
                    candidate.clone(),
                    work.clone(),
                    &parent,
                    || BUILT_AT_MS,
                    BuildReason::Requested
                )
                .is_none());
            let mut current = candidate;
            current.observation.policy_revision = handle.policy_revision();
            current.observation.operator_generation = handle.operator_generation();
            assert!(handle
                .publish_if_current(
                    current,
                    work,
                    &parent,
                    || BUILT_AT_MS,
                    BuildReason::Requested
                )
                .is_some());
        }
    }
    #[test]
    fn requested_outcome_journal_matches_the_solved_jobs_miner_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mining-history.json");
        let handle = MiningHandle::mainnet([2; 33]).with_outcome_journal(&path);
        let parent = [0; 32];
        let msg = [0xA7; 32];
        let first_pk = requested_test_key();
        let mut second_pk = first_pk;
        second_pk[0] = 3;
        handle.set_best_tip(synced_tip(parent));
        let mut seqs = Vec::new();
        for (pk, timestamp) in [(first_pk, 10), (second_pk, 20)] {
            let (candidate, work) = candidate_pair_for_key(parent, msg, pk, timestamp);
            seqs.push(
                handle
                    .publish_if_current(
                        candidate,
                        work,
                        &parent,
                        || BUILT_AT_MS,
                        BuildReason::Requested,
                    )
                    .unwrap()
                    .template_seq,
            );
        }
        handle.record_miner_outcome(Some((msg, first_pk)), Some([3; 32]), "accepted", None, 10);
        handle.record_miner_outcome(Some((msg, second_pk)), Some([4; 32]), "rejected", None, 20);
        handle.record_miner_outcome(Some((msg, [4; 33])), None, "rejected", None, 30);
        let restored = MiningHandle::mainnet([2; 33])
            .with_outcome_journal(&path)
            .mining_outcomes();
        assert_eq!(restored.len(), 3);
        assert_eq!(restored[2].template_seq, Some(seqs[0]));
        assert!(restored[2].accounting.is_none());
        assert_eq!(restored[1].template_seq, Some(seqs[1]));
        assert!(restored[1].accounting.is_none());
        assert_eq!(
            restored[0].template_seq, None,
            "unknown keys never borrow another miner's identity"
        );
    }
    #[test]
    fn nonce_only_operator_jobs_survive_wallet_key_loss() {
        let mut handle = MiningHandle::mainnet([2; 33]);
        handle.reward_key = RewardKeySource::Wallet;
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        assert_eq!(
            handle.resolve_reward_key(&state),
            RewardKeyResolution::Pending
        );
        for reason in [BuildReason::Tip, BuildReason::Requested] {
            let (mut candidate, work) = candidate_pair_for_key(parent, [0xA8; 32], [2; 33], 50);
            candidate.observation.operator_owned = true;
            handle
                .publish_if_current(candidate, work, &parent, || BUILT_AT_MS, reason)
                .unwrap();
            let outcome = handle
                .verify_solution(
                    &MinerSolution {
                        nonce: [0; 8],
                        pk: None,
                    },
                    &state,
                )
                .unwrap();
            assert!(
                matches!(outcome, SolutionOutcome::Accepted(_)),
                "{outcome:?}"
            );
        }
    }
    #[test]
    fn requested_package_cache_matches_key_order_parent_and_interval() {
        let handle = MiningHandle::mainnet([2; 33]);
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        let ids = vec![Digest32::from_bytes([1; 32]), Digest32::from_bytes([2; 32])];
        let (mut candidate, work) =
            candidate_pair_for_key(parent, [0xB1; 32], requested_test_key(), 10);
        candidate.observation.requested_ids = ids.clone();
        let seq = handle
            .publish_if_current(
                candidate,
                work,
                &parent,
                || BUILT_AT_MS,
                BuildReason::Requested,
            )
            .unwrap()
            .template_seq;
        assert_eq!(
            handle
                .cached_requested_package(Some(requested_test_key()), &ids, BUILT_AT_MS + 59_999)
                .unwrap()
                .1
                .template_seq,
            seq
        );
        assert!(handle
            .cached_requested_package(None, &ids, BUILT_AT_MS)
            .is_none());
        assert!(handle
            .cached_requested_package(Some([2; 33]), &ids, BUILT_AT_MS)
            .is_none());
        assert!(handle
            .cached_requested_package(Some(requested_test_key()), &[ids[1], ids[0]], BUILT_AT_MS)
            .is_none());
        assert!(handle
            .cached_requested_package(Some(requested_test_key()), &[], BUILT_AT_MS)
            .is_none());
        assert!(handle
            .cached_requested_package(Some(requested_test_key()), &ids, BUILT_AT_MS + 60_000)
            .is_none());
        handle.set_best_tip(synced_tip([1; 32]));
        assert!(handle
            .cached_requested_package(Some(requested_test_key()), &ids, BUILT_AT_MS)
            .is_none());
    }

    #[test]
    fn requested_churn_for_one_key_preserves_another_keys_live_job() {
        let handle = MiningHandle::mainnet([2; 33]);
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        let key = requested_test_key();
        let (candidate, work) = candidate_pair_for_key(parent, [0xB2; 32], key, 10);
        let seq = handle
            .publish_if_current(
                candidate,
                work,
                &parent,
                || BUILT_AT_MS,
                BuildReason::Requested,
            )
            .unwrap()
            .template_seq;
        for i in 0..20 {
            let (candidate, work) = candidate_pair_for_key(parent, [i; 32], [2; 33], 20 + i as u64);
            handle
                .publish_if_current(
                    candidate,
                    work,
                    &parent,
                    || BUILT_AT_MS + (i as u64 + 1) * 90_000,
                    BuildReason::Requested,
                )
                .unwrap();
        }
        assert!(handle
            .cached_requested_template_if_synced(seq, BUILT_AT_MS)
            .is_some());
        assert_eq!(handle.inspect_history().len(), 17);
        let dir = tempfile::tempdir().unwrap();
        let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        let outcome = handle
            .verify_solution(
                &MinerSolution {
                    nonce: [0; 8],
                    pk: Some(key),
                },
                &state,
            )
            .unwrap();
        assert!(matches!(outcome, SolutionOutcome::Accepted(_)));
    }

    #[test]
    fn requested_byte_budget_evicts_stale_jobs_before_live_jobs() {
        let handle = MiningHandle::mainnet([2; 33]);
        let a = [0; 32];
        let b = [1; 32];
        let mut seqs = vec![];
        for (parent, pk, msg) in [
            (a, requested_test_key(), [0xB3; 32]),
            (b, [2; 33], [0xB4; 32]),
        ] {
            handle.set_best_tip(synced_tip(parent));
            let (candidate, mut work) = candidate_pair_for_key(parent, msg, pk, 10);
            work.metrics.transactions_size_bytes = 8 * 1024 * 1024;
            seqs.push(
                handle
                    .publish_if_current(
                        candidate,
                        work,
                        &parent,
                        || BUILT_AT_MS,
                        BuildReason::Requested,
                    )
                    .unwrap()
                    .template_seq,
            );
        }
        handle.set_best_tip(synced_tip(a));
        let (candidate, work) = candidate_pair_for_key(a, [0xB5; 32], [3; 33], 10);
        handle
            .publish_if_current(candidate, work, &a, || BUILT_AT_MS, BuildReason::Requested)
            .unwrap();
        assert!(handle
            .cached_requested_template_if_synced(seqs[0], BUILT_AT_MS)
            .is_some());
        assert!(handle.inspect_template(None, Some(seqs[1])).is_none());
        let cache = handle.cache.read().unwrap();
        assert!(
            cache
                .templates
                .iter()
                .map(|t| t.requested_weight)
                .sum::<usize>()
                <= MAX_REQUESTED_TEMPLATE_BYTES
        );
    }
    #[test]
    fn requested_budget_protects_reused_job_and_its_solution() {
        for exact_reply in [false, true] {
            let handle = MiningHandle::mainnet([2; 33]);
            let parent = [0; 32];
            handle.set_best_tip(synced_tip(parent));
            let key = requested_test_key();
            let ids = vec![Digest32::from_bytes([9; 32])];
            let mut seqs = Vec::new();
            for i in 0..2 {
                let (mut candidate, mut work) =
                    candidate_pair_for_key(parent, [i; 32], key, 10 + i as u64);
                candidate.observation.requested_ids = if i == 0 { ids.clone() } else { vec![] };
                work.metrics.transactions_size_bytes = 8 * 1024 * 1024;
                seqs.push(
                    handle
                        .publish_if_current(
                            candidate,
                            work,
                            &parent,
                            || BUILT_AT_MS,
                            BuildReason::Requested,
                        )
                        .unwrap()
                        .template_seq,
                );
            }
            if exact_reply {
                assert!(handle
                    .cached_requested_template_if_synced(seqs[0], BUILT_AT_MS + 59_999)
                    .is_some());
            } else {
                assert!(handle
                    .cached_requested_package(Some(key), &ids, BUILT_AT_MS + 59_999)
                    .is_some());
            }
            let (candidate, mut work) = candidate_pair_for_key(parent, [3; 32], [2; 33], 30);
            work.metrics.transactions_size_bytes = 8 * 1024 * 1024;
            handle
                .publish_if_current(
                    candidate,
                    work,
                    &parent,
                    || BUILT_AT_MS + 100_000,
                    BuildReason::Requested,
                )
                .unwrap();
            assert!(handle.inspect_template(None, Some(seqs[0])).is_some());
            assert!(handle.inspect_template(None, Some(seqs[1])).is_none());
            let dir = tempfile::tempdir().unwrap();
            let state = StateStore::open(&dir.path().join("state.redb")).unwrap();
            let outcome = handle
                .verify_solution(
                    &MinerSolution {
                        nonce: [0; 8],
                        pk: Some(key),
                    },
                    &state,
                )
                .unwrap();
            assert!(
                matches!(outcome, SolutionOutcome::Accepted(_)),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn requested_full_cache_refuses_publish_without_evicting_recent_jobs() {
        for byte_budget in [false, true] {
            let handle = MiningHandle::mainnet([2; 33]);
            let parent = [0; 32];
            handle.set_best_tip(synced_tip(parent));
            let count = if byte_budget {
                2
            } else {
                MAX_RETAINED_TEMPLATES
            };
            for i in 0..count {
                let (candidate, mut work) =
                    candidate_pair_for_key(parent, [i as u8; 32], requested_test_key(), 10);
                if byte_budget {
                    work.metrics.transactions_size_bytes = 8 * 1024 * 1024;
                }
                handle
                    .publish_if_current(
                        candidate,
                        work,
                        &parent,
                        || BUILT_AT_MS,
                        BuildReason::Requested,
                    )
                    .unwrap();
            }
            let history = handle.inspect_history();
            let sequence = handle.cache.read().unwrap().template_seq;
            let (candidate, work) =
                candidate_pair_for_key(parent, [99; 32], requested_test_key(), 10);
            assert!(handle
                .publish_if_current(
                    candidate,
                    work,
                    &parent,
                    || BUILT_AT_MS + 60_001,
                    BuildReason::Requested
                )
                .is_none());
            assert_eq!(handle.inspect_history().len(), history.len());
            assert_eq!(handle.cache.read().unwrap().template_seq, sequence);
            assert!(handle
                .publish_if_current(
                    candidate_pair(parent).0,
                    candidate_pair(parent).1,
                    &parent,
                    || BUILT_AT_MS,
                    BuildReason::Tip
                )
                .is_some());
        }
    }

    #[test]
    fn requested_publication_does_not_wake_ordinary_longpoll() {
        let handle = MiningHandle::mainnet([2; 33]);
        let parent = [0; 32];
        handle.set_best_tip(synced_tip(parent));
        let mut changes = handle.subscribe_serve_changes();
        for reason in [
            BuildReason::Requested,
            BuildReason::Tip,
            BuildReason::Requested,
        ] {
            let (candidate, work) = candidate_pair_msg(parent, [reason as u8; 32]);
            let identity = handle
                .publish_if_current(candidate, work, &parent, || BUILT_AT_MS, reason)
                .unwrap();
            assert_eq!(
                changes.has_changed().unwrap(),
                reason != BuildReason::Requested
            );
            if reason == BuildReason::Requested {
                assert!(handle
                    .cached_requested_template_if_synced(identity.template_seq, BUILT_AT_MS)
                    .is_some());
            } else {
                assert_eq!(
                    handle.cached_template_if_synced().unwrap().1.template_seq,
                    identity.template_seq
                );
            }
            changes.borrow_and_update();
        }
    }
}
