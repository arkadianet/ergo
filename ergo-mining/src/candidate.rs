//! Block candidate orchestrator.
//!
//! Implements v12 §5 of the design plan: composes pre-header freeze,
//! transaction selection, coinbase + reemission dispatch,
//! `candidate_dry_run`, parent-id guard, header assembly, and work-message
//! construction.
//!
//! Scope / invariants:
//! - The block carries the coinbase (emission) tx, then mempool user
//!   transactions selected over an in-block overlay, then a single
//!   fee-collecting tx — block order `[emission, ...user txs, fee]`. A fee
//!   tx is emitted only when an included user tx produces a fee-proposition
//!   output.
//! - Cost and size are enforced at selection so the assembled block stays
//!   under the voted `max_block_cost` / `max_block_size`; the AVL dry-run
//!   computes only the state root + proof and checks neither.
//! - Mainnet post-EIP-27 emission only. Pre-activation and at-activation
//!   paths exist in `reemission` for completeness but mainnet is far past
//!   activation.
//! - Epoch-boundary heights are supported: the candidate runs the SAME
//!   `compute_next_params` the block validator runs, serializes the recomputed
//!   parameter map + cumulative validation settings into the extension, and
//!   uses the recomputed `block_version` in the header — so a peer accepts the
//!   block by construction. The genesis-era first boundary
//!   (`active_params.epoch_start_height == 0`) is the one exception (Scala's
//!   genesis bypass path is not reproduced); a live node is always past it.

use ergo_crypto::difficulty::{
    epoch_length_for_height, get_target, next_n_bits, previous_heights_for_recalculation,
    DifficultyParams,
};
use ergo_crypto::merkle::{extension_root, transactions_root};
use ergo_mempool::MempoolReadSnapshot;
use ergo_primitives::digest::{blake2b256, Digest32};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::difficulty::encode_compact_bits;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::{read_header, serialize_header_without_pow, Header};
use ergo_ser::transaction::{bytes_to_sign, write_transaction, Transaction};
use ergo_validation::active_params::active_params_to_extension_fields;
use ergo_validation::popow::algos::unpack_interlinks;
use ergo_validation::voting::validation_settings::validation_settings_update_to_extension_fields;
use ergo_validation::{
    compute_epoch_votes, compute_next_params, validate_transaction_parsed,
    voting::{derive_activated_script_version, select_candidate_votes},
    ActiveProtocolParameters, ChainHeaderReader, ChainHeaderReaderError, CheckedTransaction,
    CostAccumulator, ErgoValidationSettings, ErgoValidationSettingsUpdate, HeaderView, JitCost,
    ProtocolParams, ReemissionRuleInputs, TransactionContext, TxValidationCtx, TxValidationRules,
    UtxoView, VotingSettings,
};
use num_bigint::BigUint;
use std::collections::BTreeMap;

/// Rule 215 (`hdrVotesUnknown`). When this rule is soft-fork-disabled (mainnet
/// 6.0 carries `rules_to_disable=[215,409]`) an epoch-start header may seed
/// decrease and id-9 votes; while active only `{1..=8, 120}` are accepted.
const RULE_HDR_VOTES_UNKNOWN: u16 = 215;

use crate::candidate_selection::{select_user_txs, CandidateOverlay};
use crate::coinbase::{build_fee_tx, build_pre_eip27_emission_tx};
use crate::emission_box::lookup_emission_box_from_parent;
use crate::emission_rules::MonetarySettings;
use crate::error::MiningError;
use crate::extension_builder::build_candidate_extension_fields;
use crate::reemission::{build_post_eip27_emission_tx, ReemissionSettings};
use crate::state_view::CandidateStateView;
use crate::storage_rent_claim::build_budget_bounded_rent_claim;
use crate::tx_selection::DEFAULT_COST_SAFETY_GAP;
use crate::work_message::WorkMessage;
use ergo_validation::pre_header::{
    build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
};

/// Wall-clock cost of the expensive `generate_candidate` phases, measured per
/// build and surfaced on the engine's build-complete log line.
///
/// The buckets cover the five named phases; cheap assembly steps between them
/// are unmeasured, so the fields do not sum to the engine's total build time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseTimings {
    /// Phases 8–9: emission tx build + validation.
    pub emission: std::time::Duration,
    /// Phase 9c: storage-rent claim build (zero when rent disabled/empty).
    pub rent: std::time::Duration,
    /// Phases 9d–9e: mempool selection + per-tx re-validation + fee-tx trim.
    pub select: std::time::Duration,
    /// Phase 10: AVL+ dry-run (new_state_root + proof bytes) — the report's
    /// prime cost suspect.
    pub dryrun: std::time::Duration,
    /// Phase 12: tx/witness-id derivation + transactions/extension roots.
    pub roots: std::time::Duration,
}

/// What a candidate build includes. `Minimal` is the consensus-complete
/// emission-only template published the instant a new tip lands (forfeits
/// only fees for the seconds until the enriched refresh); `Full` adds the
/// rent self-claim, mempool selection, and the fee tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
    Minimal,
    Full,
}

/// Cached state for a generated candidate. Wraps everything the
/// solution path needs to assemble a `FullBlock`.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Assembled header with placeholder Autolykos solution. The
    /// solution path patches in `(pk, n)` and re-serializes.
    pub header: Header,
    /// Frozen script-visible context. Same `pre_header.*`,
    /// `last_headers`, `last_block_utxo_root` that validated the
    /// candidate's transactions during generation. Stored so the
    /// solution path can re-validate symbolically if needed.
    pub validation_ctx: CandidateValidationContext,
    /// Raw transactions in the candidate's BlockTransactions section.
    /// CheckedTransactions aren't Clone, so we keep the raw form and
    /// re-validate on solution submission if a CheckedBlock is needed.
    pub transactions: Vec<Transaction>,
    /// Raw AVL+ proof bytes captured from the dry-run. Wraps with the
    /// header id at FullBlock-assembly time to produce the ADProofs
    /// section.
    pub ad_proof_bytes: Vec<u8>,
    /// Extension fields (key/value byte pairs), already packed via
    /// `extension_builder`.
    pub extension_fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// `blake2b256(serialize_header_without_pow(header))` — the
    /// external miner hashes this with their nonce.
    pub msg: [u8; 32],
    /// Mining target. The miner's hit must be `<= target` to count
    /// as a valid solution.
    pub target: BigUint,
    /// Frozen `chain_state().best_full_block_id` at generation time.
    /// The solution-path API + executor compare this against the live
    /// best-full-block id to reject candidates whose parent the chain
    /// has moved past.
    pub parent_id: [u8; 32],
}

/// Build a candidate for the next block. Returns `None` if the chain
/// has not reached a state from which mining is possible (tip below
/// height 10, or a tip-flip caught by the post-dry-run guard).
///
/// **Synced-tip contract** (v12 §0 row 2): the caller is expected to
/// have gated on `synced(tip)` already. Mining at an unsynced tip
/// produces script-divergent candidates and is forbidden.
///
/// `mempool` supplies the priority-ordered snapshot from which user
/// transactions are selected (placed after the coinbase tx, before the
/// fee-collecting tx).
///
/// `eligible_rent_boxes` are storage-rent-eligible boxes (resolved by the
/// engine driver against the build's committed snapshot, oldest-first,
/// already capped) the miner self-claims with no fee. The claim is pinned
/// ahead of mempool selection so any conflicting fee-bearing claim on the
/// same box is excluded. An empty slice disables rent collection.
#[allow(clippy::too_many_arguments)]
pub fn generate_candidate<V: CandidateStateView>(
    view: &V,
    mode: BuildMode,
    mempool: MempoolReadSnapshot,
    miner_pk: &[u8; 33],
    monetary: &MonetarySettings,
    reemission: Option<&ReemissionSettings>,
    // EIP-27 re-emission VALIDATION rules (distinct from the emission-curve
    // `reemission` above): threaded into every `TxValidationCtx` this builds so
    // the candidate's emission tx, fee tx, storage-rent claims, and selected
    // mempool txs are all checked against the burning condition — closing the
    // gap where a locally-assembled candidate could carry an EIP-27-invalid tx
    // that block validation later rejects. `None` where EIP-27 is disabled.
    reemission_rules: Option<&ReemissionRuleInputs>,
    chain_config: &DifficultyParams,
    eligible_rent_boxes: &[ErgoBox],
    voting_targets: &BTreeMap<u8, i64>,
    voting_settings: &VotingSettings,
    // Component B side-output: ids of pooled txs whose consensus re-validation
    // failed during selection (suspected tip-invalid). Written only on the Full
    // path that runs mempool selection; left untouched for Minimal builds. The
    // engine forwards these to the node, which re-validates each against the live
    // tip and evicts the still-invalid ones. A side-output (not part of the
    // Candidate) because suspects are diagnostic, not consensus artifacts.
    suspects_out: &mut Vec<Digest32>,
    // DEVNET block-1 (genesis) build: `Some` only when building the first block
    // on a bare genesis, where there is no stored parent header / parent block.
    // Supplies the synthetic parent header (state_root + timestamp carrier) and
    // the genesis emission box; the branch also forces `initial_difficulty` and
    // an EMPTY extension (block 1 IS the genesis block — no interlinks). `None`
    // for every normal build, which reads all of this from the committed view.
    genesis: Option<&crate::genesis::GenesisBuildInputs>,
) -> Result<Option<(Candidate, WorkMessage, PhaseTimings)>, MiningError> {
    // 1. Tip + parent header (all reads via one committed view — see
    //    `CandidateStateView`; the snapshot impl sources them from a single
    //    redb read txn so the whole build is one consistent committed view).
    let parent_id: [u8; 32] = view.best_full_block_id();
    let parent_height = view.best_full_block_height();
    let candidate_height = parent_height + 1;
    let mut timings = PhaseTimings::default();

    let parent_header = match genesis {
        // Genesis (block 1): there is no stored parent header; use the synthetic
        // height-0 carrier (genesis state_root + base timestamp).
        Some(g) => g.parent_header.clone(),
        None => {
            let parent_header_bytes = view
                .get_header_bytes(&parent_id)
                .map_err(state_err)?
                .ok_or_else(|| MiningError::StateRead {
                    op: "load_parent_header",
                    reason: format!(
                        "best_full_block_id {} not in HEADERS",
                        hex::encode(parent_id)
                    ),
                })?;
            let mut r = VlqReader::new(&parent_header_bytes);
            read_header(&mut r).map_err(|e| MiningError::Decode {
                op: "parent_header",
                reason: format!("{e:?}"),
            })?
        }
    };

    // 2. Snapshot params + applied-chain window
    let (active_params, validation_settings) = view.tip_snapshot_params().map_err(state_err)?;
    // Last-10 window for the tx-validation context. Genesis (block 1) has no
    // predecessors — the apply path's `load_last_headers` returns an EMPTY
    // window for a `[0;32]` parent. The candidate context type is a fixed
    // `[Header; 10]`, so fill it with the synthetic genesis header: block 1's
    // only tx is the emission coinbase, which does not consult `CONTEXT.headers`,
    // and the apply path independently re-validates against its empty window —
    // so the fill is consensus-neutral (the increment-4 apply round-trip pins it).
    let last_headers = match genesis {
        Some(g) => std::array::from_fn(|_| g.parent_header.clone()),
        None => view.last_applied_chain_window_10().map_err(state_err)?,
    };

    // 2b. Epoch-boundary recompute. At a voting-epoch start the candidate's
    //     extension must carry the recomputed parameter map + cumulative
    //     validation settings, and its header version is the RECOMPUTED version
    //     (exBlockVersion, rule 410). We run the SAME `compute_next_params` the
    //     block validator runs (`block_proc.rs`), so a peer re-running it accepts
    //     the block by construction. Off-boundary ⇒ `None`, version unchanged.
    //     NB: the block's transactions still validate under the PREVIOUS epoch's
    //     params (`active_params`) — Scala applies the recomputed set only from
    //     the next block — so tx selection below is unaffected.
    let is_epoch_start =
        candidate_height > 0 && candidate_height.is_multiple_of(voting_settings.voting_length);
    let epoch_payload = if is_epoch_start {
        // Mode 2 (UTXO-snapshot) bootstrap: until the first post-snapshot
        // boundary block is APPLIED, the view's cumulative validation settings
        // are still launch defaults (the validator accepts that boundary only
        // via its one-shot trust path). If THIS node were to mine that boundary,
        // it would serialize an empty/partial `0x02` block omitting the real
        // pre-snapshot rules (e.g. mainnet 215/409), which full-history peers
        // reject on `exMatchValidationSettings`. Refuse the candidate ONLY while
        // the settings are genuinely untrusted (sentinel armed AND still
        // launch-empty) — a stale armed sentinel whose settings are already
        // seeded mines correctly. The engine skips this one block; boundary
        // mining resumes once the first boundary apply seeds the real settings.
        let mode2_trust_armed = view.mode2_trust_first_epoch_armed().map_err(state_err)?;
        if mode2_settings_untrusted(mode2_trust_armed, &validation_settings) {
            return Err(MiningError::InvalidConfig(format!(
                "epoch-boundary candidate at h={candidate_height} refused: Mode 2 \
                 snapshot trust is armed and the local cumulative validation settings \
                 are not yet established, so the serialized extension would be rejected \
                 by full-history peers. Boundary mining resumes after the first \
                 post-snapshot boundary block is applied."
            )));
        }
        // Tally the just-finished epoch's votes exactly as the validator does
        // (`compute_epoch_votes` over the same canonical headers), then run the
        // pure recompute.
        let reader = ViewChainHeaderReader { view };
        let epoch_votes =
            compute_epoch_votes(&reader, candidate_height, voting_settings.voting_length).map_err(
                |e| MiningError::StateRead {
                    op: "compute_epoch_votes",
                    reason: e.to_string(),
                },
            )?;
        Some(compute_epoch_payload(
            &active_params,
            &validation_settings,
            &epoch_votes,
            candidate_height,
            voting_settings,
        )?)
    } else {
        None
    };
    let block_version = epoch_payload
        .as_ref()
        .map(|p| p.computed.block_version)
        .unwrap_or(active_params.block_version);

    // 2c. Operator votes. At an epoch start these SEED the new epoch's ballot
    //     (so subsequent in-epoch votes for the same id count); off-boundary
    //     they reinforce an already-seeded id. Votes are selected against the
    //     table that takes effect for the epoch being voted on — the RECOMPUTED
    //     set at an epoch start (`vote_selection_params`), so a target the
    //     just-finished epoch already reached isn't re-voted and a parameter
    //     that becomes votable only now (e.g. subblocksPerBlock at EIP-37
    //     activation) can be seeded. `select_candidate_votes` only ever emits a
    //     triple the header-votes validator accepts; at an epoch start the
    //     suppression of decreases / id 9 follows the live rule-215 status
    //     (disabled by mainnet 6.0). Empty targets ⇒ `[0,0,0]`.
    let rule_215_disabled = validation_settings.is_rule_disabled(RULE_HDR_VOTES_UNKNOWN);
    let candidate_votes = select_candidate_votes(
        vote_selection_params(&active_params, epoch_payload.as_ref()),
        voting_targets,
        is_epoch_start,
        rule_215_disabled,
    );

    // 3. Difficulty retarget (or parent's nBits when non-recalc). Genesis
    //    (block 1) is fixed at `initial_difficulty` — Scala's genesis-header
    //    validation (`process_genesis_header`) requires exactly this, and the
    //    height-1 epoch window is degenerate (`load_epoch_headers` drops the
    //    genesis pseudo-height 0), so the retarget path can't run.
    let new_n_bits = match genesis {
        Some(_) => encode_compact_bits(&BigUint::from_bytes_be(&chain_config.initial_difficulty)),
        None => {
            let epoch_len = epoch_length_for_height(candidate_height, chain_config);
            let needed_heights = previous_heights_for_recalculation(candidate_height, epoch_len);
            let epoch_headers = load_epoch_headers(view, &needed_heights, &parent_header)?;
            next_n_bits(candidate_height, &epoch_headers, chain_config).map_err(|e| {
                MiningError::IdComputation {
                    op: "difficulty_retarget",
                    reason: e.to_string(),
                }
            })?
        }
    };

    // 4. Timestamp: clamped monotonic.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(parent_header.timestamp + 1);
    let timestamp = std::cmp::max(now_ms, parent_header.timestamp + 1);

    // 5. Build pre-header. At an epoch boundary the version is the RECOMPUTED
    //    one (a soft-fork activation bumps it here); off-boundary it equals
    //    `active_params.block_version`.
    let pre_header = CandidatePreHeader {
        version: block_version,
        parent_id,
        height: candidate_height,
        timestamp,
        n_bits: new_n_bits,
        votes: candidate_votes,
        miner_pubkey: *miner_pk,
    };

    // 6. Activated script version + last_block_utxo_root.
    let activated_script_version = derive_activated_script_version(pre_header.version);
    let last_block_utxo_root = build_last_block_utxo_root(parent_header.state_root);

    let validation_ctx = CandidateValidationContext {
        pre_header: pre_header.clone(),
        activated_script_version,
        last_headers: last_headers.clone(),
        last_block_utxo_root,
    };

    // 7. Build extension fields: interlinks always, plus — at an epoch
    //    boundary — the recomputed `0x00` parameter map (with the carried-
    //    forward `proposed_update` at id 124) and the `0x02` cumulative
    //    validation-settings chunks. Both are the exact inverse of the parser
    //    the validator runs, so the serialized extension re-parses to the same
    //    params/settings the validator recomputes.
    let extension_fields = match genesis {
        // Genesis (block 1) carries an EMPTY extension: no interlinks (height 2
        // is the first block to link back to genesis), and height 1 is never a
        // voting-epoch boundary. Confirmed against the interlinks corpus
        // (height-1 block: 0 extension fields).
        Some(_) => Vec::new(),
        None => {
            let parent_extension_bytes = read_parent_extension_bytes(view, &parent_header)?;
            let parent_interlinks = unpack_interlinks_from_extension(&parent_extension_bytes)?;
            // A non-genesis parent must carry interlinks; an empty set means its
            // stored extension is malformed or missing them. Fail the build with a
            // typed error here rather than panicking the engine task downstream
            // (`update_interlinks` asserts a non-empty interlinks vector for a
            // non-genesis header).
            if *parent_header.parent_id.as_bytes() != [0u8; 32] && parent_interlinks.is_empty() {
                return Err(MiningError::Decode {
                    op: "parent_interlinks",
                    reason: "non-genesis parent extension carries no interlinks fields".into(),
                });
            }
            let epoch_boundary_fields = epoch_payload
                .as_ref()
                .map(|p| p.extension_fields())
                .unwrap_or_default();
            build_candidate_extension_fields(
                &parent_header,
                &parent_interlinks,
                candidate_height,
                voting_settings.voting_length,
                &epoch_boundary_fields,
            )?
        }
    };

    // 8. Coinbase: emission tx. Three regimes:
    //   - reemission = Some + height > activation_height: post-EIP-27,
    //     one input, deducts reemission tokens per block (mainnet
    //     regime since h=777_217).
    //   - reemission = Some + height <= activation_height: pre-EIP-27
    //     emission tx (mainnet pre-777_217 history; not exercised in
    //     practice now that mainnet is past activation).
    //   - reemission = None: network has no EIP-27 protocol (new
    //     public testnet); always pre-EIP-27 emission tx.
    let phase_start = std::time::Instant::now();
    let emission_box = match genesis {
        // Genesis (block 1): the emission box is the seeded genesis box, not a
        // box derived from a parent block's BlockTransactions section.
        Some(g) => g.emission_box.clone(),
        None => lookup_emission_box_from_parent(view, &parent_id, &parent_header)?,
    };
    let emission_tx = match reemission {
        Some(reem) if candidate_height > reem.activation_height => {
            build_post_eip27_emission_tx(&emission_box, miner_pk, candidate_height, monetary, reem)?
        }
        _ => build_pre_eip27_emission_tx(&emission_box, miner_pk, candidate_height, monetary)?,
    };

    // 9. Validate the emission (coinbase) tx → CheckedTransaction, using the
    //    live voted params (from_active) so cost / min-value / storage
    //    params match the validator that judges the submitted block.
    let block_cap = JitCost::from_block_cost(active_params.max_block_cost as u64).map_err(|e| {
        MiningError::IdComputation {
            op: "max_block_cost_to_jit",
            reason: format!("{e:?}"),
        }
    })?;
    let params = ProtocolParams::from_active(&active_params);
    let ctx = TransactionContext {
        height: candidate_height,
        miner_pubkey: *miner_pk,
        pre_header_timestamp: timestamp,
        activated_script_version,
        pre_header_version: pre_header.version,
        pre_header_parent_id: parent_id,
        pre_header_n_bits: new_n_bits as u64,
        pre_header_votes: candidate_votes,
    };

    let emission_bytes = serialize_tx(&emission_tx, "serialize_emission_tx")?;
    let emission_size = emission_bytes.len() as u64;
    let mut emission_cost_acc = CostAccumulator::new(block_cap);
    let checked_emission = {
        let mut tx_ctx = TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut emission_cost_acc,
            last_headers: last_headers.as_slice(),
            rules: TxValidationRules {
                reemission: reemission_rules,
            },
        };
        validate_transaction_parsed(
            emission_tx.clone(),
            &emission_bytes,
            vec![emission_box.clone()],
            Vec::new(),
            false,
            &mut tx_ctx,
        )
        .map_err(|e| MiningError::IdComputation {
            op: "validate_emission_tx",
            reason: format!("{e:?}"),
        })?
    };
    let emission_cost = emission_cost_acc.total_block_cost();
    timings.emission = phase_start.elapsed();

    // 9b–9e. Block enrichment — skipped wholesale in a Minimal build: no
    //        overlay, no rent claim, no mempool selection, no fee tx. The
    //        minimal template is the strict [emission] prefix of a full
    //        block — same shape, same consensus pipeline below.
    let (checked_rent, user_checked, checked_fee) = if mode == BuildMode::Minimal {
        (None, Vec::new(), None)
    } else {
        // 9b. Seed an in-block overlay (over the committed state tip — the same
        //     base view the submit-time validator uses) with the emission tx.
        let base: &dyn UtxoView = view;
        let mut overlay = CandidateOverlay::new(base);
        overlay.apply_tx(&emission_tx)?;

        // 9c. Pinned storage-rent self-claim, sized to FILL the block budget.
        //     Sweep the oldest eligible boxes into a claim bounded by the block
        //     cost/size budget (after the coinbase, reserving ~1/16 of the block
        //     for fee-paying user txs), so the pinned [coinbase, rent] prefix can
        //     never exceed max_block_cost / max_block_size — only the block caps
        //     gate a self-mined tx (no consensus per-tx size limit; per-tx counts
        //     cap at 32_767, far above what fits). The claim is applied to the
        //     overlay BEFORE mempool selection so any conflicting fee-bearing
        //     claim on the same box is excluded. Zero fee; proceeds to the
        //     miner P2PK.
        let max_block_cost = active_params.max_block_cost as u64;
        let max_block_size = active_params.max_block_size as u64;
        let phase_start = std::time::Instant::now();
        let rent_cost_ceiling = max_block_cost
            .saturating_sub(DEFAULT_COST_SAFETY_GAP)
            .saturating_sub(emission_cost)
            .saturating_sub(max_block_cost / 16);
        let rent_size_ceiling = max_block_size
            .saturating_sub(emission_size)
            .saturating_sub(max_block_size / 16);
        let (checked_rent, rent_cost, rent_size) = match build_budget_bounded_rent_claim(
            eligible_rent_boxes,
            candidate_height,
            &params,
            eligible_rent_boxes.len(),
            miner_pk,
            &ctx,
            last_headers.as_slice(),
            rent_cost_ceiling,
            rent_size_ceiling,
            reemission_rules,
        )? {
            Some((checked, cost, size)) => {
                overlay.apply_tx(checked.transaction())?;
                (Some(checked), cost, size)
            }
            None => (None, 0, 0),
        };
        timings.rent = phase_start.elapsed();

        // 9d. Select mempool transactions into the budget remaining after the
        //     coinbase + rent claim. The overlay (emission + rent applied)
        //     excludes intra-block double-spends and rent conflicts; the budgets
        //     keep the block under the voted cost/size caps (candidate_dry_run
        //     checks neither).
        let phase_start = std::time::Instant::now();
        let cost_budget = max_block_cost
            .saturating_sub(DEFAULT_COST_SAFETY_GAP)
            .saturating_sub(emission_cost)
            .saturating_sub(rent_cost);
        let size_budget = max_block_size
            .saturating_sub(emission_size)
            .saturating_sub(rent_size)
            .saturating_sub(BLOCK_ASSEMBLY_SIZE_RESERVE);

        let selected = select_user_txs(
            &mut overlay,
            &mempool,
            &ctx,
            &params,
            last_headers.as_slice(),
            cost_budget,
            size_budget,
            reemission_rules,
        )?;

        // Component B: forward consensus-revalidation-failure suspects to the
        // caller. Copied (Digest32 is Copy) so `selected` stays intact for the
        // fee-trim below.
        suspects_out.extend(selected.suspects.iter().copied());

        // 9e. Decide the final user set + fee tx. Trim the lowest-priority user
        //     tx (rebuilding the fee tx) until the assembled block fits BOTH the
        //     voted cost cap — emission + rent + user txs + the fee tx's OWN
        //     cost, under a safety gap — and the BlockTransactions size cap
        //     (rule 306). `candidate_dry_run` checks neither, and the fee tx's
        //     cost (one input per collected fee box) is otherwise unbudgeted, so
        //     a block could pass the dry-run yet be rejected at submit on
        //     `max_block_cost`. The fee tx is validated against a FRESH overlay
        //     rebuilt from the kept set, so a trimmed tx never leaves a stale
        //     spend behind.
        let mut user_checked = selected.checked; // Vec<(CheckedTransaction, cost)>
        let cost_ceiling = max_block_cost.saturating_sub(DEFAULT_COST_SAFETY_GAP);
        let checked_fee = loop {
            let user_raw: Vec<Transaction> = user_checked
                .iter()
                .map(|(c, _)| c.transaction().clone())
                .collect();
            let fee_tx_opt = build_fee_tx(&user_raw, miner_pk, candidate_height)?;

            // Fresh overlay over [emission, rent, kept user txs] so the fee tx's
            // inputs resolve against exactly the block's contents.
            let mut fee_overlay = CandidateOverlay::new(base);
            fee_overlay.apply_tx(&emission_tx)?;
            if let Some(cr) = &checked_rent {
                fee_overlay.apply_tx(cr.transaction())?;
            }
            for (c, _) in &user_checked {
                fee_overlay.apply_tx(c.transaction())?;
            }

            let (checked_fee, fee_cost) = match &fee_tx_opt {
                Some(fee_tx) => {
                    let fee_bytes = serialize_tx(fee_tx, "serialize_fee_tx")?;
                    let (fee_inputs, fee_data_inputs) =
                        fee_overlay.resolve_tx(fee_tx).ok_or_else(|| {
                            MiningError::IdComputation {
                                op: "fee_tx_resolve",
                                reason:
                                    "fee-proposition box not resolvable against in-block overlay"
                                        .into(),
                            }
                        })?;
                    let mut fee_cost_acc = CostAccumulator::new(block_cap);
                    let cf = {
                        let mut fee_ctx = TxValidationCtx {
                            ctx: &ctx,
                            params: &params,
                            cost: &mut fee_cost_acc,
                            last_headers: last_headers.as_slice(),
                            rules: TxValidationRules {
                                reemission: reemission_rules,
                            },
                        };
                        validate_transaction_parsed(
                            fee_tx.clone(),
                            &fee_bytes,
                            fee_inputs,
                            fee_data_inputs,
                            false,
                            &mut fee_ctx,
                        )
                        .map_err(|e| MiningError::IdComputation {
                            op: "validate_fee_tx",
                            reason: format!("{e:?}"),
                        })?
                    };
                    (Some(cf), fee_cost_acc.total_block_cost())
                }
                None => (None, 0),
            };

            let user_cost: u64 = user_checked.iter().map(|(_, cost)| *cost).sum();
            let total_cost = emission_cost
                .saturating_add(rent_cost)
                .saturating_add(user_cost)
                .saturating_add(fee_cost);

            let mut probe: Vec<Transaction> = Vec::with_capacity(3 + user_raw.len());
            probe.push(emission_tx.clone());
            if let Some(cr) = &checked_rent {
                probe.push(cr.transaction().clone());
            }
            probe.extend(user_raw);
            if let Some(ft) = &fee_tx_opt {
                probe.push(ft.clone());
            }
            let section_size = block_transactions_section_size(&probe, pre_header.version)?;

            if (total_cost <= cost_ceiling && section_size <= max_block_size as usize)
                || user_checked.is_empty()
            {
                break checked_fee;
            }
            user_checked.pop();
        };
        timings.select = phase_start.elapsed();

        (checked_rent, user_checked, checked_fee)
    };

    // 9f. Assemble the final tx list in block order:
    //     emission, rent, user txs, fee.
    let mut checked: Vec<CheckedTransaction> = Vec::with_capacity(3 + user_checked.len());
    checked.push(checked_emission);
    if let Some(cr) = checked_rent {
        checked.push(cr);
    }
    for (c, _) in user_checked {
        checked.push(c);
    }
    if let Some(cf) = checked_fee {
        checked.push(cf);
    }
    let raw_txs: Vec<Transaction> = checked.iter().map(|c| c.transaction().clone()).collect();

    // 10. Dry-run AVL+ to obtain new_state_root + raw_proof_bytes.
    let phase_start = std::time::Instant::now();
    let (new_state_root, ad_proof_bytes, snapshot_tip_id) =
        view.candidate_dry_run(&checked).map_err(state_err)?;
    timings.dryrun = phase_start.elapsed();

    // 11. Parent-id guard: best-full advanced during generation.
    if snapshot_tip_id != parent_id {
        return Ok(None);
    }

    // 12. Compute roots.
    let phase_start = std::time::Instant::now();
    let ad_proofs_root = Digest32::from_bytes(*blake2b256(&ad_proof_bytes).as_bytes());

    let tx_ids_owned: Vec<[u8; 32]> = raw_txs
        .iter()
        .map(|tx| {
            let bts = bytes_to_sign(tx).map_err(|e| MiningError::IdComputation {
                op: "bytes_to_sign",
                reason: format!("{e:?}"),
            })?;
            Ok::<[u8; 32], MiningError>(*blake2b256(&bts).as_bytes())
        })
        .collect::<Result<_, _>>()?;
    let witness_ids_owned: Vec<Vec<u8>> = if pre_header.version >= 2 {
        raw_txs
            .iter()
            .map(|tx| {
                let mut all_proofs = Vec::new();
                for input in &tx.inputs {
                    all_proofs.extend_from_slice(&input.spending_proof.proof);
                }
                blake2b256(&all_proofs).as_bytes()[1..].to_vec()
            })
            .collect()
    } else {
        Vec::new()
    };

    let tx_id_slices: Vec<&[u8]> = tx_ids_owned.iter().map(|id| id.as_slice()).collect();
    let wit_slices: Vec<&[u8]> = witness_ids_owned.iter().map(|w| w.as_slice()).collect();
    let transactions_root_bytes = if pre_header.version >= 2 {
        transactions_root(&tx_id_slices, Some(&wit_slices))
    } else {
        transactions_root(&tx_id_slices, None)
    };

    let extension_field_refs: Vec<(&[u8], &[u8])> = extension_fields
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let extension_root_bytes = extension_root(&extension_field_refs);
    timings.roots = phase_start.elapsed();

    // 13. Assemble header with placeholder solution.
    let placeholder_solution = AutolykosSolution::V2 {
        pk: ergo_primitives::group_element::GroupElement::from(*miner_pk),
        nonce: [0u8; 8],
    };
    let header = Header {
        version: pre_header.version,
        parent_id: Digest32::from_bytes(parent_id).into(),
        ad_proofs_root,
        transactions_root: Digest32::from_bytes(transactions_root_bytes),
        state_root: new_state_root,
        timestamp,
        extension_root: Digest32::from_bytes(extension_root_bytes),
        n_bits: new_n_bits,
        height: candidate_height,
        votes: candidate_votes,
        unparsed_bytes: Vec::new(),
        solution: placeholder_solution,
    };

    // 14. Compute work message + target.
    let header_without_pow_bytes = serialize_header_without_pow(&header)?;
    let msg: [u8; 32] = *blake2b256(&header_without_pow_bytes).as_bytes();
    let target = get_target(new_n_bits);

    // 15. Build the typed work message (JSON marshalling happens at the
    //     node's mining bridge).
    let work_msg = WorkMessage {
        msg,
        target: target.clone(),
        height: candidate_height,
        pk: *miner_pk,
    };

    // 16. Pack the cached candidate.
    let candidate = Candidate {
        header,
        validation_ctx,
        transactions: raw_txs,
        ad_proof_bytes,
        extension_fields,
        msg,
        target,
        parent_id,
    };

    let _ = (validation_settings,); // reserved for v2 user-tx validation

    Ok(Some((candidate, work_msg, timings)))
}

// ---- private helpers ----

/// Headroom reserved under `max_block_size` when budgeting mempool
/// selection, leaving room for the fee tx + section framing. The exact
/// `block_transactions_section_size` guard trims the assembly if it still
/// overruns, so this only reduces how often that trim loop runs.
const BLOCK_ASSEMBLY_SIZE_RESERVE: u64 = 32_768;

fn serialize_tx(tx: &Transaction, op: &'static str) -> Result<Vec<u8>, MiningError> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).map_err(|e| MiningError::IdComputation {
        op,
        reason: format!("{e:?}"),
    })?;
    Ok(w.result())
}

/// Serialized length of the `BlockTransactions` section (the rule-306
/// input). Mirrors `ergo-validation::check_block_transactions_size`, which
/// re-serializes via `write_block_transactions_with_version`. The header id
/// is a placeholder — only the byte length matters, and that is independent
/// of the 32-byte id's value.
fn block_transactions_section_size(
    txs: &[Transaction],
    block_version: u8,
) -> Result<usize, MiningError> {
    let bt = BlockTransactions {
        header_id: Digest32::from_bytes([0u8; 32]).into(),
        transactions: txs.to_vec(),
    };
    let mut w = VlqWriter::new();
    write_block_transactions_with_version(&mut w, &bt, block_version).map_err(|e| {
        MiningError::IdComputation {
            op: "block_transactions_size",
            reason: format!("{e:?}"),
        }
    })?;
    Ok(w.result().len())
}

fn state_err(e: ergo_state::store::StateError) -> MiningError {
    MiningError::StateRead {
        op: "candidate_assembly",
        reason: format!("{e:?}"),
    }
}

/// Recomputed data an epoch-boundary candidate must carry: the next-epoch
/// active parameter set (whose serialized `0x00` fields + `block_version` the
/// header uses) and the cumulative validation-settings update (`0x02` fields).
#[derive(Debug)]
struct EpochBoundaryPayload {
    /// Next-epoch active params from `compute_next_params` — the SAME value the
    /// block validator recomputes, so its serialized `0x00` fields satisfy
    /// `exMatchParameters` and its `block_version` satisfies `exBlockVersion`.
    computed: ActiveProtocolParameters,
    /// Cumulative `ErgoValidationSettings.update_from_initial` after applying
    /// this epoch's `activated_update` — its serialized `0x02` chunks satisfy
    /// `exMatchValidationSettings`. Empty on chains/heights with no activated
    /// validation-settings update (e.g. all of mainnet through v3).
    cumulative: ErgoValidationSettingsUpdate,
}

impl EpochBoundaryPayload {
    /// The `0x00` parameter fields + `0x02` validation-settings chunks for the
    /// extension, in a deterministic order (params then settings) so the
    /// off-loop and on-loop builds produce byte-identical extensions.
    fn extension_fields(&self) -> Vec<([u8; 2], Vec<u8>)> {
        let mut fields = active_params_to_extension_fields(&self.computed);
        fields.extend(validation_settings_update_to_extension_fields(
            &self.cumulative,
        ));
        fields
    }
}

/// [`ChainHeaderReader`] over a [`CandidateStateView`]: resolves a height to its
/// canonical applied-chain header and projects the `votes` the epoch tally
/// needs. Used only at an epoch boundary, walking the just-finished epoch.
struct ViewChainHeaderReader<'a, V: CandidateStateView> {
    view: &'a V,
}

impl<V: CandidateStateView> ChainHeaderReader for ViewChainHeaderReader<'_, V> {
    fn header_at(&self, height: u32) -> Result<HeaderView, ChainHeaderReaderError> {
        let backend = |msg: String| ChainHeaderReaderError::Backend {
            height,
            source: Box::new(std::io::Error::other(msg)),
        };
        let id = self
            .view
            .header_id_at_height(height)
            .map_err(|e| backend(format!("header_id_at_height h={height}: {e:?}")))?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let bytes = self
            .view
            .get_header_bytes(&id)
            .map_err(|e| backend(format!("get_header_bytes h={height}: {e:?}")))?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let mut r = VlqReader::new(&bytes);
        let hdr =
            read_header(&mut r).map_err(|e| backend(format!("decode header h={height}: {e:?}")))?;
        Ok(HeaderView { votes: hdr.votes })
    }
}

/// Whether an epoch-boundary candidate must be refused because the local
/// cumulative validation settings are NOT yet trustworthy — the Mode 2
/// (UTXO-snapshot) bootstrap window. This mirrors the validator's trust gate
/// (`validate_epoch_extension` fires its one-shot trust path only when
/// `prev_settings.update_from_initial == empty()`): refuse ONLY when the Mode 2
/// sentinel is armed AND the settings are still launch-empty. A STALE armed
/// sentinel whose settings are already seeded (crash after the trusted boundary
/// applied but before `consume`, or a best-effort persisted-clear that failed)
/// can serialize the real `0x02` block correctly, so it is NOT refused; and
/// legitimately-empty pre-soft-fork settings on a normal node (sentinel not
/// armed) mine normally.
fn mode2_settings_untrusted(
    mode2_trust_armed: bool,
    validation_settings: &ErgoValidationSettings,
) -> bool {
    mode2_trust_armed
        && validation_settings.update_from_initial == ErgoValidationSettingsUpdate::empty()
}

/// The active parameter table the operator's votes are selected against. At an
/// epoch start the votes seed the NEW epoch, whose table is the recomputed
/// `epoch_payload.computed` set — selecting against it avoids re-voting a target
/// the just-finished epoch already reached, and lets a parameter that first
/// becomes present in the new epoch (e.g. `subblocksPerBlock` at EIP-37
/// activation) be seeded in its first active epoch. Off-boundary,
/// `active_params` IS the live table.
fn vote_selection_params<'a>(
    active_params: &'a ActiveProtocolParameters,
    epoch_payload: Option<&'a EpochBoundaryPayload>,
) -> &'a ActiveProtocolParameters {
    epoch_payload.map(|p| &p.computed).unwrap_or(active_params)
}

/// Run the next-epoch recompute for an epoch-boundary candidate, mirroring the
/// block validator (`block_proc.rs` → `validate_epoch_extension` →
/// `compute_next_params`). Pure (the `epoch_votes` tally is supplied by the
/// caller). The miner runs the IDENTICAL computation the validator will, so a
/// peer re-running it accepts the produced block by construction:
///
/// * `epoch_votes` is the just-finished epoch's tally, from the SAME
///   [`compute_epoch_votes`] walk the validator performs over the canonical
///   chain.
/// * `proposed_update` is CARRIED FORWARD from the previous epoch
///   (`active_params.proposed_update`), never reset — resetting would disrupt an
///   in-progress soft-fork vote. This node never casts a soft-fork (120) vote,
///   so `fork_vote` is `false`.
/// * the cumulative validation settings are `prev_settings.updated(activated)`.
///
/// The genesis-era first boundary (`active_params.epoch_start_height == 0`)
/// takes Scala's bypass path, which this does not reproduce; a live node is
/// always far past it, so that case is refused rather than mis-built.
fn compute_epoch_payload(
    active_params: &ActiveProtocolParameters,
    validation_settings: &ErgoValidationSettings,
    epoch_votes: &[(i8, i32)],
    candidate_height: u32,
    voting_settings: &VotingSettings,
) -> Result<EpochBoundaryPayload, MiningError> {
    if active_params.epoch_start_height == 0 {
        return Err(MiningError::InvalidConfig(format!(
            "genesis-era epoch-boundary candidate at h={candidate_height} not supported \
             (the previous epoch starts at genesis; the validator's genesis bypass \
             path is not reproduced here)"
        )));
    }
    // Carry forward the in-flight proposal; never reset to empty.
    let proposed = active_params.proposed_update.clone();
    let (computed, activated_update) = compute_next_params(
        active_params,
        epoch_votes,
        false, // we never emit a soft-fork (120) vote
        &proposed,
        candidate_height,
        voting_settings,
    )
    .map_err(|e| MiningError::IdComputation {
        op: "compute_next_params",
        reason: e.to_string(),
    })?;
    let cumulative = validation_settings
        .updated(&activated_update)
        .update_from_initial;
    Ok(EpochBoundaryPayload {
        computed,
        cumulative,
    })
}

fn load_epoch_headers<V: CandidateStateView>(
    view: &V,
    needed: &[u32],
    parent_header: &Header,
) -> Result<Vec<Header>, MiningError> {
    let mut out = Vec::with_capacity(needed.len());
    for &h in needed {
        if h == 0 {
            // genesis pseudo-height: Scala's flatMap silently drops
            continue;
        }
        if h == parent_header.height {
            out.push(parent_header.clone());
            continue;
        }
        let id = view
            .header_id_at_height(h)
            .map_err(state_err)?
            .ok_or_else(|| MiningError::StateRead {
                op: "load_epoch_headers",
                reason: format!("no header at height {h}"),
            })?;
        let bytes = view
            .get_header_bytes(&id)
            .map_err(state_err)?
            .ok_or_else(|| MiningError::StateRead {
                op: "load_epoch_headers",
                reason: format!("header bytes missing for id {}", hex::encode(id)),
            })?;
        let mut r = VlqReader::new(&bytes);
        let hdr = read_header(&mut r).map_err(|e| MiningError::Decode {
            op: "epoch_header",
            reason: format!("h={h}: {e:?}"),
        })?;
        out.push(hdr);
    }
    Ok(out)
}

fn read_parent_extension_bytes<V: CandidateStateView>(
    view: &V,
    parent_header: &Header,
) -> Result<Vec<u8>, MiningError> {
    use ergo_ser::modifier_id::{compute_section_id, TYPE_EXTENSION};
    let parent_header_id: [u8; 32] = {
        // header_id is blake2b256 of full serialized header. We have the
        // parent in hand; re-serialize to compute.
        let (_, id) = ergo_ser::header::serialize_header(parent_header)?;
        *id.as_bytes()
    };
    let ext_section_id = compute_section_id(
        TYPE_EXTENSION,
        &parent_header_id,
        parent_header.extension_root.as_bytes(),
    );
    view.block_section(&ext_section_id)
        .map_err(state_err)?
        .ok_or_else(|| MiningError::StateRead {
            op: "load_parent_extension",
            reason: format!(
                "extension section {} not stored",
                hex::encode(ext_section_id)
            ),
        })
}

fn unpack_interlinks_from_extension(
    extension_bytes: &[u8],
) -> Result<Vec<ergo_primitives::digest::ModifierId>, MiningError> {
    // The parent's Extension section is stored in the canonical Scala wire
    // format — `[32-byte header_id][u16 n_fields]` then per field
    // `[2-byte key][u8 val_len][val]` — the exact shape `write_extension`
    // emits and block-apply / peer ingest persist. Decode it with the
    // canonical `read_extension` so the 2-byte keys (and thus the interlinks
    // fields) align with how blocks are actually written; a bespoke parser
    // would mis-frame every field.
    let mut r = VlqReader::new(extension_bytes);
    let ext = ergo_ser::extension::read_extension(&mut r).map_err(|e| MiningError::Decode {
        op: "parent_extension",
        reason: format!("{e:?}"),
    })?;
    // `unpack_interlinks` keeps only the interlinks-prefixed fields and ignores
    // any others (voted params, etc.).
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = ext
        .fields
        .into_iter()
        .map(|f| (f.key.to_vec(), f.value))
        .collect();
    unpack_interlinks(&pairs).map_err(|e| MiningError::Decode {
        op: "interlinks",
        reason: format!("{e:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::{write_extension, Extension, ExtensionField};
    use ergo_validation::popow::algos::pack_interlinks;
    use serde::Deserialize;

    // ----- helpers -----

    /// Captured mainnet interlinks corpus entry (subset of fields needed
    /// here). Same JSON the `extension_builder` tests load.
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct InterlinksVector {
        height: u32,
        header_id: String,
        version: u8,
        n_interlinks_fields: usize,
        n_extension_fields_total: usize,
        interlinks_fields: Vec<[String; 2]>,
    }

    fn load_corpus(h: u32) -> InterlinksVector {
        let path = format!(
            "{}/../test-vectors/mining/interlinks_corpus/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            h
        );
        serde_json::from_slice(&std::fs::read(&path).expect("read corpus")).expect("parse corpus")
    }

    /// Serialize an interlinks vector into the canonical Extension section
    /// bytes — `pack_interlinks` into 2-byte-keyed fields, then
    /// `write_extension` — i.e. exactly what `apply_mined_block` / peer ingest
    /// persist for a block's parent. This is the byte form the read side under
    /// test must accept.
    fn canonical_extension_bytes(header_id: [u8; 32], interlinks: &[ModifierId]) -> Vec<u8> {
        let fields = pack_interlinks(interlinks);
        let ext = Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields: fields
                .into_iter()
                .map(|(k, v)| ExtensionField {
                    key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                    value: v,
                })
                .collect(),
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        w.result()
    }

    // ----- round-trips -----

    #[test]
    fn unpack_interlinks_from_canonically_written_extension_round_trips() {
        // The read side must consume exactly the bytes the canonical writer
        // emits (the format every applied block persists). Build an interlinks
        // vector with a duplicate run so `pack_interlinks`'s run-length
        // encoding is exercised, write it canonically, and assert the parser
        // recovers the original vector verbatim.
        let genesis = ModifierId::from_bytes([0x00u8; 32]);
        let a = ModifierId::from_bytes([0x11u8; 32]);
        let b = ModifierId::from_bytes([0x22u8; 32]);
        let interlinks = vec![genesis, a, a, a, b];

        let bytes = canonical_extension_bytes([0x9Au8; 32], &interlinks);
        let recovered =
            unpack_interlinks_from_extension(&bytes).expect("canonical extension parses");

        assert_eq!(
            recovered, interlinks,
            "the canonical writer's output must round-trip through the parser, \
             including the run-length-encoded duplicate run",
        );
    }

    #[test]
    fn unpack_interlinks_from_extension_without_interlinks_fields_is_empty() {
        // An extension carrying only non-interlinks 2-byte-key fields (e.g.
        // system-parameter `0x00..`) yields an empty interlinks vector without
        // error — `unpack_interlinks` ignores keys not prefixed with the
        // interlinks marker.
        let ext = Extension {
            header_id: ModifierId::from_bytes([0x7Cu8; 32]),
            fields: vec![
                ExtensionField {
                    key: [0x00, 0x01],
                    value: vec![0xDE, 0xAD],
                },
                ExtensionField {
                    key: [0x00, 0x02],
                    value: vec![0xBE, 0xEF],
                },
            ],
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        let bytes = w.result();

        let recovered = unpack_interlinks_from_extension(&bytes)
            .expect("non-interlinks extension parses without error");
        assert!(
            recovered.is_empty(),
            "an extension with no interlinks-prefixed fields yields no interlinks",
        );
    }

    #[test]
    fn unpack_interlinks_from_extension_with_mixed_fields_keeps_only_interlinks() {
        // A real parent extension interleaves interlinks fields with unrelated
        // ones (system parameters at epoch boundaries, miner-defined keys). The
        // parser must keep the interlinks-prefixed fields and ignore the rest,
        // recovering exactly the interlinks vector regardless of where the
        // foreign fields sit relative to the interlinks block.
        let genesis = ModifierId::from_bytes([0x00u8; 32]);
        let a = ModifierId::from_bytes([0x11u8; 32]);
        let b = ModifierId::from_bytes([0x22u8; 32]);
        let interlinks = vec![genesis, a, a, b];

        let mut fields = vec![ExtensionField {
            key: [0x00, 0x01],
            value: vec![0xDE, 0xAD],
        }];
        for (k, v) in pack_interlinks(&interlinks) {
            fields.push(ExtensionField {
                key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                value: v,
            });
        }
        fields.push(ExtensionField {
            key: [0x02, 0x00],
            value: vec![0xBE, 0xEF],
        });

        let ext = Extension {
            header_id: ModifierId::from_bytes([0x55u8; 32]),
            fields,
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        let bytes = w.result();

        let recovered = unpack_interlinks_from_extension(&bytes).expect("mixed extension parses");
        assert_eq!(
            recovered, interlinks,
            "the parser must keep only the interlinks-prefixed fields and ignore \
             unrelated extension fields, in any position",
        );
    }

    // ----- oracle parity -----

    #[test]
    fn unpack_interlinks_from_extension_recovers_real_mainnet_interlinks() {
        // Pin the section-byte parser against REAL captured mainnet interlinks:
        // block 100000 carries 7 interlinks fields with 2-byte keys
        // (0100/0101/0106/010e/010f/0111/0113) and 33-byte values. Build the
        // canonical Extension section from those captured fields, serialize it
        // exactly as an applied block persists, and assert the parser recovers
        // the same interlinks the established `unpack_interlinks` oracle does.
        // The old bespoke `[u8 key_len]` framing would mis-read the 2-byte keys
        // and fail here.
        let v = load_corpus(100_000);
        assert_eq!(v.n_interlinks_fields, v.interlinks_fields.len());

        let real_fields: Vec<(Vec<u8>, Vec<u8>)> = v
            .interlinks_fields
            .iter()
            .map(|p| {
                (
                    hex::decode(&p[0]).expect("hex key"),
                    hex::decode(&p[1]).expect("hex value"),
                )
            })
            .collect();

        let header_id_bytes: [u8; 32] = hex::decode(&v.header_id)
            .expect("hex header id")
            .try_into()
            .expect("header id is 32 bytes");

        let ext = Extension {
            header_id: ModifierId::from_bytes(header_id_bytes),
            fields: real_fields
                .iter()
                .map(|(k, val)| ExtensionField {
                    key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                    value: val.clone(),
                })
                .collect(),
        };
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("write extension");
        let bytes = w.result();

        let recovered =
            unpack_interlinks_from_extension(&bytes).expect("real mainnet extension parses");
        assert!(
            !recovered.is_empty(),
            "a block with 7 captured interlinks fields yields a non-empty vector",
        );

        let oracle = unpack_interlinks(&real_fields).expect("oracle unpack");
        assert_eq!(
            recovered, oracle,
            "section-byte parser must recover the same interlinks the \
             unpack_interlinks oracle derives from the captured mainnet fields",
        );
    }

    // ----- epoch-boundary payload (self-consistency oracle) -----

    /// Build an `Extension` from the payload's `0x00`/`0x02` fields (the parts
    /// `validate_epoch_extension` reads — interlinks `0x01` are irrelevant to
    /// it).
    fn ext_from_payload(payload: &EpochBoundaryPayload) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields: payload
                .extension_fields()
                .into_iter()
                .map(|(key, value)| ExtensionField { key, value })
                .collect(),
        }
    }

    fn boundary_header(height: u32, version: u8, votes: [u8; 3]) -> Header {
        use ergo_primitives::digest::{ADDigest, Digest32};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        Header {
            version,
            parent_id: Digest32::from_bytes([0u8; 32]).into(),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 1_700_000_000_000,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 0x0123_4567,
            height,
            votes,
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        }
    }

    /// THE consensus oracle for epoch-boundary mining: the extension + header an
    /// epoch-boundary candidate would carry must PASS the real block validator
    /// (`validate_epoch_extension` — the exact path a peer runs in
    /// `block_proc.rs`), for the SAME epoch-vote tally the miner used. If it
    /// passes here, peers accept the mined block. Covered: a quiet epoch (no
    /// votes) and an approved parameter increase.
    #[test]
    fn epoch_boundary_payload_passes_validate_epoch_extension() {
        use ergo_validation::active_params::scala_launch;
        use ergo_validation::voting::validate_epoch_extension;

        // Second-epoch boundary: prev epoch started at 1024 (non-genesis), so
        // the recompute path runs (no genesis bypass). Candidate at h=2048.
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1024;
        let prev_settings = ErgoValidationSettings::empty();
        let vs = VotingSettings::mainnet();
        let candidate_height = 2048;

        // (label, tally): quiet epoch, then a MaxBlockSize (+3) increase tallied
        // above the 1024/2 threshold (513+ approves — see recompute tests).
        let cases: [(&str, Vec<(i8, i32)>); 2] =
            [("no votes", vec![]), ("approved +3", vec![(3, 600)])];

        for (label, epoch_votes) in cases {
            let payload = compute_epoch_payload(
                &prev_active,
                &prev_settings,
                &epoch_votes,
                candidate_height,
                &vs,
            )
            .unwrap_or_else(|e| panic!("compute_epoch_payload [{label}]: {e:?}"));

            let ext = ext_from_payload(&payload);
            // Header version = the recomputed block_version (exBlockVersion).
            let header =
                boundary_header(candidate_height, payload.computed.block_version, [0u8; 3]);

            let outcome = validate_epoch_extension(
                &ext,
                &header,
                &prev_active,
                &prev_settings,
                &epoch_votes,
                &vs,
                false,
            )
            .unwrap_or_else(|e| {
                panic!("a peer must accept the mined boundary block [{label}]: {e:?}")
            });
            // The validator's recompute must equal the miner's — the block's
            // next-epoch params are exactly what we serialized.
            assert_eq!(
                outcome.computed, payload.computed,
                "validator-computed params must equal the miner's [{label}]",
            );
        }
    }

    #[test]
    fn epoch_boundary_approved_increase_moves_the_param() {
        // Sanity that the "approved +3" case is non-trivial: the recomputed
        // MaxBlockSize actually rises one step above the previous epoch's value,
        // so the oracle test above is exercising a real parameter change.
        use ergo_validation::active_params::scala_launch;
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1024;
        let prev_settings = ErgoValidationSettings::empty();
        let vs = VotingSettings::mainnet();
        let payload =
            compute_epoch_payload(&prev_active, &prev_settings, &[(3, 600)], 2048, &vs).unwrap();
        assert!(
            payload.computed.max_block_size > prev_active.max_block_size,
            "an approved +3 tally must raise MaxBlockSize ({} !> {})",
            payload.computed.max_block_size,
            prev_active.max_block_size,
        );
    }

    #[test]
    fn epoch_start_votes_select_against_recomputed_not_stale_params() {
        // codex P2: at an epoch start the seed votes must compare against the
        // RECOMPUTED table (which takes effect for the new epoch), not the stale
        // previous-epoch `active_params`. If the just-finished epoch already
        // moved a configured parameter to its target, selecting against the
        // stale table emits a pointless seed vote; selecting against `computed`
        // correctly emits none.
        use ergo_validation::active_params::scala_launch;
        use ergo_validation::voting::select_candidate_votes;

        let mut active = scala_launch();
        active.epoch_start_height = 1024;
        active.max_block_size = 524_288; // id 3, below the operator's target
        let mut computed = active.clone();
        computed.epoch_start_height = 2048;
        computed.max_block_size = 600_000; // reached the target this recompute
        let payload = EpochBoundaryPayload {
            computed,
            cumulative: ErgoValidationSettingsUpdate::empty(),
        };
        let mut targets = BTreeMap::new();
        targets.insert(3u8, 600_000i64);

        // The wiring picks the recomputed table at an epoch start.
        let chosen = vote_selection_params(&active, Some(&payload));
        assert_eq!(chosen.max_block_size, 600_000, "epoch-start uses computed");
        let votes = select_candidate_votes(chosen, &targets, true, false);
        assert_eq!(
            votes,
            [0, 0, 0],
            "target already reached in the recomputed table ⇒ no stale seed vote",
        );

        // The stale path (the bug codex caught) would re-vote the reached target.
        assert_eq!(
            select_candidate_votes(&active, &targets, true, false),
            [3, 0, 0],
            "selecting against the stale active table would emit a needless +3",
        );

        // Off-boundary, the live active table is used.
        assert_eq!(
            vote_selection_params(&active, None).max_block_size,
            524_288,
            "non-boundary uses active_params",
        );
    }

    #[test]
    fn mode2_boundary_refusal_requires_armed_and_empty_settings() {
        // codex P2: the Mode 2 boundary refusal must mirror the validator's
        // trust gate — refuse ONLY when the sentinel is armed AND the cumulative
        // settings are still launch-empty. A STALE armed sentinel (e.g. a crash
        // after the trusted boundary applied but before `consume`) with settings
        // already seeded must NOT block boundary mining, and legitimately-empty
        // pre-6.0 settings (sentinel not armed) must mine normally.
        let empty = ErgoValidationSettings::empty();
        let seeded = ErgoValidationSettings::empty().updated(&ErgoValidationSettingsUpdate {
            rules_to_disable: vec![215, 409],
            status_updates: vec![],
        });

        // Mode 2 bootstrap, untrusted launch-default settings → refuse.
        assert!(mode2_settings_untrusted(true, &empty));
        // Stale sentinel but settings already seeded → DO NOT refuse.
        assert!(!mode2_settings_untrusted(true, &seeded));
        // Not armed (normal node) → never refuse, regardless of settings.
        assert!(!mode2_settings_untrusted(false, &empty));
        assert!(!mode2_settings_untrusted(false, &seeded));
    }

    #[test]
    fn epoch_boundary_genesis_era_is_refused() {
        // The first-ever boundary (prev epoch starts at genesis, epoch_start=0)
        // takes Scala's bypass path we don't reproduce — refuse, don't mis-build.
        use ergo_validation::active_params::scala_launch;
        let prev_active = scala_launch(); // epoch_start_height == 0
        let prev_settings = ErgoValidationSettings::empty();
        let vs = VotingSettings::mainnet();
        let err = compute_epoch_payload(&prev_active, &prev_settings, &[], 1024, &vs)
            .expect_err("genesis-era boundary must be refused");
        assert!(
            matches!(err, MiningError::InvalidConfig(ref m) if m.contains("genesis-era")),
            "got {err:?}",
        );
    }
}
