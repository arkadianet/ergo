//! "Retrieve matured mining rewards" sweep: pure money breakdown, structural
//! pre-validation, and the writer-task implementation.

use parking_lot::RwLock;

use super::build::{build_unsigned_tx, MIN_BOX_VALUE, MIN_FEE};
use super::sign::{serialize_signed_tx, sign_unsigned_tx};
use crate::engine::{
    map_chain_error, map_submit_error, MempoolOverlay, TxSubmitter, WalletChainAccess,
};
use ergo_wallet_protocol::WalletAdminError;

/// Outcome of a "retrieve matured mining rewards" sweep. `tx_id` is `None` on a
/// dry-run (preview); `Some` once built, signed, self-verified, and submitted.
pub(crate) struct RetrieveRewardsOutcome {
    pub(crate) box_count: u32,
    pub(crate) box_ids: Vec<String>,
    pub(crate) remaining: u32,
    pub(crate) gross_erg: u64,
    pub(crate) reemission_paid: u64,
    pub(crate) fee: u64,
    pub(crate) net_to_destination: u64,
    pub(crate) other_tokens: Vec<([u8; 32], u64)>,
    pub(crate) destination: String,
    pub(crate) tx_id: Option<String>,
}

/// Validator cap on distinct tokens per output box (`context.rs` `max_tokens_per_box`).
/// A single sweep output can carry at most this many non-re-emission token types.
const SWEEP_MAX_TOKENS_PER_BOX: usize = 122;

/// Max reward boxes a single sweep spends. Conservative: at ~50 bytes/input a
/// 100-input tx is ~10 KB (vs the 98 KB mempool tx-size cap) and well under the
/// ~8M block-cost limit, so a previewed sweep always submits. Excess matured
/// boxes are reported as `remaining` and retrieved by running the sweep again.
const MAX_SWEEP_INPUTS: usize = 100;

/// Pure money breakdown of a reward sweep.
#[derive(Debug)]
struct SweepBreakdown {
    /// Gross matured ERG across the swept boxes.
    gross_erg: u64,
    /// nanoErg routed to pay-to-reemission (= re-emission tokens burned, 1:1).
    reemission_paid: u64,
    /// Net ERG to the destination = `gross − fee − reemission_paid`.
    net_to_destination: u64,
    /// Non-re-emission tokens carried to the destination output.
    other_tokens: std::collections::BTreeMap<[u8; 32], u64>,
}

/// Compute the sweep breakdown purely from the input boxes, using the SAME
/// `reemission_obligation_core` consensus enforces — so the reported figure and
/// the on-chain burn cannot diverge. Errors `InsufficientFunds` if the matured
/// ERG cannot cover `fee + reemission`.
fn sweep_breakdown(
    reward_boxes: &[crate::wallet::types::WalletBox],
    reemission_rules: Option<&ergo_validation::ReemissionRuleInputs>,
    tip_height: u32,
    fee: u64,
) -> Result<SweepBreakdown, WalletAdminError> {
    let reemission_token_id = reemission_rules.map(|r| r.reemission_token_id);
    let gross_erg: u64 = reward_boxes.iter().map(|b| b.value).sum();

    // Obligation first — it decides whether the re-emission token is BURNED
    // (triggered) or carried like any other token.
    let (reemission_paid, burn_triggered) = match reemission_rules {
        Some(rules) => {
            let per_input = reward_boxes.iter().map(|b| {
                let token = b
                    .assets
                    .iter()
                    .find(|(id, _)| Some(*id) == reemission_token_id)
                    .map(|(_, a)| *a)
                    .unwrap_or(0);
                (b.value, token)
            });
            let obl = ergo_validation::reemission_obligation_core(
                per_input,
                tip_height.saturating_add(1),
                rules.activation_height,
            );
            if obl.triggered {
                (obl.to_burn, true)
            } else {
                (0, false)
            }
        }
        None => (0, false),
    };

    // Carried tokens: exclude the re-emission token ONLY when it is being burned,
    // matching `build_unsigned_tx` (which strips it from change exactly when the
    // obligation fires); otherwise it is carried like any token.
    let mut other_tokens: std::collections::BTreeMap<[u8; 32], u64> =
        std::collections::BTreeMap::new();
    for b in reward_boxes {
        for (id, amt) in &b.assets {
            if burn_triggered && Some(*id) == reemission_token_id {
                continue;
            }
            let entry = other_tokens.entry(*id).or_insert(0);
            *entry = entry.saturating_add(*amt);
        }
    }

    let net_to_destination = gross_erg
        .checked_sub(fee)
        .and_then(|v| v.checked_sub(reemission_paid))
        .ok_or_else(|| {
            WalletAdminError::InsufficientFunds(format!(
                "matured rewards ({gross_erg} nanoErg) cannot cover fee ({fee}) + \
                 re-emission ({reemission_paid})"
            ))
        })?;

    Ok(SweepBreakdown {
        gross_erg,
        reemission_paid,
        net_to_destination,
        other_tokens,
    })
}

/// Structurally validate a freshly-built (unsigned) sweep tx against the SAME
/// ruleset the signed-tx self-verify uses (`validate_structural`: size-based min
/// box value, box-size cap, collection caps) — so a `dryRun` preview rejects what
/// execute would reject (e.g. a token-heavy destination box over the 4096-byte
/// limit or below its size-based minimum), instead of reporting a success the
/// execute path then fails. Proof content is irrelevant to structural checks, so
/// a zero-proof `Transaction` view suffices.
fn validate_built_structural(
    unsigned_tx: &ergo_ser::transaction::UnsignedTransaction,
    protocol_params: &ergo_validation::ProtocolParams,
    max_tx_size: usize,
) -> Result<(), WalletAdminError> {
    // Each reward-script input is a single ProveDlog Schnorr proof =
    // SOUNDNESS_BYTES (24) + GROUP_SIZE (32) = 56 bytes. Use a 64-byte dummy
    // proof (>= that, with margin) so a real SERIALIZATION of the signed-shape tx
    // is a safe upper bound on the actual signed size — no arithmetic estimate
    // that could under-count the proof-length prefix.
    const SWEEP_DUMMY_PROOF_LEN: usize = 64;
    let inputs = unsigned_tx
        .inputs
        .iter()
        .map(|ui| {
            let spending_proof = ergo_ser::input::SpendingProof::new(
                vec![0u8; SWEEP_DUMMY_PROOF_LEN],
                ui.extension.clone(),
            )
            .map_err(|e| WalletAdminError::Internal(format!("structural-check proof: {e:?}")))?;
            Ok(ergo_ser::input::Input {
                box_id: ui.box_id,
                spending_proof,
            })
        })
        .collect::<Result<Vec<_>, WalletAdminError>>()?;
    let tx = ergo_ser::transaction::Transaction {
        inputs,
        data_inputs: unsigned_tx.data_inputs.clone(),
        output_candidates: unsigned_tx.output_candidates.clone(),
    };

    // Total tx-size bound against the configured admission limit (a safe
    // over-estimate via the >= real-size dummy proofs).
    let signed_size = serialize_signed_tx(&tx)?.len();
    if signed_size > max_tx_size {
        return Err(WalletAdminError::BadRequest(format!(
            "sweep transaction (~{signed_size} bytes) exceeds the configured {max_tx_size}-byte \
             admission limit; retrieve fewer boxes per sweep"
        )));
    }

    ergo_validation::tx::structural::validate_structural(&tx, protocol_params)
        .map_err(|e| WalletAdminError::BadRequest(format!("sweep rejected: {e}")))
}

/// Sweep ALL matured (Confirmed) miner-reward boxes into the wallet change
/// address — or `destination_override`, which must be a tracked wallet address —
/// in one EIP-27-correct transaction: the re-emission token is burned and 1
/// nanoErg/token routed to pay-to-reemission, all OTHER tokens are carried to the
/// destination, and the net ERG (gross − fee − re-emission) lands at the
/// destination.
///
/// Reuses the shared [`build_unsigned_tx`] explicit-input + change path (empty
/// payment requests → everything goes to change = destination), so the preview
/// can never drift from the executed build, and the same shared
/// `reemission_obligation_core` consensus drives both the reported figure and
/// the on-chain burn. `dry_run` builds only (no sign/submit); execute additionally
/// signs (mandatory self-verify, incl. `verify_reemission_spending`) and submits.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn retrieve_rewards_impl(
    destination_override: Option<&str>,
    fee_override: Option<u64>,
    relay_floor: u64,
    max_tx_size: usize,
    box_ids_override: Option<&[String]>,
    dry_run: bool,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
    submitter: &dyn TxSubmitter,
    mempool: &dyn MempoolOverlay,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<RetrieveRewardsOutcome, WalletAdminError> {
    // Executing (sign + submit) needs an unlocked wallet; a dry-run does not.
    if !dry_run && storage.read().unlocked().is_none() {
        return Err(WalletAdminError::Locked);
    }

    // 1. Gather matured (Confirmed) miner-reward boxes. `unspent_boxes()` is
    //    already Confirmed-only; provenance pins them to the reward script.
    //    Pool-spent boxes are NOT excluded here — that filter applies only to
    //    auto-selection below; a PINNED retry must keep its (now pool-spent) boxes
    //    so it reaches the idempotent/duplicate submit handling.
    let mut matured: Vec<crate::wallet::types::WalletBox> = {
        let read = store
            .read()
            .map_err(|e| WalletAdminError::Internal(format!("wallet read txn: {e}")))?;
        read.unspent_boxes()
            .map_err(|e| WalletAdminError::Internal(format!("unspent_boxes: {e}")))?
            .into_iter()
            .filter(|b| {
                matches!(
                    b.provenance,
                    crate::wallet::types::BoxProvenance::MinerReward
                )
            })
            .collect()
    };
    if matured.is_empty() {
        return Err(WalletAdminError::BadRequest(
            "no matured mining-reward boxes to retrieve".into(),
        ));
    }
    // Deterministic oldest-first order (then box id) — selection and the per-sweep
    // cap are stable, and oldest rewards are retrieved first.
    matured.sort_by_key(|b| (b.creation_height, b.box_id));

    // A box already spent by a PENDING mempool tx (e.g. a previous sweep still
    // in-pool) is not freshly sweepable.
    let pool_spent = |b: &crate::wallet::types::WalletBox| {
        mempool.is_spent_by_pool(&ergo_primitives::digest::Digest32::from_bytes(b.box_id))
    };
    // Inputs of transactions waiting in the private mining queue, and the
    // approved inputs of pending maintenance jobs, stay reserved for them; the
    // builder refuses them as explicit inputs.
    let mut reserved = chain.reserved_wallet_inputs()?;
    reserved.extend(super::jobs::reserved_inputs(store)?);

    // Select the input set. PINNED (`Some`): spend exactly the caller's ids (the
    // set a preview returned) — pool-spent pins are KEPT so a lost-response retry
    // reaches the idempotent/duplicate submit, and a reserved pin is refused by
    // the builder. AUTO (`None`): take the oldest not-yet-pending, unreserved
    // boxes up to `MAX_SWEEP_INPUTS` (bounding tx size + cost under the mempool
    // limits), excluding boxes a prior sweep already spent so a follow-up batch
    // advances instead of re-picking them.
    let (reward_boxes, remaining): (Vec<crate::wallet::types::WalletBox>, u32) =
        match box_ids_override {
            Some(ids) => {
                let want: std::collections::BTreeSet<[u8; 32]> = ids
                    .iter()
                    .map(|h| {
                        hex::decode(h)
                            .ok()
                            .and_then(|v| <[u8; 32]>::try_from(v).ok())
                            .ok_or_else(|| WalletAdminError::BadRequest(format!("bad box id: {h}")))
                    })
                    .collect::<Result<_, _>>()?;
                let (selected, rest): (Vec<_>, Vec<_>) =
                    matured.into_iter().partition(|b| want.contains(&b.box_id));
                if selected.len() != want.len() {
                    return Err(WalletAdminError::BadRequest(
                        "one or more requested reward boxes are no longer matured/unspent — \
                         re-preview the sweep"
                            .into(),
                    ));
                }
                if selected.len() > MAX_SWEEP_INPUTS {
                    return Err(WalletAdminError::BadRequest(format!(
                        "requested {} boxes; a single sweep is capped at {MAX_SWEEP_INPUTS}",
                        selected.len()
                    )));
                }
                // Remaining = matured boxes neither pinned, pending, nor reserved.
                let remaining = rest
                    .iter()
                    .filter(|b| !pool_spent(b) && !reserved.contains(&b.box_id))
                    .count() as u32;
                (selected, remaining)
            }
            None => {
                let unreserved: Vec<_> = matured
                    .into_iter()
                    .filter(|b| !reserved.contains(&b.box_id))
                    .collect();
                if unreserved.is_empty() {
                    return Err(WalletAdminError::BadRequest(
                        "all matured reward boxes are reserved by private mining \
                         transactions or pending maintenance jobs; wait for them to \
                         finish or cancel them"
                            .into(),
                    ));
                }
                let available: Vec<_> = unreserved.into_iter().filter(|b| !pool_spent(b)).collect();
                if available.is_empty() {
                    return Err(WalletAdminError::BadRequest(
                        "all matured reward boxes are already being swept by a pending \
                         transaction; wait for it to confirm"
                            .into(),
                    ));
                }
                let total = available.len();
                let take = total.min(MAX_SWEEP_INPUTS);
                let mut sel = available;
                sel.truncate(take);
                (sel, (total - take) as u32)
            }
        };

    // PINNED request whose boxes are already being spent by a PENDING pool tx:
    // surface it as a CONFLICT carrying the pending txid BEFORE any rebuild work.
    // Rebuilding after a tip advance restamps a new `creation_height` → a
    // different tx id → submit would reject it as a double-spend rather than
    // dedupe; and we cannot treat the pooled tx as an idempotent SUCCESS (it may
    // be a conflicting/manual spend, not our sweep, and we cannot verify it pays
    // the previewed destination/amounts). Run this BEFORE `sweep_breakdown` /
    // `build_unsigned_tx` / structural validation so a tip or local-limit change
    // between preview and retry can't fail one of those first and rob the caller
    // of this stable response. Runs for a pinned DRY-RUN too, so a preview can't
    // approve boxes an immediate execute would reject.
    if box_ids_override.is_some() {
        if let Some(pending) = reward_boxes.iter().find_map(|b| {
            mempool.pool_spending_tx(&ergo_primitives::digest::Digest32::from_bytes(b.box_id))
        }) {
            return Err(WalletAdminError::BadRequest(format!(
                "the requested reward boxes are already being spent by pending transaction {}; \
                 if that is your earlier sweep, wait for it to confirm — otherwise the inputs are \
                 conflicted",
                hex::encode(pending.as_bytes())
            )));
        }
    }

    let snapshot = chain.signing_view().map_err(map_chain_error)?;
    let build_tip = snapshot.tip();

    // 2. Breakdown via the SHARED obligation (cannot drift from the build below).
    //    Fee floor = max(protocol min, configured relay floor); a sweep below it
    //    is rejected by submit before validation, so default to it and reject
    //    too-low overrides — keeping the preview/execute contract honest.
    let fee_floor = MIN_FEE.max(relay_floor);
    let fee = match fee_override {
        Some(f) if f < fee_floor => {
            return Err(WalletAdminError::BadRequest(format!(
                "fee {f} nanoErg is below the minimum relay fee ({fee_floor})"
            )));
        }
        Some(f) => f,
        None => fee_floor,
    };
    let SweepBreakdown {
        gross_erg,
        reemission_paid,
        net_to_destination,
        other_tokens,
    } = sweep_breakdown(
        &reward_boxes,
        snapshot.reemission_rules(),
        snapshot.tip().height,
        fee,
    )?;
    if other_tokens.len() > SWEEP_MAX_TOKENS_PER_BOX {
        return Err(WalletAdminError::BadRequest(format!(
            "matured reward boxes carry {} token types; a single sweep output allows at most \
             {SWEEP_MAX_TOKENS_PER_BOX}. Move some tokens out first (multi-output splitting is a \
             planned follow-up).",
            other_tokens.len()
        )));
    }
    // A tokenless net below MIN_BOX_VALUE is folded into the miner fee by the
    // builder (no destination output emitted) — which would make the reported
    // `net_to_destination` a lie ("delivered to destination" when it is actually
    // paid as extra fee). Reject it. (A token-bearing output is always emitted
    // regardless of ERG, so this only applies when there are no carried tokens.)
    if other_tokens.is_empty() && net_to_destination < MIN_BOX_VALUE {
        return Err(WalletAdminError::BadRequest(format!(
            "net to destination ({net_to_destination} nanoErg) is below the minimum box value \
             ({MIN_BOX_VALUE}); the sweep would deliver nothing (the remainder folds into the \
             miner fee). Wait for more matured rewards or lower the fee."
        )));
    }

    // 3. Destination string for the echo (default = persisted change address).
    //    A freshly initialized wallet only backfills its change address on first
    //    unlock, so an omitted destination on a locked-wallet DRY-RUN can reach
    //    here with no address. That's a caller precondition (supply a destination
    //    or unlock once), not a server fault — return 400, not a 500. `build_unsigned_tx`
    //    below resolves the SAME change address, so this also pre-empts its own
    //    `Internal("no change address set")` for the omitted-destination path.
    let destination = match destination_override {
        Some(a) => a.to_string(),
        None => state
            .read()
            .change_address()
            .ok_or_else(|| {
                WalletAdminError::BadRequest(
                    "destination omitted but the wallet has no change address yet; \
                     unlock once or supply a tracked destination"
                        .into(),
                )
            })?
            .to_string(),
    };

    // 4. Build: explicit inputs = reward boxes, NO payment requests, so the
    //    builder routes ALL net ERG + non-re-emission tokens to the change output
    //    (= destination), pays pay-to-reemission, and strips/burns the token.
    let reward_box_ids: Vec<String> = reward_boxes.iter().map(|b| hex::encode(b.box_id)).collect();
    let built = build_unsigned_tx(
        &[],
        Some(&reward_box_ids),
        None,
        Some(fee), // the effective fee (override-or-floor) — not the raw override
        destination_override,
        state,
        store,
        chain,
        network,
    )?;

    // Structurally validate the BUILT tx for BOTH paths (the dust + 122-token
    // checks above are partial — a token-heavy destination box can still exceed
    // the 4096-byte cap or fall below its size-based minimum). This makes the
    // dry-run preview reject exactly what execute would, so the preview/execute
    // contract is reliable.
    let unsigned_tx = {
        let mut r = ergo_primitives::reader::VlqReader::new(&built.bytes);
        ergo_ser::transaction::read_unsigned_transaction(&mut r)
            .map_err(|e| WalletAdminError::Internal(format!("deserialize unsigned tx: {e:?}")))?
    };
    // Structural + total-size validation (incl. the configured tx-size cap) via a
    // safe-upper-bound signed-shape serialization — so a dry-run rejects exactly
    // what execute/submit would.
    validate_built_structural(&unsigned_tx, snapshot.protocol_params(), max_tx_size)?;
    drop(snapshot);

    let box_count = reward_boxes.len() as u32;
    let box_ids = reward_box_ids;
    let other_tokens_vec: Vec<([u8; 32], u64)> = other_tokens.into_iter().collect();

    if dry_run {
        return Ok(RetrieveRewardsOutcome {
            box_count,
            box_ids,
            remaining,
            gross_erg,
            reemission_paid,
            fee,
            net_to_destination,
            other_tokens: other_tokens_vec,
            destination,
            tx_id: None,
        });
    }

    // 5. Execute: sign (mandatory self-verify, incl. `verify_reemission_spending`)
    //    then submit.
    let snapshot = chain.signing_view().map_err(map_chain_error)?;
    if snapshot.tip() != build_tip {
        return Err(WalletAdminError::StaleChainTip(
            "committed chain tip changed during reward sweep construction".to_string(),
        ));
    }
    let signed_tx = {
        let storage = storage.read();
        sign_unsigned_tx(
            &unsigned_tx,
            &storage,
            store,
            snapshot.as_ref(),
            &[],
            &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
        )?
    };
    chain
        .ensure_view_current(snapshot.as_ref())
        .map_err(map_chain_error)?;
    drop(snapshot);
    let tx_id = ergo_ser::transaction::transaction_id(&signed_tx)
        .map_err(|e| WalletAdminError::Internal(format!("transaction_id: {e:?}")))?;
    let tx_id_hex = hex::encode(tx_id.as_bytes());
    let tx_bytes = serialize_signed_tx(&signed_tx)?;
    // Mirror the native send path's typed handling: a `duplicate` (already
    // in-pool) submit is idempotently accepted — a retry or double-click of an
    // already-accepted sweep returns its txId as success — and other typed
    // failures map to their proper 4xx via `map_submit_error`, not a blanket 500.
    match submitter.submit_transaction(tx_bytes).await {
        Ok(_) => {}
        Err(e) if e.reason == "duplicate" => {}
        Err(e) => return Err(map_submit_error(e)),
    }

    Ok(RetrieveRewardsOutcome {
        box_count,
        box_ids,
        remaining,
        gross_erg,
        reemission_paid,
        fee,
        net_to_destination,
        other_tokens: other_tokens_vec,
        destination,
        tx_id: Some(tx_id_hex),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::{digest::ModifierId, reader::VlqReader};

    // The stale-tip guard must fire before any prover/context reads or submit.
    struct SweepSigningView {
        tip: crate::chain::CommittedTip,
        params: ergo_validation::ProtocolParams,
    }
    impl crate::engine::SigningView for SweepSigningView {
        fn tip(&self) -> crate::chain::CommittedTip {
            self.tip.clone()
        }
        fn headers(&self) -> &[ergo_ser::header::Header] {
            panic!("stale sweep must not sign")
        }
        fn header_ids(&self) -> &[[u8; 32]] {
            panic!("stale sweep must not sign")
        }
        fn state_context(&self) -> &ergo_wallet::tx_context::BlockchainStateContext {
            panic!("stale sweep must not sign")
        }
        fn active_params(&self) -> &ergo_validation::ActiveProtocolParameters {
            panic!("stale sweep must not sign")
        }
        fn signing_params(&self) -> &ergo_wallet::tx_context::BlockchainParameters {
            panic!("stale sweep must not sign")
        }
        fn protocol_params(&self) -> &ergo_validation::ProtocolParams {
            &self.params
        }
        fn reemission_rules(&self) -> Option<&ergo_validation::ReemissionRuleInputs> {
            None
        }
        fn lookup_utxo(
            &self,
            _: &[u8; 32],
        ) -> Result<Option<ergo_ser::ergo_box::ErgoBox>, crate::engine::ChainAccessError> {
            panic!("stale sweep must not sign")
        }
    }

    struct MovingSweepChain {
        snapshots:
            std::sync::Mutex<std::collections::VecDeque<Box<dyn crate::engine::SigningView>>>,
        input: ergo_ser::ergo_box::ErgoBox,
    }
    impl WalletChainAccess for MovingSweepChain {
        fn wallet_scan_height(&self) -> Result<u32, crate::engine::ChainAccessError> {
            Ok(1)
        }
        fn tip_height(&self) -> Result<u32, crate::engine::ChainAccessError> {
            Ok(1)
        }
        fn is_pruned(&self) -> bool {
            false
        }
        fn read_block_at(
            &self,
            _: u32,
        ) -> Result<Option<crate::wallet::scan::RescanBlock>, crate::wallet::scan::RescanReadError>
        {
            Ok(None)
        }
        fn lookup_utxo(
            &self,
            _: &[u8; 32],
        ) -> Result<Option<ergo_ser::ergo_box::ErgoBox>, crate::engine::ChainAccessError> {
            Ok(Some(self.input.clone()))
        }
        fn signing_view(
            &self,
        ) -> Result<Box<dyn crate::engine::SigningView>, crate::engine::ChainAccessError> {
            Ok(self
                .snapshots
                .lock()
                .unwrap()
                .pop_front()
                .expect("two sweep snapshots"))
        }
    }

    struct NoSubmit;
    #[async_trait::async_trait]
    impl TxSubmitter for NoSubmit {
        async fn submit_transaction(
            &self,
            _: Vec<u8>,
        ) -> Result<String, crate::engine::TxSubmitError> {
            panic!("stale sweep must not submit")
        }
    }

    // A stale sweep returns before its sole await. Polling once also ensures the
    // regression remains independent of any runtime dependency in this crate.
    fn ready_without_executor<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match std::pin::pin!(future).as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("stale sweep must finish before submit"),
        }
    }

    const REEM: [u8; 32] = [0x11; 32];
    const OTHER: [u8; 32] = [0x22; 32];
    const ACTIVATION: u32 = 777_217;

    fn rules() -> ergo_validation::ReemissionRuleInputs {
        ergo_validation::ReemissionRuleInputs {
            check_rules: true,
            emission: None,
            activation_height: ACTIVATION,
            reemission_token_id: REEM,
            pay_to_reemission_tree: vec![],
        }
    }

    fn reward_box(value: u64, assets: Vec<([u8; 32], u64)>) -> crate::wallet::types::WalletBox {
        crate::wallet::types::WalletBox {
            box_id: [0xAB; 32],
            creation_tx_id: [0; 32],
            creation_output_index: 0,
            creation_height: 1,
            value,
            assets,
            status: crate::wallet::types::BoxStatus::Confirmed,
            provenance: crate::wallet::types::BoxProvenance::MinerReward,
        }
    }

    #[test]
    fn sweep_execute_changed_build_tip_refuses_signing() {
        use crate::state::WalletState;
        use crate::wallet::tables::WALLET_BOXES;
        use ergo_ser::address::NetworkPrefix;
        use ergo_wallet::storage::SecretStorage;
        // Both a new block and a same-height fork must invalidate the breakdown.
        for (signing_height, fork) in [(2, false), (1, true)] {
            let dir = tempfile::tempdir().unwrap();
            let snapshots: std::collections::VecDeque<Box<dyn crate::engine::SigningView>> = [
                (1, [1; 32]),
                (signing_height, if fork { [2; 32] } else { [1; 32] }),
            ]
            .into_iter()
            .map(|(height, header_id)| {
                Box::new(SweepSigningView {
                    tip: crate::chain::CommittedTip { height, header_id },
                    params: ergo_validation::ProtocolParams::mainnet_default(),
                }) as Box<dyn crate::engine::SigningView>
            })
            .collect();
            let txs: Vec<serde_json::Value> = serde_json::from_str(include_str!(
                "../../../test-vectors/mainnet/transactions_1_10.json"
            ))
            .unwrap();
            let bytes = hex::decode(txs[0]["bytes"].as_str().unwrap()).unwrap();
            let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
            let input = ergo_ser::ergo_box::ErgoBox {
                candidate: tx.output_candidates[1].clone(),
                transaction_id: ModifierId::from_bytes(
                    hex::decode(txs[0]["id"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                index: 1,
            };
            let mut reward = reward_box(input.candidate.value, vec![]);
            reward.box_id = *input.box_id().unwrap().as_bytes();
            let chain = MovingSweepChain {
                snapshots: std::sync::Mutex::new(snapshots),
                input,
            };
            let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
            let mut storage = SecretStorage::open(dir.path().join("secrets"));
            storage
                .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "test", "")
                .unwrap();
            let mut state = WalletState::empty(false);
            crate::engine::WalletBootService::unlock_and_sync(
                &mut storage,
                &mut state,
                &db,
                NetworkPrefix::Mainnet,
                "test",
            )
            .unwrap();
            let write = db.begin_write().unwrap();
            write
                .open_table(WALLET_BOXES)
                .unwrap()
                .insert(reward.box_id, bincode::serialize(&reward).unwrap())
                .unwrap();
            write.commit().unwrap();

            let storage = RwLock::new(storage);
            let state = RwLock::new(state);
            let pool = crate::engine::NoopMempoolOverlay::new();
            let pending = retrieve_rewards_impl(
                None,
                None,
                MIN_FEE,
                100_000,
                None,
                false,
                &storage,
                &state,
                &db,
                &chain,
                &NoSubmit,
                &pool,
                NetworkPrefix::Mainnet,
            );
            let result = ready_without_executor(pending);
            assert!(
                matches!(result, Err(WalletAdminError::StaleChainTip(_))),
                "expected stale tip, got {:?}",
                result.err()
            );
            assert!(chain.snapshots.lock().unwrap().is_empty());
        }
    }

    // ----- happy path -----

    #[test]
    fn reward_box_burns_reemission_and_nets_remainder() {
        let r = rules();
        let boxes = vec![reward_box(15_000_000_000, vec![(REEM, 12_000_000_000)])];
        let b = sweep_breakdown(&boxes, Some(&r), ACTIVATION + 100, MIN_FEE).unwrap();
        assert_eq!(b.gross_erg, 15_000_000_000);
        assert_eq!(b.reemission_paid, 12_000_000_000, "1 nanoErg per token");
        assert_eq!(
            b.net_to_destination,
            15_000_000_000 - MIN_FEE - 12_000_000_000
        );
        assert!(
            b.other_tokens.is_empty(),
            "re-emission token is burned, not carried"
        );
    }

    #[test]
    fn carries_other_tokens_summed_and_excludes_reemission() {
        let r = rules();
        let boxes = vec![
            reward_box(15_000_000_000, vec![(REEM, 12_000_000_000), (OTHER, 7)]),
            reward_box(15_000_000_000, vec![(REEM, 12_000_000_000), (OTHER, 3)]),
        ];
        let b = sweep_breakdown(&boxes, Some(&r), ACTIVATION + 100, MIN_FEE).unwrap();
        assert_eq!(b.gross_erg, 30_000_000_000);
        assert_eq!(
            b.reemission_paid, 24_000_000_000,
            "summed across all inputs"
        );
        assert_eq!(
            b.other_tokens.get(&OTHER).copied(),
            Some(10),
            "7 + 3 carried"
        );
        assert!(
            !b.other_tokens.contains_key(&REEM),
            "re-emission token never carried to an output"
        );
    }

    /// A one-snapshot chain whose UTXO lookup and private reservations are
    /// fixed by the test.
    struct ReservingSweepChain {
        snapshot: std::sync::Mutex<Option<Box<dyn crate::engine::SigningView>>>,
        boxes: std::collections::BTreeMap<[u8; 32], ergo_ser::ergo_box::ErgoBox>,
        reserved: std::collections::BTreeSet<[u8; 32]>,
    }

    impl WalletChainAccess for ReservingSweepChain {
        fn reserved_wallet_inputs(
            &self,
        ) -> Result<std::collections::BTreeSet<[u8; 32]>, WalletAdminError> {
            Ok(self.reserved.clone())
        }
        fn wallet_scan_height(&self) -> Result<u32, crate::engine::ChainAccessError> {
            Ok(1)
        }
        fn tip_height(&self) -> Result<u32, crate::engine::ChainAccessError> {
            Ok(1)
        }
        fn is_pruned(&self) -> bool {
            false
        }
        fn read_block_at(
            &self,
            _: u32,
        ) -> Result<Option<crate::wallet::scan::RescanBlock>, crate::wallet::scan::RescanReadError>
        {
            Ok(None)
        }
        fn lookup_utxo(
            &self,
            id: &[u8; 32],
        ) -> Result<Option<ergo_ser::ergo_box::ErgoBox>, crate::engine::ChainAccessError> {
            Ok(self.boxes.get(id).cloned())
        }
        fn signing_view(
            &self,
        ) -> Result<Box<dyn crate::engine::SigningView>, crate::engine::ChainAccessError> {
            Ok(self
                .snapshot
                .lock()
                .unwrap()
                .take()
                .expect("one sweep snapshot"))
        }
    }

    // ----- private reservations -----

    #[test]
    fn sweep_auto_selection_skips_a_reserved_oldest_reward() {
        use crate::state::WalletState;
        use crate::wallet::tables::WALLET_BOXES;
        use ergo_ser::address::NetworkPrefix;
        use ergo_wallet::storage::SecretStorage;
        let dir = tempfile::tempdir().unwrap();
        let snapshot: Box<dyn crate::engine::SigningView> = Box::new(SweepSigningView {
            tip: crate::chain::CommittedTip::new(1, [1; 32]),
            params: ergo_validation::ProtocolParams::mainnet_default(),
        });
        let txs: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../test-vectors/mainnet/transactions_1_10.json"
        ))
        .unwrap();
        let bytes = hex::decode(txs[0]["bytes"].as_str().unwrap()).unwrap();
        let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        // Two reward boxes; the reserved one is the oldest, so it would be
        // picked first by the oldest-first selection.
        let mut boxes = std::collections::BTreeMap::new();
        let mut rewards = Vec::new();
        for (creator, height) in [(0x41u8, 1u32), (0x42, 2)] {
            let output = ergo_ser::ergo_box::ErgoBox {
                candidate: tx.output_candidates[1].clone(),
                transaction_id: ModifierId::from_bytes([creator; 32]),
                index: 1,
            };
            let mut wallet_box = reward_box(output.candidate.value, vec![]);
            wallet_box.box_id = *output.box_id().unwrap().as_bytes();
            wallet_box.creation_height = height;
            boxes.insert(wallet_box.box_id, output);
            rewards.push(wallet_box);
        }
        let chain = ReservingSweepChain {
            snapshot: std::sync::Mutex::new(Some(snapshot)),
            boxes,
            reserved: std::collections::BTreeSet::from([rewards[0].box_id]),
        };
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        let mut storage = SecretStorage::open(dir.path().join("secrets"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "test", "")
            .unwrap();
        let mut state = WalletState::empty(false);
        crate::engine::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &db,
            NetworkPrefix::Mainnet,
            "test",
        )
        .unwrap();
        let write = db.begin_write().unwrap();
        {
            let mut table = write.open_table(WALLET_BOXES).unwrap();
            for reward in &rewards {
                table
                    .insert(reward.box_id, bincode::serialize(reward).unwrap())
                    .unwrap();
            }
        }
        write.commit().unwrap();

        let storage = RwLock::new(storage);
        let state = RwLock::new(state);
        let pool = crate::engine::NoopMempoolOverlay::new();
        let outcome = ready_without_executor(retrieve_rewards_impl(
            None,
            None,
            MIN_FEE,
            100_000,
            None,
            true,
            &storage,
            &state,
            &db,
            &chain,
            &NoSubmit,
            &pool,
            NetworkPrefix::Mainnet,
        ))
        .expect("the unreserved reward is still retrievable");
        assert_eq!(outcome.box_ids, vec![hex::encode(rewards[1].box_id)]);
        assert_eq!(outcome.remaining, 0, "a reserved box is not left to sweep");
    }

    // ----- error paths -----

    #[test]
    fn insufficient_when_gross_below_fee_plus_reemission() {
        let r = rules();
        // gross == the re-emission owed, so it cannot also cover the fee.
        let boxes = vec![reward_box(12_000_000_000, vec![(REEM, 12_000_000_000)])];
        let err = sweep_breakdown(&boxes, Some(&r), ACTIVATION + 100, MIN_FEE).unwrap_err();
        assert!(matches!(err, WalletAdminError::InsufficientFunds(_)));
    }

    // ----- edge: no EIP-27 net / below activation (token carried, not burned) -----

    #[test]
    fn no_eip27_net_is_gross_minus_fee_all_tokens_carried() {
        let boxes = vec![reward_box(5_000_000_000, vec![(OTHER, 9)])];
        let b = sweep_breakdown(&boxes, None, ACTIVATION + 100, MIN_FEE).unwrap();
        assert_eq!(b.reemission_paid, 0);
        assert_eq!(b.net_to_destination, 5_000_000_000 - MIN_FEE);
        assert_eq!(b.other_tokens.get(&OTHER).copied(), Some(9));
    }

    #[test]
    fn below_activation_carries_token_not_burned() {
        let r = rules();
        let boxes = vec![reward_box(15_000_000_000, vec![(REEM, 12_000_000_000)])];
        // tip+1 <= activation → obligation not triggered → token is CARRIED,
        // matching build_unsigned_tx (which only strips it when the burn fires).
        let b = sweep_breakdown(&boxes, Some(&r), ACTIVATION - 10, MIN_FEE).unwrap();
        assert_eq!(b.reemission_paid, 0);
        assert_eq!(b.net_to_destination, 15_000_000_000 - MIN_FEE);
        assert_eq!(
            b.other_tokens.get(&REEM).copied(),
            Some(12_000_000_000),
            "below activation the re-emission token is carried, not burned"
        );
    }
}
