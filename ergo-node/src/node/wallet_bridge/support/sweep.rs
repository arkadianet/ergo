//! "Retrieve matured mining rewards" sweep: pure money breakdown, structural
//! pre-validation, and the writer-task implementation.

use parking_lot::RwLock;

use super::sign_submit::{map_submit_error, serialize_signed_tx, sign_unsigned_tx};
use super::tx_build::{build_unsigned_tx, MIN_BOX_VALUE, MIN_FEE};
use crate::node::wallet_bridge::{ChainStateAccessor, TxSubmitter, WalletAdminError};

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
    reward_boxes: &[ergo_state::wallet::types::WalletBox],
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
    chain: &dyn ChainStateAccessor,
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

    let params = chain.build_protocol_params()?;
    ergo_validation::tx::structural::validate_structural(&tx, &params)
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
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    submitter: &dyn TxSubmitter,
    mempool: &dyn ergo_api::MempoolView,
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
    let mut matured: Vec<ergo_state::wallet::types::WalletBox> = {
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(format!("wallet read txn: {e}")))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        reader
            .unspent_boxes()
            .map_err(|e| WalletAdminError::Internal(format!("unspent_boxes: {e}")))?
            .into_iter()
            .filter(|b| {
                matches!(
                    b.provenance,
                    ergo_state::wallet::types::BoxProvenance::MinerReward
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
    let pool_spent = |b: &ergo_state::wallet::types::WalletBox| {
        mempool.is_spent_by_pool(&ergo_primitives::digest::Digest32::from_bytes(b.box_id))
    };

    // Select the input set. PINNED (`Some`): spend exactly the caller's ids (the
    // set a preview returned) — pool-spent pins are KEPT so a lost-response retry
    // reaches the idempotent/duplicate submit. AUTO (`None`): take the oldest
    // not-yet-pending boxes up to `MAX_SWEEP_INPUTS` (bounding tx size + cost under
    // the mempool limits), excluding boxes a prior sweep already spent so a
    // follow-up batch advances instead of re-picking them.
    let (reward_boxes, remaining): (Vec<ergo_state::wallet::types::WalletBox>, u32) =
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
                // Remaining = matured boxes neither pinned nor already pending.
                let remaining = rest.iter().filter(|b| !pool_spent(b)).count() as u32;
                (selected, remaining)
            }
            None => {
                let available: Vec<_> = matured.into_iter().filter(|b| !pool_spent(b)).collect();
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
        chain.reemission_rules(),
        chain.tip_height(),
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
        db,
        chain,
        network,
    )
    .await?;

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
    validate_built_structural(&unsigned_tx, chain, max_tx_size)?;

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
    let signed_tx = {
        let storage = storage.read();
        sign_unsigned_tx(
            &unsigned_tx,
            &storage,
            db,
            chain,
            &[],
            &ergo_wallet::proving::hints::TransactionHintsBag::empty(),
        )?
    };
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

    const REEM: [u8; 32] = [0x11; 32];
    const OTHER: [u8; 32] = [0x22; 32];
    const ACTIVATION: u32 = 777_217;

    fn rules() -> ergo_validation::ReemissionRuleInputs {
        ergo_validation::ReemissionRuleInputs {
            activation_height: ACTIVATION,
            reemission_token_id: REEM,
            pay_to_reemission_tree: vec![],
        }
    }

    fn reward_box(
        value: u64,
        assets: Vec<([u8; 32], u64)>,
    ) -> ergo_state::wallet::types::WalletBox {
        ergo_state::wallet::types::WalletBox {
            box_id: [0xAB; 32],
            creation_tx_id: [0; 32],
            creation_output_index: 0,
            creation_height: 1,
            value,
            assets,
            status: ergo_state::wallet::types::BoxStatus::Confirmed,
            provenance: ergo_state::wallet::types::BoxProvenance::MinerReward,
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
