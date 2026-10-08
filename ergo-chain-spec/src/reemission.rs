//! Portable EIP-27 rule inputs and shared burn arithmetic.

const EMISSION_BOX_VALUE_FLOOR: u64 = 100_000 * 1_000_000_000;

/// Network constants needed to enforce EIP-27 re-emission spending.
///
/// Sourced from [`crate::ReemissionParams`] plus the
/// pay-to-reemission contract tree
/// (`ChainSpec::emission_script_trees().pay_to_reemission`). On networks
/// without EIP-27 (the public testnet, where `ChainSpec::reemission` is
/// `None`) no value is supplied and the rule is not enforced — matching
/// Scala's `checkReemissionRules` being effectively off there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReemissionRuleInputs {
    /// Whether the node applies rule 123. Off by default; enabled for mining.
    pub check_rules: bool,
    /// Emission-box constants. Reward-only callers can omit these.
    pub emission: Option<EmissionRuleInputs>,
    /// EIP-27 activation height. Scala `reemission.activationHeight`. The
    /// re-emission **spending** branch triggers strictly *above* this height
    /// (`height > activation_height`) — see [`reemission_obligation_core`] and
    /// `ergo_validation::verify_reemission_spending`. (Reward boxes first carry the token from
    /// the activation height onward, but a *spend* of one is only constrained
    /// once `height` exceeds it.)
    pub activation_height: u32,
    /// 32-byte re-emission token id. Scala `reemission.reemissionTokenId`.
    pub reemission_token_id: [u8; 32],
    /// Serialized `ErgoTree` of the pay-to-reemission contract. Scala
    /// `reemissionRules.payToReemission`. Pay-to-reemission outputs are
    /// matched by `ErgoTree` structural equality against this (not by raw
    /// bytes) — see `ergo_validation::verify_reemission_spending`.
    pub pay_to_reemission_tree: Vec<u8>,
}

/// Network constants for the emission-box branch of rule 123.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionRuleInputs {
    pub monetary: crate::MonetaryParams,
    pub emission_nft_id: [u8; 32],
    pub emission_tree: Vec<u8>,
}

impl ReemissionRuleInputs {
    /// Construct the complete rule inputs from network constants.
    pub fn from_chain_spec(spec: &crate::ChainSpec, check_rules: bool) -> Option<Self> {
        let reemission = spec.reemission.as_ref()?;
        let trees = spec
            .emission_script_trees()
            .expect("configured re-emission requires emission trees");
        Some(Self {
            check_rules,
            activation_height: reemission.activation_height,
            reemission_token_id: *reemission.reemission_token_id.as_bytes(),
            pay_to_reemission_tree: trees.pay_to_reemission,
            emission: Some(EmissionRuleInputs {
                monetary: spec.monetary,
                emission_nft_id: *reemission.emission_nft_id.as_bytes(),
                emission_tree: trees.emission,
            }),
        })
    }
}

/// The EXACT EIP-27 re-emission burn obligation over a set of boxes — the single
/// source of truth shared by the consensus validator
/// (`ergo_validation::verify_reemission_spending`), the wallet transaction builder, and the
/// wallet balance surface. Each caller maps its boxes to
/// `(box_value_nanoerg, reemission_token_amount_in_box)` (token amount extracted
/// against [`ReemissionRuleInputs::reemission_token_id`]) and gets back the same
/// obligation, so the wallet figures can never drift from consensus.
///
/// Mirrors Scala `verifyReemissionSpending` exactly:
/// * **Triggered** when, at a height *strictly* above `activation_height`, ANY
///   non-emission input (value `<= EMISSION_BOX_VALUE_FLOOR`) carries the
///   re-emission token.
/// * Once triggered, `to_burn` is the re-emission token amount summed across
///   **ALL** input boxes — not only the floor boxes that triggered it (a
///   non-floor input co-spent with a triggering reward box still has its tokens
///   burned). 1 nanoErg per token is owed to the pay-to-reemission contract.
///
/// The balance surface uses the obligation over the wallet's whole confirmed box
/// set ("if you swept everything in one spend") so spendable ERG is never
/// over-reported; the builder uses it over the inputs a real spend selects.
pub fn reemission_obligation_core(
    boxes: impl IntoIterator<Item = (u64, u64)>,
    height: u32,
    activation_height: u32,
) -> ReemissionObligation {
    // Single pass: a non-emission floor box carrying the token sets the trigger;
    // every box's token amount accumulates into the would-be burn (summed
    // unconditionally, mirroring the validator's all-inputs `to_burn`).
    let mut triggered_by_floor_box = false;
    let mut total_tokens: u64 = 0;
    let mut token_box_count: u64 = 0;
    for (value, token_amount) in boxes {
        if token_amount > 0 {
            total_tokens = total_tokens.saturating_add(token_amount);
            token_box_count = token_box_count.saturating_add(1);
            if value <= EMISSION_BOX_VALUE_FLOOR {
                triggered_by_floor_box = true;
            }
        }
    }
    let triggered = height > activation_height && triggered_by_floor_box;
    if !triggered {
        return ReemissionObligation::default();
    }
    ReemissionObligation {
        triggered: true,
        to_burn: total_tokens,
        box_count: token_box_count,
    }
}

/// Result of [`reemission_obligation_core`]: the exact EIP-27 burn obligation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReemissionObligation {
    /// Whether the re-emission burn rule fires for this input set.
    pub triggered: bool,
    /// Re-emission token amount summed across ALL inputs (only meaningful when
    /// `triggered`). Equals the nanoErg owed to the pay-to-reemission contract
    /// (1 nanoErg per token). Zero when not triggered.
    pub to_burn: u64,
    /// Number of input boxes carrying the re-emission token (when triggered).
    pub box_count: u64,
}
