//! Unbeatable CPFP child-fee formula (pure integer math, no I/O).
//!
//! Implements the §3 exact source-level form from the fee-formula spec
//! (`docs/superpowers/specs/2026-06-27-unbeatable-cpfp-child-fee-formula.md`).
//!
//! A storage-rent claim is broadcast as a **parent** transaction plus a
//! small **CPFP child** that pays its whole value to the miner-fee
//! ergoTree. On a mempool that resolves double-spends by
//! replace-by-weight, the child's weight rolls into the parent's family
//! weight (`updateFamily`, `OrderedTxPool.scala:196`) and is what keeps
//! the family undisplaceable by a single replacement bidding the entire
//! extractable value `G` of the same boxes.
//!
//! Because **equality blocks** replacement (`ErgoMemPool.scala:201`,
//! strict-`>`-of-average), the family only has to *match* the challenger;
//! no `+ε` is needed. The default sort axis is `"random"` over
//! `{cost, size}`, so the family must dominate on **both** axes — hence
//! the `max()` in [`unbeatable_child_fee`].

/// Per-axis feeFactors (MEASURED: cost = recorded validation cost; size =
/// serialized bytes).
///
/// All > 0; a zero factor is a builder bug.
#[derive(Debug, Clone, Copy)]
pub struct FeeFactors {
    /// Our parent transaction's feeFactor on this axis.
    pub parent: u64,
    /// Our CPFP child's feeFactor on this axis.
    pub child: u64,
    /// The challenger's parent feeFactor on this axis
    /// (`FF_comp ≈ FF_parent`, same N-input structure).
    pub challenger: u64,
}

/// Error surfaced by the fee formula. A zero feeFactor is a programming
/// error in the builder, not a recoverable input — it is reported rather
/// than silently clamped to `1`.
#[derive(Debug, thiserror::Error)]
pub enum FeeFormulaError {
    /// A feeFactor was `0`. feeFactors are measured quantities (validation
    /// cost / serialized byte length) that are always strictly positive;
    /// a `0` means the caller passed an unmeasured / mis-built tx.
    #[error("fee factor must be > 0")]
    ZeroFeeFactor,
}

/// `weight(tx) = floor(fee * 1024 / feeFactor)` (`OrderedTxPool.scala:262`)
/// as a plain value, for callers that have already validated `fee_factor > 0`
/// upstream (the `rent_broadcast` unbeatable-family checks). This is the
/// SINGLE definition of the weight math; the `Result`-returning [`weight`]
/// below delegates to it after the divisor check, and `rent_broadcast` calls
/// this directly so the two can never silently diverge.
///
/// `fee as i128 * 1024` cannot overflow i128 (`u64 * 1024 << i128::MAX`).
pub(crate) fn weight_value(fee: u64, fee_factor: u64) -> i128 {
    debug_assert!(fee_factor > 0, "feeFactor must be > 0 (validated upstream)");
    (fee as i128) * 1024 / fee_factor as i128
}

/// `weight(tx) = floor(fee * 1024 / feeFactor)` (`OrderedTxPool.scala:262`).
///
/// `fee as i128 * 1024` cannot overflow i128 (`u64 * 1024 << i128::MAX`);
/// a zero feeFactor is a bug and is reported, not divided-by.
fn weight(fee: u64, fee_factor: u64) -> Result<i128, FeeFormulaError> {
    if fee_factor == 0 {
        return Err(FeeFormulaError::ZeroFeeFactor);
    }
    Ok(weight_value(fee, fee_factor))
}

/// `f_c_min_a = ceil(max(0, W_chal - weight(f_p)) * FF_child / 1024)` —
/// equality blocks replacement, so there is no `+ε`.
///
/// SATURATING throughout — never panics: an absurd `deficit * ff.child`
/// saturates the product and the result saturates to `u64::MAX` rather
/// than `.expect()`-panicking.
fn child_fee_one_axis(g: u64, f_p: u64, ff: &FeeFactors) -> Result<u64, FeeFormulaError> {
    let deficit = (weight(g, ff.challenger)? - weight(f_p, ff.parent)?).max(0);
    let num = deficit.saturating_mul(ff.child as i128);
    let ceil = num.saturating_add(1023) / 1024;
    Ok(u64::try_from(ceil).unwrap_or(u64::MAX))
}

/// Unbeatable child fee = `max` over the `{cost, size}` axes, floored at
/// the relay minimum (`minimalFeeAmount`).
///
/// The default mempool sort axis is `"random"` over `{cost, size}`, so the
/// family must dominate on **both** axes; the binding one is selected per
/// claim by the `max()`.
///
/// # Caller contract on degenerate results
///
/// * A returned **`u64::MAX`** is a degenerate UNPAYABLE sentinel: it is
///   only reachable from *non-measured* inputs (an absurd
///   `challenger`/`child` feeFactor that saturates the i128 product — see
///   [`child_fee_one_axis`]). Real feeFactors are MEASURED validation
///   costs / serialized byte lengths, which never produce it. A caller
///   that ever sees `u64::MAX` here has a measurement bug upstream and
///   **must not broadcast** the resulting family — the affordability gate
///   in `rent_broadcast` rejects it.
/// * A zero **`child`** feeFactor (a *multiplier*, not a divisor) yields a
///   silent 0-axis contribution rather than `ZeroFeeFactor` — that is the
///   spec-literal arithmetic. A zero `child` is the caller's contract
///   violation and is surfaced upstream where `FeeFactors` are built (the
///   `rent_broadcast` construction site validates each measured factor
///   `> 0`), NOT here.
pub fn unbeatable_child_fee(
    g: u64,
    parent_fee: u64,
    cost: &FeeFactors,
    size: &FeeFactors,
    min_relay_fee: u64,
) -> Result<u64, FeeFormulaError> {
    Ok(child_fee_one_axis(g, parent_fee, cost)?
        .max(child_fee_one_axis(g, parent_fee, size)?)
        .max(min_relay_fee))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- §5 cost-axis table (the binding axis for storage-rent claims) ---
    //
    // Doc §5 assumptions: per-box rent `r = 99M` nanoErg, parent fee
    // `f_p = 3M·N`, source-default cost params, so `G = 99M·N`,
    // `C_parent = 10_100 + 2_150·N`, `C_child = 12_100`, and the
    // challenger's feeFactor `FF_comp ≈ FF_parent = C_parent`.
    //
    // Each `expected` below is the exact integer replay of the §3 form:
    //   W_chal   = floor(G · 1024 / C_parent)
    //   deficit  = max(0, W_chal − floor(f_p · 1024 / C_parent))
    //   f_c_min  = ceil(deficit · C_child / 1024)
    // which rounds to the ERG value printed in the §5 table.
    fn cost_axis(n: u64) -> FeeFactors {
        FeeFactors {
            parent: 10_100 + 2_150 * n,
            child: 12_100,
            // Challenger's parent has the same N-input structure.
            challenger: 10_100 + 2_150 * n,
        }
    }

    /// Run one §5 row on the cost axis alone (size axis disabled by a huge
    /// feeFactor so it contributes 0, min_relay = 0 so it never floors).
    fn cost_axis_row(n: u64) -> u64 {
        let g = 99_000_000 * n;
        let parent_fee = 3_000_000 * n;
        let cost = cost_axis(n);
        // Size axis neutralised: a gigantic feeFactor drives weight → 0,
        // so child_fee_one_axis(size) == 0 and max() picks the cost axis.
        let size = FeeFactors {
            parent: u64::MAX,
            child: 1,
            challenger: u64::MAX,
        };
        unbeatable_child_fee(g, parent_fee, &cost, &size, 0).unwrap()
    }

    #[test]
    fn doc_s5_cost_axis_table() {
        // (N, exact f_c_min in nanoErg, ERG label from the §5 table)
        let cases: &[(u64, u64)] = &[
            (1, 94_824_486),   // 0.095 ERG
            (2, 161_333_342),  // 0.161 ERG
            (3, 210_561_932),  // 0.211 ERG
            (5, 278_561_155),  // 0.279 ERG
            (10, 367_594_940), // 0.368 ERG
            (20, 437_514_117), // 0.438 ERG
            (40, 483_496_350), // 0.484 ERG
            (75, 508_433_032), // 0.508 ERG
        ];
        for &(n, expected) in cases {
            assert_eq!(cost_axis_row(n), expected, "N={n} cost-axis f_c_min");
        }
    }

    #[test]
    fn doc_s5_rounds_to_stated_erg() {
        // Spot-check the headline ERG figures the doc states (rounded to
        // 3 decimals): N=1 ≈ 0.095, N=10 ≈ 0.368.
        let round3 = |nano: u64| (nano as f64 / 1e9 * 1000.0).round() / 1000.0;
        assert_eq!(round3(cost_axis_row(1)), 0.095);
        assert_eq!(round3(cost_axis_row(10)), 0.368);
    }

    #[test]
    fn min_relay_floor_applies_when_axes_are_small() {
        // No deficit on either axis (challenger value 0) → both axis fees
        // are 0, so the relay floor is what comes out.
        let cost = cost_axis(1);
        let size = cost_axis(1);
        let min_relay = 1_000_000;
        let fee = unbeatable_child_fee(0, 0, &cost, &size, min_relay).unwrap();
        assert_eq!(fee, min_relay);
    }

    #[test]
    fn max_picks_the_binding_axis_not_the_floor() {
        // Cost axis demands a large fee; the relay floor is tiny → the
        // result is the cost-axis value, proving max() chooses the
        // binding axis over the floor.
        let n = 10;
        let g = 99_000_000 * n;
        let parent_fee = 3_000_000 * n;
        let cost = cost_axis(n);
        let size = FeeFactors {
            parent: u64::MAX,
            child: 1,
            challenger: u64::MAX,
        };
        let fee = unbeatable_child_fee(g, parent_fee, &cost, &size, 1_000_000).unwrap();
        assert_eq!(fee, 367_594_940);
    }

    #[test]
    fn size_axis_can_dominate_cost_axis() {
        // Construct a case where the size axis demands more than the cost
        // axis, confirming max() returns the larger of the two.
        let g = 1_000_000_000;
        let parent_fee = 0;
        // Cost axis: cheap child relative to parent → small fee.
        let cost = FeeFactors {
            parent: 1_000,
            child: 10,
            challenger: 1_000,
        };
        // Size axis: child as heavy as parent → fee ≈ full G.
        let size = FeeFactors {
            parent: 1_000,
            child: 1_000,
            challenger: 1_000,
        };
        let cost_only = unbeatable_child_fee(
            g,
            parent_fee,
            &cost,
            &FeeFactors {
                parent: u64::MAX,
                child: 1,
                challenger: u64::MAX,
            },
            0,
        )
        .unwrap();
        let both = unbeatable_child_fee(g, parent_fee, &cost, &size, 0).unwrap();
        assert!(both > cost_only, "size axis must be able to dominate");
        // Size axis with child==parent and chal==parent and f_p=0 →
        // deficit = floor(G·1024/1000), fee = ceil(deficit·1000/1024) = G.
        assert_eq!(both, g);
    }

    #[test]
    fn zero_divisor_fee_factor_is_an_error_not_a_silent_fixup() {
        let ok = FeeFactors {
            parent: 1,
            child: 1,
            challenger: 1,
        };

        // `parent` and `challenger` are the divisors in weight(); a zero on
        // either role is a builder bug and must surface ZeroFeeFactor
        // rather than being clamped to 1 (no silent `.max(1)`). Verified on
        // both the cost axis and the size axis argument positions.
        let zero_parent = FeeFactors {
            parent: 0,
            child: 1,
            challenger: 1,
        };
        let zero_challenger = FeeFactors {
            parent: 1,
            child: 1,
            challenger: 0,
        };
        for bad in [&zero_parent, &zero_challenger] {
            assert!(matches!(
                unbeatable_child_fee(1, 1, bad, &ok, 0).unwrap_err(),
                FeeFormulaError::ZeroFeeFactor
            ));
            assert!(matches!(
                unbeatable_child_fee(1, 1, &ok, bad, 0).unwrap_err(),
                FeeFormulaError::ZeroFeeFactor
            ));
        }
    }

    #[test]
    fn zero_child_fee_factor_is_a_zero_multiplier_not_an_error() {
        // `child` is a *multiplier* (numerator), not a divisor, so per the
        // §3 form a zero `child` factor yields a zero axis contribution —
        // it does NOT raise ZeroFeeFactor (only divisors are validated).
        // Documented here so the asymmetry is intentional, not a latent
        // bug: a real builder always measures child > 0; this just pins
        // the spec's exact arithmetic.
        let zero_child = FeeFactors {
            parent: 1,
            child: 0,
            challenger: 1,
        };
        assert_eq!(child_fee_one_axis(1_000_000, 0, &zero_child).unwrap(), 0);

        // And via the public API the relay floor still applies.
        let ok = FeeFactors {
            parent: 1,
            child: 1,
            challenger: 1,
        };
        let fee = unbeatable_child_fee(0, 0, &zero_child, &ok, 1_000_000).unwrap();
        assert_eq!(fee, 1_000_000);
    }

    #[test]
    fn child_fee_one_axis_saturates_not_panics() {
        // Absurd inputs: max challenger value, tiny challenger feeFactor
        // (huge W_chal), huge child feeFactor. The i128 product and the
        // u64 conversion must saturate to u64::MAX, never panic.
        let ff = FeeFactors {
            parent: u64::MAX,
            child: u64::MAX,
            challenger: 1,
        };
        let got = child_fee_one_axis(u64::MAX, 0, &ff).unwrap();
        assert_eq!(got, u64::MAX);

        // And the public entry point saturates the same way.
        let saturating_axis = FeeFactors {
            parent: u64::MAX,
            child: u64::MAX,
            challenger: 1,
        };
        let benign = FeeFactors {
            parent: 1,
            child: 1,
            challenger: 1,
        };
        let fee = unbeatable_child_fee(u64::MAX, 0, &saturating_axis, &benign, 0).unwrap();
        assert_eq!(fee, u64::MAX);
    }
}
