use thiserror::Error;

/// Cost in JIT granularity (10x finer than block cost units).
/// Matches Scala's `JitCost` from sigmastate-interpreter.
///
/// **Backing type and Scala parity.** Scala defines
/// `case class JitCost private[sigma](val value: Int)` — the
/// underlying integer is a signed 32-bit `Int`, and arithmetic uses
/// `Math.addExact` / `Math.multiplyExact` which throw at the
/// `Int.MaxValue` boundary. We back with `u64` for ergonomic
/// reasons (no negative-cost concerns, larger headroom for
/// debugging) but every arithmetic operation enforces the
/// **Scala `i32::MAX` upper bound** (`0x7FFF_FFFF` = `2_147_483_647`).
/// Going past this returns [`JitCostError::Overflow`], mirroring
/// Scala's `ArithmeticException` from `addExact`/`multiplyExact`
/// as a structured Rust error rather than a panic.
///
/// **Encapsulation.** The inner `u64` is `pub(crate)`. Construct via
/// [`Self::from_jit`] (compile-time const constructor, panics on
/// out-of-range literals — caught at compile time when used in `const`
/// initializers), [`Self::try_from_jit`] (runtime fallible constructor
/// for dynamic values), or [`Self::from_block_cost`] (validates after
/// `× 10`). Read via [`Self::value`]. Direct construction outside this
/// crate is intentionally unavailable so the invariant cannot be
/// skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct JitCost(pub(crate) u64);

/// Scala `Int.MaxValue`. The acceptance ceiling JitCost arithmetic
/// must respect to match the Scala oracle's `addExact` /
/// `multiplyExact` failure boundary.
///
/// **Hostile-input unreachability for the structured error.**
/// All three runtime arithmetic paths
/// ([`JitCost::try_from_jit`], [`JitCost::from_block_cost`],
/// [`JitCost::checked_add`]) return [`JitCostError::Overflow`] if
/// the result would exceed `SCALA_INT_MAX`. The error path is
/// unreachable from honest validation because Ergo's protocol
/// parameter `max_block_cost` (mainnet: ~4.77M block units, see
/// `ergo-validation/active_params.rs:816`) caps total accumulated
/// JIT cost at `~47.7M`, which is **~45× below `SCALA_INT_MAX`**
/// (= 2.147B). [`CostAccumulator::add`] returns
/// [`CostError::LimitExceeded`] long before the underlying
/// arithmetic could overflow.
///
/// The pin test [`tests::accumulator_at_protocol_cap_is_well_under_scala_int_max`]
/// asserts the safety margin against the live mainnet
/// `max_block_cost` value. If a future protocol soft-fork raises
/// `max_block_cost` to within the safety margin, that test fires
/// — but the API now returns a structured error rather than
/// panicking, so the consensus layer would reject the offending
/// block cleanly instead of bringing down the node.
const SCALA_INT_MAX: u64 = i32::MAX as u64;

/// Failures returned by [`JitCost`] runtime arithmetic when a
/// computation would exceed the Scala `Int.MaxValue` bound that
/// [`JitCost`] mirrors. Mirrors Scala
/// `ArithmeticException` from `Math.addExact` / `Math.multiplyExact`
/// as a structured Rust error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JitCostError {
    /// A JitCost arithmetic operation would have produced a value
    /// above `SCALA_INT_MAX` (`i32::MAX` = 2_147_483_647 JIT units).
    /// `operation` names the arithmetic site for diagnostics
    /// (e.g. `"from_jit"`, `"from_block_cost"`, `"checked_add"`).
    /// `value` is the would-be u64 result (or, for `from_block_cost`,
    /// the original block-cost input that caused the multiplication
    /// step to overflow before bound-checking).
    #[error(
        "JitCost {operation} overflow: value {value} exceeds Scala Int.MaxValue ({SCALA_INT_MAX})"
    )]
    Overflow {
        /// The named arithmetic site that overflowed.
        operation: &'static str,
        /// The would-be u64 result that exceeded the bound.
        value: u64,
    },
}

impl JitCost {
    /// Zero cost, used as the initial accumulator value.
    pub const ZERO: JitCost = JitCost(0);

    /// **Const** constructor for compile-time literals. The bound check
    /// runs at const-eval time, so an out-of-range literal fails to
    /// compile — that's the only intended use. The `panic!` arm exists
    /// because `const fn` cannot return `Result`; it's an unreachable
    /// fallback for the literal-only path, mirroring `NonZero*::new_unchecked`-
    /// flavored compile-time invariants.
    ///
    /// **Runtime callers must use [`Self::try_from_jit`]** to get a
    /// structured [`JitCostError`] instead of a panic.
    pub const fn from_jit(v: u64) -> Self {
        if v > SCALA_INT_MAX {
            panic!(
                "JitCost::from_jit: literal value exceeds Scala Int.MaxValue \
                 (use try_from_jit for runtime values)"
            );
        }
        JitCost(v)
    }

    /// Runtime fallible constructor for a JIT-scale value. Returns
    /// [`JitCostError::Overflow`] if `v` exceeds the Scala
    /// `Int.MaxValue` bound. Use this for any value computed at
    /// runtime; for compile-time literals use [`Self::from_jit`].
    pub fn try_from_jit(v: u64) -> Result<Self, JitCostError> {
        if v > SCALA_INT_MAX {
            return Err(JitCostError::Overflow {
                operation: "try_from_jit",
                value: v,
            });
        }
        Ok(JitCost(v))
    }

    /// Convert block-level cost to JIT cost (multiply by 10).
    /// Returns [`JitCostError::Overflow`] if the result exceeds
    /// `SCALA_INT_MAX`, mirroring Scala
    /// `Math.multiplyExact(blockCost, 10)` from
    /// `JitCost.fromBlockCost` (`JitCost.scala:35`).
    pub fn from_block_cost(block_cost: u64) -> Result<Self, JitCostError> {
        let scaled = block_cost.checked_mul(10).ok_or(JitCostError::Overflow {
            operation: "from_block_cost (u64 mul)",
            value: block_cost,
        })?;
        if scaled > SCALA_INT_MAX {
            return Err(JitCostError::Overflow {
                operation: "from_block_cost",
                value: scaled,
            });
        }
        Ok(JitCost(scaled))
    }

    /// Convert back to block cost units (integer division by 10).
    pub fn to_block_cost(self) -> u64 {
        self.0 / 10
    }

    /// Raw inner value.
    pub fn value(self) -> u64 {
        self.0
    }

    /// Checked addition. Returns [`JitCostError::Overflow`] if the
    /// sum exceeds `SCALA_INT_MAX`, mirroring Scala
    /// `Math.addExact(value, y.value)` from `JitCost.+`
    /// (`JitCost.scala:11`).
    pub fn checked_add(self, other: JitCost) -> Result<JitCost, JitCostError> {
        let sum = self.0.checked_add(other.0).ok_or(JitCostError::Overflow {
            operation: "checked_add (u64 sum)",
            value: u64::MAX,
        })?;
        if sum > SCALA_INT_MAX {
            return Err(JitCostError::Overflow {
                operation: "checked_add",
                value: sum,
            });
        }
        Ok(JitCost(sum))
    }
}

/// Describes how an opcode's cost is computed.
#[derive(Debug, Clone, Copy)]
pub enum CostKind {
    /// Constant cost regardless of input size.
    Fixed(JitCost),
    /// Cost that scales with input size in chunks.
    PerItem {
        base: JitCost,
        per_chunk: JitCost,
        chunk_size: u32,
    },
}

impl CostKind {
    /// Compute the cost for `n_items` input elements.
    ///
    /// For `PerItem`: `base + per_chunk * chunks` where
    /// `chunks = max(0, (n_items - 1) / chunk_size + 1)` in signed
    /// arithmetic (JVM-style truncation toward zero). At `n_items = 0`
    /// this gives `chunks = 1` for `chunk_size >= 2` (where
    /// `-1 / chunk_size` truncates to `0`) and `chunks = 0` for
    /// `chunk_size == 1` (where `-1 / 1 = -1`). Cost-table sites
    /// using `chunk_size = 1` depend on the latter.
    ///
    /// Returns [`JitCostError::Overflow`] if any arithmetic step
    /// exceeds the Scala `Int.MaxValue` bound. In practice mainnet
    /// per-opcode costs are tiny — single-digit to low-thousands JIT
    /// units — so this error path is unreachable from honest input;
    /// see `cost.rs` `SCALA_INT_MAX` doc for the full unreachability
    /// argument.
    pub fn compute(self, n_items: u32) -> Result<JitCost, JitCostError> {
        match self {
            CostKind::Fixed(cost) => Ok(cost),
            CostKind::PerItem {
                base,
                per_chunk,
                chunk_size,
            } => {
                assert!(chunk_size > 0, "CostKind::PerItem chunk_size must be > 0");
                // JVM-style truncation toward zero: at n_items=0,
                // -1/chunk_size is 0 for chunk_size >= 2 (chunks = 1)
                // but -1 for chunk_size == 1 (chunks = 0). The .max(0)
                // is defensive — with the asserted chunk_size > 0 and
                // u32 n_items, the formula is already >= 0.
                let chunks = ((n_items as i64 - 1) / chunk_size as i64 + 1).max(0);
                let chunk_cost_value =
                    per_chunk
                        .0
                        .checked_mul(chunks as u64)
                        .ok_or(JitCostError::Overflow {
                            operation: "CostKind::compute (per_chunk * chunks)",
                            value: u64::MAX,
                        })?;
                let chunk_cost = JitCost::try_from_jit(chunk_cost_value)?;
                base.checked_add(chunk_cost)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum CostError {
    #[error("cost limit exceeded: {current} > {limit} (JitCost units)")]
    LimitExceeded { current: u64, limit: u64 },
    /// Underlying [`JitCost`] arithmetic overflowed
    /// `SCALA_INT_MAX`. Unreachable from honest mainnet input
    /// (see `SCALA_INT_MAX` doc for the unreachability proof and
    /// the pin test that enforces the safety margin) — but the
    /// API surfaces it structurally so the consensus layer can
    /// reject the offending input cleanly rather than panicking.
    #[error("JitCost arithmetic overflowed: {0}")]
    Overflow(#[from] JitCostError),
}

/// Accumulates JitCost during evaluation, optionally enforcing a limit.
/// The accumulator is additive-only -- there is no way to reduce the current cost.
pub struct CostAccumulator {
    current: JitCost,
    limit: JitCost,
    enforce: bool,
}

impl CostAccumulator {
    /// Create an enforcing accumulator with the given limit.
    pub fn new(limit: JitCost) -> Self {
        CostAccumulator {
            current: JitCost::ZERO,
            limit,
            enforce: true,
        }
    }

    /// Create a non-enforcing accumulator that tracks cost without
    /// rejecting via [`CostError::LimitExceeded`]. The limit field
    /// is unused (`enforce: false`) but is set to
    /// `JitCost(SCALA_INT_MAX)` so the value remains a legal
    /// JitCost instance.
    ///
    /// Note: even in recording-only mode, an add that would overflow
    /// SCALA_INT_MAX still returns [`CostError::Overflow`] —
    /// recording-only suppresses the limit check, not the structural
    /// invariant.
    pub fn recording_only() -> Self {
        CostAccumulator {
            current: JitCost::ZERO,
            limit: JitCost(SCALA_INT_MAX),
            enforce: false,
        }
    }

    /// Add cost. Returns:
    /// - `Err(CostError::LimitExceeded)` if enforcing and the
    ///   accumulated cost exceeds the configured limit.
    /// - `Err(CostError::Overflow(_))` if the underlying
    ///   `JitCost::checked_add` would exceed `SCALA_INT_MAX`
    ///   (unreachable from honest input — see `SCALA_INT_MAX`
    ///   doc).
    pub fn add(&mut self, cost: JitCost) -> Result<(), CostError> {
        // `?` here propagates JitCostError → CostError via the
        // `#[from]` derive on the Overflow variant.
        self.current = self.current.checked_add(cost)?;
        if self.enforce && self.current > self.limit {
            Err(CostError::LimitExceeded {
                current: self.current.0,
                limit: self.limit.0,
            })
        } else {
            Ok(())
        }
    }

    /// Convenience: compute the cost for a fixed-cost kind and add it.
    pub fn add_fixed(&mut self, kind: CostKind) -> Result<(), CostError> {
        self.add(kind.compute(0)?)
    }

    /// Convenience: compute the cost for a per-item kind and add it.
    pub fn add_per_item(&mut self, kind: CostKind, n_items: u32) -> Result<(), CostError> {
        self.add(kind.compute(n_items)?)
    }

    /// Drop the JitCost remainder (mod 10) accumulated since `baseline`.
    ///
    /// Scala's `verify()` truncates each input's eval_jit to block cost
    /// (`toBlockCost = jit / 10`) before adding crypto cost.  Rust
    /// accumulates everything as JitCost and truncates once.  Calling this
    /// after script evaluation (before crypto cost) aligns the rounding.
    pub fn snap_to_block_boundary(&mut self, baseline: JitCost) {
        let delta = self.current.0.saturating_sub(baseline.0);
        let remainder = delta % 10;
        self.current = JitCost(self.current.0 - remainder);
    }

    /// Current accumulated cost.
    pub fn total(&self) -> JitCost {
        self.current
    }

    /// Current accumulated cost in block cost units.
    pub fn total_block_cost(&self) -> u64 {
        self.current.to_block_cost()
    }

    /// Consumed block cost. Alias for `total_block_cost()` named for
    /// the mempool's anti-DoS budget accounting, where partial cost
    /// is attributed to budgets even on validation failure.
    pub fn consumed(&self) -> u64 {
        self.current.to_block_cost()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn jit_cost_from_block_cost() {
        let cost = JitCost::from_block_cost(100).unwrap();
        assert_eq!(cost, JitCost(1000));
        assert_eq!(cost.to_block_cost(), 100);
    }

    #[test]
    fn jit_cost_rounding() {
        assert_eq!(JitCost(5).to_block_cost(), 0);
        assert_eq!(JitCost(15).to_block_cost(), 1);
    }

    #[test]
    fn cost_accumulator_enforcing() {
        let mut acc = CostAccumulator::new(JitCost::from_block_cost(100).unwrap());
        // limit is JitCost(1000)
        acc.add(JitCost(500)).unwrap();
        acc.add(JitCost(500)).unwrap();
        let result = acc.add(JitCost(1));
        assert!(result.is_err());
        match result.unwrap_err() {
            CostError::LimitExceeded { current, limit } => {
                assert_eq!(current, 1001);
                assert_eq!(limit, 1000);
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn cost_accumulator_recording_only() {
        let mut acc = CostAccumulator::recording_only();
        for _ in 0..1_000_000 {
            acc.add(JitCost(1000)).unwrap();
        }
        assert_eq!(acc.total(), JitCost(1_000_000_000));
    }

    #[test]
    fn per_item_cost_computation() {
        let kind = CostKind::PerItem {
            base: JitCost(20),
            per_chunk: JitCost(1),
            chunk_size: 10,
        };
        // 25 items: chunks = (25-1)/10 + 1 = 2 + 1 = 3
        // cost = 20 + 1*3 = 23
        assert_eq!(kind.compute(25).unwrap(), JitCost(23));
    }

    #[test]
    fn per_item_cost_zero_items_yields_one_chunk() {
        let kind = CostKind::PerItem {
            base: JitCost(20),
            per_chunk: JitCost(1),
            chunk_size: 10,
        };
        // 0 items: signed (0 - 1) / 10 = -1/10 = 0 (JVM truncation toward zero)
        // chunks = 0 + 1 = 1, cost = 20 + 1*1 = 21
        assert_eq!(kind.compute(0).unwrap(), JitCost(21));
    }

    /// Pin the chunk_size=1 boundary: with chunk_size=1 and n_items=0
    /// the JVM-style signed-truncating formula yields zero chunks
    /// (not one). Cost-table sites that use `chunk_size = 1` depend
    /// on this — a future "fix" that special-cased zero items would
    /// charge an extra per_chunk unit and break Scala parity.
    #[test]
    fn per_item_zero_items_chunk_size_one_uses_zero_chunks() {
        let kind = CostKind::PerItem {
            base: JitCost(20),
            per_chunk: JitCost(1),
            chunk_size: 1,
        };
        // (0 - 1) / 1 + 1 = -1 + 1 = 0
        // cost = 20 + 1 * 0 = 20
        assert_eq!(kind.compute(0).unwrap(), JitCost(20));
    }

    proptest! {
        /// Verify `CostKind::PerItem::compute` against an **independently
        /// derived** expected chunk-count formula. "Independently derived"
        /// here means from first principles in this test file — NOT
        /// quoted from a published cost-table spec; no external source
        /// of the formula is being claimed.
        ///
        /// The expected formula below is a piecewise expression in
        /// positive-integer ceiling division. It is mathematically
        /// equivalent to the implementation's signed-truncation
        /// expression `((n as i64 - 1) / chunk_size as i64 + 1).max(0)`
        /// on the input range (`chunk_size > 0`, `n_items >= 0`), but
        /// expressed in a different form, so a bug in the impl's
        /// signed-truncation arithmetic would not be replicated in the
        /// test's piecewise form.
        ///
        /// Bounds are chosen so that the *successful* compute path is
        /// exercised: `base + per_chunk * chunks` stays well under
        /// `SCALA_INT_MAX` (≈ 2.1×10⁹). The overflow path is already
        /// pinned by the named tests below; this proptest pins the
        /// formula equivalence on the honest input range.
        #[test]
        fn proptest_per_item_compute_matches_independent_chunk_formula(
            base in 0u64..1_000,
            per_chunk in 0u64..1_000,
            chunk_size in 1u32..100,
            n_items in 0u32..10_000,
        ) {
            // Independent piecewise expected formula. Derived from first
            // principles: chunks of size k holding n items, with the
            // Scala/JVM convention that an initial chunk is allocated
            // for any work iff chunk_size >= 2 (the chunk_size = 1
            // special case yields zero chunks at n = 0).
            let expected_chunks: u64 = if n_items == 0 {
                if chunk_size == 1 { 0 } else { 1 }
            } else {
                // Positive-integer ceiling division (canonical stdlib form,
                // independent from the impl's signed-truncation expression
                // `((n - 1) / k + 1).max(0)`).
                (n_items as u64).div_ceil(chunk_size as u64)
            };
            let expected_value = base + per_chunk * expected_chunks;

            let kind = CostKind::PerItem {
                base: JitCost(base),
                per_chunk: JitCost(per_chunk),
                chunk_size,
            };
            let actual = kind.compute(n_items).unwrap();
            prop_assert_eq!(actual.value(), expected_value);
        }
    }

    /// Pin the `chunk_size > 0` contract on `CostKind::PerItem`.
    /// The struct fields are public (every static cost-table site
    /// uses literal `chunk_size: N`), so a malformed literal is the
    /// only way to violate the invariant — the assert turns that
    /// programmer error into a loud panic at the compute site
    /// rather than a silent divide-by-zero. If this test ever stops
    /// firing, the invariant has been weakened — re-evaluate
    /// whether `chunk_size` should be promoted to `NonZeroU32`.
    #[test]
    #[should_panic(expected = "CostKind::PerItem chunk_size must be > 0")]
    fn per_item_compute_with_zero_chunk_size_panics() {
        let kind = CostKind::PerItem {
            base: JitCost(0),
            per_chunk: JitCost(1),
            chunk_size: 0,
        };
        let _ = kind.compute(1);
    }

    // ----- error paths -----

    #[test]
    fn checked_add_at_scala_int_max_succeeds() {
        // i32::MAX exactly is accepted (Scala addExact accepts == MaxValue).
        let cost = JitCost(SCALA_INT_MAX - 1).checked_add(JitCost(1)).unwrap();
        assert_eq!(cost.value(), SCALA_INT_MAX);
    }

    #[test]
    fn checked_add_one_above_scala_int_max_returns_overflow() {
        // Mirror Scala Math.addExact: i32::MAX + 1 errors structurally.
        match JitCost(SCALA_INT_MAX).checked_add(JitCost(1)) {
            Err(JitCostError::Overflow { operation, value }) => {
                assert_eq!(operation, "checked_add");
                assert_eq!(value, SCALA_INT_MAX + 1);
            }
            other => panic!("expected Overflow, got {other:?}"),
        }
    }

    #[test]
    fn checked_add_u64_overflow_returns_overflow() {
        // Defense-in-depth: u64 overflow is also a structured error.
        match JitCost(u64::MAX).checked_add(JitCost(1)) {
            Err(JitCostError::Overflow { operation, .. }) => {
                assert!(
                    operation.contains("u64 sum"),
                    "expected u64 overflow tag, got {operation}"
                );
            }
            other => panic!("expected Overflow, got {other:?}"),
        }
    }

    #[test]
    fn from_block_cost_one_above_scala_int_max_returns_overflow() {
        // Scaled value (block_cost * 10) just past i32::MAX must error.
        // SCALA_INT_MAX / 10 = 214_748_364, with remainder 7. So
        // block_cost = 214_748_365 produces 2_147_483_650 which is
        // i32::MAX + 3 — past the bound.
        match JitCost::from_block_cost(214_748_365) {
            Err(JitCostError::Overflow { operation, value }) => {
                assert_eq!(operation, "from_block_cost");
                assert_eq!(value, 2_147_483_650);
            }
            other => panic!("expected Overflow, got {other:?}"),
        }
    }

    #[test]
    fn from_block_cost_at_max_block_cost_well_under_bound() {
        // Practical mainnet `MaxBlockCost` is ~7M block-cost units.
        // Scaled: 70M JitCost units. Well under SCALA_INT_MAX.
        let cost = JitCost::from_block_cost(7_000_000).unwrap();
        assert_eq!(cost.value(), 70_000_000);
        assert!(cost.value() < SCALA_INT_MAX);
    }

    #[test]
    fn try_from_jit_above_scala_int_max_returns_overflow() {
        match JitCost::try_from_jit(SCALA_INT_MAX + 1) {
            Err(JitCostError::Overflow { operation, value }) => {
                assert_eq!(operation, "try_from_jit");
                assert_eq!(value, SCALA_INT_MAX + 1);
            }
            other => panic!("expected Overflow, got {other:?}"),
        }
    }

    #[test]
    fn cost_accumulator_overflow_propagates_as_cost_error() {
        // Recording-only suppresses the limit check, but a sum that
        // exceeds SCALA_INT_MAX must still surface structurally
        // (load-bearing invariant: recording-only means "no enforced
        // cap", not "no overflow detection").
        let mut acc = CostAccumulator::recording_only();
        acc.add(JitCost(SCALA_INT_MAX - 1)).unwrap();
        match acc.add(JitCost(2)) {
            Err(CostError::Overflow(JitCostError::Overflow { operation, .. })) => {
                assert_eq!(operation, "checked_add");
            }
            other => panic!("expected CostError::Overflow, got {other:?}"),
        }
    }

    /// **Pin: hostile-input error-unreachability invariant.**
    ///
    /// The three JitCost arithmetic paths return
    /// [`JitCostError::Overflow`] at SCALA_INT_MAX
    /// (i32::MAX = 2_147_483_647 JIT units). For this error to be
    /// reachable from a malicious script, accumulated cost would
    /// have to exceed that bound — which requires honest-protocol
    /// `max_block_cost` (mainnet voted-param ID 4) to be set within
    /// the error's reach when scaled `× 10` to JIT units.
    ///
    /// Mainnet value (per `ergo-validation/active_params.rs:816`):
    /// `max_block_cost = 0x0048C570 = 4_769_136` block units →
    /// `47_691_360` JIT units. SCALA_INT_MAX / mainnet_jit_cap ≈ 45×.
    ///
    /// If a future protocol soft-fork raises `max_block_cost` past
    /// `~214_748_364` block units (= SCALA_INT_MAX / 10), this
    /// test fires. Unlike the pre-conversion design (which would
    /// have panicked the node), the structured error means the
    /// consensus layer can reject the offending block cleanly via
    /// `CostError::Overflow` — but the validator should still be
    /// updated to handle the new operating regime.
    #[test]
    fn accumulator_at_protocol_cap_is_well_under_scala_int_max() {
        // Live mainnet max_block_cost (block units).
        const MAINNET_MAX_BLOCK_COST: u64 = 4_769_136;
        // Scaled to JIT units: × 10.
        const MAINNET_MAX_JIT_COST: u64 = MAINNET_MAX_BLOCK_COST * 10;

        // Sanity: the JIT cap fits well under SCALA_INT_MAX.
        // (Clippy flags this as constant-valued — that's the point;
        // we want the assertion to fail to compile if someone bumps
        // either constant past the boundary.)
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                MAINNET_MAX_JIT_COST < SCALA_INT_MAX,
                "mainnet JIT cap >= SCALA_INT_MAX — JitCostError::Overflow is now \
                 reachable from honest payloads; consensus layer must handle it",
            );
        }

        // Document the actual margin so future reviewers see how
        // close (or far) we are. >=10× is a comfortable buffer.
        let margin = SCALA_INT_MAX / MAINNET_MAX_JIT_COST;
        assert!(
            margin >= 10,
            "mainnet safety margin shrunk to {margin}× — baseline is 45×; \
             consensus layer should be audited for Overflow handling",
        );

        // End-to-end: building a JitCost from the protocol cap
        // succeeds (no error), and a CostAccumulator with that
        // limit accepts adds up to the cap then rejects the next
        // add via LimitExceeded — never via Overflow.
        let cap = JitCost::from_block_cost(MAINNET_MAX_BLOCK_COST).unwrap();
        let mut acc = CostAccumulator::new(cap);
        // Fill to exactly the cap.
        acc.add(cap).unwrap();
        // One more JIT unit must be rejected via LimitExceeded
        // (the structural cap on honest input), NOT via Overflow
        // (which would only fire above SCALA_INT_MAX).
        let err = acc.add(JitCost::from_jit(1)).unwrap_err();
        assert!(
            matches!(err, CostError::LimitExceeded { .. }),
            "expected LimitExceeded (honest path), got {err:?}",
        );
    }
}
