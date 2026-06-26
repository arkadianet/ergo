//! Weight functions for mempool priority ordering.
//!
//! Default is `ByCost` (`fee / cost_units`). All arithmetic uses
//! `u128` intermediates; the final stored weight fits in `u64`
//! because `fee × SCALE < 2^67` for any realistic Ergo fee.

use ergo_primitives::digest::Digest32;

/// Precision multiplier for fee-per-factor. `1024` matches Scala
/// `OrderedTxPool`; chosen to preserve useful precision in integer math.
pub const SCALE: u64 = 1024;

/// Inputs to a weight computation. The mempool computes these at
/// admission time and passes them to the `WeightFunction`.
#[derive(Debug, Clone, Copy)]
pub struct WeightInputs<'a> {
    pub tx_id: &'a Digest32,
    pub fee: u64,
    pub size_bytes: u32,
    pub cost: u64,
}

/// Mempool priority weight function. Different implementations optimize
/// for different fee-per-resource ratios. Must be deterministic and use
/// saturating arithmetic — a panic here would crash the mempool.
pub trait WeightFunction: Send + Sync {
    fn compute(&self, inputs: WeightInputs<'_>) -> u64;

    /// Short name used in logs and config echo. Kebab-case.
    fn name(&self) -> &'static str;
}

/// Fee per execution-cost unit. Default weight function. Closer to
/// actual node resource use than `BySize`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByCost;

impl WeightFunction for ByCost {
    fn compute(&self, inputs: WeightInputs<'_>) -> u64 {
        let fee = inputs.fee as u128;
        let cost = inputs.cost.max(1) as u128;
        let scale = SCALE as u128;
        let w = fee.saturating_mul(scale) / cost;
        u64::try_from(w).unwrap_or(u64::MAX)
    }

    fn name(&self) -> &'static str {
        "cost"
    }
}

/// Fee per byte (`fee × 1024 / size`) — Scala `SortingOption.FeePerByte`.
/// NOTE: this is *not* this node's default (that is `ByCost`), nor is it
/// Scala's stock default: Scala ships `mempoolSorting = "random"`, a
/// per-startup coin-flip between `FeePerByte` and `FeePerCycle`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BySize;

impl WeightFunction for BySize {
    fn compute(&self, inputs: WeightInputs<'_>) -> u64 {
        let fee = inputs.fee as u128;
        let size = (inputs.size_bytes as u128).max(1);
        let scale = SCALE as u128;
        let w = fee.saturating_mul(scale) / size;
        u64::try_from(w).unwrap_or(u64::MAX)
    }

    fn name(&self) -> &'static str {
        "size"
    }
}

/// Fee per max(cost, size). Penalizes transactions that are heavy along
/// either axis. Conservative; useful under sustained DoS load.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByMin;

impl WeightFunction for ByMin {
    fn compute(&self, inputs: WeightInputs<'_>) -> u64 {
        let fee = inputs.fee as u128;
        let cost = inputs.cost as u128;
        let size = inputs.size_bytes as u128;
        let denom = cost.max(size).max(1);
        let scale = SCALE as u128;
        let w = fee.saturating_mul(scale) / denom;
        u64::try_from(w).unwrap_or(u64::MAX)
    }

    fn name(&self) -> &'static str {
        "min"
    }
}

/// Parse a weight-function config string. Returns a boxed trait object
/// so the mempool can hold any variant behind a single field.
pub fn from_config(name: &str) -> Result<Box<dyn WeightFunction>, String> {
    match name {
        "cost" => Ok(Box::new(ByCost)),
        "size" => Ok(Box::new(BySize)),
        "min" => Ok(Box::new(ByMin)),
        other => Err(format!(
            "unknown weight function `{other}`; expected one of: cost, size, min"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ZERO_ID: Digest32 = Digest32::ZERO;

    fn inputs(fee: u64, size: u32, cost: u64) -> WeightInputs<'static> {
        WeightInputs {
            tx_id: &ZERO_ID,
            fee,
            size_bytes: size,
            cost,
        }
    }

    // ----- happy path -----

    #[test]
    fn by_cost_weight_matches_formula() {
        let w = ByCost.compute(inputs(1_000_000, 500, 50_000));
        assert_eq!(w, 1_000_000 * SCALE / 50_000);
    }

    #[test]
    fn by_size_weight_matches_formula() {
        let w = BySize.compute(inputs(1_000_000, 500, 50_000));
        assert_eq!(w, 1_000_000 * SCALE / 500);
    }

    #[test]
    fn by_min_picks_larger_denominator() {
        let cost_dominant = inputs(1_000_000, 100, 50_000);
        let size_dominant = inputs(1_000_000, 50_000, 100);
        assert_eq!(ByMin.compute(cost_dominant), 1_000_000 * SCALE / 50_000);
        assert_eq!(ByMin.compute(size_dominant), 1_000_000 * SCALE / 50_000);
    }

    #[test]
    fn saturates_rather_than_overflows() {
        // Worst-case fee is bounded by total supply but test the
        // saturation branch anyway.
        let huge = WeightInputs {
            tx_id: &ZERO_ID,
            fee: u64::MAX,
            size_bytes: 1,
            cost: 1,
        };
        let w = ByCost.compute(huge);
        assert!(w > 0, "saturation should still yield a positive weight");
    }

    #[test]
    fn zero_denominator_does_not_divide_by_zero() {
        let zero_cost = inputs(1_000_000, 10, 0);
        let zero_size = WeightInputs {
            tx_id: &ZERO_ID,
            fee: 1_000_000,
            size_bytes: 0,
            cost: 100,
        };
        // `.max(1)` converts the degenerate case into a tractable one.
        let _ = ByCost.compute(zero_cost);
        let _ = BySize.compute(zero_size);
    }

    #[test]
    fn from_config_round_trips_names() {
        assert_eq!(from_config("cost").unwrap().name(), "cost");
        assert_eq!(from_config("size").unwrap().name(), "size");
        assert_eq!(from_config("min").unwrap().name(), "min");
        assert!(from_config("bogus").is_err());
    }
}
