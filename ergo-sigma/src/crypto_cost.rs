use ergo_primitives::cost::JitCost;
use ergo_ser::sigma_value::SigmaBoolean;

pub const PARSE_CHALLENGE_DLOG: u64 = 10;
pub const COMPUTE_COMMITMENTS_SCHNORR: u64 = 3400;
pub const TO_BYTES_SCHNORR: u64 = 570;

pub const PARSE_CHALLENGE_DHT: u64 = 10;
pub const COMPUTE_COMMITMENTS_DHT: u64 = 6450;
pub const TO_BYTES_DHT: u64 = 680;

pub const TO_BYTES_CONJUNCTION: u64 = 15;

pub const PARSE_POLYNOMIAL_BASE: u64 = 10;
pub const PARSE_POLYNOMIAL_PER_CHUNK: u64 = 10;
pub const EVALUATE_POLYNOMIAL_BASE: u64 = 3;
pub const EVALUATE_POLYNOMIAL_PER_CHUNK: u64 = 3;

fn jit_cost(value: u64) -> JitCost {
    JitCost::from_jit(value.min(i32::MAX as u64))
}

/// JitCost charged for verifying `prop` ahead-of-time, before the actual
/// sigma-proof verification runs. Mirrors the Scala interpreter's
/// per-leaf-and-conjunction tally:
///
/// * Trivial propositions cost nothing.
/// * `ProveDlog` charges parse + commitment + serialization for one
///   Schnorr proof (`PARSE_CHALLENGE_DLOG + COMPUTE_COMMITMENTS_SCHNORR
///   + TO_BYTES_SCHNORR`).
/// * `ProveDHTuple` charges the heavier DHT variant.
/// * `Cand` / `Cor` add `TO_BYTES_CONJUNCTION` plus the recursive sum
///   over children.
/// * `Cthreshold` adds the polynomial parse and per-child polynomial
///   evaluation cost on top of the conjunction sum.
pub fn estimate_crypto_cost(prop: &SigmaBoolean) -> JitCost {
    match prop {
        SigmaBoolean::TrivialProp(_) => jit_cost(0),
        SigmaBoolean::ProveDlog(_) => jit_cost(
            PARSE_CHALLENGE_DLOG
                .saturating_add(COMPUTE_COMMITMENTS_SCHNORR)
                .saturating_add(TO_BYTES_SCHNORR),
        ),
        SigmaBoolean::ProveDHTuple { .. } => jit_cost(
            PARSE_CHALLENGE_DHT
                .saturating_add(COMPUTE_COMMITMENTS_DHT)
                .saturating_add(TO_BYTES_DHT),
        ),
        SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
            let children_cost = children.iter().fold(0u64, |cost, child| {
                cost.saturating_add(estimate_crypto_cost(child).value())
            });
            jit_cost(TO_BYTES_CONJUNCTION.saturating_add(children_cost))
        }
        SigmaBoolean::Cthreshold { k, children } => {
            let n_children = u64::try_from(children.len()).unwrap_or(u64::MAX);
            let n_coefs = n_children.saturating_sub(u64::from(*k));
            let children_cost = children.iter().fold(0u64, |cost, child| {
                cost.saturating_add(estimate_crypto_cost(child).value())
            });
            // At k == n, Scala charges only the polynomial base costs.
            // ParsePolynomial: PerItemCost(base=10, perChunk=10, chunk=1).cost(nCoefs)
            let parse_cost = PARSE_POLYNOMIAL_BASE
                .saturating_add(PARSE_POLYNOMIAL_PER_CHUNK.saturating_mul(n_coefs));
            // EvaluatePolynomial: PerItemCost(base=3, perChunk=3, chunk=1).cost(nCoefs) * nChildren
            let eval_per_child = EVALUATE_POLYNOMIAL_BASE
                .saturating_add(EVALUATE_POLYNOMIAL_PER_CHUNK.saturating_mul(n_coefs));
            let eval_cost = eval_per_child.saturating_mul(n_children);
            jit_cost(
                parse_cost
                    .saturating_add(eval_cost)
                    .saturating_add(TO_BYTES_CONJUNCTION)
                    .saturating_add(children_cost),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use ergo_primitives::group_element::GroupElement;

    use super::*;

    fn ge() -> GroupElement {
        GroupElement::from_bytes([0u8; 33])
    }

    fn dlog() -> SigmaBoolean {
        SigmaBoolean::ProveDlog(ge())
    }

    fn dht() -> SigmaBoolean {
        SigmaBoolean::ProveDHTuple {
            g: ge(),
            h: ge(),
            u: ge(),
            v: ge(),
        }
    }

    #[test]
    fn trivial_prop_cost() {
        assert_eq!(
            estimate_crypto_cost(&SigmaBoolean::TrivialProp(true)),
            JitCost::from_jit(0)
        );
        assert_eq!(
            estimate_crypto_cost(&SigmaBoolean::TrivialProp(false)),
            JitCost::from_jit(0)
        );
    }

    #[test]
    fn prove_dlog_cost() {
        // 10 + 3400 + 570 = 3980
        assert_eq!(estimate_crypto_cost(&dlog()), JitCost::from_jit(3980));
    }

    #[test]
    fn prove_dht_cost() {
        // 10 + 6450 + 680 = 7140
        assert_eq!(estimate_crypto_cost(&dht()), JitCost::from_jit(7140));
    }

    #[test]
    fn and_composition_cost() {
        let prop = SigmaBoolean::Cand(vec![dlog(), dlog()]);
        // TO_BYTES_CONJUNCTION(15) + 2 * ProveDlog(3980) = 7975
        assert_eq!(estimate_crypto_cost(&prop), JitCost::from_jit(7975));
    }

    #[test]
    fn or_composition_cost() {
        let prop = SigmaBoolean::Cor(vec![dlog(), dht()]);
        // TO_BYTES_CONJUNCTION(15) + ProveDlog(3980) + ProveDHT(7140) = 11135
        assert_eq!(estimate_crypto_cost(&prop), JitCost::from_jit(11135));
    }

    #[test]
    fn cthreshold_2_of_3_dlog() {
        // 2-of-3: k=2, n=3 => n_coefs = 3 - 2 = 1
        // parse_chunks = 1, parse_cost = 10 + 10*1 = 20
        // eval_per_child = 3 + 3*1 = 6, eval_cost = 6 * 3 = 18
        // children_cost = 3 * 3980 = 11940
        // total = 20 + 18 + 15 + 11940 = 11993
        let prop = SigmaBoolean::Cthreshold {
            k: 2,
            children: vec![dlog(), dlog(), dlog()],
        };
        assert_eq!(estimate_crypto_cost(&prop), JitCost::from_jit(11993));
    }
}
