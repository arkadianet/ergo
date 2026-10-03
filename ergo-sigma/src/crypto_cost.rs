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
    // Cache each stored node, retaining multiplicity when a parent sums its
    // children. Repeated references cost exactly as the expanded tree would,
    // while estimation takes time proportional to the stored graph.
    let mut costs = std::collections::HashMap::<*const SigmaBoolean, u64>::new();
    let mut pending = vec![(prop, false)];
    while let Some((node, children_ready)) = pending.pop() {
        let key = node as *const SigmaBoolean;
        if costs.contains_key(&key) {
            continue;
        }
        let children = match node {
            SigmaBoolean::Cand(children)
            | SigmaBoolean::Cor(children)
            | SigmaBoolean::Cthreshold { children, .. } => Some(children),
            _ => None,
        };
        if !children_ready {
            if let Some(children) = children {
                pending.push((node, true));
                pending.extend(children.iter().rev().map(|child| (child, false)));
                continue;
            }
        }
        let children_cost = children.map_or(0, |children| {
            children.iter().fold(0u64, |sum, child| {
                sum.saturating_add(costs[&(child as *const SigmaBoolean)])
            })
        });
        let cost = match node {
            SigmaBoolean::TrivialProp(_) => 0,
            SigmaBoolean::ProveDlog(_) => {
                PARSE_CHALLENGE_DLOG + COMPUTE_COMMITMENTS_SCHNORR + TO_BYTES_SCHNORR
            }
            SigmaBoolean::ProveDHTuple { .. } => {
                PARSE_CHALLENGE_DHT + COMPUTE_COMMITMENTS_DHT + TO_BYTES_DHT
            }
            SigmaBoolean::Cand(_) | SigmaBoolean::Cor(_) => {
                TO_BYTES_CONJUNCTION.saturating_add(children_cost)
            }
            SigmaBoolean::Cthreshold { k, children } => {
                let n = u64::try_from(children.len()).unwrap_or(u64::MAX);
                let n_coefs = n.saturating_sub(u64::from(*k));
                let parse = PARSE_POLYNOMIAL_BASE
                    .saturating_add(PARSE_POLYNOMIAL_PER_CHUNK.saturating_mul(n_coefs));
                let eval = EVALUATE_POLYNOMIAL_BASE
                    .saturating_add(EVALUATE_POLYNOMIAL_PER_CHUNK.saturating_mul(n_coefs))
                    .saturating_mul(n);
                parse
                    .saturating_add(eval)
                    .saturating_add(TO_BYTES_CONJUNCTION)
                    .saturating_add(children_cost)
            }
        };
        // Preserve the existing per-node JIT saturation.
        costs.insert(key, jit_cost(cost).value());
    }
    jit_cost(costs[&(prop as *const SigmaBoolean)])
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
        let prop = SigmaBoolean::Cand(vec![dlog(), dlog()].into());
        // TO_BYTES_CONJUNCTION(15) + 2 * ProveDlog(3980) = 7975
        assert_eq!(estimate_crypto_cost(&prop), JitCost::from_jit(7975));
    }

    #[test]
    fn or_composition_cost() {
        let prop = SigmaBoolean::Cor(vec![dlog(), dht()].into());
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
            children: vec![dlog(), dlog(), dlog()].into(),
        };
        assert_eq!(estimate_crypto_cost(&prop), JitCost::from_jit(11993));
    }
}
