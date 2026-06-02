use ergo_primitives::cost::JitCost;
use ergo_ser::sigma_value::SigmaBoolean;

const PARSE_CHALLENGE_DLOG: u64 = 10;
const COMPUTE_COMMITMENTS_SCHNORR: u64 = 3400;
const TO_BYTES_SCHNORR: u64 = 570;

const PARSE_CHALLENGE_DHT: u64 = 10;
const COMPUTE_COMMITMENTS_DHT: u64 = 6450;
const TO_BYTES_DHT: u64 = 680;

const TO_BYTES_CONJUNCTION: u64 = 15;

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
        SigmaBoolean::TrivialProp(_) => JitCost::from_jit(0),
        SigmaBoolean::ProveDlog(_) => {
            JitCost::from_jit(PARSE_CHALLENGE_DLOG + COMPUTE_COMMITMENTS_SCHNORR + TO_BYTES_SCHNORR)
        }
        SigmaBoolean::ProveDHTuple { .. } => {
            JitCost::from_jit(PARSE_CHALLENGE_DHT + COMPUTE_COMMITMENTS_DHT + TO_BYTES_DHT)
        }
        SigmaBoolean::Cand(children) | SigmaBoolean::Cor(children) => {
            let children_cost: u64 = children
                .iter()
                .map(|c| estimate_crypto_cost(c).value())
                .sum();
            JitCost::from_jit(TO_BYTES_CONJUNCTION + children_cost)
        }
        SigmaBoolean::Cthreshold { k, children } => {
            let n_children = children.len() as u32;
            let n_coefs = n_children.saturating_sub(*k as u32);
            let children_cost: u64 = children
                .iter()
                .map(|c| estimate_crypto_cost(c).value())
                .sum();
            // ParsePolynomial: PerItemCost(base=10, perChunk=10, chunk=1).cost(nCoefs)
            let parse_chunks = if n_coefs == 0 { 1 } else { n_coefs };
            let parse_cost = 10 + 10 * parse_chunks as u64;
            // EvaluatePolynomial: PerItemCost(base=3, perChunk=3, chunk=1).cost(nCoefs) * nChildren
            let eval_per_child = 3 + 3 * parse_chunks as u64;
            let eval_cost = eval_per_child * n_children as u64;
            JitCost::from_jit(parse_cost + eval_cost + TO_BYTES_CONJUNCTION + children_cost)
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
