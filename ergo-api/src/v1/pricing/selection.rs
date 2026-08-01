use super::SpectrumN2TPool;

pub fn select_reference_pool(pools: &[SpectrumN2TPool]) -> Option<&SpectrumN2TPool> {
    pools.iter().max_by(|left, right| {
        left.effective_erg_reserve
            .cmp(&right.effective_erg_reserve)
            .then_with(|| {
                right
                    .pool_box_id
                    .as_bytes()
                    .cmp(left.pool_box_id.as_bytes())
            })
    })
}

#[cfg(test)]
mod tests {
    use crate::v1::decode::decoders::spectrum::SpectrumN2TPool;
    use ergo_primitives::digest::Digest32;

    use super::*;

    // ----- helpers -----

    fn pool(box_id_seed: u8, effective_erg_reserve: u64) -> SpectrumN2TPool {
        SpectrumN2TPool {
            pool_box_id: Digest32::from_bytes([box_id_seed; 32]),
            pool_nft: Digest32::from_bytes([1; 32]),
            lp_token: Digest32::from_bytes([2; 32]),
            token_y: Digest32::from_bytes([3; 32]),
            token_y_reserve: 1_000_000,
            erg_reserve: effective_erg_reserve + 10_000_000,
            effective_erg_reserve,
            fee_numerator: 997,
        }
    }

    // ----- happy path -----

    #[test]
    fn selection_prefers_largest_effective_erg_reserve() {
        let pools = [pool(1, 20_000_000), pool(2, 30_000_000)];

        assert_eq!(select_reference_pool(&pools), Some(&pools[1]));
    }

    #[test]
    fn selection_breaks_tie_by_lexicographically_smallest_box_id() {
        let pools = [pool(2, 30_000_000), pool(1, 30_000_000)];

        assert_eq!(select_reference_pool(&pools), Some(&pools[1]));
    }

    #[test]
    fn selection_is_independent_of_input_order() {
        let first = [
            pool(3, 20_000_000),
            pool(2, 30_000_000),
            pool(1, 30_000_000),
        ];
        let second = [first[2].clone(), first[0].clone(), first[1].clone()];

        assert_eq!(
            select_reference_pool(&first).map(|pool| pool.pool_box_id),
            select_reference_pool(&second).map(|pool| pool.pool_box_id)
        );
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[test]
    fn selection_empty_returns_none() {
        assert_eq!(select_reference_pool(&[]), None);
    }

    // ----- oracle parity -----
}
