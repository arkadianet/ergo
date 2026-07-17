use ergo_ser::header::Header;

use super::header_id;

/// Last shared header between two chains, iff they share a genesis
/// (i.e. their first elements are equal). Returns `None` otherwise.
///
/// Scala uses the naïve intersect-then-last (`NipopowAlgos.scala:116-122`);
/// this port matches the same semantics. The intersection is by header
/// id, walked in order, so the returned header is the deepest one
/// present in both chains.
pub fn lowest_common_ancestor<'a>(
    left_chain: &'a [Header],
    right_chain: &'a [Header],
) -> Result<Option<&'a Header>, ergo_ser::error::WriteError> {
    let Some(left_head) = left_chain.first() else {
        return Ok(None);
    };
    let Some(right_head) = right_chain.first() else {
        return Ok(None);
    };
    if header_id(left_head)? != header_id(right_head)? {
        return Ok(None);
    }

    // Same-genesis: walk left, keep the deepest one that's also in
    // right by id. O(L * R) like Scala's intersect; chains used here
    // are small (proof prefixes), not full mainnet chains.
    let mut right_ids: std::collections::HashSet<[u8; 32]> =
        std::collections::HashSet::with_capacity(right_chain.len());
    for h in right_chain {
        right_ids.insert(header_id(h)?);
    }

    for h in left_chain.iter().rev() {
        if right_ids.contains(&header_id(h)?) {
            return Ok(Some(h));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;

    // ----- helpers -----

    /// Deserialize a hex-encoded header. Panics on bad hex / decode.
    fn header_from_hex(hex_bytes: &str) -> Header {
        let raw = hex::decode(hex_bytes).expect("valid hex");
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).expect("valid header bytes")
    }

    /// Mainnet genesis header (height 1). Sourced from
    /// `test-vectors/mainnet/headers_1_10.json[0]`.
    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

    /// Mainnet height 2 (v1 Autolykos, non-genesis). Sourced from
    /// `headers_1_10.json[1]`.
    const HEIGHT_2_V1_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    fn with_nonzero_parent(mut h: Header, parent: [u8; 32]) -> Header {
        h.parent_id = ergo_primitives::digest::ModifierId::from_bytes(parent);
        h
    }

    #[test]
    fn lowest_common_ancestor_shared_genesis_returns_deepest_common() {
        let g = header_from_hex(GENESIS_HEX);
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        // Both chains start at genesis, share heights 1..2, then
        // diverge synthetically at h3.
        let h3_left = with_nonzero_parent(h2.clone(), [0x11; 32]);
        let h3_right = with_nonzero_parent(h2.clone(), [0x22; 32]);
        let left = vec![g.clone(), h2.clone(), h3_left];
        let right = vec![g, h2.clone(), h3_right];
        let lca = lowest_common_ancestor(&left, &right)
            .expect("test fixture headers serialize")
            .expect("shared genesis -> some lca");
        assert_eq!(header_id(lca).unwrap(), header_id(&h2).unwrap());
    }

    #[test]
    fn lowest_common_ancestor_diff_genesis_returns_none() {
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let left = vec![h2.clone()]; // genesis = h2.id
        let right_synth_genesis = with_nonzero_parent(h2.clone(), [0xff; 32]);
        let right = vec![right_synth_genesis];
        assert!(lowest_common_ancestor(&left, &right)
            .expect("test fixture headers serialize")
            .is_none());
    }
}
