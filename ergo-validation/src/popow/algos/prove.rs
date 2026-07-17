use super::scoring::max_level_of;

/// Parameters governing NiPoPoW proof construction (KMZ17). Mirrors
/// Scala `PoPowParams(m, k, continuous)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoPowParams {
    /// Minimum super-chain length per level (mainnet = 6).
    pub m: u32,
    /// Suffix length (mainnet = 10).
    pub k: u32,
    /// Whether the proof is continuous (true) — required for the
    /// post-suffix difficulty-headers check.
    pub continuous: bool,
}

/// Construct a NiPoPoW proof for the given chain. Scala parity:
/// `NipopowAlgos.prove` (`NipopowAlgos.scala:129-159`).
///
/// Preconditions:
/// * `chain.len() >= k + m`.
/// * `chain[0]` is genesis (`parent_id == zeros`).
/// * `params.k >= 1`.
///
/// Returns `Err` on precondition violation.
///
/// The chain is supplied as a `Vec<PoPowHeader>` so each entry
/// carries its own (header, interlinks, batch-merkle-proof) — the
/// caller is expected to build PoPowHeader instances via
/// [`super::interlinks::build_popow_header`] before calling `prove`.
pub fn prove(
    chain: Vec<ergo_ser::popow_header::PoPowHeader>,
    params: PoPowParams,
) -> Result<ergo_ser::popow_proof::NipopowProof, String> {
    if params.k < 1 {
        return Err(format!("PoPowParams::k must be >= 1 (got {})", params.k));
    }
    // `m` is the minimum super-chain length; `prove_prefix_loop` indexes
    // `sub_chain[sub_chain.len() - m]`, so `m == 0` would compute
    // `sub_chain[len]` and panic out of bounds. Reject it here alongside
    // the sibling `k` check (honest callers pass `m ≥ 1`; mainnet uses 6).
    if params.m < 1 {
        return Err(format!("PoPowParams::m must be >= 1 (got {})", params.m));
    }
    if (chain.len() as u32) < params.k.saturating_add(params.m) {
        return Err(format!(
            "chain.len() = {} < k + m = {}",
            chain.len(),
            params.k.saturating_add(params.m)
        ));
    }
    let genesis = chain.first().ok_or_else(|| "empty chain".to_string())?;
    if *genesis.header.parent_id.as_bytes() != [0u8; 32] {
        return Err("chain.first() must be genesis (parent_id == zeros)".into());
    }

    let k = params.k as usize;
    let m = params.m as usize;

    // Suffix = last k entries. suffix_head = first; suffix_tail =
    // the remaining k-1 raw headers.
    let suffix_start = chain.len() - k;
    let suffix: Vec<ergo_ser::popow_header::PoPowHeader> = chain[suffix_start..].to_vec();
    let suffix_head = suffix[0].clone();
    let suffix_tail: Vec<ergo_ser::header::Header> =
        suffix.iter().skip(1).map(|p| p.header.clone()).collect();

    // The prefix carries the sparse witness chain. Scala recurses
    // from `maxLevel = chain.dropRight(k).last.interlinks.size - 1`
    // down to 0, accumulating sub-chains of each level that
    // satisfy `m < subChain.size`.
    let dropped_last = &chain[chain.len() - k - 1];
    let max_level = if dropped_last.interlinks.is_empty() {
        0i64
    } else {
        (dropped_last.interlinks.len() as i64) - 1
    };

    let mut acc: Vec<ergo_ser::popow_header::PoPowHeader> = Vec::new();
    prove_prefix_loop(&chain, max_level, &chain[0], &mut acc, k, m);
    acc.sort_by_key(|p| p.header.height);
    acc.dedup_by_key(|p| p.header.height);

    Ok(ergo_ser::popow_proof::NipopowProof {
        m: params.m,
        k: params.k,
        prefix: acc,
        suffix_head,
        suffix_tail,
        continuous: params.continuous,
    })
}

/// Tail-recursive worker for [`prove`]'s prefix construction.
/// Mirrors Scala `provePrefix` at `NipopowAlgos.scala:137-151`.
fn prove_prefix_loop(
    chain: &[ergo_ser::popow_header::PoPowHeader],
    level: i64,
    anchoring_point: &ergo_ser::popow_header::PoPowHeader,
    acc: &mut Vec<ergo_ser::popow_header::PoPowHeader>,
    k: usize,
    m: usize,
) {
    if level < 0 {
        return;
    }
    // chain.dropRight(k).filter(maxLevelOf >= level && height >= anchoring_point.height)
    let cutoff = chain.len().saturating_sub(k);
    let sub_chain: Vec<ergo_ser::popow_header::PoPowHeader> = chain[..cutoff]
        .iter()
        .filter(|p| {
            (max_level_of(&p.header) as i64) >= level
                && p.header.height >= anchoring_point.header.height
        })
        .cloned()
        .collect();
    if m < sub_chain.len() {
        // Scala: provePrefix(subChain(subChain.size - params.m), level - 1, acc ++ subChain)
        let new_anchor = sub_chain[sub_chain.len() - m].clone();
        acc.extend(sub_chain);
        prove_prefix_loop(chain, level - 1, &new_anchor, acc, k, m);
    } else {
        // Scala: provePrefix(anchoringPoint, level - 1, acc ++ subChain)
        acc.extend(sub_chain);
        let preserved_anchor = anchoring_point.clone();
        prove_prefix_loop(chain, level - 1, &preserved_anchor, acc, k, m);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::{read_header, Header};

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

    #[test]
    fn prove_rejects_chain_below_k_plus_m() {
        let g = header_from_hex(GENESIS_HEX);
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let chain: Vec<ergo_ser::popow_header::PoPowHeader> = vec![g, h2]
            .into_iter()
            .map(|h| ergo_ser::popow_header::PoPowHeader {
                header: h,
                interlinks: vec![],
                interlinks_proof: vec![],
            })
            .collect();
        let params = PoPowParams {
            m: 6,
            k: 10,
            continuous: true,
        };
        let err = prove(chain, params).expect_err("chain too short");
        assert!(err.contains("< k + m"), "unexpected error: {err}");
    }

    #[test]
    fn prove_rejects_m_zero() {
        // m == 0 would make prove_prefix_loop index sub_chain[len] (out
        // of bounds) and panic. It must be rejected up front, like k == 0.
        let g = header_from_hex(GENESIS_HEX);
        let chain: Vec<ergo_ser::popow_header::PoPowHeader> = vec![g]
            .into_iter()
            .map(|h| ergo_ser::popow_header::PoPowHeader {
                header: h,
                interlinks: vec![],
                interlinks_proof: vec![],
            })
            .collect();
        let params = PoPowParams {
            m: 0,
            k: 2,
            continuous: true,
        };
        let err = prove(chain, params).expect_err("m == 0 must be rejected");
        assert!(err.contains("m must be >= 1"), "unexpected error: {err}");
    }

    #[test]
    fn prove_rejects_non_genesis_anchored_chain() {
        // h2 first (not genesis) → must error.
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let chain: Vec<ergo_ser::popow_header::PoPowHeader> = (0..3)
            .map(|_| ergo_ser::popow_header::PoPowHeader {
                header: h2.clone(),
                interlinks: vec![],
                interlinks_proof: vec![],
            })
            .collect();
        let params = PoPowParams {
            m: 1,
            k: 2,
            continuous: true,
        };
        let err = prove(chain, params).expect_err("must be genesis-anchored");
        assert!(err.contains("genesis"), "unexpected error: {err}");
    }

    #[test]
    fn prove_minimal_chain_produces_well_formed_proof() {
        // Build a 3-header chain (genesis + 2 fake follow-ups by
        // reusing h2; the prove() function only checks heights +
        // interlinks structure, not chain semantic correctness).
        // m=1, k=2 → minimum viable.
        let g = header_from_hex(GENESIS_HEX);
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let mut h3 = header_from_hex(HEIGHT_2_V1_HEX);
        h3.height = 3;
        let chain: Vec<ergo_ser::popow_header::PoPowHeader> = vec![g, h2, h3]
            .into_iter()
            .map(|h| ergo_ser::popow_header::PoPowHeader {
                header: h,
                interlinks: vec![ModifierId::from_bytes([0x11; 32])],
                interlinks_proof: vec![],
            })
            .collect();
        let params = PoPowParams {
            m: 1,
            k: 2,
            continuous: true,
        };
        let proof = prove(chain, params).expect("3-header chain proves");
        assert_eq!(proof.m, 1);
        assert_eq!(proof.k, 2);
        // suffix = last k=2 entries: suffix_head + 1 tail header.
        assert_eq!(proof.suffix_tail.len(), 1);
        // prefix sorted by height + dedup'd.
        for w in proof.prefix.windows(2) {
            assert!(
                w[0].header.height < w[1].header.height,
                "prefix must be strictly increasing in height"
            );
        }
    }
}
