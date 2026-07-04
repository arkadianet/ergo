//! `max_level_of` parity against the Scala oracle on REAL mainnet
//! headers. Expected values captured via scala-cli (ergo-core 6.0.2
//! `NipopowAlgos.maxLevelOf`, 2026-07-05) over every header embedded in
//! the committed proof fixture — 132 headers spanning v1..v4 eras and
//! μ-levels 0..20 plus the genesis sentinel. Pins the f64 log2
//! arithmetic (`required.log2() - real.log2()` truncation) against
//! Scala's Double semantics, the recon's numbered precision risk.

#[test]
fn max_level_of_matches_scala_oracle_on_all_fixture_headers() {
    let bytes = std::fs::read("../test-vectors/mainnet/nipopow/proof_m6_k10.scala.bin").unwrap();
    let proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&bytes).unwrap();
    let headers: Vec<&ergo_ser::header::Header> = proof
        .prefix
        .iter()
        .map(|p| &p.header)
        .chain(std::iter::once(&proof.suffix_head.header))
        .chain(proof.suffix_tail.iter())
        .collect();
    let expected = std::fs::read_to_string("../test-vectors/mainnet/nipopow/max_levels_scala.txt")
        .expect("oracle fixture");
    let expected: Vec<(u32, u64)> = expected
        .lines()
        .map(|l| {
            let mut it = l.split_whitespace();
            (
                it.next().unwrap().parse().unwrap(),
                it.next().unwrap().parse().unwrap(),
            )
        })
        .collect();
    assert_eq!(headers.len(), expected.len(), "header count");
    for (h, (exp_height, exp_level)) in headers.iter().zip(expected) {
        assert_eq!(h.height, exp_height, "fixture order");
        let lvl = ergo_validation::popow::algos::max_level_of(h);
        // Scala prints Int.MaxValue for genesis; our sentinel is u32::MAX.
        let comparable = if lvl == u32::MAX {
            2147483647u64
        } else {
            lvl as u64
        };
        assert_eq!(
            comparable, exp_level,
            "level divergence at h={} (v{})",
            h.height, h.version
        );
    }
}
