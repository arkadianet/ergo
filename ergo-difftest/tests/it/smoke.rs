//! CI regression guard: a short deterministic campaign must find no invariant
//! violations against the current decoders. If a future change reintroduces a
//! decode panic or a non-fixed-point re-encode, this fails with a reproducible
//! `--repro` hex. Keep iters small so it stays fast.

use ergo_difftest::run_campaign;

#[test]
fn short_campaign_finds_no_invariant_violations() {
    let (stats, findings) = run_campaign(1, 3000, None, &[], false);
    assert!(stats.iters > 0, "campaign did not run");
    assert!(
        findings.is_empty(),
        "difftest found {} invariant violation(s):\n{:#?}",
        findings.len(),
        findings
    );
}
