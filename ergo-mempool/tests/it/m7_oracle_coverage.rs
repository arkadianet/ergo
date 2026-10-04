//! Coverage guard for the live Scala oracle (`m7_scala_oracle`). It stays
//! outside the `diagnostics` gate so default test runs execute it.

pub(crate) fn require_oracle_coverage(
    compared: usize,
    admitted_bysize: usize,
    admitted_bycost: usize,
    common_ordering: usize,
) -> Result<(), &'static str> {
    if compared == 0 {
        return Err("incomplete capture: no transaction reached both admission pipelines");
    }
    if admitted_bysize == 0 || admitted_bycost == 0 {
        return Err("incomplete capture: both weight modes require a real admission");
    }
    if common_ordering < 5 {
        return Err("incomplete capture: ordering requires at least five common admitted entries");
    }
    Ok(())
}

#[test]
fn oracle_coverage_rejects_all_excluded_and_empty_admission_results() {
    assert!(require_oracle_coverage(0, 0, 0, 0).is_err());
    assert!(require_oracle_coverage(10, 0, 0, 0).is_err());
    assert!(require_oracle_coverage(10, 5, 0, 5).is_err());
    assert!(require_oracle_coverage(10, 5, 5, 4).is_err());
    assert_eq!(require_oracle_coverage(10, 5, 5, 5), Ok(()));
}
