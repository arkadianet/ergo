#[test]
fn header_pow_script_verdicts_and_costs_match_reference() {
    super::reference_607_tx::assert_fixture("check-pow");
}
