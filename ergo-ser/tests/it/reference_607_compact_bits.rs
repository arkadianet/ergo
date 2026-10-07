use ergo_ser::difficulty::{decode_compact_bits, decode_compact_bits_signed};

#[test]
fn compact_mpi_sign_and_magnitude_match_reference() {
    let cases: Vec<_> = include_str!("../../../test-vectors/reference-6.0.7/difficulty/cases.tsv")
        .lines()
        .collect();
    let results: Vec<_> =
        include_str!("../../../test-vectors/reference-6.0.7/difficulty/cases.jvm.tsv")
            .lines()
            .collect();
    assert_eq!(cases.len(), results.len());
    for (case, result) in cases.into_iter().zip(results) {
        let fields: Vec<_> = case.split('\t').collect();
        let expected: Vec<_> = result.split('\t').collect();
        assert_eq!(fields[0], expected[0]);
        let compact = u32::from_str_radix(fields[2], 16).unwrap();
        assert_eq!(
            decode_compact_bits_signed(compact).to_string(),
            expected[1],
            "{}",
            fields[0]
        );
        assert_eq!(
            decode_compact_bits(compact).to_string(),
            expected[1].trim_start_matches('-'),
            "{}",
            fields[0]
        );
    }
}
