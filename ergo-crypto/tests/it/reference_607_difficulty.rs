use ergo_crypto::{difficulty::DifficultyParams, pow::verify_header_difficulty};
use ergo_primitives::reader::VlqReader;
use ergo_ser::{difficulty::decode_compact_bits_signed, header::read_header};

#[test]
fn compact_difficulty_values_match_reference() {
    let headers: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/difficulty/headers.json"
    ))
    .unwrap();
    let load = |height| {
        let h = headers.iter().find(|h| h["height"] == height).unwrap();
        read_header(&mut VlqReader::new(
            &hex::decode(h["bytes"].as_str().unwrap()).unwrap(),
        ))
        .unwrap()
    };
    let mut parent = load(100);
    let mut child = load(101);
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
        parent.n_bits = u32::from_str_radix(fields[1], 16).unwrap();
        child.n_bits = u32::from_str_radix(fields[2], 16).unwrap();
        assert_eq!(
            decode_compact_bits_signed(child.n_bits).to_string(),
            expected[1],
            "{}",
            fields[0]
        );
        assert_eq!(
            verify_header_difficulty(
                &child,
                std::slice::from_ref(&parent),
                &DifficultyParams::mainnet()
            )
            .is_ok(),
            expected[2].parse::<bool>().unwrap(),
            "{}",
            fields[0]
        );
    }
}
