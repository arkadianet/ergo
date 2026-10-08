use ergo_primitives::reader::VlqReader;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{read_value, SigmaValue};
use ergo_sigma::verify::verify_sigma_proof;
use std::collections::BTreeMap;

#[test]
fn response_and_challenge_bytes_match_reference() {
    let verdicts: BTreeMap<_, _> =
        include_str!("../../../test-vectors/reference-6.0.7/sigma-proofs/cases.jvm.tsv")
            .lines()
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                (fields[0], fields[1].parse::<bool>().unwrap())
            })
            .collect();
    let mut count = 0;
    for line in include_str!("../../../test-vectors/reference-6.0.7/sigma-proofs/cases.tsv").lines()
    {
        let fields: Vec<_> = line.split('\t').collect();
        let proposition = hex::decode(fields[1]).unwrap();
        let SigmaValue::SigmaProp(proposition) =
            read_value(&mut VlqReader::new(&proposition), &SigmaType::SSigmaProp).unwrap()
        else {
            panic!("expected sigma proposition");
        };
        let result = verify_sigma_proof(
            &proposition,
            &hex::decode(fields[2]).unwrap(),
            &hex::decode(fields[3]).unwrap(),
        )
        .unwrap_or(false);
        assert_eq!(result, verdicts[fields[0]], "{}", fields[0]);
        count += 1;
    }
    assert_eq!(count, verdicts.len());
}
