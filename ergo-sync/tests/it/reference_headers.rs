//! NodeHeaderOracle's parsed identifiers and PoW verdicts on ergo-core 6.0.7.
use ergo_sync::header_proc::pre_validate_header;

#[test]
fn reference_header_receive() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/reference-6.0.7/serialization");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("node-headers.json")).unwrap())
            .unwrap();
    let oracle = std::fs::read_to_string(root.join("node-headers.jvm.tsv")).unwrap();
    let rows: std::collections::BTreeMap<_, _> = oracle
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            (fields[0], fields)
        })
        .collect();
    for v in fixture["entries"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let bytes = hex::decode(v["bytes_hex"].as_str().unwrap()).unwrap();
        let expected = &rows[name];
        let actual = pre_validate_header(&bytes);
        assert_eq!(
            actual.is_ok(),
            expected[1] == "true" && expected[5] == "true",
            "{name}"
        );
        if let Ok(header) = actual {
            assert_eq!(hex::encode(header.header_id()), expected[3], "{name}");
            let (canonical, _) = ergo_ser::header::serialize_header(header.header()).unwrap();
            assert_eq!(hex::encode(&canonical), expected[4], "{name}");
            let canonical_pre = pre_validate_header(&canonical).unwrap();
            assert_eq!(header.header_id(), canonical_pre.header_id(), "{name}");
        }
    }
}
