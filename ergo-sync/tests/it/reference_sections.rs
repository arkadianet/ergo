//! BlockTransactions identifiers recorded by ergo-core 6.0.7.
#[test]
fn reference_transaction_section_identifiers() {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::block_transactions::{
        read_block_transactions, write_block_transactions_with_version,
    };
    use ergo_sync::coordinator::verify_section_modifier_id;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/reference-6.0.7/serialization");
    for file in ["relations", "transaction-encodings"] {
        let oracle = std::fs::read_to_string(root.join(format!("{file}.jvm-ids.tsv"))).unwrap();
        for line in oracle.lines() {
            let row: Vec<_> = line.split('\t').collect();
            if row[1] == "EXC" {
                continue;
            }
            let fields: std::collections::BTreeMap<_, _> = row[2]
                .split_whitespace()
                .map(|field| field.split_once('=').unwrap())
                .collect();
            for version in [1, 4] {
                let bytes =
                    hex::decode(fields[format!("section{version}.bytes").as_str()]).unwrap();
                let id: [u8; 32] = hex::decode(fields[format!("section{version}.id").as_str()])
                    .unwrap()
                    .try_into()
                    .unwrap();
                verify_section_modifier_id(102, &id, &bytes).unwrap();
                assert!(verify_section_modifier_id(102, &[0; 32], &bytes).is_err());
                let bt = read_block_transactions(&mut VlqReader::new(&bytes)).unwrap();
                let mut w = VlqWriter::new();
                write_block_transactions_with_version(&mut w, &bt, version).unwrap();
                assert_eq!(
                    hex::encode(w.result()),
                    fields[format!("section{version}.canonical").as_str()],
                    "{}",
                    row[0]
                );
            }
        }
    }
}
