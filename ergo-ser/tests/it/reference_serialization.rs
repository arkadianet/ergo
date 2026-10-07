//! Reader and writer outcomes recorded by SerializationOracle on sigma-state 6.0.7.
use ergo_primitives::{reader::VlqReader, writer::VlqWriter};
use ergo_ser::{
    ergo_box, ergo_tree, input, opcode, register, sigma_type, sigma_value, transaction,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    mode: String,
    bytes_hex: String,
    #[serde(default = "version")]
    version: u8,
    #[serde(default = "version")]
    activated: u8,
}

fn version() -> u8 {
    3
}

#[test]
fn reference_transaction_identifiers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/reference-6.0.7/serialization");
    for file in ["relations", "transaction-encodings"] {
        let fixture: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join(format!("{file}.json"))).unwrap(),
        )
        .unwrap();
        let oracle = std::fs::read_to_string(root.join(format!("{file}.jvm-ids.tsv"))).unwrap();
        let rows: std::collections::BTreeMap<_, _> = oracle
            .lines()
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                (fields[0], fields)
            })
            .collect();
        let entries = fixture["entries"].as_array().unwrap();
        assert_eq!(rows.len(), entries.len());
        for v in entries {
            let name = v["name"].as_str().unwrap();
            let bytes = hex::decode(v["tx_bytes_hex"].as_str().unwrap()).unwrap();
            let expected = &rows[name];
            let mut r = VlqReader::new(&bytes).with_activated_script_version(3);
            let result = transaction::read_transaction(&mut r).and_then(|tx| {
                transaction::bytes_to_sign(&tx)
                    .map(|message| (tx, message))
                    .map_err(|e| ergo_primitives::reader::ReadError::InvalidData(e.to_string()))
            });
            if expected[1] == "EXC" {
                assert!(result.is_err(), "{name}");
                continue;
            }
            let (tx, message) = result.unwrap();
            let fields: std::collections::BTreeMap<_, _> = expected[2]
                .split_whitespace()
                .map(|field| field.split_once('=').unwrap())
                .collect();
            let id = transaction::transaction_id(&tx).unwrap();
            assert_eq!(hex::encode(id.as_bytes()), fields["txid"], "{name}");
            assert_eq!(hex::encode(message), fields["msg"], "{name}");
            for (i, candidate) in tx.output_candidates.into_iter().enumerate() {
                assert_eq!(
                    hex::encode(candidate.ergo_tree_bytes()),
                    fields[format!("out{i}.proposition").as_str()],
                    "{name}"
                );
                let b = ergo_box::ErgoBox::new(candidate, id, i as u16);
                assert_eq!(
                    hex::encode(b.box_id().unwrap().as_bytes()),
                    fields[format!("out{i}.id").as_str()],
                    "{name}"
                );
                let mut w = VlqWriter::new();
                ergo_box::write_ergo_box(&mut w, &b).unwrap();
                assert_eq!(
                    hex::encode(w.result()),
                    fields[format!("out{i}.bytes").as_str()],
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn reference_receiver_types() {
    #[derive(Deserialize)]
    struct Fixture {
        entries: Vec<Vector>,
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/reference-6.0.7/serialization");
    let mut count = 0;
    for file in [
        "readers-receivers",
        "readers-avl",
        "readers-nested-box",
        "readers-relations",
        "readers-encodings",
    ] {
        let path = root.join(format!("{file}.json"));
        let fixture: Fixture =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let oracle = std::fs::read_to_string(path.with_extension("jvm.tsv")).unwrap();
        let rows: std::collections::BTreeMap<_, _> = oracle
            .lines()
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                (fields[0], fields)
            })
            .collect();
        assert_eq!(rows.len(), fixture.entries.len());
        for v in fixture.entries {
            let expected = &rows[v.name.as_str()];
            let bytes = hex::decode(&v.bytes_hex).unwrap();
            let mut r = VlqReader::new(&bytes).with_activated_script_version(v.activated);
            r.set_ergo_tree_version(Some(v.version));
            let mut w = VlqWriter::new();
            let mut wrapped = None;
            let mut identity = None;
            let result = (|| -> Result<(), String> {
                match v.mode.as_str() {
                    "tree" => {
                        let t = ergo_tree::read_ergo_tree(&mut r).map_err(|e| e.to_string())?;
                        ergo_tree::check_sigma_prop_root(&t).map_err(|e| e.to_string())?;
                        if let opcode::Expr::Unparsed(u) = &t.body {
                            wrapped = u.validation_error.as_ref().map(|(id, _)| *id);
                        }
                        ergo_tree::write_ergo_tree(&mut w, &t).map_err(|e| e.to_string())?;
                    }
                    "expression" => {
                        opcode::parse_body(&mut r, v.version).map_err(|e| e.to_string())?;
                    }
                    "constant-read" => {
                        sigma_value::read_constant(&mut r).map_err(|e| e.to_string())?;
                    }
                    "constant" => {
                        let (t, x) =
                            sigma_value::read_constant(&mut r).map_err(|e| e.to_string())?;
                        if let sigma_value::SigmaValue::Header(_, id) = &x {
                            identity = Some(hex::encode(id));
                        }
                        sigma_value::write_constant_versioned(&mut w, &t, &x, v.version)
                            .map_err(|e| e.to_string())?;
                    }
                    "registers" => {
                        let regs = register::read_registers(&mut r).map_err(|e| e.to_string())?;
                        register::write_registers_versioned(&mut w, &regs, v.activated)
                            .map_err(|e| e.to_string())?;
                    }
                    "context_extension" => {
                        let ext =
                            input::read_context_extension(&mut r).map_err(|e| e.to_string())?;
                        input::write_context_extension(&mut w, &ext).map_err(|e| e.to_string())?;
                    }
                    "box-candidate-read" => {
                        ergo_box::read_ergo_box_candidate(&mut r).map_err(|e| e.to_string())?;
                    }
                    "box-read" => {
                        let b = ergo_box::read_ergo_box(&mut r).map_err(|e| e.to_string())?;
                        assert_eq!(b.bytes().unwrap(), bytes[..r.position()], "{}", v.name);
                        identity = Some(hex::encode(
                            b.box_id().map_err(|e| e.to_string())?.as_bytes(),
                        ));
                    }
                    "box-candidate" => {
                        let b =
                            ergo_box::read_ergo_box_candidate(&mut r).map_err(|e| e.to_string())?;
                        ergo_box::write_ergo_box_candidate(&mut w, &b)
                            .map_err(|e| e.to_string())?;
                    }
                    "box" => {
                        let b = ergo_box::read_ergo_box(&mut r).map_err(|e| e.to_string())?;
                        assert_eq!(b.bytes().unwrap(), bytes[..r.position()], "{}", v.name);
                        identity = Some(hex::encode(
                            b.box_id().map_err(|e| e.to_string())?.as_bytes(),
                        ));
                        ergo_box::write_ergo_box(&mut w, &b).map_err(|e| e.to_string())?;
                    }
                    "transaction" => {
                        let tx =
                            transaction::read_transaction(&mut r).map_err(|e| e.to_string())?;
                        identity = Some(hex::encode(
                            transaction::transaction_id(&tx)
                                .map_err(|e| e.to_string())?
                                .as_bytes(),
                        ));
                        transaction::write_transaction(&mut w, &tx).map_err(|e| e.to_string())?;
                    }
                    "type" => {
                        let t = sigma_type::read_type(&mut r).map_err(|e| e.to_string())?;
                        sigma_type::write_type(&mut w, &t).map_err(|e| e.to_string())?;
                    }
                    other => panic!("unknown reader mode {other}"),
                }
                Ok(())
            })();
            match expected[1] {
                "ACCEPT" => {
                    assert!(result.is_ok(), "{}: {result:?}", v.name);
                    assert_eq!(wrapped, None, "{}", v.name);
                    assert_eq!(
                        r.position(),
                        expected[2].parse::<usize>().unwrap(),
                        "{}",
                        v.name
                    );
                    if expected[4] != "-" {
                        assert_eq!(hex::encode(w.result()), expected[4], "{}", v.name);
                    }
                    if let Some(id) = identity {
                        assert!(expected[5].contains(&id), "{}: {id}", v.name);
                    }
                }
                "WRAPPED" => {
                    assert!(result.is_ok(), "{}: {result:?}", v.name);
                    assert_eq!(wrapped, Some(expected[3].parse().unwrap()), "{}", v.name);
                }
                _ => assert!(
                    result.is_err(),
                    "{}: expected {}, got {result:?}",
                    v.name,
                    expected[1]
                ),
            }
            count += 1;
        }
    }
    assert!(count > 0);
}
