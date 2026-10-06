//! Scan available mainnet fixtures through the new readers, including retained
//! errors in nested scripts. This is a fixture audit, not a byte-pattern search.
use ergo_primitives::reader::VlqReader;
use ergo_ser::{ergo_box, ergo_tree, opcode, sigma_value, transaction};
use serde_json::Value;
use std::path::Path;

#[derive(Default)]
struct Audit {
    transactions: usize,
    trees: usize,
    values: usize,
}

fn inspect_tree(tree: &ergo_tree::ErgoTree) {
    for (_, value) in &tree.constants {
        inspect_value(value);
    }
    for (_, expr) in opcode::preorder(&tree.body) {
        match expr {
            opcode::Expr::Unparsed(u) => assert!(
                !matches!(u.validation_error, Some((1020, _))),
                "mainnet zero-width tree"
            ),
            opcode::Expr::Const { val, .. } => inspect_value(val),
            _ => (),
        }
    }
}

fn inspect_value(value: &sigma_value::SigmaValue) {
    use sigma_value::{CollValue, SigmaValue};
    match value {
        SigmaValue::OpaqueBoxBytes(bytes) | SigmaValue::CanonicalBoxBytes { bytes, .. } => {
            let b = ergo_box::read_ergo_box(
                &mut VlqReader::new(bytes).with_activated_script_version(3),
            )
            .unwrap();
            inspect_tree(b.candidate.ergo_tree());
            for r in &b.candidate.additional_registers().registers {
                inspect_value(&r.value);
            }
        }
        SigmaValue::Tuple(items)
        | SigmaValue::Coll(CollValue::Values(items))
        | SigmaValue::ConcreteCollection { items, .. } => {
            for x in items {
                inspect_value(x);
            }
        }
        SigmaValue::Opt(Some(x)) => inspect_value(x),
        SigmaValue::Unevaluated(expr) => {
            for (_, node) in opcode::preorder(expr) {
                if let opcode::Expr::Const { val, .. } = node {
                    inspect_value(val);
                }
            }
        }
        _ => (),
    }
}

fn inspect_json(value: &Value, path: &Path, audit: &mut Audit) {
    match value {
        Value::Array(xs) => {
            for x in xs {
                inspect_json(x, path, audit);
            }
        }
        Value::Object(obj) => {
            if obj.contains_key("bytesToSign") {
                let raw = hex::decode(obj["bytes"].as_str().unwrap()).unwrap();
                let tx = transaction::read_transaction(
                    &mut VlqReader::new(&raw).with_activated_script_version(3),
                )
                .unwrap_or_else(|e| panic!("{} transaction: {e:?}", path.display()));
                for output in &tx.output_candidates {
                    inspect_tree(output.ergo_tree());
                    for r in &output.additional_registers().registers {
                        inspect_value(&r.value);
                    }
                }
                for input in &tx.inputs {
                    for (_, v) in input.spending_proof.extension().values.values() {
                        inspect_value(v);
                    }
                }
                audit.transactions += 1;
            }
            let tree_hex = obj.get("ergoTree").and_then(Value::as_str).or_else(|| {
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("ergotrees_")
                    .then(|| obj.get("bytes").and_then(Value::as_str))
                    .flatten()
            });
            if let Some(encoded) = tree_hex {
                let raw = hex::decode(encoded).unwrap();
                let tree = ergo_tree::read_ergo_tree(
                    &mut VlqReader::new(&raw).with_activated_script_version(3),
                )
                .unwrap_or_else(|e| panic!("{} tree: {e:?}", path.display()));
                inspect_tree(&tree);
                audit.trees += 1;
            }
            for key in ["additionalRegisters", "extension"] {
                if let Some(map) = obj.get(key).and_then(Value::as_object) {
                    for (name, x) in map {
                        if key == "extension" && name.parse::<u8>().is_err() {
                            continue;
                        }
                        if let Some(encoded) = x
                            .as_str()
                            .or_else(|| x.get("serializedValue").and_then(Value::as_str))
                        {
                            let raw = hex::decode(encoded).unwrap();
                            let (_, v) = sigma_value::read_constant(
                                &mut VlqReader::new(&raw).with_activated_script_version(3),
                            )
                            .unwrap_or_else(|e| panic!("{} {key}/{name}: {e:?}", path.display()));
                            inspect_value(&v);
                            audit.values += 1;
                        }
                    }
                }
            }
            for x in obj.values() {
                inspect_json(x, path, audit);
            }
        }
        _ => (),
    }
}

fn scan(dir: &Path, audit: &mut Audit) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scan(&path, audit);
        } else if path.extension().is_some_and(|x| x == "json") {
            let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            inspect_json(&value, &path, audit);
        }
    }
}

#[test]
fn mainnet_fixtures_contain_no_607_type_depth_or_zero_width_rejections() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet");
    let mut audit = Audit::default();
    scan(&root, &mut audit);
    assert!(audit.transactions >= 1000 && audit.trees >= 100 && audit.values > 0);
    eprintln!("6.0.7 mainnet audit: {} transaction records, {} tree records, {} register/extension values; no depth or zero-width rejection", audit.transactions, audit.trees, audit.values);
}
