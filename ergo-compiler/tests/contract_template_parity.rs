//! M7 contract-template byte-exact parity gate.
//!
//! Compiles each `test-vectors/ergoscript/contract/sources/*.es` source through
//! [`ergo_compiler::compile_contract`] and compares the CANONICAL
//! `ContractTemplate` wire bytes against the committed JVM oracle capture
//! (`test-vectors/ergoscript/contract/contract_seed.json`,
//! `TyperOracle.scala` `ct` verb, sigma-state 6.0.2 / Scala 2.12.21,
//! `ORACLE_TREE_VERSION=3`, `ORACLE_NETWORK=testnet`).
//!
//! Gate:
//! - oracle `OK <hex>` → our `ContractTemplate::serialize()` MUST be
//!   byte-identical to `<hex>` (the M7 deliverable) — for ≤4 params (declaration
//!   order) AND ≥5 params (Scala 2.12 `HashTrieMap` placeholder-iteration order);
//! - oracle `REJECT …` → our `compile_contract` MUST also reject (class advisory).

use ergo_compiler::{compile_contract, NetworkPrefix};
use serde_json::Value;

const SEED: &str = include_str!("../../test-vectors/ergoscript/contract/contract_seed.json");

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn contract_template_seed_byte_parity() {
    let seed: Value = serde_json::from_str(SEED).expect("seed json parses");
    let tree_version = seed["tree_version"].as_u64().expect("tree_version") as u8;
    let vectors = seed["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "seed must carry vectors");

    let mut byte_exact = 0usize;
    let mut byte_exact_ge5 = 0usize;
    let mut rejects = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let source = v["source"].as_str().expect("source");
        let oracle = v["oracle"].as_str().expect("oracle");
        let result = compile_contract(source, tree_version, NetworkPrefix::Testnet);

        if let Some(hex) = oracle.strip_prefix("OK ") {
            match result {
                Ok(ct) => {
                    let ours = to_hex(&ct.serialize());
                    if ours == hex {
                        byte_exact += 1;
                        if ct.parameters.len() > 4 {
                            byte_exact_ge5 += 1;
                        }
                    } else {
                        failures.push(format!(
                            "[{name}] byte mismatch\n     ours: {ours}\n   oracle: {hex}"
                        ));
                    }
                }
                Err(e) => failures.push(format!(
                    "[{name}] oracle ACCEPT but compile_contract rejected: {e:?}"
                )),
            }
        } else if oracle.starts_with("REJECT") {
            match result {
                Err(_) => rejects += 1,
                Ok(_) => failures.push(format!(
                    "[{name}] oracle REJECT ({oracle}) but compile_contract accepted"
                )),
            }
        } else {
            failures.push(format!("[{name}] unrecognised oracle reply: {oracle}"));
        }
    }

    assert!(
        failures.is_empty(),
        "contract-template parity failures:\n{}",
        failures.join("\n")
    );
    // Positive coverage floor: the byte-exact class is the milestone deliverable;
    // the ≥5-param HashTrieMap-order path and the reject path must be exercised.
    assert!(
        byte_exact >= 8,
        "expected >=8 byte-exact vectors, got {byte_exact}"
    );
    assert!(
        byte_exact_ge5 >= 3,
        "the ≥5-param HashTrieMap-order path must be byte-exact (got {byte_exact_ge5})"
    );
    assert!(rejects >= 1, "a reject vector must be exercised");
}

// ----- template application (applyTemplate parity) -----

/// `apply_seed.json` vectors: the JVM oracle's `ap` verb applied real values
/// (or defaults) to each template and serialized the resulting ErgoTree.
const APPLY_SEED: &str = include_str!("../../test-vectors/ergoscript/contract/apply_seed.json");

/// Parse the oracle's `name=Type:literal,…` arg spec into typed constants.
fn parse_apply_args(
    spec: &str,
) -> std::collections::BTreeMap<
    String,
    (
        ergo_ser::sigma_type::SigmaType,
        ergo_ser::sigma_value::SigmaValue,
    ),
> {
    use ergo_ser::sigma_type::SigmaType as T;
    use ergo_ser::sigma_value::SigmaValue as V;
    let mut out = std::collections::BTreeMap::new();
    for kv in spec.split(',').filter(|s| !s.is_empty()) {
        let (name, tv) = kv.split_once('=').expect("name=Type:lit");
        let (tpe, lit) = tv.split_once(':').expect("Type:lit");
        let pair = match tpe {
            "Int" => (T::SInt, V::Int(lit.parse().unwrap())),
            "Long" => (T::SLong, V::Long(lit.parse().unwrap())),
            "Boolean" => (T::SBoolean, V::Boolean(lit.parse().unwrap())),
            "Short" => (T::SShort, V::Short(lit.parse().unwrap())),
            "Byte" => (T::SByte, V::Byte(lit.parse().unwrap())),
            other => panic!("unsupported arg type {other}"),
        };
        out.insert(name.to_string(), pair);
    }
    out
}

#[test]
fn contract_template_apply_seed_byte_parity() {
    let seed: Value = serde_json::from_str(APPLY_SEED).expect("apply seed parses");
    let vectors = seed["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 10, "apply seed must carry vectors");
    let mut byte_exact = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let source = v["source"].as_str().unwrap();
        let tree_version = v["tree_version"].as_u64().unwrap() as u8;
        let args = parse_apply_args(v["args"].as_str().unwrap());
        let oracle = v["oracle"].as_str().unwrap();
        let ct = compile_contract(source, 3, NetworkPrefix::Testnet).expect("template compiles");
        let ours = ct.apply(tree_version, &args);
        match (oracle.strip_prefix("OK "), ours) {
            (Some(hex), Ok(tree)) => {
                let mut w = ergo_primitives::writer::VlqWriter::new();
                ergo_ser::ergo_tree::write_ergo_tree(&mut w, &tree).unwrap();
                let got = to_hex(&w.result());
                if got == hex {
                    byte_exact += 1;
                } else {
                    failures.push(format!(
                        "[{name}] byte mismatch\n     ours: {got}\n   oracle: {hex}"
                    ));
                }
            }
            (Some(_), Err(e)) => {
                failures.push(format!("[{name}] oracle OK but apply rejected: {e}"))
            }
            (None, Ok(_)) => failures.push(format!(
                "[{name}] oracle REJECT ({oracle}) but apply accepted"
            )),
            (None, Err(_)) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    eprintln!("apply parity: {byte_exact} byte-exact of {}", vectors.len());
}
