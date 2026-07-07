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
//! - oracle `OK <hex>`, ≤4 params → our `ContractTemplate::serialize()` MUST be
//!   byte-identical to `<hex>` (the M7 deliverable);
//! - oracle `OK <hex>`, ≥5 params → our `compile_contract` MUST REJECT with
//!   [`ergo_compiler::ContractError::TooManyParamsForOrdering`] — the
//!   deliberately-deferred JVM-HashMap placeholder-order case
//!   (`TODO(M7-hashmap-order)`): flagged, never mis-emitted;
//! - oracle `REJECT …` → our `compile_contract` MUST also reject (class advisory).

use ergo_compiler::{compile_contract, ContractError, NetworkPrefix};
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
    let mut deferred = 0usize;
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
                    } else {
                        failures.push(format!(
                            "[{name}] byte mismatch\n     ours: {ours}\n   oracle: {hex}"
                        ));
                    }
                }
                Err(ContractError::TooManyParamsForOrdering { count, .. }) if count > 4 => {
                    // Deferred ≥5-param case: oracle accepts, we honestly flag.
                    deferred += 1;
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
    // Positive coverage floor: the byte-exact class is the milestone deliverable,
    // and both the deferral and reject paths must actually be exercised.
    assert!(
        byte_exact >= 8,
        "expected >=8 byte-exact vectors, got {byte_exact}"
    );
    assert!(deferred >= 1, "the >=5-param deferral must be exercised");
    assert!(rejects >= 1, "a reject vector must be exercised");
}
