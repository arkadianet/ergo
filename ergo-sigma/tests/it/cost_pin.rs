//! Oracle: test-vectors/ergo-sigma/cost-ledger/scala-constants.json
//!
//! L1 pins compare declarations only. Chunk counts, dispatch order, and
//! type-dependent formulas remain independent L2 obligations.

use std::collections::{BTreeMap, BTreeSet};

use ergo_primitives::cost::{CostKind, JitCost};
use ergo_sigma::{cost_table as op, crypto_cost as crypto};
use serde_json::Value;

// ----- helpers -----

fn oracle() -> Value {
    serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-ledger/scala-constants.json"
    ))
    .expect("valid JVM capture")
}

fn ledger() -> BTreeMap<String, String> {
    let value: toml::Value = toml::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-ledger/ledger.toml"
    ))
    .expect("valid authoritative ledger");
    value["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["id"].as_str().unwrap().to_owned(),
                row["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn assert_kind(name: &str, rust: CostKind, scala: &Value) {
    match rust {
        CostKind::Fixed(cost) => {
            assert_eq!(scala["kind"], "Fixed", "{name}");
            assert_eq!(Some(cost.value()), scala["base"].as_u64(), "{name}");
        }
        CostKind::PerItem {
            base,
            per_chunk,
            chunk_size,
        } => {
            assert_eq!(scala["kind"], "PerItem", "{name}");
            assert_eq!(Some(base.value()), scala["base"].as_u64(), "{name}");
            assert_eq!(
                Some(per_chunk.value()),
                scala["perChunk"].as_u64(),
                "{name}"
            );
            assert_eq!(
                Some(u64::from(chunk_size)),
                scala["chunkSize"].as_u64(),
                "{name}"
            );
        }
    }
}

fn assert_exclusions<'a>(exclusions: &[(&'a str, &str)]) -> BTreeSet<&'a str> {
    let rows = ledger();
    for &(name, id) in exclusions {
        assert_eq!(
            rows.get(id).map(String::as_str),
            Some("N-A"),
            "{name}: {id}"
        );
    }
    exclusions.iter().map(|&(name, _)| name).collect()
}

fn assert_l2_obligation(rows: &BTreeMap<String, String>, id: &str) {
    // L1 maps dynamic prices to independent L2 evidence. That evidence may
    // close a row or establish a divergence without changing the L1 mapping.
    assert!(
        matches!(
            rows.get(id).map(String::as_str),
            Some("OPEN" | "CLOSED" | "DIVERGENT")
        ),
        "unmapped L2 obligation {id}"
    );
}

const TYPE_BASED_ROWS: &[(&str, &str)] = &[
    ("Upcast", "EVAL-numeric-cast"),
    ("Downcast", "EVAL-numeric-cast"),
    ("Plus", "EVAL-arith-bigint"),
    ("Minus", "EVAL-arith-bigint"),
    ("Multiply", "EVAL-arith-bigint"),
    ("Division", "EVAL-arith-bigint"),
    ("Modulo", "EVAL-arith-bigint"),
    ("Min", "EVAL-arith-bigint"),
    ("Max", "EVAL-arith-bigint"),
    ("LT", "OP-0x8F"),
    ("LE", "OP-0x90"),
    ("GT", "OP-0x91"),
    ("GE", "OP-0x92"),
];

// ----- oracle parity -----

// ledger: OP-0x72, OP-0x73, OP-0x7A, OP-0x7B, OP-0x7C, OP-0x7F, OP-0x80, OP-0x82, OP-0x85, OP-0x86, OP-0x8C, OP-0x95, OP-0x9F, OP-0xA0, OP-0xA3, OP-0xA4, OP-0xA5, OP-0xA6, OP-0xA7, OP-0xAC, OP-0xB1, OP-0xB2, OP-0xC1, OP-0xC2, OP-0xC3, OP-0xC4, OP-0xC5, OP-0xC6, OP-0xC7, OP-0xCD, OP-0xCE, OP-0xD1, OP-0xD9, OP-0xDB, OP-0xDC, OP-0xDD, OP-0xE3, OP-0xE4, OP-0xE5, OP-0xE6, OP-0xEC, OP-0xED, OP-0xEE, OP-0xEF, OP-0xF0, OP-0xF4, OP-0xFE
#[test]
fn opcode_cost_table_matches_scala_constants() {
    let json = oracle();
    let rows = ledger();
    let rust: BTreeMap<_, _> = op::static_rows().iter().copied().collect();
    assert_eq!(rust.len(), op::static_rows().len(), "duplicate opcode");
    let exclusions = assert_exclusions(&[
        ("Select1", "OP-0x87-0x8B"),
        ("Select2", "OP-0x87-0x8B"),
        ("Select3", "OP-0x87-0x8B"),
        ("Select4", "OP-0x87-0x8B"),
        ("Select5", "OP-0x87-0x8B"),
        ("UnitConstant", "OP-0x81"),
        ("NoneValue", "OP-0xDF"),
    ]);
    let mapped_rejections = BTreeMap::from([
        ("BitOr", "OP-0xF2"),
        ("BitAnd", "OP-0xF3"),
        ("BitXor", "OP-0xF5"),
        ("BitShiftRight", "OP-0xF6"),
        ("BitShiftLeft", "OP-0xF7"),
        ("BitShiftRightZeroed", "OP-0xF8"),
        ("TaggedVariable", "OP-TaggedVariable-A003"),
        ("ModQ", "OP-0xE7-0xE9"),
        ("PlusModQ", "OP-0xE7-0xE9"),
        ("MinusModQ", "OP-0xE7-0xE9"),
    ]);
    for id in mapped_rejections.values() {
        // These declarations inherit a rejecting evaluator. Independent L2
        // fixtures can close the obligation or establish a divergence.
        assert!(
            matches!(
                rows.get(*id).map(String::as_str),
                Some("OPEN" | "CLOSED" | "DIVERGENT")
            ),
            "unmapped rejection obligation {id}"
        );
    }
    let mut seen = BTreeSet::new();
    let mut unaccounted = Vec::new();
    for entry in json["opcodes"].as_array().unwrap() {
        let opcode = u8::try_from(entry["opcode"].as_u64().unwrap()).unwrap();
        assert!(seen.insert(opcode), "duplicate JVM opcode {opcode}");
        let name = entry["name"].as_str().unwrap();
        let kind = &entry["costKind"];
        match kind["kind"].as_str().unwrap() {
            "Fixed" | "PerItem" => {
                let price = if opcode == 0 {
                    Some(CostKind::Fixed(op::INLINE_CONSTANT))
                } else {
                    rust.get(&opcode).copied()
                };
                if let Some(price) = price {
                    // A price pins costKind even for mapped rejecting nodes;
                    // only the L2 fixtures establish whether eval charges it.
                    assert_kind(name, price, kind);
                } else if !exclusions.contains(name) && !mapped_rejections.contains_key(name) {
                    unaccounted.push(name);
                }
            }
            "TypeBased" => {
                let (_, id) = TYPE_BASED_ROWS
                    .iter()
                    .find(|(n, _)| *n == name)
                    .unwrap_or_else(|| panic!("unaccounted TypeBased {name}"));
                assert_l2_obligation(&rows, id);
                assert!(
                    rust.contains_key(&opcode),
                    "missing type-based default {name}"
                );
            }
            "Dynamic" | "NotSupported" => {
                // ValDef is charged through AddToEnvironment in BlockValue.
                assert!(op::opcode_cost(opcode).is_err() || opcode == 0xD6, "{name}");
                assert_l2_obligation(&rows, &format!("OP-0x{opcode:02X}"));
            }
            other => panic!("unknown JVM cost kind {other}"),
        }
    }
    assert!(rust.keys().all(|id| seen.contains(id)), "Rust-only opcode");
    assert!(
        unaccounted.is_empty(),
        "JVM declarations without a Rust assertion, mapped L2 obligation, or N-A exclusion: {unaccounted:?}"
    );
}

// ledger: METHOD-context-dataInputs, METHOD-context-headers, METHOD-context-preHeader, METHOD-context-selfBoxIndex, METHOD-context-lastBlockUtxoRootHash, METHOD-context-minerPubKey, METHOD-context-getVarFromInput, METHOD-header-props, METHOD-header-checkPow, METHOD-preheader-props, METHOD-global-groupGenerator, METHOD-global-fromBigEndianBytes, METHOD-global-encodeNbits, METHOD-global-decodeNbits, METHOD-global-some, METHOD-global-none, METHOD-box-tokens, METHOD-box-getReg, METHOD-avl-props, METHOD-avl-updateOperations, METHOD-avl-updateDigest, METHOD-coll-get, METHOD-option-map, METHOD-option-filter, METHOD-groupelement-getEncoded, METHOD-groupelement-negate, METHOD-numeric-toBytes-toBits, METHOD-numeric-bitwise, METHOD-numeric-shift, METHOD-bigint-toUnsigned, METHOD-bigint-toUnsignedMod, METHOD-ubigint-toSigned, METHOD-ubigint-bitwise, METHOD-ubigint-shift, METHOD-ubigint-modInverse, METHOD-ubigint-plusMod, METHOD-ubigint-subtractMod, METHOD-ubigint-multiplyMod, METHOD-ubigint-mod, METHOD-groupelement-expUnsigned
#[test]
fn method_cost_table_matches_scala_constants() {
    let json = oracle();
    let methods = ergo_sigma::evaluator::method_cost_rows();
    let mut rust = BTreeMap::new();
    for (ids, name, kind) in methods {
        assert!(
            rust.insert(ids, (name, kind)).is_none(),
            "duplicate method {ids:?}"
        );
    }
    // These method declarations reuse inline-opcode costs in the JVM.
    // This pins their shared prices, not MethodCall reachability or lowering.
    for (ids, opcode) in [
        ((7, 3), 0x9F),
        ((7, 4), 0xA0),
        ((8, 1), 0xD0),
        ((12, 1), 0xB1),
        ((12, 3), 0xAD),
        ((12, 4), 0xAE),
        ((12, 5), 0xB0),
        ((12, 6), 0xAF),
        ((12, 7), 0xB4),
        ((12, 8), 0xB5),
        ((12, 9), 0xB3),
        ((12, 10), 0xB2),
        ((36, 2), 0xE6),
        ((36, 3), 0xE4),
        ((36, 4), 0xE5),
        ((101, 4), 0xA4),
        ((101, 5), 0xA5),
        ((101, 6), 0xA3),
        ((101, 7), 0xA7),
        ((101, 11), 0xE3),
        ((99, 9), 0xC6),
        ((99, 10), 0xC6),
        ((99, 11), 0xC6),
        ((99, 12), 0xC6),
        ((99, 13), 0xC6),
        ((99, 14), 0xC6),
        ((99, 15), 0xC6),
        ((99, 16), 0xC6),
        ((99, 17), 0xC6),
        ((99, 18), 0xC6),
    ] {
        assert!(rust
            .insert(ids, ("opcode alias", op::opcode_cost(opcode).unwrap()))
            .is_none());
    }
    let rows = ledger();
    let exclusions = assert_exclusions(&[("8:2", "METHOD-sigmaprop-isProven-M028")]);
    let mut seen = BTreeSet::new();
    let mut unaccounted = Vec::new();
    for entry in json["methods"].as_array().unwrap() {
        let ids = (
            u8::try_from(entry["typeId"].as_u64().unwrap()).unwrap(),
            u8::try_from(entry["methodId"].as_u64().unwrap()).unwrap(),
        );
        let name = entry["name"].as_str().unwrap();
        for version in entry["versions"].as_array().unwrap() {
            assert!(
                seen.insert((ids, version.as_u64().unwrap())),
                "duplicate versioned method"
            );
        }
        let key = format!("{}:{}", ids.0, ids.1);
        if exclusions.contains(key.as_str()) {
            continue;
        }
        match entry["costKind"]["kind"].as_str().unwrap() {
            "Fixed" | "PerItem" => {
                if let Some(&(rust_name, kind)) = rust.get(&ids) {
                    if rust_name != "opcode alias" {
                        assert_eq!(rust_name, name, "{ids:?}");
                    }
                    assert_kind(&key, kind, &entry["costKind"]);
                } else {
                    unaccounted.push(key);
                }
            }
            "NotSupported" if matches!(ids, (2..=6 | 9, 1..=5)) => {
                assert_l2_obligation(&rows, "EVAL-numeric-cast");
                assert!(
                    !rust.contains_key(&ids),
                    "standalone cast descriptor {ids:?}"
                );
            }
            // No literal descriptor to pin: retain these formulas as L2 work.
            "Dynamic" => {
                let row = match ids {
                    (12, 2) => "METHOD-unclaimed-inventory",
                    (100, 9) => "METHOD-avl-contains",
                    (100, 10) => "METHOD-avl-get",
                    (100, 11) => "METHOD-avl-getMany",
                    (100, 12) => "METHOD-avl-insert",
                    (100, 13) => "METHOD-avl-update",
                    (100, 14) => "METHOD-avl-remove",
                    (100, 16) => "METHOD-avl-insertOrUpdate",
                    (106, 3) => "METHOD-global-serialize",
                    (106, 8) => "METHOD-global-powHit",
                    _ => panic!("unaccounted dynamic method {ids:?}"),
                };
                assert_l2_obligation(&rows, row);
                assert!(
                    !rust.contains_key(&ids),
                    "static price for dynamic method {ids:?}"
                );
            }
            _ => unaccounted.push(key),
        }
    }
    assert!(
        rust.keys()
            .all(|ids| seen.iter().any(|(seen_ids, _)| seen_ids == ids)),
        "Rust-only method"
    );
    assert!(
        unaccounted.is_empty(),
        "unaccounted JVM methods: {unaccounted:?}"
    );
}

// ledger: INTERP-crypto-dlog, INTERP-crypto-dht
#[test]
fn crypto_constants_match_scala() {
    let json = oracle();
    for (name, value) in [
        (
            "SigSerializer.ParseChallenge_ProveDlog",
            crypto::PARSE_CHALLENGE_DLOG,
        ),
        (
            "SigSerializer.ParseChallenge_ProveDHT",
            crypto::PARSE_CHALLENGE_DHT,
        ),
        (
            "Interpreter.ComputeCommitments_Schnorr",
            crypto::COMPUTE_COMMITMENTS_SCHNORR,
        ),
        (
            "Interpreter.ComputeCommitments_DHT",
            crypto::COMPUTE_COMMITMENTS_DHT,
        ),
        ("FiatShamirTree.ToBytes_Schnorr", crypto::TO_BYTES_SCHNORR),
        ("FiatShamirTree.ToBytes_DHT", crypto::TO_BYTES_DHT),
        (
            "FiatShamirTree.ToBytes_ProofTreeConjecture",
            crypto::TO_BYTES_CONJUNCTION,
        ),
    ] {
        assert_kind(
            name,
            CostKind::Fixed(JitCost::from_jit(value)),
            &json["constants"][name]["costKind"],
        );
    }
    for (name, value) in [
        (
            "Interpreter.ProveDlogVerificationCost",
            crypto::PARSE_CHALLENGE_DLOG
                + crypto::COMPUTE_COMMITMENTS_SCHNORR
                + crypto::TO_BYTES_SCHNORR,
        ),
        (
            "Interpreter.ProveDHTupleVerificationCost",
            crypto::PARSE_CHALLENGE_DHT + crypto::COMPUTE_COMMITMENTS_DHT + crypto::TO_BYTES_DHT,
        ),
    ] {
        assert_eq!(
            Some(value),
            json["constants"][name]["value"].as_u64(),
            "{name}"
        );
    }
    // Partial descriptor pins: chunk size and the threshold formula remain
    // mapped to INTERP-crypto-threshold in the constant inventory.
    for (name, base, per_chunk) in [
        (
            "SigSerializer.ParsePolynomial",
            crypto::PARSE_POLYNOMIAL_BASE,
            crypto::PARSE_POLYNOMIAL_PER_CHUNK,
        ),
        (
            "SigSerializer.EvaluatePolynomial",
            crypto::EVALUATE_POLYNOMIAL_BASE,
            crypto::EVALUATE_POLYNOMIAL_PER_CHUNK,
        ),
    ] {
        let kind = &json["constants"][name]["costKind"];
        assert_eq!(kind["kind"], "PerItem");
        assert_eq!(Some(base), kind["base"].as_u64(), "{name}");
        assert_eq!(Some(per_chunk), kind["perChunk"].as_u64(), "{name}");
    }
}

// ledger: EVAL-eq-prim, EVAL-eq-matchtype, EVAL-eq-groupelement, EVAL-eq-bigint, EVAL-eq-avltree, EVAL-eq-box, EVAL-eq-preheader, EVAL-eq-header
#[test]
fn data_value_comparer_constants_match_scala() {
    let json = oracle();
    for (name, value) in [
        ("MatchType", op::MATCH_TYPE),
        ("EQ_Prim", op::EQ_PRIM),
        ("EQ_Tuple", op::EQ_TUPLE),
        ("EQ_GroupElement", op::EQ_GROUP_ELEMENT),
        ("EQ_BigInt", op::EQ_BIGINT),
        ("EQ_AvlTree", op::EQ_AVL_TREE),
        ("EQ_Box", op::EQ_BOX),
        ("EQ_Option", op::EQ_OPTION),
        ("EQ_PreHeader", op::EQ_PRE_HEADER),
        ("EQ_Header", op::EQ_HEADER),
    ] {
        let name = format!("DataValueComparer.{name}");
        assert_kind(
            &name,
            CostKind::Fixed(JitCost::from_jit(value)),
            &json["constants"][&name]["costKind"],
        );
    }
    assert_eq!(
        Some(op::MATCH_TYPE),
        json["constants"]["DataValueComparer.CostOf_MatchType"]["value"].as_u64()
    );
    for (name, kind) in [
        ("EQ_COA_Boolean", op::EQ_COA_BOOLEAN),
        ("EQ_COA_Byte", op::EQ_COA_BYTE),
        ("EQ_COA_Short", op::EQ_COA_SHORT),
        ("EQ_COA_Int", op::EQ_COA_INT),
        ("EQ_COA_Long", op::EQ_COA_LONG),
        ("EQ_COA_BigInt", op::EQ_COA_BIG_INT),
        ("EQ_COA_GroupElement", op::EQ_COA_GROUP_ELEMENT),
        ("EQ_COA_AvlTree", op::EQ_COA_AVL_TREE),
        ("EQ_COA_Box", op::EQ_COA_BOX),
        ("EQ_COA_PreHeader", op::EQ_COA_PRE_HEADER),
        ("EQ_COA_Header", op::EQ_COA_HEADER),
        ("EQ_Coll", op::EQ_COLL),
    ] {
        let name = format!("DataValueComparer.{name}");
        assert_kind(&name, kind, &json["constants"][&name]["costKind"]);
    }
}

// ledger: INTERP-init-cost, INTERP-eval-sigmaprop-constant
#[test]
fn interpreter_constants_match_scala() {
    let json = oracle();
    for (name, value) in [
        (
            "Interpreter.interpreterInitCost",
            ergo_validation::INTERPRETER_INIT_COST,
        ),
        (
            "ErgoInterpreter.interpreterInitCost",
            ergo_validation::INTERPRETER_INIT_COST,
        ),
        (
            "Constants.StorageContractCost",
            ergo_validation::STORAGE_CONTRACT_COST,
        ),
    ] {
        assert_eq!(
            Some(value),
            json["constants"][name]["value"].as_u64(),
            "{name}"
        );
    }

    assert_kind(
        "Eval_SigmaPropConstant",
        CostKind::Fixed(ergo_sigma::reduce::EVAL_SIGMA_PROP_CONSTANT),
        &json["constants"]["Interpreter.Eval_SigmaPropConstant"]["costKind"],
    );
    assert_eq!(
        Some(ergo_sigma::reduce::COST_PER_TREE_BYTE),
        json["constants"]["Interpreter.CostPerTreeByte"]["value"].as_u64()
    );
    assert_eq!(
        Some(JitCost::from_block_cost(1).unwrap().value()),
        json["constants"]["JitCost.Scale"]["value"].as_u64()
    );
    let max = json["constants"]["JitCost.MaxValue"]["value"]
        .as_u64()
        .unwrap();
    assert!(JitCost::try_from_jit(max).is_ok());
    assert!(JitCost::try_from_jit(max + 1).is_err());
    let max_block = json["constants"]["JitCost.MaxBlockCost"]["value"]
        .as_u64()
        .unwrap();
    assert!(JitCost::from_block_cost(max_block).is_ok());
    assert!(JitCost::from_block_cost(max_block + 1).is_err());
}

#[test]
fn constant_inventory_unaccounted_entries_fail() {
    let json = oracle();
    // These keys are asserted by the three constant-pin tests above.
    let asserted = BTreeSet::from([
        "Interpreter.interpreterInitCost",
        "ErgoInterpreter.interpreterInitCost",
        "Constants.StorageContractCost",
        "DataValueComparer.CostOf_MatchType",
        "DataValueComparer.EQ_AvlTree",
        "DataValueComparer.EQ_BigInt",
        "DataValueComparer.EQ_Box",
        "DataValueComparer.EQ_COA_AvlTree",
        "DataValueComparer.EQ_COA_BigInt",
        "DataValueComparer.EQ_COA_Boolean",
        "DataValueComparer.EQ_COA_Box",
        "DataValueComparer.EQ_COA_Byte",
        "DataValueComparer.EQ_COA_GroupElement",
        "DataValueComparer.EQ_COA_Header",
        "DataValueComparer.EQ_COA_Int",
        "DataValueComparer.EQ_COA_Long",
        "DataValueComparer.EQ_COA_PreHeader",
        "DataValueComparer.EQ_COA_Short",
        "DataValueComparer.EQ_Coll",
        "DataValueComparer.EQ_GroupElement",
        "DataValueComparer.EQ_Header",
        "DataValueComparer.EQ_Option",
        "DataValueComparer.EQ_PreHeader",
        "DataValueComparer.EQ_Prim",
        "DataValueComparer.EQ_Tuple",
        "DataValueComparer.MatchType",
        "FiatShamirTree.ToBytes_DHT",
        "FiatShamirTree.ToBytes_ProofTreeConjecture",
        "FiatShamirTree.ToBytes_Schnorr",
        "Interpreter.ComputeCommitments_DHT",
        "Interpreter.ComputeCommitments_Schnorr",
        "Interpreter.CostPerTreeByte",
        "Interpreter.Eval_SigmaPropConstant",
        "Interpreter.ProveDHTupleVerificationCost",
        "Interpreter.ProveDlogVerificationCost",
        "JitCost.MaxBlockCost",
        "JitCost.MaxValue",
        "JitCost.Scale",
        "SigSerializer.ParseChallenge_ProveDHT",
        "SigSerializer.ParseChallenge_ProveDlog",
    ]);
    let exclusions = assert_exclusions(&[
        ("JitCost.MinValue", "INTERP-jitcost-minvalue"),
        ("CErgoTreeEvaluator.DataBlockSize", "EVAL-datablocksize"),
    ]);
    let mapped_open = BTreeMap::from([
        (
            "Interpreter.CostPerByteDeserialized",
            "INTERP-embedded-script-deser",
        ),
        ("SigSerializer.ParsePolynomial", "INTERP-crypto-threshold"),
        (
            "SigSerializer.EvaluatePolynomial",
            "INTERP-crypto-threshold",
        ),
    ]);
    let rows = ledger();
    for id in mapped_open.values() {
        assert_l2_obligation(&rows, id);
    }
    let mapped_open: BTreeSet<_> = mapped_open.keys().copied().collect();
    let actual: BTreeSet<_> = json["constants"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        asserted.is_subset(&actual),
        "removed JVM constant still in Rust inventory"
    );
    assert!(
        asserted.is_disjoint(&exclusions)
            && asserted.is_disjoint(&mapped_open)
            && exclusions.is_disjoint(&mapped_open),
        "overlapping accounting categories"
    );
    let accounted: BTreeSet<_> = asserted
        .iter()
        .chain(&exclusions)
        .chain(&mapped_open)
        .copied()
        .collect();
    assert!(
        accounted.is_subset(&actual),
        "removed JVM entry still accounted for"
    );
    let unaccounted: Vec<_> = actual.difference(&accounted).collect();
    assert!(
        unaccounted.is_empty(),
        "JVM constants without a Rust assertion, mapped L2 obligation, or N-A exclusion: {unaccounted:?}"
    );
}
