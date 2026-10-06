//! Verbatim SANTA transaction fixtures checked against an independent JVM oracle.
//! Uses vixen's production parse/validate path (SANTA local/tx-tier).
//! Decode failures count as rejects here; consensus verdict and accept cost are
//! pinned, while the runner contract separately records decode failures as coal.
//! Oracle recipe: scripts/santa_tx_oracle/SantaTxOracle.scala (6.0.6).

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::read_header;
use ergo_ser::transaction::read_transaction;
use ergo_validation::tx::{
    validate_transaction_parsed_with_group_elements, TxValidationCtx, TxValidationRules,
};
use ergo_validation::{CostAccumulator, JitCost, ProtocolParams, TransactionContext};
use serde_json::Value as J;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn bytes(j: &J, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(j.as_str().ok_or_else(|| format!("{field}: missing hex"))?)
        .map_err(|e| format!("{field}: {e:?}"))
}
fn fixed<const N: usize>(j: &J, field: &str) -> Result<[u8; N], String> {
    bytes(j, field)?
        .try_into()
        .map_err(|_| format!("{field}: expected {N} bytes"))
}
fn number(j: &J, field: &str) -> Result<u64, String> {
    j.as_u64()
        .ok_or_else(|| format!("{field}: missing unsigned integer"))
}
fn boxes(j: &J, field: &str) -> Result<Vec<ErgoBox>, String> {
    j.as_array()
        .ok_or_else(|| format!("{field}: missing array"))?
        .iter()
        .map(|v| {
            let b = bytes(v, field)?;
            // Boxes read from UTXO: no activated-version context, no canonicalization.
            read_ergo_box(&mut VlqReader::new(&b)).map_err(|e| format!("{field}: {e}"))
        })
        .collect()
}

// A node fix must remove the corresponding independently confirmed exception.
const KNOWN_DIVERGENCES: &[(&str, &str)] = &[
    (
        "any/authored/tree-version-block-version-edges.json",
        "bv0-tree-v0-reject#7",
    ),
    (
        "any/authored/tree-version-block-version-edges.json",
        "bv200-tree-v0-reject#10",
    ),
    (
        "v6/authored/conjecture-child-count-wrap.json",
        "cand-child-count-wrap-fiat-shamir#0",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "l1-decode-cast-swallowed-live-reject#1",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "r1-self-proposition-decoded-accept#16",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "r1-unsized-tree-decode-fails-reject#19",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "root-boolean-default-true-accept#20",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s16-context-type-read-cast-swallowed-dead-accept#13",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s16b-context-decode-cast-swallowed-dead-accept#14",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s3-type-read-cast-swallowed-dead-accept#3",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s3j-decode-cast-swallowed-dead-accept#0",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s5-default-negation-rebuilt-reject#9",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s6-default-optionget-rebuilt-reject#10",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s8-default-if-rebuilt-reject#8",
    ),
    (
        "v6/authored/deserialize-substitution-spend.json",
        "s9-default-plus-rebuilt-reject#11",
    ),
    (
        "v6/authored/sized-tree-output-bytes.json",
        "output-declared-over-accept#0",
    ),
    (
        "v6/authored/sized-tree-output-bytes.json",
        "output-declared-under-accept#1",
    ),
    (
        "v6/authored/sized-tree-spend.json",
        "cand-empty-fiat-shamir-proof-accept#3",
    ),
    (
        "v6/authored/sized-tree-spend.json",
        "cthreshold-k0-cand-truncated-proof-half-coefficient-accept#15",
    ),
    (
        "v6/authored/sized-tree-spend.json",
        "cthreshold-k0-cand-truncated-proof-no-coefficient-accept#14",
    ),
    (
        "v6/authored/sized-tree-spend.json",
        "cthreshold-k0-empty-fiat-shamir-proof-accept#5",
    ),
    (
        "v6/authored/tree-version-above-activated-eval.json",
        "context-deserialize-box-v4-reject#0",
    ),
    (
        "v6/authored/tree-version-above-activated-eval.json",
        "dead-context-deserialize-box-v4-reject#4",
    ),
    (
        "v6/authored/tree-version-above-activated-eval.json",
        "deserializeto-box-v4-reject#9",
    ),
    (
        "v6/authored/tree-version-above-activated-eval.json",
        "register-deserialize-box-v4-reject#2",
    ),
    (
        "v6/authored/tree-version-above-activated-eval.json",
        "substconstants-box-v4-reject#6",
    ),
];

#[derive(Debug)]
enum NodeVerdict {
    Accept(u64),
    Reject(String),
}

fn validate(entry: &J) -> Result<NodeVerdict, String> {
    let pre = &entry["preHeader"];
    let p = &entry["parameters"];
    let pre_version =
        u8::try_from(number(&pre["version"], "preHeader.version")?).map_err(|e| e.to_string())?;
    let block_version = match p.get("blockVersion") {
        Some(v) => {
            u8::try_from(number(v, "parameters.blockVersion")?).map_err(|e| e.to_string())?
        }
        None => pre_version,
    };
    let mut params = ProtocolParams::mainnet_default();
    params.block_version = block_version;
    params.max_block_cost = number(&p["maxBlockCost"], "parameters.maxBlockCost")?;
    params.storage_fee_factor = i32::try_from(
        p["storageFeeFactor"]
            .as_i64()
            .ok_or("parameters.storageFeeFactor missing")?,
    )
    .map_err(|e| e.to_string())?;
    params.min_value_per_byte = number(&p["minValuePerByte"], "parameters.minValuePerByte")?;
    params.input_cost = number(&p["inputCost"], "parameters.inputCost")?;
    params.data_input_cost = number(&p["dataInputCost"], "parameters.dataInputCost")?;
    params.output_cost = number(&p["outputCost"], "parameters.outputCost")?;
    params.token_access_cost = number(&p["tokenAccessCost"], "parameters.tokenAccessCost")?;
    let ctx = TransactionContext {
        height: u32::try_from(number(&entry["context"]["height"], "context.height")?)
            .map_err(|e| e.to_string())?,
        miner_pubkey: fixed(&pre["minerPk"], "preHeader.minerPk")?,
        pre_header_timestamp: pre["timestamp"]
            .as_str()
            .ok_or("preHeader.timestamp missing")?
            .parse::<u64>()
            .map_err(|e| e.to_string())?,
        // Same production helper used by block and candidate contexts. Its
        // treatment of synthetic version zero is a node behavior, not corrected here.
        activated_script_version: ergo_validation::voting::derive_activated_script_version(
            block_version,
        ),
        pre_header_version: pre_version,
        pre_header_parent_id: fixed(&pre["parentId"], "preHeader.parentId")?,
        pre_header_n_bits: number(&pre["nBits"], "preHeader.nBits")?,
        pre_header_votes: fixed(&pre["votes"], "preHeader.votes")?,
    };
    let headers = entry["headers_hex"]
        .as_array()
        .ok_or("headers_hex missing")?
        .iter()
        .map(|v| {
            let b = bytes(v, "headers_hex")?;
            read_header(&mut VlqReader::new(&b)).map_err(|e| format!("headers_hex: {e}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let input_boxes = boxes(&entry["input_boxes_hex"], "input_boxes_hex")?;
    let data_boxes = boxes(&entry["data_input_boxes_hex"], "data_input_boxes_hex")?;
    let tx_bytes = bytes(&entry["tx_bytes_hex"], "tx_bytes_hex")?;
    let mut reader = VlqReader::new(&tx_bytes);
    // BlockTransactionsSerializer scope: signed blockVersion >= 4 only.
    if (block_version as i8) >= 4 {
        reader.set_activated_script_version(Some(block_version - 1));
    }
    let tx = read_transaction(&mut reader).map_err(|e| format!("deserialization: tx: {e}"))?;
    let points = reader.take_group_elements();
    let limit = JitCost::from_block_cost(params.max_block_cost)
        .map_err(|e| format!("cost-budget setup: {e}"))?;
    let mut cost = CostAccumulator::new(limit);
    let mut cx = TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &headers,
        // Contract blesses all entries under testnet chain settings (EIP-27 off).
        rules: TxValidationRules::default(),
    };
    match validate_transaction_parsed_with_group_elements(
        tx,
        &tx_bytes,
        &points,
        input_boxes,
        data_boxes,
        false,
        &mut cx,
    ) {
        Ok(_) => Ok(NodeVerdict::Accept(cost.total_block_cost())),
        Err(e) => Ok(NodeVerdict::Reject(e.to_string())),
    }
}

fn vector_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            vector_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

fn jvm_verdicts(path: &Path) -> BTreeMap<String, (bool, Option<u64>)> {
    let mut out = BTreeMap::new();
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(
            fields.len(),
            3,
            "{}: malformed JVM line {line:?}",
            path.display()
        );
        let valid = fields[1].parse::<bool>().unwrap();
        let cost = if fields[2] == "null" {
            None
        } else {
            Some(fields[2].parse::<u64>().unwrap())
        };
        assert_eq!(
            valid,
            cost.is_some(),
            "JVM cost must exist exactly on accepts"
        );
        assert!(
            out.insert(fields[0].to_owned(), (valid, cost)).is_none(),
            "duplicate JVM entry"
        );
    }
    out
}

#[test]
fn santa_tx_vectors_match_santa_the_jvm_and_the_node() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/santa/transaction");
    let mut files = Vec::new();
    vector_files(&root, &mut files);
    files.sort();
    assert_eq!(files.len(), 41, "transaction fixture coverage changed");
    assert_eq!(
        KNOWN_DIVERGENCES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        KNOWN_DIVERGENCES.len(),
        "duplicate known divergence"
    );
    let mut seen = BTreeSet::new();
    let mut failures = Vec::new();
    let mut graded = 0;
    for path in files {
        let file: J = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(file["schema"], "santa-transaction/v1");
        let entries = file["entries"].as_array().unwrap();
        let jvm = jvm_verdicts(&path.with_extension("jvm.tsv"));
        assert_eq!(
            entries.len(),
            jvm.len(),
            "{}: JVM entry count",
            path.display()
        );
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        for entry in entries {
            let name = entry["name"].as_str().unwrap();
            let santa = (
                entry["expected"]["valid"].as_bool().unwrap(),
                entry["expected"]["cost"].as_u64(),
            );
            let oracle = jvm
                .get(name)
                .unwrap_or_else(|| panic!("{relative}/{name}: missing JVM verdict"));
            if *oracle != santa {
                failures.push(format!(
                    "{relative}/{name}: CRITICAL: SANTA {santa:?}, independent JVM {oracle:?}"
                ));
                continue;
            }
            // A panic is a test failure, never a rejection. Decoder errors are
            // normalized only for this consensus comparison, per the brief.
            let (node, phase, reason) = match validate(entry) {
                Ok(NodeVerdict::Accept(cost)) => ((true, Some(cost)), "accept", String::new()),
                Ok(NodeVerdict::Reject(reason)) => ((false, None), "validation-reject", reason),
                Err(reason) => ((false, None), "decode-reject", reason),
            };
            println!(
                "TX\t{relative}\t{name}\t{}\t{}\t{phase}\t{reason}",
                node.0,
                node.1.map_or_else(|| "null".to_owned(), |c| c.to_string())
            );
            if KNOWN_DIVERGENCES.contains(&(relative.as_str(), name)) {
                seen.insert((relative.clone(), name.to_owned()));
                if node == *oracle {
                    failures.push(format!("{relative}/{name}: known divergence now agrees; remove it from KNOWN_DIVERGENCES"));
                }
            } else if node != *oracle {
                failures.push(format!(
                    "{relative}/{name}: JVM {oracle:?}, node {node:?} ({phase}: {reason})"
                ));
            }
            graded += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{} SANTA transaction failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        graded, 311,
        "transaction entry coverage changed or oracle disagrees"
    );
    assert_eq!(
        seen.len(),
        KNOWN_DIVERGENCES.len(),
        "stale known divergence: missing file/entry"
    );
}
