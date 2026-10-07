//! Transaction outcomes and costs recorded by the 6.0.7 reference node.
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::read_header;
use ergo_ser::transaction::read_transaction;
use ergo_validation::tx::{
    validate_transaction_parsed_with_group_elements, TxValidationCtx, TxValidationRules,
};
use ergo_validation::{CostAccumulator, JitCost, ProtocolParams, TransactionContext};
use serde_json::Value as J;
use std::collections::BTreeMap;

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

#[derive(Debug)]
enum NodeVerdict {
    Accept(u64),
    Reject(String),
}

fn validate(entry: &J, mempool: bool) -> Result<NodeVerdict, String> {
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
        // Same signed-byte derivation used by production block/candidate contexts.
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
    let result = if mempool {
        struct View(Vec<ErgoBox>);
        impl ergo_validation::UtxoView for View {
            fn get_box(&self, id: &ergo_primitives::digest::Digest32) -> Option<ErgoBox> {
                self.0
                    .iter()
                    .find(|b| b.box_id().is_ok_and(|found| found == *id))
                    .cloned()
            }
        }
        let view = View(input_boxes.into_iter().chain(data_boxes).collect());
        ergo_validation::tx::validate_transaction(
            &tx_bytes,
            &view,
            &ergo_validation::LocalPolicy::default_policy(),
            &mut cx,
        )
    } else {
        validate_transaction_parsed_with_group_elements(
            tx,
            &tx_bytes,
            &points,
            input_boxes,
            data_boxes,
            false,
            &mut cx,
        )
    };
    match result {
        Ok(_) => Ok(NodeVerdict::Accept(cost.total_block_cost())),
        Err(e) => Ok(NodeVerdict::Reject(e.to_string())),
    }
}

#[test]
fn reference_receiver_transactions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/reference-6.0.7/serialization");
    for file in [
        "receiver-types",
        "avl-lengths",
        "nested-boxes",
        "relations",
        "transaction-encodings",
    ] {
        let path = root.join(format!("{file}.json"));
        let fixture: J = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let oracle = std::fs::read_to_string(path.with_extension("jvm.tsv")).unwrap();
        let rows: BTreeMap<_, _> = oracle
            .lines()
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                (
                    fields[0],
                    (fields[1] == "true", fields[2].parse::<u64>().ok()),
                )
            })
            .collect();
        let entries = fixture["entries"].as_array().unwrap();
        assert_eq!(rows.len(), entries.len());
        for entry in entries {
            let name = entry["name"].as_str().unwrap();
            let expected = rows[name];
            let actual = validate(entry, false);
            let observed = match &actual {
                Ok(NodeVerdict::Accept(cost)) => (true, Some(*cost)),
                Ok(NodeVerdict::Reject(reason)) => {
                    assert!(!reason.is_empty());
                    (false, None)
                }
                Err(_) => (false, None),
            };
            assert_eq!(observed, expected, "{name}: {actual:?}");
            let actual = validate(entry, true);
            let observed = match &actual {
                Ok(NodeVerdict::Accept(cost)) => (true, Some(*cost)),
                _ => (false, None),
            };
            assert_eq!(observed, expected, "mempool {name}: {actual:?}");
        }
    }
}
