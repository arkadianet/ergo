use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::RegisterValue;
use ergo_ser::sigma_value::read_constant;
use ergo_sigma::evaluator::{EvalBox, ReductionContext};
use ergo_sigma::reduce::verify_spending_proof_with_context;
use std::collections::HashMap;

#[derive(serde::Deserialize)]
struct BoxVec {
    #[serde(default)]
    box_id: String,
    creation_height: u32,
    script_bytes: String,
    value: i64,
    #[serde(default)]
    registers: HashMap<String, String>,
    #[serde(default)]
    tokens: Vec<(String, u64)>,
}

#[derive(serde::Deserialize)]
struct DexVector {
    tx_id: String,
    ergo_tree: String,
    proof: String,
    bytes_to_sign: String,
    height: u32,
    self_value: i64,
    self_creation_height: u32,
    self_box_id: String,
    self_registers: HashMap<String, String>,
    #[serde(default)]
    self_tokens: Vec<(String, u64)>,
    outputs: Vec<BoxVec>,
    data_inputs: Vec<BoxVec>,
}

fn parse_register(hex_val: &str) -> Option<RegisterValue> {
    let bytes = hex::decode(hex_val).ok()?;
    let mut r = VlqReader::new(&bytes);
    let (tpe, value) = read_constant(&mut r).ok()?;
    Some(RegisterValue { tpe, value })
}

fn parse_tokens(tokens: &[(String, u64)]) -> Vec<([u8; 32], u64)> {
    tokens
        .iter()
        .map(|(id_hex, amt)| {
            // Test fixtures must contain valid 32-byte token ids;
            // an unwrap_or_default would silently zero-fill bad ones,
            // which is the wrong shape for an oracle parity test.
            let bytes = hex::decode(id_hex).unwrap_or_else(|e| {
                panic!("dex-oracle fixture token id `{id_hex}` not valid hex: {e}")
            });
            let id: [u8; 32] = bytes.as_slice().try_into().unwrap_or_else(|_| {
                panic!(
                    "dex-oracle fixture token id `{id_hex}` is not 32 bytes (got {})",
                    bytes.len()
                )
            });
            (id, *amt)
        })
        .collect()
}

fn build_box(
    bv: &BoxVec,
    self_regs: &HashMap<String, String>,
    self_tokens: &[(String, u64)],
) -> EvalBox {
    let regs_src = if self_regs.is_empty() {
        &bv.registers
    } else {
        self_regs
    };
    let registers = [
        regs_src.get("R4").and_then(|v| parse_register(v)),
        regs_src.get("R5").and_then(|v| parse_register(v)),
        regs_src.get("R6").and_then(|v| parse_register(v)),
        regs_src.get("R7").and_then(|v| parse_register(v)),
        regs_src.get("R8").and_then(|v| parse_register(v)),
        regs_src.get("R9").and_then(|v| parse_register(v)),
    ];
    let tokens = parse_tokens(if self_tokens.is_empty() {
        &bv.tokens
    } else {
        self_tokens
    });
    let mut b = EvalBox::simple(bv.creation_height, hex::decode(&bv.script_bytes).unwrap());
    b.value = bv.value;
    if !bv.box_id.is_empty() {
        if let Ok(id_bytes) = hex::decode(&bv.box_id) {
            if id_bytes.len() == 32 {
                b.id.copy_from_slice(&id_bytes);
            }
        }
    }
    b.registers = registers;
    b.tokens = tokens;
    b
}

fn load_vectors() -> Vec<DexVector> {
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/dex_oracle_proofs_700000.json").unwrap();
    serde_json::from_str(&data).unwrap()
}

#[test]
fn dex_oracle_all_134_verified() {
    let vectors = load_vectors();
    assert!(vectors.len() >= 134, "expected 134+ vectors");

    let mut passed = 0;
    let mut failed = 0;

    for v in &vectors {
        let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
        let mut reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut reader).unwrap();
        let proof = hex::decode(&v.proof).unwrap();
        let bts = hex::decode(&v.bytes_to_sign).unwrap();

        let empty_regs = HashMap::new();
        let empty_tokens: Vec<(String, u64)> = Vec::new();
        let self_box = build_box(
            &BoxVec {
                box_id: v.self_box_id.clone(),
                creation_height: v.self_creation_height,
                script_bytes: v.ergo_tree.clone(),
                value: v.self_value,
                registers: HashMap::new(),
                tokens: Vec::new(),
            },
            &v.self_registers,
            &v.self_tokens,
        );

        let outputs: Vec<EvalBox> = v
            .outputs
            .iter()
            .map(|o| build_box(o, &empty_regs, &empty_tokens))
            .collect();
        let data_inputs: Vec<EvalBox> = v
            .data_inputs
            .iter()
            .map(|d| build_box(d, &empty_regs, &empty_tokens))
            .collect();

        let ctx = ReductionContext {
            height: v.height,
            self_box: Some(&self_box),
            self_creation_height: v.self_creation_height,
            outputs: &outputs,
            inputs: &[],
            data_inputs: &data_inputs,
            miner_pubkey: [0u8; 33],
            pre_header_timestamp: 0,
            extension: indexmap::IndexMap::new(),
            last_headers: &[],
            last_block_utxo_root: None,
            activated_script_version: 2,
            ergo_tree_version: 2,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
            input_extensions: &[],
        };

        match verify_spending_proof_with_context(&ergo_tree, &proof, &bts, &ctx) {
            Ok(true) => passed += 1,
            Ok(false) => {
                eprintln!("REJECT: tx={} h={}", v.tx_id, v.height);
                failed += 1;
            }
            Err(e) => {
                eprintln!("ERROR: tx={} h={} err={}", v.tx_id, v.height, e);
                failed += 1;
                if failed >= 3 {
                    break;
                }
            }
        }
    }

    eprintln!(
        "{passed}/{} DEX/oracle proofs verified, {failed} failed",
        vectors.len()
    );
    assert_eq!(
        failed,
        0,
        "{failed}/{} DEX/oracle proofs failed",
        vectors.len()
    );
}
