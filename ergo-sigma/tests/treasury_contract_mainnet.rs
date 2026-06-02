use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_sigma::evaluator::{EvalBox, ReductionContext};
use ergo_sigma::reduce::verify_spending_proof_with_context;

#[derive(serde::Deserialize)]
struct OutputVec {
    creation_height: u32,
    script_bytes: String,
    value: i64,
}

#[derive(serde::Deserialize)]
struct TreasuryVector {
    tx_id: String,
    ergo_tree: String,
    proof: String,
    bytes_to_sign: String,
    height: u32,
    self_value: i64,
    self_creation_height: u32,
    self_box_id: String,
    self_script: String,
    outputs: Vec<OutputVec>,
    miner_pk: String,
}

fn load_vectors() -> Vec<TreasuryVector> {
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/treasury_contract_700000.json").unwrap();
    serde_json::from_str(&data).unwrap()
}

fn build_eval_box(creation_height: u32, script_bytes: &str, value: i64, box_id: &str) -> EvalBox {
    let mut b = EvalBox::simple(creation_height, hex::decode(script_bytes).unwrap());
    b.value = value;
    if !box_id.is_empty() {
        let id_bytes = hex::decode(box_id).unwrap();
        if id_bytes.len() == 32 {
            b.id.copy_from_slice(&id_bytes);
        }
    }
    b
}

#[test]
fn treasury_contract_all_201_verified() {
    // SBox constant parsing requires deeper stack for recursive ErgoTree parsing
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(treasury_contract_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn treasury_contract_inner() {
    let vectors = load_vectors();
    assert!(vectors.len() >= 201, "expected 201+ vectors");

    let mut passed = 0;
    let mut failed = 0;

    for v in &vectors {
        let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
        let mut reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut reader).unwrap();
        let proof = hex::decode(&v.proof).unwrap();
        let bts = hex::decode(&v.bytes_to_sign).unwrap();
        let miner_pk: [u8; 33] = hex::decode(&v.miner_pk).unwrap().try_into().unwrap();

        let self_box = build_eval_box(
            v.self_creation_height,
            &v.self_script,
            v.self_value,
            &v.self_box_id,
        );

        let outputs: Vec<EvalBox> = v
            .outputs
            .iter()
            .map(|o| {
                let mut b =
                    EvalBox::simple(o.creation_height, hex::decode(&o.script_bytes).unwrap());
                b.value = o.value;
                b
            })
            .collect();

        let ctx = ReductionContext {
            height: v.height,
            self_box: Some(&self_box),
            self_creation_height: v.self_creation_height,
            outputs: &outputs,
            inputs: &[],
            data_inputs: &[],
            miner_pubkey: miner_pk,
            pre_header_timestamp: 0,
            extension: indexmap::IndexMap::new(),
            last_headers: &[],
            last_block_utxo_root: None,
            activated_script_version: 2,
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
            }
        }
    }

    assert_eq!(
        failed,
        0,
        "{failed}/{} treasury proofs failed",
        vectors.len()
    );
    eprintln!(
        "{passed}/{} treasury contract inputs verified",
        vectors.len()
    );
}
