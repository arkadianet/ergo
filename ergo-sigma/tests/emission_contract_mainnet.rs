use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_sigma::evaluator::{EvalBox, ReductionContext};
use ergo_sigma::reduce::verify_spending_proof_with_context;

#[derive(serde::Deserialize)]
struct OutputVec {
    creation_height: u32,
    script_bytes: String,
}

#[derive(serde::Deserialize)]
struct EmissionVector {
    tx_id: String,
    input_index: usize,
    ergo_tree: String,
    proof: String,
    bytes_to_sign: String,
    height: u32,
    outputs: Vec<OutputVec>,
    miner_pk: String,
}

fn load_vectors() -> Vec<EmissionVector> {
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/emission_contract_700000.json").unwrap();
    serde_json::from_str(&data).unwrap()
}

#[test]
fn emission_contract_all_895_verified() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 895,
        "expected 895+ vectors, got {}",
        vectors.len()
    );

    let mut passed = 0;
    let mut failed = 0;

    for v in &vectors {
        let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
        let mut reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut reader).unwrap();

        let proof_bytes = hex::decode(&v.proof).unwrap();
        let bts = hex::decode(&v.bytes_to_sign).unwrap();
        let miner_pk: [u8; 33] = hex::decode(&v.miner_pk).unwrap().try_into().unwrap();

        let outputs: Vec<EvalBox> = v
            .outputs
            .iter()
            .map(|o| EvalBox::simple(o.creation_height, hex::decode(&o.script_bytes).unwrap()))
            .collect();

        let ctx = ReductionContext {
            height: v.height,
            self_box: None,
            self_creation_height: 0,
            outputs: &outputs,
            inputs: &[],
            data_inputs: &[],
            miner_pubkey: miner_pk,
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

        match verify_spending_proof_with_context(&ergo_tree, &proof_bytes, &bts, &ctx) {
            Ok(true) => passed += 1,
            Ok(false) => {
                eprintln!(
                    "REJECT: tx={} input={} h={}",
                    v.tx_id, v.input_index, v.height
                );
                failed += 1;
            }
            Err(e) => {
                eprintln!(
                    "ERROR: tx={} input={} h={} err={}",
                    v.tx_id, v.input_index, v.height, e
                );
                failed += 1;
            }
        }
    }

    assert_eq!(
        failed,
        0,
        "{failed}/{} emission proofs failed",
        vectors.len()
    );
    eprintln!(
        "{passed}/{} emission contract inputs verified",
        vectors.len()
    );
}

#[test]
fn emission_contract_negative_wrong_miner() {
    let vectors = load_vectors();
    let v = &vectors[0];

    let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
    let mut reader = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut reader).unwrap();
    let proof_bytes = hex::decode(&v.proof).unwrap();
    let bts = hex::decode(&v.bytes_to_sign).unwrap();

    let outputs: Vec<EvalBox> = v
        .outputs
        .iter()
        .map(|o| EvalBox::simple(o.creation_height, hex::decode(&o.script_bytes).unwrap()))
        .collect();

    // Use wrong miner pubkey — the generator point
    use k256::elliptic_curve::group::GroupEncoding;
    let wrong_pk: [u8; 33] = k256::ProjectivePoint::GENERATOR
        .to_affine()
        .to_bytes()
        .into();

    let ctx = ReductionContext {
        height: v.height,
        self_box: None,
        self_creation_height: 0,
        outputs: &outputs,
        inputs: &[],
        data_inputs: &[],
        miner_pubkey: wrong_pk,
        pre_header_timestamp: 0,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        activated_script_version: 0,
        ergo_tree_version: 0,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    };

    let result = verify_spending_proof_with_context(&ergo_tree, &proof_bytes, &bts, &ctx);
    match result {
        Ok(false) => {} // expected: wrong miner makes SubstConstants produce wrong script
        Err(_) => {}    // also acceptable
        Ok(true) => panic!("wrong miner pubkey should not verify"),
    }
}
