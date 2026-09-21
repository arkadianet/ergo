use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_sigma::evaluator::ReductionContext;
use ergo_sigma::reduce::verify_spending_proof_with_context;

#[derive(serde::Deserialize)]
struct MiningRewardVector {
    tx_id: String,
    input_index: usize,
    ergo_tree: String,
    proof: String,
    bytes_to_sign: String,
    height: u32,
    creation_height: u32,
}

fn load_vectors() -> Vec<MiningRewardVector> {
    let data = std::fs::read_to_string("../test-vectors/mainnet/mining_reward_proofs_700000.json")
        .unwrap();
    serde_json::from_str(&data).unwrap()
}

#[test]
fn mining_reward_all_352_verified() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 352,
        "expected 352+ vectors, got {}",
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

        let ctx = ReductionContext::minimal(v.height, v.creation_height);

        match verify_spending_proof_with_context(&ergo_tree, &proof_bytes, &bts, &ctx) {
            Ok(true) => passed += 1,
            Ok(false) => {
                eprintln!(
                    "REJECT: tx={} input={} height={} creation={}",
                    v.tx_id, v.input_index, v.height, v.creation_height
                );
                failed += 1;
            }
            Err(e) => {
                eprintln!(
                    "ERROR: tx={} input={} height={} creation={} err={}",
                    v.tx_id, v.input_index, v.height, v.creation_height, e
                );
                failed += 1;
            }
        }
    }

    assert_eq!(
        failed,
        0,
        "{failed}/{} mining reward proofs failed",
        vectors.len()
    );
    eprintln!("{passed}/{} mining reward proofs verified", vectors.len());
}

#[test]
fn mining_reward_negative_wrong_height() {
    let vectors = load_vectors();
    let v = &vectors[0];

    let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
    let mut reader = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut reader).unwrap();
    let proof_bytes = hex::decode(&v.proof).unwrap();
    let bts = hex::decode(&v.bytes_to_sign).unwrap();

    // Set height too low — before lock period expires
    let ctx = ReductionContext::minimal(v.creation_height + 100, v.creation_height);

    // Should reduce to TrivialFalse (SigmaAnd(False, pk) = False)
    let result = verify_spending_proof_with_context(&ergo_tree, &proof_bytes, &bts, &ctx);
    match result {
        Ok(false) => {} // expected — cannot spend during lock period
        Ok(true) => panic!("should not verify with height before lock period"),
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn mining_reward_negative_bad_proof() {
    let vectors = load_vectors();
    let v = &vectors[0];

    let tree_bytes = hex::decode(&v.ergo_tree).unwrap();
    let mut reader = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut reader).unwrap();
    let mut proof_bytes = hex::decode(&v.proof).unwrap();
    let bts = hex::decode(&v.bytes_to_sign).unwrap();

    proof_bytes[0] ^= 0xFF; // corrupt proof

    let ctx = ReductionContext::minimal(v.height, v.creation_height);

    let result = verify_spending_proof_with_context(&ergo_tree, &proof_bytes, &bts, &ctx);
    match result {
        Ok(false) => {} // expected — bad proof
        Ok(true) => panic!("corrupted proof should not verify"),
        Err(_) => {} // also acceptable
    }
}
