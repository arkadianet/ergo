use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_sigma::reduce::verify_spending_proof;

#[test]
fn spending_proof_p2pk_mainnet() {
    // Use the existing Schnorr vectors which have pk, proof, and bytes_to_sign.
    // Convert pk to ErgoTree format (non-segregated P2PK: 0x00 0x08 0xCD pk)
    #[derive(serde::Deserialize)]
    struct SchnorrVec {
        pk: String,
        proof: String,
        bytes_to_sign: String,
    }
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/schnorr_proofs_700000.json").unwrap();
    let vectors: Vec<SchnorrVec> = serde_json::from_str(&data).unwrap();

    let mut passed = 0;
    for v in &vectors {
        let pk_bytes = hex::decode(&v.pk).unwrap();
        let proof_bytes = hex::decode(&v.proof).unwrap();
        let bts = hex::decode(&v.bytes_to_sign).unwrap();

        // Build non-segregated P2PK ErgoTree: 0x00 + body(0x08=SSigmaProp type code, 0xCD=ProveDlog, pk)
        let mut tree_bytes = vec![0x00u8];
        tree_bytes.push(0x08); // SSigmaProp type code
        tree_bytes.push(0xCD); // ProveDlog tag
        tree_bytes.extend_from_slice(&pk_bytes);

        let mut reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut reader).unwrap();

        let result = verify_spending_proof(&ergo_tree, &proof_bytes, &bts).unwrap();
        assert!(result, "spending proof should verify for {}", v.pk);
        passed += 1;
    }
    eprintln!(
        "{passed}/{} P2PK spending proofs verified end-to-end",
        vectors.len()
    );
}

#[test]
fn spending_proof_p2pk_segregated() {
    // Test segregated ErgoTree (header 0x10)
    #[derive(serde::Deserialize)]
    struct SchnorrVec {
        pk: String,
        proof: String,
        bytes_to_sign: String,
    }
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/schnorr_proofs_700000.json").unwrap();
    let vectors: Vec<SchnorrVec> = serde_json::from_str(&data).unwrap();

    for v in vectors.iter().take(10) {
        let pk_bytes = hex::decode(&v.pk).unwrap();
        let proof_bytes = hex::decode(&v.proof).unwrap();
        let bts = hex::decode(&v.bytes_to_sign).unwrap();

        // Build segregated P2PK ErgoTree: 0x10 01 08 CD pk 73 00
        let mut tree_bytes = vec![0x10u8, 0x01, 0x08, 0xCD];
        tree_bytes.extend_from_slice(&pk_bytes);
        tree_bytes.push(0x73); // ConstPlaceholder opcode
        tree_bytes.push(0x00); // index 0

        let mut reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut reader).unwrap();

        let result = verify_spending_proof(&ergo_tree, &proof_bytes, &bts).unwrap();
        assert!(result, "segregated spending proof should verify");
    }
    eprintln!("10 segregated P2PK spending proofs verified");
}

#[test]
fn spending_proof_reject_wrong_tree() {
    #[derive(serde::Deserialize)]
    struct SchnorrVec {
        #[allow(dead_code)]
        pk: String,
        proof: String,
        bytes_to_sign: String,
    }
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/schnorr_proofs_700000.json").unwrap();
    let vectors: Vec<SchnorrVec> = serde_json::from_str(&data).unwrap();
    let v = &vectors[0];

    let proof_bytes = hex::decode(&v.proof).unwrap();
    let bts = hex::decode(&v.bytes_to_sign).unwrap();

    // Use the generator point instead of the real pk
    use k256::elliptic_curve::group::GroupEncoding;
    let wrong_pk: [u8; 33] = k256::ProjectivePoint::GENERATOR
        .to_affine()
        .to_bytes()
        .into();
    let mut tree_bytes = vec![0x00u8, 0x08, 0xCD];
    tree_bytes.extend_from_slice(&wrong_pk);

    let mut reader = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut reader).unwrap();

    let result = verify_spending_proof(&ergo_tree, &proof_bytes, &bts).unwrap();
    assert!(!result, "wrong tree should not verify");
}

#[test]
fn spending_proof_complex_tree_returns_not_reducible() {
    // A tree with version > 0 and complex body should return NotTriviallyReducible
    // Use a real complex ErgoTree from the survey: tree_len=54 (segregated with more opcodes)
    // Header 0x10, constants=[SSigmaProp(ProveDlog(pk))], body contains more than just ConstPlaceholder
    // For now, just test with a synthetic non-trivial tree
    let tree_bytes = vec![
        0x10, // header: v0 + segregation
        0x00, // 0 constants
        0x7F, // opcode: True (not a constant or placeholder)
    ];
    let mut reader = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut reader).unwrap();

    let result = verify_spending_proof(&ergo_tree, &[0u8; 56], b"test");
    assert!(result.is_err(), "complex tree should return error");
}
