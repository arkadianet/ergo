//! Regenerate the reference sigma response transaction fixtures with the node prover.

use ergo_primitives::{group_element::GroupElement, reader::VlqReader, writer::VlqWriter};
use ergo_ser::{
    sigma_value::SigmaBoolean,
    transaction::{bytes_to_sign, read_transaction, write_transaction},
};
use ergo_wallet::proving::{
    external::ProverExternalSecret,
    hints::{Hint, HintsBag, SimulatedSecretProof},
    node_position::NodePosition,
    randomness::Sha256DerivedRng,
    secrets::SecretRegistry,
    sigma::prove_sigma,
};
use k256::{elliptic_curve::group::GroupEncoding, ProjectivePoint, Scalar};
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let pk_a: [u8; 33] = (ProjectivePoint::GENERATOR * Scalar::from(7u64))
        .to_affine()
        .to_bytes()
        .into();
    let pk_b: [u8; 33] = (ProjectivePoint::GENERATOR * Scalar::from(11u64))
        .to_affine()
        .to_bytes()
        .into();
    let b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let prop = SigmaBoolean::Cor(
        vec![
            SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a)),
            b.clone(),
        ]
        .into(),
    );
    let secrets = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: Scalar::from(7u64).into(),
        }])
        .unwrap();
    let mut z = [0u8; 32];
    z[31] = 5;
    let mut hints = HintsBag::empty();
    hints.add(Hint::SimulatedSecretProof(SimulatedSecretProof {
        image: b,
        challenge: [1u8; 24],
        response: z,
        position: NodePosition::crypto_tree_prefix().child(1),
    }));
    file["entries"].as_array_mut().unwrap().truncate(1);
    let entry = &mut file["entries"][0];
    let bytes = hex::decode(entry["tx_bytes_hex"].as_str().unwrap()).unwrap();
    let mut tx = read_transaction(&mut VlqReader::new(&bytes)).unwrap();
    let message = bytes_to_sign(&tx).unwrap();
    let (proof, _) = prove_sigma(
        &prop,
        &secrets,
        &message,
        &hints,
        &mut Sha256DerivedRng::from_seed([42; 32]),
    )
    .unwrap();
    assert_eq!(&proof[proof.len() - 32..], z);
    for leaf in ergo_sigma::verify::extract_proof_leaves(&prop, &proof).unwrap() {
        use k256::elliptic_curve::PrimeField;
        assert!(bool::from(
            Scalar::from_repr(leaf.response.into()).is_some()
        ));
    }
    tx.inputs[0].spending_proof.proof = proof.clone();
    entry["tx_bytes_hex"] = {
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        hex::encode(w.result())
    }
    .into();
    entry["name"] = "node-or-response-five".into();
    let mut plus = entry.clone();
    let nplus =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364146").unwrap();
    let len = proof.len();
    tx.inputs[0].spending_proof.proof[len - 32..].copy_from_slice(&nplus);
    plus["name"] = "node-or-response-order-plus-five".into();
    plus["tx_bytes_hex"] = {
        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        hex::encode(w.result())
    }
    .into();
    file["entries"].as_array_mut().unwrap().push(plus);
    std::fs::write(path, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
}
