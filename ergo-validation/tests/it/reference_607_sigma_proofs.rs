use ergo_primitives::{digest::ModifierId, reader::VlqReader};
use ergo_ser::{
    ergo_box::ErgoBox,
    transaction::{read_transaction, transaction_id},
};

#[test]
fn response_scalars_in_transactions_match_reference() {
    super::reference_607_tx::assert_fixture("sigma-proofs");
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/sigma-proofs/transactions.json"
    ))
    .unwrap();
    let entries = file["entries"].as_array().unwrap();
    let ids: Vec<_> =
        include_str!("../../../test-vectors/reference-6.0.7/sigma-proofs/transactions.jvm-ids.tsv")
            .lines()
            .collect();
    assert_eq!(entries.len(), ids.len());
    for (entry, ids) in entries.iter().zip(ids) {
        let fields: Vec<_> = ids.split('\t').collect();
        assert_eq!(entry["name"], fields[0]);
        let bytes = hex::decode(entry["tx_bytes_hex"].as_str().unwrap()).unwrap();
        let tx = read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        let id = transaction_id(&tx).unwrap();
        assert_eq!(hex::encode(id.as_bytes()), fields[1]);
        let proofs: Vec<u8> = tx
            .inputs
            .iter()
            .flat_map(|i| i.spending_proof.proof.iter().copied())
            .collect();
        // The reference drops the first hash byte to form the 248-bit witness id.
        let witness = ergo_crypto::autolykos::common::blake2b256(&proofs);
        assert_eq!(hex::encode(&witness[1..]), fields[2]);
        let output_ids: Vec<_> = tx
            .output_candidates
            .into_iter()
            .enumerate()
            .map(|(index, candidate)| {
                let b = ErgoBox {
                    candidate,
                    transaction_id: ModifierId::from_bytes(*id.as_bytes()),
                    index: index as u16,
                };
                hex::encode(b.box_id().unwrap().as_bytes())
            })
            .collect();
        assert_eq!(output_ids.join(","), fields[3]);
    }
}
