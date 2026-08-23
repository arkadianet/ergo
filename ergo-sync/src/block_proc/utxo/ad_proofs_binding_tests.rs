//! ADProofs binding tests (UTXO path) — oracle-backed by the live
//! mainnet divergence at h1,853,301 (block 437601cd…, Scala verdict
//! "Regenerated proofHash is not equal to the declared one") and the
//! canonical sibling accept vector 7f0ee965… whose `proofBytes` provably
//! hash to the declared root.

use super::*;
use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ad_proofs::{write_ad_proofs, ADProofs};

const VEC_DIR: &str = "../test-vectors/mainnet/context_headers_1853478";

fn header_from_vector(name: &str) -> (ergo_ser::header::Header, [u8; 32]) {
    let data = std::fs::read_to_string(format!("{VEC_DIR}/{name}")).expect("oracle vector");
    let v: serde_json::Value = serde_json::from_str(&data).expect("json");
    let id_hex = v["header"]["id"].as_str().unwrap().to_lowercase();
    // Decode via rest-json's canonicalizing header decoder.
    let h = ergo_rest_json::decode_header_json(&v["header"].to_string()).expect("header decodes");
    let id: [u8; 32] = hex::decode(&id_hex).unwrap().try_into().unwrap();
    (h, id)
}

fn proof_bytes_from_vector(name: &str) -> Vec<u8> {
    let data = std::fs::read_to_string(format!("{VEC_DIR}/{name}")).expect("oracle vector");
    let v: serde_json::Value = serde_json::from_str(&data).expect("json");
    hex::decode(v["adProofs"]["proofBytes"].as_str().unwrap()).expect("proof hex")
}

/// Canonical section wire bytes for a header + proof payload.
fn wire_section(header_id: [u8; 32], proof_bytes: &[u8]) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_ad_proofs(
        &mut w,
        &ADProofs {
            header_id: ModifierId::from_bytes(header_id),
            proof_bytes: proof_bytes.to_vec(),
        },
    );
    w.result()
}

#[test]
fn canonical_block_proofs_bind_to_declared_root() {
    // 7f0ee965 (h1,853,478): real mainnet block both nodes accepted. Its
    // proofBytes hash exactly to the declared adProofsRoot — this is the
    // invariant Scala enforces and the UTXO path now checks too.
    let (h, id) = header_from_vector("block_accept_7f0ee965.json");
    let proofs = proof_bytes_from_vector("block_accept_7f0ee965.json");
    verify_ad_proofs_binding(&h, &id, &wire_section(id, &proofs))
        .expect("canonical block must pass the binding check");
}

#[test]
fn proofs_for_another_block_rejected_as_hash_mismatch() {
    // Cross-block attack: honest proofs from 7f0ee965 filed under
    // 437601cd's declared root. blake2b256(proofs) != declared ⇒ reject
    // with the typed mismatch — this is the class of block Scala rejected
    // at h1,853,301 and this node wrongly applied for 697 s.
    let (poisoned, poisoned_id) =
        header_from_vector("rejected_block_bodies/1853301_437601cd2079.json");
    let proofs = proof_bytes_from_vector("block_accept_7f0ee965.json");
    match verify_ad_proofs_binding(&poisoned, &poisoned_id, &wire_section(poisoned_id, &proofs)) {
        Err(BlockProcessError::AdProofsHashMismatch {
            header_id,
            declared_root,
            computed_root,
        }) => {
            assert_eq!(header_id, poisoned_id);
            assert_eq!(declared_root, *poisoned.ad_proofs_root.as_bytes());
            assert_eq!(
                computed_root,
                *blake2b256(&proofs).as_bytes(),
                "computed root must be blake2b256 of the actual proof bytes"
            );
            assert_ne!(declared_root, computed_root);
        }
        other => panic!("expected AdProofsHashMismatch, got {other:?}"),
    }
}

#[test]
fn tampered_proof_bytes_rejected() {
    // Same header/section pairing, but one flipped bit inside the proof
    // payload must break the declared-root binding.
    let (h, id) = header_from_vector("block_accept_7f0ee965.json");
    let mut proofs = proof_bytes_from_vector("block_accept_7f0ee965.json");
    proofs[0] ^= 0x01;
    assert!(matches!(
        verify_ad_proofs_binding(&h, &id, &wire_section(id, &proofs)),
        Err(BlockProcessError::AdProofsHashMismatch { .. })
    ));
}

#[test]
fn section_carrying_foreign_header_id_rejected() {
    // Section filed under the right id but embedding someone else's
    // header_id — decode-level consistency check must fire before hashing.
    let (h, id) = header_from_vector("block_accept_7f0ee965.json");
    let proofs = proof_bytes_from_vector("block_accept_7f0ee965.json");
    let foreign = [0xAAu8; 32];
    let err = verify_ad_proofs_binding(&h, &id, &wire_section(foreign, &proofs)).unwrap_err();
    assert!(
        matches!(err, BlockProcessError::Deserialize(ref m) if m.contains("carries header_id")),
        "expected foreign-header_id rejection, got {err}"
    );
    let _ = Digest32::from_bytes([0u8; 32]); // keep digest import honest if unused above
}
