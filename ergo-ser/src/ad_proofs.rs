use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// AVL+ batch proof attached to a block.
///
/// The proof bytes are produced by the prover-side AVL tree when applying
/// a block's transactions to the previous UTXO state and are verified by
/// peers replaying the same operations against `state_root`. The opaque
/// payload is intentionally not parsed at this layer — `ergo-state`
/// decodes it when validating a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ADProofs {
    /// Identifier of the block header this proof belongs to.
    pub header_id: ModifierId,
    /// Raw AVL+ batch-proof bytes, opaque to this crate.
    pub proof_bytes: Vec<u8>,
}

/// Serialize `proofs` as 32-byte `header_id` followed by a VLQ-`u32`
/// length and the raw proof bytes.
pub fn write_ad_proofs(w: &mut VlqWriter, proofs: &ADProofs) {
    w.put_bytes(proofs.header_id.as_bytes());
    w.put_u32(proofs.proof_bytes.len() as u32);
    w.put_bytes(&proofs.proof_bytes);
}

/// Decode the wire form produced by [`write_ad_proofs`].
pub fn read_ad_proofs(r: &mut VlqReader) -> Result<ADProofs, ReadError> {
    let header_id = ModifierId::from_bytes(r.get_array::<32>()?);
    let len = r.get_u32_exact()? as usize;
    let proof_bytes = r.get_bytes(len)?.to_vec();
    Ok(ADProofs {
        header_id,
        proof_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- round-trips -----

    #[test]
    fn ad_proofs_roundtrip_empty() {
        let proofs = ADProofs {
            header_id: ModifierId::from_bytes([0x55; 32]),
            proof_bytes: vec![],
        };
        let mut w = VlqWriter::new();
        write_ad_proofs(&mut w, &proofs);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ad_proofs(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, proofs);
    }

    #[test]
    fn ad_proofs_roundtrip_nonempty() {
        let proofs = ADProofs {
            header_id: ModifierId::from_bytes([0x66; 32]),
            proof_bytes: vec![0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF],
        };
        let mut w = VlqWriter::new();
        write_ad_proofs(&mut w, &proofs);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ad_proofs(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, proofs);
    }
}
