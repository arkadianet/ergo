use crate::modifier_id::ModifierId;

/// Authenticated data structure proofs for a block, allowing
/// verification of transactions against the state root.
///
/// Corresponds to `ADProofs` (modifier type ID 104) in the Scala Ergo node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ADProofs {
    /// The ID of the header these proofs belong to.
    pub header_id: ModifierId,
    /// Serialized proof bytes for the authenticated data structure.
    pub proof_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_construction() {
        let proof_data = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
        let proofs = ADProofs {
            header_id: ModifierId([0xcc; 32]),
            proof_bytes: proof_data.clone(),
        };
        assert_eq!(proofs.header_id, ModifierId([0xcc; 32]));
        assert_eq!(proofs.proof_bytes, proof_data);
        assert_eq!(proofs.proof_bytes.len(), 7);
    }

    #[test]
    fn empty_proof() {
        let proofs = ADProofs {
            header_id: ModifierId([0x00; 32]),
            proof_bytes: Vec::new(),
        };
        assert!(proofs.proof_bytes.is_empty());
        assert_eq!(proofs.header_id, ModifierId([0x00; 32]));
    }

    #[test]
    fn ad_proofs_clone_and_eq() {
        let proofs = ADProofs {
            header_id: ModifierId([0x55; 32]),
            proof_bytes: vec![0x01, 0x02, 0x03],
        };
        let cloned = proofs.clone();
        assert_eq!(proofs, cloned);
    }

    #[test]
    fn ad_proofs_inequality() {
        let proofs_a = ADProofs {
            header_id: ModifierId([0x01; 32]),
            proof_bytes: vec![0x01],
        };
        let proofs_b = ADProofs {
            header_id: ModifierId([0x02; 32]),
            proof_bytes: vec![0x01],
        };
        assert_ne!(proofs_a, proofs_b);
    }
}
