//! Genesis inputs for the private campaign; no synthetic header is persisted.
//! Oracle: scripts/devnet-mixed/genesis.conf and test-vectors/testnet/genesis_boxes.json

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::{autolykos::AutolykosSolution, ergo_box::ErgoBox, header::Header};
use ergo_validation::context::UtxoView;

use crate::error::MiningError;

/// Height-zero carrier for the genesis root and initial difficulty only.
/// It is never exposed in CONTEXT.headers or interlinks.
pub(crate) fn parent_header() -> Header {
    Header {
        version: 4,
        parent_id: ModifierId::from_bytes([0; 32]),
        ad_proofs_root: Digest32::from_bytes([0; 32]),
        transactions_root: Digest32::from_bytes([0; 32]),
        state_root: ADDigest::from_bytes(ergo_chain_spec::GenesisParams::devnet().state_digest),
        timestamp: 0,
        extension_root: Digest32::from_bytes([0; 32]),
        n_bits: 0x0101_0000,
        height: 0,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0; 33]),
            nonce: [0; 8],
        },
    }
}

pub(crate) fn emission_box(view: &impl UtxoView) -> Result<ErgoBox, MiningError> {
    // Genesis box zero is the emission contract in the shared JVM box set.
    let id = hex::decode("b69575e11c5c43400bfead5976ee0d6245a1168396b2e2a4f384691f275d501c")
        .expect("constant box id");
    let id = Digest32::from_bytes(id.try_into().expect("32-byte constant"));
    view.get_box(&id)
        .ok_or_else(|| MiningError::EmissionInvariant {
            op: "devnet_genesis_emission",
            reason: "shared genesis emission box is absent from committed state".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn genesis_parent_private_chain_fields_match() {
        let header = parent_header();
        assert_eq!(header.height, 0);
        assert_eq!(header.parent_id.as_bytes(), &[0; 32]);
        assert_eq!(header.n_bits, 0x0101_0000);
        assert_eq!(
            hex::encode(header.state_root.as_bytes()),
            "cb63aa99a3060f341781d8662b58bf18b9ad258db4fe88d09f8f71cb668cad4502"
        );
    }
}
