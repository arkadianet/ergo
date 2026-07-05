//! NiPoPoW REST encoders — `ergo-ser` popow types → the Scala-compat
//! JSON DTOs (`NipopowApiRoute.scala:55-90` surface).
//!
//! JSON shapes are pinned by the captured mainnet fixtures under
//! `test-vectors/mainnet/nipopow/` (see
//! `ergo-rest-json/tests/nipopow_json_fixtures.rs`). Two traps live
//! here rather than in the DTOs:
//! - the odd-trailing empty Merkle sibling (`ProofEntry.digest == None`)
//!   encodes as the EMPTY STRING, not 32 zero bytes;
//! - each embedded header's `id`/`size` are recomputed from the
//!   serialized header bytes, exactly as the `/blocks/*` encoders do.

use ergo_rest_json::types::{
    ScalaBatchMerkleProof, ScalaBatchProofElement, ScalaBatchProofIndex, ScalaNipopowProof,
    ScalaPopowHeader,
};
use ergo_ser::batch_merkle_proof::deserialize_batch_merkle_proof;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::modifier_id::ExpectedSections;
use ergo_ser::popow_header::PoPowHeader;
use ergo_ser::popow_proof::NipopowProof;

use super::compat::encode_header;
use super::error::BridgeError;

/// Serialize + id a header, then encode it through the shared
/// `/blocks/*` header encoder so every embedded header in the popow
/// JSON is byte-identical to what `/blocks/{id}/header` serves.
fn encode_plain_header(h: &Header) -> Result<ergo_rest_json::types::ScalaHeader, BridgeError> {
    let (bytes, id) = serialize_header(h).map_err(|source| BridgeError::Encode {
        what: "nipopow header",
        source,
    })?;
    let id_bytes = *id.as_bytes();
    let expected = ExpectedSections::from_header(
        &id_bytes,
        h.transactions_root.as_bytes(),
        h.extension_root.as_bytes(),
        h.ad_proofs_root.as_bytes(),
    );
    Ok(encode_header(
        h,
        bytes.len() as u32,
        &expected,
        &hex::encode(id_bytes),
    ))
}

pub(super) fn encode_popow_header(ph: &PoPowHeader) -> Result<ScalaPopowHeader, BridgeError> {
    let bmp = deserialize_batch_merkle_proof(&ph.interlinks_proof).map_err(|source| {
        BridgeError::Encode {
            what: "nipopow interlinks batch proof",
            source,
        }
    })?;
    Ok(ScalaPopowHeader {
        header: encode_plain_header(&ph.header)?,
        interlinks: ph
            .interlinks
            .iter()
            .map(|m| hex::encode(m.as_bytes()))
            .collect(),
        interlinks_proof: ScalaBatchMerkleProof {
            indices: bmp
                .indices
                .iter()
                .map(|(index, digest)| ScalaBatchProofIndex {
                    index: *index,
                    digest: hex::encode(digest),
                })
                .collect(),
            proofs: bmp
                .proofs
                .iter()
                .map(|p| ScalaBatchProofElement {
                    // None = scrypto's EmptyByteArray odd-trailing
                    // sibling → empty string in JSON (fixture-pinned).
                    digest: p.digest.map(hex::encode).unwrap_or_default(),
                    side: p.side.as_byte(),
                })
                .collect(),
        },
    })
}

pub(super) fn encode_nipopow_proof(p: &NipopowProof) -> Result<ScalaNipopowProof, BridgeError> {
    Ok(ScalaNipopowProof {
        m: p.m,
        k: p.k,
        prefix: p
            .prefix
            .iter()
            .map(encode_popow_header)
            .collect::<Result<Vec<_>, _>>()?,
        suffix_head: encode_popow_header(&p.suffix_head)?,
        suffix_tail: p
            .suffix_tail
            .iter()
            .map(encode_plain_header)
            .collect::<Result<Vec<_>, _>>()?,
        continuous: p.continuous,
    })
}
