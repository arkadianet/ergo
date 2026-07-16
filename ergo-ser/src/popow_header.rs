//! PoPowHeader codec — a Header bundled with its interlinks vector
//! and a batch Merkle proof of those interlinks against the
//! extension's interlinks-subtree root.
//!
//! Mirrors Scala `PoPowHeaderSerializer` at
//! `ergo-core/.../modifiers/history/popow/PoPowHeader.scala:142-167`
//! byte-for-byte:
//!
//! ```text
//! u32 header_size
//! [u8; header_size] header_bytes          ; full Header bytes via serialize_header
//! u32 links_qty
//! [[u8; 32]] interlinks                   ; `links_qty` 32-byte ModifierIds
//! u32 interlinks_proof_size
//! [u8; interlinks_proof_size] proof_bytes ; opaque batch Merkle proof blob
//! ```
//!
//! The batch Merkle proof itself is stored as an opaque length-prefixed
//! blob at this layer; structural parsing + verification against an
//! extension root happens in `ergo-validation::popow`, which is the
//! only consumer that needs to look inside the proof.
//! Keeping the codec opaque here matches the layering rule
//! (`ergo-ser` is byte ↔ struct only; validation predicates live in
//! `ergo-validation`).
//!
//! Exception to that rule: this reader applies one defense-in-depth
//! guard on the peer-controlled `links_qty` count before passing it to
//! `Vec::with_capacity` — see [`POPOW_HEADER_MAX_INTERLINKS`]. The DoS
//! must be caught at the alloc site (no upstream layer sees per-field
//! counts before bytes are interpreted); honest-input semantics are
//! unchanged.

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::header::{read_header, serialize_header, Header};

/// `[proposed]` hard cap on `PoPowHeader.interlinks` length for wire
/// decoding. Scala's `PoPowHeader.scala:159-167` reads the count
/// without an upper bound; this cap is local acceptance policy, not
/// inherited protocol.
///
/// Sizing rationale: per KMZ17 §4.2, interlinks length is `O(log2 h)`
/// where `h` is the header's height. Mainnet height ≈ 1.5M observed
/// today → `log2 h ≈ 21` interlinks per header. The chosen upper bound
/// for future regimes is 256 — ~12× observed mainnet, nine bits of
/// headroom against any plausible height for the next several decades.
///
/// Without the cap, `Vec::with_capacity(links_qty)` allocates
/// `links_qty * 32` bytes (≈ 64 GiB on `i32::MAX`) before any 32-byte
/// `ModifierId` is read — a single P2P message OOMs the node. Rejecting
/// past this with `ReadError::InvalidData` closes that surface and
/// matches Scala's observed acceptance behavior for every honest peer
/// message we have on file.
const POPOW_HEADER_MAX_INTERLINKS: usize = 256;

/// Block header bundled with its interlinks vector and a batch Merkle
/// proof of those interlinks against the block's extension root.
///
/// The [`Self::interlinks_proof`] field holds the opaque proof bytes
/// as transmitted on the wire. Structural decoding + verification of
/// the proof against an extension's interlinks-subtree root happens
/// in `ergo-validation::popow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoPowHeader {
    /// The header itself.
    pub header: Header,
    /// Reverse-order interlinks vector: index 0 is always genesis,
    /// index 1 is the lowest-level superblock pointer, etc. (KMZ17).
    pub interlinks: Vec<ModifierId>,
    /// Serialized batch Merkle proof. Length-prefixed on the wire;
    /// kept opaque at this layer.
    pub interlinks_proof: Vec<u8>,
}

/// Serialize a `PoPowHeader` per Scala `PoPowHeaderSerializer.serialize`
/// (`PoPowHeader.scala:148-157`).
pub fn write_popow_header(w: &mut VlqWriter, p: &PoPowHeader) -> Result<(), WriteError> {
    let header_bytes = serialize_header(&p.header).map(|(bytes, _id)| bytes)?;
    w.put_u32(header_bytes.len() as u32);
    w.put_bytes(&header_bytes);
    w.put_u32(p.interlinks.len() as u32);
    for id in &p.interlinks {
        w.put_bytes(id.as_bytes());
    }
    w.put_u32(p.interlinks_proof.len() as u32);
    w.put_bytes(&p.interlinks_proof);
    Ok(())
}

/// Convenience: serialize to a fresh `Vec<u8>`.
pub fn serialize_popow_header(p: &PoPowHeader) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    write_popow_header(&mut w, p)?;
    Ok(w.result())
}

/// Parse a `PoPowHeader` per Scala `PoPowHeaderSerializer.parse`
/// (`PoPowHeader.scala:159-167`).
pub fn read_popow_header(r: &mut VlqReader) -> Result<PoPowHeader, ReadError> {
    let header_size = r.get_u32_exact()? as usize;
    let header_bytes = r.get_bytes(header_size)?.to_vec();
    let header = {
        let mut hr = VlqReader::new(&header_bytes);
        read_header(&mut hr)?
    };

    let links_qty = r.get_u32_exact()? as usize;
    if links_qty > POPOW_HEADER_MAX_INTERLINKS {
        return Err(ReadError::InvalidData(format!(
            "PoPowHeader.interlinks length {links_qty} > cap {POPOW_HEADER_MAX_INTERLINKS}"
        )));
    }
    let mut interlinks = Vec::with_capacity(links_qty);
    for _ in 0..links_qty {
        let id_bytes = r.get_array::<32>()?;
        interlinks.push(ModifierId::from_bytes(id_bytes));
    }

    let proof_size = r.get_u32_exact()? as usize;
    let interlinks_proof = r.get_bytes(proof_size)?.to_vec();

    Ok(PoPowHeader {
        header,
        interlinks,
        interlinks_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::read_header;

    // ----- helpers -----

    /// Mainnet genesis header (height 1). Sourced from
    /// `test-vectors/mainnet/headers_1_10.json[0]`.
    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

    fn genesis_header() -> Header {
        let raw = hex::decode(GENESIS_HEX).unwrap();
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).unwrap()
    }

    // ----- round-trips -----

    #[test]
    fn popow_header_roundtrip_empty_interlinks_and_proof() {
        // Smallest shape: a PoPowHeader with no interlinks and no proof
        // bytes. This isn't a meaningful proof (genesis has interlinks
        // = [genesis.id] in practice, see `update_interlinks`), but
        // pins the codec's handling of the zero-length branches.
        let p = PoPowHeader {
            header: genesis_header(),
            interlinks: vec![],
            interlinks_proof: vec![],
        };
        let bytes = serialize_popow_header(&p).unwrap();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_popow_header(&mut r).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(r.remaining(), 0, "no trailing bytes");
    }

    #[test]
    fn popow_header_roundtrip_with_interlinks_and_opaque_proof() {
        // Realistic shape: a few interlinks and a non-empty opaque
        // proof blob. The proof bytes are not parsed at this layer
        // (handled in ergo-validation::popow), so any byte sequence
        // round-trips identically.
        let p = PoPowHeader {
            header: genesis_header(),
            interlinks: vec![
                ModifierId::from_bytes([0x11; 32]),
                ModifierId::from_bytes([0x22; 32]),
                ModifierId::from_bytes([0x33; 32]),
            ],
            interlinks_proof: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        };
        let bytes = serialize_popow_header(&p).unwrap();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_popow_header(&mut r).unwrap();
        assert_eq!(parsed, p);
    }

    // ----- error paths -----

    #[test]
    fn popow_header_truncated_interlinks_id_errors() {
        // Truncation inside the interlinks block: claim 2 interlinks
        // but only provide 1.5 worth of bytes.
        let p = PoPowHeader {
            header: genesis_header(),
            interlinks: vec![ModifierId::from_bytes([0x11; 32])],
            interlinks_proof: vec![],
        };
        // Build a raw input that claims 2 interlinks but only carries 1
        // — the reader must fail rather than read past the end.
        let mut w = VlqWriter::new();
        let header_bytes = serialize_header(&p.header).unwrap().0;
        w.put_u32(header_bytes.len() as u32);
        w.put_bytes(&header_bytes);
        w.put_u32(2); // claim 2 interlinks
        w.put_bytes(&[0x11; 32]); // only 1 actually present (need 64 bytes, supply 32)
        let truncated = w.result();
        let mut r = VlqReader::new(&truncated);
        assert!(read_popow_header(&mut r).is_err());
    }

    #[test]
    fn read_popow_header_links_qty_above_cap_rejects_before_alloc() {
        // Hostile peer claims links_qty = i32::MAX. The cap check
        // must fire on the count itself — before Vec::with_capacity
        // attempts the ~2 GiB allocation and before any 32-byte
        // interlink read can hit UnexpectedEnd. We deliberately
        // supply NO interlink bytes after the count so a
        // truncation-based error would prove the cap check was
        // skipped.
        let mut w = VlqWriter::new();
        let header_bytes = serialize_header(&genesis_header()).unwrap().0;
        w.put_u32(header_bytes.len() as u32);
        w.put_bytes(&header_bytes);
        w.put_u32(i32::MAX as u32);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_popow_header(&mut r).expect_err("hostile links_qty must reject");
        match err {
            ReadError::InvalidData(msg) => {
                assert!(msg.contains("interlinks length"), "wrong message: {msg}");
                assert!(msg.contains("256"), "cap must be cited: {msg}");
            }
            other => panic!("expected InvalidData (cap), got {other:?}"),
        }
    }

    #[test]
    fn read_popow_header_links_qty_cap_boundary_rejects_one_past() {
        // Pin the off-by-one: cap is POPOW_HEADER_MAX_INTERLINKS (256).
        // Exactly cap+1 must reject; the gate must be `>` cap, not `>=`.
        let mut w = VlqWriter::new();
        let header_bytes = serialize_header(&genesis_header()).unwrap().0;
        w.put_u32(header_bytes.len() as u32);
        w.put_bytes(&header_bytes);
        w.put_u32((POPOW_HEADER_MAX_INTERLINKS as u32) + 1);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        assert!(matches!(
            read_popow_header(&mut r),
            Err(ReadError::InvalidData(_))
        ));
    }

    #[test]
    fn popow_header_links_qty_exactly_at_cap_roundtrips() {
        // Cap-acceptance pin: `links_qty == POPOW_HEADER_MAX_INTERLINKS`
        // must round-trip cleanly. Pairs with the cap+1 rejection above
        // to fully specify the gate boundary (`>` not `>=`). Witnesses
        // that the chosen 256 ceiling is not overlapping a legal value.
        let p = PoPowHeader {
            header: genesis_header(),
            interlinks: (0..POPOW_HEADER_MAX_INTERLINKS)
                .map(|i| ModifierId::from_bytes([i as u8; 32]))
                .collect(),
            interlinks_proof: vec![],
        };
        let bytes = serialize_popow_header(&p).unwrap();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_popow_header(&mut r).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.interlinks.len(), POPOW_HEADER_MAX_INTERLINKS);
    }
}
