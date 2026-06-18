use crate::autolykos::{read_solution, write_solution, AutolykosSolution};
use crate::difficulty::{read_nbits, write_nbits};
use crate::error::WriteError;
use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// First Ergo block header version (genesis through `INTERPRETER_60_VERSION - 1`).
pub const INITIAL_VERSION: u8 = 1;

/// Last header version that does **not** preserve `unparsed_bytes`. From
/// version `INTERPRETER_60_VERSION + 1` onwards (i.e. v5+), readers
/// retain forward-compatible trailing bytes; for v2-v4 the bytes are
/// discarded on read.
pub const INTERPRETER_60_VERSION: u8 = 4;

/// Ergo block header: the consensus-critical metadata committed to by
/// proof-of-work and chained via [`Header::parent_id`]. Roots inside the
/// header authenticate the block body (transactions, AVL+ state, AD
/// proofs, extension) which is shipped separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Header layout version. Drives wire-format gating (`unparsed_bytes`
    /// length byte appears for `version > INITIAL_VERSION`) and
    /// PoW-solution layout via [`AutolykosSolution`].
    pub version: u8,
    /// Identifier of the previous block's header (zero for genesis).
    pub parent_id: ModifierId,
    /// Merkle root over the AD proofs section.
    pub ad_proofs_root: Digest32,
    /// Merkle root over the transactions section.
    pub transactions_root: Digest32,
    /// AVL+ root after applying this block's transactions to the prior
    /// state. The trailing byte encodes the tree height.
    pub state_root: ADDigest,
    /// Block timestamp, milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// Merkle root over the [`super::extension`] key-value section.
    pub extension_root: Digest32,
    /// Compact difficulty target (`nBits`); same encoding as Bitcoin.
    pub n_bits: u32,
    /// Block height (genesis is `0`; the first mined block is `1`).
    pub height: u32,
    /// Three-byte miner vote vector for protocol parameter changes.
    pub votes: [u8; 3],
    /// Forward-compatible trailing bytes between the votes vector and
    /// the PoW solution. Versions 2-4 emit these on the wire but discard
    /// them on read; v5+ preserves them so unknown future fields can be
    /// round-tripped without losing data.
    pub unparsed_bytes: Vec<u8>,
    /// PoW solution (Autolykos v1 for header v1, Autolykos v2 for v2+).
    pub solution: AutolykosSolution,
}

/// Compare a header version against a threshold using **signed** byte
/// semantics, matching Scala (`Header.Version = Byte`, so
/// `HeaderSerializer` gates `unparsed_bytes` on `version > InitialVersion`
/// where both are signed `Byte`s).
///
/// This only differs from an unsigned compare for malformed version bytes
/// `> 127` (real headers are v1-4): e.g. byte `195` is `-61` signed, which is
/// NOT `> InitialVersion(1)`, so the reference reads NO `unparsed_bytes`
/// section. An unsigned `195 > 1` would read a spurious length+payload and
/// shift the Autolykos-solution offset — a byte-grammar divergence. Keeping the
/// comparison signed makes node and reference agree on the wire grammar for
/// every version byte.
#[inline]
fn version_gt(version: u8, threshold: u8) -> bool {
    (version as i8) > (threshold as i8)
}

/// Header-side wire-format bounds. Called from
/// `write_header_without_pow`, which `write_header` delegates to —
/// so both PoW-message and header_id paths run the same check.
/// Symmetry matters because `write_header_without_pow` feeds the
/// PoW message hash (`Blake2b256(bytesWithoutPow(header))`); a silent
/// wrap there would split the header_id path from the PoW message path.
fn check_header_bounds(h: &Header) -> Result<(), WriteError> {
    if version_gt(h.version, INITIAL_VERSION)
        && !version_gt(h.version, INTERPRETER_60_VERSION)
        && !h.unparsed_bytes.is_empty()
    {
        return Err(WriteError::InvalidData(format!(
            "unparsed_bytes must be empty for header version 2-4 (got version {} with {} byte(s))",
            h.version,
            h.unparsed_bytes.len()
        )));
    }
    if version_gt(h.version, INITIAL_VERSION) && h.unparsed_bytes.len() > u8::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "header unparsed_bytes too long for Scala wire format: {} bytes (max 255)",
            h.unparsed_bytes.len()
        )));
    }
    Ok(())
}

/// Serialize a full header (with PoW solution).
pub fn write_header(w: &mut VlqWriter, h: &Header) -> Result<(), WriteError> {
    write_header_without_pow(w, h)?;
    write_solution(w, &h.solution)?;
    Ok(())
}

/// Serialize header fields **without** the PoW solution. Matches Scala's
/// `HeaderSerializer.serializeWithoutPow` — used to compute the message
/// the miner hashes (`msgByHeader = Blake2b256(bytesWithoutPow(header))`).
pub fn write_header_without_pow(w: &mut VlqWriter, h: &Header) -> Result<(), WriteError> {
    check_header_bounds(h)?;
    w.put_u8(h.version);
    w.put_bytes(h.parent_id.as_bytes());
    w.put_bytes(h.ad_proofs_root.as_bytes());
    w.put_bytes(h.transactions_root.as_bytes());
    w.put_bytes(h.state_root.as_bytes());
    w.put_u64(h.timestamp);
    w.put_bytes(h.extension_root.as_bytes());
    write_nbits(w, h.n_bits);
    w.put_u32(h.height);
    w.put_bytes(&h.votes);

    if version_gt(h.version, INITIAL_VERSION) {
        w.put_u8(h.unparsed_bytes.len() as u8);
        w.put_bytes(&h.unparsed_bytes);
    }
    Ok(())
}

/// Convenience wrapper around [`write_header_without_pow`] that returns
/// the bytes directly. Matches Scala's `HeaderSerializer.bytesWithoutPow`.
pub fn serialize_header_without_pow(h: &Header) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    write_header_without_pow(&mut w, h)?;
    Ok(w.result())
}

/// Decode a full header (with PoW solution) from `r`.
///
/// For versions 2-4 the trailing `unparsed_bytes` payload is read but
/// **discarded** — the returned `Header.unparsed_bytes` is always empty.
/// For v5+ (anything `> INTERPRETER_60_VERSION`) the bytes are
/// preserved verbatim so unknown future fields round-trip.
pub fn read_header(r: &mut VlqReader) -> Result<Header, ReadError> {
    let version = r.get_u8()?;
    let parent_id = ModifierId::from_bytes(r.get_array::<32>()?);
    let ad_proofs_root = Digest32::from_bytes(r.get_array::<32>()?);
    let transactions_root = Digest32::from_bytes(r.get_array::<32>()?);
    let state_root = ADDigest::from_bytes(r.get_array::<33>()?);
    let timestamp = r.get_u64()?;
    let extension_root = Digest32::from_bytes(r.get_array::<32>()?);
    let n_bits = read_nbits(r)?;
    let height = r.get_u32_exact()?;
    let votes: [u8; 3] = r.get_array::<3>()?;

    let unparsed_bytes = if version_gt(version, INITIAL_VERSION) {
        let len = r.get_u8()? as usize;
        let bytes = r.get_bytes(len)?;
        if version_gt(version, INTERPRETER_60_VERSION) {
            bytes.to_vec()
        } else {
            // v2-v4 emit the bytes on the wire but drop them on read,
            // matching Scala's HeaderSerializer.parseBody.
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let solution = read_solution(r, version)?;

    Ok(Header {
        version,
        parent_id,
        ad_proofs_root,
        transactions_root,
        state_root,
        timestamp,
        extension_root,
        n_bits,
        height,
        votes,
        unparsed_bytes,
        solution,
    })
}

/// Serialize a full header and compute its identifier
/// (`Blake2b256(serialized_bytes)`). Returns both, since callers usually
/// want the bytes for transmission and the id for indexing.
pub fn serialize_header(h: &Header) -> Result<(Vec<u8>, ModifierId), WriteError> {
    let mut w = VlqWriter::new();
    write_header(&mut w, h)?;
    let bytes = w.result();
    let id: ModifierId = blake2b256(&bytes).into();
    Ok((bytes, id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::group_element::GroupElement;

    // ----- round-trips -----

    #[test]
    fn header_v2_roundtrips() {
        let header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0x01; 32]),
            ad_proofs_root: Digest32::from_bytes([0x02; 32]),
            transactions_root: Digest32::from_bytes([0x03; 32]),
            state_root: ADDigest::from_bytes([0x04; 33]),
            timestamp: 1_672_531_200_000,
            extension_root: Digest32::from_bytes([0x05; 32]),
            n_bits: 0x1a01_7660,
            height: 500_000,
            votes: [0x00, 0x00, 0x00],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        };
        let (bytes, id) = serialize_header(&header).unwrap();
        let mut r = VlqReader::new(&bytes);
        let decoded = read_header(&mut r).unwrap();
        assert!(r.is_empty());
        let (rebytes, reid) = serialize_header(&decoded).unwrap();
        assert_eq!(bytes, rebytes, "roundtrip must be byte-identical");
        assert_eq!(id, reid);
    }

    #[test]
    fn header_v1_roundtrips() {
        let header = Header {
            version: 1,
            parent_id: ModifierId::from_bytes([0x01; 32]),
            ad_proofs_root: Digest32::from_bytes([0x02; 32]),
            transactions_root: Digest32::from_bytes([0x03; 32]),
            state_root: ADDigest::from_bytes([0x04; 33]),
            timestamp: 1_672_531_200_000,
            extension_root: Digest32::from_bytes([0x05; 32]),
            n_bits: 0x1a01_7660,
            height: 100_000,
            votes: [0x01, 0x00, 0x00],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V1 {
                pk: GroupElement::from_bytes([0x02; 33]),
                w: GroupElement::from_bytes([0x03; 33]),
                nonce: [0xBB; 8],
                d: vec![0x01, 0x02, 0x03],
            },
        };
        let (bytes, _id) = serialize_header(&header).unwrap();
        let mut r = VlqReader::new(&bytes);
        let decoded = read_header(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_v5_preserves_unparsed_bytes() {
        let header = Header {
            version: 5,
            parent_id: ModifierId::from_bytes([0x01; 32]),
            ad_proofs_root: Digest32::from_bytes([0x02; 32]),
            transactions_root: Digest32::from_bytes([0x03; 32]),
            state_root: ADDigest::from_bytes([0x04; 33]),
            timestamp: 1_672_531_200_000,
            extension_root: Digest32::from_bytes([0x05; 32]),
            n_bits: 0x1a01_7660,
            height: 900_000,
            votes: [0x00, 0x00, 0x00],
            unparsed_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xCC; 8],
            },
        };
        let (bytes, _id) = serialize_header(&header).unwrap();
        let mut r = VlqReader::new(&bytes);
        let decoded = read_header(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_version_above_127_uses_signed_unparsed_gate() {
        // Scala reads the version as a SIGNED `Byte`: 195 == -61, which is NOT
        // `> InitialVersion(1)`, so a v195 header has NO unparsed_bytes section
        // on the wire. The discriminator vs an unsigned gate is byte LAYOUT:
        // under unsigned (`195 > 1`) the writer would add a 1-byte length field;
        // under signed it must not. So a v195 header's bytes-without-pow length
        // must equal a v1 header's (neither has the section), and be one byte
        // shorter than a v2 header (which does). This test fails under the old
        // unsigned comparison.
        let hdr = |version: u8| Header {
            version,
            parent_id: ModifierId::from_bytes([0x01; 32]),
            ad_proofs_root: Digest32::from_bytes([0x02; 32]),
            transactions_root: Digest32::from_bytes([0x03; 32]),
            state_root: ADDigest::from_bytes([0x04; 33]),
            timestamp: 1_672_531_200_000,
            extension_root: Digest32::from_bytes([0x05; 32]),
            n_bits: 0x1a01_7660,
            height: 123_456,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        };
        let len_v1 = serialize_header_without_pow(&hdr(1)).unwrap().len();
        let len_v2 = serialize_header_without_pow(&hdr(2)).unwrap().len();
        let len_v195 = serialize_header_without_pow(&hdr(195)).unwrap().len();
        assert_eq!(
            len_v195, len_v1,
            "v>127 must use the signed gate (no unparsed-bytes section), matching v1 layout",
        );
        assert_eq!(
            len_v2,
            len_v1 + 1,
            "v2 carries a 1-byte unparsed-bytes length field (sanity for the discriminator)",
        );

        // Full round-trip is byte-stable under the signed gate.
        let (bytes, _id) = serialize_header(&hdr(195)).unwrap();
        let mut r = VlqReader::new(&bytes);
        let decoded = read_header(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(hdr(195), decoded);
    }

    #[test]
    fn header_v3_discards_unparsed_bytes_on_read() {
        // v3 writes a length byte + content, but read discards content and returns empty
        let mut w = VlqWriter::new();
        // Write a v3 header manually with non-empty unparsed_bytes in the wire format
        w.put_u8(3); // version
        w.put_bytes(&[0x01; 32]); // parent_id
        w.put_bytes(&[0x02; 32]); // ad_proofs_root
        w.put_bytes(&[0x03; 32]); // transactions_root
        w.put_bytes(&[0x04; 33]); // state_root
        w.put_u64(1_000_000); // timestamp
        w.put_bytes(&[0x05; 32]); // extension_root
        write_nbits(&mut w, 0x1a01_7660); // n_bits
        w.put_u32(200_000); // height
        w.put_bytes(&[0x00; 3]); // votes
                                 // unparsed_bytes: length=2, content=0xDE 0xAD (versions 2-4 discard content on read)
        w.put_u8(2);
        w.put_bytes(&[0xDE, 0xAD]);
        // AutolykosSolution V2 (version > 1)
        w.put_bytes(&[0x02; 33]); // pk
        w.put_bytes(&[0xBB; 8]); // nonce

        let wire = w.result();
        let mut r = VlqReader::new(&wire);
        let decoded = read_header(&mut r).unwrap();
        assert!(r.is_empty());
        // Content must be discarded for versions 2-4
        assert_eq!(decoded.unparsed_bytes, vec![] as Vec<u8>);
    }

    #[test]
    fn header_id_is_blake2b256_of_bytes() {
        let header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0xAB; 32]),
            ad_proofs_root: Digest32::from_bytes([0x00; 32]),
            transactions_root: Digest32::from_bytes([0x00; 32]),
            state_root: ADDigest::from_bytes([0x00; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0x00; 32]),
            n_bits: 0x1a01_7660,
            height: 1,
            votes: [0x00; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0x00; 8],
            },
        };
        let (bytes, id) = serialize_header(&header).unwrap();
        let expected_id: ModifierId = blake2b256(&bytes).into();
        assert_eq!(id, expected_id);
    }

    // ----- error paths -----

    fn synthetic_header_with(version: u8, unparsed: Vec<u8>) -> Header {
        Header {
            version,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 0x1a01_7660,
            height: 1,
            votes: [0; 3],
            unparsed_bytes: unparsed,
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    #[test]
    fn header_v3_with_unparsed_bytes_returns_invalid_data() {
        // v2-4 must not carry unparsed_bytes: the read side discards
        // them, so writing non-empty bytes here would silently desync
        // the header_id from a round-tripped copy.
        let h = synthetic_header_with(3, vec![0xDE, 0xAD]);
        let mut w = VlqWriter::new();
        let err = write_header(&mut w, &h).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("version 3"),
            "msg should name version, got: {msg}"
        );
        assert!(msg.contains("2-4"), "msg should name range, got: {msg}");

        // write_header_without_pow must reject the same case — otherwise
        // PoW-message bytes can disagree with header-id bytes, a
        // consensus-class drift.
        let mut w2 = VlqWriter::new();
        let err2 = write_header_without_pow(&mut w2, &h).unwrap_err();
        assert!(matches!(err2, WriteError::InvalidData(_)));
    }

    #[test]
    fn header_v5_with_unparsed_bytes_above_255_returns_invalid_data() {
        // v5+ preserves unparsed_bytes verbatim — but the on-wire length
        // byte is still `u8`, so >255 bytes would silently wrap.
        let h = synthetic_header_with(5, vec![0u8; 256]);
        let mut w = VlqWriter::new();
        let err = write_header(&mut w, &h).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(msg.contains("256"), "msg should name length, got: {msg}");
        assert!(msg.contains("max 255"), "msg should name cap, got: {msg}");
    }

    #[test]
    fn serialize_header_and_without_pow_share_failure_modes() {
        // Both helpers must fail (or succeed) on the same Header. If
        // they disagreed, a caller could compute a PoW message hash
        // whose corresponding header_id path errors, leaving a
        // header_id-less "valid" PoW message.
        let h = synthetic_header_with(3, vec![0x42]);
        assert!(serialize_header(&h).is_err());
        assert!(serialize_header_without_pow(&h).is_err());

        let h_ok = synthetic_header_with(3, vec![]);
        assert!(serialize_header(&h_ok).is_ok());
        assert!(serialize_header_without_pow(&h_ok).is_ok());
    }
}
