//! Binary serialization of Ergo block headers, matching `HeaderSerializer.scala`.

use ergo_types::header::{AutolykosSolution, Header, INITIAL_VERSION};
use ergo_types::modifier_id::{ADDigest, Digest32, ModifierId};

use crate::vlq::{get_uint, get_ulong, put_uint, put_ulong, CodecError};

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize the header fields that come before the PoW solution.
///
/// This is the exact byte sequence used as input to blake2b256 for computing
/// the header ID and for the PoW challenge message.
pub fn serialize_header_without_pow(h: &Header) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // version: 1 byte
    buf.push(h.version);

    // parentId: 32 bytes
    buf.extend_from_slice(&h.parent_id.0);

    // ADProofsRoot: 32 bytes
    buf.extend_from_slice(&h.ad_proofs_root.0);

    // transactionsRoot: 32 bytes
    buf.extend_from_slice(&h.transactions_root.0);

    // stateRoot: 33 bytes
    buf.extend_from_slice(&h.state_root.0);

    // timestamp: VLQ unsigned (putULong)
    put_ulong(&mut buf, h.timestamp);

    // extensionRoot: 32 bytes
    buf.extend_from_slice(&h.extension_root.0);

    // nBits: 4 bytes big-endian (DifficultySerializer in Scala writes raw BE u32)
    buf.extend_from_slice(&(h.n_bits as u32).to_be_bytes());

    // height: VLQ unsigned (putUInt)
    put_uint(&mut buf, h.height);

    // votes: 3 bytes
    buf.extend_from_slice(&h.votes);

    // For version > 1: unparsed_bytes length (1 byte) + unparsed_bytes
    if h.version > INITIAL_VERSION {
        buf.push(h.unparsed_bytes.len() as u8);
        buf.extend_from_slice(&h.unparsed_bytes);
    }

    buf
}

/// Serialize a complete Ergo block header (fields + PoW solution).
pub fn serialize_header(h: &Header) -> Vec<u8> {
    let mut buf = serialize_header_without_pow(h);
    serialize_pow_solution(&mut buf, h.version, &h.pow_solution);
    buf
}

/// Serialize the Autolykos PoW solution.
///
/// - v1: pk(33) + w(33) + nonce(8) + d_len(1 byte UByte) + d(variable)
/// - v2+: pk(33) + nonce(8)
fn serialize_pow_solution(buf: &mut Vec<u8>, version: u8, sol: &AutolykosSolution) {
    // miner_pk: always 33 bytes
    buf.extend_from_slice(&sol.miner_pk);

    if version == INITIAL_VERSION {
        // v1: w(33) + nonce(8) + d_len(1) + d
        buf.extend_from_slice(&sol.w);
        buf.extend_from_slice(&sol.nonce);
        buf.push(sol.d.len() as u8);
        buf.extend_from_slice(&sol.d);
    } else {
        // v2+: nonce(8) only (no w, no d)
        buf.extend_from_slice(&sol.nonce);
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a complete Ergo block header from its serialized bytes.
pub fn parse_header(data: &[u8]) -> Result<Header, CodecError> {
    let reader = &mut &data[..];

    // version: 1 byte
    let version = read_byte(reader)?;

    // parentId: 32 bytes
    let parent_id = ModifierId(read_array::<32>(reader)?);

    // ADProofsRoot: 32 bytes
    let ad_proofs_root = Digest32(read_array::<32>(reader)?);

    // transactionsRoot: 32 bytes
    let transactions_root = Digest32(read_array::<32>(reader)?);

    // stateRoot: 33 bytes
    let state_root = ADDigest(read_array::<33>(reader)?);

    // timestamp: VLQ unsigned
    let timestamp = get_ulong(reader)?;

    // extensionRoot: 32 bytes
    let extension_root = Digest32(read_array::<32>(reader)?);

    // nBits: 4 bytes big-endian (DifficultySerializer in Scala reads raw BE u32)
    let n_bits_bytes = read_array::<4>(reader)?;
    let n_bits = u32::from_be_bytes(n_bits_bytes) as u64;

    // height: VLQ unsigned (putUInt)
    let height = get_uint(reader)?;

    // votes: 3 bytes
    let votes_arr = read_array::<3>(reader)?;

    // For version > 1: unparsed_bytes length (1 byte) + unparsed_bytes
    let unparsed_bytes = if version > INITIAL_VERSION {
        let len = read_byte(reader)? as usize;
        read_bytes(reader, len)?
    } else {
        Vec::new()
    };

    // PoW solution
    let pow_solution = parse_pow_solution(reader, version)?;

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
        votes: votes_arr,
        unparsed_bytes,
        pow_solution,
    })
}

/// Parse the Autolykos PoW solution from the reader.
fn parse_pow_solution(reader: &mut &[u8], version: u8) -> Result<AutolykosSolution, CodecError> {
    // miner_pk: always 33 bytes
    let miner_pk = read_array::<33>(reader)?;

    if version == INITIAL_VERSION {
        // v1: w(33) + nonce(8) + d_len(1) + d
        let w = read_array::<33>(reader)?;
        let nonce = read_array::<8>(reader)?;
        let d_len = read_byte(reader)? as usize;
        let d = read_bytes(reader, d_len)?;

        Ok(AutolykosSolution {
            miner_pk,
            w,
            nonce,
            d,
        })
    } else {
        // v2+: nonce(8) only
        let nonce = read_array::<8>(reader)?;

        Ok(AutolykosSolution {
            miner_pk,
            w: [0u8; 33],
            nonce,
            d: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Low-level reader helpers
// ---------------------------------------------------------------------------

fn read_byte(reader: &mut &[u8]) -> Result<u8, CodecError> {
    if reader.is_empty() {
        return Err(CodecError::UnexpectedEof);
    }
    let b = reader[0];
    *reader = &reader[1..];
    Ok(b)
}

fn read_array<const N: usize>(reader: &mut &[u8]) -> Result<[u8; N], CodecError> {
    if reader.len() < N {
        return Err(CodecError::UnexpectedEof);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&reader[..N]);
    *reader = &reader[N..];
    Ok(arr)
}

fn read_bytes(reader: &mut &[u8], len: usize) -> Result<Vec<u8>, CodecError> {
    if reader.len() < len {
        return Err(CodecError::UnexpectedEof);
    }
    let data = reader[..len].to_vec();
    *reader = &reader[len..];
    Ok(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::{AutolykosSolution, Header};
    use ergo_types::modifier_id::{ADDigest, Digest32, ModifierId};

    fn test_header_v2() -> Header {
        Header {
            version: 2,
            parent_id: ModifierId([0xAA; 32]),
            ad_proofs_root: Digest32([0xBB; 32]),
            transactions_root: Digest32([0xCC; 32]),
            state_root: ADDigest([0xDD; 33]),
            timestamp: 1_700_000_000_000,
            extension_root: Digest32([0xEE; 32]),
            n_bits: 117_440_512, // example nBits
            height: 1000,
            votes: [0, 0, 0],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: [0x02; 33],
                w: [0u8; 33],
                nonce: [0xFF; 8],
                d: Vec::new(),
            },
        }
    }

    #[test]
    fn header_v2_roundtrip() {
        let h = test_header_v2();
        let bytes = serialize_header(&h);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.version, h.version);
        assert_eq!(parsed.parent_id, h.parent_id);
        assert_eq!(parsed.timestamp, h.timestamp);
        assert_eq!(parsed.height, h.height);
        assert_eq!(parsed.n_bits, h.n_bits);
        assert_eq!(parsed.votes, h.votes);
        assert_eq!(parsed.pow_solution.miner_pk, h.pow_solution.miner_pk);
        assert_eq!(parsed.pow_solution.nonce, h.pow_solution.nonce);
    }

    #[test]
    fn serialize_without_pow_excludes_solution() {
        let h = test_header_v2();
        let full = serialize_header(&h);
        let without_pow = serialize_header_without_pow(&h);
        // Full includes pow solution bytes, without_pow doesn't
        assert!(full.len() > without_pow.len());
        // without_pow should be a prefix of full (before pow)
        assert_eq!(&full[..without_pow.len()], &without_pow[..]);
    }

    #[test]
    fn header_v1_roundtrip() {
        let h = Header {
            version: 1,
            parent_id: ModifierId([0x11; 32]),
            ad_proofs_root: Digest32([0x22; 32]),
            transactions_root: Digest32([0x33; 32]),
            state_root: ADDigest([0x44; 33]),
            timestamp: 1_600_000_000_000,
            extension_root: Digest32([0x55; 32]),
            n_bits: 100_000_000,
            height: 500,
            votes: [1, 2, 3],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: [0x03; 33],
                w: [0x02; 33],
                nonce: [0xAB; 8],
                d: vec![0x01, 0x02, 0x03],
            },
        };
        let bytes = serialize_header(&h);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.pow_solution.w, h.pow_solution.w);
        assert_eq!(parsed.pow_solution.d, h.pow_solution.d);
    }

    #[test]
    fn v1_no_unparsed_bytes() {
        // v1 headers should not serialize/parse unparsed_bytes
        let h = Header {
            version: 1,
            parent_id: ModifierId([0x00; 32]),
            ad_proofs_root: Digest32([0x00; 32]),
            transactions_root: Digest32([0x00; 32]),
            state_root: ADDigest([0x00; 33]),
            timestamp: 0,
            extension_root: Digest32([0x00; 32]),
            n_bits: 0,
            height: 0,
            votes: [0, 0, 0],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: [0x00; 33],
                w: [0x00; 33],
                nonce: [0x00; 8],
                d: Vec::new(),
            },
        };
        let bytes = serialize_header(&h);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.unparsed_bytes, Vec::<u8>::new());
    }

    #[test]
    fn v2_with_unparsed_bytes() {
        let h = Header {
            version: 2,
            parent_id: ModifierId([0xAA; 32]),
            ad_proofs_root: Digest32([0xBB; 32]),
            transactions_root: Digest32([0xCC; 32]),
            state_root: ADDigest([0xDD; 33]),
            timestamp: 1_700_000_000_000,
            extension_root: Digest32([0xEE; 32]),
            n_bits: 117_440_512,
            height: 1000,
            votes: [0, 0, 0],
            unparsed_bytes: vec![0xF0, 0xF1, 0xF2],
            pow_solution: AutolykosSolution {
                miner_pk: [0x02; 33],
                w: [0u8; 33],
                nonce: [0xFF; 8],
                d: Vec::new(),
            },
        };
        let bytes = serialize_header(&h);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed.unparsed_bytes, vec![0xF0, 0xF1, 0xF2]);
    }

    #[test]
    fn parse_truncated_header_returns_error() {
        let h = test_header_v2();
        let bytes = serialize_header(&h);
        // Truncate to only 10 bytes — should fail
        let result = parse_header(&bytes[..10]);
        assert!(result.is_err());
    }

    #[test]
    fn full_field_equality_v2() {
        let h = test_header_v2();
        let bytes = serialize_header(&h);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn full_field_equality_v1() {
        let h = Header {
            version: 1,
            parent_id: ModifierId([0x11; 32]),
            ad_proofs_root: Digest32([0x22; 32]),
            transactions_root: Digest32([0x33; 32]),
            state_root: ADDigest([0x44; 33]),
            timestamp: 1_600_000_000_000,
            extension_root: Digest32([0x55; 32]),
            n_bits: 100_000_000,
            height: 500,
            votes: [1, 2, 3],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: [0x03; 33],
                w: [0x02; 33],
                nonce: [0xAB; 8],
                d: vec![0x01, 0x02, 0x03],
            },
        };
        let bytes = serialize_header(&h);
        let parsed = parse_header(&bytes).unwrap();
        assert_eq!(parsed, h);
    }
}
