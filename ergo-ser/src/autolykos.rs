use ergo_primitives::group_element::{read_group_element, GroupElement};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

/// Length in bytes of the Autolykos PoW nonce.
pub const NONCE_LENGTH: usize = 8;

/// Autolykos proof-of-work solution. V1 (header version 1) carries an
/// extra group element `w` and a length-prefixed `d` payload that v2
/// drops, so the wire formats are not interchangeable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutolykosSolution {
    /// Header v1 layout — Autolykos v1 with full `pk + w + nonce + d`.
    V1 {
        /// Miner's public key.
        pk: GroupElement,
        /// Auxiliary group element committed alongside `pk`.
        w: GroupElement,
        /// 8-byte mining nonce.
        nonce: [u8; NONCE_LENGTH],
        /// Length-prefixed `d` payload (variable size).
        d: Vec<u8>,
    },
    /// Header v2+ layout — Autolykos v2 with just `pk + nonce`.
    V2 {
        /// Miner's public key.
        pk: GroupElement,
        /// 8-byte mining nonce.
        nonce: [u8; NONCE_LENGTH],
    },
}

impl AutolykosSolution {
    /// Borrow the miner public key, regardless of solution version.
    pub fn pk(&self) -> &GroupElement {
        match self {
            Self::V1 { pk, .. } | Self::V2 { pk, .. } => pk,
        }
    }

    /// Borrow the 8-byte nonce, regardless of solution version.
    pub fn nonce(&self) -> &[u8; NONCE_LENGTH] {
        match self {
            Self::V1 { nonce, .. } | Self::V2 { nonce, .. } => nonce,
        }
    }
}

/// Serialize an Autolykos solution. The variant tag is implicit — callers
/// that consume the bytes must already know whether the matching block
/// header is v1 (Autolykos v1) or v2+ (Autolykos v2).
pub fn write_solution(w: &mut VlqWriter, sol: &AutolykosSolution) -> Result<(), WriteError> {
    match sol {
        AutolykosSolution::V1 {
            pk,
            w: w_elem,
            nonce,
            d,
        } => {
            // Scala writes `d` length as a single unsigned byte
            // (`putUByte`); a longer payload would silently wrap on
            // `as u8` and produce wire bytes the read side rejects.
            // Surface the bound as WriteError so callers building a
            // header from caller-supplied data get a recoverable error.
            if d.len() > u8::MAX as usize {
                return Err(WriteError::InvalidData(format!(
                    "Autolykos V1 d payload too long for Scala wire format: {} bytes (max 255)",
                    d.len()
                )));
            }
            w.put_bytes(pk.as_bytes());
            w.put_bytes(w_elem.as_bytes());
            w.put_bytes(nonce);
            w.put_u8(d.len() as u8);
            w.put_bytes(d);
        }
        AutolykosSolution::V2 { pk, nonce } => {
            w.put_bytes(pk.as_bytes());
            w.put_bytes(nonce);
        }
    }
    Ok(())
}

/// Decode an Autolykos solution from `r`. `block_version == 1` selects
/// the v1 layout; any higher version selects the v2 layout.
pub fn read_solution(r: &mut VlqReader, block_version: u8) -> Result<AutolykosSolution, ReadError> {
    let pk = read_group_element(r)?;

    if block_version == 1 {
        let w = read_group_element(r)?;
        let nonce = r.get_array::<NONCE_LENGTH>()?;
        let d_len = r.get_u8()? as usize;
        let d = r.get_bytes(d_len)?.to_vec();
        Ok(AutolykosSolution::V1 { pk, w, nonce, d })
    } else {
        let nonce = r.get_array::<NONCE_LENGTH>()?;
        Ok(AutolykosSolution::V2 { pk, nonce })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- round-trips -----

    #[test]
    fn solution_v2_roundtrips() {
        let sol = AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0xAA; 8],
        };
        let mut w = VlqWriter::new();
        write_solution(&mut w, &sol).unwrap();
        let data = w.result();
        assert_eq!(data.len(), 33 + 8);
        let mut r = VlqReader::new(&data);
        let decoded = read_solution(&mut r, 2).unwrap();
        assert_eq!(decoded, sol);
    }

    #[test]
    fn solution_v1_roundtrips() {
        let sol = AutolykosSolution::V1 {
            pk: GroupElement::from_bytes([0x02; 33]),
            w: GroupElement::from_bytes([0x03; 33]),
            nonce: [0xBB; 8],
            d: vec![0x01, 0x02, 0x03],
        };
        let mut w = VlqWriter::new();
        write_solution(&mut w, &sol).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_solution(&mut r, 1).unwrap();
        assert_eq!(decoded, sol);
    }

    // ----- error paths -----

    #[test]
    fn solution_v1_d_above_255_returns_invalid_data() {
        // Scala caps the v1 `d` payload length at 255 (single
        // `putUByte`). The writer surfaces a 256-byte payload as
        // `WriteError` so `write_header` (which calls `write_solution`)
        // can propagate the error rather than crash the process.
        let sol = AutolykosSolution::V1 {
            pk: GroupElement::from_bytes([0x02; 33]),
            w: GroupElement::from_bytes([0x03; 33]),
            nonce: [0; 8],
            d: vec![0u8; 256],
        };
        let mut w = VlqWriter::new();
        let err = write_solution(&mut w, &sol).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(msg.contains("256"), "msg should name length, got: {msg}");
        assert!(msg.contains("max 255"), "msg should name cap, got: {msg}");
    }

    // ----- properties -----

    proptest::proptest! {
        /// Round-trip property for AutolykosSolution::V2: for any
        /// 33-byte pk bytes and 8-byte nonce, `read_solution ∘
        /// write_solution` is the identity. V2 is a fixed 41-byte
        /// layout (33 + 8) so the wire-form is deterministic and the
        /// property catches any drift in the field order or length.
        #[test]
        fn proptest_solution_v2_roundtrips(
            pk_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 33..=33),
            nonce_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 8..=8),
        ) {
            let pk_arr: [u8; 33] = pk_bytes.try_into().unwrap();
            let nonce_arr: [u8; 8] = nonce_bytes.try_into().unwrap();
            let sol = AutolykosSolution::V2 {
                pk: GroupElement::from_bytes(pk_arr),
                nonce: nonce_arr,
            };
            let mut w = VlqWriter::new();
            write_solution(&mut w, &sol).unwrap();
            let data = w.result();
            proptest::prop_assert_eq!(data.len(), 41);
            let mut r = VlqReader::new(&data);
            let decoded = read_solution(&mut r, 2).unwrap();
            proptest::prop_assert_eq!(decoded, sol);
        }

        /// Round-trip property for AutolykosSolution::V1 with valid
        /// d-payload length (≤ 255 bytes). V1's wire form is variable
        /// length (33 pk + 33 w + 8 nonce + 1 d_len + d_len bytes).
        /// The 255-cap is exercised by the existing
        /// `solution_v1_d_above_255_returns_invalid_data` regression
        /// test; this property covers everything below the cap.
        #[test]
        fn proptest_solution_v1_roundtrips_within_d_cap(
            pk_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 33..=33),
            w_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 33..=33),
            nonce_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 8..=8),
            d in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=255),
        ) {
            let pk_arr: [u8; 33] = pk_bytes.try_into().unwrap();
            let w_arr: [u8; 33] = w_bytes.try_into().unwrap();
            let nonce_arr: [u8; 8] = nonce_bytes.try_into().unwrap();
            let sol = AutolykosSolution::V1 {
                pk: GroupElement::from_bytes(pk_arr),
                w: GroupElement::from_bytes(w_arr),
                nonce: nonce_arr,
                d,
            };
            let mut writer = VlqWriter::new();
            write_solution(&mut writer, &sol).unwrap();
            let data = writer.result();
            let mut reader = VlqReader::new(&data);
            let decoded = read_solution(&mut reader, 1).unwrap();
            proptest::prop_assert_eq!(decoded, sol);
        }
    }
}
