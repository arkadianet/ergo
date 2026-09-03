/// 33-byte compressed SEC1 encoding of a secp256k1 point.
/// Used for public keys and sigma protocol elements.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GroupElement([u8; 33]);

/// Wire size of a SEC1-compressed secp256k1 point: one parity byte plus
/// the 32-byte X coordinate.
pub const GROUP_ELEMENT_LENGTH: usize = 33;

impl GroupElement {
    /// Wrap an already-encoded SEC1-compressed point. The bytes are not
    /// validated as a valid curve point — callers that need decoded
    /// arithmetic decompress in `ergo-crypto`.
    pub fn from_bytes(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying SEC1-compressed bytes.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

/// The canonical encoding of the group identity: 33 zero bytes.
///
/// Scala `GroupElementSerializer` (`GroupElementSerializer.scala:18`,
/// `:20-33`) writes the infinity point as `Array.fill(33)(0)`.
pub const IDENTITY_ENCODING: [u8; GROUP_ELEMENT_LENGTH] = [0u8; GROUP_ELEMENT_LENGTH];

/// Normalize a 33-byte SEC1 encoding the way Scala's serializer round-trip
/// does.
///
/// `GroupElementSerializer.parse` (`GroupElementSerializer.scala:35-42`) tests
/// only the LEAD byte: `if (encoded(0) != 0) decodePoint(encoded) else
/// CryptoContext.default.infinity`. So EVERY 33-byte sequence starting with
/// `0x00` decodes to the same identity point, whatever the remaining 32 bytes
/// hold — and `serialize` then writes that point back as 33 zeroes
/// (`:21-22`). The reference therefore accepts `07 00 AA..AA` in a register
/// and re-serializes it as `07 00*33`; since a box id is `blake2b256` of the
/// re-serialized box bytes, the id is computed over the ZEROED form.
/// Preserving the original trailing garbage would give such a box a different
/// id than the reference node computes — a UTXO-set / AVL-root divergence on a
/// box the reference accepts.
///
/// A `0x02` / `0x03` compressed encoding needs no normalization: Scala
/// re-encodes it from the decoded affine coordinates, which for any point
/// `decodePoint` accepts reproduces the same 33 bytes. An X coordinate that is
/// not a valid curve point is rejected outright, by `decodePoint` there and by
/// the reader's sideband curve check here.
pub fn canonical_encoding(bytes: [u8; GROUP_ELEMENT_LENGTH]) -> [u8; GROUP_ELEMENT_LENGTH] {
    if bytes[0] == 0x00 {
        IDENTITY_ENCODING
    } else {
        bytes
    }
}

/// Read a 33-byte group element AND record it on the reader's sideband so a
/// higher (crypto-capable) layer can curve-check it after parsing. Every
/// deserializer that reads a group element must go through this — that is what
/// makes the curve check complete (the Scala reference curve-checks each point
/// while deserializing; we collect at the same points and validate later).
///
/// The SEC1 lead byte is validated HERE, byte-exact with Scala
/// `GroupElementSerializer.parse`: that decoder can only produce the identity
/// (`0x00` lead) or a compressed point (`0x02`/`0x03` lead); any other lead is
/// a guaranteed decode failure (its `IllegalArgumentException` is re-raised by
/// `DataSerializer` as a `SerializerException`, which the soft-fork wrap does
/// not catch — so an SHeader constant carrying one rejects the whole tree,
/// SANTA wire/v6 `ErgoTree.sheader_constant_v3_malformed_pk_reject`). The
/// on-curve check for `0x02`/`0x03` points stays deferred to the sideband
/// consumer — that is the documented architecture (crypto-free wire layer);
/// the identity/prefix dimension is enforced at parse because it needs no
/// curve math.
pub fn read_group_element(
    r: &mut crate::reader::VlqReader,
) -> Result<GroupElement, crate::reader::ReadError> {
    let bytes = r.get_array::<GROUP_ELEMENT_LENGTH>()?;
    match bytes[0] {
        0x00 | 0x02 | 0x03 => {}
        other => {
            return Err(crate::reader::ReadError::InvalidData(format!(
                "invalid SEC1 point prefix {other:#04x} — GroupElementSerializer only decodes identity (0x00) or compressed (0x02/0x03)"
            )));
        }
    }
    // Normalize exactly as `GroupElementSerializer.parse` does: a `0x00` lead
    // IS the identity point, whatever follows, and the identity's encoding is
    // 33 zeroes. Storing the verbatim trailing bytes would leak a non-value
    // distinction into box ids, `bytes_to_sign`, and script-level equality —
    // see `canonical_encoding`.
    let bytes = canonical_encoding(bytes);
    r.record_group_element(bytes);
    Ok(GroupElement::from_bytes(bytes))
}

impl std::fmt::Debug for GroupElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupElement({})", hex::encode(self.as_bytes()))
    }
}

impl From<[u8; 33]> for GroupElement {
    fn from(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for GroupElement {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_element_length_const_matches_array_size() {
        assert_eq!(GROUP_ELEMENT_LENGTH, 33);
        let ge = GroupElement::from_bytes([0x02; 33]);
        assert_eq!(ge.as_bytes().len(), 33);
    }
}
