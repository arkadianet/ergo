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

/// Read a 33-byte group element AND record it on the reader's sideband so a
/// higher (crypto-capable) layer can curve-check it after parsing. Every
/// deserializer that reads a group element must go through this — that is what
/// makes the curve check complete (the Scala reference curve-checks each point
/// while deserializing; we collect at the same points and validate later).
pub fn read_group_element(
    r: &mut crate::reader::VlqReader,
) -> Result<GroupElement, crate::reader::ReadError> {
    let bytes = r.get_array::<GROUP_ELEMENT_LENGTH>()?;
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
