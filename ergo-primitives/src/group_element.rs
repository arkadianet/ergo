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
