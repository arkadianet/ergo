use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as Blake2Digest};

/// 32-byte Blake2b-256 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// All-zero digest. Used as a sentinel for empty/uninitialized roots.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Wrap an already-hashed 32-byte value. No copy validation is performed.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest32({})", hex::encode(self.as_bytes()))
    }
}

impl From<[u8; 32]> for Digest32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Digest32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 33-byte authenticated state root (AVL+ tree digest with height byte).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ADDigest([u8; 33]);

impl ADDigest {
    /// Wrap a 33-byte AVL+ root (32-byte digest plus 1-byte tree height).
    pub fn from_bytes(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// AVL+ tree-height byte (the trailing byte of the 33-byte
    /// authenticated digest — `as_bytes()[32]`). Accessor exists so
    /// consumers don't repeat the magic-index pattern at every
    /// cost-model call site.
    pub fn tree_height_byte(&self) -> u8 {
        self.0[32]
    }
}

impl std::fmt::Debug for ADDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ADDigest({})", hex::encode(self.as_bytes()))
    }
}

impl From<[u8; 33]> for ADDigest {
    fn from(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for ADDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Modifier ID — semantically distinct 32-byte identifier for headers,
/// transactions, block sections (extension, ad_proofs,
/// block_transactions). Backed by [`Digest32`] but a real newtype:
/// a function expecting `&ModifierId` does not accept a state-root
/// `Digest32`, AVL-node label, or any other 32-byte hash by accident.
/// Conversion is explicit via `From<Digest32>` / `into()`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModifierId(Digest32);

impl ModifierId {
    /// Wrap an already-hashed 32-byte value.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Digest32(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Borrow the underlying [`Digest32`] when an API explicitly
    /// wants a digest rather than an id.
    pub fn as_digest(&self) -> &Digest32 {
        &self.0
    }
}

impl From<Digest32> for ModifierId {
    fn from(d: Digest32) -> Self {
        Self(d)
    }
}

impl From<[u8; 32]> for ModifierId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for ModifierId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Debug for ModifierId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ModifierId({})", hex::encode(self.as_bytes()))
    }
}

/// Compute Blake2b-256 hash of data.
pub fn blake2b256(data: &[u8]) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Digest32(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    // ----- happy path -----

    /// Known BLAKE2b-256 empty-input vector. The expected hex is the
    /// well-circulated BLAKE2b-256 value for `H("")` and is reproducible
    /// from any conformant BLAKE2b-256 implementation against
    /// `(in = "", key = "" (unkeyed), outlen = 32)` — it is NOT
    /// computed by running our own `blake2b256` function.
    ///
    /// **Not labeled as an official-KAT row.** The BLAKE2 reference
    /// `testvectors/blake2b-kat.txt` file at
    /// <https://github.com/BLAKE2/BLAKE2/tree/master/testvectors> stores
    /// keyed full-length (outlen=64) entries; the unkeyed outlen=32
    /// empty-input row is not literally present in that file under that
    /// shape. Until we cross-reference a source that does literally
    /// publish this exact row, the assertion stays in the "happy path"
    /// section as a known reference value rather than the "oracle
    /// parity" section.
    ///
    /// The mainnet-header oracle in
    /// `blake2b256_matches_published_mainnet_header_ids` (below) is the
    /// crate's load-bearing implementation-independent BLAKE2b-256 pin
    /// against an external source (the Scala node that produced the
    /// header IDs).
    #[test]
    fn blake2b256_of_empty_input_matches_known_vector() {
        let hash = blake2b256(b"");
        assert_eq!(
            hex::encode(hash.as_bytes()),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn blake2b256_is_deterministic_and_input_sensitive() {
        assert_eq!(blake2b256(b"ergo"), blake2b256(b"ergo"));
        assert_ne!(blake2b256(b"ergo"), blake2b256(b"bitcoin"));
    }

    // ----- invariants (load-bearing) -----

    /// **Load-bearing 33-byte-width invariant.** Guards against a
    /// copy/paste bug where `ADDigest` accidentally becomes a 32-byte
    /// newtype (matching `Digest32`) — that would silently drop the
    /// AVL+ tree-height byte and corrupt every `state_root` comparison
    /// in the consensus path. Do not prune this test as "trivial newtype
    /// wrap/unwrap" — the wrap/unwrap is the consensus-critical width
    /// pin.
    #[test]
    fn addigest_from_bytes_preserves_all_33_bytes() {
        let mut bytes = [0u8; 33];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let d = ADDigest::from_bytes(bytes);
        assert_eq!(d.as_bytes().len(), 33);
        assert_eq!(d.as_bytes(), &bytes);
        // Specifically pin the last byte (index 32) survives — that's
        // the byte a 32-byte truncation would lose.
        assert_eq!(d.as_bytes()[32], 32);
    }

    /// Pins `tree_height_byte()` against `as_bytes()[32]` so the
    /// accessor cannot silently drift away from the underlying
    /// representation. Companion to the 33-byte-width invariant
    /// above: consumers (AVL op cost-model paths in `ergo-sigma`)
    /// rely on this byte to compute proof-replay tree height.
    #[test]
    fn addigest_tree_height_byte_returns_index_32() {
        let mut bytes = [0u8; 33];
        bytes[32] = 0xAB;
        let d = ADDigest::from_bytes(bytes);
        assert_eq!(d.tree_height_byte(), 0xAB);
        assert_eq!(d.tree_height_byte(), d.as_bytes()[32]);
    }

    // ----- oracle parity -----

    #[derive(Deserialize)]
    struct OracleVector {
        height: u32,
        header_id: String,
        header_bytes_hex: String,
    }

    #[derive(Deserialize)]
    struct OracleFile {
        vectors: Vec<OracleVector>,
    }

    /// `blake2b256(header_bytes) == header_id` for several mainnet headers.
    /// The single test class that catches divergence from the Scala/sigma
    /// oracle: a self-oracle (`expected = blake2b256(input)`) would pass
    /// even if we and Scala both did the wrong thing — only known-correct
    /// values from the network catch consensus drift.
    ///
    /// Vectors live in `test-vectors/primitives/blake2b256_header_oracle.json`
    /// with provenance metadata; see that file for the source / regen path.
    #[test]
    fn blake2b256_matches_published_mainnet_header_ids() {
        let raw =
            std::fs::read_to_string("../test-vectors/primitives/blake2b256_header_oracle.json")
                .expect("oracle fixture missing");
        let oracle: OracleFile = serde_json::from_str(&raw).expect("oracle fixture malformed");
        assert!(!oracle.vectors.is_empty(), "oracle file must carry vectors");

        for v in &oracle.vectors {
            let header_bytes = hex::decode(&v.header_bytes_hex)
                .unwrap_or_else(|e| panic!("h={}: bad hex bytes: {e}", v.height));
            let expected_id = hex::decode(&v.header_id)
                .unwrap_or_else(|e| panic!("h={}: bad hex id: {e}", v.height));
            let computed = blake2b256(&header_bytes);
            assert_eq!(
                computed.as_bytes(),
                expected_id.as_slice(),
                "blake2b256 disagrees with mainnet header_id at h={}: \
                 expected {} got {}",
                v.height,
                v.header_id,
                hex::encode(computed.as_bytes()),
            );
        }
    }
}
