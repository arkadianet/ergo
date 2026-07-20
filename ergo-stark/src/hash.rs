//! The profile hashers used while an activated STARK profile package is
//! authenticated: BLAKE2b-256 (RFC 7693, unkeyed 32-byte digest) and SHA-256.
//!
//! The reference sigmastate carries hand-written platform-neutral
//! implementations (`ProfileBlake2b256`, `ProfileSha256`) only because `core`
//! forbids a JVM crypto provider and must produce identical bytes on Scala.js.
//! In the Rust node we take the CLAUDE.md-mandated path — proven crates only —
//! and delegate to `blake2` and `sha2`, which are standard BLAKE2b-256 and
//! SHA-256 and therefore byte-identical to the reference. The KATs below are
//! the reference's own spec vectors, verifying that equivalence.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use sha2::Sha256;

/// Standard BLAKE2b with a 256-bit (32-byte) output — matches the reference
/// `ProfileBlake2b256` (unkeyed, `fanout = 1`, `depth = 1`).
type Blake2b256 = Blake2b<U32>;

/// BLAKE2b-256 digest of `input` (32 bytes).
pub fn blake2b256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// SHA-256 digest of `input` (32 bytes).
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// `length` bytes of `i & 0xff` — the reference specs' input generator.
    fn incrementing(length: usize) -> Vec<u8> {
        (0..length).map(|i| (i & 0xff) as u8).collect()
    }

    // ----- oracle parity -----

    #[test]
    fn blake2b256_matches_reference_spec_vectors() {
        // From ProfileBlake2b256Spec: input is `length` incrementing bytes.
        let vectors: &[(usize, &str)] = &[
            (
                0,
                "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            ),
            (
                1,
                "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314",
            ),
            (
                127,
                "f2fe67ff342e21b8f45e8f2e0bcd1d9243245d50ee6c78042e9c491388791c72",
            ),
            (
                128,
                "c3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1",
            ),
            (
                129,
                "f7f3c46ba2564ff4c4c162da1f5b605f9f1c4aa6a20652a9f9a337c1a2f5b9c9",
            ),
            (
                255,
                "1d0850ee9bca0abc9601e9deabe1418fedec2fb6ac4150bd5302d2430f9be943",
            ),
            (
                256,
                "39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835",
            ),
        ];
        for (len, expected) in vectors {
            assert_eq!(
                hex::encode(blake2b256(&incrementing(*len))),
                *expected,
                "len={len}"
            );
        }
    }

    #[test]
    fn blake2b256_reference_proposition_matches_scorex_oracle() {
        // The 85-byte proposition KAT from ProfileBlake2b256Spec.
        let proposition = hex::decode(
            "1c53020e20d82a9f903bdb2c7e68dcf15686cf75b3220fe457fa6bc1042529df288de222d8\
             0e2023c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383\
             d1b9e4e3001ae4e3010e73007301",
        )
        .unwrap();
        assert_eq!(proposition.len(), 85);
        assert_eq!(
            hex::encode(blake2b256(&proposition)),
            "d4fde033ba3d2d696696cb7d0e80abd39aa84db8ba93038157338e85aac6f5b8"
        );
    }

    #[test]
    fn sha256_matches_reference_spec_vectors() {
        // From ProfileSha256Spec: FIPS one-shot KATs.
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        // Padding-boundary KATs: `length` incrementing bytes (i as u8).
        let boundaries: &[(usize, &str)] = &[
            (
                55,
                "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
            ),
            (
                56,
                "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
            ),
            (
                63,
                "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
            ),
            (
                64,
                "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
            ),
            (
                65,
                "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
            ),
        ];
        for (len, expected) in boundaries {
            let input: Vec<u8> = (0..*len).map(|i| i as u8).collect();
            assert_eq!(hex::encode(sha256(&input)), *expected, "len={len}");
        }
    }
}
