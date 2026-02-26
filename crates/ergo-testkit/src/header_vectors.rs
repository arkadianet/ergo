//! Golden test vectors from the Ergo mainnet.
//!
//! These vectors validate our header parser, header ID computation, and
//! Autolykos v2 PoW verification against real blockchain data.
//!
//! Each vector was obtained from the Ergo Explorer API at
//! `https://api.ergoplatform.com/api/v1/blocks/{headerId}`.

#[cfg(test)]
mod tests {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    use ergo_consensus::autolykos;
    use ergo_types::header::{AutolykosSolution, Header};
    use ergo_types::modifier_id::{ADDigest, Digest32, ModifierId};
    use ergo_wire::header_ser;

    type Blake2b256 = Blake2b<U32>;

    /// Helper: decode a hex string into a fixed-size array.
    fn hex_to_array<const N: usize>(hex_str: &str) -> [u8; N] {
        let bytes = hex::decode(hex_str).expect("valid hex");
        assert_eq!(
            bytes.len(),
            N,
            "expected {} bytes, got {} for hex: {}",
            N,
            bytes.len(),
            hex_str
        );
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        arr
    }

    /// Compute blake2b-256 hash of the input.
    fn blake2b256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    // -----------------------------------------------------------------------
    // Vector 1: Mainnet block at height 500,001 (Autolykos v2)
    // Explorer: https://api.ergoplatform.com/api/v1/blocks/927eb4b99a3d725e2c503c1ee9f601149cea3932958081956c5af7127722ad28
    // -----------------------------------------------------------------------

    fn mainnet_header_500001() -> Header {
        Header {
            version: 2,
            parent_id: ModifierId(hex_to_array(
                "0261b8bbe791aa26379c679e22359d21a92bda09abd369b938946d0128eed660",
            )),
            ad_proofs_root: Digest32(hex_to_array(
                "c8e78371ef52ae0662e97026a982af6aecce782e85d568f2dfd59efee606267c",
            )),
            transactions_root: Digest32(hex_to_array(
                "aebd3c318e1b0de0e1bcf1f9201bd0e99b5cb1418e8f877baefe332bd3548160",
            )),
            state_root: ADDigest(hex_to_array(
                "93c0a548ec4ee8a3596e02455adab35dae331e7c7defcadfc95a46788a9cb97715",
            )),
            timestamp: 1_622_316_376_238,
            extension_root: Digest32(hex_to_array(
                "5b1b7be58974721b508c7f7796f5fc7fca9b241449961e564429902554be6fc8",
            )),
            n_bits: 117_919_008, // 0x07069D20
            height: 500_001,
            votes: [0, 0, 0],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: hex_to_array(
                    "02b3a06d6eaa8671431ba1db4dd427a77f75a5c2acbd71bfb725d38adc2b55f669",
                ),
                w: [0u8; 33], // v2: not serialized on wire
                nonce: hex_to_array("906d3e6e46ac9ede"),
                d: Vec::new(), // v2: not serialized on wire
            },
        }
    }

    /// Known header ID for block 500,001 from the Ergo explorer.
    const HEADER_500001_ID: &str =
        "927eb4b99a3d725e2c503c1ee9f601149cea3932958081956c5af7127722ad28";

    // -----------------------------------------------------------------------
    // Vector 2: Mainnet block at height 800,000 (Autolykos v2)
    // Explorer: https://api.ergoplatform.com/api/v1/blocks/cde4d7496950b3051dac889582920ee9068e46ab3c181f1bee8d0e4ac3b564e2
    // -----------------------------------------------------------------------

    fn mainnet_header_800000() -> Header {
        Header {
            version: 2,
            parent_id: ModifierId(hex_to_array(
                "b49c242a439bb9fe75ca056f2a6003988a66e9d089842b1c2a168f4bb74c5ce0",
            )),
            ad_proofs_root: Digest32(hex_to_array(
                "5cf31166a531ae783ea4ec0e4c32a24ca0a8a2f838d36323ddb34f5f056c5c56",
            )),
            transactions_root: Digest32(hex_to_array(
                "a32c6ab2f33bbfe63b10efb6936f305dec24a67bdf6bf347b6084bcb6b7dd2c0",
            )),
            state_root: ADDigest(hex_to_array(
                "4b710894ce0371162fdba9f4cb864c87d45d8d46d70ac6ee20d5a470195bda9c19",
            )),
            timestamp: 1_658_612_970_023,
            extension_root: Digest32(hex_to_array(
                "9dd5917d7fa019a35732f43d543b7d06b007e663feca4cacf15e3df40b856bc1",
            )),
            n_bits: 117_711_961, // 0x07040459
            height: 800_000,
            votes: [8, 0, 0],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: hex_to_array(
                    "02eeec374f4e660e117fccbfec79e6fe5cdf44ac508fa228bfc654d2973f9bdc9a",
                ),
                w: [0u8; 33], // v2: not serialized on wire
                nonce: hex_to_array("4051c8071787541d"),
                d: Vec::new(), // v2: not serialized on wire
            },
        }
    }

    /// Known header ID for block 800,000 from the Ergo explorer.
    const HEADER_800000_ID: &str =
        "cde4d7496950b3051dac889582920ee9068e46ab3c181f1bee8d0e4ac3b564e2";

    // -----------------------------------------------------------------------
    // Test: Header ID computation (blake2b256 of full serialized header)
    // -----------------------------------------------------------------------

    #[test]
    fn header_500001_id_matches_explorer() {
        let header = mainnet_header_500001();
        let serialized = header_ser::serialize_header(&header);
        let computed_id = blake2b256(&serialized);
        let expected_id = hex::decode(HEADER_500001_ID).unwrap();
        assert_eq!(
            computed_id.as_slice(),
            expected_id.as_slice(),
            "header ID mismatch for block 500,001.\n  expected: {}\n  computed: {}",
            HEADER_500001_ID,
            hex::encode(computed_id),
        );
    }

    #[test]
    fn header_800000_id_matches_explorer() {
        let header = mainnet_header_800000();
        let serialized = header_ser::serialize_header(&header);
        let computed_id = blake2b256(&serialized);
        let expected_id = hex::decode(HEADER_800000_ID).unwrap();
        assert_eq!(
            computed_id.as_slice(),
            expected_id.as_slice(),
            "header ID mismatch for block 800,000.\n  expected: {}\n  computed: {}",
            HEADER_800000_ID,
            hex::encode(computed_id),
        );
    }

    // -----------------------------------------------------------------------
    // Test: Roundtrip serialization (serialize -> parse -> re-serialize)
    // -----------------------------------------------------------------------

    #[test]
    fn header_500001_roundtrip() {
        let header = mainnet_header_500001();
        let serialized = header_ser::serialize_header(&header);
        let parsed =
            header_ser::parse_header(&serialized).expect("parse mainnet header 500001");
        let reserialized = header_ser::serialize_header(&parsed);
        assert_eq!(
            serialized, reserialized,
            "roundtrip serialization mismatch for block 500,001"
        );
    }

    #[test]
    fn header_800000_roundtrip() {
        let header = mainnet_header_800000();
        let serialized = header_ser::serialize_header(&header);
        let parsed =
            header_ser::parse_header(&serialized).expect("parse mainnet header 800000");
        let reserialized = header_ser::serialize_header(&parsed);
        assert_eq!(
            serialized, reserialized,
            "roundtrip serialization mismatch for block 800,000"
        );
    }

    // -----------------------------------------------------------------------
    // Test: Parsed header fields match known values
    // -----------------------------------------------------------------------

    #[test]
    fn header_500001_parsed_fields() {
        let header = mainnet_header_500001();
        let serialized = header_ser::serialize_header(&header);
        let parsed =
            header_ser::parse_header(&serialized).expect("parse mainnet header 500001");

        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.height, 500_001);
        assert_eq!(parsed.timestamp, 1_622_316_376_238);
        assert_eq!(parsed.n_bits, 117_919_008);
        assert_eq!(parsed.votes, [0, 0, 0]);
        assert_eq!(parsed.parent_id, header.parent_id);
        assert_eq!(parsed.ad_proofs_root, header.ad_proofs_root);
        assert_eq!(parsed.transactions_root, header.transactions_root);
        assert_eq!(parsed.state_root, header.state_root);
        assert_eq!(parsed.extension_root, header.extension_root);
        assert_eq!(parsed.pow_solution.miner_pk, header.pow_solution.miner_pk);
        assert_eq!(parsed.pow_solution.nonce, header.pow_solution.nonce);
    }

    #[test]
    fn header_800000_parsed_fields() {
        let header = mainnet_header_800000();
        let serialized = header_ser::serialize_header(&header);
        let parsed =
            header_ser::parse_header(&serialized).expect("parse mainnet header 800000");

        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.height, 800_000);
        assert_eq!(parsed.timestamp, 1_658_612_970_023);
        assert_eq!(parsed.n_bits, 117_711_961);
        assert_eq!(parsed.votes, [8, 0, 0]);
        assert_eq!(parsed.parent_id, header.parent_id);
        assert_eq!(parsed.pow_solution.miner_pk, header.pow_solution.miner_pk);
        assert_eq!(parsed.pow_solution.nonce, header.pow_solution.nonce);
    }

    // -----------------------------------------------------------------------
    // Test: Autolykos v2 PoW verification
    // -----------------------------------------------------------------------

    #[test]
    fn header_500001_pow_valid() {
        let header = mainnet_header_500001();
        autolykos::validate_pow(&header)
            .expect("PoW validation should pass for mainnet block 500,001");
    }

    #[test]
    fn header_800000_pow_valid() {
        let header = mainnet_header_800000();
        autolykos::validate_pow(&header)
            .expect("PoW validation should pass for mainnet block 800,000");
    }

    // -----------------------------------------------------------------------
    // Test: Deterministic serialization
    // -----------------------------------------------------------------------

    #[test]
    fn serialization_is_deterministic() {
        let header = mainnet_header_500001();
        let bytes1 = header_ser::serialize_header(&header);
        let bytes2 = header_ser::serialize_header(&header);
        assert_eq!(bytes1, bytes2, "serialization should be deterministic");
    }

    // -----------------------------------------------------------------------
    // Test: Tampered header fails PoW
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_nonce_fails_pow() {
        let mut header = mainnet_header_500001();
        // Flip a nonce byte — should invalidate PoW
        header.pow_solution.nonce[0] ^= 0xFF;
        let result = autolykos::validate_pow(&header);
        assert!(
            result.is_err(),
            "PoW should fail for a tampered nonce"
        );
    }

    #[test]
    fn tampered_timestamp_fails_pow() {
        let mut header = mainnet_header_800000();
        // Change timestamp — should invalidate PoW since msg changes
        header.timestamp += 1;
        let result = autolykos::validate_pow(&header);
        assert!(
            result.is_err(),
            "PoW should fail for a tampered timestamp"
        );
    }
}
