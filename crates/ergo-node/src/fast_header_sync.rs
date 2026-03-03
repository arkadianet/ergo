//! Fast header sync via chainSlice REST API.

use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;

/// A single header from the chainSlice JSON response.
///
/// The Scala reference node encodes `extensionRoot` as `"extensionHash"` in JSON.
/// We accept both names via `#[serde(alias)]` for compatibility with different API
/// implementations (Scala reference uses `extensionHash`, our Rust node uses `extensionRoot`).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSliceHeader {
    pub id: String,
    pub parent_id: String,
    pub height: u32,
    pub timestamp: u64,
    pub n_bits: u64,
    pub version: u8,
    pub state_root: String,
    pub transactions_root: String,
    #[serde(alias = "extensionRoot")]
    pub extension_hash: String,
    pub ad_proofs_root: String,
    pub pow_solutions: ChainSlicePow,
    pub votes: String,
}

/// PoW solution fields from chainSlice JSON.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSlicePow {
    pub pk: String,
    pub w: String,
    pub n: String,
    pub d: String,
}

/// Convert a chainSlice JSON header into an ergo_types Header.
/// Returns (ModifierId, Header, raw_wire_bytes).
pub fn json_header_to_wire(
    jh: &ChainSliceHeader,
) -> Result<(ModifierId, Header, Vec<u8>), FastSyncError> {
    use blake2::digest::{Update, VariableOutput};
    use ergo_types::header::AutolykosSolution;
    use ergo_types::modifier_id::{ADDigest, Digest32};

    let parent_id_bytes = hex::decode(&jh.parent_id)?;
    let ad_proofs_root_bytes = hex::decode(&jh.ad_proofs_root)?;
    let transactions_root_bytes = hex::decode(&jh.transactions_root)?;
    let state_root_bytes = hex::decode(&jh.state_root)?;
    let extension_root_bytes = hex::decode(&jh.extension_hash)?;
    let votes_bytes = hex::decode(&jh.votes)?;
    let pk_bytes = hex::decode(&jh.pow_solutions.pk)?;
    let w_bytes = hex::decode(&jh.pow_solutions.w)?;
    let n_bytes = hex::decode(&jh.pow_solutions.n)?;

    // d is a decimal BigUint string; convert to unsigned big-endian bytes.
    // Scala uses BigIntegers.asUnsignedByteArray() which does NOT add a leading 0x00.
    let d_bytes = if jh.pow_solutions.d == "0" {
        Vec::new()
    } else {
        use num_bigint::BigUint;
        let d_val: BigUint = jh
            .pow_solutions
            .d
            .parse()
            .map_err(|e| FastSyncError::InvalidField(format!("d: {e}")))?;
        d_val.to_bytes_be()
    };

    let to_32 = |v: &[u8], name: &str| -> Result<[u8; 32], FastSyncError> {
        v.try_into().map_err(|_| {
            FastSyncError::InvalidField(format!("{name}: expected 32 bytes, got {}", v.len()))
        })
    };
    let to_33 = |v: &[u8], name: &str| -> Result<[u8; 33], FastSyncError> {
        v.try_into().map_err(|_| {
            FastSyncError::InvalidField(format!("{name}: expected 33 bytes, got {}", v.len()))
        })
    };

    let header = Header {
        version: jh.version,
        parent_id: ModifierId(to_32(&parent_id_bytes, "parentId")?),
        ad_proofs_root: Digest32(to_32(&ad_proofs_root_bytes, "adProofsRoot")?),
        transactions_root: Digest32(to_32(&transactions_root_bytes, "transactionsRoot")?),
        state_root: ADDigest(to_33(&state_root_bytes, "stateRoot")?),
        timestamp: jh.timestamp,
        extension_root: Digest32(to_32(&extension_root_bytes, "extensionRoot")?),
        n_bits: jh.n_bits,
        height: jh.height,
        votes: votes_bytes
            .as_slice()
            .try_into()
            .map_err(|_| FastSyncError::InvalidField("votes: expected 3 bytes".into()))?,
        unparsed_bytes: Vec::new(),
        pow_solution: AutolykosSolution {
            miner_pk: to_33(&pk_bytes, "pk")?,
            w: to_33(&w_bytes, "w")?,
            nonce: n_bytes
                .as_slice()
                .try_into()
                .map_err(|_| FastSyncError::InvalidField("nonce: expected 8 bytes".into()))?,
            d: d_bytes,
        },
    };

    let raw = ergo_wire::header_ser::serialize_header(&header);

    // Compute header ID = blake2b256(raw).
    let mut hasher = blake2::Blake2bVar::new(32).unwrap();
    hasher.update(&raw);
    let mut id_bytes = [0u8; 32];
    hasher.finalize_variable(&mut id_bytes).unwrap();
    let mid = ModifierId(id_bytes);

    // Verify computed ID matches declared ID.
    let declared_id = hex::decode(&jh.id)?;
    if declared_id.len() == 32 && mid.0.as_slice() != declared_id.as_slice() {
        return Err(FastSyncError::InvalidField(format!(
            "header ID mismatch: computed {} vs declared {}",
            hex::encode(mid.0),
            jh.id
        )));
    }

    Ok((mid, header, raw))
}

/// Errors from the fast sync subsystem.
#[derive(Debug, thiserror::Error)]
pub enum FastSyncError {
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid header field: {0}")]
    InvalidField(String),
    #[error("HTTP request failed: {0}")]
    Http(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real mainnet block 1 header data from the Ergo reference node API.
    /// Field names match the Scala jsonEncoder output (extensionHash, not extensionRoot).
    fn sample_json() -> &'static str {
        r#"{
            "id": "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
            "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 1,
            "timestamp": 1561978977137,
            "nBits": 100734821,
            "version": 1,
            "stateRoot": "18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303",
            "transactionsRoot": "93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba",
            "extensionHash": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            "adProofsRoot": "766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb",
            "powSolutions": {
                "pk": "03be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb66",
                "w": "02da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0",
                "n": "000000030151dc63",
                "d": "46909460813884299753486408728361968139945651324239558400157099627"
            },
            "votes": "000000"
        }"#
    }

    #[test]
    fn parse_chain_slice_json() {
        let jh: ChainSliceHeader = serde_json::from_str(sample_json()).unwrap();
        assert_eq!(jh.height, 1);
        assert_eq!(jh.version, 1);
        assert_eq!(jh.n_bits, 100734821);
    }

    #[test]
    fn parse_chain_slice_json_extension_root_alias() {
        // Our Rust node uses extensionRoot, not extensionHash.
        // Verify the serde alias works.
        let json = r#"{
            "id": "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
            "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 1,
            "timestamp": 1561978977137,
            "nBits": 100734821,
            "version": 1,
            "stateRoot": "18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303",
            "transactionsRoot": "93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba",
            "extensionRoot": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            "adProofsRoot": "766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb",
            "powSolutions": {
                "pk": "03be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb66",
                "w": "02da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0",
                "n": "000000030151dc63",
                "d": "46909460813884299753486408728361968139945651324239558400157099627"
            },
            "votes": "000000"
        }"#;
        let jh: ChainSliceHeader = serde_json::from_str(json).unwrap();
        assert_eq!(
            jh.extension_hash,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn json_header_to_wire_produces_valid_header() {
        let jh: ChainSliceHeader = serde_json::from_str(sample_json()).unwrap();
        let (mid, header, raw) = json_header_to_wire(&jh).unwrap();

        // ID should match the declared id from JSON
        let expected_id = hex::decode(&jh.id).unwrap();
        assert_eq!(mid.0.as_slice(), expected_id.as_slice());

        // Header fields should match JSON
        assert_eq!(header.height, 1);
        assert_eq!(header.version, 1);
        assert_eq!(header.n_bits, 100734821);
        assert_eq!(header.timestamp, 1561978977137);
        assert_eq!(hex::encode(header.votes), "000000");

        // Raw bytes should be non-empty wire-format serialization
        assert!(!raw.is_empty());

        // blake2b256(raw) should equal the declared ID
        use blake2::digest::{Update, VariableOutput};
        let mut hasher = blake2::Blake2bVar::new(32).unwrap();
        hasher.update(&raw);
        let mut hash = [0u8; 32];
        hasher.finalize_variable(&mut hash).unwrap();
        assert_eq!(&hash, mid.0.as_slice());
    }

    #[test]
    fn json_header_to_wire_bad_hex_returns_error() {
        let bad_json = r#"{
            "id": "ZZZZ",
            "parentId": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 1, "timestamp": 0, "nBits": 0, "version": 1,
            "stateRoot": "00", "transactionsRoot": "00", "extensionHash": "00",
            "adProofsRoot": "00",
            "powSolutions": { "pk": "00", "w": "00", "n": "00", "d": "0" },
            "votes": "000000"
        }"#;
        let jh: ChainSliceHeader = serde_json::from_str(bad_json).unwrap();
        assert!(json_header_to_wire(&jh).is_err());
    }
}
