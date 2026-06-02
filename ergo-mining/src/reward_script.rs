//! Mining reward output ErgoTree builder.
//!
//! Mainnet (Scala `ErgoTreePredef.rewardOutputScript`,
//! `ErgoTreePredef.scala:51-56` in the sigma-state reference):
//!
//! ```scala
//! def rewardOutputScript(delta: Int, minerPk: ProveDlog): ErgoTree = {
//!   ErgoTree.withSegregation(ZeroHeader, SigmaAnd(
//!     GE(Height, Plus(boxCreationHeight(Self), IntConstant(delta))).toSigmaProp,
//!     SigmaPropConstant(minerPk)
//!   ))
//! }
//! ```
//!
//! Logical form: `SigmaAnd(GE(HEIGHT, SELF.creationHeight + delta).toSigmaProp,
//! proveDlog(minerPk))`. Spendable only by the miner's key (proveDlog)
//! AND only after the 720-block (mainnet) maturity gate.
//!
//! Serialized as a constant-segregated ErgoTree with `ZeroHeader` and
//! two segregated constants in this order: `[delta, minerPk]`. Byte
//! layout pinned against 10 real mainnet reward boxes captured from a
//! Scala 6.0.2 node at heights 1,700,000–1,786,180:
//!
//! ```text
//! offset 0:  0x10                              // ZeroHeader + constant-segregation flag
//! offset 1:  0x02                              // 2 segregated constants
//! offset 2:  0x04                              // const[0] type: SInt
//! offset 3:  0xa0 0x0b                         // const[0] value: VLQ-zigzag(720)
//! offset 5:  0x08                              // const[1] type: SSigmaProp
//! offset 6:  0xcd                              // ProveDlog SigmaBoolean op
//! offset 7:  <33-byte compressed secp256k1 pk> // const[1] value: miner's reward pubkey
//! offset 40: 0xea 0x02 0xd1 0x92 0xa3 0x9a     // tree body (SigmaAnd + GE + Plus
//!            0x8c 0xc7 0xa7 0x01 0x73 0x00     //   + boxCreationHeight(Self) +
//!            0x73 0x01                         //   ConstPlaceholder[0] + ConstPlaceholder[1])
//! offset 54: end                               // total 54 bytes
//! ```
//!
//! Only the 33-byte pk slot at offset 7..40 varies between miners.

use crate::error::MiningError;

/// Reward-output ErgoTree byte length with `minerRewardDelay = 720`
/// (the value Scala uses on both mainnet and testnet —
/// `mainnet.conf` and `testnet.conf:48`).
pub const REWARD_SCRIPT_LEN: usize = 54;

/// Byte offset of the miner pubkey inside the serialized reward
/// script. 33-byte compressed secp256k1 point.
const PK_OFFSET: usize = 7;

/// Length of the miner pubkey embedded in the reward script.
const PK_LEN: usize = 33;

/// Constant prefix preceding the miner pubkey in a reward script.
/// Encodes `ZeroHeader + 2 constants + const[0]=SInt(720) +
/// const[1] type tag + ProveDlog SigmaBoolean op`. The embedded 720
/// is `minerRewardDelay` — same on mainnet and testnet.
const REWARD_PREFIX: [u8; PK_OFFSET] = [0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd];

/// Constant suffix following the miner pubkey. Encodes the tree body
/// `SigmaAnd(GE(Height, Plus(boxCreationHeight(Self),
/// ConstantPlaceholder[0])).toSigmaProp, ConstantPlaceholder[1])`.
const REWARD_SUFFIX: [u8; 14] = [
    0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00, 0x73, 0x01,
];

/// Build the consensus mining-reward ErgoTree bytes for a given
/// compressed-secp256k1 miner pubkey, using the canonical
/// `minerRewardDelay = 720` (mainnet and testnet agree).
///
/// The returned bytes are exactly 54 bytes long and match what Scala's
/// `ErgoTreePredef.rewardOutputScript(720, ProveDlog(miner_pk))`
/// produces, byte-for-byte. Verified against 10 real mainnet reward
/// boxes from heights 1,700,000–1,786,180.
///
/// `miner_pk` MUST be a valid 33-byte compressed secp256k1 point (the
/// first byte is `0x02` or `0x03` for the y-parity). This function
/// does not validate the point — that is the caller's responsibility
/// at configuration time. Garbage in produces garbage out (a
/// well-formed ErgoTree whose pubkey decodes to nonsense at script
/// evaluation time).
pub fn reward_output_script(miner_pk: &[u8; PK_LEN]) -> [u8; REWARD_SCRIPT_LEN] {
    let mut bytes = [0u8; REWARD_SCRIPT_LEN];
    bytes[..PK_OFFSET].copy_from_slice(&REWARD_PREFIX);
    bytes[PK_OFFSET..PK_OFFSET + PK_LEN].copy_from_slice(miner_pk);
    bytes[PK_OFFSET + PK_LEN..].copy_from_slice(&REWARD_SUFFIX);
    bytes
}

/// Decode a hex-encoded 33-byte compressed secp256k1 pubkey and call
/// [`reward_output_script`]. Convenience for the
/// [`crate::config::MiningConfig::miner_public_key_hex`] path.
pub fn reward_output_script_from_hex(
    miner_pk_hex: &str,
) -> Result<[u8; REWARD_SCRIPT_LEN], MiningError> {
    let raw =
        hex::decode(miner_pk_hex).map_err(|e| MiningError::InvalidMinerPublicKey(e.to_string()))?;
    let arr: [u8; PK_LEN] = raw.as_slice().try_into().map_err(|_| {
        MiningError::InvalidMinerPublicKey(format!(
            "expected {PK_LEN}-byte compressed point, got {} bytes",
            raw.len()
        ))
    })?;
    if arr[0] != 0x02 && arr[0] != 0x03 {
        return Err(MiningError::InvalidMinerPublicKey(format!(
            "compressed point must start with 0x02 or 0x03, got 0x{:02x}",
            arr[0]
        )));
    }
    Ok(reward_output_script(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct RewardBoxVector {
        height: u32,
        #[allow(dead_code)]
        header_id: String,
        reward_box: RewardBoxFields,
    }

    #[derive(Deserialize)]
    struct RewardBoxFields {
        #[allow(dead_code)]
        value: u64,
        #[allow(dead_code)]
        creation_height: u32,
        ergo_tree_hex: String,
    }

    const CORPUS_HEIGHTS: &[u32] = &[
        1_700_000, 1_720_000, 1_740_000, 1_760_000, 1_770_000, 1_780_000, 1_783_000, 1_785_000,
        1_786_000, 1_786_180,
    ];

    fn load_vector(height: u32) -> RewardBoxVector {
        let path = format!(
            "{}/../test-vectors/mining/reward_boxes/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            height
        );
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path}: {e}"))
    }

    // ----- happy path -----

    #[test]
    fn mainnet_reward_script_matches_real_mainnet_corpus_byte_for_byte() {
        let mut matched = 0usize;
        for &h in CORPUS_HEIGHTS {
            let v = load_vector(h);
            assert_eq!(v.height, h);
            let real_bytes = hex::decode(&v.reward_box.ergo_tree_hex)
                .unwrap_or_else(|e| panic!("hex decode at h={h}: {e}"));
            assert_eq!(
                real_bytes.len(),
                REWARD_SCRIPT_LEN,
                "h={h}: real reward box ergoTree should be {} bytes",
                REWARD_SCRIPT_LEN,
            );
            // Pull the pk back out of the real bytes (it lives in the
            // same slot the builder writes to) and feed it through the
            // builder. The resulting bytes must equal the real bytes
            // verbatim.
            let mut pk = [0u8; PK_LEN];
            pk.copy_from_slice(&real_bytes[PK_OFFSET..PK_OFFSET + PK_LEN]);
            let built = reward_output_script(&pk);
            assert_eq!(
                &built[..],
                &real_bytes[..],
                "h={h}: builder output diverges from real mainnet reward box bytes",
            );
            matched += 1;
        }
        assert_eq!(matched, CORPUS_HEIGHTS.len());
    }

    #[test]
    fn builder_pk_slot_round_trips() {
        // Sanity: the pk bytes round-trip through the builder slot.
        // 33-byte compressed point (66 hex chars).
        let pk_hex = "0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f";
        let mut pk = [0u8; PK_LEN];
        hex::decode_to_slice(pk_hex, &mut pk).expect("decode");
        let script = reward_output_script(&pk);
        assert_eq!(&script[PK_OFFSET..PK_OFFSET + PK_LEN], &pk[..]);
        // Prefix and suffix are constant.
        assert_eq!(&script[..PK_OFFSET], &REWARD_PREFIX);
        assert_eq!(&script[PK_OFFSET + PK_LEN..], &REWARD_SUFFIX);
    }

    #[test]
    fn from_hex_accepts_valid_compressed_point() {
        let pk_hex = "0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f";
        let bytes = reward_output_script_from_hex(pk_hex).expect("ok");
        assert_eq!(bytes.len(), REWARD_SCRIPT_LEN);
    }

    // ----- error paths -----

    #[test]
    fn from_hex_rejects_uncompressed_point_prefix() {
        // 04-prefix is the uncompressed-point marker — invalid for the
        // compressed slot the reward script reserves. 33 bytes/66 hex
        // chars to ensure the prefix check (not the length check) fires.
        let pk_hex = "0474e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f";
        let err = reward_output_script_from_hex(pk_hex).expect_err("must reject 04 prefix");
        match err {
            MiningError::InvalidMinerPublicKey(msg) => {
                assert!(
                    msg.contains("0x04") || msg.contains("0x02 or 0x03"),
                    "{msg}"
                )
            }
            other => panic!("expected InvalidMinerPublicKey, got {other:?}"),
        }
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let pk_hex = "0274"; // 2 bytes, way too short
        let err = reward_output_script_from_hex(pk_hex).expect_err("must reject short");
        match err {
            MiningError::InvalidMinerPublicKey(msg) => assert!(msg.contains("33-byte"), "{msg}"),
            other => panic!("expected InvalidMinerPublicKey, got {other:?}"),
        }
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        let err =
            reward_output_script_from_hex("not_hex_at_all_!!!").expect_err("must reject non-hex");
        assert!(matches!(err, MiningError::InvalidMinerPublicKey(_)));
    }
}
