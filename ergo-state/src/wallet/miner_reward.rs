//! Miner-reward script shape detection per Scala
//! `WalletScanLogic.scala:183-209` + `ErgoMiner.rewardOutputScript`.
//!
//! The canonical Ergo miner-reward script is:
//!   { HEIGHT >= R_4 && proveDlog(R_5) }
//! where R_4 and R_5 are the box's register 4 (unlock height) and
//! register 5 (miner pubkey). In ErgoTree byte form this is a
//! specific shape we can pattern-match.
//!
//! This module does NOT attempt to parse arbitrary ErgoTrees; it
//! matches ONLY the canonical miner-reward shape. Anything else
//! returns `None`. A more flexible parser could be added if dApp
//! reward shapes proliferate.

/// If `ergo_tree_bytes` matches the canonical miner-reward script
/// AND the embedded `proveDlog` argument is a 33-byte compressed
/// SEC1 pubkey, return that pubkey. Else return `None`.
///
/// This is the integrator's hook into the apply layer: at parse
/// time, the integrator calls this on each output's tree bytes and
/// passes the result as `BlockOutput::miner_reward_pubkey`.
pub fn extract_miner_reward_pubkey(ergo_tree_bytes: &[u8]) -> Option<[u8; 33]> {
    // Canonical mainnet miner-reward ErgoTree, verified byte-for-byte against
    // a corpus of real mainnet reward boxes (`test-vectors/mining/reward_boxes`,
    // heights 1.70M–1.786M). The tree is constant-segregated with two
    // constants — the unlock delay (SInt) and the miner pubkey (SigmaProp) —
    // followed by the `{ sigmaProp(HEIGHT >= minerRewardDelay) && proveDlog(pk) }`
    // body. Layout (54 bytes total):
    //
    //   10 02 04 a00b 08 cd   prefix (7B): header 0x10 (v0 + segregation),
    //                         constant-count 2, const[0]=SInt(720) via VLQ-zigzag
    //                         `a00b`, const[1]=SSigmaProp/ProveDlog tag 0xcd
    //   <pubkey>              R5 miner pubkey (33B, SEC1-compressed)
    //   ea02 d192a39a8cc7a701 7300 7301   body/closure (14B)
    //
    // The `a00b` in the prefix encodes `minerRewardDelay = 720`, so this shape
    // is MAINNET-SPECIFIC (consistent with `apply::REWARD_MATURITY_MAINNET`).
    // Testnet/devnet use a different delay and would need their own pinned
    // prefix — the same network-awareness follow-up tracked for the maturity
    // constant.
    const CANONICAL_REWARD_PREFIX: &[u8] = &[0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd];
    const CANONICAL_REWARD_SUFFIX: &[u8] = &[
        0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00, 0x73, 0x01,
    ];
    const PREFIX_LEN: usize = CANONICAL_REWARD_PREFIX.len(); // 7
    const PUBKEY_LEN: usize = 33;
    const SUFFIX_LEN: usize = CANONICAL_REWARD_SUFFIX.len(); // 14

    if ergo_tree_bytes.len() != PREFIX_LEN + PUBKEY_LEN + SUFFIX_LEN {
        return None;
    }
    if &ergo_tree_bytes[..PREFIX_LEN] != CANONICAL_REWARD_PREFIX {
        return None;
    }
    if &ergo_tree_bytes[PREFIX_LEN + PUBKEY_LEN..] != CANONICAL_REWARD_SUFFIX {
        return None;
    }
    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&ergo_tree_bytes[PREFIX_LEN..PREFIX_LEN + PUBKEY_LEN]);
    // Validate it's on-curve before returning — off-curve bytes
    // can't be a real reward output.
    k256::PublicKey::from_sec1_bytes(&pubkey).ok()?;
    Some(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    /// Real mainnet miner-reward output from block 1,700,000
    /// (`test-vectors/mining/reward_boxes/1700000.json`): the canonical
    /// reward ErgoTree and the embedded R5 miner pubkey it must yield.
    const MAINNET_REWARD_TREE_1700000: &str = "100204a00b08cd0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891fea02d192a39a8cc7a70173007301";
    const MAINNET_REWARD_PK_1700000: &str =
        "0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f";

    #[test]
    fn mainnet_miner_reward_tree_extracts_pubkey() {
        let tree = hex::decode(MAINNET_REWARD_TREE_1700000).unwrap();
        assert_eq!(tree.len(), 54, "canonical mainnet reward tree is 54 bytes");
        let pk = extract_miner_reward_pubkey(&tree)
            .expect("canonical mainnet reward shape must extract its pubkey");
        assert_eq!(hex::encode(pk), MAINNET_REWARD_PK_1700000);
    }

    #[test]
    fn corrupting_reward_suffix_rejects() {
        // Flip the last byte of the otherwise-canonical tree: the suffix
        // check must reject (guards against matching on prefix alone).
        let mut tree = hex::decode(MAINNET_REWARD_TREE_1700000).unwrap();
        *tree.last_mut().unwrap() ^= 0xff;
        assert!(extract_miner_reward_pubkey(&tree).is_none());
    }

    // ----- error paths -----

    #[test]
    fn non_reward_tree_returns_none() {
        // Bare P2PK output (no reward wrapper) — extractor must
        // return None so the apply hook falls through to the
        // tracked-tree-membership check.
        let bare_p2pk_bytes = vec![0x00, 0x08, 0xCD, 0x03];
        assert!(extract_miner_reward_pubkey(&bare_p2pk_bytes).is_none());
    }

    #[test]
    fn wrapper_with_off_curve_pubkey_returns_none() {
        // Prefix + suffix match the canonical shape but the pubkey portion
        // is off-curve (all-zero is invalid SEC1). Extractor must reject.
        let mut bad = vec![0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd];
        bad.extend_from_slice(&[0u8; 33]);
        bad.extend_from_slice(&[
            0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00, 0x73, 0x01,
        ]);
        assert_eq!(bad.len(), 54);
        assert!(extract_miner_reward_pubkey(&bad).is_none());
    }

    #[test]
    fn wrapper_with_wrong_length_returns_none() {
        // Prefix matches but the tree is too short to hold pubkey + suffix.
        let too_short = vec![0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd, 0x02];
        assert!(extract_miner_reward_pubkey(&too_short).is_none());
    }

    #[test]
    fn old_placeholder_prefix_no_longer_matches() {
        // The previous placeholder prefix (00000000, len 40) must NOT match —
        // regression guard that the real mainnet bytes are pinned.
        let mut placeholder = vec![0x10, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00];
        placeholder.extend_from_slice(&hex::decode(MAINNET_REWARD_PK_1700000).unwrap());
        assert!(extract_miner_reward_pubkey(&placeholder).is_none());
    }
}
