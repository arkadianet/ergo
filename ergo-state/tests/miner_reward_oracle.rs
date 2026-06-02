//! Oracle parity for miner-reward pubkey extraction.
//!
//! `extract_miner_reward_pubkey` pattern-matches the canonical mainnet
//! miner-reward ErgoTree and returns the embedded R5 miner pubkey. This
//! test pins it against a corpus of REAL mainnet reward outputs captured
//! from a Scala node, at `test-vectors/mining/reward_boxes/{height}.json`
//! (re-extractable via `/blocks/at/{h}` → `/blocks/{id}` → the coinbase
//! output's `ergoTree`). Every vector's tree must extract, and the
//! extracted pubkey must be the trailing SEC1 point embedded in the tree.
//!
//! This is the oracle the in-module unit test (single height) generalizes:
//! the shape must hold across the whole corpus, not just one block.

use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)] // value / creation_height / header_id captured for provenance
struct RewardBoxVector {
    height: u32,
    header_id: String,
    reward_box: RewardBox,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RewardBox {
    value: u64,
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

#[test]
fn every_mainnet_reward_box_in_corpus_extracts_its_pubkey() {
    let mut checked = 0usize;
    for &h in CORPUS_HEIGHTS {
        let v = load_vector(h);
        let tree = hex::decode(&v.reward_box.ergo_tree_hex)
            .unwrap_or_else(|e| panic!("height {h}: bad ergo_tree_hex: {e}"));

        let pk = ergo_state::wallet::miner_reward::extract_miner_reward_pubkey(&tree)
            .unwrap_or_else(|| panic!("height {h}: canonical reward tree must extract a pubkey"));

        // The extracted pubkey is exactly the 33 bytes at offset [7..40] of
        // the tree (after the 7-byte canonical prefix), and is a valid
        // SEC1-compressed point (the extractor already enforces on-curve).
        let expected = &tree[7..40];
        assert_eq!(
            pk.as_slice(),
            expected,
            "height {h}: extracted pubkey must be the tree's embedded R5 point"
        );
        assert!(
            pk[0] == 0x02 || pk[0] == 0x03,
            "height {h}: pubkey must be SEC1-compressed (02/03 prefix), got {:#04x}",
            pk[0]
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        CORPUS_HEIGHTS.len(),
        "all corpus reward boxes must be checked"
    );
}
