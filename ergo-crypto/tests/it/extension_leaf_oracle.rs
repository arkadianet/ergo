//! Scala oracle for `extension_leaf_digest`
//! (`ergo-crypto/src/merkle/mod.rs`), fixing a self-oracle gap flagged
//! in Task 5 review round 1: the original oracle-parity unit test
//! only checked `extension_leaf_digest` for internal consistency
//! against Rust's own `merkle_tree_root`/`leaf_hash` — a shared
//! Rust/Scala mismatch in either function would have been
//! undetectable. This test instead checks `extension_leaf_digest`
//! against digests computed independently by the Scala harness via
//! `Leaf[Digest32](LeafData @@ Extension.kvToLeaf((key, value)))(Algos.hash).hash`
//! (`WeakBlocksOracle.scala::extensionLeafCases`), covering a 2-byte
//! key with a 32-byte value, the real `PrevInputBlockIdKey`, and an
//! interlinks-style key.

use ergo_crypto::merkle::extension_leaf_digest;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    key_hex: String,
    value_hex: String,
    leaf_digest_hex: String,
}

#[test]
fn extension_leaf_digest_matches_scala_oracle() {
    let data = std::fs::read_to_string("../test-vectors/weak-blocks/extension_leaf.json")
        .expect("need test-vectors/weak-blocks/extension_leaf.json");
    let vectors: Vectors = serde_json::from_str(&data).expect("extension_leaf.json must parse");
    assert_eq!(vectors.cases.len(), 3, "expected 3 extension_leaf cases");

    for c in &vectors.cases {
        let key = hex::decode(&c.key_hex).expect("key_hex decodes");
        let value = hex::decode(&c.value_hex).expect("value_hex decodes");
        let expected = hex::decode(&c.leaf_digest_hex).expect("leaf_digest_hex decodes");

        let digest = extension_leaf_digest(&key, &value);
        assert_eq!(
            digest.to_vec(),
            expected,
            "{}: extension_leaf_digest must match Scala Leaf[Digest32](Extension.kvToLeaf)",
            c.name
        );
    }
}
