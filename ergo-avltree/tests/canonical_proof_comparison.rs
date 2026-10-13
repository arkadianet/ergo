#![allow(clippy::style, clippy::complexity, clippy::perf)]
//! Canonical proof comparison tests — Rust prover vs JVM oracle.
//!
//! JVM oracle source:
//!   ~/projects/santa/jvm-blesser/src/test/scala/santa/AvlProofComparison.scala
//! Generated 2026-07-06. Each case's proofDigest = blake2b256(proofBytes).

use bytes::Bytes;
use ergo_avltree::batch_avl_prover::BatchAVLProver;
use ergo_avltree::batch_node::*;
use ergo_avltree::operation::*;

fn make_prover() -> BatchAVLProver {
    let tree = AVLTree::new(
        |digest: &Digest32| Node::LabelOnly(NodeHeader::new(Some(*digest), None)),
        32,
        None,
    );
    BatchAVLProver::new(tree, false)
}

fn key_a() -> ADKey {
    Bytes::from(vec![0xAAu8; 32])
}
fn key_b() -> ADKey {
    Bytes::from(vec![0xBBu8; 32])
}
fn key_c() -> ADKey {
    Bytes::from(vec![0xCCu8; 32])
}
fn key_d() -> ADKey {
    Bytes::from(vec![0xDDu8; 32])
}

fn val_v1() -> ADValue {
    Bytes::from(vec![0x01, 0x02, 0x03, 0x04])
}
fn val_v2() -> ADValue {
    Bytes::from(vec![0x05, 0x06, 0x07, 0x08])
}
fn val_v3() -> ADValue {
    Bytes::from(vec![0x09, 0x0a, 0x0b, 0x0c])
}
fn val_v4() -> ADValue {
    Bytes::from(vec![0x0d, 0x0e, 0x0f, 0x10])
}

fn insert(p: &mut BatchAVLProver, key: &ADKey, value: &ADValue) {
    p.perform_one_operation(&Operation::Insert(KeyValue {
        key: key.clone(),
        value: value.clone(),
    }))
    .unwrap();
}

fn lookup(p: &mut BatchAVLProver, key: &ADKey) {
    p.perform_one_operation(&Operation::Lookup(key.clone()))
        .unwrap();
}

/// Seed the prover with entries, generate a proof (which resets visited
/// flags), and return the prover ready for more operations.
fn seed(entries: &[(ADKey, ADValue)]) -> BatchAVLProver {
    let mut p = make_prover();
    for (k, v) in entries {
        insert(&mut p, k, v);
    }
    p.generate_proof();
    p
}

// ── JVM oracle hex ────────────────────────────────────────────────────────

/// Case 1: empty tree, 3 inserts, no Lookup
const JVM_CASE1: &str = "020000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000400";

/// Case 2: empty tree, 3 inserts + Lookup (differs from C1 by 1 direction byte)
const JVM_CASE2: &str = "020000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000408";

/// Case 3: seeded tree (aa,bb,cc), Insert(dd) + Lookup(aa) — 28474 pattern
const JVM_CASE3: &str = "0344cfd4671a6f0b122ed4fa31f236ddbe1bd1b74897634eefb8131c975f52746402aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000040102030400034a89e7eae4f1b9317fed4cedaf6cfaeb1db251fe121fa86df2b8f41f5942d89502ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000004090a0b0c00000404";

/// Case 4: seeded tree (aa,bb,cc), Insert(dd) only (control)
const JVM_CASE4: &str = "03fec0ef32a70153f4561c58d71f62eef89a29fccd207642aa5695dc1f42fc1ea4034a89e7eae4f1b9317fed4cedaf6cfaeb1db251fe121fa86df2b8f41f5942d89502ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000004090a0b0c00000400";

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn case1_empty_3_inserts() {
    let mut p = make_prover();
    insert(&mut p, &key_a(), &val_v1());
    insert(&mut p, &key_b(), &val_v2());
    insert(&mut p, &key_c(), &val_v3());
    let proof = p.generate_proof();
    let rust_hex = base16::encode_lower(&proof);
    assert_eq!(rust_hex, JVM_CASE1, "Case 1: proof mismatch");
}

#[test]
fn case2_empty_3_inserts_1_lookup() {
    let mut p = make_prover();
    insert(&mut p, &key_a(), &val_v1());
    insert(&mut p, &key_b(), &val_v2());
    insert(&mut p, &key_c(), &val_v3());
    lookup(&mut p, &key_a());
    let proof = p.generate_proof();
    let rust_hex = base16::encode_lower(&proof);
    assert_eq!(rust_hex, JVM_CASE2, "Case 2: proof mismatch");
}

#[test]
fn case3_seeded_insert_lookup() {
    let entries = vec![
        (key_a(), val_v1()),
        (key_b(), val_v2()),
        (key_c(), val_v3()),
    ];
    let mut p = seed(&entries);
    insert(&mut p, &key_d(), &val_v4());
    lookup(&mut p, &key_a());
    let proof = p.generate_proof();
    let rust_hex = base16::encode_lower(&proof);
    assert_eq!(
        rust_hex, JVM_CASE3,
        "Case 3: proof mismatch (canonical AVL proof bytes)"
    );
}

#[test]
fn case4_seeded_insert_only() {
    let entries = vec![
        (key_a(), val_v1()),
        (key_b(), val_v2()),
        (key_c(), val_v3()),
    ];
    let mut p = seed(&entries);
    insert(&mut p, &key_d(), &val_v4());
    let proof = p.generate_proof();
    let rust_hex = base16::encode_lower(&proof);
    assert_eq!(
        rust_hex, JVM_CASE4,
        "Case 4: proof mismatch (canonical AVL proof bytes)"
    );
}
