//! SANTA nipopow conformance corpus — `NipopowProve.jvm-chain-32.json`
//! (blessed by `jvm:ergo-core-6.0.2.1-NipopowAlgos`).
//!
//! Two graded dimensions live in this vector:
//! * `nipopow_interlinks` — the interlinks vector of every header in the
//!   synthetic 32-header chain, recomputed by the JVM's
//!   `NipopowAlgos.updateInterlinks`; graded per header (2 reds: first
//!   divergence at height 23, both interlinks vectors).
//! * `nipopow_prove` — four serialized proofs (`prove-m2-k2-tip`,
//!   `prove-m3-k3-tip`, `prove-m6-k5-tip`, and the truncated
//!   `prove-m2-k2-anchored-h16`), graded byte-exact (7 reds).
//!
//! Both red families trace to one root cause: Rust's `f64::log2` returns
//! exactly N for 2^N while the JVM's `math.log(x) / math.log(2)` carries a
//! 1-ULP error, flipping the truncated μ-level at exact-power-of-two targets
//! (the synthetic fake-PoW scheme lands on one at height 22). Real PoW hits
//! are hash outputs and cannot be exact powers of two — this corpus is the
//! only place the divergence fires, and it is also the only place it can be
//! pinned. The vectors live in `test-vectors/santa/` (JVM-blessed expected
//! data; the harness repo is external).

use std::collections::BTreeMap;

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use ergo_ser::popow_proof::serialize_nipopow_proof;
use ergo_validation::popow::algos::{
    build_popow_header, pack_interlinks, prove, update_interlinks, PoPowParams,
};

const VECTOR: &str = include_str!("../../test-vectors/santa/NipopowProve.jvm-chain-32.json");

struct ChainEntry {
    height: u32,
    header: Header,
    interlinks: Vec<ModifierId>,
}

fn load_chain() -> Vec<ChainEntry> {
    let v: serde_json::Value = serde_json::from_str(VECTOR).expect("vector JSON");
    let mut out = Vec::new();
    for c in v["chain"].as_array().expect("chain array") {
        let header_hex = c["headerHex"].as_str().expect("headerHex");
        let bytes = hex::decode(header_hex).expect("header hex");
        let mut r = VlqReader::new(&bytes);
        let header = read_header(&mut r).expect("header parse");
        assert!(r.is_empty(), "header bytes fully consumed");
        let interlinks: Vec<ModifierId> = c["interlinks"]
            .as_array()
            .expect("interlinks")
            .iter()
            .map(|s| {
                let raw = hex::decode(s.as_str().unwrap()).expect("interlink hex");
                ModifierId::from_bytes(raw.try_into().expect("32-byte interlink"))
            })
            .collect();
        out.push(ChainEntry {
            height: c["height"].as_u64().expect("height") as u32,
            header,
            interlinks,
        });
    }
    out
}

/// Dimension 1 — interlinks: our `update_interlinks` walk over the parsed
/// chain must reproduce the JVM's vector at every height. This is the
/// end-to-end oracle for `max_level_of`'s log2 parity (a 1-ULP level flip at
/// height 22 used to rewrite every later vector).
#[test]
fn interlinks_match_jvm_at_every_height() {
    let chain = load_chain();
    assert_eq!(chain.len(), 32);

    // Walk: interlinks(h_{n+1}) = update_interlinks(h_n, interlinks(h_n)).
    // Genesis (height 1, parent = zeros) carries [own id], which the vector
    // also asserts.
    let mut prev = &chain[0];
    assert_eq!(
        prev.interlinks,
        {
            let (_, id) = ergo_ser::header::serialize_header(&prev.header).expect("genesis id");
            vec![id]
        },
        "genesis interlinks are [own id]"
    );
    for entry in chain.iter().skip(1) {
        let computed = update_interlinks(&prev.header, &prev.interlinks)
            .expect("update_interlinks over the blessed chain");
        assert_eq!(
            computed, entry.interlinks,
            "interlinks diverge at height {}",
            entry.height
        );
        prev = entry;
    }
}

/// Dimension 2 — prove: the four JVM-blessed proof serializations must be
/// reproduced byte-exactly. `build_popow_header` needs the block's extension
/// fields to anchor the interlinks merkle proof; the synthetic chain's blocks
/// carry interlinks-only extensions (the fixtures were produced by
/// `NipopowAlgos` over a fake chain whose extension is the packed interlink
/// vector), so the extension is reconstructed as `pack_interlinks(interlinks)`
/// — the same bytes `build_popow_header` proves against.
#[test]
fn prove_reproduces_blessed_proof_bytes() {
    let chain = load_chain();

    // Build the PoPowHeader chain once (header + interlinks + merkle proof).
    let mut pows: BTreeMap<u32, ergo_ser::popow_header::PoPowHeader> = BTreeMap::new();
    for entry in &chain {
        let ext = pack_interlinks(&entry.interlinks);
        let ph = build_popow_header(entry.header.clone(), entry.interlinks.clone(), &ext)
            .unwrap_or_else(|e| panic!("build_popow_header at h={}: {e}", entry.height));
        pows.insert(entry.height, ph);
    }

    let full_chain: Vec<ergo_ser::popow_header::PoPowHeader> =
        chain.iter().map(|e| pows[&e.height].clone()).collect();

    // (m, k, truncate-at-height-or-None, vector key). The anchored variant
    // (`truncated-prove`) is the same paper algorithm over the chain
    // truncated at anchor + k — the anchor (h16) ends up the last PREFIX
    // header, the suffix being the k headers after it (blessed suffix =
    // [h17, h18]).
    let cases: [(u32, u32, Option<u32>, &str); 4] = [
        (2, 2, None, "prove-m2-k2-tip"),
        (3, 3, None, "prove-m3-k3-tip"),
        (6, 5, None, "prove-m6-k5-tip"),
        (2, 2, Some(18), "prove-m2-k2-anchored-h16"),
    ];

    for (m, k, truncate, name) in cases {
        let sub: Vec<ergo_ser::popow_header::PoPowHeader> = match truncate {
            None => full_chain.clone(),
            Some(h) => full_chain
                .iter()
                .filter(|p| p.header.height <= h)
                .cloned()
                .collect(),
        };
        // The blesser serializes with `continuous = false` (one-shot mode; the
        // blessed proofs' trailing byte is 0). NOTE this is a corpus
        // parametrization, NOT the serving-path choice: Scala's
        // `PopowProcessor.popowProof` (the REST/P2P prover) constructs
        // `PoPowParams(m, k, continuous = true)` — which is what our
        // `StateStore::prove_nipopow` mirrors.
        let proof = prove(
            sub,
            PoPowParams {
                m,
                k,
                continuous: false,
            },
        )
        .unwrap_or_else(|e| panic!("{name}: prove failed: {e}"));
        let bytes = serialize_nipopow_proof(&proof).expect("serialize proof");
        let got = hex::encode(&bytes);

        let expected = blessed_proof_hex(name);
        assert_eq!(
            got, expected,
            "{name}: proof bytes diverge from the JVM blessing"
        );
    }
}

fn blessed_proof_hex(name: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .expect("entry")["expected"]["proofHex"]
        .as_str()
        .unwrap()
        .to_string()
}
