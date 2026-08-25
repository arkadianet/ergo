//! Integration tests for `StateStore::apply_popow_proof` (Part 2
//! sub-phase 14.5). Covers: write atomicity (dense suffix range
//! only, prefix is witness-only), mode tag persistence, crash
//! safety (reopen preserves state), and the precondition guard.

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use ergo_ser::popow_header::PoPowHeader;
use ergo_ser::popow_proof::NipopowProof;
use ergo_state::chain::HeaderAvailability;
use ergo_state::store::StateStore;
use tempfile::TempDir;

// ----- helpers -----

/// Mainnet height 1..=10 headers (genesis through h=10). Sourced
/// from `test-vectors/mainnet/headers_1_10.json`. We deliberately
/// use real headers so the chain id / parent_id / height edges
/// match — the apply path doesn't validate the chain (the verifier
/// does), but the test's `parent_id` linkage matters for any
/// downstream re-acceptance.
const MAINNET_HEADERS_1_10: &[&str] = &[
    // height 1 (genesis: parent_id = zeros)
    "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b",
    // height 2
    "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd",
    // height 3
    "01855fc5c9eed868b43ea2c3df99ec17dd9d903187d891e2365a89b98125c994b2d80fc4ec24e7874760c6e42a8bce13791f15fe7f83d4cd055f614c25527a304b4202efb982197ef2b6629c2202796584a7351bbc0563b27ed35c295e95021b947bb6a177e849e45ce5313ab7fa08e90daed00ceeadec13f271eea500df3e801303e0a9d0e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce060117650300000002d3a9410ac758ad45dfc85af8626efdacf398439c73977b13064aa8e6c8f2ac880255d213ecba5fd74e52002e08a69a2e5e08378f2e43fbbf3f1130dde976db34260000000900cb491a1b9ac9dbcdf083bb80926012e041c623adb1ed964a80eb10bbb147ac",
    // height 4
    "013ff49e2419f779390a9347e8c3ee6391dd3f9e543c12dabcb0f1ebc8168754f466a0ed18269ae22ff110eafed64e6c45cfe8fdf2815d06ccd98afd4d3bed950492bea47dc72d2bc33e4f5a05cb5ac99876534d23537742e6fbdfd3cea455c81ac5410cbb9dff9a4a98f4c9016a156a6696e609601e8c81e9c19e79816c698e9904d3fbd0e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce06011765040000000337024f9dd20621ecd32baeee4741130d24797eda8cad0d09c794cb4458c4f2a30369f2e10d3a65b5c275bf5ce7ea5105ca9a5a25f81905305454a1196a2a01d42700000012006a2db91bb1ab362b64b298bd023859869c796a05aa4e66a50f4f374c72240c",
    // height 5
    "01d46df95124a711724990f40299bb166babc56d86de624db48776e2afb80e0302073cd5a1bff88021bfb51d13ecdac28387e6d1afe96d6871f1af20d53c93ff86ccccd693bd6461f094fe0bdf15b8284e4e65183c1a0ef596dfb1c56dfe0c61201803847b5e2d8a4fa6377c4ef47b51bda27b1ba8dda853f9b4f64cd5dc7367aa04ebbed1e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce0601176505000000027de3a01d95abec7ca4a110a45ca7e22193df9b51229e0fdfeaa19ebebf3f53e6031c96172660c9f068adb6e74e10b4afe17be3ce50837d0d670aadd988e79d2e1e00000015000f94951b87b6f29b3b5c86ee003baa22e10b490045b8046b14c9281d25fd6c",
    // height 6
    "01875aaa0886c229607b3da2440f9cdb12f61ed2a0e56c6a9dd9536ac11079ff038f118c8c15e83b19c467f35ac81ff3d88ea344b4ae88231cb08304cdb1aca961296a3e3d6485b9c32a67d18f09af8758ba5f393bbcb29ed4ddcd6e357877e70f346be81869e254cbb192ee5013a9b48f07fb66e0f809b00a63d92649e12129b704e392d2e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce0601176506000000022846c4f17a909080d7cb8bcf6217e2139666f420582f04e628a1e1225b4ecf49036066a84d6ab109fd53ee769e7bbb89daf191d883007c5625a9b762c542108b8600000024030068221b48756b6ff480f656a82f94f11d479538d008c412508175748f1b9c",
    // height 7
    "01918d0c4ccb9a26cc69a3250eef1117b07bf843367a25455fd0873349a0821a61c8099d28b23cfe8a56553291318650740775b6d827818eae51ad2b0b23cc049cb96c900bef70956ca7c6b01c6e1aa543d6d50e709f852062287fdfc53e2647f91302a55e568b0075165ea085172f834a60d957c98982a51044a6931ec981ade604cb81d3e9ba2da08b33945a758152368ad5b6e2172bf4e669d04c4c951df483da39079908d107060117650700000003a1b5faf27aab713ac2114b3710fb3cf0af580d95997197435c54da4b332efd6902d2c567d69d65d6d5e621d3c2473bdb2880579eb05728cd0384a58592e6d883540000002703206c871b98190c2204cddab9e205f26bd4c7973e7d6ce2b0070e30fd46cf33",
    // height 8
    "01baffd756f86275213fb4dd9400d1d667d0a35a2ba712af050cf0a6f0dfd799919f779fdeb12596973dcaf413a8af18c1d9138bd3420414cc2d2bdb5db2c2d2e955a45f129a2a11888cb74c3c3664caa9c6ac1c1ce6d712e1fbdc1c387b88af3ee40028aadf914a098ee11a02bfcb2d5bf499c920ebce81e6a3b6c738e5c20273048fc2d3e9ba2da08b33945a758152368ad5b6e2172bf4e669d04c4c951df483da39079908d107060117650800000003149c52fbfac539d818d68eb2856b42a2053452bad123b361d5374320a77dc2bb025a20ba1794773296d1018a7a21599d15b3389b06c60c7094f936fe1fc86d968f0000002901361e821bc66259888997722b41d567a1a33e3387116416fa867c0bc37e34be",
];

fn header_from_hex(hex: &str) -> Header {
    let raw = hex::decode(hex).unwrap();
    let mut r = VlqReader::new(&raw);
    read_header(&mut r).unwrap()
}

fn popow_hdr(h: Header, links: Vec<ModifierId>) -> PoPowHeader {
    PoPowHeader {
        header: h,
        interlinks: links,
        interlinks_proof: vec![],
    }
}

/// Build a synthetic proof with k=4 over the 8 real mainnet headers:
/// prefix = [h1, h2, h3, h4], suffix_head = h5, suffix_tail = [h6, h7, h8].
/// Suffix tip height = 8, dense_from = 5 - 4 + 1 = 2.
fn synthetic_proof_k4_over_1_to_8() -> NipopowProof {
    let mut headers: Vec<Header> = MAINNET_HEADERS_1_10
        .iter()
        .take(8)
        .map(|h| header_from_hex(h))
        .collect();
    let suffix_tail: Vec<Header> = headers.drain(5..).collect();
    let suffix_head_h = headers.pop().unwrap();
    let prefix: Vec<PoPowHeader> = headers.drain(..).map(|h| popow_hdr(h, vec![])).collect();
    NipopowProof {
        m: 6,
        k: 4,
        prefix,
        suffix_head: popow_hdr(suffix_head_h, vec![]),
        suffix_tail,
        continuous: true,
    }
}

// ----- happy path -----

#[test]
fn apply_popow_proof_sets_sparse_mode_and_best_header() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    assert_eq!(store.chain_state().best_header_height, 0);

    let proof = synthetic_proof_k4_over_1_to_8();
    store.apply_popow_proof(&proof).unwrap();

    let cs = store.chain_state();
    // Suffix tip is the LAST header in suffix_tail; the suffix has
    // suffix_head + 3 tail entries (5+6+7+8 = heights 5..=8). Top tip
    // height is therefore 8.
    assert_eq!(cs.best_header_height, 8);
    // dense_from = suffix_head.height (5) - (k=4) + 1 = 2.
    match cs.header_availability {
        HeaderAvailability::PoPowSparse {
            dense_from_height,
            proof_suffix_height,
        } => {
            assert_eq!(dense_from_height, 2);
            assert_eq!(proof_suffix_height, 5); // suffix_head.height
        }
        other => panic!("expected PoPowSparse, got {other:?}"),
    }
    // best_full_block_height stays at 0 — apply_popow_proof does not
    // advance full-block state (Mode 2 snapshot bootstrap remains
    // eligible).
    assert_eq!(cs.best_full_block_height, 0);
}

#[test]
fn apply_popow_proof_writes_header_chain_index_for_dense_suffix_only() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let proof = synthetic_proof_k4_over_1_to_8();
    store.apply_popow_proof(&proof).unwrap();

    // Prefix heights 1 are NOT in HEADER_CHAIN_INDEX (height 1 is in
    // prefix, height 2 is dense_from). For k=4 with suffix_head at
    // height 5, dense range is [2, 8]. Heights 1 should not have a
    // HEADER_CHAIN_INDEX row.
    // (Note: in this synthetic proof, prefix=[h1,h2,h3,h4], suffix=[h5..h8],
    //  k=4 so dense_from = 5-3 = 2. Heights 1 = prefix-only; heights 2..=4
    //  appear in BOTH prefix AND the dense range. Per the apply rule
    //  any header in the dense range gets a row — including the prefix
    //  ones whose height falls inside [dense_from, dense_to].)
    assert_eq!(store.get_header_id_at_height(1).unwrap(), None);
    // Heights 2..=8 should have rows.
    for h in 2u32..=8 {
        assert!(
            store.get_header_id_at_height(h).unwrap().is_some(),
            "height {h} should be in HEADER_CHAIN_INDEX"
        );
    }
    // Height 9 above tip.
    assert_eq!(store.get_header_id_at_height(9).unwrap(), None);
}

#[test]
fn apply_popow_proof_persists_mode_across_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("db");
    {
        let mut store = StateStore::open(&db_path).unwrap();
        let proof = synthetic_proof_k4_over_1_to_8();
        store.apply_popow_proof(&proof).unwrap();
    } // store dropped → DB closes

    // Reopen the same path. Mode tag + best_header should survive,
    // and backfill should NOT panic against the sparse store (the
    // 14.4.5b restart-safety fix).
    let store = StateStore::open(&db_path).unwrap();
    let cs = store.chain_state();
    assert_eq!(cs.best_header_height, 8);
    assert!(matches!(
        cs.header_availability,
        HeaderAvailability::PoPowSparse { .. }
    ));
}

// ----- error paths -----

#[test]
fn apply_popow_proof_refuses_to_run_on_non_fresh_store() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let proof = synthetic_proof_k4_over_1_to_8();
    // First apply succeeds.
    store.apply_popow_proof(&proof).unwrap();
    // Second apply on the now-sparse store must error.
    let err = store
        .apply_popow_proof(&proof)
        .expect_err("re-apply must error");
    match err {
        ergo_state::store::StateError::ApplyPopowProofWrongMode {
            mode_description,
            best_header_height,
        } => {
            // Confirm the typed runtime fields make it out — both
            // pieces of operator-actionable context that the old
            // Serialization(format!) carried in its prefix.
            assert!(
                mode_description.contains("PoPowSparse"),
                "expected sparse mode label, got {mode_description}",
            );
            assert!(
                best_header_height > 0,
                "expected non-zero tip after first apply, got {best_header_height}",
            );
        }
        other => panic!("expected ApplyPopowProofWrongMode, got {other:?}"),
    }
}

// ----- 14.10 serve-side cache -----

#[test]
fn cached_popow_proof_bytes_absent_on_fresh_store() {
    let dir = TempDir::new().unwrap();
    let store = StateStore::open(&dir.path().join("db")).unwrap();
    assert!(store.get_cached_popow_proof_bytes().unwrap().is_none());
}

#[test]
fn cached_popow_proof_bytes_roundtrip_persists_across_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("db");

    let test_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    {
        let store = StateStore::open(&db_path).unwrap();
        store.set_cached_popow_proof_bytes(&test_bytes).unwrap();
        assert_eq!(
            store.get_cached_popow_proof_bytes().unwrap().as_deref(),
            Some(test_bytes.as_slice())
        );
    } // drop the store

    // Reopen — cache must survive.
    let store = StateStore::open(&db_path).unwrap();
    assert_eq!(
        store.get_cached_popow_proof_bytes().unwrap().as_deref(),
        Some(test_bytes.as_slice())
    );
}

#[test]
fn cached_popow_proof_bytes_overwrites_on_repeat_set() {
    let dir = TempDir::new().unwrap();
    let store = StateStore::open(&dir.path().join("db")).unwrap();
    store.set_cached_popow_proof_bytes(&[1, 2, 3]).unwrap();
    store.set_cached_popow_proof_bytes(&[4, 5, 6, 7]).unwrap();
    assert_eq!(
        store.get_cached_popow_proof_bytes().unwrap().as_deref(),
        Some(&[4u8, 5, 6, 7][..])
    );
}

#[test]
fn compute_popow_proof_rejects_sparse_mode_store() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let proof = synthetic_proof_k4_over_1_to_8();
    store.apply_popow_proof(&proof).unwrap();
    // Store is now sparse — compute must reject.
    let err = store
        .compute_and_cache_popow_proof_dense(6, 10)
        .expect_err("sparse-mode compute must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("not in Dense mode") || msg.contains("PoPowSparse"),
        "unexpected error: {msg}"
    );
}

#[test]
fn compute_popow_proof_rejects_chain_below_kplusm() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    // Empty store (best_header_height = 0) → fails the k+m check.
    let err = store
        .compute_and_cache_popow_proof_dense(6, 10)
        .expect_err("empty chain must reject");
    match err {
        ergo_state::store::StateError::EarlyIBD {
            needed_min,
            observed,
        } => {
            assert_eq!(needed_min, 16); // k=10 + m=6
            assert_eq!(observed, 0);
        }
        other => panic!("expected EarlyIBD, got {other:?}"),
    }
    // Cache should remain absent.
    assert!(store.get_cached_popow_proof_bytes().unwrap().is_none());
}
