//! Mainnet byte-parity oracle for `pack_interlinks` / `unpack_interlinks`.
//!
//! The Rust interlinks packing must produce byte-identical key-value
//! pairs to what mainnet stores in block extension sections, across a
//! corpus of N-1/N/N+1 triplets around named boundaries.
//!
//! The corpus is captured under
//! `test-vectors/mining/interlinks_corpus/{height}.json` by driving a
//! Scala 6.0.2 node's REST: `/blocks/at/{h}` → `/blocks/{id}` and
//! reading `extension.fields` filtered to keys starting with `0x01`.
//! Each captured field is a hex `(key, value)` pair.
//!
//! This test:
//!
//! 1. Loads each vector.
//! 2. Decodes the captured kv-fields.
//! 3. Calls [`ergo_validation::popow::algos::unpack_interlinks`] to
//!    recover the flat interlinks vector.
//! 4. Re-packs via [`ergo_validation::popow::algos::pack_interlinks`].
//! 5. Asserts the re-packed bytes equal the captured bytes
//!    field-for-field, byte-for-byte.

use ergo_validation::popow::algos::{pack_interlinks, unpack_interlinks};
use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)]
struct InterlinksVector {
    height: u32,
    header_id: String,
    version: u8,
    n_interlinks_fields: usize,
    n_extension_fields_total: usize,
    /// Each entry is `[hex_key, hex_value]`.
    interlinks_fields: Vec<[String; 2]>,
}

/// All captured corpus heights. Includes bootstrap (1, 2, 3), normal
/// (100), around-100k (99999/100000/100001), v2 activation
/// (417791 / 417792 / 417793), and EIP-37 epoch switch
/// (844672 / 844673 / 844674).
const CORPUS_HEIGHTS: &[u32] = &[
    1, 2, 3, 100, 99_999, 100_000, 100_001, 417_791, 417_792, 417_793, 844_672, 844_673, 844_674,
];

fn load_vector(height: u32) -> InterlinksVector {
    let path = format!(
        "{}/../test-vectors/mining/interlinks_corpus/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        height
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn decode_kv_fields(v: &InterlinksVector) -> Vec<(Vec<u8>, Vec<u8>)> {
    v.interlinks_fields
        .iter()
        .map(|pair| {
            (
                hex::decode(&pair[0])
                    .unwrap_or_else(|e| panic!("decode key hex at h={}: {e}", v.height)),
                hex::decode(&pair[1])
                    .unwrap_or_else(|e| panic!("decode value hex at h={}: {e}", v.height)),
            )
        })
        .collect()
}

#[test]
fn pack_then_unpack_round_trips_against_mainnet_corpus() {
    let mut total_fields = 0usize;
    for &h in CORPUS_HEIGHTS {
        let v = load_vector(h);
        assert_eq!(v.height, h);
        assert_eq!(
            v.n_interlinks_fields,
            v.interlinks_fields.len(),
            "h={h}: vector self-consistency",
        );

        let captured = decode_kv_fields(&v);

        // unpack should accept the real mainnet kv-fields.
        let flat =
            unpack_interlinks(&captured).unwrap_or_else(|e| panic!("h={h}: unpack failed: {e}"));

        // Re-pack the flat list, byte-compare against captured.
        let repacked = pack_interlinks(&flat);
        assert_eq!(
            repacked.len(),
            captured.len(),
            "h={h}: field count mismatch (captured {}, repacked {})",
            captured.len(),
            repacked.len(),
        );
        for (i, ((cap_k, cap_v), (rep_k, rep_v))) in
            captured.iter().zip(repacked.iter()).enumerate()
        {
            assert_eq!(
                cap_k,
                rep_k,
                "h={h}: field[{i}] key mismatch: captured {} vs repacked {}",
                hex::encode(cap_k),
                hex::encode(rep_k),
            );
            assert_eq!(
                cap_v,
                rep_v,
                "h={h}: field[{i}] value mismatch: captured {} vs repacked {}",
                hex::encode(cap_v),
                hex::encode(rep_v),
            );
        }
        total_fields += captured.len();
    }
    assert!(
        total_fields > 0,
        "corpus should have at least one non-empty interlinks vector"
    );
}

#[test]
fn unpack_then_pack_is_idempotent_against_mainnet_corpus() {
    // Stronger statement: unpack → pack → unpack yields the same
    // flat vector. Guards against any pack/unpack asymmetry.
    for &h in CORPUS_HEIGHTS {
        let v = load_vector(h);
        let captured = decode_kv_fields(&v);
        let flat_a =
            unpack_interlinks(&captured).unwrap_or_else(|e| panic!("h={h}: unpack a failed: {e}"));
        let repacked = pack_interlinks(&flat_a);
        let flat_b =
            unpack_interlinks(&repacked).unwrap_or_else(|e| panic!("h={h}: unpack b failed: {e}"));
        assert_eq!(
            flat_a, flat_b,
            "h={h}: unpack(pack(unpack(x))) != unpack(x)"
        );
    }
}
