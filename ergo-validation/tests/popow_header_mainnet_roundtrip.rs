//! Mainnet-derived PoPowHeader round-trip + structural-validation
//! oracle for §6.1.
//!
//! Scope:
//! - Heights 1..=3 are exercised end-to-end using the committed
//!   Scala-sourced interlinks corpus
//!   (`test-vectors/mining/interlinks_corpus/{1,2,3}.json`)
//!   captured from a Scala 6.0.2 node. The corpus byte equality
//!   against the extension fields is asserted, so the interlinks
//!   vector ingested into `build_popow_header` is the same one
//!   Scala would emit.
//! - Heights 4..=5 are NOT in the committed corpus and are
//!   intentionally skipped — they would only exercise our own
//!   `unpack_interlinks` against itself, not Scala parity.
//!
//! Pipeline:
//! 1. Real mainnet header bytes (`headers_1_2000.json`).
//! 2. Real mainnet extension fields (`blocks_1_5.json`).
//! 3. Scala-sourced corpus interlink fields cross-checked
//!    byte-for-byte against extension fields.
//! 4. `build_popow_header` constructs the `PoPowHeader` with a
//!    real batch Merkle proof against the extension's tree.
//! 5. `write_popow_header` / `read_popow_header` round-trips
//!    byte-identically (and re-serialize stable).
//! 6. The PRODUCTION verifier
//!    `popow::proof::check_popow_header_interlinks_proof` validates
//!    the proof against the verifier's reconstructed root.
//!
//! Early-mainnet heights 1..=3 carry ONLY interlink fields in the
//! extension, so the prover-side tree (over full extension) and
//! verifier-side tree (over packed interlinks) agree by
//! construction — see `PoPowHeader.scala:60-64`. Mixed-extension
//! heights need their own corpus capture (follow-up).

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_ser::popow_header::{read_popow_header, serialize_popow_header};
use ergo_validation::popow::algos::{build_popow_header, unpack_interlinks};
use ergo_validation::popow::proof::check_popow_header_interlinks_proof;
use serde::Deserialize;

#[derive(Deserialize)]
struct BlockJson {
    height: u32,
    extension: ExtJson,
}

#[derive(Deserialize)]
struct ExtJson {
    /// `[hex_key, hex_value]` pairs in on-wire order.
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct InterlinksVector {
    interlinks_fields: Vec<[String; 2]>,
}

fn load_blocks() -> Vec<BlockJson> {
    let path = format!(
        "{}/../test-vectors/mainnet/blocks_1_5.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn load_interlinks_for(height: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    // Mandatory load. The corpus is committed to the repo for the
    // heights this test exercises; a missing fixture is a test
    // failure — silently falling back to self-consistency would
    // overclaim oracle parity.
    let path = format!(
        "{}/../test-vectors/mining/interlinks_corpus/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        height
    );
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("interlinks corpus missing at {path}: {e}"));
    let v: InterlinksVector = serde_json::from_str(&raw).unwrap();
    v.interlinks_fields
        .iter()
        .map(|[k, v]| (hex::decode(k).unwrap(), hex::decode(v).unwrap()))
        .collect()
}

fn load_header_bytes(block: &BlockJson) -> ergo_ser::header::Header {
    // The block has no top-level "headerBytes" field — but every block
    // in the corpus has a known parent. We need real header bytes.
    // blocks_1_5.json carries transactions and extension, but NOT the
    // raw header. Use `headers_1_2000.json` for that.
    let path = format!(
        "{}/../test-vectors/mainnet/headers_1_2000.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap();
    #[derive(Deserialize)]
    struct HeaderVec {
        height: u32,
        bytes: String,
    }
    let vecs: Vec<HeaderVec> = serde_json::from_str(&raw).unwrap();
    let entry = vecs.iter().find(|v| v.height == block.height).unwrap();
    let raw_bytes = hex::decode(&entry.bytes).unwrap();
    let mut r = VlqReader::new(&raw_bytes);
    read_header(&mut r).unwrap()
}

fn extension_fields(block: &BlockJson) -> Vec<(Vec<u8>, Vec<u8>)> {
    block
        .extension
        .fields
        .iter()
        .map(|(k, v)| (hex::decode(k).unwrap(), hex::decode(v).unwrap()))
        .collect()
}

/// Heights covered by the committed Scala interlinks corpus. h=1 is
/// the vacuous-empty case (covered by a separate test); h=2 and h=3
/// have non-trivial interlinks corpus fixtures used here as the
/// Scala-byte oracle.
const CORPUS_BACKED_HEIGHTS: &[u32] = &[2, 3];

#[test]
fn popow_header_roundtrips_byte_identical_against_scala_corpus_h2_and_h3() {
    let blocks = load_blocks();
    let mut tested = 0;

    for height in CORPUS_BACKED_HEIGHTS {
        let block = blocks
            .iter()
            .find(|b| b.height == *height)
            .unwrap_or_else(|| panic!("h={height} missing from blocks_1_5.json"));
        let header = load_header_bytes(block);
        let ext_fields = extension_fields(block);

        // Scala-bytes oracle: corpus interlinks_fields must equal
        // the extension's fields byte-for-byte. This is the line
        // that makes the test a Scala oracle rather than a self-
        // consistency round-trip.
        let corpus_il_fields = load_interlinks_for(block.height);
        assert_eq!(
            ext_fields, corpus_il_fields,
            "h={}: extension fields differ from Scala-sourced corpus interlinks",
            block.height,
        );

        // Decode the interlinks vector via the existing oracle-pinned
        // unpack_interlinks. For h=2 this yields `[genesis_id]`; for
        // h=3 `[genesis_id, h2_id]`.
        let interlinks: Vec<ModifierId> = unpack_interlinks(&ext_fields).unwrap();
        assert!(
            !interlinks.is_empty(),
            "h={} has no interlinks",
            block.height
        );

        // Build the PoPowHeader via the production constructor.
        let popow = build_popow_header(header.clone(), interlinks.clone(), &ext_fields).unwrap();

        // Codec round-trip: serialize, parse, byte-identical, struct-equal.
        let bytes = serialize_popow_header(&popow).unwrap();
        let mut r = VlqReader::new(&bytes);
        let reparsed = read_popow_header(&mut r).unwrap();
        assert_eq!(
            reparsed, popow,
            "h={}: parsed PoPowHeader differs from built one",
            block.height,
        );
        assert_eq!(
            r.remaining(),
            0,
            "h={}: trailing bytes after parse",
            block.height
        );

        // Re-serialize the re-parsed value and assert byte-stable —
        // no codec normalization drift.
        let bytes_2 = serialize_popow_header(&reparsed).unwrap();
        assert_eq!(bytes, bytes_2, "h={}: re-serialize drift", block.height);

        // Structural validation via the PRODUCTION verifier (not a
        // local duplicate). The batch Merkle proof must verify
        // against the interlinks-subtree root the verifier
        // reconstructs. Scala parity contract:
        // `PoPowHeader.checkInterlinksProof` (PoPowHeader.scala:57-65).
        assert!(
            check_popow_header_interlinks_proof(&popow),
            "h={}: built proof must validate against production verifier",
            block.height,
        );

        tested += 1;
    }
    assert_eq!(tested, CORPUS_BACKED_HEIGHTS.len());
}

#[test]
fn popow_header_genesis_height_1_vacuous_empty_proof() {
    // Genesis (h=1) has 0 extension fields in mainnet. The PoPowHeader
    // built from genesis with empty interlinks must carry an empty
    // interlinks_proof and round-trip identically. Matches Scala
    // `PoPowHeader.scala:58-60` vacuous-proof case.
    let blocks = load_blocks();
    let genesis = blocks.iter().find(|b| b.height == 1).unwrap();
    assert!(
        genesis.extension.fields.is_empty(),
        "genesis fixture invariant: no extension fields",
    );

    let header = load_header_bytes(genesis);
    let popow = build_popow_header(header, vec![], &[]).unwrap();
    assert!(popow.interlinks.is_empty());
    assert!(popow.interlinks_proof.is_empty());

    // Round-trip.
    let bytes = serialize_popow_header(&popow).unwrap();
    let mut r = VlqReader::new(&bytes);
    let reparsed = read_popow_header(&mut r).unwrap();
    assert_eq!(reparsed, popow);

    // Vacuous validation passes via the production verifier
    // (PoPowHeader.scala:58-60).
    assert!(check_popow_header_interlinks_proof(&popow));
}
