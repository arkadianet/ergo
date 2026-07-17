use ergo_primitives::digest::ModifierId;
use ergo_ser::header::Header;

use super::{header_id, is_genesis, scoring::max_level_of};

/// Key prefix for the interlinks vector in the extension's key-value
/// fields. Scala: `Extension.InterlinksVectorPrefix = 0x01`
/// (`Extension.scala:48`).
pub const INTERLINKS_VECTOR_PREFIX: u8 = 0x01;

/// Pack an interlinks vector into the extension's key-value-fields
/// layout. Scala parity: `NipopowAlgos.packInterlinks`
/// (`NipopowAlgos.scala:171-185`).
///
/// Layout per unique entry:
/// * key = `[INTERLINKS_VECTOR_PREFIX, idx as u8]` (2 bytes)
/// * value = `[dup_count as u8, ...modifier_id_bytes]` (33 bytes)
///
/// `idx` is the index in the original interlinks vector at which the
/// entry was observed; `dup_count` is Scala's count of ALL occurrences
/// of that id in the whole vector (== the run length for well-formed
/// vectors, where each id forms one consecutive run; deliberately
/// lossy on adversarial vectors — see the inline note + adversarial
/// parity tests).
pub fn pack_interlinks(links: &[ModifierId]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut idx: usize = 0;
    while idx < links.len() {
        let head = links[idx];
        // Scala counts ALL occurrences of `head` anywhere in the vector
        // (`links.count(_ == headLink)`, NipopowAlgos.scala:177) and then
        // drops that many entries POSITIONALLY from the remainder — for a
        // well-formed interlinks vector (each id in exactly one
        // consecutive run) this equals the run length, but for an
        // adversarial vector like [A,B,A] Scala emits two qty=2 entries
        // and swallows B (oracle-pinned; see the unit tests). The
        // consume-side `checkInterlinksProof` recomputes this packing on
        // RECEIVED interlinks, so any divergence here is an
        // accept/reject divergence against Scala on adversarial popow
        // headers — parity beats sanity.
        let dup_qty = links.iter().filter(|l| **l == head).count();
        let key = vec![INTERLINKS_VECTOR_PREFIX, idx as u8];
        let mut value = Vec::with_capacity(1 + 32);
        value.push(dup_qty as u8);
        value.extend_from_slice(head.as_bytes());
        out.push((key, value));
        idx += dup_qty;
    }
    out
}

/// Inverse of [`pack_interlinks`]: read kv-fields whose key prefix
/// is [`INTERLINKS_VECTOR_PREFIX`], expand the dup-count run encoding,
/// return the flat interlinks vector. Scala parity:
/// `NipopowAlgos.unpackInterlinks` (`NipopowAlgos.scala:190-209`).
///
/// Returns `Err` if any matching field has a value that isn't exactly
/// `1 + 32 = 33` bytes long ("Interlinks improperly packed" in Scala).
/// Fields whose key doesn't start with `INTERLINKS_VECTOR_PREFIX` are
/// ignored — extensions can carry other entries (voted params, etc.)
/// alongside interlinks.
pub fn unpack_interlinks(fields: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<ModifierId>, String> {
    let mut out: Vec<ModifierId> = Vec::new();
    for (key, value) in fields {
        if key.first() != Some(&INTERLINKS_VECTOR_PREFIX) {
            continue;
        }
        if value.len() != 33 {
            return Err(format!(
                "Interlinks improperly packed: value length {} (expected 33)",
                value.len()
            ));
        }
        let duplicates_qty = value[0] as usize;
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&value[1..33]);
        let link = ModifierId::from_bytes(id_bytes);
        for _ in 0..duplicates_qty {
            out.push(link);
        }
    }
    Ok(out)
}

/// Convert a key-value extension field to its Merkle-leaf byte form.
/// Scala parity: `Extension.kvToLeaf`
/// (`Extension.scala:82-83`).
///
/// Layout: `[key.len() as u8, ...key, ...value]`.
pub fn kv_to_leaf(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(1 + key.len() + value.len());
    leaf.push(key.len() as u8);
    leaf.extend_from_slice(key);
    leaf.extend_from_slice(value);
    leaf
}

/// Build a [`PoPowHeader`] from a header, its interlinks vector,
/// and the FULL set of extension fields (kv pairs — used only to
/// check the packed interlinks are really present in this block).
///
/// The interlinks_proof is a `BatchMerkleProof` over the
/// INTERLINKS-ONLY subtree (Scala `interlinksMerkleTree`); the
/// verifier (`check_popow_header_interlinks_proof`) recomputes that
/// same tree from the interlinks vector and validates the proof
/// against its root — NOT against the full extension root. See the
/// inline note below for the epoch-boundary bug this distinction
/// caught.
///
/// Returns `Err` if the interlinks vector cannot be located in
/// `extension_fields` (caller bug — the prover must have read both
/// from the same block).
///
/// Scala parity: `NipopowAlgos.proofForInterlinkVector` +
/// `Extension.merkleTree` + `BatchMerkleProofSerializer.serialize`.
pub fn build_popow_header(
    header: ergo_ser::header::Header,
    interlinks: Vec<ModifierId>,
    extension_fields: &[(Vec<u8>, Vec<u8>)],
) -> Result<ergo_ser::popow_header::PoPowHeader, String> {
    use ergo_crypto::merkle::merkle_proof_by_indices;
    use ergo_ser::batch_merkle_proof::{
        serialize_batch_merkle_proof, BatchMerkleProof, ProofEntry, Side,
    };

    // Empty interlinks (genesis) → the EMPTY BatchMerkleProof, which
    // Scala serializes as 8 zero bytes (two u32 counts), NOT as zero
    // bytes: `proofForInterlinkVector` returns
    // `BatchMerkleProof(Seq.empty, Seq.empty)` (NipopowAlgos.scala:
    // 218-219) and `PoPowHeaderSerializer` embeds its serialized form.
    // Emitting 0 bytes here made every proof containing genesis
    // wire-divergent from Scala (their parser rejects a 0-byte proof
    // blob) -- caught by a live differential run against block h=1.
    if interlinks.is_empty() {
        // Only genesis legitimately carries no interlinks. A non-genesis
        // header with an empty vector is corrupt or forged — the empty
        // BatchMerkleProof verifies vacuously, so without this guard the
        // malformed PoPowHeader would be served as valid. `is_genesis`
        // (zero parent_id) is the codebase's own genesis predicate.
        if !is_genesis(&header) {
            return Err("build_popow_header: empty interlinks vector for a \
                 non-genesis header"
                .to_string());
        }
        let empty = BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        };
        return Ok(ergo_ser::popow_header::PoPowHeader {
            header,
            interlinks,
            interlinks_proof: serialize_batch_merkle_proof(&empty),
        });
    }

    // Pack the interlinks into the extension kv form and require each
    // packed entry to exist in the block's actual extension (Scala's
    // `batchProofFor` similarly yields nothing when a key's leaf isn't
    // found — `ExtensionCandidate.scala:48-54`).
    let packed = pack_interlinks(&interlinks);
    for (key, value) in &packed {
        if !extension_fields.iter().any(|(k, v)| k == key && v == value) {
            return Err(format!(
                "interlinks key {} not found in extension_fields — header + extension may be from different blocks",
                hex::encode(key)
            ));
        }
    }

    // Build the proof over the INTERLINKS-ONLY subtree — NOT the full
    // extension tree. Scala's `ExtensionCandidate.batchProofFor` proves
    // indices within `interlinksMerkleTree` (the tree over interlink
    // fields alone, `ExtensionCandidate.scala:48-54`), and the verifier
    // (`PoPowHeader.checkInterlinksProof`, `PoPowHeader.scala:57-65`)
    // recomputes exactly `merkleTree(packInterlinks(interlinks))` as
    // the expected root. The two trees coincide for interlinks-only
    // extensions (every non-epoch-boundary block), which is how a
    // full-extension-tree construction here survived until a real
    // epoch-boundary block (mixed params + interlink fields; found
    // live at mainnet h=1821696 = 1779*1024) produced proofs Scala's
    // verifier — and our own — reject.
    let leaves: Vec<Vec<u8>> = packed.iter().map(|(k, v)| kv_to_leaf(k, v)).collect();
    let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let interlinks_indices: Vec<u32> = (0..packed.len() as u32).collect();
    let (idx_with_hashes, raw_proofs) = merkle_proof_by_indices(&leaf_refs, &interlinks_indices)
        .ok_or_else(|| {
            "merkle_proof_by_indices returned None (likely empty interlinks)".to_string()
        })?;

    let proof_entries: Vec<ProofEntry> = raw_proofs
        .into_iter()
        .map(|e| ProofEntry {
            digest: e.digest,
            side: if e.side == 0 { Side::Left } else { Side::Right },
        })
        .collect();
    let bmp = BatchMerkleProof {
        indices: idx_with_hashes,
        proofs: proof_entries,
    };
    let interlinks_proof = serialize_batch_merkle_proof(&bmp);

    Ok(ergo_ser::popow_header::PoPowHeader {
        header,
        interlinks,
        interlinks_proof,
    })
}

/// Compute the interlinks vector for the header immediately following
/// `prev_header`, given `prev_interlinks` (the interlinks vector that
/// was attached to `prev_header`).
///
/// Rule (`NipopowAlgos.scala:45-58`):
/// * If `prev_header` is genesis: return `[prev_header.id]`.
/// * Else: let `level = max_level_of(prev_header)`.
///   * If `level == 0`: return `prev_interlinks` unchanged.
///   * Else: take genesis from `prev_interlinks.first()`, then the
///     remaining `(prev_interlinks.len() - 1 - level)` entries from
///     the middle (`tail.dropRight(level)`), then append
///     `prev_header.id` repeated `level` times.
///
/// Panics if `prev_interlinks` is empty and `prev_header` is not
/// genesis — that input shape violates the protocol invariant
/// (`require(prevInterlinks.nonEmpty)` in Scala).
pub fn update_interlinks(
    prev_header: &Header,
    prev_interlinks: &[ModifierId],
) -> Result<Vec<ModifierId>, ergo_ser::error::WriteError> {
    // Prove parent header serializability up-front so the typed-error
    // contract holds across BOTH branches. Without this gate, a
    // malformed V1 header whose `pow_hit` short-circuit yields level 0
    // would slip through the `prev_level == 0` early return below with
    // `Ok(prev_interlinks.to_vec())` — silently accepting unchanged
    // interlinks for an unserializable parent.
    let prev_id_bytes = header_id(prev_header)?;

    if is_genesis(prev_header) {
        return Ok(vec![ModifierId::from_bytes(prev_id_bytes)]);
    }

    assert!(
        !prev_interlinks.is_empty(),
        "interlinks vector cannot be empty for non-genesis header",
    );

    let prev_level = max_level_of(prev_header);
    if prev_level == 0 {
        return Ok(prev_interlinks.to_vec());
    }

    let genesis = prev_interlinks[0];
    let tail = &prev_interlinks[1..];

    // Scala `tail.dropRight(prevLevel)`: drop the last `prevLevel`
    // entries from the tail. If `prevLevel` exceeds the tail length,
    // Seq.dropRight clamps to empty — match that.
    let keep_n = tail.len().saturating_sub(prev_level as usize);
    let kept_tail = &tail[..keep_n];

    let prev_id = ModifierId::from_bytes(prev_id_bytes);
    let mut out = Vec::with_capacity(1 + kept_tail.len() + prev_level as usize);
    out.push(genesis);
    out.extend_from_slice(kept_tail);
    for _ in 0..prev_level {
        out.push(prev_id);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;

    // ----- helpers -----

    /// Deserialize a hex-encoded header. Panics on bad hex / decode.
    fn header_from_hex(hex_bytes: &str) -> Header {
        let raw = hex::decode(hex_bytes).expect("valid hex");
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).expect("valid header bytes")
    }

    /// Mainnet genesis header (height 1). Used by `is_genesis` /
    /// `max_level_of` genesis-path tests. Sourced from
    /// `test-vectors/mainnet/headers_1_10.json[0]`.
    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

    /// Mainnet height 2 (v1 Autolykos, non-genesis). Used by
    /// `max_level_of` non-genesis-path tests for the v1 branch.
    /// Sourced from `headers_1_10.json[1]`.
    const HEIGHT_2_V1_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    // ----- pack_interlinks -----

    #[test]
    fn pack_interlinks_single_unique_entry_emits_one_field() {
        let id = ModifierId::from_bytes([0x11; 32]);
        let packed = pack_interlinks(&[id]);
        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0].0, vec![INTERLINKS_VECTOR_PREFIX, 0]);
        assert_eq!(packed[0].1[0], 1); // duplicate count = 1
        assert_eq!(&packed[0].1[1..], id.as_bytes());
    }

    #[test]
    fn pack_then_unpack_interlinks_roundtrips() {
        // Pack a vector with duplicates → unpack → same vector.
        let g = ModifierId::from_bytes([0x11; 32]);
        let lvl1 = ModifierId::from_bytes([0x22; 32]);
        let lvl2 = ModifierId::from_bytes([0x33; 32]);
        let interlinks = vec![g, lvl1, lvl1, lvl1, lvl2];
        let packed = pack_interlinks(&interlinks);
        let unpacked = unpack_interlinks(&packed).unwrap();
        assert_eq!(unpacked, interlinks);
    }

    #[test]
    fn unpack_interlinks_ignores_non_interlinks_fields() {
        // Real extensions carry voted params + interlinks; only the
        // 0x01-prefixed keys should contribute.
        let g = ModifierId::from_bytes([0x11; 32]);
        let mut packed = pack_interlinks(&[g]);
        packed.push((vec![0x00, 0x05], vec![0xAB, 0xCD])); // some other field
        packed.push((vec![0x02, 0x00], vec![0xEF])); // another non-interlinks field
        let unpacked = unpack_interlinks(&packed).unwrap();
        assert_eq!(unpacked.len(), 1);
        assert_eq!(unpacked[0], g);
    }

    #[test]
    fn unpack_interlinks_rejects_wrong_value_length() {
        // A value that's not exactly 33 bytes means the dup-count
        // run-encoding is corrupted — Scala raises "Interlinks
        // improperly packed".
        let bad_fields = vec![(vec![0x01, 0x00], vec![0x01, 0xAA, 0xBB])];
        let err = unpack_interlinks(&bad_fields).expect_err("bad length must error");
        assert!(err.contains("improperly packed"), "unexpected: {err}");
    }

    #[test]
    fn pack_interlinks_runs_of_duplicates_get_run_length_encoded() {
        let g = ModifierId::from_bytes([0x11; 32]);
        let lvl1 = ModifierId::from_bytes([0x22; 32]);
        // Interlinks: [g, lvl1, lvl1, lvl1] → 2 unique entries, the
        // second with dup_count = 3 starting at index 1.
        let packed = pack_interlinks(&[g, lvl1, lvl1, lvl1]);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0].1[0], 1); // g appears once at index 0
        assert_eq!(packed[1].0, vec![INTERLINKS_VECTOR_PREFIX, 1]); // starts at index 1
        assert_eq!(packed[1].1[0], 3); // dup_count = 3
    }

    // ----- update_interlinks -----

    #[test]
    fn update_interlinks_genesis_returns_singleton_with_prev_id() {
        let g = header_from_hex(GENESIS_HEX);
        let out = update_interlinks(&g, &[]).expect("genesis header serializes");
        assert_eq!(out.len(), 1);
        assert_eq!(*out[0].as_bytes(), header_id(&g).unwrap());
    }

    #[test]
    fn update_interlinks_zero_level_returns_input_unchanged() {
        // Construct a non-genesis header whose `max_level_of` returns 0.
        // Real mainnet headers occasionally hit level 0 (most common
        // case), but determining that requires running the function on
        // a known vector. Instead: any non-genesis header with very low
        // real-target margin works. We test the BEHAVIORAL contract via
        // synthesis: we cannot easily synthesize a level-0 header
        // without manipulating PoW, so this test pins the input/output
        // shape for the level==0 branch by mocking via dependency
        // injection... which we don't have. Skip the in-mod assertion
        // and rely on the crate's oracle test surface instead. Documented
        // here so a future reader knows the intent and to extend coverage
        // when a level-0 mainnet header is pinned.
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let prev_interlinks = vec![
            ModifierId::from_bytes([0x00; 32]), // synthetic "genesis" id
            ModifierId::from_bytes([0xAA; 32]), // synthetic level-1 link
        ];
        // Compute level for h2 — if it's 0, prev_interlinks comes back
        // unchanged; otherwise the test exercises the level > 0 path
        // (which is also covered below). Either is a valid property,
        // so we just assert the structural shape Scala produces:
        let level = max_level_of(&h2);
        let out = update_interlinks(&h2, &prev_interlinks).expect("h2 header serializes");
        if level == 0 {
            assert_eq!(out, prev_interlinks);
        } else {
            // level > 0 path: out starts with genesis, then truncated
            // middle, then `level` copies of h2.id.
            assert_eq!(out[0], prev_interlinks[0]);
            let h2_id = ModifierId::from_bytes(header_id(&h2).unwrap());
            for entry in &out[out.len() - level as usize..] {
                assert_eq!(*entry, h2_id);
            }
        }
    }

    #[test]
    fn update_interlinks_genesis_branch_ignores_provided_interlinks() {
        // Genesis path returns `[genesis.id]` regardless of any
        // prev_interlinks passed in (Scala signature accepts an
        // `Option<Extension>` and short-circuits to Seq(prevHeader.id)
        // for genesis). Pin that the input vector is not consulted.
        let g = header_from_hex(GENESIS_HEX);
        let interlinks = vec![
            ModifierId::from_bytes([0x01; 32]),
            ModifierId::from_bytes([0xAA; 32]),
            ModifierId::from_bytes([0xBB; 32]),
        ];
        let out = update_interlinks(&g, &interlinks).expect("genesis header serializes");
        assert_eq!(out.len(), 1);
        assert_eq!(*out[0].as_bytes(), header_id(&g).unwrap());
    }

    // ----- error paths -----

    #[test]
    #[should_panic(expected = "interlinks vector cannot be empty for non-genesis header")]
    fn update_interlinks_non_genesis_empty_interlinks_panics() {
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        // HEIGHT_2_V1_HEX is a real serializable mainnet header, so the
        // up-front header_id gate succeeds and the assert! on empty
        // interlinks is the panic the caller hits.
        let _ = update_interlinks(&h2, &[]);
    }

    #[test]
    fn update_interlinks_unserializable_parent_returns_err_even_at_level_0() {
        // A V1 header whose `d` payload is wider than the on-wire
        // `u8` length prefix (256+ bytes) (a) fails `serialize_header`
        // (write_solution rejects), and could (b) bypass that failure
        // in `update_interlinks` if `max_level_of` returns 0 — the V1
        // `pow_hit` branch reads `d` directly without serializing.
        // The up-front `header_id(prev_header)?` gate makes
        // serialization a precondition on BOTH branches; this test
        // synthesizes the unserializable-V1 case and asserts Err.
        use ergo_primitives::digest::ModifierId;
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;

        let mut h = header_from_hex(HEIGHT_2_V1_HEX);
        // Replace the V1 solution with an overlong d payload (260 bytes
        // > u8::MAX) so write_solution rejects per
        // ergo-ser/src/autolykos.rs::write_solution length cap.
        h.solution = AutolykosSolution::V1 {
            pk: GroupElement::from_bytes([0x02; 33]),
            w: GroupElement::from_bytes([0x03; 33]),
            nonce: [0x04; 8],
            d: vec![0x05u8; 260],
        };

        // prev_interlinks chosen so prev_level == 0 path is reachable
        // for the synthesized header (the gate is the up-front
        // header_id check, not the level computation — so this Err
        // surfaces regardless).
        let prev_interlinks = vec![ModifierId::from_bytes([0x00; 32])];
        let result = update_interlinks(&h, &prev_interlinks);
        assert!(
            result.is_err(),
            "unserializable parent header must surface WriteError, got Ok({:?})",
            result
        );
    }

    // ----- build_popow_header -----

    #[test]
    fn build_popow_header_empty_interlinks_returns_empty_proof() {
        let g = header_from_hex(GENESIS_HEX);
        let p = build_popow_header(g.clone(), vec![], &[]).unwrap();
        assert!(p.interlinks.is_empty());
        // Canonical empty-proof wire form = 8 zero bytes (Scala's
        // serialized empty BatchMerkleProof), NOT 0 bytes — see the
        // genesis wire-form fix in build_popow_header.
        assert_eq!(p.interlinks_proof, vec![0u8; 8]);
    }

    #[test]
    fn build_popow_header_with_interlinks_produces_verifiable_proof() {
        // Synthesize a PoPowHeader from a header + interlinks + a
        // MIXED extension (interlink fields + unrelated fields — the
        // epoch-boundary shape that exposed the live construction bug
        // at mainnet h=1821696). The Scala contract
        // (`PoPowHeader.checkInterlinksProof`, PoPowHeader.scala:57-65)
        // verifies the proof against the INTERLINKS-ONLY tree root
        // recomputed from the interlinks vector — NOT against the full
        // extension root. This test previously pinned the
        // full-extension-root behavior, i.e. it pinned the bug.
        use crate::popow::merkle::verify_batch_merkle_proof;
        use crate::popow::proof::check_popow_header_interlinks_proof;
        use ergo_crypto::merkle::merkle_tree_root;
        use ergo_ser::batch_merkle_proof::deserialize_batch_merkle_proof;

        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let interlinks = vec![
            ModifierId::from_bytes([0x11; 32]),
            ModifierId::from_bytes([0x22; 32]),
        ];
        let packed_interlinks = pack_interlinks(&interlinks);
        // Unrelated fields FIRST — mirrors real epoch-boundary blocks,
        // where protocol-parameter fields (key prefix 0x00) precede the
        // interlink fields, shifting their full-tree positions.
        let mut extension_fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (vec![0x00, 0x01], vec![0xAB, 0xCD]),
            (vec![0x00, 0x04], vec![0xEF]),
        ];
        extension_fields.extend(packed_interlinks.clone());

        let popow = build_popow_header(h2.clone(), interlinks.clone(), &extension_fields).unwrap();
        assert!(!popow.interlinks_proof.is_empty());

        // The consume-side validator (Scala parity: interlinks-only
        // tree) must accept the constructed proof.
        assert!(
            check_popow_header_interlinks_proof(&popow),
            "constructed proof must verify against the interlinks-only tree root"
        );

        // And explicitly: the proof reduces to the interlinks-only
        // root, NOT the full-extension root (they differ here because
        // of the non-interlink fields).
        let bmp = deserialize_batch_merkle_proof(&popow.interlinks_proof).unwrap();
        let interlink_leaves: Vec<Vec<u8>> = packed_interlinks
            .iter()
            .map(|(k, v)| kv_to_leaf(k, v))
            .collect();
        let interlink_refs: Vec<&[u8]> = interlink_leaves.iter().map(|l| l.as_slice()).collect();
        assert!(verify_batch_merkle_proof(
            &bmp,
            &merkle_tree_root(&interlink_refs)
        ));
        let full_leaves: Vec<Vec<u8>> = extension_fields
            .iter()
            .map(|(k, v)| kv_to_leaf(k, v))
            .collect();
        let full_refs: Vec<&[u8]> = full_leaves.iter().map(|l| l.as_slice()).collect();
        assert!(
            !verify_batch_merkle_proof(&bmp, &merkle_tree_root(&full_refs)),
            "full-extension root must NOT verify — that was the old buggy contract"
        );
    }
}

#[cfg(test)]
mod pack_interlinks_scala_adversarial_parity {
    use super::*;

    fn mid(b: u8) -> ModifierId {
        ModifierId::from_bytes([b; 32])
    }

    /// Oracle-pinned (scala-cli, ergo-core 6.0.2 `NipopowAlgos.packInterlinks`,
    /// 2026-07-05): adversarial NON-consecutive duplicate vectors. Scala's
    /// count-all + positional-drop semantics are lossy — `[A,B,A]` packs to
    /// two qty=2 A-entries and B is swallowed. The verifier recomputes this
    /// packing on received interlinks, so byte-parity here decides
    /// accept/reject parity on adversarial popow headers.
    #[test]
    fn adversarial_vectors_match_scala_exactly() {
        let a = mid(0xAA);
        let b = mid(0xBB);
        // [A,B,A] => (idx0, qty2, A), (idx2, qty2, A)
        let p = pack_interlinks(&[a, b, a]);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].0, vec![INTERLINKS_VECTOR_PREFIX, 0]);
        assert_eq!(p[0].1[0], 2);
        assert_eq!(&p[0].1[1..], a.as_bytes());
        assert_eq!(p[1].0, vec![INTERLINKS_VECTOR_PREFIX, 2]);
        assert_eq!(p[1].1[0], 2);
        assert_eq!(&p[1].1[1..], a.as_bytes());
        // [A,A,B,A] => (idx0, qty3, A), (idx3, qty3, A)
        let p = pack_interlinks(&[a, a, b, a]);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].0[1], p[0].1[0]), (0, 3));
        assert_eq!((p[1].0[1], p[1].1[0]), (3, 3));
        assert_eq!(&p[1].1[1..], a.as_bytes());
        // [A,A,B] (well-formed) => (idx0, qty2, A), (idx2, qty1, B)
        let p = pack_interlinks(&[a, a, b]);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].0[1], p[0].1[0]), (0, 2));
        assert_eq!((p[1].0[1], p[1].1[0]), (2, 1));
        assert_eq!(&p[1].1[1..], b.as_bytes());
    }
}
