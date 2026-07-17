use super::*;
use ergo_primitives::vlq::VlqError;

#[test]
fn inv_roundtrip() {
    let data = InvData {
        type_id: 101,
        ids: vec![[0xAA; 32], [0xBB; 32]],
    };
    let bytes = serialize_inv(&data).unwrap();
    let parsed = deserialize_inv(&bytes).unwrap();
    assert_eq!(parsed.type_id, 101);
    assert_eq!(parsed.ids.len(), 2);
    assert_eq!(parsed.ids[0], [0xAA; 32]);
    assert_eq!(parsed.ids[1], [0xBB; 32]);
}

#[test]
fn inv_empty_rejected() {
    let data = InvData {
        type_id: 101,
        ids: Vec::new(),
    };
    assert!(serialize_inv(&data).is_err());
}

#[test]
fn modifiers_roundtrip() {
    let data = ModifiersData {
        type_id: 102,
        modifiers: vec![([0x11; 32], vec![1, 2, 3]), ([0x22; 32], vec![4, 5])],
    };
    let bytes = serialize_modifiers(&data).unwrap();
    let parsed = deserialize_modifiers(&bytes).unwrap();
    assert_eq!(parsed.type_id, 102);
    assert_eq!(parsed.modifiers.len(), 2);
    assert_eq!(parsed.modifiers[0].1, vec![1, 2, 3]);
    assert_eq!(parsed.modifiers[1].1, vec![4, 5]);
}

#[test]
fn deserialize_modifiers_size_check_matches_serializer_accounting() {
    // Regression for the +4 length-prefix accounting. The
    // serializer counts `MODIFIER_ID_SIZE + 4 + obj_len` per
    // entry (`message.rs:118-123`); the deserializer historically
    // counted only `MODIFIER_ID_SIZE + obj_len`, leaving a
    // 4-byte-per-entry undercount that let crafted multi-entry
    // payloads slip past the `MAX_MODIFIER_WITH_RESERVE` guard.
    //
    // Directly craft a payload (bypassing the connection-layer
    // `MAX_PAYLOAD_SIZE` check) with 250 000 zero-length entries
    // so the corrected accounting (`5 + 250_000 * 36 = 9_000_005`)
    // exceeds the reserve cap (`8_194_304`) and triggers
    // `ModifiersTooLarge`. Under the buggy accounting
    // (`5 + 250_000 * 32 = 8_000_005`) this fits and the payload
    // would be accepted.
    let n: u32 = 250_000;
    let mut w = VlqWriter::new();
    w.put_u8(101);
    w.put_u32(n);
    let mut payload = w.result();
    for _ in 0..n {
        payload.extend_from_slice(&[0u8; 32]); // id
        payload.push(0); // VLQ-encoded obj_len = 0
    }
    let result = deserialize_modifiers(&payload);
    assert!(
        matches!(result, Err(MessageError::ModifiersTooLarge(_))),
        "fixed accounting must reject 250k zero-payload entries, got {result:?}"
    );
}

#[test]
fn deserialize_modifiers_huge_count_does_not_oom() {
    // type_id (1B) + count = i32::MAX (VLQ) + no entries. Before the cap,
    // `Vec::with_capacity(count)` reserved ~120 GiB and aborted; the
    // `min(remaining / MIN_MODIFIER_ENTRY_BYTES)` bound reserves only what
    // the payload can hold, so this returns a decode error. (The test
    // reaching its assertion at all is the regression guard.)
    let mut payload = vec![101u8]; // type_id
    payload.extend_from_slice(&ergo_primitives::vlq::encode_vlq(i32::MAX as u64));
    // Pin the failure class to a byte-read error (the loop reached the first
    // entry and ran out of bytes), NOT a semantic reject. An accidental
    // "cap became a reject" regression would surface as a different
    // `MessageError` variant and fail this match — where `is_err()` wouldn't.
    assert!(matches!(
        deserialize_modifiers(&payload),
        Err(MessageError::Read(_))
    ));
}

#[test]
fn deserialize_snapshots_info_huge_count_does_not_oom() {
    // count = i32::MAX (VLQ) with no manifest entries. The 20 KiB payload
    // cap bounds the message but not the decoded count; the
    // `min(remaining / MIN_SNAPSHOT_ENTRY_BYTES)` bound stops the up-front
    // reservation from aborting the process.
    let payload = ergo_primitives::vlq::encode_vlq(i32::MAX as u64);
    // Pin the failure class to a byte-read error (see modifiers test above).
    assert!(matches!(
        deserialize_snapshots_info(&payload),
        Err(MessageError::Read(_))
    ));
}

#[test]
fn get_snapshots_info_rejects_non_empty_payload() {
    // Scala parity: GetSnapshotsInfo carries no payload. The
    // earlier "<100 bytes is fine" tolerance was a wire-compat
    // blind spot — a strict-empty check matches `deserialize_get_peers`.
    assert!(deserialize_get_snapshots_info(&[]).is_ok());
    let result = deserialize_get_snapshots_info(&[0x00]);
    assert!(
        matches!(result, Err(MessageError::NonEmptyGetSnapshotsInfo(1))),
        "non-empty payload must be rejected, got {result:?}"
    );
}

#[test]
fn sync_info_v1_roundtrip() {
    let info = SyncInfo::V1 {
        header_ids: vec![[0x01; 32], [0x02; 32], [0x03; 32]],
    };
    let bytes = serialize_sync_info(&info);
    let parsed = deserialize_sync_info(&bytes).unwrap();
    match parsed {
        SyncInfo::V1 { header_ids } => {
            assert_eq!(header_ids.len(), 3);
            assert_eq!(header_ids[0], [0x01; 32]);
        }
        _ => panic!("expected V1"),
    }
}

#[test]
fn sync_info_v2_roundtrip() {
    let info = SyncInfo::V2 {
        headers: vec![vec![10, 20, 30], vec![40, 50]],
    };
    let bytes = serialize_sync_info(&info);
    let parsed = deserialize_sync_info(&bytes).unwrap();
    match parsed {
        SyncInfo::V2 { headers } => {
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0], vec![10, 20, 30]);
            assert_eq!(headers[1], vec![40, 50]);
        }
        _ => panic!("expected V2"),
    }
}

#[test]
fn sync_info_empty_v1() {
    let info = SyncInfo::V1 {
        header_ids: Vec::new(),
    };
    let bytes = serialize_sync_info(&info);
    let parsed = deserialize_sync_info(&bytes).unwrap();
    match parsed {
        SyncInfo::V1 { header_ids } => assert!(header_ids.is_empty()),
        _ => panic!("expected V1"),
    }
}

#[test]
fn snapshots_info_roundtrip() {
    let info = SnapshotsInfo {
        available_manifests: vec![(100000, [0xDD; 32]), (200000, [0xEE; 32])],
    };
    let bytes = serialize_snapshots_info(&info);
    let parsed = deserialize_snapshots_info(&bytes).unwrap();
    assert_eq!(parsed.available_manifests.len(), 2);
    assert_eq!(parsed.available_manifests[0].0, 100000);
    assert_eq!(parsed.available_manifests[1].1, [0xEE; 32]);
}

/// Pin the SnapshotsInfo wire layout against a manually-derived
/// Scala byte sequence. One entry, height=100, manifest=[0xAB;32]:
///
/// - VLQ(1) for the entry count = `0x01`
/// - ZigZag-VLQ(100) for height = `0xC8 0x01` (100 << 1 = 200,
///   VLQ(200) = `0xC8 0x01`: low 7 bits 0x48 with continuation
///   bit set, then 0x01 with continuation clear)
/// - 32 raw bytes for the manifest id
///
/// Total: 1 + 2 + 32 = 35 bytes.
///
/// Derived from Scala `SnapshotsInfoSpec.serialize` in
/// `BasicMessagesRepo.scala:93-99`. The Scala-anchored full-frame
/// oracle suite at `tests/wire_vectors_oracle.rs` covers `Inv`,
/// `RequestModifier`, `SyncInfo` V1, and `Modifiers` from upstream
/// `*Specification.scala` byte fixtures; `SnapshotsInfo` doesn't
/// yet have an upstream byte fixture, so this inline test stays as
/// the Scala-source-line anchor until one lands. See
/// `test-vectors/ergo-p2p/PROVISIONING.md` § "Vectors not in
/// this tree" for the follow-up.
#[test]
fn snapshots_info_byte_layout_one_entry() {
    let info = SnapshotsInfo {
        available_manifests: vec![(100, [0xAB; 32])],
    };
    let bytes = serialize_snapshots_info(&info);
    let mut expected = vec![0x01u8, 0xC8, 0x01];
    expected.extend_from_slice(&[0xABu8; 32]);
    assert_eq!(
        bytes, expected,
        "SnapshotsInfo wire bytes drifted from Scala spec",
    );
}

#[test]
fn snapshots_info_byte_layout_empty() {
    // Empty manifest list — one VLQ byte (0x00) for count, no payload.
    let info = SnapshotsInfo {
        available_manifests: vec![],
    };
    let bytes = serialize_snapshots_info(&info);
    assert_eq!(
        bytes,
        vec![0x00u8],
        "empty SnapshotsInfo must be a single 0x00 byte"
    );
    let parsed = deserialize_snapshots_info(&bytes).unwrap();
    assert!(parsed.available_manifests.is_empty());
}

#[test]
fn get_snapshots_info_empty_payload() {
    // Scala parity: GetSnapshotsInfo carries an empty payload.
    // serialize must produce zero bytes; deserialize must accept
    // them (the existing test pins the rejection of non-empty).
    let bytes = serialize_get_snapshots_info();
    assert_eq!(bytes, Vec::<u8>::new());
    let result = deserialize_get_snapshots_info(&bytes);
    assert!(result.is_ok());
}

#[test]
fn get_manifest_roundtrip() {
    // 32-byte manifest id, no length prefix.
    let id = [0x42u8; 32];
    let bytes = serialize_get_manifest(&id);
    assert_eq!(
        bytes.len(),
        32,
        "GetManifest payload is exactly 32 raw bytes"
    );
    assert_eq!(bytes, id.to_vec());
    let parsed = deserialize_get_manifest(&bytes).unwrap();
    assert_eq!(parsed, id);
}

#[test]
fn get_manifest_rejects_short_payload() {
    let err = deserialize_get_manifest(&[0u8; 31]).unwrap_err();
    assert!(
        matches!(
            err,
            MessageError::PayloadTooShort {
                kind: "get_manifest",
                got: 31,
                min: 32,
            }
        ),
        "expected PayloadTooShort with kind/got/min, got {err:?}",
    );
}

#[test]
fn manifest_roundtrip() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let bytes = serialize_manifest(&data);
    let parsed = deserialize_manifest(&bytes).unwrap();
    assert_eq!(parsed, data);
}

/// Pin Manifest's wire layout: VLQ-length prefix + raw bytes.
/// Mirrors Scala `ManifestSpec.serialize` in
/// `BasicMessagesRepo.scala:146-148`. With a 4-byte payload,
/// the prefix VLQ(4) is a single byte 0x04. Same follow-up
/// status as `snapshots_info_byte_layout_one_entry` — no
/// upstream Scala-side byte fixture yet, so this stays as the
/// Scala-source-line anchor.
#[test]
fn manifest_byte_layout_short_payload() {
    let data = vec![0x01, 0x02, 0x03, 0x04];
    let bytes = serialize_manifest(&data);
    assert_eq!(bytes, vec![0x04, 0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn get_utxo_chunk_roundtrip() {
    // Same shape as GetManifest — 32 raw bytes.
    let id = [0x99u8; 32];
    let bytes = serialize_get_utxo_chunk(&id);
    assert_eq!(bytes.len(), 32);
    let parsed = deserialize_get_utxo_chunk(&bytes).unwrap();
    assert_eq!(parsed, id);
}

#[test]
fn get_utxo_chunk_rejects_short_payload() {
    let err = deserialize_get_utxo_chunk(&[0u8; 31]).unwrap_err();
    assert!(
        matches!(
            err,
            MessageError::PayloadTooShort {
                kind: "get_utxo_chunk",
                got: 31,
                min: 32,
            }
        ),
        "expected PayloadTooShort with kind/got/min, got {err:?}",
    );
}

#[test]
fn utxo_chunk_roundtrip() {
    // UtxoSnapshotChunk uses the same wire shape as Manifest.
    let data = vec![0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
    let bytes = serialize_utxo_chunk(&data);
    let parsed = deserialize_utxo_chunk(&bytes).unwrap();
    assert_eq!(parsed, data);
}

#[test]
fn utxo_chunk_byte_layout_matches_manifest() {
    // UtxoSnapshotChunk and Manifest share encoding — the same
    // input must produce identical bytes via either function.
    // Locks the "same format" invariant in
    // `serialize_utxo_chunk = serialize_manifest`.
    let data = vec![0xCC; 17];
    let chunk_bytes = serialize_utxo_chunk(&data);
    let manifest_bytes = serialize_manifest(&data);
    assert_eq!(chunk_bytes, manifest_bytes);
}

#[test]
fn get_nipopow_proof_roundtrip() {
    let data = NipopowProofData {
        m: 6,
        k: 10,
        header_id_opt: Some([0xFF; 32]),
    };
    let bytes = serialize_get_nipopow_proof(&data);
    let parsed = deserialize_get_nipopow_proof(&bytes).unwrap();
    assert_eq!(parsed.m, 6);
    assert_eq!(parsed.k, 10);
    assert_eq!(parsed.header_id_opt, Some([0xFF; 32]));
}

#[test]
fn get_nipopow_proof_without_header_id() {
    let data = NipopowProofData {
        m: 3,
        k: 7,
        header_id_opt: None,
    };
    let bytes = serialize_get_nipopow_proof(&data);
    let parsed = deserialize_get_nipopow_proof(&bytes).unwrap();
    assert_eq!(parsed.m, 3);
    assert_eq!(parsed.k, 7);
    assert!(parsed.header_id_opt.is_none());
}

#[test]
fn nipopow_proof_roundtrip() {
    let proof = vec![42; 100];
    let bytes = serialize_nipopow_proof(&proof).unwrap();
    let parsed = deserialize_nipopow_proof(&bytes).unwrap();
    assert_eq!(parsed, proof);
}

// ----- pad_length truncation -----

#[test]
fn get_nipopow_proof_missing_pad_length_errors() {
    // Build the prefix without the trailing u16 pad_length. Scala
    // and our reader both treat pad_length as mandatory; absence
    // must surface as a parse error rather than be silently
    // accepted as "pad_length = 0".
    let mut w = VlqWriter::new();
    w.put_i32(6);
    w.put_i32(10);
    w.put_u8(0); // header_id absent
                 // intentionally do NOT write put_u16 pad_length
    let bytes = w.result();
    let err = deserialize_get_nipopow_proof(&bytes).expect_err("pad_length absent");
    // Mandatory u16 pad_length absent: get_u16() is VLQ-decoded
    // so EOF surfaces as ReadError::Vlq(VlqError::UnexpectedEnd),
    // not the top-level UnexpectedEnd. The nested taxonomy lets
    // callers distinguish "no bytes for VLQ" from "raw fixed-width
    // read short" without parsing the error message.
    assert!(
        matches!(
            err,
            MessageError::Read(ReadError::Vlq(VlqError::UnexpectedEnd))
        ),
        "expected ReadError::Vlq(UnexpectedEnd) on pad_length read, got {err:?}",
    );
}

#[test]
fn get_nipopow_proof_truncated_pad_errors() {
    // pad_length claims 5 bytes of padding but only 2 follow.
    // Scala's `getBytes(remainingBytes)` throws here; we must too.
    let mut w = VlqWriter::new();
    w.put_i32(6);
    w.put_i32(10);
    w.put_u8(0);
    w.put_u16(5); // claim 5 pad bytes
    w.put_bytes(&[0xAA, 0xBB]); // only 2 actually present
    let bytes = w.result();
    let err = deserialize_get_nipopow_proof(&bytes).expect_err("truncated pad");
    // Claimed pad_len = 5 but only 2 bytes follow → get_bytes(5)
    // hits EOF needing 5 bytes from the truncation position.
    assert!(
        matches!(
            err,
            MessageError::Read(ReadError::UnexpectedEnd { needed: 5, .. })
        ),
        "expected ReadError::UnexpectedEnd on pad truncation, got {err:?}",
    );
}

#[test]
fn get_nipopow_proof_pad_above_size_limit_silent_no_op() {
    // Scala parity: `if (remainingBytes > 0 && remainingBytes < SizeLimit)`
    // means a pad_length >= 1000 is silently ignored (no read,
    // no error). Pin the parity even though no honest sender
    // would emit such a value (the outer SizeLimit check would
    // reject the message anyway in practice).
    let mut w = VlqWriter::new();
    w.put_i32(6);
    w.put_i32(10);
    w.put_u8(0);
    w.put_u16(1500); // >= 1000, Scala silent no-op branch
    let bytes = w.result();
    let parsed = deserialize_get_nipopow_proof(&bytes).expect("silent no-op");
    assert_eq!(parsed.m, 6);
    assert_eq!(parsed.k, 10);
    assert!(parsed.header_id_opt.is_none());
}

#[test]
fn nipopow_proof_missing_pad_length_errors() {
    // Same parity check for code 91 — proof bytes followed by
    // no pad_length is a parse error.
    let mut w = VlqWriter::new();
    w.put_u32(3); // proof len
    w.put_bytes(&[0xAA, 0xBB, 0xCC]); // proof bytes
                                      // intentionally omit put_u16 pad_length
    let bytes = w.result();
    let err = deserialize_nipopow_proof(&bytes).expect_err("pad_length absent");
    assert!(
        matches!(
            err,
            MessageError::Read(ReadError::Vlq(VlqError::UnexpectedEnd))
        ),
        "expected ReadError::Vlq(UnexpectedEnd) on pad_length read, got {err:?}",
    );
}

#[test]
fn nipopow_proof_truncated_pad_errors() {
    let mut w = VlqWriter::new();
    w.put_u32(3);
    w.put_bytes(&[0xAA, 0xBB, 0xCC]);
    w.put_u16(10); // claim 10 pad bytes
    w.put_bytes(&[0xDD; 3]); // only 3 present
    let bytes = w.result();
    let err = deserialize_nipopow_proof(&bytes).expect_err("truncated pad");
    assert!(
        matches!(
            err,
            MessageError::Read(ReadError::UnexpectedEnd { needed: 10, .. })
        ),
        "expected ReadError::UnexpectedEnd on pad truncation, got {err:?}",
    );
}

/// Wrap an inner-proof byte blob in the outer NipopowProof P2P
/// envelope (length-prefixed bytes + mandatory u16 pad_length) so
/// the ingress tests below all use the same outer framing.
fn wrap_nipopow_proof_envelope(inner_bytes: &[u8]) -> Vec<u8> {
    let mut outer = VlqWriter::new();
    outer.put_u32(inner_bytes.len() as u32);
    outer.put_bytes(inner_bytes);
    outer.put_u16(0); // pad_length
    outer.result()
}

#[test]
fn nipopow_proof_ingress_rejects_hostile_prefix_size_before_alloc() {
    // End-to-end ingress pin: a NipopowProof P2P payload that
    // claims `prefix_size = i32::MAX` must fail cleanly at the
    // structural parser, with no node-side allocation amplification.
    // Goes through both the ergo-p2p outer envelope (length-prefixed
    // proof blob + mandatory u16 pad_length) and the ergo-ser
    // inner parser (`deserialize_nipopow_proof` cap gate).
    let mut inner = VlqWriter::new();
    inner.put_u32(6); // m
    inner.put_u32(10); // k
    inner.put_u32(i32::MAX as u32); // hostile prefix_size
    let payload = wrap_nipopow_proof_envelope(&inner.result());

    // Outer P2P envelope succeeds — payload is well-formed and
    // well under the 2 MiB size limit, so the DoS would happen
    // downstream in the inner parser if the cap gate were missing.
    let proof_bytes = deserialize_nipopow_proof(&payload).expect("outer envelope ok");

    // Inner ergo-ser parser must reject with InvalidData(cap) at
    // the prefix_size gate, before Vec::with_capacity is invoked.
    let err = ergo_ser::popow_proof::deserialize_nipopow_proof(&proof_bytes)
        .expect_err("hostile prefix_size must reject");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("prefix length") && msg.contains("10000"),
        "expected prefix cap-violation message, got: {msg}"
    );
}

#[test]
fn nipopow_proof_ingress_rejects_hostile_suffix_size_before_alloc() {
    // Ingress pin for the `suffix_size` cap. The inner proof has
    // an empty prefix (so prefix_size cap passes) and a minimal
    // suffix_head, then a hostile `suffix_size = i32::MAX`.
    // The outer envelope must accept the payload (well under 2
    // MiB) and the inner parser must reject at the suffix gate.
    let mut inner = VlqWriter::new();
    inner.put_u32(6); // m
    inner.put_u32(10); // k
    inner.put_u32(0); // prefix_size — empty, passes its cap
                      // Minimal suffix_head: an empty PoPowHeader wrapping the
                      // mainnet genesis. We embed the bytes inline; if the
                      // genesis-header format ever shifts, the existing
                      // `nipopow_proof_roundtrip` test in this file will fail
                      // first and prompt a sync.
    let head = build_minimal_popow_header_bytes();
    inner.put_u32(head.len() as u32);
    inner.put_bytes(&head);
    inner.put_u32(i32::MAX as u32); // hostile suffix_size
    let payload = wrap_nipopow_proof_envelope(&inner.result());

    let proof_bytes = deserialize_nipopow_proof(&payload).expect("outer envelope ok");
    let err = ergo_ser::popow_proof::deserialize_nipopow_proof(&proof_bytes)
        .expect_err("hostile suffix_size must reject");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("suffix_tail length") && msg.contains("1024"),
        "expected suffix cap-violation message, got: {msg}"
    );
}

#[test]
fn popow_header_ingress_rejects_hostile_links_qty_before_alloc() {
    // Ingress pin for the `links_qty` cap inside a PoPowHeader.
    // Wraps a PoPowHeader payload (header + hostile links_qty)
    // as the suffix_head of a NipopowProof so it travels through
    // the full ingress path. The inner parser must reject at the
    // links_qty gate inside `read_popow_header`.
    let mut head = VlqWriter::new();
    let genesis = genesis_header_bytes();
    head.put_u32(genesis.len() as u32);
    head.put_bytes(&genesis);
    head.put_u32(i32::MAX as u32); // hostile links_qty
    let head_bytes = head.result();

    let mut inner = VlqWriter::new();
    inner.put_u32(6); // m
    inner.put_u32(10); // k
    inner.put_u32(0); // prefix_size — empty
    inner.put_u32(head_bytes.len() as u32);
    inner.put_bytes(&head_bytes); // suffix_head w/ hostile interlinks
    let payload = wrap_nipopow_proof_envelope(&inner.result());

    let proof_bytes = deserialize_nipopow_proof(&payload).expect("outer envelope ok");
    let err = ergo_ser::popow_proof::deserialize_nipopow_proof(&proof_bytes)
        .expect_err("hostile links_qty must reject");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("interlinks length") && msg.contains("256"),
        "expected interlinks cap-violation message, got: {msg}"
    );
}

#[test]
fn block_transactions_ingress_rejects_hostile_v2_count_before_alloc() {
    // End-to-end pin for the v2 BlockTransactions soft-alloc cap.
    // Wraps a hostile v2 section (header_id + v2 marker + hostile
    // post-marker count + no tx bytes) inside the Modifiers envelope
    // that real peers send (`type_id = 102`, one entry). The outer
    // envelope decodes; the inner parser must reject with
    // InvalidData(cap) WITHOUT triggering a multi-GiB alloc.
    let mut section = VlqWriter::new();
    section.put_bytes(&[0xAA; 32]); // header_id
                                    // v2 marker: MAX_TRANSACTIONS_IN_BLOCK + block_version=2 = 10_000_002
    section.put_u32(10_000_002);
    // Hostile post-marker count past the hard cap. The soft-alloc
    // cap also protects honest values up to MAX_TRANSACTIONS_IN_BLOCK
    // — exercised by `read_block_transactions_v2_count_at_hard_cap_bounds_initial_alloc`
    // in the ergo-ser test module.
    section.put_u32(i32::MAX as u32);
    let section_bytes = section.result();

    // Outer Modifiers envelope: type_id=102, one entry.
    let mut outer = VlqWriter::new();
    outer.put_u8(102); // TYPE_BLOCK_TRANSACTIONS
    outer.put_u32(1); // count of entries
    outer.put_bytes(&[0xAA; 32]); // modifier id (matches header_id above)
    outer.put_u32(section_bytes.len() as u32);
    outer.put_bytes(&section_bytes);
    let envelope = outer.result();

    let modifiers = deserialize_modifiers(&envelope).expect("outer envelope ok");
    assert_eq!(modifiers.type_id, 102);
    assert_eq!(modifiers.modifiers.len(), 1);
    let (_id, raw_section) = &modifiers.modifiers[0];

    // Inner ergo-ser parser must reject at the cap gate.
    let mut r = ergo_primitives::reader::VlqReader::new(raw_section);
    let err = ergo_ser::block_transactions::read_block_transactions(&mut r)
        .expect_err("hostile v2 count must reject");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("v2 count") && msg.contains("10000000"),
        "expected v2-count cap-violation message, got: {msg}"
    );
}

/// Mainnet genesis header bytes. Matches the fixture used in
/// `ergo-ser` codec tests so the ingress tests above wrap a real
/// header the inner parser will accept up to the point of the
/// hostile count field.
fn genesis_header_bytes() -> Vec<u8> {
    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";
    hex::decode(GENESIS_HEX).expect("hex decode")
}

/// Minimal valid `PoPowHeader` wire bytes: mainnet genesis header +
/// zero interlinks + zero-byte interlinks proof. Used as the
/// `suffix_head` in the suffix-cap ingress test above; the
/// `popow_header` parser must accept this before reaching the
/// outer suffix-cap gate.
fn build_minimal_popow_header_bytes() -> Vec<u8> {
    let mut w = VlqWriter::new();
    let genesis = genesis_header_bytes();
    w.put_u32(genesis.len() as u32);
    w.put_bytes(&genesis);
    w.put_u32(0); // links_qty = 0
    w.put_u32(0); // interlinks_proof_size = 0
    w.result()
}

#[test]
fn peers_roundtrip() {
    use crate::handshake::{DeclaredAddress, PeerFeature, PeerSpec, Version};
    let peers = vec![
        PeerSpec {
            agent_name: "ergo-rust/0.1".into(),
            version: Version::NIPOPOW,
            node_name: "node1".into(),
            declared_address: Some(DeclaredAddress {
                addr: vec![10, 0, 0, 1],
                port: 9030,
            }),
            features: vec![PeerFeature::Mode {
                state_type: 0,
                verify_tx: true,
                nipopow: None,
                blocks_to_keep: -1,
            }],
        },
        PeerSpec {
            agent_name: "ergo-scala/5.0.13".into(),
            version: Version::NIPOPOW,
            node_name: "node2".into(),
            declared_address: None,
            features: Vec::new(),
        },
    ];
    let bytes = serialize_peers(&peers);
    let parsed = deserialize_peers(&bytes, 100).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].agent_name, "ergo-rust/0.1");
    assert_eq!(parsed[0].declared_address.as_ref().unwrap().port, 9030);
    assert_eq!(parsed[1].agent_name, "ergo-scala/5.0.13");
    assert!(parsed[1].declared_address.is_none());
}

/// Unknown features carried inside a `PeerSpec` inside a `Peers`
/// message must round-trip verbatim. The handshake path already
/// preserves `feature_id` + `data` for unknown features (see
/// `handshake::tests::unknown_feature_preserved`); this test pins
/// the same property for the gossip path so a future peer-feature
/// id rolling out on the network rides through our `Peers`
/// re-broadcast without bit loss.
#[test]
fn peers_unknown_feature_roundtrip() {
    use crate::handshake::{PeerFeature, PeerSpec, Version};
    let peers = vec![PeerSpec {
        agent_name: "alien".into(),
        version: Version::NIPOPOW,
        node_name: "node-x".into(),
        declared_address: None,
        features: vec![PeerFeature::Unknown {
            feature_id: 123,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }],
    }];
    let bytes = serialize_peers(&peers);
    let parsed = deserialize_peers(&bytes, 10).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].features.len(), 1);
    match &parsed[0].features[0] {
        PeerFeature::Unknown { feature_id, data } => {
            assert_eq!(*feature_id, 123);
            assert_eq!(data, &vec![0xAA, 0xBB, 0xCC, 0xDD]);
        }
        other => panic!("expected Unknown feature, got {other:?}"),
    }
}

#[test]
fn peers_too_many_rejected() {
    use crate::handshake::{PeerSpec, Version};
    let peers = vec![
        PeerSpec {
            agent_name: "a".into(),
            version: Version::INITIAL,
            node_name: "n".into(),
            declared_address: None,
            features: Vec::new(),
        };
        5
    ];
    let bytes = serialize_peers(&peers);
    let result = deserialize_peers(&bytes, 3);
    assert!(result.is_err());
}

#[test]
fn sync_v1_allows_1001_rejects_1002() {
    // Scala allows MaxBlockIds + 1 = 1001, rejects 1002+.
    let mut w = VlqWriter::new();
    w.put_u16(1001u16);
    for _ in 0..1001 {
        w.put_bytes(&[0u8; 32]);
    }
    let result = deserialize_sync_info(&w.result());
    assert!(result.is_ok(), "1001 IDs should be accepted (Scala parity)");

    let mut w2 = VlqWriter::new();
    w2.put_u16(1002u16);
    for _ in 0..1002 {
        w2.put_bytes(&[0u8; 32]);
    }
    let result2 = deserialize_sync_info(&w2.result());
    assert!(result2.is_err(), "1002 IDs should be rejected");
}

#[test]
fn get_manifest_rejects_oversized() {
    let big = vec![0u8; 100];
    let result = deserialize_get_manifest(&big);
    assert!(result.is_err());
}

#[test]
fn get_utxo_chunk_rejects_oversized() {
    let big = vec![0u8; 100];
    let result = deserialize_get_utxo_chunk(&big);
    assert!(result.is_err());
}

#[test]
fn inv_exactly_max_objects_accepted() {
    let ids: Vec<[u8; 32]> = (0..MAX_INV_OBJECTS)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0] = (i & 0xFF) as u8;
            id[1] = ((i >> 8) & 0xFF) as u8;
            id
        })
        .collect();
    let data = InvData { type_id: 101, ids };
    let bytes = serialize_inv(&data).unwrap();
    let parsed = deserialize_inv(&bytes).unwrap();
    assert_eq!(parsed.ids.len(), MAX_INV_OBJECTS);
}

#[test]
fn inv_over_max_serialize_rejected() {
    let ids: Vec<[u8; 32]> = (0..=MAX_INV_OBJECTS).map(|_| [0u8; 32]).collect();
    let data = InvData { type_id: 101, ids };
    let err = serialize_inv(&data).unwrap_err();
    assert!(matches!(err, MessageError::TooManyInv(_)));
}

#[test]
fn deserialize_inv_over_max_crafted_bytes_rejected() {
    // Craft a raw payload: type_id=101, count=401, then 401×32 zero bytes.
    // 401 in little-endian VLQ (7-bit groups): 401 = 0b11_0010001 → [0x91, 0x03]
    let mut payload = vec![101u8]; // type_id
    payload.extend_from_slice(&[0x91, 0x03]); // count = 401 in VLQ
    payload.extend(std::iter::repeat_n(0u8, (MAX_INV_OBJECTS + 1) * 32));
    let err = deserialize_inv(&payload).unwrap_err();
    assert!(matches!(err, MessageError::TooManyInv(401)));
}

#[test]
fn modifiers_truncation_at_size_limit() {
    // Each large modifier is ~1 MB. Four of them exceed MAX_MODIFIER_WITH_RESERVE (8 MB).
    // serialize_modifiers should silently truncate to only the modifiers that fit.
    let one_mb = vec![0xABu8; 1_024_000];
    let data = ModifiersData {
        type_id: 101,
        modifiers: vec![
            ([0x01; 32], one_mb.clone()),
            ([0x02; 32], one_mb.clone()),
            ([0x03; 32], one_mb.clone()),
            ([0x04; 32], one_mb.clone()),
            ([0x05; 32], one_mb.clone()),
            ([0x06; 32], one_mb.clone()),
            ([0x07; 32], one_mb.clone()),
            ([0x08; 32], one_mb.clone()),
            ([0x09; 32], one_mb.clone()),
        ],
    };
    let bytes = serialize_modifiers(&data).unwrap();
    let parsed = deserialize_modifiers(&bytes).unwrap();
    // Must have fewer than 9 modifiers; each is ~1 MB + 36 byte overhead
    assert!(
        parsed.modifiers.len() < 9,
        "expected truncation, got {} modifiers",
        parsed.modifiers.len()
    );
    // Must have at least 1 modifier
    assert!(!parsed.modifiers.is_empty());
    // Must parse cleanly (no size error in deserialization)
    assert_eq!(parsed.type_id, 101);
}
