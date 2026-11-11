//! SessionId feature bodies across codec generations.
//!
//! The same 20 bodies used in the pre-fix evidence run
//! (`docs/evidence/old-vs-new-sid/`, commit `06b44bdd`) are fed to the
//! current codec:
//!
//! * 16 synthetic new-format bodies (4-byte network magic + 1..=10-byte
//!   zigzag-VLQ session id, incl. the testnet canary id);
//! * 3 bodies captured from live mainnet/testnet peers (new format);
//! * 1 body captured from our own pre-fix mainnet node (old format:
//!   4-byte magic + 8-byte big-endian id).
//!
//! Expected at the fixed codec (`85c1b052`): the handshake is never
//! rejected; every new-format body decodes to `SessionId` with the exact
//! id (the VLQ+zigzag read must consume the body exactly); the
//! old-format body is preserved verbatim as
//! `Unknown { feature_id: 3 }` (its VLQ read leaves trailing bytes).
//!
//! For contrast, the pre-fix parser accepted all 20 as well but silently
//! mis-decoded 7 of the 8 ≥12-byte bodies as `SessionId` (it read the
//! first 8 VLQ bytes as a fixed big-endian i64) and downgraded the
//! <12-byte ones to `Unknown` — see the evidence dir.

use ergo_p2p::handshake::{deserialize_handshake, PeerFeature};

/// Independent zigzag-VLQ encoder (mirrors scorex `putLong`).
fn zigzag_vlq(id: i64) -> Vec<u8> {
    let v = ((id as u64) << 1) ^ ((id >> 63) as u64);
    let mut out = Vec::new();
    let mut x = v;
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// Independent zigzag-VLQ decoder over the WHOLE slice (full-consumption
/// semantics, like the fixed codec requires).
fn zigzag_vlq_decode(bytes: &[u8]) -> Option<i64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            let u = if v & 1 == 0 { v >> 1 } else { !((v - 1) >> 1) };
            return (i + 1 == bytes.len()).then_some(u as i64);
        }
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Minimal handshake (time=0, agent "test", v6.0.7, node "nn", no declared
/// address, exactly one feature: fid 3 with the given body).
fn handshake_with_session_body(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0x00); // time = 0 (VLQ)
    v.extend_from_slice(&[0x04, b't', b'e', b's', b't']);
    v.extend_from_slice(&[0x06, 0x00, 0x07]);
    v.extend_from_slice(&[0x02, b'n', b'n']);
    v.push(0x00); // no declared address
    v.push(0x01); // one feature
    v.push(0x03); // FEATURE_SESSION_ID
    assert!(body.len() < 128, "test body must fit in one VLQ byte");
    v.push(body.len() as u8); // VLQ u16 body length (single byte)
    v.extend_from_slice(body);
    v
}

struct Case {
    label: String,
    magic: [u8; 4],
    body: Vec<u8>,
    /// Exact session id per the new codec (None for the old-format body).
    true_id: Option<i64>,
}

#[test]
fn fixed_codec_vs_cross_generation_bodies() {
    let mainnet_magic = [0x01, 0x00, 0x02, 0x04];
    let testnet_magic = [0x02, 0x03, 0x02, 0x03];

    // Synthetic new-format bodies: VLQ session id of 1..10 bytes.
    let synthetic: [(i64, usize); 16] = [
        (0, 1),
        (-1, 1),
        (63, 1),
        (64, 2),
        (8191, 2),
        (8192, 3),
        (1_048_575, 3),
        (1_048_576, 4),
        (2_097_151, 4),
        ((1i64 << 28) - 1, 5),
        ((1i64 << 35) - 1, 6),
        ((1i64 << 42) - 1, 7),
        ((1i64 << 49) - 1, 8),
        (1i64 << 49, 8),
        (i64::MAX, 10),
        (8_288_960_606_751_204_270, 10), // testnet canary id, 10-byte VLQ
    ];
    let mut cases: Vec<Case> = Vec::new();
    for (id, want_len) in synthetic {
        let vlq = zigzag_vlq(id);
        assert_eq!(vlq.len(), want_len, "unexpected VLQ length for {id}");
        let mut body = Vec::new();
        body.extend_from_slice(&testnet_magic);
        body.extend_from_slice(&vlq);
        cases.push(Case {
            label: format!("synthetic new-format id={id} (body {}B)", body.len()),
            magic: testnet_magic,
            body,
            true_id: Some(id),
        });
    }

    // Bodies captured live (2026-11-11 capture run; see captures.jsonl).
    // `true_id` is derived with the independent decoder above, not the
    // codec under test.
    let live_new: [(&[u8], [u8; 4]); 3] = [
        (
            // testnet canary (fixed rust node), 14-byte body
            b"\x02\x03\x02\x03\xdc\x8e\xe5\xa9\xa9\xf0\xa6\x88\xe6\x01",
            testnet_magic,
        ),
        (
            // ergoref 6.0.8 mainnet seed, 13-byte body
            b"\x01\x00\x02\x04\x9b\x8a\xe8\xfe\xa6\xdc\xf3\xdc\x4e",
            mainnet_magic,
        ),
        (
            // ergoref mainnet seed, 14-byte body
            b"\x01\x00\x02\x04\xbc\xea\x82\x8e\xb2\xf1\xf9\xcc\x9d\x01",
            mainnet_magic,
        ),
    ];
    for (body, magic) in live_new {
        let true_id = zigzag_vlq_decode(&body[4..])
            .unwrap_or_else(|| panic!("live body must full-consume: {body:x?}"));
        cases.push(Case {
            label: format!("live new-format {:x?}", &body[4..]),
            magic,
            body: body.to_vec(),
            true_id: Some(true_id),
        });
    }

    // Our own pre-fix mainnet node: old format, 4-byte magic + 8-byte
    // big-endian id. The fixed codec must preserve it verbatim as Unknown.
    let old_format: &[u8] = b"\x01\x00\x02\x04\x13\x2f\x6d\xd4\x1e\x97\x07\xc5";
    cases.push(Case {
        label: format!("old-format (pre-fix rust, 12-byte BE) {:x?}", old_format),
        magic: mainnet_magic,
        body: old_format.to_vec(),
        true_id: None,
    });

    let mut strict = 0usize;
    let mut unknown = 0usize;
    for c in &cases {
        let payload = handshake_with_session_body(&c.body);
        let hs = deserialize_handshake(&payload).unwrap_or_else(|e| panic!("{}: {e}", c.label));
        let feat = hs.peer_spec.features.first().expect("exactly one feature");
        match feat {
            PeerFeature::SessionId { magic, session_id } => {
                let expected = c.true_id.expect("Unknown expected for this body");
                assert_eq!(*magic, c.magic, "{}: magic", c.label);
                assert_eq!(*session_id, expected, "{}: id", c.label);
                strict += 1;
            }
            PeerFeature::Unknown { feature_id, data } => {
                assert_eq!(
                    c.true_id, None,
                    "{}: new-format body must decode as SessionId",
                    c.label
                );
                assert_eq!(*feature_id, 3, "{}: feature id", c.label);
                assert_eq!(
                    data, &c.body,
                    "{}: old-format body must be preserved verbatim",
                    c.label
                );
                unknown += 1;
            }
            other => panic!("{}: unexpected variant {other:?}", c.label),
        }
    }
    assert_eq!(strict, 19, "19 new-format bodies must decode exactly");
    assert_eq!(unknown, 1, "only the old-format body may be preserved");
}
