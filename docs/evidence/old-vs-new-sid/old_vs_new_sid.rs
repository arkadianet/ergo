//! Pre-85c1b052 codec: feed it NEW-format SessionId feature bodies
//! (4-byte network magic + VLQ+zigzag session id, as written by the fixed
//! codec and observed from live peers) and report whether the old parser
//! accepts or rejects each handshake.
//!
//! Wire format mirrored from `serialize_handshake`/`serialize_peer_spec_to`
//! at this commit:
//!   time: VLQ u64
//!   agent: u8 len + utf8
//!   version: 3 raw bytes
//!   node: u8 len + utf8
//!   declared: u8 option (0 | 1 + u8 total_len + addr + VLQ u32 port)
//!   features: u8 count + [ u8 fid + VLQ u16 body_len + body ]

use ergo_p2p::handshake::{deserialize_handshake, PeerFeature};

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

fn zigzag_vlq_decode(bytes: &[u8]) -> Option<i64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            let u = if v & 1 == 0 { v >> 1 } else { !((v - 1) >> 1) };
            return Some(u as i64).filter(|_| i + 1 == bytes.len());
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
    body: Vec<u8>,
    /// True session id per the new codec, when the body is new-format.
    true_id: Option<i64>,
}

#[test]
fn old_parser_vs_new_format_bodies() {
    let magic = [0x02, 0x03, 0x02, 0x03];
    let mut cases: Vec<Case> = Vec::new();
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
        (1i64 << 49, 9),
        (i64::MAX, 10),
        (8_288_960_606_751_204_270, 10), // testnet canary id, 10-byte VLQ
    ];
    for (id, _want_len) in synthetic {
        let vlq = zigzag_vlq(id);
        let mut body = Vec::new();
        body.extend_from_slice(&magic);
        body.extend_from_slice(&vlq);
        cases.push(Case {
            label: format!("synthetic id={id} (vlq={}B, body={}B)", vlq.len(), body.len()),
            body,
            true_id: Some(id),
        });
    }
    // Real bodies captured from live mainnet peers (new format) and from our
    // pre-fix node (old format: magic + 8-byte big-endian).
    let real: [(&str, &[u8]); 4] = [
        ("live: testnet canary (new rust, 14B body)",
         b"\x02\x03\x02\x03\xdc\x8e\xe5\xa9\xa9\xf0\xa6\x88\xe6\x01"),
        ("live: ergoref 6.0.8 seed (13B body)",
         b"\x01\x00\x02\x04\x9b\x8a\xe8\xfe\xa6\xdc\xf3\xdc\x4e"),
        ("live: ergoref seed toronto (14B body)",
         b"\x01\x00\x02\x04\xbc\xea\x82\x8e\xb2\xf1\xf9\xcc\x9d\x01"),
        ("live: our pre-fix mainnet node (old 12B body)",
         b"\x01\x00\x02\x04\x13\x2f\x6d\xd4\x1e\x97\x07\xc5"),
    ];
    for (label, body) in real {
        cases.push(Case {
            label: label.to_string(),
            body: body.to_vec(),
            true_id: if body.len() > 12 {
                zigzag_vlq_decode(&body[4..])
            } else {
                Some(i64::from_be_bytes(body[4..12].try_into().unwrap()))
            },
        });
    }

    let mut accepted_sessionid = 0usize;
    let mut accepted_unknown = 0usize;
    let mut rejected = 0usize;
    let mut misdecoded = 0usize;

    println!(
        "{:<52} {:<10} {:<34} {}",
        "case", "old-parser", "feature outcome", "note"
    );
    for c in &cases {
        let payload = handshake_with_session_body(&c.body);
        let res = deserialize_handshake(&payload);
        match res {
            Ok(hs) => {
                let feat = hs.peer_spec.features.first().unwrap();
                match feat {
                    PeerFeature::SessionId { magic, session_id } => {
                        accepted_sessionid += 1;
                        let note = match c.true_id {
                            Some(t) if t == *session_id => String::from("correct value"),
                            Some(t) => {
                                misdecoded += 1;
                                format!("SILENT MISDECODE (true {t})")
                            }
                            None => String::from("value not cross-checked"),
                        };
                        println!(
                            "{:<52} {:<10} {:<34} {}",
                            c.label,
                            "ACCEPT",
                            format!("SessionId magic={magic:?} id={session_id}"),
                            note
                        );
                    }
                    PeerFeature::Unknown { feature_id, data } => {
                        accepted_unknown += 1;
                        println!(
                            "{:<52} {:<10} {:<34} {}",
                            c.label,
                            "ACCEPT",
                            format!("Unknown fid={feature_id} ({}B preserved)", data.len()),
                            "feature dropped, handshake kept"
                        );
                    }
                    other => {
                        println!(
                            "{:<52} {:<10} {:<34} {}",
                            c.label, "ACCEPT", format!("{other:?}"), "unexpected variant"
                        );
                    }
                }
            }
            Err(e) => {
                rejected += 1;
                println!(
                    "{:<52} {:<10} {:<34} {}",
                    c.label, "REJECT", "-", e
                );
            }
        }
    }

    println!();
    println!("SUMMARY: total={} accepted_as_SessionId={} accepted_as_Unknown={} rejected={}",
        cases.len(), accepted_sessionid, accepted_unknown, rejected);
    println!("        of the SessionId accepts, {} silently carried a wrong id", misdecoded);
    assert_eq!(rejected, 0, "expected the old parser to never reject these bodies");
}
