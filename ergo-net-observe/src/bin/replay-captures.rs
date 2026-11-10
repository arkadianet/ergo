//! Replays captured raw peer handshakes through the current codec.
//!
//! Input: an `ergo-observer/1` JSONL stream from a capture run
//! (`--capture-handshake-hex`). For every `handshake_ok` record (field
//! `peer_handshake_hex`) and `handshake_fail` record (field
//! `received_hex`) the raw bytes are re-parsed with the current
//! `deserialize_handshake_with_consumed`. Output: one JSON line per
//! captured record on stdout, and a summary on stderr.
//!
//! The summary separates the evidence needed for the SessionId fix
//! report (`85c1b052`):
//!   * how often the `SessionId` feature (id 3) body parses strictly
//!     (VLQ+zigzag with exact field bounds and full consumption) versus
//!     falling through to the verbatim `Unknown` preservation path;
//!   * which rejection classes the current codec applies;
//!   * which rejections the pre-fix codec would *not* have made. Of the
//!     five item-4 codec fixes, only `MalformedDeclaredAddress` changed
//!     accept/reject behaviour (the old code saturated a declared-address
//!     length hint below 4 to an empty address); the other rejections
//!     (oversize, truncation, empty agent, negative feature count,
//!     out-of-range port) existed identically in the old codec.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use ergo_p2p::handshake::{deserialize_handshake_with_consumed, HandshakeError, PeerFeature};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(arg) = args.get(1) else {
        eprintln!("usage: replay-captures <captures.jsonl | ->");
        std::process::exit(2);
    };
    let is_stdin = arg == "-";
    let input = PathBuf::from(arg);
    let reader: Box<dyn BufRead> = if is_stdin {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        match File::open(&input) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(e) => {
                eprintln!("cannot open {}: {e}", input.display());
                std::process::exit(1);
            }
        }
    };

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    let mut lines = 0usize;
    let mut captured = 0usize;
    let mut ok_count = 0usize;
    let mut rejected_count = 0usize;
    let mut new_only_rejects = 0usize;
    let mut sid_strict = 0usize;
    let mut sid_unknown = 0usize;
    let mut rejections: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut unknown_ids: std::collections::BTreeMap<u8, usize> = std::collections::BTreeMap::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("read error: {e}");
                std::process::exit(1);
            }
        };
        lines += 1;
        if line.trim().is_empty() {
            continue;
        }
        let rec: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(event) = rec.get("event").and_then(|v| v.as_str()) else {
            continue;
        };
        if event != "handshake_ok" && event != "handshake_fail" {
            continue;
        }

        let hex_field = if event == "handshake_ok" {
            "peer_handshake_hex"
        } else {
            "received_hex"
        };
        let Some(hex_str) = rec.get(hex_field).and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(bytes) = hex::decode(hex_str) else {
            eprintln!("line {lines}: bad hex in {hex_field}");
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        captured += 1;

        let peer_id = rec
            .pointer("/peer/id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let agent = rec
            .get("agent")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        match deserialize_handshake_with_consumed(&bytes) {
            Ok((hs, consumed)) => {
                ok_count += 1;
                let mut features = Vec::new();
                let mut session_id = "absent".to_string();
                for f in &hs.peer_spec.features {
                    let (id, status) = match f {
                        PeerFeature::LocalAddress { .. } => (2u8, "strict"),
                        PeerFeature::SessionId { .. } => (3u8, "strict"),
                        PeerFeature::RestApiUrl { .. } => (4u8, "strict"),
                        PeerFeature::Mode { .. } => (16u8, "strict"),
                        PeerFeature::Unknown { feature_id, .. } => {
                            unknown_ids.entry(*feature_id).or_insert(0);
                            *unknown_ids.get_mut(feature_id).unwrap() += 1;
                            (*feature_id, "unknown")
                        }
                    };
                    if id == 3 && status == "strict" && session_id == "absent" {
                        sid_strict += 1;
                        session_id = "strict".to_string();
                    } else if id == 3 && status == "unknown" && session_id == "absent" {
                        sid_unknown += 1;
                        session_id = "unknown".to_string();
                    }
                    features.push(serde_json::json!({ "id": id, "status": status }));
                }
                let _ = serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({
                        "line": lines,
                        "event": event,
                        "peer": peer_id,
                        "agent": agent,
                        "bytes": bytes.len(),
                        "consumed": consumed,
                        "parse": "ok",
                        "features": features,
                        "session_id": session_id,
                    }),
                );
                let _ = writeln!(out);
            }
            Err(e) => {
                rejected_count += 1;
                let reason = e.to_string();
                let old_codec_would_accept =
                    matches!(e, HandshakeError::MalformedDeclaredAddress(_));
                if old_codec_would_accept {
                    new_only_rejects += 1;
                }
                *rejections.entry(reason.clone()).or_insert(0) += 1;
                let _ = serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({
                        "line": lines,
                        "event": event,
                        "peer": peer_id,
                        "agent": agent,
                        "bytes": bytes.len(),
                        "parse": "rejected",
                        "reason": reason,
                        "old_codec_would_accept": old_codec_would_accept,
                    }),
                );
                let _ = writeln!(out);
            }
        }
    }

    let sid_absent = ok_count - sid_strict - sid_unknown;
    let present = sid_strict + sid_unknown;
    let pct = |a: usize, b: usize| -> String {
        if b == 0 {
            "-".to_string()
        } else {
            format!("{:.1}%", 100.0 * a as f64 / b as f64)
        }
    };
    let pct_nopercent = |a: usize, b: usize| -> String {
        if b == 0 {
            "-".to_string()
        } else {
            format!("{:.1}", 100.0 * a as f64 / b as f64)
        }
    };
    eprintln!(
        "replay: {lines} lines, {captured} captured byte sequences (ok {ok_count}, rejected {rejected_count})"
    );
    eprintln!(
        "  parse ok: {ok_count} ({}%), rejected: {rejected_count} ({}%)",
        pct_nopercent(ok_count, captured),
        pct_nopercent(rejected_count, captured)
    );
    if !rejections.is_empty() {
        for (reason, n) in &rejections {
            eprintln!("  rejection: {reason} — {n}");
        }
    }
    eprintln!("  new-only rejections (pre-fix codec would have accepted): {new_only_rejects}");
    eprintln!(
        "  SessionId: strict {sid_strict}, unknown {sid_unknown}, absent {sid_absent}; strict of presenting: {} (n={present})",
        pct(sid_strict, present)
    );
    if !unknown_ids.is_empty() {
        let ids: Vec<String> = unknown_ids
            .iter()
            .map(|(id, n)| format!("id {id}: {n}"))
            .collect();
        eprintln!("  unknown feature ids: {}", ids.join(", "));
    }
    let _ = out.flush();
}
