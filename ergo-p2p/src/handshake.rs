//! Handshake (code 75), PeerSpec, Version, and peer feature serialization.
//!
//! Verified against: HandshakeSerializer.scala, PeerSpec.scala, Version.scala,
//! PeerFeatureDescriptors.scala, SessionIdPeerFeature.scala,
//! LocalAddressPeerFeature.scala, RestApiUrlPeerFeature.scala,
//! ModePeerFeature.scala.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use thiserror::Error;

// ---- Version ----

/// Protocol version: 3 raw bytes [major, minor, patch].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl Version {
    pub const INITIAL: Self = Self {
        major: 0,
        minor: 0,
        patch: 1,
    };
    pub const EIP37_FORK: Self = Self {
        major: 4,
        minor: 0,
        patch: 100,
    };
    pub const JIT_SOFT_FORK: Self = Self {
        major: 5,
        minor: 0,
        patch: 0,
    };
    pub const UTXO_SNAPSHOT: Self = Self {
        major: 5,
        minor: 0,
        patch: 12,
    };
    pub const NIPOPOW: Self = Self {
        major: 5,
        minor: 0,
        patch: 13,
    };
    /// Reference-node default `scorex.network.appVersion`.
    ///
    /// Scala keeps named constants here for activation milestones, then wires
    /// the advertised handshake version from config. Until we expose the same
    /// config knob, this is the version our node announces.
    pub const CURRENT: Self = Self {
        major: 6,
        minor: 0,
        patch: 2,
    };
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---- Peer features ----

pub const FEATURE_LOCAL_ADDRESS: u8 = 2;
pub const FEATURE_SESSION_ID: u8 = 3;
pub const FEATURE_REST_API_URL: u8 = 4;
pub const FEATURE_MODE: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerFeature {
    LocalAddress {
        addr: [u8; 4],
        port: u32,
    },
    SessionId {
        magic: [u8; 4],
        session_id: i64,
    },
    RestApiUrl {
        url: String,
    },
    Mode {
        state_type: u8, // 0=UTXO, 1=Digest
        verify_tx: bool,
        nipopow: Option<i32>, // Some(1) = KMZ17 bootstrapped
        blocks_to_keep: i32,  // -1=all, -2=UTXO-bootstrapped, >0=suffix
    },
    Unknown {
        feature_id: u8,
        data: Vec<u8>,
    },
}

fn serialize_feature_body(feature: &PeerFeature) -> (u8, Vec<u8>) {
    match feature {
        PeerFeature::LocalAddress { addr, port } => {
            let mut w = VlqWriter::new();
            w.put_bytes(addr);
            w.put_u32(*port);
            (FEATURE_LOCAL_ADDRESS, w.result())
        }
        PeerFeature::SessionId { magic, session_id } => {
            let mut buf = Vec::with_capacity(12);
            buf.extend_from_slice(magic);
            buf.extend_from_slice(&session_id.to_be_bytes());
            (FEATURE_SESSION_ID, buf)
        }
        PeerFeature::RestApiUrl { url } => {
            let url_bytes = url.as_bytes();
            let mut w = VlqWriter::new();
            w.put_u8(url_bytes.len() as u8);
            w.put_bytes(url_bytes);
            (FEATURE_REST_API_URL, w.result())
        }
        PeerFeature::Mode {
            state_type,
            verify_tx,
            nipopow,
            blocks_to_keep,
        } => {
            let mut w = VlqWriter::new();
            w.put_u8(*state_type);
            w.put_u8(if *verify_tx { 1 } else { 0 });
            // putOption: byte(0|1) + value if present
            match nipopow {
                Some(val) => {
                    w.put_u8(1);
                    w.put_i32(*val);
                }
                None => {
                    w.put_u8(0);
                }
            }
            w.put_i32(*blocks_to_keep);
            (FEATURE_MODE, w.result())
        }
        PeerFeature::Unknown { feature_id, data } => (*feature_id, data.clone()),
    }
}

/// Check that a string has a URL scheme (e.g. "http://", "https://", "ftp://").
/// Matches java.net.URL which requires scheme://... syntax.
fn has_url_scheme(s: &str) -> bool {
    match s.find("://") {
        Some(pos) if pos > 0 => s[..pos]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.'),
        _ => false,
    }
}

fn deserialize_feature(feature_id: u8, data: &[u8]) -> PeerFeature {
    match feature_id {
        FEATURE_LOCAL_ADDRESS => {
            if data.len() < 5 {
                return PeerFeature::Unknown {
                    feature_id,
                    data: data.to_vec(),
                };
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&data[..4]);
            let mut r = VlqReader::new(&data[4..]);
            // Malformed port VLQ keeps the existing coercion to 0 (Scala
            // parity) but is no longer silent.
            let port = match r.get_u32_exact() {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = ?e, feature = "LocalAddress.port", "handshake: malformed feature field; coercing to 0");
                    0
                }
            };
            PeerFeature::LocalAddress { addr, port }
        }
        FEATURE_SESSION_ID => {
            if data.len() < 12 {
                return PeerFeature::Unknown {
                    feature_id,
                    data: data.to_vec(),
                };
            }
            let mut magic = [0u8; 4];
            magic.copy_from_slice(&data[..4]);
            let session_id = i64::from_be_bytes(data[4..12].try_into().unwrap());
            PeerFeature::SessionId { magic, session_id }
        }
        FEATURE_REST_API_URL => {
            if data.is_empty() {
                return PeerFeature::Unknown {
                    feature_id,
                    data: data.to_vec(),
                };
            }
            let url_len = data[0] as usize;
            if data.len() < 1 + url_len {
                return PeerFeature::Unknown {
                    feature_id,
                    data: data.to_vec(),
                };
            }
            let url_bytes = &data[1..1 + url_len];
            // Validate UTF-8 strictly, then check URL syntax.
            // Scala parses via new java.net.URL(...) which requires a valid
            // scheme://... structure. We approximate by requiring "scheme://"
            // where scheme is at least one ASCII letter.
            let url_str = match std::str::from_utf8(url_bytes) {
                Ok(s) if !s.is_empty() => s,
                _ => {
                    return PeerFeature::Unknown {
                        feature_id,
                        data: data.to_vec(),
                    }
                }
            };
            if !has_url_scheme(url_str) {
                return PeerFeature::Unknown {
                    feature_id,
                    data: data.to_vec(),
                };
            }
            PeerFeature::RestApiUrl {
                url: url_str.to_string(),
            }
        }
        FEATURE_MODE => {
            let mut r = VlqReader::new(data);
            // Truncated/malformed Mode fields keep their existing default
            // coercions (Scala parity) but are no longer silently swallowed.
            let state_type = match r.get_u8() {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(error = ?e, feature = "Mode.state_type", "handshake: malformed feature field; coercing to 0");
                    0
                }
            };
            let verify_tx = match r.get_u8() {
                Ok(b) => b > 0,
                Err(e) => {
                    tracing::debug!(error = ?e, feature = "Mode.verify_tx", "handshake: malformed feature field; coercing to false");
                    false
                }
            };
            // Read option: byte(0|1) + value
            let nipopow = match r.get_u8() {
                Ok(1) => r.get_i32().ok(),
                _ => None,
            };
            let blocks_to_keep = match r.get_i32() {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = ?e, feature = "Mode.blocks_to_keep", "handshake: malformed feature field; coercing to archive default (-1)");
                    -1
                }
            };
            PeerFeature::Mode {
                state_type,
                verify_tx,
                nipopow,
                blocks_to_keep,
            }
        }
        _ => PeerFeature::Unknown {
            feature_id,
            data: data.to_vec(),
        },
    }
}

// ---- PeerSpec ----

#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub agent_name: String,
    pub version: Version,
    pub node_name: String,
    pub declared_address: Option<DeclaredAddress>,
    pub features: Vec<PeerFeature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredAddress {
    pub addr: Vec<u8>, // 4 bytes IPv4 or 16 bytes IPv6
    pub port: u32,
}

/// Serialize a PeerSpec into the given writer (used by both Handshake and Peers).
pub fn serialize_peer_spec_to(spec: &PeerSpec, w: &mut VlqWriter) {
    // shortString: byte(len) + UTF-8
    let agent_bytes = spec.agent_name.as_bytes();
    w.put_u8(agent_bytes.len() as u8);
    w.put_bytes(agent_bytes);

    // Version: 3 raw bytes
    w.put_u8(spec.version.major);
    w.put_u8(spec.version.minor);
    w.put_u8(spec.version.patch);

    // shortString: node_name
    let name_bytes = spec.node_name.as_bytes();
    w.put_u8(name_bytes.len() as u8);
    w.put_bytes(name_bytes);

    // option(declaredAddress)
    match &spec.declared_address {
        Some(addr) => {
            w.put_u8(1); // option present
            w.put_u8((addr.addr.len() + 4) as u8); // length hint
            w.put_bytes(&addr.addr);
            w.put_u32(addr.port);
        }
        None => {
            w.put_u8(0); // option absent
        }
    }

    // Features: byte(count) + Feature[]
    w.put_u8(spec.features.len() as u8);
    for feature in &spec.features {
        let (id, body) = serialize_feature_body(feature);
        w.put_u8(id);
        w.put_u16(body.len() as u16); // VLQ UShort
        w.put_bytes(&body);
    }
}

/// Deserialize a PeerSpec from the given reader (used by both Handshake and Peers).
pub fn deserialize_peer_spec_from(r: &mut VlqReader) -> Result<PeerSpec, HandshakeError> {
    // shortString: agent_name
    let agent_len = r.get_u8()? as usize;
    let agent_bytes = r.get_bytes(agent_len)?;
    let agent_name = String::from_utf8_lossy(agent_bytes).to_string();
    if agent_name.is_empty() {
        return Err(HandshakeError::EmptyAgentName);
    }

    // Version
    let major = r.get_u8()?;
    let minor = r.get_u8()?;
    let patch = r.get_u8()?;
    let version = Version {
        major,
        minor,
        patch,
    };

    // shortString: node_name
    let name_len = r.get_u8()? as usize;
    let name_bytes = r.get_bytes(name_len)?;
    let node_name = String::from_utf8_lossy(name_bytes).to_string();

    // option(declaredAddress)
    let addr_present = r.get_u8()?;
    let declared_address = if addr_present == 1 {
        let total_len = r.get_u8()? as usize;
        let addr_len = total_len.saturating_sub(4);
        let addr = r.get_bytes(addr_len)?.to_vec();
        let port = r.get_u32_exact()?;
        Some(DeclaredAddress { addr, port })
    } else {
        None
    };

    // Features
    let feature_count = r.get_u8()? as i8;
    if feature_count < 0 {
        return Err(HandshakeError::NegativeFeatureCount(feature_count));
    }
    let mut features = Vec::new();
    for _ in 0..feature_count {
        let feat_id = r.get_u8()?;
        let feat_len = r.get_u16()? as usize;
        let feat_bytes = r.get_bytes(feat_len)?;
        features.push(deserialize_feature(feat_id, feat_bytes));
    }

    Ok(PeerSpec {
        agent_name,
        version,
        node_name,
        declared_address,
        features,
    })
}

// ---- Handshake ----

pub const MAX_HANDSHAKE_SIZE: usize = 8096;

#[derive(Debug, Clone)]
pub struct Handshake {
    pub time: u64,
    pub peer_spec: PeerSpec,
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("handshake too large: {0} bytes (max {MAX_HANDSHAKE_SIZE})")]
    TooLarge(usize),
    #[error("empty agent name")]
    EmptyAgentName,
    #[error("read error: {0}")]
    Read(#[from] ReadError),
    #[error("negative feature count: {0}")]
    NegativeFeatureCount(i8),
}

pub fn serialize_handshake(hs: &Handshake) -> Vec<u8> {
    let mut w = VlqWriter::new();
    w.put_u64(hs.time);
    serialize_peer_spec_to(&hs.peer_spec, &mut w);
    w.result()
}

pub fn deserialize_handshake(payload: &[u8]) -> Result<Handshake, HandshakeError> {
    let (hs, _) = deserialize_handshake_with_consumed(payload)?;
    Ok(hs)
}

/// Deserialize a handshake and return how many bytes were consumed.
/// Used when the buffer may contain both the handshake and subsequent
/// framed messages (common after raw TCP read).
pub fn deserialize_handshake_with_consumed(
    payload: &[u8],
) -> Result<(Handshake, usize), HandshakeError> {
    if payload.len() > MAX_HANDSHAKE_SIZE {
        return Err(HandshakeError::TooLarge(payload.len()));
    }
    let mut r = VlqReader::new(payload);
    let time = r.get_u64()?;
    let peer_spec = deserialize_peer_spec_from(&mut r)?;
    let consumed = r.position();
    Ok((Handshake { time, peer_spec }, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_handshake() -> Handshake {
        Handshake {
            time: 1700000000000,
            peer_spec: PeerSpec {
                agent_name: "ergo-rust/0.1.0".into(),
                version: Version {
                    major: 5,
                    minor: 0,
                    patch: 13,
                },
                node_name: "test-node".into(),
                declared_address: Some(DeclaredAddress {
                    addr: vec![127, 0, 0, 1],
                    port: 9030,
                }),
                features: vec![
                    PeerFeature::SessionId {
                        magic: [1, 0, 2, 4],
                        session_id: 42,
                    },
                    PeerFeature::Mode {
                        state_type: 0,
                        verify_tx: true,
                        nipopow: None,
                        blocks_to_keep: -1,
                    },
                ],
            },
        }
    }

    #[test]
    fn handshake_roundtrip() {
        let hs = make_test_handshake();
        let bytes = serialize_handshake(&hs);
        let parsed = deserialize_handshake(&bytes).unwrap();

        assert_eq!(parsed.time, hs.time);
        assert_eq!(parsed.peer_spec.agent_name, "ergo-rust/0.1.0");
        assert_eq!(
            parsed.peer_spec.version,
            Version {
                major: 5,
                minor: 0,
                patch: 13
            }
        );
        assert_eq!(parsed.peer_spec.node_name, "test-node");
        assert!(parsed.peer_spec.declared_address.is_some());
        let addr = parsed.peer_spec.declared_address.unwrap();
        assert_eq!(addr.addr, vec![127, 0, 0, 1]);
        assert_eq!(addr.port, 9030);
        assert_eq!(parsed.peer_spec.features.len(), 2);
    }

    #[test]
    fn handshake_without_address() {
        let hs = Handshake {
            time: 12345,
            peer_spec: PeerSpec {
                agent_name: "test".into(),
                version: Version::EIP37_FORK,
                node_name: "n".into(),
                declared_address: None,
                features: Vec::new(),
            },
        };
        let bytes = serialize_handshake(&hs);
        let parsed = deserialize_handshake(&bytes).unwrap();
        assert!(parsed.peer_spec.declared_address.is_none());
        assert!(parsed.peer_spec.features.is_empty());
    }

    #[test]
    fn all_features_roundtrip() {
        let features = vec![
            PeerFeature::LocalAddress {
                addr: [192, 168, 1, 1],
                port: 9030,
            },
            PeerFeature::SessionId {
                magic: [1, 0, 2, 4],
                session_id: -12345678,
            },
            PeerFeature::RestApiUrl {
                url: "http://localhost:9053".into(),
            },
            PeerFeature::Mode {
                state_type: 0,
                verify_tx: true,
                nipopow: Some(1),
                blocks_to_keep: -1,
            },
        ];
        let hs = Handshake {
            time: 999,
            peer_spec: PeerSpec {
                agent_name: "a".into(),
                version: Version::NIPOPOW,
                node_name: "b".into(),
                declared_address: None,
                features,
            },
        };
        let bytes = serialize_handshake(&hs);
        let parsed = deserialize_handshake(&bytes).unwrap();
        assert_eq!(parsed.peer_spec.features.len(), 4);

        match &parsed.peer_spec.features[0] {
            PeerFeature::LocalAddress { addr, port } => {
                assert_eq!(*addr, [192, 168, 1, 1]);
                assert_eq!(*port, 9030);
            }
            _ => panic!("expected LocalAddress"),
        }
        match &parsed.peer_spec.features[1] {
            PeerFeature::SessionId { magic, session_id } => {
                assert_eq!(*magic, [1, 0, 2, 4]);
                assert_eq!(*session_id, -12345678);
            }
            _ => panic!("expected SessionId"),
        }
        match &parsed.peer_spec.features[2] {
            PeerFeature::RestApiUrl { url } => {
                assert_eq!(url, "http://localhost:9053");
            }
            _ => panic!("expected RestApiUrl"),
        }
        match &parsed.peer_spec.features[3] {
            PeerFeature::Mode {
                state_type,
                verify_tx,
                nipopow,
                blocks_to_keep,
            } => {
                assert_eq!(*state_type, 0);
                assert!(*verify_tx);
                assert_eq!(*nipopow, Some(1));
                assert_eq!(*blocks_to_keep, -1);
            }
            _ => panic!("expected Mode"),
        }
    }

    /// Roundtrip the `Mode` feature in configurations this node does not
    /// yet advertise but the wire format already supports: Digest backend
    /// (state_type=1), headers-only (verify_tx=false). Pins the VLQ codec
    /// so those modes land on a proven serializer once this node starts
    /// advertising them.
    #[test]
    fn mode_feature_state_type_and_verify_tx_roundtrip() {
        let combos = &[
            // (state_type, verify_tx, blocks_to_keep)
            (0u8, true, -1i32), // Mode 1 — archive (today)
            (0, true, 1024),    // Mode 3 — pruned
            (0, true, -2),      // Mode 2 — post-snapshot
            (1, true, -1),      // Mode 5 — digest verifier
            (1, false, 0),      // Mode 6 — headers-only
        ];
        for &(st, vt, btk) in combos {
            let features = vec![PeerFeature::Mode {
                state_type: st,
                verify_tx: vt,
                nipopow: None,
                blocks_to_keep: btk,
            }];
            let hs = Handshake {
                time: 7,
                peer_spec: PeerSpec {
                    agent_name: "a".into(),
                    version: Version::NIPOPOW,
                    node_name: "b".into(),
                    declared_address: None,
                    features,
                },
            };
            let bytes = serialize_handshake(&hs);
            let parsed = deserialize_handshake(&bytes)
                .unwrap_or_else(|e| panic!("deserialize failed for ({st}, {vt}, {btk}): {e:?}"));
            match &parsed.peer_spec.features[0] {
                PeerFeature::Mode {
                    state_type,
                    verify_tx,
                    blocks_to_keep,
                    ..
                } => {
                    assert_eq!(*state_type, st, "state_type drift ({st}, {vt}, {btk})");
                    assert_eq!(*verify_tx, vt, "verify_tx drift ({st}, {vt}, {btk})");
                    assert_eq!(
                        *blocks_to_keep, btk,
                        "blocks_to_keep drift ({st}, {vt}, {btk})",
                    );
                }
                _ => panic!("expected Mode feature for ({st}, {vt}, {btk})"),
            }
        }
    }

    /// Roundtrip the `Mode.blocks_to_keep` field at the wire-defined
    /// boundary values: -1 (full archive — already pinned in
    /// `all_features_roundtrip`), -2 (UTXO-bootstrap completed
    /// sentinel), 0 (extreme prune — keep zero suffix), and a
    /// positive N (typical Mode 3 retention). Failure here means the
    /// VLQ codec is dropping or corrupting i32 mode values that other,
    /// not-yet-advertised modes will need once this node emits them.
    #[test]
    fn mode_feature_blocks_to_keep_roundtrip_boundary_values() {
        for &v in &[-1i32, -2, 0, 1024, i32::MAX] {
            let features = vec![PeerFeature::Mode {
                state_type: 0,
                verify_tx: true,
                nipopow: None,
                blocks_to_keep: v,
            }];
            let hs = Handshake {
                time: 42,
                peer_spec: PeerSpec {
                    agent_name: "a".into(),
                    version: Version::NIPOPOW,
                    node_name: "b".into(),
                    declared_address: None,
                    features,
                },
            };
            let bytes = serialize_handshake(&hs);
            let parsed = deserialize_handshake(&bytes)
                .unwrap_or_else(|e| panic!("deserialize failed for blocks_to_keep = {v}: {e:?}"));
            match &parsed.peer_spec.features[0] {
                PeerFeature::Mode { blocks_to_keep, .. } => {
                    assert_eq!(*blocks_to_keep, v, "roundtrip mismatch at v = {v}");
                }
                _ => panic!("expected Mode for v = {v}"),
            }
        }
    }

    #[test]
    fn unknown_feature_preserved() {
        let features = vec![PeerFeature::Unknown {
            feature_id: 99,
            data: vec![1, 2, 3],
        }];
        let hs = Handshake {
            time: 1,
            peer_spec: PeerSpec {
                agent_name: "x".into(),
                version: Version::INITIAL,
                node_name: "y".into(),
                declared_address: None,
                features,
            },
        };
        let bytes = serialize_handshake(&hs);
        let parsed = deserialize_handshake(&bytes).unwrap();
        match &parsed.peer_spec.features[0] {
            PeerFeature::Unknown { feature_id, data } => {
                assert_eq!(*feature_id, 99);
                assert_eq!(*data, vec![1, 2, 3]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn version_ordering() {
        assert!(Version::INITIAL < Version::EIP37_FORK);
        assert!(Version::EIP37_FORK < Version::JIT_SOFT_FORK);
        assert!(Version::JIT_SOFT_FORK < Version::NIPOPOW);
        assert!(Version::NIPOPOW < Version::CURRENT);
    }

    #[test]
    fn rest_api_url_requires_valid_url_syntax() {
        let id = FEATURE_REST_API_URL;

        // http:// accepted
        let (_, body) = serialize_feature_body(&PeerFeature::RestApiUrl {
            url: "http://localhost:9053".into(),
        });
        assert!(matches!(
            deserialize_feature(id, &body),
            PeerFeature::RestApiUrl { .. }
        ));

        // https:// accepted
        let url = b"https://node.example.com:9053";
        let mut body = vec![url.len() as u8];
        body.extend_from_slice(url);
        assert!(matches!(
            deserialize_feature(id, &body),
            PeerFeature::RestApiUrl { .. }
        ));

        // ftp:// accepted (Scala parity — new URL accepts any scheme)
        let url = b"ftp://files.example.com";
        let mut body = vec![url.len() as u8];
        body.extend_from_slice(url);
        assert!(matches!(
            deserialize_feature(id, &body),
            PeerFeature::RestApiUrl { .. }
        ));

        // "not a url" rejected (no scheme://)
        let url = b"not a url";
        let mut body = vec![url.len() as u8];
        body.extend_from_slice(url);
        assert!(matches!(
            deserialize_feature(id, &body),
            PeerFeature::Unknown { .. }
        ));

        // "localhost:9053" rejected (no scheme)
        let url = b"localhost:9053";
        let mut body = vec![url.len() as u8];
        body.extend_from_slice(url);
        assert!(matches!(
            deserialize_feature(id, &body),
            PeerFeature::Unknown { .. }
        ));

        // Invalid UTF-8 rejected
        let body = vec![2, 0xFF, 0xFE];
        assert!(matches!(
            deserialize_feature(id, &body),
            PeerFeature::Unknown { .. }
        ));
    }

    /// Pin our peer-feature IDs against Scala's
    /// `org.ergoplatform.settings.PeerFeatureDescriptors`. Drift here
    /// means a Scala peer's serialized feature lands in our
    /// `PeerFeature::Unknown` catchall instead of being parsed, and
    /// vice versa — wire-compat hole without a wire-level error.
    #[test]
    fn peer_feature_ids_match_scala() {
        assert_eq!(FEATURE_LOCAL_ADDRESS, 2);
        assert_eq!(FEATURE_SESSION_ID, 3);
        assert_eq!(FEATURE_REST_API_URL, 4);
        assert_eq!(FEATURE_MODE, 16);
    }

    #[test]
    fn mode_with_utxo_bootstrapped() {
        let feature = PeerFeature::Mode {
            state_type: 0,
            verify_tx: true,
            nipopow: None,
            blocks_to_keep: -2, // UTXOSetBootstrapped
        };
        let (id, body) = serialize_feature_body(&feature);
        assert_eq!(id, FEATURE_MODE);
        let parsed = deserialize_feature(id, &body);
        match parsed {
            PeerFeature::Mode { blocks_to_keep, .. } => {
                assert_eq!(blocks_to_keep, -2);
            }
            _ => panic!("expected Mode"),
        }
    }
}
