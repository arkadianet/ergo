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
    /// Reference-node default `scorex.network.appVersion` of Scala 6.0.7, the
    /// stable release whose consensus and mempool rules this node implements.
    ///
    /// Scala keeps named constants here for activation milestones, then wires
    /// the advertised handshake version from config. Until we expose the same
    /// config knob, this is the version our node announces. Scala gates no
    /// peer behavior on versions above `NIPOPOW`, so this signals parity only.
    pub const CURRENT: Self = Self {
        major: 6,
        minor: 0,
        patch: 7,
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
            // Cap at i32::MAX: the parse side enforces that bound
            // (`get_u32_exact`, mirroring Scala's `getUInt().toIntExact` in
            // `LocalAddressPeerFeatureSerializer.parse`,
            // LocalAddressPeerFeature.scala:33), and emitting a value it
            // rejects would make serialization non-idempotent. Real socket
            // ports are <= 65535, so like the >255-byte name truncation and
            // the 127-feature cap this never fires in production.
            w.put_u32((*port).min(i32::MAX as u32));
            (FEATURE_LOCAL_ADDRESS, w.result())
        }
        PeerFeature::SessionId { magic, session_id } => {
            // Scala: `putBytes(magic)` + `putLong(sessionId)`
            // (SessionIdPeerFeature.scala:33-39). scorex's `putLong` is
            // VLQ+ZigZag (scorex-util 0.2.2 `VLQWriter.putLong`), not a
            // fixed-width write — the body is 4 magic bytes plus a
            // 1..=10-byte zigzag VLQ.
            let mut w = VlqWriter::new();
            w.put_bytes(magic);
            w.put_i64(*session_id);
            (FEATURE_SESSION_ID, w.result())
        }
        PeerFeature::RestApiUrl { url } => {
            let url_bytes = truncate_to_u8(url.as_bytes());
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

/// Deserialize a single peer feature from its raw body bytes.
///
/// A known feature id is accepted only when the body is exactly the
/// canonical serialization of that feature (in-range fields, fully
/// consumed, minimal VLQ encodings — enforced by re-serializing the
/// parsed feature and requiring byte identity with the input).
/// Anything else — truncation, trailing bytes, out-of-range values,
/// overlong VLQs, non-canonical booleans — is preserved as
/// `Unknown { feature_id, data }`:
///
/// * this is a documented superset over Scala, which *drops* a feature
///   that fails `parseTry` (PeerSpec.scala:94-101: "we ignore a feature
///   found in the PeersData if we do not know how to parse it or failed
///   to do that");
/// * it keeps `serialize(deserialize(x)) == x` byte-stable for every body
///   this codec can emit, which matters because preserved `PeerSpec`s are
///   re-emitted in `Peers` replies.
///
/// Note that Scala silently ignores trailing bytes in a feature chunk
/// (the chunk reader is not checked for exhaustion); we deliberately do
/// not mirror that, since re-emitting the typed feature would rewrite the
/// peer's bytes.
fn deserialize_feature(feature_id: u8, data: &[u8]) -> PeerFeature {
    let unknown = || {
        tracing::debug!(
            feature_id,
            len = data.len(),
            "handshake: feature body not canonical; preserving as Unknown"
        );
        PeerFeature::Unknown {
            feature_id,
            data: data.to_vec(),
        }
    };
    // Parse to a typed feature, or `None` when the body is not decodable
    // (truncation, trailing bytes, out-of-range values).
    let parsed: Option<PeerFeature> = match feature_id {
        // Scala: `getBytes(4)` + `getUInt().toIntExact` — the port is
        // bounded by i32::MAX (LocalAddressPeerFeature.scala:31-35,
        // scorex-util `VLQReader.getUIntExact`).
        FEATURE_LOCAL_ADDRESS => {
            if data.len() < 5 {
                None
            } else {
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&data[..4]);
                let mut r = VlqReader::new(&data[4..]);
                // Scala parity on well-formed input: `getBytes(4)` +
                // `getUInt().toIntExact` (LocalAddressPeerFeature.scala:31-35).
                // `toIntExact` rejects port values above i32::MAX, in which case
                // `PeerSpecSerializer.parse` drops the whole feature
                // (`parseTry(...).toOption`, PeerSpec.scala:99-101). We preserve
                // the raw feature bytes as Unknown instead of fabricating a port
                // (documented superset stance for malformed feature data), which
                // also keeps serialize->deserialize byte-idempotent.
                // The port VLQ must end exactly at the end of the body (see the
                // function doc for why trailing bytes are preserved).
                match (r.get_u32_exact(), r.remaining()) {
                    (Ok(port), 0) => Some(PeerFeature::LocalAddress { addr, port }),
                    _ => None,
                }
            }
        }
        // Scala: `getBytes(MagicLength=4)` + `getLong()` — `getLong` is
        // VLQ+ZigZag, so the body is 4 magic bytes plus a 1..=10-byte
        // zigzag VLQ (SessionIdPeerFeature.scala:36-40, scorex-util
        // `VLQReader.getLong`), not a fixed-width 8-byte write.
        FEATURE_SESSION_ID => {
            if data.len() < 5 {
                None
            } else {
                let mut magic = [0u8; 4];
                magic.copy_from_slice(&data[..4]);
                let mut r = VlqReader::new(&data[4..]);
                match (r.get_i64(), r.remaining()) {
                    (Ok(session_id), 0) => Some(PeerFeature::SessionId { magic, session_id }),
                    _ => None,
                }
            }
        }
        FEATURE_REST_API_URL => {
            // The body is exactly 1+len bytes (Scala: `getUByte()` +
            // `getBytes(len)`); trailing bytes are preserved, not ignored.
            let url_bytes = match data.first() {
                Some(&url_len) if data.len() == 1 + url_len as usize => {
                    Some(&data[1..1 + url_len as usize])
                }
                _ => None,
            };
            let url_str = url_bytes.and_then(|bytes| {
                // Validate UTF-8 strictly, then check URL syntax.
                // Scala parses via new java.net.URL(...) which requires a valid
                // scheme://... structure. We approximate by requiring "scheme://"
                // where scheme is at least one ASCII letter.
                std::str::from_utf8(bytes)
                    .ok()
                    .filter(|s| !s.is_empty() && has_url_scheme(s))
                    .map(|s| s.to_string())
            });
            url_str.map(|url| PeerFeature::RestApiUrl { url })
        }
        // Scala: `getByte` stateType (unknown code throws, feature dropped)
        // + `getByte` verify (>0 = true) + `getOption(getInt)` + `getInt`
        // (`ModeFeatureSerializer.parse`, ModePeerFeature.scala). We are
        // lenient where Scala throws on the stateType code (superset: any
        // u8 is kept), but strict on the option flag (the serializer emits
        // only 0|1) and on full consumption — see the function doc.
        FEATURE_MODE => (|| {
            let mut r = VlqReader::new(data);
            let state_type = r.get_u8().ok()?;
            // Scala's `byteToBoolean` compares the *signed* byte
            // (`if (byte > 0) true else false`, ModePeerFeature.scala:109),
            // so 0x80..=0xFF parse as `false`.
            let verify_tx = (r.get_u8().ok()? as i8) > 0;
            let nipopow = match r.get_u8().ok()? {
                0 => None,
                1 => Some(r.get_i32().ok()?),
                _ => return None,
            };
            let blocks_to_keep = match r.get_i32() {
                Ok(v) if r.remaining() == 0 => v,
                _ => return None,
            };
            Some(PeerFeature::Mode {
                state_type,
                verify_tx,
                nipopow,
                blocks_to_keep,
            })
        })(),
        _ => None,
    };
    match parsed {
        // Canonical re-serialization check: a body that decodes but does not
        // re-encode to itself — an overlong VLQ (`80 00` -> id 0), or a Mode
        // verify byte > 1 that Scala would still call `true` — would change
        // bytes when the preserved spec is re-emitted in `Peers` replies.
        // Scala's serializers only ever emit canonical bodies, so this
        // affects only adversarial input; preserve it as Unknown.
        Some(feature) => {
            let (id, body) = serialize_feature_body(&feature);
            if id == feature_id && body == data {
                feature
            } else {
                unknown()
            }
        }
        None => unknown(),
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

/// Longest prefix of `bytes` whose length fits the one-byte `shortString`
/// length prefix, snapped back to a UTF-8 char boundary. Writing
/// `len as u8` while emitting every byte would wrap the prefix and desync
/// the receiver's parser — Scala escalates handshake parse failures to a
/// permanent IP ban (PeerConnectionHandler.scala:104-106).
fn truncate_to_u8(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len().min(u8::MAX as usize);
    if end < bytes.len() {
        while end > 0 && bytes[end] & 0xC0 == 0x80 {
            end -= 1;
        }
    }
    &bytes[..end]
}

/// Serialize a PeerSpec into the given writer (used by both Handshake and Peers).
pub fn serialize_peer_spec_to(spec: &PeerSpec, w: &mut VlqWriter) {
    // shortString: byte(len) + UTF-8
    let agent_bytes = truncate_to_u8(spec.agent_name.as_bytes());
    w.put_u8(agent_bytes.len() as u8);
    w.put_bytes(agent_bytes);

    // Version: 3 raw bytes
    w.put_u8(spec.version.major);
    w.put_u8(spec.version.minor);
    w.put_u8(spec.version.patch);

    // shortString: node_name
    let name_bytes = truncate_to_u8(spec.node_name.as_bytes());
    w.put_u8(name_bytes.len() as u8);
    w.put_bytes(name_bytes);

    // option(declaredAddress)
    match &spec.declared_address {
        Some(addr) => {
            w.put_u8(1); // option present
                         // Length hint: Scala writes `put((addr.size + 4).toByteExact)`
                         // (PeerSpec.scala:58) — the fixed 4 is an offset, not a port
                         // width (the port is VLQ after the address bytes).
            w.put_u8((addr.addr.len() + 4) as u8);
            w.put_bytes(&addr.addr);
            // Same i32::MAX cap as the LocalAddress feature port: the parse
            // side (and Scala's `getUInt().toIntExact`, PeerSpec.scala:84)
            // rejects larger values. Real declared ports are <= 65535.
            w.put_u32(addr.port.min(i32::MAX as u32));
        }
        None => {
            w.put_u8(0); // option absent
        }
    }

    // Features: byte(count) + Feature[]. The count byte is SIGNED on the
    // wire (Scala parses it with getByte + require(>=0), and our
    // deserializer mirrors that via `as i8`), so counts above 127 are
    // unrepresentable — serialize at most 127 features and drop the rest.
    let feature_cap = (u8::MAX as usize) / 2; // 127: keep the signed byte non-negative
    w.put_u8(spec.features.len().min(feature_cap) as u8);
    for feature in spec.features.iter().take(feature_cap) {
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
        // Scala: `r.getBytes(fas - 4)` (PeerSpec.scala:83) throws for
        // `fas < 4` (negative length), failing the whole handshake —
        // mirror that instead of saturating to a zero-length address.
        if total_len < 4 {
            return Err(HandshakeError::MalformedDeclaredAddress(total_len));
        }
        let addr_len = total_len - 4;
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
    #[error("malformed declared address length byte {0}: must be >= 4 (address bytes + 4 offset)")]
    MalformedDeclaredAddress(usize),
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
    // A raw TCP read can coalesce a small handshake with framed traffic.
    // Bound the handshake parser itself; bytes after a complete prefix belong
    // to the framed connection and must not count against this admission cap.
    let mut r = VlqReader::new(&payload[..payload.len().min(MAX_HANDSHAKE_SIZE)]);
    let parsed = (|| {
        let time = r.get_u64()?;
        let peer_spec = deserialize_peer_spec_from(&mut r)?;
        Ok((Handshake { time, peer_spec }, r.position()))
    })();
    match parsed {
        Err(HandshakeError::Read(
            ReadError::UnexpectedEnd { .. }
            | ReadError::Vlq(ergo_primitives::vlq::VlqError::UnexpectedEnd),
        )) if payload.len() > MAX_HANDSHAKE_SIZE => Err(HandshakeError::TooLarge(payload.len())),
        other => other,
    }
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

    /// Golden vector: a real mainnet node handshake captured by the Scala
    /// test suite (`ergo-core/src/test/scala/org/ergoplatform/network/
    /// HandshakeSpecification.scala:13`, v6.0.7). Byte layout, verified
    /// against `PeerSpecSerializer.scala` / `ModeFeatureSerializer.scala` /
    /// `LocalAddressPeerFeature.scala`:
    ///
    /// `bcd2919cee2e`  time VLQ = 1610134874428 (Fri, 8 Jan 2021 19:41:14 UTC)
    /// `07` + `ergoref`            agent name
    /// `03 03 06`                  protocol version 3.3.6
    /// `12` + `ergo-mainnet-3.3.6` node name
    /// `00`                        declared address: absent
    /// `02`                        feature count (signed byte)
    /// `10` `04` `00 01 00 01`     mode: Utxo, verify-tx, no nipopow, blocks-to-keep -1
    /// `02` `06` `7f000001` `ae46` local address 127.0.0.1:9006 (port VLQ)
    #[test]
    fn real_node_handshake_fixture() {
        const HEX: &str =
            "bcd2919cee2e076572676f726566030306126572676f2d6d61696e6e65742d332e332e36000210040001000102067f000001ae46";
        let bytes = hex::decode(HEX).unwrap();
        assert_eq!(bytes.len(), 52);

        let (hs, consumed) = deserialize_handshake_with_consumed(&bytes).unwrap();
        assert_eq!(consumed, bytes.len(), "fixture must be fully consumed");

        assert_eq!(hs.time, 1610134874428);
        let spec = &hs.peer_spec;
        assert_eq!(spec.agent_name, "ergoref");
        assert_eq!(
            spec.version,
            Version {
                major: 3,
                minor: 3,
                patch: 6
            }
        );
        assert_eq!(spec.node_name, "ergo-mainnet-3.3.6");
        assert!(spec.declared_address.is_none());
        assert_eq!(spec.features.len(), 2);
        match &spec.features[0] {
            PeerFeature::Mode {
                state_type,
                verify_tx,
                nipopow,
                blocks_to_keep,
            } => {
                assert_eq!(*state_type, 0); // StateType.Utxo
                assert!(*verify_tx);
                assert!(nipopow.is_none());
                assert_eq!(*blocks_to_keep, -1); // AllBlocksKept
            }
            other => panic!("expected Mode feature, got {other:?}"),
        }
        match &spec.features[1] {
            PeerFeature::LocalAddress { addr, port } => {
                assert_eq!(addr, &[127, 0, 0, 1]);
                assert_eq!(*port, 9006);
            }
            other => panic!("expected LocalAddress feature, got {other:?}"),
        }
    }

    #[test]
    fn raw_handshake_prefix_preserves_large_coalesced_frame() {
        use crate::framing::{deserialize_frame, serialize_frame, MessageFrame, MAINNET_MAGIC};
        let hs = make_test_handshake();
        let prefix = serialize_handshake(&hs);
        let frame = MessageFrame {
            code: 33,
            payload: vec![7; MAX_HANDSHAKE_SIZE],
        };
        let wire = serialize_frame(&MAINNET_MAGIC, &frame);
        let mut read = prefix.clone();
        read.extend_from_slice(&wire);
        assert!(read.len() > MAX_HANDSHAKE_SIZE);
        let (parsed, consumed) = deserialize_handshake_with_consumed(&read).unwrap();
        assert_eq!(parsed.time, hs.time);
        assert_eq!(consumed, prefix.len());
        assert_eq!(&read[consumed..], wire);
        let (decoded, frame_len) = deserialize_frame(&MAINNET_MAGIC, &read[consumed..])
            .unwrap()
            .unwrap();
        assert_eq!(decoded.payload, frame.payload);
        assert_eq!(frame_len, wire.len());
    }

    #[test]
    fn handshake_parser_enforces_prefix_size_boundary() {
        // The fixed prefix is 13 bytes: time1, agent2, version3, name2,
        // address flag1, feature count1, feature id1, VLQ length2.
        let mut hs = Handshake {
            time: 0,
            peer_spec: PeerSpec {
                agent_name: "a".into(),
                version: Version::CURRENT,
                node_name: "n".into(),
                declared_address: None,
                features: vec![PeerFeature::Unknown {
                    feature_id: 250,
                    data: vec![7; MAX_HANDSHAKE_SIZE - 13],
                }],
            },
        };
        let bytes = serialize_handshake(&hs);
        assert_eq!(bytes.len(), MAX_HANDSHAKE_SIZE);
        assert_eq!(
            deserialize_handshake_with_consumed(&bytes).unwrap().1,
            MAX_HANDSHAKE_SIZE
        );
        if let PeerFeature::Unknown { data, .. } = &mut hs.peer_spec.features[0] {
            data.push(7);
        }
        let oversize = serialize_handshake(&hs);
        assert!(
            matches!(deserialize_handshake_with_consumed(&oversize), Err(HandshakeError::TooLarge(n)) if n == MAX_HANDSHAKE_SIZE + 1)
        );
        assert!(matches!(
            deserialize_handshake_with_consumed(&bytes[..bytes.len() - 1]),
            Err(HandshakeError::Read(_))
        ));
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
    fn advertised_version_is_scala_6_0_7() {
        assert_eq!(Version::CURRENT.to_string(), "6.0.7");
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

    /// shortString fields carry a one-byte length prefix; over-long
    /// inputs must be truncated on a UTF-8 boundary rather than wrapping
    /// the prefix (a wrapped prefix desyncs the receiving parser, which
    /// Scala escalates to a permanent IP ban). Pins the 255-byte ceiling
    /// and mid-char snapping.
    #[test]
    fn peer_spec_string_fields_truncate_to_u8_prefix() {
        fn spec_with(agent: &str, name: &str) -> Handshake {
            Handshake {
                time: 1,
                peer_spec: PeerSpec {
                    agent_name: agent.into(),
                    version: Version::NIPOPOW,
                    node_name: name.into(),
                    declared_address: None,
                    features: Vec::new(),
                },
            }
        }
        // Exactly 255 ASCII bytes roundtrip unchanged.
        let s255 = "a".repeat(255);
        let bytes = serialize_handshake(&spec_with("a", &s255));
        let (parsed, _) = deserialize_handshake_with_consumed(&bytes).unwrap();
        assert_eq!(parsed.peer_spec.node_name.len(), 255);

        // 400 ASCII bytes truncate to 255.
        let s400 = "b".repeat(400);
        let bytes = serialize_handshake(&spec_with(&s400, "n"));
        let (parsed, _) = deserialize_handshake_with_consumed(&bytes).unwrap();
        assert_eq!(parsed.peer_spec.agent_name.len(), 255);

        // Multi-byte truncation snaps to a char boundary: "é" is 2 bytes,
        // so 128 of them are 256 bytes and a naive cut at 255 splits the
        // final char.
        let multi = "é".repeat(128);
        let bytes = serialize_handshake(&spec_with("a", &multi));
        let (parsed, _) = deserialize_handshake_with_consumed(&bytes).unwrap();
        assert_eq!(parsed.peer_spec.node_name, "é".repeat(127));
    }

    #[test]
    fn rest_api_url_feature_body_truncates_to_u8() {
        let url = format!("http://example.com/{}", "p".repeat(300));
        let (id, body) = serialize_feature_body(&PeerFeature::RestApiUrl { url });
        assert_eq!(id, FEATURE_REST_API_URL);
        assert_eq!(body[0] as usize, u8::MAX as usize);
        assert_eq!(body.len(), 1 + u8::MAX as usize);
    }

    /// The feature-count byte is signed on the wire (Scala getByte +
    /// require(>=0)), so counts above 127 are unrepresentable; over-long
    /// lists must be capped, not wrapped.
    #[test]
    fn peer_spec_feature_count_caps_at_127() {
        let features: Vec<PeerFeature> = (0..300u16)
            .map(|i| PeerFeature::Unknown {
                feature_id: 200 + (i % 50) as u8,
                data: vec![1, 2, 3],
            })
            .collect();
        let hs = Handshake {
            time: 1,
            peer_spec: PeerSpec {
                agent_name: "a".into(),
                version: Version::NIPOPOW,
                node_name: "n".into(),
                declared_address: None,
                features,
            },
        };
        let bytes = serialize_handshake(&hs);
        let (parsed, _) = deserialize_handshake_with_consumed(&bytes).unwrap();
        assert_eq!(parsed.peer_spec.features.len(), (u8::MAX as usize) / 2);
    }

    /// Golden vectors for the `SessionId` feature body, computed
    /// independently in Python from the pinned layout
    /// `putBytes(magic)` + `putLong(sessionId)` (scorex `putLong` =
    /// VLQ+ZigZag, scorex-util 0.2.2 `VLQWriter.putLong` /
    /// `VLQReader.getLong`):
    ///
    /// | session_id | body hex |
    /// |---|---|
    /// | 42 | `0100020454` |
    /// | -12345678 | `010002049b85e30b` |
    /// | -1 | `0100020401` |
    /// | 0 | `0100020400` |
    /// | i64::MAX | `01000204feffffffffffffffff01` |
    /// | i64::MIN | `01000204ffffffffffffffffff01` |
    ///
    /// These pin the wire format against the pre-fix bug where the
    /// serializer wrote the id as a fixed 8-byte big-endian (and the
    /// parser read one back), which silently misread Scala peers'
    /// variable-length zigzag bodies in both directions.
    #[test]
    fn session_id_feature_wire_format_golden_vectors() {
        let magic = [1, 0, 2, 4];
        let cases = [
            (42i64, "0100020454"),
            (-12345678i64, "010002049b85e30b"),
            (-1i64, "0100020401"),
            (0i64, "0100020400"),
            (i64::MAX, "01000204feffffffffffffffff01"),
            (i64::MIN, "01000204ffffffffffffffffff01"),
        ];
        for (sid, expected) in cases {
            let (id, body) = serialize_feature_body(&PeerFeature::SessionId {
                magic,
                session_id: sid,
            });
            assert_eq!(id, FEATURE_SESSION_ID, "sid={sid}");
            assert_eq!(
                hex::encode(&body),
                expected,
                "wire drift for session_id={sid}"
            );
            // And the parser must invert it exactly.
            match deserialize_feature(FEATURE_SESSION_ID, &body) {
                PeerFeature::SessionId {
                    magic: m,
                    session_id: s,
                } => {
                    assert_eq!(m, magic);
                    assert_eq!(s, sid);
                }
                other => panic!("roundtrip failed for sid={sid}: {other:?}"),
            }
        }
    }

    /// Ports above `i32::MAX` are unrepresentable on the parse side
    /// (`get_u32_exact` mirrors Scala's `getUInt().toIntExact`), so the
    /// serializer caps them instead of emitting bytes it would reject.
    /// Pinned at the exact boundary 2^31 = i32::MAX + 1 (the case the
    /// offline fuzz suite first found).
    #[test]
    fn local_address_port_capped_at_i32_max() {
        let over = serialize_feature_body(&PeerFeature::LocalAddress {
            addr: [0, 0, 0, 0],
            port: 2u32.pow(31),
        });
        let maxed = serialize_feature_body(&PeerFeature::LocalAddress {
            addr: [0, 0, 0, 0],
            port: i32::MAX as u32,
        });
        assert_eq!(over.0, maxed.0);
        assert_eq!(
            hex::encode(&over.1),
            "00000000ffffffff07", // 4 zero addr bytes + VLQ(0x7FFFFFFF)
        );
        match deserialize_feature(over.0, &over.1) {
            PeerFeature::LocalAddress { port, .. } => {
                assert_eq!(port, i32::MAX as u32);
            }
            other => panic!("expected LocalAddress, got {other:?}"),
        }
    }

    /// A known feature id with a non-canonical body (trailing bytes,
    /// truncated fields, out-of-range values) is preserved verbatim as
    /// `Unknown`, never coerced into a typed feature with fabricated
    /// fields. Preserved specs are re-emitted in `Peers` replies, so
    /// `serialize(deserialize(x)) == x` must hold for these bodies.
    #[test]
    fn non_canonical_feature_bodies_preserved_as_unknown() {
        // feature id 2 = LocalAddress; 6 bytes = 4 addr + port VLQ(1
        // byte) + one trailing byte.
        let body: [u8; 6] = [0, 0, 0, 0, 0, 0];
        match deserialize_feature(FEATURE_LOCAL_ADDRESS, &body) {
            PeerFeature::Unknown { feature_id, data } => {
                assert_eq!(feature_id, FEATURE_LOCAL_ADDRESS);
                assert_eq!(data, body.to_vec());
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        // The canonical 5-byte form of the same prefix still parses.
        match deserialize_feature(FEATURE_LOCAL_ADDRESS, &body[..5]) {
            PeerFeature::LocalAddress { addr, port } => {
                assert_eq!(addr, [0, 0, 0, 0]);
                assert_eq!(port, 0);
            }
            other => panic!("expected LocalAddress, got {other:?}"),
        }
        // Trailing bytes after a valid Mode body are preserved too.
        let (id, mode_body) = serialize_feature_body(&PeerFeature::Mode {
            state_type: 0,
            verify_tx: true,
            nipopow: None,
            blocks_to_keep: -1,
        });
        assert_eq!(id, FEATURE_MODE);
        let mut padded = mode_body.clone();
        padded.push(0);
        match deserialize_feature(id, &padded) {
            PeerFeature::Unknown { feature_id, data } => {
                assert_eq!(feature_id, FEATURE_MODE);
                assert_eq!(data, padded);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        // An overlong VLQ that decodes cleanly but re-encodes differently
        // (`80 00` -> id 0, canonical form `00`) must not survive as a typed
        // feature: re-emitting it in a `Peers` reply would rewrite the
        // peer's bytes.
        let mut overlong = [1u8, 0, 2, 4].to_vec();
        overlong.extend_from_slice(&[0x80, 0x00]);
        match deserialize_feature(FEATURE_SESSION_ID, &overlong) {
            PeerFeature::Unknown { feature_id, data } => {
                assert_eq!(feature_id, FEATURE_SESSION_ID);
                assert_eq!(data, overlong);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        // A Mode verify byte > 1 decodes (Scala's byteToBoolean: any
        // positive signed byte is true) but re-serializes as `00 01` —
        // also not canonical, also preserved as Unknown. Scala's serializer
        // only emits 0|1, so such bodies come only from adversarial peers.
        let (id, mode_body) = serialize_feature_body(&PeerFeature::Mode {
            state_type: 0,
            verify_tx: true,
            nipopow: None,
            blocks_to_keep: -1,
        });
        let mut verify_two = mode_body.clone();
        verify_two[1] = 2;
        match deserialize_feature(id, &verify_two) {
            PeerFeature::Unknown { feature_id, data } => {
                assert_eq!(feature_id, FEATURE_MODE);
                assert_eq!(data, verify_two);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    /// A declared-address length hint below 4 cannot hold the fixed 4
    /// offset (Scala `getBytes(fas - 4)` throws, failing the whole
    /// handshake — PeerSpec.scala:83); mirror that rejection instead of
    /// saturating to a zero-length address.
    #[test]
    fn declared_address_length_below_4_rejects_spec() {
        let mut w = VlqWriter::new();
        w.put_u8(1);
        w.put_bytes(b"a"); // agent
        w.put_u8(3);
        w.put_u8(3);
        w.put_u8(6); // version
        w.put_u8(1);
        w.put_bytes(b"n"); // node name
        w.put_u8(1); // declared present
        w.put_u8(3); // length hint < 4
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = deserialize_peer_spec_from(&mut r).unwrap_err();
        assert!(
            matches!(err, HandshakeError::MalformedDeclaredAddress(3)),
            "unexpected error: {err:?}"
        );
    }
}
