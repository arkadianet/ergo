use crate::peer_feature::PeerFeature;
use crate::vlq::{self, CodecError};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl ProtocolVersion {
    pub const EIP37_FORK: Self = Self { major: 4, minor: 0, patch: 100 };
    pub const SYNC_V2_MIN: Self = Self { major: 4, minor: 0, patch: 16 };

    /// Parse a version string like "6.0.1" into a ProtocolVersion.
    pub fn from_version_str(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        vec![self.major, self.minor, self.patch]
    }

    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < 3 {
            return Err(CodecError::UnexpectedEof);
        }
        Ok(Self {
            major: data[0],
            minor: data[1],
            patch: data[2],
        })
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Whether a peer connection was initiated by us or by the remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub agent_name: String,
    pub protocol_version: ProtocolVersion,
    pub node_name: String,
    pub declared_address: Option<SocketAddr>,
    pub features: Vec<PeerFeature>,
}

impl PeerSpec {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        vlq::put_short_string(&mut buf, &self.agent_name);
        buf.extend_from_slice(&self.protocol_version.serialize());
        vlq::put_short_string(&mut buf, &self.node_name);

        // declared address: Option encoding
        match &self.declared_address {
            None => buf.push(0),
            Some(addr) => {
                buf.push(1);
                match addr {
                    SocketAddr::V4(v4) => {
                        let ip_bytes = v4.ip().octets();
                        // Size byte = ip_len + 4 (Scala convention)
                        buf.push((ip_bytes.len() + 4) as u8);
                        buf.extend_from_slice(&ip_bytes);
                        // Port is VLQ-encoded (Scorex putUInt = VLQ)
                        vlq::put_uint(&mut buf, v4.port() as u32);
                    }
                    SocketAddr::V6(v6) => {
                        let ip_bytes = v6.ip().octets();
                        buf.push((ip_bytes.len() + 4) as u8);
                        buf.extend_from_slice(&ip_bytes);
                        vlq::put_uint(&mut buf, v6.port() as u32);
                    }
                }
            }
        }

        // features
        buf.push(self.features.len() as u8);
        for feat in &self.features {
            buf.push(feat.feature_id());
            let feat_bytes = feat.serialize_bytes();
            // Feature data length as VLQ UShort (Scala: w.putUShort(fBytes.length))
            vlq::put_ushort(&mut buf, feat_bytes.len() as u16);
            buf.extend_from_slice(&feat_bytes);
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut pos = 0;

        // agent_name
        let (agent_name, _) = vlq::get_short_string(&data[pos..])?;
        pos += 1 + agent_name.len();

        // protocol version
        if data.len() < pos + 3 {
            return Err(CodecError::UnexpectedEof);
        }
        let protocol_version = ProtocolVersion::parse(&data[pos..pos + 3])?;
        pos += 3;

        // node_name
        let (node_name, _) = vlq::get_short_string(&data[pos..])?;
        pos += 1 + node_name.len();

        // declared address
        if pos >= data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let has_addr = data[pos];
        pos += 1;
        let declared_address = if has_addr == 0 {
            None
        } else {
            if pos >= data.len() {
                return Err(CodecError::UnexpectedEof);
            }
            let addr_size = data[pos] as usize;
            pos += 1;
            let ip_len = addr_size - 4;
            if data.len() < pos + ip_len {
                return Err(CodecError::UnexpectedEof);
            }
            let ip_bytes = &data[pos..pos + ip_len];
            pos += ip_len;
            // Port is VLQ-encoded (Scorex getUInt = VLQ)
            let mut reader = &data[pos..];
            let port = vlq::get_uint(&mut reader)? as u16;
            let port_bytes_consumed = data[pos..].len() - reader.len();
            pos += port_bytes_consumed;

            if ip_len == 4 {
                let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
            } else {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(ip_bytes);
                let ip = std::net::Ipv6Addr::from(octets);
                Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
            }
        };

        // features
        if pos >= data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let feat_count = data[pos] as usize;
        pos += 1;

        let mut features = Vec::with_capacity(feat_count);
        for _ in 0..feat_count {
            if pos + 2 > data.len() {
                return Err(CodecError::UnexpectedEof);
            }
            let feat_id = data[pos];
            pos += 1;
            // Feature data length is VLQ UShort (Scala: r.getUShort())
            let mut feat_reader = &data[pos..];
            let feat_len = vlq::get_ushort(&mut feat_reader)? as usize;
            let vlq_bytes = data[pos..].len() - feat_reader.len();
            pos += vlq_bytes;
            if data.len() < pos + feat_len {
                return Err(CodecError::UnexpectedEof);
            }
            let feat_data = &data[pos..pos + feat_len];
            pos += feat_len;
            match PeerFeature::parse_feature(feat_id, feat_data) {
                Ok(f) => features.push(f),
                Err(_) => features.push(PeerFeature::Unknown {
                    id: feat_id,
                    data: feat_data.to_vec(),
                }),
            }
        }

        Ok((
            Self {
                agent_name,
                protocol_version,
                node_name,
                declared_address,
                features,
            },
            pos,
        ))
    }
}

/// Full handshake message
#[derive(Debug, Clone)]
pub struct Handshake {
    pub time: u64,
    pub peer_spec: PeerSpec,
}

impl Handshake {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        vlq::put_ulong(&mut buf, self.time);
        buf.extend_from_slice(&self.peer_spec.serialize());
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, CodecError> {
        let mut reader = data;
        let time = vlq::get_ulong(&mut reader)?;
        let consumed = data.len() - reader.len();
        let (peer_spec, _) = PeerSpec::parse(&data[consumed..])?;
        Ok(Self { time, peer_spec })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_feature::{ModeFeature, SessionFeature, StateTypeCode};

    #[test]
    fn handshake_roundtrip() {
        let hs = Handshake {
            time: 1700000000000,
            peer_spec: PeerSpec {
                agent_name: "ergoref".to_string(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 1 },
                node_name: "ergo-rust-test".to_string(),
                declared_address: None,
                features: vec![
                    PeerFeature::Mode(ModeFeature {
                        state_type: StateTypeCode::Utxo,
                        verifying_transactions: true,
                        nipopow_bootstrapped: None,
                        blocks_to_keep: -1,
                    }),
                    PeerFeature::Session(SessionFeature {
                        network_magic: [2, 0, 0, 1],
                        session_id: 12345,
                    }),
                ],
            },
        };

        let bytes = hs.serialize();
        let parsed = Handshake::parse(&bytes).unwrap();

        assert_eq!(parsed.time, hs.time);
        assert_eq!(parsed.peer_spec.agent_name, "ergoref");
        assert_eq!(parsed.peer_spec.protocol_version.major, 6);
        assert_eq!(parsed.peer_spec.node_name, "ergo-rust-test");
        assert!(parsed.peer_spec.declared_address.is_none());
        assert_eq!(parsed.peer_spec.features.len(), 2);
    }

    #[test]
    fn handshake_with_declared_address() {
        let addr: SocketAddr = "192.168.1.1:9030".parse().unwrap();
        let hs = Handshake {
            time: 1700000000000,
            peer_spec: PeerSpec {
                agent_name: "ergoref".to_string(),
                protocol_version: ProtocolVersion { major: 5, minor: 0, patch: 12 },
                node_name: "test".to_string(),
                declared_address: Some(addr),
                features: vec![],
            },
        };

        let bytes = hs.serialize();
        let parsed = Handshake::parse(&bytes).unwrap();

        assert_eq!(parsed.peer_spec.declared_address.unwrap(), addr);
    }

    #[test]
    fn protocol_version_serialization() {
        let v = ProtocolVersion { major: 6, minor: 0, patch: 1 };
        let bytes = v.serialize();
        assert_eq!(bytes, vec![6, 0, 1]);
        let parsed = ProtocolVersion::parse(&bytes).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn handshake_size_within_limit() {
        let hs = Handshake {
            time: 1700000000000,
            peer_spec: PeerSpec {
                agent_name: "ergoref".to_string(),
                protocol_version: ProtocolVersion { major: 6, minor: 0, patch: 1 },
                node_name: "test".to_string(),
                declared_address: None,
                features: vec![],
            },
        };
        let bytes = hs.serialize();
        assert!(bytes.len() < ergo_settings::constants::MAX_HANDSHAKE_SIZE);
    }

    #[test]
    fn protocol_version_from_str() {
        let v = ProtocolVersion::from_version_str("6.0.1").unwrap();
        assert_eq!(v, ProtocolVersion { major: 6, minor: 0, patch: 1 });

        let v2 = ProtocolVersion::from_version_str("5.0.12").unwrap();
        assert_eq!(v2, ProtocolVersion { major: 5, minor: 0, patch: 12 });

        assert!(ProtocolVersion::from_version_str("6.0").is_none());
        assert!(ProtocolVersion::from_version_str("abc").is_none());
        assert!(ProtocolVersion::from_version_str("6.0.256").is_none()); // u8 overflow
    }

    #[test]
    fn protocol_version_ordering() {
        let v4_0_99 = ProtocolVersion { major: 4, minor: 0, patch: 99 };
        let v4_0_100 = ProtocolVersion { major: 4, minor: 0, patch: 100 };
        let v5_0_0 = ProtocolVersion { major: 5, minor: 0, patch: 0 };
        let v4_9_255 = ProtocolVersion { major: 4, minor: 9, patch: 255 };
        assert!(v4_0_99 < v4_0_100);
        assert!(v4_0_100 < v5_0_0);
        assert!(v5_0_0 > v4_9_255);
    }

    #[test]
    fn connection_direction_eq() {
        assert_eq!(ConnectionDirection::Incoming, ConnectionDirection::Incoming);
        assert_ne!(ConnectionDirection::Incoming, ConnectionDirection::Outgoing);
    }

    #[test]
    fn protocol_version_display() {
        let v = ProtocolVersion { major: 5, minor: 0, patch: 0 };
        assert_eq!(format!("{}", v), "5.0.0");
        let v2 = ProtocolVersion { major: 4, minor: 0, patch: 100 };
        assert_eq!(format!("{}", v2), "4.0.100");
    }

    #[test]
    fn eip37_fork_implies_sync_v2_support() {
        let eip37 = ProtocolVersion::EIP37_FORK;
        let sync_v2 = ProtocolVersion::SYNC_V2_MIN;
        // EIP37_FORK (4.0.100) must be >= SYNC_V2_MIN (4.0.16)
        // This guarantees all connected peers support SyncInfo V2,
        // since we reject peers below EIP37_FORK during handshake.
        assert!(
            eip37 >= sync_v2,
            "EIP37_FORK ({eip37}) must be >= SYNC_V2_MIN ({sync_v2})"
        );
    }
}
