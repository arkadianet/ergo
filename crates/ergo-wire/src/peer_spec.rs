use std::net::{Ipv4Addr, SocketAddr};

use crate::vlq::{self, CodecError};

/// A peer address extracted from a Peers message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddr {
    pub address: SocketAddr,
}

/// Serialize a single peer entry into the buffer.
///
/// Matches Scala `PeerSpecSerializer.serialize` wire format:
///   - agentName: 1-byte length + UTF-8 (putShortString)
///   - protocolVersion: 3 raw bytes
///   - nodeName: 1-byte length + UTF-8 (putShortString)
///   - declaredAddress: option byte (0x00=None, 0x01=Some) + if Some:
///       - addr_size: 1 byte = ip_bytes.len + 4 (Scala quirk)
///       - ip bytes (4 for IPv4)
///       - port as VLQ uint
///   - features: 1-byte count + per feature: id(1) + VLQ ushort len + data
fn serialize_one_peer(buf: &mut Vec<u8>, addr: &SocketAddr) {
    // Agent name (1-byte length + UTF-8)
    vlq::put_short_string(buf, "ergo-rust");
    // Protocol version (3 raw bytes)
    buf.extend_from_slice(&[5, 0, 0]);
    // Node name (1-byte length + UTF-8)
    vlq::put_short_string(buf, "node");
    // Declared address (option encoding)
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(0x01); // option byte: Some
            let ip_bytes = v4.ip().octets();
            let ip_len = ip_bytes.len() as u8; // 4 for IPv4
            buf.push(ip_len + 4); // addr_size = ip_len + 4 (Scala convention)
            buf.extend_from_slice(&ip_bytes);
            vlq::put_uint(buf, v4.port() as u32); // VLQ-encoded port
        }
        SocketAddr::V6(_) => {
            buf.push(0x00); // option byte: None (IPv6 not supported)
        }
    }
    // Feature count = 0
    buf.push(0);
}

/// Serialize a list of peer addresses into a Peers message body.
///
/// The body is a VLQ-uint count followed by each peer entry.
pub fn serialize_peers(peers: &[PeerAddr]) -> Vec<u8> {
    let mut buf = Vec::new();
    vlq::put_uint(&mut buf, peers.len() as u32);
    for peer in peers {
        serialize_one_peer(&mut buf, &peer.address);
    }
    buf
}

/// Parse a single peer entry from the data slice, advancing the offset.
///
/// Matches Scala `PeerSpecSerializer.parse` wire format:
///   - agentName: getShortString (1-byte len + UTF-8)
///   - protocolVersion: 3 raw bytes
///   - nodeName: getShortString
///   - declaredAddress: getOption { getUByte (addr_size), getBytes(addr_size-4) (IP), getUInt (port) }
///   - features: getByte (count) + per feature: getByte (id) + getUShort (data_len) + getChunk(data_len)
///
/// Returns `Ok(Some(PeerAddr))` if the peer has a valid IPv4 declared
/// address, `Ok(None)` if the peer has no address or an unrecognised
/// address format, and `Err` on malformed input.
fn parse_one_peer(data: &[u8], offset: &mut usize) -> Result<Option<PeerAddr>, CodecError> {
    // Skip agent name (1-byte length + UTF-8)
    let remaining = &data[*offset..];
    let (_agent, rest) = vlq::get_short_string(remaining)?;
    *offset += remaining.len() - rest.len();

    // Skip protocol version (3 raw bytes)
    if *offset + 3 > data.len() {
        return Err(CodecError::UnexpectedEof);
    }
    *offset += 3;

    // Skip node name (1-byte length + UTF-8)
    let remaining = &data[*offset..];
    let (_name, rest) = vlq::get_short_string(remaining)?;
    *offset += remaining.len() - rest.len();

    // Read declared address option (Scala: r.getOption { ... })
    // Option byte: 0x00 = None, non-zero = Some
    if *offset >= data.len() {
        return Err(CodecError::UnexpectedEof);
    }
    let has_addr = data[*offset];
    *offset += 1;

    let peer_addr = if has_addr != 0 {
        // addr_size (Scala: r.getUByte())
        if *offset >= data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let fas = data[*offset] as usize;
        *offset += 1;

        // IP bytes = fas - 4 bytes (Scala: r.getBytes(fas - 4))
        let ip_len = fas.saturating_sub(4);
        if ip_len == 0 || *offset + ip_len > data.len() {
            // Skip to port and return None for malformed address
            let mut reader = &data[*offset..];
            let _port = vlq::get_uint(&mut reader)?;
            *offset = data.len() - reader.len();
            None
        } else if ip_len == 4 {
            // IPv4
            let ip = Ipv4Addr::new(
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            );
            *offset += ip_len;

            // Port as VLQ uint (Scala: r.getUInt())
            let mut reader = &data[*offset..];
            let port = vlq::get_uint(&mut reader)? as u16;
            *offset = data.len() - reader.len();

            Some(PeerAddr {
                address: SocketAddr::new(ip.into(), port),
            })
        } else {
            // IPv6 or unknown — skip IP bytes + VLQ port
            *offset += ip_len;
            let mut reader = &data[*offset..];
            let _port = vlq::get_uint(&mut reader)?;
            *offset = data.len() - reader.len();
            None
        }
    } else {
        None // No declared address
    };

    // Skip features (Scala: r.getByte() count, per feature: getByte id + getUShort len + getChunk)
    if *offset >= data.len() {
        return Err(CodecError::UnexpectedEof);
    }
    let feature_count = data[*offset] as usize;
    *offset += 1;
    for _ in 0..feature_count {
        // feature id (1 byte)
        if *offset >= data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        *offset += 1;
        // feature data length (VLQ-ushort)
        let mut reader = &data[*offset..];
        let feat_len = vlq::get_ushort(&mut reader)? as usize;
        let vlq_bytes = (data.len() - *offset) - reader.len();
        *offset += vlq_bytes;
        if *offset + feat_len > data.len() {
            return Err(CodecError::UnexpectedEof);
        }
        *offset += feat_len;
    }

    Ok(peer_addr)
}

/// Parse a Peers message body into a list of socket addresses.
///
/// Gracefully handles unknown features and missing addresses: peers
/// without a declared address are simply omitted from the result.
pub fn parse_peers(data: &[u8]) -> Result<Vec<PeerAddr>, CodecError> {
    let mut reader = data;
    let count = vlq::get_uint(&mut reader)? as usize;
    let mut offset = data.len() - reader.len();
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        if let Some(peer) = parse_one_peer(data, &mut offset)? {
            peers.push(peer);
        }
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn serialize_parse_roundtrip() {
        let addr: SocketAddr = "10.0.0.1:9030".parse().unwrap();
        let peers = vec![PeerAddr { address: addr }];
        let encoded = serialize_peers(&peers);
        let decoded = parse_peers(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].address, addr);
    }

    #[test]
    fn serialize_parse_multiple() {
        let addrs: Vec<PeerAddr> = vec![
            PeerAddr {
                address: "192.168.1.1:9030".parse().unwrap(),
            },
            PeerAddr {
                address: "10.0.0.5:9031".parse().unwrap(),
            },
            PeerAddr {
                address: "172.16.0.100:9032".parse().unwrap(),
            },
        ];
        let encoded = serialize_peers(&addrs);
        let decoded = parse_peers(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        for (original, parsed) in addrs.iter().zip(decoded.iter()) {
            assert_eq!(original.address, parsed.address);
        }
    }

    #[test]
    fn empty_peers_list() {
        let peers: Vec<PeerAddr> = vec![];
        let encoded = serialize_peers(&peers);
        // VLQ(0) = single byte 0x00
        assert_eq!(encoded, vec![0x00]);
        let decoded = parse_peers(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn parse_peer_without_address() {
        // Build a Peers body with one peer that has no declared address (option byte = 0x00)
        let mut buf = Vec::new();
        vlq::put_uint(&mut buf, 1); // count = 1
        vlq::put_short_string(&mut buf, "ergo-ref");
        buf.extend_from_slice(&[5, 0, 0]); // version
        vlq::put_short_string(&mut buf, "test");
        buf.push(0x00); // option byte: None (no declared address)
        buf.push(0); // zero features

        let decoded = parse_peers(&buf).unwrap();
        // Peer without address is skipped
        assert!(decoded.is_empty());
    }

    #[test]
    fn ipv4_address_encoding() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 9030);
        let peers = vec![PeerAddr { address: addr }];
        let encoded = serialize_peers(&peers);

        // Layout (Scala-compatible):
        //   [0]     VLQ(1) = 0x01
        //   [1]     short_string len("ergo-rust") = 0x09
        //   [2..11] "ergo-rust" (9 bytes)
        //   [11..14] version = [5, 0, 0]
        //   [14]    short_string len("node") = 0x04
        //   [15..19] "node" (4 bytes)
        //   [19]    option byte = 0x01 (Some)
        //   [20]    addr_size = 0x08 (4 IP + 4, Scala convention)
        //   [21..25] IP = [192, 168, 1, 100]
        //   [25..27] port = VLQ(9030) = [0xC6, 0x46]
        //   [27]    feature_count = 0x00

        // Verify option byte
        assert_eq!(encoded[19], 0x01);
        // Verify addr_size byte
        assert_eq!(encoded[20], 8);
        // Verify IP bytes
        assert_eq!(&encoded[21..25], &[192, 168, 1, 100]);
        // Verify port as VLQ: 9030 = [0xC6, 0x46]
        assert_eq!(&encoded[25..27], &[0xC6, 0x46]);
        // Verify feature count
        assert_eq!(encoded[27], 0);
        // Total length
        assert_eq!(encoded.len(), 28);

        // Also verify roundtrip
        let decoded = parse_peers(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].address, addr);
    }

    #[test]
    fn parse_truncated_returns_error() {
        let addr: SocketAddr = "10.0.0.1:9030".parse().unwrap();
        let peers = vec![PeerAddr { address: addr }];
        let encoded = serialize_peers(&peers);
        // Truncate the data
        let truncated = &encoded[..encoded.len() / 2];
        assert!(parse_peers(truncated).is_err());
    }

    // -----------------------------------------------------------------------
    // Scala format compliance tests
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_one_peer_has_option_byte() {
        // Verify the option byte (0x01 for Some) appears at the correct position
        let addr: SocketAddr = "10.0.0.1:9030".parse().unwrap();
        let peers = vec![PeerAddr { address: addr }];
        let encoded = serialize_peers(&peers);

        // After VLQ(1) + short_string("ergo-rust") + version(3) + short_string("node"):
        // 1 + (1+9) + 3 + (1+4) = 19 bytes
        // Byte 19 should be the option byte
        assert_eq!(
            encoded[19], 0x01,
            "option byte should be 0x01 for IPv4 address"
        );
    }

    #[test]
    fn serialize_one_peer_port_is_vlq() {
        // Verify port is VLQ-encoded, NOT 4-byte big-endian
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9030);
        let peers = vec![PeerAddr { address: addr }];
        let encoded = serialize_peers(&peers);

        // Option byte at [19], addr_size at [20], IP at [21..25], port starts at [25]
        // VLQ(9030) should be 2 bytes [0xC6, 0x46], NOT 4 bytes [0x00, 0x00, 0x23, 0x46]
        let port_bytes = &encoded[25..27];
        assert_eq!(port_bytes, &[0xC6, 0x46], "port should be VLQ-encoded");

        // Also verify it's NOT the old BE format by checking total length:
        // Old format would be 29 bytes (4-byte BE port), new format is 28 (2-byte VLQ port)
        assert_eq!(
            encoded.len(),
            28,
            "total length should reflect VLQ port encoding"
        );
    }

    #[test]
    fn serialize_one_peer_small_port_single_vlq_byte() {
        // Port < 128 should be a single VLQ byte
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80);
        let peers = vec![PeerAddr { address: addr }];
        let encoded = serialize_peers(&peers);

        // Port at [25], VLQ(80) = single byte 0x50
        assert_eq!(encoded[25], 80);
        // Feature count right after: 1 byte for port + feature_count
        assert_eq!(encoded[26], 0x00, "feature count after 1-byte VLQ port");
        assert_eq!(encoded.len(), 27, "total length with 1-byte VLQ port");
    }

    #[test]
    fn parse_scala_format_peers_message() {
        // Construct a Peers message in exact Scala wire format and verify parsing
        let mut buf = Vec::new();
        vlq::put_uint(&mut buf, 2); // count = 2

        // Peer 1: 192.168.1.1:9030, agent="ergo-scala", version=[5,0,2]
        vlq::put_short_string(&mut buf, "ergo-scala");
        buf.extend_from_slice(&[5, 0, 2]); // version
        vlq::put_short_string(&mut buf, "scala-node");
        buf.push(0x01); // option byte: Some
        buf.push(4 + 4); // addr_size = 8 (Scala convention: ip_len + 4)
        buf.extend_from_slice(&[192, 168, 1, 1]); // IPv4
        vlq::put_uint(&mut buf, 9030); // VLQ port
        buf.push(0); // 0 features

        // Peer 2: 10.0.0.5:9031, agent="ergo-ref", version=[5,0,0]
        vlq::put_short_string(&mut buf, "ergo-ref");
        buf.extend_from_slice(&[5, 0, 0]); // version
        vlq::put_short_string(&mut buf, "ref-node");
        buf.push(0x01); // option byte: Some
        buf.push(4 + 4); // addr_size = 8
        buf.extend_from_slice(&[10, 0, 0, 5]); // IPv4
        vlq::put_uint(&mut buf, 9031); // VLQ port
        buf.push(0); // 0 features

        let decoded = parse_peers(&buf).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(
            decoded[0].address,
            "192.168.1.1:9030".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            decoded[1].address,
            "10.0.0.5:9031".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_scala_format_with_features() {
        // Construct a Peers message with features (Scala format)
        let mut buf = Vec::new();
        vlq::put_uint(&mut buf, 1); // count = 1

        vlq::put_short_string(&mut buf, "ergo-scala");
        buf.extend_from_slice(&[5, 0, 2]); // version
        vlq::put_short_string(&mut buf, "node1");
        buf.push(0x01); // option byte: Some
        buf.push(4 + 4); // addr_size = 8
        buf.extend_from_slice(&[172, 16, 0, 1]); // IPv4
        vlq::put_uint(&mut buf, 9030); // VLQ port

        // 2 features
        buf.push(2);
        // Feature 1: id=3, data=[0xAB, 0xCD]
        buf.push(3); // feature id
        vlq::put_ushort(&mut buf, 2); // data length (VLQ ushort)
        buf.extend_from_slice(&[0xAB, 0xCD]); // feature data
                                              // Feature 2: id=17, data=[0x01]
        buf.push(17); // feature id
        vlq::put_ushort(&mut buf, 1); // data length
        buf.push(0x01); // feature data

        let decoded = parse_peers(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].address,
            "172.16.0.1:9030".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn roundtrip_with_new_format() {
        // Serialize with our code and parse back — full roundtrip
        let addresses = vec![
            PeerAddr {
                address: "1.2.3.4:9030".parse().unwrap(),
            },
            PeerAddr {
                address: "255.255.255.255:65535".parse().unwrap(),
            },
            PeerAddr {
                address: "127.0.0.1:1".parse().unwrap(),
            },
            PeerAddr {
                address: "10.20.30.40:80".parse().unwrap(),
            },
        ];
        let encoded = serialize_peers(&addresses);
        let decoded = parse_peers(&encoded).unwrap();
        assert_eq!(decoded.len(), addresses.len());
        for (orig, parsed) in addresses.iter().zip(decoded.iter()) {
            assert_eq!(orig.address, parsed.address);
        }
    }

    #[test]
    fn parse_peer_without_address_option_byte() {
        // Build a Peers body with one peer that has option byte 0x00 (no address)
        let mut buf = Vec::new();
        vlq::put_uint(&mut buf, 1); // count = 1
        vlq::put_short_string(&mut buf, "ergo-ref");
        buf.extend_from_slice(&[5, 0, 0]); // version
        vlq::put_short_string(&mut buf, "noaddr");
        buf.push(0x00); // option byte: None
        buf.push(0); // zero features

        let decoded = parse_peers(&buf).unwrap();
        assert!(decoded.is_empty(), "peer without address should be skipped");
    }

    #[test]
    fn mixed_peers_with_and_without_address() {
        // One peer with address, one without
        let mut buf = Vec::new();
        vlq::put_uint(&mut buf, 2); // count = 2

        // Peer 1: has address
        vlq::put_short_string(&mut buf, "ergo-rust");
        buf.extend_from_slice(&[5, 0, 0]);
        vlq::put_short_string(&mut buf, "node1");
        buf.push(0x01); // option byte: Some
        buf.push(4 + 4); // addr_size
        buf.extend_from_slice(&[192, 168, 0, 1]);
        vlq::put_uint(&mut buf, 9030);
        buf.push(0); // 0 features

        // Peer 2: no address
        vlq::put_short_string(&mut buf, "ergo-ref");
        buf.extend_from_slice(&[5, 0, 0]);
        vlq::put_short_string(&mut buf, "node2");
        buf.push(0x00); // option byte: None
        buf.push(0); // 0 features

        let decoded = parse_peers(&buf).unwrap();
        assert_eq!(
            decoded.len(),
            1,
            "only peer with address should be returned"
        );
        assert_eq!(
            decoded[0].address,
            "192.168.0.1:9030".parse::<SocketAddr>().unwrap()
        );
    }
}
