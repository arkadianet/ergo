//! Address routability filters used by [`super::PeerManager`].
//!
//! [`is_routable_for_p2p`] is the gate for "should I dial this address
//! and should I propagate it to other peers via the Peers message?"
//! [`declared_to_socket`] parses a wire-format declared address (4
//! bytes IPv4 or 16 bytes IPv6) into a [`SocketAddr`] without the
//! IPv4-vs-IPv6 length-coercion bug a previous `try_from(...).unwrap_or([0;4])`
//! call site had (it silently turned every IPv6 address into
//! `0.0.0.0:port`, polluting the dial pool).

use std::net::{IpAddr, SocketAddr};

/// Whether an address is plausibly routable for peer-to-peer dial /
/// gossip on the public internet. Filters out addresses we cannot
/// usefully attempt and that we must not propagate to other peers via
/// `peers_for_sharing` — chiefly RFC1918, loopback, link-local,
/// multicast, and unspecified addresses.
///
/// Mirrors the practical effect of the Scala node's "should I dial
/// this" gate: connecting to a peer's LAN-internal IP from across the
/// internet only burns dial slots (best case) or leaks the peer's
/// internal topology (worst case). The most prominent symptom is one
/// node behind a NAT advertising e.g. `10.0.0.8:9030` in handshakes;
/// without filtering, every other peer in the network adds it to its
/// dial pool and tries it on every dial cycle.
pub fn is_routable_for_p2p(addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if addr.port() == 0 {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            // RFC1918 private ranges
            if v4.is_private() {
                return false;
            }
            // 169.254/16 link-local; the std method covers it.
            if v4.is_link_local() {
                return false;
            }
            // 0.0.0.0/8 covered by is_unspecified above for 0.0.0.0
            // exactly; stricter "0.0.0.0/8" rejection isn't required.
            // 100.64/10 carrier-grade NAT — not is_private, but never
            // routable across the public internet either. The std lib
            // only marks it as "shared address space" via the unstable
            // `is_shared` method, so check explicitly.
            let oct = v4.octets();
            if oct[0] == 100 && (64..=127).contains(&oct[1]) {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            // fe80::/10 link-local
            let segs = v6.segments();
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            // fc00::/7 unique local addresses (RFC4193) — private LAN
            if (segs[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            true
        }
    }
}

/// Parse a declared address (4 bytes IPv4 or 16 bytes IPv6) into a
/// [`SocketAddr`]. Returns `None` for malformed addresses (any other
/// length). Used by Peers-message ingress and by `peers_for_sharing`
/// egress to keep IPv4/IPv6 handling consistent.
pub fn declared_to_socket(declared: &crate::handshake::DeclaredAddress) -> Option<SocketAddr> {
    let port = u16::try_from(declared.port).ok()?;
    match declared.addr.len() {
        4 => {
            let octets: [u8; 4] = declared.addr.as_slice().try_into().ok()?;
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        16 => {
            let octets: [u8; 16] = declared.addr.as_slice().try_into().ok()?;
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        _ => None,
    }
}
