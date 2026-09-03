//! Address routability filters used by [`super::PeerManager`].
//!
//! [`is_routable_for_p2p`] is the gate for "should I dial this address
//! and should I propagate it to other peers via the Peers message?",
//! parameterised by the operator's `[peers] allow_local` (Scala's
//! `scorex.network.allowLocal`).
//! [`declared_to_socket`] parses a wire-format declared address (4
//! bytes IPv4 or 16 bytes IPv6) into a [`SocketAddr`] without the
//! IPv4-vs-IPv6 length-coercion bug a previous `try_from(...).unwrap_or([0;4])`
//! call site had (it silently turned every IPv6 address into
//! `0.0.0.0:port`, polluting the dial pool).

use std::net::{IpAddr, SocketAddr};

/// Whether an address may be dialed and gossiped.
///
/// This is the single gate for "should I dial this address and should I
/// propagate it to other peers via the `Peers` message?" Applied on
/// gossip ingest, on dial-candidate selection, on the persistence side
/// (which address a handshake is booked under), on `peers_for_sharing`
/// egress, and on the boot-time sanitisation of `peers.redb`.
///
/// Two classes of rejection:
///
/// * **Never dialable, whatever the setting** — unspecified, multicast,
///   and port 0. These are not addresses a peer can listen on.
/// * **Local-network addresses** — loopback, RFC1918 / site-local,
///   link-local, IPv6 unique-local, and carrier-grade NAT. Rejected
///   unless `allow_local` is set.
///
/// `allow_local` is the operator's `[peers] allow_local`, mirroring
/// Scala's `scorex.network.allowLocal` — default `false`
/// (`application.conf:492`) — which gates `NetworkUtils.isLocal`,
/// `isSiteLocalAddress || isLinkLocalAddress || isLoopbackAddress`
/// (`NetworkUtils.scala:31-38`). Scala consults it before storing a
/// peer (`PeerManager.scala:52-54`, `:67-70`, `:103`) and before
/// dialing one — `NetworkController.scala:337-338` refuses with
/// "Prevented attempt to connect to local peer". Left off, connecting
/// to a peer's
/// LAN-internal IP from across the internet only burns dial slots (best
/// case) or leaks the peer's internal topology (worst case): the
/// prominent symptom is one node behind a NAT advertising e.g.
/// `10.0.0.8:9030` in handshakes, which without filtering every other
/// node adds to its dial pool and retries forever. Turned on, a LAN
/// devnet forms by gossip the way it does under Scala.
///
/// Deltas from Java's classification, deliberate and both stricter:
/// 100.64.0.0/10 (carrier-grade NAT) is not `isSiteLocalAddress` and
/// fc00::/7 (IPv6 unique-local, RFC 4193) is not either — Java only
/// knows the deprecated fec0::/10 site-local form — yet neither is
/// reachable across the public internet. Both are classed local here,
/// so `allow_local` re-admits them along with everything else and a
/// LAN operator loses nothing by the extra strictness.
pub fn is_routable_for_p2p(addr: &SocketAddr, allow_local: bool) -> bool {
    // Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) down to its
    // IPv4 form before classifying it. `is_local_address`'s IPv6 arm
    // only recognises fe80::/10, fc00::/7 and fec0::/10 — an address
    // like `::ffff:10.0.0.8` matches none of those (its top segment is
    // `0`), so without this it sailed past the RFC1918 check that
    // `10.0.0.8` itself would fail, reaching the dial pool and
    // `Peers`-message egress despite being the same private host
    // (CodeRabbit #299 round 2, SSRF-class). `to_canonical` performs
    // exactly this fold via `Ipv6Addr::to_ipv4_mapped()` and otherwise
    // returns the address unchanged.
    let ip = addr.ip().to_canonical();
    if ip.is_unspecified() || ip.is_multicast() || addr.port() == 0 {
        return false;
    }
    // 255.255.255.255 is never a listening address either — it is the
    // limited-broadcast destination. Gossip that hands it out via a
    // `Peers` response would otherwise sail past every other check and
    // sit in the dial pool and `peers.redb` forever (CodeRabbit #299
    // round 2, DoS).
    if let IpAddr::V4(v4) = ip {
        if v4.is_broadcast() {
            return false;
        }
    }
    !is_local_address(&ip) || allow_local
}

/// Whether an IP belongs to a local-network class — the set
/// `[peers] allow_local` re-admits.
fn is_local_address(ip: &IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            // RFC1918 private ranges and 169.254/16 link-local, both
            // covered by std; `is_shared` (100.64/10 carrier-grade NAT)
            // is still unstable, so spell it out.
            let oct = v4.octets();
            v4.is_private() || v4.is_link_local() || (oct[0] == 100 && (64..=127).contains(&oct[1]))
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // fe80::/10 link-local, fc00::/7 unique-local (RFC4193),
            // fec0::/10 deprecated site-local (what Java's
            // `isSiteLocalAddress` matches for IPv6).
            (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfec0
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
