//! Helpers shared by the `observer` and `crawler` binaries: peer-list
//! parsing, local-address detection, and clock-offset resolution.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;

/// Loopback, private, link-local, unspecified, broadcast, and ULA: not
/// dialable from a public vantage, or lab-only.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

/// Parse and de-duplicate a raw peer list. An empty list falls back to
/// `fallback` (usually the network's seed list).
pub fn parse_peer_list(
    raw: Vec<String>,
    fallback: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, String> {
    if raw.is_empty() {
        return Ok(fallback);
    }
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let addr: SocketAddr = item
            .parse()
            .map_err(|e| format!("peer {item:?} is not host:port: {e}"))?;
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

/// Read a peer list file: one `host:port` per line, `#` comments, blank
/// lines ignored.
pub fn read_peer_file(path: &std::path::Path) -> Result<Vec<String>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

/// Best-effort clock offset. `chronyc tracking` reports the system clock's
/// error against NTP; we record `true - local` in milliseconds.
pub fn resolve_clock(offset_ms: f64, source: &str) -> (f64, String) {
    if source != "chrony" {
        return (offset_ms, source.to_string());
    }
    match query_chrony() {
        Some(offset) => (offset, "chrony".to_string()),
        None => (offset_ms, "unset".to_string()),
    }
}

/// `chronyc tracking` → the "System time ... seconds slow/fast of NTP
/// time" field as a signed millisecond offset (true minus local).
pub fn query_chrony() -> Option<f64> {
    let output = Command::new("chronyc").arg("tracking").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("System time") else {
            continue;
        };
        let rest = rest.trim_start_matches([' ', ':']).trim();
        let mut parts = rest.split_whitespace();
        let value: f64 = parts.next()?.parse().ok()?;
        // "0.000000123 seconds slow of NTP time" → local is behind true.
        let slow = rest.contains("slow");
        let signed = if slow { value } else { -value };
        return Some(signed * 1000.0);
    }
    None
}

/// Parse a 4- or 16-byte big-endian address octet string plus port into a
/// `SocketAddr`. Used for lab fixtures that build `PeerSpec` addresses
/// from raw octets.
pub fn octets_to_socket(octets: &[u8], port: u32) -> Option<SocketAddr> {
    let ip = match octets.len() {
        4 => IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
        16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(octets);
            IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(bytes)))
        }
        _ => return None,
    };
    if port == 0 || port > u16::MAX as u32 {
        return None;
    }
    Some(SocketAddr::new(ip, port as u16))
}
