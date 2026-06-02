//! Byte codec + on-disk schema for [`super::AddressBook`].
//!
//! Public types ([`super::PersistedPeer`], [`super::BanRecord`],
//! [`super::LastDirection`]) live in the parent module so the public
//! API surface stays where downstream callers expect it; this module
//! holds the wire-format encode/decode functions, the schema tag and
//! flag constants, the address/IP key formats used for the redb
//! tables, and the small `Cursor` helper.
//!
//! Everything here is `pub(super)` — the parent's `impl AddressBook`
//! is the only intended consumer.
//!
//! Schema is versioned via [`super::SCHEMA_VERSION`] in the META
//! table. Bumping any tag, flag, or field width is a schema change
//! and the version must move with it.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{BanRecord, LastDirection, PersistedPeer};
use crate::peer_manager::PeerOrigin;

// ---- Schema tags ----

pub(super) const SCHEMA_TAG_PEER: u8 = 0x01;
pub(super) const SCHEMA_TAG_BAN: u8 = 0x01;

// ---- Address-key kinds ----

pub(super) const KIND_IPV4: u8 = 0x04;
pub(super) const KIND_IPV6: u8 = 0x06;

// ---- Flag bits ----

pub(super) const FLAG_HANDSHAKED: u8 = 0x01;
pub(super) const FLAG_FROM_SEED: u8 = 0x02;
pub(super) const FLAG_LAST_DIR_INBOUND: u8 = 0x04;

// ---- Limits ----

pub(super) const MAX_NAME_LEN: usize = 256;

// ---- Address keys ----

pub(super) fn encode_addr_key(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(KIND_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(KIND_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

pub(super) fn decode_addr_key(bytes: &[u8]) -> Option<SocketAddr> {
    let kind = *bytes.first()?;
    match kind {
        KIND_IPV4 if bytes.len() == 7 => {
            let octets: [u8; 4] = bytes[1..5].try_into().ok()?;
            let port = u16::from_be_bytes(bytes[5..7].try_into().ok()?);
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        KIND_IPV6 if bytes.len() == 19 => {
            let octets: [u8; 16] = bytes[1..17].try_into().ok()?;
            let port = u16::from_be_bytes(bytes[17..19].try_into().ok()?);
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        _ => None,
    }
}

pub(super) fn encode_ip_key(ip: IpAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    match ip {
        IpAddr::V4(v4) => {
            out.push(KIND_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(KIND_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out
}

pub(super) fn decode_ip_key(bytes: &[u8]) -> Option<IpAddr> {
    let kind = *bytes.first()?;
    match kind {
        KIND_IPV4 if bytes.len() == 5 => {
            let octets: [u8; 4] = bytes[1..5].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        KIND_IPV6 if bytes.len() == 17 => {
            let octets: [u8; 16] = bytes[1..17].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

// ---- Time codecs ----

pub(super) fn unix_secs(t: Option<SystemTime>) -> u64 {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(super) fn from_unix_secs(secs: u64) -> Option<SystemTime> {
    if secs == 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

// ---- Persisted peer codec ----

pub(super) fn encode_persisted_peer(p: &PersistedPeer) -> Vec<u8> {
    let agent = p.agent_name.as_bytes();
    let node = p.node_name.as_bytes();
    let agent_len = agent.len().min(MAX_NAME_LEN);
    let node_len = node.len().min(MAX_NAME_LEN);

    let mut flags = 0u8;
    if p.handshaked {
        flags |= FLAG_HANDSHAKED;
    }
    if p.origin.is_seed() {
        flags |= FLAG_FROM_SEED;
    }
    if matches!(p.last_direction, Some(LastDirection::Inbound)) {
        flags |= FLAG_LAST_DIR_INBOUND;
    }

    let mut out = Vec::with_capacity(40 + agent_len + node_len);
    out.push(SCHEMA_TAG_PEER);
    out.extend_from_slice(&unix_secs(p.last_handshake).to_be_bytes());
    out.extend_from_slice(&unix_secs(p.last_seen).to_be_bytes());
    out.extend_from_slice(&unix_secs(p.last_failure).to_be_bytes());
    out.extend_from_slice(&p.consecutive_failures.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&p.agent_version);
    out.extend_from_slice(&(agent_len as u16).to_be_bytes());
    out.extend_from_slice(&agent[..agent_len]);
    out.extend_from_slice(&(node_len as u16).to_be_bytes());
    out.extend_from_slice(&node[..node_len]);
    out
}

#[derive(Debug)]
pub(super) struct DecodeError;

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decode error")
    }
}

pub(super) fn decode_persisted_peer(
    addr: SocketAddr,
    bytes: &[u8],
) -> Result<PersistedPeer, DecodeError> {
    let mut r = Cursor { buf: bytes, pos: 0 };
    let tag = r.read_u8().ok_or(DecodeError)?;
    if tag != SCHEMA_TAG_PEER {
        return Err(DecodeError);
    }
    let last_handshake = from_unix_secs(r.read_u64().ok_or(DecodeError)?);
    let last_seen = from_unix_secs(r.read_u64().ok_or(DecodeError)?);
    let last_failure = from_unix_secs(r.read_u64().ok_or(DecodeError)?);
    let consecutive_failures = r.read_u32().ok_or(DecodeError)?;
    let flags = r.read_u8().ok_or(DecodeError)?;
    let agent_version: [u8; 3] = r.read_bytes(3).ok_or(DecodeError)?.try_into().unwrap();
    let agent_len = r.read_u16().ok_or(DecodeError)? as usize;
    if agent_len > MAX_NAME_LEN {
        return Err(DecodeError);
    }
    let agent = r.read_bytes(agent_len).ok_or(DecodeError)?;
    let node_len = r.read_u16().ok_or(DecodeError)? as usize;
    if node_len > MAX_NAME_LEN {
        return Err(DecodeError);
    }
    let node = r.read_bytes(node_len).ok_or(DecodeError)?;

    let agent_name = String::from_utf8(agent.to_vec()).map_err(|_| DecodeError)?;
    let node_name = String::from_utf8(node.to_vec()).map_err(|_| DecodeError)?;

    Ok(PersistedPeer {
        addr,
        last_handshake,
        last_seen,
        last_failure,
        consecutive_failures,
        origin: if flags & FLAG_FROM_SEED != 0 {
            PeerOrigin::Seed
        } else {
            PeerOrigin::Gossip
        },
        handshaked: flags & FLAG_HANDSHAKED != 0,
        last_direction: if flags & FLAG_HANDSHAKED == 0 {
            None
        } else if flags & FLAG_LAST_DIR_INBOUND != 0 {
            Some(LastDirection::Inbound)
        } else {
            Some(LastDirection::Outbound)
        },
        agent_name,
        agent_version,
        node_name,
    })
}

// ---- Ban codec ----

pub(super) fn encode_ban(b: &BanRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(14);
    out.push(SCHEMA_TAG_BAN);
    out.extend_from_slice(&unix_secs(Some(b.until)).to_be_bytes());
    out.extend_from_slice(&b.count.to_be_bytes());
    out.push(if b.permanent { 1 } else { 0 });
    out
}

pub(super) fn decode_ban(ip: IpAddr, bytes: &[u8]) -> Result<BanRecord, DecodeError> {
    let mut r = Cursor { buf: bytes, pos: 0 };
    let tag = r.read_u8().ok_or(DecodeError)?;
    if tag != SCHEMA_TAG_BAN {
        return Err(DecodeError);
    }
    let until_secs = r.read_u64().ok_or(DecodeError)?;
    let count = r.read_u32().ok_or(DecodeError)?;
    let permanent_byte = r.read_u8().ok_or(DecodeError)?;
    Ok(BanRecord {
        ip,
        until: UNIX_EPOCH + Duration::from_secs(until_secs),
        count,
        permanent: permanent_byte != 0,
    })
}

// ---- Name clamping ----

pub(super) fn clamp_name(s: &str) -> String {
    if s.len() <= MAX_NAME_LEN {
        return s.to_string();
    }
    let mut end = MAX_NAME_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// ---- Tiny byte cursor used by the decoders above ----

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_u16(&mut self) -> Option<u16> {
        let bytes: [u8; 2] = self.read_bytes(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }
    fn read_u32(&mut self) -> Option<u32> {
        let bytes: [u8; 4] = self.read_bytes(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
    fn read_u64(&mut self) -> Option<u64> {
        let bytes: [u8; 8] = self.read_bytes(8)?.try_into().ok()?;
        Some(u64::from_be_bytes(bytes))
    }
    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
}
