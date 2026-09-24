use std::net::SocketAddr;

use crate::id::HeaderId;

pub const DEFAULT_RECENT_BLOCK_COUNT: u32 = 10;
pub const MAX_RECENT_BLOCK_COUNT: u32 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentBlockRecord {
    pub height: u32,
    pub header_id: HeaderId,
    pub timestamp_unix_ms: u64,
    pub transaction_count: u32,
    pub size_bytes: u64,
    pub delivered_by: Option<SocketAddr>,
    pub miner_public_key: Option<[u8; 33]>,
    pub miner_address: Option<String>,
}

pub trait RecentBlockSource: Send + Sync + 'static {
    fn recent_blocks(&self, count: u32) -> Vec<RecentBlockRecord>;
}
