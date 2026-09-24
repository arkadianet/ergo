use std::str::FromStr;

use ergo_api::types::ApiRecentBlock;
use ergo_api_core::id::HeaderId;
use ergo_api_core::observability::{RecentBlockRecord, RecentBlockSource, MAX_RECENT_BLOCK_COUNT};

use super::SnapshotReadState;

fn convert(block: &ApiRecentBlock) -> Option<RecentBlockRecord> {
    Some(RecentBlockRecord {
        height: block.height,
        header_id: HeaderId::from_str(&block.header_id).ok()?,
        timestamp_unix_ms: block.ts_unix_ms,
        transaction_count: block.txs,
        size_bytes: block.size_bytes,
        delivered_by: block
            .delivered_by
            .as_deref()
            .and_then(|value| value.parse().ok()),
        miner_public_key: block
            .miner_pk
            .as_deref()
            .and_then(|value| hex::decode(value).ok())
            .and_then(|value| value.try_into().ok()),
        miner_address: block.miner_address.clone(),
    })
}

fn convert_recent_blocks(blocks: &[ApiRecentBlock], count: u32) -> Vec<RecentBlockRecord> {
    let count = count.clamp(1, MAX_RECENT_BLOCK_COUNT) as usize;
    blocks.iter().take(count).filter_map(convert).collect()
}

impl RecentBlockSource for SnapshotReadState {
    fn recent_blocks(&self, count: u32) -> Vec<RecentBlockRecord> {
        convert_recent_blocks(&self.handle.load().recent_blocks, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_snapshot_tail_without_reordering_or_dropping_fields() {
        let blocks = vec![
            ApiRecentBlock {
                height: 12,
                header_id: hex::encode([12; 32]),
                ts_unix_ms: 1_700_000_000_012,
                txs: 3,
                size_bytes: 4_096,
                delivered_by: Some("203.0.113.7:9030".to_string()),
                miner_pk: Some(hex::encode([2; 33])),
                miner_address: Some("miner-address".to_string()),
            },
            ApiRecentBlock {
                height: 11,
                header_id: hex::encode([11; 32]),
                ts_unix_ms: 1_700_000_000_011,
                txs: 2,
                size_bytes: 3_072,
                delivered_by: None,
                miner_pk: None,
                miner_address: None,
            },
        ];

        let converted = convert_recent_blocks(&blocks, 2);

        assert_eq!(converted[0].header_id, HeaderId::from_bytes([12; 32]));
        assert_eq!(converted[1].header_id, HeaderId::from_bytes([11; 32]));
        assert_eq!(converted[0].timestamp_unix_ms, 1_700_000_000_012);
        assert_eq!(converted[0].transaction_count, 3);
        assert_eq!(converted[0].size_bytes, 4_096);
        assert_eq!(
            converted[0].delivered_by,
            Some("203.0.113.7:9030".parse().unwrap())
        );
        assert_eq!(converted[0].miner_public_key, Some([2; 33]));
        assert_eq!(converted[0].miner_address.as_deref(), Some("miner-address"));
        assert_eq!(converted[1].delivered_by, None);
        assert_eq!(converted[1].miner_public_key, None);
        assert_eq!(converted[1].miner_address, None);
    }

    #[test]
    fn bounds_snapshot_conversion_to_thirty_two() {
        let blocks = (0..40)
            .map(|height| ApiRecentBlock {
                height,
                header_id: hex::encode([height as u8; 32]),
                ts_unix_ms: height as u64,
                txs: 0,
                size_bytes: 0,
                delivered_by: None,
                miner_pk: None,
                miner_address: None,
            })
            .collect::<Vec<_>>();

        assert_eq!(convert_recent_blocks(&blocks, 100).len(), 32);
        assert_eq!(convert_recent_blocks(&blocks, 0).len(), 1);
    }
}
