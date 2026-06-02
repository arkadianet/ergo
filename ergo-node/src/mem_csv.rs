//! Append-only memory observability CSV.
//!
//! Format: one row per sample, columns documented in `HEADER`. The writer
//! is intentionally synchronous and tiny — std::fs only, no async runtime,
//! no external CSV crate. Sampling cadence is set by the caller.
//!
//! The current schema layers three column groups after the original
//! per-sample block: redb cache evictions per DB, indexer status, and
//! a `/proc/self/smaps_rollup` snapshot. New columns are append-only;
//! the ordering of pre-existing columns is unchanged so older
//! summarisers still parse the leading prefix.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mem_probe::ProcStatus;
use crate::mem_smaps::SmapsRollup;

/// CSV header row. Keep in lockstep with [`format_row`] field order.
pub const HEADER: &str = "ts_ms,best_header,best_full_block,sync_phase,\
vm_rss_kb,vm_size_kb,rss_anon_kb,rss_file_kb,\
avl_cache_clean_bytes,avl_cache_capacity_bytes,avl_clean_len,avl_dirty_len,avl_read_count,\
batch_headers_len,batch_headers_bytes,batch_meta_len,\
header_index_len,header_index_est_bytes,\
last_headers_len,last_headers_bytes,\
orphan_headers_len,orphan_headers_bytes,\
pending_blocks_len,delivery_received_len,delivery_inflight_total,\
mempool_count,mempool_bytes,peer_count,known_addresses_len,\
redb_state_evictions,redb_indexer_evictions,redb_addrbook_evictions,\
indexer_indexed_height,indexer_lag,indexer_status,\
smaps_rss_kb,smaps_pss_kb,smaps_shared_clean_kb,smaps_shared_dirty_kb,\
smaps_private_clean_kb,smaps_private_dirty_kb,smaps_anonymous_kb,\
smaps_anon_huge_pages_kb,smaps_file_pmd_mapped_kb";

/// One sample of memory + chain state. All counters are point-in-time reads.
#[derive(Debug, Default, Clone)]
pub struct MemSample {
    pub ts_ms: u64,
    pub best_header: u32,
    pub best_full_block: u32,
    pub sync_phase: &'static str,
    pub proc: ProcStatus,
    pub avl_cache_clean_bytes: u64,
    pub avl_cache_capacity_bytes: u64,
    pub avl_clean_len: u64,
    pub avl_dirty_len: u64,
    pub avl_read_count: u64,
    pub batch_headers_len: u64,
    pub batch_headers_bytes: u64,
    pub batch_meta_len: u64,
    pub header_index_len: u64,
    pub header_index_est_bytes: u64,
    pub last_headers_len: u64,
    pub last_headers_bytes: u64,
    pub orphan_headers_len: u64,
    pub orphan_headers_bytes: u64,
    pub pending_blocks_len: u64,
    pub delivery_received_len: u64,
    pub delivery_inflight_total: u64,
    pub mempool_count: u64,
    pub mempool_bytes: u64,
    pub peer_count: u64,
    pub known_addresses_len: u64,
    pub redb_state_evictions: u64,
    pub redb_indexer_evictions: u64,
    pub redb_addrbook_evictions: u64,
    pub indexer_indexed_height: u64,
    pub indexer_lag: u64,
    pub indexer_status: &'static str,
    pub smaps: SmapsRollup,
}

/// Format a single CSV row. No trailing newline.
pub fn format_row(s: &MemSample) -> String {
    format!(
        "{},{},{},{},\
         {},{},{},{},\
         {},{},{},{},{},\
         {},{},{},\
         {},{},\
         {},{},\
         {},{},\
         {},{},{},\
         {},{},{},{},\
         {},{},{},\
         {},{},{},\
         {},{},{},{},\
         {},{},{},\
         {},{}",
        s.ts_ms,
        s.best_header,
        s.best_full_block,
        s.sync_phase,
        s.proc.vm_rss_kb,
        s.proc.vm_size_kb,
        s.proc.rss_anon_kb,
        s.proc.rss_file_kb,
        s.avl_cache_clean_bytes,
        s.avl_cache_capacity_bytes,
        s.avl_clean_len,
        s.avl_dirty_len,
        s.avl_read_count,
        s.batch_headers_len,
        s.batch_headers_bytes,
        s.batch_meta_len,
        s.header_index_len,
        s.header_index_est_bytes,
        s.last_headers_len,
        s.last_headers_bytes,
        s.orphan_headers_len,
        s.orphan_headers_bytes,
        s.pending_blocks_len,
        s.delivery_received_len,
        s.delivery_inflight_total,
        s.mempool_count,
        s.mempool_bytes,
        s.peer_count,
        s.known_addresses_len,
        s.redb_state_evictions,
        s.redb_indexer_evictions,
        s.redb_addrbook_evictions,
        s.indexer_indexed_height,
        s.indexer_lag,
        s.indexer_status,
        s.smaps.rss_kb,
        s.smaps.pss_kb,
        s.smaps.shared_clean_kb,
        s.smaps.shared_dirty_kb,
        s.smaps.private_clean_kb,
        s.smaps.private_dirty_kb,
        s.smaps.anonymous_kb,
        s.smaps.anon_huge_pages_kb,
        s.smaps.file_pmd_mapped_kb,
    )
}

/// Wall-clock milliseconds since the Unix epoch. Returns 0 if the system
/// clock is set before 1970 (impossible in practice).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Open the CSV file for append, writing the header row if the file is new.
/// Returns the open file handle the caller can keep across samples.
pub fn open_or_init(path: &Path) -> io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let needs_header = !path.exists()
        || std::fs::metadata(path)
            .map(|m| m.len() == 0)
            .unwrap_or(true);
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    if needs_header {
        writeln!(f, "{HEADER}")?;
    }
    Ok(f)
}

/// Append one sample row to an already-open file handle.
pub fn append_row(f: &mut std::fs::File, sample: &MemSample) -> io::Result<()> {
    writeln!(f, "{}", format_row(sample))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> MemSample {
        MemSample {
            ts_ms: 1_730_000_000_000,
            best_header: 1_771_976,
            best_full_block: 1_771_976,
            sync_phase: "AtTip",
            proc: ProcStatus {
                vm_rss_kb: 1_492_988,
                vm_size_kb: 2_625_436,
                rss_anon_kb: 1_432_156,
                rss_file_kb: 60_832,
            },
            avl_cache_clean_bytes: 900_000_000,
            avl_cache_capacity_bytes: 1_073_741_824,
            avl_clean_len: 6_500_000,
            avl_dirty_len: 12,
            avl_read_count: 4_200_000,
            batch_headers_len: 0,
            batch_headers_bytes: 0,
            batch_meta_len: 0,
            header_index_len: 1_771_977,
            header_index_est_bytes: 152_390_022,
            last_headers_len: 50,
            last_headers_bytes: 25_000,
            orphan_headers_len: 0,
            orphan_headers_bytes: 0,
            pending_blocks_len: 0,
            delivery_received_len: 1_000,
            delivery_inflight_total: 0,
            mempool_count: 7,
            mempool_bytes: 12_345,
            peer_count: 47,
            known_addresses_len: 312,
            redb_state_evictions: 0,
            redb_indexer_evictions: 612_345,
            redb_addrbook_evictions: 0,
            indexer_indexed_height: 1_771_900,
            indexer_lag: 76,
            indexer_status: "Syncing",
            smaps: SmapsRollup {
                rss_kb: 1_492_988,
                pss_kb: 700_123,
                shared_clean_kb: 80_000,
                shared_dirty_kb: 100,
                private_clean_kb: 12_888,
                private_dirty_kb: 900_000,
                anonymous_kb: 1_432_156,
                anon_huge_pages_kb: 102_400,
                file_pmd_mapped_kb: 2_048,
            },
        }
    }

    #[test]
    fn header_column_count_matches_row() {
        let row = format_row(&fixture());
        let header_cols = HEADER.split(',').count();
        let row_cols = row.split(',').count();
        assert_eq!(header_cols, row_cols, "header/row column count mismatch");
    }

    #[test]
    fn header_has_44_columns() {
        // Pin the slice-2 wire shape: any column add/remove/rename must
        // bump this number deliberately and update downstream summarisers.
        assert_eq!(HEADER.split(',').count(), 44);
    }

    #[test]
    fn row_round_trips_key_fields() {
        let s = fixture();
        let row = format_row(&s);
        let cols: Vec<&str> = row.split(',').collect();
        assert_eq!(cols[0], "1730000000000");
        assert_eq!(cols[1], "1771976");
        assert_eq!(cols[3], "AtTip");
        assert_eq!(cols[4], "1492988"); // vm_rss_kb
        assert_eq!(cols[8], "900000000"); // avl_cache_clean_bytes
        assert_eq!(cols[30], "612345"); // redb_indexer_evictions
        assert_eq!(cols[32], "1771900"); // indexer_indexed_height
        assert_eq!(cols[33], "76"); // indexer_lag
        assert_eq!(cols[34], "Syncing"); // indexer_status
        assert_eq!(cols[41], "1432156"); // smaps_anonymous_kb
    }

    #[test]
    fn open_or_init_writes_header_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.csv");
        {
            let _f = open_or_init(&path).unwrap();
        }
        {
            let _f = open_or_init(&path).unwrap();
        }
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.matches(HEADER).count(), 1);
    }
}
