//! Background storage probes, isolated from the runtime and wedge telemetry.
//!
//! Filesystem probes can hang on network mounts. A dedicated, detached thread
//! publishes complete samples so API requests and shutdown never wait for them.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;

use crate::api_bridge::HostPaths;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageSample {
    pub state_db_bytes: Option<u64>,
    pub index_db_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
}

/// Lock-free slot containing a complete sample, or nothing before the first probe.
#[derive(Default)]
pub struct LiveStorage {
    sample: ArcSwapOption<StorageSample>,
}

impl LiveStorage {
    pub fn latest(&self) -> Option<StorageSample> {
        self.sample.load().as_deref().copied()
    }

    pub fn store_sample(&self, sample: StorageSample) {
        self.sample.store(Some(Arc::new(sample)));
    }
}

/// Probe the database files and the filesystem holding the data directory.
pub fn sample(paths: &HostPaths) -> StorageSample {
    let (state_db_bytes, index_db_bytes) = db_sizes(paths);
    let (disk_free_bytes, disk_total_bytes) = disk_space(paths);
    StorageSample {
        state_db_bytes,
        index_db_bytes,
        disk_free_bytes,
        disk_total_bytes,
    }
}

/// Spawn a process-lifetime thread, sampling immediately and then every `every`.
/// Like telemetry, the thread is detached; shutdown never joins a hung probe.
pub fn spawn(paths: HostPaths, every: Duration) -> Arc<LiveStorage> {
    let live = Arc::new(LiveStorage::default());
    let writer = Arc::clone(&live);
    std::thread::Builder::new()
        .name("storage-probe".into())
        .spawn(move || loop {
            writer.store_sample(sample(&paths));
            std::thread::sleep(every);
        })
        .expect("storage-probe thread spawn");
    live
}

/// On-disk sizes of the two redb stores, read by the sampler. Plain
/// files, so the on-disk size is `metadata().len()`. The indexer
/// file is absent when `[indexer] enabled = false`, which produces
/// `None` for that half.
fn db_sizes(paths: &HostPaths) -> (Option<u64>, Option<u64>) {
    let state = std::fs::metadata(&paths.state_db).map(|m| m.len()).ok();
    let index = std::fs::metadata(&paths.index_db).map(|m| m.len()).ok();
    (state, index)
}

/// Free / total bytes on the filesystem holding the data dir — the
/// disk whose mount-point is a longest-prefix match of data_dir
/// (in case data_dir lives on a sub-mount).
///
/// On Windows, `std::fs::canonicalize` returns paths prefixed
/// with the `\\?\` extended-length namespace (e.g.
/// `\\?\C:\Users\...\ergo-data`), while sysinfo's mount points
/// come back as bare drive roots (e.g. `C:\`). `Path::starts_with`
/// compares path components, not byte prefixes, so the extended
/// namespace prefix kills the match. Strip it before comparing.
fn disk_space(paths: &HostPaths) -> (Option<u64>, Option<u64>) {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let canonical_data = std::fs::canonicalize(&paths.data_dir)
        .map(strip_extended_length_prefix)
        .unwrap_or_else(|_| paths.data_dir.clone());
    let mut best_match: Option<&sysinfo::Disk> = None;
    let mut best_len = 0usize;
    for disk in &disks {
        let mp = disk.mount_point();
        if canonical_data.starts_with(mp) && mp.as_os_str().len() > best_len {
            best_len = mp.as_os_str().len();
            best_match = Some(disk);
        }
    }
    best_match
        .map(|d| (Some(d.available_space()), Some(d.total_space())))
        .unwrap_or((None, None))
}

/// Drop the Windows `\\?\` extended-length namespace prefix from a
/// canonicalized path so it can be compared against bare drive roots
/// returned by sysinfo (e.g. `C:\`). No-op on non-Windows paths and
/// on paths that don't start with the prefix. Returned as `PathBuf`
/// so the caller can use `Path::starts_with` on it.
fn strip_extended_length_prefix(p: PathBuf) -> PathBuf {
    // The prefix is `\\?\` (four characters). Use `Path::components`
    // first so we don't accidentally rewrite a path that happens to
    // contain `?` literals later in its body.
    use std::path::{Component, Prefix};
    let mut comps = p.components();
    if let Some(Component::Prefix(prefix_comp)) = comps.next() {
        match prefix_comp.kind() {
            Prefix::VerbatimDisk(letter) => {
                // `\\?\C:\Users\...` → `C:\Users\...`
                let mut rebuilt = PathBuf::from(format!("{}:", letter as char));
                for c in comps {
                    rebuilt.push(c.as_os_str());
                }
                return rebuilt;
            }
            Prefix::Verbatim(_) | Prefix::VerbatimUNC(_, _) => {
                // Other extended-length forms (rare): fall through
                // and return the original. Disk-space match will
                // miss, but that's better than guessing wrong.
            }
            _ => {}
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn paths(dir: &std::path::Path) -> HostPaths {
        HostPaths {
            state_db: dir.join("state.redb"),
            index_db: dir.join("index.redb"),
            data_dir: dir.to_path_buf(),
        }
    }

    // ----- happy path -----

    #[test]
    fn sample_reads_db_sizes_and_disk_space() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        std::fs::write(&paths.state_db, b"redb-payload").unwrap();
        std::fs::write(&paths.index_db, [0u8; 567]).unwrap();
        let sample = sample(&paths);
        assert_eq!(sample.state_db_bytes, Some(12));
        assert_eq!(sample.index_db_bytes, Some(567));
        let free = sample
            .disk_free_bytes
            .expect("tempdir is on a mounted volume");
        let total = sample
            .disk_total_bytes
            .expect("tempdir is on a mounted volume");
        assert!(free <= total);
        assert!(total > 0);
    }

    #[test]
    fn sample_empty_file_is_some_zero() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        std::fs::File::create(&paths.state_db).unwrap();
        std::fs::File::create(&paths.index_db).unwrap();
        let sample = sample(&paths);
        assert_eq!(sample.state_db_bytes, Some(0));
        assert_eq!(sample.index_db_bytes, Some(0));
    }

    #[test]
    fn live_storage_latest_is_none_until_first_store() {
        let live = LiveStorage::default();
        assert_eq!(live.latest(), None);
        let first = StorageSample {
            state_db_bytes: Some(12),
            index_db_bytes: None,
            disk_free_bytes: Some(100),
            disk_total_bytes: Some(200),
        };
        live.store_sample(first);
        assert_eq!(live.latest(), Some(first));
        let next = StorageSample {
            state_db_bytes: Some(24),
            index_db_bytes: Some(0),
            disk_free_bytes: Some(88),
            disk_total_bytes: Some(200),
        };
        live.store_sample(next);
        assert_eq!(live.latest(), Some(next));
    }

    // ----- error paths -----

    #[test]
    fn sample_missing_files_are_none() {
        let dir = tempfile::tempdir().unwrap();
        let sample = sample(&paths(dir.path()));
        assert_eq!(sample.state_db_bytes, None);
        assert_eq!(sample.index_db_bytes, None);
    }

    #[test]
    fn sample_index_db_disabled_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        std::fs::write(&paths.state_db, b"x").unwrap();
        let sample = sample(&paths);
        assert_eq!(sample.state_db_bytes, Some(1));
        assert_eq!(sample.index_db_bytes, None);
    }
}
