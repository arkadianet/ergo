//! Init-time memory markers.
//!
//! Writes one row to a sidecar CSV `<ERGO_MEM_CSV-stem>.markers.csv`
//! every time `record_init_marker(...)` is called. Cardinality is small
//! (~10–20 rows per node start) — these are explicit attribution
//! checkpoints inside `run_inner`, complementing the per-tick boot
//! sampler.
//!
//! Each marker captures:
//!   - label (which init step)
//!   - ts_ms
//!   - `/proc/self/status` (VmRSS, VmSize, RssAnon, RssFile)
//!   - `/proc/self/smaps_rollup` (Pss, Private_Dirty, Anonymous, ...)
//!   - optional `/proc/self/maps` category summary, gated by
//!     `ERGO_MEM_MAPS=1` (off by default — full maps parse is O(N))
//!
//! No-op when `ERGO_MEM_CSV` is unset. Latches off after a permanent
//! write failure, mirroring the action-loop sampler's recovery model.
//!
//! Failure mode is intentionally silent past the first `eprintln!`:
//! observability MUST NOT block boot.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::mem_maps::read_maps_summary;
use crate::mem_probe::{read_proc_status, ProcStatus};
use crate::mem_smaps::{read_smaps_rollup, SmapsRollup};

const HEADER: &str = "ts_ms,label,vm_rss_kb,vm_size_kb,rss_anon_kb,rss_file_kb,\
smaps_rss_kb,smaps_pss_kb,smaps_shared_clean_kb,smaps_shared_dirty_kb,\
smaps_private_clean_kb,smaps_private_dirty_kb,smaps_anonymous_kb,\
smaps_anon_huge_pages_kb,smaps_file_pmd_mapped_kb,maps_summary";

/// Per-process state for the marker sink.
struct MarkerState {
    /// `None` after a permanent write failure or when initialisation
    /// failed — once latched, all subsequent calls are no-ops.
    sink: Option<MarkerSink>,
}

/// Open file + bookkeeping for a single markers CSV.
struct MarkerSink {
    file: File,
    /// Whether `ERGO_MEM_MAPS=1` is set — read once at construction so
    /// flipping it mid-run doesn't half-fill the column.
    maps_enabled: bool,
}

static MARKER_STATE: OnceLock<Mutex<MarkerState>> = OnceLock::new();

/// Append one marker row. No-op when `ERGO_MEM_CSV` is unset or when
/// the sink has latched off after a prior permanent failure.
///
/// Best-effort: errors are reported once via `eprintln!` and silenced
/// thereafter so the caller's hot path isn't cluttered.
pub fn record_init_marker(label: &'static str) {
    let mu = MARKER_STATE.get_or_init(|| Mutex::new(MarkerState { sink: init_sink() }));
    // PoisonError just means a previous panic happened with the lock
    // held; the data inside is still valid for our append-only schema,
    // so unwrap-the-poison and proceed.
    let mut state = match mu.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let Some(ref mut sink) = state.sink else {
        return;
    };
    if let Err(e) = append_row(sink, label) {
        warn!(error = %e, "marker append failed — disabling markers for this run");
        state.sink = None;
    }
}

fn init_sink() -> Option<MarkerSink> {
    let csv_path: PathBuf = std::env::var_os("ERGO_MEM_CSV").map(PathBuf::from)?;
    let markers_path = derive_markers_path(&csv_path);
    let maps_enabled = std::env::var_os("ERGO_MEM_MAPS")
        .map(|v| v == "1")
        .unwrap_or(false);
    match open_markers_file(&markers_path) {
        Ok(file) => Some(MarkerSink { file, maps_enabled }),
        Err(e) => {
            warn!(
                error = %e,
                path = %markers_path.display(),
                "marker open failed — markers disabled for this run",
            );
            None
        }
    }
}

/// Convert `<dir>/<stem>.<ext>` → `<dir>/<stem>.markers.csv`.
/// If the input has no extension, append `.markers.csv` directly.
pub(crate) fn derive_markers_path(csv_path: &Path) -> PathBuf {
    let parent = csv_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = csv_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "memory".to_string());
    parent.join(format!("{stem}.markers.csv"))
}

fn open_markers_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // Try to create the file fresh first (writes header on success);
    // if it already exists from a prior run with the same path, append
    // without re-emitting the header — UNLESS the existing file is
    // zero bytes (typical signature of a prior crash mid-create that
    // got the inode but no header), in which case treat it as fresh
    // and write the header. Blindly appending to an empty file
    // produces an unparseable CSV. We do not attempt
    // the full `mem_csv::adopt_or_repair_existing` machinery — markers
    // are sidecar single-process observability with very low cardinality
    // (~14 rows per boot), so the extra surface isn't justified. The
    // empty-file case is the only realistic corruption mode for a sink
    // that's only ever opened by `record_init_marker` inside `run_inner`.
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .append(true)
        .open(path)
    {
        Ok(mut f) => {
            f.write_all(HEADER.as_bytes())?;
            f.write_all(b"\n")?;
            Ok(f)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let mut f = OpenOptions::new().append(true).open(path)?;
            if f.metadata()?.len() == 0 {
                f.write_all(HEADER.as_bytes())?;
                f.write_all(b"\n")?;
            }
            Ok(f)
        }
        Err(e) => Err(e),
    }
}

fn append_row(sink: &mut MarkerSink, label: &'static str) -> io::Result<()> {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let proc = read_proc_status().unwrap_or_default();
    let smaps = read_smaps_rollup().unwrap_or_default();
    let maps_summary = if sink.maps_enabled {
        read_maps_summary().unwrap_or_default().format_compact()
    } else {
        String::new()
    };
    let row = format_row(ts_ms, label, &proc, &smaps, &maps_summary);
    sink.file.write_all(row.as_bytes())?;
    sink.file.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn format_row(
    ts_ms: u64,
    label: &str,
    proc: &ProcStatus,
    smaps: &SmapsRollup,
    maps_summary: &str,
) -> String {
    format!(
        "{ts_ms},{label},{vm_rss},{vm_size},{rss_anon},{rss_file},\
         {srss},{spss},{ssc},{ssd},{spc},{spd},{anon},{ahp},{fpm},{maps}",
        vm_rss = proc.vm_rss_kb,
        vm_size = proc.vm_size_kb,
        rss_anon = proc.rss_anon_kb,
        rss_file = proc.rss_file_kb,
        srss = smaps.rss_kb,
        spss = smaps.pss_kb,
        ssc = smaps.shared_clean_kb,
        ssd = smaps.shared_dirty_kb,
        spc = smaps.private_clean_kb,
        spd = smaps.private_dirty_kb,
        anon = smaps.anonymous_kb,
        ahp = smaps.anon_huge_pages_kb,
        fpm = smaps.file_pmd_mapped_kb,
        maps = maps_summary,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn derives_markers_path_with_csv_extension() {
        let p = PathBuf::from("logs/memory-resume-p25-X.csv");
        assert_eq!(
            derive_markers_path(&p),
            PathBuf::from("logs/memory-resume-p25-X.markers.csv")
        );
    }

    #[test]
    fn derives_markers_path_without_extension() {
        let p = PathBuf::from("logs/mem");
        assert_eq!(
            derive_markers_path(&p),
            PathBuf::from("logs/mem.markers.csv")
        );
    }

    #[test]
    fn derives_markers_path_with_no_parent() {
        let p = PathBuf::from("mem.csv");
        assert_eq!(derive_markers_path(&p), PathBuf::from("mem.markers.csv"));
    }

    #[test]
    fn format_row_emits_expected_columns() {
        let proc = ProcStatus {
            vm_rss_kb: 100,
            vm_size_kb: 200,
            rss_anon_kb: 90,
            rss_file_kb: 10,
        };
        let smaps = SmapsRollup {
            rss_kb: 100,
            pss_kb: 50,
            shared_clean_kb: 5,
            shared_dirty_kb: 0,
            private_clean_kb: 10,
            private_dirty_kb: 80,
            anonymous_kb: 90,
            anon_huge_pages_kb: 0,
            file_pmd_mapped_kb: 0,
        };
        let row = format_row(123, "init/begin", &proc, &smaps, "");
        let cols: Vec<&str> = row.split(',').collect();
        assert_eq!(cols.len(), 16);
        assert_eq!(cols[0], "123");
        assert_eq!(cols[1], "init/begin");
        assert_eq!(cols[2], "100"); // vm_rss_kb
        assert_eq!(cols[6], "100"); // smaps_rss_kb
        assert_eq!(cols[11], "80"); // smaps_private_dirty_kb
        assert_eq!(cols[12], "90"); // smaps_anonymous_kb
        assert_eq!(cols[15], ""); // empty maps_summary
    }

    #[test]
    fn format_row_passes_through_maps_summary_as_single_field() {
        let proc = ProcStatus::default();
        let smaps = SmapsRollup::default();
        let summary = "heap=12kb anon=234kb redb=345kb so=12kb bin=2kb stack=1kb other=4kb";
        let row = format_row(0, "init/done", &proc, &smaps, summary);
        // 15 commas separate 16 fields; the maps_summary contains
        // spaces and `=` but no commas, so it stays a single field.
        let cols: Vec<&str> = row.split(',').collect();
        assert_eq!(cols.len(), 16);
        assert_eq!(cols[15], summary);
    }

    /// Zero-byte file from a prior crash should be treated as fresh,
    /// not blindly appended to. Verifies the empty-file repair path
    /// inside `open_markers_file`.
    #[test]
    fn open_markers_file_writes_header_when_existing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.markers.csv");
        // Simulate the post-crash state: file exists but is zero bytes.
        std::fs::File::create(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);

        let mut f = open_markers_file(&path).unwrap();
        f.write_all(b"row1,a,1,2,3,4,5,6,7,8,9,10,11,12,13,\n").unwrap();
        drop(f);

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "header + 1 row, got: {body:?}");
        assert_eq!(lines[0], HEADER);
        assert!(lines[1].starts_with("row1"));
    }

    #[test]
    fn open_markers_file_writes_header_then_appends_without_duplication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.markers.csv");

        // First open: fresh creator → writes header.
        {
            let mut f = open_markers_file(&path).unwrap();
            f.write_all(b"row1,a,1,2,3,4,5,6,7,8,9,10,11,12,13,\n").unwrap();
        }

        // Second open: file exists → no header re-emission.
        {
            let mut f = open_markers_file(&path).unwrap();
            f.write_all(b"row2,b,1,2,3,4,5,6,7,8,9,10,11,12,13,\n").unwrap();
        }

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 rows, got: {body:?}");
        assert_eq!(lines[0], HEADER);
        assert!(lines[1].starts_with("row1"));
        assert!(lines[2].starts_with("row2"));
    }
}
