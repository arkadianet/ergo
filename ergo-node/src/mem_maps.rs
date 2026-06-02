//! `/proc/self/maps` category summary for memory observability.
//!
//! Bucket the process's virtual mappings into rough categories so the
//! operator can answer: "is the 4.8 GB plateau heap, anonymous mmap,
//! redb file mapping, or library text?" Used by the init markers
//! (`mem_marker`) when `ERGO_MEM_MAPS=1`. Disabled by default because
//! the parse is O(N) in mapping count (~hundreds on a healthy node)
//! and we don't need it on every sampler tick — only at boot markers.

use std::path::Path;

/// Per-category byte totals (sum of `end - start` across all matching
/// mappings). All fields are in **bytes**, not kB, so the caller can
/// surface them at whatever resolution they want.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MapsSummary {
    pub heap_bytes: u64,
    pub stack_bytes: u64,
    pub anon_bytes: u64,
    pub redb_bytes: u64,
    pub so_bytes: u64,
    pub bin_bytes: u64,
    pub other_bytes: u64,
}

impl MapsSummary {
    /// Compact one-field-per-category formatting in **kB** for the
    /// markers CSV. Single line, space-separated, no embedded commas
    /// (so it stays a single CSV field without quoting).
    ///
    /// Example:
    /// `heap=12345kb anon=234567kb redb=345678kb so=12345kb bin=2048kb stack=132kb other=4567kb`
    pub fn format_compact(&self) -> String {
        format!(
            "heap={}kb anon={}kb redb={}kb so={}kb bin={}kb stack={}kb other={}kb",
            self.heap_bytes / 1024,
            self.anon_bytes / 1024,
            self.redb_bytes / 1024,
            self.so_bytes / 1024,
            self.bin_bytes / 1024,
            self.stack_bytes / 1024,
            self.other_bytes / 1024,
        )
    }
}

#[cfg(target_os = "linux")]
pub fn read_maps_summary() -> Option<MapsSummary> {
    let text = std::fs::read_to_string("/proc/self/maps").ok()?;
    let exe = std::env::current_exe().ok();
    Some(parse_maps_summary(&text, exe.as_deref()))
}

#[cfg(not(target_os = "linux"))]
pub fn read_maps_summary() -> Option<MapsSummary> {
    None
}

pub(crate) fn parse_maps_summary(text: &str, exe: Option<&Path>) -> MapsSummary {
    let mut s = MapsSummary::default();
    let exe_str: Option<&str> = exe.and_then(|p| p.to_str());

    for line in text.lines() {
        let Some(size) = parse_line_size(line) else {
            continue;
        };
        let path = pathname_part(line);
        match categorise(path, exe_str) {
            Category::Heap => s.heap_bytes += size,
            Category::Stack => s.stack_bytes += size,
            Category::Anon => s.anon_bytes += size,
            Category::Redb => s.redb_bytes += size,
            Category::So => s.so_bytes += size,
            Category::Bin => s.bin_bytes += size,
            Category::Other => s.other_bytes += size,
        }
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    Heap,
    Stack,
    Anon,
    Redb,
    So,
    Bin,
    Other,
}

fn pathname_part(line: &str) -> &str {
    // `/proc/self/maps` columns: addr perms offset dev inode pathname
    // The pathname column may be absent (empty) or contain spaces in
    // theory, but in practice the kernel emits it as a single token
    // followed by trailing whitespace. Splitting on whitespace and
    // taking the 6th field is reliable on every Linux we care about.
    line.split_whitespace().nth(5).unwrap_or("")
}

fn parse_line_size(line: &str) -> Option<u64> {
    let addr = line.split_whitespace().next()?;
    let (start, end) = addr.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    end.checked_sub(start)
}

fn categorise(path: &str, exe: Option<&str>) -> Category {
    if path.is_empty() {
        return Category::Anon;
    }
    if path == "[heap]" {
        return Category::Heap;
    }
    if path == "[stack]" || path.starts_with("[stack:") {
        return Category::Stack;
    }
    // [anon:...], [anon_shmem], [vvar], [vvar_vclock] → anonymous-ish.
    // [vdso] and [vsyscall] are technically kernel-mapped code; classify
    // them as `so` since they behave as shared executable text.
    if path == "[vdso]" || path == "[vsyscall]" {
        return Category::So;
    }
    if path.starts_with('[') {
        return Category::Anon;
    }
    if let Some(exe) = exe {
        if path == exe {
            return Category::Bin;
        }
    }
    if is_shared_object(path) {
        return Category::So;
    }
    if path.ends_with(".redb") {
        return Category::Redb;
    }
    Category::Other
}

fn is_shared_object(path: &str) -> bool {
    // Match `*.so` and `*.so.NN` (ld.so style) anywhere in the basename.
    // We test the basename specifically so a path like
    // `/opt/foo.so.bar/data` doesn't false-positive.
    let base = match path.rsplit_once('/') {
        Some((_, b)) => b,
        None => path,
    };
    if base.ends_with(".so") {
        return true;
    }
    // Match `.so.<digits>(.<digits>)*` suffix
    if let Some(idx) = base.find(".so.") {
        let tail = &base[idx + 4..];
        return !tail.is_empty()
            && tail.chars().all(|c| c.is_ascii_digit() || c == '.');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Each address span is hand-picked so `end - start` matches the
    // size asserted below. Don't rebalance one without the other.
    const SAMPLE: &str = "\
55a5b0000000-55a5b0100000 r--p 00000000 fd:01 11 /home/user/ergo-node
55a5b0100000-55a5b0200000 r-xp 00100000 fd:01 11 /home/user/ergo-node
55a5b0200000-55a5b0300000 r--p 00200000 fd:01 11 /home/user/ergo-node
7f1234500000-7f1234600000 r--p 00000000 fd:01 22 /usr/lib/libc.so.6
7f1234600000-7f1234700000 r-xp 00100000 fd:01 22 /usr/lib/libc.so.6
7f5600000000-7f5700000000 r--p 00000000 fd:01 33 /home/user/data/state.redb
7f9a00000000-7f9b00000000 rw-p 00000000 00:00 0
7ffd12345000-7ffd12366000 rw-p 00000000 00:00 0 [stack]
55a5b1000000-55a5b1010000 rw-p 00000000 00:00 0 [heap]
7fff00000000-7fff00001000 r-xp 00000000 00:00 0 [vdso]
7fff00001000-7fff00002000 rw-p 00000000 00:00 0 [anon:libc-malloc-arena]
7fff00002000-7fff00003000 rw-p 00000000 00:00 0 [vvar]
7fff00003000-7fff00004000 rw-p 00000000 00:00 0 [vsyscall]
";

    #[test]
    fn buckets_categories_correctly() {
        let exe = PathBuf::from("/home/user/ergo-node");
        let s = parse_maps_summary(SAMPLE, Some(&exe));

        // bin: 3 mappings × 0x10_0000 (1 MiB) each = 3 MiB
        assert_eq!(s.bin_bytes, 3 * 0x10_0000);
        // so: libc 2 × 0x10_0000 + vdso 0x1000 + vsyscall 0x1000
        // (both [vdso] and [vsyscall] map to So per categorise()).
        assert_eq!(s.so_bytes, 2 * 0x10_0000 + 2 * 0x1000);
        // redb: 0x1_0000_0000 (4 GiB)
        assert_eq!(s.redb_bytes, 0x1_0000_0000);
        // anon: empty-path 0x1_0000_0000 (4 GiB) + [anon:...] 0x1000 + [vvar] 0x1000
        assert_eq!(s.anon_bytes, 0x1_0000_0000 + 0x2000);
        // stack
        assert_eq!(s.stack_bytes, 0x21000);
        // heap
        assert_eq!(s.heap_bytes, 0x10000);
        // [vsyscall] is classified as so, not anon
        assert_eq!(s.other_bytes, 0);
    }

    #[test]
    fn empty_input_is_all_zeros() {
        let s = parse_maps_summary("", None);
        assert_eq!(s, MapsSummary::default());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let s = parse_maps_summary("not-a-map-line\n\n# comment\n", None);
        assert_eq!(s, MapsSummary::default());
    }

    #[test]
    fn no_exe_path_still_classifies_other_categories() {
        let line = "7f5600000000-7f5700000000 r--p 0 fd:01 33 /home/user/data/state.redb\n";
        let s = parse_maps_summary(line, None);
        assert_eq!(s.redb_bytes, 0x1_0000_0000);
        assert_eq!(s.other_bytes, 0);
    }

    #[test]
    fn shared_object_versioned_suffix() {
        assert!(is_shared_object("/usr/lib/libc.so.6"));
        assert!(is_shared_object("/usr/lib/libstdc++.so.6.0.32"));
        assert!(is_shared_object("/lib/foo.so"));
        assert!(!is_shared_object("/opt/foo.so.bar/data"));
        assert!(!is_shared_object("/opt/something.txt"));
        assert!(!is_shared_object(""));
    }

    #[test]
    fn unknown_path_goes_to_other() {
        let line = "55a5b0d2a000-55a5b0d3a000 r--p 0 fd:01 11 /opt/data/foo.txt\n";
        let s = parse_maps_summary(line, None);
        assert_eq!(s.other_bytes, 0x10000);
    }

    #[test]
    fn compact_format_round_trips_kb() {
        let s = MapsSummary {
            heap_bytes: 1024 * 12,
            anon_bytes: 1024 * 234,
            redb_bytes: 1024 * 345,
            so_bytes: 1024 * 12,
            bin_bytes: 1024 * 2,
            stack_bytes: 1024 * 1,
            other_bytes: 1024 * 4,
        };
        let out = s.format_compact();
        assert_eq!(
            out,
            "heap=12kb anon=234kb redb=345kb so=12kb bin=2kb stack=1kb other=4kb"
        );
        // No commas — the compact field must round-trip as a single
        // CSV field without quoting.
        assert!(!out.contains(','));
    }
}
