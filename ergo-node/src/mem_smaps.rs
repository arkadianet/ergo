//! `/proc/self/smaps_rollup` snapshot for memory observability.
//!
//! Linux 4.14+ exposes a process-wide rollup of `smaps` as a single
//! pseudo-file, parseable in O(1) lines. We surface PSS / private dirty /
//! anonymous so the operator can attribute VmRSS to *kind* of memory, not
//! just bulk size — answering questions like "is the 4.8 GB plateau
//! mostly anonymous mmap or redb file mapping?"
//!
//! On non-Linux platforms, the reader returns `None` and the sampler
//! records zeros for every smaps field.

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SmapsRollup {
    pub rss_kb: u64,
    pub pss_kb: u64,
    pub shared_clean_kb: u64,
    pub shared_dirty_kb: u64,
    pub private_clean_kb: u64,
    pub private_dirty_kb: u64,
    pub anonymous_kb: u64,
    pub anon_huge_pages_kb: u64,
    pub file_pmd_mapped_kb: u64,
}

#[cfg(target_os = "linux")]
pub fn read_smaps_rollup() -> Option<SmapsRollup> {
    let text = std::fs::read_to_string("/proc/self/smaps_rollup").ok()?;
    Some(parse_smaps_rollup(&text))
}

#[cfg(not(target_os = "linux"))]
pub fn read_smaps_rollup() -> Option<SmapsRollup> {
    None
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_smaps_rollup(text: &str) -> SmapsRollup {
    let mut s = SmapsRollup::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Rss:") {
            s.rss_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("Pss:") {
            s.pss_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("Shared_Clean:") {
            s.shared_clean_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("Shared_Dirty:") {
            s.shared_dirty_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("Private_Clean:") {
            s.private_clean_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("Private_Dirty:") {
            s.private_dirty_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("Anonymous:") {
            s.anonymous_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("AnonHugePages:") {
            s.anon_huge_pages_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("FilePmdMapped:") {
            s.file_pmd_mapped_kb = parse_kb(v);
        }
    }
    s
}

#[cfg(any(target_os = "linux", test))]
fn parse_kb(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|w| w.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
55a5b0d2a000-7fff21efb000 ---p 00000000 00:00 0                          [rollup]
Rss:             1492988 kB
Pss:              700123 kB
Pss_Dirty:        650000 kB
Pss_Anon:         648000 kB
Pss_File:          50000 kB
Pss_Shmem:             0 kB
Shared_Clean:      80000 kB
Shared_Dirty:        100 kB
Private_Clean:     12888 kB
Private_Dirty:    900000 kB
Referenced:      1300000 kB
Anonymous:       1432156 kB
LazyFree:              0 kB
AnonHugePages:    102400 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:      2048 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
";

    #[test]
    fn parses_smaps_rollup_fields() {
        let r = parse_smaps_rollup(SAMPLE);
        assert_eq!(r.rss_kb, 1_492_988);
        assert_eq!(r.pss_kb, 700_123);
        assert_eq!(r.shared_clean_kb, 80_000);
        assert_eq!(r.shared_dirty_kb, 100);
        assert_eq!(r.private_clean_kb, 12_888);
        assert_eq!(r.private_dirty_kb, 900_000);
        assert_eq!(r.anonymous_kb, 1_432_156);
        assert_eq!(r.anon_huge_pages_kb, 102_400);
        assert_eq!(r.file_pmd_mapped_kb, 2_048);
    }

    #[test]
    fn missing_fields_default_to_zero() {
        let r = parse_smaps_rollup("Rss:\t 12 kB\n");
        assert_eq!(r.rss_kb, 12);
        assert_eq!(r.pss_kb, 0);
        assert_eq!(r.private_dirty_kb, 0);
        assert_eq!(r.anonymous_kb, 0);
        assert_eq!(r.anon_huge_pages_kb, 0);
        assert_eq!(r.file_pmd_mapped_kb, 0);
    }

    #[test]
    fn empty_input_is_all_zeros() {
        let r = parse_smaps_rollup("");
        assert_eq!(r, SmapsRollup::default());
    }

    #[test]
    fn malformed_value_is_zero() {
        let r = parse_smaps_rollup("Pss:\tnot-a-number kB\n");
        assert_eq!(r.pss_kb, 0);
    }

    /// Pss_Dirty / Pss_Anon are *prefixes* of "Pss:" only because we
    /// strip the trailing colon — we must not match them as `Pss`.
    /// This test pins the colon-required matching behavior.
    #[test]
    fn pss_dirty_does_not_match_pss() {
        let r = parse_smaps_rollup("Pss_Dirty:\t 999 kB\nPss:\t 100 kB\n");
        assert_eq!(r.pss_kb, 100);
    }
}
