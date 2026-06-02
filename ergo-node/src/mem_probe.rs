//! `/proc/self/status` snapshot for memory observability (Slice 1).
//!
//! Linux-only. On other platforms `read_proc_status()` returns `None` and the
//! caller must record the row with zeros for the proc fields.

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProcStatus {
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub rss_anon_kb: u64,
    pub rss_file_kb: u64,
}

#[cfg(target_os = "linux")]
pub fn read_proc_status() -> Option<ProcStatus> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    Some(parse_proc_status(&text))
}

#[cfg(not(target_os = "linux"))]
pub fn read_proc_status() -> Option<ProcStatus> {
    None
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_proc_status(text: &str) -> ProcStatus {
    let mut s = ProcStatus::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("VmSize:") {
            s.vm_size_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("VmRSS:") {
            s.vm_rss_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("RssAnon:") {
            s.rss_anon_kb = parse_kb(v);
        } else if let Some(v) = line.strip_prefix("RssFile:") {
            s.rss_file_kb = parse_kb(v);
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
Name:\tergo-node
Umask:\t0022
State:\tR (running)
VmPeak:\t 2625436 kB
VmSize:\t 2625436 kB
VmLck:\t       0 kB
VmHWM:\t 1493012 kB
VmRSS:\t 1492988 kB
RssAnon:\t 1432156 kB
RssFile:\t   60832 kB
RssShmem:\t       0 kB
";

    #[test]
    fn parses_proc_status_fields() {
        let s = parse_proc_status(SAMPLE);
        assert_eq!(s.vm_size_kb, 2_625_436);
        assert_eq!(s.vm_rss_kb, 1_492_988);
        assert_eq!(s.rss_anon_kb, 1_432_156);
        assert_eq!(s.rss_file_kb, 60_832);
    }

    #[test]
    fn missing_fields_default_to_zero() {
        let s = parse_proc_status("VmRSS:\t 12 kB\n");
        assert_eq!(s.vm_rss_kb, 12);
        assert_eq!(s.vm_size_kb, 0);
        assert_eq!(s.rss_anon_kb, 0);
        assert_eq!(s.rss_file_kb, 0);
    }

    #[test]
    fn malformed_value_is_zero() {
        let s = parse_proc_status("VmRSS:\tnot-a-number kB\n");
        assert_eq!(s.vm_rss_kb, 0);
    }
}
