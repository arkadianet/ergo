#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostStatus {
    pub rss_bytes: Option<u64>,
    pub state_db_bytes: Option<u64>,
    pub index_db_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub cpu_pct: Option<f32>,
    pub net_in_bps: Option<u64>,
    pub net_out_bps: Option<u64>,
    pub load_1m: Option<f32>,
}

pub trait HostStatusSource: Send + Sync + 'static {
    fn host_status(&self) -> HostStatus;
}

pub type HostRecord = HostStatus;
pub use HostStatusSource as HostSource;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_status_keeps_every_measurement_unknown() {
        let status = HostStatus::default();
        assert!(status.rss_bytes.is_none());
        assert!(status.state_db_bytes.is_none());
        assert!(status.index_db_bytes.is_none());
        assert!(status.disk_free_bytes.is_none());
        assert!(status.disk_total_bytes.is_none());
        assert!(status.cpu_pct.is_none());
        assert!(status.net_in_bps.is_none());
        assert!(status.net_out_bps.is_none());
        assert!(status.load_1m.is_none());
    }

    #[test]
    fn status_retains_each_optional_measurement() {
        let status = HostStatus {
            rss_bytes: Some(1),
            state_db_bytes: Some(0),
            index_db_bytes: Some(2),
            disk_free_bytes: Some(3),
            disk_total_bytes: Some(4),
            cpu_pct: Some(5.5),
            net_in_bps: Some(6),
            net_out_bps: Some(7),
            load_1m: Some(8.25),
        };
        assert_eq!(status.rss_bytes, Some(1));
        assert_eq!(status.state_db_bytes, Some(0));
        assert_eq!(status.index_db_bytes, Some(2));
        assert_eq!(status.disk_free_bytes, Some(3));
        assert_eq!(status.disk_total_bytes, Some(4));
        assert_eq!(status.cpu_pct, Some(5.5));
        assert_eq!(status.net_in_bps, Some(6));
        assert_eq!(status.net_out_bps, Some(7));
        assert_eq!(status.load_1m, Some(8.25));
    }
}
