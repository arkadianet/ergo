use ergo_api::types::ApiHost;
use ergo_api::NodeReadState;
use ergo_api_core::observability::{HostStatus, HostStatusSource};

use super::SnapshotReadState;

fn convert_host(host: ApiHost) -> HostStatus {
    HostStatus {
        rss_bytes: host.rss_bytes,
        state_db_bytes: host.state_db_bytes,
        index_db_bytes: host.index_db_bytes,
        disk_free_bytes: host.disk_free_bytes,
        disk_total_bytes: host.disk_total_bytes,
        cpu_pct: host.cpu_pct,
        net_in_bps: host.net_in_bps,
        net_out_bps: host.net_out_bps,
        load_1m: host.load_1m,
    }
}

impl HostStatusSource for SnapshotReadState {
    fn host_status(&self) -> HostStatus {
        convert_host(NodeReadState::host(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_preserves_all_host_fields() {
        let status = convert_host(ApiHost {
            rss_bytes: Some(1),
            state_db_bytes: Some(0),
            index_db_bytes: None,
            disk_free_bytes: Some(3),
            disk_total_bytes: Some(4),
            cpu_pct: Some(5.5),
            net_in_bps: Some(6),
            net_out_bps: Some(7),
            load_1m: Some(8.25),
        });

        assert_eq!(status.rss_bytes, Some(1));
        assert_eq!(status.state_db_bytes, Some(0));
        assert_eq!(status.index_db_bytes, None);
        assert_eq!(status.disk_free_bytes, Some(3));
        assert_eq!(status.disk_total_bytes, Some(4));
        assert_eq!(status.cpu_pct, Some(5.5));
        assert_eq!(status.net_in_bps, Some(6));
        assert_eq!(status.net_out_bps, Some(7));
        assert_eq!(status.load_1m, Some(8.25));
    }
}
