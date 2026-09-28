//! Read-only peer enrichment. No lookups run on the P2P/sync action loop.
//! Local MMDB lookups are cached by canonical IP. Reverse DNS uses the OS
//! resolver on at most four blocking workers; a timed-out OS call keeps its
//! permit until it actually finishes, so timeouts cannot exhaust the pool.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ergo_api::types::ApiPeerNetwork;
use maxminddb::Reader;
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use tokio::sync::Semaphore;

const CACHE_LIMIT: usize = 1024;
const SUCCESS_TTL: Duration = Duration::from_secs(24 * 3600);
const FAILURE_TTL: Duration = Duration::from_secs(15 * 60);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

mod download;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerLookupConfig {
    /// Opt in to DNS queries that disclose peer IPs to the OS resolver.
    pub reverse_dns: bool,
    /// Opt in to downloading/updating DB-IP Lite datasets over HTTPS.
    pub auto_download: bool,
    /// Local City or Country MMDB override. Relative paths use the data directory.
    pub geoip_db: Option<PathBuf>,
    /// Local ASN MMDB override. Relative paths use the data directory.
    pub asn_db: Option<PathBuf>,
}

enum Database {
    Unconfigured,
    Pending,
    Failed,
    Loaded(Reader<Vec<u8>>),
}

impl Database {
    fn open(path: Option<&Path>, data_dir: &Path) -> Self {
        let Some(path) = path else {
            return Self::Unconfigured;
        };
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            data_dir.join(path)
        };
        match Reader::open_readfile(&path) {
            Ok(reader) => Self::Loaded(reader),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "peer IP database unavailable");
                Self::Failed
            }
        }
    }

    fn status(&self) -> &'static str {
        match self {
            Self::Unconfigured => "not_configured",
            Self::Pending => "downloading",
            Self::Failed => "error",
            Self::Loaded(_) => "not_found",
        }
    }
}

struct Entry {
    data: ApiPeerNetwork,
    expires: Instant,
    pending: bool,
}

pub struct PeerResolver {
    reverse_dns: bool,
    geo: RwLock<Database>,
    asn: RwLock<Database>,
    cache: Mutex<HashMap<IpAddr, Entry>>,
    workers: Arc<Semaphore>,
    lookup: Arc<dyn Fn(IpAddr) -> Option<String> + Send + Sync>,
    update_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for PeerResolver {
    fn drop(&mut self) {
        if let Some(task) = self.update_task.get_mut().take() {
            task.abort();
        }
    }
}

impl PeerResolver {
    pub fn new(config: &PeerLookupConfig, data_dir: &Path) -> Arc<Self> {
        Arc::new(Self {
            reverse_dns: config.reverse_dns,
            geo: RwLock::new(download::open_database(
                config,
                data_dir,
                download::Kind::City,
            )),
            asn: RwLock::new(download::open_database(
                config,
                data_dir,
                download::Kind::Asn,
            )),
            cache: Mutex::new(HashMap::new()),
            workers: Arc::new(Semaphore::new(4)),
            lookup: Arc::new(|ip| dns_lookup::lookup_addr(&ip).ok()),
            update_task: Mutex::new(None),
        })
    }

    /// Only the node's connected peer snapshot supplies addresses to this method.
    /// API reads return immediately, including while a DNS request is pending.
    pub fn resolve(self: &Arc<Self>, ip: IpAddr) -> ApiPeerNetwork {
        let ip = ip.to_canonical();
        let now = Instant::now();
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(&ip) {
            if entry.pending || entry.expires > now {
                return entry.data.clone();
            }
        }
        let mut data = self.local_lookup(ip);
        let public = data.scope == "public";
        data.hostname_status = if !public {
            "not_public"
        } else if !self.reverse_dns {
            "disabled"
        } else {
            "pending"
        }
        .into();
        // Evict a completed entry only. In-flight results must not overwrite a
        // new entry for the same IP; at most four entries can be in flight.
        if cache.len() >= CACHE_LIMIT && !cache.contains_key(&ip) {
            if let Some(oldest) = cache
                .iter()
                .filter(|(_, e)| !e.pending)
                .min_by_key(|(_, e)| e.expires)
                .map(|(ip, _)| *ip)
            {
                cache.remove(&oldest);
            }
        }
        let mut entry = Entry {
            data,
            expires: now + SUCCESS_TTL,
            pending: false,
        };
        if public && self.reverse_dns {
            // No task queue: once capacity is available a subsequent API read
            // retries. The cache itself remains bounded under peer churn.
            entry.expires = now;
            if let (Ok(permit), Ok(runtime)) = (
                self.workers.clone().try_acquire_owned(),
                tokio::runtime::Handle::try_current(),
            ) {
                entry.pending = true;
                let resolver = Arc::clone(self);
                let lookup = Arc::clone(&self.lookup);
                runtime.spawn(async move {
                    let job = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        lookup(ip)
                    });
                    let (hostname, status) = match tokio::time::timeout(DNS_TIMEOUT, job).await {
                        Ok(Ok(Some(name)))
                            if !name.is_empty() && name.parse::<IpAddr>().is_err() =>
                        {
                            (Some(name), "resolved")
                        }
                        Err(_) => (None, "timeout"),
                        _ => (None, "unavailable"),
                    };
                    let mut cache = resolver.cache.lock();
                    if let Some(entry) = cache.get_mut(&ip) {
                        entry.data.hostname = hostname;
                        entry.data.hostname_status = status.into();
                        entry.data.hostname_checked_at_unix_ms =
                            Some(crate::snapshot::unix_now_ms());
                        entry.expires = Instant::now()
                            + if status == "resolved" {
                                SUCCESS_TTL
                            } else {
                                FAILURE_TTL
                            };
                        entry.pending = false;
                    }
                });
            }
        }
        let result = entry.data.clone();
        cache.insert(ip, entry);
        result
    }

    fn local_lookup(&self, ip: IpAddr) -> ApiPeerNetwork {
        let geo = self.geo.read();
        let asn = self.asn.read();
        let scope = address_scope(ip);
        let mut data = ApiPeerNetwork {
            ip: ip.to_string(),
            ip_version: if ip.is_ipv4() { "IPv4" } else { "IPv6" }.into(),
            scope: scope.into(),
            geo_status: geo.status().into(),
            asn_status: asn.status().into(),
            ..Default::default()
        };
        if scope != "public" {
            data.geo_status = "not_public".into();
            data.asn_status = "not_public".into();
            return data;
        }
        if let Database::Loaded(reader) = &*geo {
            data.geo_database = Some(reader.metadata().database_type.clone());
            data.geo_database_built_at_unix_seconds = Some(reader.metadata().build_epoch);
            match reader
                .lookup(ip)
                .and_then(|result| result.decode::<GeoRecord>())
            {
                Ok(Some(record)) => record.apply(&mut data),
                Ok(None) => {}
                Err(_) => data.geo_status = "error".into(),
            }
        }
        if let Database::Loaded(reader) = &*asn {
            data.asn_database = Some(reader.metadata().database_type.clone());
            data.asn_database_built_at_unix_seconds = Some(reader.metadata().build_epoch);
            match reader.lookup(ip).and_then(|result| {
                Ok((result.decode::<AsnRecord>()?, result.network()?.to_string()))
            }) {
                Ok((Some(record), network)) => {
                    if record.autonomous_system_number.is_some()
                        || record.autonomous_system_organization.is_some()
                    {
                        data.asn_status = "available".into();
                        data.asn = record.autonomous_system_number;
                        data.organization = record.autonomous_system_organization;
                        data.network_cidr = Some(network);
                    }
                }
                Ok(_) => {}
                Err(_) => data.asn_status = "error".into(),
            }
        }
        data
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Place {
    iso_code: Option<String>,
    names: BTreeMap<String, String>,
}

impl Place {
    fn name(&self) -> Option<String> {
        self.names
            .get("en")
            .or_else(|| self.names.values().next())
            .cloned()
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Location {
    time_zone: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy_radius: Option<u16>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct GeoRecord {
    country: Place,
    continent: Place,
    subdivisions: Vec<Place>,
    city: Place,
    location: Location,
}

impl GeoRecord {
    fn apply(self, data: &mut ApiPeerNetwork) {
        data.country = self.country.name();
        data.country_code = self.country.iso_code;
        data.continent = self.continent.name();
        data.region = self.subdivisions.last().and_then(Place::name);
        data.city = self.city.name();
        data.time_zone = self.location.time_zone;
        data.latitude = self.location.latitude;
        data.longitude = self.location.longitude;
        data.accuracy_radius_km = self.location.accuracy_radius;
        if data.country_code.is_some()
            || data.country.is_some()
            || data.city.is_some()
            || data.continent.is_some()
        {
            data.geo_status = "available".into();
        }
    }
}

#[derive(Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

/// Conservative lookup eligibility: local, documentation, transition and
/// reserved addresses must never be submitted to an external DNS resolver.
fn address_scope(ip: IpAddr) -> &'static str {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            if ip.is_loopback() {
                "loopback"
            } else if ip.is_private() {
                "private"
            } else if ip.is_link_local() {
                "link_local"
            } else if a == 100 && (64..=127).contains(&b) {
                "shared"
            } else if ip.is_unspecified() {
                "unspecified"
            } else if ip.is_multicast() {
                "multicast"
            } else if a == 0
                || a >= 240
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
            {
                "special"
            } else {
                "public"
            }
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            if ip.is_loopback() {
                "loopback"
            } else if ip.is_unspecified() {
                "unspecified"
            } else if s[0] & 0xfe00 == 0xfc00 {
                "private"
            } else if s[0] & 0xffc0 == 0xfe80 {
                "link_local"
            } else if ip.is_multicast() {
                "multicast"
            } else if s[0] & 0xe000 != 0x2000
                || (s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                || s[0] == 0x2002
                || (s[0] == 0x3fff && s[1] < 0x1000)
            {
                "special"
            } else {
                "public"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn skips_non_public_addresses_including_mapped_ipv4() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.2",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:192.168.1.2",
            "64:ff9b::1",
        ] {
            assert_ne!(address_scope(ip.parse().unwrap()), "public", "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert_eq!(address_scope(ip.parse().unwrap()), "public", "{ip}");
        }
    }

    #[test]
    fn distinguishes_unconfigured_broken_and_non_public_lookups() {
        let resolver = PeerResolver::new(
            &PeerLookupConfig {
                reverse_dns: false,
                asn_db: Some(PathBuf::from("does-not-exist.mmdb")),
                ..Default::default()
            },
            Path::new("."),
        );
        let public = resolver.resolve("8.8.8.8".parse().unwrap());
        assert_eq!(public.hostname_status, "disabled");
        assert_eq!(public.geo_status, "not_configured");
        assert_eq!(public.asn_status, "error");
        let local = resolver.resolve("::ffff:127.0.0.1".parse().unwrap());
        assert_eq!(local.ip, "127.0.0.1");
        assert_eq!(local.hostname_status, "not_public");
        assert_eq!(local.geo_status, "not_public");
    }

    #[tokio::test]
    async fn dns_is_cached_and_deduplicated_with_negative_caching() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let mut resolver = PeerResolver::new(
            &PeerLookupConfig {
                reverse_dns: true,
                ..Default::default()
            },
            Path::new("."),
        );
        Arc::get_mut(&mut resolver).unwrap().lookup = Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            None
        });
        let ip = "8.8.8.8".parse().unwrap();
        for _ in 0..20 {
            resolver.resolve(ip);
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while resolver.resolve(ip).hostname_status == "pending" {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(resolver.resolve(ip).hostname_status, "unavailable");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        resolver.cache.lock().get_mut(&ip).unwrap().expires = Instant::now();
        assert_eq!(resolver.resolve(ip).hostname_status, "pending");
    }

    #[test]
    fn cache_stays_bounded_and_geo_fields_preserve_estimates() {
        let resolver = PeerResolver::new(
            &PeerLookupConfig {
                reverse_dns: false,
                ..Default::default()
            },
            Path::new("."),
        );
        for n in 0..1500_u32 {
            resolver.resolve(std::net::Ipv4Addr::from(0x08080000 + n).into());
        }
        assert_eq!(resolver.cache.lock().len(), CACHE_LIMIT);
        let record: GeoRecord = serde_json::from_value(serde_json::json!({
            "country": {"iso_code": "SE", "names": {"en": "Sweden"}},
            "city": {"names": {"en": "Linköping"}},
            "location": {"latitude": 58.41, "longitude": 15.62, "accuracy_radius": 50, "time_zone": "Europe/Stockholm"}
        })).unwrap();
        let mut data = ApiPeerNetwork::default();
        record.apply(&mut data);
        assert_eq!(data.geo_status, "available");
        assert_eq!(data.country_code.as_deref(), Some("SE"));
        assert_eq!(data.accuracy_radius_km, Some(50));
        assert_eq!(data.latitude, Some(58.41));
    }

    #[tokio::test]
    async fn timeout_retains_worker_permit_until_os_call_finishes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let mut resolver = PeerResolver::new(
            &PeerLookupConfig {
                reverse_dns: true,
                ..Default::default()
            },
            Path::new("."),
        );
        let inner = Arc::get_mut(&mut resolver).unwrap();
        inner.workers = Arc::new(Semaphore::new(1));
        inner.lookup = Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(DNS_TIMEOUT + Duration::from_secs(1));
            Some("late.example.test".into())
        });
        let ip = "8.8.8.8".parse().unwrap();
        assert_eq!(resolver.resolve(ip).hostname_status, "pending");
        tokio::time::sleep(DNS_TIMEOUT + Duration::from_millis(100)).await;
        assert_eq!(resolver.resolve(ip).hostname_status, "timeout");
        assert_eq!(resolver.workers.available_permits(), 0);
        for n in 1..20 {
            assert_eq!(
                resolver
                    .resolve(std::net::Ipv4Addr::new(1, 1, 1, n).into())
                    .hostname_status,
                "pending"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(resolver.workers.available_permits(), 1);
        assert_eq!(
            resolver.resolve(ip).hostname_status,
            "timeout",
            "late result must not replace the cached timeout"
        );
    }
}
