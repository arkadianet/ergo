//! Optional DB-IP Lite updates. This module never receives a peer IP.
//! Downloads run off the API/P2P loops; only validated MMDBs replace the cache.

use super::{Database, PeerLookupConfig, PeerResolver};
use maxminddb::Reader;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

type Error = Box<dyn std::error::Error + Send + Sync>;
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 3600);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug)]
pub(super) enum Kind {
    City,
    Asn,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::City => "city",
            Self::Asn => "asn",
        }
    }

    fn override_path(self, config: &PeerLookupConfig) -> Option<&Path> {
        match self {
            Self::City => config.geoip_db.as_deref(),
            Self::Asn => config.asn_db.as_deref(),
        }
    }

    fn path(self, cache_dir: &Path) -> PathBuf {
        cache_dir.join(format!("dbip-{}-lite.mmdb", self.name()))
    }

    fn release_path(self, cache_dir: &Path) -> PathBuf {
        self.path(cache_dir).with_extension("release")
    }

    fn url(self, release: &str) -> String {
        format!(
            "https://download.db-ip.com/free/dbip-{}-lite-{release}.mmdb.gz",
            self.name()
        )
    }

    fn limits(self) -> (u64, u64) {
        // Compressed and decompressed limits, respectively.
        let mib = 1024 * 1024;
        match self {
            Self::City => (128 * mib, 512 * mib),
            Self::Asn => (32 * mib, 128 * mib),
        }
    }
}

pub(super) fn open_database(config: &PeerLookupConfig, data_dir: &Path, kind: Kind) -> Database {
    if let Some(path) = kind.override_path(config) {
        return Database::open(Some(path), data_dir);
    }
    let path = kind.path(&data_dir.join("geoip"));
    if path.exists() {
        // Already-installed data remains usable with downloads disabled.
        Database::open(Some(&path), Path::new("."))
    } else if config.auto_download {
        Database::Pending
    } else {
        Database::Unconfigured
    }
}

impl PeerResolver {
    /// Called only when the API is enabled. No client, task, directory, or
    /// network request is created unless the operator explicitly opts in.
    pub fn start_updates(self: &Arc<Self>, config: &PeerLookupConfig, data_dir: &Path) {
        let kinds: Vec<_> = [Kind::City, Kind::Asn]
            .into_iter()
            .filter(|kind| kind.override_path(config).is_none())
            .collect();
        if !config.auto_download || kinds.is_empty() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let mut task = self.update_task.lock();
        if task.is_some() {
            return;
        }
        let resolver = Arc::downgrade(self);
        let cache_dir = data_dir.join("geoip");
        *task = Some(runtime.spawn(update_loop(resolver, cache_dir, kinds)));
    }

    fn database(&self, kind: Kind) -> &parking_lot::RwLock<Database> {
        match kind {
            Kind::City => &self.geo,
            Kind::Asn => &self.asn,
        }
    }

    fn install(&self, kind: Kind, database: Database) {
        // Match resolve's lock order. Preserve DNS results and in-flight jobs
        // while making the new local data visible on the next API read.
        let mut cache = self.cache.lock();
        let old = std::mem::replace(&mut *self.database(kind).write(), database);
        for (ip, entry) in cache.iter_mut() {
            let mut data = self.local_lookup(*ip);
            data.hostname = entry.data.hostname.take();
            data.hostname_status = std::mem::take(&mut entry.data.hostname_status);
            data.hostname_checked_at_unix_ms = entry.data.hostname_checked_at_unix_ms;
            entry.data = data;
        }
        drop(cache);
        drop(old);
    }

    fn failed_update(&self, kind: Kind) {
        if !matches!(*self.database(kind).read(), Database::Loaded(_)) {
            self.install(kind, Database::Failed);
        }
    }
}

fn download_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent(concat!("ergo-node/", env!("CARGO_PKG_VERSION")))
        .build()
}

async fn update_loop(resolver: Weak<PeerResolver>, cache_dir: PathBuf, kinds: Vec<Kind>) {
    let client = match download_client() {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "peer database download client unavailable");
            if let Some(resolver) = resolver.upgrade() {
                for kind in kinds {
                    resolver.failed_update(kind);
                }
            }
            return;
        }
    };
    loop {
        let now = time::OffsetDateTime::now_utc();
        let release = format!("{:04}-{:02}", now.year(), u8::from(now.month()));
        for &kind in &kinds {
            let Some(active) = resolver.upgrade() else {
                return;
            };
            let minimum_epoch = match &*active.database(kind).read() {
                Database::Loaded(reader) => Some(reader.metadata().build_epoch),
                _ => None,
            };
            drop(active);
            if minimum_epoch.is_some()
                && tokio::fs::read_to_string(kind.release_path(&cache_dir))
                    .await
                    .is_ok_and(|value| value.trim() == release)
            {
                continue;
            }
            tracing::info!(database = kind.name(), %release, "updating optional DB-IP Lite peer database");
            let result = download(
                &client,
                &kind.url(&release),
                &cache_dir,
                kind,
                &release,
                minimum_epoch,
                kind.limits(),
            )
            .await;
            let Some(active) = resolver.upgrade() else {
                return;
            };
            match result {
                Ok(reader) => {
                    active.install(kind, Database::Loaded(reader));
                    tracing::info!(database = kind.name(), %release, "installed DB-IP Lite peer database (CC BY 4.0; https://db-ip.com)");
                }
                Err(error) => {
                    active.failed_update(kind);
                    tracing::warn!(database = kind.name(), %error, "peer database update failed; keeping existing data and retrying in 24 hours");
                }
            }
        }
        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

async fn download(
    client: &reqwest::Client,
    url: &str,
    cache_dir: &Path,
    kind: Kind,
    release: &str,
    minimum_epoch: Option<u64>,
    limits: (u64, u64),
) -> Result<Reader<Vec<u8>>, Error> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    // error_for_status does not reject redirects. Never follow them or decode
    // their bodies as a dataset, including HTTPS -> HTTP redirects.
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("unexpected download status {}", response.status()).into());
    }
    if response
        .content_length()
        .is_some_and(|length| length > limits.0)
    {
        return Err("compressed peer database exceeds size limit".into());
    }
    tokio::fs::create_dir_all(cache_dir).await?;
    let archive = tempfile::NamedTempFile::new_in(cache_dir)?;
    let mut file = tokio::fs::File::from_std(archive.reopen()?);
    let mut downloaded = 0_u64;
    while let Some(chunk) = response.chunk().await? {
        downloaded += chunk.len() as u64;
        if downloaded > limits.0 {
            return Err("compressed peer database exceeds size limit".into());
        }
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    drop(file);
    let cache_dir = cache_dir.to_path_buf();
    let release = release.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut unpacked = tempfile::NamedTempFile::new_in(&cache_dir)?;
        let mut decoder =
            flate2::read::GzDecoder::new(std::fs::File::open(archive.path())?).take(limits.1 + 1);
        let size = std::io::copy(&mut decoder, &mut unpacked)?;
        if size > limits.1 {
            return Err("decompressed peer database exceeds size limit".into());
        }
        unpacked.flush()?;
        let reader = Reader::open_readfile(unpacked.path())?;
        let database_type = reader.metadata().database_type.to_ascii_lowercase();
        if !database_type.contains("dbip") || !database_type.contains(kind.name()) {
            return Err("download is not the expected DB-IP database type".into());
        }
        if minimum_epoch.is_some_and(|epoch| reader.metadata().build_epoch < epoch) {
            return Err("download is older than the installed database".into());
        }
        reader.verify()?;
        unpacked.as_file().sync_all()?;
        // NamedTempFile::persist atomically replaces the destination on Unix
        // and Windows. Failed or partial downloads never replace good data.
        unpacked.persist(kind.path(&cache_dir))?;
        // A missing marker only causes an extra download, never lost data.
        let marker_result = (|| -> Result<(), Error> {
            let mut marker = tempfile::NamedTempFile::new_in(&cache_dir)?;
            marker.write_all(release.as_bytes())?;
            marker.as_file().sync_all()?;
            marker.persist(kind.release_path(&cache_dir))?;
            Ok(())
        })();
        if let Err(error) = marker_result {
            tracing::warn!(%error, "could not save peer database release marker");
        }
        Ok(reader)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    // A tiny, self-contained MMDB fixture: one IPv4 tree node, two leaves
    // pointing to the same record. No third-party data or network is needed.
    fn string(value: &str) -> Vec<u8> {
        let mut bytes = if value.len() < 29 {
            vec![0x40 | value.len() as u8]
        } else {
            vec![0x40 | 29, (value.len() - 29) as u8]
        };
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![0xe0 | entries.len() as u8];
        for (key, value) in entries {
            bytes.extend(string(key));
            bytes.extend(value);
        }
        bytes
    }

    fn uint(value: u32) -> Vec<u8> {
        let mut bytes = vec![0xc4];
        bytes.extend(value.to_be_bytes());
        bytes
    }

    fn uint16(value: u16) -> Vec<u8> {
        let mut bytes = vec![0xa2];
        bytes.extend(value.to_be_bytes());
        bytes
    }

    fn fixture(kind: Kind, epoch: u64) -> Vec<u8> {
        let record = match kind {
            Kind::City => map(&[("country", map(&[("iso_code", string("ZZ"))]))]),
            Kind::Asn => map(&[
                ("autonomous_system_number", uint(64500)),
                ("autonomous_system_organization", string("Example network")),
            ]),
        };
        let mut build_epoch = vec![8, 2]; // MMDB extended uint64 type.
        build_epoch.extend(epoch.to_be_bytes());
        let mut bytes = vec![0, 0, 17, 0, 0, 17];
        bytes.extend([0; 16]);
        bytes.extend(record);
        bytes.extend(b"\xab\xcd\xefMaxMind.com");
        bytes.extend(map(&[
            ("binary_format_major_version", uint16(2)),
            ("binary_format_minor_version", uint16(0)),
            ("build_epoch", build_epoch),
            (
                "database_type",
                string(&format!("DBIP-{}-Lite", kind.name())),
            ),
            (
                "description",
                map(&[("en", string("Synthetic test fixture"))]),
            ),
            ("ip_version", uint16(4)),
            ("languages", vec![0, 4]), // Empty MMDB array (extended type 11).
            ("node_count", uint(1)),
            ("record_size", uint16(24)),
        ]));
        bytes
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    async fn serve(
        body: Vec<u8>,
        status: u16,
        chunked: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let mut received = 0;
            loop {
                let count = socket.read(&mut request[received..]).await.unwrap();
                assert_ne!(count, 0, "expected a complete HTTP request header");
                received += count;
                if request[..received].ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(
                    received < request.len(),
                    "request header exceeds test limit"
                );
            }
            let header = if chunked {
                "Transfer-Encoding: chunked\r\n".to_owned()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            };
            let mut response =
                format!("HTTP/1.1 {status} Test\r\n{header}Connection: close\r\n\r\n").into_bytes();
            if chunked {
                response.extend(format!("{:x}\r\n", body.len()).as_bytes());
                response.extend(body);
                response.extend(b"\r\n0\r\n\r\n");
            } else {
                response.extend(body);
            }
            let _ = socket.write_all(&response).await;
        });
        (format!("http://{addr}/db"), task)
    }

    fn test_client() -> reqwest::Client {
        // Loopback HTTP is only permitted in this test harness.
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn defaults_do_not_start_dns_downloads_or_create_cache() {
        let dir = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let config = PeerLookupConfig::default();
        let mut resolver = PeerResolver::new(&config, dir.path());
        Arc::get_mut(&mut resolver).unwrap().lookup = Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Some("unexpected.test".into())
        });
        resolver.start_updates(&config, dir.path());
        for ip in ["8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1"] {
            let result = resolver.resolve(ip.parse().unwrap());
            assert_eq!(result.hostname_status, "disabled");
            assert_eq!(result.geo_status, "not_configured");
        }
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(resolver.update_task.lock().is_none());
        assert!(!dir.path().join("geoip").exists());
    }

    #[tokio::test]
    async fn production_client_rejects_plain_http_before_connecting() {
        let error = download_client()
            .unwrap()
            .get("http://127.0.0.1:1/db")
            .send()
            .await
            .unwrap_err();
        assert!(error.is_builder(), "HTTPS-only policy must reject the URL");
    }

    #[tokio::test]
    #[ignore = "downloads current DB-IP Lite City/ASN over HTTPS; run explicitly with network access"]
    async fn live_dbip_lite_download() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("geoip");
        let now = time::OffsetDateTime::now_utc();
        let release = format!("{:04}-{:02}", now.year(), u8::from(now.month()));
        let client = download_client().unwrap();
        for kind in [Kind::City, Kind::Asn] {
            let reader = download(
                &client,
                &kind.url(&release),
                &cache,
                kind,
                &release,
                None,
                kind.limits(),
            )
            .await
            .unwrap();
            assert!(reader.metadata().build_epoch > 0);
        }
        let resolver = PeerResolver::new(&PeerLookupConfig::default(), dir.path());
        let result = resolver.resolve("8.8.8.8".parse().unwrap());
        assert_eq!(result.geo_status, "available");
        assert_eq!(result.asn_status, "available");
        assert_eq!(result.hostname_status, "disabled");
    }

    #[tokio::test]
    async fn overrides_prevent_downloads_even_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = PeerLookupConfig {
            auto_download: true,
            geoip_db: Some("missing-city.mmdb".into()),
            asn_db: Some("missing-asn.mmdb".into()),
            ..Default::default()
        };
        let resolver = PeerResolver::new(&config, dir.path());
        resolver.start_updates(&config, dir.path());
        assert!(resolver.update_task.lock().is_none());
        assert_eq!(
            resolver.resolve("8.8.8.8".parse().unwrap()).geo_status,
            "error"
        );
        assert!(!dir.path().join("geoip").exists());
        let mut only_city = config.clone();
        only_city.asn_db = None;
        assert!(Kind::City.override_path(&only_city).is_some());
        assert!(Kind::Asn.override_path(&only_city).is_none());
    }

    #[tokio::test]
    async fn installs_valid_download_and_reuses_cache_offline() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("geoip");
        let (url, server) = serve(gzip(&fixture(Kind::City, 100)), 200, false).await;
        let reader = download(
            &test_client(),
            &url,
            &cache,
            Kind::City,
            "2026-09",
            None,
            (4096, 4096),
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(reader.metadata().build_epoch, 100);
        assert_eq!(
            std::fs::read_to_string(Kind::City.release_path(&cache)).unwrap(),
            "2026-09"
        );
        // Exercise atomic replacement of an existing destination on Windows too.
        let (url, server) = serve(gzip(&fixture(Kind::City, 102)), 200, false).await;
        download(
            &test_client(),
            &url,
            &cache,
            Kind::City,
            "2026-10",
            Some(100),
            (4096, 4096),
        )
        .await
        .unwrap();
        server.await.unwrap();
        let resolver = PeerResolver::new(&PeerLookupConfig::default(), dir.path());
        let ip = "8.8.8.8".parse().unwrap();
        let result = resolver.resolve(ip);
        assert_eq!(result.country_code.as_deref(), Some("ZZ"));
        assert_eq!(result.geo_database_built_at_unix_seconds, Some(102));
        assert_eq!(result.hostname_status, "disabled");
        // A hot reload must refresh existing peer cache entries immediately,
        // preserving DNS state, and later failure must retain the working data.
        resolver.install(
            Kind::Asn,
            Database::Loaded(Reader::from_source(fixture(Kind::Asn, 101)).unwrap()),
        );
        resolver.failed_update(Kind::City);
        let result = resolver.resolve(ip);
        assert_eq!(result.country_code.as_deref(), Some("ZZ"));
        assert_eq!(result.asn, Some(64500));
        assert_eq!(result.organization.as_deref(), Some("Example network"));
        assert_eq!(result.hostname_status, "disabled");
        assert_eq!(
            std::fs::read_dir(&cache).unwrap().count(),
            2,
            "temporary files cleaned up"
        );
    }

    #[tokio::test]
    async fn rejects_failed_corrupt_oversized_wrong_type_and_older_downloads_without_replacing_cache(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let previous = fixture(Kind::City, 100);
        std::fs::write(Kind::City.path(dir.path()), &previous).unwrap();
        std::fs::write(Kind::City.release_path(dir.path()), "2026-08").unwrap();
        let good = gzip(&fixture(Kind::City, 101));
        let cases = [
            (good.clone(), 404, false, (4096, 4096)),
            (good.clone(), 302, false, (4096, 4096)),
            (b"bad gzip".to_vec(), 200, false, (4096, 4096)),
            (gzip(b"not an mmdb"), 200, false, (4096, 4096)),
            (good.clone(), 200, false, (16, 4096)),
            (good.clone(), 200, true, (16, 4096)),
            (good, 200, false, (4096, 16)),
            (gzip(&fixture(Kind::Asn, 101)), 200, false, (4096, 4096)),
            (gzip(&fixture(Kind::City, 99)), 200, false, (4096, 4096)),
        ];
        for (body, status, chunked, limits) in cases {
            let (url, server) = serve(body, status, chunked).await;
            assert!(download(
                &test_client(),
                &url,
                dir.path(),
                Kind::City,
                "2026-09",
                Some(100),
                limits
            )
            .await
            .is_err());
            server.await.unwrap();
            assert_eq!(
                std::fs::read(Kind::City.path(dir.path())).unwrap(),
                previous
            );
            assert_eq!(
                std::fs::read_to_string(Kind::City.release_path(dir.path())).unwrap(),
                "2026-08"
            );
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        }
    }
}
