use std::net::IpAddr;
use std::sync::Arc;

use maxminddb::geoip2;
use serde::{Deserialize, Serialize};

/// Geolocation info returned by a GeoIP lookup.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeoInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
}

/// Wrapper around a MaxMind GeoLite2 database reader.
/// The inner `Reader<Vec<u8>>` is `Send + Sync`.
pub struct GeoIp {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    /// Open a MaxMind .mmdb file. Returns `None` if the file is missing or invalid.
    pub fn open(path: &str) -> Option<Self> {
        match maxminddb::Reader::open_readfile(path) {
            Ok(reader) => {
                tracing::info!(path, "GeoIP database loaded");
                Some(Self { reader })
            }
            Err(e) => {
                tracing::warn!(path, error = %e, "failed to open GeoIP database, geo lookups disabled");
                None
            }
        }
    }

    /// Look up geolocation for an IP address. Returns `None` on lookup failure.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let city: geoip2::City = self.reader.lookup(ip).ok()?;
        let country_code = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code.map(|s| s.to_string()));
        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|names| names.get("en"))
            .map(|s| s.to_string());
        let (latitude, longitude) = city
            .location
            .as_ref()
            .map(|loc| (loc.latitude, loc.longitude))
            .unwrap_or((None, None));
        Some(GeoInfo {
            country_code,
            city: city_name,
            latitude,
            longitude,
        })
    }
}

/// Shared GeoIP handle. `None` when geo lookups are disabled.
pub type SharedGeoIp = Arc<Option<GeoIp>>;
