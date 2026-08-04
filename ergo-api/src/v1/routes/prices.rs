use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_indexer_types::TokenId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::dto::unix_ms_to_iso;
use super::extract::V1Query;
use super::{parse_id32, V1State};
use crate::v1::error::{v1_error, Reason, V1Error};
use crate::v1::pricing::{
    reference_spot, select_reference_pool, DiscoveryError, IndexerPoolDiscovery, PoolDiscovery,
};

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PricesQuery {
    pub token_id: Option<String>,
    pub quote: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PricesResponse {
    pub quote: String,
    pub height: u64,
    pub timestamp: String,
    pub items: Vec<PriceItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PriceItem {
    pub token_id: String,
    pub priced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<PriceValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<PriceSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PriceValue {
    pub display: String,
    pub raw: RawPrice,
    pub token_decimals: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RawPrice {
    pub numerator: String,
    pub denominator: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PriceSource {
    pub protocol: String,
    pub pool_type: String,
    pub pool_box_id: String,
    pub path: Vec<PricePathHop>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PricePathHop {
    pub pool_box_id: String,
    pub pool_type: String,
}

#[derive(Debug)]
struct ValidatedPricesQuery {
    token_id: TokenId,
    token_id_hex: String,
    quote: String,
}

fn validate_prices_query(query: PricesQuery) -> Result<ValidatedPricesQuery, Box<Response>> {
    let token_id_hex = query.token_id.ok_or_else(|| Box::new(invalid_token_id()))?;
    let token_id = parse_id32(&token_id_hex)
        .map(TokenId::from_bytes)
        .ok_or_else(|| Box::new(invalid_token_id()))?;
    let quote = match query.quote {
        None => "ERG".to_string(),
        Some(quote) if quote.eq_ignore_ascii_case("ERG") => "ERG".to_string(),
        Some(_) => {
            return Err(Box::new(v1_error(
                Reason::UnsupportedQuote,
                "only ERG reference prices are available",
                "omit quote or set quote=ERG",
            )));
        }
    };

    Ok(ValidatedPricesQuery {
        token_id,
        token_id_hex,
        quote,
    })
}

fn invalid_token_id() -> Response {
    v1_error(
        Reason::InvalidTokenId,
        "token_id is required and must be a 64-character lowercase hex string",
        "supply one unprefixed lowercase token id",
    )
}

fn prices_response<D: PoolDiscovery + ?Sized>(
    discovery: &D,
    query: ValidatedPricesQuery,
    now_ms: u64,
) -> Response {
    let snapshot = match discovery.discover(&query.token_id) {
        Ok(snapshot) => snapshot,
        Err(DiscoveryError::Read(error)) => {
            // The underlying read error names internal store state, so it
            // stays server-side; `detail` is the client's remediation hint.
            tracing::warn!(
                route = "/api/v1/prices",
                error = %error,
                "price discovery index read failed",
            );
            return v1_error(
                Reason::InternalError,
                "price discovery could not read the index",
                "retry the request; if it persists, check the node's indexer logs",
            );
        }
        Err(DiscoveryError::LimitExceeded) => {
            return v1_error(
                Reason::PricingUnavailable,
                "price discovery exceeded its candidate limit",
                "retry after the index state changes",
            );
        }
        Err(DiscoveryError::UnstableIndex) => {
            return v1_error(
                Reason::PricingUnavailable,
                "the index changed repeatedly during price discovery",
                "retry the request",
            );
        }
    };

    let item = match select_reference_pool(&snapshot.pools) {
        None => unpriced_item(query.token_id_hex, "no_liquidity"),
        Some(_) if snapshot.token_decimals.is_none() => {
            unpriced_item(query.token_id_hex, "decimals_unknown")
        }
        Some(pool) => {
            let price = reference_spot(
                pool,
                snapshot
                    .token_decimals
                    .expect("token decimals were checked above"),
            );
            let (numerator, denominator) = price.raw.parts_decimal();
            let pool_box_id = hex::encode(pool.pool_box_id.as_bytes());
            PriceItem {
                token_id: query.token_id_hex,
                priced: true,
                reason: None,
                price: Some(PriceValue {
                    display: price.display,
                    raw: RawPrice {
                        numerator,
                        denominator,
                    },
                    token_decimals: price.token_decimals,
                }),
                source: Some(PriceSource {
                    protocol: "spectrum".to_string(),
                    pool_type: "N2T".to_string(),
                    pool_box_id: pool_box_id.clone(),
                    path: vec![PricePathHop {
                        pool_box_id,
                        pool_type: "N2T".to_string(),
                    }],
                }),
                warnings: Some(Vec::new()),
            }
        }
    };

    Json(PricesResponse {
        quote: query.quote,
        height: snapshot.height,
        timestamp: unix_ms_to_iso(now_ms),
        items: vec![item],
    })
    .into_response()
}

fn unpriced_item(token_id: String, reason: &str) -> PriceItem {
    PriceItem {
        token_id,
        priced: false,
        reason: Some(reason.to_string()),
        price: None,
        source: None,
        warnings: None,
    }
}

/// `GET /api/v1/prices` — one token's deterministic Spectrum N2T reference
/// spot price in ERG.
#[utoipa::path(
    get, path = "/api/v1/prices", tag = "prices",
    params(
        ("token_id" = String, Query, description = "64-char lowercase hex token id"),
        ("quote" = Option<String>, Query, description = "Quote asset; defaults to ERG"),
    ),
    responses(
        (status = 200, description = "Reference price or an unpriced reason", body = PricesResponse),
        (status = 400, description = "Malformed token id, query, or unsupported quote", body = V1Error),
        (status = 409, description = "Extra index disabled", body = V1Error),
        (status = 500, description = "Price discovery index read failed", body = V1Error),
        (status = 503, description = "Extra index unavailable or price discovery incomplete", body = V1Error),
    ),
)]
pub async fn get_prices(
    State(state): State<V1State>,
    V1Query(query): V1Query<PricesQuery>,
) -> Response {
    let query = match validate_prices_query(query) {
        Ok(query) => query,
        Err(response) => return *response,
    };
    let indexer = match state.indexer() {
        Ok(indexer) => indexer,
        Err(response) => return *response,
    };
    let discovery = IndexerPoolDiscovery::new(indexer.as_ref());
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);

    prices_response(&discovery, query, now_ms)
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::response::Response;
    use ergo_indexer_types::{IndexerReadError, TokenId};
    use ergo_primitives::digest::Digest32;
    use serde_json::Value;

    use super::*;
    use crate::v1::decode::decoders::spectrum::{SpectrumN2TPool, N2T_NON_TRADABLE_NANOERG};
    use crate::v1::pricing::{DiscoveryError, DiscoverySnapshot, PoolDiscovery};

    // ----- helpers -----

    const TOKEN_ID_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone)]
    struct StubDiscovery {
        result: Result<DiscoverySnapshot, DiscoveryError>,
    }

    impl PoolDiscovery for StubDiscovery {
        fn discover(&self, _token_id: &TokenId) -> Result<DiscoverySnapshot, DiscoveryError> {
            self.result.clone()
        }
    }

    fn query(quote: Option<&str>) -> PricesQuery {
        PricesQuery {
            token_id: Some(TOKEN_ID_HEX.to_string()),
            quote: quote.map(str::to_string),
        }
    }

    fn snapshot(pools: Vec<SpectrumN2TPool>, token_decimals: Option<u32>) -> DiscoverySnapshot {
        DiscoverySnapshot {
            height: 700_000,
            pools,
            token_decimals,
        }
    }

    fn pool() -> SpectrumN2TPool {
        SpectrumN2TPool {
            pool_box_id: Digest32::from_bytes([1; 32]),
            pool_nft: Digest32::from_bytes([2; 32]),
            lp_token: Digest32::from_bytes([3; 32]),
            token_y: Digest32::from_bytes([0xaa; 32]),
            token_y_reserve: 1_000_000,
            erg_reserve: 34_583_910,
            effective_erg_reserve: 34_583_910 - N2T_NON_TRADABLE_NANOERG,
            fee_numerator: 997,
        }
    }

    async fn response_json(response: Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("collect response body");
        serde_json::from_slice(&body).expect("response body is JSON")
    }

    fn validated(quote: Option<&str>) -> ValidatedPricesQuery {
        validate_prices_query(query(quote)).expect("query is valid")
    }

    // ----- happy path -----

    #[test]
    fn omitted_quote_defaults_to_erg() {
        assert_eq!(validated(None).quote, "ERG");
    }

    #[test]
    fn lowercase_quote_normalizes_to_erg() {
        assert_eq!(validated(Some("erg")).quote, "ERG");
    }

    #[tokio::test]
    async fn no_liquidity_omits_optional_price_fields() {
        let discovery = StubDiscovery {
            result: Ok(snapshot(Vec::new(), None)),
        };

        let response = prices_response(&discovery, validated(None), 1_600_000_000_123);

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let json = response_json(response).await;
        let item = &json["items"][0];
        assert_eq!(item["token_id"], TOKEN_ID_HEX);
        assert_eq!(item["priced"], false);
        assert_eq!(item["reason"], "no_liquidity");
        assert!(item.get("price").is_none());
        assert!(item.get("source").is_none());
        assert!(item.get("warnings").is_none());
    }

    #[tokio::test]
    async fn unknown_decimals_omits_optional_price_fields() {
        let discovery = StubDiscovery {
            result: Ok(snapshot(vec![pool()], None)),
        };

        let response = prices_response(&discovery, validated(None), 1_600_000_000_123);

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let json = response_json(response).await;
        let item = &json["items"][0];
        assert_eq!(item["reason"], "decimals_unknown");
        assert!(item.get("price").is_none());
        assert!(item.get("source").is_none());
        assert!(item.get("warnings").is_none());
    }

    #[tokio::test]
    async fn priced_item_has_exact_price_and_one_hop_source() {
        let discovery = StubDiscovery {
            result: Ok(snapshot(vec![pool()], Some(6))),
        };

        let response = prices_response(&discovery, validated(None), 1_600_000_000_123);

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["quote"], "ERG");
        assert_eq!(json["height"], 700_000);
        assert_eq!(json["timestamp"], "2020-09-13T12:26:40.123Z");
        let item = &json["items"][0];
        assert_eq!(item["priced"], true);
        assert!(item.get("reason").is_none());
        assert_eq!(item["price"]["display"], "0.02458391");
        assert_eq!(item["price"]["raw"]["numerator"], "2458391");
        assert_eq!(item["price"]["raw"]["denominator"], "100000000");
        assert_eq!(item["price"]["token_decimals"], 6);
        assert_eq!(item["source"]["protocol"], "spectrum");
        assert_eq!(item["source"]["pool_type"], "N2T");
        assert_eq!(
            item["source"]["pool_box_id"],
            "0101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(item["source"]["path"].as_array().unwrap().len(), 1);
        assert_eq!(
            item["source"]["path"][0]["pool_box_id"],
            item["source"]["pool_box_id"]
        );
        assert_eq!(item["source"]["path"][0]["pool_type"], "N2T");
        assert_eq!(item["warnings"], serde_json::json!([]));
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[tokio::test]
    async fn missing_token_id_returns_invalid_token_id() {
        let response = validate_prices_query(PricesQuery::default()).unwrap_err();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(*response).await["error"]["reason"],
            "invalid_token_id"
        );
    }

    #[tokio::test]
    async fn malformed_token_id_returns_invalid_token_id() {
        let response = validate_prices_query(PricesQuery {
            token_id: Some("AA".repeat(32)),
            quote: None,
        })
        .unwrap_err();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(*response).await["error"]["reason"],
            "invalid_token_id"
        );
    }

    #[tokio::test]
    async fn unsupported_quote_returns_unsupported_quote() {
        let response = validate_prices_query(query(Some("USD"))).unwrap_err();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(*response).await["error"]["reason"],
            "unsupported_quote"
        );
    }

    #[tokio::test]
    async fn discovery_read_error_returns_internal_error() {
        let discovery = StubDiscovery {
            result: Err(DiscoveryError::Read(IndexerReadError::new("read failed"))),
        };

        let response = prices_response(&discovery, validated(None), 0);

        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let json = response_json(response).await;
        assert_eq!(json["error"]["reason"], "internal_error");
        // The raw indexer error is logged, never echoed to the client.
        let detail = json["error"]["detail"]
            .as_str()
            .expect("detail is a string");
        assert!(!detail.contains("read failed"));
        assert!(!detail.is_empty());
    }

    #[tokio::test]
    async fn discovery_limit_returns_pricing_unavailable() {
        let discovery = StubDiscovery {
            result: Err(DiscoveryError::LimitExceeded),
        };

        let response = prices_response(&discovery, validated(None), 0);

        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response_json(response).await["error"]["reason"],
            "pricing_unavailable"
        );
    }

    #[tokio::test]
    async fn unstable_index_returns_pricing_unavailable() {
        let discovery = StubDiscovery {
            result: Err(DiscoveryError::UnstableIndex),
        };

        let response = prices_response(&discovery, validated(None), 0);

        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response_json(response).await["error"]["reason"],
            "pricing_unavailable"
        );
    }

    // ----- oracle parity -----
}
