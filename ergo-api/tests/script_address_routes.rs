//! `GET /script/addressToTree/{address}` + `GET /script/addressToBytes/{address}`
//! — the two decode-only members of Scala's `ScriptApiRoute`.
//!
//! End-to-end routing/extractor coverage on top of the byte-parity unit tests
//! in `crate::utils`: drives the real handlers through axum routing with the
//! `NetworkPrefix` state, so the `Path`/`State` extractors and the error→400
//! mapping are exercised, not just the pure conversion core.
//!
//! Oracle vectors captured from the live Scala mainnet node (`:9053`):
//!   `/script/addressToTree/<ADDR>`  -> `{"tree":"0008cd03…068df"}`
//!   `/script/addressToBytes/<ADDR>` -> `{"bytes":"0e240008cd03…068df"}`
//! `addressToBytes` is the tree serialized as a `Coll[Byte]` constant:
//! `0x0e` (type) + VLQ length (`0x24` == 36) + the 36-byte P2PK tree.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use ergo_ser::address::NetworkPrefix;
use http_body_util::BodyExt;
use tower::ServiceExt;

const ADDR: &str = "9gZyL9m7J9eJv7h6gvxurbD986nWkw44NmHBgMkcxGezesPiETp";
const TREE: &str = "0008cd030e0048c32f4c804c809edfdff3f3fb70154e5066d0c4e04a767bb5bd149068df";

fn app() -> Router {
    Router::new()
        .route(
            "/script/addressToTree/:address",
            get(ergo_api::utils::script_address_to_tree_handler),
        )
        .route(
            "/script/addressToBytes/:address",
            get(ergo_api::utils::script_address_to_bytes_handler),
        )
        .with_state(NetworkPrefix::Mainnet)
}

async fn get_json(path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn address_to_tree_route_serves_oracle_tree() {
    let (status, body) = get_json(&format!("/script/addressToTree/{ADDR}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tree"], TREE);
}

#[tokio::test]
async fn address_to_bytes_route_serves_coll_byte_constant() {
    let (status, body) = get_json(&format!("/script/addressToBytes/{ADDR}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["bytes"], format!("0e24{TREE}"));
}

#[tokio::test]
async fn invalid_address_is_bad_request() {
    let (status, body) = get_json("/script/addressToTree/not-a-real-address").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Pin the error envelope, not just the status: `{error, reason, detail}`
    // is the contract every route in this API shares (`bad_request`).
    assert_eq!(body["error"], 400);
    assert_eq!(body["reason"], "bad-request");
    // `detail`'s prefix is OUR AddressDecodeError variant ("invalid base58");
    // the remainder is the bs58 crate's message — deliberately not pinned so
    // a dependency bump can't break the test.
    let detail = body["detail"].as_str().expect("detail is a string");
    assert!(
        detail.starts_with("invalid base58"),
        "detail should name the decode failure, got: {detail}"
    );
}
