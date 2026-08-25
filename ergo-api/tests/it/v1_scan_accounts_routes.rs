//! Route tests for the v1 scan/accounts group (`/api/v1/scan/*`,
//! `/api/v1/accounts/*` — `v1-api-design.md` §3.10–§3.11).
//!
//! Proves: (1) scan register/list are T1-gated (no key → 401, valid key → ok);
//! (2) watch-only reads are public T0, writes T1; (3) named-account and PSBT
//! surfaces answer honest `route_unavailable`; and — critically — (4) the T2
//! private-key export is reachable ONLY with an admin key from loopback: a
//! keyless caller is 401 and a keyed non-loopback caller under hard-deny is
//! rejected at the gate BEFORE the secret handler ever runs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
use ergo_api::v1::{accounts_router, AccountsState, GovernorConfig, V1AuthConfig};
use ergo_api::wallet::admin_advanced::{
    DeriveKeyRequest, DeriveKeyResponse, DeriveNextKeyResponse, GetPrivateKeyRequest,
    GetPrivateKeyResponse,
};
use ergo_api::wallet::multi_sig::{
    GenerateCommitmentsRequest, GenerateCommitmentsResponse, HintExtractionRequest,
    HintExtractionResponse,
};
use ergo_api::wallet::scan::{ScanBoxEntry, ScanBoxFilter, ScanDto, ScanRequestDto};
use ergo_api::wallet::sending::{
    BoxesCollectRequest, BoxesCollectResponse, PaymentRequestDto, TransactionGenerateRequest,
    TransactionGenerateResponse, TransactionGenerateUnsignedRequest,
    TransactionGenerateUnsignedResponse, TransactionSendRequest, TransactionSignRequest,
    TransactionSignResponse,
};
use ergo_api::wallet::types::*;
use ergo_api::wallet::{WalletAdmin, WalletAdminError};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

const KEY: &[u8] = b"a-strong-rotated-operator-secret-2026";
const ADDR: &str = "9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zexg6N8v";
const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Stateful scan mock: register/list/deregister + a preset watch-only
/// (`wallet_interaction="off"`) scan, and a `get_private_key` that succeeds so
/// the T2 handler is exercised when — and only when — the gate lets it through.
#[derive(Default)]
struct Mock {
    scans: Mutex<Vec<ScanDto>>,
    last: Mutex<u16>,
}

#[async_trait::async_trait]
impl WalletAdmin for Mock {
    async fn register_scan(&self, request: ScanRequestDto) -> Result<u16, WalletAdminError> {
        let mut last = self.last.lock().unwrap();
        let id = (*last).max(10) + 1;
        *last = id;
        self.scans.lock().unwrap().push(ScanDto {
            scan_id: id,
            scan_name: request.scan_name,
            tracking_rule: request.tracking_rule,
            wallet_interaction: request
                .wallet_interaction
                .unwrap_or_else(|| "shared".into()),
            remove_offchain: request.remove_offchain.unwrap_or(true),
        });
        Ok(id)
    }
    async fn deregister_scan(&self, scan_id: u16) -> Result<(), WalletAdminError> {
        let mut scans = self.scans.lock().unwrap();
        let before = scans.len();
        scans.retain(|s| s.scan_id != scan_id);
        if scans.len() < before {
            Ok(())
        } else {
            Err(WalletAdminError::BadRequest(format!("no scan {scan_id}")))
        }
    }
    async fn list_scans(&self) -> Result<Vec<ScanDto>, WalletAdminError> {
        let mut out = vec![ScanDto {
            scan_id: 7,
            scan_name: "watched".into(),
            tracking_rule: serde_json::json!({"predicate": "equals"}),
            wallet_interaction: "off".into(),
            remove_offchain: false,
        }];
        out.extend(self.scans.lock().unwrap().iter().cloned());
        out.sort_by_key(|s| s.scan_id);
        Ok(out)
    }
    async fn scan_unspent_boxes(
        &self,
        scan_id: u16,
        filter: ScanBoxFilter,
    ) -> Result<Vec<ScanBoxEntry>, WalletAdminError> {
        if scan_id != 7 {
            return Ok(vec![]);
        }
        Ok(vec![ScanBoxEntry {
            box_id: "ab".repeat(32),
            value: 1_000_000,
            inclusion_height: Some(filter.min_inclusion_height.max(0) as u32),
            confirmations_num: Some(3),
            spent: false,
            bytes: "00".into(),
        }])
    }
    async fn scan_p2s_rule(&self, _p2s: String) -> Result<u16, WalletAdminError> {
        Ok(99)
    }
    async fn get_private_key(
        &self,
        _: GetPrivateKeyRequest,
    ) -> Result<GetPrivateKeyResponse, WalletAdminError> {
        Ok(GetPrivateKeyResponse { w: "de".repeat(32) })
    }

    // ----- unused by these routes -----
    async fn scan_spent_boxes(
        &self,
        _: u16,
        _: ScanBoxFilter,
    ) -> Result<Vec<ScanBoxEntry>, WalletAdminError> {
        Ok(vec![])
    }
    async fn scan_stop_tracking(&self, _: u16, _: String) -> Result<(), WalletAdminError> {
        Ok(())
    }
    async fn scan_add_box(
        &self,
        _: Vec<u16>,
        _: serde_json::Value,
    ) -> Result<String, WalletAdminError> {
        Ok("cd".repeat(32))
    }
    async fn status(&self) -> Result<WalletStatus, WalletAdminError> {
        unimplemented!()
    }
    async fn init(&self, _: String, _: String, _: u8) -> Result<String, WalletAdminError> {
        unimplemented!()
    }
    async fn restore(
        &self,
        _: String,
        _: String,
        _: String,
        _: bool,
    ) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn unlock(&self, _: String) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn lock(&self) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn check(&self, _: String, _: String) -> Result<bool, WalletAdminError> {
        unimplemented!()
    }
    async fn rescan(&self, _: u32) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn update_change_address(&self, _: String) -> Result<(), WalletAdminError> {
        unimplemented!()
    }
    async fn balances(&self) -> Result<WalletBalances, WalletAdminError> {
        unimplemented!()
    }
    async fn balances_with_unconfirmed(&self) -> Result<WalletBalances, WalletAdminError> {
        unimplemented!()
    }
    async fn addresses(&self) -> Result<WalletAddressList, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes(&self, _: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes_unspent(&self, _: Page) -> Result<WalletBoxesPage, WalletAdminError> {
        unimplemented!()
    }
    async fn transactions(&self, _: Page) -> Result<WalletTransactionsPage, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_by_id(
        &self,
        _: String,
    ) -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
        unimplemented!()
    }
    async fn transactions_by_scan_id(
        &self,
        _: u32,
        _: Page,
    ) -> Result<WalletTransactionsPage, WalletAdminError> {
        Ok(WalletTransactionsPage {
            total: 0,
            items: vec![],
        })
    }
    async fn payment_send(&self, _: Vec<PaymentRequestDto>) -> Result<String, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_generate(
        &self,
        _: TransactionGenerateRequest,
    ) -> Result<TransactionGenerateResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_generate_unsigned(
        &self,
        _: TransactionGenerateUnsignedRequest,
    ) -> Result<TransactionGenerateUnsignedResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_sign(
        &self,
        _: TransactionSignRequest,
    ) -> Result<TransactionSignResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn transaction_send(
        &self,
        _: TransactionSendRequest,
    ) -> Result<String, WalletAdminError> {
        unimplemented!()
    }
    async fn boxes_collect(
        &self,
        _: BoxesCollectRequest,
    ) -> Result<BoxesCollectResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn generate_commitments(
        &self,
        _: GenerateCommitmentsRequest,
    ) -> Result<GenerateCommitmentsResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn extract_hints(
        &self,
        _: HintExtractionRequest,
    ) -> Result<HintExtractionResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn derive_key(&self, _: DeriveKeyRequest) -> Result<DeriveKeyResponse, WalletAdminError> {
        unimplemented!()
    }
    async fn derive_next_key(&self) -> Result<DeriveNextKeyResponse, WalletAdminError> {
        unimplemented!()
    }
}

fn app(hard_deny: bool) -> axum::Router {
    let sec = Arc::new(ApiSecurity::new(ApiSecurity::hash_key(KEY)).unwrap());
    let auth = V1AuthConfig::new(Some(sec))
        .with_admin_hard_deny(hard_deny)
        .into_shared();
    let governor = ergo_api::v1::Governor::new(GovernorConfig::default()).unwrap();
    let state = AccountsState {
        admin: Arc::new(Mock::default()),
        network: NetworkPrefix::Mainnet,
    };
    accounts_router(state, governor, auth)
}

fn req(
    method: Method,
    uri: &str,
    key: Option<&[u8]>,
    body: Body,
    peer: Option<IpAddr>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        b = b.header(API_KEY_HEADER, String::from_utf8_lossy(k).to_string());
    }
    b = b.header("content-type", "application/json");
    let mut r = b.body(body).unwrap();
    if let Some(ip) = peer {
        r.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40000)));
    }
    r
}

async fn status_of(app: axum::Router, r: Request<Body>) -> StatusCode {
    app.oneshot(r).await.unwrap().status()
}

async fn json_of(app: axum::Router, r: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.oneshot(r).await.unwrap();
    let st = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (st, v)
}

// ----- scan T1 gating -----

#[tokio::test]
async fn scan_register_without_key_is_401() {
    let r = req(
        Method::POST,
        "/api/v1/scan/scans",
        None,
        Body::from(r#"{"name":"x","tracking_rule":{}}"#),
        Some(REMOTE),
    );
    assert_eq!(status_of(app(false), r).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn scan_register_and_list_with_key() {
    let a = app(false);
    let (st, v) = json_of(
        a.clone(),
        req(
            Method::POST,
            "/api/v1/scan/scans",
            Some(KEY),
            Body::from(r#"{"name":"assets","tracking_rule":{"predicate":"equals"}}"#),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "register: {v}");
    assert_eq!(v["scan_id"], 11);

    let (st, v) = json_of(
        a,
        req(
            Method::GET,
            "/api/v1/scan/scans",
            Some(KEY),
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(v["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["scan_id"] == 11));
    assert!(v["page"]["has_more"].is_boolean());
}

#[tokio::test]
async fn scan_get_one_missing_is_404() {
    let (st, v) = json_of(
        app(false),
        req(
            Method::GET,
            "/api/v1/scan/scans/999",
            Some(KEY),
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["reason"], "scan_not_found");
}

// ----- watch-only: T0 read, T1 write, backed by scan machinery -----

#[tokio::test]
async fn watch_list_is_public_t0() {
    // No key: watch reads are public (T0), governor-bounded only.
    let (st, v) = json_of(
        app(false),
        req(
            Method::GET,
            "/api/v1/accounts/watch",
            None,
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // The preset wallet_interaction="off" scan surfaces as a watch entry.
    assert!(v["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["scan_id"] == 7));
}

#[tokio::test]
async fn watch_unspent_read_is_backed_t0() {
    let (st, v) = json_of(
        app(false),
        req(
            Method::GET,
            "/api/v1/accounts/watch/7/unspent",
            None,
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["items"][0]["value"], "1000000");
}

#[tokio::test]
async fn watch_register_without_key_is_401() {
    let r = req(
        Method::POST,
        "/api/v1/accounts/watch",
        None,
        Body::from(format!(r#"{{"address":"{ADDR}"}}"#)),
        Some(REMOTE),
    );
    assert_eq!(status_of(app(false), r).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn watch_register_with_key_ok() {
    let (st, v) = json_of(
        app(false),
        req(
            Method::POST,
            "/api/v1/accounts/watch",
            Some(KEY),
            Body::from(format!(r#"{{"address":"{ADDR}","label":"exchange"}}"#)),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "watch register: {v}");
    assert_eq!(v["scan_id"], 99);
    assert_eq!(v["address"], ADDR);
}

// ----- account + PSBT honest seams -----

#[tokio::test]
async fn named_accounts_answer_route_unavailable() {
    let (st, v) = json_of(
        app(false),
        req(
            Method::GET,
            "/api/v1/accounts",
            Some(KEY),
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["reason"], "route_unavailable");
}

#[tokio::test]
async fn psbt_answers_route_unavailable() {
    let (st, v) = json_of(
        app(false),
        req(
            Method::POST,
            "/api/v1/transactions-psbt",
            Some(KEY),
            Body::from("{}"),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["reason"], "route_unavailable");
}

// ----- T2 private-key export: the unforgivable-bug surface -----

#[tokio::test]
async fn private_key_export_without_key_is_401() {
    let r = req(
        Method::POST,
        "/api/v1/accounts/private-key",
        None,
        Body::from(format!(r#"{{"address":"{ADDR}","acknowledge":true}}"#)),
        Some(LOCAL),
    );
    assert_eq!(status_of(app(false), r).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn private_key_export_keyed_but_remote_is_rejected_under_hard_deny() {
    // A valid operator key from a NON-loopback peer must NOT reach the secret
    // handler under admin hard-deny: the gate answers sensitive_op_disabled
    // BEFORE get_private_key runs. This is the "not weaker than admin+loopback"
    // guarantee for secret material.
    let (st, v) = json_of(
        app(true),
        req(
            Method::POST,
            "/api/v1/accounts/private-key",
            Some(KEY),
            Body::from(format!(r#"{{"address":"{ADDR}","acknowledge":true}}"#)),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(v["error"]["reason"], "sensitive_op_disabled");
    // The secret must NOT be present in the rejected response.
    assert!(v.get("private_key").is_none());
}

#[tokio::test]
async fn private_key_export_reaches_handler_only_from_loopback_admin() {
    // Valid key + loopback passes the T2 gate; the handler then requires the
    // explicit acknowledgement before returning the scalar.
    let a = app(true);
    let (st, v) = json_of(
        a.clone(),
        req(
            Method::POST,
            "/api/v1/accounts/private-key",
            Some(KEY),
            Body::from(format!(r#"{{"address":"{ADDR}","acknowledge":false}}"#)),
            Some(LOCAL),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(v["error"]["reason"], "acknowledgement_required");

    let (st, v) = json_of(
        a,
        req(
            Method::POST,
            "/api/v1/accounts/private-key",
            Some(KEY),
            Body::from(format!(r#"{{"address":"{ADDR}","acknowledge":true}}"#)),
            Some(LOCAL),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "acked loopback admin: {v}");
    assert_eq!(v["private_key"], "de".repeat(32));
}

// ----- route smoke coverage: wiring + tier gating (CodeRabbit #185) --------

#[tokio::test]
async fn scan_deregister_with_key_deletes_then_404s() {
    let a = app(false);
    let (st, v) = json_of(
        a.clone(),
        req(
            Method::POST,
            "/api/v1/scan/scans",
            Some(KEY),
            Body::from(r#"{"name":"temp","tracking_rule":{"predicate":"equals"}}"#),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "register: {v}");
    let id = v["scan_id"].as_u64().unwrap();

    let uri = format!("/api/v1/scan/scans/{id}");
    let st = status_of(
        a.clone(),
        req(Method::DELETE, &uri, Some(KEY), Body::empty(), Some(REMOTE)),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    // NOTE: the mock is per-app (each `app()` is fresh), so re-deleting the
    // synthetic-only id against a fresh app 404s.
    let (st, v) = json_of(
        app(false),
        req(Method::DELETE, &uri, Some(KEY), Body::empty(), Some(REMOTE)),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "re-delete: {v}");
}

#[tokio::test]
async fn scan_unspent_with_key_lists_boxes_and_accepts_full_limit() {
    // Regression: the overfetch-by-one probe used to push a valid large
    // `?limit` past the ScanBoxFilter 1..=2500 validator bound → 400.
    let (st, v) = json_of(
        app(false),
        req(
            Method::GET,
            "/api/v1/scan/scans/7/unspent?limit=2500",
            Some(KEY),
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "unspent: {v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert_eq!(v["items"][0]["box_id"], "ab".repeat(32));
}

#[tokio::test]
async fn scan_transactions_with_key_is_page() {
    let (st, v) = json_of(
        app(false),
        req(
            Method::GET,
            "/api/v1/scan/scans/7/transactions",
            Some(KEY),
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "transactions: {v}");
    assert!(v["items"].is_array());
}

#[tokio::test]
async fn scan_attach_and_detach_box_dispatch_to_admin() {
    let a = app(false);
    let (st, v) = json_of(
        a.clone(),
        req(
            Method::POST,
            "/api/v1/scan/scans/7/boxes",
            Some(KEY),
            Body::from(r#"{"box":{"value":1}}"#),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "attach: {v}");
    assert_eq!(v["box_id"], "cd".repeat(32));

    let uri = format!("/api/v1/scan/scans/7/boxes/{}", "ab".repeat(32));
    let (st, v) = json_of(
        a,
        req(Method::DELETE, &uri, Some(KEY), Body::empty(), Some(REMOTE)),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "detach: {v}");
    assert_eq!(v["scan_id"], 7);
}

#[tokio::test]
async fn scan_writes_without_key_are_401() {
    for (method, uri) in [
        (Method::DELETE, "/api/v1/scan/scans/7".to_string()),
        (Method::GET, "/api/v1/scan/scans/7/unspent".to_string()),
        (Method::GET, "/api/v1/scan/scans/7/transactions".to_string()),
        (Method::POST, "/api/v1/scan/scans/7/boxes".to_string()),
        (
            Method::DELETE,
            format!("/api/v1/scan/scans/7/boxes/{}", "ab".repeat(32)),
        ),
        (Method::DELETE, "/api/v1/accounts/watch/7".to_string()),
    ] {
        let st = status_of(
            app(false),
            req(method.clone(), &uri, None, Body::empty(), Some(REMOTE)),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

#[tokio::test]
async fn watch_delete_with_key_removes_registered_scan() {
    let a = app(false);
    let (st, v) = json_of(
        a.clone(),
        req(
            Method::POST,
            "/api/v1/scan/scans",
            Some(KEY),
            Body::from(r#"{"name":"w","tracking_rule":{},"wallet_interaction":"off"}"#),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "register: {v}");
    let uri = format!("/api/v1/accounts/watch/{}", v["scan_id"]);
    let (st, v) = json_of(
        a,
        req(Method::DELETE, &uri, Some(KEY), Body::empty(), Some(REMOTE)),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "watch delete: {v}");
}

// ----- T0 watch unspent is scoped to watch-only scans ----------------------

#[tokio::test]
async fn watch_unspent_serves_watch_only_scan_publicly() {
    // Scan 7 is the mock's watch-only scan — public (no key) read works.
    let (st, v) = json_of(
        app(false),
        req(
            Method::GET,
            "/api/v1/accounts/watch/7/unspent",
            None,
            Body::empty(),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "watch unspent: {v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn watch_unspent_hides_wallet_interacting_scans() {
    // Regression: the public T0 mount used the unscoped handler, exposing
    // operator (wallet-interacting) scans without a key.
    let a = app(false);
    let (st, v) = json_of(
        a.clone(),
        req(
            Method::POST,
            "/api/v1/scan/scans",
            Some(KEY),
            Body::from(r#"{"name":"op","tracking_rule":{}}"#),
            Some(REMOTE),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "register: {v}");
    let id = v["scan_id"].as_u64().unwrap(); // wallet_interaction defaults "shared"

    let uri = format!("/api/v1/accounts/watch/{id}/unspent");
    let (st, v) = json_of(
        a.clone(),
        req(Method::GET, &uri, None, Body::empty(), Some(REMOTE)),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "public read must hide it: {v}");
    assert_eq!(v["error"]["reason"], "scan_not_found");

    // The T1 api-key mount still serves the same scan.
    let uri = format!("/api/v1/scan/scans/{id}/unspent");
    let st = status_of(
        a,
        req(Method::GET, &uri, Some(KEY), Body::empty(), Some(REMOTE)),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}
