//! Transport/auth tests on the real merged production router. Journal integrity
//! and pending-job invisibility are exercised against a real DB in ergo-node.
use std::sync::{Arc, Condvar, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ergo_api::auth::ApiSecurity;
use ergo_api::evidence::*;
use ergo_api::server::{
    router_with_mempool_and_wallet_and_security_and_inventory, RouteOperation, ServerCtx,
};
use ergo_api::traits::{NodeReadState, NoopMempoolView};
use ergo_api::types::*;
use ergo_api::wallet::NoopWalletAdmin;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

const PATH: &str = "/api/v1/evidence/committed";

struct Reader {
    calls: Mutex<Vec<(Option<EvidenceCursor>, usize)>>,
    error: bool,
    oversized: bool,
    blocker: Option<Arc<(Mutex<bool>, Condvar)>>,
}
impl CommittedEvidenceReader for Reader {
    fn read_committed(
        &self,
        after: Option<&EvidenceCursor>,
        limit: usize,
    ) -> Result<CommittedEvidencePage, EvidenceReadError> {
        self.calls.lock().unwrap().push((after.cloned(), limit));
        if let Some(blocker) = &self.blocker {
            let (released, ready) = blocker.as_ref();
            let _released = ready
                .wait_while(released.lock().unwrap(), |released| !*released)
                .unwrap();
        }
        if self.error {
            return Err(EvidenceReadError::ReconstructionRequired(
                "journal gap; reconstruction required".into(),
            ));
        }
        let cursor = EvidenceCursor {
            archive_id: "11".repeat(32),
            sequence: 1,
            event_hash: "22".repeat(32),
        };
        Ok(CommittedEvidencePage {
            schema: "ergo-committed-evidence-page-v1".into(),
            source: EvidenceSource {
                kind: "committedRedbJournal".into(),
                configured_genesis_anchor: "33".repeat(32),
            },
            meta: EvidenceMeta {
                archive_id: cursor.archive_id.clone(),
                anchor_id: "33".repeat(32),
                cursor: cursor.clone(),
                branch_generation: 0,
                tip_id: "44".repeat(32),
                tip_height: 1,
                reconstruction_required: false,
            },
            events: vec![EvidenceRecord {
                event_json: if self.oversized {
                    "x".repeat(MAX_EVIDENCE_RESPONSE_BYTES)
                } else {
                    "{\"sequence\":1}".into()
                },
                event_hash: cursor.event_hash.clone(),
            }],
            next_cursor: cursor,
        })
    }
}
struct Read(Option<Arc<Reader>>);
impl NodeReadState for Read {
    fn committed_evidence_reader(&self) -> Option<EvidenceReaderHandle> {
        self.0.clone().map(|value| value as EvidenceReaderHandle)
    }
    fn info(&self) -> ApiInfo {
        unreachable!()
    }
    fn status(&self) -> ApiStatus {
        unreachable!()
    }
    fn tip(&self) -> ApiTip {
        unreachable!()
    }
    fn sync(&self) -> ApiSyncStatus {
        unreachable!()
    }
    fn peers(&self) -> Vec<ApiPeer> {
        unreachable!()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        unreachable!()
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        unreachable!()
    }
    fn mempool_transaction(&self, _: &str) -> Option<ApiMempoolTransaction> {
        unreachable!()
    }
    fn health(&self) -> ApiHealth {
        unreachable!()
    }
}

fn reader(error: bool, oversized: bool) -> Arc<Reader> {
    Arc::new(Reader {
        calls: Mutex::new(vec![]),
        error,
        oversized,
        blocker: None,
    })
}
fn app(reader: Option<Arc<Reader>>, secured: bool) -> axum::Router {
    let context = ServerCtx {
        read: Arc::new(Read(reader.clone())),
        compat: None,
        submit: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    let security =
        secured.then(|| Arc::new(ApiSecurity::new(ApiSecurity::hash_key(b"reader-key")).unwrap()));
    let (router, inventory) = router_with_mempool_and_wallet_and_security_and_inventory(
        context,
        None,
        Arc::new(NoopWalletAdmin),
        security,
    );
    assert_eq!(
        inventory.rust.contains(&RouteOperation::new(PATH, "get")),
        reader.is_some() && secured
    );
    router
}
fn request(path: &str, key: Option<&str>, body: Body) -> Request<Body> {
    let mut builder = Request::builder().uri(path);
    if let Some(key) = key {
        builder = builder.header("api_key", key);
    }
    builder.body(body).unwrap()
}
async fn result(
    app: axum::Router,
    path: &str,
    key: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(request(path, key, Body::empty()))
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), MAX_EVIDENCE_RESPONSE_BYTES + 1)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn committed_reader_mount_requires_both_real_reader_and_security() {
    for (configured, secured) in [(false, false), (false, true), (true, false)] {
        let configured = configured.then(|| reader(false, false));
        let (status, _) = result(app(configured, secured), PATH, Some("reader-key")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn committed_reader_requires_header_api_key_before_calling_reader() {
    let reader = reader(false, false);
    let router = app(Some(reader.clone()), true);
    for key in [None, Some("wrong")] {
        let (status, body) = result(router.clone(), PATH, key).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["reason"], "invalid.api-key");
    }
    let (status, _) = result(router.clone(), &format!("{PATH}?api_key=reader-key"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(reader.calls.lock().unwrap().is_empty());
    let (status, body) = result(router, PATH, Some("reader-key")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["source"]["configuredGenesisAnchor"], "33".repeat(32));
    assert_eq!(body["meta"]["tipHeight"], 1);
    assert_eq!(body["events"][0]["eventJson"], "{\"sequence\":1}");
    assert!(body.get("authenticated").is_none());
    assert_eq!(reader.calls.lock().unwrap()[0], (None, 1));
}

#[tokio::test]
async fn committed_reader_validates_complete_exact_cursor_and_bounded_query() {
    let reader = reader(false, false);
    let router = app(Some(reader.clone()), true);
    for query in [
        "limit=0",
        "limit=17",
        "limit=01",
        "limit=1.0",
        "afterSequence=1",
        "authenticated=true",
        "limit=1&limit=2",
    ] {
        let (status, _) = result(
            router.clone(),
            &format!("{PATH}?{query}"),
            Some("reader-key"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
    let long = format!("{PATH}?afterArchiveId={}", "a".repeat(513));
    assert_eq!(
        result(router.clone(), &long, Some("reader-key")).await.0,
        StatusCode::BAD_REQUEST
    );
    for sequence in ["9007199254740992", "01", "-1"] {
        let query = format!(
            "{PATH}?afterArchiveId={}&afterSequence={sequence}&afterEventHash={}",
            "11".repeat(32),
            "22".repeat(32)
        );
        assert_eq!(
            result(router.clone(), &query, Some("reader-key")).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(reader.calls.lock().unwrap().is_empty());
    let path = format!(
        "{PATH}?limit=16&afterArchiveId={}&afterSequence=1&afterEventHash={}",
        "11".repeat(32),
        "22".repeat(32)
    );
    assert_eq!(
        result(router, &path, Some("reader-key")).await.0,
        StatusCode::OK
    );
    assert_eq!(reader.calls.lock().unwrap()[0].1, 16);
    assert_eq!(
        reader.calls.lock().unwrap()[0].0.as_ref().unwrap().sequence,
        1
    );
}

#[tokio::test]
async fn committed_reader_returns_reconstruction_error_without_a_success_cursor() {
    let (status, body) = result(
        app(Some(reader(true, false)), true),
        PATH,
        Some("reader-key"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "reconstruction_required");
    assert!(body.get("nextCursor").is_none());
}

#[tokio::test]
async fn committed_reader_refuses_get_bodies_and_oversized_response_atomically() {
    let fixture = reader(false, false);
    let router = app(Some(fixture.clone()), true);
    let response = router
        .oneshot(request(PATH, Some("reader-key"), Body::from("x")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(fixture.calls.lock().unwrap().is_empty());
    let (status, body) = result(
        app(Some(reader(false, true)), true),
        PATH,
        Some("reader-key"),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["reason"], "page_too_large");
    assert!(body.get("nextCursor").is_none());
}

#[tokio::test]
async fn committed_reader_has_two_bounded_workers_and_refuses_a_third() {
    struct Release(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            let (released, ready) = self.0.as_ref();
            *released.lock().unwrap() = true;
            ready.notify_all();
        }
    }
    let blocker = Arc::new((Mutex::new(false), Condvar::new()));
    let release = Release(blocker.clone());
    let fixture = Arc::new(Reader {
        calls: Mutex::new(vec![]),
        error: false,
        oversized: false,
        blocker: Some(blocker),
    });
    let router = app(Some(fixture.clone()), true);
    let first = tokio::spawn(result(router.clone(), PATH, Some("reader-key")));
    let second = tokio::spawn(result(router.clone(), PATH, Some("reader-key")));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while fixture.calls.lock().unwrap().len() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (status, body) = result(router, PATH, Some("reader-key")).await;
    drop(release);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "reader_busy");
    assert_eq!(fixture.calls.lock().unwrap().len(), 2);
    assert_eq!(first.await.unwrap().0, StatusCode::OK);
    assert_eq!(second.await.unwrap().0, StatusCode::OK);
}
