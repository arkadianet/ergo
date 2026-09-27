use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use ergo_primitives::digest::ModifierId;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_wallet_service::{ChainClient, ChainClientError, CommittedTip};
use reqwest::Url;

use ergo_walletd::chain_http::HttpChainClient;
use ergo_walletd::config::ApiKey;

fn id(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn sample_box(tx_id: [u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let tree = ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: true,
        constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        },
    };
    let candidate =
        ErgoBoxCandidate::new(1, tree, 1, Vec::new(), AdditionalRegisters::empty()).unwrap();
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id),
        index: 0,
    };
    let box_id = *ergo_box.box_id().unwrap().as_bytes();
    (serialize_ergo_box(&ergo_box).unwrap(), box_id)
}

fn serve_once<F>(handler: F) -> (String, thread::JoinHandle<()>)
where
    F: FnOnce(String, String) -> (u16, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = vec![0u8; 8192];
        let count = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..count]).to_string();
        let mut lines = request.lines();
        let first = lines.next().unwrap_or_default().to_string();
        let path = first
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string();
        let header = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("api_key:"))
            .unwrap_or_default()
            .to_string();
        let (status, body) = handler(path, header);
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    (format!("http://{address}/"), handle)
}

fn client(url: &str) -> HttpChainClient {
    HttpChainClient::with_timeouts(
        Url::parse(url).unwrap(),
        ApiKey::from_test(b"secret".to_vec()),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(2),
    )
    .unwrap()
}

#[test]
fn auth_header_is_sent_and_status_mapping_is_typed() {
    let (url, handle) = serve_once(|path, header| {
        assert!(path.starts_with("/api/v1/chain/tip"));
        assert!(header.to_ascii_lowercase().contains("secret"));
        (200, format!(r#"{{"height":1,"headerId":"{}"}}"#, id(1)))
    });
    assert_eq!(client(&url).committed_tip().unwrap().height, 1);
    handle.join().unwrap();

    let (url, handle) = serve_once(|_, _| {
        (
            410,
            format!(
                r#"{{"type":"pruned","tip":{{"height":9,"headerId":"{}"}},"minimumHeight":4}}"#,
                id(9)
            ),
        )
    });
    let error = client(&url)
        .blocks_since(ergo_wallet_service::BlocksSinceRequest {
            cursor: ergo_wallet_service::ChainCursor::genesis(),
            limit: 1,
        })
        .unwrap_err();
    assert!(matches!(
        error,
        ChainClientError::HistoryPruned {
            minimum_height: Some(4)
        }
    ));
    handle.join().unwrap();

    let (url, handle) = serve_once(|_, _| (409, "stale".to_string()));
    assert!(matches!(
        client(&url).committed_tip(),
        Err(ChainClientError::Conflict)
    ));
    handle.join().unwrap();
}

#[test]
fn not_found_box_lookup_is_an_explicit_absent_utxo() {
    let (url, handle) = serve_once(|path, _| {
        assert!(path.starts_with("/api/v1/chain/boxes/"));
        (404, "not found".to_string())
    });
    let lookup = client(&url)
        .lookup_utxo([3; 32], CommittedTip::new(1, [1; 32]))
        .unwrap();
    assert!(lookup.utxo.is_none());
    assert_eq!(lookup.tip, CommittedTip::new(1, [1; 32]));
    handle.join().unwrap();
}

#[test]
fn canonical_box_identity_and_forward_tip_identity_are_checked() {
    let (bytes, box_id) = sample_box([4; 32]);
    let (url, handle) = serve_once(move |_, _| {
        (
            200,
            format!(
                r#"{{"tip":{{"height":1,"headerId":"{}"}},"box":{{"boxId":"{}","bytes":"{}","value":"2","assets":[],"creationTxId":"{}","creationOutputIndex":0,"creationHeight":1}}}}"#,
                id(1),
                id(3),
                hex::encode(&bytes),
                id(4)
            ),
        )
    });
    assert!(matches!(
        client(&url).lookup_utxo(box_id, CommittedTip::new(1, [1; 32])),
        Err(ChainClientError::Protocol(_))
    ));
    handle.join().unwrap();

    let (url, handle) = serve_once(|_, _| {
        (
            200,
            format!(
                r#"{{"type":"forward","tip":{{"height":1,"headerId":"{}"}},"blocks":[{{"blockId":"{}","height":1,"parentId":"{}","transactions":[]}}]}}"#,
                id(2),
                id(1),
                id(0)
            ),
        )
    });
    assert!(matches!(
        client(&url).blocks_since(ergo_wallet_service::BlocksSinceRequest {
            cursor: ergo_wallet_service::ChainCursor::genesis(),
            limit: 1,
        }),
        Err(ChainClientError::Protocol(_))
    ));
    handle.join().unwrap();
}
