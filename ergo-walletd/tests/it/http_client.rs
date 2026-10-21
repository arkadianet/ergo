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
        reserved_header_bits: 0,
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

// ----- the node's address index -----

/// Serve `requests` requests, one connection each, answering from `handler`
/// with `(status, body)` for the request path.
fn serve_many<F>(requests: usize, handler: F) -> (String, thread::JoinHandle<Vec<String>>)
where
    F: Fn(&str) -> (u16, String) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = vec![0u8; 8192];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]).to_string();
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            let (status, body) = handler(&path);
            seen.push(path);
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
        seen
    });
    (format!("http://{address}/"), handle)
}

const KEY: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

fn indexed_tx(number: u32) -> String {
    format!(
        r#"{{"id":"{}","inclusionHeight":{},"blockId":"{}","inputs":[],"outputs":[]}}"#,
        hex::encode([number as u8; 32]),
        number,
        hex::encode([0xB0 | (number as u8 & 0x0F); 32]),
    )
}

fn page_of(path: &str, total: u32) -> String {
    let query = path.split_once('?').map_or("", |(_, query)| query);
    let value = |name: &str| -> u32 {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .unwrap()
            .parse()
            .unwrap()
    };
    let (offset, limit) = (value("offset"), value("limit"));
    let items: Vec<String> = (offset..total.min(offset + limit))
        .map(|number| indexed_tx(number + 1))
        .collect();
    format!(r#"{{"items":[{}],"total":{total}}}"#, items.join(","))
}

const CAUGHT_UP: &str = r#"{"indexedHeight":120,"fullHeight":120,"status":"caughtUp"}"#;

fn key_tree() -> Vec<u8> {
    ergo_ser::address::build_p2pk_tree_bytes(&KEY).unwrap()
}

#[test]
fn address_history_reads_every_page_of_the_index_listing() {
    // 120 transactions: three pages of 50, 50 and 20, after the height probe.
    let (url, handle) = serve_many(4, |path| {
        if path.starts_with("/blockchain/indexedHeight") {
            (200, CAUGHT_UP.to_string())
        } else {
            assert!(
                path.starts_with("/blockchain/transaction/byAddress/"),
                "{path}"
            );
            (200, page_of(path, 120))
        }
    });
    let history = client(&url)
        .address_history(ergo_ser::address::NetworkPrefix::Testnet, &[key_tree()])
        .unwrap()
        .unwrap();
    assert_eq!(history.indexed_height, 120);
    assert_eq!(history.transactions.len(), 120);
    assert_eq!(history.transactions[0].height, 1);
    assert_eq!(history.transactions[119].height, 120);
    let seen = handle.join().unwrap();
    assert!(seen[1].contains("offset=0&limit=50"), "{seen:?}");
    assert!(seen[2].contains("offset=50&limit=50"), "{seen:?}");
    assert!(seen[3].contains("offset=100&limit=50"), "{seen:?}");
}

#[test]
fn a_listing_that_moves_while_it_is_read_is_read_again() {
    // The first read sees a total of 60, then 61 on its second page: a block
    // arrived and shifted the pages. The second attempt sees a steady 61.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let (url, handle) = serve_many(1 + 2 + 2, move |path| {
        if path.starts_with("/blockchain/indexedHeight") {
            return (200, CAUGHT_UP.to_string());
        }
        let call = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let total = if call == 0 { 60 } else { 61 };
        (200, page_of(path, total))
    });
    let history = client(&url)
        .address_history(ergo_ser::address::NetworkPrefix::Testnet, &[key_tree()])
        .unwrap()
        .unwrap();
    assert_eq!(history.transactions.len(), 61);
    handle.join().unwrap();
}

#[test]
fn a_node_with_no_usable_index_answers_none_not_an_error() {
    for (status, body) in [
        (404, "{}".to_string()),
        (
            200,
            r#"{"indexedHeight":5,"fullHeight":120,"status":"syncing"}"#.to_string(),
        ),
    ] {
        let (url, handle) = serve_many(1, move |_| (status, body.clone()));
        let tree = key_tree();
        let client = client(&url);
        assert!(client
            .address_history(
                ergo_ser::address::NetworkPrefix::Testnet,
                std::slice::from_ref(&tree)
            )
            .unwrap()
            .is_none());
        handle.join().unwrap();
    }
    // A listing the index refuses while it is mid-sync is the same answer.
    let (url, handle) = serve_many(2, |path| {
        if path.starts_with("/blockchain/indexedHeight") {
            (200, CAUGHT_UP.to_string())
        } else {
            (503, r#"{"reason":"indexer-syncing"}"#.to_string())
        }
    });
    assert!(client(&url)
        .address_history(ergo_ser::address::NetworkPrefix::Testnet, &[key_tree()])
        .unwrap()
        .is_none());
    handle.join().unwrap();
}

#[test]
fn addresses_used_asks_for_one_transaction_per_address() {
    let (url, handle) = serve_many(3, |path| {
        if path.starts_with("/blockchain/indexedHeight") {
            return (200, CAUGHT_UP.to_string());
        }
        assert!(path.ends_with("offset=0&limit=1"), "{path}");
        // The plain script has history, the reward script has none.
        if path.contains(
            &ergo_ser::address::encode_p2pk_from_pubkey(
                ergo_ser::address::NetworkPrefix::Testnet,
                &KEY,
            )
            .unwrap(),
        ) {
            (200, page_of(path, 7))
        } else {
            (200, r#"{"items":[],"total":0}"#.to_string())
        }
    });
    let trees = vec![
        key_tree(),
        ergo_wallet_service::address_index::reward_script(&KEY),
    ];
    let used = client(&url)
        .addresses_used(ergo_ser::address::NetworkPrefix::Testnet, &trees)
        .unwrap()
        .unwrap();
    assert_eq!(used, vec![true, false]);
    handle.join().unwrap();
}
