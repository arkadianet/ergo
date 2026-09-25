use std::io::Read;
use std::time::Duration;

use ergo_wallet_protocol::chain as wire;
use ergo_wallet_service::{
    ChainBlock, ChainBox, ChainClient, ChainClientError, ChainInput, ChainOutput, ChainSnapshot,
    ChainTransaction, CommittedTip, ReemissionInput, SubmitRequest, SubmitResponse, UtxoLookup,
};
use reqwest::blocking::{Client, Response};
use reqwest::header::HeaderValue;
use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;

use crate::config::ApiKey;

const API_KEY_HEADER: &str = "api_key";
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

pub struct HttpChainClient {
    client: Client,
    base_url: Url,
    api_key: ApiKey,
    max_response_body_bytes: usize,
}

impl std::fmt::Debug for HttpChainClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpChainClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .finish()
    }
}

impl HttpChainClient {
    pub fn new(base_url: Url, api_key: ApiKey) -> Result<Self, ChainClientError> {
        Self::with_timeouts(base_url, api_key, CONNECT_TIMEOUT, TOTAL_TIMEOUT)
    }

    pub fn with_timeouts(
        mut base_url: Url,
        api_key: ApiKey,
        connect_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, ChainClientError> {
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(total_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(2)
            .build()
            .map_err(|_| {
                ChainClientError::Transport("HTTP client initialization failed".to_string())
            })?;
        Ok(Self {
            client,
            base_url,
            api_key,
            max_response_body_bytes: MAX_RESPONSE_BODY_BYTES,
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    fn get_bytes(&self, path: &str) -> Result<Vec<u8>, ChainClientError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| ChainClientError::Protocol("invalid chain endpoint URL".to_string()))?;
        let value = HeaderValue::from_bytes(self.api_key.expose())
            .map_err(|_| ChainClientError::Protocol("API key is not a valid header".to_string()))?;
        let response = self
            .client
            .get(url)
            .header(API_KEY_HEADER, value)
            .send()
            .map_err(map_transport_error)?;
        let status = response.status();
        if status.is_success() {
            return read_bounded(response, self.max_response_body_bytes);
        }
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ChainClientError::Unauthorized),
            StatusCode::CONFLICT => Err(ChainClientError::Conflict),
            StatusCode::GONE => {
                let body = read_bounded(response, self.max_response_body_bytes)?;
                let parsed: wire::BlocksSinceResponse = parse_json(&body)?;
                match parsed {
                    wire::BlocksSinceResponse::Pruned(pruned) => {
                        let tip = neutral_tip(pruned.tip)?;
                        if pruned.minimum_height > tip.height {
                            return Err(ChainClientError::Protocol(
                                "410 response has a pruned floor above its tip".to_string(),
                            ));
                        }
                        Err(ChainClientError::HistoryPruned {
                            minimum_height: Some(pruned.minimum_height),
                        })
                    }
                    _ => Err(ChainClientError::Protocol(
                        "410 response was not a pruned-history response".to_string(),
                    )),
                }
            }
            StatusCode::TOO_MANY_REQUESTS
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => Err(ChainClientError::Unavailable(format!(
                "node returned HTTP {status}"
            ))),
            _ => Err(ChainClientError::Protocol(format!(
                "node returned HTTP {status}"
            ))),
        }
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ChainClientError> {
        let body = self.get_bytes(path)?;
        parse_json(&body)
    }
}

impl ChainClient for HttpChainClient {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        let tip: wire::ChainTip = self.get_json("api/v1/chain/tip")?;
        neutral_tip(tip)
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        let snapshot: wire::ChainSnapshot = self.get_json("api/v1/chain/snapshot")?;
        neutral_snapshot(snapshot)
    }

    fn blocks_since(
        &self,
        request: ergo_wallet_service::BlocksSinceRequest,
    ) -> Result<ergo_wallet_service::BlocksSinceResponse, ChainClientError> {
        if request.limit == 0 || request.limit > 1024 {
            return Err(ChainClientError::Protocol(
                "blocks-since limit must be between 1 and 1024".to_string(),
            ));
        }
        let mut url = self
            .base_url
            .join("api/v1/chain/blocks-since")
            .map_err(|_| ChainClientError::Protocol("invalid chain endpoint URL".to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("height", &request.cursor.height.to_string());
            query.append_pair("id", &hex::encode(request.cursor.header_id));
            query.append_pair("limit", &request.limit.to_string());
        }
        let url = url.to_string();
        let path = url.strip_prefix(self.base_url.as_str()).ok_or_else(|| {
            ChainClientError::Protocol("chain endpoint URL escaped base".to_string())
        })?;
        let response: wire::BlocksSinceResponse = self.get_json(path)?;
        neutral_blocks_since(response, request.cursor, request.limit)
    }

    fn lookup_utxo(
        &self,
        box_id: [u8; 32],
        expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        let mut url = self
            .base_url
            .join(&format!("api/v1/chain/boxes/{}", hex::encode(box_id)))
            .map_err(|_| ChainClientError::Protocol("invalid box endpoint URL".to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("tip", &hex::encode(expected_tip.header_id));
            query.append_pair("height", &expected_tip.height.to_string());
        }
        let path = url
            .to_string()
            .strip_prefix(self.base_url.as_str())
            .ok_or_else(|| ChainClientError::Protocol("box endpoint URL escaped base".to_string()))?
            .to_string();
        let response: wire::BoxLookupResponse = self.get_json(&path)?;
        let tip = neutral_tip(response.tip)?;
        if tip != expected_tip {
            return Err(ChainClientError::stale_tip(expected_tip, tip));
        }
        let box_info = response.box_info;
        if box_info.box_id != hex::encode(box_id) {
            return Err(ChainClientError::Protocol(
                "box lookup returned a different box id".to_string(),
            ));
        }
        Ok(UtxoLookup {
            tip,
            utxo: Some(neutral_box(box_info)?),
        })
    }

    fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }
}

fn map_transport_error(error: reqwest::Error) -> ChainClientError {
    if error.is_timeout() {
        ChainClientError::Timeout("chain request timed out".to_string())
    } else {
        ChainClientError::Transport("chain request failed".to_string())
    }
}

fn read_bounded(response: Response, limit: usize) -> Result<Vec<u8>, ChainClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ChainClientError::Protocol(
            "chain response body exceeds the configured limit".to_string(),
        ));
    }
    let mut body = Vec::new();
    response
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| ChainClientError::Transport("chain response read failed".to_string()))?;
    if body.len() > limit {
        return Err(ChainClientError::Protocol(
            "chain response body exceeds the configured limit".to_string(),
        ));
    }
    Ok(body)
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ChainClientError> {
    serde_json::from_slice(body)
        .map_err(|_| ChainClientError::Protocol("invalid chain JSON response".to_string()))
}

fn decode_id(value: &str, field: &str) -> Result<[u8; 32], ChainClientError> {
    wire::validate_id32(value, field)
        .map_err(|_| ChainClientError::Protocol(format!("invalid {field} in chain response")))?;
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            ChainClientError::Protocol(format!("invalid {field} length in chain response"))
        })
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, ChainClientError> {
    wire::validate_hex_bytes(value, field)
        .map_err(|_| ChainClientError::Protocol(format!("invalid {field} in chain response")))?;
    hex::decode(value)
        .map_err(|_| ChainClientError::Protocol(format!("invalid {field} in chain response")))
}

fn neutral_tip(tip: wire::ChainTip) -> Result<CommittedTip, ChainClientError> {
    let header_id = decode_id(&tip.header_id, "header_id")?;
    if tip.height > 0 && header_id == [0; 32] {
        return Err(ChainClientError::Protocol(
            "positive-height tip has a zero header id".to_string(),
        ));
    }
    Ok(CommittedTip::new(tip.height, header_id))
}

fn neutral_snapshot(snapshot: wire::ChainSnapshot) -> Result<ChainSnapshot, ChainClientError> {
    if !snapshot.active_parameters.is_object() {
        return Err(ChainClientError::Protocol(
            "snapshot active parameters must be an object".to_string(),
        ));
    }
    let tip = neutral_tip(snapshot.tip)?;
    let mut headers = Vec::with_capacity(snapshot.headers.len());
    let mut ids = std::collections::BTreeSet::new();
    for header in snapshot.headers {
        let header_id = decode_id(&header.header_id, "header_id")?;
        let parent_id = decode_id(&header.parent_id, "parent_id")?;
        if !ids.insert(header_id) {
            return Err(ChainClientError::Protocol(
                "snapshot contains duplicate headers".to_string(),
            ));
        }
        headers.push(ergo_wallet_service::ChainHeader {
            height: header.height,
            header_id,
            parent_id,
            timestamp_unix_ms: header.timestamp_unix_ms,
        });
    }
    let reemission_inputs = snapshot
        .reemission_inputs
        .into_iter()
        .map(|input| {
            Ok(ReemissionInput {
                token_id: decode_id(&input.token_id, "token_id")?,
                amount: input.amount.parse::<u64>().map_err(|_| {
                    ChainClientError::Protocol("invalid reemission amount".to_string())
                })?,
                box_ids: input
                    .box_ids
                    .unwrap_or_default()
                    .into_iter()
                    .map(|id| decode_id(&id, "box_id"))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, ChainClientError>>()?;
    let snapshot_id = decode_id(&snapshot.snapshot_id, "snapshot_id")?;
    if snapshot_id == [0; 32] || snapshot_id == [0xff; 32] {
        return Err(ChainClientError::Protocol(
            "snapshot_id is reserved".to_string(),
        ));
    }
    Ok(ChainSnapshot {
        tip,
        headers,
        active_parameters: snapshot.active_parameters,
        reemission_inputs,
        snapshot_id,
    })
}

fn neutral_box(box_info: wire::ChainBox) -> Result<ChainBox, ChainClientError> {
    let bytes = decode_hex(&box_info.bytes, "box bytes")?;
    if bytes.is_empty() {
        return Err(ChainClientError::Protocol(
            "box bytes are empty".to_string(),
        ));
    }
    Ok(ChainBox {
        box_id: decode_id(&box_info.box_id, "box_id")?,
        bytes,
        value: box_info.value,
        assets: box_info
            .assets
            .into_iter()
            .map(|asset| {
                Ok(ergo_wallet_service::chain::ChainAsset {
                    token_id: decode_id(&asset.token_id, "token_id")?,
                    amount: asset.amount.parse::<u64>().map_err(|_| {
                        ChainClientError::Protocol("invalid asset amount".to_string())
                    })?,
                })
            })
            .collect::<Result<Vec<_>, ChainClientError>>()?,
        creation_tx_id: decode_id(&box_info.creation_tx_id, "creation_tx_id")?,
        creation_output_index: box_info.creation_output_index,
        creation_height: box_info.creation_height,
    })
}

fn neutral_block(block: wire::ChainBlock) -> Result<ChainBlock, ChainClientError> {
    let block_id = decode_id(&block.block_id, "block_id")?;
    if block.height > 0 && block_id == [0; 32] {
        return Err(ChainClientError::Protocol(
            "positive-height block has a zero block id".to_string(),
        ));
    }
    let parent_id = decode_id(&block.parent_id, "parent_id")?;
    let mut tx_ids = std::collections::BTreeSet::new();
    let mut transactions = Vec::with_capacity(block.transactions.len());
    for transaction in block.transactions {
        let tx_id = decode_id(&transaction.tx_id, "tx_id")?;
        if !tx_ids.insert(tx_id) {
            return Err(ChainClientError::Protocol(
                "block contains duplicate transactions".to_string(),
            ));
        }
        let mut inputs = Vec::with_capacity(transaction.inputs.len());
        for input in transaction.inputs {
            inputs.push(ChainInput {
                box_id: decode_id(&input.box_id, "input box_id")?,
                index: input.index,
            });
        }
        let mut outputs = Vec::with_capacity(transaction.outputs.len());
        for output in transaction.outputs {
            let bytes = decode_hex(&output.bytes, "output bytes")?;
            if bytes.is_empty() {
                return Err(ChainClientError::Protocol(
                    "output bytes are empty".to_string(),
                ));
            }
            outputs.push(ChainOutput {
                box_id: decode_id(&output.box_id, "output box_id")?,
                index: output.index,
                bytes,
            });
        }
        transactions.push(ChainTransaction {
            tx_id,
            inputs,
            outputs,
        });
    }
    Ok(ChainBlock {
        block_id,
        height: block.height,
        parent_id,
        transactions,
    })
}

fn neutral_blocks_since(
    response: wire::BlocksSinceResponse,
    cursor: ergo_wallet_service::ChainCursor,
    limit: u32,
) -> Result<ergo_wallet_service::BlocksSinceResponse, ChainClientError> {
    match response {
        wire::BlocksSinceResponse::Forward(forward) => {
            let tip = neutral_tip(forward.tip)?;
            if tip.height < cursor.height {
                return Err(ChainClientError::Protocol(
                    "chain response tip is behind the requested cursor".to_string(),
                ));
            }
            if forward.blocks.len() > limit as usize || forward.blocks.len() > 1024 {
                return Err(ChainClientError::Protocol(
                    "chain returned more blocks than requested".to_string(),
                ));
            }
            let mut expected_height = cursor.height.saturating_add(1);
            let mut expected_parent = (cursor.height > 0).then_some(cursor.header_id);
            let mut block_ids = std::collections::BTreeSet::new();
            let mut blocks = Vec::with_capacity(forward.blocks.len());
            for block in forward.blocks {
                let block = neutral_block(block)?;
                if block.height != expected_height {
                    return Err(ChainClientError::Protocol(format!(
                        "chain block height {} does not match expected {expected_height}",
                        block.height
                    )));
                }
                if !block_ids.insert(block.block_id) {
                    return Err(ChainClientError::Protocol(
                        "chain page contains duplicate block ids".to_string(),
                    ));
                }
                if expected_parent.is_some_and(|parent| block.parent_id != parent) {
                    return Err(ChainClientError::Protocol(
                        "chain block parent continuity is invalid".to_string(),
                    ));
                }
                expected_parent = Some(block.block_id);
                expected_height = expected_height.saturating_add(1);
                blocks.push(block);
            }
            Ok(ergo_wallet_service::BlocksSinceResponse::Forward(
                ergo_wallet_service::ForwardBlocksSince { tip, blocks },
            ))
        }
        wire::BlocksSinceResponse::Ancestor(ancestor) => {
            let tip = neutral_tip(ancestor.tip)?;
            let ancestor_id = decode_id(&ancestor.ancestor.header_id, "ancestor header_id")?;
            if ancestor.ancestor.height > tip.height {
                return Err(ChainClientError::Protocol(
                    "chain ancestor is ahead of its tip".to_string(),
                ));
            }
            Ok(ergo_wallet_service::BlocksSinceResponse::Ancestor(
                ergo_wallet_service::AncestorBlocksSince {
                    tip,
                    ancestor: ergo_wallet_service::ChainCursor {
                        height: ancestor.ancestor.height,
                        header_id: ancestor_id,
                    },
                },
            ))
        }
        wire::BlocksSinceResponse::Pruned(pruned) => {
            let tip = neutral_tip(pruned.tip)?;
            if pruned.minimum_height > tip.height {
                return Err(ChainClientError::Protocol(
                    "pruned floor is above the chain tip".to_string(),
                ));
            }
            Ok(ergo_wallet_service::BlocksSinceResponse::Pruned(
                ergo_wallet_service::PrunedBlocksSince {
                    tip,
                    minimum_height: pruned.minimum_height,
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn serve_once<F>(handler: F) -> (String, thread::JoinHandle<()>)
    where
        F: FnOnce(&str, &str) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let count = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..count]);
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
            let body = handler(&path, &header);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}/"), handle)
    }

    #[test]
    fn sends_api_key_and_rejects_unauthorized() {
        let (url, handle) = serve_once(|path, header| {
            assert!(path.starts_with("/api/v1/chain/tip"));
            assert!(header.to_ascii_lowercase().contains("secret"));
            format!(r#"{{"height":1,"headerId":"{}"}}"#, id(1))
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(client.committed_tip().unwrap().height, 1);
        handle.join().unwrap();
    }

    #[test]
    fn maps_status_codes_without_exposing_body() {
        for (status, expected) in [
            (401u16, "unauthorized"),
            (409, "conflict"),
            (503, "unavailable"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).unwrap();
                let body = "secret-value-that-must-not-escape";
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
            let client = HttpChainClient::with_timeouts(
                Url::parse(&format!("http://{address}/")).unwrap(),
                ApiKey::from_test(b"secret".to_vec()),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .unwrap();
            let error = client.committed_tip().unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("secret-value"));
            handle.join().unwrap();
        }
    }

    #[test]
    fn parses_blocks_since_and_rejects_invalid_continuity() {
        let (url, handle) = serve_once(|path, _| {
            assert!(path.starts_with("/api/v1/chain/blocks-since"));
            format!(
                r#"{{"type":"forward","tip":{{"height":1,"headerId":"{}"}},"blocks":[{{"blockId":"{}","height":1,"parentId":"{}","transactions":[]}}]}}"#,
                id(1),
                id(1),
                id(0)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let response = client
            .blocks_since(ergo_wallet_service::BlocksSinceRequest {
                cursor: ergo_wallet_service::ChainCursor::genesis(),
                limit: 1,
            })
            .unwrap();
        assert!(matches!(
            response,
            ergo_wallet_service::BlocksSinceResponse::Forward(_)
        ));
        handle.join().unwrap();

        let (url, handle) = serve_once(|_, _| {
            format!(
                r#"{{"type":"forward","tip":{{"height":2,"headerId":"{}"}},"blocks":[{{"blockId":"{}","height":2,"parentId":"{}","transactions":[]}}]}}"#,
                id(2),
                id(2),
                id(1)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client.blocks_since(ergo_wallet_service::BlocksSinceRequest {
                cursor: ergo_wallet_service::ChainCursor::genesis(),
                limit: 1,
            }),
            Err(ChainClientError::Protocol(_))
        ));
        handle.join().unwrap();
    }

    #[test]
    fn parses_snapshot_and_box_lookup_and_submits_are_disabled() {
        let (url, handle) = serve_once(|path, _| {
            assert_eq!(path, "/api/v1/chain/snapshot");
            format!(
                r#"{{"tip":{{"height":1,"headerId":"{}"}},"headers":[],"activeParameters":{{}},"reemissionInputs":[],"snapshotId":"{}"}}"#,
                id(1),
                id(2)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(client.snapshot().unwrap().snapshot_id, [2; 32]);
        handle.join().unwrap();

        let (url, handle) = serve_once(|path, _| {
            assert!(path.starts_with("/api/v1/chain/boxes/"));
            format!(
                r#"{{"tip":{{"height":1,"headerId":"{}"}},"box":{{"boxId":"{}","bytes":"00","value":"1","assets":[],"creationTxId":"{}","creationOutputIndex":0,"creationHeight":1}}}}"#,
                id(1),
                id(3),
                id(4)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let lookup = client
            .lookup_utxo([3; 32], CommittedTip::new(1, [1; 32]))
            .unwrap();
        assert_eq!(lookup.utxo.unwrap().box_id, [3; 32]);
        assert!(matches!(
            client.submit(ergo_wallet_service::SubmitRequest {
                transaction: vec![1],
                snapshot_id: None,
            }),
            Err(ChainClientError::Unsupported)
        ));
        handle.join().unwrap();
    }

    #[test]
    fn rejects_malformed_and_oversized_responses() {
        let (url, handle) = serve_once(|_, _| "not-json".to_string());
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client.committed_tip(),
            Err(ChainClientError::Protocol(_))
        ));
        handle.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            let body = "x".repeat(9 * 1024 * 1024);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&format!("http://{address}/")).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client.committed_tip(),
            Err(ChainClientError::Protocol(_))
        ));
        handle.join().unwrap();
    }
}
