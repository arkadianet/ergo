//! Bridge between the API task (`/mining/*` axum handlers) and the
//! single-writer main loop where `StateStore` lives.
//!
//! Mirrors `crate::api_bridge::SubmitBridge` exactly:
//! - The bridge holds an `mpsc::Sender<MiningRequest>`.
//! - Each `NodeMining` method packages its inputs + an `oneshot` reply
//!   sender into a `MiningRequest`, hands it to the channel, and awaits
//!   the reply with a hard deadline.
//! - Channel-full → 503 `overloaded`. Channel closed → 503
//!   `shutting_down`. No reply within timeout → 504 `timeout`.
//!
//! Reward address + reward pubkey are pure functions of the miner pk
//! pinned at startup, so they're computed in the bridge without
//! crossing the channel.

use std::sync::Arc;

use async_trait::async_trait;
use ergo_api::mining::{MiningApiError, NodeMining};
use ergo_rest_json::mining::{
    AutolykosSolutionJson, CandidateMetricsJson, MiningTemplateJson, TemplateExtensionFieldJson,
    TemplateTransactionJson, WorkMessageJson,
};
use tokio::sync::{mpsc, oneshot};

/// Project a typed mining `WorkMessage` to its JSON wire shape, stamping the
/// pool-facing template versioning (`template_seq` / `clean_jobs`) from the
/// served template's identity. Lives in the node bridge (which owns both the
/// typed and JSON sides) so `ergo-mining` stays free of the JSON / presentation
/// DTOs. The Scala-parity fields (`msg` / `b` / `h` / `pk` / `proof`) are
/// untouched; template metrics are copied from the same frozen work message.
pub(crate) fn work_message_to_json(
    w: ergo_mining::work_message::WorkMessage,
    template_seq: u64,
    clean_jobs: bool,
) -> WorkMessageJson {
    WorkMessageJson {
        msg: hex::encode(w.msg),
        b: w.target,
        h: Some(w.height),
        pk: hex::encode(w.pk),
        proof: None,
        template_seq,
        clean_jobs,
        metrics: Some(CandidateMetricsJson {
            transaction_count: w.metrics.transaction_count,
            selected_transaction_count: w.metrics.selected_transaction_count,
            fees_nano_erg: w.metrics.fees_nano_erg.to_string(),
            transactions_size_bytes: w.metrics.transactions_size_bytes,
            max_block_size_bytes: w.metrics.max_block_size_bytes,
            validation_cost: w.metrics.validation_cost,
            max_block_cost: w.metrics.max_block_cost,
        }),
    }
}

/// Serialize exactly one frozen candidate; no second cache read can mix jobs.
pub(crate) fn template_to_json(
    template: ergo_mining::engine::Template,
) -> Result<MiningTemplateJson, MiningApiError> {
    use ergo_primitives::writer::VlqWriter;
    let candidate = template.candidate;
    let header = ergo_ser::header::serialize_header_without_pow(&candidate.header)
        .map_err(|e| MiningApiError::Internal(format!("serialize candidate header: {e:?}")))?;
    if template.work.msg != candidate.msg
        || ergo_primitives::digest::blake2b256(&header).as_bytes() != &candidate.msg
    {
        return Err(MiningApiError::Internal(
            "candidate header and work hash disagree".into(),
        ));
    }
    let transactions = candidate
        .transactions
        .iter()
        .map(|tx| {
            let mut writer = VlqWriter::new();
            ergo_ser::transaction::write_transaction(&mut writer, tx).map_err(|e| {
                MiningApiError::Internal(format!("serialize template transaction: {e:?}"))
            })?;
            let id = ergo_ser::transaction::transaction_id(tx)
                .map_err(|e| MiningApiError::Internal(format!("template transaction id: {e:?}")))?;
            Ok(TemplateTransactionJson {
                id: hex::encode(id.as_bytes()),
                bytes: hex::encode(writer.result()),
            })
        })
        .collect::<Result<Vec<_>, MiningApiError>>()?;
    Ok(MiningTemplateJson {
        work: work_message_to_json(
            template.work,
            template.identity.template_seq,
            template.identity.clean_jobs,
        ),
        header_without_pow: hex::encode(header),
        parent_id: hex::encode(candidate.parent_id),
        version: candidate.header.version,
        transactions,
        extension: candidate
            .extension_fields
            .into_iter()
            .map(|(key, value)| TemplateExtensionFieldJson {
                key: hex::encode(key),
                value: hex::encode(value),
            })
            .collect(),
        ad_proofs: hex::encode(candidate.ad_proof_bytes),
        required_transaction_ids: candidate
            .required_transaction_ids
            .into_iter()
            .map(hex::encode)
            .collect(),
    })
}

/// Requested builds have a longer deadline than cache-only mining reads.
pub const REQUIRED_BUILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-request deadline. If the main loop hasn't drained and replied
/// within this window, the handler returns 504 `timeout`. Matches the
/// existing `crate::api_bridge::SUBMIT_TIMEOUT` value (5s).
pub const MINING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bound on a `GET /mining/candidate?longpoll=` block. When the client
/// is already on the current template the handler parks until the next publish
/// or this elapses, then returns whatever is current (a fresher template, or
/// the same one on timeout). Bounded so the HTTP connection refreshes rather
/// than hanging indefinitely on a quiet chain; independent of the 5s
/// `MINING_TIMEOUT` that bounds each individual channel round-trip.
pub const LONGPOLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One mining request ferried from the API task to the main loop. The
/// handler holds the `Sender` end of the embedded oneshot; the main
/// loop's `select!` arm sends back when the request completes.
#[derive(Debug)]
pub enum MiningRequest {
    /// `GET /mining/candidate` — main loop serves the cache via
    /// [`ergo_mining::handle::MiningHandle::cached_template_if_synced`] (the
    /// off-loop engine is the sole builder) and replies with the work message
    /// plus its pool-facing versioning (`template_seq` / `clean_jobs`), or
    /// `Unavailable` when unsynced or no candidate has been published for the
    /// current tip yet.
    GetCandidate {
        reply: oneshot::Sender<Result<WorkMessageJson, MiningApiError>>,
    },
    /// Cache-only complete-template read.
    GetTemplate {
        reply: oneshot::Sender<Result<Option<ergo_mining::engine::Template>, MiningApiError>>,
    },
    /// A single off-loop request owns the permit until its worker exits.
    /// HTTP disconnect/timeouts cannot release capacity while a build runs.
    CandidateWithTxs {
        transactions: Vec<Arc<[u8]>>,
        permit: tokio::sync::OwnedSemaphorePermit,
        reply: oneshot::Sender<Result<MiningTemplateJson, MiningApiError>>,
    },
    /// `POST /mining/solution` — main loop runs the API-side pre-check
    /// via [`ergo_mining::handle::MiningHandle::verify_solution`], then
    /// (on Accepted) drives the apply path: recheck the parent and
    /// serialize via [`ergo_mining::submit::prepare_mined_block`], advance
    /// the header chain via `header_proc::process_header_cfg_with_genesis`,
    /// persist sections via [`ergo_mining::submit::store_mined_sections`],
    /// announce a new best header, then validate + apply via the executor's
    /// `Action::AssembleBlock`.
    SubmitSolution {
        solution: AutolykosSolutionJson,
        reply: oneshot::Sender<Result<(), MiningApiError>>,
    },
    /// `GET /mining/rewardAddress` + `/rewardPublicKey` — main loop resolves
    /// the reward key against live wallet state via
    /// [`ergo_mining::handle::MiningHandle::resolve_reward_key`] and replies
    /// with the raw 33-byte pubkey. A `Pinned` key always resolves; a `Wallet`
    /// key is `Unavailable` (503) until the wallet is initialized and
    /// `Internal` (500) if tracking is inconsistent. NOT behind the synced-tip
    /// gate — the reward key is meaningful regardless of sync state.
    GetRewardKey {
        reply: oneshot::Sender<Result<[u8; 33], MiningApiError>>,
    },
}

/// `NodeMining` impl over an mpsc channel. Construct one in the node
/// init alongside the `mining_submit_{tx,rx}` channel, hand the
/// `Sender` here and the `Receiver` to the action loop.
///
/// The reward key is resolved on demand through the action loop (it may be
/// wallet-derived and only available after the wallet is unlocked), so the
/// bridge holds no precomputed reward strings — only the channel and the
/// network prefix for address encoding.
pub struct MiningBridge {
    tx: mpsc::Sender<MiningRequest>,
    network: ergo_ser::address::NetworkPrefix,
    /// Serve-state-change receiver from the [`MiningHandle`]. Observes a change
    /// whenever the served candidate changes — a publish OR a tip transition
    /// (parent change or synced-bit flip). The longpoll path parks on it so the
    /// wait lives entirely in the API task, never on the action loop.
    serve_rx: tokio::sync::watch::Receiver<u64>,
    /// Upper bound on a single longpoll block. Defaults to [`LONGPOLL_TIMEOUT`];
    /// a test constructor overrides it so the timeout path runs deterministically
    /// without a real 30 s wait.
    longpoll_timeout: std::time::Duration,
    required_builds: Arc<tokio::sync::Semaphore>,
}

impl MiningBridge {
    /// Construct a bridge. `tx` is the sender half of the main-loop mining
    /// channel; `network` is the prefix used to encode the resolved reward
    /// pubkey into a P2S reward address; `serve_rx` is a fresh subscription to
    /// the handle's serve-state-change notifications (see
    /// [`ergo_mining::handle::MiningHandle::subscribe_serve_changes`]) backing the
    /// longpoll wait. The reward key itself is resolved lazily (see
    /// [`MiningRequest::GetRewardKey`]).
    pub fn new(
        tx: mpsc::Sender<MiningRequest>,
        network: ergo_ser::address::NetworkPrefix,
        serve_rx: tokio::sync::watch::Receiver<u64>,
    ) -> Self {
        Self {
            tx,
            network,
            serve_rx,
            longpoll_timeout: LONGPOLL_TIMEOUT,
            required_builds: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    /// Test-only constructor with an explicit (short) longpoll bound so the
    /// timeout path runs deterministically without a real 30 s wait. Production
    /// always goes through [`MiningBridge::new`] (30 s).
    #[cfg(test)]
    fn new_with_longpoll_timeout(
        tx: mpsc::Sender<MiningRequest>,
        network: ergo_ser::address::NetworkPrefix,
        serve_rx: tokio::sync::watch::Receiver<u64>,
        longpoll_timeout: std::time::Duration,
    ) -> Self {
        Self {
            tx,
            network,
            serve_rx,
            longpoll_timeout,
            required_builds: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    /// One `GetCandidate` channel round-trip: package the oneshot, hand it to
    /// the action loop, and await the quick cache-only reply with the per-round
    /// deadline. Returns `Ok(None)` when the loop reports `Unavailable` (no
    /// candidate for the current tip / unsynced) so the handler maps it to 503;
    /// any other categorized error propagates. Shared by the plain and the
    /// longpoll-armed candidate paths — the action loop only ever serves this
    /// quick reply, never the wait.
    async fn request_current_candidate(&self) -> Result<Option<WorkMessageJson>, MiningApiError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        match self
            .tx
            .try_send(MiningRequest::GetCandidate { reply: reply_tx })
        {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(MiningApiError::Unavailable(
                    "mining submission channel full; retry with backoff".into(),
                ));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(MiningApiError::Unavailable(
                    "node main loop has stopped accepting requests".into(),
                ));
            }
        }
        match tokio::time::timeout(MINING_TIMEOUT, reply_rx).await {
            Ok(Ok(Ok(w))) => Ok(Some(w)),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(MiningApiError::Unavailable(
                "main loop closed reply channel".into(),
            )),
            Err(_) => Err(MiningApiError::Timeout(format!(
                "main loop did not reply within {} ms",
                MINING_TIMEOUT.as_millis()
            ))),
        }
    }

    /// Resolve the raw reward pubkey through the action loop. Shared by the
    /// rewardAddress / rewardPublicKey endpoints.
    async fn request_reward_key(&self) -> Result<[u8; 33], MiningApiError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .try_send(MiningRequest::GetRewardKey { reply: reply_tx })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    MiningApiError::Unavailable("mining channel full; retry with backoff".into())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    MiningApiError::Unavailable("node main loop has stopped".into())
                }
            })?;
        match tokio::time::timeout(MINING_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(MiningApiError::Unavailable(
                "main loop closed reply channel".into(),
            )),
            Err(_) => Err(MiningApiError::Timeout(format!(
                "main loop did not reply within {} ms",
                MINING_TIMEOUT.as_millis()
            ))),
        }
    }

    /// Erase the concrete type for axum state injection.
    pub fn into_dyn(self) -> Arc<dyn NodeMining> {
        Arc::new(self)
    }
}

fn parse_and_encode_reward_address(
    reward_bytes: &[u8],
    network: ergo_ser::address::NetworkPrefix,
) -> Result<String, String> {
    let mut r = ergo_primitives::reader::VlqReader::new(reward_bytes);
    let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut r)
        .map_err(|e| format!("parse reward tree: {e:?}"))?;
    Ok(ergo_ser::address::encode_address(
        network,
        &tree,
        reward_bytes,
    ))
}

#[async_trait]
impl NodeMining for MiningBridge {
    async fn candidate(
        &self,
        longpoll: Option<String>,
    ) -> Result<Option<WorkMessageJson>, MiningApiError> {
        // Snapshot the serve-state version as seen BEFORE reading the current
        // template. A serve-state change (publish or tip transition) that lands
        // between this read and `rx.changed()` below bumps the version
        // `borrow_and_update` just consumed, so `changed()` returns immediately
        // rather than parking — no change can slip through the gap (the classic
        // check-then-wait race).
        let mut rx = self.serve_rx.clone();
        rx.borrow_and_update();

        let current = self.request_current_candidate().await?;

        if let Some(lp) = longpoll {
            // Block only while the client is on the current template; otherwise
            // it is already behind and gets the current one immediately below.
            if current.as_ref().map(|w| w.msg.as_str()) == Some(lp.as_str()) {
                // Park until the served state changes (a fresh publish, or a tip
                // transition that moves off this work) or the bound elapses. The
                // timeout result is intentionally ignored: on either branch we
                // return whatever is current — a fresher template, `None` if the
                // tip went unsynced, or the same one on a quiet-chain timeout
                // (the client re-polls).
                //
                // Herd note: under many concurrent direct-miner longpoll clients
                // a single serve-state change wakes them all and they re-fetch
                // through the depth-64 mining channel, so some may get a 503
                // (channel full) and re-longpoll — graceful degradation to a
                // client retry. This is acceptable because the intended
                // deployment is a Stratum proxy (a few longpoll connections
                // fanning out to many miners), not thousands of direct miners.
                //
                // Shutdown wake: `self.tx.closed()` resolves when the action
                // loop drops the mining-request receiver during shutdown. Parking
                // on it too means a longpoll in flight when the node stops wakes
                // promptly and returns (the re-fetch below sees the closed
                // channel → 503 `shutting_down`), so the request drains
                // gracefully within the API shutdown window instead of being
                // force-aborted (TCP RST) after the cap.
                tokio::select! {
                    _ = tokio::time::sleep(self.longpoll_timeout) => {}
                    _ = rx.changed() => {}
                    _ = self.tx.closed() => {}
                }
                return self.request_current_candidate().await;
            }
        }

        Ok(current)
    }

    async fn template(&self) -> Result<Option<MiningTemplateJson>, MiningApiError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .try_send(MiningRequest::GetTemplate { reply })
            .map_err(|_| {
                MiningApiError::Unavailable("mining channel unavailable; retry with backoff".into())
            })?;
        let template = tokio::time::timeout(MINING_TIMEOUT, rx)
            .await
            .map_err(|_| MiningApiError::Timeout("template read deadline exceeded".into()))?
            .map_err(|_| MiningApiError::Unavailable("main loop closed reply channel".into()))??;
        // Serialize off the action loop; the frozen clone cannot mix refreshes.
        template.map(template_to_json).transpose()
    }

    async fn candidate_with_txs(
        &self,
        transactions: Vec<Vec<u8>>,
    ) -> Result<MiningTemplateJson, MiningApiError> {
        if transactions.len() > 256 || transactions.iter().map(Vec::len).sum::<usize>() > 1_048_576
        {
            return Err(MiningApiError::BadRequest(
                "at most 256 transactions and 1 MiB of transaction bytes may be requested".into(),
            ));
        }
        let permit = self
            .required_builds
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                MiningApiError::Unavailable(
                    "a required-transaction build is already running; retry with backoff".into(),
                )
            })?;
        let (reply, rx) = oneshot::channel();
        self.tx
            .try_send(MiningRequest::CandidateWithTxs {
                transactions: transactions.into_iter().map(Arc::from).collect(),
                permit,
                reply,
            })
            .map_err(|_| {
                MiningApiError::Unavailable("mining channel unavailable; retry with backoff".into())
            })?;
        tokio::time::timeout(REQUIRED_BUILD_TIMEOUT, rx)
            .await
            .map_err(|_| {
                MiningApiError::Timeout("required-transaction build deadline exceeded".into())
            })?
            .map_err(|_| MiningApiError::Unavailable("main loop closed reply channel".into()))?
    }

    async fn submit_solution(&self, solution: AutolykosSolutionJson) -> Result<(), MiningApiError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        match self.tx.try_send(MiningRequest::SubmitSolution {
            solution,
            reply: reply_tx,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(MiningApiError::Unavailable(
                    "mining submission channel full; retry with backoff".into(),
                ));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(MiningApiError::Unavailable(
                    "node main loop has stopped accepting requests".into(),
                ));
            }
        }
        match tokio::time::timeout(MINING_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(MiningApiError::Unavailable(
                "main loop closed reply channel".into(),
            )),
            Err(_) => Err(MiningApiError::Timeout(format!(
                "main loop did not reply within {} ms",
                MINING_TIMEOUT.as_millis()
            ))),
        }
    }

    async fn reward_address(&self) -> Result<String, MiningApiError> {
        let pk = self.request_reward_key().await?;
        let reward_bytes = ergo_mining::reward_output_script(&pk).to_vec();
        parse_and_encode_reward_address(&reward_bytes, self.network)
            .map_err(|e| MiningApiError::Internal(format!("encode reward address: {e}")))
    }

    async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
        let pk = self.request_reward_key().await?;
        Ok(hex::encode(pk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // ----- helpers -----

    /// Build a `WorkMessageJson` carrying just the `msg` the longpoll path keys
    /// on; the other fields are inert placeholders the tests never inspect.
    fn work_json(msg: &str) -> WorkMessageJson {
        WorkMessageJson {
            msg: msg.to_string(),
            b: num_bigint::BigUint::from(1u8),
            h: Some(1),
            pk: hex::encode([0x02u8; 33]),
            proof: None,
            template_seq: 0,
            clean_jobs: false,
            metrics: None,
        }
    }

    /// Spawn a responder task that answers every `GetCandidate` from the canned
    /// `served` slot: `Some(msg)` → reply that work message; `None` → reply
    /// `Unavailable` (the action loop's unsynced / no-candidate signal). Replies
    /// promptly so only the longpoll wait depends on the (short, test-set) bound.
    /// Returns the wired bridge, the serve-change `watch::Sender` to bump, and
    /// the shared `served` slot to flip mid-test.
    ///
    /// The mpsc is depth-1 like nothing in particular — the tests issue one
    /// request at a time, so a small buffer suffices. `longpoll_timeout` is set
    /// short so the quiet-chain timeout test finishes fast and deterministically
    /// (no real 30 s wait, no `tokio::time` pausing to entangle with the
    /// channel round-trip's own `MINING_TIMEOUT`).
    fn wired_bridge(
        initial: Option<&str>,
        longpoll_timeout: std::time::Duration,
    ) -> (
        MiningBridge,
        tokio::sync::watch::Sender<u64>,
        Arc<Mutex<Option<String>>>,
    ) {
        let (tx, mut rx) = mpsc::channel::<MiningRequest>(4);
        let (serve_tx, serve_rx) = tokio::sync::watch::channel(0u64);
        let served = Arc::new(Mutex::new(initial.map(str::to_string)));
        let responder_served = Arc::clone(&served);
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req {
                    MiningRequest::GetCandidate { reply } => {
                        let payload = match responder_served.lock().expect("served slot").clone() {
                            Some(msg) => Ok(work_json(&msg)),
                            None => Err(MiningApiError::Unavailable("unsynced".into())),
                        };
                        let _ = reply.send(payload);
                    }
                    // The longpoll tests only exercise GetCandidate; the other
                    // arms are unreachable here.
                    MiningRequest::SubmitSolution { reply, .. } => {
                        let _ = reply.send(Err(MiningApiError::Unavailable("n/a".into())));
                    }
                    MiningRequest::GetRewardKey { reply } => {
                        let _ = reply.send(Err(MiningApiError::Unavailable("n/a".into())));
                    }
                    MiningRequest::GetTemplate { reply } => {
                        let _ = reply.send(Err(MiningApiError::Unavailable("n/a".into())));
                    }
                    MiningRequest::CandidateWithTxs { reply, .. } => {
                        let _ = reply.send(Err(MiningApiError::Unavailable("n/a".into())));
                    }
                }
            }
        });
        let bridge = MiningBridge::new_with_longpoll_timeout(
            tx,
            ergo_ser::address::NetworkPrefix::Mainnet,
            serve_rx,
            longpoll_timeout,
        );
        (bridge, serve_tx, served)
    }

    #[test]
    fn exported_template_header_hash_matches_work_and_keeps_frozen_artifacts() {
        use ergo_mining::{
            candidate::Candidate,
            engine::{BuildReason, Template, TemplateIdentity},
            work_message::WorkMessage,
        };
        use ergo_primitives::digest::{ADDigest, Digest32};
        use ergo_ser::{autolykos::AutolykosSolution, header::Header};
        use ergo_validation::pre_header::{
            build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
        };
        let header = Header {
            version: 3,
            parent_id: Digest32::from_bytes([2; 32]).into(),
            ad_proofs_root: Digest32::from_bytes([3; 32]),
            transactions_root: Digest32::from_bytes([4; 32]),
            state_root: ADDigest::from_bytes([5; 33]),
            extension_root: Digest32::from_bytes([6; 32]),
            timestamp: 1234,
            n_bits: 0x01010000,
            height: 100,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
                nonce: [0; 8],
            },
        };
        let header_bytes = ergo_ser::header::serialize_header_without_pow(&header).unwrap();
        let msg = *ergo_primitives::digest::blake2b256(&header_bytes).as_bytes();
        let template = Template {
            candidate: Candidate {
                header: header.clone(),
                validation_ctx: CandidateValidationContext {
                    pre_header: CandidatePreHeader {
                        version: 3,
                        parent_id: [2; 32],
                        height: 100,
                        timestamp: 1234,
                        n_bits: 0x01010000,
                        votes: [0; 3],
                        miner_pubkey: [2; 33],
                    },
                    activated_script_version: 2,
                    last_headers: vec![],
                    last_block_utxo_root: build_last_block_utxo_root(header.state_root),
                },
                transactions: vec![],
                required_transaction_ids: vec![[9; 32]],
                ad_proof_bytes: vec![7, 8],
                extension_fields: vec![(vec![1, 2], vec![3, 4])],
                msg,
                target: 1u8.into(),
                parent_id: [2; 32],
            },
            work: WorkMessage {
                msg,
                target: 1u8.into(),
                height: 100,
                pk: [2; 33],
                metrics: Default::default(),
            },
            identity: TemplateIdentity {
                template_id: msg,
                parent_id: [2; 32],
                chain_seq: 1,
                template_seq: 12,
                clean_jobs: false,
                built_at_ms: 1000,
                reason: BuildReason::RequiredTransactions,
            },
        };
        let exported = template_to_json(template.clone()).unwrap();
        assert_eq!(exported.header_without_pow, hex::encode(header_bytes));
        assert_eq!(
            hex::encode(
                ergo_primitives::digest::blake2b256(
                    &hex::decode(&exported.header_without_pow).unwrap()
                )
                .as_bytes()
            ),
            exported.work.msg
        );
        assert_eq!(exported.work.template_seq, 12);
        assert_eq!(exported.ad_proofs, "0708");
        assert_eq!(exported.extension[0].key, "0102");
        assert_eq!(exported.extension[0].value, "0304");
        assert_eq!(exported.required_transaction_ids, vec!["09".repeat(32)]);
        let mut wrong = template;
        wrong.work.msg[0] ^= 1;
        assert!(matches!(
            template_to_json(wrong),
            Err(MiningApiError::Internal(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn required_build_permit_survives_http_timeout_until_worker_exits() {
        let (tx, mut rx) = mpsc::channel(4);
        let (_notify, serve_rx) = tokio::sync::watch::channel(0u64);
        let bridge = Arc::new(MiningBridge::new(
            tx,
            ergo_ser::address::NetworkPrefix::Mainnet,
            serve_rx,
        ));
        let first = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.candidate_with_txs(vec![]).await })
        };
        let request = rx.recv().await.unwrap();
        assert!(matches!(
            bridge.candidate_with_txs(vec![]).await,
            Err(MiningApiError::Unavailable(_))
        ));
        tokio::time::advance(REQUIRED_BUILD_TIMEOUT + std::time::Duration::from_secs(1)).await;
        assert!(matches!(
            first.await.unwrap(),
            Err(MiningApiError::Timeout(_))
        ));
        assert!(matches!(
            bridge.candidate_with_txs(vec![]).await,
            Err(MiningApiError::Unavailable(_))
        ));
        match &request {
            MiningRequest::CandidateWithTxs { reply, .. } => assert!(reply.is_closed()),
            _ => panic!("wrong mining request"),
        }
        drop(request);
        assert_eq!(bridge.required_builds.available_permits(), 1);
    }

    // ----- happy path -----

    #[test]
    fn work_message_to_json_matches_legacy_wire_shape() {
        // Pin the external-miner wire contract after the typed-WorkMessage
        // move: msg/pk hex, `b` as a bare JSON number (Scala's
        // `ApiCodecs.bigIntEncoder`, pinned against a live 6.0.3 candidate in
        // `ergo-rest-json::mining`), `h` present, and `proof` omitted when
        // None. Lithos/Rigel/ErgoStratum depend on this.
        // The pool-versioning extension (template_seq / clean_jobs) is purely
        // additive — the Scala-parity fields below must be byte-identical to
        // the pre-extension shape, which this asserts key-by-key.
        let w = ergo_mining::work_message::WorkMessage {
            msg: [0xAB; 32],
            target: num_bigint::BigUint::from(123_456_789u64),
            height: 1_786_188,
            pk: [0x02; 33],
            metrics: ergo_mining::work_message::CandidateMetrics {
                transaction_count: 5,
                selected_transaction_count: 3,
                fees_nano_erg: 9_007_199_254_740_993,
                transactions_size_bytes: 1234,
                max_block_size_bytes: 524_288,
                validation_cost: 4321,
                max_block_cost: 1_000_000,
            },
        };
        let v = serde_json::to_value(work_message_to_json(w, 42, true)).unwrap();
        assert_eq!(v["msg"], serde_json::Value::String("ab".repeat(32)));
        assert!(v["b"].is_number(), "b must be a bare number: {}", v["b"]);
        assert_eq!(v["b"].to_string(), "123456789");
        assert_eq!(v["h"], serde_json::Value::Number(1_786_188.into()));
        assert_eq!(v["pk"].as_str().unwrap(), hex::encode([0x02u8; 33]));
        assert!(v.get("proof").is_none(), "proof omitted when None");
        // The two new node-specific pool extensions are present and carry the
        // identity's values.
        assert_eq!(v["template_seq"], serde_json::Value::Number(42.into()));
        assert_eq!(v["clean_jobs"], serde_json::Value::Bool(true));
        assert_eq!(v["metrics"]["fees_nano_erg"], "9007199254740993");
        assert_eq!(v["metrics"]["transaction_count"], 5);
        assert_eq!(v["metrics"]["selected_transaction_count"], 3);
        assert_eq!(v["metrics"]["transactions_size_bytes"], 1234);
        assert_eq!(v["metrics"]["max_block_size_bytes"], 524_288);
        assert_eq!(v["metrics"]["validation_cost"], 4321);
        assert_eq!(v["metrics"]["max_block_cost"], 1_000_000);
        // The original fields retain their encodings; metrics are additive.
        let obj = v.as_object().expect("object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "b",
                "clean_jobs",
                "h",
                "metrics",
                "msg",
                "pk",
                "template_seq"
            ],
            "legacy fields plus pool identity and template metrics",
        );
    }

    #[tokio::test]
    async fn candidate_longpoll_non_matching_value_returns_immediately() {
        // The client's longpoll value isn't the current template, so it is
        // already behind and gets the current one at once — no parking.
        let (bridge, _serve_tx, _served) =
            wired_bridge(Some("AA"), std::time::Duration::from_millis(50));
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bridge.candidate(Some("BB".into())),
        )
        .await
        .expect("must return without parking on a non-matching longpoll value")
        .expect("candidate ok");
        assert_eq!(got.map(|w| w.msg), Some("AA".to_string()));
    }

    #[tokio::test]
    async fn candidate_longpoll_matching_value_wakes_on_serve_change() {
        // The client is on the current template "AA", so it parks. A serve-state
        // change bumps the watch and flips the served template to "BB"; the
        // longpoll wakes and re-fetches the fresh "BB".
        let (bridge, serve_tx, served) =
            wired_bridge(Some("AA"), std::time::Duration::from_secs(30));
        let waker = {
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                *served.lock().expect("served slot") = Some("BB".to_string());
                serve_tx.send_modify(|v| *v = v.wrapping_add(1));
            })
        };
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bridge.candidate(Some("AA".into())),
        )
        .await
        .expect("must wake well before the 30 s bound")
        .expect("candidate ok");
        waker.await.expect("waker task");
        assert_eq!(
            got.map(|w| w.msg),
            Some("BB".to_string()),
            "longpoll woke on the serve-state change and re-fetched the fresh template",
        );
    }

    #[tokio::test]
    async fn candidate_longpoll_returns_on_timeout_when_no_change() {
        // Quiet chain: the client is on the current template and nothing changes,
        // so the longpoll returns the same template once the bound elapses. The
        // per-bridge bound is set to a few ms here so the timeout path runs fast
        // and deterministically — production keeps the 30 s `LONGPOLL_TIMEOUT`.
        // (A real short clock is used rather than `tokio::time::pause`, which
        // would also fast-forward the channel round-trip's own `MINING_TIMEOUT`
        // and needs the `test-util` feature this crate does not enable.)
        let (bridge, _serve_tx, _served) =
            wired_bridge(Some("AA"), std::time::Duration::from_millis(20));
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bridge.candidate(Some("AA".into())),
        )
        .await
        .expect("the short bound must elapse and return well under 1 s")
        .expect("candidate ok on timeout");
        assert_eq!(
            got.map(|w| w.msg),
            Some("AA".to_string()),
            "on a quiet-chain timeout the longpoll returns the current template",
        );
    }

    #[tokio::test]
    async fn candidate_longpoll_wakes_promptly_when_tip_goes_unsynced() {
        // Regression guard for the serve-notify fix: a tip transition that flips
        // synced→false changes the served state with NO publish. A client
        // longpolling the current "AA" must wake on the serve-change bump and
        // re-fetch the now-unsynced result PROMPTLY, not sit until the bound.
        // Before the fix the watch only fired on publishes, so this waiter slept
        // the full timeout on work the tip had already moved off.
        let (bridge, serve_tx, served) =
            wired_bridge(Some("AA"), std::time::Duration::from_secs(30));
        let waker = {
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                // Tip went unsynced: the loop now serves nothing.
                *served.lock().expect("served slot") = None;
                serve_tx.send_modify(|v| *v = v.wrapping_add(1));
            })
        };
        // The bound is 30 s; assert the call resolves well under it (1 s),
        // proving it woke on the bump rather than timing out.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bridge.candidate(Some("AA".into())),
        )
        .await
        .expect("must wake on the unsync serve-change, not sit until the 30 s bound");
        waker.await.expect("waker task");
        assert!(
            matches!(result, Err(MiningApiError::Unavailable(_))),
            "after the tip goes unsynced the re-fetch reports Unavailable, got {result:?}",
        );
    }

    #[tokio::test]
    async fn candidate_longpoll_wakes_on_channel_close() {
        // Shutdown wake: a parked longpoll must exit promptly when the action
        // loop drops the mining-request receiver (node shutting down), so the
        // in-flight HTTP request drains gracefully inside the API shutdown
        // window instead of being force-aborted after the bound. The responder
        // answers the first GetCandidate ("AA") then returns, dropping the
        // receiver — which resolves `self.tx.closed()` while the waiter parks.
        let (tx, mut rx) = mpsc::channel::<MiningRequest>(4);
        let (_serve_tx, serve_rx) = tokio::sync::watch::channel(0u64);
        tokio::spawn(async move {
            if let Some(MiningRequest::GetCandidate { reply }) = rx.recv().await {
                let _ = reply.send(Ok(work_json("AA")));
            }
            // `rx` drops here → the bridge's `tx.closed()` future resolves.
        });
        let bridge = MiningBridge::new_with_longpoll_timeout(
            tx,
            ergo_ser::address::NetworkPrefix::Mainnet,
            serve_rx,
            std::time::Duration::from_secs(30),
        );
        // Park on the current template "AA"; the channel closes mid-park. Assert
        // the call resolves well under the 30 s bound (1 s), then re-fetches
        // against the closed channel → `Unavailable` (shutting down).
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            bridge.candidate(Some("AA".into())),
        )
        .await
        .expect("must wake on channel close, not sit until the 30 s bound");
        assert!(
            matches!(result, Err(MiningApiError::Unavailable(_))),
            "a longpoll parked at shutdown returns Unavailable, got {result:?}",
        );
    }
}
