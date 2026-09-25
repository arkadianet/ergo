use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ergo_wallet_service::{
    BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient, ChainClientError,
    ChainSnapshot, CommittedTip, SubmitRequest, SubmitResponse, UtxoLookup, WalletRead,
    WalletStore, WalletStoreError, WalletWrite,
};

pub struct FakeChain {
    pub tip: CommittedTip,
    pub responses: Arc<Mutex<VecDeque<BlocksSinceResponse>>>,
    pub requests: Arc<Mutex<Vec<(u32, u32)>>>,
}

impl FakeChain {
    pub fn new(tip: CommittedTip) -> Arc<Self> {
        Arc::new(Self {
            tip,
            responses: Arc::new(Mutex::new(VecDeque::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn with_responses(
        tip: CommittedTip,
        responses: impl IntoIterator<Item = BlocksSinceResponse>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tip,
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn requests(&self) -> Vec<(u32, u32)> {
        self.requests.lock().expect("requests lock").clone()
    }
}

impl ChainClient for FakeChain {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        Ok(self.tip.clone())
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        self.requests
            .lock()
            .expect("requests lock")
            .push((request.cursor.height, request.limit));
        if let Some(response) = self.responses.lock().expect("responses lock").pop_front() {
            return Ok(response);
        }
        let first = request.cursor.height.saturating_add(1);
        let last = self
            .tip
            .height
            .min(first.saturating_add(request.limit.saturating_sub(1)));
        let blocks = (first..=last).map(block).collect();
        Ok(BlocksSinceResponse::Forward(
            ergo_wallet_service::ForwardBlocksSince {
                tip: self.tip.clone(),
                blocks,
            },
        ))
    }

    fn lookup_utxo(
        &self,
        _box_id: [u8; 32],
        _expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }
}

pub fn block(height: u32) -> ChainBlock {
    ChainBlock {
        block_id: [height as u8; 32],
        height,
        parent_id: [height.saturating_sub(1) as u8; 32],
        transactions: Vec::new(),
    }
}

/// Delegating store that counts the write transactions opened through it.
///
/// `WalletStore` is two methods wide, so wrapping it is cheap, and the count is
/// the only way to see *how much* a pass durably wrote rather than just what it
/// ended up writing: a caught-up tick that ends on `idle` looks identical to one
/// that wrote `running` first and then `idle`, unless the extra write is
/// counted. Every call is forwarded, so the pass still runs the real redb path.
pub struct WriteSpy {
    inner: Arc<dyn WalletStore>,
    writes: Arc<Mutex<usize>>,
}

impl WriteSpy {
    pub fn new(inner: Arc<dyn WalletStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            writes: Arc::new(Mutex::new(0)),
        })
    }

    /// Number of write transactions opened so far.
    pub fn writes(&self) -> usize {
        *self.writes.lock().expect("writes lock")
    }
}

impl WalletStore for WriteSpy {
    fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
        self.inner.begin_read()
    }

    fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
        *self.writes.lock().expect("writes lock") += 1;
        self.inner.begin_write()
    }
}

pub struct NoChain;

impl ChainClient for NoChain {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn blocks_since(
        &self,
        _request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn lookup_utxo(
        &self,
        _box_id: [u8; 32],
        _expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }
}
