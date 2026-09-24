use std::sync::Arc;

use ergo_primitives::digest::ADDigest;
use ergo_ser::ad_proofs::ADProofs;
use ergo_ser::block_transactions::BlockTransactions;
use ergo_ser::extension::Extension;
use ergo_ser::header::Header;

use crate::error::{ServiceError, ServiceResult};
use crate::id::{HeaderId, ModifierId};
use crate::page::{Page, PageRequest};

pub const MAX_RECENT_HEADERS: u32 = 16_384;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolHistory {
    pub epoch_length: u32,
    pub current_height: u32,
    pub changes: Vec<ProtocolChangeEvent>,
}

pub type ProtocolParameterHistory = ProtocolHistory;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolChangeEvent {
    pub height: u32,
    pub params: Vec<ProtocolParamChange>,
}

pub type ProtocolParameterChangeEvent = ProtocolChangeEvent;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolParamChange {
    pub id: u8,
    pub name: String,
    pub description: String,
    pub from: Option<i64>,
    pub to: i64,
}

pub type ProtocolParameterChange = ProtocolParamChange;

#[derive(Debug, Clone, PartialEq)]
pub struct Stored<T> {
    pub id: ModifierId,
    pub bytes: Arc<[u8]>,
    pub value: T,
}

impl<T> Stored<T> {
    pub fn new(id: ModifierId, bytes: Arc<[u8]>, value: T) -> Self {
        Self { id, bytes, value }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FullBlock {
    pub header: Stored<Header>,
    pub transactions: Stored<BlockTransactions>,
    pub extension: Stored<Extension>,
    pub ad_proofs: Option<Stored<ADProofs>>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    pub id: HeaderId,
    pub parent_id: HeaderId,
    pub height: u32,
    pub timestamp_unix_ms: u64,
    pub state_root: Option<ADDigest>,
    pub transaction_count: u32,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderQuery {
    pub from_height: Option<u32>,
    pub to_height: Option<u32>,
    pub order: SortOrder,
}

#[allow(clippy::result_large_err)]
pub trait ChainArchive: Send + Sync + 'static {
    fn header_ids_at_height(&self, height: u32) -> ServiceResult<Vec<HeaderId>>;

    fn header_ids(&self, query: HeaderQuery, page: PageRequest) -> ServiceResult<Page<HeaderId>>;

    fn headers(&self, query: HeaderQuery, page: PageRequest)
        -> ServiceResult<Page<Stored<Header>>>;

    fn protocol_history(&self) -> ServiceResult<ProtocolHistory> {
        self.protocol_parameter_history()
    }

    fn protocol_parameter_history(&self) -> ServiceResult<ProtocolHistory> {
        Ok(ProtocolHistory::default())
    }

    fn recent_headers(&self, count: u32) -> ServiceResult<Vec<Stored<Header>>> {
        let count = count.min(MAX_RECENT_HEADERS);
        if count == 0 {
            return Ok(Vec::new());
        }
        let query = HeaderQuery {
            from_height: Some(1),
            to_height: None,
            order: SortOrder::Descending,
        };
        let mut cursor = None;
        let mut remaining = count;
        let mut headers = Vec::with_capacity(count as usize);
        while remaining > 0 {
            let limit = remaining.min(1_000);
            let page = PageRequest::new(limit, cursor).map_err(|_| {
                ServiceError::validation("invalid_limit", "header limit is invalid")
            })?;
            let page = self.headers(query, page)?;
            let returned = page.items.len() as u32;
            headers.extend(page.items);
            if returned == 0 {
                break;
            }
            remaining = remaining.saturating_sub(returned);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        headers.truncate(count as usize);
        Ok(headers)
    }

    fn header_by_id(&self, id: HeaderId) -> ServiceResult<Option<Stored<Header>>>;

    fn block_transactions_by_id(
        &self,
        id: HeaderId,
    ) -> ServiceResult<Option<Stored<BlockTransactions>>>;

    fn full_block_by_id(&self, id: HeaderId) -> ServiceResult<Option<FullBlock>>;

    fn block_summary_by_id(&self, id: HeaderId) -> ServiceResult<Option<BlockSummary>>;

    fn full_blocks_by_ids(&self, ids: &[HeaderId]) -> ServiceResult<Page<FullBlock>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyChain;

    impl ChainArchive for EmptyChain {
        fn header_ids_at_height(&self, _height: u32) -> ServiceResult<Vec<HeaderId>> {
            unreachable!()
        }

        fn header_ids(
            &self,
            _query: HeaderQuery,
            _page: PageRequest,
        ) -> ServiceResult<Page<HeaderId>> {
            unreachable!()
        }

        fn headers(
            &self,
            _query: HeaderQuery,
            _page: PageRequest,
        ) -> ServiceResult<Page<Stored<Header>>> {
            unreachable!()
        }

        fn header_by_id(&self, _id: HeaderId) -> ServiceResult<Option<Stored<Header>>> {
            unreachable!()
        }

        fn block_transactions_by_id(
            &self,
            _id: HeaderId,
        ) -> ServiceResult<Option<Stored<BlockTransactions>>> {
            unreachable!()
        }

        fn full_block_by_id(&self, _id: HeaderId) -> ServiceResult<Option<FullBlock>> {
            unreachable!()
        }

        fn block_summary_by_id(&self, _id: HeaderId) -> ServiceResult<Option<BlockSummary>> {
            unreachable!()
        }

        fn full_blocks_by_ids(&self, _ids: &[HeaderId]) -> ServiceResult<Page<FullBlock>> {
            unreachable!()
        }
    }

    #[test]
    fn protocol_history_default_is_empty() {
        assert_eq!(
            EmptyChain.protocol_history().unwrap(),
            ProtocolHistory::default()
        );
    }
}
