//! Shared request bounds for the batch-by-id routes (`/blocks/headerIds`,
//! `/blockchain/block/byHeaderIds`, `/blockchain/tokens`,
//! `/utxo/withPool/byIds`).
//!
//! Each route answers one entry per distinct id: repeated ids are folded to
//! their first occurrence (ids compare case-insensitively, as hex) before
//! the count cap is applied, so a request cannot multiply one large item.

use std::collections::HashSet;
use std::io::Write;

/// Default distinct ids per `/blocks/headerIds` and
/// `/blockchain/block/byHeaderIds` request (`[api] max_blocks_per_request`).
pub const DEFAULT_MAX_BLOCKS_PER_REQUEST: usize = 1000;

/// Default budget for one serialized full-block batch response
/// (`[api] max_blocks_response_bytes`): 64 MiB.
pub const DEFAULT_MAX_BLOCKS_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Limits for the full-block batch routes. The server installs the
/// operator's values as a request extension; a router built without one
/// (tests, embedders) uses the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockBatchLimits {
    /// Distinct ids accepted per request.
    pub max_blocks: usize,
    /// Serialized response size, in bytes, above which the request is
    /// refused instead of answered.
    pub max_response_bytes: usize,
}

impl Default for BlockBatchLimits {
    fn default() -> Self {
        Self {
            max_blocks: DEFAULT_MAX_BLOCKS_PER_REQUEST,
            max_response_bytes: DEFAULT_MAX_BLOCKS_RESPONSE_BYTES,
        }
    }
}

impl BlockBatchLimits {
    /// The limits a handler should apply: the installed extension, or the
    /// defaults.
    pub fn from_extension(ext: Option<axum::Extension<Self>>) -> Self {
        ext.map(|axum::Extension(limits)| limits)
            .unwrap_or_default()
    }
}

/// The 400 detail for a block batch whose response exceeds the budget.
pub fn response_too_large(budget: usize) -> String {
    format!("Response for the requested blocks exceeds {budget} bytes; request fewer ids")
}

/// Incremental JSON array writer with a byte budget. Each item is
/// serialized straight into the buffer; the first write that would pass
/// the budget fails, so an oversized batch stops at that item instead of
/// materializing the rest. The finished bytes equal `serde_json::to_vec`
/// of the same items as a `Vec`.
pub struct BudgetedJsonArray {
    buf: Vec<u8>,
    budget: usize,
    items: usize,
}

/// Returned when the budget would be exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverBudget;

impl BudgetedJsonArray {
    pub fn new(budget: usize) -> Self {
        Self {
            buf: vec![b'['],
            budget,
            items: 0,
        }
    }

    /// Append one item. `Err(OverBudget)` once the response (including the
    /// closing bracket) would exceed the budget.
    pub fn push<T: serde::Serialize>(&mut self, item: &T) -> Result<(), OverBudget> {
        if self.items > 0 {
            self.write(b",")?;
        }
        serde_json::to_writer(&mut *self, item).map_err(|_| OverBudget)?;
        self.items += 1;
        Ok(())
    }

    /// Close the array and return the JSON bytes.
    pub fn finish(mut self) -> Result<Vec<u8>, OverBudget> {
        if self.buf.len() + 1 > self.budget {
            return Err(OverBudget);
        }
        self.buf.push(b']');
        Ok(self.buf)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), OverBudget> {
        // Item bytes keep one byte free for the closing bracket.
        if self.buf.len() + bytes.len() + 1 > self.budget {
            return Err(OverBudget);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }
}

impl Write for BudgetedJsonArray {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        BudgetedJsonArray::write(self, bytes)
            .map(|()| bytes.len())
            .map_err(|OverBudget| std::io::Error::other("response budget exceeded"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A `200 application/json` response carrying pre-serialized bytes.
pub fn json_bytes_response(bytes: Vec<u8>) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response()
}

/// Distinct ids per `/blockchain/tokens` and `/utxo/withPool/byIds`
/// request. Tokens and boxes are at most a few kilobytes of JSON each.
pub const MAX_LOOKUP_IDS: usize = 1000;

/// Fold repeated ids (first occurrence wins, original spelling kept) and
/// check the distinct count against `cap`. The error string is the `detail`
/// the caller returns in its 400.
pub fn dedupe_and_cap(ids: Vec<String>, cap: usize) -> Result<Vec<String>, String> {
    let mut seen = HashSet::with_capacity(ids.len().min(cap + 1));
    let mut out = Vec::with_capacity(ids.len().min(cap));
    for id in ids {
        if seen.insert(id.to_ascii_lowercase()) {
            if out.len() == cap {
                return Err(too_many(cap));
            }
            out.push(id);
        }
    }
    Ok(out)
}

/// The 400 detail for a request above `cap` distinct ids.
pub fn too_many(cap: usize) -> String {
    format!("No more than {cap} ids can be requested")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_ids_fold_to_first_occurrence_case_insensitively() {
        let a = "AB".repeat(32);
        let b = "cd".repeat(32);
        let out = dedupe_and_cap(
            vec![a.clone(), b.clone(), a.to_ascii_lowercase(), b.clone()],
            10,
        )
        .unwrap();
        assert_eq!(out, vec![a, b]);
    }

    #[test]
    fn budgeted_array_matches_serde_and_stops_at_the_budget() {
        let items = vec![serde_json::json!({"a": 1}), serde_json::json!("bb")];
        let mut array = BudgetedJsonArray::new(1024);
        for item in &items {
            array.push(item).unwrap();
        }
        assert_eq!(array.finish().unwrap(), serde_json::to_vec(&items).unwrap());
        let exact = serde_json::to_vec(&items).unwrap().len();
        let mut array = BudgetedJsonArray::new(exact);
        for item in &items {
            array.push(item).unwrap();
        }
        assert!(
            array.finish().is_ok(),
            "a response of exactly the budget fits"
        );
        let mut array = BudgetedJsonArray::new(exact - 1);
        let pushed: Result<Vec<()>, OverBudget> = items.iter().map(|i| array.push(i)).collect();
        assert!(pushed.is_err() || array.finish().is_err());
        assert!(BudgetedJsonArray::new(0).finish().is_err());
    }

    #[test]
    fn cap_counts_distinct_ids_only() {
        let one = "ab".repeat(32);
        assert_eq!(
            dedupe_and_cap(vec![one.clone(); 50_000], 1).unwrap(),
            vec![one]
        );
        let ids: Vec<String> = (0..3).map(|i| format!("{i:064x}")).collect();
        assert_eq!(dedupe_and_cap(ids.clone(), 3).unwrap().len(), 3);
        assert_eq!(dedupe_and_cap(ids, 2).unwrap_err(), too_many(2));
    }
}
