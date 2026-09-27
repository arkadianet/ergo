//! Page segment histories without materializing the owner's entire history.
//! One held read transaction also resolves the page's numeric IDs and records,
//! so an apply or rollback cannot mix database versions within a response.

use std::borrow::Cow;

use ergo_indexer_types::{IndexedBoxDto, IndexedTxDto, Page, SortDir};
use ergo_primitives::digest::Digest32;
use redb::ReadTransaction;

use super::{address, boxes, numeric, segment, template, token, txs, IndexerStore};
use crate::error::{IndexerError, SpillParentKind};
use crate::segment::SEGMENT_THRESHOLD;
use crate::segment_id::{box_segment_id, token_unique_id, tx_segment_id};
use crate::{BoxId, TxId};

#[derive(Clone, Copy)]
pub(crate) enum PageOwner {
    AddressBoxes(Digest32),
    AddressTxs(Digest32),
    Template(Digest32),
    Token(Digest32),
}

pub(crate) struct PageReader {
    txn: ReadTransaction,
}

impl IndexerStore {
    pub(crate) fn page_reader(&self) -> Result<PageReader, IndexerError> {
        Ok(PageReader {
            txn: self.db.begin_read()?,
        })
    }
}

impl PageReader {
    pub(crate) fn entries(
        &self,
        owner: PageOwner,
        page: Page,
        dir: SortDir,
        unspent: bool,
    ) -> Result<Option<Vec<i64>>, IndexerError> {
        let (id, spill_parent, kind, head, tx_entries) = match owner {
            PageOwner::AddressBoxes(id) | PageOwner::AddressTxs(id) => {
                let Some(rec) = address::read_address_in(&self.txn, &id)? else {
                    return Ok(None);
                };
                (
                    id,
                    id,
                    SpillParentKind::Address,
                    rec.segment,
                    matches!(owner, PageOwner::AddressTxs(_)),
                )
            }
            PageOwner::Template(id) => {
                let Some(rec) = template::read_template_in(&self.txn, &id)? else {
                    return Ok(None);
                };
                (id, id, SpillParentKind::Template, rec.segment, false)
            }
            PageOwner::Token(id) => {
                let Some(rec) = token::read_token_in(&self.txn, &id)? else {
                    return Ok(None);
                };
                (
                    id,
                    token_unique_id(&id),
                    SpillParentKind::Token,
                    rec.segment,
                    false,
                )
            }
        };
        let (head_entries, count) = if tx_entries {
            (&head.txs, head.tx_segment_count)
        } else {
            (&head.boxes, head.box_segment_count)
        };
        collect_page(head_entries, count, page, dir, unspent, |seg_num| {
            let seg_id = if tx_entries {
                tx_segment_id(&spill_parent, seg_num)
            } else {
                box_segment_id(&spill_parent, seg_num)
            };
            let spill = segment::read_spill_in(&self.txn, &seg_id)?.ok_or_else(|| {
                IndexerError::SpillMissingFromParent {
                    parent_id: hex::encode(id.as_bytes()),
                    seg_num,
                    parent_kind: kind,
                }
            })?;
            Ok(if tx_entries { spill.txs } else { spill.boxes })
        })
        .map(Some)
    }

    pub(crate) fn read_numeric_box(&self, n: u64) -> Result<Option<BoxId>, IndexerError> {
        numeric::read_numeric_box_in(&self.txn, n)
    }

    pub(crate) fn read_numeric_tx(&self, n: u64) -> Result<Option<TxId>, IndexerError> {
        numeric::read_numeric_tx_in(&self.txn, n)
    }

    pub(crate) fn read_box(&self, id: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerError> {
        boxes::read_box_in(&self.txn, id)
    }

    pub(crate) fn read_tx(&self, id: &TxId) -> Result<Option<IndexedTxDto>, IndexerError> {
        txs::read_tx_in(&self.txn, id)
    }
}

/// Spills contain exactly SEGMENT_THRESHOLD entries. Unfiltered pages jump
/// directly to their starting segment. Unspent pages scan in the requested
/// direction, filtering before offset/limit and stopping once the page is full.
/// Only inspected rows are checked; this query is not a full history scrub.
fn collect_page(
    head: &[i64],
    count: i32,
    page: Page,
    dir: SortDir,
    unspent: bool,
    mut read_spill: impl FnMut(i32) -> Result<Vec<i64>, IndexerError>,
) -> Result<Vec<i64>, IndexerError> {
    if count < 0 || head.len() > SEGMENT_THRESHOLD {
        return Err(IndexerError::SegmentTopologyError {
            detail: format!("invalid page head: {count} spills, {} entries", head.len()),
        });
    }
    let total = count as u64 * SEGMENT_THRESHOLD as u64 + head.len() as u64;
    let mut skip = u64::from(page.offset);
    if page.limit == 0 || skip >= total {
        return Ok(Vec::new());
    }
    let mut seg = match dir {
        SortDir::Asc => 0_i64,
        SortDir::Desc => i64::from(count),
    };
    if !unspent {
        match dir {
            SortDir::Asc => {
                seg = (skip / SEGMENT_THRESHOLD as u64).min(count as u64) as i64;
                skip -= seg as u64 * SEGMENT_THRESHOLD as u64;
            }
            SortDir::Desc => {
                if skip >= head.len() as u64 {
                    skip -= head.len() as u64;
                    seg -= 1 + (skip / SEGMENT_THRESHOLD as u64) as i64;
                    skip %= SEGMENT_THRESHOLD as u64;
                }
            }
        }
    }
    // Grow only with matches; a large limit on a sparse unspent set must not
    // reserve memory proportional to the owner's complete history.
    let mut result = Vec::new();
    while seg >= 0 && seg <= i64::from(count) {
        let entries = if seg == i64::from(count) {
            Cow::Borrowed(head)
        } else {
            let entries = read_spill(seg as i32)?;
            if entries.len() != SEGMENT_THRESHOLD {
                return Err(IndexerError::SegmentTopologyError {
                    detail: format!(
                        "page spill {seg} has {} entries, expected {SEGMENT_THRESHOLD}",
                        entries.len()
                    ),
                });
            }
            Cow::Owned(entries)
        };
        for i in 0..entries.len() {
            let entry = entries[match dir {
                SortDir::Asc => i,
                SortDir::Desc => entries.len() - 1 - i,
            }];
            // Preserve the existing positive-only rule, including exclusion of 0.
            if unspent && entry <= 0 {
                continue;
            }
            if skip != 0 {
                skip -= 1;
            } else {
                result.push(entry);
                if result.len() as u64 == u64::from(page.limit) {
                    return Ok(result);
                }
            }
        }
        seg += match dir {
            SortDir::Asc => 1,
            SortDir::Desc => -1,
        };
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::IndexedAddress;
    use crate::segment::Segment;
    use crate::store::tables::{INDEXED_ADDRESS, INDEXED_TX, NUMERIC_TX, SEGMENTS};

    #[test]
    fn all_owner_types_read_their_own_spills_and_preserve_page_order() {
        use crate::store::tables::{INDEXED_TEMPLATE, INDEXED_TOKEN};
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
        let addr_id = Digest32::from_bytes([1; 32]);
        let template_id = Digest32::from_bytes([2; 32]);
        let token_id = Digest32::from_bytes([3; 32]);
        let head = Segment {
            boxes: vec![-600, 601, 601],
            txs: vec![1200, 1201],
            box_segment_count: 1,
            tx_segment_count: 1,
        };
        let boxes: Vec<i64> = (0..512).map(|n| if n % 2 == 0 { -n } else { n }).collect();
        let txs: Vec<i64> = (700..1212).collect();
        let write = store.begin_write().unwrap();
        address::write_address(
            &write,
            &addr_id,
            &IndexedAddress {
                tree_hash: addr_id,
                balance: None,
                segment: head.clone(),
            },
        )
        .unwrap();
        let mut w = ergo_primitives::writer::VlqWriter::new();
        crate::template::write_indexed_template(
            &mut w,
            &crate::template::IndexedTemplate {
                template_hash: template_id,
                segment: head.clone(),
            },
        );
        write
            .open_table(INDEXED_TEMPLATE)
            .unwrap()
            .insert(template_id.as_bytes().as_slice(), w.as_slice())
            .unwrap();
        w.clear();
        let mut token = crate::token::IndexedToken::empty(token_id);
        token.segment = head.clone();
        crate::token::write_indexed_token(&mut w, &token);
        write
            .open_table(INDEXED_TOKEN)
            .unwrap()
            .insert(
                token_unique_id(&token_id).as_bytes().as_slice(),
                w.as_slice(),
            )
            .unwrap();
        for id in [addr_id, template_id, token_unique_id(&token_id)] {
            segment::write_spill(
                &write,
                &box_segment_id(&id, 0),
                &Segment {
                    boxes: boxes.clone(),
                    ..Segment::empty()
                },
            )
            .unwrap();
        }
        segment::write_spill(
            &write,
            &tx_segment_id(&addr_id, 0),
            &Segment {
                txs: txs.clone(),
                ..Segment::empty()
            },
        )
        .unwrap();
        write.commit().unwrap();
        let reader = store.page_reader().unwrap();
        for (owner, history) in [
            (
                PageOwner::AddressBoxes(addr_id),
                store.read_address_box_entries(&addr_id).unwrap().unwrap(),
            ),
            (
                PageOwner::AddressTxs(addr_id),
                store.read_address_tx_entries(&addr_id).unwrap().unwrap(),
            ),
            (
                PageOwner::Template(template_id),
                store
                    .read_template_box_entries(&template_id)
                    .unwrap()
                    .unwrap(),
            ),
            (
                PageOwner::Token(token_id),
                store.read_token_box_entries(&token_id).unwrap().unwrap(),
            ),
        ] {
            for dir in [SortDir::Asc, SortDir::Desc] {
                for unspent in [false, true] {
                    let mut expected: Vec<_> = history
                        .iter()
                        .copied()
                        .filter(|&e| !unspent || e > 0)
                        .collect();
                    if dir == SortDir::Desc {
                        expected.reverse();
                    }
                    for offset in [0, 2, 255, 500, 513] {
                        let got = reader
                            .entries(owner, Page { offset, limit: 20 }, dir, unspent)
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            got,
                            expected
                                .iter()
                                .copied()
                                .skip(offset as usize)
                                .take(20)
                                .collect::<Vec<_>>()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn pages_match_full_history_oracle_across_boundaries_and_filters() {
        for count in [0, 1, 3] {
            for head_len in [0, 1, SEGMENT_THRESHOLD] {
                let history: Vec<i64> = (0..count as usize * SEGMENT_THRESHOLD + head_len)
                    .map(|i| {
                        // Include zero, repeated indexes, sign flips and sparse positives.
                        let n = (i / 3) as i64;
                        if i % 7 == 0 {
                            n
                        } else {
                            -n
                        }
                    })
                    .collect();
                let head = &history[count as usize * SEGMENT_THRESHOLD..];
                for dir in [SortDir::Asc, SortDir::Desc] {
                    for unspent in [false, true] {
                        let mut ordered: Vec<i64> = history
                            .iter()
                            .copied()
                            .filter(|&n| !unspent || n > 0)
                            .collect();
                        if dir == SortDir::Desc {
                            ordered.reverse();
                        }
                        for offset in [0, 1, 511, 512, 513, 1023, 1536, u32::MAX] {
                            for limit in [0, 1, 20, 512, 2048, u32::MAX] {
                                let expected: Vec<_> = ordered
                                    .iter()
                                    .copied()
                                    .skip(offset as usize)
                                    .take(limit as usize)
                                    .collect();
                                let got = collect_page(
                                    head,
                                    count,
                                    Page { offset, limit },
                                    dir,
                                    unspent,
                                    |n| {
                                        let start = n as usize * SEGMENT_THRESHOLD;
                                        Ok(history[start..start + SEGMENT_THRESHOLD].to_vec())
                                    },
                                )
                                .unwrap();
                                assert_eq!(got, expected, "count={count} head={head_len} {dir:?} unspent={unspent} offset={offset} limit={limit}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn deep_pages_read_only_intersecting_spills() {
        // Over two million historical entries. No history-sized allocation.
        let count = 4096;
        let head = [count as i64 * SEGMENT_THRESHOLD as i64];
        for dir in [SortDir::Asc, SortDir::Desc] {
            let mut reads = Vec::new();
            let page = Page {
                offset: 1_000_000,
                limit: 20,
            };
            let got = collect_page(&head, count, page, dir, false, |n| {
                reads.push(n);
                let start = n as i64 * SEGMENT_THRESHOLD as i64;
                Ok((start..start + SEGMENT_THRESHOLD as i64).collect())
            })
            .unwrap();
            let expected: Vec<_> = match dir {
                SortDir::Asc => (1_000_000..1_000_020).collect(),
                SortDir::Desc => (head[0] - 1_000_019..=head[0] - 1_000_000).rev().collect(),
            };
            assert_eq!(got, expected);
            assert_eq!(reads.len(), 1, "skip directly to the requested spill");
        }
        let got = collect_page(
            &head,
            count,
            Page {
                offset: 0,
                limit: 1,
            },
            SortDir::Desc,
            false,
            |_| panic!("head-only page must not read spills"),
        )
        .unwrap();
        assert_eq!(got, head);
    }

    #[test]
    fn unspent_pages_stop_at_limit_without_scanning_remaining_history() {
        for dir in [SortDir::Asc, SortDir::Desc] {
            let mut reads = 0;
            let got = collect_page(
                &[-5000, 5001],
                4096,
                Page {
                    offset: 1,
                    limit: 3,
                },
                dir,
                true,
                |_| {
                    reads += 1;
                    let mut entries = vec![-1; SEGMENT_THRESHOLD];
                    entries[..5].copy_from_slice(&[0, 1, 1, 2, 3]);
                    Ok(entries)
                },
            )
            .unwrap();
            assert_eq!(
                got,
                if dir == SortDir::Asc {
                    vec![1, 2, 3]
                } else {
                    vec![3, 2, 1]
                }
            );
            assert_eq!(reads, 1);
        }
    }

    #[test]
    fn malformed_inspected_segments_and_counts_return_errors() {
        let page = Page {
            offset: 0,
            limit: 10,
        };
        assert!(matches!(
            collect_page(&[], -1, page, SortDir::Asc, false, |_| unreachable!()),
            Err(IndexerError::SegmentTopologyError { .. })
        ));
        assert!(matches!(
            collect_page(
                &vec![1; 513],
                0,
                page,
                SortDir::Asc,
                false,
                |_| unreachable!()
            ),
            Err(IndexerError::SegmentTopologyError { .. })
        ));
        assert!(matches!(
            collect_page(&[], 1, page, SortDir::Asc, false, |_| Ok(vec![1; 511])),
            Err(IndexerError::SegmentTopologyError { .. })
        ));
    }

    #[test]
    fn page_reader_preserves_missing_and_malformed_spill_errors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
        let id = Digest32::from_bytes([1; 32]);
        let rec = IndexedAddress {
            tree_hash: id,
            balance: None,
            segment: Segment {
                box_segment_count: 1,
                ..Segment::empty()
            },
        };
        let write = store.begin_write().unwrap();
        address::write_address(&write, &id, &rec).unwrap();
        write.commit().unwrap();
        let page = Page {
            offset: 0,
            limit: 1,
        };
        let err = store
            .page_reader()
            .unwrap()
            .entries(PageOwner::AddressBoxes(id), page, SortDir::Asc, false)
            .unwrap_err();
        assert!(matches!(
            err,
            IndexerError::SpillMissingFromParent {
                seg_num: 0,
                parent_kind: SpillParentKind::Address,
                ..
            }
        ));

        let write = store.begin_write().unwrap();
        let mut w = ergo_primitives::writer::VlqWriter::new();
        crate::segment::write_segment(
            &mut w,
            &Segment {
                boxes: vec![1; SEGMENT_THRESHOLD],
                ..Segment::empty()
            },
        );
        w.put_u8(0); // Valid body with corrupt trailing framing.
        write
            .open_table(SEGMENTS)
            .unwrap()
            .insert(box_segment_id(&id, 0).as_bytes().as_slice(), w.as_slice())
            .unwrap();
        write.commit().unwrap();
        let err = store
            .page_reader()
            .unwrap()
            .entries(PageOwner::AddressBoxes(id), page, SortDir::Asc, false)
            .unwrap_err();
        assert!(matches!(
            err,
            IndexerError::DbRowLength {
                context: "segment",
                ..
            }
        ));
    }

    #[test]
    fn entries_and_records_remain_on_same_snapshot_after_removal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
        let address_id = Digest32::from_bytes([1; 32]);
        let tx_id = Digest32::from_bytes([2; 32]);
        let rec = IndexedAddress {
            tree_hash: address_id,
            balance: None,
            segment: Segment {
                txs: vec![7],
                ..Segment::empty()
            },
        };
        let tx = IndexedTxDto {
            id: tx_id,
            index_in_block: 0,
            height: 1,
            size: 100,
            global_index: 7,
            input_nums: vec![],
            output_nums: vec![],
            data_inputs: vec![],
        };
        let bytes = crate::ser::txs::serialize_indexed_tx(&tx).unwrap();
        let write = store.begin_write().unwrap();
        address::write_address(&write, &address_id, &rec).unwrap();
        write
            .open_table(NUMERIC_TX)
            .unwrap()
            .insert(7_u64.to_be_bytes().as_slice(), tx_id.as_bytes().as_slice())
            .unwrap();
        write
            .open_table(INDEXED_TX)
            .unwrap()
            .insert(tx_id.as_bytes().as_slice(), bytes.as_slice())
            .unwrap();
        write.commit().unwrap();

        let reader = store.page_reader().unwrap();
        let page = Page {
            offset: 0,
            limit: 10,
        };
        assert_eq!(
            reader
                .entries(
                    PageOwner::AddressTxs(address_id),
                    page,
                    SortDir::Desc,
                    false
                )
                .unwrap(),
            Some(vec![7])
        );
        // A rollback removes all three rows atomically while the reader is held.
        let write = store.begin_write().unwrap();
        write
            .open_table(INDEXED_ADDRESS)
            .unwrap()
            .remove(address_id.as_bytes().as_slice())
            .unwrap();
        write
            .open_table(NUMERIC_TX)
            .unwrap()
            .remove(7_u64.to_be_bytes().as_slice())
            .unwrap();
        write
            .open_table(INDEXED_TX)
            .unwrap()
            .remove(tx_id.as_bytes().as_slice())
            .unwrap();
        write.commit().unwrap();
        assert_eq!(reader.read_numeric_tx(7).unwrap(), Some(tx_id));
        assert_eq!(reader.read_tx(&tx_id).unwrap(), Some(tx));
        let fresh = store.page_reader().unwrap();
        assert!(fresh
            .entries(
                PageOwner::AddressTxs(address_id),
                page,
                SortDir::Desc,
                false
            )
            .unwrap()
            .is_none());
        assert!(fresh.read_numeric_tx(7).unwrap().is_none());
        assert!(fresh.read_tx(&tx_id).unwrap().is_none());
    }
}
