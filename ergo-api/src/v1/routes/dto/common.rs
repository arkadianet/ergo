//! Shared v1 wire primitives every route-group DTO file leans on:
//! the self-contained ISO-8601 renderer, the `{items, page}` /
//! `{items, page, meta}` collection envelopes, and the shared
//! confirmation-count rule.

use serde::Serialize;
use utoipa::ToSchema;

use crate::v1::cursor::Page;

// ----- timestamps --------------------------------------------------

/// Render a unix-milliseconds instant as the `<name>_iso` ISO-8601 mirror
/// using the ISO-8601 rule (`YYYY-MM-DDTHH:MM:SS.sssZ`, always UTC/`Z`).
///
/// Self-contained (no `chrono`/`time` dependency): the calendar date is
/// derived with Howard Hinnant's `civil_from_days` algorithm, which is exact
/// for all in-range instants. Pinned by oracle tests against well-known unix
/// epochs (0, 10^9 s, 1.6×10^9 s).
pub(crate) fn unix_ms_to_iso(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

// ----- collections envelope ----------------------------------------

/// A v1 collection: `{items, page}`. Uniform for
/// every list, even single-page ones (a block's tx list, header-ids at a
/// height): those carry `page.has_more = false`, `page.next_cursor = null`.
#[derive(Debug, Serialize, ToSchema)]
pub struct Collection<T> {
    pub items: Vec<T>,
    pub page: Page,
}

impl<T> Collection<T> {
    /// A bounded, single-page collection (`has_more = false`), for lists that
    /// never span pages (block transactions, header-ids at a height).
    pub fn single_page(items: Vec<T>) -> Self {
        let limit = items.len() as u32;
        Collection {
            items,
            page: Page {
                limit,
                next_cursor: None,
                has_more: false,
            },
        }
    }
}

/// A v1 collection carrying an extra `meta` object for whole-result scalars
/// (coherence Part D): `{items, page, meta}`. Used by `tokens/{id}/holders`,
/// whose `as_of_height` / `scanned_boxes` / `scan_capped` belong under `meta`,
/// never as ad-hoc top-level siblings.
#[derive(Debug, Serialize, ToSchema)]
pub struct CollectionMeta<T, M> {
    pub items: Vec<T>,
    pub page: Page,
    pub meta: M,
}

/// Blocks-above confirmation count: `best - inclusion`, floored at 0. Matches
/// the Scala `IndexedErgoTransaction` mirror (`blockchain/transactions.rs`).
pub(crate) fn confirmations(best_full_block_height: u32, inclusion_height: i32) -> i64 {
    (i64::from(best_full_block_height) - i64::from(inclusion_height)).max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity (well-known unix epochs) -----

    #[test]
    fn unix_ms_to_iso_epoch_zero() {
        assert_eq!(unix_ms_to_iso(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn unix_ms_to_iso_billion_seconds() {
        // 1_000_000_000 s — the famous "unix billennium".
        assert_eq!(
            unix_ms_to_iso(1_000_000_000_000),
            "2001-09-09T01:46:40.000Z"
        );
    }

    #[test]
    fn unix_ms_to_iso_preserves_millis() {
        assert_eq!(
            unix_ms_to_iso(1_600_000_000_123),
            "2020-09-13T12:26:40.123Z"
        );
    }

    // ----- happy path -----

    #[test]
    fn single_page_collection_never_spans() {
        let c = Collection::single_page(vec![1u32, 2, 3]);
        assert_eq!(c.page.limit, 3);
        assert!(!c.page.has_more);
        assert!(c.page.next_cursor.is_none());
    }
}
