//! `compute_epoch_votes_via_txn` — recomputes the previous voting
//! epoch's tally inside an existing redb write_txn. Delegates the
//! algorithm to `ergo_validation::compute_epoch_votes` via a
//! `ChainHeaderReader` adapter that walks `chain_index → headers`
//! inside the borrowed write_txn. Called from the codec migration
//! (`StateStore::migrate_voted_params_codec_v2_if_needed`) when a
//! mid-session params row needs to be regenerated.

use ergo_primitives::reader::VlqReader;
use ergo_validation::voting::{
    compute_epoch_votes, ChainHeaderReader, ChainHeaderReaderError, HeaderView,
};
use redb::ReadableTable;

use super::{CHAIN_INDEX, HEADERS};

/// `ChainHeaderReader` over a borrowed redb write transaction. Reads
/// `CHAIN_INDEX → HEADERS` inside the existing txn — no fresh read_txn,
/// no cached snapshot — so the recomputed tally matches the chain
/// state the surrounding write transaction is about to commit.
struct WriteTxnChainHeaderReader<'a> {
    txn: &'a redb::WriteTransaction,
}

impl ChainHeaderReader for WriteTxnChainHeaderReader<'_> {
    fn header_at(&self, height: u32) -> Result<HeaderView, ChainHeaderReaderError> {
        let backend = |msg: String| ChainHeaderReaderError::Backend {
            height,
            source: Box::new(std::io::Error::other(msg)),
        };
        let chain_table = self
            .txn
            .open_table(CHAIN_INDEX)
            .map_err(|e| backend(format!("CHAIN_INDEX open: {e}")))?;
        let header_id = chain_table
            .get(height as u64)
            .map_err(|e| backend(format!("CHAIN_INDEX get h={height}: {e}")))?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(header_id.value());
        let headers_table = self
            .txn
            .open_table(HEADERS)
            .map_err(|e| backend(format!("HEADERS open: {e}")))?;
        let header_bytes = headers_table
            .get(id.as_slice())
            .map_err(|e| backend(format!("HEADERS get h={height}: {e}")))?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let mut r = VlqReader::new(header_bytes.value());
        let header = ergo_ser::header::read_header(&mut r)
            .map_err(|e| backend(format!("header decode h={height}: {e:?}")))?;
        Ok(HeaderView {
            votes: header.votes,
        })
    }
}

/// Compute the previous voting epoch's tally by walking
/// `chain_index → headers` inside the borrowed write_txn. Delegates
/// the tally algorithm (seed from prev-epoch-start votes, walk the
/// remaining epoch incrementing existing entries on match, drop
/// unseen vote ids) to `ergo_validation::compute_epoch_votes` —
/// `ergo-validation/tests/votes_first_epoch_oracle.rs` pins that
/// algorithm to a Scala fixture, so this path inherits Scala parity
/// without keeping a second copy of the walk loop.
///
/// Returns `Err(String)` rather than panicking on a non-epoch-boundary
/// argument — the codec migration's recovery path can't unwind.
pub(super) fn compute_epoch_votes_via_txn(
    txn: &redb::WriteTransaction,
    epoch_start_height: u32,
    voting_length: u32,
) -> Result<Vec<(i8, i32)>, String> {
    if epoch_start_height < voting_length || !epoch_start_height.is_multiple_of(voting_length) {
        return Err(format!(
            "compute_epoch_votes_via_txn: not an epoch boundary: \
             {epoch_start_height} (voting_length={voting_length})"
        ));
    }
    let reader = WriteTxnChainHeaderReader { txn };
    compute_epoch_votes(&reader, epoch_start_height, voting_length).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{write_header, Header};
    use redb::Database;

    // ----- helpers -----

    fn header_bytes_with_votes(votes: [u8; 3], height: u32) -> (Vec<u8>, [u8; 32]) {
        let header = Header {
            version: 4,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            timestamp: 1_700_000_000,
            n_bits: 0x1234_5678,
            height,
            extension_root: Digest32::from_bytes([0u8; 32]),
            votes,
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0u8; 8],
            },
        };
        let mut w = VlqWriter::new();
        write_header(&mut w, &header).expect("synthetic header fits wire bounds");
        let bytes = w.result();
        let id = *blake2b256(&bytes).as_bytes();
        (bytes, id)
    }

    fn tmp_db(tag: &str) -> (std::path::PathBuf, Database) {
        let path = std::env::temp_dir().join(format!("{tag}_{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Database::create(&path).unwrap();
        (path, db)
    }

    fn populate_headers<F: Fn(u32) -> [u8; 3]>(
        txn: &redb::WriteTransaction,
        range: std::ops::Range<u32>,
        votes_at: F,
    ) {
        let mut idx = txn.open_table(CHAIN_INDEX).unwrap();
        let mut hdrs = txn.open_table(HEADERS).unwrap();
        for h in range {
            let (bytes, id) = header_bytes_with_votes(votes_at(h), h);
            idx.insert(h as u64, id.as_slice()).unwrap();
            hdrs.insert(id.as_slice(), bytes.as_slice()).unwrap();
        }
    }

    // ----- happy path -----

    #[test]
    fn first_boundary_helper_returns_empty_with_no_h0_row() {
        // Spec 2026-05-02-voted-params-first-epoch-boundary: at the
        // first epoch boundary the recompute returns empty because
        // Rust storage has no chain row at h=0. Validation's
        // `compute_epoch_votes` handles the empty seed branch; the
        // adapter is simply never asked about h=0.
        let (path, db) = tmp_db("first_epoch_helper");
        let write_txn = crate::begin_write_qr(&db).unwrap();
        populate_headers(&write_txn, 1..1024, |h| {
            if h % 100 == 0 {
                [3, 0, 0]
            } else {
                [0, 0, 0]
            }
        });
        let result = compute_epoch_votes_via_txn(&write_txn, 1024, 1024).unwrap();
        assert!(
            result.is_empty(),
            "first-boundary tally must be empty; got {:?}",
            result
        );
        drop(write_txn);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_first_boundary_adapter_preserves_seed_order_and_drops_unseen() {
        // Non-first boundary tally over h=[1024..2048]: prev-epoch-start
        // (h=1024) seeds (id, 1) entries in header.votes order; off-boundary
        // headers increment existing entries on match and drop unseen
        // vote ids. Signed `i8` identity must be preserved so a vote
        // for +120 and -120 are distinct ids.
        //
        // Seed at h=1024: votes [+5, -3, 0] -> entries [(5, 1), (-3, 1)].
        // h=1025 votes: [+5, 0, 0] -> entry (5, *) becomes (5, 2).
        // h=1026 votes: [+99, 0, 0] -> +99 not in seed -> drop.
        // h=1027 votes: [-3, +5, 0] -> both seeded; each becomes
        //   (5, 3), (-3, 2).
        // h=1028 votes: [-5, 0, 0] -> -5 not in seed (+5 is) -> drop.
        // All other heights vote 0.
        // Expected final: [(5, 3), (-3, 2)].
        let (path, db) = tmp_db("non_first_boundary_adapter");
        let write_txn = crate::begin_write_qr(&db).unwrap();
        populate_headers(&write_txn, 1024..2048, |h| match h {
            1024 => [5u8, (-3i8) as u8, 0],
            1025 => [5, 0, 0],
            1026 => [99, 0, 0],
            1027 => [(-3i8) as u8, 5, 0],
            1028 => [(-5i8) as u8, 0, 0],
            _ => [0, 0, 0],
        });
        let result = compute_epoch_votes_via_txn(&write_txn, 2048, 1024).unwrap();
        assert_eq!(
            result,
            vec![(5i8, 3i32), (-3i8, 2i32)],
            "adapter must preserve seed order, increment matches, drop unseen ids, \
             distinguish signed vote IDs"
        );
        drop(write_txn);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    // ----- error paths -----

    #[test]
    fn non_boundary_height_returns_explicit_error() {
        let (path, db) = tmp_db("non_boundary_height");
        let write_txn = crate::begin_write_qr(&db).unwrap();
        let err = compute_epoch_votes_via_txn(&write_txn, 1500, 1024).unwrap_err();
        assert!(
            err.contains("not an epoch boundary"),
            "expected boundary error, got: {err}"
        );
        drop(write_txn);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_header_row_surfaces_not_found_at_height() {
        // Seed h=1024 but leave h=1025..2047 empty: the walk hits
        // NotFound at h=1025, which the shim stringifies into the
        // Err message.
        let (path, db) = tmp_db("missing_header_row");
        let write_txn = crate::begin_write_qr(&db).unwrap();
        populate_headers(&write_txn, 1024..1025, |_| [5, 0, 0]);
        let err = compute_epoch_votes_via_txn(&write_txn, 2048, 1024).unwrap_err();
        assert!(
            err.contains("height 1025") || err.contains("not found"),
            "expected NotFound surfacing height, got: {err}"
        );
        drop(write_txn);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
