//! In-memory record types for the per-type indexed rows. The wire
//! format (matching `ExtraIndexSerializer`) lives in
//! `ergo-indexer::ser` — these are the parsed/structured forms held
//! in memory while the apply path is running and surfaced to readers.

use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::input::SpendingProof;

use crate::{BoxId, TxId};

/// `IndexedErgoBox`: one redb row per `BoxId`. The three `Option`
/// fields together encode "this box has been spent" — `global_index`
/// is non-negative on valid persisted box records (assigned at output
/// time and never sign-flipped; the spent-flag is carried by the
/// segment-side sign, not the box record). The first-indexed output
/// (in practice, the genesis output) gets `global_index = 0`; this is
/// not a mempool sentinel — the mempool overlay's discriminator is
/// `inclusion_height = 0` (block heights start at 1), not
/// `global_index = 0`.
///
/// `[inherited]` segment-filter quirk: segment-based unspent queries
/// (`Segment.scala:247` and our mirror in
/// `ergo_indexer::handle::address/template/token_unspent_paged`)
/// filter `_ > 0`, so the genesis output is invisible to those routes
/// on both Scala and Rust. Do not attempt to "fix" the filter to
/// include `0` — that would diverge from Scala mainnet.
///
/// `spending_tx_id`, `spending_height`, and `spending_proof` are
/// set or unset together on valid persisted records — Scala's `IndexedErgoBox.asSpent`
/// mutates all three at once (`IndexedErgoBox.scala:38-43`). Our
/// checked persistence helpers preserve that invariant. These public fields
/// permit other in-memory combinations; callers must validate before persisting.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedErgoBox {
    pub inclusion_height: i32,
    pub spending_tx_id: Option<TxId>,
    pub spending_height: Option<i32>,
    pub spending_proof: Option<SpendingProof>,
    pub box_data: ErgoBox,
    /// Non-negative on valid persisted box records (i.e. the value assigned
    /// at output time, never sign-flipped). Genesis output has `0`;
    /// the segment-side spent-flag uses the sign of segment entries
    /// instead.
    pub global_index: i64,
}

impl IndexedErgoBox {
    /// `IndexedErgoBox.isSpent` — driven by the spending-tx-id
    /// `Option` (set means spent).
    pub fn is_spent(&self) -> bool {
        self.spending_tx_id.is_some()
    }
}

/// `IndexedErgoTransaction`: one redb row per `TxId`.
/// `input_nums` / `output_nums` are the global indices assigned to the
/// spent inputs and the created outputs, in iteration order; they are
/// what `byIndex` lookups dereference. `data_inputs` carries the raw
/// box ids — data inputs do not get global indices because they are
/// not spent.
///
/// Per `IndexedErgoTransaction.scala:62`, `numConfirmations` is a
/// transient field rebuilt on read (`bestFullBlockHeight - height`)
/// and is **not persisted**; we omit it here and let the API formatter
/// compute it from `IndexerHandle::indexed_height` at response time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedErgoTransaction {
    pub id: TxId,
    pub index_in_block: i32,
    pub height: i32,
    pub size: i32,
    pub global_index: i64,
    pub input_nums: Vec<i64>,
    pub output_nums: Vec<i64>,
    pub data_inputs: Vec<BoxId>,
}
