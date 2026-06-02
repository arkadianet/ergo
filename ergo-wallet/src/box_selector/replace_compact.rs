//! ReplaceCompactCollectBoxSelector port from Scala's
//! `ReplaceCompactCollectBoxSelector.scala`.
//!
//! Currently delegates to DefaultBoxSelector. The compaction optimization
//! (replace one large selected box with multiple smaller unused candidates when
//! the swap reduces total ERG locked) is not yet implemented. It improves
//! change-size economy but does not affect correctness — every selection this
//! produces is valid. The trait surface is in place so operator-selectable
//! compaction can land later without a signature change.

use super::{BoxSelector, BoxSummary, SelectionResult, SelectionTarget};
use crate::{box_selector::default::DefaultBoxSelector, error::WalletError};

pub struct ReplaceCompactCollectBoxSelector;

impl BoxSelector for ReplaceCompactCollectBoxSelector {
    fn select(
        &self,
        candidates: &[BoxSummary],
        target: &SelectionTarget,
    ) -> Result<SelectionResult, WalletError> {
        DefaultBoxSelector.select(candidates, target)
    }
}
