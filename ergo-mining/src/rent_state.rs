//! Availability of the optional storage-rent self-claim scan.

/// Allow the indexer's ordinary one- or two-block apply lag without pausing.
/// Larger gaps make the eligible-box index too stale to scan economically.
pub const RENT_INDEX_LAG_MARGIN: u64 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RentSelfClaimState {
    #[default]
    Disabled,
    Active,
    PausedIndexerBehind {
        indexed_height: u64,
        chain_height: u32,
    },
}

impl RentSelfClaimState {
    pub fn at_height(enabled: bool, indexed_height: u64, parent_height: u32) -> Self {
        if !enabled {
            Self::Disabled
        } else if u64::from(parent_height).saturating_sub(indexed_height) > RENT_INDEX_LAG_MARGIN {
            Self::PausedIndexerBehind {
                indexed_height,
                chain_height: parent_height,
            }
        } else {
            Self::Active
        }
    }
}
