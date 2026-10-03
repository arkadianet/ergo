//! Operator block-assembly policy. These limits only narrow valid candidate
//! selection; consensus validation and the voted block limits still apply.

use std::collections::HashSet;

use ergo_primitives::digest::Digest32;
use serde::{Deserialize, Serialize};

use crate::error::MiningError;

/// Treatment of tokens recovered from fully consumed storage-rent boxes.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RentTokenPolicy {
    /// Defer a claim rather than discard any of its recovered tokens.
    #[default]
    Preserve,
    /// Permit overflow tokens to be burned when a payout box cannot hold them.
    BurnOverflow,
}

/// Bounded configuration for miner-selected block contents. Basis points are
/// hundredths of one percent (10,000 means 100%). Private reservations keep
/// rent from consuming that budget when private transactions are waiting;
/// public transactions may use whatever remains after private selection.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BlockPolicy {
    pub rent_max_cost_basis_points: u16,
    pub rent_max_size_basis_points: u16,
    pub private_reserved_cost_basis_points: u16,
    pub private_reserved_size_basis_points: u16,
    /// Every required transaction and its available ancestors must be present
    /// in the final candidate. Missing, conflicting or oversized requirements
    /// stop candidate publication until the operator changes the policy.
    pub required_tx_ids: Vec<String>,
    pub excluded_tx_ids: Vec<String>,
    /// Each list is an ordered mandatory bundle. Transaction dependencies are
    /// still ordered before children; every listed transaction is required.
    pub required_bundles: Vec<Vec<String>>,
    pub rent_token_policy: RentTokenPolicy,
}

impl Default for BlockPolicy {
    fn default() -> Self {
        Self {
            rent_max_cost_basis_points: 9_375,
            rent_max_size_basis_points: 9_375,
            private_reserved_cost_basis_points: 1_000,
            private_reserved_size_basis_points: 1_000,
            required_tx_ids: Vec::new(),
            excluded_tx_ids: Vec::new(),
            required_bundles: Vec::new(),
            rent_token_policy: RentTokenPolicy::Preserve,
        }
    }
}

impl BlockPolicy {
    /// Reject unbounded, malformed or contradictory operator requirements.
    pub fn validate(&self) -> Result<(), MiningError> {
        for (name, value) in [
            (
                "rent_max_cost_basis_points",
                self.rent_max_cost_basis_points,
            ),
            (
                "rent_max_size_basis_points",
                self.rent_max_size_basis_points,
            ),
            (
                "private_reserved_cost_basis_points",
                self.private_reserved_cost_basis_points,
            ),
            (
                "private_reserved_size_basis_points",
                self.private_reserved_size_basis_points,
            ),
        ] {
            if value > 10_000 {
                return Err(MiningError::InvalidConfig(format!(
                    "{name} must be at most 10000"
                )));
            }
        }
        let required_count =
            self.required_tx_ids.len() + self.required_bundles.iter().map(Vec::len).sum::<usize>();
        if required_count > 1_024
            || self.excluded_tx_ids.len() > 1_024
            || self.required_bundles.len() > 128
        {
            return Err(MiningError::InvalidConfig(
                "block policy permits at most 1024 required and excluded IDs and 128 bundles"
                    .into(),
            ));
        }
        if self.required_bundles.iter().any(Vec::is_empty) {
            return Err(MiningError::InvalidConfig(
                "required bundles must not be empty".into(),
            ));
        }
        let excluded: HashSet<_> = self.excluded_ids()?.into_iter().collect();
        for id in self.required_ids()? {
            if excluded.contains(&id) {
                return Err(MiningError::InvalidConfig(
                    "a required transaction cannot also be excluded".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn has_required_transactions(&self) -> bool {
        !self.required_tx_ids.is_empty() || !self.required_bundles.is_empty()
    }

    pub fn required_ids(&self) -> Result<Vec<Digest32>, MiningError> {
        self.required_tx_ids
            .iter()
            .chain(self.required_bundles.iter().flatten())
            .map(|id| parse_id(id))
            .collect()
    }

    pub fn excluded_ids(&self) -> Result<Vec<Digest32>, MiningError> {
        self.excluded_tx_ids.iter().map(|id| parse_id(id)).collect()
    }

    /// A rent ceiling after protecting the private reservation and mandatory
    /// emission/framing overhead. Saturation makes tiny voted blocks safe.
    pub fn rent_ceiling(
        total: u64,
        overhead: u64,
        maximum: u16,
        private_reserve: u16,
        private_waiting: bool,
    ) -> u64 {
        let usable = total.saturating_sub(overhead);
        let rent = (total.saturating_mul(u64::from(maximum)) / 10_000).saturating_sub(overhead);
        let private = if private_waiting {
            total.saturating_mul(u64::from(private_reserve)) / 10_000
        } else {
            0
        };
        rent.min(usable.saturating_sub(private))
    }
}

fn parse_id(value: &str) -> Result<Digest32, MiningError> {
    let bytes = hex::decode(value).map_err(|_| {
        MiningError::InvalidConfig("transaction IDs must be 64 hexadecimal characters".into())
    })?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        MiningError::InvalidConfig("transaction IDs must be 64 hexadecimal characters".into())
    })?;
    Ok(Digest32::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn rent_ceiling_protects_private_budget_and_emission() {
        assert_eq!(
            BlockPolicy::rent_ceiling(10_000, 500, 9_375, 1_000, true),
            8_500
        );
        assert_eq!(
            BlockPolicy::rent_ceiling(10_000, 500, 9_375, 1_000, false),
            8_875
        );
        assert_eq!(BlockPolicy::rent_ceiling(10, 100, 9_375, 1_000, true), 0);
    }

    // ----- round-trips -----

    #[test]
    fn policy_default_roundtrips_with_preservation() {
        let policy = BlockPolicy::default();
        assert_eq!(
            serde_json::from_str::<BlockPolicy>(&serde_json::to_string(&policy).unwrap()).unwrap(),
            policy
        );
        assert_eq!(
            serde_json::from_str::<BlockPolicy>("{}")
                .unwrap()
                .rent_token_policy,
            RentTokenPolicy::Preserve
        );
    }

    // ----- error paths -----

    #[test]
    fn policy_rejects_conflicting_ids_independent_of_hex_case() {
        let policy = BlockPolicy {
            required_tx_ids: vec!["ab".repeat(32)],
            excluded_tx_ids: vec!["AB".repeat(32)],
            ..Default::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_rejects_invalid_percentage_and_empty_bundle() {
        assert!(BlockPolicy {
            rent_max_cost_basis_points: 10_001,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(BlockPolicy {
            required_bundles: vec![vec![]],
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
