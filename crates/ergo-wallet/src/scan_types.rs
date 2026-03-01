//! Scan types for external applications to track on-chain boxes.
//!
//! A **scan** is a user-defined rule that identifies outputs of interest on the
//! Ergo blockchain.  Each scan has a [`ScanningPredicate`] that is evaluated
//! against every new box.  Matching boxes are persisted in the wallet's scan
//! registry so that external applications can query them.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Well-known scan IDs
// ---------------------------------------------------------------------------

/// Scan ID reserved for mining-related outputs.
pub const MINING_SCAN_ID: u16 = 9;

/// Scan ID reserved for simple payment outputs.
pub const PAYMENTS_SCAN_ID: u16 = 10;

/// First scan ID available for user-defined scans.
pub const FIRST_USER_SCAN_ID: u16 = 11;

// ---------------------------------------------------------------------------
// ScanningPredicate
// ---------------------------------------------------------------------------

/// Default register for `Equals` and `Contains` predicates.
fn default_register() -> String {
    "R1".to_owned()
}

/// A predicate that determines whether a box matches a scan.
///
/// Register semantics:
/// - `R0` — the box value encoded as 8-byte little-endian.
/// - `R1` — the raw ErgoTree bytes (the guarding proposition).
/// - Any other register name is treated as empty (no match for `Equals`,
///   `Contains` always fails).
///
/// `value` fields are hex-encoded byte strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "predicate", rename_all = "camelCase")]
pub enum ScanningPredicate {
    /// Exact equality: the register bytes must equal the decoded hex value.
    #[serde(rename = "equals")]
    Equals {
        #[serde(default = "default_register")]
        register: String,
        value: String,
    },

    /// Subsequence containment: the register bytes must contain the decoded hex
    /// value as a contiguous subsequence.
    #[serde(rename = "contains")]
    Contains {
        #[serde(default = "default_register")]
        register: String,
        value: String,
    },

    /// Asset containment: at least one token must have the given asset ID.
    #[serde(rename = "containsAsset")]
    ContainsAsset {
        #[serde(rename = "assetId")]
        asset_id: String,
    },

    /// Conjunction: all child predicates must match.
    #[serde(rename = "and")]
    And { args: Vec<ScanningPredicate> },

    /// Disjunction: at least one child predicate must match.
    #[serde(rename = "or")]
    Or { args: Vec<ScanningPredicate> },
}

impl ScanningPredicate {
    /// Evaluate this predicate against a box described by its raw fields.
    ///
    /// # Arguments
    ///
    /// - `ergo_tree_bytes` — raw ErgoTree bytes (register R1).
    /// - `tokens` — `(token_id, amount)` pairs carried by the box.
    /// - `value` — nanoERG value locked in the box (register R0).
    pub fn matches(&self, ergo_tree_bytes: &[u8], tokens: &[([u8; 32], u64)], value: u64) -> bool {
        match self {
            ScanningPredicate::Equals {
                register,
                value: hex_val,
            } => {
                let expected = match hex::decode(hex_val) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let reg_bytes = register_bytes(register, ergo_tree_bytes, value);
                reg_bytes == expected
            }

            ScanningPredicate::Contains {
                register,
                value: hex_val,
            } => {
                let needle = match hex::decode(hex_val) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let haystack = register_bytes(register, ergo_tree_bytes, value);
                contains_subsequence(&haystack, &needle)
            }

            ScanningPredicate::ContainsAsset { asset_id } => {
                let target: [u8; 32] = match hex::decode(asset_id) {
                    Ok(v) if v.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&v);
                        arr
                    }
                    _ => return false,
                };
                tokens.iter().any(|(tid, _)| *tid == target)
            }

            ScanningPredicate::And { args } => args
                .iter()
                .all(|p| p.matches(ergo_tree_bytes, tokens, value)),

            ScanningPredicate::Or { args } => args
                .iter()
                .any(|p| p.matches(ergo_tree_bytes, tokens, value)),
        }
    }
}

/// Resolve a register name to its byte representation.
///
/// - `R0` — box value as 8-byte little-endian.
/// - `R1` — raw ErgoTree bytes.
/// - Anything else — empty (unsupported register).
fn register_bytes(register: &str, ergo_tree_bytes: &[u8], value: u64) -> Vec<u8> {
    match register {
        "R0" => value.to_le_bytes().to_vec(),
        "R1" => ergo_tree_bytes.to_vec(),
        _ => Vec::new(),
    }
}

/// Check whether `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// ScanWalletInteraction
// ---------------------------------------------------------------------------

/// How a scan interacts with the main wallet.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ScanWalletInteraction {
    /// Scan-tracked boxes are invisible to the wallet.
    #[default]
    Off,
    /// Scan-tracked boxes are shared with the wallet (both can see them).
    Shared,
    /// Scan-tracked boxes are forcibly attributed to the wallet.
    Forced,
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

/// A user-defined scan that tracks on-chain boxes matching a predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scan {
    /// Unique identifier for this scan.
    pub scan_id: u16,
    /// Human-readable name.
    pub scan_name: String,
    /// The predicate used to match boxes.
    pub tracking_rule: ScanningPredicate,
    /// How this scan's boxes interact with the main wallet.
    #[serde(default)]
    pub wallet_interaction: ScanWalletInteraction,
    /// Whether to remove off-chain (mempool) boxes when a matching on-chain
    /// box appears.
    #[serde(default)]
    pub remove_offchain: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a deterministic 32-byte token ID from a single seed byte.
    fn token_id(seed: u8) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        arr
    }

    // -- Equals --

    #[test]
    fn equals_matches_ergo_tree() {
        let tree = vec![0x00, 0x08, 0xCD, 0xAA];
        let pred = ScanningPredicate::Equals {
            register: "R1".to_owned(),
            value: hex::encode(&tree),
        };
        assert!(pred.matches(&tree, &[], 0));

        // Different tree should not match.
        let other_tree = vec![0x00, 0x08, 0xCD, 0xBB];
        assert!(!pred.matches(&other_tree, &[], 0));
    }

    #[test]
    fn equals_matches_value_register() {
        let value: u64 = 1_000_000;
        let pred = ScanningPredicate::Equals {
            register: "R0".to_owned(),
            value: hex::encode(value.to_le_bytes()),
        };
        assert!(pred.matches(&[], &[], value));
        assert!(!pred.matches(&[], &[], value + 1));
    }

    // -- Contains --

    #[test]
    fn contains_matches_substring() {
        let tree = vec![0x00, 0x08, 0xCD, 0xAA, 0xBB, 0xCC];
        let pred = ScanningPredicate::Contains {
            register: "R1".to_owned(),
            value: hex::encode([0xCD, 0xAA]),
        };
        assert!(pred.matches(&tree, &[], 0));

        // Needle not present.
        let pred_miss = ScanningPredicate::Contains {
            register: "R1".to_owned(),
            value: hex::encode([0xFF, 0xFE]),
        };
        assert!(!pred_miss.matches(&tree, &[], 0));
    }

    // -- ContainsAsset --

    #[test]
    fn contains_asset_matches() {
        let tid = token_id(0xAA);
        let tokens = vec![(tid, 100u64)];
        let pred = ScanningPredicate::ContainsAsset {
            asset_id: hex::encode(tid),
        };
        assert!(pred.matches(&[], &tokens, 0));

        // Different token should not match.
        let other_tokens = vec![(token_id(0xBB), 50)];
        assert!(!pred.matches(&[], &other_tokens, 0));

        // Empty tokens should not match.
        assert!(!pred.matches(&[], &[], 0));
    }

    // -- And --

    #[test]
    fn and_requires_all() {
        let tree = vec![0x00, 0x08, 0xCD, 0xAA];
        let tid = token_id(0xBB);
        let tokens = vec![(tid, 50)];

        let pred = ScanningPredicate::And {
            args: vec![
                ScanningPredicate::Equals {
                    register: "R1".to_owned(),
                    value: hex::encode(&tree),
                },
                ScanningPredicate::ContainsAsset {
                    asset_id: hex::encode(tid),
                },
            ],
        };

        // Both match.
        assert!(pred.matches(&tree, &tokens, 0));

        // Only tree matches (no token).
        assert!(!pred.matches(&tree, &[], 0));

        // Only token matches (different tree).
        assert!(!pred.matches(&[0xFF], &tokens, 0));
    }

    // -- Or --

    #[test]
    fn or_requires_any() {
        let tree = vec![0x00, 0x08, 0xCD, 0xAA];
        let tid = token_id(0xBB);
        let tokens = vec![(tid, 50)];

        let pred = ScanningPredicate::Or {
            args: vec![
                ScanningPredicate::Equals {
                    register: "R1".to_owned(),
                    value: hex::encode(&tree),
                },
                ScanningPredicate::ContainsAsset {
                    asset_id: hex::encode(tid),
                },
            ],
        };

        // Both match.
        assert!(pred.matches(&tree, &tokens, 0));

        // Only tree matches.
        assert!(pred.matches(&tree, &[], 0));

        // Only token matches.
        assert!(pred.matches(&[0xFF], &tokens, 0));

        // Neither matches.
        assert!(!pred.matches(&[0xFF], &[], 0));
    }

    // -- JSON round-trip --

    #[test]
    fn json_roundtrip() {
        let pred = ScanningPredicate::And {
            args: vec![
                ScanningPredicate::Equals {
                    register: "R1".to_owned(),
                    value: "0008cd".to_owned(),
                },
                ScanningPredicate::Or {
                    args: vec![
                        ScanningPredicate::ContainsAsset {
                            asset_id: hex::encode(token_id(0xAA)),
                        },
                        ScanningPredicate::Contains {
                            register: "R1".to_owned(),
                            value: "deadbeef".to_owned(),
                        },
                    ],
                },
            ],
        };

        let json = serde_json::to_string(&pred).expect("serialize");
        let restored: ScanningPredicate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pred, restored);
    }

    #[test]
    fn json_roundtrip_scan() {
        let scan = Scan {
            scan_id: FIRST_USER_SCAN_ID,
            scan_name: "My Scan".to_owned(),
            tracking_rule: ScanningPredicate::ContainsAsset {
                asset_id: hex::encode(token_id(0xCC)),
            },
            wallet_interaction: ScanWalletInteraction::Shared,
            remove_offchain: true,
        };

        let json = serde_json::to_string(&scan).expect("serialize");
        let restored: Scan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(scan, restored);
    }

    // -- Constants --

    #[test]
    fn well_known_scan_ids() {
        assert_eq!(MINING_SCAN_ID, 9);
        assert_eq!(PAYMENTS_SCAN_ID, 10);
        assert_eq!(FIRST_USER_SCAN_ID, 11);
        assert!(FIRST_USER_SCAN_ID > PAYMENTS_SCAN_ID);
    }

    // -- Default register --

    #[test]
    fn default_register_is_r1() {
        let json = r#"{"predicate":"equals","value":"aabb"}"#;
        let pred: ScanningPredicate = serde_json::from_str(json).expect("parse");
        if let ScanningPredicate::Equals { register, .. } = &pred {
            assert_eq!(register, "R1");
        } else {
            panic!("expected Equals variant");
        }
    }

    // -- Unknown register --

    #[test]
    fn unknown_register_returns_empty() {
        let pred = ScanningPredicate::Equals {
            register: "R5".to_owned(),
            value: hex::encode([0x00]),
        };
        // Unknown register is empty, so it won't match a non-empty value.
        assert!(!pred.matches(&[0x00, 0x08], &[], 0));
    }

    // -- Invalid hex --

    #[test]
    fn invalid_hex_does_not_match() {
        let pred = ScanningPredicate::Equals {
            register: "R1".to_owned(),
            value: "not_valid_hex!!".to_owned(),
        };
        assert!(!pred.matches(&[0x00], &[], 0));
    }

    // -- ScanWalletInteraction default --

    #[test]
    fn scan_wallet_interaction_default_is_off() {
        assert_eq!(ScanWalletInteraction::default(), ScanWalletInteraction::Off);
    }
}
