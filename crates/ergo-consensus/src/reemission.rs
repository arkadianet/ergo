//! EIP-27 Re-emission validation rules.
//!
//! After activation height 777,217 (mainnet), additional consensus checks
//! are required for transactions that spend the emission box or contain
//! re-emission tokens.

use ergo_types::transaction::{ErgoBox, ErgoBoxCandidate, ErgoTransaction};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// EIP-27 activation height (mainnet).
pub const EIP27_ACTIVATION_HEIGHT: u32 = 777_217;

/// Coins in one ERG (nanoERGs).
pub const COINS_IN_ONE_ERG: u64 = 1_000_000_000;

/// Fixed rate period for emission (blocks).
pub const FIXED_RATE_PERIOD: u32 = 525_600;
/// Fixed rate per block (nanoERGs).
pub const FIXED_RATE: u64 = 75 * COINS_IN_ONE_ERG;
/// Epoch length for emission reduction.
pub const EMISSION_EPOCH_LENGTH: u32 = 64_800;
/// Reduction per epoch (nanoERGs).
pub const ONE_EPOCH_REDUCTION: u64 = 3 * COINS_IN_ONE_ERG;

/// Basic charge amount for re-emission (12 ERG).
pub const BASIC_CHARGE_AMOUNT: u64 = 12 * COINS_IN_ONE_ERG;
/// Minimum miner reward (3 ERG) -- matches REEMISSION_REWARD in emission.rs.
pub const MIN_MINER_REWARD: u64 = 3 * COINS_IN_ONE_ERG;

/// Minimum emission box value to trigger emission-path checks (100,000 ERG).
pub const MIN_EMISSION_BOX_VALUE: u64 = 100_000 * COINS_IN_ONE_ERG;

/// Emission NFT token ID (mainnet).
pub const EMISSION_NFT_ID: [u8; 32] = [
    0x20, 0xfa, 0x2b, 0xf2, 0x39, 0x62, 0xcd, 0xf5, 0x1b, 0x07, 0x72, 0x2d, 0x62, 0x37, 0xc0, 0xc7,
    0xb8, 0xa4, 0x4f, 0x78, 0x85, 0x6c, 0x0f, 0x7e, 0xc3, 0x08, 0xdc, 0x1e, 0xf1, 0xa9, 0x2a, 0x51,
];

/// Re-emission token ID (mainnet).
pub const REEMISSION_TOKEN_ID: [u8; 32] = [
    0xd9, 0xa2, 0xcc, 0x8a, 0x09, 0xab, 0xfa, 0xed, 0x87, 0xaf, 0xac, 0xfb, 0xb7, 0xda, 0xee, 0x79,
    0xa6, 0xb2, 0x6f, 0x10, 0xc6, 0x61, 0x3f, 0xc1, 0x3d, 0x3f, 0x39, 0x53, 0xe5, 0x52, 0x1d, 0x1a,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ReemissionError {
    #[error("emission NFT not preserved in output[0]")]
    EmissionNftNotPreserved,
    #[error("reemission tokens not conserved: in={in_amount}, out={out_amount}")]
    ReemissionTokensNotConserved { in_amount: u64, out_amount: u64 },
    #[error("wrong reemission reward: expected={expected}, got={got}")]
    WrongReemissionReward { expected: u64, got: u64 },
    #[error("reemission tokens not fully burned in outputs")]
    ReemissionTokensNotBurned,
}

// ---------------------------------------------------------------------------
// Emission / re-emission computation
// ---------------------------------------------------------------------------

/// Compute the emission amount for a given height.
///
/// Matches the logic in `ergo-network/src/emission.rs::emission_at_height`.
pub fn emission_at_height(h: u32) -> u64 {
    if h < FIXED_RATE_PERIOD {
        FIXED_RATE
    } else {
        let epoch = 1 + (h - FIXED_RATE_PERIOD) / EMISSION_EPOCH_LENGTH;
        let reduction = ONE_EPOCH_REDUCTION * u64::from(epoch);
        FIXED_RATE.saturating_sub(reduction)
    }
}

/// Compute the re-emission charge for a given height.
///
/// Matches the logic in `ergo-network/src/emission.rs::reemission_for_height`.
pub fn reemission_for_height(h: u32) -> u64 {
    if h < EIP27_ACTIVATION_HEIGHT {
        return 0;
    }
    let emission = emission_at_height(h);
    if emission >= BASIC_CHARGE_AMOUNT + MIN_MINER_REWARD {
        BASIC_CHARGE_AMOUNT
    } else {
        emission.saturating_sub(MIN_MINER_REWARD)
    }
}

// ---------------------------------------------------------------------------
// Token counting helpers
// ---------------------------------------------------------------------------

/// Count tokens of a given ID across a box's tokens.
fn count_token(ergo_box: &ErgoBox, token_id: &[u8; 32]) -> u64 {
    ergo_box
        .candidate
        .tokens
        .iter()
        .filter(|(id, _)| id.0 == *token_id)
        .map(|(_, amount)| amount)
        .sum()
}

/// Count tokens of a given ID in a box candidate.
fn count_token_candidate(candidate: &ErgoBoxCandidate, token_id: &[u8; 32]) -> u64 {
    candidate
        .tokens
        .iter()
        .filter(|(id, _)| id.0 == *token_id)
        .map(|(_, amount)| amount)
        .sum()
}

/// Check if a box has a specific token.
fn has_token(ergo_box: &ErgoBox, token_id: &[u8; 32]) -> bool {
    ergo_box
        .candidate
        .tokens
        .iter()
        .any(|(id, _)| id.0 == *token_id)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify EIP-27 re-emission spending rules for a transaction.
///
/// Returns `Ok(())` if:
/// - Height < activation height (no checks needed)
/// - Transaction does not involve emission/reemission tokens
/// - All re-emission rules pass
pub fn verify_reemission_spending(
    tx: &ErgoTransaction,
    input_boxes: &[ErgoBox],
    height: u32,
) -> Result<(), ReemissionError> {
    if height < EIP27_ACTIVATION_HEIGHT {
        return Ok(());
    }

    // Path 1: Emission box spending.
    // Find input with emission NFT and value > MIN_EMISSION_BOX_VALUE.
    let emission_input = input_boxes
        .iter()
        .find(|b| has_token(b, &EMISSION_NFT_ID) && b.candidate.value > MIN_EMISSION_BOX_VALUE);

    if let Some(_emission_box) = emission_input {
        // Verify emission NFT is preserved in output[0].
        if tx.output_candidates.is_empty()
            || !tx.output_candidates[0]
                .tokens
                .iter()
                .any(|(id, _)| id.0 == EMISSION_NFT_ID)
        {
            return Err(ReemissionError::EmissionNftNotPreserved);
        }

        // Count reemission tokens in inputs.
        let reemission_tokens_in: u64 = input_boxes
            .iter()
            .map(|b| count_token(b, &REEMISSION_TOKEN_ID))
            .sum();

        // Count reemission tokens in emission output (output[0]).
        let emission_tokens_out =
            count_token_candidate(&tx.output_candidates[0], &REEMISSION_TOKEN_ID);

        // Count reemission tokens in rewards output (output[1] if exists).
        let rewards_tokens_out = if tx.output_candidates.len() > 1 {
            count_token_candidate(&tx.output_candidates[1], &REEMISSION_TOKEN_ID)
        } else {
            0
        };

        // Verify conservation: tokens_in == emission_out + rewards_out.
        let total_out = emission_tokens_out + rewards_tokens_out;
        if reemission_tokens_in != total_out {
            return Err(ReemissionError::ReemissionTokensNotConserved {
                in_amount: reemission_tokens_in,
                out_amount: total_out,
            });
        }

        // Verify rewards match expected re-emission amount.
        let expected_rewards = reemission_for_height(height);
        if rewards_tokens_out != expected_rewards {
            return Err(ReemissionError::WrongReemissionReward {
                expected: expected_rewards,
                got: rewards_tokens_out,
            });
        }

        return Ok(());
    }

    // Path 2: Re-emission token spending (any input with reemission tokens,
    // but not the emission box).
    let has_reemission_input = input_boxes
        .iter()
        .any(|b| has_token(b, &REEMISSION_TOKEN_ID));

    if has_reemission_input {
        // All outputs must NOT contain reemission tokens (they must be burned).
        for output in &tx.output_candidates {
            if output
                .tokens
                .iter()
                .any(|(id, _)| id.0 == REEMISSION_TOKEN_ID)
            {
                return Err(ReemissionError::ReemissionTokensNotBurned);
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::transaction::*;

    #[test]
    fn test_reemission_before_activation() {
        let tx = ErgoTransaction {
            inputs: vec![],
            data_inputs: vec![],
            output_candidates: vec![],
            tx_id: TxId([0; 32]),
        };
        assert!(verify_reemission_spending(&tx, &[], 700_000).is_ok());
    }

    #[test]
    fn test_reemission_no_emission_tokens() {
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0; 32]),
        };
        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        assert!(verify_reemission_spending(&tx, &[input_box], 800_000).is_ok());
    }

    #[test]
    fn test_emission_at_height_fixed_period() {
        assert_eq!(emission_at_height(1), 75 * COINS_IN_ONE_ERG);
        assert_eq!(emission_at_height(525_599), 75 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn test_emission_at_height_decreasing() {
        // First reduction epoch starts at height 525,600:
        // epoch = 1 + (525_600 - 525_600)/64_800 = 1
        // emission = 75 - 3*1 = 72 ERG
        assert_eq!(emission_at_height(525_600), 72 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn test_emission_matches_network_module() {
        // Verify our emission_at_height matches the one in ergo-network.
        // Height 525,601: epoch = 1 + (525_601 - 525_600)/64_800 = 1 + 0 = 1
        // emission = 75 - 3*1 = 72 ERG
        assert_eq!(emission_at_height(525_601), 72 * COINS_IN_ONE_ERG);

        // Height 590,400: epoch = 1 + (590_400 - 525_600)/64_800 = 1 + 1 = 2
        // emission = 75 - 3*2 = 69 ERG
        assert_eq!(emission_at_height(590_400), 69 * COINS_IN_ONE_ERG);

        // Height 2,080,800: epoch = 1 + (2_080_800 - 525_600)/64_800 = 25
        // emission = 75 - 3*25 = 0 ERG
        assert_eq!(emission_at_height(2_080_800), 0);
    }

    #[test]
    fn test_reemission_for_height_basic_charge() {
        // At height 800,000:
        // epoch = 1 + (800_000 - 525_600)/64_800 = 1 + 4 = 5
        // emission = 75 - 3*5 = 60 ERG
        // 60 >= 12 + 3 = 15, so charge = 12 ERG
        let r = reemission_for_height(800_000);
        assert_eq!(r, 12 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn test_reemission_for_height_before_activation() {
        assert_eq!(reemission_for_height(700_000), 0);
    }

    #[test]
    fn test_reemission_for_height_low_emission() {
        // Height 1,951,200: epoch = 1 + (1_951_200 - 525_600)/64_800 = 23
        // emission = 75 - 3*23 = 6 ERG
        // 6 < 12 + 3 = 15, so charge = 6 - 3 = 3 ERG
        let h = 1_951_200;
        assert_eq!(emission_at_height(h), 6 * COINS_IN_ONE_ERG);
        assert_eq!(reemission_for_height(h), 3 * COINS_IN_ONE_ERG);
    }

    #[test]
    fn test_reemission_tokens_not_burned() {
        // Transaction with reemission tokens in input but not properly burned.
        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![(BoxId(REEMISSION_TOKEN_ID), 100)],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![(BoxId(REEMISSION_TOKEN_ID), 100)], // NOT burned!
                additional_registers: vec![],
            }],
            tx_id: TxId([0; 32]),
        };
        let result = verify_reemission_spending(&tx, &[input_box], 800_000);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ReemissionError::ReemissionTokensNotBurned)
        ));
    }

    #[test]
    fn test_reemission_tokens_properly_burned() {
        // Transaction with reemission tokens in input, properly burned (no reemission tokens in outputs).
        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![(BoxId(REEMISSION_TOKEN_ID), 100)],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![], // Properly burned.
                additional_registers: vec![],
            }],
            tx_id: TxId([0; 32]),
        };
        let result = verify_reemission_spending(&tx, &[input_box], 800_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emission_nft_not_preserved() {
        // Input has emission NFT with high value, but output[0] does not preserve it.
        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: MIN_EMISSION_BOX_VALUE + 1,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![(BoxId(EMISSION_NFT_ID), 1)],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![], // Missing emission NFT!
                additional_registers: vec![],
            }],
            tx_id: TxId([0; 32]),
        };
        let result = verify_reemission_spending(&tx, &[input_box], 800_000);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ReemissionError::EmissionNftNotPreserved)
        ));
    }

    #[test]
    fn test_emission_box_spending_correct() {
        // Correct emission box spending: NFT preserved, reemission tokens conserved,
        // correct reward amount.
        let height = 800_000;
        let expected_reward = reemission_for_height(height);
        assert_eq!(expected_reward, 12 * COINS_IN_ONE_ERG);

        let total_reemission_tokens: u64 = 100 * COINS_IN_ONE_ERG;

        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: MIN_EMISSION_BOX_VALUE + 1,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![
                    (BoxId(EMISSION_NFT_ID), 1),
                    (BoxId(REEMISSION_TOKEN_ID), total_reemission_tokens),
                ],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![
                // output[0]: emission box with NFT + remaining reemission tokens
                ErgoBoxCandidate {
                    value: MIN_EMISSION_BOX_VALUE,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![
                        (BoxId(EMISSION_NFT_ID), 1),
                        (
                            BoxId(REEMISSION_TOKEN_ID),
                            total_reemission_tokens - expected_reward,
                        ),
                    ],
                    additional_registers: vec![],
                },
                // output[1]: rewards with reemission tokens
                ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![(BoxId(REEMISSION_TOKEN_ID), expected_reward)],
                    additional_registers: vec![],
                },
            ],
            tx_id: TxId([0; 32]),
        };
        let result = verify_reemission_spending(&tx, &[input_box], height);
        assert!(result.is_ok());
    }

    #[test]
    fn test_emission_box_wrong_reward() {
        // Emission box spending with incorrect reward amount.
        let height = 800_000;
        let expected_reward = reemission_for_height(height);
        let wrong_reward = expected_reward + 1; // Off by one

        let total_reemission_tokens: u64 = 100 * COINS_IN_ONE_ERG;

        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: MIN_EMISSION_BOX_VALUE + 1,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![
                    (BoxId(EMISSION_NFT_ID), 1),
                    (BoxId(REEMISSION_TOKEN_ID), total_reemission_tokens),
                ],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: MIN_EMISSION_BOX_VALUE,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![
                        (BoxId(EMISSION_NFT_ID), 1),
                        (
                            BoxId(REEMISSION_TOKEN_ID),
                            total_reemission_tokens - wrong_reward,
                        ),
                    ],
                    additional_registers: vec![],
                },
                ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![(BoxId(REEMISSION_TOKEN_ID), wrong_reward)],
                    additional_registers: vec![],
                },
            ],
            tx_id: TxId([0; 32]),
        };
        let result = verify_reemission_spending(&tx, &[input_box], height);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ReemissionError::WrongReemissionReward { .. })
        ));
    }

    #[test]
    fn test_emission_box_tokens_not_conserved() {
        // Emission box spending where reemission tokens are not conserved.
        let height = 800_000;
        let expected_reward = reemission_for_height(height);
        let total_reemission_tokens: u64 = 100 * COINS_IN_ONE_ERG;

        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: MIN_EMISSION_BOX_VALUE + 1,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![
                    (BoxId(EMISSION_NFT_ID), 1),
                    (BoxId(REEMISSION_TOKEN_ID), total_reemission_tokens),
                ],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: MIN_EMISSION_BOX_VALUE,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![
                        (BoxId(EMISSION_NFT_ID), 1),
                        // Missing some tokens -- not conserved!
                        (BoxId(REEMISSION_TOKEN_ID), 100),
                    ],
                    additional_registers: vec![],
                },
                ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![(BoxId(REEMISSION_TOKEN_ID), expected_reward)],
                    additional_registers: vec![],
                },
            ],
            tx_id: TxId([0; 32]),
        };
        let result = verify_reemission_spending(&tx, &[input_box], height);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ReemissionError::ReemissionTokensNotConserved { .. })
        ));
    }

    #[test]
    fn test_emission_box_below_min_value_skipped() {
        // Emission box with NFT but value below threshold -- not considered emission path.
        let input_box = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: MIN_EMISSION_BOX_VALUE - 1, // Below threshold
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![(BoxId(EMISSION_NFT_ID), 1)],
                additional_registers: vec![],
            },
            transaction_id: TxId([0; 32]),
            index: 0,
            box_id: BoxId([0; 32]),
        };
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0; 32]),
        };
        // Not an emission box spending, no reemission tokens -- should pass.
        let result = verify_reemission_spending(&tx, &[input_box], 800_000);
        assert!(result.is_ok());
    }
}
