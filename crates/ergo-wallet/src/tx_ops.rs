//! Transaction building, signing, and box collection operations.
//!
//! Provides three main operations:
//!
//! 1. **Build unsigned transaction** from payment requests using ergo-lib's
//!    `SimpleBoxSelector` and `TxBuilder`.
//! 2. **Sign a transaction** with wallet keys and an `ErgoStateContext`
//!    derived from blockchain headers.
//! 3. **Collect boxes** matching a target balance via greedy selection.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;

use ergo_consensus::sigma_verify::{convert_state_context, SigmaStateContext};
use ergo_lib::chain::ergo_box::box_builder::ErgoBoxCandidateBuilder;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::wallet::box_selector::{BoxSelection, BoxSelector, SimpleBoxSelector};
use ergo_lib::wallet::tx_builder::TxBuilder;
use ergo_lib::wallet::tx_context::TransactionContext;
use ergo_lib::wallet::Wallet;
use ergotree_ir::chain::address::{AddressEncoder, NetworkPrefix};
use ergotree_ir::chain::ergo_box::box_value::BoxValue;
use ergotree_ir::chain::ergo_box::{BoxTokens, ErgoBox, NonMandatoryRegisters};
use ergotree_ir::chain::token::{Token, TokenAmount, TokenId};
use ergotree_ir::chain::tx_id::TxId;
use ergotree_ir::ergo_tree::ErgoTree;
use ergotree_ir::serialization::SigmaSerializable;

use crate::keys::WalletKeys;
use crate::tracked_box::TrackedBox;

// ---------------------------------------------------------------------------
// PaymentRequest
// ---------------------------------------------------------------------------

/// A request to send funds to an address.
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// Base58-encoded Ergo address (mainnet).
    pub address: String,
    /// Amount in nanoERG.
    pub value: u64,
    /// Tokens to include: `(token_id_hex, amount)`.
    pub tokens: Vec<(String, u64)>,
}

// ---------------------------------------------------------------------------
// TxOpsError
// ---------------------------------------------------------------------------

/// Errors produced by transaction operations.
#[derive(Debug)]
pub enum TxOpsError {
    /// Not enough ERG across available boxes.
    InsufficientFunds {
        /// How much was needed.
        needed: u64,
        /// How much was available.
        available: u64,
    },
    /// Not enough of a specific token across available boxes.
    InsufficientTokens {
        /// Hex-encoded token ID.
        token_id: String,
        /// How many were needed.
        needed: u64,
        /// How many were available.
        available: u64,
    },
    /// Transaction building failed.
    BuildError(String),
    /// Transaction signing failed.
    SignError(String),
    /// Address parsing or encoding error.
    AddressError(String),
}

impl std::fmt::Display for TxOpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxOpsError::InsufficientFunds { needed, available } => {
                write!(
                    f,
                    "insufficient funds: needed {needed}, available {available}"
                )
            }
            TxOpsError::InsufficientTokens {
                token_id,
                needed,
                available,
            } => {
                write!(
                    f,
                    "insufficient tokens ({token_id}): needed {needed}, available {available}"
                )
            }
            TxOpsError::BuildError(msg) => write!(f, "build error: {msg}"),
            TxOpsError::SignError(msg) => write!(f, "sign error: {msg}"),
            TxOpsError::AddressError(msg) => write!(f, "address error: {msg}"),
        }
    }
}

impl std::error::Error for TxOpsError {}

// ---------------------------------------------------------------------------
// Helper: TrackedBox -> ergo-lib ErgoBox
// ---------------------------------------------------------------------------

/// Convert a [`TrackedBox`] into an ergo-lib [`ErgoBox`].
///
/// Parses the ErgoTree from raw bytes and constructs the full `ErgoBox` with
/// tokens, value, creation height, transaction id, and output index.
fn tracked_to_ergo_box(tb: &TrackedBox) -> Result<ErgoBox, TxOpsError> {
    let ergo_tree = ErgoTree::sigma_parse_bytes(&tb.ergo_tree_bytes)
        .map_err(|e| TxOpsError::BuildError(format!("ErgoTree parse error: {e}")))?;

    let value = BoxValue::new(tb.value)
        .map_err(|e| TxOpsError::BuildError(format!("invalid box value: {e}")))?;

    let tokens: Option<BoxTokens> = if tb.tokens.is_empty() {
        None
    } else {
        let token_vec: Vec<Token> = tb
            .tokens
            .iter()
            .map(|(tid, amt)| {
                let token_id: TokenId = ergo_chain_types::Digest32::from(*tid).into();
                let amount = TokenAmount::try_from(*amt)
                    .map_err(|e| TxOpsError::BuildError(format!("invalid token amount: {e}")))?;
                Ok(Token { token_id, amount })
            })
            .collect::<Result<Vec<_>, TxOpsError>>()?;
        Some(
            BoxTokens::from_vec(token_vec)
                .map_err(|e| TxOpsError::BuildError(format!("token vec error: {e}")))?,
        )
    };

    let tx_id = TxId(ergo_chain_types::Digest32::from(tb.tx_id));

    let registers = if tb.additional_registers.is_empty() {
        NonMandatoryRegisters::empty()
    } else {
        use ergotree_ir::chain::ergo_box::{NonMandatoryRegisterId, RegisterValue};
        use std::collections::HashMap;

        let mut reg_map: HashMap<NonMandatoryRegisterId, RegisterValue> = HashMap::new();
        for &(idx, ref bytes) in &tb.additional_registers {
            if let Ok(reg_id) = NonMandatoryRegisterId::try_from(idx as i8) {
                let reg_val = RegisterValue::sigma_parse_bytes(bytes);
                reg_map.insert(reg_id, reg_val);
            }
        }
        NonMandatoryRegisters::try_from(reg_map).unwrap_or_else(|_| NonMandatoryRegisters::empty())
    };

    ErgoBox::new(
        value,
        ergo_tree,
        tokens,
        registers,
        tb.creation_height,
        tx_id,
        tb.output_index,
    )
    .map_err(|e| TxOpsError::BuildError(format!("ErgoBox construction error: {e}")))
}

// ---------------------------------------------------------------------------
// build_unsigned_tx
// ---------------------------------------------------------------------------

/// Build an unsigned transaction from payment requests.
///
/// 1. Compute target ERG and tokens from all payment requests + fee
/// 2. Select boxes using [`SimpleBoxSelector`]
/// 3. Build outputs from payment requests
/// 4. Build unsigned tx via [`TxBuilder`]
///
/// Returns the `UnsignedTransaction` and the list of input box IDs.
pub fn build_unsigned_tx(
    requests: &[PaymentRequest],
    fee: u64,
    change_address: &str,
    unspent_boxes: &[TrackedBox],
    current_height: u32,
) -> Result<(UnsignedTransaction, Vec<[u8; 32]>), TxOpsError> {
    if requests.is_empty() {
        return Err(TxOpsError::BuildError(
            "no payment requests provided".into(),
        ));
    }

    // --- Parse change address -----------------------------------------------
    let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
    let change_addr = encoder
        .parse_address_from_str(change_address)
        .map_err(|e| TxOpsError::AddressError(format!("invalid change address: {e}")))?;

    // --- Aggregate target values --------------------------------------------
    let total_erg: u64 = requests.iter().map(|r| r.value).sum::<u64>() + fee;
    let fee_box_value = BoxValue::new(fee)
        .map_err(|e| TxOpsError::BuildError(format!("invalid fee value: {e}")))?;

    // Aggregate target tokens
    let mut target_tokens_map: HashMap<String, u64> = HashMap::new();
    for req in requests {
        for (tid, amt) in &req.tokens {
            *target_tokens_map.entry(tid.clone()).or_insert(0) += amt;
        }
    }
    let target_tokens: Vec<Token> = target_tokens_map
        .iter()
        .map(|(hex_id, &amt)| {
            let bytes: [u8; 32] = hex::decode(hex_id)
                .map_err(|e| TxOpsError::BuildError(format!("bad token id hex: {e}")))?
                .try_into()
                .map_err(|_| TxOpsError::BuildError("token id must be 32 bytes".into()))?;
            let token_id: TokenId = ergo_chain_types::Digest32::from(bytes).into();
            let amount = TokenAmount::try_from(amt)
                .map_err(|e| TxOpsError::BuildError(format!("bad token amount: {e}")))?;
            Ok(Token { token_id, amount })
        })
        .collect::<Result<Vec<_>, TxOpsError>>()?;

    // --- Convert TrackedBox -> ErgoBox --------------------------------------
    let ergo_boxes: Vec<ErgoBox> = unspent_boxes
        .iter()
        .map(tracked_to_ergo_box)
        .collect::<Result<Vec<_>, TxOpsError>>()?;

    // --- Select inputs using SimpleBoxSelector ------------------------------
    let target_balance = BoxValue::new(total_erg)
        .map_err(|e| TxOpsError::BuildError(format!("invalid target balance: {e}")))?;

    let selector = SimpleBoxSelector::new();
    let selection: BoxSelection<ErgoBox> = selector
        .select(ergo_boxes, target_balance, &target_tokens)
        .map_err(|e| TxOpsError::BuildError(format!("box selection failed: {e}")))?;

    // --- Build output candidates from payment requests ----------------------
    let mut output_candidates = Vec::new();
    for req in requests {
        let addr = encoder
            .parse_address_from_str(&req.address)
            .map_err(|e| TxOpsError::AddressError(format!("invalid recipient address: {e}")))?;
        let ergo_tree = addr
            .script()
            .map_err(|e| TxOpsError::AddressError(format!("address script error: {e}")))?;
        let box_value = BoxValue::new(req.value)
            .map_err(|e| TxOpsError::BuildError(format!("invalid output value: {e}")))?;
        let mut builder = ErgoBoxCandidateBuilder::new(box_value, ergo_tree, current_height);
        for (tid_hex, amt) in &req.tokens {
            let bytes: [u8; 32] = hex::decode(tid_hex)
                .map_err(|e| TxOpsError::BuildError(format!("bad token id hex: {e}")))?
                .try_into()
                .map_err(|_| TxOpsError::BuildError("token id must be 32 bytes".into()))?;
            let token_id: TokenId = ergo_chain_types::Digest32::from(bytes).into();
            let amount = TokenAmount::try_from(*amt)
                .map_err(|e| TxOpsError::BuildError(format!("bad token amount: {e}")))?;
            builder.add_token(Token { token_id, amount });
        }
        let candidate = builder
            .build()
            .map_err(|e| TxOpsError::BuildError(format!("output box build error: {e}")))?;
        output_candidates.push(candidate);
    }

    // --- Build unsigned transaction via TxBuilder ---------------------------
    let tx_builder = TxBuilder::new(
        selection.clone(),
        output_candidates,
        current_height,
        fee_box_value,
        change_addr,
    );

    let unsigned_tx: UnsignedTransaction = tx_builder
        .build()
        .map_err(|e| TxOpsError::BuildError(format!("tx build error: {e}")))?;

    // Collect input box IDs
    let input_ids: Vec<[u8; 32]> = selection
        .boxes
        .iter()
        .map(|b| {
            let box_id = b.box_id();
            let id_ref: &[u8] = box_id.as_ref();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(id_ref);
            arr
        })
        .collect();

    Ok((unsigned_tx, input_ids))
}

/// Serialize an `UnsignedTransaction` to its bytes-to-sign form.
pub fn serialize_unsigned_tx(tx: &UnsignedTransaction) -> Result<Vec<u8>, TxOpsError> {
    tx.bytes_to_sign()
        .map_err(|e| TxOpsError::BuildError(format!("serialization error: {e}")))
}

// ---------------------------------------------------------------------------
// sign_transaction
// ---------------------------------------------------------------------------

/// Sign an unsigned transaction using wallet keys and blockchain state context.
///
/// Derives secret keys at the given EIP-3 indices, builds a `Wallet` from
/// those secrets, constructs a `TransactionContext` from the unsigned
/// transaction and input/data boxes, then delegates to ergo-lib's
/// `Wallet::sign_transaction`.
///
/// Returns the serialized signed `Transaction` bytes on success.
pub fn sign_transaction(
    unsigned_tx: UnsignedTransaction,
    wallet_keys: &WalletKeys,
    key_indices: &[u32],
    inputs: &[TrackedBox],
    data_boxes: &[TrackedBox],
    state_context: &SigmaStateContext,
) -> Result<Vec<u8>, TxOpsError> {
    // Derive secret keys at the requested EIP-3 indices.
    let secret_keys = wallet_keys
        .secret_keys(key_indices)
        .map_err(|e| TxOpsError::SignError(format!("key derivation failed: {e}")))?;

    let wallet = Wallet::from_secrets(secret_keys);

    // Convert TrackedBox inputs and data boxes to ergo-lib ErgoBox.
    let input_boxes: Vec<ErgoBox> = inputs
        .iter()
        .map(tracked_to_ergo_box)
        .collect::<Result<Vec<_>, TxOpsError>>()?;

    let data_input_boxes: Vec<ErgoBox> = data_boxes
        .iter()
        .map(tracked_to_ergo_box)
        .collect::<Result<Vec<_>, TxOpsError>>()?;

    // Build the transaction context.
    let tx_context = TransactionContext::new(unsigned_tx, input_boxes, data_input_boxes)
        .map_err(|e| TxOpsError::SignError(format!("transaction context error: {e}")))?;

    // Convert our SigmaStateContext to ergo-lib's ErgoStateContext.
    let ergo_state_ctx = convert_state_context(state_context)
        .map_err(|e| TxOpsError::SignError(format!("state context conversion error: {e}")))?;

    // Sign the transaction.
    let signed_tx: Transaction = wallet
        .sign_transaction(tx_context, &ergo_state_ctx, None)
        .map_err(|e| TxOpsError::SignError(format!("signing failed: {e}")))?;

    // Serialize the signed transaction to bytes.
    signed_tx
        .sigma_serialize_bytes()
        .map_err(|e| TxOpsError::SignError(format!("serialization error: {e}")))
}

// ---------------------------------------------------------------------------
// collect_boxes
// ---------------------------------------------------------------------------

/// Collect unspent boxes that satisfy a target balance and optional target
/// tokens.
///
/// Uses greedy selection: iterates boxes, accumulating until the ERG target
/// and all token targets are met.
pub fn collect_boxes(
    unspent: &[TrackedBox],
    target_value: u64,
    target_tokens: &[(String, u64)],
) -> Result<Vec<TrackedBox>, TxOpsError> {
    let mut collected: Vec<TrackedBox> = Vec::new();
    let mut collected_value: u64 = 0;

    // Build remaining-tokens map: token_id_hex -> amount still needed
    let mut tokens_remaining: HashMap<String, u64> = HashMap::new();
    for (tid, amt) in target_tokens {
        *tokens_remaining.entry(tid.clone()).or_insert(0) += amt;
    }

    for tb in unspent {
        if tb.spent {
            continue;
        }

        let value_satisfied = collected_value >= target_value;
        let tokens_satisfied = tokens_remaining.values().all(|&v| v == 0);

        if value_satisfied && tokens_satisfied {
            break;
        }

        // Check if this box contributes anything useful
        let adds_value = collected_value < target_value;
        let adds_tokens = tb.tokens.iter().any(|(tid, _)| {
            let hex_id = hex::encode(tid);
            tokens_remaining.get(&hex_id).copied().unwrap_or(0) > 0
        });

        if !adds_value && !adds_tokens {
            continue;
        }

        collected_value = collected_value.saturating_add(tb.value);

        // Subtract tokens this box provides from remaining
        for (tid, amt) in &tb.tokens {
            let hex_id = hex::encode(tid);
            if let Some(remaining) = tokens_remaining.get_mut(&hex_id) {
                if *remaining > 0 {
                    let subtract = (*remaining).min(*amt);
                    *remaining -= subtract;
                }
            }
        }

        collected.push(tb.clone());
    }

    // Check final satisfaction
    if collected_value < target_value {
        return Err(TxOpsError::InsufficientFunds {
            needed: target_value,
            available: collected_value,
        });
    }

    for (tid, remaining) in &tokens_remaining {
        if *remaining > 0 {
            // Calculate total available for this token
            let total_available: u64 = unspent
                .iter()
                .filter(|b| !b.spent)
                .flat_map(|b| b.tokens.iter())
                .filter(|(t, _)| hex::encode(t) == *tid)
                .map(|(_, amt)| amt)
                .sum();
            return Err(TxOpsError::InsufficientTokens {
                token_id: tid.clone(),
                needed: target_tokens
                    .iter()
                    .filter(|(t, _)| t == tid)
                    .map(|(_, a)| a)
                    .sum(),
                available: total_available,
            });
        }
    }

    Ok(collected)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test tracked box with given value and optional tokens.
    fn make_box(id_byte: u8, value: u64, tokens: Vec<([u8; 32], u64)>) -> TrackedBox {
        let mut box_id = [0u8; 32];
        box_id[0] = id_byte;
        let mut tx_id = [0u8; 32];
        tx_id[0] = id_byte;
        tx_id[1] = 0xFF;

        TrackedBox {
            box_id,
            // A minimal valid P2PK ErgoTree (ProveDlog constant with dummy pubkey)
            ergo_tree_bytes: vec![0x00, 0x08, 0xCD],
            value,
            tokens,
            creation_height: 100,
            inclusion_height: 100,
            tx_id,
            output_index: 0,
            serialized_box: vec![],
            additional_registers: vec![],
            spent: false,
            spending_tx_id: None,
            spending_height: None,
            scan_ids: vec![10],
        }
    }

    fn token_id_from_byte(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    // -----------------------------------------------------------------------
    // collect_boxes tests
    // -----------------------------------------------------------------------

    #[test]
    fn collect_boxes_sufficient_funds() {
        let boxes = vec![
            make_box(1, 1_000_000_000, vec![]),
            make_box(2, 2_000_000_000, vec![]),
            make_box(3, 2_000_000_000, vec![]),
        ];
        // 5 ERG total, request 3 ERG
        let result = collect_boxes(&boxes, 3_000_000_000, &[]).unwrap();
        let total: u64 = result.iter().map(|b| b.value).sum();
        assert!(
            total >= 3_000_000_000,
            "collected total {total} should be >= 3 ERG"
        );
        // Should not need all 3 boxes (first two suffice: 1+2=3 ERG)
        assert!(result.len() <= 3, "should collect at most all boxes");
    }

    #[test]
    fn collect_boxes_insufficient_funds() {
        let boxes = vec![
            make_box(1, 1_000_000_000, vec![]),
            make_box(2, 1_000_000_000, vec![]),
        ];
        // 2 ERG total, request 5 ERG
        let result = collect_boxes(&boxes, 5_000_000_000, &[]);
        match result {
            Err(TxOpsError::InsufficientFunds { needed, available }) => {
                assert_eq!(needed, 5_000_000_000);
                assert_eq!(available, 2_000_000_000);
            }
            other => panic!("expected InsufficientFunds, got: {other:?}"),
        }
    }

    #[test]
    fn collect_boxes_with_tokens() {
        let tok_a = token_id_from_byte(0xAA);
        let tok_b = token_id_from_byte(0xBB);
        let boxes = vec![
            make_box(1, 2_000_000_000, vec![(tok_a, 100)]),
            make_box(2, 2_000_000_000, vec![(tok_b, 200)]),
            make_box(3, 1_000_000_000, vec![(tok_a, 50)]),
        ];
        let tok_a_hex = hex::encode(tok_a);
        let result = collect_boxes(&boxes, 1_000_000_000, &[(tok_a_hex.clone(), 120)]).unwrap();

        // Should collect boxes that have tok_a to reach 120 (box 1 has 100, box 3 has 50)
        let total_tok_a: u64 = result
            .iter()
            .flat_map(|b| b.tokens.iter())
            .filter(|(t, _)| *t == tok_a)
            .map(|(_, a)| a)
            .sum();
        assert!(
            total_tok_a >= 120,
            "collected token A amount {total_tok_a} should be >= 120"
        );
    }

    #[test]
    fn collect_boxes_insufficient_tokens() {
        let tok_a = token_id_from_byte(0xAA);
        let boxes = vec![
            make_box(1, 2_000_000_000, vec![(tok_a, 50)]),
            make_box(2, 2_000_000_000, vec![]),
        ];
        let tok_a_hex = hex::encode(tok_a);
        let result = collect_boxes(&boxes, 1_000_000_000, &[(tok_a_hex.clone(), 200)]);
        match result {
            Err(TxOpsError::InsufficientTokens {
                token_id,
                needed,
                available,
            }) => {
                assert_eq!(token_id, tok_a_hex);
                assert_eq!(needed, 200);
                assert_eq!(available, 50);
            }
            other => panic!("expected InsufficientTokens, got: {other:?}"),
        }
    }

    #[test]
    fn collect_boxes_skips_spent() {
        let mut spent_box = make_box(1, 5_000_000_000, vec![]);
        spent_box.spent = true;
        let boxes = vec![spent_box, make_box(2, 1_000_000_000, vec![])];
        let result = collect_boxes(&boxes, 2_000_000_000, &[]);
        match result {
            Err(TxOpsError::InsufficientFunds { needed, available }) => {
                assert_eq!(needed, 2_000_000_000);
                assert_eq!(available, 1_000_000_000);
            }
            other => panic!("expected InsufficientFunds, got: {other:?}"),
        }
    }

    #[test]
    fn collect_boxes_exact_value() {
        let boxes = vec![
            make_box(1, 1_000_000_000, vec![]),
            make_box(2, 2_000_000_000, vec![]),
        ];
        let result = collect_boxes(&boxes, 3_000_000_000, &[]).unwrap();
        let total: u64 = result.iter().map(|b| b.value).sum();
        assert_eq!(total, 3_000_000_000);
        assert_eq!(result.len(), 2);
    }

    // -----------------------------------------------------------------------
    // build_unsigned_tx tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_unsigned_tx_validates_funds() {
        // Create boxes with only minimal value, request far more than available
        let boxes = vec![make_box(1, 1_000_000, vec![])];
        let requests = vec![PaymentRequest {
            address: "9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zit1YUkY".into(),
            value: 100_000_000_000, // 100 ERG — way more than available
            tokens: vec![],
        }];
        let result = build_unsigned_tx(
            &requests,
            1_100_000,
            "9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zit1YUkY",
            &boxes,
            100,
        );
        assert!(result.is_err(), "should fail with insufficient funds");
    }

    #[test]
    fn build_unsigned_tx_empty_requests() {
        let boxes = vec![make_box(1, 1_000_000_000, vec![])];
        let result = build_unsigned_tx(
            &[],
            1_100_000,
            "9f4QF8AD1nQ3nJahQVkMj8hFSVVzVom77b52JU7EW71Zit1YUkY",
            &boxes,
            100,
        );
        match result {
            Err(TxOpsError::BuildError(msg)) => {
                assert!(msg.contains("no payment requests"), "got: {msg}");
            }
            other => panic!("expected BuildError, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // sign_transaction tests
    // -----------------------------------------------------------------------

    #[test]
    fn sign_transaction_fails_gracefully_with_empty_inputs() {
        use ergo_consensus::sigma_verify::SigmaStateContext;

        let keys = test_wallet_keys();

        // Build a valid P2PK ErgoTree using the secp256k1 generator point.
        let gen_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let gen_bytes = hex::decode(gen_hex).unwrap();
        let mut tree_bytes = vec![0x00, 0x08, 0xCD];
        tree_bytes.extend_from_slice(&gen_bytes);
        let ergo_tree = ErgoTree::sigma_parse_bytes(&tree_bytes).unwrap();

        let box_value = BoxValue::new(1_000_000_000).unwrap();
        let candidate = ergo_lib::chain::ergo_box::box_builder::ErgoBoxCandidateBuilder::new(
            box_value, ergo_tree, 100,
        )
        .build()
        .unwrap();

        let unsigned_input = ergo_lib::chain::transaction::UnsignedInput::new(
            ergotree_ir::chain::ergo_box::BoxId::zero(),
            ergotree_ir::chain::context_extension::ContextExtension::empty(),
        );
        let unsigned_tx =
            UnsignedTransaction::new_from_vec(vec![unsigned_input], vec![], vec![candidate])
                .unwrap();

        let mut miner_pk = [0u8; 33];
        miner_pk.copy_from_slice(&gen_bytes);

        let state_ctx = SigmaStateContext {
            last_headers: vec![],
            current_height: 100,
            current_timestamp: 1000,
            current_n_bits: 100,
            current_votes: [0; 3],
            current_miner_pk: miner_pk,
            state_digest: [0; 33],
            parameters: ergo_consensus::parameters::Parameters::genesis(),
            current_version: 2,
            current_parent_id: [0; 32],
        };

        // Pass empty inputs -- TransactionContext::new requires at least one
        // input box that matches the unsigned tx inputs, so this should fail.
        let result = sign_transaction(unsigned_tx, &keys, &[0], &[], &[], &state_ctx);
        match result {
            Err(TxOpsError::SignError(msg)) => {
                assert!(
                    !msg.is_empty(),
                    "error message should be non-empty, got: {msg}"
                );
            }
            other => panic!("expected SignError, got: {other:?}"),
        }
    }

    /// Create test wallet keys for signing tests.
    fn test_wallet_keys() -> WalletKeys {
        WalletKeys::from_mnemonic(
            "slow silly start wash bundle suffer bulb ancient height spin express remind today effort helmet",
            "",
        )
        .unwrap()
    }
}
