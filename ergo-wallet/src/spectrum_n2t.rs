//! Direct swaps against the exact canonical Spectrum N2T v1 contract.
//!
//! The successor is output zero. The pool NFT, LP reserve, script and all
//! registers are preserved. The contract prices against the FULL ERG value;
//! the 0.01 ERG storage floor is a successor constraint, not a price reserve.

use std::collections::BTreeSet;

use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{write_ergo_box_candidate, ErgoBox, ErgoBoxCandidate};
use ergo_ser::input::{ContextExtension, UnsignedInput};
use ergo_ser::register::{AdditionalRegisters, RegisterId};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::UnsignedTransaction;
use ergo_validation::ProtocolParams;
use num_bigint::BigUint;

use crate::WalletError;

/// Canonical proposition hash captured independently from mainnet pool bytes.
pub const TREE_HASH: &str = "99f30ad579a2c98ad31b432676627fcd9e303d43c06e898725f6155d8ac40aa9";
pub const STORAGE_FLOOR: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ErgToToken,
    TokenToErg,
}

#[derive(Clone, Debug)]
pub struct Pool {
    pub box_data: ErgoBox,
    pub fee_numerator: u64,
}

fn invalid(message: impl Into<String>) -> WalletError {
    WalletError::TxBuild(message.into())
}

pub fn is_supported_tree(bytes: &[u8]) -> bool {
    ergo_ser::ergo_tree::tree_hash_from_bytes(bytes)
        .is_ok_and(|hash| hex::encode(hash) == TREE_HASH)
}

fn is_p2pk(bytes: &[u8]) -> bool {
    bytes.len() == 36
        && bytes.starts_with(&[0, 8, 205])
        && ergo_ser::address::build_p2pk_tree_bytes(&bytes[3..].try_into().unwrap_or([0; 33]))
            .is_ok_and(|tree| tree == bytes)
}

impl Pool {
    pub fn parse(box_data: ErgoBox, nft: &[u8; 32]) -> Result<Self, WalletError> {
        let candidate = &box_data.candidate;
        if !is_supported_tree(candidate.ergo_tree_bytes())
            || candidate.tokens.len() != 3
            || candidate.tokens[0].token_id.as_bytes() != nft
            || candidate.tokens[0].amount != 1
            || candidate.value <= STORAGE_FLOOR
            || candidate.value > i64::MAX as u64
            || candidate
                .tokens
                .iter()
                .any(|token| token.amount == 0 || token.amount > i64::MAX as u64)
            || candidate
                .tokens
                .iter()
                .map(|token| *token.token_id.as_bytes())
                .collect::<BTreeSet<_>>()
                .len()
                != 3
        {
            return Err(invalid(
                "unsupported or malformed pinned Spectrum N2T v1 pool",
            ));
        }
        let fee = match candidate.additional_registers().get(RegisterId::R4) {
            Some(register) => match (&register.tpe, &register.value) {
                (SigmaType::SInt, SigmaValue::Int(value)) if (1..=1000).contains(value) => {
                    *value as u64
                }
                _ => return Err(invalid("pool R4 must be an Int fee numerator in 1..=1000")),
            },
            None => return Err(invalid("pool has no fee register")),
        };
        Ok(Self {
            box_data,
            fee_numerator: fee,
        })
    }

    /// Largest integer output allowed by Pool.sc's swap inequality.
    pub fn quote(&self, direction: Direction, input: u64) -> Result<u64, WalletError> {
        // Pool.sc performs input * fee as a Long BEFORE its BigInt upcast.
        // Avoid its overflow boundary even though the quote uses wide arithmetic.
        if input == 0 || input > i64::MAX as u64 / self.fee_numerator {
            return Err(invalid(
                "swap input exceeds the contract's safe Long arithmetic bound",
            ));
        }
        let candidate = &self.box_data.candidate;
        let (reserve_in, reserve_out) = match direction {
            Direction::ErgToToken => (candidate.value, candidate.tokens[2].amount),
            Direction::TokenToErg => (candidate.tokens[2].amount, candidate.value),
        };
        if reserve_in
            .checked_add(input)
            .is_none_or(|value| value > i64::MAX as u64)
        {
            return Err(invalid("pool successor reserve exceeds Scala Long"));
        }
        let weighted = BigUint::from(input) * BigUint::from(self.fee_numerator);
        let output = BigUint::from(reserve_out) * &weighted
            / (BigUint::from(reserve_in) * BigUint::from(1000u32) + weighted);
        let mut amount = output.to_u64_digits().first().copied().unwrap_or(0);
        if direction == Direction::TokenToErg {
            amount = amount.min(candidate.value - STORAGE_FLOOR - 1);
        }
        if amount == 0 || amount >= reserve_out {
            return Err(invalid("swap output rounds to zero or drains the reserve"));
        }
        Ok(amount)
    }
}

/// Conservative minimum value uses a maximal Long value encoding and the
/// actual output index. This can reserve a few extra nanoERG of wallet dust.
fn minimum_value(
    candidate: &ErgoBoxCandidate,
    index: u16,
    params: &ProtocolParams,
) -> Result<u64, WalletError> {
    let mut sized = candidate.clone();
    sized.value = i64::MAX as u64;
    let mut writer = VlqWriter::new();
    write_ergo_box_candidate(&mut writer, &sized).map_err(|error| invalid(error.to_string()))?;
    let mut index_writer = VlqWriter::new();
    index_writer.put_u16(index);
    let size = writer.result().len() + 32 + index_writer.result().len();
    if size > params.max_box_size as usize
        || candidate.tokens.len() > params.max_tokens_per_box as usize
    {
        return Err(invalid(
            "preserved funding output exceeds protocol box limits",
        ));
    }
    (size as u64)
        .checked_mul(params.min_value_per_byte)
        .ok_or_else(|| invalid("minimum box value overflow"))
}

/// Build a zero-fee direct swap with the exact approved funding set. Each
/// funding box is recreated separately, preserving its script/registers and
/// every non-trade asset. No extra inputs, token burns or public relay occur.
pub fn build(
    pool: &Pool,
    funding: &[ErgoBox],
    receiving_tree: &[u8],
    direction: Direction,
    input: u64,
    min_output: u64,
    height: u32,
    params: &ProtocolParams,
) -> Result<(UnsignedTransaction, u64), WalletError> {
    if funding.is_empty() || funding.len() > 32 {
        return Err(invalid("direct swaps require 1..=32 pinned funding boxes"));
    }
    let output = pool.quote(direction, input)?;
    if output < min_output {
        return Err(invalid(format!(
            "quote {output} is below approved minimum {min_output}"
        )));
    }
    let trade_token = pool.box_data.candidate.tokens[2].token_id;
    let mut successor = pool.box_data.candidate.clone();
    successor.creation_height = height;
    match direction {
        Direction::ErgToToken => {
            successor.value += input;
            successor.tokens[2].amount -= output;
        }
        Direction::TokenToErg => {
            successor.value -= output;
            successor.tokens[2].amount += input;
        }
    }
    let mut reader = ergo_primitives::reader::VlqReader::new(receiving_tree);
    let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut reader)
        .map_err(|error| invalid(error.to_string()))?;
    if !reader.is_empty() || !is_p2pk(receiving_tree) {
        return Err(invalid("swap receiving output must be P2PK"));
    }
    let mut received = ErgoBoxCandidate::new(
        if direction == Direction::TokenToErg {
            output
        } else {
            1
        },
        tree,
        height,
        if direction == Direction::ErgToToken {
            vec![Token {
                token_id: trade_token,
                amount: output,
            }]
        } else {
            vec![]
        },
        AdditionalRegisters::empty(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    let received_minimum = minimum_value(&received, (funding.len() + 1) as u16, params)?;
    if direction == Direction::ErgToToken {
        received.value = received_minimum;
    } else if output < received_minimum {
        return Err(invalid(
            "quoted ERG output is below the receiving box minimum",
        ));
    }
    let mut erg_remaining = if direction == Direction::ErgToToken {
        input
            .checked_add(received.value)
            .ok_or_else(|| invalid("funding debit overflow"))?
    } else {
        0
    };
    let mut token_remaining = if direction == Direction::TokenToErg {
        input
    } else {
        0
    };
    let mut outputs = vec![successor];
    let mut seen = BTreeSet::new();
    seen.insert(
        *pool
            .box_data
            .box_id()
            .map_err(|error| invalid(error.to_string()))?
            .as_bytes(),
    );
    for (index, full) in funding.iter().enumerate() {
        let id = full.box_id().map_err(|error| invalid(error.to_string()))?;
        if !seen.insert(*id.as_bytes()) || !is_p2pk(full.candidate.ergo_tree_bytes()) {
            return Err(invalid("funding boxes must be distinct owned P2PK inputs"));
        }
        let mut change = full.candidate.clone();
        change.creation_height = height;
        for token in &mut change.tokens {
            if token.token_id == trade_token {
                let debit = token.amount.min(token_remaining);
                token.amount -= debit;
                token_remaining -= debit;
            }
        }
        change.tokens.retain(|token| token.amount > 0);
        let minimum = minimum_value(&change, (index + 1) as u16, params)?;
        let available = change
            .value
            .checked_sub(minimum)
            .ok_or_else(|| invalid("funding box cannot preserve its minimum value"))?;
        let debit = available.min(erg_remaining);
        change.value -= debit;
        erg_remaining -= debit;
        outputs.push(change);
    }
    if erg_remaining > 0 || token_remaining > 0 {
        return Err(invalid(
            "approved funding boxes cannot cover swap and preserved output minimums",
        ));
    }
    outputs.push(received);
    let inputs = std::iter::once(&pool.box_data)
        .chain(funding)
        .map(|full| {
            Ok(UnsignedInput {
                box_id: full.box_id().map_err(|error| invalid(error.to_string()))?,
                extension: ContextExtension::empty(),
            })
        })
        .collect::<Result<Vec<_>, WalletError>>()?;
    Ok((
        UnsignedTransaction {
            inputs,
            data_inputs: vec![],
            output_candidates: outputs,
        },
        output,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::external::ProverExternalSecret;
    use crate::proving::hints::TransactionHintsBag;
    use crate::proving::prover::Prover;
    use crate::proving::secrets::SecretRegistry;
    use crate::tx_context::{BlockchainParameters, BlockchainStateContext};
    use ergo_primitives::digest::{ADDigest, ModifierId};
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::register::read_registers;
    use ergo_ser::sigma_value::SigmaBoolean;

    // ----- helpers -----
    fn pool() -> Pool {
        let json: serde_json::Value = serde_json::from_str(include_str!(
            "../../test-vectors/spectrum-n2t/mainnet-pool.json"
        ))
        .unwrap();
        let tree_bytes = hex::decode(json["ergoTree"].as_str().unwrap()).unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&tree_bytes)).unwrap();
        let mut raw_registers = vec![1];
        raw_registers.extend(
            hex::decode(
                json["additionalRegisters"]["R4"]["serializedValue"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        );
        let registers = read_registers(&mut VlqReader::new(&raw_registers)).unwrap();
        let tokens = json["assets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|token| Token {
                token_id: hex::decode(token["tokenId"].as_str().unwrap())
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .map(ergo_primitives::digest::Digest32::from_bytes)
                    .unwrap(),
                amount: token["amount"].as_u64().unwrap(),
            })
            .collect::<Vec<_>>();
        let nft = *tokens[0].token_id.as_bytes();
        let candidate = ErgoBoxCandidate::try_from_raw_parts(
            json["value"].as_u64().unwrap(),
            tree,
            tree_bytes,
            json["creationHeight"].as_u64().unwrap() as u32,
            tokens,
            registers,
            raw_registers,
        )
        .unwrap();
        let full = ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes(
                hex::decode(json["transactionId"].as_str().unwrap())
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            index: json["index"].as_u64().unwrap() as u16,
        };
        assert_eq!(
            hex::encode(full.box_id().unwrap().as_bytes()),
            json["boxId"].as_str().unwrap()
        );
        Pool::parse(full, &nft).unwrap()
    }
    fn key() -> [u8; 33] {
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap()
    }
    fn funding(trade: Token) -> ErgoBox {
        let tree = ergo_ser::address::build_p2pk_tree_bytes(&key()).unwrap();
        let parsed = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&tree)).unwrap();
        ErgoBox {
            candidate: ErgoBoxCandidate::new(
                2_000_000_000,
                parsed,
                1_111_331,
                vec![
                    trade,
                    Token {
                        token_id: [8; 32].into(),
                        amount: 777,
                    },
                ],
                AdditionalRegisters {
                    registers: vec![ergo_ser::register::RegisterValue {
                        tpe: SigmaType::SInt,
                        value: SigmaValue::Int(91),
                    }],
                },
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([3; 32]),
            index: 0,
        }
    }
    fn context() -> BlockchainStateContext {
        BlockchainStateContext {
            sigma_last_headers: vec![],
            sigma_pre_header: ergo_validation::pre_header::CandidatePreHeader {
                version: 4,
                parent_id: [0; 32],
                height: 1_111_336,
                timestamp: 1_700_000_000_000,
                n_bits: 0x1a017660,
                votes: [0; 3],
                miner_pubkey: key(),
            },
            previous_state_digest: ADDigest::from_bytes([0; 33]),
        }
    }
    fn reduce_pool(pool: &Pool, funding: &ErgoBox, tx: &UnsignedTransaction) -> SigmaBoolean {
        let extensions = tx
            .inputs
            .iter()
            .map(|input| input.extension.clone())
            .collect::<Vec<_>>();
        let boxes = [pool.box_data.clone(), funding.clone()];
        let owned = context().build_reduction_owned(
            &pool.box_data,
            &tx.inputs[0].extension,
            &boxes,
            &[],
            &tx.output_candidates,
            &extensions,
        );
        let tree = pool.box_data.candidate.ergo_tree();
        ergo_sigma::evaluator::reduce_expr_with_cost(
            &tree.body,
            &owned.as_borrowed(),
            &tree.constants,
            &mut ergo_primitives::cost::CostAccumulator::recording_only(),
        )
        .unwrap()
    }

    // ----- happy path -----
    #[test]
    fn direct_swap_preserves_funding_registers_and_nontrade_assets() {
        let pool = pool();
        for direction in [Direction::ErgToToken, Direction::TokenToErg] {
            let funding = funding(Token {
                token_id: pool.box_data.candidate.tokens[2].token_id,
                amount: 500_000,
            });
            let input = if direction == Direction::ErgToToken {
                100_000_000
            } else {
                100_000
            };
            let (tx, _) = build(
                &pool,
                std::slice::from_ref(&funding),
                &ergo_ser::address::build_p2pk_tree_bytes(&key()).unwrap(),
                direction,
                input,
                1,
                context().sigma_pre_header.height,
                &ProtocolParams::mainnet_default(),
            )
            .unwrap();
            assert_eq!(
                tx.output_candidates[1].register_bytes(),
                funding.candidate.register_bytes()
            );
            assert_eq!(
                tx.output_candidates[1].tokens[1],
                funding.candidate.tokens[1]
            );
            assert_eq!(
                tx.output_candidates[0].register_bytes(),
                pool.box_data.candidate.register_bytes()
            );
            assert_eq!(
                tx.output_candidates[0].tokens[0..2],
                pool.box_data.candidate.tokens[0..2]
            );
            let input_value = pool.box_data.candidate.value + funding.candidate.value;
            assert_eq!(
                input_value,
                tx.output_candidates
                    .iter()
                    .map(|candidate| candidate.value)
                    .sum::<u64>()
            );
            assert_eq!(
                reduce_pool(&pool, &funding, &tx),
                SigmaBoolean::TrivialProp(true)
            );
        }
    }

    // ----- error paths -----
    #[test]
    fn direct_swap_rejects_slippage_and_unfunded_pinned_inputs() {
        let pool = pool();
        assert!(pool.quote(Direction::ErgToToken, i64::MAX as u64).is_err());
        let funding = funding(Token {
            token_id: pool.box_data.candidate.tokens[2].token_id,
            amount: 5,
        });
        let tree = ergo_ser::address::build_p2pk_tree_bytes(&key()).unwrap();
        assert!(build(
            &pool,
            std::slice::from_ref(&funding),
            &tree,
            Direction::ErgToToken,
            100_000_000,
            89_845,
            1_111_336,
            &ProtocolParams::mainnet_default()
        )
        .is_err());
        assert!(build(
            &pool,
            &[funding],
            &tree,
            Direction::TokenToErg,
            100_000,
            1,
            1_111_336,
            &ProtocolParams::mainnet_default()
        )
        .is_err());
    }

    // ----- oracle parity -----
    #[test]
    fn mainnet_pool_identity_and_primary_contract_price_bound_match() {
        let pool = pool();
        assert_eq!(
            pool.quote(Direction::ErgToToken, 100_000_000).unwrap(),
            89_844
        );
        assert_eq!(
            pool.quote(Direction::TokenToErg, 100_000).unwrap(),
            91_567_700
        );
        let funding = funding(Token {
            token_id: pool.box_data.candidate.tokens[2].token_id,
            amount: 500_000,
        });
        let (mut tx, _) = build(
            &pool,
            std::slice::from_ref(&funding),
            &ergo_ser::address::build_p2pk_tree_bytes(&key()).unwrap(),
            Direction::ErgToToken,
            100_000_000,
            1,
            1_111_336,
            &ProtocolParams::mainnet_default(),
        )
        .unwrap();
        // One extra token exceeds the independently published contract bound.
        tx.output_candidates[0].tokens[2].amount -= 1;
        assert_eq!(
            reduce_pool(&pool, &funding, &tx),
            SigmaBoolean::TrivialProp(false)
        );
    }
    #[test]
    fn canonical_pool_wallet_signer_reduces_pool_and_proves_owned_funding() {
        let pool = pool();
        let funding = funding(Token {
            token_id: pool.box_data.candidate.tokens[2].token_id,
            amount: 500_000,
        });
        let (tx, _) = build(
            &pool,
            std::slice::from_ref(&funding),
            &ergo_ser::address::build_p2pk_tree_bytes(&key()).unwrap(),
            Direction::TokenToErg,
            100_000,
            1,
            1_111_336,
            &ProtocolParams::mainnet_default(),
        )
        .unwrap();
        let secrets = SecretRegistry::empty()
            .merge_external_secrets(&[ProverExternalSecret::Dlog {
                pk: key(),
                scalar: k256::Scalar::ONE.into(),
            }])
            .unwrap();
        let prover = Prover::new(
            secrets,
            BlockchainParameters {
                max_block_cost: 1_000_000,
                input_cost: 2000,
                data_input_cost: 100,
                output_cost: 100,
                token_access_cost: 100,
                interpreter_init_cost: 1000,
                block_version: 4,
            },
        );
        let signed = prover
            .sign(
                &tx,
                &[pool.box_data, funding],
                &[],
                &context(),
                &TransactionHintsBag::empty(),
            )
            .unwrap();
        assert!(signed.inputs[0].spending_proof.proof.is_empty());
        assert!(!signed.inputs[1].spending_proof.proof.is_empty());
    }
}
