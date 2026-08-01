//! Strict Spectrum N2T v1 pool decoding.

use std::collections::BTreeSet;

use ergo_indexer_types::{BoxId, IndexedBoxDto, TokenId};
use ergo_ser::ergo_tree::tree_hash_from_bytes;
use ergo_ser::register::RegisterId;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use serde_json::{json, Value};

use super::super::service::DecodeInput;

pub const SPECTRUM_N2T_V1_TEMPLATE_HASH_HEX: &str =
    "850f2d5b02b3e66612e5499953fe8dfe54b8c077a0bd85362b5c706ffebd2bae";
pub const SPECTRUM_N2T_V1_TREE_HASH_HEX: &str =
    "99f30ad579a2c98ad31b432676627fcd9e303d43c06e898725f6155d8ac40aa9";
pub const N2T_NON_TRADABLE_NANOERG: u64 = 10_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpectrumN2TPool {
    pub pool_box_id: BoxId,
    pub pool_nft: TokenId,
    pub lp_token: TokenId,
    pub token_y: TokenId,
    pub token_y_reserve: u64,
    pub erg_reserve: u64,
    pub effective_erg_reserve: u64,
    pub fee_numerator: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpectrumN2TDecodeError {
    TreeHash,
    TokenCount,
    DuplicateTokenId,
    PoolNftAmount,
    TokenYReserve,
    FeeRegister,
    FeeRange,
    ErgReserve,
    BoxId,
}

struct ValidatedPoolFields {
    effective_erg_reserve: u64,
    fee_numerator: u32,
}

fn validate_pool_fields(
    token_ids: &[[u8; 32]],
    token_amounts: &[u64],
    value: u64,
    r4: Option<(&SigmaType, &SigmaValue)>,
) -> Result<ValidatedPoolFields, SpectrumN2TDecodeError> {
    if token_ids.len() != 3 || token_amounts.len() != 3 {
        return Err(SpectrumN2TDecodeError::TokenCount);
    }

    let distinct_ids = token_ids.iter().copied().collect::<BTreeSet<_>>();
    if distinct_ids.len() != 3 {
        return Err(SpectrumN2TDecodeError::DuplicateTokenId);
    }
    if token_amounts[0] != 1 {
        return Err(SpectrumN2TDecodeError::PoolNftAmount);
    }
    if token_amounts[2] == 0 {
        return Err(SpectrumN2TDecodeError::TokenYReserve);
    }

    let fee = match r4 {
        Some((SigmaType::SInt, SigmaValue::Int(fee))) => *fee,
        _ => return Err(SpectrumN2TDecodeError::FeeRegister),
    };
    let fee_numerator = u32::try_from(fee).map_err(|_| SpectrumN2TDecodeError::FeeRange)?;
    if !(1..=1000).contains(&fee_numerator) {
        return Err(SpectrumN2TDecodeError::FeeRange);
    }
    if value <= N2T_NON_TRADABLE_NANOERG {
        return Err(SpectrumN2TDecodeError::ErgReserve);
    }
    let effective_erg_reserve = value
        .checked_sub(N2T_NON_TRADABLE_NANOERG)
        .ok_or(SpectrumN2TDecodeError::ErgReserve)?;

    Ok(ValidatedPoolFields {
        effective_erg_reserve,
        fee_numerator,
    })
}

pub fn decode_n2t_pool(
    indexed_box: &IndexedBoxDto,
) -> Result<SpectrumN2TPool, SpectrumN2TDecodeError> {
    let candidate = &indexed_box.box_data.candidate;
    let tree_hash = tree_hash_from_bytes(candidate.ergo_tree_bytes())
        .map_err(|_| SpectrumN2TDecodeError::TreeHash)?;
    if hex::encode(tree_hash) != SPECTRUM_N2T_V1_TREE_HASH_HEX {
        return Err(SpectrumN2TDecodeError::TreeHash);
    }

    let token_ids = candidate
        .tokens
        .iter()
        .map(|token| *token.token_id.as_bytes())
        .collect::<Vec<_>>();
    let token_amounts = candidate
        .tokens
        .iter()
        .map(|token| token.amount)
        .collect::<Vec<_>>();
    let r4 = candidate
        .additional_registers
        .get(RegisterId::R4)
        .map(|register| (&register.tpe, &register.value));
    let fields = validate_pool_fields(&token_ids, &token_amounts, candidate.value, r4)?;
    let pool_box_id = indexed_box
        .box_data
        .box_id()
        .map_err(|_| SpectrumN2TDecodeError::BoxId)?;

    Ok(SpectrumN2TPool {
        pool_box_id,
        pool_nft: candidate.tokens[0].token_id,
        lp_token: candidate.tokens[1].token_id,
        token_y: candidate.tokens[2].token_id,
        token_y_reserve: candidate.tokens[2].amount,
        erg_reserve: candidate.value,
        effective_erg_reserve: fields.effective_erg_reserve,
        fee_numerator: fields.fee_numerator,
    })
}

pub struct StateResult {
    pub state: Value,
    pub downgraded: bool,
}

pub fn decode_state(input: &DecodeInput) -> StateResult {
    let Some(token_ids) = input
        .tokens
        .iter()
        .map(|(id, _)| {
            let bytes = hex::decode(id).ok()?;
            bytes.try_into().ok()
        })
        .collect::<Option<Vec<[u8; 32]>>>()
    else {
        return StateResult {
            state: Value::Null,
            downgraded: true,
        };
    };
    let token_amounts = input
        .tokens
        .iter()
        .map(|(_, amount)| *amount)
        .collect::<Vec<_>>();
    let r4 = input.registers.get("R4").map(|(tpe, value)| (tpe, value));
    let Ok(fields) = validate_pool_fields(&token_ids, &token_amounts, input.value, r4) else {
        return StateResult {
            state: Value::Null,
            downgraded: true,
        };
    };

    StateResult {
        state: json!({
            "pool_nft": hex::encode(token_ids[0]),
            "lp_token": hex::encode(token_ids[1]),
            "token_y": hex::encode(token_ids[2]),
            "token_y_reserve": token_amounts[2].to_string(),
            "erg_reserve": input.value.to_string(),
            "effective_erg_reserve": fields.effective_erg_reserve.to_string(),
            "fee_numerator": fields.fee_numerator,
        }),
        downgraded: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::decode::service::decode_box;
    use ergo_indexer_types::IndexedBoxDto;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::{read_ergo_tree, template_hash_from_bytes, tree_hash_from_bytes};
    use ergo_ser::register::{write_registers, AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{write_constant, SigmaValue};
    use ergo_ser::token::Token;

    // ----- helpers -----

    fn fixture_tree_bytes() -> Vec<u8> {
        hex::decode(include_str!("../../../../tests/fixtures/spectrum_n2t_v1_ergo_tree.hex").trim())
            .unwrap()
    }

    fn altered_fixture_tree_bytes() -> Vec<u8> {
        let original = fixture_tree_bytes();
        let template_hash = template_hash_from_bytes(&original).unwrap();
        let tree_hash = tree_hash_from_bytes(&original).unwrap();

        for index in 1..original.len() {
            for mask in [1, 2, 4, 8, 16, 32, 64, 128] {
                let mut altered = original.clone();
                altered[index] ^= mask;
                let mut reader = VlqReader::new(&altered);
                if read_ergo_tree(&mut reader).is_ok()
                    && reader.is_empty()
                    && template_hash_from_bytes(&altered).ok() == Some(template_hash)
                    && tree_hash_from_bytes(&altered).ok() != Some(tree_hash)
                {
                    return altered;
                }
            }
        }

        panic!("fixture must contain a mutable segregated constant");
    }

    fn token(seed: u8, amount: u64) -> Token {
        Token {
            token_id: Digest32::from_bytes([seed; 32]),
            amount,
        }
    }

    fn int_register(value: i32) -> RegisterValue {
        RegisterValue {
            tpe: SigmaType::SInt,
            value: SigmaValue::Int(value),
        }
    }

    fn indexed_box(
        tree_bytes: Vec<u8>,
        value: u64,
        tokens: Vec<Token>,
        r4: Option<RegisterValue>,
    ) -> IndexedBoxDto {
        let mut tree_reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut tree_reader).unwrap();
        assert!(tree_reader.is_empty());

        let additional_registers = AdditionalRegisters {
            registers: r4.into_iter().collect(),
        };
        let mut register_writer = VlqWriter::new();
        write_registers(&mut register_writer, &additional_registers).unwrap();
        let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
            value,
            ergo_tree,
            tree_bytes,
            700_000,
            tokens,
            additional_registers,
            register_writer.result(),
        );

        IndexedBoxDto {
            inclusion_height: 700_000,
            spending_tx_id: None,
            spending_height: None,
            spending_proof: None,
            box_data: ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes([0xAA; 32]),
                index: 0,
            },
            global_index: 1,
        }
    }

    fn accepted_box() -> IndexedBoxDto {
        indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            Some(int_register(997)),
        )
    }

    fn service_register(value: i32) -> String {
        let mut writer = VlqWriter::new();
        write_constant(&mut writer, &SigmaType::SInt, &SigmaValue::Int(value)).unwrap();
        hex::encode(writer.result())
    }

    fn service_tokens() -> Vec<(String, u64)> {
        vec![
            (hex::encode([1; 32]), 1),
            (hex::encode([2; 32]), 1_000_000),
            (hex::encode([3; 32]), 2_000_000),
        ]
    }

    // ----- happy path -----

    #[test]
    fn accepts_exact_n2t_tree_and_strict_box_layout() {
        let pool = decode_n2t_pool(&accepted_box()).unwrap();

        assert_eq!(pool.erg_reserve, 60_000_000);
        assert_eq!(pool.effective_erg_reserve, 50_000_000);
        assert_eq!(pool.token_y_reserve, 2_000_000);
        assert_eq!(pool.fee_numerator, 997);
    }

    #[test]
    fn effective_reserve_is_exact_validated_subtraction() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            N2T_NON_TRADABLE_NANOERG + 1,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            Some(int_register(997)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box).unwrap().effective_erg_reserve,
            1
        );
    }

    #[test]
    fn registry_matches_spectrum_by_exact_tree_hash() {
        let mut registers = std::collections::BTreeMap::new();
        registers.insert("R4".to_string(), service_register(997));
        let decoded = decode_box(
            include_str!("../../../../tests/fixtures/spectrum_n2t_v1_ergo_tree.hex").trim(),
            60_000_000,
            &service_tokens(),
            &registers,
        );

        let contract = &decoded["contract"];
        assert_eq!(contract["protocol_id"], "spectrum");
        assert_eq!(contract["box_role"], "n2t_pool");
        assert_eq!(contract["matched_by"], "tree_hash");
        assert_eq!(contract["confidence"], "exact");
        assert_eq!(contract["state"]["erg_reserve"], "60000000");
        assert_eq!(contract["state"]["effective_erg_reserve"], "50000000");
        assert_eq!(contract["state"]["token_y_reserve"], "2000000");
        assert_eq!(contract["state"]["fee_numerator"], 997);
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[test]
    fn rejects_shape_match_with_altered_tree_bytes() {
        let indexed_box = indexed_box(
            altered_fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            Some(int_register(997)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::TreeHash)
        );
    }

    #[test]
    fn rejects_extra_token() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![
                token(1, 1),
                token(2, 1_000_000),
                token(3, 2_000_000),
                token(4, 1),
            ],
            Some(int_register(997)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::TokenCount)
        );

        let mut tokens = service_tokens();
        tokens.push((hex::encode([4; 32]), 1));
        let mut registers = std::collections::BTreeMap::new();
        registers.insert("R4".to_string(), service_register(997));
        let decoded = decode_box(
            include_str!("../../../../tests/fixtures/spectrum_n2t_v1_ergo_tree.hex").trim(),
            60_000_000,
            &tokens,
            &registers,
        );
        assert_eq!(decoded["contract"]["confidence"], "heuristic");
        assert!(decoded["contract"]["state"].is_null());
    }

    #[test]
    fn rejects_duplicate_token_ids() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(2, 2_000_000)],
            Some(int_register(997)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::DuplicateTokenId)
        );
    }

    #[test]
    fn rejects_non_singleton_pool_nft() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 2), token(2, 1_000_000), token(3, 2_000_000)],
            Some(int_register(997)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::PoolNftAmount)
        );
    }

    #[test]
    fn rejects_zero_y_reserve() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(3, 0)],
            Some(int_register(997)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::TokenYReserve)
        );
    }

    #[test]
    fn rejects_missing_r4() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            None,
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::FeeRegister)
        );
    }

    #[test]
    fn rejects_non_int_r4() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            Some(RegisterValue {
                tpe: SigmaType::SLong,
                value: SigmaValue::Long(997),
            }),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::FeeRegister)
        );
    }

    #[test]
    fn rejects_fee_zero() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            Some(int_register(0)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::FeeRange)
        );
    }

    #[test]
    fn rejects_fee_above_one_thousand() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            60_000_000,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            Some(int_register(1_001)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::FeeRange)
        );
    }

    #[test]
    fn rejects_value_at_non_tradable_floor() {
        let indexed_box = indexed_box(
            fixture_tree_bytes(),
            N2T_NON_TRADABLE_NANOERG,
            vec![token(1, 1), token(2, 1_000_000), token(3, 2_000_000)],
            Some(int_register(997)),
        );

        assert_eq!(
            decode_n2t_pool(&indexed_box),
            Err(SpectrumN2TDecodeError::ErgReserve)
        );
    }

    #[test]
    fn registry_rejects_spectrum_shape_only_lookalike() {
        let altered = altered_fixture_tree_bytes();
        assert_eq!(
            template_hash_from_bytes(&altered).unwrap(),
            template_hash_from_bytes(&fixture_tree_bytes()).unwrap()
        );
        let mut registers = std::collections::BTreeMap::new();
        registers.insert("R4".to_string(), service_register(997));
        let decoded = decode_box(
            &hex::encode(altered),
            60_000_000,
            &service_tokens(),
            &registers,
        );

        assert!(decoded["contract"].is_null());
    }

    // ----- oracle parity -----

    #[test]
    fn n2t_fixture_has_pinned_template_and_tree_hashes() {
        let bytes = hex::decode(
            include_str!("../../../../tests/fixtures/spectrum_n2t_v1_ergo_tree.hex").trim(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(template_hash_from_bytes(&bytes).unwrap()),
            SPECTRUM_N2T_V1_TEMPLATE_HASH_HEX
        );
        assert_eq!(
            hex::encode(tree_hash_from_bytes(&bytes).unwrap()),
            SPECTRUM_N2T_V1_TREE_HASH_HEX
        );
    }
}
