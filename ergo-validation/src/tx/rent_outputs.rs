//! Scala 6.0.7 `rentOutputIndicesDistinct` (rule 125).
//!
//! This checks every present var-127 VALUE, regardless of proof, age or type.
//! It is not restricted to inputs that take the interpreter's rent shortcut.

use std::collections::HashSet;

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::read_accepted_ergo_box;
use ergo_ser::sigma_type::{write_type, SigmaType};
use ergo_ser::sigma_value::{write_constant, CollValue, SigmaValue, SECP256K1_GENERATOR};
use ergo_ser::transaction::Transaction;

use crate::error::ValidationError;
use crate::storage_rent::DISTINCT_RENT_OUTPUTS_ACTIVATION_HEIGHT;

pub(super) fn validate_rent_output_indices(
    tx: &Transaction,
    height: u32,
) -> Result<(), ValidationError> {
    if height < DISTINCT_RENT_OUTPUTS_ACTIVATION_HEIGHT {
        return Ok(());
    }
    let mut seen = HashSet::new();
    for (index, input) in tx.inputs.iter().enumerate() {
        if let Some((tpe, value)) = input.spending_proof.extension().values.get(&127) {
            if !seen.insert(runtime_key(tpe, value)?) {
                return Err(ValidationError::DuplicateStorageRentOutput { index });
            }
        }
    }
    Ok(())
}

/// Scala `Seq[Any].distinct` compares boxed primitive numbers across widths,
/// tuples/options by their contents, and collections with their element RType.
/// Wire node encodings (GroupGenerator/ConcreteCollection) do not affect values.
#[derive(PartialEq, Eq, Hash)]
enum RuntimeKey {
    Number(i64),
    Leaf(Vec<u8>),
    Tuple(Vec<RuntimeKey>),
    Option(Option<Box<RuntimeKey>>),
    Collection(Vec<u8>, Vec<RuntimeKey>),
    Header([u8; 32]),
    Box([u8; 32]),
}

fn runtime_key(tpe: &SigmaType, value: &SigmaValue) -> Result<RuntimeKey, ValidationError> {
    let fail = |e: ergo_ser::error::WriteError| ValidationError::Deserialization(e.to_string());
    Ok(match value {
        SigmaValue::Byte(n) => RuntimeKey::Number(i64::from(*n)),
        SigmaValue::Short(n) => RuntimeKey::Number(i64::from(*n)),
        SigmaValue::Int(n) => RuntimeKey::Number(i64::from(*n)),
        SigmaValue::Long(n) => RuntimeKey::Number(*n),
        SigmaValue::Header(_, id) => RuntimeKey::Header(*id),
        SigmaValue::OpaqueBoxBytes(bytes) => {
            // CBox equality/hash use the parsed ErgoBox id, not the input
            // encoding. Read an already-accepted nested box without resetting
            // its binding scope; allow all supported script versions here.
            let mut reader = VlqReader::new(bytes).with_activated_script_version(3);
            let box_value = read_accepted_ergo_box(&mut reader)
                .map_err(|e| ValidationError::Deserialization(e.to_string()))?;
            RuntimeKey::Box(*box_value.box_id().map_err(fail)?.as_bytes())
        }
        SigmaValue::GroupGenerator => runtime_key(
            &SigmaType::SGroupElement,
            &SigmaValue::GroupElement(SECP256K1_GENERATOR.into()),
        )?,
        SigmaValue::Tuple(items) => {
            let SigmaType::STuple(types) = tpe else {
                return Err(ValidationError::InternalInvariantViolated(
                    "tuple type mismatch",
                ));
            };
            RuntimeKey::Tuple(
                items
                    .iter()
                    .zip(types)
                    .map(|(v, t)| runtime_key(t, v))
                    .collect::<Result<_, _>>()?,
            )
        }
        SigmaValue::Opt(item) => {
            let SigmaType::SOption(inner) = tpe else {
                return Err(ValidationError::InternalInvariantViolated(
                    "option type mismatch",
                ));
            };
            RuntimeKey::Option(
                item.as_ref()
                    .map(|v| runtime_key(inner, v).map(Box::new))
                    .transpose()?,
            )
        }
        SigmaValue::Coll(_) | SigmaValue::ConcreteCollection { .. } => {
            let SigmaType::SColl(inner) = tpe else {
                return Err(ValidationError::InternalInvariantViolated(
                    "collection type mismatch",
                ));
            };
            let mut type_bytes = VlqWriter::new();
            write_type(&mut type_bytes, inner).map_err(fail)?;
            let items = match value {
                SigmaValue::Coll(CollValue::BoolBits(vs)) => vs
                    .iter()
                    .map(|v| runtime_key(inner, &SigmaValue::Boolean(*v)))
                    .collect::<Result<_, _>>()?,
                SigmaValue::Coll(CollValue::Bytes(vs)) => vs
                    .iter()
                    .map(|v| RuntimeKey::Number(i64::from(*v as i8)))
                    .collect(),
                SigmaValue::Coll(CollValue::Values(vs))
                | SigmaValue::ConcreteCollection { items: vs, .. } => vs
                    .iter()
                    .map(|v| runtime_key(inner, v))
                    .collect::<Result<_, _>>()?,
                _ => unreachable!(),
            };
            RuntimeKey::Collection(type_bytes.result(), items)
        }
        _ => {
            let mut writer = VlqWriter::new();
            write_constant(&mut writer, tpe, value).map_err(fail)?;
            RuntimeKey::Leaf(writer.result())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};

    fn transaction(values: Vec<Option<(SigmaType, SigmaValue)>>, proof: Vec<u8>) -> Transaction {
        Transaction {
            inputs: values
                .into_iter()
                .enumerate()
                .map(|(i, value)| {
                    let mut extension = ContextExtension::empty();
                    if let Some(value) = value {
                        extension.values.insert(127, value);
                    }
                    Input {
                        box_id: Digest32::from_bytes([i as u8; 32]),
                        spending_proof: SpendingProof::new(proof.clone(), extension).unwrap(),
                    }
                })
                .collect(),
            data_inputs: vec![],
            output_candidates: vec![],
        }
    }

    #[test]
    fn rent_distinct_activation_and_all_input_values() {
        let height = DISTINCT_RENT_OUTPUTS_ACTIVATION_HEIGHT;
        for proof in [vec![], vec![1]] {
            let tx = transaction(
                vec![
                    Some((SigmaType::SShort, SigmaValue::Short(0))),
                    None,
                    Some((SigmaType::SShort, SigmaValue::Short(0))),
                ],
                proof,
            );
            assert!(validate_rent_output_indices(&tx, height - 1).is_ok());
            for h in [height, height + 1] {
                assert!(matches!(
                    validate_rent_output_indices(&tx, h),
                    Err(ValidationError::DuplicateStorageRentOutput { index: 2 })
                ));
            }
        }
        let tx = transaction(
            vec![
                Some((SigmaType::SShort, SigmaValue::Short(0))),
                None,
                Some((SigmaType::SShort, SigmaValue::Short(1))),
            ],
            vec![],
        );
        assert!(validate_rent_output_indices(&tx, height).is_ok());
    }

    #[test]
    fn rent_distinct_matches_scala_runtime_equality() {
        let height = DISTINCT_RENT_OUTPUTS_ACTIVATION_HEIGHT;
        for value in [
            (SigmaType::SByte, SigmaValue::Byte(0)),
            (SigmaType::SInt, SigmaValue::Int(0)),
            (SigmaType::SLong, SigmaValue::Long(0)),
        ] {
            let tx = transaction(
                vec![Some((SigmaType::SShort, SigmaValue::Short(0))), Some(value)],
                vec![1],
            );
            assert!(matches!(
                validate_rent_output_indices(&tx, height),
                Err(ValidationError::DuplicateStorageRentOutput { .. })
            ));
        }
        let tpe = SigmaType::SColl(Box::new(SigmaType::SShort));
        let values = vec![SigmaValue::Short(1)];
        let tx = transaction(
            vec![
                Some((
                    tpe.clone(),
                    SigmaValue::Coll(CollValue::Values(values.clone())),
                )),
                Some((
                    tpe,
                    SigmaValue::ConcreteCollection {
                        elem_type: Box::new(SigmaType::SShort),
                        items: values,
                    },
                )),
            ],
            vec![],
        );
        assert!(validate_rent_output_indices(&tx, height).is_err());
        let tx = transaction(
            vec![
                Some((
                    SigmaType::SColl(Box::new(SigmaType::SShort)),
                    SigmaValue::Coll(CollValue::Values(vec![])),
                )),
                Some((
                    SigmaType::SColl(Box::new(SigmaType::SInt)),
                    SigmaValue::Coll(CollValue::Values(vec![])),
                )),
            ],
            vec![],
        );
        assert!(validate_rent_output_indices(&tx, height).is_ok());
    }
}
