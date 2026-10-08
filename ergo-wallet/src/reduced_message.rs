//! Resource-bounded message construction for the offline reduced codec.
//!
//! This wallet policy does not change the consensus transaction writer. The
//! emitted message is bounded exactly; extensions retain the consensus codec's
//! node provenance and ordering after a separate, finite structural preflight.

use std::collections::BTreeMap;

use ergo_primitives::writer::VlqWriter;
use ergo_ser::{
    autolykos::AutolykosSolution,
    input::{write_context_extension, ContextExtension},
    opcode::{children, Expr, Payload},
    sigma_type::SigmaType,
    sigma_value::{write_sigma_boolean_bounded, CollValue, SigmaValue},
    transaction::UnsignedTransaction,
};

use crate::WalletError;

// The extension writer can normalize evaluated nodes and make temporary clones.
// This conservative work ceiling is distinct from the exact message byte cap.
// Each visited type/value/expression is charged 64 bytes, plus retained payloads
// and expanded SigmaBoolean wire bytes, before that writer is called.
const EXTENSION_WORK_LIMIT: usize = 64 * super::reduced::MAX_REDUCED_TRANSACTION_BYTES;
const MAX_CONTEXT_DEPTH: usize = 110;

pub(crate) fn bytes_to_sign_bounded(
    tx: &UnsignedTransaction,
    max_bytes: usize,
) -> Result<Vec<u8>, WalletError> {
    if [
        tx.inputs.len(),
        tx.data_inputs.len(),
        tx.output_candidates.len(),
    ]
    .into_iter()
    .any(|n| n > u16::MAX as usize)
    {
        return Err(invalid("transaction collection exceeds wire bound"));
    }

    // Count a lower bound before building the token table or serializing any
    // extension. Large cached trees/registers are rejected without cloning.
    let mut minimum = vlq_len(tx.inputs.len() as u64)
        + vlq_len(tx.data_inputs.len() as u64)
        + vlq_len(tx.output_candidates.len() as u64)
        + 1; // empty token-table count
    add_size(&mut minimum, tx.inputs.len().saturating_mul(34), max_bytes)?;
    add_size(
        &mut minimum,
        tx.data_inputs.len().saturating_mul(32),
        max_bytes,
    )?;
    for output in &tx.output_candidates {
        if output.tokens.len() > u8::MAX as usize {
            return Err(invalid("output token collection exceeds wire bound"));
        }
        add_size(
            &mut minimum,
            vlq_len(output.value)
                + vlq_len(u64::from(output.creation_height))
                + 1
                + output.tokens.len() * 2,
            max_bytes,
        )?;
        add_size(
            &mut minimum,
            output
                .checked_serialized_ergo_tree_bytes()
                .map_err(write_error)?
                .len(),
            max_bytes,
        )?;
        add_size(
            &mut minimum,
            output.checked_register_bytes().map_err(write_error)?.len(),
            max_bytes,
        )?;
    }

    // Preserve first occurrence order, exactly as the consensus writer does.
    // The map also avoids its linear search for each indexed output token.
    let mut indexes = BTreeMap::<[u8; 32], u32>::new();
    let mut token_ids = Vec::new();
    for output in &tx.output_candidates {
        for token in &output.tokens {
            let id = *token.token_id.as_bytes();
            if !indexes.contains_key(&id) {
                add_size(&mut minimum, 32, max_bytes)?;
                let index = token_ids.len() as u32;
                indexes.insert(id, index);
                token_ids.push(id);
            }
        }
    }

    let mut message = BoundedWriter::new(max_bytes);
    message.unsigned(tx.inputs.len() as u64)?;
    for input in &tx.inputs {
        message.bytes(input.box_id.as_bytes())?;
        message.byte(0)?; // empty signed proof, not the unsigned wire format
        preflight_extension(&input.extension)?;
        let mut extension = VlqWriter::new();
        write_context_extension(&mut extension, &input.extension).map_err(write_error)?;
        message.bytes(extension.as_slice())?;
    }
    message.unsigned(tx.data_inputs.len() as u64)?;
    for input in &tx.data_inputs {
        message.bytes(input.box_id.as_bytes())?;
    }
    message.unsigned(token_ids.len() as u64)?;
    for id in &token_ids {
        message.bytes(id)?;
    }
    message.unsigned(tx.output_candidates.len() as u64)?;
    for output in &tx.output_candidates {
        message.unsigned(output.value)?;
        message.bytes(
            output
                .checked_serialized_ergo_tree_bytes()
                .map_err(write_error)?,
        )?;
        message.unsigned(u64::from(output.creation_height))?;
        message.byte(output.tokens.len() as u8)?;
        for token in &output.tokens {
            let index = indexes[&*token.token_id.as_bytes()];
            message.unsigned(u64::from(index))?;
            message.unsigned(token.amount)?;
        }
        message.bytes(output.checked_register_bytes().map_err(write_error)?)?;
    }
    Ok(message.writer.result())
}

struct BoundedWriter {
    writer: VlqWriter,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            writer: VlqWriter::new(),
            limit,
        }
    }

    fn ensure(&self, bytes: usize) -> Result<(), WalletError> {
        if bytes > self.limit.saturating_sub(self.writer.len()) {
            Err(invalid("reduced transaction message exceeds byte bound"))
        } else {
            Ok(())
        }
    }

    fn byte(&mut self, byte: u8) -> Result<(), WalletError> {
        self.ensure(1)?;
        self.writer.put_u8(byte);
        Ok(())
    }

    fn unsigned(&mut self, value: u64) -> Result<(), WalletError> {
        self.ensure(vlq_len(value))?;
        self.writer.put_u64(value);
        Ok(())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), WalletError> {
        self.ensure(bytes.len())?;
        self.writer.put_bytes(bytes);
        Ok(())
    }
}

fn vlq_len(value: u64) -> usize {
    (64 - value.leading_zeros()).max(1).div_ceil(7) as usize
}

fn add_size(total: &mut usize, bytes: usize, limit: usize) -> Result<(), WalletError> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| invalid("message size overflow"))?;
    if *total > limit {
        return Err(invalid("reduced transaction exceeds resource bound"));
    }
    Ok(())
}

fn preflight_extension(extension: &ContextExtension) -> Result<(), WalletError> {
    if extension.values.len() > i8::MAX as usize {
        return Err(invalid("context extension exceeds entry bound"));
    }
    let mut work = Preflight { used: 0 };
    for (tpe, value) in extension.values.values() {
        work.tpe(tpe, 0)?;
        work.value(value, 0)?;
    }
    Ok(())
}

struct Preflight {
    used: usize,
}

impl Preflight {
    fn charge(&mut self, bytes: usize) -> Result<(), WalletError> {
        add_size(&mut self.used, bytes, EXTENSION_WORK_LIMIT)
    }

    fn node(&mut self, depth: usize) -> Result<(), WalletError> {
        if depth >= MAX_CONTEXT_DEPTH {
            return Err(invalid("context extension exceeds depth bound"));
        }
        self.charge(64)
    }

    fn tpe(&mut self, tpe: &SigmaType, depth: usize) -> Result<(), WalletError> {
        self.node(depth)?;
        match tpe {
            SigmaType::SColl(inner) | SigmaType::SOption(inner) => self.tpe(inner, depth + 1)?,
            SigmaType::STuple(items) => {
                if items.len() > u8::MAX as usize {
                    return Err(invalid("tuple type exceeds arity bound"));
                }
                for item in items {
                    self.tpe(item, depth + 1)?;
                }
            }
            SigmaType::SFunc {
                t_dom,
                t_range,
                tpe_params,
            } => {
                if t_dom.len() > u8::MAX as usize || tpe_params.len() > u8::MAX as usize {
                    return Err(invalid("function type exceeds arity bound"));
                }
                for item in t_dom.iter().chain(tpe_params) {
                    self.tpe(item, depth + 1)?;
                }
                self.tpe(t_range, depth + 1)?;
            }
            SigmaType::STypeVar(name) => self.charge(name.len())?,
            _ => {}
        }
        Ok(())
    }

    fn value(&mut self, value: &SigmaValue, depth: usize) -> Result<(), WalletError> {
        self.node(depth)?;
        match value {
            SigmaValue::Str(s) => self.charge(s.len())?,
            SigmaValue::BigInt(n) => {
                if n.bits() > 256 {
                    return Err(invalid("context BigInt exceeds wire bound"));
                }
            }
            SigmaValue::SigmaProp(sigma) => {
                // The helper measures shared children without expanding them;
                // never call the unbounded SigmaBoolean writer first.
                let mut scratch = VlqWriter::new();
                write_sigma_boolean_bounded(
                    &mut scratch,
                    sigma,
                    super::reduced::MAX_REDUCED_TRANSACTION_BYTES,
                )
                .map_err(write_error)?;
                self.charge(scratch.len())?;
            }
            SigmaValue::AvlTree(tree) => self.charge(tree.digest.len())?,
            SigmaValue::Coll(CollValue::Bytes(bytes)) => {
                collection_bound(bytes.len())?;
                self.charge(bytes.len())?;
            }
            SigmaValue::OpaqueBoxBytes(bytes) => self.charge(bytes.len())?,
            SigmaValue::Coll(CollValue::BoolBits(bits)) => {
                collection_bound(bits.len())?;
                self.charge(bits.len())?;
            }
            SigmaValue::Coll(CollValue::Values(values)) => {
                collection_bound(values.len())?;
                for value in values {
                    self.value(value, depth + 1)?;
                }
            }
            SigmaValue::Tuple(values) => {
                for value in values {
                    self.value(value, depth + 1)?;
                }
            }
            SigmaValue::ConcreteCollection { elem_type, items } => {
                collection_bound(items.len())?;
                self.tpe(elem_type, depth + 1)?;
                for value in items {
                    self.value(value, depth + 1)?;
                }
            }
            SigmaValue::Opt(Some(value)) => self.value(value, depth + 1)?,
            SigmaValue::Unevaluated(expr) => self.expr(expr, depth + 1)?,
            SigmaValue::CanonicalBoxBytes {
                bytes,
                canonical_bytes,
                legacy_bytes,
            } => {
                self.charge(bytes.len())?;
                if let Ok(bytes) = canonical_bytes {
                    self.charge(bytes.len())?;
                }
                if let Some(Ok(bytes)) = legacy_bytes {
                    self.charge(bytes.len())?;
                }
            }
            SigmaValue::Header(header, _) => {
                self.charge(1024 + header.unparsed_bytes.len())?;
                if let AutolykosSolution::V1 { d, .. } = &header.solution {
                    self.charge(d.len())?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn expr(&mut self, expr: &Expr, depth: usize) -> Result<(), WalletError> {
        self.node(depth)?;
        match expr {
            Expr::Const { tpe, val } => {
                self.tpe(tpe, depth + 1)?;
                self.value(val, depth + 1)?;
            }
            Expr::Unparsed(tree) => self.charge(tree.bytes.len())?,
            Expr::Op(node) => {
                match &node.payload {
                    Payload::TaggedVar { tpe, .. } | Payload::ValDef { tpe, .. } => {
                        if let Some(tpe) = tpe {
                            self.tpe(tpe, depth + 1)?;
                        }
                    }
                    Payload::FunDef { tpe, tpe_args, .. } => {
                        if let Some(tpe) = tpe {
                            self.tpe(tpe, depth + 1)?;
                        }
                        for tpe in tpe_args {
                            self.tpe(tpe, depth + 1)?;
                        }
                    }
                    Payload::FuncValue { args, .. } => {
                        self.charge(args.len().saturating_mul(8))?;
                        for (_, tpe) in args {
                            if let Some(tpe) = tpe {
                                self.tpe(tpe, depth + 1)?;
                            }
                        }
                    }
                    Payload::MethodCall { type_args, .. } => {
                        for tpe in type_args {
                            self.tpe(tpe, depth + 1)?;
                        }
                    }
                    Payload::ConcreteCollection { elem_type, .. } => {
                        self.tpe(elem_type, depth + 1)?
                    }
                    Payload::BoolCollection { bits } => self.charge(bits.len())?,
                    Payload::ExtractRegisterAs { tpe, .. }
                    | Payload::GetVar { tpe, .. }
                    | Payload::DeserializeContext { tpe, .. }
                    | Payload::DeserializeRegister { tpe, .. }
                    | Payload::NoneValue { tpe }
                    | Payload::NumericCast { tpe, .. } => self.tpe(tpe, depth + 1)?,
                    _ => {}
                }
                // Check wide child vectors before the common walker allocates
                // its temporary vector of borrowed child pointers.
                let width = match &node.payload {
                    Payload::BlockValue { items, .. }
                    | Payload::ConcreteCollection { items, .. }
                    | Payload::Tuple { items }
                    | Payload::SigmaCollection { items } => items.len(),
                    Payload::MethodCall { args, .. } | Payload::FuncApply { args, .. } => {
                        args.len()
                    }
                    _ => 0,
                };
                self.charge(width.saturating_mul(8))?;
                for child in children(expr) {
                    self.expr(child, depth + 1)?;
                }
            }
        }
        Ok(())
    }
}

fn invalid(message: &str) -> WalletError {
    WalletError::TxBuild(message.into())
}

fn collection_bound(length: usize) -> Result<(), WalletError> {
    if length > u16::MAX as usize {
        Err(invalid("context collection exceeds wire bound"))
    } else {
        Ok(())
    }
}

fn write_error(error: ergo_ser::error::WriteError) -> WalletError {
    invalid(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proving::prover::Prover, ReducedTransaction};
    use ergo_primitives::digest::Digest32;
    use ergo_ser::{
        ergo_box::ErgoBoxCandidate,
        register::{AdditionalRegisters, RegisterValue},
        sigma_value::SigmaBoolean,
        token::Token,
    };

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../test-vectors/wallet/reduced_scala_6_0_7.json"
        ))
        .unwrap()
    }

    fn transaction(row: &serde_json::Value) -> UnsignedTransaction {
        ReducedTransaction::from_bytes(
            &hex::decode(row["reduced_hex"].as_str().unwrap()).unwrap(),
            4,
        )
        .unwrap()
        .unsigned_transaction
    }

    #[test]
    fn bounded_messages_match_the_original_writer_and_exact_size_boundary() {
        for row in fixtures()["cases"].as_array().unwrap() {
            let tx = transaction(row);
            let expected = Prover::bytes_to_sign_for_tx(&tx).unwrap();
            assert_eq!(
                bytes_to_sign_bounded(&tx, expected.len()).unwrap(),
                expected
            );
            assert!(bytes_to_sign_bounded(&tx, expected.len() - 1).is_err());
        }
    }

    #[test]
    fn bounded_messages_preserve_tuple_collection_generator_and_hamt_provenance() {
        let mut tx = transaction(&fixtures()["cases"][0]);
        let entries = &mut tx.inputs[0].extension.values;
        entries.insert(100, (SigmaType::SGroupElement, SigmaValue::GroupGenerator));
        entries.insert(
            3,
            (
                SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SBoolean]),
                SigmaValue::Coll(CollValue::Values(vec![
                    SigmaValue::Int(42),
                    SigmaValue::Boolean(true),
                ])),
            ),
        );
        entries.insert(
            8,
            (
                SigmaType::SColl(Box::new(SigmaType::SBoolean)),
                SigmaValue::ConcreteCollection {
                    elem_type: Box::new(SigmaType::SBoolean),
                    items: vec![SigmaValue::Boolean(true), SigmaValue::Boolean(false)],
                },
            ),
        );
        entries.insert(0, (SigmaType::SInt, SigmaValue::Int(-1)));
        entries.insert(5, (SigmaType::SInt, SigmaValue::Int(128)));
        let expected = Prover::bytes_to_sign_for_tx(&tx).unwrap();
        assert_eq!(
            bytes_to_sign_bounded(&tx, expected.len()).unwrap(),
            expected
        );
    }

    #[test]
    fn shared_sigma_amplification_in_an_extension_is_rejected_before_writing() {
        let fixture = fixtures();
        let mut tx = transaction(&fixture["cases"][1]);
        let reduced = ReducedTransaction::from_bytes(
            &hex::decode(fixture["cases"][1]["reduced_hex"].as_str().unwrap()).unwrap(),
            4,
        )
        .unwrap();
        let mut sigma = reduced.reduced_inputs[0].sigma.clone();
        for _ in 0..30 {
            sigma = SigmaBoolean::Cand(vec![sigma.clone(), sigma].into());
        }
        tx.inputs[0]
            .extension
            .values
            .insert(1, (SigmaType::SSigmaProp, SigmaValue::SigmaProp(sigma)));
        assert!(
            bytes_to_sign_bounded(&tx, super::super::reduced::MAX_REDUCED_TRANSACTION_BYTES)
                .is_err()
        );
    }

    #[test]
    fn extension_depth_and_count_are_checked_before_recursive_serialization() {
        let mut extension = ContextExtension::empty();
        let mut tpe = SigmaType::SInt;
        let mut value = SigmaValue::Int(1);
        for _ in 0..MAX_CONTEXT_DEPTH {
            tpe = SigmaType::SOption(Box::new(tpe));
            value = SigmaValue::Opt(Some(Box::new(value)));
        }
        extension.values.insert(0, (tpe, value));
        assert!(preflight_extension(&extension)
            .unwrap_err()
            .to_string()
            .contains("depth bound"));
        extension.values.clear();
        for key in 0..=127 {
            extension
                .values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(0)));
        }
        assert!(preflight_extension(&extension)
            .unwrap_err()
            .to_string()
            .contains("entry bound"));
    }

    #[test]
    fn oversized_cached_output_and_token_table_fail_without_message_clones() {
        let mut tx = transaction(&fixtures()["cases"][0]);
        let output = &tx.output_candidates[0];
        tx.output_candidates[0] = ErgoBoxCandidate::new(
            output.value,
            output.ergo_tree().clone(),
            output.creation_height,
            vec![],
            AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SString,
                    value: SigmaValue::Str(
                        "x".repeat(super::super::reduced::MAX_REDUCED_TRANSACTION_BYTES),
                    ),
                }],
            },
        )
        .unwrap();
        assert!(
            bytes_to_sign_bounded(&tx, super::super::reduced::MAX_REDUCED_TRANSACTION_BYTES)
                .unwrap_err()
                .to_string()
                .contains("resource bound")
        );

        let mut tx = transaction(&fixtures()["cases"][0]);
        let mut output = tx.output_candidates[0].clone();
        output.tokens = (0..255)
            .map(|n: u32| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&n.to_be_bytes());
                Token {
                    token_id: Digest32::from_bytes(bytes),
                    amount: 1,
                }
            })
            .collect();
        tx.output_candidates = vec![output];
        assert!(bytes_to_sign_bounded(&tx, 4096)
            .unwrap_err()
            .to_string()
            .contains("resource bound"));
    }
}
