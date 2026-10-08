//! Resource-bounded message construction for the offline reduced codec.
//!
//! This wallet policy does not change the consensus transaction writer. The
//! emitted message is bounded exactly; extensions retain the consensus codec's
//! node provenance and ordering after a separate, finite structural preflight.

use std::collections::BTreeMap;

use ergo_primitives::{digest::Digest32, writer::VlqWriter};
use ergo_ser::{
    autolykos::AutolykosSolution,
    ergo_box::ErgoBoxCandidate,
    input::{write_context_extension, ContextExtension, DataInput},
    opcode::{children, Expr, Payload},
    sigma_type::SigmaType,
    sigma_value::{write_sigma_boolean_bounded, CollValue, SigmaValue},
    transaction::{Transaction, UnsignedTransaction},
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
    bytes_to_sign_from_parts(
        tx.inputs
            .iter()
            .map(|input| (&input.box_id, BorrowedExtension::Parsed(&input.extension))),
        &tx.data_inputs,
        &tx.output_candidates,
        max_bytes,
    )
}

pub(crate) fn bytes_to_sign_bounded_signed(
    tx: &Transaction,
    max_bytes: usize,
) -> Result<Vec<u8>, WalletError> {
    bytes_to_sign_from_parts(
        tx.inputs.iter().map(|input| {
            (
                &input.box_id,
                BorrowedExtension::Canonical(input.spending_proof.extension_bytes()),
            )
        }),
        &tx.data_inputs,
        &tx.output_candidates,
        max_bytes,
    )
}

enum BorrowedExtension<'a> {
    Parsed(&'a ContextExtension),
    // Consensus bytes_to_sign uses the canonical cache, not received bytes.
    Canonical(&'a [u8]),
}

fn bytes_to_sign_from_parts<'a>(
    inputs: impl ExactSizeIterator<Item = (&'a Digest32, BorrowedExtension<'a>)>,
    data_inputs: &[DataInput],
    output_candidates: &[ErgoBoxCandidate],
    max_bytes: usize,
) -> Result<Vec<u8>, WalletError> {
    let inputs_len = inputs.len();
    if [inputs_len, data_inputs.len(), output_candidates.len()]
        .into_iter()
        .any(|n| n > u16::MAX as usize)
    {
        return Err(invalid("transaction collection exceeds wire bound"));
    }

    // Count a lower bound before building the token table or serializing any
    // extension. Large cached trees/registers are rejected without cloning.
    let mut minimum = vlq_len(inputs_len as u64)
        + vlq_len(data_inputs.len() as u64)
        + vlq_len(output_candidates.len() as u64)
        + 1; // empty token-table count
    add_size(&mut minimum, inputs_len.saturating_mul(34), max_bytes)?;
    add_size(
        &mut minimum,
        data_inputs.len().saturating_mul(32),
        max_bytes,
    )?;
    for output in output_candidates {
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
    for output in output_candidates {
        for token in &output.tokens {
            let id = *token.token_id.as_bytes();
            if let std::collections::btree_map::Entry::Vacant(entry) = indexes.entry(id) {
                add_size(&mut minimum, 32, max_bytes)?;
                let index = token_ids.len() as u32;
                entry.insert(index);
                token_ids.push(id);
            }
        }
    }

    let mut message = BoundedWriter::new(max_bytes);
    message.unsigned(inputs_len as u64)?;
    for (box_id, extension) in inputs {
        message.bytes(box_id.as_bytes())?;
        message.byte(0)?; // empty signed proof, not the unsigned wire format
        match extension {
            BorrowedExtension::Parsed(extension) => {
                preflight_extension(extension)?;
                let mut encoded = VlqWriter::new();
                write_context_extension(&mut encoded, extension).map_err(write_error)?;
                message.bytes(encoded.as_slice())?;
            }
            BorrowedExtension::Canonical(bytes) => message.bytes(bytes)?,
        }
    }
    message.unsigned(data_inputs.len() as u64)?;
    for input in data_inputs {
        message.bytes(input.box_id.as_bytes())?;
    }
    message.unsigned(token_ids.len() as u64)?;
    for id in &token_ids {
        message.bytes(id)?;
    }
    message.unsigned(output_candidates.len() as u64)?;
    for output in output_candidates {
        message.unsigned(output.value)?;
        message.bytes(
            output
                .checked_serialized_ergo_tree_bytes()
                .map_err(write_error)?,
        )?;
        message.unsigned(u64::from(output.creation_height))?;
        message.byte(output.tokens.len() as u8)?;
        for token in &output.tokens {
            let index = indexes[token.token_id.as_bytes()];
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
                for cache in std::iter::once(canonical_bytes).chain(legacy_bytes.iter()) {
                    match cache {
                        Ok(bytes) => self.charge(bytes.len())?,
                        Err(ergo_ser::error::WriteError::InvalidData(message)) => {
                            self.charge(message.len())?;
                        }
                    }
                }
            }
            SigmaValue::Header(header, _) => {
                self.charge(1024 + header.unparsed_bytes.len())?;
                if let AutolykosSolution::V1 { d, .. } = &header.solution {
                    self.charge(d.len())?;
                }
            }
            SigmaValue::Unit
            | SigmaValue::Boolean(_)
            | SigmaValue::Byte(_)
            | SigmaValue::Short(_)
            | SigmaValue::Int(_)
            | SigmaValue::Long(_)
            | SigmaValue::GroupElement(_)
            | SigmaValue::GroupGenerator
            | SigmaValue::Opt(None) => {}
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
            Expr::Unparsed(tree) => {
                self.charge(tree.bytes.len())?;
                if let Some((_, args)) = &tree.validation_error {
                    self.charge(args.len())?;
                }
            }
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
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::{
        ergo_box::ErgoBoxCandidate,
        input::read_spending_proof,
        register::{AdditionalRegisters, RegisterValue},
        sigma_value::SigmaBoolean,
        token::Token,
        transaction::{bytes_to_sign, read_transaction},
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

    fn signed_transaction(row: &serde_json::Value) -> Transaction {
        let bytes = hex::decode(row["scala_signed_hex"].as_str().unwrap()).unwrap();
        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let tx = read_transaction(&mut reader).unwrap();
        assert_eq!(reader.remaining(), 0);
        tx
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
    fn signed_messages_match_appkit_and_ignore_only_signature_proof_bytes() {
        for row in fixtures()["cases"].as_array().unwrap() {
            let mut tx = signed_transaction(row);
            let expected = bytes_to_sign(&tx).unwrap();
            assert_eq!(
                expected,
                hex::decode(row["unsigned_message_hex"].as_str().unwrap()).unwrap()
            );
            assert_eq!(
                bytes_to_sign_bounded_signed(&tx, expected.len()).unwrap(),
                expected
            );
            assert!(bytes_to_sign_bounded_signed(&tx, expected.len() - 1).is_err());
            tx.inputs[0].spending_proof.proof = vec![0xAA; 1024];
            assert_eq!(
                bytes_to_sign_bounded_signed(&tx, expected.len()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn signed_messages_use_canonical_extension_cache_instead_of_received_encoding() {
        let mut tx = signed_transaction(&fixtures()["cases"][0]);
        // Empty proof plus one TrueLeaf extension: Scala signs a canonical
        // Boolean Constant, while the accepted received bytes remain distinct.
        let mut reader = VlqReader::new(&[0, 1, 7, 0x7F]);
        tx.inputs[0].spending_proof = read_spending_proof(&mut reader).unwrap();
        let proof = &tx.inputs[0].spending_proof;
        assert_ne!(proof.extension_bytes(), proof.received_extension_bytes());
        let expected = bytes_to_sign(&tx).unwrap();
        assert_eq!(
            bytes_to_sign_bounded_signed(&tx, expected.len()).unwrap(),
            expected
        );
    }

    #[test]
    fn signed_extra_outputs_and_token_tables_obey_the_same_resource_caps() {
        let row = &fixtures()["cases"][0];
        let mut tx = signed_transaction(row);
        let budget = bytes_to_sign(&tx).unwrap().len();
        tx.output_candidates.push(tx.output_candidates[0].clone());
        assert!(bytes_to_sign_bounded_signed(&tx, budget).is_err());

        let mut tx = signed_transaction(row);
        tx.output_candidates[0].tokens = (0..255)
            .map(|n: u32| {
                let mut id = [0; 32];
                id[..4].copy_from_slice(&n.to_be_bytes());
                Token {
                    token_id: Digest32::from_bytes(id),
                    amount: 1,
                }
            })
            .collect();
        assert!(bytes_to_sign_bounded_signed(&tx, 4096)
            .unwrap_err()
            .to_string()
            .contains("resource bound"));
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
