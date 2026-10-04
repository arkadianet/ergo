//! Parsed allocation charges in addition to retained wire bytes and their margin.

use std::mem::size_of;

use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::opcode::{preorder, Expr, Payload};
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

use crate::candidate::Candidate;

fn vector_size<T>(values: &Vec<T>) -> usize {
    values.capacity().saturating_mul(size_of::<T>())
}

fn sigma_size(value: &SigmaBoolean) -> usize {
    match value {
        SigmaBoolean::Cand(children)
        | SigmaBoolean::Cor(children)
        | SigmaBoolean::Cthreshold { children, .. } => children
            .len()
            .saturating_mul(2 * size_of::<SigmaBoolean>())
            .saturating_add(children.iter().map(sigma_size).sum::<usize>()),
        _ => 0,
    }
}

fn value_size(value: &SigmaValue) -> usize {
    match value {
        SigmaValue::Coll(CollValue::Values(items))
        | SigmaValue::Tuple(items)
        | SigmaValue::ConcreteCollection { items, .. } => {
            vector_size(items).saturating_add(items.iter().map(value_size).sum::<usize>())
        }
        SigmaValue::Coll(CollValue::BoolBits(bits)) => vector_size(bits),
        SigmaValue::Coll(CollValue::Bytes(bytes)) | SigmaValue::OpaqueBoxBytes(bytes) => {
            bytes.capacity()
        }
        SigmaValue::Opt(Some(value)) => size_of::<SigmaValue>().saturating_add(value_size(value)),
        SigmaValue::Str(value) => value.capacity(),
        SigmaValue::BigInt(value) => (value.bits().div_ceil(8) as usize).saturating_mul(2),
        SigmaValue::SigmaProp(value) => sigma_size(value),
        SigmaValue::AvlTree(value) => value.digest.capacity(),
        SigmaValue::Header(header, _) => {
            size_of::<ergo_ser::header::Header>() + header.unparsed_bytes.capacity()
        }
        _ => 0,
    }
}

fn box_size(box_: &ErgoBoxCandidate) -> usize {
    let tree = box_.ergo_tree();
    let nodes = preorder(&tree.body)
        .map(|(_, node)| {
            // Count boxed nodes and spare vector capacity conservatively. The wire
            // margin also covers leaf data, type descriptors and allocator overhead.
            let extra = match node {
                Expr::Const { val, .. } => value_size(val),
                Expr::Op(node) => match &node.payload {
                    Payload::BoolCollection { bits } => vector_size(bits),
                    _ => 0,
                },
                Expr::Unparsed(raw) => raw.bytes.capacity(),
            };
            (2 * size_of::<Expr>()).saturating_add(extra)
        })
        .sum::<usize>();
    let registers = box_.additional_registers();
    size_of::<ErgoBoxCandidate>()
        .saturating_add(vector_size(&box_.tokens))
        .saturating_add(vector_size(&tree.constants))
        .saturating_add(
            tree.constants
                .iter()
                .map(|(_, value)| value_size(value))
                .sum::<usize>(),
        )
        .saturating_add(vector_size(&registers.registers))
        .saturating_add(
            registers
                .registers
                .iter()
                .map(|r| value_size(&r.value))
                .sum::<usize>(),
        )
        .saturating_add(nodes)
}

pub(crate) fn candidate_parsed_size(candidate: &Candidate) -> usize {
    let transactions = candidate
        .transactions
        .iter()
        .map(|tx| {
            vector_size(&tx.inputs)
                .saturating_add(vector_size(&tx.data_inputs))
                .saturating_add(vector_size(&tx.output_candidates))
                .saturating_add(tx.output_candidates.iter().map(box_size).sum::<usize>())
                .saturating_add(
                    tx.inputs
                        .iter()
                        .map(|input| {
                            input
                                .spending_proof
                                .proof
                                .capacity()
                                .saturating_add(
                                    input
                                        .spending_proof
                                        .extension()
                                        .values
                                        .capacity()
                                        .saturating_mul(size_of::<(
                                            u8,
                                            (ergo_ser::sigma_type::SigmaType, SigmaValue),
                                        )>(
                                        )),
                                )
                                .saturating_add(
                                    input
                                        .spending_proof
                                        .extension()
                                        .values
                                        .values()
                                        .map(|(_, value)| value_size(value))
                                        .sum::<usize>(),
                                )
                        })
                        .sum::<usize>(),
                )
        })
        .sum::<usize>();
    let observations = candidate
        .observation
        .transactions
        .iter()
        .map(|tx| {
            vector_size(&tx.resolved_inputs).saturating_add(
                tx.resolved_inputs
                    .iter()
                    .map(|box_| box_size(&box_.candidate))
                    .sum::<usize>(),
            )
        })
        .sum::<usize>();
    vector_size(&candidate.transactions)
        .saturating_add(transactions)
        .saturating_add(vector_size(&candidate.observation.transactions))
        .saturating_add(observations)
        .saturating_add(vector_size(&candidate.observation.requested_ids))
        .saturating_add(vector_size(&candidate.validation_ctx.last_headers))
        .saturating_add(
            candidate
                .validation_ctx
                .last_headers
                .iter()
                .map(|h| h.unparsed_bytes.capacity())
                .sum::<usize>(),
        )
}
