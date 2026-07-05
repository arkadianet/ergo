//! Scala-compat encoders and parsers used by the API bridge.
//!
//! Pure transforms over wire types: parse `Header` / `BlockTransactions`
//! / `Extension` from canonical bytes, and translate them plus their
//! components (`Transaction`, `Input`, `Output`, `Extension`, `AdProofs`,
//! Autolykos solution) into the Scala-compatible JSON DTOs that
//! `ergo_api::compat::types` defines. No state, no I/O, no NodeState
//! coupling — sibling helpers in `api_bridge.rs` (`load_and_encode_*`,
//! `assemble_full_block`, etc.) supply the bytes and call into these.

use std::collections::BTreeMap;

use ergo_api::compat::types::{
    ScalaAdProofs, ScalaAsset, ScalaBlockTransactions, ScalaDataInput, ScalaExtension, ScalaHeader,
    ScalaInput, ScalaOutput, ScalaPowSolutions, ScalaSpendingProof, ScalaTransaction,
};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ad_proofs::read_ad_proofs;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::extension::read_extension;
use ergo_ser::header::{read_header, Header};
use ergo_ser::input::split_context_extension_bytes;
use ergo_ser::modifier_id::ExpectedSections;
use ergo_ser::register::split_register_bytes;
use ergo_ser::transaction::transaction_id;

use super::error::BridgeError;

pub(super) fn parse_header(bytes: &[u8]) -> Result<Header, BridgeError> {
    let mut r = VlqReader::new(bytes);
    read_header(&mut r).map_err(|source| BridgeError::Parse {
        what: "header",
        source,
    })
}

pub(super) fn parse_block_transactions(
    bytes: &[u8],
) -> Result<ergo_ser::block_transactions::BlockTransactions, BridgeError> {
    let mut r = VlqReader::new(bytes);
    read_block_transactions(&mut r).map_err(|source| BridgeError::Parse {
        what: "block_transactions",
        source,
    })
}

pub(super) fn parse_extension(bytes: &[u8]) -> Result<ergo_ser::extension::Extension, BridgeError> {
    let mut r = VlqReader::new(bytes);
    read_extension(&mut r).map_err(|source| BridgeError::Parse {
        what: "extension",
        source,
    })
}

/// Scala's `Header.jsonEncoder` emits `id` from `bytesWithoutPow` round-tripped
/// through blake2b, but the canonical id is just blake2b256 of the full bytes.
/// We use the latter (matches the chain's notion of header_id).
pub(super) fn encode_header(
    h: &Header,
    size: u32,
    expected: &ExpectedSections,
    header_id_hex: &str,
) -> ScalaHeader {
    let (pk_hex, w_hex, n_hex, d_value) = encode_pow_solutions(&h.solution);
    let difficulty = decode_compact_bits(h.n_bits).to_string();
    ScalaHeader {
        extension_id: hex::encode(expected.extension_id),
        difficulty,
        votes: hex::encode(h.votes),
        timestamp: h.timestamp,
        size,
        unparsed_bytes: hex::encode(&h.unparsed_bytes),
        state_root: hex::encode(h.state_root.as_bytes()),
        height: h.height,
        n_bits: h.n_bits as u64,
        version: h.version,
        id: header_id_hex.to_string(),
        ad_proofs_root: hex::encode(h.ad_proofs_root.as_bytes()),
        transactions_root: hex::encode(h.transactions_root.as_bytes()),
        extension_hash: hex::encode(h.extension_root.as_bytes()),
        pow_solutions: ScalaPowSolutions {
            pk: pk_hex,
            w: w_hex,
            n: n_hex,
            d: d_value,
        },
        ad_proofs_id: hex::encode(expected.ad_proofs_id),
        transactions_id: hex::encode(expected.transactions_id),
        parent_id: hex::encode(h.parent_id.as_bytes()),
    }
}

const SECP256K1_GENERATOR_HEX: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

pub(super) fn encode_pow_solutions(
    sol: &AutolykosSolution,
) -> (String, String, String, serde_json::Value) {
    match sol {
        AutolykosSolution::V1 { pk, w, nonce, d } => (
            hex::encode(pk.as_bytes()),
            hex::encode(w.as_bytes()),
            hex::encode(nonce),
            // V1 d is a big-endian UNSIGNED magnitude (Scala serializes
            // it via `BigIntegers.asUnsignedByteArray`, no sign byte) and
            // Scala's JSON renders it as a bare NUMBER literal (circe
            // BigInt encoder), not a string. Both halves were wrong here
            // until the NiPoPoW oracle capture exposed them on real v1
            // headers: `from_signed_bytes_be` flipped high-bit magnitudes
            // negative (live repro: h=28662 served d = -652…), and the
            // string form diverged from Scala's number. Requires
            // serde_json `arbitrary_precision` (enabled via
            // ergo-rest-json) — v1 d values are ~2^190.
            {
                let dec = num_bigint::BigUint::from_bytes_be(d).to_string();
                let n: serde_json::Number = dec
                    .parse()
                    .expect("decimal digit string always parses as an arbitrary-precision number");
                serde_json::Value::Number(n)
            },
        ),
        AutolykosSolution::V2 { pk, nonce } => (
            hex::encode(pk.as_bytes()),
            SECP256K1_GENERATOR_HEX.to_string(),
            hex::encode(nonce),
            serde_json::Value::Number(0u64.into()),
        ),
    }
}

pub(super) fn encode_block_transactions(
    bt: &ergo_ser::block_transactions::BlockTransactions,
    header_id_hex: &str,
    section_size: u32,
    header: &Header,
) -> Result<ScalaBlockTransactions, BridgeError> {
    let mut transactions = Vec::with_capacity(bt.transactions.len());
    for tx in &bt.transactions {
        transactions.push(encode_transaction(tx)?);
    }
    Ok(ScalaBlockTransactions {
        header_id: header_id_hex.to_string(),
        transactions,
        block_version: header.version,
        size: section_size,
    })
}

pub(super) fn encode_transaction(
    tx: &ergo_ser::transaction::Transaction,
) -> Result<ScalaTransaction, BridgeError> {
    let tx_id = transaction_id(tx).map_err(|source| BridgeError::Encode {
        what: "tx_id",
        source,
    })?;
    let tx_id_hex = hex::encode(tx_id.as_bytes());

    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        inputs.push(encode_input(input)?);
    }
    let data_inputs = tx
        .data_inputs
        .iter()
        .map(|di| ScalaDataInput {
            box_id: hex::encode(di.box_id.as_bytes()),
        })
        .collect();
    let mut outputs = Vec::with_capacity(tx.output_candidates.len());
    for (idx, candidate) in tx.output_candidates.iter().enumerate() {
        let ergo_box = ErgoBox {
            candidate: candidate.clone(),
            transaction_id: tx_id,
            index: idx as u16,
        };
        let box_id = ergo_box.box_id().map_err(|source| BridgeError::Encode {
            what: "box_id",
            source,
        })?;
        outputs.push(encode_output(
            candidate,
            hex::encode(box_id.as_bytes()),
            tx_id_hex.clone(),
            idx as u16,
        )?);
    }

    let size = tx_size(tx)?;
    Ok(ScalaTransaction {
        id: tx_id_hex,
        inputs,
        data_inputs,
        outputs,
        size,
    })
}

fn tx_size(tx: &ergo_ser::transaction::Transaction) -> Result<u32, BridgeError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_transaction(&mut w, tx).map_err(|source| BridgeError::Encode {
        what: "transaction",
        source,
    })?;
    Ok(w.result().len() as u32)
}

pub(super) fn encode_input(input: &ergo_ser::input::Input) -> Result<ScalaInput, BridgeError> {
    let entries = split_context_extension_bytes(input.spending_proof.extension_bytes()).map_err(
        |source| BridgeError::Parse {
            what: "spending_proof_extension",
            source,
        },
    )?;
    let extension: indexmap::IndexMap<String, String> = entries
        .into_iter()
        .map(|(k, v)| (k.to_string(), hex::encode(v)))
        .collect();
    Ok(ScalaInput {
        box_id: hex::encode(input.box_id.as_bytes()),
        spending_proof: ScalaSpendingProof {
            proof_bytes: hex::encode(&input.spending_proof.proof),
            extension,
        },
    })
}

pub(super) const REGISTER_NAMES: [&str; 6] = ["R4", "R5", "R6", "R7", "R8", "R9"];

pub(super) fn encode_output(
    candidate: &ergo_ser::ergo_box::ErgoBoxCandidate,
    box_id_hex: String,
    transaction_id_hex: String,
    index: u16,
) -> Result<ScalaOutput, BridgeError> {
    let assets = candidate
        .tokens
        .iter()
        .map(|t| ScalaAsset {
            token_id: hex::encode(t.token_id.as_bytes()),
            amount: t.amount,
        })
        .collect();

    // Emit the wire-form register bytes the parser preserved, not a
    // round-trip through `write_registers`. The parser
    // captures the original encoding verbatim (Const vs expr form,
    // padding, ordering), which `split_register_bytes` walks back out
    // into per-register slices without ever calling the writer.
    let slices =
        split_register_bytes(candidate.register_bytes()).map_err(|source| BridgeError::Parse {
            what: "registers",
            source,
        })?;
    let additional_registers: BTreeMap<String, String> = slices
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| (REGISTER_NAMES[i].to_string(), hex::encode(bytes)))
        .collect();

    Ok(ScalaOutput {
        box_id: box_id_hex,
        value: candidate.value,
        ergo_tree: hex::encode(candidate.ergo_tree_bytes()),
        assets,
        creation_height: candidate.creation_height,
        additional_registers,
        transaction_id: transaction_id_hex,
        index,
    })
}

pub(super) fn encode_extension(
    ext: &ergo_ser::extension::Extension,
    header_id_hex: &str,
    extension_root: &[u8; 32],
) -> ScalaExtension {
    let fields = ext
        .fields
        .iter()
        .map(|f| [hex::encode(f.key), hex::encode(&f.value)])
        .collect();
    ScalaExtension {
        header_id: header_id_hex.to_string(),
        // Scala's `Extension.jsonEncoder` emits `merkleTree.rootHash`,
        // which equals the header's `extensionRoot` by construction.
        digest: hex::encode(extension_root),
        fields,
    }
}

pub(super) fn encode_ad_proofs(
    bytes: &[u8],
    header_id_hex: &str,
    header: &Header,
) -> Result<ScalaAdProofs, BridgeError> {
    let mut r = VlqReader::new(bytes);
    let proofs = read_ad_proofs(&mut r).map_err(|source| BridgeError::Parse {
        what: "ad_proofs",
        source,
    })?;
    Ok(ScalaAdProofs {
        header_id: header_id_hex.to_string(),
        proof_bytes: hex::encode(&proofs.proof_bytes),
        digest: hex::encode(header.ad_proofs_root.as_bytes()),
        size: bytes.len() as u32,
    })
}
