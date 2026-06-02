//! JSON `ScalaTransactionInput` → canonical wire bytes.
//!
//! Parse incoming hex via existing `ergo-ser` readers, then re-serialize
//! via existing writers to canonical bytes; reject soft-fork ergoTree
//! submissions in v1 with `non_canonical`.
//!
//! The first element of the error tuple is the envelope reason string
//! (`"deserialize"` for malformed wire / hex, `"non_canonical"` for
//! the soft-fork reject path); the second is operator-readable detail.
//!
//! Anchored by the b4_* byte-parity oracle in
//! `ergo-node/src/api_bridge.rs::tests`.

use std::collections::BTreeMap;

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ad_proofs::{write_ad_proofs, ADProofs};
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree, ErgoTree};
use ergo_ser::extension::{write_extension, Extension, ExtensionField};
use ergo_ser::input::{read_context_extension, ContextExtension, DataInput, Input, SpendingProof};
use ergo_ser::opcode::Expr;
use ergo_ser::register::{read_registers, write_registers, AdditionalRegisters};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::{Token, TokenId};
use ergo_ser::transaction::{write_transaction, Transaction};

use crate::types::{
    ScalaAdProofs, ScalaBlockTransactions, ScalaDataInput, ScalaExtension, ScalaFullBlock,
    ScalaHeader, ScalaInput, ScalaOutputInput, ScalaTransactionInput,
};

pub const NON_CANONICAL: &str = "non_canonical";
pub const DESERIALIZE: &str = "deserialize";

/// Maximum supported ErgoTree version for canonical re-serialization.
/// Matches `ergo_ser::ergo_tree::MAX_SUPPORTED_TREE_VERSION` (private
/// there). Mirrors Scala's `VersionContext.MaxSupportedScriptVersion`.
const MAX_SUPPORTED_TREE_VERSION: u8 = 3;

const REGISTER_NAMES: [&str; 6] = ["R4", "R5", "R6", "R7", "R8", "R9"];

/// Reason+detail tuple. The reason string is the envelope reason
/// (`"deserialize"` / `"non_canonical"`).
pub type DecodeError = (&'static str, String);

pub fn decode_scala_transaction(input: &ScalaTransactionInput) -> Result<Vec<u8>, DecodeError> {
    decode_scala_transaction_with_mode(input, DecodeMode::Submit)
}

/// Mode-aware variant. Pass `DecodeMode::Preserve` to keep wire
/// bytes verbatim and accept soft-fork ergoTree versions already
/// on chain.
pub fn decode_scala_transaction_with_mode(
    input: &ScalaTransactionInput,
    mode: DecodeMode,
) -> Result<Vec<u8>, DecodeError> {
    let tx = build_transaction_from_input(input, mode, "")?;
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).map_err(|e| (DESERIALIZE, format!("tx serialize: {e}")))?;
    Ok(w.result())
}

/// Build a [`Transaction`] from a [`ScalaTransactionInput`] in the
/// given mode. Single-source-of-truth for the input / data-input /
/// output loops shared by [`decode_scala_transaction_with_mode`]
/// and [`decode_block_transactions_with_mode`] — prevents the two
/// callers from drifting and accidentally invoking the submit-
/// default helpers on the preserve path.
///
/// `path_prefix` scopes error messages (e.g. `"transactions[7]."`
/// for the block-section caller; empty string for the standalone-
/// tx caller).
fn build_transaction_from_input(
    input: &ScalaTransactionInput,
    mode: DecodeMode,
    path_prefix: &str,
) -> Result<Transaction, DecodeError> {
    let mut inputs = Vec::with_capacity(input.inputs.len());
    for (i, si) in input.inputs.iter().enumerate() {
        inputs.push(
            decode_input_with_mode(si, mode)
                .map_err(|(r, d)| (r, format!("{path_prefix}inputs[{i}]: {d}")))?,
        );
    }
    let mut data_inputs = Vec::with_capacity(input.data_inputs.len());
    for (i, di) in input.data_inputs.iter().enumerate() {
        data_inputs.push(
            decode_data_input(di)
                .map_err(|(r, d)| (r, format!("{path_prefix}dataInputs[{i}]: {d}")))?,
        );
    }
    let mut output_candidates = Vec::with_capacity(input.outputs.len());
    for (i, so) in input.outputs.iter().enumerate() {
        output_candidates.push(
            decode_output_with_mode(so, mode)
                .map_err(|(r, d)| (r, format!("{path_prefix}outputs[{i}]: {d}")))?,
        );
    }
    Ok(Transaction {
        inputs,
        data_inputs,
        output_candidates,
    })
}

/// Defaults to [`DecodeMode::Submit`]. See [`decode_input_with_mode`]
/// for the mode contract.
pub fn decode_input(si: &ScalaInput) -> Result<Input, DecodeError> {
    decode_input_with_mode(si, DecodeMode::Submit)
}

/// Mode-aware variant of [`decode_input`].
///
/// **`DecodeMode::Submit`** (wallet → node): the input's
/// `spendingProof.extension` is parsed and re-serialized via
/// [`SpendingProof::new`], canonicalizing non-canonical encodings
/// the wallet may have submitted (mirrors register canonicalization
/// — see `b4_q5_extension_canonicalization*` in
/// `ergo-node/src/api_bridge.rs`).
///
/// **`DecodeMode::Preserve`**:
/// the input's `extension_bytes` are preserved verbatim from the
/// JSON hex via [`SpendingProof::from_trusted_raw_parts`]. Scala has
/// already validated these bytes on chain; the consensus-bearing
/// `tx_id = blake2b256(bytes_to_sign)` requires byte-identical
/// re-emission. Closes the same `ConstantSerializer`-vs-AST-form
/// drift class that the register-side fix addresses.
pub fn decode_input_with_mode(si: &ScalaInput, mode: DecodeMode) -> Result<Input, DecodeError> {
    let box_id = decode_digest32(&si.box_id, "boxId")?;
    let proof = hex::decode(&si.spending_proof.proof_bytes)
        .map_err(|e| (DESERIALIZE, format!("spendingProof.proofBytes hex: {e}")))?;
    let (extension, raw_extension_bytes) =
        decode_context_extension_with_mode(&si.spending_proof.extension, mode)
            .map_err(|(r, d)| (r, format!("spendingProof.{d}")))?;
    let spending_proof = match mode {
        DecodeMode::Preserve => {
            SpendingProof::from_trusted_raw_parts(proof, extension, raw_extension_bytes)
        }
        DecodeMode::Submit => SpendingProof::new(proof, extension)
            .map_err(|e| (DESERIALIZE, format!("spendingProof build: {e}")))?,
    };
    Ok(Input {
        box_id,
        spending_proof,
    })
}

pub fn decode_data_input(di: &ScalaDataInput) -> Result<DataInput, DecodeError> {
    let box_id = decode_digest32(&di.box_id, "boxId")?;
    Ok(DataInput { box_id })
}

pub fn decode_output(so: &ScalaOutputInput) -> Result<ErgoBoxCandidate, DecodeError> {
    decode_output_with_mode(so, DecodeMode::Submit)
}

pub fn decode_output_with_mode(
    so: &ScalaOutputInput,
    mode: DecodeMode,
) -> Result<ErgoBoxCandidate, DecodeError> {
    let value = so.value;
    let creation_height = so.creation_height;

    // ergoTree: parse → canonicalize. Submit rejects soft-fork;
    // Preserve accepts it (already on chain).
    let (parsed_tree, canonical_tree_bytes) =
        decode_ergo_tree_canonicalize_with_mode(&so.ergo_tree, mode)
            .map_err(|(r, d)| (r, format!("ergoTree: {d}")))?;

    // assets → Vec<Token>
    let mut tokens = Vec::with_capacity(so.assets.len());
    for (i, a) in so.assets.iter().enumerate() {
        let token_id_bytes = decode_digest32(&a.token_id, "tokenId")
            .map_err(|(r, d)| (r, format!("assets[{i}]: {d}")))?;
        tokens.push(Token {
            token_id: TokenId::from_bytes(*token_id_bytes.as_bytes()),
            amount: a.amount,
        });
    }

    // additionalRegisters: map → AdditionalRegisters → canonical bytes.
    // In Preserve mode the wire bytes are returned verbatim so
    // bytes_to_sign(tx) reproduces Scala's emission byte-for-byte
    // (Constant[STuple] vs CreateTuple form is value-node-driven on
    // the Scala side; we cannot canonicalize without losing parity).
    let (registers, canonical_register_bytes) =
        decode_registers_with_mode(&so.additional_registers, mode)
            .map_err(|(r, d)| (r, d.to_string()))?;

    Ok(ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        parsed_tree,
        canonical_tree_bytes,
        creation_height,
        tokens,
        registers,
        canonical_register_bytes,
    ))
}

pub fn decode_digest32(s: &str, field: &str) -> Result<Digest32, DecodeError> {
    let raw = hex::decode(s).map_err(|e| (DESERIALIZE, format!("{field} hex: {e}")))?;
    if raw.len() != 32 {
        return Err((DESERIALIZE, format!("{field} length {} != 32", raw.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(Digest32::from_bytes(arr))
}

/// Decode the JSON `extension` map (decimal-keyed) into a structured
/// `ContextExtension`. Defaults to [`DecodeMode::Submit`].
///
/// In Submit mode only the parsed struct is returned; callers that
/// need the canonicalized wire bytes should pass through
/// [`SpendingProof::new`] which re-serializes the parsed struct.
/// See [`decode_context_extension_with_mode`] for the raw-bytes
/// variant used by `DecodeMode::Preserve` callers.
pub fn decode_context_extension(
    map: &indexmap::IndexMap<String, String>,
) -> Result<ContextExtension, DecodeError> {
    decode_context_extension_with_mode(map, DecodeMode::Submit).map(|(p, _)| p)
}

/// Mode-aware variant returning the raw wire bytes of the parsed
/// extension along with the parsed struct.
///
/// **`DecodeMode::Submit`**: the returned `Vec<u8>` is the
/// re-serialized canonical wire (output of `write_context_extension`
/// applied to the parsed struct). Wallets that submit non-canonical
/// encodings (e.g. SBoolean `0105`) get normalized to canonical
/// (`0101`) bytes — pinned by `b4_q5_extension_canonicalization*`
/// in `ergo-node/src/api_bridge.rs`.
///
/// **`DecodeMode::Preserve`**: the returned `Vec<u8>` is the input
/// hex concatenated verbatim (`count(u8) || repeated (key(u8),
/// value_bytes)`). Used by [`decode_input_with_mode`] +
/// [`SpendingProof::from_trusted_raw_parts`] so `bytes_to_sign(tx)` matches
/// Scala's wire form byte-for-byte. Same architectural class as the
/// register raw-passthrough fix at [`decode_registers_with_mode`].
pub fn decode_context_extension_with_mode(
    map: &indexmap::IndexMap<String, String>,
    mode: DecodeMode,
) -> Result<(ContextExtension, Vec<u8>), DecodeError> {
    if map.len() > u8::MAX as usize {
        return Err((
            DESERIALIZE,
            format!("extension entry count {} exceeds u8 max", map.len()),
        ));
    }
    // Build wire-shape: count(u8) + repeated (key(u8), constant_bytes).
    // IndexMap iteration preserves JSON object key order, so a Scala
    // wallet's emit order survives deserialization end-to-end.
    let mut entries: Vec<(u8, Vec<u8>)> = Vec::with_capacity(map.len());
    for (k, v) in map {
        let key: u8 = k
            .parse()
            .map_err(|_| (DESERIALIZE, format!("extension key {k:?} not a u8")))?;
        let bytes =
            hex::decode(v).map_err(|e| (DESERIALIZE, format!("extension[{k}] value hex: {e}")))?;
        entries.push((key, bytes));
    }
    // Duplicate-key check via HashSet so we don't mutate the order
    // the wallet sent (`IndexMap<String, String>` from serde would
    // already collapse duplicates to last-value-wins; this is a
    // defensive guard for any future input type or malicious JSON).
    {
        let mut seen = std::collections::HashSet::new();
        for (k, _) in &entries {
            if !seen.insert(*k) {
                return Err((DESERIALIZE, "extension has duplicate keys".to_string()));
            }
        }
    }
    // For ≥ 5 entries, override the JSON order with Scala 2.12 HAMT
    // depth-first iteration. HAMT order is a pure function of the
    // keyset, so the JSON arrival order doesn't matter. For ≤ 4
    // entries, the JSON order IS the wallet's insertion order — keep
    // it to preserve `Map1`-`Map4` parity.
    if entries.len() >= 5 {
        entries.sort_by_key(|(k, _)| ergo_ser::scala_hamt::hamt_sort_key_for_byte_key(*k));
    }

    let mut buf = VlqWriter::new();
    buf.put_u8(entries.len() as u8);
    for (k, v) in &entries {
        buf.put_u8(*k);
        buf.put_bytes(v);
    }
    let wire = buf.result();
    let mut r = VlqReader::new(&wire);
    let parsed = read_context_extension(&mut r)
        .map_err(|e| (DESERIALIZE, format!("extension parse: {e}")))?;
    if !r.is_empty() {
        return Err((
            DESERIALIZE,
            format!(
                "extension has {} trailing bytes after parse",
                wire.len() - r.position()
            ),
        ));
    }

    match mode {
        DecodeMode::Preserve => Ok((parsed, wire)),
        DecodeMode::Submit => {
            let mut cw = VlqWriter::new();
            ergo_ser::input::write_context_extension(&mut cw, &parsed)
                .map_err(|e| (DESERIALIZE, format!("extension re-serialize: {e}")))?;
            Ok((parsed, cw.result()))
        }
    }
}

/// Decode the JSON `additionalRegisters` map into a structured
/// `AdditionalRegisters` plus its canonical wire bytes. Densely
/// packed from R4 upward — gaps are rejected, and any key outside
/// R4..R9 is rejected (matches Scala's `registersDecoder` in
/// `JsonCodecs.scala:106`).
///
/// Defaults to `DecodeMode::Submit` — see
/// [`decode_registers_with_mode`] for the mode contract.
pub fn decode_registers(
    map: &BTreeMap<String, String>,
) -> Result<(AdditionalRegisters, Vec<u8>), DecodeError> {
    decode_registers_with_mode(map, DecodeMode::Submit)
}

/// Mode-aware variant of [`decode_registers`].
///
/// **`DecodeMode::Submit`** (wallet → node): the returned wire
/// bytes are the writer's re-serialized canonical form. This
/// canonicalizes non-canonical encodings the wallet might have
/// submitted (e.g. SBoolean `0105` → `0101`) so hash-bearing
/// surfaces (tx_id, box_id) collapse to one form. Pinned by the
/// `b4_q5_register_canonicalization*` tests in
/// `ergo-node/src/api_bridge.rs`.
///
/// **`DecodeMode::Preserve`**:
/// the returned wire bytes are the **original** input hex
/// concatenated, byte-for-byte. Scala already validated these on
/// chain; the consensus-bearing `tx_id =
/// blake2b256(bytes_to_sign)` requires byte-identical re-emission
/// of every section we ingested. Re-serializing via
/// `write_registers` would normalize legitimate `Constant[STuple]`
/// forms (e.g. `3c 0e 0e …` at h=836113 R9) into the writer's
/// `CreateTuple` form (`86 02 …`), which Scala accepts as also
/// valid but breaks byte-fidelity for the upstream wire. Pinned by
/// `ergo-validation/tests/diagnose_block_836113.rs`. Scala's choice
/// between `Constant[STuple]` and `Tuple(...)` is AST-driven, not
/// type-driven, so a type-conditional canonicalizer cannot reproduce
/// both forms — preserve mode keeps the original bytes verbatim.
///
/// In both modes the parse-validation step still runs — gap /
/// trailing-byte / unknown-register checks fire identically.
pub fn decode_registers_with_mode(
    map: &BTreeMap<String, String>,
    mode: DecodeMode,
) -> Result<(AdditionalRegisters, Vec<u8>), DecodeError> {
    for key in map.keys() {
        if !REGISTER_NAMES.contains(&key.as_str()) {
            return Err((
                DESERIALIZE,
                format!("additionalRegisters: unknown register name `{key}` (allowed: R4..R9)"),
            ));
        }
    }
    let mut ordered: Vec<Vec<u8>> = Vec::with_capacity(map.len());
    for (idx, name) in REGISTER_NAMES.iter().enumerate() {
        match map.get(*name) {
            Some(hex_str) => {
                let bytes = hex::decode(hex_str)
                    .map_err(|e| (DESERIALIZE, format!("additionalRegisters[{name}] hex: {e}")))?;
                ordered.push(bytes);
            }
            None => {
                if (idx + 1..6).any(|j| map.contains_key(REGISTER_NAMES[j])) {
                    return Err((
                        DESERIALIZE,
                        format!(
                            "additionalRegisters has gap at {name} (must be densely packed R4..R9)"
                        ),
                    ));
                }
                break;
            }
        }
    }

    let mut buf = VlqWriter::new();
    buf.put_u8(ordered.len() as u8);
    for entry in &ordered {
        buf.put_bytes(entry);
    }
    let wire = buf.result();

    let mut r = VlqReader::new(&wire);
    let parsed = read_registers(&mut r)
        .map_err(|e| (DESERIALIZE, format!("additionalRegisters parse: {e}")))?;
    if !r.is_empty() {
        return Err((
            DESERIALIZE,
            format!(
                "additionalRegisters has {} trailing bytes",
                wire.len() - r.position()
            ),
        ));
    }

    match mode {
        DecodeMode::Preserve => Ok((parsed, wire)),
        DecodeMode::Submit => {
            let mut cw = VlqWriter::new();
            write_registers(&mut cw, &parsed).map_err(|e| {
                (
                    DESERIALIZE,
                    format!("additionalRegisters re-serialize: {e}"),
                )
            })?;
            Ok((parsed, cw.result()))
        }
    }
}

/// Decode mode: SUBMIT (wallet→node) is strict; PRESERVE
/// (on-chain bytes from Scala) is lenient on soft-fork ergoTree
/// versions.
///
/// SUBMIT path defenses: reject `version > MAX_SUPPORTED_TREE_VERSION`
/// AND placeholder-fallback re-emit divergence — a wallet cannot
/// sneak in an unsupported tree.
///
/// PRESERVE path (live mainnet bytes from Scala): accept any
/// version that `read_ergo_tree` can handle (including the
/// soft-fork placeholder fallback for `version > 3` AND
/// has_size). Scala already validated these on chain, our
/// executor will re-validate; the JSON→wire conversion just
/// needs to produce byte-identical canonical bytes for hashing
/// and persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    /// Wallet/operator submission. Reject soft-fork versions and
    /// canonicalize incoming wire bytes.
    Submit,
    /// Preserve incoming wire bytes verbatim and accept soft-fork
    /// ergoTree versions. Used for data already accepted on chain
    /// (historical-block diagnostics, byte-fidelity oracles) where
    /// re-canonicalization would corrupt content-addressed identifiers.
    Preserve,
}

/// Decode an `ergoTree` hex string into `(parsed, canonical_bytes)`.
///
/// Always returns the INPUT bytes as the canonical Vec<u8>. We
/// do NOT use `write_ergo_tree`'s re-emitted form because the
/// serializer is lossy for some opcode encodings (live h=303967
/// case: `1000d1ed8501` re-emitted as `1000d1ed01010100`,
/// caused tx_id divergence).
///
/// Live mainnet history caught:
/// - Block 303967 / tx[1] / output[0]: ergoTree `1000d1ed8501`
///   re-emitted lossily as `1000d1ed01010100` → tx_id divergence
///   → Merkle root mismatch → IBD wedge. Fix: use input bytes.
/// - Block 545684 / tx[1] / output[0]: ergoTree `cd07021a8e6f59fd4a`
///   (version=5 soft-fork, has_size=true). The pre-check
///   rejection blocked the on-chain decode path; `read_ergo_tree`
///   itself handles this fine via `unparsed_soft_fork_tree`. Fix:
///   drop the pre-check in `Preserve` mode; keep it for `Submit`.
pub fn decode_ergo_tree_canonicalize_with_mode(
    hex_str: &str,
    mode: DecodeMode,
) -> Result<(ErgoTree, Vec<u8>), DecodeError> {
    let input = hex::decode(hex_str).map_err(|e| (DESERIALIZE, format!("hex: {e}")))?;
    if input.is_empty() {
        return Err((DESERIALIZE, "empty".to_string()));
    }

    if mode == DecodeMode::Submit {
        let header_version = input[0] & 0x07;
        if header_version > MAX_SUPPORTED_TREE_VERSION {
            return Err((
                NON_CANONICAL,
                format!(
                    "soft-fork ergoTree submission not supported (version {} > {})",
                    header_version, MAX_SUPPORTED_TREE_VERSION
                ),
            ));
        }
    }

    let mut r = VlqReader::new(&input);
    let parsed = read_ergo_tree(&mut r).map_err(|e| (DESERIALIZE, format!("parse: {e}")))?;
    if !r.is_empty() {
        return Err((
            DESERIALIZE,
            format!(
                "trailing bytes after parse ({})",
                input.len() - r.position()
            ),
        ));
    }

    if mode == DecodeMode::Submit {
        // Submit-only: reject placeholder-fallback patterns where
        // re-emit doesn't roundtrip (defense vs malicious wallets).
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &parsed)
            .map_err(|e| (DESERIALIZE, format!("re-serialize: {e}")))?;
        let re_emitted = w.result();

        let is_placeholder_pattern = parsed.constants.is_empty()
            && matches!(
                &parsed.body,
                Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(true),
                }
            );
        if is_placeholder_pattern && re_emitted != input {
            return Err((
                NON_CANONICAL,
                "ergoTree did not roundtrip — likely soft-fork or unparseable body wrapper"
                    .to_string(),
            ));
        }
    }

    Ok((parsed, input))
}

/// Backwards-compat entry point: defaults to `Submit` mode.
/// Callers needing the on-chain-preserve semantics MUST use
/// `decode_ergo_tree_canonicalize_with_mode` with `DecodeMode::Preserve`.
pub fn decode_ergo_tree_canonicalize(hex_str: &str) -> Result<(ErgoTree, Vec<u8>), DecodeError> {
    decode_ergo_tree_canonicalize_with_mode(hex_str, DecodeMode::Submit)
}

// ---- Block-section decoders ----
//
// Reconstruct `ScalaBlockSection` JSON bodies into canonical wire
// bytes that match Scala's emission, so the section_id derived from
// the parent header's transactions_root / extension_root /
// ad_proofs_root verifies against `blake2b256(reconstructed_bytes)`.
// Used by historical-block byte-fidelity diagnostics.

/// Decode a `ScalaHeader` JSON to canonical wire bytes (with PoW).
/// Returns `(bytes, header_id)` so callers that need to dispatch
/// modifiers by id (like `POST /blocks` sendMinedBlock) don't have
/// to recompute the digest.
///
/// Field mapping (Scala JSON → internal `Header`):
/// - `parentId` / `adProofsRoot` / `transactionsRoot` / `extensionHash`
///   → corresponding `Digest32` / `ModifierId` fields
/// - `stateRoot` (33 hex chars = 33 bytes) → `ADDigest`
/// - `votes` (6 hex chars = 3 bytes) → `[u8; 3]`
/// - `unparsedBytes` (hex) → `Vec<u8>`
/// - `nBits` (u64 in JSON, capped at `u32::MAX` per protocol) → `u32`
/// - `powSolutions` → `AutolykosSolution::V1` if `version == 1`,
///   `V2` otherwise. `pk` / `w` are 33-byte SEC1 compressed group
///   elements; `nonce` is 8 bytes; `d` is a BigInt for v1 (Scala
///   emits decimal string) and ignored for v2.
///
/// Scala-emitted `extensionId`, `transactionsId`, `adProofsId`,
/// `size`, `id`, `difficulty` are derived fields the indexer
/// emits and the decoder ignores — they don't appear in the wire
/// header.
pub fn decode_scala_header(h: &ScalaHeader) -> Result<(Vec<u8>, ModifierId), DecodeError> {
    let parent_id_bytes = decode_digest32(&h.parent_id, "header.parentId")?;
    let parent_id = ModifierId::from_bytes(*parent_id_bytes.as_bytes());
    let ad_proofs_root = decode_digest32(&h.ad_proofs_root, "header.adProofsRoot")?;
    let transactions_root = decode_digest32(&h.transactions_root, "header.transactionsRoot")?;
    let extension_root = decode_digest32(&h.extension_hash, "header.extensionHash")?;

    let state_root_raw = hex::decode(&h.state_root)
        .map_err(|e| (DESERIALIZE, format!("header.stateRoot hex: {e}")))?;
    if state_root_raw.len() != 33 {
        return Err((
            DESERIALIZE,
            format!(
                "header.stateRoot length {} != 33 bytes",
                state_root_raw.len()
            ),
        ));
    }
    let mut state_root_arr = [0u8; 33];
    state_root_arr.copy_from_slice(&state_root_raw);
    let state_root = ergo_primitives::digest::ADDigest::from_bytes(state_root_arr);

    let votes_raw =
        hex::decode(&h.votes).map_err(|e| (DESERIALIZE, format!("header.votes hex: {e}")))?;
    if votes_raw.len() != 3 {
        return Err((
            DESERIALIZE,
            format!("header.votes length {} != 3 bytes", votes_raw.len()),
        ));
    }
    let mut votes = [0u8; 3];
    votes.copy_from_slice(&votes_raw);

    let unparsed_bytes = if h.unparsed_bytes.is_empty() {
        Vec::new()
    } else {
        hex::decode(&h.unparsed_bytes)
            .map_err(|e| (DESERIALIZE, format!("header.unparsedBytes hex: {e}")))?
    };

    // `nBits` is `u64` in the JSON DTO (Scala uses Long) but the
    // wire format is u32. Anything above `u32::MAX` would round-
    // trip wrong; reject rather than truncate.
    if h.n_bits > u32::MAX as u64 {
        return Err((
            DESERIALIZE,
            format!(
                "header.nBits {} exceeds u32::MAX — invalid difficulty target",
                h.n_bits
            ),
        ));
    }
    let n_bits = h.n_bits as u32;

    // PoW solution: v1 (Autolykos v1) for header.version == 1,
    // v2 (Autolykos v2) for everything else. Solution layouts
    // are not interchangeable across versions.
    let solution = decode_scala_pow_solution(&h.pow_solutions, h.version)?;

    let header = ergo_ser::header::Header {
        version: h.version,
        parent_id,
        ad_proofs_root,
        transactions_root,
        state_root,
        timestamp: h.timestamp,
        extension_root,
        n_bits,
        height: h.height,
        votes,
        unparsed_bytes,
        solution,
    };

    let (bytes, header_id) = ergo_ser::header::serialize_header(&header)
        .map_err(|e| (DESERIALIZE, format!("header serialize: {e}")))?;
    Ok((bytes, header_id))
}

fn decode_scala_pow_solution(
    pow: &crate::types::ScalaPowSolutions,
    header_version: u8,
) -> Result<ergo_ser::autolykos::AutolykosSolution, DecodeError> {
    use ergo_primitives::group_element::GroupElement;

    let pk_bytes =
        hex::decode(&pow.pk).map_err(|e| (DESERIALIZE, format!("powSolutions.pk hex: {e}")))?;
    if pk_bytes.len() != 33 {
        return Err((
            DESERIALIZE,
            format!("powSolutions.pk length {} != 33 bytes", pk_bytes.len()),
        ));
    }
    let mut pk_arr = [0u8; 33];
    pk_arr.copy_from_slice(&pk_bytes);
    let pk = GroupElement::from_bytes(pk_arr);

    let nonce_bytes =
        hex::decode(&pow.n).map_err(|e| (DESERIALIZE, format!("powSolutions.n hex: {e}")))?;
    if nonce_bytes.len() != 8 {
        return Err((
            DESERIALIZE,
            format!("powSolutions.n length {} != 8 bytes", nonce_bytes.len()),
        ));
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&nonce_bytes);

    if header_version == 1 {
        // v1: also need `w` (33-byte group element) + `d` (BigInt).
        let w_bytes =
            hex::decode(&pow.w).map_err(|e| (DESERIALIZE, format!("powSolutions.w hex: {e}")))?;
        if w_bytes.len() != 33 {
            return Err((
                DESERIALIZE,
                format!("powSolutions.w length {} != 33 bytes", w_bytes.len()),
            ));
        }
        let mut w_arr = [0u8; 33];
        w_arr.copy_from_slice(&w_bytes);
        let w = GroupElement::from_bytes(w_arr);

        // `d` for v1 is a Scala `BigInt`, JSON-encoded as a
        // decimal string. The wire form is signed two's-complement
        // big-endian bytes — the production encoder
        // (`ergo-node::api_bridge::compat::encode_pow_solutions`)
        // round-trips via `BigInt::from_signed_bytes_be(d)`. We
        // mirror that exactly: parse the decimal as signed `BigInt`,
        // then call `to_signed_bytes_be()`. This preserves the
        // leading `0x00` disambiguator that positive values with
        // the high bit set require; an unsigned-magnitude encoding
        // would silently drop that byte.
        let d_str = pow.d.as_str().ok_or((
            DESERIALIZE,
            "powSolutions.d must be a decimal string for v1 header".to_string(),
        ))?;
        let d_big = d_str.parse::<num_bigint::BigInt>().map_err(|_| {
            (
                DESERIALIZE,
                format!("powSolutions.d {d_str:?} is not a valid decimal BigInt"),
            )
        })?;
        let d = d_big.to_signed_bytes_be();

        Ok(ergo_ser::autolykos::AutolykosSolution::V1 { pk, w, nonce, d })
    } else {
        // v2: pk + nonce only. `w` and `d` in the JSON are
        // Scala's encoding artifacts (Scala emits `w = "00…"`
        // and `d = 0` for v2 headers); ignored on the wire.
        Ok(ergo_ser::autolykos::AutolykosSolution::V2 { pk, nonce })
    }
}

/// Decode `ScalaBlockTransactions` JSON to canonical wire bytes.
/// Uses the `block_version` field to emit the correct v1/v2+ wire
/// format per ergo-ser's [`write_block_transactions_with_version`].
/// `DecodeMode::Preserve` accepts soft-fork ergoTree versions and
/// lossy-roundtrip cases — these are already on chain and must be
/// re-ingested verbatim to preserve content-addressed identifiers.
pub fn decode_block_transactions_with_mode(
    bt: &ScalaBlockTransactions,
    mode: DecodeMode,
) -> Result<Vec<u8>, DecodeError> {
    let header_id_bytes = decode_digest32(&bt.header_id, "headerId")?;
    let header_id = ModifierId::from_bytes(*header_id_bytes.as_bytes());
    let mut transactions = Vec::with_capacity(bt.transactions.len());
    for (i, tx_json) in bt.transactions.iter().enumerate() {
        // Build a ScalaTransactionInput from the read-side
        // ScalaTransaction shape (the read shape has extra
        // derived fields like id/size that the input shape
        // ignores — accepted-and-ignored).
        let tx_input = ScalaTransactionInput {
            inputs: tx_json.inputs.clone(),
            data_inputs: tx_json.data_inputs.clone(),
            outputs: tx_json
                .outputs
                .iter()
                .map(|o| ScalaOutputInput {
                    value: o.value,
                    ergo_tree: o.ergo_tree.clone(),
                    assets: o.assets.clone(),
                    creation_height: o.creation_height,
                    additional_registers: o.additional_registers.clone(),
                })
                .collect(),
        };

        // Funnel through the shared builder so the standalone-tx
        // and block-section paths cannot drift on mode propagation.
        let path_prefix = format!("transactions[{i}].");
        let tx = build_transaction_from_input(&tx_input, mode, &path_prefix)?;
        transactions.push(tx);
    }

    let parsed = BlockTransactions {
        header_id,
        transactions,
    };
    let mut w = VlqWriter::new();
    write_block_transactions_with_version(&mut w, &parsed, bt.block_version)
        .map_err(|e| (DESERIALIZE, format!("blockTransactions serialize: {e}")))?;
    Ok(w.result())
}

/// Decode `ScalaExtension` JSON to canonical wire bytes via
/// ergo-ser's [`write_extension`]. The JSON `fields` array is a
/// list of two-element string arrays `[key_hex, value_hex]`; each
/// `key_hex` MUST be exactly 4 chars (2 bytes).
pub fn decode_extension(ext: &ScalaExtension) -> Result<Vec<u8>, DecodeError> {
    let header_id_bytes = decode_digest32(&ext.header_id, "headerId")?;
    let header_id = ModifierId::from_bytes(*header_id_bytes.as_bytes());
    let mut fields = Vec::with_capacity(ext.fields.len());
    for (i, kv) in ext.fields.iter().enumerate() {
        let key_raw = hex::decode(&kv[0])
            .map_err(|e| (DESERIALIZE, format!("extension.fields[{i}].key hex: {e}")))?;
        if key_raw.len() != 2 {
            return Err((
                DESERIALIZE,
                format!(
                    "extension.fields[{i}].key length {} != 2 bytes",
                    key_raw.len()
                ),
            ));
        }
        let mut key = [0u8; 2];
        key.copy_from_slice(&key_raw);
        let value = hex::decode(&kv[1])
            .map_err(|e| (DESERIALIZE, format!("extension.fields[{i}].value hex: {e}")))?;
        fields.push(ExtensionField { key, value });
    }
    let parsed = Extension { header_id, fields };
    let mut w = VlqWriter::new();
    write_extension(&mut w, &parsed)
        .map_err(|e| (DESERIALIZE, format!("extension serialize: {e}")))?;
    Ok(w.result())
}

/// Decoded full-block sections, ready for the apply-pipeline
/// injection on `POST /blocks`. Each `bytes` value is the
/// canonical wire form for that section type (matches what the
/// P2P layer would have produced).
#[derive(Debug, Clone)]
pub struct DecodedFullBlock {
    /// Header bytes (with PoW) — feed to `store_header`.
    pub header_bytes: Vec<u8>,
    /// Header id (`Blake2b256` of the header bytes) — used as
    /// `headerId` key for the section table inserts.
    pub header_id: ModifierId,
    /// Block-transactions section bytes.
    pub block_transactions_bytes: Vec<u8>,
    /// Extension section bytes.
    pub extension_bytes: Vec<u8>,
    /// AD proofs section bytes, when the block carries them
    /// (UTXO-mode blocks always do; digest-mode blocks may not).
    pub ad_proofs_bytes: Option<Vec<u8>>,
}

/// Decode a full `ScalaFullBlock` JSON to canonical wire bytes
/// for each section. The result is sufficient to drive a
/// `POST /blocks` apply: store header + sections, then call
/// the block-processing pipeline.
///
/// `DecodeMode::Submit` (default): rejects soft-fork ergoTree
/// versions and non-canonical inputs — these would never be
/// produced by an honest miner.
///
/// Fails fast: any per-section decode error short-circuits the
/// whole block.
pub fn decode_scala_full_block(b: &ScalaFullBlock) -> Result<DecodedFullBlock, DecodeError> {
    let (header_bytes, header_id) = decode_scala_header(&b.header)?;
    let header_id_hex = hex::encode(header_id.as_bytes());

    // Boundary consistency check: each section carries the
    // header_id it belongs to. Mismatched sections in one
    // ScalaFullBlock body are a sign of a malformed (or
    // adversarial) submission — reject at the JSON boundary
    // rather than letting a mixed block reach the apply path.
    if !eq_ci_hex(&b.block_transactions.header_id, &header_id_hex) {
        return Err((
            DESERIALIZE,
            format!(
                "blockTransactions.headerId {:?} does not match header.id {}",
                b.block_transactions.header_id, header_id_hex
            ),
        ));
    }
    if !eq_ci_hex(&b.extension.header_id, &header_id_hex) {
        return Err((
            DESERIALIZE,
            format!(
                "extension.headerId {:?} does not match header.id {}",
                b.extension.header_id, header_id_hex
            ),
        ));
    }
    if let Some(p) = &b.ad_proofs {
        if !eq_ci_hex(&p.header_id, &header_id_hex) {
            return Err((
                DESERIALIZE,
                format!(
                    "adProofs.headerId {:?} does not match header.id {}",
                    p.header_id, header_id_hex
                ),
            ));
        }
    }

    let block_transactions_bytes =
        decode_block_transactions_with_mode(&b.block_transactions, DecodeMode::Submit)?;
    let extension_bytes = decode_extension(&b.extension)?;
    let ad_proofs_bytes = match &b.ad_proofs {
        Some(p) => Some(decode_ad_proofs(p)?),
        None => None,
    };
    Ok(DecodedFullBlock {
        header_bytes,
        header_id,
        block_transactions_bytes,
        extension_bytes,
        ad_proofs_bytes,
    })
}

/// Case-insensitive hex compare. Scala emits lowercase by
/// convention but accepts uppercase on input; we mirror that.
fn eq_ci_hex(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

/// Decode `ScalaAdProofs` JSON to canonical wire bytes via
/// ergo-ser's [`write_ad_proofs`].
pub fn decode_ad_proofs(p: &ScalaAdProofs) -> Result<Vec<u8>, DecodeError> {
    let header_id_bytes = decode_digest32(&p.header_id, "headerId")?;
    let header_id = ModifierId::from_bytes(*header_id_bytes.as_bytes());
    let proof_bytes = hex::decode(&p.proof_bytes)
        .map_err(|e| (DESERIALIZE, format!("adProofs.proofBytes hex: {e}")))?;
    let parsed = ADProofs {
        header_id,
        proof_bytes,
    };
    let mut w = VlqWriter::new();
    write_ad_proofs(&mut w, &parsed);
    Ok(w.result())
}
