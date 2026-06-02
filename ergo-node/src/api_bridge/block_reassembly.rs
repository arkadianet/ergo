//! Block-section reassembly for the Scala-compat API.
//!
//! Loads canonical-chain bytes (`Header`, `BlockTransactions`,
//! `Extension`, `AdProofs`) from `ChainStoreReader`, parses them via the
//! sibling `compat` parsers, and encodes them into the Scala-shaped DTOs
//! the API surface emits. Also builds the `getProofForTx` Merkle
//! membership proof, including a runtime self-check against the
//! header's `transactions_root` so a builder/verifier drift can never
//! ship a malformed proof.
//!
//! Extracted from `api_bridge.rs` per the public-readiness audit (item
//! 5: assemble_full_block + Merkle proof construction at lines
//! 619-1289). All callers are inside the `NodeChainQuery` impl on
//! `ScalaCompatBridge`; this module is a `pub(super)` helper surface.

use tracing::{error, warn};

use ergo_api::compat::types::{
    ScalaBlockSection, ScalaBlockTransactions, ScalaFullBlock, ScalaHeader, ScalaMerkleProof,
};
use ergo_ser::modifier_id::{
    ExpectedSections, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION, TYPE_HEADER,
};
use ergo_state::reader::ChainStoreReader;

use super::compat::{
    encode_ad_proofs, encode_block_transactions, encode_extension, encode_header,
    parse_block_transactions, parse_extension, parse_header,
};
use super::error::BridgeError;

/// Load and encode every canonical-chain header in `[lo, hi]` (ascending).
/// Heights with no chain entry, missing header bytes, or parse failures
/// are silently skipped — this matches Scala's `chainSlice`/`lastHeaders`,
/// which `flatMap` through `headerIdsAtHeight(_).headOption.flatMap(typedModifierById)`
/// and drop misses rather than 500-ing the whole call.
pub(super) fn load_headers_in_range(
    reader: &ChainStoreReader,
    lo: u32,
    hi: u32,
) -> Vec<ScalaHeader> {
    let entries = match reader.scan_header_chain_range(lo, hi) {
        Ok(e) => e,
        Err(e) => {
            warn!(handler = "scan_header_chain_range", lo, hi, error = %e, "scala-compat handler failed");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(entries.len());
    for (_, header_id) in entries {
        match load_and_encode_header(reader, &header_id) {
            Ok(Some(h)) => out.push(h),
            Ok(None) => {} // race: chain index advanced past header bytes — skip
            Err(e) => {
                warn!(handler = "load_and_encode_header", header_id = %hex::encode(header_id), error = %e, "scala-compat handler failed");
            }
        }
    }
    out
}

pub(super) fn load_and_encode_header(
    reader: &ChainStoreReader,
    header_id: &[u8; 32],
) -> Result<Option<ScalaHeader>, BridgeError> {
    let Some(header_bytes) = reader.get_header(header_id)? else {
        return Ok(None);
    };
    let header = parse_header(&header_bytes)?;
    let header_id_hex = hex::encode(header_id);
    let expected = ExpectedSections::from_header(
        header_id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    Ok(Some(encode_header(
        &header,
        header_bytes.len() as u32,
        &expected,
        &header_id_hex,
    )))
}

pub(super) fn load_and_encode_block_transactions(
    reader: &ChainStoreReader,
    header_id: &[u8; 32],
) -> Result<Option<ScalaBlockTransactions>, BridgeError> {
    let Some(header_bytes) = reader.get_header(header_id)? else {
        return Ok(None);
    };
    let header = parse_header(&header_bytes)?;
    let header_id_hex = hex::encode(header_id);
    let expected = ExpectedSections::from_header(
        header_id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    let Some(bt_bytes) = reader.get_block_section(&expected.transactions_id)? else {
        return Ok(None);
    };
    let bt = parse_block_transactions(&bt_bytes)?;
    Ok(Some(encode_block_transactions(
        &bt,
        &header_id_hex,
        bt_bytes.len() as u32,
        &header,
    )?))
}

/// Reassemble a `/blocks/{id}` response from the store. Returns `Ok(None)`
/// when the header is not found or any required section (blockTransactions,
/// extension) is missing — Scala emits a 404 in that case. AdProofs is
/// optional: missing → `adProofs: null`. Other errors propagate so the
/// handler can log them; the trait method translates them to None.
pub(super) fn assemble_full_block(
    reader: &ChainStoreReader,
    header_id: &[u8; 32],
) -> Result<Option<ScalaFullBlock>, BridgeError> {
    let Some(header_bytes) = reader.get_header(header_id)? else {
        return Ok(None);
    };
    let header = parse_header(&header_bytes)?;
    let header_id_hex = hex::encode(header_id);

    let expected = ExpectedSections::from_header(
        header_id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );

    let Some(bt_bytes) = reader.get_block_section(&expected.transactions_id)? else {
        return Ok(None);
    };
    let Some(ext_bytes) = reader.get_block_section(&expected.extension_id)? else {
        return Ok(None);
    };
    let ad_proofs_bytes = reader.get_block_section(&expected.ad_proofs_id)?;

    let bt = parse_block_transactions(&bt_bytes)?;
    let ext = parse_extension(&ext_bytes)?;

    let scala_header = encode_header(
        &header,
        header_bytes.len() as u32,
        &expected,
        &header_id_hex,
    );
    let scala_bt = encode_block_transactions(&bt, &header_id_hex, bt_bytes.len() as u32, &header)?;
    let scala_ext = encode_extension(&ext, &header_id_hex, header.extension_root.as_bytes());
    let scala_ad_proofs = match ad_proofs_bytes.as_deref() {
        Some(bytes) => Some(encode_ad_proofs(bytes, &header_id_hex, &header)?),
        None => None,
    };

    let total_size = header_bytes.len() as u32
        + bt_bytes.len() as u32
        + ad_proofs_bytes.as_ref().map_or(0, |b| b.len() as u32);

    Ok(Some(ScalaFullBlock {
        header: scala_header,
        block_transactions: scala_bt,
        extension: scala_ext,
        ad_proofs: scala_ad_proofs,
        size: total_size,
    }))
}

/// Resolve a modifier id (header or block section) and encode to its
/// Scala-shaped DTO. Routes via `MODIFIER_TYPE_INDEX` populated at write
/// time for new data, with a `HEADERS`-direct fallback that covers
/// the index-cold case (data dirs that predate `store_header` tagging
/// the index, or that committed the `STATE_META` backfill sentinel
/// before the header-tagging arm was added to back-fill). Section
/// dispatch requires both the type byte AND the parent header id,
/// so section misses on `MODIFIER_TYPE_INDEX` remain unrecoverable
/// without an expensive per-section body parse — matches Scala's
/// 404 on the equivalent case.
///
/// Returns `Ok(None)` on a clean miss (id unknown / no parent header /
/// section bytes pruned). Errors propagate so the trait wrapper can log.
pub(super) fn load_and_encode_modifier_by_id(
    reader: &ChainStoreReader,
    id: &[u8; 32],
) -> Result<Option<ScalaBlockSection>, BridgeError> {
    let type_byte = match reader.get_modifier_type(id)? {
        Some(b) => b,
        None => {
            // MODIFIER_TYPE_INDEX miss. Fall back to a direct
            // HEADERS lookup before giving up — `store_header` tags
            // 101 going forward, but a node whose data dir
            // predates the tagging (or whose back-fill sentinel
            // committed before the header-tagging arm was added)
            // can have headers in `HEADERS` without a matching
            // index entry. Scala 6.0.3RC1 returns 200 here
            // (parity probe 2026-05-19 on mainnet + testnet); the
            // fallback closes that gap regardless of index state.
            //
            // BLOCK_SECTIONS isn't probed by the fallback because
            // section dispatch needs the parent header_id (the
            // first 32 bytes of the section payload) AND the
            // section type to encode — the type byte is what the
            // index provides. A section without an index entry is
            // genuinely unrecoverable without a costly per-section
            // body parse, and Scala returns 404 for that case too,
            // so the fallback only covers headers.
            return Ok(load_and_encode_header(reader, id)?
                .map(|header| ScalaBlockSection::Header(Box::new(header))));
        }
    };

    match type_byte {
        TYPE_HEADER => {
            // Same encoder as `header_by_id`, called via the parent header path.
            Ok(load_and_encode_header(reader, id)?
                .map(|header| ScalaBlockSection::Header(Box::new(header))))
        }
        TYPE_BLOCK_TRANSACTIONS | TYPE_AD_PROOFS | TYPE_EXTENSION => {
            let Some(section_bytes) = reader.get_block_section(id)? else {
                return Ok(None);
            };
            // All three section serializers begin with a 32-byte
            // `headerId` field (BlockTransactionsSerializer.scala:165,
            // ADProofsSerializer.scala:108, ExtensionSerializer.scala:25).
            // Peek it without re-parsing to find the parent header.
            if section_bytes.len() < 32 {
                return Ok(None);
            }
            let mut parent_id = [0u8; 32];
            parent_id.copy_from_slice(&section_bytes[..32]);

            let Some(header_bytes) = reader.get_header(&parent_id)? else {
                // Section without reachable parent — orphan or pruned.
                return Ok(None);
            };
            let header = parse_header(&header_bytes)?;
            let header_id_hex = hex::encode(parent_id);

            match type_byte {
                TYPE_BLOCK_TRANSACTIONS => {
                    let bt = parse_block_transactions(&section_bytes)?;
                    let scala_bt = encode_block_transactions(
                        &bt,
                        &header_id_hex,
                        section_bytes.len() as u32,
                        &header,
                    )?;
                    Ok(Some(ScalaBlockSection::BlockTransactions(scala_bt)))
                }
                TYPE_EXTENSION => {
                    let ext = parse_extension(&section_bytes)?;
                    let scala_ext =
                        encode_extension(&ext, &header_id_hex, header.extension_root.as_bytes());
                    Ok(Some(ScalaBlockSection::Extension(scala_ext)))
                }
                TYPE_AD_PROOFS => {
                    let scala_ap = encode_ad_proofs(&section_bytes, &header_id_hex, &header)?;
                    Ok(Some(ScalaBlockSection::AdProofs(scala_ap)))
                }
                _ => unreachable!(),
            }
        }
        // Unknown type byte — should not happen given write-time tagging
        // and back-fill, but a foreign value would land here.
        _ => Ok(None),
    }
}

/// Build a Merkle membership proof for `tx_id` in the block whose
/// header is `header_id`. Mirrors Scala `getProofForTx`
/// (`BlocksApiRoute.scala:78-91`) and the proof shape per
/// `BlockTransactions.scala:76-79`.
///
/// Returns `Ok(None)` when:
/// - header unknown,
/// - block_transactions section missing,
/// - tx_id not present in the block.
///
/// For v2+ blocks, the tree is built over `txIds ++ witnessIds`; the
/// proof index is the tx's position in `txIds` (NOT shifted), per
/// scrypto `proofByIndex` walking the actual tree
/// (`MerkleTree.scala:22-40`).
pub(super) fn build_proof_for_tx(
    reader: &ChainStoreReader,
    header_id: &[u8; 32],
    tx_id: &[u8; 32],
) -> Result<Option<ScalaMerkleProof>, BridgeError> {
    let Some(header_bytes) = reader.get_header(header_id)? else {
        return Ok(None);
    };
    let header = parse_header(&header_bytes)?;

    let expected = ExpectedSections::from_header(
        header_id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    let Some(bt_bytes) = reader.get_block_section(&expected.transactions_id)? else {
        return Ok(None);
    };
    let bt = parse_block_transactions(&bt_bytes)?;

    // Compute tx_ids; find target index. Match Scala's
    // `proofByElement` semantics (`MerkleTree.scala:18-19` →
    // `elementsHashIndex.get`) which returns the FIRST matching leaf.
    let mut tx_id_bytes: Vec<[u8; 32]> = Vec::with_capacity(bt.transactions.len());
    let mut target_index: Option<usize> = None;
    for (i, tx) in bt.transactions.iter().enumerate() {
        let bts =
            ergo_ser::transaction::bytes_to_sign(tx).map_err(|source| BridgeError::Encode {
                what: "bytes_to_sign",
                source,
            })?;
        let id = *ergo_primitives::digest::blake2b256(&bts).as_bytes();
        if id == *tx_id && target_index.is_none() {
            target_index = Some(i);
        }
        tx_id_bytes.push(id);
    }
    let target_index = match target_index {
        Some(i) => i,
        None => return Ok(None),
    };

    // Build leaf array. v1: txIds. v2+: txIds ++ witnessIds. Witness id
    // recipe matches the validator's path (`ergo-validation/block.rs:395-411`):
    // blake2b256(concat(spending_proofs)).drop(1) → 31 bytes.
    let mut witness_id_bytes: Vec<Vec<u8>> = Vec::new();
    if header.version >= 2 {
        witness_id_bytes.reserve(bt.transactions.len());
        for tx in bt.transactions.iter() {
            let mut all_proofs = Vec::new();
            for input in &tx.inputs {
                all_proofs.extend_from_slice(&input.spending_proof.proof);
            }
            let h = ergo_crypto::autolykos::common::blake2b256(&all_proofs);
            witness_id_bytes.push(h[1..].to_vec());
        }
    }

    let mut leaves: Vec<&[u8]> = tx_id_bytes.iter().map(|b| b.as_slice()).collect();
    if header.version >= 2 {
        for w in &witness_id_bytes {
            leaves.push(w.as_slice());
        }
    }

    let proof = match ergo_crypto::merkle::merkle_proof_by_index(&leaves, target_index) {
        Some(p) => p,
        None => return Ok(None),
    };

    // Runtime self-check: verify the proof against the header's
    // `transactions_root` BEFORE returning. The proof builder is an
    // independent code path from `merkle_tree_root` (the root used by
    // block validation), so this catches any drift between the two
    // and prevents shipping a malformed proof to SPV consumers. If
    // the check fails, surface as a clean `Ok(None)` (handler 404)
    // and log loudly — never return a proof that would not verify.
    let expected_root = *header.transactions_root.as_bytes();
    if !ergo_crypto::merkle::merkle_proof_verify(&proof, &expected_root) {
        error!(
            handler = "proof_for_tx",
            header_id = %hex::encode(header_id),
            tx_id = %hex::encode(tx_id),
            "scala-compat self-check failed: proof builder/root computation drift; refusing to serve"
        );
        return Ok(None);
    }

    Ok(Some(ScalaMerkleProof {
        leaf_data: hex::encode(&proof.leaf_data),
        levels: proof
            .levels
            .into_iter()
            .map(|(sibling, side)| (hex::encode(sibling), side))
            .collect(),
    }))
}
