//! The registry of consensus decode surfaces and the per-surface invariant
//! checks.
//!
//! Two invariant shapes, both oracle-free (no JVM needed):
//!
//! * **read+write fixed point** — for surfaces with a serializer: decode, then
//!   `decode(encode(decode(x)))` must succeed and reach a byte-stable fixed
//!   point. This catches (a) emitting bytes we cannot read back, (b)
//!   non-canonical/echo-trap re-encoding, and (c) structural drift.
//! * **read-only no-panic** — for read-only surfaces: a decode must terminate
//!   with `Ok`/`Err`, never panic. The runner's `catch_unwind` turns a panic
//!   into a [`Outcome::Bug`].

use crate::avl_frame::{AvlFrame, AvlOp};
use crate::Outcome;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::WriteError;

/// A check over raw input bytes (decode + invariant verification).
pub type RunFn = Box<dyn Fn(&[u8]) -> Outcome>;

/// One named check over raw input bytes.
pub struct Surface {
    pub name: &'static str,
    pub run: RunFn,
}

/// read+write fixed-point check shared by every (decode, encode) pair.
///
/// `is_soft_fork_opaque` marks values whose body is a size-delimited
/// `UnparsedErgoTree`. For those, Bug #19 structural body advance after a
/// canonical re-encode of following VLQ fields can desynchronize re-decode
/// — Scala shares that hazard, so difftest reports [`Outcome::WriteRejected`]
/// rather than [`Outcome::Bug`].
fn rw_check<T, D, E, F>(input: &[u8], decode: D, encode: E, is_soft_fork_opaque: F) -> Outcome
where
    T: PartialEq + std::fmt::Debug,
    D: Fn(&mut VlqReader) -> Result<T, ReadError>,
    E: Fn(&mut VlqWriter, &T) -> Result<(), WriteError>,
    F: Fn(&T) -> bool,
{
    let mut r1 = VlqReader::new(input);
    let v1 = match decode(&mut r1) {
        Ok(v) => v,
        Err(_) => return Outcome::Rejected, // rejecting malformed input is correct
    };

    // Re-encode the parsed value. An intentional WriteError (e.g. a name/count
    // that overflows the single-byte wire field, or non-self-delimiting
    // UnparsedErgoTree propositionBytes) is allowed — not a Rust-only Bug.
    let mut w1 = VlqWriter::new();
    if encode(&mut w1, &v1).is_err() {
        return Outcome::WriteRejected;
    }
    let b1 = w1.result();

    // We must be able to read back our own output.
    let mut r2 = VlqReader::new(&b1);
    let v2 = match decode(&mut r2) {
        Ok(v) => v,
        Err(e) => {
            // The `MAX_TYPE_DEPTH` (=100) guard is a stack-overflow safeguard, NOT
            // a consensus boundary: Scala's `TypeSerializer` imposes no type-depth
            // limit (only the 4096-byte proposition cap), so the node deliberately
            // rejects 101..4096-deep *type descriptors* Scala accepts (documented,
            // not fixed — see ergo-ser sigma_type.rs MAX_TYPE_DEPTH). A
            // re-decode that trips ONLY that conservative cap is that documented
            // divergence firing on a near-boundary re-encoding, not a codec
            // inconsistency — so it is not a Bug. NOTE: this excludes the *type*
            // guard only; the value/expression tree-depth guard (Scala MaxTreeDepth
            // = 110) IS a real consensus limit and still counts as a Bug.
            let msg = format!("{e:?}");
            if msg.contains("type recursion depth") {
                return Outcome::WriteRejected;
            }
            // Bug #19 (known-bug-catalog): size-delimited soft-fork wrap +
            // canonical rewrite of subsequent VLQ fields can flip wrap→structural
            // on re-parse and desync the stream. Scala shares the hazard; the
            // consensus writers still emit verbatim Unparsed bytes for id-parity.
            if is_soft_fork_opaque(&v1) {
                return Outcome::WriteRejected;
            }
            return Outcome::bug(format!("re-decode of own output failed: {msg}"), &b1);
        }
    };

    // ...and re-encoding it must reach a byte fixed point.
    let mut w2 = VlqWriter::new();
    if let Err(e) = encode(&mut w2, &v2) {
        return Outcome::bug(format!("re-encode of own output failed: {e:?}"), &b1);
    }
    let b2 = w2.result();
    if b1 != b2 {
        return Outcome::bug("serialize is not a fixed point (b1 != b2)".into(), input);
    }
    if v1 != v2 {
        return Outcome::bug("structure changed across re-encode".into(), input);
    }
    Outcome::Accepted
}

fn tree_is_unparsed(tree: &ergo_ser::ergo_tree::ErgoTree) -> bool {
    matches!(tree.body, ergo_ser::opcode::Expr::Unparsed(_))
}

fn box_candidate_is_unparsed(c: &ergo_ser::ergo_box::ErgoBoxCandidate) -> bool {
    tree_is_unparsed(c.ergo_tree())
}

fn box_is_unparsed(b: &ergo_ser::ergo_box::ErgoBox) -> bool {
    box_candidate_is_unparsed(&b.candidate)
}

fn tx_has_unparsed(tx: &ergo_ser::transaction::Transaction) -> bool {
    tx.output_candidates.iter().any(box_candidate_is_unparsed)
}

fn unsigned_tx_has_unparsed(tx: &ergo_ser::transaction::UnsignedTransaction) -> bool {
    tx.output_candidates.iter().any(box_candidate_is_unparsed)
}

fn block_txs_have_unparsed(bt: &ergo_ser::block_transactions::BlockTransactions) -> bool {
    bt.transactions.iter().any(tx_has_unparsed)
}

macro_rules! rw {
    ($name:literal, $decode:path, $encode:path) => {
        Surface {
            name: $name,
            run: Box::new(|b| rw_check(b, $decode, $encode, |_| false)),
        }
    };
    ($name:literal, $decode:path, $encode:path, soft_fork = $pred:expr) => {
        Surface {
            name: $name,
            run: Box::new(|b| rw_check(b, $decode, $encode, $pred)),
        }
    };
}

/// Names of all phase-1 surfaces (for validating a `--surface` argument).
pub fn names() -> Vec<&'static str> {
    registry(None).into_iter().map(|s| s.name).collect()
}

/// Build the surface registry. Optionally filter to a single surface by name.
pub fn registry(only: Option<&str>) -> Vec<Surface> {
    use ergo_ser::{
        ad_proofs, autolykos, batch_merkle_proof, block_transactions, difficulty, ergo_box,
        ergo_tree, extension, header, input, popow_header, popow_proof, register, sigma_type,
        sigma_value, token, transaction,
    };

    let all: Vec<Surface> = vec![
        // ----- read + write fixed point -----
        rw!("sigma_type", sigma_type::read_type, sigma_type::write_type),
        rw!("constant", sigma_value::read_constant, write_constant_pair),
        rw!(
            "ergo_tree",
            ergo_tree::read_ergo_tree,
            ergo_tree::write_ergo_tree,
            soft_fork = tree_is_unparsed
        ),
        // Eval-rich ErgoTree bodies (the `sigma_expr` generator) are ErgoTree
        // wire bytes, so hermetically they run the SAME read/write fixed-point
        // invariant as `ergo_tree`. The consensus-complete differential for them
        // is the JVM `reduce` oracle surface; this hermetic entry just proves the
        // generator emits no-panic, byte-stable trees.
        rw!(
            "sigma_expr",
            ergo_tree::read_ergo_tree,
            ergo_tree::write_ergo_tree,
            soft_fork = tree_is_unparsed
        ),
        rw!(
            "ergo_box_candidate",
            ergo_box::read_ergo_box_candidate,
            ergo_box::write_ergo_box_candidate,
            soft_fork = box_candidate_is_unparsed
        ),
        rw!(
            "ergo_box",
            ergo_box::read_ergo_box,
            ergo_box::write_ergo_box,
            soft_fork = box_is_unparsed
        ),
        rw!(
            "transaction",
            transaction::read_transaction,
            transaction::write_transaction,
            soft_fork = tx_has_unparsed
        ),
        rw!(
            "unsigned_transaction",
            transaction::read_unsigned_transaction,
            transaction::write_unsigned_transaction,
            soft_fork = unsigned_tx_has_unparsed
        ),
        // Block / header sections.
        rw!("header", header::read_header, header::write_header),
        rw!(
            "block_transactions",
            block_transactions::read_block_transactions,
            block_transactions::write_block_transactions,
            soft_fork = block_txs_have_unparsed
        ),
        rw!(
            "extension",
            extension::read_extension,
            extension::write_extension
        ),
        rw!(
            "popow_header",
            popow_header::read_popow_header,
            popow_header::write_popow_header
        ),
        rw!(
            "nipopow_proof",
            popow_proof::read_nipopow_proof,
            popow_proof::write_nipopow_proof
        ),
        // Input / proof / register sub-structures.
        rw!("input", input::read_input, input::write_input),
        rw!(
            "unsigned_input",
            input::read_unsigned_input,
            input::write_unsigned_input
        ),
        rw!(
            "context_extension",
            input::read_context_extension,
            input::write_context_extension
        ),
        rw!(
            "spending_proof",
            input::read_spending_proof,
            input::write_spending_proof
        ),
        rw!(
            "register",
            register::read_registers,
            register::write_registers
        ),
        // Adapter surfaces: the writer returns `()` (infallible) or the
        // reader takes a version, so they don't fit the `rw!` path macro.
        Surface {
            name: "ad_proofs",
            run: Box::new(|b| {
                rw_check(
                    b,
                    ad_proofs::read_ad_proofs,
                    |w, v| {
                        ad_proofs::write_ad_proofs(w, v);
                        Ok(())
                    },
                    |_| false,
                )
            }),
        },
        Surface {
            name: "token",
            run: Box::new(|b| {
                rw_check(
                    b,
                    token::read_token,
                    |w, v| {
                        token::write_token(w, v);
                        Ok(())
                    },
                    |_| false,
                )
            }),
        },
        Surface {
            name: "nbits_difficulty",
            run: Box::new(|b| {
                rw_check(
                    b,
                    difficulty::read_nbits,
                    |w, v| {
                        difficulty::write_nbits(w, *v);
                        Ok(())
                    },
                    |_| false,
                )
            }),
        },
        Surface {
            name: "autolykos_v1",
            run: Box::new(|b| {
                rw_check(
                    b,
                    |r| autolykos::read_solution(r, 1),
                    autolykos::write_solution,
                    |_| false,
                )
            }),
        },
        Surface {
            name: "autolykos_v2",
            run: Box::new(|b| {
                rw_check(
                    b,
                    |r| autolykos::read_solution(r, 2),
                    autolykos::write_solution,
                    |_| false,
                )
            }),
        },
        // ----- `ctx_expr`: contextExtension · ergoBoxCandidate frame -----
        // The wire form behind the `reduce_ctx` oracle surface. Both halves are
        // self-delimiting, so one reader consumes them in sequence; hermetically
        // the pair must reach the same read/write fixed point the two codecs
        // reach individually. A frame whose extension parses but whose box does
        // not (or vice versa) is a plain Rejected, not a Bug.
        Surface {
            name: "ctx_expr",
            run: Box::new(|b| {
                rw_check(
                    b,
                    |r| {
                        let ext = ergo_ser::input::read_context_extension(r)?;
                        let candidate = ergo_ser::ergo_box::read_ergo_box_candidate(r)?;
                        Ok((ext, candidate))
                    },
                    |w, (ext, candidate)| {
                        ergo_ser::input::write_context_extension(w, ext)?;
                        ergo_ser::ergo_box::write_ergo_box_candidate(w, candidate)
                    },
                    |(_, candidate)| box_candidate_is_unparsed(candidate),
                )
            }),
        },
        // ----- read-only no-panic -----
        // `deserialize_batch_merkle_proof` takes the whole byte slice (and a
        // `WriteError`-typed result), so it can't go through `ro_check`/`rw!`;
        // a panic on malformed bytes is caught by the runner and reported.
        Surface {
            name: "batch_merkle_proof",
            run: Box::new(
                |b| match batch_merkle_proof::deserialize_batch_merkle_proof(b) {
                    Ok(_) => Outcome::Accepted,
                    Err(_) => Outcome::Rejected,
                },
            ),
        },
        // ----- `validate`: stateless transaction structural check -----
        // Hermetic check: parse the transaction bytes and run the stateless
        // structural rules (Scala `ErgoTransaction.statelessValidity`).
        // No UTXO set or chain state needed. Accepted / rejected only; no
        // write fixed-point (the surface has no independent canonical form).
        Surface {
            name: "validate",
            run: Box::new(|b| {
                use ergo_validation::tx::structural::validate_structural;
                let mut r = VlqReader::new(b);
                let tx = match ergo_ser::transaction::read_transaction(&mut r) {
                    Ok(t) => t,
                    Err(_) => return Outcome::Rejected,
                };
                let params = ergo_validation::context::ProtocolParams::mainnet_default();
                match validate_structural(&tx, &params) {
                    Ok(()) => Outcome::Accepted,
                    Err(_) => Outcome::Rejected,
                }
            }),
        },
        // ----- `verify_avl`: AVL+ batch-proof verification -----
        //
        // Hermetic check that exercises the `AvlVerifier` panic guard:
        //   CLEAN HEAD  — `AvlVerifier::guarded` catches an op-time panic from
        //                 the upstream crate and returns `Err(())` → `Rejected`.
        //   PATCHED HEAD — the guard is removed; the panic escapes the surface
        //                 run fn; `run_one`'s `catch_unwind` catches it →
        //                 `Outcome::Bug("PANIC: …")`.
        //
        // This surface is the canonical re-injection detection channel for
        // a regression of that guard.
        Surface {
            name: "verify_avl",
            run: Box::new(|b| {
                let frame = match AvlFrame::decode(b) {
                    Ok(f) => f,
                    Err(_) => return Outcome::Rejected,
                };
                let mut verifier = match ergo_sigma::avl::AvlVerifier::new(
                    &frame.starting_digest,
                    &frame.proof,
                    frame.key_len as usize,
                    frame.value_len_opt.map(|n| n as usize),
                    None,
                    None,
                ) {
                    Ok(v) => v,
                    Err(_) => return Outcome::Rejected,
                };
                for op in &frame.ops {
                    let r = match op {
                        AvlOp::Lookup { key } => verifier.lookup(key).map(|_| ()),
                        AvlOp::Insert { key, value } => verifier.insert(key, value).map(|_| ()),
                        AvlOp::Update { key, value } => verifier.update(key, value).map(|_| ()),
                        AvlOp::Remove { key } => verifier.remove(key),
                    };
                    if r.is_err() {
                        return Outcome::Rejected;
                    }
                }
                match verifier.digest() {
                    Some(_) => Outcome::Accepted,
                    None => Outcome::Rejected,
                }
            }),
        },
    ];

    match only {
        Some(name) => all.into_iter().filter(|s| s.name == name).collect(),
        None => all,
    }
}

/// Adapter so `read_constant`'s `(SigmaType, SigmaValue)` tuple fits the
/// `encode(&mut w, &T)` shape used by [`rw_check`].
fn write_constant_pair(
    w: &mut VlqWriter,
    pair: &(
        ergo_ser::sigma_type::SigmaType,
        ergo_ser::sigma_value::SigmaValue,
    ),
) -> Result<(), WriteError> {
    ergo_ser::sigma_value::write_constant(w, &pair.0, &pair.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    // A trivial codec: decode one byte; the encoders below vary so we can test
    // that rw_check distinguishes a fixed point from a non-fixed point.
    fn decode_u8(r: &mut VlqReader) -> Result<u8, ReadError> {
        r.get_u8()
    }
    fn encode_identity(w: &mut VlqWriter, v: &u8) -> Result<(), WriteError> {
        w.put_u8(*v);
        Ok(())
    }
    fn encode_drifting(w: &mut VlqWriter, v: &u8) -> Result<(), WriteError> {
        // re-encodes to a different byte every round -> never a fixed point
        w.put_u8(v.wrapping_add(1));
        Ok(())
    }

    // ----- teeth: rw_check must catch a non-fixed-point codec -----

    #[test]
    fn rw_check_flags_non_fixed_point() {
        assert!(matches!(
            rw_check(&[5], decode_u8, encode_drifting, |_| false),
            Outcome::Bug(_)
        ));
    }

    // ----- and must NOT false-positive on a real fixed point -----

    #[test]
    fn rw_check_accepts_fixed_point() {
        assert_eq!(
            rw_check(&[5], decode_u8, encode_identity, |_| false),
            Outcome::Accepted
        );
    }

    #[test]
    fn rw_check_rejects_empty_without_bug() {
        assert_eq!(
            rw_check(&[], decode_u8, encode_identity, |_| false),
            Outcome::Rejected
        );
    }

    #[test]
    fn rw_check_soft_fork_opaque_redecode_is_write_rejected() {
        fn decode_ok(r: &mut VlqReader) -> Result<u8, ReadError> {
            r.get_u8()
        }
        fn encode_empty(_w: &mut VlqWriter, _v: &u8) -> Result<(), WriteError> {
            Ok(()) // emits nothing → re-decode UnexpectedEnd
        }
        assert_eq!(
            rw_check(&[5], decode_ok, encode_empty, |_| true),
            Outcome::WriteRejected
        );
        assert!(matches!(
            rw_check(&[5], decode_ok, encode_empty, |_| false),
            Outcome::Bug(_)
        ));
    }
}
