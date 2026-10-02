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

#[path = "surfaces_parity.rs"]
mod parity;
use parity::ParityNormalize;

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

/// Scala SigmaConstants.MaxTreeDepth is 110, also enforced by ergo-ser's
/// private opcode::types::MAX_EXPR_DEPTH. Each strip round removes a level.
const MAX_UPCAST_STRIP_ROUNDS: usize = 110;

/// Mainnet's activated script version (protocol 6.0).
const CURRENT_ACTIVATED_VERSION: u8 = 3;

fn is_boolean_depth_limit_error(error: &ReadError) -> bool {
    match error {
        ReadError::DepthLimitExceeded { max: 110 } => true,
        // ergo-ser/src/block_transactions.rs:237-238 wraps transaction read
        // errors as InvalidData(format!("tx[{tx_idx}]: {e}")). Match exactly
        // that wrapper with a canonical usize index and this depth error.
        ReadError::InvalidData(message) => {
            let Some((index, inner)) = message
                .strip_prefix("tx[")
                .and_then(|rest| rest.split_once("]: "))
            else {
                return false;
            };
            index
                .parse::<usize>()
                .is_ok_and(|parsed| parsed.to_string() == index)
                && inner == ReadError::DepthLimitExceeded { max: 110 }.to_string()
        }
        _ => false,
    }
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
    T: PartialEq + std::fmt::Debug + ParityNormalize,
    D: Fn(&mut VlqReader) -> Result<T, ReadError>,
    E: Fn(&mut VlqWriter, &T) -> Result<(), WriteError>,
    F: Fn(&T) -> bool,
{
    // Parse under mainnet's activated script version, as the JVM fixtures
    // are captured. The default context is pre-JIT, where a future-version
    // nested tree is wrapped rather than parsed; that is not today's rule.
    let mut r1 = VlqReader::new(input).with_activated_script_version(CURRENT_ACTIVATED_VERSION);
    r1.enable_header_spans();
    let v1 = match decode(&mut r1) {
        Ok(v) => v,
        Err(_) => return Outcome::Rejected, // rejecting malformed input is correct
    };
    if !parity::header_ids_match_wire(&v1, &r1) {
        return Outcome::bug(
            "header id does not have an unambiguous retained-wire hash".into(),
            input,
        );
    }

    // Re-encode the parsed value. An intentional WriteError (e.g. a name/count
    // that overflows the single-byte wire field, or non-self-delimiting
    // UnparsedErgoTree propositionBytes) is allowed — not a Rust-only Bug.
    let mut w1 = VlqWriter::new();
    if encode(&mut w1, &v1).is_err() {
        return Outcome::WriteRejected;
    }
    let b1 = w1.result();

    // We must be able to read back our own output.
    let mut r2 = VlqReader::new(&b1).with_activated_script_version(CURRENT_ACTIVATED_VERSION);
    r2.enable_header_spans();
    let v2 = match decode(&mut r2) {
        Ok(v) => v,
        Err(e) => {
            // Scala writes TrueLeaf/FalseLeaf as Boolean constants. At the
            // last expression level their added data-value read exceeds 110.
            // Exempt only this AST shape and the matching depth failure.
            if is_boolean_depth_limit_error(&e) && v1.has_depth_expanding_boolean() {
                return Outcome::WriteRejected;
            }
            // Scala also expands compact type descriptors (e.g. 0x18 into
            // two 0x0c bytes). An accepted tree or box candidate can consequently
            // serialize past MaxPropositionSize and fail rule 1014 on re-read.
            // Restrict this to a tree that grew from within its size window;
            // other validation errors and surfaces remain Bugs.
            if matches!(e, ReadError::SigmaValidation { rule_id: 1014, .. })
                && v1
                    .wire_position_limit()
                    .is_some_and(|limit| r1.position() <= limit && b1.len() > limit)
            {
                return Outcome::WriteRejected;
            }
            // A nested box's tree can read past the box's own bytes before a
            // validation failure rewinds the reader, so its verdict depends on
            // what follows the box: a dropped suffix, or a later field the
            // writer re-encodes canonically. Scala shares this: for the fuzz
            // inputs pinned below, sigma-state 6.0.2 re-serializes to exactly
            // our bytes and then rejects them. Exempt it only when every
            // retained box reappears verbatim in the output and the output is
            // not the input itself; a corrupted box, or the same bytes failing
            // twice, still report a Bug.
            let boxes = v1.retained_boxes();
            if !boxes.is_empty()
                && b1 != input
                && boxes
                    .iter()
                    .all(|bx| !bx.is_empty() && b1.windows(bx.len()).any(|w| w == *bx))
            {
                return Outcome::WriteRejected;
            }
            // Pre-v3, both writers strip `Upcast(Const)` to the bare constant,
            // so an operand keeps its pre-cast type on re-read and can fail a
            // type check the cast satisfied (a collection item's type, a
            // comparison's operand types). sigma-state 6.0.2 re-serializes such
            // an input to our exact bytes and rejects them. Only a hard type
            // rejection is exempt; truncation or misframing is still a Bug.
            if v1.has_pending_upcast_strip() && matches!(e, ReadError::HardReject(_)) {
                return Outcome::WriteRejected;
            }
            let msg = format!("{e:?}");
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

    if !parity::header_ids_match_wire(&v2, &r2) {
        return Outcome::bug(
            "re-decoded header id does not match retained wire".into(),
            &b1,
        );
    }
    if v1.parity_normalized(true) != v2.parity_normalized(false) {
        // A sized tree catches the same size expansion as a rule-1014 wrap
        // instead of returning an error. Require exact retained output bytes.
        if v1
            .wire_position_limit()
            .is_some_and(|limit| r1.position() <= limit && b1.len() > limit)
            && v2.is_position_limit_wrap(&b1)
        {
            return Outcome::WriteRejected;
        }
        // Bug #19 can also re-decode successfully: the rewritten bytes after a
        // size-delimited wrap become its lookahead and now parse structurally.
        // Scala re-serializes these inputs identically, so only that
        // wrap→structural flip is exempt.
        if is_soft_fork_opaque(&v1) && !is_soft_fork_opaque(&v2) {
            return Outcome::WriteRejected;
        }
        return Outcome::bug("structure changed across re-encode".into(), input);
    }

    // Follow Scala's one-level-per-pass Upcast stripping to a byte fixed point.
    let mut bytes = b1;
    let mut value = &v2;
    let mut owned_value;
    let mut rounds = 0;
    loop {
        let mut writer = VlqWriter::new();
        if let Err(e) = encode(&mut writer, value) {
            return Outcome::bug(format!("re-encode of own output failed: {e:?}"), &bytes);
        }
        let next_bytes = writer.result();
        if next_bytes == bytes {
            // A ByIndex byte/short index is stripped and reinserted as the
            // same Int cast. Byte stability is valid when the expected AST
            // round trip is also stable; other pending strips must progress.
            if value.has_pending_upcast_strip()
                && value.parity_normalized(true) != value.parity_normalized(false)
            {
                return Outcome::bug("pending Upcast strip did not change bytes".into(), &bytes);
            }
            break;
        }
        if !value.has_pending_upcast_strip() {
            return Outcome::bug("serialize is not a fixed point (b1 != b2)".into(), input);
        }
        rounds += 1;
        if rounds > MAX_UPCAST_STRIP_ROUNDS {
            return Outcome::bug("Upcast strip did not converge".into(), input);
        }
        let mut next_reader =
            VlqReader::new(&next_bytes).with_activated_script_version(CURRENT_ACTIVATED_VERSION);
        next_reader.enable_header_spans();
        let next = match decode(&mut next_reader) {
            Ok(next) => next,
            // A later strip pass can expose the same type failure as the
            // first (see the pending-strip case above): sigma-state 6.0.2
            // writes each pass identically and rejects the same pass.
            Err(ReadError::HardReject(_)) => return Outcome::WriteRejected,
            Err(e) => {
                return Outcome::bug(
                    format!("re-decode of own output failed: {e:?}"),
                    &next_bytes,
                );
            }
        };
        if !parity::header_ids_match_wire(&next, &next_reader) {
            return Outcome::bug(
                "re-decoded header id does not match retained wire".into(),
                &next_bytes,
            );
        }
        if value.parity_normalized(true) != next.parity_normalized(false) {
            return Outcome::bug("structure changed across re-encode".into(), input);
        }
        bytes = next_bytes;
        owned_value = next;
        value = &owned_value;
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

/// `read_ergo_tree` is deliberately lenient; the consensus box-script readers
/// apply these gates after it (`ergo_ser::ergo_tree::gates`). A standalone tree
/// surface must apply them too, or it fuzzes trees no consensus path accepts
/// (a sizeless or above-activation version) against a reference that rejects
/// them.
fn read_ergo_tree_gated(r: &mut VlqReader) -> Result<ergo_ser::ergo_tree::ErgoTree, ReadError> {
    use ergo_ser::ergo_tree as t;
    let tree = t::read_ergo_tree(r)?;
    t::check_tree_version_supported(
        &tree,
        r.activated_script_version()
            .unwrap_or(t::DEFAULT_ACTIVATED_SCRIPT_VERSION),
    )?;
    t::check_header_size_bit(&tree)?;
    t::check_resolvable_methods(&tree)?;
    t::check_sigma_prop_root(&tree)?;
    Ok(tree)
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
            read_ergo_tree_gated,
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
            read_ergo_tree_gated,
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
        Surface {
            name: "verify",
            run: Box::new(|b| {
                let (verdict, _) = crate::oracle::verify_verdict(b);
                match verdict {
                    crate::oracle::Verdict::Accept(record)
                        if serde_json::from_str::<serde_json::Value>(&record)
                            .is_ok_and(|r| r["verdict"] == "Accept") =>
                    {
                        Outcome::Accepted
                    }
                    _ => Outcome::Rejected,
                }
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

    const ERGO_TREE_CRASH: &str = "1014040004000e208c27dd9d8a35aac1e3167d58858c0a8b4059b277da790552e37eba22df9b903504000400040204020101040205a0c21e040204080500040c040204a0c21e0402050a05c8010402d806d601b2a5731014040004000e208c27dd9d8a35aac1e3167d58858c0a8b4059b277da790552e37eba22df9b903504007e0400040204020101";
    const SIGMA_EXPR_CRASH: &str = "1014040004000e208c27dd9d8a35aac1e3167d58858c0a8b4059b277da790552e37eba22df9b903504000400040204020101040205a0c21e040204080500040c040204a0c21e0402050a05c8010402d806d601b2a5730000d602b5db6501fed9010263ed93e4c67202050ec5a7938cb2db63087202730100017302d603b17202d604e4c6b272027303000605d605d90105049590720573047204e4c6b272029972057305000605d606b07202860273067307d901063c400163d803d6088c720601d6098c720801d60a8c72060286029a72097308ededed8c72080293c2b2a5720900d0cde4c6720a040792c1b2a5720900730992da720501997209730ae4c6720a0605ea02d1ededededededed93cbc27201e4c6a7060e927203730b93db63000e087201db6308a793e4c6720104059db07202730cd9010741639a8c720701e47e05c672068c020772030593e4c6722105049ae4c6a70504730d92c1720199c1a77e9c9a7203730e730f058c72060292da720501998c72060173109972049d9c720473117312b2ad7202d9010763cde4c672070407e4c6b2a5731300040400";
    const CONSTANT_CRASH: &str = "68ffffffffffffff000000000000000000000000000000000c0000000000000000000000000000454501000000aeaeae000000000000000000000000000000000000000000000000aeaeaeffffffffffffffffffffffffffffffffffffffffff490c312300000017000000000000000000000000ffffffffffffffaeaeae000000000000000000000000000000000000000c0000000000000000000000000000454501000000000000000000000000aeaeae000000000000000000000000000000000000000000000000aeaeaeffffffffffffffffffffffffffff";
    const ERGO_BOX_CANDIDATE_CRASH: &str = "0108018c81000108ff07000000ffff0075ff041000004c04ff00fbffffff2aff000000000000000000000000000000000000000000000000000000000000000000000000005b0000000000000000000000000000000000000000000000000000ff0001041000004c";

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

    // Synthetic codecs reach a byte fixed point while changing structure.
    // Thus these tests exercise structural comparison, not just b1 != b2.
    fn structural_outcome<T: Clone + PartialEq + std::fmt::Debug + ParityNormalize>(
        before: T,
        after: T,
    ) -> Outcome {
        rw_check(
            &[0],
            |r| {
                Ok(if r.get_u8()? == 0 {
                    before.clone()
                } else {
                    after.clone()
                })
            },
            |w, _| {
                w.put_u8(1);
                Ok(())
            },
            |_| false,
        )
    }

    fn cast_tree(version: u8, opcode: u8) -> ergo_ser::ergo_tree::ErgoTree {
        use ergo_ser::{
            opcode::{Expr, IrNode, Payload},
            sigma_type::SigmaType,
            sigma_value::SigmaValue,
        };
        ergo_ser::ergo_tree::ErgoTree {
            version,
            has_size: true,
            constant_segregation: false,
            reserved_header_bits: 0,
            constants: vec![],
            body: Expr::Op(IrNode {
                opcode,
                payload: Payload::NumericCast {
                    input: Box::new(Expr::Const {
                        tpe: SigmaType::SInt,
                        val: SigmaValue::Int(1),
                    }),
                    tpe: SigmaType::SLong,
                },
            }),
        }
    }

    fn strip_cast(tree: &ergo_ser::ergo_tree::ErgoTree) -> ergo_ser::ergo_tree::ErgoTree {
        let mut after = tree.clone();
        if let ergo_ser::opcode::Expr::Op(ergo_ser::opcode::IrNode {
            payload: ergo_ser::opcode::Payload::NumericCast { input, .. },
            ..
        }) = &tree.body
        {
            after.body = *input.clone();
        } else {
            panic!("expected cast");
        }
        after
    }

    fn cast_chain(version: u8, opcode: u8, levels: usize) -> ergo_ser::ergo_tree::ErgoTree {
        let mut tree = cast_tree(version, opcode);
        for _ in 1..levels {
            let mut outer = cast_tree(version, opcode);
            let ergo_ser::opcode::Expr::Op(ergo_ser::opcode::IrNode {
                payload: ergo_ser::opcode::Payload::NumericCast { input, .. },
                ..
            }) = &mut outer.body
            else {
                unreachable!()
            };
            **input = tree.body;
            tree = outer;
        }
        tree
    }

    // Every encode changes the byte, independently of the synthetic AST. The
    // decode count makes both accidental early acceptance and endless loops fail.
    fn drifting_tree_outcome(
        tree_at: impl Fn(usize) -> ergo_ser::ergo_tree::ErgoTree,
    ) -> (Outcome, usize) {
        let encodes = std::cell::Cell::new(0usize);
        let decodes = std::cell::Cell::new(0usize);
        let outcome = rw_check(
            &[0],
            |_| {
                let round = decodes.get();
                decodes.set(round + 1);
                assert!(round <= MAX_UPCAST_STRIP_ROUNDS + 1);
                Ok(tree_at(round))
            },
            |w, _| {
                let round = encodes.get() + 1;
                encodes.set(round);
                assert!(round <= MAX_UPCAST_STRIP_ROUNDS + 2);
                w.put_u8(round as u8);
                Ok(())
            },
            |_| false,
        );
        (outcome, encodes.get())
    }

    // ----- round-trips -----

    #[test]
    fn rw_check_byte_drift_bug() {
        assert!(matches!(
            rw_check(&[5], decode_u8, encode_drifting, |_| false),
            Outcome::Bug(_)
        ));
    }

    // ----- happy path -----

    #[test]
    fn rw_check_fixed_point_accepted() {
        assert_eq!(
            rw_check(&[5], decode_u8, encode_identity, |_| false),
            Outcome::Accepted
        );
    }

    // ----- error paths -----

    #[test]
    fn rw_check_empty_rejected() {
        assert_eq!(
            rw_check(&[], decode_u8, encode_identity, |_| false),
            Outcome::Rejected
        );
    }

    #[test]
    fn rw_check_opaque_redecode_failure_write_rejected() {
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

    /// The Bug #19 reshape can also re-decode successfully: the canonical
    /// rewrite hands the size-delimited body new lookahead bytes, and the
    /// soft-fork wrap becomes a structural parse. Only that wrap→structural
    /// flip is exempt; a change that keeps or gains opacity is still a Bug.
    #[test]
    fn rw_check_opaque_to_structural_flip_write_rejected() {
        fn decode(r: &mut VlqReader) -> Result<u8, ReadError> {
            r.get_u8()
        }
        fn encode_next(w: &mut VlqWriter, v: &u8) -> Result<(), WriteError> {
            w.put_u8(v + 1);
            Ok(())
        }
        assert_eq!(
            rw_check(&[5], decode, encode_next, |v| *v == 5),
            Outcome::WriteRejected
        );
        for opaque in [|_: &u8| true, |_: &u8| false, |v: &u8| *v == 6] {
            assert!(matches!(
                rw_check(&[5], decode, encode_next, opaque),
                Outcome::Bug(_)
            ));
        }
    }

    /// Nightly 2026-09-29 (main `bd9c1172`): a v3 sized tree declares a
    /// 0-byte body, and its lookahead into an overlong creation height wraps
    /// as rule 1002. sigma-state 6.0.2 accepts the input (43 bytes, tree
    /// `Unparsed(eb00)`) and re-serializes it to the same bytes we write.
    #[test]
    fn nightly_20260929_box_candidate_reshape_write_rejected() {
        let bytes = hex::decode(
            "00eb00e4daff81000100000000000000002e01000006b7b72e000000000000000001fd261000000000000000f0f0",
        )
        .unwrap();
        assert_eq!(
            (registry(Some("ergo_box_candidate"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
    }

    /// Local fuzz find (2026-09-29): a constant type written with compact
    /// `Coll[Coll[T]]` codes stays under the type-depth guard, but the
    /// canonical re-encode (one `Coll` byte per level, as Scala writes it)
    /// did not, flipping the sized tree to an opaque wrap on re-decode. The
    /// guard now charges both levels, so both reads wrap alike.
    #[test]
    fn compact_nested_coll_type_depth_is_stable_across_reencode() {
        let bytes = hex::decode(
            "2800d1c6ff181818181818181850505050505050505050505050505050505050505050505050505050505050505050505050505050505050501818181818181818181818181818181818181818181818181c01000004000000000fff",
        )
        .unwrap();
        assert_eq!(
            (registry(Some("sigma_expr"))[0].run)(&bytes),
            Outcome::Accepted
        );
    }

    /// Local cargo-fuzz finds (2026-09-29). Each hides a nested tree whose
    /// verdict depends on lookahead past a retained box, so a canonical
    /// rewrite after the box flipped the re-decode. sigma-state 6.0.2 rejects
    /// all three at activated version 3: the constant for a tree version above
    /// activation, the two trees for rule 1012 (a sizeless version above 0).
    #[test]
    fn local_fuzz_20260929_rejected_under_consensus_context() {
        for (surface, hex) in [
            ("constant", "4d4d4d4d4f4d6300f83c4d4d4d6300f83c3c0e0e0e0e0e0e0e0e0e0e0e5454571f4d4d4d4d4d6300f84d4d4d630e0e4d00000e2500000e0e0e000045450100d40000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000f94d4d4d4d4d4d4d4d4d4d4d4dff"),
            ("ergo_tree", "4463f7049b6d7e68686868686868686868030193a3686868686868686868686868686868680000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006868686868686868686868686868686868686868686868686868686868686868686868680303030303030303030303030303030303001000000303030303030303030303030303030303030000006868686868ab48484848333333333333330348484848484800ffffffffffffff4900000000000031f81798ea02d192a39a8cc7a701730073761001020402d19683030193a38cc7a5738303016868686868686868686868686868686868686868686868686868686868686803030393a358a57300000007fffffffd2e070200000000b2a57383030193a38cc7b2a573000705040004000e36104204a00b08cd0279be66ce28d959f2815b101010101010101010101010101010101003036810"),
            ("sigma_expr", "474949494949494949494963494949494949494949494949494949494949494949494949634949494949494949634949494949494949494949490d0d720e01000000000000000000000100000500000000000000fc0000000000000000000000e1e1e1e1e1e1e1010504010303030ed60f95720d0b730000000000001000000000000000000000007208d70b10b25e8472"),
        ] {
            let bytes = hex::decode(hex).unwrap();
            assert_eq!(
                (registry(Some(surface))[0].run)(&bytes),
                Outcome::Rejected,
                "{surface}"
            );
        }
    }

    /// Local fuzz find (2026-09-29): a context-extension box whose nested
    /// tree reads past the box into a later entry the writer re-encodes.
    /// sigma-state 6.0.2 accepted the input (723 bytes) and re-serialized it
    /// to exactly our 432 bytes, which it rejected. One of its extension ids
    /// is negative as a signed byte (-39), and sigma-state 6.0.5+ rejects
    /// that at parse: 6.0.6 answers `REJECT SerializerException` on both the
    /// `transaction` and `validate` surfaces.
    #[test]
    fn retained_box_lookahead_in_transaction_is_rejected() {
        let bytes = hex::decode(
            "01b69575e11c1d1d1d1d1d1d2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2fee0d6245a1168396b2e2a4f384691f275d501c00000054000000594a5959595959595959595959d95959595963595959595959595959595959595959595959595959595959596359595959595959595959595959595959635959595959595959595959595959595959595959595959595963595959595959595959595959595959595905050505050505050505050505050505058505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505640505050505050505050505050505050505050505050505050303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505640505050505050505050505050505050505ffff05050505050303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030305050505050505050505050505050505050505050505640505050505050505050505050505050505ffff05050505050303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0303030303030303030303030303030303030559595959d959595959635959599ed889ddd8899d0059590110595959595959595959595959595959592fee0d6245a1168396b2e2a4f384691f275d500000005400001c00594a5959595959595959595959d959595959635959590505050505050505050505050505055959595959595963595959595959595959595959595959",
        )
        .unwrap();
        assert_eq!(
            (registry(Some("transaction"))[0].run)(&bytes),
            Outcome::Rejected
        );
    }

    /// CI fuzz find (run 36561954936): a pre-v3 `Upcast(Const)` item in a
    /// `ConcreteCollection`. Both writers strip the cast, leaving a constant of
    /// the item's pre-cast type, which the per-item assertion then rejects.
    /// sigma-state 6.0.2 accepts the input, re-serializes it to exactly our
    /// 166 bytes, and rejects those.
    #[test]
    fn pre_v3_upcast_strip_breaking_reparse_is_write_rejected() {
        let bytes = hex::decode(
            "00d1999999999999999999999999990f270000d9999999990001999999060606de0604020400040004060404080404000002040204040500050005020100d808d6ffffa4d602c2a7d603c606060606060606060606060606060606060606090000000000008006060606060606060606060606d17e7e93027e05030283020606060000008006067e020606060606060606060606060606060606060606060606060606060606060606060606060b0606060606060606ad06060606060600d1937e7e0206060606060606060606060606e6060606060606060606060606060606060606060606060606069a066a00999900990099999999999906999999",
        )
        .unwrap();
        assert_eq!(
            (registry(Some("ergo_tree"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
    }

    /// CI fuzz finds (run 36563327031): pre-v3 `ByIndex` index chains
    /// `Upcast(Upcast(Long, Long), Short)`. Pass by pass, sigma-state 6.0.2
    /// writes exactly our bytes, and after two strips both reject the bare
    /// `Long` index.
    #[test]
    fn later_strip_pass_type_failure_is_write_rejected() {
        for (surface, hex) in [
            ("sigma_expr", "00d1ffffffb2a57e7e050405035555105555550d55160eefefedffffefffffef000404b2a57e7e050405035555105555550d55160e201a6a72160000e4b1cc"),
            ("ergo_tree", "00d1a2a2a2a2a2a2a2a2b20d0da2a27e7e05030402feff03310203030d0d0d0d0d0d05030402fe030402feffffff01c7"),
        ] {
            let bytes = hex::decode(hex).unwrap();
            assert_eq!(
                (registry(Some(surface))[0].run)(&bytes),
                Outcome::WriteRejected,
                "{surface}"
            );
        }
    }

    #[test]
    fn rw_check_both_opaque_byte_drift_bug() {
        assert!(matches!(
            rw_check(&[5], decode_u8, encode_drifting, |_| true),
            Outcome::Bug(_)
        ));
    }

    #[test]
    fn rw_check_downcast_strip_bug() {
        let before = cast_tree(0, 0x7d);
        let after = strip_cast(&before);
        assert!(matches!(structural_outcome(before, after), Outcome::Bug(_)));
    }

    #[test]
    fn rw_check_v3_upcast_strip_bug() {
        for version in 3..=7 {
            let before = cast_tree(version, 0x7e);
            let after = strip_cast(&before);
            assert!(matches!(structural_outcome(before, after), Outcome::Bug(_)));
        }
    }

    #[test]
    fn rw_check_header_fields_drift_bug() {
        let bytes = hex::decode(CONSTANT_CRASH).unwrap();
        let before = ergo_ser::sigma_value::read_constant(&mut VlqReader::new(&bytes)).unwrap();
        let mut after = before.clone();
        let ergo_ser::sigma_value::SigmaValue::Header(header, _) = &mut after.1 else {
            panic!("expected header");
        };
        header.timestamp += 1;
        assert!(matches!(structural_outcome(before, after), Outcome::Bug(_)));
    }

    #[test]
    fn rw_check_nonconstant_upcast_strip_bug() {
        use ergo_ser::opcode::{Expr, IrNode, Payload};
        let mut before = cast_tree(0, 0x7e);
        let Expr::Op(IrNode {
            payload: Payload::NumericCast { input, .. },
            ..
        }) = &mut before.body
        else {
            unreachable!()
        };
        **input = Expr::Op(IrNode {
            opcode: 0xa3,
            payload: Payload::Zero,
        });
        let after = strip_cast(&before);
        assert!(matches!(structural_outcome(before, after), Outcome::Bug(_)));
    }

    #[test]
    fn rw_check_constant_value_drift_bug() {
        use ergo_ser::{sigma_type::SigmaType, sigma_value::SigmaValue};
        assert!(matches!(
            structural_outcome(
                (SigmaType::SInt, SigmaValue::Int(1)),
                (SigmaType::SInt, SigmaValue::Int(2))
            ),
            Outcome::Bug(_)
        ));
    }

    #[test]
    fn rw_check_no_pending_strip_byte_drift_bug() {
        let tree = strip_cast(&cast_tree(0, 0x7e));
        let (outcome, encodes) = drifting_tree_outcome(|_| tree.clone());
        assert!(matches!(outcome, Outcome::Bug(detail) if detail.contains("b1 != b2")));
        assert_eq!(encodes, 2);
    }

    #[test]
    fn rw_check_v3_chain_byte_drift_bug() {
        let (outcome, encodes) = drifting_tree_outcome(|_| cast_chain(3, 0x7e, 3));
        assert!(matches!(outcome, Outcome::Bug(detail) if detail.contains("b1 != b2")));
        assert_eq!(encodes, 2);
    }

    #[test]
    fn rw_check_pending_strip_value_drift_bug() {
        let (outcome, encodes) = drifting_tree_outcome(|round| {
            let tree = cast_chain(0, 0x7e, 2);
            if round == 0 {
                return tree;
            }
            if round == 1 {
                return cast_chain(0, 0x7e, 1);
            }
            let mut next = strip_cast(&strip_cast(&tree));
            let ergo_ser::opcode::Expr::Const { val, .. } = &mut next.body else {
                unreachable!()
            };
            *val = ergo_ser::sigma_value::SigmaValue::Int(2);
            next
        });
        assert!(matches!(outcome, Outcome::Bug(detail) if detail.contains("structure changed")));
        assert_eq!(encodes, 2);
    }

    #[test]
    fn rw_check_pending_strip_without_progress_bug() {
        let (outcome, encodes) = drifting_tree_outcome(|_| cast_chain(0, 0x7e, 2));
        assert!(matches!(outcome, Outcome::Bug(detail) if detail.contains("structure changed")));
        assert_eq!(encodes, 1);
    }

    #[test]
    fn rw_check_downcast_chain_strip_bug() {
        // A synthetic writer removes one level each pass, even for Downcast.
        let outcome = rw_check(
            &[3],
            |r| Ok(cast_chain(0, 0x7d, usize::from(r.get_u8()?))),
            |w, tree| {
                let mut levels = 0;
                let mut expr = &tree.body;
                while let ergo_ser::opcode::Expr::Op(ergo_ser::opcode::IrNode {
                    payload: ergo_ser::opcode::Payload::NumericCast { input, .. },
                    ..
                }) = expr
                {
                    levels += 1;
                    expr = input;
                }
                w.put_u8(levels - 1);
                Ok(())
            },
            |_| false,
        );
        assert!(matches!(outcome, Outcome::Bug(_)));
    }

    // ----- normalization -----

    #[test]
    fn rw_check_premature_chain_collapse_and_surviving_target_drift_are_bugs() {
        use ergo_ser::opcode::{Expr, IrNode, Payload};
        let before = cast_chain(0, 0x7e, 3);
        let collapsed = strip_cast(&cast_tree(0, 0x7e));
        assert!(matches!(
            structural_outcome(before.clone(), collapsed),
            Outcome::Bug(_)
        ));
        let mut after = cast_chain(0, 0x7e, 2);
        let Expr::Op(IrNode {
            payload: Payload::NumericCast { tpe, .. },
            ..
        }) = &mut after.body
        else {
            unreachable!()
        };
        *tpe = ergo_ser::sigma_type::SigmaType::SInt;
        assert!(matches!(structural_outcome(before, after), Outcome::Bug(_)));
    }

    #[test]
    fn rw_check_opaque_exclusion_preserves_unrelated_fields() {
        use ergo_ser::opcode::{Expr, UnparsedErgoTree};
        let mut before = cast_tree(0, 0x7e);
        before.body = Expr::Unparsed(UnparsedErgoTree {
            bytes: vec![8, 1, 0xff],
            validation_error: Some((1001, vec![])),
        });
        let mut after = before.clone();
        let Expr::Unparsed(opaque) = &mut after.body else {
            unreachable!()
        };
        opaque.validation_error = Some((1016, vec![0xff]));
        assert_eq!(
            structural_outcome(before.clone(), after.clone()),
            Outcome::Accepted
        );
        // Both aggregate values contain an opaque tree, but the integer drifts.
        let outcome = rw_check(
            &[0],
            |r| {
                Ok(if r.get_u8()? == 0 {
                    (1u8, before.clone())
                } else {
                    (2u8, after.clone())
                })
            },
            |w, _| {
                w.put_u8(1);
                Ok(())
            },
            |_| true,
        );
        assert!(matches!(outcome, Outcome::Bug(_)));
        // A successful opaque-to-structural transition is compared too.
        assert!(matches!(
            structural_outcome(before, cast_tree(0, 0x7e)),
            Outcome::Bug(_)
        ));
    }

    #[test]
    fn rw_check_header_hash_is_verified_before_normalization() {
        let bytes = hex::decode(CONSTANT_CRASH).unwrap();
        let outcome = rw_check(
            &bytes,
            |r| {
                let (tpe, mut value) = ergo_ser::sigma_value::read_constant(r)?;
                let ergo_ser::sigma_value::SigmaValue::Header(_, id) = &mut value else {
                    unreachable!()
                };
                *id = [42; 32];
                Ok((tpe, value))
            },
            |w, (tpe, value)| ergo_ser::sigma_value::write_constant(w, tpe, value),
            |_| false,
        );
        assert!(matches!(outcome, Outcome::Bug(detail) if detail.contains("header id")));
    }

    #[test]
    fn header_wire_observations_cross_sized_tree_readers() {
        let header = hex::decode(CONSTANT_CRASH).unwrap();
        let mut body = vec![1]; // segregated constant count
        body.extend_from_slice(&header);
        body.extend_from_slice(&[8, 0xd3]);
        let mut bytes = vec![0x1b]; // v3, sized, segregated
        ergo_primitives::vlq::encode_vlq_into(body.len() as u64, &mut bytes);
        bytes.extend_from_slice(&body);
        assert_eq!(
            (registry(Some("ergo_tree"))[0].run)(&bytes),
            Outcome::Accepted
        );
    }

    #[test]
    fn invalid_casts_and_tuple_projections_cannot_be_normalized_away() {
        for bytes in [
            "00d17e010104",
            "00d17d010104",
            "00d17e040208",
            "00d18c010108",
        ] {
            for surface in ["ergo_tree", "sigma_expr"] {
                assert_eq!(
                    (registry(Some(surface))[0].run)(&hex::decode(bytes).unwrap()),
                    Outcome::Rejected
                );
            }
        }
    }

    #[test]
    fn normalizer_pre_v3_constant_chains_strip_one_level() {
        for version in 0..3 {
            for levels in [2, 3] {
                let tree = cast_chain(version, 0x7e, levels);
                assert!(tree.has_pending_upcast_strip());
                assert_eq!(
                    parity::normalized_tree(&tree, true),
                    cast_chain(version, 0x7e, levels - 1)
                );
            }
        }
    }

    #[test]
    fn normalizer_nonconstant_downcast_v3_chains_unchanged() {
        use ergo_ser::opcode::{Expr, IrNode, Payload};
        let mut height = cast_chain(0, 0x7e, 2);
        let mut expr = &mut height.body;
        while let Expr::Op(IrNode {
            payload: Payload::NumericCast { input, .. },
            ..
        }) = expr
        {
            expr = input;
        }
        *expr = Expr::Op(IrNode {
            opcode: 0xa3,
            payload: Payload::Zero,
        });
        for tree in [height, cast_chain(0, 0x7d, 3), cast_chain(3, 0x7e, 3)] {
            assert!(!tree.has_pending_upcast_strip());
            // Compare the normalized tree directly against the raw tree,
            // avoiding normalization of both sides that could hide a rewrite.
            assert_eq!(parity::normalized_tree(&tree, true), tree);
        }
    }

    #[test]
    fn normalizer_unparsed_body_unchanged() {
        let mut tree = cast_tree(0, 0x7e);
        tree.body = ergo_ser::opcode::Expr::Unparsed(vec![0x7e, 0x02, 5, 3].into());
        assert!(!tree.has_pending_upcast_strip());
        assert_eq!(parity::normalized_tree(&tree, true), tree);
    }

    // ----- oracle parity -----

    #[test]
    fn byindex_implicit_casts_match_jvm_serialization() {
        // sigma-state 6.0.2, VersionContext(3, 3): the tree's own version
        // controls stripping. These expected bytes were captured from Scala.
        for (input, canonical) in [
            ("00d1b2850100020000", "00d1b2850100020000"),
            ("00d1b2850100030000", "00d1b2850100030000"),
            ("00d1b28501007e03000400", "00d1b2850100030000"),
            ("00d1b28501007e7e0200030400", "00d1b28501007e02000400"),
            ("0b08d1b2850100050000", "0b08d1b2850100050000"),
        ] {
            let bytes = hex::decode(input).unwrap();
            let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
            let mut writer = VlqWriter::new();
            ergo_ser::ergo_tree::write_ergo_tree(&mut writer, &tree).unwrap();
            assert_eq!(hex::encode(writer.result()), canonical);
            for surface in ["ergo_tree", "sigma_expr"] {
                assert_eq!((registry(Some(surface))[0].run)(&bytes), Outcome::Accepted);
            }
        }
    }

    /// The retained box `[1]` must reappear verbatim, and the output must not
    /// be the input itself (identical bytes cannot change a lookahead).
    #[test]
    fn retained_box_exception_requires_verbatim_boxes() {
        use ergo_ser::sigma_value::SigmaValue;
        for (input, output, expected_bug) in [
            (&[1, 2][..], &[1][..], false),
            (&[1, 2, 3][..], &[1, 9][..], false),
            (&[1, 2][..], &[3][..], true),
            (&[1, 2][..], &[][..], true),
            (&[1][..], &[1][..], true),
        ] {
            let calls = std::cell::Cell::new(0);
            let outcome = rw_check(
                input,
                |reader| {
                    calls.set(calls.get() + 1);
                    reader.get_u8()?;
                    if calls.get() > 1 {
                        return Err(ReadError::InvalidData("injected re-decode failure".into()));
                    }
                    Ok(SigmaValue::OpaqueBoxBytes(vec![1]))
                },
                |writer, _| {
                    writer.put_bytes(output);
                    Ok(())
                },
                |_| false,
            );
            assert_eq!(
                matches!(outcome, Outcome::Bug(_)),
                expected_bug,
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn nightly_20260929_crash_outcomes() {
        for line in
            include_str!("../../test-vectors/scala/sigma/fuzz_parity_validation.tsv").lines()
        {
            if !line.starts_with("nightly_20260929_") {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            assert!(fields.len() > 4, "malformed fixture row: {line}");
            let surface = fields[0].strip_prefix("nightly_20260929_").unwrap();
            let bytes = hex::decode(fields[4]).unwrap();
            let expected = if surface == "constant" {
                Outcome::WriteRejected
            } else {
                Outcome::Rejected
            };
            assert_eq!(
                (registry(Some(surface))[0].run)(&bytes),
                expected,
                "{surface}"
            );
        }
    }

    #[test]
    fn fuzz_seed_decoding_matches_captured_jvm_verdicts() {
        for line in
            include_str!("../../test-vectors/scala/sigma/fuzz_parity_validation.tsv").lines()
        {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            let bytes = hex::decode(fields[4]).unwrap();
            let mut r =
                VlqReader::new(&bytes).with_activated_script_version(CURRENT_ACTIVATED_VERSION);
            let result = match fields[1] {
                "tree" => ergo_ser::ergo_tree::read_ergo_tree(&mut r).map(|_| ()),
                "constant" => ergo_ser::sigma_value::read_constant(&mut r).map(|_| ()),
                "candidate" => ergo_ser::ergo_box::read_ergo_box_candidate(&mut r).map(|_| ()),
                "tx" => ergo_ser::transaction::read_transaction(&mut r).map(|_| ()),
                surface => panic!("unknown surface {surface}"),
            };
            assert_eq!(
                result.is_ok(),
                fields[2] == "ACCEPT",
                "{}: {result:?}",
                fields[0]
            );
            if result.is_ok() {
                assert_eq!(
                    r.position(),
                    fields[3].parse::<usize>().unwrap(),
                    "{}",
                    fields[0]
                );
            }
        }
    }

    /// Scala ValueSerializer.scala:154-166 and 359-370 remove one Upcast level
    /// per pass. Scala's fixed point accepts this two-level chain on both surfaces.
    #[test]
    fn tree_surfaces_two_level_upcast_chain_accepted() {
        for surface in ["ergo_tree", "sigma_expr"] {
            let bytes = hex::decode("00d17e7e02050304").unwrap();
            assert_eq!((registry(Some(surface))[0].run)(&bytes), Outcome::Accepted);
        }
    }

    /// Scala ValueSerializer.scala:154-166 and 359-370 likewise require several
    /// passes for Byte -> Short -> Int -> Long; Scala predicts acceptance.
    #[test]
    fn tree_surfaces_three_level_upcast_chain_accepted() {
        let bytes = hex::decode("00d17e7e7e0205030405").unwrap();
        let mut reader = VlqReader::new(&bytes);
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut reader).unwrap();
        assert!(!tree_is_unparsed(&tree));
        assert!(tree.has_pending_upcast_strip());
        for surface in ["ergo_tree", "sigma_expr"] {
            assert_eq!((registry(Some(surface))[0].run)(&bytes), Outcome::Accepted);
        }
    }

    /// JVM 6.0.2 rejects a constant in the BlockValue item list (ClassCastException).
    #[test]
    fn ergo_tree_invalid_block_item_crash_rejected() {
        let bytes = hex::decode(ERGO_TREE_CRASH).unwrap();
        assert_eq!(
            (registry(Some("ergo_tree"))[0].run)(&bytes),
            Outcome::Rejected
        );
    }

    /// JVM 6.0.2 rejects the unknown SBox method in this sizeless tree.
    #[test]
    fn sigma_expr_unknown_method_crash_rejected() {
        let bytes = hex::decode(SIGMA_EXPR_CRASH).unwrap();
        assert_eq!(
            (registry(Some("sigma_expr"))[0].run)(&bytes),
            Outcome::Rejected
        );
    }

    /// Scala org/ergoplatform/ErgoHeader.scala:132-140,167-180 hashes the retained
    /// input slice, so canonicalizing a zero-prefix identity pk changes only its id.
    #[test]
    fn constant_header_id_crash_accepted() {
        let bytes = hex::decode(CONSTANT_CRASH).unwrap();
        assert_eq!(
            (registry(Some("constant"))[0].run)(&bytes),
            Outcome::Accepted
        );
    }

    /// Scala sigma/serialization/ErgoTreeSerializer.scala:179 computes
    /// `treeSize = r.position - startPos`, allowing reads past declared size (#19).
    #[test]
    fn ergo_box_candidate_softfork_flip_crash_write_rejected() {
        let bytes = hex::decode(ERGO_BOX_CANDIDATE_CRASH).unwrap();
        assert_eq!(
            (registry(Some("ergo_box_candidate"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
    }

    /// sigma-state 6.0.6 rejects this nightly input: CreateAvlTree's SAvlTree
    /// result fails rule 1001 in the sizeless box script.
    #[test]
    fn nightly_box_candidate_avl_root_rejected() {
        let bytes = include_bytes!("../fuzz/corpus/ergo_box_candidate/nightly-2026-09-30-avl-root");
        assert_eq!(
            (registry(Some("ergo_box_candidate"))[0].run)(bytes),
            Outcome::Rejected
        );

        // The same fixed result must reject a standalone sizeless tree and
        // degrade a size-delimited tree, matching Scala's rule-1001 catch.
        let body = hex::decode("b60202020204000400").unwrap();
        let mut sizeless = vec![0];
        sizeless.extend_from_slice(&body);
        assert_eq!(
            (registry(Some("ergo_tree"))[0].run)(&sizeless),
            Outcome::Rejected
        );
        let mut sized = vec![8, body.len() as u8];
        sized.extend_from_slice(&body);
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&sized)).unwrap();
        assert!(tree_is_unparsed(&tree));
    }

    /// Both writers expand the original 3205-byte compact descriptor input to
    /// the captured 4940-byte Scala output, which both readers then refuse.
    #[test]
    fn nightly_compact_type_expansion_matches_scala_write_rejection() {
        std::thread::Builder::new()
            // Deep type clone/equality/drop are recursive in debug builds.
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let bytes = include_bytes!(
                    "../fuzz/corpus/ergo_tree/nightly-2026-09-30-compact-type-expansion"
                );
                let mut reader = VlqReader::new(bytes).with_activated_script_version(3);
                let tree = read_ergo_tree_gated(&mut reader).unwrap();
                let mut writer = VlqWriter::new();
                ergo_ser::ergo_tree::write_ergo_tree(&mut writer, &tree).unwrap();
                let output = writer.result();
                let expected =
                    include_str!("../../test-vectors/scala/sigma/nightly_type_expansion.hex")
                        .lines()
                        .find(|line| !line.starts_with('#'))
                        .unwrap();
                assert_eq!(hex::encode(&output), expected);
                assert_eq!(output.len(), 4940);
                assert!(matches!(
                    read_ergo_tree_gated(&mut VlqReader::new(&output)),
                    Err(ReadError::SigmaValidation { rule_id: 1014, .. })
                ));
                for surface in ["ergo_tree", "sigma_expr"] {
                    assert_eq!(
                        (registry(Some(surface))[0].run)(bytes),
                        Outcome::WriteRejected
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Runs 36835270692 and 36792671282: pinned sigma-state 6.0.6 behavior.
    #[test]
    fn nightly_box_serialization_size_and_tuple_failures() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let bytes = include_bytes!(
                    "../fuzz/corpus/ergo_box_candidate/nightly-2026-10-01-type-expansion"
                );
                let mut reader = VlqReader::new(bytes).with_activated_script_version(3);
                let candidate = ergo_ser::ergo_box::read_ergo_box_candidate(&mut reader).unwrap();
                assert_eq!(reader.position(), 2656);
                let mut writer = VlqWriter::new();
                ergo_ser::ergo_box::write_ergo_box_candidate(&mut writer, &candidate).unwrap();
                let output = writer.result();
                let expected =
                    include_str!("../../test-vectors/scala/sigma/nightly_box_type_expansion.hex")
                        .lines()
                        .find(|line| !line.starts_with('#'))
                        .unwrap();
                assert_eq!(hex::encode(&output), expected);
                assert_eq!(output.len(), 4589);
                assert!(matches!(
                    ergo_ser::ergo_box::read_ergo_box_candidate(
                        &mut VlqReader::new(&output).with_activated_script_version(3)
                    ),
                    Err(ReadError::SigmaValidation { rule_id: 1014, .. })
                ));
                assert_eq!(
                    (registry(Some("ergo_box_candidate"))[0].run)(bytes),
                    Outcome::WriteRejected
                );
                crate::fuzz::fuzz_one("ergo_box_candidate", bytes);

                // The sigma-state 6.0.6 transcript lives beside the corpus seed;
                // read the bytes from it so the pinned oracle input and the
                // committed regression corpus cannot drift apart.
                let transcript =
                    include_str!("../../test-vectors/scala/sigma/nightly_box_unwritable_tuple.txt");
                let field = |key: &str| {
                    transcript
                        .lines()
                        .find_map(|l| l.strip_prefix(key).map(str::trim))
                        .unwrap_or_else(|| panic!("{key} missing from the oracle transcript"))
                };
                let expected_error = field("exception=");
                let bytes = hex::decode(field("input=")).unwrap();
                assert_eq!(
                    bytes,
                    include_bytes!(
                        "../fuzz/corpus/ergo_box_candidate/nightly-2026-10-01-unwritable-tuple"
                    )
                );
                assert_eq!(field("verdict="), "REJECT");
                let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
                let candidate = ergo_ser::ergo_box::read_ergo_box_candidate(&mut reader).unwrap();
                // The reference parses the same bytes and stops here too.
                assert_eq!(
                    reader.position(),
                    field("parsed_bytes=").parse::<usize>().unwrap()
                );
                // Scala parses the degenerate tuple, then raises the pinned
                // `expected_error` instead of writing the original script bytes.
                // The Rust wording differs from Scala's, so pin the condition
                // rather than the text.
                assert!(expected_error.contains("less than 2 items"));
                for indexed in [false, true] {
                    let mut writer = VlqWriter::new();
                    let result = if indexed {
                        ergo_ser::ergo_box::write_ergo_box_candidate_indexed(
                            &mut writer,
                            &candidate,
                            &[],
                        )
                    } else {
                        ergo_ser::ergo_box::write_ergo_box_candidate(&mut writer, &candidate)
                    };
                    assert!(matches!(result, Err(WriteError::InvalidData(message))
                        if message.contains("STuple must have at least 2 elements")));
                }
                assert_eq!(
                    (registry(Some("ergo_box_candidate"))[0].run)(&bytes),
                    Outcome::WriteRejected
                );
                crate::fuzz::fuzz_one("ergo_box_candidate", &bytes);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Local campaign: a box candidate whose tree is `XorOf^n(FalseLeaf)` to
    /// the read-depth limit. sigma-state 6.0.6 parses it, re-serializes it to
    /// 117 bytes, and then CANNOT re-read its own output
    /// (`DeserializeCallDepthExceeded: ...depth(111) exceeds allowed maximum
    /// 110`), because writing the leaf as a Boolean constant costs one more
    /// read level. `WriteRejected` is therefore the reference-compatible
    /// verdict.
    ///
    /// #459 already pinned that verdict for the standalone `ergo_tree`
    /// surface, but `has_depth_expanding_boolean` defaulted to false and
    /// `view!` never forwarded it, so the box surface could not reach it.
    #[test]
    fn box_boolean_depth_exemption_reaches_container_surfaces() {
        let transcript =
            include_str!("../../test-vectors/scala/sigma/nightly_box_boolean_depth.txt");
        let field = |key: &str| {
            transcript
                .lines()
                .find_map(|l| l.strip_prefix(key).map(str::trim))
                .unwrap_or_else(|| panic!("{key} missing from the oracle transcript"))
        };
        assert_eq!(field("verdict="), "ACCEPT");
        assert_eq!(
            field("redecode_exception="),
            "sigma.serialization.DeserializeCallDepthExceeded"
        );

        let bytes = hex::decode(field("input=")).unwrap();
        assert_eq!(
            bytes.len(),
            field("parsed_bytes=").parse::<usize>().unwrap()
        );
        // The corpus seed and the pinned oracle input are the same bytes, so
        // the fuzzer's reproducer and the transcript cannot drift apart.
        assert_eq!(
            bytes,
            include_bytes!("../fuzz/corpus/ergo_box_candidate/nightly-2026-10-02-boolean-depth")
        );

        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let candidate = ergo_ser::ergo_box::read_ergo_box_candidate(&mut reader).unwrap();
        // The exemption has to see THROUGH the box to the tree it carries.
        assert!(candidate.ergo_tree().has_depth_expanding_boolean());
        assert!(candidate.has_depth_expanding_boolean());

        let mut writer = VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box_candidate(&mut writer, &candidate).unwrap();
        let output = writer.result().to_vec();
        assert_eq!(
            output.len(),
            field("reencoded_bytes=").parse::<usize>().unwrap()
        );
        assert_eq!(hex::encode(&output), field("reencoded_hex="));

        // The reference cannot read this back; we must not call that a Bug.
        assert!(matches!(
            ergo_ser::ergo_box::read_ergo_box_candidate(
                &mut VlqReader::new(&output).with_activated_script_version(3)
            ),
            Err(ReadError::DepthLimitExceeded { max: 110 })
        ));
        assert_eq!(
            (registry(Some("ergo_box_candidate"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
        crate::fuzz::fuzz_one("ergo_box_candidate", &bytes);
    }

    /// The exemption has to survive being nested: a transaction reaches its
    /// tree through `output_candidates`, a `Vec`, so forwarding only one level
    /// (container -> Vec) still loses it. Found by a later local campaign,
    /// after the container forwarding above looked complete: the output box's
    /// own predicate was `true` while the transaction's was `false`, because
    /// the `Vec<T>` impl did not forward the predicate at all.
    #[test]
    fn boolean_depth_exemption_survives_vec_nesting() {
        let bytes: &[u8] =
            include_bytes!("../fuzz/corpus/transaction/nightly-2026-10-02-boolean-depth");
        let mut reader = VlqReader::new(bytes).with_activated_script_version(3);
        let tx = ergo_ser::transaction::read_transaction(&mut reader).unwrap();

        // The box itself sees it...
        let box_predicate = tx.output_candidates[0]
            .ergo_tree()
            .has_depth_expanding_boolean();
        assert!(
            box_predicate,
            "the output box carries the depth-109 Boolean"
        );
        // ...and so must the box, its Vec, and the transaction around it.
        assert!(tx.output_candidates[0].has_depth_expanding_boolean());
        assert!(tx.output_candidates.has_depth_expanding_boolean());
        assert!(tx.has_depth_expanding_boolean());

        assert_eq!(
            (registry(Some("transaction"))[0].run)(bytes),
            Outcome::WriteRejected
        );
        crate::fuzz::fuzz_one("transaction", bytes);
    }

    #[test]
    fn boolean_depth_limit_error_accepts_only_exact_forms() {
        let depth_error = ReadError::DepthLimitExceeded { max: 110 };
        assert!(is_boolean_depth_limit_error(&depth_error));
        for index in [0, 1, usize::MAX] {
            assert!(is_boolean_depth_limit_error(&ReadError::InvalidData(
                format!("tx[{index}]: {depth_error}")
            )));
        }

        let other_depth = ReadError::DepthLimitExceeded { max: 111 };
        assert!(!is_boolean_depth_limit_error(&other_depth));
        let other_error = ReadError::InvalidData("different inner error".into());
        for message in [
            format!("tx[0]: {other_error}"),
            format!("tx[0]: {other_depth}"),
            format!("tx[not-a-number]: {depth_error}"),
            format!("tx[0]: {depth_error} trailing text"),
            format!("tx[00]: {depth_error}"),
            format!("tx[+0]: {depth_error}"),
            format!("tx[-1]: {depth_error}"),
            format!("tx[ 0]: {depth_error}"),
            format!("tx[]: {depth_error}"),
            format!("tx[{}0]: {depth_error}", usize::MAX),
            format!("prefix tx[0]: {depth_error}"),
            format!("tx[0]:{depth_error}"),
            depth_error.to_string(),
        ] {
            assert!(
                !is_boolean_depth_limit_error(&ReadError::InvalidData(message.clone())),
                "unexpectedly accepted {message:?}"
            );
        }
    }

    #[test]
    fn boolean_depth_exemption_survives_ctx_expr_tuple_nesting() {
        use ergo_ser::input::{read_context_extension, write_context_extension, ContextExtension};

        let seed =
            include_bytes!("../fuzz/corpus/ergo_box_candidate/nightly-2026-10-02-boolean-depth");
        let mut writer = VlqWriter::new();
        write_context_extension(&mut writer, &ContextExtension::empty()).unwrap();
        let mut bytes = writer.result();
        assert_eq!(bytes, [0]);
        bytes.extend_from_slice(seed);
        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let frame = (
            read_context_extension(&mut reader).unwrap(),
            ergo_ser::ergo_box::read_ergo_box_candidate(&mut reader).unwrap(),
        );
        assert!(frame.1.has_depth_expanding_boolean());
        assert_eq!(
            (registry(Some("ctx_expr"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
        assert!(frame.has_depth_expanding_boolean());
    }

    /// Preserve the committed seed's leaf encoding for the initial input.
    /// A normally read candidate already caches the expanded, unreadable
    /// canonical tree, so writing that candidate would skip the regression's
    /// successful first read. Validate its original bytes before using the
    /// real container writers to frame them.
    fn boolean_depth_candidate_for_writing() -> ergo_ser::ergo_box::ErgoBoxCandidate {
        use ergo_ser::ergo_box::{
            read_ergo_box_candidate, write_ergo_box_candidate, ErgoBoxCandidate,
        };

        let seed =
            include_bytes!("../fuzz/corpus/ergo_box_candidate/nightly-2026-10-02-boolean-depth");
        let mut reader = VlqReader::new(seed).with_activated_script_version(3);
        let parsed = read_ergo_box_candidate(&mut reader).unwrap();
        let candidate = ErgoBoxCandidate::try_from_raw_parts(
            parsed.value,
            parsed.ergo_tree().clone(),
            parsed.ergo_tree_bytes().to_vec(),
            parsed.creation_height,
            parsed.tokens.clone(),
            parsed.additional_registers().clone(),
            parsed.register_bytes().to_vec(),
        )
        .unwrap();
        let mut writer = VlqWriter::new();
        write_ergo_box_candidate(&mut writer, &candidate).unwrap();
        // The fuzz seed includes a suffix that the candidate reader ignores.
        assert_eq!(writer.result(), &seed[..reader.position()]);
        candidate
    }

    fn boolean_depth_transaction_for_writing() -> ergo_ser::transaction::Transaction {
        let seed = include_bytes!("../fuzz/corpus/transaction/nightly-2026-10-02-boolean-depth");
        let mut reader = VlqReader::new(seed).with_activated_script_version(3);
        let mut tx = ergo_ser::transaction::read_transaction(&mut reader).unwrap();
        tx.output_candidates = vec![boolean_depth_candidate_for_writing()];
        tx
    }

    #[test]
    fn boolean_depth_exemption_reaches_ergo_box_surface() {
        use ergo_ser::ergo_box::{read_ergo_box, write_ergo_box, ErgoBox};

        let bx = ErgoBox {
            candidate: boolean_depth_candidate_for_writing(),
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes([0; 32]),
            index: 0,
        };
        let mut writer = VlqWriter::new();
        write_ergo_box(&mut writer, &bx).unwrap();
        let bytes = writer.result();
        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let parsed = read_ergo_box(&mut reader).unwrap();
        assert!(reader.is_empty());
        assert!(parsed.candidate.has_depth_expanding_boolean());
        assert_eq!(
            (registry(Some("ergo_box"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
        assert!(parsed.has_depth_expanding_boolean());
    }

    #[test]
    fn boolean_depth_exemption_reaches_unsigned_transaction_surface() {
        use ergo_ser::{
            input::UnsignedInput,
            transaction::{
                read_unsigned_transaction, write_unsigned_transaction, UnsignedTransaction,
            },
        };

        let tx = boolean_depth_transaction_for_writing();
        let unsigned = UnsignedTransaction {
            inputs: tx
                .inputs
                .iter()
                .map(|input| UnsignedInput {
                    box_id: input.box_id,
                    extension: input.spending_proof.extension().clone(),
                })
                .collect(),
            data_inputs: tx.data_inputs,
            output_candidates: tx.output_candidates,
        };
        let mut writer = VlqWriter::new();
        write_unsigned_transaction(&mut writer, &unsigned).unwrap();
        let bytes = writer.result();
        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let parsed = read_unsigned_transaction(&mut reader).unwrap();
        assert!(reader.is_empty());
        assert!(parsed.output_candidates.has_depth_expanding_boolean());
        assert_eq!(
            (registry(Some("unsigned_transaction"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
        assert!(parsed.has_depth_expanding_boolean());
    }

    #[test]
    fn boolean_depth_exemption_reaches_block_transactions_surface() {
        use ergo_ser::block_transactions::{
            read_block_transactions, write_block_transactions, BlockTransactions,
        };

        let block = BlockTransactions {
            header_id: ergo_primitives::digest::ModifierId::from_bytes([0; 32]),
            transactions: vec![boolean_depth_transaction_for_writing()],
        };
        let mut writer = VlqWriter::new();
        write_block_transactions(&mut writer, &block).unwrap();
        let bytes = writer.result();
        let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
        let parsed = read_block_transactions(&mut reader).unwrap();
        assert!(reader.is_empty());
        assert!(parsed.transactions.has_depth_expanding_boolean());
        assert!(parsed.has_depth_expanding_boolean());
        assert_eq!(
            (registry(Some("block_transactions"))[0].run)(&bytes),
            Outcome::WriteRejected
        );
    }

    #[test]
    fn tree_size_expansion_exception_requires_growth_and_position_rule() {
        for (input_size, output_size, rule_id, expected_bug) in [
            (4096, 4097, 1014, false),
            (4097, 4098, 1014, true),
            (4095, 4096, 1014, true),
            (4096, 4097, 1001, true),
        ] {
            let calls = std::cell::Cell::new(0);
            let outcome = rw_check(
                &vec![0; input_size],
                |reader| {
                    calls.set(calls.get() + 1);
                    if calls.get() > 1 {
                        return Err(ReadError::SigmaValidation {
                            rule_id,
                            args: vec![],
                            message: "injected validation failure".into(),
                        });
                    }
                    reader.set_position(input_size);
                    Ok(cast_tree(3, 0x7e))
                },
                |writer, _| {
                    writer.put_bytes(&vec![0; output_size]);
                    Ok(())
                },
                |_| false,
            );
            assert_eq!(matches!(outcome, Outcome::Bug(_)), expected_bug);
        }
    }

    /// Run 36775308168: all three first serializations match sigma-state 6.0.6.
    #[test]
    fn nightly_20261001_crashes_match_scala_serialization_and_outcomes() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                for line in
                    include_str!("../../test-vectors/scala/sigma/nightly_roundtrip_2026_10_01.tsv")
                        .lines()
                        .filter(|line| !line.starts_with('#'))
                {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("fuzz/corpus")
                        .join(fields[0])
                        .join(fields[1]);
                    let bytes = std::fs::read(path).unwrap();
                    let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
                    let mut writer = VlqWriter::new();
                    if fields[0] == "ergo_box_candidate" {
                        let value =
                            ergo_ser::ergo_box::read_ergo_box_candidate(&mut reader).unwrap();
                        ergo_ser::ergo_box::write_ergo_box_candidate(&mut writer, &value).unwrap();
                    } else {
                        let value = read_ergo_tree_gated(&mut reader).unwrap();
                        ergo_ser::ergo_tree::write_ergo_tree(&mut writer, &value).unwrap();
                    }
                    assert_eq!(hex::encode(writer.result()), fields[3], "{}", fields[1]);
                    let expected = match fields[2] {
                        "Accepted" => Outcome::Accepted,
                        "WriteRejected" => Outcome::WriteRejected,
                        _ => unreachable!(),
                    };
                    assert_eq!((registry(Some(fields[0]))[0].run)(&bytes), expected);
                    crate::fuzz::fuzz_one(fields[0], &bytes);
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Boolean leaves add a data-value level only when written as constants.
    #[test]
    fn boolean_leaf_depth_expansion_has_exact_boundary() {
        for leaf in [0x7f, 0x80] {
            for (nots, expected) in [
                (107, Outcome::Accepted),
                (108, Outcome::WriteRejected),
                (109, Outcome::Rejected),
            ] {
                let mut bytes = vec![0, 0xd1]; // BoolToSigmaProp
                bytes.extend(std::iter::repeat_n(0xef, nots));
                bytes.push(leaf);
                for surface in ["ergo_tree", "sigma_expr"] {
                    assert_eq!((registry(Some(surface))[0].run)(&bytes), expected);
                }
            }
        }
    }

    /// A box's cached canonical script strips one cast per read, also when
    /// carried by indexed transaction outputs or block transaction sections.
    #[test]
    fn cached_script_cast_chains_converge_through_containers() {
        for version in 0..=3 {
            for casts in 1..=3 {
                let mut candidate = vec![57, 0xc8 | version, 4, 0xcd, 0xff];
                candidate.extend(std::iter::repeat_n(0x7e, casts));
                candidate.extend([4, 4]); // Int constant 2
                candidate.extend(std::iter::repeat_n(4, casts)); // Int cast targets
                candidate.extend([4, 0, 0]); // height, tokens, registers
                let mut bx = candidate.clone();
                bx.extend([0; 33]); // transaction id + index
                let mut tx = vec![0, 0, 0, 1]; // inputs, data inputs, token table, outputs
                tx.extend_from_slice(&candidate);
                let mut block = vec![0; 32];
                block.push(1);
                block.extend_from_slice(&tx);
                for (surface, bytes) in [
                    ("ergo_box_candidate", &candidate),
                    ("ergo_box", &bx),
                    ("transaction", &tx),
                    ("unsigned_transaction", &tx),
                    ("block_transactions", &block),
                ] {
                    assert_eq!(
                        (registry(Some(surface))[0].run)(bytes),
                        Outcome::Accepted,
                        "{surface}, version={version}, casts={casts}"
                    );
                }
            }
        }
    }

    #[test]
    fn tree_size_wrap_exception_requires_growth_rule_and_exact_bytes() {
        use ergo_ser::opcode::Expr;
        for (input_size, output_size, rule, retained_byte, expected_bug) in [
            (4096, 4097, 1014, 1, false),
            (4097, 4098, 1014, 1, true),
            (4095, 4096, 1014, 1, true),
            (4096, 4097, 1001, 1, true),
            (4096, 4097, 1014, 2, true),
        ] {
            let outcome = rw_check(
                &vec![0; input_size],
                |reader| {
                    let mut tree = cast_tree(3, 0x7e);
                    if reader.get_u8()? == 0 {
                        reader.set_position(input_size);
                    } else {
                        let mut raw = ergo_ser::opcode::UnparsedErgoTree::from(vec![
                            retained_byte;
                            output_size
                        ]);
                        raw.validation_error = Some((rule, vec![]));
                        tree.body = Expr::Unparsed(raw);
                    }
                    Ok(tree)
                },
                |writer, _| {
                    writer.put_bytes(&vec![1; output_size]);
                    Ok(())
                },
                tree_is_unparsed,
            );
            assert_eq!(matches!(outcome, Outcome::Bug(_)), expected_bug);
        }
    }

    /// Scala ValueSerializer.scala:154-166,359-370: only pre-v3 Upcast(Const) is stripped.
    #[test]
    fn rw_check_pre_v3_upcast_strip_accepted() {
        for version in 0..3 {
            let before = cast_tree(version, 0x7e);
            let after = strip_cast(&before);
            assert_eq!(structural_outcome(before, after), Outcome::Accepted);
        }
    }

    /// Scala ErgoHeader.scala:132-140,167-180: serializedId derives from the
    /// retained slice even when nested; all actual header fields remain data.
    #[test]
    fn rw_check_nested_header_id_corruption_is_a_bug() {
        use ergo_ser::{
            block_transactions::BlockTransactions,
            ergo_box::{ErgoBox, ErgoBoxCandidate},
            input::{ContextExtension, Input, SpendingProof, UnsignedInput},
            register::{AdditionalRegisters, RegisterValue},
            sigma_type::SigmaType,
            sigma_value::{CollValue, SigmaValue},
            transaction::{Transaction, UnsignedTransaction},
        };
        let bytes = hex::decode(CONSTANT_CRASH).unwrap();
        let mut reader = VlqReader::new(&bytes);
        reader.enable_header_spans();
        let (_, value) = ergo_ser::sigma_value::read_constant(&mut reader).unwrap();
        let mut other = value.clone();
        let SigmaValue::Header(_, id) = &mut other else {
            panic!("expected header");
        };
        *id = [42; 32];
        let wrap = |value: SigmaValue| {
            SigmaValue::Tuple(vec![
                SigmaValue::Coll(CollValue::Values(vec![value.clone()])),
                SigmaValue::Opt(Some(Box::new(value.clone()))),
                SigmaValue::ConcreteCollection {
                    elem_type: Box::new(SigmaType::SHeader),
                    items: vec![value],
                },
            ])
        };
        assert!(parity::header_ids_match_wire(&wrap(value.clone()), &reader));
        assert!(!parity::header_ids_match_wire(
            &wrap(other.clone()),
            &reader
        ));
        assert!(matches!(
            structural_outcome(wrap(value.clone()), wrap(other.clone())),
            Outcome::Bug(_)
        ));
        let make = |value: SigmaValue| {
            let mut tree = cast_tree(3, 0x7e);
            tree.constant_segregation = true;
            tree.constants = vec![(SigmaType::SHeader, value.clone())];
            tree.body = ergo_ser::opcode::Expr::Const {
                tpe: SigmaType::SHeader,
                val: value.clone(),
            };
            let regs = AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SHeader,
                    value: value.clone(),
                }],
            };
            let mut ext = ContextExtension::empty();
            ext.values.insert(1, (SigmaType::SHeader, value));
            let proof = SpendingProof::new(vec![], ext.clone()).unwrap();
            let input = Input {
                box_id: ergo_primitives::digest::Digest32::from_bytes([0; 32]),
                spending_proof: proof.clone(),
            };
            let unsigned_input = UnsignedInput {
                box_id: ergo_primitives::digest::Digest32::from_bytes([0; 32]),
                extension: ext.clone(),
            };
            let candidate =
                ErgoBoxCandidate::new(1, tree.clone(), 0, vec![], regs.clone()).unwrap();
            let bx = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: ergo_primitives::digest::ModifierId::from_bytes([0; 32]),
                index: 0,
            };
            let tx = Transaction {
                inputs: vec![input.clone()],
                data_inputs: vec![],
                output_candidates: vec![candidate.clone()],
            };
            let unsigned_tx = UnsignedTransaction {
                inputs: vec![unsigned_input.clone()],
                data_inputs: vec![],
                output_candidates: vec![candidate.clone()],
            };
            let block = BlockTransactions {
                header_id: ergo_primitives::digest::ModifierId::from_bytes([0; 32]),
                transactions: vec![tx.clone()],
            };
            (
                tree,
                regs,
                ext,
                proof,
                input,
                unsigned_input,
                candidate,
                bx,
                tx,
                unsigned_tx,
                block,
            )
        };
        let a = make(value);
        let b = make(other);
        macro_rules! check { ($($field:tt),*) => { $(
            assert!(parity::header_ids_match_wire(&a.$field, &reader));
            assert!(!parity::header_ids_match_wire(&b.$field, &reader));
            assert!(matches!(structural_outcome(a.$field.clone(), b.$field.clone()), Outcome::Bug(_)));
        )* }; }
        check!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        assert!(matches!(
            structural_outcome((a.2, a.6), (b.2, b.6)),
            Outcome::Bug(_)
        ));
    }
}
