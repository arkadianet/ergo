//! Generator for the `ctx_expr` frame — the wire form behind the consensus-
//! complete **`reduce_ctx`** oracle surface.
//!
//! ```text
//! frame := contextExtension · ergoBoxCandidate
//! ```
//!
//! Both halves are self-delimiting, so one reader consumes them in sequence on
//! either implementation. The point of the frame is that **both** positions that
//! Scala parses as an `EvaluatedValue` — the input's context extension and the
//! box's registers — come from the WIRE, and the box's ergoTree is the script
//! that READS them. That closes the loop the plain `reduce` surface leaves open:
//! `reduce` fixes an empty extension and no registers, so the evaluated-value
//! vocabulary there is only ever exercised at parse.
//!
//! Two arms:
//!
//! * **catalog** — a [`CtxRead`] script paired with exactly the value(s) it
//!   reads, so the tree reduces to a concrete `P:<prop>|<cost>` instead of a
//!   lockstep type-mismatch reject. These are the calibrated forms; four of them
//!   are the JVM verdicts pinned in PR #301.
//! * **sweep** — a randomized extension + register block from the full
//!   [`evaluated_value`] vocabulary under a script that never reads them, so the
//!   PARSE of every vocabulary class is exercised across the frame.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};

use crate::gen::asm;
use crate::gen::evaluated_value::{self, value_bytes};
use crate::gen::sigma_expr::{ctx_read_tree_bytes, CtxRead};
use crate::gen::{Feature, FeatureSet, GenMode, GenOutput};
use crate::rng::Rng;

const SURFACE: &str = "ctx_expr";

// ---------------------------------------------------------------------------
// The value catalog: the exact values each `CtxRead` variant reads.
// ---------------------------------------------------------------------------

fn c_int(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(v),
    }
}

/// `Tuple(Int(1), Int(2))` as a `Tuple` NODE (`0x86`) — an `EvaluatedValue`
/// whose `.value` is a `Coll`, not a `Tuple2`.
fn tuple_node_1_2() -> Expr {
    Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple {
            items: vec![c_int(1), c_int(2)],
        },
    })
}

/// `ConcreteCollection[Int](7, 8)` as a node (`0x83`).
fn coll_node_7_8() -> Expr {
    Expr::Op(IrNode {
        opcode: 0x83,
        payload: Payload::ConcreteCollection {
            elem_type: SigmaType::SInt,
            items: vec![c_int(7), c_int(8)],
        },
    })
}

/// `GroupGenerator` (`0x82`).
fn group_generator() -> Expr {
    Expr::Op(IrNode {
        opcode: 0x82,
        payload: Payload::Zero,
    })
}

/// A plain `Coll[Byte]` constant.
fn byte_coll_const() -> Expr {
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])),
    }
}

/// A context-extension block from `(key, value)` pairs.
fn extension_block(entries: &[(u8, Expr)]) -> Vec<u8> {
    let mut b = vec![entries.len() as u8];
    for (key, expr) in entries {
        b.push(*key);
        b.extend_from_slice(&value_bytes(expr));
    }
    b
}

/// A positional register block (`R4..`) from an ordered value list.
fn register_block(values: &[Expr]) -> Vec<u8> {
    let mut b = vec![values.len() as u8];
    for expr in values {
        b.extend_from_slice(&value_bytes(expr));
    }
    b
}

/// The extension + register blocks a `CtxRead` variant needs, plus the feature
/// bits those values contribute.
///
/// A variant carries ONLY the values its script reads: that keeps the control
/// arm (`NeverReads`, constants only) free of the evaluated-node vocabulary, so
/// it stays a clean lockstep-agreement baseline while the other arms carry the
/// class under test.
fn value_blocks_for(read: CtxRead) -> (Vec<u8>, Vec<u8>, Vec<Feature>) {
    match read {
        CtxRead::NeverReads => (
            extension_block(&[(3, c_int(42))]),
            register_block(&[]),
            vec![Feature::CtxExtConstantVocabulary],
        ),
        CtxRead::TupleVarIsDefined | CtxRead::TupleVarFieldEq => (
            extension_block(&[(1, tuple_node_1_2())]),
            register_block(&[]),
            vec![Feature::CtxExtEvaluatedNode],
        ),
        CtxRead::CollVarIndexEq => (
            extension_block(&[(2, coll_node_7_8())]),
            register_block(&[]),
            vec![Feature::CtxExtEvaluatedNode],
        ),
        CtxRead::IntVarEq => (
            extension_block(&[(3, c_int(42))]),
            register_block(&[]),
            vec![Feature::CtxExtConstantVocabulary],
        ),
        CtxRead::GroupElementVarIsDefined => (
            extension_block(&[(4, group_generator())]),
            register_block(&[]),
            vec![Feature::CtxExtEvaluatedNode],
        ),
        // Registers are POSITIONAL (R4 first), so a script reading R5 / R6 needs
        // the preceding slots filled.
        CtxRead::TupleRegisterFieldEq => (
            extension_block(&[]),
            register_block(&[tuple_node_1_2()]),
            vec![Feature::RegisterEvaluatedNode],
        ),
        CtxRead::CollRegisterIndexEq => (
            extension_block(&[]),
            register_block(&[c_int(0), coll_node_7_8()]),
            vec![
                Feature::RegisterConstantVocabulary,
                Feature::RegisterEvaluatedNode,
            ],
        ),
        CtxRead::ByteCollRegisterIsDefined => (
            extension_block(&[]),
            register_block(&[c_int(0), c_int(1), byte_coll_const()]),
            vec![Feature::RegisterConstantVocabulary],
        ),
    }
}

// ---------------------------------------------------------------------------
// Frame assembly.
// ---------------------------------------------------------------------------

/// `value · ergoTree · creationHeight · tokens · registers` — a standalone box
/// candidate (full token ids), matching `read_ergo_box_candidate`.
fn box_candidate_bytes(tree: &[u8], registers: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    asm::put_vlq(&mut b, 1_000_000);
    b.extend_from_slice(tree);
    asm::put_vlq(&mut b, 1); // creation height
    b.push(0x00); // no tokens
    b.extend_from_slice(registers);
    b
}

fn frame(extension: &[u8], tree: &[u8], registers: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(extension.len() + tree.len() + registers.len() + 8);
    b.extend_from_slice(extension);
    b.extend_from_slice(&box_candidate_bytes(tree, registers));
    b
}

fn out(bytes: Vec<u8>, intended_valid: bool, mode: GenMode, features: FeatureSet) -> GenOutput {
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid,
        mode,
        features,
    }
}

/// One `ctx_expr` input: ~40 % on-manifold (constant-only, lockstep-clean),
/// ~60 % the evaluated-value vocabulary.
pub fn gen(rng: &mut Rng) -> GenOutput {
    if rng.below(100) < 40 {
        gen_valid(rng)
    } else {
        gen_adversarial(rng)
    }
}

/// On-manifold: a catalog frame whose values are plain `Constant`s — the only
/// form every implementation, before and after #301, parses identically.
pub fn gen_valid(rng: &mut Rng) -> GenOutput {
    let read = if rng.coin() {
        CtxRead::NeverReads
    } else {
        CtxRead::IntVarEq
    };
    let (extension, registers, features) = value_blocks_for(read);
    let bytes = frame(&extension, &ctx_read_tree_bytes(read), &registers);
    let mut set = FeatureSet::from_iter(features);
    set.insert(Feature::OnManifoldValid);
    set.insert(Feature::EvalCtxVarRead);
    out(bytes, true, GenMode::OnManifold, set)
}

fn gen_adversarial(rng: &mut Rng) -> GenOutput {
    if rng.below(100) < 70 {
        catalog(rng)
    } else {
        sweep(rng)
    }
}

/// A calibrated read paired with exactly the value it reads.
fn catalog(rng: &mut Rng) -> GenOutput {
    let read = CtxRead::ALL[rng.below(CtxRead::ALL.len())];
    let (extension, registers, features) = value_blocks_for(read);
    let bytes = frame(&extension, &ctx_read_tree_bytes(read), &registers);
    let mut set = FeatureSet::from_iter(features);
    set.insert(Feature::EvalCtxVarRead);
    // Every catalog value is one the reference PARSES (`Constant` / `Tuple` /
    // `ConcreteCollection` / `GroupGenerator`); whether the resulting REDUCTION
    // succeeds is a separate question the oracle answers.
    out(bytes, true, GenMode::Adversarial, set)
}

/// A randomized vocabulary sweep at both positions under a script that never
/// reads them, so the frame's verdict is decided purely by the two parsers.
fn sweep(rng: &mut Rng) -> GenOutput {
    let (extension, ext_features, ext_ok) = evaluated_value::gen_context_extension(rng, 4);
    let (registers, reg_features, reg_ok) = evaluated_value::gen_register_block(rng, 3);
    let tree = ctx_read_tree_bytes(CtxRead::NeverReads);
    let bytes = frame(&extension, &tree, &registers);
    let mut set = FeatureSet::from_iter(ext_features);
    set.extend(&FeatureSet::from_iter(reg_features));
    out(bytes, ext_ok && reg_ok, GenMode::Adversarial, set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Outcome;

    // ----- helpers -----

    fn hermetic(bytes: &[u8]) -> Outcome {
        crate::run_input(bytes, Some(SURFACE))
            .into_iter()
            .find(|(n, _)| *n == SURFACE)
            .map(|(_, o)| o)
            .expect("ctx_expr hermetic surface is registered")
    }

    // ----- happy path -----

    #[test]
    fn catalog_frames_parse_as_extension_plus_box_candidate() {
        for read in CtxRead::ALL {
            let (extension, registers, _) = value_blocks_for(read);
            let bytes = frame(&extension, &ctx_read_tree_bytes(read), &registers);
            let outcome = hermetic(&bytes);
            assert!(
                !matches!(outcome, Outcome::Bug(_)),
                "catalog frame for {read:?} tripped a hermetic invariant: {outcome:?}"
            );
        }
    }

    #[test]
    fn constant_only_catalog_frames_are_accepted() {
        // The on-manifold arm must survive the CURRENT decoder: a constant-only
        // extension is the form every version of the reader accepts, so a
        // rejection here means the frame layout itself is wrong.
        for read in [CtxRead::NeverReads, CtxRead::IntVarEq] {
            let (extension, registers, _) = value_blocks_for(read);
            let bytes = frame(&extension, &ctx_read_tree_bytes(read), &registers);
            assert_eq!(
                hermetic(&bytes),
                Outcome::Accepted,
                "constant-only frame for {read:?} was not accepted"
            );
        }
    }

    /// Pin the catalog frames' hexes: these are what
    /// `known_bugs/manifest.toml` records as `trigger_hex` for the #301
    /// re-injection entry. Run with `--nocapture` to print them.
    #[test]
    fn catalog_frames_pin_their_trigger_hexes() {
        for read in CtxRead::ALL {
            let (extension, registers, _) = value_blocks_for(read);
            let bytes = frame(&extension, &ctx_read_tree_bytes(read), &registers);
            println!("CTX_TRIGGER {read:?} = {}", crate::to_hex(&bytes));
            assert!(!bytes.is_empty());
        }
    }

    // ----- round-trips -----

    #[test]
    fn generated_frames_never_trip_a_hermetic_invariant() {
        let mut rng = Rng::new(0xC7E0_0000_0000_0001);
        for _ in 0..2_000 {
            let g = gen(&mut rng);
            assert_eq!(g.surface, SURFACE);
            let outcome = hermetic(&g.bytes);
            assert!(
                !matches!(outcome, Outcome::Bug(_)),
                "generated ctx_expr frame tripped an invariant: {outcome:?} bytes={}",
                crate::to_hex(&g.bytes)
            );
        }
    }
}
