//! Structure-aware generator for the `ergo_box_candidate` SER surface.
//!
//! A box candidate is `value · ergoTree · creationHeight · tokens · registers`.
//! The embedded ErgoTree is the richest field, so this generator both drives
//! the box-level knobs (token amount, register type) and re-uses the tree-level
//! adversarial scripts through the box's own post-parse gates.

use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{write_ergo_box_candidate, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use crate::gen::asm;
use crate::gen::{Feature, FeatureSet, GenMode, GenOutput};
use crate::rng::Rng;

const SURFACE: &str = "ergo_box_candidate";

/// Generate one box-candidate input: ~35% on-manifold, ~65% adversarial.
pub fn gen(rng: &mut Rng) -> GenOutput {
    if rng.below(100) < 35 {
        gen_valid(rng)
    } else {
        gen_adversarial(rng)
    }
}

/// A valid `SigmaProp`-rooted tree struct for building on-manifold boxes.
fn valid_sigmaprop_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        },
    }
}

/// On-manifold: a valid box the reference accepts, built with the real writer.
pub fn gen_valid(rng: &mut Rng) -> GenOutput {
    let value = 1 + (rng.next_u64() >> 1); // positive, well within range
    let height = (rng.next_u64() & 0x000f_ffff) as u32;
    let candidate = ErgoBoxCandidate::new(
        value,
        valid_sigmaprop_tree(),
        height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .expect("valid box candidate serializes");
    let mut w = VlqWriter::new();
    write_ergo_box_candidate(&mut w, &candidate).expect("valid box candidate writes");
    GenOutput {
        surface: SURFACE,
        bytes: w.result(),
        intended_valid: true,
        mode: GenMode::OnManifold,
        features: FeatureSet::from_iter([Feature::OnManifoldValid]),
    }
}

/// Assemble a standalone box candidate from raw field bytes. `registers`
/// includes its own leading count byte.
fn assemble(
    value: u64,
    tree: &[u8],
    height: u32,
    tokens: &[([u8; 32], u64)],
    registers: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    asm::put_vlq(&mut b, value);
    b.extend_from_slice(tree);
    asm::put_vlq(&mut b, height as u64);
    b.push(tokens.len() as u8);
    for (id, amount) in tokens {
        b.extend_from_slice(id);
        asm::put_vlq(&mut b, *amount);
    }
    b.extend_from_slice(registers);
    b
}

fn gen_adversarial(rng: &mut Rng) -> GenOutput {
    match rng.below(5) {
        0 => sigmaprop_root_violation(rng),
        1 => tree_version_nonzero(rng),
        2 => register_v6_type(rng),
        3 => zero_amount_token(rng),
        _ => off_curve_group_element(rng),
    }
}

fn out(bytes: Vec<u8>, intended_valid: bool, features: FeatureSet) -> GenOutput {
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid,
        mode: GenMode::Adversarial,
        features,
    }
}

/// Box whose script is a sizeless non-`SigmaProp` root (`00 01 01`). Bug #25:
/// the box parser runs `check_sigma_prop_root` and rejects it.
fn sigmaprop_root_violation(rng: &mut Rng) -> GenOutput {
    let tree: &[u8] = if rng.coin() {
        &[0x00, 0x01, 0x01] // Const(SBoolean, true)
    } else {
        &[0x00, 0x04, 0x00] // Const(SInt, 0)
    };
    let bytes = assemble(1_000_000, tree, 1, &[], &[0x00]);
    out(
        bytes,
        false,
        FeatureSet::from_iter([Feature::TreeSigmaPropRootViolation]),
    )
}

/// Box whose script header carries a non-zero version. Bug #17: either a
/// sizeless nonzero-version tree (rule 1012) or a size-delimited soft-fork
/// version (`check_tree_version_supported`) — both hard-reject at the box.
fn tree_version_nonzero(rng: &mut Rng) -> GenOutput {
    let (tree, features): (Vec<u8>, FeatureSet) = if rng.coin() {
        // sizeless v1 SigmaProp tree — rule 1012 (needs size bit).
        (
            vec![0x01, 0x08, 0xD3],
            FeatureSet::from_iter([Feature::TreeVersionNonZero]),
        )
    } else {
        // size-delimited v4 tree — above the supported version.
        let mut t = vec![0x04 | 0x08];
        asm::put_vlq(&mut t, asm::SIGMAPROP_TRUE_BODY.len() as u64);
        t.extend_from_slice(&asm::SIGMAPROP_TRUE_BODY);
        (
            t,
            FeatureSet::from_iter([Feature::TreeVersionNonZero, Feature::TreeSizeBit]),
        )
    };
    let bytes = assemble(1_000_000, &tree, 1, &[], &[0x00]);
    out(bytes, false, features)
}

/// Box with a register typed with a v6-only type (`SOption` / `SHeader` /
/// `SUnsignedBigInt`). Bug #5: `CheckV6Type` (rule 1019) rejects it at ANY
/// tree version. The script is valid so the register is the sole reject cause.
fn register_v6_type(rng: &mut Rng) -> GenOutput {
    // count=1, then the register entry.
    let register: Vec<u8> = match rng.below(3) {
        // Option[Boolean] None: type 0x25 (36+1), tag 0x00.
        0 => vec![0x01, 0x25, 0x00],
        // SUnsignedBigInt (code 9), value = u16 len(1) + 1-byte magnitude 0x2A.
        1 => vec![0x01, 0x09, 0x01, 0x2A],
        // SHeader (code 104=0x68) is expensive to materialize; use SOption of
        // an Int instead as a second Option variant: type 0x28 (36+4), None.
        _ => vec![0x01, 0x28, 0x00],
    };
    let bytes = assemble(1_000_000, &asm::TREE_TRUE_PROP, 1, &[], &register);
    out(
        bytes,
        false,
        FeatureSet::from_iter([Feature::RegisterV6Type]),
    )
}

/// Box with an output token whose amount is 0. Bug #23: the codec accepts it
/// (the positive-amount rule lives in validation), so this round-trips.
fn zero_amount_token(rng: &mut Rng) -> GenOutput {
    let mut id = [0u8; 32];
    for b in id.iter_mut() {
        *b = rng.byte();
    }
    let bytes = assemble(1_000_000, &asm::TREE_TRUE_PROP, 1, &[(id, 0)], &[0x00]);
    out(
        bytes,
        true,
        FeatureSet::from_iter([Feature::TxZeroAmountToken]),
    )
}

/// Box whose P2PK script embeds an off-curve group element. Bug #4: the box's
/// `read_ergo_tree` defers the curve check, so the codec accepts it while the
/// reference rejects at deserialize.
fn off_curve_group_element(rng: &mut Rng) -> GenOutput {
    let ge = asm::off_curve_group_element(rng);
    let mut tree = vec![0x00, 0x08, 0xCD];
    tree.extend_from_slice(&ge);
    let bytes = assemble(1_000_000, &tree, 1, &[], &[0x00]);
    out(
        bytes,
        false,
        FeatureSet::from_iter([Feature::OffCurveGroupElement]),
    )
}
