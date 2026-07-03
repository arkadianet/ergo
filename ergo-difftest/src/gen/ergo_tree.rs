//! Structure-aware generator for the `ergo_tree` SER surface.
//!
//! The ErgoTree header byte and body are the densest bug surface in the whole
//! wire format, so this generator is the richest: it decomposes the header
//! (`version | size | cseg`) and the body grammar into independent adversarial
//! knobs, each mapped to a known bug.

use crate::gen::asm;
use crate::gen::{Feature, FeatureSet, GenMode, GenOutput};
use crate::rng::Rng;

const SURFACE: &str = "ergo_tree";

const SIZE_FLAG: u8 = 0x08;
const CSEG_FLAG: u8 = 0x10;

/// Generate one `ergo_tree` input: ~35% on-manifold, ~65% adversarial.
pub fn gen(rng: &mut Rng) -> GenOutput {
    if rng.below(100) < 35 {
        gen_valid(rng)
    } else {
        gen_adversarial(rng)
    }
}

/// On-manifold: a valid `SigmaProp`-rooted tree the reference accepts. We keep
/// a small hand-verified seed set covering the header-flag combinations that
/// still parse (v0 sizeless, size-delimited, constant-segregated, P2PK).
pub fn gen_valid(rng: &mut Rng) -> GenOutput {
    let bytes: Vec<u8> = match rng.below(5) {
        0 => asm::TREE_TRUE_PROP.to_vec(),
        1 => asm::TREE_FALSE_PROP.to_vec(),
        // P2PK: Const(SSigmaProp, ProveDlog(<valid GE>)) = 0x08 0xCD <33-byte GE>.
        2 => {
            let mut b = vec![0x00, 0x08, 0xCD];
            b.extend_from_slice(&asm::VALID_GENERATOR_GE);
            b
        }
        // Size-delimited v0 SigmaProp tree: header 0x08, size 2, body 08 D3.
        3 => {
            let mut b = vec![SIZE_FLAG];
            asm::put_vlq(&mut b, asm::SIGMAPROP_TRUE_BODY.len() as u64);
            b.extend_from_slice(&asm::SIGMAPROP_TRUE_BODY);
            b
        }
        // Constant-segregated v0 tree, 0 constants, SigmaProp root.
        _ => {
            let mut b = vec![CSEG_FLAG, 0x00];
            b.extend_from_slice(&asm::SIGMAPROP_TRUE_BODY);
            b
        }
    };
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid: true,
        mode: GenMode::OnManifold,
        features: FeatureSet::from_iter([Feature::OnManifoldValid]),
    }
}

/// Adversarial: hand-assemble a tree with a per-position knob.
fn gen_adversarial(rng: &mut Rng) -> GenOutput {
    match rng.below(11) {
        0 => tree_version_bits(rng),
        1 => tree_size_bit(rng),
        2 => tree_const_seg_bit(rng),
        3 => tree_sigmaprop_root_violation(rng),
        4 => tree_declared_size_mismatch(rng),
        5 => fundef_ntpeargs_high_bit(rng),
        6 => stypevar_illformed_utf8(rng),
        7 => vlq_above_i32_max(rng),
        8 => unsigned_bigint_pre_v3(rng),
        9 => relation2_compact_bool_pair(rng),
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

/// Header version bits `1..=7`. `1..=3` are supported (bare codec accepts;
/// box/oracle reject a sizeless nonzero-version tree via rule 1012). `4..=7`
/// are soft-fork territory the reference hard-rejects at the box layer.
/// Bug #17. Sometimes with the size bit set (bug #9 combined).
fn tree_version_bits(rng: &mut Rng) -> GenOutput {
    let version = rng.range(1, 7) as u8;
    let with_size = rng.coin();
    let mut features = FeatureSet::from_iter([Feature::TreeVersionNonZero]);
    let mut bytes;
    if with_size {
        features.insert(Feature::TreeSizeBit);
        bytes = vec![version | SIZE_FLAG];
        asm::put_vlq(&mut bytes, asm::SIGMAPROP_TRUE_BODY.len() as u64);
        bytes.extend_from_slice(&asm::SIGMAPROP_TRUE_BODY);
    } else {
        bytes = vec![version];
        bytes.extend_from_slice(&asm::SIGMAPROP_TRUE_BODY);
    }
    // v1..v3 sizeless: the bare codec parses it but the reference rejects a
    // sizeless nonzero-version tree (rule 1012). v>3: soft-fork hard-reject.
    // Either way the consensus reference does NOT accept it.
    out(bytes, false, features)
}

/// Size bit set on a v0 tree with a valid `SigmaProp` body. Bug #9.
fn tree_size_bit(_rng: &mut Rng) -> GenOutput {
    let mut bytes = vec![SIZE_FLAG];
    asm::put_vlq(&mut bytes, asm::SIGMAPROP_TRUE_BODY.len() as u64);
    bytes.extend_from_slice(&asm::SIGMAPROP_TRUE_BODY);
    out(bytes, true, FeatureSet::from_iter([Feature::TreeSizeBit]))
}

/// Constant-segregation bit set. Sometimes with a bogus constants-count VLQ
/// just above `i32::MAX` (bug #20) — the reference reads it non-exact and
/// yields zero constants, so this is an accepted-but-non-canonical form.
fn tree_const_seg_bit(rng: &mut Rng) -> GenOutput {
    let mut features = FeatureSet::from_iter([Feature::TreeConstSegBit]);
    let mut bytes = vec![CSEG_FLAG];
    if rng.coin() {
        features.insert(Feature::VlqAboveI32Max);
        bytes.extend_from_slice(&asm::VLQ_JUST_ABOVE_I32_MAX);
    } else {
        asm::put_vlq(&mut bytes, 0); // zero constants
    }
    bytes.extend_from_slice(&asm::SIGMAPROP_TRUE_BODY);
    out(bytes, true, features)
}

/// Sizeless tree whose determinable root type is NOT `SSigmaProp` — e.g.
/// `Const(SBoolean, true)` = `00 01 01`, or `Const(SInt, 0)` = `00 04 00`.
/// The bare codec accepts it; the reference rejects (rule 1001, sizeless).
/// Bug #25.
fn tree_sigmaprop_root_violation(rng: &mut Rng) -> GenOutput {
    let body: &[u8] = if rng.coin() {
        &[0x01, 0x01] // Const(SBoolean, true)
    } else {
        &[0x04, 0x00] // Const(SInt, 0)
    };
    let mut bytes = vec![0x00];
    bytes.extend_from_slice(body);
    out(
        bytes,
        false,
        FeatureSet::from_iter([Feature::TreeSigmaPropRootViolation]),
    )
}

/// Size-delimited tree whose declared size ≠ the actual structural body length.
/// Bug #19: the reference reads the declared size non-exact and, on the success
/// path, advances by the ACTUAL body length — so the next box field is read
/// from a different offset than a size-trusting parser would use.
fn tree_declared_size_mismatch(rng: &mut Rng) -> GenOutput {
    let body = asm::SIGMAPROP_TRUE_BODY;
    // A declared size deliberately off by a non-zero delta.
    let declared: u64 = match rng.below(3) {
        0 => body.len() as u64 + 1,
        1 => body.len() as u64 + 7,
        _ => body.len().saturating_sub(1) as u64,
    };
    let mut bytes = vec![SIZE_FLAG];
    asm::put_vlq(&mut bytes, declared);
    bytes.extend_from_slice(&body);
    // On the success path the reference ignores the declared size and parses
    // the (valid) body, so the tree itself is accepted; the divergence is an
    // offset one that only bites in a box/tx context (see box_candidate).
    out(
        bytes,
        true,
        FeatureSet::from_iter([Feature::TreeDeclaredSizeMismatch, Feature::TreeSizeBit]),
    )
}

/// `FunDef` (0xD7) with an `nTpeArgs` byte in `0x80..=0xFF`. Bug #14: the byte
/// is negative-as-signed, so Scala's `safeNewArray` throws — the node must
/// reject, not read `128..=255` type args and over-read the stream.
fn fundef_ntpeargs_high_bit(rng: &mut Rng) -> GenOutput {
    let n = 0x80u8 | (rng.byte() & 0x7f); // guaranteed >= 0x80
                                          // 00 (header v0) D7 (FunDef) 01 (id VLQ) <n> ... then a trivial rhs so the
                                          // shape is a real FunDef even though the parse rejects at the count byte.
    let mut bytes = vec![0x00, 0xD7, 0x01, n];
    bytes.extend_from_slice(&[0x04, 0x00]); // rhs = Const(SInt, 0)
    out(
        bytes,
        false,
        FeatureSet::from_iter([Feature::FunDefNTpeArgsHighBit]),
    )
}

/// `FunDef` carrying one `STypeVar` whose name bytes are ill-formed UTF-8
/// (`ED A0 80`). Bug #1: a strict decoder rejects, the JVM lossy-decodes. Our
/// port matches the JVM, so the bare codec accepts and round-trips (via U+FFFD).
fn stypevar_illformed_utf8(_rng: &mut Rng) -> GenOutput {
    // 00 D7 01 (FunDef id=1) 01 (nTpeArgs=1) 67 03 ED A0 80 (STypeVar "<ill>")
    // 04 00 (rhs = Const(SInt, 0)).
    let mut bytes = vec![0x00, 0xD7, 0x01, 0x01, asm::STYPEVAR_CODE, 0x03];
    bytes.extend_from_slice(&asm::ILL_FORMED_UTF8_NAME);
    bytes.extend_from_slice(&[0x04, 0x00]);
    out(
        bytes,
        true,
        FeatureSet::from_iter([Feature::STypeVarIllFormedUtf8]),
    )
}

/// A `ValUse` (0x72) id VLQ just above `i32::MAX`. Bug #20: read non-exact
/// (`getUInt().toInt` wraps negative) and kept as the raw `u32`, so it
/// round-trips byte-identically — the accepted, wrapping form.
fn vlq_above_i32_max(_rng: &mut Rng) -> GenOutput {
    let mut bytes = vec![0x00, 0x72];
    bytes.extend_from_slice(&asm::VLQ_JUST_ABOVE_I32_MAX);
    out(
        bytes,
        true,
        FeatureSet::from_iter([Feature::VlqAboveI32Max]),
    )
}

/// Type code 9 (`SUnsignedBigInt`) as an inline constant in a PRE-V3 (v0
/// header) tree. Bug #21: `embeddableV5` lacks code 9, so the reference
/// rejects it at the type layer (not later at the value read). The tree's v0
/// header scopes the gate, so the node rejects to match.
fn unsigned_bigint_pre_v3(_rng: &mut Rng) -> GenOutput {
    // 00 (v0 header) 09 (SUnsignedBigInt type code) 01 00 (a 1-byte value, never
    // reached — decode_type errors on code 9 before the value read).
    let bytes = vec![0x00, 0x09, 0x01, 0x00];
    out(
        bytes,
        false,
        FeatureSet::from_iter([Feature::UnsignedBigIntTypePreV3]),
    )
}

/// A `Relation2` operator over two boolean constants in the compact `0x85`
/// form. Bug #12: `93 85 03` = `Eq(Const(true), Const(true))`. Both node and
/// reference emit/read this packed form, so it round-trips.
fn relation2_compact_bool_pair(rng: &mut Rng) -> GenOutput {
    // Relation2 opcodes: 0x8F..0x94 (Lt..Neq), 0xEC/0xED (BinOr/BinAnd), 0xF4.
    let op = match rng.below(6) {
        0 => 0x8F,
        1 => 0x90,
        2 => 0x91,
        3 => 0x92,
        4 => 0x93,
        _ => 0x94,
    };
    let packed = rng.byte() & 0x03; // low 2 bits = (left, right)
    let bytes = vec![0x00, op, 0x85, packed];
    out(
        bytes,
        true,
        FeatureSet::from_iter([Feature::Relation2CompactBoolPair]),
    )
}

/// A `Const(SGroupElement)` whose 33 bytes are an off-curve compressed point
/// (`0x02`/`0x03` prefix, x = all `0xFF` > field prime). Bug #4: the bare codec
/// accepts (curve-check deferred); the reference curve-checks at deserialize.
fn off_curve_group_element(rng: &mut Rng) -> GenOutput {
    let ge = asm::off_curve_group_element(rng);
    // Sometimes as a bare SGroupElement constant (07 <ge>), sometimes as a
    // ProveDlog SigmaProp (08 CD <ge>) so it also hits the sigma-boolean path.
    let mut bytes = vec![0x00];
    if rng.coin() {
        bytes.push(0x07);
        bytes.extend_from_slice(&ge);
    } else {
        bytes.extend_from_slice(&[0x08, 0xCD]);
        bytes.extend_from_slice(&ge);
    }
    out(
        bytes,
        false,
        FeatureSet::from_iter([Feature::OffCurveGroupElement]),
    )
}
