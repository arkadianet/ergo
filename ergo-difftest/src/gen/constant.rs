//! Structure-aware generator for the `constant` SER surface
//! (`read_constant` = type descriptor + value data).

use crate::gen::asm;
use crate::gen::{Feature, FeatureSet, GenMode, GenOutput};
use crate::rng::Rng;

const SURFACE: &str = "constant";

/// Generate one `constant` input: ~45% on-manifold, ~55% adversarial.
pub fn gen(rng: &mut Rng) -> GenOutput {
    if rng.below(100) < 45 {
        gen_valid(rng)
    } else {
        gen_adversarial(rng)
    }
}

/// On-manifold: a valid constant of a primitive / group-element / sigma type.
pub fn gen_valid(rng: &mut Rng) -> GenOutput {
    let bytes: Vec<u8> = match rng.below(8) {
        0 => vec![0x01, 0x01],                   // SBoolean true
        1 => vec![0x01, 0x00],                   // SBoolean false
        2 => vec![0x02, rng.byte()],             // SByte
        3 => sint_bytes(rng.next_u64() as i32),  // SInt
        4 => slong_bytes(rng.next_u64() as i64), // SLong
        5 => vec![0x08, 0xD3],                   // SSigmaProp TrivialProp(true)
        6 => {
            // SGroupElement with the valid generator point.
            let mut b = vec![0x07];
            b.extend_from_slice(&asm::VALID_GENERATOR_GE);
            b
        }
        // Coll[Byte] of a few bytes: type 0x0E (Coll+SByte code 2 -> 12+2), u16
        // length, then bytes.
        _ => {
            let n = rng.below(6);
            let mut b = vec![0x0E];
            asm::put_vlq(&mut b, n as u64); // Coll length is a VLQ u16
            for _ in 0..n {
                b.push(rng.byte());
            }
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

fn sint_bytes(v: i32) -> Vec<u8> {
    let mut b = vec![0x04];
    // zig-zag i32
    let zz = ((v << 1) ^ (v >> 31)) as u32 as u64;
    asm::put_vlq(&mut b, zz);
    b
}

fn slong_bytes(v: i64) -> Vec<u8> {
    let mut b = vec![0x05];
    let zz = ((v << 1) ^ (v >> 63)) as u64;
    asm::put_vlq(&mut b, zz);
    b
}

fn gen_adversarial(rng: &mut Rng) -> GenOutput {
    match rng.below(2) {
        0 => off_curve_group_element(rng),
        _ => sstring_length_above_i32_max(rng),
    }
}

/// A `Const(SGroupElement)` with an off-curve compressed point. Bug #4: the
/// bare codec reads the 33 bytes without a curve check; the reference rejects.
fn off_curve_group_element(rng: &mut Rng) -> GenOutput {
    let ge = asm::off_curve_group_element(rng);
    let mut bytes = vec![0x07];
    bytes.extend_from_slice(&ge);
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid: false,
        mode: GenMode::Adversarial,
        features: FeatureSet::from_iter([Feature::OffCurveGroupElement]),
    }
}

/// A `Const(SString)` whose length prefix VLQ is just above `i32::MAX`. Bug
/// #20: the value length is read with `getUIntExact`, which rejects the
/// overflow — both node and reference reject, but the generator must be able
/// to place the value to exercise the boundary.
fn sstring_length_above_i32_max(_rng: &mut Rng) -> GenOutput {
    // 0x66 = SString type code (102), then the overflowing length VLQ.
    let mut bytes = vec![0x66];
    bytes.extend_from_slice(&asm::VLQ_JUST_ABOVE_I32_MAX);
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid: false,
        mode: GenMode::Adversarial,
        features: FeatureSet::from_iter([Feature::VlqAboveI32Max]),
    }
}
