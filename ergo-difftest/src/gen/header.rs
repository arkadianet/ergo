//! Structure-aware generator for the `header` SER surface.
//!
//! The block header's version byte is the sole adversarial knob here (bug #8):
//! Scala treats it as a SIGNED `Byte`, so a value in `0x80..=0xFF` is negative,
//! which changes the `unparsed_bytes` grammar gate and hence the PoW-solution
//! offset. The generator places version bytes across that range so the
//! differential can confirm node and reference agree on the signed grammar.

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{write_header, Header};

use crate::gen::asm;
use crate::gen::{Feature, FeatureSet, GenMode, GenOutput};
use crate::rng::Rng;

const SURFACE: &str = "header";

/// Generate one header input: ~50% on-manifold, ~50% adversarial.
pub fn gen(rng: &mut Rng) -> GenOutput {
    if rng.coin() {
        gen_valid(rng)
    } else {
        gen_adversarial(rng)
    }
}

fn fill32(rng: &mut Rng) -> [u8; 32] {
    let mut a = [0u8; 32];
    for b in a.iter_mut() {
        *b = rng.byte();
    }
    a
}

fn fill33(rng: &mut Rng) -> [u8; 33] {
    let mut a = [0u8; 33];
    for b in a.iter_mut() {
        *b = rng.byte();
    }
    a
}

fn v2_solution(rng: &mut Rng) -> AutolykosSolution {
    let mut nonce = [0u8; 8];
    for b in nonce.iter_mut() {
        *b = rng.byte();
    }
    AutolykosSolution::V2 {
        pk: GroupElement::from_bytes(asm::VALID_GENERATOR_GE),
        nonce,
    }
}

/// On-manifold: a valid v2-v4 header, built and serialized by the real writer.
pub fn gen_valid(rng: &mut Rng) -> GenOutput {
    let version = 2 + (rng.below(3) as u8); // 2..=4 (V2 Autolykos, no unparsed)
    let header = Header {
        version,
        parent_id: ModifierId::from_bytes(fill32(rng)),
        ad_proofs_root: Digest32::from_bytes(fill32(rng)),
        transactions_root: Digest32::from_bytes(fill32(rng)),
        state_root: ADDigest::from_bytes(fill33(rng)),
        timestamp: rng.next_u64() >> 1,
        extension_root: Digest32::from_bytes(fill32(rng)),
        n_bits: rng.next_u64() as u32,
        height: (rng.next_u64() & 0x00ff_ffff) as u32,
        votes: [0, 0, 0],
        unparsed_bytes: vec![],
        solution: v2_solution(rng),
    };
    let mut w = VlqWriter::new();
    write_header(&mut w, &header).expect("valid header writes");
    GenOutput {
        surface: SURFACE,
        bytes: w.result(),
        intended_valid: true,
        mode: GenMode::OnManifold,
        features: FeatureSet::from_iter([Feature::OnManifoldValid]),
    }
}

/// Adversarial: hand-assemble a header with a version byte in `0x80..=0xFF`.
/// As a signed `Byte` this is negative, so `version > InitialVersion(1)` is
/// FALSE and no `unparsed_bytes` section is read — the solution follows the
/// votes directly. The node's signed comparison matches the reference. Bug #8.
fn gen_adversarial(rng: &mut Rng) -> GenOutput {
    let version = 0x80u8 | (rng.byte() & 0x7f); // guaranteed high bit set
    let mut b = Vec::new();
    b.push(version);
    b.extend_from_slice(&fill32(rng)); // parent_id
    b.extend_from_slice(&fill32(rng)); // ad_proofs_root
    b.extend_from_slice(&fill32(rng)); // transactions_root
    b.extend_from_slice(&fill33(rng)); // state_root
    asm::put_vlq(&mut b, rng.next_u64() >> 1); // timestamp
    b.extend_from_slice(&fill32(rng)); // extension_root
    b.extend_from_slice(&(rng.next_u64() as u32).to_be_bytes()); // n_bits (4 raw BE)
    asm::put_vlq(&mut b, rng.next_u64() & 0x00ff_ffff); // height
    b.extend_from_slice(&[0, 0, 0]); // votes
                                     // Signed version < 0, so NO unparsed_bytes section. Solution = V2 (pk+nonce).
    b.extend_from_slice(&asm::VALID_GENERATOR_GE); // solution pk
    for _ in 0..8 {
        b.push(rng.byte()); // solution nonce
    }
    GenOutput {
        surface: SURFACE,
        bytes: b,
        intended_valid: true,
        mode: GenMode::Adversarial,
        features: FeatureSet::from_iter([Feature::HeaderVersionHighBit]),
    }
}
