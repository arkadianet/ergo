//! Low-level wire-byte assembly primitives shared by the structured
//! generators. These place values at real grammar positions the `ergo-ser`
//! writers would never emit (non-canonical VLQ, out-of-band field values,
//! ill-formed sub-fields), which is exactly what a structure-aware fuzzer
//! needs to reach the SER bug surface.

use crate::rng::Rng;

/// Append an unsigned VLQ (Scorex `putULong`/`putUInt`/`putUShort` — all
/// unsigned LEB128, LSB group first, high bit = continuation) to `out`.
/// Matches [`ergo_primitives::writer::VlqWriter::put_u64`] byte-for-byte, so a
/// value we hand-assemble here reads back identically through the node's
/// reader.
pub fn put_vlq(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            return;
        }
    }
}

/// The VLQ encoding of `0x8000_0000` = `i32::MAX + 1`. This is the exact wire
/// value that distinguishes the two Scala readers: `getUIntExact` REJECTS it
/// (arithmetic overflow) while `getUInt().toInt` wraps it to a negative `Int`
/// and ACCEPTS it. Placing it at a count / id position is bug #20's surface.
pub const VLQ_JUST_ABOVE_I32_MAX: [u8; 5] = [0x80, 0x80, 0x80, 0x80, 0x08];

/// `STypeVar` type-descriptor code (`TypeSerializer`, Scala code 103).
pub const STYPEVAR_CODE: u8 = 103;

/// A UTF-8-encoded lone high surrogate (U+D800): ILL-FORMED UTF-8 that a
/// strict `from_utf8` rejects but the JVM's `new String(bytes, UTF_8)` lossily
/// maps to U+FFFD. Placing it as an `STypeVar` name is bug #1's surface.
pub const ILL_FORMED_UTF8_NAME: [u8; 3] = [0xED, 0xA0, 0x80];

/// The compressed secp256k1 generator point (a VALID on-curve group element),
/// used to build on-manifold constants / scripts the reference accepts.
pub const VALID_GENERATOR_GE: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

/// A 33-byte compressed group element with a `0x02`/`0x03` parity prefix and an
/// x coordinate of all-`0xFF` — which is `> p` (the secp256k1 field prime), so
/// it can never decompress to a curve point. This is bug #4's surface: the bare
/// codec accepts the 33 bytes, but the reference's `GroupElementSerializer`
/// curve-checks at deserialize and rejects.
pub fn off_curve_group_element(rng: &mut Rng) -> [u8; 33] {
    let mut ge = [0xFFu8; 33];
    ge[0] = if rng.coin() { 0x02 } else { 0x03 };
    ge
}

/// A valid sizeless v0 `SigmaProp` tree body that the reference accepts as a
/// script (`Const(SSigmaProp, TrivialProp(true))`): the two bytes AFTER the
/// tree header — type code `0x08` (SSigmaProp) + sigma-boolean tag `0xD3`
/// (TrivialProp true).
pub const SIGMAPROP_TRUE_BODY: [u8; 2] = [0x08, 0xD3];

/// Full valid sizeless v0 TrueProp tree (`header 0x00` + [`SIGMAPROP_TRUE_BODY`]).
pub const TREE_TRUE_PROP: [u8; 3] = [0x00, 0x08, 0xD3];

/// Full valid sizeless v0 FalseProp tree.
pub const TREE_FALSE_PROP: [u8; 3] = [0x00, 0x08, 0xD2];
