//! Oracle test for v3 / Sigma 6.0 ErgoTree containing an `SUnsignedBigInt`
//! constant — the script that stalled Rust testnet sync at h=210,076
//! (tx 1, input 0, box `2c0411b4…4713`, creationHeight 210,072).
//!
//! Extracted from the live v6.0.3RC1 Scala testnet node (the running
//! `127.0.0.1:9052` oracle). The constant value `fffffff…0364141` is
//! the secp256k1 curve order `n` — this contract embeds it for custom
//! sigma-protocol arithmetic.
//!
//! Lifecycle:
//! - Pre-fix: documents the current `UnsupportedConstant(SUnsignedBigInt)`
//!   failure so any regression flips a red test.
//! - Post-v6-carrier: assertions invert to expect a successful
//!   `Value::UnsignedBigInt(_)` round-trip and full-evaluator reduction
//!   to a `SigmaBoolean` (or a clearly-named next-stage missing-method
//!   error, depending on which v6 method the contract reaches first).

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::sigma_type::SigmaType;

const SCRIPT_HEX: &str =
    include_str!("../../test-vectors/testnet/v6_unsigned_bigint_script_h210076.hex");

fn parse_tree() -> ergo_ser::ergo_tree::ErgoTree {
    let hex = SCRIPT_HEX.trim();
    let bytes = hex::decode(hex).expect("fixture is valid hex");
    let mut r = VlqReader::new(&bytes);
    read_ergo_tree(&mut r).expect("ergoTree deserializer accepts the bytes")
}

#[test]
fn fixture_decodes_as_v3_segregated_tree() {
    let t = parse_tree();
    assert_eq!(t.version, 3, "the on-chain header byte 0x1b encodes v3");
    assert!(
        t.has_size,
        "header bit 3 is set — size-prefixed body required for soft-fork round-trip",
    );
    assert!(
        t.constant_segregation,
        "header bit 4 is set — constants live in a segregated table",
    );
    assert!(
        t.constants.len() >= 5,
        "the fixture's constants table carries at least the curve order \
         + generator-coords + 2-3 numeric scalars; got {}",
        t.constants.len(),
    );
}

/// Pins the **correct unsigned wire decoding** for SUnsignedBigInt
/// against the on-chain fixture. Scala's
/// `CoreDataSerializer.scala:36` uses `BigIntegers.fromUnsignedByteArray`
/// for `SUnsignedBigInt`, so bytes like the curve-order constant
/// `0xfffffff…0364141` decode as a positive integer with magnitude
/// equal to secp256k1's `n`. Regression test against the historic
/// signed-bytes bug.
///
/// Companion negative assertion: no SUnsignedBigInt should ever
/// decode with `Sign::Minus`. The wire reader at
/// `sigma_value.rs::read_unsigned_bigint_value` always lifts via
/// `from_bytes_be(Sign::Plus, _)`, and the carrier at
/// `helpers.rs::sigma_to_value` rejects a `Minus` BigInt as a
/// deserializer bug rather than silently re-aliasing.
#[test]
fn unsigned_bigint_wire_decodes_as_positive_unsigned_value() {
    let t = parse_tree();

    const SECP256K1_N_HEX: &str =
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    let mut found_curve_order = false;
    for (tpe, val) in &t.constants {
        if *tpe != SigmaType::SUnsignedBigInt {
            continue;
        }
        if let ergo_ser::sigma_value::SigmaValue::BigInt(n) = val {
            assert_ne!(
                n.sign(),
                num_bigint::Sign::Minus,
                "SUnsignedBigInt must never decode as a negative BigInt",
            );
            let (_sign, mag) = n.to_bytes_be();
            if hex::encode(&mag) == SECP256K1_N_HEX {
                found_curve_order = true;
            }
        }
    }
    assert!(
        found_curve_order,
        "the fixture's curve-order constant should decode as (Plus, n)",
    );
}

/// `sigma_to_value` must lift every `SUnsignedBigInt` constant into
/// the dedicated `Value::UnsignedBigInt` carrier (NOT alias through
/// `Value::BigInt`) so downstream v6 method dispatch can branch on
/// type identity. Mirrors Scala's `CUnsignedBigInt` /
/// `CBigInt` separation
/// (`core/.../sigma/data/CUnsignedBigInt.scala:13`).
#[test]
fn unsigned_bigint_constant_lifts_to_unsigned_bigint_carrier() {
    use ergo_sigma::evaluator::{sigma_to_value, Value};

    let t = parse_tree();
    let mut at_least_one = false;
    for (tpe, val) in &t.constants {
        if *tpe != SigmaType::SUnsignedBigInt {
            continue;
        }
        at_least_one = true;
        let lifted = sigma_to_value(tpe, val).expect(
            "post-fix: every well-formed SUnsignedBigInt constant lifts \
             into Value::UnsignedBigInt",
        );
        assert!(
            matches!(lifted, Value::UnsignedBigInt(_)),
            "expected Value::UnsignedBigInt, got {lifted:?}",
        );
        if let Value::UnsignedBigInt(n) = &lifted {
            assert_ne!(
                n.sign(),
                num_bigint::Sign::Minus,
                "the unsigned carrier's BigInt must be non-negative",
            );
        }
    }
    assert!(at_least_one, "fixture has no SUnsignedBigInt constants?");
}
