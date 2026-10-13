#![allow(clippy::style, clippy::complexity, clippy::perf)]
//! Regression tests: `UpdateLongBy` must reject sums that leave `i64` rather
//! than acting on a wrapped value.
//!
//! The old value is read from the proof and the delta comes from the
//! operation, so the sum can leave the range in either direction. A plain `+`
//! panics in debug and wraps in release, and the sign tests then ran on the
//! wrapped result: a negative overflow could store a large positive value, or
//! -- when the wrap landed exactly on zero -- remove the key outright. Both are
//! wrong accepts, not just crashes.
//!
//! The reference adds with `Math.addExact` (scrypto 3.0.0,
//! `UpdateLongBy.$anonfun$updateFn$7`, offset 169). The resulting
//! `ArithmeticException` is `NonFatal`, so the `Try` around the operation
//! converts it to a failure — which is what `Err` reproduces here.

use bytes::Bytes;
use ergo_avltree::operation::*;

fn key() -> ADKey {
    Bytes::copy_from_slice(&[1u8; 32])
}

fn value(v: i64) -> ADValue {
    Bytes::copy_from_slice(&v.to_be_bytes())
}

fn update_by(delta: i64, old: i64) -> anyhow::Result<Option<ADValue>> {
    Operation::UpdateLongBy(KeyDelta { key: key(), delta }).update_fn(Some(value(old)))
}

#[test]
fn negative_overflow_is_err_not_a_large_positive() {
    // MIN + (-1) wraps to MAX, which the sign test used to accept and store.
    let res = update_by(-1, i64::MIN);
    assert!(res.is_err(), "negative overflow must be rejected");
}

#[test]
fn negative_overflow_landing_on_zero_is_err_not_a_removal() {
    // MIN + MIN wraps to exactly 0, which used to be read as "remove the key".
    let res = update_by(i64::MIN, i64::MIN);
    assert!(res.is_err(), "overflow to zero must not remove the key");
}

#[test]
fn positive_overflow_is_err() {
    // MAX + 1 wraps to MIN; the old code rejected this via the negative test,
    // i.e. for the wrong reason. It must still be rejected.
    let res = update_by(1, i64::MAX);
    assert!(res.is_err(), "positive overflow must be rejected");
}

#[test]
fn in_range_sums_are_unaffected() {
    assert_eq!(update_by(3, 5).unwrap(), Some(value(8)));
    // Reaching exactly zero still removes the key.
    assert_eq!(update_by(-5, 5).unwrap(), None);
    // A genuinely negative result is still rejected.
    assert!(update_by(-6, 5).is_err());
}
