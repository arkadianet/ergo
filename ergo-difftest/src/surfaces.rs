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
fn rw_check<T, D, E>(input: &[u8], decode: D, encode: E) -> Outcome
where
    T: PartialEq + std::fmt::Debug,
    D: Fn(&mut VlqReader) -> Result<T, ReadError>,
    E: Fn(&mut VlqWriter, &T) -> Result<(), WriteError>,
{
    let mut r1 = VlqReader::new(input);
    let v1 = match decode(&mut r1) {
        Ok(v) => v,
        Err(_) => return Outcome::Rejected, // rejecting malformed input is correct
    };

    // Re-encode the parsed value. An intentional WriteError (e.g. a name/count
    // that overflows the single-byte wire field) is allowed — the JVM throws on
    // the same overflow — so it is not a bug.
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
            return Outcome::bug(format!("re-decode of own output failed: {e:?}"), &b1);
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

/// read-only no-panic check: outcome only distinguishes Ok/Err; a panic is
/// caught by the runner and reported as a bug.
fn ro_check<T, D>(input: &[u8], decode: D) -> Outcome
where
    D: Fn(&mut VlqReader) -> Result<T, ReadError>,
{
    let mut r = VlqReader::new(input);
    match decode(&mut r) {
        Ok(_) => Outcome::Accepted,
        Err(_) => Outcome::Rejected,
    }
}

macro_rules! rw {
    ($name:literal, $decode:path, $encode:path) => {
        Surface {
            name: $name,
            run: Box::new(|b| rw_check(b, $decode, $encode)),
        }
    };
}

macro_rules! ro {
    ($name:literal, $decode:path) => {
        Surface {
            name: $name,
            run: Box::new(|b| ro_check(b, $decode)),
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
        ad_proofs, ergo_box, ergo_tree, extension, header, input, sigma_type, sigma_value,
        transaction,
    };

    let all: Vec<Surface> = vec![
        // ----- read + write fixed point -----
        rw!("sigma_type", sigma_type::read_type, sigma_type::write_type),
        rw!("constant", sigma_value::read_constant, write_constant_pair),
        rw!(
            "ergo_tree",
            ergo_tree::read_ergo_tree,
            ergo_tree::write_ergo_tree
        ),
        rw!(
            "ergo_box_candidate",
            ergo_box::read_ergo_box_candidate,
            ergo_box::write_ergo_box_candidate
        ),
        rw!(
            "ergo_box",
            ergo_box::read_ergo_box,
            ergo_box::write_ergo_box
        ),
        rw!(
            "transaction",
            transaction::read_transaction,
            transaction::write_transaction
        ),
        // ----- read-only no-panic -----
        ro!("header", header::read_header),
        ro!("context_extension", input::read_context_extension),
        ro!("input", input::read_input),
        ro!("extension", extension::read_extension),
        ro!("ad_proofs", ad_proofs::read_ad_proofs),
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
            rw_check(&[5], decode_u8, encode_drifting),
            Outcome::Bug(_)
        ));
    }

    // ----- and must NOT false-positive on a real fixed point -----

    #[test]
    fn rw_check_accepts_fixed_point() {
        assert_eq!(
            rw_check(&[5], decode_u8, encode_identity),
            Outcome::Accepted
        );
    }

    #[test]
    fn rw_check_rejects_empty_without_bug() {
        assert_eq!(rw_check(&[], decode_u8, encode_identity), Outcome::Rejected);
    }
}
