//! `subst_constants` — the `SubstConstants` (0xD9) template-constant
//! substitution, depending on `serialize`'s `value_to_typed_sigma` and
//! `type_infer`'s `sigma_type_compatible`.

use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use super::*;
use crate::evaluator::types::*;

/// Replace constants in a serialized ErgoTree at given positions, mirroring
/// Scala `ErgoTreeSerializer.substituteConstants` (JIT path). Returns
/// `(result_bytes, n_constants)` where `n_constants` is the number of constants
/// in the input tree — the count Scala feeds to `SubstConstants`'s
/// `PerItemCost(100, 100, 1)`.
///
/// Faithful to the reference in three consensus-critical ways:
/// - The tree BODY is kept as opaque raw bytes (`deserializeHeaderWithTreeBytes`
///   → `treeBytes` → `putBytes(treeBytes)`); it is never re-parsed or
///   re-serialized. Only the constants section is rewritten. Parsing and
///   re-serializing the body would risk a non-identity round trip — a chain
///   split — and reject trees whose body our parser cannot fully decode.
/// - Out-of-range positions are SKIPPED, not rejected: Scala
///   `getPositionsBackref` ignores `pos < 0 || pos >= nConstants` and the first
///   reference to a given index wins. A non-segregated tree thus returns
///   unchanged with `n_constants = 0`.
/// - A parse failure, a positions/newValues length mismatch, or a type mismatch
///   (`require(c.tpe == newConst.tpe)`) raises `RuntimeException` (Scala
///   throws), surfacing as `errored` — not the `not-implemented` an
///   `UnsupportedOpcode` would produce.
pub(crate) fn subst_constants(
    script_bytes: &[u8],
    positions: &[i32],
    new_values: &[Value],
    is_v3_ergo_tree: bool,
) -> Result<(Vec<u8>, usize), EvalError> {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::sigma_value::{read_constant, write_constant};

    // Scala `require(positions.length == newVals.length)`.
    if positions.len() != new_values.len() {
        return Err(EvalError::RuntimeException(
            "substConstants: positions and newValues length mismatch",
        ));
    }

    let parse_err = |_| EvalError::RuntimeException("substConstants: malformed ErgoTree bytes");
    let reser_err =
        |_| EvalError::RuntimeException("substConstants: constant re-serialization failed");

    // deserializeHeaderWithTreeBytes: header [+ size] + segregated constants,
    // leaving the body as opaque raw bytes.
    let mut r = VlqReader::new(script_bytes);
    let header = r.get_u8().map_err(parse_err)?;
    let has_size = header & 0x08 != 0;
    let constant_segregation = header & 0x10 != 0;
    if has_size {
        // Original declared size; recomputed on output for v3+ trees and
        // dropped pre-v3 (bug-for-bug with Scala's pre-v6 substituteConstants).
        r.get_u32_exact().map_err(parse_err)?;
    }
    let mut constants: Vec<(SigmaType, SigmaValue)> = Vec::new();
    if constant_segregation {
        let n = r.get_u32_exact().map_err(parse_err)? as usize;
        for _ in 0..n {
            let (tpe, val) = read_constant(&mut r).map_err(parse_err)?;
            // Scala deserializes the constants under the executing
            // VersionContext: `DataSerializer.deserialize(SHeader)` is gated on
            // `isV3OrLaterErgoTreeVersion` (pre-v3 falls through to the base
            // deserializer and throws). Our `read_constant` is version-agnostic,
            // so a pre-v3 tree carrying an SHeader constant — reachable via
            // crafted `scriptBytes` — must be rejected here even when that
            // constant is not the one being substituted (else we accept where
            // the reference errors). The check is VALUE-based (per materialized
            // header): an empty `Coll[Header]` constant materializes no header
            // and is accepted on any version, matching Scala.
            if !is_v3_ergo_tree && val.contains_header() {
                return Err(EvalError::RuntimeException(
                    "substConstants: SHeader constant requires ErgoTree version >= 3",
                ));
            }
            // SOption is gated identically to SHeader (CoreDataSerializer matches
            // SOption only at isV3OrLaterErgoTreeVersion); a pre-v3 tree carrying
            // a materialized Option constant in crafted scriptBytes is rejected.
            // Value-based: an empty Coll[Option] materializes none and is accepted.
            if !is_v3_ergo_tree && val.contains_option() {
                return Err(EvalError::RuntimeException(
                    "substConstants: SOption constant requires ErgoTree version >= 3",
                ));
            }
            constants.push((tpe, val));
        }
    }
    let tree_bytes = script_bytes[r.position()..].to_vec();
    let n_constants = constants.len();

    // getPositionsBackref: backref[i] = index into `positions` that targets
    // constant i, or -1. Out-of-range positions are ignored; first reference
    // wins.
    let mut backref = vec![-1i64; n_constants];
    for (i_pos, &pos) in positions.iter().enumerate() {
        if pos >= 0 && (pos as usize) < n_constants && backref[pos as usize] == -1 {
            backref[pos as usize] = i_pos as i64;
        }
    }

    // Re-serialize the constants section: the segregation count (only when
    // segregated) followed by each constant — substituted where a position
    // references it, original otherwise.
    let mut const_w = VlqWriter::new();
    if constant_segregation {
        const_w.put_u32(n_constants as u32);
    }
    for (i, (template_type, original_value)) in constants.iter().enumerate() {
        if backref[i] >= 0 {
            let new_value = &new_values[backref[i] as usize];
            // No ReductionContext on the SubstConstants path: a context-backed
            // box as a substituted constant stays unsupported (pre-existing
            // residual; SGlobal.serialize handles the box case with `Some`).
            let (new_type, sv) = value_to_typed_sigma(new_value, None)?;
            // Scala `require(c.tpe == newConst.tpe)`: a substitution cannot
            // change the constant's type. `sigma_type_compatible` bridges the
            // SAny wildcard our type recovery surfaces for `Opt(None)` / empty
            // collections back to the template's concrete type.
            if !sigma_type_compatible(template_type, &new_type) {
                return Err(EvalError::RuntimeException(
                    "substConstants: new value type does not match the constant type",
                ));
            }
            // Re-serializing a Header constant runs the same version-gated
            // DataSerializer.serialize(SHeader) (which throws pre-v3); a pre-v3
            // executing ErgoTree must reject it. Same `errored` class as the
            // template-constant gate above — both mirror a Scala throw.
            if sv.contains_header() && !is_v3_ergo_tree {
                return Err(EvalError::RuntimeException(
                    "substConstants: SHeader substitution requires ErgoTree version >= 3",
                ));
            }
            // Same v3 gate for a substituted Option value
            // (DataSerializer.serialize(SOption) throws pre-v3) — covers e.g. a
            // non-empty Coll[Option] replacement of an empty (accepted) template.
            if sv.contains_option() && !is_v3_ergo_tree {
                return Err(EvalError::RuntimeException(
                    "substConstants: SOption substitution requires ErgoTree version >= 3",
                ));
            }
            // Serialize with the TEMPLATE type (== the new value's type by the
            // check above), matching Scala and preserving the template's
            // concrete descriptor where our recovery would degrade to
            // `SOption(SAny)`.
            write_constant(&mut const_w, template_type, &sv).map_err(reser_err)?;
        } else {
            write_constant(&mut const_w, template_type, original_value).map_err(reser_err)?;
        }
    }
    let const_bytes = const_w.result();

    // Compose the result: header [+ recomputed size for v3+] + constants + body.
    let mut w = VlqWriter::new();
    w.put_u8(header);
    if is_v3_ergo_tree && has_size {
        w.put_u32((const_bytes.len() + tree_bytes.len()) as u32);
    }
    w.put_bytes(&const_bytes);
    w.put_bytes(&tree_bytes);

    Ok((w.result(), n_constants))
}
