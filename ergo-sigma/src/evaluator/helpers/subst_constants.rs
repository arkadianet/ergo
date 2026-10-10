//! `subst_constants` — the `SubstConstants` (0x74) template-constant
//! substitution, depending on `serialize`'s `value_to_typed_sigma`.

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
#[cfg(test)]
pub(crate) fn subst_constants(
    script_bytes: &[u8],
    positions: &[i32],
    new_values: &[Value],
    is_v3_ergo_tree: bool,
) -> Result<(Vec<u8>, usize), EvalError> {
    subst_constants_versioned(
        script_bytes,
        positions,
        new_values,
        is_v3_ergo_tree,
        if is_v3_ergo_tree { 3 } else { 2 },
    )
}

pub(crate) fn subst_constants_versioned(
    script_bytes: &[u8],
    positions: &[i32],
    new_values: &[Value],
    is_v3_ergo_tree: bool,
    activated_script_version: u8,
) -> Result<(Vec<u8>, usize), EvalError> {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::sigma_value::{read_constant, write_constant};
    let is_jit_activated = (activated_script_version as i8) >= 2;

    // Scala lifts every new value to a Constant before it reads the template
    // or the positions, so an unliftable value fails the call even when no
    // position substitutes it.
    for value in new_values {
        check_liftable(value, is_v3_ergo_tree, is_jit_activated)?;
    }

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
    // substituteConstants reads only the template header/size, so the
    // template version is not checked. deserializeConstants still parses
    // every nested SBox under the executing activated version, even when no
    // position is substituted. Its tree-version failure is a hard error.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ErgoTreeSerializer.scala#L245-L291
    r.set_activated_script_version(Some(activated_script_version));
    let header = r.get_u8().map_err(parse_err)?;
    let has_size = header & 0x08 != 0;
    // `deserializeHeaderAndSize` runs `CheckHeaderSizeBit` (rule 1012) on the
    // template header: a non-zero version without the size bit throws a
    // ValidationException, which nothing catches during evaluation.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ErgoTreeSerializer.scala#L216-L219
    if header & 0x07 != 0 && !has_size {
        return Err(EvalError::EvaluationValidation {
            rule_id: 1012,
            args: vec![header],
        });
    }
    let constant_segregation = header & 0x10 != 0;
    if has_size {
        // Original declared size, read like Scala's `deserializeHeaderAndSize`
        // (`getUInt().toInt`): anything up to u32::MAX parses, and the value is
        // never used. It is recomputed on output for v3+ trees and dropped
        // pre-v3 (bug-for-bug with Scala's pre-v6 substituteConstants).
        r.get_uint_to_i32().map_err(parse_err)?;
    }
    let mut constants: Vec<(SigmaType, SigmaValue)> = Vec::new();
    if constant_segregation {
        // Scala `deserializeConstants` reads the count as `getUInt().toInt`
        // and treats a count that wraps negative as no constants.
        let n = r.get_uint_to_i32().map_err(parse_err)?.max(0) as usize;
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
    // substituteConstants parses every constant with the JVM serializers, which
    // decode each GroupElement (also inside SigmaProp, Box and Header values):
    // an off-curve point throws even when no constant is substituted.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ErgoTreeSerializer.scala#L320-L411
    crate::evaluator::dispatch::validate_recorded_group_elements(r.group_elements())?;
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
    // Pre-JIT serialization writes the count even without segregation.
    if constant_segregation || !is_jit_activated {
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
            // change the constant's type. Liftable values carry their exact
            // type (an Option, whose None would surface as `SOption(SAny)`,
            // never gets here), so the comparison is exact.
            if *template_type != new_type {
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
    if is_jit_activated && is_v3_ergo_tree && has_size {
        w.put_u32((const_bytes.len() + tree_bytes.len()) as u32);
    }
    w.put_bytes(&const_bytes);
    w.put_bytes(&tree_bytes);

    Ok((w.result(), n_constants))
}

/// `Platform.liftToConstant` on the JVM: the runtime values `substConstants`
/// can turn into constants. Tuples, Options, Unit and the context objects have
/// no case and make `toArrayOfConstants` throw. Header, PreHeader and
/// UnsignedBigInt lift only in v3 trees, String only before v3, and a Box only
/// once JIT is active. A collection lifts whatever its element type.
/// <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/jvm/src/main/scala/sigma/Platform.scala#L16-L64>
fn check_liftable(
    value: &Value,
    is_v3_ergo_tree: bool,
    is_jit_activated: bool,
) -> Result<(), EvalError> {
    let liftable = match value {
        Value::Byte(_)
        | Value::Short(_)
        | Value::Int(_)
        | Value::Long(_)
        | Value::BigInt(_)
        | Value::Bool(_)
        | Value::GroupElement(_)
        | Value::SigmaProp(_)
        | Value::AvlTree(_)
        | Value::CollGeneric(..)
        | Value::CollLegacyPair(..)
        | Value::CollBool(_)
        | Value::CollBytes(_)
        | Value::Tokens(_)
        | Value::CollInt(_)
        | Value::CollLong(_)
        | Value::CollShort(_)
        | Value::CollSigmaProp(_)
        | Value::CollBox(_)
        | Value::BoxCollection(_)
        | Value::CollHeader(_) => true,
        Value::Header(_) | Value::PreHeader | Value::UnsignedBigInt(_) => is_v3_ergo_tree,
        Value::Str(_) => !is_v3_ergo_tree,
        Value::SelfBox | Value::BoxRef { .. } | Value::InlineBox(_) => is_jit_activated,
        Value::Unit
        | Value::Tuple(_)
        | Value::Opt(_)
        | Value::Global
        | Value::Context
        | Value::Func { .. } => false,
    };
    if liftable {
        Ok(())
    } else {
        Err(EvalError::RuntimeException(
            "substConstants: new value cannot be lifted to a constant",
        ))
    }
}
