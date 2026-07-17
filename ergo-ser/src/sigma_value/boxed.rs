//! Nested `SBox`-constant handling: structurally skipping / validating the
//! inner ErgoTree (the crate's strongest circular-dependency point — it
//! calls back into [`crate::ergo_tree`]) and capturing the box bytes
//! opaquely for round-trip fidelity.

use ergo_primitives::reader::{ReadError, VlqReader};

use super::{read_constant, SigmaValue};

/// Skip past an ErgoTree in the reader without fully parsing the body.
///
/// For size-delimited trees: reads header + size + body_bytes (skips body).
/// For non-size-delimited trees: reads header + constants (if cseg) +
///   falls back to the full opcode parser for the body.
/// Parse a SIZELESS nested box script's constants + body to find the box-field
/// boundary, and apply the v6/EIP-50 pre-v3 method gate. Returns SOFT errors
/// (`InvalidData`) — the caller (`skip_ergo_tree`) hardens them via
/// [`harden_sizeless_inner_error`], because for a sizeless inner tree Scala
/// re-raises any inner `ValidationException` as a `SerializerException`. The
/// rule-1012 / `version != 0` check is done by the caller BEFORE this (Scala
/// runs `CheckHeaderSizeBit` ahead of constants, outside the inner `try`).
fn parse_sizeless_inner_box_script(
    r: &mut VlqReader,
    version: u8,
    cseg: bool,
) -> Result<(), ReadError> {
    // A nested box-constant script is its OWN deserialization scope, parsed on the
    // SAME reader as the enclosing tree, so two pieces of version-scoped reader state
    // are saved/set/restored around the ENTIRE inner parse — segregated constants AND
    // body — so the inner tree uses ITS OWN header version, not the outer's:
    //  - `ergo_tree_version`: the embeddable type-code gate must resolve against the
    //    inner version (a sizeless inner is v0). An `SUnsignedBigInt` (code 9) type in
    //    a v0 script nested under a v3+ outer tree must reject, whether it appears in a
    //    segregated constant or the body; without scoping it inherits the outer
    //    `Some(3)` and is accepted — accept-invalid. It is therefore set BEFORE the
    //    constants are read. (The has_size nested path recurses through
    //    `read_ergo_tree_tracking_wrap`, which scopes its own inner reader.)
    //  - the unresolved-method checkpoint: an unresolved method inside the inner tree
    //    is hard-rejected here (Scala re-raises the sizeless `ValidationException` as a
    //    `SerializerException`), NOT folded into the enclosing size-delimited tree's
    //    wrap, so it must not mark the OUTER reader's checkpoint.
    let saved_checkpoint = r.unresolved_method_checkpoint();
    let saved_version = r.ergo_tree_version();
    r.set_ergo_tree_version(Some(version));
    let result = parse_sizeless_inner_box_script_scoped(r, version, cseg);
    r.set_ergo_tree_version(saved_version);
    r.restore_unresolved_method_checkpoint(saved_checkpoint);
    result
}

/// Inner of [`parse_sizeless_inner_box_script`], run with the reader's
/// `ergo_tree_version` already set to the inner tree's version so the embeddable
/// type gate applies to the segregated constants and the body alike.
fn parse_sizeless_inner_box_script_scoped(
    r: &mut VlqReader,
    version: u8,
    cseg: bool,
) -> Result<(), ReadError> {
    let mut constants = Vec::new();
    if cseg {
        // Nested-tree `deserializeConstants` reads the count via `getUInt().toInt`
        // (non-exact), same as the top-level tree: an overflowed count wraps
        // negative and yields ZERO constants in Scala, not a hard rejection.
        let count = r.get_uint_to_i32()?.max(0) as usize;
        if count > 4096 {
            return Err(ReadError::InvalidData(format!(
                "unreasonable constant count in inner tree: {count}"
            )));
        }
        constants.reserve(count.min(4096));
        for _ in 0..count {
            constants.push(read_constant(r)?);
        }
    }
    let body = crate::opcode::parse_body(r, version)?;
    // Sizeless inner tree => version 0 (the caller ran rule 1012 first), so methods
    // resolve against the v5 registry; a v6-only OR genuinely-unknown id makes Scala
    // throw a method-resolution `ValidationException`, hardened by the caller.
    if let Some((type_id, method_id)) = crate::opcode::find_unresolved_v5_method(&body) {
        return Err(ReadError::InvalidData(format!(
            "nested box script: method ({type_id}, {method_id}) does not resolve in the v5 registry for tree version {version}"
        )));
    }
    // CheckDeserializedScriptIsSigmaProp (rule 1001): the inner box script is
    // deserialized with `checkType = true` too, so a determinable non-SigmaProp
    // root (bare Boolean/Long `Const`, `TrueLeaf`/`FalseLeaf`, or a placeholder
    // resolving to one) is a sizeless `ValidationException` Scala re-raises as a
    // `SerializerException` — hardened by the caller. Mirrors the box-reader
    // `check_sigma_prop_root` gate for the top-level tree.
    if let Some(tpe) = crate::ergo_tree::determinable_root_type_of(&body, &constants) {
        if tpe != crate::sigma_type::SigmaType::SSigmaProp {
            return Err(ReadError::InvalidData(format!(
                "nested box script: sizeless root has type {tpe:?}, expected SigmaProp (CheckDeserializedScriptIsSigmaProp, rule 1001)"
            )));
        }
    }
    Ok(())
}

/// Harden a sizeless inner box-script parse failure to [`ReadError::HardReject`]
/// (a Scala `SerializerException`), so an enclosing SIZE-DELIMITED outer tree
/// re-raises it rather than soft-fork-wrapping it into an `UnparsedErgoTree`.
/// Already-hard errors (`DepthLimitExceeded`, nested `HardReject`) pass through.
fn harden_sizeless_inner_error(e: ReadError) -> ReadError {
    match e {
        e @ (ReadError::DepthLimitExceeded { .. } | ReadError::HardReject(_)) => e,
        other => ReadError::HardReject(format!("nested sizeless box script: {other}")),
    }
}

fn skip_ergo_tree(r: &mut VlqReader) -> Result<(), ReadError> {
    let tree_start = r.position();
    let header = r.get_u8()?;
    let version = header & 0x07;
    let has_size = header & 0x08 != 0;
    let cseg = header & 0x10 != 0;

    if has_size {
        // Size-delimited: Scala deserializes the nested box's proposition INLINE via
        // `ErgoTreeSerializer.deserializeErgoTree`, which is structure-delimited —
        // the declared size does NOT bound the parse or advance the reader on
        // success (it leaves the reader at the actual body end, where the box's
        // next field is read). Rewind to before the header and delegate to
        // `read_ergo_tree_tracking_wrap`, which (since #123) advances `r` by the
        // true body length on success or to Scala's `numBytes` boundary on a wrap,
        // forwards the inner tree's group elements onto `r` (the JVM curve-checks an
        // off-curve point inside a nested box while deserializing it), and re-raises
        // `DepthLimitExceeded` / `HardReject` so they escape the enclosing tree's
        // soft-fork wrap. The box stays opaque for round-trip fidelity via the
        // caller's preserved bytes; only the reader advance moves here. (The old
        // `get_bytes(size)` skip desynced the box tail when size != body length.)
        r.set_position(tree_start);
        let (sub_tree, _) = crate::ergo_tree::read_ergo_tree_tracking_wrap(r)?;
        // A future-version inner tree is HARD-rejected (Scala's
        // `VersionContext.withVersions` throws a `SerializerException` the enclosing
        // tree does not catch). `read_ergo_tree` wrapped it leniently; reject here —
        // UNLESS the reader is decoding a TRUSTED, already-validated stored box
        // (`VlqReader::trusted`), where a legacy high-version opaque NESTED tree
        // must round-trip exactly like the top-level case (the indexer re-reading
        // its own `INDEXED_BOX` rows). The structural parse above already advanced
        // the reader, so only the acceptance check is skipped.
        if !r.is_trusted() {
            crate::ergo_tree::check_tree_version_supported(&sub_tree)?;
        }
    } else {
        // SIZELESS nested box script (an `SBox` constant's inner ErgoTree). This
        // mirrors Scala `deserializeErgoTree` for `sizeOpt = None`, where the
        // exception CLASS decides whether an enclosing SIZE-DELIMITED outer tree
        // wraps the failure (`UnparsedErgoTree`) or is rejected by it:
        //
        // - `CheckHeaderSizeBit` (rule 1012, `version != 0`) runs in
        //   `deserializeHeaderAndSize`, BEFORE constants/body and OUTSIDE the
        //   inner `try` — so it is a `ValidationException` the OUTER tree's catch
        //   WRAPS. It is checked FIRST (before any constant is read) and kept
        //   SOFT (`InvalidData`): a size-delimited outer wraps it; a sizeless
        //   outer / register / standalone read rejects.
        // - Everything else (constants, body, and the v6/EIP-50 method check) is
        //   INSIDE Scala's inner `try`. For `sizeOpt = None`, EVERY
        //   `ValidationException` thrown there is re-raised as a hard
        //   `SerializerException`, which the outer catch does NOT catch — so all
        //   soft failures of the inner parse are hardened to `HardReject`
        //   (already-hard `DepthLimitExceeded` / nested `HardReject` pass
        //   through). A size-delimited outer must reject, not wrap.
        //
        // Size-delimited nested trees are kept opaque above — Scala wraps an
        // inner failure as `UnparsedErgoTree`, rejected only on spend, which the
        // evaluator's spend-path gate handles.
        if version != 0 && !r.is_trusted() {
            return Err(ReadError::InvalidData(format!(
                "nested box script: ErgoTree version {version} requires the size bit (CheckHeaderSizeBit, rule 1012)"
            )));
        }
        parse_sizeless_inner_box_script(r, version, cseg).map_err(harden_sizeless_inner_error)?;
    }
    Ok(())
}

/// Maximum serialized box size (`SigmaConstants.MaxBoxSize = 4 * 1024`). Scala's
/// `ErgoBoxCandidate.parseBodyWithIndexedDigests` bounds the candidate body to
/// `position + MaxBoxSize` via the reader's position limit.
const MAX_BOX_SIZE: usize = 4 * 1024;

/// Read an inline SBox constant by structurally advancing through the box
/// fields, then capturing the raw bytes as opaque data for roundtrip fidelity.
///
/// The candidate body (value..registers) is bounded to `start + MaxBoxSize`
/// exactly as Scala's `parseBodyWithIndexedDigests` sets `positionLimit`: a read
/// that BEGINS past the window trips `CheckPositionLimit` (rule 1014) and the box
/// parse errors — so e.g. `deserializeTo[Box]` of an over-large token list is
/// rejected. The limit is restored before the ref tail (txId + index), which
/// Scala reads after `positionLimit` is reset, so the tail is unbounded.
pub(super) fn read_opaque_box(r: &mut VlqReader) -> Result<SigmaValue, ReadError> {
    let start = r.position();

    let previous_limit = r.position_limit();
    r.set_position_limit(Some(start + MAX_BOX_SIZE));
    let body = (|| {
        // value (nanoErgs) - VLQ u64
        let _ = r.get_u64()?;
        // ergo tree - skip past without full body parse (for size-delimited trees)
        skip_ergo_tree(r)?;
        // creation height - VLQ u32
        let _ = r.get_u32_exact()?;
        // token count + tokens (full 32-byte token IDs for inline constants)
        let tc = r.get_u8()? as usize;
        for _ in 0..tc {
            let _ = r.get_bytes(32)?; // token id
            let _ = r.get_u64()?; // amount
        }
        // additional registers
        let _ = crate::register::read_registers(r)?;
        Ok::<(), ReadError>(())
    })();
    // Restore on both the success and error paths (Scala previousPositionLimit).
    r.set_position_limit(previous_limit);
    body?;

    // transaction id (32 bytes) + output index (VLQ u16) — outside the window.
    let _ = r.get_bytes(32)?;
    let _ = r.get_u16()?;

    let end = r.position();
    let raw = r.data_slice(start, end).to_vec();
    Ok(SigmaValue::OpaqueBoxBytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{read_value, write_value};
    use ergo_primitives::writer::VlqWriter;

    // ----- helpers -----

    fn roundtrip_value(tpe: &SigmaType, val: &SigmaValue) {
        let mut w = VlqWriter::new();
        write_value(&mut w, tpe, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_value(&mut r, tpe).unwrap();
        assert!(r.is_empty(), "leftover bytes for {tpe:?}");
        assert_eq!(&decoded, val);
    }

    /// Full box bytes (candidate ++ txId ++ index) with `n` single-byte-amount
    /// tokens. candidate length = 3(value)+7(tree)+1(height)+1(tokenCount)
    /// +33*n+1(regCount); n=124 crosses 4096, n=120 stays under.
    fn box_bytes_with_tokens(n: usize) -> Vec<u8> {
        let mut w = VlqWriter::new();
        w.put_u64(1_000_000); // value
        w.put_bytes(&[0x10, 0x01, 0x01, 0x01, 0xD1, 0x73, 0x00]); // minimal tree
        w.put_u32(0); // creation height
        w.put_u8(n as u8); // token count
        for i in 0..n {
            w.put_bytes(&[(i & 0xff) as u8; 32]); // token id
            w.put_u64(1); // amount
        }
        w.put_u8(0); // register count
        w.put_bytes(&[0x11; 32]); // transaction id
        w.put_u16(0); // output index
        w.result()
    }

    /// Scala `ErgoBoxCandidate.parseBodyWithIndexedDigests` sets
    /// `positionLimit = position + ErgoBox.MaxBoxSize` (4096) before reading the
    /// candidate body. A token loop read that BEGINS past 4096 trips
    /// CheckPositionLimit (rule 1014) and the box parse errors.
    #[test]
    fn opaque_box_over_4096_candidate_errors() {
        let bytes = box_bytes_with_tokens(124); // candidate 4105 > 4096
        let mut r = VlqReader::new(&bytes);
        let res = read_value(&mut r, &SigmaType::SBox);
        assert!(
            res.is_err(),
            "124-token box candidate (> 4096) must error, got {res:?}"
        );
    }

    /// A candidate at/under the 4096 window parses normally (no read begins past
    /// the limit).
    #[test]
    fn opaque_box_under_4096_candidate_ok() {
        let bytes = box_bytes_with_tokens(120); // candidate 3973 < 4096
        let mut r = VlqReader::new(&bytes);
        let res = read_value(&mut r, &SigmaType::SBox);
        assert!(
            res.is_ok(),
            "120-token box candidate (< 4096) must parse, got {res:?}"
        );
    }

    #[test]
    fn sbox_constant_with_over_depth_tree_hard_rejects() {
        // An SBox inline constant whose proposition is a SIZE-DELIMITED tree
        // nested past MaxTreeDepth must hard-reject (Scala deserializes the
        // embedded box tree via ErgoTreeSerializer, which depth-checks it) — not
        // be accepted as opaque bytes by skip_ergo_tree.
        let mut tree = vec![0x08u8]; // header: v0, has_size
        let mut tree_body = vec![0xB1u8; 150]; // SizeOf chain (over-depth)
        tree_body.push(0xA3); // Height leaf
        ergo_primitives::vlq::encode_vlq_into(tree_body.len() as u64, &mut tree);
        tree.extend_from_slice(&tree_body);
        let mut box_bytes = vec![0x01u8]; // box value = 1 nanoErg
        box_bytes.extend_from_slice(&tree); // proposition (parse fails here)
        let mut r = VlqReader::new(&box_bytes);
        let err = read_value(&mut r, &SigmaType::SBox).unwrap_err();
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { .. }),
            "SBox-embedded over-depth tree must hard-reject, got {err:?}"
        );
    }

    /// Assemble standalone SBox-constant bytes (value + proposition + box tail).
    fn sbox_constant_bytes(tree: &[u8]) -> Vec<u8> {
        let mut w = VlqWriter::new();
        w.put_u64(1_000_000); // value
        w.put_bytes(tree); // proposition
        w.put_u32(100); // creation height
        w.put_u8(0); // token count
        w.put_u8(0); // register count
        w.put_bytes(&[0u8; 32]); // tx id
        w.put_u16(0); // output index
        w.result()
    }

    /// A SIZELESS pre-v3 (`0x10` = v0 + const-seg) `SBox` constant whose
    /// proposition carries the `SGlobal.none[T]` v6 PropertyCall is REJECTED at
    /// deserialize. With no size bit, `skip_ergo_tree` walks the body through
    /// the full parser to find the box-field boundary, and the mirrored gate
    /// rejects the v6-only method exactly as Scala's box deserialize does
    /// (method resolution against the pre-v3 method table; no size bit means the
    /// `ValidationException` is re-raised as a `SerializerException`). This is an
    /// accept-invalid the box-script-reader gate alone would miss: a box
    /// embedded as a CONSTANT is never spent, so the evaluator's spend-path gate
    /// never fires on its inner tree. The rejection is a `HardReject` so it
    /// survives an enclosing size-delimited tree's soft-fork wrap.
    #[test]
    fn sbox_constant_sizeless_v6_tree_rejected() {
        let tree = hex::decode("1000d1efe6db6a0add04").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        let err = read_value(&mut r, &SigmaType::SBox).expect_err(
            "sizeless pre-v3 SBox constant carrying a v6 method must reject at deserialize",
        );
        assert!(
            matches!(&err, ReadError::HardReject(m) if m.contains("does not resolve in the v5 registry")),
            "got {err:?}",
        );
    }

    /// A sizeless v0 nested `SBox`-constant script carrying the v6-only embeddable
    /// type `SUnsignedBigInt` (code 9) must be gated against the INNER tree's own
    /// version (0), NOT the enclosing tree's. We pre-set the reader's
    /// `ergo_tree_version` to `Some(3)` (a v3+ outer context); the nested parse must
    /// still reject code 9 because its own header is v0. Without the per-nested-tree
    /// version scoping, the inner script would inherit `Some(3)` and wrongly accept —
    /// accept-invalid.
    #[test]
    fn sbox_constant_sizeless_unsigned_bigint_gated_by_inner_version() {
        // The v6-only type must reject under the INNER v0 version whether it appears
        // inline in the body OR as a segregated constant (which is read BEFORE the
        // body) — both are within the nested tree's own version scope.
        let inners = [
            // inline: header 0x00 + Const(SUnsignedBigInt) (type 0x09 + len 0x00).
            "000900",
            // const-segregated: header 0x10 (v0+cseg) + count 0x01 + segregated
            // Const(SUnsignedBigInt) (09 00) + body ConstPlaceholder(0) (73 00).
            "100109007300",
        ];
        for inner_hex in inners {
            let inner = hex::decode(inner_hex).unwrap();
            let box_bytes = sbox_constant_bytes(&inner);
            let mut r = VlqReader::new(&box_bytes);
            r.set_ergo_tree_version(Some(3)); // simulate a v3+ enclosing tree
            let err = read_value(&mut r, &SigmaType::SBox).expect_err(&format!(
                "sizeless v0 nested script ({inner_hex}) with SUnsignedBigInt must reject under inner version 0",
            ));
            assert!(
                matches!(&err, ReadError::HardReject(m) if m.contains("SUnsignedBigInt")),
                "inner {inner_hex}: got {err:?}",
            );
        }
    }

    /// A sizeless `version != 0` nested box script violates rule 1012
    /// (`CheckHeaderSizeBit`). Read standalone (no enclosing tree), the
    /// rejection propagates and the box is rejected. The error is a SOFT
    /// `InvalidData` (Scala throws this as a `ValidationException`), so an
    /// enclosing size-delimited tree would instead WRAP it — see
    /// `ergo_tree::tests::nested_box_constant_rule1012_in_size_delimited_outer_wraps`.
    #[test]
    fn sbox_constant_sizeless_nonzero_version_rejected() {
        // header 0x01 = version 1, no size bit, no const-seg; body `d3`.
        let tree = hex::decode("01d3").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        let err = read_value(&mut r, &SigmaType::SBox)
            .expect_err("sizeless version!=0 nested box script must reject (rule 1012)");
        assert!(
            matches!(&err, ReadError::InvalidData(m) if m.contains("rule 1012")),
            "got {err:?}",
        );
    }

    /// A SIZELESS valid `SBox` constant round-trips: `skip_ergo_tree` has no
    /// blob length to skip by, so it walks the non-size-delimited body to find
    /// the box-field boundary — the box fields after the tree must still land
    /// exactly. Uses a minimal v0 `sigmaProp(true)` proposition (no v6 method),
    /// proving the gate does not over-reject a legitimate sizeless tree.
    #[test]
    fn sbox_constant_sizeless_valid_tree_roundtrips() {
        let tree = hex::decode("0008d3").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        let val =
            read_value(&mut r, &SigmaType::SBox).expect("valid sizeless SBox constant must parse");
        assert!(r.is_empty(), "box-field boundary must land exactly at end");
        assert_eq!(val, SigmaValue::OpaqueBoxBytes(box_bytes));
        roundtrip_value(&SigmaType::SBox, &val);
    }

    /// A nested `SBox` constant whose inner ErgoTree is a HIGH-VERSION
    /// size-delimited (opaque) tree (header `0xcd` = version 5, has_size) is
    /// HARD-rejected by the strict consensus reader (`check_tree_version_supported`
    /// inside `skip_ergo_tree`), but a TRUSTED reader accepts it. This is the
    /// nested mirror of the top-level legacy-box case: a stored box can carry such
    /// a tree nested in a register / `SBox` constant / context-extension, and the
    /// indexer (re-reading its OWN already-validated data with a trusted reader)
    /// must round-trip it instead of halting the rebuild. The trusted flag rides
    /// on the reader, so it reaches this nested gate without any param threading.
    #[test]
    fn sbox_constant_high_version_opaque_tree_strict_rejects_trusted_accepts() {
        // Real nested-tree bytes shape from mainnet box gi 5918565: header 0xcd
        // (version 5, has_size), declared size 7, 7 opaque body bytes.
        let tree = hex::decode("cd07021a8e6f59fd4a").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);

        // Strict (untrusted) consensus reader rejects the future-version tree.
        let mut strict = VlqReader::new(&box_bytes);
        read_value(&mut strict, &SigmaType::SBox)
            .expect_err("strict reader must reject a version-5 nested box-constant tree");

        // Trusted reader (already-validated stored data) accepts it, landing the
        // box-field boundary exactly.
        let mut trusted = VlqReader::new(&box_bytes).trusted();
        let val = read_value(&mut trusted, &SigmaType::SBox)
            .expect("trusted reader must accept a stored high-version nested opaque tree");
        assert!(
            trusted.is_empty(),
            "box-field boundary must land exactly at end"
        );
        assert_eq!(val, SigmaValue::OpaqueBoxBytes(box_bytes));
    }

    /// A nested `SBox`-constant whose inner script is a sizeless Boolean-root tree
    /// (`00 01 73` = Const(SBoolean, true)) must REJECT, matching Scala's
    /// `CheckDeserializedScriptIsSigmaProp` (rule 1001) on the inner root — the
    /// same gate `check_sigma_prop_root` enforces for a top-level box script. The
    /// valid SigmaProp-root case above proves this does not over-reject.
    #[test]
    fn sbox_constant_sizeless_non_sigmaprop_root_rejects() {
        let tree = hex::decode("000173").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        assert!(
            read_value(&mut r, &SigmaType::SBox).is_err(),
            "nested sizeless Boolean-root box script must reject (rule 1001)"
        );
    }

    /// `harden_sizeless_inner_error` turns ANY soft inner-parse failure of a
    /// sizeless inner box tree into a `HardReject` (Scala re-raises every inner
    /// `ValidationException` as a `SerializerException` for `sizeOpt = None`),
    /// while already-hard errors pass through unchanged.
    #[test]
    fn harden_sizeless_inner_error_classifies() {
        // Soft `InvalidData` (e.g. unknown opcode / bad type / v6 method) -> hard.
        assert!(matches!(
            super::harden_sizeless_inner_error(ReadError::InvalidData("x".into())),
            ReadError::HardReject(_)
        ));
        // Already-hard errors are preserved.
        assert!(matches!(
            super::harden_sizeless_inner_error(ReadError::DepthLimitExceeded { max: 110 }),
            ReadError::DepthLimitExceeded { .. }
        ));
        assert!(matches!(
            super::harden_sizeless_inner_error(ReadError::HardReject("y".into())),
            ReadError::HardReject(_)
        ));
    }

    /// A nested `SBox`-constant SIZE-delimited inner tree is skipped by STRUCTURE,
    /// not the declared size (matching Scala's inline `deserializeErgoTree`): a
    /// tree declaring size 5 but a 2-byte body (`08d3` = sigmaProp(true)),
    /// followed by trailing box bytes, must advance only past the 2-byte body so
    /// the box's next field is read from the right offset. The old
    /// `get_bytes(size)` skip would consume 5 bytes (two of the trailing field),
    /// desyncing the box.
    #[test]
    fn skip_ergo_tree_size_delimited_advances_by_body_not_declared_size() {
        // header 08 | size 05 | body 08d3 (2 bytes) | trailing aabbcc (3 bytes)
        let bytes = hex::decode("080508d3aabbcc").unwrap();
        let mut r = VlqReader::new(&bytes);
        super::skip_ergo_tree(&mut r).expect("nested size-delimited tree must skip");
        assert_eq!(
            r.remaining(),
            3,
            "must advance by the 2-byte body, leaving the 3 trailing box bytes"
        );
    }
}
