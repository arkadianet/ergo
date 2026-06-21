use ergo_primitives::reader::{ReadError, VlqReader};

use crate::sigma_type::{decode_type, read_type, SigmaType};
use crate::sigma_value::{read_value_at_depth, SigmaValue};

use super::types::{
    is_v3_only_method, method_explicit_type_args_count, opcode_pattern, ArgPattern, Body, Expr,
    IrNode, Payload, LAST_CONSTANT_CODE, MAX_EXPR_DEPTH,
};

/// Parse an ErgoTree body (single root expression) from bytes.
///
/// `tree_version` is the ErgoTree header version byte (`0..=3` in
/// real-world chains), threaded through the whole expression walk the
/// way Scala's `SigmaByteReader` exposes the version context to every
/// serializer. No body-wire SHAPE rule consults it: the `MethodCall`
/// explicit-type-args bytes are keyed on `(type_id, method_id)` alone
/// (see [`method_explicit_type_args_count`]), so callers without a
/// surrounding tree header (registers,
/// `DeserializeContext`/`DeserializeRegister` payloads) pass `0` and
/// still parse v6 method calls correctly without desyncing the stream.
/// It IS consulted for VALIDATION: pre-v3 inline `SHeader`/`SOption`
/// constants are rejected (see [`parse_expr`]); the version-0 sentinel
/// those headerless callers pass makes that rejection fire, which is
/// correct — the reference also rejects such values there (the constant
/// path via the v3 data gate, register/context vars via `CheckV6Type`).
pub fn parse_body(r: &mut VlqReader, tree_version: u8) -> Result<Body, ReadError> {
    parse_expr(r, 0, tree_version)
}

/// Parse a single expression from the byte stream.
///
/// `depth` guards against stack overflow on malicious input.
/// `_tree_version` — see [`parse_body`].
///
/// Public so that register values — which are serialized as arbitrary
/// evaluated expressions, not just plain constants — can be parsed.
pub fn parse_expr(r: &mut VlqReader, depth: usize, _tree_version: u8) -> Result<Expr, ReadError> {
    // `>=`: depth is 0-based here (root enters at 0), while Scala's shared
    // reader level is incremented BEFORE parsing each nested value, so Rust
    // `depth` == Scala `level - 1`. Rejecting at `depth >= MAX_EXPR_DEPTH`
    // therefore matches Scala's `level > MaxTreeDepth` boundary exactly.
    if depth >= MAX_EXPR_DEPTH {
        return Err(ReadError::DepthLimitExceeded {
            max: MAX_EXPR_DEPTH,
        });
    }
    let first = r.get_u8()?;

    if first <= LAST_CONSTANT_CODE {
        // Inline constant: first byte is a type code
        let tpe = decode_type(r, first)?;
        // Thread the current expression depth into the constant's value so a
        // nested SigmaProp continues the shared MaxTreeDepth budget (Scala's
        // single CoreByteReader.level across expr + value + SigmaBoolean).
        let val = read_value_at_depth(r, &tpe, depth)?;
        // SHeader value deserialization is gated on isV3OrLaterErgoTreeVersion
        // (Scala DataSerializer.deserialize(SHeader)). The gate fires PER
        // materialized header, so a constant that actually CARRIES a header
        // (incl. nested) in a pre-v3 (version < 3) tree is rejected by the
        // reference at parse time — but an empty Coll[Header] (no header
        // materialized) is accepted. Match that value-based behavior.
        if _tree_version < 3 && val.contains_header() {
            return Err(ReadError::InvalidData(format!(
                "SHeader value requires ErgoTree version >= 3 (got {_tree_version})"
            )));
        }
        // SOption data is likewise gated on isV3OrLaterErgoTreeVersion
        // (CoreDataSerializer matches `SOption` only when v3+, otherwise falls
        // through to CheckSerializableTypeCode and throws — for Some AND None).
        // This is the PARSE-TIME companion to the value-materialization gate in
        // `ergo-sigma` (`sigma_to_value_versioned`): here it rejects a
        // materialized Option constant that appears INLINE in the parsed tree
        // body, which carries the real tree version, so a pre-v3 (version < 3)
        // tree is rejected exactly as the reference rejects it. Plain register /
        // context-var constants do NOT reach this path (they are read via
        // `read_constant`); those are gated at materialization instead. An empty
        // Coll[Option] materializes no Option and is accepted here.
        if _tree_version < 3 && val.contains_option() {
            return Err(ReadError::InvalidData(format!(
                "SOption value requires ErgoTree version >= 3 (got {_tree_version})"
            )));
        }
        return Ok(Expr::Const { tpe, val });
    }

    let pattern = opcode_pattern(first)
        .ok_or_else(|| ReadError::InvalidData(format!("unknown opcode: 0x{first:02X}")))?;

    let next = depth + 1;
    let payload = match pattern {
        ArgPattern::Zero => Payload::Zero,

        ArgPattern::One => {
            let a = parse_expr(r, next, _tree_version)?;
            Payload::One(Box::new(a))
        }

        ArgPattern::Two => {
            let a = parse_expr(r, next, _tree_version)?;
            let b = parse_expr(r, next, _tree_version)?;
            Payload::Two(Box::new(a), Box::new(b))
        }

        ArgPattern::Three => {
            let a = parse_expr(r, next, _tree_version)?;
            let b = parse_expr(r, next, _tree_version)?;
            let c = parse_expr(r, next, _tree_version)?;
            Payload::Three(Box::new(a), Box::new(b), Box::new(c))
        }

        ArgPattern::Four => {
            let a = parse_expr(r, next, _tree_version)?;
            let b = parse_expr(r, next, _tree_version)?;
            let c = parse_expr(r, next, _tree_version)?;
            let d = parse_expr(r, next, _tree_version)?;
            Payload::Four(Box::new(a), Box::new(b), Box::new(c), Box::new(d))
        }

        ArgPattern::ValUse => {
            let id = r.get_u32_exact()?;
            Payload::ValUse { id }
        }

        ArgPattern::ConstPlaceholder => {
            let index = r.get_u32_exact()?;
            Payload::ConstPlaceholder { index }
        }

        ArgPattern::TaggedVar => {
            // Scala TaggedVariableSerializer.scala:16 reads `varId`
            // as a single signed `Byte`. Sign-extend through `i8`
            // into `i32` then reinterpret as `u32` so negative Scala
            // bytes (0x80..0xFF) round-trip with the same bit pattern
            // (`0xFFFF_FF80..0xFFFF_FFFF`). Reading VLQ-u32 would
            // alias raw byte only for `id < 128`.
            let id = (r.get_u8()? as i8) as u32;
            // Scala's SigmaByteReader always has constantStore set (even when
            // cseg=false it uses ConstantStore.empty), so the type is NEVER
            // read from the byte stream during deserialization.
            Payload::TaggedVar { id, tpe: None }
        }

        ArgPattern::ValDef => {
            let id = r.get_u32_exact()?;
            // Type is never serialized: Scala's reader always has a non-null
            // constantStore (ConstantStore.empty for non-cseg trees), so the
            // `if (r.constantStore == null) r.getType()` branch is never taken.
            let rhs = parse_expr(r, next, _tree_version)?;
            Payload::ValDef {
                id,
                tpe: None,
                rhs: Box::new(rhs),
            }
        }

        ArgPattern::FunDef => {
            let id = r.get_u32_exact()?;
            // Scala ValDefSerializer: the FunDef opcode (0xD7) carries
            // `nTpeArgs(u8)` + that many types between the id and the
            // rhs; each must be an STypeVar
            // (`r.getType().asInstanceOf[STypeVar]` — a non-typevar
            // type fails the cast and the whole parse).
            //
            // Scala reads nTpeArgs as a SIGNED Byte (`r.getByte()`) and passes
            // it to `safeNewArray[STypeVar](nTpeArgs)`, which throws
            // NegativeArraySizeException for a negative count. Wire bytes
            // 0x80..=0xFF are negative-as-signed, so they are an unconditional
            // deserialization failure — reject them rather than reading them as
            // an unsigned 128..=255 count and over-reading that many type args.
            let n_tpe_args_byte = r.get_u8()?;
            if n_tpe_args_byte > 0x7f {
                return Err(ReadError::InvalidData(format!(
                    "FunDef nTpeArgs {n_tpe_args_byte} is negative as a signed \
                     Byte (Scala safeNewArray rejects the negative count)"
                )));
            }
            let n_tpe_args = n_tpe_args_byte as usize;
            let mut tpe_args = Vec::with_capacity(n_tpe_args);
            for _ in 0..n_tpe_args {
                let t = read_type(r)?;
                if !matches!(t, SigmaType::STypeVar(_)) {
                    return Err(ReadError::InvalidData(format!(
                        "FunDef tpeArg must be an STypeVar, got {t:?}"
                    )));
                }
                tpe_args.push(t);
            }
            let rhs = parse_expr(r, next, _tree_version)?;
            Payload::FunDef {
                id,
                tpe: None,
                tpe_args,
                rhs: Box::new(rhs),
            }
        }

        ArgPattern::BlockValue => {
            let count = r.get_u32_exact()? as usize;
            if count > 10_000 {
                return Err(ReadError::InvalidData(format!(
                    "BlockValue item count too large: {count}"
                )));
            }
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(parse_expr(r, next, _tree_version)?);
            }
            let result = parse_expr(r, next, _tree_version)?;
            Payload::BlockValue {
                items,
                result: Box::new(result),
            }
        }

        ArgPattern::FuncValue => {
            let n_args = r.get_u32_exact()? as usize;
            if n_args > 10_000 {
                return Err(ReadError::InvalidData(format!(
                    "FuncValue arg count too large: {n_args}"
                )));
            }
            let mut args = Vec::with_capacity(n_args);
            for _ in 0..n_args {
                let id = r.get_u32_exact()?;
                // FuncValue always writes arg types (they define the function signature).
                let tpe = Some(read_type(r)?);
                args.push((id, tpe));
            }
            let body = parse_expr(r, next, _tree_version)?;
            Payload::FuncValue {
                args,
                body: Box::new(body),
            }
        }

        ArgPattern::PropertyCall => {
            let type_id = r.get_u8()?;
            let method_id = r.get_u8()?;
            let obj = parse_expr(r, next, _tree_version)?;
            // v6 checkpoint: Scala's `PropertyCallSerializer.parse` resolves the
            // method (and throws for a pre-v3 tree) right after `obj`. Mark the
            // group-element sideband here so the ErgoTree layer can forward
            // exactly the GEs Scala curve-checked before wrapping. Recorded
            // version-independently; the gate stays at the version-aware layer.
            if is_v3_only_method(type_id, method_id) {
                r.mark_v6_method_checkpoint();
            }
            // PropertyCall (0xDB) is the zero-args form, but a v6
            // property-call SMethod can still declare
            // `hasExplicitTypeArgs`: `SGlobal.none[T]` carries `Seq(tT)`.
            // Read the same explicit type-args block the MethodCall path
            // does. Scala's `PropertyCallSerializer.parse` reads these
            // right after `obj` when `method.hasExplicitTypeArgs`, with
            // no args list in between.
            let n_type_args = method_explicit_type_args_count(type_id, method_id);
            let mut type_args = Vec::with_capacity(n_type_args);
            for _ in 0..n_type_args {
                type_args.push(read_type(r)?);
            }
            Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(obj),
                args: vec![],
                type_args,
            }
        }

        ArgPattern::MethodCall => {
            let type_id = r.get_u8()?;
            let method_id = r.get_u8()?;
            let obj = parse_expr(r, next, _tree_version)?;
            let n_args = r.get_u32_exact()? as usize;
            if n_args > 10_000 {
                return Err(ReadError::InvalidData(format!(
                    "MethodCall arg count too large: {n_args}"
                )));
            }
            let mut args = Vec::with_capacity(n_args);
            for _ in 0..n_args {
                args.push(parse_expr(r, next, _tree_version)?);
            }
            // v6 checkpoint: Scala's `MethodCallSerializer.parse` resolves the
            // method (and throws for a pre-v3 tree) right after the receiver and
            // value args, before the explicit type args. Mark the group-element
            // sideband here (see the PropertyCall arm above).
            //
            // NOTE: this covers the v6/EIP-50-only methods. Scala wraps under
            // has_size for ANY method-resolution `ValidationException`, including
            // a genuinely unknown/future `(type_id, method_id)` pair — the same
            // GE-ordering shape. Catching those needs the full per-version method
            // registry and is a tracked follow-up.
            if is_v3_only_method(type_id, method_id) {
                r.mark_v6_method_checkpoint();
            }
            // v6 / EIP-50: methods whose Scala `SMethod` sets
            // `hasExplicitTypeArgs = true` write N type bytes after
            // the value args. Without this read the next opcode byte
            // is mis-aligned by N — silent failure further down the
            // body parse. See `method_explicit_type_args_count` doc
            // for the method set.
            let n_type_args = method_explicit_type_args_count(type_id, method_id);
            let mut type_args = Vec::with_capacity(n_type_args);
            for _ in 0..n_type_args {
                type_args.push(read_type(r)?);
            }
            Payload::MethodCall {
                type_id,
                method_id,
                obj: Box::new(obj),
                args,
                type_args,
            }
        }

        ArgPattern::ConcreteCollection => {
            let count = r.get_u16()? as usize;
            let elem_type = read_type(r)?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(parse_expr(r, next, _tree_version)?);
            }
            Payload::ConcreteCollection { elem_type, items }
        }

        ArgPattern::BoolCollection => {
            let n_bits = r.get_u16()? as usize;
            let n_bytes = n_bits.div_ceil(8);
            let packed = r.get_bytes(n_bytes)?;
            let mut bits = Vec::with_capacity(n_bits);
            for i in 0..n_bits {
                let byte_idx = i / 8;
                let bit_idx = i % 8; // LSB-first (matches Scala's putBits/getBits)
                bits.push((packed[byte_idx] >> bit_idx) & 1 == 1);
            }
            Payload::BoolCollection { bits }
        }

        ArgPattern::CreateTuple => {
            // Scala TupleSerializer.scala:28 reads count as signed
            // `Byte` and immediately calls `safeNewArray[SValue](size)`,
            // which throws on negative size — so Scala accepts only
            // 0..=127 in practice. The value-type writer puts an
            // unsigned byte (`putUByte`), so writes of 128..=255
            // serialize but fail on read. VLQ-u32 would alias raw byte
            // only for `count < 128` (the only range Scala accepts).
            let count_byte = r.get_u8()? as i8;
            if count_byte < 0 {
                return Err(ReadError::InvalidData(format!(
                    "Tuple item count negative ({count_byte}); Scala safeNewArray rejects"
                )));
            }
            let count = count_byte as usize;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(parse_expr(r, next, _tree_version)?);
            }
            Payload::Tuple { items }
        }

        ArgPattern::SelectField => {
            let input = parse_expr(r, next, _tree_version)?;
            let field_idx = r.get_u8()?;
            Payload::SelectField {
                input: Box::new(input),
                field_idx,
            }
        }

        ArgPattern::ExtractRegisterAs => {
            let input = parse_expr(r, next, _tree_version)?;
            let reg_id = r.get_u8()?;
            let tpe = read_type(r)?;
            Payload::ExtractRegisterAs {
                input: Box::new(input),
                reg_id,
                tpe,
            }
        }

        ArgPattern::GetVar => {
            let var_id = r.get_u8()?;
            let tpe = read_type(r)?;
            Payload::GetVar { var_id, tpe }
        }

        ArgPattern::DeserializeContext => {
            // Scala: type first, then id (DeserializeContextSerializer.scala:20-21)
            let tpe = read_type(r)?;
            let id = r.get_u8()?;
            Payload::DeserializeContext { id, tpe }
        }

        ArgPattern::DeserializeRegister => {
            let reg_id = r.get_u8()?;
            let tpe = read_type(r)?;
            let has_default = r.get_u8()?;
            let default = if has_default != 0 {
                Some(Box::new(parse_expr(r, next, _tree_version)?))
            } else {
                None
            };
            Payload::DeserializeRegister {
                reg_id,
                tpe,
                default,
            }
        }

        ArgPattern::SigmaCollection => {
            let count = r.get_u16()? as usize;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(parse_expr(r, next, _tree_version)?);
            }
            Payload::SigmaCollection { items }
        }

        ArgPattern::NoneValue => {
            let tpe = read_type(r)?;
            Payload::NoneValue { tpe }
        }

        ArgPattern::ByIndex => {
            let input = parse_expr(r, next, _tree_version)?;
            let index = parse_expr(r, next, _tree_version)?;
            let has_default = r.get_u8()?;
            let default = if has_default != 0 {
                Some(Box::new(parse_expr(r, next, _tree_version)?))
            } else {
                None
            };
            Payload::ByIndex {
                input: Box::new(input),
                index: Box::new(index),
                default,
            }
        }

        ArgPattern::NumericCast => {
            let input = parse_expr(r, next, _tree_version)?;
            let tpe = read_type(r)?;
            Payload::NumericCast {
                input: Box::new(input),
                tpe,
            }
        }

        ArgPattern::FuncApply => {
            let func = parse_expr(r, next, _tree_version)?;
            let n_args = r.get_u32_exact()? as usize;
            if n_args > 10_000 {
                return Err(ReadError::InvalidData(format!(
                    "FuncApply arg count too large: {n_args}"
                )));
            }
            let mut args = Vec::with_capacity(n_args);
            for _ in 0..n_args {
                args.push(parse_expr(r, next, _tree_version)?);
            }
            Payload::FuncApply {
                func: Box::new(func),
                args,
            }
        }

        // Relation2Serializer: when both args are boolean constants,
        // the Scala serializer emits 0x85 marker + 2 packed bits
        // instead of two child expressions. (Relation2Serializer.scala:41-46)
        ArgPattern::Relation2 => {
            if r.peek_u8().ok() == Some(0x85) {
                let _ = r.get_u8()?; // consume 0x85 marker
                let packed = r.get_u8()?;
                // Scala packs bits LSB-first: first bool at bit 0, second at bit 1.
                let left = packed & 1 == 1;
                let right = (packed >> 1) & 1 == 1;
                let a = Box::new(Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(left),
                });
                let b = Box::new(Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(right),
                });
                Payload::Two(a, b)
            } else {
                let a = Box::new(parse_expr(r, next, _tree_version)?);
                let b = Box::new(parse_expr(r, next, _tree_version)?);
                Payload::Two(a, b)
            }
        }
    };

    Ok(Expr::Op(IrNode {
        opcode: first,
        payload,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `SOption[SInt]` Some(5) inline constant: type code 0x28
    // (OPTION_CODE 0x24 + SInt 0x04), option tag 0x01 (Some), zig-zag SInt 0x0a
    // (= 5). This is the inline (non-segregated) form of the value carried by
    // the segregated `SOption.pre_v3_data_constant` conformance vector.
    const INLINE_SOME_INT: &[u8] = &[0x28, 0x01, 0x0a];

    #[test]
    fn inline_option_constant_rejected_in_pre_v3_tree_body() {
        // Tree-body inline constants are parsed with the real tree version, so
        // a materialized Option in a version-2 tree must be rejected exactly as
        // the reference rejects it (CoreDataSerializer falls through the v3-gated
        // SOption case to CheckSerializableTypeCode and throws). This is the
        // escape that the segregated-only `ergo_tree.rs` gate does NOT cover.
        for version in 0u8..3 {
            let mut r = VlqReader::new(INLINE_SOME_INT);
            let err = parse_expr(&mut r, 0, version).expect_err("pre-v3 inline Option must reject");
            assert!(
                matches!(&err, ReadError::InvalidData(m) if m.contains("SOption")),
                "version {version}: unexpected error {err:?}"
            );
        }
    }

    #[test]
    fn inline_option_constant_accepted_in_v3_tree_body() {
        let mut r = VlqReader::new(INLINE_SOME_INT);
        let expr = parse_expr(&mut r, 0, 3).expect("v3 inline Option must parse");
        match expr {
            Expr::Const { val, .. } => assert!(val.contains_option()),
            other => panic!("expected Const, got {other:?}"),
        }
    }

    // ----- FunDef nTpeArgs signed-byte bound -----

    /// Build a `FunDef` expr (opcode 0xD7): id=1, `n_tpe_args` STypeVar params,
    /// trivial `Const(SInt, 0)` rhs. The count byte is written RAW, so values
    /// 0x80..=0xFF reproduce a wire FunDef whose nTpeArgs is negative-as-signed
    /// — with that many valid type-arg entries present, so a non-rejecting
    /// parser reads them all and (wrongly) succeeds.
    fn fundef_expr_bytes(n_tpe_args: u8) -> Vec<u8> {
        let mut b = vec![0xD7, 0x01, n_tpe_args]; // FunDef, id=1 (VLQ), nTpeArgs
        for i in 0..(n_tpe_args as usize) {
            let name = format!("T{}", i + 1);
            b.push(0x67); // STYPEVAR_CODE
            b.push(name.len() as u8);
            b.extend_from_slice(name.as_bytes());
        }
        b.extend_from_slice(&[0x04, 0x00]); // rhs = Const(SInt, 0)
        b
    }

    #[test]
    fn fundef_ntpeargs_127_accepts() {
        // 0x7f is the signed-Byte max; Scala safeNewArray(127) succeeds.
        let bytes = fundef_expr_bytes(0x7f);
        let mut r = VlqReader::new(&bytes);
        parse_expr(&mut r, 0, 3).expect("nTpeArgs=127 must parse");
    }

    #[test]
    fn fundef_ntpeargs_128_rejects() {
        // 0x80 is negative as a signed Byte; Scala ValDefSerializer reads
        // getByte() -> safeNewArray(-128) -> NegativeArraySizeException, failing
        // the whole deserialize. We must reject too, not over-read 128 args.
        let bytes = fundef_expr_bytes(0x80);
        let mut r = VlqReader::new(&bytes);
        let err = parse_expr(&mut r, 0, 3).expect_err("nTpeArgs=128 must reject");
        assert!(
            matches!(&err, ReadError::InvalidData(m) if m.contains("nTpeArgs")),
            "unexpected error {err:?}"
        );
    }

    #[test]
    fn inline_option_constant_rejected_on_headerless_sentinel_path() {
        // Expression-form headerless payloads (Deserialize* / expression-form
        // register values) reach parse_expr with the version-0 sentinel; an
        // inline Option constant nested there is rejected (< 3). Plain register
        // constants do not reach this path — they go through `read_constant`
        // and are gated at materialization by `sigma_to_value_versioned`.
        let mut r = VlqReader::new(INLINE_SOME_INT);
        let err = parse_expr(&mut r, 0, 0).expect_err("headerless Option must reject");
        assert!(matches!(&err, ReadError::InvalidData(m) if m.contains("SOption")));
    }
}
