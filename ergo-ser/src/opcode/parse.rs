//! Oracle: test-vectors/scala/select_field_index_bounds.json

use ergo_primitives::reader::{ReadError, VlqReader};

use crate::sigma_type::{decode_type, read_type, SigmaType};
use crate::sigma_value::{read_value_at_depth, SigmaValue};

use super::types::{
    check_array_length, is_known_method, method_explicit_type_args_count, opcode_pattern,
    ArgPattern, Body, Expr, IrNode, Payload, LAST_CONSTANT_CODE, MAX_EXPR_DEPTH,
};

/// Parse an ErgoTree body (single root expression) from bytes.
///
/// `tree_version` is the ErgoTree header version byte (`0..=3` in
/// real-world chains), threaded through the whole expression walk the
/// way Scala's `VersionContext` scopes each deserializer. Headerless register,
/// extension and embedded-expression callers supply their ambient tree version.
/// Method wire shapes (including explicit type arguments) remain keyed on the
/// method ids; builder upcasts and the empty-argument assert use the version.
pub fn parse_body(r: &mut VlqReader, tree_version: u8) -> Result<Body, ReadError> {
    parse_expr(r, 0, tree_version)
}

/// Parse an embedded expression and retain the outcome of its deferred type read.
/// Constructor casts fail before charging; a deferred type cast is returned for
/// the caller to inspect after charging. Both use the same single parser walk.
/// <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala#L97-L126>
pub fn parse_body_for_substitution(
    r: &mut VlqReader,
    tree_version: u8,
) -> Result<(Body, super::ConstructorType), ReadError> {
    let mut types = ParseTypes {
        check_substitution_constructors: true,
        ..Default::default()
    };
    let expr = parse_typed_expr(r, 0, tree_version, &mut types, &mut Vec::new())?;
    let tpe = types.constructor_children.pop().unwrap().pop().unwrap();
    Ok((expr, tpe))
}

/// Parse a single expression from the byte stream.
///
/// `depth` guards against stack overflow on malicious input.
/// `_tree_version` — see [`parse_body`].
///
/// Public so that register values — which are serialized as arbitrary
/// evaluated expressions, not just plain constants — can be parsed.
pub fn parse_expr(r: &mut VlqReader, depth: usize, _tree_version: u8) -> Result<Expr, ReadError> {
    parse_typed_expr(
        r,
        depth,
        _tree_version,
        &mut ParseTypes::default(),
        &mut Vec::new(),
    )
}

struct ParseTypes<'a> {
    bindings: crate::ergo_tree::root_type::ValDefTypeStore,
    constants: &'a [(SigmaType, SigmaValue)],
    constructors: Option<super::ConstructorTypes>,
    check_substitution_constructors: bool,
    constructor_children: Vec<Vec<super::ConstructorType>>,
}

impl Default for ParseTypes<'_> {
    fn default() -> Self {
        Self {
            bindings: Default::default(),
            constants: &[],
            constructors: Some(Default::default()),
            constructor_children: vec![Vec::new()],
            check_substitution_constructors: false,
        }
    }
}

pub(crate) fn parse_body_with_constants(
    r: &mut VlqReader,
    version: u8,
    constants: &[(SigmaType, SigmaValue)],
) -> Result<Body, ReadError> {
    let mut types = ParseTypes {
        constants,
        ..Default::default()
    };
    let body = parse_typed_expr(r, 0, version, &mut types, &mut Vec::new())?;
    // deserializeErgoTree(checkType = true) requests the root's tpe. Filter's
    // receiver cast is deferred until that request; a parent with a fixed type
    // (such as BoolToSigmaProp) need not request its child's type at all.
    // Deliberately preserve this JVM laziness for consensus.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ErgoTreeSerializer.scala#L169-L174
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/transformers.scala#L117-L122
    types
        .constructor_children
        .last_mut()
        .unwrap()
        .pop()
        .unwrap()
        .map_err(super::ConstructorError::into_read_error)?;
    Ok(body)
}

fn parse_typed_expr(
    r: &mut VlqReader,
    depth: usize,
    version: u8,
    types: &mut ParseTypes<'_>,
    parent_types: &mut Vec<Option<SigmaType>>,
) -> Result<Expr, ReadError> {
    if types.constructors.is_some() {
        types.constructor_children.push(Vec::new());
    }
    let mut children = Vec::new();
    let expr = parse_node(r, depth, version, types, &mut children)?;
    let mut children = children.into_iter();
    let tpe = crate::ergo_tree::root_type::infer_node_type(
        &expr,
        &mut types.bindings,
        types.constants,
        true,
        true,
        &mut |child, _, _| match child {
            // Relation2's packed constants have no recursive parser call.
            Expr::Const { tpe, .. } => children.next().unwrap_or_else(|| Some(tpe.clone())),
            _ => children.next().flatten(),
        },
    );
    if let Some(constructors) = &mut types.constructors {
        let children = types.constructor_children.pop().unwrap();
        // The cached failed type read is forced only by constructors/builders
        // which actually inspect that child. This reuses the parser's metadata;
        // it does not walk the subtree again.
        let check_type_reads =
            types.check_substitution_constructors || children.iter().any(Result::is_err);
        if check_type_reads {
            super::check_rebuilt_constructor(&expr, &children)
                .map_err(super::ConstructorError::into_read_error)?;
        }
        // These are serializer/builder type reads, distinct from reflective
        // case-class construction. Preserve their direct exception class.
        // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala#L686-L703
        // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ConcreteCollectionSerializer.scala#L33-L39
        if let Expr::Op(node) = &expr {
            let reads_all = matches!(
                node.payload,
                Payload::ValDef { .. }
                    | Payload::FunDef { .. }
                    | Payload::MethodCall { .. }
                    | Payload::ConcreteCollection { .. }
            ) || (0x8F..=0x94).contains(&node.opcode);
            if reads_all && check_type_reads {
                for t in &children {
                    t.as_ref().map_err(|e| e.into_read_error())?;
                }
            }
            if check_type_reads && version < 3 && matches!(node.payload, Payload::ByIndex { .. }) {
                if let Some(Err(e)) = children.get(1) {
                    return Err(e.into_read_error());
                }
            }
        }
        let tpe = constructors.node_type_with_constants(&expr, &children, types.constants);
        types.constructor_children.last_mut().unwrap().push(tpe);
    }
    parent_types.push(tpe.filter(crate::ergo_tree::root_type::type_is_precise));
    // `ValDefSerializer` stores the binding once its rhs is parsed.
    if let Expr::Op(IrNode {
        payload: Payload::ValDef { id, .. } | Payload::FunDef { id, .. },
        ..
    }) = &expr
    {
        r.bind_val(*id);
    }
    Ok(expr)
}

fn parse_node(
    r: &mut VlqReader,
    depth: usize,
    _tree_version: u8,
    types: &mut ParseTypes<'_>,
    children: &mut Vec<Option<SigmaType>>,
) -> Result<Expr, ReadError> {
    // `>=`: depth is 0-based here (root enters at 0), while Scala's shared
    // reader level is incremented BEFORE parsing each nested value, so Rust
    // `depth` == Scala `level - 1`. Rejecting at `depth >= MAX_EXPR_DEPTH`
    // therefore matches Scala's `level > MaxTreeDepth` boundary exactly.
    //
    // `depth` is local to the tree being parsed, so it is measured from the
    // reader's nesting base: Scala's level lives on the reader and keeps
    // climbing when an `SBox` constant's box script re-enters this parser on
    // the SAME reader, rather than restarting at 0 (see
    // `VlqReader::nesting_depth_base`). The base is 0 for every top-level
    // parse, so this is inert outside a nested box script. The floor also
    // counts the levels degraded trees left open earlier on the reader.
    let effective_depth = r.depth_floor().saturating_add(depth);
    if effective_depth >= MAX_EXPR_DEPTH {
        return Err(ReadError::DepthLimitExceeded {
            max: MAX_EXPR_DEPTH,
        });
    }
    // `ValueSerializer.deserialize` holds one reader level for the node and
    // gives it back only when the node parses (ValueSerializer.scala:397-409).
    r.enter_level();
    let node = parse_node_value(r, depth, _tree_version, types, children)?;
    r.exit_level();
    Ok(node)
}

fn parse_node_value(
    r: &mut VlqReader,
    depth: usize,
    _tree_version: u8,
    types: &mut ParseTypes<'_>,
    children: &mut Vec<Option<SigmaType>>,
) -> Result<Expr, ReadError> {
    // `ValueSerializer.deserialize` peeks the first byte (`r.peekByte()`,
    // ValueSerializer.scala:399), which checks only the buffer bounds, not the
    // position limit: at the end of the input it throws a raw
    // `ArrayIndexOutOfBoundsException` (hard) even past the window. Only the
    // read that follows checks the limit (rule 1014).
    r.peek_u8()?;
    let first = r.get_u8()?;

    if first <= LAST_CONSTANT_CODE {
        // Inline constant: first byte is a type code
        let tpe = decode_type(r, first)?;
        // Thread the current expression depth into the constant's value so a
        // nested SigmaProp continues the shared MaxTreeDepth budget (Scala's
        // single CoreByteReader.level across expr + value + SigmaBoolean).
        let val = read_value_at_depth(r, &tpe, depth + 1)?;
        // Inside a tree the value reader applies the pre-v3 `SHeader` /
        // `SOption` data gates at the point Scala throws, against the tree
        // version the reader carries (`read_value_at_depth`). A headerless
        // payload (a register or context-extension expression, `Deserialize*`
        // bytes) has no tree version on the reader and is judged against the
        // version passed in, once the value is read: a Header is Scala's hard
        // `SerializerException`, an Option its rule-1009 `ValidationException`.
        if r.ergo_tree_version().is_none() && _tree_version < 3 {
            if val.contains_header() {
                return Err(ReadError::HardReject(format!(
                    "SHeader value requires ErgoTree version >= 3 (got {_tree_version})"
                )));
            }
            if val.contains_option() {
                return Err(ReadError::SigmaValidation {
                    rule_id: 1009,
                    args: vec![36],
                    message: format!(
                        "SOption value requires ErgoTree version >= 3 (got {_tree_version})"
                    ),
                });
            }
        }
        return Ok(Expr::Const { tpe, val });
    }

    // `TrueLeaf` / `FalseLeaf` are `ConstantNode`s in Scala (`values.scala:
    // 771-790`): the parser accepts the bare opcode, but the node it builds is
    // the Boolean constant, with `Constant.costKind`, and every write treats it
    // as one. Parse it as the constant so evaluation, typing and the canonical
    // re-encoding (`01 01` / `01 00`) all see the same node.
    if first == 0x7F || first == 0x80 {
        return Ok(Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(first == 0x7F),
        });
    }
    let pattern = opcode_pattern(first).ok_or_else(|| ReadError::SigmaValidation {
        rule_id: 1002,
        args: vec![first],
        message: format!("unknown opcode: 0x{first:02X}"),
    })?;

    let next = depth + 1;
    let payload = match pattern {
        ArgPattern::Zero => Payload::Zero,

        ArgPattern::One => {
            let a = parse_typed_expr(r, next, _tree_version, types, children)?;
            // OptionGet.tpe accesses SOption.elemType during construction.
            // Its ClassCastException is not a soft-fork ValidationException.
            if first == 0xe4 {
                if let Some(Some(tpe)) = children.last() {
                    if !matches!(tpe, SigmaType::SOption(_)) {
                        return Err(ReadError::ClassCast(format!(
                            "OptionGet input must be an option, got {tpe:?}"
                        )));
                    }
                }
            }
            check_numeric_operands(first, &children[children.len() - 1..])?;
            Payload::One(Box::new(a))
        }

        ArgPattern::Two => {
            let mut a = parse_typed_expr(r, next, _tree_version, types, children)?;
            let mut b = parse_typed_expr(r, next, _tree_version, types, children)?;
            // DeserializationSigmaBuilder deliberately stops auto-upcasting
            // arithmetic from tree v3. Earlier trees retain inserted Upcasts.
            // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala#L706-L711
            // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala#L750-L763
            if _tree_version < 3 && matches!(first, 0x99..=0x9A | 0x9C..=0x9E | 0xA1..=0xA2) {
                let num_children = children.len();
                let operand_types = &mut children[num_children - 2..];
                if let Some(target) = apply_upcast(&mut a, &mut b, operand_types) {
                    if types.constructors.is_some() {
                        let ct = types.constructor_children.last_mut().unwrap();
                        let len = ct.len();
                        ct[len - 2..].fill(Ok(Some(target)));
                    }
                }
            }

            check_numeric_operands(first, &children[children.len() - 2..])?;
            check_constructor_casts(first, &children[children.len() - 2..])?;
            Payload::Two(Box::new(a), Box::new(b))
        }

        ArgPattern::Three => {
            let a = parse_typed_expr(r, next, _tree_version, types, children)?;
            let b = parse_typed_expr(r, next, _tree_version, types, children)?;
            let c = parse_typed_expr(r, next, _tree_version, types, children)?;
            check_constructor_casts(first, &children[children.len() - 3..])?;
            Payload::Three(Box::new(a), Box::new(b), Box::new(c))
        }

        ArgPattern::Four => {
            let a = parse_typed_expr(r, next, _tree_version, types, children)?;
            let b = parse_typed_expr(r, next, _tree_version, types, children)?;
            let c = parse_typed_expr(r, next, _tree_version, types, children)?;
            let d = parse_typed_expr(r, next, _tree_version, types, children)?;
            Payload::Four(Box::new(a), Box::new(b), Box::new(c), Box::new(d))
        }

        ArgPattern::ValUse => {
            // Scala `ValUseSerializer` reads the id via `getUInt.toInt`
            // (ValUseSerializer.scala:13) — NOT `getUIntExact`. A value past
            // i32::MAX wraps to a negative `Int`. Read non-exact and preserve
            // the bit pattern, including when looking up a negative binding.
            let id = r.get_uint_to_i32()? as u32;
            // Scala's `valDefTypeStore` belongs to the reader and is never
            // reset, so an id bound by an earlier tree on the same reader,
            // including a nested box's script, resolves. Absence is conclusive
            // only while the reader has tracked every binding since Scala's
            // reader started; nested trees share that set.
            if r.tracks_val_bindings()
                && !r.is_val_bound(id)
                && !types.bindings.bindings.contains_key(&id)
            {
                return Err(ReadError::HardReject(format!(
                    "ValUse {id} has no preceding definition (Scala NoSuchElementException)"
                )));
            }
            Payload::ValUse { id }
        }

        ArgPattern::ConstPlaceholder => {
            let index = r.get_u32_exact()?;
            // ConstantPlaceholderSerializer.scala:20 looks up the type immediately.
            // ArrayIndexOutOfBoundsException escapes the size-delimited soft-fork wrap.
            if r.constant_pool_len()
                .is_some_and(|len| index as usize >= len)
            {
                return Err(ReadError::HardReject(format!(
                    "ConstantPlaceholder index {index} is outside the constant pool"
                )));
            }
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
            // TaggedVariableSerializer.parse reads the type unconditionally
            // (unlike ValDef, it has no constantStore branch). An unsupported
            // code fails rule 1018 like any other type read.
            let tpe = read_type(r)?;
            Payload::TaggedVar { id, tpe: Some(tpe) }
        }

        ArgPattern::ValDef => {
            let id = r.get_u32_exact()?;
            // Type is never serialized: Scala's reader always has a non-null
            // constantStore (ConstantStore.empty for non-cseg trees), so the
            // `if (r.constantStore == null) r.getType()` branch is never taken.
            let rhs = parse_typed_expr(r, next, _tree_version, types, children)?;
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
                    return Err(ReadError::ClassCast(format!(
                        "FunDef tpeArg must be an STypeVar, got {t:?}"
                    )));
                }
                tpe_args.push(t);
            }
            let rhs = parse_typed_expr(r, next, _tree_version, types, children)?;
            Payload::FunDef {
                id,
                tpe: None,
                tpe_args,
                rhs: Box::new(rhs),
            }
        }

        ArgPattern::BlockValue => {
            let count = r.get_u32_exact()? as usize;
            check_array_length(count, "BlockValue items")?;
            let mut items = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                let item = parse_typed_expr(r, next, _tree_version, types, children)?;
                // BlockValueSerializer casts each parsed item to BlockItem
                // before reading the next item/result. Only ValDef/FunDef are
                // BlockItems; the ClassCastException cannot soft-fork-wrap.
                if !matches!(
                    &item,
                    Expr::Op(IrNode {
                        payload: Payload::ValDef { .. } | Payload::FunDef { .. },
                        ..
                    })
                ) {
                    return Err(ReadError::ClassCast(
                        "BlockValue item must be a ValDef or FunDef".into(),
                    ));
                }
                items.push(item);
            }
            let result = parse_typed_expr(r, next, _tree_version, types, children)?;
            Payload::BlockValue {
                items,
                result: Box::new(result),
            }
        }

        ArgPattern::FuncValue => {
            let n_args = r.get_u32_exact()? as usize;
            check_array_length(n_args, "FuncValue args")?;
            let mut args = Vec::with_capacity(n_args.min(64));
            for _ in 0..n_args {
                // Scala `FuncValueSerializer` reads each arg id via `getUInt().toInt`
                // (FuncValueSerializer.scala:36) — NOT `getUIntExact` (which it uses
                // only for the arg COUNT on line 30). A value past i32::MAX wraps to
                // a negative `Int` and is accepted. Read non-exact, keep the raw u32
                // for byte-identical round-trip.
                let id = r.get_uint_to_i32()? as u32;
                // FuncValue always writes arg types (they define the function signature).
                let tpe = Some(read_type(r)?);
                types.bindings.bindings.insert(id, tpe.clone());
                r.bind_val(id);
                args.push((id, tpe));
            }
            if let Some(constructors) = &mut types.constructors {
                constructors.bind_args(&args);
            }
            let body = parse_typed_expr(r, next, _tree_version, types, children)?;
            Payload::FuncValue {
                args,
                body: Box::new(body),
            }
        }

        ArgPattern::PropertyCall => {
            let type_id = r.get_u8()?;
            let method_id = r.get_u8()?;
            let obj = parse_typed_expr(r, next, _tree_version, types, children)?;
            // Unresolved-method checkpoint: Scala's `PropertyCallSerializer.parse`
            // resolves the method (and throws a `ValidationException` when it is not
            // in this tree-version's registry) right after `obj`. Mark the
            // group-element sideband here so the ErgoTree layer forwards exactly the
            // GEs Scala curve-checked before wrapping. `is_known_method` keys on the
            // tree-header version (v5 for pre-v3, v6 for v3+), so this catches both a
            // v6-only method in a pre-v3 tree and a genuinely unknown id at any version.
            if !is_known_method(type_id, method_id, _tree_version) {
                if r.strict_method_resolution() {
                    // MethodsContainer.methodsV5/V6 (methods.scala:146-172).
                    // An unknown container raises rule 1010, not method rule 1011.
                    if !(matches!(type_id, 1..=8 | 12 | 36 | 96..=102 | 104..=106)
                        || type_id == 9 && _tree_version >= 3)
                    {
                        return Err(ReadError::SigmaValidation {
                            rule_id: 1010,
                            args: vec![type_id],
                            message: format!("unknown method container {type_id}"),
                        });
                    }
                    return Err(ReadError::SigmaValidation {
                        rule_id: 1011,
                        args: vec![type_id, method_id],
                        message: format!("unknown method {type_id}:{method_id}"),
                    });
                }
                r.mark_unresolved_method_checkpoint(type_id, method_id);
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
            let obj = parse_typed_expr(r, next, _tree_version, types, children)?;
            let n_args = r.get_u32_exact()? as usize;
            check_array_length(n_args, "MethodCall args")?;
            let mut args = Vec::with_capacity(n_args.min(64));
            for _ in 0..n_args {
                args.push(parse_typed_expr(r, next, _tree_version, types, children)?);
            }
            if _tree_version >= 3 && args.is_empty() {
                return Err(ReadError::HardReject(
                    "MethodCall requires nonempty arguments (Scala AssertionError)".into(),
                ));
            }
            // Unresolved-method checkpoint: Scala's `MethodCallSerializer.parse`
            // resolves the method (and throws a `ValidationException` when it is not
            // in this tree-version's registry) right after the receiver and value
            // args, before the explicit type args. Mark the group-element sideband
            // here (see the PropertyCall arm above). `is_known_method` keys on the
            // tree-header version, so this covers both a v6/EIP-50-only method in a
            // pre-v3 tree AND a genuinely unknown/future `(type_id, method_id)` pair
            // at any version — both wrap under has_size with the same GE-ordering shape.
            if !is_known_method(type_id, method_id, _tree_version) {
                if r.strict_method_resolution() {
                    // MethodsContainer.methodsV5/V6 (methods.scala:146-172).
                    // An unknown container raises rule 1010, not method rule 1011.
                    if !(matches!(type_id, 1..=8 | 12 | 36 | 96..=102 | 104..=106)
                        || type_id == 9 && _tree_version >= 3)
                    {
                        return Err(ReadError::SigmaValidation {
                            rule_id: 1010,
                            args: vec![type_id],
                            message: format!("unknown method container {type_id}"),
                        });
                    }
                    return Err(ReadError::SigmaValidation {
                        rule_id: 1011,
                        args: vec![type_id, method_id],
                        message: format!("unknown method {type_id}:{method_id}"),
                    });
                }
                r.mark_unresolved_method_checkpoint(type_id, method_id);
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
            let mut items = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                let item = parse_typed_expr(r, next, _tree_version, types, children)?;
                // This assert is made after EACH item, on both ordinary and
                // substitution parsing. Deliberately match Scala AssertionError
                // as a hard reject, even inside a size-delimited tree.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ConcreteCollectionSerializer.scala#L33-L39
                let tpe = if types.constructors.is_some() {
                    types
                        .constructor_children
                        .last()
                        .unwrap()
                        .last()
                        .unwrap()
                        .as_ref()
                        .map_err(|e| e.into_read_error())?
                        .clone()
                } else {
                    children.last().cloned().flatten()
                };
                if let Some(tpe) = tpe {
                    if tpe != elem_type {
                        return Err(ReadError::HardReject(format!(
                            "ConcreteCollection item has type {tpe:?}, expected {elem_type:?} (Scala AssertionError)"
                        )));
                    }
                }
                items.push(item);
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
            let mut items = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                items.push(parse_typed_expr(r, next, _tree_version, types, children)?);
            }
            Payload::Tuple { items }
        }

        ArgPattern::SelectField => {
            let input = parse_typed_expr(r, next, _tree_version, types, children)?;
            let field_idx = r.get_u8()?;
            // Scala builds `SelectField(input, fieldIndex)` at deserialization and
            // its `tpe = input.tpe.items(fieldIndex - 1)` (transformers.scala:294)
            // throws IndexOutOfBoundsException for index 0 and for an index above
            // the tuple arity. `deserializeErgoTree` does not catch it, so the tree
            // hard-rejects even under a size-delimited header (no soft-fork wrap).
            // Types are captured at each child's parse position, before later
            // bindings can overwrite the flat store.
            if field_idx == 0 {
                return Err(ReadError::HardReject(
                    "SelectField index 0 (indexes are 1-based)".into(),
                ));
            }
            let literal_arity = match children.last().and_then(Option::as_ref) {
                Some(SigmaType::STuple(items)) => Some(items.len()),
                Some(tpe) => {
                    // SelectField's constructor eagerly reads input.tpe.items.
                    // A known non-tuple throws ClassCastException in Scala,
                    // which is not eligible for an ErgoTree soft-fork wrap.
                    return Err(ReadError::ClassCast(format!(
                        "SelectField input must be a tuple, got {tpe:?}"
                    )));
                }
                _ => match &input {
                    Expr::Op(IrNode {
                        payload: Payload::Tuple { items },
                        ..
                    }) => Some(items.len()),
                    _ => None,
                },
            };
            if let Some(arity) = literal_arity {
                if field_idx as usize > arity {
                    return Err(ReadError::HardReject(format!(
                        "SelectField index {field_idx} exceeds tuple arity {arity}"
                    )));
                }
            }
            Payload::SelectField {
                input: Box::new(input),
                field_idx,
            }
        }

        ArgPattern::ExtractRegisterAs => {
            let input = parse_typed_expr(r, next, _tree_version, types, children)?;
            let reg_id = r.get_u8()?;
            // `ErgoBox.findRegisterByIndex(regId).get`
            // (ExtractRegisterAsSerializer.scala:28): an id outside R0..R9,
            // including a negative Byte, is a `NoSuchElementException` thrown
            // before the type is read: a hard reject.
            if reg_id > 9 {
                return Err(ReadError::HardReject(format!(
                    "ExtractRegisterAs register id {} is not R0..R9 (Scala NoSuchElementException)",
                    reg_id as i8
                )));
            }
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
            // findRegisterByIndex(getByte()).get throws before reading the type.
            if reg_id > 9 {
                return Err(ReadError::HardReject(format!(
                    "DeserializeRegister register {reg_id} is outside R0..R9"
                )));
            }
            let tpe = read_type(r)?;
            let has_default = r.get_u8()?;
            let default = if has_default != 0 {
                Some(Box::new(parse_typed_expr(
                    r,
                    next,
                    _tree_version,
                    types,
                    children,
                )?))
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
            // Scala `SigmaTransformerSerializer` (SigmaAnd/SigmaOr) reads the
            // child count with `getUIntExact` (SigmaTransformerSerializer.scala:21)
            // — a u32, NOT a u16. Match the width (an overflow past i32::MAX is a
            // hard `ArithmeticException` in Scala, surfaced here as `ValueTooLarge`).
            // The reservation is soft-capped to avoid OOM on a hostile count; the
            // loop still reads `count` items and fails on truncated input.
            let count = r.get_u32_exact()? as usize;
            check_array_length(count, "SigmaAnd/SigmaOr items")?;
            let mut items = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                items.push(parse_typed_expr(r, next, _tree_version, types, children)?);
            }
            Payload::SigmaCollection { items }
        }

        ArgPattern::NoneValue => {
            let tpe = read_type(r)?;
            Payload::NoneValue { tpe }
        }

        ArgPattern::ByIndex => {
            let input = parse_typed_expr(r, next, _tree_version, types, children)?;
            let mut index = parse_typed_expr(r, next, _tree_version, types, children)?;
            if _tree_version < 3 {
                if let Some(Some(tpe)) = children.last() {
                    if !matches!(tpe, SigmaType::SByte | SigmaType::SShort | SigmaType::SInt) {
                        return Err(ReadError::HardReject(format!(
                            "ByIndex index cannot be upcast to Int, got {tpe:?}"
                        )));
                    }
                }
            }
            // Scala ByIndexSerializer inserts a charged Upcast before v3.
            if _tree_version < 3
                && matches!(
                    children.last().and_then(Option::as_ref),
                    Some(SigmaType::SByte | SigmaType::SShort)
                )
            {
                index = Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast {
                        input: Box::new(index),
                        tpe: SigmaType::SInt,
                    },
                });
            }
            let has_default = r.get_u8()?;
            let default = if has_default != 0 {
                Some(Box::new(parse_typed_expr(
                    r,
                    next,
                    _tree_version,
                    types,
                    children,
                )?))
            } else {
                None
            };
            // ByIndex.tpe casts the receiver's type to SCollection after the
            // default has been parsed. Unknown types stay lenient.
            if let Some(Some(tpe)) = children.first() {
                // Scala STuple extends SCollection[SAny], so dynamic tuple
                // indexing also reaches this constructor.
                if !matches!(tpe, SigmaType::SColl(_) | SigmaType::STuple(_)) {
                    return Err(ReadError::ClassCast(format!(
                        "ByIndex input must be a collection, got {tpe:?}"
                    )));
                }
            }
            Payload::ByIndex {
                input: Box::new(input),
                index: Box::new(index),
                default,
            }
        }

        ArgPattern::NumericCast => {
            let input = parse_typed_expr(r, next, _tree_version, types, children)?;
            let tpe = read_type(r)?;
            // Scala `NumericCastSerializer.parse`
            // (transformers/NumericCastSerializer.scala:20-24) is
            //     val input = r.getValue().asNumValue
            //     val tpe   = r.getType().asNumType
            //     cons(input, tpe)
            // `asNumType` is `asInstanceOf[SNumericType]` on a CONCRETE type, so
            // a non-numeric target throws `ClassCastException`; `asNumValue` is
            // erased and throws nothing, but `cons` then hits
            // `require(input.tpe.isInstanceOf[SNumericType])` on `Upcast` /
            // `Downcast` (ast/trees.scala:398, :431) and throws
            // `IllegalArgumentException`. Neither is a `ValidationException`, so
            // neither is soft-fork-wrapped into an `UnparsedErgoTree`: both are
            // hard deserialization failures. Accepting them made us more
            // permissive than consensus, and (for a pre-v3 tree) the write-side
            // `Upcast(Const)` strip then re-emitted bytes whose re-parse failed
            // rule 1001 — how the nightly fuzzer found this.
            if !tpe.is_numeric() {
                return Err(ReadError::ClassCast(format!(
                    "numeric cast target type must be numeric, got {tpe:?} \
                     (Scala asNumType ClassCastException)"
                )));
            }
            // The input's type is checked only when this parser could infer it
            // precisely. Scala always has the parsed value's `tpe`; we may not
            // (a placeholder resolved later, an opaque subtree), and rejecting
            // on an unknown type would refuse scripts the reference accepts —
            // the more dangerous direction. So an indeterminate input is left
            // alone, which stays at worst as permissive as before.
            if let Some(Some(input_tpe)) = children.last() {
                if !input_tpe.is_numeric() {
                    return Err(ReadError::HardReject(format!(
                        "numeric cast input type must be numeric, got {input_tpe:?} \
                         (Scala Upcast/Downcast require)"
                    )));
                }
            }
            Payload::NumericCast {
                input: Box::new(input),
                tpe,
            }
        }

        ArgPattern::FuncApply => {
            let func = parse_typed_expr(r, next, _tree_version, types, children)?;
            let n_args = r.get_u32_exact()? as usize;
            check_array_length(n_args, "Apply args")?;
            let mut args = Vec::with_capacity(n_args.min(64));
            for _ in 0..n_args {
                args.push(parse_typed_expr(r, next, _tree_version, types, children)?);
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
                let t = Some(SigmaType::SBoolean);
                check_relation_numeric(first, &t, &t)?;
                check_relation_constraints(first, &t, &t)?;
                Payload::Two(a, b)
            } else {
                let mut a = parse_typed_expr(r, next, _tree_version, types, children)?;
                let mut b = parse_typed_expr(r, next, _tree_version, types, children)?;
                let n = children.len();
                let operands = &mut children[n - 2..];
                // These cached types preserve real SAny and composite types;
                // the root gate's imprecision sentinel cannot check SameType.
                // Builder check2 reads both types before applying its constraint.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala#L286-L294
                if types.constructors.is_some() && (0x8F..=0x94).contains(&first) {
                    let cached = types.constructor_children.last().unwrap();
                    for (operand, tpe) in operands.iter_mut().zip(&cached[cached.len() - 2..]) {
                        *operand = tpe.as_ref().map_err(|e| e.into_read_error())?.clone();
                    }
                }
                // comparisonOp checks OnlyNumeric before applyUpcast; equalityOp
                // applies Upcast directly. Both then check SameType.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala#L686-L701
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala#L750-L763
                check_relation_numeric(first, &operands[0], &operands[1])?;
                if _tree_version < 3 && (0x8F..=0x94).contains(&first) {
                    if let Some(target) = apply_upcast(&mut a, &mut b, operands) {
                        if types.constructors.is_some() {
                            let ct = types.constructor_children.last_mut().unwrap();
                            let len = ct.len();
                            ct[len - 2..].fill(Ok(Some(target)));
                        }
                    }
                }
                check_relation_constraints(first, &operands[0], &operands[1])?;
                Payload::Two(Box::new(a), Box::new(b))
            }
        }
    };

    Ok(Expr::Op(IrNode {
        opcode: first,
        payload,
    }))
}

// Mirror TransformingSigmaBuilder.applyUpcast: cast only the narrower numeric
// operand. Constants retain the cast in the AST too; the versioned writer alone
// strips a constant's leading Upcast below tree v3.
// https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala#L674-L684
fn apply_upcast(
    a: &mut Expr,
    b: &mut Expr,
    operands: &mut [Option<SigmaType>],
) -> Option<SigmaType> {
    let [Some(left), Some(right)] = operands else {
        return None;
    };
    let rank = |t: &SigmaType| match t {
        SigmaType::SByte => 1,
        SigmaType::SShort => 2,
        SigmaType::SInt => 3,
        SigmaType::SLong => 4,
        SigmaType::SBigInt => 5,
        SigmaType::SUnsignedBigInt => 6,
        _ => 0,
    };
    if left == right || rank(left) == 0 || rank(right) == 0 {
        return None;
    }
    let target = if rank(left) > rank(right) {
        left.clone()
    } else {
        right.clone()
    };
    for (expr, tpe) in [(a, left), (b, right)] {
        if *tpe != target {
            *expr = Expr::Op(IrNode {
                opcode: 0x7E,
                payload: Payload::NumericCast {
                    input: Box::new(std::mem::replace(
                        expr,
                        Expr::Const {
                            tpe: SigmaType::SUnit,
                            val: SigmaValue::Unit,
                        },
                    )),
                    tpe: target.clone(),
                },
            });
            *tpe = target.clone();
        }
    }
    Some(target)
}

/// The bitwise and negation nodes check their operands when they are built:
/// `Negation` and `BitInversion` `require(input.tpe.isNumTypeOrNoType)`, and
/// `BitOp` (BitOr, BitAnd, BitXor and the three shifts) the same of both
/// operands (`trees.scala:882`, `:900`, `:913`). The arithmetic operations
/// (Plus .. Max) have no such check (`SigmaBuilder.scala:707-712`). A failed
/// `require` is an `IllegalArgumentException`, which `deserializeErgoTree`
/// rethrows as a `SerializerException`: a hard reject, also in a sized tree.
///
/// Only an operand whose type is known precisely is judged; an unknown type
/// could be Scala's `NoType`, which passes.
fn check_numeric_operands(opcode: u8, operands: &[Option<SigmaType>]) -> Result<(), ReadError> {
    if !matches!(opcode, 0xF0..=0xF3 | 0xF5..=0xF8) {
        return Ok(());
    }
    for tpe in operands.iter().flatten() {
        if !tpe.is_numeric() {
            return Err(ReadError::HardReject(format!(
                "operand of opcode {opcode:#04x} must be numeric, got {tpe:?} \
                 (Scala require -> SerializerException)"
            )));
        }
    }
    Ok(())
}

/// Nodes whose type is a strict `val` computed from an operand cast it when
/// they are built, so an operand of the wrong kind is a `ClassCastException`,
/// a hard reject also in a sized tree: `Append` and `Slice` take
/// `input.tpe` as an `SCollection` (`transformers.scala:62`, `:89`; an
/// `STuple` is one). `OptionGetOrElse.opType` eagerly reads its receiver's
/// option element type. Filter's deferred cast is retained by ConstructorTypes.
/// `MapCollection` takes `mapper.tpe` as an `SFunc`
/// (`:38`). Only an operand whose type is known precisely is judged.
// https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/transformers.scala#L117-L122
// https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/transformers.scala#L622-L626
fn check_constructor_casts(opcode: u8, operands: &[Option<SigmaType>]) -> Result<(), ReadError> {
    let (operand, want) = match opcode {
        0xB3 | 0xB4 => (&operands[0], "a collection"),
        0xE5 => (&operands[0], "an option"),
        0xAD => (&operands[1], "a function"),
        _ => return Ok(()),
    };
    let Some(tpe) = operand else {
        return Ok(());
    };
    let fits = match opcode {
        0xAD => matches!(tpe, SigmaType::SFunc { .. }),
        0xE5 => matches!(tpe, SigmaType::SOption(_)),
        _ => matches!(tpe, SigmaType::SColl(_) | SigmaType::STuple(_)),
    };
    if !fits {
        return Err(ReadError::ClassCast(format!(
            "operand of opcode {opcode:#04x} must be {want}, got {tpe:?} (Scala ClassCastException)"
        )));
    }
    Ok(())
}

/// `DeserializationSigmaBuilder` checks comparison and equality operands
/// (`SigmaBuilder.scala` `comparisonOp` / `equalityOp`): `Lt`..`Ge` require
/// both operands numeric, and all six require the same type once a pre-v3
/// tree has upcast two numeric operands to the wider one. `ConstraintFailed`
/// is not a `ValidationException`, so even a sized tree hard-rejects.
///
/// Only known types are judged. The numeric check is a class test, like the
/// other parse-time checks. Cached constructor types retain exact composite
/// types and real SAny; unknown types remain unchecked.
fn check_relation_numeric(
    opcode: u8,
    ta: &Option<SigmaType>,
    tb: &Option<SigmaType>,
) -> Result<(), ReadError> {
    if opcode <= 0x92 {
        for t in [ta, tb].into_iter().flatten() {
            if !t.is_numeric() {
                return Err(ReadError::HardReject(format!(
                    "relation {opcode:#04x} operands {:?} and {:?} fail the builder constraint (Scala ConstraintFailed)",
                    ta.as_ref().unwrap_or(t), tb.as_ref().unwrap_or(t)
                )));
            }
        }
    }
    Ok(())
}

fn check_relation_constraints(
    opcode: u8,
    ta: &Option<SigmaType>,
    tb: &Option<SigmaType>,
) -> Result<(), ReadError> {
    if !(0x8F..=0x94).contains(&opcode) {
        return Ok(());
    }
    let fail = |ta: &SigmaType, tb: &SigmaType| {
        Err(ReadError::HardReject(format!(
            "relation {opcode:#04x} operands {ta:?} and {tb:?} fail the builder \
             constraint (Scala ConstraintFailed)"
        )))
    };
    let (Some(ta), Some(tb)) = (ta, tb) else {
        return Ok(());
    };
    if ta != tb {
        return fail(ta, tb);
    }
    Ok(())
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
                matches!(&err, ReadError::SigmaValidation { rule_id: 1009, message: m, .. } if m.contains("SOption")),
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
        assert!(
            matches!(&err, ReadError::SigmaValidation { rule_id: 1009, message: m, .. } if m.contains("SOption"))
        );
    }

    // ----- oracle parity -----

    /// `Negation`, `BitInversion` and `BitOp` require numeric operands when
    /// built; arithmetic does not. JVM (`ErgoSerdeOracle.scala`, sigma-state
    /// 6.0.6, `ergo_tree`, activated 3), all `BoolToSigmaProp(EQ(op, x))`:
    ///
    /// ```text
    /// 00d193f001010101              Negation(true)          REJECT SerializerException
    /// 00d193f101010101              BitInversion(true)      REJECT SerializerException
    /// 00d193f685010185010185010101  ShiftRight(C, C), C = Coll[Boolean]  REJECT
    /// 00d193f604020402f60402040204  ShiftRight(Int, Int)    ACCEPT
    /// 00d193f004020402              Negation(Int)           ACCEPT
    /// 00d193f2040204020402          BitOr(Int, Int)         ACCEPT
    /// ```
    #[test]
    fn bit_and_negation_operands_must_be_numeric() {
        for (body, accept) in [
            ("d193f001010101", false),
            ("d193f101010101", false),
            ("d193f685010185010185010101", false),
            ("d193f604020402f60402040204", true),
            ("d193f004020402", true),
            ("d193f2040204020402", true),
        ] {
            let bytes = hex::decode(body).unwrap();
            let mut r = VlqReader::new(&bytes);
            let result = parse_expr(&mut r, 0, 0);
            if accept {
                assert!(result.is_ok(), "{body}: {result:?}");
            } else {
                assert!(
                    matches!(&result, Err(ReadError::HardReject(m)) if m.contains("must be numeric")),
                    "{body}: {result:?}"
                );
            }
        }
    }

    /// Constructor casts: `Append` / `Slice` cast `input.tpe` to a collection,
    /// `MapCollection` casts the mapper's type to a function, and
    /// `ExtractRegisterAs` looks its register id up with `.get`. JVM
    /// (`ErgoSerdeOracle.scala`, sigma-state 6.0.6, `ergo_tree`, activated 3);
    /// the first and the Slice rows are SANTA `tree_parse_acceptance` e1 / e2
    /// (https://github.com/mwaddip/santa, MIT):
    ///
    /// ```text
    /// EQ(SizeOf(Append(Int 1, Int 2)), 0)           REJECT ClassCastException
    /// EQ(SizeOf(Append(Coll[Int], Coll[Int])), 0)   ACCEPT
    /// EQ(SizeOf(Append((1,1), (1,1))), 0)           ACCEPT  (STuple is an SCollection)
    /// EQ(SizeOf(Slice(Int 1, 0, 1)), 0)             REJECT ClassCastException
    /// EQ(SizeOf(Map(Coll[Int], Int 1)), 0)          REJECT ClassCastException
    /// EQ(SizeOf(Map(Coll[Int], (x: Int) => x)), 0)  ACCEPT
    /// isDefined(SELF.R9[Int])                       ACCEPT
    /// isDefined(SELF.R10[Int]) / (SELF.R-128[Int])  REJECT NoSuchElementException
    /// ```
    #[test]
    fn constructor_casts_reject_operands_of_the_wrong_kind() {
        for (body, accept) in [
            ("d193b1b3040204040400", false),
            ("d193b1b31001021001020400", true),
            ("d193b1b35802025802020400", true),
            ("d193b1b40402040004020400", false),
            ("d193b1ad1001020402040000", false),
            ("d193b1ad100102d901010472010400", true),
            ("d1e6c6a70904", true),
            ("d1e6c6a70a04", false),
            ("d1e6c6a78004", false),
        ] {
            let bytes = hex::decode(body).unwrap();
            let mut r = VlqReader::new(&bytes);
            let result = parse_expr(&mut r, 0, 0);
            if accept {
                assert!(result.is_ok(), "{body}: {result:?}");
            } else {
                assert!(
                    matches!(
                        &result,
                        Err(ReadError::HardReject(_) | ReadError::ClassCast(_))
                    ),
                    "{body}: {result:?}"
                );
            }
        }
    }

    /// An INLINE pre-v3 `SHeader` constant must be a [`ReadError::HardReject`],
    /// not a soft `InvalidData`. The reference's `DataSerializer` matches
    /// `SHeader` only when `isV3OrLaterErgoTreeVersion`; otherwise it falls
    /// through to `CoreDataSerializer` and throws a `SerializerException`, which
    /// `deserializeErgoTree` does NOT catch — so the whole tree is rejected
    /// rather than wrapped as `UnparsedErgoTree`. A soft error here was swallowed
    /// by the size-delimited body-error wrap (cargo-fuzz #304). The SEGREGATED
    /// constant path already hard-rejects (`ergo_tree::read::parse_body`, blessed
    /// by SANTA wire/v6 `Box.softfork_header_constant_reject`); the two paths
    /// must agree.
    ///
    /// `SOption` is the discriminator: its pre-v3 rejection comes from
    /// `CheckSerializableTypeCode`, a `ValidationException` the reference DOES
    /// wrap, so it stays soft — see `inline_option_constant_rejected_in_pre_v3_tree_body`.
    #[test]
    fn inline_header_constant_pre_v3_hard_rejects() {
        // `68` = SHeader type code; the value bytes never need to be well formed
        // — an empty header payload already fails, and either way the version
        // gate is what must classify the error as hard.
        let mut header_const = vec![0x68u8];
        header_const.extend_from_slice(
            &crate::header::serialize_header_without_pow(&min_header()).unwrap(),
        );
        header_const.extend_from_slice(&[0x02; 33]); // Autolykos v2 pk
        header_const.extend_from_slice(&[0x00; 8]); // nonce
        for version in 0u8..3 {
            let mut r = VlqReader::new(&header_const);
            let err = parse_expr(&mut r, 0, version).expect_err("pre-v3 inline Header must reject");
            assert!(
                matches!(&err, ReadError::HardReject(m) if m.contains("SHeader")),
                "version {version}: a pre-v3 inline Header constant must HARD reject so it \
                 escapes the size-delimited soft-fork wrap, got: {err:?}"
            );
        }
    }

    /// A TRUNCATED/malformed inline `SHeader` constant (no payload at all)
    /// must also be a [`ReadError::HardReject`] — and, unlike the version-gate
    /// check above, this holds at EVERY tree version, v3 included: `SHeader`
    /// decode failures are mapped to `HardReject` unconditionally inside
    /// `read_value_at_depth` itself (`sigma_value/mod.rs`'s `SHeader` arm),
    /// independent of the separate `_tree_version < 3 && val.contains_header()`
    /// check that only fires once a value has successfully materialized.
    /// Confirms a malformed pre-v3 payload can't slip past the version gate by
    /// erroring inside the value read before that check ever runs: it already
    /// hard-rejects one step earlier, on the SAME path a well-formed pre-v3
    /// header uses. Oracle (`ErgoSerdeOracle.scala`, sigma-state 6.0.2):
    /// `constant 68 -> REJECT SerializerException`.
    #[test]
    fn inline_header_constant_truncated_hard_rejects_at_every_version() {
        for version in 0u8..=3 {
            let mut r = VlqReader::new(&[0x68u8]);
            let err = parse_expr(&mut r, 0, version)
                .expect_err("a truncated inline Header constant must reject");
            assert!(
                matches!(&err, ReadError::HardReject(m) if m.contains("SHeader")),
                "version {version}: a truncated inline Header constant must HARD \
                 reject regardless of tree version, got: {err:?}"
            );
        }
    }

    #[test]
    fn inline_header_constant_v3_parses() {
        let mut header_const = vec![0x68u8];
        header_const.extend_from_slice(
            &crate::header::serialize_header_without_pow(&min_header()).unwrap(),
        );
        header_const.extend_from_slice(&[0x02; 33]);
        header_const.extend_from_slice(&[0x00; 8]);
        let mut r = VlqReader::new(&header_const);
        let expr = parse_expr(&mut r, 0, 3).expect("v3 inline Header must parse");
        match expr {
            Expr::Const { val, .. } => assert!(val.contains_header()),
            other => panic!("expected Const, got {other:?}"),
        }
    }

    fn min_header() -> crate::header::Header {
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        crate::header::Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 0x1a01_7660,
            height: 1,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: crate::autolykos::AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    // ----- oracle parity -----

    // ledger: OP-0x8C
    #[test]
    fn select_field_index_bounds_match_jvm_verdicts() {
        use crate::ergo_tree::read_ergo_tree;
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/select_field_index_bounds.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["tree_hex"].as_str().unwrap()).unwrap();
            let result = read_ergo_tree(&mut VlqReader::new(&bytes));
            match case["jvm"].as_str().unwrap() {
                "Accept" => assert!(result.is_ok(), "{}: {result:?}", case["name"]),
                "Reject" => assert!(
                    matches!(result, Err(ReadError::HardReject(_))),
                    "{}: {result:?}",
                    case["name"]
                ),
                other => panic!("unexpected JVM verdict {other}"),
            }
        }
    }
}
