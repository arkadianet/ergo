//! Canonical s-expression printer for `TypedExpr`.
//!
//! Implements the oracle format from m2-oracle.md §4 and TyperOracle.scala
//! (scripts/jvm_typer_oracle/TyperOracle.scala) EXACTLY. The format is:
//!
//!   `(ProductPrefix:TypeTermString field1 field2 …)`
//!
//! Normalization rules (N1-N5 from TyperOracle.scala `renderNode`):
//!   N1 — The header is always `Name:TypeTermString`.
//!   N2 — Skip a field whose unwrapped SType (bare, Option-wrapped, or
//!        Nullable-wrapped) equals the node's own tpe. E6 extends this to
//!        unwrap `Option[SType]` before the self-type test (Select.resType).
//!   N3 — Node fields render recursively: `(ChildName:Type …)`.
//!   N4 — typeSubst entries are sorted by rendered full-entry string
//!        (TyperOracle.scala:172 `.sorted`) then joined with "," (not space).
//!        Renders as `{k1->v1,k2->v2}` or `{}`.
//!   N5 — String fields render as `'text'`; numeric scalars as `@n`; SType
//!        fields as `#TypeTermString`; MethodRef as `%Owner.name`; node
//!        sequences as `[n1 n2 …]`; primitive arrays as `<@v1 @v2 …>`;
//!        Option[SValue] as "None" or the unwrapped node; lambda args as
//!        `[name:#Type …]`.

use ergo_crypto::group_element::{decompress_to_affine_hex, strip_leading_zero_hex};

use crate::stype::SType;
use crate::typed::{node_tpe, product_prefix, ConstPayload, STypeParam, TypedExpr};

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the canonical type-term string for `t`.
///
/// Mirrors the Scala `toTermString` function in TyperOracle.scala. SGlobal
/// renders as "SigmaDslBuilder" (its Scala object name, not "SGlobal").
/// STypeVar renders as its ident verbatim (no `#` prefix here — callers add
/// that). NoType renders as "NoType" (sentinel; shouldn't appear in
/// well-typed trees).
pub fn to_term_string(t: &SType) -> String {
    match t {
        SType::NoType => "NoType".to_string(),
        SType::SBoolean => "Boolean".to_string(),
        SType::SByte => "Byte".to_string(),
        SType::SShort => "Short".to_string(),
        SType::SInt => "Int".to_string(),
        SType::SLong => "Long".to_string(),
        SType::SBigInt => "BigInt".to_string(),
        SType::SUnsignedBigInt => "UnsignedBigInt".to_string(),
        SType::SGroupElement => "GroupElement".to_string(),
        SType::SSigmaProp => "SigmaProp".to_string(),
        SType::SAvlTree => "AvlTree".to_string(),
        SType::SContext => "Context".to_string(),
        // SGlobal is the singleton object; its Scala typeName = "SigmaDslBuilder".
        // Verified by golden seed: `(Global:SigmaDslBuilder)`.
        SType::SGlobal => "SigmaDslBuilder".to_string(),
        SType::SHeader => "Header".to_string(),
        SType::SPreHeader => "PreHeader".to_string(),
        SType::SString => "String".to_string(),
        SType::SBox => "Box".to_string(),
        SType::SUnit => "Unit".to_string(),
        SType::SAny => "Any".to_string(),
        // STypeVar renders as the raw ident (callers prepend # where needed).
        SType::STypeVar(s) => s.clone(),
        SType::SColl(inner) => format!("Coll[{}]", to_term_string(inner)),
        SType::SOption(inner) => format!("Option[{}]", to_term_string(inner)),
        SType::STuple(vs) => {
            let parts: Vec<String> = vs.iter().map(to_term_string).collect();
            format!("({})", parts.join(","))
        }
        SType::SFunc {
            dom,
            range,
            tpe_params,
        } => {
            // `(T1,T2) => R` — parens even for single-element domain.
            // Verified: `(Box) => Long`, `(Long) => Boolean` in golden seed.
            // A polymorphic (unapplied) function type prepends its `[params]` binder,
            // comma-joined, matching Scala `SFunc.toTermString` (SType.scala:644,653):
            // e.g. `[T](T) => Coll[Byte]`, `[K,L,R,O](...) => ...`.  Empty for every
            // monomorphic function type (no prefix).
            let dom_parts: Vec<String> = dom.iter().map(to_term_string).collect();
            let prefix = if tpe_params.is_empty() {
                String::new()
            } else {
                format!("[{}]", tpe_params.join(","))
            };
            format!(
                "{}({}) => {}",
                prefix,
                dom_parts.join(","),
                to_term_string(range)
            )
        }
        SType::STypeApply { name, args } => {
            let arg_parts: Vec<String> = args.iter().map(to_term_string).collect();
            format!("{}[{}]", name, arg_parts.join(","))
        }
    }
}

/// Render a `TypedExpr` as the canonical oracle s-expression.
///
/// Exactly matches the output of `TyperOracle.scala renderNode` for the same
/// AST. Use the `golden_seed.txt` expected-output strings as the test oracle.
pub fn print_typed(e: &TypedExpr) -> String {
    let prefix = product_prefix(e);
    let tpe_str = to_term_string(node_tpe(e));
    let fields = collect_fields(e);
    if fields.is_empty() {
        format!("({}:{})", prefix, tpe_str)
    } else {
        format!("({}:{} {})", prefix, tpe_str, fields.join(" "))
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Render a sequence of nodes as `[n1 n2 …]` (N5 sequence form).
/// Empty sequence → `[]`.
fn render_seq(nodes: &[TypedExpr]) -> String {
    let parts: Vec<String> = nodes.iter().map(print_typed).collect();
    format!("[{}]", parts.join(" "))
}

/// Render a SType as a `#TypeTermString` field (N5 SType form).
fn render_hash_type(t: &SType) -> String {
    format!("#{}", to_term_string(t))
}

/// Render lambda `tpe_params` as `[ident1 ident2 …]`.
/// Empty → `[]`.
fn render_tpe_params(params: &[STypeParam]) -> String {
    let parts: Vec<String> = params.iter().map(|p| p.ident.clone()).collect();
    format!("[{}]", parts.join(" "))
}

/// Render lambda `args` as `[name1:#Type1 name2:#Type2 …]`.
/// Empty → `[]`.
fn render_lambda_args(args: &[(String, SType)]) -> String {
    let parts: Vec<String> = args
        .iter()
        .map(|(name, t)| format!("{}:#{}", name, to_term_string(t)))
        .collect();
    format!("[{}]", parts.join(" "))
}

/// Render `MethodCall.type_subst` as `{k1->v1,k2->v2}` sorted by full entry
/// string (N4, TyperOracle.scala:172 `.sorted` + `mkString("{", ",", "}")`).
/// Empty → `{}`.
fn render_type_subst(subst: &[(String, SType)]) -> String {
    if subst.is_empty() {
        return "{}".to_string();
    }
    // Build full entry strings `#K->#V`, then sort them (N4).
    let mut entries: Vec<String> = subst
        .iter()
        .map(|(k, v)| format!("#{}->{}", k, render_hash_type(v)))
        .collect();
    entries.sort();
    format!("{{{}}}", entries.join(","))
}

/// Render an `Option<Box<TypedExpr>>` field.
/// `None` → `"None"` (N5 Option form); `Some(e)` → `print_typed(e)`.
fn render_opt_node(opt: &Option<Box<TypedExpr>>) -> String {
    match opt {
        None => "None".to_string(),
        Some(e) => print_typed(e),
    }
}

/// Render a `ConstPayload` value field (the scalar/array portion of a Constant).
///
/// Rendering rules from TyperOracle.scala `renderField` (N5):
///   Bool(b)             → `@true` / `@false`
///   numeric primitives  → `@n` (signed decimal)
///   BigInt(s)           → `(CBigInt @n)` — the CBigInt wrapper
///   String(s)           → `'s'`
///   Unit                → `@()` (Scala BoxedUnit in productIterator context)
///   ByteColl/LongColl   → `<@v1 @v2 …>` (N5 primitive-seq form)
///   GroupElement(bytes) → `(CGroupElement (Ecp @(x,y,1)))` — decompresses the
///                         33-byte SEC1-compressed point to affine hex (M3, D-T6).
///                         x/y are UNPADDED (Java `BigInteger.toString(16)`
///                         semantics via BouncyCastle's `ECPoint.toString`) —
///                         oracle-pinned on a leading-zero coordinate,
///                         golden_seed.txt §23(f); see `strip_leading_zero_hex`.
///   SigmaProp(s)        → opaque string (M3 scope for full parity)
///   ProveDlog(bytes)    → `(ProveDlog (Ecp @(x,y,1)))` — NO CGroupElement
///                         wrapper (oracle-verified, golden_seed.txt §10),
///                         same unpadded x/y semantics as GroupElement above.
fn render_payload(p: &ConstPayload) -> String {
    match p {
        ConstPayload::Bool(b) => format!("@{}", b),
        ConstPayload::Byte(n) => format!("@{}", n),
        ConstPayload::Short(n) => format!("@{}", n),
        ConstPayload::Int(n) => format!("@{}", n),
        ConstPayload::Long(n) => format!("@{}", n),
        ConstPayload::BigInt(s) => format!("(CBigInt @{})", s),
        // String renders with single quotes per N5 `case s: String => "'" + s + "'"`.
        // Verified: `"ab"+"cd"` → oracle `(ConstantNode:String 'abcd')`.
        ConstPayload::String(s) => format!("'{}'", s),
        // Unit renders as `@()` in productIterator context.
        // Verified: `()` → oracle `(ConstantNode:Unit @())`.
        ConstPayload::Unit => "@()".to_string(),
        ConstPayload::ByteColl(vs) => {
            let parts: Vec<String> = vs.iter().map(|v| format!("@{}", v)).collect();
            format!("<{}>", parts.join(" "))
        }
        ConstPayload::LongColl(vs) => {
            let parts: Vec<String> = vs.iter().map(|v| format!("@{}", v)).collect();
            format!("<{}>", parts.join(" "))
        }
        ConstPayload::GroupElement(bytes) => {
            // D-T6: bytes are the source of truth; decompress on demand. An
            // env-lifted GroupElement is on-curve-checked at `env::lift`
            // (D-T5), so this cannot fail for a well-formed compile.
            // The oracle's `Ecp @(x,y,1)` prints UNPADDED BigInteger hex
            // (BouncyCastle `ECPoint.toString`, not our fixed-width SEC1
            // decompression) — strip the padding golden_seed.txt §23(f)
            // pinned on a leading-zero y-coordinate.
            let (x, y) = decompress_to_affine_hex(bytes).expect(
                "GroupElement constant bytes must be on-curve — checked at env::lift (D-T5)",
            );
            let x = strip_leading_zero_hex(&x);
            let y = strip_leading_zero_hex(&y);
            format!("(CGroupElement (Ecp @({x},{y},1)))")
        }
        // SigmaProp: opaque in M2; store the full representation string.
        ConstPayload::SigmaProp(s) => s.clone(),
        // ProveDlog: decompressed Ecp form (golden_seed.txt §10), no
        // CGroupElement wrapper (oracle-verified). Bytes are on-curve by
        // construction: `bind_pk` curve-checks the decoded pubkey (D-T5),
        // so decompression here cannot fail for a well-formed compile.
        // Same unpadded-hex correction as GroupElement above (§23(f)).
        ConstPayload::ProveDlog(bytes) => {
            let (x, y) = decompress_to_affine_hex(bytes)
                .expect("ProveDlog constant bytes must be on-curve — checked at bind_pk (D-T5)");
            let x = strip_leading_zero_hex(&x);
            let y = strip_leading_zero_hex(&y);
            format!("(CSigmaProp (ProveDlog (Ecp @({x},{y},1))))")
        }
    }
}

// ── collect_fields split into logical groups ──────────────────────────────────
//
// The match is split into five helper functions to keep each function under
// clippy's too_many_lines threshold (100 lines). `collect_fields` is the
// dispatcher; helpers below cover non-overlapping variant subsets.

/// Dispatch to the appropriate field-collector for `e`.
fn collect_fields(e: &TypedExpr) -> Vec<String> {
    use TypedExpr::*;
    match e {
        // ── singletons: no fields ────────────────────────────────────────────
        Height { .. }
        | Self_ { .. }
        | Inputs { .. }
        | Outputs { .. }
        | Context { .. }
        | Global { .. }
        | MinerPubkey { .. }
        | LastBlockUtxoRootHash { .. }
        | GroupGenerator { .. } => vec![],

        // ── frontend nodes ────────────────────────────────────────────────────
        Constant { .. }
        | Block { .. }
        | ValNode { .. }
        | Ident { .. }
        | Lambda { .. }
        | Select { .. }
        | Apply { .. }
        | Tuple { .. }
        | ConcreteCollection { .. }
        | If { .. } => collect_frontend(e),

        // ── arithmetic and boolean ops ────────────────────────────────────────
        ArithOp { .. }
        | BitOp { .. }
        | Upcast { .. }
        | Downcast { .. }
        | GT { .. }
        | GE { .. }
        | LT { .. }
        | LE { .. }
        | EQ { .. }
        | NEQ { .. }
        | BinAnd { .. }
        | BinOr { .. }
        | BinXor { .. }
        | LogicalNot { .. }
        | Negation { .. }
        | BitInversion { .. } => collect_arith_bool(e),

        // ── collection transformers ───────────────────────────────────────────
        MapCollection { .. }
        | Append { .. }
        | Slice { .. }
        | Filter { .. }
        | Exists { .. }
        | ForAll { .. }
        | Fold { .. }
        | ByIndex { .. }
        | SelectField { .. }
        | SizeOf { .. } => collect_coll(e),

        // ── sigma + group + option ops ────────────────────────────────────────
        BoolToSigmaProp { .. }
        | SigmaPropIsProven { .. }
        | SigmaPropBytes { .. }
        | SigmaAnd { .. }
        | SigmaOr { .. }
        | AND { .. }
        | OR { .. }
        | XorOf { .. }
        | MultiplyGroup { .. }
        | Exponentiate { .. }
        | Xor { .. }
        | OptionGet { .. }
        | OptionGetOrElse { .. }
        | OptionIsDefined { .. } => collect_sigma_group(e),

        // ── context access + predef + MethodCall + pre-typed nodes ────────────
        _ => collect_ctx_predef(e),
    }
}

/// Fields for frontend / structural nodes.
fn collect_frontend(e: &TypedExpr) -> Vec<String> {
    use TypedExpr::*;
    match e {
        // ── Constant ─────────────────────────────────────────────────────────
        // productIterator: [value, tpe].
        // N2: tpe == Constant.tpe → always stripped.
        // All payloads render via render_payload, including Unit → `@()`.
        Constant { value, .. } => vec![render_payload(value)],

        // ── Block ─────────────────────────────────────────────────────────────
        // productIterator: [bindings: Seq[Val], result: SValue].
        Block {
            bindings, result, ..
        } => vec![render_seq(bindings), print_typed(result)],

        // ── ValNode ───────────────────────────────────────────────────────────
        // productIterator: [name, givenType, body].
        // N2: givenType (bare SType) == ValNode.tpe (= givenType always) → STRIP.
        ValNode { name, body, .. } => vec![format!("'{}'", name), print_typed(body)],

        // ── Ident ─────────────────────────────────────────────────────────────
        // productIterator: [name, tpe].
        // N2: tpe == Ident.tpe → always stripped.
        Ident { name, .. } => vec![format!("'{}'", name)],

        // ── Lambda ────────────────────────────────────────────────────────────
        // productIterator: [tpeParams, args, givenResType, body].
        Lambda {
            tpe_params,
            args,
            given_res_type,
            body,
            ..
        } => vec![
            render_tpe_params(tpe_params),
            render_lambda_args(args),
            render_hash_type(given_res_type),
            render_opt_node(body),
        ],

        // ── Select ────────────────────────────────────────────────────────────
        // productIterator: [obj, field: String, resType: Option[SType]].
        // N2 (E6): unwrap Option[SType] → if inner == Select.tpe → STRIP.
        Select {
            obj,
            field,
            res_type,
            tpe,
        } => {
            let mut fields = vec![print_typed(obj), format!("'{}'", field)];
            let stripped = match res_type {
                None => false,
                Some(t) => t == tpe,
            };
            if !stripped {
                let rendered = match res_type {
                    None => "None".to_string(),
                    Some(t) => render_hash_type(t),
                };
                fields.push(rendered);
            }
            fields
        }

        // ── Apply ─────────────────────────────────────────────────────────────
        Apply { func, args, .. } => vec![print_typed(func), render_seq(args)],

        // ── Tuple ─────────────────────────────────────────────────────────────
        Tuple { items, .. } => vec![render_seq(items)],

        // ── ConcreteCollection ────────────────────────────────────────────────
        // N2: elementType (e.g. SInt) ≠ node.tpe (SColl[SInt]) → never stripped.
        ConcreteCollection {
            items, elem_type, ..
        } => vec![render_seq(items), render_hash_type(elem_type)],

        // ── If ────────────────────────────────────────────────────────────────
        If {
            condition,
            true_branch,
            false_branch,
            ..
        } => vec![
            print_typed(condition),
            print_typed(true_branch),
            print_typed(false_branch),
        ],

        _ => unreachable!("collect_frontend called on non-frontend variant"),
    }
}

/// Fields for arithmetic, bitwise, and boolean-op nodes.
fn collect_arith_bool(e: &TypedExpr) -> Vec<String> {
    use TypedExpr::*;
    match e {
        // ── ArithOp ───────────────────────────────────────────────────────────
        // productIterator: [left, right, opCode: Byte] (signed decimal).
        ArithOp {
            left,
            right,
            opcode,
            ..
        } => vec![
            print_typed(left),
            print_typed(right),
            format!("@{}", opcode),
        ],

        // ── BitOp ─────────────────────────────────────────────────────────────
        BitOp {
            left,
            right,
            opcode,
            ..
        } => vec![
            print_typed(left),
            print_typed(right),
            format!("@{}", opcode),
        ],

        // ── Upcast / Downcast ─────────────────────────────────────────────────
        // N2: tpe == node.tpe → always stripped.
        Upcast { input, .. } | Downcast { input, .. } => vec![print_typed(input)],

        // ── Relations ────────────────────────────────────────────────────────
        GT { left, right, .. }
        | GE { left, right, .. }
        | LT { left, right, .. }
        | LE { left, right, .. }
        | EQ { left, right, .. }
        | NEQ { left, right, .. } => vec![print_typed(left), print_typed(right)],

        // ── Boolean binary ops ────────────────────────────────────────────────
        BinAnd { left, right, .. } | BinOr { left, right, .. } | BinXor { left, right, .. } => {
            vec![print_typed(left), print_typed(right)]
        }

        // ── Unary ops ─────────────────────────────────────────────────────────
        LogicalNot { input, .. } | Negation { input, .. } | BitInversion { input, .. } => {
            vec![print_typed(input)]
        }

        _ => unreachable!("collect_arith_bool called on non-arith/bool variant"),
    }
}

/// Fields for collection-transformer nodes.
fn collect_coll(e: &TypedExpr) -> Vec<String> {
    use TypedExpr::*;
    match e {
        MapCollection { input, mapper, .. } => vec![print_typed(input), print_typed(mapper)],
        Append { input, col2, .. } => vec![print_typed(input), print_typed(col2)],
        Slice {
            input, from, until, ..
        } => vec![print_typed(input), print_typed(from), print_typed(until)],
        Filter {
            input, condition, ..
        } => vec![print_typed(input), print_typed(condition)],
        Exists {
            input, condition, ..
        } => vec![print_typed(input), print_typed(condition)],
        ForAll {
            input, condition, ..
        } => vec![print_typed(input), print_typed(condition)],
        Fold {
            input,
            zero,
            fold_op,
            ..
        } => vec![print_typed(input), print_typed(zero), print_typed(fold_op)],
        ByIndex {
            input,
            index,
            default,
            ..
        } => vec![
            print_typed(input),
            print_typed(index),
            render_opt_node(default),
        ],
        SelectField {
            input, field_index, ..
        } => vec![print_typed(input), format!("@{}", field_index)],
        SizeOf { input, .. } => vec![print_typed(input)],
        _ => unreachable!("collect_coll called on non-collection variant"),
    }
}

/// Fields for sigma-prop, group-element, and option-op nodes.
fn collect_sigma_group(e: &TypedExpr) -> Vec<String> {
    use TypedExpr::*;
    match e {
        // ── SigmaProp / bool coercions ────────────────────────────────────────
        BoolToSigmaProp { value, .. } => vec![print_typed(value)],
        SigmaPropIsProven { input, .. } => vec![print_typed(input)],
        SigmaPropBytes { input, .. } => vec![print_typed(input)],

        // ── Sigma combiners ───────────────────────────────────────────────────
        SigmaAnd { items, .. } | SigmaOr { items, .. } => vec![render_seq(items)],
        AND { input, .. } | OR { input, .. } | XorOf { input, .. } => vec![print_typed(input)],

        // ── Group-element ops ─────────────────────────────────────────────────
        MultiplyGroup { left, right, .. } => vec![print_typed(left), print_typed(right)],
        Exponentiate { left, right, .. } => vec![print_typed(left), print_typed(right)],
        Xor { left, right, .. } => vec![print_typed(left), print_typed(right)],

        // ── Option ops ────────────────────────────────────────────────────────
        OptionGet { input, .. } => vec![print_typed(input)],
        OptionGetOrElse { input, default, .. } => vec![print_typed(input), print_typed(default)],
        OptionIsDefined { input, .. } => vec![print_typed(input)],

        _ => unreachable!("collect_sigma_group called on non-sigma/group variant"),
    }
}

/// Fields for context-access, predef, MethodCall, and pre-typed nodes.
fn collect_ctx_predef(e: &TypedExpr) -> Vec<String> {
    use TypedExpr::*;
    match e {
        // ── Context access ────────────────────────────────────────────────────
        // GetVar productIterator: [varId: Byte, tpe: SOption[V]].
        // N2: tpe == GetVar.tpe → always stripped.
        GetVar { var_id, .. } => vec![format!("@{}", var_id)],

        // DeserializeContext productIterator: [id: Byte, tpe: V].
        // N2: tpe == node.tpe → always stripped.
        DeserializeContext { id, .. } => vec![format!("@{}", id)],

        // DeserializeRegister productIterator: [reg: RegisterId, tpe: V, default].
        // N2: tpe == node.tpe → stripped.  `reg` is a register index (0..=9); the
        // Scala `RegisterId.toString` renders it `R{n}` (oracle: `@R4`), so the
        // productIterator element prints `@R4`, not `@4`.
        DeserializeRegister { reg, default, .. } => {
            vec![format!("@R{}", reg), render_opt_node(default)]
        }

        // ── Predef irBuilder outputs ──────────────────────────────────────────
        CreateProveDlog { value, .. } => vec![print_typed(value)],
        CreateProveDHTuple { gv, hv, uv, vv, .. } => vec![
            print_typed(gv),
            print_typed(hv),
            print_typed(uv),
            print_typed(vv),
        ],
        CalcBlake2b256 { input, .. } => vec![print_typed(input)],
        CalcSha256 { input, .. } => vec![print_typed(input)],
        ByteArrayToBigInt { input, .. } => vec![print_typed(input)],
        ByteArrayToLong { input, .. } => vec![print_typed(input)],
        LongToByteArray { input, .. } => vec![print_typed(input)],
        DecodePoint { input, .. } => vec![print_typed(input)],
        SubstConstants {
            script_bytes,
            positions,
            new_values,
            ..
        } => vec![
            print_typed(script_bytes),
            print_typed(positions),
            print_typed(new_values),
        ],
        AtLeast { bound, input, .. } => vec![print_typed(bound), print_typed(input)],
        CreateAvlTree {
            operation_flags,
            digest,
            key_length,
            value_length_opt,
            ..
        } => vec![
            print_typed(operation_flags),
            print_typed(digest),
            print_typed(key_length),
            print_typed(value_length_opt),
        ],
        TreeLookup {
            tree, key, proof, ..
        } => vec![print_typed(tree), print_typed(key), print_typed(proof)],
        ZKProofBlock { body, .. } => vec![print_typed(body)],

        // ── MethodCall ────────────────────────────────────────────────────────
        // productIterator: [obj, method (SMethod), args (IndexedSeq), typeSubst (Map)].
        // The tpe is derived from method.stype.tRange — NOT a productIterator field.
        MethodCall {
            obj,
            method,
            args,
            type_subst,
            ..
        } => vec![
            print_typed(obj),
            format!("%{}.{}", method.owner, method.name),
            render_seq(args),
            render_type_subst(type_subst),
        ],

        // ── Pre-typed / bound-tree nodes ──────────────────────────────────────
        // These are never in post-typecheck oracle output (see typed.rs for rationale).

        // ApplyTypes productIterator: [input (Value[SFunc]), typeArgs (Seq[SType])].
        // typeArgs render as `[#T1 #T2 …]` (Seq[SType] → space-sep hash-types).
        // source-derived shape: TyperOracle.scala:175 `case it: Iterable[_]` applied
        // to Seq[SType] items each rendered by `case t: SType => "#" + typeTerm(t)`.
        ApplyTypes {
            input, type_args, ..
        } => {
            let type_fields: Vec<String> = type_args.iter().map(render_hash_type).collect();
            vec![print_typed(input), format!("[{}]", type_fields.join(" "))]
        }

        // MethodCallLike productIterator: [obj, name: String, args (IndexedSeq), tpe (N2)].
        // N2: tpe == node.tpe (NoType for pre-typed) → stripped (per extractSType match).
        // source-derived shape: TyperOracle.scala renderNode positional fields.
        MethodCallLike {
            obj, name, args, ..
        } => {
            vec![print_typed(obj), format!("'{}'", name), render_seq(args)]
        }

        _ => unreachable!("collect_ctx_predef: unexpected variant (should be unreachable)"),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed::{MethodRef, TypedExpr, ARITH_PLUS};

    // ----- helpers -----

    fn int_const(v: i32) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Int(v),
            tpe: SType::SInt,
        }
    }

    fn long_const(v: i64) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Long(v),
            tpe: SType::SLong,
        }
    }

    fn bool_const(b: bool) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Bool(b),
            tpe: SType::SBoolean,
        }
    }

    fn height() -> TypedExpr {
        TypedExpr::Height { tpe: SType::SInt }
    }

    fn int_gt(left: TypedExpr, right: TypedExpr) -> TypedExpr {
        TypedExpr::GT {
            left: Box::new(left),
            right: Box::new(right),
            tpe: SType::SBoolean,
        }
    }

    /// Look up the expected oracle output for `source` in the committed seed file.
    ///
    /// The seed file (`test-vectors/ergoscript/typer/golden_seed.txt`) is embedded
    /// at compile time so tests can't silently drift from the authoritative expected
    /// values.  Panics on a first-match `REJECT` line (fail-loud); only `OK` lines
    /// produce a return value.
    fn seed_expected(source: &str) -> String {
        let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
        for line in seed.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            if parts.len() == 3 && parts[1] == source {
                let expected = parts[2];
                if let Some(rest) = expected.strip_prefix("OK ") {
                    return rest.to_string();
                }
                panic!("seed line for {:?} is not OK: {}", source, expected);
            }
        }
        panic!("no seed line found for source: {:?}", source);
    }

    // ----- to_term_string unit tests -----

    #[test]
    fn to_term_string_primitives() {
        assert_eq!(to_term_string(&SType::SBoolean), "Boolean");
        assert_eq!(to_term_string(&SType::SByte), "Byte");
        assert_eq!(to_term_string(&SType::SShort), "Short");
        assert_eq!(to_term_string(&SType::SInt), "Int");
        assert_eq!(to_term_string(&SType::SLong), "Long");
        assert_eq!(to_term_string(&SType::SBigInt), "BigInt");
        assert_eq!(to_term_string(&SType::SGroupElement), "GroupElement");
        assert_eq!(to_term_string(&SType::SSigmaProp), "SigmaProp");
        assert_eq!(to_term_string(&SType::SAvlTree), "AvlTree");
        assert_eq!(to_term_string(&SType::SBox), "Box");
        assert_eq!(to_term_string(&SType::SUnit), "Unit");
    }

    #[test]
    fn to_term_string_sglobal_renders_as_sigma_dsl_builder() {
        // golden seed: `(Global:SigmaDslBuilder)` — SGlobal's typeName in Scala.
        assert_eq!(to_term_string(&SType::SGlobal), "SigmaDslBuilder");
    }

    #[test]
    fn to_term_string_compound_types() {
        assert_eq!(
            to_term_string(&SType::SColl(Box::new(SType::SByte))),
            "Coll[Byte]"
        );
        assert_eq!(
            to_term_string(&SType::SOption(Box::new(SType::SInt))),
            "Option[Int]"
        );
        assert_eq!(
            to_term_string(&SType::STuple(vec![SType::SLong, SType::SLong])),
            "(Long,Long)"
        );
        assert_eq!(
            to_term_string(&SType::SFunc {
                dom: vec![SType::SBox],
                range: Box::new(SType::SLong),
                tpe_params: vec![],
            }),
            "(Box) => Long"
        );
        assert_eq!(
            to_term_string(&SType::SFunc {
                dom: vec![SType::SLong],
                range: Box::new(SType::SBoolean),
                tpe_params: vec![],
            }),
            "(Long) => Boolean"
        );
    }

    #[test]
    fn to_term_string_stypevar() {
        assert_eq!(to_term_string(&SType::STypeVar("T".to_string())), "T");
    }

    /// B5: a polymorphic function type prepends its comma-joined `[params]` binder
    /// (SType.scala:644,653); a monomorphic one (empty params) has no prefix.
    #[test]
    fn to_term_string_sfunc_polymorphic_prints_type_param_binder() {
        // [T](T,T) => T  (min/max shape).
        assert_eq!(
            to_term_string(&SType::SFunc {
                dom: vec![SType::STypeVar("T".into()), SType::STypeVar("T".into())],
                range: Box::new(SType::STypeVar("T".into())),
                tpe_params: vec!["T".into()],
            }),
            "[T](T,T) => T"
        );
        // Multi-param, comma-joined (no spaces): [K,L].
        assert_eq!(
            to_term_string(&SType::SFunc {
                dom: vec![SType::STypeVar("K".into())],
                range: Box::new(SType::STypeVar("L".into())),
                tpe_params: vec!["K".into(), "L".into()],
            }),
            "[K,L](K) => L"
        );
        // Empty tpe_params → no prefix (monomorphic function types unchanged).
        assert_eq!(
            to_term_string(&SType::SFunc {
                dom: vec![SType::SBox],
                range: Box::new(SType::SLong),
                tpe_params: vec![],
            }),
            "(Box) => Long"
        );
    }

    #[test]
    fn to_term_string_nested_coll() {
        assert_eq!(
            to_term_string(&SType::SColl(Box::new(SType::SOption(Box::new(
                SType::SInt
            ))))),
            "Coll[Option[Int]]"
        );
    }

    // ----- happy path (golden seed fixtures) -----

    /// golden seed line 19: `tc sigmaProp(HEIGHT > 100)`
    #[test]
    fn fixture_bool_to_sigma_prop_height_gt_100() {
        let e = TypedExpr::BoolToSigmaProp {
            value: Box::new(int_gt(height(), int_const(100))),
            tpe: SType::SSigmaProp,
        };
        assert_eq!(print_typed(&e), seed_expected("sigmaProp(HEIGHT > 100)"));
    }

    /// golden seed line 20: `tc { val x = HEIGHT; x > 5 }`
    #[test]
    fn fixture_block_val_x_height_gt_5() {
        let x_ident = TypedExpr::Ident {
            name: "x".to_string(),
            tpe: SType::SInt,
        };
        let val_x = TypedExpr::ValNode {
            name: "x".to_string(),
            given_type: SType::SInt,
            body: Box::new(height()),
            tpe: SType::SInt,
        };
        let result = int_gt(x_ident, int_const(5));
        let e = TypedExpr::Block {
            bindings: vec![val_x],
            result: Box::new(result),
            tpe: SType::SBoolean,
        };
        assert_eq!(print_typed(&e), seed_expected("{ val x = HEIGHT; x > 5 }"));
    }

    /// golden seed line 21: `tc INPUTS.map({(b:Box)=>b.value})`
    #[test]
    fn fixture_inputs_map_b_value() {
        let b_ident = TypedExpr::Ident {
            name: "b".to_string(),
            tpe: SType::SBox,
        };
        let select_value = TypedExpr::Select {
            obj: Box::new(b_ident),
            field: "value".to_string(),
            res_type: Some(SType::SLong),
            tpe: SType::SLong,
        };
        let lambda = TypedExpr::Lambda {
            tpe_params: vec![],
            args: vec![("b".to_string(), SType::SBox)],
            given_res_type: SType::SLong,
            body: Some(Box::new(select_value)),
            tpe: SType::SFunc {
                dom: vec![SType::SBox],
                range: Box::new(SType::SLong),
                tpe_params: vec![],
            },
        };
        let inputs = TypedExpr::Inputs {
            tpe: SType::SColl(Box::new(SType::SBox)),
        };
        let e = TypedExpr::MapCollection {
            input: Box::new(inputs),
            mapper: Box::new(lambda),
            tpe: SType::SColl(Box::new(SType::SLong)),
        };
        assert_eq!(
            print_typed(&e),
            seed_expected("INPUTS.map({(b:Box)=>b.value})")
        );
    }

    /// golden seed line 22: `tce a ++ b`
    #[test]
    fn fixture_append_byte_colls() {
        let a = TypedExpr::Constant {
            value: ConstPayload::ByteColl(vec![1, 2]),
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        let b = TypedExpr::Constant {
            value: ConstPayload::ByteColl(vec![3, 4]),
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        let e = TypedExpr::Append {
            input: Box::new(a),
            col2: Box::new(b),
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        assert_eq!(print_typed(&e), seed_expected("a ++ b"));
    }

    /// golden seed line 23: `tc 1L + 1`
    #[test]
    fn fixture_arith_op_long_plus() {
        let upcast = TypedExpr::Upcast {
            input: Box::new(int_const(1)),
            tpe: SType::SLong,
        };
        let e = TypedExpr::ArithOp {
            left: Box::new(long_const(1)),
            right: Box::new(upcast),
            opcode: ARITH_PLUS,
            tpe: SType::SLong,
        };
        assert_eq!(print_typed(&e), seed_expected("1L + 1"));
    }

    /// golden seed line 26: `tc 1.toByte + 2.toByte`
    #[test]
    fn fixture_arith_op_byte_select_tobyte() {
        let sel1 = TypedExpr::Select {
            obj: Box::new(int_const(1)),
            field: "toByte".to_string(),
            res_type: Some(SType::SByte),
            tpe: SType::SByte,
        };
        let sel2 = TypedExpr::Select {
            obj: Box::new(int_const(2)),
            field: "toByte".to_string(),
            res_type: Some(SType::SByte),
            tpe: SType::SByte,
        };
        let e = TypedExpr::ArithOp {
            left: Box::new(sel1),
            right: Box::new(sel2),
            opcode: ARITH_PLUS,
            tpe: SType::SByte,
        };
        assert_eq!(print_typed(&e), seed_expected("1.toByte + 2.toByte"));
    }

    /// golden seed line 27: `tc true && (1 == 1)`
    #[test]
    fn fixture_bin_and_bool_eq() {
        let eq_node = TypedExpr::EQ {
            left: Box::new(int_const(1)),
            right: Box::new(int_const(1)),
            tpe: SType::SBoolean,
        };
        let e = TypedExpr::BinAnd {
            left: Box::new(bool_const(true)),
            right: Box::new(eq_node),
            tpe: SType::SBoolean,
        };
        assert_eq!(print_typed(&e), seed_expected("true && (1 == 1)"));
    }

    /// golden seed line 28: `tc HEIGHT>5 && HEIGHT<9`
    #[test]
    fn fixture_bin_and_height_range() {
        let gt = int_gt(height(), int_const(5));
        let lt = TypedExpr::LT {
            left: Box::new(height()),
            right: Box::new(int_const(9)),
            tpe: SType::SBoolean,
        };
        let e = TypedExpr::BinAnd {
            left: Box::new(gt),
            right: Box::new(lt),
            tpe: SType::SBoolean,
        };
        assert_eq!(print_typed(&e), seed_expected("HEIGHT>5 && HEIGHT<9"));
    }

    /// golden seed line 29: `tc Coll(1, 2, 3)`
    #[test]
    fn fixture_concrete_collection_ints() {
        let e = TypedExpr::ConcreteCollection {
            items: vec![int_const(1), int_const(2), int_const(3)],
            elem_type: SType::SInt,
            tpe: SType::SColl(Box::new(SType::SInt)),
        };
        assert_eq!(print_typed(&e), seed_expected("Coll(1, 2, 3)"));
    }

    /// golden seed line 30: `tce col1.exists({(x:Long)=>x>1L})`
    #[test]
    fn fixture_exists_long_gt() {
        let col1 = TypedExpr::Constant {
            value: ConstPayload::LongColl(vec![1, 2]),
            tpe: SType::SColl(Box::new(SType::SLong)),
        };
        let x_ident = TypedExpr::Ident {
            name: "x".to_string(),
            tpe: SType::SLong,
        };
        let body = TypedExpr::GT {
            left: Box::new(x_ident),
            right: Box::new(long_const(1)),
            tpe: SType::SBoolean,
        };
        let lambda = TypedExpr::Lambda {
            tpe_params: vec![],
            args: vec![("x".to_string(), SType::SLong)],
            given_res_type: SType::SBoolean,
            body: Some(Box::new(body)),
            tpe: SType::SFunc {
                dom: vec![SType::SLong],
                range: Box::new(SType::SBoolean),
                tpe_params: vec![],
            },
        };
        let e = TypedExpr::Exists {
            input: Box::new(col1),
            condition: Box::new(lambda),
            tpe: SType::SBoolean,
        };
        assert_eq!(
            print_typed(&e),
            seed_expected("col1.exists({(x:Long)=>x>1L})")
        );
    }

    /// golden seed line 46: `tc Global.serialize(1)`
    #[test]
    fn fixture_method_call_global_serialize() {
        let e = TypedExpr::MethodCall {
            obj: Box::new(TypedExpr::Global {
                tpe: SType::SGlobal,
            }),
            method: MethodRef {
                owner: "SigmaDslBuilder".to_string(),
                name: "serialize".to_string(),
            },
            args: vec![int_const(1)],
            type_subst: vec![],
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        assert_eq!(print_typed(&e), seed_expected("Global.serialize(1)"));
    }

    /// golden seed line 47: `tce Global.some[Int](1)`
    #[test]
    fn fixture_method_call_global_some_int() {
        let e = TypedExpr::MethodCall {
            obj: Box::new(TypedExpr::Global {
                tpe: SType::SGlobal,
            }),
            method: MethodRef {
                owner: "SigmaDslBuilder".to_string(),
                name: "some".to_string(),
            },
            args: vec![int_const(1)],
            type_subst: vec![("T".to_string(), SType::SInt)],
            tpe: SType::SOption(Box::new(SType::SInt)),
        };
        assert_eq!(print_typed(&e), seed_expected("Global.some[Int](1)"));
    }

    /// golden seed line 80: `tc getVar[AvlTree](1).get.digest`
    #[test]
    fn fixture_method_call_avl_digest() {
        let get_var = TypedExpr::GetVar {
            var_id: 1,
            tpe: SType::SOption(Box::new(SType::SAvlTree)),
        };
        let option_get = TypedExpr::OptionGet {
            input: Box::new(get_var),
            tpe: SType::SAvlTree,
        };
        let e = TypedExpr::MethodCall {
            obj: Box::new(option_get),
            method: MethodRef {
                owner: "AvlTree".to_string(),
                name: "digest".to_string(),
            },
            args: vec![],
            type_subst: vec![],
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        assert_eq!(
            print_typed(&e),
            seed_expected("getVar[AvlTree](1).get.digest")
        );
    }

    /// golden seed line 31: `tc HEIGHT > 5`
    #[test]
    fn fixture_height_gt_5() {
        let e = int_gt(height(), int_const(5));
        assert_eq!(print_typed(&e), seed_expected("HEIGHT > 5"));
    }

    /// golden seed line 48: `tc Global.none[Int]()`
    #[test]
    fn fixture_method_call_global_none_int() {
        let e = TypedExpr::MethodCall {
            obj: Box::new(TypedExpr::Global {
                tpe: SType::SGlobal,
            }),
            method: MethodRef {
                owner: "SigmaDslBuilder".to_string(),
                name: "none".to_string(),
            },
            args: vec![],
            type_subst: vec![("T".to_string(), SType::SInt)],
            tpe: SType::SOption(Box::new(SType::SInt)),
        };
        assert_eq!(print_typed(&e), seed_expected("Global.none[Int]()"));
    }

    // ----- round-trips -----

    #[test]
    fn singleton_singletons_render_without_fields() {
        assert_eq!(
            print_typed(&TypedExpr::Height { tpe: SType::SInt }),
            "(Height:Int)"
        );
        assert_eq!(
            print_typed(&TypedExpr::Self_ { tpe: SType::SBox }),
            "(Self:Box)"
        );
        assert_eq!(
            print_typed(&TypedExpr::Inputs {
                tpe: SType::SColl(Box::new(SType::SBox))
            }),
            "(Inputs:Coll[Box])"
        );
        assert_eq!(
            print_typed(&TypedExpr::Global {
                tpe: SType::SGlobal
            }),
            "(Global:SigmaDslBuilder)"
        );
        assert_eq!(
            print_typed(&TypedExpr::LastBlockUtxoRootHash {
                tpe: SType::SAvlTree
            }),
            "(LastBlockUtxoRootHash:AvlTree)"
        );
    }

    /// N4: multiple typeSubst entries are sorted by full rendered entry string and
    /// joined with "," (TyperOracle.scala:172-173 `.sorted` + `mkString("{",",","}")`).
    ///
    /// source-derived: TyperOracle.scala:172-173 mkString(",") — no 2-subst producer
    /// found in 6.0.2 typer output after 6 probes (col1.flatMap, Global.some[Coll[Int]],
    /// Global.fromBigEndianBytes, Coll(1,2).zip(Coll(true,false)),
    /// Coll(Coll(1,2),Coll(3,4)).flatMap, Coll(1,2).fold). All surviving MethodCall
    /// nodes have 0 or 1 typeSubst entry in sigma-state 6.0.2.
    #[test]
    fn type_subst_comma_separated_sorted_by_full_entry() {
        // N4: multiple typeSubst entries → comma-separated, sorted by full `#K->#V` string.
        // #T->#Int < #U->#Long lexicographically (T before U).
        let subst = vec![
            ("U".to_string(), SType::SLong),
            ("T".to_string(), SType::SInt),
        ];
        let mc = TypedExpr::MethodCall {
            obj: Box::new(TypedExpr::Global {
                tpe: SType::SGlobal,
            }),
            method: MethodRef {
                owner: "SigmaDslBuilder".to_string(),
                name: "test".to_string(),
            },
            args: vec![],
            type_subst: subst,
            tpe: SType::SUnit,
        };
        // Comma-separated: `{#T->#Int,#U->#Long}`.
        let s = print_typed(&mc);
        assert!(s.contains("{#T->#Int,#U->#Long}"), "got: {}", s);
    }

    // ----- error paths -----

    #[test]
    fn bigint_constant_renders_cbigint_wrapper() {
        let e = TypedExpr::Constant {
            value: ConstPayload::BigInt("5".to_string()),
            tpe: SType::SBigInt,
        };
        assert_eq!(print_typed(&e), "(ConstantNode:BigInt (CBigInt @5))");
    }

    #[test]
    fn group_element_constant_renders_cecp_wrapper() {
        // secp256k1 generator G, SEC1-compressed; oracle x/y at golden_seed.txt L54/L126.
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        let e = TypedExpr::Constant {
            value: ConstPayload::GroupElement(bytes),
            tpe: SType::SGroupElement,
        };
        let expected = "(ConstantNode:GroupElement (CGroupElement (Ecp @(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,1))))";
        assert_eq!(print_typed(&e), expected);
    }

    /// D-T4/D-T6 leading-zero-y fix: `ECPoint.toString`'s `Ecp @(x,y,1)` prints
    /// UNPADDED `BigInteger.toString(16)` hex, not our fixed-width 64-char
    /// decompression — the y-coordinate below (`0ab0902e...`) loses its
    /// leading zero. Oracle-pinned via `PK("3WzPmMVoyrrj1m9NkmpWchWoiZy1wN3wYsmn8gE1cZXcdwck7LBg")`,
    /// golden_seed.txt §23(f).
    #[test]
    fn provedlog_constant_leading_zero_y_renders_unpadded() {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x03;
        let x = hex::decode("f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        let e = TypedExpr::Constant {
            value: ConstPayload::ProveDlog(bytes),
            tpe: SType::SSigmaProp,
        };
        let expected = "(ConstantNode:SigmaProp (CSigmaProp (ProveDlog (Ecp @(f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81,1)))))";
        assert_eq!(print_typed(&e), expected);
    }

    #[test]
    fn empty_byte_coll_renders_angle_brackets() {
        let e = TypedExpr::Constant {
            value: ConstPayload::ByteColl(vec![]),
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        assert_eq!(print_typed(&e), "(ConstantNode:Coll[Byte] <>)");
    }

    // ----- oracle parity — new §8 vectors (Fix round 1) -----

    /// golden seed §8: `tc ()` → `(ConstantNode:Unit @())`
    ///
    /// Verifies Fix 2: Unit constant emits its `@()` payload (was erroneously
    /// suppressed).  Pinned against ORACLE_TREE_VERSION=3.
    #[test]
    fn fixture_unit_constant_emits_at_unit() {
        let e = TypedExpr::Constant {
            value: ConstPayload::Unit,
            tpe: SType::SUnit,
        };
        assert_eq!(print_typed(&e), seed_expected("()"));
    }

    /// golden seed §8: `tc "ab" + "cd"` → `(ConstantNode:String 'abcd')`
    ///
    /// Verifies Fix 3: ConstPayload::String renders with single quotes.
    /// The Scala typer const-folds string concatenation → one StringConstant.
    /// Pinned against ORACLE_TREE_VERSION=3.
    #[test]
    fn fixture_string_constant_renders_single_quotes() {
        let e = TypedExpr::Constant {
            value: ConstPayload::String("abcd".to_string()),
            tpe: SType::SString,
        };
        assert_eq!(print_typed(&e), seed_expected("\"ab\" + \"cd\""));
    }

    // ----- E11 bound-tree variant rendering (source-derived; no oracle vectors) -----

    /// ApplyTypes renders as `(ApplyTypes:<tpe> <input> [#T1 #T2 …])`.
    ///
    /// Source-derived shape: TyperOracle.scala positional rendering — input rendered
    /// as a node, typeArgs as `[#T1 #T2 …]` (Iterable[SType] → each `#typeTerm`).
    /// Doc note: oracle never prints ApplyTypes because `typecheck` eliminates it.
    #[test]
    fn apply_types_renders_positionally() {
        let e = TypedExpr::ApplyTypes {
            input: Box::new(TypedExpr::Ident {
                name: "f".to_string(),
                tpe: SType::SFunc {
                    dom: vec![],
                    range: Box::new(SType::SLong),
                    tpe_params: vec![],
                },
            }),
            type_args: vec![SType::SLong, SType::SInt],
            tpe: SType::SLong,
        };
        let s = print_typed(&e);
        assert_eq!(s, "(ApplyTypes:Long (Ident:() => Long 'f') [#Long #Int])");
    }

    /// MethodCallLike renders as `(MethodCallLike:<tpe> <obj> '<name>' [args…])`.
    ///
    /// Source-derived shape: TyperOracle.scala positional rendering — obj, name
    /// (String → single-quoted), args (sequence). tpe (NoType for pre-typed) is
    /// stripped by N2 (== node.tpe).
    /// Doc note: oracle never prints MethodCallLike because `typecheck` eliminates it.
    #[test]
    fn method_call_like_renders_positionally() {
        let e = TypedExpr::MethodCallLike {
            obj: Box::new(height()),
            name: "foo".to_string(),
            args: vec![int_const(1)],
            tpe: SType::NoType,
        };
        let s = print_typed(&e);
        assert_eq!(
            s,
            "(MethodCallLike:NoType (Height:Int) 'foo' [(ConstantNode:Int @1)])"
        );
    }
}
