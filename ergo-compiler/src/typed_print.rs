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
//!   N4 — typeSubst entries are sorted by rendered key, rendered as
//!        `{#k->#v …}` or `{}`.
//!   N5 — String fields render as `'text'`; numeric scalars as `@n`; SType
//!        fields as `#TypeTermString`; MethodRef as `%Owner.name`; node
//!        sequences as `[n1 n2 …]`; primitive arrays as `<@v1 @v2 …>`;
//!        Option[SValue] as "None" or the unwrapped node; lambda args as
//!        `[name:#Type …]`.

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
        SType::SFunc { dom, range } => {
            // `(T1,T2) => R` — parens even for single-element domain.
            // Verified: `(Box) => Long`, `(Long) => Boolean` in golden seed.
            let dom_parts: Vec<String> = dom.iter().map(to_term_string).collect();
            format!("({}) => {}", dom_parts.join(","), to_term_string(range))
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

/// Render `MethodCall.type_subst` as `{#k1->#v1 …}` sorted by key (N4).
/// Empty → `{}`.
fn render_type_subst(subst: &[(String, SType)]) -> String {
    if subst.is_empty() {
        return "{}".to_string();
    }
    // Build (rendered_key, rendered_value) pairs.
    let mut entries: Vec<(String, String)> = subst
        .iter()
        .map(|(k, v)| (format!("#{}", k), format!("#{}", to_term_string(v))))
        .collect();
    // N4: sort by rendered key (lexicographic on the `#<ident>` string).
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let parts: Vec<String> = entries
        .iter()
        .map(|(k, v)| format!("{}->{}", k, v))
        .collect();
    format!("{{{}}}", parts.join(" "))
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
///   Unit                → `@()` (Scala productIterator value for unit)
///   ByteColl/LongColl   → `<@v1 @v2 …>` (N5 primitive-seq form)
///   GroupElement(s)     → `(CGroupElement (Ecp @s))` — wraps the Ecp string
///   SigmaProp(s)        → opaque string (M3 scope for full parity)
fn render_payload(p: &ConstPayload) -> String {
    match p {
        ConstPayload::Bool(b) => format!("@{}", b),
        ConstPayload::Byte(n) => format!("@{}", n),
        ConstPayload::Short(n) => format!("@{}", n),
        ConstPayload::Int(n) => format!("@{}", n),
        ConstPayload::Long(n) => format!("@{}", n),
        ConstPayload::BigInt(s) => format!("(CBigInt @{})", s),
        // Scala Unit renders as `@()` in productIterator context.
        ConstPayload::Unit => "@()".to_string(),
        ConstPayload::ByteColl(vs) => {
            let parts: Vec<String> = vs.iter().map(|v| format!("@{}", v)).collect();
            format!("<{}>", parts.join(" "))
        }
        ConstPayload::LongColl(vs) => {
            let parts: Vec<String> = vs.iter().map(|v| format!("@{}", v)).collect();
            format!("<{}>", parts.join(" "))
        }
        ConstPayload::GroupElement(ecp_str) => {
            format!("(CGroupElement (Ecp @{}))", ecp_str)
        }
        // SigmaProp: opaque in M2; store the full representation string.
        ConstPayload::SigmaProp(s) => s.clone(),
    }
}

/// Collect all rendered fields for a node in Scala productIterator order,
/// applying N2 to skip SType fields that equal the node's own tpe.
///
/// Returns `Vec<String>` — the caller joins with " " and wraps in parens.
#[allow(clippy::too_many_lines)] // this is inherently a large match
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

        // ── Constant ─────────────────────────────────────────────────────────
        // productIterator: [value, tpe].
        // N2: tpe == Constant.tpe → always stripped.
        // If payload is Unit, Scala productIterator still has a value `()` but
        // the oracle renders nothing beyond the type header.  For all other
        // payloads, `render_payload` produces the appropriate @-or-parens form.
        Constant { value, tpe: _ } => {
            // Unit constant has no visible value field in the oracle format
            // (Scala: "ConstantNode:Unit" with nothing after).
            if matches!(value, ConstPayload::Unit) {
                vec![]
            } else {
                vec![render_payload(value)]
            }
        }

        // ── Block ─────────────────────────────────────────────────────────────
        // productIterator: [bindings: Seq[Val], result: SValue].
        Block {
            bindings, result, ..
        } => vec![render_seq(bindings), print_typed(result)],

        // ── ValNode ───────────────────────────────────────────────────────────
        // productIterator: [name, givenType, body].
        // N2: givenType (bare SType) == ValNode.tpe (= givenType always) → STRIP.
        ValNode {
            name,
            given_type: _,
            body,
            ..
        } => vec![format!("'{}'", name), print_typed(body)],

        // ── Ident ─────────────────────────────────────────────────────────────
        // productIterator: [name, tpe].
        // N2: tpe == Ident.tpe → always stripped.
        Ident { name, .. } => vec![format!("'{}'", name)],

        // ── Lambda ────────────────────────────────────────────────────────────
        // productIterator: [tpeParams, args, givenResType, body].
        // givenResType is a bare SType; Lambda.tpe = SFunc(…) → never equal →
        // N2 never strips it.
        // body: Option[SValue] — None → "None", Some(e) → rendered node.
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
        // In practice all well-typed Select nodes have resType == Some(tpe).
        Select {
            obj,
            field,
            res_type,
            tpe,
        } => {
            let mut fields = vec![print_typed(obj), format!("'{}'", field)];
            // N2(E6): unwrap Option before self-type test.
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
        // productIterator: [func, args: Seq[SValue]].
        Apply { func, args, .. } => vec![print_typed(func), render_seq(args)],

        // ── Tuple ─────────────────────────────────────────────────────────────
        // productIterator: [items: Seq[SValue]].
        Tuple { items, .. } => vec![render_seq(items)],

        // ── ConcreteCollection ────────────────────────────────────────────────
        // productIterator: [items: Seq, elementType: SType].
        // N2: elementType (e.g. SInt) ≠ node.tpe (SColl[SInt]) → never stripped.
        ConcreteCollection {
            items, elem_type, ..
        } => vec![render_seq(items), render_hash_type(elem_type)],

        // ── If ────────────────────────────────────────────────────────────────
        // productIterator: [condition, trueBranch, falseBranch].
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

        // ── ArithOp ───────────────────────────────────────────────────────────
        // productIterator: [left, right, opCode: Byte].
        // opCode renders as @n (signed decimal i8).
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
        // productIterator: [left, right, opCode: Byte].
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
        // productIterator: [input, tpe: R].
        // N2: tpe == node.tpe → always stripped.
        Upcast { input, .. } | Downcast { input, .. } => vec![print_typed(input)],

        // ── Relations (GT/GE/LT/LE/EQ/NEQ) ──────────────────────────────────
        // productIterator: [left, right]. No SType fields.
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

        // ── Collection transformers ───────────────────────────────────────────
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

        // ── Context access ────────────────────────────────────────────────────
        // GetVar productIterator: [varId: Byte, tpe: SOption[V]].
        // N2: tpe == GetVar.tpe → always stripped.
        GetVar { var_id, .. } => vec![format!("@{}", var_id)],

        // DeserializeContext productIterator: [id: Byte, tpe: V].
        // N2: tpe == node.tpe → always stripped.
        DeserializeContext { id, .. } => vec![format!("@{}", id)],

        // DeserializeRegister productIterator: [reg: Byte, tpe: V, default].
        // N2: tpe == node.tpe → stripped.
        DeserializeRegister { reg, default, .. } => {
            vec![format!("@{}", reg), render_opt_node(default)]
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
        // All four positional fields are always rendered (empty args → `[]`,
        // empty subst → `{}`).
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
            }),
            "(Box) => Long"
        );
        assert_eq!(
            to_term_string(&SType::SFunc {
                dom: vec![SType::SLong],
                range: Box::new(SType::SBoolean),
            }),
            "(Long) => Boolean"
        );
    }

    #[test]
    fn to_term_string_stypevar() {
        assert_eq!(to_term_string(&SType::STypeVar("T".to_string())), "T");
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

    /// golden seed line 19:
    /// `tc sigmaProp(HEIGHT > 100)   OK (BoolToSigmaProp:SigmaProp (GT:Boolean (Height:Int) (ConstantNode:Int @100)))`
    #[test]
    fn fixture_bool_to_sigma_prop_height_gt_100() {
        let e = TypedExpr::BoolToSigmaProp {
            value: Box::new(int_gt(height(), int_const(100))),
            tpe: SType::SSigmaProp,
        };
        assert_eq!(
            print_typed(&e),
            "(BoolToSigmaProp:SigmaProp (GT:Boolean (Height:Int) (ConstantNode:Int @100)))"
        );
    }

    /// golden seed line 20:
    /// `tc { val x = HEIGHT; x > 5 }   OK (Block:Boolean [(ValNode:Int 'x' (Height:Int))] (GT:Boolean (Ident:Int 'x') (ConstantNode:Int @5)))`
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
        assert_eq!(
            print_typed(&e),
            "(Block:Boolean [(ValNode:Int 'x' (Height:Int))] (GT:Boolean (Ident:Int 'x') (ConstantNode:Int @5)))"
        );
    }

    /// golden seed line 21:
    /// `tc INPUTS.map({(b:Box)=>b.value})   OK (MapCollection:Coll[Long] (Inputs:Coll[Box]) (Lambda:(Box) => Long [] [b:#Box] #Long (Select:Long (Ident:Box 'b') 'value')))`
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
            "(MapCollection:Coll[Long] (Inputs:Coll[Box]) (Lambda:(Box) => Long [] [b:#Box] #Long (Select:Long (Ident:Box 'b') 'value')))"
        );
    }

    /// golden seed line 22 (tce, demo env a,b:Coll[Byte]):
    /// `tce a ++ b   OK (Append:Coll[Byte] (ConstantNode:Coll[Byte] <@1 @2>) (ConstantNode:Coll[Byte] <@3 @4>))`
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
        assert_eq!(
            print_typed(&e),
            "(Append:Coll[Byte] (ConstantNode:Coll[Byte] <@1 @2>) (ConstantNode:Coll[Byte] <@3 @4>))"
        );
    }

    /// golden seed line 23:
    /// `tc 1L + 1   OK (ArithOp:Long (ConstantNode:Long @1) (Upcast:Long (ConstantNode:Int @1)) @-102)`
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
        assert_eq!(
            print_typed(&e),
            "(ArithOp:Long (ConstantNode:Long @1) (Upcast:Long (ConstantNode:Int @1)) @-102)"
        );
    }

    /// golden seed line 26:
    /// `tc 1.toByte + 2.toByte   OK (ArithOp:Byte (Select:Byte (ConstantNode:Int @1) 'toByte') (Select:Byte (ConstantNode:Int @2) 'toByte') @-102)`
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
        assert_eq!(
            print_typed(&e),
            "(ArithOp:Byte (Select:Byte (ConstantNode:Int @1) 'toByte') (Select:Byte (ConstantNode:Int @2) 'toByte') @-102)"
        );
    }

    /// golden seed line 27:
    /// `tc true && (1 == 1)   OK (BinAnd:Boolean (ConstantNode:Boolean @true) (EQ:Boolean (ConstantNode:Int @1) (ConstantNode:Int @1)))`
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
        assert_eq!(
            print_typed(&e),
            "(BinAnd:Boolean (ConstantNode:Boolean @true) (EQ:Boolean (ConstantNode:Int @1) (ConstantNode:Int @1)))"
        );
    }

    /// golden seed line 28:
    /// `tc HEIGHT>5 && HEIGHT<9   OK (BinAnd:Boolean (GT:Boolean (Height:Int) (ConstantNode:Int @5)) (LT:Boolean (Height:Int) (ConstantNode:Int @9)))`
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
        assert_eq!(
            print_typed(&e),
            "(BinAnd:Boolean (GT:Boolean (Height:Int) (ConstantNode:Int @5)) (LT:Boolean (Height:Int) (ConstantNode:Int @9)))"
        );
    }

    /// golden seed line 29:
    /// `tc Coll(1, 2, 3)   OK (ConcreteCollection:Coll[Int] [(ConstantNode:Int @1) (ConstantNode:Int @2) (ConstantNode:Int @3)] #Int)`
    #[test]
    fn fixture_concrete_collection_ints() {
        let e = TypedExpr::ConcreteCollection {
            items: vec![int_const(1), int_const(2), int_const(3)],
            elem_type: SType::SInt,
            tpe: SType::SColl(Box::new(SType::SInt)),
        };
        assert_eq!(
            print_typed(&e),
            "(ConcreteCollection:Coll[Int] [(ConstantNode:Int @1) (ConstantNode:Int @2) (ConstantNode:Int @3)] #Int)"
        );
    }

    /// golden seed line 30 (tce, demo env col1:Coll[Long]):
    /// `tce col1.exists({(x:Long)=>x>1L})   OK (Exists:Boolean (ConstantNode:Coll[Long] <@1 @2>) (Lambda:(Long) => Boolean [] [x:#Long] #Boolean (GT:Boolean (Ident:Long 'x') (ConstantNode:Long @1))))`
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
            },
        };
        let e = TypedExpr::Exists {
            input: Box::new(col1),
            condition: Box::new(lambda),
            tpe: SType::SBoolean,
        };
        assert_eq!(
            print_typed(&e),
            "(Exists:Boolean (ConstantNode:Coll[Long] <@1 @2>) (Lambda:(Long) => Boolean [] [x:#Long] #Boolean (GT:Boolean (Ident:Long 'x') (ConstantNode:Long @1))))"
        );
    }

    /// golden seed line 46:
    /// `tc Global.serialize(1)   OK (MethodCall:Coll[Byte] (Global:SigmaDslBuilder) %SigmaDslBuilder.serialize [(ConstantNode:Int @1)] {})`
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
        assert_eq!(
            print_typed(&e),
            "(MethodCall:Coll[Byte] (Global:SigmaDslBuilder) %SigmaDslBuilder.serialize [(ConstantNode:Int @1)] {})"
        );
    }

    /// golden seed line 47 (tce):
    /// `tce Global.some[Int](1)   OK (MethodCall:Option[Int] (Global:SigmaDslBuilder) %SigmaDslBuilder.some [(ConstantNode:Int @1)] {#T->#Int})`
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
        assert_eq!(
            print_typed(&e),
            "(MethodCall:Option[Int] (Global:SigmaDslBuilder) %SigmaDslBuilder.some [(ConstantNode:Int @1)] {#T->#Int})"
        );
    }

    /// golden seed line 80:
    /// `tc getVar[AvlTree](1).get.digest   OK (MethodCall:Coll[Byte] (OptionGet:AvlTree (GetVar:Option[AvlTree] @1)) %AvlTree.digest [] {})`
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
            "(MethodCall:Coll[Byte] (OptionGet:AvlTree (GetVar:Option[AvlTree] @1)) %AvlTree.digest [] {})"
        );
    }

    /// golden seed line 31:
    /// `tc HEIGHT > 5   OK (GT:Boolean (Height:Int) (ConstantNode:Int @5))`
    #[test]
    fn fixture_height_gt_5() {
        let e = int_gt(height(), int_const(5));
        assert_eq!(
            print_typed(&e),
            "(GT:Boolean (Height:Int) (ConstantNode:Int @5))"
        );
    }

    // ----- round-trips -----

    #[test]
    fn singleton_singletons_render_without_fields() {
        // Singletons have no payload fields — just the header.
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

    #[test]
    fn type_subst_sorted_lexicographically() {
        // N4: multiple typeSubst entries are sorted by rendered key.
        // #T->#Int and #U->#Long → sort order: #T < #U.
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
        // Should be {#T->#Int #U->#Long} — T before U.
        let s = print_typed(&mc);
        assert!(s.contains("{#T->#Int #U->#Long}"), "got: {}", s);
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
        let ecp = "(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,1)";
        let e = TypedExpr::Constant {
            value: ConstPayload::GroupElement(ecp.to_string()),
            tpe: SType::SGroupElement,
        };
        let expected = format!("(ConstantNode:GroupElement (CGroupElement (Ecp @{})))", ecp);
        assert_eq!(print_typed(&e), expected);
    }

    #[test]
    fn empty_byte_coll_renders_angle_brackets() {
        let e = TypedExpr::Constant {
            value: ConstPayload::ByteColl(vec![]),
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        // Empty collection → `<>`.
        assert_eq!(print_typed(&e), "(ConstantNode:Coll[Byte] <>)");
    }

    // ----- oracle parity -----

    /// golden seed line 48:
    /// `tc Global.none[Int]()   OK (MethodCall:Option[Int] (Global:SigmaDslBuilder) %SigmaDslBuilder.none [] {#T->#Int})`
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
        assert_eq!(
            print_typed(&e),
            "(MethodCall:Option[Int] (Global:SigmaDslBuilder) %SigmaDslBuilder.none [] {#T->#Int})"
        );
    }
}
