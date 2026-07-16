//! Contract-template assembly — the Rust mirror of
//! `SigmaTemplateCompiler.compile`/`assemble`
//! (`sc/.../sigma/compiler/SigmaTemplateCompiler.scala:22-53`, sigma-state
//! 6.0.2). Drives [`crate::contract_parse::parse_contract`] → typer (with the
//! named-param TYPE env) → the SHARED graph-building pipeline
//! ([`crate::tree::graph_build`]) with one `ConstantPlaceholder(index, tpe)`
//! seeded per param → a [`ContractTemplate`] metadata record.
//!
//! ## Placeholder-index assignment — map iteration order
//! Scala builds `parEnv = params.map(p => p.name -> p.tpe).toMap`
//! (SigmaTemplateCompiler.scala:28) then, in `compileTyped`,
//! `placeholdersEnv = env.collect{…}.zipWithIndex.map{ (name,t),i =>
//! name -> ConstantPlaceholder(i, t) }.toMap` (SigmaCompiler.scala:88-92). The
//! placeholder index each param receives is thus its position in the immutable
//! `Map`'s ITERATION order, which is serialized into the `expressionTree` bytes.
//!
//! For **≤4** entries Scala's immutable `Map` is a `Map1..Map4` that preserves
//! INSERTION order, so `index = declaration position` — byte-exact against
//! declaration order. For **≥5** params the `.toMap` upgrades to a
//! JVM `HashMap` whose iteration order is `improve(String.hashCode)` bucket
//! order, NOT declaration order — reproduced here via
//! [`crate::param_order::iteration_order_2_12`] (Scala 2.12 `HashTrieMap` walk,
//! the version the `ct` oracle and ergo-appkit pin).
//!
//! CRUCIAL: `constTypes`/`constValues`/`parameters` (and each
//! `Parameter.constantIndex`) walk `parsed.signature.params` DIRECTLY, so they
//! stay declaration-ordered regardless (mirror `assemble`). ONLY the body's
//! `ConstantPlaceholder` substitution follows the map order.

use std::collections::HashMap;

use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::opcode::{write_expr, Expr as WireExpr, IrNode, Payload};
use ergo_ser::sigma_type::{write_type, SigmaType};
use ergo_ser::sigma_value::{write_value, SigmaValue};

use crate::ast::Expr;
use crate::contract_parse::{parse_contract, ContractParam};
use crate::emit::{emit_with_placeholders, map_const, map_type};
use crate::stype::SType;
use crate::tree::graph_build;
use crate::typecheck::{typecheck_contract_body, CompileError};
use crate::typed::{node_tpe, ConstPayload};

/// Scala's `Map1..Map4` preserve insertion order; `.toMap` upgrades to a
/// hash map ABOVE this many entries. At or below it, placeholder
/// index assignment is declaration order; above it, Scala 2.12 `HashTrieMap`
/// iteration order ([`crate::param_order::iteration_order_2_12`]).
pub const MAX_DECLARATION_ORDER_PARAMS: usize = 4;

/// A contract-template parameter record (`org.ergoplatform.sdk.Parameter`,
/// ContractTemplate.scala:22-32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    pub name: String,
    pub description: String,
    pub constant_index: u32,
}

/// The assembled contract template (`org.ergoplatform.sdk.ContractTemplate`,
/// ContractTemplate.scala:96-104). `expression_tree` holds the serialized value
/// bytes (`ValueSerializer.serialize` of the graph-built body, with inline
/// `ConstantPlaceholder(index)` nodes for params). `tree_version` is always
/// `None` here (`ContractTemplate.apply`, ContractTemplate.scala:204-211).
#[derive(Debug, Clone, PartialEq)]
pub struct ContractTemplate {
    pub name: String,
    pub description: String,
    pub const_types: Vec<SigmaType>,
    /// `None` when every param lacks a default (`allConstValuesAreNone`,
    /// SigmaTemplateCompiler.scala:36-39); otherwise one entry per constant,
    /// `None` where the param had no default.
    pub const_values: Option<Vec<Option<(SigmaType, SigmaValue)>>>,
    pub parameters: Vec<Parameter>,
    pub expression_tree: WireExpr,
}

/// Contract-template compile failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    /// Parse/typecheck/emit failure in the underlying pipeline.
    #[error(transparent)]
    Compile(#[from] CompileError),
    /// Two `@contract` parameters share the same name. Scala's
    /// `ContractTemplate.validate()` `require(!paramNames.contains(p.name), ...)`
    /// (ContractTemplate.scala:116-117) throws `IllegalArgumentException` — a
    /// runtime reject, NOT a last-wins collapse (verified: oracle REJECTs
    /// `@contract def f(a: Int, a: Long)` with `IllegalArgumentException`).
    #[error("parameter names must be unique; found duplicate parameter with name {name}")]
    DuplicateParamName { name: String },
}

/// Compile an ErgoScript contract-template source into a [`ContractTemplate`].
/// Mirrors `SigmaTemplateCompiler(networkPrefix).compile(source)`.
pub fn compile_contract(
    source: &str,
    tree_version: u8,
    network: NetworkPrefix,
) -> Result<ContractTemplate, ContractError> {
    let parsed = parse_contract(source, tree_version).map_err(CompileError::Parse)?;
    let params = &parsed.signature.params;

    // parEnv = params.map(p => p.name -> p.tpe) (SigmaTemplateCompiler.scala:28).
    let type_params: Vec<(String, SType)> = params
        .iter()
        .map(|p| (p.name.clone(), p.tpe.clone()))
        .collect();

    // typecheck(env, body) with the param TYPE env (SigmaCompiler.scala:74-78).
    let typed = typecheck_contract_body(&parsed.body, &type_params, tree_version, network)?;

    // placeholdersEnv: name -> ConstantPlaceholder(index) at the param's position
    // in the immutable `Map`'s ITERATION order (SigmaCompiler.scala:88-92). For
    // ≤4 params `Map1..Map4` preserve insertion order (index = declaration
    // position); for ≥5 the `.toMap` hash map iterates in Scala 2.12
    // `HashTrieMap` order. Only this substitution follows the map order —
    // `constTypes`/`parameters` below stay declaration-ordered.
    let placeholders: HashMap<String, u32> = if params.len() <= MAX_DECLARATION_ORDER_PARAMS {
        params
            .iter()
            .enumerate()
            .map(|(i, p)| (p.name.clone(), i as u32))
            .collect()
    } else {
        let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
        crate::param_order::iteration_order_2_12(&names)
            .into_iter()
            .enumerate()
            .map(|(placeholder_idx, decl_idx)| {
                (params[decl_idx].name.clone(), placeholder_idx as u32)
            })
            .collect()
    };

    // Root dispatch + placeholder-aware emit, then the SHARED graph-building
    // pipeline (identical to `compile`). `expr.toSigmaProp`
    // (SigmaTemplateCompiler.scala:50) is the same Boolean→BoolToSigmaProp wrap
    // the compile route's root dispatch performs.
    let root = match node_tpe(&typed) {
        SType::SSigmaProp => {
            emit_with_placeholders(&typed, placeholders).map_err(CompileError::Emit)?
        }
        SType::SBoolean => WireExpr::Op(IrNode {
            opcode: 0xD1, // BoolToSigmaProp (values.scala:58)
            payload: Payload::One(Box::new(
                emit_with_placeholders(&typed, placeholders).map_err(CompileError::Emit)?,
            )),
        }),
        other => {
            return Err(ContractError::Compile(CompileError::Root {
                tpe: crate::typed_print::to_term_string(other),
            }))
        }
    };
    let root = graph_build(root)?;

    // assemble (SigmaTemplateCompiler.scala:34-52). constTypes/constValues/
    // parameters all walk `parsed.signature.params` DIRECTLY, so they are
    // declaration-order-stable regardless of the placeholder-map order.
    let const_types: Vec<SigmaType> = params
        .iter()
        .map(|p| map_type(&p.tpe))
        .collect::<Result<_, _>>()
        .map_err(CompileError::Emit)?;

    let all_none = params.iter().all(|p| p.default.is_none());
    let const_values = if all_none {
        None
    } else {
        Some(
            params
                .iter()
                .map(param_default_wire)
                .collect::<Result<Vec<_>, _>>()?,
        )
    };

    // Reject duplicate parameter names (ContractTemplate.validate(),
    // ContractTemplate.scala:116-117): a runtime `require` throwing
    // IllegalArgumentException. Mirror it AFTER typecheck, as Scala does in the
    // ContractTemplate constructor. NOT last-wins — the template is rejected.
    let mut seen_names = std::collections::HashSet::with_capacity(params.len());
    for p in params {
        if !seen_names.insert(p.name.as_str()) {
            return Err(ContractError::DuplicateParamName {
                name: p.name.clone(),
            });
        }
    }

    let parameters = params
        .iter()
        .enumerate()
        .map(|(idx, p)| Parameter {
            name: p.name.clone(),
            description: parsed
                .docs
                .params
                .iter()
                .find(|d| d.name == p.name)
                .map(|d| d.description.clone())
                .unwrap_or_default(),
            constant_index: idx as u32,
        })
        .collect();

    Ok(ContractTemplate {
        name: parsed.signature.name.clone(),
        description: parsed.docs.description.clone(),
        const_types,
        const_values,
        parameters,
        expression_tree: root,
    })
}

/// Convert a param's optional literal default to its wire `(type, value)` pair,
/// serialized later as `constValues[i]` under the DECLARED constant type
/// (`DataSerializer.serialize(const, constTypes(i), w)`,
/// ContractTemplate.scala serializer). The literal's type must match the
/// declared type (`map_const` cross-checks), mirroring Scala pairing the
/// `defaultValue` with `constTypes(i)`.
fn param_default_wire(p: &ContractParam) -> Result<Option<(SigmaType, SigmaValue)>, ContractError> {
    match &p.default {
        None => Ok(None),
        Some(lit) => {
            let payload = literal_payload(lit).ok_or({
                ContractError::Compile(CompileError::Emit(crate::emit::EmitError::InvalidShape(
                    "non-literal contract default",
                )))
            })?;
            let pair = map_const(&payload, &p.tpe).map_err(CompileError::Emit)?;
            Ok(Some(pair))
        }
    }
}

/// Literal `Expr` → `ConstPayload` (the restricted `ExprLiteral` set,
/// Core.scala:55). Non-literal defaults were already rejected at parse time.
fn literal_payload(e: &Expr) -> Option<ConstPayload> {
    Some(match e {
        Expr::IntConst { value, .. } => ConstPayload::Int(*value),
        Expr::LongConst { value, .. } => ConstPayload::Long(*value),
        Expr::BoolConst { value, .. } => ConstPayload::Bool(*value),
        Expr::StringConst { value, .. } => ConstPayload::String(value.clone()),
        Expr::UnitConst { .. } => ConstPayload::Unit,
        _ => return None,
    })
}

impl ContractTemplate {
    /// Serialize the raw `expressionTree` value bytes
    /// (`ValueSerializer.serialize(expressionTree, w)`), the natural byte-exact
    /// oracle target (ContractTemplate JSON `expressionTree` field / binary
    /// serializer's inner block).
    pub fn expression_tree_bytes(&self) -> Vec<u8> {
        let mut w = VlqWriter::new();
        // The graph-built root already holds inline constants + placeholders; the
        // `cseg=false` flag is inert here (write_expr never re-segregates).
        write_expr(&mut w, &self.expression_tree, false)
            .expect("graph-built contract body serializes (same writer as compile)");
        w.result()
    }

    /// Full `ContractTemplate.serializer` bytes (ContractTemplate.scala:227-260),
    /// the canonical wire form used for byte-exact oracle parity.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = VlqWriter::new();
        // putOption(treeVersion)(putUByte) — always None here → 0x00.
        w.put_u8(0);
        put_string(&mut w, &self.name);
        put_string(&mut w, &self.description);

        // nConstants + each TypeSerializer.serialize(constType).
        w.put_u32(self.const_types.len() as u32);
        for t in &self.const_types {
            write_type(&mut w, t).expect("constType serializes");
        }

        // putOption(constValues)((_, values) => per-index putOption + DataSerializer).
        match &self.const_values {
            None => w.put_u8(0),
            Some(values) => {
                w.put_u8(1);
                for v in values {
                    match v {
                        None => w.put_u8(0),
                        Some((tpe, val)) => {
                            w.put_u8(1);
                            write_value(&mut w, tpe, val).expect("constValue serializes");
                        }
                    }
                }
            }
        }

        // nParameters + each Parameter.serializer.
        w.put_u32(self.parameters.len() as u32);
        for p in &self.parameters {
            put_string(&mut w, &p.name);
            put_string(&mut w, &p.description);
            w.put_u32(p.constant_index);
        }

        // expressionTree: length-prefixed value bytes.
        let expr_bytes = self.expression_tree_bytes();
        w.put_u32(expr_bytes.len() as u32);
        w.put_bytes(&expr_bytes);
        w.result()
    }
}

/// `serializeString` (SerializationUtils.scala:14-18): `putUInt(len)` then the
/// UTF-8 bytes.
fn put_string(w: &mut VlqWriter, s: &str) {
    w.put_length_prefixed_bytes(s.as_bytes());
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn cc(src: &str) -> ContractTemplate {
        compile_contract(src, 3, NetworkPrefix::Testnet).expect("contract compiles")
    }

    // ----- happy path -----

    #[test]
    fn assembles_name_description_and_declaration_order_parameters() {
        let ct = cc(
            "/**\n * Range check.\n * @param lo lower\n * @param hi upper\n */\n\
             @contract def rangeCheck(lo: Int, hi: Int) = sigmaProp(HEIGHT > lo && HEIGHT < hi)",
        );
        assert_eq!(ct.name, "rangeCheck");
        assert_eq!(ct.description, "Range check.");
        assert_eq!(ct.const_types.len(), 2);
        // Parameters carry declaration-order constant indices + doc descriptions.
        assert_eq!(ct.parameters[0].name, "lo");
        assert_eq!(ct.parameters[0].constant_index, 0);
        assert_eq!(ct.parameters[0].description, "lower");
        assert_eq!(ct.parameters[1].constant_index, 1);
        // No defaults → constValues is None (allConstValuesAreNone).
        assert!(ct.const_values.is_none());
    }

    #[test]
    fn defaults_populate_const_values() {
        let ct = cc("/* */\n@contract def c(x: Int = 1000) = sigmaProp(HEIGHT > x)");
        let cv = ct.const_values.expect("some default present");
        assert_eq!(cv.len(), 1);
        assert!(cv[0].is_some());
    }

    #[test]
    fn expression_tree_serializes_deterministically() {
        // The graph-built body serializes; a second call is byte-identical.
        let ct = cc("/* */\n@contract def c(x: Int) = sigmaProp(HEIGHT > x)");
        assert_eq!(ct.expression_tree_bytes(), ct.expression_tree_bytes());
        assert!(!ct.serialize().is_empty());
    }

    // ----- error paths -----

    #[test]
    fn five_params_compiles_with_hashmap_placeholder_order() {
        // ≥5 params: placeholder indices follow the Scala 2.12 HashTrieMap
        // iteration order, no longer rejected. `parameters` stay declaration-
        // ordered; byte-exactness vs the oracle is the parity gate's job.
        let ct = cc(
            "/* */\n@contract def g5(a: Int, b: Int, c: Int, d: Int, e: Int) \
             = sigmaProp(a + b + c + d + e > 0)",
        );
        assert_eq!(ct.const_types.len(), 5);
        assert_eq!(ct.parameters.len(), 5);
        // Declaration order preserved in the parameters list + constant indices.
        let names: Vec<&str> = ct.parameters.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c", "d", "e"]);
        for (i, p) in ct.parameters.iter().enumerate() {
            assert_eq!(p.constant_index, i as u32);
        }
    }

    #[test]
    fn four_params_is_still_accepted() {
        // The ≤4 boundary is byte-exact-supported (declaration order).
        let ct = cc("/* */\n@contract def g4(a: Int, b: Int, c: Int, d: Int) \
             = sigmaProp(a + b + c + d > 0)");
        assert_eq!(ct.const_types.len(), 4);
        assert_eq!(ct.parameters.len(), 4);
    }

    #[test]
    fn body_type_error_rejects() {
        let err = compile_contract(
            "/* */\n@contract def c(x: Int) = sigmaProp(x)",
            3,
            NetworkPrefix::Testnet,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Compile(_)));
    }

    #[test]
    fn duplicate_param_names_reject() {
        // Scala's `ContractTemplate.validate()` rejects duplicate parameter names
        // with IllegalArgumentException (ContractTemplate.scala:116-117) — NOT a
        // last-wins collapse (verified: ct oracle REJECTs `def f(a: Int, a: Long)`
        // with IllegalArgumentException).
        let err = compile_contract(
            "/* */\n@contract def c(a: Int, a: Long) = sigmaProp(HEIGHT > a)",
            3,
            NetworkPrefix::Testnet,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::DuplicateParamName { name } if name == "a"));
    }
}
