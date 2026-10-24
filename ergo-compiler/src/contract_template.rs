//! Contract-template assembly — the Rust mirror of
//! `SigmaTemplateCompiler.compile`/`assemble`
//! (`sc/.../sigma/compiler/SigmaTemplateCompiler.scala:22-53`, sigma-state
//! 6.0.2). Drives [`crate::contract_parse::parse_contract`] → typer (with the
//! named-param TYPE env) → the SHARED graph-building pipeline
//! (`crate::tree::graph_build`) with one `ConstantPlaceholder(index, tpe)`
//! seeded per param → a [`ContractTemplate`] metadata record.
//!
//! ## Placeholder-index assignment — declaration order (a deliberate deviation)
//! `constTypes`/`constValues`/`parameters` (and each `Parameter.constantIndex`)
//! walk `parsed.signature.params` in declaration order, as Scala's `assemble`
//! does, and [`ContractTemplate::apply`] fills constant `i` from the parameter
//! whose `constantIndex` is `i`. [`compile_contract`] numbers the body's
//! `ConstantPlaceholder`s in that same declaration order, so every parameter's
//! value lands where the body reads it.
//!
//! Scala does not, for **≥5** params. It builds
//! `parEnv = params.map(p => p.name -> p.tpe).toMap`
//! (SigmaTemplateCompiler.scala:28) and, in `compileTyped`, numbers placeholders
//! by that `Map`'s ITERATION order (`env.collect{…}.zipWithIndex`,
//! SigmaCompiler.scala:88-92). For ≤4 entries the `Map1..Map4` keep insertion
//! order, so the indices agree; from 5 entries `.toMap` is a hash map iterated in
//! `improve(String.hashCode)` bucket order, so the body reads other parameters'
//! constants: a valid tree with swapped values when the swapped params share a
//! type, a tree the deserializer rejects when they do not. Reported upstream as
//! ergoplatform/sigmastate-interpreter#1205 (reproduced on sigma-state 6.0.5,
//! Scala 2.12 and 2.13; unchanged through 6.0.7). The hash order is also
//! Scala-version dependent (`crate::param_order` documents 2.12 and 2.13).
//!
//! Scala's exact bytes remain available as
//! [`PlaceholderOrder::Scala212`] through [`compile_contract_with_order`]: the
//! Scala 2.12 `HashTrieMap` walk (`crate::param_order::iteration_order_2_12`,
//! the version the `ct` oracle and ergo-appkit pin), for comparing with
//! Scala-produced templates and the JVM-oracle parity gate. For ≤4 params both
//! orders are identical.

use std::collections::{BTreeMap, HashMap};

use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::NetworkPrefix;
use ergo_ser::ergo_tree::ErgoTree;
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
/// hash map ABOVE this many entries. At or below it, Scala's placeholder
/// index assignment is declaration order; above it, under
/// [`PlaceholderOrder::Scala212`], Scala 2.12 `HashTrieMap` iteration order
/// (`crate::param_order::iteration_order_2_12`).
pub const MAX_DECLARATION_ORDER_PARAMS: usize = 4;

/// How [`compile_contract_with_order`] numbers the body's `ConstantPlaceholder`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlaceholderOrder {
    /// Declaration order, matching each parameter's `constantIndex`: the
    /// template applies correctly at any parameter count. [`compile_contract`]
    /// uses this.
    #[default]
    Declaration,
    /// Scala sigma-state's order, byte-exact with `SigmaTemplateCompiler`
    /// (Scala 2.12): declaration order up to 4 params, `HashTrieMap` iteration
    /// order from 5. With 5+ params the applied tree binds values to the wrong
    /// constants (ergoplatform/sigmastate-interpreter#1205). For comparing with
    /// Scala-produced templates only; never deploy a 5+ parameter template
    /// compiled this way.
    Scala212,
}

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
///
/// Manual construction is trusted: parameter indices must address `const_types`,
/// defaults must have the same count/types as that table, and expression
/// placeholders/child types must agree with it. All types/values/expressions must
/// satisfy the wire writers' bounds. Serialization does not validate these
/// relationships; invalid manual fields can panic or emit inconsistent bytes.
/// Prefer [`compile_contract`] for validated source input.
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

/// Why [`ContractTemplate::apply`] refused to produce a tree. Each variant
/// mirrors a `require(...)` in Scala's `applyTemplate`
/// (`sdk/.../ContractTemplate.scala:147-181`), which throws
/// `IllegalArgumentException` for the same conditions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// A parameter with no default was not given a value
    /// (`value for parameter `x` was not provided while it does not have a
    /// default value`).
    #[error("value for parameter `{name}` was not provided and it has no default")]
    MissingParameter { name: String },
    /// The value's type differs from the declared constant type
    /// (`parameter type mismatch, expected T, got U`).
    #[error("parameter `{name}`: type mismatch, expected {expected:?}, got {got:?}")]
    TypeMismatch {
        name: String,
        expected: Box<SigmaType>,
        got: Box<SigmaType>,
    },
    /// A value was supplied for a name that is not a template parameter.
    /// Scala silently ignores extras; refusing them is stricter, never
    /// looser, and catches the misspelling a caller would otherwise miss.
    /// Raised only once every constant slot resolved, so it never masks a
    /// rejection Scala would also have made.
    #[error("`{name}` is not a parameter of this template")]
    UnknownParameter { name: String },
    /// The supplied `(SigmaType, SigmaValue)` pair is internally inconsistent —
    /// the value variant is not the one the type names (e.g. `SInt` with
    /// `SigmaValue::Long`). Scala's `Constant[SType]` pairs type and value by
    /// construction, so this state is unrepresentable there; the Rust tuple can
    /// express it, and the tree it would produce does not represent the declared
    /// type. Refused here rather than at serialization time.
    #[error("value supplied for parameter `{name}` is not a {tpe:?}")]
    InconsistentValue { name: String, tpe: Box<SigmaType> },
}

/// Compile an ErgoScript contract-template source into a [`ContractTemplate`].
/// Mirrors `SigmaTemplateCompiler(networkPrefix).compile(source)`, byte-exact up to
/// 4 params; from 5 params the body's placeholders follow declaration order,
/// where Scala's hash order binds values to the wrong constants (see the module
/// docs; [`PlaceholderOrder::Scala212`] reproduces Scala's bytes).
pub fn compile_contract(
    source: &str,
    tree_version: u8,
    network: NetworkPrefix,
) -> Result<ContractTemplate, ContractError> {
    compile_contract_with_order(source, tree_version, network, PlaceholderOrder::Declaration)
}

/// [`compile_contract`] with an explicit placeholder numbering. Every other byte
/// of the template is the same under either order.
pub fn compile_contract_with_order(
    source: &str,
    tree_version: u8,
    network: NetworkPrefix,
    order: PlaceholderOrder,
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

    // placeholdersEnv: name -> ConstantPlaceholder(index). Declaration order by
    // default, matching `parameters[i].constant_index` below. Scala212 reproduces
    // Scala's position in the immutable `Map`'s ITERATION order
    // (SigmaCompiler.scala:88-92): insertion order for ≤4 params (`Map1..Map4`),
    // Scala 2.12 `HashTrieMap` order from 5 — which then disagrees with the
    // declaration-ordered `constTypes`/`parameters` (sigmastate-interpreter#1205).
    let declaration = order == PlaceholderOrder::Declaration;
    let placeholders: HashMap<String, u32> =
        if declaration || params.len() <= MAX_DECLARATION_ORDER_PARAMS {
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
    // `buildGraph` builds the `env ++ placeholdersEnv` env at the root before
    // the body, so every param's placeholder is a root node: a param read in two
    // sibling thunks (`HEIGHT > 0 && a > 1 && a < 9`) is one shared `ValDef`,
    // not two inline copies (see `crate::cse`'s module docs).
    let env_nodes: Vec<WireExpr> = (0..params.len() as u32)
        .map(|index| {
            WireExpr::Op(IrNode {
                opcode: 0x73, // ConstantPlaceholder (SigmaCompiler.scala:88-92)
                payload: Payload::ConstPlaceholder { index },
            })
        })
        .collect();
    // A template's `expressionTree` is headerless (`treeVersion = None`), so
    // the shared pipeline runs with header version 0: the pre-v3 data gate
    // stays on, exactly as before the compile route took versioned headers.
    let root = graph_build(root, &env_nodes, 0)?;

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
    /// Instantiate the template into an [`ErgoTree`] — Scala's
    /// `ContractTemplate.applyTemplate(Some(version), paramValues)`
    /// (`sdk/.../ContractTemplate.scala:147-181`).
    ///
    /// The constants table is rebuilt slot by slot: a slot whose parameter
    /// was given a value takes it (type-checked against `constTypes[i]`),
    /// otherwise the declared default; a slot with neither is an error. The
    /// body is the template's `expressionTree` unchanged — its
    /// `ConstantPlaceholder(i)` nodes now resolve against the new table. The
    /// header is `setConstantSegregation(headerWithVersion(version))`, so
    /// `has_size` follows Scala's rule of the size bit for version > 0.
    ///
    /// Each supplied `(SigmaType, SigmaValue)` must be self-consistent — the
    /// value variant is the one the type names — which Scala gets for free from
    /// `Constant[SType]`; an inconsistent pair is an
    /// [`ApplyError::InconsistentValue`], not a tree.
    ///
    /// Byte parity is graded by `tests/contract_template_parity.rs` against
    /// the JVM oracle's `ap` verb (`test-vectors/ergoscript/contract/apply_seed.json`).
    pub fn apply(
        &self,
        tree_version: u8,
        values: &BTreeMap<String, (SigmaType, SigmaValue)>,
    ) -> Result<ErgoTree, ApplyError> {
        let mut constants: Vec<(SigmaType, SigmaValue)> =
            Vec::with_capacity(self.const_types.len());
        for (i, tpe) in self.const_types.iter().enumerate() {
            let param = self
                .parameters
                .iter()
                .find(|p| p.constant_index as usize == i);
            let given = param.and_then(|p| values.get(&p.name));
            let value = match given {
                Some((got, v)) => {
                    if got != tpe {
                        return Err(ApplyError::TypeMismatch {
                            name: param.map(|p| p.name.clone()).unwrap_or_default(),
                            expected: Box::new(tpe.clone()),
                            got: Box::new(got.clone()),
                        });
                    }
                    // `(tpe, value)` is a plain tuple here, so the value variant
                    // can disagree with the type it is paired with. `write_value`
                    // is the authority on which pairs are representable — ask it,
                    // rather than duplicating its match arms. Trial-serializing a
                    // single constant is cheap and cannot drift from the writer.
                    let mut probe = VlqWriter::new();
                    if write_value(&mut probe, tpe, v).is_err() {
                        return Err(ApplyError::InconsistentValue {
                            name: param.map(|p| p.name.clone()).unwrap_or_default(),
                            tpe: Box::new(tpe.clone()),
                        });
                    }
                    v.clone()
                }
                None => match self
                    .const_values
                    .as_ref()
                    .and_then(|cv| cv.get(i))
                    .and_then(|d| d.as_ref())
                {
                    Some((_, default)) => default.clone(),
                    None => {
                        return Err(ApplyError::MissingParameter {
                            name: param
                                .map(|p| p.name.clone())
                                .unwrap_or_else(|| format!("#{i}")),
                        })
                    }
                },
            };
            constants.push((tpe.clone(), value));
        }

        // Unknown names are refused only AFTER every slot resolved. Scala's
        // applyTemplate ignores extras, so this rejection has no counterpart in
        // the oracle; running it last keeps the deviation strictly additive —
        // wherever Scala rejects, we reject for the SAME reason and in the same
        // slot order, and the extra strictness only bites on inputs Scala would
        // have accepted. (Checking it first reported an unknown name for a
        // template that was in fact missing a required parameter.)
        for name in values.keys() {
            if !self.parameters.iter().any(|p| &p.name == name) {
                return Err(ApplyError::UnknownParameter { name: name.clone() });
            }
        }

        Ok(ErgoTree {
            version: tree_version,
            has_size: tree_version > 0,
            constant_segregation: true,
            reserved_header_bits: 0,
            constants,
            body: self.expression_tree.clone(),
        })
    }

    /// Serialize the raw `expressionTree` value bytes
    /// (`ValueSerializer.serialize(expressionTree, w)`), the natural byte-exact
    /// oracle target (ContractTemplate JSON `expressionTree` field / binary
    /// serializer's inner block).
    ///
    /// # Panics
    ///
    /// Panics if a manually constructed expression violates the wire writer's
    /// invariants or bounds. See [`ContractTemplate`] for construction requirements.
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
    ///
    /// # Panics
    ///
    /// Panics if manually constructed types, default values or the expression
    /// cannot serialize. This method trusts the table/parameter relationships
    /// documented on [`ContractTemplate`]; it is not a validating constructor.
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

    /// One `Int` parameter, no default — the smallest template that exercises
    /// every `apply` rejection.
    fn one_int_param_template() -> ContractTemplate {
        cc("/* */\n@contract def c(threshold: Int) = sigmaProp(HEIGHT > threshold)")
    }

    fn values(
        pairs: &[(&str, SigmaType, SigmaValue)],
    ) -> BTreeMap<String, (SigmaType, SigmaValue)> {
        pairs
            .iter()
            .map(|(n, t, v)| (n.to_string(), (t.clone(), v.clone())))
            .collect()
    }

    // ----- happy path -----

    #[test]
    fn apply_sets_size_bit_for_version_above_zero() {
        let ct = one_int_param_template();
        let vals = values(&[("threshold", SigmaType::SInt, SigmaValue::Int(7))]);
        let v0 = ct.apply(0, &vals).expect("v0 applies");
        assert!(!v0.has_size, "ErgoTree v0 carries no size bit");
        let v1 = ct.apply(1, &vals).expect("v1 applies");
        assert!(v1.has_size, "ErgoTree v1+ always carries the size bit");
        assert!(v1.constant_segregation, "applyTemplate always segregates");
    }

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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Five same-typed keys whose Scala 2.12 hash order is not declaration order.
    const FIVE_KEYS: &str = "/* */\n@contract def t(bob: SigmaProp, dave: SigmaProp, alice: SigmaProp, \
         carol: SigmaProp, erin: SigmaProp) = (atLeast(2, Coll(bob, dave, alice)) && carol) || erin";

    #[test]
    fn five_params_number_placeholders_in_declaration_order() {
        // SigmaOr(SigmaAnd(AtLeast(2, Coll(ph0, ph1, ph2)), ph3), ph4): each name
        // reads its own constant (parameters[i].constant_index == i).
        let ct = cc(FIVE_KEYS);
        let names: Vec<&str> = ct.parameters.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["bob", "dave", "alice", "carol", "erin"]);
        for (i, p) in ct.parameters.iter().enumerate() {
            assert_eq!(p.constant_index, i as u32);
        }
        assert_eq!(
            hex(&ct.expression_tree_bytes()),
            "eb02ea0298040483030873007301730273037304"
        );
    }

    #[test]
    fn scala212_order_reproduces_sigma_state_bytes() {
        // Scala sigma-state 6.0.5 (2.12.21 and 2.13.18), SigmaTemplateCompiler on the
        // same source: expressionTree reads Coll(ph4, ph0, ph3), ph1, ph2 while the
        // parameters keep constantIndex bob..erin = 0..4, so applyTemplate yields
        // (atLeast(2, Coll(erin, bob, carol)) && dave) || alice
        // (ergoplatform/sigmastate-interpreter#1205). Tail of the JVM's applied tree.
        let ct = compile_contract_with_order(
            FIVE_KEYS,
            3,
            NetworkPrefix::Testnet,
            PlaceholderOrder::Scala212,
        )
        .expect("compiles");
        for (i, p) in ct.parameters.iter().enumerate() {
            assert_eq!(p.constant_index, i as u32);
        }
        assert_eq!(
            hex(&ct.expression_tree_bytes()),
            "eb02ea0298040483030873047300730373017302"
        );
    }

    #[test]
    fn orders_agree_up_to_four_params() {
        let src = "/* */\n@contract def t(bob: SigmaProp, dave: SigmaProp, alice: SigmaProp, \
                   carol: SigmaProp) = atLeast(2, Coll(bob, dave, alice)) && carol";
        let scala =
            compile_contract_with_order(src, 3, NetworkPrefix::Testnet, PlaceholderOrder::Scala212)
                .expect("compiles");
        assert_eq!(cc(src).serialize(), scala.serialize());
    }

    #[test]
    fn five_mixed_type_params_apply_to_a_tree_the_deserializer_accepts() {
        // Declared bob, dave, alice: Int; carol: Long; erin: Coll[Byte]. In Scala's
        // order `bob` reads constant 4 (erin's Coll[Byte]), so `HEIGHT > bob`
        // compares an Int with a Coll[Byte] and the deserializer refuses the tree
        // (the same names read other constants too); in declaration order the tree
        // parses back to itself.
        let src = "/* */\n@contract def t(bob: Int, dave: Int, alice: Int, carol: Long, \
                   erin: Coll[Byte]) = sigmaProp(HEIGHT > bob && HEIGHT > dave && \
                   HEIGHT > alice && HEIGHT.toLong > carol && erin.size > 0)";
        let bytes = SigmaType::SColl(Box::new(SigmaType::SByte));
        let vals = values(&[
            ("bob", SigmaType::SInt, SigmaValue::Int(1)),
            ("dave", SigmaType::SInt, SigmaValue::Int(2)),
            ("alice", SigmaType::SInt, SigmaValue::Int(3)),
            ("carol", SigmaType::SLong, SigmaValue::Long(4)),
            (
                "erin",
                bytes,
                SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Bytes(vec![5])),
            ),
        ]);
        let roundtrip = |order| -> Result<ErgoTree, String> {
            let ct = compile_contract_with_order(src, 3, NetworkPrefix::Testnet, order)
                .expect("compiles");
            let tree = ct.apply(0, &vals).map_err(|e| e.to_string())?;
            let mut w = VlqWriter::new();
            ergo_ser::ergo_tree::write_ergo_tree(&mut w, &tree).map_err(|e| format!("{e:?}"))?;
            let written = w.result();
            let mut r = ergo_primitives::reader::VlqReader::new(&written);
            let back = ergo_ser::ergo_tree::read_ergo_tree(&mut r).map_err(|e| format!("{e:?}"))?;
            // A mistyped operand the reader can widen (Int where Long belongs) parses
            // as a different tree rather than failing; count that as a failure too.
            if back != tree {
                return Err("parses back to a different tree".into());
            }
            Ok(tree)
        };
        assert_eq!(roundtrip(PlaceholderOrder::Declaration).map(|_| ()), Ok(()));
        let scala = roundtrip(PlaceholderOrder::Scala212);
        assert!(
            scala.is_err(),
            "Scala's order should mis-bind these params: {scala:?}"
        );
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

    #[test]
    fn apply_missing_required_parameter_rejects() {
        let err = one_int_param_template()
            .apply(0, &BTreeMap::new())
            .unwrap_err();
        assert!(matches!(err, ApplyError::MissingParameter { name } if name == "threshold"));
    }

    #[test]
    fn apply_declared_type_mismatch_rejects() {
        let err = one_int_param_template()
            .apply(
                0,
                &values(&[("threshold", SigmaType::SLong, SigmaValue::Long(7))]),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::TypeMismatch { name, .. } if name == "threshold"));
    }

    #[test]
    fn apply_unknown_parameter_name_rejects() {
        // Deliberate deviation: Scala's applyTemplate ignores extras.
        let err = one_int_param_template()
            .apply(
                0,
                &values(&[
                    ("threshold", SigmaType::SInt, SigmaValue::Int(7)),
                    ("nosuch", SigmaType::SInt, SigmaValue::Int(1)),
                ]),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::UnknownParameter { name } if name == "nosuch"));
    }

    #[test]
    fn apply_type_value_pair_disagreeing_rejects() {
        // The declared type matches constTypes[0], but the paired value is a
        // Long — a pair Scala's Constant[SType] cannot express. The tree must
        // not be built from it.
        let err = one_int_param_template()
            .apply(
                0,
                &values(&[("threshold", SigmaType::SInt, SigmaValue::Long(7))]),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::InconsistentValue { name, .. } if name == "threshold"));
    }
}
