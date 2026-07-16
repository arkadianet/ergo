//! Binder — port of Scala `SigmaBinder` (sigma-state 6.0.2).
//!
//! Runs between the parser and the typer: substitutes ScriptEnv constants
//! and global names, and performs the shallow structural rewrites (Coll,
//! min/max, PK, serialize, isEmpty). All actual type inference, method
//! resolution, and local-variable scoping is the TYPER's job.
//!
//! Normative source:
//!   sc/shared/src/main/scala/sigma/compiler/phases/SigmaBinder.scala (123 lines)
//!   data/shared/src/main/scala/sigma/ast/SigmaPredef.scala (PK/serialize irBuilders)
//!
//! # Traversal / fixpoint equivalence
//!
//! Scala runs `rewrite(reduce(strategy[Any]({...})))(e)` — kiama's `reduce` is
//! a bottom-up (children-first) traversal repeated to FIXPOINT. This port is a
//! single bottom-up recursion, which is equivalent because no rule's OUTPUT
//! matches any other rule's PATTERN (the rule set is non-cascading):
//!
//! - Rule 1 outputs `Constant`/singleton nodes — no rule matches those.
//! - Rules 2-3 output `ConcreteCollection` — never a rule's redex.
//! - Rules 4-5 output `ArithOp` — never a redex.
//! - Rule 6 rebuilds `Lambda` with a bound body — the Lambda rule re-firing is
//!   the identity (Scala returns `None` when unchanged).
//! - Rule 7 (`Block([], e) → e`) CAN expose a new parent redex (e.g.
//!   `({min})(1,2)` — the unwrapped Ident becomes an Apply callee). This port
//!   handles it because the Apply handler dispatches on the BOUND callee shape
//!   (children are bound before the parent rule check), exactly like kiama's
//!   children-first order.
//! - Rule 8 fills val types — idempotent; a second pass computes the same block.
//! - Rules 9-10 output `Constant`/`MethodCall` — never a redex.
//! - Rule 11 outputs `LogicalNot(Select(_, "isDefined"))` — "isDefined" is not
//!   a rule pattern.
//!
//! Scala's `SrcCtxCallbackRewriter` source-context propagation has no
//! equivalent here: `TypedExpr` carries no positions (positions surface only in
//! `BindError`), so nothing is lost by not porting it.
//!
//! # Error-order faithfulness
//!
//! Because kiama is children-first, an error inside a child (min/max arity,
//! PK decode) fires BEFORE the parent Block's duplicate-name check. This port
//! preserves that order: the Block handler binds every val body and the result
//! FIRST, and only then runs the duplicate-name checks in val order.

use ergo_ser::address::{decode_p2pk_address, NetworkPrefix};

use crate::ast::{product_method_tpe, ArithKind, BitKind, Expr, RelKind, ValDef};
use crate::env::{lift, ScriptEnv};
use crate::span::Pos;
use crate::stype::SType;
use crate::typed::{
    node_tpe, ConstPayload, MethodRef, TypedExpr, ARITH_DIVISION, ARITH_MAX, ARITH_MIN,
    ARITH_MINUS, ARITH_MODULO, BIT_AND, BIT_OR,
};
use crate::typer::get_method;

// ── BindError ────────────────────────────────────────────────────────────────

/// Binder reject surface. Error MESSAGES are not parity-relevant (same policy
/// as `ParseError`); the accept/reject verdict, the error class, and the
/// position are.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindError {
    /// Scala `BinderException` (SigmaBinder.scala:121 `error()`): a Block
    /// `val` name is already defined in the OUTER ScriptEnv
    /// (SigmaBinder.scala:93). Positioned at the `val` (v.sourceContext).
    #[error("{msg} (offset {pos})")]
    BinderException { pos: Pos, msg: String },
    /// Scala `InvalidArguments`: `min`/`max` arity != 2 (SigmaBinder.scala:
    /// 68-70, 73-77), positioned at the callee Ident (i.sourceContext).
    ///
    /// Also covers PK/serialize irBuilder arg-shape mismatches (wrong arity,
    /// non-String-constant PK arg): the Scala strategy applies the irBuilder
    /// PartialFunction UNCONDITIONALLY (SigmaBinder.scala:105-109), so a
    /// non-matching shape is a `scala.MatchError` crash → REJECT. Verdict
    /// parity holds; the class tag differs (deviation D-T8: Scala has no dedicated
    /// class for this crash; we use `InvalidArguments`; see lib.rs § "Known M2
    /// deviations" D-T8), positioned at the Apply.
    #[error("{msg} (offset {pos})")]
    InvalidArguments { pos: Pos, msg: String },
    /// `PK("addr")` address decode failure (SigmaPredef.scala:159-166):
    /// malformed Base58/checksum (`Try.get` → NoSuchElementException in
    /// Scala), wrong network prefix, or a non-P2PK address (`sys.error` →
    /// RuntimeException). All are compile rejects; ours wraps
    /// `AddressDecodeError`, positioned at the Apply.
    #[error("{msg} (offset {pos})")]
    InvalidAddress { pos: Pos, msg: String },
}

impl BindError {
    /// The error's source offset.
    pub fn pos(&self) -> Pos {
        match self {
            BindError::BinderException { pos, .. }
            | BindError::InvalidArguments { pos, .. }
            | BindError::InvalidAddress { pos, .. } => *pos,
        }
    }
}

// ── bind ─────────────────────────────────────────────────────────────────────

/// Bind a parsed expression: substitute ScriptEnv constants and global names,
/// apply the 11 SigmaBinder rewrite rules, and convert the untyped `Expr`
/// vocabulary into the single post-parse `TypedExpr` vocabulary, with
/// `NoType` placeholders wherever typing is pending.
///
/// Mirrors `SigmaBinder.bind(e) = eval(e, env)` (SigmaBinder.scala:116-117).
///
/// `network` discriminates PK address decoding (rule 9); `tree_version` feeds
/// the parse-time product-method type derivation (Select `.tpe`, ast.rs).
pub fn bind(
    env: &ScriptEnv,
    e: &Expr,
    network: NetworkPrefix,
    tree_version: u8,
) -> Result<TypedExpr, BindError> {
    bind_expr(env, e, network, tree_version)
}

/// Bottom-up bind of one node: children first, then this node's rule.
fn bind_expr(
    env: &ScriptEnv,
    e: &Expr,
    network: NetworkPrefix,
    tree_version: u8,
) -> Result<TypedExpr, BindError> {
    match e {
        // ── constants: mechanical conversion, concrete types ────────────────
        Expr::IntConst { value, .. } => Ok(TypedExpr::Constant {
            value: ConstPayload::Int(*value),
            tpe: SType::SInt,
        }),
        Expr::LongConst { value, .. } => Ok(TypedExpr::Constant {
            value: ConstPayload::Long(*value),
            tpe: SType::SLong,
        }),
        Expr::BoolConst { value, .. } => Ok(TypedExpr::Constant {
            value: ConstPayload::Bool(*value),
            tpe: SType::SBoolean,
        }),
        Expr::StringConst { value, .. } => Ok(TypedExpr::Constant {
            value: ConstPayload::String(value.clone()),
            tpe: SType::SString,
        }),
        Expr::UnitConst { .. } => Ok(TypedExpr::Constant {
            value: ConstPayload::Unit,
            tpe: SType::SUnit,
        }),

        // ── Rule 1: Ident(n, NoType) — env substitution + global names ─────
        // SigmaBinder.scala:39-53. Fires ONLY for NoType idents; the ZKProof
        // callee (the one parser-typed Ident, SFunc) passes through untouched
        // even when the env contains its name.
        Expr::Ident { name, tpe, pos } => {
            if *tpe != SType::NoType {
                return Ok(TypedExpr::Ident {
                    name: name.clone(),
                    tpe: tpe.clone(),
                });
            }
            // 1a. ScriptEnv lookup — env takes priority over ALL global names.
            // liftAny always succeeds for EnvValue (every variant is liftable;
            // the Scala unliftable-value branch is unreachable here — SType env
            // entries are stripped by the compiler driver before binding,
            // SigmaCompiler.scala:76). The one exception is D-T5: an off-curve
            // or identity `GroupElement` literal — see `env::lift`'s doc for
            // why this has no oracle-observed Scala counterpart to mirror.
            if let Some(v) = env.get(name) {
                return lift(v).map_err(|e| BindError::InvalidArguments {
                    msg: format!("GroupElement literal {name:?}: {e}"),
                    pos: *pos,
                });
            }
            // 1b. Global name substitution (SigmaBinder.scala:42-51).
            Ok(match name.as_str() {
                "HEIGHT" => TypedExpr::Height { tpe: SType::SInt },
                "MinerPubkey" => TypedExpr::MinerPubkey {
                    tpe: SType::SColl(Box::new(SType::SByte)),
                },
                "INPUTS" => TypedExpr::Inputs {
                    tpe: SType::SColl(Box::new(SType::SBox)),
                },
                "OUTPUTS" => TypedExpr::Outputs {
                    tpe: SType::SColl(Box::new(SType::SBox)),
                },
                "LastBlockUtxoRootHash" => TypedExpr::LastBlockUtxoRootHash {
                    tpe: SType::SAvlTree,
                },
                "EmptyByteArray" => TypedExpr::Constant {
                    value: ConstPayload::ByteColl(vec![]),
                    tpe: SType::SColl(Box::new(SType::SByte)),
                },
                "SELF" => TypedExpr::Self_ { tpe: SType::SBox },
                "CONTEXT" => TypedExpr::Context {
                    tpe: SType::SContext,
                },
                "Global" => TypedExpr::Global {
                    tpe: SType::SGlobal,
                },
                // Unresolved: survives to the typer (predef funcs, block vals,
                // lambda params — SigmaBinder.scala:51 `case _ => None`).
                _ => TypedExpr::Ident {
                    name: name.clone(),
                    tpe: SType::NoType,
                },
            })
        }

        // ── Rule 11: obj.isEmpty → !obj.isDefined (SigmaBinder.scala:111-113)
        // plus the mechanical Select conversion. `obj` is bound first
        // (children-first); the rewrite does NOT re-traverse it.
        Expr::Select { obj, field, .. } => {
            let obj_b = bind_expr(env, obj, network, tree_version)?;
            let obj_tpe = node_tpe(&obj_b).clone();
            if field == "isEmpty" {
                // mkLogicalNot(mkSelect(obj, "isDefined")): the inner Select
                // has resType=None; its tpe is the same product-method lookup
                // the parse-time Select.tpe def performs (values.scala:1171).
                let inner = TypedExpr::Select {
                    obj: Box::new(obj_b),
                    field: "isDefined".to_string(),
                    res_type: None,
                    tpe: product_method_tpe(&obj_tpe, "isDefined", tree_version),
                };
                Ok(TypedExpr::LogicalNot {
                    input: Box::new(inner),
                    tpe: SType::SBoolean, // trees.scala:1378
                })
            } else {
                Ok(TypedExpr::Select {
                    obj: Box::new(obj_b),
                    field: field.clone(),
                    res_type: None, // always None at parse time
                    tpe: declared_select_tpe(&obj_tpe, field, tree_version),
                })
            }
        }

        // ── Rules 2-5, 9-10 dispatch on the BOUND callee shape ─────────────
        Expr::Apply { func, args, pos } => {
            let func_pos = func.pos();
            let func_b = bind_expr(env, func, network, tree_version)?;
            let args_b = args
                .iter()
                .map(|a| bind_expr(env, a, network, tree_version))
                .collect::<Result<Vec<_>, _>>()?;
            bind_apply(func_b, args_b, *pos, func_pos, network, tree_version)
        }

        // ApplyTypes: pass-through (no binder rule matches the node itself;
        // rule 2 matches it only as an Apply callee). tpe = input.tpe
        // (values.scala:1262-1267).
        Expr::ApplyTypes {
            input, type_args, ..
        } => {
            let input_b = bind_expr(env, input, network, tree_version)?;
            let tpe = node_tpe(&input_b).clone();
            Ok(TypedExpr::ApplyTypes {
                input: Box::new(input_b),
                type_args: type_args.clone(),
                tpe,
            })
        }

        // MethodCallLike: structurally unchanged; resolved by the typer.
        // tpe = NoType (values.scala:1282 default).
        Expr::MethodCallLike {
            obj, name, args, ..
        } => {
            let obj_b = bind_expr(env, obj, network, tree_version)?;
            let args_b = args
                .iter()
                .map(|a| bind_expr(env, a, network, tree_version))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TypedExpr::MethodCallLike {
                obj: Box::new(obj_b),
                name: name.clone(),
                args: args_b,
                tpe: SType::NoType,
            })
        }

        // ── Rule 6: Lambda body bound with the SAME outer env ──────────────
        // (SigmaBinder.scala:81-86). Lambda params are NOT added to env —
        // param scoping is the typer's job (SigmaTyper.scala:132). The Scala
        // `require(params.isEmpty)` is structurally guaranteed here: the
        // parser AST has no tpe_params field at all.
        Expr::Lambda {
            args,
            given_res_type,
            body,
            ..
        } => {
            let body_b = bind_expr(env, body, network, tree_version)?;
            // Lambda.tpe = SFunc(args, givenResType ?: body.tpe)
            // (values.scala:1404-1407).
            let range = if *given_res_type == SType::NoType {
                node_tpe(&body_b).clone()
            } else {
                given_res_type.clone()
            };
            Ok(TypedExpr::Lambda {
                tpe_params: vec![],
                args: args.clone(),
                given_res_type: given_res_type.clone(),
                body: Some(Box::new(body_b)),
                tpe: SType::SFunc {
                    dom: args.iter().map(|(_, t)| t.clone()).collect(),
                    range: Box::new(range),
                    tpe_params: vec![],
                },
            })
        }

        // Standalone Val (statement position outside a Block): NO strategy
        // rule matches a bare Val in Scala — children are bound, but the
        // given-type fill and the duplicate-name check happen ONLY inside the
        // Block rule (rule 8). tpe = givenType ?: body.tpe (values.scala:1152).
        Expr::Val(vd) => {
            let body_b = bind_expr(env, &vd.body, network, tree_version)?;
            let tpe = if vd.given_type == SType::NoType {
                node_tpe(&body_b).clone()
            } else {
                vd.given_type.clone()
            };
            Ok(TypedExpr::ValNode {
                name: vd.name.clone(),
                given_type: vd.given_type.clone(),
                body: Box::new(body_b),
                tpe,
            })
        }

        // ── Rules 7-8: Block ────────────────────────────────────────────────
        Expr::Block {
            bindings, result, ..
        } => {
            // Rule 7: { e } → e (SigmaBinder.scala:88). Fires before rule 8.
            if bindings.is_empty() {
                return bind_expr(env, result, network, tree_version);
            }
            bind_block(env, bindings, result, network, tree_version)
        }

        // ── mechanical conversions (no binder rule; tpe defs from ast.rs) ──
        Expr::Tuple { items, .. } => {
            let items_b = items
                .iter()
                .map(|i| bind_expr(env, i, network, tree_version))
                .collect::<Result<Vec<_>, _>>()?;
            let tpe = SType::STuple(items_b.iter().map(|i| node_tpe(i).clone()).collect());
            Ok(TypedExpr::Tuple {
                items: items_b,
                tpe,
            })
        }
        Expr::If {
            condition,
            true_branch,
            false_branch,
            ..
        } => {
            let c = bind_expr(env, condition, network, tree_version)?;
            let t = bind_expr(env, true_branch, network, tree_version)?;
            let f = bind_expr(env, false_branch, network, tree_version)?;
            let tpe = node_tpe(&t).clone(); // If.tpe = trueBranch.tpe
            Ok(TypedExpr::If {
                condition: Box::new(c),
                true_branch: Box::new(t),
                false_branch: Box::new(f),
                tpe,
            })
        }
        Expr::LogicalNot { input, .. } => {
            let input_b = bind_expr(env, input, network, tree_version)?;
            Ok(TypedExpr::LogicalNot {
                input: Box::new(input_b),
                tpe: SType::SBoolean,
            })
        }
        Expr::Negation { input, .. } => {
            let input_b = bind_expr(env, input, network, tree_version)?;
            let tpe = node_tpe(&input_b).clone();
            Ok(TypedExpr::Negation {
                input: Box::new(input_b),
                tpe,
            })
        }
        Expr::BitInversion { input, .. } => {
            let input_b = bind_expr(env, input, network, tree_version)?;
            let tpe = node_tpe(&input_b).clone();
            Ok(TypedExpr::BitInversion {
                input: Box::new(input_b),
                tpe,
            })
        }
        Expr::Relation {
            kind, left, right, ..
        } => {
            let l = Box::new(bind_expr(env, left, network, tree_version)?);
            let r = Box::new(bind_expr(env, right, network, tree_version)?);
            let tpe = SType::SBoolean; // trees.scala:1072-1073
            Ok(match kind {
                RelKind::Eq => TypedExpr::EQ {
                    left: l,
                    right: r,
                    tpe,
                },
                RelKind::Neq => TypedExpr::NEQ {
                    left: l,
                    right: r,
                    tpe,
                },
                RelKind::Ge => TypedExpr::GE {
                    left: l,
                    right: r,
                    tpe,
                },
                RelKind::Gt => TypedExpr::GT {
                    left: l,
                    right: r,
                    tpe,
                },
                RelKind::Le => TypedExpr::LE {
                    left: l,
                    right: r,
                    tpe,
                },
                RelKind::Lt => TypedExpr::LT {
                    left: l,
                    right: r,
                    tpe,
                },
            })
        }
        Expr::ArithOp {
            kind, left, right, ..
        } => {
            let l = bind_expr(env, left, network, tree_version)?;
            let r = bind_expr(env, right, network, tree_version)?;
            let tpe = node_tpe(&l).clone(); // ArithOp.tpe = left.tpe
            let opcode = match kind {
                ArithKind::Minus => ARITH_MINUS,
                ArithKind::Divide => ARITH_DIVISION,
                ArithKind::Modulo => ARITH_MODULO,
            };
            Ok(TypedExpr::ArithOp {
                left: Box::new(l),
                right: Box::new(r),
                opcode,
                tpe,
            })
        }
        Expr::BitOp {
            kind, left, right, ..
        } => {
            let l = bind_expr(env, left, network, tree_version)?;
            let r = bind_expr(env, right, network, tree_version)?;
            let tpe = node_tpe(&l).clone(); // BitOp.tpe = left.tpe
            let opcode = match kind {
                BitKind::Or => BIT_OR,
                BitKind::And => BIT_AND,
            };
            Ok(TypedExpr::BitOp {
                left: Box::new(l),
                right: Box::new(r),
                opcode,
                tpe,
            })
        }
    }
}

/// Rules 2-5, 9-10: Apply dispatch on the BOUND callee shape, falling back to
/// the mechanical Apply conversion.
///
/// Env priority is implicit: an env-substituted callee is a `Constant` by the
/// time this runs, so no special-form rule matches (matching Scala, where
/// rule 1 rewrites the child Ident before the parent Apply rule is tried).
fn bind_apply(
    func: TypedExpr,
    args: Vec<TypedExpr>,
    apply_pos: Pos,
    func_pos: Pos,
    _network: NetworkPrefix,
    _tree_version: u8,
) -> Result<TypedExpr, BindError> {
    // Rule 2: Coll[T](a, b, …) → ConcreteCollection(args, T)
    // (SigmaBinder.scala:56-57). Pattern requires EXACTLY one type arg; a
    // multi-type-arg ApplyTypes falls through to the plain Apply (typer
    // rejects it later).
    if let TypedExpr::ApplyTypes {
        input, type_args, ..
    } = &func
    {
        if matches!(input.as_ref(), TypedExpr::Ident { name, .. } if name == "Coll")
            && type_args.len() == 1
        {
            let elem = type_args[0].clone();
            return Ok(TypedExpr::ConcreteCollection {
                items: args,
                elem_type: elem.clone(),
                tpe: SType::SColl(Box::new(elem)),
            });
        }
    }

    if let TypedExpr::Ident { name, tpe } = &func {
        match name.as_str() {
            // Rule 3: Coll(a, b, …) → ConcreteCollection(args, args(0).tpe)
            // (SigmaBinder.scala:60-62). Scala's pattern is Ident("Coll", _)
            // — ANY tpe wildcard.
            "Coll" => {
                let elem = if args.is_empty() {
                    SType::NoType
                } else {
                    node_tpe(&args[0]).clone()
                };
                return Ok(TypedExpr::ConcreteCollection {
                    items: args,
                    elem_type: elem.clone(),
                    tpe: SType::SColl(Box::new(elem)),
                });
            }
            // Rules 4-5: min/max (SigmaBinder.scala:65-78). Exactly 2 args →
            // ArithOp(l, r, Min/Max); otherwise InvalidArguments positioned
            // at the callee Ident (i.sourceContext).
            "min" | "max" => {
                if args.len() == 2 {
                    let opcode = if name == "min" { ARITH_MIN } else { ARITH_MAX };
                    let tpe = node_tpe(&args[0]).clone(); // ArithOp.tpe = left.tpe
                    let mut it = args.into_iter();
                    let l = it.next().expect("len checked");
                    let r = it.next().expect("len checked");
                    return Ok(TypedExpr::ArithOp {
                        left: Box::new(l),
                        right: Box::new(r),
                        opcode,
                        tpe,
                    });
                }
                return Err(BindError::InvalidArguments {
                    msg: format!("Invalid arguments for {name}: {args:?}"),
                    pos: func_pos,
                });
            }
            // Rule 9: PK("addr") → SigmaPropConstant(pubkey). Pattern is
            // symNoType = Ident("PK", NoType) EXACTLY (SigmaBinder.scala:105).
            "PK" if *tpe == SType::NoType => return bind_pk(args, apply_pos, _network),
            // Rule 10: serialize(v) → MethodCall(Global, serializeMethod, [v], {}).
            // symNoType pattern again (SigmaBinder.scala:108).
            "serialize" if *tpe == SType::NoType => return bind_serialize(args, apply_pos),
            _ => {}
        }
    }

    // Mechanical Apply: tpe from the callee (values.scala:1218-1222).
    let tpe = match node_tpe(&func) {
        SType::SFunc { range, .. } => (**range).clone(),
        SType::SColl(elem) => (**elem).clone(),
        _ => SType::NoType,
    };
    Ok(TypedExpr::Apply {
        func: Box::new(func),
        args,
        tpe,
    })
}

/// Rule 9 body: the PK irBuilder (SigmaPredef.scala:156-166).
///
/// `case (_, Seq(arg: EvaluatedValue[SString.type])) => ErgoAddressEncoder(
/// networkPrefix).fromString(arg.value).get match { case a: P2PKAddress =>
/// SigmaPropConstant(a.pubkey); case a => sys.error(...) }`
///
/// A non-matching arg shape (wrong arity, or a non-String-constant arg after
/// children-first binding) is a `scala.MatchError` crash in the reference —
/// mapped to `InvalidArguments` here (verdict parity; class tag deviation D-T8).
fn bind_pk(args: Vec<TypedExpr>, pos: Pos, network: NetworkPrefix) -> Result<TypedExpr, BindError> {
    match args.as_slice() {
        [TypedExpr::Constant {
            value: ConstPayload::String(s),
            ..
        }] => {
            // decode_p2pk_address = Base58 + checksum + network-prefix +
            // P2PK-type checks (ergo-ser · src/address.rs:277).
            let pubkey =
                decode_p2pk_address(s, network).map_err(|e| BindError::InvalidAddress {
                    msg: format!("PK(\"{s}\"): {e}"),
                    pos,
                })?;
            // D-T5: on-curve validation of the decoded key, mirroring Scala's
            // GroupElementSerializer.parse which validates the point at decode
            // time. Rejects off-curve AND identity keys — keeps the printer's
            // decompress-on-demand invariant (typed_print.rs) panic-free.
            ergo_crypto::group_element::decompress_to_affine_hex(&pubkey).map_err(|e| {
                BindError::InvalidAddress {
                    msg: format!("PK(\"{s}\"): pubkey is not a valid curve point: {e}"),
                    pos,
                }
            })?;
            Ok(TypedExpr::Constant {
                value: ConstPayload::ProveDlog(pubkey),
                tpe: SType::SSigmaProp,
            })
        }
        _ => Err(BindError::InvalidArguments {
            msg: format!(
                "Invalid arguments for PK: expected a single String constant, got {args:?} \
                 (scala.MatchError in the reference)"
            ),
            pos,
        }),
    }
}

/// The bound (pre-typer) `tpe` of a `Select` node: the reference lazy `Value.tpe`
/// on a bound tree (values.scala:1171-1178) —
/// `resType.getOrElse(obj.tpe match { case p: SProduct => p.method(field).stype;
/// case _ => NoType })`.  `resType` is always `None` at bind time, so this is the
/// method's raw DECLARED signature: `SFunc` with the declared receiver in `dom[0]`
/// and the method's own type parameters (e.g. `SELF.value → (Box) => Long`,
/// `xs.size → (Coll[IV]) => Int`, `xs.map → [IV,OV](Coll[IV],(IV) => OV) => Coll[OV]`),
/// or `NoType` when the receiver is not an `SProduct` or has no such method.
///
/// A bound Select's `tpe` is normally OVERWRITTEN by the typer — `assign_type`
/// re-derives it in `assign_select` (via `get_method`) and fills `res_type` — so
/// this value is only ever *observed* on a Select that survives un-typed: inside a
/// binder-prebuilt `serialize(v)` argument, which passes through unchanged.
/// There the s-expression must match the reference byte-for-byte (`get_method`
/// supplies the full declared `SFunc`, incl. `SBox`/`SGroupElement`/… receivers the
/// parse-AST `product_method_tpe` port omits), and any `NoType` node makes the
/// reference printer throw → REJECT (enforced by that passthrough).
///
/// This does NOT change `Expr::parse_tpe` (a separate `product_method_tpe` call site
/// on the untyped parse AST that drives unary/relation operand checks); only the
/// bound `TypedExpr` Select carries this signature.
fn declared_select_tpe(obj_tpe: &SType, field: &str, tree_version: u8) -> SType {
    match get_method(obj_tpe, field, tree_version) {
        Some(m) => SType::SFunc {
            dom: m.stype.dom.clone(),
            range: Box::new(m.stype.range.clone()),
            tpe_params: m.stype.tpe_params.clone(),
        },
        None => SType::NoType,
    }
}

/// Rule 10 body: the serialize irBuilder (SigmaPredef.scala:449-459).
///
/// `case (_, args @ Seq(value)) => MethodCall.typed[Value[SCollection[SByte]]](
/// Global, SGlobalMethods.serializeMethod.withConcreteTypes(Map(tT ->
/// value.tpe)), args, Map())`
///
/// The `withConcreteTypes` substitution specializes the METHOD DESCRIPTOR
/// (not the MethodCall.typeSubst, which stays empty `Map()`); `MethodRef`
/// carries only owner+name, and neither the printer nor the rest of the
/// pipeline reads the descriptor's dom, so dropping the specialization is
/// lossless here (the lowering pass recomputes it). tpe = the method range,
/// `Coll[Byte]`.
///
/// Non-single arity is a `scala.MatchError` crash in the reference — mapped
/// to `InvalidArguments` (verdict parity; class tag deviation D-T8).
fn bind_serialize(args: Vec<TypedExpr>, pos: Pos) -> Result<TypedExpr, BindError> {
    if args.len() != 1 {
        return Err(BindError::InvalidArguments {
            msg: format!(
                "Invalid arguments for serialize: expected exactly one argument, got {args:?} \
                 (scala.MatchError in the reference)"
            ),
            pos,
        });
    }
    Ok(TypedExpr::MethodCall {
        obj: Box::new(TypedExpr::Global {
            tpe: SType::SGlobal,
        }),
        method: MethodRef {
            owner: "SigmaDslBuilder".to_string(),
            name: "serialize".to_string(),
        },
        args,
        type_subst: vec![],
        tpe: SType::SColl(Box::new(SType::SByte)),
    })
}

/// Rule 8: Block with bindings (SigmaBinder.scala:90-103).
///
/// Children (all val bodies + the result) are bound FIRST — kiama order — so
/// any child error fires before the duplicate-name checks. Then, per val in
/// order: the OUTER-env duplicate check (`env.contains(n)` — sibling names in
/// the same block are NOT checked; that is the typer's check), and the
/// given-type fill `mkVal(n, if (t != NoType) t else b1.tpe, b1)`.
fn bind_block(
    env: &ScriptEnv,
    bindings: &[ValDef],
    result: &Expr,
    network: NetworkPrefix,
    tree_version: u8,
) -> Result<TypedExpr, BindError> {
    // Children first (val bodies in order, then the result).
    let bodies = bindings
        .iter()
        .map(|vd| bind_expr(env, &vd.body, network, tree_version))
        .collect::<Result<Vec<_>, _>>()?;
    let result_b = bind_expr(env, result, network, tree_version)?;

    // Duplicate-name checks + val assembly, in val order.
    let mut new_binds = Vec::with_capacity(bindings.len());
    for (vd, b1) in bindings.iter().zip(bodies) {
        if let Some(v) = env.get(&vd.name) {
            // sic: the Scala message omits the closing paren
            // (SigmaBinder.scala:93 `"... ($n = ${env(n)}"`).
            return Err(BindError::BinderException {
                msg: format!(
                    "Variable {} already defined ({} = {:?}",
                    vd.name, vd.name, v
                ),
                pos: vd.pos,
            });
        }
        let filled = if vd.given_type != SType::NoType {
            vd.given_type.clone()
        } else {
            node_tpe(&b1).clone()
        };
        new_binds.push(TypedExpr::ValNode {
            name: vd.name.clone(),
            given_type: filled.clone(),
            body: Box::new(b1),
            tpe: filled,
        });
    }
    let tpe = node_tpe(&result_b).clone(); // Block.tpe = result.tpe
    Ok(TypedExpr::Block {
        bindings: new_binds,
        result: Box::new(result_b),
        tpe,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::EnvValue;
    use crate::parse::parse;
    use crate::typed_print::print_typed;
    use ergo_ser::address::encode_p2pk_from_pubkey;

    // ----- helpers -----

    fn bind_src(src: &str) -> TypedExpr {
        bind_src_env(&ScriptEnv::new(), src)
    }

    fn bind_src_env(env: &ScriptEnv, src: &str) -> TypedExpr {
        let ast = parse(src, 3).expect("parse must succeed");
        bind(env, &ast, NetworkPrefix::Mainnet, 3).expect("bind must succeed")
    }

    fn bind_err_env(env: &ScriptEnv, src: &str) -> BindError {
        let ast = parse(src, 3).expect("parse must succeed");
        bind(env, &ast, NetworkPrefix::Mainnet, 3).expect_err("bind must fail")
    }

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

    /// The oracle demo env (golden_seed.txt header): a,b:Coll[Byte];
    /// col1,col2:Coll[Long]; g1:GroupElement (secp256k1 generator); n1:BigInt.
    fn demo_env() -> ScriptEnv {
        let mut env = ScriptEnv::new();
        env.insert("a", EnvValue::ByteArray(vec![1, 2]));
        env.insert("b", EnvValue::ByteArray(vec![3, 4]));
        env.insert("col1", EnvValue::LongArray(vec![1, 2]));
        env.insert("col2", EnvValue::LongArray(vec![3, 4]));
        env.insert("n1", EnvValue::BigInt("5".to_string()));
        env
    }

    /// secp256k1 generator compressed pubkey (02 || x).
    fn generator_pubkey() -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        bytes
    }

    // ----- happy path -----

    // Rule 1a: env substitution.
    #[test]
    fn rule1_env_ident_substitutes_lifted_constant() {
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Long(7));
        assert_eq!(bind_src_env(&env, "x"), long_const(7));
    }

    // Rule 1a beats 1b: env priority over global names (SigmaBinder.scala:40).
    #[test]
    fn rule1_env_height_beats_global_singleton() {
        let mut env = ScriptEnv::new();
        env.insert("HEIGHT", EnvValue::Int(100));
        assert_eq!(bind_src_env(&env, "HEIGHT"), int_const(100));
    }

    // Rule 1b: the 8 global singletons (SigmaBinder.scala:42-50).
    #[test]
    fn rule1_global_names_substitute_singletons() {
        let cases: &[(&str, TypedExpr)] = &[
            ("HEIGHT", TypedExpr::Height { tpe: SType::SInt }),
            (
                "MinerPubkey",
                TypedExpr::MinerPubkey {
                    tpe: SType::SColl(Box::new(SType::SByte)),
                },
            ),
            (
                "INPUTS",
                TypedExpr::Inputs {
                    tpe: SType::SColl(Box::new(SType::SBox)),
                },
            ),
            (
                "OUTPUTS",
                TypedExpr::Outputs {
                    tpe: SType::SColl(Box::new(SType::SBox)),
                },
            ),
            (
                "LastBlockUtxoRootHash",
                TypedExpr::LastBlockUtxoRootHash {
                    tpe: SType::SAvlTree,
                },
            ),
            ("SELF", TypedExpr::Self_ { tpe: SType::SBox }),
            (
                "CONTEXT",
                TypedExpr::Context {
                    tpe: SType::SContext,
                },
            ),
            (
                "Global",
                TypedExpr::Global {
                    tpe: SType::SGlobal,
                },
            ),
        ];
        for (src, expected) in cases {
            assert_eq!(&bind_src(src), expected, "{src}");
        }
    }

    // Rule 1b: EmptyByteArray → ByteArrayConstant(empty) (SigmaBinder.scala:47).
    #[test]
    fn rule1_empty_byte_array_is_empty_bytecoll_constant() {
        assert_eq!(
            bind_src("EmptyByteArray"),
            TypedExpr::Constant {
                value: ConstPayload::ByteColl(vec![]),
                tpe: SType::SColl(Box::new(SType::SByte)),
            }
        );
    }

    // Rule 1 fallthrough: unknown NoType Ident survives to the typer.
    #[test]
    fn rule1_unknown_ident_survives_untouched() {
        assert_eq!(
            bind_src("foo"),
            TypedExpr::Ident {
                name: "foo".to_string(),
                tpe: SType::NoType,
            }
        );
    }

    // Rule 1 does NOT fire for a typed Ident (pattern is Ident(n, NoType));
    // the ZKProof callee is the only parser-typed Ident.
    #[test]
    fn rule1_typed_ident_not_substituted_even_when_in_env() {
        let mut env = ScriptEnv::new();
        env.insert("ZKProof", EnvValue::Int(1));
        let sfunc = SType::SFunc {
            dom: vec![SType::SSigmaProp],
            range: Box::new(SType::SBoolean),
            tpe_params: vec![],
        };
        let e = Expr::Ident {
            name: "ZKProof".to_string(),
            tpe: sfunc.clone(),
            pos: 0,
        };
        let bound = bind(&env, &e, NetworkPrefix::Mainnet, 3).expect("bind");
        assert_eq!(
            bound,
            TypedExpr::Ident {
                name: "ZKProof".to_string(),
                tpe: sfunc,
            }
        );
    }

    // Rule 2: Coll[T](…) with a declared element type.
    #[test]
    fn rule2_typed_coll_becomes_concrete_collection() {
        assert_eq!(
            bind_src("Coll[Int](1, 2)"),
            TypedExpr::ConcreteCollection {
                items: vec![int_const(1), int_const(2)],
                elem_type: SType::SInt,
                tpe: SType::SColl(Box::new(SType::SInt)),
            }
        );
    }

    // Rule 2 pattern requires EXACTLY one type arg; two fall through to a
    // plain Apply (constructed directly — grammar acceptance of the source
    // form is a parser concern).
    #[test]
    fn rule2_multi_type_args_fall_through_to_apply() {
        let e = Expr::Apply {
            func: Box::new(Expr::ApplyTypes {
                input: Box::new(Expr::Ident {
                    name: "Coll".to_string(),
                    tpe: SType::NoType,
                    pos: 0,
                }),
                type_args: vec![SType::SInt, SType::SLong],
                pos: 0,
            }),
            args: vec![Expr::IntConst { value: 1, pos: 0 }],
            pos: 0,
        };
        let bound = bind(&ScriptEnv::new(), &e, NetworkPrefix::Mainnet, 3).expect("bind");
        assert!(matches!(bound, TypedExpr::Apply { .. }));
    }

    // Rule 3: Coll(…) infers the element type from the FIRST bound arg.
    #[test]
    fn rule3_untyped_coll_infers_elem_from_first_arg() {
        assert_eq!(
            bind_src("Coll(1L, 2L)"),
            TypedExpr::ConcreteCollection {
                items: vec![long_const(1), long_const(2)],
                elem_type: SType::SLong,
                tpe: SType::SColl(Box::new(SType::SLong)),
            }
        );
    }

    // Rule 3: empty Coll() → NoType element (SigmaBinder.scala:61).
    #[test]
    fn rule3_empty_coll_elem_is_no_type() {
        assert_eq!(
            bind_src("Coll()"),
            TypedExpr::ConcreteCollection {
                items: vec![],
                elem_type: SType::NoType,
                tpe: SType::SColl(Box::new(SType::NoType)),
            }
        );
    }

    // Env priority: an env-shadowed "Coll" is substituted by rule 1 first, so
    // rule 3 never sees the Ident (kiama children-first).
    #[test]
    fn rule3_env_coll_shadows_builtin() {
        let mut env = ScriptEnv::new();
        env.insert("Coll", EnvValue::Int(5));
        assert_eq!(
            bind_src_env(&env, "Coll(1)"),
            TypedExpr::Apply {
                func: Box::new(int_const(5)),
                args: vec![int_const(1)],
                tpe: SType::NoType, // callee tpe SInt is neither SFunc nor SColl
            }
        );
    }

    // Rule 4: min(l, r) → ArithOp(l, r, Min).
    #[test]
    fn rule4_min_two_args_becomes_arith_min() {
        assert_eq!(
            bind_src("min(1, 2)"),
            TypedExpr::ArithOp {
                left: Box::new(int_const(1)),
                right: Box::new(int_const(2)),
                opcode: ARITH_MIN,
                tpe: SType::SInt,
            }
        );
    }

    // Rule 5: max(l, r) → ArithOp(l, r, Max).
    #[test]
    fn rule5_max_two_args_becomes_arith_max() {
        assert_eq!(
            bind_src("max(1L, 2L)"),
            TypedExpr::ArithOp {
                left: Box::new(long_const(1)),
                right: Box::new(long_const(2)),
                opcode: ARITH_MAX,
                tpe: SType::SLong,
            }
        );
    }

    // Env priority for min: substituted callee → plain Apply, no arity check.
    #[test]
    fn rule4_env_min_shadows_builtin() {
        let mut env = ScriptEnv::new();
        env.insert("min", EnvValue::Int(9));
        assert_eq!(
            bind_src_env(&env, "min(1, 2, 3)"),
            TypedExpr::Apply {
                func: Box::new(int_const(9)),
                args: vec![int_const(1), int_const(2), int_const(3)],
                tpe: SType::NoType,
            }
        );
    }

    // Rule 6: lambda body bound with the OUTER env; params NOT in scope.
    #[test]
    fn rule6_lambda_body_bound_params_not_in_env() {
        let bound = bind_src("{(x: Int) => x + HEIGHT}");
        match bound {
            TypedExpr::Lambda {
                tpe_params,
                args,
                given_res_type,
                body,
                tpe,
            } => {
                assert!(tpe_params.is_empty());
                assert_eq!(args, vec![("x".to_string(), SType::SInt)]);
                assert_eq!(given_res_type, SType::NoType);
                // body: `x + HEIGHT` is a MethodCallLike; HEIGHT substituted,
                // x survives (param scoping is the typer's job).
                assert_eq!(
                    *body.expect("body present"),
                    TypedExpr::MethodCallLike {
                        obj: Box::new(TypedExpr::Ident {
                            name: "x".to_string(),
                            tpe: SType::NoType,
                        }),
                        name: "+".to_string(),
                        args: vec![TypedExpr::Height { tpe: SType::SInt }],
                        tpe: SType::NoType,
                    }
                );
                // Lambda.tpe = SFunc([SInt], givenResType ?: body.tpe=NoType).
                assert_eq!(
                    tpe,
                    SType::SFunc {
                        dom: vec![SType::SInt],
                        range: Box::new(SType::NoType),
                        tpe_params: vec![],
                    }
                );
            }
            other => panic!("expected Lambda, got {other:?}"),
        }
    }

    // Rule 7: { e } → e.
    #[test]
    fn rule7_empty_block_unwraps_to_result() {
        assert_eq!(
            bind_src("{ HEIGHT }"),
            TypedExpr::Height { tpe: SType::SInt }
        );
    }

    // Rule 7 exposing a parent redex: `({min})(1,2)` — the unwrapped Ident
    // becomes the Apply callee and rule 4 still fires (fixpoint equivalence).
    #[test]
    fn rule7_unwrapped_callee_still_hits_min_rule() {
        assert_eq!(
            bind_src("({min})(1, 2)"),
            TypedExpr::ArithOp {
                left: Box::new(int_const(1)),
                right: Box::new(int_const(2)),
                opcode: ARITH_MIN,
                tpe: SType::SInt,
            }
        );
    }

    // Rule 8: unascribed val gets given_type filled from the bound body.
    #[test]
    fn rule8_block_val_type_filled_from_body() {
        assert_eq!(
            bind_src("{ val x = HEIGHT; x }"),
            TypedExpr::Block {
                bindings: vec![TypedExpr::ValNode {
                    name: "x".to_string(),
                    given_type: SType::SInt,
                    body: Box::new(TypedExpr::Height { tpe: SType::SInt }),
                    tpe: SType::SInt,
                }],
                result: Box::new(TypedExpr::Ident {
                    name: "x".to_string(),
                    tpe: SType::NoType,
                }),
                tpe: SType::NoType, // Block.tpe = result.tpe
            }
        );
    }

    // Rule 8: an explicit annotation is KEPT (not overwritten by body.tpe).
    #[test]
    fn rule8_block_val_explicit_annotation_kept() {
        let bound = bind_src("{ val x: Long = HEIGHT; x }");
        match bound {
            TypedExpr::Block { bindings, .. } => match &bindings[0] {
                TypedExpr::ValNode {
                    given_type, tpe, ..
                } => {
                    assert_eq!(*given_type, SType::SLong);
                    assert_eq!(*tpe, SType::SLong);
                }
                other => panic!("expected ValNode, got {other:?}"),
            },
            other => panic!("expected Block, got {other:?}"),
        }
    }

    // Rule 8 checks ONLY the outer env — sibling duplicates pass the binder
    // (the typer rejects them, SigmaTyper.scala:58-59).
    #[test]
    fn rule8_sibling_duplicate_names_pass_binder() {
        let bound = bind_src("{ val y = 1; val y = 2; y }");
        assert!(matches!(bound, TypedExpr::Block { ref bindings, .. } if bindings.len() == 2));
    }

    // Rule 9: PK with a valid mainnet address → SigmaPropConstant(pubkey).
    #[test]
    fn rule9_pk_valid_mainnet_address_becomes_provedlog_constant() {
        let pk = generator_pubkey();
        let addr = encode_p2pk_from_pubkey(NetworkPrefix::Mainnet, &pk).expect("encode P2PK");
        let src = format!("PK(\"{addr}\")");
        assert_eq!(
            bind_src(&src),
            TypedExpr::Constant {
                value: ConstPayload::ProveDlog(pk),
                tpe: SType::SSigmaProp,
            }
        );
    }

    // Env priority for PK: substituted callee → plain Apply, NO address
    // decode (an invalid address string does not error).
    #[test]
    fn rule9_env_pk_shadows_builtin_no_decode() {
        let mut env = ScriptEnv::new();
        env.insert("PK", EnvValue::Int(3));
        assert_eq!(
            bind_src_env(&env, "PK(\"not an address\")"),
            TypedExpr::Apply {
                func: Box::new(int_const(3)),
                args: vec![TypedExpr::Constant {
                    value: ConstPayload::String("not an address".to_string()),
                    tpe: SType::SString,
                }],
                tpe: SType::NoType,
            }
        );
    }

    // Rule 10: serialize(v) → MethodCall(Global, serialize, [v], {}).
    #[test]
    fn rule10_serialize_becomes_global_methodcall() {
        assert_eq!(
            bind_src("serialize(1)"),
            TypedExpr::MethodCall {
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
            }
        );
    }

    // Rule 11: obj.isEmpty → !obj.isDefined.
    #[test]
    fn rule11_isempty_desugars_to_not_isdefined() {
        assert_eq!(
            bind_src("x.isEmpty"),
            TypedExpr::LogicalNot {
                input: Box::new(TypedExpr::Select {
                    obj: Box::new(TypedExpr::Ident {
                        name: "x".to_string(),
                        tpe: SType::NoType,
                    }),
                    field: "isDefined".to_string(),
                    res_type: None,
                    tpe: SType::NoType, // NoType receiver → NoType lookup
                }),
                tpe: SType::SBoolean,
            }
        );
    }

    // Rule 11 fires only for the "isEmpty" field.
    #[test]
    fn rule11_other_fields_stay_select() {
        assert_eq!(
            bind_src("x.isDefined"),
            TypedExpr::Select {
                obj: Box::new(TypedExpr::Ident {
                    name: "x".to_string(),
                    tpe: SType::NoType,
                }),
                field: "isDefined".to_string(),
                res_type: None,
                tpe: SType::NoType,
            }
        );
    }

    // Mechanical conversion: constants carry their concrete types.
    #[test]
    fn mechanical_constants_convert_with_concrete_types() {
        assert_eq!(bind_src("42"), int_const(42));
        assert_eq!(bind_src("1L"), long_const(1));
        assert_eq!(
            bind_src("true"),
            TypedExpr::Constant {
                value: ConstPayload::Bool(true),
                tpe: SType::SBoolean,
            }
        );
        assert_eq!(
            bind_src("\"abc\""),
            TypedExpr::Constant {
                value: ConstPayload::String("abc".to_string()),
                tpe: SType::SString,
            }
        );
        assert_eq!(
            bind_src("()"),
            TypedExpr::Constant {
                value: ConstPayload::Unit,
                tpe: SType::SUnit,
            }
        );
    }

    // Mechanical conversion: op nodes with their frontend tpe defs.
    #[test]
    fn mechanical_ops_convert_with_frontend_tpes() {
        // Relation → SBoolean (trees.scala:1072-1073).
        assert_eq!(
            bind_src("1 < 2"),
            TypedExpr::LT {
                left: Box::new(int_const(1)),
                right: Box::new(int_const(2)),
                tpe: SType::SBoolean,
            }
        );
        // ArithOp.tpe = left.tpe (trees.scala:704-707).
        assert_eq!(
            bind_src("5 - 3"),
            TypedExpr::ArithOp {
                left: Box::new(int_const(5)),
                right: Box::new(int_const(3)),
                opcode: ARITH_MINUS,
                tpe: SType::SInt,
            }
        );
        // BitOp.tpe = left.tpe (trees.scala:911-915).
        assert_eq!(
            bind_src("1 | 2"),
            TypedExpr::BitOp {
                left: Box::new(int_const(1)),
                right: Box::new(int_const(2)),
                opcode: BIT_OR,
                tpe: SType::SInt,
            }
        );
        // `+` is a MethodCallLike in the reference grammar; tpe = NoType.
        assert_eq!(
            bind_src("1 + 2"),
            TypedExpr::MethodCallLike {
                obj: Box::new(int_const(1)),
                name: "+".to_string(),
                args: vec![int_const(2)],
                tpe: SType::NoType,
            }
        );
        // LogicalNot → SBoolean.
        assert_eq!(
            bind_src("!true"),
            TypedExpr::LogicalNot {
                input: Box::new(TypedExpr::Constant {
                    value: ConstPayload::Bool(true),
                    tpe: SType::SBoolean,
                }),
                tpe: SType::SBoolean,
            }
        );
    }

    // Mechanical conversion: Tuple/If tpe derivations.
    #[test]
    fn mechanical_tuple_and_if_tpes() {
        assert_eq!(
            bind_src("(1, true)"),
            TypedExpr::Tuple {
                items: vec![
                    int_const(1),
                    TypedExpr::Constant {
                        value: ConstPayload::Bool(true),
                        tpe: SType::SBoolean,
                    },
                ],
                tpe: SType::STuple(vec![SType::SInt, SType::SBoolean]),
            }
        );
        // If.tpe = trueBranch.tpe (trees.scala:1348-1351).
        let bound = bind_src("if (c) 1L else 2L");
        assert_eq!(node_tpe(&bound), &SType::SLong);
    }

    // Bound Select mirrors the parse-time product-method tpe derivation.
    #[test]
    fn mechanical_select_tpe_mirrors_product_lookup() {
        // `5.toByte`: SInt receiver, found method → SFunc(SInt → SByte).
        assert_eq!(
            bind_src("5.toByte"),
            TypedExpr::Select {
                obj: Box::new(int_const(5)),
                field: "toByte".to_string(),
                res_type: None,
                tpe: SType::SFunc {
                    dom: vec![SType::SInt],
                    range: Box::new(SType::SByte),
                    tpe_params: vec![],
                },
            }
        );
    }

    // ----- round-trips -----

    // bind is deterministic: same input, same output tree.
    #[test]
    fn bind_same_source_twice_is_deterministic() {
        let env = demo_env();
        let src = "{ val x = min(1, HEIGHT); Coll(x, a.size) }";
        assert_eq!(bind_src_env(&env, src), bind_src_env(&env, src));
    }

    // ----- error paths -----

    // Rules 4-5: arity != 2 → InvalidArguments at the callee Ident.
    #[test]
    fn min_wrong_arity_errors_invalid_arguments() {
        let err = bind_err_env(&ScriptEnv::new(), "min(1)");
        assert!(matches!(err, BindError::InvalidArguments { .. }), "{err:?}");
        assert_eq!(err.pos(), 0); // the `min` Ident offset
    }

    #[test]
    fn max_three_args_errors_invalid_arguments() {
        let err = bind_err_env(&ScriptEnv::new(), "max(1, 2, 3)");
        assert!(matches!(err, BindError::InvalidArguments { .. }), "{err:?}");
    }

    // Rule 8: a block val colliding with the OUTER env → BinderException.
    #[test]
    fn block_val_colliding_with_env_errors_binder_exception() {
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Int(1));
        let err = bind_err_env(&env, "{ val x = 2; x }");
        match &err {
            BindError::BinderException { msg, .. } => {
                assert!(msg.contains("already defined"), "{msg}");
            }
            other => panic!("expected BinderException, got {other:?}"),
        }
        assert_eq!(err.pos(), 6); // the bound name `x` (ValDef.pos) in `{ val x = 2; x }`
    }

    // kiama order: a child error (min arity) fires BEFORE the parent block's
    // duplicate-name check.
    #[test]
    fn child_error_fires_before_block_dup_check() {
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Int(1));
        let err = bind_err_env(&env, "{ val x = min(1); x }");
        assert!(matches!(err, BindError::InvalidArguments { .. }), "{err:?}");
    }

    // Rule 9: malformed Base58 → InvalidAddress.
    // Oracle probe `PK("notanaddress")` → REJECT 0:0 Exception (golden_seed.txt §10).
    // Scala: Try.get on a bad decode throws NoSuchElementException with no source
    // position; our class = InvalidAddress (more specific than Scala's base Exception;
    // verdict parity holds).
    #[test]
    fn pk_malformed_address_errors_invalid_address() {
        let err = bind_err_env(&ScriptEnv::new(), "PK(\"notAnAddress\")");
        assert!(matches!(err, BindError::InvalidAddress { .. }), "{err:?}");
    }

    // Rule 9: a testnet address under a mainnet binder → InvalidAddress
    // (network prefix mismatch).
    #[test]
    fn pk_wrong_network_errors_invalid_address() {
        let addr = encode_p2pk_from_pubkey(NetworkPrefix::Testnet, &generator_pubkey())
            .expect("encode P2PK");
        let err = bind_err_env(&ScriptEnv::new(), &format!("PK(\"{addr}\")"));
        assert!(matches!(err, BindError::InvalidAddress { .. }), "{err:?}");
    }

    // D-T5: a well-formed P2PK address (valid Base58/checksum/prefix) whose
    // 33-byte payload is NOT a curve point → InvalidAddress at bind time,
    // mirroring Scala's GroupElementSerializer.parse decode-time validation.
    // Off-curve bytes = 0x02-prefix, x=5 (no valid y on secp256k1 — same
    // vector as ergo-crypto::group_element::tests::off_curve_bytes).
    #[test]
    fn pk_off_curve_pubkey_errors_invalid_address() {
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 0x05;
        let addr =
            encode_p2pk_from_pubkey(NetworkPrefix::Mainnet, &off_curve).expect("encode P2PK");
        let err = bind_err_env(&ScriptEnv::new(), &format!("PK(\"{addr}\")"));
        assert!(matches!(err, BindError::InvalidAddress { .. }), "{err:?}");
    }

    // Rule 9: non-String-constant arg → reject (scala.MatchError parity).
    // Oracle probe `PK(1)` → REJECT 1:1 TyperException (golden_seed.txt §10).
    // Scala: MatchError on a non-String irBuilder arg is wrapped at the typer level
    // as TyperException; our class = InvalidArguments (verdict parity holds).
    #[test]
    fn pk_non_string_arg_errors_invalid_arguments() {
        let err = bind_err_env(&ScriptEnv::new(), "PK(1)");
        assert!(matches!(err, BindError::InvalidArguments { .. }), "{err:?}");
    }

    // Rule 9: wrong arity → reject (scala.MatchError parity).
    #[test]
    fn pk_wrong_arity_errors_invalid_arguments() {
        for src in ["PK()", "PK(\"a\", \"b\")"] {
            let err = bind_err_env(&ScriptEnv::new(), src);
            assert!(
                matches!(err, BindError::InvalidArguments { .. }),
                "{src}: {err:?}"
            );
        }
    }

    // Rule 10: wrong arity → reject (scala.MatchError parity).
    #[test]
    fn serialize_wrong_arity_errors_invalid_arguments() {
        for src in ["serialize()", "serialize(1, 2)"] {
            let err = bind_err_env(&ScriptEnv::new(), src);
            assert!(
                matches!(err, BindError::InvalidArguments { .. }),
                "{src}: {err:?}"
            );
        }
    }

    // ----- oracle parity -----

    // golden_seed.txt §2: `Coll(1, 2, 3)` — the binder's ConcreteCollection is
    // already the final typed form for uniform int items; its print must match
    // the typer-oracle record byte-for-byte.
    #[test]
    fn coll_print_matches_typer_oracle_seed() {
        let bound = bind_src("Coll(1, 2, 3)");
        assert_eq!(
            print_typed(&bound),
            "(ConcreteCollection:Coll[Int] [(ConstantNode:Int @1) (ConstantNode:Int @2) \
             (ConstantNode:Int @3)] #Int)"
        );
    }

    // golden_seed.txt §4: `Global.serialize(1)` — rule 10 produces the SAME
    // MethodCall node the typer emits for the explicit Global form, so the
    // print of `serialize(1)` after binding must equal that oracle record.
    #[test]
    fn serialize_print_matches_global_methodcall_seed() {
        let bound = bind_src("serialize(1)");
        assert_eq!(
            print_typed(&bound),
            "(MethodCall:Coll[Byte] (Global:SigmaDslBuilder) %SigmaDslBuilder.serialize \
             [(ConstantNode:Int @1)] {})"
        );
    }

    // Demo-env substitutions print as the oracle's tce constants
    // (golden_seed.txt §1/§4 demo env: a=[1,2] bytes, col1=[1,2] longs, n1=5).
    #[test]
    fn demo_env_substitution_prints_match_oracle_constants() {
        let env = demo_env();
        assert_eq!(
            print_typed(&bind_src_env(&env, "a")),
            "(ConstantNode:Coll[Byte] <@1 @2>)"
        );
        assert_eq!(
            print_typed(&bind_src_env(&env, "col1")),
            "(ConstantNode:Coll[Long] <@1 @2>)"
        );
        assert_eq!(
            print_typed(&bind_src_env(&env, "n1")),
            "(ConstantNode:BigInt (CBigInt @5))"
        );
    }

    // golden_seed.txt §10: PK with the secp256k1 generator G (testnet address).
    // The oracle runs with ORACLE_NETWORK=testnet (default); the address string here
    // is IDENTICAL to the `tc` record committed in §10.
    // External byte anchor: `generator_pubkey()` hardcodes the secp256k1 G-point
    // x-coordinate — the expected bytes are NEVER derived from the address under test.
    #[test]
    fn pk_provedlog_bytes_match_seed_section_10_g_point() {
        // Same address as golden_seed.txt §10 (secp256k1 G, testnet P2PK).
        let addr = "3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN";
        let src = format!("PK(\"{addr}\")");
        let ast = parse(&src, 3).expect("parse");
        let bound = bind(&ScriptEnv::new(), &ast, NetworkPrefix::Testnet, 3)
            .expect("bind must succeed for valid testnet G-point address");
        let g = generator_pubkey();
        assert_eq!(
            bound,
            TypedExpr::Constant {
                value: ConstPayload::ProveDlog(g),
                tpe: SType::SSigmaProp,
            },
            "ProveDlog payload must be the secp256k1 G-point bytes"
        );
    }

    // tce `a ++ b` (golden_seed.txt §1): the binder substitutes both operands;
    // the ++ MethodCallLike survives for the typer (which lowers it to Append).
    #[test]
    fn demo_env_append_operands_substituted() {
        let env = demo_env();
        assert_eq!(
            bind_src_env(&env, "a ++ b"),
            TypedExpr::MethodCallLike {
                obj: Box::new(TypedExpr::Constant {
                    value: ConstPayload::ByteColl(vec![1, 2]),
                    tpe: SType::SColl(Box::new(SType::SByte)),
                }),
                name: "++".to_string(),
                args: vec![TypedExpr::Constant {
                    value: ConstPayload::ByteColl(vec![3, 4]),
                    tpe: SType::SColl(Box::new(SType::SByte)),
                }],
                tpe: SType::NoType,
            }
        );
    }
}
