//! Typed ErgoScript AST → `ergo-ser` opcode IR (backend emission).
//!
//! M3 Task 7 laid the type map ([`map_type`]), the constant map
//! ([`map_const`]), and every FIXED-ARITY opcode arm of [`emit`] — context
//! singletons, relations, arithmetic/boolean operators, collection
//! transformers, sigma combinators, crypto primitives, option/context access.
//! (Bit operators later became Task-11 wave-1 GraphBuilding-parity REJECTS —
//! lib.rs D-C5; Scala's full compiler cannot lower them.)
//! M3 Task 8 adds the binding forms (`Block`/`ValNode`/`Ident`/`Lambda` →
//! `BlockValue`/`ValDef`/`ValUse`/`FuncValue`), `MethodCall`/`PropertyCall`
//! wire dispatch, the residual `Apply`/`Select` lowering catalog (numeric
//! casts, box/sigma-prop/tuple properties, `FuncApply`), and defensive
//! mixed-width `Upcast` normalization inside the binary arith/relation and
//! `ByIndex` arms.
//!
//! Opcode bytes come from the `opcode_pattern` dispatch table
//! (`ergo-ser/src/opcode/types.rs:276-436`), which is the crate's consensus
//! contract with Scala `ValueSerializer`/`OpCodes.scala` (sigma-state 6.0.2).
//! Payload shapes follow `dev-docs/ergoscript-compiler-m3-recon/recon-ergoser-ir.md`.
//!
//! # Boolean constants — byte-shape intel for Task 9/10 (oracle-captured)
//!
//! Live TyperOracle captures (sigma-state 6.0.2, 2026-07-05, `cc` verb):
//!
//! ```text
//! sigmaProp(true)        → 10 01 0101   d1 7300
//! sigmaProp(false)       → 10 01 0100   d1 7300
//! sigmaProp(HEIGHT>100)  → 10 01 04c801 d1 91 a3 7300
//! ```
//!
//! The Scala compile path emits Boolean constants via the CONSTANT path — a
//! segregated `SBoolean` table entry (`0101`/`0100`) referenced by a
//! `ConstPlaceholder` (`7300`) — NOT the dedicated `0x7F` True / `0x80` False
//! opcodes. `emit` therefore builds `Expr::Const { SBoolean, Boolean(_) }`
//! with no True/False special-casing; the M4 segregation transform (the
//! D-C1 flip point — M3 deliberately emits non-segregated trees) will turn
//! inline constants into table entries. The captures also pin the
//! default P2S tree header `0x10` (version 0 + constant-segregation bit).
//! (Note: the Task-1 review notes mislabeled the `sigmaProp(HEIGHT > 100)`
//! bytes as the `sigmaProp(true)` reply; the three-way capture above
//! disambiguates.)
//!
//! # Nodes `ergo-ser` cannot represent (deviation-ledger entries in lib.rs)
//!
//! - `CreateAvlTree` — Scala 6.0.2 registers `CreateAvlTreeSerializer` at
//!   opcode `0xB6` with four value args (`ValueSerializer.scala:54`,
//!   `trees.scala:88` `opCode = OpCodes.AvlTreeCode`), but ergo-ser's
//!   `opcode_pattern` parses `0xB6` as `Zero` ("AvlTreeCode (deprecated)"),
//!   so an emitted `Four @ 0xB6` node would not re-parse. Resolved toward
//!   ergo-ser per the M3 ground rule: [`EmitError::UnsupportedNode`].
//! - `ZKProofBlock` — no serializer registration in Scala 6.0.2's
//!   `ValueSerializer` and no byte in `opcode_pattern`: the Scala compiler
//!   itself cannot serialize a `ZKProofBlock` (it is erased by `ZKProving`
//!   before serialization, a prover-side transform out of compiler scope).
//! - `ConstPayload::SigmaProp(String)` — an opaque env-injected sigma
//!   proposition label carries no curve bytes to serialize.
//!
//! `None: Option[T]` never becomes a `Payload::NoneValue` op node: dispatch
//! byte `0xDF` is not parser-accepted (recon §1); a `None` literal must flow
//! through the constant path (`SOption` type + `0x00` discriminant). No
//! `ConstPayload` variant produces one; `Global.none[T]()` lowers to a
//! `PropertyCall` (106, 10) with an explicit type arg.

use std::collections::HashMap;

use ergo_primitives::group_element::GroupElement;
use ergo_ser::opcode::{method_explicit_type_args_count, Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

use crate::stype::SType;
use crate::typed::{node_tpe, ConstPayload, MethodRef, TypedExpr};
use crate::typer::methods::wire_method;
use crate::typer::unify::numeric_index;

/// Emission failure. `UnresolvedType`/`UnsupportedNode`/`InvalidShape` are
/// COMPILER bug surfaces, not user errors: the typer guarantees the
/// invariants those errors report (no `NoType` in output, no pre-typed
/// nodes, payloads matching node types), so the variants are typed and
/// spanless. `GraphBuildingReject` is the exception — a USER-reachable
/// verdict-parity gate (see its docs).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    /// A compiler-internal type (`NoType`, `STypeApply`) reached `map_type`.
    /// The typer must eliminate both before emit (recon-ergoser-ir OQ2).
    #[error("unresolved compiler-internal type reached emit: {0}")]
    UnresolvedType(String),
    /// A typed node with no opcode-IR lowering: a node `ergo-ser` cannot
    /// represent (see the module docs), or a residual `Select`/`Apply`/
    /// `MethodCall` outside the lowering catalog — the message names the
    /// offending method/field/owner so the Task-11 adversarial pass can hunt
    /// the gap.
    #[error("node not supported by emit: {0}")]
    UnsupportedNode(String),
    /// A structurally invalid shape that must never reach emit (pre-typed
    /// nodes, payload/type mismatches, wire-arity violations, unbound
    /// identifiers).
    #[error("invalid shape reached emit: {0}")]
    InvalidShape(&'static str),
    /// A construct the TYPER accepts (M2 parity holds on both sides) but the
    /// FULL Scala compiler REJECTS at its GraphBuilding/IR stage — no
    /// lowering exists for the node, or compile-time constant evaluation
    /// throws. Mirroring the verdict keeps `compile()` from handing out tree
    /// bytes + addresses the reference compiler can never produce (several
    /// such trees are unspendable — the funds-stranding surface the
    /// oracle-parity bar exists for). `class` is the ORACLE's exception
    /// class, verbatim, for reject-class parity grading (lib.rs D-C5).
    #[error("rejected for Scala GraphBuilding parity ({class}): {what}")]
    GraphBuildingReject {
        /// The Scala exception class the oracle reports for this reject.
        class: &'static str,
        /// What was rejected (names the operator/method/constant family).
        what: String,
    },
}

/// Lower a typed expression to the `ergo-ser` opcode IR.
///
/// Fixed-arity forms map 1:1 onto `Payload::Zero/One/Two/Three/Four` and the
/// named-field payloads per the `opcode_pattern` table; constants map through
/// [`map_const`]; binding forms allocate ids through a fresh [`Scope`].
pub fn emit(expr: &TypedExpr) -> Result<Expr, EmitError> {
    Scope::new().emit(expr)
}

/// `Ok(Expr::Op { .. })` shorthand shared by every opcode arm.
fn node(opcode: u8, payload: Payload) -> Result<Expr, EmitError> {
    Ok(Expr::Op(IrNode { opcode, payload }))
}

/// Surface symbol of a `TypedExpr::BitOp` opcode byte (typed.rs `BIT_*`
/// constants) — for the GraphBuilding-reject message only.
fn bit_op_symbol(opcode: i8) -> &'static str {
    use crate::typed::{
        BIT_AND, BIT_OR, BIT_SHIFT_LEFT, BIT_SHIFT_RIGHT, BIT_SHIFT_RIGHT_ZEROED, BIT_XOR,
    };
    match opcode {
        BIT_OR => "|",
        BIT_AND => "&",
        BIT_XOR => "^",
        BIT_SHIFT_LEFT => "<<",
        BIT_SHIFT_RIGHT => ">>",
        BIT_SHIFT_RIGHT_ZEROED => ">>>",
        _ => "?",
    }
}

/// Wrap an already-emitted IR expression in `Upcast` (0x7E) to `tpe`.
fn upcast_ir(input: Expr, tpe: SigmaType) -> Expr {
    Expr::Op(IrNode {
        opcode: 0x7E,
        payload: Payload::NumericCast {
            input: Box::new(input),
            tpe,
        },
    })
}

/// Binding scope for the emission walk.
///
/// `bindings` is a stack of frames (one per `Block`/`Lambda`); a name
/// resolves innermost-first, so lambda args shadow enclosing `val`s exactly
/// like the typer's `lambdaEnv = env ++ args` overwrite
/// (SigmaTyper.scala:128). Each entry carries the binding's wire type for
/// scope introspection; only the id goes on the wire (`ValUse` is untyped,
/// `FuncValue` args are typed at the definition site).
///
/// # Id allocation (Scala TreeBuilding scheme, collision-free relaxation)
///
/// `next_id` is a single monotonic counter starting at 1. A `ValDef` takes
/// the next id AFTER its rhs is emitted (Scala: `val rhs = buildValue(...,
/// curId, ...); curId += 1; ValDef(curId, ...)` — TreeBuilding.scala:511-513);
/// a lambda arg takes the enclosing scope's next id and body ValDefs continue
/// past it (`varId = defId + 1`, body from `varId + 1` —
/// TreeBuilding.scala:186-191, recon-scala-pipeline §6). Scala additionally
/// REUSES ids across disjoint scopes (each `processAstGraph` restarts its
/// `curId` from the enclosing `defId`) and skips ids for non-materialized
/// graph nodes (CSE); the monotonic counter never reuses, which is the
/// M3-sanctioned relaxation — the milestone gates on validity and
/// collision-freedom only, exact id parity is M5 (ValDef sharing).
struct Scope {
    bindings: Vec<HashMap<String, (u32, SigmaType)>>,
    next_id: u32,
}

impl Scope {
    fn new() -> Self {
        Scope {
            bindings: vec![HashMap::new()],
            next_id: 1,
        }
    }

    /// Resolve `name` innermost-frame-first to its binding id.
    fn lookup(&self, name: &str) -> Option<u32> {
        self.bindings
            .iter()
            .rev()
            .find_map(|frame| frame.get(name).map(|(id, _)| *id))
    }

    /// Take the next binding id and record `name` in the innermost frame.
    fn bind(&mut self, name: &str, tpe: SigmaType) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.bindings
            .last_mut()
            .expect("Scope always holds at least the root frame")
            .insert(name.to_string(), (id, tpe));
        id
    }

    // ── fixed-positional payload builders ────────────────────────────────

    fn one(&mut self, a: &TypedExpr) -> Result<Payload, EmitError> {
        Ok(Payload::One(Box::new(self.emit(a)?)))
    }

    fn two(&mut self, a: &TypedExpr, b: &TypedExpr) -> Result<Payload, EmitError> {
        Ok(Payload::Two(
            Box::new(self.emit(a)?),
            Box::new(self.emit(b)?),
        ))
    }

    fn three(&mut self, a: &TypedExpr, b: &TypedExpr, c: &TypedExpr) -> Result<Payload, EmitError> {
        Ok(Payload::Three(
            Box::new(self.emit(a)?),
            Box::new(self.emit(b)?),
            Box::new(self.emit(c)?),
        ))
    }

    fn four(
        &mut self,
        a: &TypedExpr,
        b: &TypedExpr,
        c: &TypedExpr,
        d: &TypedExpr,
    ) -> Result<Payload, EmitError> {
        Ok(Payload::Four(
            Box::new(self.emit(a)?),
            Box::new(self.emit(b)?),
            Box::new(self.emit(c)?),
            Box::new(self.emit(d)?),
        ))
    }

    fn items_of(&mut self, items: &[TypedExpr]) -> Result<Vec<Expr>, EmitError> {
        items.iter().map(|it| self.emit(it)).collect()
    }

    /// `Two` payload with mixed-width normalization: when BOTH operands are
    /// numeric and their ladder widths differ, the narrower side is wrapped
    /// in `Upcast(_, wider)` — the `TransformingSigmaBuilder.applyUpcast`
    /// rule (SigmaBuilder.scala:664-676, applied by `arithOp` :700-705 and
    /// `comparisonOp`/`equalityOp` :679-697). The frontend already inserts
    /// these `Upcast` nodes at typer time (unify.rs `apply_upcast`, mirroring
    /// the same builder), so on frontend trees this is a no-op; it normalizes
    /// hand-built trees defensively. (`BitOp` never reaches a payload builder
    /// — its emit arm rejects for GraphBuilding verdict parity.)
    fn two_upcast(&mut self, l: &TypedExpr, r: &TypedExpr) -> Result<Payload, EmitError> {
        let mut le = self.emit(l)?;
        let mut re = self.emit(r)?;
        if let (Some(li), Some(ri)) = (numeric_index(node_tpe(l)), numeric_index(node_tpe(r))) {
            match li.cmp(&ri) {
                std::cmp::Ordering::Less => le = upcast_ir(le, map_type(node_tpe(r))?),
                std::cmp::Ordering::Greater => re = upcast_ir(re, map_type(node_tpe(l))?),
                std::cmp::Ordering::Equal => {}
            }
        }
        Ok(Payload::Two(Box::new(le), Box::new(re)))
    }

    /// Emit a collection/tuple index expression, wrapping a narrower-than-Int
    /// numeric index in `Upcast(_, SInt)` — `typedIndex.upcastTo(SInt)`,
    /// SigmaTyper.scala:265-288. The frontend inserts this at typer time
    /// (assign.rs `assign_collection_index`/`assign_tuple_index`), so this is
    /// defensive normalization for hand-built trees. A WIDER index (Long+) is
    /// left untouched: `upcastTo(SInt)` would be a downcast, which the Scala
    /// typer rejects before this point.
    fn emit_index(&mut self, index: &TypedExpr) -> Result<Expr, EmitError> {
        let e = self.emit(index)?;
        Ok(match numeric_index(node_tpe(index)) {
            Some(i) if i < numeric_index(&SType::SInt).expect("SInt is numeric") => {
                upcast_ir(e, SigmaType::SInt)
            }
            _ => e,
        })
    }

    fn emit(&mut self, expr: &TypedExpr) -> Result<Expr, EmitError> {
        use TypedExpr as T;

        match expr {
            // ── context singletons: leaf opcodes, Zero payload ────────────────
            T::Height { .. } => node(0xA3, Payload::Zero),
            T::Inputs { .. } => node(0xA4, Payload::Zero),
            T::Outputs { .. } => node(0xA5, Payload::Zero),
            T::Self_ { .. } => node(0xA7, Payload::Zero),
            T::MinerPubkey { .. } => node(0xAC, Payload::Zero),
            T::Context { .. } => node(0xFE, Payload::Zero),
            T::Global { .. } => node(0xDD, Payload::Zero),

            // ── M4 Task 8 (recon-transforms.md §9, D-C7 singleton bullet):
            //    bare `LastBlockUtxoRootHash` and bare/dotted `groupGenerator`
            //    are NOT `IsContextProperty`-recognized primitives on the
            //    Scala side (unlike Height/Inputs/Outputs/Self/MinerPubkey) —
            //    buildTree's fallback re-materializes both as PropertyCalls.
            //    Oracle-confirmed 2026-07-07 (×2 runs each,
            //    `ORACLE_TREE_VERSION=3`): `LastBlockUtxoRootHash.digest.size`
            //    and `CONTEXT.LastBlockUtxoRootHash.digest.size` both reply
            //    `…db6509fe…` (`PropertyCall(101, 9)` over a bare `Context`
            //    receiver, opcode 0xFE) — so this arm alone closes the gap
            //    without touching the (already-correct) dotted-form typer
            //    path, which never constructs this TypedExpr variant.
            //    `groupGenerator == groupGenerator` and
            //    `Global.groupGenerator.getEncoded.size`/bare
            //    `groupGenerator.getEncoded.size` both reply
            //    `…db6a01dd…` (`PropertyCall(106, 1)` over a bare `Global`
            //    receiver, opcode 0xDD) for BOTH forms — unlike
            //    LastBlockUtxoRootHash, our typer routes bare `groupGenerator`
            //    (`process_global_method`) AND dotted `Global.groupGenerator`
            //    (`lower_method`) to the SAME `TypedExpr::GroupGenerator`
            //    node, so this single arm fixes both call sites at once.
            T::LastBlockUtxoRootHash { .. } => self.emit_method_call(
                &TypedExpr::Context {
                    tpe: SType::SContext,
                },
                &MethodRef {
                    owner: "Context".to_string(),
                    name: "LastBlockUtxoRootHash".to_string(),
                },
                &[],
                &[],
            ),
            T::GroupGenerator { .. } => self.emit_method_call(
                &TypedExpr::Global {
                    tpe: SType::SGlobal,
                },
                &MethodRef {
                    owner: "SigmaDslBuilder".to_string(),
                    name: "groupGenerator".to_string(),
                },
                &[],
                &[],
            ),

            // ── constants: always the constant path (incl. Booleans — see the
            //    module docs; never the 0x7F/0x80 True/False opcodes) ──────────
            T::Constant { value, tpe } => {
                let (tpe, val) = map_const(value, tpe)?;
                Ok(Expr::Const { tpe, val })
            }

            // ── relations (Relation2 pattern; the writer auto-compacts a
            //    bool-constant pair to the 0x85 form). Mixed-width numeric
            //    operands are Upcast-normalized (two_upcast docs) ──────────────
            T::GT { left, right, .. } => node(0x91, self.two_upcast(left, right)?),
            T::GE { left, right, .. } => node(0x92, self.two_upcast(left, right)?),
            T::LT { left, right, .. } => node(0x8F, self.two_upcast(left, right)?),
            T::LE { left, right, .. } => node(0x90, self.two_upcast(left, right)?),
            T::EQ { left, right, .. } => node(0x93, self.two_upcast(left, right)?),
            T::NEQ { left, right, .. } => node(0x94, self.two_upcast(left, right)?),

            // ── arithmetic: the typer stores Scala's opcode byte (typed.rs
            //    ARITH_* constants); passthrough as u8. Mixed widths are
            //    Upcast-normalized (arithOp → applyUpcast,
            //    SigmaBuilder.scala:700-705) ────────────────────────────────────
            T::ArithOp {
                left,
                right,
                opcode,
                ..
            } => node(*opcode as u8, self.two_upcast(left, right)?),

            // ── bitwise: REJECTED for full-compiler verdict parity — Scala
            //    6.0.2 GraphBuilding has NO lowering arm for `BitOp`, so the
            //    reference compiler rejects EVERY `|`/`&`/`^`(numeric)/`<<`/
            //    `>>`/`>>>` expression at every width (oracle:
            //    `cc sigmaProp((1 | 2) == 3)` → `REJECT 1:12
            //    GraphBuildingException`, 19-probe family, compile_seed.json;
            //    the TYPER accepts on both sides — golden_seed `1 | 2L`/`5 <<
            //    1` records stay valid). Opcodes 0xF2-0xF8 are therefore
            //    unreachable from `compile()`, exactly as from Scala's.
            //    Boolean `^` is a DIFFERENT node (`BinXor`, accepted below).
            T::BitOp { opcode, .. } => Err(EmitError::GraphBuildingReject {
                class: "GraphBuildingException",
                what: format!(
                    "bit operator '{}' has no GraphBuilding lowering in Scala 6.0.2",
                    bit_op_symbol(*opcode),
                ),
            }),

            // ── boolean binary (lazy) + unary ─────────────────────────────────
            T::BinAnd { left, right, .. } => node(0xED, self.two(left, right)?),
            T::BinOr { left, right, .. } => node(0xEC, self.two(left, right)?),
            T::BinXor { left, right, .. } => node(0xF4, self.two(left, right)?),
            T::LogicalNot { input, .. } => node(0xEF, self.one(input)?),
            T::Negation { input, .. } => node(0xF0, self.one(input)?),
            // Same GraphBuilding gap as `BitOp`: no lowering for
            // `BitInversion` — Scala compile-rejects every `~x` (oracle:
            // `cc sigmaProp((~1) == -2)` → `REJECT 1:13
            // GraphBuildingException`); opcode 0xF1 never leaves compile().
            T::BitInversion { .. } => Err(EmitError::GraphBuildingReject {
                class: "GraphBuildingException",
                what: "bit inversion '~' has no GraphBuilding lowering in Scala 6.0.2".into(),
            }),

            // ── control / structure ───────────────────────────────────────────
            T::If {
                condition,
                true_branch,
                false_branch,
                ..
            } => node(0x95, self.three(condition, true_branch, false_branch)?),
            T::Tuple { items, .. } => {
                // Scala STuple is 2..=255 items; the ergo-ser writer asserts
                // (panics) past 255 (write.rs Tuple arm), so guard recoverably.
                if !(2..=255).contains(&items.len()) {
                    return Err(EmitError::InvalidShape(
                        "Tuple arity outside the Scala wire range 2..=255",
                    ));
                }
                node(
                    0x86,
                    Payload::Tuple {
                        items: self.items_of(items)?,
                    },
                )
            }
            T::SelectField {
                input, field_index, ..
            } => node(
                0x8C,
                Payload::SelectField {
                    input: Box::new(self.emit(input)?),
                    // 1-based already (transformers.scala:291 fieldIndex).
                    field_idx: *field_index as u8,
                },
            ),
            T::ConcreteCollection {
                items, elem_type, ..
            } => node(
                0x83,
                Payload::ConcreteCollection {
                    elem_type: map_type(elem_type)?,
                    items: self.items_of(items)?,
                },
            ),

            // ── numeric casts ─────────────────────────────────────────────────
            T::Upcast { input, tpe } => node(
                0x7E,
                Payload::NumericCast {
                    input: Box::new(self.emit(input)?),
                    tpe: map_type(tpe)?,
                },
            ),
            T::Downcast { input, tpe } => node(
                0x7D,
                Payload::NumericCast {
                    input: Box::new(self.emit(input)?),
                    tpe: map_type(tpe)?,
                },
            ),

            // ── collection transformers ───────────────────────────────────────
            T::MapCollection { input, mapper, .. } => node(0xAD, self.two(input, mapper)?),
            T::Exists {
                input, condition, ..
            } => node(0xAE, self.two(input, condition)?),
            T::ForAll {
                input, condition, ..
            } => node(0xAF, self.two(input, condition)?),
            T::Fold {
                input,
                zero,
                fold_op,
                ..
            } => node(0xB0, self.three(input, zero, fold_op)?),
            T::Filter {
                input, condition, ..
            } => node(0xB5, self.two(input, condition)?),
            T::Slice {
                input, from, until, ..
            } => node(0xB4, self.three(input, from, until)?),
            T::Append { input, col2, .. } => node(0xB3, self.two(input, col2)?),
            T::SizeOf { input, .. } => node(0xB1, self.one(input)?),
            T::ByIndex {
                input,
                index,
                default,
                ..
            } => node(
                0xB2,
                Payload::ByIndex {
                    input: Box::new(self.emit(input)?),
                    index: Box::new(self.emit_index(index)?),
                    default: default
                        .as_deref()
                        .map(|d| self.emit(d).map(Box::new))
                        .transpose()?,
                },
            ),

            // ── collection-boolean gates: ONE arg (the collection expr) ───────
            T::AND { input, .. } => node(0x96, self.one(input)?),
            T::OR { input, .. } => node(0x97, self.one(input)?),
            T::XorOf { input, .. } => {
                // Verdict parity with the FULL Scala compiler (Task-10 gate):
                // the reference typer accepts `xorOf(Coll(sigmaProp(..)))` as
                // `XorOf(ConcreteCollection[SigmaProp])` — the Bool↔SigmaProp
                // unifier admits the elements WITHOUT the per-element
                // `SigmaPropIsProven` coercion that `allOf`/`anyOf` get
                // (golden_seed §14) — but GraphBuilding then force-casts the
                // input to `Coll[Boolean]` (`asRep[Coll[Boolean]]` /
                // `sigmaDslBuilder.xorOf`, GraphBuilding.scala:855-862) and
                // dies with an `AssertionError`, so `compiler.compile` REJECTS
                // every such source (oracle: `cc xorOf(Coll(sigmaProp(true)))`
                // → `REJECT 0:0 AssertionError`, compile_seed.json). Mirror
                // the verdict: a SigmaProp-element XorOf never reaches the
                // wire. (0xFF's wire/eval semantics also require booleans.)
                if matches!(node_tpe(input), SType::SColl(el) if **el == SType::SSigmaProp) {
                    return Err(EmitError::UnsupportedNode(
                        "XorOf over Coll[SigmaProp] (Scala GraphBuilding rejects: \
                         xorOf input must be Coll[Boolean], GraphBuilding.scala:855-862)"
                            .into(),
                    ));
                }
                node(0xFF, self.one(input)?)
            }

            // ── sigma combinators ─────────────────────────────────────────────
            T::AtLeast { bound, input, .. } => node(0x98, self.two(bound, input)?),
            T::SigmaAnd { items, .. } => node(
                0xEA,
                Payload::SigmaCollection {
                    items: self.items_of(items)?,
                },
            ),
            T::SigmaOr { items, .. } => node(
                0xEB,
                Payload::SigmaCollection {
                    items: self.items_of(items)?,
                },
            ),

            // ── sigma / boolean coercions ─────────────────────────────────────
            T::BoolToSigmaProp { value, .. } => node(0xD1, self.one(value)?),
            T::SigmaPropIsProven { input, .. } => node(0xCF, self.one(input)?),
            T::SigmaPropBytes { input, .. } => node(0xD0, self.one(input)?),

            // ── crypto primitives ─────────────────────────────────────────────
            T::CreateProveDlog { value, .. } => node(0xCD, self.one(value)?),
            T::CreateProveDHTuple { gv, hv, uv, vv, .. } => node(0xCE, self.four(gv, hv, uv, vv)?),
            T::CalcBlake2b256 { input, .. } => node(0xCB, self.one(input)?),
            T::CalcSha256 { input, .. } => node(0xCC, self.one(input)?),

            // ── byte conversions ──────────────────────────────────────────────
            T::ByteArrayToBigInt { input, .. } => node(0x7B, self.one(input)?),
            T::ByteArrayToLong { input, .. } => node(0x7C, self.one(input)?),
            T::LongToByteArray { input, .. } => node(0x7A, self.one(input)?),

            // ── group ops ─────────────────────────────────────────────────────
            T::DecodePoint { input, .. } => node(0xEE, self.one(input)?),
            T::MultiplyGroup { left, right, .. } => node(0xA0, self.two(left, right)?),
            T::Exponentiate { left, right, .. } => node(0x9F, self.two(left, right)?),
            T::Xor { left, right, .. } => node(0x9B, self.two(left, right)?),

            // ── option ops ────────────────────────────────────────────────────
            T::OptionGet { input, .. } => node(0xE4, self.one(input)?),
            T::OptionGetOrElse { input, default, .. } => node(0xE5, self.two(input, default)?),
            T::OptionIsDefined { input, .. } => node(0xE6, self.one(input)?),

            // ── context access ────────────────────────────────────────────────
            T::GetVar { var_id, tpe } => {
                // Node type is SOption(V) (transformers.scala:576); the wire
                // carries the INNER V (Scala GetVarSerializer writes
                // `tpe.elemType`; ergo-ser's parse arm reads one bare type).
                let SType::SOption(inner) = tpe else {
                    return Err(EmitError::InvalidShape("GetVar node type must be SOption"));
                };
                node(
                    0xE3,
                    Payload::GetVar {
                        var_id: *var_id as u8,
                        tpe: map_type(inner)?,
                    },
                )
            }
            T::DeserializeContext { id, tpe } => node(
                0xD4,
                Payload::DeserializeContext {
                    id: *id as u8,
                    tpe: map_type(tpe)?,
                },
            ),
            T::DeserializeRegister { reg, tpe, default } => node(
                0xD5,
                Payload::DeserializeRegister {
                    reg_id: *reg as u8,
                    tpe: map_type(tpe)?,
                    default: default
                        .as_deref()
                        .map(|d| self.emit(d).map(Box::new))
                        .transpose()?,
                },
            ),

            // ── misc fixed-arity ──────────────────────────────────────────────
            T::SubstConstants {
                script_bytes,
                positions,
                new_values,
                ..
            } => node(0x74, self.three(script_bytes, positions, new_values)?),
            T::TreeLookup {
                tree, key, proof, ..
            } => node(0xB7, self.three(tree, key, proof)?),

            // ── nodes ergo-ser cannot represent (module docs + lib.rs ledger) ─
            T::CreateAvlTree { .. } => Err(EmitError::UnsupportedNode("CreateAvlTree".to_string())),
            T::ZKProofBlock { .. } => Err(EmitError::UnsupportedNode("ZKProofBlock".to_string())),

            // ── binding forms ─────────────────────────────────────────────────
            T::Block {
                bindings, result, ..
            } => self.emit_block(bindings, result),
            // A ValNode can only appear inside Block.bindings (grammar: a bare
            // top-level `val x = 1` is a PARSE reject — golden_seed §25,
            // oracle `REJECT 1:1 ParserException`); reaching one here is a
            // pipeline bug.
            T::ValNode { .. } => Err(EmitError::InvalidShape(
                "ValNode outside Block.bindings must not reach emit",
            )),
            T::Ident { name, .. } => match self.lookup(name) {
                Some(id) => node(0x72, Payload::ValUse { id }),
                // The binder substitutes env values as Constants and the typer
                // only emits Ident for in-scope val/lambda-arg names, so an
                // unbound Ident is a pipeline bug.
                None => Err(EmitError::InvalidShape(
                    "Ident not bound to any enclosing ValDef or lambda arg",
                )),
            },
            T::Lambda {
                tpe_params,
                args,
                body,
                ..
            } => self.emit_lambda(tpe_params, args, body.as_deref()),
            T::Apply { func, args, .. } => self.emit_apply(func, args),
            T::Select {
                obj,
                field,
                res_type,
                tpe,
            } => self.emit_select(obj, field, res_type.as_ref(), tpe),
            T::MethodCall {
                obj,
                method,
                args,
                type_subst,
                ..
            } => self.emit_method_call(obj, method, args, type_subst),

            // ── pre-typed nodes: must never reach emit ────────────────────────
            T::ApplyTypes { .. } => Err(EmitError::InvalidShape(
                "ApplyTypes is pre-typed-only and must not reach emit",
            )),
            T::MethodCallLike { .. } => Err(EmitError::InvalidShape(
                "MethodCallLike is pre-typed-only and must not reach emit",
            )),
        }
    }

    /// `Block(bindings, result)` → `BlockValue(ValDef*, result)` @ 0xD8.
    ///
    /// Each source `val` materializes one `ValDef` (0xD6) — M3 does no CSE, so
    /// the mapping is 1:1, unlike Scala's shared-node materialization
    /// (TreeBuilding.scala:498-516). Ordering matches Scala: the rhs is
    /// emitted BEFORE the ValDef id is taken (`val rhs = buildValue(...,
    /// curId, ...); curId += 1` — :511-513), so a lambda inside the rhs takes
    /// the lower id. The name binds only AFTER its rhs (no self-reference,
    /// mirroring the typer's sequential env build, SigmaTyper.scala:56-63).
    /// An empty-bindings Block collapses to the bare result — Scala only
    /// wraps `BlockValue` when `valdefs.nonEmpty` (TreeBuilding.scala:520-529).
    fn emit_block(
        &mut self,
        bindings: &[TypedExpr],
        result: &TypedExpr,
    ) -> Result<Expr, EmitError> {
        self.bindings.push(HashMap::new());
        let mut items = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let TypedExpr::ValNode {
                name, body, tpe, ..
            } = binding
            else {
                return Err(EmitError::InvalidShape("Block binding is not a ValNode"));
            };
            let rhs = self.emit(body)?;
            let id = self.bind(name, map_type(tpe)?);
            items.push(Expr::Op(IrNode {
                opcode: 0xD6,
                // tpe is never on the ValDef wire: Scala's reader always has a
                // constantStore, so the type branch is dead and ergo-ser's
                // parse arm pins `tpe: None` (parse.rs ValDef arm).
                payload: Payload::ValDef {
                    id,
                    tpe: None,
                    rhs: Box::new(rhs),
                },
            }));
        }
        let result = self.emit(result)?;
        self.bindings.pop();
        if items.is_empty() {
            Ok(result)
        } else {
            node(
                0xD8,
                Payload::BlockValue {
                    items,
                    result: Box::new(result),
                },
            )
        }
    }

    /// `Lambda(args, body)` → `FuncValue(Vector((argId, argType)), body)` @
    /// 0xD9. Args MUST carry types — they define the function signature and
    /// the ergo-ser writer panics on a type-less arg (write.rs FuncValue arm,
    /// recon-ergoser-ir §1).
    fn emit_lambda(
        &mut self,
        tpe_params: &[crate::typed::STypeParam],
        args: &[(String, SType)],
        body: Option<&TypedExpr>,
    ) -> Result<Expr, EmitError> {
        // The binder enforces `!(tpeParams.nonEmpty && body.nonEmpty)` and the
        // wire FuncValue has no type-param block: both shapes are pipeline bugs.
        if !tpe_params.is_empty() {
            return Err(EmitError::InvalidShape(
                "Lambda with type parameters cannot be serialized as FuncValue",
            ));
        }
        let Some(body) = body else {
            return Err(EmitError::InvalidShape(
                "Lambda with no body cannot be serialized as FuncValue",
            ));
        };
        self.bindings.push(HashMap::new());
        let mut wire_args = Vec::with_capacity(args.len());
        for (name, tpe) in args {
            let wire_tpe = map_type(tpe)?;
            let id = self.bind(name, wire_tpe.clone());
            wire_args.push((id, Some(wire_tpe)));
        }
        let body = self.emit(body)?;
        self.bindings.pop();
        node(
            0xD9,
            Payload::FuncValue {
                args: wire_args,
                body: Box::new(body),
            },
        )
    }

    /// Residual `Apply` lowering.
    ///
    /// - function-typed callee (val-bound lambda `ValUse`, inline `Lambda`)
    ///   → `FuncApply` @ 0xDA (TreeBuilding `Def(Apply(...)) => mkApply`,
    ///   TreeBuilding.scala:192-194);
    /// - collection-typed callee → `ByIndex` with the index Upcast-ed to
    ///   `SInt` when narrower (SigmaTyper.scala:261-277; the frontend lowers
    ///   `coll(i)` at typer time, so this arm is defensive normalization);
    /// - anything else → [`EmitError::UnsupportedNode`] naming the callee.
    fn emit_apply(&mut self, func: &TypedExpr, args: &[TypedExpr]) -> Result<Expr, EmitError> {
        match node_tpe(func) {
            SType::SFunc { .. } => {
                let func = self.emit(func)?;
                let args = self.items_of(args)?;
                node(
                    0xDA,
                    Payload::FuncApply {
                        func: Box::new(func),
                        args,
                    },
                )
            }
            SType::SColl(_) => {
                let [index] = args else {
                    return Err(EmitError::InvalidShape(
                        "collection Apply expects exactly one index argument",
                    ));
                };
                let input = self.emit(func)?;
                let index = self.emit_index(index)?;
                node(
                    0xB2,
                    Payload::ByIndex {
                        input: Box::new(input),
                        index: Box::new(index),
                        default: None,
                    },
                )
            }
            other => Err(EmitError::UnsupportedNode(format!(
                "Apply on a callee of type {other:?}"
            ))),
        }
    }

    /// Residual `Select` lowering — the no-irBuilder methods the typer leaves
    /// as `Select` (methods.rs `v5s` entries), lowered exactly where Scala's
    /// GraphBuilding lowers them:
    ///
    /// - numeric casts `toByte`..`toBigInt` → same-type unwrap / `Downcast` /
    ///   `Upcast` by ladder order (GraphBuilding.scala:555-563);
    /// - `.size` on a collection-like receiver → `SizeOf` (:520-525);
    /// - `SigmaProp.isProven`/`.propBytes` → dedicated nodes (:527-533);
    /// - Box properties → the `Extract*` family (:541-549) and
    ///   `R0`..`R9[T]` → `ExtractRegisterAs` (:536-539) with the INNER type
    ///   on the wire (`putType(obj.tpe.elemType)`,
    ///   ExtractRegisterAsSerializer.scala serialize);
    /// - tuple `_i` → `SelectField` (:551-553);
    /// - anything else → [`EmitError::UnsupportedNode`] naming the field.
    fn emit_select(
        &mut self,
        obj: &TypedExpr,
        field: &str,
        res_type: Option<&SType>,
        tpe: &SType,
    ) -> Result<Expr, EmitError> {
        let obj_tpe = node_tpe(obj);

        // Numeric casts (GraphBuilding.scala:555-563): the match requires a
        // numeric receiver and a numeric result (resType when the typer set
        // one, else the node type — §1.5 sets both identically for casts).
        if matches!(
            field,
            "toByte" | "toShort" | "toInt" | "toLong" | "toBigInt"
        ) {
            let target = res_type.unwrap_or(tpe);
            if let (Some(src), Some(dst)) = (numeric_index(obj_tpe), numeric_index(target)) {
                let input = self.emit(obj)?;
                return match src.cmp(&dst) {
                    // Same type: `eval(numValue)` — the cast disappears.
                    std::cmp::Ordering::Equal => Ok(input),
                    // `(numValue.tpe max tRes) == numValue.tpe` → Downcast.
                    std::cmp::Ordering::Greater => node(
                        0x7D,
                        Payload::NumericCast {
                            input: Box::new(input),
                            tpe: map_type(target)?,
                        },
                    ),
                    std::cmp::Ordering::Less => node(
                        0x7E,
                        Payload::NumericCast {
                            input: Box::new(input),
                            tpe: map_type(target)?,
                        },
                    ),
                };
            }
        }

        // `col.size` → SizeOf (GraphBuilding.scala:520-525; STuple extends
        // SCollection[SAny], SType.scala:822-825, so tuples are
        // collection-like).
        if field == "size" && matches!(obj_tpe, SType::SColl(_) | SType::STuple(_)) {
            return node(0xB1, self.one(obj)?);
        }

        if matches!(obj_tpe, SType::SSigmaProp) {
            match field {
                "isProven" => return node(0xCF, self.one(obj)?),
                "propBytes" => return node(0xD0, self.one(obj)?),
                _ => {}
            }
        }

        if matches!(obj_tpe, SType::SBox) {
            match field {
                "value" => return node(0xC1, self.one(obj)?),
                "propositionBytes" => return node(0xC2, self.one(obj)?),
                "bytes" => return node(0xC3, self.one(obj)?),
                "bytesWithoutRef" => return node(0xC4, self.one(obj)?),
                "id" => return node(0xC5, self.one(obj)?),
                "creationInfo" => return node(0xC7, self.one(obj)?),
                _ => {}
            }
            // `box.R$i[T]` with a resolved Option result → ExtractRegisterAs.
            // A bare `SELF.R4` (no `[T]`) keeps its polymorphic SFunc type and
            // falls through to the UnsupportedNode below, matching Scala's
            // graph-build error for an unresolved register read.
            if let Some(reg_digit) = field.strip_prefix('R') {
                if let (Ok(reg_id), Some(SType::SOption(inner))) =
                    (reg_digit.parse::<u8>(), res_type)
                {
                    if reg_id <= 9 {
                        return node(
                            0xC6,
                            Payload::ExtractRegisterAs {
                                input: Box::new(self.emit(obj)?),
                                reg_id,
                                tpe: map_type(inner)?,
                            },
                        );
                    }
                }
            }
        }

        // Tuple component `_i` → SelectField, 1-based (GraphBuilding.scala:
        // 551-553 `fn.substring(1).toByte`).
        if let SType::STuple(items) = obj_tpe {
            if let Some(idx_str) = field.strip_prefix('_') {
                if let Ok(idx) = idx_str.parse::<u8>() {
                    if idx == 0 || usize::from(idx) > items.len() {
                        return Err(EmitError::InvalidShape(
                            "tuple field index outside the tuple arity",
                        ));
                    }
                    return node(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(self.emit(obj)?),
                            field_idx: idx,
                        },
                    );
                }
            }
        }

        Err(EmitError::UnsupportedNode(format!(
            "Select '{field}' on a receiver of type {obj_tpe:?}"
        )))
    }

    /// `MethodCall`/`PropertyCall` wire dispatch.
    ///
    /// `(type_id, method_id)` resolve through the SAME tables the typer used
    /// (`methods::wire_method`, keyed on the version-aware owner name —
    /// D-T10). Opcode selection is Scala's `MethodCall.companion`:
    /// `if (args.isEmpty) PropertyCall else MethodCall` (values.scala:1322) —
    /// 0xDB writes no arg block, 0xDC writes count + args. The v6 explicit
    /// type-args block (both opcodes) carries the `type_subst` bindings in
    /// the method's DECLARED type-param order, cross-checked against
    /// ergo-ser's per-pair count ([`method_explicit_type_args_count`],
    /// opcode/types.rs:573-589).
    fn emit_method_call(
        &mut self,
        obj: &TypedExpr,
        method: &crate::typed::MethodRef,
        args: &[TypedExpr],
        type_subst: &[(String, SType)],
    ) -> Result<Expr, EmitError> {
        // GraphBuilding reject gates (lib.rs D-C5) — residual MethodCalls the
        // typer accepts (M2 parity) but the FULL Scala compiler rejects:
        //
        // (a) Shared-SNumericType-container methods (`toBytes`/`toBits`,
        //     D-T10): the owner name "SNumericType" is only ever produced at
        //     `tree_version < 3` (`owner_name_for_method`), where Scala's
        //     GraphBuilding rejects the v6-only method under v5 activation
        //     (oracle, ORACLE_TREE_VERSION=2: `ccs sigmaProp(x.toBytes.size
        //     == 4)` → `REJECT 1:13 GraphBuildingException`, 2026-07-07 ×3
        //     runs). At v3 the owner resolves per-type (`Int`/…): a CONSTANT
        //     receiver folds at gate (d) below (wave 2, lib.rs D-C6), a
        //     non-constant one keeps the residual MethodCall (Err/Err reduce
        //     parity).
        if method.owner == "SNumericType" {
            return Err(EmitError::GraphBuildingReject {
                class: "GraphBuildingException",
                what: format!(
                    "v6-only numeric method '{}' on the shared SNumericType container \
                     (tree_version < 3): Scala GraphBuilding rejects it under v5 activation",
                    method.name,
                ),
            });
        }
        // (b) Postfix residual `size`: a space-form nullary call (`arr1
        //     size`) survives BOTH typers as `MethodCall %SCollection.size`,
        //     but Scala's GraphBuilding has no arm for the wire pair (12,1)
        //     — only the Select path lowers `size` to `SizeOf` — and NO
        //     evaluator accepts the pair (oracle: `ccs sigmaProp((arr1 size)
        //     > 0)` → `REJECT 1:12 GraphBuildingException`; `size` is the
        //     sole nullary custom-irBuilder Coll method, the other postfix
        //     families reject in parity upstream —
        //     adversarial-findings-methodcalls.md F1).
        if method.owner == "SCollection" && method.name == "size" {
            return Err(EmitError::GraphBuildingReject {
                class: "GraphBuildingException",
                what: "residual MethodCall %SCollection.size (postfix `size`): Scala \
                       GraphBuilding only lowers the Select path (SizeOf); wire pair \
                       (12,1) is unevaluable on both sides"
                    .into(),
            });
        }
        // (c) `Box.getReg[T](<literal>)`: Scala lowers a CONST-index getReg
        //     to `ExtractRegisterAs` at GraphBuilding, bounds-checking
        //     `ErgoBox.registers(i)` at compile time (oracle: `cc sigmaProp(
        //     SELF.getReg[Int](-1).isDefined)` → `REJECT 0:0
        //     ArrayIndexOutOfBoundsException`; same for 10 and 100). Out of
        //     range → the wave-1 reject gate; IN RANGE → the wave-2 lowering
        //     (adversarial-findings-methodcalls.md F4): `SELF.getReg[Int](5)`
        //     must emit the SAME bytes as `SELF.R5[Int]` (oracle 2026-07-07
        //     ×3: both reply `1000d1e6c6a70504` — body `…c6a70504`,
        //     ExtractRegisterAs). The wire carries the INNER elem type T
        //     (mirrors the Select `R0`..`R9` arm; ExtractRegisterAsSerializer
        //     writes `tpe.elemType`). Only a LITERAL Int argument lowers — a
        //     dynamic index stays a MethodCall in Scala too (oracle:
        //     `getReg[Int](HEIGHT)` keeps wire pair (99,19) on both sides;
        //     Err/Err reduce parity). Residual (lib.rs D-C6): Scala
        //     const-propagates a val-bound index (`{ val i = 4; …getReg[Int]
        //     (i) }` → `ExtractRegisterAs` reg 4, oracle ×3) — our typed AST
        //     keeps the ValUse, so that form stays a both-accept unevaluable
        //     MethodCall here.
        if method.owner == "Box" && method.name == "getReg" {
            if let Some(TypedExpr::Constant {
                value: crate::typed::ConstPayload::Int(i),
                ..
            }) = args.first()
            {
                if !(0..=9).contains(i) {
                    return Err(EmitError::GraphBuildingReject {
                        class: "ArrayIndexOutOfBoundsException",
                        what: format!(
                            "getReg register index {i} outside 0..=9: Scala lowers the \
                             const-index form to ExtractRegisterAs and bounds-checks it \
                             at compile time"
                        ),
                    });
                }
                let Some((_, inner)) = type_subst.first() else {
                    return Err(EmitError::InvalidShape(
                        "getReg MethodCall missing its explicit T type_subst binding",
                    ));
                };
                return node(
                    0xC6,
                    Payload::ExtractRegisterAs {
                        input: Box::new(self.emit(obj)?),
                        reg_id: *i as u8,
                        tpe: map_type(inner)?,
                    },
                );
            }
        }
        // (d) v6 numeric methods over CONSTANT receivers fold at compile time
        //     — Scala's GraphBuilding partially evaluates them, emitting the
        //     folded constant (wave 2, adversarial-findings-methodcalls.md
        //     F6). Oracle-probed fold set ONLY (2026-07-07 ×3 runs each):
        //     `toBytes`/`toBits` on Byte/Short/Int/Long constants (`ccs
        //     sigmaProp(x.toBytes.size == 4)` → const `0e04 0000000a`,
        //     big-endian; `x.toBits` → const `0d20 00000050`, Coll[Boolean]
        //     MSB-first; `7.toByte.toBytes` → `0e01 07` — a single explicit
        //     cast of a literal folds too) and `bitwiseAnd`/`bitwiseOr`/
        //     `bitwiseXor` over two constants (all three fold: the x/y
        //     probes each reply the fully-folded `10010101d17300`). Probed
        //     NON-folds, deliberately left as residual MethodCalls:
        //     `HEIGHT.toBytes` (non-constant receiver — oracle keeps wire
        //     pair (4,6)), `n1.toBytes` (BigInt receiver — keeps (6,6)),
        //     `x.shiftLeft(1)` (keeps (4,12)); all Err/Err reduce parity.
        //     The owner name is per-type ("Byte"/"Short"/"Int"/"Long") only
        //     at `tree_version >= 3` — pre-v3 the SNumericType gate (a)
        //     already rejected. Out-of-range cast receivers
        //     (`300.toByte.toBytes`) do NOT fold here ([`const_numeric_i64`]
        //     returns `None`): the residual Downcast reaches tree.rs's
        //     `fold_direct_const_casts`, which rejects with the
        //     oracle's ArithmeticException. Residual (lib.rs D-C6): deeper
        //     constant receivers Scala's full partial evaluation also folds —
        //     arithmetic results (`(1 + 2).toBytes`) and multi-cast chains —
        //     stay residual MethodCalls here.
        if let Some(width_bytes) = match method.owner.as_str() {
            "Byte" => Some(1usize),
            "Short" => Some(2),
            "Int" => Some(4),
            "Long" => Some(8),
            _ => None,
        } {
            match method.name.as_str() {
                "toBytes" => {
                    if let Some(v) = const_numeric_i64(obj) {
                        let bytes: Vec<u8> = v.to_be_bytes()[8 - width_bytes..].to_vec();
                        return Ok(Expr::Const {
                            tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                            val: SigmaValue::Coll(CollValue::Bytes(bytes)),
                        });
                    }
                }
                "toBits" => {
                    if let Some(v) = const_numeric_i64(obj) {
                        let n_bits = width_bytes * 8;
                        // Collection index 0 = the MOST significant bit
                        // (oracle: `7.toByte.toBits` → `0d08 e0` =
                        // [f,f,f,f,f,t,t,t] — bit (n-1-i) of the value at
                        // index i).
                        let bits: Vec<bool> = (0..n_bits)
                            .map(|i| (v >> (n_bits - 1 - i)) & 1 == 1)
                            .collect();
                        return Ok(Expr::Const {
                            tpe: SigmaType::SColl(Box::new(SigmaType::SBoolean)),
                            val: SigmaValue::Coll(CollValue::BoolBits(bits)),
                        });
                    }
                }
                "bitwiseAnd" | "bitwiseOr" | "bitwiseXor" => {
                    if let (Some(a), Some(b)) = (
                        const_numeric_i64(obj),
                        args.first().and_then(const_numeric_i64),
                    ) {
                        // Bitwise ops on two same-width sign-extended values
                        // stay in range — no overflow path exists.
                        let v = match method.name.as_str() {
                            "bitwiseAnd" => a & b,
                            "bitwiseOr" => a | b,
                            _ => a ^ b,
                        };
                        let (tpe, val) = match method.owner.as_str() {
                            "Byte" => (SigmaType::SByte, SigmaValue::Byte(v as i8)),
                            "Short" => (SigmaType::SShort, SigmaValue::Short(v as i16)),
                            "Int" => (SigmaType::SInt, SigmaValue::Int(v as i32)),
                            _ => (SigmaType::SLong, SigmaValue::Long(v)),
                        };
                        return Ok(Expr::Const { tpe, val });
                    }
                }
                _ => {}
            }
        }
        let Some((type_id, desc)) = wire_method(&method.owner, &method.name) else {
            return Err(EmitError::UnsupportedNode(format!(
                "MethodCall %{}.{} has no wire (typeId, methodId)",
                method.owner, method.name
            )));
        };
        // The thin id projection must stay in lockstep with the full lookup
        // (same table; pins the invariant for direct `wire_ids` consumers).
        debug_assert_eq!(
            crate::typer::methods::wire_ids(&method.owner, &method.name),
            Some((type_id, desc.method_id)),
        );
        // PropertyCall discipline: an empty arg list is only valid when the
        // method table declares the method nullary (receiver-only dom) — a
        // zero-arg call of an args-taking method would serialize as a
        // PropertyCall that Scala deserializes to a different (arg-less)
        // invocation.
        if args.is_empty() && desc.stype.dom.len() != 1 {
            return Err(EmitError::InvalidShape(
                "zero-arg MethodCall of a method whose table entry declares value args",
            ));
        }
        let obj = self.emit(obj)?;
        let args = self.items_of(args)?;
        let mut type_args = Vec::new();
        if desc.explicit_type_args {
            for param in &desc.stype.tpe_params {
                let Some((_, bound)) = type_subst.iter().find(|(name, _)| name == param) else {
                    return Err(EmitError::InvalidShape(
                        "MethodCall missing a type_subst binding for an explicit type param",
                    ));
                };
                type_args.push(map_type(bound)?);
            }
        }
        if type_args.len() != method_explicit_type_args_count(type_id, desc.method_id) {
            return Err(EmitError::InvalidShape(
                "MethodCall explicit-type-arg count disagrees with the ergo-ser wire table",
            ));
        }
        let opcode = if args.is_empty() { 0xDB } else { 0xDC };
        node(
            opcode,
            Payload::MethodCall {
                type_id,
                method_id: desc.method_id,
                obj: Box::new(obj),
                args,
                type_args,
            },
        )
    }
}

/// Constant value of a v6-numeric-method receiver/argument for the wave-2
/// compile-time fold (emit_method_call gate (d), lib.rs D-C6): a DIRECT
/// Byte/Short/Int/Long constant, or a single explicit numeric cast of one
/// (`7.toByte` — a typed `Select` the typer leaves unfolded, class-4(a)).
/// The cast case is range-checked: an out-of-range cast (`300.toByte`)
/// returns `None`, so the residual `Downcast` reaches
/// `tree.rs::fold_direct_const_casts`, which rejects with the oracle's
/// `ArithmeticException` (oracle: `cc sigmaProp(300.toByte.toBytes.size ==
/// 1)` → `REJECT 0:0 ArithmeticException`, 2026-07-07 ×3).
fn const_numeric_i64(e: &TypedExpr) -> Option<i64> {
    fn direct(e: &TypedExpr) -> Option<i64> {
        match e {
            TypedExpr::Constant { value, .. } => match value {
                ConstPayload::Byte(v) => Some(i64::from(*v)),
                ConstPayload::Short(v) => Some(i64::from(*v)),
                ConstPayload::Int(v) => Some(i64::from(*v)),
                ConstPayload::Long(v) => Some(*v),
                _ => None,
            },
            _ => None,
        }
    }
    match e {
        TypedExpr::Constant { .. } => direct(e),
        TypedExpr::Select { obj, field, .. } => {
            let v = direct(obj)?;
            let in_range = match field.as_str() {
                "toByte" => i8::try_from(v).is_ok(),
                "toShort" => i16::try_from(v).is_ok(),
                "toInt" => i32::try_from(v).is_ok(),
                "toLong" => true,
                _ => return None,
            };
            in_range.then_some(v)
        }
        _ => None,
    }
}

/// Map a compiler-domain [`SType`] to the wire-domain [`SigmaType`].
///
/// Mechanical 1:1 for every serializable variant; `SFunc` renames
/// `dom`/`range` → `t_dom`/`t_range` and lifts each `tpe_params` ident into
/// a `SigmaType::STypeVar` (the ergo-ser writer requires exactly that shape,
/// `sigma_type.rs:235-244`). `NoType`/`STypeApply` are compiler-internal and
/// error as [`EmitError::UnresolvedType`].
pub(crate) fn map_type(t: &SType) -> Result<SigmaType, EmitError> {
    Ok(match t {
        // Compiler-internal shapes the typer must eliminate (OQ2 defense).
        SType::NoType => return Err(EmitError::UnresolvedType("NoType".to_string())),
        SType::STypeApply { name, .. } => {
            return Err(EmitError::UnresolvedType(format!("STypeApply({name})")))
        }

        // 1:1 renames (stype.rs:14-56 ↔ sigma_type.rs:70-135).
        SType::SBoolean => SigmaType::SBoolean,
        SType::SByte => SigmaType::SByte,
        SType::SShort => SigmaType::SShort,
        SType::SInt => SigmaType::SInt,
        SType::SLong => SigmaType::SLong,
        SType::SBigInt => SigmaType::SBigInt,
        SType::SUnsignedBigInt => SigmaType::SUnsignedBigInt,
        SType::SGroupElement => SigmaType::SGroupElement,
        SType::SSigmaProp => SigmaType::SSigmaProp,
        SType::SAvlTree => SigmaType::SAvlTree,
        SType::SContext => SigmaType::SContext,
        SType::SGlobal => SigmaType::SGlobal,
        SType::SHeader => SigmaType::SHeader,
        SType::SPreHeader => SigmaType::SPreHeader,
        SType::SString => SigmaType::SString,
        SType::SBox => SigmaType::SBox,
        SType::SUnit => SigmaType::SUnit,
        SType::SAny => SigmaType::SAny,
        SType::STypeVar(name) => SigmaType::STypeVar(name.clone()),

        // Compound shapes recurse.
        SType::SColl(elem) => SigmaType::SColl(Box::new(map_type(elem)?)),
        SType::SOption(elem) => SigmaType::SOption(Box::new(map_type(elem)?)),
        SType::STuple(elems) => {
            SigmaType::STuple(elems.iter().map(map_type).collect::<Result<Vec<_>, _>>()?)
        }

        // SFunc: dom→t_dom, range→t_range, String idents → STypeVar
        // (the ergo-ser writer requires STypeVar tpe_params,
        // sigma_type.rs:235-244).
        SType::SFunc {
            dom,
            range,
            tpe_params,
        } => SigmaType::SFunc {
            t_dom: dom.iter().map(map_type).collect::<Result<Vec<_>, _>>()?,
            t_range: Box::new(map_type(range)?),
            tpe_params: tpe_params
                .iter()
                .map(|ident| SigmaType::STypeVar(ident.clone()))
                .collect(),
        },
    })
}

/// Map a constant payload (+ its node type) to the wire `(type, value)` pair.
///
/// The pair is derived from the payload (the byte-of-record); the node type
/// is cross-checked against it — a mismatch is a typer bug surfaced as
/// [`EmitError::InvalidShape`]. `SUnsignedBigInt` values reuse
/// `SigmaValue::BigInt` on the wire (`write_unsigned_bigint_value` takes the
/// BigInt payload, `sigma_value.rs:225-227`).
pub(crate) fn map_const(p: &ConstPayload, t: &SType) -> Result<(SigmaType, SigmaValue), EmitError> {
    // The typer stores BigInt/UnsignedBigInt canonically via
    // `num_bigint::{BigInt,BigUint}::to_string` (D-T3), so a parse failure
    // here means a hand-built payload bypassed the frontend.
    fn parse_bigint(s: &str) -> Result<num_bigint::BigInt, EmitError> {
        s.parse::<num_bigint::BigInt>().map_err(|_| {
            EmitError::InvalidShape("BigInt constant payload is not a decimal integer")
        })
    }

    let (tpe, val) = match p {
        ConstPayload::Bool(b) => (SigmaType::SBoolean, SigmaValue::Boolean(*b)),
        ConstPayload::Byte(v) => (SigmaType::SByte, SigmaValue::Byte(*v)),
        ConstPayload::Short(v) => (SigmaType::SShort, SigmaValue::Short(*v)),
        ConstPayload::Int(v) => (SigmaType::SInt, SigmaValue::Int(*v)),
        ConstPayload::Long(v) => (SigmaType::SLong, SigmaValue::Long(*v)),
        ConstPayload::BigInt(s) => (SigmaType::SBigInt, SigmaValue::BigInt(parse_bigint(s)?)),
        // SUnsignedBigInt reuses the BigInt value on the wire
        // (write_unsigned_bigint_value, sigma_value.rs:225-227).
        ConstPayload::UnsignedBigInt(s) => (
            SigmaType::SUnsignedBigInt,
            SigmaValue::BigInt(parse_bigint(s)?),
        ),
        ConstPayload::String(s) => (SigmaType::SString, SigmaValue::Str(s.clone())),
        ConstPayload::Unit => (SigmaType::SUnit, SigmaValue::Unit),
        // Signed i8 elements reinterpreted as raw wire bytes.
        ConstPayload::ByteColl(bytes) => (
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes(bytes.iter().map(|b| *b as u8).collect())),
        ),
        ConstPayload::LongColl(longs) => (
            SigmaType::SColl(Box::new(SigmaType::SLong)),
            SigmaValue::Coll(CollValue::Values(
                longs.iter().map(|v| SigmaValue::Long(*v)).collect(),
            )),
        ),
        // 33-byte SEC1-compressed point, on-curve-checked upstream (D-T5).
        ConstPayload::GroupElement(bytes) => (
            SigmaType::SGroupElement,
            SigmaValue::GroupElement(GroupElement::from_bytes(*bytes)),
        ),
        // Binder PK-rule output — same shape as ergo-ser's own P2PK
        // construction (address.rs:365-368).
        ConstPayload::ProveDlog(pubkey) => (
            SigmaType::SSigmaProp,
            SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(*pubkey))),
        ),
        // Opaque env-injected sigma proposition: no curve bytes to
        // serialize (module docs + lib.rs ledger entry).
        ConstPayload::SigmaProp(_) => {
            return Err(EmitError::UnsupportedNode(
                "opaque SigmaProp constant payload".to_string(),
            ))
        }
    };

    // Cross-check the payload-derived wire type against the node's assigned
    // type: a mismatch is a typer bug, caught here rather than at write time.
    if map_type(t)? != tpe {
        return Err(EmitError::InvalidShape(
            "constant payload does not match the node's assigned type",
        ));
    }
    Ok((tpe, val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{EnvValue, ScriptEnv};
    use crate::typecheck::typecheck;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::opcode::{parse_expr, write_expr};

    // ----- helpers -----

    /// The secp256k1 generator point, SEC1-compressed (same fixture as
    /// `tests/typer_oracle_parity.rs::generator_ge`).
    fn generator_ge() -> GroupElement {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        GroupElement::from_bytes(bytes)
    }

    /// Subset of the oracle demo env (`TyperOracle.scala:demoEnv`) used by the
    /// golden-seed sources in this module: `a`,`b: Coll[Byte]`,
    /// `col1: Coll[Long]`, `g1`,`g2: GroupElement`, `n1: BigInt`.
    fn demo_env() -> ScriptEnv {
        let ge = generator_ge();
        let mut env = ScriptEnv::new();
        env.insert("a", EnvValue::ByteArray(vec![1, 2]));
        env.insert("b", EnvValue::ByteArray(vec![3, 4]));
        env.insert("col1", EnvValue::LongArray(vec![1, 2]));
        env.insert("g1", EnvValue::GroupElement(ge));
        env.insert("g2", EnvValue::GroupElement(ge));
        env.insert("n1", EnvValue::BigInt("5".to_string()));
        env
    }

    /// Real-frontend typecheck at tree_version 3 against the demo env.
    fn tc(src: &str) -> TypedExpr {
        typecheck(&demo_env(), src, 3).unwrap_or_else(|e| panic!("typecheck({src:?}): {e}"))
    }

    fn emit_tc(src: &str) -> Expr {
        emit(&tc(src)).unwrap_or_else(|e| panic!("emit({src:?}): {e}"))
    }

    /// write_expr → parse_expr → structural equality → re-write → byte
    /// equality (the `ergo-ser/src/opcode/tests.rs::roundtrip_v` pattern via
    /// the PUBLIC API). cseg=false: Task 7 emits inline constants only; the
    /// segregation transform is Task 9/10.
    fn wire_roundtrip(ir: &Expr) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_expr(&mut w, ir, false).expect("write_expr");
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = parse_expr(&mut r, 0, 3).expect("parse_expr");
        assert!(r.is_empty(), "leftover bytes after roundtrip");
        assert_eq!(&decoded, ir, "parsed IR differs from emitted IR");
        let mut w2 = VlqWriter::new();
        write_expr(&mut w2, &decoded, false).expect("re-write_expr");
        assert_eq!(data, w2.result(), "reserialized bytes differ");
        data
    }

    fn root_opcode(e: &Expr) -> u8 {
        match e {
            Expr::Op(node) => node.opcode,
            other => panic!("expected an Op node, got {other:?}"),
        }
    }

    /// Frontend source → emit → assert root opcode → wire round-trip.
    fn rt_op(src: &str, opcode: u8) {
        let ir = emit_tc(src);
        assert_eq!(
            root_opcode(&ir),
            opcode,
            "{src:?}: expected opcode {opcode:#04x}"
        );
        wire_roundtrip(&ir);
    }

    fn int_c(v: i32) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Int(v),
            tpe: SType::SInt,
        }
    }

    fn long_c(v: i64) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Long(v),
            tpe: SType::SLong,
        }
    }

    fn bool_c(v: bool) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Bool(v),
            tpe: SType::SBoolean,
        }
    }

    fn byte_coll_c(v: Vec<i8>) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::ByteColl(v),
            tpe: scoll(SType::SByte),
        }
    }

    fn scoll(t: SType) -> SType {
        SType::SColl(Box::new(t))
    }

    /// Hand-built node → emit → assert opcode → round-trip. For arms the
    /// M3 frontend cannot reach without Task-8 forms (documented per test).
    fn rt_node(node: &TypedExpr, opcode: u8) -> Expr {
        let ir = emit(node).unwrap_or_else(|e| panic!("emit({node:?}): {e}"));
        assert_eq!(root_opcode(&ir), opcode, "expected opcode {opcode:#04x}");
        wire_roundtrip(&ir);
        ir
    }

    // ----- happy path -----

    #[test]
    fn map_type_primitives_map_one_to_one() {
        for (s, g) in [
            (SType::SBoolean, SigmaType::SBoolean),
            (SType::SByte, SigmaType::SByte),
            (SType::SShort, SigmaType::SShort),
            (SType::SInt, SigmaType::SInt),
            (SType::SLong, SigmaType::SLong),
            (SType::SBigInt, SigmaType::SBigInt),
            (SType::SUnsignedBigInt, SigmaType::SUnsignedBigInt),
            (SType::SGroupElement, SigmaType::SGroupElement),
            (SType::SSigmaProp, SigmaType::SSigmaProp),
            (SType::SAvlTree, SigmaType::SAvlTree),
            (SType::SContext, SigmaType::SContext),
            (SType::SGlobal, SigmaType::SGlobal),
            (SType::SHeader, SigmaType::SHeader),
            (SType::SPreHeader, SigmaType::SPreHeader),
            (SType::SString, SigmaType::SString),
            (SType::SBox, SigmaType::SBox),
            (SType::SUnit, SigmaType::SUnit),
            (SType::SAny, SigmaType::SAny),
            (
                SType::STypeVar("T".to_string()),
                SigmaType::STypeVar("T".to_string()),
            ),
        ] {
            assert_eq!(map_type(&s).unwrap(), g, "{s:?}");
        }
    }

    #[test]
    fn map_type_compound_shapes_map_recursively() {
        assert_eq!(
            map_type(&scoll(scoll(SType::SByte))).unwrap(),
            SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))))
        );
        assert_eq!(
            map_type(&SType::SOption(Box::new(SType::SInt))).unwrap(),
            SigmaType::SOption(Box::new(SigmaType::SInt))
        );
        assert_eq!(
            map_type(&SType::STuple(vec![
                SType::SInt,
                SType::SLong,
                SType::SBoolean
            ]))
            .unwrap(),
            SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong, SigmaType::SBoolean])
        );
    }

    #[test]
    fn map_type_sfunc_maps_fields_and_tpe_params() {
        // Field renames dom→t_dom / range→t_range, and String idents →
        // SigmaType::STypeVar (recon §2 obligation; the ergo-ser writer
        // rejects any non-STypeVar tpe_param).
        let f = SType::SFunc {
            dom: vec![SType::SInt, SType::STypeVar("T".to_string())],
            range: Box::new(SType::SBoolean),
            tpe_params: vec!["T".to_string()],
        };
        assert_eq!(
            map_type(&f).unwrap(),
            SigmaType::SFunc {
                t_dom: vec![SigmaType::SInt, SigmaType::STypeVar("T".to_string())],
                t_range: Box::new(SigmaType::SBoolean),
                tpe_params: vec![SigmaType::STypeVar("T".to_string())],
            }
        );
    }

    #[test]
    fn map_const_scalar_payloads_produce_expected_pairs() {
        use num_bigint::BigInt;
        for (p, t, exp_t, exp_v) in [
            (
                ConstPayload::Bool(true),
                SType::SBoolean,
                SigmaType::SBoolean,
                SigmaValue::Boolean(true),
            ),
            (
                ConstPayload::Byte(-3),
                SType::SByte,
                SigmaType::SByte,
                SigmaValue::Byte(-3),
            ),
            (
                ConstPayload::Short(300),
                SType::SShort,
                SigmaType::SShort,
                SigmaValue::Short(300),
            ),
            (
                ConstPayload::Int(42),
                SType::SInt,
                SigmaType::SInt,
                SigmaValue::Int(42),
            ),
            (
                ConstPayload::Long(-7),
                SType::SLong,
                SigmaType::SLong,
                SigmaValue::Long(-7),
            ),
            (
                ConstPayload::BigInt("5".to_string()),
                SType::SBigInt,
                SigmaType::SBigInt,
                SigmaValue::BigInt(BigInt::from(5)),
            ),
            // SUnsignedBigInt reuses SigmaValue::BigInt on the wire
            // (write_unsigned_bigint_value takes the BigInt payload).
            (
                ConstPayload::UnsignedBigInt("5".to_string()),
                SType::SUnsignedBigInt,
                SigmaType::SUnsignedBigInt,
                SigmaValue::BigInt(BigInt::from(5)),
            ),
            (
                ConstPayload::String("abc".to_string()),
                SType::SString,
                SigmaType::SString,
                SigmaValue::Str("abc".to_string()),
            ),
            (
                ConstPayload::Unit,
                SType::SUnit,
                SigmaType::SUnit,
                SigmaValue::Unit,
            ),
        ] {
            assert_eq!(map_const(&p, &t).unwrap(), (exp_t, exp_v), "{p:?}");
        }
    }

    #[test]
    fn map_const_collection_and_crypto_payloads_produce_expected_pairs() {
        // ByteColl: signed i8 elements reinterpreted as raw u8 bytes.
        assert_eq!(
            map_const(&ConstPayload::ByteColl(vec![-1, 2]), &scoll(SType::SByte)).unwrap(),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(vec![0xFF, 0x02])),
            )
        );
        assert_eq!(
            map_const(&ConstPayload::LongColl(vec![1, -2]), &scoll(SType::SLong)).unwrap(),
            (
                SigmaType::SColl(Box::new(SigmaType::SLong)),
                SigmaValue::Coll(CollValue::Values(vec![
                    SigmaValue::Long(1),
                    SigmaValue::Long(-2)
                ])),
            )
        );
        let ge_bytes = *generator_ge().as_bytes();
        assert_eq!(
            map_const(&ConstPayload::GroupElement(ge_bytes), &SType::SGroupElement).unwrap(),
            (
                SigmaType::SGroupElement,
                SigmaValue::GroupElement(GroupElement::from_bytes(ge_bytes)),
            )
        );
        assert_eq!(
            map_const(&ConstPayload::ProveDlog(ge_bytes), &SType::SSigmaProp).unwrap(),
            (
                SigmaType::SSigmaProp,
                SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(ge_bytes))),
            )
        );
    }

    // Semantic smoke (Step 4): the emitted IR is not just parseable — it
    // EVALUATES correctly under the in-repo interpreter (first ergo-sigma
    // dev-dep use in this crate; recon confirmed no dependency cycle).

    #[test]
    fn emitted_sigma_prop_height_gt_100_reduces_true_at_height_200() {
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(HEIGHT > 100)");
        let ctx = ReductionContext::minimal(200, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    #[test]
    fn emitted_sigma_prop_height_gt_100_reduces_false_at_height_50() {
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(HEIGHT > 100)");
        let ctx = ReductionContext::minimal(50, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(false));
    }

    #[test]
    fn emitted_block_val_binding_reduces_across_100() {
        // BlockValue/ValDef/ValUse evaluate correctly under the in-repo
        // interpreter — the binding actually carries HEIGHT to the guard.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp({ val x = HEIGHT; x > 100 })");
        for (height, expected) in [(200u32, true), (50, false)] {
            let ctx = ReductionContext::minimal(height, 0);
            let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
            assert_eq!(sb, SigmaBoolean::TrivialProp(expected), "height {height}");
        }
    }

    #[test]
    fn emitted_val_bound_lambda_funcapply_reduces_true() {
        // FuncValue + FuncApply semantics: f(2) == 3 for f = x + 1.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp({ val f = {(x: Int) => x + 1}; f(2) == 3 })");
        let ctx = ReductionContext::minimal(1, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    #[test]
    fn emitted_coll_map_lambda_reduces_true() {
        // MapCollection over an emitted FuncValue: Coll(1,2).map(+1)(0) == 2.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(Coll(1, 2).map({(x: Int) => x + 1})(0) == 2)");
        let ctx = ReductionContext::minimal(1, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    #[test]
    fn emitted_get_var_composite_reduces_with_extension() {
        // `getVar[Int](1).get > 0`: GetVar inner-type wire + OptionGet +
        // relation, end-to-end against a context extension.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp(getVar[Int](1).get > 0)");
        let mut ctx = ReductionContext::minimal(1, 0);
        ctx.extension
            .insert(1, (SigmaType::SInt, SigmaValue::Int(5)));
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
        // Var absent → OptionGet on None → the script FAILS, like Scala.
        let empty_ctx = ReductionContext::minimal(1, 0);
        assert!(reduce_expr(&ir, &empty_ctx, &[]).is_err());
    }

    #[test]
    fn emitted_mixed_width_arith_reduces_true() {
        // The typer-inserted Upcast (mirrored by emit's normalization)
        // evaluates: (1 + 2L) == 3L.
        use ergo_sigma::evaluator::{reduce_expr, ReductionContext};
        let ir = emit_tc("sigmaProp((1 + 2L) == 3L)");
        let ctx = ReductionContext::minimal(1, 0);
        let sb = reduce_expr(&ir, &ctx, &[]).expect("reduce");
        assert_eq!(sb, SigmaBoolean::TrivialProp(true));
    }

    // ----- round-trips -----

    #[test]
    fn context_singletons_emit_zero_payload_and_roundtrip() {
        for (src, opcode) in [
            ("HEIGHT", 0xA3),
            ("INPUTS", 0xA4),
            ("OUTPUTS", 0xA5),
            ("SELF", 0xA7),
            ("MinerPubkey", 0xAC),
            ("CONTEXT", 0xFE),
            ("Global", 0xDD),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode { payload, .. }) => {
                    assert_eq!(payload, &Payload::Zero, "{src}: singleton payload")
                }
                other => panic!("{src}: expected Op, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn lowered_singletons_emit_property_call_and_roundtrip() {
        // M4 Task 8 (recon-transforms.md §9, D-C7): bare `LastBlockUtxoRootHash`
        // and bare/dotted `groupGenerator` are NOT `IsContextProperty`
        // primitives on the Scala side — both lower to a `PropertyCall`
        // (opcode 0xDB), not the dedicated 0xA6/0x82 leaf. Oracle-confirmed
        // 2026-07-07 (`ORACLE_TREE_VERSION=3`, ×2 runs each): both
        // `LastBlockUtxoRootHash.digest.size` and
        // `CONTEXT.LastBlockUtxoRootHash.digest.size` reply the SAME
        // `PropertyCall(101, 9)` receiver bytes (`…db6509fe…`); both
        // `groupGenerator.getEncoded.size` and
        // `Global.groupGenerator.getEncoded.size` reply the SAME
        // `PropertyCall(106, 1)` receiver bytes (`…db6a01dd…`).
        for (src, (type_id, method_id), receiver_opcode) in [
            ("LastBlockUtxoRootHash", (101u8, 9u8), 0xFEu8),
            ("groupGenerator", (106, 1), 0xDD),
            ("Global.groupGenerator", (106, 1), 0xDD),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), 0xDB, "{src}: PropertyCall opcode");
            match &ir {
                Expr::Op(IrNode {
                    payload:
                        Payload::MethodCall {
                            type_id: tid,
                            method_id: mid,
                            obj,
                            args,
                            type_args,
                        },
                    ..
                }) => {
                    assert_eq!((*tid, *mid), (type_id, method_id), "{src}: wire ids");
                    assert!(args.is_empty(), "{src}: PropertyCall has no args");
                    assert!(type_args.is_empty(), "{src}: no explicit type args");
                    assert_eq!(root_opcode(obj), receiver_opcode, "{src}: receiver");
                    match obj.as_ref() {
                        Expr::Op(IrNode { payload, .. }) => {
                            assert_eq!(payload, &Payload::Zero, "{src}: receiver is a bare leaf")
                        }
                        other => panic!("{src}: expected Op receiver, got {other:?}"),
                    }
                }
                other => panic!("{src}: expected MethodCall payload, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn constants_emit_via_constant_path_and_roundtrip() {
        for src in [
            "42",
            "1L",
            "true",
            "\"abc\"",
            "()",
            "bigInt(\"5\")",
            "unsignedBigInt(\"5\")",
            "fromBase64(\"YWJj\")",
            "col1",
            "g1",
        ] {
            let ir = emit_tc(src);
            assert!(matches!(ir, Expr::Const { .. }), "{src}: expected Const");
            wire_roundtrip(&ir);
        }
        // Spot-check the UBI wire pair: SUnsignedBigInt type + BigInt value.
        match emit_tc("unsignedBigInt(\"5\")") {
            Expr::Const { tpe, val } => {
                assert_eq!(tpe, SigmaType::SUnsignedBigInt);
                assert_eq!(val, SigmaValue::BigInt(num_bigint::BigInt::from(5)));
            }
            other => panic!("expected Const, got {other:?}"),
        }
    }

    #[test]
    fn relations_emit_relation2_opcodes_and_roundtrip() {
        rt_op("HEIGHT > 100", 0x91);
        rt_op("HEIGHT >= 100", 0x92);
        rt_op("HEIGHT < 100", 0x8F);
        rt_op("HEIGHT <= 100", 0x90);
        rt_op("HEIGHT == 100", 0x93);
        rt_op("HEIGHT != 100", 0x94);
    }

    #[test]
    fn relation_over_two_bool_constants_roundtrips_via_compact_wire_form() {
        // The writer compacts a Relation2 over two Boolean constants into the
        // 0x85 packed form (write.rs:relation2_bool_pair); emit does NOT
        // special-case it — the round-trip must still be structural+byte
        // exact. Hand-built EQ to sidestep any frontend folding.
        let node = TypedExpr::EQ {
            left: Box::new(bool_c(true)),
            right: Box::new(bool_c(false)),
            tpe: SType::SBoolean,
        };
        let ir = rt_node(&node, 0x93);
        let bytes = wire_roundtrip(&ir);
        assert_eq!(bytes, vec![0x93, 0x85, 0x01], "compact Relation2 form");
    }

    #[test]
    fn arith_ops_emit_scala_opcode_bytes_and_roundtrip() {
        rt_op("1 + 2", 0x9A);
        rt_op("5 - 1", 0x99);
        rt_op("2 * 3", 0x9C);
        rt_op("6 / 2", 0x9D);
        rt_op("5 % 2", 0x9E);
        rt_op("min(1, 2)", 0xA1);
        rt_op("max(1, 2)", 0xA2);
    }

    #[test]
    fn bit_ops_reject_graph_building_parity() {
        // Scala 6.0.2 GraphBuilding has NO BitOp lowering — the full
        // compiler rejects every bit operator at every width, shifts
        // included (surface `5 << 1` parses and typechecks fine on both
        // sides; oracle `cc sigmaProp((5 << 1) == 10)` → `REJECT 1:12
        // GraphBuildingException`, compile_seed.json). Opcodes 0xF2-0xF8
        // are unreachable from emit.
        for src in ["1 | 2", "1 & 2", "1 ^ 2", "5 << 1", "5 >> 1", "5 >>> 1"] {
            let err = emit(&tc(src)).expect_err(src);
            assert!(
                matches!(
                    &err,
                    EmitError::GraphBuildingReject { class, .. }
                        if *class == "GraphBuildingException"
                ),
                "{src}: {err:?}"
            );
        }
        // Hand-built BitOp (any opcode byte) rejects the same way.
        let node = TypedExpr::BitOp {
            left: Box::new(int_c(1)),
            right: Box::new(int_c(2)),
            opcode: crate::typed::BIT_SHIFT_LEFT,
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node),
            Err(EmitError::GraphBuildingReject { .. })
        ));
    }

    #[test]
    fn bool_xor_still_emits_binxor_nearest_accept_boundary() {
        // `^` over BOOLEANS is a different node (BinXor, 0xF4) with a real
        // GraphBuilding lowering — the bit-op gate must not touch it.
        rt_op("(HEIGHT > 1) ^ (HEIGHT < 5)", 0xF4);
    }

    #[test]
    fn bool_binops_emit_lazy_opcodes_and_roundtrip() {
        rt_op("HEIGHT > 1 && HEIGHT < 5", 0xED);
        rt_op("HEIGHT > 1 || HEIGHT < 5", 0xEC);
        rt_op("(HEIGHT > 1) ^ (HEIGHT < 5)", 0xF4);
    }

    #[test]
    fn unary_ops_emit_one_payload_and_roundtrip() {
        rt_op("!(HEIGHT > 1)", 0xEF);
        rt_op("-HEIGHT", 0xF0);
    }

    #[test]
    fn bit_inversion_rejects_graph_building_parity() {
        // Same GraphBuilding gap as BitOp (oracle: `cc sigmaProp((~1) ==
        // -2)` → `REJECT 1:13 GraphBuildingException`); 0xF1 never emits.
        let err = emit(&tc("~HEIGHT")).expect_err("~ must reject");
        assert!(
            matches!(
                &err,
                EmitError::GraphBuildingReject { class, .. }
                    if *class == "GraphBuildingException"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn if_emits_three_payload_and_roundtrips() {
        rt_op("if (HEIGHT > 1) 1 else 2", 0x95);
    }

    #[test]
    fn tuple_and_select_field_emit_and_roundtrip() {
        rt_op("(1, 2L)", 0x86);
        // `(1, 2L)._2` survives as `Select '_2'` in the typed AST; the Task-8
        // Select arm lowers it to SelectField (GraphBuilding.scala:551-553).
        let ir = emit_tc("(1, 2L)._2");
        assert_eq!(root_opcode(&ir), 0x8C);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::SelectField { field_idx, .. },
                ..
            }) => assert_eq!(*field_idx, 2, "1-based field index"),
            other => panic!("expected SelectField, got {other:?}"),
        }
        wire_roundtrip(&ir);
        // Hand-built SelectField node (typer static tuple-index arm shape,
        // golden_seed §23(b) static record) still round-trips.
        let node = TypedExpr::SelectField {
            input: Box::new(tc("(1, 2L)")),
            field_index: 2,
            tpe: SType::SLong,
        };
        rt_node(&node, 0x8C);
    }

    #[test]
    fn tuple_select_field_first_component_emits_index_one() {
        let ir = emit_tc("(1, 2L)._1");
        assert_eq!(root_opcode(&ir), 0x8C);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::SelectField { field_idx, .. },
                ..
            }) => assert_eq!(*field_idx, 1),
            other => panic!("expected SelectField, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn concrete_collection_emits_elem_type_and_roundtrips() {
        let ir = emit_tc("Coll(1, 2)");
        assert_eq!(root_opcode(&ir), 0x83);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ConcreteCollection { elem_type, items },
                ..
            }) => {
                assert_eq!(elem_type, &SigmaType::SInt);
                assert_eq!(items.len(), 2);
            }
            other => panic!("expected ConcreteCollection, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn upcast_from_mixed_arith_emits_numeric_cast() {
        // `1 + 1L` — the typer wraps the Int side in Upcast(SLong)
        // (unify.rs:478); emit lowers it to NumericCast @ 0x7E.
        let ir = emit_tc("1 + 1L");
        assert_eq!(root_opcode(&ir), 0x9A);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, _),
                ..
            }) => match left.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { tpe, .. },
                }) => assert_eq!(tpe, &SigmaType::SLong),
                other => panic!("expected Upcast on the left, got {other:?}"),
            },
            other => panic!("expected Two payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn downcast_hand_built_emits_numeric_cast_and_roundtrips() {
        // Direct Downcast node (the frontend route is the `Select` cast arm,
        // covered by `select_numeric_casts_*` below).
        let node = TypedExpr::Downcast {
            input: Box::new(long_c(1)),
            tpe: SType::SInt,
        };
        let ir = rt_node(&node, 0x7D);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::NumericCast { tpe, .. },
                ..
            }) => assert_eq!(tpe, &SigmaType::SInt),
            other => panic!("expected NumericCast, got {other:?}"),
        }
    }

    #[test]
    fn select_numeric_casts_emit_numeric_cast_by_ladder_order() {
        // GraphBuilding.scala:555-563: narrower target → Downcast, wider →
        // Upcast, chained casts compose.
        let ir = emit_tc("1.toByte");
        assert_eq!(root_opcode(&ir), 0x7D, "Int→Byte is a Downcast");
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::NumericCast { tpe, .. },
                ..
            }) => assert_eq!(tpe, &SigmaType::SByte),
            other => panic!("expected NumericCast, got {other:?}"),
        }
        wire_roundtrip(&ir);
        rt_op("1.toLong", 0x7E);
        rt_op("1.toBigInt", 0x7E);
        rt_op("1.toByte.toShort", 0x7E); // Upcast over the inner Downcast
    }

    #[test]
    fn select_numeric_cast_same_type_unwraps_to_input() {
        // GraphBuilding.scala:558-559 `if (numValue.tpe == tRes)
        // eval(numValue)` — a same-type cast disappears from the tree.
        let ir = emit_tc("1.toInt");
        assert!(
            matches!(
                &ir,
                Expr::Const {
                    tpe: SigmaType::SInt,
                    val: SigmaValue::Int(1),
                }
            ),
            "same-type cast must unwrap to the bare input, got {ir:?}"
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn collection_ops_emit_and_roundtrip() {
        rt_op("a.slice(0, 1)", 0xB4);
        rt_op("a ++ b", 0xB3);
        rt_op("Coll(1, 2)(0)", 0xB2);
        // getOrElse on a collection → ByIndex WITH a default child.
        let ir = emit_tc("Coll(1, 2).getOrElse(0, 5)");
        assert_eq!(root_opcode(&ir), 0xB2);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ByIndex { default, .. },
                ..
            }) => assert!(default.is_some(), "getOrElse default present"),
            other => panic!("expected ByIndex, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn size_of_hand_built_emits_one_payload() {
        // Direct SizeOf node; the frontend `Select 'size'` route is covered
        // by `select_size_emits_size_of` below.
        let node = TypedExpr::SizeOf {
            input: Box::new(TypedExpr::Inputs {
                tpe: scoll(SType::SBox),
            }),
            tpe: SType::SInt,
        };
        rt_node(&node, 0xB1);
    }

    #[test]
    fn select_size_emits_size_of() {
        // `col1.size` survives as `Select 'size'` (golden_seed §23(a) dot
        // form); the Select arm lowers it to SizeOf
        // (GraphBuilding.scala:520-525). Also holds for INPUTS and tuples
        // (STuple is collection-like, SType.scala:822-825).
        rt_op("col1.size", 0xB1);
        rt_op("(1, 2L).size", 0xB1);
        let ir = emit_tc("INPUTS.size > 1");
        assert_eq!(root_opcode(&ir), 0x91);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, _),
                ..
            }) => assert_eq!(root_opcode(left), 0xB1, "SizeOf child"),
            other => panic!("expected Two payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn postfix_size_residual_method_call_rejects_graph_building_parity() {
        // `col1 size` (no dot, the grammar's PostFix rule) desugars to a
        // zero-arg MethodCall `%SCollection.size [] {}` (golden_seed §23(a))
        // on BOTH typers, but Scala's GraphBuilding has no arm for the wire
        // pair (12,1) — only the Select path lowers `size` (SizeOf) — and
        // rejects (oracle: `ccs sigmaProp((arr1 size) > 0)` → `REJECT 1:12
        // GraphBuildingException`, compile_seed.json). Emit mirrors the
        // verdict.
        let err = emit(&tc("col1 size")).expect_err("postfix size must reject");
        assert!(
            matches!(
                &err,
                EmitError::GraphBuildingReject { class, .. }
                    if *class == "GraphBuildingException"
            ),
            "{err:?}"
        );
        // Nearest-accept boundary: the DOT form lowers via the Select path
        // to SizeOf (0xB1) — untouched by the gate.
        rt_op("col1.size", 0xB1);
    }

    #[test]
    fn snumeric_container_method_call_rejects_graph_building_parity() {
        // tree_version < 3 resolves `1.toBytes` to the shared SNumericType
        // container (D-T10); Scala's GraphBuilding rejects the v6-only
        // method under v5 activation (oracle, ORACLE_TREE_VERSION=2:
        // `cc sigmaProp(1.toBytes.size == 1)` → `REJECT 1:11
        // GraphBuildingException`, compile_seed.json). The TYPER stays
        // permissive on both sides (M2 parity, golden_seed §21) — the gate
        // is emit's.
        let typed = typecheck(&demo_env(), "1.toBytes", 2).expect("v2 typer accepts (M2 parity)");
        let err = emit(&typed).expect_err("SNumericType residual must reject");
        assert!(
            matches!(
                &err,
                EmitError::GraphBuildingReject { class, .. }
                    if *class == "GraphBuildingException"
            ),
            "{err:?}"
        );
        // Nearest-accept boundary: at v3 the owner resolves per-type (Int).
        // A NON-constant receiver keeps the residual MethodCall with wire
        // pair (4, 6) (oracle: `ccs sigmaProp(HEIGHT.toBytes.size == 4)`
        // keeps the pair too — Err/Err reduce parity, compile_seed.json); a
        // CONSTANT receiver now FOLDS at v3 (wave 2 — see
        // `numeric_const_receiver_methods_fold_to_oracle_bytes`).
        let ir = emit_tc("HEIGHT.toBytes");
        assert_eq!(root_opcode(&ir), 0xDB);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::MethodCall {
                        type_id, method_id, ..
                    },
                ..
            }) => assert_eq!((*type_id, *method_id), (4, 6)),
            other => panic!("expected MethodCall payload, got {other:?}"),
        }
    }

    #[test]
    fn get_reg_out_of_range_literal_rejects_graph_building_parity() {
        // Scala bounds-checks a CONST-index getReg at compile time while
        // lowering it to ExtractRegisterAs (oracle: `cc sigmaProp(
        // SELF.getReg[Int](-1).isDefined)` → `REJECT 0:0
        // ArrayIndexOutOfBoundsException`; same for 10 and 100,
        // compile_seed.json).
        for src in [
            "SELF.getReg[Int](-1)",
            "SELF.getReg[Int](10)",
            "SELF.getReg[Int](100)",
        ] {
            let err = emit(&tc(src)).expect_err(src);
            assert!(
                matches!(
                    &err,
                    EmitError::GraphBuildingReject { class, .. }
                        if *class == "ArrayIndexOutOfBoundsException"
                ),
                "{src}: {err:?}"
            );
        }
        // Nearest-accept boundaries: in-range literals (0..=9) lower to
        // ExtractRegisterAs (wave 2 — byte pins in
        // `get_reg_in_range_literal_lowers_to_extract_register_as`), and a
        // DYNAMIC index is untouched (Scala keeps the MethodCall there too —
        // Err/Err reduce parity).
        for src in ["SELF.getReg[Int](0)", "SELF.getReg[Int](9)"] {
            let ir = emit(&tc(src)).unwrap_or_else(|e| panic!("{src}: {e:?}"));
            assert_eq!(root_opcode(&ir), 0xC6, "{src}");
        }
        let ir = emit(&tc("SELF.getReg[Int](HEIGHT)")).expect("dynamic index");
        assert_eq!(root_opcode(&ir), 0xDC);
    }

    #[test]
    fn numeric_const_receiver_methods_fold_to_oracle_bytes() {
        // Wave 2 (adversarial-findings-methodcalls.md F6): Scala's
        // GraphBuilding partially evaluates v6 numeric methods over CONSTANT
        // receivers at v3; emit folds the same probed set. Every expected
        // hex below is the CONSTANT segment of a fresh oracle capture
        // (2026-07-07, 3 identical runs):
        //   ccs `x.toBytes` (x=10)        → `0e04 0000000a` (big-endian)
        //   ccs `x.toBits`                → `0d20 00000050` (Coll[Boolean],
        //       index 0 = the most significant bit; bit-packed on the wire)
        //   cc `7.toByte.toBytes`         → `0e01 07` (cast-of-literal folds)
        //   cc `7.toByte.toBits`          → `0d08 e0`
        //   cc `5.toShort.toBytes`        → `0e02 0005`
        //   ccs `height1.toBytes` (=100L) → `0e08 0000000000000064`
        //   ccs `b1.toBytes` (=1)         → `0e01 01`
        // bitwiseAnd/Or/Xor over two constants fold too (the x/y probes each
        // reply the FULLY-folded `10010101d17300`; the folded values are
        // pinned here at the constant level).
        for (src, expect_hex) in [
            ("10.toBytes", "0e040000000a"),
            ("10.toBits", "0d2000000050"),
            ("7.toByte.toBytes", "0e0107"),
            ("7.toByte.toBits", "0d08e0"),
            ("5.toShort.toBytes", "0e020005"),
            ("100L.toBytes", "0e080000000000000064"),
            ("1.toByte.toBytes", "0e0101"),
            ("10.bitwiseAnd(11)", "0414"), // Int 10 & 11 = 10 (zigzag 0x14)
            ("10.bitwiseOr(11)", "0416"),  // Int 10 | 11 = 11 (zigzag 0x16)
            ("10.bitwiseXor(11)", "0402"), // Int 10 ^ 11 = 1 (zigzag 0x02)
            ("1.toByte.bitwiseAnd(2.toByte)", "0200"), // Byte 1 & 2 = 0
        ] {
            let ir = emit_tc(src);
            assert!(
                matches!(&ir, Expr::Const { .. }),
                "{src}: expected a folded constant, got {ir:?}"
            );
            assert_eq!(hex::encode(wire_roundtrip(&ir)), expect_hex, "{src}");
        }
        // Probed NON-folds stay residual MethodCalls: BigInt receiver
        // (oracle keeps wire pair (6, 6)) and shiftLeft (keeps (4, 12)).
        rt_op("n1.toBytes", 0xDB);
        rt_op("10.shiftLeft(1)", 0xDC);
    }

    #[test]
    fn get_reg_in_range_literal_lowers_to_extract_register_as() {
        // Wave 2 (adversarial-findings-methodcalls.md F4): Scala lowers a
        // CONST-index `getReg[T]` to ExtractRegisterAs at GraphBuilding —
        // `cc sigmaProp(SELF.getReg[Int](5).isDefined)` and `cc sigmaProp(
        // SELF.R5[Int].isDefined)` reply IDENTICALLY (`1000d1e6c6a70504`,
        // oracle 2026-07-07 ×3; body `…c6 a7 05 04` = ExtractRegisterAs(
        // SELF, reg 5, Int) — the wire carries the INNER elem type).
        let get_reg = emit_tc("SELF.getReg[Int](5)");
        let r5 = emit_tc("SELF.R5[Int]");
        assert_eq!(get_reg, r5, "getReg literal must lower like the R5 path");
        assert_eq!(hex::encode(wire_roundtrip(&get_reg)), "c6a70504");
        // Long variant over another register, with the getOrElse chain the
        // oracle probed (`…e5c6a70405…`).
        let ir = emit_tc("SELF.getReg[Long](4).getOrElse(7L)");
        assert_eq!(hex::encode(wire_roundtrip(&ir)), "e5c6a70405050e");
    }

    #[test]
    fn higher_order_ops_emit_fixed_arity_payloads() {
        // Fixed-arity opcode mapping pinned with constant stand-ins in the
        // function position (the wire pattern is child-shape-agnostic); the
        // real-lambda frontend route is `higher_order_ops_with_frontend_
        // lambdas_emit_func_values` below.
        let input = byte_coll_c(vec![1, 2]);
        let f = long_c(7);
        let mk = |node: TypedExpr, byte: u8| {
            rt_node(&node, byte);
        };
        mk(
            TypedExpr::MapCollection {
                input: Box::new(input.clone()),
                mapper: Box::new(f.clone()),
                tpe: scoll(SType::SLong),
            },
            0xAD,
        );
        mk(
            TypedExpr::Exists {
                input: Box::new(input.clone()),
                condition: Box::new(f.clone()),
                tpe: SType::SBoolean,
            },
            0xAE,
        );
        mk(
            TypedExpr::ForAll {
                input: Box::new(input.clone()),
                condition: Box::new(f.clone()),
                tpe: SType::SBoolean,
            },
            0xAF,
        );
        mk(
            TypedExpr::Filter {
                input: Box::new(input.clone()),
                condition: Box::new(f.clone()),
                tpe: scoll(SType::SByte),
            },
            0xB5,
        );
        mk(
            TypedExpr::Fold {
                input: Box::new(input),
                zero: Box::new(long_c(0)),
                fold_op: Box::new(f),
                tpe: SType::SLong,
            },
            0xB0,
        );
    }

    #[test]
    fn logical_fold_predefs_emit_one_collection_arg() {
        rt_op("allOf(Coll(HEIGHT > 1, HEIGHT > 2))", 0x96);
        rt_op("anyOf(Coll(HEIGHT > 1, HEIGHT > 2))", 0x97);
        rt_op("xorOf(Coll(HEIGHT > 1, HEIGHT > 2))", 0xFF);
    }

    #[test]
    fn at_least_emits_bound_then_input() {
        let ir = emit_tc("atLeast(1, Coll(proveDlog(g1), proveDlog(g2)))");
        assert_eq!(root_opcode(&ir), 0x98);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(bound, _input),
                ..
            }) => assert!(
                matches!(
                    bound.as_ref(),
                    Expr::Const {
                        val: SigmaValue::Int(1),
                        ..
                    }
                ),
                "bound child first (AtLeast wire order)"
            ),
            other => panic!("expected Two payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn sigma_combinators_emit_sigma_collection() {
        for (src, opcode) in [
            ("proveDlog(g1) && proveDlog(g2)", 0xEA),
            ("proveDlog(g1) || proveDlog(g2)", 0xEB),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode {
                    payload: Payload::SigmaCollection { items },
                    ..
                }) => assert_eq!(items.len(), 2, "{src}"),
                other => panic!("{src}: expected SigmaCollection, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn sigma_coercions_emit_and_roundtrip() {
        rt_op("sigmaProp(HEIGHT > 100)", 0xD1);
        // `.propBytes` / `.isProven` survive as `Select` and the Select arm
        // lowers them (GraphBuilding.scala:527-533).
        rt_op("proveDlog(g1).propBytes", 0xD0);
        rt_op("proveDlog(g1).isProven", 0xCF);
        // Hand-built dedicated nodes still round-trip.
        rt_node(
            &TypedExpr::SigmaPropBytes {
                input: Box::new(tc("proveDlog(g1)")),
                tpe: scoll(SType::SByte),
            },
            0xD0,
        );
        rt_node(
            &TypedExpr::SigmaPropIsProven {
                input: Box::new(tc("proveDlog(g1)")),
                tpe: SType::SBoolean,
            },
            0xCF,
        );
    }

    #[test]
    fn crypto_ops_emit_and_roundtrip() {
        rt_op("proveDlog(g1)", 0xCD);
        rt_op("proveDHTuple(g1, g2, g1, g2)", 0xCE);
        rt_op("blake2b256(a)", 0xCB);
        rt_op("sha256(a)", 0xCC);
    }

    #[test]
    fn byte_conversions_emit_and_roundtrip() {
        rt_op("byteArrayToBigInt(a)", 0x7B);
        rt_op("byteArrayToLong(a)", 0x7C);
        rt_op("longToByteArray(1L)", 0x7A);
    }

    #[test]
    fn group_ops_emit_and_roundtrip() {
        rt_op("decodePoint(a)", 0xEE);
        rt_op("g1.multiply(g2)", 0xA0);
        rt_op("g1.exp(n1)", 0x9F);
        rt_op("Global.xor(a, b)", 0x9B);
    }

    #[test]
    fn option_ops_emit_and_roundtrip() {
        rt_op("getVar[Int](1)", 0xE3);
        rt_op("getVar[Int](1).get", 0xE4);
        rt_op("getVar[Int](1).isDefined", 0xE6);
        rt_op("getVar[Int](1).getOrElse(2)", 0xE5);
    }

    #[test]
    fn get_var_emits_inner_type_on_the_wire() {
        // GetVar's node type is SOption(V); the wire carries V (Scala
        // GetVarSerializer writes `tpe.elemType`; ergo-ser's parse arm reads
        // one bare type and our GetVar payload docs call it the read type).
        let ir = emit_tc("getVar[Int](1)");
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::GetVar { var_id, tpe },
                ..
            }) => {
                assert_eq!(*var_id, 1);
                assert_eq!(tpe, &SigmaType::SInt, "inner type, not SOption");
            }
            other => panic!("expected GetVar, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_ops_emit_and_roundtrip() {
        rt_op("executeFromVar[Boolean](1)", 0xD4);
        let ir = emit_tc("executeFromSelfReg[Boolean](4)");
        assert_eq!(root_opcode(&ir), 0xD5);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::DeserializeRegister {
                        reg_id,
                        tpe,
                        default,
                    },
                ..
            }) => {
                assert_eq!(*reg_id, 4);
                assert_eq!(tpe, &SigmaType::SBoolean);
                assert!(default.is_none());
            }
            other => panic!("expected DeserializeRegister, got {other:?}"),
        }
        wire_roundtrip(&ir);
        let ir = emit_tc("executeFromSelfRegWithDefault[Int](4, 7)");
        assert_eq!(root_opcode(&ir), 0xD5);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::DeserializeRegister { default, .. },
                ..
            }) => assert!(default.is_some(), "default child present"),
            other => panic!("expected DeserializeRegister, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn subst_constants_emits_three_and_roundtrips() {
        rt_op("substConstants(a, Coll(0), Coll(1L))", 0x74);
    }

    #[test]
    fn tree_lookup_hand_built_roundtrips() {
        // No frontend surface constructs TreeLookup at M3 (`avlTree`/AvlTree
        // methods lower elsewhere); 0xB7 parses with wire arity 3 and the
        // evaluator rejects at execution, matching Scala (types.rs:346-353).
        let node = TypedExpr::TreeLookup {
            tree: Box::new(TypedExpr::LastBlockUtxoRootHash {
                tpe: SType::SAvlTree,
            }),
            key: Box::new(byte_coll_c(vec![1])),
            proof: Box::new(byte_coll_c(vec![2])),
            tpe: SType::SOption(Box::new(scoll(SType::SByte))),
        };
        rt_node(&node, 0xB7);
    }

    #[test]
    fn block_val_emits_blockvalue_valdef_valuse_and_roundtrips() {
        // `{ val x = HEIGHT; x > 100 }` → BlockValue(ValDef(1, Height),
        // GT(ValUse(1), 100)); ValDef ids start at 1 in source order and the
        // wire ValDef carries NO type (ergo-ser parse pins tpe: None).
        let ir = emit_tc("{ val x = HEIGHT; x > 100 }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { items, result },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        assert_eq!(items.len(), 1);
        match &items[0] {
            Expr::Op(IrNode {
                opcode: 0xD6,
                payload: Payload::ValDef { id, tpe, rhs },
            }) => {
                assert_eq!(*id, 1);
                assert_eq!(*tpe, None, "ValDef type never on the wire");
                assert_eq!(root_opcode(rhs), 0xA3, "rhs is Height");
            }
            other => panic!("expected ValDef, got {other:?}"),
        }
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0x91,
                payload: Payload::Two(left, _),
            }) => assert_eq!(
                left.as_ref(),
                &Expr::Op(IrNode {
                    opcode: 0x72,
                    payload: Payload::ValUse { id: 1 },
                }),
                "block result references the val through ValUse(1)"
            ),
            other => panic!("expected GT result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn lambda_emits_funcvalue_with_typed_arg_and_roundtrips() {
        // `OUTPUTS.map({ (o: Box) => o.value })` → MapCollection(Outputs,
        // FuncValue([(1, SBox)], ExtractAmount(ValUse(1)))). FuncValue args
        // MUST carry types — the ergo-ser writer panics otherwise
        // (write.rs FuncValue arm).
        let ir = emit_tc("OUTPUTS.map({ (o: Box) => o.value })");
        assert_eq!(root_opcode(&ir), 0xAD);
        let Expr::Op(IrNode {
            payload: Payload::Two(_, mapper),
            ..
        }) = &ir
        else {
            panic!("expected Two payload, got {ir:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0xD9,
            payload: Payload::FuncValue { args, body },
        }) = mapper.as_ref()
        else {
            panic!("expected FuncValue mapper, got {mapper:?}");
        };
        assert_eq!(args, &vec![(1u32, Some(SigmaType::SBox))]);
        assert_eq!(
            body.as_ref(),
            &Expr::Op(IrNode {
                opcode: 0xC1, // ExtractAmount — Select 'value' lowering
                payload: Payload::One(Box::new(Expr::Op(IrNode {
                    opcode: 0x72,
                    payload: Payload::ValUse { id: 1 },
                }))),
            })
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn higher_order_ops_with_frontend_lambdas_emit_func_values() {
        for (src, opcode) in [
            ("col1.map({(x: Long) => x})", 0xAD),
            ("col1.exists({(x: Long) => x > 1L})", 0xAE),
            ("col1.forall({(x: Long) => x > 1L})", 0xAF),
            ("col1.filter({(x: Long) => x > 1L})", 0xB5),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode {
                    payload: Payload::Two(_, f),
                    ..
                }) => assert_eq!(root_opcode(f), 0xD9, "{src}: FuncValue lambda"),
                other => panic!("{src}: expected Two payload, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
        // fold's op is a TWO-arg lambda → FuncValue with two typed arg slots.
        let ir = emit_tc("col1.fold(0L, {(acc: Long, x: Long) => acc + x})");
        assert_eq!(root_opcode(&ir), 0xB0);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Three(_, _, op),
                ..
            }) => match op.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0xD9,
                    payload: Payload::FuncValue { args, .. },
                }) => assert_eq!(
                    args,
                    &vec![
                        (1u32, Some(SigmaType::SLong)),
                        (2u32, Some(SigmaType::SLong))
                    ]
                ),
                other => panic!("expected two-arg FuncValue, got {other:?}"),
            },
            other => panic!("expected Three payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn nested_scopes_allocate_collision_free_ids() {
        // Outer val takes id 1; the lambda arg continues from the same
        // monotonic counter (id 2) — never-reuse relaxation of the Scala
        // scheme (TreeBuilding.scala:186-191, see the Scope docs).
        let ir = emit_tc("{ val w = 1L; col1.map({(x: Long) => x + w}) }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { items, result },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match &items[0] {
            Expr::Op(IrNode {
                payload: Payload::ValDef { id, .. },
                ..
            }) => assert_eq!(*id, 1),
            other => panic!("expected ValDef, got {other:?}"),
        }
        let Expr::Op(IrNode {
            payload: Payload::Two(_, f),
            ..
        }) = result.as_ref()
        else {
            panic!("expected MapCollection result, got {result:?}");
        };
        let Expr::Op(IrNode {
            payload: Payload::FuncValue { args, body },
            ..
        }) = f.as_ref()
        else {
            panic!("expected FuncValue, got {f:?}");
        };
        assert_eq!(args, &vec![(2u32, Some(SigmaType::SLong))]);
        // Lambda body `x + a`: ValUse(2) for the arg, ValUse(1) for the
        // enclosing val — the arg SHADOWS nothing here, both resolve.
        assert_eq!(
            body.as_ref(),
            &Expr::Op(IrNode {
                opcode: 0x9A,
                payload: Payload::Two(
                    Box::new(Expr::Op(IrNode {
                        opcode: 0x72,
                        payload: Payload::ValUse { id: 2 },
                    })),
                    Box::new(Expr::Op(IrNode {
                        opcode: 0x72,
                        payload: Payload::ValUse { id: 1 },
                    })),
                ),
            })
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn lambda_arg_shadows_enclosing_val() {
        // The inner `x` must resolve to the lambda arg (id 2), not the
        // enclosing val (id 1) — innermost-frame-first lookup, mirroring the
        // typer's `lambdaEnv = env ++ args` overwrite (SigmaTyper.scala:128).
        let ir = emit_tc("{ val x = 5L; col1.map({(x: Long) => x}) }");
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        let Expr::Op(IrNode {
            payload: Payload::Two(_, f),
            ..
        }) = result.as_ref()
        else {
            panic!("expected MapCollection result, got {result:?}");
        };
        let Expr::Op(IrNode {
            payload: Payload::FuncValue { body, .. },
            ..
        }) = f.as_ref()
        else {
            panic!("expected FuncValue, got {f:?}");
        };
        assert_eq!(
            body.as_ref(),
            &Expr::Op(IrNode {
                opcode: 0x72,
                payload: Payload::ValUse { id: 2 },
            }),
            "inner x resolves to the lambda arg"
        );
        wire_roundtrip(&ir);
    }

    #[test]
    fn apply_of_val_bound_lambda_emits_funcapply_and_roundtrips() {
        // `f(2)` where f is a val-bound lambda → FuncApply(ValUse, [2]).
        let ir = emit_tc("{ val f = {(x: Int) => x + 1}; f(2) }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0xDA,
                payload: Payload::FuncApply { func, args },
            }) => {
                assert_eq!(
                    func.as_ref(),
                    &Expr::Op(IrNode {
                        opcode: 0x72,
                        payload: Payload::ValUse { id: 2 },
                    }),
                    "callee is the val's ValUse (lambda arg took id 1 — \
                     rhs is emitted before the ValDef id is taken, \
                     TreeBuilding.scala:511-513 ordering)"
                );
                assert_eq!(args.len(), 1);
            }
            other => panic!("expected FuncApply result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn outputs_and_coll_index_emit_byindex_and_roundtrip() {
        // Apply-on-Coll is lowered to ByIndex at typer time
        // (SigmaTyper.scala:261-277 port); emit passes it through 0xB2.
        rt_op("OUTPUTS(0)", 0xB2);
        rt_op("col1(0)", 0xB2);
    }

    #[test]
    fn byte_index_from_frontend_carries_single_typer_upcast() {
        // golden_seed §"{ val i = 1.toByte; Coll(1, 2, 3)(i) }": the TYPER
        // already wraps the Byte index in Upcast(SInt); emit_index must not
        // double-wrap (the emitted index node's type is already SInt).
        let ir = emit_tc("{ val i = 1.toByte; Coll(1, 2, 3)(i) }");
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0xB2,
                payload: Payload::ByIndex { index, .. },
            }) => match index.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { input, tpe },
                }) => {
                    assert_eq!(tpe, &SigmaType::SInt);
                    assert_eq!(
                        root_opcode(input),
                        0x72,
                        "exactly ONE Upcast layer over the ValUse"
                    );
                }
                other => panic!("expected a single Upcast, got {other:?}"),
            },
            other => panic!("expected ByIndex result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn tuple_dynamic_index_emits_byindex_per_committed_record() {
        // golden_seed §23(b): a non-constant tuple index typechecks to
        // ByIndex:Any over the Tuple value (STuple extends SCollection[SAny]).
        let ir = emit_tc("{ val i = HEIGHT; (1, 2)(i) }");
        assert_eq!(root_opcode(&ir), 0xD8);
        let Expr::Op(IrNode {
            payload: Payload::BlockValue { result, .. },
            ..
        }) = &ir
        else {
            panic!("expected BlockValue, got {ir:?}");
        };
        match result.as_ref() {
            Expr::Op(IrNode {
                opcode: 0xB2,
                payload: Payload::ByIndex { input, index, .. },
            }) => {
                assert_eq!(root_opcode(input), 0x86, "Tuple input");
                assert_eq!(root_opcode(index), 0x72, "ValUse index (Int, no cast)");
            }
            other => panic!("expected ByIndex result, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn select_box_properties_emit_extract_opcodes() {
        // GraphBuilding.scala:541-549 property → Extract* mapping.
        for (src, opcode) in [
            ("SELF.value", 0xC1),
            ("SELF.propositionBytes", 0xC2),
            ("SELF.bytes", 0xC3),
            ("SELF.bytesWithoutRef", 0xC4),
            ("SELF.id", 0xC5),
            ("SELF.creationInfo", 0xC7),
        ] {
            rt_op(src, opcode);
        }
    }

    #[test]
    fn select_register_emits_extract_register_as_with_inner_type() {
        // `SELF.R4[Long]` → ExtractRegisterAs(reg 4) with the INNER type on
        // the wire (Scala serializer writes `obj.tpe.elemType`,
        // ExtractRegisterAsSerializer.scala serialize).
        let ir = emit_tc("SELF.R4[Long]");
        assert_eq!(root_opcode(&ir), 0xC6);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ExtractRegisterAs { reg_id, tpe, .. },
                ..
            }) => {
                assert_eq!(*reg_id, 4);
                assert_eq!(tpe, &SigmaType::SLong, "inner type, not SOption");
            }
            other => panic!("expected ExtractRegisterAs, got {other:?}"),
        }
        wire_roundtrip(&ir);
        // Composite: `.get` over the register read → OptionGet root.
        rt_op("SELF.R4[Long].get", 0xE4);
        // R0 and R9 bound registers.
        for (src, reg) in [("SELF.R0[Long]", 0u8), ("SELF.R9[Int]", 9u8)] {
            let ir = emit_tc(src);
            match &ir {
                Expr::Op(IrNode {
                    payload: Payload::ExtractRegisterAs { reg_id, .. },
                    ..
                }) => assert_eq!(*reg_id, reg, "{src}"),
                other => panic!("{src}: expected ExtractRegisterAs, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
    }

    #[test]
    fn method_call_get_reg_emits_explicit_type_arg() {
        // `SELF.getReg[Int](HEIGHT)` (DYNAMIC index — a literal index lowers
        // to ExtractRegisterAs since wave 2) → MethodCall 0xDC (99, 19) with
        // one value arg and the explicit `[T]` type block (ergo-ser
        // method_explicit_type_args_count(99, 19) == 1). Oracle keeps the
        // MethodCall for the dynamic form too (`cc sigmaProp(SELF.getReg[
        // Int](HEIGHT).isDefined)` → body `…dc6313a701a304`, 2026-07-07 ×3).
        let ir = emit_tc("SELF.getReg[Int](HEIGHT)");
        assert_eq!(root_opcode(&ir), 0xDC);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::MethodCall {
                        type_id,
                        method_id,
                        args,
                        type_args,
                        ..
                    },
                ..
            }) => {
                assert_eq!((*type_id, *method_id), (99, 19));
                assert_eq!(args.len(), 1);
                assert_eq!(type_args, &vec![SigmaType::SInt]);
            }
            other => panic!("expected MethodCall payload, got {other:?}"),
        }
        assert_eq!(hex::encode(wire_roundtrip(&ir)), "dc6313a701a304");
        // Composite: OptionGet over the MethodCall.
        rt_op("SELF.getReg[Int](HEIGHT).get", 0xE4);
    }

    #[test]
    fn property_call_none_emits_type_arg_without_args() {
        // `Global.none[Int]()` → PropertyCall 0xDB (106, 10): zero value
        // args but STILL one explicit type arg on the wire (the ergo-ser
        // PropertyCall arm reads the same type block).
        let ir = emit_tc("Global.none[Int]()");
        assert_eq!(root_opcode(&ir), 0xDB);
        match &ir {
            Expr::Op(IrNode {
                payload:
                    Payload::MethodCall {
                        type_id,
                        method_id,
                        args,
                        type_args,
                        ..
                    },
                ..
            }) => {
                assert_eq!((*type_id, *method_id), (106, 10));
                assert!(args.is_empty());
                assert_eq!(type_args, &vec![SigmaType::SInt]);
            }
            other => panic!("expected MethodCall payload, got {other:?}"),
        }
        wire_roundtrip(&ir);
    }

    #[test]
    fn residual_method_calls_emit_wire_ids_and_roundtrip() {
        // Property/method calls the M2 lowering leaves as MethodCall:
        // context/avltree/group-element properties and Global v6 methods.
        for (src, opcode, ids) in [
            ("CONTEXT.dataInputs", 0xDB, (101u8, 1u8)),
            ("CONTEXT.preHeader", 0xDB, (101, 3)),
            ("LastBlockUtxoRootHash.digest", 0xDB, (100, 1)),
            ("g1.getEncoded", 0xDB, (7, 2)),
            // v3 concrete %Int.toBytes — NON-constant receiver (a constant
            // one folds since wave 2, gate (d) in emit_method_call).
            ("HEIGHT.toBytes", 0xDB, (4, 6)),
            ("Global.serialize(HEIGHT)", 0xDC, (106, 3)),
        ] {
            let ir = emit_tc(src);
            assert_eq!(root_opcode(&ir), opcode, "{src}");
            match &ir {
                Expr::Op(IrNode {
                    payload:
                        Payload::MethodCall {
                            type_id, method_id, ..
                        },
                    ..
                }) => assert_eq!((*type_id, *method_id), ids, "{src}"),
                other => panic!("{src}: expected MethodCall payload, got {other:?}"),
            }
            wire_roundtrip(&ir);
        }
        // Chained: PreHeader property over a Context property.
        rt_op("CONTEXT.preHeader.height", 0xDB);
    }

    #[test]
    fn hand_built_mixed_relation_gets_upcast_inserted() {
        // Frontend trees carry typer-inserted Upcasts already; a hand-built
        // mixed GT exercises emit's own normalization
        // (comparisonOp → applyUpcast, SigmaBuilder.scala:688-697).
        let node = TypedExpr::GT {
            left: Box::new(int_c(1)),
            right: Box::new(long_c(2)),
            tpe: SType::SBoolean,
        };
        let ir = rt_node(&node, 0x91);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, right),
                ..
            }) => {
                assert_eq!(root_opcode(left), 0x7E, "narrower Int side upcast");
                assert!(matches!(right.as_ref(), Expr::Const { .. }));
            }
            other => panic!("expected Two payload, got {other:?}"),
        }
        // Mirror case: narrower side on the right.
        let node = TypedExpr::ArithOp {
            left: Box::new(long_c(2)),
            right: Box::new(int_c(1)),
            opcode: crate::typed::ARITH_PLUS,
            tpe: SType::SLong,
        };
        let ir = rt_node(&node, 0x9A);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::Two(left, right),
                ..
            }) => {
                assert!(matches!(left.as_ref(), Expr::Const { .. }));
                assert_eq!(root_opcode(right), 0x7E, "narrower Int side upcast");
            }
            other => panic!("expected Two payload, got {other:?}"),
        }
    }

    #[test]
    fn hand_built_mixed_bit_op_rejects_like_frontend_ones() {
        // Mixed-width bit ops reject the same as same-width ones — Scala's
        // GraphBuilding has no BitOp arm at ANY width (oracle: `cc
        // sigmaProp((1 | 2L) == 3L)` → `REJECT 1:12 GraphBuildingException`,
        // compile_seed.json).
        use crate::typed::BIT_OR;
        let node = TypedExpr::BitOp {
            left: Box::new(int_c(1)),
            right: Box::new(long_c(2)),
            opcode: BIT_OR,
            tpe: SType::SLong,
        };
        assert!(matches!(
            emit(&node),
            Err(EmitError::GraphBuildingReject { .. })
        ));
    }

    #[test]
    fn hand_built_byte_index_gets_upcast_to_int() {
        // Defensive emit_index normalization (SigmaTyper.scala:265-288
        // `typedIndex.upcastTo(SInt)`) for a hand-built narrow index.
        let node = TypedExpr::ByIndex {
            input: Box::new(byte_coll_c(vec![1, 2])),
            index: Box::new(TypedExpr::Constant {
                value: ConstPayload::Byte(1),
                tpe: SType::SByte,
            }),
            default: None,
            tpe: SType::SByte,
        };
        let ir = rt_node(&node, 0xB2);
        match &ir {
            Expr::Op(IrNode {
                payload: Payload::ByIndex { index, .. },
                ..
            }) => match index.as_ref() {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { tpe, .. },
                }) => assert_eq!(tpe, &SigmaType::SInt),
                other => panic!("expected Upcast index, got {other:?}"),
            },
            other => panic!("expected ByIndex, got {other:?}"),
        }
    }

    #[test]
    fn mixed_width_arith_relation_frontend_roundtrips() {
        // `(1 + 2L) == 3L`: the typer inserts the Upcast; emit's
        // normalization is a no-op on the already-normalized tree.
        let ir = emit_tc("(1 + 2L) == 3L");
        assert_eq!(root_opcode(&ir), 0x93);
        wire_roundtrip(&ir);
    }

    // ----- error paths -----

    #[test]
    fn create_avl_tree_returns_unsupported_node() {
        // ergo-ser parses 0xB6 as Zero (deprecated AvlTreeCode) while Scala
        // 6.0.2 registers CreateAvlTreeSerializer (Four) on the same byte —
        // resolved toward ergo-ser (module docs + lib.rs ledger).
        let node = TypedExpr::CreateAvlTree {
            operation_flags: Box::new(TypedExpr::Constant {
                value: ConstPayload::Byte(0),
                tpe: SType::SByte,
            }),
            digest: Box::new(byte_coll_c(vec![0; 33])),
            key_length: Box::new(int_c(1)),
            value_length_opt: Box::new(int_c(1)),
            tpe: SType::SAvlTree,
        };
        assert_eq!(
            emit(&node).unwrap_err(),
            EmitError::UnsupportedNode("CreateAvlTree".to_string())
        );
    }

    #[test]
    fn zk_proof_block_returns_unsupported_node() {
        let node = TypedExpr::ZKProofBlock {
            body: Box::new(tc("proveDlog(g1)")),
            tpe: SType::SBoolean,
        };
        assert_eq!(
            emit(&node).unwrap_err(),
            EmitError::UnsupportedNode("ZKProofBlock".to_string())
        );
    }

    #[test]
    fn opaque_sigma_prop_constant_returns_unsupported_node() {
        // An env-injected opaque SigmaProp label has no curve bytes to
        // serialize (lib.rs ledger; only reachable from a hand-built env).
        let err = map_const(
            &ConstPayload::SigmaProp("p1".to_string()),
            &SType::SSigmaProp,
        )
        .unwrap_err();
        assert!(matches!(err, EmitError::UnsupportedNode(_)));
    }

    #[test]
    fn apply_types_and_method_call_like_return_invalid_shape() {
        // Pre-typed-only nodes: the typer eliminates both before returning
        // (typed.rs docs) — reaching emit is a pipeline bug, not a scope gap.
        let at = TypedExpr::ApplyTypes {
            input: Box::new(int_c(1)),
            type_args: vec![SType::SInt],
            tpe: SType::SInt,
        };
        assert!(matches!(emit(&at).unwrap_err(), EmitError::InvalidShape(_)));
        let mcl = TypedExpr::MethodCallLike {
            obj: Box::new(int_c(1)),
            name: "+".to_string(),
            args: vec![int_c(2)],
            tpe: SType::NoType,
        };
        assert!(matches!(
            emit(&mcl).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn map_type_notype_and_stypeapply_return_unresolved_type() {
        assert!(matches!(
            map_type(&SType::NoType).unwrap_err(),
            EmitError::UnresolvedType(_)
        ));
        assert!(matches!(
            map_type(&SType::STypeApply {
                name: "Coll".to_string(),
                args: vec![SType::SInt],
            })
            .unwrap_err(),
            EmitError::UnresolvedType(_)
        ));
    }

    #[test]
    fn tuple_arity_out_of_bounds_returns_invalid_shape() {
        // The ergo-ser writer asserts (panics) past 255 items and a 1-tuple
        // is not a Scala STuple; emit guards both as recoverable errors.
        let one = TypedExpr::Tuple {
            items: vec![int_c(1)],
            tpe: SType::STuple(vec![SType::SInt]),
        };
        assert!(matches!(
            emit(&one).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
        let many = TypedExpr::Tuple {
            items: (0..256).map(int_c).collect(),
            tpe: SType::STuple(vec![SType::SInt; 256]),
        };
        assert!(matches!(
            emit(&many).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn get_var_with_non_option_type_returns_invalid_shape() {
        // GetVar's node type must be SOption(V) (transformers.scala:576);
        // anything else means the typer broke its own invariant.
        let node = TypedExpr::GetVar {
            var_id: 1,
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn lambda_without_body_returns_invalid_shape() {
        // `body: None` only occurs in pre-typed trees (binder invariant); a
        // FuncValue cannot be serialized without a body.
        let node = TypedExpr::Lambda {
            tpe_params: vec![],
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::SInt,
            body: None,
            tpe: SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SInt),
                tpe_params: vec![],
            },
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn lambda_with_type_params_returns_invalid_shape() {
        // The wire FuncValue has no type-param block; the binder enforces
        // `!(tpeParams.nonEmpty && body.nonEmpty)` upstream.
        let node = TypedExpr::Lambda {
            tpe_params: vec![crate::typed::STypeParam {
                ident: "T".to_string(),
            }],
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::SInt,
            body: Some(Box::new(int_c(1))),
            tpe: SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SInt),
                tpe_params: vec![],
            },
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn unbound_ident_returns_invalid_shape() {
        let node = TypedExpr::Ident {
            name: "ghost".to_string(),
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn val_node_outside_block_returns_invalid_shape() {
        // A bare top-level `val` is a PARSE reject (golden_seed §25), so a
        // root ValNode can only be hand-built — a pipeline bug surface.
        let node = TypedExpr::ValNode {
            name: "x".to_string(),
            given_type: SType::SInt,
            body: Box::new(int_c(1)),
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn block_with_non_val_binding_returns_invalid_shape() {
        let node = TypedExpr::Block {
            bindings: vec![int_c(1)],
            result: Box::new(int_c(2)),
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn residual_select_returns_unsupported_node_naming_the_field() {
        // Outside the lowering catalog → UnsupportedNode carrying the field
        // name (the Task-11 adversarial pass greps for these).
        let node = TypedExpr::Select {
            obj: Box::new(tc("SELF")),
            field: "getRegV5".to_string(),
            res_type: None,
            tpe: SType::SInt,
        };
        match emit(&node).unwrap_err() {
            EmitError::UnsupportedNode(msg) => {
                assert!(msg.contains("getRegV5"), "message names the field: {msg}")
            }
            other => panic!("expected UnsupportedNode, got {other:?}"),
        }
        // Bare `SELF.R4` (function-typed, no `[T]`) is also residual: the
        // register arm requires a resolved Option res_type.
        let bare_reg = tc("SELF.R4");
        match emit(&bare_reg).unwrap_err() {
            EmitError::UnsupportedNode(msg) => {
                assert!(msg.contains("R4"), "message names the field: {msg}")
            }
            other => panic!("expected UnsupportedNode, got {other:?}"),
        }
    }

    #[test]
    fn method_call_with_unknown_owner_returns_unsupported_node() {
        use crate::typed::MethodRef;
        let node = TypedExpr::MethodCall {
            obj: Box::new(int_c(1)),
            method: MethodRef {
                owner: "?".to_string(),
                name: "mystery".to_string(),
            },
            args: vec![],
            type_subst: vec![],
            tpe: SType::SInt,
        };
        match emit(&node).unwrap_err() {
            EmitError::UnsupportedNode(msg) => assert!(
                msg.contains("?.mystery"),
                "message names owner.method: {msg}"
            ),
            other => panic!("expected UnsupportedNode, got {other:?}"),
        }
    }

    #[test]
    fn method_call_missing_explicit_type_binding_returns_invalid_shape() {
        // getReg (99,19) requires a `{T -> _}` binding for its wire type arg.
        use crate::typed::MethodRef;
        let node = TypedExpr::MethodCall {
            obj: Box::new(tc("SELF")),
            method: MethodRef {
                owner: "Box".to_string(),
                name: "getReg".to_string(),
            },
            args: vec![int_c(4)],
            type_subst: vec![],
            tpe: SType::SOption(Box::new(SType::SInt)),
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn zero_arg_method_call_of_args_method_returns_invalid_shape() {
        // %SCollection.slice with an empty arg list would serialize as a
        // PropertyCall that deserializes to a different invocation.
        use crate::typed::MethodRef;
        let node = TypedExpr::MethodCall {
            obj: Box::new(tc("col1")),
            method: MethodRef {
                owner: "SCollection".to_string(),
                name: "slice".to_string(),
            },
            args: vec![],
            type_subst: vec![],
            tpe: scoll(SType::SLong),
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::InvalidShape(_)
        ));
    }

    #[test]
    fn apply_on_non_callable_returns_unsupported_node() {
        let node = TypedExpr::Apply {
            func: Box::new(int_c(1)),
            args: vec![int_c(2)],
            tpe: SType::SInt,
        };
        assert!(matches!(
            emit(&node).unwrap_err(),
            EmitError::UnsupportedNode(_)
        ));
    }

    // ----- oracle parity -----

    #[test]
    fn standalone_top_level_val_rejects_matching_oracle() {
        // golden_seed §25 (live capture 2026-07-05): `tc val x = 1` →
        // `REJECT 1:1 ParserException`. Emit never sees a ValNode root from
        // the frontend because the parse already rejects.
        let err = typecheck(&demo_env(), "val x = 1", 3).unwrap_err();
        assert_eq!(err.class(), "ParserException");
    }

    #[test]
    fn sigma_prop_true_emits_boolean_via_constant_path() {
        // Oracle capture (module docs): `cc sigmaProp(true)` →
        // `10 01 0101 d1 7300` — the Boolean rides the CONSTANT path
        // (segregated 0101 table entry + placeholder), not opcode 0x7F.
        // Pre-segregation (Task 7) the same constant is inline: d1 01 01.
        let ir = emit_tc("sigmaProp(true)");
        assert_eq!(
            ir,
            Expr::Op(IrNode {
                opcode: 0xD1,
                payload: Payload::One(Box::new(Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(true),
                })),
            })
        );
        let bytes = wire_roundtrip(&ir);
        assert_eq!(bytes, vec![0xD1, 0x01, 0x01]);
    }

    #[test]
    fn sigma_prop_height_gt_100_inline_bytes_match_oracle_constant_bytes() {
        // Oracle capture: `cc sigmaProp(HEIGHT > 100)` →
        // `10 01 04c801 d191a37300` (segregated). The inline Task-7 body is
        // the same opcode spine with the constant bytes `04 c8 01` in place
        // of the placeholder: d1 91 a3 04c801.
        let bytes = wire_roundtrip(&emit_tc("sigmaProp(HEIGHT > 100)"));
        assert_eq!(bytes, vec![0xD1, 0x91, 0xA3, 0x04, 0xC8, 0x01]);
    }
}
