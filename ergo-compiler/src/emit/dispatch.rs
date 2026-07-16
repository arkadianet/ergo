use std::collections::HashMap;

use ergo_ser::opcode::{Expr, IrNode, Payload};

use crate::stype::SType;
use crate::typed::{node_tpe, MethodRef, TypedExpr};

use super::*;

impl Scope {
    pub(crate) fn emit(&mut self, expr: &TypedExpr) -> Result<Expr, EmitError> {
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

            // ── (D-C7): bare `LastBlockUtxoRootHash` and bare/dotted `groupGenerator`
            //    are NOT `IsContextProperty`-recognized primitives on the
            //    Scala side (unlike Height/Inputs/Outputs/Self/MinerPubkey) —
            //    buildTree's fallback re-materializes both as PropertyCalls.
            //    Oracle-confirmed (`ORACLE_TREE_VERSION=3`):
            //    `LastBlockUtxoRootHash.digest.size` and
            //    `CONTEXT.LastBlockUtxoRootHash.digest.size` both reply
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
                // Verdict parity with the FULL Scala compiler:
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
                // Two distinct reasons an Ident can be unbound here, and they
                // must NOT be conflated (D-C8):
                //
                // 1. `name` is a KNOWN predef function (`allZK`/`anyZK`/
                //    `outerJoin` — `predef_ir.rs`'s `predefined_env`) whose
                //    Scala `irBuilder` is the literal `PredefFuncInfo(undefined)`
                //    sentinel (SigmaPredef.scala:79-92/108-123) — genuinely
                //    UNIMPLEMENTED in the reference compiler itself, not a gap
                //    in this port. `predef_ir_builder` mirrors that with a
                //    `None` fall-through, so the typed tree keeps the raw
                //    `Apply(Ident, args)` shape all the way here — BYTE-
                //    IDENTICAL to the oracle's own `tce`/`tcs` residual. Scala's
                //    `compiler.compile` (the `cc`/`cce`/`ccs` verbs this
                //    crate's `compile()` mirrors) reaches `GraphBuilding.eval`'s
                //    `Ident` case, `env.getOrElse(n, !!!(...))`, which throws
                //    unconditionally (`n` was never bound as a lambda arg or
                //    block val) — a `StagingException`. Oracle-confirmed:
                //    literal single-/multi-element `Coll` AND a val-bound
                //    `Coll` all REJECT identically for both `allZK`/`anyZK` —
                //    there is no accepting form, not even the "literal Coll
                //    unwraps to SigmaAnd/SigmaOr" shape this port used to
                //    assume (that unwrap only fires for the `&&`/`||`
                //    OPERATOR route, which builds a `SigmaAnd`/`SigmaOr` node
                //    directly and never passes through `PredefinedFuncApply`
                //    at all). This is a real, user-reachable REJECT —
                //    reported as such, not as an internal pipeline bug.
                // 2. Anything else: the binder substitutes env values as
                //    Constants and the typer only emits Ident for in-scope
                //    val/lambda-arg names or (1) above, so any OTHER unbound
                //    Ident is a genuine pipeline bug.
                None => match self.placeholders.get(name) {
                    // M7: a contract named parameter → ConstantPlaceholder(index)
                    // (opcode 0x73; SigmaCompiler.scala:88-92). The wire type is
                    // recovered from the template's `constTypes` on read
                    // (ConstantPlaceholderSerializer parity), so only the index
                    // is emitted.
                    Some(index) => node(0x73, Payload::ConstPlaceholder { index: *index }),
                    None => match known_predef_gap(name) {
                        Some(what) => Err(EmitError::GraphBuildingReject {
                            class: "StagingException",
                            what: format!(
                                "predef function `{what}` has no compile-time lowering \
                                 (Scala SigmaPredef irBuilder = undefined; GraphBuilding's \
                                 Ident eval throws for an unbound predef name)"
                            ),
                        }),
                        None => Err(EmitError::InvalidShape(
                            "Ident not bound to any enclosing ValDef or lambda arg",
                        )),
                    },
                },
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
    pub(crate) fn emit_block(
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
    /// the ergo-ser writer panics on a type-less arg (write.rs FuncValue arm).
    pub(crate) fn emit_lambda(
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
    pub(crate) fn emit_apply(
        &mut self,
        func: &TypedExpr,
        args: &[TypedExpr],
    ) -> Result<Expr, EmitError> {
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
}
