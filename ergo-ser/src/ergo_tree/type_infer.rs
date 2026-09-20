//! Exact substitution type inference: a faithful replica of Scala's parse-order
//! `valDefTypeStore` plus expression types mirrored from Scala's
//! deserialize-time `Value.tpe` derivation.
//! Oracle: scripts/jvm_serde_oracle/MethodTypes.scala
//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/deserialize-types.json.gz

mod method_registry;

use super::root_type::{type_is_precise, ValDefTypeStore};

/// Exact static type for embedded-script substitution. Unknown types and
/// imprecision sentinels cannot establish substitution compatibility.
pub fn substitution_type_of(body: &crate::opcode::Expr) -> Option<crate::sigma_type::SigmaType> {
    let mut store = ValDefTypeStore::new();
    infer_type(body, &mut store, &[]).filter(type_is_precise)
}

/// Infer each node once, visiting all children in wire order before computing
/// its result. Unknown bindings and box-induced store pollution return `None`;
/// substitution rejects these types. A box constant's nested script can mutate
/// Scala's shared binding store, so entries predating that constant become
/// unknown; later explicit bindings become trusted again.
fn infer_type(
    body: &crate::opcode::Expr,
    store: &mut ValDefTypeStore,
    constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
) -> Option<crate::sigma_type::SigmaType> {
    super::root_type::infer_node_type(body, store, constants, true, false, &mut infer_type)
}

/// Specialize the JVM-extracted signature using Scala's directional unification.
/// A failed unification leaves the template unchanged (SMethod.specializeFor).
pub(super) fn method_call_result_type(
    type_id: u8,
    method_id: u8,
    obj_type: Option<crate::sigma_type::SigmaType>,
    arg_types: &[Option<crate::sigma_type::SigmaType>],
    type_args: &[crate::sigma_type::SigmaType],
) -> Option<crate::sigma_type::SigmaType> {
    use crate::sigma_type::SigmaType;
    let (signature, explicit) = method_registry::signature(type_id, method_id)?;
    let mut subst = std::collections::HashMap::new();
    for (param, arg) in explicit.iter().zip(type_args) {
        if let SigmaType::STypeVar(name) = param {
            subst.insert(name.clone(), arg.clone());
        }
    }
    let signature = apply_type_subst(&signature, &subst);
    let SigmaType::SFunc { t_dom, t_range, .. } = signature else {
        return None;
    };
    let actual: Option<Vec<_>> = std::iter::once(obj_type)
        .chain(arg_types.iter().cloned())
        .collect();
    let actual = actual?;
    subst.clear();
    if unify_type_lists(&t_dom, &actual, &mut subst) {
        Some(apply_type_subst(&t_range, &subst))
    } else {
        Some(*t_range)
    }
}

type TypeSubst = std::collections::HashMap<String, crate::sigma_type::SigmaType>;

fn apply_type_subst(
    t: &crate::sigma_type::SigmaType,
    subst: &TypeSubst,
) -> crate::sigma_type::SigmaType {
    use crate::sigma_type::SigmaType::*;
    match t {
        STypeVar(name) => subst.get(name).cloned().unwrap_or_else(|| t.clone()),
        SColl(e) => SColl(Box::new(apply_type_subst(e, subst))),
        SOption(e) => SOption(Box::new(apply_type_subst(e, subst))),
        STuple(items) => STuple(items.iter().map(|t| apply_type_subst(t, subst)).collect()),
        SFunc {
            t_dom,
            t_range,
            tpe_params,
        } => SFunc {
            t_dom: t_dom.iter().map(|t| apply_type_subst(t, subst)).collect(),
            t_range: Box::new(apply_type_subst(t_range, subst)),
            tpe_params: tpe_params
                .iter()
                .filter(|t| !matches!(t, STypeVar(n) if subst.contains_key(n)))
                .cloned()
                .collect(),
        },
        _ => t.clone(),
    }
}

/// Scala zips domains without an arity check; nested tuples/functions check lengths.
fn unify_type_lists(
    a: &[crate::sigma_type::SigmaType],
    b: &[crate::sigma_type::SigmaType],
    subst: &mut TypeSubst,
) -> bool {
    a.iter().zip(b).all(|(a, b)| unify_types(a, b, subst))
}

fn unify_types(
    a: &crate::sigma_type::SigmaType,
    b: &crate::sigma_type::SigmaType,
    subst: &mut TypeSubst,
) -> bool {
    use crate::sigma_type::SigmaType::*;
    match (a, b) {
        (STypeVar(a), STypeVar(b)) => a == b,
        (STypeVar(name), t) => match subst.get(name) {
            Some(previous) => previous == t,
            None => {
                subst.insert(name.clone(), t.clone());
                true
            }
        },
        (SColl(a), SColl(b)) | (SOption(a), SOption(b)) => unify_types(a, b, subst),
        (SColl(a), STuple(_)) => unify_types(a, &SAny, subst),
        (STuple(a), STuple(b)) => a.len() == b.len() && unify_type_lists(a, b, subst),
        (
            SFunc {
                t_dom: a,
                t_range: ar,
                ..
            },
            SFunc {
                t_dom: b,
                t_range: br,
                ..
            },
        ) => a.len() == b.len() && unify_type_lists(a, b, subst) && unify_types(ar, br, subst),
        (SBoolean, SSigmaProp) | (SAny, _) => true,
        _ => a == b,
    }
}

/// Fixed-result opcode types from the pinned Scala AST declarations.
pub(super) fn op_result_type(opcode: u8) -> Option<crate::sigma_type::SigmaType> {
    if matches!(opcode, 0x98 | 0xCD | 0xCE | 0xD1 | 0xEA | 0xEB) {
        return Some(crate::sigma_type::SigmaType::SSigmaProp);
    }
    use crate::sigma_type::SigmaType::*;
    match opcode {
        0x8F..=0x94
        | 0x96
        | 0x97
        | 0xAE
        | 0xAF
        | 0xCF
        | 0xE6
        | 0xEC
        | 0xED
        | 0xEF
        | 0xF4
        | 0xFF => Some(SBoolean),
        0xB1 => Some(SInt),
        0x7C | 0xC1 => Some(SLong),
        0x7B | 0xE7..=0xE9 => Some(SBigInt),
        0x9F | 0xA0 | 0xEE => Some(SGroupElement),
        0x74 | 0x7A | 0x9B | 0xC2..=0xC5 | 0xCB | 0xCC | 0xD0 => Some(SColl(Box::new(SByte))),
        0xC7 => Some(STuple(vec![SInt, SColl(Box::new(SByte))])),
        // CreateAvlTreeSerializer reads four expressions; trees.scala:83 returns SAvlTree.
        0xB6 => Some(SAvlTree),
        0xB7 => Some(SOption(Box::new(SColl(Box::new(SByte))))),
        _ => None,
    }
}

/// Statically-known result type of a zero-argument (leaf) ErgoTree opcode. EVERY
/// leaf in the parser's table is non-`SSigmaProp`: `True`/`False` → `SBoolean`,
/// `GroupGenerator` → `SGroupElement`, `Height` → `SInt`, `Inputs`/`Outputs` →
/// `Coll[SBox]`, `LastBlockUtxoRootHash` → `SAvlTree`, `Self` → `SBox`,
/// `MinerPubkey` → `Coll[SByte]`, `Global` → `SGlobal`, `Context` → `SContext`.
/// (A `SigmaProp`-producing op — `ProveDlog`, `BoolToSigmaProp`, `SigmaAnd`, … —
/// always takes arguments, so it is never a `Zero` leaf.) An unrecognized leaf
/// falls back to `SAny`, which cannot establish substitution compatibility.
pub(super) fn zero_arg_type(opcode: u8) -> crate::sigma_type::SigmaType {
    use crate::sigma_type::SigmaType::*;
    match opcode {
        0x7F | 0x80 => SBoolean,              // True / False
        0x82 => SGroupElement,                // GroupGenerator
        0xA3 => SInt,                         // Height
        0xA4 | 0xA5 => SColl(Box::new(SBox)), // Inputs / Outputs
        0xA6 => SAvlTree,                     // LastBlockUtxoRootHash
        0xA7 => SBox,                         // Self
        0xAC => SColl(Box::new(SByte)),       // MinerPubkey
        0xDD => SGlobal,                      // Global
        0xFE => SContext,                     // Context
        _ => SAny,                            // deprecated/unknown leaf — still non-SigmaProp
    }
}

#[cfg(test)]
mod tests {
    //! Focused unit tests for the parse-order `valDefTypeStore` replica: the
    //! duplicate-binding-id accept/reject boundary (Finding E). Every verdict
    //! below is pinned by the live-oracle probe set in
    //! `ergo-difftest/src/oracle.rs`
    //! (`valdef_type_store_shapes_match_jvm_oracle`).

    use super::{infer_type, ValDefTypeStore};
    use crate::opcode::{Expr, IrNode, Payload};
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{SigmaBoolean, SigmaValue};

    // ----- helpers -----

    fn op(opcode: u8, payload: Payload) -> Expr {
        Expr::Op(IrNode { opcode, payload })
    }
    fn long0() -> Expr {
        Expr::Const {
            tpe: SigmaType::SLong,
            val: SigmaValue::Long(0),
        }
    }
    fn sigma_const() -> Expr {
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        }
    }
    fn box_const() -> Expr {
        Expr::Const {
            tpe: SigmaType::SBox,
            val: SigmaValue::OpaqueBoxBytes(vec![]),
        }
    }
    fn val_def(id: u32, rhs: Expr) -> Expr {
        op(
            0xD6,
            Payload::ValDef {
                id,
                tpe: None,
                rhs: Box::new(rhs),
            },
        )
    }
    fn fun_def(id: u32, rhs: Expr) -> Expr {
        op(
            0xD7,
            Payload::FunDef {
                id,
                tpe: None,
                tpe_args: vec![SigmaType::STypeVar("T".into())],
                rhs: Box::new(rhs),
            },
        )
    }
    fn val_use(id: u32) -> Expr {
        op(0x72, Payload::ValUse { id })
    }
    fn block(items: Vec<Expr>, result: Expr) -> Expr {
        op(
            0xD8,
            Payload::BlockValue {
                items,
                result: Box::new(result),
            },
        )
    }
    fn func_value(args: Vec<(u32, Option<SigmaType>)>, body: Expr) -> Expr {
        op(
            0xD9,
            Payload::FuncValue {
                args,
                body: Box::new(body),
            },
        )
    }
    fn exact_type_for_test(
        body: &crate::opcode::Expr,
        constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
    ) -> Option<crate::sigma_type::SigmaType> {
        infer_type(body, &mut ValDefTypeStore::new(), constants)
    }

    fn exact(body: &Expr) -> Option<SigmaType> {
        exact_type_for_test(body, &[])
    }

    // ----- oracle parity -----

    /// `{ val x = 0L; val x = 0L; x }`
    /// resolves the root `ValUse` from the last store write (SLong) → the gate
    /// rejects, as Scala does. And last-write-wins in the ACCEPT direction:
    /// `{ val x = 0L; val x = sigma; x }` is SigmaProp (a first-write-wins bug
    /// would reject-valid it).
    #[test]
    fn duplicate_id_valuse_resolves_to_last_parse_order_write() {
        let dup = block(vec![val_def(1, long0()), val_def(1, long0())], val_use(1));
        assert_eq!(exact(&dup), Some(SigmaType::SLong));

        let last_sigma = block(
            vec![val_def(1, long0()), val_def(1, sigma_const())],
            val_use(1),
        );
        assert_eq!(exact(&last_sigma), Some(SigmaType::SSigmaProp));
    }

    /// THE GUARDRAIL (a reject here = reject-valid = chain stall):
    /// `{ val x = sigma; val y = x; val x = 0L; y }` MUST classify SigmaProp —
    /// `y`'s rhs `ValUse(x)` reads the store BEFORE the rebind, exactly as
    /// Scala's `ValDefSerializer.parse` does (oracle ACCEPT).
    #[test]
    fn guardrail_forward_reference_fixed_before_rebind_stays_sigma() {
        let guardrail = block(
            vec![
                val_def(1, sigma_const()),
                val_def(2, val_use(1)),
                val_def(1, long0()),
            ],
            val_use(2),
        );
        assert_eq!(exact(&guardrail), Some(SigmaType::SSigmaProp));
    }

    /// Off-spine and scope-boundary rebinds all reach the flat store in parse
    /// order (oracle REJECT for each — the node was unknown-ACCEPT pre-fix):
    /// a rebind nested in a later item's rhs; a `FuncValue` ARG declaration; a
    /// rebind inside a `FuncValue` BODY (no scoping/popping); a `FunDef` write.
    #[test]
    fn off_spine_and_boundary_rebinds_reach_the_store() {
        // { val x = sigma; val d = { val x = 0L; 0L }; x } -> SLong.
        let offspine = block(
            vec![
                val_def(1, sigma_const()),
                val_def(2, block(vec![val_def(1, long0())], long0())),
            ],
            val_use(1),
        );
        assert_eq!(exact(&offspine), Some(SigmaType::SLong));

        // { val x = sigma; val f = (id1: Long) => 0L; x } -> the lambda ARG
        // rebinds x to its declared SLong.
        let arg_rebind = block(
            vec![
                val_def(1, sigma_const()),
                val_def(2, func_value(vec![(1, Some(SigmaType::SLong))], long0())),
            ],
            val_use(1),
        );
        assert_eq!(exact(&arg_rebind), Some(SigmaType::SLong));

        // { val x = sigma; val f = (id3: Long) => { val x = 0L; 0L }; x } ->
        // the ValDef inside the lambda body rebinds x (flat store, never popped).
        let body_rebind = block(
            vec![
                val_def(1, sigma_const()),
                val_def(
                    2,
                    func_value(
                        vec![(3, Some(SigmaType::SLong))],
                        block(vec![val_def(1, long0())], long0()),
                    ),
                ),
            ],
            val_use(1),
        );
        assert_eq!(exact(&body_rebind), Some(SigmaType::SLong));

        // { fun f[T] = sigma; val f = 0L; f } -> FunDef writes like ValDef;
        // the later ValDef wins.
        let fundef_rebind = block(
            vec![fun_def(1, sigma_const()), val_def(1, long0())],
            val_use(1),
        );
        assert_eq!(exact(&fundef_rebind), Some(SigmaType::SLong));

        // Lambda args SURVIVE the lambda (never popped): a root ValUse of a
        // lambda arg id reads its declared type.
        let arg_survives = block(
            vec![val_def(
                2,
                func_value(vec![(5, Some(SigmaType::SLong))], long0()),
            )],
            val_use(5),
        );
        assert_eq!(exact(&arg_survives), Some(SigmaType::SLong));
    }

    /// Leniency boundaries that MUST stay unknown (`None` = accept):
    /// a `ValUse` with no prior write (Scala throws at parse — a parse-layer
    /// verdict this typer cannot express, documented residual), and a dup-id
    /// tree whose root does not resolve through the store at all is still
    /// classified.
    #[test]
    fn unbound_valuse_is_unknown_and_independent_root_still_classified() {
        assert_eq!(exact(&block(vec![], val_use(1))), None);
        // Use-before-def inside the same block: the write happens AFTER the
        // use in parse order, so the use sees nothing (Scala throws).
        let use_before_def = block(
            vec![val_def(2, val_use(1)), val_def(1, long0())],
            val_use(2),
        );
        assert_eq!(exact(&use_before_def), None);
        // Root independent of the reused id -> still classified.
        let independent = block(
            vec![val_def(1, long0()), val_def(1, long0())],
            sigma_const(),
        );
        assert_eq!(exact(&independent), Some(SigmaType::SSigmaProp));
    }

    /// Box-constant pollution is POSITIONAL: a box value's nested script parses
    /// on Scala's shared reader at the constant's position, so entries written
    /// BEFORE it become untrusted (unknown), while a binding (re)established
    /// AFTER it is trusted again (it overwrites any pollution, last-write-wins
    /// — in Scala too). A segregated box constant parses before the whole body,
    /// so a body-bound id stays trusted.
    #[test]
    fn box_constant_pollution_is_positional() {
        // { val x = sigma; val b = box; x } -> x's entry predates the box -> unknown.
        let poisoned = block(
            vec![val_def(1, sigma_const()), val_def(2, box_const())],
            val_use(1),
        );
        assert_eq!(exact(&poisoned), None);

        // { val b = box; val x = sigma; x } -> x bound after the box -> trusted.
        let rebound = block(
            vec![val_def(2, box_const()), val_def(1, sigma_const())],
            val_use(1),
        );
        assert_eq!(exact(&rebound), Some(SigmaType::SSigmaProp));

        // Segregated box constant + `{ val x = 0L; x }`: the constant table is
        // parsed BEFORE the body, so the body's ValDef overwrites any pollution
        // -> the SLong root is trusted (REJECT, as Scala: its last write to x
        // is also the body's).
        let body = block(vec![val_def(1, long0())], val_use(1));
        let constants = vec![(SigmaType::SBox, SigmaValue::OpaqueBoxBytes(vec![]))];
        assert_eq!(
            exact_type_for_test(&body, &constants),
            Some(SigmaType::SLong)
        );
    }

    /// A bare `ValDef`/`FunDef` node types as its rhs (`ValDef.tpe = rhs.tpe`,
    /// values.scala:924) — a Long rhs is non-SigmaProp (reject), a sigma rhs is
    /// SigmaProp (accept).
    #[test]
    fn bare_valdef_root_types_as_its_rhs() {
        assert_eq!(exact(&val_def(1, long0())), Some(SigmaType::SLong));
        assert_eq!(
            exact(&val_def(1, sigma_const())),
            Some(SigmaType::SSigmaProp)
        );
        assert_eq!(exact(&fun_def(1, long0())), Some(SigmaType::SLong));
    }

    /// A `FuncValue` types as `SFunc(declared args, body.tpe)` when the body is
    /// determinable, returning `None` otherwise.
    #[test]
    fn func_value_types_as_sfunc_when_precise() {
        let lambda = func_value(vec![(1, Some(SigmaType::SLong))], long0());
        assert_eq!(
            exact(&lambda),
            Some(SigmaType::SFunc {
                t_dom: vec![SigmaType::SLong],
                t_range: Box::new(SigmaType::SLong),
                tpe_params: vec![],
            })
        );
        // Tuple component types remain precise inside a function range.
        let tuple_range = func_value(
            vec![(1, Some(SigmaType::SLong))],
            op(
                0x86,
                Payload::Tuple {
                    items: vec![long0(), long0()],
                },
            ),
        );
        assert_eq!(
            exact(&tuple_range),
            Some(SigmaType::SFunc {
                t_dom: vec![SigmaType::SLong],
                t_range: Box::new(SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong])),
                tpe_params: vec![],
            })
        );
    }
}
