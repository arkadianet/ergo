//! Eval-rich generator for the consensus-complete `reduce` oracle surface.
//!
//! Where [`super::ergo_tree`] targets the PARSE surface (header/body wire edges),
//! this generator emits **well-typed ErgoTree bodies whose root reduces
//! non-trivially** against the JVM oracle's dummy reduction context (`SELF` = the
//! tree at 1M nanoErg, activated v3, empty context). The trees are assembled from
//! the `ergo_ser::opcode::Expr` AST and serialized through the real
//! `write_ergo_tree` writer, so mode-A (on-manifold) trees are guaranteed
//! well-formed and reduce identically on both implementations.
//!
//! The vocabulary is the EVAL/COST surface where real consensus divergences live:
//! sigma propositions, boolean logic, arithmetic, comparisons, collection
//! transforms, context accessors, and — the bug-bearing edges — `atLeast`
//! (trivial-child fold + >255 cap, bug #13), `Coll` equality that differs EARLY
//! vs late (short-circuit cost, bug #15), token-collection equality (per-token
//! short-circuit cost, bug #16), and deserialize nodes (bug #3).
//!
//! **Clean-baseline discipline:** every tree here reduces to an IDENTICAL
//! `P:<prop>|<cost>` on both sides on clean code (or both reject in lockstep, e.g.
//! the >255-child atLeast). A divergence on clean HEAD is therefore either a
//! miscalibrated tree or a genuine consensus candidate — never something to tune
//! away.

use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

use crate::gen::{Feature, FeatureSet, GenMode, GenOutput};
use crate::rng::Rng;

const SURFACE: &str = "sigma_expr";

// ---------------------------------------------------------------------------
// Valid on-curve secp256k1 points (used for ProveDlog / ProveDHTuple / sigma
// conjectures). These pass the `reduce` surface's GroupElement curve-check.
// ---------------------------------------------------------------------------

/// The compressed secp256k1 generator point.
const GE_GEN: [u8; 33] = crate::gen::asm::VALID_GENERATOR_GE;

/// A second valid compressed point (the P2PK key from the `reduce` oracle
/// parity test in `oracle.rs`, so it is known on-curve).
const GE_TWO: [u8; 33] = [
    0x02, 0x00, 0x0a, 0x51, 0x8d, 0xc9, 0x76, 0x13, 0x06, 0xf0, 0x48, 0xc7, 0x0a, 0xd4, 0x4e, 0x1a,
    0x7f, 0xc9, 0xe4, 0xce, 0x2c, 0xee, 0xea, 0x52, 0x96, 0x46, 0xf7, 0x3a, 0xad, 0xa1, 0xea, 0x66,
    0x40,
];

// ---------------------------------------------------------------------------
// Expr builder helpers.
// ---------------------------------------------------------------------------

fn c_int(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(v),
    }
}

fn c_long(v: i64) -> Expr {
    Expr::Const {
        tpe: SigmaType::SLong,
        val: SigmaValue::Long(v),
    }
}

fn c_bool(v: bool) -> Expr {
    Expr::Const {
        tpe: SigmaType::SBoolean,
        val: SigmaValue::Boolean(v),
    }
}

fn c_bigint(v: num_bigint::BigInt) -> Expr {
    Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(v),
    }
}

fn c_coll_bytes(bytes: Vec<u8>) -> Expr {
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(bytes)),
    }
}

fn c_coll_int(ints: Vec<i32>) -> Expr {
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SInt)),
        val: SigmaValue::Coll(CollValue::Values(
            ints.into_iter().map(SigmaValue::Int).collect(),
        )),
    }
}

/// A `Coll[(Coll[Byte], Long)]` constant — the on-wire shape of a box token
/// collection. Reduces to the boxed tuple carrier the token-equality cost path
/// (bug #16) walks.
fn c_token_coll(tokens: &[(Vec<u8>, i64)]) -> Expr {
    let tuple_type = SigmaType::STuple(vec![
        SigmaType::SColl(Box::new(SigmaType::SByte)),
        SigmaType::SLong,
    ]);
    let vals: Vec<SigmaValue> = tokens
        .iter()
        .map(|(id, amount)| {
            SigmaValue::Tuple(vec![
                SigmaValue::Coll(CollValue::Bytes(id.clone())),
                SigmaValue::Long(*amount),
            ])
        })
        .collect();
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(tuple_type)),
        val: SigmaValue::Coll(CollValue::Values(vals)),
    }
}

fn op1(opcode: u8, a: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode,
        payload: Payload::One(Box::new(a)),
    })
}

fn op2(opcode: u8, a: Expr, b: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode,
        payload: Payload::Two(Box::new(a), Box::new(b)),
    })
}

fn op3(opcode: u8, a: Expr, b: Expr, c: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode,
        payload: Payload::Three(Box::new(a), Box::new(b), Box::new(c)),
    })
}

fn zero_op(opcode: u8) -> Expr {
    Expr::Op(IrNode {
        opcode,
        payload: Payload::Zero,
    })
}

/// `sigmaProp(boolExpr)` — coerce a `Boolean` root to a `SigmaProp` so the tree
/// passes the deserialize rule-1001 SigmaProp-root check and reduces to a
/// TrivialProp under the dummy context.
fn bool_to_sigma(bool_expr: Expr) -> Expr {
    op1(0xD1, bool_expr)
}

/// `ProveDlog(ge)`.
fn prove_dlog(ge: [u8; 33]) -> Expr {
    op1(
        0xCD,
        Expr::Const {
            tpe: SigmaType::SGroupElement,
            val: SigmaValue::GroupElement(GroupElement::from_bytes(ge)),
        },
    )
}

/// A `SigmaProp` constant carrying a `TrivialProp(true/false)`.
fn sigma_prop_const(b: bool) -> Expr {
    Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(b)),
    }
}

/// `ConcreteCollection[elem_type]` literal.
fn concrete_coll(elem_type: SigmaType, items: Vec<Expr>) -> Expr {
    Expr::Op(IrNode {
        opcode: 0x83,
        payload: Payload::ConcreteCollection { elem_type, items },
    })
}

/// A sigma conjecture over `SSigmaProp` children (SigmaAnd 0xEA / SigmaOr 0xEB).
fn sigma_collection(opcode: u8, items: Vec<Expr>) -> Expr {
    Expr::Op(IrNode {
        opcode,
        payload: Payload::SigmaCollection { items },
    })
}

/// `SizeOf(coll)` (0xB1) → SInt.
fn size_of(coll: Expr) -> Expr {
    op1(0xB1, coll)
}

/// A single-argument lambda `FuncValue([(1, arg_type)], body)`.
fn lambda1(arg_type: SigmaType, body: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode: 0xD9,
        payload: Payload::FuncValue {
            args: vec![(1, Some(arg_type))],
            body: Box::new(body),
        },
    })
}

/// `ValUse(id)`.
fn val_use(id: u32) -> Expr {
    Expr::Op(IrNode {
        opcode: 0x72,
        payload: Payload::ValUse { id },
    })
}

/// Serialize a v0, non-segregated, sizeless ErgoTree with `body` as its root.
fn tree_bytes(body: Expr) -> Vec<u8> {
    let tree = ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body,
    };
    let mut w = VlqWriter::new();
    // The bodies here are always writer-serializable; a WriteError would be a
    // generator bug, so surface it rather than emitting truncated bytes.
    write_ergo_tree(&mut w, &tree).expect("sigma_expr tree must serialize");
    w.result()
}

fn out(bytes: Vec<u8>, intended_valid: bool, mode: GenMode, features: FeatureSet) -> GenOutput {
    GenOutput {
        surface: SURFACE,
        bytes,
        intended_valid,
        mode,
        features,
    }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

/// One `sigma_expr` input: ~35% on-manifold (clean-reducing), ~65% adversarial
/// (cost/eval edges — still identical on both sides on clean code).
pub fn gen(rng: &mut Rng) -> GenOutput {
    if rng.below(100) < 35 {
        gen_valid(rng)
    } else {
        gen_adversarial(rng)
    }
}

/// On-manifold: a clean-reducing tree, tagged `OnManifoldValid` + its category
/// feature. All reduce to a concrete `P:<prop>|<cost>` on both sides.
pub fn gen_valid(rng: &mut Rng) -> GenOutput {
    let (bytes, feature) = match rng.below(9) {
        0 => sigma_props(rng),
        1 => bool_logic(rng),
        2 => arith(rng),
        3 => bigint_arith(rng),
        4 => comparison(rng),
        5 => at_least_calibration(rng),
        6 => coll_ops(rng),
        7 => context_access(rng),
        _ => reg_tuple_option(rng),
    };
    out(
        bytes,
        true,
        GenMode::OnManifold,
        FeatureSet::from_iter([Feature::OnManifoldValid, feature]),
    )
}

/// Adversarial: the full eval vocabulary including the cost/eval-edge triggers.
/// Every branch is a well-typed tree the reference reduces (or rejects) in
/// lockstep with the node on clean code.
fn gen_adversarial(rng: &mut Rng) -> GenOutput {
    let (bytes, feature, intended_valid) = match rng.below(13) {
        0 => with_valid(sigma_props(rng)),
        1 => with_valid(bool_logic(rng)),
        2 => with_valid(arith(rng)),
        3 => with_valid(bigint_arith(rng)),
        4 => with_valid(comparison(rng)),
        5 => with_valid(at_least_calibration(rng)),
        // >255-child atLeast: the reference (and clean node) BOTH reject via the
        // MaxChildrenCount cap; the JVM does not accept it, so intended_valid=false.
        6 => {
            let (b, f) = at_least_over_cap(rng);
            (b, f, false)
        }
        7 => with_valid(coll_eq(rng)),
        8 => with_valid(token_eq(rng)),
        9 => with_valid(coll_ops(rng)),
        10 => with_valid(context_access(rng)),
        11 => with_valid(deserialize_node(rng)),
        _ => with_valid(reg_tuple_option(rng)),
    };
    out(
        bytes,
        intended_valid,
        GenMode::Adversarial,
        FeatureSet::from_iter([feature]),
    )
}

fn with_valid((bytes, feature): (Vec<u8>, Feature)) -> (Vec<u8>, Feature, bool) {
    (bytes, feature, true)
}

// ---------------------------------------------------------------------------
// Categories.
// ---------------------------------------------------------------------------

/// Sigma propositions: ProveDlog, ProveDHTuple, sigmaAnd/sigmaOr, Bool→SigmaProp.
fn sigma_props(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let body = match rng.below(6) {
        0 => prove_dlog(GE_GEN),
        1 => prove_dlog(GE_TWO),
        // ProveDHTuple(g, h, u, v) — 4 valid points.
        2 => Expr::Op(IrNode {
            opcode: 0xCE,
            payload: Payload::Four(
                Box::new(ge_const(GE_GEN)),
                Box::new(ge_const(GE_TWO)),
                Box::new(ge_const(GE_GEN)),
                Box::new(ge_const(GE_TWO)),
            ),
        }),
        // sigmaAnd([pd1, pd2]) → CAND
        3 => sigma_collection(0xEA, vec![prove_dlog(GE_GEN), prove_dlog(GE_TWO)]),
        // sigmaOr([pd1, pd2]) → COR
        4 => sigma_collection(0xEB, vec![prove_dlog(GE_GEN), prove_dlog(GE_TWO)]),
        // sigmaProp(true) / sigmaProp(false)
        _ => bool_to_sigma(c_bool(rng.coin())),
    };
    (tree_bytes(body), Feature::EvalSigmaProps)
}

fn ge_const(ge: [u8; 33]) -> Expr {
    Expr::Const {
        tpe: SigmaType::SGroupElement,
        val: SigmaValue::GroupElement(GroupElement::from_bytes(ge)),
    }
}

/// Boolean logic: AND/OR over Coll[Boolean], BinAnd/BinOr/BinXor, LogicalNot, If.
fn bool_logic(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let a = rng.coin();
    let b = rng.coin();
    let body = match rng.below(6) {
        // AND(Coll[Boolean]) (0x96) over a ConcreteCollection[SBoolean]
        0 => bool_to_sigma(op1(
            0x96,
            concrete_coll(
                SigmaType::SBoolean,
                vec![c_bool(a), c_bool(b), c_bool(true)],
            ),
        )),
        // OR(Coll[Boolean]) (0x97)
        1 => bool_to_sigma(op1(
            0x97,
            concrete_coll(
                SigmaType::SBoolean,
                vec![c_bool(a), c_bool(b), c_bool(false)],
            ),
        )),
        // BinAnd (0xED) / BinOr (0xEC) / BinXor (0xF4) over two Bool consts
        2 => bool_to_sigma(op2(0xED, c_bool(a), c_bool(b))),
        3 => bool_to_sigma(op2(0xEC, c_bool(a), c_bool(b))),
        4 => bool_to_sigma(op2(0xF4, c_bool(a), c_bool(b))),
        // LogicalNot (0xEF)
        _ => bool_to_sigma(op1(0xEF, c_bool(a))),
    };
    // If/else over a Bool result, folded in for coverage of 0x95.
    let body = if rng.coin() {
        bool_to_sigma(op3(0x95, c_bool(rng.coin()), c_bool(a), c_bool(b)))
    } else {
        body
    };
    (tree_bytes(body), Feature::EvalBoolLogic)
}

/// Arithmetic over Int/Long with edge values, reduced to a Bool via a comparison
/// then coerced to SigmaProp. Divisors are kept non-zero and operands chosen to
/// avoid overflow so the tree reduces to a concrete prop (overflow/÷0 would make
/// BOTH sides reject in lockstep — still clean, just not a reduction).
fn arith(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let use_long = rng.coin();
    let (lo, hi): (i64, i64) = (-1_000_000, 1_000_000);
    let a = rng.range(0, (hi - lo) as usize) as i64 + lo;
    let b = rng.range(1, (hi - lo) as usize) as i64 + 1; // non-zero
                                                         // opcodes: Plus 0x9A, Minus 0x99, Multiply 0x9C, Division 0x9D, Modulo 0x9E,
                                                         // Min 0xA1, Max 0xA2. Multiply is bounded so it cannot overflow i32/i64 here.
    let op = match rng.below(7) {
        0 => 0x9A,
        1 => 0x99,
        2 => 0x9C,
        3 => 0x9D,
        4 => 0x9E,
        5 => 0xA1,
        _ => 0xA2,
    };
    let (lhs, rhs, cmp_rhs) = if use_long {
        (c_long(a), c_long(b), c_long(0))
    } else {
        (
            c_int(a as i32 % 30_000),
            c_int(b as i32 % 30_000 + 1),
            c_int(0),
        )
    };
    // GE(arith, 0) OR EQ(arith, arith) — both yield a Bool.
    let arith_expr = op2(op, lhs, rhs);
    let bool_expr = op2(0x92, arith_expr, cmp_rhs); // GE
    (tree_bytes(bool_to_sigma(bool_expr)), Feature::EvalArith)
}

/// BigInt arithmetic with edge magnitudes, compared to yield a Bool.
fn bigint_arith(rng: &mut Rng) -> (Vec<u8>, Feature) {
    use num_bigint::BigInt;
    let magnitudes = [
        BigInt::from(0),
        BigInt::from(1),
        BigInt::from(-1),
        BigInt::from(i64::MAX),
        BigInt::from(i64::MIN),
        BigInt::from(1_000_000_007i64),
    ];
    let a = magnitudes[rng.below(magnitudes.len())].clone();
    let b = magnitudes[rng.below(magnitudes.len())].clone();
    // Plus / Minus / Multiply over BigInt stay well within the 256-bit bound for
    // these magnitudes, so no overflow.
    let op = match rng.below(3) {
        0 => 0x9A,
        1 => 0x99,
        _ => 0x9C,
    };
    let arith_expr = op2(op, c_bigint(a), c_bigint(b));
    // Compare the BigInt result to 0 (GE) → Bool.
    let bool_expr = op2(0x92, arith_expr, c_bigint(num_bigint::BigInt::from(0)));
    (
        tree_bytes(bool_to_sigma(bool_expr)),
        Feature::EvalBigIntArith,
    )
}

/// Ordered / equality comparisons over primitives.
fn comparison(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let a = rng.range(0, 1000) as i32;
    let b = rng.range(0, 1000) as i32;
    // Lt 0x8F, Le 0x90, Gt 0x91, Ge 0x92, Eq 0x93, Neq 0x94
    let op = 0x8F + rng.below(6) as u8;
    let body = bool_to_sigma(op2(op, c_int(a), c_int(b)));
    (tree_bytes(body), Feature::EvalComparison)
}

/// `atLeast` calibration: k-of-n over a small `Coll[SigmaProp]` that folds
/// cleanly to COR / CAND / CTHRESHOLD on BOTH sides (no cap, no nested trivial).
fn at_least_calibration(rng: &mut Rng) -> (Vec<u8>, Feature) {
    // Children: a mix of real ProveDlogs and trivial props, so the fold path is
    // exercised (a TrueProp satisfies a slot; a FalseProp drops).
    let children = vec![
        prove_dlog(GE_GEN),
        prove_dlog(GE_TWO),
        sigma_prop_const(true),
        sigma_prop_const(false),
    ];
    let n = children.len();
    let k = rng.range(1, n) as i32; // 1..=n-1 → a real threshold (not all/none)
    let body = op2(
        0x98,
        c_int(k),
        concrete_coll(SigmaType::SSigmaProp, children),
    );
    (tree_bytes(body), Feature::EvalAtLeast)
}

/// **Bug #13 trigger.** `atLeast(1, [256 × trivial SigmaProp])`: the child count
/// exceeds `MaxChildrenCountForAtLeastOp` (255). Clean node AND JVM both REJECT
/// (the `CSigmaDslBuilder.atLeast` cap throws before the fold). With the cap
/// removed the node reduces to `TrivialProp(true)` while the JVM still rejects —
/// an accept/reject divergence on `reduce`.
fn at_least_over_cap(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let n = 256 + rng.below(4); // 256..=259, all > 255
    let children: Vec<Expr> = (0..n).map(|_| sigma_prop_const(true)).collect();
    let body = op2(
        0x98,
        c_int(1),
        concrete_coll(SigmaType::SSigmaProp, children),
    );
    (tree_bytes(body), Feature::EvalAtLeast)
}

/// **Bug #15 surface.** EQ/NEQ over two equal-length primitive collections
/// (`Coll[Byte]` / `Coll[Int]`) that differ EARLY (index 0), LATE (last index),
/// or are EQUAL. The early-mismatch case is where the short-circuit cost model
/// bites: clean node + JVM both charge over the compared prefix (1 element),
/// while re-injecting the bug charges over the full length → a `|cost` divergence.
fn coll_eq(rng: &mut Rng) -> (Vec<u8>, Feature) {
    // Long enough that a full-length charge spans more cost chunks than a
    // single-element prefix (Byte chunk=128, Int chunk=64).
    let use_int = rng.coin();
    let len = 200usize;
    let eq_op = if rng.coin() { 0x93 } else { 0x94 }; // EQ / NEQ

    let (lhs, rhs) = if use_int {
        let base: Vec<i32> = (0..len as i32).collect();
        let mut other = base.clone();
        match rng.below(3) {
            0 => other[0] = 0x7fff_ffff,       // early mismatch
            1 => other[len - 1] = 0x7fff_ffff, // late mismatch
            _ => {}                            // equal
        }
        (c_coll_int(base), c_coll_int(other))
    } else {
        let base: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut other = base.clone();
        match rng.below(3) {
            0 => other[0] ^= 0xff,       // early mismatch
            1 => other[len - 1] ^= 0xff, // late mismatch
            _ => {}                      // equal
        }
        (c_coll_bytes(base), c_coll_bytes(other))
    };
    let body = bool_to_sigma(op2(eq_op, lhs, rhs));
    (tree_bytes(body), Feature::EvalCollEqEarly)
}

/// **Bug #16 surface.** EQ over two `Coll[(Coll[Byte], Long)]` token collections
/// differing at the FIRST token. The per-token equality loop short-circuits at
/// the first unequal token on clean code (matching the JVM `equalColls`
/// fallback); re-injecting the bug charges every token → a `|cost` divergence.
fn token_eq(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let n = rng.range(3, 6);
    let mk = |seed: u8| -> Vec<(Vec<u8>, i64)> {
        (0..n)
            .map(|i| (vec![seed.wrapping_add(i as u8); 32], 1000 + i as i64))
            .collect()
    };
    let a = mk(0x11);
    let mut b = mk(0x11);
    match rng.below(3) {
        0 => b[0].0[0] ^= 0xff, // first token id differs (early)
        1 => b[n - 1].1 += 1,   // last token amount differs (late)
        _ => {}                 // equal
    }
    let eq_op = if rng.coin() { 0x93 } else { 0x94 };
    let body = bool_to_sigma(op2(eq_op, c_token_coll(&a), c_token_coll(&b)));
    (tree_bytes(body), Feature::EvalTokenEq)
}

/// Collection transforms over a `Coll[Int]`: size, exists/forall, byIndex, slice,
/// indexOf, map — each reduced to a Bool.
fn coll_ops(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let coll = || c_coll_int(vec![3, 1, 4, 1, 5, 9, 2, 6]);
    let body = match rng.below(7) {
        // size > 0
        0 => bool_to_sigma(op2(0x92, size_of(coll()), c_int(0))),
        // exists(coll, x => x > 4) (0xAE)
        1 => bool_to_sigma(op2(
            0xAE,
            coll(),
            lambda1(SigmaType::SInt, op2(0x91, val_use(1), c_int(4))),
        )),
        // forall(coll, x => x >= 0) (0xAF)
        2 => bool_to_sigma(op2(
            0xAF,
            coll(),
            lambda1(SigmaType::SInt, op2(0x92, val_use(1), c_int(0))),
        )),
        // byIndex(coll, 2, default 0) == 4 (0xB2)
        3 => bool_to_sigma(op2(
            0x93,
            Expr::Op(IrNode {
                opcode: 0xB2,
                payload: Payload::ByIndex {
                    input: Box::new(coll()),
                    index: Box::new(c_int(2)),
                    default: Some(Box::new(c_int(0))),
                },
            }),
            c_int(4),
        )),
        // size(slice(coll, 1, 4)) == 3 (Slice 0xB4)
        4 => bool_to_sigma(op2(
            0x93,
            size_of(op3(0xB4, coll(), c_int(1), c_int(4))),
            c_int(3),
        )),
        // size(map(coll, x => x + 1)) > 0 (MapCollection 0xAD)
        5 => bool_to_sigma(op2(
            0x91,
            size_of(op2(
                0xAD,
                coll(),
                lambda1(SigmaType::SInt, op2(0x9A, val_use(1), c_int(1))),
            )),
            c_int(0),
        )),
        // size(filter(coll, x => x > 3)) >= 0 (Filter 0xB5)
        _ => bool_to_sigma(op2(
            0x92,
            size_of(op2(
                0xB5,
                coll(),
                lambda1(SigmaType::SInt, op2(0x91, val_use(1), c_int(3))),
            )),
            c_int(0),
        )),
    };
    (tree_bytes(body), Feature::EvalCollOps)
}

/// Context accessors reduced to a Bool: HEIGHT, SELF.value/.id/.propositionBytes,
/// INPUTS/OUTPUTS size, getVar.
fn context_access(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let self_box = || zero_op(0xA7); // SELF
    let body = match rng.below(6) {
        // HEIGHT >= 0  (0xA3)
        0 => bool_to_sigma(op2(0x92, zero_op(0xA3), c_int(0))),
        // SELF.value > 0  (ExtractAmount 0xC1)
        1 => bool_to_sigma(op2(0x91, op1(0xC1, self_box()), c_long(0))),
        // size(SELF.propositionBytes) > 0  (ExtractScriptBytes 0xC2)
        2 => bool_to_sigma(op2(0x91, size_of(op1(0xC2, self_box())), c_int(0))),
        // size(SELF.id) == 32  (ExtractId 0xC5)
        3 => bool_to_sigma(op2(0x93, size_of(op1(0xC5, self_box())), c_int(32))),
        // size(INPUTS) > 0  (Inputs 0xA4) — dummy ctx has SELF as the sole input
        4 => bool_to_sigma(op2(0x91, size_of(zero_op(0xA4)), c_int(0))),
        // getVar[Int](1).isDefined  (GetVar 0xE3 → Option; absent → None → false)
        _ => bool_to_sigma(op1(
            0xE6,
            Expr::Op(IrNode {
                opcode: 0xE3,
                payload: Payload::GetVar {
                    var_id: 1,
                    tpe: SigmaType::SInt,
                },
            }),
        )),
    };
    (tree_bytes(body), Feature::EvalContext)
}

/// A tree that CONTAINS a `DeserializeRegister`/`DeserializeContext` node on a
/// DEAD `If` branch (never evaluated in the dummy context), so it reduces cleanly
/// while still exercising the `hasDeserialize` wire vocabulary (bug #3 surface).
fn deserialize_node(rng: &mut Rng) -> (Vec<u8>, Feature) {
    // Dead branch: the deserialize expression, typed SBoolean.
    let deser: Expr = if rng.coin() {
        Expr::Op(IrNode {
            opcode: 0xD5,
            payload: Payload::DeserializeRegister {
                reg_id: 4,
                tpe: SigmaType::SBoolean,
                default: Some(Box::new(c_bool(false))),
            },
        })
    } else {
        Expr::Op(IrNode {
            opcode: 0xD4,
            payload: Payload::DeserializeContext {
                id: 7,
                tpe: SigmaType::SBoolean,
            },
        })
    };
    // If(true, <live bool>, <deserialize bool>) — the deserialize arm is dead.
    let body = bool_to_sigma(op3(0x95, c_bool(true), c_bool(rng.coin()), deser));
    (tree_bytes(body), Feature::EvalDeserializeNode)
}

/// Registers / tuples / options: a tuple projection and an absent-register option
/// probe, each reduced to a Bool.
fn reg_tuple_option(rng: &mut Rng) -> (Vec<u8>, Feature) {
    let body = match rng.below(3) {
        // (7, 9)._1 == 7  (Tuple + SelectField 0x8C)
        0 => {
            let tuple = Expr::Op(IrNode {
                opcode: 0x86,
                payload: Payload::Tuple {
                    items: vec![c_int(7), c_int(9)],
                },
            });
            bool_to_sigma(op2(
                0x93,
                Expr::Op(IrNode {
                    opcode: 0x8C,
                    payload: Payload::SelectField {
                        input: Box::new(tuple),
                        field_idx: 1,
                    },
                }),
                c_int(7),
            ))
        }
        // SELF.R4[Int].isDefined  (ExtractRegisterAs 0xC6 → Option; absent → false)
        1 => bool_to_sigma(op1(
            0xE6,
            Expr::Op(IrNode {
                opcode: 0xC6,
                payload: Payload::ExtractRegisterAs {
                    input: Box::new(zero_op(0xA7)),
                    reg_id: 4,
                    tpe: SigmaType::SInt,
                },
            }),
        )),
        // getVar[Long](2).getOrElse(0L) == 0L  (OptionGetOrElse 0xE5)
        _ => bool_to_sigma(op2(
            0x93,
            op2(
                0xE5,
                Expr::Op(IrNode {
                    opcode: 0xE3,
                    payload: Payload::GetVar {
                        var_id: 2,
                        tpe: SigmaType::SLong,
                    },
                }),
                c_long(0),
            ),
            c_long(0),
        )),
    };
    (tree_bytes(body), Feature::EvalRegTupleOption)
}

// ---------------------------------------------------------------------------
// Deterministic minimal triggers for the re-injection gate.
//
// These are STABLE, RNG-free representatives the `known_bugs/manifest.toml`
// pins as `trigger_hex`. On clean code each reduces in lockstep with the JVM
// (both agree); with the mapped bug re-injected into `ergo-sigma`, the node's
// `reduce` verdict diverges (accept/reject for #13, `|cost` for #15/#16). The
// randomized `gen()` path reaches the SAME surfaces; these fixed forms make the
// gate reproducible without a JVM in the loop for the clean assertion.
// ---------------------------------------------------------------------------

/// Bug #13 trigger: `atLeast(1, [256 × sigmaProp(true)])`. Clean node + JVM both
/// REJECT (MaxChildrenCount cap, 255). Cap removed → node accepts `P:d3`, JVM
/// still rejects.
#[cfg(test)]
fn trigger_at_least_over_cap() -> Vec<u8> {
    let children: Vec<Expr> = (0..256).map(|_| sigma_prop_const(true)).collect();
    tree_bytes(op2(
        0x98,
        c_int(1),
        concrete_coll(SigmaType::SSigmaProp, children),
    ))
}

/// Bug #15 trigger: `sigmaProp(Coll[Byte](0..200) == Coll[Byte] differing at
/// index 0)`. Both reduce to `P:d2` at an identical cost (the short-circuit
/// charges the 1-element compared prefix); dropping the short-circuit charges
/// the full 200 → a `|cost` divergence.
#[cfg(test)]
fn trigger_coll_eq_early() -> Vec<u8> {
    let base: Vec<u8> = (0..200u16).map(|i| (i % 251) as u8).collect();
    let mut other = base.clone();
    other[0] ^= 0xff;
    tree_bytes(bool_to_sigma(op2(
        0x93,
        c_coll_bytes(base),
        c_coll_bytes(other),
    )))
}

/// Bug #16 trigger: `sigmaProp(tokens == tokens differing at the FIRST token
/// id)` over a 5-token `Coll[(Coll[Byte], Long)]`. Both reduce to `P:d2` at an
/// identical cost (short-circuit at token 0); dropping the short-circuit charges
/// all 5 tokens → a `|cost` divergence.
#[cfg(test)]
fn trigger_token_eq_early() -> Vec<u8> {
    let a: Vec<(Vec<u8>, i64)> = (0..5)
        .map(|i| (vec![0x11u8.wrapping_add(i as u8); 32], 1000 + i as i64))
        .collect();
    let mut b = a.clone();
    b[0].0[0] ^= 0xff;
    tree_bytes(bool_to_sigma(op2(0x93, c_token_coll(&a), c_token_coll(&b))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::cost::{CostAccumulator, JitCost};
    use ergo_sigma::evaluator::{reduce_expr_with_cost, EvalBox, ReductionContext};

    /// Reduce a generated tree the way the `reduce` oracle surface does (dummy
    /// SELF box at 1M nanoErg, activated v3). Returns the reduced prop bytes +
    /// total cost, or an error string.
    fn reduce_tree(bytes: &[u8]) -> Result<(Vec<u8>, u64), String> {
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::ergo_tree::read_ergo_tree;
        let mut r = VlqReader::new(bytes);
        let tree = read_ergo_tree(&mut r).map_err(|e| format!("parse: {e:?}"))?;
        let self_box = EvalBox {
            value: 1_000_000,
            script_bytes: bytes.to_vec(),
            creation_height: 0,
            id: [0u8; 32],
            transaction_id: [0u8; 32],
            output_index: 0,
            registers: [None, None, None, None, None, None],
            tokens: vec![],
            raw_bytes: vec![],
            register_bytes: vec![0u8],
        };
        let inputs = [self_box];
        let ctx = ReductionContext {
            self_box: Some(&inputs[0]),
            inputs: &inputs,
            ergo_tree_version: tree.version,
            ..ReductionContext::minimal(0, 0)
        };
        let limit = JitCost::from_block_cost(1_000_000).map_err(|e| format!("{e:?}"))?;
        let mut cost = CostAccumulator::new(limit);
        let sb = reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost)
            .map_err(|e| format!("reduce: {e:?}"))?;
        let mut w = VlqWriter::new();
        ergo_ser::sigma_value::write_sigma_boolean(&mut w, &sb).map_err(|e| format!("{e:?}"))?;
        Ok((w.result(), cost.total().value()))
    }

    /// Every clean-reducing category must (a) round-trip through the ergo_tree
    /// codec and (b) reduce to a concrete prop with a real (>0) cost — i.e.
    /// reduce NON-trivially on the node side. (The oracle campaign proves the
    /// two SIDES agree; this proves the trees are well-typed and evaluate.)
    #[test]
    fn mode_a_trees_reduce_nontrivially() {
        let mut rng = Rng::new(0xE7A1_0000_0000_0001);
        let mut reduced = 0;
        for _ in 0..2_000 {
            let g = gen_valid(&mut rng);
            assert_eq!(g.surface, SURFACE);
            assert!(g.intended_valid);
            // Hermetic parse round-trip.
            let outcome = crate::run_input(&g.bytes, Some("sigma_expr"));
            let (_, o) = outcome
                .into_iter()
                .find(|(n, _)| *n == "sigma_expr")
                .unwrap();
            assert!(
                matches!(o, crate::Outcome::Accepted),
                "mode-A tree not codec-accepted: {o:?} bytes={}",
                crate::to_hex(&g.bytes)
            );
            // Node-side reduction must succeed.
            match reduce_tree(&g.bytes) {
                Ok((_prop, cost)) => {
                    assert!(
                        cost > 0,
                        "reduced with zero cost: {}",
                        crate::to_hex(&g.bytes)
                    );
                    reduced += 1;
                }
                Err(e) => panic!(
                    "mode-A tree failed to reduce: {e} bytes={}",
                    crate::to_hex(&g.bytes)
                ),
            }
        }
        assert_eq!(reduced, 2_000);
    }

    /// The bug-surface triggers must be reachable AND reduce the way the
    /// clean-baseline discipline requires:
    ///  * coll-eq / token-eq early-mismatch → node reduces to FalseProp (`d2`)
    ///    at a real cost (the JVM agrees on clean code; a re-injected bug shifts
    ///    only the cost).
    ///  * the >255-child atLeast → node REJECTS (the cap), matching the JVM.
    #[test]
    fn bug_triggers_reduce_as_expected() {
        let mut rng = Rng::new(99);
        // coll-eq early mismatch: build many, ensure at least the early-mismatch
        // variants reduce to FalseProp.
        let mut saw_false = false;
        for _ in 0..200 {
            let (bytes, _f) = coll_eq(&mut rng);
            if let Ok((prop, cost)) = reduce_tree(&bytes) {
                assert!(cost > 0);
                if prop == vec![0xd2] {
                    saw_false = true;
                }
            }
        }
        assert!(saw_false, "coll_eq never reduced to FalseProp");

        // token-eq: must reduce to a prop at a real cost.
        for _ in 0..50 {
            let (bytes, _f) = token_eq(&mut rng);
            let (_prop, cost) = reduce_tree(&bytes).expect("token_eq must reduce");
            assert!(cost > 0);
        }

        // >255-child atLeast: clean node must REJECT (the MaxChildrenCount cap).
        for _ in 0..8 {
            let (bytes, _f) = at_least_over_cap(&mut rng);
            let r = reduce_tree(&bytes);
            assert!(
                r.is_err(),
                "over-cap atLeast reduced on clean code (expected cap reject): {r:?}"
            );
        }
    }

    /// Pin the deterministic re-injection triggers: their hex is what
    /// `known_bugs/manifest.toml` records, and their CLEAN node-side reduction
    /// is the baseline the gate asserts. Run with `--nocapture` to print the
    /// hexes for the manifest.
    #[test]
    fn reinjection_triggers_clean_baseline() {
        // #13: the over-cap atLeast REJECTs on clean code (cap fires).
        let cap = trigger_at_least_over_cap();
        println!("TRIGGER at_least_over_cap = {}", crate::to_hex(&cap));
        assert!(
            reduce_tree(&cap).is_err(),
            "over-cap atLeast must reject on clean code"
        );

        // #15: coll-eq early mismatch reduces to FalseProp at a real cost.
        let ce = trigger_coll_eq_early();
        let (prop, cost) = reduce_tree(&ce).expect("coll_eq trigger must reduce");
        println!(
            "TRIGGER coll_eq_early = {}  -> P:{}|{}",
            crate::to_hex(&ce),
            crate::to_hex(&prop),
            cost
        );
        assert_eq!(prop, vec![0xd2], "coll_eq early mismatch must be FalseProp");

        // #16: token-eq early mismatch reduces to FalseProp at a real cost.
        let te = trigger_token_eq_early();
        let (prop, cost) = reduce_tree(&te).expect("token_eq trigger must reduce");
        println!(
            "TRIGGER token_eq_early = {}  -> P:{}|{}",
            crate::to_hex(&te),
            crate::to_hex(&prop),
            cost
        );
        assert_eq!(
            prop,
            vec![0xd2],
            "token_eq early mismatch must be FalseProp"
        );
    }
}
