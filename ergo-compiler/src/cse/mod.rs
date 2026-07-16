//! M5 Task 1 — CSE scaffold: the scope-chain hash-cons SUBSTRATE.
//!
//! This module reproduces the *build-time identity* half of Scala's Scalan
//! CSE — the part that decides **how many distinct symbols exist** and **which
//! scope each was first built in**. It is a graph-build SIMULATION over our
//! opcode IR (`ergo_ser::opcode::Expr`), NOT a Scalan port. It builds ONLY the
//! substrate: interning + scope stack + bound-var dependency tags. It does NOT
//! emit `ValDef`s, assign ids, or run usage counting (Tasks 2–4), and it is NOT
//! wired into `compile()` yet.
//!
//! Spec: the validated spike `dev-docs/ergoscript-compiler-m5-recon/
//! spike-scope-chain.md` (6/6 oracle predictions). All Scala citations resolve
//! under the pinned oracle checkout
//! `ergo-core/sigmastate-interpreter-v6.0.2`,
//! `sc/shared/src/main/scala/sigma/compiler/ir/`.
//!
//! # The identity model (spike §1)
//!
//! There are two tiers a node can be interned into, chosen at the moment it is
//! *first constructed* by the top of the thunk stack (`Base.scala:777-789`
//! `findOrCreateDefinition`, `Thunks.scala:219-226` `findDef`):
//!
//! - **Global table** (`_globalDefs`, `Base.scala:732`) — used when the thunk
//!   stack is empty (root / condition / any non-thunk position). Visible to
//!   every later scope via the `findDef` chain's `findGlobalDefinition` tail, so
//!   a global symbol is **shared** across branches/thunks that reference it.
//! - **Per-thunk table** (`ThunkScope.bodyDefs`, `Thunks.scala:182`) — one per
//!   open thunk. Built while a thunk is on the stack ⇒ invisible to siblings
//!   (`findDef` walks bodyDefs → parent → global; **siblings are never on each
//!   other's parent chain**, `Thunks.scala:248-253`). A byte-identical node
//!   built inside sibling thunk B misses A entirely and creates a **second
//!   distinct symbol** — cannonQ's "per-Thunk-distinct-sym".
//!
//! A node is **never migrated** between scopes (spike §1.3). The single
//! determinant of sharing is the **scope of first build** — not use-count, not
//! LCA. The keystone is the E2-vs-E6 pair (spike §6): they differ only in the
//! `if` condition, yet E2 (each `HEIGHT+1` first built inside its own branch)
//! emits two un-shared copies while E6 (`HEIGHT+1` first built in the shared
//! condition) emits one.
//!
//! # Scope-push sites (spike §2, CORRECTED for getOrElse — M5 Task 5c/R2)
//!
//! A hash-cons scope is pushed at EXACTLY three source shapes, each a *by-name*
//! (lazy) operand; the left/condition operand is evaluated in the CURRENT scope
//! *first*:
//!
//! | opcode | shape | scoped operand(s) | current-scope operand |
//! |--------|-------|-------------------|-----------------------|
//! | `0x95` If         | `if(c) t else e`   | **both** `t`, `e` | `c`      |
//! | `0xED` BinAnd     | `a && b`           | **right** `b`     | `a`      |
//! | `0xEC` BinOr      | `a \|\| b`         | **right** `b`     | `a`      |
//!
//! `0xF4` BinXor is **eager** (spike §2 last row, `GraphBuilding.scala:874-877`)
//! — no scope; both arms in the current scope (handled by the general path).
//!
//! **`0xE5` OptionGetOrElse is NOT a scope-push site** — the correction the R2
//! recon pinned from source. The spike §2 table (and the M5-Task-5 model) wrongly
//! listed `opt.getOrElse(d)` as thunking its default `d`. In Scala 6.0.2 the
//! default is built **eagerly, as an ordinary argument, in the ENCLOSING scope**
//! (`GraphBuilding.scala:441` `In`, `:962` `argsV`, `:1013-1035` the getOrElse
//! dispatch), *before* it is wrapped in a Thunk; that Thunk has an EMPTY body and
//! merely references the already-built ref (`Thunks.scala:261,283-286` —
//! `thunk_create` of a built ref schedules nothing, `isEmptyBody == true`). So the
//! default is hash-consed at the enclosing scope like `opt` itself: byte-identical
//! defaults across sibling `def`-lambdas share ONE node and hoist to a root
//! `ValDef`. It routes through the general (all-children-current-scope) path. The
//! distinguishing predicate is the builder's evaluation strategy (by-name ⇒
//! thunk-local, by-value ⇒ enclosing), NOT any property of the node — the E2
//! keystone's `HEIGHT+1` is built by-name inside its If-branch and stays
//! thunk-local even though it is bound-var-free.
//!
//! # Pair projections bypass thunk isolation (M5 Task 5d — `unzipPair`/`tuplesCache`)
//!
//! One node class breaks the "first-build scope decides identity" rule above:
//! pair projections `t._1`/`t._2`. Scalan's `unzipPair` (`Tuples.scala:57-74`,
//! pinned 6.0.2) memoizes them in a PROCESS-WIDE `tuplesCache`
//! (`AVHashMap`, `:57`), a field on the IRContext, keyed by the pair `Ref`
//! (nodeId identity) — NOT a per-thunk table. Two facts do all the work:
//!
//! 1. **Both-projections-eager** (`:65`): the FIRST access to EITHER `t._1` or
//!    `t._2` constructs BOTH `First(t)` and `Second(t)` together, in the current
//!    scope, even if only one is used there.
//! 2. **Process-wide memo** (`:63-67`): once `(First(t), Second(t))` is cached
//!    for pair `t`, EVERY later `t._1`/`t._2` anywhere — including inside a
//!    sibling `if`-branch thunk — returns the SAME projection symbol, bypassing
//!    thunk hash-cons isolation (`findDef`, `Thunks.scala:219-226`). This is the
//!    SOLE such bypass; every non-projection node obeys thunk isolation.
//!
//! We port this as [`Interner::pair_projections`], a process-wide
//! `BTreeMap<SymId, (SymId, SymId)>` keyed by the pair RECEIVER's `SymId`, never
//! reset at scope push/pop ([`Interner::pair_projection`]). Because a root-shared
//! pair has ONE receiver `SymId` across branches (global hash-cons) while a
//! thunk-local pair gets a DISTINCT one, sharing happens IFF the receiver is
//! root-shared — reproducing the `basis-token` cross-branch `SELF.tokens(1)._2`
//! ValDef (`Tuples.scala:57-74`). It touches ONLY `SelectField` on `field_idx
//! ∈ {1,2}`; `Plus` and every other opcode never enter it, so the E2 keystone
//! (`HEIGHT+1`, a `Plus`) is untouchable. Literal-tuple receivers take the
//! `Tup(a,b)` case (`:60`) and stay on the general path.
//!
//! # Lambdas are NOT thunks (spike §1.4 — the cannonQ correction)
//!
//! `FuncValue` (`0xD9`) bodies do NOT push a hash-cons scope: `lambda`
//! (`Functions.scala:359-383`) pushes only `lambdaStack`, never `thunkStack`. So
//! a node built inside a lambda body is hash-consed into whatever scope was
//! already open (global at root) — a root-shared def referenced from two
//! sibling lambdas is a single global symbol (E4). To let Task 3 decide
//! lambda-float-up, each interned symbol is tagged with the set of bound-var
//! ids (lambda arg ids) it transitively depends on; a bound-var-free node floats
//! up to the enclosing scope, a bound-var-dependent node belongs to the body
//! (`AstGraphs.scala:56-85,111-121` `freeVars`/`domain`).
//!
//! This module keeps the [`cse`] entry point and the opcode constants; the
//! substrate is split across submodules, each contributing its own
//! `impl Interner` block:
//! - [`key`] — the type definitions ([`SymId`], `KeyTag`, `ExprKey`, `Node`,
//!   `ScopeId`, `ScopeKind`) that key and describe an interned symbol.
//! - [`interner`] — the [`Interner`] struct itself (owns the scope stack,
//!   symbol table, and bindings) plus its constructor and read-only
//!   introspection accessors.
//! - [`intern`] — Phase A interning (`intern`/`intern_op`/`pair_projection`
//!   and friends).
//! - [`gate`] — Phase B usage counting and the 4-predicate admission gate
//!   (`flat_usage`/`is_context_property`/`is_internal`/`is_const`/
//!   `should_hoist`).
//! - [`materialize`] — Task 3 schedule + materialize (`materialize`/
//!   `process_scope`/`schedule_order`/`build_value`/`build_op`), plus the
//!   `val_def`/`val_use`/`wrap_block` tree-rebuilding helpers.
//! - [`codec`] — the mutually-inverse `decompose`/`recompose` payload pair.

use std::collections::BTreeSet;

use ergo_ser::opcode::Expr;

mod codec;
mod gate;
mod intern;
mod interner;
mod key;
mod materialize;
pub(crate) use codec::*;
pub use interner::*;
pub use key::*;

// ----- opcode constants (verified against ergo-ser/src/opcode/types.rs) -----

/// `if(c) t else e` — both branches thunked (`IfThenElse.scala:50-53`).
const IF: u8 = 0x95;
/// `a && b` — right arm thunked (`GraphBuilding.scala:869-872`).
const BIN_AND: u8 = 0xED;
/// `a || b` — right arm thunked (`GraphBuilding.scala:864-867`).
const BIN_OR: u8 = 0xEC;
// `0xE5` OptionGetOrElse is deliberately ABSENT (M5 Task 5c/R2): its default is
// built EAGERLY in the enclosing scope, not a thunk (GraphBuilding.scala:441,962,
// 1013-1035 + Thunks.scala:261,283-286 empty-body thunk), so it routes through
// the general eager path like any other node. See the module docs.
/// Lambda — pushes `lambdaStack`, NOT `thunkStack` (spike §1.4).
const FUNC_VALUE: u8 = 0xD9;
/// `{ items; result }` block — transparent; items register bindings.
const BLOCK_VALUE: u8 = 0xD8;
/// `val id = rhs` — registers a binding; the node itself is transparent.
const VAL_DEF: u8 = 0xD6;
/// Use of an existing binding by id — resolves to the bound symbol.
const VAL_USE: u8 = 0x72;
// `0xF4` BinXor is deliberately absent: it is EAGER and routes through the
// general path (both arms in the current scope). See module docs.

/// `SelectField` tuple projection (`0x8C`, types.rs:303) — `t._1`/`t._2` on a
/// pair. The sole node routed through the process-wide pair-projection memo
/// (Scalan `unzipPair`, `Tuples.scala:57-74`); see the module docs.
const SELECT_FIELD: u8 = 0x8C;
/// `Tuple` literal (`0x86`, types.rs). A `._1`/`._2` on a LITERAL tuple is the
/// Scala `unzipPair` `Tup(a,b)` case (`Tuples.scala:60`): it projects to the
/// element directly, NOT through `First`/`Second`, so it bypasses the memo and
/// stays on the general path.
const TUPLE: u8 = 0x86;

// ----- admission-gate predicate opcodes (Task 2, spike §5) -----
//
// The four *free context globals* recognized by Scala's `IsContextProperty`
// (`TreeBuilding.scala:140-148`: `ContextM.HEIGHT/INPUTS/OUTPUTS/SELF` →
// `Height`/`Inputs`/`Outputs`/`Self`). These NEVER get a ValDef even at high
// use-count — they re-emit inline per use (validated E2/E3/E5, `a3` per use).
// Opcode bytes verified against `ergo-ser/src/opcode/types.rs:327-331`.
//
// NOTE the deliberate omissions, matching Scala exactly: `LastBlockUtxoRootHash`
// (`0xA6`, types.rs:330) and `MinerPubkey` (`0xAC`, types.rs:333) are context
// nodes but are NOT in `IsContextProperty` — so they are hoistable like any
// other node and are absent here.
const HEIGHT: u8 = 0xA3;
const INPUTS: u8 = 0xA4;
const OUTPUTS: u8 = 0xA5;
const SELF_BOX: u8 = 0xA7;

/// `Global` / `SGlobal` (`0xDD`, types.rs:388) — our lowering of `SigmaDslBuilder`
/// (`TypedExpr::Global` → `Op(0xDD, Zero)`, `emit.rs:322`; `SType::SGlobal`
/// prints as `"SigmaDslBuilder"`, `typed_print.rs:53`). This is the OUR-IR
/// analogue of Scala's `IsInternalDef` (`TreeBuilding.scala:153-158`:
/// `SigmaDslBuilder | CollBuilder`). The `CollBuilder` alternative has NO node in
/// our lowered IR (collections lower straight to `ConcreteCollection`, never
/// through an explicit builder singleton), so that half of the predicate is
/// vacuous for us — documented, not fabricated (no `grep` hit for a CollBuilder
/// node in `ergo-compiler/src/emit.rs`).
const GLOBAL: u8 = 0xDD;

/// The single subexpression-sharing pass — Scala's scope-chain hash-cons +
/// `hasManyUsagesGlobal` ValDef materialization (spike §7.1), the SOLE replacement
/// for the retired M4 `inline_vals`/`renumber_dense` machinery (locked decision 4,
/// spike §7.2). Interns the tree once (Phase A: identity by first-build scope),
/// then materializes from the root symbol (Phase B: flat usage count → 4-predicate
/// admission gate → per-scope `ValDef` schedule with assign-once dense ids).
///
/// Subsumes val inlining for free: a use-count-1 symbol is not hoisted, so its one
/// use inlines at the materialization site; a multi-use non-const/non-context
/// symbol hoists to a `ValDef` in its first-build scope. Dense ids are assigned as
/// the tree is built (no post-hoc renumber). Runs at the spike §7.2 position
/// (after all folds/lowering/tupling, before segregation); its input must already
/// be `prune_dead_vals`-cleaned so dead-code refs do not inflate the flat usage
/// count, and a final `crate::fold::fold` must run over its output to collapse the
/// constant adjacencies it exposes by P4-inlining constant-valued `val`s (the
/// constant-through-`val` case — see `crate::tree::compile`, oracle-pinned).
pub(crate) fn cse(root: Expr) -> Expr {
    let mut it = Interner::new();
    let root_sym = it.intern(&root);
    it.materialize(root_sym)
}

#[cfg(test)]
mod tests {
    use super::materialize::{val_def, val_use, wrap_block};
    use super::*;
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::opcode::{Expr, IrNode, Payload};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    // ----- helpers -----

    const PLUS: u8 = 0x9A;
    const GT: u8 = 0x91;
    const LT: u8 = 0x8F;
    const HEIGHT_OP: u8 = 0xA3;
    const INPUTS_OP: u8 = 0xA4;
    const BIN_XOR: u8 = 0xF4;
    /// `opt.getOrElse(d)` — NOT a scope-push site (M5 Task 5c/R2): its default is
    /// built eagerly in the enclosing scope. Test-local only.
    const OPT_GET_OR_ELSE: u8 = 0xE5;
    const TUPLE: u8 = 0x86;
    /// `Global` / `SigmaDslBuilder` singleton (P3 `IsInternalDef`).
    const GLOBAL_OP: u8 = 0xDD;
    /// `CreateProveDHTuple` (spike §5 / OQ4 P4 witness).
    const CREATE_PROVE_DHTUPLE: u8 = 0xCE;

    fn op0(opcode: u8) -> Expr {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::Zero,
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

    fn int(v: i32) -> Expr {
        Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(v),
        }
    }

    fn height() -> Expr {
        op0(HEIGHT_OP)
    }

    /// An opaque non-literal-tuple pair receiver (stands in for `SELF.tokens(1)`
    /// at the sym level — the memo keys on the receiver's SymId, not its type).
    fn pair_receiver() -> Expr {
        op0(INPUTS_OP)
    }

    /// `t._i` — a `SelectField` pair projection (`0x8C`, 1-based `field_idx`).
    fn select_field(input: Expr, field_idx: u8) -> Expr {
        Expr::Op(IrNode {
            opcode: SELECT_FIELD,
            payload: Payload::SelectField {
                input: Box::new(input),
                field_idx,
            },
        })
    }

    /// `HEIGHT + 1` — the shared keystone subexpression.
    fn height_plus_one() -> Expr {
        op2(PLUS, height(), int(1))
    }

    fn valuse(id: u32) -> Expr {
        Expr::Op(IrNode {
            opcode: VAL_USE,
            payload: Payload::ValUse { id },
        })
    }

    fn valdef(id: u32, rhs: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: VAL_DEF,
            payload: Payload::ValDef {
                id,
                tpe: None,
                rhs: Box::new(rhs),
            },
        })
    }

    fn block(items: Vec<Expr>, result: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: BLOCK_VALUE,
            payload: Payload::BlockValue {
                items,
                result: Box::new(result),
            },
        })
    }

    fn func_value(arg_id: u32, body: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: FUNC_VALUE,
            payload: Payload::FuncValue {
                args: vec![(arg_id, Some(SigmaType::SInt))],
                body: Box::new(body),
            },
        })
    }

    fn op4(opcode: u8, a: Expr, b: Expr, c: Expr, d: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode,
            payload: Payload::Four(Box::new(a), Box::new(b), Box::new(c), Box::new(d)),
        })
    }

    /// A `GroupElement` constant with a deterministic body (distinct `prefix` ⇒
    /// distinct value ⇒ distinct hash-cons symbol). Valid SEC1 compressed prefix.
    fn ge_const(prefix: u8) -> Expr {
        let mut bytes = [prefix; 33];
        bytes[0] = 0x02;
        Expr::Const {
            tpe: SigmaType::SGroupElement,
            val: SigmaValue::GroupElement(GroupElement::from_bytes(bytes)),
        }
    }

    /// Count distinct interned symbols whose class is opcode `op`.
    fn count_op(it: &Interner, op: u8) -> usize {
        it.symbols_with_opcode(op).len()
    }

    /// The single symbol of opcode `op` (asserts uniqueness first).
    fn only_op(it: &Interner, op: u8) -> SymId {
        let syms = it.symbols_with_opcode(op);
        assert_eq!(syms.len(), 1, "expected exactly one {op:#x} symbol");
        syms[0]
    }

    // ----- happy path -----

    #[test]
    fn equal_consts_share_and_distinct_consts_split() {
        // Two byte-identical constants hash-cons to one symbol; a different
        // value is a different symbol. Type-stripped structural identity.
        let mut it = Interner::new();
        let a = it.intern(&int(42));
        let b = it.intern(&int(42));
        let c = it.intern(&int(43));
        assert_eq!(a, b, "equal Const values must hash-cons to one symbol");
        assert_ne!(a, c, "distinct Const values must be distinct symbols");
        assert_eq!(it.const_symbol_count(), 2);
    }

    // ----- E1..E6 source shapes at the symbol level (spike §6) -----

    #[test]
    fn e1_and_shares_val_across_both_arms() {
        // E1: `{ val a = HEIGHT+1; a>5 && a<100 }`.
        // `a` is built once at root (the block val), so BOTH `&&` arms resolve
        // it to the same symbol — one Plus symbol, and the two comparisons share
        // an identical first child.
        let e1 = block(
            vec![valdef(1, height_plus_one())],
            op2(
                BIN_AND,
                op2(GT, valuse(1), int(5)),
                op2(LT, valuse(1), int(100)),
            ),
        );
        let mut it = Interner::new();
        it.intern(&e1);

        assert_eq!(count_op(&it, PLUS), 1, "HEIGHT+1 built once at root");
        let gt = it.symbols_with_opcode(GT)[0];
        let lt = it.symbols_with_opcode(LT)[0];
        assert_eq!(
            it.children_of(gt)[0],
            it.children_of(lt)[0],
            "both && arms must resolve `a` to the SAME SymId"
        );
    }

    #[test]
    fn e2_sibling_if_branches_do_not_share_keystone() {
        // E2: `if(HEIGHT>0) HEIGHT+1>5 else HEIGHT+1<100` — the KEYSTONE.
        // `HEIGHT+1` is first built INSIDE each branch (sibling thunks), so the
        // two are distinct symbols → TWO Plus symbols. If this fails, the scope
        // mechanism is wrong.
        let e2 = op3(
            IF,
            op2(GT, height(), int(0)),
            op2(GT, height_plus_one(), int(5)),
            op2(LT, height_plus_one(), int(100)),
        );
        let mut it = Interner::new();
        it.intern(&e2);
        assert_eq!(
            count_op(&it, PLUS),
            2,
            "sibling branches must NOT share HEIGHT+1 (keystone)"
        );
    }

    #[test]
    fn e6_condition_built_expr_shared_across_branches_keystone() {
        // E6: `if(HEIGHT+1>0) HEIGHT+1>5 else HEIGHT+1<100` — the KEYSTONE twin.
        // `HEIGHT+1` is first built in the CONDITION (current/root scope), so it
        // is visible to both branch child-scopes via the parent chain → ONE Plus
        // symbol shared by condition + both branches. E6 differs from E2 ONLY in
        // the condition, yet shares where E2 does not.
        let e6 = op3(
            IF,
            op2(GT, height_plus_one(), int(0)),
            op2(GT, height_plus_one(), int(5)),
            op2(LT, height_plus_one(), int(100)),
        );
        let mut it = Interner::new();
        it.intern(&e6);
        assert_eq!(
            count_op(&it, PLUS),
            1,
            "condition-built HEIGHT+1 must be shared across both branches (keystone)"
        );
    }

    #[test]
    fn e3_height_and_const_hashcons_at_symbol_level() {
        // E3: `HEIGHT>42 && HEIGHT<42`.
        // The left arm builds HEIGHT and 42 at ROOT (global); the scoped right
        // arm's HEIGHT / 42 lookups hit global, so at the INTERNING level both
        // hash-cons to ONE symbol each. NOTE: this is Phase A only. The LATER
        // gates (Tasks 2-3) diverge: P2 `IsContextProperty` re-emits HEIGHT
        // inline per use (never a ValDef) and P4 `IsConstantDef` suppresses the
        // constant's ValDef so constant segregation gives the `42` TWO
        // per-occurrence pool slots with no dedup (spike §5, E3 decoded tree).
        let e3 = op2(
            BIN_AND,
            op2(GT, height(), int(42)),
            op2(LT, height(), int(42)),
        );
        let mut it = Interner::new();
        it.intern(&e3);
        assert_eq!(
            count_op(&it, HEIGHT_OP),
            1,
            "HEIGHT hash-cons to one symbol"
        );
        assert_eq!(
            it.const_symbol_count(),
            1,
            "the `42` hash-cons to one symbol at Phase A (segregated to 2 slots later)"
        );
    }

    #[test]
    fn e5_val_at_root_shares_across_if_branches_vs_e2() {
        // E5: `{ val a = HEIGHT+1; if(HEIGHT>0) a>5 else a<100 }`.
        // The val puts HEIGHT+1 at ROOT (global), so both `if` branches resolve
        // `a` to it → ONE Plus symbol. Contrast E2 (no val, same branch shapes)
        // which yields TWO — the first-build-site rule in one pair.
        let e5 = block(
            vec![valdef(1, height_plus_one())],
            op3(
                IF,
                op2(GT, height(), int(0)),
                op2(GT, valuse(1), int(5)),
                op2(LT, valuse(1), int(100)),
            ),
        );
        let mut it = Interner::new();
        it.intern(&e5);
        assert_eq!(
            count_op(&it, PLUS),
            1,
            "root val makes HEIGHT+1 shared across both if branches (contrast E2=2)"
        );
    }

    // ----- scope-site mechanics -----

    #[test]
    fn binxor_is_eager_both_arms_current_scope() {
        // `(HEIGHT+1) ^ (HEIGHT+1)` — BinXor (0xF4) is EAGER (spike §2): no
        // thunk is pushed, both arms are interned in the current (root) scope,
        // so the two identical operands hash-cons to ONE Plus symbol.
        let xor = op2(BIN_XOR, height_plus_one(), height_plus_one());
        let mut it = Interner::new();
        it.intern(&xor);
        assert_eq!(
            count_op(&it, PLUS),
            1,
            "BinXor is eager: both arms share the current-scope symbol"
        );
    }

    #[test]
    fn option_get_or_else_default_is_enclosing_scope_not_thunk() {
        // CORRECTED mechanism check (M5 Task 5c/R2): `getOrElse` does NOT thunk
        // its default — the default is built eagerly in the ENCLOSING scope
        // (GraphBuilding.scala:441,962,1013-1035 + Thunks.scala:261,283-286).
        // Distinguishing test vs a thunk-push: two SIBLING getOrElse nodes with
        // byte-identical defaults (`HEIGHT+1`) but distinct receivers. Under the
        // (wrong) thunk model each default lands in its own sibling thunk → TWO
        // distinct Plus symbols. Under the correct eager model both defaults are
        // built in the shared root scope → hash-cons → ONE Plus symbol. This is
        // the exact under-sharing that pinned buy-token-for-erg's 2 missing root
        // ValDefs.
        let e = Expr::Op(IrNode {
            opcode: TUPLE,
            payload: Payload::Tuple {
                items: vec![
                    op2(OPT_GET_OR_ELSE, int(0), height_plus_one()),
                    op2(OPT_GET_OR_ELSE, int(1), height_plus_one()),
                ],
            },
        });
        let mut it = Interner::new();
        it.intern(&e);
        assert_eq!(
            count_op(&it, PLUS),
            1,
            "sibling getOrElse defaults share (eager, enclosing-scope) — NOT thunk-local"
        );
    }

    // ----- pair projections (M5 Task 5d, Tuples.scala:57-74) -----

    #[test]
    fn pair_projection_root_forced_receiver_shares_second_across_if_branches() {
        // Probe A (m5-basis-token-recon §3): the pair receiver is projected at
        // ROOT via `._1`, then `._2` in BOTH `if` branches. Scala's `unzipPair`
        // builds First+Second together at the root `._1` (Tuples.scala:65) and
        // memoizes them process-wide (`tuplesCache`, :57), so both branch `._2`
        // resolve to the ONE root Second symbol — the cross-branch ValDef share.
        //   { val r1 = p._1; if (HEIGHT>0) p._2 else p._2 }
        let e = block(
            vec![valdef(1, select_field(pair_receiver(), 1))],
            op3(
                IF,
                op2(GT, height(), int(0)),
                select_field(pair_receiver(), 2),
                select_field(pair_receiver(), 2),
            ),
        );
        let mut it = Interner::new();
        it.intern(&e);

        // Exactly two projection symbols exist: the root First (`._1`) and the
        // root Second (`._2`) — both branches reuse the memoized Second, none is
        // rebuilt thunk-locally.
        assert_eq!(
            count_op(&it, SELECT_FIELD),
            2,
            "root `._1` forces First+Second at root; both branch `._2` reuse the memo"
        );
        // Both `if` branches (children[1]/[2]) resolve `._2` to the SAME SymId.
        let if_sym = only_op(&it, IF);
        let branches = it.children_of(if_sym);
        assert_eq!(
            branches[1], branches[2],
            "both branch `._2` must resolve to the one shared root Second symbol"
        );
    }

    #[test]
    fn pair_projection_thunk_local_receiver_does_not_share_second_across_branches() {
        // Probe B (m5-basis-token-recon §3, the CONTROL): the receiver is NEVER
        // projected at root — its first projection is INSIDE each branch. Each
        // branch builds a DISTINCT thunk-local receiver SymId, so the memo (keyed
        // by receiver SymId) never bridges them: two distinct `._2`, NO share.
        // This is the exact non-share that keeps `selfOut.tokens(1)._2` unshared.
        //   if (HEIGHT>0) p._2 else p._2      // no root projection of p
        let e = op3(
            IF,
            op2(GT, height(), int(0)),
            select_field(pair_receiver(), 2),
            select_field(pair_receiver(), 2),
        );
        let mut it = Interner::new();
        it.intern(&e);

        // Each branch: a distinct receiver + its eager First/Second pair → four
        // projection symbols, and the two `._2` are DISTINCT.
        assert_eq!(
            count_op(&it, SELECT_FIELD),
            4,
            "thunk-local receivers give each branch its own First/Second pair"
        );
        let if_sym = only_op(&it, IF);
        let branches = it.children_of(if_sym);
        assert_ne!(
            branches[1], branches[2],
            "sibling-thunk `._2` on a thunk-local receiver must NOT share"
        );
    }

    #[test]
    fn pair_projection_unused_sibling_does_not_inflate_receiver_usage() {
        // The eager sibling (Tuples.scala:65) must be output-neutral when unused:
        // `p._1 > 5` builds `._1` AND (eagerly) `._2`, but `._2` is unreachable
        // from the root, so — like Scala's reachable-flatSchedule count — it must
        // NOT add a use of `p`. Otherwise `p` would reach 2 uses and wrongly hoist.
        let e = op2(GT, select_field(pair_receiver(), 1), int(5));
        let mut it = Interner::new();
        let root = it.intern(&e);
        let usage = it.flat_usage_reachable(root);
        // The receiver `p` (INPUTS) is used exactly ONCE (by the live `._1`),
        // not twice — the dead `._2` sibling contributes nothing.
        let p = only_op(&it, INPUTS_OP);
        assert_eq!(
            usage.get(&p).copied().unwrap_or(0),
            1,
            "unused eager sibling must not count as a use of the receiver"
        );
        assert!(!Interner::has_many(&usage, p));
    }

    // ----- lambdas (spike §1.4) -----

    #[test]
    fn lambda_bodies_share_root_def_and_track_bound_var_deps() {
        // Two sibling lambdas over a root-built `k = HEIGHT+1`:
        //   { val k = HEIGHT+1;
        //     ( b => b > k ,  c => c > k ) }
        // Lambdas push no hash-cons scope, so `k` (bound-var-free) is a single
        // root symbol shared into BOTH bodies → ONE Plus symbol. The two body
        // comparisons differ (distinct arg ids → distinct ValUse → distinct GT)
        // → TWO GT symbols. Each GT depends on its own arg id; `k` depends on no
        // bound var (float-up candidate).
        let e = block(
            vec![valdef(1, height_plus_one())],
            Expr::Op(IrNode {
                opcode: TUPLE,
                payload: Payload::Tuple {
                    items: vec![
                        func_value(2, op2(GT, valuse(2), valuse(1))),
                        func_value(3, op2(GT, valuse(3), valuse(1))),
                    ],
                },
            }),
        );
        let mut it = Interner::new();
        it.intern(&e);

        assert_eq!(count_op(&it, PLUS), 1, "root `k` shared into both lambdas");
        let gts = it.symbols_with_opcode(GT);
        assert_eq!(
            gts.len(),
            2,
            "sibling lambda bodies do not share (distinct args)"
        );

        // Bound-var dependency tags: each GT depends on exactly its own arg id;
        // `k` (the Plus) depends on none.
        assert_eq!(it.deps_of(gts[0]), &BTreeSet::from([2]));
        assert_eq!(it.deps_of(gts[1]), &BTreeSet::from([3]));
        let plus = it.symbols_with_opcode(PLUS)[0];
        assert!(
            it.deps_of(plus).is_empty(),
            "HEIGHT+1 is bound-var-free (floats up in Task 3)"
        );

        // A FuncValue is lambda-invariant w.r.t. its OWN bound var (Scala
        // `freeVars` excludes a Lambda's arguments): each of these lambdas
        // references only its own arg + the root-shared `k`, so its deps are
        // EMPTY (a float-up candidate). The arg dependency lives on the BODY
        // nodes (the two GTs above, deps {2}/{3}), not on the FuncValue itself —
        // this is what lets a shared closed `def` (`deposit.es`'s `getSellerPk`)
        // schedule as a root ValDef instead of inlining.
        let funcs = it.symbols_with_opcode(FUNC_VALUE);
        assert_eq!(funcs.len(), 2);
        assert!(it.deps_of(funcs[0]).is_empty());
        assert!(it.deps_of(funcs[1]).is_empty());
    }

    // ----- Phase B: flat usage count + admission gate (Task 2, spike §3/§5) -----

    #[test]
    fn flat_usage_counts_each_reference_with_multiplicity() {
        // `7 + 7` — the two operands hash-cons to ONE const symbol referenced
        // twice (Scala's `syms = [x, x]` counts with multiplicity, spike §3).
        let e = op2(PLUS, int(7), int(7));
        let mut it = Interner::new();
        it.intern(&e);
        let usage = it.flat_usage();
        let c7 = only_op_const(&it);
        assert_eq!(
            usage.get(&c7).copied(),
            Some(2),
            "one operand symbol used 2x"
        );
        assert!(Interner::has_many(&usage, c7));
        // The Plus is a tree root — referenced by nothing.
        let plus = only_op(&it, PLUS);
        assert_eq!(usage.get(&plus).copied().unwrap_or(0), 0);
    }

    #[test]
    fn e1_shared_val_is_hoist_eligible() {
        // E1: `{ val a = HEIGHT+1; a>5 && a<100 }`. `a` (the Plus) is referenced by
        // both comparison arms → count 2 → has_many, and clears P2/P3/P4 → HOIST.
        let e1 = block(
            vec![valdef(1, height_plus_one())],
            op2(
                BIN_AND,
                op2(GT, valuse(1), int(5)),
                op2(LT, valuse(1), int(100)),
            ),
        );
        let mut it = Interner::new();
        it.intern(&e1);
        let usage = it.flat_usage();
        let plus = only_op(&it, PLUS);
        assert_eq!(usage.get(&plus).copied(), Some(2));
        assert!(
            it.should_hoist(plus, &usage),
            "E1 `a = HEIGHT+1` used twice, all predicates pass → hoist-eligible"
        );
        // HEIGHT inside the Plus is used once here and is a context property either
        // way → never hoisted.
        let h = only_op(&it, HEIGHT_OP);
        assert!(it.is_context_property(h));
        assert!(!it.should_hoist(h, &usage));
    }

    #[test]
    fn e5_root_val_hoists_e6_condition_built_hoists() {
        // E5: root `val a` → Plus used by both if-branches (count 2) → hoist.
        let e5 = block(
            vec![valdef(1, height_plus_one())],
            op3(
                IF,
                op2(GT, height(), int(0)),
                op2(GT, valuse(1), int(5)),
                op2(LT, valuse(1), int(100)),
            ),
        );
        let mut it5 = Interner::new();
        it5.intern(&e5);
        let u5 = it5.flat_usage();
        let plus5 = only_op(&it5, PLUS);
        assert_eq!(u5.get(&plus5).copied(), Some(2));
        assert!(it5.should_hoist(plus5, &u5), "E5 root val hoists");

        // E6: HEIGHT+1 first built in the condition → shared by cond + both
        // branches (count 3) → hoist.
        let e6 = op3(
            IF,
            op2(GT, height_plus_one(), int(0)),
            op2(GT, height_plus_one(), int(5)),
            op2(LT, height_plus_one(), int(100)),
        );
        let mut it6 = Interner::new();
        it6.intern(&e6);
        let u6 = it6.flat_usage();
        let plus6 = only_op(&it6, PLUS);
        assert_eq!(u6.get(&plus6).copied(), Some(3));
        assert!(
            it6.should_hoist(plus6, &u6),
            "E6 condition-built Plus hoists"
        );
    }

    #[test]
    fn e3_height_context_prop_and_const_both_used_twice_never_hoist() {
        // E3: `HEIGHT>42 && HEIGHT<42`. HEIGHT and `42` each hash-cons to one
        // symbol used twice → has_many BOTH — yet P2 (HEIGHT) and P4 (`42`)
        // suppress each → NOTHING hoists (spike's "no ValDef" E3 prediction).
        let e3 = op2(
            BIN_AND,
            op2(GT, height(), int(42)),
            op2(LT, height(), int(42)),
        );
        let mut it = Interner::new();
        it.intern(&e3);
        let usage = it.flat_usage();

        let h = only_op(&it, HEIGHT_OP);
        assert!(Interner::has_many(&usage, h), "HEIGHT used twice");
        assert!(it.is_context_property(h));
        assert!(!it.should_hoist(h, &usage), "P2 suppresses HEIGHT");

        let c42 = only_op_const(&it);
        assert!(Interner::has_many(&usage, c42), "`42` used twice");
        assert!(it.is_const(c42));
        assert!(!it.should_hoist(c42, &usage), "P4 suppresses the constant");

        // No symbol at all clears the gate.
        assert!(
            (0..it.syms.len()).all(|i| !it.should_hoist(SymId(i as u32), &usage)),
            "E3 hoists nothing"
        );
    }

    #[test]
    fn e2_sibling_copies_each_used_once_do_not_hoist() {
        // E2: `if(HEIGHT>0) HEIGHT+1>5 else HEIGHT+1<100`. The two sibling-thunk
        // `HEIGHT+1` copies are DISTINCT symbols (Task 1), each referenced once →
        // neither has_many → nothing hoists. Sibling-distinctness is load-bearing:
        // if interning had merged them the count would be 2 and one would hoist.
        let e2 = op3(
            IF,
            op2(GT, height(), int(0)),
            op2(GT, height_plus_one(), int(5)),
            op2(LT, height_plus_one(), int(100)),
        );
        let mut it = Interner::new();
        it.intern(&e2);
        let usage = it.flat_usage();
        let pluses = it.symbols_with_opcode(PLUS);
        assert_eq!(pluses.len(), 2, "sibling copies are distinct symbols");
        for p in &pluses {
            assert_eq!(usage.get(p).copied().unwrap_or(0), 1, "each copy used once");
            assert!(!it.should_hoist(*p, &usage));
        }
    }

    #[test]
    fn single_use_subexpr_is_not_hoisted() {
        // `(HEIGHT+1) > 5` — the Plus is referenced exactly once (by the GT), so
        // has_many is false → not hoisted. Single-use inlining falls out for free.
        let e = op2(GT, height_plus_one(), int(5));
        let mut it = Interner::new();
        it.intern(&e);
        let usage = it.flat_usage();
        let plus = only_op(&it, PLUS);
        assert_eq!(usage.get(&plus).copied(), Some(1));
        assert!(!Interner::has_many(&usage, plus));
        assert!(
            !it.should_hoist(plus, &usage),
            "single-use → inline, not hoist"
        );
    }

    #[test]
    fn global_builder_singleton_used_twice_is_internal_not_hoisted() {
        // P3: `Global`(0xDD) = our `SigmaDslBuilder`. Referenced twice → has_many,
        // but `is_internal` suppresses the ValDef. (`CollBuilder` has no OUR-IR
        // node, so that half of `IsInternalDef` is vacuous — see the const docs.)
        let e = op2(PLUS, op0(GLOBAL_OP), op0(GLOBAL_OP));
        let mut it = Interner::new();
        it.intern(&e);
        let usage = it.flat_usage();
        let g = only_op(&it, GLOBAL_OP);
        assert!(
            Interner::has_many(&usage, g),
            "builder singleton used twice"
        );
        assert!(it.is_internal(g));
        assert!(
            !it.should_hoist(g, &usage),
            "P3 suppresses the builder singleton"
        );
    }

    #[test]
    fn context_property_predicate_excludes_a6_and_ac() {
        // Lock the exact `IsContextProperty` set: `LastBlockUtxoRootHash`(0xA6) and
        // `MinerPubkey`(0xAC) are context nodes but are NOT context properties in
        // Scala (`TreeBuilding.scala:140-148`), so they must NOT match P2.
        let mut it = Interner::new();
        let a6 = it.intern(&op0(0xA6));
        let ac = it.intern(&op0(0xAC));
        assert!(
            !it.is_context_property(a6),
            "0xA6 is not a context property"
        );
        assert!(
            !it.is_context_property(ac),
            "0xAC is not a context property"
        );
        // Sanity: a genuine one does match.
        let h = it.intern(&height());
        assert!(it.is_context_property(h));
    }

    #[test]
    fn provedhtuple_repeated_ge_consts_hoist_liftedconst_not_p4_suppressed() {
        // M5 Task 5 Fix 2 (`m5-sched-small.md` §1.3): `proveDHTuple(…)` over
        // repeated `GroupElement` constants. A `GroupElement` literal is a
        // `LiftedConst`, NOT Scala's narrow `Const[_]`, so P4 (`IsConstantDef`)
        // structurally cannot see it — it hoists like any ordinary multi-use
        // node. Here two DISTINCT group elements each arrive at CSE referenced
        // TWICE (positions 0/2 and 1/3); each is `has_many`, clears P2/P3, and is
        // NOT `is_const` → BOTH hoist. (The live `cce` env binds g1==g2 to ONE
        // value used 4×, giving the single `ValDef(1)` the oracle emits; this
        // two-distinct-value probe isolates the predicate flip.)
        let e = op4(
            CREATE_PROVE_DHTUPLE,
            ge_const(0x11),
            ge_const(0x22),
            ge_const(0x11),
            ge_const(0x22),
        );
        let mut it = Interner::new();
        it.intern(&e);
        let usage = it.flat_usage();

        let consts = it.symbols_with_opcode_const();
        assert_eq!(consts.len(), 2, "g1 and g2 are two distinct const symbols");
        for c in &consts {
            assert_eq!(usage.get(c).copied(), Some(2), "each GE const used twice");
            assert!(Interner::has_many(&usage, *c));
            assert!(
                !it.is_const(*c),
                "a GroupElement literal is a LiftedConst — P4 does not match it"
            );
            assert!(
                it.should_hoist(*c, &usage),
                "the GE const clears all four predicates → hoists (Fix 2)"
            );
        }
    }

    #[test]
    fn provedhtuple_cce_single_ge_const_hoists_to_one_valdef_matches_oracle() {
        // The live `cce` vector `proveDHTuple(g1, g2, g1, g2)` (seed index 61):
        // the DEMO env binds g1 and g2 to the SAME `GroupElementConstant`
        // (secp256k1 generator), so all four arguments are one const symbol used
        // 4× → a single `ValDef(1)` whose rhs segregates to `ConstPlaceholder(0)`,
        // result `ProveDHTuple(v1,v1,v1,v1)`. Byte-exact vs the Scala 6.0.2 `cce`
        // oracle (`m5-sched-small.md` §1.2). Fix 2 is what makes this ValDef appear.
        let g = ge_const(0x42);
        let e = op4(CREATE_PROVE_DHTUPLE, g.clone(), g.clone(), g.clone(), g);
        let mut it = Interner::new();
        let root = it.intern(&e);
        let mat = it.materialize(root);
        let expected = block(
            vec![val_def(1, ge_const(0x42))],
            op4(
                CREATE_PROVE_DHTUPLE,
                valuse(1),
                valuse(1),
                valuse(1),
                valuse(1),
            ),
        );
        assert_eq!(mat, expected);
    }

    // ----- Task 3: ValDef materialization — byte-exact vs the JVM oracle -----
    //
    // Each vector below runs the pipeline PREFIX that precedes CSE (emit → the
    // M4 fold/inline transforms), then this module's `materialize`, then the
    // existing segregation + `write_ergo_tree`, and byte-compares the FULL tree
    // bytes to the Scala 6.0.2 `cc` oracle (spike §6 E1–E6, captured live via
    // `scripts/jvm_typer_oracle`). This is the first CSE task producing bytes to
    // diff, so the comparison is end-to-end against the reference compiler — not
    // a self-oracle.
    //
    // Placement note (route coercion vs explicit `sigmaProp`): the route wraps a
    // Boolean source in `BoolToSigmaProp` AFTER `buildTree` (so the block sits
    // INSIDE: `d1 d801 …`), while an explicit `sigmaProp({block})` has the
    // wrapper IN the graph root (block OUTSIDE: `d801 … d1 …`). Both are the SAME
    // `materialize`, applied at a different root — `via_cse` reproduces the
    // order by materializing the inner Boolean and wrapping after, matching
    // Scala's `buildTree`-then-`toSigmaProp` order. Both placements are asserted
    // (e1_* covers both).

    use crate::env::ScriptEnv;
    use crate::stype::SType;
    use crate::typed::node_tpe;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::address::NetworkPrefix;
    use ergo_ser::ergo_tree::write_ergo_tree;
    use ergo_ser::opcode::write_expr;

    /// Compile `source` through the CSE materializer and return the full
    /// segregated `ergo_tree` bytes as lowercase hex — the exact string the
    /// `cc <hex>` oracle answers with. `tree_version = 3`, mainnet (matching the
    /// oracle default).
    fn via_cse(source: &str) -> String {
        let (inner, wrap_sigma) = pre_cse_root(source);
        let mut it = Interner::new();
        let root = it.intern(&inner);
        let mat = it.materialize(root);
        // Route coercion, applied AFTER CSE (Scala buildTree-then-toSigmaProp).
        let final_root = if wrap_sigma {
            Expr::Op(IrNode {
                opcode: 0xD1, // BoolToSigmaProp
                payload: Payload::One(Box::new(mat)),
            })
        } else {
            mat
        };
        let tree = crate::tree::build_tree(final_root).expect("build_tree");
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree).expect("write_ergo_tree");
        hex(&w.result())
    }

    /// Run the pipeline transforms that PRECEDE the CSE slot (spike §7.2), the
    /// same ones `crate::tree::compile` runs, and return the pre-CSE root plus
    /// whether the route must re-wrap it in `BoolToSigmaProp` after CSE. A
    /// Boolean source is materialized bare and wrapped after (matching Scala's
    /// order); an explicit `sigmaProp(...)` source keeps its wrapper in the tree.
    fn pre_cse_root(source: &str) -> (Expr, bool) {
        let typed =
            crate::typecheck_with_network(&ScriptEnv::new(), source, 3, NetworkPrefix::Mainnet)
                .expect("typecheck");
        let (inner, wrap) = match node_tpe(&typed) {
            SType::SSigmaProp => (crate::emit::emit(&typed).expect("emit"), false),
            SType::SBoolean => (crate::emit::emit(&typed).expect("emit"), true),
            other => panic!("unexpected root type: {other:?}"),
        };
        // The CSE-preceding M4 transforms, MINUS `inline_vals`: CSE subsumes val
        // inlining via its hash-cons (locked decision 4). This is load-bearing,
        // not incidental — `inline_vals` SYNTACTICALLY clones a shared `def`'s
        // rhs into each use site, and when two uses land in sibling thunks (e.g.
        // `deposit.es`: `def f = …; if (c) f(SELF) else f(SELF)`) the clones
        // become sibling-distinct symbols that never share, so CSE would never
        // hoist the def. Scala's `buildGraph` instead threads the shared GRAPH
        // NODE, which is exactly what `intern` reproduces (a `ValDef`'s rhs is
        // interned once; every `ValUse` resolves to that one symbol). So CSE must
        // see the un-inlined tree. `prune_dead_vals` is kept so a dead `val`'s
        // rhs is not interned (its refs would otherwise inflate the flat usage
        // count). `fold_direct_const_casts` is a no-op for these cast-free
        // vectors and is private to tree.rs, so it is omitted.
        //
        // Task-4 note: the fold pass in `crate::tree::compile` runs AFTER
        // `inline_vals` (so `{val x=2; x+1}` folds to `3`). Dropping the inline
        // here loses that constant-through-`val` propagation — none of the Task-3
        // single-ValDef vectors exercise it, but Task 4's retirement of
        // `inline.rs` into CSE must fold over the interned graph (or keep a
        // constant-only pre-inline) to preserve it.
        let inner = crate::isproven::eliminate_isproven(inner);
        let inner = crate::fold::fold(inner).expect("fold");
        let inner = crate::inline::prune_dead_vals(inner);
        (inner, wrap)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ----- E1..E6 oracle byte-parity (single-ValDef class) -----

    #[test]
    fn e1_bool_source_valdef_inside_sigmaprop_matches_oracle() {
        // E1 route-coerced Boolean: ValDef(1)=HEIGHT+1 shared across both `&&`
        // arms, block INSIDE BoolToSigmaProp.
        assert_eq!(
            via_cse("{val a = HEIGHT + 1; a > 5 && a < 100}"),
            "10030402040a04c801d1d801d6019aa37300ed91720173018f72017302"
        );
    }

    #[test]
    fn e1_explicit_sigmaprop_valdef_outside_matches_oracle() {
        // Same graph, explicit `sigmaProp({block})`: the wrapper is the graph
        // root, so the ValDef block hoists ABOVE it (`d801 … d1 …`). Proves the
        // id/ValDef materialization is placement-agnostic.
        assert_eq!(
            via_cse("sigmaProp({val a = HEIGHT + 1; a > 5 && a < 100})"),
            "10030402040a04c801d801d6019aa37300d1ed91720173018f72017302"
        );
    }

    #[test]
    fn e2_sibling_if_branches_no_valdef_matches_oracle() {
        // Keystone: HEIGHT+1 first built inside each branch (sibling thunks) →
        // two distinct single-use copies → NO ValDef, no BlockValue.
        assert_eq!(
            via_cse("if (HEIGHT > 0) HEIGHT + 1 > 5 else HEIGHT + 1 < 100"),
            "100504000402040a040204c801d19591a37300919aa3730173028f9aa373037304"
        );
    }

    #[test]
    fn e3_const_and_context_prop_suppressed_no_valdef_matches_oracle() {
        // `42` used 2× but P4-suppressed (two pool slots, no dedup); HEIGHT
        // P2-suppressed (inline both arms) → no ValDef.
        assert_eq!(
            via_cse("HEIGHT > 42 && HEIGHT < 42"),
            "100204540454d1ed91a373008fa37301"
        );
    }

    #[test]
    fn e5_root_val_shared_across_if_branches_matches_oracle() {
        // Root `val a` dominates both If branches → ValDef(1), branches ValUse(1).
        assert_eq!(
            via_cse("{val a = HEIGHT + 1; if (HEIGHT > 0) a > 5 else a < 100}"),
            "100404020400040a04c801d1d801d6019aa373009591a3730191720173028f72017303"
        );
    }

    #[test]
    fn e6_condition_built_expr_shared_across_branches_matches_oracle() {
        // HEIGHT+1 first built in the condition (root) → shared cond + both
        // branches → ValDef(1). Same tree shape as E5 bar the condition operand.
        assert_eq!(
            via_cse("if (HEIGHT + 1 > 0) HEIGHT + 1 > 5 else HEIGHT + 1 < 100"),
            "100404020400040a04c801d1d801d6019aa3730095917201730191720173028f72017303"
        );
    }

    #[test]
    fn e4_lambda_arg_id_threading_matches_oracle() {
        // Root ValDef k=id1 shared into TWO sibling lambdas; each lambda arg =
        // defId(1)+1 = id 2 (`d9 01 02`), body ValUse(1)=k. Proves the assign-once
        // id threading through FuncValue (spike §4).
        assert_eq!(
            via_cse(
                "{val k = HEIGHT + 1; \
                 OUTPUTS.exists({(b: Box) => b.creationInfo._1 > k}) && \
                 INPUTS.exists({(b: Box) => b.creationInfo._1 > k})}"
            ),
            "10010402d1d801d6019aa37300edaea5d9010263918cc77202017201\
aea4d9010263918cc77202017201"
        );
    }

    // ----- pre-segregation body structure (dual gate: ValDef/ValUse shape) -----

    #[test]
    fn e1_pre_segregation_body_has_expected_valdef_valuse_shape() {
        // Independently of constant segregation, the materialized body (constants
        // still inline) must carry the ValDef/ValUse/BlockValue structure:
        // `d1 d801 d601 <plus> ed 91 7201 <5> 8f 7201 <100>` with inline consts
        // `0402`/`040a`/`04c801`. This is the ValDef-shape half of the dual gate
        // (the segregated tests above pin the constant-pool half).
        let (inner, wrap) = pre_cse_root("{val a = HEIGHT + 1; a > 5 && a < 100}");
        assert!(wrap, "Boolean source must re-wrap after CSE");
        let mut it = Interner::new();
        let root = it.intern(&inner);
        let mat = it.materialize(root);
        let wrapped = Expr::Op(IrNode {
            opcode: 0xD1,
            payload: Payload::One(Box::new(mat)),
        });
        let mut w = VlqWriter::new();
        write_expr(&mut w, &wrapped, false).expect("write_expr");
        assert_eq!(
            hex(&w.result()),
            "d1d801d6019aa30402ed917201040a8f720104c801"
        );
    }

    // ----- id-threading / collapse unit checks (hand-built, no source) -----

    #[test]
    fn materialize_no_hoist_returns_bare_tree() {
        // A single-use subexpression is inlined (not hoisted): `(HEIGHT+1) > 5`
        // materializes back to the same GT tree, no BlockValue.
        let e = op2(GT, height_plus_one(), int(5));
        let mut it = Interner::new();
        let root = it.intern(&e);
        let mat = it.materialize(root);
        assert_eq!(mat, e);
    }

    #[test]
    fn materialize_root_valdef_gets_dense_id_one() {
        // E1 inner (Boolean) materializes to BlockValue([ValDef(1, HEIGHT+1)],
        // BinAnd(GT(ValUse(1),5), LT(ValUse(1),100))) — id 1 dense, both arms
        // ValUse(1). Asserted structurally (independent of serialization).
        let e = block(
            vec![valdef(9, height_plus_one())], // emit-time id 9 → reassigned to 1
            op2(
                BIN_AND,
                op2(GT, valuse(9), int(5)),
                op2(LT, valuse(9), int(100)),
            ),
        );
        let mut it = Interner::new();
        let root = it.intern(&e);
        let mat = it.materialize(root);
        let expected = block(
            vec![valdef(1, height_plus_one())],
            op2(
                BIN_AND,
                op2(GT, valuse(1), int(5)),
                op2(LT, valuse(1), int(100)),
            ),
        );
        assert_eq!(mat, expected);
    }

    #[test]
    fn root_thunked_conjunct_block_emits_before_eager_block() {
        // M5 Task 5e (basis-token): schedule-order freeVars. Two distinct
        // multi-use root Boolean vals `x = HEIGHT>1`, `y = HEIGHT>2`, referenced
        // ONLY inside a single if-branch — as the two operands of `x && y`, where
        // `y` is the THUNKED right `&&` operand and `x` the EAGER left. Scala
        // schedules the nested thunk (carrying `y`) as a post-order entry BEFORE
        // the `BinAnd` that owns the eager `x`, so `freeVars` collects `y` before
        // `x` → the root ValDef schedule emits `y`'s block first (dense id 1),
        // `x`'s second. The pre-fix child-order collection emitted `x` first —
        // this asserts the reorder end-to-end through `materialize`.
        let e = block(
            vec![
                valdef(1, op2(GT, height(), int(1))), // x = HEIGHT > 1
                valdef(2, op2(GT, height(), int(2))), // y = HEIGHT > 2
            ],
            op3(
                IF,
                op2(GT, height(), int(0)),
                op2(BIN_AND, valuse(1), valuse(2)), // then: x && y  (y thunked)
                op2(BIN_OR, valuse(1), valuse(2)),  // else: x || y  (2nd use → hoist)
            ),
        );
        let mut it = Interner::new();
        let root = it.intern(&e);
        let mat = it.materialize(root);
        let Expr::Op(IrNode {
            opcode: BLOCK_VALUE,
            payload: Payload::BlockValue { items, .. },
        }) = &mat
        else {
            panic!("expected a root BlockValue, got {mat:?}");
        };
        assert_eq!(items.len(), 2, "both x and y hoist to root ValDefs");
        // Decisive: id 1 is `y` (HEIGHT>2, the thunked conjunct), id 2 is `x`.
        assert_eq!(
            items[0],
            valdef(1, op2(GT, height(), int(2))),
            "thunked conjunct block (y) must emit before the eager block (x)"
        );
        assert_eq!(items[1], valdef(2, op2(GT, height(), int(1))));
    }

    #[test]
    fn materialize_singleton_valuse_block_collapses() {
        // The `{ val idNew = ValUse(t); ValUse(idNew) } → ValUse(t)` peephole
        // (TreeBuilding.scala:522-525). Hand-build a graph where the scope root
        // is exactly a shared alias to a lambda arg used twice inside a body,
        // exercised via a lambda whose body is `{ val n = b; (n, n) }`-shaped is
        // over-complex; instead assert the peephole directly on `wrap_block`.
        let collapsed = wrap_block(vec![val_def(3, val_use(7))], val_use(3));
        assert_eq!(collapsed, val_use(7));
        // Non-matching id → no collapse (stays a block).
        let kept = wrap_block(vec![val_def(3, val_use(7))], val_use(4));
        assert!(matches!(
            kept,
            Expr::Op(IrNode {
                opcode: BLOCK_VALUE,
                ..
            })
        ));
    }

    // ----- corpus graduation (single-ValDef class) -----

    #[test]
    fn corpus_crystalpool_deposit_matches_oracle() {
        // `crystalpool/deposit.es` — a shared `def getSellerPk` (a closed lambda)
        // called from BOTH `if` branches. Its FuncValue is built once at root and
        // used twice → hoisted as a single root `ValDef(1, FuncValue)` with the
        // two branch calls as `FuncApply(ValUse(1), SELF)` — the single-ValDef
        // class over a lambda rhs. This vector is in `DC7_P2SH_MISMATCH_SET`
        // (M4-blocked on CSE); Task 3's `materialize` produces byte-identical
        // bytes to the Scala 6.0.2 `cc` oracle. It stays SET-listed until Task 4
        // wires CSE into `compile()` (this test proves the materializer, not the
        // live path).
        let src =
            std::fs::read_to_string("../test-vectors/ergoscript/corpus/crystalpool/deposit.es")
                .expect("read deposit.es");
        assert_eq!(
            via_cse(&src),
            "10010400d801d601d9010163b2e4c6720104147300009591a3\
dad9010263e4c67202050401a7da720101a7da720101a7"
        );
    }

    #[test]
    fn corpus_dexy_gort_emission_matches_oracle() {
        // `dexy/gort-dev/emission.es` — a SEVEN-ValDef root `BlockValue`
        // (`d807`) plus a nested one-ValDef block. Post-order-DFS schedule order
        // already matches Scala's `depthFirstOrderFrom(deps)` for this vector, so
        // it is byte-identical to the oracle — a Task-5 preview showing the
        // multi-ValDef machinery works where the schedule order coincides.
        // (The remaining chaincash/crystalpool multi-ValDef vectors do NOT yet
        // agree on schedule order — that is Task 5's reverse-engineering loop,
        // spike §7.4/OQ1 — so they stay in the mismatch set.) Also in
        // `DC7_P2SH_MISMATCH_SET`; graduates only once Task 4 wires CSE live.
        let src =
            std::fs::read_to_string("../test-vectors/ergoscript/corpus/dexy/gort-dev/emission.es")
                .expect("read emission.es");
        assert_eq!(
            via_cse(&src),
            "100d040004000402040204020402040004020402040204020402\
0402d807d601b2a57ee4e300030400d602db63087201d603db6308a7d604c27201d605c2a7\
d606ededed93b27202730000b27203730100938cb27202730200018cb272037303000193b4\
72047304b17204b472057305b1720592c17201c1a7d607e4c6a7040495937ee4e301020473\
06d1ededed7206918cb27202730700028cb272037308000293e4c672010404720793e4c672\
010508e4c6a70508d801d608e4c672010404ea02d1edededed7206918cb27203730900028c\
b27202730a000290998cb27203730b00028cb27202730c00027e997208720705917208720\
7907208a3e4c6a70508"
        );
    }

    // ----- test-only introspection helpers -----

    /// The single `Const` symbol (asserts uniqueness).
    fn only_op_const(it: &Interner) -> SymId {
        let syms = it.symbols_with_opcode_const();
        assert_eq!(syms.len(), 1, "expected exactly one Const symbol");
        syms[0]
    }
}
