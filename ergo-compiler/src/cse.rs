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
//! `/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2`,
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
//! # Scope-push sites (spike §2)
//!
//! A hash-cons scope is pushed at EXACTLY four source shapes; the
//! left/condition/receiver operand is evaluated in the CURRENT scope *first*:
//!
//! | opcode | shape | scoped operand(s) | current-scope operand |
//! |--------|-------|-------------------|-----------------------|
//! | `0x95` If         | `if(c) t else e`   | **both** `t`, `e` | `c`      |
//! | `0xED` BinAnd     | `a && b`           | **right** `b`     | `a`      |
//! | `0xEC` BinOr      | `a \|\| b`         | **right** `b`     | `a`      |
//! | `0xE5` OptionGetOrElse | `opt.getOrElse(d)` | the default `d` | `opt` |
//!
//! `0xF4` BinXor is **eager** (spike §2 last row, `GraphBuilding.scala:874-877`)
//! — no scope; both arms in the current scope (handled by the general path).
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

use std::collections::{BTreeMap, BTreeSet};

use ergo_primitives::writer::VlqWriter;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::{write_type, SigmaType};
use ergo_ser::sigma_value::{write_constant, SigmaValue};

// ----- opcode constants (verified against ergo-ser/src/opcode/types.rs) -----

/// `if(c) t else e` — both branches thunked (`IfThenElse.scala:50-53`).
const IF: u8 = 0x95;
/// `a && b` — right arm thunked (`GraphBuilding.scala:869-872`).
const BIN_AND: u8 = 0xED;
/// `a || b` — right arm thunked (`GraphBuilding.scala:864-867`).
const BIN_OR: u8 = 0xEC;
/// `opt.getOrElse(d)` — default thunked (`GraphBuilding.scala:1033-1035`).
const OPT_GET_OR_ELSE: u8 = 0xE5;
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

// ----- symbol identity -----

/// A build-time symbol identity. Assigned densely in interning (evaluation)
/// order; the numeric value doubles as the index into [`Interner::syms`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SymId(pub u32);

/// The class half of a structural key. The scalar payload (ids, indices,
/// types, opcode-specific literals) lives in [`ExprKey::literal`]; the child
/// symbol identities in [`ExprKey::children`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum KeyTag {
    /// Inline constant — `literal` is its `write_constant` (type+value) bytes.
    Const,
    /// A whole-tree `Unparsed` body kept verbatim.
    Unparsed,
    /// An opcode node — the dispatch byte.
    Op(u8),
    /// A synthetic lambda-argument placeholder (never hash-cons shared).
    Arg,
}

/// Structural hash key — span-stripped by construction (our opcode `Expr`
/// carries no source spans; only the typed AST did). Keys on `(class, ordered
/// child SymIds, scalar literal bytes)` exactly as the spike §7.1 step 1 / the
/// cannonQ ExprKey pattern prescribes. `Ord` so it can key a deterministic
/// `BTreeMap` (never a `HashMap` with random state, per the M5 plan).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct ExprKey {
    tag: KeyTag,
    children: Vec<SymId>,
    literal: Vec<u8>,
}

/// Per-scope hash-cons table (Scala's `_globalDefs` at index 0, a
/// `ThunkScope.bodyDefs` for each pushed thunk). Lookup only — never iterated in
/// a way that affects output — but kept a deterministic `BTreeMap` regardless.
#[derive(Default)]
struct ScopeTable {
    by_key: BTreeMap<ExprKey, SymId>,
}

/// The rebuild template for an interned symbol — everything Task 3's
/// [`Interner::materialize`] needs to reconstruct the node's `Expr` from its
/// interned children. The interner's [`ExprKey`] is a hash key (span- and
/// structure-stripped); it is intentionally lossy about scalar payload layout,
/// so materialization keeps this parallel template. Rebuilt children come from
/// [`ExprKey::children`] (in `decompose` order); the scalar fields come from
/// here.
#[derive(Debug)]
enum Node {
    /// A constant leaf — its wire type + value, re-emitted inline at every use
    /// (constants never hoist, spike §5 P4).
    Const(SigmaType, SigmaValue),
    /// A whole-tree `Unparsed` body kept verbatim.
    Unparsed(Vec<u8>),
    /// A generic opcode node. The stored `Payload`'s CHILD slots are stale
    /// (they hold the original pre-interning `Expr`s); rebuild reads only its
    /// SCALAR fields and substitutes fresh children from [`ExprKey::children`].
    Op(Payload),
    /// A `FuncValue` (lambda). Unlike a generic op it re-assigns its argument
    /// ids at materialization (spike §4), so it keeps the arg placeholder
    /// [`SymId`]s (to bind them in the body env) and the body symbol directly
    /// rather than going through the generic child list.
    Func {
        args: Vec<(SymId, Option<SigmaType>)>,
        body: SymId,
    },
    /// A lambda-argument placeholder (carries its original wire arg id). Never
    /// scheduled or rebuilt directly — only ever resolved to a `ValUse` through
    /// the materialization env.
    Arg,
}

/// Everything recorded about one interned symbol.
#[derive(Debug)]
struct SymInfo {
    key: ExprKey,
    /// Bound-var (lambda arg) ids this symbol transitively depends on. Empty ⇒
    /// lambda-invariant (floats up in Task 3); non-empty ⇒ pinned inside the
    /// lambda whose arg id it names.
    deps: BTreeSet<u32>,
    /// The rebuild template (Task 3 materialization).
    node: Node,
    /// The hash-cons scope DEPTH this symbol was first built at (0 = global /
    /// root; each pushed thunk scope is one deeper — lambdas do NOT push, spike
    /// §1.4). A `ValDef` is materialized in the scope of this depth
    /// (`TreeBuilding` `processAstGraph` per-scope schedule, spike §3).
    scope_depth: u32,
}

/// The scope-chain hash-cons interner (Phase A of the spike). Owns the scope
/// stack (index 0 = global), the dense symbol table, and the binding
/// environment that resolves `ValUse` and lambda args.
pub struct Interner {
    /// Scope stack; index 0 is the global table, the last element is the
    /// innermost open scope.
    scopes: Vec<ScopeTable>,
    /// Dense symbol table, indexed by `SymId.0`.
    syms: Vec<SymInfo>,
    /// `ValDef`/lambda-arg id → the symbol it binds. Lookup only.
    bindings: BTreeMap<u32, SymId>,
}

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    /// A fresh interner with only the global scope open.
    pub fn new() -> Self {
        Interner {
            scopes: vec![ScopeTable::default()],
            syms: Vec::new(),
            bindings: BTreeMap::new(),
        }
    }

    /// Intern an expression tree rooted at global scope, returning the root
    /// symbol. Children are interned FIRST, in evaluation order, so a child's
    /// `SymId` is known before its parent's key is built (spike §7.1 step 1).
    pub fn intern(&mut self, expr: &Expr) -> SymId {
        match expr {
            Expr::Const { tpe, val } => {
                let literal = const_key_bytes(tpe, val);
                self.finish(
                    KeyTag::Const,
                    Vec::new(),
                    literal,
                    Node::Const(tpe.clone(), val.clone()),
                )
            }
            Expr::Unparsed(bytes) => self.finish(
                KeyTag::Unparsed,
                Vec::new(),
                bytes.clone(),
                Node::Unparsed(bytes.clone()),
            ),
            Expr::Op(node) => self.intern_op(node),
        }
    }

    /// Dispatch an opcode node: the four scope-push sites and the three
    /// binding-aware forms are handled explicitly; everything else flows
    /// through the exhaustive general path.
    fn intern_op(&mut self, node: &IrNode) -> SymId {
        let op = node.opcode;
        let (children, literal) = decompose(&node.payload);
        match op {
            VAL_USE => self.intern_val_use(node, literal),
            VAL_DEF => self.intern_val_def(node),
            BLOCK_VALUE => self.intern_block(node),
            FUNC_VALUE => self.intern_func(node, literal),
            IF if children.len() == 3 => {
                // condition in the current scope; each branch in its own thunk.
                let c = self.intern(children[0]);
                let t = self.intern_scoped(children[1]);
                let e = self.intern_scoped(children[2]);
                self.finish(
                    KeyTag::Op(op),
                    vec![c, t, e],
                    literal,
                    Node::Op(node.payload.clone()),
                )
            }
            BIN_AND | BIN_OR | OPT_GET_OR_ELSE if children.len() == 2 => {
                // left/receiver in the current scope; right/default thunked.
                let l = self.intern(children[0]);
                let r = self.intern_scoped(children[1]);
                self.finish(
                    KeyTag::Op(op),
                    vec![l, r],
                    literal,
                    Node::Op(node.payload.clone()),
                )
            }
            // Every other opcode (incl. eager BinXor 0xF4): all children in the
            // current scope.
            _ => {
                let mut child_syms = Vec::with_capacity(children.len());
                for c in &children {
                    child_syms.push(self.intern(c));
                }
                self.finish(
                    KeyTag::Op(op),
                    child_syms,
                    literal,
                    Node::Op(node.payload.clone()),
                )
            }
        }
    }

    /// `ValUse` resolves to the symbol its id was bound to (a `ValDef` rhs or a
    /// lambda arg). An unbound id (free/ill-formed input) falls back to an
    /// opaque leaf keyed by the id so interning stays total and deterministic.
    fn intern_val_use(&mut self, node: &IrNode, literal: Vec<u8>) -> SymId {
        if let Payload::ValUse { id } = &node.payload {
            if let Some(&sym) = self.bindings.get(id) {
                return sym;
            }
        }
        self.finish(
            KeyTag::Op(VAL_USE),
            Vec::new(),
            literal,
            Node::Op(node.payload.clone()),
        )
    }

    /// A standalone `ValDef` interns its rhs in the current scope and registers
    /// the binding; the node is transparent (returns the rhs symbol). In
    /// well-formed input `ValDef`s appear only as `BlockValue` items.
    fn intern_val_def(&mut self, node: &IrNode) -> SymId {
        if let Payload::ValDef { id, rhs, .. } = &node.payload {
            let sym = self.intern(rhs);
            self.bindings.insert(*id, sym);
            return sym;
        }
        self.intern_general(node)
    }

    /// A block is transparent (no thunk): its items are interned in the current
    /// scope (registering bindings), then the result is returned. This is what
    /// puts a source `val`'s rhs at the block's scope — the E5-vs-E2 first-build
    /// distinction (spike §6).
    fn intern_block(&mut self, node: &IrNode) -> SymId {
        if let Payload::BlockValue { items, result } = &node.payload {
            for item in items {
                self.intern(item);
            }
            return self.intern(result);
        }
        self.intern_general(node)
    }

    /// A lambda does NOT push a hash-cons scope (spike §1.4). Each arg id is
    /// bound to a fresh unshared placeholder symbol tagged `deps = {arg id}`;
    /// the body is interned in the CURRENT scope. On exit the arg bindings are
    /// restored (lexical shadowing). The lambda node keys on its body symbol +
    /// its arg signature.
    fn intern_func(&mut self, node: &IrNode, literal: Vec<u8>) -> SymId {
        if let Payload::FuncValue { args, body } = &node.payload {
            let mut saved: Vec<(u32, Option<SymId>)> = Vec::with_capacity(args.len());
            let mut arg_syms: Vec<(SymId, Option<SigmaType>)> = Vec::with_capacity(args.len());
            for (arg_id, tpe) in args {
                let prev = self.bindings.get(arg_id).copied();
                let arg_sym = self.alloc_arg(*arg_id);
                self.bindings.insert(*arg_id, arg_sym);
                saved.push((*arg_id, prev));
                arg_syms.push((arg_sym, tpe.clone()));
            }
            let body_sym = self.intern(body);
            for (arg_id, prev) in saved.into_iter().rev() {
                match prev {
                    Some(p) => {
                        self.bindings.insert(arg_id, p);
                    }
                    None => {
                        self.bindings.remove(&arg_id);
                    }
                }
            }
            // A lambda's own bound vars are NOT free in it (Scala `freeVars`
            // excludes a Lambda's arguments): the arg is defined INSIDE the
            // FuncValue, so the FuncValue is lambda-invariant w.r.t. it. Subtract
            // this lambda's arg ids from the body's transitive deps — otherwise
            // the FuncValue would carry its own arg id and never schedule as a
            // ValDef (a shared `def` like `deposit.es`'s `getSellerPk` would be
            // wrongly inlined). Deps from ENCLOSING lambdas' args stay (a nested
            // lambda genuinely depends on an outer bound var).
            let key = ExprKey {
                tag: KeyTag::Op(FUNC_VALUE),
                children: vec![body_sym],
                literal,
            };
            if let Some(sym) = self.lookup(&key) {
                return sym;
            }
            let mut deps = self.union_child_deps(&key.children);
            for (arg_id, _tpe) in args {
                deps.remove(arg_id);
            }
            return self.alloc(
                key,
                deps,
                true,
                Node::Func {
                    args: arg_syms,
                    body: body_sym,
                },
            );
        }
        self.intern_general(node)
    }

    /// The general path: intern every direct child in the current scope, then
    /// key on `(opcode, child syms, scalar literal)`. Used by all opcodes that
    /// are neither a scope-push site nor a binding form.
    fn intern_general(&mut self, node: &IrNode) -> SymId {
        let (children, literal) = decompose(&node.payload);
        let mut child_syms = Vec::with_capacity(children.len());
        for c in &children {
            child_syms.push(self.intern(c));
        }
        self.finish(
            KeyTag::Op(node.opcode),
            child_syms,
            literal,
            Node::Op(node.payload.clone()),
        )
    }

    /// Intern `expr` inside a freshly pushed thunk scope, popping it after. The
    /// pushed scope's parent is the scope below it — exactly Scala's
    /// `beginScope`/`endScope` bracket (`Thunks.scala:248-253`).
    fn intern_scoped(&mut self, expr: &Expr) -> SymId {
        self.scopes.push(ScopeTable::default());
        let sym = self.intern(expr);
        self.scopes.pop();
        sym
    }

    /// Build the key, look it up innermost → parent chain → global; on a hit
    /// return the existing symbol, on a miss allocate a fresh one in the
    /// INNERMOST open scope. A new symbol's `deps` are the union of its
    /// children's `deps` (bound-var dependency flows up).
    fn finish(&mut self, tag: KeyTag, children: Vec<SymId>, literal: Vec<u8>, node: Node) -> SymId {
        let key = ExprKey {
            tag,
            children,
            literal,
        };
        if let Some(sym) = self.lookup(&key) {
            return sym;
        }
        let deps = self.union_child_deps(&key.children);
        self.alloc(key, deps, true, node)
    }

    /// Allocate a lambda-argument placeholder: a leaf symbol tagged with its own
    /// arg id, kept OUT of the scope table so it can never be hash-cons shared
    /// with another lambda's arg (spike §1.4 — fresh placeholder per lambda).
    fn alloc_arg(&mut self, arg_id: u32) -> SymId {
        let key = ExprKey {
            tag: KeyTag::Arg,
            children: Vec::new(),
            literal: arg_id.to_le_bytes().to_vec(),
        };
        let mut deps = BTreeSet::new();
        deps.insert(arg_id);
        self.alloc(key, deps, false, Node::Arg)
    }

    /// Look up `key` from the innermost open scope down through the parent chain
    /// to global — Scala's `findDef` (`Thunks.scala:219-226`). Walking the stack
    /// top-to-bottom IS the parent chain, because a pushed scope's parent is the
    /// scope immediately below it.
    fn lookup(&self, key: &ExprKey) -> Option<SymId> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.by_key.get(key).copied())
    }

    /// Insert a fresh symbol into `syms`; when `shared`, also register it in the
    /// innermost open scope's table so later builds can hash-cons to it.
    fn alloc(&mut self, key: ExprKey, deps: BTreeSet<u32>, shared: bool, node: Node) -> SymId {
        let id = SymId(self.syms.len() as u32);
        let scope_depth = (self.scopes.len() - 1) as u32;
        if shared {
            self.scopes
                .last_mut()
                .expect("global scope is always open")
                .by_key
                .insert(key.clone(), id);
        }
        self.syms.push(SymInfo {
            key,
            deps,
            node,
            scope_depth,
        });
        id
    }

    fn union_child_deps(&self, children: &[SymId]) -> BTreeSet<u32> {
        let mut deps = BTreeSet::new();
        for c in children {
            deps.extend(self.syms[c.0 as usize].deps.iter().copied());
        }
        deps
    }

    // ----- introspection (read API over the substrate) -----
    //
    // The interned symbol graph IS this pass's product; these read-only
    // accessors are how the Task-1 unit tests assert symbol identity (there is
    // no ValDef/tree emission to diff yet) and how Tasks 2-4 (usage count,
    // admission gate, schedule) will consume it. Public so they are part of the
    // module's surface rather than dead in the non-test build.

    /// The symbols whose class is opcode `op`, in allocation order.
    pub fn symbols_with_opcode(&self, op: u8) -> Vec<SymId> {
        self.syms
            .iter()
            .enumerate()
            .filter(|(_, s)| s.key.tag == KeyTag::Op(op))
            .map(|(i, _)| SymId(i as u32))
            .collect()
    }

    /// The number of distinct `Const` symbols (span-stripped, keyed on
    /// type+value bytes).
    pub fn const_symbol_count(&self) -> usize {
        self.syms
            .iter()
            .filter(|s| s.key.tag == KeyTag::Const)
            .count()
    }

    /// The distinct `Const` symbols, in allocation order (the `Const` analogue of
    /// [`symbols_with_opcode`](Self::symbols_with_opcode); `Const` is not an
    /// opcode class, so it needs its own accessor).
    pub fn symbols_with_opcode_const(&self) -> Vec<SymId> {
        self.syms
            .iter()
            .enumerate()
            .filter(|(_, s)| s.key.tag == KeyTag::Const)
            .map(|(i, _)| SymId(i as u32))
            .collect()
    }

    /// Bound-var ids a symbol transitively depends on (empty ⇒ float-up
    /// candidate).
    pub fn deps_of(&self, sym: SymId) -> &BTreeSet<u32> {
        &self.syms[sym.0 as usize].deps
    }

    /// A symbol's ordered child symbols.
    pub fn children_of(&self, sym: SymId) -> &[SymId] {
        &self.syms[sym.0 as usize].key.children
    }

    // ----- Phase B: flat usage count (spike §3) -----

    /// **Phase B — emit-time usage counting, FLAT and GLOBAL per SymId.**
    ///
    /// Scala's `hasManyUsagesGlobal(s)` (`AstGraphs.scala:201-206`) counts uses of
    /// symbol `s` over `buildUsageMap(flatSchedule, usingDeps=false)`
    /// (`AstGraphs.scala:197-199`): `flatSchedule` recursively unfolds EVERY lambda
    /// and thunk body into one flat sequence, and counting is over `syms`
    /// (structural children), not `deps`. Our interned graph is already that flat
    /// sequence — `self.syms` holds every distinct symbol across all scopes exactly
    /// once, and `key.children` are its structural children. So a straight pass
    /// tallying each child reference (WITH multiplicity: `x * x` counts `x` twice,
    /// matching Scala's `syms = [x, x]`) reproduces the flat global count.
    ///
    /// The CRITICAL nuance (spike §3, §1.2): sibling-thunk COPIES of a byte-identical
    /// subexpression are DISTINCT SymIds (Task 1's scope-chained interning gave them
    /// different ids because siblings are never on each other's parent chain), so
    /// each is referenced once and counted once — never merged. That is exactly why
    /// E2's two `HEIGHT+1` copies each land at count 1 (→ no hoist) while E6's single
    /// condition-built `HEIGHT+1` lands at count 3. We get this for free from
    /// per-SymId reference counting; the `e2_*` test below asserts it explicitly.
    ///
    /// Returns a map over every referenced SymId. A symbol referenced nowhere (a
    /// tree root) is absent — read via `.get(&sym).copied().unwrap_or(0)`.
    pub fn flat_usage(&self) -> BTreeMap<SymId, usize> {
        let mut usage: BTreeMap<SymId, usize> = BTreeMap::new();
        for info in &self.syms {
            for &child in &info.key.children {
                *usage.entry(child).or_insert(0) += 1;
            }
        }
        usage
    }

    /// `has_many(sym) := usage(sym) > 1` — predicate P1 of the admission gate
    /// (`mainG.hasManyUsagesGlobal(s)`, `TreeBuilding.scala:503`). Takes a map from
    /// [`flat_usage`](Self::flat_usage) so callers count once and query many times.
    pub fn has_many(usage: &BTreeMap<SymId, usize>, sym: SymId) -> bool {
        usage.get(&sym).copied().unwrap_or(0) > 1
    }

    // ----- the 4-predicate admission gate (spike §5, TreeBuilding.scala:503-509) -----

    /// The class tag of an interned symbol — the node-class discriminant the P2/P3/P4
    /// predicates key on.
    fn tag_of(&self, sym: SymId) -> &KeyTag {
        &self.syms[sym.0 as usize].key.tag
    }

    /// **P2 `IsContextProperty`** (`TreeBuilding.scala:140-148`,
    /// `:504`). True for the four free context globals `Height`/`Inputs`/`Outputs`/
    /// `Self` (`0xA3`/`0xA4`/`0xA5`/`0xA7`) — and ONLY those; `LastBlockUtxoRootHash`
    /// / `MinerPubkey` are intentionally excluded (see the opcode-const docs).
    /// A context property re-emits inline at every use, never a ValDef.
    pub fn is_context_property(&self, sym: SymId) -> bool {
        matches!(
            self.tag_of(sym),
            KeyTag::Op(HEIGHT) | KeyTag::Op(INPUTS) | KeyTag::Op(OUTPUTS) | KeyTag::Op(SELF_BOX)
        )
    }

    /// **P3 `IsInternalDef`** (`TreeBuilding.scala:153-158`, `:505`). Scala:
    /// `SigmaDslBuilder | CollBuilder`. In OUR lowered IR the only representable
    /// alternative is `SigmaDslBuilder` = the `Global` node (`0xDD`); `CollBuilder`
    /// has no node (vacuous for us, see the `GLOBAL` const docs). A builder singleton
    /// threads through many nodes but is never itself a ValDef.
    pub fn is_internal(&self, sym: SymId) -> bool {
        matches!(self.tag_of(sym), KeyTag::Op(GLOBAL))
    }

    /// **P4 `IsConstantDef`** (`TreeBuilding.scala:161-166`, `:509`). Any `Const`.
    /// Constants are suppressed even at use-count > 1 "to increase effect of
    /// constant segregation … two equal constants don't always have the same
    /// meaning" (source comment `:506-508`); each occurrence re-segregates into its
    /// own pool slot with no dedup (validated E3: `42` used twice → two `0454`
    /// slots). NOT vacuous: an env-aliased identical `Const` reaches CSE unfolded
    /// (the `proveDHTuple(g1,g2,g1,g2)` case, spike §3/OQ4, D-C7) — the
    /// `provedhtuple_*` test below confirms P4 is load-bearing there.
    pub fn is_const(&self, sym: SymId) -> bool {
        matches!(self.tag_of(sym), KeyTag::Const)
    }

    /// The exact admission conjunction (`TreeBuilding.scala:503-509`):
    /// `has_many && !IsContextProperty && !IsInternalDef && !IsConstantDef`.
    /// A symbol clears the gate ⇒ Task 3 will materialize it as a `ValDef`; a
    /// single-use symbol fails P1 and stays inlined at its one use (this is where
    /// single-use inlining "falls out free", spike §7.2). Takes the precomputed
    /// [`flat_usage`](Self::flat_usage) map.
    ///
    /// Note this is the PURE 4-predicate gate. Lambda-argument placeholder symbols
    /// (`KeyTag::Arg`) are not excluded here by a predicate — Scala excludes them
    /// structurally (a bound `Variable` is never in a scope's `schedule`), which is
    /// Task 3's schedule-membership concern, not a gate predicate.
    pub fn should_hoist(&self, sym: SymId, usage: &BTreeMap<SymId, usize>) -> bool {
        Self::has_many(usage, sym)
            && !self.is_context_property(sym)
            && !self.is_internal(sym)
            && !self.is_const(sym)
    }

    // ----- Task 3: per-scope schedule + ValDef materialization + assign-once ids -----

    /// Reconstruct an opcode `Expr` from the interned graph rooted at `root`,
    /// materializing a `ValDef`/`ValUse`/`BlockValue`/`FuncValue` tree with
    /// serial, assign-once ids — the observable of Scala's `TreeBuilding`
    /// (`buildTree`/`processAstGraph`/`buildValue`, `TreeBuilding.scala:186-191,
    /// 498-546`, spike §3/§4/§7.1 step 3-4).
    ///
    /// A symbol clearing the [`should_hoist`](Self::should_hoist) gate is emitted
    /// as ONE `ValDef` in the scope it was first built (spike §3); every
    /// reference to it becomes a `ValUse` of the assigned id. A single-use symbol
    /// (or a gate-suppressed context/builder/constant) is INLINED at each use
    /// (single-use inlining falls out for free, spike §7.2 / locked decision 4).
    ///
    /// # Scope class (Task-3 boundary)
    ///
    /// This lands the **single-ValDef class** byte-exact: the root scope emits
    /// its hoisted symbols as dense ids `1, 2, …` in post-order-DFS schedule
    /// order, and lambda-argument ids thread exactly per spike §4 (arg =
    /// `defId+1`, body from `varId+1`, tuple arg = ONE id). Thunk (`If`/`&&`/
    /// `||`/`getOrElse`) sub-scopes and lambda bodies are materialized too, but a
    /// multi-ValDef scope's INTRA-SCOPE ORDER matching Scala's exact
    /// `GraphUtil.depthFirstOrderFrom(deps)` (`Thunks.scala:196-212`) is the
    /// ORACLE-NEEDED reverse-engineering loop reserved for Task 5 (spike
    /// §7.4/OQ1). Post-order DFS is provably correct for a single-ValDef scope
    /// (order-trivial); a multi-ValDef vector whose id-order diverges is left in
    /// the mismatch set for Task 5, not hacked here.
    pub fn materialize(&self, root: SymId) -> Expr {
        let usage = self.flat_usage();
        let env: BTreeMap<SymId, u32> = BTreeMap::new();
        self.process_scope(root, 0, &env, 0, &usage)
    }

    /// Materialize one scope (root `PGraph`, a thunk `ThunkDef`, or a lambda
    /// body) — Scala's `processAstGraph` (`TreeBuilding.scala:498-531`). Emits a
    /// `ValDef` for each scheduled hoisted symbol (ids threaded from `def_id`),
    /// binds it in the env, then builds the scope result; wraps in a
    /// `BlockValue` when any `ValDef` was emitted, applying the
    /// `{ val idNew = id; idNew } → id` collapse (`TreeBuilding.scala:522-525`).
    fn process_scope(
        &self,
        scope_root: SymId,
        depth: u32,
        env: &BTreeMap<SymId, u32>,
        def_id: u32,
        usage: &BTreeMap<SymId, usize>,
    ) -> Expr {
        let schedule = self.scope_schedule(scope_root, depth, env, usage);
        let mut cur_id = def_id;
        let mut cur_env = env.clone();
        let mut valdefs: Vec<Expr> = Vec::with_capacity(schedule.len());
        for s in &schedule {
            // rhs is built with defId = curId BEFORE the increment (so a lambda
            // in the rhs takes `curId+1` as its arg id), then curId++ and
            // ValDef(curId) — `TreeBuilding.scala:510-513`.
            let rhs = self.build_value(*s, depth, &cur_env, cur_id, usage);
            cur_id += 1;
            valdefs.push(val_def(cur_id, rhs));
            cur_env.insert(*s, cur_id);
        }
        let rhs = self.build_value(scope_root, depth, &cur_env, cur_id, usage);
        wrap_block(valdefs, rhs)
    }

    /// The scheduled (hoisted) symbols of the scope at hash-cons `depth` rooted
    /// at `scope_root`, in post-order DFS (dependency) order — Scala's
    /// `subG.schedule` (`AstGraph.schedule`, spike §3). A symbol is scheduled
    /// here iff it clears the admission gate, was first built at THIS scope's
    /// depth, is lambda-invariant (no bound-var deps — a bound-var-dependent
    /// node belongs to the lambda body that binds it, spike §1.4), and is not
    /// already bound by an enclosing scope.
    ///
    /// Post-order over the full reachable DAG yields a valid topological order
    /// (a symbol's hoisted dependencies precede it), which is what makes the
    /// dense id allocation in [`process_scope`](Self::process_scope) sound. For a
    /// single-ValDef scope the order is trivial; the multi-ValDef tie-break is
    /// Task 5 (see [`materialize`](Self::materialize)).
    fn scope_schedule(
        &self,
        scope_root: SymId,
        depth: u32,
        env: &BTreeMap<SymId, u32>,
        usage: &BTreeMap<SymId, usize>,
    ) -> Vec<SymId> {
        let mut visited: BTreeSet<SymId> = BTreeSet::new();
        let mut out: Vec<SymId> = Vec::new();
        self.schedule_dfs(scope_root, depth, env, usage, &mut visited, &mut out);
        out
    }

    fn schedule_dfs(
        &self,
        sym: SymId,
        depth: u32,
        env: &BTreeMap<SymId, u32>,
        usage: &BTreeMap<SymId, usize>,
        visited: &mut BTreeSet<SymId>,
        out: &mut Vec<SymId>,
    ) {
        if !visited.insert(sym) {
            return;
        }
        // Descend into every structural child (through thunk/lambda children too)
        // so a symbol first built at THIS depth but referenced only from a deeper
        // scope is still found (e.g. E4's root `k`, referenced only inside the two
        // lambda bodies).
        for &child in &self.syms[sym.0 as usize].key.children {
            self.schedule_dfs(child, depth, env, usage, visited, out);
        }
        let info = &self.syms[sym.0 as usize];
        let scheduled = self.should_hoist(sym, usage)
            && info.scope_depth == depth
            && info.deps.is_empty()
            && !env.contains_key(&sym)
            && !matches!(info.node, Node::Arg);
        if scheduled {
            out.push(sym);
        }
    }

    /// Reconstruct the `Expr` for a single symbol — Scala's `buildValue`
    /// (`TreeBuilding.scala:498-517`). A symbol bound in `env` (an emitted
    /// `ValDef` id or a lambda arg) resolves to a `ValUse` (the recursion base);
    /// otherwise the node is rebuilt from its template and children.
    fn build_value(
        &self,
        sym: SymId,
        depth: u32,
        env: &BTreeMap<SymId, u32>,
        def_id: u32,
        usage: &BTreeMap<SymId, usize>,
    ) -> Expr {
        // recursion base: an in-scope binding → ValUse (TreeBuilding.scala:498).
        if let Some(&id) = env.get(&sym) {
            return val_use(id);
        }
        let info = &self.syms[sym.0 as usize];
        match &info.node {
            Node::Const(tpe, val) => Expr::Const {
                tpe: tpe.clone(),
                val: val.clone(),
            },
            Node::Unparsed(bytes) => Expr::Unparsed(bytes.clone()),
            Node::Arg => {
                // A bound var reached outside its binding env is an ill-formed
                // graph; keep the walk total with an opaque ValUse leaf rather
                // than panicking (never hit by well-formed emitted IR).
                val_use(0)
            }
            Node::Func { args, body } => self.build_func(args, *body, depth, env, def_id, usage),
            Node::Op(_) => self.build_op(sym, depth, env, def_id, usage),
        }
    }

    /// Rebuild a lambda — Scala's `buildValue` `Lambda` case
    /// (`TreeBuilding.scala:186-191`). Each argument consumes ONE id starting at
    /// `def_id+1` (a tupled lambda still has a single `STuple` arg → one id, the
    /// Task-7 `+1`-not-`+2` correction, spike §4); the body is a nested
    /// materialization scope whose ids continue from `varId+1`.
    fn build_func(
        &self,
        args: &[(SymId, Option<SigmaType>)],
        body: SymId,
        depth: u32,
        env: &BTreeMap<SymId, u32>,
        def_id: u32,
        usage: &BTreeMap<SymId, usize>,
    ) -> Expr {
        let mut body_env = env.clone();
        let mut wire_args: Vec<(u32, Option<SigmaType>)> = Vec::with_capacity(args.len());
        let mut cur = def_id;
        for (arg_sym, tpe) in args {
            cur += 1;
            body_env.insert(*arg_sym, cur);
            wire_args.push((cur, tpe.clone()));
        }
        // A lambda does NOT push a hash-cons thunk scope (spike §1.4), so the
        // body materializes at the SAME `depth`; only the id counter advances.
        let body_expr = self.process_scope(body, depth, &body_env, cur + 1, usage);
        Expr::Op(IrNode {
            opcode: FUNC_VALUE,
            payload: Payload::FuncValue {
                args: wire_args,
                body: Box::new(body_expr),
            },
        })
    }

    /// Rebuild a generic opcode node. `If` branches and the `&&`/`||`/
    /// `getOrElse` right-hand operand are their own thunk sub-scopes (depth +1,
    /// spike §2); every other child is rebuilt in the current scope. Scalar
    /// fields come from the stored template; children from the symbol's
    /// `key.children` (in `decompose` order).
    fn build_op(
        &self,
        sym: SymId,
        depth: u32,
        env: &BTreeMap<SymId, u32>,
        def_id: u32,
        usage: &BTreeMap<SymId, usize>,
    ) -> Expr {
        let info = &self.syms[sym.0 as usize];
        let Node::Op(template) = &info.node else {
            unreachable!("build_op on a non-Op symbol");
        };
        let child_syms = &info.key.children;
        let opcode = op_of(&info.key.tag);
        // Which child indices open a thunk sub-scope (spike §2). A thunk carries
        // the SAME `def_id` (no arg, no id consumed — `ThunkDef` case,
        // `TreeBuilding.scala:195-197`).
        let is_scoped = |idx: usize| -> bool {
            match opcode {
                IF => idx == 1 || idx == 2,
                BIN_AND | BIN_OR | OPT_GET_OR_ELSE => idx == 1,
                _ => false,
            }
        };
        let rebuilt: Vec<Expr> = child_syms
            .iter()
            .enumerate()
            .map(|(idx, &c)| {
                if is_scoped(idx) {
                    self.process_scope(c, depth + 1, env, def_id, usage)
                } else {
                    self.build_value(c, depth, env, def_id, usage)
                }
            })
            .collect();
        let mut it = rebuilt.into_iter();
        let payload = recompose(template, &mut it);
        Expr::Op(IrNode { opcode, payload })
    }
}

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

/// A materialized `ValDef` node (`0xD6`). `tpe` is never on the wire (the reader
/// always has a constant store), so it is pinned `None` exactly as emit does
/// (`emit.rs` `emit_block`, `parse.rs` ValDef arm).
fn val_def(id: u32, rhs: Expr) -> Expr {
    Expr::Op(IrNode {
        opcode: VAL_DEF,
        payload: Payload::ValDef {
            id,
            tpe: None,
            rhs: Box::new(rhs),
        },
    })
}

/// A materialized `ValUse` node (`0x72`) — an untyped reference to a bound id.
fn val_use(id: u32) -> Expr {
    Expr::Op(IrNode {
        opcode: VAL_USE,
        payload: Payload::ValUse { id },
    })
}

/// Wrap a scope's `ValDef`s + result into a `BlockValue` (`0xD8`), or the bare
/// result when nothing hoisted — Scala's `processAstGraph` tail
/// (`TreeBuilding.scala:518-529`). Applies the one documented peephole: a block
/// whose sole `ValDef` is `idNew = <ValUse>` and whose result is `ValUse(idNew)`
/// collapses to that inner `ValUse` (`TreeBuilding.scala:522-525`).
fn wrap_block(valdefs: Vec<Expr>, rhs: Expr) -> Expr {
    if valdefs.is_empty() {
        return rhs;
    }
    if valdefs.len() == 1 {
        if let Expr::Op(IrNode {
            payload:
                Payload::ValDef {
                    id: id_new,
                    rhs: source,
                    ..
                },
            ..
        }) = &valdefs[0]
        {
            if matches!(
                source.as_ref(),
                Expr::Op(IrNode {
                    payload: Payload::ValUse { .. },
                    ..
                })
            ) {
                if let Expr::Op(IrNode {
                    payload: Payload::ValUse { id: id_use },
                    ..
                }) = &rhs
                {
                    if id_use == id_new {
                        return (**source).clone();
                    }
                }
            }
        }
    }
    Expr::Op(IrNode {
        opcode: BLOCK_VALUE,
        payload: Payload::BlockValue {
            items: valdefs,
            result: Box::new(rhs),
        },
    })
}

/// The opcode byte of an interned `Op` symbol (its `KeyTag::Op` discriminant).
/// Only ever called on `Node::Op` symbols, whose tag is `Op(_)` by construction.
fn op_of(tag: &KeyTag) -> u8 {
    match tag {
        KeyTag::Op(op) => *op,
        // Const/Unparsed/Arg are handled by their own `Node` arms in
        // `build_value` and never reach `build_op`.
        _ => unreachable!("op_of on a non-Op symbol"),
    }
}

fn boxn(it: &mut dyn Iterator<Item = Expr>) -> Box<Expr> {
    Box::new(
        it.next()
            .expect("recompose: fewer rebuilt children than the template"),
    )
}

fn takev(it: &mut dyn Iterator<Item = Expr>, n: usize) -> Vec<Expr> {
    (0..n)
        .map(|_| {
            it.next()
                .expect("recompose: fewer rebuilt children than the template")
        })
        .collect()
}

/// EXHAUSTIVE inverse of [`decompose`]: rebuild a `Payload` from its template
/// (scalar fields) and the rebuilt children `it` yields in `decompose` child
/// order. A `_ =>` arm is FORBIDDEN — a new child-carrying `Payload` variant must
/// fail to compile here, mirroring [`decompose`]'s own exhaustiveness discipline
/// (a mismatch would silently drop or misplace a child). The child COUNT and
/// ORDER for each variant match [`decompose`] exactly.
fn recompose(template: &Payload, it: &mut dyn Iterator<Item = Expr>) -> Payload {
    match template {
        Payload::Zero => Payload::Zero,
        Payload::One(_) => Payload::One(boxn(it)),
        Payload::Two(_, _) => Payload::Two(boxn(it), boxn(it)),
        Payload::Three(_, _, _) => Payload::Three(boxn(it), boxn(it), boxn(it)),
        Payload::Four(_, _, _, _) => Payload::Four(boxn(it), boxn(it), boxn(it), boxn(it)),
        Payload::ValUse { id } => Payload::ValUse { id: *id },
        Payload::ConstPlaceholder { index } => Payload::ConstPlaceholder { index: *index },
        Payload::TaggedVar { id, tpe } => Payload::TaggedVar {
            id: *id,
            tpe: tpe.clone(),
        },
        Payload::ValDef { id, tpe, .. } => Payload::ValDef {
            id: *id,
            tpe: tpe.clone(),
            rhs: boxn(it),
        },
        Payload::FunDef {
            id, tpe, tpe_args, ..
        } => Payload::FunDef {
            id: *id,
            tpe: tpe.clone(),
            tpe_args: tpe_args.clone(),
            rhs: boxn(it),
        },
        Payload::BlockValue { items, .. } => {
            let n = items.len();
            let items = takev(it, n);
            Payload::BlockValue {
                items,
                result: boxn(it),
            }
        }
        Payload::FuncValue { args, .. } => Payload::FuncValue {
            args: args.clone(),
            body: boxn(it),
        },
        Payload::MethodCall {
            type_id,
            method_id,
            args,
            type_args,
            ..
        } => {
            let obj = boxn(it);
            let n = args.len();
            let args = takev(it, n);
            Payload::MethodCall {
                type_id: *type_id,
                method_id: *method_id,
                obj,
                args,
                type_args: type_args.clone(),
            }
        }
        Payload::ConcreteCollection { elem_type, items } => {
            let n = items.len();
            Payload::ConcreteCollection {
                elem_type: elem_type.clone(),
                items: takev(it, n),
            }
        }
        Payload::BoolCollection { bits } => Payload::BoolCollection { bits: bits.clone() },
        Payload::Tuple { items } => {
            let n = items.len();
            Payload::Tuple {
                items: takev(it, n),
            }
        }
        Payload::SelectField { field_idx, .. } => Payload::SelectField {
            input: boxn(it),
            field_idx: *field_idx,
        },
        Payload::ExtractRegisterAs { reg_id, tpe, .. } => Payload::ExtractRegisterAs {
            input: boxn(it),
            reg_id: *reg_id,
            tpe: tpe.clone(),
        },
        Payload::GetVar { var_id, tpe } => Payload::GetVar {
            var_id: *var_id,
            tpe: tpe.clone(),
        },
        Payload::DeserializeContext { id, tpe } => Payload::DeserializeContext {
            id: *id,
            tpe: tpe.clone(),
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id: *reg_id,
            tpe: tpe.clone(),
            default: default.as_ref().map(|_| boxn(it)),
        },
        Payload::SigmaCollection { items } => {
            let n = items.len();
            Payload::SigmaCollection {
                items: takev(it, n),
            }
        }
        Payload::NoneValue { tpe } => Payload::NoneValue { tpe: tpe.clone() },
        Payload::ByIndex { default, .. } => {
            let input = boxn(it);
            let index = boxn(it);
            Payload::ByIndex {
                input,
                index,
                default: default.as_ref().map(|_| boxn(it)),
            }
        }
        Payload::NumericCast { tpe, .. } => Payload::NumericCast {
            input: boxn(it),
            tpe: tpe.clone(),
        },
        Payload::FuncApply { args, .. } => {
            let func = boxn(it);
            let n = args.len();
            Payload::FuncApply {
                func,
                args: takev(it, n),
            }
        }
    }
}

/// Canonical span-free key bytes for a constant: its wire type+value encoding
/// (`write_constant`). Falls back to a deterministic debug encoding only if the
/// writer ever errors (unreachable for well-formed emitted IR).
fn const_key_bytes(tpe: &SigmaType, val: &SigmaValue) -> Vec<u8> {
    let mut w = VlqWriter::new();
    if write_constant(&mut w, tpe, val).is_ok() {
        w.result()
    } else {
        format!("{tpe:?}|{val:?}").into_bytes()
    }
}

/// EXHAUSTIVE decomposition of a payload into `(ordered child expressions,
/// canonical scalar-literal bytes)`. This is the single child-and-literal
/// walker; a `_ =>` arm is FORBIDDEN (cannonQ A.6) — a missed variant would
/// silently drop a node from interning, so a new `Payload` variant must fail to
/// compile here. All scalar encodings are self-delimiting (VLQ ints, framed
/// types), so their fixed-order concatenation is unambiguous within a class.
fn decompose(payload: &Payload) -> (Vec<&Expr>, Vec<u8>) {
    let mut lw = VlqWriter::new();
    let children: Vec<&Expr> = match payload {
        Payload::Zero => Vec::new(),
        Payload::One(a) => vec![a],
        Payload::Two(a, b) => vec![a, b],
        Payload::Three(a, b, c) => vec![a, b, c],
        Payload::Four(a, b, c, d) => vec![a, b, c, d],
        Payload::ValUse { id } => {
            lw.put_u32(*id);
            Vec::new()
        }
        Payload::ConstPlaceholder { index } => {
            lw.put_u32(*index);
            Vec::new()
        }
        Payload::TaggedVar { id, tpe } => {
            lw.put_u32(*id);
            put_opt_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::ValDef { id, tpe, rhs } => {
            lw.put_u32(*id);
            put_opt_type(&mut lw, tpe);
            vec![rhs]
        }
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => {
            lw.put_u32(*id);
            put_opt_type(&mut lw, tpe);
            put_types(&mut lw, tpe_args);
            vec![rhs]
        }
        Payload::BlockValue { items, result } => {
            let mut v: Vec<&Expr> = items.iter().collect();
            v.push(result);
            v
        }
        Payload::FuncValue { args, body } => {
            put_args(&mut lw, args);
            vec![body]
        }
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => {
            lw.put_u8(*type_id);
            lw.put_u8(*method_id);
            put_types(&mut lw, type_args);
            let mut v: Vec<&Expr> = vec![obj];
            v.extend(args.iter());
            v
        }
        Payload::ConcreteCollection { elem_type, items } => {
            let _ = write_type(&mut lw, elem_type);
            items.iter().collect()
        }
        Payload::BoolCollection { bits } => {
            lw.put_u32(bits.len() as u32);
            for b in bits {
                lw.put_u8(u8::from(*b));
            }
            Vec::new()
        }
        Payload::Tuple { items } => items.iter().collect(),
        Payload::SelectField { input, field_idx } => {
            lw.put_u8(*field_idx);
            vec![input]
        }
        Payload::ExtractRegisterAs { input, reg_id, tpe } => {
            lw.put_u8(*reg_id);
            let _ = write_type(&mut lw, tpe);
            vec![input]
        }
        Payload::GetVar { var_id, tpe } => {
            lw.put_u8(*var_id);
            let _ = write_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::DeserializeContext { id, tpe } => {
            lw.put_u8(*id);
            let _ = write_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => {
            lw.put_u8(*reg_id);
            let _ = write_type(&mut lw, tpe);
            default.as_deref().into_iter().collect()
        }
        Payload::SigmaCollection { items } => items.iter().collect(),
        Payload::NoneValue { tpe } => {
            let _ = write_type(&mut lw, tpe);
            Vec::new()
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            let mut v: Vec<&Expr> = vec![input, index];
            if let Some(d) = default.as_deref() {
                v.push(d);
            }
            v
        }
        Payload::NumericCast { input, tpe } => {
            let _ = write_type(&mut lw, tpe);
            vec![input]
        }
        Payload::FuncApply { func, args } => {
            let mut v: Vec<&Expr> = vec![func];
            v.extend(args.iter());
            v
        }
    };
    (children, lw.result())
}

fn put_opt_type(w: &mut VlqWriter, tpe: &Option<SigmaType>) {
    match tpe {
        Some(t) => {
            w.put_u8(1);
            let _ = write_type(w, t);
        }
        None => w.put_u8(0),
    }
}

fn put_types(w: &mut VlqWriter, types: &[SigmaType]) {
    w.put_u32(types.len() as u32);
    for t in types {
        let _ = write_type(w, t);
    }
}

fn put_args(w: &mut VlqWriter, args: &[(u32, Option<SigmaType>)]) {
    w.put_u32(args.len() as u32);
    for (id, tpe) in args {
        w.put_u32(*id);
        put_opt_type(w, tpe);
    }
}

#[cfg(test)]
mod tests {
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
    const BIN_XOR: u8 = 0xF4;
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
    fn option_get_or_else_default_is_scoped() {
        // Mechanism check for the `getOrElse` scope site (spike §2 / OQ5): the
        // receiver is interned in the current scope, the default in a pushed
        // thunk. A subexpr built ONLY in the default is invisible to a sibling
        // scope. Here the receiver `HEIGHT+1` (root) is shared by a default that
        // also computes `HEIGHT+1` → one Plus (default sees root via parent
        // chain), proving the receiver-before-thunk evaluation order.
        let goe = op2(OPT_GET_OR_ELSE, height_plus_one(), height_plus_one());
        let mut it = Interner::new();
        it.intern(&goe);
        assert_eq!(
            count_op(&it, PLUS),
            1,
            "receiver built in current scope is visible to the scoped default"
        );
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
    fn provedhtuple_repeated_ge_consts_are_const_suppressed_p4_load_bearing() {
        // OQ4 / P4 witness: `proveDHTuple(g1, g2, g1, g2)` — the two DISTINCT group
        // elements each arrive at CSE as a `Const` referenced TWICE (positions
        // 0/2 and 1/3). On the oracle side these reach CSE unfolded (lib.rs:611-616,
        // D-C7): each is `has_many` AND clears P2/P3 — so ONLY P4 keeps them from
        // hoisting. This proves P4 is load-bearing, not vacuous.
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
            assert!(it.is_const(*c));
            // Without P4 the symbol would clear the gate — P4 is the deciding vote.
            let passes_without_p4 = Interner::has_many(&usage, *c)
                && !it.is_context_property(*c)
                && !it.is_internal(*c);
            assert!(passes_without_p4, "the GE const clears P1/P2/P3");
            assert!(
                !it.should_hoist(*c, &usage),
                "P4 alone suppresses the GE const"
            );
        }
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
