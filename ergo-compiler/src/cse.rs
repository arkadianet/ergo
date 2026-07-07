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

/// Everything recorded about one interned symbol.
#[derive(Debug)]
struct SymInfo {
    key: ExprKey,
    /// Bound-var (lambda arg) ids this symbol transitively depends on. Empty ⇒
    /// lambda-invariant (floats up in Task 3); non-empty ⇒ pinned inside the
    /// lambda whose arg id it names.
    deps: BTreeSet<u32>,
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
                self.finish(KeyTag::Const, Vec::new(), literal)
            }
            Expr::Unparsed(bytes) => self.finish(KeyTag::Unparsed, Vec::new(), bytes.clone()),
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
                self.finish(KeyTag::Op(op), vec![c, t, e], literal)
            }
            BIN_AND | BIN_OR | OPT_GET_OR_ELSE if children.len() == 2 => {
                // left/receiver in the current scope; right/default thunked.
                let l = self.intern(children[0]);
                let r = self.intern_scoped(children[1]);
                self.finish(KeyTag::Op(op), vec![l, r], literal)
            }
            // Every other opcode (incl. eager BinXor 0xF4): all children in the
            // current scope.
            _ => {
                let mut child_syms = Vec::with_capacity(children.len());
                for c in &children {
                    child_syms.push(self.intern(c));
                }
                self.finish(KeyTag::Op(op), child_syms, literal)
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
        self.finish(KeyTag::Op(VAL_USE), Vec::new(), literal)
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
            for (arg_id, _tpe) in args {
                let prev = self.bindings.get(arg_id).copied();
                let arg_sym = self.alloc_arg(*arg_id);
                self.bindings.insert(*arg_id, arg_sym);
                saved.push((*arg_id, prev));
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
            return self.finish(KeyTag::Op(FUNC_VALUE), vec![body_sym], literal);
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
        self.finish(KeyTag::Op(node.opcode), child_syms, literal)
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
    fn finish(&mut self, tag: KeyTag, children: Vec<SymId>, literal: Vec<u8>) -> SymId {
        let key = ExprKey {
            tag,
            children,
            literal,
        };
        if let Some(sym) = self.lookup(&key) {
            return sym;
        }
        let deps = self.union_child_deps(&key.children);
        self.alloc(key, deps, true)
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
        self.alloc(key, deps, false)
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
    fn alloc(&mut self, key: ExprKey, deps: BTreeSet<u32>, shared: bool) -> SymId {
        let id = SymId(self.syms.len() as u32);
        if shared {
            self.scopes
                .last_mut()
                .expect("global scope is always open")
                .by_key
                .insert(key.clone(), id);
        }
        self.syms.push(SymInfo { key, deps });
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

    /// Bound-var ids a symbol transitively depends on (empty ⇒ float-up
    /// candidate).
    pub fn deps_of(&self, sym: SymId) -> &BTreeSet<u32> {
        &self.syms[sym.0 as usize].deps
    }

    /// A symbol's ordered child symbols.
    pub fn children_of(&self, sym: SymId) -> &[SymId] {
        &self.syms[sym.0 as usize].key.children
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

    /// Count distinct interned symbols whose class is opcode `op`.
    fn count_op(it: &Interner, op: u8) -> usize {
        it.symbols_with_opcode(op).len()
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

        // Each FuncValue symbol carries its own arg id as a dependency.
        let funcs = it.symbols_with_opcode(FUNC_VALUE);
        assert_eq!(funcs.len(), 2);
        assert_eq!(it.deps_of(funcs[0]), &BTreeSet::from([2]));
        assert_eq!(it.deps_of(funcs[1]), &BTreeSet::from([3]));
    }
}
