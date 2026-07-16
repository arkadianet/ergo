use std::collections::{BTreeMap, BTreeSet};

use ergo_ser::opcode::Payload;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

// ----- symbol identity -----

/// A build-time symbol identity. Assigned densely in interning (evaluation)
/// order; the numeric value doubles as the index into [`Interner::syms`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SymId(pub u32);

/// The class half of a structural key. The scalar payload (ids, indices,
/// types, opcode-specific literals) lives in [`ExprKey::literal`]; the child
/// symbol identities in [`ExprKey::children`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum KeyTag {
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
pub(crate) struct ExprKey {
    pub(crate) tag: KeyTag,
    pub(crate) children: Vec<SymId>,
    pub(crate) literal: Vec<u8>,
}

/// Per-scope hash-cons table (Scala's `_globalDefs` at index 0, a
/// `ThunkScope.bodyDefs` for each pushed thunk). Lookup only — never iterated in
/// a way that affects output — but kept a deterministic `BTreeMap` regardless.
#[derive(Default)]
pub(crate) struct ScopeTable {
    pub(crate) by_key: BTreeMap<ExprKey, SymId>,
}

/// The rebuild template for an interned symbol — everything Task 3's
/// [`Interner::materialize`] needs to reconstruct the node's `Expr` from its
/// interned children. The interner's [`ExprKey`] is a hash key (span- and
/// structure-stripped); it is intentionally lossy about scalar payload layout,
/// so materialization keeps this parallel template. Rebuilt children come from
/// [`ExprKey::children`] (in `decompose` order); the scalar fields come from
/// here.
#[derive(Debug)]
pub(crate) enum Node {
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
        /// The placement scope id of the lambda BODY (a `ScopeId` into
        /// [`Interner::scope_parents`]). A lambda opens a schedule scope even
        /// though it opens no hash-cons scope (spike §1.4): its body's local
        /// nodes schedule INSIDE it (`Functions.scala:112-134`).
        body_scope: ScopeId,
    },
    /// A lambda-argument placeholder (carries its original wire arg id). Never
    /// scheduled or rebuilt directly — only ever resolved to a `ValUse` through
    /// the materialization env.
    Arg,
}

/// An index into [`Interner::scope_parents`] — a node in the SCHEDULE scope
/// tree. Scope 0 is the root program scope; every thunk push (both `If`
/// branches, `&&`/`||` right arm) AND every lambda body
/// opens a child scope. Distinct from the hash-cons scope stack (`scopes`,
/// which lambdas do NOT push): identity is decided by first-build hash-cons
/// scope, PLACEMENT by this tree (`AstGraph.schedule`, `m5-sched-chaincash.md`
/// §1).
pub(crate) type ScopeId = usize;

/// Everything recorded about one interned symbol.
#[derive(Debug)]
pub(crate) struct SymInfo {
    pub(crate) key: ExprKey,
    /// Bound-var (lambda arg) ids this symbol transitively depends on. Empty ⇒
    /// lambda-invariant; non-empty ⇒ references the lambda whose arg id it
    /// names. Kept for introspection/tests; PLACEMENT now uses `scope` (the
    /// scope tree captures lambda nesting directly).
    pub(crate) deps: BTreeSet<u32>,
    /// The rebuild template (Task 3 materialization).
    pub(crate) node: Node,
    /// The PLACEMENT scope this symbol was first built in — a node in the
    /// schedule scope tree ([`ScopeId`]). A `ValDef` is materialized in exactly
    /// this scope (Scala `processAstGraph` per-scope schedule, `m5-sched-*` §1):
    /// membership in a materialization scope is `sym.scope == that scope`.
    pub(crate) scope: ScopeId,
    /// For an `Op` whose children include thunk sub-scopes (`If` → `[then,
    /// else]`; `&&`/`||` → `[right]`), the [`ScopeId`] of each such
    /// thunk, in child order. Empty for every other node. Lets materialization
    /// re-enter the exact scope each thunk branch was interned into (so a shared
    /// thunk-result symbol does not drag the wrong scope's members).
    pub(crate) branch_scopes: Vec<ScopeId>,
}

/// The kind of a schedule scope frame.
#[derive(Debug)]
pub(crate) enum ScopeKind {
    /// The root program scope (scope 0).
    Root,
    /// A thunk (`If` branch, `&&`/`||` right arm) — a
    /// hash-cons identity boundary; a node built inside stays inside.
    Thunk,
    /// A lambda body, carrying the lambda's argument ids. A node built inside
    /// but not depending on ANY of these args is lambda-invariant and floats up.
    Lambda(Vec<u32>),
}
