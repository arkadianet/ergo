use std::collections::BTreeMap;

use super::*;

/// The scope-chain hash-cons interner (Phase A of the spike). Owns the scope
/// stack (index 0 = global), the dense symbol table, and the binding
/// environment that resolves `ValUse` and lambda args.
pub struct Interner {
    /// Hash-cons scope stack (IDENTITY); index 0 is the global table, the last
    /// element is the innermost open scope. Thunks push here; lambdas do NOT.
    pub(crate) scopes: Vec<ScopeTable>,
    /// Dense symbol table, indexed by `SymId.0`. Allocation order == source
    /// construction (nodeId) order — the live construction-order graph the
    /// schedule DFS runs over (F2, `m5-sched-crystalpool.md` §6).
    pub(crate) syms: Vec<SymInfo>,
    /// `ValDef`/lambda-arg id → the symbol it binds. Lookup only.
    pub(crate) bindings: BTreeMap<u32, SymId>,
    /// The SCHEDULE scope tree: `scope_parents[s]` is scope `s`'s parent (root
    /// scope 0 has `None`). Pushed for both thunk and lambda entries.
    pub(crate) scope_parents: Vec<Option<ScopeId>>,
    /// The kind of each scope frame (parallel to `scope_parents`). Placement
    /// walks up this stack, floating a node OUT of any enclosing lambda whose
    /// argument it does not depend on (`m5-sched-crystalpool.md` finding 2 / the
    /// buy/sell `getX(SELF)` apps), and stopping at the root, a thunk (an
    /// identity boundary a node built inside never leaves), or a lambda whose arg
    /// it does depend on.
    pub(crate) scope_kinds: Vec<ScopeKind>,
    /// The innermost open placement scope during interning.
    pub(crate) cur_scope: ScopeId,
    /// Process-wide pair-projection memo — the port of Scalan's `tuplesCache`
    /// (`Tuples.scala:57`, pinned 6.0.2). Keyed by a pair RECEIVER's [`SymId`] →
    /// its `(First, Second)` projection symbols. Deliberately NOT cleared at
    /// scope push/pop: a projection first built in an enclosing scope is reused
    /// verbatim inside a sibling thunk, which is exactly how Scala shares one
    /// `SELF.tokens(1)._2` ValDef across both `if` branches. See the module docs
    /// and [`pair_projection`](Self::pair_projection).
    pub(crate) pair_projections: BTreeMap<SymId, (SymId, SymId)>,
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
            scope_parents: vec![None],
            scope_kinds: vec![ScopeKind::Root],
            cur_scope: 0,
            pair_projections: BTreeMap::new(),
        }
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
}
