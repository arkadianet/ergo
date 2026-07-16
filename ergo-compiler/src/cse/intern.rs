use std::collections::BTreeSet;

use ergo_primitives::writer::VlqWriter;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{write_constant, SigmaValue};

use super::*;

impl Interner {
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
    pub(crate) fn intern_op(&mut self, node: &IrNode) -> SymId {
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
                let (t, t_scope) = self.intern_scoped(children[1]);
                let (e, e_scope) = self.intern_scoped(children[2]);
                self.finish_branches(
                    KeyTag::Op(op),
                    vec![c, t, e],
                    literal,
                    Node::Op(node.payload.clone()),
                    vec![t_scope, e_scope],
                )
            }
            BIN_AND | BIN_OR if children.len() == 2 => {
                // left in the current scope; right arm thunked (by-name).
                let l = self.intern(children[0]);
                let (r, r_scope) = self.intern_scoped(children[1]);
                self.finish_branches(
                    KeyTag::Op(op),
                    vec![l, r],
                    literal,
                    Node::Op(node.payload.clone()),
                    vec![r_scope],
                )
            }
            // Pair projection `t._1`/`t._2` — the process-wide `tuplesCache`
            // bypass (Tuples.scala:57-74). On the first projection of the pair
            // receiver `t` (via EITHER field), build BOTH First/Second together
            // and memoize keyed by `t`'s SymId; later projections of `t` anywhere
            // — incl. a sibling thunk — reuse them, bypassing thunk isolation.
            // Only `field_idx ∈ {1,2}` on a NON-literal-tuple receiver enters:
            // `._3+` (a >2-tuple) and a literal-tuple `Tup(a,b)` (Tuples.scala:60)
            // stay on the general path.
            SELECT_FIELD => {
                if let Payload::SelectField { input, field_idx } = &node.payload {
                    if matches!(field_idx, 1 | 2) {
                        let p = self.intern(input);
                        if !matches!(self.syms[p.0 as usize].key.tag, KeyTag::Op(TUPLE)) {
                            let (first, second) = self.pair_projection(p, input);
                            return if *field_idx == 1 { first } else { second };
                        }
                    }
                }
                self.intern_general(node)
            }
            // Every other opcode — incl. eager BinXor (0xF4) AND OptionGetOrElse
            // (0xE5), whose default is built EAGERLY in the enclosing scope, not a
            // thunk (M5 Task 5c/R2; GraphBuilding.scala:441,962,1013-1035) — all
            // children in the current scope.
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
    pub(crate) fn intern_val_use(&mut self, node: &IrNode, literal: Vec<u8>) -> SymId {
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
    pub(crate) fn intern_val_def(&mut self, node: &IrNode) -> SymId {
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
    pub(crate) fn intern_block(&mut self, node: &IrNode) -> SymId {
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
    pub(crate) fn intern_func(&mut self, node: &IrNode, literal: Vec<u8>) -> SymId {
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
            // Open a SCHEDULE scope for the body (no hash-cons scope — spike
            // §1.4). Body-local nodes are placed here; the lambda-invariant ones
            // that resolve to ancestor symbols keep their ancestor scope.
            let parent_scope = self.cur_scope;
            let body_scope = self.scope_parents.len();
            self.scope_parents.push(Some(parent_scope));
            self.scope_kinds
                .push(ScopeKind::Lambda(args.iter().map(|(id, _)| *id).collect()));
            self.cur_scope = body_scope;
            let body_sym = self.intern(body);
            self.cur_scope = parent_scope;
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
                    body_scope,
                },
                Vec::new(),
            );
        }
        self.intern_general(node)
    }

    /// The general path: intern every direct child in the current scope, then
    /// key on `(opcode, child syms, scalar literal)`. Used by all opcodes that
    /// are neither a scope-push site nor a binding form.
    pub(crate) fn intern_general(&mut self, node: &IrNode) -> SymId {
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

    /// Port of Scalan's `unzipPair` + process-wide `tuplesCache`
    /// (`Tuples.scala:57-74`, pinned 6.0.2). On the FIRST projection of pair
    /// receiver `p` (reached via `._1` OR `._2`), eagerly intern BOTH `First(p)`
    /// and `Second(p)` in the CURRENT scope (`:65` builds them together) and
    /// memoize them keyed by `p`'s [`SymId`]; every later projection of `p` —
    /// including inside a sibling thunk — returns the memoized pair verbatim
    /// (`:63-67`), the sole documented bypass of thunk hash-cons isolation.
    /// Returns `(first, second)`.
    ///
    /// The eagerly-built sibling (the projection not requested here) is placed at
    /// `cur_scope` like `p` itself; if it is never used elsewhere it is
    /// unreachable from any schedule root and emits no `ValDef` (output-neutral).
    /// `input` is the original receiver `Expr`, kept ONLY to seed each
    /// projection's rebuild template — `build_op` reads a `SelectField`'s scalar
    /// `field_idx` and substitutes the interned child `p`, never this stale
    /// input.
    pub(crate) fn pair_projection(&mut self, p: SymId, input: &Expr) -> (SymId, SymId) {
        if let Some(&pair) = self.pair_projections.get(&p) {
            return pair;
        }
        let first = self.select_projection(p, input, 1);
        let second = self.select_projection(p, input, 2);
        self.pair_projections.insert(p, (first, second));
        (first, second)
    }

    /// Intern one `SelectField(p, field_idx)` projection: builds the key with the
    /// exact `decompose` literal (so it hash-cons-agrees with any general-path
    /// `SelectField` of the same shape) and a rebuild template carrying the
    /// scalar `field_idx`.
    pub(crate) fn select_projection(&mut self, p: SymId, input: &Expr, field_idx: u8) -> SymId {
        let payload = Payload::SelectField {
            input: Box::new(input.clone()),
            field_idx,
        };
        let (_, literal) = decompose(&payload);
        self.finish(
            KeyTag::Op(SELECT_FIELD),
            vec![p],
            literal,
            Node::Op(payload),
        )
    }

    /// Intern `expr` inside a freshly pushed thunk scope, popping it after, and
    /// return `(result symbol, the thunk's schedule [`ScopeId`])`. The pushed
    /// hash-cons scope's parent is the scope below it (Scala's
    /// `beginScope`/`endScope` bracket, `Thunks.scala:248-253`); the schedule
    /// scope's parent is the current placement scope.
    pub(crate) fn intern_scoped(&mut self, expr: &Expr) -> (SymId, ScopeId) {
        self.scopes.push(ScopeTable::default());
        let parent_scope = self.cur_scope;
        let thunk_scope = self.scope_parents.len();
        self.scope_parents.push(Some(parent_scope));
        self.scope_kinds.push(ScopeKind::Thunk);
        self.cur_scope = thunk_scope;
        let sym = self.intern(expr);
        self.cur_scope = parent_scope;
        self.scopes.pop();
        (sym, thunk_scope)
    }

    /// Build the key, look it up innermost → parent chain → global; on a hit
    /// return the existing symbol, on a miss allocate a fresh one in the
    /// INNERMOST open scope. A new symbol's `deps` are the union of its
    /// children's `deps` (bound-var dependency flows up).
    pub(crate) fn finish(
        &mut self,
        tag: KeyTag,
        children: Vec<SymId>,
        literal: Vec<u8>,
        node: Node,
    ) -> SymId {
        self.finish_branches(tag, children, literal, node, Vec::new())
    }

    /// [`finish`](Self::finish) for a node that owns thunk sub-scopes: the extra
    /// `branch_scopes` are the [`ScopeId`]s of its scoped children in child
    /// order (recorded so materialization re-enters the exact thunk scope).
    pub(crate) fn finish_branches(
        &mut self,
        tag: KeyTag,
        children: Vec<SymId>,
        literal: Vec<u8>,
        node: Node,
        branch_scopes: Vec<ScopeId>,
    ) -> SymId {
        let key = ExprKey {
            tag,
            children,
            literal,
        };
        if let Some(sym) = self.lookup(&key) {
            return sym;
        }
        let deps = self.union_child_deps(&key.children);
        self.alloc(key, deps, true, node, branch_scopes)
    }

    /// Allocate a lambda-argument placeholder: a leaf symbol tagged with its own
    /// arg id, kept OUT of the scope table so it can never be hash-cons shared
    /// with another lambda's arg (spike §1.4 — fresh placeholder per lambda).
    pub(crate) fn alloc_arg(&mut self, arg_id: u32) -> SymId {
        let key = ExprKey {
            tag: KeyTag::Arg,
            children: Vec::new(),
            literal: arg_id.to_le_bytes().to_vec(),
        };
        let mut deps = BTreeSet::new();
        deps.insert(arg_id);
        self.alloc(key, deps, false, Node::Arg, Vec::new())
    }

    /// Look up `key` from the innermost open scope down through the parent chain
    /// to global — Scala's `findDef` (`Thunks.scala:219-226`). Walking the stack
    /// top-to-bottom IS the parent chain, because a pushed scope's parent is the
    /// scope immediately below it.
    pub(crate) fn lookup(&self, key: &ExprKey) -> Option<SymId> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.by_key.get(key).copied())
    }

    /// Insert a fresh symbol into `syms`; when `shared`, also register it in the
    /// innermost open scope's table so later builds can hash-cons to it. The
    /// symbol's PLACEMENT scope is the current schedule scope (`cur_scope`).
    pub(crate) fn alloc(
        &mut self,
        key: ExprKey,
        deps: BTreeSet<u32>,
        shared: bool,
        node: Node,
        branch_scopes: Vec<ScopeId>,
    ) -> SymId {
        let id = SymId(self.syms.len() as u32);
        let scope = self.placement_scope(&deps);
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
            scope,
            branch_scopes,
        });
        id
    }

    /// The PLACEMENT scope for a node with transitive bound-var `deps`, built at
    /// `cur_scope`: walk up from `cur_scope`, floating OUT of every enclosing
    /// lambda whose argument the node does not depend on (a lambda-invariant node
    /// escapes to where it is actually shared — the buy/sell `getX(SELF)` apps,
    /// `m5-sched-crystalpool.md` finding 2). Stop at the root, a thunk (identity
    /// boundary), or a lambda whose arg the node depends on. This is the
    /// deps-based lambda placement (spike §1.4) — NOT the lexical first-build
    /// scope, which would wrongly pin an invariant app inside the lambda it
    /// happens to appear in.
    pub(crate) fn placement_scope(&self, deps: &BTreeSet<u32>) -> ScopeId {
        let mut s = self.cur_scope;
        loop {
            match &self.scope_kinds[s] {
                ScopeKind::Lambda(args) if !args.iter().any(|a| deps.contains(a)) => {
                    match self.scope_parents[s] {
                        Some(p) => s = p,
                        None => break,
                    }
                }
                _ => break,
            }
        }
        s
    }

    pub(crate) fn union_child_deps(&self, children: &[SymId]) -> BTreeSet<u32> {
        let mut deps = BTreeSet::new();
        for c in children {
            deps.extend(self.syms[c.0 as usize].deps.iter().copied());
        }
        deps
    }
}

/// Canonical span-free key bytes for a constant: its wire type+value encoding
/// (`write_constant`). Falls back to a deterministic debug encoding only if the
/// writer ever errors (unreachable for well-formed emitted IR).
pub(crate) fn const_key_bytes(tpe: &SigmaType, val: &SigmaValue) -> Vec<u8> {
    let mut w = VlqWriter::new();
    if write_constant(&mut w, tpe, val).is_ok() {
        w.result()
    } else {
        format!("{tpe:?}|{val:?}").into_bytes()
    }
}
