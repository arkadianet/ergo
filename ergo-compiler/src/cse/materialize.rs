use std::collections::{BTreeMap, BTreeSet};

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;

use super::*;

impl Interner {
    // ----- Task 3/5: per-scope schedule + ValDef materialization + assign-once ids -----

    /// Reconstruct an opcode `Expr` from the interned graph rooted at `root`,
    /// materializing a `ValDef`/`ValUse`/`BlockValue`/`FuncValue` tree with
    /// serial, assign-once ids — the observable of Scala's `TreeBuilding`
    /// (`buildTree`/`processAstGraph`/`buildValue`, `TreeBuilding.scala:186-191,
    /// 498-546`).
    ///
    /// A symbol clearing the [`should_hoist`](Self::should_hoist) gate is emitted
    /// as ONE `ValDef` in the scope it was first built (spike §3); every
    /// reference to it becomes a `ValUse` of the assigned id. A single-use symbol
    /// (or a gate-suppressed context/builder/constant) is INLINED at each use
    /// (single-use inlining falls out for free, spike §7.2 / locked decision 4).
    ///
    /// # The schedule rule (M5 Task 5, Fix 1a/1b)
    ///
    /// Per-scope ValDef order is Scala's `GraphUtil.depthFirstOrderFrom`
    /// (`GraphUtil.scala:43-64`): a POST-ORDER DFS from the scope's result symbol,
    /// following each node's deps in construction/argument order, first-visit-wins,
    /// filtered to that scope. The DFS runs over the LIVE construction-order graph
    /// — `self.syms` is indexed in interning order (== source construction / nodeId
    /// order) and `key.children` are in argument order, so the tie-break among
    /// mutually-independent same-scope symbols is construction order for free (F2,
    /// `m5-sched-crystalpool.md` §6). A nested compound (`BlockValue`/`FuncValue`
    /// child, i.e. a symbol whose placement scope is DEEPER) is ONE node in its
    /// parent's DFS whose ordered deps are its `freeVars` — the ancestor-scope
    /// symbols it references, in the CHILD's schedule order (F1,
    /// `AstGraphs.scala:56-85`; `m5-sched-chaincash.md` §1). This is what makes the
    /// chaincash root order `[1,2,3,4,5]` (a naive descend-in-source DFS predicts
    /// `[1,2,4,3,5]`).
    pub fn materialize(&self, root: SymId) -> Expr {
        let usage = self.flat_usage_reachable(root);
        let env: BTreeMap<SymId, u32> = BTreeMap::new();
        // The root program scope is scope 0 (`scope_parents[0] == None`).
        self.process_scope(root, 0, &env, 0, &usage)
    }

    /// Materialize one scope (root `PGraph`, a thunk `ThunkDef`, or a lambda
    /// body) — Scala's `processAstGraph` (`TreeBuilding.scala:498-531`). Walks the
    /// scope's `depthFirstOrderFrom` schedule; emits a `ValDef` for each MEMBER
    /// (`sym.scope == scope`) that clears the hoist gate and is not already bound
    /// by an ancestor (ids threaded from `def_id`), binds it in the env, then
    /// builds the scope result; wraps in a `BlockValue` when any `ValDef` was
    /// emitted, applying the `{ val idNew = id; idNew } → id` collapse
    /// (`TreeBuilding.scala:522-525`).
    pub(crate) fn process_scope(
        &self,
        scope_root: SymId,
        scope: ScopeId,
        env: &BTreeMap<SymId, u32>,
        def_id: u32,
        usage: &BTreeMap<SymId, usize>,
    ) -> Expr {
        let order = self.schedule_order(scope_root, scope);
        let mut cur_id = def_id;
        let mut cur_env = env.clone();
        let mut valdefs: Vec<Expr> = Vec::new();
        for &s in &order {
            let info = &self.syms[s.0 as usize];
            let member = info.scope == scope
                && !matches!(info.node, Node::Arg)
                && self.should_hoist(s, usage)
                && !cur_env.contains_key(&s);
            if !member {
                continue;
            }
            // rhs is built with defId = curId BEFORE the increment (so a lambda
            // in the rhs takes `curId+1` as its arg id), then curId++ and
            // ValDef(curId) — `TreeBuilding.scala:510-513`.
            let rhs = self.build_value(s, scope, &cur_env, cur_id, usage);
            cur_id += 1;
            valdefs.push(val_def(cur_id, rhs));
            cur_env.insert(s, cur_id);
        }
        let rhs = self.build_value(scope_root, scope, &cur_env, cur_id, usage);
        wrap_block(valdefs, rhs)
    }

    /// A symbol's placement relation to the materialization scope `cur`.
    pub(crate) fn classify(&self, s_scope: ScopeId, cur: ScopeId) -> Rel {
        if s_scope == cur {
            Rel::Local
        } else if self.scope_is_ancestor(cur, s_scope) {
            // `cur` is a proper ancestor of `s_scope` ⇒ the symbol lives in a
            // scope nested INSIDE `cur` (a thunk/lambda interior).
            Rel::Deeper
        } else {
            // `s_scope` is an ancestor of `cur`, or an unrelated sibling scope:
            // a `freeVar` boundary — not followed by `cur`'s DFS.
            Rel::Outside
        }
    }

    /// True iff `anc` is a PROPER ancestor of `node` in the schedule scope tree.
    pub(crate) fn scope_is_ancestor(&self, anc: ScopeId, node: ScopeId) -> bool {
        let mut cur = self.scope_parents[node];
        while let Some(p) = cur {
            if p == anc {
                return true;
            }
            cur = self.scope_parents[p];
        }
        false
    }

    /// Full post-order DFS over scope `scope` from `scope_root` — the
    /// `depthFirstOrderFrom` schedule, INCLUDING single-use (non-hoisted) local
    /// nodes and the freeVar leaves (they matter for relative order and for the
    /// freeVars of a parent). The hoisted subset is filtered by
    /// [`process_scope`](Self::process_scope).
    pub(crate) fn schedule_order(&self, scope_root: SymId, scope: ScopeId) -> Vec<SymId> {
        let mut visited: BTreeSet<SymId> = BTreeSet::new();
        let mut out: Vec<SymId> = Vec::new();
        self.sched_dfs(scope_root, scope, &mut visited, &mut out);
        out
    }

    pub(crate) fn sched_dfs(
        &self,
        sym: SymId,
        scope: ScopeId,
        visited: &mut BTreeSet<SymId>,
        out: &mut Vec<SymId>,
    ) {
        if !visited.insert(sym) {
            return;
        }
        for d in self.neighbours(sym, scope) {
            self.sched_dfs(d, scope, visited, out);
        }
        out.push(sym);
    }

    /// The DFS neighbours (`deps`) of `sym` as seen by scope `scope` — Scala's
    /// `neighbours(id)` (`ProgramGraphs.scala:49-60` / `Thunks.scala:205`). A
    /// LOCAL node exposes its structural children (construction order); a DEEPER
    /// nested compound exposes its `freeVars` (F1); a `freeVar`/`isVar` leaf
    /// exposes nothing.
    pub(crate) fn neighbours(&self, sym: SymId, scope: ScopeId) -> Vec<SymId> {
        let info = &self.syms[sym.0 as usize];
        if matches!(info.node, Node::Arg) {
            return Vec::new();
        }
        match self.classify(info.scope, scope) {
            Rel::Local => info.key.children.clone(),
            Rel::Deeper => self.free_vars(sym),
            Rel::Outside => Vec::new(),
        }
    }

    /// The `freeVars` of a compound (a symbol whose scope is `cscope`): the
    /// symbols it references that live OUTSIDE `cscope` (ancestor scopes), in
    /// Scala's `AstGraph.freeVars` order (`AstGraphs.scala:56-85`) — the
    /// compound's own LOCAL-only post-order schedule (`Thunks.scala:196-212`
    /// `scheduleForResult`), scanning each scheduled node's deps and collecting
    /// those that are neither local (scheduled) nor bound vars, first-appearance.
    ///
    /// The crux (M5 Task 5e, `m5-root-schedule-order.md`): Scala schedules each
    /// by-name (`ThunkDef`) operand — the `&&`/`||` right arm, an `if` branch —
    /// as a SEPARATE post-order entry that PRECEDES the operator owning it, so its
    /// freeVars are collected BEFORE the operator's EAGER operands'. For `a && b`
    /// (`BinAnd(a, Thunk(b))`) Scala yields `b`'s freeVars before `a` — NOT child
    /// (argument) order. Our interner does not reify a `ThunkDef` node when a
    /// thunk arm resolves to an ancestor symbol (a bare `ValUse` to a hoisted
    /// `val`, e.g. `tokenIdsPreserved`), so the reorder cannot come from the
    /// schedule alone; it is reproduced HERE by collecting a Local node's SCOPED
    /// (thunk-arm) children before its eager children. This is what makes
    /// `basis-token`'s root `[token block][register block]` — the token conjunct
    /// is the thunked `&&` right arm after the eager register conjunct — match the
    /// Scala 6.0.2 oracle byte-for-byte.
    pub(crate) fn free_vars(&self, compound: SymId) -> Vec<SymId> {
        let cscope = self.syms[compound.0 as usize].scope;
        let schedule = self.body_schedule(compound, cscope);
        let mut out: Vec<SymId> = Vec::new();
        let mut seen: BTreeSet<SymId> = BTreeSet::new();
        for &n in &schedule {
            // The scheduled node's deps as Scala sees them: a Local member exposes
            // its structural children (thunk-arm children FIRST — see
            // `local_dep_order`); a Deeper nested thunk exposes its own freeVars
            // (`ThunkDef.getDeps` override, `Thunks.scala:163`). An Outside node is
            // never in the schedule.
            let deps: Vec<SymId> = match self.classify(self.syms[n.0 as usize].scope, cscope) {
                Rel::Local => self.local_dep_order(n),
                Rel::Deeper => self.free_vars(n),
                Rel::Outside => Vec::new(),
            };
            for &d in &deps {
                // Free iff not local (scheduled) and not a bound var. A Deeper dep
                // is itself scheduled (contributes at its own slot) so it is not a
                // freeVar here — no inline descent (the Task-5e fix).
                if matches!(self.syms[d.0 as usize].node, Node::Arg) {
                    continue;
                }
                if self.classify(self.syms[d.0 as usize].scope, cscope) == Rel::Outside
                    && seen.insert(d)
                {
                    out.push(d);
                }
            }
        }
        out
    }

    /// A Local node's children in Scala schedule-collection order: the SCOPED
    /// (by-name `ThunkDef`) arms first, in child order, then the EAGER children,
    /// in child order. Scala schedules a thunk arm as a node preceding its
    /// operator, so an Outside free-var reached only through a thunk arm is
    /// collected before the operator's eager Outside operands. Reordering the
    /// child list here reproduces that for arms our interner resolves to an
    /// ancestor symbol (no reified `ThunkDef` node). Deeper thunk arms are already
    /// scheduled ahead of the node by [`body_schedule`], so this reorder only ever
    /// changes the relative position of a node's own Outside children.
    pub(crate) fn local_dep_order(&self, sym: SymId) -> Vec<SymId> {
        let children = &self.syms[sym.0 as usize].key.children;
        let mut ordered: Vec<SymId> = Vec::with_capacity(children.len());
        for (idx, &c) in children.iter().enumerate() {
            if self.is_scoped_child(sym, idx) {
                ordered.push(c);
            }
        }
        for (idx, &c) in children.iter().enumerate() {
            if !self.is_scoped_child(sym, idx) {
                ordered.push(c);
            }
        }
        ordered
    }

    /// True iff child `idx` of `sym` is a by-name (thunked) operand — the `&&`/`||`
    /// right arm or an `if` branch, matching the scope-push sites in
    /// [`intern_op`](Self::intern_op) and the re-entry sites in
    /// [`build_op`](Self::build_op). Every other operand is eager.
    pub(crate) fn is_scoped_child(&self, sym: SymId, idx: usize) -> bool {
        match &self.syms[sym.0 as usize].node {
            Node::Op(_) => match op_of(&self.syms[sym.0 as usize].key.tag) {
                IF => idx == 1 || idx == 2,
                BIN_AND | BIN_OR => idx == 1,
                _ => false,
            },
            _ => false,
        }
    }

    /// The LOCAL-only post-order schedule of `compound` — Scala's
    /// `scheduleForResult` (`Thunks.scala:196-212`): a `depthFirstOrderFrom` DFS
    /// whose neighbours are filtered to `bodyIds(id) && !isVar`. Outside
    /// (free-var) leaves and bound `Arg`s are pruned as neighbours and never
    /// appended; a nested `Deeper` thunk IS in `bodyIds` (built in-scope) so it is
    /// a neighbour and lands in post-order BEFORE the operator that owns it.
    pub(crate) fn body_schedule(&self, compound: SymId, cscope: ScopeId) -> Vec<SymId> {
        let mut visited: BTreeSet<SymId> = BTreeSet::new();
        let mut out: Vec<SymId> = Vec::new();
        self.body_sched_dfs(compound, cscope, &mut visited, &mut out);
        out
    }

    pub(crate) fn body_sched_dfs(
        &self,
        sym: SymId,
        cscope: ScopeId,
        visited: &mut BTreeSet<SymId>,
        out: &mut Vec<SymId>,
    ) {
        if !visited.insert(sym) {
            return;
        }
        for d in self.body_neighbours(sym, cscope) {
            self.body_sched_dfs(d, cscope, visited, out);
        }
        out.push(sym);
    }

    /// The in-body neighbours of `sym` for the LOCAL schedule of scope `cscope`:
    /// `sym`'s deps filtered to `bodyIds(cscope) && !isVar` (`Thunks.scala:205`) —
    /// only Local members and Deeper nested thunks; Outside free-vars and bound
    /// `Arg`s are dropped so they never enter the schedule. A Local node's deps are
    /// its structural children; a Deeper thunk's deps are its own `freeVars`.
    pub(crate) fn body_neighbours(&self, sym: SymId, cscope: ScopeId) -> Vec<SymId> {
        let raw: Vec<SymId> = match self.classify(self.syms[sym.0 as usize].scope, cscope) {
            Rel::Local => self.syms[sym.0 as usize].key.children.clone(),
            Rel::Deeper => self.free_vars(sym),
            Rel::Outside => return Vec::new(),
        };
        raw.into_iter()
            .filter(|&d| {
                !matches!(self.syms[d.0 as usize].node, Node::Arg)
                    && self.classify(self.syms[d.0 as usize].scope, cscope) != Rel::Outside
            })
            .collect()
    }

    /// Reconstruct the `Expr` for a single symbol — Scala's `buildValue`
    /// (`TreeBuilding.scala:498-517`). A symbol bound in `env` (an emitted
    /// `ValDef` id or a lambda arg) resolves to a `ValUse` (the recursion base);
    /// otherwise the node is rebuilt from its template and children.
    pub(crate) fn build_value(
        &self,
        sym: SymId,
        scope: ScopeId,
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
            Node::Func {
                args,
                body,
                body_scope,
            } => self.build_func(args, *body, *body_scope, env, def_id, usage),
            Node::Op(_) => self.build_op(sym, scope, env, def_id, usage),
        }
    }

    /// Rebuild a lambda — Scala's `buildValue` `Lambda` case
    /// (`TreeBuilding.scala:186-191`). Each argument consumes ONE id starting at
    /// `def_id+1` (a tupled lambda still has a single `STuple` arg → one id, the
    /// Task-7 `+1`-not-`+2` correction, spike §4); the body is a nested
    /// materialization scope (`body_scope`) whose ids continue from `varId+1`.
    /// The `def_id`-by-value threading (T1) is what lets sibling lambdas reuse the
    /// same arg id range (`m5-sched-small.md` §2.5), and building the rhs with
    /// `def_id = id-1` makes a lambda-valued ValDef's arg id equal the ValDef id
    /// (T2, `m5-sched-chaincash.md` §3).
    pub(crate) fn build_func(
        &self,
        args: &[(SymId, Option<SigmaType>)],
        body: SymId,
        body_scope: ScopeId,
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
        let body_expr = self.process_scope(body, body_scope, &body_env, cur + 1, usage);
        Expr::Op(IrNode {
            opcode: FUNC_VALUE,
            payload: Payload::FuncValue {
                args: wire_args,
                body: Box::new(body_expr),
            },
        })
    }

    /// Rebuild a generic opcode node. `If` branches and the `&&`/`||`
    /// right-hand operand are their own thunk sub-scopes (re-entered
    /// via the recorded `branch_scopes`, so a shared thunk-result symbol does not
    /// drag the wrong scope's members); every other child — including a
    /// getOrElse default, built eagerly in the enclosing scope (M5 Task 5c/R2) —
    /// is rebuilt in the current scope. A thunk carries the SAME `def_id` (no arg, no id consumed —
    /// `ThunkDef` case, `TreeBuilding.scala:195-197`).
    pub(crate) fn build_op(
        &self,
        sym: SymId,
        scope: ScopeId,
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
        let scoped_idx = |idx: usize| -> bool {
            match opcode {
                IF => idx == 1 || idx == 2,
                BIN_AND | BIN_OR => idx == 1,
                _ => false,
            }
        };
        let mut rebuilt: Vec<Expr> = Vec::with_capacity(child_syms.len());
        let mut next_branch = 0usize;
        for (idx, &c) in child_syms.iter().enumerate() {
            if scoped_idx(idx) {
                let child_scope = info.branch_scopes[next_branch];
                next_branch += 1;
                rebuilt.push(self.process_scope(c, child_scope, env, def_id, usage));
            } else {
                rebuilt.push(self.build_value(c, scope, env, def_id, usage));
            }
        }
        let mut it = rebuilt.into_iter();
        let payload = recompose(template, &mut it);
        Expr::Op(IrNode { opcode, payload })
    }
}

/// A symbol's placement relation to a materialization scope (see
/// [`Interner::classify`]).
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) enum Rel {
    /// Built in exactly this scope — a member (candidate ValDef).
    Local,
    /// Built in a scope nested inside this one — a compound; contributes its
    /// `freeVars` to this scope's DFS.
    Deeper,
    /// Built in an ancestor (or unrelated) scope — a `freeVar` boundary leaf.
    Outside,
}

/// A materialized `ValDef` node (`0xD6`). `tpe` is never on the wire (the reader
/// always has a constant store), so it is pinned `None` exactly as emit does
/// (`emit.rs` `emit_block`, `parse.rs` ValDef arm).
pub(crate) fn val_def(id: u32, rhs: Expr) -> Expr {
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
pub(crate) fn val_use(id: u32) -> Expr {
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
pub(crate) fn wrap_block(valdefs: Vec<Expr>, rhs: Expr) -> Expr {
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
pub(crate) fn op_of(tag: &KeyTag) -> u8 {
    match tag {
        KeyTag::Op(op) => *op,
        // Const/Unparsed/Arg are handled by their own `Node` arms in
        // `build_value` and never reach `build_op`.
        _ => unreachable!("op_of on a non-Op symbol"),
    }
}
