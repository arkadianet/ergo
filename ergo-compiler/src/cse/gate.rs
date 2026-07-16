use std::collections::{BTreeMap, BTreeSet};

use ergo_ser::sigma_type::SigmaType;

use super::*;

impl Interner {
    // ----- Phase B: flat usage count -----

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
    /// The CRITICAL nuance: sibling-thunk COPIES of a byte-identical
    /// subexpression are DISTINCT SymIds (scope-chained interning gives them
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

    /// [`flat_usage`](Self::flat_usage) restricted to the syms REACHABLE from
    /// `root` — Scala counts `hasManyUsagesGlobal` over the reachable
    /// `flatSchedule` (`AstGraphs.scala:197-206`), never over dead nodes. This
    /// matters ONLY since the pair-projection memo (`Tuples.scala:65`): a `._1`
    /// access eagerly builds the `._2` sibling too, and if that sibling is never
    /// used it is unreachable from every schedule root, so — exactly as in Scala —
    /// it must NOT count as a use of its pair receiver (otherwise a single-`._1`
    /// receiver like `b.creationInfo` would spuriously reach 2 uses and hoist).
    /// For a memo-free tree every allocated sym is reachable, so this is identical
    /// to [`flat_usage`](Self::flat_usage).
    pub(crate) fn flat_usage_reachable(&self, root: SymId) -> BTreeMap<SymId, usize> {
        let reachable = self.reachable_from(root);
        let mut usage: BTreeMap<SymId, usize> = BTreeMap::new();
        for &s in &reachable {
            for &child in &self.syms[s.0 as usize].key.children {
                *usage.entry(child).or_insert(0) += 1;
            }
        }
        usage
    }

    /// The set of syms reachable from `root` by following structural children
    /// (`key.children`) transitively. Lambda arg placeholders and bodies are
    /// reached through their referencing nodes' children (a body's arg-using node
    /// carries the arg sym in its own `key.children`), so this closure is
    /// complete without special-casing `Node::Func`.
    pub(crate) fn reachable_from(&self, root: SymId) -> BTreeSet<SymId> {
        let mut seen: BTreeSet<SymId> = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(s) = stack.pop() {
            if !seen.insert(s) {
                continue;
            }
            for &c in &self.syms[s.0 as usize].key.children {
                stack.push(c);
            }
        }
        seen
    }

    /// `has_many(sym) := usage(sym) > 1` — predicate P1 of the admission gate
    /// (`mainG.hasManyUsagesGlobal(s)`, `TreeBuilding.scala:503`). Takes a map from
    /// [`flat_usage`](Self::flat_usage) so callers count once and query many times.
    pub fn has_many(usage: &BTreeMap<SymId, usize>, sym: SymId) -> bool {
        usage.get(&sym).copied().unwrap_or(0) > 1
    }

    // ----- the 4-predicate admission gate (`TreeBuilding.scala:503-509`) -----

    /// The class tag of an interned symbol — the node-class discriminant the P2/P3/P4
    /// predicates key on.
    pub(crate) fn tag_of(&self, sym: SymId) -> &KeyTag {
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

    /// **P4 `IsConstantDef`** (`TreeBuilding.scala:161-166`, `:509`). Matches
    /// only Scala's NARROW `Const[_]` class — the primitive scalar literals the
    /// `toRep` fallback (`GraphBuilding.scala:495-498`) produces:
    /// Int/Byte/Short/Long/Boolean/String. Those are suppressed even at
    /// use-count > 1 "to increase effect of constant segregation … two equal
    /// constants don't always have the same meaning" (source comment `:506-508`);
    /// each occurrence re-segregates into its own pool slot with no dedup
    /// (validated E3: `42` used twice → two `0454` slots).
    ///
    /// **Type boundary.** Every
    /// OTHER literal — `GroupElement`/`SigmaProp`/`BigInt`/`UnsignedBigInt`/
    /// `Coll`/`Box`/`AvlTree` — lifts to a `GroupElementConst`-style
    /// `LiftedConst` (`Base.scala:240`, `SigmaDslImpl.scala:539-593` via the
    /// explicit `liftConst` arms, `GraphBuilding.scala:461-498`), a DIFFERENT
    /// `Def` trait that `IsConstantDef.unapply`'s `case _: Const[_]` structurally
    /// cannot see. So P4 NEVER fires for them and a multi-use literal of those
    /// types HOISTS to an ordinary `ValDef` like any other node — the decisive
    /// fact for `proveDHTuple(g1,g2,g1,g2)` (4 uses of one `GroupElement` value →
    /// 1 pool slot + `ValDef(1)`, oracle `d801 d601 7300 ce 7201 7201 7201 7201`).
    /// A type-BLIND `is_const` would wrongly suppress that ValDef.
    pub fn is_const(&self, sym: SymId) -> bool {
        matches!(
            &self.syms[sym.0 as usize].node,
            Node::Const(tpe, _) if is_primitive_scalar_const_type(tpe)
        )
    }

    /// The exact admission conjunction (`TreeBuilding.scala:503-509`):
    /// `has_many && !IsContextProperty && !IsInternalDef && !IsConstantDef`.
    /// A symbol clearing the gate is materialized as a `ValDef`; a
    /// single-use symbol fails P1 and stays inlined at its one use (this is where
    /// single-use inlining "falls out free"). Takes the precomputed
    /// [`flat_usage`](Self::flat_usage) map.
    ///
    /// Note this is the PURE 4-predicate gate. Lambda-argument placeholder symbols
    /// (`KeyTag::Arg`) are not excluded here by a predicate — Scala excludes them
    /// structurally (a bound `Variable` is never in a scope's `schedule`), which is
    /// materialization's schedule-membership concern, not a gate predicate.
    pub fn should_hoist(&self, sym: SymId, usage: &BTreeMap<SymId, usize>) -> bool {
        Self::has_many(usage, sym)
            && !self.is_context_property(sym)
            && !self.is_internal(sym)
            && !self.is_const(sym)
    }
}

/// Scala's narrow `Const[_]` class as a TYPE test (P4, `IsConstantDef`): the
/// primitive scalar literals produced by the `toRep` fallback
/// (`GraphBuilding.scala:495-498`) — Int/Byte/Short/Long/Boolean/String. Every
/// other literal type lifts to a `LiftedConst` (`Base.scala:240`) that P4
/// structurally cannot see and so hoists as an ordinary node.
/// `SString` is `Coll[SByte]` at the value level but
/// carries its own type code and IS a scalar `Const` in Scala, so it stays here.
pub(crate) fn is_primitive_scalar_const_type(tpe: &SigmaType) -> bool {
    matches!(
        tpe,
        SigmaType::SBoolean
            | SigmaType::SByte
            | SigmaType::SShort
            | SigmaType::SInt
            | SigmaType::SLong
            | SigmaType::SString
    )
}
