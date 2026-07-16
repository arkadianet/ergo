use std::collections::HashMap;

use ergo_ser::opcode::{Expr, Payload};
use ergo_ser::sigma_type::SigmaType;

use crate::stype::SType;
use crate::typed::{node_tpe, TypedExpr};
use crate::typer::unify::numeric_index;

use super::*;

/// Binding scope for the emission walk.
///
/// `bindings` is a stack of frames (one per `Block`/`Lambda`); a name
/// resolves innermost-first, so lambda args shadow enclosing `val`s exactly
/// like the typer's `lambdaEnv = env ++ args` overwrite
/// (SigmaTyper.scala:128). Each entry carries the binding's wire type for
/// scope introspection; only the id goes on the wire (`ValUse` is untyped,
/// `FuncValue` args are typed at the definition site).
///
/// # Id allocation (Scala TreeBuilding scheme, collision-free relaxation)
///
/// `next_id` is a single monotonic counter starting at 1. A `ValDef` takes
/// the next id AFTER its rhs is emitted (Scala: `val rhs = buildValue(...,
/// curId, ...); curId += 1; ValDef(curId, ...)` — TreeBuilding.scala:511-513);
/// a lambda arg takes the enclosing scope's next id and body ValDefs continue
/// past it (`varId = defId + 1`, body from `varId + 1` —
/// TreeBuilding.scala:186-191, recon-scala-pipeline §6). Scala additionally
/// REUSES ids across disjoint scopes (each `processAstGraph` restarts its
/// `curId` from the enclosing `defId`) and skips ids for non-materialized
/// graph nodes (CSE); the monotonic counter never reuses. This is a
/// sanctioned relaxation from exact Scala id parity: validity and
/// collision-freedom are the only guarantees this module makes.
pub(crate) struct Scope {
    pub(crate) bindings: Vec<HashMap<String, (u32, SigmaType)>>,
    next_id: u32,
    /// Contract-template named parameters → their `ConstantPlaceholder` index
    /// (M7). Mirrors `SigmaCompiler.compileTyped`'s `placeholdersEnv`
    /// (SigmaCompiler.scala:88-92): a param name that is not bound by any
    /// enclosing `val`/lambda resolves to `ConstantPlaceholder(index, tpe)`
    /// instead of erroring. Empty for the ordinary (non-contract) compile path,
    /// so this is a pure superset — the base pipeline is unaffected.
    pub(crate) placeholders: HashMap<String, u32>,
    /// The requested ErgoTree version for this compile (Scala's `treeVersion`
    /// under `VersionContext.withVersions`). Rides on the scope so every nested
    /// `emit_method_call` sees it; drives the V6-method GraphBuilding gate.
    pub(crate) tree_version: u8,
}

impl Scope {
    pub(crate) fn new(tree_version: u8) -> Self {
        Scope {
            bindings: vec![HashMap::new()],
            next_id: 1,
            placeholders: HashMap::new(),
            tree_version,
        }
    }

    /// Emission scope seeded with a contract's named-parameter placeholder env
    /// (M7). See [`emit_with_placeholders`]. Compiles under V6-active
    /// (`tree_version` = [`V6_ERGO_TREE_VERSION`]), so the emit-time V6 gate
    /// never fires on the contract path — the same version-agnostic behavior
    /// [`emit`] has always given the ordinary path's default entry.
    pub(crate) fn with_placeholders(placeholders: HashMap<String, u32>) -> Self {
        Scope {
            bindings: vec![HashMap::new()],
            next_id: 1,
            placeholders,
            tree_version: V6_ERGO_TREE_VERSION,
        }
    }

    /// Resolve `name` innermost-frame-first to its binding id.
    pub(crate) fn lookup(&self, name: &str) -> Option<u32> {
        self.bindings
            .iter()
            .rev()
            .find_map(|frame| frame.get(name).map(|(id, _)| *id))
    }

    /// Take the next binding id and record `name` in the innermost frame.
    pub(crate) fn bind(&mut self, name: &str, tpe: SigmaType) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.bindings
            .last_mut()
            .expect("Scope always holds at least the root frame")
            .insert(name.to_string(), (id, tpe));
        id
    }

    // ── fixed-positional payload builders ────────────────────────────────

    pub(crate) fn one(&mut self, a: &TypedExpr) -> Result<Payload, EmitError> {
        Ok(Payload::One(Box::new(self.emit(a)?)))
    }

    pub(crate) fn two(&mut self, a: &TypedExpr, b: &TypedExpr) -> Result<Payload, EmitError> {
        Ok(Payload::Two(
            Box::new(self.emit(a)?),
            Box::new(self.emit(b)?),
        ))
    }

    pub(crate) fn three(
        &mut self,
        a: &TypedExpr,
        b: &TypedExpr,
        c: &TypedExpr,
    ) -> Result<Payload, EmitError> {
        Ok(Payload::Three(
            Box::new(self.emit(a)?),
            Box::new(self.emit(b)?),
            Box::new(self.emit(c)?),
        ))
    }

    pub(crate) fn four(
        &mut self,
        a: &TypedExpr,
        b: &TypedExpr,
        c: &TypedExpr,
        d: &TypedExpr,
    ) -> Result<Payload, EmitError> {
        Ok(Payload::Four(
            Box::new(self.emit(a)?),
            Box::new(self.emit(b)?),
            Box::new(self.emit(c)?),
            Box::new(self.emit(d)?),
        ))
    }

    pub(crate) fn items_of(&mut self, items: &[TypedExpr]) -> Result<Vec<Expr>, EmitError> {
        items.iter().map(|it| self.emit(it)).collect()
    }

    /// `Two` payload with mixed-width normalization: when BOTH operands are
    /// numeric and their ladder widths differ, the narrower side is wrapped
    /// in `Upcast(_, wider)` — the `TransformingSigmaBuilder.applyUpcast`
    /// rule (SigmaBuilder.scala:664-676, applied by `arithOp` :700-705 and
    /// `comparisonOp`/`equalityOp` :679-697). The frontend already inserts
    /// these `Upcast` nodes at typer time (unify.rs `apply_upcast`, mirroring
    /// the same builder), so on frontend trees this is a no-op; it normalizes
    /// hand-built trees defensively. (`BitOp` never reaches a payload builder
    /// — its emit arm rejects for GraphBuilding verdict parity.)
    pub(crate) fn two_upcast(
        &mut self,
        l: &TypedExpr,
        r: &TypedExpr,
    ) -> Result<Payload, EmitError> {
        let mut le = self.emit(l)?;
        let mut re = self.emit(r)?;
        if let (Some(li), Some(ri)) = (numeric_index(node_tpe(l)), numeric_index(node_tpe(r))) {
            match li.cmp(&ri) {
                std::cmp::Ordering::Less => le = upcast_ir(le, map_type(node_tpe(r))?),
                std::cmp::Ordering::Greater => re = upcast_ir(re, map_type(node_tpe(l))?),
                std::cmp::Ordering::Equal => {}
            }
        }
        Ok(Payload::Two(Box::new(le), Box::new(re)))
    }

    /// Emit a collection/tuple index expression, wrapping a narrower-than-Int
    /// numeric index in `Upcast(_, SInt)` — `typedIndex.upcastTo(SInt)`,
    /// SigmaTyper.scala:265-288. The frontend inserts this at typer time
    /// (`typer::assign::assign_collection_index`/`assign_tuple_index`), so
    /// this is defensive normalization for hand-built trees. A WIDER index
    /// (Long+) is
    /// left untouched: `upcastTo(SInt)` would be a downcast, which the Scala
    /// typer rejects before this point.
    pub(crate) fn emit_index(&mut self, index: &TypedExpr) -> Result<Expr, EmitError> {
        let e = self.emit(index)?;
        Ok(match numeric_index(node_tpe(index)) {
            Some(i) if i < numeric_index(&SType::SInt).expect("SInt is numeric") => {
                upcast_ir(e, SigmaType::SInt)
            }
            _ => e,
        })
    }
}
