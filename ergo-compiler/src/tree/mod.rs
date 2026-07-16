//! ErgoTree assembly + the public end-to-end [`compile`] API (M3 Task 9).
//!
//! Wires the full pipeline source → bytes → address: parse → bind →
//! typecheck ([`crate::typecheck_with_network`]) → root coercion → emit
//! ([`crate::emit`]) → [`build_tree`] → wire write → P2S/P2SH address
//! construction. Mirrors the node's compile surface,
//! `ScriptApiRoute.compileSource`
//! (`ergo/src/main/scala/org/ergoplatform/http/api/ScriptApiRoute.scala:56-67`).
//!
//! This module keeps [`graph_build`] and [`compile`] centralized — the pass
//! ordering rationale for the nine-pass `graph_build` pipeline is dense and
//! interdependent, so it stays attached to that one function rather than
//! scattered across files. The rest is split across submodules:
//! - [`assemble`] — [`CompileResult`], [`build_tree`], and constant
//!   segregation.
//! - [`v0_gate`] — the v0-header-unserializable-data walker.
//! - [`lambda_gate`] — the GraphBuilding lambda/application verdict-parity
//!   reject gate.
//! - [`walk`] — `push_children`, the `Payload` child-walker shared by both
//!   gates (and by a test helper).
//! - [`cast_fold`] — the direct-constant-cast folding subsystem.

use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_p2s, encode_p2sh, NetworkPrefix};
use ergo_ser::ergo_tree::write_ergo_tree;
use ergo_ser::opcode::{write_expr, Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::CollValue;

use crate::emit::emit_with_version;
use crate::env::ScriptEnv;
use crate::stype::SType;
use crate::typecheck::{typecheck_with_network, CompileError};
use crate::typed::node_tpe;
use crate::typed_print::to_term_string;

mod assemble;
mod cast_fold;
mod lambda_gate;
mod v0_gate;
mod walk;
pub(crate) use assemble::build_tree;
pub use assemble::CompileResult;
pub(crate) use cast_fold::*;
pub(crate) use lambda_gate::*;
pub(crate) use v0_gate::*;
pub(crate) use walk::*;

/// The GraphBuilding pipeline shared by [`compile`] and the M7 contract-template
/// assembler (`crate::contract_template`). Runs every fold, lowering,
/// isProven-fusion, multi-arg-tupling and CSE pass that Scala's `IR.buildGraph`
/// then `IR.buildTree` run, in the oracle-pinned order. Takes the emitted (and
/// `toSigmaProp`-wrapped) root and returns the fully graph-built root — the exact
/// tree Scala serialises as `expressionTree` or segregates into an `ErgoTree`.
/// Extracted verbatim from `compile` so both surfaces stay byte-identical; the
/// only difference between the two callers is whether the emitted root carried
/// `ConstantPlaceholder` nodes for named params.
pub(crate) fn graph_build(root: Expr) -> Result<Expr, CompileError> {
    // GraphBuilding verdict-parity gates (lib.rs D-C5): reject the emitted
    // shapes Scala's full compiler rejects — lambda/application rules first.
    if let Some(e) = graph_building_lambda_reject(&root) {
        return Err(CompileError::Emit(e));
    }

    // Explicit-cast folds, BOTH directions (M4 Task 4, lib.rs D-C7 cast
    // bullet; recon-transforms.md §7): fold `Downcast`/`Upcast` of a DIRECT
    // constant (range-checked — the reject side of the retired D-C5 checker
    // cast arm now lives in this pass, one code path) while leaving a
    // cast-of-cast CHAIN's outer casts unfolded, exactly like Scala. MUST run
    // BEFORE `crate::fold::fold` below: a direct-constant `Upcast` (e.g. the
    // typer's mixed-width widening in `9223372036854775807L + 1`) needs to
    // already BE a plain `Const` by the time the arithmetic fold looks at it,
    // or that pass's `Expr::Const` fast path never sees a value to propagate
    // into the parent `+`/`-`/`*`/`min`/`max` (the overflow would silently go
    // undetected). It also runs before the generic fold's `SizeOf`-literal
    // rule — see `fold_direct_const_casts`'s docs for the oracle-pinned
    // `.size.toLong` regression that position protects.
    let root = fold_direct_const_casts(root).map_err(CompileError::Emit)?;

    // isProven→isValid fusion (M4 Task 6, D-C3; recon-transforms.md §3;
    // `crate::isproven`): `SigmaPropIsProven(BoolToSigmaProp(x)) → x` and its
    // dual `BoolToSigmaProp(SigmaPropIsProven(p)) → p`. This first placement is
    // the fixpoint fusion (`GraphBuilding.scala:188-189`) — it must run BEFORE
    // the generic fold so a fusion-exposed Boolean feeds the fold (e.g.
    // `sigmaProp(true) ^ (1 == 1)` → `BinXor(true, true)` → `false`). The
    // second placement is AFTER the lowering block (the top-level
    // `removeIsProven`, over the coercion adjacency the unwrap/D-C2 fold
    // expose) — see below.
    let root = crate::isproven::eliminate_isproven(root);

    // `val` inlining RETIRED (M5 Task 4, locked decision 4; spike §7.2): the
    // M4 `inline_vals` pass is gone — `crate::cse::cse` below is now the SOLE
    // subexpression-sharing pass and subsumes it (a use-count-1 symbol is not
    // hoisted, so its one use inlines at materialization; a constant-valued
    // `val` is P4-suppressed and inlines per-use). `inline_vals` could not stay:
    // it SYNTACTICALLY clones a shared `def`'s rhs into each use site, so two
    // uses in sibling `If`/`&&` thunks became sibling-distinct symbols that CSE
    // (scope-chain hash-cons) could never re-share — the exact under-hoisting
    // the M5 model exists to fix. CSE instead threads the shared graph node
    // (`intern` gives every `ValUse` of a `ValDef` the same symbol), matching
    // Scala's `buildGraph`. The overflow-reject-in-dead-`val` behaviour
    // (`{ val unused = 2147483647 + 1; ... }` → reject) is UNCHANGED: the fold
    // below still traverses every `ValDef` rhs (dead or live) and `prune_dead_
    // vals` runs AFTER it, so the eager `buildNode` overflow still fires.

    // Generic constant fold (M4 Task 5, recon-transforms.md §1b/§2a-2d;
    // `crate::fold`) — the GraphBuilding-exact `rewriteDef` cascade as one
    // bottom-up fixpoint pass. It ABSORBS the two retired D-C5/D-C6 twins into
    // one traversal (F5 discipline): the overflow CHECK is now the fold's
    // reject arm (a both-`Const` `+`/`-`/`*` that overflows its width is
    // Scala's `ArithmeticException` → compile reject, now byte-correct because
    // the node is actually replaced), and the `SizeOf(<coll literal>)` element-
    // count fold is one rule among many. Runs AFTER `fold_direct_const_casts`
    // (casts fold their immediate-`Const` children BEFORE arith sees them, and
    // this pass never re-folds a cast — mirroring Scala's build-time cast
    // interception vs the `rewriteDef` fixpoint) and BEFORE the v0 data gate
    // below — so a fold that erases v3-only constant DATA (a
    // `Coll[UnsignedBigInt]().size` collapsing to `Int`, or the NF-1
    // `unsignedBigInt == unsignedBigInt` closure) never puts that data on the
    // wire (locked decision 1).
    let root = crate::fold::fold(root).map_err(CompileError::Emit)?;

    // Dead-`val` pruning (M4 Task 9, recon-transforms.md §8; `crate::inline`).
    // Removes every `val` unreachable from its block result — Scala's schedule
    // DFS (`ProgramGraphs.scala:35-64`) never visits it, so it is absent from
    // the final tree. Runs AFTER `crate::fold::fold` (so any overflow in a dead
    // `val`'s rhs has already rejected, matching the eager `buildNode`) and
    // recomputes reachability, so a `val` that a fold turned dead (its sole use
    // erased by `x * 0 -> 0`) is dropped too. Runs BEFORE the v0-data gate so a
    // dead `val` holding v3-only data (`{ val unused = Coll[BigInt](); ... }`)
    // is gone before the gate scans — the oracle accepts it (the schedule
    // prunes it), and the gate must too. STILL REQUIRED pre-CSE (M5 Task 4): a
    // dead `val`'s rhs must not be interned, else its `ValUse` refs would
    // inflate `crate::cse`'s flat usage count and wrongly hoist a
    // used-only-in-dead-code subexpression.
    let root = crate::inline::prune_dead_vals(root);

    // Dense id renumbering RETIRED (M5 Task 4, locked decision 4; spike §7.2):
    // `crate::inline::renumber_dense` is gone. Dense, assign-once ids now come
    // from `crate::cse::cse` below, which allocates them top-down as the final
    // tree is built (spike §4) — there is no post-hoc renumber pass to layer.

    // v0-header data gate — Scala's compile route cannot serialize v6-only
    // constant DATA: `ErgoTreeSerializer.serializeErgoTree` re-pins
    // `VersionContext.withVersions(_, treeVersion = ergoTree.version)`
    // (v6.0.2 `data/.../ErgoTreeSerializer.scala:105-112`), and the route's
    // header is ALWAYS `defaultHeaderWithVersion(0)` — so even an
    // ORACLE_TREE_VERSION=3 compile serializes under `treeVersion = 0`, where
    // `CoreDataSerializer.serialize`'s v3-gated arms (`SUnsignedBigInt` at
    // :39, `SOption` at :78) fall through to the :86 catch-all
    // `SerializerException`. Mirror the reject (oracle:
    // `cc unsignedBigInt("5") > unsignedBigInt("3")` → `REJECT 0:0
    // SerializerException`, compile_seed.json). Our wire layer is
    // deliberately version-independent (ergo-ser stays consensus-lenient), so
    // the gate lives here in the compile surface. M4 NOTE: when `build_tree`
    // grows versioned headers, gate on the emitted header version < 3.
    if let Some(what) = find_v0_unserializable(&root) {
        return Err(CompileError::Serializer { what });
    }

    // Lowering block (M4 Task 3, locked decision 1): AFTER every gate/fold
    // above, BEFORE constant segregation. D-C2 (`CreateProveDlog(Const)` /
    // `CreateProveDHTuple(Const×4)` → bare `SigmaPropConstant`) + the
    // single-element `anyOf`/`allOf`/`allZK`/`anyZK` unwrap
    // (recon-transforms.md §4/§5; `crate::lower`). Must run before the P2SH
    // proposition bytes below are computed, so the folded/unwrapped shape is
    // what both the proposition hash and `build_tree`'s bare-root check see.
    let root = crate::lower::lower(root);

    // Re-fold after lowering (NF-M4-2, M4 close-out; mirrors the double-
    // `isProven` pattern in this pipeline). Scala runs `proveDlog(const)` /
    // `proveDHTuple(const×4)` folding and the `Equals` equal-operand fold in the
    // SAME `rewriteDef` FIXPOINT, so `proveDlog(g1) == proveDlog(g1)` folds to
    // `true` in one cascade: the D-C2 fold makes both operands identical
    // `SigmaPropConstant`s, and the still-live `Equals` rule then collapses them.
    // Our `crate::fold::fold` runs ONCE, BEFORE `crate::lower` — at which point
    // the operands are still `CreateProveDlog` nodes, not `Const`, so the
    // `Const`-restricted `Equals` rule correctly declines. `crate::lower` then
    // exposes the identical-`Const` pair, but nothing re-examines it. Presenting
    // the lowered tree to the fold a second time closes exactly that
    // ordering-dependent gap. Idempotence: `fold` rewrites each node to its
    // per-node fixpoint, so the first pass SATURATED every shape it could see —
    // the second pass can only act on nodes `lower` newly exposed (the
    // D-C2-created `Const == Const` / `Const != Const` pairs); everything else
    // is already at its fixpoint and passes through unchanged.
    let root = crate::fold::fold(root).map_err(CompileError::Emit)?;

    // Top-level `removeIsProven` (M4 Task 6, D-C3; recon-transforms.md §3;
    // `GraphBuilding.scala:245-252`, applied at `:418` AFTER buildGraph). The
    // lowering block above (D-C2 `proveDlog(const)` fold + single-element
    // `AllOf`/`AnyOf` unwrap) is what makes the `BoolToSigmaProp`/
    // `SigmaPropIsProven` adjacency appear: `allOf(Coll(proveDlog(g1)))` lowers
    // to `BoolToSigmaProp(SigmaPropIsProven(Const{SigmaProp}))`, which this
    // strips to the bare `SigmaPropConstant` root (header `0x00`, matching PK).
    // The `false`-XOR / `BinAnd` forms were already fused+folded pre-fold above,
    // so this second pass is a no-op for them.
    let root = crate::isproven::eliminate_isproven(root);

    // Multi-arg lambda TUPLING (M4 Task 7, D-C4; recon-transforms.md §6;
    // `crate::tuple`): a fold-slot lambda `{(a, b) => ...}` emits as a 2-arg
    // `FuncValue`, which is wire-legal but unevaluable — the reference JIT
    // hard-errors on any non-1-arg function (`values.scala:1042-1056`). Scala's
    // IR pipeline lowers it to the tupled 1-arg form
    // `FuncValue([(id, STuple(t_a, t_b))], body[a := SelectField(ValUse(id),1),
    // b := SelectField(ValUse(id),2)])` (`GraphBuilding.scala:917-924` +
    // `TreeBuilding.scala:185-190/454-457`) — the only shape real `Fold` trees
    // carry on-chain. Runs AFTER `graph_building_lambda_reject` above (which has
    // already rejected the non-1-arg *applications* Scala refuses; every
    // multi-arg *definition* surviving to here is the D-C4 both-accept class —
    // fold-slot and un-applied lambdas both compilers accept) and is a no-op for
    // every 1-arg lambda. The tuple param reuses the first arg's id, matching
    // Scala's `varId = defId + 1` for the non-CSE case (byte-verified against the
    // oracle).
    let root = crate::tuple::tuple_lambdas(root);

    // CSE / ValDef materialization (M5, locked decision 4; spike §7.1/§7.2;
    // `crate::cse`) — the SOLE subexpression-sharing pass, replacing the retired
    // M4 `inline_vals`/`renumber_dense`. A scope-chain hash-cons decides identity
    // by FIRST-BUILD scope (both `If` branches / `&&`/`||` right arm /
    // `getOrElse` default push a scope; siblings never share), a flat global
    // usage count + the 4-predicate gate (`has_many && !IsContextProperty &&
    // !IsInternalDef && !IsConstantDef`) decides which symbols become `ValDef`s,
    // and dense ids are threaded assign-once top-down (no renumber). Runs at the
    // spike §7.2 position: AFTER every fold/lowering/tupling (so it sees the
    // final lowered shape) and BEFORE constant segregation / `write_ergo_tree`.
    // Its input is `prune_dead_vals`-cleaned (above) so dead-code refs do not
    // inflate the usage count.
    let root = crate::cse::cse(root);

    // Re-fold after CSE (M5 Task 4, oracle-pinned; mirrors the post-`lower`
    // re-fold above). Scala folds continuously in `rewriteDef` AS the graph is
    // built, so a constant threaded through a `val` (`{ val x = 1 + 1;
    // sigmaProp(x > 0 && x < 3) }`) is already folded through its uses before the
    // comparison nodes exist. Our fold ran BEFORE CSE, where `x`'s uses were
    // still `ValUse` nodes it cannot fold through; CSE then P4-inlines the
    // constant `2` at each use, newly exposing `2 > 0` / `2 < 3` as
    // `Const`-adjacent. This pass collapses exactly those CSE-exposed constant
    // adjacencies (oracle: the source above → `1000d1ed8503`, ZERO constants,
    // ZERO ValDefs — identical to `sigmaProp(1 > 0 && 1 < 3)`). It never touches
    // a hoisted `ValDef`/`ValUse` (fold does not propagate through `ValUse`), so
    // it cannot disturb CSE's placement or ids; idempotence guarantees it only
    // acts on the newly-inlined-constant shapes.
    let root = crate::fold::fold(root).map_err(CompileError::Emit)?;
    Ok(root)
}

/// Compile ErgoScript `source` end-to-end: typecheck, lower to opcode IR,
/// assemble the ErgoTree, serialize, and derive the P2S/P2SH addresses.
///
/// Pipeline: parse → bind → typecheck → root-coerce → emit → [`build_tree`] →
/// `write_ergo_tree` → addresses. Mirrors `ScriptApiRoute.compileSource`
/// (`ScriptApiRoute.scala:56-67`).
///
/// # The three version axes
///
/// 1. **`tree_version` (axis 1, frontend gate ONLY):** threads the v5/v6
///    method-table + predef visibility gate through parse/bind/typecheck
///    (`tree_version >= 3` ⇔ `VersionContext.isV3OrLaterErgoTreeVersion`).
///    Scala's route forwards its `treeVersion` param ONLY into
///    `VersionContext.withVersions` — never into the tree header.
/// 2. **Wire header version (axis 2):** fixed at 0 in M3 (and in the route:
///    `ErgoTree.defaultHeaderWithVersion(0.toByte)` unconditionally). See
///    [`build_tree`].
/// 3. **Activated script version (axis 3):** the EVALUATOR's
///    block-consensus version; a compile-time no-op here — it decides how a
///    node executes the tree, not what bytes we produce.
///
/// # Root coercion
///
/// Mirrors the route's dispatch (`ScriptApiRoute.scala:60-65`): a
/// `SigmaProp`-typed root passes through; a `Boolean`-typed root is wrapped
/// in `BoolToSigmaProp` (opcode `0xD1`, Scala `script.toSigmaProp`); any
/// other root type is [`CompileError::Root`] (the route's bare
/// `new Exception(...)`; oracle: `cc HEIGHT` → `REJECT 0:0 Exception`).
///
/// # P2SH contract
///
/// The P2SH content hash covers the PROPOSITION bytes — the serialized root
/// expression WITHOUT the ErgoTree header/constants wrapper
/// (`Pay2SHAddress.apply(prop)`, `ErgoAddress.scala:210-218`). Scala hashes
/// `toProposition(replaceConstants = isConstantSegregation)`
/// (`ErgoAddress.scala:201-204`) — i.e. it re-INLINES placeholders before
/// hashing. We hash the PRE-segregation `root` (still fully inline) directly,
/// which is byte-equal to that re-inlined proposition and cheaper. This is why
/// P2SH is SEGREGATION-invariant (the D-C1 flip never moves it; D-C7 covers the
/// residual IR-shape divergences that DO move it).
///
/// # Task-10 verdict adjudication (the semantic-parity gate)
///
/// The Task-10 corpus run (`tests/compile_semantic_parity.rs`,
/// `test-vectors/ergoscript/compile/compile_seed.json`) adjudicated every
/// verdict divergence against the full Scala compiler:
/// - Postfix method-call residuals (e.g. `arr1 size`): the UNWRAPPED corpus
///   forms have non-`Boolean`/`SigmaProp` roots, so the route's root
///   dispatch rejects them (class advisory); the WRAPPED forms
///   (`sigmaProp((arr1 size) > 0)`) are rejected by the Task-11 wave-1
///   `%SCollection.size` gate in `emit_method_call` (lib.rs D-C5, exact
///   `GraphBuildingException` class).
/// - `xorOf` over `Coll[SigmaProp]`: rejected in `emit` (Scala
///   GraphBuilding `AssertionError`; see the `XorOf` arm).
/// - v6-only constant data under the v0 header (`unsignedBigInt(..)`
///   comparisons): rejected by the v0-header data gate below
///   ([`CompileError::Serializer`], mirroring Scala's
///   `SerializerException`).
/// - Residual `SigmaPropIsProven` in mixed `Bool`/`SigmaProp` logical
///   contexts: coercion-cancellation CLOSED (M4 Task 6, lib.rs D-C3) —
///   [`crate::isproven`] cancels the `BoolToSigmaProp`/`SigmaPropIsProven`
///   round trips before the fold and after the lowering block. The
///   surviving-sigma `HasSigmas` `SigmaAnd`/`SigmaOr` reconstruction (a
///   residual `0xCF` in five corpus outputs) stays open, co-blocked on
///   val-inline/CSE (Tasks 8/9).
/// - Task-11 wave 1 added the GraphBuilding reject-gate family (lib.rs
///   D-C5): bit ops, zero-arg/non-1-arg lambda applications, SFunc-typed
///   lambda params, postfix `size`, out-of-range `getReg` literals,
///   pre-v3 SNumericType methods, and the constant-fold overflow check
///   ([`graph_building_lambda_reject`] below + [`crate::fold`]'s
///   arithmetic-overflow reject arm + the emit-arm gates).
///
/// # Examples
///
/// ```
/// use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
///
/// let r = compile(&ScriptEnv::new(), "sigmaProp(HEIGHT > 100)", 0, NetworkPrefix::Mainnet)
///     .unwrap();
/// // A non-bare root segregates: header byte 0x10 (constant-segregation bit).
/// assert_eq!(r.tree_bytes[0], 0x10);
/// ```
pub fn compile(
    env: &ScriptEnv,
    source: &str,
    tree_version: u8,
    network: NetworkPrefix,
) -> Result<CompileResult, CompileError> {
    let typed = typecheck_with_network(env, source, tree_version, network)?;

    // Root dispatch — ScriptApiRoute.scala:60-65. Emit under the requested
    // `tree_version` so the GraphBuilding-parity gates reject V6-only constructs
    // (e.g. the bare `fromBigEndianBytes` predef) under a v5 target.
    let root = match node_tpe(&typed) {
        SType::SSigmaProp => emit_with_version(&typed, tree_version)?,
        SType::SBoolean => Expr::Op(IrNode {
            // BoolToSigmaProp — Scala `script.toSigmaProp` (values.scala:58).
            opcode: 0xD1,
            payload: Payload::One(Box::new(emit_with_version(&typed, tree_version)?)),
        }),
        other => {
            return Err(CompileError::Root {
                tpe: to_term_string(other),
            })
        }
    };

    let root = graph_build(root)?;

    // P2SH proposition bytes — Scala's `Pay2SHAddress.apply(script: ErgoTree)`
    // hashes `toProposition(replaceConstants = isConstantSegregation)`
    // (`ErgoAddress.scala:201-204`), i.e. the constant-INLINED proposition. The
    // pre-segregation `root` already IS that inlined body (every constant is
    // still inline here, no placeholders yet), so hashing it is byte-equal to
    // Scala's re-inlining step AND cheaper than segregating then substituting
    // back. For a bare-constant root this is the body itself — equivalent. This
    // is why the D-C1 segregation flip leaves the P2SH address INVARIANT
    // (recon-segregation.md §4; lib.rs D-C1/D-C7).
    let mut pw = VlqWriter::new();
    write_expr(&mut pw, &root, false)?;
    let proposition_bytes = pw.result();

    let ergo_tree = build_tree(root)?;

    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &ergo_tree)?;
    let tree_bytes = w.result();

    // Post-write self-check (Task-11 wave 2; lib.rs D-C6): the bytes we are
    // about to derive ADDRESSES from must round-trip through our own
    // deserializer. A failure means compile() would hand out a P2S address whose
    // script no deserializer accepts — funds sent there are stranded (the F-3
    // class, adversarial-findings-constants.md).
    //
    // The re-read runs under the ACTIVATED-version axis (`tree_version`), NOT the
    // emitted header version (always 0). Scala gates V6-embeddable TYPE codes
    // (`SUnsignedBigInt`, …) on the ACTIVATED version
    // (`TypeSerializer.getEmbeddableType` → `VersionContext.isV6Activated`,
    // `VersionContext.scala:33`; deser under `withVersions(activatedVersion,
    // treeVersion)`, `ErgoTreeSerializer.scala:148-154`), so a header-v0 tree
    // carrying a code-9 type that a `tree_version >= 3` compile produces DOES
    // re-parse on a V6-activated network — `read_ergo_tree_with_activated_version`
    // mirrors that. (The earlier premise that these bytes "neither side's reader
    // re-parses → strands funds" was WRONG: the wrong-axis header-version gate in
    // the plain reader was the only thing rejecting them; corrected here + lib.rs
    // D-C6 item 5a.) A genuinely unrepresentable emission (a real serializer
    // failure) still rejects reject-side-safely: a wrong-reject surfaces a user
    // error, a wrong-accept strands funds.
    {
        use ergo_primitives::reader::VlqReader;
        use ergo_ser::ergo_tree::read_ergo_tree_with_activated_version;
        let mut r = VlqReader::new(&tree_bytes);
        let reread = read_ergo_tree_with_activated_version(&mut r, tree_version);
        if let Err(e) = reread {
            return Err(CompileError::Serializer {
                what: format!(
                    "emitted tree is not self-readable ({e:?}): refusing to derive an \
                     address for a script no deserializer accepts"
                ),
            });
        }
        if !r.is_empty() {
            return Err(CompileError::Serializer {
                what: "emitted tree has trailing bytes after re-read".to_string(),
            });
        }
    }

    let p2s_address = encode_p2s(network, &tree_bytes);
    let p2sh_address = encode_p2sh(network, &proposition_bytes);

    Ok(CompileResult {
        tree_bytes,
        ergo_tree,
        p2s_address,
        p2sh_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::EnvValue;
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

    // ----- helpers -----

    /// secp256k1 generator, SEC1-compressed. The Task-1 PK test address
    /// `3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN` decodes to
    /// ProveDlog of exactly this point (the well-known "secret = 1" testnet
    /// address), and the oracle env's `g1` is bound to it too.
    const GENERATOR_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Oracle capture, VERBATIM (TyperOracle.scala `cc` verb, sigma-state
    /// 6.0.2 SigmaCompiler + ErgoTreeSerializer + Pay2S/Pay2SHAddress,
    /// ORACLE_NETWORK=testnet, captured 2026-07-04,
    /// `.superpowers/sdd/task-1-report.md` Step-4 smoke, line 2):
    ///
    ///   cc PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")
    ///   → OK <ORACLE_PK_TREE_HEX> <ORACLE_PK_P2S> <ORACLE_PK_P2SH>
    const ORACLE_PK_TREE_HEX: &str =
        "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ORACLE_PK_P2S: &str = "5AgXz2KadZrAXE86MMjVQ7UAWeRFbhBZcQms4j2RgBuHNrVRwY7xvp2S";
    const ORACLE_PK_P2SH: &str = "qETVgcEctaXurNbFRgGUcZEGg4EKa8R4a5UNHY7";

    /// Same capture, line 1:
    ///
    ///   cc sigmaProp(HEIGHT > 100)
    ///   → OK 100104c801d191a37300 Xw4DF8oEhUcUi3f7LAHt
    ///        qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S
    ///
    /// The oracle tree is SEGREGATED (header 0x10, constants table
    /// `01 04c801`, body `d191a37300` with placeholder `7300`); its
    /// constant-INLINED proposition — what Pay2SHAddress hashes — is
    /// `d191a304c801`.
    const ORACLE_HGT_P2S: &str = "Xw4DF8oEhUcUi3f7LAHt";
    const ORACLE_HGT_P2SH: &str = "qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S";

    fn compile_testnet(env: &ScriptEnv, source: &str) -> Result<CompileResult, CompileError> {
        // tree_version 0 = the route default; axis-1 only gates v6 method
        // visibility, which none of these sources touch.
        compile(env, source, 0, NetworkPrefix::Testnet)
    }

    fn ct(source: &str) -> Result<CompileResult, CompileError> {
        compile_testnet(&ScriptEnv::new(), source)
    }

    /// The [`fold_direct_const_casts`] output BEFORE `build_tree`/
    /// segregation — needed to inspect a cast-fold's shape directly, since
    /// `CompileResult::ergo_tree.body` replaces every folded constant with
    /// a `ConstPlaceholder` once segregation runs.
    fn folded_root(source: &str) -> Expr {
        let typed = typecheck_with_network(&ScriptEnv::new(), source, 0, NetworkPrefix::Testnet)
            .expect("typecheck");
        let root = emit_with_version(&typed, 0).expect("emit");
        fold_direct_const_casts(root).expect("fold_direct_const_casts")
    }

    /// Depth-first search for the first `FuncValue` payload in `expr`
    /// (test-only tree introspection — reuses [`push_children`]).
    fn find_func_value(expr: &Expr) -> Option<&Payload> {
        let mut stack = vec![expr];
        while let Some(e) = stack.pop() {
            if let Expr::Op(IrNode { payload, .. }) = e {
                if matches!(payload, Payload::FuncValue { .. }) {
                    return Some(payload);
                }
                push_children(payload, &mut stack);
            }
        }
        None
    }

    fn generator_env() -> ScriptEnv {
        let bytes: [u8; 33] = hex::decode(GENERATOR_HEX).unwrap().try_into().unwrap();
        let mut env = ScriptEnv::new();
        env.insert(
            "g1",
            EnvValue::GroupElement(GroupElement::from_bytes(bytes)),
        );
        env
    }

    fn reparse(bytes: &[u8]) -> ErgoTree {
        let mut r = VlqReader::new(bytes);
        read_ergo_tree(&mut r).expect("compiled tree must reparse")
    }

    /// Reparse under a V6-activated deserializer — the axis the compile
    /// self-check uses for a `tree_version >= 3` build (F1). Mirrors Scala
    /// re-reading a header-v0 tree on a V6-activated network.
    fn reparse_v6(bytes: &[u8]) -> ErgoTree {
        let mut r = VlqReader::new(bytes);
        ergo_ser::ergo_tree::read_ergo_tree_with_activated_version(&mut r, 3)
            .expect("compiled tree must reparse under V6 activation")
    }

    // ----- happy path -----

    #[test]
    fn compile_bool_root_wraps_in_bool_to_sigma_prop() {
        // `HEIGHT > 100` types SBoolean → route coercion wraps in 0xD1
        // (ScriptApiRoute.scala:62-63 `script.toSigmaProp`), producing the
        // SAME tree as the explicit `sigmaProp(...)` form.
        let bare = ct("HEIGHT > 100").expect("compile");
        let explicit = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert!(
            matches!(&bare.ergo_tree.body, Expr::Op(IrNode { opcode: 0xD1, .. })),
            "bool root must be wrapped in BoolToSigmaProp"
        );
        assert_eq!(bare.tree_bytes, explicit.tree_bytes);
        assert_eq!(bare.p2s_address, explicit.p2s_address);
        assert_eq!(bare.p2sh_address, explicit.p2sh_address);
    }

    #[test]
    fn compile_pk_bare_const_header_zero_and_shape() {
        // PK(...) compiles straight to a bare SigmaPropConstant — the
        // fromProposition `SigmaPropConstant(_)` branch (withoutSegregation):
        // header 0x00, empty constants, body = the constant itself (the
        // exact `detect_p2pk` shape in ergo-ser).
        let r = compile_testnet(
            &ScriptEnv::new(),
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
        )
        .expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00, "non-segregated v0 header");
        assert!(r.ergo_tree.constants.is_empty());
        assert!(matches!(
            &r.ergo_tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_)),
            }
        ));
    }

    #[test]
    fn compile_sigmaprop_height_segregated_matches_oracle_bytes() {
        // The D-C1 flip (M4 Task 2): a non-bare root segregates. Scala's
        // `withSegregation` header 0x10, constants table `01 04c801` (one SInt
        // constant, value 100), body `d191a37300` = BoolToSigmaProp(GT(HEIGHT,
        // ConstPlaceholder(0))). Oracle capture (sigma-state 6.0.2, testnet):
        // `cc sigmaProp(HEIGHT > 100)` → `100104c801d191a37300`.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x10, "constant-segregation header");
        assert!(r.ergo_tree.constant_segregation);
        assert_eq!(
            r.ergo_tree.constants,
            vec![(SigmaType::SInt, SigmaValue::Int(100))],
            "one segregated constant, first-write slot"
        );
        assert_eq!(hex::encode(&r.tree_bytes), "100104c801d191a37300");
    }

    #[test]
    fn compile_bool_pair_compaction_survives_segregation_zero_constants() {
        // The Relation2 `0x85` bool-pair compaction is bypassed by the
        // constant sink (it never reaches the Expr::Const arm), so a script
        // whose only literal constants are a compacted bool pair segregates to
        // a header-0x10 tree with a ZERO-entry constants table. Oracle:
        // `cc c1 && c2` (env booleans → literals → compacted) → `1000d1ed8501`.
        let mut env = ScriptEnv::new();
        env.insert("c1", EnvValue::Bool(true));
        env.insert("c2", EnvValue::Bool(false));
        let r = compile_testnet(&env, "c1 && c2").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x10, "segregated header");
        assert!(
            r.ergo_tree.constants.is_empty(),
            "the compacted bool pair must NOT segregate"
        );
        assert_eq!(hex::encode(&r.tree_bytes), "1000d1ed8501");
    }

    #[test]
    fn compile_single_use_val_inlines_matching_oracle_bytes() {
        // M4 Task 9 graduation (recon-targets #2): `{ val x = HEIGHT; x > 5 }`
        // inlines the single-use `val x` and flattens the block to the bare
        // `GT(Height, 5)` — no `BlockValue`/`ValDef`/`ValUse` survives. Oracle
        // (`cc`, sigma-state 6.0.2, testnet): `1001040ad191a37300` (header 0x10,
        // one segregated SInt constant `5`, body `d191a37300` =
        // BoolToSigmaProp(GT(Height, ConstPlaceholder(0)))).
        let r = ct("{ val x = HEIGHT; x > 5 }").expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "1001040ad191a37300");
    }

    #[test]
    fn compile_lsp_test_contract_val_inlines_matching_oracle_bytes() {
        // M4 Task 9 graduation (recon-targets #46, `corpus:lsp/test_contract.es`):
        // `{ val deadline = SELF.R4[Int].get; sigmaProp(HEIGHT > deadline) }`
        // inlines `deadline` (single use) to `GT(Height, SELF.R4[Int].get)` with
        // no block and ZERO constants. Oracle (`cc`, testnet):
        // `1000d191a3e4c6a70404` (header 0x10, empty constants table, body
        // `d191a3e4c6a70404` = BoolToSigmaProp(GT(Height,
        // ExtractRegisterAs(Self, R4, SInt).get))).
        let r = ct("{ val deadline = SELF.R4[Int].get; sigmaProp(HEIGHT > deadline) }")
            .expect("compile");
        assert!(r.ergo_tree.constants.is_empty(), "no literal constants");
        assert_eq!(hex::encode(&r.tree_bytes), "1000d191a3e4c6a70404");
    }

    #[test]
    fn compile_lambda_arg_id_densifies_after_val_inline_matching_oracle_bytes() {
        // M4 Task 9 review nit (dense id renumbering; `crate::inline::
        // renumber_dense`): `{ val t = HEIGHT + 1;
        // sigmaProp(OUTPUTS.exists({(b: Box) => b.creationInfo._1 < t})) }`
        // inlines the single-use `val t` into the lambda body (cross-lambda
        // inline, already correct pre-fix), but our M3 emit had allocated the
        // lambda arg `b` id **2** (following `t`'s id 1) — surviving the
        // inline as a permanent numbering gap. Scala's post-inline schedule
        // gives the lambda arg id **1**. Oracle (`cc`, sigma-state 6.0.2,
        // testnet, captured 2026-07-07,
        // `test-vectors/ergoscript/compile/compile_seed.json`):
        // `10010402d1aea5d90101638f8cc77201019aa37300` — note `d90101`
        // (FuncValue, one arg, id **1**), not the pre-fix `d90102`.
        let r = ct(
            "{ val t = HEIGHT + 1; sigmaProp(OUTPUTS.exists({(b: Box) => b.creationInfo._1 < t})) }",
        )
        .expect("compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "10010402d1aea5d90101638f8cc77201019aa37300"
        );
        assert_eq!(r.p2s_address, "arcTuUnjRPq95jiYnHq6eU4AJyr8XCH9HoN");
        assert_eq!(r.p2sh_address, "rk4vxuStzvtBhd694dpg7jJYeBp22aBZue4jw6Q");
    }

    #[test]
    fn compile_inline_then_fold_reaches_sigmaprop_true() {
        // Pipeline-order pin (M5 Task 4): the constant-through-`val` fold now
        // comes from CSE + the post-CSE re-fold, not the retired `inline_vals`.
        // `{ val x = 2; sigmaProp(x + 1 == 3) }`: the pre-CSE fold cannot fold
        // `ValUse(x) + 1`, CSE P4-inlines the constant `2` at its use, and the
        // re-fold then collapses `2 + 1 == 3` → `true`. Oracle (`cc`, testnet):
        // `10010101d17300` (one SBoolean constant `true`, body
        // BoolToSigmaProp(ConstPlaceholder(0))).
        let r = ct("{ val x = 2; sigmaProp(x + 1 == 3) }").expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
    }

    #[test]
    fn compile_const_through_multiuse_val_folds_after_cse_matching_oracle() {
        // M5 Task 4 fold-ordering decision, oracle-pinned. The keystone probe for
        // "does fold run before or after CSE": a MULTI-use constant `val`. Scala
        // folds `1 + 1` → `2` and threads it through the env so both comparisons
        // are `Const`-adjacent and fold at build time — the whole thing collapses
        // to `true && true` with ZERO constants and ZERO ValDefs. Our pipeline
        // reproduces this ONLY because a `crate::fold::fold` runs AFTER CSE: the
        // pre-CSE fold folds `1 + 1` inside the `ValDef` rhs but cannot fold
        // `ValUse(x) > 0`; CSE then P4-inlines the constant `2` at each use,
        // newly exposing `2 > 0` / `2 < 3`; the post-CSE fold collapses them. If
        // fold ran ONLY before CSE this would wrongly emit `2 > 0 && 2 < 3` with
        // four segregated constants. Oracle (`cc`, testnet, decoded live):
        // `1000d1ed8503` — header 0x10, EMPTY constants table, body
        // `d1 ed 8503` (BoolToSigmaProp(BinAnd(compacted-bool-pair[true,true]))),
        // byte-identical to `sigmaProp(1 > 0 && 1 < 3)`.
        let r = ct("{ val x = 1 + 1; sigmaProp(x > 0 && x < 3) }").expect("compile");
        assert!(r.ergo_tree.constants.is_empty(), "no surviving constants");
        assert_eq!(hex::encode(&r.tree_bytes), "1000d1ed8503");
    }

    #[test]
    fn compile_cast_over_inlined_val_stays_unfolded() {
        // Pipeline-order pin (M4 Task 9): `fold_direct_const_casts` runs BEFORE
        // inline, and Scala's `Downcast(Constant)` fold is an AST-pattern match
        // that never fires over a `ValUse`, so a cast over an inlined `val` keeps
        // its `Downcast` node. `{ val x = 2; sigmaProp(x.toByte < 0.toByte) }`
        // keeps `Downcast(2, Byte)`. Oracle (`cc`, testnet):
        // `100204040200d18f7d7300027301`.
        let r = ct("{ val x = 2; sigmaProp(x.toByte < 0.toByte) }").expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "100204040200d18f7d7300027301");
    }

    #[test]
    fn compile_overflow_in_dead_val_still_rejects() {
        // Pipeline-order pin (M4 Task 9): a dead `val`'s rhs is folded by the
        // fold pass BEFORE pruning (mirroring Scala's eager `buildNode`), so an
        // overflow in an unused `val` still rejects. Oracle (`cc`, testnet):
        // `{ val unused = 300.toByte; sigmaProp(true) }` → REJECT
        // ArithmeticException.
        assert!(matches!(
            ct("{ val unused = 300.toByte; sigmaProp(true) }"),
            Err(CompileError::Emit(_))
        ));
    }

    #[test]
    fn compile_nested_sfunc_in_dead_val_accepts_nf2() {
        // NF-2 CLOSED (M4 Task 9): a higher-order (`SFunc`-param) lambda NESTED
        // inside an unreachable `val`'s rhs is pruned by Scala's schedule before
        // the lowering that `MatchError`s → oracle ACCEPTs. Previously rejected
        // (only a direct-rhs unused lambda was exempt).
        let r = ct("{ val unused = Coll({(f: Int => Int) => 1}); sigmaProp(true) }")
            .expect("NF-2: nested SFunc-param lambda in a dead val must compile");
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
    }

    // ----- round-trips -----

    #[test]
    fn compile_output_reparses_to_same_tree() {
        for src in [
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
            "sigmaProp(HEIGHT > 100)",
            "HEIGHT > 100",
        ] {
            let r = compile_testnet(&ScriptEnv::new(), src).expect("compile");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "src = {src}");
        }
        let r = compile_testnet(&generator_env(), "proveDlog(g1)").expect("compile");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
    }

    // ----- error paths -----

    #[test]
    fn compile_int_root_rejects_with_exception_class() {
        // Route :64-65: neither Bool nor SigmaProp root → bare Exception.
        let err = ct("1 + 1").expect_err("Int root must reject");
        assert!(matches!(&err, CompileError::Root { tpe } if tpe == "Int"));
        assert_eq!(err.class(), "Exception");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_height_root_rejects_matching_oracle_probe() {
        // Oracle (task-1-report.md extra probes): `cc HEIGHT` →
        // `REJECT 0:0 Exception`.
        let err = ct("HEIGHT").expect_err("Int root must reject");
        assert_eq!(err.class(), "Exception");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_parse_error_propagates_as_parse_phase() {
        let err = ct(")(").expect_err("parse must fail");
        assert!(matches!(err, CompileError::Parse(_)));
    }

    #[test]
    fn compile_unsigned_bigint_constant_rejects_serializer_class() {
        // Oracle (compile_seed.json, ORACLE_TREE_VERSION=3, captured
        // 2026-07-07): both UnsignedBigInt comparison sources reply
        // `REJECT 0:0 SerializerException` — the route's fixed v0 header
        // cannot carry UnsignedBigInt constant DATA (the v0-header data gate
        // in `compile`; mechanism citations there). tree_version = 3: the
        // FRONTEND accepts the v6 predef; the reject is the WIRE header's —
        // the two version axes are independent.
        for src in [
            r#"unsignedBigInt("5") == unsignedBigInt("3")"#,
            r#"unsignedBigInt("5") > unsignedBigInt("3")"#,
        ] {
            let err = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)
                .expect_err("UBI constant under a v0 header must reject");
            assert!(
                matches!(&err, CompileError::Serializer { .. }),
                "{src}: {err:?}"
            );
            assert_eq!(err.class(), "SerializerException", "{src}");
            assert_eq!(err.pos(), 0, "{src}");
        }
    }

    #[test]
    fn compile_v0_data_gate_runs_before_segregation() {
        // D-C6 pipeline-order invariant (locked decision 1): the
        // v0-unserializable-data gate runs on the PRE-segregation root (every
        // constant still inline), so the D-C1 flip does not change what it
        // catches — a UnsignedBigInt-data source (a NON-bare root that WOULD
        // otherwise segregate its UBI constant into the table) still rejects
        // identically, BEFORE `build_tree`/`segregate` ever runs. This pins
        // that the gate never needs to walk the post-segregation constants
        // table instead.
        let err = compile(
            &ScriptEnv::new(),
            r#"unsignedBigInt("5") == unsignedBigInt("3")"#,
            3,
            NetworkPrefix::Testnet,
        )
        .expect_err("UBI data must reject at the pre-segregation v0 gate");
        assert!(matches!(&err, CompileError::Serializer { .. }), "{err:?}");
        assert_eq!(err.class(), "SerializerException");
    }

    // ----- error paths: GraphBuilding parity gates (lib.rs D-C5, wave 1) -----
    // Every oracle fact below: captured 2026-07-07, 3 identical runs,
    // committed as compile_seed.json vectors (except the ACCEPT boundaries
    // that byte-mismatch pending val-inline/pruning — the unused/aliased
    // multi-arg-definition boundaries — which are pinned here verdict-only;
    // the D-C4 fold-slot class is now tupled+committed, see the smoke vector).

    #[test]
    fn compile_bit_op_wrapped_in_sigmaprop_rejects_graph_building_class() {
        // Oracle: `cc sigmaProp((1 | 2) == 3)` → `REJECT 1:12
        // GraphBuildingException` (all of |,&,^,<<,>>,>>>,~ — the emit
        // BitOp/BitInversion arms; width matrix pinned in emit.rs tests).
        for src in ["sigmaProp((1 | 2) == 3)", "sigmaProp((~1) == -2)"] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "GraphBuildingException", "{src}");
        }
        // Boolean ^ is BinXor, not a BitOp — still compiles.
        ct("sigmaProp((HEIGHT > 1) ^ (HEIGHT < 5))").expect("BinXor untouched");
    }

    #[test]
    fn compile_zero_arg_lambda_rejects_even_unused() {
        // Oracle: `cc { val f = {() => 1}; sigmaProp(f() == 1) }` → `REJECT
        // 1:12 GraphBuildingException`; the UNUSED variant rejects too
        // (`REJECT 1:17`) — the definition itself crashes Scala's graph
        // construction, before dead-code elimination.
        for src in [
            "{ val f = {() => 1}; sigmaProp(f() == 1) }",
            "{ val unused = {() => 1}; sigmaProp(true) }",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "GraphBuildingException", "{src}");
        }
    }

    #[test]
    fn compile_multi_arg_application_rejects_definitions_and_hof_slots_accept() {
        // Rejects: every non-1-arg APPLICATION (direct, aliased, inline) —
        // oracle `REJECT GraphBuildingException` on all four.
        for src in [
            "{ val f = {(x: Int, y: Int) => x + y}; sigmaProp(f(1, 2) == 3) }",
            "{ val f = {(x: Int, y: Int, z: Int) => x + y + z}; sigmaProp(f(1, 2, 3) == 6) }",
            "{ val f = {(x: Int, y: Int) => x + y}; val g = f; sigmaProp(g(1, 2) == 3) }",
            "sigmaProp({(x: Int, y: Int) => x + y}(1, 2) == 3)",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "GraphBuildingException", "{src}");
        }
        // Accepts (oracle OK): the multi-arg DEFINITION is fine — unused
        // val, un-applied alias, and both fold-callback forms (direct and
        // val-bound = the D-C4 both-accept class; our trees for these now
        // TUPLE to the evaluable 1-arg form, ledger D-C4 CLOSED / D-C5).
        for src in [
            "{ val unused = {(x: Int, y: Int) => x + y}; sigmaProp(true) }",
            "{ val f = {(x: Int, y: Int) => x + y}; val g = f; sigmaProp(true) }",
            "{ val f = {(a: Long, b: Long) => a + b}; sigmaProp(Coll(1L, 2L).fold(0L, f) == 3L) }",
            "sigmaProp(Coll(1L, 2L).fold(0L, {(a: Long, b: Long) => a + b}) == 3L)",
        ] {
            ct(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        }
    }

    #[test]
    fn compile_fold_slot_multi_arg_lambda_tuples_to_one_arg_funcvalue() {
        // D-C4 (M4 Task 7): the fold's 2-arg lambda must reach `build_tree` as
        // a TUPLED 1-arg `FuncValue(STuple)` — the only on-chain-valid shape.
        // (The context-free smoke also byte-matches the oracle in
        // compile_semantic_parity via compile_seed.json; this pins the shape
        // through the full pipeline.)
        let r = ct("sigmaProp(Coll(1, 2).fold(0, {(a: Int, b: Int) => a + b}) == 3)")
            .expect("fold with a 2-arg lambda compiles");
        let fv = find_func_value(&r.ergo_tree.body).expect("a FuncValue in the fold op slot");
        let Payload::FuncValue { args, .. } = fv else {
            unreachable!()
        };
        assert_eq!(args.len(), 1, "multi-arg lambda tupled to a single arg");
        assert!(
            matches!(&args[0].1, Some(SigmaType::STuple(ts)) if ts.len() == 2),
            "the single arg is a 2-tuple, got {:?}",
            args[0].1
        );
    }

    #[test]
    fn compile_function_typed_lambda_param_rejects_match_error_class() {
        // Oracle: `REJECT 0:0 MatchError` — even when the parameter is never
        // applied in the body; the exemption is an UNUSED val binding
        // (pruned before the lowering that dies — fresh boundary capture).
        for src in [
            "{ val h = {(f: Int => Int) => f(10)}; sigmaProp(h({(x: Int) => x + 1}) == 11) }",
            "{ val h = {(f: Int => Int) => 1}; sigmaProp(h({(x: Int) => x}) == 1) }",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "MatchError", "{src}");
        }
        // Oracle OK: unused val-bound SFunc-param lambda (pruned)...
        ct("{ val unused = {(f: Int => Int) => 1}; sigmaProp(true) }")
            .expect("unused SFunc-param lambda is pruned by Scala — must accept");
        // ...and a lambda RETURNING a lambda (curried) is not a
        // function-typed PARAMETER — accepted on both sides.
        ct("{ val f = {(x: Int) => {(y: Int) => x + y}}; sigmaProp(f(1)(2) == 3) }")
            .expect("curried lambda accepts");
    }

    #[test]
    fn compile_postfix_size_and_get_reg_range_reject_with_oracle_classes() {
        // Postfix residual `size` (emit gate; oracle `cc sigmaProp((OUTPUTS
        // size) >= 0)` → `REJECT 1:12 GraphBuildingException`).
        let err = ct("sigmaProp((OUTPUTS size) >= 0)").expect_err("postfix size");
        assert_eq!(err.class(), "GraphBuildingException");
        // getReg out-of-range literal (emit gate; oracle `REJECT 0:0
        // ArrayIndexOutOfBoundsException`); v6 method → tree_version 3.
        let err = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.getReg[Int](100).isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect_err("out-of-range getReg");
        assert_eq!(err.class(), "ArrayIndexOutOfBoundsException");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_allzk_anyzk_reject_staging_exception_full_pipeline() {
        // D-C8 (M4 Task 8 review): `allZK`/`anyZK` typecheck fine (the
        // typer's `predefined_env` has both names) but Scala's
        // `SigmaPredef.AllZKFunc`/`AnyZKFunc` register `PredefFuncInfo(
        // undefined)` as their irBuilder — genuinely unimplemented upstream
        // (sigmastate-interpreter#543), not a porting gap. The typed tree
        // keeps the raw `Apply(Ident, args)` shape (byte-identical to the
        // oracle's `tce` residual), and `compiler.compile`'s GraphBuilding
        // stage throws `StagingException` reaching that unbound `Ident` —
        // live-probed 2026-07-07, ×3 identical runs: literal single-element,
        // literal multi-element, AND a val-bound `Coll` ALL reject
        // identically for both names. There is NO accepting form — the
        // "literal Coll unwraps to SigmaAnd/SigmaOr" shape this port used to
        // assume never fires for the direct function-call route (that
        // unwrap only applies to typed `SigmaAnd`/`SigmaOr` nodes built by
        // the `&&`/`||` OPERATORS, a disjoint code path).
        for src in [
            "allZK(Coll(proveDlog(g1)))",
            "anyZK(Coll(proveDlog(g1)))",
            "{ val c = Coll(proveDlog(g1)); allZK(c) }",
        ] {
            let err = compile_testnet(&generator_env(), src).expect_err(src);
            assert_eq!(err.class(), "StagingException", "{src}");
        }
    }

    #[test]
    fn compile_constant_fold_overflow_rejects_arithmetic_exception_class() {
        // Oracle: `REJECT 0:0 ArithmeticException` on the whole family
        // (compile-time exact fold of constant +,-,* and casts-of-literals;
        // the fold runs in unused-val rhs and lambda bodies too).
        for src in [
            "sigmaProp(300.toByte < 0.toByte)",
            "sigmaProp(2147483647.toShort > 0.toShort)",
            "sigmaProp((2147483647 + 1) < 0)",
            "sigmaProp((9223372036854775807L + 1L) < 0L)",
            "sigmaProp((9223372036854775807L + 1) < 0L)", // folded Upcast(1) feeds the +
            "sigmaProp(9223372036854775807L * 2L > 0L)",
            "sigmaProp((127.toByte + 1.toByte) < 0.toByte)",
            "sigmaProp(-2147483647 - 2 < 0)",
            "sigmaProp((-(2147483647) - 2) < 0)", // parser folds -(<lit>) → the `-` fold fires
            "{ val unused = 2147483647 + 1; sigmaProp(true) }",
            "sigmaProp(Coll(1).map({(t: Int) => 2147483647 + 1})(0) < 0)",
            // folded arith chains INTO a parent fold (review follow-up probe)
            "sigmaProp(((2147483646 + 1) + 1) < 0)",
            // min/max propagate their folded constant into the parent check
            "sigmaProp((min(2147483647, 1) + 2147483647) < 0)",
            "sigmaProp((max(2147483647, 1) + 2147483647) < 0)",
            // mixed-width min: the typer's Upcast(1, SLong) folds first
            "sigmaProp((min(1, 9223372036854775807L) + 9223372036854775807L) < 0L)",
        ] {
            let err = ct(src).expect_err(src);
            assert_eq!(err.class(), "ArithmeticException", "{src}");
            assert_eq!(err.pos(), 0, "{src}");
        }
    }

    #[test]
    fn compile_fold_boundary_controls_still_accept() {
        // Oracle ACCEPT controls pinning what Scala does NOT compile-fold:
        // division (`1 / 0` compiles!), in-range folds, non-constant
        // operands, exactly-representable boundaries.
        for src in [
            "sigmaProp(1 / 0 == 0)",
            "sigmaProp((2147483647 + 0) < 0)",
            "sigmaProp((2147483646 + 1) < 0)",
            "sigmaProp((-9223372036854775807L - 1L) < 0L)", // exactly Long.MIN
            "sigmaProp((HEIGHT + 2147483647) > 0)",
            // min/max fold-through NON-overflow controls (oracle OK)
            "sigmaProp((min(1, 2) + 1) == 2)",
            "sigmaProp((max(1, 2) + 1) == 3)",
            // a non-constant min operand breaks the chain — no fold, no reject
            "sigmaProp((min(HEIGHT, 1) + 2147483647) > 0)",
            // Negation over a NON-literal folded constant stays unfolded on
            // both sides (probe-confirmed: oracle tree keeps the 0xF0 node)
            "sigmaProp((-(0 + 2147483647) - 2) < 0)",
        ] {
            ct(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        }
        // A cast of a NON-direct-constant subexpression is not folded even
        // when the subtree folds (oracle: `ccs sigmaProp((x * 100).toByte >
        // 0.toByte)` → OK, residual Downcast; x is the env constant 10).
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Int(10));
        compile(
            &env,
            "sigmaProp((x * 100).toByte > 0.toByte)",
            0,
            NetworkPrefix::Testnet,
        )
        .expect("cast of folded-but-not-direct constant stays unfolded — must accept");
    }

    #[test]
    fn compile_xorof_sigmaprop_coll_rejects_matching_oracle_verdict() {
        // Oracle: `cc xorOf(Coll(sigmaProp(true)))` → `REJECT 0:0
        // AssertionError` (GraphBuilding.scala:855-862 force-casts the input
        // to Coll[Boolean] and dies; see the emit XorOf arm). The class is
        // advisory — Java's AssertionError has no Rust analog — the REJECT
        // verdict is the parity fact.
        let err = ct("xorOf(Coll(sigmaProp(true)))").expect_err("must reject");
        assert!(matches!(&err, CompileError::Emit(_)), "{err:?}");
        // Boolean-element xorOf is untouched by the gate.
        ct("xorOf(Coll(true, false))").expect("boolean xorOf still compiles");
    }

    // ----- oracle parity -----

    #[test]
    fn compile_pk_bytes_and_addresses_match_oracle() {
        // The ONE byte-gated class at M3: a bare-constant root takes the
        // withoutSegregation branch on BOTH sides, so bytes AND both
        // addresses must match the oracle verbatim (capture provenance on
        // the ORACLE_PK_* consts above; testnet capture → testnet compile).
        let r = compile_testnet(
            &ScriptEnv::new(),
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
        )
        .expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), ORACLE_PK_TREE_HEX);
        assert_eq!(r.p2s_address, ORACLE_PK_P2S);
        assert_eq!(r.p2sh_address, ORACLE_PK_P2SH);
        // The oracle P2S reply doubles as the forced-P2S pin: Scala's
        // Pay2SAddress answers P2S even for a bare ProveDlog constant, and
        // matching it proves we did not route through encode_address (which
        // would detect_p2pk this exact body and emit a P2PK address).
        // Belt-and-braces: the raw prefix byte is testnet|P2S = 0x13.
        let raw = bs58::decode(&r.p2s_address).into_vec().unwrap();
        assert_eq!(raw[0], 0x13, "testnet P2S prefix, not P2PK (0x11)");
    }

    /// A second bare-const pin beyond the PK class — and the oracle
    /// authority for the SigmaTyperTest env's `g2 = 2·G` value (final
    /// whole-M3 review finding 1). The oracle constant-folds
    /// `proveDlog(g2)` into a bare `SigmaPropConstant` carrying the
    /// NORMALIZED compressed point, so its tree hex is a byte-level pin
    /// of the 2·G bytes the twin envs must bind.
    ///
    /// Oracle: `ccs proveDlog(g2)` →
    /// `OK 0008cd02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    ///  5AgXz2LADsxyCxEWvvHHpM9vKJsKbCwMjhXmVVrjH1dFtMgEupoAtSQd
    ///  rnwHaWHeaqaP7sCPFCF8VdN2Mxe72y4oLt8XKAt`
    /// (sigma-state 6.0.2, ORACLE_NETWORK=testnet, captured 2026-07-07).
    /// **M4 Task 3 flip:** the D-C2 fold now runs (`crate::lower`), so our
    /// `CreateProveDlog(Const)` collapses into the SAME bare
    /// `SigmaPropConstant` the oracle emits — full tree bytes AND both
    /// addresses now match, not just the 33-byte point inside the constant.
    #[test]
    fn compile_provedlog_two_g_point_bytes_match_oracle_fold() {
        let mut env = ScriptEnv::new();
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        env.insert(
            "g2",
            EnvValue::GroupElement(GroupElement::from_bytes(bytes)),
        );
        let r = compile_testnet(&env, "proveDlog(g2)").expect("compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "0008cd02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
        assert_eq!(
            r.p2s_address,
            "5AgXz2LADsxyCxEWvvHHpM9vKJsKbCwMjhXmVVrjH1dFtMgEupoAtSQd"
        );
        assert_eq!(r.p2sh_address, "rnwHaWHeaqaP7sCPFCF8VdN2Mxe72y4oLt8XKAt");
    }

    #[test]
    fn compile_sigmaprop_height_p2s_and_p2sh_match_oracle_after_segregation() {
        // Post-D-C1 (M4 Task 2): the oracle tree `100104c801d191a37300`
        // (header 0x10) and ours are now byte-identical, so the P2S address
        // MATCHES the oracle capture — the segregation-only gap is closed for
        // this shape-identical vector.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_eq!(r.p2s_address, ORACLE_HGT_P2S);
        // The P2SH address hashes the constant-INLINED proposition
        // (`d191a304c801`) — segregation-invariant, so it matched before AND
        // after the flip. Wherever Scala's IR reshapes the proposition itself,
        // the P2SH diverges (lib.rs D-C7; wave-3 address gate).
        assert_eq!(r.p2sh_address, ORACLE_HGT_P2SH);
    }

    // ----- oracle parity: Task-11 wave-2 lowerings/folds (lib.rs D-C6) -----
    // Every oracle fact below: TyperOracle cc/ccs verbs, sigma-state 6.0.2,
    // ORACLE_TREE_VERSION=3, ORACLE_NETWORK=testnet, captured 2026-07-07,
    // 3 identical runs (committed as compile_seed.json wave-2 vectors).
    // Our trees stay non-segregated (D-C1), so the ORACLE-comparable byte
    // surface is the P2SH address — it hashes the constant-inlined
    // PROPOSITION, which must be node-for-node identical after the fixes.

    #[test]
    fn compile_get_reg_literal_lowers_to_r5_bytes_and_oracle_p2sh() {
        // Oracle: `cc sigmaProp(SELF.getReg[Int](5).isDefined)` and
        // `cc sigmaProp(SELF.R5[Int].isDefined)` reply IDENTICALLY:
        // `1000d1e6c6a70504 2b6DJR5QoSgM31MUQ6 qzYN3szTjLnSbqXUA55vyCopdNpu88qJuPzmoks`.
        let get_reg = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.getReg[Int](5).isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        let r5 = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.R5[Int].isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(get_reg.tree_bytes, r5.tree_bytes);
        // Segregated header 0x10, zero-entry table (no literal constant in
        // this register-accessor body) — byte-identical to the oracle capture.
        assert_eq!(hex::encode(&get_reg.tree_bytes), "1000d1e6c6a70504");
        assert_eq!(
            get_reg.p2sh_address,
            "qzYN3szTjLnSbqXUA55vyCopdNpu88qJuPzmoks"
        );
        // Dynamic index keeps the MethodCall on BOTH sides (oracle:
        // `1000d1e6dc6313a701a304 … q1RuFk3PeKdvEbAb6dUZqVxYDZ5i8QdWg4DkK4Z`).
        let dynamic = compile(
            &ScriptEnv::new(),
            "sigmaProp(SELF.getReg[Int](HEIGHT).isDefined)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&dynamic.tree_bytes), "1000d1e6dc6313a701a304");
        assert_eq!(
            dynamic.p2sh_address,
            "q1RuFk3PeKdvEbAb6dUZqVxYDZ5i8QdWg4DkK4Z"
        );
    }

    #[test]
    fn compile_val_bound_get_reg_index_stays_residual_method_call() {
        // getReg dynamic→static lowering residual (MEMORY "getReg dynamic-index
        // plan"), pinned verdict-only (NOT a committed vector). M4 Task 9's `val`
        // inlining now DOES eliminate `val i` (`crate::inline`), so the index
        // becomes the inlined constant `4` — matching Scala's const-propagation
        // this far. What still diverges is the SECOND half: Scala lowers
        // `getReg[Int](4)` (a now-constant index) to the STATIC
        // `ExtractRegisterAs(Self, R4, Int)` (`cc { val i = 4;
        // sigmaProp(SELF.getReg[Int](i).isDefined) }` → `1000d1e6c6a70404`, zero
        // constants), whereas our emit fixed the getReg static-vs-dynamic shape
        // in the TYPED AST (where `i` was still a `ValUse`), so it stays a
        // dynamic `getReg` MethodCall with the inlined `4` as a
        // ConstPlaceholder. BOTH sides accept; the residual is the getReg
        // static lowering, no longer `val` inlining.
        let r = compile(
            &ScriptEnv::new(),
            "{ val i = 4; sigmaProp(SELF.getReg[Int](i).isDefined) }",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("both-accept residual must still compile");
        // Self-pin (NOT an oracle vector): header 0x10, one SInt(4) constant
        // slot, dynamic getReg MethodCall over ConstPlaceholder(0) — differs
        // from the oracle's static `1000d1e6c6a70404` on the getReg lowering
        // only. A regression guard on our own deterministic output.
        assert_eq!(hex::encode(&r.tree_bytes), "10010408d1e6dc6313a701730004");
    }

    #[test]
    fn compile_slice_explicit_type_arg_matches_unannotated_and_oracle_p2sh() {
        // Oracle: the annotated and un-annotated forms reply IDENTICALLY
        // (`ccs sigmaProp(arr1.slice[Byte](0, 1).size == 1)` =
        //  `ccs sigmaProp(arr1.slice(0, 1).size == 1)` →
        // `10040e020102040004020402d193b1b47300730173027303 …
        //  rgwBvuzJFRePZZ1FJp4qddZq8KXpjkdA5a8hfbJ`).
        let mut env = ScriptEnv::new();
        env.insert("arr1", EnvValue::ByteArray(vec![1, 2]));
        let annotated = compile(
            &env,
            "sigmaProp(arr1.slice[Byte](0, 1).size == 1)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        let plain = compile(
            &env,
            "sigmaProp(arr1.slice(0, 1).size == 1)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(annotated.tree_bytes, plain.tree_bytes);
        // Segregated, byte-identical to the oracle capture above.
        assert_eq!(
            hex::encode(&annotated.tree_bytes),
            "10040e020102040004020402d193b1b47300730173027303"
        );
        assert_eq!(
            annotated.p2sh_address,
            "rgwBvuzJFRePZZ1FJp4qddZq8KXpjkdA5a8hfbJ"
        );
    }

    #[test]
    fn compile_numeric_const_fold_matches_oracle_p2sh() {
        // Oracle: `ccs sigmaProp(x.toBytes.size == 4)` →
        // `10020e040000000a0408d193b173007301 … qApjfu2kT7Lr8bYG7c4UMKgYJSPD32SkbBDAQMD`
        // (x = 10; the folded big-endian Coll[Byte] constant), and
        // `ccs sigmaProp(x.toBits.size == 32)` →
        // `10020d20000000500440d193b173007301 … qse65TyiDnutjxRzCP1mnCttRKWZqPrhnsvG7cg`.
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Int(10));
        let bytes = compile(
            &env,
            "sigmaProp(x.toBytes.size == 4)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(
            hex::encode(&bytes.tree_bytes),
            "10020e040000000a0408d193b173007301"
        );
        assert_eq!(
            bytes.p2sh_address,
            "qApjfu2kT7Lr8bYG7c4UMKgYJSPD32SkbBDAQMD"
        );
        let bits = compile(
            &env,
            "sigmaProp(x.toBits.size == 32)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(
            hex::encode(&bits.tree_bytes),
            "10020d20000000500440d193b173007301"
        );
        assert_eq!(bits.p2sh_address, "qse65TyiDnutjxRzCP1mnCttRKWZqPrhnsvG7cg");
    }

    #[test]
    fn compile_bitwise_or_xor_fold_values_pinned() {
        // Value-distinguishing forms of the bitwise folds: the whole equality
        // folds to `sigmaProp(true)` ONLY if the folded byte VALUE is right
        // (`5 | 3 = 7`, `5 ^ 3 = 6`) — a wrong value would leave a residual
        // `Eq(<byte>, <byte>)` (or fold to `false`), so this pins the value.
        //
        // **M4 Task 5:** with the cast fold (Task 4: `5.toByte`, `3.toByte`,
        // `7.toByte`/`6.toByte` all fold to bare Byte constants) AND the
        // pre-existing bitwiseOr/Xor-of-constants fold feeding two equal Byte
        // constants into the `Eq`, the generic engine's `Const == Const →
        // true` closes it: byte-identical to the oracle (`10010101d17300`).
        // recon-targets vectors 84/85 graduate out of `DC7_P2SH_MISMATCH_SET`.
        let env = ScriptEnv::new();
        let cv3 = |src| compile(&env, src, 3, NetworkPrefix::Testnet);
        let or = cv3("sigmaProp((5.toByte.bitwiseOr(3.toByte)) == 7.toByte)").expect("compile");
        assert_eq!(hex::encode(&or.tree_bytes), "10010101d17300");
        let xor = cv3("sigmaProp((5.toByte.bitwiseXor(3.toByte)) == 6.toByte)").expect("compile");
        assert_eq!(hex::encode(&xor.tree_bytes), "10010101d17300");
    }

    #[test]
    fn compile_cast_chain_keeps_only_innermost_fold_matching_oracle_probe_34() {
        // The crux regression this task's fold-one-level/keep-chain
        // invariant exists to pin (M3 numerics N-3 probe 34,
        // adversarial-findings-numerics.md:137; now committed as an M4
        // Task 4 `cc` vector in `compile_probes.txt`/`compile_seed.json`,
        // re-verified via `compile_seed_live_recapture`): a literal cast
        // CHAIN folds ONLY the cast immediately adjacent to the literal —
        // `1.toByte` folds to a bare `Const(Byte, 1)`, but the two outer
        // `.toLong`/`.toBigInt` casts stay real `Upcast` nodes wrapping it,
        // exactly like Scala's `GraphBuilding.scala:514-518` (a
        // non-recursive structural match against the untouched AST child).
        // Byte-exact vs. the oracle capture — NOT a self-oracle: this is
        // the live-recaptured, committed `p2sh_address`
        // (`rnuja5Bnkuz4BzMETLRwybfPAo6VBt4eC4dP3CL`) too.
        let r = ct("sigmaProp(1.toByte.toLong.toBigInt > 0.toBigInt)").expect("compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "10020201060100d1917e7e730005067301"
        );
        assert_eq!(r.p2sh_address, "rnuja5Bnkuz4BzMETLRwybfPAo6VBt4eC4dP3CL");
        // Structural pin, same invariant from the AST side: exactly TWO
        // real `Upcast` (0x7E) nodes remain over a folded `Const(Byte, 1)`
        // — a cascade-fold bug would collapse both into a single
        // `Const(BigInt, 1)` and this match would fail to find any cast
        // node at all. Inspected on the PRE-segregation tree (`emit` +
        // `fold_direct_const_casts` directly): `r.ergo_tree.body` has
        // already been segregated into a `ConstPlaceholder`, which would
        // hide the very shape this test pins.
        let folded = folded_root("sigmaProp(1.toByte.toLong.toBigInt > 0.toBigInt)");
        let Expr::Op(IrNode {
            opcode: 0xD1,
            payload: Payload::One(gt),
        }) = &folded
        else {
            panic!("root must be BoolToSigmaProp: {folded:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x91,
            payload: Payload::Two(lhs, _rhs),
        }) = gt.as_ref()
        else {
            panic!("expected GT: {gt:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x7E,
            payload: Payload::NumericCast { input: inner1, .. },
        }) = lhs.as_ref()
        else {
            panic!("expected outer Upcast (toBigInt): {lhs:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x7E,
            payload: Payload::NumericCast { input: inner2, .. },
        }) = inner1.as_ref()
        else {
            panic!("expected middle Upcast (toLong): {inner1:?}");
        };
        assert!(
            matches!(
                inner2.as_ref(),
                Expr::Const {
                    tpe: SigmaType::SByte,
                    val: SigmaValue::Byte(1),
                }
            ),
            "innermost cast must have folded to a bare Const(Byte, 1): {inner2:?}"
        );
    }

    #[test]
    fn compile_cast_chain_depth_three_nested_under_gt_keeps_all_outer_casts() {
        // Generalizes the probe-34 invariant one nesting level deeper
        // (`1.toByte.toShort.toLong.toBigInt`, 4 casts total): the
        // anti-cascade rule Scala's structural match implements
        // (GraphBuilding.scala:514-518, depth-independent by construction —
        // it only ever inspects ONE node's immediate, untouched child) must
        // leave THREE real `Upcast` nodes over the folded innermost
        // constant, not just the two probe-34 pins. This is a
        // self-consistency shape check on OUR OWN non-cascading discipline
        // (not an independent oracle round-trip — the underlying rule is
        // already oracle-verified at depth 2 above; this extends it
        // structurally to depth 3, which the fold's node-local recursion
        // makes mechanically identical).
        let r = ct("sigmaProp(1.toByte.toShort.toLong.toBigInt > 0.toBigInt)").expect("compile");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "10020201060100d1917e7e7e73000305067301"
        );
        fn cast_depth_over_byte_const(e: &Expr) -> usize {
            match e {
                Expr::Op(IrNode {
                    opcode: 0x7E,
                    payload: Payload::NumericCast { input, .. },
                }) => 1 + cast_depth_over_byte_const(input),
                Expr::Const {
                    tpe: SigmaType::SByte,
                    val: SigmaValue::Byte(1),
                } => 0,
                other => panic!("expected an Upcast chain over Const(Byte, 1): {other:?}"),
            }
        }
        // Inspected on the PRE-segregation tree — see `folded_root`'s docs.
        let folded = folded_root("sigmaProp(1.toByte.toShort.toLong.toBigInt > 0.toBigInt)");
        let Expr::Op(IrNode {
            opcode: 0xD1,
            payload: Payload::One(gt),
        }) = &folded
        else {
            panic!("root must be BoolToSigmaProp: {folded:?}");
        };
        let Expr::Op(IrNode {
            opcode: 0x91,
            payload: Payload::Two(lhs, _rhs),
        }) = gt.as_ref()
        else {
            panic!("expected GT: {gt:?}");
        };
        assert_eq!(
            cast_depth_over_byte_const(lhs),
            3,
            "depth-3 chain must keep exactly 3 real Upcast nodes, not cascade-fold"
        );
    }

    #[test]
    fn compile_sizeof_coll_literal_folds_to_clean_v0_bytes() {
        // F-3 (adversarial-findings-constants.md): before wave 2 the empty
        // `Coll[UnsignedBigInt]()` literal put v3-only TYPE code 9 on the v0
        // wire — bytes our own read_ergo_tree refuses (a stranded-funds
        // P2S). The SizeOf fold keeps it off the wire, matching Scala's
        // GraphBuilding fold (oracle: `.size == 0` → the fully-folded
        // `10010101d17300`; `.size.toLong == SELF.value` →
        // `10010400d1937e730005c1a7 … pvyEFnLjY1hb7ebaccofdS88Z9v1WwKxUzUB4y9`
        // — the `.size` folds to Int 0 even when the surrounding expression
        // cannot fold).
        let r = compile(
            &ScriptEnv::new(),
            "sigmaProp(Coll[UnsignedBigInt]().size == 0)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        // M4 Task 5: the generic const fold now folds `.size` → Int 0 AND the
        // enclosing `0 == 0` → `sigmaProp(true)`, byte-identical to the oracle
        // (`10010101d17300`) — recon-targets vector 77 graduates (NF-1 closure:
        // the SizeOf fold erases the empty `Coll[UnsignedBigInt]()` BEFORE the
        // v0-data gate, so the F-3 stranded-funds invariant holds too).
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
        let r = compile(
            &ScriptEnv::new(),
            "sigmaProp(Coll[UnsignedBigInt]().size.toLong == SELF.value)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        // Shape-identical to the oracle here (the `.size` fold matches Scala,
        // the surrounding expression is un-foldable on BOTH sides) — so our
        // segregated bytes are byte-identical to the oracle capture.
        assert_eq!(hex::encode(&r.tree_bytes), "10010400d1937e730005c1a7");
        assert_eq!(r.p2sh_address, "pvyEFnLjY1hb7ebaccofdS88Z9v1WwKxUzUB4y9");
        // The `.size` fold covers NON-constant elements too (a `Coll(HEIGHT)`
        // literal folds to Int 1 regardless of item constancy); M4 Task 5's
        // `Const == Const → true` then closes the equality, byte-identical to
        // the oracle (`10010101d17300`) — recon-targets vector 79 graduates.
        let r = ct("sigmaProp(Coll(HEIGHT).size == 1)").expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
        // Discarded elements are still verdict-checked: children fold BEFORE a
        // parent's SizeOf, so the overflow in the dropped item still rejects
        // (oracle rejects this too).
        let err = ct("sigmaProp(Coll(2147483647 + 1).size == 1)").expect_err("overflow");
        assert_eq!(err.class(), "ArithmeticException");
    }

    #[test]
    fn compile_v6_embeddable_type_code_under_v0_header_accepts_at_tv3_matching_oracle() {
        // F1 (m5-adversarial-findings-CAPTURED.md): the post-write self-check
        // (D-C6) re-reads compile()'s own bytes and refuses to derive an address
        // for a script no deserializer accepts. It USED to gate V6-embeddable
        // TYPE codes (`SUnsignedBigInt` = code 9, …) on the emitted HEADER version
        // (always 0), and so wrongly rejected a header-v0 tree carrying code 9 —
        // which a `tree_version >= 3` (V6-activated) compile legitimately produces
        // and which Scala re-parses fine. Scala gates the embeddable set on the
        // ACTIVATED version (`TypeSerializer.getEmbeddableType` →
        // `VersionContext.isV6Activated`, `VersionContext.scala:33`; deser under
        // `withVersions(activatedVersion, treeVersion)`,
        // `ErgoTreeSerializer.scala:148-154`), NOT the tree header. The self-check
        // now reads via `read_ergo_tree_with_activated_version(tree_version)` and
        // ACCEPTS these at tv=3, byte-identical to the oracle (verified live vs
        // sigma-state 6.0.2, ORACLE_TREE_VERSION=3, 2026-07-07). The earlier
        // "poisoned type code / strands funds" premise was FALSE — the wrong-axis
        // header-version gate was the only thing rejecting them.
        //
        // All 7 captured blast-radius shapes (bare + val-bound; every target
        // type + Coll/tuple/Option container) accept byte-exact at tv=3:
        for (src, want) in [
            (
                "sigmaProp(SELF.R4[UnsignedBigInt].isDefined)",
                "1000d1e6c6a70409",
            ),
            (
                "sigmaProp(getVar[UnsignedBigInt](1).isDefined)",
                "1000d1e6e30109",
            ),
            (
                "sigmaProp(SELF.R4[Coll[UnsignedBigInt]].isDefined)",
                "1000d1e6c6a70415",
            ),
            (
                "sigmaProp(SELF.R4[(UnsignedBigInt,Int)].isDefined)",
                "1000d1e6c6a7044504",
            ),
            (
                "sigmaProp(SELF.R4[Option[UnsignedBigInt]].isDefined)",
                "1000d1e6c6a7042d",
            ),
            (
                "sigmaProp(getVar[Coll[UnsignedBigInt]](1).isDefined)",
                "1000d1e6e30115",
            ),
            (
                "sigmaProp(SELF.R4[(Int,UnsignedBigInt)].isDefined)",
                "1000d1e6c6a7044009",
            ),
        ] {
            let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)
                .unwrap_or_else(|e| panic!("{src}: self-check must accept at tv=3: {e:?}"));
            assert_eq!(hex::encode(&r.tree_bytes), want, "{src}");
            // The accepted bytes must round-trip through the SAME activated-version
            // reader (defends the self-check's own invariant).
            assert_eq!(reparse_v6(&r.tree_bytes), r.ergo_tree, "{src}");
        }

        // At tree_version 0 these shapes reject at the PARSER on BOTH sides —
        // `UnsignedBigInt` is not a known type name under v5 (oracle:
        // `REJECT <pos> ParserException`; parity holds, the self-check axis is
        // never reached). Class-exact.
        for src in [
            "sigmaProp(SELF.R4[UnsignedBigInt].isDefined)",
            "sigmaProp(getVar[UnsignedBigInt](1).isDefined)",
            "sigmaProp(SELF.R4[Coll[UnsignedBigInt]].isDefined)",
        ] {
            let err = compile(&ScriptEnv::new(), src, 0, NetworkPrefix::Testnet)
                .expect_err("v6 type name must reject at tv=0");
            assert_eq!(err.class(), "ParserException", "{src}");
        }

        // Sibling GRADUATION (M4 Task 9, unchanged by F1): a VAL-BOUND
        // `Coll[UnsignedBigInt]()` under `.size` folds the UBI data OFF the wire
        // before the self-check ever sees a code-9 type, so it stays byte- and
        // address-identical to the oracle (`10010400d1937e730005c1a7`).
        let r = compile(
            &ScriptEnv::new(),
            "{ val u = Coll[UnsignedBigInt](); sigmaProp(u.size.toLong == SELF.value) }",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("val-inline + SizeOf fold erases the UBI data before the v0 gate");
        assert_eq!(hex::encode(&r.tree_bytes), "10010400d1937e730005c1a7");
    }

    #[test]
    fn compile_bare_from_big_endian_bytes_rejects_below_tv3_matching_oracle() {
        // F2 (m5-adversarial-findings-CAPTURED.md) — accept-invalid, SEVERE:
        // the BARE `fromBigEndianBytes[T]` predef (typer/predef_ir
        // `global_deserialize`) builds `MethodCall(Global, m)` DIRECTLY, bypassing
        // the version-scoped SGlobal method table the dotted `Global.<m>` form
        // resolves against. Scala exposes `fromBigEndianBytes` on `SGlobal` ONLY at
        // `isV3OrLaterErgoTreeVersion` (`SGlobalMethods.getMethods`,
        // methods.scala:2001-2021, pinned v6.0.2 — the v5 SGlobal set is just
        // {groupGenerator, xor}); GraphBuilding throws `GraphBuildingException` on
        // the residual MethodCall under v5 activation. Before F2 we emitted a
        // SPENDABLE address at tv 0/1/2. Now the emit-time GraphBuilding-parity
        // gate rejects it — class-exact vs the oracle (ORACLE_TREE_VERSION=0/1/2:
        // `REJECT 0:0 GraphBuildingException`); at tv=3 both accept, byte-identical.
        let src = "sigmaProp(fromBigEndianBytes[Int](Coll[Byte](0.toByte)) > 0)";
        for tv in [0u8, 1, 2] {
            let err = compile(&ScriptEnv::new(), src, tv, NetworkPrefix::Testnet)
                .expect_err(&format!("tv={tv}: bare fromBigEndianBytes must reject"));
            assert!(matches!(&err, CompileError::Emit(_)), "tv={tv}: {err:?}");
            assert_eq!(err.class(), "GraphBuildingException", "tv={tv}");
        }
        // tv=3: accepts, byte-identical to the oracle capture.
        let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet)
            .expect("bare fromBigEndianBytes accepts at tv=3");
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "100202000400d191dc6a05dd018301027300047301"
        );
        // The dotted `Global.fromBigEndianBytes` form stays typer-rejected at
        // tv<3 (method not in the v5 SGlobal table) — the leak was bare-only.
        let dotted = compile(
            &ScriptEnv::new(),
            "sigmaProp(Global.fromBigEndianBytes[Int](Coll[Byte](0.toByte)) > 0)",
            0,
            NetworkPrefix::Testnet,
        )
        .expect_err("dotted form must reject at tv=0");
        assert!(matches!(&dotted, CompileError::Type(_)), "{dotted:?}");
    }

    #[test]
    fn compile_prove_dlog_generator_folds_to_bare_const_matching_pk_oracle() {
        // Oracle capture, line 3: `cce proveDlog(g1)` → the SAME reply as
        // the PK line (tree `0008cd0279be...`, both addresses identical):
        // Scala's IR pipeline constant-folds CreateProveDlog(const) →
        // SigmaPropConstant at the GraphBuilding stage (task-1-report.md
        // Concern 1; g1 = the generator = the PK test key).
        //
        // **M4 Task 3 flip:** `crate::lower`'s D-C2 fold now runs BEFORE
        // `build_tree`, so our `CreateProveDlog(Const)` folds to the SAME
        // bare `SigmaPropConstant` the oracle emits — the root is bare, so
        // it takes `withoutSegregation` (header `0x00`, empty constants
        // table) exactly like the PK vector, and every byte/address matches
        // the oracle verbatim (D-C2 CLOSED).
        let r = compile_testnet(&generator_env(), "proveDlog(g1)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00, "folded bare root, no segregation");
        assert!(r.ergo_tree.constants.is_empty());
        assert!(matches!(
            &r.ergo_tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_)),
            }
        ));
        assert_eq!(hex::encode(&r.tree_bytes), ORACLE_PK_TREE_HEX);
        assert_eq!(r.p2s_address, ORACLE_PK_P2S);
        assert_eq!(r.p2sh_address, ORACLE_PK_P2SH);
    }

    #[test]
    fn compile_isproven_bool_and_reconstructs_binand_matching_oracle() {
        // M4 Task 6 (D-C3): `sigmaProp(true) && (1 == 1)` — the SigmaProp
        // operand's `.isProven` fuses (`SigmaPropIsProven(BoolToSigmaProp(true))
        // → true`) BEFORE the fold, exposing `BinAnd(true, EQ(1,1))`. The fold
        // reduces `EQ(1,1) → true` but keeps `BinAnd` (lazy, never const-folded),
        // and the Boolean root re-wraps in `BoolToSigmaProp` — byte-identical to
        // the oracle `BoolToSigmaProp(BinAnd(true, true))` (`1000d1ed8503`; the
        // `85` bool-pair compaction extracts ZERO constants, header `0x10`/`00`).
        for src in ["sigmaProp(true) && (1 == 1)", "(1 == 1) && sigmaProp(true)"] {
            let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).expect(src);
            assert_eq!(hex::encode(&r.tree_bytes), "1000d1ed8503", "{src}");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "{src}");
        }
    }

    #[test]
    fn compile_isproven_bool_xor_folds_to_false_matching_oracle() {
        // M4 Task 6 (D-C3): `sigmaProp(true) ^ (1 == 1)` — same isProven fusion
        // exposes `BinXor(true, EQ(1,1))`; unlike BinAnd, BinXor IS eagerly
        // const-folded (`true ^ true → false`), so the whole XOR collapses to a
        // `false` constant. Segregation extracts it into the constants table
        // (`0100` = SBoolean/false) with a placeholder body — byte-identical to
        // the oracle `BoolToSigmaProp(placeholder0=false)` (`10010100d17300`).
        for src in ["sigmaProp(true) ^ (1 == 1)", "(1 == 1) ^ sigmaProp(true)"] {
            let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).expect(src);
            assert_eq!(hex::encode(&r.tree_bytes), "10010100d17300", "{src}");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "{src}");
        }
    }

    #[test]
    fn compile_allof_singleton_provedlog_strips_isproven_to_bare_const() {
        // M4 Task 6 (D-C3): `allOf(Coll(proveDlog(g1)))` — the lowering block
        // (D-C2 `CreateProveDlog(const)` fold + single-element `AllOf` unwrap)
        // exposes `BoolToSigmaProp(SigmaPropIsProven(Const{SigmaProp}))`, which
        // the post-lower top-level `removeIsProven` strips to the bare
        // `SigmaPropConstant` root. Bare root → `withoutSegregation` (header
        // `0x00`), byte-identical to the oracle `0008cd0279be…` — the SAME tree
        // as `proveDlog(g1)`/PK.
        let r = compile(
            &generator_env(),
            "allOf(Coll(proveDlog(g1)))",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00, "bare root, no segregation");
        assert!(matches!(
            &r.ergo_tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_)),
            }
        ));
        assert_eq!(
            hex::encode(&r.tree_bytes),
            "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
    }

    #[test]
    fn compile_bare_singleton_lowering_matches_oracle_property_call() {
        // M4 Task 8 (recon-transforms.md §9, D-C7 singleton bullet, vector
        // 30): bare `LastBlockUtxoRootHash` and bare `groupGenerator` are NOT
        // `IsContextProperty` primitives on the Scala side — both re-emit as
        // `PropertyCall`s. Oracle-confirmed 2026-07-07, `ORACLE_TREE_VERSION=3`:
        for (src, oracle_hex) in [
            (
                "sigmaProp(LastBlockUtxoRootHash.digest.size > 0)",
                "10010400d191b1db6401db6509fe7300",
            ),
            (
                "sigmaProp(groupGenerator.getEncoded.size > 0)",
                "10010400d191b1db0702db6a01dd7300",
            ),
        ] {
            let r = compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).expect(src);
            assert_eq!(hex::encode(&r.tree_bytes), oracle_hex, "{src}");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "{src}");
        }
    }

    #[test]
    fn compile_deserialize_constant_matches_oracle() {
        // M4 Task 8 (gap F6, D-T2 CLOSED): `deserialize[Int]("Jq")` decodes
        // (Base58) to bytes `04 0a` — `IntConstant(5)` — and folds through the
        // generic constant fold (`5 == 5` → `true`) exactly like the oracle.
        // Oracle-confirmed 2026-07-07: `sigmaProp(deserialize[Int]("Jq") == 5)`
        // → `10010101d17300`.
        let r = compile(
            &ScriptEnv::new(),
            "sigmaProp(deserialize[Int](\"Jq\") == 5)",
            3,
            NetworkPrefix::Testnet,
        )
        .expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), "10010101d17300");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
    }
}
