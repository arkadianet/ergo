use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::opcode::{self, Body};
use crate::sigma_type::SigmaType;
use crate::sigma_value::{read_constant, write_constant, SigmaValue};

const VERSION_MASK: u8 = 0x07;
const SIZE_FLAG: u8 = 0x08;
const CONSTANT_SEGREGATION_FLAG: u8 = 0x10;

/// Soft `Vec::with_capacity` cap for an ErgoTree's segregated-constant list.
/// `parse_body` reads the count via `get_u32_exact`, which only bounds it to
/// i32::MAX — so a hostile tree header claiming `count = i32::MAX` would
/// otherwise reserve multiple GiB before the first constant is read. The Vec
/// still grows on `push`, so a legitimate tree with more constants than this
/// parses unchanged; the cap only bounds the *initial* reservation. It is a
/// soft cap (not the hard reject `skip_ergo_tree` applies to inner,
/// box-size-bounded trees) because `parse_body` is the top-level consensus
/// parse and must not reject a tree the Scala node would accept.
const CONSTANTS_VEC_SOFT_CAP: usize = 4096;

/// Scala `SigmaSerializer.MaxPropositionSize` (`SigmaConstants.MaxPropositionBytes`
/// = 4096). `deserializeErgoTree` bounds the body parse by this position limit —
/// NOT by the tree's declared size, which it uses only for the `UnparsedErgoTree`
/// byte count. So the body is structure-delimited up to this cap.
const MAX_PROPOSITION_BYTES: usize = 4096;

/// Parsed ErgoTree: header byte + optional constants table + parsed
/// body expression.
///
/// The `version` / `has_size` / `constant_segregation` triple is the
/// decomposition of the on-wire header byte:
/// `header = (version & 0x07) | (has_size ? 0x08 : 0) | (cseg ? 0x10 : 0)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ErgoTree {
    /// ErgoTree layout version (low 3 bits of the header byte).
    pub version: u8,
    /// `true` when the header carries a VLQ-`u32` size field that
    /// length-prefixes the body — required for the soft-fork-friendly
    /// path that lets unknown bodies round-trip verbatim.
    pub has_size: bool,
    /// `true` when constants are pulled out into a separate table
    /// referenced by `ConstPlaceholder` opcodes inside the body.
    pub constant_segregation: bool,
    /// Constants table — only populated when `constant_segregation` is set.
    pub constants: Vec<(SigmaType, SigmaValue)>,
    /// Root body expression.
    pub body: Body,
}

/// Serialize an ErgoTree to bytes.
pub fn write_ergo_tree(w: &mut VlqWriter, tree: &ErgoTree) -> Result<(), WriteError> {
    // A soft-fork-wrapped (unparsed) tree re-emits its preserved original bytes
    // verbatim — header + size + body, byte-identical to the wire form — exactly
    // as Scala re-serializes an `UnparsedErgoTree` from its kept `propositionBytes`.
    if let crate::opcode::Expr::Unparsed(raw) = &tree.body {
        w.put_bytes(raw);
        return Ok(());
    }
    let header = (tree.version & VERSION_MASK)
        | if tree.has_size { SIZE_FLAG } else { 0 }
        | if tree.constant_segregation {
            CONSTANT_SEGREGATION_FLAG
        } else {
            0
        };
    w.put_u8(header);

    if tree.has_size {
        let mut inner = VlqWriter::new();
        write_ergo_tree_body(&mut inner, tree)?;
        let inner_bytes = inner.result();
        w.put_u32(inner_bytes.len() as u32);
        w.put_bytes(&inner_bytes);
    } else {
        write_ergo_tree_body(w, tree)?;
    }
    Ok(())
}

fn write_ergo_tree_body(w: &mut VlqWriter, tree: &ErgoTree) -> Result<(), WriteError> {
    if tree.constant_segregation {
        w.put_u32(tree.constants.len() as u32);
        for (tpe, val) in &tree.constants {
            write_constant(w, tpe, val)?;
        }
    }
    opcode::write_body(w, &tree.body, tree.constant_segregation)?;
    Ok(())
}

/// Deserialize an ErgoTree from bytes.
///
/// For size-delimited trees, exactly `size` bytes are consumed after the size
/// field. For non-size-delimited trees, all remaining bytes in the reader are
/// consumed (the caller must provide exact bounds).
/// Maximum ErgoTree version we can fully parse and evaluate.
/// Trees with higher versions are accepted without body parsing (soft-fork).
/// Matches Scala's VersionContext.MaxSupportedScriptVersion = 3.
const MAX_SUPPORTED_TREE_VERSION: u8 = 3;

/// Scala `CheckHeaderSizeBit` (validation rule 1012, in `deserializeErgoTree`
/// via `deserializeHeaderAndSize`): a non-zero ErgoTree version REQUIRES the
/// size bit, so an old node can skip an unknown-version tree by its declared
/// byte length. A `version != 0` tree with the size bit clear is rejected with a
/// hard `SerializerException`. Version-0 trees legitimately carry no size bit.
///
/// [`read_ergo_tree`] is intentionally LENIENT about this (the SANTA conformance
/// hook feeds it size-stripped trees, and higher-version soft-fork trees parse
/// opaquely), so the consensus box-script readers enforce the rule AFTER parsing
/// — boxes are the consensus-reachable deserialization path for ErgoTrees.
pub fn check_header_size_bit(tree: &ErgoTree) -> Result<(), ReadError> {
    if tree.version != 0 && !tree.has_size {
        return Err(ReadError::InvalidData(format!(
            "ErgoTree version {} requires the size bit (CheckHeaderSizeBit, rule 1012)",
            tree.version
        )));
    }
    Ok(())
}

/// Reject a tree whose header version exceeds the maximum this node supports
/// (= the network's activated script version). Scala's `deserializeErgoTree`
/// wraps the parse in `VersionContext.withVersions(activatedScriptVersion,
/// treeVersion)`, whose `require(treeVersion <= activatedVersion)` throws an
/// `IllegalArgumentException` that is re-thrown as a `SerializerException`
/// ("Tree version (N) is above activated script version") — NOT a
/// `ValidationException`, so it is never soft-fork-wrapped and the box is
/// hard-rejected at creation (`ErgoTreeSerializer.scala` deserializeErgoTree
/// inner catch; confirmed against the 6.0.2 oracle: a v4/v5/v7 tree throws even
/// with the size bit set).
///
/// As with [`check_header_size_bit`], [`read_ergo_tree`] stays lenient (it wraps
/// a future-version tree so the conformance hook and template-hash paths keep
/// working); this box-script gate supplies the hard rejection at the consensus
/// box-parse layer. Uses [`ReadError::HardReject`] so a nested `SBox`-constant
/// inner tree with a future version also escapes the enclosing tree's soft-fork
/// wrap. `MAX_SUPPORTED_TREE_VERSION` equals the activated script version this
/// node is built for; a future activation is a node upgrade that raises it.
///
/// We gate on the static max rather than the per-block `activatedScriptVersion`
/// (matching the static `check_resolvable_methods` gate). The only case the two
/// disagree is re-validating a historical block at a height where activated was
/// below 3 with a higher-version tree — unreachable, since a tree of version N
/// cannot be created until version N is activated, so no such tree exists in
/// real pre-activation history.
pub fn check_tree_version_supported(tree: &ErgoTree) -> Result<(), ReadError> {
    if tree.version > MAX_SUPPORTED_TREE_VERSION {
        return Err(ReadError::HardReject(format!(
            "ErgoTree version {} exceeds the maximum supported version {} (above activated script version)",
            tree.version, MAX_SUPPORTED_TREE_VERSION
        )));
    }
    Ok(())
}

/// Reject a method a sizeless ErgoTree's registry cannot resolve
/// ([`crate::opcode::find_unresolved_v5_method`]) at DESERIALIZE. Scala resolves
/// methods against the tree-header version (`MethodsContainer._methodsMap`,
/// methods.scala); an id absent from `_v5MethodsMap` makes
/// `MethodCallSerializer.parse` throw a `ValidationException`. This covers both a
/// v6/EIP-50-only id ([`crate::opcode::is_v3_only_method`]) AND a genuinely
/// unknown/future `(type_id, method_id)` pair — the latter would otherwise be
/// accept-invalid (the node parses any id as a generic `MethodCall`).
///
/// **Gated on the SIZELESS case only.** When the size bit is set,
/// `ErgoTreeSerializer.deserializeErgoTree` CATCHES that `ValidationException`
/// and wraps the tree as `UnparsedErgoTree` (stored verbatim; the size-delimited
/// wrap path handles it); only WITHOUT the size bit is it re-raised as a hard
/// `SerializerException` that rejects the box at parse
/// (`ErgoTreeSerializer.scala:196-209`). Gating a size-flagged tree here would be
/// reject-valid. Since rule 1012 already rejects a sizeless `version != 0` tree,
/// the reachable case is a sizeless v0 tree, which resolves against the v5
/// registry — hence [`find_unresolved_v5_method`](crate::opcode::find_unresolved_v5_method).
///
/// Enforced at the box-script readers (alongside [`check_header_size_bit`]):
/// `read_ergo_tree` stays lenient, so an OUTPUT box storing such a tree —
/// never spent, so the evaluator gate never fires — is still rejected at the
/// creating transaction's parse, matching Scala's eager box-deserialize reject.
pub fn check_resolvable_methods(tree: &ErgoTree) -> Result<(), ReadError> {
    if !tree.has_size && tree.version < 3 {
        if let Some((type_id, method_id)) = crate::opcode::find_unresolved_v5_method(&tree.body) {
            return Err(ReadError::InvalidData(format!(
                "method ({type_id}, {method_id}) does not resolve in the v5 registry for tree version {} (method-resolution ValidationException at deserialize)",
                tree.version
            )));
        }
    }
    Ok(())
}

/// Reject a SIZELESS ErgoTree whose determinable root type is not `SSigmaProp`
/// (Scala `CheckDeserializedScriptIsSigmaProp`, validation rule 1001, in
/// `deserializeErgoTree` right after the body parse). A non-SigmaProp root raises
/// a `ValidationException`; WITHOUT a size bit there is no declared-size region to
/// preserve, so `deserializeErgoTree` cannot wrap it as an `UnparsedErgoTree` and
/// re-raises it as a hard `SerializerException` (the `sizeOpt == None` arm,
/// `ErgoTreeSerializer.scala:204-208`).
///
/// **Gated on the SIZELESS case only**, exactly like [`check_resolvable_methods`]:
/// when the size bit is set, [`read_ergo_tree`] already wraps a non-SigmaProp root
/// as `UnparsedErgoTree` during the parse (Scala's `sizeOpt == Some` arm), so the
/// wrapped tree's body is `Unparsed` and [`determinable_root_type`] returns `None`
/// here. The reachable case is therefore a sizeless v0 tree (rule 1012 already
/// hard-rejects a sizeless `version != 0` tree). Our untyped IR can only judge a
/// determinable root — an inline `Const` or a `ConstPlaceholder` resolving to its
/// segregated constant's type; a bare Boolean/Int root (e.g. `000173`) is the
/// reachable accept-invalid case. An `Op` root has no typechecker and would fail
/// at evaluation instead.
///
/// Enforced at the box-script readers (alongside [`check_header_size_bit`]) — the
/// node's lenient codec accepts a box storing such a tree, never spends it (so the
/// evaluator never re-checks), and would forward a block every Scala node rejects.
pub fn check_sigma_prop_root(tree: &ErgoTree) -> Result<(), ReadError> {
    if !tree.has_size {
        if let Some(tpe) = determinable_root_type(tree) {
            if tpe != crate::sigma_type::SigmaType::SSigmaProp {
                return Err(ReadError::InvalidData(format!(
                    "sizeless ErgoTree root has type {tpe:?}, expected SigmaProp \
                     (CheckDeserializedScriptIsSigmaProp, rule 1001)"
                )));
            }
        }
    }
    Ok(())
}

/// The deserialized root's static type WHEN it is trivially determinable from
/// the parsed IR: an inline `Const` carries its own type, a `ConstPlaceholder`
/// resolves to its segregated constant's type (Scala
/// `ConstantPlaceholderSerializer.parse` gives the placeholder the constant's
/// `tpe`), and the boolean-literal leaves `TrueLeaf`/`FalseLeaf` are
/// unconditionally `SBoolean`. Scala's `CheckDeserializedScriptIsSigmaProp`
/// rejects (→ soft-fork wrap under `has_size`, hard reject when sizeless) any
/// root whose type is not `SSigmaProp`. For every other `Op` root shape we have
/// no typechecker and accept — a genuinely non-sigma operator root would fail
/// later at evaluation. Returns `None` when the root type is not statically
/// known here (including an out-of-range placeholder index, which we leave to
/// the existing lenient handling).
fn determinable_root_type(tree: &ErgoTree) -> Option<crate::sigma_type::SigmaType> {
    determinable_root_type_of(&tree.body, &tree.constants)
}

/// [`determinable_root_type`] over a raw `(body, constants)` pair — so the nested
/// `SBox`-constant inner-script path (which parses a body + constants without
/// building an [`ErgoTree`]) can run the same rule-1001 root-type judgement.
/// Entry point: the root is typed in an empty binding environment. `Some(SSigmaProp)`
/// accepts, `Some(other)` is the wrap/reject verdict, and `None` is lenient (the
/// root type is not statically determinable). Public so the `difftest --methodcall`
/// harness can diff this exact verdict against the JVM reference.
pub fn determinable_root_type_of(
    body: &crate::opcode::Expr,
    constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
) -> Option<crate::sigma_type::SigmaType> {
    let scan = scan_tree(body, constants);
    infer_type(
        body,
        &[],
        &InferCtx {
            constants,
            scan: &scan,
        },
    )
}

/// The set of binding ids (`ValDef` / `FunDef` / `FuncValue` arg) that occur more
/// than once anywhere in the tree. Walks EVERY child (not just the type-
/// determining spine) so a rebinding buried in an off-spine subtree is recorded.
///
/// Scala's `ValUse.tpe` is read from a FLAT, never-popped, last-write-wins
/// `valDefTypeStore` keyed by id, SHARED across the whole reader. Two things make
/// our post-parse lexical [`infer_type`] env disagree with it, and [`scan_tree`]
/// detects both so a `ValUse` can fall back to `None` (lenient) rather than trust a
/// stale type and REJECT a tree Scala accepts (a reject-valid):
///
///  - REUSED binding ids ([`BindingScan::dup_ids`]). A `ValUse` of a reused id is
///    resolved to `None` (lenient). Matching Scala here would require its exact
///    POSITION-AWARE store evolution: the value of a reused id depends on how many
///    of its rebinds have been parsed at the point of the `ValUse`, and a rebind can
///    sit in an off-spine subtree our type recursion never visits. Every cheaper
///    approximation we tried (trust the lexical env / the whole-tree last write)
///    reject-valid'd a real Scala-accepted shape — e.g.
///    `{ val x = sigmaProp; val y = x; val x = 0L; y }`, where Scala fixes `y` to
///    SigmaProp BEFORE the rebind. Since a reused binding id NEVER occurs in a
///    legitimately compiled tree, we take the safe direction (lenient) and accept a
///    residual ACCEPT-invalid on adversarial duplicate-id trees whose root type is
///    statically determinable (e.g. `{ val x = 0L; val x = 0L; x }`, which Scala
///    rejects). The leniency is scoped to a `ValUse` of the reused id, so a
///    duplicate-id tree whose ROOT is independent of it (e.g. a Boolean block
///    result) is still classified and rule-1001-rejected.
///  - A constant that MATERIALIZES a box value ([`BindingScan::has_box_const`], by
///    [`value_contains_box`] — value, not type, so an empty `Coll[SBox]` does not
///    count). Scala parses a box's NESTED ErgoTree on the SAME reader, whose
///    `valDefTypeStore` is shared and NOT restored
///    (`ErgoTreeSerializer.deserializeErgoTree` saves `constantStore`/
///    `wasDeserialize` but not `valDefTypeStore`); so the inner script's `ValDef`s
///    — invisible to our body walk — can rebind an id the outer body uses. With a
///    box value present we therefore trust no `ValUse`.
///
/// Legitimate Scala-produced trees reuse no id and rarely embed box constants, so
/// for them `dup_ids` is empty and `has_box_const` is false.
struct BindingScan {
    dup_ids: std::collections::HashSet<u32>,
    has_box_const: bool,
}

/// `true` if `val` MATERIALIZES at least one box value (possibly nested in a
/// collection / option / tuple). A box value is the only constant whose bytes embed
/// a nested ErgoTree, which Scala parses on the shared reader — so only an actual
/// box can pollute `valDefTypeStore`. We key on the VALUE, not the type: an empty
/// `Coll[SBox]` has a box-bearing type but materializes no box and changes nothing,
/// so it must NOT trigger `ValUse` leniency (which would be an accept-invalid).
fn value_contains_box(val: &crate::sigma_value::SigmaValue) -> bool {
    use crate::sigma_value::{CollValue, SigmaValue};
    match val {
        SigmaValue::OpaqueBoxBytes(_) => true,
        // `BoolBits` / `Bytes` collections never hold boxes; only `Values` can.
        SigmaValue::Coll(CollValue::Values(items)) | SigmaValue::Tuple(items) => {
            items.iter().any(value_contains_box)
        }
        SigmaValue::Opt(Some(inner)) => value_contains_box(inner),
        _ => false,
    }
}

/// Whole-tree scan (every child, not just the type spine) collecting reused binding
/// ids and whether any constant — inline in `body` or in the segregated `constants`
/// table — materializes a box value. See [`BindingScan`] for why both matter.
fn scan_tree(
    body: &crate::opcode::Expr,
    constants: &[(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
) -> BindingScan {
    use crate::opcode::Payload;
    fn walk(
        e: &crate::opcode::Expr,
        seen: &mut std::collections::HashSet<u32>,
        dups: &mut std::collections::HashSet<u32>,
        has_box: &mut bool,
    ) {
        let node = match e {
            crate::opcode::Expr::Unparsed(_) => return,
            crate::opcode::Expr::Const { val, .. } => {
                *has_box |= value_contains_box(val);
                return;
            }
            crate::opcode::Expr::Op(node) => node,
        };
        let mut record = |id: u32| {
            if !seen.insert(id) {
                dups.insert(id);
            }
        };
        match &node.payload {
            Payload::ValDef { id, rhs, .. } | Payload::FunDef { id, rhs, .. } => {
                record(*id);
                walk(rhs, seen, dups, has_box);
            }
            Payload::FuncValue { args, body } => {
                for (id, _) in args {
                    record(*id);
                }
                walk(body, seen, dups, has_box);
            }
            Payload::BlockValue { items, result } => {
                for item in items {
                    walk(item, seen, dups, has_box);
                }
                walk(result, seen, dups, has_box);
            }
            Payload::MethodCall { obj, args, .. } => {
                walk(obj, seen, dups, has_box);
                for a in args {
                    walk(a, seen, dups, has_box);
                }
            }
            Payload::One(a) => walk(a, seen, dups, has_box),
            Payload::Two(a, b) => {
                walk(a, seen, dups, has_box);
                walk(b, seen, dups, has_box);
            }
            Payload::Three(a, b, c) => {
                walk(a, seen, dups, has_box);
                walk(b, seen, dups, has_box);
                walk(c, seen, dups, has_box);
            }
            Payload::Four(a, b, c, d) => {
                walk(a, seen, dups, has_box);
                walk(b, seen, dups, has_box);
                walk(c, seen, dups, has_box);
                walk(d, seen, dups, has_box);
            }
            Payload::ConcreteCollection { items, .. }
            | Payload::Tuple { items }
            | Payload::SigmaCollection { items } => {
                for i in items {
                    walk(i, seen, dups, has_box);
                }
            }
            Payload::SelectField { input, .. }
            | Payload::ExtractRegisterAs { input, .. }
            | Payload::NumericCast { input, .. } => walk(input, seen, dups, has_box),
            Payload::ByIndex {
                input,
                index,
                default,
            } => {
                walk(input, seen, dups, has_box);
                walk(index, seen, dups, has_box);
                if let Some(d) = default.as_deref() {
                    walk(d, seen, dups, has_box);
                }
            }
            Payload::FuncApply { func, args } => {
                walk(func, seen, dups, has_box);
                for a in args {
                    walk(a, seen, dups, has_box);
                }
            }
            Payload::DeserializeRegister { default, .. } => {
                if let Some(d) = default.as_deref() {
                    walk(d, seen, dups, has_box);
                }
            }
            // Leaves and id-free payloads: no binding ids, nothing to recurse.
            Payload::Zero
            | Payload::ValUse { .. }
            | Payload::ConstPlaceholder { .. }
            | Payload::TaggedVar { .. }
            | Payload::BoolCollection { .. }
            | Payload::GetVar { .. }
            | Payload::DeserializeContext { .. }
            | Payload::NoneValue { .. } => {}
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut dups = std::collections::HashSet::new();
    // A segregated constant pollutes the shared store the same way an inline one
    // does, even when no `ConstPlaceholder` references it (the whole table is
    // parsed), so seed the box flag from the constants table too.
    let mut has_box = constants.iter().any(|(_, val)| value_contains_box(val));
    walk(body, &mut seen, &mut dups, &mut has_box);
    BindingScan {
        dup_ids: dups,
        has_box_const: has_box,
    }
}

/// Immutable context threaded through [`infer_type`] for the whole judgement: the
/// segregated `constants` table (for `ConstPlaceholder`) plus the [`BindingScan`]
/// flags that make a `ValUse` fall back to `None`.
struct InferCtx<'a> {
    constants: &'a [(crate::sigma_type::SigmaType, crate::sigma_value::SigmaValue)],
    scan: &'a BindingScan,
}

/// A binding environment frame: `(binding id, its static type)` pairs, threaded
/// through [`infer_type`] so a `ValUse` can recover the type of the `ValDef` /
/// `FunDef` it references (Scala's `ValUse.tpe` reads a type the wire does NOT
/// carry for us). A `ValUse` flagged ambiguous by the [`BindingScan`] is resolved
/// to `None` instead, so the at-most-one-relevant-entry-per-id assumption the
/// newest-first scan relies on holds for every id it actually returns.
type TypeEnv<'a> = &'a [(u32, crate::sigma_type::SigmaType)];

/// Recursive static-type inference over the ErgoTree IR — the rule-1001
/// (`CheckDeserializedScriptIsSigmaProp`) root typechecker, computing the same
/// `Value.tpe` Scala derives bottom-up at deserialize. Returns the type when it
/// is STATICALLY DETERMINABLE, or `None` (treated as lenient/accept by the gate)
/// — so an as-yet-unhandled shape can never reject a tree Scala accepts.
fn infer_type(
    body: &crate::opcode::Expr,
    env: TypeEnv,
    ctx: &InferCtx,
) -> Option<crate::sigma_type::SigmaType> {
    use crate::opcode::Payload;
    use crate::sigma_type::SigmaType;
    match body {
        crate::opcode::Expr::Const { tpe, .. } => Some(tpe.clone()),
        crate::opcode::Expr::Op(node) => match &node.payload {
            Payload::ConstPlaceholder { index } => ctx
                .constants
                .get(*index as usize)
                .map(|(tpe, _)| tpe.clone()),
            // Payloads carrying their result type EXPLICITLY in the IR.
            // `Deserialize{Context,Register}[T]` return `T` DIRECTLY, so they CAN
            // be SigmaProp (accept iff T == SSigmaProp); `NumericCast`'s target is
            // always a numeric type (never SigmaProp). Returning the declared type
            // lets the gate accept/reject exactly as Scala does (oracle-verified:
            // `DeserializeRegister[SigmaProp]` accepts, `[SLong]` rejects).
            Payload::DeserializeContext { tpe, .. }
            | Payload::DeserializeRegister { tpe, .. }
            | Payload::NumericCast { tpe, .. } => Some(tpe.clone()),
            // `getVar[T]` / `box.RX[T]` statically return `Option[T]` — never
            // SigmaProp, even for T = SigmaProp (oracle-verified).
            Payload::GetVar { tpe, .. } | Payload::ExtractRegisterAs { tpe, .. } => {
                Some(SigmaType::SOption(Box::new(tpe.clone())))
            }
            // Collection / tuple literals — `Coll[..]` / a tuple — are never
            // SigmaProp even when every element is SigmaProp (oracle-verified:
            // `Coll[SigmaProp]` and `(SigmaProp, SigmaProp)` both reject).
            Payload::ConcreteCollection { elem_type, .. } => {
                Some(SigmaType::SColl(Box::new(elem_type.clone())))
            }
            Payload::BoolCollection { .. } => Some(SigmaType::SColl(Box::new(SigmaType::SBoolean))),
            Payload::Tuple { .. } => Some(SigmaType::SAny),
            // ARG-DEPENDENT roots whose type is a PROJECTION of a child's type
            // (Scala computes these bottom-up at deserialize). RECURSE into the
            // type-determining child — `determinable_root_type_of` only ever yields
            // an oracle-verified concrete type or `None`, so a non-determinable
            // child maps to `None` (lenient) and this can NEVER reject a tree Scala
            // accepts. `MethodCall`/`PropertyCall` are typed by
            // [`method_call_result_type`] (the harness-verified registry);
            // `FuncApply` still needs a binding environment and stays lenient via the
            // fallback below.
            //
            // ArithOp (Minus/Plus/Multiply/Division/Modulo/Min/Max): `tpe =
            // left.tpe` and Scala does NOT type-check the operands at deserialize,
            // so a SigmaProp LEFT operand makes the op SigmaProp (oracle-verified:
            // `Plus(sigma, x)` accepts, `Plus(Long, Long)` rejects). Recurse into
            // the left operand (child 0 of the `Two` payload).
            Payload::Two(left, _right)
                if matches!(node.opcode, 0x99 | 0x9A | 0x9C | 0x9D | 0x9E | 0xA1 | 0xA2) =>
            {
                infer_type(left, env, ctx)
            }
            // If: `If.tpe = trueBranch.tpe` (the then-branch, child 1; Scala does
            // NOT unify the branches at deserialize).
            Payload::Three(_cond, then_branch, _else) if node.opcode == 0x95 => {
                infer_type(then_branch, env, ctx)
            }
            // Fold: result = the accumulator type = the `zero` arg (child 1).
            Payload::Three(_coll, zero, _op) if node.opcode == 0xB0 => infer_type(zero, env, ctx),
            // BlockValue `{ vals...; result }`: type = the result expression's type,
            // typed under an environment extended with each `ValDef` / `FunDef`
            // binding (in order; a later item may reference an earlier one). Both
            // bind their id to their RHS type — Scala's `ValUse.tpe` reads the
            // referenced definition's value type, and a `FunDef` RHS is NOT always a
            // function (e.g. `fun x = sigmaProp`), so deriving it from the RHS keeps
            // a `ValUse` of a SigmaProp-RHS binding accepting (oracle-verified).
            // A non-determinable RHS is skipped, so a `ValUse` of it stays lenient.
            Payload::BlockValue { items, result } => {
                let mut scope = env.to_vec();
                for item in items {
                    if let crate::opcode::Expr::Op(item_node) = item {
                        if let Payload::ValDef { id, rhs, .. } | Payload::FunDef { id, rhs, .. } =
                            &item_node.payload
                        {
                            if let Some(t) = infer_type(rhs, &scope, ctx) {
                                scope.push((*id, t));
                            }
                        }
                    }
                }
                infer_type(result, &scope, ctx)
            }
            // ValUse: the type of the `ValDef`/`FunDef` it binds. We cannot match
            // Scala's flat, shared, last-write-wins store for an ambiguous id, so go
            // lenient (`None`) for: a REUSED id (its value is position-dependent and
            // may be rebound off-spine), or ANY `ValUse` once an `SBox` constant is
            // present (its nested script can rebind ids on the shared reader with
            // bindings we cannot see). A unique id in a box-free tree resolves from
            // the lexical env. See [`BindingScan`].
            Payload::ValUse { id } => {
                if ctx.scan.has_box_const || ctx.scan.dup_ids.contains(id) {
                    return None;
                }
                env.iter()
                    .rev()
                    .find(|(i, _)| i == id)
                    .map(|(_, t)| t.clone())
            }
            // A function literal is never SigmaProp (its type is `SFunc`), so a
            // `FuncValue` root fails rule 1001 (oracle-verified: a FuncValue-rooted
            // tree rejects).
            Payload::FuncValue { .. } => Some(SigmaType::SAny),
            // SelectField `tuple._i`: the i-th component type of the input tuple
            // (1-based). Only resolvable when the input's type is a determinable
            // `STuple` (e.g. a tuple constant); otherwise lenient.
            Payload::SelectField { input, field_idx } => match infer_type(input, env, ctx) {
                Some(SigmaType::STuple(items)) => (*field_idx as usize)
                    .checked_sub(1)
                    .and_then(|i| items.get(i))
                    .cloned(),
                _ => None,
            },
            // ByIndex `coll(i)`: the element type of the input collection.
            Payload::ByIndex { input, .. } => match infer_type(input, env, ctx) {
                Some(SigmaType::SColl(elem)) => Some(*elem),
                _ => None,
            },
            // OptionGet `opt.get` / OptionGetOrElse `opt.getOrElse(d)`: the option's
            // element type (the option is child 0 in both).
            Payload::One(opt) if node.opcode == 0xE4 => match infer_type(opt, env, ctx) {
                Some(SigmaType::SOption(elem)) => Some(*elem),
                _ => None,
            },
            Payload::Two(opt, _default) if node.opcode == 0xE5 => match infer_type(opt, env, ctx) {
                Some(SigmaType::SOption(elem)) => Some(*elem),
                _ => None,
            },
            // MethodCall / PropertyCall: the method's result static type, classified
            // by the (type_id, method_id) registry the `difftest --methodcall`
            // harness verified end-to-end against the JVM reference. See
            // [`method_call_result_type`].
            Payload::MethodCall {
                type_id,
                method_id,
                obj,
                args,
                type_args,
            } => method_call_result_type(*type_id, *method_id, obj, args, type_args, env, ctx),
            // A zero-argument (leaf) opcode root has a statically-known type and
            // NONE of them is `SSigmaProp` (see [`zero_arg_root_type`]), so a
            // script rooted at one fails CheckDeserializedScriptIsSigmaProp just
            // like an inline non-SigmaProp `Const`.
            Payload::Zero => Some(zero_arg_root_type(node.opcode)),
            // An operator root whose result type is unconditionally non-SigmaProp
            // (regardless of its argument types) — relations, arithmetic, etc.
            _ => op_root_non_sigma_type(node.opcode),
        },
        crate::opcode::Expr::Unparsed(_) => None,
    }
}

/// The result static type of a `MethodCall` / `PropertyCall`, for the rule-1001
/// root judgement. Scala computes `MethodCall.tpe` as the SMethod's result type
/// specialized for the receiver/arg types; the only methods whose specialized
/// result can be `SigmaProp` are the 7 the `difftest --methodcall` harness verified
/// END-TO-END against the JVM reference (every other of the 199 registered methods
/// returns a concrete type or an `Option`/`Coll`/tuple wrapper — structurally never
/// `SigmaProp`). Each of the 7 is a projection of the receiver / args / explicit
/// type, exactly mirroring the `ByIndex` / `OptionGet` / `Fold` / `Deserialize`
/// arms above. A result type VARIABLE that occurs more than once (`getOrElse`'s
/// receiver + default, `fold`'s zero + op range) is reconciled with
/// [`unify_occurrences`] — Scala `unifyTypeLists` makes the result `SigmaProp` only
/// when ALL occurrences are, so checking just one would accept a tree Scala rejects.
///
/// (A determinable occurrence MISMATCH actually makes Scala THROW at deserialize —
/// `specializeFor`'s `IllegalArgumentException` — which our structural parser does
/// not replicate at parse time. The rule-1001 verdict still matches where it is
/// enforced: this returns `SAny` (non-`SigmaProp`), so a SIZELESS conflict root is
/// rejected as Scala rejects it. A has_size conflict tree is soft-fork-wrapped here
/// vs hard-rejected by Scala — a pre-existing parse-layer accept-invalid, the safe
/// direction, outside this rule-1001 root typer.)
///
/// Reject-valid-safe by construction:
///  - a non-determinable projection returns `None` (lenient), so a SigmaProp-capable
///    method whose receiver type we cannot pin never gets rejected;
///  - every OTHER `(type_id, method_id)` returns `SAny` (non-`SigmaProp`). For the
///    192 known non-landmine methods this is the harness's verified result; an
///    UNKNOWN method is rejected by Scala at method resolution (so a non-`SigmaProp`
///    root verdict matches). The landmine set MUST stay complete — adding a method
///    here that can return `SigmaProp` without listing it would be a reject-valid.
fn method_call_result_type(
    type_id: u8,
    method_id: u8,
    obj: &crate::opcode::Expr,
    args: &[crate::opcode::Expr],
    type_args: &[crate::sigma_type::SigmaType],
    env: TypeEnv,
    ctx: &InferCtx,
) -> Option<crate::sigma_type::SigmaType> {
    use crate::sigma_type::SigmaType;
    let arg_ty = |i: usize| args.get(i).and_then(|a| infer_type(a, env, ctx));
    // The receiver's Coll / Option element type (the result type variable `IV`/`T`).
    // Computed LAZILY and AT MOST ONCE per call — inferring the receiver eagerly for
    // every MethodCall (including the non-landmine fallback) re-walks a nested
    // MethodCall receiver chain on each level, which is exponential (a parse-time
    // CPU DoS). The non-landmine / Global arms never touch the receiver.
    let coll_elem = || match infer_type(obj, env, ctx) {
        Some(SigmaType::SColl(elem)) => Some(*elem),
        _ => None,
    };
    let opt_elem = || match infer_type(obj, env, ctx) {
        Some(SigmaType::SOption(elem)) => Some(*elem),
        _ => None,
    };
    // Each landmine's result is the receiver/explicit projection, GATED on every
    // signature constraint Scala's `specializeFor` (`unifyTypeLists`) enforces: a
    // FIXED-type arg must equal its signature type, and every additional occurrence
    // of the result type variable must agree with the receiver/zero. A determinable
    // violation leaves the variable unbound -> non-`SigmaProp` (`SAny`, reject); an
    // undeterminable one -> `None` (lenient). See [`gated`] / [`agree`].
    let int = Some(SigmaType::SInt);
    match (type_id, method_id) {
        // Coll.apply(index: SInt): IV. `IV` is only in the receiver, but the index
        // must be SInt (else specializeFor fails and IV stays unbound).
        (12, 10) => gated(coll_elem(), &[agree(arg_ty(0), int)]),
        // Coll.getOrElse(index: SInt, default: IV): IV. index = SInt; default = IV.
        (12, 2) => {
            let elem = coll_elem();
            gated(
                elem.clone(),
                &[agree(arg_ty(0), int), agree(elem, arg_ty(1))],
            )
        }
        // Coll.fold(zero: OV, op: (OV, IV) => OV): OV. OV = zero = op arg0 = op range;
        // IV (receiver elem) = op arg1.
        (12, 5) => {
            let zero = arg_ty(0);
            let (op_a0, op_a1) = args.get(1).map_or((None, None), func_value_arg_types);
            let op_range = args.get(1).and_then(|op| func_value_range(op, env, ctx));
            gated(
                zero.clone(),
                &[
                    agree(zero.clone(), op_range),
                    agree(zero, op_a0),
                    agree(coll_elem(), op_a1),
                ],
            )
        }
        // Option.get: the receiver Option's element type (`T` only in the receiver).
        (36, 3) => opt_elem(),
        // Option.getOrElse(default: T): T. T = receiver elem = default.
        (36, 4) => {
            let elem = opt_elem();
            gated(elem.clone(), &[agree(elem, arg_ty(0))])
        }
        // Global.deserializeTo[T] / fromBigEndianBytes[T]: the explicit type arg `T`.
        // Scala applies the EXPLICIT type subst (T -> ...) to the method BEFORE
        // `specializeFor`, and `specializeFor` returns that already-substituted method
        // even when `unifyTypeLists` fails — so the result is `T` REGARDLESS of the
        // receiver or the `Coll[Byte]` value arg. Oracle-verified: a has_size
        // `deserializeTo[SigmaProp]` on a `Global`, a `Box`(SELF), or with an `Int`
        // value arg ALL classify SIGMA. Hence no receiver/arg gating here.
        (106, 4) | (106, 5) => type_args.first().cloned(),
        // Every other method (and any unknown one) is non-SigmaProp.
        _ => Some(SigmaType::SAny),
    }
}

/// Three-state result of comparing two inferred types for `specializeFor`
/// unification: `Some(Match)` they are equal, `Some(Mismatch)` a determinable
/// conflict (Scala fails to unify), `None`-side -> `Unknown` (non-determinable).
#[derive(PartialEq)]
enum Unify {
    Match,
    Mismatch,
    Unknown,
}

/// Compare two occurrences of a unified type (or an arg against its fixed signature
/// type, passed as `b`): equal -> `Match`, both PRECISELY determinable but different
/// -> `Mismatch`, otherwise `Unknown`. `SAny` is the typer's "non-`SigmaProp`, but
/// precise type not tracked" sentinel (returned for a non-landmine `MethodCall`, a
/// `Tuple`, a non-`SigmaProp` operator, …), NOT a literal `SAny` — so it is treated
/// as `Unknown`, never a `Mismatch`. Reporting `Mismatch` for it would reject a tree
/// Scala accepts, e.g. `Coll[SigmaProp].apply(coll.size)` whose `SInt` index the
/// sentinel hides (a reject-valid).
fn agree(
    a: Option<crate::sigma_type::SigmaType>,
    b: Option<crate::sigma_type::SigmaType>,
) -> Unify {
    use crate::sigma_type::SigmaType::SAny;
    match (a, b) {
        (Some(SAny), _) | (_, Some(SAny)) | (None, _) | (_, None) => Unify::Unknown,
        (Some(x), Some(y)) if x == y => Unify::Match,
        (Some(_), Some(_)) => Unify::Mismatch,
    }
}

/// Fold a landmine's projected `result` with its signature `checks`: any determinable
/// `Mismatch` makes `specializeFor` fail -> non-`SigmaProp` (`SAny`, reject); else any
/// `Unknown` -> lenient (`None`); else the projected result.
fn gated(
    result: Option<crate::sigma_type::SigmaType>,
    checks: &[Unify],
) -> Option<crate::sigma_type::SigmaType> {
    if checks.contains(&Unify::Mismatch) {
        Some(crate::sigma_type::SigmaType::SAny)
    } else if checks.contains(&Unify::Unknown) {
        None
    } else {
        result
    }
}

/// The first two declared argument types of a `FuncValue` operand (e.g.
/// `Coll.fold`'s `(OV, IV) => OV` reducer). `(None, None)` for a non-`FuncValue`.
fn func_value_arg_types(
    op: &crate::opcode::Expr,
) -> (
    Option<crate::sigma_type::SigmaType>,
    Option<crate::sigma_type::SigmaType>,
) {
    if let crate::opcode::Expr::Op(node) = op {
        if let crate::opcode::Payload::FuncValue { args, .. } = &node.payload {
            let a0 = args.first().and_then(|(_, t)| t.clone());
            let a1 = args.get(1).and_then(|(_, t)| t.clone());
            return (a0, a1);
        }
    }
    (None, None)
}

/// The RANGE type of a `FuncValue` operand (e.g. `Coll.fold`'s `(OV, IV) => OV`
/// reducer): its body typed under the function's declared arg types. `None` for a
/// non-`FuncValue` arg or a non-determinable body — leaving the caller lenient.
fn func_value_range(
    op: &crate::opcode::Expr,
    env: TypeEnv,
    ctx: &InferCtx,
) -> Option<crate::sigma_type::SigmaType> {
    let crate::opcode::Expr::Op(node) = op else {
        return None;
    };
    let crate::opcode::Payload::FuncValue { args, body } = &node.payload else {
        return None;
    };
    let mut scope = env.to_vec();
    for (id, tpe) in args {
        if let Some(t) = tpe {
            scope.push((*id, t.clone()));
        }
    }
    infer_type(body, &scope, ctx)
}

/// A non-`SSigmaProp` result type for operator (generic `One`/`Two`/`Three`
/// payload) opcodes whose result is UNCONDITIONALLY non-SigmaProp regardless of
/// argument types. Returns `Some(SAny)` for those (the gate only needs
/// `!= SSigmaProp`); `None` otherwise. Every listed opcode is oracle-verified to
/// reject a well-formed sizeless root (Scala 6.0.2, rule 1001).
///
/// NOT listed — and therefore left lenient (`None`) — are opcodes that CAN be
/// `SigmaProp` (`ProveDlog`/`ProveDHTuple` 0xCD/0xCE, `BoolToSigmaProp` 0xD1,
/// `AtLeast` 0x98, `SigmaAnd`/`SigmaOr` 0xEA/0xEB — all oracle-verified to ACCEPT)
/// and those whose result type DEPENDS on their arguments (`If` 0x95,
/// `BlockValue`/`FuncValue`/`FuncApply`, `SelectField`/`ByIndex`/`ValUse`/
/// `OptionGet`, `TaggedVar` 0x71). Adding any of those would reject a
/// Scala-accepted (SigmaProp-rooted) tree — a reject-valid. Payloads carrying an
/// explicit static type (`ConcreteCollection`, `Tuple`, `GetVar`,
/// `ExtractRegisterAs`, `NumericCast`, `Deserialize{Context,Register}`) and
/// `MethodCall`/`PropertyCall` (see [`method_call_result_type`]) are classified by
/// [`determinable_root_type_of`] BEFORE this fallback.
fn op_root_non_sigma_type(opcode: u8) -> Option<crate::sigma_type::SigmaType> {
    let never_sigma = matches!(
        opcode,
        0x8F..=0x94                    // Lt Le Gt Ge Eq Neq -> SBoolean
        // NB: ArithOp (Minus 0x99, Plus 0x9A, Multiply 0x9C, Division 0x9D,
        // Modulo 0x9E, Min 0xA1, Max 0xA2) is NOT here: Scala types it as
        // `left.tpe` with NO operand type-check, so a SigmaProp left operand makes
        // the whole op SigmaProp (oracle-verified ACCEPT). It is handled by the
        // arg-dependent left-operand recursion in `determinable_root_type_of`.
        | 0x9F | 0xA0                  // Exponentiate / MultiplyGroup (operand-typed -> reject sigma)
        | 0x7A | 0x7B | 0x7C           // LongToByteArray ByteArrayToBigInt ByteArrayToLong
        | 0xB1                         // SizeOf -> SInt
        | 0xCB | 0xCC                  // CalcBlake2b256 CalcSha256 -> Coll[SByte]
        | 0xC1 | 0xC2 | 0xC3 | 0xC4 | 0xC5 | 0xC7  // Extract{Amount,ScriptBytes,Bytes,BytesNoRef,Id,CreationInfo}
        | 0xCF | 0xD0                  // SigmaPropIsProven -> SBoolean, SigmaPropBytes -> Coll[SByte]
        // Boolean-result operators (predicates / Bool logic) -> SBoolean.
        | 0x96 | 0x97                  // And Or (Bool BinAnd/BinOr over Coll[Boolean]; NOT SigmaAnd/Or 0xEA/0xEB)
        | 0xAE | 0xAF                  // Exists ForAll
        | 0xE6                         // OptionIsDefined
        | 0xEC | 0xED | 0xEF | 0xF4 | 0xFF  // BinOr BinAnd LogicalNot BinXor XorOf
        // Numeric / byte-collection-result operators -> never SigmaProp.
        | 0x9B                         // Xor (byte-array)
        | 0xE7 | 0xE8 | 0xE9           // ModQ PlusModQ MinusModQ
        | 0xF0 | 0xF1 | 0xF2 | 0xF3 | 0xF5 | 0xF6 | 0xF7 | 0xF8  // Negation BitInversion BitOr BitAnd BitXor BitShift{Right,Left,RightZeroed}
        // Fixed-result structural ops.
        | 0x74                         // SubstConstants -> Coll[SByte]
        | 0xB7                         // TreeLookup -> Option[Coll[SByte]]
        | 0xEE                         // DecodePoint -> SGroupElement
        | 0xB3 | 0xB5                  // Append Filter -> Coll
        | 0xAD | 0xB4 // MapCollection Slice -> Coll
                      // NB: Fold (0xB0) / ByIndex (0xB2) / OptionGet (0xE4) / OptionGetOrElse
                      // (0xE5) are arg-dependent (result = accumulator / element type) and stay
                      // lenient — they CAN be SigmaProp.
    );
    never_sigma.then_some(crate::sigma_type::SigmaType::SAny)
}

/// Statically-known result type of a zero-argument (leaf) ErgoTree opcode. EVERY
/// leaf in the parser's table is non-`SSigmaProp`: `True`/`False` → `SBoolean`,
/// `GroupGenerator` → `SGroupElement`, `Height` → `SInt`, `Inputs`/`Outputs` →
/// `Coll[SBox]`, `LastBlockUtxoRootHash` → `SAvlTree`, `Self` → `SBox`,
/// `MinerPubkey` → `Coll[SByte]`, `Global` → `SGlobal`, `Context` → `SContext`.
/// (A `SigmaProp`-producing op — `ProveDlog`, `BoolToSigmaProp`, `SigmaAnd`, … —
/// always takes arguments, so it is never a `Zero` leaf.) An unrecognized leaf
/// falls back to `SAny`, still `!= SSigmaProp`, so the rule-1001 gate rejects it.
fn zero_arg_root_type(opcode: u8) -> crate::sigma_type::SigmaType {
    use crate::sigma_type::SigmaType::*;
    match opcode {
        0x7F | 0x80 => SBoolean,              // True / False
        0x82 => SGroupElement,                // GroupGenerator
        0xA3 => SInt,                         // Height
        0xA4 | 0xA5 => SColl(Box::new(SBox)), // Inputs / Outputs
        0xA6 => SAvlTree,                     // LastBlockUtxoRootHash
        0xA7 => SBox,                         // Self
        0xAC => SColl(Box::new(SByte)),       // MinerPubkey
        0xDD => SGlobal,                      // Global
        0xFE => SContext,                     // Context
        _ => SAny,                            // deprecated/unknown leaf — still non-SigmaProp
    }
}

pub fn read_ergo_tree(r: &mut VlqReader) -> Result<ErgoTree, ReadError> {
    let (tree, _was_wrapped) = read_ergo_tree_tracking_wrap(r)?;
    Ok(tree)
}

/// Like [`read_ergo_tree`] but also reports whether the returned tree
/// was rebuilt by `unparsed_soft_fork_tree` instead of fully parsed
/// (Scala's `Left(UnparsedErgoTree)` branch). Used by the template-hash
/// path — Scala's `tree.template` throws on the unparsed branch, so we
/// skip recording a template entry rather than emit one bogus hash for
/// every unparsed tree.
/// Advance `r` from the body start to the DECLARED-size end and return the
/// verbatim bytes. Mirrors Scala's wrap path EXACTLY: it computes
/// `numBytes = bodyPos - startPos + declaredSize`, rewinds (`r.position =
/// startPos`), then `propositionBytes = r.getBytes(numBytes)` — leaving the
/// reader at `startPos + numBytes`. Because the declared size is read non-exact
/// (`getUInt().toInt`) it can be NEGATIVE; Scala still accepts as long as
/// `numBytes >= 0` and in range (it does NOT reject merely because the size is
/// negative), and the resulting position can sit BEFORE `body_start`. Errors only
/// when `numBytes` is negative or past the buffer end, as Scala's `getBytes`
/// would. Used only when wrapping; the success path advances by the ACTUAL body
/// length instead. `r` is at `body_start` on entry.
fn take_unparsed_size_region(
    r: &mut VlqReader,
    tree_start: usize,
    body_start: usize,
    declared_size: i32,
) -> Result<Vec<u8>, ReadError> {
    let num_bytes = (body_start - tree_start) as i64 + declared_size as i64;
    let buf_end = (body_start + r.remaining()) as i64; // r is at body_start here
    if num_bytes < 0 || tree_start as i64 + num_bytes > buf_end {
        return Err(ReadError::InvalidData(format!(
            "ErgoTree declared size {declared_size} yields an out-of-range \
             UnparsedErgoTree byte count {num_bytes}"
        )));
    }
    let end = tree_start + num_bytes as usize;
    r.set_position(end); // Scala: position = startPos + numBytes (may rewind)
    Ok(r.data_slice(tree_start, end).to_vec())
}

pub(crate) fn read_ergo_tree_tracking_wrap(
    r: &mut VlqReader,
) -> Result<(ErgoTree, bool), ReadError> {
    let tree_start = r.position();
    let header = r.get_u8()?;
    let version = header & VERSION_MASK;
    let has_size = header & SIZE_FLAG != 0;
    let constant_segregation = header & CONSTANT_SEGREGATION_FLAG != 0;

    if has_size {
        // Scala reads the size with `getUInt().toInt` (NON-exact) and uses it ONLY
        // for the `UnparsedErgoTree` byte count on the wrap path. The body parse is
        // bounded by `MaxPropositionSize`, and on the SUCCESS path the reader
        // advances by the ACTUAL body length (structure-delimited) — the declared
        // size neither bounds the parse nor advances the reader on success. Scala's
        // box parser reads `creationHeight` immediately after this inline tree
        // parse (ErgoBoxCandidate.parseBodyWithIndexedDigests), so matching the
        // advance is consensus-relevant for a box whose declared size ≠ body length.
        let declared_size = r.get_uint_to_i32()?;
        let body_start = r.position();

        // A future-version tree is wrapped LENIENTLY here (the conformance hook
        // feeds size-stripped trees, template-hashing relies on the wrap) and
        // hard-rejected at the box-script layer via `check_tree_version_supported`.
        // Scala HARD-rejects it at deserialize (`VersionContext.withVersions`
        // throws when treeVersion > activated). The reader advances to the
        // declared-size end, as on every wrap path.
        if version > MAX_SUPPORTED_TREE_VERSION {
            let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
            return Ok((
                unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                true,
            ));
        }

        // Parse the body on a view of all remaining bytes WITHOUT advancing `r`,
        // bounded by a POSITION LIMIT of `MaxPropositionSize` (NOT the declared
        // size). `parse_body` is structure-delimited — it reads exactly the root
        // expression — so `inner.position()` is the true body length. A body that
        // would exceed the cap fails the parse and maps to the soft-fork wrap
        // below, exactly as Scala hits its position limit (`ReaderPositionLimit
        // Exceeded` → `CheckPositionLimit` `ValidationException`) and wraps.
        //
        // Scala anchors the limit at `startPos + MaxPropositionSize` (set BEFORE
        // the header + size are read) and checks `position > positionLimit` BEFORE
        // each read, so a final read that BEGINS exactly at the limit still
        // proceeds. The reader's `position_limit` mirrors that begin-check
        // precisely; using it (rather than truncating the view) matches Scala's
        // boundary byte-for-byte. The limit, relative to the inner view that
        // starts at `body_start`, is `MaxPropositionSize - (header + size length)`.
        let body_budget = MAX_PROPOSITION_BYTES.saturating_sub(body_start - tree_start);
        let (parsed, unresolved_checkpoint, body_consumed, inner_ges) = {
            let body_view = r.data_slice(body_start, body_start + r.remaining());
            let mut inner = VlqReader::new(body_view);
            inner.set_position_limit(Some(body_budget));
            // Gate embeddable type codes (e.g. SUnsignedBigInt, v6-only) against
            // this tree's header version, like Scala's version-scoped
            // `getEmbeddableType`. Covers segregated constants + the body.
            inner.set_ergo_tree_version(Some(version));
            let parsed = parse_body(&mut inner, version, has_size, constant_segregation);
            (
                parsed,
                inner.unresolved_method_checkpoint(),
                inner.position(),
                inner.take_group_elements(),
            )
        };
        // A size-delimited tree carrying a method the tree's registry cannot resolve
        // is wrapped by Scala as `UnparsedErgoTree`: `MethodCallSerializer.parse`
        // throws a method-resolution `ValidationException`, caught under has_size.
        // The parser keyed that on the tree-header version (v6-only method in a
        // pre-v3 tree, or a genuinely unknown id at any version) and recorded the
        // group-element sideband length at the exact throw point (after the method's
        // receiver + value args).
        let unresolved_method_wrap = unresolved_checkpoint.is_some();

        // Forward the group elements the inner parse collected onto `r` — EVEN when
        // about to wrap (Scala curve-checks them while deserializing, before
        // producing its UnparsedErgoTree). For the unresolved-method wrap, forward
        // ONLY the prefix Scala reached before it threw at the method; points after
        // it are never deserialized, hence never curve-checked.
        let forward_upto = if unresolved_method_wrap {
            unresolved_checkpoint.unwrap().min(inner_ges.len())
        } else {
            inner_ges.len()
        };
        for ge in &inner_ges[..forward_upto] {
            r.record_group_element(*ge);
        }

        // Once the parser has passed a method the registry cannot resolve, Scala has
        // already thrown the method-resolution `ValidationException` — right after the
        // method's receiver + value args (oracle-confirmed: the obj/args, including any
        // group elements, ARE decoded first; resolution is the next step) — and, under
        // has_size, caught it and wrapped WITHOUT reading the rest of the body. So the
        // outcome is a wrap REGARDLESS of whether the trailing bytes then parsed cleanly
        // OR hit a hard error (depth / overflow / nested HardReject) Scala never reaches.
        // Checked BEFORE the `parsed` match so such a later hard error cannot override it.
        if unresolved_method_wrap {
            let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
            return Ok((
                unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                true,
            ));
        }

        match parsed {
            Ok(tree) => {
                // Scala wraps any non-SigmaProp root
                // (`CheckDeserializedScriptIsSigmaProp`) as `UnparsedErgoTree`.
                // `determinable_root_type` is the rule-1001 typer — it covers inline
                // `Const`/`ConstPlaceholder`, the zero-arg + operator + binding +
                // MethodCall roots — and returns `None` (lenient, no wrap) only for a
                // shape it cannot yet type. The wrap path advances to the
                // declared-size end.
                if determinable_root_type(&tree)
                    .is_some_and(|tpe| tpe != crate::sigma_type::SigmaType::SSigmaProp)
                {
                    let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
                    return Ok((
                        unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                        true,
                    ));
                }
                // Parsed as SigmaProp: advance `r` by the ACTUAL body length so the
                // next box field is read from the structural body end, exactly where
                // Scala leaves the reader on success (the declared size is ignored).
                let _ = r.get_bytes(body_consumed)?;
                Ok((tree, false))
            }
            // Reached only when NO unresolved method preceded the error (that case
            // wrapped above) — so this hard error is the FIRST thing Scala hits too.
            // A tree-depth overflow is Scala's `DeserializeCallDepthExceeded`,
            // a `SerializerException` that `deserializeErgoTree` does NOT catch
            // (it only wraps ReaderPositionLimitExceeded / IllegalArgumentException
            // / ValidationException). So it must HARD-REJECT even under has_size,
            // not become an UnparsedErgoTree — otherwise a size-delimited tree
            // nested past MaxTreeDepth would be accept-invalid vs Scala.
            //
            // `HardReject` carries the same semantics for a NESTED box script
            // (an `SBox` constant whose sizeless pre-v3 inner tree carries a v6
            // method, or violates rule 1012): Scala re-raises those as
            // `SerializerException` too, so they must escape this size-delimited
            // wrap rather than be swallowed into an `UnparsedErgoTree`.
            //
            // `ValueTooLarge` is a VLQ value that overflowed its declared integer
            // width during the body parse. After routing the NON-exact
            // `getUInt().toInt` sites (segregated constants count, `ValUse` id,
            // `FuncValue` arg ids) through `get_uint_to_i32`, every `ValueTooLarge`
            // reachable HERE is from a width Scala hard-rejects: a `getUIntExact`
            // site (ConstantPlaceholder index, ValDef/FunDef id, BlockValue /
            // FuncValue / SigmaAnd-SigmaOr counts, SString length →
            // `ArithmeticException`) or a `getUShort` range overflow — neither a
            // `ValidationException`, so it must escape the wrap.
            Err(
                e @ (ReadError::DepthLimitExceeded { .. }
                | ReadError::HardReject(_)
                | ReadError::ValueTooLarge { .. }),
            ) => Err(e),
            Err(_) => {
                // Other parse failures (unknown opcode, invalid type tag, body
                // truncated at the MaxPropositionSize view) map to Scala's
                // ValidationException, wrapped as UnparsedErgoTree under has_size.
                let full = take_unparsed_size_region(r, tree_start, body_start, declared_size)?;
                Ok((
                    unparsed_soft_fork_tree(version, has_size, constant_segregation, full),
                    true,
                ))
            }
        }
    } else {
        // Sizeless body parses directly on `r`; scope the version gate to the body
        // and restore it so subsequent reads (box fields, an enclosing tree) are
        // unaffected. A v6-only embeddable type in a sizeless v<3 tree errors
        // (`InvalidData`); the box-script readers propagate it as a reject, matching
        // Scala re-raising the uncaught `ValidationException` as a hard reject.
        let saved_v = r.ergo_tree_version();
        r.set_ergo_tree_version(Some(version));
        let parsed = parse_body(r, version, has_size, constant_segregation);
        r.set_ergo_tree_version(saved_v);
        parsed.map(|tree| (tree, false))
    }
}

/// Construct a soft-fork-accepted ErgoTree (Scala's
/// `Left(UnparsedErgoTree(bytes, error))`): the outer flags are preserved and
/// the body holds the FULL original tree bytes verbatim
/// ([`crate::opcode::Expr::Unparsed`]), so re-serialization is byte-identical to
/// the wire form (matching Scala's preserved `propositionBytes`) and evaluation
/// hard-errors (Scala throws on an unparsed tree unless its error is an active
/// soft-fork). Used for:
/// - trees whose `version > MAX_SUPPORTED_TREE_VERSION` (version-based soft-fork)
/// - trees with `has_size` whose body fails to parse OR has a non-`SigmaProp`
///   constant root (validation-triggered soft-fork, matches Scala's
///   `UnparsedErgoTree` path)
fn unparsed_soft_fork_tree(
    version: u8,
    has_size: bool,
    constant_segregation: bool,
    full_tree_bytes: Vec<u8>,
) -> ErgoTree {
    ErgoTree {
        version,
        has_size,
        constant_segregation,
        constants: vec![],
        body: crate::opcode::Expr::Unparsed(full_tree_bytes),
    }
}

fn parse_body(
    r: &mut VlqReader,
    version: u8,
    has_size: bool,
    constant_segregation: bool,
) -> Result<ErgoTree, ReadError> {
    let constants = if constant_segregation {
        // Scala `deserializeConstants` reads the count via `getUInt().toInt`
        // (ErgoTreeSerializer.scala:248) — NOT `getUIntExact`. A value past
        // i32::MAX wraps to a negative `Int`, and the `cfor(0)(_ < nConsts)` loop
        // then yields ZERO constants rather than overflowing. Match that: read
        // non-exact and treat a negative count as 0 (an overflowed count is a
        // valid empty-constants tree in Scala, not a hard rejection).
        let count = r.get_uint_to_i32()?.max(0) as usize;
        let mut consts = Vec::with_capacity(count.min(CONSTANTS_VEC_SOFT_CAP));
        for _ in 0..count {
            let (tpe, val) = read_constant(r)?;
            // SHeader value deserialization is gated on isV3OrLaterErgoTreeVersion
            // (Scala DataSerializer.deserialize(SHeader)), per materialized
            // header: a segregated constant carrying a header in a pre-v3 tree
            // is rejected; an empty Coll[Header] is accepted.
            if version < 3 && val.contains_header() {
                return Err(ReadError::InvalidData(format!(
                    "SHeader value requires ErgoTree version >= 3 (got {version})"
                )));
            }
            // SOption data is gated on isV3OrLaterErgoTreeVersion too
            // (CheckSerializableTypeCode rejects SOption pre-v3, Some AND None);
            // a segregated Option constant in a pre-v3 tree is rejected.
            if version < 3 && val.contains_option() {
                return Err(ReadError::InvalidData(format!(
                    "SOption value requires ErgoTree version >= 3 (got {version})"
                )));
            }
            consts.push((tpe, val));
        }
        consts
    } else {
        vec![]
    };

    let body = opcode::parse_body(r, version)?;

    Ok(ErgoTree {
        version,
        has_size,
        constant_segregation,
        constants,
        body,
    })
}

/// Failure modes for [`tree_hash_from_bytes`]. Separate variants for
/// parse-failure vs reserialize-failure let callers map each onto the
/// right HTTP envelope (Scala returns 400 on either; we keep them
/// distinct in the type for diagnostics).
#[derive(Debug)]
pub enum TreeHashError {
    /// Input bytes could not be parsed into an `ErgoTree`.
    Parse(ReadError),
    /// Tree parsed cleanly but failed to re-serialize.
    Write(WriteError),
}

impl std::fmt::Display for TreeHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "ergo-tree parse: {e:?}"),
            Self::Write(e) => write!(f, "ergo-tree reserialize: {e:?}"),
        }
    }
}

impl std::error::Error for TreeHashError {}

/// Mirror of Scala's `IndexedErgoAddressSerializer.hashErgoTree(tree)`
/// for the API-surface case where the caller submits raw tree bytes.
/// Parse → re-serialize → blake2b256 yields the same key the indexer's
/// address-keyed tables use, so the byErgoTree routes can dispatch into
/// the address methods without a separate trait surface.
///
/// Re-serializing matches Scala's `tree.bytes` accessor (canonical
/// form). Hashing the input bytes verbatim would risk a mismatch on
/// non-canonical inputs that still parse cleanly; the parse-then-write
/// roundtrip pins us to the exact bytes the indexer keys on. The cost
/// is one extra serialization per request — negligible for a route
/// behind the indexer status gate.
pub fn tree_hash_from_bytes(tree_bytes: &[u8]) -> Result<[u8; 32], TreeHashError> {
    let mut reader = VlqReader::new(tree_bytes);
    let tree = read_ergo_tree(&mut reader).map_err(TreeHashError::Parse)?;
    let mut writer = VlqWriter::new();
    write_ergo_tree(&mut writer, &tree).map_err(TreeHashError::Write)?;
    Ok(*blake2b256(&writer.result()).as_bytes())
}

/// Failure modes for the template-hash derivations. Distinct from
/// [`TreeHashError`] because templating has the extra `Unparseable`
/// case: a tree that `read_ergo_tree` accepted as a soft-fork
/// placeholder cannot produce a meaningful template hash (Scala's
/// `tree.template` throws on its `Left(UnparsedErgoTree)` branch).
#[derive(Debug)]
pub enum TemplateHashError {
    /// Input bytes could not be parsed into an `ErgoTree`.
    Parse(ReadError),
    /// Tree parsed cleanly but its template body failed to re-serialize.
    Write(WriteError),
    /// Tree was rebuilt by `unparsed_soft_fork_tree` and does not have
    /// a meaningful template — the indexer must skip template recording
    /// for this output rather than emit a hash that collides across all
    /// unparsed trees.
    Unparseable,
}

impl std::fmt::Display for TemplateHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "ergo-tree parse: {e:?}"),
            Self::Write(e) => write!(f, "ergo-tree template reserialize: {e:?}"),
            Self::Unparseable => write!(f, "ergo-tree was wrapped as unparsed soft-fork"),
        }
    }
}

impl std::error::Error for TemplateHashError {}

/// Serialize the body of an `ErgoTree` to bytes. Mirrors Scala's
/// `ErgoTree.template` (which calls
/// `DefaultSerializer.serializeErgoTreeTemplate(tree)` =
/// `ValueSerializer.serialize(tree.toProposition(replaceConstants = false))`).
///
/// Result excludes the header byte and (when `constant_segregation` is
/// set) the constants table — both live in the parent serialization,
/// not the template. For segregated trees the body contains
/// `ConstPlaceholder` opcodes that reference the (omitted) constants
/// table; those placeholders are the byte sequence Scala diffs against.
pub fn template_bytes(tree: &ErgoTree) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    crate::opcode::write_body(&mut w, &tree.body, tree.constant_segregation)?;
    Ok(w.result())
}

/// `hashTreeTemplate(tree) = blake2b256(tree.template)` from the parsed
/// `ErgoTree`. Mirrors `IndexedContractTemplate.hashTreeTemplate` under
/// `VersionContext.withVersions(MaxSupportedScriptVersion = 3, ...)`.
///
/// Returns `TemplateHashError::Unparseable` on soft-fork-wrapped trees
/// — caller must check `was_wrapped` (use [`template_hash_from_bytes`]
/// for the parse-then-hash path).
pub fn template_hash(tree: &ErgoTree) -> Result<[u8; 32], TemplateHashError> {
    let bytes = template_bytes(tree).map_err(TemplateHashError::Write)?;
    Ok(*blake2b256(&bytes).as_bytes())
}

/// `hashTreeTemplate` from raw tree bytes. Parses, detects the
/// soft-fork wrap branch, and on the parsed branch hashes the template
/// body. The hot path on the indexer apply loop — one parse + one body
/// reserialize + one hash per output box.
pub fn template_hash_from_bytes(tree_bytes: &[u8]) -> Result<[u8; 32], TemplateHashError> {
    let mut reader = VlqReader::new(tree_bytes);
    let (tree, was_wrapped) =
        read_ergo_tree_tracking_wrap(&mut reader).map_err(TemplateHashError::Parse)?;
    if was_wrapped {
        return Err(TemplateHashError::Unparseable);
    }
    template_hash(&tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::Expr;
    use ergo_primitives::group_element::GroupElement;

    // ----- helpers -----

    /// Simplest valid body: a boolean constant `true` (serializes as 0x01 0x01).
    /// NOTE: a non-SigmaProp root is only valid under a NON-size-delimited tree.
    /// Under `has_size`, Scala's `CheckDeserializedScriptIsSigmaProp` soft-fork-
    /// wraps a non-SigmaProp root into `Expr::Unparsed`, so size-delimited
    /// fixtures must use [`sigma_prop_body`] instead.
    fn simple_body() -> Body {
        Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        }
    }

    /// A valid proposition body for size-delimited (`has_size`) fixtures:
    /// `sigmaProp(true)` (root type `SSigmaProp`), which survives re-parse
    /// without being soft-fork-wrapped.
    fn sigma_prop_body() -> Body {
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
        }
    }

    /// A ConstPlaceholder body for cseg tests (serializes as 0x73 + VLQ(0)).
    fn placeholder_body() -> Body {
        Expr::Op(crate::opcode::IrNode {
            opcode: 0x73,
            payload: crate::opcode::Payload::ConstPlaceholder { index: 0 },
        })
    }

    fn roundtrip(tree: &ErgoTree) {
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, tree).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ergo_tree(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after roundtrip");
        assert_eq!(&decoded, tree);
    }

    fn roundtrip_bytes(tree: &ErgoTree) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, tree).unwrap();
        w.result()
    }

    // ----- round-trips -----

    #[test]
    fn header_byte_version_only() {
        let tree = ErgoTree {
            version: 3,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        assert_eq!(bytes[0], 0x03);
        roundtrip(&tree);
    }

    #[test]
    fn header_byte_all_flags() {
        let tree = ErgoTree {
            version: 1,
            has_size: true,
            constant_segregation: true,
            constants: vec![],
            body: sigma_prop_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        // version=1, size=0x08, cseg=0x10 => 0x19
        assert_eq!(bytes[0], 0x19);
        roundtrip(&tree);
    }

    #[test]
    fn header_byte_size_flag_only() {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: sigma_prop_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        assert_eq!(bytes[0], 0x08);
        roundtrip(&tree);
    }

    #[test]
    fn header_byte_cseg_flag_only() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![],
            body: simple_body(),
        };
        let bytes = roundtrip_bytes(&tree);
        assert_eq!(bytes[0], 0x10);
        roundtrip(&tree);
    }

    #[test]
    fn no_constants_no_size() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn cseg_no_constants_no_size() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![],
            body: simple_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn cseg_with_constants_no_size() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![
                (SigmaType::SInt, SigmaValue::Int(42)),
                (SigmaType::SLong, SigmaValue::Long(1_000_000)),
            ],
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn cseg_with_constants_and_size() {
        // The body is `ConstPlaceholder(0)`, so under `has_size` the root's
        // resolved type IS checked (CheckDeserializedScriptIsSigmaProp): the
        // placeholder must resolve to a SigmaProp constant or the tree would be
        // soft-fork-wrapped. constants[0] is therefore `sigmaProp(true)`; the
        // trailing non-SigmaProp constants still exercise multi-constant cseg.
        let tree = ErgoTree {
            version: 1,
            has_size: true,
            constant_segregation: true,
            constants: vec![
                (
                    SigmaType::SSigmaProp,
                    SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
                ),
                (SigmaType::SBoolean, SigmaValue::Boolean(true)),
                (
                    SigmaType::SColl(Box::new(SigmaType::SByte)),
                    SigmaValue::Coll(crate::sigma_value::CollValue::Bytes(vec![0xDE, 0xAD])),
                ),
            ],
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn read_ergo_tree_constant_count_above_soft_cap_still_parses() {
        // CONSTANTS_VEC_SOFT_CAP bounds only the initial Vec reservation; it must
        // NOT reject a tree the Scala node would accept. A cseg tree with more
        // constants than the cap round-trips — the Vec grows past the cap on
        // push and parsing succeeds. Pins the consensus-acceptance claim of the
        // soft cap (contrast `read_ergo_tree_huge_constant_count_does_not_oom`,
        // which checks the hostile short-payload path returns an error).
        let n = CONSTANTS_VEC_SOFT_CAP + 904; // 5000, comfortably above the cap
        assert!(n > CONSTANTS_VEC_SOFT_CAP);
        let constants: Vec<(SigmaType, SigmaValue)> = (0..n)
            .map(|i| (SigmaType::SInt, SigmaValue::Int(i as i32)))
            .collect();
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants,
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn size_delimited_no_cseg() {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: sigma_prop_body(),
        };
        roundtrip(&tree);
    }

    #[test]
    fn multiple_constants_roundtrip() {
        let ge_bytes = [0x02; 33];
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![
                (SigmaType::SInt, SigmaValue::Int(0)),
                (SigmaType::SLong, SigmaValue::Long(i64::MAX)),
                (SigmaType::SBoolean, SigmaValue::Boolean(false)),
                (
                    SigmaType::SGroupElement,
                    SigmaValue::GroupElement(GroupElement::from_bytes(ge_bytes)),
                ),
            ],
            body: placeholder_body(),
        };
        roundtrip(&tree);
    }

    /// Assert that `hex` decodes to a valid ErgoTree wire form: header +
    /// optional constants table + body parses cleanly with no leftover
    /// bytes. Used by the per-fixture regression tests below to pin
    /// specific mainnet contracts.
    fn trace_tree(hex: &str) {
        let raw = hex::decode(hex).unwrap();
        let mut r = VlqReader::new(&raw);
        let header = r.get_u8().unwrap();
        let has_size = header & 0x08 != 0;
        let cseg = header & 0x10 != 0;

        if has_size {
            let _ = r.get_u32_exact().unwrap();
        }
        let const_count = if cseg { r.get_u32_exact().unwrap() } else { 0 };
        for _ in 0..const_count {
            crate::sigma_value::read_constant(&mut r).expect("constant parse");
        }
        crate::opcode::parse_body(&mut r, 0).expect("body parse");
        assert!(
            r.is_empty(),
            "leftover bytes: {} remaining at pos {}",
            r.remaining(),
            r.position()
        );
    }

    #[test]
    fn trace_emission_contract() {
        trace_tree("101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f");
    }

    #[test]
    fn mainnet_ergotrees_roundtrip() {
        #[derive(serde::Deserialize)]
        struct TestVector {
            #[allow(dead_code)]
            source: String,
            bytes: String,
        }

        let json_data = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/ergotrees_1_10.json"
        ))
        .expect("test vectors file");
        let vectors: Vec<TestVector> = serde_json::from_str(&json_data).expect("parse JSON");

        for (i, tv) in vectors.iter().enumerate() {
            let original_bytes =
                hex::decode(&tv.bytes).unwrap_or_else(|e| panic!("vector {i}: bad hex: {e}"));

            let mut r = VlqReader::new(&original_bytes);
            let tree = read_ergo_tree(&mut r)
                .unwrap_or_else(|e| panic!("vector {i} ({}): parse failed: {e}", tv.source));
            assert!(
                r.is_empty(),
                "vector {i} ({}): leftover bytes after parse",
                tv.source
            );

            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &tree).unwrap();
            let reserialized = w.result();

            assert_eq!(
                original_bytes,
                reserialized,
                "vector {i} ({}): roundtrip mismatch.\n  original:     {}\n  reserialized: {}",
                tv.source,
                hex::encode(&original_bytes),
                hex::encode(&reserialized),
            );
        }
    }

    #[test]
    fn trace_failing_tree_0x59() {
        // Tree #1645: height_700046, 440 bytes, header=0x19 (cseg, has_size)
        // Fails with "unknown type code: 0x59"
        let hex_bytes = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/failing_tree_1645.hex"
        ))
        .expect("read failing tree hex");
        let hex = hex_bytes.trim();
        trace_tree(hex.trim());
    }

    #[test]
    fn trace_block_1160831_tx14() {
        // TX 14 Out 0 from block 1160831 - complex contract with 24 constants
        trace_tree("19fc031808cd03c3ce4fd9a252ec9e58a766481f7d09dae2c9c2c48f22b47d97c4af12347a2ffc04000580a0be819501040404060402040004000e201b694b15467c62f0cd4525e368dbdea2329c713aa200b73df4a622e950551b400e208b08cdd5449a9592a9e79711d7d79249d7a03c535d17efaee83e216e80a44c4b05a8b22505bc81c4cbf9dbfa06058080d287e2bc2d040404ca0f06010104d00f0580a0be81950104ca0f0e691005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a5730405000500058092f4010100d803d6017300d602b2a4730100d6037302eb027201d195ed92b1a4730393b1db630872027304d804d604db63087202d605b2a5730500d606b2db63087205730600d6077e8c72060206edededededed938cb2720473070001730893c27205d07201938c72060173099272077e730a06927ec172050699997ec1a7069d9c72077e730b067e730c067e720306909c9c7e8cb27204730d0002067e7203067e730e069c9a7207730f9a9c7ec17202067e7310067e9c73117e7312050690b0ada5d90108639593c272087313c1720873147315d90108599a8c7208018c72080273167317");
    }

    #[test]
    fn trace_block_1160831_tx18_spectrum_dex() {
        // TX 18 Out 0 from block 1160831 - Spectrum DEX
        trace_tree("1999030f0400040204020404040405feffffffffffffffff0105feffffffffffffffff01050004d00f040004000406050005000580dac409d819d601b2a5730000d602e4c6a70404d603db63087201d604db6308a7d605b27203730100d606b27204730200d607b27203730300d608b27204730400d6099973058c720602d60a999973068c7205027209d60bc17201d60cc1a7d60d99720b720cd60e91720d7307d60f8c720802d6107e720f06d6117e720d06d612998c720702720fd6137e720c06d6147308d6157e721206d6167e720a06d6177e720906d6189c72117217d6199c72157217d1ededededededed93c27201c2a793e4c672010404720293b27203730900b27204730a00938c7205018c720601938c7207018c72080193b17203730b9593720a730c95720e929c9c721072117e7202069c7ef07212069a9c72137e7214067e9c720d7e72020506929c9c721372157e7202069c7ef0720d069a9c72107e7214067e9c72127e7202050695ed720e917212730d907216a19d721872139d72197210ed9272189c721672139272199c7216721091720b730e");
    }

    #[test]
    fn trace_block_1160831_tx35_options() {
        // TX 35 Out 0 from block 1160831 - options contract
        trace_tree("00d836d601db6308a7d60286028300020500d603b272010400017202d6048c720301d605e4c6a70763d606ed937204c5720593c2a7c27205d6079572067205a7d608e4c67207091ad609ef7206d60ac57207d60bb0dc0c0fa501d9010b63addb6308720bd9010d4d0e95938c720d01720a8c720d0205000500d9010b599a8c720b018c720b02d60cb27208040200d60db27208040400d60eb27208040600d60fb27208040800d610b2a5040000d611c27210d612e4c672070811d613b27212040c00d6149a72130580897ad615e4c67207050ed61695937211c2a7edededed92c17210721493e4c67210040ee4c67207040e93e4c67210050e721593e4c67210060ee4c67207060e93e4c67210076372070100d617b27212040600d618db6903db6503fed619c1a7d61ab27212040a00d61bdb63087210d61cb2721b0400017202d61d8c720302d61eb27212040400d61fb27212040800d62093b272120400000500d6218c721c02d622b2721b0402017202d623b2a5040200d6240e20e540cceffd3b8dd0f401193576cc413467039695969427df94454193dddfb375d6259172187217d626ed720693721d0502d6279593b272120402000500eded722672258f72189a72170580f0b252ed72269072187217d628b272010402017202d6298c722802d62a8c722202d62b8c722201d62cdb63087223d62db2722c0400017202d62e8c722d01d62f8c722d02d630b2a5040400d631db63087230d632b272310400017202d633957206e4c6a7081183020505000500d634b27233040000d635b27233040200d6368c721c01eb02ea02cdeeb27208040000d1ed720993720b0500d1ececec95eded720993b1a4040493b1a50406d804d637b2a4040200d638c17237d6399a999972197213721a7238d63a9572209d721d721e9d9972399c050472149c721f721eedededededededededededededededed927238058092f40193cbb2e4c67237091a040200720c93cbb2e4c67237091a040400720d93cbb2e4c67237091a040600720e93cbb2e4c67237091a040800720f72168f99721772180580909cf1c00593c17210723992c172109c05047214d801d63b723693723bc5a79372219a723a0502ecededed7220d801d63b722b93723b7215937222720393b1721b0404edef722093b1721b040293b2e4c672100811040000723a93b2e4c672100811040200050093cbc27223720c93c17223721a93cbc2b2a50404007224010095eded722793b1a4040493b1a50408d807d637957220997229722a997219c17210d6389572209d7237721e9d72379c721f721ed639b2db6308b2a40402000400017202d63a95938c723901720a8c7239020500d63b7230d63c7231d63d7232ededededededed937238723a7216ecedededededededed7220937203721c93c172107219ec93722b721593722a050093722e721593722f723793b1722c040292c1723b9c9c7238721f721e93b1723c0400edededededef722092c17223723793b1722c0400938c723d017215928c723d029c7238721e93b1723c040293b2e4c672100811040000723493b2e4c6721008110402009a7235723a93cbc2723b720e93cbc2b2a5040600722490c1b2a50406007213010095eded720693b1a4040293b1a50406edededededededededededed93c172109999721972130580897a721693723672049372210502937222722893b2e4c672100811040000723493b2e4c672100811040200050093cbc27223720d93c172230580897a93b1722c0402d801d637722e937237720493722f99721d050293cbc2b2a50404007224010095eced7225ef722795720693723572340100ededededededed93b1a4040293b1a5040493cb7211720f92c1721099721972139372368c722801937221722993720b050093cbc2722372240100");
    }

    #[test]
    fn trace_block_1160831_tx35_out1() {
        trace_tree("00d806d601e4c6a7091ad602b27201040000d603b27201040a00d604937203cbc2b2a5040000d605e4c6a7050ed606e4c6a70711eb02ea02cdee7202d1ef7204d195eded93b1a4040493b1a5040493cbc2b2a40400007203d801d607b2a4040000ededed93c2a7c27207ed93c17207c1a793e4c67207050e7205938cb27206040000017203ec93720672019683020193e4c67207060ee4c6a7060e93e4c67207070e7206d801d607b2a4040000ededededed93c2a7c27207ed93c17207c1a793e4c67207050e720593e4c67207060ee4c6a7060e93e4c67207070e7206d801d608e4c672070811eded93b27208040000720293b27208040200720493c172079c9c997208c17207050472039c72040502");
    }

    // ----- error paths -----

    #[test]
    fn read_ergo_tree_huge_constant_count_does_not_oom() {
        // Non-size-delimited, constant-segregated tree (header 0x10) that
        // claims count = i32::MAX with no constant bytes. Before the soft cap,
        // `Vec::with_capacity(count)` reserved multiple GiB and aborted the
        // process; the cap bounds the reservation, so parsing returns a clean
        // decode error instead.
        let mut bytes = vec![CONSTANT_SEGREGATION_FLAG]; // v0, no size, cseg
        bytes.extend_from_slice(&ergo_primitives::vlq::encode_vlq(i32::MAX as u64));
        let mut r = VlqReader::new(&bytes);
        assert!(read_ergo_tree(&mut r).is_err());
    }

    /// The declared `has_size` size neither bounds the body parse (Scala bounds
    /// it by `MaxPropositionSize`) nor advances the reader on success (Scala
    /// advances by the ACTUAL body length — structure-delimited). So a size that
    /// is too LARGE, too SMALL, or overflowed still PARSES, and the reader stops
    /// at the structural body end. Oracle (6.0.2): all four below → PARSED
    /// SSigmaProp. The old `get_u32_exact` + `get_bytes(size)` made the large /
    /// overflowed cases reject-valid and desynced a box stream on a wrong size.
    #[test]
    fn declared_size_is_not_the_body_bound_nor_the_success_advance() {
        // body `08d3` = sigmaProp(true), 2 bytes.
        for hex in [
            "080208d3",         // size 2 == body
            "080508d3",         // size 5  > body
            "080108d3",         // size 1  < body
            "08808080800808d3", // size 0x80000000 (overflow > i32::MAX)
        ] {
            let bytes = hex::decode(hex).unwrap();
            let mut r = VlqReader::new(&bytes);
            let tree = read_ergo_tree(&mut r)
                .unwrap_or_else(|e| panic!("{hex} must parse (Scala PARSED), got {e:?}"));
            assert!(
                matches!(
                    tree.body,
                    crate::opcode::Expr::Const {
                        tpe: crate::sigma_type::SigmaType::SSigmaProp,
                        ..
                    }
                ),
                "{hex}: expected a parsed SigmaProp root, got {:?}",
                tree.body
            );
        }
        // STRUCTURE-DELIMITED advance: a tree declaring size 3 but a 2-byte body,
        // followed by a trailing byte, must consume only the 2-byte body and leave
        // the trailing byte (where Scala reads the next box field), NOT advance to
        // the declared-size end.
        let bytes = hex::decode("080308d3ff").unwrap();
        let mut r = VlqReader::new(&bytes);
        let _ = read_ergo_tree(&mut r).expect("must parse");
        assert_eq!(
            r.remaining(),
            1,
            "reader must stop at the structural body end (one trailing byte left)"
        );
    }

    /// On the WRAP path Scala preserves `numBytes = bodyPos - startPos +
    /// declaredSize` bytes — and the declared size, read non-exact, may be
    /// NEGATIVE while `numBytes` stays in range, in which case Scala wraps (it
    /// does NOT reject for a negative size). Body `0204` = `Const(SByte)`, a
    /// non-SigmaProp root → wrap. Oracle (6.0.2): byte counts 5 / 4 / 0.
    #[test]
    fn negative_declared_size_wraps_with_scala_numbytes() {
        for (hex, expected_len) in [
            ("08ffffffff0f0204", 5usize), // size -1 → numBytes 6 + (-1) = 5
            ("08feffffff0f0204", 4),      // size -2 → 4
            ("08faffffff0f0204", 0),      // size -6 → 0 (empty propositionBytes)
        ] {
            let bytes = hex::decode(hex).unwrap();
            let mut r = VlqReader::new(&bytes);
            let tree = read_ergo_tree(&mut r)
                .unwrap_or_else(|e| panic!("{hex} must wrap (Scala UNPARSED), got {e:?}"));
            match &tree.body {
                crate::opcode::Expr::Unparsed(raw) => assert_eq!(
                    raw.len(),
                    expected_len,
                    "{hex}: UnparsedErgoTree byte count must match Scala numBytes"
                ),
                other => panic!("{hex}: expected Unparsed, got {other:?}"),
            }
        }
    }

    /// A segregated constants COUNT past i32::MAX is read non-exact (Scala
    /// `getUInt().toInt`): it wraps negative and yields ZERO constants, so the
    /// tree PARSES (here to `sigmaProp(true)`), it is NOT hard-rejected. Oracle
    /// (6.0.2): `1807808080800808d3` → PARSED SSigmaProp. The previous
    /// `get_u32_exact` raised `ValueTooLarge` here — reject-valid.
    #[test]
    fn constants_count_overflow_parses_as_empty_not_rejects() {
        let bytes = hex::decode("1807808080800808d3").unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).expect("overflowed constants count must parse");
        assert!(
            !matches!(tree.body, crate::opcode::Expr::Unparsed(_)),
            "must parse, not wrap"
        );
        assert!(
            tree.constants.is_empty(),
            "overflowed count yields 0 constants"
        );
    }

    /// A `getUIntExact` site (here a `ConstantPlaceholder` index) past i32::MAX
    /// HARD-rejects: Scala `toIntExact` throws `ArithmeticException`, caught by
    /// neither deserialize catch, so it escapes the has_size wrap. Oracle:
    /// `18070073ffffffff0f` → THROW. (Wrapping it was accept-invalid.)
    #[test]
    fn getuintexact_index_overflow_hard_rejects_not_wrapped() {
        let bytes = hex::decode("18070073ffffffff0f").unwrap();
        let mut r = VlqReader::new(&bytes);
        let err = read_ergo_tree(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::ValueTooLarge { .. }),
            "ConstantPlaceholder index overflow must hard-reject; got {err:?}"
        );
    }

    /// A `ValUse` id past i32::MAX is read non-exact (Scala `getUInt.toInt`):
    /// accepted, kept as the raw u32 so it round-trips byte-identically.
    #[test]
    fn valuse_id_overflow_roundtrips() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: crate::opcode::Expr::Op(crate::opcode::IrNode {
                opcode: 0x72, // ValUse
                payload: crate::opcode::Payload::ValUse { id: 0xFFFF_FFFF },
            }),
        };
        roundtrip(&tree);
    }

    /// A `FuncValue` arg id past i32::MAX is read non-exact (Scala
    /// `getUInt().toInt`) while the arg COUNT stays exact; the id round-trips.
    #[test]
    fn funcvalue_arg_id_overflow_roundtrips() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: crate::opcode::Expr::Op(crate::opcode::IrNode {
                opcode: 0xD9, // FuncValue
                payload: crate::opcode::Payload::FuncValue {
                    args: vec![(0xFFFF_FFFF, Some(SigmaType::SInt))],
                    body: Box::new(crate::opcode::Expr::Op(crate::opcode::IrNode {
                        opcode: 0xA3, // Height — a valid leaf body
                        payload: crate::opcode::Payload::Zero,
                    })),
                },
            }),
        };
        roundtrip(&tree);
    }

    // ----- oracle parity -----

    // -- Size-flagged malformed tree (Scala UnparsedErgoTree parity) --

    /// Block 1,702,686 tx #3 output[0] on mainnet carries an ErgoTree with
    /// header 0x09 (v=1, has_size=true, no cseg), declared body size 47
    /// bytes. The body's first two bytes parse as `Const(SByte = 4)`, but
    /// since the root type is SByte — not SigmaProp — Scala's
    /// CheckDeserializedScriptIsSigmaProp raises a ValidationException,
    /// and because `has_size` is set the outer catch wraps as
    /// UnparsedErgoTree preserving all declared bytes (Scala
    /// ErgoTreeSerializer.scala:197-208). The remaining 45 bytes inside
    /// the declared-size region are ignored — size is a position LIMIT,
    /// not an equality constraint.
    ///
    /// Our parser must NOT raise on this input. It must accept and return a
    /// soft-fork-wrapped tree whose body is [`Expr::Unparsed`], preserving the
    /// full original tree bytes verbatim (mirroring Scala's
    /// `UnparsedErgoTree(propositionBytes)`). Regression guard for sync
    /// stalling at block 1702686.
    #[test]
    fn size_flagged_non_sigmaprop_root_wraps_as_unparsed() {
        let hex = "092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402";
        let bytes = hex::decode(hex).unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree =
            read_ergo_tree(&mut r).expect("size-flagged non-SigmaProp tree must wrap, not raise");
        assert_eq!(tree.version, 1);
        assert!(tree.has_size);
        assert!(!tree.constant_segregation);
        // The body holds the FULL original tree bytes verbatim (Scala preserves
        // an UnparsedErgoTree's propositionBytes), so re-serialization is
        // byte-identical and evaluation hard-errors rather than silently
        // succeeding as an always-true proposition.
        match &tree.body {
            Expr::Unparsed(raw) => assert_eq!(
                raw, &bytes,
                "unparsed soft-fork body must preserve the full tree bytes"
            ),
            other => panic!("expected Unparsed soft-fork body, got {other:?}"),
        }
        // Byte-identical re-serialization — the property that closes the wire
        // round-trip divergence for soft-fork-wrapped scripts.
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree).unwrap();
        assert_eq!(
            w.result(),
            bytes,
            "soft-fork-wrapped tree must re-serialize verbatim"
        );
    }

    /// A size-delimited tree whose ROOT is a `ConstPlaceholder` resolving to a
    /// non-SigmaProp segregated constant fails Scala's
    /// `CheckDeserializedScriptIsSigmaProp` just like an inline non-SigmaProp
    /// `Const` root — the placeholder carries the constant's type
    /// (`ConstantPlaceholderSerializer.parse`). It must soft-fork-wrap to
    /// `Expr::Unparsed` (byte-preserving), NOT be accepted as a parsed
    /// `Int`-typed proposition. A placeholder resolving to a SigmaProp constant
    /// is a valid root and is NOT wrapped.
    #[test]
    fn size_flagged_const_placeholder_non_sigmaprop_root_wraps_as_unparsed() {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SInt, SigmaValue::Int(7))],
            body: placeholder_body(), // ConstPlaceholder(0) → SInt (non-SigmaProp)
        };
        let bytes = roundtrip_bytes(&tree);
        let decoded = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
        match &decoded.body {
            Expr::Unparsed(raw) => assert_eq!(
                raw, &bytes,
                "non-SigmaProp placeholder root must wrap, preserving bytes"
            ),
            other => panic!("expected Unparsed soft-fork body, got {other:?}"),
        }
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &decoded).unwrap();
        assert_eq!(w.result(), bytes, "wrapped tree must re-serialize verbatim");

        // A placeholder resolving to a SigmaProp constant is a valid root.
        let valid = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(
                SigmaType::SSigmaProp,
                SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
            )],
            body: placeholder_body(),
        };
        roundtrip(&valid);
    }

    /// A size-delimited (`has_size`) tree whose body nests past MaxTreeDepth
    /// (110) must HARD-REJECT, NOT be wrapped as `UnparsedErgoTree`. Scala's
    /// `DeserializeCallDepthExceeded` is a `SerializerException` that
    /// `deserializeErgoTree` does not catch, so a depth overflow is
    /// consensus-rejected even under the soft-fork wrapper. (Regression for the
    /// codex review of the MAX_EXPR_DEPTH=110 fix — the wrapper used to swallow
    /// this into an accepted unparsed tree.)
    #[test]
    fn size_flagged_over_depth_body_hard_rejects_not_wrapped() {
        // header 0x08 = v0, has_size, no cseg; body = 150x SizeOf(0xB1) then a
        // Height (0xA3) leaf — depth far exceeds MaxTreeDepth (110).
        let mut body = vec![0xB1u8; 150];
        body.push(0xA3);
        let mut bytes = vec![0x08u8];
        ergo_primitives::vlq::encode_vlq_into(body.len() as u64, &mut bytes);
        bytes.extend_from_slice(&body);
        let mut r = VlqReader::new(&bytes);
        let err = read_ergo_tree(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { .. }),
            "size-delimited over-depth tree must hard-reject, not soft-fork wrap; got {err:?}"
        );
    }

    /// Same tree, but with `has_size` bit cleared — Scala raises rather
    /// than wraps (ErgoTreeSerializer.scala:205). We match: the non-size
    /// path still parses strictly.
    #[test]
    fn non_size_flagged_non_sigmaprop_root_returns_const_without_wrap() {
        // Header 0x01 = v=1, no has_size, no cseg. Body: SByte=4.
        // Without a size delimiter, parse_body consumes 2 bytes
        // ("02 04") and returns Const(SByte=4) cleanly — no wrap
        // because we don't have the size field to justify it.
        let bytes = hex::decode("010204").unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        match &tree.body {
            Expr::Const { tpe, .. } => assert_eq!(
                *tpe,
                SigmaType::SByte,
                "without has_size, non-SigmaProp Const is returned verbatim"
            ),
            other => panic!("expected Const(SByte), got {other:?}"),
        }
    }

    // ----- oracle parity -----

    /// `check_sigma_prop_root` is the box-script gate that enforces Scala
    /// `CheckDeserializedScriptIsSigmaProp` (rule 1001) for SIZELESS trees, which
    /// `deserializeErgoTree` hard-rejects (no size region to wrap into an
    /// `UnparsedErgoTree`). The accept/reject verdicts below are the JVM oracle's
    /// (`ErgoSerdeOracle`, sigma-state 6.0.2 `ergo_tree`/`reduce`): `000173` →
    /// REJECT (SerializerException), `0008d3` / a P2PK `0008cd02..` → ACCEPT. The
    /// lenient `read_ergo_tree` codec accepts all three; only the gate diverges.
    #[test]
    fn check_sigma_prop_root_matches_jvm_on_sizeless_trees() {
        let parse = |hex: &str| {
            let bytes = hex::decode(hex).unwrap();
            let mut r = VlqReader::new(&bytes);
            read_ergo_tree(&mut r).expect("lenient codec parses")
        };
        // Sizeless Boolean root (`01 73` = Const(SBoolean, true)) → rejected.
        let boolean_root = parse("000173");
        assert!(
            check_sigma_prop_root(&boolean_root).is_err(),
            "sizeless Boolean-root script must reject (rule 1001)"
        );
        // Sizeless Long root (`05 01` = Const(SLong, -1)) → rejected.
        assert!(
            check_sigma_prop_root(&parse("000501")).is_err(),
            "sizeless Long-root script must reject (rule 1001)"
        );
        // Sizeless zero-arg (leaf) opcode roots are all non-SigmaProp → rejected,
        // like the `Const` cases. JVM oracle: each `ergo_tree 00<op>` → REJECT
        // (SerializerException). TrueLeaf 0x7F / FalseLeaf 0x80 (SBoolean),
        // GroupGenerator 0x82, Height 0xA3, Self 0xA7, MinerPubkey 0xAC,
        // Context 0xFE.
        for op in ["007f", "0080", "0082", "00a3", "00a7", "00ac", "00fe"] {
            assert!(
                check_sigma_prop_root(&parse(op)).is_err(),
                "sizeless zero-arg root {op} must reject (rule 1001)"
            );
        }
        // Sizeless operator roots whose result type is unconditionally
        // non-SigmaProp also reject. JVM oracle: each → REJECT. Eq/Gt/Lt (rel,
        // SBoolean), Plus/Multiply (numeric), SizeOf (SInt), ExtractAmount/
        // ExtractScriptBytes (Box fields), SigmaPropIsProven/SigmaPropBytes.
        for op in [
            "009305010501", // Eq(Long,Long)
            "009105010501", // Gt(Long,Long)
            "009a05010501", // Plus(Long,Long)
            "009c05010501", // Multiply(Long,Long)
            "00b1a5",       // SizeOf(Outputs)
            "00c1a7",       // ExtractAmount(Self)
            "00c2a7",       // ExtractScriptBytes(Self)
            "00cf08d3",     // SigmaPropIsProven(sigmaProp)
            "00d008d3",     // SigmaPropBytes(sigmaProp)
            // More fixed-result operator roots (oracle-verified REJECT).
            "0096968300020101010101", // And(Coll[Boolean]) -> Boolean
            "00ae8300020404000400d90101040101", // Exists -> Boolean
            "00ef0101",               // LogicalNot -> Boolean
            "009b0e01000e0100",       // Xor(byte arrays) -> Coll[Byte]
            "00f00400",               // Negation -> numeric
            "00740e0100100100100100", // SubstConstants -> Coll[Byte]
            "00ee0e0102",             // DecodePoint -> SGroupElement
            "00b4a504000400",         // Slice(Outputs, 0, 0) -> Coll
            "00ada5d901010ec172010100", // MapCollection(Outputs, f) -> Coll
            // ARG-DEPENDENT roots typed by recursion (oracle-verified REJECT — the
            // type-determining child is non-SigmaProp).
            "00957f7f80",     // If(true, true, false) -> then=Boolean
            "00957f010108d3", // If(true, then=Boolean, else=sigma) -> then=Boolean
            "0095a3a4a5",     // If(Height, Inputs, Outputs) -> then=Coll[Box]
            "00d8000101",     // BlockValue(result = Boolean const)
            // Env-threaded (Stage A): a ValUse resolves to its binding's type.
            "00d801d60105007201", // { val x = Long(0); x } -> SLong
            // FunDef binds its id to its RHS type (Phase 2): a non-SigmaProp RHS
            // makes the ValUse — and the block result — non-SigmaProp (oracle REJECT).
            "00d801d7010005007201", // { fun x = Long(0); x } -> SLong
            // Duplicate-id block whose RESULT is independent of the reused binding:
            // `{ val x = sigmaProp; val x = sigmaProp; true }` -> SBoolean. The id is
            // ambiguous but the root (a Boolean const) does not resolve through it,
            // so rule 1001 is still enforced (oracle REJECT — the dup-id leniency is
            // scoped to a ValUse of the reused id, not the whole tree).
            "00d802d60108d3d60108d30101",
            // FuncValue root -> SFunc (a function is never SigmaProp).
            "00d90101017201", // FuncValue(arg: Bool, body: ValUse) -> SFunc
            // MethodCall/PropertyCall roots (Phase 3, harness-verified registry):
            // a NON-landmine method is non-SigmaProp -> reject.
            "00db6301a7", // SBox.value (99,1) -> SLong  (PropertyCall)
            "00db0c01a7", // Coll.size (12,1) -> SInt    (PropertyCall)
            // ...and a LANDMINE with a NON-SigmaProp receiver: Coll[Long].apply(0)
            // -> SLong (the projection is the receiver element type).
            "00dc0c0a8301050500010400",
            // Type-variable UNIFICATION (codex P1): getOrElse/fold have the result
            // variable in TWO places; a determinable conflict -> non-SigmaProp ->
            // reject. Oracle REJECT (the receiver/zero is SigmaProp but the
            // default/op is not):
            "00dc2404e30008010500",         // Option[Sigma].getOrElse(0L)
            "00dc0c0283010808d30204000500", // Coll[Sigma].getOrElse(0, 0L)
            "00dc0c0583010808d30208d3d902010502057201", // Coll.fold(sigmaZero, Long-op)
            // ...and a FIXED-type arg mismatch (codex P1): Coll[Sigma].apply needs an
            // SInt index; a Long index makes specializeFor fail -> non-SigmaProp.
            "00dc0c0a83010808d3010500", // Coll[Sigma].apply(0L) -> reject
        ] {
            assert!(
                check_sigma_prop_root(&parse(op)).is_err(),
                "sizeless operator root {op} must reject (rule 1001)"
            );
        }
        // Payloads carrying an explicit static type (oracle-verified REJECT — none
        // is SigmaProp, even when the element/declared type IS SigmaProp, because
        // the result is a Coll/tuple/Option, not a SigmaProp).
        for op in [
            "0083000108d3",   // ConcreteCollection: Coll[SigmaProp] literal
            "0085000101",     // BoolCollection: Coll[Boolean]
            "00860208d308d3", // Tuple: (SigmaProp, SigmaProp)
            "00e30008",       // getVar[SigmaProp] -> Option[SigmaProp]
            "00c6a70408",     // box.R4[SigmaProp] -> Option[SigmaProp]
            "007d050004",     // Downcast (numeric)
            "00d40500",       // deserializeContext[Long]
            "00d5040500",     // deserializeRegister[Long]
        ] {
            assert!(
                check_sigma_prop_root(&parse(op)).is_err(),
                "sizeless explicit-type root {op} must reject (rule 1001)"
            );
        }
        // SigmaProp-rooted / SigmaProp-capable roots → accepted (oracle-verified
        // ACCEPT). These are the reject-valid landmines the gate must NOT reject.
        for op in [
            "00d10101",   // BoolToSigmaProp(true) — well-typed: child IS a Boolean
            "0008d3",     // SigmaProp constant
            "00d40801",   // deserializeContext[SigmaProp] — type tag = SigmaProp
            "00d5040800", // deserializeRegister[SigmaProp]
            "00710108",   // TaggedVar[SigmaProp] (type-tag dependent → lenient)
            // P2PK (ProveDlog) root.
            "0008cd02000a518dc9761306f048c70ad44e1a7fc9e4ce2ceeea529646f73aada1ea6640",
            // SigmaAnd / SigmaOr / AtLeast of ProveDlogs — common multisig roots.
            "00ea02cd070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798cd070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0098040002cd070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798cd070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            // ARG-DEPENDENT roots typed by recursion whose type IS SigmaProp — these
            // MUST pass (rejecting them would be a reject-valid). `If` uses the
            // then-branch type; `BlockValue` uses its result type.
            "00957f08d308d3", // If(true, sigma, sigma) -> then=SigmaProp
            "00957f08d30101", // If(true, then=sigma, else=Boolean) -> then=SigmaProp
            "00d80008d3",     // BlockValue(result = SigmaProp const)
            // ArithOp.tpe = left.tpe: a SigmaProp LEFT operand makes Plus SigmaProp
            // (Scala accepts; a fixed-numeric classification would reject-valid).
            "009a08d308d3",   // Plus(sigma, sigma) -> left=SigmaProp
            // MethodCall/PropertyCall LANDMINES with a SigmaProp receiver/arg (Phase
            // 3): the projection yields SigmaProp, so these MUST pass (rejecting them
            // would be a reject-valid). Oracle-verified ACCEPT.
            "00dc0c0a83010808d3010400", // Coll[SigmaProp].apply(0) -> SigmaProp
            "00db2403e30008",           // Option[SigmaProp].get -> SigmaProp (PropertyCall)
            // getOrElse/fold where BOTH occurrences of the result variable are
            // SigmaProp -> SigmaProp -> accept (the unification check must not
            // reject-valid these). Oracle ACCEPT:
            "00dc2404e300080108d3",                     // Option[Sigma].getOrElse(sigma)
            "00dc0c0283010808d302040008d3",             // Coll[Sigma].getOrElse(0, sigma)
            "00dc0c0583010808d30208d3d902010802087201", // Coll.fold(sigmaZero, sigma-op)
            // An arg whose type is the SAny "non-SigmaProp sentinel" (a non-landmine
            // MethodCall, here Coll.size -> SInt) must NOT be read as a mismatch:
            // Coll[Sigma].apply(coll.size) has an SInt index -> SigmaProp -> accept
            // (rejecting it would be a reject-valid; the sentinel hides the real type).
            "00dc0c0a83010808d301db0c0183010808d3",
            // Env-threaded (Stage A): { val x = sigmaProp; x } -> result=ValUse=SigmaProp.
            "00d801d60108d37201",
            // FunDef RHS is NOT always a function: { fun x = sigmaProp; x } binds x
            // to SigmaProp, so the ValUse result IS SigmaProp (oracle ACCEPT — a
            // FunDef->SAny classification here would reject-valid, codex P1).
            "00d801d7010008d37201",
            // REUSED-ID ValUse -> lenient (a reused binding id never occurs in a
            // legitimately compiled tree; matching Scala's position-aware shared
            // store is intractable from the parsed AST, so we take the safe
            // direction). All four are oracle ACCEPT, and lenient resolution accepts
            // them — three because Scala also accepts (no reject-valid), the last as
            // a deliberate, documented accept-invalid. See `BindingScan`.
            //   reject-valid avoided — Scala's last write makes `x` SigmaProp:
            "00d802d6010500d601d101017201", // { val x=Long; val x=BoolToSigmaProp; x }
            //   ...same, but the rebinding is buried off-spine in an `Eq` operand:
            "00d802d6010500d60293d801d601d10101050005007201",
            //   ...forward reference: Scala fixes `y` to SigmaProp BEFORE the rebind
            //   (a whole-tree last-write would wrongly reject this):
            "00d803d60108d3d6027201d60105007202", // { val x=sigma; val y=x; val x=0L; y }
            //   documented ACCEPT-invalid: Scala rejects (last-write SLong), we are
            //   lenient — the safe direction on an adversarial determinable dup-id tree:
            "00d802d6010500d60105007201", // { val x=0L; val x=0L; x }
        ] {
            assert!(
                check_sigma_prop_root(&parse(op)).is_ok(),
                "SigmaProp(-capable) root {op} must pass (no reject-valid)"
            );
        }
    }

    /// `value_contains_box` keys on the VALUE: it sees an actual box through `Coll`
    /// / `Option` / tuple nesting, but a box-FREE value — including an EMPTY
    /// box-typed collection — must NOT count (codex P1: an empty `Coll[SBox]`
    /// materializes no box and cannot pollute the shared store).
    #[test]
    fn value_contains_box_keys_on_value_not_type() {
        use crate::sigma_value::{CollValue, SigmaValue};
        assert!(value_contains_box(&SigmaValue::OpaqueBoxBytes(vec![1, 2])));
        assert!(value_contains_box(&SigmaValue::Coll(CollValue::Values(
            vec![SigmaValue::OpaqueBoxBytes(vec![])]
        ))));
        assert!(value_contains_box(&SigmaValue::Tuple(vec![
            SigmaValue::Long(1),
            SigmaValue::OpaqueBoxBytes(vec![])
        ])));
        assert!(value_contains_box(&SigmaValue::Opt(Some(Box::new(
            SigmaValue::OpaqueBoxBytes(vec![])
        )))));
        // box-free, incl. an EMPTY box-typed collection and a None option:
        assert!(!value_contains_box(&SigmaValue::Coll(CollValue::Values(
            vec![]
        ))));
        assert!(!value_contains_box(&SigmaValue::Opt(None)));
        assert!(!value_contains_box(&SigmaValue::Coll(CollValue::Bytes(
            vec![1, 2]
        ))));
        assert!(!value_contains_box(&SigmaValue::Long(0)));
    }

    /// Reject-valid guard (codex P1): a box VALUE constant's nested script is parsed
    /// on the SAME reader, whose `valDefTypeStore` is shared and never restored, so
    /// it can rebind an id the outer body uses. Once a box value is present we trust
    /// no `ValUse` — `{ val x = Long; x }`, which alone rejects (root `SLong`), must
    /// go lenient so Scala's box-polluted `ValUse(1).tpe` (potentially `SigmaProp`)
    /// is never rejected. But a box-typed constant with NO box value (empty
    /// `Coll[SBox]`) changes nothing and must STILL reject (codex P1 accept-invalid).
    #[test]
    fn box_value_forces_valuse_root_leniency_but_empty_box_coll_does_not() {
        use crate::sigma_value::{CollValue, SigmaValue};
        let parse = |hex: &str| {
            let bytes = hex::decode(hex).unwrap();
            let mut r = VlqReader::new(&bytes);
            read_ergo_tree(&mut r).expect("lenient codec parses")
        };
        // Baseline: `{ val x = Long(0); x }` -> SLong root, rejected by rule 1001.
        let base = parse("00d801d60105007201");
        assert!(
            check_sigma_prop_root(&base).is_err(),
            "baseline val-x-equals-Long block must reject (root SLong)"
        );
        // A real box value pollutes the shared store -> the ValUse can no longer be
        // trusted -> lenient (accept).
        let mut with_box = base.clone();
        with_box
            .constants
            .push((SigmaType::SBox, SigmaValue::OpaqueBoxBytes(vec![])));
        assert!(
            check_sigma_prop_root(&with_box).is_ok(),
            "a box value must force ValUse-root leniency (reject-valid guard)"
        );
        // An EMPTY Coll[SBox] materializes no box, so the store is unchanged and the
        // SLong root must STILL reject (no spurious leniency).
        let mut with_empty_box_coll = base.clone();
        with_empty_box_coll.constants.push((
            SigmaType::SColl(Box::new(SigmaType::SBox)),
            SigmaValue::Coll(CollValue::Values(vec![])),
        ));
        assert!(
            check_sigma_prop_root(&with_empty_box_coll).is_err(),
            "an empty Coll[SBox] constant must NOT trigger leniency (codex P1)"
        );
    }

    /// A deeply-nested MethodCall receiver chain must type in LINEAR time (codex P1
    /// DoS): `method_call_result_type` infers the receiver lazily, so a non-landmine
    /// root (`SBox.value`) returns `SAny` WITHOUT walking the chain. The eager
    /// version re-walked the receiver twice per level — exponential, a parse-time
    /// CPU DoS — and would hang this test well before 100 levels.
    #[test]
    fn nested_methodcall_receiver_types_in_linear_time() {
        // 100 levels of `SBox.value` (PropertyCall 0xDB, type 99, method 1) over SELF.
        let mut hex = String::from("00");
        for _ in 0..100 {
            hex.push_str("db6301");
        }
        hex.push_str("a7");
        let bytes = hex::decode(&hex).unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).expect("lenient codec parses");
        // SBox.value root is non-SigmaProp -> rejected — and returns ~instantly.
        assert!(check_sigma_prop_root(&tree).is_err());
    }

    /// `Global.deserializeTo[T]`'s result is the EXPLICIT type `T` regardless of the
    /// receiver / value-arg types (Scala applies the type subst before
    /// `specializeFor`, which returns the substituted method even on unify failure).
    /// Oracle-verified SIGMA for a `Global`, a `Box`(SELF), and an `Int` value arg —
    /// so the node must type a has_size `deserializeTo[SigmaProp]` on SELF as a
    /// SigmaProp root (NOT soft-fork-wrapped), matching the reference.
    #[test]
    fn global_deserialize_to_result_is_the_explicit_type_regardless_of_receiver() {
        // has_size v3: deserializeTo[SigmaProp](SELF, Coll[Byte] empty).
        let bytes = hex::decode("0b08dc6a04a7010e0008").unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).expect("lenient codec parses");
        assert!(
            !matches!(tree.body, Expr::Unparsed(_)),
            "deserializeTo[SigmaProp] root is SigmaProp (explicit type) -> not wrapped"
        );
    }

    /// A SIZE-flagged tree whose root is a boolean-literal leaf (`TrueLeaf`) is a
    /// non-SigmaProp root: Scala's `CheckDeserializedScriptIsSigmaProp` raises and,
    /// under `has_size`, it is soft-fork-wrapped (`UnparsedErgoTree`) — but here the
    /// declared size (`80 3e` = 7936) overruns the 4-byte buffer, so building that
    /// wrap region overflows and Scala rejects with an `IllegalArgumentException`
    /// (JVM oracle: REJECT). The wrap path's bounds check raises the same way.
    #[test]
    fn size_flagged_trueleaf_root_with_oversized_declared_len_rejects() {
        let bytes = hex::decode("eb803e7f").unwrap();
        let mut r = VlqReader::new(&bytes);
        assert!(
            read_ergo_tree(&mut r).is_err(),
            "has_size TrueLeaf root with out-of-range declared size must reject"
        );
    }

    /// The gate fires through the box-candidate reader: a box whose script is a
    /// sizeless Boolean-root tree is rejected at parse, matching Scala rejecting
    /// the creating transaction (accept-invalid otherwise).
    #[test]
    fn box_candidate_sizeless_non_sigmaprop_root_rejected() {
        // value(VLQ 1000) ++ tree `00 01 73` (v0, no-size, Const(SBoolean,true))
        // ++ height(0) ++ 0 tokens ++ 0 regs.
        let bytes = [0xE8u8, 0x07, 0x00, 0x01, 0x73, 0x00, 0x00, 0x00];
        let mut r = VlqReader::new(&bytes);
        assert!(
            crate::ergo_box::read_ergo_box_candidate(&mut r).is_err(),
            "box with a sizeless non-SigmaProp script must reject (rule 1001)"
        );
    }

    // -- Template-hash derivations --

    /// `template_bytes` strips the header byte and (when present) the
    /// constants table — only the body opcode stream survives. For a
    /// simple non-segregated tree with body `Const(SBoolean=true)`, the
    /// full tree serializes as `[header, 0x01, 0x01]` and the template
    /// is just `[0x01, 0x01]`.
    #[test]
    fn template_bytes_excludes_header_for_simple_tree() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        let full = roundtrip_bytes(&tree);
        let tmpl = template_bytes(&tree).unwrap();
        assert_eq!(full[0], 0x00, "header byte should be 0x00 (no flags)");
        assert_eq!(
            tmpl,
            full[1..].to_vec(),
            "template = full - header (no cseg, no size)"
        );
    }

    /// For a segregated tree, `template_bytes` excludes both the header
    /// AND the constants table — only the body (which contains
    /// `ConstPlaceholder` opcodes referencing the omitted constants by
    /// index) is hashed. This is what makes templates structurally
    /// equal across different parameter values.
    #[test]
    fn template_bytes_excludes_constants_table_for_segregated_tree() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: placeholder_body(),
        };
        let full = roundtrip_bytes(&tree);
        let tmpl = template_bytes(&tree).unwrap();
        // Full layout (no has_size): [header=0x10][const_count=0x01]
        // [const_type=0x01][const_val=0x01][body opcode 0x73][index 0x00]
        // = 6 bytes. Template = body only = [0x73, 0x00] = 2 bytes.
        assert_eq!(full.len(), 6);
        assert_eq!(tmpl, vec![0x73, 0x00]);
    }

    /// `template_hash` is exactly `blake2b256(template_bytes)`.
    #[test]
    fn template_hash_is_blake2_of_template_bytes() {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        };
        let tmpl = template_bytes(&tree).unwrap();
        let expected = *blake2b256(&tmpl).as_bytes();
        assert_eq!(template_hash(&tree).unwrap(), expected);
    }

    /// Emission-contract self-consistency: parsing a known mainnet tree
    /// then taking `template_hash` of the parsed value must equal taking
    /// `template_hash_from_bytes` of the original bytes. This is the
    /// API-surface invariant the indexer apply path relies on (it has
    /// the parsed tree in hand) versus the byErgoTree route (which
    /// receives raw bytes from the client).
    #[test]
    fn template_hash_self_consistent_for_emission_contract() {
        let hex = "101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f";
        let bytes = hex::decode(hex).unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        assert!(r.is_empty());

        let from_parsed = template_hash(&tree).unwrap();
        let from_bytes = template_hash_from_bytes(&bytes).unwrap();
        assert_eq!(from_parsed, from_bytes);
    }

    /// Block 1,702,686 size-flagged non-SigmaProp tree must surface as
    /// `Unparseable` from the bytes path so the indexer can skip
    /// recording an entry rather than emitting a hash that would
    /// collide across every soft-fork-wrapped tree on the chain.
    #[test]
    fn template_hash_from_bytes_unparseable_for_block_1702686() {
        let hex = "092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402";
        let bytes = hex::decode(hex).unwrap();
        match template_hash_from_bytes(&bytes) {
            Err(TemplateHashError::Unparseable) => {}
            other => panic!("expected Unparseable, got {other:?}"),
        }
    }

    /// A v4 tree (version > MAX_SUPPORTED_TREE_VERSION = 3) is wrapped
    /// by the version-soft-fork branch and must also surface as
    /// `Unparseable`.
    #[test]
    fn template_hash_from_bytes_unparseable_for_v4_softfork() {
        // Header: 0x0C = v=4, has_size=true, no cseg. Size VLQ(1)=0x01.
        // Body: one arbitrary byte (0x00) — never parsed because version
        // exceeds MAX_SUPPORTED_TREE_VERSION, so the wrap branch fires.
        let bytes = hex::decode("0C0100").unwrap();
        match template_hash_from_bytes(&bytes) {
            Err(TemplateHashError::Unparseable) => {}
            other => panic!("expected Unparseable for v4 tree, got {other:?}"),
        }
    }

    /// Every mainnet vector that the existing roundtrip test exercises
    /// must also produce a template hash without surfacing
    /// `Unparseable` — the corpus is curated to be parseable. Also
    /// confirms `template_hash(parsed) == template_hash_from_bytes(raw)`
    /// for each, which is the indexer-vs-API-route consistency contract.
    #[test]
    fn template_hash_consistent_across_mainnet_vectors() {
        #[derive(serde::Deserialize)]
        struct TestVector {
            #[allow(dead_code)]
            source: String,
            bytes: String,
        }

        let json_data = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/ergotrees_1_10.json"
        ))
        .expect("test vectors file");
        let vectors: Vec<TestVector> = serde_json::from_str(&json_data).expect("parse JSON");

        for (i, tv) in vectors.iter().enumerate() {
            let raw = hex::decode(&tv.bytes).unwrap_or_else(|e| panic!("vector {i}: bad hex: {e}"));
            let mut r = VlqReader::new(&raw);
            let tree = read_ergo_tree(&mut r)
                .unwrap_or_else(|e| panic!("vector {i} ({}): parse failed: {e}", tv.source));

            let from_parsed = template_hash(&tree)
                .unwrap_or_else(|e| panic!("vector {i} ({}): template_hash: {e}", tv.source));
            let from_bytes = template_hash_from_bytes(&raw).unwrap_or_else(|e| {
                panic!("vector {i} ({}): template_hash_from_bytes: {e}", tv.source)
            });
            assert_eq!(
                from_parsed, from_bytes,
                "vector {i} ({}): parsed/bytes hash mismatch",
                tv.source
            );
        }
    }

    // ----- check_resolvable_methods (box-deserialize method-resolution gate) -----

    fn parse_tree(hex_str: &str) -> ErgoTree {
        let bytes = hex::decode(hex_str).unwrap();
        read_ergo_tree(&mut VlqReader::new(&bytes)).expect("tree parses")
    }

    /// A SIZELESS pre-v3 tree carrying a v6 method (`SGlobal.none[Int]`, 106/10)
    /// is rejected — Scala re-raises the method-resolution `ValidationException`
    /// because there is no size bit to soft-fork-wrap it.
    #[test]
    fn check_resolvable_methods_rejects_sizeless_pre_v3_v6() {
        let tree = parse_tree("1000d1efe6db6a0add04");
        assert_eq!(tree.version, 0);
        assert!(!tree.has_size);
        let err = check_resolvable_methods(&tree).expect_err("sizeless v0 + v6 method must reject");
        assert!(
            matches!(&err, ReadError::InvalidData(m) if m.contains("does not resolve in the v5 registry")),
            "got {err:?}",
        );
    }

    /// The SAME body with the SIZE bit set is wrapped as `UnparsedErgoTree`
    /// during `read_ergo_tree` (Scala catches the v6-method `ValidationException`
    /// under has_size), so the box parses (creation accepted, matching Scala) and
    /// is rejected later on spend by the evaluator gate. The sizeless-only
    /// `check_resolvable_methods` box-parse gate must therefore NOT fire here.
    #[test]
    fn check_resolvable_methods_accepts_size_flagged_pre_v3_v6() {
        let tree = parse_tree("180900d1efe6db6a0add04");
        assert_eq!(tree.version, 0);
        assert!(tree.has_size);
        assert!(
            matches!(tree.body, crate::opcode::Expr::Unparsed(_)),
            "size-flagged pre-v3 v6-method tree wraps as Unparsed"
        );
        assert!(check_resolvable_methods(&tree).is_ok());
    }

    /// DIVERGENCE B fixed — GE-ordering past a v6 method (oracle-validated).
    ///
    /// A size-flagged pre-v3 tree carrying a v6-only method (`SBox.getReg[Int]`,
    /// 99/19) is wrapped by Scala as `UnparsedErgoTree`:
    /// `MethodCallSerializer.parse` throws the method-resolution
    /// `ValidationException`, caught under has_size. Scala curve-checks only the
    /// group elements it deserialized BEFORE that throw (the method's receiver +
    /// args, and anything earlier); points AFTER are never reached.
    ///
    /// Both vectors below were confirmed against the Scala oracle (sigma-state
    /// 6.0.2 `deserializeErgoTree`): the GE-after vector is `UNPARSED`
    /// (accepted), the GE-before vector throws (`SerializerException`, the
    /// off-curve point decoded before the method). We reproduce the accept/reject
    /// outcome: wrap as `Unparsed`, and forward exactly the GE prefix Scala
    /// reached — so an off-curve GE AFTER the method is dropped (accepted), while
    /// one BEFORE it is still forwarded (rejected downstream).
    #[test]
    fn pre_v3_v6_method_size_flagged_wraps_and_forwards_only_pre_method_ges() {
        let mut off_curve = [0xffu8; 33];
        off_curve[0] = 0x02; // off-curve x (cf. trivial_p2pk_offcurve_ge_constant_rejects)
        let off_curve_ge = || Expr::Const {
            tpe: SigmaType::SGroupElement,
            val: SigmaValue::GroupElement(GroupElement::from_bytes(off_curve)),
        };
        let v6_method = || {
            Expr::Op(crate::opcode::IrNode {
                opcode: 0xDC,
                payload: crate::opcode::Payload::MethodCall {
                    type_id: 99,
                    method_id: 19, // SBox.getReg[T] — v6-only
                    obj: Box::new(Expr::Op(crate::opcode::IrNode {
                        opcode: 0xA7, // Self
                        payload: crate::opcode::Payload::Zero,
                    })),
                    args: vec![Expr::Op(crate::opcode::IrNode {
                        opcode: 0xA3, // a 0-arg leaf in the reg-id slot
                        payload: crate::opcode::Payload::Zero,
                    })],
                    type_args: vec![SigmaType::SInt],
                },
            })
        };
        let size_flagged_v0 = |body: Body| ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body,
        };
        let read = |tree: &ErgoTree| {
            let bytes = roundtrip_bytes(tree);
            let mut r = VlqReader::new(&bytes);
            let decoded = read_ergo_tree(&mut r).expect("parses version-independently");
            let ges = r.take_group_elements();
            (bytes, decoded, ges)
        };

        // GE AFTER the v6 method — Scala wraps before reaching it (UNPARSED).
        // We must wrap and DROP the trailing off-curve GE (accept at creation).
        let after = size_flagged_v0(Expr::Op(crate::opcode::IrNode {
            opcode: 0x9A, // Plus(v6_method, off_curve_ge)
            payload: crate::opcode::Payload::Two(Box::new(v6_method()), Box::new(off_curve_ge())),
        }));
        let (after_bytes, after_decoded, after_ges) = read(&after);
        assert!(
            matches!(after_decoded.body, Expr::Unparsed(_)),
            "pre-v3 v6-method tree must wrap as Unparsed (Scala parity)"
        );
        assert!(
            !after_ges.iter().any(|ge| ge == &off_curve),
            "off-curve GE AFTER the v6 method must be dropped (Scala never reaches it)"
        );
        // Wrap preserves the bytes verbatim.
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &after_decoded).unwrap();
        assert_eq!(w.result(), after_bytes);

        // GE BEFORE the v6 method — Scala decodes it first and throws. The GE is
        // within the checkpoint prefix, so it is still forwarded (rejected
        // downstream by the curve check).
        let before = size_flagged_v0(Expr::Op(crate::opcode::IrNode {
            opcode: 0x9A, // Plus(off_curve_ge, v6_method)
            payload: crate::opcode::Payload::Two(Box::new(off_curve_ge()), Box::new(v6_method())),
        }));
        let (_, before_decoded, before_ges) = read(&before);
        assert!(
            matches!(before_decoded.body, Expr::Unparsed(_)),
            "pre-v3 v6-method tree wraps regardless of GE position"
        );
        assert!(
            before_ges.iter().any(|ge| ge == &off_curve),
            "off-curve GE BEFORE the v6 method must still be forwarded (rejected downstream)"
        );
    }

    /// A hard parse error in bytes AFTER an unresolved method must NOT override the
    /// wrap: Scala throws the method-resolution `ValidationException` at the method
    /// (right after its receiver + args) and, under has_size, wraps there — it never
    /// reads the trailing bytes, so the hard error is unreachable. The node parses the
    /// whole body generically, so it WOULD hit the trailing error; the wrap decision is
    /// therefore made BEFORE the parse-result match. Holds at v0 (v5 registry) and v3
    /// (v6 registry).
    ///
    /// `Plus(PropertyCall(106, 42, Global), ConstPlaceholder(0x80000000))`: the
    /// placeholder index is read via `get_u32_exact` (Scala `getUIntExact` ->
    /// `ArithmeticException`), a HARD error. Oracle (sigma-state 6.0.2): both header
    /// versions are `UNPARSED bytes=13`; the same trailing error WITHOUT a preceding
    /// unknown method THROWs (`ArithmeticException: Int overflow`) — hard reject.
    #[test]
    fn unresolved_method_wrap_survives_trailing_hard_error() {
        // (header) + Plus(0x9a) + PropertyCall(db 6a 2a) Global(dd)
        //         + ConstPlaceholder(0x73) index-vlq(80 80 80 80 08).
        for (hex_str, version) in [
            ("080b9adb6a2add738080808008", 0u8),
            ("0b0b9adb6a2add738080808008", 3u8),
        ] {
            let bytes = hex::decode(hex_str).unwrap();
            let decoded =
                read_ergo_tree(&mut VlqReader::new(&bytes)).expect("must wrap, not hard-reject");
            assert_eq!(decoded.version, version);
            assert!(
                matches!(decoded.body, Expr::Unparsed(_)),
                "v{version}: unknown method before a trailing hard error must still wrap (Scala UNPARSED)"
            );
            // Wrap preserves the bytes verbatim.
            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &decoded).unwrap();
            assert_eq!(w.result(), bytes);
        }
        // Control: the SAME trailing hard error with NO preceding unknown method is a
        // genuine hard reject (Scala THROWs `Int overflow`), so the wrap must NOT fire.
        let control = hex::decode("08089add738080808008").unwrap();
        assert!(
            read_ergo_tree(&mut VlqReader::new(&control)).is_err(),
            "trailing hard error with no unresolved method must hard-reject"
        );
    }

    /// UNKNOWN-method generalization of divergence B. A genuinely unknown
    /// `(type_id, method_id)` — not in EITHER the v5 or v6 registry — makes Scala's
    /// `deserializeErgoTree` throw the same method-resolution `ValidationException`
    /// as a v6-only method, so a size-flagged tree carrying one wraps as
    /// `UnparsedErgoTree` and curve-checks ONLY the group elements decoded before
    /// the throw. The node previously knew only v6-only ids, so a trailing off-curve
    /// GE after an unknown method was curve-checked (reject-valid). This holds at
    /// BOTH a pre-v3 header (v5 registry) and a v3 header (v6 registry) — only the
    /// unknown id, not a v6-only one, wraps at v3.
    ///
    /// Bytes confirmed UNPARSED against the Scala oracle (sigma-state 6.0.2); see
    /// the PR description.
    #[test]
    fn unknown_method_size_flagged_wraps_and_drops_trailing_ge() {
        let mut off_curve = [0xffu8; 33];
        off_curve[0] = 0x02; // off-curve x
        let off_curve_ge = || Expr::Const {
            tpe: SigmaType::SGroupElement,
            val: SigmaValue::GroupElement(GroupElement::from_bytes(off_curve)),
        };
        // SGlobal (type 106) has methods 1..=10; method 42 resolves in NO registry.
        // Receiver is GE-free (Global) so the trailing GE is the only group element,
        // entirely after the method subtree regardless of the exact throw point.
        let unknown_method = || {
            Expr::Op(crate::opcode::IrNode {
                opcode: 0xDB, // PropertyCall
                payload: crate::opcode::Payload::MethodCall {
                    type_id: 106,
                    method_id: 42,
                    obj: Box::new(Expr::Op(crate::opcode::IrNode {
                        opcode: 0xDD, // Global
                        payload: crate::opcode::Payload::Zero,
                    })),
                    args: vec![],
                    type_args: vec![],
                },
            })
        };
        let tree = |version: u8| {
            ErgoTree {
                version,
                has_size: true,
                constant_segregation: false,
                constants: vec![],
                // Plus(unknown_method, off_curve_ge): the off-curve GE is decoded
                // AFTER the method, so Scala never reaches it.
                body: Expr::Op(crate::opcode::IrNode {
                    opcode: 0x9A,
                    payload: crate::opcode::Payload::Two(
                        Box::new(unknown_method()),
                        Box::new(off_curve_ge()),
                    ),
                }),
            }
        };

        // The exact bytes were run through the Scala oracle: both are
        // `UNPARSED bytes=41 err=ValidationException` (wrap, trailing GE never reached).
        let expected_hex = [
            (0u8, "08279adb6a2add0702ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            (3u8, "0b279adb6a2add0702ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ];
        for (version, oracle_hex) in expected_hex {
            let t = tree(version);
            let bytes = roundtrip_bytes(&t);
            assert_eq!(
                hex::encode(&bytes),
                oracle_hex,
                "v{version} oracle-validated bytes"
            );
            let mut r = VlqReader::new(&bytes);
            let decoded = read_ergo_tree(&mut r).expect("parses version-independently");
            let ges = r.take_group_elements();
            assert!(
                matches!(decoded.body, Expr::Unparsed(_)),
                "v{version} unknown-method tree must wrap as Unparsed (Scala parity)"
            );
            assert!(
                !ges.iter().any(|ge| ge == &off_curve),
                "v{version}: off-curve GE AFTER the unknown method must be dropped"
            );
            // The wrap preserves the bytes verbatim.
            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &decoded).unwrap();
            assert_eq!(w.result(), bytes, "v{version} wrap is byte-exact");
        }
    }

    /// A SIZELESS v0 tree carrying an UNKNOWN method is HARD-rejected by
    /// `check_resolvable_methods` (Scala re-raises the method-resolution
    /// `ValidationException` with no size bit to wrap it). Without the registry
    /// generalization this was accept-invalid: the node parsed the unknown id as a
    /// generic `MethodCall` and the v6-only-specific gate did not fire.
    ///
    /// Bytes confirmed THROW against the Scala oracle (sigma-state 6.0.2).
    #[test]
    fn check_resolvable_methods_rejects_sizeless_unknown_method() {
        // header 00 (v0, sizeless) + PropertyCall(106, 42, Global): db 6a 2a dd.
        let bytes = hex::decode("00db6a2add").unwrap();
        let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).expect("parses leniently");
        assert_eq!(tree.version, 0);
        assert!(!tree.has_size);
        let err = check_resolvable_methods(&tree)
            .expect_err("sizeless v0 + unknown method must hard-reject");
        assert!(
            matches!(&err, ReadError::InvalidData(m) if m.contains("does not resolve in the v5 registry")),
            "got {err:?}",
        );
    }

    /// A valid sizeless tree with no unresolved method passes.
    #[test]
    fn check_resolvable_methods_accepts_valid_sizeless_tree() {
        let tree = parse_tree("0008d3");
        assert!(check_resolvable_methods(&tree).is_ok());
    }

    /// A size-delimited pre-v3 tree whose body carries the v6-only embeddable type
    /// `SUnsignedBigInt` (code 9, here `Coll[SUnsignedBigInt]`) wraps as
    /// `UnparsedErgoTree` — Scala's `getEmbeddableType` selects `embeddableV5`
    /// (codes 1..=8) at version 1 and throws a soft `ValidationException` caught
    /// under has_size. Oracle (sigma-state 6.0.2): `09061501f0a20400` →
    /// `UNPARSED bytes=8`. The node previously accepted the type and hard-rejected
    /// on the over-large bigint value read — a reject-valid.
    #[test]
    fn pre_v3_unsigned_bigint_embeddable_type_wraps_unparsed() {
        // header 0x09 (v1, has_size), size 6, body = Coll[SUnsignedBigInt](0x15)
        // + coll count 1 + over-large bigint length VLQ (f0a204) + 0x00.
        let bytes = hex::decode("09061501f0a20400").unwrap();
        let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).expect("wraps, not rejects");
        assert_eq!(tree.version, 1);
        assert!(
            matches!(tree.body, crate::opcode::Expr::Unparsed(_)),
            "pre-v3 SUnsignedBigInt-typed tree must wrap as Unparsed (Scala parity)"
        );
        // Wrap preserves the bytes verbatim.
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree).unwrap();
        assert_eq!(w.result(), bytes);
    }

    /// `check_tree_version_supported` HARD-rejects a tree whose version exceeds
    /// the activated/max supported version (Scala throws a `SerializerException`
    /// at deserialize via `VersionContext.withVersions`), and accepts v0..=3.
    /// Oracle-confirmed against sigma-state 6.0.2: `0c0208d3`/`0d…`/`0f…` (v4/5/7)
    /// all THROW, `080208d3` (v0) PARSES.
    #[test]
    fn check_tree_version_supported_rejects_future_versions() {
        // read_ergo_tree stays lenient: it wraps v4..=7 trees as Unparsed...
        for hex in ["0c0208d3", "0d0208d3", "0f0208d3"] {
            let tree = parse_tree(hex);
            assert!(tree.version > 3, "{hex}: version {} not > 3", tree.version);
            // ...but the box-script gate hard-rejects them.
            assert!(
                matches!(
                    check_tree_version_supported(&tree),
                    Err(ReadError::HardReject(_))
                ),
                "{hex}: version {} must hard-reject",
                tree.version
            );
        }
        // v0..=3 are accepted.
        for hex in ["080208d3", "0b0208d3"] {
            let tree = parse_tree(hex);
            assert!(tree.version <= 3);
            assert!(check_tree_version_supported(&tree).is_ok());
        }
    }

    /// Regression: an `SBox` constant whose sizeless pre-v3 inner tree carries a
    /// v6 method, embedded in the constants table of a SIZE-DELIMITED outer
    /// tree, must REJECT. The nested `HardReject` must NOT be swallowed into an
    /// `UnparsedErgoTree` by the outer tree's soft-fork wrap (Scala re-raises the
    /// nested `SerializerException`, which the enclosing tree's deserialize does
    /// not catch).
    #[test]
    fn nested_box_constant_v6_in_size_delimited_outer_hard_rejects() {
        // Inner box: sizeless v0 tree carrying SGlobal.none[Int].
        let mut bw = ergo_primitives::writer::VlqWriter::new();
        bw.put_u64(1_000_000);
        bw.put_bytes(&hex::decode("1000d1efe6db6a0add04").unwrap());
        bw.put_u32(100);
        bw.put_u8(0);
        bw.put_u8(0);
        bw.put_bytes(&[0u8; 32]);
        bw.put_u16(0);
        let inner_box = bw.result();

        let outer = ErgoTree {
            version: 0,
            has_size: true, // SIZE-DELIMITED outer — the soft-fork-wrap path
            constant_segregation: true,
            constants: vec![(SigmaType::SBox, SigmaValue::OpaqueBoxBytes(inner_box))],
            body: placeholder_body(),
        };
        let mut w = ergo_primitives::writer::VlqWriter::new();
        write_ergo_tree(&mut w, &outer).unwrap();
        let outer_bytes = w.result();

        let err = read_ergo_tree(&mut VlqReader::new(&outer_bytes)).expect_err(
            "a nested v6 box constant under a size-delimited outer tree must hard-reject",
        );
        assert!(matches!(err, ReadError::HardReject(_)), "got {err:?}");
    }

    /// Contrast with the v6 case: a nested `SBox` constant whose inner tree
    /// violates rule 1012 (`version != 0`, sizeless) is a Scala
    /// `ValidationException` (thrown in `deserializeHeaderAndSize`, before the
    /// inner catch), so a SIZE-DELIMITED outer tree WRAPS it as
    /// `UnparsedErgoTree` rather than rejecting — the rule-1012 nested rejection
    /// must therefore be SOFT (`InvalidData`), not `HardReject`. Rejecting here
    /// would be reject-valid.
    #[test]
    fn nested_box_constant_rule1012_in_size_delimited_outer_wraps() {
        // Inner box: sizeless version-1 tree (header 0x01) — rule-1012 violation.
        let mut bw = ergo_primitives::writer::VlqWriter::new();
        bw.put_u64(1_000_000);
        bw.put_bytes(&hex::decode("01d3").unwrap());
        bw.put_u32(100);
        bw.put_u8(0);
        bw.put_u8(0);
        bw.put_bytes(&[0u8; 32]);
        bw.put_u16(0);
        let inner_box = bw.result();

        let outer = ErgoTree {
            version: 0,
            has_size: true, // SIZE-DELIMITED outer — must WRAP a nested ValidationException
            constant_segregation: true,
            constants: vec![(SigmaType::SBox, SigmaValue::OpaqueBoxBytes(inner_box))],
            body: placeholder_body(),
        };
        let mut w = ergo_primitives::writer::VlqWriter::new();
        write_ergo_tree(&mut w, &outer).unwrap();
        let outer_bytes = w.result();

        let (tree, was_wrapped) = read_ergo_tree_tracking_wrap(&mut VlqReader::new(&outer_bytes))
            .expect(
            "a nested rule-1012 box constant under a size-delimited outer must WRAP, not reject",
        );
        assert!(
            was_wrapped,
            "the outer tree must be wrapped as UnparsedErgoTree, not parsed",
        );
        let _ = tree;
    }

    // ----- unparsed (soft-fork-wrapped) tree: verbatim round-trip -----

    /// A size-delimited tree whose body cannot be parsed is wrapped as
    /// `Expr::Unparsed` holding the FULL original bytes, and re-serializes
    /// BYTE-IDENTICAL — matching Scala's preserved `propositionBytes`. (The
    /// prior `Const(true)` substitution lost the bytes, changing the
    /// `propositionBytes` / boxId on re-serialization.)
    #[test]
    fn unparsed_soft_fork_tree_roundtrips_byte_identical() {
        for hex_str in [
            "0b01fd",     // v3 + size, 1-byte unknown-opcode body 0xfd
            "0b03fd0102", // v3 + size, 3-byte unknown-opcode body
            "1c020008",   // v4 (> MAX_SUPPORTED) + size, opaque body — version soft-fork
        ] {
            let bytes = hex::decode(hex_str).unwrap();
            let tree = read_ergo_tree(&mut VlqReader::new(&bytes))
                .unwrap_or_else(|e| panic!("{hex_str} must parse (soft-fork wrap): {e:?}"));
            assert!(
                matches!(tree.body, crate::opcode::Expr::Unparsed(_)),
                "{hex_str} must wrap to Expr::Unparsed, got {:?}",
                tree.body
            );
            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &tree).unwrap();
            assert_eq!(
                w.result(),
                bytes,
                "{hex_str} must re-serialize byte-identical"
            );
        }
    }
}
