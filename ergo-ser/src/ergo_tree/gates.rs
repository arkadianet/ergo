//! Consensus reject-gates applied by the box-script readers after
//! [`super::read_ergo_tree`]'s lenient parse: rule 1012 (header size bit),
//! the activated-version tree-version check, method resolvability, and the
//! rule-1001 SigmaProp-root check.

use ergo_primitives::reader::ReadError;

use super::type_infer::determinable_root_type;
use super::{ErgoTree, JIT_ACTIVATION_VERSION};

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

/// Reject a tree whose header version exceeds the ACTIVATED script version the
/// parse runs under — Scala's `VersionContext` invariant, keyed to the
/// activated version, NOT to a static maximum.
///
/// The reference rule (`VersionContext.scala:17-21`):
///
/// ```text
/// case class VersionContext(activatedVersion: Byte, ergoTreeVersion: Byte) {
///   require(activatedVersion < JitActivationVersion || ergoTreeVersion <= activatedVersion, …)
/// ```
///
/// `ErgoTreeSerializer.deserializeErgoTree` (`ErgoTreeSerializer.scala:148-154`)
/// constructs that context with `activatedVersion = VersionContext.current
/// .activatedVersion` and the header's tree version, INSIDE its inner
/// `try`; a failing `require` is an `IllegalArgumentException` re-thrown as a
/// `SerializerException` ("Tree version (N) is above activated script version",
/// `:191-193`) — NOT a `ValidationException`, so the outer catch never wraps it
/// as `UnparsedErgoTree` and the box is hard-rejected, size bit or not. The
/// four cases, with `JitActivationVersion = 2`:
///
/// - **activated < 2** (header version 1 or 2, i.e. mainnet below the 5.0
///   activation at 843,776): the `require` is INERT — any tree version is
///   admitted to the body parse. A future-version body that then fails
///   (rule 1001 / an unknown opcode …) is a `ValidationException`, so WITH the
///   size bit `deserializeErgoTree` keeps it as `UnparsedErgoTree` with its
///   `propositionBytes` verbatim (`:197-203`); WITHOUT the size bit
///   `CheckHeaderSizeBit` (rule 1012, `:219`) has already thrown outside the
///   inner `try` for any `version != 0` — [`check_header_size_bit`] covers that
///   unconditionally.
/// - **activated >= 2** and `tree.version <= activated`: accepted.
/// - **activated >= 2** and `tree.version > activated`: hard `SerializerException`
///   with or without the size bit. Confirmed against the 6.0.2 oracle at
///   activated 3: v4/v5/v7 size-delimited trees THROW; at activated 1 and 2 the
///   same bytes PARSE (see `tree_version_oracle_parity.rs`).
/// - **activated > MaxSupportedScriptVersion (3)**: a future soft fork this node
///   does not implement; the tree gate is the least of it (the node cannot
///   evaluate such blocks at all). `MAX_SUPPORTED_TREE_VERSION` therefore only
///   bounds what `read_ergo_tree` parses — it is NOT this gate's threshold.
///
/// Which activated version applies is the caller's `VersionContext` scope, and
/// the reference's block path is NOT "the block's activated version": Scala only
/// scopes `BlockTransactionsSerializer.parse` from the wire block version for
/// `blockVersion >= Interpreter60Version (4)` (`BlockTransactions.scala:185-201`);
/// every earlier block, and every stored box re-read (`ErgoBoxSerializer.parse`
/// from the UTXO db), runs under the default context, activated 1 (`VersionContext
/// .scala:58`). Live counterexample: mainnet block 545,684 (header version 2), tx[1]
/// output[0] `cd07021a8e6f59fd4a` — header 0xcd = version 5 + size bit — is kept
/// as an `UnparsedErgoTree` and later spent by storage rent at 1,596,890 (header
/// version 3); the previous static `version > 3` gate wedged a from-genesis sync
/// on that block (#327). The mempool / P2P transaction parse is scoped to the
/// tip's activated version (`ErgoMemPool.scala:259`, `ErgoNodeViewSynchronizer
/// .scala:778`), so a future-version tree is refused at admission today.
///
/// As with [`check_header_size_bit`], [`read_ergo_tree`] stays lenient (it wraps
/// a future-version tree so the conformance hook and template-hash paths keep
/// working); this box-script gate supplies the hard rejection at the consensus
/// box-parse layer. Uses [`ReadError::HardReject`] so a nested `SBox`-constant
/// inner tree with a future version also escapes the enclosing tree's soft-fork
/// wrap. Readers obtain `activated_script_version` from their reader's scope via
/// [`super::reader_activated_script_version`].
pub fn check_tree_version_supported(
    tree: &ErgoTree,
    activated_script_version: u8,
) -> Result<(), ReadError> {
    if activated_script_version >= JIT_ACTIVATION_VERSION && tree.version > activated_script_version
    {
        return Err(ReadError::HardReject(format!(
            "ErgoTree version {} exceeds the activated script version {} (VersionContext require, SerializerException)",
            tree.version, activated_script_version
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
