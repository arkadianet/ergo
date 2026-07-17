//! The whole-tree consensus reject-gate cluster, run once at the shared
//! depth-0 reduction entry (and by the trivial-reduction fast path via
//! `pre_reduction_checks`): on-curve GroupElement constants, the
//! ContextExtension key domain, and the pre-v3 v6-method gate. Also
//! `validate_group_element`, the single-point curve check the verifier drains.

use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use crate::evaluator::opcodes;
use crate::evaluator::types::*;

/// Validate every `GroupElement` constant in the segregated constant table the
/// way Scala's `GroupElementSerializer.parse` does at deserialize time: a
/// non-zero lead byte must encode a point on SecP256K1, so an off-curve
/// constant errors EVEN WHEN the live evaluation path never reads it (it sits
/// in a dead `if`-branch). A lead-`0x00` (identity) encoding is accepted with
/// its trailing bytes discarded — only non-zero leads curve-validate. GE values
/// nested inside `Coll`/`Tuple`/`Option` constants are walked too.
fn validate_group_element_constants(
    constants: &[(SigmaType, SigmaValue)],
) -> Result<(), EvalError> {
    fn walk(v: &SigmaValue) -> Result<(), EvalError> {
        match v {
            SigmaValue::GroupElement(ge) => {
                opcodes::sigma::canonicalize_group_element(*ge.as_bytes())?;
                Ok(())
            }
            SigmaValue::Coll(ergo_ser::sigma_value::CollValue::Values(vs))
            | SigmaValue::Tuple(vs) => vs.iter().try_for_each(walk),
            SigmaValue::Opt(Some(inner)) => walk(inner),
            _ => Ok(()),
        }
    }
    constants.iter().try_for_each(|(_, val)| walk(val))
}

/// Reject a ContextExtension whose variable-id key has the high bit set
/// (>= 0x80). Scala stores extension keys as signed `Byte` and `toSigmaContext`
/// materializes a dense `Array(maxKey + 1)` indexed by that key — a key >= 0x80
/// is negative as a `Byte`, so the array build throws BEFORE any bytecode runs
/// and the spend fails regardless of whether the script reads the extension.
/// (Our map stores keys as unsigned `u8`; `k as i8 < 0` is the same domain.)
fn check_extension_key_domain(ctx: &ReductionContext<'_>) -> Result<(), EvalError> {
    if ctx.extension.keys().any(|&k| (k as i8) < 0) {
        return Err(EvalError::RuntimeException(
            "ContextExtension variable id with the high bit set (>= 0x80) is invalid",
        ));
    }
    Ok(())
}

/// Whole-tree checks Scala performs at context-build / deserialize time, BEFORE
/// any reduction runs (trivial or full): the ContextExtension key domain
/// (`toSigmaContext`) and every GroupElement constant on-curve
/// (`GroupElementSerializer.parse`). Exposed for the verifier so the
/// trivial-reduction fast path (`reduce::trivial_reduce`, which never enters
/// [`eval_expr`]) enforces them too — otherwise a bare P2PK spend with a
/// malformed context/constant would be accepted where Scala rejects.
pub(crate) fn pre_reduction_checks(
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    body: &Expr,
) -> Result<(), EvalError> {
    validate_group_element_constants(constants)?;
    check_extension_key_domain(ctx)?;
    check_v3_only_methods(ctx, body)?;
    Ok(())
}

/// Reject a v6/EIP-50 method ([`ergo_ser::opcode::is_v3_only_method`]) used in a
/// real pre-v3 (tree-header version < 3) ErgoTree. Scala's `deserializeErgoTree`
/// resolves the method table against the TREE-HEADER version and throws a
/// `ValidationException` for a v3-only method id in a v0/v1/v2 tree — eagerly,
/// over the whole AST, so even a dead `If`-branch method rejects (vector
/// `Global.none_pre_v3_dead_branch`). The wire parser stays version-independent
/// (headerless register / context payloads parse with a v0 sentinel and gate v6
/// methods at evaluation time via [`EvalError::SoftForkNotActivated`]); this
/// gate runs once at the shared depth-0 reduction entry — covering the spend
/// path — and keys on the tree-header version ([`ReductionContext::is_v3_ergo_tree`]),
/// NOT the activated soft-fork version.
fn check_v3_only_methods(ctx: &ReductionContext<'_>, body: &Expr) -> Result<(), EvalError> {
    if !ctx.is_v3_ergo_tree() {
        if let Some((type_id, method_id)) = ergo_ser::opcode::find_v3_only_method(body) {
            return Err(EvalError::PreV3V6Method {
                type_id,
                method_id,
                tree_version: ctx.ergo_tree_version,
            });
        }
    }
    Ok(())
}

/// Validate one group-element encoding exactly as Scala's
/// `GroupElementSerializer.parse` does at deserialize time: a `0x00`-lead
/// encoding is the identity (accepted, trailing bytes ignored); any other lead
/// must decode to an on-curve SecP256K1 point. Off-curve points and invalid
/// SEC1 prefixes error.
///
/// Exposed for the consensus group-element check: the node stores group elements
/// as raw bytes and defers the curve check to spend-eval, so a transaction
/// carrying an off-curve point would be accepted at creation where the JVM
/// rejects it at deserialize. `ergo-ser` collects every point seen during a
/// parse on the reader's sideband; `ergo-validation` drains that set and passes
/// each point here.
pub fn validate_group_element(bytes: [u8; 33]) -> Result<(), EvalError> {
    opcodes::sigma::canonicalize_group_element(bytes).map(|_| ())
}
