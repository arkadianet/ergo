//! `/api/v1/script/*` — the ErgoScript playground (`v1-api-design.md` §5,
//! `dev-docs/v1-design-fragments/script-tooling.md`).
//!
//! The developer-facing surface over the node's TWO node-only assets: the
//! byte-parity compiler ([`ergo_compiler::compile`]) and the consensus-exact
//! interpreter ([`ergo_sigma`]'s reduce/cost path). Seven `POST` endpoints —
//! `compile` / `inspect` / `execute` / `cost` / `simulate` / `explain` /
//! `diff` — each a **thin adapter** over one of those primitives; this module
//! owns NO reduction / cost / compile logic (locked decision **D3**).
//!
//! **Tier (locked decision D2).** The whole group is **T0 public-but-BOUNDED**,
//! gated not by an api-key but by the shared per-IP [`Governor`] at the
//! `Compute` route class + a hard per-request cost cap (§6 of the fragment).
//! The cost governor is the load-bearing anti-DoS control: `execute` / `cost` /
//! `simulate` / `explain` run attacker-supplied code, and every reduction is
//! bounded by [`ScriptConfig::max_cost`] through an enforcing
//! [`CostAccumulator`] — a script that would exceed it answers
//! `400 cost_limit`, it never hangs. A paranoid operator can flip the whole
//! group to T1 with `[api.script] require_api_key = true`
//! ([`ScriptConfig::require_api_key`]); the router then wraps every route in the
//! [`Tier::Operator`] api-key gate instead of [`Tier::Public`].
//!
//! **Compat boundary (D3).** The frozen M6 Scala-compat slice
//! (`POST /script/p2sAddress` + `/p2shAddress`) is a *separate*, byte-frozen
//! surface — this native `script/compile` is its own richer adapter over the
//! SAME [`ergo_compiler::compile`] facade and never proxies or enriches the
//! compat route.

mod handlers;

use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use utoipa::ToSchema;

use ergo_compiler::{CompileError, EnvValue, NetworkPrefix, ScriptEnv};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_sigma::evaluator::{
    reduce_expr_traced_with_cost, reduce_expr_with_cost, EvalBox, EvalError, ReductionContext,
    TraceEntry,
};

use crate::compat::NodeChainQuery;
use crate::traits::NodeReadState;
use crate::v1::auth::{require_tier, Tier, V1AuthConfig};
use crate::v1::error::{v1_error, Reason};
use crate::v1::governor::{governor_mw, Governor, RouteClass};

use axum::response::Response;

// ----- caps (fragment §6) -------------------------------------------------

/// Consensus `maxBlockCost` default (fragment §3.4 / §6): the ceiling a
/// per-request cost cap may never exceed. Block-cost units.
pub const MAX_BLOCK_COST: u64 = 8_001_091;

/// Hard cap on the hex length of an `ergo_tree` input (bytes on the wire are
/// half this). Bounds the parse/reduce work an unauthenticated caller can ask
/// for (fragment §6 body-size caps). 128 KiB of hex ⇒ 64 KiB of tree.
pub const MAX_TREE_HEX_LEN: usize = 128 * 1024;

/// Hard cap on `source` text length for `compile` (fragment §6). The compiler's
/// recursion is depth-guarded at the wire layer; this bounds the parser input.
pub const MAX_SOURCE_LEN: usize = 64 * 1024;

/// Operator-tunable knobs for the whole `script/*` group (locked decision D2).
#[derive(Debug, Clone)]
pub struct ScriptConfig {
    /// `[api.script] require_api_key` — flip the group from **T0 public**
    /// (default, bounded by the governor) to **T1** (operator api-key gate).
    /// Default `false`: the cost governor is the load-bearing control, so the
    /// bounded surface is safe to expose publicly like any other T0 dry-run.
    pub require_api_key: bool,
    /// Per-request reduce/execute cost ceiling in block-cost units — the
    /// anti-DoS bound. Clamped to `[1, MAX_BLOCK_COST]`; a per-request
    /// `max_cost` in the body may only lower it, never raise it.
    pub max_cost: u64,
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            require_api_key: false,
            max_cost: MAX_BLOCK_COST,
        }
    }
}

impl ScriptConfig {
    /// The effective per-request cost ceiling: the group ceiling, optionally
    /// lowered by a caller-supplied `max_cost` (never raised above the group
    /// ceiling), clamped to at least 1 block-cost unit.
    fn effective_cost_limit(&self, requested: Option<u64>) -> u64 {
        let group = self.max_cost.clamp(1, MAX_BLOCK_COST);
        match requested {
            Some(r) => r.clamp(1, group),
            None => group,
        }
    }
}

/// Config-gated Scala reference oracle for `script/diff` (locked decision
/// **D3** residual / fragment §7-D4). Transport-agnostic: a live Scala node OR
/// a bundled scala-cli reducer implements this trait. **Unconfigured
/// (`None`) ⇒ `diff` answers `oracle_unavailable`** — the trait is never
/// required to exist.
#[async_trait::async_trait]
pub trait ScalaOracle: Send + Sync {
    /// Reduce `tree_bytes` against a minimal context at `height` on the Scala
    /// reference, returning its verdict. Bounded / pooled / timeout-guarded is
    /// the implementation's responsibility (fragment §4.8) — a diff request
    /// must never spawn one process per call.
    async fn reduce_tree(&self, tree_bytes: &[u8], height: u32) -> Result<OracleVerdict, String>;
}

/// A Scala-oracle reduction verdict (fragment §4.8).
#[derive(Debug, Clone)]
pub struct OracleVerdict {
    /// `true` = the reference accepted (reduced without error), `false` = it
    /// rejected.
    pub accept: bool,
    /// Rendered sigma proposition the tree reduced to (`None` on reject).
    pub reduced_to: Option<String>,
    /// Block-cost the reference charged (`None` when the transport does not
    /// surface it).
    pub cost: Option<u64>,
}

/// Shared state for the `script/*` group. Every reduce/compile primitive is a
/// free function; the only state is the read seams (`read` for the tip height,
/// `chain` for `simulate`/`explain` box lookups), the address network, the
/// optional Scala `oracle`, and the operator `config`.
#[derive(Clone)]
pub struct ScriptState {
    /// Snapshot reader — the default `height` for `execute`/`cost` contexts and
    /// `simulate`'s `at_height`.
    pub read: Arc<dyn NodeReadState>,
    /// Live-store chain reader — backs `simulate`/`explain` real-box lookups.
    /// `None` ⇒ those answer the honest `chain_reader_unavailable`.
    pub chain: Option<Arc<dyn NodeChainQuery>>,
    /// Address-encoding network prefix.
    pub network: NetworkPrefix,
    /// Scala reference oracle for `diff`. `None` ⇒ `oracle_unavailable` (D3).
    pub oracle: Option<Arc<dyn ScalaOracle>>,
    /// Operator knobs (tier switch + cost ceiling).
    pub config: ScriptConfig,
}

/// Build the `/api/v1/script/*` router (fragment §1). All seven routes sit at
/// the governor's [`RouteClass::Compute`] weight — the load-bearing bound — and
/// carry the tier gate the operator selected via `require_api_key` (T0
/// [`Tier::Public`] by default, T1 [`Tier::Operator`] when set). State-erased
/// for merging under `/api/v1`.
pub fn script_router(
    state: ScriptState,
    governor: Arc<Governor>,
    auth: Arc<V1AuthConfig>,
) -> Router {
    let tier = if state.config.require_api_key {
        Tier::Operator
    } else {
        Tier::Public
    };
    Router::new()
        .route("/api/v1/script/compile", post(handlers::compile))
        .route("/api/v1/script/inspect", post(handlers::inspect))
        .route("/api/v1/script/execute", post(handlers::execute))
        .route("/api/v1/script/cost", post(handlers::cost))
        .route("/api/v1/script/simulate", post(handlers::simulate))
        .route("/api/v1/script/explain", post(handlers::explain))
        .route("/api/v1/script/diff", post(handlers::diff))
        // Tier gate FIRST (outermost) so an unauthenticated T1 caller is
        // rejected before consuming a governor token; the governor then bounds
        // every admitted request at the Compute weight.
        .route_layer(axum::middleware::from_fn_with_state(
            governor.state(RouteClass::Compute),
            governor_mw,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            auth.state(tier),
            require_tier,
        ))
        .with_state(state)
}

// ==========================================================================
//  Shared primitives — thin wrappers over the ONE reduce / compile / parse
//  facade (D3). No reduction/cost/compile logic lives here.
// ==========================================================================

/// A boxed v1 error — helpers return `Result<_, Box<Response>>` so the `Ok`
/// value stays small (repo convention; clippy `result_large_err`).
pub(crate) fn err(
    reason: Reason,
    message: impl Into<String>,
    detail: impl Into<String>,
) -> Box<Response> {
    Box::new(v1_error(reason, message, detail))
}

/// Cap-check + hex-decode an `ergo_tree` input — the shared front half of
/// [`parse_tree_hex`]. The size cap is enforced BEFORE any allocation, so an
/// oversized body is refused without decoding it.
pub(crate) fn decode_tree_hex(hex_str: &str) -> Result<Vec<u8>, Box<Response>> {
    let hex_str = hex_str.trim();
    if hex_str.len() > MAX_TREE_HEX_LEN {
        return Err(err(
            Reason::LimitExceeded,
            "ergo_tree hex exceeds the size cap",
            format!("ergo_tree hex is capped at {MAX_TREE_HEX_LEN} characters"),
        ));
    }
    hex::decode(hex_str).map_err(|e| {
        err(
            Reason::InvalidHex,
            "ergo_tree is not valid hex",
            format!("hex decode: {e}"),
        )
    })
}

/// Parse raw `ergo_tree` bytes to an [`ErgoTree`] under the same size cap as
/// the hex path (so an address-derived tree cannot bypass it). A malformed
/// tree is `400 invalid_ergo_tree` — never a panic (fragment §6).
pub(crate) fn parse_tree_bytes(bytes: &[u8]) -> Result<ErgoTree, Box<Response>> {
    if bytes.len() * 2 > MAX_TREE_HEX_LEN {
        return Err(err(
            Reason::LimitExceeded,
            "ergo_tree exceeds the size cap",
            format!("ergo_tree hex is capped at {MAX_TREE_HEX_LEN} characters"),
        ));
    }
    let mut reader = ergo_primitives::reader::VlqReader::new(bytes);
    read_ergo_tree(&mut reader).map_err(|e| {
        err(
            Reason::InvalidErgoTree,
            "ergo_tree bytes do not parse",
            format!("read_ergo_tree: {e}"),
        )
    })
}

/// Parse an unprefixed `ergo_tree` hex string to an [`ErgoTree`], enforcing the
/// body-size cap first (see [`decode_tree_hex`] / [`parse_tree_bytes`]).
pub(crate) fn parse_tree_hex(hex_str: &str) -> Result<ErgoTree, Box<Response>> {
    parse_tree_bytes(&decode_tree_hex(hex_str)?)
}

/// Build a compiler [`ScriptEnv`] from the request `env` map: `{name: {type,
/// value}}`. Only the constant kinds the M6 `keysToEnv`/`Platform.liftToConstant`
/// surface accepts are supported; an unsupported kind is an honest
/// `400 bad_request` rather than a fabricated binding.
pub(crate) fn build_env(
    raw: Option<&std::collections::BTreeMap<String, TypedConstant>>,
) -> Result<ScriptEnv, Box<Response>> {
    let mut env = ScriptEnv::new();
    let Some(map) = raw else {
        return Ok(env);
    };
    for (name, tc) in map {
        env.insert(name.clone(), env_value_from_typed(name, tc)?);
    }
    Ok(env)
}

/// A typed constant on the wire: `{ "type": "<sigma type>", "value": "<string>" }`
/// (fragment §4.1). Scalars are decimal strings, byte collections / group
/// elements are hex, booleans are `"true"`/`"false"`.
#[derive(Debug, Clone, serde::Deserialize, ToSchema)]
pub struct TypedConstant {
    /// Lowercase-or-Scala sigma type name (`SInt`, `SLong`, `Coll[Byte]`, …).
    #[serde(rename = "type")]
    pub ty: String,
    /// The value as a string (decimal for numerics, hex for byte/group).
    pub value: String,
}

fn env_value_from_typed(name: &str, tc: &TypedConstant) -> Result<EnvValue, Box<Response>> {
    let bad = |what: &str| {
        err(
            Reason::BadRequest,
            format!("env entry `{name}` has an invalid {what}"),
            format!("type={:?} value={:?}", tc.ty, tc.value),
        )
    };
    let v = &tc.value;
    match tc.ty.as_str() {
        "Boolean" | "SBoolean" => match v.as_str() {
            "true" => Ok(EnvValue::Bool(true)),
            "false" => Ok(EnvValue::Bool(false)),
            _ => Err(bad("boolean value")),
        },
        "Byte" | "SByte" => v.parse::<i8>().map(EnvValue::Byte).map_err(|_| bad("byte value")),
        "Short" | "SShort" => v
            .parse::<i16>()
            .map(EnvValue::Short)
            .map_err(|_| bad("short value")),
        "Int" | "SInt" => v.parse::<i32>().map(EnvValue::Int).map_err(|_| bad("int value")),
        "Long" | "SLong" => v.parse::<i64>().map(EnvValue::Long).map_err(|_| bad("long value")),
        "BigInt" | "SBigInt" => {
            // The compiler validates the decimal form; pass it through.
            Ok(EnvValue::BigInt(v.clone()))
        }
        "Coll[Byte]" | "SColl[SByte]" => {
            let bytes = hex::decode(v.trim()).map_err(|_| bad("Coll[Byte] hex value"))?;
            Ok(EnvValue::ByteArray(bytes.into_iter().map(|b| b as i8).collect()))
        }
        "GroupElement" | "SGroupElement" => {
            let bytes = hex::decode(v.trim()).map_err(|_| bad("GroupElement hex value"))?;
            let arr: [u8; 33] = bytes.try_into().map_err(|_| bad("GroupElement length (need 33 bytes)"))?;
            Ok(EnvValue::GroupElement(
                ergo_primitives::group_element::GroupElement::from_bytes(arr),
            ))
        }
        _ => Err(err(
            Reason::BadRequest,
            format!("env entry `{name}` uses an unsupported type"),
            format!(
                "supported: Boolean, Byte, Short, Int, Long, BigInt, Coll[Byte], GroupElement; got {:?}",
                tc.ty
            ),
        )),
    }
}

/// Map a compiler [`CompileError`] to a v1 error [`Response`], carrying the
/// error position / phase / Scala class in `detail` for free (fragment §4.7).
pub(crate) fn compile_error_response(e: &CompileError) -> Box<Response> {
    let detail = format!(
        "position={} phase={} scala_class={}",
        e.pos(),
        compile_error_phase(e),
        e.class()
    );
    err(Reason::InvalidErgoTree, e.to_string(), detail)
}

/// The compile phase a [`CompileError`] failed in — a stable machine hint in
/// the error `detail`.
fn compile_error_phase(e: &CompileError) -> &'static str {
    match e {
        CompileError::Parse(_) => "parse",
        CompileError::Bind(_) => "bind",
        CompileError::Type(_) => "typecheck",
        CompileError::Root { .. } => "root",
        CompileError::Emit(_) => "emit",
        CompileError::Serializer { .. } => "serialize",
        CompileError::Write(_) => "write",
    }
}

// ----- the ONE bounded reduce primitive -----------------------------------

/// The outcome of a bounded reduction (`execute`/`cost`/`simulate`/`explain`
/// all funnel through [`bounded_reduce`]).
pub(crate) struct ReduceOutput {
    /// The sigma proposition the tree reduced to.
    pub reduced_to: SigmaBoolean,
    /// `Some(true|false)` only when it collapsed to a `TrivialProp`; else
    /// `None` (the caller must prove the returned proposition).
    pub result: Option<bool>,
    /// Consumed cost, block-cost units.
    pub block_cost: u64,
}

/// Reduce `tree` against a minimal context on the EXACT interpreter path
/// ([`reduce_expr_with_cost`]), bounded by an ENFORCING [`CostAccumulator`] at
/// `limit_block_cost` — the load-bearing anti-DoS control (D2 / fragment §6).
/// A cost-over-limit is surfaced as [`EvalError::CostExceeded`], never a hang;
/// evaluation depth is independently bounded by the interpreter's
/// `MAX_EVAL_DEPTH`.
///
/// `self_box` is optional (a bare-tree eval needs no `SELF`); `height` feeds
/// `CONTEXT.HEIGHT`. Rich context (inputs/outputs/data-inputs/extension) is a
/// documented follow-on — a script reading them errors honestly (`script_error`)
/// rather than silently seeing empty collections drive a wrong verdict.
pub(crate) fn bounded_reduce(
    tree: &ErgoTree,
    height: u32,
    self_box: Option<&EvalBox>,
    limit_block_cost: u64,
) -> Result<ReduceOutput, EvalError> {
    let (mut cost, ctx) = reduction_env(tree, height, self_box, limit_block_cost);
    let reduced_to = reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost)?;
    let result = match reduced_to {
        SigmaBoolean::TrivialProp(b) => Some(b),
        _ => None,
    };
    Ok(ReduceOutput {
        reduced_to,
        result,
        block_cost: cost.total_block_cost(),
    })
}

/// [`bounded_reduce`]'s traced sibling for `script/explain`: the SAME
/// reduction environment (one owner — any future context or cost change lands
/// in [`reduction_env`] once), but through the interpreter's trace walker.
pub(crate) fn bounded_reduce_traced(
    tree: &ErgoTree,
    height: u32,
    self_box: Option<&EvalBox>,
    limit_block_cost: u64,
) -> (Result<SigmaBoolean, EvalError>, Vec<TraceEntry>) {
    let (mut cost, ctx) = reduction_env(tree, height, self_box, limit_block_cost);
    reduce_expr_traced_with_cost(&tree.body, &ctx, &tree.constants, &mut cost)
}

/// The one place the playground wires the cost accumulator + minimal
/// reduction context, so the plain and traced reduce paths can never drift.
fn reduction_env<'a>(
    tree: &ErgoTree,
    height: u32,
    self_box: Option<&'a EvalBox>,
    limit_block_cost: u64,
) -> (CostAccumulator, ReductionContext<'a>) {
    let limit = JitCost::from_block_cost(limit_block_cost.clamp(1, MAX_BLOCK_COST))
        .unwrap_or_else(|_| JitCost::from_jit(10));
    let self_ch = self_box.map(|b| b.creation_height).unwrap_or(height);
    let mut ctx = ReductionContext::minimal(height, self_ch);
    ctx.self_box = self_box;
    ctx.ergo_tree_version = tree.version;
    (CostAccumulator::new(limit), ctx)
}

/// Map an [`EvalError`] from the reduce path to the v1 envelope. Cost / depth
/// refusals get DISTINCT reasons (`cost_limit` / `too_deep`) so a caller
/// distinguishes a resource refusal from a genuine script error
/// (fragment §4.0).
pub(crate) fn eval_error_response(e: &EvalError) -> Box<Response> {
    match e {
        EvalError::CostExceeded(_) | EvalError::JitCostOverflow(_) => err(
            Reason::CostLimit,
            "script reduction exceeded the per-request cost bound",
            e.to_string(),
        ),
        EvalError::DepthLimitExceeded(_) => err(
            Reason::TooDeep,
            "script reduction exceeded the evaluation-depth bound",
            e.to_string(),
        ),
        _ => err(
            Reason::ScriptError,
            "the script failed to reduce",
            e.to_string(),
        ),
    }
}

// ----- rendering ----------------------------------------------------------

/// Render a [`SigmaBoolean`] to a stable human string for `reduced_to`.
pub(crate) fn render_sigma_boolean(sb: &SigmaBoolean) -> String {
    format!("{sb:?}")
}

/// A lowercase-ish sigma type name for the `inspect` constants view.
pub(crate) fn sigma_type_name(t: &SigmaType) -> String {
    format!("{t:?}")
}

/// A stable string rendering of a segregated constant value.
pub(crate) fn render_sigma_value(v: &SigmaValue) -> String {
    format!("{v:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn tc(ty: &str, value: &str) -> TypedConstant {
        TypedConstant {
            ty: ty.to_string(),
            value: value.to_string(),
        }
    }

    // ----- happy path -----

    #[test]
    fn effective_cost_limit_clamps_and_lowers_only() {
        let cfg = ScriptConfig::default();
        // No request cap ⇒ the group ceiling.
        assert_eq!(cfg.effective_cost_limit(None), MAX_BLOCK_COST);
        // A request cap only lowers.
        assert_eq!(cfg.effective_cost_limit(Some(100)), 100);
        // A request cap ABOVE the ceiling is clamped down, never raised.
        assert_eq!(cfg.effective_cost_limit(Some(u64::MAX)), MAX_BLOCK_COST);
        // Zero clamps to at least 1.
        assert_eq!(cfg.effective_cost_limit(Some(0)), 1);
    }

    #[test]
    fn build_env_supports_the_liftable_scalar_kinds() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("a".to_string(), tc("Int", "42"));
        m.insert("b".to_string(), tc("Long", "9000000000"));
        m.insert("c".to_string(), tc("Boolean", "true"));
        let env = build_env(Some(&m)).expect("liftable scalars build an env");
        assert!(env.contains("a") && env.contains("b") && env.contains("c"));
    }

    // ----- error paths -----

    #[test]
    fn build_env_rejects_unsupported_type() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("x".to_string(), tc("Header", "deadbeef"));
        assert!(
            build_env(Some(&m)).is_err(),
            "unsupported env type is a 400"
        );
    }

    #[test]
    fn build_env_rejects_malformed_scalar() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("x".to_string(), tc("Int", "not-a-number"));
        assert!(build_env(Some(&m)).is_err());
    }

    #[test]
    fn parse_tree_hex_rejects_bad_hex() {
        assert!(parse_tree_hex("zz").is_err());
    }
}
