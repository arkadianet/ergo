//! The seven `script/*` route handlers — each a thin adapter over the ONE
//! reduce / compile / parse facade in [`super`] (locked decision D3). No
//! handler owns reduction, cost, or compile logic.

use std::collections::BTreeMap;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use ergo_ser::address::{decode_address_to_tree_bytes, encode_p2s, encode_p2sh};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::{Body, IrNode, Payload};
use ergo_sigma::evaluator::{reduce_expr_traced_with_cost, EvalBox, ReductionContext};

use ergo_primitives::cost::{CostAccumulator, JitCost};

use super::{
    bounded_reduce, build_env, compile_error_response, err, eval_error_response, parse_tree_hex,
    render_sigma_boolean, render_sigma_value, sigma_type_name, ScriptState, TypedConstant,
    MAX_BLOCK_COST, MAX_SOURCE_LEN,
};
use crate::compat::types::ScalaOutput;
use crate::v1::error::Reason;
use crate::v1::routes::extract::V1Json;

// A trace entry cap: the one place a response array is bounded in lieu of
// pagination (fragment §4.3).
const MAX_TRACE_ENTRIES: usize = 4096;

// ----- shared helpers -----------------------------------------------------

/// An unprefixed 64-char hex id → 32 raw bytes, or `None` (wrong length /
/// non-hex).
fn parse_id32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// Resolve the [`ErgoTree`] a request names — exactly one of `ergo_tree` (hex,
/// parsed) or `source` (compiled). Two-or-none is a `400 bad_request`.
fn resolve_tree(
    state: &ScriptState,
    ergo_tree: Option<&str>,
    source: Option<&str>,
    tree_version: u8,
    env: Option<&BTreeMap<String, TypedConstant>>,
) -> Result<ErgoTree, Box<Response>> {
    match (ergo_tree, source) {
        (Some(hex_str), None) => parse_tree_hex(hex_str),
        (None, Some(src)) => {
            if src.len() > MAX_SOURCE_LEN {
                return Err(err(
                    Reason::LimitExceeded,
                    "source exceeds the size cap",
                    format!("source is capped at {MAX_SOURCE_LEN} characters"),
                ));
            }
            let script_env = build_env(env)?;
            ergo_compiler::compile(&script_env, src, tree_version, state.network)
                .map(|r| r.ergo_tree)
                .map_err(|e| compile_error_response(&e))
        }
        (Some(_), Some(_)) => Err(err(
            Reason::BadRequest,
            "provide exactly one of `ergo_tree` or `source`",
            "the two inputs are mutually exclusive",
        )),
        (None, None) => Err(err(
            Reason::BadRequest,
            "provide `ergo_tree` (hex) or `source` (ErgoScript)",
            "one script input is required",
        )),
    }
}

/// The effective block-height for an `execute`/`cost` context: the caller's
/// `height`, else the node tip.
fn context_height(state: &ScriptState, ctx: Option<&ContextDto>) -> u32 {
    ctx.and_then(|c| c.height)
        .unwrap_or_else(|| state.read.tip().best_full_block.height)
}

/// Build an optional `SELF` [`EvalBox`] from the context. Registers / tokens
/// are a documented follow-on (fragment §7-D2 single-box first cut); a script
/// reading them errors honestly rather than seeing empty defaults drive a wrong
/// verdict.
fn self_box_from_ctx(
    ctx: Option<&ContextDto>,
    height: u32,
) -> Result<Option<EvalBox>, Box<Response>> {
    let Some(sb) = ctx.and_then(|c| c.self_box.as_ref()) else {
        return Ok(None);
    };
    let script_bytes = match sb.ergo_tree.as_deref() {
        Some(h) => hex::decode(h.trim()).map_err(|e| {
            err(
                Reason::InvalidHex,
                "context.self.ergo_tree is not valid hex",
                format!("hex decode: {e}"),
            )
        })?,
        None => Vec::new(),
    };
    let value = match sb.value.as_deref() {
        Some(v) => v.parse::<i64>().map_err(|_| {
            err(
                Reason::InvalidParams,
                "context.self.value must be a decimal nanoERG string",
                "value is a u64 encoded as a base-10 string",
            )
        })?,
        None => 0,
    };
    let creation_height = sb.creation_height.unwrap_or(height);
    let mut b = EvalBox::simple(creation_height, script_bytes);
    b.value = value;
    Ok(Some(b))
}

// ==========================================================================
//  POST /api/v1/script/compile   (fragment §4.7)
// ==========================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileBody {
    source: String,
    #[serde(default)]
    tree_version: u8,
    #[serde(default)]
    env: Option<BTreeMap<String, TypedConstant>>,
}

#[derive(Debug, Serialize)]
struct CompileResponse {
    ergo_tree: String,
    tree_bytes: String,
    p2s_address: String,
    p2sh_address: String,
    typed_ast: String,
    size: usize,
    warnings: Vec<String>,
}

/// `POST /script/compile` — ErgoScript source → tree / address / typed-AST.
/// A thin adapter over [`ergo_compiler::compile`]; a compile error is the v1
/// envelope with the error position / phase / Scala class in `detail`.
pub async fn compile(State(state): State<ScriptState>, body: V1Json<CompileBody>) -> Response {
    let V1Json(body) = body;
    match compile_inner(&state, body) {
        Ok(resp) => Json(resp).into_response(),
        Err(resp) => *resp,
    }
}

fn compile_inner(state: &ScriptState, body: CompileBody) -> Result<CompileResponse, Box<Response>> {
    if body.source.len() > MAX_SOURCE_LEN {
        return Err(err(
            Reason::LimitExceeded,
            "source exceeds the size cap",
            format!("source is capped at {MAX_SOURCE_LEN} characters"),
        ));
    }
    let script_env = build_env(body.env.as_ref())?;
    let result =
        ergo_compiler::compile(&script_env, &body.source, body.tree_version, state.network)
            .map_err(|e| compile_error_response(&e))?;

    // `typed_ast` from a typecheck pass (compose, don't re-run the compiler
    // differently — same env/source/version). Best-effort: compile already
    // typechecked, so this succeeds; on the off chance the printer path
    // diverges, fall back to an empty string rather than fail the whole call.
    let typed_ast = ergo_compiler::typecheck_with_network(
        &script_env,
        &body.source,
        body.tree_version,
        state.network,
    )
    .map(|typed| ergo_compiler::print_typed(&typed))
    .unwrap_or_default();

    Ok(CompileResponse {
        ergo_tree: hex::encode(&result.tree_bytes),
        tree_bytes: hex::encode(&result.tree_bytes),
        size: result.tree_bytes.len(),
        p2s_address: result.p2s_address,
        p2sh_address: result.p2sh_address,
        typed_ast,
        // The compiler surfaces no warning channel yet — honest empty, not a
        // fabricated list.
        warnings: Vec::new(),
    })
}

// ==========================================================================
//  POST /api/v1/script/inspect   (fragment §4.2)
// ==========================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectBody {
    #[serde(default)]
    ergo_tree: Option<String>,
    #[serde(default)]
    address: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConstantView {
    index: usize,
    #[serde(rename = "type")]
    ty: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct InspectResponse {
    ergo_tree_version: u8,
    has_size: bool,
    constant_segregation: bool,
    constants: Vec<ConstantView>,
    opcode_count: usize,
    size: usize,
    p2s_address: String,
    p2sh_address: String,
}

/// `POST /script/inspect` — decompile an `ergo_tree` (hex) or `address` into a
/// structured typed view. Pure parse; no eval, no chain read.
pub async fn inspect(State(state): State<ScriptState>, body: V1Json<InspectBody>) -> Response {
    let V1Json(body) = body;
    match inspect_inner(&state, body) {
        Ok(resp) => Json(resp).into_response(),
        Err(resp) => *resp,
    }
}

fn inspect_inner(state: &ScriptState, body: InspectBody) -> Result<InspectResponse, Box<Response>> {
    let tree_bytes = match (body.ergo_tree.as_deref(), body.address.as_deref()) {
        (Some(hex_str), None) => hex::decode(hex_str.trim()).map_err(|e| {
            err(
                Reason::InvalidHex,
                "ergo_tree is not valid hex",
                format!("hex decode: {e}"),
            )
        })?,
        (None, Some(addr)) => decode_address_to_tree_bytes(addr, state.network).map_err(|e| {
            err(
                Reason::InvalidAddress,
                "address is not valid base58 for this network",
                e.to_string(),
            )
        })?,
        (Some(_), Some(_)) => {
            return Err(err(
                Reason::BadRequest,
                "provide exactly one of `ergo_tree` or `address`",
                "the two inputs are mutually exclusive",
            ))
        }
        (None, None) => {
            return Err(err(
                Reason::BadRequest,
                "provide `ergo_tree` (hex) or `address` (base58)",
                "one input is required",
            ))
        }
    };
    let tree = parse_tree_hex(&hex::encode(&tree_bytes))?;

    let constants = tree
        .constants
        .iter()
        .enumerate()
        .map(|(index, (ty, val))| ConstantView {
            index,
            ty: sigma_type_name(ty),
            value: render_sigma_value(val),
        })
        .collect();

    Ok(InspectResponse {
        ergo_tree_version: tree.version,
        has_size: tree.has_size,
        constant_segregation: tree.constant_segregation,
        constants,
        opcode_count: count_nodes(&tree.body),
        size: tree_bytes.len(),
        p2s_address: encode_p2s(state.network, &tree_bytes),
        p2sh_address: encode_p2sh(state.network, &tree_bytes),
    })
}

/// Count the opcode nodes in a body (a coarse complexity signal). Exhaustive
/// over [`Payload`] so a future variant cannot silently under-count.
fn count_nodes(body: &Body) -> usize {
    let node = match body {
        Body::Const { .. } | Body::Unparsed(_) => return 1,
        Body::Op(node) => node,
    };
    1 + count_payload(node)
}

fn count_payload(node: &IrNode) -> usize {
    match &node.payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::NoneValue { .. }
        | Payload::DeserializeContext { .. } => 0,
        Payload::One(a) => count_nodes(a),
        Payload::Two(a, b) => count_nodes(a) + count_nodes(b),
        Payload::Three(a, b, c) => count_nodes(a) + count_nodes(b) + count_nodes(c),
        Payload::Four(a, b, c, d) => {
            count_nodes(a) + count_nodes(b) + count_nodes(c) + count_nodes(d)
        }
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => count_nodes(rhs),
        Payload::BlockValue { items, result } => {
            items.iter().map(count_nodes).sum::<usize>() + count_nodes(result)
        }
        Payload::FuncValue { body, .. } => count_nodes(body),
        Payload::MethodCall { obj, args, .. } => {
            count_nodes(obj) + args.iter().map(count_nodes).sum::<usize>()
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter().map(count_nodes).sum(),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => count_nodes(input),
        Payload::DeserializeRegister { default, .. } => {
            default.as_deref().map(count_nodes).unwrap_or(0)
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            count_nodes(input)
                + count_nodes(index)
                + default.as_deref().map(count_nodes).unwrap_or(0)
        }
        Payload::FuncApply { func, args } => {
            count_nodes(func) + args.iter().map(count_nodes).sum::<usize>()
        }
    }
}

// ==========================================================================
//  POST /api/v1/script/execute   (fragment §4.3)  — cost governor MANDATORY
// ==========================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteBody {
    #[serde(default)]
    ergo_tree: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    tree_version: u8,
    #[serde(default)]
    env: Option<BTreeMap<String, TypedConstant>>,
    #[serde(default)]
    context: Option<ContextDto>,
    /// Per-request cost ceiling (block-cost units). May only LOWER the group
    /// ceiling, never raise it (fragment §4.3).
    #[serde(default)]
    max_cost: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextDto {
    #[serde(default)]
    height: Option<u32>,
    #[serde(rename = "self", default)]
    self_box: Option<SelfBoxDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfBoxDto {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    ergo_tree: Option<String>,
    #[serde(default)]
    creation_height: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ExecuteResponse {
    reduced_to: String,
    result: Option<bool>,
    cost: u64,
    within_block_limit: bool,
}

/// `POST /script/execute` — reduce a tree/source against a context on the exact
/// block-validation path, **bounded by the cost governor** (D2). A script that
/// would exceed the per-request cost cap answers `400 cost_limit`, never hangs.
pub async fn execute(State(state): State<ScriptState>, body: V1Json<ExecuteBody>) -> Response {
    let V1Json(body) = body;
    match execute_inner(&state, body) {
        Ok(resp) => Json(resp).into_response(),
        Err(resp) => *resp,
    }
}

fn execute_inner(state: &ScriptState, body: ExecuteBody) -> Result<ExecuteResponse, Box<Response>> {
    let tree = resolve_tree(
        state,
        body.ergo_tree.as_deref(),
        body.source.as_deref(),
        body.tree_version,
        body.env.as_ref(),
    )?;
    let height = context_height(state, body.context.as_ref());
    let self_box = self_box_from_ctx(body.context.as_ref(), height)?;
    let limit = state.config.effective_cost_limit(body.max_cost);

    let out = bounded_reduce(&tree, height, self_box.as_ref(), limit)
        .map_err(|e| eval_error_response(&e))?;
    Ok(ExecuteResponse {
        reduced_to: render_sigma_boolean(&out.reduced_to),
        result: out.result,
        cost: out.block_cost,
        within_block_limit: out.block_cost <= MAX_BLOCK_COST,
    })
}

// ==========================================================================
//  POST /api/v1/script/cost   (fragment §4.4)  — cost governor MANDATORY
// ==========================================================================

#[derive(Debug, Serialize)]
struct CostResponse {
    total_cost: u64,
    within_block_limit: bool,
    /// A per-opcode `breakdown` is gated on the interpreter's `cost-trace`
    /// feature (fragment §4.4); until that is wired at the API seam the field
    /// is an honest empty array, not a fabricated split.
    breakdown: Vec<CostBreakdownEntry>,
}

#[derive(Debug, Serialize)]
struct CostBreakdownEntry {
    op: String,
    cost: u64,
}

/// `POST /script/cost` — the total reduce cost under a bounded accumulator.
/// Same request shape as `execute`; reuses the SAME bounded reduce primitive
/// (compose, don't reimplement the cost accounting — fragment §4.4).
pub async fn cost(State(state): State<ScriptState>, body: V1Json<ExecuteBody>) -> Response {
    let V1Json(body) = body;
    match cost_inner(&state, body) {
        Ok(resp) => Json(resp).into_response(),
        Err(resp) => *resp,
    }
}

fn cost_inner(state: &ScriptState, body: ExecuteBody) -> Result<CostResponse, Box<Response>> {
    let tree = resolve_tree(
        state,
        body.ergo_tree.as_deref(),
        body.source.as_deref(),
        body.tree_version,
        body.env.as_ref(),
    )?;
    let height = context_height(state, body.context.as_ref());
    let self_box = self_box_from_ctx(body.context.as_ref(), height)?;
    let limit = state.config.effective_cost_limit(body.max_cost);

    let out = bounded_reduce(&tree, height, self_box.as_ref(), limit)
        .map_err(|e| eval_error_response(&e))?;
    Ok(CostResponse {
        total_cost: out.block_cost,
        within_block_limit: out.block_cost <= MAX_BLOCK_COST,
        breakdown: Vec::new(),
    })
}

// ==========================================================================
//  POST /api/v1/script/simulate   (fragment §4.5)  — node-only differentiator
// ==========================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulateBody {
    box_id: String,
    #[serde(default)]
    at_height: Option<u32>,
    #[serde(default)]
    max_cost: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SimulateResponse {
    spendable: bool,
    reduced_to: String,
    result: Option<bool>,
    cost: u64,
    at_height: u32,
    /// Honest scope marker: this first cut reduces the real box's guard against
    /// a single-box context (no spending tx, no proof verification) — fragment
    /// §7-D2. A `reduced_to` sigma proposition means "spendable with the right
    /// proof", not a verified spend.
    note: &'static str,
}

/// `POST /script/simulate` — resolve a REAL on-chain box and reduce its guard
/// against real chain state. `box_id` missing ⇒ `box_not_found`; the chain
/// reader unwired ⇒ `chain_reader_unavailable` (never a bare 404).
pub async fn simulate(State(state): State<ScriptState>, body: V1Json<SimulateBody>) -> Response {
    let V1Json(body) = body;
    match simulate_inner(&state, body) {
        Ok(resp) => Json(resp).into_response(),
        Err(resp) => *resp,
    }
}

/// Resolve the real box + build its `SELF` [`EvalBox`] and the effective
/// height — the shared context builder for `simulate` and `explain`.
fn resolve_real_box(
    state: &ScriptState,
    box_id: &str,
    at_height: Option<u32>,
) -> Result<(EvalBox, ErgoTree, u32), Box<Response>> {
    if parse_id32(box_id).is_none() {
        return Err(err(
            Reason::InvalidBoxId,
            "box_id is not a 64-character hex id",
            "supply an unprefixed hex box id",
        ));
    }
    let Some(chain) = state.chain.as_ref() else {
        return Err(err(
            Reason::ChainReaderUnavailable,
            "box lookups require the live-store chain reader",
            "this node was wired without the NodeChainQuery bridge",
        ));
    };
    let Some(output) = chain.utxo_box_by_id(box_id) else {
        return Err(err(
            Reason::BoxNotFound,
            "no unspent box with that id",
            "the box is spent or was never created",
        ));
    };
    let eval_box = eval_box_from_scala(&output)?;
    let tree = parse_tree_hex(&output.ergo_tree)?;
    let height = at_height.unwrap_or_else(|| state.read.tip().best_full_block.height);
    Ok((eval_box, tree, height))
}

fn simulate_inner(
    state: &ScriptState,
    body: SimulateBody,
) -> Result<SimulateResponse, Box<Response>> {
    let (eval_box, tree, height) = resolve_real_box(state, &body.box_id, body.at_height)?;
    let limit = state.config.effective_cost_limit(body.max_cost);
    let out = bounded_reduce(&tree, height, Some(&eval_box), limit)
        .map_err(|e| eval_error_response(&e))?;
    Ok(SimulateResponse {
        spendable: out.result != Some(false),
        reduced_to: render_sigma_boolean(&out.reduced_to),
        result: out.result,
        cost: out.block_cost,
        at_height: height,
        note: "single-box reduction: no spending tx or proof verified (fragment §7-D2)",
    })
}

/// Convert a [`ScalaOutput`] (the chain reader's box shape) into an
/// [`EvalBox`]. Registers are a documented follow-on — a script reading its own
/// registers errors honestly (`script_error`) rather than silently seeing
/// `None` (fragment §7-D2 single-box first cut).
fn eval_box_from_scala(o: &ScalaOutput) -> Result<EvalBox, Box<Response>> {
    let script_bytes = hex::decode(o.ergo_tree.trim()).map_err(|e| {
        err(
            Reason::InvalidErgoTree,
            "the resolved box has an unparseable ergo_tree",
            format!("hex decode: {e}"),
        )
    })?;
    let id = parse_id32(&o.box_id).unwrap_or([0u8; 32]);
    let transaction_id = parse_id32(&o.transaction_id).unwrap_or([0u8; 32]);
    let mut tokens = Vec::with_capacity(o.assets.len());
    for a in &o.assets {
        let tid = parse_id32(&a.token_id).ok_or_else(|| {
            err(
                Reason::InvalidTokenId,
                "the resolved box has a malformed token id",
                "token ids are 64-char hex",
            )
        })?;
        tokens.push((tid, a.amount));
    }
    let mut b = EvalBox::simple(o.creation_height, script_bytes);
    b.value = o.value as i64;
    b.id = id;
    b.transaction_id = transaction_id;
    b.output_index = o.index;
    b.tokens = tokens;
    Ok(b)
}

// ==========================================================================
//  POST /api/v1/script/explain   (fragment §4.6)  — the debugger
// ==========================================================================

#[derive(Debug, Serialize)]
struct TraceView {
    label: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ExplainResponse {
    spendable: bool,
    reduced_to: Option<String>,
    reduction_trace: Vec<TraceView>,
    trace_truncated: bool,
    at_height: u32,
    human_diagnosis: String,
}

/// `POST /script/explain` — same input as `simulate`, plus the mechanical
/// diagnosis: the reduction trace and a best-effort human line. The mechanical
/// fields ship in the node; the `human_diagnosis` is explicitly
/// non-authoritative (fragment §7-D3).
pub async fn explain(State(state): State<ScriptState>, body: V1Json<SimulateBody>) -> Response {
    let V1Json(body) = body;
    match explain_inner(&state, body) {
        Ok(resp) => Json(resp).into_response(),
        Err(resp) => *resp,
    }
}

fn explain_inner(
    state: &ScriptState,
    body: SimulateBody,
) -> Result<ExplainResponse, Box<Response>> {
    let (eval_box, tree, height) = resolve_real_box(state, &body.box_id, body.at_height)?;
    let limit = state.config.effective_cost_limit(body.max_cost);

    // Traced reduction on the SAME interpreter path, bounded by the cost
    // governor. The trace walker adds no reduction logic — it renders the
    // interpreter's own `TraceEntry` stream.
    let jit_limit = JitCost::from_block_cost(limit.clamp(1, MAX_BLOCK_COST))
        .unwrap_or_else(|_| JitCost::from_jit(10));
    let mut cost = CostAccumulator::new(jit_limit);
    let mut ctx = ReductionContext::minimal(height, eval_box.creation_height);
    ctx.self_box = Some(&eval_box);
    ctx.ergo_tree_version = tree.version;
    let (result, entries) =
        reduce_expr_traced_with_cost(&tree.body, &ctx, &tree.constants, &mut cost);

    let trace_truncated = entries.len() > MAX_TRACE_ENTRIES;
    let reduction_trace: Vec<TraceView> = entries
        .into_iter()
        .take(MAX_TRACE_ENTRIES)
        .map(|e| TraceView {
            label: e.label,
            value: e.value,
        })
        .collect();

    let (spendable, reduced_to, diagnosis) = match result {
        Ok(sb) => {
            let trivial_false =
                matches!(sb, ergo_ser::sigma_value::SigmaBoolean::TrivialProp(false));
            let diag = if trivial_false {
                "the guard reduced to a statically-false proposition — unspendable at this height/context".to_string()
            } else {
                "the guard reduced to a satisfiable proposition (a valid proof would spend it)"
                    .to_string()
            };
            (!trivial_false, Some(render_sigma_boolean(&sb)), diag)
        }
        Err(e) => (
            false,
            None,
            format!("the guard errored during reduction: {e}"),
        ),
    };

    Ok(ExplainResponse {
        spendable,
        reduced_to,
        reduction_trace,
        trace_truncated,
        at_height: height,
        human_diagnosis: diagnosis,
    })
}

// ==========================================================================
//  POST /api/v1/script/diff   (fragment §4.8)  — opt-in Scala oracle
// ==========================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffBody {
    #[serde(default)]
    ergo_tree: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    tree_version: u8,
    #[serde(default)]
    env: Option<BTreeMap<String, TypedConstant>>,
    #[serde(default)]
    context: Option<ContextDto>,
    #[serde(default)]
    max_cost: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DiffSide {
    verdict: &'static str,
    reduced_to: Option<String>,
    cost: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Divergence {
    field: &'static str,
    rust: String,
    scala: String,
}

#[derive(Debug, Serialize)]
struct DiffResponse {
    rust: DiffSide,
    scala: DiffSide,
    agree: bool,
    divergence: Option<Divergence>,
}

/// `POST /script/diff` — reduce via OUR path AND the Scala oracle, diff the
/// verdict. **Unconfigured oracle ⇒ `oracle_unavailable`** (D3 residual; the
/// oracle is never required to exist). The Rust side runs under the same
/// bounded cost governor as `execute`.
pub async fn diff(State(state): State<ScriptState>, body: V1Json<DiffBody>) -> Response {
    let V1Json(body) = body;
    match diff_inner(&state, body).await {
        Ok(resp) => Json(resp).into_response(),
        Err(resp) => *resp,
    }
}

async fn diff_inner(state: &ScriptState, body: DiffBody) -> Result<DiffResponse, Box<Response>> {
    let Some(oracle) = state.oracle.as_ref() else {
        return Err(err(
            Reason::OracleUnavailable,
            "no Scala reference oracle is configured",
            "configure a Scala node or bundled reducer to enable script/diff",
        ));
    };

    let tree = resolve_tree(
        state,
        body.ergo_tree.as_deref(),
        body.source.as_deref(),
        body.tree_version,
        body.env.as_ref(),
    )?;
    let height = context_height(state, body.context.as_ref());
    let self_box = self_box_from_ctx(body.context.as_ref(), height)?;
    let limit = state.config.effective_cost_limit(body.max_cost);

    // Rust side: our verdict + reduced proposition + cost.
    let rust = match bounded_reduce(&tree, height, self_box.as_ref(), limit) {
        Ok(out) => DiffSide {
            verdict: "accept",
            reduced_to: Some(render_sigma_boolean(&out.reduced_to)),
            cost: Some(out.block_cost),
        },
        Err(_) => DiffSide {
            verdict: "reject",
            reduced_to: None,
            cost: None,
        },
    };

    // Scala side via the configured oracle transport.
    let tree_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::ergo_tree::write_ergo_tree(&mut w, &tree).map_err(|e| {
            err(
                Reason::InvalidErgoTree,
                "the tree could not be re-serialized for the oracle",
                e.to_string(),
            )
        })?;
        w.result()
    };
    let scala = match oracle.reduce_tree(&tree_bytes, height).await {
        Ok(v) => DiffSide {
            verdict: if v.accept { "accept" } else { "reject" },
            reduced_to: v.reduced_to,
            cost: v.cost,
        },
        Err(detail) => {
            return Err(err(
                Reason::OracleUnavailable,
                "the Scala reference oracle failed to respond",
                detail,
            ))
        }
    };

    let divergence = if rust.verdict != scala.verdict {
        Some(Divergence {
            field: "verdict",
            rust: rust.verdict.to_string(),
            scala: scala.verdict.to_string(),
        })
    } else if rust.reduced_to != scala.reduced_to {
        Some(Divergence {
            field: "reduced_to",
            rust: rust.reduced_to.clone().unwrap_or_default(),
            scala: scala.reduced_to.clone().unwrap_or_default(),
        })
    } else {
        None
    };

    Ok(DiffResponse {
        agree: divergence.is_none(),
        divergence,
        rust,
        scala,
    })
}
