use ergo_primitives::cost::CostAccumulator;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use super::cost::*;
use super::dispatch::*;
use super::helpers::*;
use super::types::*;

// Shared builders remain in this module for every behavior file.
// ── Per-opcode evaluation tests ──────────────────────────────
//
// Sections below follow the AGENTS.md test convention:
//   helpers -> happy path -> error paths -> oracle parity.
// Multi-batch happy-path corpora are grouped by topic with their
// own `// ── Batch N: ...` sub-headers retained for navigation.

// ----- helpers -----

fn op(opcode: u8, payload: Payload) -> Expr {
    Expr::Op(IrNode { opcode, payload })
}

fn const_int(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(v),
    }
}

fn const_long(v: i64) -> Expr {
    Expr::Const {
        tpe: SigmaType::SLong,
        val: SigmaValue::Long(v),
    }
}

fn const_bool(v: bool) -> Expr {
    Expr::Const {
        tpe: SigmaType::SBoolean,
        val: SigmaValue::Boolean(v),
    }
}

fn const_bytes(v: Vec<u8>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(v)),
    }
}

/// A flat `(Int, Int, ...)` tuple as a CONSTANT. Tuples with more than 2
/// elements only exist as values/constants (STuple = Coll[Any]); the
/// `0x86 CreateTuple` opcode evaluates only pairs (Scala `Tuple.eval`
/// errors for arity != 2). Use this to exercise SelectField on >2-element
/// tuples without building a non-evaluable CreateTuple node.
fn int_tuple_const(vals: &[i32]) -> Expr {
    Expr::Const {
        tpe: SigmaType::STuple(vals.iter().map(|_| SigmaType::SInt).collect()),
        val: SigmaValue::Tuple(vals.iter().map(|&v| SigmaValue::Int(v)).collect()),
    }
}

fn run_eval(expr: &Expr) -> Value {
    eval_to_value(expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap()
}

fn run_eval_ctx(expr: &Expr, ctx: &ReductionContext<'_>) -> Value {
    eval_to_value(expr, ctx, &[]).unwrap()
}

fn run_eval_with_constants(expr: &Expr, constants: &[(SigmaType, SigmaValue)]) -> Value {
    eval_to_value(expr, &ReductionContext::minimal(500_000, 0), constants).unwrap()
}

fn const_coll_int(vals: Vec<i32>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SInt)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter().map(SigmaValue::Int).collect(),
        )),
    }
}

fn const_coll_bool(vals: Vec<bool>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SBoolean)),
        val: SigmaValue::Coll(CollValue::BoolBits(vals)),
    }
}

fn run_eval_err(expr: &Expr) -> EvalError {
    eval_to_value(expr, &ReductionContext::minimal(500_000, 0), &[]).unwrap_err()
}

fn make_test_box() -> EvalBox {
    EvalBox {
        lazy_vals: Default::default(),
        creation_height: 500_000,
        script_bytes: vec![0x00, 0x08, 0xCD],
        value: 1_000_000_000,
        id: {
            let mut id = [0u8; 32];
            id[0] = 0xAA;
            id[31] = 0xBB;
            id
        },
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [
            Some(ergo_ser::register::RegisterValue {
                tpe: SigmaType::SInt,
                value: SigmaValue::Int(42),
            }),
            Some(ergo_ser::register::RegisterValue {
                tpe: SigmaType::SLong,
                value: SigmaValue::Long(999),
            }),
            None,
            None,
            None,
            None,
        ],
        tokens: vec![([0x11; 32], 100), ([0x22; 32], 200)],
        raw_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        register_bytes: Vec::new(),
    }
}

fn ctx_with_self_box(b: &EvalBox) -> ReductionContext<'_> {
    ReductionContext {
        validation_settings: Default::default(),
        height: 600_000,
        self_box: Some(b),
        self_creation_height: b.creation_height,
        outputs: &[],
        inputs: &[],
        data_inputs: &[],
        miner_pubkey: [0x33; 33],
        pre_header_timestamp: 1_700_000_000_000,
        extension: indexmap::IndexMap::new(),
        last_headers: &[],
        last_block_utxo_root: None,
        // EIP-50 / Sigma 6.0 activated — same rationale as
        // `ReductionContext::minimal`'s default. Lets v6 MethodCall
        // tests share this helper.
        activated_script_version: 3,
        ergo_tree_version: 3,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
        input_extensions: &[],
    }
}

fn extract_register_as(reg_id: u8, tpe: SigmaType) -> Expr {
    op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)),
            reg_id,
            tpe,
        },
    )
}

/// `SELF.getReg[Int](idx)` as a v6 MethodCall with an Int index const.
fn getreg_v6_int_index(idx: i32) -> Expr {
    Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 99,
            method_id: 19,
            obj: Box::new(op(0xA7, Payload::Zero)),
            args: vec![const_int(idx)],
            type_args: vec![SigmaType::SInt],
        },
    })
}

fn by_index_with_default(coll: Expr, idx: i32, default: Expr) -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(const_int(idx)),
            default: Some(Box::new(default)),
        },
    )
}

/// Default whose evaluation carries its own opcode cost (SizeOf).
fn costed_default() -> Expr {
    op(0xB1, Payload::One(Box::new(const_coll_int(vec![7, 8]))))
}

/// Default whose evaluation errors (ByIndex out of range, no default).
fn erroring_default() -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(const_coll_int(vec![])),
            index: Box::new(const_int(0)),
            default: None,
        },
    )
}

fn ctx_with_tree_version(version: u8) -> ReductionContext<'static> {
    ReductionContext {
        ergo_tree_version: version,
        ..ReductionContext::minimal(500_000, 0)
    }
}

fn eval_value_and_cost(expr: &Expr, ctx: &ReductionContext<'_>) -> (Result<Value, EvalError>, u64) {
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut cost = CostAccumulator::recording_only();
    let mut trace = None;
    let res = eval_expr(expr, ctx, &[], &mut env, &mut depth, &mut cost, &mut trace);
    (res, cost.total().value())
}

/// Serialized `Global.deserializeTo[Boolean](Coll[Byte](0x01))` body —
/// a v6 MethodCall whose wire form ends with the trailing explicit
/// type byte (`0x01` = SBoolean). Embedded-deserialization payloads
/// carry no tree header, so `parse_body(.., 0)` must consume that
/// byte keyed on `(type_id, method_id)` alone; the layout is
/// oracle-pinned by
/// `test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/`.
fn v6_typearg_methodcall_payload() -> Vec<u8> {
    let expr = Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 106,
            method_id: 4,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![const_bytes(vec![0x01])],
            type_args: vec![SigmaType::SBoolean],
        },
    });
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::opcode::write_body(&mut w, &expr, false).unwrap();
    w.result()
}

/// Output (0 txid, index 0) holding 1,000,000 nanoErgs under the sized v0
/// tree `08 02 72 01`: its body is `ValUse(1)`, which only an enclosing tree
/// that binds val 1 can resolve.
fn box_bytes_using_val_1() -> Vec<u8> {
    build_box(
        1_000_000,
        &[0x08, 0x02, 0x72, 0x01],
        100,
        &[],
        &reg_none(),
        &[0; 32],
        0,
    )
}

fn run_eval_ctx_err(expr: &Expr, ctx: &ReductionContext<'_>) -> EvalError {
    eval_to_value(expr, ctx, &[]).expect_err("expected error")
}

/// `val id[T] = {(x: <param_tpe>) => <body>}` as a FunDef block item.
fn fun_def_t(param_tpe: SigmaType, body: Expr) -> Expr {
    op(
        0xD7,
        Payload::FunDef {
            id: 1,
            tpe: None,
            tpe_args: vec![SigmaType::STypeVar("T".into())],
            rhs: Box::new(op(
                0xD9,
                Payload::FuncValue {
                    args: vec![(2, Some(param_tpe))],
                    body: Box::new(body),
                },
            )),
        },
    )
}

fn eval_value_and_cost_consts(
    expr: &Expr,
    constants: &[(SigmaType, SigmaValue)],
) -> (Result<Value, EvalError>, u64) {
    let ctx = ReductionContext::minimal(500_000, 0);
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut cost = CostAccumulator::recording_only();
    let mut trace = None;
    let res = eval_expr(
        expr, &ctx, constants, &mut env, &mut depth, &mut cost, &mut trace,
    );
    (res, cost.total().value())
}

fn val_def_item(id: u32, rhs: Expr) -> Expr {
    op(
        0xD6,
        Payload::ValDef {
            id,
            tpe: None,
            rhs: Box::new(rhs),
        },
    )
}

fn block(items: Vec<Expr>, result: Expr) -> Expr {
    op(
        0xD8,
        Payload::BlockValue {
            items,
            result: Box::new(result),
        },
    )
}

fn const_bigint(n: i64) -> Expr {
    Expr::Const {
        tpe: SigmaType::SBigInt,
        val: SigmaValue::BigInt(n.into()),
    }
}

fn binop(opcode: u8, l: Expr, r: Expr) -> Expr {
    op(opcode, Payload::Two(Box::new(l), Box::new(r)))
}

fn poly_identity_lambda() -> Expr {
    op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(SigmaType::STypeVar("T".into())))],
            body: Box::new(op(0x72, Payload::ValUse { id: 1 })),
        },
    )
}

fn const_some_int(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
        val: SigmaValue::Opt(Some(Box::new(SigmaValue::Int(v)))),
    }
}

fn const_coll_long(vals: Vec<i64>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SLong)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter().map(SigmaValue::Long).collect(),
        )),
    }
}

fn coll_updated_call(obj: Expr, idx: i32, elem: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 20, // updated
            obj: Box::new(obj),
            args: vec![const_int(idx), elem],
            type_args: vec![],
        },
    )
}

fn assert_updated_oob(expr: Expr, label: &str) {
    let err = run_eval_err(&expr);
    match err {
        EvalError::RuntimeException(msg) => assert!(
            msg.contains("Coll.updated") && msg.contains("out of bounds"),
            "{label}: wrong message: {msg}"
        ),
        other => panic!("{label}: expected RuntimeException(out of bounds), got {other:?}"),
    }
}

fn coll_updated_call_byte_elem(obj: Expr, idx: i32, byte_val: i8) -> Expr {
    // Build a Coll[Byte] element by fetching index 0 from a single-
    // byte literal collection. Mirrors the natural compile-time IR
    // where the element is sourced from another Coll[Byte] read.
    let byte_source = const_bytes(vec![byte_val as u8]);
    let byte_elem = op(
        0xB2, // ByIndex
        Payload::ByIndex {
            input: Box::new(byte_source),
            index: Box::new(const_int(0)),
            default: None,
        },
    );
    coll_updated_call(obj, idx, byte_elem)
}

fn const_coll_short(vals: Vec<i16>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SShort)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter().map(SigmaValue::Short).collect(),
        )),
    }
}

fn const_short(v: i16) -> Expr {
    Expr::Const {
        tpe: SigmaType::SShort,
        val: SigmaValue::Short(v),
    }
}

fn const_coll_sigma_prop_trivial(vals: Vec<bool>) -> Expr {
    use ergo_ser::sigma_value::CollValue;
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SSigmaProp)),
        val: SigmaValue::Coll(CollValue::Values(
            vals.into_iter()
                .map(|b| SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(b)))
                .collect(),
        )),
    }
}

fn const_sigma_prop_trivial(v: bool) -> Expr {
    Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(v)),
    }
}

/// Build a `MethodCall(12, 20)` Expr — the same shape `coll_updated_call`
/// uses but with arbitrary `obj` + `elem` Expr inputs.
fn coll_updated_via_method_call(obj: Expr, idx: Expr, elem: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 20,
            obj: Box::new(obj),
            args: vec![idx, elem],
            type_args: vec![],
        },
    )
}

fn op_inputs() -> Expr {
    // 0xA4 INPUTS — yields Value::BoxCollection(BoxSource::Inputs).
    op(0xA4, Payload::Zero)
}

fn op_self() -> Expr {
    // 0xA7 SELF — yields Value::SelfBox.
    op(0xA7, Payload::Zero)
}

fn op_by_index(coll: Expr, idx: Expr) -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(coll),
            index: Box::new(idx),
            default: None,
        },
    )
}

fn op_extract_register_2_tokens(box_expr: Expr) -> Expr {
    op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(box_expr),
            reg_id: 2,
            tpe: SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaType::SLong,
            ]))),
        },
    )
}

fn op_opt_get(opt_expr: Expr) -> Expr {
    // 0xE4 OptionGet — unwrap Option, error if None or non-Option.
    op(0xE4, Payload::One(Box::new(opt_expr)))
}

fn coll_patch_call(obj: Expr, from: i32, patch: Expr, replaced: i32) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 19, // patch
            obj: Box::new(obj),
            args: vec![const_int(from), patch, const_int(replaced)],
            type_args: vec![],
        },
    )
}

fn run_patch_int(xs: Vec<i32>, from: i32, patch: Vec<i32>, replaced: i32) -> Vec<i32> {
    let expr = coll_patch_call(const_coll_int(xs), from, const_coll_int(patch), replaced);
    match eval_to_value(&expr, &ReductionContext::minimal(500_000, 0), &[])
        .expect("Coll.patch must not throw for non-negative-throw inputs")
    {
        Value::CollInt(c) => c,
        other => panic!("expected CollInt, got {other:?}"),
    }
}

/// Compute the per-method PerItemCost charge for a given n, matching
/// `CostKind::PerItem::compute`'s `base + perChunk * ceil(n/chunkSize)`.
fn per_item_compute(base: u32, per_chunk: u32, chunk_size: u32, n: u32) -> u32 {
    base + per_chunk * n.div_ceil(chunk_size)
}

fn patch_call(obj: Expr, from: i32, patch: Expr, replaced: i32) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 19,
            obj: Box::new(obj),
            args: vec![const_int(from), patch, const_int(replaced)],
            type_args: vec![],
        },
    )
}

fn cost_of(expr: &Expr) -> u64 {
    let ctx = ReductionContext::minimal(10_000_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let _ = reduce_expr_with_cost(expr, &ctx, &[], &mut cost);
    cost.total().value()
}

/// 1-arg `Func` over `tpe` whose body ignores the bound argument
/// and returns a constant. Lets cost comparisons across element
/// carriers (Coll[Short] vs Coll[Int]) isolate the per-item layer
/// — body cost is identical regardless of carrier because the
/// argument is never touched.
fn const_pred_of(tpe: SigmaType, body: Expr) -> Expr {
    op(
        0xD9,
        Payload::FuncValue {
            args: vec![(1, Some(tpe))],
            body: Box::new(body),
        },
    )
}

/// An `SUnsignedBigInt` CONSTANT carrying `v` (must be in [0, 2^256-1] for a
/// legal value; eval rejects a negative magnitude).
fn const_ubi(v: num_bigint::BigInt) -> Expr {
    Expr::Const {
        tpe: SigmaType::SUnsignedBigInt,
        val: SigmaValue::BigInt(v),
    }
}

fn ubi(v: i64) -> num_bigint::BigInt {
    num_bigint::BigInt::from(v)
}

/// `op(left, right)` where `op` is a binary ArithOp opcode, both operands
/// `SUnsignedBigInt` constants.
fn ubi_arith(opcode: u8, a: num_bigint::BigInt, b: num_bigint::BigInt) -> Expr {
    op(
        opcode,
        Payload::Two(Box::new(const_ubi(a)), Box::new(const_ubi(b))),
    )
}

fn eval_total(expr: &Expr) -> u64 {
    let cx = ReductionContext::minimal(10_000_000, 0);
    let mut cost = CostAccumulator::recording_only();
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    eval_expr(expr, &cx, &[], &mut env, &mut depth, &mut cost, &mut trace).unwrap();
    cost.total().value()
}

fn option_map_inc(obj: Expr) -> Expr {
    // obj.map((y: Int) => y + 1) as MethodCall(36, 7)
    let lambda = op(
        0xD9,
        Payload::FuncValue {
            args: vec![(2, Some(SigmaType::SInt))],
            body: Box::new(op(
                0x9A,
                Payload::Two(
                    Box::new(op(0x72, Payload::ValUse { id: 2 })),
                    Box::new(const_int(1)),
                ),
            )),
        },
    );
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 36,
            method_id: 7,
            obj: Box::new(obj),
            args: vec![lambda],
            type_args: vec![],
        },
    )
}

fn coll_update_many(recv: Expr, indexes: Expr, values: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 12,
            method_id: 21,
            obj: Box::new(recv),
            args: vec![indexes, values],
            type_args: vec![],
        },
    )
}

fn test_avl_tree(value_length: Option<i32>) -> ergo_ser::sigma_value::AvlTreeData {
    ergo_ser::sigma_value::AvlTreeData {
        digest: [0u8; 33].to_vec(),
        insert_allowed: true,
        update_allowed: false,
        remove_allowed: true,
        key_length: 32,
        value_length_opt: value_length,
    }
}

fn test_eval_header_v2() -> EvalHeader {
    EvalHeader {
        id: [0xAA; 32],
        version: 2,
        parent_id: [0xBB; 32],
        ad_proofs_root: [0; 32],
        state_root: [0; 33],
        transactions_root: [0; 32],
        timestamp: 1_600_000_000_000,
        n_bits: 0x0100_0000,
        height: 500_000,
        extension_root: [0; 32],
        miner_pk: [0x02; 33],
        pow_onetime_pk: [0x03; 33],
        pow_nonce: [0xFF; 8],
        pow_distance: num_bigint::BigInt::from(0),
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
    }
}

// CONTEXT.headers(idx) — a RUNTIME-sourced header, materialized from
// ctx.last_headers rather than a constant. A const Header (Expr::Const) would
// be rejected by the const/value-decoder SHeader gate
// (sigma_to_value_versioned) BEFORE reaching the (106,3) serialize gate, so
// these gate tests must use a runtime source to prove the serialize gate
// itself.
fn ctx_headers_index(idx: i32) -> Expr {
    op(
        0xB2,
        Payload::ByIndex {
            input: Box::new(op(
                0xDB,
                Payload::MethodCall {
                    type_id: 101, // SContext.headers
                    method_id: 2,
                    obj: Box::new(op(0xFE, Payload::Zero)),
                    args: vec![],
                    type_args: vec![],
                },
            )),
            index: Box::new(const_int(idx)),
            default: None,
        },
    )
}

fn serialize_call_expr(arg: Expr) -> Expr {
    op(
        0xDC,
        Payload::MethodCall {
            type_id: 106,
            method_id: 3,
            obj: Box::new(op(0xDD, Payload::Zero)),
            args: vec![arg],
            type_args: vec![],
        },
    )
}

/// Minimal valid sizeless v0 proposition tree (3 bytes): header `0x00` (v0, no
/// segregation, no size) + inline `SSigmaProp` constant (type `0x08`) value
/// `TrivialProp(true)` (`0xd3`). Carries NO v6 method, so it parses cleanly
/// through the box-script readers' `check_v3_only_methods` gate. (The previous
/// fixture `1000d1efe6db6a0add04` carried a v6 `SGlobal.none[Int]` in a pre-v3
/// tree — now rejected at box deserialize, like Scala.)
fn ser_box_tree() -> Vec<u8> {
    hex::decode("0008d3").unwrap()
}

/// Assemble standalone box bytes (candidate body + 32-byte txId + VLQ index)
/// from parts. `reg_section` is the verbatim register block (count byte +
/// entries) so const-vs-expr register encodings round-trip byte-exact.
fn build_box(
    value: u64,
    tree: &[u8],
    height: u32,
    tokens: &[([u8; 32], u64)],
    reg_section: &[u8],
    txid: &[u8; 32],
    index: u16,
) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u64(value);
    w.put_bytes(tree);
    w.put_u32(height);
    w.put_u8(tokens.len() as u8);
    for (id, amt) in tokens {
        w.put_bytes(id);
        w.put_u64(*amt);
    }
    w.put_bytes(reg_section);
    w.put_bytes(txid);
    w.put_u16(index);
    w.result()
}

/// Register block with zero registers (the bare count byte).
fn reg_none() -> Vec<u8> {
    vec![0u8]
}

/// Register block: a single R4 written in CONSTANT form (type code <= 0x70
/// followed by data). Tuple constants (quad code 0x54, tuple-n code 0x60) are
/// detected as constants by `read_register_value` and cost
/// type_enc_bytes(tpe) + DataSerializer cost.
fn reg_const(tpe: &SigmaType, val: &SigmaValue) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u8(1);
    ergo_ser::sigma_value::write_constant(&mut w, tpe, val).unwrap();
    w.result()
}

/// Register block from structured `AdditionalRegisters` — `write_registers`
/// emits tuples in the CreateTuple (0x86) EXPRESSION form, which costs
/// 1(opcode) + 1(count) + Σ item putValue.
fn reg_from_registers(regs: ergo_ser::register::AdditionalRegisters) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::register::write_registers(&mut w, &regs).unwrap();
    w.result()
}

fn ser_box_cost(bytes: Vec<u8>) -> u64 {
    crate::evaluator::opcodes::method_call::serialize_put_cost(
        &SigmaType::SBox,
        &SigmaValue::OpaqueBoxBytes(bytes),
    )
    .unwrap()
}

// Scala CAvlTree.updateDigest stores any-length Coll[Byte] verbatim (no length
// check); updateOperations swaps the flags byte (insert=&0x01, update=&0x02,
// remove=&0x04). Costs (46/51/65/262) are pinned by the SANTA vectors (which
// use ConstPlaceholder framing); these tests pin the VALUE behavior + the
// variable-length-digest cost-helper guard. The digest field is now Vec<u8>.
fn avl_const_expr(digest: Vec<u8>) -> Expr {
    Expr::Const {
        tpe: SigmaType::SAvlTree,
        val: SigmaValue::AvlTree(ergo_ser::sigma_value::AvlTreeData {
            digest,
            insert_allowed: true,
            update_allowed: true,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: None,
        }),
    }
}

fn avl_method(obj: Expr, method_id: u8, args: Vec<Expr>) -> Expr {
    Expr::Op(IrNode {
        opcode: 0xDC,
        payload: Payload::MethodCall {
            type_id: 100,
            method_id,
            obj: Box::new(obj),
            args,
            type_args: vec![],
        },
    })
}

// Encode an expression to its wire bytes (for building register entries).
fn expr_wire_bytes(e: &Expr) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::opcode::write_expr(&mut w, e, false).unwrap();
    w.result()
}

// Build a self_box carrying exactly `register_bytes` and return its
// bytesWithoutRef (0xC4). Only the register block drives the 0xC4 register
// tail, so the prefix fields and parsed `registers` are placeholders.
fn bytes_with_no_ref_for_register_block(register_bytes: Vec<u8>) -> Vec<u8> {
    let b = EvalBox {
        lazy_vals: Default::default(),
        creation_height: 0,
        script_bytes: vec![0x10, 0x00],
        value: 1000,
        id: [0u8; 32],
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: Vec::new(),
        raw_bytes: Vec::new(),
        register_bytes,
    };
    let ctx = ctx_with_self_box(&b);
    let expr = op(0xC4, Payload::One(Box::new(op(0xA7, Payload::Zero))));
    match run_eval_ctx(&expr, &ctx) {
        Value::CollBytes(v) => v,
        other => panic!("expected CollBytes, got {other:?}"),
    }
}

// These includes preserve the evaluator::tests namespace and Cargo test filters.
include!("tests/reduction_and_equality.rs");
include!("tests/opcodes.rs");
include!("tests/box_access.rs");
include!("tests/collection_basics.rs");
include!("tests/crypto_and_conversions.rs");
include!("tests/deserialization.rs");
include!("tests/rejection_parity.rs");
include!("tests/oracle_and_binding.rs");
include!("tests/activation.rs");
include!("tests/collection_updates.rs");
include!("tests/collection_bounds_and_cost.rs");
include!("tests/numeric_and_method_costs.rs");
include!("tests/serialization.rs");
include!("tests/flatmap_and_avl.rs");
include!("tests/tree_validation_and_box_identity.rs");
