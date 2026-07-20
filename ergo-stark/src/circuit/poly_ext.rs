//! The recursion circuit's constraint system as data (the parsed
//! `PolyExtStepDef` op table) plus the interpreter that evaluates it — a
//! faithful port of the reference sigmastate `PolyExtOp` / `PolyExtTable` /
//! `PolyExtInterpreter` (mirror of risc0-circuit-recursion 4.0.4 `poly_ext.rs`
//! for the data and risc0-zkp 3.0.4 `src/adapter.rs` `PolyExtStepDef::step`
//! for the interpreter contract).
//!
//! The program is a straight-line pass over the op table driving two
//! append-only stacks: `fp` of [`Ext4`] values and `mix` of `(tot, mul)`
//! [`Ext4`] pairs. The result is `mix(ret)`; its `tot` component is the mixed
//! constraint-polynomial evaluation the DEEP-ALI FRI query compares against the
//! recombined check polynomial — i.e. the per-query FRI "goal".
//!
//! Consensus-critical: reproduce the reference byte-for-byte. Pinned by the
//! extracted `circuit_polyext_ops.tsv` table (its Blake2b-256 integrity hash)
//! and the compact `polyext_transcript_oracle.tsv` checkpoints captured from a
//! real devnet receipt, per the oracle-parity rule.

use crate::ext4::Ext4;
use std::collections::HashMap;

/// The canonical BabyBear prime `p = 15·2^27 + 1`. A `Const`/`GetGlobal` value
/// at or above this is rejected rather than reduced (the EIP-0045 B2 boundary
/// requires canonical field elements).
const P: u32 = crate::baby_bear::BabyBear::P;

/// One step of the recursion-circuit constraint program.
///
/// Every operand is a position in one of the two append-only stacks (so an
/// operand can only reference an already-pushed value) except `Const`/`ConstExt`
/// (raw base-field literals) and `Get`/`GetGlobal` (indices into the tapped
/// evaluations / global buffers). Index operands are kept as `i32` to mirror the
/// reference's signed `Int` operands so the interpreter's `< 0` guards stay
/// meaningful; `Const`/`ConstExt` literals are held as the raw `u32` from the
/// table so the canonical re-serialization reproduces the generator's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolyExtOp {
    /// Push fp: base-field constant lifted to [`Ext4`].
    Const(u32),
    /// Push fp: explicit [`Ext4`] constant (0 occurrences in the recursion circuit).
    ConstExt(u32, u32, u32, u32),
    /// Push fp: `u[tap]` — a tapped trace-polynomial evaluation.
    Get(i32),
    /// Push fp: `args[arg][offset]` lifted to [`Ext4`]; arg 0 = out globals (32),
    /// arg 1 = accum-mix globals (20).
    GetGlobal(i32, i32),
    /// Push fp: `fp[a] + fp[b]`.
    Add(i32, i32),
    /// Push fp: `fp[a] - fp[b]`.
    Sub(i32, i32),
    /// Push fp: `fp[a] * fp[b]`.
    Mul(i32, i32),
    /// Push mix: `(tot = 0, mul = 1)` — the empty constraint chain.
    True,
    /// Push mix: `(chain.tot + chain.mul * fp[inner], chain.mul * poly_mix)`.
    AndEqz(i32, i32),
    /// Push mix: `(chain.tot + fp[cond] * mix[inner].tot * chain.mul,
    /// chain.mul * mix[inner].mul)`.
    AndCond(i32, i32, i32),
}

impl PolyExtOp {
    /// Mnemonic + operand list, matching the generator's `serialize_op` exactly.
    fn serialize(self, out: &mut String) {
        use std::fmt::Write as _;
        match self {
            PolyExtOp::Const(v) => {
                let _ = write!(out, "Const:{v}");
            }
            PolyExtOp::ConstExt(a, b, c, d) => {
                let _ = write!(out, "ConstExt:{a},{b},{c},{d}");
            }
            PolyExtOp::Get(t) => {
                let _ = write!(out, "Get:{t}");
            }
            PolyExtOp::GetGlobal(arg, off) => {
                let _ = write!(out, "GetGlobal:{arg},{off}");
            }
            PolyExtOp::Add(a, b) => {
                let _ = write!(out, "Add:{a},{b}");
            }
            PolyExtOp::Sub(a, b) => {
                let _ = write!(out, "Sub:{a},{b}");
            }
            PolyExtOp::Mul(a, b) => {
                let _ = write!(out, "Mul:{a},{b}");
            }
            PolyExtOp::True => out.push_str("True:"),
            PolyExtOp::AndEqz(c, i) => {
                let _ = write!(out, "AndEqz:{c},{i}");
            }
            PolyExtOp::AndCond(c, cond, i) => {
                let _ = write!(out, "AndCond:{c},{cond},{i}");
            }
        }
    }

    /// Whether this op pushes onto the `mix` stack (vs the `fp` stack).
    fn is_mix(self) -> bool {
        matches!(
            self,
            PolyExtOp::True | PolyExtOp::AndEqz(..) | PolyExtOp::AndCond(..)
        )
    }
}

/// The running `(tot, mul)` pair of a constraint chain (mirror of risc0-zkp's
/// `MixState`). `tot` is the mixed constraint evaluation; for the result mix var
/// it is the DEEP-ALI FRI goal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixState {
    pub tot: Ext4,
    pub mul: Ext4,
}

/// The recursion circuit's constraint system as data — the parsed op table,
/// validated structurally (sequential indices, append-only in-range stack
/// operands, final stack sizes, `ret` in range, opcode histogram vs the recorded
/// meta). The Blake2b-256 integrity hash over [`canonical_bytes`] is asserted by
/// the KATs (proving parse fidelity), not by `parse` itself.
#[derive(Clone, Debug)]
pub struct PolyExtTable {
    ops: Vec<PolyExtOp>,
    ret: usize,
    fp_vars: usize,
    mix_vars: usize,
    opcode_histogram: HashMap<String, i32>,
    blake2b256_hex: String,
}

impl PolyExtTable {
    /// The result mix-var index; `mix(ret)` is the returned [`MixState`].
    pub fn ret(&self) -> usize {
        self.ret
    }
    /// Final `fp` stack size.
    pub fn fp_vars(&self) -> usize {
        self.fp_vars
    }
    /// Final `mix` stack size (`ret + 1`).
    pub fn mix_vars(&self) -> usize {
        self.mix_vars
    }
    /// Number of ops in the program.
    pub fn ops_count(&self) -> usize {
        self.ops.len()
    }
    /// The op at `index`.
    pub fn op_at(&self, index: usize) -> PolyExtOp {
        self.ops[index]
    }
    /// The full op sequence.
    pub fn ops(&self) -> &[PolyExtOp] {
        &self.ops
    }
    /// Mnemonic -> occurrence count.
    pub fn opcode_histogram(&self) -> &HashMap<String, i32> {
        &self.opcode_histogram
    }
    /// The Blake2b-256 hex the generator recorded from the Rust table.
    pub fn blake2b256_hex(&self) -> &str {
        &self.blake2b256_hex
    }

    /// The generator's canonical serialization of the parsed table — UTF-8 of
    /// `"<mnemonic>:<comma-operands>\n"` per op in order. Recomputed from the
    /// PARSED ops (not file bytes) so hashing it re-proves parse fidelity.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut s = String::with_capacity(self.ops.len() * 16);
        for op in &self.ops {
            op.serialize(&mut s);
            s.push('\n');
        }
        s.into_bytes()
    }

    /// Construction boundary for hand-built / authenticated-binary tables
    /// (mirror of the reference `fromValidatedBinary`): used by tests and, later,
    /// by the EIP-0045 B2 decoder which has already enforced the append-only
    /// discipline, exact stack sizes, opcode census and canonical constants.
    pub fn from_validated(
        ops: Vec<PolyExtOp>,
        ret: usize,
        fp_vars: usize,
        mix_vars: usize,
    ) -> PolyExtTable {
        PolyExtTable {
            ops,
            ret,
            fp_vars,
            mix_vars,
            opcode_histogram: HashMap::new(),
            blake2b256_hex: "authenticated-b2".to_string(),
        }
    }

    /// Parse `circuit_polyext_ops.tsv` content. Total: any malformed input —
    /// bad numbers, out-of-range stack operands, meta/structure mismatches —
    /// yields `Err`, never panics. `#` comments and blank lines are skipped.
    pub fn parse(content: &str) -> Result<PolyExtTable, String> {
        let mut meta: HashMap<String, String> = HashMap::new();
        let mut ops: Vec<PolyExtOp> = Vec::new();
        // Append-only stack discipline: operand validity is decidable during the
        // single parse pass by tracking how many values each stack holds so far.
        let mut fp_count: i32 = 0;
        let mut mix_count: i32 = 0;
        let mut histogram: HashMap<String, i32> = HashMap::new();

        for line in content.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Data rows are whitespace-free tokens separated only by tabs. A
            // zero-arity True op uses the explicit `-` sentinel; an empty final
            // cell must not be normalized away.
            let f: Vec<&str> = line.split('\t').collect();
            if f.iter().any(|x| x.is_empty()) {
                return Err(format!("circuit_polyext_ops: empty field in row: {line}"));
            }
            if f.iter().any(|x| x.chars().any(char::is_whitespace)) {
                return Err(format!(
                    "circuit_polyext_ops: whitespace in field in row: {line}"
                ));
            }
            match f[0] {
                "meta" => {
                    if f.len() != 3 {
                        return Err(format!("circuit_polyext_ops: bad meta row: {line}"));
                    }
                    if meta.contains_key(f[1]) {
                        return Err(format!("circuit_polyext_ops: duplicate meta '{}'", f[1]));
                    }
                    meta.insert(f[1].to_string(), f[2].to_string());
                }
                "op" => {
                    if f.len() != 4 {
                        return Err(format!("circuit_polyext_ops: bad op row: {line}"));
                    }
                    let idx = parse_i64(f[1])?;
                    if idx != ops.len() as i64 {
                        return Err(format!(
                            "circuit_polyext_ops: op index {idx} out of order (expected {})",
                            ops.len()
                        ));
                    }
                    if f[3] == "-" && f[2] != "True" {
                        return Err(format!(
                            "circuit_polyext_ops: op {idx}: '-' is only valid for True"
                        ));
                    }
                    if f[2] == "True" && f[3] != "-" {
                        return Err(format!("circuit_polyext_ops: op {idx}: True requires '-'"));
                    }
                    let operands: Vec<i64> = if f[3] == "-" {
                        Vec::new()
                    } else {
                        f[3].split(',').map(parse_i64).collect::<Result<_, _>>()?
                    };

                    let op = build_op(idx, f[2], &operands, fp_count, mix_count)?;
                    if op.is_mix() {
                        mix_count += 1;
                    } else {
                        fp_count += 1;
                    }
                    *histogram.entry(f[2].to_string()).or_insert(0) += 1;
                    ops.push(op);
                }
                other => {
                    return Err(format!("circuit_polyext_ops: unknown row kind '{other}'"));
                }
            }
        }

        let meta_int = |key: &str| -> Result<i32, String> {
            match meta.get(key) {
                Some(v) => parse_i64(v).map(|n| n as i32),
                None => Err(format!("circuit_polyext_ops: missing meta '{key}'")),
            }
        };

        let ops_count = meta_int("ops_count")?;
        let ret = meta_int("ret")?;
        let fp_vars = meta_int("fp_vars")?;
        let mix_vars = meta_int("mix_vars")?;

        // Final structural validation against the recorded meta (mirror of the
        // reference `validate`).
        if ops.len() as i32 != ops_count {
            return Err(format!(
                "circuit_polyext_ops: {} ops parsed but meta ops_count={ops_count}",
                ops.len()
            ));
        }
        if fp_count != fp_vars {
            return Err(format!(
                "circuit_polyext_ops: {fp_count} fp vars but meta fp_vars={fp_vars}"
            ));
        }
        if mix_count != mix_vars {
            return Err(format!(
                "circuit_polyext_ops: {mix_count} mix vars but meta mix_vars={mix_vars}"
            ));
        }
        if ret < 0 || ret >= mix_count {
            return Err(format!(
                "circuit_polyext_ops: ret={ret} not in [0, {mix_count})"
            ));
        }
        // Upstream sizes the mix stack as ret + 1: the result must be the LAST
        // mix var pushed.
        if mix_vars != ret + 1 {
            return Err(format!(
                "circuit_polyext_ops: mix_vars={mix_vars} but ret={ret} requires {}",
                ret + 1
            ));
        }

        let hist_meta = meta
            .get("opcode_histogram")
            .ok_or("circuit_polyext_ops: missing meta 'opcode_histogram'")?;
        let mut meta_hist: HashMap<String, i32> = HashMap::new();
        for entry in hist_meta.split(',') {
            let kv: Vec<&str> = entry.splitn(2, '=').collect();
            if kv.len() != 2 {
                return Err(format!(
                    "circuit_polyext_ops: bad histogram meta '{hist_meta}'"
                ));
            }
            meta_hist.insert(kv[0].to_string(), parse_i64(kv[1])? as i32);
        }
        if histogram != meta_hist {
            return Err(format!(
                "circuit_polyext_ops: opcode histogram {histogram:?} != meta {meta_hist:?}"
            ));
        }

        let blake2b256_hex = meta
            .get("blake2b256")
            .ok_or("circuit_polyext_ops: missing meta 'blake2b256'")?
            .clone();

        Ok(PolyExtTable {
            ops,
            ret: ret as usize,
            fp_vars: fp_vars as usize,
            mix_vars: mix_vars as usize,
            opcode_histogram: histogram,
            blake2b256_hex,
        })
    }
}

/// Run the constraint program. Mirror of the reference `PolyExtInterpreter.step`
/// / upstream `PolyExtStepDef::step(mix, u, args)`.
///
/// - `poly_mix`: the transcript-drawn constraint mixer (`poly_mix`).
/// - `u`: the tapped evaluations `eval_u`, one [`Ext4`] per tap in canonical tap
///   order; coefficients must be canonical.
/// - `args`: the global buffers of canonical base-field values; `args[0]` = out
///   globals (`OUT_SIZE = 32`), `args[1]` = accum-mix globals (`MIX_SIZE = 20`)
///   — exactly what `verify` passes as `&[out, mix]`.
///
/// Returns `Ok(MixState)` on success; `Err` for any malformed access (tap index
/// outside `u`, global outside `args`, non-canonical global value, stack-shape
/// mismatch) — never panics.
pub fn step(
    table: &PolyExtTable,
    poly_mix: Ext4,
    u: &[Ext4],
    args: &[&[u32]],
) -> Result<MixState, String> {
    let fp_vars = table.fp_vars;
    let mix_vars = table.mix_vars;

    let mut fp: Vec<Ext4> = Vec::with_capacity(fp_vars);
    let mut mix_tot: Vec<Ext4> = Vec::with_capacity(mix_vars);
    let mut mix_mul: Vec<Ext4> = Vec::with_capacity(mix_vars);

    for (i, op) in table.ops.iter().enumerate() {
        match *op {
            PolyExtOp::Const(v) => {
                if fp.len() >= fp_vars {
                    return Err(format!("op {i}: fp stack overflow"));
                }
                if v >= P {
                    return Err(format!(
                        "op {i}: Const value {v} is not a canonical BabyBear element"
                    ));
                }
                fp.push(Ext4::from_base(v));
            }
            PolyExtOp::ConstExt(c0, c1, c2, c3) => {
                if fp.len() >= fp_vars {
                    return Err(format!("op {i}: fp stack overflow"));
                }
                if c0 >= P || c1 >= P || c2 >= P || c3 >= P {
                    return Err(format!(
                        "op {i}: ConstExt contains a non-canonical BabyBear element"
                    ));
                }
                fp.push(Ext4::new(c0, c1, c2, c3));
            }
            PolyExtOp::Get(tap) => {
                if tap < 0 || tap as usize >= u.len() {
                    return Err(format!("op {i}: Get({tap}) outside u ({} taps)", u.len()));
                }
                if fp.len() >= fp_vars {
                    return Err(format!("op {i}: fp stack overflow"));
                }
                fp.push(u[tap as usize]);
            }
            PolyExtOp::GetGlobal(arg, offset) => {
                if arg < 0 || arg as usize >= args.len() {
                    return Err(format!(
                        "op {i}: GetGlobal arg {arg} outside args ({})",
                        args.len()
                    ));
                }
                let buffer = args[arg as usize];
                if offset < 0 || offset as usize >= buffer.len() {
                    return Err(format!(
                        "op {i}: GetGlobal({arg}, {offset}) outside buffer ({})",
                        buffer.len()
                    ));
                }
                let v = buffer[offset as usize];
                if v >= P {
                    return Err(format!(
                        "op {i}: GetGlobal({arg}, {offset}) value {v} not a canonical field element"
                    ));
                }
                if fp.len() >= fp_vars {
                    return Err(format!("op {i}: fp stack overflow"));
                }
                fp.push(Ext4::from_base(v));
            }
            PolyExtOp::Add(a, b) => {
                if fp.len() >= fp_vars {
                    return Err(format!("op {i}: fp stack overflow"));
                }
                let (a, b) = fp_operands(i, "Add", a, b, fp.len())?;
                fp.push(fp[a].add(fp[b]));
            }
            PolyExtOp::Sub(a, b) => {
                if fp.len() >= fp_vars {
                    return Err(format!("op {i}: fp stack overflow"));
                }
                let (a, b) = fp_operands(i, "Sub", a, b, fp.len())?;
                fp.push(fp[a].sub(fp[b]));
            }
            PolyExtOp::Mul(a, b) => {
                if fp.len() >= fp_vars {
                    return Err(format!("op {i}: fp stack overflow"));
                }
                let (a, b) = fp_operands(i, "Mul", a, b, fp.len())?;
                fp.push(fp[a].mul(fp[b]));
            }
            PolyExtOp::True => {
                if mix_tot.len() >= mix_vars {
                    return Err(format!("op {i}: mix stack overflow"));
                }
                mix_tot.push(Ext4::ZERO);
                mix_mul.push(Ext4::ONE);
            }
            PolyExtOp::AndEqz(chain, inner) => {
                if mix_tot.len() >= mix_vars {
                    return Err(format!("op {i}: mix stack overflow"));
                }
                if chain < 0
                    || chain as usize >= mix_tot.len()
                    || inner < 0
                    || inner as usize >= fp.len()
                {
                    return Err(format!(
                        "op {i}: AndEqz operands ({chain},{inner}) outside mix/fp stacks ({},{})",
                        mix_tot.len(),
                        fp.len()
                    ));
                }
                let (chain, inner) = (chain as usize, inner as usize);
                mix_tot.push(mix_tot[chain].add(mix_mul[chain].mul(fp[inner])));
                mix_mul.push(mix_mul[chain].mul(poly_mix));
            }
            PolyExtOp::AndCond(chain, cond, inner) => {
                if mix_tot.len() >= mix_vars {
                    return Err(format!("op {i}: mix stack overflow"));
                }
                if chain < 0
                    || chain as usize >= mix_tot.len()
                    || cond < 0
                    || cond as usize >= fp.len()
                    || inner < 0
                    || inner as usize >= mix_tot.len()
                {
                    return Err(format!(
                        "op {i}: AndCond operands ({chain},{cond},{inner}) outside mix/fp stacks ({},{})",
                        mix_tot.len(),
                        fp.len()
                    ));
                }
                let (chain, cond, inner) = (chain as usize, cond as usize, inner as usize);
                mix_tot.push(mix_tot[chain].add(fp[cond].mul(mix_tot[inner]).mul(mix_mul[chain])));
                mix_mul.push(mix_mul[chain].mul(mix_mul[inner]));
            }
        }
    }

    // Post-run stack-shape assertions (as Err, mirroring upstream's asserts).
    if fp.len() != fp_vars {
        Err(format!(
            "fp stack ended at {}, expected {fp_vars}",
            fp.len()
        ))
    } else if mix_tot.len() != mix_vars {
        Err(format!(
            "mix stack ended at {}, expected {mix_vars}",
            mix_tot.len()
        ))
    } else if table.ret >= mix_tot.len() {
        Err(format!(
            "ret {} outside mix stack ({})",
            table.ret,
            mix_tot.len()
        ))
    } else {
        Ok(MixState {
            tot: mix_tot[table.ret],
            mul: mix_mul[table.ret],
        })
    }
}

/// Compute the per-query DEEP-ALI FRI goal — the entry point Layer 4 wires into
/// [`crate::fri::fri_verify`]'s
/// `inner: FnMut(&mut ReadIop, usize) -> Result<Ext4, String>`.
///
/// This is [`step`] projected to its `tot` component: the mixed
/// constraint-polynomial evaluation the FRI query requires equal the recombined
/// check polynomial. Layer 4 builds the per-query tapped evaluations `u` (from
/// the DEEP tap openings at that position) and the `args` globals, then closes
/// over `table`/`poly_mix` to form the `inner` closure.
pub fn deep_goal(
    table: &PolyExtTable,
    poly_mix: Ext4,
    u: &[Ext4],
    args: &[&[u32]],
) -> Result<Ext4, String> {
    step(table, poly_mix, u, args).map(|ms| ms.tot)
}

/// Validate `a`, `b` as in-range `fp` positions, returning them as `usize`.
fn fp_operands(
    i: usize,
    name: &str,
    a: i32,
    b: i32,
    fp_len: usize,
) -> Result<(usize, usize), String> {
    if a < 0 || a as usize >= fp_len || b < 0 || b as usize >= fp_len {
        return Err(format!(
            "op {i}: {name} operands ({a},{b}) outside fp stack ({fp_len})"
        ));
    }
    Ok((a as usize, b as usize))
}

/// Build one op from its mnemonic + operands, enforcing arity, the append-only
/// stack discipline (operands must reference already-pushed values), and the u32
/// range of literal constants. Mirror of the reference `parseChecked` op switch.
fn build_op(
    idx: i64,
    mnemonic: &str,
    operands: &[i64],
    fp_count: i32,
    mix_count: i32,
) -> Result<PolyExtOp, String> {
    let arity = |n: usize| -> Result<(), String> {
        if operands.len() != n {
            Err(format!(
                "circuit_polyext_ops: op {idx}: {mnemonic} expects {n} operands, got {}",
                operands.len()
            ))
        } else {
            Ok(())
        }
    };
    let fp_idx = |v: i64| -> Result<i32, String> {
        if v < 0 || v >= fp_count as i64 {
            Err(format!(
                "circuit_polyext_ops: op {idx}: fp operand {v} not in [0, {fp_count})"
            ))
        } else {
            Ok(v as i32)
        }
    };
    let mix_idx = |v: i64| -> Result<i32, String> {
        if v < 0 || v >= mix_count as i64 {
            Err(format!(
                "circuit_polyext_ops: op {idx}: mix operand {v} not in [0, {mix_count})"
            ))
        } else {
            Ok(v as i32)
        }
    };
    let u32c = |v: i64| -> Result<u32, String> {
        if !(0..=0xFFFF_FFFF).contains(&v) {
            Err(format!(
                "circuit_polyext_ops: op {idx}: operand {v} not a u32"
            ))
        } else {
            Ok(v as u32)
        }
    };
    let non_neg = |v: i64| -> Result<i32, String> {
        if v < 0 || v > i32::MAX as i64 {
            Err(format!(
                "circuit_polyext_ops: op {idx}: operand {v} out of range"
            ))
        } else {
            Ok(v as i32)
        }
    };

    match mnemonic {
        "Const" => {
            arity(1)?;
            Ok(PolyExtOp::Const(u32c(operands[0])?))
        }
        "ConstExt" => {
            arity(4)?;
            Ok(PolyExtOp::ConstExt(
                u32c(operands[0])?,
                u32c(operands[1])?,
                u32c(operands[2])?,
                u32c(operands[3])?,
            ))
        }
        "Get" => {
            arity(1)?;
            Ok(PolyExtOp::Get(non_neg(operands[0])?))
        }
        "GetGlobal" => {
            arity(2)?;
            Ok(PolyExtOp::GetGlobal(
                non_neg(operands[0])?,
                non_neg(operands[1])?,
            ))
        }
        "Add" => {
            arity(2)?;
            Ok(PolyExtOp::Add(fp_idx(operands[0])?, fp_idx(operands[1])?))
        }
        "Sub" => {
            arity(2)?;
            Ok(PolyExtOp::Sub(fp_idx(operands[0])?, fp_idx(operands[1])?))
        }
        "Mul" => {
            arity(2)?;
            Ok(PolyExtOp::Mul(fp_idx(operands[0])?, fp_idx(operands[1])?))
        }
        "True" => {
            arity(0)?;
            Ok(PolyExtOp::True)
        }
        "AndEqz" => {
            arity(2)?;
            Ok(PolyExtOp::AndEqz(
                mix_idx(operands[0])?,
                fp_idx(operands[1])?,
            ))
        }
        "AndCond" => {
            arity(3)?;
            Ok(PolyExtOp::AndCond(
                mix_idx(operands[0])?,
                fp_idx(operands[1])?,
                mix_idx(operands[2])?,
            ))
        }
        other => Err(format!(
            "circuit_polyext_ops: op {idx}: unknown mnemonic '{other}'"
        )),
    }
}

/// Parse a signed decimal, mapping failure to the loader's `Err` convention.
fn parse_i64(s: &str) -> Result<i64, String> {
    s.parse::<i64>()
        .map_err(|_| format!("circuit_polyext_ops: bad number: '{s}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    const OPS_TSV: &str = include_str!("../../../test-vectors/ergo-stark/circuit_polyext_ops.tsv");

    /// The tiny well-formed table from the reference spec, as tab/newline text.
    const TINY: &[&str] = &[
        "meta\tops_count\t5",
        "meta\tret\t1",
        "meta\tfp_vars\t3",
        "meta\tmix_vars\t2",
        "meta\topcode_histogram\tAndEqz=1,Const=2,Sub=1,True=1",
        "meta\tblake2b256\t00",
        "op\t0\tConst\t5",
        "op\t1\tConst\t5",
        "op\t2\tSub\t0,1",
        "op\t3\tTrue\t-",
        "op\t4\tAndEqz\t0,2",
    ];

    fn tiny() -> String {
        TINY.join("\n")
    }

    /// The tiny table with one full line rewritten.
    fn tiny_mut(from: &str, to: &str) -> String {
        TINY.iter()
            .map(|l| if *l == from { to } else { l })
            .collect::<Vec<_>>()
            .join("\n")
    }

    const EMPTY_ARGS: [&[u32]; 2] = [&[], &[]];

    // ----- happy path -----

    #[test]
    fn ops_loader_matches_the_extracted_table_shape_and_integrity_hash() {
        let table = PolyExtTable::parse(OPS_TSV).expect("ops parse");
        assert_eq!(table.ops_count(), 12359);
        assert_eq!(table.ret(), 1228);
        assert_eq!(table.fp_vars(), 11130);
        assert_eq!(table.mix_vars(), 1229);

        let expected: HashMap<String, i32> = [
            ("Add", 4061),
            ("AndCond", 152),
            ("AndEqz", 1076),
            ("Const", 284),
            ("Get", 669),
            ("GetGlobal", 52),
            ("Mul", 4679),
            ("Sub", 1385),
            ("True", 1),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();
        assert_eq!(table.opcode_histogram(), &expected);

        // Integrity: Blake2b-256 over the canonical re-serialization of the
        // PARSED ops must equal the hash the generator recorded from the Rust
        // table (proves parse fidelity, not just file integrity).
        let hash = hex::encode(crate::hash::blake2b256(&table.canonical_bytes()));
        assert_eq!(hash, table.blake2b256_hex());
        assert_eq!(
            hash,
            "8040da9d6a5331edd3e7e0c32a55a180b42ea112e23178b4a14c2b5e4a2d3974"
        );
    }

    #[test]
    fn op_count_is_exactly_12359() {
        let table = PolyExtTable::parse(OPS_TSV).expect("ops parse");
        assert_eq!(table.ops_count(), 12359);
        assert_eq!(table.ops().len(), 12359);
    }

    #[test]
    fn ops_loader_accepts_tiny_table_and_interpreter_evaluates_it() {
        let t = PolyExtTable::parse(&tiny()).expect("tiny parse");
        let poly_mix = Ext4::new(7, 0, 3, 0);
        // (5 - 5) folded through True gives tot = 0, mul = poly_mix.
        let ms = step(&t, poly_mix, &[], &EMPTY_ARGS).expect("tiny evaluates");
        assert_eq!(ms.tot, Ext4::ZERO);
        assert_eq!(ms.mul, poly_mix);
    }

    // ----- error paths -----

    #[test]
    fn interpreter_rejects_non_canonical_const_and_const_ext() {
        let bad_const =
            PolyExtTable::parse(&tiny_mut("op\t0\tConst\t5", "op\t0\tConst\t2013265921"))
                .expect("parse accepts u32-range literal");
        assert!(step(&bad_const, Ext4::ONE, &[], &EMPTY_ARGS).is_err());

        let const_ext_tbl = [
            "meta\tops_count\t2",
            "meta\tret\t0",
            "meta\tfp_vars\t1",
            "meta\tmix_vars\t1",
            "meta\topcode_histogram\tConstExt=1,True=1",
            "meta\tblake2b256\t00",
            "op\t0\tConstExt\t0,0,2013265921,0",
            "op\t1\tTrue\t-",
        ]
        .join("\n");
        let bad_const_ext = PolyExtTable::parse(&const_ext_tbl).expect("parse accepts");
        assert!(step(&bad_const_ext, Ext4::ONE, &[], &EMPTY_ARGS).is_err());
    }

    #[test]
    fn ops_loader_requires_explicit_sentinel_and_rejects_ambiguous_fields() {
        assert!(PolyExtTable::parse(&tiny_mut("op\t3\tTrue\t-", "op\t3\tTrue\t")).is_err());
        assert!(PolyExtTable::parse(&tiny_mut("op\t3\tTrue\t-", "op\t3\tTrue\t- ")).is_err());
        assert!(PolyExtTable::parse(&tiny_mut("op\t3\tTrue\t-", "op\t3\tTrue\t0")).is_err());
        assert!(PolyExtTable::parse(&tiny_mut("op\t0\tConst\t5", "op\t0\tConst\t-")).is_err());
        assert!(PolyExtTable::parse(&tiny_mut("op\t0\tConst\t5", "op\t0\t\t5")).is_err());
        assert!(PolyExtTable::parse(&tiny_mut("meta\tret\t1", "meta\tret\t")).is_err());
    }

    #[test]
    fn ops_loader_rejects_forward_refs_bad_mnemonics_and_shape_mismatches() {
        // Sub referencing an fp var not pushed yet.
        assert!(PolyExtTable::parse(&tiny_mut("op\t2\tSub\t0,1", "op\t2\tSub\t0,2")).is_err());
        // AndEqz referencing a mix var not pushed yet.
        assert!(
            PolyExtTable::parse(&tiny_mut("op\t4\tAndEqz\t0,2", "op\t4\tAndEqz\t1,2")).is_err()
        );
        // Unknown mnemonic.
        assert!(PolyExtTable::parse(&tiny_mut("op\t0\tConst\t5", "op\t0\tFrobnicate\t5")).is_err());
        // Non-numeric operand.
        assert!(PolyExtTable::parse(&tiny_mut("op\t0\tConst\t5", "op\t0\tConst\tx")).is_err());
        // Out-of-order op index.
        assert!(PolyExtTable::parse(&tiny_mut("op\t1\tConst\t5", "op\t9\tConst\t5")).is_err());
        // ret not the last mix var.
        assert!(PolyExtTable::parse(&tiny_mut("meta\tret\t1", "meta\tret\t0")).is_err());
        // Histogram mismatch.
        assert!(PolyExtTable::parse(&tiny_mut(
            "meta\topcode_histogram\tAndEqz=1,Const=2,Sub=1,True=1",
            "meta\topcode_histogram\tAndEqz=1,Const=1,Sub=2,True=1"
        ))
        .is_err());
        // Truncated table: meta counts no longer match (drop the last op).
        let truncated = TINY[..TINY.len() - 1].join("\n");
        assert!(PolyExtTable::parse(&truncated).is_err());
    }

    #[test]
    fn interpreter_rejects_out_of_range_taps_and_globals_with_err() {
        let table = PolyExtTable::parse(OPS_TSV).expect("ops parse");
        let tap_count = 643usize;
        let poly_mix = Ext4::new(1, 2, 3, 4);
        let ok_out = vec![0u32; 32];
        let ok_mix = vec![0u32; 20];

        // Real table, u too short for its Get ops.
        assert!(step(&table, poly_mix, &[], &[&ok_out, &ok_mix]).is_err());

        let u = vec![Ext4::ZERO; tap_count];
        // Missing mix-globals buffer.
        assert!(step(&table, poly_mix, &u, &[&ok_out]).is_err());
        // Mix-globals buffer too short.
        let short_mix = vec![0u32; 19];
        assert!(step(&table, poly_mix, &u, &[&ok_out, &short_mix]).is_err());
        // Non-canonical global value.
        let mut bad_out = vec![0u32; 32];
        bad_out[0] = 2013265921;
        assert!(step(&table, poly_mix, &u, &[&bad_out, &ok_mix]).is_err());
        // All-zero canonical inputs are structurally fine and must evaluate.
        assert!(step(&table, poly_mix, &u, &[&ok_out, &ok_mix]).is_ok());
    }

    #[test]
    fn from_validated_interpreter_rejects_out_of_range_operands() {
        // The construction boundary preserves the interpreter's defensive
        // bounds even for hand-built tables (mirror of the reference's
        // fromValidatedBinary negative-operand rejection).
        let taps = [Ext4::ZERO];
        let globals: [&[u32]; 2] = [&[0], &[0]];

        let get_oob =
            PolyExtTable::from_validated(vec![PolyExtOp::Get(1), PolyExtOp::True], 0, 1, 1);
        assert!(step(&get_oob, Ext4::ONE, &taps, &globals).is_err());

        let fp_oob = PolyExtTable::from_validated(
            vec![PolyExtOp::Const(1), PolyExtOp::Add(1, 0), PolyExtOp::True],
            0,
            2,
            1,
        );
        assert!(step(&fp_oob, Ext4::ONE, &taps, &globals).is_err());

        let good_global = PolyExtTable::from_validated(
            vec![PolyExtOp::GetGlobal(0, 0), PolyExtOp::True],
            0,
            1,
            1,
        );
        assert!(step(&good_global, Ext4::ONE, &taps, &globals).is_ok());
    }
}
