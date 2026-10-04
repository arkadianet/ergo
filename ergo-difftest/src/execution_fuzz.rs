//! Compiler-source and bounded evaluator workloads complement the wire-codec
//! campaigns. They exercise construction, evaluation, sharing and destruction.

use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
use ergo_primitives::{
    cost::{CostAccumulator, JitCost},
    reader::VlqReader,
};
use ergo_sigma::evaluator::{reduce_expr_with_cost, ReductionContext};

/// Compile valid UTF-8 source up to the public playground's 64 KiB source cap.
/// Errors are expected; panics or unsafe recursive destruction are findings.
pub fn fuzz_compiler_source(data: &[u8]) {
    if data.len() > 64 * 1024 {
        return;
    }
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = compile(&ScriptEnv::new(), source, 3, NetworkPrefix::Mainnet);
    }
}

/// Execute a small, well-typed program whose logical proposition can grow
/// exponentially. At most 64 fold steps and a 100,000-JIT evaluator budget keep
/// the workload bounded; repeated values must retain shared storage.
pub fn fuzz_bounded_evaluator(data: &[u8]) {
    let iterations = usize::from(data.first().copied().unwrap_or(0) % 64) + 1;
    let combine = match data.get(1).copied().unwrap_or(0) % 3 {
        0 => "a && a",
        1 => "a || a",
        _ => "atLeast(1, Coll(a, a))",
    };
    let source = format!(
        "Coll({}).fold(proveDlog(groupGenerator), {{ (a: SigmaProp, i: Int) => {combine} }})",
        vec!["0"; iterations].join(",")
    );
    let source = if data.get(2).copied().unwrap_or(0) & 1 == 0 {
        source
    } else {
        format!("sigmaProp(({source}).propBytes.size >= 0)")
    };
    let compiled = compile(&ScriptEnv::new(), &source, 3, NetworkPrefix::Mainnet)
        .expect("bounded workload is well typed");
    let mut reader = VlqReader::new(&compiled.tree_bytes).with_activated_script_version(3);
    let tree =
        ergo_ser::ergo_tree::read_ergo_tree(&mut reader).expect("compiler emits a valid tree");
    assert!(reader.is_empty());
    let mut ctx = ReductionContext::minimal(0, 3);
    ctx.ergo_tree_version = tree.version;
    let mut cost = CostAccumulator::new(JitCost::from_jit(100_000));
    if let Ok(prop) = reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost) {
        let cloned = prop.clone();
        assert_eq!(cloned, prop);
        assert_eq!(cloned.size(), prop.size());
        let _ = ergo_sigma::crypto_cost::estimate_crypto_cost(&prop);
        let mut verify_budget = CostAccumulator::new(JitCost::from_jit(100_000));
        let _ = ergo_sigma::verify::verify_sigma_proof_with_cost(
            &prop,
            &[0; 56],
            b"fuzz",
            &mut verify_budget,
        );
        assert!(format!("{prop:?}").len() < 20_000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn bounded_evaluator_covers_all_fold_and_serialization_choices() {
        for iterations in [0, 4, 9, 15, 31, 63] {
            for combine in 0..3 {
                for serialize in 0..2 {
                    fuzz_bounded_evaluator(&[iterations, combine, serialize]);
                }
            }
        }
    }

    // ----- error paths -----

    #[test]
    fn compiler_source_covers_flat_depth_bypass_and_invalid_utf8() {
        fuzz_compiler_source(&[0xff]);
        fuzz_compiler_source(vec!["1"; 4096].join(" - ").as_bytes());
        fuzz_compiler_source(format!("f{}", "().x".repeat(4096)).as_bytes());
    }
}
