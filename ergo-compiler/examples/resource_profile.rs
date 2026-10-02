//! Repeatable compiler/evaluator resource measurements. Run in release mode;
//! use an external RSS profiler when measuring process memory or allocations.

use std::{collections::HashSet, hint::black_box, time::Instant};

use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
use ergo_primitives::{
    cost::{CostAccumulator, JitCost},
    reader::VlqReader,
};
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::evaluator::{reduce_expr_with_cost, ReductionContext};

fn stored_nodes(prop: &SigmaBoolean) -> usize {
    let mut pending = vec![prop];
    let mut seen = HashSet::new();
    while let Some(prop) = pending.pop() {
        if !seen.insert(prop as *const SigmaBoolean) {
            continue;
        }
        match prop {
            SigmaBoolean::Cand(children)
            | SigmaBoolean::Cor(children)
            | SigmaBoolean::Cthreshold { children, .. } => pending.extend(children.iter()),
            _ => {}
        }
    }
    seen.len()
}

fn main() {
    let repeats = std::env::args()
        .nth(1)
        .map(|n| n.parse::<usize>().expect("positive repeat count"))
        .unwrap_or(1000)
        .max(1);
    println!("layers,source_bytes,tree_bytes,logical_nodes,stored_nodes,eval_jit,crypto_jit,compile_us,reduce_us,clone_ns,estimate_ns");
    for layers in [1, 5, 10, 16, 32, 64] {
        let source = format!(
            "Coll({}).fold(proveDlog(groupGenerator), {{ (a: SigmaProp, i: Int) => a && a }})",
            vec!["0"; layers].join(",")
        );
        let started = Instant::now();
        let compiled = compile(&ScriptEnv::new(), &source, 3, NetworkPrefix::Mainnet).unwrap();
        let compile_us = started.elapsed().as_micros();
        let mut reader = VlqReader::new(&compiled.tree_bytes).with_activated_script_version(3);
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut reader).unwrap();
        let mut ctx = ReductionContext::minimal(0, 0);
        ctx.ergo_tree_version = tree.version;
        let mut cost = CostAccumulator::new(JitCost::from_jit(100_000));
        let started = Instant::now();
        let prop = reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost).unwrap();
        let reduce_us = started.elapsed().as_micros();
        let started = Instant::now();
        for _ in 0..repeats {
            black_box(black_box(&prop).clone());
        }
        let clone_ns = started.elapsed().as_nanos() / repeats as u128;
        let started = Instant::now();
        for _ in 0..repeats {
            black_box(ergo_sigma::crypto_cost::estimate_crypto_cost(black_box(
                &prop,
            )));
        }
        let estimate_ns = started.elapsed().as_nanos() / repeats as u128;
        println!(
            "{layers},{},{},{},{},{},{},{compile_us},{reduce_us},{clone_ns},{estimate_ns}",
            source.len(),
            compiled.tree_bytes.len(),
            prop.size(),
            stored_nodes(&prop),
            cost.total().value(),
            ergo_sigma::crypto_cost::estimate_crypto_cost(&prop).value()
        );
    }
}
