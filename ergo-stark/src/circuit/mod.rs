//! Layer 3 — the recursion circuit's DEEP-ALI constraint layer of the EIP-0045
//! `verifyStark` raw-seal STARK verifier.
//!
//! Two faithful ports of the reference sigmastate circuit tables plus their
//! interpreter:
//! - [`tap_set`] — the [`CircuitTapSet`]: which trace columns/registers are
//!   sampled at which rotations (backs). This drives which sampled values feed
//!   the interpreter.
//! - [`poly_ext`] — the 12,359-op [`PolyExtTable`] constraint program and the
//!   [`step`] interpreter that executes it over [`Ext4`](crate::ext4::Ext4),
//!   producing the per-query DEEP-ALI "goal" that FRI consumes.
//!
//! The Layer-4 verifier wires [`deep_goal`] into
//! [`fri_verify`](crate::fri::fri_verify)'s
//! `inner: FnMut(&mut ReadIop, usize) -> Result<Ext4, String>`: for each query
//! position it reads that query's tap Merkle openings, builds the tapped
//! evaluations `u` and the global buffers, then calls the interpreter and takes
//! the result `tot` as the goal.
//!
//! Consensus-critical: every table and every op result reproduces the reference
//! byte-for-byte, pinned by the extracted KAT oracles (`circuit_taps.tsv`,
//! `circuit_polyext_ops.tsv`, `polyext_transcript_oracle.tsv`) per the
//! oracle-parity rule.

pub mod poly_ext;
pub mod tap_set;

pub use poly_ext::{deep_goal, step, MixState, PolyExtOp, PolyExtTable};
pub use tap_set::{CircuitTap, CircuitTapSet, TapRegister};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext4::Ext4;
    use std::collections::HashMap;

    // ----- helpers -----

    const TAPS_TSV: &str = include_str!("../../../test-vectors/ergo-stark/circuit_taps.tsv");
    const OPS_TSV: &str = include_str!("../../../test-vectors/ergo-stark/circuit_polyext_ops.tsv");
    const ORACLE_TSV: &str =
        include_str!("../../../test-vectors/ergo-stark/polyext_transcript_oracle.tsv");

    /// The BabyBear prime; canonical checkpoint words are `[0, P)`.
    const P: i64 = 2013265921;

    fn ext(words: &[u32], at: usize) -> Ext4 {
        Ext4::new(words[at], words[at + 1], words[at + 2], words[at + 3])
    }

    /// Parse the six `ck` checkpoint rows of the transcript oracle by label.
    /// `eval_u` carries a leading count field; the rest are plain comma-joined
    /// canonical u32 lists.
    fn checkpoints() -> HashMap<String, Vec<u32>> {
        let mut map = HashMap::new();
        for line in ORACLE_TSV.lines() {
            if !line.starts_with("ck\t") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            let label = f[1];
            let values: Vec<u32> = f
                .last()
                .unwrap()
                .split(',')
                .map(|s| {
                    let v: i64 = s.parse().unwrap();
                    assert!((0..P).contains(&v), "non-canonical checkpoint word {v}");
                    v as u32
                })
                .collect();
            if label == "eval_u" {
                assert_eq!(f[2].parse::<usize>().unwrap(), values.len() / 4);
            }
            map.insert(label.to_string(), values);
        }
        map
    }

    // ----- oracle parity -----

    #[test]
    fn interpreter_reproduces_devnet_receipt_constraint_evaluation() {
        // Expected values come from the compact external oracle extracted
        // verbatim from a real devnet receipt the unmodified Rust verifier
        // accepted — never from this port (oracle-parity rule).
        let cps = checkpoints();
        let out = &cps["out"];
        let mix = &cps["mix"];
        assert_eq!(out.len(), 32);
        assert_eq!(mix.len(), 20);
        let poly_mix = ext(&cps["poly_mix"], 0);

        let tap_set = CircuitTapSet::parse(TAPS_TSV).expect("taps parse");
        let eval_u = &cps["eval_u"];
        assert_eq!(eval_u.len(), tap_set.tap_size() * 4);
        let u: Vec<Ext4> = (0..tap_set.tap_size())
            .map(|i| ext(eval_u, i * 4))
            .collect();

        let table = PolyExtTable::parse(OPS_TSV).expect("ops parse");
        let args: [&[u32]; 2] = [out.as_slice(), mix.as_slice()];
        let ms = step(&table, poly_mix, &u, &args).expect("interpreter accepts recorded inputs");

        let expected = ext(&cps["result"], 0);
        assert_eq!(
            ms.tot, expected,
            "constraint evaluation must match the receipt"
        );
        // The DEEP-goal entry point projects to the same value.
        assert_eq!(deep_goal(&table, poly_mix, &u, &args).unwrap(), expected);
        // The verifier accepted, so the recorded check polynomial equals the
        // recorded result — pin that consistency of the capture itself too.
        assert_eq!(cps["check_value"], cps["result"]);
    }

    #[test]
    fn get_ops_stay_inside_the_tapset() {
        let table = PolyExtTable::parse(OPS_TSV).expect("ops parse");
        let tap_set = CircuitTapSet::parse(TAPS_TSV).expect("taps parse");
        let max_get = table
            .ops()
            .iter()
            .filter_map(|op| match op {
                PolyExtOp::Get(t) => Some(*t),
                _ => None,
            })
            .max()
            .expect("table references taps");
        assert!((max_get as usize) < tap_set.tap_size());
    }
}
