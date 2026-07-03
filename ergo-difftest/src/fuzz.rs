//! Stable `fuzz_one` entry point consumed by the nightly cargo-fuzz shims.
//!
//! The REAL fuzz logic lives here, compiled on stable 1.95.0 and unit-tested
//! without nightly. The `ergo-difftest/fuzz/fuzz_targets/` directory contains
//! thin 3-line shims that call this function via libFuzzer. See
//! `ergo-difftest/fuzz/README.md` for how to run those targets.
//!
//! # Design (decision D1 from interface-contracts.md §6)
//!
//! Keeping the logic on stable means:
//! - The invariant code is covered by the stable CI gate and unit tests.
//! - The nightly shims are 3 lines each and contain no testable logic.
//! - A nightly build outage cannot blind the coverage gate (it runs on stable).
//!
//! # Panic contract
//!
//! `fuzz_one` panics if and only if an invariant violation (`Outcome::Bug`) is
//! detected. libFuzzer treats a panic as a crash and records the input.
//! Clean outcomes (`Accepted`, `Rejected`, `WriteRejected`) and unknown surface
//! names all return `()` silently — no false-positive crashes.

use crate::{run_input, Outcome};

/// Run `data` through the hermetic invariant for `surface` and panic if any
/// invariant is violated.
///
/// Behavior:
/// * `Outcome::Bug` — panics (libFuzzer crash signal; the bytes are saved).
/// * `Outcome::Accepted` / `Rejected` / `WriteRejected` — returns `()`.
/// * Unknown `surface` name — returns `()` silently (no false positive).
pub fn fuzz_one(surface: &str, data: &[u8]) {
    let results = run_input(data, Some(surface));
    for (_, outcome) in results {
        if let Outcome::Bug(detail) = outcome {
            panic!("fuzz_one({surface:?}): invariant violation: {detail}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::{self, SURFACES};
    use crate::rng::Rng;

    /// An on-manifold generator output (believed valid by the real writers) must
    /// never trigger an invariant violation.
    #[test]
    fn fuzz_one_on_manifold_ergo_tree_does_not_panic() {
        let mut rng = Rng::new(42);
        let output = gen::gen_on_manifold(&mut rng, "ergo_tree");
        // Must not panic.
        fuzz_one("ergo_tree", &output.bytes);
    }

    /// Arbitrary / malformed bytes must be rejected cleanly (`Rejected`), never
    /// cause a Bug or panic.
    #[test]
    fn fuzz_one_garbage_does_not_panic() {
        fuzz_one("ergo_tree", &[0xFF, 0xFE, 0x00, 0x12]);
        fuzz_one("constant", &[0xDE, 0xAD, 0xBE, 0xEF]);
        fuzz_one("header", &[0x00]);
        fuzz_one("transaction", &[]);
        fuzz_one("ergo_box_candidate", &[0x80, 0x80, 0x80]);
        fuzz_one("sigma_expr", &[0xFF]);
    }

    /// An unknown surface must return silently — no panic, no false positive.
    #[test]
    fn fuzz_one_unknown_surface_does_not_panic() {
        fuzz_one("totally_unknown_surface", &[1, 2, 3]);
        fuzz_one("", &[]);
        fuzz_one("__not_a_surface__", &[0x00]);
    }

    /// Every named gen surface must accept an on-manifold seed without panicking.
    #[test]
    fn fuzz_one_all_gen_surfaces_valid_on_manifold() {
        let mut rng = Rng::new(99);
        for &surface in SURFACES.iter() {
            let output = gen::gen_on_manifold(&mut rng, surface);
            // must not panic on a valid seed
            fuzz_one(surface, &output.bytes);
        }
    }

    /// Empty input on any gen surface must not panic (always Rejected or similar,
    /// never Bug).
    #[test]
    fn fuzz_one_empty_does_not_panic_on_any_surface() {
        for &surface in SURFACES.iter() {
            fuzz_one(surface, &[]);
        }
    }
}
