//! Deterministic delta-debugging minimizer for the fuzz-differential harness.
//!
//! [`minimize`] shrinks an input byte slice to the smallest form that still
//! satisfies a caller-supplied predicate.  Contract:
//!
//! * **Correct** — the returned slice always satisfies the predicate (never
//!   returns a slice for which the predicate is false).
//! * **Deterministic** — same `(input, predicate)` → same output.
//! * **Terminating** — the outer loop exits when no phase makes progress; since
//!   each iteration only exits the loop by shrinking `current.len()`, and
//!   length is bounded below by 0, this terminates in ≤ `O(n²)` predicate calls.
//!
//! [`minimize_divergence`] wires the minimizer to the JVM oracle: it builds the
//! predicate from a `diff` call (same surface + same [`DivergenceKind`] + same
//! rust/jvm verdict class), minimizes, and then **re-verifies** that the result
//! still produces the same divergence signature.  A non-reproducing result is a
//! bug in the minimizer — not a finding — and is reported as an error.

use std::io;

use crate::oracle::{diff, Divergence, Oracle, SurfaceSpec, Verdict};

// ─────────────────────────────────────────────────────────────────────────────
// Core minimizer
// ─────────────────────────────────────────────────────────────────────────────

/// Greedy byte-delta minimizer.
///
/// Each outer iteration runs three phases in order:
///
/// 1. **Chunk removal** — for chunk sizes `len/2`, `len/4`, …, `1`: scan the
///    current bytes and drop every block of that size for which the predicate
///    still holds.  On a successful removal, restart with `chunk_size =
///    new_len/2` so larger jumps are tried again before finer ones.
/// 2. **Truncation** — find the shortest prefix (longest to shortest) that
///    still satisfies the predicate and truncate to it.
/// 3. **Single-byte deletion** — scan left to right; delete any byte whose
///    removal preserves the predicate.
///
/// The outer loop exits once a full pass through all three phases leaves
/// `current.len()` unchanged (fixed point).
pub fn minimize<P: FnMut(&[u8]) -> bool>(input: &[u8], mut predicate: P) -> Vec<u8> {
    let mut current = input.to_vec();

    loop {
        let prev_len = current.len();

        // ── Phase 1: chunk-based removal ─────────────────────────────────────
        // Start at len/2, halve down to 1.  On every successful removal we
        // reset to `new_len/2` so we try larger chunks again on the shorter
        // input before continuing.
        let mut chunk_size = current.len() / 2;
        while chunk_size >= 1 {
            let mut pos = 0;
            let mut shrank_this_pass = false;
            while pos + chunk_size <= current.len() {
                let end = pos + chunk_size;
                let mut candidate = current[..pos].to_vec();
                candidate.extend_from_slice(&current[end..]);
                if predicate(&candidate) {
                    current = candidate;
                    shrank_this_pass = true;
                    // Stay at `pos`: the bytes from `end..` shifted left so
                    // the next chunk to try starts at the same index.
                } else {
                    pos += chunk_size;
                }
            }
            if shrank_this_pass {
                // Try larger chunks again on the now-shorter input.
                chunk_size = current.len() / 2;
            } else {
                chunk_size /= 2;
            }
        }

        // ── Phase 2: truncation ───────────────────────────────────────────────
        // Try prefixes from `len-1` down to `0`; accept the first that satisfies.
        for new_len in (0..current.len()).rev() {
            if predicate(&current[..new_len]) {
                current.truncate(new_len);
                break;
            }
        }

        // ── Phase 3: single-byte deletion ─────────────────────────────────────
        let mut pos = 0;
        while pos < current.len() {
            let mut candidate = current[..pos].to_vec();
            candidate.extend_from_slice(&current[pos + 1..]);
            if predicate(&candidate) {
                current = candidate;
                // Stay at `pos`: bytes shifted left, so we try the same
                // index again (a different byte now occupies it).
            } else {
                pos += 1;
            }
        }

        // Fixed-point check.
        if current.len() == prev_len {
            break;
        }
    }

    current
}

// ─────────────────────────────────────────────────────────────────────────────
// Oracle-wired minimize_divergence
// ─────────────────────────────────────────────────────────────────────────────

/// Root-cause key: captures the essential identity of a divergence for
/// predicate matching during minimization.  We use `surface`, `kind`, and the
/// verdict class of each side (accept vs. reject:<first-word>) so a minimized
/// input that shifts the error site to a different message still counts as
/// "same divergence".  We do NOT embed the exact canonical bytes or error text.
pub(crate) fn divergence_class_key(d: &Divergence) -> String {
    let cls = |v: &Verdict| match v {
        Verdict::Accept(_) => "accept".to_string(),
        Verdict::Reject(e) => format!("reject:{}", e.split_whitespace().next().unwrap_or("")),
        Verdict::Err(_) => "err".to_string(),
    };
    format!(
        "{}|{:?}|rust={}|jvm={}",
        d.surface,
        d.kind,
        cls(&d.rust),
        cls(&d.jvm)
    )
}

/// Minimize a diverging input to its shortest form that still produces the
/// same divergence class, then **re-verify** the result.
///
/// Returns `(minimized_bytes, minimized_divergence)`.
///
/// # Re-verify invariant
/// After minimization, this function calls `diff` once more on the minimized
/// bytes.  If the result does not reproduce with the same signature, an
/// `InvalidData` error is returned — this indicates a minimizer bug (the
/// predicate returned `true` for a candidate that later failed re-verification).
///
/// # Errors
/// * `InvalidInput` — `orig_input` does not diverge (predicate never true).
/// * `Other` — oracle pipe broke during minimization.
/// * `InvalidData` — minimized bytes no longer reproduce (minimizer bug).
pub fn minimize_divergence(
    orig_input: &[u8],
    spec: &SurfaceSpec,
    oracle: &mut Oracle,
) -> io::Result<(Vec<u8>, Divergence)> {
    // Step 1: confirm the original input diverges and record its class key.
    let orig_div = diff(spec, orig_input, oracle)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "orig_input does not diverge on the given surface",
        )
    })?;
    let orig_key = divergence_class_key(&orig_div);

    // Step 2: minimize.
    //
    // The closure captures `oracle` by unique reborrow and `oracle_err` by
    // unique reborrow.  Both captures are scoped to the inner block so they are
    // released (closure dropped) when `minimize` returns, making `oracle`
    // accessible again for the re-verify step below.
    let mut oracle_err: Option<io::Error> = None;
    let minimized = {
        let oracle_ref: &mut Oracle = &mut *oracle;
        let err_ref: &mut Option<io::Error> = &mut oracle_err;
        minimize(orig_input, |candidate| {
            if err_ref.is_some() {
                return false;
            }
            match diff(spec, candidate, oracle_ref) {
                Ok(Some(d)) => divergence_class_key(&d) == orig_key,
                Ok(None) => false,
                Err(e) => {
                    *err_ref = Some(e);
                    false
                }
            }
        })
    };
    if let Some(e) = oracle_err {
        return Err(e);
    }

    // Step 3: re-verify — oracle is accessible again because the closure above
    // was dropped when `minimize` returned.
    let min_div = diff(spec, &minimized, oracle)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "minimizer bug: minimized input ({} bytes, hex={}) no longer diverges",
                minimized.len(),
                crate::to_hex(&minimized),
            ),
        )
    })?;
    if divergence_class_key(&min_div) != orig_key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "minimizer bug: divergence signature changed after minimization \
                 (was {orig_key:?}, now {:?})",
                divergence_class_key(&min_div),
            ),
        ));
    }

    Ok((minimized, min_div))
}
