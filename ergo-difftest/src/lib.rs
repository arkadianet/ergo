//! `ergo-difftest` — an invariant / differential fuzzing harness for the Ergo
//! consensus wire-format decoders.
//!
//! Phase 1 (this crate) generates and mutates bytes, runs them through the
//! `ergo-ser` decoders, and checks oracle-free invariants:
//!   * no decode ever panics (the panic class — e.g. the write-overflow fixed
//!     in #97), and
//!   * `decode → encode` reaches a byte-stable fixed point.
//!
//! Phase 2 (`scripts/jvm_serde_oracle`, modeled on `scripts/scala_hamt_oracle`)
//! extracts the Scala reference node's accept/reject + canonical bytes for the
//! inputs this harness surfaces, committing them as Rust vectors — that is the
//! layer that catches accept-vs-reject divergences like the UTF-8 bug.
//!
//! Everything is deterministic: a `(seed, iter)` pair reproduces an identical
//! input, and every finding records the offending bytes as hex.

use std::panic::{self, AssertUnwindSafe};

pub mod generate;
pub mod oracle;
pub mod rng;
pub mod surfaces;

use rng::Rng;

/// Result of running one surface over one input.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Decode returned `Err` — rejecting malformed input is correct.
    Rejected,
    /// Decode succeeded and all invariants held.
    Accepted,
    /// Decode succeeded but re-encode intentionally refused (e.g. a field that
    /// overflows the single-byte wire form). The JVM throws on the same input,
    /// so this is not a bug.
    WriteRejected,
    /// An invariant was violated (or the decode panicked). Carries a
    /// human-readable detail including the offending bytes.
    Bug(String),
}

impl Outcome {
    pub(crate) fn bug(detail: String, bytes: &[u8]) -> Outcome {
        Outcome::Bug(format!("{detail} [bytes={}]", to_hex(bytes)))
    }
}

/// A reproducible invariant violation.
#[derive(Debug, Clone)]
pub struct Finding {
    pub surface: &'static str,
    pub seed: u64,
    pub iter: u64,
    pub input_hex: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub iters: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub write_rejected: u64,
    pub bugs: u64,
}

/// Run a fuzzing campaign. Returns aggregate stats and every finding.
///
/// `only` filters to a single surface by name; `corpus` seeds mutation
/// (empty = pure random). `stop_on_first` returns as soon as a bug is found.
pub fn run_campaign(
    seed: u64,
    iters: u64,
    only: Option<&str>,
    corpus: &[Vec<u8>],
    stop_on_first: bool,
) -> (Stats, Vec<Finding>) {
    let surfaces = surfaces::registry(only);
    let mut rng = Rng::new(seed);
    let mut stats = Stats::default();
    let mut findings = Vec::new();

    let _silent = SilencePanics::install();

    for iter in 0..iters {
        let input = generate::gen_input(&mut rng, corpus);
        for s in &surfaces {
            stats.iters += 1;
            let outcome = run_one(s, &input);
            match outcome {
                Outcome::Accepted => stats.accepted += 1,
                Outcome::Rejected => stats.rejected += 1,
                Outcome::WriteRejected => stats.write_rejected += 1,
                Outcome::Bug(detail) => {
                    stats.bugs += 1;
                    findings.push(Finding {
                        surface: s.name,
                        seed,
                        iter,
                        input_hex: to_hex(&input),
                        detail,
                    });
                    if stop_on_first {
                        return (stats, findings);
                    }
                }
            }
        }
    }
    (stats, findings)
}

/// Run every surface over a single explicit input (for `--repro` / triage).
pub fn run_input(input: &[u8], only: Option<&str>) -> Vec<(&'static str, Outcome)> {
    let surfaces = surfaces::registry(only);
    let _silent = SilencePanics::install();
    surfaces
        .iter()
        .map(|s| (s.name, run_one(s, input)))
        .collect()
}

fn run_one(s: &surfaces::Surface, input: &[u8]) -> Outcome {
    match panic::catch_unwind(AssertUnwindSafe(|| (s.run)(input))) {
        Ok(o) => o,
        // `payload` is `Box<dyn Any>`; deref to inspect the inner `&str`/`String`
        // rather than the box itself.
        Err(payload) => Outcome::bug(format!("PANIC: {}", panic_msg(payload.as_ref())), input),
    }
}

/// Self-check that the harness's bug-detection machinery actually has teeth,
/// run the same way a campaign runs (hook silenced + `catch_unwind`). A decode
/// panic MUST be caught and reported as a [`Outcome::Bug`], never abort the
/// process. Invoked out-of-process via `difftest --selftest` (see
/// `tests/selftest.rs`) so it does not fight the libtest panic hook.
pub fn selftest() -> Result<(), String> {
    let _silent = SilencePanics::install();

    let boom = surfaces::Surface {
        name: "boom",
        run: Box::new(|_| panic!("kaboom")),
    };
    match run_one(&boom, &[1, 2, 3]) {
        Outcome::Bug(d) if d.contains("PANIC") && d.contains("kaboom") => {}
        other => return Err(format!("panic was not caught/reported as Bug: {other:?}")),
    }

    let clean = surfaces::Surface {
        name: "ok",
        run: Box::new(|_| Outcome::Accepted),
    };
    if run_one(&clean, &[0]) != Outcome::Accepted {
        return Err("clean surface did not pass through".to_string());
    }

    Ok(())
}

fn panic_msg(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    // Operate on bytes, not string slices: `&s[i..i + 2]` would panic on a
    // multi-byte UTF-8 char straddling an even offset. A hex parser must
    // reject any non-ASCII-hex input with `None`, never crash on it.
    let s = s.trim().as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    s.chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

/// RAII guard that silences the default panic hook for the duration of a
/// campaign (the decoders' panics are expected to be caught and reported, not
/// printed). Restores the prior hook on drop.
type PanicHook = Box<dyn Fn(&panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

struct SilencePanics {
    prev: Option<PanicHook>,
}

impl SilencePanics {
    fn install() -> Self {
        let prev = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        SilencePanics { prev: Some(prev) }
    }
}

impl Drop for SilencePanics {
    fn drop(&mut self) {
        if let Some(prev) = self.prev.take() {
            panic::set_hook(prev);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NB: the panic-catching path is verified out-of-process by
    // `tests/selftest.rs` (`difftest --selftest`). Triggering a real panic
    // inside a `#[test]` fights the libtest panic hook, so it is not done here.

    #[test]
    fn clean_surface_passes_through() {
        let s = surfaces::Surface {
            name: "ok",
            run: Box::new(|_| Outcome::Accepted),
        };
        assert_eq!(run_one(&s, &[0]), Outcome::Accepted);
    }

    #[test]
    fn hex_round_trips() {
        let b = vec![0x00, 0x1b, 0xff, 0xa0];
        assert_eq!(from_hex(&to_hex(&b)).unwrap(), b);
    }

    #[test]
    fn from_hex_non_ascii_returns_none_not_panic() {
        // A multi-byte UTF-8 char at an even offset would panic a string-slice
        // parser. The byte-wise parser must reject it with `None`.
        assert_eq!(from_hex("éé"), None); // 4 bytes, no ASCII-hex boundary panic
        assert_eq!(from_hex("0é"), None); // odd-after-trim shape, mixed bytes
        assert_eq!(from_hex("zz"), None); // even length, not hex digits
    }
}
