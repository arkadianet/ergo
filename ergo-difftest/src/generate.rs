//! Input generation: pure random bytes plus mutation of a seed corpus.
//!
//! Mutation-from-corpus is the high-yield strategy — real mainnet wire bytes
//! sit on the valid manifold, and a few flips push them just off it, which is
//! exactly where divergences and panics hide. Pure random covers the
//! lead-byte / length-field handling that a corpus rarely exercises.

use crate::rng::Rng;

/// Upper bound on generated input length. The decoders have their own depth and
/// position limits; this just bounds wasted work per iteration.
pub const MAX_INPUT_LEN: usize = 4096;

/// Produce one input. With an empty corpus (or ~1/2 of the time otherwise) it
/// returns random bytes; otherwise it mutates a corpus seed.
pub fn gen_input(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    if corpus.is_empty() || rng.coin() {
        random_bytes(rng)
    } else {
        let seed = &corpus[rng.below(corpus.len())];
        mutate(rng, seed)
    }
}

fn random_bytes(rng: &mut Rng) -> Vec<u8> {
    let len = rng.below(256);
    (0..len).map(|_| rng.byte()).collect()
}

/// Apply 1..=4 small mutations to a copy of `seed`.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    let rounds = rng.range(1, 4);
    for _ in 0..rounds {
        match rng.below(6) {
            // bit flip
            0 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            // byte set (biased toward boundary bytes that drive UTF-8 / VLQ / length handling)
            1 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] = BOUNDARY[rng.below(BOUNDARY.len())];
            }
            // truncate
            2 if !out.is_empty() => {
                out.truncate(rng.below(out.len()));
            }
            // insert a byte
            3 if out.len() < MAX_INPUT_LEN => {
                let i = rng.below(out.len() + 1);
                out.insert(i, rng.byte());
            }
            // duplicate a region (stresses length / count fields)
            4 if !out.is_empty() => {
                let i = rng.below(out.len());
                let n = rng.range(1, out.len() - i);
                let chunk = out[i..i + n].to_vec();
                let at = rng.below(out.len() + 1);
                for (k, b) in chunk.into_iter().enumerate() {
                    if out.len() >= MAX_INPUT_LEN {
                        break;
                    }
                    out.insert(at + k, b);
                }
            }
            // overwrite a random byte with a fully random value
            _ if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] = rng.byte();
            }
            _ => {}
        }
    }
    out.truncate(MAX_INPUT_LEN);
    out
}

/// Bytes that sit on the decision boundaries of the wire format: UTF-8
/// lead/continuation/invalid bytes, VLQ continuation bits, and 0x00/0xFF.
const BOUNDARY: &[u8] = &[
    0x00, 0x01, 0x7f, 0x80, 0x81, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xed, 0xef, 0xf0, 0xf4, 0xf5,
    0xf8, 0xfe, 0xff,
];
