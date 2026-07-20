//! The FRI low-degree-test verifier of the EIP-0045 `verifyStark` raw-seal
//! STARK verifier — a faithful port of the reference sigmastate `FriVerifier`
//! (mirror of risc0-zkp 3.0.4 `verify::fri::fri_verify` / `verify_query` with
//! the Poseidon2 hash suite, plus the 16-point inverse NTT it folds with).
//! Consensus-critical: it must accept exactly the FRI transcripts the reference
//! accepts and reject exactly the ones it rejects.
//!
//! # Protocol (upstream `fri_verify`, parameterized by `tot_cycles` = the
//! degree bound and `queries`)
//! 1. Commit phase: while `degree > FRI_MIN_DEGREE`, read one fold-round Merkle
//!    tree (rows = domain/16, cols = 64) via [`MerkleVerifier`] (which commits
//!    the root to the transcript), then draw the round's fold mix
//!    ([`ReadIop::random_ext_elem`]), dividing degree and domain by 16.
//! 2. Read the final polynomial (`4·degree` elements) and commit its hash.
//! 3. Query phase, per query: draw `pos = random_bits(log2(orig_domain))`,
//!    obtain the DEEP-ALI `goal` from `inner(pos)`, then per round: open the
//!    64-element column at `pos % rows`, check the goal against the column,
//!    fold (inverse-NTT the 16 ext elements, evaluate at
//!    `mix · RouRev(log2(16·rows))^group`) and reduce the position; finally
//!    evaluate the final polynomial at `RouFwd(log2(final_domain))^pos` and
//!    require it equal the goal.
//!
//! `inner` is the caller-supplied per-query opening of the DEEP-ALI quotient
//! (upstream's `InnerFn`); it may read from the same `iop` (branch reads never
//! touch the transcript rng, exactly upstream's split).
//!
//! # Wire-form conventions
//! Follow [`ReadIop`] / [`MerkleVerifier`]: Merkle column values and final-poly
//! coefficients arrive as validated CANONICAL values
//! ([`ReadIop::read_field_elem_slice`]); the fold math runs entirely in
//! canonical [`Ext4`]; the final-poly digest is re-encoded RAW
//! ([`BabyBear::to_raw`]) at the commit boundary, matching upstream's
//! `hash_elem_slice` + `commit`.

use crate::baby_bear::BabyBear;
use crate::ext4::Ext4;
use crate::merkle::MerkleVerifier;
use crate::poseidon2::Poseidon2;
use crate::read_iop::ReadIop;

/// risc0-zkp 3.0.4 `src/lib.rs`: query count of the stock profile.
pub const QUERIES: usize = 50;
/// risc0-zkp 3.0.4 `src/lib.rs`: the reciprocal of the coding rate.
pub const INV_RATE: usize = 4;
/// risc0-zkp 3.0.4 `src/lib.rs`: fold factor exponent (`16 = 1 << 4`).
pub const FRI_FOLD_PO2: usize = 4;
/// risc0-zkp 3.0.4 `src/lib.rs`: fold factor `16`.
pub const FRI_FOLD: usize = 1 << FRI_FOLD_PO2;
/// risc0-zkp 3.0.4 `src/lib.rs` (private upstream, cited): folding stops once
/// the degree is at most this.
pub const FRI_MIN_DEGREE: usize = 256;

/// risc0-core BabyBear roots of unity (`field/baby_bear.rs`
/// `RootsOfUnity::ROU_FWD`), CANONICAL values; index = po2, `MAX_ROU_PO2 = 27`.
/// `RouFwd(k)` has order `2^k`. Asserted equal to risc0-core's own constants by
/// the `rou_fwd` vector of `fri_kat.tsv`.
static ROU_FWD_TABLE: [u32; 28] = [
    1, 2013265920, 284861408, 1801542727, 567209306, 740045640, 918899846, 1881002012, 1453957774,
    65325759, 1538055801, 515192888, 483885487, 157393079, 1695124103, 2005211659, 1540072241,
    88064245, 1542985445, 1269900459, 1461624142, 825701067, 682402162, 1311873874, 1164520853,
    352275361, 18769, 137,
];

/// `RouRev(k) = RouFwd(k)^-1` (`field/baby_bear.rs` `RootsOfUnity::ROU_REV`),
/// CANONICAL values. Asserted equal to risc0-core's own constants by the
/// `rou_rev` vector of `fri_kat.tsv`.
static ROU_REV_TABLE: [u32; 28] = [
    1, 2013265920, 1728404513, 1592366214, 196396260, 1253260071, 72041623, 1091445674, 145223211,
    1446820157, 1030796471, 2010749425, 1827366325, 1239938613, 246299276, 596347512, 1893145354,
    246074437, 1525739923, 1194341128, 1463599021, 704606912, 95395244, 15672543, 647517488,
    584175179, 137728885, 749463956,
];

/// `RouFwd(po2)` — a forward root of unity of order `2^po2`.
pub fn rou_fwd(po2: usize) -> u32 {
    ROU_FWD_TABLE[po2]
}

/// `RouRev(po2)` — the inverse of [`rou_fwd`].
pub fn rou_rev(po2: usize) -> u32 {
    ROU_REV_TABLE[po2]
}

/// Immutable view of the forward roots-of-unity table. The table is a private
/// `static`, so this borrow can never mutate the consensus constants.
pub fn rou_fwd_table() -> &'static [u32] {
    &ROU_FWD_TABLE
}

/// Immutable view of the reverse roots-of-unity table.
pub fn rou_rev_table() -> &'static [u32] {
    &ROU_REV_TABLE
}

/// Instrumentation hook called with `(query, round, pos, goal)` immediately
/// before round `round` processes the query (`round == rounds` = the
/// final-polynomial comparison state). Consensus paths use [`fri_verify`],
/// which supplies a no-op; the KAT harness uses [`fri_verify_probed`] to pin
/// per-round fold checkpoints.
pub trait Probe {
    /// Observe one `(query, round, pos, goal)` checkpoint.
    fn probe(&mut self, query: usize, round: usize, pos: usize, goal: Ext4);
}

impl<F: FnMut(usize, usize, usize, Ext4)> Probe for F {
    fn probe(&mut self, query: usize, round: usize, pos: usize, goal: Ext4) {
        self(query, round, pos, goal)
    }
}

/// One fold round's verification state (upstream `VerifyRoundInfo`): `rows` =
/// the folded domain, the round's Merkle tree over 64-element columns, and the
/// fold mix drawn AFTER the root commit.
struct RoundInfo {
    rows: usize,
    merkle: MerkleVerifier,
    mix: Ext4,
}

/// Verify the FRI proof section of `iop` — upstream `fri_verify`, with a no-op
/// probe. See [`fri_verify_probed`] for the semantics of `tot_cycles`,
/// `queries` and `inner`.
pub fn fri_verify<I>(
    iop: &mut ReadIop,
    tot_cycles: usize,
    queries: usize,
    inner: I,
) -> Result<(), String>
where
    I: FnMut(usize) -> Result<Ext4, String>,
{
    fri_verify_probed(iop, tot_cycles, queries, inner, |_, _, _, _| {})
}

/// Verify the FRI proof section of `iop` with a per-round `probe` —
/// upstream `fri_verify`.
///
/// `tot_cycles` is the degree bound (`2^po2`, a verifier-validated parameter,
/// not raw proof data — the outer verifier bounds po2 before calling);
/// `inner` supplies each query's DEEP-ALI goal and may consume proof words from
/// `iop`. Returns `Err` on any malformed or non-verifying proof; never panics
/// on proof data.
///
/// # Panics
/// Panics (via `assert!`) if `tot_cycles` is not a positive power of two or
/// `queries` is not positive — verifier-chosen parameters, mirroring the
/// reference `require`.
pub fn fri_verify_probed<I, P>(
    iop: &mut ReadIop,
    tot_cycles: usize,
    queries: usize,
    mut inner: I,
    mut probe: P,
) -> Result<(), String>
where
    I: FnMut(usize) -> Result<Ext4, String>,
    P: Probe,
{
    assert!(
        tot_cycles > 0 && (tot_cycles & (tot_cycles - 1)) == 0,
        "totCycles not a power of 2: {tot_cycles}"
    );
    assert!(queries > 0, "queries must be positive: {queries}");

    let mut degree = tot_cycles;
    let orig_domain = INV_RATE * tot_cycles;
    let mut domain = orig_domain;

    // Commit phase: one Merkle tree + fold mix per round. Pushing appends in
    // natural (first-to-last) round order — the reference prepends then
    // reverses to reach the same order.
    let mut rounds: Vec<RoundInfo> = Vec::new();
    while degree > FRI_MIN_DEGREE {
        let rows = domain / FRI_FOLD;
        let merkle = MerkleVerifier::create(iop, rows, FRI_FOLD * 4, queries)
            .map_err(|e| format!("fri round: {e}"))?;
        // The fold mix is drawn AFTER `create` commits the round's root.
        let mix = iop.random_ext_elem();
        rounds.push(RoundInfo { rows, merkle, mix });
        domain /= FRI_FOLD;
        degree /= FRI_FOLD;
    }

    // Final polynomial: read, commit its hash.
    let final_coeffs = iop
        .read_field_elem_slice(4 * degree)
        .ok_or_else(|| "fri final poly: truncated or word >= P".to_string())?;
    let digest = Poseidon2::unpadded_hash(&final_coeffs).map(BabyBear::to_raw);
    iop.commit(&digest);
    // Natural-order ext coefficients (plane-major on the wire).
    let mut final_ext = Vec::with_capacity(degree);
    for i in 0..degree {
        final_ext.push(Ext4::new(
            final_coeffs[i],
            final_coeffs[degree + i],
            final_coeffs[2 * degree + i],
            final_coeffs[3 * degree + i],
        ));
    }
    let gen = rou_fwd(log2_ceil(domain));

    // Query phase.
    let pos_bits = log2_ceil(orig_domain) as u32;
    for q in 0..queries {
        let mut pos = iop.random_bits(pos_bits) as usize;
        let mut goal = inner(pos).map_err(|e| format!("fri query {q} inner: {e}"))?;
        for (r, round) in rounds.iter().enumerate() {
            probe.probe(q, r, pos, goal);
            let quot = pos / round.rows;
            let group = pos % round.rows;
            let row = round
                .merkle
                .verify(iop, group)
                .map_err(|e| format!("fri query {q} round {r}: {e}"))?;
            let mut data_ext = [Ext4::ZERO; FRI_FOLD];
            for (k, cell) in data_ext.iter_mut().enumerate() {
                *cell = Ext4::new(
                    row[k],
                    row[FRI_FOLD + k],
                    row[2 * FRI_FOLD + k],
                    row[3 * FRI_FOLD + k],
                );
            }
            if data_ext[quot] != goal {
                return Err(format!("fri query {q} round {r}: goal mismatch"));
            }
            let root_po2 = log2_ceil(FRI_FOLD * round.rows);
            let inv_wk = BabyBear::pow(rou_rev(root_po2), group as u64);
            interpolate_ntt(&mut data_ext);
            bit_reverse(&mut data_ext);
            goal = poly_eval(&data_ext, scale(round.mix, inv_wk));
            pos = group;
        }
        probe.probe(q, rounds.len(), pos, goal);
        let fx = poly_eval(&final_ext, Ext4::from_base(BabyBear::pow(gen, pos as u64)));
        if fx != goal {
            return Err(format!("fri query {q}: final poly mismatch"));
        }
    }
    Ok(())
}

/// Smallest `r` with `2^r >= v` — upstream `log2_ceil`.
pub fn log2_ceil(v: usize) -> usize {
    let mut r = 0;
    while (1usize << r) < v {
        r += 1;
    }
    r
}

/// Evaluate a polynomial with [`Ext4`] coefficients at `x` (ascending powers) —
/// upstream `Verifier::poly_eval`.
pub fn poly_eval(coeffs: &[Ext4], x: Ext4) -> Ext4 {
    let mut mul_x = Ext4::ONE;
    let mut tot = Ext4::ZERO;
    for c in coeffs {
        tot = tot.add(c.mul(mul_x));
        mul_x = mul_x.mul(x);
    }
    tot
}

/// `e · s` for a base-field scalar `s` (upstream `ExtElem * Elem`).
fn scale(e: Ext4, s: u32) -> Ext4 {
    Ext4::new(
        BabyBear::mul(e.c0, s),
        BabyBear::mul(e.c1, s),
        BabyBear::mul(e.c2, s),
        BabyBear::mul(e.c3, s),
    )
}

/// In-place inverse NTT over a power-of-two-sized array — upstream
/// `core/ntt.rs interpolate_ntt` (`rev_butterfly` then divide by the size).
/// Base-field twiddles ([`rou_rev`]), [`Ext4`] values; output coefficients are
/// in bit-reversed order (upstream pairs this with [`bit_reverse`]).
///
/// # Panics
/// Panics if `io.len()` is not a power of two, mirroring the reference
/// `require`.
pub fn interpolate_ntt(io: &mut [Ext4]) {
    let n = log2_ceil(io.len());
    assert!(
        io.len() == (1usize << n),
        "size not a power of 2: {}",
        io.len()
    );
    rev_butterfly(io, 0, n);
    let norm = BabyBear::inv((io.len() as u64 % BabyBear::P as u64) as u32);
    for e in io.iter_mut() {
        *e = scale(*e, norm);
    }
}

fn rev_butterfly(io: &mut [Ext4], off: usize, n: usize) {
    if n > 0 {
        let half = 1usize << (n - 1);
        let step = rou_rev(n);
        let mut cur = 1u32;
        for i in 0..half {
            let a = io[off + i];
            let b = io[off + i + half];
            io[off + i] = a.add(b);
            io[off + i + half] = scale(a.sub(b), cur);
            cur = BabyBear::mul(cur, step);
        }
        rev_butterfly(io, off, n - 1);
        rev_butterfly(io, off + half, n - 1);
    }
}

/// In-place bit-reversal permutation — upstream `core/ntt.rs bit_reverse`.
///
/// # Panics
/// Panics if `io.len()` is not a power of two, mirroring the reference
/// `require`.
pub fn bit_reverse(io: &mut [Ext4]) {
    let n = log2_ceil(io.len());
    assert!(
        io.len() == (1usize << n),
        "size not a power of 2: {}",
        io.len()
    );
    // The reference shifts by `32 - n`; Java masks the shift amount by 31, so a
    // size-1 array (`n == 0`) shifts by 0. `& 31` reproduces that masking and
    // keeps the shift in range for `u32`.
    let shift = (32 - n as u32) & 31;
    for i in 0..io.len() {
        let rev = ((i as u32).reverse_bits() >> shift) as usize;
        if i < rev {
            io.swap(i, rev);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ----- helpers -----

    fn words(s: &str) -> Vec<u32> {
        if s.is_empty() {
            Vec::new()
        } else {
            s.split(',')
                .map(|w| w.trim().parse::<u64>().unwrap() as u32)
                .collect()
        }
    }

    fn ext(v: &[u32]) -> Ext4 {
        Ext4::new(v[0], v[1], v[2], v[3])
    }

    #[derive(Clone)]
    struct FriCase {
        name: String,
        degree: usize,
        queries: usize,
        initial_commit: [u32; 8],
        proof: Vec<u32>,
        /// `qck[q][r] = (pos, goal)` before round r; last entry = final-poly
        /// comparison state.
        qck: Vec<Vec<(usize, Ext4)>>,
        bad_words: Vec<(usize, u32)>,
        truncates: Vec<usize>,
        bad_goals: Vec<usize>,
    }

    struct FriKat {
        rou_fwd: Vec<u32>,
        rou_rev: Vec<u32>,
        cases: Vec<FriCase>,
    }

    fn parse_kat() -> FriKat {
        let tsv = include_str!("../../test-vectors/ergo-stark/fri_kat.tsv");
        let mut rou_fwd = Vec::new();
        let mut rou_rev = Vec::new();
        let mut cases = Vec::new();
        // Raw per-case fields plus the flat (q,r) -> (pos, goal) checkpoint map.
        let mut cur: Option<FriCase> = None;
        let mut qck: HashMap<(usize, usize), (usize, Ext4)> = HashMap::new();

        for line in tsv
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            if let Some(rest) = line.strip_prefix("rou_fwd:") {
                rou_fwd = words(rest);
            } else if let Some(rest) = line.strip_prefix("rou_rev:") {
                rou_rev = words(rest);
            } else if let Some(rest) = line.strip_prefix("case:") {
                let p: Vec<&str> = rest.split(',').collect();
                cur = Some(FriCase {
                    name: p[0].to_string(),
                    degree: p[1].parse().unwrap(),
                    queries: p[2].parse().unwrap(),
                    initial_commit: [0u32; 8],
                    proof: Vec::new(),
                    qck: Vec::new(),
                    bad_words: Vec::new(),
                    truncates: Vec::new(),
                    bad_goals: Vec::new(),
                });
                qck = HashMap::new();
            } else if let Some(rest) = line.strip_prefix("initial_commit:") {
                let w = words(rest);
                cur.as_mut().unwrap().initial_commit.copy_from_slice(&w);
            } else if line.starts_with("final_off:") {
                // Informational only (the first final-poly word); unused here.
            } else if let Some(rest) = line.strip_prefix("proof:") {
                cur.as_mut().unwrap().proof = words(rest);
            } else if let Some(rest) = line.strip_prefix("qck:") {
                let (qr, v) = rest.split_once(" -> ").unwrap();
                let qr: Vec<usize> = qr.split(',').map(|x| x.trim().parse().unwrap()).collect();
                let vs = words(v);
                qck.insert((qr[0], qr[1]), (vs[0] as usize, ext(&vs[1..5])));
            } else if let Some(rest) = line.strip_prefix("badword:") {
                let (pos, xor) = rest.split_once(',').unwrap();
                cur.as_mut()
                    .unwrap()
                    .bad_words
                    .push((pos.parse().unwrap(), xor.parse::<u64>().unwrap() as u32));
            } else if let Some(rest) = line.strip_prefix("truncate:") {
                cur.as_mut().unwrap().truncates.push(rest.parse().unwrap());
            } else if let Some(rest) = line.strip_prefix("badgoal:") {
                cur.as_mut().unwrap().bad_goals.push(rest.parse().unwrap());
            } else if line == "endcase" {
                let mut c = cur.take().unwrap();
                // Reassemble per-query checkpoint chains: query q has rounds
                // 0..=max_r(q).
                let mut chains = Vec::with_capacity(c.queries);
                for q in 0..c.queries {
                    let max_r = qck
                        .keys()
                        .filter(|(qq, _)| *qq == q)
                        .map(|(_, r)| *r)
                        .max()
                        .unwrap();
                    chains.push((0..=max_r).map(|r| qck[&(q, r)]).collect());
                }
                c.qck = chains;
                cases.push(c);
            } else {
                panic!("unknown fri KAT line: {}", &line[..line.len().min(60)]);
            }
        }
        assert!(
            !rou_fwd.is_empty() && !rou_rev.is_empty() && !cases.is_empty(),
            "incomplete fri_kat.tsv"
        );
        FriKat {
            rou_fwd,
            rou_rev,
            cases,
        }
    }

    /// Mirror of the generator's `oracle_fri_ok`: known position -> its recorded
    /// round-0 goal, unknown position -> 0; `bad_goal` makes the q-th inner call
    /// return goal + 1.
    fn replay_ok(v: &FriCase, proof: &[u32], bad_goal: Option<usize>) -> bool {
        let goal_map: HashMap<usize, Ext4> = v.qck.iter().map(|c| (c[0].0, c[0].1)).collect();
        let mut iop = ReadIop::new(proof.to_vec());
        iop.commit(&v.initial_commit);
        let mut call = 0usize;
        let inner = |pos: usize| -> Result<Ext4, String> {
            let mut g = goal_map.get(&pos).copied().unwrap_or(Ext4::ZERO);
            if bad_goal == Some(call) {
                g = g.add(Ext4::ONE);
            }
            call += 1;
            Ok(g)
        };
        match fri_verify(&mut iop, v.degree, v.queries, inner) {
            Err(_) => false,
            Ok(()) => iop.verify_complete(),
        }
    }

    // ----- constants parity -----

    #[test]
    fn roots_of_unity_tables_match_risc0_core() {
        let kat = parse_kat();
        assert_eq!(kat.rou_fwd.len(), 28);
        assert_eq!(kat.rou_rev.len(), 28);
        assert_eq!(rou_fwd_table(), kat.rou_fwd.as_slice());
        assert_eq!(rou_rev_table(), kat.rou_rev.as_slice());
        // Spot-check the algebra: RouFwd(k) has order 2^k, RouRev(k) inverts it.
        for k in 0..=27usize {
            assert_eq!(
                BabyBear::pow(rou_fwd(k), 1u64 << k),
                1,
                "order of RouFwd({k})"
            );
            assert_eq!(
                BabyBear::mul(rou_fwd(k), rou_rev(k)),
                1,
                "RouRev({k}) inverse"
            );
        }
    }

    #[test]
    fn profile_constants_match_pinned_oracle() {
        let tsv = include_str!("../../test-vectors/ergo-stark/eip0045-direct/profile-oracle.tsv");
        let params: HashMap<&str, &str> = tsv
            .lines()
            .filter(|l| l.starts_with("param\t"))
            .map(|l| {
                let p: Vec<&str> = l.split('\t').collect();
                (p[1], p[2])
            })
            .collect();
        assert_eq!(QUERIES, params["queries"].parse::<usize>().unwrap());
        assert_eq!(INV_RATE, params["inv_rate"].parse::<usize>().unwrap());
        assert_eq!(FRI_FOLD, params["fri_fold"].parse::<usize>().unwrap());
        assert_eq!(
            FRI_FOLD_PO2,
            params["fri_fold_po2"].parse::<usize>().unwrap()
        );
        assert_eq!(
            FRI_MIN_DEGREE,
            params["fri_min_degree"].parse::<usize>().unwrap()
        );
    }

    // ----- oracle parity -----

    #[test]
    fn replays_prover_built_proofs_across_fold_rounds() {
        let kat = parse_kat();
        let names: Vec<&str> = kat.cases.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            ["deg256_r0", "deg4096_r1", "deg65536_r2", "deg262144_r3"]
        );
        for v in &kat.cases {
            // Round structure implied by the checkpoints must match the
            // protocol's fold recursion (degree/16 while degree > 256).
            let mut exp_rounds = 0;
            let mut d = v.degree;
            while d > FRI_MIN_DEGREE {
                exp_rounds += 1;
                d /= FRI_FOLD;
            }
            for chain in &v.qck {
                assert_eq!(chain.len(), exp_rounds + 1, "case {}: chain length", v.name);
            }

            let goal_map: HashMap<usize, Ext4> = v.qck.iter().map(|c| (c[0].0, c[0].1)).collect();
            let mut iop = ReadIop::new(v.proof.clone());
            iop.commit(&v.initial_commit);

            let mut call = 0usize;
            let qck_inner = &v.qck;
            let inner = |pos: usize| -> Result<Ext4, String> {
                assert_eq!(
                    pos, qck_inner[call][0].0,
                    "case {}: query {call} pos",
                    v.name
                );
                call += 1;
                Ok(goal_map[&pos])
            };
            let qck_probe = &v.qck;
            let probe = |q: usize, r: usize, pos: usize, goal: Ext4| {
                let (exp_pos, exp_goal) = qck_probe[q][r];
                assert_eq!(pos, exp_pos, "case {}: checkpoint q{q} r{r} pos", v.name);
                assert_eq!(goal, exp_goal, "case {}: checkpoint q{q} r{r} goal", v.name);
            };

            assert_eq!(
                fri_verify_probed(&mut iop, v.degree, v.queries, inner, probe),
                Ok(()),
                "case {} must verify",
                v.name
            );
            assert_eq!(call, v.queries, "case {}: inner call count", v.name);
            assert!(iop.verify_complete(), "case {}: verify_complete", v.name);
        }
    }

    // ----- error paths -----

    #[test]
    fn rejects_corrupted_proof_words() {
        let kat = parse_kat();
        assert!(kat.cases.iter().any(|v| !v.bad_words.is_empty()));
        for v in &kat.cases {
            for &(pos, xor) in &v.bad_words {
                let mut corrupted = v.proof.clone();
                corrupted[pos] ^= xor;
                assert!(
                    !replay_ok(v, &corrupted, None),
                    "case {} badword {pos}^{xor} must reject",
                    v.name
                );
            }
        }
    }

    #[test]
    fn rejects_truncated_proofs() {
        let kat = parse_kat();
        for v in &kat.cases {
            for &keep in &v.truncates {
                assert!(
                    !replay_ok(v, &v.proof[..keep], None),
                    "case {} truncate {keep} must reject",
                    v.name
                );
            }
        }
    }

    #[test]
    fn rejects_wrong_deep_ali_goal() {
        let kat = parse_kat();
        assert!(kat.cases.iter().any(|v| !v.bad_goals.is_empty()));
        for v in &kat.cases {
            for &q in &v.bad_goals {
                assert!(
                    !replay_ok(v, &v.proof, Some(q)),
                    "case {} badgoal {q} must reject",
                    v.name
                );
            }
        }
    }

    #[test]
    fn surfaces_inner_failure() {
        let kat = parse_kat();
        let v = &kat.cases[0];
        let mut iop = ReadIop::new(v.proof.clone());
        iop.commit(&v.initial_commit);
        let res = fri_verify(
            &mut iop,
            v.degree,
            v.queries,
            |_| Err("no goal".to_string()),
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("no goal"));
    }

    #[test]
    fn rejects_empty_stream() {
        let mut iop = ReadIop::new(Vec::new());
        assert!(fri_verify(&mut iop, 4096, 50, |_| Ok(Ext4::ZERO)).is_err());
    }
}
