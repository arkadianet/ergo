//! Layer 4 (capstone) — the top-level `Risc0RawSealVerifier`, a faithful port
//! of the reference sigmastate `Risc0RawSealVerifier.starkVerify`.
//!
//! It ties Layers 1–3 together into a single accept/reject over a decoded raw
//! seal: a [`ReadIop`](crate::read_iop::ReadIop) transcript drives the group
//! Merkle commitments ([`MerkleVerifier`](crate::merkle::MerkleVerifier)), the
//! DEEP-ALI constraint evaluation ([`deep_goal`](crate::circuit::deep_goal)
//! fed as FRI's per-query `inner`), and the FRI low-degree test
//! ([`fri_verify`](crate::fri::fri_verify)). The reconstructed code-group
//! Merkle root is matched against the profile's fixed 10-entry terminal-control
//! allowlist, and the recursion output's inner control root / claim digest /
//! outer po2 are checked after full cryptographic verification.
//!
//! Consensus-critical: every reject condition the reference has rejects here,
//! and the flow is fail-closed — any decode/verify/mismatch yields an `Err`
//! (or `false` at the public entry), never a panic on proof-controlled bytes.

use crate::baby_bear::BabyBear;
use crate::circuit::{deep_goal, CircuitTapSet, PolyExtTable};
use crate::ext4::Ext4;
use crate::fri::{fri_verify, log2_ceil, rou_fwd, rou_rev, INV_RATE, QUERIES};
use crate::merkle::MerkleVerifier;
use crate::poseidon2::Poseidon2;
use crate::read_iop::ReadIop;

/// Recursion-output word index carrying the literal outer po2 exponent.
const OUTER_PO2_WORD_INDEX: usize = 32;
/// Extension-field degree.
const EXT_SIZE: usize = 4;
/// Decoded raw-seal word count (`RawSealV1Decoder.WordCount`).
pub const WORD_COUNT: usize = 55667;
/// Digest length in bytes.
pub const DIGEST_BYTES: usize = 32;

/// Terminal-control kinds (`Risc0RawSealVerifier`): 1 = normal lift,
/// 2 = join, 3 = resolve.
const NORMAL_LIFT_CONTROL_KIND: u32 = 1;
const JOIN_CONTROL_KIND: u32 = 2;
const RESOLVE_CONTROL_KIND: u32 = 3;
const REQUIRED_CONTROL_COUNT: usize = 10;
const FIRST_SEGMENT_PO2: u32 = 15;
const LAST_SEGMENT_PO2: u32 = 22;
const LIFT_COUNT: usize = 8;

/// Stock recursion-circuit dimensions, mirroring the reference invariants.
const STOCK_TAP_SIZE: usize = 643;
const STOCK_REGISTER_COUNT: i32 = 163;
const STOCK_COMBO_COUNT: i32 = 5;
const STOCK_POLY_EXT_OPS: usize = 12359;
const STOCK_POLY_EXT_RET: usize = 1228;
const STOCK_POLY_EXT_FP_VARS: usize = 11130;
const STOCK_POLY_EXT_MIX_VARS: usize = 1229;
const STOCK_OUTPUT_SIZE: usize = 32;
const STOCK_MIX_SIZE: usize = 20;
const STOCK_CHECK_SIZE: usize = 16;
const STOCK_GROUP_SIZE: [i32; 3] = [12, 23, 128];
const STOCK_GROUP_BEGIN: [i32; 4] = [0, 16, 39, 643];
const STOCK_COMBO_BEGIN: [i32; 6] = [0, 1, 3, 9, 15, 20];
const STOCK_COMBO_TAPS: [i32; 20] = [
    0, 0, 1, 0, 1, 2, 3, 4, 68, 0, 1, 2, 7, 15, 16, 0, 2, 7, 15, 16,
];

const STOCK_PROOF_SYSTEM_INFO: &str = "RISC0_STARK:v1__";
const STOCK_CIRCUIT_INFO: &str = "RECURSION:rev1v1";

/// The `[0, 2, 1, 3]` check-polynomial plane remap (risc0-zkp).
const CHECK_REMAP: [usize; 4] = [0, 2, 1, 3];

/// One manifest-owned terminal recursion program. `control_id` bytes use RISC0
/// `Digest::as_bytes()` order (eight little-endian raw BabyBear words). Normal
/// lifts carry their segment po2; join and resolve carry parameter zero.
#[derive(Clone, Debug)]
pub struct TerminalControl {
    pub kind: u32,
    pub parameter: u32,
    pub control_id: [u8; DIGEST_BYTES],
}

/// Manifest-owned inputs the direct verifier needs. Carries no activation
/// identity nor claimed final profile ID.
#[derive(Clone, Debug)]
pub struct RawSealProfile {
    pub outer_po2: u32,
    pub inner_control_root: [u8; DIGEST_BYTES],
    pub controls: Vec<TerminalControl>,
}

/// Numeric/circuit inputs owned by the profile's algorithm and data artifacts.
#[derive(Clone)]
pub struct VerifierParameters {
    pub proof_system_info: String,
    pub circuit_info: String,
    pub output_size: usize,
    pub mix_size: usize,
    pub queries: usize,
    pub inv_rate: usize,
    pub ext_size: usize,
    pub check_size: usize,
    pub taps: CircuitTapSet,
    pub poly_ext: PolyExtTable,
}

/// Successful verification result. Kind 1 = normal lift, 2 = join, 3 = resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    pub control_kind: u32,
    pub control_parameter: u32,
}

/// Stable proof-rejection taxonomy (mirrors the reference `Failure`). A
/// construction-time [`Error::ProfileInvariant`] is never used for
/// proof-controlled bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    ProfileInvariant(String),
    WrongDecodedWordCount { expected: usize, actual: usize },
    UnreducedDecodedWord { word_index: usize, value: u32 },
    WrongOuterPo2 { expected: u32, actual: u32 },
    NonZeroRootPadding { word_index: usize, value: u32 },
    ClaimHalfwordOutOfRange { word_index: usize, value: u32 },
    MalformedProof { stage: &'static str, detail: String },
    ControlIdNotAllowed,
    ConstraintCheckFailed,
    TrailingSealWords { remaining: usize },
    InnerControlRootMismatch,
    ClaimMismatch,
}

/// A validated terminal-control role matched from the reconstructed code root.
struct TerminalRole {
    kind: u32,
    parameter: u32,
}

/// The direct verifier for the EIP-0045 stock RISC0 raw-seal profile.
pub struct Risc0RawSealVerifier {
    params: VerifierParameters,
    profile: RawSealProfile,
    tot_cycles: usize,
    domain: usize,
    proof_system_digest: [u32; 8],
    circuit_digest: [u32; 8],
}

impl Risc0RawSealVerifier {
    /// Construct after structurally validating the profile and parameters
    /// against the stock recursion circuit. Returns [`Error::ProfileInvariant`]
    /// for a malformed immutable profile/parameter set — never for proof bytes.
    pub fn new(params: VerifierParameters, profile: RawSealProfile) -> Result<Self, Error> {
        validate_profile(&profile)?;
        validate_parameters(&params)?;

        let outer_po2 = profile.outer_po2;
        if outer_po2 as usize >= crate::fri::rou_rev_table().len() {
            return Err(invariant("outerPo2 is outside the BabyBear root table"));
        }
        let tot_cycles = 1usize << outer_po2;
        let domain = tot_cycles
            .checked_mul(params.inv_rate)
            .ok_or_else(|| invariant("outer domain overflows"))?;
        if domain == 0 || (domain & (domain - 1)) != 0 {
            return Err(invariant("outer domain is not a power of two"));
        }
        if log2_ceil(domain) >= crate::fri::rou_fwd_table().len() {
            return Err(invariant("outer domain is outside the BabyBear root table"));
        }

        let proof_system_digest = protocol_info_digest_raw(&params.proof_system_info);
        let circuit_digest = protocol_info_digest_raw(&params.circuit_info);

        Ok(Risc0RawSealVerifier {
            params,
            profile,
            tot_cycles,
            domain,
            proof_system_digest,
            circuit_digest,
        })
    }

    /// The profile bound into this verifier.
    pub fn profile(&self) -> &RawSealProfile {
        &self.profile
    }

    /// Verify a decoded raw-seal word stream against an expected 32-byte claim.
    ///
    /// Mirrors `Risc0RawSealVerifier.verifyDecoded`: validate the decoded word
    /// shape, reconstruct the recursion-output inner control root and claim
    /// digest from the words, run `starkVerify`, and only then bind the inner
    /// control root and claim. Fail-closed: any rejection is a typed `Err`.
    pub fn verify_words(
        &self,
        seal_words: &[u32],
        expected_claim: &[u8; DIGEST_BYTES],
    ) -> Result<Verified, Error> {
        if seal_words.len() != WORD_COUNT {
            return Err(Error::WrongDecodedWordCount {
                expected: WORD_COUNT,
                actual: seal_words.len(),
            });
        }
        // Word-shape gate (`RawSealV1Decoder` + `validateDecoded`): word 32 is
        // the literal outer exponent; every other word is a reduced residue.
        for (i, &w) in seal_words.iter().enumerate() {
            if i == OUTER_PO2_WORD_INDEX {
                if w != self.profile.outer_po2 {
                    return Err(Error::WrongOuterPo2 {
                        expected: self.profile.outer_po2,
                        actual: w,
                    });
                }
            } else if w >= BabyBear::P {
                return Err(Error::UnreducedDecodedWord {
                    word_index: i,
                    value: w,
                });
            }
        }

        let inner_control_root = decode_inner_control_root(seal_words)?;
        let claim_digest = decode_claim_digest(seal_words)?;

        let role = self.stark_verify(seal_words)?;

        if inner_control_root != self.profile.inner_control_root {
            return Err(Error::InnerControlRootMismatch);
        }
        if &claim_digest != expected_claim {
            return Err(Error::ClaimMismatch);
        }
        Ok(Verified {
            control_kind: role.kind,
            control_parameter: role.parameter,
        })
    }

    // ------------------------------------------------------------------
    // STARK core: risc0-zkp verify + verify_validity.
    // ------------------------------------------------------------------

    fn stark_verify(&self, seal: &[u32]) -> Result<TerminalRole, Error> {
        let p = &self.params;
        let taps = &p.taps;
        let mut iop = ReadIop::new(seal.to_vec());

        iop.commit(&self.proof_system_digest);
        iop.commit(&self.circuit_digest);

        // read_slice_with_po2(OUTPUT_SIZE): output elements are ordinary field
        // values; the final slot is a literal raw u32 exponent.
        let slice = iop
            .read_field_elem_slice(p.output_size + 1)
            .ok_or_else(|| malformed("output", "truncated or unreduced output slice"))?;
        iop.commit(&to_raw_digest(&Poseidon2::unpadded_hash(&slice)));
        let out = slice[0..p.output_size].to_vec();
        let outer_po2 = BabyBear::to_raw(slice[p.output_size]);
        if outer_po2 != self.profile.outer_po2 {
            return Err(Error::WrongOuterPo2 {
                expected: self.profile.outer_po2,
                actual: outer_po2,
            });
        }

        let tot_cycles = self.tot_cycles;
        let domain = self.domain;

        // Merkle group ids: 0=accum, 1=code, 2=data. Transcript creation order
        // is CODE, DATA, ACCUM; query openings are ACCUM, CODE, DATA.
        let code_merkle =
            MerkleVerifier::create(&mut iop, domain, taps.group_size()[1] as usize, p.queries)
                .map_err(|d| malformed("code-group", &d))?;
        let terminal = self.match_control_id(&code_merkle.root_raw())?;

        let data_merkle =
            MerkleVerifier::create(&mut iop, domain, taps.group_size()[2] as usize, p.queries)
                .map_err(|d| malformed("data-group", &d))?;

        let mut mix_globals = vec![0u32; p.mix_size];
        for slot in mix_globals.iter_mut() {
            *slot = iop.random_elem();
        }

        let accum_merkle =
            MerkleVerifier::create(&mut iop, domain, taps.group_size()[0] as usize, p.queries)
                .map_err(|d| malformed("accum-group", &d))?;

        let poly_mix = iop.random_ext_elem();

        let check_merkle = MerkleVerifier::create(&mut iop, domain, p.check_size, p.queries)
            .map_err(|d| malformed("check-group", &d))?;

        let z = iop.random_ext_elem();
        let back_one = rou_rev(outer_po2 as usize);

        let num_taps = taps.tap_size();
        let coeff_words = iop
            .read_field_elem_slice(EXT_SIZE * (num_taps + p.check_size))
            .ok_or_else(|| malformed("coeff-u", "truncated or unreduced coefficient slice"))?;
        iop.commit(&to_raw_digest(&Poseidon2::unpadded_hash(&coeff_words)));

        let coeff_u: Vec<Ext4> = (0..num_taps + p.check_size)
            .map(|i| {
                Ext4::new(
                    coeff_words[EXT_SIZE * i],
                    coeff_words[EXT_SIZE * i + 1],
                    coeff_words[EXT_SIZE * i + 2],
                    coeff_words[EXT_SIZE * i + 3],
                )
            })
            .collect();

        let mut eval_u = vec![Ext4::ZERO; num_taps];
        let mut cur_pos = 0usize;
        let mut eval_pos = 0usize;
        for register in taps.regs() {
            for &back in &register.backs {
                let x = scale_ext(z, BabyBear::pow(back_one, back as u64));
                eval_u[eval_pos] = poly_eval_range(&coeff_u, cur_pos, register.backs.len(), x);
                eval_pos += 1;
            }
            cur_pos += register.backs.len();
        }

        let args: [&[u32]; 2] = [out.as_slice(), mix_globals.as_slice()];
        let result = deep_goal(&p.poly_ext, poly_mix, &eval_u, &args)
            .map_err(|d| invariant(&format!("constraint program changed after validation: {d}")))?;

        // Four check-polynomial planes, with risc0-zkp's [0,2,1,3] remap.
        let mut check = Ext4::ZERO;
        let mut zi = Ext4::ONE;
        for &remapped in CHECK_REMAP.iter() {
            check = check
                .add(coeff_u[num_taps + remapped].mul(zi))
                .add(coeff_u[num_taps + remapped + EXT_SIZE].mul(zi).mul(BASIS1))
                .add(
                    coeff_u[num_taps + remapped + 2 * EXT_SIZE]
                        .mul(zi)
                        .mul(BASIS2),
                )
                .add(
                    coeff_u[num_taps + remapped + 3 * EXT_SIZE]
                        .mul(zi)
                        .mul(BASIS3),
                );
            zi = zi.mul(z);
        }
        check = check.mul(scale_ext(z, 3).pow(tot_cycles as u128).sub(Ext4::ONE));
        if check != result {
            return Err(Error::ConstraintCheckFailed);
        }

        // DEEP-ALI batching.
        let fri_mix = iop.random_ext_elem();
        let tot_combo_backs = taps.tot_combo_backs() as usize;
        let mut combo_u = vec![Ext4::ZERO; tot_combo_backs + 1];
        let mut tap_mix_pows = vec![Ext4::ZERO; taps.regs().len()];
        let mut check_mix_pows = vec![Ext4::ZERO; p.check_size];
        let mut cur_mix = Ext4::ONE;
        cur_pos = 0;
        for (register_index, register) in taps.regs().iter().enumerate() {
            for (i, _) in register.backs.iter().enumerate() {
                let index = taps.combo_begin()[register.combo as usize] as usize + i;
                combo_u[index] = combo_u[index].add(cur_mix.mul(coeff_u[cur_pos + i]));
            }
            tap_mix_pows[register_index] = cur_mix;
            cur_mix = cur_mix.mul(fri_mix);
            cur_pos += register.backs.len();
        }
        for slot in check_mix_pows.iter_mut() {
            combo_u[tot_combo_backs] = combo_u[tot_combo_backs].add(cur_mix.mul(coeff_u[cur_pos]));
            cur_pos += 1;
            *slot = cur_mix;
            cur_mix = cur_mix.mul(fri_mix);
        }

        let gen = rou_fwd(log2_ceil(domain));
        let inner = |iop: &mut ReadIop, index: usize| -> Result<Ext4, String> {
            let accum_row = accum_merkle
                .verify(iop, index)
                .map_err(|d| format!("accum row: {d}"))?;
            let code_row = code_merkle
                .verify(iop, index)
                .map_err(|d| format!("code row: {d}"))?;
            let data_row = data_merkle
                .verify(iop, index)
                .map_err(|d| format!("data row: {d}"))?;
            let check_row = check_merkle
                .verify(iop, index)
                .map_err(|d| format!("check row: {d}"))?;
            Ok(fri_eval_taps(
                taps,
                p.check_size,
                p.inv_rate,
                &combo_u,
                &check_row,
                back_one,
                BabyBear::pow(gen, index as u64),
                z,
                [&accum_row, &code_row, &data_row],
                &tap_mix_pows,
                &check_mix_pows,
            ))
        };

        fri_verify(&mut iop, tot_cycles, p.queries, inner).map_err(|d| malformed("fri", &d))?;

        if !iop.verify_complete() {
            return Err(Error::TrailingSealWords {
                remaining: iop.remaining(),
            });
        }
        Ok(terminal)
    }

    /// Match the reconstructed code-group root against the fixed allowlist.
    /// Exactly one entry must match; zero matches rejects, and (given the
    /// pairwise-distinct construction invariant) more than one is impossible.
    fn match_control_id(&self, root_raw: &[u32; 8]) -> Result<TerminalRole, Error> {
        let root_bytes = raw_digest_bytes(root_raw)?;
        let mut matched: Option<TerminalRole> = None;
        for entry in &self.profile.controls {
            if root_bytes == entry.control_id {
                if matched.is_some() {
                    return Err(invariant("validated profile produced an ambiguous match"));
                }
                matched = Some(TerminalRole {
                    kind: entry.kind,
                    parameter: entry.parameter,
                });
            }
        }
        matched.ok_or(Error::ControlIdNotAllowed)
    }
}

const BASIS1: Ext4 = Ext4::new(0, 1, 0, 0);
const BASIS2: Ext4 = Ext4::new(0, 0, 1, 0);
const BASIS3: Ext4 = Ext4::new(0, 0, 0, 1);

/// Mirror of risc0-zkp `fri_eval_taps`. Zero inversion follows RISC0's
/// base/extension convention (`inv(0) = 0`).
#[allow(clippy::too_many_arguments)]
fn fri_eval_taps(
    taps: &CircuitTapSet,
    check_size: usize,
    inv_rate: usize,
    combo_u: &[Ext4],
    check_row: &[u32],
    back_one: u32,
    x_base: u32,
    z: Ext4,
    rows: [&[u32]; 3],
    tap_mix_pows: &[Ext4],
    check_mix_pows: &[Ext4],
) -> Ext4 {
    let combos = taps.combos_count() as usize;
    let mut totals = vec![Ext4::ZERO; combos + 1];
    let x = Ext4::from_base(x_base);

    for (register_index, register) in taps.regs().iter().enumerate() {
        let combo = register.combo as usize;
        let value = rows[register.group as usize][register.offset as usize];
        totals[combo] = totals[combo].add(scale_ext(tap_mix_pows[register_index], value));
    }
    for i in 0..check_size {
        totals[combos] = totals[combos].add(scale_ext(check_mix_pows[i], check_row[i]));
    }

    let combo_begin = taps.combo_begin();
    let combo_taps = taps.combo_taps();
    let mut ret = Ext4::ZERO;
    for combo in 0..combos {
        let begin = combo_begin[combo] as usize;
        let end = combo_begin[combo + 1] as usize;
        let numerator = totals[combo].sub(poly_eval_range(combo_u, begin, end - begin, x));
        let mut divisor = Ext4::ONE;
        for &tap in &combo_taps[begin..end] {
            divisor = divisor.mul(x.sub(scale_ext(z, BabyBear::pow(back_one, tap as u64))));
        }
        ret = ret.add(numerator.mul(inv_or_zero(divisor)));
    }
    let tot_combo_backs = taps.tot_combo_backs() as usize;
    let check_numerator = totals[combos].sub(combo_u[tot_combo_backs]);
    let check_divisor = x.sub(z.pow(inv_rate as u128));
    ret.add(check_numerator.mul(inv_or_zero(check_divisor)))
}

// ------------------------------------------------------------------
// Recursion-output decode (`RawSealV1Decoder` post-word processing).
// ------------------------------------------------------------------

fn decode_inner_control_root(words: &[u32]) -> Result<[u8; DIGEST_BYTES], Error> {
    let mut root = [0u8; DIGEST_BYTES];
    for root_word in 0..8 {
        let even_index = root_word * 2;
        let padding_index = even_index + 1;
        if words[padding_index] != 0 {
            return Err(Error::NonZeroRootPadding {
                word_index: padding_index,
                value: words[padding_index],
            });
        }
        let canonical = BabyBear::from_raw(words[even_index]);
        root[root_word * 4..root_word * 4 + 4].copy_from_slice(&canonical.to_le_bytes());
    }
    Ok(root)
}

fn decode_claim_digest(words: &[u32]) -> Result<[u8; DIGEST_BYTES], Error> {
    let mut claim = [0u8; DIGEST_BYTES];
    for claim_word in 0..16 {
        let word_index = claim_word + 16;
        let decoded = BabyBear::from_raw(words[word_index]);
        if decoded > 0xffff {
            return Err(Error::ClaimHalfwordOutOfRange {
                word_index,
                value: decoded,
            });
        }
        claim[claim_word * 2..claim_word * 2 + 2].copy_from_slice(&(decoded as u16).to_le_bytes());
    }
    Ok(claim)
}

// ------------------------------------------------------------------
// Small helpers.
// ------------------------------------------------------------------

fn invariant(message: &str) -> Error {
    Error::ProfileInvariant(message.to_string())
}

fn malformed(stage: &'static str, detail: &str) -> Error {
    Error::MalformedProof {
        stage,
        detail: detail.to_string(),
    }
}

/// Poseidon2 digest of a 16-byte ASCII protocol-info string, raw (Montgomery)
/// words ready to commit.
fn protocol_info_digest_raw(info: &str) -> [u32; 8] {
    let elements: Vec<u32> = info.chars().map(|c| c as u32).collect();
    to_raw_digest(&Poseidon2::unpadded_hash(&elements))
}

/// Map a canonical Poseidon2 digest to raw (Montgomery) words for `commit`.
fn to_raw_digest(canonical: &[u32; 8]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (o, &c) in out.iter_mut().zip(canonical.iter()) {
        *o = BabyBear::to_raw(c);
    }
    out
}

/// Eight raw BabyBear words → 32 little-endian bytes (`Digest::as_bytes`).
fn raw_digest_bytes(words: &[u32; 8]) -> Result<[u8; DIGEST_BYTES], Error> {
    let mut bytes = [0u8; DIGEST_BYTES];
    for (i, &word) in words.iter().enumerate() {
        if word >= BabyBear::P {
            return Err(invariant("reconstructed digest contains an unreduced word"));
        }
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

/// Scale an extension element by a canonical base-field scalar.
fn scale_ext(value: Ext4, scalar: u32) -> Ext4 {
    Ext4::new(
        BabyBear::mul(value.c0, scalar),
        BabyBear::mul(value.c1, scalar),
        BabyBear::mul(value.c2, scalar),
        BabyBear::mul(value.c3, scalar),
    )
}

/// RISC0 base/extension zero-inversion convention: `inv(0) = 0`.
fn inv_or_zero(value: Ext4) -> Ext4 {
    if value.is_zero() {
        Ext4::ZERO
    } else {
        value.inv()
    }
}

/// Evaluate `coefficients[offset..offset+length]` as a polynomial at `x`.
fn poly_eval_range(coefficients: &[Ext4], offset: usize, length: usize, x: Ext4) -> Ext4 {
    let mut power = Ext4::ONE;
    let mut total = Ext4::ZERO;
    for i in 0..length {
        total = total.add(coefficients[offset + i].mul(power));
        power = power.mul(x);
    }
    total
}

// ------------------------------------------------------------------
// Construction-time structural validation (mirrors the reference snapshots).
// ------------------------------------------------------------------

fn validate_digest_words(bytes: &[u8; DIGEST_BYTES], label: &str) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let word = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        if word >= BabyBear::P {
            return Err(invariant(&format!("{label} contains an unreduced word")));
        }
        offset += 4;
    }
    Ok(())
}

fn validate_profile(profile: &RawSealProfile) -> Result<(), Error> {
    validate_digest_words(&profile.inner_control_root, "profile inner control root")?;
    if profile.controls.len() != REQUIRED_CONTROL_COUNT {
        return Err(invariant(
            "profile must contain exactly ten terminal controls",
        ));
    }
    for (i, entry) in profile.controls.iter().enumerate() {
        let (expected_kind, expected_parameter) = if i < LIFT_COUNT {
            (NORMAL_LIFT_CONTROL_KIND, FIRST_SEGMENT_PO2 + i as u32)
        } else if i == LIFT_COUNT {
            (JOIN_CONTROL_KIND, 0)
        } else {
            (RESOLVE_CONTROL_KIND, 0)
        };
        if entry.kind != expected_kind || entry.parameter != expected_parameter {
            return Err(invariant(
                "profile control role does not match the stock roles",
            ));
        }
        if i < LIFT_COUNT && entry.parameter > LAST_SEGMENT_PO2 {
            return Err(invariant("profile lift po2 exceeds 22"));
        }
        validate_digest_words(&entry.control_id, "profile control ID")?;
        for earlier in &profile.controls[..i] {
            if earlier.control_id == entry.control_id {
                return Err(invariant("profile control IDs must be pairwise distinct"));
            }
        }
    }
    Ok(())
}

fn validate_parameters(params: &VerifierParameters) -> Result<(), Error> {
    if params.proof_system_info != STOCK_PROOF_SYSTEM_INFO
        || params.circuit_info != STOCK_CIRCUIT_INFO
    {
        return Err(invariant(
            "transcript protocol-info does not match the stock profile",
        ));
    }
    if params.output_size != STOCK_OUTPUT_SIZE {
        return Err(invariant("stock recursion output size must be 32"));
    }
    if params.mix_size != STOCK_MIX_SIZE {
        return Err(invariant("accumulator mix size must be 20"));
    }
    if params.queries != QUERIES {
        return Err(invariant(
            "query count does not match the stock FRI implementation",
        ));
    }
    if params.inv_rate != INV_RATE {
        return Err(invariant(
            "inverse rate does not match the stock FRI implementation",
        ));
    }
    if params.ext_size != EXT_SIZE {
        return Err(invariant("extension degree must be four"));
    }
    if params.check_size != STOCK_CHECK_SIZE {
        return Err(invariant("check polynomial size must be 16"));
    }

    let taps = &params.taps;
    if taps.group_names() != ["accum", "code", "data"] {
        return Err(invariant(
            "circuit tap groups must be exactly accum,code,data",
        ));
    }
    if taps.group_size() != STOCK_GROUP_SIZE
        || taps.group_begin() != STOCK_GROUP_BEGIN
        || taps.tap_size() != STOCK_TAP_SIZE
        || taps.reg_count() != STOCK_REGISTER_COUNT
        || taps.regs().len() as i32 != STOCK_REGISTER_COUNT
        || taps.combos_count() != STOCK_COMBO_COUNT
        || taps.combo_begin() != STOCK_COMBO_BEGIN
        || taps.combo_taps() != STOCK_COMBO_TAPS
    {
        return Err(invariant(
            "circuit tap dimensions do not match the stock profile",
        ));
    }

    let program = &params.poly_ext;
    if program.ops_count() != STOCK_POLY_EXT_OPS
        || program.ret() != STOCK_POLY_EXT_RET
        || program.fp_vars() != STOCK_POLY_EXT_FP_VARS
        || program.mix_vars() != STOCK_POLY_EXT_MIX_VARS
    {
        return Err(invariant(
            "constraint program dimensions do not match the stock profile",
        ));
    }
    Ok(())
}
