//! Layer-4 capstone integration tests: the EIP-0045 stock-profile loader and
//! the top-level raw-seal verifier, exercised from a downstream user's
//! perspective (public API only).
//!
//! Oracle-parity discipline: the positive seals are real RISC0 prover outputs
//! (the `eip0045-direct` and `eip0045-arkadia-independent` fixtures, plus a
//! real po2-20 multi-segment Aegis settlement proof whose seal + claim were
//! extracted with risc0-zkvm's own library). The profile constants come from
//! the reference `profile-oracle.tsv` and the frozen `profile-id.bin`. No value
//! is ever produced by this port itself.

use ergo_stark::circuit::{CircuitTapSet, PolyExtTable};
use ergo_stark::profile::{
    artifact_digest, profile_id_digest, stock_loaded_profile, verify_stock_profile_seal,
    verify_stock_profile_seal_checked, LoaderError, ProfilePackageLoader, StockSealError,
    VerifierParameters, VerifyError, STOCK_PROFILE_ID_HEX,
};
use ergo_stark::{RawSealProfile, Risc0RawSealVerifier, Verified};

// ----- helpers -----

const PKG_MANIFEST: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-profile-package/manifest.bin");
const PKG_ALGORITHM: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-profile-package/algorithm.txt");
const PKG_CONSTANTS: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-profile-package/constants.bin");
const PKG_PROFILE_ID: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-profile-package/profile-id.bin");

const DIRECT_SEAL: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-direct/po2-15-raw-seal.bin");
const DIRECT_CLAIM: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-direct/po2-15-claim-digest.bin");

const ARKADIA_SEAL: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-arkadia-independent/raw-seal.bin");
const ARKADIA_CLAIM: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-arkadia-independent/claim-digest.bin");

const AEGIS_SEAL: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-aegis-settlec/raw-seal.bin");
const AEGIS_CLAIM: &[u8] =
    include_bytes!("../../test-vectors/ergo-stark/eip0045-aegis-settlec/claim-digest.bin");

const ORACLE_TSV: &str =
    include_str!("../../test-vectors/ergo-stark/eip0045-direct/profile-oracle.tsv");
const TAPS_TSV: &str = include_str!("../../test-vectors/ergo-stark/circuit_taps.tsv");
const POLYEXT_TSV: &str = include_str!("../../test-vectors/ergo-stark/circuit_polyext_ops.tsv");

/// Convert a byte-string seal into little-endian u32 words.
fn to_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn to_claim(bytes: &[u8]) -> [u8; 32] {
    let mut c = [0u8; 32];
    c.copy_from_slice(bytes);
    c
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extract the loader error from a load result (whose `Ok` variant is not
/// `Debug`), panicking if the load unexpectedly succeeded.
fn load_err<T>(result: Result<T, LoaderError>) -> LoaderError {
    match result {
        Ok(_) => panic!("expected the load to be rejected"),
        Err(e) => e,
    }
}

/// The stock parameter set built exactly as the reference E2E test builds it:
/// the pinned oracle scalars + the Layer-3 compiled circuit tables. Used to
/// construct verifiers with a deliberately altered profile (control overrides /
/// inner root), mirroring `Risc0RawSealVerifierE2ESpec`.
fn stock_params() -> VerifierParameters {
    VerifierParameters {
        proof_system_info: "RISC0_STARK:v1__".to_string(),
        circuit_info: "RECURSION:rev1v1".to_string(),
        output_size: 32,
        mix_size: 20,
        queries: 50,
        inv_rate: 4,
        ext_size: 4,
        check_size: 16,
        taps: CircuitTapSet::parse(TAPS_TSV).expect("taps parse"),
        poly_ext: PolyExtTable::parse(POLYEXT_TSV).expect("polyext parse"),
    }
}

/// The frozen stock profile (loaded once, cached).
fn stock_profile() -> RawSealProfile {
    stock_loaded_profile()
        .expect("stock profile loads")
        .verifier()
        .profile()
        .clone()
}

// ----- happy path (E2E accept) -----

#[test]
fn stock_verifier_accepts_the_real_direct_po2_15_seal() {
    let words = to_words(DIRECT_SEAL);
    let claim = to_claim(DIRECT_CLAIM);
    assert!(verify_stock_profile_seal(&words, &claim));
    assert_eq!(
        verify_stock_profile_seal_checked(&words, &claim),
        Ok(Verified {
            control_kind: 1,
            control_parameter: 15,
        })
    );
}

#[test]
fn stock_verifier_accepts_the_arkadia_independent_real_seal() {
    let words = to_words(ARKADIA_SEAL);
    let claim = to_claim(ARKADIA_CLAIM);
    assert!(verify_stock_profile_seal(&words, &claim));
    // Independent fixture: normal lift, po2 16.
    assert_eq!(
        verify_stock_profile_seal_checked(&words, &claim),
        Ok(Verified {
            control_kind: 1,
            control_parameter: 16,
        })
    );
}

#[test]
fn stock_verifier_accepts_the_real_aegis_settlec_proof() {
    // The definitive test: a real po2-20 multi-segment Aegis settlement proof,
    // whose succinct seal + ReceiptClaim digest were extracted with risc0-zkvm
    // 3.0.5's own library. Its terminal control is Join (kind 2), already in the
    // stock allowlist. If this fails, the port cannot accept real Aegis proofs.
    let words = to_words(AEGIS_SEAL);
    let claim = to_claim(AEGIS_CLAIM);
    assert_eq!(words.len(), 55667, "aegis seal must decode to 55667 words");
    assert!(
        verify_stock_profile_seal(&words, &claim),
        "the ported verifier must accept the real Aegis settleC proof"
    );
    assert_eq!(
        verify_stock_profile_seal_checked(&words, &claim),
        Ok(Verified {
            control_kind: 2,
            control_parameter: 0,
        })
    );
}

// ----- error paths (E2E reject / soundness) -----

#[test]
fn wrong_claim_is_rejected_only_after_full_verification() {
    let words = to_words(DIRECT_SEAL);
    let mut claim = to_claim(DIRECT_CLAIM);
    claim[0] ^= 1;
    assert!(!verify_stock_profile_seal(&words, &claim));
    assert_eq!(
        verify_stock_profile_seal_checked(&words, &claim),
        Err(StockSealError::Verify(VerifyError::ClaimMismatch))
    );
}

#[test]
fn corrupted_seal_words_cannot_verify() {
    // Middle and final proof words — the reference's cryptographic-mutation
    // fixture. Both must fail the FRI low-degree test.
    for word_index in [27000usize, 55667 - 1] {
        let mut words = to_words(DIRECT_SEAL);
        words[word_index] ^= 1;
        let claim = to_claim(DIRECT_CLAIM);
        assert!(
            !verify_stock_profile_seal(&words, &claim),
            "corrupted word {word_index} verified"
        );
        // A single-bit cryptographic mutation must be caught by the transcript;
        // the exact stage depends on where the word falls in the seal layout.
        match verify_stock_profile_seal_checked(&words, &claim) {
            Err(StockSealError::Verify(_)) => {}
            other => panic!("corrupted word {word_index}: unexpected {other:?}"),
        }
    }
}

#[test]
fn wrong_outer_po2_is_rejected() {
    let mut words = to_words(DIRECT_SEAL);
    words[32] = 17;
    let claim = to_claim(DIRECT_CLAIM);
    assert!(!verify_stock_profile_seal(&words, &claim));
    assert_eq!(
        verify_stock_profile_seal_checked(&words, &claim),
        Err(StockSealError::Verify(VerifyError::WrongOuterPo2 {
            expected: 18,
            actual: 17,
        }))
    );
}

#[test]
fn truncated_seal_is_rejected() {
    let words = to_words(DIRECT_SEAL);
    let claim = to_claim(DIRECT_CLAIM);
    let truncated = &words[..words.len() - 1];
    assert!(!verify_stock_profile_seal(truncated, &claim));
    assert_eq!(
        verify_stock_profile_seal_checked(truncated, &claim),
        Err(StockSealError::Verify(VerifyError::WrongDecodedWordCount {
            expected: 55667,
            actual: 55666,
        }))
    );
}

#[test]
fn a_control_id_outside_the_allowlist_is_rejected() {
    // Build a verifier whose (1,15) control ID is all-zeros: the reconstructed
    // code root then matches no allowlisted entry.
    let mut profile = stock_profile();
    profile.controls[0].control_id = [0u8; 32];
    assert_eq!(profile.controls[0].kind, 1);
    assert_eq!(profile.controls[0].parameter, 15);
    let verifier = Risc0RawSealVerifier::new(stock_params(), profile).expect("construct");
    let words = to_words(DIRECT_SEAL);
    let claim = to_claim(DIRECT_CLAIM);
    assert_eq!(
        verifier.verify_words(&words, &claim),
        Err(VerifyError::ControlIdNotAllowed)
    );
}

#[test]
fn inner_control_root_mismatch_is_rejected_after_full_verification() {
    let mut profile = stock_profile();
    profile.inner_control_root = [0u8; 32];
    let verifier = Risc0RawSealVerifier::new(stock_params(), profile).expect("construct");
    let words = to_words(DIRECT_SEAL);
    let claim = to_claim(DIRECT_CLAIM);
    assert_eq!(
        verifier.verify_words(&words, &claim),
        Err(VerifyError::InnerControlRootMismatch)
    );
}

#[test]
fn a_tampered_merkle_opening_cannot_verify() {
    // Words deep in the query-opening region drive the accum/code/data/check
    // Merkle branches and the FRI folds; mutating one breaks a root path.
    let mut words = to_words(DIRECT_SEAL);
    words[40000] ^= 1;
    let claim = to_claim(DIRECT_CLAIM);
    assert!(!verify_stock_profile_seal(&words, &claim));
}

// ----- profile loader (Risc0ProfilePackageLoaderSpec parity) -----

#[test]
fn profile_id_and_artifact_digests_match_the_frozen_fixtures() {
    // BLAKE2b-256 artifact envelope KAT ("abc", kind 1).
    assert_eq!(
        hex(&artifact_digest(1, b"abc")),
        "a16874031c15d7bf7f5a3fbe5a14e1a34bb4d57b02d33344ab5e9d9caa7d024c"
    );
    // Empty-manifest profile-id KAT.
    assert_eq!(
        hex(&profile_id_digest(&[0u8; 458])),
        "24537f0d2c05444666acfee843fe041aae1136e0b97e039863bd26f27d042ee9"
    );
    // Frozen B3 artifact digests and profile ID.
    assert_eq!(
        hex(&artifact_digest(1, PKG_ALGORITHM)),
        "6ed8a807a7b55177fa664de51c1d6f0daad81daf879e651da32367fed9d171c4"
    );
    assert_eq!(
        hex(&artifact_digest(2, PKG_CONSTANTS)),
        "dd8528a8621edc8dd24aadeed7bd7a2f0c1afd88dd563c5ec8f51cc7f75df0b1"
    );
    assert_eq!(hex(PKG_PROFILE_ID), STOCK_PROFILE_ID_HEX);
    assert_eq!(hex(&profile_id_digest(PKG_MANIFEST)), STOCK_PROFILE_ID_HEX);
}

#[test]
fn stock_package_loads_and_exposes_the_oracle_constants() {
    let loaded =
        ProfilePackageLoader::load(PKG_MANIFEST, PKG_ALGORITHM, PKG_CONSTANTS, PKG_PROFILE_ID)
            .expect("stock profile loads");
    assert_eq!(loaded.exact_proof_bytes, 222_668);
    assert_eq!(loaded.max_application_payload_bytes, 16384);
    assert_eq!(loaded.outer_po2, 18);
    assert_eq!(hex(&loaded.profile_id()), STOCK_PROFILE_ID_HEX);

    // The 10 terminal controls and the inner control root must match the
    // reference profile oracle byte-for-byte.
    let profile = loaded.verifier().profile();
    let inner_root_hex = ORACLE_TSV
        .lines()
        .find_map(|l| l.strip_prefix("inner_control_root\t"))
        .expect("oracle inner root");
    assert_eq!(hex(&profile.inner_control_root), inner_root_hex);

    let oracle_controls: Vec<(u32, u32, String)> = ORACLE_TSV
        .lines()
        .filter_map(|l| l.strip_prefix("control\t"))
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (
                f[0].parse().unwrap(),
                f[1].parse().unwrap(),
                f[2].to_string(),
            )
        })
        .collect();
    assert_eq!(oracle_controls.len(), 10);
    assert_eq!(profile.controls.len(), 10);
    for (i, (kind, parameter, id_hex)) in oracle_controls.iter().enumerate() {
        assert_eq!(profile.controls[i].kind, *kind, "control {i} kind");
        assert_eq!(
            profile.controls[i].parameter, *parameter,
            "control {i} param"
        );
        assert_eq!(
            hex(&profile.controls[i].control_id),
            *id_hex,
            "control {i} id"
        );
    }
}

#[test]
fn a_wrong_expected_profile_id_is_rejected_before_any_artifact() {
    let mut wrong = profile_id_digest(PKG_MANIFEST);
    wrong[0] ^= 1;
    assert_eq!(
        load_err(ProfilePackageLoader::load(
            PKG_MANIFEST,
            PKG_ALGORITHM,
            PKG_CONSTANTS,
            &wrong
        )),
        LoaderError::ProfileIdMismatch
    );
}

#[test]
fn malformed_manifest_fields_are_rejected() {
    let recompute = |m: &[u8]| {
        let id = profile_id_digest(m);
        ProfilePackageLoader::load(m, PKG_ALGORITHM, PKG_CONSTANTS, &id)
    };

    let mut wrong_version = PKG_MANIFEST.to_vec();
    wrong_version[0] = 2;
    assert!(matches!(
        recompute(&wrong_version),
        Err(LoaderError::ManifestRejected { field }) if field == "formatVersion"
    ));

    // Duplicate control ID: copy control[0]'s ID over control[1]'s.
    let mut dup = PKG_MANIFEST.to_vec();
    dup.copy_within(44..76, 78);
    assert!(matches!(
        recompute(&dup),
        Err(LoaderError::ManifestRejected { field }) if field == "controls[1].controlId"
    ));

    // Wrong join parameter (control[8], at offset 42 + 8*34 + 1).
    let mut wrong_join = PKG_MANIFEST.to_vec();
    wrong_join[42 + 8 * 34 + 1] = 1;
    assert!(matches!(
        recompute(&wrong_join),
        Err(LoaderError::ManifestRejected { field }) if field == "controls[8].parameter"
    ));
}

#[test]
fn artifact_length_and_digest_mismatches_are_isolated() {
    let mut longer = PKG_ALGORITHM.to_vec();
    longer.push(b'\n');
    assert_eq!(
        load_err(ProfilePackageLoader::load(
            PKG_MANIFEST,
            &longer,
            PKG_CONSTANTS,
            PKG_PROFILE_ID
        )),
        LoaderError::ArtifactLengthMismatch {
            kind: 1,
            expected: PKG_ALGORITHM.len() as u64,
            actual: longer.len(),
        }
    );

    let mut changed_binary = PKG_CONSTANTS.to_vec();
    changed_binary[0] ^= 1;
    assert_eq!(
        load_err(ProfilePackageLoader::load(
            PKG_MANIFEST,
            PKG_ALGORITHM,
            &changed_binary,
            PKG_PROFILE_ID
        )),
        LoaderError::ArtifactDigestMismatch { kind: 2 }
    );
}

#[test]
fn a_compiled_reverse_root_mismatch_blocks_startup() {
    // Mutate B2 byte 87 (the first reverse root) and re-derive the manifest so
    // the digest chain still authenticates; the compiled cross-check must then
    // reject it — mirrors the reference `CompiledImplementationMismatch`.
    let mut changed = PKG_CONSTANTS.to_vec();
    changed[87] ^= 1;
    let mut manifest = PKG_MANIFEST.to_vec();
    let new_digest = artifact_digest(2, &changed);
    manifest[426..458].copy_from_slice(&new_digest);
    let id = profile_id_digest(&manifest);
    assert_eq!(
        load_err(ProfilePackageLoader::load(
            &manifest,
            PKG_ALGORITHM,
            &changed,
            &id
        )),
        LoaderError::CompiledImplementationMismatch {
            component: "reverse-root",
            index: 0,
        }
    );
}
