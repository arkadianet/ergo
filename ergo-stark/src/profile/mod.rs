//! Layer 4 (capstone) — the EIP-0045 stock-profile package loader and the
//! public `verifyStark` entry point.
//!
//! [`ProfilePackageLoader`] authenticates one activated profile package: it
//! decodes and validates the exact 458-byte Manifest V1, derives and checks the
//! network-selected `profileId` (`23c4…d383` for the stock profile), binds the
//! B1 (algorithm) and B2 (binary-data) artifacts through their
//! domain-separated digest envelopes, decodes and cross-checks the B2 fixed
//! header and roots-of-unity table against Layer 1, and only then constructs a
//! [`Risc0RawSealVerifier`]. The recursion circuit (tap set + constraint
//! program) is the Layer-3 compiled table, whose byte-exactness to the
//! reference is pinned by its own KAT oracles; the authenticated 65,119-byte B2
//! binds that same circuit through the manifest digest chain.
//!
//! [`verify_stock_profile_seal`] is the fail-closed opcode entry: it loads the
//! stock profile once (cached) and returns `true` iff a decoded raw seal fully
//! verifies, its committed claim digest equals the caller's expected claim, and
//! its reconstructed terminal control is in the fixed allowlist.

pub mod verifier;

use std::sync::OnceLock;

use crate::baby_bear::BabyBear;
use crate::circuit::{CircuitTapSet, PolyExtTable};
use crate::fri::{rou_fwd_table, rou_rev_table};
use crate::hash::blake2b256;

pub use verifier::{
    Error as VerifyError, RawSealProfile, Risc0RawSealVerifier, TerminalControl, Verified,
    VerifierParameters, DIGEST_BYTES, WORD_COUNT,
};

// ------------------------------------------------------------------
// Embedded stock profile package + compiled recursion circuit.
// ------------------------------------------------------------------

const STOCK_MANIFEST: &[u8] =
    include_bytes!("../../../test-vectors/ergo-stark/eip0045-profile-package/manifest.bin");
const STOCK_ALGORITHM: &[u8] =
    include_bytes!("../../../test-vectors/ergo-stark/eip0045-profile-package/algorithm.txt");
const STOCK_BINARY: &[u8] =
    include_bytes!("../../../test-vectors/ergo-stark/eip0045-profile-package/constants.bin");
const STOCK_PROFILE_ID: &[u8] =
    include_bytes!("../../../test-vectors/ergo-stark/eip0045-profile-package/profile-id.bin");
const STOCK_TAPS_TSV: &str = include_str!("../../../test-vectors/ergo-stark/circuit_taps.tsv");
const STOCK_POLYEXT_TSV: &str =
    include_str!("../../../test-vectors/ergo-stark/circuit_polyext_ops.tsv");

/// The frozen stock-profile identity (`Risc0ProfilePackageLoaderSpec`).
pub const STOCK_PROFILE_ID_HEX: &str =
    "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";

// ------------------------------------------------------------------
// Loader constants.
// ------------------------------------------------------------------

const MANIFEST_BYTES: usize = 458;
const BINARY_DATA_BYTES: usize = 65119;
const PROFILE_ID_BYTES: usize = 32;
const MAX_ALGORITHM_BYTES: usize = 1024 * 1024;
const MANIFEST_VERSION: u8 = 1;
const CONTROL_COUNT: usize = 10;
const LIFT_COUNT: usize = 8;
const FIRST_SEGMENT_PO2: u32 = 15;
const STOCK_PAYLOAD_BYTES: u32 = 16384;
const EXPECTED_PROOF_BYTES: u32 = 222_668;
const EXPECTED_OUTER_PO2: u8 = 18;
const ALGORITHM_KIND: u16 = 1;
const BINARY_DATA_KIND: u16 = 2;
const HEADER_BYTES: usize = 87;
const ROOT_COUNT: usize = 28;

const NORMAL_LIFT_CONTROL_KIND: u8 = 1;
const JOIN_CONTROL_KIND: u8 = 2;
const RESOLVE_CONTROL_KIND: u8 = 3;

const ARTIFACT_DOMAIN: &[u8] = b"Ergo.StarkProfileArtifact.v1";
const PROFILE_ID_DOMAIN: &[u8] = b"Ergo.StarkProfileId.v1";

/// Scalar constants decoded from the B2 fixed header.
struct BinaryHeader {
    output_size: usize,
    mix_size: usize,
    queries: usize,
    inv_rate: usize,
    ext_size: usize,
    check_size: usize,
}

/// A profile package authenticated before construction.
pub struct LoadedProfile {
    verifier: Risc0RawSealVerifier,
    pub exact_proof_bytes: u32,
    pub max_application_payload_bytes: u32,
    pub outer_po2: u32,
    profile_id: [u8; PROFILE_ID_BYTES],
}

impl LoadedProfile {
    /// The constructed direct verifier.
    pub fn verifier(&self) -> &Risc0RawSealVerifier {
        &self.verifier
    }
    /// The authenticated profile identity.
    pub fn profile_id(&self) -> [u8; PROFILE_ID_BYTES] {
        self.profile_id
    }
}

/// Stable startup rejection taxonomy (mirrors the reference loader `Failure`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoaderError {
    WrongInputLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    AlgorithmTooLarge {
        actual: usize,
        maximum: usize,
    },
    AlgorithmEncodingRejected {
        offset: usize,
        value: i32,
    },
    ManifestRejected {
        field: String,
    },
    ProfileIdMismatch,
    ArtifactLengthMismatch {
        kind: u16,
        expected: u64,
        actual: usize,
    },
    ArtifactDigestMismatch {
        kind: u16,
    },
    BinaryDataRejected {
        offset: usize,
        detail: String,
    },
    CompiledImplementationMismatch {
        component: &'static str,
        index: i32,
    },
    CircuitParseRejected(String),
    VerifierConstructionRejected(VerifyError),
}

/// The public production construction boundary for a [`Risc0RawSealVerifier`].
pub struct ProfilePackageLoader;

impl ProfilePackageLoader {
    /// Load one package selected by a network activation record. The expected
    /// profile ID is an activation input, not read from the package itself.
    pub fn load(
        raw_manifest: &[u8],
        algorithm_bytes: &[u8],
        binary_data_bytes: &[u8],
        expected_profile_id: &[u8],
    ) -> Result<LoadedProfile, LoaderError> {
        if raw_manifest.len() != MANIFEST_BYTES {
            return Err(LoaderError::WrongInputLength {
                name: "manifest",
                expected: MANIFEST_BYTES,
                actual: raw_manifest.len(),
            });
        }
        if expected_profile_id.len() != PROFILE_ID_BYTES {
            return Err(LoaderError::WrongInputLength {
                name: "expected-profile-id",
                expected: PROFILE_ID_BYTES,
                actual: expected_profile_id.len(),
            });
        }
        if binary_data_bytes.len() != BINARY_DATA_BYTES {
            return Err(LoaderError::WrongInputLength {
                name: "binary-data",
                expected: BINARY_DATA_BYTES,
                actual: binary_data_bytes.len(),
            });
        }
        if algorithm_bytes.len() > MAX_ALGORITHM_BYTES {
            return Err(LoaderError::AlgorithmTooLarge {
                actual: algorithm_bytes.len(),
                maximum: MAX_ALGORITHM_BYTES,
            });
        }

        let manifest = decode_manifest(raw_manifest)?;
        let derived_profile_id = profile_id_digest(raw_manifest);
        if derived_profile_id.as_slice() != expected_profile_id {
            return Err(LoaderError::ProfileIdMismatch);
        }

        validate_artifact(&manifest.algorithm, algorithm_bytes)?;
        validate_artifact(&manifest.binary, binary_data_bytes)?;
        validate_algorithm(algorithm_bytes)?;

        let header = decode_binary_header(binary_data_bytes)?;

        let taps =
            CircuitTapSet::parse(STOCK_TAPS_TSV).map_err(LoaderError::CircuitParseRejected)?;
        let poly_ext =
            PolyExtTable::parse(STOCK_POLYEXT_TSV).map_err(LoaderError::CircuitParseRejected)?;

        let params = VerifierParameters {
            proof_system_info: "RISC0_STARK:v1__".to_string(),
            circuit_info: "RECURSION:rev1v1".to_string(),
            output_size: header.output_size,
            mix_size: header.mix_size,
            queries: header.queries,
            inv_rate: header.inv_rate,
            ext_size: header.ext_size,
            check_size: header.check_size,
            taps,
            poly_ext,
        };

        let controls = manifest
            .controls
            .iter()
            .map(|c| TerminalControl {
                kind: c.kind as u32,
                parameter: c.parameter as u32,
                control_id: c.control_id,
            })
            .collect();
        let profile = RawSealProfile {
            outer_po2: manifest.outer_po2 as u32,
            inner_control_root: manifest.inner_control_root,
            controls,
        };

        let verifier = Risc0RawSealVerifier::new(params, profile)
            .map_err(LoaderError::VerifierConstructionRejected)?;

        Ok(LoadedProfile {
            verifier,
            exact_proof_bytes: manifest.exact_proof_bytes,
            max_application_payload_bytes: manifest.max_payload_bytes,
            outer_po2: manifest.outer_po2 as u32,
            profile_id: derived_profile_id,
        })
    }
}

// ------------------------------------------------------------------
// Public opcode entry.
// ------------------------------------------------------------------

fn stock_profile() -> &'static Result<LoadedProfile, LoaderError> {
    static STOCK: OnceLock<Result<LoadedProfile, LoaderError>> = OnceLock::new();
    STOCK.get_or_init(|| {
        ProfilePackageLoader::load(
            STOCK_MANIFEST,
            STOCK_ALGORITHM,
            STOCK_BINARY,
            STOCK_PROFILE_ID,
        )
    })
}

/// The cached, authenticated stock profile (loaded once). `Err` iff the frozen
/// embedded package fails authentication — a build defect, not proof data.
pub fn stock_loaded_profile() -> Result<&'static LoadedProfile, &'static LoaderError> {
    stock_profile().as_ref()
}

/// Verify a decoded raw seal against the stock EIP-0045 profile — the
/// fail-closed entry the `verifyStark` opcode calls.
///
/// Returns `true` iff the seal fully verifies, its committed claim digest
/// (recursion-output words 16..31) equals `expected_claim`, and its terminal
/// control is in the fixed 10-entry allowlist. Any decode/verify/mismatch (or a
/// profile-load failure) returns `false`; this function never panics on
/// proof-controlled input.
pub fn verify_stock_profile_seal(seal_words: &[u32], expected_claim: &[u8; DIGEST_BYTES]) -> bool {
    verify_stock_profile_seal_checked(seal_words, expected_claim).is_ok()
}

/// Diagnostic form of [`verify_stock_profile_seal`]: returns the matched
/// [`Verified`] control on success, or a typed [`VerifyError`]/[`LoaderError`].
pub fn verify_stock_profile_seal_checked(
    seal_words: &[u32],
    expected_claim: &[u8; DIGEST_BYTES],
) -> Result<Verified, StockSealError> {
    match stock_profile() {
        Ok(loaded) => loaded
            .verifier()
            .verify_words(seal_words, expected_claim)
            .map_err(StockSealError::Verify),
        Err(e) => Err(StockSealError::Load(e.clone())),
    }
}

/// Failure of the stock-profile seal entry: either the (constant) profile
/// failed to load, or the proof was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StockSealError {
    Load(LoaderError),
    Verify(VerifyError),
}

// ------------------------------------------------------------------
// Manifest V1.
// ------------------------------------------------------------------

struct ArtifactReference {
    kind: u16,
    length: u64,
    digest: [u8; PROFILE_ID_BYTES],
}

struct ManifestControl {
    kind: u8,
    parameter: u8,
    control_id: [u8; PROFILE_ID_BYTES],
}

struct Manifest {
    exact_proof_bytes: u32,
    max_payload_bytes: u32,
    outer_po2: u8,
    inner_control_root: [u8; PROFILE_ID_BYTES],
    controls: Vec<ManifestControl>,
    algorithm: ArtifactReference,
    binary: ArtifactReference,
}

/// Domain-separated artifact digest — `BLAKE2b256(domain ‖ 0x00 ‖ u16le(kind)
/// ‖ u32le(len) ‖ bytes)`.
pub fn artifact_digest(kind: u16, bytes: &[u8]) -> [u8; PROFILE_ID_BYTES] {
    let mut preimage = Vec::with_capacity(ARTIFACT_DOMAIN.len() + 1 + 2 + 4 + bytes.len());
    preimage.extend_from_slice(ARTIFACT_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(&kind.to_le_bytes());
    preimage.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    preimage.extend_from_slice(bytes);
    blake2b256(&preimage)
}

/// Domain-separated profile ID — `BLAKE2b256(domain ‖ 0x00 ‖ u32le(458) ‖
/// manifest)`.
pub fn profile_id_digest(manifest: &[u8]) -> [u8; PROFILE_ID_BYTES] {
    let mut preimage = Vec::with_capacity(PROFILE_ID_DOMAIN.len() + 1 + 4 + MANIFEST_BYTES);
    preimage.extend_from_slice(PROFILE_ID_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(&(MANIFEST_BYTES as u32).to_le_bytes());
    preimage.extend_from_slice(manifest);
    blake2b256(&preimage)
}

fn manifest_reject(field: &str) -> LoaderError {
    LoaderError::ManifestRejected {
        field: field.to_string(),
    }
}

fn decode_manifest(bytes: &[u8]) -> Result<Manifest, LoaderError> {
    let mut cur = Cursor::new(bytes);
    let version = cur.u8();
    if version != MANIFEST_VERSION {
        return Err(manifest_reject("formatVersion"));
    }
    let exact_proof_bytes = cur.u32();
    let max_payload_bytes = cur.u32();
    let outer_po2 = cur.u8();
    let inner_control_root = cur.digest();

    let mut controls = Vec::with_capacity(CONTROL_COUNT);
    for _ in 0..CONTROL_COUNT {
        controls.push(ManifestControl {
            kind: cur.u8(),
            parameter: cur.u8(),
            control_id: cur.digest(),
        });
    }
    let algorithm = ArtifactReference {
        kind: cur.u16(),
        length: cur.u32() as u64,
        digest: cur.digest(),
    };
    let binary = ArtifactReference {
        kind: cur.u16(),
        length: cur.u32() as u64,
        digest: cur.digest(),
    };
    if cur.pos != MANIFEST_BYTES {
        return Err(manifest_reject("layout"));
    }

    if exact_proof_bytes == 0 || exact_proof_bytes != EXPECTED_PROOF_BYTES {
        return Err(manifest_reject("exactProofBytes"));
    }
    if max_payload_bytes != STOCK_PAYLOAD_BYTES {
        return Err(manifest_reject("maxApplicationPayloadBytes"));
    }
    if outer_po2 != EXPECTED_OUTER_PO2 {
        return Err(manifest_reject("outerPo2"));
    }
    validate_digest_words(&inner_control_root, "innerControlRoot")?;

    for i in 0..CONTROL_COUNT {
        let (expected_kind, expected_parameter) = if i < LIFT_COUNT {
            (NORMAL_LIFT_CONTROL_KIND, FIRST_SEGMENT_PO2 as u8 + i as u8)
        } else if i == LIFT_COUNT {
            (JOIN_CONTROL_KIND, 0)
        } else {
            (RESOLVE_CONTROL_KIND, 0)
        };
        if controls[i].kind != expected_kind {
            return Err(manifest_reject(&format!("controls[{i}].kind")));
        }
        if controls[i].parameter != expected_parameter {
            return Err(manifest_reject(&format!("controls[{i}].parameter")));
        }
        validate_digest_words(&controls[i].control_id, &format!("controls[{i}].controlId"))?;
        for earlier in 0..i {
            if controls[earlier].control_id == controls[i].control_id {
                return Err(manifest_reject(&format!("controls[{i}].controlId")));
            }
        }
    }
    if algorithm.kind != ALGORITHM_KIND {
        return Err(manifest_reject("algorithm.kind"));
    }
    if binary.kind != BINARY_DATA_KIND {
        return Err(manifest_reject("binaryData.kind"));
    }
    if algorithm.length == 0 {
        return Err(manifest_reject("algorithm.length"));
    }
    if algorithm.length > MAX_ALGORITHM_BYTES as u64 {
        return Err(manifest_reject("algorithm.length"));
    }
    if binary.length != BINARY_DATA_BYTES as u64 {
        return Err(manifest_reject("binaryData.length"));
    }

    Ok(Manifest {
        exact_proof_bytes,
        max_payload_bytes,
        outer_po2,
        inner_control_root,
        controls,
        algorithm,
        binary,
    })
}

fn validate_artifact(reference: &ArtifactReference, bytes: &[u8]) -> Result<(), LoaderError> {
    if reference.length != bytes.len() as u64 {
        return Err(LoaderError::ArtifactLengthMismatch {
            kind: reference.kind,
            expected: reference.length,
            actual: bytes.len(),
        });
    }
    let actual = artifact_digest(reference.kind, bytes);
    if actual != reference.digest {
        return Err(LoaderError::ArtifactDigestMismatch {
            kind: reference.kind,
        });
    }
    Ok(())
}

fn validate_algorithm(bytes: &[u8]) -> Result<(), LoaderError> {
    if bytes.is_empty() {
        return Err(LoaderError::AlgorithmEncodingRejected {
            offset: 0,
            value: -1,
        });
    }
    for (i, &b) in bytes.iter().enumerate() {
        let value = b as i32;
        if value != 0x09 && value != 0x0a && !(0x20..=0x7e).contains(&value) {
            return Err(LoaderError::AlgorithmEncodingRejected { offset: i, value });
        }
    }
    let last = bytes.len() - 1;
    if bytes[last] != 0x0a {
        return Err(LoaderError::AlgorithmEncodingRejected {
            offset: last,
            value: bytes[last] as i32,
        });
    }
    if bytes.len() >= 2 && bytes[last - 1] == 0x0a {
        return Err(LoaderError::AlgorithmEncodingRejected {
            offset: last - 1,
            value: 0x0a,
        });
    }
    Ok(())
}

fn validate_digest_words(bytes: &[u8; PROFILE_ID_BYTES], field: &str) -> Result<(), LoaderError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let word = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        if word >= BabyBear::P {
            return Err(manifest_reject(field));
        }
        offset += 4;
    }
    Ok(())
}

// ------------------------------------------------------------------
// B2 fixed header + roots-of-unity cross-check.
// ------------------------------------------------------------------

fn binary_reject(offset: usize, detail: &str) -> LoaderError {
    LoaderError::BinaryDataRejected {
        offset,
        detail: detail.to_string(),
    }
}

fn decode_binary_header(bytes: &[u8]) -> Result<BinaryHeader, LoaderError> {
    let mut cur = Cursor::new(bytes);
    let expect_u32 = |cur: &mut Cursor, expected: u32, detail: &str| -> Result<(), LoaderError> {
        let offset = cur.pos;
        let value = cur.u32();
        if value != expected {
            return Err(binary_reject(offset, detail));
        }
        Ok(())
    };
    let expect_u8 = |cur: &mut Cursor, expected: u8, detail: &str| -> Result<u8, LoaderError> {
        let offset = cur.pos;
        let value = cur.u8();
        if value != expected {
            return Err(binary_reject(offset, detail));
        }
        Ok(value)
    };
    let expect_u16 = |cur: &mut Cursor, expected: u16, detail: &str| -> Result<u16, LoaderError> {
        let offset = cur.pos;
        let value = cur.u16();
        if value != expected {
            return Err(binary_reject(offset, detail));
        }
        Ok(value)
    };

    expect_u32(&mut cur, BabyBear::P, "BabyBear modulus")?;
    let ext_size = expect_u8(&mut cur, 4, "extension degree")? as usize;
    expect_u32(&mut cur, 11, "extension polynomial beta")?;
    expect_u8(&mut cur, 27, "maximum root exponent")?;
    expect_u8(&mut cur, 24, "Poseidon2 cells")?;
    expect_u8(&mut cur, 16, "Poseidon2 rate")?;
    expect_u8(&mut cur, 8, "Poseidon2 output")?;
    expect_u8(&mut cur, 4, "Poseidon2 half-full rounds")?;
    expect_u8(&mut cur, 21, "Poseidon2 partial rounds")?;
    expect_u8(&mut cur, 7, "Poseidon2 S-box degree")?;
    expect_u16(&mut cur, 213, "stored Poseidon2 constants")?;
    expect_u8(&mut cur, 24, "Poseidon2 diagonal constants")?;
    let queries = expect_u8(&mut cur, 50, "STARK queries")? as usize;
    let inv_rate = expect_u8(&mut cur, 4, "inverse Reed-Solomon rate")? as usize;
    expect_u8(&mut cur, 16, "FRI fold")?;
    expect_u8(&mut cur, 4, "FRI fold exponent")?;
    expect_u16(&mut cur, 256, "FRI minimum degree")?;
    let output_size = expect_u8(&mut cur, 32, "recursion output size")? as usize;
    let mix_size = expect_u8(&mut cur, 20, "recursion mix size")? as usize;
    let check_size = expect_u8(&mut cur, 16, "check size")? as usize;
    expect_u16(&mut cur, 643, "tap count")?;
    expect_u8(&mut cur, 3, "register-group count")?;
    for (i, gs) in [12u8, 23, 128].into_iter().enumerate() {
        expect_u8(&mut cur, gs, &format!("group size {i}"))?;
    }
    expect_u8(&mut cur, 5, "combination count")?;
    expect_u8(&mut cur, 20, "total combination backs")?;
    expect_u16(&mut cur, 12359, "PolyExt instruction count")?;
    expect_u16(&mut cur, 11130, "PolyExt field-variable count")?;
    expect_u16(&mut cur, 1229, "PolyExt mix-variable count")?;
    expect_u16(&mut cur, 1228, "returned mix-variable index")?;
    for (i, r) in [0u8, 2, 1, 3].into_iter().enumerate() {
        expect_u8(&mut cur, r, &format!("extension coefficient remap {i}"))?;
    }
    for i in 0u8..3 {
        expect_u8(&mut cur, i, &format!("register-group identifier {i}"))?;
    }
    expect_u8(&mut cur, 16, "proof-system info length")?;
    expect_u8(&mut cur, 16, "circuit info length")?;
    expect_u8(&mut cur, 5, "tap-record width")?;
    expect_u8(&mut cur, 3, "extension challenge scale")?;
    let proof_system_info = cur.ascii(16, "proof-system info")?;
    let circuit_info = cur.ascii(16, "circuit info")?;
    if proof_system_info != "RISC0_STARK:v1__" {
        return Err(binary_reject(
            cur.pos - 32,
            "proof-system info does not match stock profile",
        ));
    }
    if circuit_info != "RECURSION:rev1v1" {
        return Err(binary_reject(
            cur.pos - 16,
            "circuit info does not match stock profile",
        ));
    }
    if cur.pos != HEADER_BYTES {
        return Err(binary_reject(
            cur.pos,
            "fixed header did not end at byte 87",
        ));
    }

    // Reverse roots-of-unity table, cross-checked against Layer 1 (mirrors the
    // reference `validateCompiledImplementation`).
    for i in 0..ROOT_COUNT {
        let offset = cur.pos;
        let root = cur.u32();
        if root >= BabyBear::P {
            return Err(binary_reject(
                offset,
                "reverse root is not a canonical value",
            ));
        }
        if root != rou_rev_table()[i] {
            return Err(LoaderError::CompiledImplementationMismatch {
                component: "reverse-root",
                index: i as i32,
            });
        }
        if BabyBear::inv(root) != rou_fwd_table()[i] {
            return Err(LoaderError::CompiledImplementationMismatch {
                component: "forward-root",
                index: i as i32,
            });
        }
    }

    Ok(BinaryHeader {
        output_size,
        mix_size,
        queries,
        inv_rate,
        ext_size,
        check_size,
    })
}

// ------------------------------------------------------------------
// Total little-endian cursor (rejects, never panics on short input).
// ------------------------------------------------------------------

struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Cursor { input, pos: 0 }
    }
    fn u8(&mut self) -> u8 {
        let v = self.input[self.pos];
        self.pos += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes([self.input[self.pos], self.input[self.pos + 1]]);
        self.pos += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes([
            self.input[self.pos],
            self.input[self.pos + 1],
            self.input[self.pos + 2],
            self.input[self.pos + 3],
        ]);
        self.pos += 4;
        v
    }
    fn digest(&mut self) -> [u8; PROFILE_ID_BYTES] {
        let mut d = [0u8; PROFILE_ID_BYTES];
        d.copy_from_slice(&self.input[self.pos..self.pos + PROFILE_ID_BYTES]);
        self.pos += PROFILE_ID_BYTES;
        d
    }
    fn ascii(&mut self, len: usize, label: &str) -> Result<String, LoaderError> {
        let mut s = String::with_capacity(len);
        for i in 0..len {
            let b = self.input[self.pos + i];
            if b > 0x7f {
                return Err(binary_reject(
                    self.pos + i,
                    &format!("{label} byte is not ASCII"),
                ));
            }
            s.push(b as char);
        }
        self.pos += len;
        Ok(s)
    }
}
