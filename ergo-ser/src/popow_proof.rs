//! NipopowProof codec — the wire payload carried inside the
//! `NipopowProof` P2P message (code 91). Mirrors Scala
//! `NipopowProofSerializer` at
//! `ergo-core/.../modifiers/history/popow/NipopowProof.scala:188-228`
//! byte-for-byte:
//!
//! ```text
//! u32 m
//! u32 k
//! u32 prefix_size
//! { u32 entry_size, [u8; entry_size] PoPowHeader_bytes } * prefix_size
//! u32 suffix_head_size
//! [u8; suffix_head_size] suffix_head_bytes      ; PoPowHeader bytes
//! u32 suffix_tail_size
//! { u32 entry_size, [u8; entry_size] Header_bytes } * suffix_tail_size
//! u8  continuous                                ; 1 == true, 0 == false
//! ```
//!
//! Each prefix entry and suffix-tail entry is length-prefixed so the
//! parser can `getBytes(entry_size)` into a sub-reader. We mirror the
//! same shape — `read_popow_header` and `read_header` are invoked on
//! sub-slices, not on the outer reader.
//!
//! Layering note: `ergo-ser` is normally byte↔struct only, with
//! acceptance policy living above. This reader is the exception — it
//! applies two defense-in-depth guards on the peer-controlled
//! `prefix_size` and `suffix_size` counts before passing them to
//! `Vec::with_capacity` (see [`POPOW_PROOF_MAX_PREFIX`] and
//! [`POPOW_PROOF_MAX_SUFFIX`]). The DoS must be caught at the alloc
//! site (no upstream layer sees per-field counts before bytes are
//! interpreted); honest-input semantics are unchanged.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::header::{read_header, serialize_header, Header};
use crate::popow_header::{read_popow_header, serialize_popow_header, PoPowHeader};

/// `[proposed]` hard cap on `NipopowProof.prefix` length for wire
/// decoding. Scala's `NipopowProofSerializer.parse` reads the count
/// without an upper bound; this cap is local acceptance policy, not
/// inherited protocol.
///
/// Sizing rationale: per KMZ17 §6, prefix length is
/// `O(log2(height) · m)` where `m = P2P_NIPOPOW_PROOF_M`. Mainnet
/// (`m = 6`, height ≈ 1.5M) → `log2 h · m ≈ 126` entries.
/// `10_000` is ~80× observed mainnet — comfortable headroom for any
/// plausible height/m regime while preventing peer-controlled
/// multi-GiB `Vec::with_capacity` allocation before the first prefix
/// entry's length-prefix bytes are even read.
const POPOW_PROOF_MAX_PREFIX: usize = 10_000;

/// `[proposed]` hard cap on `NipopowProof.suffix_tail` length. Scala's
/// `NipopowProofSerializer.parse` reads the count without an upper
/// bound; this cap is local acceptance policy, not inherited protocol.
///
/// Sizing rationale: the suffix shape is exactly `suffix_head` plus
/// `k` dense headers (`k = P2P_NIPOPOW_PROOF_K`). Mainnet `k = 10`,
/// so honest `suffix_tail.len() = 10`. `1_024` is ~100× observed
/// mainnet — accommodates any future `k` regime while bounding
/// allocation surface on hostile peer messages.
const POPOW_PROOF_MAX_SUFFIX: usize = 1_024;

/// Initial `Vec::with_capacity` hint for the prefix vector. Bounded so
/// a hostile peer that claims `prefix_size = POPOW_PROOF_MAX_PREFIX`
/// cannot force a ~2 MiB upfront reservation (`10_000 *
/// size_of::<PoPowHeader>`) before any entry's length-prefix byte is
/// read. The Vec still grows on `push` up to the hard cap; this only
/// bounds the *initial* reservation. Honest mainnet prefix sizes are
/// O(log2 h · m) ≈ 150 entries — well within this hint, so no
/// reallocation happens on honest inputs.
const POPOW_PROOF_PREFIX_VEC_SOFT_CAP: usize = 256;

/// A non-interactive proof of proof-of-work (KMZ17), as transmitted on
/// the wire under message code 91. The verifier
/// (`ergo-validation::popow`, sub-phase 14.3) consumes this struct
/// directly; the codec here is the byte ↔ struct boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NipopowProof {
    /// Minimum super-chain length parameter (μ in KMZ17). For mainnet
    /// `P2P_NIPOPOW_PROOF_M = 6` (`ErgoHistoryUtils.scala:29`).
    pub m: u32,
    /// Suffix length parameter (k in KMZ17). For mainnet
    /// `P2P_NIPOPOW_PROOF_K = 10` (`ErgoHistoryUtils.scala:34`).
    pub k: u32,
    /// Sparse witness chain anchored at genesis: each entry is a
    /// `PoPowHeader` with its interlinks vector + Merkle proof.
    pub prefix: Vec<PoPowHeader>,
    /// First dense suffix entry — `PoPowHeader` (with interlinks
    /// proof) for the suffix tip. The remaining suffix headers do
    /// not need interlinks proofs and are stored as raw `Header`s
    /// in `suffix_tail`.
    pub suffix_head: PoPowHeader,
    /// Dense suffix continuation. Together with `suffix_head` these
    /// form a contiguous `k`-header chain ending at the proof's tip.
    pub suffix_tail: Vec<Header>,
    /// Whether the proof claims a continuous chain (true) or a
    /// one-shot light-client proof (false). Our bootstrap path
    /// requires `continuous == true`.
    pub continuous: bool,
}

/// Serialize a `NipopowProof` per Scala `NipopowProofSerializer.serialize`
/// (`NipopowProof.scala:190-209`).
pub fn write_nipopow_proof(w: &mut VlqWriter, p: &NipopowProof) -> Result<(), WriteError> {
    w.put_u32(p.m);
    w.put_u32(p.k);

    w.put_u32(p.prefix.len() as u32);
    for entry in &p.prefix {
        let entry_bytes = serialize_popow_header(entry)?;
        w.put_u32(entry_bytes.len() as u32);
        w.put_bytes(&entry_bytes);
    }

    let head_bytes = serialize_popow_header(&p.suffix_head)?;
    w.put_u32(head_bytes.len() as u32);
    w.put_bytes(&head_bytes);

    w.put_u32(p.suffix_tail.len() as u32);
    for entry in &p.suffix_tail {
        let entry_bytes = serialize_header(entry).map(|(b, _id)| b)?;
        w.put_u32(entry_bytes.len() as u32);
        w.put_bytes(&entry_bytes);
    }

    w.put_u8(if p.continuous { 1 } else { 0 });
    Ok(())
}

/// Convenience: serialize to a fresh `Vec<u8>`.
pub fn serialize_nipopow_proof(p: &NipopowProof) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    write_nipopow_proof(&mut w, p)?;
    Ok(w.result())
}

/// Parse a `NipopowProof` per Scala `NipopowProofSerializer.parse`
/// (`NipopowProof.scala:211-228`).
pub fn read_nipopow_proof(r: &mut VlqReader) -> Result<NipopowProof, ReadError> {
    let m = r.get_u32_exact()?;
    let k = r.get_u32_exact()?;

    // `m` (minimum super-chain length) and `k` (suffix length) are ≥ 1 for
    // every well-formed proof — KMZ17 requires positive parameters and
    // mainnet uses `m = 6`, `k = 10`. A peer-supplied `m = 0` or `k = 0`
    // is malformed and is dangerous downstream: `m = 0` makes
    // `best_arg`'s `count < m` cutoff unreachable (an unbounded scoring
    // loop) and `prove`'s `sub_chain[len - m]` index out of bounds. Reject
    // both at the untrusted deserialize boundary so no such value ever
    // reaches the scoring / proving code. (`ergo-validation` also guards
    // these functions defensively, but the wire boundary is the root gate.)
    if m == 0 {
        return Err(ReadError::InvalidData(
            "NipopowProof.m must be >= 1 (got 0)".to_string(),
        ));
    }
    if k == 0 {
        return Err(ReadError::InvalidData(
            "NipopowProof.k must be >= 1 (got 0)".to_string(),
        ));
    }

    let prefix_size = r.get_u32_exact()? as usize;
    if prefix_size > POPOW_PROOF_MAX_PREFIX {
        return Err(ReadError::InvalidData(format!(
            "NipopowProof.prefix length {prefix_size} > cap {POPOW_PROOF_MAX_PREFIX}"
        )));
    }
    let mut prefix = Vec::with_capacity(prefix_size.min(POPOW_PROOF_PREFIX_VEC_SOFT_CAP));
    for _ in 0..prefix_size {
        let entry_size = r.get_u32_exact()? as usize;
        let entry_bytes = r.get_bytes(entry_size)?.to_vec();
        let mut er = VlqReader::new(&entry_bytes);
        prefix.push(read_popow_header(&mut er)?);
    }

    let suffix_head_size = r.get_u32_exact()? as usize;
    let head_bytes = r.get_bytes(suffix_head_size)?.to_vec();
    let suffix_head = {
        let mut sr = VlqReader::new(&head_bytes);
        read_popow_header(&mut sr)?
    };

    let suffix_size = r.get_u32_exact()? as usize;
    if suffix_size > POPOW_PROOF_MAX_SUFFIX {
        return Err(ReadError::InvalidData(format!(
            "NipopowProof.suffix_tail length {suffix_size} > cap {POPOW_PROOF_MAX_SUFFIX}"
        )));
    }
    let mut suffix_tail = Vec::with_capacity(suffix_size);
    for _ in 0..suffix_size {
        let entry_size = r.get_u32_exact()? as usize;
        let entry_bytes = r.get_bytes(entry_size)?.to_vec();
        let mut hr = VlqReader::new(&entry_bytes);
        suffix_tail.push(read_header(&mut hr)?);
    }

    let continuous_byte = r.get_u8()?;
    let continuous = continuous_byte == 1;

    Ok(NipopowProof {
        m,
        k,
        prefix,
        suffix_head,
        suffix_tail,
        continuous,
    })
}

/// Deserialize a complete `NipopowProof` from a byte slice. Reads to
/// EOF and returns an error if any trailing bytes remain (strict
/// framing — matches the wire convention that the proof bytes blob
/// has no trailing padding inside itself; the outer message frame
/// carries the only padding field).
pub fn deserialize_nipopow_proof(bytes: &[u8]) -> Result<NipopowProof, ReadError> {
    let mut r = VlqReader::new(bytes);
    let proof = read_nipopow_proof(&mut r)?;
    if r.remaining() != 0 {
        return Err(ReadError::InvalidData(format!(
            "trailing bytes after NipopowProof: {} byte(s)",
            r.remaining()
        )));
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::read_header;
    use ergo_primitives::digest::ModifierId;

    // ----- helpers -----

    /// Mainnet genesis (height 1). Used to build synthetic
    /// `PoPowHeader` / `NipopowProof` test fixtures whose header
    /// payloads round-trip through the real header codec.
    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";
    const HEIGHT_2_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    fn header_from_hex(s: &str) -> Header {
        let raw = hex::decode(s).unwrap();
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).unwrap()
    }

    fn popow_header(h: Header, interlinks: Vec<ModifierId>, proof: Vec<u8>) -> PoPowHeader {
        PoPowHeader {
            header: h,
            interlinks,
            interlinks_proof: proof,
        }
    }

    // ----- round-trips -----

    #[test]
    fn nipopow_proof_roundtrip_minimal_continuous_true() {
        // Smallest meaningful shape: empty prefix, one suffix_head,
        // empty suffix_tail, continuous = true.
        let proof = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_header(header_from_hex(GENESIS_HEX), vec![], vec![]),
            suffix_tail: vec![],
            continuous: true,
        };
        let bytes = serialize_nipopow_proof(&proof).unwrap();
        let parsed = deserialize_nipopow_proof(&bytes).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn nipopow_proof_roundtrip_populated_continuous_false() {
        // Non-empty prefix + non-empty suffix_tail. The light-client
        // shape (continuous = false) round-trips identically; we use
        // continuous=false here to pin both byte states of the flag.
        let proof = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![
                popow_header(
                    header_from_hex(GENESIS_HEX),
                    vec![ModifierId::from_bytes([0x11; 32])],
                    vec![0xAA, 0xBB],
                ),
                popow_header(
                    header_from_hex(HEIGHT_2_HEX),
                    vec![
                        ModifierId::from_bytes([0x11; 32]),
                        ModifierId::from_bytes([0x22; 32]),
                    ],
                    vec![0xCC, 0xDD, 0xEE],
                ),
            ],
            suffix_head: popow_header(
                header_from_hex(HEIGHT_2_HEX),
                vec![
                    ModifierId::from_bytes([0x11; 32]),
                    ModifierId::from_bytes([0x22; 32]),
                ],
                vec![0xFF, 0x00],
            ),
            suffix_tail: vec![header_from_hex(HEIGHT_2_HEX)],
            continuous: false,
        };
        let bytes = serialize_nipopow_proof(&proof).unwrap();
        let parsed = deserialize_nipopow_proof(&bytes).unwrap();
        assert_eq!(parsed, proof);

        // Encode -> decode -> re-encode produces identical bytes.
        let re_bytes = serialize_nipopow_proof(&parsed).unwrap();
        assert_eq!(re_bytes, bytes, "re-encode must be byte-identical");
    }

    // ----- error paths -----

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let proof = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_header(header_from_hex(GENESIS_HEX), vec![], vec![]),
            suffix_tail: vec![],
            continuous: true,
        };
        let mut bytes = serialize_nipopow_proof(&proof).unwrap();
        bytes.push(0xAA); // junk byte
        let err = deserialize_nipopow_proof(&bytes).expect_err("trailing byte must error");
        match err {
            ReadError::InvalidData(msg) => {
                assert!(msg.contains("trailing bytes"), "unexpected message: {msg}")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_truncated_continuous_flag() {
        // Strip the trailing continuous flag (1 byte) — parser must
        // error rather than default the flag to false.
        let proof = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_header(header_from_hex(GENESIS_HEX), vec![], vec![]),
            suffix_tail: vec![],
            continuous: true,
        };
        let mut bytes = serialize_nipopow_proof(&proof).unwrap();
        bytes.pop(); // remove continuous flag
        assert!(deserialize_nipopow_proof(&bytes).is_err());
    }

    /// Build a hostile header preamble (m, k, prefix_size) for cap
    /// tests. Supplies NO prefix entries after the count so any error
    /// that escapes the cap check must come from EOF, not Vec growth.
    fn hostile_prefix_preamble(prefix_size: u32) -> Vec<u8> {
        let mut w = VlqWriter::new();
        w.put_u32(6); // m
        w.put_u32(10); // k
        w.put_u32(prefix_size);
        w.result()
    }

    #[test]
    fn read_nipopow_proof_rejects_zero_m() {
        // A peer-supplied m = 0 is malformed and must be rejected at the
        // wire boundary (before it can reach best_arg's unbounded loop).
        // k = 10 is valid, so this pins the m guard specifically.
        let mut w = VlqWriter::new();
        w.put_u32(0); // m = 0
        w.put_u32(10); // k
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        match read_nipopow_proof(&mut r).expect_err("m = 0 must be rejected") {
            ReadError::InvalidData(msg) => {
                assert!(msg.contains("m must be >= 1"), "wrong message: {msg}");
            }
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    #[test]
    fn read_nipopow_proof_rejects_zero_k() {
        // Sibling guard: k = 0 is likewise malformed. m = 6 is valid so
        // the k guard is exercised on its own.
        let mut w = VlqWriter::new();
        w.put_u32(6); // m
        w.put_u32(0); // k = 0
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        match read_nipopow_proof(&mut r).expect_err("k = 0 must be rejected") {
            ReadError::InvalidData(msg) => {
                assert!(msg.contains("k must be >= 1"), "wrong message: {msg}");
            }
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    #[test]
    fn read_nipopow_proof_prefix_size_above_cap_rejects_before_alloc() {
        // Hostile prefix_size = i32::MAX. The cap check must fire on
        // the count itself, before Vec::with_capacity allocates and
        // before any inner read_popow_header is invoked. No prefix
        // bytes follow — a truncation-based error would prove the cap
        // gate was skipped.
        let bytes = hostile_prefix_preamble(i32::MAX as u32);
        let mut r = VlqReader::new(&bytes);
        let err = read_nipopow_proof(&mut r).expect_err("hostile prefix_size");
        match err {
            ReadError::InvalidData(msg) => {
                assert!(msg.contains("prefix length"), "wrong message: {msg}");
                assert!(msg.contains("10000"), "cap must be cited: {msg}");
            }
            other => panic!("expected InvalidData (cap), got {other:?}"),
        }
    }

    #[test]
    fn read_nipopow_proof_prefix_size_cap_boundary_rejects_one_past() {
        // Off-by-one pin: cap = POPOW_PROOF_MAX_PREFIX. cap + 1 must
        // reject; the gate must be `>` cap, not `>=`.
        let bytes = hostile_prefix_preamble((POPOW_PROOF_MAX_PREFIX as u32) + 1);
        let mut r = VlqReader::new(&bytes);
        assert!(matches!(
            read_nipopow_proof(&mut r),
            Err(ReadError::InvalidData(_))
        ));
    }

    /// Build a hostile preamble that includes a valid prefix (empty),
    /// a valid suffix_head, then the hostile suffix_size and nothing
    /// further. Any error escaping the suffix-cap check must come from
    /// EOF — proving the gate was skipped.
    fn hostile_suffix_preamble(suffix_size: u32) -> Vec<u8> {
        let proof = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_header(header_from_hex(GENESIS_HEX), vec![], vec![]),
            // Placeholder; we strip past suffix_size and rewrite below.
            suffix_tail: vec![],
            continuous: true,
        };
        let mut bytes = serialize_nipopow_proof(&proof).unwrap();
        // The serialized form ends with `u32 suffix_size (=0)` followed
        // by `u8 continuous`. Strip the trailing 0-suffix u32 + flag,
        // then re-append the hostile suffix_size.
        bytes.pop(); // continuous flag
        for _ in 0..vlq_len(0) {
            bytes.pop(); // suffix_size = 0 (VLQ-encoded)
        }
        let mut tail = VlqWriter::new();
        tail.put_u32(suffix_size);
        bytes.extend_from_slice(&tail.result());
        bytes
    }

    /// Byte-width of a VLQ-encoded u64 — needed because the preamble
    /// builder above strips a known-zero u32 from the tail.
    fn vlq_len(mut v: u64) -> usize {
        let mut n = 1;
        while v >= 0x80 {
            v >>= 7;
            n += 1;
        }
        n
    }

    #[test]
    fn read_nipopow_proof_suffix_size_above_cap_rejects_before_alloc() {
        let bytes = hostile_suffix_preamble(i32::MAX as u32);
        let mut r = VlqReader::new(&bytes);
        let err = read_nipopow_proof(&mut r).expect_err("hostile suffix_size");
        match err {
            ReadError::InvalidData(msg) => {
                assert!(msg.contains("suffix_tail length"), "wrong message: {msg}");
                assert!(msg.contains("1024"), "cap must be cited: {msg}");
            }
            other => panic!("expected InvalidData (cap), got {other:?}"),
        }
    }

    #[test]
    fn read_nipopow_proof_suffix_size_cap_boundary_rejects_one_past() {
        let bytes = hostile_suffix_preamble((POPOW_PROOF_MAX_SUFFIX as u32) + 1);
        let mut r = VlqReader::new(&bytes);
        assert!(matches!(
            read_nipopow_proof(&mut r),
            Err(ReadError::InvalidData(_))
        ));
    }

    #[test]
    fn nipopow_proof_prefix_size_exactly_at_cap_roundtrips() {
        // Cap-acceptance pin for prefix: `prefix.len() == cap` must
        // round-trip cleanly. Minimal PoPowHeader entries (empty
        // interlinks + empty proof) keep the wire footprint to
        // ~410 bytes per entry — ≈4 MiB total at cap=10_000, fine
        // for a unit test. Pairs with the cap+1 reject above.
        let entry = popow_header(header_from_hex(GENESIS_HEX), vec![], vec![]);
        let proof = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![entry.clone(); POPOW_PROOF_MAX_PREFIX],
            suffix_head: entry,
            suffix_tail: vec![],
            continuous: true,
        };
        let bytes = serialize_nipopow_proof(&proof).unwrap();
        let parsed = deserialize_nipopow_proof(&bytes).unwrap();
        assert_eq!(parsed.prefix.len(), POPOW_PROOF_MAX_PREFIX);
        assert_eq!(parsed, proof);
    }

    #[test]
    fn nipopow_proof_suffix_size_exactly_at_cap_roundtrips() {
        // Cap-acceptance pin for suffix_tail. Each tail entry is a
        // length-prefixed Header (≈400 bytes); cap=1024 → ~400 KiB.
        // Pairs with the cap+1 reject above.
        let head = popow_header(header_from_hex(GENESIS_HEX), vec![], vec![]);
        let tail_header = header_from_hex(GENESIS_HEX);
        let proof = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: head,
            suffix_tail: vec![tail_header; POPOW_PROOF_MAX_SUFFIX],
            continuous: true,
        };
        let bytes = serialize_nipopow_proof(&proof).unwrap();
        let parsed = deserialize_nipopow_proof(&bytes).unwrap();
        assert_eq!(parsed.suffix_tail.len(), POPOW_PROOF_MAX_SUFFIX);
        assert_eq!(parsed, proof);
    }
}
