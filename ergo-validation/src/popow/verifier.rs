//! NiPoPoW proof verifier — stateful collector that picks the best
//! valid proof seen so far across a sequence of `process` calls.
//!
//! Owned by the sync layer (`ergo-sync::popow_bootstrap`); single-
//! threaded, mutated under `&mut self`. Scala wraps the equivalent
//! in `bestProofOpt.synchronized` because actors share the verifier;
//! we don't, so the locking goes away.
//!
//! Scala source:
//! `ergo-core/.../local/NipopowVerifier.scala` (constructor + process
//! + reset semantics).

use ergo_crypto::difficulty::DifficultyParams;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::popow_proof::NipopowProof;

use super::proof::NipopowProofExt;

/// Outcome of [`NipopowVerifier::process`]. Mirrors Scala's
/// `NipopowProofVerificationResult` sealed hierarchy at
/// `ergo-core/.../local/NipopowVerificationResult.scala`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NipopowVerificationResult {
    /// The submitted proof is valid AND better than the current best
    /// (or the first valid proof seen). Best-proof has been replaced.
    BetterChain {
        /// Running count of successfully-processed (valid) proofs,
        /// post-increment.
        total_proofs: u32,
    },
    /// The submitted proof is valid but not better than the current
    /// best. Best-proof unchanged; counter still incremented.
    NoBetterChain {
        /// Running count of successfully-processed proofs.
        total_proofs: u32,
    },
    /// The submitted proof's `is_valid` returned `false`. Counter
    /// NOT incremented (matches Scala — only valid proofs count).
    ValidationError,
    /// The proof's first header id does not match the configured
    /// genesis id. Strong signal of a malicious peer or wrong network.
    /// Counter NOT incremented.
    WrongGenesis,
    /// The proof contained a header that cannot be reserialized via
    /// `ergo_ser::header::serialize_header`
    /// (`version ∈ [2, 4]` with non-empty `unparsed_bytes`, or
    /// `unparsed_bytes.len() > 255`). Strong signal of a malicious
    /// peer crafting structurally-impossible headers. Counter NOT
    /// incremented; `best_proof` unchanged.
    MalformedHeader,
}

/// Stateful collector that retains the best NiPoPoW proof seen so far.
///
/// Construct with [`NipopowVerifier::new`], feed proofs via
/// [`NipopowVerifier::process`], read the accepted chain via
/// [`NipopowVerifier::best_chain`], and clear the in-progress best
/// (without zeroing the processed counter) via
/// [`NipopowVerifier::reset`].
pub struct NipopowVerifier {
    genesis_id_opt: Option<[u8; 32]>,
    best_proof: Option<NipopowProof>,
    proofs_processed: u32,
    chain_config: DifficultyParams,
}

impl NipopowVerifier {
    /// Construct a verifier rooted at the supplied genesis id (or
    /// `None` for an open verifier that accepts any first-header).
    ///
    /// **Mainnet must always pass `Some(_)`** — passing `None` makes
    /// the verifier accept proofs for any chain; pinning the genesis id
    /// is what prevents that.
    pub fn new(genesis_id_opt: Option<[u8; 32]>, chain_config: DifficultyParams) -> Self {
        Self {
            genesis_id_opt,
            best_proof: None,
            proofs_processed: 0,
            chain_config,
        }
    }

    /// Headers from the current best proof in ascending height order,
    /// or empty if no proof has been accepted yet.
    pub fn best_chain(&self) -> Vec<Header> {
        self.best_proof
            .as_ref()
            .map(|p| p.headers_chain())
            .unwrap_or_default()
    }

    /// Borrow the current best NiPoPoW proof, if any. Needed by the
    /// sync-layer orchestration (`drive_popow_bootstrap`) so it can
    /// hand the proof directly to
    /// [`ergo_state::store::StateStore::apply_popow_proof`] without
    /// going through the consumed-headers projection.
    pub fn best_proof(&self) -> Option<&NipopowProof> {
        self.best_proof.as_ref()
    }

    /// Process a candidate proof; see [`NipopowVerificationResult`]
    /// for the four outcomes.
    ///
    /// Semantics mirror Scala `NipopowVerifier.scala:31-58`:
    /// 1. If `genesis_id_opt` is set AND `new_proof.headers_chain[0].id`
    ///    does not match → [`NipopowVerificationResult::WrongGenesis`].
    /// 2. Else, if no current best:
    ///    a. `new_proof.is_valid` → store, increment counter, return
    ///    [`NipopowVerificationResult::BetterChain`].
    ///    b. Otherwise → [`NipopowVerificationResult::ValidationError`].
    /// 3. Else (have current best):
    ///    a. `new_proof.is_better_than(best)` → replace, increment,
    ///    return [`NipopowVerificationResult::BetterChain`].
    ///    b. Else `new_proof.is_valid` → increment, return
    ///    [`NipopowVerificationResult::NoBetterChain`].
    ///    c. Else → [`NipopowVerificationResult::ValidationError`].
    pub fn process(&mut self, new_proof: NipopowProof) -> NipopowVerificationResult {
        // Pre-gate. Reject proofs containing headers that can't
        // reserialize. Done BEFORE the Scala-parity genesis check because
        // `header_id_first` needs to compute the first header's ID and
        // would otherwise have to surface a typed error from the
        // serializer. Counter and best_proof are untouched on this branch
        // (same conservative posture as `WrongGenesis` and
        // `ValidationError`).
        if !new_proof.all_headers_serializable() {
            return NipopowVerificationResult::MalformedHeader;
        }

        // Genesis check first. Scala uses `headersChain.head.id` which
        // is the FIRST header of the proof — prefix.head if prefix is
        // non-empty, else suffix_head.
        let first_id = match header_id_first(&new_proof) {
            Ok(id) => id,
            // Pre-gate above already rejected unserializable proofs, so
            // this is unreachable from honest control flow. Surface as a
            // typed result rather than panicking; the pre-gate could be
            // refactored away in the future and we'd rather degrade to
            // MalformedHeader than abort the node.
            Err(_) => return NipopowVerificationResult::MalformedHeader,
        };
        if let Some(expected) = self.genesis_id_opt {
            if first_id != expected {
                return NipopowVerificationResult::WrongGenesis;
            }
        }

        match self.best_proof.take() {
            None => {
                if new_proof.is_valid(&self.chain_config) {
                    self.best_proof = Some(new_proof);
                    self.proofs_processed += 1;
                    NipopowVerificationResult::BetterChain {
                        total_proofs: self.proofs_processed,
                    }
                } else {
                    NipopowVerificationResult::ValidationError
                }
            }
            Some(best_proof) => {
                if new_proof.is_better_than(&best_proof, &self.chain_config) {
                    // new_proof wins — drop the old best, install new.
                    self.best_proof = Some(new_proof);
                    self.proofs_processed += 1;
                    NipopowVerificationResult::BetterChain {
                        total_proofs: self.proofs_processed,
                    }
                } else {
                    // Restore old best (we took it with .take()), then
                    // judge new_proof's validity for the counter.
                    self.best_proof = Some(best_proof);
                    if new_proof.is_valid(&self.chain_config) {
                        self.proofs_processed += 1;
                        NipopowVerificationResult::NoBetterChain {
                            total_proofs: self.proofs_processed,
                        }
                    } else {
                        NipopowVerificationResult::ValidationError
                    }
                }
            }
        }
    }

    /// Drop the current best-proof.
    ///
    /// **Does NOT reset `proofs_processed`** — Scala's `reset()` at
    /// `NipopowVerifier.scala:63-66` only clears `bestProofOpt`, not
    /// the counter. Zeroing the counter here would diverge from
    /// Scala; the counter must survive across resets.
    pub fn reset(&mut self) {
        self.best_proof = None;
    }

    /// Number of successfully-processed (valid) proofs since the
    /// verifier was constructed. Survives across [`Self::reset`].
    pub fn proofs_processed(&self) -> u32 {
        self.proofs_processed
    }
}

// ---- internal helpers ----

fn header_id_first(proof: &NipopowProof) -> Result<[u8; 32], ergo_ser::error::WriteError> {
    // `headers_chain[0]` = prefix.first().map(.header).unwrap_or(suffix_head.header).
    let first = if let Some(p) = proof.prefix.first() {
        &p.header
    } else {
        &proof.suffix_head.header
    };
    // Caller (`NipopowVerifier::process`) calls `all_headers_serializable`
    // first, so this serialize_header call is unreachable in honest
    // control flow. Surfacing the WriteError as Result rather than
    // panicking lets future callers (or a refactor that removes the
    // pre-gate) degrade to MalformedHeader instead of aborting.
    let (_bytes, id) = serialize_header(first)?;
    Ok(*id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;
    use ergo_ser::popow_header::PoPowHeader;

    // ----- helpers -----

    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";
    const HEIGHT_2_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    fn header(s: &str) -> Header {
        let raw = hex::decode(s).unwrap();
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).unwrap()
    }

    fn popow_hdr(h: Header) -> PoPowHeader {
        PoPowHeader {
            header: h,
            interlinks: vec![],
            interlinks_proof: vec![],
        }
    }

    /// Build a synthetic valid 2-header proof: genesis + height 2,
    /// continuous=false so the difficulty-headers check is skipped.
    fn valid_proof() -> NipopowProof {
        NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![popow_hdr(header(GENESIS_HEX))],
            suffix_head: popow_hdr(header(HEIGHT_2_HEX)),
            suffix_tail: vec![],
            continuous: false,
        }
    }

    fn invalid_proof() -> NipopowProof {
        let mut h2 = header(HEIGHT_2_HEX);
        h2.parent_id = ModifierId::from_bytes([0xFF; 32]); // break connections
        NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![popow_hdr(header(GENESIS_HEX))],
            suffix_head: popow_hdr(h2),
            suffix_tail: vec![],
            continuous: false,
        }
    }

    fn mainnet_config() -> DifficultyParams {
        DifficultyParams::mainnet()
    }

    // ----- happy path -----

    #[test]
    fn empty_verifier_accepts_first_valid_proof_as_better_chain() {
        let mut v = NipopowVerifier::new(None, mainnet_config());
        let result = v.process(valid_proof());
        assert!(matches!(
            result,
            NipopowVerificationResult::BetterChain { total_proofs: 1 }
        ));
        assert_eq!(v.proofs_processed(), 1);
        assert!(!v.best_chain().is_empty());
    }

    #[test]
    fn same_proof_submitted_twice_returns_no_better_chain_on_second() {
        let mut v = NipopowVerifier::new(None, mainnet_config());
        v.process(valid_proof());
        let result = v.process(valid_proof());
        // Second submission is structurally identical, not better.
        // Counter still increments — Scala counts every valid proof.
        assert!(matches!(
            result,
            NipopowVerificationResult::NoBetterChain { total_proofs: 2 }
        ));
        assert_eq!(v.proofs_processed(), 2);
    }

    // ----- error paths -----

    #[test]
    fn invalid_first_proof_returns_validation_error_no_counter_bump() {
        let mut v = NipopowVerifier::new(None, mainnet_config());
        let result = v.process(invalid_proof());
        assert!(matches!(result, NipopowVerificationResult::ValidationError));
        assert_eq!(v.proofs_processed(), 0, "counter must NOT bump on invalid");
        assert!(v.best_chain().is_empty());
    }

    #[test]
    fn invalid_proof_after_valid_proof_does_not_disturb_best() {
        let mut v = NipopowVerifier::new(None, mainnet_config());
        v.process(valid_proof());
        let best_before = v.best_chain();
        let result = v.process(invalid_proof());
        assert!(matches!(result, NipopowVerificationResult::ValidationError));
        // best_chain unchanged; counter unchanged (Scala doesn't
        // increment on ValidationError after a best is established).
        assert_eq!(v.proofs_processed(), 1);
        assert_eq!(v.best_chain(), best_before);
    }

    #[test]
    fn wrong_genesis_returns_wrong_genesis_no_counter_bump() {
        // Configure verifier with a genesis id that doesn't match the
        // proof's first-header id.
        let v_genesis = [0xDE; 32];
        let mut v = NipopowVerifier::new(Some(v_genesis), mainnet_config());
        let result = v.process(valid_proof());
        assert!(matches!(result, NipopowVerificationResult::WrongGenesis));
        assert_eq!(v.proofs_processed(), 0);
        assert!(v.best_chain().is_empty());
    }

    #[test]
    fn correct_genesis_matches_proof_first_header_id() {
        // Compute the genesis id from the real GENESIS_HEX so the
        // verifier accepts the proof.
        let genesis = header(GENESIS_HEX);
        let (_b, id) = serialize_header(&genesis).unwrap();
        let mut v = NipopowVerifier::new(Some(*id.as_bytes()), mainnet_config());
        let result = v.process(valid_proof());
        assert!(matches!(
            result,
            NipopowVerificationResult::BetterChain { total_proofs: 1 }
        ));
    }

    // ----- edge cases: genesis-only and single-header proofs -----

    /// A proof containing only the genesis header (prefix empty,
    /// suffix_head = genesis, no suffix_tail). All Scala
    /// `is_valid` sub-checks are vacuously true:
    /// - `has_valid_heights`: 1-element chain, no pairs to compare
    /// - `has_valid_connections`: prefix_to_check.len() == 1, loop
    ///   range `1..1` is empty; suffix_tail is empty → no checks
    /// - `has_valid_proofs`: empty prefix + empty interlinks_proof
    ///   on suffix_head → vacuously valid
    /// - `has_valid_difficulty_headers`: continuous=false → trivial
    /// - `has_valid_per_header_pow`: genesis is skipped
    ///   (parent_id == zeros)
    #[test]
    fn genesis_only_proof_passes_is_valid() {
        let g = header(GENESIS_HEX);
        let mut p = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_hdr(g),
            suffix_tail: vec![],
            continuous: false,
        };
        p.continuous = false;
        // Direct check via the verifier's process call.
        let mut v = NipopowVerifier::new(None, mainnet_config());
        let result = v.process(p);
        assert!(
            matches!(
                result,
                NipopowVerificationResult::BetterChain { total_proofs: 1 }
            ),
            "genesis-only proof must be accepted as the first better chain, got {result:?}",
        );
        assert_eq!(v.best_chain().len(), 1);
    }

    /// `header_id_first` falls back to `suffix_head.header` when the
    /// prefix is empty (matches Scala's `headersChain.head`). Pin
    /// that the genesis-id check fires against the correct value
    /// for prefix-empty proofs.
    #[test]
    fn genesis_only_proof_first_id_from_suffix_head_for_genesis_check() {
        let g = header(GENESIS_HEX);
        let (_b, g_id) = serialize_header(&g).unwrap();

        // Verifier configured with the matching genesis: accept.
        let mut v_ok = NipopowVerifier::new(Some(*g_id.as_bytes()), mainnet_config());
        let p_ok = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_hdr(g.clone()),
            suffix_tail: vec![],
            continuous: false,
        };
        assert!(matches!(
            v_ok.process(p_ok),
            NipopowVerificationResult::BetterChain { .. }
        ));

        // Verifier configured with a non-matching genesis: WrongGenesis.
        let mut v_bad = NipopowVerifier::new(Some([0xDE; 32]), mainnet_config());
        let p_bad = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_hdr(g),
            suffix_tail: vec![],
            continuous: false,
        };
        assert!(matches!(
            v_bad.process(p_bad),
            NipopowVerificationResult::WrongGenesis
        ));
    }

    /// Single-header proof using a non-genesis header. Currently
    /// the per-header PoW check fires (h2 is non-genesis); if its
    /// PoW is real mainnet bytes it passes. Pin the acceptance to
    /// document the contract.
    #[test]
    fn single_non_genesis_header_proof_passes_is_valid() {
        let h2 = header(HEIGHT_2_HEX);
        let p = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_hdr(h2),
            suffix_tail: vec![],
            continuous: false,
        };
        let mut v = NipopowVerifier::new(None, mainnet_config());
        let result = v.process(p);
        assert!(
            matches!(result, NipopowVerificationResult::BetterChain { .. }),
            "single non-genesis header with valid PoW must pass, got {result:?}",
        );
    }

    /// Two genesis-only proofs submitted in sequence: second is
    /// not better than the first (`is_better_than` returns false
    /// when LCA is the only shared header and both diverging
    /// chains are empty).
    #[test]
    fn genesis_only_then_genesis_only_no_better_chain() {
        let g = header(GENESIS_HEX);
        let p1 = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_hdr(g.clone()),
            suffix_tail: vec![],
            continuous: false,
        };
        let p2 = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_hdr(g),
            suffix_tail: vec![],
            continuous: false,
        };
        let mut v = NipopowVerifier::new(None, mainnet_config());
        assert!(matches!(
            v.process(p1),
            NipopowVerificationResult::BetterChain { total_proofs: 1 }
        ));
        // Second submission: same chain → not better → counter still
        // bumps because the proof is structurally valid.
        assert!(matches!(
            v.process(p2),
            NipopowVerificationResult::NoBetterChain { total_proofs: 2 }
        ));
    }

    /// A longer proof shares genesis with a genesis-only proof:
    /// the longer one must be `is_better_than` the genesis-only.
    /// LCA is genesis; diverging chains are `[]` on the genesis-
    /// only side and `[h2]` on the longer side. `best_arg([], m)
    /// = 0`, `best_arg([h2], m) = 1` (level-0 count = 1). So the
    /// longer wins.
    #[test]
    fn longer_proof_supersedes_genesis_only_via_is_better_than() {
        let g = header(GENESIS_HEX);
        let h2 = header(HEIGHT_2_HEX);

        let genesis_only = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![],
            suffix_head: popow_hdr(g.clone()),
            suffix_tail: vec![],
            continuous: false,
        };
        let longer = NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![popow_hdr(g)],
            suffix_head: popow_hdr(h2),
            suffix_tail: vec![],
            continuous: false,
        };

        let mut v = NipopowVerifier::new(None, mainnet_config());
        assert!(matches!(
            v.process(genesis_only),
            NipopowVerificationResult::BetterChain { total_proofs: 1 }
        ));
        // Longer proof shares the genesis prefix; LCA = genesis;
        // diverging chains: [] vs [h2]; best_arg([h2], m) = 1 > 0.
        assert!(matches!(
            v.process(longer),
            NipopowVerificationResult::BetterChain { total_proofs: 2 }
        ));
        // best_chain now reflects the longer proof.
        assert_eq!(v.best_chain().len(), 2);
    }

    // ----- reset semantics -----

    #[test]
    fn reset_clears_best_proof_but_keeps_processed_counter() {
        let mut v = NipopowVerifier::new(None, mainnet_config());
        v.process(valid_proof());
        v.process(valid_proof()); // total_proofs = 2
        assert_eq!(v.proofs_processed(), 2);
        assert!(!v.best_chain().is_empty());

        v.reset();
        // best_chain cleared
        assert!(v.best_chain().is_empty(), "reset must drop best-proof");
        // Counter preserved (Scala parity NipopowVerifier.scala:63-66).
        assert_eq!(
            v.proofs_processed(),
            2,
            "reset must NOT zero proofs_processed (Scala parity)"
        );
    }
}
