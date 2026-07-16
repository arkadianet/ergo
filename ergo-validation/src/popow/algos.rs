//! Pure NiPoPoW algorithms — KMZ17 maxLevelOf, bestArg, LCA, and
//! update_interlinks. Scala reference: `NipopowAlgos.scala` (lines
//! cited inline at each function).

use ergo_crypto::autolykos::common::{blake2b256, calc_n};
use ergo_crypto::autolykos::v1::secp256k1_order;
use ergo_crypto::autolykos::v2::hit_for_v2;
use ergo_primitives::digest::ModifierId;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::header::{serialize_header_without_pow, Header};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

/// Sentinel μ-level for genesis. Matches Scala's `Int.MaxValue`
/// (`NipopowAlgos.scala:75`). A genesis header is at infinite level
/// because its required-target / real-target ratio is degenerate
/// and the consensus definition assigns it the top of the lattice.
pub const GENESIS_LEVEL: u32 = u32::MAX;

/// Key prefix for the interlinks vector in the extension's key-value
/// fields. Scala: `Extension.InterlinksVectorPrefix = 0x01`
/// (`Extension.scala:48`).
pub const INTERLINKS_VECTOR_PREFIX: u8 = 0x01;

/// Pack an interlinks vector into the extension's key-value-fields
/// layout. Scala parity: `NipopowAlgos.packInterlinks`
/// (`NipopowAlgos.scala:171-185`).
///
/// Layout per unique entry:
/// * key = `[INTERLINKS_VECTOR_PREFIX, idx as u8]` (2 bytes)
/// * value = `[dup_count as u8, ...modifier_id_bytes]` (33 bytes)
///
/// `idx` is the index in the original interlinks vector at which the
/// entry was observed; `dup_count` is Scala's count of ALL occurrences
/// of that id in the whole vector (== the run length for well-formed
/// vectors, where each id forms one consecutive run; deliberately
/// lossy on adversarial vectors — see the inline note + adversarial
/// parity tests).
pub fn pack_interlinks(links: &[ModifierId]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut idx: usize = 0;
    while idx < links.len() {
        let head = links[idx];
        // Scala counts ALL occurrences of `head` anywhere in the vector
        // (`links.count(_ == headLink)`, NipopowAlgos.scala:177) and then
        // drops that many entries POSITIONALLY from the remainder — for a
        // well-formed interlinks vector (each id in exactly one
        // consecutive run) this equals the run length, but for an
        // adversarial vector like [A,B,A] Scala emits two qty=2 entries
        // and swallows B (oracle-pinned; see the unit tests). The
        // consume-side `checkInterlinksProof` recomputes this packing on
        // RECEIVED interlinks, so any divergence here is an
        // accept/reject divergence against Scala on adversarial popow
        // headers — parity beats sanity.
        let dup_qty = links.iter().filter(|l| **l == head).count();
        let key = vec![INTERLINKS_VECTOR_PREFIX, idx as u8];
        let mut value = Vec::with_capacity(1 + 32);
        value.push(dup_qty as u8);
        value.extend_from_slice(head.as_bytes());
        out.push((key, value));
        idx += dup_qty;
    }
    out
}

/// Inverse of [`pack_interlinks`]: read kv-fields whose key prefix
/// is [`INTERLINKS_VECTOR_PREFIX`], expand the dup-count run encoding,
/// return the flat interlinks vector. Scala parity:
/// `NipopowAlgos.unpackInterlinks` (`NipopowAlgos.scala:190-209`).
///
/// Returns `Err` if any matching field has a value that isn't exactly
/// `1 + 32 = 33` bytes long ("Interlinks improperly packed" in Scala).
/// Fields whose key doesn't start with `INTERLINKS_VECTOR_PREFIX` are
/// ignored — extensions can carry other entries (voted params, etc.)
/// alongside interlinks.
pub fn unpack_interlinks(fields: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<ModifierId>, String> {
    let mut out: Vec<ModifierId> = Vec::new();
    for (key, value) in fields {
        if key.first() != Some(&INTERLINKS_VECTOR_PREFIX) {
            continue;
        }
        if value.len() != 33 {
            return Err(format!(
                "Interlinks improperly packed: value length {} (expected 33)",
                value.len()
            ));
        }
        let duplicates_qty = value[0] as usize;
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&value[1..33]);
        let link = ModifierId::from_bytes(id_bytes);
        for _ in 0..duplicates_qty {
            out.push(link);
        }
    }
    Ok(out)
}

/// Convert a key-value extension field to its Merkle-leaf byte form.
/// Scala parity: `Extension.kvToLeaf`
/// (`Extension.scala:82-83`).
///
/// Layout: `[key.len() as u8, ...key, ...value]`.
pub fn kv_to_leaf(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(1 + key.len() + value.len());
    leaf.push(key.len() as u8);
    leaf.extend_from_slice(key);
    leaf.extend_from_slice(value);
    leaf
}

/// Build a [`PoPowHeader`] from a header, its interlinks vector,
/// and the FULL set of extension fields (kv pairs — used only to
/// check the packed interlinks are really present in this block).
///
/// The interlinks_proof is a `BatchMerkleProof` over the
/// INTERLINKS-ONLY subtree (Scala `interlinksMerkleTree`); the
/// verifier (`check_popow_header_interlinks_proof`) recomputes that
/// same tree from the interlinks vector and validates the proof
/// against its root — NOT against the full extension root. See the
/// inline note below for the epoch-boundary bug this distinction
/// caught.
///
/// Returns `Err` if the interlinks vector cannot be located in
/// `extension_fields` (caller bug — the prover must have read both
/// from the same block).
///
/// Scala parity: `NipopowAlgos.proofForInterlinkVector` +
/// `Extension.merkleTree` + `BatchMerkleProofSerializer.serialize`.
pub fn build_popow_header(
    header: ergo_ser::header::Header,
    interlinks: Vec<ModifierId>,
    extension_fields: &[(Vec<u8>, Vec<u8>)],
) -> Result<ergo_ser::popow_header::PoPowHeader, String> {
    use ergo_crypto::merkle::merkle_proof_by_indices;
    use ergo_ser::batch_merkle_proof::{
        serialize_batch_merkle_proof, BatchMerkleProof, ProofEntry, Side,
    };

    // Empty interlinks (genesis) → the EMPTY BatchMerkleProof, which
    // Scala serializes as 8 zero bytes (two u32 counts), NOT as zero
    // bytes: `proofForInterlinkVector` returns
    // `BatchMerkleProof(Seq.empty, Seq.empty)` (NipopowAlgos.scala:
    // 218-219) and `PoPowHeaderSerializer` embeds its serialized form.
    // Emitting 0 bytes here made every proof containing genesis
    // wire-divergent from Scala (their parser rejects a 0-byte proof
    // blob) -- caught by a live differential run against block h=1.
    if interlinks.is_empty() {
        // Only genesis legitimately carries no interlinks. A non-genesis
        // header with an empty vector is corrupt or forged — the empty
        // BatchMerkleProof verifies vacuously, so without this guard the
        // malformed PoPowHeader would be served as valid. `is_genesis`
        // (zero parent_id) is the codebase's own genesis predicate.
        if !is_genesis(&header) {
            return Err("build_popow_header: empty interlinks vector for a \
                 non-genesis header"
                .to_string());
        }
        let empty = BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        };
        return Ok(ergo_ser::popow_header::PoPowHeader {
            header,
            interlinks,
            interlinks_proof: serialize_batch_merkle_proof(&empty),
        });
    }

    // Pack the interlinks into the extension kv form and require each
    // packed entry to exist in the block's actual extension (Scala's
    // `batchProofFor` similarly yields nothing when a key's leaf isn't
    // found — `ExtensionCandidate.scala:48-54`).
    let packed = pack_interlinks(&interlinks);
    for (key, value) in &packed {
        if !extension_fields.iter().any(|(k, v)| k == key && v == value) {
            return Err(format!(
                "interlinks key {} not found in extension_fields — header + extension may be from different blocks",
                hex::encode(key)
            ));
        }
    }

    // Build the proof over the INTERLINKS-ONLY subtree — NOT the full
    // extension tree. Scala's `ExtensionCandidate.batchProofFor` proves
    // indices within `interlinksMerkleTree` (the tree over interlink
    // fields alone, `ExtensionCandidate.scala:48-54`), and the verifier
    // (`PoPowHeader.checkInterlinksProof`, `PoPowHeader.scala:57-65`)
    // recomputes exactly `merkleTree(packInterlinks(interlinks))` as
    // the expected root. The two trees coincide for interlinks-only
    // extensions (every non-epoch-boundary block), which is how a
    // full-extension-tree construction here survived until a real
    // epoch-boundary block (mixed params + interlink fields; found
    // live at mainnet h=1821696 = 1779*1024) produced proofs Scala's
    // verifier — and our own — reject.
    let leaves: Vec<Vec<u8>> = packed.iter().map(|(k, v)| kv_to_leaf(k, v)).collect();
    let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let interlinks_indices: Vec<u32> = (0..packed.len() as u32).collect();
    let (idx_with_hashes, raw_proofs) = merkle_proof_by_indices(&leaf_refs, &interlinks_indices)
        .ok_or_else(|| {
            "merkle_proof_by_indices returned None (likely empty interlinks)".to_string()
        })?;

    let proof_entries: Vec<ProofEntry> = raw_proofs
        .into_iter()
        .map(|e| ProofEntry {
            digest: e.digest,
            side: if e.side == 0 { Side::Left } else { Side::Right },
        })
        .collect();
    let bmp = BatchMerkleProof {
        indices: idx_with_hashes,
        proofs: proof_entries,
    };
    let interlinks_proof = serialize_batch_merkle_proof(&bmp);

    Ok(ergo_ser::popow_header::PoPowHeader {
        header,
        interlinks,
        interlinks_proof,
    })
}

/// Parameters governing NiPoPoW proof construction (KMZ17). Mirrors
/// Scala `PoPowParams(m, k, continuous)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoPowParams {
    /// Minimum super-chain length per level (mainnet = 6).
    pub m: u32,
    /// Suffix length (mainnet = 10).
    pub k: u32,
    /// Whether the proof is continuous (true) — required for the
    /// post-suffix difficulty-headers check.
    pub continuous: bool,
}

/// Construct a NiPoPoW proof for the given chain. Scala parity:
/// `NipopowAlgos.prove` (`NipopowAlgos.scala:129-159`).
///
/// Preconditions:
/// * `chain.len() >= k + m`.
/// * `chain[0]` is genesis (`parent_id == zeros`).
/// * `params.k >= 1`.
///
/// Returns `Err` on precondition violation.
///
/// The chain is supplied as a `Vec<PoPowHeader>` so each entry
/// carries its own (header, interlinks, batch-merkle-proof) — the
/// caller is expected to build PoPowHeader instances via
/// [`build_popow_header`] before calling `prove`.
pub fn prove(
    chain: Vec<ergo_ser::popow_header::PoPowHeader>,
    params: PoPowParams,
) -> Result<ergo_ser::popow_proof::NipopowProof, String> {
    if params.k < 1 {
        return Err(format!("PoPowParams::k must be >= 1 (got {})", params.k));
    }
    if (chain.len() as u32) < params.k.saturating_add(params.m) {
        return Err(format!(
            "chain.len() = {} < k + m = {}",
            chain.len(),
            params.k.saturating_add(params.m)
        ));
    }
    let genesis = chain.first().ok_or_else(|| "empty chain".to_string())?;
    if *genesis.header.parent_id.as_bytes() != [0u8; 32] {
        return Err("chain.first() must be genesis (parent_id == zeros)".into());
    }

    let k = params.k as usize;
    let m = params.m as usize;

    // Suffix = last k entries. suffix_head = first; suffix_tail =
    // the remaining k-1 raw headers.
    let suffix_start = chain.len() - k;
    let suffix: Vec<ergo_ser::popow_header::PoPowHeader> = chain[suffix_start..].to_vec();
    let suffix_head = suffix[0].clone();
    let suffix_tail: Vec<ergo_ser::header::Header> =
        suffix.iter().skip(1).map(|p| p.header.clone()).collect();

    // The prefix carries the sparse witness chain. Scala recurses
    // from `maxLevel = chain.dropRight(k).last.interlinks.size - 1`
    // down to 0, accumulating sub-chains of each level that
    // satisfy `m < subChain.size`.
    let dropped_last = &chain[chain.len() - k - 1];
    let max_level = if dropped_last.interlinks.is_empty() {
        0i64
    } else {
        (dropped_last.interlinks.len() as i64) - 1
    };

    let mut acc: Vec<ergo_ser::popow_header::PoPowHeader> = Vec::new();
    prove_prefix_loop(&chain, max_level, &chain[0], &mut acc, k, m);
    acc.sort_by_key(|p| p.header.height);
    acc.dedup_by_key(|p| p.header.height);

    Ok(ergo_ser::popow_proof::NipopowProof {
        m: params.m,
        k: params.k,
        prefix: acc,
        suffix_head,
        suffix_tail,
        continuous: params.continuous,
    })
}

/// Tail-recursive worker for [`prove`]'s prefix construction.
/// Mirrors Scala `provePrefix` at `NipopowAlgos.scala:137-151`.
fn prove_prefix_loop(
    chain: &[ergo_ser::popow_header::PoPowHeader],
    level: i64,
    anchoring_point: &ergo_ser::popow_header::PoPowHeader,
    acc: &mut Vec<ergo_ser::popow_header::PoPowHeader>,
    k: usize,
    m: usize,
) {
    if level < 0 {
        return;
    }
    // chain.dropRight(k).filter(maxLevelOf >= level && height >= anchoring_point.height)
    let cutoff = chain.len().saturating_sub(k);
    let sub_chain: Vec<ergo_ser::popow_header::PoPowHeader> = chain[..cutoff]
        .iter()
        .filter(|p| {
            (max_level_of(&p.header) as i64) >= level
                && p.header.height >= anchoring_point.header.height
        })
        .cloned()
        .collect();
    if m < sub_chain.len() {
        // Scala: provePrefix(subChain(subChain.size - params.m), level - 1, acc ++ subChain)
        let new_anchor = sub_chain[sub_chain.len() - m].clone();
        acc.extend(sub_chain);
        prove_prefix_loop(chain, level - 1, &new_anchor, acc, k, m);
    } else {
        // Scala: provePrefix(anchoringPoint, level - 1, acc ++ subChain)
        acc.extend(sub_chain);
        let preserved_anchor = anchoring_point.clone();
        prove_prefix_loop(chain, level - 1, &preserved_anchor, acc, k, m);
    }
}

/// μ-level of `header` per KMZ17 §2.2:
///
/// ```text
/// μ = log2(requiredTarget) - log2(realTarget)
/// requiredTarget = q / decode_compact_bits(nBits)
/// realTarget     = powHit(header)
/// ```
///
/// `q` is the secp256k1 group order (Autolykos `Q`). `powHit` is the
/// header's PoW hit value: for header version 1 it is the
/// solution's `d` component; for v2+ it is the
/// `hit_for_v2(msg, nonce, height, n)` value where
/// `msg = Blake2b256(header bytes without PoW)`.
///
/// Genesis returns [`GENESIS_LEVEL`].
///
/// Returns `0` if either target is non-positive after `BigUint -> f64`
/// conversion (defensive — would indicate corrupt nBits or a hit of
/// zero). The Scala `.toInt` truncation on a negative `log2` diff is
/// matched by clamping to `0` here, since unsigned `u32::from`
/// otherwise wraps.
///
/// Scala source: `NipopowAlgos.scala:68-76`.
pub fn max_level_of(header: &Header) -> u32 {
    if is_genesis(header) {
        return GENESIS_LEVEL;
    }

    let required_target = secp256k1_order() / decode_compact_bits(header.n_bits);
    // If pow_hit can't serialize the header (unreachable from honest
    // callers — pre-gates filter), fall through to level 0 (the same
    // defensive return used below for non-positive targets and
    // non-finite log diffs). This keeps `max_level_of` infallible
    // without re-introducing a panic.
    let real_target = match pow_hit(header) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(error = ?e, "popow: pow_hit failed in max_level_of; degrading header to level 0");
            return 0;
        }
    };

    let required_f = biguint_to_f64(&required_target);
    let real_f = biguint_to_f64(&real_target);

    if required_f <= 0.0 || real_f <= 0.0 {
        tracing::debug!(
            required_f,
            real_f,
            "popow: non-positive target in max_level_of; degrading header to level 0"
        );
        return 0;
    }

    let level = required_f.log2() - real_f.log2();
    if !level.is_finite() || level <= 0.0 {
        tracing::debug!(level, "popow: non-finite or non-positive mu-level in max_level_of; degrading header to level 0");
        return 0;
    }
    level as u32
}

/// Best argument score for `chain` under minimum-superchain-length `m`.
/// Iterates μ-levels from 0 upward, accumulating `(level, count_at_or_above)`
/// for each level whose super-chain has length ≥ `m`. Level 0 is always
/// accumulated with `count = chain.len()`. Returns the maximum of
/// `2^level * count` over the accumulated pairs.
///
/// KMZ17 Algorithm 4. Scala source: `NipopowAlgos.scala:98-111`.
///
/// `u64` return covers any realistic chain × level product without
/// overflow; Scala returns `Int` and would overflow at extreme inputs.
/// Empty chain returns `0` (level 0 contributes `2^0 * 0 = 0`; no
/// higher level reaches the m-cutoff).
pub fn best_arg(chain: &[Header], m: u32) -> u64 {
    // `max_level_of` is a deterministic function of the header, so
    // computing each level once and scoring over the vector is
    // score-identical to the previous per-level recomputation.
    let levels: Vec<u32> = chain.iter().map(max_level_of).collect();
    best_arg_from_levels(&levels, m)
}

/// [`best_arg`] over pre-computed μ-levels instead of headers — the
/// same KMZ17 Algorithm 4 score for callers that track per-header
/// levels without retaining full `Header`s (e.g. a light
/// header-follower scoring its own followed chain against a NiPoPoW
/// proof). `levels[i]` must be `max_level_of` of the i-th chain
/// header; the genesis sentinel [`GENESIS_LEVEL`] participates in
/// every level's count, exactly as the header form does.
pub fn best_arg_from_levels(levels: &[u32], m: u32) -> u64 {
    let mut best: u64 = 0;

    // Level 0: always included with count = levels.len(). Every header
    // is by definition at least level 0; Scala explicitly skips the
    // m-cutoff at level 0 (`NipopowAlgos.scala:101-102`).
    let level_0_count = levels.len() as u64;
    best = best.max(level_0_count); // 2^0 * count

    let mut level: u32 = 1;
    loop {
        let count = levels.iter().filter(|&&l| l >= level).count() as u64;
        if count < m as u64 {
            return best;
        }
        // 2^level * count, saturating at u64::MAX so a hypothetical
        // 2^64 wrap-around can't underestimate the score.
        let score = (1u64)
            .checked_shl(level)
            .unwrap_or(u64::MAX)
            .saturating_mul(count);
        if score > best {
            best = score;
        }
        // u32 level cap: a chain whose every header has level ≥ 32 is
        // already at score ~chain.len() * 2^32. Beyond that we'd need
        // u64 levels, which KMZ17 does not produce in practice. Cap
        // here defensively rather than overflowing the shift.
        if level == u32::MAX {
            return best;
        }
        level += 1;
    }
}

/// Last shared header between two chains, iff they share a genesis
/// (i.e. their first elements are equal). Returns `None` otherwise.
///
/// Scala uses the naïve intersect-then-last (`NipopowAlgos.scala:116-122`);
/// this port matches the same semantics. The intersection is by header
/// id, walked in order, so the returned header is the deepest one
/// present in both chains.
pub fn lowest_common_ancestor<'a>(
    left_chain: &'a [Header],
    right_chain: &'a [Header],
) -> Result<Option<&'a Header>, ergo_ser::error::WriteError> {
    let Some(left_head) = left_chain.first() else {
        return Ok(None);
    };
    let Some(right_head) = right_chain.first() else {
        return Ok(None);
    };
    if header_id(left_head)? != header_id(right_head)? {
        return Ok(None);
    }

    // Same-genesis: walk left, keep the deepest one that's also in
    // right by id. O(L * R) like Scala's intersect; chains used here
    // are small (proof prefixes), not full mainnet chains.
    let mut right_ids: std::collections::HashSet<[u8; 32]> =
        std::collections::HashSet::with_capacity(right_chain.len());
    for h in right_chain {
        right_ids.insert(header_id(h)?);
    }

    for h in left_chain.iter().rev() {
        if right_ids.contains(&header_id(h)?) {
            return Ok(Some(h));
        }
    }
    Ok(None)
}

/// Compute the interlinks vector for the header immediately following
/// `prev_header`, given `prev_interlinks` (the interlinks vector that
/// was attached to `prev_header`).
///
/// Rule (`NipopowAlgos.scala:45-58`):
/// * If `prev_header` is genesis: return `[prev_header.id]`.
/// * Else: let `level = max_level_of(prev_header)`.
///   * If `level == 0`: return `prev_interlinks` unchanged.
///   * Else: take genesis from `prev_interlinks.first()`, then the
///     remaining `(prev_interlinks.len() - 1 - level)` entries from
///     the middle (`tail.dropRight(level)`), then append
///     `prev_header.id` repeated `level` times.
///
/// Panics if `prev_interlinks` is empty and `prev_header` is not
/// genesis — that input shape violates the protocol invariant
/// (`require(prevInterlinks.nonEmpty)` in Scala).
pub fn update_interlinks(
    prev_header: &Header,
    prev_interlinks: &[ModifierId],
) -> Result<Vec<ModifierId>, ergo_ser::error::WriteError> {
    // Prove parent header serializability up-front so the typed-error
    // contract holds across BOTH branches. Without this gate, a
    // malformed V1 header whose `pow_hit` short-circuit yields level 0
    // would slip through the `prev_level == 0` early return below with
    // `Ok(prev_interlinks.to_vec())` — silently accepting unchanged
    // interlinks for an unserializable parent.
    let prev_id_bytes = header_id(prev_header)?;

    if is_genesis(prev_header) {
        return Ok(vec![ModifierId::from_bytes(prev_id_bytes)]);
    }

    assert!(
        !prev_interlinks.is_empty(),
        "interlinks vector cannot be empty for non-genesis header",
    );

    let prev_level = max_level_of(prev_header);
    if prev_level == 0 {
        return Ok(prev_interlinks.to_vec());
    }

    let genesis = prev_interlinks[0];
    let tail = &prev_interlinks[1..];

    // Scala `tail.dropRight(prevLevel)`: drop the last `prevLevel`
    // entries from the tail. If `prevLevel` exceeds the tail length,
    // Seq.dropRight clamps to empty — match that.
    let keep_n = tail.len().saturating_sub(prev_level as usize);
    let kept_tail = &tail[..keep_n];

    let prev_id = ModifierId::from_bytes(prev_id_bytes);
    let mut out = Vec::with_capacity(1 + kept_tail.len() + prev_level as usize);
    out.push(genesis);
    out.extend_from_slice(kept_tail);
    for _ in 0..prev_level {
        out.push(prev_id);
    }
    Ok(out)
}

// ---- internal helpers ----

/// Genesis predicate: parent_id is the zero-bytes 32-byte array.
/// Matches Scala `Header.isGenesis` (`parentId.sameElements(GenesisParentId)`).
pub(crate) fn is_genesis(header: &Header) -> bool {
    *header.parent_id.as_bytes() == [0u8; 32]
}

/// Header id: Blake2b256 of the canonical serialized bytes. We compute
/// from the `bytes-without-pow` || solution path implicitly via
/// `serialize_header` if needed, but for popow we only need an id-by-
/// header lookup; build it via `blake2b256` of the full
/// serialization.
fn header_id(header: &Header) -> Result<[u8; 32], ergo_ser::error::WriteError> {
    // Pre-gates (NipopowProofExt::all_headers_serializable at verifier
    // entry; block validation / mining callers exercise paths where the
    // parent header has already been accepted) keep this Err
    // unreachable in honest control flow. Returning Result rather than
    // panicking lets production callers (block.rs interlinks check,
    // extension_builder.rs candidate construction) degrade to typed
    // errors instead of aborting the node when peer-supplied or
    // mempool-derived headers slip past a future relaxation.
    let (_bytes, id) = ergo_ser::header::serialize_header(header)?;
    Ok(*id.as_bytes())
}

/// `powHit(header)` per Scala `AutolykosPowScheme.scala:219-225`:
/// v1 reads `header.solution.d`; v2+ computes `hit_for_v2`.
fn pow_hit(header: &Header) -> Result<BigUint, ergo_ser::error::WriteError> {
    match &header.solution {
        AutolykosSolution::V1 { d, .. } => Ok(BigUint::from_bytes_be(d)),
        AutolykosSolution::V2 { nonce, .. } => {
            // Same pre-gate as `header_id` above. Returning Result lets
            // `max_level_of` degrade to level 0 ("not a μ-level
            // qualifier") instead of panicking when production callers
            // hit malformed headers.
            let header_bytes = serialize_header_without_pow(header)?;
            let msg = blake2b256(&header_bytes);
            let n = calc_n(header.version, header.height);
            Ok(hit_for_v2(&msg, nonce, header.height, n))
        }
    }
}

fn biguint_to_f64(v: &BigUint) -> f64 {
    v.to_f64().unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;

    // ----- helpers -----

    /// Deserialize a hex-encoded header. Panics on bad hex / decode.
    fn header_from_hex(hex_bytes: &str) -> Header {
        let raw = hex::decode(hex_bytes).expect("valid hex");
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).expect("valid header bytes")
    }

    /// Mainnet genesis header (height 1). Used by `is_genesis` /
    /// `max_level_of` genesis-path tests. Sourced from
    /// `test-vectors/mainnet/headers_1_10.json[0]`.
    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

    /// Mainnet height 2 (v1 Autolykos, non-genesis). Used by
    /// `max_level_of` non-genesis-path tests for the v1 branch.
    /// Sourced from `headers_1_10.json[1]`.
    const HEIGHT_2_V1_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    /// Helper: synthesize a non-genesis header by mutating a real one's
    /// `parent_id` to a non-zero value (and otherwise keeping every
    /// field, so the solution remains consistent for downstream
    /// hashing). Only used in tests that don't validate the PoW.
    fn with_nonzero_parent(mut h: Header, parent: [u8; 32]) -> Header {
        h.parent_id = ergo_primitives::digest::ModifierId::from_bytes(parent);
        h
    }

    // ----- happy path -----

    #[test]
    fn max_level_of_genesis_returns_sentinel() {
        let h = header_from_hex(GENESIS_HEX);
        assert_eq!(max_level_of(&h), GENESIS_LEVEL);
    }

    #[test]
    fn max_level_of_non_genesis_v1_returns_finite_level() {
        // Height 2: real mainnet v1 header. We don't pin a specific
        // level value here (no Scala-extracted oracle vector is
        // available for this height yet); instead we pin that the
        // function:
        //   * does not panic
        //   * returns a finite value (< GENESIS_LEVEL)
        //   * returns 0 or more (no underflow/wraparound)
        let h = header_from_hex(HEIGHT_2_V1_HEX);
        let level = max_level_of(&h);
        assert!(level < GENESIS_LEVEL, "level should be finite, got {level}");
    }

    #[test]
    fn best_arg_empty_chain_returns_zero() {
        let score = best_arg(&[], 2);
        assert_eq!(score, 0);
    }

    #[test]
    fn best_arg_single_genesis_chain_returns_one_at_level_zero() {
        // Genesis has max_level_of == u32::MAX. For m=2, the level-0
        // count is 1 (< m). Higher levels would all pass the filter
        // (genesis satisfies any level), but the count there is also
        // 1 < m, so the loop terminates immediately after level 0.
        // The level-0 entry contributes 2^0 * 1 = 1.
        let h = header_from_hex(GENESIS_HEX);
        let score = best_arg(std::slice::from_ref(&h), 2);
        assert_eq!(score, 1);
    }

    #[test]
    fn best_arg_from_levels_matches_header_form_on_real_headers() {
        // The refactor-parity pin: `best_arg` must equal
        // `best_arg_from_levels` over `max_level_of`-derived levels for
        // real headers, for several m values.
        let chain = vec![
            header_from_hex(GENESIS_HEX),
            header_from_hex(HEIGHT_2_V1_HEX),
        ];
        let levels: Vec<u32> = chain.iter().map(max_level_of).collect();
        for m in [1u32, 2, 6] {
            assert_eq!(best_arg(&chain, m), best_arg_from_levels(&levels, m));
        }
    }

    #[test]
    fn best_arg_from_levels_empty_returns_zero() {
        assert_eq!(best_arg_from_levels(&[], 2), 0);
    }

    #[test]
    fn best_arg_from_levels_level_zero_skips_m_cutoff() {
        // One level-0 header with m=6: level 0 always counts
        // (2^0 * 1 = 1) even though 1 < m.
        assert_eq!(best_arg_from_levels(&[0], 6), 1);
    }

    #[test]
    fn best_arg_from_levels_scores_superchain_over_length() {
        // Six level-3 headers with m=2: level 3 passes the cutoff
        // (count 6 >= 2) and scores 2^3 * 6 = 48, beating the level-0
        // score of 6. A longer all-level-0 chain of 20 scores only 20.
        assert_eq!(best_arg_from_levels(&[3; 6], 2), 48);
        assert_eq!(best_arg_from_levels(&[0; 20], 2), 20);
    }

    #[test]
    fn best_arg_from_levels_m_cutoff_stops_at_thin_level() {
        // Levels [2, 2, 0]: at level 1 and 2 the count is 2 >= m=2
        // (score 2^2 * 2 = 8); at level 3 the count 0 < m stops the
        // loop. Max(3, 4, 8) = 8.
        assert_eq!(best_arg_from_levels(&[2, 2, 0], 2), 8);
        // Same levels with m=3: count 2 < 3 already at level 1, so
        // only level 0 contributes.
        assert_eq!(best_arg_from_levels(&[2, 2, 0], 3), 3);
    }

    #[test]
    fn lowest_common_ancestor_shared_genesis_returns_deepest_common() {
        let g = header_from_hex(GENESIS_HEX);
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        // Both chains start at genesis, share heights 1..2, then
        // diverge synthetically at h3.
        let h3_left = with_nonzero_parent(h2.clone(), [0x11; 32]);
        let h3_right = with_nonzero_parent(h2.clone(), [0x22; 32]);
        let left = vec![g.clone(), h2.clone(), h3_left];
        let right = vec![g, h2.clone(), h3_right];
        let lca = lowest_common_ancestor(&left, &right)
            .expect("test fixture headers serialize")
            .expect("shared genesis -> some lca");
        assert_eq!(header_id(lca).unwrap(), header_id(&h2).unwrap());
    }

    #[test]
    fn lowest_common_ancestor_diff_genesis_returns_none() {
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let left = vec![h2.clone()]; // genesis = h2.id
        let right_synth_genesis = with_nonzero_parent(h2.clone(), [0xff; 32]);
        let right = vec![right_synth_genesis];
        assert!(lowest_common_ancestor(&left, &right)
            .expect("test fixture headers serialize")
            .is_none());
    }

    #[test]
    fn update_interlinks_genesis_returns_singleton_with_prev_id() {
        let g = header_from_hex(GENESIS_HEX);
        let out = update_interlinks(&g, &[]).expect("genesis header serializes");
        assert_eq!(out.len(), 1);
        assert_eq!(*out[0].as_bytes(), header_id(&g).unwrap());
    }

    #[test]
    fn update_interlinks_zero_level_returns_input_unchanged() {
        // Construct a non-genesis header whose `max_level_of` returns 0.
        // Real mainnet headers occasionally hit level 0 (most common
        // case), but determining that requires running the function on
        // a known vector. Instead: any non-genesis header with very low
        // real-target margin works. We test the BEHAVIORAL contract via
        // synthesis: we cannot easily synthesize a level-0 header
        // without manipulating PoW, so this test pins the input/output
        // shape for the level==0 branch by mocking via dependency
        // injection... which we don't have. Skip the in-mod assertion
        // and rely on the crate's oracle test surface instead. Documented
        // here so a future reader knows the intent and to extend coverage
        // when a level-0 mainnet header is pinned.
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let prev_interlinks = vec![
            ModifierId::from_bytes([0x00; 32]), // synthetic "genesis" id
            ModifierId::from_bytes([0xAA; 32]), // synthetic level-1 link
        ];
        // Compute level for h2 — if it's 0, prev_interlinks comes back
        // unchanged; otherwise the test exercises the level > 0 path
        // (which is also covered below). Either is a valid property,
        // so we just assert the structural shape Scala produces:
        let level = max_level_of(&h2);
        let out = update_interlinks(&h2, &prev_interlinks).expect("h2 header serializes");
        if level == 0 {
            assert_eq!(out, prev_interlinks);
        } else {
            // level > 0 path: out starts with genesis, then truncated
            // middle, then `level` copies of h2.id.
            assert_eq!(out[0], prev_interlinks[0]);
            let h2_id = ModifierId::from_bytes(header_id(&h2).unwrap());
            for entry in &out[out.len() - level as usize..] {
                assert_eq!(*entry, h2_id);
            }
        }
    }

    #[test]
    fn update_interlinks_genesis_branch_ignores_provided_interlinks() {
        // Genesis path returns `[genesis.id]` regardless of any
        // prev_interlinks passed in (Scala signature accepts an
        // `Option<Extension>` and short-circuits to Seq(prevHeader.id)
        // for genesis). Pin that the input vector is not consulted.
        let g = header_from_hex(GENESIS_HEX);
        let interlinks = vec![
            ModifierId::from_bytes([0x01; 32]),
            ModifierId::from_bytes([0xAA; 32]),
            ModifierId::from_bytes([0xBB; 32]),
        ];
        let out = update_interlinks(&g, &interlinks).expect("genesis header serializes");
        assert_eq!(out.len(), 1);
        assert_eq!(*out[0].as_bytes(), header_id(&g).unwrap());
    }

    // ----- error paths -----

    #[test]
    #[should_panic(expected = "interlinks vector cannot be empty for non-genesis header")]
    fn update_interlinks_non_genesis_empty_interlinks_panics() {
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        // HEIGHT_2_V1_HEX is a real serializable mainnet header, so the
        // up-front header_id gate succeeds and the assert! on empty
        // interlinks is the panic the caller hits.
        let _ = update_interlinks(&h2, &[]);
    }

    #[test]
    fn update_interlinks_unserializable_parent_returns_err_even_at_level_0() {
        // A V1 header whose `d` payload is wider than the on-wire
        // `u8` length prefix (256+ bytes) (a) fails `serialize_header`
        // (write_solution rejects), and could (b) bypass that failure
        // in `update_interlinks` if `max_level_of` returns 0 — the V1
        // `pow_hit` branch reads `d` directly without serializing.
        // The up-front `header_id(prev_header)?` gate makes
        // serialization a precondition on BOTH branches; this test
        // synthesizes the unserializable-V1 case and asserts Err.
        use ergo_primitives::digest::ModifierId;
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;

        let mut h = header_from_hex(HEIGHT_2_V1_HEX);
        // Replace the V1 solution with an overlong d payload (260 bytes
        // > u8::MAX) so write_solution rejects per
        // ergo-ser/src/autolykos.rs::write_solution length cap.
        h.solution = AutolykosSolution::V1 {
            pk: GroupElement::from_bytes([0x02; 33]),
            w: GroupElement::from_bytes([0x03; 33]),
            nonce: [0x04; 8],
            d: vec![0x05u8; 260],
        };

        // prev_interlinks chosen so prev_level == 0 path is reachable
        // for the synthesized header (the gate is the up-front
        // header_id check, not the level computation — so this Err
        // surfaces regardless).
        let prev_interlinks = vec![ModifierId::from_bytes([0x00; 32])];
        let result = update_interlinks(&h, &prev_interlinks);
        assert!(
            result.is_err(),
            "unserializable parent header must surface WriteError, got Ok({:?})",
            result
        );
    }

    // ----- pack_interlinks -----

    #[test]
    fn pack_interlinks_single_unique_entry_emits_one_field() {
        let id = ModifierId::from_bytes([0x11; 32]);
        let packed = pack_interlinks(&[id]);
        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0].0, vec![INTERLINKS_VECTOR_PREFIX, 0]);
        assert_eq!(packed[0].1[0], 1); // duplicate count = 1
        assert_eq!(&packed[0].1[1..], id.as_bytes());
    }

    #[test]
    fn pack_then_unpack_interlinks_roundtrips() {
        // Pack a vector with duplicates → unpack → same vector.
        let g = ModifierId::from_bytes([0x11; 32]);
        let lvl1 = ModifierId::from_bytes([0x22; 32]);
        let lvl2 = ModifierId::from_bytes([0x33; 32]);
        let interlinks = vec![g, lvl1, lvl1, lvl1, lvl2];
        let packed = pack_interlinks(&interlinks);
        let unpacked = unpack_interlinks(&packed).unwrap();
        assert_eq!(unpacked, interlinks);
    }

    #[test]
    fn unpack_interlinks_ignores_non_interlinks_fields() {
        // Real extensions carry voted params + interlinks; only the
        // 0x01-prefixed keys should contribute.
        let g = ModifierId::from_bytes([0x11; 32]);
        let mut packed = pack_interlinks(&[g]);
        packed.push((vec![0x00, 0x05], vec![0xAB, 0xCD])); // some other field
        packed.push((vec![0x02, 0x00], vec![0xEF])); // another non-interlinks field
        let unpacked = unpack_interlinks(&packed).unwrap();
        assert_eq!(unpacked.len(), 1);
        assert_eq!(unpacked[0], g);
    }

    #[test]
    fn unpack_interlinks_rejects_wrong_value_length() {
        // A value that's not exactly 33 bytes means the dup-count
        // run-encoding is corrupted — Scala raises "Interlinks
        // improperly packed".
        let bad_fields = vec![(vec![0x01, 0x00], vec![0x01, 0xAA, 0xBB])];
        let err = unpack_interlinks(&bad_fields).expect_err("bad length must error");
        assert!(err.contains("improperly packed"), "unexpected: {err}");
    }

    #[test]
    fn pack_interlinks_runs_of_duplicates_get_run_length_encoded() {
        let g = ModifierId::from_bytes([0x11; 32]);
        let lvl1 = ModifierId::from_bytes([0x22; 32]);
        // Interlinks: [g, lvl1, lvl1, lvl1] → 2 unique entries, the
        // second with dup_count = 3 starting at index 1.
        let packed = pack_interlinks(&[g, lvl1, lvl1, lvl1]);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0].1[0], 1); // g appears once at index 0
        assert_eq!(packed[1].0, vec![INTERLINKS_VECTOR_PREFIX, 1]); // starts at index 1
        assert_eq!(packed[1].1[0], 3); // dup_count = 3
    }

    // ----- prove -----

    #[test]
    fn prove_rejects_chain_below_k_plus_m() {
        let g = header_from_hex(GENESIS_HEX);
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let chain: Vec<ergo_ser::popow_header::PoPowHeader> = vec![g, h2]
            .into_iter()
            .map(|h| ergo_ser::popow_header::PoPowHeader {
                header: h,
                interlinks: vec![],
                interlinks_proof: vec![],
            })
            .collect();
        let params = PoPowParams {
            m: 6,
            k: 10,
            continuous: true,
        };
        let err = prove(chain, params).expect_err("chain too short");
        assert!(err.contains("< k + m"), "unexpected error: {err}");
    }

    #[test]
    fn prove_rejects_non_genesis_anchored_chain() {
        // h2 first (not genesis) → must error.
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let chain: Vec<ergo_ser::popow_header::PoPowHeader> = (0..3)
            .map(|_| ergo_ser::popow_header::PoPowHeader {
                header: h2.clone(),
                interlinks: vec![],
                interlinks_proof: vec![],
            })
            .collect();
        let params = PoPowParams {
            m: 1,
            k: 2,
            continuous: true,
        };
        let err = prove(chain, params).expect_err("must be genesis-anchored");
        assert!(err.contains("genesis"), "unexpected error: {err}");
    }

    #[test]
    fn prove_minimal_chain_produces_well_formed_proof() {
        // Build a 3-header chain (genesis + 2 fake follow-ups by
        // reusing h2; the prove() function only checks heights +
        // interlinks structure, not chain semantic correctness).
        // m=1, k=2 → minimum viable.
        let g = header_from_hex(GENESIS_HEX);
        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let mut h3 = header_from_hex(HEIGHT_2_V1_HEX);
        h3.height = 3;
        let chain: Vec<ergo_ser::popow_header::PoPowHeader> = vec![g, h2, h3]
            .into_iter()
            .map(|h| ergo_ser::popow_header::PoPowHeader {
                header: h,
                interlinks: vec![ModifierId::from_bytes([0x11; 32])],
                interlinks_proof: vec![],
            })
            .collect();
        let params = PoPowParams {
            m: 1,
            k: 2,
            continuous: true,
        };
        let proof = prove(chain, params).expect("3-header chain proves");
        assert_eq!(proof.m, 1);
        assert_eq!(proof.k, 2);
        // suffix = last k=2 entries: suffix_head + 1 tail header.
        assert_eq!(proof.suffix_tail.len(), 1);
        // prefix sorted by height + dedup'd.
        for w in proof.prefix.windows(2) {
            assert!(
                w[0].header.height < w[1].header.height,
                "prefix must be strictly increasing in height"
            );
        }
    }

    // ----- build_popow_header -----

    #[test]
    fn build_popow_header_empty_interlinks_returns_empty_proof() {
        let g = header_from_hex(GENESIS_HEX);
        let p = build_popow_header(g.clone(), vec![], &[]).unwrap();
        assert!(p.interlinks.is_empty());
        // Canonical empty-proof wire form = 8 zero bytes (Scala's
        // serialized empty BatchMerkleProof), NOT 0 bytes — see the
        // genesis wire-form fix in build_popow_header.
        assert_eq!(p.interlinks_proof, vec![0u8; 8]);
    }

    #[test]
    fn build_popow_header_with_interlinks_produces_verifiable_proof() {
        // Synthesize a PoPowHeader from a header + interlinks + a
        // MIXED extension (interlink fields + unrelated fields — the
        // epoch-boundary shape that exposed the live construction bug
        // at mainnet h=1821696). The Scala contract
        // (`PoPowHeader.checkInterlinksProof`, PoPowHeader.scala:57-65)
        // verifies the proof against the INTERLINKS-ONLY tree root
        // recomputed from the interlinks vector — NOT against the full
        // extension root. This test previously pinned the
        // full-extension-root behavior, i.e. it pinned the bug.
        use super::super::merkle::verify_batch_merkle_proof;
        use super::super::proof::check_popow_header_interlinks_proof;
        use ergo_crypto::merkle::merkle_tree_root;
        use ergo_ser::batch_merkle_proof::deserialize_batch_merkle_proof;

        let h2 = header_from_hex(HEIGHT_2_V1_HEX);
        let interlinks = vec![
            ModifierId::from_bytes([0x11; 32]),
            ModifierId::from_bytes([0x22; 32]),
        ];
        let packed_interlinks = pack_interlinks(&interlinks);
        // Unrelated fields FIRST — mirrors real epoch-boundary blocks,
        // where protocol-parameter fields (key prefix 0x00) precede the
        // interlink fields, shifting their full-tree positions.
        let mut extension_fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (vec![0x00, 0x01], vec![0xAB, 0xCD]),
            (vec![0x00, 0x04], vec![0xEF]),
        ];
        extension_fields.extend(packed_interlinks.clone());

        let popow = build_popow_header(h2.clone(), interlinks.clone(), &extension_fields).unwrap();
        assert!(!popow.interlinks_proof.is_empty());

        // The consume-side validator (Scala parity: interlinks-only
        // tree) must accept the constructed proof.
        assert!(
            check_popow_header_interlinks_proof(&popow),
            "constructed proof must verify against the interlinks-only tree root"
        );

        // And explicitly: the proof reduces to the interlinks-only
        // root, NOT the full-extension root (they differ here because
        // of the non-interlink fields).
        let bmp = deserialize_batch_merkle_proof(&popow.interlinks_proof).unwrap();
        let interlink_leaves: Vec<Vec<u8>> = packed_interlinks
            .iter()
            .map(|(k, v)| kv_to_leaf(k, v))
            .collect();
        let interlink_refs: Vec<&[u8]> = interlink_leaves.iter().map(|l| l.as_slice()).collect();
        assert!(verify_batch_merkle_proof(
            &bmp,
            &merkle_tree_root(&interlink_refs)
        ));
        let full_leaves: Vec<Vec<u8>> = extension_fields
            .iter()
            .map(|(k, v)| kv_to_leaf(k, v))
            .collect();
        let full_refs: Vec<&[u8]> = full_leaves.iter().map(|l| l.as_slice()).collect();
        assert!(
            !verify_batch_merkle_proof(&bmp, &merkle_tree_root(&full_refs)),
            "full-extension root must NOT verify — that was the old buggy contract"
        );
    }
}

#[cfg(test)]
mod pack_interlinks_scala_adversarial_parity {
    use super::*;

    fn mid(b: u8) -> ModifierId {
        ModifierId::from_bytes([b; 32])
    }

    /// Oracle-pinned (scala-cli, ergo-core 6.0.2 `NipopowAlgos.packInterlinks`,
    /// 2026-07-05): adversarial NON-consecutive duplicate vectors. Scala's
    /// count-all + positional-drop semantics are lossy — `[A,B,A]` packs to
    /// two qty=2 A-entries and B is swallowed. The verifier recomputes this
    /// packing on received interlinks, so byte-parity here decides
    /// accept/reject parity on adversarial popow headers.
    #[test]
    fn adversarial_vectors_match_scala_exactly() {
        let a = mid(0xAA);
        let b = mid(0xBB);
        // [A,B,A] => (idx0, qty2, A), (idx2, qty2, A)
        let p = pack_interlinks(&[a, b, a]);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].0, vec![INTERLINKS_VECTOR_PREFIX, 0]);
        assert_eq!(p[0].1[0], 2);
        assert_eq!(&p[0].1[1..], a.as_bytes());
        assert_eq!(p[1].0, vec![INTERLINKS_VECTOR_PREFIX, 2]);
        assert_eq!(p[1].1[0], 2);
        assert_eq!(&p[1].1[1..], a.as_bytes());
        // [A,A,B,A] => (idx0, qty3, A), (idx3, qty3, A)
        let p = pack_interlinks(&[a, a, b, a]);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].0[1], p[0].1[0]), (0, 3));
        assert_eq!((p[1].0[1], p[1].1[0]), (3, 3));
        assert_eq!(&p[1].1[1..], a.as_bytes());
        // [A,A,B] (well-formed) => (idx0, qty2, A), (idx2, qty1, B)
        let p = pack_interlinks(&[a, a, b]);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].0[1], p[0].1[0]), (0, 2));
        assert_eq!((p[1].0[1], p[1].1[0]), (2, 1));
        assert_eq!(&p[1].1[1..], b.as_bytes());
    }
}
