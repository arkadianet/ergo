//! Differential test against crates.io `ergo_avltree_rust` 0.1.1, the crate
//! this one replaced.
//!
//! Random trees (key length 4 or 32, values fixed at 8 bytes or of variable
//! length) are built by both provers in lockstep, then batches of mixed
//! operations are applied. Both provers must return the same results and
//! produce byte-identical proofs and digests. Each proof is then verified by
//! both verifiers, unchanged and after byte-level mutations, with and without
//! an operation bound; both must agree on construction, on every operation
//! result up to the first failure, and on the final digest. A panic counts as
//! a failure (0.1.1 panics where this crate returns an error on some
//! malformed proofs; the node's wrapper treats the two the same way).
//!
//! The one change known to separate the two, a leaf value longer than 4 MiB,
//! needs proofs far larger than the ones generated here; it is pinned by the
//! JVM-checked tests in `ergo-sigma`'s `avl` module.

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

#[derive(Clone, Debug)]
enum TOp {
    Lookup(Vec<u8>),
    Insert(Vec<u8>, Vec<u8>),
    Update(Vec<u8>, Vec<u8>),
    InsertOrUpdate(Vec<u8>, Vec<u8>),
    Remove(Vec<u8>),
    RemoveIfExists(Vec<u8>),
}

type OpResult = Result<Option<Vec<u8>>, ()>;

/// What a verifier run observed.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    constructed: bool,
    /// Results up to and including the first failure.
    results: Vec<OpResult>,
    digest: Option<Vec<u8>>,
}

macro_rules! side {
    ($name:ident, $krate:ident) => {
        mod $name {
            use super::{OpResult, Outcome, TOp};
            use bytes::Bytes;
            use std::panic::{catch_unwind, AssertUnwindSafe};
            use $krate::authenticated_tree_ops::AuthenticatedTreeOps;
            use $krate::batch_avl_prover::BatchAVLProver;
            use $krate::batch_avl_verifier::BatchAVLVerifier;
            use $krate::batch_node::{AVLTree, Node, NodeHeader};
            use $krate::operation::{KeyValue, Operation};

            fn tree(kl: usize, vl: Option<usize>) -> AVLTree {
                AVLTree::new(|d| Node::LabelOnly(NodeHeader::new(Some(*d), None)), kl, vl)
            }

            fn op(o: &TOp) -> Operation {
                let b = |x: &Vec<u8>| Bytes::copy_from_slice(x);
                let kv = |k: &Vec<u8>, v: &Vec<u8>| KeyValue {
                    key: b(k),
                    value: b(v),
                };
                match o {
                    TOp::Lookup(k) => Operation::Lookup(b(k)),
                    TOp::Insert(k, v) => Operation::Insert(kv(k, v)),
                    TOp::Update(k, v) => Operation::Update(kv(k, v)),
                    TOp::InsertOrUpdate(k, v) => Operation::InsertOrUpdate(kv(k, v)),
                    TOp::Remove(k) => Operation::Remove(b(k)),
                    TOp::RemoveIfExists(k) => Operation::RemoveIfExists(b(k)),
                }
            }

            pub struct Prover(BatchAVLProver);

            impl Prover {
                pub fn new(kl: usize, vl: Option<usize>) -> Self {
                    Prover(BatchAVLProver::new(tree(kl, vl), true))
                }
                pub fn apply(&mut self, o: &TOp) -> OpResult {
                    self.0
                        .perform_one_operation(&op(o))
                        .map(|r| r.map(|v| v.to_vec()))
                        .map_err(|_| ())
                }
                pub fn proof(&mut self) -> Vec<u8> {
                    self.0.generate_proof().to_vec()
                }
                pub fn digest(&self) -> Vec<u8> {
                    self.0.digest().expect("prover digest").to_vec()
                }
            }

            /// Verify `ops` against `(start, proof)`; a panic anywhere is a
            /// failure at that point.
            pub fn verify(
                start: &[u8],
                proof: &[u8],
                kl: usize,
                vl: Option<usize>,
                max_ops: Option<usize>,
                ops: &[TOp],
            ) -> (Outcome, bool) {
                let built = catch_unwind(|| {
                    BatchAVLVerifier::new(
                        &Bytes::copy_from_slice(start),
                        &Bytes::copy_from_slice(proof),
                        tree(kl, vl),
                        max_ops,
                        None,
                    )
                    .ok()
                });
                let panicked = built.is_err();
                let Ok(Some(mut v)) = built else {
                    let outcome = Outcome {
                        constructed: false,
                        results: Vec::new(),
                        digest: None,
                    };
                    return (outcome, panicked);
                };
                let mut results = Vec::new();
                for o in ops {
                    let r = catch_unwind(AssertUnwindSafe(|| {
                        v.perform_one_operation(&op(o))
                            .map(|r| r.map(|x| x.to_vec()))
                            .map_err(|_| ())
                    }));
                    match r {
                        Ok(Ok(x)) => results.push(Ok(x)),
                        Ok(Err(())) => {
                            results.push(Err(()));
                            break;
                        }
                        Err(_) => {
                            results.push(Err(()));
                            let outcome = Outcome {
                                constructed: true,
                                results,
                                digest: None,
                            };
                            return (outcome, true);
                        }
                    }
                }
                let digest = catch_unwind(AssertUnwindSafe(|| v.digest().map(|d| d.to_vec())))
                    .ok()
                    .flatten();
                let outcome = Outcome {
                    constructed: true,
                    results,
                    digest,
                };
                (outcome, false)
            }
        }
    };
}

side!(new_side, ergo_avltree);
side!(old_side, ergo_avltree_rust_0_1_1);

fn random_key(rng: &mut SplitMix64, kl: usize, keys: &[Vec<u8>]) -> Vec<u8> {
    if !keys.is_empty() && rng.below(2) == 0 {
        keys[rng.below(keys.len() as u64) as usize].clone()
    } else {
        rng.bytes(kl)
    }
}

fn random_value(rng: &mut SplitMix64, vl: Option<usize>) -> Vec<u8> {
    let len = vl.unwrap_or_else(|| rng.below(41) as usize);
    rng.bytes(len)
}

fn random_op(rng: &mut SplitMix64, kl: usize, vl: Option<usize>, keys: &[Vec<u8>]) -> TOp {
    let k = random_key(rng, kl, keys);
    match rng.below(6) {
        0 => TOp::Lookup(k),
        1 => TOp::Insert(k, random_value(rng, vl)),
        2 => TOp::Update(k, random_value(rng, vl)),
        3 => TOp::InsertOrUpdate(k, random_value(rng, vl)),
        4 => TOp::Remove(k),
        _ => TOp::RemoveIfExists(k),
    }
}

fn mutate(rng: &mut SplitMix64, proof: &[u8]) -> Vec<u8> {
    let mut p = proof.to_vec();
    if p.is_empty() {
        return p;
    }
    let at = rng.below(p.len() as u64) as usize;
    match rng.below(6) {
        0 => p[at] ^= 1 << rng.below(8),
        1 => p[at] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x7F, 0x80, 0xFF][rng.below(8) as usize],
        2 => p.truncate(at),
        3 => {
            p.remove(at);
        }
        4 => p.insert(at, rng.next_u64() as u8),
        _ => p[at] = rng.next_u64() as u8,
    }
    p
}

/// The root label a proof reconstructs to (same grammar as the verifiers,
/// lengths read unsigned), so a mutated proof can be paired with a digest it
/// matches and reach the operations. `None` when it does not parse.
fn root_label(proof: &[u8], kl: usize, vl: Option<usize>) -> Option<[u8; 32]> {
    use blake2::Digest as _;
    let hash = |parts: &[&[u8]]| {
        let mut h = ergo_avltree::batch_node::Blake2b256::new();
        for p in parts {
            h.update(p);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    };
    let take = |i: &mut usize, n: usize| -> Option<&[u8]> {
        let s = proof.get(*i..i.checked_add(n)?)?;
        *i += n;
        Some(s)
    };
    let mut stack: Vec<[u8; 32]> = Vec::new();
    let mut prev_next: Option<&[u8]> = None;
    let mut i = 0;
    loop {
        let n = *proof.get(i)?;
        if n == 4 {
            break;
        }
        i += 1;
        match n {
            3 => {
                let mut l = [0u8; 32];
                l.copy_from_slice(take(&mut i, 32)?);
                stack.push(l);
                prev_next = None;
            }
            2 => {
                let key = match prev_next {
                    Some(k) => k,
                    None => take(&mut i, kl)?,
                };
                let next = take(&mut i, kl)?;
                let len = match vl {
                    Some(l) => l,
                    None => u32::from_be_bytes(take(&mut i, 4)?.try_into().ok()?) as usize,
                };
                let value = take(&mut i, len)?;
                stack.push(hash(&[&[0], key, value, next]));
                prev_next = Some(next);
            }
            b => {
                let r = stack.pop()?;
                let l = stack.pop()?;
                stack.push(hash(&[&[1], &[b], &l, &r]));
            }
        }
    }
    (stack.len() == 1).then(|| stack[0])
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send>;

struct Silence(Option<PanicHook>);

impl Silence {
    fn install() -> Self {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        Silence(Some(prev))
    }
}

impl Drop for Silence {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            if let Some(prev) = self.0.take() {
                std::panic::set_hook(prev);
            }
        }
    }
}

#[test]
fn provers_and_verifiers_agree_with_0_1_1() {
    const CASES: usize = 3000;
    const MUTATIONS: usize = 6;
    let mut rng = SplitMix64(0x0A71_7EE0_0011_2026);
    let mut failures = Vec::new();
    let (mut verified, mut mutated_built, mut mutated_ok_ops) = (0usize, 0usize, 0usize);
    let (mut old_panics, mut new_panics) = (0usize, 0usize);
    {
        let _quiet = Silence::install();
        for case in 0..CASES {
            let kl = if rng.below(4) == 0 { 4 } else { 32 };
            let vl = if rng.below(2) == 0 { Some(8) } else { None };
            let mut old = old_side::Prover::new(kl, vl);
            let mut new = new_side::Prover::new(kl, vl);
            let mut keys: Vec<Vec<u8>> = Vec::new();
            for _ in 0..rng.below(41) {
                let k = rng.bytes(kl);
                let v = random_value(&mut rng, vl);
                let o = TOp::Insert(k.clone(), v);
                let (a, b) = (old.apply(&o), new.apply(&o));
                if a != b {
                    failures.push(format!("case {case}: prover seed insert {a:?} vs {b:?}"));
                }
                if a.is_ok() {
                    keys.push(k);
                }
            }
            let (pa, pb) = (old.proof(), new.proof());
            if pa != pb {
                failures.push(format!("case {case}: seed proofs differ"));
            }
            let start = old.digest();
            if start != new.digest() {
                failures.push(format!("case {case}: seed digests differ"));
                continue;
            }
            let ops: Vec<TOp> = (0..1 + rng.below(10))
                .map(|_| random_op(&mut rng, kl, vl, &keys))
                .collect();
            let mut applied = Vec::new();
            for o in &ops {
                let (a, b) = (old.apply(o), new.apply(o));
                if a != b {
                    failures.push(format!("case {case}: prover {o:?}: {a:?} vs {b:?}"));
                }
                if a.is_ok() {
                    applied.push(o.clone());
                }
            }
            let (proof, proof_new) = (old.proof(), new.proof());
            if proof != proof_new {
                failures.push(format!("case {case}: batch proofs differ"));
                continue;
            }
            let end = old.digest();
            if end != new.digest() {
                failures.push(format!("case {case}: batch digests differ"));
            }
            let max_ops = if rng.below(2) == 0 {
                None
            } else {
                Some(applied.len())
            };
            // The honest replay must succeed and reach the prover's digest.
            let (honest, _) = new_side::verify(&start, &proof, kl, vl, max_ops, &applied);
            if !honest.constructed
                || honest.results.iter().any(|r| r.is_err())
                || honest.digest.as_deref() != Some(&end[..])
            {
                failures.push(format!("case {case}: honest replay failed: {honest:?}"));
            }
            let mut runs = vec![
                (proof.clone(), applied.clone()),
                (proof.clone(), ops.clone()),
            ];
            for _ in 0..MUTATIONS {
                runs.push((mutate(&mut rng, &proof), applied.clone()));
            }
            for (i, (p, o)) in runs.iter().enumerate() {
                // A mutated proof is verified against the digest it
                // reconstructs to (with the original height byte), so most of
                // them reach the operations.
                let mut digest = start.clone();
                if i >= 2 {
                    if let Some(label) = root_label(p, kl, vl) {
                        digest[..32].copy_from_slice(&label);
                    }
                }
                let (a, old_panicked) = old_side::verify(&digest, p, kl, vl, max_ops, o);
                let (b, new_panicked) = new_side::verify(&digest, p, kl, vl, max_ops, o);
                verified += 1;
                old_panics += usize::from(old_panicked);
                new_panics += usize::from(new_panicked);
                if i >= 2 && b.constructed {
                    mutated_built += 1;
                    mutated_ok_ops += b.results.iter().filter(|r| r.is_ok()).count();
                }
                if a != b {
                    failures.push(format!(
                        "case {case} run {i}: verifiers differ\n  0.1.1: {a:?}\n  new:   {b:?}\n  proof {}",
                        base16::encode_lower(p)
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures[..failures.len().min(20)].join("\n")
    );
    eprintln!(
        "{CASES} cases, {verified} verifier runs; {mutated_built} mutated proofs reconstructed, \
         {mutated_ok_ops} operations succeeded on them; panics: 0.1.1 {old_panics}, new {new_panics}"
    );
    assert!(mutated_built > 1000 && mutated_ok_ops > 1000);
}

/// A fixed operation sequence replayed through the prover: the digest after
/// every batch and the proofs must not change. The values were produced by
/// crates.io 0.1.1 and are unchanged by the vendored copy.
#[test]
fn prover_digests_are_pinned() {
    let mut rng = SplitMix64(42);
    let mut prover = new_side::Prover::new(32, None);
    let mut old = old_side::Prover::new(32, None);
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut proofs_hash: u64 = 0xCBF2_9CE4_8422_2325;
    let mut digests = Vec::new();
    for batch in 0..20 {
        for _ in 0..25 {
            let o = if batch < 4 {
                TOp::Insert(rng.bytes(32), random_value(&mut rng, None))
            } else {
                random_op(&mut rng, 32, None, &keys)
            };
            let r = prover.apply(&o);
            assert_eq!(r, old.apply(&o));
            if let (Ok(_), TOp::Insert(k, _) | TOp::InsertOrUpdate(k, _)) = (&r, &o) {
                keys.push(k.clone());
            }
        }
        let proof = prover.proof();
        assert_eq!(proof, old.proof());
        for b in &proof {
            proofs_hash = (proofs_hash ^ u64::from(*b)).wrapping_mul(0x0100_0000_01B3);
        }
        digests.push(base16::encode_lower(&prover.digest()));
    }
    assert_eq!(digests[0], PINNED_FIRST_DIGEST);
    assert_eq!(digests[19], PINNED_LAST_DIGEST);
    assert_eq!(proofs_hash, PINNED_PROOFS_FNV);
}

const PINNED_FIRST_DIGEST: &str =
    "58652e7ec8603e1c5772b6315bb0caaa0ea0c0c0aefee9890c6a12f42397cd4106";
const PINNED_LAST_DIGEST: &str =
    "960cc9f043cfbc4a65976889d991103bfb53135b069ea0702899071075f7bb6e08";
/// FNV-1a over the 20 batch proofs, concatenated.
const PINNED_PROOFS_FNV: u64 = 10_212_933_476_374_214_645;
