//! Scala 2.12 immutable-`HashMap` (`HashTrieMap`) iteration order over a set of
//! contract-template param names — the byte-exact source of `ConstantPlaceholder`
//! indices for `@contract` templates with ≥5 params.
//!
//! ## Why this exists
//! `SigmaTemplateCompiler.compile` builds the param env as an immutable `Map`
//! (`parEnv = params.map(p => p.name -> p.tpe).toMap`,
//! SigmaTemplateCompiler.scala:28), then `SigmaCompiler.compileTyped`
//! (SigmaCompiler.scala:88-92) does
//! `env.collect{…}.zipWithIndex.map{ (name,t),i => name -> ConstantPlaceholder(i, t) }`.
//! The placeholder INDEX handed to each param is thus the param's position **in
//! the `Map`'s iteration order**, which is serialized into the `expressionTree`
//! bytes. For ≤4 entries Scala's `Map1..Map4` preserve insertion (declaration)
//! order; at ≥5 entries `.toMap` upgrades to a hash map whose iteration order is
//! `improve(String.hashCode)` bucket order — NOT declaration order.
//!
//! ## Version pin — Scala 2.12
//! The iteration order is Scala-version dependent: 2.12 uses
//! `scala.collection.immutable.HashMap$HashTrieMap` (5-bit-sliced trie, sub-tries
//! visited **in place** in ascending bucket order); 2.13 uses the CHAMP `HashMap`
//! (all same-level payloads first, THEN sub-nodes). This crate pins **2.12**, matching the
//! `ct` oracle (`TyperOracle.scala` `//> using scala 2.12`, captured under Scala
//! 2.12.21) and ergo-appkit (the real-world `ContractTemplate` producer, a 2.12
//! artifact). The 2.13 CHAMP order is documented in [`iteration_order_2_13`] for
//! the day the ecosystem's producer moves to 2.13.
//!
//! Reverse-engineered and bit-validated against the live oracle.

/// JVM `String.hashCode`: `h = 31*h + c` over the string's UTF-16 code units,
/// `i32` wrapping arithmetic (`java.lang.String.hashCode`).
pub fn jvm_string_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for unit in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    h
}

/// `scala.collection.Hashing.improve` — the hash-mix immutable `HashMap` applies
/// before bucketing (byte-identical bytecode in Scala 2.12 and 2.13). All 32-bit
/// wrapping / logical-shift arithmetic.
fn improve(hash: i32) -> u32 {
    let h = hash as u32;
    let h = h.wrapping_add(!(h << 9));
    let h = h ^ (h >> 14);
    let h = h.wrapping_add(h << 4);
    h ^ (h >> 10)
}

/// The 5-bit trie slice selecting a param's bucket at `depth` (`BitPartition=5`,
/// `scala.collection.immutable.Node`): `(improve(hash) >>> (5*depth)) & 0x1f`.
fn bucket(improved_hash: u32, depth: u32) -> u32 {
    (improved_hash >> (5 * depth)) & 0x1f
}

/// The `improve(hash)` mix is a 32-bit value; a 5-bit slice per level consumes
/// all of it after this many levels. Beyond it two names share the full 32-bit
/// hash and land in a `HashMapCollision` list, iterated in insertion order.
const TRIE_MAX_DEPTH: u32 = 32_u32.div_ceil(5); // = 7

/// The Scala **2.12** `HashTrieMap` iteration order over `names` (declaration
/// order in, iteration order out). Returns the declaration indices `0..names.len()`
/// permuted into the order the map yields them — i.e. `result[k]` is the
/// declaration index of the param that receives `ConstantPlaceholder(k)`.
///
/// The trie is walked depth-first: at each level, params are bucketed by their
/// 5-bit hash slice and the buckets are visited in **ascending** bucket order; a
/// singleton bucket emits its param, a multi-param bucket recurses one level
/// deeper **in place** (this is the 2.12-specific behavior — 2.13 demotes
/// collisions after all same-level singletons).
pub fn iteration_order_2_12(names: &[&str]) -> Vec<usize> {
    let improved: Vec<u32> = names.iter().map(|n| improve(jvm_string_hash(n))).collect();
    let group: Vec<usize> = (0..names.len()).collect();
    let mut out = Vec::with_capacity(names.len());
    order_2_12(&group, 0, &improved, &mut out);
    out
}

fn order_2_12(group: &[usize], depth: u32, improved: &[u32], out: &mut Vec<usize>) {
    if group.len() == 1 {
        out.push(group[0]);
        return;
    }
    if depth >= TRIE_MAX_DEPTH {
        // Full 32-bit hash collision: entries live in a `HashMapCollision` list
        // keyed by insertion (declaration) order — `group` is already in it.
        out.extend_from_slice(group);
        return;
    }
    // Bucketize preserving insertion order within each bucket; BTreeMap yields the
    // bucket keys ascending, matching HashTrieMap's low-to-high slot iteration.
    let mut buckets: std::collections::BTreeMap<u32, Vec<usize>> =
        std::collections::BTreeMap::new();
    for &i in group {
        buckets
            .entry(bucket(improved[i], depth))
            .or_default()
            .push(i);
    }
    for members in buckets.into_values() {
        if members.len() == 1 {
            out.push(members[0]);
        } else {
            order_2_12(&members, depth + 1, improved, out);
        }
    }
}

/// The Scala **2.13** CHAMP `HashMap` iteration order over `names` — documented
/// alternative for the day the `ContractTemplate` producer moves to 2.13 (this
/// crate pins 2.12; see the module docs). Differs from [`iteration_order_2_12`] only in that
/// a colliding bucket is demoted after ALL same-level singletons rather than
/// visited in place.
#[cfg(test)]
pub fn iteration_order_2_13(names: &[&str]) -> Vec<usize> {
    let improved: Vec<u32> = names.iter().map(|n| improve(jvm_string_hash(n))).collect();
    let group: Vec<usize> = (0..names.len()).collect();
    let mut out = Vec::with_capacity(names.len());
    order_2_13(&group, 0, &improved, &mut out);
    out
}

#[cfg(test)]
fn order_2_13(group: &[usize], depth: u32, improved: &[u32], out: &mut Vec<usize>) {
    if group.len() == 1 {
        out.push(group[0]);
        return;
    }
    if depth >= TRIE_MAX_DEPTH {
        out.extend_from_slice(group);
        return;
    }
    let mut buckets: std::collections::BTreeMap<u32, Vec<usize>> =
        std::collections::BTreeMap::new();
    for &i in group {
        buckets
            .entry(bucket(improved[i], depth))
            .or_default()
            .push(i);
    }
    // CHAMP: all same-level payloads (singletons) first, ascending …
    for members in buckets.values() {
        if members.len() == 1 {
            out.push(members[0]);
        }
    }
    // … then the sub-nodes (collisions), ascending.
    for members in buckets.values() {
        if members.len() > 1 {
            order_2_13(members, depth + 1, improved, out);
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// name -> placeholder index, from the iteration-order permutation.
    fn placeholder_map(
        names: &[&str],
        order: Vec<usize>,
    ) -> std::collections::BTreeMap<String, u32> {
        order
            .into_iter()
            .enumerate()
            .map(|(placeholder_idx, decl_idx)| {
                (names[decl_idx].to_string(), placeholder_idx as u32)
            })
            .collect()
    }

    fn expect(pairs: &[(&str, u32)]) -> std::collections::BTreeMap<String, u32> {
        pairs.iter().map(|(n, i)| (n.to_string(), *i)).collect()
    }

    // ----- oracle parity (bit-validated vs live JVM) -----

    #[test]
    fn jvm_string_hash_matches_known_values() {
        // Java String.hashCode of these param names, load-bearing for the port.
        assert_eq!(jvm_string_hash("zeta"), 3735256);
        assert_eq!(jvm_string_hash("alpha"), 92909918);
        assert_eq!(jvm_string_hash("mike"), 3351542);
        assert_eq!(jvm_string_hash("bravo"), 93998218);
        assert_eq!(jvm_string_hash("oscar"), 106035056);
        assert_eq!(jvm_string_hash("sigma"), 109435429);
        assert_eq!(jvm_string_hash("delta"), 95468472);
        assert_eq!(jvm_string_hash("kappa"), 101817675);
        assert_eq!(jvm_string_hash("omega"), 105858401);
        assert_eq!(jvm_string_hash("theta"), 110327454);
        assert_eq!(jvm_string_hash("gamma"), 98120615);
        assert_eq!(jvm_string_hash("lambda"), -1110092857);
        assert_eq!(jvm_string_hash("beta"), 3020272);
    }

    #[test]
    fn jvm_string_hash_empty_is_zero() {
        assert_eq!(jvm_string_hash(""), 0);
    }

    #[test]
    fn order_2_12_p5_matches_oracle() {
        // oracle: p5 2.12 → alpha=0 zeta=1 bravo=2 oscar=3 mike=4.
        let names = ["zeta", "alpha", "mike", "bravo", "oscar"];
        let got = placeholder_map(&names, iteration_order_2_12(&names));
        let want = expect(&[
            ("alpha", 0),
            ("zeta", 1),
            ("bravo", 2),
            ("oscar", 3),
            ("mike", 4),
        ]);
        assert_eq!(got, want);
    }

    #[test]
    fn order_2_12_p8_matches_oracle() {
        // oracle: p8 2.12 → kappa=0 lambda=1 omega=2 sigma=3 theta=4 delta=5 beta=6 gamma=7.
        let names = [
            "sigma", "delta", "kappa", "omega", "theta", "gamma", "lambda", "beta",
        ];
        let got = placeholder_map(&names, iteration_order_2_12(&names));
        let want = expect(&[
            ("kappa", 0),
            ("lambda", 1),
            ("omega", 2),
            ("sigma", 3),
            ("theta", 4),
            ("delta", 5),
            ("beta", 6),
            ("gamma", 7),
        ]);
        assert_eq!(got, want);
    }

    #[test]
    fn order_2_13_p5_matches_oracle() {
        // oracle: p5 2.13 → alpha=0 oscar=1 mike=2 zeta=3 bravo=4 (collision demoted).
        let names = ["zeta", "alpha", "mike", "bravo", "oscar"];
        let got = placeholder_map(&names, iteration_order_2_13(&names));
        let want = expect(&[
            ("alpha", 0),
            ("oscar", 1),
            ("mike", 2),
            ("zeta", 3),
            ("bravo", 4),
        ]);
        assert_eq!(got, want);
    }

    #[test]
    fn order_2_13_p8_matches_oracle() {
        // oracle: p8 2.13 → kappa,lambda,omega,sigma,theta,gamma,delta,beta.
        let names = [
            "sigma", "delta", "kappa", "omega", "theta", "gamma", "lambda", "beta",
        ];
        let got = placeholder_map(&names, iteration_order_2_13(&names));
        let want = expect(&[
            ("kappa", 0),
            ("lambda", 1),
            ("omega", 2),
            ("sigma", 3),
            ("theta", 4),
            ("gamma", 5),
            ("delta", 6),
            ("beta", 7),
        ]);
        assert_eq!(got, want);
    }

    #[test]
    fn order_single_and_empty_are_identity() {
        assert_eq!(iteration_order_2_12(&["only"]), vec![0]);
        assert!(iteration_order_2_12(&[]).is_empty());
    }
}
