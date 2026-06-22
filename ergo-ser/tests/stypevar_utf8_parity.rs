//! Consensus parity for `STypeVar`-bearing trees whose ROOT is non-`SigmaProp`.
//!
//! Each vector is a v3 (header `0x1b` = v3 + has_size + const-segregation) tree
//! whose body is a `BlockValue` of a polymorphic `FunDef`/`FuncValue` (the only
//! place an ill-formed-UTF-8 `STypeVar` name occurs on the wire) with a non-
//! SigmaProp result. Because the root is non-`SigmaProp`, the Scala reference's
//! `deserializeErgoTree` (checkType = true) fails `CheckDeserializedScriptIsSigma`
//! `Prop` (rule 1001) and, under has_size, SOFT-FORK-WRAPS the tree as an
//! `UnparsedErgoTree`, preserving the proposition bytes VERBATIM (so the
//! ill-formed name is NOT lossily decoded). The node must match: with the
//! rule-1001 root typing complete (`determinable_root_type` recurses into the
//! `BlockValue` result), `read_ergo_tree` wraps these the same way and
//! re-serializes byte-identically to the input.
//!
//! Oracle: each `expected_hex` is the JVM `ergo_tree`-surface re-serialization
//! (sigma-state 6.0.2, activated v3) — verified to echo the input verbatim. The
//! lossy `new String(UTF_8)` decode itself (which fires only when an STypeVar is
//! actually PARSED, i.e. in a SigmaProp-rooted/sizeless context) is unit-tested
//! in `ergo-ser/src/jvm_utf8.rs`.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree};

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ----- oracle parity -----

/// `(name, input_hex, expected_hex)` — `expected_hex` is the JVM-verbatim
/// (soft-fork-wrapped) re-serialization, which equals the input for these
/// non-SigmaProp-rooted has_size trees.
const VECTORS: &[(&str, &str, &str)] = &[
    (
        "ff",
        "1b1501040ad801d701016701ffd901026701ff72027300",
        "1b1501040ad801d701016701ffd901026701ff72027300",
    ),
    (
        "e282",
        "1b1701040ad801d701016702e282d901026702e28272027300",
        "1b1701040ad801d701016702e282d901026702e28272027300",
    ),
    (
        "c080",
        "1b1701040ad801d701016702c080d901026702c08072027300",
        "1b1701040ad801d701016702c080d901026702c08072027300",
    ),
    (
        "eda080",
        "1b1901040ad801d701016703eda080d901026703eda08072027300",
        "1b1901040ad801d701016703eda080d901026703eda08072027300",
    ),
    (
        "61ff62",
        "1b1901040ad801d70101670361ff62d90102670361ff6272027300",
        "1b1901040ad801d70101670361ff62d90102670361ff6272027300",
    ),
];

/// A non-SigmaProp-rooted has_size tree soft-fork-wraps (rule 1001) and
/// re-serializes VERBATIM, matching the JVM — the ill-formed STypeVar name is
/// preserved, not lossily decoded, because the wrapped body is never parsed.
#[test]
fn stypevar_nonsigma_root_softfork_wraps_verbatim_matching_jvm() {
    for (name, input_hex, expected_hex) in VECTORS {
        let input = hx(input_hex);
        let mut r = VlqReader::new(&input);
        let tree = read_ergo_tree(&mut r)
            .unwrap_or_else(|e| panic!("[{name}] expected soft-fork wrap to accept, got {e:?}"));

        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree)
            .unwrap_or_else(|e| panic!("[{name}] re-serialize failed: {e:?}"));
        assert_eq!(
            to_hex(&w.result()),
            *expected_hex,
            "[{name}] non-SigmaProp-root has_size tree must re-serialize verbatim (JVM wrap)"
        );
    }
}

// ----- error paths (regression: the reject-valid branch) -----

/// A sizeless (`has_size=false`, v0) tree carrying the same ill-formed
/// `STypeVar` name previously hard-rejected via strict `from_utf8` while the
/// JVM lossy-accepts — the reject-valid stall class. After the fix the node
/// must accept it. Built by stripping the size byte off each vector's body
/// and re-fronting with header 0x10 (v0 + const-segregation).
#[test]
fn sizeless_tree_with_illformed_name_no_longer_rejects() {
    for (name, input_hex, _) in VECTORS {
        let raw = hx(input_hex);
        let size = raw[1] as usize; // single-byte VLQ size (all < 128)
        let mut sizeless = vec![0x10u8];
        sizeless.extend_from_slice(&raw[2..2 + size]);

        let mut r = VlqReader::new(&sizeless);
        let parsed = read_ergo_tree(&mut r);
        assert!(
            parsed.is_ok(),
            "[{name}] sizeless tree with lossy-decodable name must parse, got {parsed:?}"
        );
    }
}
