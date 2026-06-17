//! Consensus parity for ill-formed UTF-8 in `STypeVar` names: the Scala
//! reference node decodes the name with the JVM's lossy `new String(UTF_8)`,
//! so an ErgoTree carrying such a name must parse (not reject) and, when
//! re-serialized from structure, reproduce the JVM-canonical bytes.
//!
//! Oracle: the `expected_bytes_hex` column is the JVM (`rudolph`)
//! re-serialization shipped in the SANTA `STypeVar.name_utf8_roundtrip`
//! wire vector — an external oracle, never computed from this crate.

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

/// SANTA `STypeVar.name_utf8_roundtrip` vectors (input -> JVM-canonical).
/// All inputs are header 0x1b = v3 + has_size + const-segregation.
const VECTORS: &[(&str, &str, &str)] = &[
    (
        "ff",
        "1b1501040ad801d701016701ffd901026701ff72027300",
        "1b1901040ad801d701016703efbfbdd901026703efbfbd72027300",
    ),
    (
        "e282",
        "1b1701040ad801d701016702e282d901026702e28272027300",
        "1b1901040ad801d701016703efbfbdd901026703efbfbd72027300",
    ),
    (
        "c080",
        "1b1701040ad801d701016702c080d901026702c08072027300",
        "1b1f01040ad801d701016706efbfbdefbfbdd901026706efbfbdefbfbd72027300",
    ),
    (
        "eda080",
        "1b1901040ad801d701016703eda080d901026703eda08072027300",
        "1b1901040ad801d701016703efbfbdd901026703efbfbd72027300",
    ),
    (
        "61ff62",
        "1b1901040ad801d70101670361ff62d90102670361ff6272027300",
        "1b1d01040ad801d70101670561efbfbd62d90102670561efbfbd6272027300",
    ),
];

#[test]
fn stypevar_illformed_name_parses_and_reserializes_to_jvm_canonical() {
    for (name, input_hex, expected_hex) in VECTORS {
        let input = hx(input_hex);
        let mut r = VlqReader::new(&input);
        let tree = read_ergo_tree(&mut r)
            .unwrap_or_else(|e| panic!("[{name}] expected lossy parse to accept, got {e:?}"));

        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree)
            .unwrap_or_else(|e| panic!("[{name}] re-serialize failed: {e:?}"));
        assert_eq!(
            to_hex(&w.result()),
            *expected_hex,
            "[{name}] re-serialization must match the JVM-canonical bytes"
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
