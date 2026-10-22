//! A `val` block whose result mixes a SigmaProp with a Boolean (`{ val owner =
//! SELF.R4[SigmaProp].get; owner && HEIGHT > 1 }`) must compile to Scala's bare
//! `SigmaAnd`/`SigmaOr`, not `BoolToSigmaProp(SigmaPropIsProven(..))`: 0xCF is refused by
//! both interpreters, so such a tree can never be spent. Expected bytes: sigma-state 6.0.7
//! `SigmaCompiler` (v0 header, constant segregation, as the node's compile route).

use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};

const CASES: &[(&str, &str, &str)] = &[
    (
        "val_and",
        r#"{
  val bob = proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")))
  bob && HEIGHT > 1
}"#,
        "10020e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50402ea02cdee7300d191a37301",
    ),
    (
        "inline_and",
        r#"proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"))) && HEIGHT > 1"#,
        "10020e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50402ea02cdee7300d191a37301",
    ),
    (
        "val_sigma",
        r#"{
  val bob = proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")))
  bob && sigmaProp(HEIGHT > 1)
}"#,
        "10020e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50402ea02cdee7300d191a37301",
    ),
    (
        "val_and_rev",
        r#"{
  val bob = proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")))
  HEIGHT > 1 && bob
}"#,
        "100204020e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ea02d191a37300cdee7301",
    ),
    (
        "val_or",
        r#"{
  val bob = proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")))
  bob || HEIGHT > 1
}"#,
        "10020e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50402eb02cdee7300d191a37301",
    ),
    (
        "val_and_wrapped",
        r#"{
  val bob = proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")))
  sigmaProp(bob && HEIGHT > 1)
}"#,
        "10020e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50402ea02cdee7300d191a37301",
    ),
    (
        "inline_valbool",
        r#"{
  val h = HEIGHT > 1
  proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"))) && h
}"#,
        "10020e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee50402ea02cdee7300d191a37301",
    ),
    (
        "reg_and",
        r#"{
  val owner = SELF.R4[SigmaProp].get
  owner && HEIGHT > 1
}"#,
        "10010402ea02e4c6a70408d191a37300",
    ),
    (
        "reg_and_rev",
        r#"{
  val owner = SELF.R4[SigmaProp].get
  HEIGHT > 1 && owner
}"#,
        "10010402ea02d191a37300e4c6a70408",
    ),
    (
        "kept_block",
        r#"{
  val x = SELF.value
  proveDlog(decodePoint(fromBase16("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"))) && x > 1 && x < 100
}"#,
        "10030e2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5050205c801d801d601c1a7ea02ea02cdee7300d19172017301d18f72017302",
    ),
    (
        "reg_two_vals",
        r#"{
  val owner = SELF.R4[SigmaProp].get
  val ok = OUTPUTS(0).value >= SELF.value
  ok && owner
}"#,
        "10010400ea02d192c1b2a5730000c1a7e4c6a70408",
    ),
    (
        "reg_twice",
        r#"{
  val owner = SELF.R4[SigmaProp].get
  owner || (HEIGHT > 1 && owner)
}"#,
        "10010402d801d601e4c6a70408eb027201ea02d191a373007201",
    ),
    (
        "reg_inline",
        r#"SELF.R4[SigmaProp].get && HEIGHT > 1"#,
        "10010402ea02e4c6a70408d191a37300",
    ),
];

#[test]
fn val_block_sigma_bool_mix_matches_scala() {
    let mut bad = Vec::new();
    for (name, src, want) in CASES {
        let got = compile(&ScriptEnv::new(), src, 0, NetworkPrefix::Mainnet).expect(name);
        let hex: String = got.tree_bytes.iter().map(|b| format!("{b:02x}")).collect();
        if hex != *want {
            bad.push(format!("{name}: got {hex}, Scala {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
